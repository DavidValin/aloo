//! Two real sessions, one real pad between them, and the acknowledgement
//! actually crossing from one to the other.
//!
//! Everything else about the nonce ack is proven in pieces elsewhere -
//! `otp_cli_test.rs` against the real binary, `otp_store_test.rs` over the
//! gate, `ui_test.rs` over the arrow. What none of those can show is the
//! wiring: that alice's send really does record what it is waiting for,
//! that bob's receive path really does put the derived proof on the wire,
//! and that alice's ack handler really does check it before opening
//! anything. That is what this file drives, end to end, through the same
//! functions the app calls (`otp::send_or_queue`, `otp::on_message`,
//! `otp::on_delivery_ack`) over real `SessionState`s.
//!
//! No sockets are punched. Each side's link to the other is only ever
//! `ensure_link`-ed, so whatever a session decides to send waits in that
//! link's pending queue where the assertions can read it and hand it to
//! the other session by hand - which is exactly what makes the handoff
//! visible rather than implied.
//!
//! @requirement AC-250, AC-251

use aloo::client::connect::ResolvedIdentity;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::{DeliveryStatus, MessageBody, UiState};
use aloo::control::NullSink;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{Content, KeyMode, UserId, UserInfo};

/// Keeps the suite quick - none of these assert anything about key size.
const SCENARIO_KEY_BITS: usize = 1024;

const ALICE: UserId = UserId(1);
const BOB: UserId = UserId(2);

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-ack-wiring-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The pad layer is the whole subject here, so skip rather than pass when
/// the binary this depends on is not installed - the same fail-visibly
/// convention `otp_cli_test.rs` uses.
fn require_otp(cfg: &OtpCliConfig) -> bool {
    if aloo::client::otp_cli::binary_available(cfg) {
        return true;
    }
    eprintln!("skipping: the `otp` binary is not installed");
    false
}

/// One side: its session, its UI, and who it is on the wire.
struct Side {
    session: SessionState,
    ui: UiState,
    /// This side's own id, and the peer's - opposite on each side.
    peer: UserId,
    peer_der: Vec<u8>,
}

impl Side {
    /// Whatever this side decided to send its peer, still queued because
    /// the link was never punched.
    fn queued(&mut self) -> Vec<P2pPayload> {
        let peer = self.peer;
        self.session.peer_link_mut().pending_payloads(peer)
    }

    /// This side's view of its one outgoing row's delivery state - what
    /// the `->` arrow is coloured by (`DeliveryStatus::color`).
    fn arrow(&self) -> DeliveryStatus {
        self.ui
            .private_rooms
            .values()
            .flat_map(|r| r.log.iter())
            .find_map(|e| e.delivery.as_ref().map(|d| d.status()))
            .expect("the outgoing row tracks its own delivery")
    }

    /// Whether a message to this contact is still awaiting acknowledgement
    /// - the gate that decides if anything more may be encrypted.
    fn gate_held(&mut self, contact: &str) -> bool {
        self.session
            .otp_store_mut()
            .get(contact)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_some()
    }
}

/// One real pad, split in two and filed on opposite sides under `contact`
/// - alice's encryption half is bob's decryption half and vice versa.
async fn split_one_pad(label: &str, contact: &str) -> (OtpCliConfig, OtpCliConfig) {
    let alice_cfg = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch(&format!("{label}-alice-otp")),
    };
    let bob_cfg = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch(&format!("{label}-bob-otp")),
    };
    otp_cli::new_key_pair(&alice_cfg, 1, "a", "b")
        .await
        .expect("key generation");
    let a_keys = alice_cfg.working_dir.join("a_keys");
    let b_keys = alice_cfg.working_dir.join("b_keys");
    otp_cli::add_contact(
        &alice_cfg,
        contact,
        &a_keys.join("encryption_for_b.key"),
        &a_keys.join("decryption_from_b.key"),
    )
    .await
    .expect("alice add-contact");
    otp_cli::add_contact(
        &bob_cfg,
        contact,
        &b_keys.join("encryption_for_a.key"),
        &b_keys.join("decryption_from_a.key"),
    )
    .await
    .expect("bob add-contact");
    (alice_cfg, bob_cfg)
}

/// Two sessions that genuinely hold the two halves of one pad, each
/// knowing the other as a `pq_hybrid` peer, with the OTP session already
/// active between them.
///
/// The keychain contact is filed under the *derived* name both sides
/// compute from their fingerprints, not a nickname - the same binding the
/// real provisioning path produces, and the reason an impostor taking a
/// familiar name reaches nobody's pad.
async fn provisioned_pair(label: &str) -> (Side, Side, String) {
    let (alice_pub, alice_priv) =
        aloo::crypto::pq::generate_bundle_with_bits(SCENARIO_KEY_BITS).expect("alice pq keygen");
    let (bob_pub, bob_priv) =
        aloo::crypto::pq::generate_bundle_with_bits(SCENARIO_KEY_BITS).expect("bob pq keygen");
    let alice_der = aloo::proto::encode(&alice_pub).expect("alice der");
    let bob_der = aloo::proto::encode(&bob_pub).expect("bob der");
    let alice_fp = aloo::crypto::pq::fingerprint_of_encoded(&alice_der).expect("alice fp");
    let bob_fp = aloo::crypto::pq::fingerprint_of_encoded(&bob_der).expect("bob fp");
    let contact = aloo::crypto::otp::contact_name_for(&alice_fp, &bob_fp);

    let (alice_cfg, bob_cfg) = split_one_pad(label, &contact).await;

    let alice = build_side(
        "alice",
        ALICE,
        alice_priv,
        alice_der.clone(),
        BOB,
        "bob",
        bob_der.clone(),
        alice_cfg,
        &contact,
        label,
    )
    .await;
    let bob = build_side(
        "bob",
        BOB,
        bob_priv,
        bob_der,
        ALICE,
        "alice",
        alice_der,
        bob_cfg,
        &contact,
        label,
    )
    .await;
    (alice, bob, contact)
}

/// The same pair, but with `Password` identities on both sides and no
/// `pq_hybrid` anywhere - the configuration `/otp` accepts for pure-OTP
/// mode, where the pad is bound to the two pinned RSA keys rather than to
/// `pq` fingerprints (`crypto::otp::contact_name_for_keys`).
async fn pure_otp_pair(label: &str) -> (Side, Side, String) {
    let alice_kp = aloo::crypto::KeyPair::generate_with_bits(SCENARIO_KEY_BITS).expect("alice rsa");
    let bob_kp = aloo::crypto::KeyPair::generate_with_bits(SCENARIO_KEY_BITS).expect("bob rsa");
    let alice_der = aloo::crypto::public_key_to_der(&alice_kp.public).expect("alice der");
    let bob_der = aloo::crypto::public_key_to_der(&bob_kp.public).expect("bob der");
    // Order-independent, so both sides reach the same name unprompted.
    let contact = aloo::crypto::otp::contact_name_for_keys(&alice_der, &bob_der);
    assert_eq!(
        contact,
        aloo::crypto::otp::contact_name_for_keys(&bob_der, &alice_der)
    );

    let (alice_cfg, bob_cfg) = split_one_pad(label, &contact).await;
    let alice = build_password_side(
        "alice", ALICE, alice_kp, BOB, "bob", bob_der, alice_cfg, &contact, label,
    )
    .await;
    let bob = build_password_side(
        "bob", BOB, bob_kp, ALICE, "alice", alice_der, bob_cfg, &contact, label,
    )
    .await;
    (alice, bob, contact)
}

#[allow(clippy::too_many_arguments)]
async fn build_password_side(
    own_name: &str,
    own_id: UserId,
    own_kp: aloo::crypto::KeyPair,
    peer_id: UserId,
    peer_name: &str,
    peer_der: Vec<u8>,
    otp: OtpCliConfig,
    contact: &str,
    label: &str,
) -> Side {
    let mut session = SessionState::for_test(TestSessionSpec {
        key_mode: KeyMode::Password,
        identity: ResolvedIdentity::Rsa(own_kp),
        scratch: scratch(&format!("{label}-{own_name}")),
        otp: Some(otp),
    })
    .await;
    session.otp_store_mut().mark_provisioned(contact);

    let mut ui = UiState::new(own_name.into());
    ui.set_own_id(own_id);
    let peer = UserInfo {
        id: peer_id,
        name: peer_name.into(),
        public_key_der: peer_der.clone(),
        key_mode: KeyMode::Password,
    };
    ui.known_users.insert(peer_id, peer.clone());
    ui.open_private_room(peer);
    session
        .peer_link_mut()
        .ensure_link(&mut NullSink, peer_id)
        .await;
    Side {
        session,
        ui,
        peer: peer_id,
        peer_der,
    }
}

#[allow(clippy::too_many_arguments)]
async fn build_side(
    own_name: &str,
    own_id: UserId,
    own_private: aloo::crypto::pq::PqPrivateBundle,
    own_der: Vec<u8>,
    peer_id: UserId,
    peer_name: &str,
    peer_der: Vec<u8>,
    otp: OtpCliConfig,
    contact: &str,
    label: &str,
) -> Side {
    let mut session = SessionState::for_test(TestSessionSpec {
        key_mode: KeyMode::PqHybrid,
        identity: ResolvedIdentity::Pq {
            private: own_private,
            public_der: own_der,
        },
        scratch: scratch(&format!("{label}-{own_name}")),
        otp: Some(otp),
    })
    .await;
    // Already provisioned: this file is about what happens *after* the two
    // sides hold matching pads, which `otp_provisioning_test.rs` covers.
    session.otp_store_mut().mark_provisioned(contact);

    let mut ui = UiState::new(own_name.into());
    ui.set_own_id(own_id);
    let peer = UserInfo {
        id: peer_id,
        name: peer_name.into(),
        public_key_der: peer_der.clone(),
        key_mode: KeyMode::PqHybrid,
    };
    ui.known_users.insert(peer_id, peer.clone());
    ui.open_private_room(peer.clone());
    // Exactly what the real connect path does when a peer becomes known -
    // without it there is no encryption key to seal the inner envelope to.
    aloo::client::session::seed_direct_peer_keys(&mut session, peer_id, &peer);
    session
        .peer_link_mut()
        .ensure_link(&mut NullSink, peer_id)
        .await;
    Side {
        session,
        ui,
        peer: peer_id,
        peer_der,
    }
}

/// Sends one text under the pad, exactly as `direct_message::handle_send_text`
/// does once it finds an active contact: a row first (so the arrow has
/// something to colour), then the pad-wrapped send naming it.
async fn send_text(side: &mut Side, contact: &str, text: &str) -> u64 {
    send_text_as(side, contact, KeyMode::PqHybrid, text).await
}

async fn send_text_as(side: &mut Side, contact: &str, mode: KeyMode, text: &str) -> u64 {
    let (msg_id, delivery) = side.ui.start_delivery(&[side.peer]);
    side.ui.push_outgoing_dm(
        side.peer,
        MessageBody::Text(text.to_string()),
        Some(delivery),
    );
    let peer_der = side.peer_der.clone();
    aloo::client::otp::send_or_queue(
        &mut NullSink,
        &mut side.session,
        &mut side.ui,
        side.peer,
        contact,
        mode,
        &peer_der,
        text.as_bytes(),
        Content::Text,
        None,
        None,
        Some(msg_id),
    )
    .await
    .expect("the send path should not fail");
    msg_id
}

/// The one `OtpEnvelope` this side put on the wire.
fn take_envelope(side: &mut Side) -> (u64, Option<u64>, aloo::proto::Envelope) {
    let queued = side.queued();
    queued
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                ..
            } => Some((seq, msg_id, envelope)),
            _ => None,
        })
        .expect("a pad-wrapped message should have gone out")
}

/// The one `OtpDeliveryAck` this side put on the wire.
fn take_ack(side: &mut Side) -> (u64, [u8; 32]) {
    let queued = side.queued();
    queued
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .expect("receiving should have produced an acknowledgement")
}

/// Hands alice's envelope to bob's real receive path.
async fn deliver_to(bob: &mut Side, from: UserId, seq: u64, msg_id: Option<u64>, envelope: aloo::proto::Envelope) {
    aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        from,
        "alice".into(),
        seq,
        msg_id,
        envelope,
    )
    .await
    .expect("the receive path should not fail");
}

// ---------------------------------------------------------------------
// The successful round trip
// ---------------------------------------------------------------------

/// The whole chain, in the order it really happens: alice sends and closes
/// her gate, bob decrypts and answers with a proof he could only have
/// derived by decrypting, alice checks it, and only then does her gate open
/// and her arrow turn green.
///
/// @requirement AC-250, AC-251
#[tokio::test]
async fn an_acknowledgement_that_proves_itself_opens_the_gate_and_the_arrow() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-ok"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = provisioned_pair("ok").await;

    send_text(&mut alice, &contact, "meet me at six").await;
    assert!(
        alice.gate_held(&contact),
        "the send must close the gate behind it"
    );
    assert_eq!(
        alice.arrow(),
        DeliveryStatus::None,
        "and nothing has acknowledged it yet"
    );

    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    deliver_to(&mut bob, ALICE, seq, msg_id, envelope).await;

    // Bob really did read it, through the pad.
    assert!(
        bob.ui
            .private_rooms
            .values()
            .flat_map(|r| r.log.iter())
            .any(|e| format!("{:?}", e.body).contains("meet me at six")),
        "the message must have reached bob's log"
    );

    let (ack_seq, proof) = take_ack(&mut bob);
    assert_eq!(ack_seq, seq, "the ack names the message it answers");

    // Bob sends no ordinary receipt for a pad-wrapped text - it would only
    // repeat, unprovenly, what this ack already establishes.
    assert!(
        !bob.queued()
            .iter()
            .any(|p| matches!(p, P2pPayload::DeliveryReceipt { .. })),
        "a redundant receipt must not go out alongside the ack"
    );

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");

    assert!(!alice.gate_held(&contact), "a proved ack opens the gate");
    assert_eq!(
        alice.arrow(),
        DeliveryStatus::All,
        "and turns the row's arrow green"
    );
}

// ---------------------------------------------------------------------
// The failed acknowledgement
// ---------------------------------------------------------------------

/// The attack this exists to stop: someone who saw the packet go past can
/// read its sequence number off the wire and quote it back. Without the
/// proof that would have been enough to open the gate - and the next
/// message would have gone out to a party that never held the pad.
///
/// @requirement AC-250, AC-251
#[tokio::test]
async fn an_acknowledgement_that_cannot_prove_itself_changes_nothing() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-bad"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = provisioned_pair("bad").await;

    send_text(&mut alice, &contact, "meet me at six").await;
    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    deliver_to(&mut bob, ALICE, seq, msg_id, envelope).await;
    let (ack_seq, real_proof) = take_ack(&mut bob);

    // Right sequence number, invented proof.
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        [0xAB; 32],
    )
    .await
    .expect("a refused ack is not an error");

    assert!(
        alice.gate_held(&contact),
        "an unprovable ack must leave the message outstanding"
    );
    assert_eq!(
        alice.arrow(),
        DeliveryStatus::None,
        "and must not let the row claim it was delivered"
    );

    // The genuine one still works afterwards - refusing is not a wedge.
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        real_proof,
    )
    .await
    .expect("the ack path should not fail");
    assert!(!alice.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::All);
}

/// An ack naming a sequence that is not the one outstanding proves nothing
/// about the one that is, however genuine its proof.
///
/// @requirement AC-250
#[tokio::test]
async fn an_acknowledgement_for_a_different_sequence_does_not_open_this_gate() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-seq"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = provisioned_pair("seq").await;

    send_text(&mut alice, &contact, "meet me at six").await;
    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    deliver_to(&mut bob, ALICE, seq, msg_id, envelope).await;
    let (_, proof) = take_ack(&mut bob);

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        seq + 1,
        proof,
    )
    .await
    .expect("a mismatched ack is not an error");

    assert!(alice.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::None);
}

/// While the gate is held nothing more may be encrypted, so a message
/// typed meanwhile waits rather than spending pad - and is released by the
/// proved ack, not by the unprovable one.
///
/// @requirement AC-250, AC-137
#[tokio::test]
async fn a_queued_message_is_released_only_by_an_ack_that_proves_itself() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-queue"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = provisioned_pair("queue").await;

    // `pending_payloads` reads rather than drains, so the count of
    // pad-wrapped sends still queued is what says whether anything more
    // actually left.
    let sent_count = |side: &mut Side| {
        side.queued()
            .iter()
            .filter(|p| matches!(p, P2pPayload::OtpEnvelope { .. }))
            .count()
    };

    send_text(&mut alice, &contact, "first").await;
    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    assert_eq!(sent_count(&mut alice), 1);

    send_text(&mut alice, &contact, "second").await;
    assert_eq!(
        sent_count(&mut alice),
        1,
        "the second message must wait behind the first rather than spend pad"
    );

    deliver_to(&mut bob, ALICE, seq, msg_id, envelope).await;
    let (ack_seq, proof) = take_ack(&mut bob);

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        [0x11; 32],
    )
    .await
    .expect("a refused ack is not an error");
    assert_eq!(
        sent_count(&mut alice),
        1,
        "an unprovable ack must not release the queued message"
    );

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");
    assert_eq!(
        sent_count(&mut alice),
        2,
        "the proved ack releases exactly one queued send"
    );
}

/// Both directions at once, which is the ordinary case: each side is a
/// sender and a receiver, and the two gates are wholly independent. An
/// inbound message proves identity, but says nothing about whether this
/// side's own outbound one arrived - so it must not open this side's gate.
///
/// @requirement AC-250
#[tokio::test]
async fn each_direction_keeps_its_own_gate() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-both"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = provisioned_pair("both").await;

    // Crossing in flight: each sends before either has received.
    send_text(&mut alice, &contact, "from alice").await;
    send_text(&mut bob, &contact, "from bob").await;
    let (a_seq, a_msg, a_env) = take_envelope(&mut alice);
    let (b_seq, b_msg, b_env) = take_envelope(&mut bob);

    deliver_to(&mut bob, ALICE, a_seq, a_msg, a_env).await;
    assert!(
        bob.gate_held(&contact),
        "receiving proves who they are, not that bob's own message arrived"
    );
    assert_eq!(
        bob.arrow(),
        DeliveryStatus::None,
        "so bob's own row is unmoved by it"
    );

    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        b_seq,
        b_msg,
        b_env,
    )
    .await
    .expect("the receive path should not fail");

    let (b_ack_seq, b_proof) = take_ack(&mut bob);
    let (a_ack_seq, a_proof) = take_ack(&mut alice);

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        b_ack_seq,
        b_proof,
    )
    .await
    .expect("the ack path should not fail");
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        a_ack_seq,
        a_proof,
    )
    .await
    .expect("the ack path should not fail");

    assert!(!alice.gate_held(&contact));
    assert!(!bob.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::All);
    assert_eq!(bob.arrow(), DeliveryStatus::All);
}

// ---------------------------------------------------------------------
// Pure-OTP mode reaching the send path at all
// ---------------------------------------------------------------------

/// The same round trip as the first test, but with no `pq_hybrid` anywhere
/// - so there is no envelope inside the pad, the plaintext goes in
/// directly, and the decrypt verdict is the *only* authentication. The
/// nonce rides at the pad layer, so the acknowledgement works identically.
///
/// @requirement AC-250, AC-251
#[tokio::test]
async fn a_pure_otp_pair_completes_the_same_proved_round_trip() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-pure"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = pure_otp_pair("pure").await;

    send_text_as(&mut alice, &contact, KeyMode::Password, "no pq anywhere").await;
    assert!(alice.gate_held(&contact));

    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    assert_eq!(
        envelope.blocks.len(),
        1,
        "direct framing puts the plaintext in the pad, with no envelope around it"
    );
    deliver_to(&mut bob, ALICE, seq, msg_id, envelope).await;
    assert!(
        bob.ui
            .private_rooms
            .values()
            .flat_map(|r| r.log.iter())
            .any(|e| format!("{:?}", e.body).contains("no pq anywhere")),
        "the message must have reached bob's log on the verdict alone"
    );

    let (ack_seq, proof) = take_ack(&mut bob);
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");
    assert!(!alice.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::All);
}

/// And it must still refuse an ack that cannot name the message - the pad
/// is the only thing authenticating anything here, so this is the case
/// where an unverified acknowledgement would matter most.
///
/// @requirement AC-250
#[tokio::test]
async fn a_pure_otp_pair_still_refuses_an_unprovable_ack() {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe-pure-bad"),
    };
    if !require_otp(&probe) {
        return;
    }
    let (mut alice, mut bob, contact) = pure_otp_pair("pure-bad").await;

    send_text_as(&mut alice, &contact, KeyMode::Password, "no pq anywhere").await;
    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    deliver_to(&mut bob, ALICE, seq, msg_id, envelope).await;
    let (ack_seq, _) = take_ack(&mut bob);

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        ack_seq,
        [0x77; 32],
    )
    .await
    .expect("a refused ack is not an error");
    assert!(alice.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::None);
}

/// `/otp` deliberately allows a pair with no `pq_hybrid` between them, so
/// long as both have an identity that survives a reconnect
/// (`handle_otp_command`'s `uses_byte_comparison_pinning` check). Once
/// provisioned that way, an ordinary send has to actually *find* the
/// contact - otherwise the session reads as active while every message
/// quietly leaves without the pad.
///
/// @requirement AC-250
#[tokio::test]
async fn a_password_pinned_pair_is_found_by_the_send_path() {
    let me = aloo::crypto::KeyPair::generate_with_bits(SCENARIO_KEY_BITS).expect("own keygen");
    let them = aloo::crypto::KeyPair::generate_with_bits(SCENARIO_KEY_BITS).expect("peer keygen");
    let own_der = aloo::crypto::public_key_to_der(&me.public).expect("own der");
    let peer_der = aloo::crypto::public_key_to_der(&them.public).expect("peer der");

    let mut session = SessionState::for_test(TestSessionSpec {
        key_mode: KeyMode::Password,
        identity: ResolvedIdentity::Rsa(me),
        scratch: scratch("pure-otp-send"),
        otp: None,
    })
    .await;

    // Exactly the name `handle_otp_command` files this pair's pad under.
    let contact = aloo::crypto::otp::contact_name_for_keys(&own_der, &peer_der);
    session.otp_store_mut().mark_provisioned(&contact);

    assert_eq!(
        aloo::client::otp::contact_name_if_active(&session, &peer_der).as_deref(),
        Some(contact.as_str()),
        "a pure-OTP session that /otp was willing to start must be usable for sending"
    );
}
