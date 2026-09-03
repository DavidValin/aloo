//! Two real sessions, one real pad between them, and the acknowledgement
//! actually crossing from one to the other - across every combination of
//! identities the pad layer supports, and for every kind of thing it can
//! carry.
//!
//! Everything else about the nonce ack is proven in pieces elsewhere:
//! `otp_cli_test.rs` against the real binary, `otp_store_test.rs` over the
//! gate, `ui_test.rs` over the arrow. What none of those can show is the
//! wiring - that a send really does record what it is waiting for, that the
//! receive path really does put the derived proof on the wire, and that the
//! ack handler really does check it before opening anything.
//!
//! The matrix that matters, since the framing decision changes what goes
//! *inside* the pad but must never change how the acknowledgement works:
//!
//! | alice | bob | framing | what goes on the wire |
//! |---|---|---|---|
//! | pq_hybrid | pq_hybrid | `PqWrapped` | `seal(pad(payload))` |
//! | pq_hybrid | password  | `Direct`    | `pad(payload)` |
//! | password  | password  | `Direct`    | `pad(payload)` |
//!
//! The pad is innermost either way, so the framing changes what the *wire*
//! block weighs but never what the *pad* costs - which is the property
//! these tests measure directly (`Side::pad_spent`).
//!
//! No sockets are punched. Each side's link to the other is only ever
//! `ensure_link`-ed, so whatever a session decides to send waits in that
//! link's pending queue where the assertions can read it and hand it to the
//! other session by hand - which is what makes the handoff visible rather
//! than implied. The chunked file transport is stood in for the same way:
//! the staged ciphertext is copied across directly.
//!
//! @requirement AC-250, AC-251

use aloo::client::connect::ResolvedIdentity;
use aloo::client::file_transfer::{OtpIncomingFileReceive, OtpIncomingKind};
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::{DeliveryStatus, MessageBody, MessageCrypto, UiState};
use aloo::control::NullSink;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{Content, Envelope, KeyMode, UserId, UserInfo};

/// Keeps the suite quick - none of these assert anything about key size.
const SCENARIO_KEY_BITS: usize = 1024;

const ALICE: UserId = UserId(1);
const BOB: UserId = UserId(2);

/// Every scratch directory this file makes lives under one root, wiped once
/// per process.
///
/// A single run writes tens of megabytes of real pad material, and a test
/// that panics never reaches any cleanup of its own - so without this the
/// leftovers accumulate run after run until the disk fills, which is
/// exactly how this was found.
fn scratch_root() -> &'static std::path::Path {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join("aloo-otp-ack-wiring");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        root
    })
}

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = scratch_root().join(format!(
        "{label}-{}-{}",
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
/// the binary it depends on is not installed - the same fail-visibly
/// convention `otp_cli_test.rs` uses.
fn require_otp() -> bool {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("probe"),
    };
    if aloo::client::otp_cli::binary_available(&probe) {
        return true;
    }
    eprintln!("skipping: the `otp` binary is not installed");
    false
}

/// Which kind of identity one side of a pair has - the only input the
/// framing decision actually turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Id {
    /// The ordinary case: this side announces its real `pq_hybrid`
    /// keybundle, so its peer can seal and sign an inner envelope to it.
    Pq,
    /// This side is known to its peer only by a key that does not decode
    /// as a keybundle - a peer reached with no server whose identity this
    /// client cannot read (`docs/PROTOCOL.md` §16.2's `Direct` framing).
    /// Its own session still holds a real `pq_hybrid` identity, since
    /// every session does; what varies is what the *other* side has to
    /// work with.
    Opaque,
}

/// One side: its session, its UI, and who its peer is.
struct Side {
    session: SessionState,
    ui: UiState,
    peer: UserId,
    peer_der: Vec<u8>,
    otp: OtpCliConfig,
}

impl Side {
    /// Whatever this side decided to send its peer, still queued because
    /// the link was never punched.
    fn queued(&mut self) -> Vec<P2pPayload> {
        let peer = self.peer;
        self.session.sent_or_queued_payloads(peer)
    }

    /// This side's one outgoing row's delivery state - what the `->` arrow
    /// is coloured by (`DeliveryStatus::color`).
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

    /// How many pad-wrapped sends have genuinely left. `Side::queued`
    /// reads rather than drains, so counting is what says whether anything
    /// *more* went out.
    fn envelopes_sent(&mut self) -> usize {
        self.queued()
            .iter()
            .filter(|p| matches!(p, P2pPayload::OtpEnvelope { .. }))
            .count()
    }

    /// How far this side's *encryption* half of the pad has been consumed -
    /// the figure the whole pad-innermost layering exists to keep small,
    /// read straight from the binary rather than inferred from the wire.
    async fn pad_spent(&self, contact: &str) -> u64 {
        otp_cli::show_contact(&self.otp, contact)
            .await
            .expect("show-contact")
            .expect("the pair's contact exists")
            .enc_offset
    }
}

/// One real pad, split in two and filed on opposite sides under `contact` -
/// alice's encryption half is bob's decryption half and vice versa.
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

/// A built identity: the real keybundle the session runs on, plus the
/// bytes its *peer* has for it - the same bundle under `Id::Pq`, or
/// something unreadable under `Id::Opaque`.
struct Identity {
    resolved: ResolvedIdentity,
    /// What this side is announced/pinned as, from the other side's point
    /// of view. This is what `framing_for` and the contact-naming rules
    /// actually read.
    der: Vec<u8>,
}

fn identity(kind: Id, who: &str) -> Identity {
    let (public, private) =
        aloo::crypto::pq::generate_bundle_with_bits(SCENARIO_KEY_BITS).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    let der = match kind {
        Id::Pq => public_der.clone(),
        // Deterministic per side, so both ends derive one identical
        // contact name from the pair - the same thing a real unreadable
        // pin gives them.
        Id::Opaque => format!("opaque-pin-for-{who}").into_bytes(),
    };
    Identity {
        resolved: ResolvedIdentity {
            private,
            public_der,
        },
        der,
    }
}

/// Two sessions holding the two halves of one pad, each knowing the other,
/// with the OTP session already active between them.
///
/// The contact is filed under the name *both sides derive independently* -
/// from `pq` fingerprints when both have one, from the two pinned public
/// keys otherwise. Never from a nickname: see
/// `crypto::otp::contact_name_for_keys` for what that would have cost. The
/// helper asserts the two sides really do agree, since a pair that filed
/// its pad under two different names would fail in a far more confusing way
/// later.
async fn pair(label: &str, alice_kind: Id, bob_kind: Id) -> (Side, Side, String) {
    let a = identity(alice_kind, "alice");
    let b = identity(bob_kind, "bob");

    let contact = match (alice_kind, bob_kind) {
        (Id::Pq, Id::Pq) => {
            let a_fp = aloo::crypto::pq::fingerprint_of_encoded(&a.der).expect("alice fp");
            let b_fp = aloo::crypto::pq::fingerprint_of_encoded(&b.der).expect("bob fp");
            // Both sides run under `SessionState::for_test`'s fixed own
            // device_id, so both halves of this pair use that same literal.
            aloo::crypto::otp::contact_name_for(&a_fp, "test-device", &b_fp, "test-device")
        }
        _ => aloo::crypto::otp::contact_name_for_keys(&a.der, &b.der),
    };
    let (alice_cfg, bob_cfg) = split_one_pad(label, &contact).await;

    // Each side is built with the *pinned* bytes for the other, and with
    // its own identity replaced by those bytes too where this side is
    // `Opaque` - which is what makes the pair's view of each other
    // symmetric, exactly as two real clients pinning each other would be.
    let alice = build_side(
        "alice", ALICE, a.resolved, a.der.clone(), BOB, "bob", b.der.clone(), alice_cfg, &contact,
        label,
    )
    .await;
    let bob = build_side(
        "bob", BOB, b.resolved, b.der, ALICE, "alice", a.der, bob_cfg, &contact, label,
    )
    .await;

    // Both sides must find the same contact, with nothing negotiated.
    for (side, who) in [(&alice, "alice"), (&bob, "bob")] {
        assert_eq!(
            aloo::client::otp::contact_name_if_active(&side.session, side.peer, &side.peer_der).as_deref(),
            Some(contact.as_str()),
            "{who} must find this pair's provisioned pad, or every send \
             would silently leave without it"
        );
    }
    (alice, bob, contact)
}

#[allow(clippy::too_many_arguments)]
async fn build_side(
    own_name: &str,
    own_id: UserId,
    own_identity: ResolvedIdentity,
    own_pinned_der: Vec<u8>,
    peer_id: UserId,
    peer_name: &str,
    peer_der: Vec<u8>,
    otp: OtpCliConfig,
    contact: &str,
    label: &str,
) -> Side {
    let otp_cfg = otp.clone();
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: own_identity,
        scratch: scratch(&format!("{label}-{own_name}")),
        otp: Some(otp),
    })
    .await;
    // Stands in for what the *peer* has pinned for us: under `Id::Opaque`
    // that is not our keybundle, which is exactly what drops this pair to
    // `Direct` framing on both sides.
    session.set_own_pinned_der_for_test(own_pinned_der);
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
    // A pair this helper builds already has a working pad and can already
    // send each other messages, so the direct link between them is - by
    // definition - up; individual tests modeling a peer going unreachable
    // override this explicitly.
    ui.set_link_status(peer_id, aloo::client::p2p::LinkStatus::Active);
    // Exactly what the real connect path does when a peer becomes known -
    // without it there is no encryption key to seal an inner envelope to.
    aloo::client::session::seed_direct_peer_keys(&mut session, peer_id, &peer);
    // Stands in for the peer's real `DeviceIdAnnounce` - both sides use
    // `SessionState::for_test`'s own fixed device_id, so this is simply
    // that same literal from the peer's point of view (device-pinning
    // plan §4's `PqWrapped` naming needs both device_ids resolved).
    session.set_peer_device_id_for_test(peer_id, "test-device".to_string());
    // Opens the link record each side queues against. Nothing is punched,
    // so nothing leaves the machine - but without it a session has nowhere
    // to put what it decides to send, and it is silently dropped.
    session
        .peer_link_mut()
        .ensure_link(&mut NullSink, peer_id)
        .await;
    Side {
        session,
        ui,
        peer: peer_id,
        peer_der,
        otp: otp_cfg,
    }
}

// ---------------------------------------------------------------------
// Driving one send of each kind
// ---------------------------------------------------------------------

async fn send_text(side: &mut Side, contact: &str, text: &str) -> u64 {
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

async fn send_file(side: &mut Side, contact: &str, path: std::path::PathBuf, size: u64) {
    let peer_der = side.peer_der.clone();
    aloo::client::otp::send_file_offer(
        &mut NullSink,
        &mut side.session,
        &mut side.ui,
        side.peer,
        contact,
        &peer_der,
        path,
        "notes.txt".to_string(),
        size,
    )
    .await
    .expect("the file offer path should not fail");
}

async fn send_voice(side: &mut Side, contact: &str, pcm: Vec<u8>) {
    let peer_der = side.peer_der.clone();
    aloo::client::otp::send_voice_offer(
        &mut NullSink,
        &mut side.session,
        &mut side.ui,
        side.peer,
        contact,
        &peer_der,
        pcm,
        1500,
    )
    .await
    .expect("the voice offer path should not fail");
}

// ---------------------------------------------------------------------
// Reading what went out
// ---------------------------------------------------------------------

fn take_envelope(side: &mut Side) -> (u64, Option<u64>, Envelope, String) {
    side.queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .expect("a pad-wrapped message should have gone out")
}

fn take_file_offer(side: &mut Side) -> (u64, u64, Envelope, String) {
    side.queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileOffer {
                stream_id,
                seq,
                envelope,
                sender_device_id,
                ..
            } => Some((stream_id, seq, envelope, sender_device_id)),
            _ => None,
        })
        .expect("a pad-wrapped file offer should have gone out")
}

fn take_voice_offer(side: &mut Side) -> (u64, u64, Envelope, String) {
    side.queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpVoiceOffer {
                stream_id,
                seq,
                envelope,
                sender_device_id,
                ..
            } => Some((stream_id, seq, envelope, sender_device_id)),
            _ => None,
        })
        .expect("a pad-wrapped voice offer should have gone out")
}

/// The acks this side has queued, oldest first - a file transfer produces
/// two over its life (offer, then content), so they cannot be looked up as
/// "the one ack".
fn last_ack(side: &mut Side) -> (u64, [u8; 32]) {
    side.queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .next_back()
        .expect("an acknowledgement should have gone out")
}

async fn ack(to: &mut Side, from: UserId, seq: u64, proof: [u8; 32]) {
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut to.ui,
        &mut to.session,
        from,
        seq,
        proof,
    )
    .await
    .expect("the ack path should never be an error, refused or not");
}

async fn receive_text(
    bob: &mut Side,
    seq: u64,
    msg_id: Option<u64>,
    envelope: Envelope,
    sender_device_id: String,
) {
    aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        seq,
        msg_id,
        envelope,
        sender_device_id,
    )
    .await
    .expect("the receive path should not fail");
}

// ---------------------------------------------------------------------
// The framing matrix, over a text message
// ---------------------------------------------------------------------

/// The whole chain for one pairing: alice sends and closes her gate, bob
/// decrypts and answers with a proof he could only have derived by
/// decrypting, alice checks it, and only then does her gate open and her
/// arrow turn green. Then the same ack with an invented proof, which must
/// change nothing.
async fn text_round_trip(label: &str, alice_kind: Id, bob_kind: Id, direct: bool) {
    let (mut alice, mut bob, contact) = pair(label, alice_kind, bob_kind).await;

    send_text(&mut alice, &contact, "meet me at six").await;
    assert!(
        alice.gate_held(&contact),
        "the send must close the gate behind it"
    );
    assert_eq!(alice.arrow(), DeliveryStatus::None);

    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    // The pad goes on the message and the seal goes around the pad, so the
    // pad costs about the length of the line under *both* framings - the
    // ~6.4KB of ML-DSA/ML-KEM/RSA a sealed envelope weighs never touches
    // it. Before the layering was inverted this same message cost the pad
    // the whole envelope.
    let spent = alice.pad_spent(&contact).await;
    assert!(
        spent < 200,
        "the pad should only ever cover the message itself, spent {spent}"
    );
    let on_wire = envelope.blocks.first().map(|b| b.len()).unwrap_or(0);
    if direct {
        // Within framing overhead of the spend itself: there is no seal
        // around it, so the wire block *is* the pad ciphertext.
        assert!(
            on_wire as u64 <= spent + 64,
            "direct framing adds nothing around the pad, {on_wire} on the wire for {spent} spent"
        );
    } else {
        assert!(
            on_wire > 5000,
            "the seal is the outer layer now, so the wire block carries it, {on_wire}"
        );
    }

    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    assert!(
        bob.ui
            .private_rooms
            .values()
            .flat_map(|r| r.log.iter())
            .any(|e| format!("{:?}", e.body).contains("meet me at six")),
        "the message must have reached bob's log"
    );

    // No ordinary receipt: it would repeat, unprovenly, what the ack says.
    assert!(
        !bob.queued()
            .iter()
            .any(|p| matches!(p, P2pPayload::DeliveryReceipt { .. })),
        "a redundant receipt must not go out alongside the ack"
    );

    let (ack_seq, proof) = last_ack(&mut bob);
    assert_eq!(ack_seq, seq, "the ack names the message it answers");

    // Failed first: an observer could read `seq` off the wire, but not the
    // nonce that was under the pad.
    ack(&mut alice, BOB, ack_seq, [0xAB; 32]).await;
    assert!(
        alice.gate_held(&contact),
        "an unprovable ack must leave the message outstanding"
    );
    assert_eq!(
        alice.arrow(),
        DeliveryStatus::None,
        "and must not let the row claim it was delivered"
    );

    // Then the genuine one - refusing is not a wedge.
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(!alice.gate_held(&contact), "a proved ack opens the gate");
    assert_eq!(alice.arrow(), DeliveryStatus::All);
}

/// Both sides `pq_hybrid`: the pad wraps a sealed, signed envelope, and the
/// nonce rides underneath it.
///
/// @requirement AC-250, AC-251, AC-260
#[tokio::test]
async fn text_both_pq_hybrid_wraps_an_envelope_and_still_proves_its_ack() {
    if !require_otp() {
        return;
    }
    text_round_trip("text-pq-pq", Id::Pq, Id::Pq, false).await;
}

/// Only one side has `pq_hybrid`, so there is no envelope both could agree
/// on - the plaintext goes straight in the pad and the decrypt verdict is
/// the whole of the authentication.
///
/// @requirement AC-250, AC-251, AC-252
#[tokio::test]
async fn text_one_pq_hybrid_side_falls_to_direct_and_still_proves_its_ack() {
    if !require_otp() {
        return;
    }
    text_round_trip("text-pq-pw", Id::Pq, Id::Opaque, true).await;
}

/// Neither side has `pq_hybrid` - pure OTP, pinned RSA identities, pad
/// bound to those keys.
///
/// @requirement AC-250, AC-251, AC-252, AC-260
#[tokio::test]
async fn text_no_pq_hybrid_anywhere_uses_direct_and_still_proves_its_ack() {
    if !require_otp() {
        return;
    }
    text_round_trip("text-pw-pw", Id::Opaque, Id::Opaque, true).await;
}

/// The mixed pairing the other way round, since the framing decision is
/// made independently on each side and must land the same either way.
///
/// @requirement AC-250, AC-252
#[tokio::test]
async fn text_the_mixed_pairing_is_symmetric() {
    if !require_otp() {
        return;
    }
    text_round_trip("text-pw-pq", Id::Opaque, Id::Pq, true).await;
}

// ---------------------------------------------------------------------
// The framing matrix, over a file transfer
// ---------------------------------------------------------------------

/// A file is *two* independent pad spends, each with its own proof: the
/// offer (a nonce under the pad, like a text message) and then the content
/// (the file's own plaintext digest, since the user's bytes leave no room
/// to bury a nonce). Both gates, both proofs, and the refusal of each.
async fn file_round_trip(label: &str, alice_kind: Id, bob_kind: Id, direct: bool) {
    let (mut alice, mut bob, contact) = pair(label, alice_kind, bob_kind).await;

    let dir = scratch(&format!("{label}-payload"));
    let source = dir.join("notes.txt");
    let body = b"the quick brown fox, several times over, for good measure";
    std::fs::write(&source, body).unwrap();

    // --- offer phase (pad spend A) ---
    send_file(&mut alice, &contact, source.clone(), body.len() as u64).await;
    assert!(alice.gate_held(&contact), "the offer is a real pad spend");

    let (stream_id, offer_seq, offer_env, offer_env_device) = take_file_offer(&mut alice);
    if direct {
        assert_eq!(
            offer_env.blocks.len(),
            1,
            "direct framing carries the encoded offer with no envelope around it"
        );
    }

    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        stream_id,
        offer_seq,
        offer_env,
        offer_env_device,
    )
    .await;
    let (a_seq, a_proof) = last_ack(&mut bob);
    assert_eq!(a_seq, offer_seq);

    ack(&mut alice, BOB, a_seq, [0x01; 32]).await;
    assert!(
        alice.gate_held(&contact),
        "an unprovable ack must not close the offer's slot"
    );
    ack(&mut alice, BOB, a_seq, a_proof).await;
    assert!(!alice.gate_held(&contact));

    // --- content phase (pad spend B, its own independent slot) ---
    aloo::client::otp::start_outgoing_file_content(&mut alice.session, &mut alice.ui, stream_id)
        .await
        .expect("the content phase should not fail");
    assert!(
        alice.gate_held(&contact),
        "the content is a second, wholly separate spend"
    );
    let content_seq = alice
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileContentSeq { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the content phase names its own slot");
    assert_ne!(
        content_seq, offer_seq,
        "the two phases must never share one slot"
    );

    // Stands in for the chunked transport: the staged ciphertext is what
    // would have travelled, so it is what bob decrypts.
    let staged = alice
        .session
        .otp_send_temp_file(stream_id)
        .expect("the content phase stages its ciphertext")
        .clone();
    let arrived = dir.join("arrived.otp");
    std::fs::copy(&staged, &arrived).unwrap();

    let final_path = dir.join("downloaded.txt");
    aloo::client::otp::finish_incoming_file(
        &mut bob.session,
        &mut bob.ui,
        ALICE,
        stream_id,
        OtpIncomingFileReceive {
            contact_name: contact.clone(),
            seq: Some(content_seq),
            temp_path: arrived,
            kind: OtpIncomingKind::File {
                final_path: final_path.clone(),
            },
        },
    )
    .await;
    assert_eq!(
        std::fs::read(&final_path).unwrap(),
        body,
        "the file must come out of the pad byte-identical"
    );

    let (b_seq, b_proof) = last_ack(&mut bob);
    assert_eq!(b_seq, content_seq);
    ack(&mut alice, BOB, b_seq, [0x02; 32]).await;
    assert!(
        alice.gate_held(&contact),
        "the content phase's gate is no less strict than the offer's"
    );
    ack(&mut alice, BOB, b_seq, b_proof).await;
    assert!(!alice.gate_held(&contact));

    // --- and a retried content announcement is re-answered, not dropped ---
    // The sender retries `OtpFileContentSeq` when the content's ack was
    // lost; with the slot already consumed, the durable record answers it
    // at no cost, exactly as for any other repeated spend.
    let acks_before = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();
    aloo::client::otp::on_content_seq(&mut bob.session, &mut bob.ui, ALICE, stream_id, content_seq)
        .await;
    let acks_after = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();
    assert_eq!(
        acks_after,
        acks_before + 1,
        "a retried content announcement whose ack was lost is re-answered from the record"
    );
    let (reack_seq, reack_proof) = last_ack(&mut bob);
    assert_eq!(reack_seq, content_seq);
    assert_eq!(
        reack_proof, b_proof,
        "and with the very same proof the original acceptance derived"
    );

    // --- and the conversation must simply continue afterwards ---
    // The content spend consumed a slot in the same, single sequence space
    // everything shares; if the receiving side's expectation did not move
    // past it, the very next ordinary message would be silently dropped as
    // out-of-order, wedging the pair for good.
    send_text(&mut alice, &contact, "did the file make it?").await;
    let (seq, msg_id, envelope, envelope_device) = alice
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the follow-up text should have gone out");
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let delivered = bob
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "did the file make it?"));
    assert!(
        delivered,
        "a text following a completed file transfer must still be accepted - the content \
         spend advances the receiver's expectation like every other slot"
    );
}

/// @requirement AC-250
#[tokio::test]
async fn file_both_pq_hybrid_proves_both_of_its_spends() {
    if !require_otp() {
        return;
    }
    file_round_trip("file-pq-pq", Id::Pq, Id::Pq, false).await;
}

/// One side has no readable keybundle, so both the offer and the content
/// go under `Direct` framing - the content's chunks carry the pad
/// ciphertext verbatim, since the file was already encrypted whole before
/// the first chunk left.
///
/// @requirement AC-250, AC-252
#[tokio::test]
async fn file_one_pq_hybrid_side_proves_both_of_its_spends() {
    if !require_otp() {
        return;
    }
    file_round_trip("file-pq-direct", Id::Pq, Id::Opaque, true).await;
}

/// Neither side has one - pure OTP, both spends still proved.
///
/// @requirement AC-250, AC-252
#[tokio::test]
async fn file_no_pq_hybrid_anywhere_proves_both_of_its_spends() {
    if !require_otp() {
        return;
    }
    file_round_trip("file-direct-direct", Id::Opaque, Id::Opaque, true).await;
}

// ---------------------------------------------------------------------
// The framing matrix, over a voice message
// ---------------------------------------------------------------------

/// A voice message is one spend, not two - there is no accept step to defer
/// content encryption behind, so the offer and the content share a slot.
/// Its proof is the PCM's own digest, for the same reason a file's content
/// phase uses one.
async fn voice_round_trip(label: &str, alice_kind: Id, bob_kind: Id, direct: bool) {
    let (mut alice, mut bob, contact) = pair(label, alice_kind, bob_kind).await;
    // Queueing off: this drives the *unqueued* two-phase protocol by hand
    // (offer, accept, then `start_outgoing_file_content`'s own encrypt).
    // With the queue on the recording is sealed at record time and
    // released by the pump instead - the queued tests below cover that
    // shape.
    alice.session.set_queue_send_messages(false);
    bob.session.set_queue_send_messages(false);
    let pcm: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();

    send_voice(&mut alice, &contact, pcm.clone()).await;
    assert!(alice.gate_held(&contact));

    let (stream_id, seq, envelope, envelope_device) = take_voice_offer(&mut alice);
    assert_eq!(envelope.blocks.len(), 1);
    if direct {
        // Padded either way, so the duration never travels in the clear -
        // which under `Direct` is the only thing protecting it.
        assert!(
            !envelope.blocks[0].is_empty(),
            "the offer goes through the pad, not on the wire as it stands"
        );
    }

    aloo::client::otp::on_voice_offer(
        &mut NullSink,
        &mut bob.session,
        &mut bob.ui,
        ALICE,
        stream_id,
        seq,
        envelope,
        envelope_device,
    )
    .await;
    let pending = bob
        .session
        .take_otp_incoming_receive(ALICE, stream_id)
        .expect("the voice offer must register an arriving transfer");
    assert!(
        matches!(pending.kind, OtpIncomingKind::Voice { duration_ms } if duration_ms == 1500),
        "the offer's payload must have been read, whichever framing carried it"
    );
    assert!(
        pending.seq.is_none(),
        "the recording's own slot is not named until the sender reserves it"
    );

    // The offer is a real pad spend of its own, acknowledged the moment it
    // opens - exactly like a file offer's, and what keeps `duration_ms`
    // out of the clear under `Direct`.
    let (offer_ack_seq, offer_proof) = last_ack(&mut bob);
    assert_eq!(offer_ack_seq, seq);
    ack(&mut alice, BOB, offer_ack_seq, [0x03; 32]).await;
    assert!(
        alice.gate_held(&contact),
        "an unprovable ack must not close the offer's slot"
    );
    ack(&mut alice, BOB, offer_ack_seq, offer_proof).await;
    assert!(!alice.gate_held(&contact));

    // --- content phase (pad spend B, its own independent slot) ---
    aloo::client::otp::start_outgoing_file_content(&mut alice.session, &mut alice.ui, stream_id)
        .await
        .expect("the recording's own phase should not fail");
    assert!(
        alice.gate_held(&contact),
        "the recording is a second, wholly separate spend"
    );
    let content_seq = alice
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileContentSeq { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the recording names its own slot");
    assert_ne!(
        content_seq, seq,
        "the offer and the recording must never share one slot"
    );

    // Stands in for the chunked transport, which `voice_stream_test.rs`
    // covers directly: the staged ciphertext is what would have travelled.
    let staged = alice
        .session
        .otp_send_temp_file(stream_id)
        .expect("the recording's phase stages its ciphertext")
        .clone();
    let arrived = scratch(&format!("{label}-arrived")).join("voice.otp");
    std::fs::copy(&staged, &arrived).unwrap();

    aloo::client::otp::finish_incoming_file(
        &mut bob.session,
        &mut bob.ui,
        ALICE,
        stream_id,
        OtpIncomingFileReceive {
            temp_path: arrived,
            seq: Some(content_seq),
            ..pending
        },
    )
    .await;
    assert!(
        bob.ui
            .private_rooms
            .values()
            .flat_map(|r| r.log.iter())
            .any(|e| matches!(&e.body, MessageBody::Voice { pcm: got, .. } if got == &pcm)),
        "the recording must come out of the pad byte-identical"
    );

    let (ack_seq, proof) = last_ack(&mut bob);
    assert_eq!(ack_seq, content_seq);
    ack(&mut alice, BOB, ack_seq, [0x04; 32]).await;
    assert!(alice.gate_held(&contact));
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(!alice.gate_held(&contact));
}

/// @requirement AC-250
#[tokio::test]
async fn voice_both_pq_hybrid_proves_its_spend() {
    if !require_otp() {
        return;
    }
    voice_round_trip("voice-pq-pq", Id::Pq, Id::Pq, false).await;
}

/// A voice message's audio rides the same chunk transport a file's content
/// does, so `Direct` carries it the same way: pad ciphertext verbatim.
///
/// @requirement AC-250, AC-252
#[tokio::test]
async fn voice_one_pq_hybrid_side_proves_its_spend() {
    if !require_otp() {
        return;
    }
    voice_round_trip("voice-pq-direct", Id::Pq, Id::Opaque, true).await;
}

/// @requirement AC-250, AC-252
#[tokio::test]
async fn voice_no_pq_hybrid_anywhere_proves_its_spend() {
    if !require_otp() {
        return;
    }
    voice_round_trip("voice-direct-direct", Id::Opaque, Id::Opaque, true).await;
}

// ---------------------------------------------------------------------
// Mail
// ---------------------------------------------------------------------

/// OTP mail is `pq_hybrid`-only by design, and this is the check that says
/// so out loud.
///
/// Mail is the one spend nobody can prove to the sender: it is stored by
/// the server and acknowledged by the server, which holds no pad. What
/// binds it to a sender instead is an ML-DSA signature over the payload
/// (`crypto::pq::sign_mail`), and a pure-OTP pair has no signing identity
/// to produce one with. So rather than fall back to something weaker, the
/// recipient check refuses - visibly, before any pad is spent. It refuses
/// as `NotPinned`, since an unreadable pin is exactly what it is.
///
/// @requirement AC-250, AC-252
#[tokio::test]
async fn mail_refuses_a_pure_otp_pair_rather_than_falling_back() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("mail-pw-pw", Id::Opaque, Id::Opaque).await;
    assert!(
        matches!(
            // No pq_hybrid pin exists at all for a pure-OTP pair, so which
            // device_id is named here doesn't matter - every one still
            // reads as `NotPinned`.
            aloo::client::otp_mail::check_recipient(&alice.session, "bob", "any-device").await,
            aloo::client::otp_mail::RecipientCheck::NotPinned
        ),
        "a pad alone cannot carry an offline mail's sender binding, and \
         refusing is the only honest answer"
    );
    assert!(
        !alice.gate_held(&contact),
        "and the refusal must cost no pad"
    );
}

// ---------------------------------------------------------------------
// A serverless, pad-only pair (AC-259)
// ---------------------------------------------------------------------

/// The scenario this whole `Direct` path exists for: two peers who reach
/// each other by direct punch, hold a one-time pad for each other, and
/// have no `pq_hybrid` identity of each other at all - no server ever
/// introduced them, so neither has the other's keybundle.
///
/// Built without pre-seeding `known_users`: registering them is exactly
/// what is under test. One side is introduced by its link coming up
/// (`session::register_pad_only_peer`), the other by the pad opening the
/// first message that arrives (`otp::otp_sender_of` +
/// `adopt_pad_verified_sender`).
/// What a serverless peer is pinned under: not a keybundle, because there
/// is none to have learned. This is the `id_store` entry a hand-installed
/// contact leaves (`/contacts` `o`).
fn opaque_pin(who: &str) -> Vec<u8> {
    format!("pad-only-pin-for-{who}").into_bytes()
}

#[allow(clippy::too_many_arguments)]
async fn pad_only_side(
    label: &str,
    own_name: &str,
    own_id: UserId,
    peer_name: &str,
    otp: OtpCliConfig,
    contact: &str,
) -> Side {
    let otp_cfg = otp.clone();
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: identity(Id::Pq, own_name).resolved,
        scratch: scratch(&format!("{label}-{own_name}")),
        otp: Some(otp),
    })
    .await;
    // What the *peer* has pinned for us, and what we have pinned for them:
    // neither decodes as a keybundle, which is what makes this pair
    // `Direct` from both sides.
    session.set_own_pinned_der_for_test(opaque_pin(own_name));
    session.id_store_mut().pin_new_device(
        peer_name,
        "test-device",
        &opaque_pin(peer_name),
        aloo::client::idstore::Trust::Tofu,
    );
    session.otp_store_mut().mark_provisioned(contact);

    // No server anywhere: the only thing that makes this peer addressable
    // is a `direct_punch_to` entry naming them, which is also where their
    // nickname comes from (`p2p::direct_nickname_of`).
    session.peer_link_mut().configure_direct_punch(
        own_name.to_string(),
        vec![aloo::settings::DirectPunchTarget {
            nickname: peer_name.to_string(),
            device_id: None,
            host: "127.0.0.1".to_string(),
            ports: vec![19000],
            frequency: aloo::settings::PunchFrequency::parse("every_1m").expect("valid"),
        }],
        0,
    );
    // Somewhere for a send to queue. Never punched, so nothing leaves the
    // machine and every assertion below reads what this side *decided* to
    // send (`SessionState::for_test`'s own convention).
    let peer = aloo::client::p2p::direct_peer_id(peer_name, None);
    session.peer_link_mut().open_unpunched_link_for_test(peer);

    let mut ui = UiState::new(own_name.into());
    ui.set_own_id(own_id);
    Side {
        session,
        ui,
        peer,
        peer_der: opaque_pin(peer_name),
        otp: otp_cfg,
    }
}

/// @requirement AC-259
#[tokio::test]
async fn a_serverless_pad_only_pair_registers_and_talks_without_any_pq_hybrid_identity() {
    if !require_otp() {
        return;
    }
    let contact = aloo::crypto::otp::contact_name_for_keys(&opaque_pin("alice"), &opaque_pin("bob"));
    let (alice_cfg, bob_cfg) = split_one_pad("pad-only", &contact).await;
    let mut alice = pad_only_side("pad-only", "alice", ALICE, "bob", alice_cfg, &contact).await;
    let mut bob = pad_only_side("pad-only", "bob", BOB, "alice", bob_cfg, &contact).await;

    // Both sides derive the same contact from the two pins, with nothing
    // negotiated - the whole basis of a pad-only pair.
    for (side, who) in [(&alice, "alice"), (&bob, "bob")] {
        assert_eq!(
            aloo::client::otp::contact_name_if_active(&side.session, side.peer, &side.peer_der).as_deref(),
            Some(contact.as_str()),
            "{who} must find this pair's pad"
        );
    }

    // --- alice's link to bob comes up: the pad is what introduces him ---
    assert!(
        !alice.ui.known_users.contains_key(&alice.peer),
        "nobody has introduced bob yet"
    );
    aloo::client::session::register_pad_only_peer(&mut alice.session, &mut alice.ui, alice.peer);
    assert!(
        alice.ui.known_users.contains_key(&alice.peer),
        "an installed pad stands in for the handshake a keybundle would have run"
    );
    assert!(
        alice.ui.is_otp_active(alice.peer),
        "there is no session left to negotiate - the pad is already shared"
    );

    // --- alice sends, with no pq_hybrid identity of bob anywhere ---
    let msg_id = send_text(&mut alice, &contact, "no server, no keybundle, still private").await;
    assert!(alice.gate_held(&contact), "the send really spent pad");
    let (seq, _, envelope, envelope_device) = take_envelope(&mut alice);
    assert_eq!(
        envelope.blocks.len(),
        1,
        "direct framing puts the message straight in the pad, with no envelope around it"
    );

    // --- bob has never heard of alice: the pad introduces her ---
    assert!(
        !bob.ui.known_users.contains_key(&bob.peer),
        "bob has no reason to know alice yet"
    );
    aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        bob.peer,
        "alice".into(),
        seq,
        Some(msg_id),
        envelope,
        envelope_device,
    )
    .await
    .expect("bob's receive path should not fail");

    assert!(
        bob.ui.known_users.contains_key(&bob.peer),
        "opening the message is what proves who sent it, and registers them"
    );
    let body = bob.ui.private_rooms[&bob.peer]
        .log
        .iter()
        .find_map(|e| match &e.body {
            MessageBody::Text(t) => Some(t.clone()),
            _ => None,
        })
        .expect("the message landed in alice's room");
    assert_eq!(body, "no server, no keybundle, still private");

    // --- and bob's ack, which he could only produce by decrypting it ---
    let ack = bob
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .expect("bob acknowledges what he read");
    assert_eq!(ack.0, seq, "the ack names the message it opened");

    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        alice.peer,
        ack.0,
        ack.1,
    )
    .await
    .expect("alice's ack path should not fail");
    assert!(
        !alice.gate_held(&contact),
        "a proof alice can verify is what reopens her gate"
    );

    // --- and bob can answer, which needs him registered to address her ---
    let reply = send_text(&mut bob, &contact, "received").await;
    let (reply_seq, _, reply_env, reply_env_device) = take_envelope(&mut bob);
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        alice.peer,
        "bob".into(),
        reply_seq,
        Some(reply),
        reply_env,
        reply_env_device,
    )
    .await
    .expect("alice's receive path should not fail");
    let back = alice.ui.private_rooms[&alice.peer]
        .log
        .iter()
        .find_map(|e| match &e.body {
            MessageBody::Text(t) if t == "received" => Some(t.clone()),
            _ => None,
        });
    assert_eq!(back.as_deref(), Some("received"), "the pair talks both ways");
}

// ---------------------------------------------------------------------
// Cross-cutting
// ---------------------------------------------------------------------

/// An ack naming a sequence that is not the one outstanding proves nothing
/// about the one that is, however genuine its proof.
///
/// @requirement AC-250
#[tokio::test]
async fn an_acknowledgement_for_a_different_sequence_does_not_open_this_gate() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("seq", Id::Pq, Id::Pq).await;
    send_text(&mut alice, &contact, "meet me at six").await;
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let (_, proof) = last_ack(&mut bob);

    ack(&mut alice, BOB, seq + 1, proof).await;
    assert!(alice.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::None);
}

/// While the gate is held nothing more may be encrypted, so a message typed
/// meanwhile waits rather than spending pad - and is released by the proved
/// ack, not by the unprovable one.
///
/// @requirement AC-250, AC-137
#[tokio::test]
async fn a_queued_message_is_released_only_by_an_ack_that_proves_itself() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("queue", Id::Pq, Id::Pq).await;

    send_text(&mut alice, &contact, "first").await;
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    assert_eq!(alice.envelopes_sent(), 1);

    send_text(&mut alice, &contact, "second").await;
    assert_eq!(
        alice.envelopes_sent(),
        1,
        "the second message must wait behind the first rather than spend pad"
    );

    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let (ack_seq, proof) = last_ack(&mut bob);

    ack(&mut alice, BOB, ack_seq, [0x11; 32]).await;
    assert_eq!(
        alice.envelopes_sent(),
        1,
        "an unprovable ack must not release the queued message"
    );

    ack(&mut alice, BOB, ack_seq, proof).await;
    assert_eq!(
        alice.envelopes_sent(),
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
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("both", Id::Pq, Id::Pq).await;

    // Crossing in flight: each sends before either has received.
    send_text(&mut alice, &contact, "from alice").await;
    send_text(&mut bob, &contact, "from bob").await;
    let (a_seq, a_msg, a_env, a_env_device) = take_envelope(&mut alice);
    let (b_seq, b_msg, b_env, b_env_device) = take_envelope(&mut bob);

    receive_text(&mut bob, a_seq, a_msg, a_env, a_env_device).await;
    assert!(
        bob.gate_held(&contact),
        "receiving proves who they are, not that bob's own message arrived"
    );
    assert_eq!(bob.arrow(), DeliveryStatus::None);

    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        b_seq,
        b_msg,
        b_env,
        b_env_device,
    )
    .await
    .expect("the receive path should not fail");

    let (b_ack_seq, b_proof) = last_ack(&mut bob);
    let (a_ack_seq, a_proof) = last_ack(&mut alice);
    ack(&mut alice, BOB, b_ack_seq, b_proof).await;
    ack(&mut bob, ALICE, a_ack_seq, a_proof).await;

    assert!(!alice.gate_held(&contact));
    assert!(!bob.gate_held(&contact));
    assert_eq!(alice.arrow(), DeliveryStatus::All);
    assert_eq!(bob.arrow(), DeliveryStatus::All);
}

// ---------------------------------------------------------------------
// The framing matrix, over the session-control payloads
// ---------------------------------------------------------------------

/// Hands a queued `OtpEnvelope` to the other side, whoever they are - the
/// control payloads travel in both directions, unlike a text message.
async fn deliver_envelope(to: &mut Side, from: UserId, from_name: &str, side: &mut Side) {
    let (seq, msg_id, envelope, envelope_device) = take_envelope(side);
    aloo::client::otp::on_message(
        &mut to.session,
        &mut to.ui,
        None,
        from,
        from_name.into(),
        seq,
        msg_id,
        envelope,
        envelope_device,
    )
    .await
    .expect("the receive path should not fail");
}

/// `/endotp` and the notice it owes the peer, under one framing.
///
/// Ending a session is something said to this contact like anything else,
/// so it goes under their pad - which for a `Direct` pair is the only way
/// it can be said at all, there being no envelope to seal it into. And it
/// is an *ordinary* stop-and-wait send in every mechanical respect: it arms
/// the gate behind it, and the peer confirms it with the same
/// proof-carrying `OtpDeliveryAck` every message earns. The whole operation
/// is two-phase: the initiator's own side stays fully in the session until
/// that confirmation arrives - only then do both sides stand paused, in
/// sync.
async fn end_session_round_trip(label: &str, alice_kind: Id, bob_kind: Id) {
    let (mut alice, mut bob, contact) = pair(label, alice_kind, bob_kind).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    let before = alice.pad_spent(&contact).await;
    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");

    assert!(
        alice.pad_spent(&contact).await > before,
        "the notice is a real pad spend, not a plaintext aside"
    );
    assert!(
        alice.gate_held(&contact),
        "an ordinary stop-and-wait send now: the gate closes behind the notice, and only \
         the peer's proof-carrying ack reopens it - anything less let a later spend \
         overwrite its recovery copy or leapfrog it on the pad"
    );
    assert_eq!(
        alice.envelopes_sent(),
        1,
        "the notice goes out padded, not as a bare pq_hybrid envelope"
    );
    assert!(
        alice.ui.is_otp_active(BOB),
        "two-phase: the end takes no local effect before the peer confirms it"
    );
    let (message, _) = alice.ui.status_notice.clone().expect("progress is announced");
    assert!(
        message.contains("waiting for") && message.contains("confirm"),
        "the user is told the end awaits confirmation: {message:?}"
    );

    deliver_envelope(&mut bob, ALICE, "alice", &mut alice).await;
    assert!(
        !bob.ui.is_otp_active(ALICE),
        "the peer converges to paused on receiving it"
    );
    assert!(
        !bob.gate_held(&contact),
        "the OtpDeliveryAck it answers with costs bob nothing and arms nothing"
    );

    // The proof-carrying ack comes back and settles everything at once:
    // the gate, the durable retry debt, and - the two-phase design's whole
    // point - the initiator's own pause.
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| s.pending_end_notice),
        "until the ack lands, the notice is still owed"
    );
    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(
        !alice.gate_held(&contact),
        "the proof opened the gate exactly as a message's ack would"
    );
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice),
        "the ack is what finally stops the retry"
    );
    assert!(
        !alice.ui.is_otp_active(BOB),
        "and only now does the initiator's own side pause - both ends in sync"
    );
    let (message, _) = alice.ui.status_notice.clone().expect("the end is announced");
    assert!(
        message.contains("confirmed by"),
        "the confirmation names itself: {message:?}"
    );
}

/// Both sides `pq_hybrid`: `seal(pad(notice))`.
///
/// @requirement AC-260
#[tokio::test]
async fn end_session_both_pq_hybrid_travels_under_the_pad() {
    if !require_otp() {
        return;
    }
    end_session_round_trip("end-pq-pq", Id::Pq, Id::Pq).await;
}

/// A pad-only pair: `pad(notice)`, which is the only shape that can carry
/// it - before this, `/endotp` on such a pair tore the session down
/// locally and the peer was never told at all.
///
/// @requirement AC-260, AC-252
#[tokio::test]
async fn end_session_no_pq_hybrid_anywhere_still_reaches_the_peer() {
    if !require_otp() {
        return;
    }
    end_session_round_trip("end-pw-pw", Id::Opaque, Id::Opaque).await;
}

/// The exact bug `/endotp` used to have for a `PqWrapped` pair:
/// `contact_name_if_active` alone (what every send-gating call site used
/// to check) only ever asked "is a pad provisioned here", which
/// `/endotp`'s own pause deliberately never clears - so text, voice, file
/// sends, and `/call`'s own eligibility check all kept believing a paused
/// session was still live, forever. `contact_name_for_sending` is what
/// fixes that: it also consults `UiState::is_otp_active`, which
/// `/endotp` *does* clear, so a pair with pq_hybrid to fall back to stops
/// routing new sends through the pad the moment it pauses - while the pad
/// itself stays provisioned underneath, exactly as documented (`/otp`
/// with the same contact later resumes it).
///
/// @requirement AC-303
#[tokio::test]
async fn a_send_after_endotp_no_longer_rides_the_paused_pad() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-send-gate", Id::Pq, Id::Pq).await;
    // `pair()`/`build_side()` provision the pad directly without going
    // through the real handshake, so - unlike a session actually reached
    // via `/otp` - the live toggle isn't set yet; set it here to model
    // what a genuinely active session looks like before ending it.
    alice.ui.mark_otp_active(BOB);

    assert_eq!(
        aloo::client::otp::contact_name_for_sending(&alice.session, &alice.ui, BOB, &alice.peer_der),
        Some(contact.clone()),
        "while active, a new send still rides the pad"
    );

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");

    // Mid-handshake: the session is still nominally active (two-phase),
    // but a new text is refused out loud rather than queued behind the
    // very notice ending things.
    send_text(&mut alice, &contact, "one more thing").await;
    let (message, _) = alice.ui.status_notice.clone().expect("the refusal explains itself");
    assert!(
        message.contains("is ending") && message.contains("not sent"),
        "a send during the end handshake is refused, not silently rerouted: {message:?}"
    );

    // The peer confirms; only now does the pause take effect.
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;

    assert_eq!(
        aloo::client::otp::contact_name_for_sending(&alice.session, &alice.ui, BOB, &alice.peer_der),
        None,
        "a paused session must not route a new send through the pad any more"
    );
    assert_eq!(
        aloo::client::otp::contact_name_if_active(&alice.session, alice.peer, &alice.peer_der),
        Some(contact),
        "the pad itself is kept, not destroyed - only new sends stop using it"
    );
}

/// The mirror case: a `Direct`-framed (pad-only) pair has no `pq_hybrid`
/// to fall back to at all, so for them the pad *is* the whole relationship
/// - `contact_name_for_sending` must keep answering `Some` even once the
/// confirmed end has cleared `is_otp_active`, unlike the `PqWrapped` case
/// above.
///
/// @requirement AC-303
#[tokio::test]
async fn endotp_on_a_pad_only_pair_never_stops_contact_name_for_sending() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-send-gate-direct", Id::Opaque, Id::Opaque).await;
    alice.ui.mark_otp_active(BOB);

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(
        !alice.ui.is_otp_active(BOB),
        "the live toggle clears once the peer confirmed, as usual"
    );

    assert_eq!(
        aloo::client::otp::contact_name_for_sending(&alice.session, &alice.ui, BOB, &alice.peer_der),
        Some(contact),
        "a pad-only pair has no plain channel to fall back to, so sending must still use the pad"
    );
}

// ---------------------------------------------------------------------
// A resend of an already-processed message must re-ack, not go silent
// ---------------------------------------------------------------------

/// Alice's own ack for a message she already delivered can be lost just as
/// easily as her original send's ack can - and until now, bob answered a
/// repeat of that exact ciphertext with total silence (see `on_message`'s
/// old duplicate branch, which only special-cased `OtpEndSession`). That
/// permanently strands alice's `pending_unacked_out_seq` gate: her retry is
/// the *only* thing that could ever unstick it, and it gets no reply.
///
/// @requirement AC-304
#[tokio::test]
async fn a_duplicate_text_message_re_acks_the_same_proof_without_reprocessing() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("dup-text-reack", Id::Pq, Id::Pq).await;

    send_text(&mut alice, &contact, "meet me at six").await;
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq, msg_id, envelope.clone(), envelope_device.clone()).await;
    let first_ack = last_ack(&mut bob);
    let acks_before = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();

    // Alice's retry: the identical ciphertext reappears because her copy of
    // the ack never arrived - this must never touch the pad or the UI a
    // second time, but it must still get a fresh ack back, not silence.
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let acks_after = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();
    let second_ack = last_ack(&mut bob);

    assert_eq!(
        acks_after,
        acks_before + 1,
        "the repeat must queue a genuinely new ack, not leave the peer's retry unanswered"
    );
    assert_eq!(
        second_ack, first_ack,
        "and it must be the very same recorded ack, not a fresh derivation"
    );
    let text_count = bob
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .filter(|e| matches!(&e.body, MessageBody::Text(t) if t == "meet me at six"))
        .count();
    assert_eq!(
        text_count, 1,
        "a duplicate delivery must never be shown to the user twice"
    );
}

/// The other half of the same guarantee: only the single most recent
/// message could ever legitimately reappear (the sender's own
/// stop-and-wait gate never has more than one outstanding at a time), so a
/// replay of something *older* than that must still be dropped in silence
/// exactly as before - re-acking it would be answering a message that was
/// never actually the one left unacknowledged.
///
/// @requirement AC-304
#[tokio::test]
async fn a_stale_replay_older_than_the_last_received_message_is_still_silently_dropped() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("dup-text-stale", Id::Pq, Id::Pq).await;

    send_text(&mut alice, &contact, "first").await;
    let (seq1, msg_id1, envelope1, envelope1_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq1, msg_id1, envelope1.clone(), envelope1_device.clone()).await;
    let (ack_seq, ack_proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, ack_proof).await;

    send_text(&mut alice, &contact, "second").await;
    // `queued()` reads rather than drains (`Side::queued`'s doc), so the
    // first envelope is still sitting there too - `take_envelope` would
    // find it again by returning the first match. Pick the one that isn't
    // `seq1` instead, to actually get the new send.
    let (seq2, msg_id2, envelope2, envelope2_device) = alice
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq, msg_id, envelope, sender_device_id, ..
            } if seq != seq1 => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .expect("the second send should have queued its own envelope");
    receive_text(&mut bob, seq2, msg_id2, envelope2, envelope2_device).await;

    let acks_before = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();

    // A genuinely stale replay of the *first* message, long superseded by
    // the second - must produce no ack at all.
    receive_text(&mut bob, seq1, msg_id1, envelope1, envelope1_device).await;

    let acks_after = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();
    assert_eq!(
        acks_after, acks_before,
        "a stale, non-latest duplicate must not be re-acked"
    );
}

/// A decrypt that fails for any reason other than `otp`'s own metadata
/// rejection - here, the contact was never actually installed on this
/// side's keychain, exactly what a failed/interrupted pad-commit install
/// leaves behind (`client::otp::on_pad_commit`) - must never be silent.
/// Before this was fixed, `unwrap_incoming`'s catch-all collapsed every
/// such case into a bare `UnwrapOutcome::Failed` with no reason, and
/// `finish_opening_otp_envelope` turned that into a plain `return None`:
/// the message vanished with nothing on screen, indistinguishable from it
/// never having arrived at all - which is exactly what real users reported
/// ("the other side could not decrypt the messages").
///
/// @requirement AC-375
#[tokio::test]
async fn a_message_for_a_contact_never_installed_produces_a_visible_notice_not_silence() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("missing-contact", Id::Pq, Id::Pq).await;

    send_text(&mut alice, &contact, "hello").await;
    let (seq, msg_id, envelope, sender_device_id) = take_envelope(&mut alice);

    // Simulate the exact state a failed pad-commit install leaves bob in:
    // alice believes the pair is fully provisioned (she already installed
    // her own half), but bob's keychain never actually got its half.
    otp_cli::remove_contact(&bob.otp, &contact)
        .await
        .expect("removing the contact to simulate a failed install");

    assert!(
        bob.ui.status_notice.is_none(),
        "sanity: nothing shown yet before the message arrives"
    );
    receive_text(&mut bob, seq, msg_id, envelope, sender_device_id).await;

    let (message, success) = bob
        .ui
        .status_notice
        .clone()
        .expect("a decrypt failure that is not otp's own rejection must still be shown");
    assert!(!success, "a decrypt failure is never a success notice");
    assert!(
        message.contains("could not be decrypted") && message.contains("alice"),
        "the notice must say what happened and who it was from: {message:?}"
    );

    // Nothing was acknowledged - the sender must not be told this arrived.
    let acks = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();
    assert_eq!(acks, 0, "a message that could not be decrypted must not be acked");
}

/// The contact-missing case above, taken all the way through: bob's
/// keychain entry is genuinely gone (deleted, exactly as
/// `contacts::handle_delete_otp_key` would leave it), so there is nothing
/// transient about the decrypt failure - retrying can never succeed.
/// Ends the session locally on bob's side and tells alice directly (a
/// sealed, unpadded `OtpEndSession` - there is no pad left on bob's side
/// to protect it with), so both sides converge to "ended" instead of
/// alice being left to believe the session is still alive while every
/// message she sends here keeps failing to decrypt with nothing on her
/// side ever explaining why.
///
/// @requirement AC-380
#[tokio::test]
async fn a_missing_contact_on_receipt_ends_the_session_on_both_sides() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("missing-contact-ends-both", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut alice, &contact, "hello").await;
    let (seq, msg_id, envelope, sender_device_id) = take_envelope(&mut alice);
    otp_cli::remove_contact(&bob.otp, &contact)
        .await
        .expect("removing the contact to simulate bob having deleted his key");

    receive_text(&mut bob, seq, msg_id, envelope, sender_device_id).await;

    assert!(
        !bob.ui.is_otp_active(ALICE),
        "bob's own side must end the moment he discovers the key is gone"
    );
    let (bob_message, bob_success) = bob
        .ui
        .status_notice
        .clone()
        .expect("bob must be told his own side ended");
    assert!(!bob_success);
    assert!(
        bob_message.contains("ending the session") && bob_message.contains("alice"),
        "bob's notice must say the session is ending and who it was from: {bob_message:?}"
    );

    // Bob's sealed, unpadded notice to alice - never `OtpEnvelope` (padded),
    // since bob has no pad left at all to wrap it with.
    let notice_envelope = bob
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::Envelope { envelope, .. } if envelope.content == Content::OtpEndSession => {
                Some(envelope)
            }
            _ => None,
        })
        .expect("bob must tell alice directly, not just end silently on his own side");

    let bob_info = UserInfo {
        id: BOB,
        name: "bob".to_string(),
        public_key_der: alice.peer_der.clone(),
        key_mode: KeyMode::PqHybrid,
    };
    aloo::client::otp::on_end_session(
        &mut alice.session,
        &mut alice.ui,
        BOB,
        "bob".to_string(),
        &bob_info,
        notice_envelope,
    )
    .await;

    assert!(
        !alice.ui.is_otp_active(BOB),
        "alice's side must converge to ended too, once bob's notice reaches her"
    );
    let (alice_message, alice_success) = alice
        .ui
        .status_notice
        .clone()
        .expect("alice must be told her side ended as well");
    assert!(!alice_success);
    assert!(
        alice_message.contains("ended by bob"),
        "alice's notice must name who ended it: {alice_message:?}"
    );
}

/// The same trigger as above, but for a decrypt failure that is *not*
/// about a missing contact - the contact still genuinely exists, `otp`
/// itself just could not run this one time (a stand-in for a transient
/// binary/disk hiccup). Must fall through to the ordinary "could not be
/// decrypted" notice (AC-375) rather than escalating to ending the
/// session: unlike a deleted key, there is nothing here that retrying
/// could not fix.
///
/// @requirement AC-380
#[tokio::test]
async fn a_transient_decrypt_failure_with_the_contact_still_present_does_not_end_the_session() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("transient-failure-stays-active", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut alice, &contact, "hello").await;
    let (seq, msg_id, envelope, sender_device_id) = take_envelope(&mut alice);

    // Bob's contact is untouched; only his binary becomes unreachable for
    // this one decrypt attempt - `has_contact` itself now also fails, so
    // the missing-contact escalation must not fire (`unwrap_or(true)`).
    bob.session
        .set_otp_binary_path_for_test(std::path::PathBuf::from("aloo-test-otp-does-not-exist-xyz"));

    receive_text(&mut bob, seq, msg_id, envelope, sender_device_id).await;

    assert!(
        bob.ui.is_otp_active(ALICE),
        "a transient failure must never end the session - only a genuinely missing contact does"
    );
    let (message, success) = bob
        .ui
        .status_notice
        .clone()
        .expect("the failure must still be shown");
    assert!(!success);
    assert!(
        message.contains("could not be decrypted") && !message.contains("ending the session"),
        "must be the ordinary decrypt-failure notice, not the ends-the-session one: {message:?}"
    );
}

/// The `/endotp` counterpart of
/// `a_missing_contact_on_receipt_ends_the_session_on_both_sides`: this time
/// it is alice's own real `/endotp` notice that bob cannot decrypt (his key
/// for the contact is gone), so bob's substitute `OtpEndSession`
/// (`end_session_for_missing_contact`) is what reaches alice - not the
/// `OtpDeliveryAck`/`OtpEndSessionAck` her own send was actually waiting
/// for. Without `OtpStore::clear_own_pending_end_notice_send`, alice's own
/// `pending_end_notice` and the gate her notice armed would stay set
/// forever: nothing else ever answers that specific send, so every later
/// send to this contact would keep refusing with "the session is ending"
/// and a repeated `/endotp` would keep saying "already ending" even though
/// her UI already shows the session ended.
///
/// @requirement AC-382
#[tokio::test]
async fn a_substitute_end_notice_also_settles_this_sides_own_pending_end_notice() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-vs-missing-key", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");

    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| s.pending_end_notice),
        "sanity: alice's own notice is now pending"
    );
    assert!(alice.gate_held(&contact), "sanity: the gate is armed behind it");

    let (seq, msg_id, envelope, sender_device_id) = take_envelope(&mut alice);
    otp_cli::remove_contact(&bob.otp, &contact)
        .await
        .expect("removing the contact to simulate bob having deleted his key");

    receive_text(&mut bob, seq, msg_id, envelope, sender_device_id).await;
    assert!(
        !bob.ui.is_otp_active(ALICE),
        "sanity: bob's own side ends on discovering the key is gone"
    );

    let notice_envelope = bob
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::Envelope { envelope, .. } if envelope.content == Content::OtpEndSession => {
                Some(envelope)
            }
            _ => None,
        })
        .expect("bob must tell alice directly with his own substitute notice");

    let bob_info = UserInfo {
        id: BOB,
        name: "bob".to_string(),
        public_key_der: alice.peer_der.clone(),
        key_mode: KeyMode::PqHybrid,
    };
    aloo::client::otp::on_end_session(
        &mut alice.session,
        &mut alice.ui,
        BOB,
        "bob".to_string(),
        &bob_info,
        notice_envelope,
    )
    .await;

    assert!(
        !alice.ui.is_otp_active(BOB),
        "alice's side converges to ended (already covered by AC-380)"
    );
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice),
        "bob's substitute notice must also settle alice's own outstanding end-notice bookkeeping, \
         since no ack will ever come for it now"
    );
    assert!(
        !alice.gate_held(&contact),
        "the gate alice's own notice armed must not stay closed forever with nothing left to open it"
    );
}

/// `push_outgoing_dm` (UI thread, at submit time) and the send path
/// (session task, once the queued action is actually processed) both read
/// `is_otp_active` - but at two different moments. A session starting in
/// the gap between them - exactly the window a real network round trip
/// (the peer's resume confirmation) widens far past what a loopback test
/// ever shows - must not leave the row permanently misdescribing what it
/// actually sent under.
///
/// @requirement AC-377
#[tokio::test]
async fn a_message_logged_before_the_session_activates_is_corrected_to_otp_once_actually_sent() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("race-inactive-to-active", Id::Pq, Id::Pq).await;
    assert!(
        !alice.ui.is_otp_active(BOB),
        "sanity: pair() provisions a pad but never marks a session active on its own"
    );

    // The row is logged while the local session still believes OTP is not
    // active - `push_outgoing_dm`'s snapshot exactly as `submit_text` would
    // take it at this instant.
    let (msg_id, delivery) = alice.ui.start_delivery(&[BOB]);
    let log_index = alice
        .ui
        .push_outgoing_dm(BOB, MessageBody::Text("racing message".into()), Some(delivery))
        .expect("the room exists");
    assert!(
        matches!(
            alice.ui.private_rooms[&BOB].log[log_index].crypto,
            Some(MessageCrypto::Envelope { .. })
        ),
        "logged before activation: stamped as an ordinary envelope"
    );

    // The peer's confirmation arrives in the gap before the queued send is
    // actually processed - the real session-side trigger for
    // `is_otp_active` flipping true mid-flight. Production always pairs
    // this with a status refresh (`finish_provisioning`'s doc); the two
    // together are what actually flips `message_crypto`'s OTP branch on.
    alice.ui.mark_otp_active(BOB);
    aloo::client::otp::refresh_otp_key_status(&alice.otp, &mut alice.ui, BOB, &contact).await;

    aloo::client::otp::send_or_queue(
        &mut NullSink,
        &mut alice.session,
        &mut alice.ui,
        BOB,
        &contact,
        &alice.peer_der,
        b"racing message",
        Content::Text,
        None,
        Some(log_index),
        Some(msg_id),
    )
    .await
    .expect("the send path should not fail");

    assert!(
        matches!(
            alice.ui.private_rooms[&BOB].log[log_index].crypto,
            Some(MessageCrypto::Otp { .. })
        ),
        "the row must be corrected to what actually went out: the pad, not a plain envelope"
    );
}

/// The mirror race: logged while a session is active, but it ends (or was
/// never really usable any more) before the send is actually processed -
/// the row must not go on claiming a pad spend that never happened.
///
/// @requirement AC-377
#[tokio::test]
async fn a_message_logged_while_active_is_corrected_to_plain_once_the_session_has_ended() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("race-active-to-inactive", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    aloo::client::otp::refresh_otp_key_status(&alice.otp, &mut alice.ui, BOB, &contact).await;

    let (msg_id, delivery) = alice.ui.start_delivery(&[BOB]);
    let log_index = alice
        .ui
        .push_outgoing_dm(BOB, MessageBody::Text("racing message".into()), Some(delivery))
        .expect("the room exists");
    assert!(
        matches!(
            alice.ui.private_rooms[&BOB].log[log_index].crypto,
            Some(MessageCrypto::Otp { .. })
        ),
        "logged while active: stamped as an otp spend"
    );

    // The session ends (or the peer's end-notice lands) in the gap before
    // the queued send is actually processed.
    alice.ui.clear_otp_active(BOB);

    aloo::client::direct_message::handle_send_text(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        "racing message".to_string(),
        alice.peer_der.clone(),
        Some(log_index),
        msg_id,
    )
    .await
    .expect("the send path should not fail");

    assert!(
        matches!(
            alice.ui.private_rooms[&BOB].log[log_index].crypto,
            Some(MessageCrypto::Envelope { .. })
        ),
        "the row must be corrected to what actually went out: a plain envelope, not a pad spend"
    );
}

/// The same guarantee, for the file-offer phase specifically -
/// `on_file_offer` shares `on_message`'s exact duplicate-ack gap, and now
/// shares its fix.
///
/// @requirement AC-304
#[tokio::test]
async fn a_duplicate_file_offer_re_acks_the_same_proof_without_reprocessing() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("dup-file-reack", Id::Pq, Id::Pq).await;

    let dir = scratch("dup-file-reack-payload");
    let source = dir.join("notes.txt");
    let body = b"the quick brown fox";
    std::fs::write(&source, body).unwrap();

    send_file(&mut alice, &contact, source, body.len() as u64).await;
    let (stream_id, offer_seq, offer_env, offer_env_device) = take_file_offer(&mut alice);

    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        stream_id,
        offer_seq,
        offer_env.clone(),
        offer_env_device.clone(),
    )
    .await;
    let first_ack = last_ack(&mut bob);
    let acks_before = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();

    // The sender's retry: the identical offer reappears because the ack
    // for it never arrived.
    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        stream_id,
        offer_seq,
        offer_env,
        offer_env_device,
    )
    .await;
    let acks_after = bob
        .queued()
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. }))
        .count();
    let second_ack = last_ack(&mut bob);

    assert_eq!(
        acks_after,
        acks_before + 1,
        "the repeat must queue a genuinely new ack, not leave the sender's retry unanswered"
    );
    assert_eq!(
        second_ack, first_ack,
        "and it must be the very same recorded ack, not go silent or derive a fresh one"
    );
}

// ---------------------------------------------------------------------
// /endotp while the peer is unreachable, then a reconnect retry
// ---------------------------------------------------------------------

/// `/endotp` spends this contact's pad for the `OtpEndSession` notice the
/// instant it runs, whether or not the peer can receive it right then - a
/// `/endotp` needs the peer online to enter at all now - but the peer can
/// still vanish inside the handshake window, after the notice went out and
/// before their confirmation lands. That first ciphertext is then orphaned
/// (their `UserId` is dead by the time they reconnect), and the reconnect
/// retry must resend it *recovered* - a re-encrypt would spend a second,
/// later range of the pad for a message the peer's decoder was still
/// expecting at the *first* range, breaking their very first decrypt of it
/// with exactly the "no valid metadata" failure `otp --decrypt` reports
/// for an offset mismatch. As an ordinary gated send, the notice rides
/// `recover_and_resend` - the same recovered-ciphertext path every
/// unacknowledged spend takes - and the on-reconnect notice pass
/// explicitly declines to touch a contact whose gate is armed. Until the
/// confirmation finally lands, the initiator's own side stays in the
/// session (two-phase) - and converges the instant it does.
///
/// Runs the full reconnect sequence exactly as `session.rs`'s link-Active
/// handler does - `recover_and_resend` first, `resend_pending_end_notices`
/// after - and delivers to bob only what those passes queued *last*, since
/// the original send went to a dead `UserId` and can never arrive.
///
/// A file's offer and a voice message's offer recover through one
/// function told which it is (`recover_and_resend_offer`, `OfferKind`),
/// so the two things that kind decides - the `Content` the recovered blob
/// is framed under, and the payload variant it goes back out in - are the
/// whole of what separates the two paths. Cross either and the offer
/// still goes out, but the peer's handler drops it on the floor with no
/// diagnostic at all, so nothing short of this notices.
///
/// Also pins what makes a recovery a recovery rather than a fresh send:
/// AC-147's "never by re-encoding" - no further pad is spent - and its
/// "under the exact same sequence number", checked the only way that
/// really counts, by handing the recovered offer to the peer and watching
/// their decoder accept it and ack that same slot.
///
/// Everything here reads the payloads queued *after* the recovery pass:
/// `Side::queued` reports the whole backlog rather than draining it, so
/// the original offer - the one that never arrived - is still sitting in
/// front of the resend.
/// @requirement AC-147
#[tokio::test]
async fn a_lost_file_offer_and_a_lost_voice_offer_each_recover_as_their_own_kind() {
    if !require_otp() {
        return;
    }

    // --- a file offer that never arrived ---
    let (mut alice, mut bob, contact) = pair("recover-file-offer", Id::Pq, Id::Pq).await;
    let dir = scratch("recover-file-offer-payload");
    let source = dir.join("notes.txt");
    let body = b"a file whose offer never made it across";
    std::fs::write(&source, body).unwrap();

    send_file(&mut alice, &contact, source, body.len() as u64).await;
    let (stream_id, seq, _, _) = take_file_offer(&mut alice);
    assert!(
        alice.gate_held(&contact),
        "the offer is a real pad spend, so it stays outstanding until acked"
    );
    let already_queued = alice.queued().len();
    let spent_before = alice.pad_spent(&contact).await;

    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the recovery pass should not fail");

    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_before,
        "recovery replays the kept ciphertext; it must not spend more pad"
    );
    let resent: Vec<P2pPayload> = alice.queued().into_iter().skip(already_queued).collect();
    assert!(
        !resent
            .iter()
            .any(|p| matches!(p, P2pPayload::OtpVoiceOffer { .. })),
        "a file offer must never come back as a voice offer: {resent:?}"
    );
    let (again_stream, again_seq, envelope, envelope_device) = resent
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileOffer {
                stream_id,
                seq,
                envelope,
                sender_device_id,
                ..
            } => Some((stream_id, seq, envelope, sender_device_id)),
            _ => None,
        })
        .expect("the outstanding file offer should have been resent");
    assert_eq!(
        (again_stream, again_seq),
        (stream_id, seq),
        "resent under the original stream and slot, never a fresh pair"
    );

    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        again_stream,
        again_seq,
        envelope,
        envelope_device,
    )
    .await;
    let (acked_seq, _) = last_ack(&mut bob);
    assert_eq!(
        acked_seq, seq,
        "the recovered offer must open on bob's side - framed as the file offer it is, \
         under the slot his decoder was waiting for"
    );

    // --- a voice offer that never arrived ---
    let (mut alice, mut bob, contact) = pair("recover-voice-offer", Id::Pq, Id::Pq).await;
    // Queueing off: this is the unqueued voice path, whose outstanding
    // offer is recovered by `recover_and_resend`. With the queue on the
    // offer lives in it instead and `retry_outstanding_otp_send` is what
    // puts it back on the wire - covered separately.
    alice.session.set_queue_send_messages(false);
    bob.session.set_queue_send_messages(false);
    let pcm: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();

    send_voice(&mut alice, &contact, pcm).await;
    let (stream_id, seq, _, _) = take_voice_offer(&mut alice);
    assert!(alice.gate_held(&contact));
    let already_queued = alice.queued().len();
    let spent_before = alice.pad_spent(&contact).await;

    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the recovery pass should not fail");

    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_before,
        "the same rule holds for a voice offer: replay, never re-encode"
    );
    let resent: Vec<P2pPayload> = alice.queued().into_iter().skip(already_queued).collect();
    assert!(
        !resent
            .iter()
            .any(|p| matches!(p, P2pPayload::OtpFileOffer { .. })),
        "a voice offer must never come back as a file offer: {resent:?}"
    );
    let (again_stream, again_seq, envelope, envelope_device) = resent
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpVoiceOffer {
                stream_id,
                seq,
                envelope,
                sender_device_id,
                ..
            } => Some((stream_id, seq, envelope, sender_device_id)),
            _ => None,
        })
        .expect("the outstanding voice offer should have been resent");
    assert_eq!((again_stream, again_seq), (stream_id, seq));

    aloo::client::otp::on_voice_offer(
        &mut NullSink,
        &mut bob.session,
        &mut bob.ui,
        ALICE,
        again_stream,
        again_seq,
        envelope,
        envelope_device,
    )
    .await;
    let (acked_seq, _) = last_ack(&mut bob);
    assert_eq!(
        acked_seq, seq,
        "and the voice offer's recovered ciphertext still opens on bob's side too"
    );
}

/// @requirement AC-307
#[tokio::test]
async fn an_end_confirmation_lost_in_the_handshake_window_is_recovered_on_reconnect() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-offline-notice", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    // `/endotp` while bob is still online - he drops right after, so
    // whatever this queues is simply never handed to bob below, standing
    // in for a peer whose `UserId` is dead by the time they reconnect.
    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");
    assert!(
        alice.gate_held(&contact),
        "the notice is an ordinary gated spend, so it holds the gate until acked"
    );
    assert!(
        alice.ui.is_otp_active(BOB),
        "two-phase: with the confirmation still missing, alice's side stays in the session"
    );

    let spent_after_first_attempt = alice.pad_spent(&contact).await;

    // The reconnect retry passes, in session.rs's exact order.
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the recovery pass should not fail");
    aloo::client::otp::resend_pending_end_notices(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the notice pass should not fail");

    let spent_after_retry = alice.pad_spent(&contact).await;
    assert_eq!(
        spent_after_first_attempt, spent_after_retry,
        "the retry must recover the original ciphertext, not spend more pad re-encrypting"
    );

    // Deliver the *retry* - the last envelope queued - never the original,
    // which went to a dead UserId. It must still be exactly what bob's own
    // decoder expects next: the same pad range, the same sequence number.
    let (seq, msg_id, envelope, envelope_device) = alice
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the recovery pass should have queued the recovered notice");
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let (message, success) = bob
        .ui
        .status_notice
        .clone()
        .expect("bob should see the session end, proving the notice decrypted cleanly");
    assert!(
        message.contains("OTP session ended"),
        "bob must be able to decrypt and apply the notice: {message:?}"
    );
    assert!(!success);
    assert!(!bob.ui.is_otp_active(ALICE), "bob's side ends right away");

    // And bob's ack settles alice's retry debt - and, two-phase, her own
    // pause: both ends leave the session together.
    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(!alice.gate_held(&contact));
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice),
        "the proof-carrying ack is what stops the durable retry"
    );
    assert!(
        !alice.ui.is_otp_active(BOB),
        "and only that confirmation pauses alice's own side"
    );
}

/// The deferral half of the same guarantee: `/endotp` while an earlier
/// message is still unacknowledged must not spend a single further byte of
/// pad - the in-flight message's recover-last safety copy is the only way
/// that message can ever reach the peer, and the notice taking a later pad
/// range would strand a peer who never received the message. The notice
/// waits its turn durably (`pending_end_notice`), the message is what the
/// reconnect resends, and the message's own ack is what finally sends the
/// notice - so a peer who missed the message still gets *both*, in order,
/// the moment they are back.
///
/// @requirement AC-308
#[tokio::test]
async fn endotp_with_an_unacked_message_defers_the_notice_behind_it() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-deferred-notice", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    // An in-flight message whose ack hasn't arrived yet - and bob drops
    // right after `/endotp` is typed, so he never received it at all.
    send_text(&mut alice, &contact, "did you get this?").await;
    assert!(alice.gate_held(&contact));
    let spent_after_message = alice.pad_spent(&contact).await;

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail with a send in flight");
    assert!(
        alice.ui.is_otp_active(BOB),
        "two-phase: nothing ends anywhere until the peer confirms"
    );
    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_after_message,
        "the deferred notice must not spend any pad while the message is unacknowledged"
    );
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| s.pending_end_notice),
        "the notice is owed durably, not forgotten"
    );

    // Bob reconnects: the standard retry passes run, and only what they
    // queue can reach him - the original send went to a dead UserId.
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the recovery pass should not fail");
    aloo::client::otp::resend_pending_end_notices(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the notice pass should not fail");
    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_after_message,
        "the reconnect passes recover; they never re-encrypt, and never jump the queue"
    );

    let (seq, msg_id, envelope, envelope_device) = alice
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the recovered message should have been queued");
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    let delivered = bob
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "did you get this?"));
    assert!(delivered, "the in-flight message reaches bob first, intact");

    // Bob's ack clears the gate - and that is the moment the deferred
    // notice goes out, as the gate's next occupant.
    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(
        alice.gate_held(&contact),
        "the notice takes the gate the instant the message's ack frees it"
    );

    let (seq, msg_id, envelope, envelope_device) = alice
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the notice should have followed the ack");
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    assert!(
        !bob.ui.is_otp_active(ALICE),
        "bob's session ends the moment the notice lands"
    );

    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(!alice.gate_held(&contact));
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice),
        "both spends confirmed, nothing owed, nothing desynced"
    );
    assert!(
        !alice.ui.is_otp_active(BOB),
        "and alice's own side ends exactly here, on the confirmation"
    );
}

/// The lost-ack variant: bob *did* receive the in-flight message - only his
/// acknowledgement died with the link. On reconnect the recovered message
/// is a duplicate to him, answered by the recorded-ack machinery (AC-304)
/// rather than a re-decrypt; that re-ack is what clears alice's gate and
/// releases the deferred notice. The two fixes compose.
///
/// @requirement AC-308
#[tokio::test]
async fn a_deferred_notice_converges_even_when_only_the_messages_ack_was_lost() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-deferred-lost-ack", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut alice, &contact, "made it?").await;
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq, msg_id, envelope.clone(), envelope_device.clone()).await;
    // Bob's ack is never delivered - the link died around it.

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");
    let spent_after_endotp = alice.pad_spent(&contact).await;

    // Reconnect: the recovery pass resends the message; to bob it is a
    // duplicate of something he already processed, so AC-304's recorded
    // ack answers it without touching his pad.
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the recovery pass should not fail");
    aloo::client::otp::resend_pending_end_notices(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the notice pass should not fail");
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;

    let (ack_seq, proof) = last_ack(&mut bob);
    assert_eq!(ack_seq, seq, "the duplicate is answered with the recorded ack");
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(
        alice.gate_held(&contact),
        "the re-ack both closes the message's slot and releases the deferred notice"
    );
    assert!(
        alice.pad_spent(&contact).await > spent_after_endotp,
        "the notice's spend happens only now, after the message's slot genuinely closed"
    );

    let (seq, msg_id, envelope, envelope_device) = alice
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the notice should have followed the re-ack");
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;
    assert!(!bob.ui.is_otp_active(ALICE), "bob converges to ended");
}

/// The one benign shape a pad rejection can take, healed in place: the
/// receiver decrypted a message but died (crash, kill, power loss) before
/// persisting the acceptance - the tool's decrypt counter moved, the aloo
/// store's did not, and the sender's retry of that exact ciphertext then
/// decodes against the wrong pad range and is refused as "corrupted or out
/// of sync". Instead of surfacing that rejection (and wedging the sender's
/// gate forever), the receiver detects the exact off-by-one between the
/// two counters, recovers the orphaned plaintext - nonce included - from
/// the tool's own received-side safety copy, and processes it as if the
/// decrypt had just happened: delivered, accepted, and acknowledged with
/// its true proof.
///
/// @requirement AC-312
#[tokio::test]
async fn a_decrypt_orphaned_by_a_crash_is_healed_from_the_tools_safety_copy() {
    if !require_otp() {
        return;
    }
    // A Direct-framed pair, so the envelope's single block is the raw pad
    // ciphertext - which lets the crash be simulated faithfully: run the
    // tool's decrypt directly (its state advances), then hand the same
    // envelope to `on_message` with the aloo store never having recorded
    // the acceptance.
    let (mut alice, mut bob, contact) = pair("orphaned-decrypt-heal", Id::Opaque, Id::Opaque).await;

    send_text(&mut alice, &contact, "the message the crash orphaned").await;
    let (seq, msg_id, envelope, envelope_device) = take_envelope(&mut alice);
    let padded = envelope.blocks.first().cloned().expect("direct framing carries the pad block");
    match aloo::client::otp::unwrap_incoming(&bob.otp, &padded, &contact).await {
        aloo::client::otp::UnwrapOutcome::Ok(..) => {}
        other => panic!("the simulated pre-crash decrypt should succeed, got {other:?}"),
    }
    // ...process dies here: nothing recorded, nothing shown, no ack sent...

    // The sender's retry of the very same ciphertext, after the restart.
    receive_text(&mut bob, seq, msg_id, envelope, envelope_device).await;

    let delivered = bob
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "the message the crash orphaned"));
    assert!(delivered, "the orphaned message is recovered and shown, not rejected");
    assert!(
        bob.ui.status_notice.clone().is_none_or(|(m, _)| !m.contains("was rejected")),
        "no rejection notice - the heal recognised the crash shape"
    );

    // And the ack it produced carries the *true* proof - alice's gate opens.
    let (ack_seq, proof) = last_ack(&mut bob);
    assert_eq!(ack_seq, seq);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(
        !alice.gate_held(&contact),
        "the recovered nonce yields the genuine proof, so the sender's gate opens normally"
    );
}

/// `/endotp` is a synchronised, two-party operation: it takes effect only
/// when the peer's proof-carrying acknowledgement comes back, so a peer
/// who is offline - and can confirm nothing - refuses the whole request up
/// front. Nothing is spent, nothing pauses, and the session stays exactly
/// as it was.
///
/// @requirement AC-310
#[tokio::test]
async fn endotp_while_the_peer_is_offline_is_refused_with_nothing_spent() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("endotp-peer-offline", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    alice.ui.offline.insert(BOB);
    alice.ui.set_link_status(BOB, aloo::client::p2p::LinkStatus::Lost);
    let spent_before = alice.pad_spent(&contact).await;

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("the refusal itself is not an error");

    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_before,
        "a refused /endotp spends nothing"
    );
    assert!(
        alice.ui.is_otp_active(BOB),
        "the session stays active - nothing was ended anywhere"
    );
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice),
        "no end is owed either - the request never entered the handshake"
    );
    let (message, success) = alice
        .ui
        .status_notice
        .clone()
        .expect("the refusal explains itself");
    assert!(
        message.contains("offline") && message.contains("both sides online"),
        "the user learns why and what to do: {message:?}"
    );
    assert!(!success);
}

/// A second `/endotp` while the first's notice is still owed must spend
/// nothing and change nothing - re-running the send step is exactly the
/// duplicate-notice double-spend the retry machinery exists to prevent.
///
/// @requirement AC-308
#[tokio::test]
async fn a_second_endotp_while_the_notice_is_still_owed_spends_nothing_more() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("endotp-twice", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);

    let peer_der = alice.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der.clone(),
    )
    .await
    .expect("the first /endotp should not fail");
    let spent_after_first = alice.pad_spent(&contact).await;
    let envelopes_after_first = alice.envelopes_sent();

    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut alice.ui,
        &mut alice.session,
        BOB,
        peer_der,
    )
    .await
    .expect("the second /endotp should not fail either");

    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_after_first,
        "a second /endotp on an already-ended session must not spend pad on a duplicate notice"
    );
    assert_eq!(
        alice.envelopes_sent(),
        envelopes_after_first,
        "nor queue a second copy of it"
    );
    let (message, _) = alice
        .ui
        .status_notice
        .clone()
        .expect("the refusal explains itself");
    assert!(
        message.contains("already ending"),
        "the second /endotp is told the end is already in flight: {message:?}"
    );
}

// ---------------------------------------------------------------------
// Crash-window reconciliation, sender side (AC-313)
// ---------------------------------------------------------------------

/// The sender's mirror of the orphaned-decrypt heal: killed between
/// `otp --encrypt` succeeding and `record_sent`, the tool's counter is one
/// ahead of the store's with a write-ahead intent left announcing what the
/// spend was. Startup reconciliation promotes it to an ordinary recorded
/// send - which the standard recovery machinery then resends - instead of
/// letting the next send leapfrog it and poison the peer's decoder.
///
/// @requirement AC-313
#[tokio::test]
async fn a_spend_orphaned_by_a_crash_is_promoted_from_its_write_ahead_intent() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("orphaned-encrypt-promote", Id::Pq, Id::Pq).await;

    // The write-ahead record, exactly as `send_now` writes it - the nonce
    // drawn first so its proof is recorded with the intent...
    let (nonce, proof) = aloo::crypto::otp::fresh_ack_nonce();
    alice.session.otp_store_mut().set_encrypt_intent_with_proof(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
        Some(proof),
    );
    // ...then the encrypt itself - the tool advances - and the process
    // dies before `record_sent` ever runs.
    let spent = aloo::client::otp::wrap_outgoing_with_nonce(&alice.otp, b"orphaned".to_vec(), &contact, nonce)
        .await
        .expect("the simulated pre-crash encrypt should succeed");
    drop(spent);

    let promoted = aloo::client::otp::reconcile_orphaned_sends(
        &alice.otp,
        alice.session.otp_store_mut(),
    )
    .await;
    assert_eq!(promoted.len(), 1, "exactly the one orphan is promoted");
    let state = alice
        .session
        .otp_store_mut()
        .get(&contact)
        .expect("the contact exists");
    assert_eq!(
        state.pending_unacked_out_seq,
        Some(0),
        "the orphan now occupies the gate as an ordinary recorded send"
    );
    assert_eq!(
        state.pending_content,
        Some(aloo::client::otp_store::PendingOtpContent::Text { channel: None }),
        "under the framing the intent announced"
    );
    assert_eq!(state.encrypt_intent, None, "the intent has done its job");
    assert_eq!(
        state.pending_ack_proof,
        Some(proof),
        "the promoted send insists on the very proof its intent recorded - the tool's kept \
         copy is ciphertext, so nothing else could have supplied it"
    );

    // The standard recovery pass resends the tool's kept ciphertext -
    // spending nothing further.
    let spent_before = alice.pad_spent(&contact).await;
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("the recovery pass should not fail");
    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_before,
        "recovery re-frames the kept ciphertext, never re-encrypts"
    );
    assert!(
        alice
            .queued()
            .iter()
            .any(|p| matches!(p, P2pPayload::OtpEnvelope { seq: 0, .. })),
        "the promoted orphan goes out under its own slot"
    );
}

/// The other side of the same reconciliation: an intent whose encrypt never
/// ran (the kill landed first) is dropped - nothing was spent, so nothing
/// may be fabricated.
///
/// @requirement AC-313
#[tokio::test]
async fn an_intent_whose_encrypt_never_ran_is_dropped_not_promoted() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("orphaned-intent-drop", Id::Pq, Id::Pq).await;
    alice.session.otp_store_mut().set_encrypt_intent(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
    );

    let promoted = aloo::client::otp::reconcile_orphaned_sends(
        &alice.otp,
        alice.session.otp_store_mut(),
    )
    .await;
    assert!(promoted.is_empty(), "nothing was spent, so nothing is promoted");
    let state = alice
        .session
        .otp_store_mut()
        .get(&contact)
        .expect("the contact exists");
    assert_eq!(state.pending_unacked_out_seq, None);
    assert_eq!(state.encrypt_intent, None, "the stale intent is gone");
    assert_eq!(state.next_out_seq, 0, "and the counters are untouched");
}

// ---------------------------------------------------------------------
// A content transfer surviving the receiver's restart (AC-314)
// ---------------------------------------------------------------------

/// The receiver restarted between accepting a file's offer and the content
/// arriving: the in-memory registration died with the process, while the
/// sender's recovery legitimately retries `OtpFileContentSeq` and the
/// chunks. Rather than dropping those retries forever - wedging both the
/// sender's gate and this side's expectation - the announcement alone
/// re-registers the transfer generically, the bytes land under the OTP
/// working directory, and the spend is acknowledged: the pads stay in
/// lockstep, with only the presentation degraded.
///
/// @requirement AC-314
#[tokio::test]
async fn a_content_transfer_is_re_registered_from_its_retry_after_a_restart() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("content-reregister", Id::Pq, Id::Pq).await;

    let dir = scratch("content-reregister-payload");
    let source = dir.join("notes.txt");
    let body = b"the bytes the restart nearly stranded";
    std::fs::write(&source, body).unwrap();

    send_file(&mut alice, &contact, source, body.len() as u64).await;
    let (stream_id, offer_seq, offer_env, offer_env_device) = take_file_offer(&mut alice);
    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        stream_id,
        offer_seq,
        offer_env,
        offer_env_device,
    )
    .await;
    let (a_seq, a_proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, a_seq, a_proof).await;

    // Bob "accepts", then restarts: no registration exists on his side by
    // the time alice's content phase runs.
    aloo::client::otp::start_outgoing_file_content(&mut alice.session, &mut alice.ui, stream_id)
        .await
        .expect("the content phase should not fail");
    let content_seq = alice
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileContentSeq { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the content phase names its own slot");

    // The retried announcement re-registers the transfer from the wire
    // alone.
    aloo::client::otp::on_content_seq(&mut bob.session, &mut bob.ui, ALICE, stream_id, content_seq)
        .await;
    let mut pending = bob
        .session
        .take_otp_incoming_receive(ALICE, stream_id)
        .expect("the announcement alone re-registers the transfer");
    assert!(
        matches!(pending.kind, OtpIncomingKind::Recovered),
        "re-registered generically - what the content was died with the process"
    );
    assert_eq!(pending.seq, Some(content_seq));

    // The chunks land (stood in for by copying the staged ciphertext, as
    // every content test here does) and the transfer finishes: recovered
    // bytes on disk, spend acknowledged, expectation advanced. Handed over
    // on a path of the test's own - in production the spawned worker owns
    // `temp_path` exclusively and finish runs only after its ReceiveDone,
    // an ordering this by-hand drive would otherwise race.
    let staged = alice
        .session
        .otp_send_temp_file(stream_id)
        .expect("the content phase stages its ciphertext")
        .clone();
    let handed = dir.join("handed.otp");
    std::fs::copy(&staged, &handed).unwrap();
    pending.temp_path = handed;
    aloo::client::otp::finish_incoming_file(&mut bob.session, &mut bob.ui, ALICE, stream_id, pending)
        .await;

    let (b_seq, b_proof) = last_ack(&mut bob);
    assert_eq!(b_seq, content_seq);
    ack(&mut alice, BOB, b_seq, b_proof).await;
    assert!(
        !alice.gate_held(&contact),
        "the recovered transfer's ack reopens the sender's gate normally"
    );
    let recovered_path = bob.otp.working_dir.join(format!("recovered-{stream_id}"));
    assert_eq!(
        std::fs::read(&recovered_path).unwrap(),
        body,
        "the bytes still land, byte-identical, under the recovered name"
    );
    let (message, _) = bob.ui.status_notice.clone().expect("the recovery names itself");
    assert!(
        message.contains("recovered to"),
        "the user is told where the bytes went: {message:?}"
    );
}

// ---------------------------------------------------------------------
// A genuine process restart mid-handshake, on the side holding the debt
// ---------------------------------------------------------------------

/// Reproduces exactly a user report: an ordinary message round-trips fine
/// first (confirming the pad starts genuinely in sync), then `/endotp`
/// spends real pad for the notice while the peer is unreachable, then the
/// *initiating* side's whole process restarts before the peer ever
/// confirms - not merely a network blip continuing the same in-memory
/// session, but `otp_store` actually dropped and reloaded from the same
/// file `save()` wrote, exactly as `session.rs`'s real startup does. On
/// restart, `reconcile_orphaned_sends` should find nothing to heal (the
/// encrypt fully completed and was fully recorded before the restart —
/// there is no orphaned intent), so the reload is meant to be a pure
/// continuation of the same durable state. The reconnect retry must then
/// still deliver a cleanly decryptable notice - this is the one
/// permutation ("spend fully recorded, then a *real* restart, then
/// retry") no earlier test exercised: every crash-window test simulated a
/// kill *during* the encrypt, and every other reconnect test kept the
/// same in-memory `SessionState` throughout.
///
/// @requirement AC-315
#[tokio::test]
async fn an_end_notice_survives_the_initiators_own_process_restart() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("endotp-initiator-restart", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    // An ordinary message round-trips first, exactly as in the report.
    send_text(&mut bob, &contact, "hello").await;
    let (seq0, msg_id0, envelope0, envelope0_device) = take_envelope(&mut bob);
    // `receive_text` hardcodes "from alice" - bob is the sender in this
    // scenario, so `on_message` is driven directly with the right sender.
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        seq0,
        msg_id0,
        envelope0,
        envelope0_device,
    )
    .await
    .expect("the receive path should not fail");
    let (ack_seq0, proof0) = last_ack(&mut alice);
    ack(&mut bob, ALICE, ack_seq0, proof0).await;
    assert!(!bob.gate_held(&contact), "the ordinary message must fully round-trip first");
    let spent_after_hello = bob.pad_spent(&contact).await;

    // Bob ends the session while alice is unreachable - modeled simply by
    // never delivering what this queues.
    let peer_der = bob.peer_der.clone();
    aloo::client::otp::handle_end_otp_command(
        &mut NullSink,
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");
    assert!(bob.gate_held(&contact), "the notice is a real, gated spend");
    let spent_after_notice = bob.pad_spent(&contact).await;
    assert!(spent_after_notice > spent_after_hello, "and it must have actually spent pad");

    // Bob's whole process restarts: `otp_store` is dropped and reloaded
    // from the exact file the notice's `record_sent`+`save()` just wrote -
    // a real restart, not a continued in-memory session.
    let store_path = bob.session.otp_store_mut().path().to_path_buf();
    let reloaded = aloo::client::otp_store::OtpStore::load(&store_path)
        .expect("the store file the notice was saved to must reload");
    *bob.session.otp_store_mut() = reloaded;
    assert!(
        bob.gate_held(&contact),
        "the reload must still show the notice's gate held - it was fully persisted"
    );

    // Startup reconciliation runs, exactly as `session.rs` runs it - and
    // must find nothing to heal, since nothing was orphaned.
    let promoted = aloo::client::otp::reconcile_orphaned_sends(&bob.otp, bob.session.otp_store_mut())
        .await;
    assert!(
        promoted.is_empty(),
        "a fully-recorded send predating the restart is not an orphan - reconciliation must \
         leave it exactly as it was, not touch it"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_after_notice,
        "reconciliation itself must never spend pad"
    );

    // Bob reconnects: the standard retry passes run, exactly as
    // `session.rs`'s link-Active handler runs them.
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut bob.session, &mut bob.ui)
        .await
        .expect("the recovery pass should not fail");
    aloo::client::otp::resend_pending_end_notices(&mut NullSink, &mut bob.session, &mut bob.ui)
        .await
        .expect("the notice pass should not fail");
    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_after_notice,
        "the retry after restart must recover the original ciphertext, never re-encrypt"
    );

    // What bob queued must still be exactly what alice's own decoder
    // expects next.
    let (seq, msg_id, envelope, envelope_device) = bob
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the recovery pass should have queued the recovered notice");
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        seq,
        msg_id,
        envelope,
        envelope_device,
    )
    .await
    .expect("the receive path should not fail");
    let (message, success) = alice
        .ui
        .status_notice
        .clone()
        .expect("alice should see the session end, proving the notice decrypted cleanly");
    assert!(
        !message.contains("was rejected"),
        "the notice must not be rejected as corrupted/out of sync after bob's restart: {message:?}"
    );
    assert!(
        message.contains("OTP session ended"),
        "alice must be able to decrypt and apply the notice: {message:?}"
    );
    assert!(!success);
    assert!(!alice.ui.is_otp_active(BOB));

    // And alice's confirmation still closes the loop on bob's side.
    let (ack_seq, proof) = last_ack(&mut alice);
    aloo::client::otp::on_delivery_ack(&mut NullSink, &mut bob.ui, &mut bob.session, ALICE, ack_seq, proof)
        .await
        .expect("the ack path should not fail");
    assert!(!bob.gate_held(&contact));
    assert!(!bob.ui.is_otp_active(ALICE));
}

// ---------------------------------------------------------------------
// A voice/file send surviving the SENDER's own restart while awaiting accept
// ---------------------------------------------------------------------

/// Reproduces exactly the gap found while answering a user's question: the
/// offer phase is a durable, gated spend (safe on its own), but the
/// *content* - the actual recording - only gets encrypted once
/// `FileAccepted` arrives, and until this fix, that arrival was tracked
/// purely in memory (`SessionState::own_file_targets`). A sender who
/// restarted in that exact window - offer sent, not yet accepted, or
/// accepted by a peer whose `FileAccepted` the old process never lived to
/// see - silently lost the recording, with the plaintext orphaned on disk
/// and neither side ever told.
///
/// Drives the two sub-cases event ordering can produce, both in one test:
/// alice's `FileAccepted` reaches bob *before* her own `OtpDeliveryAck` for
/// the offer does (matching `on_voice_offer`'s own send order), so it must
/// first only *queue* the content (the offer's gate is still held) - and
/// only bob's later-arriving ack actually drains it. No pad is ever at
/// risk either way: the content's own encrypt happens exactly once,
/// whichever path completes it.
///
/// @requirement AC-316
#[tokio::test]
async fn a_voice_recording_survives_the_senders_own_restart_while_awaiting_accept() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("content-send-restart", Id::Pq, Id::Pq).await;
    // Queueing off: this pins the *unqueued* two-phase shape, where the
    // recording is staged as plaintext and encrypted only once the peer
    // accepts. With the queue on it is sealed when it is recorded
    // instead - a different contract, covered separately.
    alice.session.set_queue_send_messages(false);
    bob.session.set_queue_send_messages(false);
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    let pcm = b"the recording the restart nearly stranded".to_vec();
    send_voice(&mut bob, &contact, pcm.clone()).await;

    // Staged durably the instant the offer went out - before alice has
    // even seen it.
    let staged: Vec<(u64, String)> = bob
        .session
        .otp_store_mut()
        .content_sends()
        .map(|(id, t)| (id, t.contact_name.clone()))
        .collect();
    assert_eq!(staged.len(), 1, "the content is staged awaiting alice's accept");
    let (stream_id, staged_contact) = staged[0].clone();
    assert_eq!(staged_contact, contact);

    let (offer_stream_id, offer_seq, offer_env, offer_env_device) = take_voice_offer(&mut bob);
    assert_eq!(offer_stream_id, stream_id);
    aloo::client::otp::on_voice_offer(
        &mut NullSink,
        &mut alice.session,
        &mut alice.ui,
        BOB,
        stream_id,
        offer_seq,
        offer_env,
        offer_env_device,
    )
    .await;
    // `on_voice_offer` sends FileAccept before the offer's own ack - both
    // sit in alice's queue, undelivered, exactly as they would if bob were
    // offline right now.
    let alice_queued = alice.queued();
    assert!(
        alice_queued
            .iter()
            .any(|p| matches!(p, P2pPayload::FileAccept { stream_id: s } if *s == stream_id)),
        "alice auto-accepts a voice offer"
    );
    let (offer_ack_seq, offer_ack_proof) = last_ack(&mut alice);

    // Bob's whole process restarts here: `own_file_targets` (in-memory
    // only) is gone, and `otp_store` is dropped and reloaded from the
    // exact file the staging record was saved to.
    bob.session.clear_own_file_targets_for_test();
    let store_path = bob.session.otp_store_mut().path().to_path_buf();
    let reloaded = aloo::client::otp_store::OtpStore::load(&store_path)
        .expect("the store file the staging record was saved to must reload");
    *bob.session.otp_store_mut() = reloaded;
    assert_eq!(
        bob.session.otp_store_mut().content_sends().count(),
        1,
        "the staged record survives the reload - it was fully persisted"
    );

    // Bob reconnects: the standard retry passes run, including the new one.
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut bob.session, &mut bob.ui)
        .await
        .expect("the recovery pass should not fail");
    aloo::client::otp::resume_pending_content_sends(&mut bob.session, &mut bob.ui)
        .await
        .expect("the resume pass should not fail");

    // The gate is still held (alice's ack for the offer hasn't reached bob
    // yet in this ordering) - so resuming must have *queued* the content,
    // not encrypted it, and must not have consumed the staged record
    // (it survives for a second resume to find safely, proven below).
    assert!(bob.gate_held(&contact), "the offer's own gate is still outstanding");
    assert_eq!(
        bob.session.otp_store_mut().content_sends().count(),
        1,
        "queued, not consumed - the record is only cleared once the encrypt actually starts"
    );

    // A second reconnect pass (a link flap right after the first, say)
    // must not queue a second copy of the same content.
    aloo::client::otp::resume_pending_content_sends(&mut bob.session, &mut bob.ui)
        .await
        .expect("a second resume pass should not fail");

    // Now alice's ack for the offer finally arrives, clearing the gate and
    // draining the queue - which is where the content actually encrypts.
    let spent_before_content = bob.pad_spent(&contact).await;
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        offer_ack_seq,
        offer_ack_proof,
    )
    .await
    .expect("the ack path should not fail");
    assert!(
        bob.pad_spent(&contact).await > spent_before_content,
        "the content's own encrypt must have run exactly once, draining the queue"
    );
    assert_eq!(
        bob.session.otp_store_mut().content_sends().count(),
        0,
        "fully resolved now - nothing left staged"
    );

    // And the recording actually reaches alice, byte-identical - the same
    // stand-in-for-the-chunked-transport pattern `voice_round_trip` uses.
    let content_seq = bob
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileContentSeq { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the recording names its own slot");
    let staged = bob
        .session
        .otp_send_temp_file(stream_id)
        .expect("the recording's phase stages its ciphertext")
        .clone();
    let arrived = scratch("content-send-restart-arrived").join("voice.otp");
    std::fs::copy(&staged, &arrived).unwrap();

    aloo::client::otp::finish_incoming_file(
        &mut alice.session,
        &mut alice.ui,
        BOB,
        stream_id,
        OtpIncomingFileReceive {
            contact_name: contact.clone(),
            seq: Some(content_seq),
            temp_path: arrived,
            kind: OtpIncomingKind::Voice { duration_ms: 1500 },
        },
    )
    .await;
    let delivered = alice
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| matches!(&e.body, MessageBody::Voice { pcm: p, .. } if *p == pcm));
    assert!(delivered, "the recording arrives at alice, byte-identical");

    let (final_ack_seq, final_proof) = last_ack(&mut alice);
    assert_eq!(final_ack_seq, content_seq);
    ack(&mut bob, ALICE, final_ack_seq, final_proof).await;
    assert!(!bob.gate_held(&contact), "the content's own ack reopens the gate normally");
}

/// `resume_pending_content_sends` (a reconnect) and a genuinely
/// re-delivered `FileAccepted` (the peer's own transport-level retry, if
/// their first send's low-level ack never reached this side before it
/// restarted) can each independently reach `start_outgoing_file_content`'s
/// "gate is busy, queue this content" branch for the very same stream.
/// `OtpOutQueue::has_queued_stream` is what stops a second one from
/// accumulating - a stale, never-drained duplicate entry otherwise sits in
/// the queue forever the moment the real one is drained and its
/// `own_file_targets` entry removed (`start_outgoing_file_content`'s very
/// first line then finds nothing for that `stream_id` and no-ops), so this
/// is a memory-hygiene guard rather than a double-spend one - but a real
/// one, tested directly against the queue itself.
///
/// @requirement AC-316
#[test]
fn otp_out_queue_never_double_queues_the_same_streams_content() {
    let mut queue = aloo::client::otp::OtpOutQueue::new();
    let contact = "alice-bob";
    for _ in 0..2 {
        if !queue.has_queued_stream(contact, 7) {
            queue.enqueue(
                contact.to_string(),
                aloo::client::otp::PendingOtpSend::FileContent {
                    stream_id: 7,
                    to: BOB,
                },
            );
        }
    }
    assert!(queue.pop_front(contact).is_some(), "the one genuine copy was queued");
    assert!(
        queue.pop_front(contact).is_none(),
        "and only the one - the guard refused a second enqueue for the same stream"
    );
}

// ---------------------------------------------------------------------
// Device-pinning plan §5: a `Direct`-framed pad binds to whichever device
// first successfully decrypts under it, and refuses a different one
// *before* the pad is ever touched.
// ---------------------------------------------------------------------

/// Pulls the *second* queued envelope for this contact - the one whose
/// `seq` isn't `first_seq`. `Side::queued`'s own doc explains why this is
/// necessary: `Side::queued` reads rather than drains, so a second
/// `take_envelope` call would just find the first envelope again.
fn take_second_envelope(side: &mut Side, first_seq: u64) -> (u64, Option<u64>, Envelope, String) {
    side.queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } if seq != first_seq => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .expect("the second send should have queued its own envelope")
}

/// The core, security-relevant property: checking a mismatched device
/// claim must never call `otp --decrypt` at all - the exact bug caught in
/// review (embedding the claim *inside* the padded payload would have
/// required decrypting to see it, spending the pad even on a refusal).
/// Asserted by comparing the receiver's `dec_offset`/`dec_sequence`
/// before and after a refused attempt: byte-for-byte identical.
///
/// The very first message on a pad always binds to whichever device
/// claims it, since there is nothing yet to compare against - so this
/// scenario needs the pad genuinely bound first, then a *second* message
/// claimed by a different device, to actually exercise a mismatch.
///
/// @requirement AC-317
#[tokio::test]
async fn a_mismatched_device_claim_is_refused_before_the_pad_is_touched() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) =
        pair("device-claim-mismatch", Id::Opaque, Id::Opaque).await;

    send_text(&mut alice, &contact, "first").await;
    let (seq1, msg_id1, envelope1, real_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq1, msg_id1, envelope1, real_device).await;
    let (ack_seq, ack_proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, ack_proof).await;

    send_text(&mut alice, &contact, "hello from a copied pad").await;
    let (seq2, msg_id2, envelope2, _real_device2) = take_second_envelope(&mut alice, seq1);

    let before = otp_cli::show_contact(&bob.otp, &contact)
        .await
        .expect("show-contact should succeed")
        .expect("the contact exists");

    // A different physical machine, holding a copy of the same pad file,
    // claims this exact ciphertext as its own.
    let outcome = aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        seq2,
        msg_id2,
        envelope2,
        "alices-phone-not-her-laptop".to_string(),
    )
    .await;
    assert!(outcome.is_ok(), "a refusal is not an error - it's Ok(()), nothing delivered");

    let after = otp_cli::show_contact(&bob.otp, &contact)
        .await
        .expect("show-contact should succeed")
        .expect("the contact still exists");
    assert_eq!(
        before.dec_offset, after.dec_offset,
        "the pad's decrypt offset must not move on a refused claim"
    );
    assert_eq!(
        before.dec_sequence, after.dec_sequence,
        "nor the tool's own decrypt counter"
    );
    assert!(
        !bob.ui.private_rooms[&ALICE]
            .log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::Text(t) if t.contains("copied pad"))),
        "the message must not have been delivered"
    );
}

/// The message the mismatched device sent is not lost - it is exactly as
/// "not yet delivered" as any other unacknowledged send, and the sender's
/// own retry (unchanged, never a re-encrypt) succeeds once the *actually*
/// bound device answers.
///
/// @requirement AC-317
#[tokio::test]
async fn a_refused_claim_leaves_the_senders_outstanding_send_untouched_and_it_still_delivers() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("device-claim-recovers", Id::Opaque, Id::Opaque).await;

    // Prime the bind, then clear the gate so the message under test is the
    // one being tracked.
    send_text(&mut alice, &contact, "priming").await;
    let (seq1, msg_id1, envelope1, real_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq1, msg_id1, envelope1, real_device.clone()).await;
    let (ack_seq, ack_proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, ack_proof).await;

    send_text(&mut alice, &contact, "hello").await;
    assert!(alice.gate_held(&contact), "the send is still awaiting a genuine ack");
    let (seq2, msg_id2, envelope2, _real_device2) = take_second_envelope(&mut alice, seq1);

    // The wrong device's claim is refused...
    aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        seq2,
        msg_id2,
        envelope2.clone(),
        "a-third-devices-claim".to_string(),
    )
    .await
    .expect("a refusal is not an error");
    assert!(
        !bob.ui.private_rooms[&ALICE]
            .log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "hello")),
        "the wrongly-claimed attempt must not have delivered the message"
    );
    assert!(
        alice.gate_held(&contact),
        "no ack could possibly have come back from a message that was never delivered"
    );

    // ...but the exact same ciphertext, honestly claimed by the device the
    // pad is actually meant for, still decrypts and delivers cleanly -
    // nothing about the pad's own position was disturbed by the refusal.
    aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        seq2,
        msg_id2,
        envelope2,
        real_device,
    )
    .await
    .expect("the genuine device's receive path should not fail");
    assert!(
        bob.ui.private_rooms[&ALICE]
            .log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "hello")),
        "the message delivers once the actually-bound device answers"
    );
}

/// The pad binds to whichever device's claim is attached to the *first*
/// message that genuinely decrypts - not to any earlier, merely-claimed
/// value - and every later message from that same device continues to be
/// accepted normally.
///
/// @requirement AC-317
#[tokio::test]
async fn the_pad_binds_to_the_first_device_that_genuinely_decrypts() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("device-claim-binds", Id::Opaque, Id::Opaque).await;

    send_text(&mut alice, &contact, "first").await;
    let (seq1, msg_id1, envelope1, real_device) = take_envelope(&mut alice);
    receive_text(&mut bob, seq1, msg_id1, envelope1, real_device.clone()).await;
    assert_eq!(
        bob.session.otp_store_mut().get(&contact).and_then(|s| s.bound_peer_device_id.clone()),
        Some(real_device.clone()),
        "the pad is now bound to the device that actually decrypted it"
    );
    let (ack_seq, ack_proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, ack_proof).await;

    // A genuine second message from the same, now-bound device.
    send_text(&mut alice, &contact, "second").await;
    let (seq2, msg_id2, envelope2, real_device2) = take_second_envelope(&mut alice, seq1);
    assert_eq!(real_device, real_device2, "still the same physical machine");
    receive_text(&mut bob, seq2, msg_id2, envelope2, real_device2).await;
    assert!(
        bob.ui.private_rooms[&ALICE]
            .log
            .iter()
            .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "second")),
        "and delivers normally"
    );
}

/// A voice message recorded for someone who is not there, with the durable
/// queue on: the whole thing is sealed *now* - the offer that announces it
/// and the recording itself - and both wait in the one queue, the
/// recording as its own entry referencing its own ciphertext file.
///
/// This is the queued counterpart of
/// `a_voice_recording_survives_the_senders_own_restart_while_awaiting_accept`,
/// which pins the unqueued shape. The difference is where the pad is spent:
/// there, when the peer accepts; here, when the user finishes recording,
/// which is what lets it be written to someone who is offline at all.
/// @requirement AC-423
#[tokio::test]
async fn a_queued_voice_message_is_sealed_when_it_is_recorded_not_when_it_is_accepted() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("queued-voice-seal", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    let spent_before = bob.pad_spent(&contact).await;
    let pcm: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    send_voice(&mut bob, &contact, pcm.clone()).await;

    // Both positions are gone already - the offer's and the recording's -
    // even though alice has not seen, let alone opened, anything.
    let spent_after = bob.pad_spent(&contact).await;
    assert!(
        spent_after >= spent_before + pcm.len() as u64,
        "the recording itself must have been encrypted at record time, not deferred: \
         {spent_before} -> {spent_after}"
    );

    // Two entries wait, in the order the peer will read them: the offer,
    // then the recording - the recording as a reference to a ciphertext
    // file the queue owns.
    assert_eq!(bob.session.otp_queued_total(), 2);
    let offer_seq = {
        let outbox = bob.session.otp_outbox_ref().expect("the queue is on");
        let front = outbox.front(&contact).expect("the offer waits first");
        assert!(
            matches!(front.payload(), Some(P2pPayload::OtpVoiceOffer { .. })),
            "the front is the offer that announces the recording"
        );
        assert!(front.recording().is_none());
        front.seq().expect("the offer owns a position")
    };

    // What waits on disk for them is ciphertext, not the recording.
    let (rec_path, rec_seq) = {
        let outbox = bob.session.otp_outbox_ref().expect("on");
        let rec = outbox
            .entries_for(&contact)
            .iter()
            .find_map(|e| e.recording().map(|(path, _)| (path, e.seq())))
            .expect("the recording waits as its own entry");
        (rec.0, rec.1.expect("and owns a position"))
    };
    assert!(
        offer_seq < rec_seq,
        "the peer reads the offer before the recording it announces: {offer_seq} < {rec_seq}"
    );
    let on_disk = std::fs::read(&rec_path).expect("the sealed recording is on disk");
    assert_ne!(
        on_disk, pcm,
        "nothing readable may wait on disk while they are away"
    );
}

/// A text written after a queued voice message waits its turn behind it -
/// which under one queue is nothing special to enforce: the recording is
/// an ordinary entry, and order is what the queue *is*. Pinned anyway,
/// because it is the property the old two-store shape broke.
/// @requirement AC-423
#[tokio::test]
async fn a_message_written_after_a_queued_voice_never_overtakes_it() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("queued-voice-order", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    send_voice(&mut bob, &contact, b"the recording that must go first".to_vec()).await;
    send_text(&mut bob, &contact, "written after the voice message").await;

    // One queue, strictly ordered: offer, recording, text.
    let outbox = bob.session.otp_outbox_ref().expect("the queue is on");
    let kinds: Vec<&str> = outbox
        .entries_for(&contact)
        .iter()
        .map(|e| {
            if e.recording().is_some() {
                "recording"
            } else if matches!(e.payload(), Some(P2pPayload::OtpVoiceOffer { .. })) {
                "offer"
            } else {
                "text"
            }
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["offer", "recording", "text"],
        "written order is delivery order, the recording included"
    );
    let seqs: Vec<u64> = outbox
        .entries_for(&contact)
        .iter()
        .filter_map(|e| e.seq())
        .collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "and the pad positions agree with it: {seqs:?}"
    );
}

/// The write-ahead record that protects a pad spend is only worth
/// anything if it actually reached the disk. On a full disk it does not -
/// setting it in memory still succeeds and only the save fails - and
/// spending a position nothing can account for turns a recoverable
/// accident into an unrecoverable one: the process dies, nothing says the
/// position went, and the receiver's gap-free counter refuses everything
/// after it.
///
/// Simulated the only way that is deterministic: make the store's own path
/// unwritable, which is what a full disk amounts to from here.
/// @requirement AC-424
#[tokio::test]
async fn a_send_whose_write_ahead_record_cannot_be_written_spends_no_pad() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("intent-unwritable", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    // A directory where the store's file belongs: every save now fails.
    let store_path = bob.session.otp_store_mut().path().to_path_buf();
    std::fs::remove_file(&store_path).ok();
    std::fs::create_dir_all(&store_path).expect("stand a directory in the file's place");
    assert!(
        bob.session.otp_store_mut().save().is_err(),
        "the store must genuinely be unable to save for this test to mean anything"
    );

    let spent_before = bob.pad_spent(&contact).await;
    let sent_before = bob.envelopes_sent();
    send_text(&mut bob, &contact, "this must not spend a position").await;

    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_before,
        "no position may be spent when nothing could record that it was"
    );
    assert_eq!(
        bob.envelopes_sent(),
        sent_before,
        "and nothing goes on the wire either"
    );
    assert!(
        !bob.gate_held(&contact),
        "nor is the acknowledgement gate left armed for a send that never happened"
    );
}

/// The reported failure: an `/otp` session open, the peer goes away, a
/// message is written and queued, and when they come back nothing arrives.
///
/// They come back under a *new* `UserId` - which is the whole reason the
/// queues are keyed by nickname and contact name rather than by id - so
/// this drives the reconnect the way the session really does: the old id
/// is forgotten, the returning peer is adopted onto a fresh one, and their
/// link comes up.
/// @requirement AC-425
#[tokio::test]
async fn a_queued_pad_message_goes_out_when_the_peer_returns_under_a_new_id() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("otp-queue-reconnect", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    // She goes away: her link is lost and the session forgets what
    // belonged to that connection.
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    send_text(&mut bob, &contact, "while you were out").await;
    assert_eq!(
        bob.session.otp_queued_total(),
        1,
        "with her unreachable the sealed message is held"
    );

    // She returns as somebody new, as far as this connection is concerned.
    let returned = UserId(4242);
    let her = aloo::proto::UserInfo {
        id: returned,
        name: "alice".into(),
        public_key_der: bob.peer_der.clone(),
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    bob.ui.known_users.insert(returned, her.clone());
    bob.ui.adopt_returning_peer(ALICE, &her);
    bob.session
        .peer_link_mut()
        .open_unpunched_link_for_test(returned);
    bob.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
            peer: returned,
            status: aloo::client::p2p::LinkStatus::Active,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut bob.ui, &mut bob.session)
        .await
        .expect("draining should not fail");

    // Her device id has not arrived yet, so her pad contact cannot even be
    // named (`otp::contact_name_for_peer` is device-qualified for a
    // PqWrapped pair) - the link-up drain finds nothing to drain. This is
    // the state the bug left the queue in permanently.
    assert!(
        !bob.session
            .sent_or_queued_payloads(returned)
            .iter()
            .any(|p| matches!(p, P2pPayload::OtpEnvelope { .. })),
        "nothing can go out before her contact can be named"
    );
    assert_eq!(bob.session.otp_queued_total(), 1, "and it is still held");

    // Her `DeviceIdAnnounce` lands. That is what names the contact, and so
    // the first - and for a returning peer the only - moment her queue can
    // be drained at all.
    bob.session
        .set_peer_device_id_for_test(returned, "test-device".to_string());
    bob.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::DeviceIdAnnounce {
            from: returned,
            envelope: Envelope {
                content: Content::DeviceIdAnnounce,
                blocks: vec![vec![0u8; 8]],
            },
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut bob.ui, &mut bob.session)
        .await
        .expect("draining should not fail");

    let sent = bob.session.sent_or_queued_payloads(returned);
    assert!(
        sent.iter()
            .any(|p| matches!(p, P2pPayload::OtpEnvelope { .. })),
        "the held pad message must go out to the id she has now: {sent:?}"
    );
}

/// The reported pad desync: a voice message queued for someone away, and
/// on their return the announcement arrived but the recording never did -
/// then nothing in that direction worked again.
///
/// The recording is released by the queue's own pump, and the pump
/// resolves the recipient and the chunk-transport key from the contact
/// name at release time (`release_queued_recording`) - never from
/// anything captured at record time, which for a held recording names the
/// id the peer will never hold again.
/// @requirement AC-428
#[tokio::test]
async fn a_queued_recording_follows_its_peer_to_the_id_they_return_under() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("voice-queue-reconnect", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);
    send_voice(&mut bob, &contact, b"the recording that must follow her".to_vec()).await;
    assert_eq!(
        bob.session.otp_queued_total(),
        2,
        "offer and recording both wait in the one queue"
    );

    // She returns as somebody new.
    let returned = UserId(4243);
    let her = aloo::proto::UserInfo {
        id: returned,
        name: "alice".into(),
        public_key_der: bob.peer_der.clone(),
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    bob.ui.known_users.insert(returned, her.clone());
    bob.ui.adopt_returning_peer(ALICE, &her);
    bob.session
        .set_peer_device_id_for_test(returned, "test-device".to_string());
    bob.session
        .peer_link_mut()
        .open_unpunched_link_for_test(returned);

    // Her link coming up re-offers what the gate is still waiting on -
    // the offer went to the transport while she was away and was dropped
    // with her old link - and then pumps: the exact pair the production
    // link-up drain runs (`drain_otp_queue_for`).
    let mut bob_ui = std::mem::replace(&mut bob.ui, UiState::new("swap".into()));
    bob.session
        .retry_outstanding_otp_send_for_test(&mut bob_ui, returned, &contact)
        .await;
    bob.ui = bob_ui;
    let mut bob_ui = std::mem::replace(&mut bob.ui, UiState::new("swap".into()));
    bob.session
        .pump_otp_queue_for_test(&mut bob_ui, returned, &contact)
        .await;
    bob.ui = bob_ui;
    let sent = bob.session.sent_or_queued_payloads(returned);
    assert!(
        sent.iter()
            .any(|p| matches!(p, P2pPayload::OtpVoiceOffer { .. })),
        "the offer goes to the id she has now: {sent:?}"
    );

    // ...and her acknowledgement of it - the real ack path, which retires
    // the offer's entry and pumps - releases the recording, addressed and
    // keyed for the same current id.
    let (offer_seq, offer_proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            state.pending_unacked_out_seq.expect("the offer is outstanding"),
            state.pending_ack_proof.expect("the offer's proof is recorded"),
        )
    };
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut bob.ui,
        &mut bob.session,
        returned,
        offer_seq,
        offer_proof,
    )
    .await
    .expect("the ack path should not fail");

    let sent = bob.session.sent_or_queued_payloads(returned);
    assert!(
        sent.iter()
            .any(|p| matches!(p, P2pPayload::OtpFileContentSeq { .. })),
        "the recording's sequence announcement goes to the id she has now: {sent:?}"
    );
    assert!(
        sent.iter()
            .any(|p| matches!(p, P2pPayload::StreamKeySetup { .. })),
        "and so does its chunk-transport key setup: {sent:?}"
    );
    assert!(
        !bob
            .session
            .sent_or_queued_payloads(ALICE)
            .iter()
            .any(|p| matches!(p, P2pPayload::OtpFileContentSeq { .. } | P2pPayload::StreamKeySetup { .. })),
        "nothing of the recording is addressed to the id she no longer holds"
    );
}

/// The same return, for a pad-only pair. Their contact is named from the
/// keys alone (`contact_name_for_keys`), with no device id in it, so the
/// link coming up is enough on its own - no `DeviceIdAnnounce` needed.
/// Asserted separately rather than assumed: the fix for the `PqWrapped`
/// case turned on a device id this framing does not have, and "it should
/// therefore already work" is exactly the kind of reasoning worth checking.
/// @requirement AC-425
#[tokio::test]
async fn a_pad_only_pairs_queue_drains_on_the_link_alone_when_they_return() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) =
        pair("otp-queue-reconnect-direct", Id::Opaque, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);
    send_text(&mut bob, &contact, "while you were out").await;
    assert_eq!(bob.session.otp_queued_total(), 1, "held while she is away");

    // She comes back under the *same* id, which is the whole difference: a
    // direct peer's `UserId` is derived from their nickname and device id
    // (`p2p::direct_peer_id`), so unlike a server-assigned one it is
    // deterministic and survives the reconnect. There is no new id to
    // learn and no device announce to wait for - the link is enough.
    let her = aloo::proto::UserInfo {
        id: ALICE,
        name: "alice".into(),
        public_key_der: bob.peer_der.clone(),
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    bob.ui.known_users.insert(ALICE, her.clone());
    bob.session
        .peer_link_mut()
        .open_unpunched_link_for_test(ALICE);
    // Deliberately no `DeviceIdAnnounce`: this framing must not need one.
    bob.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
            peer: ALICE,
            status: aloo::client::p2p::LinkStatus::Active,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut bob.ui, &mut bob.session)
        .await
        .expect("draining should not fail");

    let sent = bob.session.sent_or_queued_payloads(ALICE);
    assert!(
        sent.iter()
            .any(|p| matches!(p, P2pPayload::OtpEnvelope { .. })),
        "a pad-only pair's held message needs only the link: {sent:?}"
    );
}

/// An acknowledgement retires the queue's front only when the front is
/// the message it names. With the recording an ordinary entry this is the
/// common case by construction, but the check is what protects the queue
/// from an ack arriving for anything *outside* it - a file's content
/// phase, or a send that raced a just-enabled queue - which used to
/// discard the next queued message unsent and desync the pad for good.
/// @requirement AC-430
#[tokio::test]
async fn an_acknowledgement_never_retires_a_message_it_does_not_name() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("ack-retires-only-its-own", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    send_text(&mut bob, &contact, "the line that must not vanish").await;
    let held_before = bob.session.otp_queued_total();
    assert_eq!(held_before, 1);

    // An acknowledgement for a position the queue does not hold - a
    // file-content spend, say. The gate is armed with it, and its ack
    // must clear that gate without touching the queue.
    let outside_seq = 90;
    bob.session
        .otp_store_mut()
        .arm_gate_for_test(&contact, outside_seq);
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        outside_seq,
        [outside_seq as u8; 32],
    )
    .await
    .expect("the ack path should not fail");

    assert_eq!(
        bob.session.otp_queued_total(),
        held_before,
        "an ack for something outside the queue must not discard a queued text"
    );
}

/// The three-voice-messages question: with several seals stacked in the
/// queue, the CLI's `.last_sent` safety copy holds only the newest, so
/// the recovery pass must never touch it for anything the queue still
/// holds - it would resend the wrong ciphertext under the right sequence.
/// The queue's own bytes are the retry.
/// @requirement AC-431
#[tokio::test]
async fn recovery_never_resends_a_queued_message_from_the_cli_copy() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("recovery-skips-queued", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    // Three seals stack up: `.last_sent` now holds only the third.
    send_text(&mut bob, &contact, "first").await;
    send_text(&mut bob, &contact, "second").await;
    send_text(&mut bob, &contact, "third").await;

    // The first is outstanding (the pump released it and armed the gate);
    // the queue still holds all three.
    assert_eq!(bob.session.otp_queued_total(), 3);
    let outstanding = bob
        .session
        .otp_store_mut()
        .get(&contact)
        .and_then(|s| s.pending_unacked_out_seq)
        .expect("the front is on the wire");
    let sent_before = bob.envelopes_sent();

    // A link flap runs the recovery pass. It must leave this contact
    // alone: the queue owns the retry.
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut bob.session, &mut bob.ui)
        .await
        .expect("the recovery pass should not fail");

    assert_eq!(
        bob.envelopes_sent(),
        sent_before,
        "nothing recovered from `.last_sent` for a message the queue still holds"
    );
    assert_eq!(
        bob.session
            .otp_store_mut()
            .get(&contact)
            .and_then(|s| s.pending_unacked_out_seq),
        Some(outstanding),
        "and the outstanding send is left to the queue's own retry"
    );
}

/// The queue-owned retry for a recording: put back on the wire from its
/// own ciphertext file, never from `.last_sent`.
/// @requirement AC-431
#[tokio::test]
async fn a_recording_front_is_retried_from_its_own_file() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("recording-retry-file", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    send_voice(&mut bob, &contact, b"retried from my own file".to_vec()).await;
    // The pump released the offer; bob acknowledges it, which releases the
    // recording and arms the gate with its sequence.
    let (offer_seq, offer_proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            state.pending_unacked_out_seq.expect("the offer is outstanding"),
            state.pending_ack_proof.expect("recorded"),
        )
    };
    aloo::client::otp::on_delivery_ack(
        &mut NullSink,
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        offer_seq,
        offer_proof,
    )
    .await
    .expect("the ack path should not fail");

    let setups_before = bob
        .queued()
        .iter()
        .filter(|p| matches!(p, P2pPayload::StreamKeySetup { .. }))
        .count();

    // Its acknowledgement never arrives; the link comes back and the
    // retry re-runs the release from the `.rec` file.
    let mut bob_ui = std::mem::replace(&mut bob.ui, UiState::new("swap".into()));
    let retried = bob
        .session
        .retry_outstanding_otp_send_for_test(&mut bob_ui, ALICE, &contact)
        .await;
    bob.ui = bob_ui;
    assert!(retried, "a recording front is the retry's to make");
    assert!(
        bob.queued()
            .iter()
            .filter(|p| matches!(p, P2pPayload::StreamKeySetup { .. }))
            .count()
            > setups_before,
        "the release ran again - key setup and chunks from the queue's own file"
    );
}

/// The reported failure: a voice message queued while the peer is away
/// does arrive when they come back, and every text written *afterwards* -
/// with them plainly online - then never leaves.
///
/// Nothing about being online makes a send skip the queue, so a text
/// written then is an ordinary entry behind the recording, and the only
/// thing that can release it is the recording's own acknowledgement. This
/// walks the whole sequence with the real ack path: offer out, offer
/// acked, recording released, text written while they are online,
/// recording acked. The text has to be on the wire at the end of it.
/// @requirement AC-423
/// @requirement AC-430
#[tokio::test]
async fn a_text_written_after_a_queued_voice_is_released_still_goes_out() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("queued-voice-then-text", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    send_voice(&mut bob, &contact, b"the voice that arrives just fine".to_vec()).await;
    assert_eq!(
        bob.session.otp_queued_total(),
        2,
        "a queued voice is an offer plus its recording"
    );

    // She comes back.
    let her = aloo::proto::UserInfo {
        id: ALICE,
        name: "alice".into(),
        public_key_der: bob.peer_der.clone(),
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    bob.ui.known_users.insert(ALICE, her);
    bob.session
        .peer_link_mut()
        .open_unpunched_link_for_test(ALICE);
    bob.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
            peer: ALICE,
            status: aloo::client::p2p::LinkStatus::Active,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut bob.ui, &mut bob.session)
        .await
        .expect("draining should not fail");

    // The offer goes, and her acknowledgement of it releases the recording.
    let (offer_seq, offer_proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            state.pending_unacked_out_seq.expect("the offer is outstanding"),
            state.pending_ack_proof.expect("its proof is recorded"),
        )
    };
    ack(&mut bob, ALICE, offer_seq, offer_proof).await;

    let (content_seq, content_proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed again");
        (
            state
                .pending_unacked_out_seq
                .expect("the recording takes the gate next"),
            state.pending_ack_proof.expect("with its own proof"),
        )
    };
    assert_ne!(content_seq, offer_seq, "the recording has its own position");

    // She is online now. This is the text that went missing.
    send_text(&mut bob, &contact, "written after she came back").await;

    // Her acknowledgement of the recording, which is what should let it go.
    ack(&mut bob, ALICE, content_seq, content_proof).await;

    let sent = bob.session.sent_or_queued_payloads(ALICE);
    assert!(
        sent.iter()
            .any(|p| matches!(p, P2pPayload::OtpEnvelope { .. })),
        "the text written while she was online has to leave once the recording is \
         acknowledged: {sent:?}"
    );
    // It having *left* is the gate now standing on the text's own
    // position: the queue holds a sent entry until its acknowledgement, so
    // it still being there says nothing either way.
    let gate = bob
        .session
        .otp_store_mut()
        .get(&contact)
        .and_then(|s| s.pending_unacked_out_seq);
    assert!(
        gate.is_some_and(|s| s > content_seq),
        "the text has to take the gate once the recording is acknowledged, \
         instead of sitting behind a gate that never opened: {gate:?}"
    );
}

/// The same sequence as above, but with the *receiving* side really run
/// instead of its acknowledgement assumed: the queued voice is delivered,
/// unwrapped, its content decrypted and finished. What that has to produce
/// is an acknowledgement naming the recording's own slot - the one thing
/// that reopens the sender's gate, and so the only thing that lets a text
/// written after the peer came back ever leave.
/// @requirement AC-423
#[tokio::test]
async fn a_released_recording_is_acknowledged_by_the_receiver() {
    if !require_otp() {
        return;
    }
    let dir = scratch("released-recording-ack");
    let (mut alice, mut bob, contact) = pair("released-recording-ack", Id::Pq, Id::Pq).await;
    bob.ui.mark_otp_active(ALICE);
    alice.ui.mark_otp_active(BOB);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    let pcm = b"a recording queued while she was away".to_vec();
    send_voice(&mut bob, &contact, pcm.clone()).await;

    // The recording's sealed copy, captured before its release consumes
    // the entry - it stands in for the chunked transport below.
    let (cipher_path, rec_stream_id) = bob
        .session
        .otp_outbox_ref()
        .expect("the queue is on")
        .entries_for(&contact)
        .iter()
        .find_map(|e| e.recording())
        .expect("the recording is queued as its own entry");

    // She comes back and the offer goes out.
    let her = aloo::proto::UserInfo {
        id: ALICE,
        name: "alice".into(),
        public_key_der: bob.peer_der.clone(),
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    bob.ui.known_users.insert(ALICE, her);
    bob.session
        .peer_link_mut()
        .open_unpunched_link_for_test(ALICE);
    bob.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
            peer: ALICE,
            status: aloo::client::p2p::LinkStatus::Active,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut bob.ui, &mut bob.session)
        .await
        .expect("draining should not fail");

    let (stream_id, offer_seq, envelope, sender_device_id) = bob
        .session
        .sent_or_queued_payloads(ALICE)
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpVoiceOffer {
                stream_id,
                seq,
                envelope,
                sender_device_id,
                ..
            } => Some((stream_id, seq, envelope, sender_device_id)),
            _ => None,
        })
        .expect("the offer goes out when she returns");
    assert_eq!(stream_id, rec_stream_id, "offer and recording are one stream");

    // She unwraps the offer and acknowledges it; that releases the recording.
    aloo::client::otp::on_voice_offer(
        &mut NullSink,
        &mut alice.session,
        &mut alice.ui,
        BOB,
        stream_id,
        offer_seq,
        envelope,
        sender_device_id,
    )
    .await;
    let (a_seq, a_proof) = last_ack(&mut alice);
    assert_eq!(a_seq, offer_seq, "she acknowledges the offer's own slot");
    ack(&mut bob, ALICE, a_seq, a_proof).await;

    let content_seq = bob
        .session
        .sent_or_queued_payloads(ALICE)
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileContentSeq { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the recording is released with a slot of its own");

    // The content arrives: announcement first, then the bytes.
    aloo::client::otp::on_content_seq(&mut alice.session, &mut alice.ui, BOB, stream_id, content_seq)
        .await;
    let mut pending = alice
        .session
        .take_otp_incoming_receive(BOB, stream_id)
        .expect("the offer registered the receive");
    assert_eq!(
        pending.seq,
        Some(content_seq),
        "the announcement names the slot the content spent"
    );
    let arrived = dir.join("arrived.otp");
    std::fs::copy(&cipher_path, &arrived).expect("the sealed recording is still on disk");
    pending.temp_path = arrived;
    aloo::client::otp::finish_incoming_file(
        &mut alice.session,
        &mut alice.ui,
        BOB,
        stream_id,
        pending,
    )
    .await;

    // This is the whole point: without it the sender's gate never reopens
    // and every later message sits behind it forever.
    let (b_seq, b_proof) = last_ack(&mut alice);
    assert_eq!(
        b_seq, content_seq,
        "the released recording has to be acknowledged on its own slot"
    );

    ack(&mut bob, ALICE, b_seq, b_proof).await;
    assert!(
        !bob.gate_held(&contact),
        "and that acknowledgement reopens the gate for everything written after"
    );
}

/// Whether a row is claiming to be waiting on the queue.
fn row_queued(side: &mut Side, peer: UserId, msg_id: u64) -> Option<bool> {
    side.ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .chain(side.ui.channels.iter().flat_map(|c| c.log.iter()))
        .find_map(|e| {
            let d = e.delivery.as_ref()?;
            if d.msg_id != msg_id {
                return None;
            }
            d.recipients.iter().find(|r| r.id == peer).map(|r| r.queued)
        })
}

/// A message the durable queue holds behind an un-acknowledged send has to
/// say so on its row.
///
/// Held silently it looks exactly like one that went out, which is what
/// makes a genuinely stuck gate indistinguishable from a healthy round
/// trip - the reason the in-memory path this replaced always surfaced a
/// held message. That surfacing was lost when the queue became durable:
/// its notice sits behind `otp_outbox.is_none()`, so with queueing on
/// nothing said anything at all.
/// @requirement AC-439
#[tokio::test]
async fn a_message_the_queue_holds_says_so_on_its_row() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("queued-row-visible", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    // The first goes straight out and takes the gate.
    let first = send_text(&mut bob, &contact, "the one holding the gate").await;
    assert_eq!(
        row_queued(&mut bob, ALICE, first),
        Some(false),
        "a message that reached the wire is not waiting on anything"
    );
    assert!(bob.gate_held(&contact), "and it holds the gate");

    // The second can only wait, and has to say so.
    let second = send_text(&mut bob, &contact, "the one that waits").await;
    assert_eq!(
        row_queued(&mut bob, ALICE, second),
        Some(true),
        "a message held behind the gate must not look identical to a sent one"
    );

    // The first is acknowledged, which releases the second.
    let (seq, proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            state.pending_unacked_out_seq.expect("outstanding"),
            state.pending_ack_proof.expect("recorded"),
        )
    };
    ack(&mut bob, ALICE, seq, proof).await;
    assert_eq!(
        row_queued(&mut bob, ALICE, second),
        Some(false),
        "released onto the wire, so it must stop claiming to wait"
    );
}

/// A lost acknowledgement on a link that never drops used to wedge a
/// contact's queue for good: the gate opens only on an ack, and the only
/// retry fired on a link-up that was never coming. The timer closes that,
/// and re-sends the bytes already sealed rather than encrypting anything
/// new - so it can neither spend a second pad position nor deliver twice.
/// @requirement AC-440
#[tokio::test]
async fn an_unacknowledged_send_is_retried_once_its_wait_runs_out() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("retry-on-timer", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    // Genuinely reachable, not merely attempted: the timer deliberately
    // leaves a peer whose link is not up to the queue, so a half-open link
    // would make this pass or fail on timing rather than on the property.
    bob.session.peer_link_mut().mark_active_for_test(ALICE);
    // The sweep finds its candidates through `known_users`, so she has to
    // be someone this side knows, not merely someone it has a link to.
    bob.ui.known_users.insert(
        ALICE,
        aloo::proto::UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );

    send_text(&mut bob, &contact, "the one whose ack goes missing").await;
    assert!(bob.gate_held(&contact), "it is outstanding");
    // Measured after the send, so what this pins is that *retrying* costs
    // nothing - the send's own spend is not what is in question.
    let spent_before = bob.pad_spent(&contact).await;

    // Each precondition the sweep depends on, so a failure below names
    // which one is not holding rather than just "nothing was sent".
    assert_eq!(
        aloo::client::otp::active_contact_name(&bob.session, &bob.ui, ALICE).as_deref(),
        Some(contact.as_str()),
        "the sweep resolves its contact through known_users"
    );
    let gate = bob
        .session
        .otp_store_mut()
        .get(&contact)
        .and_then(|s| s.pending_unacked_out_seq);
    let front = bob
        .session
        .otp_outbox_ref()
        .and_then(|o| o.front(&contact))
        .and_then(|e| e.seq());
    assert_eq!(front, gate, "the queue front is the message the gate names");

    // Before the wait is up, the sweep only starts the clock.
    let t0 = std::time::Instant::now();
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, t0).await;
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        Some(0),
        "a send that is merely young must not be repeated"
    );

    // Once it runs out, the same bytes go again.
    let later = t0 + aloo::client::otp::OTP_RETRY_DELAY + std::time::Duration::from_secs(1);
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, later).await;
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        Some(1),
        "an acknowledgement that never came has to put the send back on the wire"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_before,
        "and it must re-send what was sealed, never seal anything new"
    );
    // The re-send really is the queue front going out again, not a no-op.
    assert!(
        bob.session
            .retry_outstanding_otp_send_for_test(&mut bob.ui, ALICE, &contact)
            .await,
        "the gate's own message is what goes back on the wire"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_before,
        "still nothing newly sealed"
    );

    // And an acknowledgement puts the wait away entirely.
    let (seq, proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            state.pending_unacked_out_seq.expect("outstanding"),
            state.pending_ack_proof.expect("recorded"),
        )
    };
    ack(&mut bob, ALICE, seq, proof).await;
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, later).await;
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        None,
        "nothing is owed, so nothing is waiting on anything"
    );
}

/// The guard that matters most. Re-releasing a recording whose worker is
/// still streaming would put two workers on one `stream_id`; their
/// interleaved chunks decrypt to something neither side's `ack_proof`
/// matches, which turns a lost acknowledgement - recoverable - into a gate
/// that can never open. The timer must leave a live transfer alone.
/// @requirement AC-440
#[tokio::test]
async fn the_retry_timer_never_disturbs_a_recording_still_being_sent() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("retry-skips-live-stream", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);
    send_voice(&mut bob, &contact, b"still going out".to_vec()).await;

    let her = aloo::proto::UserInfo {
        id: ALICE,
        name: "alice".into(),
        public_key_der: bob.peer_der.clone(),
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    bob.ui.known_users.insert(ALICE, her);
    bob.session
        .peer_link_mut()
        .open_unpunched_link_for_test(ALICE);
    bob.session
        .inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
            peer: ALICE,
            status: aloo::client::p2p::LinkStatus::Active,
        });
    aloo::client::session::drain_p2p_events(&mut NullSink, &mut bob.ui, &mut bob.session)
        .await
        .expect("draining should not fail");

    // Release the recording, then declare its worker still running.
    let (offer_seq, offer_proof) = {
        let state = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            state.pending_unacked_out_seq.expect("outstanding"),
            state.pending_ack_proof.expect("recorded"),
        )
    };
    ack(&mut bob, ALICE, offer_seq, offer_proof).await;
    let streaming = bob
        .session
        .otp_outbox_ref()
        .expect("the queue is on")
        .front(&contact)
        .and_then(|e| e.recording())
        .map(|(_, stream_id)| stream_id)
        .expect("the recording is the front now");
    assert!(
        bob.session.otp_sending_streams_contains_for_test(streaming),
        "releasing a recording registers its worker as running"
    );

    // Genuinely reachable. Injecting a `LinkStatusChanged` event only
    // feeds the handler - it does not put the link into `Active` - and the
    // sweep skips a peer it cannot reach, so without this the tick would
    // turn back before any guard was even consulted and this test would
    // pass whether or not the guard exists.
    bob.session.peer_link_mut().mark_active_for_test(ALICE);
    assert!(bob.session.peer_link_mut().is_active(ALICE));

    let sent_before = bob.session.sent_or_queued_payloads(ALICE).len();
    let spent_before = bob.pad_spent(&contact).await;
    let (next_out_before, gate_before) = {
        let s = bob.session.otp_store_mut().get(&contact).expect("armed");
        (s.next_out_seq, s.pending_unacked_out_seq)
    };

    // Hammered while the worker is still alive. A second release here is
    // what would put two workers on one stream_id, whose interleaved
    // chunks decrypt to something no ack_proof matches - the gate could
    // then never open again.
    let t0 = std::time::Instant::now();
    for step in [0u64, 1, 5, 6, 29, 30, 60, 600] {
        let at = t0 + std::time::Duration::from_secs(step);
        // Still alive: a worker proves that by making progress, and one
        // mid-stream keeps doing so.
        bob.session.register_sending_stream_for_test(streaming, at);
        aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, at).await;
        // The schedule is only created *after* the guards, so its absence
        // is what says the sweep turned back. Deliberately not the queued
        // payload count: on a live link a re-released recording leaves
        // immediately, so that count is unchanged either way and would
        // pass with the guard deleted.
        assert_eq!(
            bob.session.otp_retry_attempts_for_test(ALICE),
            None,
            "a recording still being streamed must not be released again (at +{step}s)"
        );
        assert_eq!(
            bob.session.sent_or_queued_payloads(ALICE).len(),
            sent_before,
            "and nothing was queued for her either (at +{step}s)"
        );
    }

    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_before,
        "and no pad is spent by any of it"
    );
    let s = bob.session.otp_store_mut().get(&contact).expect("still armed");
    assert_eq!(s.next_out_seq, next_out_before, "no position reserved");
    assert_eq!(
        s.pending_unacked_out_seq, gate_before,
        "the gate still names the recording, not something new"
    );
    assert!(
        bob.session.otp_sending_streams_contains_for_test(streaming),
        "and the one live worker is still the only one"
    );
}

/// A retry must never cut across a seal that is mid-operation: the store's
/// write-ahead intent is standing, `record_sent` has not run, and a second
/// pass would race the tool over one pad.
/// @requirement AC-440
#[tokio::test]
async fn the_retry_timer_stands_off_while_an_encrypt_is_in_flight() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("retry-skips-encrypt", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.session.peer_link_mut().mark_active_for_test(ALICE);
    bob.ui.known_users.insert(
        ALICE,
        aloo::proto::UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );
    send_text(&mut bob, &contact, "outstanding").await;
    assert!(bob.gate_held(&contact));

    // A seal in progress for this contact.
    bob.session.otp_store_mut().set_encrypt_intent(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
    );
    assert!(bob.session.otp_store_mut().encrypt_in_flight(&contact));

    // Everything the pad's integrity rests on, before the sweep runs.
    let spent_before = bob.pad_spent(&contact).await;
    let (next_out_before, gate_before, intent_before) = {
        let s = bob.session.otp_store_mut().get(&contact).expect("armed");
        (s.next_out_seq, s.pending_unacked_out_seq, s.encrypt_intent.clone())
    };
    let front_before = bob
        .session
        .otp_outbox_ref()
        .and_then(|o| o.front(&contact))
        .and_then(|e| e.seq());

    // Hammered, not sampled: every moment the timer could plausibly fire,
    // repeatedly, while the seal is still in flight.
    let t0 = std::time::Instant::now();
    for step in [0u64, 1, 5, 6, 30, 60, 61, 600] {
        let at = t0 + std::time::Duration::from_secs(step);
        aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, at).await;
        assert_eq!(
            bob.session.otp_retry_attempts_for_test(ALICE),
            None,
            "an encrypt in flight must hold the retry off entirely (at +{step}s)"
        );
    }

    // And nothing about the pad moved: no position spent, no position
    // reserved, the gate still naming the same message, the write-ahead
    // intent still standing for the encrypt that owns it.
    assert_eq!(
        bob.pad_spent(&contact).await,
        spent_before,
        "no pad may be spent while a seal is in flight"
    );
    let s = bob.session.otp_store_mut().get(&contact).expect("still armed");
    assert_eq!(s.next_out_seq, next_out_before, "no position may be reserved either");
    assert_eq!(s.pending_unacked_out_seq, gate_before, "the gate still names its message");
    assert_eq!(
        s.encrypt_intent, intent_before,
        "the intent belongs to the encrypt in flight - the sweep must not clear it"
    );
    assert_eq!(
        bob.session
            .otp_outbox_ref()
            .and_then(|o| o.front(&contact))
            .and_then(|e| e.seq()),
        front_before,
        "and the queue is exactly as it was"
    );
}

/// A peer who is not reachable is the queue's business. Retrying at them
/// would spend nothing and prove nothing.
/// @requirement AC-440
#[tokio::test]
async fn the_retry_timer_ignores_a_peer_whose_link_is_down() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("retry-skips-offline", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.known_users.insert(
        ALICE,
        aloo::proto::UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );
    send_text(&mut bob, &contact, "outstanding").await;
    assert!(bob.gate_held(&contact));
    // Deliberately no link at all.
    assert!(!bob.session.peer_link_mut().is_active(ALICE));

    let late = std::time::Instant::now()
        + aloo::client::otp::OTP_RETRY_MAX_DELAY
        + std::time::Duration::from_secs(1);
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, late).await;
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        None,
        "a peer this side cannot reach is not someone to retry at"
    );
}

/// The guard must not become a stall of its own. A worker that dies
/// without saying so leaves its stream registered; believed forever, it
/// would block this contact's retries for the rest of the session.
/// @requirement AC-440
#[tokio::test]
async fn a_send_worker_that_dies_silently_stops_blocking_retries() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, _contact) = pair("stalled-worker", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    let stream_id = 4242;
    bob.session
        .register_sending_stream_for_test(stream_id, std::time::Instant::now());
    assert!(
        bob.session.otp_sending_streams_contains_for_test(stream_id),
        "a freshly spawned worker counts as sending"
    );

    // Silence past the grace period is taken as gone, so the retry that
    // this guard was holding back may proceed.
    let stalled = std::time::Instant::now()
        + aloo::client::session::SEND_STALL_GRACE
        + std::time::Duration::from_secs(1);
    assert!(
        !bob.session.is_stream_sending_for_test(stream_id, stalled),
        "a worker that has shown no sign of life must stop being believed"
    );
}

/// The sweep is only worth anything if the session loop actually runs it,
/// and no unit test here can reach that call site: `run_connected_session`
/// needs a server, sockets and an identity before it turns once.
///
/// Asserted against the source instead, the way `docs_test` checks its own
/// mappings. Crude, and it proves only that the call is written - not that
/// it fires. But the failure it catches is the one this feature is most
/// exposed to: the wiring being dropped while every other test here keeps
/// passing and a lost acknowledgement silently wedges the queue again.
/// @requirement AC-440
#[test]
fn the_session_loop_runs_the_retry_sweep() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/client/session/mod.rs"),
    )
    .expect("the session loop's source");
    assert!(
        source.contains("tick_otp_retries("),
        "the retry sweep has to be called from the session loop, or an \
         acknowledgement that never comes wedges the queue forever again"
    );
    assert!(
        source.contains("last_otp_retry_sweep"),
        "and throttled rather than run on every turn of a 150ms loop"
    );
}

/// How many rows in this side's logs carry `text`.
fn rows_saying(side: &mut Side, text: &str) -> usize {
    let ui = &side.ui;
    ui.private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .chain(ui.channels.iter().flat_map(|c| c.log.iter()))
        .filter(|e| match &e.body {
            aloo::client::tui::ui::MessageBody::Text(t) => t.contains(text),
            _ => false,
        })
        .count()
}

/// The whole loop, with a real peer on the other end and a genuinely lost
/// acknowledgement: bob sends, alice receives and answers, her answer never
/// arrives, bob re-sends what he sealed, and alice - who has already spent
/// that position - answers again from her record instead of decrypting it
/// a second time. Her second answer reaches him, the gate opens, and the
/// message written behind it goes.
///
/// This is the failure the retry exists for, end to end: without it bob
/// waits on an acknowledgement that already came and was lost, and
/// everything behind it stops for good.
/// @requirement AC-440
#[tokio::test]
async fn a_lost_acknowledgement_recovers_without_resealing_or_duplicating() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("lost-ack-recovery", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut bob, &contact, "the message whose ack goes missing").await;
    let sealed_after_send = bob.pad_spent(&contact).await;

    // She receives it and answers - and her answer is thrown away, exactly
    // as a dropped frame on a link that never went down would be.
    deliver_envelope(&mut alice, BOB, "bob", &mut bob).await;
    assert_eq!(
        rows_saying(&mut alice, "the message whose ack goes missing"),
        1,
        "she has it once"
    );
    let (lost_seq, _lost_proof) = last_ack(&mut alice);
    assert!(
        bob.gate_held(&contact),
        "his gate stays shut, since nothing reached him"
    );

    // He puts the same sealed bytes back on the wire - the retry the timer
    // drives, called here directly so the resend is observable.
    assert!(
        bob.session
            .retry_outstanding_otp_send_for_test(&mut bob.ui, ALICE, &contact)
            .await,
        "the outstanding message is re-sent"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        sealed_after_send,
        "re-sending must seal nothing new"
    );

    // She sees a position she has already spent: answered from her record,
    // never decrypted twice, and no second row.
    deliver_envelope(&mut alice, BOB, "bob", &mut bob).await;
    assert_eq!(
        rows_saying(&mut alice, "the message whose ack goes missing"),
        1,
        "a re-sent message must not arrive twice"
    );
    let (again_seq, again_proof) = last_ack(&mut alice);
    assert_eq!(
        again_seq, lost_seq,
        "she re-answers the same position rather than a new one"
    );

    // This time it gets through.
    ack(&mut bob, ALICE, again_seq, again_proof).await;
    assert!(
        !bob.gate_held(&contact),
        "the recovered acknowledgement opens the gate"
    );

    // And what was written behind it now goes. Taken from the end of his
    // queue rather than the front: `queued` reads without draining, so the
    // front is still the message just recovered.
    send_text(&mut bob, &contact, "the one that was stuck behind it").await;
    let (seq, msg_id, envelope, device) = bob
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the message behind the gate goes out once it opens");
    assert!(seq > again_seq, "and it takes the next position, not a repeat");
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        seq,
        msg_id,
        envelope,
        device,
    )
    .await
    .expect("the receive path should not fail");
    assert_eq!(
        rows_saying(&mut alice, "the one that was stuck behind it"),
        1,
        "the queue moves again once the lost acknowledgement is recovered"
    );
}

/// The retry's own state is deliberately in-memory: after a restart no
/// worker is running and nothing is owed a schedule, so both start empty.
/// What must not happen is the gate outliving the machinery that reopens
/// it - a send left outstanding by a crash has to be retried by the
/// restarted process, from the bytes on disk, without sealing anything.
/// @requirement AC-440
#[tokio::test]
async fn an_outstanding_send_is_still_retried_after_the_sender_restarts() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("retry-after-restart", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.known_users.insert(
        ALICE,
        aloo::proto::UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );
    send_text(&mut bob, &contact, "outstanding when the process died").await;
    let sealed = bob.pad_spent(&contact).await;

    // The process restarts: the store comes back off disk, and the
    // transient retry state does not come back at all.
    let store_path = bob.session.otp_store_mut().path().to_path_buf();
    let reloaded = aloo::client::otp_store::OtpStore::load(&store_path)
        .expect("the store must reload");
    *bob.session.otp_store_mut() = reloaded;
    bob.session.forget_transient_otp_state_for_test();
    bob.session.peer_link_mut().mark_active_for_test(ALICE);

    assert!(
        bob.gate_held(&contact),
        "the gate survived the restart, as it must - it is on disk"
    );
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        None,
        "and nothing is owed a schedule yet"
    );

    // The restarted process waits its turn, then re-sends what is on disk.
    let t0 = std::time::Instant::now();
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, t0).await;
    let later = t0 + aloo::client::otp::OTP_RETRY_DELAY + std::time::Duration::from_secs(1);
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, later).await;
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        Some(1),
        "a crash must not leave a send outstanding with nothing to reopen it"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        sealed,
        "and the restarted process re-sends what was sealed, never re-seals"
    );
}

/// A crash mid-stream leaves no worker behind, so the guard that protects
/// a live transfer must not keep protecting a dead one. The registry is
/// in-memory precisely so a restart clears it.
/// @requirement AC-440
#[tokio::test]
async fn a_stream_interrupted_by_a_crash_no_longer_blocks_its_retry() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, _contact) = pair("stream-crash-restart", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    let stream_id = 909;
    bob.session
        .register_sending_stream_for_test(stream_id, std::time::Instant::now());
    assert!(bob.session.otp_sending_streams_contains_for_test(stream_id));

    bob.session.forget_transient_otp_state_for_test();
    assert!(
        !bob.session.otp_sending_streams_contains_for_test(stream_id),
        "a worker cannot outlive the process it ran in, so nothing may still \
         be treated as streaming after a restart"
    );
}

/// Network delay, not loss: an acknowledgement that arrives after the gate
/// has already moved on. It names a position that is settled, so it must
/// do nothing at all - not open the gate the next message is holding, and
/// not retire that message from the queue unsent.
/// @requirement AC-440
#[tokio::test]
async fn an_acknowledgement_delayed_past_its_own_message_changes_nothing() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("late-ack", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut bob, &contact, "first").await;
    let (first_seq, first_proof) = {
        let s = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            s.pending_unacked_out_seq.expect("outstanding"),
            s.pending_ack_proof.expect("recorded"),
        )
    };
    ack(&mut bob, ALICE, first_seq, first_proof).await;

    // The next message takes the gate.
    send_text(&mut bob, &contact, "second").await;
    let (gate_before, front_before, spent_before, held_before) = {
        let front = bob
            .session
            .otp_outbox_ref()
            .and_then(|o| o.front(&contact))
            .and_then(|e| e.seq());
        let s = bob.session.otp_store_mut().get(&contact).expect("armed again");
        (
            s.pending_unacked_out_seq,
            front,
            bob.pad_spent(&contact).await,
            bob.session.otp_queued_total(),
        )
    };
    assert_ne!(gate_before, Some(first_seq), "the gate has moved on");

    // The first message's acknowledgement finally turns up, twice over.
    ack(&mut bob, ALICE, first_seq, first_proof).await;
    ack(&mut bob, ALICE, first_seq, first_proof).await;

    let s = bob.session.otp_store_mut().get(&contact).expect("still armed");
    assert_eq!(
        s.pending_unacked_out_seq, gate_before,
        "a settled position's acknowledgement must not open the gate the next \
         message is holding"
    );
    assert_eq!(
        bob.session
            .otp_outbox_ref()
            .and_then(|o| o.front(&contact))
            .and_then(|e| e.seq()),
        front_before,
        "nor retire the queued message it does not name"
    );
    assert_eq!(bob.session.otp_queued_total(), held_before, "the queue is intact");
    assert_eq!(bob.pad_spent(&contact).await, spent_before, "and no pad moved");
}

/// The unqueued mode's version of the same failure. With
/// `queue_send_messages` off there is no queue to retry from - the retry
/// comes from the CLI's own one-deep `.last_sent` copy - and that recovery
/// only ever ran on a link coming up. So a send whose acknowledgement was
/// lost while the link stayed healthy wedged the contact exactly as the
/// queued one used to, and the sweep has to reach this path too.
/// @requirement AC-440
#[tokio::test]
async fn an_unqueued_send_whose_ack_is_lost_is_also_retried_on_the_timer() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("unqueued-timer-retry", Id::Pq, Id::Pq).await;
    // No queue at all: this is the mode the whole test is about.
    bob.session.set_queue_send_messages(false);
    assert!(
        !bob.session.queue_send_messages_enabled(),
        "this is the mode that does not hold messages for an absent peer"
    );
    bob.ui.mark_otp_active(ALICE);
    bob.ui.known_users.insert(
        ALICE,
        aloo::proto::UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );

    send_text(&mut bob, &contact, "unqueued, and never acknowledged").await;
    assert!(bob.gate_held(&contact), "it is outstanding");
    let sealed = bob.pad_spent(&contact).await;

    // She is there - the link never went down, which is precisely why the
    // link-up recovery never fires.
    bob.session.peer_link_mut().mark_active_for_test(ALICE);
    // Frames genuinely in flight to her, which is what moves when a
    // recovery really sends. Deliberately not the *unsent* queue: on a
    // live link a recovered send leaves at once, so that count would sit
    // still whether or not anything was recovered.
    let in_flight_before = bob.session.peer_link_mut().outbound_depth(ALICE);

    let t0 = std::time::Instant::now();
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, t0).await;
    assert_eq!(
        bob.session.peer_link_mut().outbound_depth(ALICE),
        in_flight_before,
        "nothing before the wait is up"
    );

    let later = t0 + aloo::client::otp::OTP_RETRY_DELAY + std::time::Duration::from_secs(1);
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, later).await;
    assert!(
        bob.session.peer_link_mut().outbound_depth(ALICE) > in_flight_before,
        "an unqueued send has to be recovered and re-sent too, or a lost \
         acknowledgement wedges this contact for good"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        sealed,
        "recovered from the recorded ciphertext, never encrypted again"
    );
    assert!(
        bob.gate_held(&contact),
        "and it is still outstanding until she actually answers"
    );
    let _ = &mut alice;
}

/// The live scenario's exact shape, isolated: bob consumes the message and
/// answers, his answer is lost, and he then comes back under a *different*
/// `UserId` - which is what a server hands out on every reconnect. The
/// retry has to follow him to the id he has now, or the gate stays shut
/// against a peer who is plainly there and everything behind it stops.
/// @requirement AC-440
#[tokio::test]
async fn a_lost_ack_still_recovers_when_the_peer_returns_under_a_new_id() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("lost-ack-new-id", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut bob, &contact, "answered, but the answer was lost").await;
    deliver_envelope(&mut alice, BOB, "bob", &mut bob).await;
    let _ = last_ack(&mut alice); // thrown away: this is the lost ack
    assert!(bob.gate_held(&contact), "his gate is shut");

    // She reconnects and the server gives her a new id.
    let returned = UserId(4242);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);
    bob.ui.known_users.insert(
        returned,
        aloo::proto::UserInfo {
            id: returned,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );
    bob.session
        .peer_link_mut()
        .mark_active_for_test(returned);
    // Her `DeviceIdAnnounce`, which is what names the contact for a peer
    // under an id this side has not seen before. A real reconnect always
    // brings one; leaving it out would test a state that never occurs.
    bob.session
        .set_peer_device_id_for_test(returned, "test-device".to_string());

    let t0 = std::time::Instant::now();
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, t0).await;
    let later = t0 + aloo::client::otp::OTP_RETRY_DELAY + std::time::Duration::from_secs(1);
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, later).await;

    assert_eq!(
        bob.session.otp_retry_attempts_for_test(returned),
        Some(1),
        "the retry has to find her under the id she has now - keyed to the old \
         one it never fires, and the gate never reopens"
    );
}

/// The `msg_id` of the newest row carrying a delivery, whichever log it
/// landed in.
fn latest_row_msg_id(side: &mut Side) -> Option<u64> {
    let ui = &side.ui;
    ui.private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .chain(ui.channels.iter().flat_map(|c| c.log.iter()))
        .filter_map(|e| e.delivery.as_ref().map(|d| d.msg_id))
        .last()
}

/// A voice message the queue holds has to say so too. It never passes
/// through `send_now`, so the marking there does not reach it - and a
/// queued recording that looked identical to one already sent is exactly
/// the confusion this indicator exists to remove.
/// @requirement AC-439
#[tokio::test]
async fn a_queued_voice_message_says_so_on_its_row_as_well() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("queued-voice-row", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);
    bob.ui.on_user_offline(ALICE);
    aloo::client::session::forget_peer_for_test(&mut bob.ui, &mut bob.session, ALICE);

    // Something ahead of it holding the gate - which is what makes the
    // voice message wait at all. The front of the queue is handed to the
    // transport as soon as the gate is free, absent peer or not, so a
    // voice message with nothing in front of it is genuinely not queued.
    send_text(&mut bob, &contact, "the one holding the gate").await;
    assert!(bob.gate_held(&contact), "the gate is held by the text");

    // The row the send will attach itself to, keyed by the stream id it is
    // about to use - the same shape the UI lays down when recording starts,
    // and where `own_stream_msg_id` finds the `msg_id`.
    let stream_id = bob.session.next_stream_id_for_test();
    let (msg_id, delivery) = bob.ui.start_delivery(&[ALICE]);
    bob.ui.push_outgoing_dm(
        ALICE,
        aloo::client::tui::ui::MessageBody::VoiceStreaming { stream_id },
        Some(delivery),
    );

    send_voice(&mut bob, &contact, b"a recording nobody can take yet".to_vec()).await;

    assert_eq!(
        row_queued(&mut bob, ALICE, msg_id),
        Some(true),
        "a held voice message must not look identical to one already sent"
    );
}

/// The write-ahead record is the only evidence that a position may have
/// been spent without being recorded. Reconciliation used to discard it
/// before it had read the pad, so one unreadable pad - a keychain briefly
/// unavailable at startup - stranded that spend for good: not on that
/// start, and not on any later one, leaving this side permanently a
/// position behind the pad it is encrypting against.
/// @requirement AC-424
#[tokio::test]
async fn an_unreadable_pad_does_not_discard_the_record_of_an_interrupted_send() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("intent-survives-unreadable", Id::Pq, Id::Pq).await;

    alice.session.otp_store_mut().set_encrypt_intent(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
    );
    let spent = aloo::client::otp::wrap_outgoing(&alice.otp, b"orphaned".to_vec(), &contact)
        .await
        .expect("the simulated pre-crash encrypt should succeed");
    drop(spent);

    // The pad cannot be read this once: the binary is not where it was.
    let unreadable = aloo::client::otp_cli::OtpCliConfig {
        binary_path: std::path::PathBuf::from("/nonexistent/otp"),
        working_dir: alice.otp.working_dir.clone(),
    };
    let promoted =
        aloo::client::otp::reconcile_orphaned_sends(&unreadable, alice.session.otp_store_mut())
            .await;
    assert!(promoted.is_empty(), "nothing can be promoted without reading the pad");
    assert!(
        alice
            .session
            .otp_store_mut()
            .encrypt_in_flight(&contact),
        "the record has to survive, or the spend it accounts for is stranded \
         on every future start too"
    );

    // With the pad readable again, the very same record heals it.
    let promoted =
        aloo::client::otp::reconcile_orphaned_sends(&alice.otp, alice.session.otp_store_mut())
            .await;
    assert_eq!(promoted.len(), 1, "the kept record is what makes the later start work");
    assert!(
        !alice.session.otp_store_mut().encrypt_in_flight(&contact),
        "and it is cleared once it has actually been acted on"
    );
}

/// A send promoted from its write-ahead record has to keep the proof
/// requirement every other send carries. Recorded with no proof,
/// `record_acked` accepts *any* value for that position - so anyone who
/// merely saw the packet could open the gate, which is exactly what the
/// proof exists to prevent. The proof cannot be recovered after the fact -
/// the tool's kept `.last_sent` copy is ciphertext and the nonce is under
/// the pad - so it is written ahead with the intent, and promotion carries
/// that recorded value.
/// @requirement AC-424
#[tokio::test]
async fn a_promoted_send_still_demands_a_real_acknowledgement() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("promoted-keeps-proof", Id::Pq, Id::Pq).await;

    let (nonce, expected_proof) = aloo::crypto::otp::fresh_ack_nonce();
    alice.session.otp_store_mut().set_encrypt_intent_with_proof(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
        Some(expected_proof),
    );
    let sealed = aloo::client::otp::wrap_outgoing_with_nonce(&alice.otp, b"orphaned".to_vec(), &contact, nonce)
        .await
        .expect("the simulated pre-crash encrypt should succeed");
    drop(sealed);

    let promoted =
        aloo::client::otp::reconcile_orphaned_sends(&alice.otp, alice.session.otp_store_mut())
            .await;
    assert_eq!(promoted.len(), 1, "the orphan is promoted");
    let (seq, recorded) = {
        let s = alice.session.otp_store_mut().get(&contact).expect("armed");
        (
            s.pending_unacked_out_seq.expect("outstanding"),
            s.pending_ack_proof,
        )
    };
    let proof = recorded.expect(
        "a promoted send must carry the proof its acknowledgement will have to \
         match, written ahead with its intent",
    );
    assert_eq!(proof, expected_proof, "and it is the one the intent recorded");

    // A wrong proof must not open it...
    assert!(
        !alice
            .session
            .otp_store_mut()
            .record_acked(&contact, seq, Some([0xEE; 32])),
        "an unproven acknowledgement must be refused, exactly as for any other send"
    );
    // ...and the real one must.
    assert!(
        alice
            .session
            .otp_store_mut()
            .record_acked(&contact, seq, Some(proof)),
        "and the genuine proof still opens it"
    );
}

/// With queueing off, a message waiting on the gate is held in memory for
/// ordering rather than durability - that much is the mode working as
/// asked. What it must not do is look identical to a message already on
/// the wire, which is the one kind of held send that used to say nothing
/// at all.
/// @requirement AC-439
#[tokio::test]
async fn an_unqueued_message_waiting_on_the_gate_says_so_on_its_row() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("unqueued-row", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.session.set_queue_send_messages(false);
    assert!(
        !bob.session.queue_send_messages_enabled(),
        "this is the mode that does not hold messages for an absent peer"
    );
    bob.ui.mark_otp_active(ALICE);

    let first = send_text(&mut bob, &contact, "the one holding the gate").await;
    assert!(bob.gate_held(&contact));
    assert_eq!(
        row_queued(&mut bob, ALICE, first),
        Some(false),
        "the first went straight out"
    );

    let second = send_text(&mut bob, &contact, "the one waiting its turn").await;
    assert_eq!(
        row_queued(&mut bob, ALICE, second),
        Some(true),
        "a message waiting on the gate must not look like one already sent"
    );

    // Its turn comes and it stops claiming to wait.
    let (seq, proof) = {
        let s = bob.session.otp_store_mut().get(&contact).expect("armed");
        (
            s.pending_unacked_out_seq.expect("outstanding"),
            s.pending_ack_proof.expect("recorded"),
        )
    };
    ack(&mut bob, ALICE, seq, proof).await;
    assert_eq!(
        row_queued(&mut bob, ALICE, second),
        Some(false),
        "released, so no longer waiting"
    );
}

/// What comes out of a decrypt is plaintext, and the tool writes it under
/// the process umask - 0644 on a typical machine. Everything this side
/// *writes* in the clear is already restricted; what it *receives* was
/// not, which left a decoded voice message and a downloaded file readable
/// by any other account on the machine until they were erased.
/// @requirement AC-433
#[cfg(unix)]
#[tokio::test]
async fn what_comes_out_of_a_decrypt_is_not_left_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    if !require_otp() {
        return;
    }
    let dir = scratch("decrypt-perms");
    let (mut alice, mut bob, contact) = pair("decrypt-perms", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);

    // A file sealed by alice, delivered to bob as the content phase does.
    let body = b"plaintext nobody else on this machine may read".to_vec();
    let source = dir.join("source.bin");
    std::fs::write(&source, &body).unwrap();
    let sealed = dir.join("sealed.otp");
    aloo::client::otp_cli::encrypt_file(&alice.otp, &contact, &source, &sealed, true)
        .await
        .expect("sealing the content");

    let final_path = dir.join("downloaded.bin");
    aloo::client::otp::finish_incoming_file(
        &mut bob.session,
        &mut bob.ui,
        ALICE,
        7,
        OtpIncomingFileReceive {
            contact_name: contact.clone(),
            // The stream's own position - a transfer that names none is
            // refused before the pad is touched (TB-288), so this test of
            // what *lands* has to name the one bob expects.
            seq: Some(0),
            temp_path: sealed,
            kind: OtpIncomingKind::File {
                final_path: final_path.clone(),
            },
        },
    )
    .await;

    assert_eq!(
        std::fs::read(&final_path).unwrap(),
        body,
        "it decrypted, so there is something to protect"
    );
    let mode = std::fs::metadata(&final_path).unwrap().permissions().mode() & 0o077;
    assert_eq!(
        mode, 0,
        "decrypted plaintext must not be readable by group or others \
         (mode was {:o})",
        std::fs::metadata(&final_path).unwrap().permissions().mode()
    );
}

/// The failure the retry timer exists for, with the acknowledgement
/// genuinely lost rather than the state constructed by hand.
///
/// Every other test of this drops the ack by simply not delivering it.
/// Here the receiver really sends one and the transport really discards it
/// (`drop_next_delivery_acks_for_test`), so what is exercised is her whole
/// send path - and what the timer then recovers is a real loss, not a
/// staged one.
/// @requirement AC-440
#[tokio::test]
async fn a_genuinely_lost_acknowledgement_is_recovered_by_the_timer() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("really-lost-ack", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);
    bob.ui.mark_otp_active(ALICE);
    bob.ui.known_users.insert(
        ALICE,
        aloo::proto::UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: bob.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );

    // Her side will really lose the next acknowledgement it sends.
    alice
        .session
        .peer_link_mut()
        .drop_next_delivery_acks_for_test(1);

    send_text(&mut bob, &contact, "the message whose ack is really lost").await;
    let sealed = bob.pad_spent(&contact).await;
    let envelope = take_envelope(&mut bob);
    let first_seq = envelope.0;
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        envelope.0,
        envelope.1,
        envelope.2.clone(),
        envelope.3.clone(),
    )
    .await
    .expect("the receive path should not fail");
    assert!(
        !alice
            .queued()
            .iter()
            .any(|p| matches!(p, P2pPayload::OtpDeliveryAck { .. })),
        "her acknowledgement was really discarded on the way out, not merely \
         left undelivered by the test"
    );
    assert!(bob.gate_held(&contact), "so his gate stays shut");

    // The timer's turn. She is reachable now, which is what makes the
    // stall pathological: the link is fine, the ack simply never came.
    bob.session.peer_link_mut().mark_active_for_test(ALICE);
    let t0 = std::time::Instant::now();
    let later = t0 + aloo::client::otp::OTP_RETRY_DELAY + std::time::Duration::from_secs(1);
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, t0).await;
    aloo::client::otp::tick_otp_retries(&mut NullSink, &mut bob.session, &mut bob.ui, later).await;
    assert_eq!(
        bob.session.otp_retry_attempts_for_test(ALICE),
        Some(1),
        "the timer has to put it back on the wire"
    );
    assert_eq!(
        bob.pad_spent(&contact).await,
        sealed,
        "and re-send what was sealed, never seal again"
    );

    // The retried datagram is the same bytes, so this is what she receives.
    // She has already spent that position, and answers from her record.
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        BOB,
        "bob".into(),
        envelope.0,
        envelope.1,
        envelope.2,
        envelope.3,
    )
    .await
    .expect("the receive path should not fail");
    let (seq, proof) = last_ack(&mut alice);
    assert_eq!(seq, first_seq, "she re-answers the same position");
    ack(&mut bob, ALICE, seq, proof).await;
    assert!(
        !bob.gate_held(&contact),
        "a genuinely lost acknowledgement has to be recoverable, or everything \
         written after it stops for good"
    );
}

// ---------------------------------------------------------------------
// Sealing ahead is only safe behind a spend the queue holds (TB-286)
// ---------------------------------------------------------------------

/// A file offer is a spend the durable queue never holds: its only retry
/// copy is the tool's one-deep `.last_sent`. A text typed while that offer
/// is still unacknowledged must therefore *not* be sealed - sealing would
/// overwrite that copy, and recovery would then replay the text's bytes
/// under the offer's sequence forever. It waits as plaintext, recovery
/// still replays the offer's own bytes, and the text seals the moment the
/// offer's genuine acknowledgement arrives.
///
/// A `Direct` pair, so the envelope's single block *is* the pad ciphertext
/// and the recovered bytes can be compared to the original byte for byte.
///
/// @requirement TB-286
#[tokio::test]
async fn a_text_behind_an_unacknowledged_file_offer_waits_rather_than_overwriting_its_recovery_copy() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("hold-behind-offer", Id::Opaque, Id::Opaque).await;
    alice.ui.mark_otp_active(BOB);

    let dir = scratch("hold-behind-offer-payload");
    let source = dir.join("notes.txt");
    std::fs::write(&source, b"the offered file").unwrap();
    send_file(&mut alice, &contact, source, 16).await;
    assert!(alice.gate_held(&contact), "the offer is a real, non-queued spend");
    let (stream_id, offer_seq, offer_env, offer_device) = take_file_offer(&mut alice);
    let spent_after_offer = alice.pad_spent(&contact).await;

    let msg_id = send_text(&mut alice, &contact, "typed while the offer is out").await;

    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_after_offer,
        "the text must not be sealed while the offer's .last_sent copy is the only one"
    );
    assert_eq!(alice.session.otp_queued_total(), 0, "nothing sealed, so nothing durably queued");
    assert_eq!(alice.session.otp_held_plaintext_for(&contact), 1, "it waits as plaintext");
    assert!(
        alice.ui.status_notice.clone().is_some_and(|(m, _)| m.contains("queued")),
        "and the user is told it is waiting"
    );

    // A link flap's recovery pass replays the *offer* - byte-identical.
    let sent_before = alice.queued().len();
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("recovery should not fail");
    let recovered = alice
        .queued()
        .into_iter()
        .skip(sent_before)
        .find_map(|p| match p {
            P2pPayload::OtpFileOffer { seq, envelope, .. } => Some((seq, envelope)),
            _ => None,
        })
        .expect("the outstanding offer is what recovery resends");
    assert_eq!(recovered.0, offer_seq);
    assert_eq!(
        recovered.1.blocks, offer_env.blocks,
        "recovery replays the offer's own ciphertext, not the text's"
    );

    // The offer lands and is acknowledged; only now does the text seal.
    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        stream_id,
        offer_seq,
        offer_env,
        offer_device,
    )
    .await;
    let (a_seq, a_proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, a_seq, a_proof).await;

    assert!(
        alice.pad_spent(&contact).await > spent_after_offer,
        "the held text is sealed once the offer's acknowledgement frees the gate"
    );
    assert_eq!(alice.session.otp_held_plaintext_for(&contact), 0);
    let (seq, sent_msg_id, envelope, device) = alice
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                sender_device_id,
                ..
            } => Some((seq, msg_id, envelope, sender_device_id)),
            _ => None,
        })
        .next_back()
        .expect("the text goes out after the offer");
    assert_eq!(seq, offer_seq + 1, "in sequence, right behind the offer");
    assert_eq!(sent_msg_id, Some(msg_id));
    receive_text(&mut bob, seq, sent_msg_id, envelope, device).await;
    let delivered = bob
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "typed while the offer is out"));
    assert!(delivered, "and decrypts in order on the other side");
}

/// The queued voice path seals two positions on the spot, so it is held to
/// the same rule: behind a non-queued spend it is refused outright, with
/// nothing spent.
///
/// @requirement TB-286
#[tokio::test]
async fn a_voice_message_behind_an_unacknowledged_file_offer_is_refused_with_nothing_spent() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("voice-behind-offer", Id::Pq, Id::Pq).await;
    alice.ui.mark_otp_active(BOB);

    let dir = scratch("voice-behind-offer-payload");
    let source = dir.join("notes.txt");
    std::fs::write(&source, b"the offered file").unwrap();
    send_file(&mut alice, &contact, source, 16).await;
    let spent_after_offer = alice.pad_spent(&contact).await;

    send_voice(&mut alice, &contact, b"recorded while the offer is out".to_vec()).await;

    assert_eq!(
        alice.pad_spent(&contact).await,
        spent_after_offer,
        "neither of the recording's two positions may be spent behind the offer"
    );
    assert_eq!(alice.session.otp_queued_total(), 0);
    let (message, success) = alice.ui.status_notice.clone().expect("the refusal is explained");
    assert!(!success);
    assert!(message.contains("hasn't been acknowledged yet"), "{message:?}");
}

// ---------------------------------------------------------------------
// A replaced pad takes the old pad's queue with it (TB-287)
// ---------------------------------------------------------------------

/// Messages sealed under a pad are useless under its replacement: pumped
/// after the counters reset they would go out as the new pad's first
/// positions, be refused on metadata by the peer's tool, and never be
/// acknowledged - the new pad wedged at position zero before carrying a
/// word. Installing a replacement therefore drops everything still queued
/// for that contact, and the first message written afterwards is the new
/// pad's genuine position zero.
///
/// @requirement TB-287
#[tokio::test]
async fn installing_a_replacement_pad_drops_what_was_queued_under_the_old_one() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("replace-purges-queue", Id::Pq, Id::Pq).await;
    let _ = &mut alice;
    bob.ui.mark_otp_active(ALICE);

    send_text(&mut bob, &contact, "sealed under the old pad").await;
    send_text(&mut bob, &contact, "and so was this").await;
    assert_eq!(bob.session.otp_queued_for(&contact), 2);
    assert!(bob.gate_held(&contact));

    // Alice re-provisions (her keychain was lost); bob accepted and her
    // commit now authorises the install of the replacement.
    bob.session.stage_incoming_pad_for_test(ALICE, contact.clone());
    aloo::client::otp::on_pad_commit(&mut bob.session, &mut bob.ui, ALICE, contact.clone()).await;

    assert_eq!(
        bob.session.otp_queued_for(&contact),
        0,
        "nothing sealed under the old pad may be pumped under the new one"
    );
    let state = bob.session.otp_store_mut().get(&contact).cloned().expect("the new pad's entry");
    assert_eq!(state.pending_unacked_out_seq, None, "no gate carried over");
    assert_eq!(state.next_out_seq, 0);
    assert_eq!(bob.pad_spent(&contact).await, 0, "a fresh pad, untouched");

    // The next message is the new pad's position zero, and it is sealed.
    send_text(&mut bob, &contact, "the first word under the new pad").await;
    let (seq, ..) = bob
        .queued()
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::OtpEnvelope { seq, msg_id, envelope, sender_device_id, .. } => {
                Some((seq, msg_id, envelope, sender_device_id))
            }
            _ => None,
        })
        .next_back()
        .expect("sent");
    assert_eq!(seq, 0);
    assert!(bob.pad_spent(&contact).await > 0);
}

// ---------------------------------------------------------------------
// The content phase is guarded and healed like every other spend (TB-288)
// ---------------------------------------------------------------------

impl Side {
    /// How far this side's *decryption* half has been consumed - what a
    /// receive-side "nothing was spent" assertion reads.
    async fn pad_received(&self, contact: &str) -> u64 {
        otp_cli::show_contact(&self.otp, contact)
            .await
            .expect("show-contact")
            .expect("the pair's contact exists")
            .dec_offset
    }
}

/// Runs a file transfer up to the point where bob holds the content
/// ciphertext, returning `(content_seq, staged ciphertext path, body, dir)`.
async fn file_content_in_bobs_hands(
    label: &str,
    alice: &mut Side,
    bob: &mut Side,
    contact: &str,
) -> (u64, std::path::PathBuf, Vec<u8>, std::path::PathBuf) {
    let dir = scratch(&format!("{label}-payload"));
    let source = dir.join("notes.txt");
    let body = b"content that lands exactly once, whatever the receiver survives".to_vec();
    std::fs::write(&source, &body).unwrap();
    send_file(alice, contact, source, body.len() as u64).await;
    let (stream_id, offer_seq, offer_env, offer_device) = take_file_offer(alice);
    aloo::client::otp::on_file_offer(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        stream_id,
        offer_seq,
        offer_env,
        offer_device,
    )
    .await;
    let (a_seq, a_proof) = last_ack(bob);
    ack(alice, BOB, a_seq, a_proof).await;
    aloo::client::otp::start_outgoing_file_content(&mut alice.session, &mut alice.ui, stream_id)
        .await
        .expect("content phase");
    let content_seq = alice
        .queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileContentSeq { seq, .. } => Some(seq),
            _ => None,
        })
        .expect("the content slot is named");
    let staged = alice
        .session
        .otp_send_temp_file(stream_id)
        .expect("staged ciphertext")
        .clone();
    (content_seq, staged, body, dir)
}

/// A content stream whose named position is not the next expected must
/// never reach `otp --decrypt`: a retry of content already consumed is
/// re-answered from the record, and a stream that names a wrong or no
/// position is refused - in every case without a single pad byte spent.
///
/// @requirement TB-288
#[tokio::test]
async fn a_content_stream_out_of_sequence_is_refused_before_the_pad_is_touched() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("content-guard", Id::Pq, Id::Pq).await;
    let (content_seq, staged, _body, dir) =
        file_content_in_bobs_hands("content-guard", &mut alice, &mut bob, &contact).await;
    let received_before = bob.pad_received(&contact).await;
    let acks_before = bob.queued().len();

    for (label, seq) in [("a position from the future", Some(content_seq + 3)), ("no position", None)] {
        let arrived = dir.join(format!("arrived-{}.otp", seq.unwrap_or(0)));
        std::fs::copy(&staged, &arrived).unwrap();
        let final_path = dir.join(format!("downloaded-{}.txt", seq.unwrap_or(0)));
        aloo::client::otp::finish_incoming_file(
            &mut bob.session,
            &mut bob.ui,
            ALICE,
            77,
            OtpIncomingFileReceive {
                contact_name: contact.clone(),
                seq,
                temp_path: arrived.clone(),
                kind: OtpIncomingKind::File { final_path: final_path.clone() },
            },
        )
        .await;
        assert_eq!(
            bob.pad_received(&contact).await,
            received_before,
            "{label}: nothing may be spent on a stream the store cannot record"
        );
        assert!(!final_path.exists(), "{label}: nothing lands");
        assert!(!arrived.exists(), "{label}: the arrived ciphertext is cleaned up");
        assert_eq!(bob.queued().len(), acks_before, "{label}: and nothing is acknowledged");
    }
}

/// The receiver's crash between a content decrypt and its record - the
/// tool one ahead of the store, the plaintext already produced - is healed
/// from the tool's kept received-side copy when the sender's faithful
/// retry is refused: the content lands, the position is recorded, and the
/// acknowledgement carries the plaintext's true digest. Before, that
/// retry was refused forever and the pair wedged on a spend both sides had
/// in fact completed.
///
/// @requirement TB-288
#[tokio::test]
async fn a_content_decrypt_orphaned_by_a_crash_is_healed_from_the_tools_safety_copy() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("content-heal", Id::Pq, Id::Pq).await;
    let (content_seq, staged, body, dir) =
        file_content_in_bobs_hands("content-heal", &mut alice, &mut bob, &contact).await;

    // The pre-crash decrypt: the tool's state advances, and the process
    // dies before anything is recorded or acknowledged.
    let pre_crash_in = dir.join("arrived-first.otp");
    std::fs::copy(&staged, &pre_crash_in).unwrap();
    let pre_crash_out = dir.join("lost-with-the-process.txt");
    let outcome = otp_cli::decrypt_file_retrying(&bob.otp, &contact, &pre_crash_in, &pre_crash_out, true)
        .await
        .expect("decrypt runs");
    assert!(matches!(outcome, otp_cli::FileCliOutcome::Ok), "{outcome:?}");
    std::fs::remove_file(&pre_crash_out).unwrap();

    // ...restart; the sender's retry of the very same content arrives.
    let arrived = dir.join("arrived-retry.otp");
    std::fs::copy(&staged, &arrived).unwrap();
    let final_path = dir.join("downloaded.txt");
    let acks_before = bob.queued().len();
    aloo::client::otp::finish_incoming_file(
        &mut bob.session,
        &mut bob.ui,
        ALICE,
        78,
        OtpIncomingFileReceive {
            contact_name: contact.clone(),
            seq: Some(content_seq),
            temp_path: arrived,
            kind: OtpIncomingKind::File { final_path: final_path.clone() },
        },
    )
    .await;

    assert_eq!(
        std::fs::read(&final_path).expect("the orphaned content is recovered and lands"),
        body
    );
    assert!(
        bob.ui.status_notice.clone().is_none_or(|(m, _)| !m.contains("rejected")),
        "no rejection notice - the heal recognised the crash shape"
    );
    assert!(bob.queued().len() > acks_before, "the spend is acknowledged");
    let (ack_seq, proof) = last_ack(&mut bob);
    assert_eq!(ack_seq, content_seq);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert!(!alice.gate_held(&contact), "the true digest opens the sender's gate");
    assert!(
        bob.session.otp_store_mut().is_next_expected(&contact, content_seq + 1),
        "and the receiver's expectation moved past the healed position"
    );
}

// ---------------------------------------------------------------------
// An orphaned spend behind a draining queue is promoted, not dropped (TB-290)
// ---------------------------------------------------------------------

/// The pad queue seals ahead of an armed gate, so a kill between an
/// encrypt and its `record_sealed` leaves a real spend that is sequenced
/// *after* everything queued while an earlier send still holds the gate.
/// Startup reconciliation used to read that armed gate as "stale intent"
/// and drop the record - the next seal then leapfrogged the orphan, and
/// the peer's tool refused its bytes at the orphan's position for good.
/// Now the intent stands: every new seal for the contact waits, the queue
/// drains, and the moment the gate clears the orphan is promoted onto it
/// and recovered from `.last_sent`, which nothing could overwrite meanwhile.
///
/// @requirement TB-290
#[tokio::test]
async fn an_orphaned_spend_behind_a_draining_queue_is_promoted_once_the_gate_clears() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob, contact) = pair("deferred-orphan", Id::Opaque, Id::Opaque).await;
    alice.ui.mark_otp_active(BOB);

    send_text(&mut alice, &contact, "first").await;
    send_text(&mut alice, &contact, "second").await;
    assert_eq!(alice.session.otp_queued_for(&contact), 2);
    let front_seq = alice
        .session
        .otp_store_mut()
        .get(&contact)
        .and_then(|s| s.pending_unacked_out_seq)
        .expect("the front is on the wire");

    // The interrupted third seal: intent written, tool advanced, process
    // dead before `record_sealed`.
    let (orphan_nonce, orphan_proof) = aloo::crypto::otp::fresh_ack_nonce();
    alice.session.otp_store_mut().set_encrypt_intent_with_proof(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
        Some(orphan_proof),
    );
    // What goes under the pad is the routing header plus the text
    // (`otp::OtpInner`, private - mirrored here field for field, since
    // bincode encodes by position), exactly as `build_otp_envelope` frames
    // it, so bob's receive path opens it like any other message.
    #[derive(serde::Serialize)]
    struct Inner {
        channel: Option<String>,
        payload: Vec<u8>,
    }
    let inner = aloo::proto::encode(&Inner {
        channel: None,
        payload: b"third, orphaned".to_vec(),
    })
    .unwrap();
    let orphan_bytes = aloo::client::otp::wrap_outgoing_with_nonce(&alice.otp, inner, &contact, orphan_nonce)
        .await
        .expect("the pre-crash encrypt succeeds");
    let orphan_seq = alice.session.otp_store_mut().get(&contact).unwrap().next_out_seq;
    let spent_at_crash = alice.pad_spent(&contact).await;

    // Restart: reconciliation must neither drop the record nor promote it
    // over the queued front.
    let promoted = aloo::client::otp::reconcile_orphaned_sends(&alice.otp, alice.session.otp_store_mut()).await;
    assert!(promoted.is_empty(), "nothing is promoted while the queue front holds the gate");
    let state = alice.session.otp_store_mut().get(&contact).cloned().unwrap();
    assert!(state.encrypt_intent.is_none(), "the write-ahead slot is free for the next seal's own record");
    assert!(state.deferred_spend.is_some(), "the record of the orphaned spend stands, parked");
    assert!(alice.session.otp_store_mut().encrypt_in_flight(&contact), "and it holds every new seal");
    assert_eq!(state.pending_unacked_out_seq, Some(front_seq), "the front keeps the gate");

    // Anything written meanwhile waits - a seal now would overwrite the
    // orphan's only copy and leapfrog its position.
    send_text(&mut alice, &contact, "fourth, written after the restart").await;
    assert_eq!(alice.pad_spent(&contact).await, spent_at_crash, "held, not sealed");
    assert_eq!(alice.session.otp_held_plaintext_for(&contact), 1);

    // The queue drains: first, then second, each acknowledged for real.
    for _ in 0..2 {
        let (seq, msg_id, envelope, device) = alice
            .queued()
            .into_iter()
            .filter_map(|p| match p {
                P2pPayload::OtpEnvelope { seq, msg_id, envelope, sender_device_id, .. } => {
                    Some((seq, msg_id, envelope, sender_device_id))
                }
                _ => None,
            })
            .next_back()
            .expect("the front is on the wire");
        receive_text(&mut bob, seq, msg_id, envelope, device).await;
        let (ack_seq, proof) = last_ack(&mut bob);
        ack(&mut alice, BOB, ack_seq, proof).await;
    }
    assert_eq!(alice.session.otp_queued_for(&contact), 0, "the queue has drained");

    // The gate clearing with nothing queued is what promotes the orphan.
    let state = alice.session.otp_store_mut().get(&contact).cloned().unwrap();
    assert_eq!(state.pending_unacked_out_seq, Some(orphan_seq), "the orphan now holds the gate");
    assert!(state.deferred_spend.is_none(), "and its parked record is retired");
    assert_eq!(state.pending_ack_proof, Some(orphan_proof), "insisting on the proof its intent recorded");
    assert_eq!(alice.session.otp_held_plaintext_for(&contact), 1, "the fourth still waits behind it");
    assert_eq!(alice.pad_spent(&contact).await, spent_at_crash, "nothing new was sealed");

    // Recovery carries it - the very bytes the interrupted encrypt made.
    let sent_before = alice.queued().len();
    aloo::client::otp::recover_and_resend(&mut NullSink, &mut alice.session, &mut alice.ui)
        .await
        .expect("recovery");
    let (seq, msg_id, envelope, device) = alice
        .queued()
        .into_iter()
        .skip(sent_before)
        .find_map(|p| match p {
            P2pPayload::OtpEnvelope { seq, msg_id, envelope, sender_device_id, .. } => {
                Some((seq, msg_id, envelope, sender_device_id))
            }
            _ => None,
        })
        .expect("the orphan is resent");
    assert_eq!(seq, orphan_seq);
    assert_eq!(envelope.blocks, vec![orphan_bytes], "byte-identical to the interrupted encrypt");

    // It lands in order, its ack opens the gate, and the fourth finally seals.
    receive_text(&mut bob, seq, msg_id, envelope, device).await;
    let delivered = bob
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| matches!(&e.body, MessageBody::Text(t) if t == "third, orphaned"));
    assert!(delivered);
    let (ack_seq, proof) = last_ack(&mut bob);
    ack(&mut alice, BOB, ack_seq, proof).await;
    assert_eq!(alice.session.otp_held_plaintext_for(&contact), 0);
    assert!(alice.pad_spent(&contact).await > spent_at_crash, "the fourth sealed behind it");
}
