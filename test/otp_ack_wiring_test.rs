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
use aloo::client::tui::ui::{DeliveryStatus, MessageBody, UiState};
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
        self.session.peer_link_mut().pending_payloads(peer)
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

    /// How many pad-wrapped sends have genuinely left. `pending_payloads`
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
            port: 1,
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

    // The write-ahead record, exactly as `send_now` writes it...
    alice.session.otp_store_mut().set_encrypt_intent(
        &contact,
        aloo::client::otp_store::PendingOtpContent::Text { channel: None },
    );
    // ...then the encrypt itself - the tool advances - and the process
    // dies before `record_sent` ever runs.
    let spent = aloo::client::otp::wrap_outgoing(&alice.otp, b"orphaned".to_vec(), &contact)
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
/// necessary: `pending_payloads` reads rather than drains, so a second
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
