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
            aloo::crypto::otp::contact_name_for(&a_fp, &b_fp)
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
            aloo::client::otp::contact_name_if_active(&side.session, &side.peer_der).as_deref(),
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
    // Exactly what the real connect path does when a peer becomes known -
    // without it there is no encryption key to seal an inner envelope to.
    aloo::client::session::seed_direct_peer_keys(&mut session, peer_id, &peer);
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

fn take_envelope(side: &mut Side) -> (u64, Option<u64>, Envelope) {
    side.queued()
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

fn take_file_offer(side: &mut Side) -> (u64, u64, Envelope) {
    side.queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpFileOffer {
                stream_id,
                seq,
                envelope,
                ..
            } => Some((stream_id, seq, envelope)),
            _ => None,
        })
        .expect("a pad-wrapped file offer should have gone out")
}

fn take_voice_offer(side: &mut Side) -> (u64, u64, Envelope) {
    side.queued()
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::OtpVoiceOffer {
                stream_id,
                seq,
                envelope,
                ..
            } => Some((stream_id, seq, envelope)),
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

async fn receive_text(bob: &mut Side, seq: u64, msg_id: Option<u64>, envelope: Envelope) {
    aloo::client::otp::on_message(
        &mut bob.session,
        &mut bob.ui,
        None,
        ALICE,
        "alice".into(),
        seq,
        msg_id,
        envelope,
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

    let (seq, msg_id, envelope) = take_envelope(&mut alice);
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

    receive_text(&mut bob, seq, msg_id, envelope).await;
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

    let (stream_id, offer_seq, offer_env) = take_file_offer(&mut alice);
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

    let (stream_id, seq, envelope) = take_voice_offer(&mut alice);
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
            aloo::client::otp_mail::check_recipient(&alice.session, "bob").await,
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
    session
        .id_store_mut()
        .check_and_pin(peer_name, &opaque_pin(peer_name));
    session.otp_store_mut().mark_provisioned(contact);

    // No server anywhere: the only thing that makes this peer addressable
    // is a `direct_punch_to` entry naming them, which is also where their
    // nickname comes from (`p2p::direct_nickname_of`).
    session.peer_link_mut().configure_direct_punch(
        own_name.to_string(),
        vec![aloo::settings::DirectPunchTarget {
            nickname: peer_name.to_string(),
            host: "127.0.0.1".to_string(),
            port: 1,
            frequency: aloo::settings::PunchFrequency::parse("1m").expect("valid"),
        }],
        0,
    );
    // Somewhere for a send to queue. Never punched, so nothing leaves the
    // machine and every assertion below reads what this side *decided* to
    // send (`SessionState::for_test`'s own convention).
    let peer = aloo::client::p2p::direct_peer_id(peer_name);
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
            aloo::client::otp::contact_name_if_active(&side.session, &side.peer_der).as_deref(),
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
    let (seq, _, envelope) = take_envelope(&mut alice);
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
    let (reply_seq, _, reply_env) = take_envelope(&mut bob);
    aloo::client::otp::on_message(
        &mut alice.session,
        &mut alice.ui,
        None,
        alice.peer,
        "bob".into(),
        reply_seq,
        Some(reply),
        reply_env,
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
    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    receive_text(&mut bob, seq, msg_id, envelope).await;
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
    let (seq, msg_id, envelope) = take_envelope(&mut alice);
    assert_eq!(alice.envelopes_sent(), 1);

    send_text(&mut alice, &contact, "second").await;
    assert_eq!(
        alice.envelopes_sent(),
        1,
        "the second message must wait behind the first rather than spend pad"
    );

    receive_text(&mut bob, seq, msg_id, envelope).await;
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
    let (a_seq, a_msg, a_env) = take_envelope(&mut alice);
    let (b_seq, b_msg, b_env) = take_envelope(&mut bob);

    receive_text(&mut bob, a_seq, a_msg, a_env).await;
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
    let (seq, msg_id, envelope) = take_envelope(side);
    aloo::client::otp::on_message(
        &mut to.session,
        &mut to.ui,
        None,
        from,
        from_name.into(),
        seq,
        msg_id,
        envelope,
    )
    .await
    .expect("the receive path should not fail");
}

/// `/endotp` and the notice it owes the peer, under one framing.
///
/// Ending a session is something said to this contact like anything else,
/// so it goes under their pad - which for a `Direct` pair is the only way
/// it can be said at all, there being no envelope to seal it into. The
/// notice is confirmed by its own ack rather than by an `OtpDeliveryAck`,
/// so neither side may leave the stop-and-wait gate armed behind it.
async fn end_session_round_trip(label: &str, alice_kind: Id, bob_kind: Id) {
    let (mut alice, mut bob, contact) = pair(label, alice_kind, bob_kind).await;

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
        !alice.gate_held(&contact),
        "nothing acks the notice the way a message is acked, so arming the \
         gate behind it would wedge a later /otp on this same contact"
    );
    assert_eq!(
        alice.envelopes_sent(),
        1,
        "the notice goes out padded, not as a bare pq_hybrid envelope"
    );

    deliver_envelope(&mut bob, ALICE, "alice", &mut alice).await;
    assert!(
        !bob.ui.is_otp_active(ALICE),
        "the peer converges to paused on receiving it"
    );
    assert!(
        !bob.gate_held(&contact),
        "and the ack it sends back must not arm bob's gate either"
    );

    // The ack comes back the same way, and stops alice's durable retry.
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| s.pending_end_notice),
        "until the ack lands, the notice is still owed"
    );
    deliver_envelope(&mut alice, BOB, "bob", &mut bob).await;
    assert!(
        alice
            .session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice),
        "the ack is what finally stops the retry"
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
