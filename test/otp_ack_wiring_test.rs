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
//! | alice | bob | framing | what is inside the pad |
//! |---|---|---|---|
//! | pq_hybrid | pq_hybrid | `PqWrapped` | a sealed, signed envelope |
//! | pq_hybrid | password  | `Direct`    | the plaintext itself |
//! | password  | password  | `Direct`    | the plaintext itself |
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
    /// A `pq_hybrid` bundle: can seal and sign an inner envelope.
    Pq,
    /// A password-derived RSA identity: persists across reconnects (so
    /// `/otp` will file a pad against it) but carries no envelope.
    Password,
}

impl Id {
    fn key_mode(self) -> KeyMode {
        match self {
            Id::Pq => KeyMode::PqHybrid,
            Id::Password => KeyMode::Password,
        }
    }
}

/// One side: its session, its UI, and who its peer is.
struct Side {
    session: SessionState,
    ui: UiState,
    peer: UserId,
    peer_der: Vec<u8>,
    peer_mode: KeyMode,
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

/// A built identity, in the two forms the rest of this file needs it.
struct Identity {
    resolved: ResolvedIdentity,
    der: Vec<u8>,
}

fn identity(kind: Id) -> Identity {
    match kind {
        Id::Pq => {
            let (public, private) =
                aloo::crypto::pq::generate_bundle_with_bits(SCENARIO_KEY_BITS).expect("pq keygen");
            let der = aloo::proto::encode(&public).expect("pq der");
            Identity {
                resolved: ResolvedIdentity::Pq {
                    private,
                    public_der: der.clone(),
                },
                der,
            }
        }
        Id::Password => {
            let kp = aloo::crypto::KeyPair::generate_with_bits(SCENARIO_KEY_BITS).expect("rsa");
            let der = aloo::crypto::public_key_to_der(&kp.public).expect("rsa der");
            Identity {
                resolved: ResolvedIdentity::Rsa(kp),
                der,
            }
        }
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
    let a = identity(alice_kind);
    let b = identity(bob_kind);

    let contact = match (alice_kind, bob_kind) {
        (Id::Pq, Id::Pq) => {
            let a_fp = aloo::crypto::pq::fingerprint_of_encoded(&a.der).expect("alice fp");
            let b_fp = aloo::crypto::pq::fingerprint_of_encoded(&b.der).expect("bob fp");
            aloo::crypto::otp::contact_name_for(&a_fp, &b_fp)
        }
        _ => aloo::crypto::otp::contact_name_for_keys(&a.der, &b.der),
    };
    let (alice_cfg, bob_cfg) = split_one_pad(label, &contact).await;

    let alice = build_side(
        "alice", ALICE, a.resolved, alice_kind, BOB, "bob", b.der, bob_kind, alice_cfg, &contact,
        label,
    )
    .await;
    let bob = build_side(
        "bob", BOB, b.resolved, bob_kind, ALICE, "alice", a.der, alice_kind, bob_cfg, &contact,
        label,
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
    own_kind: Id,
    peer_id: UserId,
    peer_name: &str,
    peer_der: Vec<u8>,
    peer_kind: Id,
    otp: OtpCliConfig,
    contact: &str,
    label: &str,
) -> Side {
    let mut session = SessionState::for_test(TestSessionSpec {
        key_mode: own_kind.key_mode(),
        identity: own_identity,
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
        key_mode: peer_kind.key_mode(),
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
        peer_mode: peer_kind.key_mode(),
    }
}

// ---------------------------------------------------------------------
// Driving one send of each kind
// ---------------------------------------------------------------------

async fn send_text(side: &mut Side, contact: &str, text: &str) -> u64 {
    let (msg_id, delivery) = side.ui.start_delivery(&[side.peer]);
    side.ui
        .push_outgoing_dm(side.peer, MessageBody::Text(text.to_string()), Some(delivery));
    let peer_der = side.peer_der.clone();
    let peer_mode = side.peer_mode;
    aloo::client::otp::send_or_queue(
        &mut NullSink,
        &mut side.session,
        &mut side.ui,
        side.peer,
        contact,
        peer_mode,
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
    aloo::client::otp::on_delivery_ack(&mut NullSink, &mut to.ui, &mut to.session, from, seq, proof)
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
    // The wire block is pad ciphertext either way, so what distinguishes the
    // two framings is how much pad it cost. That is the whole reason
    // `Direct` exists: a `pq_hybrid` envelope is ~7KB of ML-DSA/ML-KEM/RSA
    // regardless of the message, which for a short chat line is almost all
    // of what the pad is spent on.
    let spent = envelope.blocks.first().map(|b| b.len()).unwrap_or(0);
    if direct {
        assert!(
            spent < 200,
            "direct framing should cost about the length of the message, spent {spent}"
        );
    } else {
        assert!(
            spent > 5000,
            "pq_hybrid framing seals a signed envelope before the pad ever sees it, spent {spent}"
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
/// @requirement AC-250, AC-251
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
    text_round_trip("text-pq-pw", Id::Pq, Id::Password, true).await;
}

/// Neither side has `pq_hybrid` - pure OTP, pinned RSA identities, pad
/// bound to those keys.
///
/// @requirement AC-250, AC-251, AC-252
#[tokio::test]
async fn text_no_pq_hybrid_anywhere_uses_direct_and_still_proves_its_ack() {
    if !require_otp() {
        return;
    }
    text_round_trip("text-pw-pw", Id::Password, Id::Password, true).await;
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
    text_round_trip("text-pw-pq", Id::Password, Id::Pq, true).await;
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

/// @requirement AC-250, AC-252
#[tokio::test]
async fn file_one_pq_hybrid_side_proves_both_of_its_spends() {
    if !require_otp() {
        return;
    }
    file_round_trip("file-pq-pw", Id::Pq, Id::Password, true).await;
}

/// @requirement AC-250, AC-252
#[tokio::test]
async fn file_no_pq_hybrid_anywhere_proves_both_of_its_spends() {
    if !require_otp() {
        return;
    }
    file_round_trip("file-pw-pw", Id::Password, Id::Password, true).await;
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
    if direct {
        assert_eq!(
            envelope.blocks.len(),
            1,
            "direct framing carries the encoded offer with no envelope around it"
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

    // Stands in for the chunked transport. The real receive worker
    // `on_voice_offer` just spawned owns `pending.temp_path` and would
    // race a write to it, so this hands the ciphertext over at a path of
    // its own - which is exactly what that worker would have produced.
    let staged = alice
        .session
        .otp_send_temp_file(stream_id)
        .expect("voice stages its ciphertext at offer time")
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
    assert_eq!(ack_seq, seq);
    ack(&mut alice, BOB, ack_seq, [0x03; 32]).await;
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

/// @requirement AC-250, AC-252
#[tokio::test]
async fn voice_one_pq_hybrid_side_proves_its_spend() {
    if !require_otp() {
        return;
    }
    voice_round_trip("voice-pq-pw", Id::Pq, Id::Password, true).await;
}

/// @requirement AC-250, AC-252
#[tokio::test]
async fn voice_no_pq_hybrid_anywhere_proves_its_spend() {
    if !require_otp() {
        return;
    }
    voice_round_trip("voice-pw-pw", Id::Password, Id::Password, true).await;
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
/// recipient check refuses - visibly, before any pad is spent.
///
/// @requirement AC-250, AC-252
#[tokio::test]
async fn mail_refuses_a_pure_otp_pair_rather_than_falling_back() {
    if !require_otp() {
        return;
    }
    let (mut alice, _bob, contact) = pair("mail-pw-pw", Id::Password, Id::Password).await;
    assert!(
        matches!(
            aloo::client::otp_mail::check_recipient(&alice.session, "bob").await,
            aloo::client::otp_mail::RecipientCheck::NotPqIdentity
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
