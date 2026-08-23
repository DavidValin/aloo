//! The one decision a delivery receipt turns on: a message is
//! acknowledged when, and only when, this side could actually decrypt it
//! (docs/PROTOCOL.md 7.2.1).
//!
//! Driven through the real receive paths (`channel::on_message`,
//! `direct_message::on_message`) over a real `SessionState`
//! (`SessionState::for_test`), rather than around them - the whole point
//! is that the receipt is emitted from the decrypted branch and nowhere
//! else.
//!
//! Nothing here needs a peer: the link to the "sender" is only ever
//! `ensure_link`-ed, never punched, so anything the session decides to
//! send waits in that link's pending queue where the assertions can read
//! it (`PeerLinkManager::pending_payloads`).

use aloo::client::connect::ResolvedIdentity;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::crypto::pq::{
    PqPrivateBundle, PqPublicBundle, bundle_fingerprint, generate_bundle_with_bits, seal_send,
};
use aloo::p2p_proto::{P2pPayload, ReceiptStage};
use aloo::proto::{self, ChannelInfo, ChannelKind, Content, Envelope, KeyMode, UserId, UserInfo};

/// Small enough to keep the suite quick - key *size* is not what any of
/// these assert (see `test/cucumber/world.rs`'s `SCENARIO_KEY_BITS` for
/// the same trade and the same reasoning).
const TEST_KEY_BITS: usize = 1024;

const ALICE: UserId = UserId(2);
const MSG_ID: u64 = 4242;

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-session-receipt-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Both halves of one identity, for the two roles a test plays: ours (the
/// session's own keybundle) and alice's (the sender that seals to it).
struct Identity {
    public: PqPublicBundle,
    private: PqPrivateBundle,
    der: Vec<u8>,
}

fn identity() -> Identity {
    let (public, private) = generate_bundle_with_bits(TEST_KEY_BITS).expect("keygen");
    let der = proto::encode(&public).expect("encode bundle");
    Identity {
        public,
        private,
        der,
    }
}

/// A session that can read what alice seals to it, with alice already
/// known as a peer and a link opened to her (but never punched).
async fn session_and_ui(name: &str) -> (SessionState, UiState, Peers) {
    let me = identity();
    let alice_identity = identity();
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity {
            private: me.private.clone(),
            public_der: me.der.clone(),
        },
        scratch: scratch_dir(name),
        otp: None,
    })
    .await;

    let mut ui = UiState::new("me".into());
    ui.set_own_id(UserId(1));
    ui.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    ui.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    let alice = UserInfo {
        id: ALICE,
        name: "alice".into(),
        public_key_der: alice_identity.der.clone(),
        key_mode: KeyMode::PqHybrid,
    };
    ui.seed_member("general", alice.clone());
    ui.known_users.insert(ALICE, alice);

    // Opens the link record the receipt will queue against. Nothing is
    // punched, so nothing leaves the machine.
    session
        .peer_link_mut()
        .ensure_link(&mut NullSink, ALICE)
        .await;
    (
        session,
        ui,
        Peers {
            me,
            alice: alice_identity,
        },
    )
}

/// The two identities a test needs back: ours (what an envelope must be
/// sealed to) and alice's (what signs it).
struct Peers {
    me: Identity,
    alice: Identity,
}

/// An envelope alice really did seal to us - the same construction
/// `envelope::encrypt_envelope_for` builds, at the sender's side.
///
/// `send_id` is per-message because `ReplayGuard` refuses a second send
/// from one peer under an id it has already accepted.
fn sealed_to(peers: &Peers, channel: Option<&str>, send_id: u64, text: &str) -> Envelope {
    let blob = seal_send(
        &peers.alice.private,
        peers.me.public.bootstrap_encap(),
        bundle_fingerprint(&peers.me.public).expect("fingerprint"),
        channel.map(str::to_string),
        send_id,
        text.as_bytes(),
    )
    .expect("sealing should succeed");
    Envelope {
        content: Content::Text,
        blocks: vec![blob],
    }
}

/// An envelope alice sealed to *someone else*: it arrives, and nothing
/// here can open it.
fn sealed_to_someone_else(peers: &Peers, channel: Option<&str>, send_id: u64) -> Envelope {
    let stranger = identity();
    let blob = seal_send(
        &peers.alice.private,
        stranger.public.bootstrap_encap(),
        bundle_fingerprint(&stranger.public).expect("fingerprint"),
        channel.map(str::to_string),
        send_id,
        b"not for you",
    )
    .expect("sealing should succeed");
    Envelope {
        content: Content::Text,
        blocks: vec![blob],
    }
}

/// Anything the session decided to send alice, still queued because her
/// link was never punched.
fn queued_for_alice(session: &mut SessionState) -> Vec<P2pPayload> {
    session.peer_link_mut().pending_payloads(ALICE)
}

fn receipts(session: &mut SessionState) -> Vec<(u64, ReceiptStage)> {
    queued_for_alice(session)
        .into_iter()
        .filter_map(|p| match p {
            P2pPayload::DeliveryReceipt { msg_id, stage } => Some((msg_id, stage)),
            _ => None,
        })
        .collect()
}

/// @requirement AC-233, TB-233
#[tokio::test]
async fn a_channel_message_is_receipted_once_it_has_been_decrypted() {
    let (mut session, mut ui, peers) = session_and_ui("channel-ok").await;

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        Some(MSG_ID),
        sealed_to(&peers, Some("general"), 1, "hi there"),
    );

    assert_eq!(
        ui.channels[0].log.len(),
        1,
        "the message itself landed in the log"
    );
    assert_eq!(
        receipts(&mut session),
        vec![(MSG_ID, ReceiptStage::Decrypted)],
        "and exactly one receipt was sent, naming that message"
    );
}

/// The whole distinction the receipt exists to make: arriving is not the
/// same as being readable.
/// @requirement AC-233
#[tokio::test]
async fn an_undecryptable_message_is_never_receipted() {
    let (mut session, mut ui, peers) = session_and_ui("channel-bad").await;

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        Some(MSG_ID),
        // Sealed to a key that is not ours: it arrives, and stays shut.
        sealed_to_someone_else(&peers, Some("general"), 1),
    );

    assert!(
        ui.channels[0].log.is_empty(),
        "nothing readable, so nothing shown"
    );
    assert!(
        receipts(&mut session).is_empty(),
        "and nothing acknowledged - the sender's row stays undelivered, which is the truth"
    );
}

/// @requirement AC-233
#[tokio::test]
async fn a_direct_message_is_receipted_once_it_has_been_decrypted() {
    let (mut session, mut ui, peers) = session_and_ui("dm-ok").await;

    aloo::client::direct_message::on_message(
        &mut ui,
        &mut session,
        ALICE,
        "alice".into(),
        Some(MSG_ID),
        sealed_to(&peers, None, 1, "just between us"),
    )
    .await;

    assert_eq!(
        ui.private_rooms[&ALICE].log.len(),
        1,
        "the message landed in her room"
    );
    assert_eq!(
        receipts(&mut session),
        vec![(MSG_ID, ReceiptStage::Decrypted)]
    );
}

/// @requirement TB-230
#[tokio::test]
async fn a_message_that_names_nothing_is_never_receipted() {
    let (mut session, mut ui, peers) = session_and_ui("unnamed").await;

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, Some("general"), 1, "no answer wanted"),
    );

    assert_eq!(ui.channels[0].log.len(), 1, "it still arrives");
    assert!(
        receipts(&mut session).is_empty(),
        "a sender that asked for nothing is answered with nothing"
    );
}

/// A message held behind an identity review (docs/PROTOCOL.md §12) was
/// still read - the gate is about whether to show it, not whether it made
/// sense - so it is acknowledged like any other.
/// @requirement AC-233, TB-233
#[tokio::test]
async fn a_message_held_pending_a_trust_decision_is_still_receipted() {
    let (mut session, mut ui, peers) = session_and_ui("held").await;
    ui.push_identity_review(
        ALICE,
        "alice".into(),
        "their key changed".into(),
        aloo::client::tui::ui::IdentityCase::StaticMismatch {
            new_public_key_der: vec![9; 4],
            previous_public_key_der: vec![8; 4],
        },
    );
    assert!(ui.is_trust_gated(ALICE), "the gate is up");

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        Some(MSG_ID),
        sealed_to(&peers, Some("general"), 1, "held for now"),
    );

    assert!(
        ui.channels[0].log.is_empty(),
        "it is held back from the visible log"
    );
    assert_eq!(
        receipts(&mut session),
        vec![(MSG_ID, ReceiptStage::Decrypted)],
        "but it was read, and saying otherwise would be a lie"
    );
}
