//! Two decisions a live session's own paths make about a message, driven
//! over a real `SessionState` (`SessionState::for_test`) the same way
//! `session_receipt_test.rs` is and for the same reason: each is made
//! *inside* those paths, so testing around them would prove nothing.
//!
//! - **Being named with an `@`** (docs/SPEC.md Functionality #33): an
//!   arriving text message that writes `@<your nickname>` plays
//!   `assets/ping.wav`, and one that does not plays nothing. `for_test`
//!   drops the mixer's receiver, so the sound itself is not audible to a
//!   test; what is observable is that a source was pushed onto the mixer
//!   at all (`SessionState::mixer_sources_started`).
//! - **The durable send queue** (docs/SPEC.md Functionality #34): what
//!   the transport could not send is handed to the session as
//!   `P2pEvent::Undeliverable`, and the session decides whether to keep
//!   it. `client::outbox`'s own store is `outbox_test.rs`; this is the
//!   wiring between the two.

use aloo::client::connect::ResolvedIdentity;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::crypto::pq::{
    PqPrivateBundle, PqPublicBundle, bundle_fingerprint, generate_bundle_with_bits, seal_send,
};
use aloo::proto::{self, ChannelInfo, ChannelKind, Content, Envelope, KeyMode, UserId, UserInfo};

/// Small enough to keep the suite quick - key *size* is not what any of
/// these assert, same trade `session_receipt_test.rs` makes.
const TEST_KEY_BITS: usize = 1024;

const ALICE: UserId = UserId(2);

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-mention-ping-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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

struct Peers {
    me: Identity,
    alice: Identity,
}

/// A session belonging to `own_name`, with alice known and a link opened
/// to her (never punched, so nothing leaves the machine).
async fn session_and_ui(name: &str, own_name: &str) -> (SessionState, UiState, Peers) {
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

    let mut ui = UiState::new(own_name.into());
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
    session.peer_link_mut().ensure_link(&mut NullSink, ALICE).await;
    (
        session,
        ui,
        Peers {
            me,
            alice: alice_identity,
        },
    )
}

/// An envelope alice really did seal to us. `send_id` is per-message
/// because `ReplayGuard` refuses a repeat.
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

/// @requirement AC-403
#[tokio::test]
async fn a_channel_message_naming_you_plays_a_sound_and_one_that_does_not_is_silent() {
    let (mut session, mut ui, peers) = session_and_ui("channel", "me").await;
    let before = session.mixer_sources_started();

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, Some("general"), 1, "nothing to see here"),
    );
    assert_eq!(ui.channels[0].log.len(), 1, "the message landed either way");
    assert_eq!(
        session.mixer_sources_started(),
        before,
        "an ordinary message plays nothing"
    );

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, Some("general"), 2, "@me can you look at this"),
    );
    assert_eq!(
        session.mixer_sources_started(),
        before + 1,
        "being named plays assets/ping.wav"
    );
}

/// @requirement AC-403
#[tokio::test]
async fn a_dm_naming_you_plays_the_same_sound() {
    let (mut session, mut ui, peers) = session_and_ui("dm", "me").await;
    let before = session.mixer_sources_started();

    aloo::client::direct_message::on_message(
        &mut ui,
        &mut session,
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, None, 1, "hey @me"),
    )
    .await;

    assert_eq!(session.mixer_sources_started(), before + 1);
}

/// `sound_notifications=off` silences it, like every other event sound -
/// the message still arrives and is still logged.
/// @requirement AC-402
#[tokio::test]
async fn sound_notifications_off_silences_the_mention_ping() {
    let (mut session, mut ui, peers) = session_and_ui("silent", "me").await;
    session.set_sound_switches(true, false);
    let before = session.mixer_sources_started();

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, Some("general"), 1, "@me are you there"),
    );

    assert_eq!(ui.channels[0].log.len(), 1, "the message still arrives");
    assert_eq!(session.mixer_sources_started(), before, "but nothing sounds");
}

/// The nickname it matches is this client's own, not a fixed word: a
/// session belonging to someone else is not pinged by `@me`.
/// @requirement AC-403
#[tokio::test]
async fn the_sound_follows_your_own_nickname() {
    let (mut session, mut ui, peers) = session_and_ui("other-nick", "bob").await;
    let before = session.mixer_sources_started();

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, Some("general"), 1, "@me is someone else"),
    );
    assert_eq!(session.mixer_sources_started(), before);

    aloo::client::channel::on_message(
        &mut ui,
        &mut session,
        "general".into(),
        ALICE,
        "alice".into(),
        None,
        sealed_to(&peers, Some("general"), 2, "@bob over to you"),
    );
    assert_eq!(session.mixer_sources_started(), before + 1);
}

// ---------------------------------------------------------------------
// The durable send queue, through the real transport (US-064)
// ---------------------------------------------------------------------

/// Plays the session loop's part: a send only *raises* the fact that it
/// could not go out (`P2pEvent::Undeliverable`); the loop is what turns
/// that into a queued message.
async fn drain(ui: &mut UiState, session: &mut SessionState) {
    aloo::client::session::drain_p2p_events(&mut aloo::control::NullSink, ui, session)
        .await
        .expect("draining should not fail");
}

/// A sealed text payload, of the shape the DM send path produces. Opaque
/// on purpose: the queue keeps what was already encrypted for the
/// recipient and never looks inside, which is what keeps a queued message
/// under whatever layering it was sent with.
fn sealed_text(body: &[u8]) -> aloo::p2p_proto::P2pPayload {
    aloo::p2p_proto::P2pPayload::Envelope {
        channel: None,
        msg_id: Some(1),
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![body.to_vec()],
        },
    }
}

/// Content addressed to a peer whose link was never punched is kept
/// rather than dropped - through the real transport, the real event, and
/// the real session handler, which is where each half could disagree.
/// @requirement AC-410
#[tokio::test]
async fn a_message_to_an_unreachable_peer_is_queued_rather_than_lost() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-dm", "me").await;
    assert_eq!(session.queued_for("alice"), 0);

    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"are you there"));
    drain(&mut ui, &mut session).await;

    assert_eq!(
        session.queued_for("alice"),
        1,
        "the sealed message is waiting for alice, not gone"
    );
    assert!(
        session
            .peer_link_mut()
            .pending_payloads(ALICE)
            .is_empty(),
        "and it is not also sitting in the transport's own queue - one copy, or it goes twice"
    );
}

/// With the setting off, nothing is kept: the transport's own short
/// in-memory queue is back in charge, exactly as it was before. Flipped
/// on a live session, not read at start - `queue_send_messages` is one of
/// the settings that takes effect when it is changed.
/// @requirement AC-410, AC-411
#[tokio::test]
async fn nothing_is_queued_while_the_setting_is_off() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-off", "me").await;
    session.set_queue_send_messages(false);

    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"are you there"));
    drain(&mut ui, &mut session).await;

    assert_eq!(session.queued_for("alice"), 0);
    assert_eq!(
        session.peer_link_mut().pending_payloads(ALICE).len(),
        1,
        "it waits in the transport's own queue instead, as it always did"
    );
}

/// Several messages to the same peer keep the order they were written in
/// - what a pad-wrapped conversation's sequence depends on.
/// @requirement AC-410
#[tokio::test]
async fn messages_queue_in_the_order_they_were_sent() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-order", "me").await;
    for body in [b"first".as_slice(), b"second", b"third"] {
        session
            .peer_link_mut()
            .send_reliable_or_queue(ALICE, sealed_text(body));
        drain(&mut ui, &mut session).await;
    }
    assert_eq!(session.queued_for("alice"), 3);
}

/// Once anything is queued for a peer, a later send joins the back of
/// that queue rather than overtaking it - even after their link is up
/// again. Overtaking would deliver a message ahead of ones sealed before
/// it, which for a pad-wrapped run breaks the sequence its receiver's pad
/// expects.
/// @requirement AC-414
#[tokio::test]
async fn a_later_send_never_overtakes_what_is_already_queued() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-fifo", "me").await;
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"first"));
    drain(&mut ui, &mut session).await;
    assert_eq!(session.queued_for("alice"), 1);

    // Their link comes up, but the queue has not been drained yet - the
    // state a send must not slip through.
    session.peer_link_mut().set_queue_held(ALICE, true);
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"second"));
    drain(&mut ui, &mut session).await;
    assert_eq!(
        session.queued_for("alice"),
        2,
        "the later message joined the queue instead of going out ahead of the first"
    );

    // Draining clears the hold, so what comes out of the queue does go.
    session.peer_link_mut().set_queue_held(ALICE, false);
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"third"));
    drain(&mut ui, &mut session).await;
    assert_eq!(
        session.queued_for("alice"),
        3,
        "still queued, because their link was never actually punched"
    );
}

/// The one thing that removes a queued message: the contact is gone from
/// this machine, so nothing queued for them could be delivered or read
/// back. A contact still pinned keeps their whole queue, however long it
/// has been waiting.
/// @requirement AC-413
#[tokio::test]
async fn the_sweep_drops_a_deleted_contacts_queue_and_keeps_a_pinned_ones() {
    let (mut session, mut ui, _peers) = session_and_ui("sweep", "me").await;
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"for alice"));
    drain(&mut ui, &mut session).await;
    assert_eq!(session.queued_for("alice"), 1);

    // Nothing is pinned for alice in this scratch id_store, so the sweep
    // treats her as a contact this machine no longer holds keys for.
    assert_eq!(aloo::client::session::sweep_outbox(&mut session), 1);
    assert_eq!(session.queued_for("alice"), 0);

    // Pinned, and the queue survives every sweep from then on.
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"again"));
    drain(&mut ui, &mut session).await;
    session.pin_bare_contact_for_test("alice", "laptop");
    assert_eq!(aloo::client::session::sweep_outbox(&mut session), 0);
    assert_eq!(session.queued_for("alice"), 1);
    assert_eq!(aloo::client::session::sweep_outbox(&mut session), 0, "and again");
}

/// A voice message's chunks are sealed for the recipient before they
/// reach the transport, so keeping them costs no plaintext - and they are
/// kept, which is what lets a recording be made for someone who is not
/// there yet.
/// @requirement AC-410
#[tokio::test]
async fn a_voice_chunk_for_an_unreachable_peer_is_queued_too() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-voice", "me").await;
    session
        .peer_link_mut()
        .send_unreliable_voice(ALICE, 7, 0, vec![vec![1, 2, 3, 4]]);
    drain(&mut ui, &mut session).await;
    assert_eq!(session.queued_for("alice"), 1);
}

/// A file transfer is a live, consent-gated conversation - replaying half
/// of one later is not a delivery, so it fails the way it always did.
/// @requirement AC-408
#[tokio::test]
async fn a_file_payload_is_never_queued() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-file", "me").await;
    session.peer_link_mut().send_reliable_or_queue(
        ALICE,
        aloo::p2p_proto::P2pPayload::FileChunk {
            stream_id: 1,
            seq: 0,
            blocks: vec![vec![9u8; 16]],
        },
    );
    drain(&mut ui, &mut session).await;
    assert_eq!(session.queued_for("alice"), 0);
}

/// Nothing is queued against a peer we hold no name for: a nickname is
/// what this queue outlives a reconnect by, and there is nothing else to
/// file it under.
/// @requirement AC-410
#[tokio::test]
async fn an_unnamed_peer_is_not_queued_against() {
    let (mut session, mut ui, _peers) = session_and_ui("queue-unnamed", "me").await;
    ui.known_users.remove(&ALICE);
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"who?"));
    drain(&mut ui, &mut session).await;
    assert_eq!(session.queued_for("alice"), 0);
}

// ---------------------------------------------------------------------
// Settings that take effect when they are changed (AC-411)
// ---------------------------------------------------------------------

/// The No-IP updater is rebuilt from the settings as they are now, not as
/// they were at session start - so filling the three fields in, or
/// turning the switch off, is answered on the spot.
/// @requirement AC-411
#[tokio::test]
async fn the_noip_updater_is_rebuilt_when_its_settings_change() {
    let (mut session, _ui, _peers) = session_and_ui("noip", "me").await;
    assert!(!session.noip_is_configured(), "nothing is configured to start with");

    let target = aloo::settings::DirectPunchTarget::parse("alice,alicehost.example,every_5m")
        .expect("a valid target");
    let configured = aloo::settings::Settings {
        noip_when_no_server_and_direct_punch_is_active: true,
        direct_punch: true,
        direct_punch_to: vec![target.clone()],
        noip_hostname: "me.ddns.example".into(),
        noip_username: "alice".into(),
        noip_password: "hunter2".into(),
        ..aloo::settings::Settings::default()
    };
    session.resync_noip(&configured);
    assert!(session.noip_is_configured(), "all three filled in and a target named");

    // The switch alone is not enough - there has to be someone to be
    // reachable *for*, the same three-way check the session start makes.
    let no_targets = aloo::settings::Settings {
        direct_punch_to: Vec::new(),
        ..configured.clone()
    };
    session.resync_noip(&no_targets);
    assert!(!session.noip_is_configured());

    session.resync_noip(&configured);
    assert!(session.noip_is_configured());
    let switched_off = aloo::settings::Settings {
        noip_when_no_server_and_direct_punch_is_active: false,
        ..configured
    };
    session.resync_noip(&switched_off);
    assert!(!session.noip_is_configured(), "turning it off stops it now, not next run");
}

/// A half-filled No-IP account cannot update anything, so it configures
/// nothing rather than running and failing forever.
/// @requirement AC-411
#[tokio::test]
async fn a_half_filled_noip_account_configures_nothing() {
    let (mut session, _ui, _peers) = session_and_ui("noip-partial", "me").await;
    let target = aloo::settings::DirectPunchTarget::parse("alice,alicehost.example,every_5m")
        .expect("a valid target");
    session.resync_noip(&aloo::settings::Settings {
        noip_when_no_server_and_direct_punch_is_active: true,
        direct_punch: true,
        direct_punch_to: vec![target],
        noip_hostname: "me.ddns.example".into(),
        noip_username: String::new(),
        noip_password: "hunter2".into(),
        ..aloo::settings::Settings::default()
    });
    assert!(!session.noip_is_configured());
}
