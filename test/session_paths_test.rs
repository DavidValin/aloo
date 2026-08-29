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
use aloo::client::tui::ui::MessageBody;
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

/// The whole reported flow, end to end: an open DM, the peer goes
/// offline, a message is sent to them, and they come back **under a new
/// `UserId`** - which is what every reconnect gives them
/// (`docs/PROTOCOL.md` §3), and the reason this queue is keyed by
/// nickname at all.
/// @requirement AC-410
#[tokio::test]
async fn a_message_queued_while_a_peer_was_away_goes_out_when_they_reconnect() {
    let (mut session, mut ui, _peers) = session_and_ui("reconnect", "me").await;

    // Sent while she is unreachable.
    session
        .peer_link_mut()
        .send_reliable_or_queue(ALICE, sealed_text(b"while you were out"));
    drain(&mut ui, &mut session).await;
    assert_eq!(session.queued_for("alice"), 1);

    // She disconnects: the server frees her id and the client forgets
    // everything that id named.
    aloo::client::session::forget_peer_for_test(&mut ui, &mut session, ALICE);
    assert_eq!(
        session.queued_for("alice"),
        1,
        "the queue outlives the connection it was written during"
    );

    // ...and comes back as somebody new, as far as the server is
    // concerned: same person, same nickname, different `UserId`.
    let reconnected = UserId(99);
    let alice = aloo::proto::UserInfo {
        id: reconnected,
        name: "alice".into(),
        public_key_der: vec![1, 2, 3, 4],
        key_mode: aloo::proto::KeyMode::PqHybrid,
    };
    ui.known_users.insert(reconnected, alice);
    session
        .peer_link_mut()
        .open_unpunched_link_for_test(reconnected);

    // Her link comes up, which is what the session acts on.
    session.inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
        peer: reconnected,
        status: aloo::client::p2p::LinkStatus::Active,
    });
    drain(&mut ui, &mut session).await;

    assert_eq!(
        session.queued_for("alice"),
        1,
        "handed to the transport, but still held: nothing may be deleted \
         on the strength of having been sent, only on her acknowledging it"
    );
    let sent = session.sent_or_queued_payloads(reconnected);
    assert!(
        sent.iter().any(|p| matches!(
            p,
            aloo::p2p_proto::P2pPayload::Envelope { envelope, .. }
                if envelope.blocks == vec![b"while you were out".to_vec()]
        )),
        "the message should have gone out to her new id: {sent:?}"
    );

    // Her acknowledgement is what finally retires it - and the only thing
    // that does.
    session.inject_p2p_event(aloo::client::p2p::P2pEvent::FrameAcked {
        peer: reconnected,
        tag: 0,
    });
    drain(&mut ui, &mut session).await;
    assert_eq!(
        session.queued_for("alice"),
        0,
        "acknowledged, so the copy on disk is finally redundant"
    );
}

/// The window this closes: a flushed message whose link dies before the
/// peer acknowledges it. The transport gives up on the frame
/// (`expire_pending`) and nothing else would ever re-send it, so the
/// on-disk copy has to still be there - and it is offered again the next
/// time the link opens.
/// @requirement AC-422
#[tokio::test]
async fn a_flushed_message_that_is_never_acknowledged_stays_held() {
    let (mut session, mut ui, peers) = session_and_ui("no-ack", "me").await;
    let _ = &peers;
    session
        .outbox_mut()
        .expect("the queue is on in a test session")
        .queue(
            "alice",
            aloo::client::outbox::OutboxItem::Reliable(aloo::p2p_proto::P2pPayload::Envelope {
                channel: None,
                msg_id: Some(1),
                envelope: aloo::proto::Envelope {
                    content: aloo::proto::Content::Text,
                    blocks: vec![b"never acknowledged".to_vec()],
                },
            }),
        )
        .expect("queueing should succeed");

    session.peer_link_mut().mark_active_for_test(ALICE);
    session.inject_p2p_event(aloo::client::p2p::P2pEvent::LinkStatusChanged {
        peer: ALICE,
        status: aloo::client::p2p::LinkStatus::Active,
    });
    drain(&mut ui, &mut session).await;

    assert_eq!(
        session.queued_for("alice"),
        1,
        "no acknowledgement came back, so it is still held and will be offered again"
    );
}

/// The reported flow through the *real* DM send path, not the transport
/// directly: an open DM with someone who has gone offline, a message
/// typed and sent. It has to reach the durable queue.
/// @requirement AC-410
#[tokio::test]
async fn a_dm_sent_through_the_real_path_while_offline_is_queued() {
    let (mut session, mut ui, peers) = session_and_ui("real-dm", "me").await;
    ui.on_direct_message(ALICE, "alice".into(), MessageBody::Text("hi".into()));
    ui.on_user_offline(ALICE);

    aloo::client::direct_message::handle_send_text(
        &mut aloo::control::NullSink,
        &mut ui,
        &mut session,
        ALICE,
        "while you were out".into(),
        peers.alice.der.clone(),
        None,
        1,
    )
    .await
    .expect("sending should not fail because they are away");
    drain(&mut ui, &mut session).await;

    assert_eq!(
        session.queued_for("alice"),
        1,
        "the real send path must reach the durable queue, not stop short of it"
    );
}

/// Sealing a message no longer depends on holding the peer's *rotating*
/// key - which is discarded the moment they disconnect
/// (`session::drop_peer_state`). Without the fallback to their bundle's
/// bootstrap key, every send to someone who had gone offline sealed to
/// nothing and was dropped before the queue ever saw it: the reported
/// break.
/// @requirement AC-410
#[tokio::test]
async fn a_message_seals_for_a_peer_whose_rotating_key_is_gone() {
    let (mut session, mut ui, peers) = session_and_ui("no-rotating-key", "me").await;
    // Exactly what a disconnect leaves behind: known, pinned, no
    // rotating key.
    aloo::client::session::forget_peer_for_test(&mut ui, &mut session, ALICE);
    ui.known_users.insert(
        ALICE,
        UserInfo {
            id: ALICE,
            name: "alice".into(),
            public_key_der: peers.alice.der.clone(),
            key_mode: KeyMode::PqHybrid,
        },
    );

    aloo::client::direct_message::handle_send_text(
        &mut aloo::control::NullSink,
        &mut ui,
        &mut session,
        ALICE,
        "sealed to your bootstrap key".into(),
        peers.alice.der.clone(),
        None,
        1,
    )
    .await
    .expect("sending must not fail for want of a key they took with them");
    drain(&mut ui, &mut session).await;

    assert_eq!(
        session.queued_for("alice"),
        1,
        "it must be sealed and held, not silently dropped"
    );
}

/// A punched peer's first payload can beat the server's word that they
/// exist. There is then no key to decrypt it with and no name to render it
/// under - but it *arrived*, so losing it is not an option available to us.
/// @requirement AC-420
#[tokio::test]
async fn a_message_from_a_sender_we_do_not_know_yet_is_held_not_dropped() {
    let (mut session, mut ui, peers) = session_and_ui("unknown-sender", "me").await;
    ui.known_users.remove(&ALICE);

    aloo::client::direct_message::on_message(
        &mut ui,
        &mut session,
        ALICE,
        String::new(),
        None,
        sealed_to(&peers, None, 1, "sent before you had heard of me"),
    )
    .await;

    assert_eq!(
        session.deferred_dm_count(),
        1,
        "it must be held rather than discarded for arriving early"
    );
    assert!(
        ui.private_rooms.get(&ALICE).is_none(),
        "and nothing can be rendered for a sender with no name yet"
    );
}

/// The other half of the guarantee: held is only worth anything if it is
/// then shown. Once the sender is known the message is offered again and
/// lands in the room, which opening the DM displays.
/// @requirement AC-420
#[tokio::test]
async fn a_held_message_is_shown_once_its_sender_becomes_known() {
    let (mut session, mut ui, peers) = session_and_ui("late-sender", "me").await;
    let alice = ui.known_users.remove(&ALICE).expect("seeded");

    aloo::client::direct_message::on_message(
        &mut ui,
        &mut session,
        ALICE,
        String::new(),
        None,
        sealed_to(&peers, None, 1, "while you were still learning my name"),
    )
    .await;
    assert_eq!(session.deferred_dm_count(), 1);

    // What the server's roster does when it finally arrives.
    ui.known_users.insert(ALICE, alice);
    aloo::client::session::retry_deferred_dms(&mut ui, &mut session).await;

    assert_eq!(session.deferred_dm_count(), 0, "nothing is left waiting");
    let room = ui.private_rooms.get(&ALICE).expect("the room now exists");
    assert!(
        room.log.iter().any(|entry| matches!(
            &entry.body,
            MessageBody::Text(text) if text == "while you were still learning my name"
        )),
        "and the message that arrived is in it, ready for the DM to be opened"
    );
}

/// A sender who never turns up must not cost the message either: it stays
/// held, still offered on every turn, rather than being given up on.
/// @requirement AC-420
#[tokio::test]
async fn a_held_message_whose_sender_never_arrives_stays_held() {
    let (mut session, mut ui, peers) = session_and_ui("never-known", "me").await;
    ui.known_users.remove(&ALICE);

    aloo::client::direct_message::on_message(
        &mut ui,
        &mut session,
        ALICE,
        String::new(),
        None,
        sealed_to(&peers, None, 1, "nobody knows who I am"),
    )
    .await;

    for _ in 0..5 {
        aloo::client::session::retry_deferred_dms(&mut ui, &mut session).await;
    }
    assert_eq!(
        session.deferred_dm_count(),
        1,
        "still held, not consumed by the attempts to deliver it"
    );
}

/// Turning the queue off must not abandon pad positions that are already
/// spent: they would never be delivered, while the next send went out
/// under a later sequence number and left the peer's pad behind for good.
/// @requirement AC-421
#[tokio::test]
async fn turning_the_queue_off_leaves_sealed_pad_messages_to_drain() {
    let (mut session, _ui, _peers) = session_and_ui("pad-drain", "me").await;
    assert!(
        session.queue_sealed_otp_for_test("alice-bob", 0),
        "the pad queue is on by default in a test session"
    );

    session.set_queue_send_messages(false);
    assert_eq!(
        session.otp_queued_total(),
        1,
        "a spent pad position is kept and allowed to drain, not dropped"
    );
}

/// Once there is nothing spent left waiting, the switch is free to take
/// effect fully.
/// @requirement AC-421
#[tokio::test]
async fn turning_the_queue_off_takes_full_effect_once_nothing_is_waiting() {
    let (mut session, _ui, _peers) = session_and_ui("pad-empty", "me").await;
    assert_eq!(session.otp_queued_total(), 0);

    session.set_queue_send_messages(false);
    assert_eq!(session.otp_queued_total(), 0);
    assert!(
        !session.queue_sealed_otp_for_test("alice-bob", 0),
        "with nothing left to desynchronize the queue is gone, and nothing new is sealed into it"
    );
}

/// The gate only ever opens on an acknowledgement, and it is durable - so
/// a message that left and was never answered (killed between the send and
/// the ack, or a frame the transport gave up on while the peer was away)
/// would wedge this contact's queue for good. A link coming up puts it
/// back on the wire.
/// @requirement AC-421
#[tokio::test]
async fn an_outstanding_pad_send_goes_back_on_the_wire_when_the_link_returns() {
    let (mut session, mut ui, _peers) = session_and_ui("pad-retry", "me").await;
    assert!(session.queue_sealed_otp_for_test("alice-bob", 0));

    assert!(
        !session
            .retry_outstanding_otp_send_for_test(&mut ui, ALICE, "alice-bob")
            .await,
        "nothing is outstanding yet, so there is nothing to put back"
    );

    session.arm_otp_ack_gate_for_test("alice-bob", 0);
    assert!(
        session
            .retry_outstanding_otp_send_for_test(&mut ui, ALICE, "alice-bob")
            .await,
        "the message the gate is waiting on is re-sent rather than left stuck"
    );
    assert_eq!(
        session.otp_queued_total(),
        1,
        "and it stays at the front until its own acknowledgement retires it"
    );
}

/// Only the message the gate actually names is re-sent: anything else
/// would put a pad position on the wire out of turn.
/// @requirement AC-421
#[tokio::test]
async fn a_gate_naming_something_other_than_the_front_re_sends_nothing() {
    let (mut session, mut ui, _peers) = session_and_ui("pad-retry-other", "me").await;
    assert!(session.queue_sealed_otp_for_test("alice-bob", 0));
    session.arm_otp_ack_gate_for_test("alice-bob", 7);

    assert!(
        !session
            .retry_outstanding_otp_send_for_test(&mut ui, ALICE, "alice-bob")
            .await,
        "the gate belongs to a send this queue is not responsible for"
    );
}
