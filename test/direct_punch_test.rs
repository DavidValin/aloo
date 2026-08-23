//! Serverless direct UDP punching (`docs/PROTOCOL.md` §7.1.5): the slot
//! grid two peers meet on, one real loopback punch driven entirely by that
//! grid with no candidate relay involved, and the rules that decide when a
//! target may punch again - the 30-second attempt window, the
//! already-connected skip, the post-loss reconnect budget, and the
//! one-link-per-peer guarantee that keeps this from racing the
//! server-coordinated path (§7.1).
//!
//! Loopback punching trivially succeeds - there is no NAT here - so what
//! this proves is the mechanics and the scheduling, not real-world
//! traversal; see `docs/TESTING.md`'s known coverage gaps.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use aloo::client::p2p::{
    DIRECT_MAX_RECONNECTS, DIRECT_PUNCH_WINDOW, InboundDatagram, LINK_IDLE_TIMEOUT, LinkReadiness,
    LinkStatus, P2pEvent, PeerLinkManager, direct_peer_id, is_direct_peer_id, utc_second_of_hour,
};
use aloo::p2p_proto::{P2pPayload, PunchDatagram};
use aloo::proto::{Content, Envelope, UserId};
use aloo::settings::{DirectPunchTarget, PunchFrequency};
use tokio::net::UdpSocket;

/// A stand-in for the server's UDP rendezvous socket that answers every
/// `BindingRequest` with a publicly-routable-looking observation, so
/// `PeerLinkManager::bind`'s reflexive probe is answered on its first
/// attempt instead of timing out three times over. Nothing here punches
/// through it - it exists purely so binding a manager is fast.
async fn spawn_fake_rendezvous() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let Ok(aloo::p2p_proto::RendezvousMessage::BindingRequest { token }) =
                aloo::proto::decode(&buf[..n])
            else {
                continue;
            };
            let reply = aloo::proto::encode(&aloo::p2p_proto::RendezvousMessage::BindingResponse {
                token,
                observed: "203.0.113.7:41234".parse().unwrap(),
            })
            .unwrap();
            let _ = socket.send_to(&reply, from).await;
        }
    });
    addr
}

fn target(nickname: &str, port: u16, frequency: &str) -> DirectPunchTarget {
    DirectPunchTarget {
        nickname: nickname.to_string(),
        host: "127.0.0.1".to_string(),
        port,
        frequency: PunchFrequency::parse(frequency).unwrap(),
    }
}

/// One manager bound on loopback, plus the raw-datagram channel a real
/// session would drive it from.
struct Client {
    link: PeerLinkManager,
    port: u16,
    raw_rx: tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, InboundDatagram)>,
    events_rx: tokio::sync::mpsc::UnboundedReceiver<P2pEvent>,
}

async fn spawn_client(rendezvous: SocketAddr) -> Client {
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (link, socket) = PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(rendezvous), events_tx)
        .await
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let (raw_tx, raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(socket, Some(rendezvous), raw_tx);
    Client {
        link,
        port,
        raw_rx,
        events_rx,
    }
}

// ---- The slot grid ------------------------------------------------------

/// @requirement AC-206, TB-221
#[test]
fn every_frequencys_slot_grid_restarts_at_the_top_of_the_hour() {
    for minutes in aloo::settings::PUNCH_FREQUENCIES {
        let freq = PunchFrequency::parse(&if minutes == 60 {
            "every_1h".to_string()
        } else {
            format!("every_{minutes}m")
        })
        .unwrap();
        // O'clock is always slot 0, and the last second of the hour is
        // always the last slot of that hour - never the first of the next.
        assert_eq!(freq.slot_of_hour(0), 0, "{freq} at :00");
        assert_eq!(
            freq.slot_of_hour(3599),
            3599 / (minutes as u64 * 60),
            "{freq} at the last second of the hour"
        );
        // A slot boundary is exactly where the frequency says it is.
        assert_eq!(freq.slot_of_hour(minutes as u64 * 60 - 1), 0, "{freq} just before its first boundary");
        if minutes < 60 {
            assert_eq!(freq.slot_of_hour(minutes as u64 * 60), 1, "{freq} at its first boundary");
        }
    }
}

/// @requirement TB-221
#[test]
fn an_interval_that_does_not_divide_the_hour_still_restarts_at_oclock() {
    let freq = PunchFrequency::parse("every_55m").unwrap();
    // :00 and :55 are its only two slots; :55 lasts until the hour turns
    // over rather than a third slot opening at 1h50m.
    assert_eq!(freq.slot_of_hour(0), 0);
    assert_eq!(freq.slot_of_hour(54 * 60), 0);
    assert_eq!(freq.slot_of_hour(55 * 60), 1);
    assert_eq!(freq.slot_of_hour(3599), 1);
}

/// @requirement TB-221
#[test]
fn the_slot_clock_is_the_utc_second_of_the_hour() {
    assert!(utc_second_of_hour() < 3600);
}

/// @requirement TB-223
#[test]
fn a_nickname_derived_peer_id_is_stable_and_never_collides_with_a_servers() {
    assert_eq!(direct_peer_id("bob"), direct_peer_id("bob"));
    assert_ne!(direct_peer_id("bob"), direct_peer_id("marco"));
    assert!(is_direct_peer_id(direct_peer_id("bob")));
    // The server hands ids out from a counter starting at 1.
    for id in 1..1000u64 {
        assert!(!is_direct_peer_id(UserId(id)));
    }
}

// ---- A whole punch, with no server in it --------------------------------

/// @requirement AC-206, AC-207
#[tokio::test]
async fn two_peers_punch_a_link_from_the_schedule_alone_and_carry_a_message() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    let mut bob = spawn_client(rendezvous).await;

    // Each side knows only what its own settings file says: the other's
    // nickname, host and port. Nothing is relayed, and neither manager is
    // ever handed the other's candidates.
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", bob.port, "every_1m")], 30);
    bob.link
        .configure_direct_punch("bob".into(), vec![target("alice", alice.port, "every_1m")], 30);

    let bob_as_alice_sees_him = direct_peer_id("bob");
    let alice_as_bob_sees_her = direct_peer_id("alice");

    // Nothing happens until a slot boundary arrives - which for both of
    // them is the same wall-clock instant, since both grids restart at the
    // same o'clock.
    alice.link.tick_with_clock_at(Instant::now(), 45);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(alice.link.is_active(bob_as_alice_sees_him)
        && bob.link.is_active(alice_as_bob_sees_her))
    {
        if tokio::time::Instant::now() >= deadline {
            panic!("the scheduled direct punch did not complete in time");
        }
        tokio::select! {
            Some((addr, dgram)) = alice.raw_rx.recv() => alice.link.on_inbound(addr, dgram),
            Some((addr, dgram)) = bob.raw_rx.recv() => bob.link.on_inbound(addr, dgram),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                // Second 60 is the next every_1m slot after the 30 both were
                // configured at, so this is the boundary firing.
                alice.link.tick_with_clock_at(Instant::now(), 60);
                bob.link.tick_with_clock_at(Instant::now(), 60);
            }
        }
    }
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Active));
    assert_eq!(bob.link.direct_status("alice"), Some(LinkStatus::Active));

    // The link is an ordinary one from here: content rides the same
    // reliable layer a server-coordinated link uses.
    alice.link.send_reliable_or_queue(
        bob_as_alice_sees_him,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope: Envelope {
                content: Content::Text,
                blocks: vec![b"no server involved".to_vec()],
            },
        },
    );
    let received = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = alice.raw_rx.recv() => alice.link.on_inbound(addr, dgram),
                Some((addr, dgram)) = bob.raw_rx.recv() => bob.link.on_inbound(addr, dgram),
                Some(event) = bob.events_rx.recv() => {
                    if let P2pEvent::Message { from, envelope, .. } = event {
                        return (from, envelope);
                    }
                }
            }
        }
    })
    .await
    .expect("bob should receive alice's message over the direct link");
    assert_eq!(received.0, alice_as_bob_sees_her);
    assert_eq!(received.1.blocks[0], b"no server involved".to_vec());
}

/// @requirement AC-208
#[tokio::test]
async fn a_slot_arriving_on_a_link_that_is_already_up_does_not_punch_again() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    let mut bob = spawn_client(rendezvous).await;
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", bob.port, "every_1m")], 30);
    bob.link
        .configure_direct_punch("bob".into(), vec![target("alice", alice.port, "every_1m")], 30);
    let bob_id = direct_peer_id("bob");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !alice.link.is_active(bob_id) {
        if tokio::time::Instant::now() >= deadline {
            panic!("the scheduled direct punch did not complete in time");
        }
        tokio::select! {
            Some((addr, dgram)) = alice.raw_rx.recv() => alice.link.on_inbound(addr, dgram),
            Some((addr, dgram)) = bob.raw_rx.recv() => bob.link.on_inbound(addr, dgram),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                alice.link.tick_with_clock_at(Instant::now(), 60);
                bob.link.tick_with_clock_at(Instant::now(), 60);
            }
        }
    }
    let addr_before = alice.link.active_addr(bob_id);

    // Several more slots come and go. The link is untouched - not
    // re-punched, not re-nonced, not interrupted.
    for slot in 2..6u64 {
        alice.link.tick_with_clock_at(Instant::now(), slot * 60);
    }
    assert!(alice.link.is_active(bob_id));
    assert_eq!(alice.link.active_addr(bob_id), addr_before);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Active));
}

// ---- The attempt window, and giving up ----------------------------------

/// @requirement AC-209
#[tokio::test]
async fn an_attempt_probes_for_the_punch_window_and_is_then_abandoned_until_the_next_slot() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    // A port nobody is listening on: this attempt can only ever time out.
    let dead_port = {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };
    alice
        .link
        .configure_direct_punch("bob".into(), vec![target("bob", dead_port, "every_1m")], 30);

    let start = Instant::now();
    alice.link.tick_with_clock_at(start, 60);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));

    // Still trying one second before the window closes.
    alice
        .link
        .tick_with_clock_at(start + DIRECT_PUNCH_WINDOW - Duration::from_secs(1), 60);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));

    // And abandoned the moment it does - back to waiting for a slot, with
    // no reconnect budget spent, since this attempt never had a link to
    // lose in the first place.
    alice.link.tick_with_clock_at(start + DIRECT_PUNCH_WINDOW, 60);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));
    assert_eq!(alice.link.direct_reconnects("bob"), Some(0));

    // The next slot starts a fresh attempt, and only the next slot does.
    alice
        .link
        .tick_with_clock_at(start + DIRECT_PUNCH_WINDOW + Duration::from_secs(1), 60);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));
    alice
        .link
        .tick_with_clock_at(start + DIRECT_PUNCH_WINDOW + Duration::from_secs(2), 120);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));
}

/// @requirement AC-210
#[tokio::test]
async fn a_direct_only_link_that_drops_is_reconnected_up_to_the_reconnect_budget() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    let mut bob = spawn_client(rendezvous).await;
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", bob.port, "every_1m")], 30);
    bob.link
        .configure_direct_punch("bob".into(), vec![target("alice", alice.port, "every_1m")], 30);
    let bob_id = direct_peer_id("bob");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !alice.link.is_active(bob_id) {
        if tokio::time::Instant::now() >= deadline {
            panic!("the scheduled direct punch did not complete in time");
        }
        tokio::select! {
            Some((addr, dgram)) = alice.raw_rx.recv() => alice.link.on_inbound(addr, dgram),
            Some((addr, dgram)) = bob.raw_rx.recv() => bob.link.on_inbound(addr, dgram),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                alice.link.tick_with_clock_at(Instant::now(), 60);
                bob.link.tick_with_clock_at(Instant::now(), 60);
            }
        }
    }
    assert_eq!(alice.link.direct_reconnects("bob"), Some(0));

    // bob vanishes: nothing more is fed to alice, so her link goes quiet
    // and the ordinary liveness check loses it. Nobody has a server to
    // re-signal through - bob is a settings-file peer, not a server one -
    // so this scheduler owns bringing it back.
    let mut now = Instant::now() + LINK_IDLE_TIMEOUT + Duration::from_secs(1);
    alice.link.tick_with_clock_at(now, 60);
    assert!(!alice.link.is_active(bob_id));
    // Noticed on the following turn, which starts reconnect 1 of 5.
    alice.link.tick_with_clock_at(now, 60);
    assert_eq!(alice.link.direct_reconnects("bob"), Some(1));
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));

    // Each reconnect gets its own full attempt window before the next one
    // starts, and the budget is spent exactly DIRECT_MAX_RECONNECTS times.
    for expected in 2..=DIRECT_MAX_RECONNECTS {
        now += DIRECT_PUNCH_WINDOW;
        alice.link.tick_with_clock_at(now, 60);
        assert_eq!(
            alice.link.direct_reconnects("bob"),
            Some(expected),
            "reconnect {expected}"
        );
        assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));
    }

    // Once it is spent the target goes back to its schedule rather than
    // hammering the peer forever.
    now += DIRECT_PUNCH_WINDOW;
    alice.link.tick_with_clock_at(now, 60);
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));
    assert_eq!(alice.link.direct_reconnects("bob"), Some(0));
}

// ---- One link between two people ---------------------------------------

/// @requirement AC-211
#[tokio::test]
async fn a_peer_being_punched_directly_is_never_also_signalled_through_the_server() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    let dead_port = {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.local_addr().unwrap().port()
    };
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", dead_port, "every_1m")], 30);
    let bob_id = direct_peer_id("bob");
    alice.link.tick_with_clock_at(Instant::now(), 60);

    // A send while the direct attempt is in flight waits on that attempt
    // rather than opening a second, server-relayed one.
    let mut sink = RecordingSink::default();
    assert_eq!(
        alice.link.ensure_link(&mut sink, bob_id).await,
        LinkReadiness::Pending
    );
    assert!(
        sink.sent.is_empty(),
        "a direct attempt must not be duplicated through the server: {:?}",
        sink.sent
    );

    // Nor does the retry backoff ever hand this link to the server: no
    // Signal is emitted for a peer the server has never named.
    let mut now = Instant::now();
    for _ in 0..40 {
        now += Duration::from_secs(5);
        alice.link.tick_with_clock_at(now, 60);
    }
    let mut signals = 0;
    while let Ok(event) = alice.events_rx.try_recv() {
        if matches!(event, P2pEvent::Signal { peer, .. } if peer == bob_id) {
            signals += 1;
        }
    }
    assert_eq!(signals, 0, "a direct-only peer must never be re-signalled");
}

/// @requirement AC-211
#[tokio::test]
async fn a_direct_target_moves_onto_the_user_id_the_server_gives_it() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", 65000, "every_1h")], 30);
    assert_eq!(alice.link.direct_peer("bob"), Some(direct_peer_id("bob")));

    // The same person, once a server names them, is one peer with one link
    // - not one per route.
    alice.link.set_direct_peer_id("bob", Some(UserId(7)));
    assert_eq!(alice.link.direct_peer("bob"), Some(UserId(7)));

    // And goes back to being a settings-file peer when they disconnect
    // from it, so the next slot still punches at them.
    alice.link.release_direct_peer_id(UserId(7));
    assert_eq!(alice.link.direct_peer("bob"), Some(direct_peer_id("bob")));
}

/// @requirement TB-222
#[tokio::test]
async fn a_direct_ping_naming_a_nickname_that_is_not_configured_is_ignored() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", 65000, "every_1m")], 30);

    let stranger: SocketAddr = "127.0.0.1:65001".parse().unwrap();
    alice.link.on_datagram(
        stranger,
        PunchDatagram::DirectPing {
            link_nonce: 1234,
            from: "mallory".into(),
        },
    );
    // Nothing was started, and nothing was answered - the socket gives a
    // scanner no more than it would without direct punching on.
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));
    assert_eq!(alice.link.status(direct_peer_id("mallory")), None);

    // An over-long nickname is dropped before it can be looked up at all.
    alice.link.on_datagram(
        stranger,
        PunchDatagram::DirectPing {
            link_nonce: 1234,
            from: "b".repeat(aloo::p2p_proto::MAX_DIRECT_PUNCH_NICK_LEN + 1),
        },
    );
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));
}

/// @requirement TB-222
#[tokio::test]
async fn a_peers_probe_is_answered_and_opens_this_sides_attempt_too() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    let bob_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bob_addr = bob_socket.local_addr().unwrap();
    alice.link.configure_direct_punch(
        "alice".into(),
        vec![target("bob", bob_addr.port(), "every_1h")],
        30,
    );
    // No slot is due for an hourly target, so alice is idle - it is bob's
    // probe alone that starts her side.
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Lost));

    alice.link.on_datagram(
        bob_addr,
        PunchDatagram::DirectPing {
            link_nonce: 99,
            from: "bob".into(),
        },
    );
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));

    let mut buf = [0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), bob_socket.recv_from(&mut buf))
        .await
        .expect("alice should answer a configured peer's probe")
        .unwrap();
    let answer: PunchDatagram = aloo::proto::decode(&buf[..n]).unwrap();
    match answer {
        PunchDatagram::DirectPong { link_nonce, from } => {
            assert_eq!(link_nonce, 99, "the pong echoes the ping's nonce");
            assert_eq!(from, "alice");
        }
        // alice also probes back at the address bob actually reached her
        // from; whichever of the two datagrams lands first is fine.
        PunchDatagram::DirectPing { from, .. } => assert_eq!(from, "alice"),
        other => panic!("unexpected answer to a direct ping: {other:?}"),
    }
}

/// A `ControlSink` that records what would have gone to the server, so a
/// test can assert that nothing did.
#[derive(Default)]
struct RecordingSink {
    sent: Vec<aloo::proto::ClientMessage>,
}

impl aloo::control::ControlSink for RecordingSink {
    async fn send_control(&mut self, msg: &aloo::proto::ClientMessage) -> aloo::proto::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
}

/// @requirement AC-209
#[tokio::test]
async fn probing_really_continues_for_the_whole_window_not_just_one_link_attempt() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    // A socket that receives but never answers, so the attempt runs its
    // full course while we watch what actually goes on the wire.
    let bob_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bob_addr = bob_socket.local_addr().unwrap();
    alice.link.configure_direct_punch(
        "alice".into(),
        vec![target("bob", bob_addr.port(), "every_1m")],
        30,
    );

    /// Drains whatever is already queued on the socket and reports whether
    /// any of it was a direct probe.
    async fn drain_probes(socket: &UdpSocket) -> bool {
        let mut buf = [0u8; 512];
        let mut saw = false;
        for _ in 0..256 {
            let Ok(Ok((n, _))) =
                tokio::time::timeout(Duration::from_millis(30), socket.recv_from(&mut buf)).await
            else {
                break;
            };
            if matches!(
                aloo::proto::decode::<PunchDatagram>(&buf[..n]),
                Ok(PunchDatagram::DirectPing { .. })
            ) {
                saw = true;
            }
        }
        saw
    }

    let start = Instant::now();
    alice.link.tick_with_clock_at(start, 60);
    assert!(drain_probes(&bob_socket).await, "the attempt should start probing");

    // Well past the *link's* own punch timeout, which is much shorter than
    // the direct window. The link underneath has given up and been marked
    // lost by now - but the direct attempt has not, so it must keep
    // probing, or a 30-second window is 30 seconds in name only.
    assert!(
        aloo::client::p2p::PUNCH_TIMEOUT < DIRECT_PUNCH_WINDOW,
        "this test only means anything while PUNCH_TIMEOUT is inside DIRECT_PUNCH_WINDOW"
    );
    let mut now = start + aloo::client::p2p::PUNCH_TIMEOUT + Duration::from_secs(1);
    alice.link.tick_with_clock_at(now, 60);
    let _ = drain_probes(&bob_socket).await;

    // Several more ticks, all still inside the window: every one of them
    // should be putting probes on the wire.
    for _ in 0..5 {
        now += Duration::from_millis(150);
        alice.link.tick_with_clock_at(now, 60);
    }
    assert!(
        drain_probes(&bob_socket).await,
        "probing stopped at the link's own punch timeout instead of running the whole window"
    );
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Connecting));
}

/// Daemon mode makes this ordering the common one: the daemon runs for
/// hours with a direct link already up, and the peer connects to the
/// server later (`--focus <nickname>` only ever resolves off `UserJoined`).
/// @requirement AC-211
#[tokio::test]
async fn a_peer_who_joins_the_server_after_a_direct_link_is_up_gets_only_one_link() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    let mut bob = spawn_client(rendezvous).await;
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", bob.port, "every_1m")], 30);
    bob.link
        .configure_direct_punch("bob".into(), vec![target("alice", alice.port, "every_1m")], 30);

    let synthetic = direct_peer_id("bob");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !alice.link.is_active(synthetic) {
        assert!(tokio::time::Instant::now() < deadline, "punch timed out");
        tokio::select! {
            Some((a, d)) = alice.raw_rx.recv() => alice.link.on_inbound(a, d),
            Some((a, d)) = bob.raw_rx.recv() => bob.link.on_inbound(a, d),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                alice.link.tick_with_clock_at(Instant::now(), 60);
                bob.link.tick_with_clock_at(Instant::now(), 60);
            }
        }
    }

    // Now bob turns up on the server, exactly as `UserJoined` reports him.
    let server_id = UserId(7);
    alice.link.set_direct_peer_id("bob", Some(server_id));
    let mut sink = RecordingSink::default();
    alice.link.ensure_link(&mut sink, server_id).await;

    assert!(
        sink.sent.is_empty(),
        "bob is already reachable directly, so nothing about him should be \
         signalled through the server - got {:?}",
        sink.sent
    );
    // The one live link moved onto the id the server named, rather than a
    // second one being opened beside it.
    assert!(
        alice.link.is_active(server_id),
        "the working direct link should now be filed under the server's id"
    );
    assert_eq!(
        alice.link.status(synthetic),
        None,
        "nothing should be left behind under the settings-file identity"
    );
    assert_eq!(alice.link.direct_peer("bob"), Some(server_id));
    assert_eq!(alice.link.direct_status("bob"), Some(LinkStatus::Active));

    // And it survives the peer leaving the server again: the direct path
    // is unaffected by that, so the link moves back rather than dying.
    alice.link.release_direct_peer_id(server_id);
    assert!(alice.link.is_active(synthetic));
    assert_eq!(alice.link.status(server_id), None);
}

// ---- Becoming a real, addressable peer (docs/PROTOCOL.md 7.1.5) --------

/// @requirement AC-214
#[test]
fn announced_membership_is_reconciled_against_our_own_joined_channels() {
    use aloo::client::session::reconcile_direct_membership;

    let ours = vec!["general".to_string(), "dev".to_string()];

    // Only channels we are in count: a peer listing one we never joined
    // tells us nothing we have anywhere to put.
    let r = reconcile_direct_membership(
        &["general".into(), "elsewhere".into()],
        &ours,
        &[],
    );
    assert_eq!(r.shared, vec!["general".to_string()]);
    assert_eq!(r.join, vec!["general".to_string()]);
    assert!(r.leave.is_empty());

    // A second announcement listing the same channel changes nothing -
    // they are already there.
    let r = reconcile_direct_membership(&["general".into()], &ours, &["general".into()]);
    assert!(r.join.is_empty());
    assert!(r.leave.is_empty());

    // The list is authoritative, not additive: dropping a channel from it
    // is how a peer says they left.
    let r = reconcile_direct_membership(&["dev".into()], &ours, &["general".into()]);
    assert_eq!(r.join, vec!["dev".to_string()]);
    assert_eq!(r.leave, vec!["general".to_string()]);

    // And a peer that has left everything shared is dropped from all of it
    // without being forgotten as a person.
    let r = reconcile_direct_membership(&[], &ours, &["general".into(), "dev".into()]);
    assert!(r.shared.is_empty());
    assert!(r.join.is_empty());
    assert_eq!(r.leave, vec!["general".to_string(), "dev".to_string()]);
}

/// @requirement AC-215, AC-259
#[test]
fn a_nickname_names_someone_only_once_something_is_pinned_for_it() {
    use aloo::client::idstore::IdStore;
    use aloo::client::session::direct_peer_identity;

    let path = std::env::temp_dir().join(format!(
        "aloo-direct-id-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut store = IdStore::new_empty(path);

    // Nobody pinned: there is nothing to encrypt to, so no identity.
    assert!(direct_peer_identity(&store, "bob").is_none());

    // Pinned, but not a keybundle - what a hand-installed pad contact
    // leaves. The pin names them, which is what lets a pad-only pair exist
    // at all; nothing is sealed to it, and the pad is what proves the
    // claim (`docs/PROTOCOL.md` §7.1.5 step 7, §16.2).
    store.check_and_pin("bob", b"not-a-pq-bundle");
    let info = direct_peer_identity(&store, "bob").expect("a pin names someone");
    assert!(
        aloo::crypto::pq::fingerprint_of_encoded(&info.public_key_der).is_none(),
        "no envelope can be built for them - only a pad can carry this pair"
    );
    assert_eq!(
        aloo::client::otp::framing_for(b"our-own-pad-only-pin", &info.public_key_der),
        aloo::client::otp::OtpFraming::Direct,
    );
}

/// @requirement TB-224
#[tokio::test]
async fn a_direct_targets_nickname_and_live_peers_are_queryable() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut alice = spawn_client(rendezvous).await;
    alice
        .link
        .configure_direct_punch("alice".into(), vec![target("bob", 65000, "every_1h")], 30);

    let bob = direct_peer_id("bob");
    assert_eq!(alice.link.direct_nickname_of(bob).as_deref(), Some("bob"));
    assert_eq!(alice.link.direct_nickname_of(UserId(7)), None);
    // Nothing is up yet, so there is nobody to announce membership to.
    assert!(alice.link.active_direct_peers().is_empty());
}

// ---- Running with no server at all (--no-server) ------------------------

/// @requirement AC-218, TB-245
#[test]
fn server_state_distinguishes_no_server_from_an_unreachable_one() {
    use aloo::client::session::ServerState;

    // Both mean "cannot happen now"...
    assert!(ServerState::Absent.is_absent());
    assert!(ServerState::Unreachable.is_absent());
    assert!(!ServerState::Connected.is_absent());
    // ...but only one of them is permanent, and only that one is worth
    // telling a user to stop waiting for.
    assert!(ServerState::Absent.is_serverless());
    assert!(!ServerState::Unreachable.is_serverless());

    let absent = ServerState::Absent.refusal("joining a channel");
    let away = ServerState::Unreachable.refusal("joining a channel");
    assert_ne!(
        absent, away,
        "the two states must not be explained with the same sentence"
    );
    assert!(absent.contains("joining a channel"));
    assert!(away.contains("joining a channel"));
    assert!(
        away.contains("unreachable"),
        "a server that is merely away should read as temporary: {away}"
    );
}

/// @requirement AC-219
#[test]
fn only_server_backed_actions_are_refused_without_one() {
    use aloo::client::tui::ui::UiAction;
    use aloo::proto::ChannelKind;

    // Server state, so it must be refused (and named).
    assert_eq!(
        UiAction::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        }
        .needs_server(),
        Some("joining a channel")
    );
    // Stored on the server for an offline recipient.
    assert_eq!(UiAction::OpenOtpMailbox.needs_server(), Some("OTP mail"));
    assert_eq!(UiAction::SendOtpMail.needs_server(), Some("OTP mail"));

    // Peer-to-peer, and so unaffected: these are the whole point of
    // running without a server.
    assert_eq!(UiAction::VoiceRecordStop.needs_server(), None);
    assert_eq!(UiAction::EndCall.needs_server(), None);
    assert_eq!(
        UiAction::SendChannelText {
            channel: "general".into(),
            plaintext: "hi".to_string(),
            recipients: Vec::new(),
            msg_id: 0,
        }
        .needs_server(),
        None
    );
    // Leaving is local: with no server a channel is a name we declared, so
    // dropping it needs nobody's permission.
    assert_eq!(
        UiAction::LeaveChannel {
            name: "general".into()
        }
        .needs_server(),
        None
    );
}

/// Punching is mutual by construction: a probe is answered only for a
/// nickname the *receiver* lists (TB-214), so listing someone who has not
/// listed you buys nothing in either direction. Worth pinning down because
/// it is the asymmetry people get wrong when writing a settings file - it
/// reads like "I can reach them", and it is not.
///
/// @requirement TB-214
#[tokio::test]
async fn listing_a_peer_who_has_not_listed_you_opens_no_link_either_way() {
    let rendezvous = spawn_fake_rendezvous().await;
    let mut bob = spawn_client(rendezvous).await;
    let mut peter = spawn_client(rendezvous).await;

    // bob lists peter. peter lists someone else entirely.
    bob.link
        .configure_direct_punch("bob".into(), vec![target("peter", peter.port, "every_1m")], 30);
    peter
        .link
        .configure_direct_punch("peter".into(), vec![target("omar", 65000, "every_1m")], 30);

    let peter_as_bob_sees_him = direct_peer_id("peter");
    let bob_as_peter_sees_him = direct_peer_id("bob");

    // Drive both for well past a punch window's worth of slots.
    let start = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut now = start;
    while tokio::time::Instant::now() < deadline {
        tokio::select! {
            Some((a, d)) = bob.raw_rx.recv() => bob.link.on_inbound(a, d),
            Some((a, d)) = peter.raw_rx.recv() => peter.link.on_inbound(a, d),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {
                now += Duration::from_millis(200);
                bob.link.tick_with_clock_at(now, 60);
                peter.link.tick_with_clock_at(now, 60);
            }
        }
    }

    assert!(
        !bob.link.is_active(peter_as_bob_sees_him),
        "bob listed peter, but peter never listed bob - his probes must go unanswered"
    );
    assert!(
        !peter.link.is_active(bob_as_peter_sees_him),
        "peter must not acquire a link to someone he never configured"
    );
    // And peter learns nothing about bob at all: an unlisted nickname is
    // not a peer, so no link state is created for him.
    assert_eq!(peter.link.status(bob_as_peter_sees_him), None);
    assert_eq!(peter.link.direct_status("bob"), None);
}

// ---- Key rotation over the link (docs/PROTOCOL.md 13.10, 7.1.5) --------

/// A rotation carried by the link is verified and installed exactly as one
/// a server relayed would be, using real `pq_hybrid` key material.
///
/// This is what keeps forward secrecy working with no server in reach: the
/// signature is over the rotation, the recipient and the recipient's own
/// fingerprint, none of which the transport touches - so a server relaying
/// it never contributed anything a link cannot.
///
/// @requirement TB-225
#[test]
fn a_rotation_carried_on_the_link_verifies_and_installs_like_a_relayed_one() {
    use aloo::client::pq_rekey::{PqOwnKeys, PqPeerKeys};
    use aloo::crypto::pq::{bundle_fingerprint, generate_bundle_with_bits, sign_rotation, verify_rotation};

    // Small modulus for speed - nothing here asserts key size (same trade
    // as `identity_continuity_test`).
    const BITS: usize = 1024;
    let (alice_pub, alice_priv) = generate_bundle_with_bits(BITS).unwrap();
    let (bob_pub, bob_priv) = generate_bundle_with_bits(BITS).unwrap();
    let bob_fp = bundle_fingerprint(&bob_pub).unwrap();
    let bob = UserId(0);
    let alice = direct_peer_id("alice");

    // Alice rotates the keys she wants bob to encrypt to from now on.
    let mut alice_own = PqOwnKeys::new(alice_priv.bootstrap_decap().clone());
    let rotation = alice_own.rotate_for(bob);
    let (encoded, signature) = sign_rotation(&alice_priv, bob, &bob_fp, &rotation).unwrap();

    // It travels as an ordinary reliable payload rather than through a
    // server, and survives that trip byte for byte.
    let payload = P2pPayload::KeyRotation {
        rotation: encoded.clone(),
        signature: signature.clone(),
    };
    let decoded: P2pPayload = aloo::proto::decode(&aloo::proto::encode(&payload).unwrap()).unwrap();
    let P2pPayload::KeyRotation {
        rotation: got_rotation,
        signature: got_signature,
    } = decoded
    else {
        panic!("wrong variant");
    };

    // Bob verifies it against alice's pinned identity - the transport had
    // no part in that - and installs it.
    let opened = verify_rotation(&alice_pub, bob, &bob_fp, &got_rotation, &got_signature)
        .expect("a rotation that travelled on the link must verify");
    let mut bob_peers = PqPeerKeys::new();
    assert!(
        bob_peers.install(alice, opened),
        "the rotation should be accepted as newer than nothing"
    );
    assert!(
        bob_peers.encap_for(alice).is_some(),
        "bob must now have keys to encrypt to alice with"
    );

    // And the guarantees do not soften for having come over the link: a
    // rotation signed for somebody else is still refused.
    let someone_else = UserId(999);
    assert!(
        verify_rotation(&alice_pub, someone_else, &bob_fp, &got_rotation, &got_signature).is_none(),
        "a rotation is bound to its recipient, whatever carried it"
    );
    // As is one whose bytes were altered in flight.
    let mut tampered = got_rotation.clone();
    tampered[0] ^= 0xff;
    assert!(
        verify_rotation(&alice_pub, bob, &bob_fp, &tampered, &got_signature).is_none(),
        "a tampered rotation must not verify"
    );
    // And one that claims to come from someone it does not.
    assert!(
        verify_rotation(&bob_pub, bob, &bob_fp, &got_rotation, &got_signature).is_none(),
        "a rotation must verify only against its actual sender's identity"
    );
    let _ = bob_priv;
}
