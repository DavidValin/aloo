//! Loopback integration test for the direct peer-to-peer transport
//! (`src/client/p2p.rs`): a real server (TCP + UDP rendezvous) plus two real
//! `PeerLinkManager`s exercising the full `RequestPeerLink` ->
//! `PeerCandidates` -> `Ping`/`Pong` -> `Active` handshake, then a reliable
//! text send end to end. Loopback trivially succeeds at punching (there's
//! no real NAT involved) - this validates the protocol mechanics, not
//! real-world cross-NAT traversal success rate; see `docs/TESTING.md`'s
//! known-coverage-gaps section for that.

use std::net::SocketAddr;
use std::time::Duration;

use aloo::client::p2p::{
    LINK_IDLE_TIMEOUT, LinkStatus, P2pEvent, PENDING_MAX_AGE, PeerLinkManager,
    RETRY_BASE, RETRY_MAX, REFLEXIVE_REFRESH_INTERVAL, SIGNAL_TIMEOUT,
};
use aloo::p2p_proto::{P2pPayload, PunchDatagram, RendezvousMessage};
use aloo::proto::*;
use aloo::server::{AuthConfig, serve_with_rendezvous};
use aloo::control::ControlEndpoint;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn spawn_test_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let _ = serve_with_rendezvous(listener, udp, AuthConfig::None).await;
    });
    addr
}

/// Link-state bookkeeping (`LinkStatusChanged` as a link is established or
/// re-established, `Signal` as a retry asks for candidates to be relayed)
/// flows on the same event channel as content, and fires on every state
/// move. Tests waiting for a specific content event skip it.
fn is_link_bookkeeping(event: &P2pEvent) -> bool {
    matches!(
        event,
        P2pEvent::LinkStatusChanged { .. } | P2pEvent::Signal { .. }
    )
}

/// Drains `rx` and returns the first `P2pEvent::Signal` for `peer`, or
/// `None` if none arrives before the channel goes quiet. Used to prove an
/// automatic re-punch actually asked the server to relay candidates again.
fn next_signal_for(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<P2pEvent>,
    peer: UserId,
) -> Option<u64> {
    while let Ok(event) = rx.try_recv() {
        if let P2pEvent::Signal {
            peer: p, link_nonce, ..
        } = event
            && p == peer
        {
            return Some(link_nonce);
        }
    }
    None
}

/// Whether any `LinkFailed` for `peer` has been emitted so far.
fn had_link_failure(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<P2pEvent>,
    peer: UserId,
) -> bool {
    let mut found = false;
    while let Ok(event) = rx.try_recv() {
        if let P2pEvent::LinkFailed { peer: p, .. } = event
            && p == peer
        {
            found = true;
        }
    }
    found
}

async fn handshake(stream: &mut ControlEndpoint<TcpStream>, name: &str) -> UserId {
    let (auth, _) = stream
        .client_handshake(None)
        .await
        .unwrap()
        .expect("server closed during handshake");
    assert_eq!(auth, AuthKind::None);
    stream.send(&ClientMessage::Auth(AuthResponse::None))
        .await
        .unwrap();
    let _: ServerMessage = stream.recv().await.unwrap().unwrap(); // AuthResult
    stream.send(&ClientMessage::Identify {
            display_name: name.into(),
            public_key_der: vec![],
            key_mode: KeyMode::Password,
        },
    )
    .await
    .unwrap();
    let identify_result: ServerMessage = stream.recv().await.unwrap().unwrap();
    let ServerMessage::IdentifyResult {
        ok: true,
        you: Some(you),
        ..
    } = identify_result
    else {
        panic!("expected a successful IdentifyResult, got {identify_result:?}");
    };
    let _: ServerMessage = stream.recv().await.unwrap().unwrap(); // ChannelList
    you
}

/// @requirement AC-100, TB-146
#[tokio::test]
async fn direct_link_handshake_and_reliable_message_end_to_end() {
    let server_addr = spawn_test_server().await;

    let mut a = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let alice_id = handshake(&mut a, "alice").await;
    let mut b = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let bob_id = handshake(&mut b, "bob").await;

    let (a_events_tx, mut a_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (b_events_tx, mut b_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, a_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, a_events_tx)
            .await
            .unwrap();
    let (mut bob, b_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, b_events_tx)
            .await
            .unwrap();

    let (a_raw_tx, mut a_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_raw_tx, mut b_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(a_socket, server_addr, a_raw_tx);
    aloo::client::p2p::spawn_receive_loop(b_socket, server_addr, b_raw_tx);

    // alice proposes a link to bob - relayed by the server as PeerCandidates.
    alice.ensure_link(&mut a, bob_id).await;
    let ServerMessage::PeerCandidates {
        from,
        candidates,
        link_nonce,
    } = b.recv().await.unwrap().unwrap()
    else {
        panic!("bob should receive alice's PeerCandidates");
    };
    assert_eq!(from, alice_id);

    // bob replies in kind (relayed back to alice) and starts punching.
    bob.on_peer_candidates(&mut b, alice_id, candidates, link_nonce)
        .await;
    let ServerMessage::PeerCandidates {
        from,
        candidates,
        link_nonce,
    } = a.recv().await.unwrap().unwrap()
    else {
        panic!("alice should receive bob's PeerCandidates reply");
    };
    assert_eq!(from, bob_id);
    alice
        .on_peer_candidates(&mut a, bob_id, candidates, link_nonce)
        .await;

    // Both sides now exchange Ping/Pong over loopback UDP until each has a
    // confirmed, bidirectional Active link to the other.
    let both_active =
        |a: &PeerLinkManager, b: &PeerLinkManager| a.is_active(bob_id) && b.is_active(alice_id);
    let timeout = Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + timeout;
    while !both_active(&alice, &bob) {
        if tokio::time::Instant::now() >= deadline {
            panic!("loopback punch did not complete in time");
        }
        tokio::select! {
            Some((addr, dgram)) = a_raw_rx.recv() => alice.on_inbound(addr, dgram),
            Some((addr, dgram)) = b_raw_rx.recv() => bob.on_inbound(addr, dgram),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    // alice sends a channel-addressed text envelope reliably to bob.
    let envelope = Envelope {
        content: Content::Text,
        blocks: vec![b"hi bob, direct".to_vec()],
    };
    alice.send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            channel: Some("general".into()),
            envelope: envelope.clone(),
        },
    );

    // Drain both sides (bob needs the Reliable frame; alice needs its Ack)
    // until bob's event channel actually reports the message.
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = a_raw_rx.recv() => alice.on_inbound(addr, dgram),
                Some((addr, dgram)) = b_raw_rx.recv() => bob.on_inbound(addr, dgram),
                Some(event) = b_events_rx.recv() => {
                    if is_link_bookkeeping(&event) {
                        continue;
                    }
                    return event;
                }
            }
        }
    })
    .await
    .expect("bob should receive alice's message within the timeout");

    match received {
        P2pEvent::Message {
            channel,
            from,
            envelope: got,
        } => {
            assert_eq!(channel.as_deref(), Some("general"));
            assert_eq!(from, alice_id);
            assert_eq!(got, envelope);
        }
        _ => panic!("expected P2pEvent::Message, got a different event"),
    }

    // Nothing should ever have reached the server-relay path for this
    // content - only the two PeerCandidates exchanges above went over TCP.
    let _ = a_events_rx.try_recv(); // no assertion needed; just avoid an unused warning
}

/// There is deliberately no relay fallback (`docs/PROTOCOL.md` §7.1): if a
/// peer never answers the candidate exchange at all, whatever was queued
/// against them is not silently dropped and not silently retried forever
/// either - it keeps being retried, and once it has been undeliverable for
/// `PENDING_MAX_AGE` the user is told, naming why. Uses `tick_at` with
/// injected future `Instant`s instead of real sleeps so this stays fast.
///
/// @requirement AC-101, TB-146
#[tokio::test]
async fn undeliverable_queued_content_is_reported_once_it_ages_out() {
    let server_addr = spawn_test_server().await;

    let mut a = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let _alice_id = handshake(&mut a, "alice").await;
    // Registered so the RequestPeerLink itself is accepted by the server,
    // but this connection never does anything with it - nobody ever
    // answers alice's candidate proposal.
    let mut b = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let bob_id = handshake(&mut b, "bob").await;

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, _socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, events_tx)
            .await
            .unwrap();
    alice.ensure_link(&mut a, bob_id).await;
    assert!(!alice.is_active(bob_id));
    alice.send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            channel: None,
            envelope: Envelope {
                content: Content::Text,
                blocks: vec![vec![1]],
            },
        },
    );

    let t0 = tokio::time::Instant::now().into_std();

    // Past the signalling timeout: the link is lost, but the message is
    // still held - a retry may yet deliver it, so nothing is reported.
    alice.tick_at(t0 + SIGNAL_TIMEOUT + Duration::from_secs(1));
    assert_eq!(alice.status(bob_id), Some(LinkStatus::Lost));
    assert!(
        !had_link_failure(&mut events_rx, bob_id),
        "a first failed attempt must not report anything yet - it is still being retried"
    );

    // Past the age bound with still no path: now it is genuinely lost, and
    // the user has to be told rather than left believing it was delivered.
    alice.tick_at(t0 + PENDING_MAX_AGE + Duration::from_secs(1));
    assert!(
        had_link_failure(&mut events_rx, bob_id),
        "content undeliverable for PENDING_MAX_AGE must surface as a LinkFailed"
    );
}

/// `session.rs`'s `UserJoined` handler pre-warms a link to every
/// newly-learned peer well before anyone tries to talk to them
/// (`docs/PROTOCOL.md` §7.1's "trigger" - eager on learning about a peer,
/// not lazy-on-first-send, precisely to give real sends like voice a head
/// start on reaching `Active`). Most channel-mates are never actually
/// addressed, so a pre-warm-only link that fails to punch must stay
/// silent - no `P2pEvent::LinkFailed` - rather than showing a "direct
/// connection failed" banner for people nobody ever tried to reach. Its
/// status still moves, since that is what colours the sidebar.
///
/// @requirement TB-149
#[tokio::test]
async fn punch_timeout_with_nothing_pending_fails_silently() {
    let server_addr = spawn_test_server().await;

    let mut a = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let _alice_id = handshake(&mut a, "alice").await;
    let mut b = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let bob_id = handshake(&mut b, "bob").await;

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, _socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, events_tx)
            .await
            .unwrap();
    // A bare pre-warm - nothing ever queued against this link.
    alice.ensure_link(&mut a, bob_id).await;

    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + PENDING_MAX_AGE + Duration::from_secs(1));

    assert!(
        !had_link_failure(&mut events_rx, bob_id),
        "a pre-warm-only failure must not emit a user-visible LinkFailed event"
    );
    assert!(
        !alice.is_active(bob_id),
        "the link must still actually be marked lost internally"
    );
}

// ---------------------------------------------------------------------
// Tier 1: punching across NAT
// ---------------------------------------------------------------------

/// Binds one `PeerLinkManager` for alice plus both clients' control
/// connections - the starting point for the tests below, which drive the
/// peer side by hand (injecting the datagrams a NAT would have mangled)
/// rather than punching a second real manager over loopback.
async fn one_manager(
    server_addr: SocketAddr,
) -> (
    PeerLinkManager,
    tokio::sync::mpsc::UnboundedReceiver<P2pEvent>,
    ControlEndpoint<TcpStream>,
    ControlEndpoint<TcpStream>,
    UserId,
) {
    let mut a = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let _alice_id = handshake(&mut a, "alice").await;
    let mut b = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let bob_id = handshake(&mut b, "bob").await;

    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (alice, _socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, events_tx)
            .await
            .unwrap();
    (alice, events_rx, a, b, bob_id)
}

/// Reads the `PeerCandidates` the server just relayed to `b`, returning the
/// `link_nonce` the sender chose - the only way to observe a nonce, since
/// it is deliberately not exposed on `PeerLinkManager`.
async fn relayed_nonce(b: &mut ControlEndpoint<TcpStream>) -> u64 {
    let ServerMessage::PeerCandidates { link_nonce, .. } = b.recv().await.unwrap().unwrap() else {
        panic!("expected a relayed PeerCandidates");
    };
    link_nonce
}

/// The heart of cross-NAT traversal: a NAT that maps a different external
/// port per destination (symmetric/carrier-grade NAT) makes the peer's
/// probe arrive from an address *neither side could have advertised*.
/// Attributing it by the shared `link_nonce` and adopting that source as a
/// peer-reflexive candidate is what makes such a pair punchable at all -
/// without it the probe is dropped and the link can never open.
///
/// @requirement TB-176
#[tokio::test]
async fn a_ping_from_an_unadvertised_source_is_answered_and_adopted_as_a_candidate() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    // alice proposes a link; the nonce she chose is what both sides will
    // use to recognise each other's probes.
    alice.ensure_link(&mut a, bob_id).await;
    let link_nonce = relayed_nonce(&mut b).await;
    assert_eq!(
        alice.candidate_count(bob_id),
        0,
        "precondition: nothing known to probe yet"
    );

    // bob's probe shows up from an address nobody advertised - his NAT
    // picked a different external port for this destination than the one
    // the rendezvous server observed.
    let remapped: SocketAddr = "203.0.113.50:40404".parse().unwrap();
    alice.on_datagram(remapped, PunchDatagram::Ping { link_nonce });

    assert_eq!(
        alice.candidate_count(bob_id),
        1,
        "the remapped source must be adopted as a peer-reflexive candidate"
    );

    // Adoption is what makes the link usable in the other direction too:
    // a Pong now arriving from it is attributed and activates the link.
    alice.on_datagram(remapped, PunchDatagram::Pong { link_nonce });
    assert!(alice.is_active(bob_id));
    assert_eq!(alice.active_addr(bob_id), Some(remapped));
}

/// The mirror of the above on the answering side: a `Pong` confirming our
/// probe may itself come back from a remapped source. It is attributed by
/// nonce, activates the link, and that observed address - not any
/// advertised one - becomes the link's address.
///
/// @requirement TB-176
#[tokio::test]
async fn a_pong_from_an_unadvertised_source_activates_the_link() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, _b, bob_id) = one_manager(server_addr).await;

    let link_nonce = 0x0f0f_0f0f;
    alice
        .on_peer_candidates(&mut a, bob_id, vec!["198.51.100.7:9999".parse().unwrap()], link_nonce)
        .await;
    assert!(!alice.is_active(bob_id), "precondition: still punching");

    let remapped: SocketAddr = "203.0.113.50:40404".parse().unwrap();
    alice.on_datagram(remapped, PunchDatagram::Pong { link_nonce });

    assert!(
        alice.is_active(bob_id),
        "a matching Pong from a non-candidate source must activate the link"
    );
    assert_eq!(
        alice.active_addr(bob_id),
        Some(remapped),
        "the link must use the address the answer actually came from"
    );
}

/// Accepting probes from unknown addresses must not turn the client into
/// something that answers anyone who scans it. The gate is the nonce: a
/// probe that matches no link being established gets no reply at all, even
/// while other links are mid-punch.
///
/// @requirement TB-176
#[tokio::test]
async fn a_ping_matching_no_link_is_ignored() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice
        .on_peer_candidates(&mut a, bob_id, vec![], 0x1111_1111)
        .await;

    let stranger: SocketAddr = "203.0.113.99:1234".parse().unwrap();
    alice.on_datagram(stranger, PunchDatagram::Ping {
        link_nonce: 0x9999_9999,
    });

    assert_eq!(
        alice.candidate_count(bob_id),
        0,
        "a probe whose nonce matches nothing must not be adopted onto any link"
    );
}

/// Both sides pre-warm a link the moment they learn about each other
/// (§7.1), so both initiating at once is the normal case - and then each
/// starts out holding a different nonce. They must converge on one shared
/// value, or nonce-based attribution (TB-176) silently stops working in
/// exactly the common case.
///
/// @requirement TB-177
#[tokio::test]
async fn simultaneous_open_converges_on_one_shared_nonce() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    // alice initiates with her own random nonce...
    alice.ensure_link(&mut a, bob_id).await;
    let alice_nonce = relayed_nonce(&mut b).await;

    // ...and bob's own simultaneous proposal, carrying a different nonce,
    // crosses hers on the wire.
    let bob_nonce = alice_nonce.wrapping_add(1);
    alice
        .on_peer_candidates(&mut a, bob_id, vec![], bob_nonce)
        .await;

    // The one both sides compute is the smaller of the two. A Pong
    // carrying the *other* one belongs to no link and must be ignored.
    let (agreed, discarded) = (alice_nonce.min(bob_nonce), alice_nonce.max(bob_nonce));
    let addr: SocketAddr = "203.0.113.5:5555".parse().unwrap();
    alice.on_datagram(addr, PunchDatagram::Pong {
        link_nonce: discarded,
    });
    assert!(
        !alice.is_active(bob_id),
        "the nonce that lost the tie-break must not activate anything"
    );

    alice.on_datagram(addr, PunchDatagram::Pong {
        link_nonce: agreed,
    });
    assert!(
        alice.is_active(bob_id),
        "both sides must end up using the numerically smaller nonce"
    );
}

// ---------------------------------------------------------------------
// Tier 2: continuous establishment
// ---------------------------------------------------------------------

/// A link that could not be established is not abandoned: with the peer
/// still online, it is re-signalled automatically on a backoff, with no
/// user action and nothing queued against it. This is what makes "both
/// online" eventually mean "connected" rather than "connected only if the
/// first attempt happened to work".
///
/// @requirement TB-178
#[tokio::test]
async fn a_lost_link_is_re_signalled_automatically_on_a_backoff() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let t0 = tokio::time::Instant::now().into_std();

    // Nobody answers: the attempt is abandoned and a retry scheduled.
    alice.tick_at(t0 + SIGNAL_TIMEOUT + Duration::from_millis(100));
    assert_eq!(alice.status(bob_id), Some(LinkStatus::Lost));
    assert!(
        next_signal_for(&mut events, bob_id).is_none(),
        "the retry must wait out its backoff rather than firing instantly"
    );

    // Once the first backoff elapses, a fresh candidate exchange is asked
    // for - the server's help, without anyone typing anything.
    alice.tick_at(t0 + SIGNAL_TIMEOUT + RETRY_BASE + Duration::from_millis(200));
    assert!(
        next_signal_for(&mut events, bob_id).is_some(),
        "an elapsed backoff must re-signal the peer through the server"
    );
    assert_eq!(
        alice.status(bob_id),
        Some(LinkStatus::Connecting),
        "a retry puts the link back into establishment"
    );
}

/// The backoff grows with consecutive failures instead of hammering a peer
/// that is simply unreachable, but is capped so recovery is never more
/// than `RETRY_MAX` away once a path becomes possible again.
///
/// @requirement TB-178
#[tokio::test]
async fn the_retry_backoff_grows_and_stays_capped() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let mut now = tokio::time::Instant::now().into_std();
    let mut gaps = Vec::new();

    for _ in 0..8 {
        // Fail the current attempt.
        now += SIGNAL_TIMEOUT + Duration::from_millis(100);
        alice.tick_at(now);
        // Then step forward until the retry actually fires, in RETRY_BASE
        // increments, counting how long it took.
        let mut waited = Duration::ZERO;
        loop {
            now += RETRY_BASE;
            waited += RETRY_BASE;
            alice.tick_at(now);
            if next_signal_for(&mut events, bob_id).is_some() {
                break;
            }
            assert!(waited <= RETRY_MAX + RETRY_BASE, "a retry must always come");
        }
        gaps.push(waited);
    }

    assert!(
        gaps[1] > gaps[0],
        "consecutive failures must back off, got {gaps:?}"
    );
    assert!(
        gaps.iter().all(|g| *g <= RETRY_MAX + RETRY_BASE),
        "the backoff must stay capped at RETRY_MAX, got {gaps:?}"
    );
}

/// A punched link can die without either side sending anything - a NAT
/// rebinding, a route changing, the peer's network dropping. Keepalives
/// are what make that observable, so an `Active` link that receives
/// nothing at all for `LINK_IDLE_TIMEOUT` is treated as lost and put back
/// into establishment rather than silently swallowing everything sent on
/// it.
///
/// @requirement TB-179
#[tokio::test]
async fn an_active_link_that_goes_quiet_is_lost_and_re_established() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    let link_nonce = 0x2222_2222;
    alice
        .on_peer_candidates(&mut a, bob_id, vec![], link_nonce)
        .await;
    let addr: SocketAddr = "203.0.113.8:6666".parse().unwrap();
    let t0 = tokio::time::Instant::now().into_std();
    alice.on_datagram_at(addr, PunchDatagram::Pong { link_nonce }, t0);
    assert!(alice.is_active(bob_id));

    // Still within the window: nothing has been heard, but not for long
    // enough to call it dead.
    alice.tick_at(t0 + LINK_IDLE_TIMEOUT - Duration::from_secs(1));
    assert!(
        alice.is_active(bob_id),
        "a quiet-but-not-yet-stale link must be left alone"
    );

    // Past it: lost, and heading back into establishment on the backoff.
    alice.tick_at(t0 + LINK_IDLE_TIMEOUT + Duration::from_secs(1));
    assert_eq!(alice.status(bob_id), Some(LinkStatus::Lost));
    alice.tick_at(t0 + LINK_IDLE_TIMEOUT + RETRY_BASE + Duration::from_secs(2));
    assert!(
        next_signal_for(&mut events, bob_id).is_some(),
        "a link that went quiet must be re-punched, not left dead"
    );
}

/// The counterpart: a peer that is still there keeps its link alive purely
/// by its `Keepalive` beat, with no content flowing in either direction.
///
/// @requirement TB-179
#[tokio::test]
async fn a_peers_keepalive_keeps_an_otherwise_idle_link_alive() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, _b, bob_id) = one_manager(server_addr).await;

    let link_nonce = 0x3333_3333;
    alice
        .on_peer_candidates(&mut a, bob_id, vec![], link_nonce)
        .await;
    let addr: SocketAddr = "203.0.113.9:7777".parse().unwrap();
    let t0 = tokio::time::Instant::now().into_std();
    alice.on_datagram_at(addr, PunchDatagram::Pong { link_nonce }, t0);

    // A beat arrives well into the idle window, resetting it.
    let beat_at = t0 + LINK_IDLE_TIMEOUT - Duration::from_secs(5);
    alice.on_datagram_at(addr, PunchDatagram::Keepalive { link_nonce }, beat_at);

    // A moment that would have been past the deadline without that beat.
    alice.tick_at(t0 + LINK_IDLE_TIMEOUT + Duration::from_secs(1));
    assert!(
        alice.is_active(bob_id),
        "a keepalive must count as liveness, not just content"
    );
}

// ---------------------------------------------------------------------
// Tier 3: not losing messages
// ---------------------------------------------------------------------

/// Content typed while a link is down must survive the link being punched
/// again and be delivered on recovery - the case that previously dropped
/// messages on the floor with no error at all.
///
/// @requirement TB-180
#[tokio::test]
async fn content_queued_while_the_link_is_down_is_flushed_when_it_recovers() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + SIGNAL_TIMEOUT + Duration::from_millis(100));
    assert_eq!(
        alice.status(bob_id),
        Some(LinkStatus::Lost),
        "precondition: the link is down"
    );

    // Typed while it is down.
    alice.send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            channel: None,
            envelope: Envelope {
                content: Content::Text,
                blocks: vec![b"sent while down".to_vec()],
            },
        },
    );
    assert_eq!(
        alice.pending_count(bob_id),
        1,
        "content for a down link must be held, not dropped"
    );
    assert!(
        !had_link_failure(&mut events, bob_id),
        "holding it is not a failure - nothing should be reported yet"
    );

    // The link comes back.
    let link_nonce = 0x4444_4444;
    alice
        .on_peer_candidates(&mut a, bob_id, vec![], link_nonce)
        .await;
    let addr: SocketAddr = "203.0.113.11:8888".parse().unwrap();
    alice.on_datagram(addr, PunchDatagram::Pong { link_nonce });

    assert!(alice.is_active(bob_id));
    assert_eq!(
        alice.pending_count(bob_id),
        0,
        "the queue must be flushed onto the recovered link"
    );
}

/// Our own public address can change under us (a NAT dropping the mapping
/// while we sit idle is the common one). Re-probing keeps the candidate we
/// advertise true, and a change re-signals every link that isn't up so the
/// peer learns where we actually are now.
///
/// @requirement TB-181
#[tokio::test]
async fn a_changed_reflexive_address_re_signals_links_that_are_not_up() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let _ = next_signal_for(&mut events, bob_id);

    // The periodic re-probe goes out...
    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + REFLEXIVE_REFRESH_INTERVAL + Duration::from_millis(100));
    let token = alice.reflexive_token();

    // ...and comes back naming an address different from the one we have.
    let observed: SocketAddr = "203.0.113.77:33333".parse().unwrap();
    alice.on_rendezvous(
        server_addr,
        RendezvousMessage::BindingResponse { token, observed },
    );

    assert!(
        next_signal_for(&mut events, bob_id).is_some(),
        "a moved public address must be re-advertised to peers we aren't connected to yet"
    );
    assert!(
        alice.local_candidate_list().contains(&observed),
        "the new address must actually be in what we advertise"
    );
}

/// Retries are one-sided: whichever side's backoff elapses first proposes
/// again, and the other may still be sitting on a lost link of its own. A
/// peer in that state has to answer a fresh invite rather than ignore it,
/// or the proposer waits out its whole signalling timeout for a reply that
/// was never going to come and the two never re-converge.
///
/// @requirement TB-178
#[tokio::test]
async fn a_lost_link_still_answers_a_fresh_invite_from_the_peer() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    // alice's own attempt fails and is now waiting out a backoff.
    alice.ensure_link(&mut a, bob_id).await;
    let _ = relayed_nonce(&mut b).await;
    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + SIGNAL_TIMEOUT + Duration::from_millis(100));
    assert_eq!(alice.status(bob_id), Some(LinkStatus::Lost));

    // bob's retry reaches her first.
    let bob_nonce = 0x7777_7777;
    alice
        .on_peer_candidates(&mut a, bob_id, vec!["198.51.100.4:4444".parse().unwrap()], bob_nonce)
        .await;

    // She must have replied with her own candidates, echoing his nonce...
    assert_eq!(
        relayed_nonce(&mut b).await,
        bob_nonce,
        "a lost link must answer a peer's fresh invite, echoing their nonce"
    );
    // ...and be punching again rather than waiting out her own backoff.
    assert_eq!(alice.status(bob_id), Some(LinkStatus::Connecting));
}
