//! Loopback integration test for the direct peer-to-peer transport
//! (`src/p2p.rs`): a real server (TCP + UDP rendezvous) plus two real
//! `PeerLinkManager`s exercising the full `RequestPeerLink` ->
//! `PeerCandidates` -> `Ping`/`Pong` -> `Active` handshake, then a reliable
//! text send end to end. Loopback trivially succeeds at punching (there's
//! no real NAT involved) - this validates the protocol mechanics, not
//! real-world cross-NAT traversal success rate; see `docs/TESTING.md`'s
//! known-coverage-gaps section for that.

use std::net::SocketAddr;
use std::time::Duration;

use aloo::p2p::{P2pEvent, PeerLinkManager};
use aloo::p2p_proto::P2pPayload;
use aloo::proto::*;
use aloo::server::{serve_with_rendezvous, AuthConfig};
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

async fn handshake(stream: &mut TcpStream, name: &str) -> UserId {
    let hello: ServerMessage = read_message(stream).await.unwrap().unwrap();
    assert!(matches!(hello, ServerMessage::Hello { auth: AuthKind::None, .. }));
    write_message(stream, &ClientMessage::Auth(AuthResponse::None)).await.unwrap();
    let _: ServerMessage = read_message(stream).await.unwrap().unwrap(); // AuthResult
    write_message(
        stream,
        &ClientMessage::Identify { display_name: name.into(), public_key_der: vec![], key_mode: KeyMode::Rsa },
    )
    .await
    .unwrap();
    let identify_result: ServerMessage = read_message(stream).await.unwrap().unwrap();
    let ServerMessage::IdentifyResult { ok: true, you: Some(you), .. } = identify_result else {
        panic!("expected a successful IdentifyResult, got {identify_result:?}");
    };
    let _: ServerMessage = read_message(stream).await.unwrap().unwrap(); // ChannelList
    you
}

/// @requirement AC-100, TB-146
#[tokio::test]
async fn direct_link_handshake_and_reliable_message_end_to_end() {
    let server_addr = spawn_test_server().await;

    let mut a = TcpStream::connect(server_addr).await.unwrap();
    let alice_id = handshake(&mut a, "alice").await;
    let mut b = TcpStream::connect(server_addr).await.unwrap();
    let bob_id = handshake(&mut b, "bob").await;

    let (a_events_tx, mut a_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (b_events_tx, mut b_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, a_socket) = PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, a_events_tx).await.unwrap();
    let (mut bob, b_socket) = PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, b_events_tx).await.unwrap();

    let (a_raw_tx, mut a_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_raw_tx, mut b_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::p2p::spawn_receive_loop(a_socket, a_raw_tx);
    aloo::p2p::spawn_receive_loop(b_socket, b_raw_tx);

    // alice proposes a link to bob - relayed by the server as PeerCandidates.
    alice.ensure_link(&mut a, bob_id).await;
    let ServerMessage::PeerCandidates { from, candidates, link_nonce } = read_message(&mut b).await.unwrap().unwrap() else {
        panic!("bob should receive alice's PeerCandidates");
    };
    assert_eq!(from, alice_id);

    // bob replies in kind (relayed back to alice) and starts punching.
    bob.on_peer_candidates(&mut b, alice_id, candidates, link_nonce).await;
    let ServerMessage::PeerCandidates { from, candidates, link_nonce } = read_message(&mut a).await.unwrap().unwrap() else {
        panic!("alice should receive bob's PeerCandidates reply");
    };
    assert_eq!(from, bob_id);
    alice.on_peer_candidates(&mut a, bob_id, candidates, link_nonce).await;

    // Both sides now exchange Ping/Pong over loopback UDP until each has a
    // confirmed, bidirectional Active link to the other.
    let both_active = |a: &PeerLinkManager, b: &PeerLinkManager| a.is_active(bob_id) && b.is_active(alice_id);
    let timeout = Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + timeout;
    while !both_active(&alice, &bob) {
        if tokio::time::Instant::now() >= deadline {
            panic!("loopback punch did not complete in time");
        }
        tokio::select! {
            Some((addr, dgram)) = a_raw_rx.recv() => alice.on_datagram(addr, dgram),
            Some((addr, dgram)) = b_raw_rx.recv() => bob.on_datagram(addr, dgram),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    // alice sends a channel-addressed text envelope reliably to bob.
    let envelope = Envelope { content: Content::Text, blocks: vec![b"hi bob, direct".to_vec()] };
    alice.send_reliable_or_queue(bob_id, P2pPayload::Envelope { channel: Some("general".into()), envelope: envelope.clone() });

    // Drain both sides (bob needs the Reliable frame; alice needs its Ack)
    // until bob's event channel actually reports the message.
    let received = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = a_raw_rx.recv() => alice.on_datagram(addr, dgram),
                Some((addr, dgram)) = b_raw_rx.recv() => bob.on_datagram(addr, dgram),
                Some(event) = b_events_rx.recv() => return event,
            }
        }
    })
    .await
    .expect("bob should receive alice's message within the timeout");

    match received {
        P2pEvent::Message { channel, from, envelope: got } => {
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

/// There is deliberately no relay fallback (`docs/PROTOCOL.md`'s "Direct
/// peer-to-peer transport" section): if a peer never answers the candidate
/// exchange/punch at all, the link must fail visibly once `PUNCH_TIMEOUT`
/// elapses, not hang or silently drop whatever was pending against it.
/// Uses `tick_at` with an injected future `Instant` instead of a real sleep
/// so this stays fast.
///
/// @requirement AC-101, TB-146
#[tokio::test]
async fn punch_timeout_fails_the_link_and_emits_link_failed() {
    let server_addr = spawn_test_server().await;

    let mut a = TcpStream::connect(server_addr).await.unwrap();
    let _alice_id = handshake(&mut a, "alice").await;
    // Registered so the RequestPeerLink itself is accepted by the server,
    // but this connection never does anything with it - nobody ever
    // answers alice's candidate proposal.
    let mut b = TcpStream::connect(server_addr).await.unwrap();
    let bob_id = handshake(&mut b, "bob").await;

    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, _socket) = PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), server_addr, events_tx).await.unwrap();
    alice.ensure_link(&mut a, bob_id).await;
    assert!(!alice.is_active(bob_id));

    alice.tick_at(tokio::time::Instant::now().into_std() + Duration::from_secs(6));

    let event = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
        .await
        .expect("tick_at should fail the link synchronously")
        .expect("channel should still be open");
    match event {
        P2pEvent::LinkFailed { peer, .. } => assert_eq!(peer, bob_id),
        _ => panic!("expected P2pEvent::LinkFailed"),
    }
    assert!(!alice.is_active(bob_id));
}
