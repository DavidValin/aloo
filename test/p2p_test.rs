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
    InboundDatagram, LINK_IDLE_TIMEOUT, LinkStatus, P2pEvent, PENDING_MAX_AGE, PeerLinkManager,
    RETRY_BASE, RETRY_MAX, REFLEXIVE_REFRESH_INTERVAL, SIGNAL_TIMEOUT,
};
use aloo::crypto;
use rand_core::OsRng;
use rsa::RsaPrivateKey;
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
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), a_events_tx)
            .await
            .unwrap();
    let (mut bob, b_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), b_events_tx)
            .await
            .unwrap();

    let (a_raw_tx, mut a_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_raw_tx, mut b_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(a_socket, Some(server_addr), a_raw_tx);
    aloo::client::p2p::spawn_receive_loop(b_socket, Some(server_addr), b_raw_tx);

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
            msg_id: None,
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
            ..
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

/// A device id (docs/PROTOCOL.md §12.7) travels exactly like any other
/// content: `P2pPayload::DeviceIdAnnounce` carries a per-recipient
/// RSA-OAEP-sealed `Envelope` (`Content::DeviceIdAnnounce`), delivered
/// reliably over the punched link like a text message, never as plaintext
/// on the wire. This is the wire/crypto layer alone - `session.rs`'s
/// automatic send-on-Active and decrypt-on-arrival orchestration around it
/// isn't reachable from here (it lives on `SessionState`, not
/// `PeerLinkManager`).
///
/// @requirement AC-165
#[tokio::test]
async fn device_id_announce_travels_encrypted_and_decrypts_on_arrival() {
    let server_addr = spawn_test_server().await;

    let mut a = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let alice_id = handshake(&mut a, "alice").await;
    let mut b = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let bob_id = handshake(&mut b, "bob").await;

    let (a_events_tx, _a_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (b_events_tx, mut b_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, a_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), a_events_tx)
            .await
            .unwrap();
    let (mut bob, b_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), b_events_tx)
            .await
            .unwrap();

    let (a_raw_tx, mut a_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_raw_tx, mut b_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(a_socket, Some(server_addr), a_raw_tx);
    aloo::client::p2p::spawn_receive_loop(b_socket, Some(server_addr), b_raw_tx);

    alice.ensure_link(&mut a, bob_id).await;
    let ServerMessage::PeerCandidates {
        candidates, link_nonce, ..
    } = b.recv().await.unwrap().unwrap()
    else {
        panic!("bob should receive alice's PeerCandidates");
    };
    bob.on_peer_candidates(&mut b, alice_id, candidates, link_nonce)
        .await;
    let ServerMessage::PeerCandidates {
        candidates, link_nonce, ..
    } = a.recv().await.unwrap().unwrap()
    else {
        panic!("alice should receive bob's PeerCandidates reply");
    };
    alice
        .on_peer_candidates(&mut a, bob_id, candidates, link_nonce)
        .await;

    let both_active =
        |a: &PeerLinkManager, b: &PeerLinkManager| a.is_active(bob_id) && b.is_active(alice_id);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
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

    // Bob's keypair - small but big enough for a 50-byte device id under
    // OAEP/SHA-256 (needs > 66 + 50 = 116 bytes of modulus; 1024 bits is
    // 128 bytes), and much faster to generate than the production
    // `RSA_KEY_BITS` (2048).
    let bob_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("keygen");
    // Round-tripped through DER, exactly like the real send path: a
    // sender only ever holds a peer's `public_key_der` bytes (from
    // `UserInfo`), never a live key object.
    let bob_public_der = crypto::public_key_to_der(&bob_key.to_public_key()).unwrap();
    let bob_public = crypto::public_key_from_der(&bob_public_der).unwrap();
    let alice_device_id = "a".repeat(50);

    let blocks = crypto::encrypt_chunked(&bob_public, alice_device_id.as_bytes()).unwrap();
    let envelope = Envelope {
        content: Content::DeviceIdAnnounce,
        blocks,
    };
    // Sanity check: the plaintext device id must not appear anywhere in
    // the encoded wire bytes - proof this isn't accidentally sent as
    // cleartext.
    let wire_bytes = encode(&P2pPayload::DeviceIdAnnounce {
        envelope: envelope.clone(),
    })
    .unwrap();
    assert!(
        !wire_bytes
            .windows(alice_device_id.len())
            .any(|w| w == alice_device_id.as_bytes()),
        "the device id must never appear verbatim in the encoded frame"
    );

    alice.send_reliable_or_queue(bob_id, P2pPayload::DeviceIdAnnounce { envelope });

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
    .expect("bob should receive alice's DeviceIdAnnounce within the timeout");

    match received {
        P2pEvent::DeviceIdAnnounce { from, envelope } => {
            assert_eq!(from, alice_id);
            assert_eq!(envelope.content, Content::DeviceIdAnnounce);
            let plaintext = crypto::decrypt_chunked(&bob_key, &envelope.blocks).unwrap();
            assert_eq!(
                String::from_utf8(plaintext).unwrap(),
                alice_device_id,
                "bob must recover exactly alice's device id, unmodified"
            );
        }
        _ => panic!("expected P2pEvent::DeviceIdAnnounce, got a different event"),
    }
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
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), events_tx)
            .await
            .unwrap();
    alice.ensure_link(&mut a, bob_id).await;
    assert!(!alice.is_active(bob_id));
    alice.send_reliable_or_queue(
        bob_id,
        P2pPayload::Envelope {
            msg_id: None,
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
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), events_tx)
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
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), events_tx)
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
            msg_id: None,
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

/// The reflexive candidate is the only address in the list that can work
/// between two peers on different networks. The host candidates around it
/// are whatever `if_addrs` reports - loopback, the LAN address, and one
/// gateway per Docker bridge, VPN or container network - and a receiver
/// stops storing at `CANDIDATES_MAX`. Advertising the useful one last
/// therefore let a machine with enough virtual interfaces push its own
/// only routable address off the end of its peer's list, leaving nothing
/// to punch to but private addresses. It goes first.
///
/// @requirement TB-200
#[tokio::test]
async fn the_reflexive_candidate_is_advertised_ahead_of_the_host_ones() {
    let server_addr = spawn_test_server().await;
    let (alice, _events, _a, _b, _bob_id) = one_manager(server_addr).await;

    let candidates = alice.local_candidate_list();
    assert!(
        !candidates.is_empty(),
        "a bound manager always has at least its own host addresses"
    );
    // On loopback the rendezvous socket always answers, so the reflexive
    // address is known - and must be the entry a truncating peer keeps.
    let reflexive = candidates[0];
    assert_eq!(
        reflexive.ip(),
        std::net::Ipv4Addr::LOCALHOST,
        "loopback's reflexive address is 127.0.0.1, observed by the server"
    );
    // No duplicates: the reflexive address is also a host address here, and
    // spending two of a peer's sixteen slots on one address helps nobody.
    let mut seen = std::collections::HashSet::new();
    for addr in &candidates {
        assert!(seen.insert(*addr), "{addr} advertised twice");
    }
}

/// The session's one UDP socket is bound to a single address family for
/// its whole life, and `send_to` across families fails at the syscall. An
/// address of the other family is therefore not a worse candidate but an
/// impossible one, and storing it only spends a `CANDIDATES_MAX` slot that
/// a reachable address needs - so neither side ever advertises or keeps
/// one.
///
/// @requirement TB-200
#[tokio::test]
async fn candidates_of_the_wrong_address_family_are_never_advertised_or_stored() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    // This manager is bound on IPv4 (loopback server), so nothing it
    // advertises may be IPv6.
    assert!(
        alice.local_candidate_list().iter().all(|c| c.is_ipv4()),
        "an IPv4-bound socket advertised an IPv6 candidate it could never send from"
    );

    alice.ensure_link(&mut a, bob_id).await;
    let nonce = relayed_nonce(&mut b).await;

    // bob replies with a mix: two IPv6 addresses that alice's socket can
    // never reach, and one usable IPv4 one.
    alice
        .on_peer_candidates(
            &mut a,
            bob_id,
            vec![
                "[2001:db8::1]:7000".parse().unwrap(),
                "[::1]:7001".parse().unwrap(),
                "127.0.0.1:7002".parse().unwrap(),
            ],
            nonce,
        )
        .await;

    assert_eq!(
        alice.candidate_count(bob_id),
        1,
        "only the IPv4 candidate is reachable and so only it should be kept"
    );
}

/// A link-local address cannot be probed once it has been relayed: the scope
/// id naming which interface it belongs to survives neither the wire format
/// nor `SocketAddr`, so the syscall rejects it outright. They are not a rare
/// case to tidy up, either - every IPv6 interface has one, so on an
/// IPv6-bound session they are the bulk of what the machine reports, and
/// unfiltered they crowd the one globally routable address out of the peer's
/// `CANDIDATES_MAX` window, exactly the failure ordering the reflexive
/// candidate first was meant to end.
///
/// @requirement TB-200
#[tokio::test]
async fn link_local_candidates_are_never_advertised_or_stored() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    assert!(
        alice
            .local_candidate_list()
            .iter()
            .all(|c| !is_link_local_addr(c)),
        "a link-local address was advertised, though no peer could ever probe it: {:?}",
        alice.local_candidate_list()
    );

    alice.ensure_link(&mut a, bob_id).await;
    let nonce = relayed_nonce(&mut b).await;

    // A peer (an older build, say) offers its link-locals alongside one
    // genuinely reachable address.
    alice
        .on_peer_candidates(
            &mut a,
            bob_id,
            vec![
                "169.254.13.7:7000".parse().unwrap(),
                "169.254.99.1:7001".parse().unwrap(),
                "127.0.0.1:7002".parse().unwrap(),
            ],
            nonce,
        )
        .await;

    assert_eq!(
        alice.candidate_count(bob_id),
        1,
        "only the routable candidate should be kept - a relayed link-local can \
         only ever fail at the syscall, and spends a slot that a reachable \
         address needs"
    );
}

/// The whole point of the reflexive filter: a server that sees clients
/// through a Docker bridge reports the bridge's own address as everybody's
/// "public" one. Advertising it doesn't just fail to help - it actively
/// poisons the candidate list, since it is the first address peers try and
/// it can never work across networks. It must be refused outright rather
/// than stored, and must not re-signal links as a genuine address change
/// does.
///
/// @requirement TB-204
#[tokio::test]
async fn a_bogus_reflexive_observation_is_refused_rather_than_advertised() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let _ = next_signal_for(&mut events, bob_id);

    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + REFLEXIVE_REFRESH_INTERVAL + Duration::from_millis(100));
    let token = alice.reflexive_token();

    // The server answers with its own docker-bridge address.
    let bogus: SocketAddr = "172.17.0.1:38082".parse().unwrap();
    alice.on_rendezvous(
        server_addr,
        RendezvousMessage::BindingResponse {
            token,
            observed: bogus,
        },
    );

    assert!(
        !alice.local_candidate_list().contains(&bogus),
        "a docker-bridge address must never be advertised as our public one"
    );
    assert!(
        next_signal_for(&mut events, bob_id).is_none(),
        "refusing an unusable observation is not an address change - re-signalling \
         peers over it would spend a round trip advertising an address that cannot work"
    );
}

/// A dual-stack server sees an IPv4 client through a socket bound to `::`,
/// so it reports that client's own address back in IPv4-mapped form. Stored
/// verbatim it is an `IpAddr::V6` as far as this program is concerned, and
/// every peer whose socket is IPv4 - which, for an IPv4 client, is all the
/// ones that can reach it - discards it on the family filter. The net effect
/// is that reflexive discovery silently yields nothing usable for every IPv4
/// client of a dual-stack server.
///
/// @requirement TB-204
#[tokio::test]
async fn a_mapped_reflexive_observation_is_advertised_as_plain_ipv4() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, _a, _b, _bob_id) = one_manager(server_addr).await;

    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + REFLEXIVE_REFRESH_INTERVAL + Duration::from_millis(100));
    let token = alice.reflexive_token();

    // What a dual-stack server reports for an IPv4 client.
    let mapped: SocketAddr = "[::ffff:203.0.113.9]:33333".parse().unwrap();
    alice.on_rendezvous(
        server_addr,
        RendezvousMessage::BindingResponse {
            token,
            observed: mapped,
        },
    );

    let advertised = alice.local_candidate_list();
    let plain: SocketAddr = "203.0.113.9:33333".parse().unwrap();
    assert!(
        advertised.contains(&plain),
        "the mapped observation must be advertised as the IPv4 address it names, \
         or an IPv4 peer's family filter discards it: {advertised:?}"
    );
    assert!(
        !advertised.contains(&mapped),
        "the mapped form must not also be advertised - it spends a CANDIDATES_MAX \
         slot on an address no IPv4 peer will keep"
    );
}

/// A mapped address that names a *private* IPv4 address is the docker-bridge
/// case wearing a different hat, and is the reason the usability check has to
/// see the normalized address: judged as IPv6 it passes every rule, since
/// none of the IPv4 private/loopback rules have an IPv6 counterpart.
///
/// @requirement TB-204
#[tokio::test]
async fn a_mapped_bogus_reflexive_observation_is_refused_too() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, _a, _b, _bob_id) = one_manager(server_addr).await;

    let t0 = tokio::time::Instant::now().into_std();
    alice.tick_at(t0 + REFLEXIVE_REFRESH_INTERVAL + Duration::from_millis(100));
    let token = alice.reflexive_token();

    let mapped_bogus: SocketAddr = "[::ffff:172.17.0.1]:38082".parse().unwrap();
    alice.on_rendezvous(
        server_addr,
        RendezvousMessage::BindingResponse {
            token,
            observed: mapped_bogus,
        },
    );

    let advertised = alice.local_candidate_list();
    let plain: SocketAddr = "172.17.0.1:38082".parse().unwrap();
    assert!(
        !advertised.contains(&mapped_bogus) && !advertised.contains(&plain),
        "a mapped docker-bridge address is the same unusable address in a \
         different shape and must be refused in either form: {advertised:?}"
    );
}

fn is_link_local_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// `UserOffline` forgets a peer's link outright - stopping its keepalives,
/// its retries and its backoff. Everything that brings the link back
/// therefore hangs off the `ensure_link` on their next `UserJoined`, which
/// is why that call fires on *every* sighting rather than only the first
/// one: a peer who blips offline and reconnects (a heartbeat timeout on a
/// slow link is enough) would otherwise be left with no link at all, and
/// nothing scheduled to build one, until the user happened to send them
/// something.
///
/// @requirement TB-149
#[tokio::test]
async fn a_peer_who_reconnects_is_punched_again() {
    let server_addr = spawn_test_server().await;
    let (mut alice, _events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let first = relayed_nonce(&mut b).await;
    assert_eq!(alice.status(bob_id), Some(LinkStatus::Connecting));

    // What `UserOffline` does: the link, its retries and its backoff go.
    alice.forget(bob_id);
    assert_eq!(
        alice.status(bob_id),
        None,
        "a forgotten peer has no link left to retry"
    );

    // What their next `UserJoined` now does unconditionally.
    alice.ensure_link(&mut a, bob_id).await;
    let second = relayed_nonce(&mut b).await;

    assert_eq!(
        alice.status(bob_id),
        Some(LinkStatus::Connecting),
        "reconnecting must put the peer back into establishment"
    );
    assert_ne!(
        first, second,
        "the re-punch is a fresh attempt, not a resumption of the forgotten one"
    );
}

// ---------------------------------------------------------------------
// Two real managers: the flow's unhappy paths
// ---------------------------------------------------------------------

/// Both ends of a real link plus everything needed to drive them: the two
/// control connections signalling actually travels over (relayed by a real
/// server), the raw-datagram feed each side's `spawn_receive_loop` publishes,
/// and each side's `P2pEvent` channel.
///
/// The single-manager tests above inject datagrams by hand, which is exact
/// but cannot exercise anything where *both* sides' state machines have to
/// agree: a re-punch, an ARQ sequence space restarting on both sides at once,
/// a peer that disappears mid-conversation and comes back. Those need two
/// managers actually talking, which is what this drives.
struct Pair {
    alice: PeerLinkManager,
    bob: PeerLinkManager,
    a_ctl: ControlEndpoint<TcpStream>,
    b_ctl: ControlEndpoint<TcpStream>,
    a_events: tokio::sync::mpsc::UnboundedReceiver<P2pEvent>,
    b_events: tokio::sync::mpsc::UnboundedReceiver<P2pEvent>,
    a_raw: tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, InboundDatagram)>,
    b_raw: tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, InboundDatagram)>,
    /// Everything drained off each event channel so far. Buffered rather
    /// than consumed on the spot so a helper looking for one kind of event
    /// (a `Signal` to relay) never throws away another kind a test still
    /// wants to assert on (a delivered `Message`).
    a_seen: Vec<P2pEvent>,
    b_seen: Vec<P2pEvent>,
    alice_id: UserId,
    bob_id: UserId,
}

impl Pair {
    async fn connect(server_addr: SocketAddr) -> Self {
        let mut a_ctl = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
        let alice_id = handshake(&mut a_ctl, "alice").await;
        let mut b_ctl = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
        let bob_id = handshake(&mut b_ctl, "bob").await;

        let (a_events_tx, a_events) = tokio::sync::mpsc::unbounded_channel();
        let (b_events_tx, b_events) = tokio::sync::mpsc::unbounded_channel();
        let (alice, a_socket) =
            PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), a_events_tx)
                .await
                .unwrap();
        let (bob, b_socket) =
            PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), b_events_tx)
                .await
                .unwrap();

        let (a_raw_tx, a_raw) = tokio::sync::mpsc::unbounded_channel();
        let (b_raw_tx, b_raw) = tokio::sync::mpsc::unbounded_channel();
        aloo::client::p2p::spawn_receive_loop(a_socket, Some(server_addr), a_raw_tx);
        aloo::client::p2p::spawn_receive_loop(b_socket, Some(server_addr), b_raw_tx);

        Self {
            alice,
            bob,
            a_ctl,
            b_ctl,
            a_events,
            b_events,
            a_raw,
            b_raw,
            a_seen: Vec::new(),
            b_seen: Vec::new(),
            alice_id,
            bob_id,
        }
    }

    fn drain_events(&mut self) {
        while let Ok(e) = self.a_events.try_recv() {
            self.a_seen.push(e);
        }
        while let Ok(e) = self.b_events.try_recv() {
            self.b_seen.push(e);
        }
    }

    /// Removes and returns every buffered `Signal`, leaving other events in
    /// place.
    fn take_signals(seen: &mut Vec<P2pEvent>) -> Vec<(UserId, Vec<SocketAddr>, u64)> {
        let mut signals = Vec::new();
        let mut rest = Vec::new();
        for event in seen.drain(..) {
            match event {
                P2pEvent::Signal {
                    peer,
                    candidates,
                    link_nonce,
                } => signals.push((peer, candidates, link_nonce)),
                other => rest.push(other),
            }
        }
        *seen = rest;
        signals
    }

    /// The signalling half of `session.rs`: forwards every `Signal` either
    /// manager emitted out over that side's own control connection as a
    /// `RequestPeerLink`, and feeds back in every `PeerCandidates` the server
    /// relays as a result - including the replies those themselves provoke.
    async fn relay_signalling(&mut self) {
        for _ in 0..6 {
            self.drain_events();
            let mut moved = false;
            for (peer, candidates, link_nonce) in Self::take_signals(&mut self.a_seen) {
                self.a_ctl
                    .send(&ClientMessage::RequestPeerLink {
                        peer,
                        candidates,
                        link_nonce,
                    })
                    .await
                    .unwrap();
                moved = true;
            }
            for (peer, candidates, link_nonce) in Self::take_signals(&mut self.b_seen) {
                self.b_ctl
                    .send(&ClientMessage::RequestPeerLink {
                        peer,
                        candidates,
                        link_nonce,
                    })
                    .await
                    .unwrap();
                moved = true;
            }
            if self.feed_relayed_candidates().await {
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }

    /// Hands each side any `PeerCandidates` the server has relayed to it.
    async fn feed_relayed_candidates(&mut self) -> bool {
        let mut any = false;
        for _ in 0..4 {
            let mut moved = false;
            if let Some((from, candidates, link_nonce)) = next_candidates(&mut self.b_ctl).await {
                self.bob
                    .on_peer_candidates(&mut self.b_ctl, from, candidates, link_nonce)
                    .await;
                moved = true;
            }
            if let Some((from, candidates, link_nonce)) = next_candidates(&mut self.a_ctl).await {
                self.alice
                    .on_peer_candidates(&mut self.a_ctl, from, candidates, link_nonce)
                    .await;
                moved = true;
            }
            if !moved {
                break;
            }
            any = true;
        }
        any
    }

    /// Feeds inbound datagrams into both managers, ticking both on roughly
    /// the session loop's cadence, until `done` holds or `limit` elapses.
    async fn pump(
        &mut self,
        limit: Duration,
        done: impl Fn(&PeerLinkManager, &PeerLinkManager) -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let mut fed = false;
            while let Ok((addr, dgram)) = self.a_raw.try_recv() {
                self.alice.on_inbound(addr, dgram);
                fed = true;
            }
            while let Ok((addr, dgram)) = self.b_raw.try_recv() {
                self.bob.on_inbound(addr, dgram);
                fed = true;
            }
            self.drain_events();
            if done(&self.alice, &self.bob) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            if fed {
                tokio::task::yield_now().await;
            } else {
                self.alice.tick();
                self.bob.tick();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    /// One full candidate exchange followed by punching, asserting both
    /// sides end up with a confirmed link.
    async fn punch(&mut self) {
        self.relay_signalling().await;
        let (alice_id, bob_id) = (self.alice_id, self.bob_id);
        assert!(
            self.pump(Duration::from_secs(10), move |a, b| {
                a.is_active(bob_id) && b.is_active(alice_id)
            })
            .await,
            "the loopback punch should complete in both directions"
        );
    }

    /// Drives the pair until a text message surfaces on bob's event channel,
    /// returning its single plaintext block.
    async fn bob_next_text(&mut self, limit: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(idx) = self
                .b_seen
                .iter()
                .position(|e| matches!(e, P2pEvent::Message { .. }))
            {
                return match self.b_seen.remove(idx) {
                    P2pEvent::Message { envelope, .. } => envelope.blocks.into_iter().next(),
                    _ => None,
                };
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            self.pump(Duration::from_millis(50), |_, _| false).await;
        }
    }
}

/// The next `PeerCandidates` waiting on this connection, or `None` if none
/// arrives promptly. Timeout-guarded rather than a plain `recv`: whether a
/// side answers a proposal at all depends on its own link state, so the
/// correct answer is often "nothing", which a blocking read would hang on.
async fn next_candidates(
    ctl: &mut ControlEndpoint<TcpStream>,
) -> Option<(UserId, Vec<SocketAddr>, u64)> {
    let msg: ServerMessage = tokio::time::timeout(Duration::from_millis(300), ctl.recv())
        .await
        .ok()?
        .ok()??;
    match msg {
        ServerMessage::PeerCandidates {
            from,
            candidates,
            link_nonce,
        } => Some((from, candidates, link_nonce)),
        _ => None,
    }
}

/// One payload the size of a real OTP setup chunk: a label block to assert
/// order and completeness on, plus 32KB of filler standing in for the two
/// 16KB key chunks such an envelope actually carries.
fn otp_sized_payload(i: usize) -> P2pPayload {
    P2pPayload::Envelope {
        msg_id: None,
        channel: None,
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![format!("chunk-{i}").into_bytes(), vec![b'x'; 32 * 1024]],
        },
    }
}

fn text_payload(body: &str) -> P2pPayload {
    P2pPayload::Envelope {
        msg_id: None,
        channel: None,
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![body.as_bytes().to_vec()],
        },
    }
}

/// A peer going offline discards their link outright (TB-178), and with it
/// anything still queued against it. That silence made a peer who vanished
/// mid-send indistinguishable from one who received everything: the sender
/// sat on "waiting for their confirmation" forever, because the only thing
/// that reports undelivered content - `expire_pending` - needs a link that
/// still exists to age it out of.
///
/// @requirement AC-142
#[tokio::test]
async fn forgetting_a_link_reports_content_that_was_still_waiting_on_it() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    alice.send_reliable_or_queue(bob_id, text_payload("an invitation in flight"));
    assert_eq!(
        alice.pending_count(bob_id),
        1,
        "precondition: the send is queued against a link that never came up"
    );

    alice.forget(bob_id);

    let failed = std::iter::from_fn(|| events.try_recv().ok()).any(|e| {
        matches!(
            e,
            P2pEvent::LinkFailed { peer, .. } if peer == bob_id
        )
    });
    assert!(
        failed,
        "content dropped with a forgotten link must be reported, not silently discarded"
    );
}

/// The counterpart: forgetting a link with nothing waiting on it is routine
/// housekeeping (every `UserOffline` does it) and must stay silent, or every
/// disconnect would raise a failure for content that never existed.
///
/// @requirement AC-142
#[tokio::test]
async fn forgetting_an_empty_link_reports_nothing() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, _b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    while events.try_recv().is_ok() {}
    alice.forget(bob_id);

    let failed = std::iter::from_fn(|| events.try_recv().ok())
        .any(|e| matches!(e, P2pEvent::LinkFailed { .. }));
    assert!(!failed, "an empty link going away is not a delivery failure");
}

/// Provisioning must not take the link hostage. A pad is handed over as one
/// large burst, and ordinary conversation - which is not OTP-encrypted and
/// has nothing to do with the invitation - has to keep flowing while that
/// burst is in progress, rather than being lost or blocked behind it
/// indefinitely.
///
/// @requirement AC-142
#[tokio::test]
async fn ordinary_messages_still_arrive_while_a_pad_is_being_transferred() {
    let server_addr = spawn_test_server().await;
    let mut pair = Pair::connect(server_addr).await;
    pair.alice.ensure_link(&mut pair.a_ctl, pair.bob_id).await;
    pair.punch().await;

    // A pad-sized burst goes out, and a plain chat message is sent into the
    // middle of it - the ordering a user typing during provisioning creates.
    for i in 0..40 {
        pair.alice
            .send_reliable_or_queue(pair.bob_id, otp_sized_payload(i));
    }
    pair.alice
        .send_reliable_or_queue(pair.bob_id, text_payload("hello while provisioning"));
    for i in 40..80 {
        pair.alice
            .send_reliable_or_queue(pair.bob_id, otp_sized_payload(i));
    }

    let mut texts: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut delivered = 0usize;
    loop {
        pair.pump(Duration::from_millis(50), |_, _| false).await;
        let mut rest = Vec::new();
        for event in pair.b_seen.drain(..) {
            match event {
                P2pEvent::Message { envelope, .. } => {
                    delivered += 1;
                    let block = envelope.blocks.first().cloned().unwrap_or_default();
                    let body = String::from_utf8_lossy(&block).into_owned();
                    if !body.starts_with("chunk-") {
                        texts.push(body);
                    }
                }
                other => rest.push(other),
            }
        }
        pair.b_seen = rest;
        if delivered >= 81 || tokio::time::Instant::now() >= deadline {
            break;
        }
    }

    assert_eq!(
        texts,
        vec!["hello while provisioning".to_string()],
        "a plain message sent during provisioning must still reach the peer"
    );
    assert_eq!(
        delivered, 81,
        "and it must not cost the pad any of its chunks either"
    );
}

/// Regression, and the one that reproduces the OTP failure end to end: a
/// pad provisioning hands the link hundreds of chunked envelopes in a single
/// pass, far more than the ARQ send window. Every one of them must arrive,
/// in the order it was handed over.
///
/// Before the window existed they all went onto the socket in the same
/// instant; the tail was dropped, and since a receiver has to buffer every
/// frame after a lost one, it hit `REORDER_BUFFER_LIMIT` and failed the
/// whole link. The receiving side then reassembled a pad whose front was
/// missing and reported a malformed setup message.
///
/// @requirement TB-202
#[tokio::test]
async fn a_burst_larger_than_the_send_window_arrives_complete_and_in_order() {
    let server_addr = spawn_test_server().await;
    let mut pair = Pair::connect(server_addr).await;
    pair.alice.ensure_link(&mut pair.a_ctl, pair.bob_id).await;
    pair.punch().await;

    // Comfortably more than one window, so the backlog has to drain through
    // several rounds of acks rather than emptying on the first.
    // Sized like a real pad, not just "more than one window": the smallest
    // pad the `/otp` size prompt allows is 64 chunks, which is also exactly
    // the receiver's `REORDER_BUFFER_LIMIT`. A burst below that limit cannot
    // reproduce the failure at all - the receiver absorbs the reordering and
    // the ARQ retransmits whatever was dropped - so the count has to clear
    // it the way a genuine pad does.
    let burst = 100;
    // Sized like the real thing: an OTP setup chunk carries 16KB of each key
    // (`client::otp::OTP_SETUP_CHUNK_BYTES`), so the datagrams are ~32KB
    // rather than a few bytes. That is what actually loads the socket
    // buffer - a burst of tiny text frames fits on loopback whether it is
    // paced or not, and would pass against the very bug this pins.
    for i in 0..burst {
        pair.alice
            .send_reliable_or_queue(pair.bob_id, otp_sized_payload(i));
    }

    let bob_id = pair.bob_id;
    let _ = bob_id;
    let delivered = {
        let mut got: Vec<String> = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            pair.pump(Duration::from_millis(50), |_, _| false).await;
            let mut rest = Vec::new();
            for event in pair.b_seen.drain(..) {
                match event {
                    P2pEvent::Message { envelope, .. } => {
                        let block = envelope.blocks.first().cloned().unwrap_or_default();
                        got.push(String::from_utf8_lossy(&block).into_owned());
                    }
                    other => rest.push(other),
                }
            }
            pair.b_seen = rest;
            if got.len() >= burst || tokio::time::Instant::now() >= deadline {
                break got;
            }
        }
    };

    let expected: Vec<String> = (0..burst).map(|i| format!("chunk-{i}")).collect();
    assert_eq!(
        delivered.len(),
        burst,
        "every frame of the burst must arrive - {} of {burst} did. A pad with any \
         chunk missing is not a smaller pad, it is a malformed setup message",
        delivered.len()
    );
    assert_eq!(
        delivered, expected,
        "the burst must be delivered in the order it was handed over"
    );
    assert!(
        pair.alice.is_active(pair.bob_id) && pair.bob.is_active(pair.alice_id),
        "the link must survive the burst rather than failing on a blown reorder buffer"
    );
}

/// Regression. A changed reflexive address re-signals every link that is not
/// `Active` (TB-181) - and such a link may be `Lost` rather than merely
/// `Requested`, still holding the ARQ state of the traffic it carried before
/// it died (marking a link lost deliberately does not reset that; the reset
/// belongs to the next attempt). Re-signalling it without going through that
/// reset left this side numbering its next frame from where the dead link
/// stopped, while the peer - following the new nonce onto a fresh attempt -
/// restarted its receive sequence at zero. Every later frame then sat in the
/// peer's reorder buffer forever: acked, so never retransmitted, and never
/// delivered, with nothing reported to either user.
///
/// @requirement TB-180, TB-181
#[tokio::test]
async fn a_reflexive_change_restarts_the_sequence_space_of_a_link_that_carried_traffic() {
    let server_addr = spawn_test_server().await;
    let mut pair = Pair::connect(server_addr).await;
    pair.alice.ensure_link(&mut pair.a_ctl, pair.bob_id).await;
    pair.punch().await;

    // Real traffic first, so both sides' sequence spaces have actually
    // advanced past zero before anything restarts.
    let bob_id = pair.bob_id;
    pair.alice
        .send_reliable_or_queue(bob_id, text_payload("before the restart"));
    assert_eq!(
        pair.bob_next_text(Duration::from_secs(10))
            .await
            .as_deref()
            .map(String::from_utf8_lossy),
        Some("before the restart".into()),
        "precondition: the original link delivers, advancing both sequence spaces"
    );

    // Alice's side of the link dies quietly (a NAT rebinding, a route
    // change) and is marked lost, while bob still believes it is up.
    let future = tokio::time::Instant::now().into_std() + LINK_IDLE_TIMEOUT + Duration::from_secs(1);
    pair.alice.tick_at(future);
    assert_eq!(
        pair.alice.status(bob_id),
        Some(LinkStatus::Lost),
        "precondition: alice's link is lost, and still holds the dead link's ARQ state"
    );

    // Her public address turns out to have moved too, which re-signals the
    // lost link - the path this regression is about.
    let observed: SocketAddr = "203.0.113.77:33333".parse().unwrap();
    let token = pair.alice.reflexive_token();
    pair.alice.on_rendezvous(
        server_addr,
        RendezvousMessage::BindingResponse { token, observed },
    );
    assert_eq!(
        pair.alice.status(bob_id),
        Some(LinkStatus::Connecting),
        "a moved address must put the lost link back into establishment"
    );

    // Bob sees a nonce he does not recognise on a link he thought was up,
    // concludes alice restarted, and follows her - resetting his own receive
    // sequence to zero as he does.
    pair.punch().await;

    pair.alice
        .send_reliable_or_queue(bob_id, text_payload("after the restart"));
    assert_eq!(
        pair.bob_next_text(Duration::from_secs(10))
            .await
            .as_deref()
            .map(String::from_utf8_lossy),
        Some("after the restart".into()),
        "content sent on the re-punched link must actually be delivered: both \
         sides restart the sequence space together, or every frame is acked \
         into the peer's reorder buffer and silently never delivered"
    );
}

/// A peer that goes quiet mid-conversation and comes back. Everything typed
/// while the link was down has to arrive once it reopens, under a sequence
/// space both sides restarted together - the two-sided counterpart of
/// `content_queued_while_the_link_is_down_is_flushed_when_it_recovers`,
/// which proves the queue survives but cannot prove the peer accepts what
/// comes out of it.
///
/// @requirement TB-179, TB-180
#[tokio::test]
async fn content_queued_while_a_peer_is_away_is_delivered_once_the_link_returns() {
    let server_addr = spawn_test_server().await;
    let mut pair = Pair::connect(server_addr).await;
    pair.alice.ensure_link(&mut pair.a_ctl, pair.bob_id).await;
    pair.punch().await;

    let (alice_id, bob_id) = (pair.alice_id, pair.bob_id);
    pair.alice
        .send_reliable_or_queue(bob_id, text_payload("while up"));
    assert!(
        pair.bob_next_text(Duration::from_secs(10)).await.is_some(),
        "precondition: the link works and both sequence spaces have advanced"
    );

    // The path between them dies. Both sides notice independently, which is
    // what really happens: neither is told, each just stops hearing beats.
    let future = tokio::time::Instant::now().into_std() + LINK_IDLE_TIMEOUT + Duration::from_secs(1);
    pair.alice.tick_at(future);
    pair.bob.tick_at(future);
    assert_eq!(pair.alice.status(bob_id), Some(LinkStatus::Lost));
    assert_eq!(pair.bob.status(alice_id), Some(LinkStatus::Lost));

    // The user types anyway - it queues against the down link rather than
    // being dropped or reported.
    pair.alice
        .send_reliable_or_queue(bob_id, text_payload("typed while away"));
    assert_eq!(
        pair.alice.pending_count(bob_id),
        1,
        "content for a down link must be held, not dropped"
    );

    // A send is also what skips the retry backoff and re-signals.
    pair.alice.ensure_link(&mut pair.a_ctl, bob_id).await;
    pair.punch().await;

    assert_eq!(
        pair.bob_next_text(Duration::from_secs(10))
            .await
            .as_deref()
            .map(String::from_utf8_lossy),
        Some("typed while away".into()),
        "what was queued while the peer was away must arrive once it returns"
    );
    assert_eq!(
        pair.alice.pending_count(bob_id),
        0,
        "and must not be left sitting in the queue afterwards"
    );
}

/// The whole reconnect cycle, end to end: a peer disconnects (their link is
/// forgotten, as `UserOffline` does), comes back as the brand-new `UserId` a
/// reconnect always is - ids are never reused - and gets punched from
/// scratch. Nothing from the previous session may linger: not the link, not
/// its retries, and not its addresses in the demultiplexing index, which
/// would otherwise attribute a stale datagram to the wrong peer.
///
/// @requirement TB-149, TB-178
#[tokio::test]
async fn a_peer_that_reconnects_under_a_new_id_is_punched_from_scratch() {
    let server_addr = spawn_test_server().await;
    let mut pair = Pair::connect(server_addr).await;
    pair.alice.ensure_link(&mut pair.a_ctl, pair.bob_id).await;
    pair.punch().await;

    let old_bob_id = pair.bob_id;
    let old_bob_addr = pair
        .alice
        .active_addr(old_bob_id)
        .expect("the established link has an address");

    // Bob's connection goes away for real, so the server unregisters him -
    // the same thing that makes it send everyone else `UserOffline`.
    let placeholder = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    drop(std::mem::replace(&mut pair.b_ctl, placeholder));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Which is what forgets his link here.
    pair.alice.forget(old_bob_id);
    assert_eq!(
        pair.alice.status(old_bob_id),
        None,
        "a disconnected peer's link, and its retries, are gone"
    );

    // Bob comes back: a new connection, a new UDP socket, and a new UserId.
    let mut b_ctl = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let new_bob_id = handshake(&mut b_ctl, "bob").await;
    assert_ne!(
        new_bob_id, old_bob_id,
        "a reconnect is always a brand-new identity"
    );
    let (b_events_tx, b_events) = tokio::sync::mpsc::unbounded_channel();
    let (bob, b_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), b_events_tx)
            .await
            .unwrap();
    let (b_raw_tx, b_raw) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(b_socket, Some(server_addr), b_raw_tx);
    pair.bob = bob;
    pair.b_ctl = b_ctl;
    pair.b_events = b_events;
    pair.b_raw = b_raw;
    pair.b_seen.clear();
    pair.bob_id = new_bob_id;

    // A stale datagram from the dead session must not be attributed to
    // anything, even though its address was live moments ago.
    pair.alice
        .on_datagram(old_bob_addr, PunchDatagram::Keepalive { link_nonce: 1 });
    assert_eq!(
        pair.alice.status(old_bob_id),
        None,
        "a forgotten peer's address must no longer resolve to any link"
    );

    // The new identity punches from scratch and carries content.
    pair.alice.ensure_link(&mut pair.a_ctl, new_bob_id).await;
    pair.punch().await;
    pair.alice
        .send_reliable_or_queue(new_bob_id, text_payload("hello again"));
    assert_eq!(
        pair.bob_next_text(Duration::from_secs(10))
            .await
            .as_deref()
            .map(String::from_utf8_lossy),
        Some("hello again".into()),
        "the reconnected peer must get a working link of its own"
    );
    assert_eq!(
        pair.alice.status(old_bob_id),
        None,
        "and the previous session's link must still be gone"
    );
}

/// Forgetting a peer has to be complete, not just a status change: nothing
/// may keep probing them, and no address they used may still resolve to
/// them. A stale `Ping` carrying the forgotten link's own nonce is the
/// sharpest version of this - if `forget` left either the link or its
/// addresses behind, that datagram would revive or misattribute it.
///
/// @requirement TB-178
#[tokio::test]
async fn forgetting_a_peer_stops_its_retries_and_drops_its_addresses() {
    let server_addr = spawn_test_server().await;
    let (mut alice, mut events, mut a, mut b, bob_id) = one_manager(server_addr).await;

    alice.ensure_link(&mut a, bob_id).await;
    let link_nonce = relayed_nonce(&mut b).await;
    let peer_addr: SocketAddr = "203.0.113.50:40404".parse().unwrap();
    alice.on_datagram(peer_addr, PunchDatagram::Pong { link_nonce });
    assert!(alice.is_active(bob_id), "precondition: an established link");

    alice.forget(bob_id);

    // Its own nonce, from its own address, must revive nothing.
    alice.on_datagram(peer_addr, PunchDatagram::Ping { link_nonce });
    alice.on_datagram(peer_addr, PunchDatagram::Pong { link_nonce });
    assert_eq!(
        alice.status(bob_id),
        None,
        "a forgotten link must not come back from stale datagrams"
    );
    assert_eq!(alice.candidate_count(bob_id), 0);

    // And no retry may be scheduled for it, however far time moves.
    let _ = next_signal_for(&mut events, bob_id);
    let long_after = tokio::time::Instant::now().into_std() + RETRY_MAX * 4;
    alice.tick_at(long_after);
    assert_eq!(
        next_signal_for(&mut events, bob_id),
        None,
        "a forgotten peer must never be re-signalled"
    );
}

/// The rendezvous socket is the one part of punching that is served by the
/// server, and it faces the open internet with no authentication at all: it
/// answers whatever arrives. A single failed receive must therefore never
/// end its loop - it serves every client on the server, so ending it would
/// silently leave every later client with host candidates only, able to
/// punch on a LAN and nowhere else, for the rest of the server's uptime.
///
/// The error that motivates this is platform-specific (on Windows a client
/// that vanishes surfaces as `WSAECONNRESET` on a *later* receive, and an
/// oversized datagram as `WSAEMSGSIZE`), so what is portable to assert is
/// the property itself: after junk, an oversized datagram, a wrong-direction
/// message and a client that goes away mid-exchange, a legitimate request
/// is still answered.
///
/// @requirement TB-201
#[tokio::test]
async fn the_rendezvous_socket_keeps_serving_after_junk_and_a_vanished_client() {
    let server_addr = spawn_test_server().await;

    // Junk that decodes to nothing.
    let noise = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    noise.send_to(b"not a rendezvous message", server_addr).await.unwrap();
    // Larger than the server's receive buffer.
    noise.send_to(&vec![0xAB; 2048], server_addr).await.unwrap();
    // A well-formed message travelling the wrong way.
    let wrong_way = aloo::proto::encode(&RendezvousMessage::BindingResponse {
        token: 7,
        observed: "203.0.113.9:1".parse().unwrap(),
    })
    .unwrap();
    noise.send_to(&wrong_way, server_addr).await.unwrap();

    // A client that asks and then vanishes before the reply lands, so the
    // server's own `send_to` has nowhere to go.
    let vanishing = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = aloo::proto::encode(&RendezvousMessage::BindingRequest { token: 11 }).unwrap();
    vanishing.send_to(&request, server_addr).await.unwrap();
    drop(vanishing);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A legitimate client must still be served.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let expected = client.local_addr().unwrap();
    let request = aloo::proto::encode(&RendezvousMessage::BindingRequest { token: 42 }).unwrap();
    client.send_to(&request, server_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("the rendezvous socket must still answer after all of the above")
        .unwrap();
    assert_eq!(from, server_addr);
    assert_eq!(
        aloo::proto::decode::<RendezvousMessage>(&buf[..n]).unwrap(),
        RendezvousMessage::BindingResponse {
            token: 42,
            observed: expected,
        },
        "the reply must echo the token and the address the request came from"
    );
}

// ---------------------------------------------------------------------
// Delivery acknowledgment on the wire (docs/PROTOCOL.md 7.2.1)
// ---------------------------------------------------------------------

/// The id the sender puts on its message has to reach the receiving side,
/// because answering it is the receiver's job - a receiver that never saw
/// it could not acknowledge anything. `session.rs` is what decides to
/// answer (only once the envelope has actually opened); this is the wire
/// half alone.
/// @requirement AC-233
#[tokio::test]
async fn a_message_carries_the_id_its_recipient_must_receipt() {
    let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (_manager, _socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), None, events_tx.clone())
            .await
            .unwrap();

    let named = P2pPayload::Envelope {
        channel: None,
        msg_id: Some(4242),
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![b"did you get this".to_vec()],
        },
    };
    let decoded: P2pPayload = aloo::proto::decode(&aloo::proto::encode(&named).unwrap()).unwrap();
    match decoded {
        P2pPayload::Envelope { msg_id, .. } => assert_eq!(msg_id, Some(4242)),
        other => panic!("expected an Envelope, got {other:?}"),
    }
    drop(events_rx.try_recv());
}

/// A receipt is ordinary reliable content in both directions: the sender
/// learns of it as `P2pEvent::Delivered`, attributed to whichever link it
/// arrived on, exactly like any other payload.
/// @requirement AC-233
#[tokio::test]
async fn a_delivery_receipt_becomes_a_delivered_event_naming_its_sender() {
    let server_addr = spawn_test_server().await;

    let mut a = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let alice_id = handshake(&mut a, "alice").await;
    let mut b = ControlEndpoint::new(TcpStream::connect(server_addr).await.unwrap());
    let bob_id = handshake(&mut b, "bob").await;

    let (a_events_tx, mut a_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (b_events_tx, mut b_events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (mut alice, a_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), a_events_tx)
            .await
            .unwrap();
    let (mut bob, b_socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), b_events_tx)
            .await
            .unwrap();

    let (a_raw_tx, mut a_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_raw_tx, mut b_raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(a_socket, Some(server_addr), a_raw_tx);
    aloo::client::p2p::spawn_receive_loop(b_socket, Some(server_addr), b_raw_tx);

    alice.ensure_link(&mut a, bob_id).await;
    let ServerMessage::PeerCandidates {
        candidates,
        link_nonce,
        ..
    } = b.recv().await.unwrap().unwrap()
    else {
        panic!("bob should receive alice's PeerCandidates");
    };
    bob.on_peer_candidates(&mut b, alice_id, candidates, link_nonce)
        .await;
    let ServerMessage::PeerCandidates {
        candidates,
        link_nonce,
        ..
    } = a.recv().await.unwrap().unwrap()
    else {
        panic!("alice should receive bob's reply");
    };
    alice
        .on_peer_candidates(&mut a, bob_id, candidates, link_nonce)
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while !(alice.is_active(bob_id) && bob.is_active(alice_id)) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "loopback punch did not complete in time"
        );
        tokio::select! {
            Some((addr, dgram)) = a_raw_rx.recv() => alice.on_inbound(addr, dgram),
            Some((addr, dgram)) = b_raw_rx.recv() => bob.on_inbound(addr, dgram),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }

    // Bob answers a message he could read. `session.rs` sends this from the
    // one branch that has actually decrypted an envelope; here it is sent
    // directly, since the crypto is not what this test is about.
    bob.send_reliable_or_queue(alice_id, P2pPayload::DeliveryReceipt {
            msg_id: 4242,
            stage: aloo::p2p_proto::ReceiptStage::Decrypted,
        });

    let got = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = a_raw_rx.recv() => alice.on_inbound(addr, dgram),
                Some((addr, dgram)) = b_raw_rx.recv() => bob.on_inbound(addr, dgram),
                Some(event) = a_events_rx.recv() => {
                    if is_link_bookkeeping(&event) {
                        continue;
                    }
                    return event;
                }
            }
        }
    })
    .await
    .expect("alice should be told her message was read");

    match got {
        P2pEvent::Delivered {
            peer,
            msg_id,
            stage,
        } => {
            assert_eq!(peer, bob_id, "attributed to the link it arrived on");
            assert_eq!(msg_id, 4242, "and naming the sender's own message");
            assert_eq!(
                stage,
                aloo::p2p_proto::ReceiptStage::Decrypted,
                "and saying how far he got with it"
            );
        }
        _ => panic!("expected P2pEvent::Delivered, got a different event"),
    }
    let _ = b_events_rx.try_recv();
}

/// A whole megabyte of pad, at the real chunk size, over a genuinely
/// punched link - every frame of it must arrive.
///
/// This deliberately asserts arrival and *not* a rate. Throughput cannot be
/// measured here: `Pair::pump` hand-feeds datagrams between the two
/// managers with sleeps between rounds, so a run is bounded by the
/// harness's own cadence rather than by the transport - measured at roughly
/// 2ms per frame regardless of how many frames there are, which is a
/// per-frame harness cost, not a window-over-round-trip one. A number
/// printed from here would describe this test, not the app.
///
/// What it does pin is the property that actually broke provisioning: a
/// pad-sized burst far larger than one window arrives complete. A pad
/// missing a chunk is not a smaller pad - it decodes to garbage with
/// nothing anywhere reporting it.
///
/// @requirement AC-254
#[tokio::test]
async fn a_megabyte_of_pad_chunks_arrives_complete() {
    let server_addr = spawn_test_server().await;
    let mut pair = Pair::connect(server_addr).await;
    pair.alice.ensure_link(&mut pair.a_ctl, pair.bob_id).await;
    pair.punch().await;

    let chunk = aloo::client::otp_pad::PAD_CHUNK_BYTES;
    let frames = (1024 * 1024) / chunk;
    assert!(
        frames > aloo::client::p2p_reliable::SEND_WINDOW,
        "the burst has to exceed one window or it proves nothing about draining"
    );
    for i in 0..frames {
        pair.alice.send_reliable_or_queue(
            pair.bob_id,
            P2pPayload::OtpPadChunk {
                stream_id: 1,
                seq: i as u32,
                blocks: vec![vec![b'k'; chunk + 16]],
            },
        );
    }

    let mut arrived = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        pair.pump(Duration::from_millis(20), |_, _| false).await;
        let mut rest = Vec::new();
        for event in pair.b_seen.drain(..) {
            match event {
                P2pEvent::OtpPadChunk { .. } => arrived += 1,
                other => rest.push(other),
            }
        }
        pair.b_seen = rest;
        if arrived >= frames || tokio::time::Instant::now() >= deadline {
            break;
        }
    }

    assert_eq!(
        arrived, frames,
        "every pad chunk must arrive - {arrived} of {frames} did"
    );
}
