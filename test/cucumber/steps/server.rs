//! Server-side steps: authentication, nicknames, channel membership and
//! message relay (US-002, US-003, US-004, US-005, US-006, US-007).
//!
//! Scenarios that describe what a *user* observes drive a real server over a
//! loopback TCP socket, handshake and all - the same path the shipped client
//! takes. Scenarios about routing rules the user never sees directly drive
//! `Registry` in-process, which is where those rules actually live.

use std::net::{IpAddr, Ipv4Addr};

use cucumber::{given, then, when};
use aloo::control::ControlEndpoint;
use tokio::net::{TcpListener, TcpStream};

use aloo::crypto;
use aloo::client::p2p::{P2pEvent, PeerLinkManager};
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{
    AuthKind, AuthResponse, ChannelKind, ClientMessage, Content, Envelope, KeyMode, ServerMessage,
    UserId,
};
use aloo::server::{AuthConfig, Registry, serve_with_rendezvous};

use crate::world::{AlooWorld, ClientState, keypair_for};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

async fn spawn_server(auth: AuthConfig) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
    tokio::spawn(async move {
        let _ = serve_with_rendezvous(listener, udp, auth).await;
    });
    addr
}

/// Binds `who`'s direct-link transport the first time it's needed - a
/// no-op if it already has one.
async fn bind_peer_link(w: &mut AlooWorld, who: &str) {
    if w.client_mut(who).peer_link.is_some() {
        return;
    }
    let server_addr = w.addr.expect("no server running");
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel::<P2pEvent>();
    let (peer_link, socket) =
        PeerLinkManager::bind("127.0.0.1:0".parse().unwrap(), Some(server_addr), events_tx)
            .await
            .expect("failed to bind direct-link socket");
    let (raw_tx, raw_rx) = tokio::sync::mpsc::unbounded_channel();
    aloo::client::p2p::spawn_receive_loop(socket, Some(server_addr), raw_tx);
    let client = w.client_mut(who);
    client.peer_link = Some(peer_link);
    client.p2p_raw_rx = Some(raw_rx);
    client.p2p_events_rx = Some(events_rx);
}

/// Runs the full server-assisted candidate exchange and loopback punch
/// handshake between `a` and `b` (mirrors `test/p2p_test.rs`), leaving both
/// with an `Active` direct link - a no-op if one already exists. Scenarios
/// call this once before their first send between two people; every step
/// that sends content over the direct link assumes it's already been
/// called (via the `{word} and {word} are both in the channel` / a direct
/// first-send Given/When step).
async fn ensure_peer_link(w: &mut AlooWorld, a: &str, b: &str) {
    let (a_id, b_id) = (w.id_of(a), w.id_of(b));
    bind_peer_link(w, a).await;
    bind_peer_link(w, b).await;
    if w.client_mut(a).peer_link.as_ref().unwrap().is_active(b_id) {
        return;
    }

    // Both clients' streams/peer_links are borrowed at once below, so pull
    // them out of the map rather than fighting the borrow checker with two
    // `client_mut` calls.
    let mut ca = w.clients.remove(a).expect("no such client");
    let mut cb = w.clients.remove(b).expect("no such client");

    let a_stream = ca.stream.as_mut().expect("a has no socket");
    ca.peer_link
        .as_mut()
        .unwrap()
        .ensure_link(a_stream, b_id)
        .await;
    let ServerMessage::PeerCandidates {
        from,
        candidates,
        link_nonce,
    } = cb.stream.as_mut().unwrap().recv()
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("b should receive a's PeerCandidates");
    };
    assert_eq!(from, a_id);
    let b_stream = cb.stream.as_mut().unwrap();
    cb.peer_link
        .as_mut()
        .unwrap()
        .on_peer_candidates(b_stream, a_id, candidates, link_nonce)
        .await;

    let ServerMessage::PeerCandidates {
        from,
        candidates,
        link_nonce,
    } = ca.stream.as_mut().unwrap().recv()
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("a should receive b's PeerCandidates reply");
    };
    assert_eq!(from, b_id);
    let a_stream = ca.stream.as_mut().unwrap();
    ca.peer_link
        .as_mut()
        .unwrap()
        .on_peer_candidates(a_stream, b_id, candidates, link_nonce)
        .await;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    while !(ca.peer_link.as_ref().unwrap().is_active(b_id)
        && cb.peer_link.as_ref().unwrap().is_active(a_id))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "loopback punch did not complete in time"
        );
        tokio::select! {
            Some((addr, dgram)) = ca.p2p_raw_rx.as_mut().unwrap().recv() => ca.peer_link.as_mut().unwrap().on_inbound(addr, dgram),
            Some((addr, dgram)) = cb.p2p_raw_rx.as_mut().unwrap().recv() => cb.peer_link.as_mut().unwrap().on_inbound(addr, dgram),
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }
    }

    w.clients.insert(a.to_string(), ca);
    w.clients.insert(b.to_string(), cb);
}

/// Drains `who`'s direct-link datagrams until its event channel yields one,
/// or `timeout` elapses - the direct-transport counterpart of
/// `expect_message` below.
async fn expect_p2p_event(w: &mut AlooWorld, who: &str, timeout: std::time::Duration) -> P2pEvent {
    let client = w.client_mut(who);
    let peer_link = client
        .peer_link
        .as_mut()
        .expect("no direct link bound for this client");
    let raw_rx = client.p2p_raw_rx.as_mut().unwrap();
    let events_rx = client.p2p_events_rx.as_mut().unwrap();
    tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                Some((addr, dgram)) = raw_rx.recv() => peer_link.on_inbound(addr, dgram),
                Some(event) = events_rx.recv() => {
                    // Link-state bookkeeping (§7.1's continuous
                    // establishment) is not what any scenario using this
                    // helper is waiting for - they want the content event.
                    if matches!(
                        event,
                        P2pEvent::LinkStatusChanged { .. } | P2pEvent::Signal { .. }
                    ) {
                        continue;
                    }
                    return event;
                }
            }
        }
    })
    .await
    .expect("timed out waiting for a direct-link event")
}

/// Runs the full Hello/Auth/Identify handshake and returns the assigned id.
/// Asserts the documented ordering as it goes: `IdentifyResult` then
/// `ChannelList`, back to back, as the first two messages after a successful
/// `Identify`.
async fn handshake(stream: &mut ControlEndpoint<TcpStream>, name: &str, key_mode: KeyMode) -> UserId {
    let (auth, challenge) = stream
        .client_handshake(None)
        .await
        .unwrap()
        .expect("server closed during handshake");
    assert_eq!(
        (auth, challenge),
        (AuthKind::None, None),
        "an open server should advertise no auth and no challenge"
    );

    stream.send(&ClientMessage::Auth(AuthResponse::None))
        .await
        .unwrap();
    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(result, ServerMessage::AuthResult { ok: true, .. }),
        "auth should succeed"
    );

    stream.send(&ClientMessage::Identify {
            display_name: name.into(),
            public_key_der: vec![],
            key_mode,
        },
    )
    .await
    .unwrap();

    let identify: ServerMessage = stream.recv().await.unwrap().unwrap();
    let ServerMessage::IdentifyResult {
        ok: true,
        you: Some(you),
        ..
    } = identify
    else {
        panic!("expected a successful IdentifyResult, got {identify:?}");
    };
    let list: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(list, ServerMessage::ChannelList(_)),
        "ChannelList must follow IdentifyResult immediately, got {list:?}"
    );
    you
}

// ---------------------------------------------------------------------
// Given - servers
// ---------------------------------------------------------------------

#[given("a server that anyone may connect to")]
async fn server_open(w: &mut AlooWorld) {
    w.addr = Some(spawn_server(AuthConfig::None).await);
}

#[given(expr = "a server that requires the password {string}")]
async fn server_password(w: &mut AlooWorld, password: String) {
    w.addr = Some(spawn_server(AuthConfig::Password(password)).await);
}

#[given("a running server registry")]
async fn registry_fresh(w: &mut AlooWorld) {
    w.registry = Some(Registry::new());
}

/// The handle used in the scenario doubles as the nickname, so `alice` in a
/// step is the same person the server knows as "alice". Also usable as a
/// `When`: the OTP mail scenarios connect the recipient mid-scenario,
/// after mail for them is already waiting.
#[given(expr = "{word} has connected")]
#[when(expr = "{word} has connected")]
async fn client_connects(w: &mut AlooWorld, who: String) {
    let addr = w.addr.expect("no server running");
    let mut stream = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
    let id = handshake(&mut stream, &who, KeyMode::Password).await;
    w.ids.insert(who.clone(), id);
    w.clients.insert(
        who,
        ClientState {
            stream: Some(stream),
            received: Vec::new(),
            ..Default::default()
        },
    );
}

#[given(expr = "{word} and {word} are both in the channel {string}")]
async fn both_in_channel(w: &mut AlooWorld, a: String, b: String, channel: String) {
    join_channel(w, &a, &channel).await;
    // a's own Joined confirmation
    let _ = expect_message(w, &a).await;
    // `channel` is always newly created here (a fresh server per scenario
    // only ever seeds the-hall) and b is already connected, so a creating
    // it broadcasts ChannelCreated to b (AC-108) before b ever joins it.
    let _ = expect_message(w, &b).await;
    join_channel(w, &b, &channel).await;
    // a learns b joined; b gets the snapshot of a, then its own Joined
    let _ = expect_message(w, &a).await;
    let _ = expect_message(w, &b).await;
    let _ = expect_message(w, &b).await;
}

#[given(expr = "{word} and {word} are registered users")]
async fn two_registered(w: &mut AlooWorld, a: String, b: String) {
    let reg = w.registry_mut();
    let ida = reg.register(a.clone(), vec![9], KeyMode::Password);
    let idb = reg.register(b.clone(), vec![8], KeyMode::Password);
    w.ids.insert(a, ida);
    w.ids.insert(b, idb);
}

#[given(expr = "{word} is a registered user who never joins anything")]
async fn one_registered_outsider(w: &mut AlooWorld, who: String) {
    let reg = w.registry_mut();
    let id = reg.register(who.clone(), vec![7], KeyMode::Password);
    w.ids.insert(who, id);
}

#[given(expr = "{word} and {word} have both joined {string}")]
async fn both_joined_registry(w: &mut AlooWorld, a: String, b: String, channel: String) {
    let (ida, idb) = (w.id_of(&a), w.id_of(&b));
    let reg = w.registry_mut();
    reg.join_channel(ida, &channel, ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(idb, &channel, ChannelKind::Public, None, TEST_IP)
        .unwrap();
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

async fn join_channel(w: &mut AlooWorld, who: &str, channel: &str) {
    let client = w.client_mut(who);
    let stream = client.stream.as_mut().expect("client has no socket");
    stream.send(&ClientMessage::JoinChannel {
            name: channel.into(),
            kind: ChannelKind::Public,
            password: None,
        },
    )
    .await
    .unwrap();
}

async fn expect_message(w: &mut AlooWorld, who: &str) -> ServerMessage {
    let client = w.client_mut(who);
    let stream = client.stream.as_mut().expect("client has no socket");
    let msg: ServerMessage =
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.recv())
            .await
            .expect("timed out waiting for a server message")
            .unwrap()
            .expect("connection closed while a message was expected");
    client.received.push(msg.clone());
    msg
}

#[when(expr = "{word} joins the channel {string}")]
async fn when_joins(w: &mut AlooWorld, who: String, channel: String) {
    join_channel(w, &who, &channel).await;
}

#[when(expr = "{word} sends {string} to {word} in {string}")]
async fn send_channel_text(
    w: &mut AlooWorld,
    from: String,
    body: String,
    to: String,
    channel: String,
) {
    ensure_peer_link(w, &from, &to).await;
    let to_id = w.id_of(&to);
    let envelope = Envelope {
        content: Content::Text,
        blocks: vec![body.into_bytes()],
    };
    w.envelope = Some(envelope.clone());
    w.client_mut(&from)
        .peer_link
        .as_mut()
        .unwrap()
        .send_reliable_or_queue(
            to_id,
            P2pPayload::Envelope {
                channel: Some(channel),
                envelope,
            },
        );
}

#[when(expr = "{word} sends the private message {string} to {word}")]
async fn send_direct_text(w: &mut AlooWorld, from: String, body: String, to: String) {
    ensure_peer_link(w, &from, &to).await;
    let to_id = w.id_of(&to);
    let envelope = Envelope {
        content: Content::Text,
        blocks: vec![body.into_bytes()],
    };
    w.envelope = Some(envelope.clone());
    w.client_mut(&from)
        .peer_link
        .as_mut()
        .unwrap()
        .send_reliable_or_queue(
            to_id,
            P2pPayload::Envelope {
                channel: None,
                envelope,
            },
        );
}

#[when(expr = "{word} streams a voice message to {string} addressed to {word}")]
async fn stream_voice(w: &mut AlooWorld, from: String, channel: String, to: String) {
    ensure_peer_link(w, &from, &to).await;
    let to_id = w.id_of(&to);
    let peer_link = w.client_mut(&from).peer_link.as_mut().unwrap();
    peer_link.send_reliable_or_queue(
        to_id,
        P2pPayload::StreamStart {
            channel: Some(channel),
            stream_id: 42,
        },
    );
    peer_link.send_unreliable_voice(to_id, 42, 0, vec![vec![1, 2, 3]]);
    peer_link.send_reliable_or_queue(
        to_id,
        P2pPayload::StreamEnd {
            stream_id: 42,
            duration_ms: 100,
        },
    );
}

#[when(expr = "someone else tries to connect as {string}")]
async fn duplicate_nickname(w: &mut AlooWorld, name: String) {
    let addr = w.addr.expect("no server running");
    let mut stream = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());

    let (auth_kind, _) = stream
        .client_handshake(None)
        .await
        .unwrap()
        .expect("server closed during handshake");
    assert_eq!(auth_kind, AuthKind::None);
    stream.send(&ClientMessage::Auth(AuthResponse::None))
        .await
        .unwrap();
    let auth: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(auth, ServerMessage::AuthResult { ok: true, .. }),
        "auth itself should still pass"
    );

    stream.send(&ClientMessage::Identify {
            display_name: name,
            public_key_der: vec![],
            key_mode: KeyMode::Password,
        },
    )
    .await
    .unwrap();

    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    w.clients.insert(
        "impostor".into(),
        ClientState {
            stream: Some(stream),
            received: vec![result],
            ..Default::default()
        },
    );
}

#[when(expr = "{word} disconnects entirely")]
async fn disconnects(w: &mut AlooWorld, who: String) {
    w.clients.remove(&who);
    // Give the server a moment to notice the closed socket and unregister.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

#[when(expr = "a client offers the password {string}")]
async fn offer_password(w: &mut AlooWorld, password: String) {
    let addr = w.addr.expect("no server running");
    let mut stream = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
    let (auth, challenge) = stream
        .client_handshake(None)
        .await
        .unwrap()
        .expect("server closed during handshake");
    assert_eq!(
        (auth, challenge),
        (AuthKind::Password, None),
        "a password-protected server should advertise Password and issue no challenge"
    );
    stream.send(&ClientMessage::Auth(AuthResponse::Password(password)),
    )
    .await
    .unwrap();
    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    w.clients.insert(
        "candidate".into(),
        ClientState {
            stream: Some(stream),
            received: vec![result],
            ..Default::default()
        },
    );
}

#[when(expr = "{word} leaves {string}")]
async fn registry_leave(w: &mut AlooWorld, who: String, channel: String) {
    let id = w.id_of(&who);
    let out = w.registry_mut().leave_channel(id, &channel);
    w.emitted = out;
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "{word} receives the message {string} from {string} in {string}")]
async fn receives_channel_message(
    w: &mut AlooWorld,
    who: String,
    body: String,
    from_name: String,
    channel: String,
) {
    let from_id = w.id_of(&from_name);
    let expected = w.envelope.clone().expect("nothing was sent");
    let event = expect_p2p_event(w, &who, std::time::Duration::from_secs(5)).await;
    match event {
        P2pEvent::Message {
            channel: got_channel,
            from,
            envelope,
        } => {
            assert_eq!(
                got_channel.as_deref(),
                Some(channel.as_str()),
                "delivered into the wrong channel"
            );
            assert_eq!(from, from_id, "attributed to the wrong sender id");
            assert_eq!(envelope, expected, "the message must arrive byte for byte");
            assert_eq!(
                envelope.blocks,
                vec![body.into_bytes()],
                "the delivered ciphertext must be exactly what the sender addressed"
            );
        }
        _ => panic!("expected a direct-link Message event"),
    }
}

#[then(expr = "{word} receives the private message {string} from {string}")]
async fn receives_direct_message(w: &mut AlooWorld, who: String, body: String, from_name: String) {
    let from_id = w.id_of(&from_name);
    let expected = w.envelope.clone().expect("nothing was sent");
    let event = expect_p2p_event(w, &who, std::time::Duration::from_secs(5)).await;
    match event {
        P2pEvent::Message {
            channel,
            from,
            envelope,
        } => {
            assert_eq!(channel, None, "a DM must not carry a channel");
            assert_eq!(from, from_id);
            assert_eq!(envelope, expected, "the message must arrive unchanged");
            assert_eq!(envelope.blocks, vec![body.into_bytes()]);
        }
        _ => panic!("expected a direct-link Message event"),
    }
}

/// Consumes the joiner's own `Joined` confirmation. Scenarios need this to
/// order two clients' joins deterministically: both writes are fire-and-forget,
/// so without waiting for the first join to be acknowledged the server may
/// legitimately process the second one first.
#[then(expr = "{word} is confirmed as joined")]
async fn join_confirmed(w: &mut AlooWorld, who: String) {
    let msg = expect_message(w, &who).await;
    assert!(
        matches!(msg, ServerMessage::Joined { .. }),
        "expected a Joined confirmation, got {msg:?}"
    );
}

#[then(expr = "{word} is told that {string} joined")]
async fn told_that_joined(w: &mut AlooWorld, who: String, joiner: String) {
    let joiner_id = w.id_of(&joiner);
    let msg = expect_message(w, &who).await;
    match msg {
        ServerMessage::UserJoined { user, .. } => {
            assert_eq!(user.id, joiner_id, "should be told about the right user");
            assert_eq!(
                user.name, joiner,
                "the notification carries the joiner's nickname"
            );
        }
        other => panic!("expected a UserJoined, got {other:?}"),
    }
}

#[then(expr = "{word} learns about {string} and then that the join succeeded")]
async fn learns_then_joined(w: &mut AlooWorld, who: String, other: String) {
    let other_id = w.id_of(&other);
    let snapshot = expect_message(w, &who).await;
    match snapshot {
        ServerMessage::UserJoined { user, .. } => {
            assert_eq!(
                user.id, other_id,
                "the joiner should learn about the existing member"
            );
        }
        got => panic!("expected the membership snapshot first, got {got:?}"),
    }
    let confirmation = expect_message(w, &who).await;
    assert!(
        matches!(confirmation, ServerMessage::Joined { .. }),
        "the Joined confirmation must come last, after every UserJoined, got {confirmation:?}"
    );
}

#[then(expr = "{word} receives the voice message start, chunk and end in that order")]
async fn receives_stream_in_order(w: &mut AlooWorld, who: String) {
    let timeout = std::time::Duration::from_secs(5);
    let start = expect_p2p_event(w, &who, timeout).await;
    assert!(
        matches!(&start, P2pEvent::StreamStart { stream_id: 42, .. }),
        "expected the stream to open"
    );

    let chunk = expect_p2p_event(w, &who, timeout).await;
    match chunk {
        P2pEvent::StreamChunk {
            stream_id,
            seq,
            blocks,
            ..
        } => {
            assert_eq!(stream_id, 42, "chunk belongs to the stream that opened");
            assert_eq!(seq, 0);
            assert_eq!(
                blocks,
                vec![vec![1, 2, 3]],
                "the audio must arrive unchanged"
            );
        }
        _ => panic!("expected a stream chunk"),
    }

    let end = expect_p2p_event(w, &who, timeout).await;
    assert!(
        matches!(end, P2pEvent::StreamEnd { stream_id: 42, .. }),
        "expected the stream to close"
    );
}

#[then("the connection is accepted")]
async fn connection_accepted(w: &mut AlooWorld) {
    let client = w.clients.get("candidate").expect("nobody tried to connect");
    match client.received.first().expect("no auth result") {
        ServerMessage::AuthResult { ok: true, .. } => {}
        other => panic!("expected the connection to be accepted, got {other:?}"),
    }
}

#[then("the connection is refused")]
async fn connection_refused(w: &mut AlooWorld) {
    let client = w.clients.get("candidate").expect("nobody tried to connect");
    match client.received.first().expect("no auth result") {
        ServerMessage::AuthResult { ok: false, .. } => {}
        other => panic!("expected the connection to be refused, got {other:?}"),
    }
}

#[then(expr = "the nickname is refused, naming {string}")]
async fn nickname_refused(w: &mut AlooWorld, name: String) {
    let client = w
        .clients
        .get("impostor")
        .expect("nobody tried a duplicate nickname");
    match client.received.first().expect("no identify result") {
        ServerMessage::IdentifyResult {
            ok: false,
            you: None,
            reason: Some(reason),
        } => {
            assert!(
                reason.contains(&name),
                "the reason {reason:?} should name the taken nickname"
            );
        }
        other => panic!("expected a rejected IdentifyResult, got {other:?}"),
    }
}

#[then("that connection is then closed by the server")]
async fn connection_closed(w: &mut AlooWorld) {
    let client = w.client_mut("impostor");
    let stream = client.stream.as_mut().unwrap();
    let after: Option<ServerMessage> = stream.recv().await.unwrap();
    assert!(
        after.is_none(),
        "the server should close the connection after rejecting the nickname"
    );
}

#[then(expr = "{word} is completely unaffected and can still join {string}")]
async fn unaffected(w: &mut AlooWorld, who: String, channel: String) {
    join_channel(w, &who, &channel).await;
    let msg = expect_message(w, &who).await;
    assert!(
        matches!(msg, ServerMessage::Joined { .. }),
        "the original holder's session must carry on untouched, got {msg:?}"
    );
}

#[then(expr = "the nickname {string} can be claimed again")]
async fn nickname_reclaimable(w: &mut AlooWorld, name: String) {
    let addr = w.addr.expect("no server running");
    let mut stream = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
    // A rejection or a hang here fails the scenario through handshake's asserts.
    let id = handshake(&mut stream, &name, KeyMode::Password).await;
    w.ids.insert("reclaimer".into(), id);
    w.clients.insert(
        "reclaimer".into(),
        ClientState {
            stream: Some(stream),
            received: vec![],
            ..Default::default()
        },
    );
}

#[then(expr = "a brand new server offers exactly one public channel called {string}")]
async fn default_channel(w: &mut AlooWorld, name: String) {
    let list = w.registry_mut().channel_list();
    assert_eq!(
        list.len(),
        1,
        "a fresh server seeds exactly one channel, got {list:?}"
    );
    assert_eq!(list[0].name, name);
    assert_eq!(list[0].kind, ChannelKind::Public);
}

#[then(expr = "{word} joining the private channel {string} leaves it unlisted")]
async fn private_unlisted(w: &mut AlooWorld, who: String, channel: String) {
    let id = w.id_of(&who);
    w.registry_mut()
        .join_channel(id, &channel, ChannelKind::Private, None, TEST_IP)
        .unwrap();
    let list = w.registry_mut().channel_list();
    assert!(
        list.iter().all(|c| c.name != channel),
        "a private channel must never be advertised, got {list:?}"
    );
}

#[then(expr = "{string} is still listed")]
async fn still_listed(w: &mut AlooWorld, channel: String) {
    let list = w.registry_mut().channel_list();
    assert!(
        list.iter().any(|c| c.name == channel),
        "expected {channel:?} to still be listed, got {list:?}"
    );
}

#[then(expr = "{string} is no longer listed")]
async fn no_longer_listed(w: &mut AlooWorld, channel: String) {
    let list = w.registry_mut().channel_list();
    assert!(
        list.iter().all(|c| c.name != channel),
        "expected {channel:?} to have been unregistered, got {list:?}"
    );
}

#[then(expr = "{word} is told that {string} now exists")]
async fn told_channel_created(w: &mut AlooWorld, who: String, channel: String) {
    let msg = expect_message(w, &who).await;
    match msg {
        ServerMessage::ChannelCreated { channel: got } => {
            assert_eq!(got.name, channel);
            assert_eq!(got.kind, ChannelKind::Public);
        }
        other => panic!("expected ChannelCreated, got {other:?}"),
    }
}

#[then(expr = "{word} is told that {word} left {string}")]
async fn told_left(w: &mut AlooWorld, who: String, leaver: String, channel: String) {
    let (who_id, leaver_id) = (w.id_of(&who), w.id_of(&leaver));
    assert_eq!(
        w.emitted.len(),
        1,
        "only the remaining member should be notified: {:?}",
        w.emitted
    );
    let out = &w.emitted[0];
    assert_eq!(out.to, who_id);
    match &out.message {
        ServerMessage::UserLeft {
            channel: got,
            user_id,
        } => {
            assert_eq!(got, &channel);
            assert_eq!(*user_id, leaver_id);
        }
        other => panic!("leaving one channel must send UserLeft, not {other:?}"),
    }
}

#[then(expr = "{word} is still connected")]
async fn still_connected(w: &mut AlooWorld, who: String) {
    let id = w.id_of(&who);
    assert!(
        w.registry_mut().user_info(id).is_some(),
        "leaving a channel is not a disconnect - the user stays registered"
    );
}

#[then("an RSA-protected server accepts the real key holder and refuses an impostor")]
async fn rsa_auth(_w: &mut AlooWorld) {
    let server_kp = keypair_for("server");
    let impostor_kp = keypair_for("mallory");
    let cfg = AuthConfig::Rsa(Box::new(server_kp.private));
    assert_eq!(cfg.kind(), AuthKind::Rsa);

    let challenge = cfg
        .make_challenge()
        .expect("rsa auth must issue a challenge nonce");
    assert_eq!(
        challenge.len(),
        32,
        "the documented nonce is 32 random bytes"
    );

    let good = crypto::encrypt_chunked(&server_kp.public, &challenge).unwrap();
    assert!(
        cfg.verify(Some(&challenge), &AuthResponse::Rsa { blocks: good }),
        "the real key holder gets in"
    );

    let bad = crypto::encrypt_chunked(&impostor_kp.public, &challenge).unwrap();
    assert!(
        !cfg.verify(Some(&challenge), &AuthResponse::Rsa { blocks: bad }),
        "a nonce encrypted to somebody else's key must not authenticate"
    );

    // A response of the wrong shape is an authentication failure too.
    assert!(!cfg.verify(Some(&challenge), &AuthResponse::None));
    assert!(!cfg.verify(Some(&challenge), &AuthResponse::Password("whatever".into())));
}

#[then("an open server issues no challenge and accepts an empty credential")]
async fn open_server_auth(_w: &mut AlooWorld) {
    let cfg = AuthConfig::None;
    assert_eq!(cfg.kind(), AuthKind::None);
    assert!(
        cfg.make_challenge().is_none(),
        "no auth means no challenge to answer"
    );
    assert!(
        cfg.verify(None, &AuthResponse::None),
        "an empty credential is the right one here"
    );
    assert!(
        !cfg.verify(None, &AuthResponse::Password("x".into())),
        "a response of the wrong variant is still a failure"
    );
}
