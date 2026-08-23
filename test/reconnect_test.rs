//! `crate::client::reconnect` - keeping the control connection up
//! (`docs/PROTOCOL.md` §4.2).
//!
//! The backoff schedule, the countdown, and the header states are pure and
//! tested directly. The supervisor itself is tested against a real server
//! over loopback, stopped and restarted underneath a live session - the
//! only way to prove the thing this module exists for: that a client whose
//! server went away comes back, and comes back *joined*.

use std::time::{Duration, Instant};

use aloo::client::connect::{ConnectRequest, MyKeySelection, ServerKeySelection};
use aloo::client::reconnect::{
    Backoff, RECONNECT_FIRST_DELAY, RECONNECT_MAX_DELAY, SERVER_DOWN_AFTER_ATTEMPTS, ServerEvent,
    ServerLinkState, ServerSink, delay_after, seconds_left,
};
use aloo::control::ControlSink;
use aloo::proto::{ChannelKind, ClientMessage, ServerMessage};
use aloo::server::AuthConfig;
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------
// The backoff schedule
// ---------------------------------------------------------------------

/// @requirement AC-222
#[test]
fn the_first_attempt_is_immediate_and_every_failure_widens_the_wait() {
    assert_eq!(
        delay_after(0),
        Duration::ZERO,
        "the attempt made the moment the loss is noticed must not wait"
    );
    assert_eq!(delay_after(1), RECONNECT_FIRST_DELAY);
    assert_eq!(delay_after(2), RECONNECT_FIRST_DELAY * 2);
    assert_eq!(delay_after(3), RECONNECT_FIRST_DELAY * 4);
}

/// @requirement AC-222
#[test]
fn the_wait_never_grows_past_the_ceiling() {
    for failed in 4..64u32 {
        assert!(
            delay_after(failed) <= RECONNECT_MAX_DELAY,
            "attempt {failed} waits longer than the ceiling"
        );
    }
    // Including the far end, where a naive shift would wrap back around to
    // a tight retry loop.
    assert_eq!(delay_after(u32::MAX), RECONNECT_MAX_DELAY);
}

/// @requirement TB-226
#[test]
fn a_backoff_can_be_driven_faster_than_the_default_without_changing_its_shape() {
    let fast = Backoff {
        first: Duration::from_millis(10),
        max: Duration::from_millis(40),
    };
    assert_eq!(fast.delay_after(0), Duration::ZERO);
    assert_eq!(fast.delay_after(1), Duration::from_millis(10));
    assert_eq!(fast.delay_after(2), Duration::from_millis(20));
    assert_eq!(fast.delay_after(3), Duration::from_millis(40));
    assert_eq!(fast.delay_after(9), Duration::from_millis(40));
    assert_eq!(Backoff::default().delay_after(1), delay_after(1));
}

// ---------------------------------------------------------------------
// The countdown
// ---------------------------------------------------------------------

/// @requirement AC-223
#[test]
fn the_countdown_rounds_up_so_it_never_sits_on_a_zero_that_has_not_happened() {
    let now = Instant::now();
    assert_eq!(seconds_left(now, now + Duration::from_secs(5)), 5);
    assert_eq!(seconds_left(now, now + Duration::from_millis(4_001)), 5);
    assert_eq!(seconds_left(now, now + Duration::from_millis(1)), 1);
}

/// @requirement AC-223
#[test]
fn the_countdown_stops_at_zero_rather_than_going_backwards() {
    let now = Instant::now();
    assert_eq!(seconds_left(now, now), 0);
    assert_eq!(seconds_left(now, now - Duration::from_secs(30)), 0);
}

// ---------------------------------------------------------------------
// What the header says
// ---------------------------------------------------------------------

/// @requirement AC-223
#[test]
fn a_reconnect_reads_as_a_hiccup_until_enough_attempts_have_failed() {
    for failed in 0..SERVER_DOWN_AFTER_ATTEMPTS {
        assert_eq!(
            ServerLinkState::waiting(failed, 5),
            ServerLinkState::RetryingIn { seconds_left: 5 },
            "{failed} failures is not yet a server that is down"
        );
    }
    assert_eq!(
        ServerLinkState::waiting(SERVER_DOWN_AFTER_ATTEMPTS, 20),
        ServerLinkState::Down { seconds_left: 20 },
    );
    assert_eq!(
        ServerLinkState::waiting(SERVER_DOWN_AFTER_ATTEMPTS + 40, 30),
        ServerLinkState::Down { seconds_left: 30 },
    );
}

/// @requirement AC-223
#[test]
fn every_state_says_exactly_what_is_happening() {
    assert_eq!(
        ServerLinkState::Connected.label(false),
        "\u{1F7E2} Connected to server!"
    );
    assert_eq!(
        ServerLinkState::Reconnecting.label(false),
        "\u{1F534} Reconnecting..."
    );
    assert_eq!(
        ServerLinkState::RetryingIn { seconds_left: 5 }.label(false),
        "\u{1F534} Reconnecting in 5s..."
    );
    assert_eq!(
        ServerLinkState::Down { seconds_left: 12 }.label(false),
        "\u{1F534} Server down (reconnecting in 12 sec...)"
    );
    assert_eq!(
        ServerLinkState::NoServer.label(false),
        "\u{26AA} No server mode"
    );
}

/// @requirement AC-224
#[test]
fn a_punch_in_flight_is_only_worth_naming_when_there_is_no_server() {
    assert_eq!(
        ServerLinkState::NoServer.label(true),
        "\u{26AA} No server mode (punching)"
    );
    // With a server, punching is the ordinary case and the sidebar already
    // colours the peer it belongs to - saying it here too would be noise
    // on top of a state the user does need to read carefully.
    for state in [
        ServerLinkState::Connected,
        ServerLinkState::Reconnecting,
        ServerLinkState::RetryingIn { seconds_left: 5 },
        ServerLinkState::Down { seconds_left: 5 },
    ] {
        assert_eq!(
            state.label(true),
            state.label(false),
            "{state:?} must read the same whether or not a punch is in flight"
        );
    }
}

// ---------------------------------------------------------------------
// The sink whose socket gets swapped
// ---------------------------------------------------------------------

/// A `ServerSink` over a real, live loopback connection, plus the listener
/// side kept alive so nothing is torn down behind it.
async fn live_sink() -> (
    ServerSink,
    tokio::sync::mpsc::UnboundedReceiver<()>,
    TcpStream,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server_side, _) = listener.accept().await.unwrap();
    let (_, wr) = tokio::io::split(client);
    let (sink, lost_rx) = ServerSink::new(aloo::control::ControlWriter::new(wr));
    (sink, lost_rx, server_side)
}

/// @requirement TB-227
#[tokio::test]
async fn a_sink_with_no_connection_installed_discards_instead_of_failing() {
    let (mut sink, mut lost_rx, _peer) = live_sink().await;
    assert!(sink.is_connected().await);

    sink.clear().await;
    assert!(!sink.is_connected().await);

    // Discarded, not an error: every call site propagates with `?`, and
    // ending the session is the one thing this module exists to prevent.
    sink.send_control(&ClientMessage::Heartbeat)
        .await
        .expect("a send with the server away must not fail the session");
    assert!(
        lost_rx.try_recv().is_err(),
        "a send into an already-cleared sink is not itself a loss"
    );
}

/// @requirement TB-227
#[tokio::test]
async fn installing_a_connection_makes_the_sink_usable_again() {
    let (mut sink, _lost_rx, _peer) = live_sink().await;
    sink.clear().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (_kept_alive, _) = listener.accept().await.unwrap();
    let (_, wr) = tokio::io::split(client);
    sink.install(aloo::control::ControlWriter::new(wr)).await;

    assert!(sink.is_connected().await);
    sink.send_control(&ClientMessage::Heartbeat).await.unwrap();
}

/// The other way a dead connection is noticed: with nothing arriving there
/// is nothing for the read half to fail on, and the heartbeat is what
/// finds out (§4.1).
/// @requirement TB-228
#[tokio::test]
async fn a_write_that_fails_drops_the_connection_and_reports_the_loss() {
    let (mut sink, mut lost_rx, peer) = live_sink().await;
    // Dropped without a shutdown: the next write is answered with a reset,
    // exactly as a peer that has gone away answers one.
    drop(peer);

    // The first write after the peer disappears usually succeeds - it only
    // reaches the local buffer, and the reset comes back afterwards - so
    // this writes until it is noticed rather than assuming which one fails.
    for _ in 0..200 {
        sink.send_control(&ClientMessage::Heartbeat)
            .await
            .expect("a failed write must never surface as a session error");
        if !sink.is_connected().await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert!(
        !sink.is_connected().await,
        "a broken socket must be dropped rather than written to forever"
    );
    assert!(
        lost_rx.try_recv().is_ok(),
        "the supervisor must be woken to start reconnecting"
    );
}

// ---------------------------------------------------------------------
// The supervisor, against a real server
// ---------------------------------------------------------------------

/// A server that can be stopped. Everything it spawns - the accept loop
/// and every live connection - belongs to this runtime, so dropping it is
/// what a server going away actually looks like to a client: connections
/// cut, port closed.
struct StoppableServer {
    addr: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl StoppableServer {
    /// `port == 0` picks a free one; passing a previous instance's port is
    /// how "the same server came back" is staged.
    fn start(port: u16) -> Self {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
                ready_tx.send(listener.local_addr().unwrap()).unwrap();
                tokio::select! {
                    _ = aloo::server::serve(listener, AuthConfig::None) => {}
                    _ = stop_rx => {}
                }
            });
            // Dropping the runtime here is what kills the connections it
            // was still serving.
        });
        let addr = ready_rx.recv().unwrap();
        Self {
            addr,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for StoppableServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A keybundle written once per test process, at a small modulus - these
/// tests are about the reconnect handshake, never about key strength, and
/// a real RSA-4096 pair takes seconds (see `world.rs`'s `SCENARIO_KEY_BITS`
/// for the same trade). Written up front rather than left to
/// `ensure_bundle_at` so nothing here pays full keygen.
fn scenario_keybundle(nickname: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "aloo-reconnect-test-keys-{}-{nickname}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file_pub = dir.join("id.pub");
    let file_priv = dir.join("id.priv");
    if !file_pub.exists() {
        let (public, private) =
            aloo::crypto::pq::generate_bundle_with_bits(1024).expect("scenario keygen");
        aloo::crypto::pq::save_private_bundle(&private, &file_priv).expect("save private");
        aloo::crypto::pq::save_public_bundle(&public, &file_pub).expect("save public");
    }
    (file_pub, file_priv)
}

fn request_for(addr: std::net::SocketAddr, nickname: &str) -> ConnectRequest {
    // One fixed keybundle per nickname, on purpose: a reconnect must come
    // back as the *same* person, and re-resolving from these same two
    // paths is what proves the identity did not quietly change.
    let (file_pub, file_priv) = scenario_keybundle(nickname);
    ConnectRequest {
        host: addr.ip().to_string(),
        port: addr.port(),
        nickname: nickname.to_string(),
        server_key: ServerKeySelection::None,
        my_key: MyKeySelection {
            file_pub,
            file_priv,
        },
        id_store_path: std::env::temp_dir().join(format!(
            "aloo-reconnect-test-idstore-{}-{}",
            std::process::id(),
            nickname
        )),
    }
}

/// Waits for the next event, failing the test rather than hanging forever.
async fn next_event(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ServerEvent>) -> ServerEvent {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("timed out waiting for a server event")
        .expect("the supervisor must not stop while the session holds its receiver")
}

/// The whole point, end to end: the server goes away, the client keeps
/// asking, and when it comes back the client is on it again - as a
/// different `UserId`, because that is what a new connection is.
/// @requirement AC-225
#[tokio::test]
async fn a_session_whose_server_disappears_gets_itself_back_on() {
    let mut server = StoppableServer::start(0);
    let addr = server.addr;
    let request = request_for(addr, "alice");

    let (mut events, _sink, first_id, _identity, _addr) =
        aloo::client::connect::connect_with_reconnect(&request)
            .await
            .expect("the first connection is an ordinary one");

    server.stop();

    // Told once that it is gone - after whatever the connection had
    // already sent (the `ChannelList` every registration is answered
    // with), which is itself the ordering guarantee: one stream, so a
    // message can never arrive after the loss that ended its connection.
    loop {
        match next_event(&mut events).await {
            ServerEvent::Message(_) => {}
            ServerEvent::Lost => break,
            other => panic!("expected the loss to be reported, got {other:?}"),
        }
    }

    // ...then asked for, repeatedly, until it answers. The server comes
    // back on the very port it left, which is what a restarted one does.
    let mut waited = 0;
    let mut restarted: Option<StoppableServer> = None;
    let second_id = loop {
        match next_event(&mut events).await {
            ServerEvent::Attempting => {}
            ServerEvent::Waiting {
                failed_attempts, ..
            } => {
                waited += 1;
                assert_eq!(failed_attempts, waited, "attempts must be counted in order");
                if restarted.is_none() {
                    restarted = Some(StoppableServer::start(addr.port()));
                }
            }
            ServerEvent::Reconnected { you } => break you,
            other => panic!("unexpected event while reconnecting: {other:?}"),
        }
    };

    assert!(
        waited >= 1,
        "the server was down: at least one attempt must have failed"
    );
    // The id comes from the server that answered, and is reported to the
    // session so it can stop calling itself by an id the previous
    // connection owned. It is not asserted to *differ* here: this test
    // restarts the server, whose registry starts counting again - the
    // "never reused" guarantee (TB-020) is one server's, for its own
    // lifetime.
    let _ = (first_id, second_id);
    drop(restarted);
}

/// A nickname the server still holds (§5.4) comes back as an ordinary
/// failure, which is the whole reason the reconnect loop treats *every*
/// error the same way: the connection holding it is usually this client's
/// own dead one, freed within `HEARTBEAT_TIMEOUT`, so the next attempt
/// gets in. Giving up there would turn "your network blinked" into "you
/// are locked out of your own nickname".
/// @requirement AC-226
#[tokio::test]
async fn a_taken_nickname_is_an_ordinary_retryable_failure() {
    let server = StoppableServer::start(0);
    let request = request_for(server.addr, "alice");

    let (_events, _sink, _you, _identity, _addr) =
        aloo::client::connect::connect_with_reconnect(&request)
            .await
            .expect("first connection");

    // Exactly what a reconnect racing the old registration's cleanup runs
    // into. It is an `Err` like a refused connection is an `Err` - nothing
    // in the loop distinguishes them, which is the point.
    let again = aloo::client::connect::connect_with_reconnect(&request).await;
    assert!(
        again.is_err(),
        "a nickname already held must be refused, not silently duplicated"
    );
}

/// The reported bug, end to end.
///
/// A daemon session is connected and in a channel. Its connection dies
/// without closing - here by being reaped for missed heartbeats (§4.1),
/// which is exactly what a pulled network cable ends as - and the server
/// drops it from every member list. Someone who connects *afterwards*
/// must still see it: which is only true if it noticed, reconnected, and
/// re-joined on its own.
/// @requirement AC-227
#[tokio::test]
async fn a_session_reaped_by_the_server_reappears_in_a_later_arrival_s_member_list() {
    use aloo::client::daemon::{DaemonChannel, DaemonPlan};
    use aloo::client::tui::surface::Surface;
    use aloo::control::ControlEndpoint;

    // Short enough to be waited out in a test; the real 30s is the same
    // mechanism, just slower (`server::serve_with_heartbeat_timeout`).
    let reap_after = Duration::from_millis(1_500);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = aloo::server::serve_with_heartbeat_timeout(listener, AuthConfig::None, reap_after)
            .await;
    });

    let request = request_for(addr, "alice");
    let (events, sink, first_id, identity, server_addr) =
        aloo::client::connect::connect_with_reconnect(&request)
            .await
            .expect("first connection");

    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    let id_store = aloo::client::idstore::IdStore::new_empty(request.id_store_path.clone());
    let plan = DaemonPlan::new(
        vec![DaemonChannel {
            name: "general".into(),
            password: None,
        }],
        None,
    );
    let session = tokio::spawn(async move {
        let mut surface = Surface::Detached;
        aloo::client::session::run_daemon_session(
            &mut surface,
            Some(events),
            sink,
            "alice".to_string(),
            first_id,
            identity,
            id_store,
            None,
            Some(server_addr),
            input_rx,
            plan,
        )
        .await
    });

    // The session never sends a heartbeat inside `reap_after` (the
    // interval is 10s), so the server treats it as gone, frees the
    // nickname, and closes the socket - the moment this is all about.
    tokio::time::sleep(reap_after + Duration::from_millis(700)).await;

    // Bob arrives now: everything he is told about the channel comes from
    // the server's *current* membership, which knows nothing of alice's
    // first connection.
    let mut bob = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
    handshake(&mut bob, "bob").await;
    join(&mut bob, "general").await;

    let mut saw_alice = false;
    for _ in 0..8 {
        let next = tokio::time::timeout(Duration::from_secs(2), bob.recv::<ServerMessage>()).await;
        let Ok(Ok(Some(msg))) = next else { break };
        if let ServerMessage::UserJoined { user, .. } = &msg
            && user.name == "alice"
        {
            saw_alice = true;
            break;
        }
    }
    assert!(
        saw_alice,
        "alice reconnected but was invisible to someone who arrived afterwards - \
         which is the whole bug: her messages still arrive over the direct links, \
         and she is in nobody's user list"
    );

    input_tx
        .send(aloo::client::session::SessionInput::Shutdown)
        .ok();
    let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
}

async fn handshake(
    stream: &mut aloo::control::ControlEndpoint<TcpStream>,
    nickname: &str,
) -> aloo::proto::UserId {
    let hello: ServerMessage = stream.recv().await.unwrap().unwrap();
    let ServerMessage::Hello { control, .. } = hello else {
        panic!("expected Hello");
    };
    let (accept, keys) = aloo::control::accept_offer(&control).unwrap();
    stream
        .send(&ClientMessage::SecureChannel(accept))
        .await
        .unwrap();
    stream.enable(keys);
    stream
        .send(&ClientMessage::Auth(aloo::proto::AuthResponse::None))
        .await
        .unwrap();
    let _auth: ServerMessage = stream.recv().await.unwrap().unwrap();
    stream
        .send(&ClientMessage::Identify {
            display_name: nickname.to_string(),
            public_key_der: vec![1, 2, 3],
            key_mode: aloo::proto::KeyMode::PqHybrid,
        })
        .await
        .unwrap();
    let identify: ServerMessage = stream.recv().await.unwrap().unwrap();
    let ServerMessage::IdentifyResult { you: Some(you), .. } = identify else {
        panic!("expected a successful IdentifyResult, got {identify:?}");
    };
    let _channels: ServerMessage = stream.recv().await.unwrap().unwrap();
    you
}

async fn join(stream: &mut aloo::control::ControlEndpoint<TcpStream>, channel: &str) {
    stream
        .send(&ClientMessage::JoinChannel {
            name: channel.to_string(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();
}
