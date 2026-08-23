//! Getting back onto the server, and what the header says while that is
//! happening (US-040, docs/PROTOCOL.md 4.2).

use std::time::Duration;

use cucumber::{given, then, when};
use ratatui::style::Color;
use tokio::net::{TcpListener, TcpStream};

use aloo::client::p2p::LinkStatus;
use aloo::client::reconnect::{RECONNECT_MAX_DELAY, ServerLinkState, delay_after};
use aloo::client::tui::channel::messages_start_col;
use aloo::proto::{ChannelKind, ClientMessage, ServerMessage, UserId};
use aloo::server::ServerOptions;
use aloo::server::users_registry::UsersRegistry;

use crate::steps::ui_common::id_for;
use crate::support::{find_text_start, header_row, ui_buffer, ui_rows_wide};
use crate::world::AlooWorld;

/// Wide enough that the server state and the selectors beside it both have
/// room - a narrow terminal is what one scenario here is specifically
/// about, and says so.
const WIDE: u16 = 160;

// ---------------------------------------------------------------------
// The backoff schedule (AC-222)
// ---------------------------------------------------------------------

#[then("the wait before the first attempt is no wait at all")]
async fn first_attempt_is_immediate(_w: &mut AlooWorld) {
    assert_eq!(
        delay_after(0),
        Duration::ZERO,
        "most losses are a socket dropping under a working network - waiting \
         out a backoff for those is five seconds of nothing, for nothing"
    );
}

#[then(expr = "the wait after {int} failed attempt(s) is {int} seconds")]
async fn wait_after(_w: &mut AlooWorld, failed: u32, seconds: u64) {
    assert_eq!(
        delay_after(failed),
        Duration::from_secs(seconds),
        "unexpected wait after {failed} failed attempt(s)"
    );
}

#[then(expr = "the wait never grows past {int} seconds, however many have failed")]
async fn wait_ceiling(_w: &mut AlooWorld, seconds: u64) {
    assert_eq!(RECONNECT_MAX_DELAY, Duration::from_secs(seconds));
    for failed in [4u32, 10, 100, u32::MAX] {
        assert!(
            delay_after(failed) <= RECONNECT_MAX_DELAY,
            "attempt {failed} waits longer than the ceiling"
        );
    }
}

// ---------------------------------------------------------------------
// What the header says (AC-223, AC-224)
// ---------------------------------------------------------------------

#[when("the server connection is lost")]
async fn connection_lost(w: &mut AlooWorld) {
    w.ui_mut().set_server_link(ServerLinkState::Reconnecting);
}

#[when(expr = "{int} attempt(s) has/have failed and the next is {int} seconds away")]
async fn waiting_after(w: &mut AlooWorld, failed: u32, seconds: u64) {
    w.ui_mut()
        .set_server_link(ServerLinkState::waiting(failed, seconds));
}

#[given("I am running with no server at all")]
async fn no_server(w: &mut AlooWorld) {
    let state = w.ui_mut();
    state.serverless = true;
    state.set_server_link(ServerLinkState::NoServer);
}

#[when(expr = "a direct punch to {word} is in flight")]
async fn punch_in_flight(w: &mut AlooWorld, name: String) {
    w.ui_mut()
        .set_link_status(UserId(id_for(&name)), LinkStatus::Connecting);
}

#[then(expr = "the server state reads {string} in {word}")]
async fn state_reads(w: &mut AlooWorld, text: String, colour: String) {
    let expected = match colour.as_str() {
        "green" => Color::Green,
        "red" => Color::Red,
        "white" => Color::White,
        other => panic!("unknown colour {other:?} - expected green/red/white"),
    };
    let rows = ui_rows_wide(w.ui_ref());
    let header = header_row(&rows);
    assert!(
        header.contains(&text),
        "expected the header to say {text:?}: {header:?}"
    );
    let buffer = ui_buffer(w.ui_ref(), WIDE, 30);
    let (x, y) = find_text_start(&buffer, &text);
    assert_eq!(
        buffer[(x, y)].fg,
        expected,
        "{text:?} should render {colour}"
    );
}

#[then("the server state is the first thing on the header row")]
async fn state_is_first(w: &mut AlooWorld) {
    let rows = ui_rows_wide(w.ui_ref());
    let header = header_row(&rows);
    let state = header
        .find("Connected to server!")
        .expect("the header must say what the connection is doing");
    let selector = header
        .find("general")
        .expect("the channel selector names the channel");
    assert!(
        state < selector,
        "the server state comes before the selectors: {header:?}"
    );
}

#[then("the channel selector starts where the message list starts")]
async fn selector_aligned(w: &mut AlooWorld) {
    let buffer = ui_buffer(w.ui_ref(), WIDE, 30);
    // The selector's own `#name` is its first cell (a public channel
    // carries no kind icon); one column past the message pane's own edge
    // is where the messages inside it begin, so the two columns of text
    // line up.
    let (x, _) = find_text_start(&buffer, "#general");
    assert_eq!(
        x,
        messages_start_col(WIDE) + 1,
        "the selectors must line up with the message list under them"
    );
}

#[then("the whole countdown is still readable")]
async fn countdown_readable(w: &mut AlooWorld) {
    // The default 100-column frame: narrower than the state needs.
    let rows = crate::support::ui_rows(w.ui_ref());
    let header = header_row(&rows);
    assert!(
        header.contains("Server down (reconnecting in 30 sec...)"),
        "a countdown missing its number says nothing: {header:?}"
    );
}

#[then("the selectors have moved aside for it")]
async fn selectors_moved(w: &mut AlooWorld) {
    let rows = crate::support::ui_rows(w.ui_ref());
    let header = header_row(&rows);
    let end = header.find("sec...)").expect("the countdown") + "sec...)".len();
    let selector = header.find("general").expect("the channel selector");
    assert!(
        selector > end,
        "the selectors move rather than being written over: {header:?}"
    );
}

// ---------------------------------------------------------------------
// Reconnecting for real (AC-225, AC-226, AC-227)
// ---------------------------------------------------------------------


/// A keybundle written once per nickname, at a small modulus - these
/// scenarios are about reconnecting, never about key strength, and a real
/// RSA-4096 pair takes seconds (`world.rs`'s `SCENARIO_KEY_BITS` makes the
/// same trade). Fixed per nickname on purpose: a reconnect must come back
/// as the *same* person, which is exactly what re-resolving these two
/// paths proves.
fn scenario_keybundle(nickname: &str) -> aloo::client::connect::MyKeySelection {
    let dir = std::env::temp_dir().join(format!(
        "aloo-cucumber-reconnect-keys-{}-{nickname}",
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
    aloo::client::connect::MyKeySelection {
        file_pub,
        file_priv,
    }
}

fn password_for(nickname: &str) -> String {
    format!("pw-{nickname}")
}

/// Registers `nickname` in `w`'s server registry (creating a scratch one
/// if this is the scenario's first) if it is not there yet.
fn ensure_registered(w: &mut AlooWorld, nickname: &str) {
    let users = w.server_users.get_or_insert_with(|| {
        let dir = std::env::temp_dir().join(format!(
            "aloo-cucumber-reconnect-users-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        UsersRegistry::open_with_iterations(dir, 100).unwrap()
    });
    if !users.is_registered(nickname) {
        users.register_manual(nickname, &password_for(nickname)).unwrap();
    }
}

fn request_for(
    addr: std::net::SocketAddr,
    nickname: &str,
) -> aloo::client::connect::ConnectRequest {
    aloo::client::connect::ConnectRequest {
        host: addr.ip().to_string(),
        port: addr.port(),
        ssl: false,
        ssl_ca: None,
        nickname: nickname.to_string(),
        password: password_for(nickname),
        my_key: scenario_keybundle(nickname),
        activation_code: None,
    }
}

#[then(expr = "reconnecting as {string} is refused while that connection holds the name")]
async fn reconnect_refused(w: &mut AlooWorld, nickname: String) {
    let addr = w.addr.expect("no server running");
    ensure_registered(w, &nickname);
    let outcome =
        aloo::client::connect::connect_with_reconnect(&request_for(addr, &nickname)).await;
    let err = match outcome {
        Ok(_) => panic!("a nickname already held must not be handed out twice"),
        Err(e) => e.to_string(),
    };
    w.reconnect_failure = Some(err);
}

#[then("the refusal is an ordinary failure, scheduled for another attempt")]
async fn refusal_is_retryable(w: &mut AlooWorld) {
    let reason = w
        .reconnect_failure
        .as_ref()
        .expect("no refusal was recorded");
    assert!(
        !reason.is_empty(),
        "the reason is what the one status notice reports"
    );
    // Nothing distinguishes it from a refused connection: the same wait,
    // then the same next attempt. The connection holding the name is
    // usually this client's own dead one, freed within HEARTBEAT_TIMEOUT.
    assert_eq!(delay_after(1), Duration::from_secs(5));
}

#[given(expr = "a server that gives up on a silent client after {int} second(s)")]
async fn reaping_server(w: &mut AlooWorld, seconds: u64) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let users = UsersRegistry::open_with_iterations(
        std::env::temp_dir().join(format!(
            "aloo-cucumber-reconnect-users-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )),
        100,
    )
    .unwrap();
    let options =
        ServerOptions::new(users.clone()).with_heartbeat_timeout(Duration::from_secs(seconds));
    tokio::spawn(async move {
        let _ = aloo::server::serve(listener, options).await;
    });
    w.addr = Some(addr);
    w.server_users = Some(users);
    w.reap_after = Some(Duration::from_secs(seconds));
}

#[given(expr = "{word} is running a session on it, joined to {string}")]
async fn session_joined(w: &mut AlooWorld, nickname: String, channel: String) {
    let addr = w.addr.expect("no server running");
    ensure_registered(w, &nickname);
    let request = request_for(addr, &nickname);
    let (events, sink, you, identity, server_addr) =
        aloo::client::connect::connect_with_reconnect(&request)
            .await
            .expect("the first connection is an ordinary one");

    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    let id_store =
        aloo::client::idstore::IdStore::new_empty(aloo::client::idstore::default_path());
    let plan = aloo::client::daemon::DaemonPlan::new(
        vec![aloo::client::daemon::DaemonChannel {
            name: channel,
            password: None,
        }],
        None,
    );
    let handle = tokio::spawn(async move {
        let mut surface = aloo::client::tui::surface::Surface::Detached;
        let _ = aloo::client::session::run_daemon_session(
            &mut surface,
            Some(events),
            sink,
            nickname,
            you,
            identity,
            id_store,
            None,
            Some(server_addr),
            input_rx,
            plan,
        )
        .await;
    });
    w.session = Some(handle);
    w.session_input = Some(input_tx);
}

#[when(expr = "the server gives up on {word}'s connection")]
async fn server_gives_up(w: &mut AlooWorld, _nickname: String) {
    // The session's own heartbeat is far longer than this server's
    // patience, so it is treated as gone: nickname freed, everyone told,
    // socket closed - the moment this whole feature is about.
    let reap = w.reap_after.expect("no reaping server was started");
    tokio::time::sleep(reap + Duration::from_millis(700)).await;
}

#[then(expr = "{word}, connecting afterwards, is told {word} is in {string}")]
async fn late_arrival_sees(w: &mut AlooWorld, newcomer: String, who: String, channel: String) {
    let addr = w.addr.expect("no server running");
    let mut stream = aloo::control::ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
    ensure_registered(w, &newcomer);
    handshake(&mut stream, &newcomer, &password_for(&newcomer)).await;
    stream
        .send(&ClientMessage::JoinChannel {
            name: channel.clone(),
            kind: ChannelKind::Public,
            password: None,
        })
        .await
        .unwrap();

    let mut seen = false;
    for _ in 0..8 {
        let next =
            tokio::time::timeout(Duration::from_secs(2), stream.recv::<ServerMessage>()).await;
        let Ok(Ok(Some(msg))) = next else { break };
        if let ServerMessage::UserJoined { user, .. } = &msg
            && user.name == who
        {
            seen = true;
            break;
        }
    }
    assert!(
        seen,
        "{who} reconnected but was invisible to {newcomer}, who arrived afterwards - \
         which is the whole bug: her messages still arrive over the direct links, \
         and she is in nobody's user list"
    );

    if let Some(input) = w.session_input.take() {
        let _ = input.send(aloo::client::session::SessionInput::Shutdown);
    }
    if let Some(handle) = w.session.take() {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
}

/// A plain client handshake, enough to watch what the server says.
async fn handshake(
    stream: &mut aloo::control::ControlEndpoint<TcpStream>,
    nickname: &str,
    password: &str,
) {
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
        .send(&ClientMessage::Auth {
            nickname: nickname.to_string(),
            password: password.to_string(),
        })
        .await
        .unwrap();
    let auth: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(matches!(auth, ServerMessage::AuthResult { ok: true, .. }), "{auth:?}");
    stream
        .send(&ClientMessage::Identify {
            public_key_der: vec![1, 2, 3],
            key_mode: aloo::proto::KeyMode::PqHybrid,
        })
        .await
        .unwrap();
    let _identify: ServerMessage = stream.recv().await.unwrap().unwrap();
    let _channels: ServerMessage = stream.recv().await.unwrap().unwrap();
}
