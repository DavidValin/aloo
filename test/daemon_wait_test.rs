//! `crate::client::daemon::connect_until_reachable` - a daemon whose
//! server is not there yet waits for it rather than exiting
//! (`docs/SPEC.md` "Running in background mode", "Waiting for the server").
//!
//! Driven against a real server over loopback that is brought up *after*
//! the daemon has already started dialling - the only way to prove the
//! thing this exists for: that a daemon started with the network down is
//! connected once the network is up, with nobody having restarted it.
//! What a terminal attaching mid-wait sees, what `--daemon-status` says,
//! and what `--daemon-stop` does are read off the same real plumbing the
//! daemon uses (`SessionInput`, `AttachWriter`, `StatusLine`).

use std::time::Duration;

#[path = "server_common.rs"]
mod server_common;

use aloo::client::connect::{
    AuthRefusedError, ConnectRequest, MyKeySelection, ResolvedIdentity, SslMismatchError,
    is_server_refusal, resolve_identity,
};
use aloo::client::daemon::{StatusLine, WaitPlan, connect_until_reachable};
use aloo::client::reconnect::Backoff;
use aloo::client::session::SessionInput;
use aloo::client::tui::surface::{AttachWriter, Surface, TerminalSize};
use server_common::{TestServer, password_for, test_options};

/// A keybundle written once per test process, at a small modulus - these
/// tests are about the wait, never about key strength (the same trade
/// `reconnect_test.rs` makes).
fn scenario_keybundle(nickname: &str) -> MyKeySelection {
    // Every test in this process shares one bundle per nickname, and the
    // tests run in parallel: without this lock two of them can both see
    // no bundle, both generate one, and one of them then reads a file the
    // other is still halfway through writing (seen on CI as a decode
    // error resolving the bundle).
    static KEYGEN: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one_at_a_time = KEYGEN.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!(
        "aloo-daemon-wait-test-keys-{}-{nickname}",
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
    MyKeySelection { file_pub, file_priv }
}

fn request_for(port: u16, nickname: &str, password: &str) -> ConnectRequest {
    ConnectRequest {
        host: "127.0.0.1".to_string(),
        port,
        ssl: false,
        ssl_ca: None,
        nickname: nickname.to_string(),
        password: password.to_string(),
        my_key: scenario_keybundle(nickname),
        activation_code: None,
    }
}

async fn identity_for(nickname: &str) -> ResolvedIdentity {
    resolve_identity(&scenario_keybundle(nickname))
        .await
        .expect("the scenario keybundle resolves")
}

/// A loopback port with nothing listening on it: bound to learn the
/// number, then released. Exactly the shape a daemon started before its
/// server (or its network) sees.
async fn closed_port() -> u16 {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    probe.local_addr().unwrap().port()
}

/// Milliseconds rather than the production seconds, so a whole sequence
/// of failed attempts fits in a test.
fn fast() -> WaitPlan {
    WaitPlan {
        backoff: Backoff {
            first: Duration::from_millis(20),
            max: Duration::from_millis(60),
        },
        desktop_notification: false,
    }
}

/// A wait that would take longer than any test's patience: proof, when a
/// call returns promptly anyway, that it did not retry.
fn glacial() -> WaitPlan {
    WaitPlan {
        backoff: Backoff {
            first: Duration::from_secs(60),
            max: Duration::from_secs(60),
        },
        desktop_notification: false,
    }
}

/// Polls `status` until it says the daemon is waiting - the moment at
/// least one attempt has failed.
async fn wait_until_waiting(status: &StatusLine) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !status.is_waiting() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the daemon should have reported a failed attempt by now");
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------
// The wait itself
// ---------------------------------------------------------------------

/// The reported bug, end to end: `aloo --daemon` with the wifi off used
/// to fail its one connection attempt and exit. Now it keeps dialling,
/// and the moment the server is reachable it is on it - as a daemon that
/// was never restarted.
/// @requirement AC-442
#[tokio::test]
async fn a_daemon_whose_server_is_not_there_yet_waits_for_it() {
    let port = closed_port().await;
    let request = request_for(port, "alice", &password_for("alice"));
    let identity = identity_for("alice").await;
    let status = StatusLine::default();
    let (_input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();

    let waiting_status = status.clone();
    let daemon = tokio::spawn(async move {
        let mut surface = Surface::Detached;
        connect_until_reachable(
            &request,
            &identity,
            fast(),
            &mut input_rx,
            &waiting_status,
            &mut surface,
        )
        .await
    });

    wait_until_waiting(&status).await;
    let line = status.render();
    assert!(
        line.contains("waiting for the server at 127.0.0.1:") && line.contains("trying again in"),
        "--daemon-status must say the daemon is waiting, and where it is up to: {line}"
    );
    assert!(
        !daemon.is_finished(),
        "an unreachable server must be waited for, not returned as a failure"
    );

    // The network comes up: the server appears exactly where the daemon
    // has been looking.
    let server = TestServer::spawn_at(port, test_options("daemon-wait")).await;
    server.ensure_user("alice");

    let first = tokio::time::timeout(Duration::from_secs(10), daemon)
        .await
        .expect("the daemon should have connected once the server was up")
        .expect("the wait task must not panic")
        .expect("the connection is an ordinary one")
        .expect("a wait that ends in a connection is not a stop");
    assert_eq!(first.server_addr, server.addr);
    assert!(
        !status.is_waiting(),
        "once connected, --daemon-status must go back to plainly running"
    );
    assert_eq!(
        status.render(),
        format!("aloo daemon running (pid {})", std::process::id())
    );
}

/// A wrong password is the server's answer, not its absence: retrying it
/// would get the same answer forever, and a daemon doing so would look
/// exactly like one that is working. It is the startup failure it always
/// was, returned at once - proven by a backoff no test would wait out.
/// @requirement TB-292
#[tokio::test]
async fn an_answer_from_the_server_ends_the_wait_at_once() {
    let server = TestServer::spawn(test_options("daemon-wait-refused")).await;
    server.ensure_user("alice");
    let request = request_for(server.addr.port(), "alice", "not-alices-password");
    let identity = identity_for("alice").await;
    let status = StatusLine::default();
    let (_input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut surface = Surface::Detached;

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        connect_until_reachable(&request, &identity, glacial(), &mut input_rx, &status, &mut surface),
    )
    .await
    .expect("a refusal must come back without a single retry");
    let err = match outcome {
        Err(e) => e,
        Ok(_) => panic!("a wrong password must not connect"),
    };
    assert!(
        err.downcast_ref::<AuthRefusedError>().is_some(),
        "the refusal must come back as itself, got {err}"
    );
    assert!(
        !status.is_waiting(),
        "a refusal is a failure, never a wait: {}",
        status.render()
    );
}

/// The line between "wait" and "fail", stated directly.
/// @requirement TB-292
#[test]
fn only_an_answer_from_the_server_is_a_refusal() {
    let refused: aloo::BoxError = Box::new(AuthRefusedError("authentication failed".into()));
    let mismatch: aloo::BoxError = Box::new(SslMismatchError("appears to require SSL".into()));
    let unreachable: aloo::BoxError =
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused").into();
    let no_such_host: aloo::BoxError = "host does not resolve".into();
    let timed_out: aloo::BoxError = "connect to h:1 timed out after 15s".into();

    assert!(is_server_refusal(&refused));
    assert!(is_server_refusal(&mismatch));
    assert!(!is_server_refusal(&unreachable));
    assert!(!is_server_refusal(&no_such_host));
    assert!(!is_server_refusal(&timed_out));
}

// ---------------------------------------------------------------------
// Being reachable while waiting
// ---------------------------------------------------------------------

/// `aloo --daemon-stop` during the wait ends the daemon as cleanly as one
/// after a session - `Ok(None)`, not an error and not a hang until the
/// next attempt.
/// @requirement AC-442
#[tokio::test]
async fn a_stop_request_during_the_wait_ends_the_daemon_cleanly() {
    let port = closed_port().await;
    let request = request_for(port, "alice", &password_for("alice"));
    let identity = identity_for("alice").await;
    let status = StatusLine::default();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();

    let waiting_status = status.clone();
    let daemon = tokio::spawn(async move {
        let mut surface = Surface::Detached;
        connect_until_reachable(
            &request,
            &identity,
            glacial(),
            &mut input_rx,
            &waiting_status,
            &mut surface,
        )
        .await
        .map(|first| first.is_some())
    });
    wait_until_waiting(&status).await;

    input_tx.send(SessionInput::Shutdown).unwrap();
    let connected = tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .expect("a stop must end the wait at once, not after the backoff")
        .expect("the wait task must not panic")
        .expect("a stop is a clean end, not an error");
    assert!(!connected, "a stopped wait never connected");
}

/// A bare `aloo` during the wait gets a screen that says what is going
/// on - the connect screen's own processing animation with the wait's
/// countdown - rather than a blank terminal, and `/daemon` (a `Detach`)
/// hands it back without disturbing the wait.
/// @requirement AC-442
#[tokio::test]
async fn an_attached_terminal_is_shown_where_the_wait_is_up_to() {
    let port = closed_port().await;
    let request = request_for(port, "alice", &password_for("alice"));
    let identity = identity_for("alice").await;
    let status = StatusLine::default();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();

    let waiting_status = status.clone();
    let daemon = tokio::spawn(async move {
        let mut surface = Surface::Detached;
        connect_until_reachable(
            &request,
            &identity,
            glacial(),
            &mut input_rx,
            &waiting_status,
            &mut surface,
        )
        .await
        .map(|first| first.is_some())
    });
    wait_until_waiting(&status).await;

    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel();
    input_tx
        .send(SessionInput::Attached {
            writer: AttachWriter::new(frame_tx),
            size: TerminalSize::new(120, 40),
        })
        .unwrap();

    let mut seen = String::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let bytes = frame_rx.recv().await.expect("the viewer should be drawn to");
            seen.push_str(&strip_ansi(&String::from_utf8_lossy(&bytes)));
            if seen.contains("cannot reach 127.0.0.1:") && seen.contains("trying again in") {
                break;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the attached terminal never saw the wait; it saw: {seen:?}"));

    input_tx.send(SessionInput::Detach).unwrap();
    assert!(
        !daemon.is_finished(),
        "attaching and detaching must leave the wait exactly where it was"
    );
    input_tx.send(SessionInput::Shutdown).unwrap();
    let connected = tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .expect("a stop must end the wait at once")
        .unwrap()
        .unwrap();
    assert!(!connected);
}
