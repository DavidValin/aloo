//! `crate::client::daemon_ipc` - the local channel a terminal attaches to
//! a running daemon through.
//!
//! Two halves: the wire types, which are pure and tested directly, and the
//! socket lifecycle, which needs a filesystem and is tested against temp
//! paths rather than the real `~/.aloo`.

use aloo::client::daemon_ipc::{
    self, AttachMessage, DaemonMessage, KeyCodeWire, KeyKindWire, KeyWire,
};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use std::path::PathBuf;

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-daemon-ipc-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

// ---------------------------------------------------------------------
// Keys on the wire
// ---------------------------------------------------------------------

/// Every key the attached terminal can send has to survive the trip, or
/// the session silently misreads what was typed at it.
/// @requirement TB-219
#[test]
fn every_named_key_code_round_trips() {
    let codes = [
        KeyCode::Char('a'),
        KeyCode::Char('/'),
        KeyCode::Char(' '),
        KeyCode::Char('ñ'),
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::Backspace,
        KeyCode::Tab,
        KeyCode::BackTab,
        KeyCode::Left,
        KeyCode::Right,
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::PageUp,
        KeyCode::PageDown,
        KeyCode::Delete,
        KeyCode::Insert,
        KeyCode::F(5),
    ];
    for code in codes {
        let wire = KeyWire::from_crossterm(code, KeyModifiers::NONE, KeyEventKind::Press);
        let (back, _, _) = wire.to_crossterm();
        assert_eq!(back, code, "{code:?} must survive the round trip");
    }
}

/// @requirement TB-219
#[test]
fn modifiers_and_event_kinds_round_trip() {
    // Space held with Ctrl+Alt, released - the exact shape push-to-talk
    // depends on, and the one where losing the `Release` would leave a
    // recording running forever.
    for kind in [
        KeyEventKind::Press,
        KeyEventKind::Repeat,
        KeyEventKind::Release,
    ] {
        let mods = KeyModifiers::CONTROL | KeyModifiers::ALT;
        let wire = KeyWire::from_crossterm(KeyCode::Char(' '), mods, kind);
        let (code, back_mods, back_kind) = wire.to_crossterm();
        assert_eq!(code, KeyCode::Char(' '));
        assert_eq!(back_mods, mods);
        assert_eq!(back_kind, kind);
    }
}

/// A key this enum does not name still arrives as *a* key event rather
/// than vanishing - `handle_key` ignores it exactly as it ignores the
/// unnamed `KeyCode` variants today.
/// @requirement TB-219
#[test]
fn an_unnamed_key_code_becomes_other_rather_than_being_dropped() {
    let wire = KeyWire::from_crossterm(
        KeyCode::Media(crossterm::event::MediaKeyCode::Play),
        KeyModifiers::NONE,
        KeyEventKind::Press,
    );
    assert_eq!(wire.code, KeyCodeWire::Other);
    assert_eq!(wire.to_crossterm().0, KeyCode::Null);
}

/// A daemon and a client built from different revisions could disagree
/// about which modifier bits exist. Dropping an unknown bit is right where
/// refusing the whole keystroke would not be.
/// @requirement TB-219
#[test]
fn an_unknown_modifier_bit_is_dropped_not_fatal() {
    let wire = KeyWire {
        code: KeyCodeWire::Char('a'),
        modifiers: 0xFF,
        kind: KeyKindWire::Press,
    };
    let (code, mods, _) = wire.to_crossterm();
    assert_eq!(code, KeyCode::Char('a'));
    assert!(mods.contains(KeyModifiers::CONTROL));
}

// ---------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------

/// @requirement TB-219
#[test]
fn attach_messages_round_trip_through_a_frame() {
    let messages = [
        AttachMessage::Attach {
            cols: 120,
            rows: 40,
            supports_key_release: true,
        },
        AttachMessage::Key(KeyWire::from_crossterm(
            KeyCode::Enter,
            KeyModifiers::NONE,
            KeyEventKind::Press,
        )),
        AttachMessage::Resize { cols: 80, rows: 24 },
        AttachMessage::Detach,
        AttachMessage::Status,
        AttachMessage::Shutdown,
    ];
    for message in messages {
        let bytes = daemon_ipc::encode_frame(&message).unwrap();
        let (decoded, consumed) = daemon_ipc::decode_frame::<AttachMessage>(&bytes)
            .unwrap()
            .expect("a whole frame must decode");
        assert_eq!(decoded, message);
        assert_eq!(consumed, bytes.len());
    }
}

/// @requirement TB-219
#[test]
fn daemon_messages_round_trip_through_a_frame() {
    let messages = [
        DaemonMessage::Attached,
        DaemonMessage::Busy,
        DaemonMessage::Frame(vec![0x1b, b'[', b'2', b'J']),
        DaemonMessage::Detached {
            reason: "detached".into(),
        },
        DaemonMessage::Status("running".into()),
    ];
    for message in messages {
        let bytes = daemon_ipc::encode_frame(&message).unwrap();
        let (decoded, _) = daemon_ipc::decode_frame::<DaemonMessage>(&bytes)
            .unwrap()
            .expect("a whole frame must decode");
        assert_eq!(decoded, message);
    }
}

/// A socket read returns whatever happened to arrive, which is routinely
/// half a frame. Decoding must wait rather than fail.
/// @requirement TB-219
#[test]
fn a_partial_frame_decodes_to_nothing_yet_rather_than_an_error() {
    let bytes = daemon_ipc::encode_frame(&AttachMessage::Detach).unwrap();
    for cut in 0..bytes.len() {
        let partial = &bytes[..cut];
        assert!(
            matches!(daemon_ipc::decode_frame::<AttachMessage>(partial), Ok(None)),
            "{cut} of {} bytes should decode to Ok(None)",
            bytes.len()
        );
    }
}

/// The other routine case: several frames arriving in one read.
/// @requirement TB-219
#[test]
fn several_frames_in_one_buffer_are_consumed_one_at_a_time() {
    let mut buf = Vec::new();
    buf.extend(daemon_ipc::encode_frame(&AttachMessage::Status).unwrap());
    buf.extend(daemon_ipc::encode_frame(&AttachMessage::Detach).unwrap());

    let (first, consumed) = daemon_ipc::decode_frame::<AttachMessage>(&buf)
        .unwrap()
        .unwrap();
    assert_eq!(first, AttachMessage::Status);
    buf.drain(..consumed);

    let (second, consumed) = daemon_ipc::decode_frame::<AttachMessage>(&buf)
        .unwrap()
        .unwrap();
    assert_eq!(second, AttachMessage::Detach);
    buf.drain(..consumed);
    assert!(buf.is_empty());
}

// ---------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------

/// All three live beside the rest of this app's state, so `ALOO_HOME`
/// separates two daemons exactly as it separates two clients.
/// @requirement TB-220
#[test]
fn the_daemon_files_sit_together_under_the_aloo_directory() {
    let socket = daemon_ipc::socket_path();
    let pid = daemon_ipc::pid_path();
    let log = daemon_ipc::log_path();
    assert!(socket.ends_with("daemon.sock"));
    assert!(pid.ends_with("daemon.pid"));
    assert!(log.ends_with("daemon.log"));
    assert_eq!(socket.parent(), pid.parent());
    assert_eq!(socket.parent(), log.parent());
}

// ---------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------

/// The socket's permissions *are* the access control - anyone who can
/// write to it controls the session completely - so this is a security
/// property, not a tidiness one.
/// @requirement TB-220
#[cfg(unix)]
#[tokio::test]
async fn the_socket_is_created_private_to_this_user() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_path("perms");
    let _listener = daemon_ipc::bind_listener(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "got {mode:o}");

    std::fs::remove_file(&path).ok();
}

/// A daemon killed with SIGKILL leaves its socket file behind. Refusing to
/// start over that debris would need a manual `rm` after every crash.
/// @requirement TB-220
#[cfg(unix)]
#[tokio::test]
async fn a_stale_socket_file_is_replaced_rather_than_refused() {
    let path = temp_path("stale");
    std::fs::write(&path, b"not a socket").unwrap();

    let _listener = daemon_ipc::bind_listener(&path)
        .expect("debris from a killed daemon must not block a fresh start");

    std::fs::remove_file(&path).ok();
}

/// "Is a daemon running?" is answered by connecting, never by the file
/// existing - which is the only way to tell a live daemon from its debris.
/// @requirement TB-220
#[cfg(unix)]
#[tokio::test]
async fn a_running_daemon_is_detected_by_connecting_not_by_the_file() {
    let path = temp_path("running");
    assert!(
        !daemon_ipc::is_daemon_running(&path).await,
        "nothing there at all"
    );

    std::fs::write(&path, b"debris").unwrap();
    assert!(
        !daemon_ipc::is_daemon_running(&path).await,
        "a plain file is not a running daemon"
    );
    std::fs::remove_file(&path).ok();

    let listener = daemon_ipc::bind_listener(&path).unwrap();
    assert!(
        daemon_ipc::is_daemon_running(&path).await,
        "something is listening"
    );

    drop(listener);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// The pipe (Windows)
// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// Only one daemon at a time
// ---------------------------------------------------------------------

use aloo::client::daemon::SingleInstance;

/// @requirement TB-220
#[cfg(unix)]
#[tokio::test]
async fn acquiring_records_the_pid_and_releasing_cleans_up() {
    let socket = temp_path("inst-sock");
    let pid = temp_path("inst-pid");

    let instance = SingleInstance::acquire(socket.clone(), pid.clone())
        .await
        .unwrap();
    let listener = daemon_ipc::bind_listener(&socket).unwrap();

    assert_eq!(
        std::fs::read_to_string(&pid).unwrap().trim(),
        std::process::id().to_string(),
        "the pid file names this process, so a second start can report it"
    );

    drop(listener);
    drop(instance);
    assert!(!socket.exists(), "the socket must not outlive the daemon");
    assert!(!pid.exists(), "nor the pid file");
}

/// Windows' counterpart to both `a_running_daemon_is_detected_by_connecting_not_by_the_file`
/// and the test above, combined into one rather than kept as two: on
/// Windows, `pipe_name` is a single fixed, username-scoped name - unlike
/// Unix's per-test temp socket path, `bind_listener`/`connect` here never
/// read or write `_path`/`socket` at all (see their doc comments) - so two
/// *separate* tests each binding it would race each other under libtest's
/// default parallel execution; whichever ran second would hit
/// `first_pipe_instance`'s refusal (which Windows reports as
/// `ERROR_ACCESS_DENIED`) meant for a genuine second daemon, not a test
/// ordering artifact. One sequential test sidesteps that by construction.
/// Also exercises the DACL `bind_listener` now applies
/// (`create_owner_only_pipe_instance`) end to end: if it were too
/// restrictive to admit even this same account, `is_daemon_running`
/// (`connect` internally) would fail here exactly as it would for a real
/// second, unauthorized account.
///
/// Minus the Unix tests' stale-*file*/socket-file assertions: there is
/// nothing analogous to either on Windows, since the channel is the pipe,
/// never a file at `_path`/`socket`.
/// @requirement TB-220
#[cfg(windows)]
#[tokio::test]
async fn a_running_daemon_is_detected_and_its_pid_file_cleaned_up_windows() {
    let path = temp_path("pipe-running");
    assert!(
        !daemon_ipc::is_daemon_running(&path).await,
        "nothing is listening yet"
    );

    let socket = temp_path("pipe-inst-sock");
    let pid = temp_path("pipe-inst-pid");
    let instance = SingleInstance::acquire(socket.clone(), pid.clone())
        .await
        .unwrap();
    let listener = daemon_ipc::bind_listener(&socket).unwrap();

    assert!(
        daemon_ipc::is_daemon_running(&path).await,
        "the pipe's own creator must still be able to reach it"
    );
    assert_eq!(
        std::fs::read_to_string(&pid).unwrap().trim(),
        std::process::id().to_string(),
        "the pid file names this process, so a second start can report it"
    );

    drop(listener);
    drop(instance);
    assert!(!pid.exists(), "the pid file must not outlive the daemon");
}

/// A second daemon must refuse rather than fight over the socket - and
/// must say which process already has it.
/// @requirement TB-220
#[cfg(unix)]
#[tokio::test]
async fn a_second_daemon_refuses_while_one_is_listening() {
    let socket = temp_path("second-sock");
    let pid = temp_path("second-pid");

    let first = SingleInstance::acquire(socket.clone(), pid.clone())
        .await
        .unwrap();
    let listener = daemon_ipc::bind_listener(&socket).unwrap();

    let err = SingleInstance::acquire(socket.clone(), pid.clone())
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("already running"), "{err}");
    assert!(
        err.contains(&std::process::id().to_string()),
        "must name the pid holding it: {err}"
    );
    assert!(err.contains("aloo"), "must say how to reach it: {err}");

    drop(listener);
    drop(first);
}

/// Debris from a killed daemon must not need a manual `rm` before the next
/// start - which is the whole reason "running" is decided by connecting.
/// @requirement TB-220
#[cfg(unix)]
#[tokio::test]
async fn a_daemon_starts_over_the_debris_of_a_killed_one() {
    let socket = temp_path("debris-sock");
    let pid = temp_path("debris-pid");
    // Exactly what SIGKILL leaves behind: both files, nothing listening.
    std::fs::write(&socket, b"stale").unwrap();
    std::fs::write(&pid, b"99999").unwrap();

    let instance = SingleInstance::acquire(socket.clone(), pid.clone())
        .await
        .expect("a killed daemon's leftovers must not block a fresh start");
    drop(instance);
    std::fs::remove_file(&socket).ok();
}

// ---------------------------------------------------------------------
// Attaching, over a real socket
// ---------------------------------------------------------------------

use aloo::client::session::SessionInput;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Reads exactly one message from the daemon side of an attach socket.
async fn read_one(
    stream: &mut daemon_ipc::ClientStream,
    buf: &mut Vec<u8>,
) -> DaemonMessage {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((message, consumed)) = daemon_ipc::decode_frame::<DaemonMessage>(buf).unwrap() {
            buf.drain(..consumed);
            return message;
        }
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut chunk),
        )
        .await
        .expect("the daemon should have answered by now")
        .unwrap();
        assert_ne!(read, 0, "the daemon closed the connection unexpectedly");
        buf.extend_from_slice(&chunk[..read]);
    }
}

async fn next_input(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionInput>,
) -> SessionInput {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the session should have been told by now")
        .expect("the input channel must stay open")
}

/// The whole attach conversation end to end: the handshake, a keystroke
/// reaching the session, a resize, and a detach that leaves the session
/// running.
/// @requirement AC-203
#[cfg(unix)]
#[tokio::test]
async fn attaching_forwards_keys_and_resizes_and_detaches_cleanly() {
    let socket = temp_path("attach");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));

    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    let mut buf = Vec::new();

    // Attach -> Attached, and the session is told to start drawing.
    client
        .write_all(
            &daemon_ipc::encode_frame(&AttachMessage::Attach {
                cols: 120,
                rows: 40,
                supports_key_release: true,
            })
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_one(&mut client, &mut buf).await, DaemonMessage::Attached);
    match next_input(&mut input_rx).await {
        SessionInput::Attached { size, .. } => {
            assert_eq!((size.cols, size.rows), (120, 40));
        }
        other => panic!("expected Attached, got {other:?}"),
    }

    // A keystroke reaches the session as the key that was pressed.
    client
        .write_all(
            &daemon_ipc::encode_frame(&AttachMessage::Key(KeyWire::from_crossterm(
                KeyCode::Char('x'),
                KeyModifiers::NONE,
                KeyEventKind::Press,
            )))
            .unwrap(),
        )
        .await
        .unwrap();
    match next_input(&mut input_rx).await {
        SessionInput::Key(crossterm::event::Event::Key(key)) => {
            assert_eq!(key.code, KeyCode::Char('x'));
        }
        other => panic!("expected a key, got {other:?}"),
    }

    // A resize reaches it too - otherwise frames stay laid out for a
    // window that no longer exists.
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Resize { cols: 80, rows: 24 }).unwrap())
        .await
        .unwrap();
    match next_input(&mut input_rx).await {
        SessionInput::Resized(size) => assert_eq!((size.cols, size.rows), (80, 24)),
        other => panic!("expected a resize, got {other:?}"),
    }

    // Detach: the viewer is told, and the session is told to stop drawing
    // - but never to stop.
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Detach).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        read_one(&mut client, &mut buf).await,
        DaemonMessage::Detached { .. }
    ));
    assert!(matches!(
        next_input(&mut input_rx).await,
        SessionInput::Detach
    ));
    assert!(
        !input_rx.is_closed(),
        "detaching must leave the session running"
    );

    std::fs::remove_file(&socket).ok();
}

/// A viewer whose terminal is closed, or which crashes, drops the socket
/// without saying goodbye. The session must still be told to stop drawing
/// into it - and must still be running afterwards.
/// @requirement AC-203
#[cfg(unix)]
#[tokio::test]
async fn a_viewer_vanishing_without_notice_still_detaches_the_session() {
    let socket = temp_path("vanish");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));

    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    client
        .write_all(
            &daemon_ipc::encode_frame(&AttachMessage::Attach {
                cols: 80,
                rows: 24,
                supports_key_release: false,
            })
            .unwrap(),
        )
        .await
        .unwrap();
    read_one(&mut client, &mut buf).await;
    next_input(&mut input_rx).await;

    drop(client); // the terminal window closed

    assert!(matches!(
        next_input(&mut input_rx).await,
        SessionInput::Detach
    ));
    assert!(!input_rx.is_closed(), "the session survives its viewer");

    std::fs::remove_file(&socket).ok();
}

/// `--daemon-status` asks without attaching, and must not disturb a
/// session or leave the daemon thinking someone is watching.
/// @requirement AC-203
#[cfg(unix)]
#[tokio::test]
async fn status_answers_without_attaching() {
    let socket = temp_path("status");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));

    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Status).unwrap())
        .await
        .unwrap();

    match read_one(&mut client, &mut buf).await {
        DaemonMessage::Status(text) => assert!(text.contains("running"), "{text}"),
        other => panic!("expected a status, got {other:?}"),
    }
    assert!(
        matches!(input_rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Empty)),
        "asking for status must not tell the session anything"
    );

    std::fs::remove_file(&socket).ok();
}

/// `--daemon-stop` is the one thing that ends the session - deliberately a
/// different command from detaching, so quitting a viewer can never do it.
/// @requirement AC-203
#[cfg(unix)]
#[tokio::test]
async fn shutdown_ends_the_session_where_detach_does_not() {
    let socket = temp_path("shutdown");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));

    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Shutdown).unwrap())
        .await
        .unwrap();

    assert!(matches!(
        read_one(&mut client, &mut buf).await,
        DaemonMessage::Detached { .. }
    ));
    assert!(matches!(
        next_input(&mut input_rx).await,
        SessionInput::Shutdown
    ));

    std::fs::remove_file(&socket).ok();
}

/// `/daemon` detaches from the *session* side: the session drops the
/// writer it was drawing through, which is the only signal the daemon
/// gets. The viewer is sitting waiting for a frame, so it has to be told,
/// or it hangs with a stale screen until something kills it.
///
/// This regressed once already, and invisibly: `serve_one` kept its own
/// clone of the frame sender, so the session dropping its half closed
/// nothing at all.
/// @requirement AC-203
#[cfg(unix)]
#[tokio::test]
async fn a_session_side_detach_tells_the_viewer_and_ends_the_connection() {
    let socket = temp_path("session-detach");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, mut input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));

    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    client
        .write_all(
            &daemon_ipc::encode_frame(&AttachMessage::Attach {
                cols: 80,
                rows: 24,
                supports_key_release: false,
            })
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_one(&mut client, &mut buf).await, DaemonMessage::Attached);

    // Take the writer the session was handed, and drop it - exactly what
    // `Surface::detach` does when `/daemon` is typed.
    let writer = match next_input(&mut input_rx).await {
        SessionInput::Attached { writer, .. } => writer,
        other => panic!("expected Attached, got {other:?}"),
    };
    drop(writer);

    match read_one(&mut client, &mut buf).await {
        DaemonMessage::Detached { reason } => {
            assert!(
                reason.contains("still running"),
                "the viewer must be told the daemon lives on: {reason}"
            );
        }
        other => panic!("expected to be told it was detached, got {other:?}"),
    }

    std::fs::remove_file(&socket).ok();
}

/// The counterpart: a connection that only ever asked a question has no
/// viewer to say goodbye to, and must not be sent one.
/// @requirement AC-203
#[cfg(unix)]
#[tokio::test]
async fn a_query_connection_is_never_told_it_was_detached() {
    let socket = temp_path("query-only");
    let listener = daemon_ipc::bind_listener(&socket).unwrap();
    let (input_tx, _input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(aloo::client::daemon::serve_attachments(listener, input_tx));

    let mut client = daemon_ipc::connect(&socket).await.unwrap();
    let mut buf = Vec::new();
    client
        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Status).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        read_one(&mut client, &mut buf).await,
        DaemonMessage::Status(_)
    ));

    std::fs::remove_file(&socket).ok();
}
