//! Daemon mode: connect once, stay connected, and let a terminal borrow
//! the session (`docs/SPEC.md` "Running in background mode").
//!
//! Three separate jobs live here, in the order they happen:
//!
//! 1. **Resolving what to run as** (`DaemonConfig`) - flags first, then
//!    `daemon_*` keys in `~/.aloo/settings`, then the connect cache, then
//!    compiled defaults. The same precedence `run_server` already
//!    established for its own flags.
//! 2. **Becoming a daemon** (`spawn_detached`, `SingleInstance`) - getting
//!    out of the launching terminal's process group so closing that
//!    terminal cannot take the session with it, and making sure there is
//!    only ever one.
//! 3. **Serving viewers** (`serve_attachments`) - turning a connected
//!    socket into the `SessionInput` stream the ordinary session loop
//!    already consumes, and its frames back into bytes on that socket.
//!
//! What is deliberately *not* here: anything about how the session itself
//! works. A daemon runs the same `session::run_connected_session` a
//! foreground client does, against the same `UiState`, differing only in
//! which `Surface` it draws to and where its input comes from.

use std::path::{Path, PathBuf};

use crate::BoxError;
use crate::client::daemon_ipc::{self, AttachMessage, DaemonMessage};
use crate::client::session::SessionInput;
use crate::client::tui::surface::{AttachWriter, TerminalSize};

/// Environment marker set on the re-executed child so it knows not to
/// background itself a second time. An env var rather than a flag so the
/// child's command line still reads exactly like what the user typed,
/// which is what shows up in `ps` and in a systemd unit.
pub const DAEMON_CHILD_ENV: &str = "ALOO_DAEMON_CHILD";

// ---------------------------------------------------------------------
// What to focus, and what to join
// ---------------------------------------------------------------------

/// Where a daemon's voice goes when the global shortcut is pressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonFocus {
    /// A channel, by name - selected as soon as the join is confirmed.
    Channel(String),
    /// A person, by nickname - the DM opens as soon as they are seen.
    /// `otp` additionally proposes an OTP session the moment they appear.
    Dm { nickname: String, otp: bool },
}

impl DaemonFocus {
    /// Parses a `--focus` value. `channel:<name>` and `dm:<nickname>` are
    /// the explicit spellings; a bare value is a nickname, since that is
    /// the shorter and more common case and a channel already has a
    /// natural prefix to reach for.
    pub fn parse(value: &str, otp: bool) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("--focus needs a value".to_string());
        }
        if let Some(name) = value.strip_prefix("channel:") {
            if name.is_empty() {
                return Err("--focus=channel: needs a channel name after the colon".to_string());
            }
            if otp {
                // OTP is provisioned pairwise, per contact - there is no
                // such thing as an OTP session with a channel (see
                // `client::otp`'s module doc), so this is a mistake worth
                // naming rather than quietly ignoring.
                return Err("--otp needs a person to focus, not a channel".to_string());
            }
            return Ok(Self::Channel(name.to_string()));
        }
        let nickname = value.strip_prefix("dm:").unwrap_or(value);
        if nickname.is_empty() {
            return Err("--focus=dm: needs a nickname after the colon".to_string());
        }
        Ok(Self::Dm {
            nickname: nickname.to_string(),
            otp,
        })
    }
}

/// One `--channel` value: a name, and optionally the password to join it
/// with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonChannel {
    pub name: String,
    pub password: Option<String>,
}

impl DaemonChannel {
    /// Parses one `name[:password]` item.
    ///
    /// The separator is a colon, not a comma, and the split is on the
    /// **first** one. A colon is legal in neither a channel name
    /// (`validation::channel_name_char_allowed`) nor a channel password
    /// (`validation::CHANNEL_PASSWORD_SYMBOLS`), which is exactly what
    /// makes it unambiguous here - a comma could not be, since a password
    /// may contain one and `--channels` uses commas to separate items.
    ///
    /// Splitting on the first colon rather than the last means a password
    /// containing a comma still round-trips through a single
    /// `daemon_channel=` line, where nothing is splitting on commas.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        let (name, password) = match value.split_once(':') {
            Some((name, password)) => (name.trim(), Some(password.to_string())),
            None => (value, None),
        };
        // `--channels=#team` is the channel written the way it is shown
        // (`docs/SPEC.md` "Connected UI"); the `#` is decoration.
        let name = crate::validation::normalize_channel_name(name);
        if !crate::validation::channel_name_is_valid(name) {
            return Err(format!(
                "{name:?} is not a usable channel name (letters, digits and - only, \
                 up to {} characters)",
                crate::validation::CHANNEL_NAME_MAX_LEN
            ));
        }
        // An empty password is "no password", not "the empty password" -
        // `--channels=ops:` is a typo, and treating it as a real (empty)
        // credential would fail the join for a confusing reason.
        Ok(Self {
            name: name.to_string(),
            password: password.filter(|p| !p.is_empty()),
        })
    }

    /// Parses a whole `--channels` value: `name[:password]`, comma
    /// separated.
    ///
    /// Empty items are skipped rather than refused, so a trailing comma or
    /// a doubled one is a typo that costs nothing - unlike a malformed
    /// channel name, which is refused, since that one silently joins the
    /// wrong place or nothing at all.
    ///
    /// The one thing this cannot express is a password containing a comma:
    /// the item split happens first. Such a password still works from
    /// `~/.aloo/settings`, where each channel has a line to itself and
    /// nothing splits on commas.
    pub fn parse_list(value: &str) -> Result<Vec<Self>, String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(Self::parse)
            .collect()
    }

    /// The `daemon_channel=` line this round-trips through.
    pub fn to_setting(&self) -> String {
        match &self.password {
            Some(password) => format!("{}:{}", self.name, password),
            None => self.name.clone(),
        }
    }
}

// ---------------------------------------------------------------------
// Single instance
// ---------------------------------------------------------------------

/// Owns the daemon's socket and pid file for as long as it runs, and
/// removes both on the way out.
///
/// A `Drop` guard rather than explicit cleanup at each exit point: a
/// daemon exits from several places (a fatal startup error, `--daemon-stop`,
/// the session ending), and a socket file left behind is exactly the
/// debris that makes the *next* start ambiguous.
#[derive(Debug)]
pub struct SingleInstance {
    socket: PathBuf,
    pid: PathBuf,
}

impl SingleInstance {
    /// Claims the socket and pid paths, refusing if a daemon is already
    /// live.
    ///
    /// "Live" is decided by connecting, never by the socket file existing:
    /// a daemon killed with SIGKILL leaves the file behind, and refusing
    /// to start because of debris would need a manual `rm` after every
    /// crash.
    pub async fn acquire(socket: PathBuf, pid: PathBuf) -> Result<Self, BoxError> {
        if daemon_ipc::is_daemon_running(&socket).await {
            let running = std::fs::read_to_string(&pid).unwrap_or_default();
            let running = running.trim();
            return Err(if running.is_empty() {
                "an aloo daemon is already running - type 'aloo' to attach to it".into()
            } else {
                format!(
                    "an aloo daemon is already running (pid {running}) - \
                     type 'aloo' to attach to it"
                )
                .into()
            });
        }
        if let Some(parent) = pid.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&pid, std::process::id().to_string())?;
        Ok(Self { socket, pid })
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.pid);
    }
}

// ---------------------------------------------------------------------
// Backgrounding
// ---------------------------------------------------------------------

/// Re-runs this executable with the same arguments, detached from the
/// launching terminal, and returns the child's pid.
///
/// Deliberately a re-exec rather than `fork`. By the time `main` runs,
/// this process may already have spawned threads (cpal opens one for
/// audio; the global-hotkey backend runs its own), and `fork` in a
/// threaded process gives a child holding locks no thread will ever
/// release - the classic way a daemon deadlocks on its first allocation.
/// A re-exec starts from a clean single-threaded process, and is the same
/// code path on every OS this ships to.
///
/// stdout and stderr go to `~/.aloo/daemon.log`: a backgrounded daemon has
/// nowhere else to report a failure, and the failures worth knowing about
/// happen before anyone could attach to watch.
pub fn spawn_detached(log: &Path) -> Result<u32, BoxError> {
    use std::process::{Command, Stdio};

    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    let err = out.try_clone()?;

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args(std::env::args_os().skip(1))
        .env(DAEMON_CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` runs between fork and exec, where only
        // async-signal-safe calls are allowed. `setsid` is one of them.
        // It gives the child its own session with no controlling
        // terminal, which is what makes closing the launching terminal -
        // and the SIGHUP that comes with it - not reach the daemon.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    Ok(cmd.spawn()?.id())
}

/// Whether this process is the re-executed child (and so must not
/// background itself again).
pub fn is_daemon_child() -> bool {
    std::env::var_os(DAEMON_CHILD_ENV).is_some()
}

// ---------------------------------------------------------------------
// Serving viewers
// ---------------------------------------------------------------------

/// Accepts attach connections forever, turning each into `SessionInput`s
/// for the session loop and writing that loop's frames back out.
///
/// Runs as its own task for the daemon's whole life. One viewer at a time:
/// a second gets `Busy` and is closed. Multiplexing viewers would need a
/// shared cursor position and one agreed terminal size, which is a
/// different feature from resuming a session.
///
/// Errors are never propagated out of this loop. A daemon whose listener
/// task died would keep running with no way to reach it, which is worse
/// than any single failed connection - so a bad connection is dropped and
/// the loop continues.
pub async fn serve_attachments(
    mut listener: daemon_ipc::Listener,
    input_tx: tokio::sync::mpsc::UnboundedSender<SessionInput>,
) {
    loop {
        let Ok(stream) = listener.accept().await else {
            continue;
        };
        // Sequential, not spawned: serving one connection to completion
        // *is* the "one viewer at a time" rule. A second connection simply
        // waits in the accept backlog until the first finishes, which is
        // indistinguishable from being served and told `Busy` a moment
        // later, and needs no shared "is someone attached" state.
        if serve_one(stream, &input_tx).await.is_err() {
            // The viewer went away mid-conversation. Nothing to clean up
            // beyond what dropping the stream already did - the session
            // notices through its own `Detach`.
        }
        // Whatever happened, the session must stop drawing to a socket
        // that is now closed.
        let _ = input_tx.send(SessionInput::Detach);
    }
}

/// Handles one attach connection from its first message to its last.
async fn serve_one(
    stream: daemon_ipc::Stream,
    input_tx: &tokio::sync::mpsc::UnboundedSender<SessionInput>,
) -> Result<(), BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];

    // Frames the session renders, drained by the writer task below.
    // Held in an `Option` so the Attach handler can *move* it to the
    // session rather than cloning. That matters: a clone left behind here
    // would keep `frame_rx` open for the whole connection, so the session
    // dropping its writer on `/daemon` would close nothing, the writer
    // task would wait forever, and the viewer would never be told it had
    // been detached - it would simply hang.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let mut frame_tx = Some(frame_tx);
    // Lets the writer task tell "the session detached" (frames stop after
    // an attach) apart from "this connection never attached at all" (a
    // `--daemon-status` query), which look identical from `frame_rx`.
    let attached_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_attached = attached_flag.clone();
    // Replies this function itself needs to send (Attached, Status, ...),
    // funnelled through the same task so two writers never interleave
    // halfway through a frame.
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<DaemonMessage>();

    let writer = tokio::spawn(async move {
        // Frames stop first and replies stop last, so the loop ends on
        // `reply_rx` alone. Getting this the other way round loses the
        // goodbye: `Detached` is queued on `reply_rx` and *then* both
        // senders are dropped, so a writer that broke as soon as
        // `frame_rx` closed would exit with that reply still sitting in
        // the queue - and `aloo --daemon-stop` would print nothing.
        //
        // `biased` makes the choice deterministic rather than random:
        // replies are always drained before a closed frame channel is
        // even noticed. An unbounded receiver yields everything already
        // queued before it yields `None`, so nothing sent before the drop
        // can be missed.
        let mut frames_open = true;
        loop {
            let message = tokio::select! {
                biased;
                reply = reply_rx.recv() => match reply {
                    Some(reply) => reply,
                    None => break,
                },
                frame = frame_rx.recv(), if frames_open => match frame {
                    Some(bytes) => DaemonMessage::Frame(bytes),
                    None => {
                        frames_open = false;
                        // Frames stopping *after* an attach means the
                        // session let go of this viewer - `/daemon`, or
                        // the session ending. The viewer is waiting to be
                        // told, so tell it. Frames stopping without an
                        // attach is just a query connection that never
                        // had any, and needs no goodbye.
                        if writer_attached.load(std::sync::atomic::Ordering::Relaxed) {
                            DaemonMessage::Detached {
                                reason: "detached - the daemon is still running".to_string(),
                            }
                        } else {
                            continue;
                        }
                    }
                },
            };
            let Ok(bytes) = daemon_ipc::encode_frame(&message) else {
                continue;
            };
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let mut attached = false;
    loop {
        let read = rd.read(&mut chunk).await?;
        if read == 0 {
            break; // viewer closed the socket
        }
        buf.extend_from_slice(&chunk[..read]);

        while let Some((message, consumed)) = daemon_ipc::decode_frame::<AttachMessage>(&buf)? {
            buf.drain(..consumed);
            match message {
                AttachMessage::Attach {
                    cols,
                    rows,
                    supports_key_release: _,
                } => {
                    if attached {
                        continue; // a second Attach on one connection
                    }
                    attached = true;
                    attached_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    let _ = reply_tx.send(DaemonMessage::Attached);
                    let Some(frame_tx) = frame_tx.take() else {
                        continue;
                    };
                    let _ = input_tx.send(SessionInput::Attached {
                        writer: AttachWriter::new(frame_tx),
                        size: TerminalSize::new(cols, rows),
                    });
                }
                AttachMessage::Key(key) => {
                    let (code, modifiers, kind) = key.to_crossterm();
                    let _ = input_tx.send(SessionInput::Key(crossterm::event::Event::Key(
                        crossterm::event::KeyEvent::new_with_kind(code, modifiers, kind),
                    )));
                }
                AttachMessage::Resize { cols, rows } => {
                    let _ = input_tx.send(SessionInput::Resized(TerminalSize::new(cols, rows)));
                }
                AttachMessage::Detach => {
                    let _ = reply_tx.send(DaemonMessage::Detached {
                        reason: "detached".to_string(),
                    });
                    drop(reply_tx);
                    drop(frame_tx);
                    let _ = writer.await;
                    return Ok(());
                }
                AttachMessage::Status => {
                    let _ = reply_tx.send(DaemonMessage::Status(format!(
                        "aloo daemon running (pid {})",
                        std::process::id()
                    )));
                }
                AttachMessage::Shutdown => {
                    let _ = reply_tx.send(DaemonMessage::Detached {
                        reason: "daemon shutting down".to_string(),
                    });
                    let _ = input_tx.send(SessionInput::Shutdown);
                    drop(reply_tx);
                    drop(frame_tx);
                    let _ = writer.await;
                    return Ok(());
                }
            }
        }
    }

    drop(reply_tx);
    drop(frame_tx);
    let _ = writer.await;
    Ok(())
}

// ---------------------------------------------------------------------
// Attaching from a terminal
// ---------------------------------------------------------------------

/// Takes over a running daemon's session from this terminal, and gives it
/// back on `/daemon` or Ctrl+C.
///
/// This is the whole of `aloo` when a daemon is running: no `UiState`, no
/// keys, no network - a terminal borrowed to the process that has all of
/// that. Frames arrive rendered and are written to stdout verbatim;
/// keystrokes go the other way.
///
/// Ctrl+C is answered *here* rather than forwarded, and that is the point:
/// a viewer quitting its own window must never be able to kill the
/// session behind it. `aloo --daemon-stop` is how the daemon itself is
/// ended.
pub async fn run_attach_client(socket: &Path) -> Result<(), BoxError> {
    use tokio::io::AsyncWriteExt;

    let stream = daemon_ipc::connect(socket).await?;
    let (mut rd, mut wr) = tokio::io::split(stream);

    // A failure here, and a 0x0 answer from a pty nobody sized, are the
    // same thing: no idea. Resolved through `TerminalSize` before it goes
    // on the wire, so the daemon receives a size it can lay out against
    // rather than having to know this rule too.
    let reported = crossterm::terminal::size().unwrap_or((0, 0));
    let TerminalSize { cols, rows } = TerminalSize::new(reported.0, reported.1);
    let supports_key_release =
        crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    wr.write_all(&daemon_ipc::encode_frame(&AttachMessage::Attach {
        cols,
        rows,
        supports_key_release,
    })?)
    .await?;

    // The viewer's own terminal, set up and torn down by this process -
    // the daemon never touches it.
    let (mut terminal, _) = crate::client::tui::terminal::setup()?;
    let result = pump_attach(&mut rd, &mut wr).await;
    crate::client::tui::terminal::restore(&mut terminal)?;

    match result {
        Ok(reason) => {
            println!("aloo: {reason}");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// The attached client's two-way pump, split out so terminal setup and
/// restore bracket it on every exit path - including an error one, which
/// would otherwise leave the user's terminal in raw mode.
async fn pump_attach(
    rd: &mut (impl tokio::io::AsyncRead + Unpin),
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<String, BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut events = crate::client::tui::terminal::spawn_input_thread();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut stdout = std::io::stdout();

    loop {
        tokio::select! {
            read = rd.read(&mut chunk) => {
                let read = read?;
                if read == 0 {
                    return Ok("daemon closed the connection".to_string());
                }
                buf.extend_from_slice(&chunk[..read]);
                while let Some((message, consumed)) =
                    daemon_ipc::decode_frame::<DaemonMessage>(&buf)?
                {
                    buf.drain(..consumed);
                    match message {
                        // Written straight through: these bytes are ANSI
                        // the daemon already rendered for exactly this
                        // terminal's size.
                        DaemonMessage::Frame(bytes) => {
                            use std::io::Write;
                            stdout.write_all(&bytes)?;
                            stdout.flush()?;
                        }
                        DaemonMessage::Attached => {}
                        DaemonMessage::Busy => {
                            return Ok(
                                "another terminal is already attached to the daemon".to_string()
                            );
                        }
                        DaemonMessage::Detached { reason } => return Ok(reason),
                        DaemonMessage::Status(text) => return Ok(text),
                    }
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    return Ok("input ended".to_string());
                };
                let key = match event {
                    crossterm::event::Event::Key(key) => key,
                    // The daemon renders for *this* terminal and has no
                    // way to ask how big it is (its own stdout is
                    // /dev/null), so a viewer that resizes has to say so -
                    // otherwise every later frame stays laid out for the
                    // window that was there on attach.
                    crossterm::event::Event::Resize(cols, rows) => {
                        wr.write_all(&daemon_ipc::encode_frame(&AttachMessage::Resize {
                            cols,
                            rows,
                        })?)
                        .await?;
                        continue;
                    }
                    _ => continue,
                };
                // Answered locally, never forwarded - see this module's
                // `run_attach_client` doc.
                if key.code == crossterm::event::KeyCode::Char('c')
                    && key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                {
                    let _ = wr
                        .write_all(&daemon_ipc::encode_frame(&AttachMessage::Detach)?)
                        .await;
                    return Ok("detached - the daemon is still running".to_string());
                }
                let wire = daemon_ipc::KeyWire::from_crossterm(
                    key.code,
                    key.modifiers,
                    key.kind,
                );
                wr.write_all(&daemon_ipc::encode_frame(&AttachMessage::Key(wire))?)
                    .await?;
            }
        }
    }
}

/// Sends one message to a running daemon and prints its reply - what
/// `--daemon-status` and `--daemon-stop` are.
pub async fn send_control(socket: &Path, message: AttachMessage) -> Result<(), BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = daemon_ipc::connect(socket)
        .await
        .map_err(|_| "no aloo daemon is running")?;
    let (mut rd, mut wr) = tokio::io::split(stream);
    wr.write_all(&daemon_ipc::encode_frame(&message)?).await?;

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = rd.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..read]);
        while let Some((message, consumed)) = daemon_ipc::decode_frame::<DaemonMessage>(&buf)? {
            buf.drain(..consumed);
            match message {
                DaemonMessage::Status(text) | DaemonMessage::Detached { reason: text } => {
                    println!("aloo: {text}");
                    return Ok(());
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------

/// What a daemon with a server but no password is refused with
/// (`run`): the one credential a login needs, and nobody is there to
/// type it.
pub const NO_PASSWORD_ERROR: &str = "no password for the server - pass --server-pwd, or set \
                                     daemon_server_password in ~/.aloo/settings";

/// Everything a daemon needs to connect and place itself, once flags,
/// `~/.aloo/settings` and the connect cache have been folded together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub host: String,
    pub port: u16,
    pub nickname: String,
    /// The nickname's password (docs/PROTOCOL.md §5.1) - the one
    /// credential a login needs, and a daemon has nobody there to type
    /// it, so it comes from `--server-pwd` or `daemon_server_password`.
    pub password: String,
    /// Dial over TLS (`--ssl` / `daemon_ssl`).
    pub ssl: bool,
    pub my_key: crate::client::connect::MyKeySelection,
    /// The channels to join, in order. Never includes `the-hall` unless
    /// it was asked for - the whole point of daemon mode is to be in the
    /// places that matter rather than the default one.
    pub channels: Vec<DaemonChannel>,
    pub focus: Option<DaemonFocus>,
    /// Run with no server at all (`--no-server`): reachable only by the
    /// `direct_punch_to` peers in `~/.aloo/settings` (docs/PROTOCOL.md
    /// §7.1.5). Everything that needs a server is refused, by name, at the
    /// point it is asked for.
    pub no_server: bool,
}

/// The flags a daemon start can carry, straight off the command line.
/// Separated from `DaemonConfig` because every field is optional here:
/// this is "what the user said this time", which is only one of the three
/// inputs to what the daemon actually runs as.
#[derive(Debug, Clone, Default)]
pub struct DaemonFlags {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub nickname: Option<String>,
    pub server_pwd: Option<String>,
    pub ssl: bool,
    pub my_key_prefix: Option<String>,
    pub channels: Vec<String>,
    pub focus: Option<String>,
    pub otp: bool,
    pub no_server: bool,
}

impl DaemonConfig {
    /// Folds flags, settings and the connect cache into one configuration.
    ///
    /// Precedence is the rule `main.rs`'s `run_server` already set for the
    /// server's own flags: **a flag given this run wins; anything omitted
    /// falls back to `~/.aloo/settings`; anything still missing comes from
    /// the connect cache (the keybundle last connected with); and only
    /// then a compiled default.** That is what lets a bare `aloo --daemon`
    /// reproduce the last one exactly, which is what a systemd unit runs.
    ///
    /// Settings are consulted twice, in order: the `daemon_*` keys a
    /// previous daemon start wrote, then the `connect_*` keys the connect
    /// popup last recorded (`settings::Settings::remember_connection`).
    /// The second is what makes a first `--daemon` on a machine that has
    /// only ever been used interactively need no flags at all - it comes
    /// back on the same server, as the same person, rather than as `$USER`
    /// on a host it has to be told about again.
    ///
    /// A DM focus with no channels gets `the-hall` inserted, and says so.
    /// This is not a convenience: channel membership is the *only* way a
    /// client ever learns a peer exists (a `UserJoined` reaches only
    /// clients sharing a joined channel, and no message asks "is this
    /// nickname online?"), so a DM focus with nothing joined would wait
    /// for a peer it could never be told about.
    pub fn resolve(
        flags: &DaemonFlags,
        settings: &crate::settings::Settings,
        cache: &crate::client::connect::ConnectCache,
    ) -> Result<Self, String> {
        let cached = cache.most_recent();

        let host = flags
            .host
            .clone()
            .or_else(|| settings.daemon_host.clone())
            .or_else(|| settings.connect_host.clone())
            .or_else(|| cached.map(|(host, ..)| host.to_string()))
            // `--no-server` is the one start that legitimately has nowhere
            // to connect to, so it must not be held to this.
            .or_else(|| (flags.no_server || settings.daemon_no_server).then(String::new))
            .ok_or_else(|| {
                "no server to connect to - pass --host, set daemon_host in ~/.aloo/settings, \
                 connect once with plain `aloo` so the daemon can reuse it, or pass \
                 --no-server to run with none at all"
                    .to_string()
            })?;
        let port = flags
            .port
            .or(settings.daemon_port)
            .or(settings.connect_port)
            .or_else(|| cached.map(|(_, port, ..)| port))
            .unwrap_or(crate::settings::DEFAULT_PORT);
        let nickname = flags
            .nickname
            .clone()
            .or_else(|| settings.daemon_nickname.clone())
            .or_else(|| settings.connect_nickname.clone())
            .unwrap_or_else(local_display_name);

        let no_server = flags.no_server || settings.daemon_no_server;
        // Empty when nothing names one - a serverless daemon has nothing
        // to log in to, and for one with a server `run` refuses to start
        // before dialling rather than here, so a configuration can still
        // be resolved and shown without a password.
        let password = flags
            .server_pwd
            .clone()
            .or_else(|| settings.daemon_server_password.clone())
            .unwrap_or_default();
        let ssl = flags.ssl || settings.daemon_ssl;

        let my_key = resolve_my_key(flags, settings, cached)?;

        let mut channels = Vec::new();
        for value in &flags.channels {
            channels.extend(DaemonChannel::parse_list(value)?);
        }
        if channels.is_empty() {
            // One channel per settings line, so these are single items -
            // which is what lets a comma-bearing password live here.
            for value in &settings.daemon_channels {
                channels.push(DaemonChannel::parse(value)?);
            }
        }

        let focus_value = flags
            .focus
            .clone()
            .or_else(|| settings.daemon_focus.clone());
        let otp = flags.otp || settings.daemon_otp;
        let focus = match focus_value {
            Some(value) => Some(DaemonFocus::parse(&value, otp)?),
            None => None,
        };

        // A focused channel is one the daemon must actually be in.
        if let Some(DaemonFocus::Channel(name)) = &focus
            && !channels.iter().any(|c| &c.name == name)
        {
            channels.push(DaemonChannel::parse(name)?);
        }
        // See this function's doc: a DM focus needs somewhere to see the
        // person from.
        // ...but only where presence exists to be watched. With no server
        // a peer is found by punching at the address settings names, not by
        // being announced in a channel, and the hall is not a channel a
        // serverless client could join anyway - adding it would produce an
        // empty tab that can never fill (§7.1.5).
        if !(flags.no_server || settings.daemon_no_server)
            && matches!(focus, Some(DaemonFocus::Dm { .. }))
            && channels.is_empty()
        {
            crate::log_warn!(
                "no --channel given, so joining {} to watch for the focused peer - \
                 presence is only ever announced within a shared channel",
                crate::server::DEFAULT_CHANNEL_NAME
            );
            channels.push(DaemonChannel {
                name: crate::server::DEFAULT_CHANNEL_NAME.to_string(),
                password: None,
            });
        }

        Ok(Self {
            host,
            port,
            nickname,
            password,
            ssl,
            my_key,
            channels,
            focus,
            no_server,
        })
    }

    /// The `ConnectRequest` this configuration connects with - the same
    /// type the connect popup produces, so the handshake itself is shared
    /// rather than reimplemented headlessly.
    pub fn to_connect_request(&self) -> crate::client::connect::ConnectRequest {
        crate::client::connect::ConnectRequest {
            host: self.host.clone(),
            port: self.port,
            nickname: self.nickname.clone(),
            password: self.password.clone(),
            ssl: self.ssl,
            ssl_ca: None,
            my_key: self.my_key.clone(),
            activation_code: None,
        }
    }

    /// Whatever `run` needs true before it touches a socket: a server
    /// configuration with nothing to log in with is refused outright
    /// rather than dialling in with an empty password. Pure and
    /// side-effect-free so a test (or a scenario) can check it without
    /// spinning up the daemon's socket and single-instance lock.
    pub fn ensure_startable(&self) -> Result<(), String> {
        if !self.no_server && self.password.is_empty() {
            return Err(NO_PASSWORD_ERROR.to_string());
        }
        Ok(())
    }

    /// Writes this configuration back to `~/.aloo/settings` so the next
    /// bare `aloo --daemon` - the one a systemd unit runs at boot -
    /// reproduces it. Uses the merging writer, never a whole-struct save,
    /// for the reason `Settings::update` documents.
    pub fn persist(&self, path: &Path) -> std::io::Result<()> {
        let channels: Vec<String> = self.channels.iter().map(|c| c.to_setting()).collect();
        let focus = self.focus.as_ref().map(|f| match f {
            DaemonFocus::Channel(name) => format!("channel:{name}"),
            DaemonFocus::Dm { nickname, .. } => nickname.clone(),
        });
        let otp = matches!(self.focus, Some(DaemonFocus::Dm { otp: true, .. }));
        crate::settings::Settings::update(path, |s| {
            s.daemon_no_server = self.no_server;
            // A serverless daemon has no host, and writing the empty one it
            // stands in for would leave the next bare `--daemon` start
            // resolving a host that is not a host. Whatever was recorded
            // before is left alone instead: it costs nothing, and it is
            // what a later start *with* a server should find.
            if !self.no_server {
                s.daemon_host = Some(self.host.clone());
            }
            s.daemon_port = Some(self.port);
            s.daemon_nickname = Some(self.nickname.clone());
            s.daemon_channels = channels;
            s.daemon_focus = focus;
            s.daemon_otp = otp;
            if !self.password.is_empty() {
                s.daemon_server_password = Some(self.password.clone());
            }
            s.daemon_ssl = self.ssl;
            s.set_daemon_my_key(&self.my_key);
        })
    }
}

/// Resolves the `my_key` identity: an explicit `--my-key <PREFIX>` names
/// `<PREFIX>.pub`/`<PREFIX>.priv`, otherwise the settings pair, otherwise
/// whatever the connect cache last used for this host, otherwise a fresh
/// location under `~/.aloo`.
///
/// Always `pq_hybrid`. A daemon connects with no one watching, and this is
/// the only identity type that needs no typed secret and no prompt -
/// `crypto::pq::ensure_bundle_at` generates the keybundle on first connect
/// if it is not there yet, so a fresh machine needs no keygen step.
fn resolve_my_key(
    flags: &DaemonFlags,
    settings: &crate::settings::Settings,
    cached: Option<(&str, u16, &str, &str)>,
) -> Result<crate::client::connect::MyKeySelection, String> {
    if let Some(prefix) = &flags.my_key_prefix {
        return Ok(crate::client::connect::MyKeySelection {
            file_pub: PathBuf::from(format!("{prefix}.pub")),
            file_priv: PathBuf::from(format!("{prefix}.priv")),
        });
    }
    if let (Some(file_pub), Some(file_priv)) =
        (&settings.daemon_my_key_pub, &settings.daemon_my_key_priv)
    {
        return Ok(crate::client::connect::MyKeySelection {
            file_pub: PathBuf::from(file_pub),
            file_priv: PathBuf::from(file_priv),
        });
    }
    if let Some((_, _, file_pub, file_priv)) = cached {
        return Ok(crate::client::connect::MyKeySelection {
            file_pub: PathBuf::from(file_pub),
            file_priv: PathBuf::from(file_priv),
        });
    }
    let (file_pub, file_priv) =
        crate::client::connect::fresh_pq_hybrid_paths_in(&crate::platform::aloo_dir());
    Ok(crate::client::connect::MyKeySelection {
        file_pub,
        file_priv,
    })
}

fn local_display_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anon".to_string())
}

// ---------------------------------------------------------------------
// The join / focus plan
// ---------------------------------------------------------------------

/// What a daemon does once it is connected: join these channels, put the
/// focus there, and watch for the person it was told to watch for.
///
/// Held on `SessionState` and consulted from the handlers that already
/// exist (`ChannelList`, `Joined`, `UserJoined`, `UserLeft`,
/// `UserOffline`). Every hook is additive: with no plan - which is every
/// foreground `aloo` - none of them change anything.
#[derive(Debug, Clone)]
pub struct DaemonPlan {
    pub channels: Vec<DaemonChannel>,
    pub focus: Option<DaemonFocus>,
    /// Whether the initial join requests have gone out. The server sends
    /// `ChannelList` once at connect, but a client also gets one for
    /// channels created later - this makes sure the plan is executed once,
    /// not re-executed every time the directory changes.
    pub joins_requested: bool,
    /// Set once the focus has actually been placed, so a peer rejoining a
    /// channel later does not re-steal the focus from wherever the user
    /// has since moved it while attached.
    pub focus_applied: bool,
    /// Set once an OTP session has been proposed for a DM focus, so a
    /// peer flapping does not propose one repeatedly.
    pub otp_requested: bool,
}

impl DaemonPlan {
    pub fn new(channels: Vec<DaemonChannel>, focus: Option<DaemonFocus>) -> Self {
        Self {
            channels,
            focus,
            joins_requested: false,
            focus_applied: false,
            otp_requested: false,
        }
    }

    /// The nickname a DM focus is waiting for, if that is what this plan
    /// is focused on.
    pub fn focused_nickname(&self) -> Option<&str> {
        match &self.focus {
            Some(DaemonFocus::Dm { nickname, .. }) => Some(nickname.as_str()),
            _ => None,
        }
    }

    /// The channel this plan focuses, if any.
    pub fn focused_channel(&self) -> Option<&str> {
        match &self.focus {
            Some(DaemonFocus::Channel(name)) => Some(name.as_str()),
            _ => None,
        }
    }

    /// Whether an OTP session should be proposed the moment the focused
    /// peer appears.
    pub fn wants_otp(&self) -> bool {
        matches!(self.focus, Some(DaemonFocus::Dm { otp: true, .. }))
    }

    /// Whether someone arriving should be announced out loud
    /// (`assets/joined.wav`).
    ///
    /// The sound exists for one situation: nobody is looking at aloo, and
    /// something changed where your voice is currently pointed. Every
    /// condition below narrows it to exactly that.
    ///
    /// - **`daemon_mode`** - a foreground client shows the arrival in its
    ///   own log, where a sound would only be noise.
    /// - **`viewer_attached`** - while a terminal is watching, the arrival
    ///   is on screen already. The sound is for when it is not.
    /// - **`focus`** - the *current* focus, not the `--focus` the daemon
    ///   started with. Those agree until someone attaches and moves, and
    ///   after that only the live one is worth announcing: it is where a
    ///   held shortcut actually goes.
    /// - **`already_announced`** (DM focus only) - a peer joining two
    ///   channels you share produces two `UserJoined`, and "alice is
    ///   online" is one event however many rooms it arrives through.
    ///   Reset when they go offline, so their next arrival is announced
    ///   again.
    ///
    /// A channel focus needs no such guard: `UserJoined` names one
    /// channel, so only arrivals into the focused one match at all, and
    /// each is a genuinely separate event worth hearing.
    ///
    /// Free of `self` because it depends on the live session rather than
    /// the plan - kept here beside the other daemon decisions, and pure so
    /// a scenario can drive it without a connection.
    pub fn should_play_joined_chime(
        daemon_mode: bool,
        viewer_attached: bool,
        focus: &crate::client::tui::ui::CurrentFocus,
        joining_peer: crate::proto::UserId,
        joining_channel: Option<&str>,
        already_announced: bool,
    ) -> bool {
        use crate::client::tui::ui::CurrentFocus;
        if !daemon_mode || viewer_attached {
            return false;
        }
        match focus {
            // A peer who arrived through no channel at all - punched
            // directly, sharing none (§7.1.5) - cannot be the arrival the
            // *channel* in focus was waiting for.
            CurrentFocus::Channel(name) => joining_channel == Some(name.as_str()),
            CurrentFocus::Dm(peer) => *peer == joining_peer && !already_announced,
            CurrentFocus::Nowhere => false,
        }
    }

    /// Whether the focus still needs placing - true until it has been
    /// placed once, false forever after.
    ///
    /// `--focus` is a *starting* position, not a standing instruction. It
    /// answers "where should a held shortcut go when this daemon comes
    /// up", and once that question has been answered, where the focus sits
    /// belongs to whoever is driving the session: someone who attaches,
    /// moves to another channel or DM, and detaches again has said where
    /// they want to be, and the daemon must not overrule them.
    ///
    /// This is why it is a latch rather than a re-check. The events that
    /// would otherwise re-place it are ordinary and frequent - a focused
    /// peer's connection dropping and coming back, or a focused channel
    /// being rejoined - and each one would silently move where the next
    /// held shortcut sends your voice, which is the one thing about this
    /// mode that must never be surprising.
    ///
    /// A DM focus may well be placed long after startup: the person has to
    /// appear first, and until they do there is nothing to focus. "Once"
    /// means the first opportunity, not the first instant.
    pub fn should_place_focus(&self) -> bool {
        !self.focus_applied
    }

    /// Whether `--otp` should send an *invitation* to `nickname`, given
    /// whether a session with them is already live.
    ///
    /// `--otp` asks for a session to exist, which since `docs/PROTOCOL.md`
    /// §16.6 is two different jobs. A session outlives both sides
    /// disconnecting and even an app restart - only `/endotp` ends one -
    /// and the client resumes it automatically the moment the peer
    /// reappears. Inviting on top of that would put an Accept/Reject popup
    /// in front of someone already in the session, and spend a fresh pad
    /// handshake to arrive back where they started. So an active session
    /// is continued in silence, and only a peer without one is invited.
    ///
    /// At most one invitation per daemon run (`otp_requested`): a peer on
    /// a flapping connection must not turn into a queue of popups.
    ///
    /// A pure decision, split out from the session handler that acts on it
    /// so it is testable without a live connection - the same split
    /// `global_ptt::is_wayland_session` and `connect::prefer_ipv4` use.
    pub fn should_invite_otp(&self, nickname: &str, already_active: bool) -> bool {
        self.wants_otp()
            && self.focused_nickname() == Some(nickname)
            && !self.otp_requested
            && !already_active
    }

    /// Whether someone appearing in `channel` under `nickname` is an
    /// event this plan cares about - what decides whether the join sound
    /// and the notification fire.
    ///
    /// A DM focus cares about exactly one person, wherever they turn up.
    /// A channel focus cares about anyone arriving in that channel, which
    /// is the honest reading of "a user where I have the focus on joins":
    /// the focus is the channel, so its arrivals are its events.
    pub fn is_focus_event(&self, nickname: &str, channel: Option<&str>) -> bool {
        match &self.focus {
            Some(DaemonFocus::Dm { nickname: want, .. }) => nickname == want,
            Some(DaemonFocus::Channel(want)) => channel == Some(want.as_str()),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------

/// Connects and runs the session, detached, until it ends.
///
/// The whole of daemon mode's difference from an ordinary client lives in
/// the three arguments this passes on: a `Detached` surface instead of a
/// terminal, an input stream fed by attaching viewers instead of stdin,
/// and a `DaemonPlan`. Everything else - the handshake, the session loop,
/// the UI state - is shared code, which is what keeps the two modes from
/// drifting apart.
///
/// `hotkey_rx` is registered by the caller rather than here, because on
/// macOS it can only be registered on the process's real main thread -
/// see `main.rs`'s `with_global_ptt`. `None` means no global shortcut,
/// which a daemon warns about below.
pub async fn run(
    config: DaemonConfig,
    hotkey_rx: Option<
        tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>,
    >,
) -> Result<(), BoxError> {
    config.ensure_startable()?;
    let instance =
        SingleInstance::acquire(daemon_ipc::socket_path(), daemon_ipc::pid_path()).await?;
    let listener = daemon_ipc::bind_listener(&daemon_ipc::socket_path())?;

    // Persisted *before* connecting, not after: a bare `aloo --daemon` at
    // the next boot must reproduce this configuration even if this start
    // is the one that fails, since a failed start is exactly when the
    // user will re-run it.
    if let Err(e) = config.persist(&crate::settings::default_path()) {
        crate::log_warn!("could not persist daemon settings to ~/.aloo/settings ({e})");
    }

    let mut request = config.to_connect_request();
    // The extra trusted roots for `ssl` live only in settings
    // (`connect_ssl_ca`), read here the same way the connect popup's path
    // reads them - never persisted as part of the daemon's own keys.
    request.ssl_ca = crate::settings::Settings::load_or_create(&crate::settings::default_path())
        .ok()
        .and_then(|s| s.connect_ssl_ca)
        .as_deref()
        .map(crate::platform::expand_tilde);
    // With `--no-server` there is nobody to hand us a `UserId`, no control
    // channel to open and no rendezvous to ask - only local key material
    // and the peers `direct_punch_to` names (docs/PROTOCOL.md §7.1.5). The
    // identity resolution is the very same one a connecting client does;
    // all that is skipped is the part that needed somewhere to connect to.
    let serverless = config.no_server;
    let (server_events, wr, you, identity, server_addr) = if serverless {
        let identity = crate::client::connect::resolve_my_keypair(&request.my_key)?;
        (
            None,
            ServerlessSink::Null(crate::control::NullSink),
            crate::client::p2p::direct_peer_id(&request.nickname),
            identity,
            None,
        )
    } else {
        // A daemon is the start that most needs reconnecting: nobody is
        // watching it, and the session it would otherwise sit out is one
        // whose peers can still hear it (`docs/PROTOCOL.md` §4.2).
        let (events, sink, you, identity, server_addr) =
            crate::client::connect::connect_with_reconnect(&request).await?;
        (
            Some(events),
            ServerlessSink::Server(sink),
            you,
            identity,
            Some(server_addr),
        )
    };

    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve_attachments(listener, input_tx));

    if serverless {
        crate::log_warn!(
            "daemon started as {} with no server (pid {}) - reachable \
             only by the direct_punch_to peers in ~/.aloo/settings",
            config.nickname,
            std::process::id()
        );
    } else {
        crate::log_warn!(
            "daemon connected to {}:{} as {} (pid {})",
            config.host,
            config.port,
            config.nickname,
            std::process::id()
        );
    }

    let id_store =
        crate::client::idstore::IdStore::load(&crate::client::idstore::default_path()).unwrap_or_else(|_| {
            crate::client::idstore::IdStore::new_empty(crate::client::idstore::default_path())
        });
    if hotkey_rx.is_none() {
        // Not fatal - the session is still worth running, and someone can
        // still attach and hold Space - but it is the one thing a daemon
        // exists for, so it must not fail silently into a log nobody
        // reads.
        crate::log_warn!(
            "the global push-to-talk shortcut is not available - \
             this daemon can be attached to, but the shortcut will not fire"
        );
        crate::client::global_notification::notify(
            crate::client::global_notification::Notification::new(
                "aloo: no global shortcut",
                "The daemon is connected, but push-to-talk from other apps is unavailable.",
            ),
        );
    }

    let mut surface = crate::client::tui::surface::Surface::Detached;
    let plan = DaemonPlan::new(config.channels.clone(), config.focus.clone());
    let result = crate::client::session::run_daemon_session(
        &mut surface,
        server_events,
        wr,
        request.nickname.clone(),
        you,
        identity,
        id_store,
        hotkey_rx,
        server_addr,
        input_rx,
        plan,
    )
    .await;

    drop(instance);
    result
}

/// The control channel a daemon writes to: a real one, or nothing at all
/// under `--no-server`. One type rather than a generic parameter on `run`,
/// since the choice is made at runtime from configuration.
enum ServerlessSink {
    Server(crate::client::reconnect::ServerSink),
    Null(crate::control::NullSink),
}

impl crate::control::ControlSink for ServerlessSink {
    async fn send_control(
        &mut self,
        msg: &crate::proto::ClientMessage,
    ) -> crate::proto::Result<()> {
        match self {
            Self::Server(w) => w.send_control(msg).await,
            Self::Null(n) => n.send_control(msg).await,
        }
    }
}

/// Plays the "this did not start" tone and reports why.
///
/// The one thing a daemon owes a user who is not watching: a boot where it
/// silently failed to come up is indistinguishable from one where it
/// worked until the moment you press the shortcut and nothing happens.
pub fn report_startup_failure(error: &dyn std::fmt::Display) {
    crate::log_warn!("daemon failed to start: {error}");
    crate::client::global_notification::notify(
        crate::client::global_notification::Notification::new(
            "aloo daemon failed to start",
            error.to_string(),
        ),
    );
    // `bell.wav`, the app's existing "something needs you" sound, played
    // through a mixer of its own - there is no session to borrow one from,
    // and the process is about to exit, so this has to wait for the sound
    // to actually be audible (`play_samples_blocking`).
    crate::client::voice::play_samples_blocking(crate::client::voice::bell_chime_samples());
}
