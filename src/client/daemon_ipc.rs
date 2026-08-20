//! The local control channel between a running daemon and an `aloo`
//! attaching to it (`docs/SPEC.md` "Running in background mode").
//!
//! Deliberately *not* the wire protocol. This never leaves the machine: a
//! Unix domain socket at `~/.aloo/daemon.sock`, or a named pipe on
//! Windows. What travels on it is a rendered frame in one direction and a
//! keystroke in the other - things the peer-to-peer protocol has no
//! concept of and must never grow one.
//!
//! Framing and encoding are reused wholesale from `crate::proto`
//! (4-byte big-endian length prefix, bincode payload) rather than invented
//! again. There is no encryption and no authentication: the socket's file
//! permissions *are* the access control, which is why `bind_listener`
//! creates it `0600` and `connect` refuses a socket this user does not
//! own.
//!
//! ## Trust boundary
//!
//! Whoever can write to this socket controls the session completely: they
//! see every message in it and can send voice, text and files as the user.
//! That is a strictly larger capability than reading `~/.aloo/settings`
//! (which only leaks stored secrets), so it is worth stating plainly -
//! see `docs/SECURITY.md`.

use std::io;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use serde::{Deserialize, Serialize};

/// Where the daemon listens: `~/.aloo/daemon.sock`, resolved the same way
/// as every other file this app owns (`crate::platform::aloo_dir`, and so
/// honouring `ALOO_HOME` - two daemons under two `ALOO_HOME`s are two
/// independent instances, exactly as the rest of the state store already
/// behaves).
pub fn socket_path() -> PathBuf {
    crate::platform::aloo_dir().join("daemon.sock")
}

/// Where the daemon records its process id, next to the socket. Read only
/// to tell a live daemon from the socket file a killed one left behind,
/// and to name the pid in the "already running" message.
pub fn pid_path() -> PathBuf {
    crate::platform::aloo_dir().join("daemon.pid")
}

/// Where a backgrounded daemon's stdout and stderr go. A daemon has no
/// terminal to complain to, and the failures worth knowing about (could
/// not reach the server, nickname taken, hotkey registration refused)
/// happen before anyone could attach to see them.
pub fn log_path() -> PathBuf {
    crate::platform::aloo_dir().join("daemon.log")
}

// ---------------------------------------------------------------------
// Key events, on the wire
// ---------------------------------------------------------------------

/// One key press, as it travels from the attached client to the daemon.
///
/// A hand-written mirror of the `crossterm` types rather than a
/// `serde`-derived copy of them: crossterm's own serde support is not
/// enabled in this build, and turning it on would put its entire event
/// enum - mouse events, paste events, focus events, every future variant -
/// on a wire that only ever needs the handful of things
/// `UiState::handle_key` looks at. Anything this cannot express is
/// something the daemon would have ignored anyway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWire {
    pub code: KeyCodeWire,
    /// `crossterm::event::KeyModifiers`' raw bits.
    pub modifiers: u8,
    pub kind: KeyKindWire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyCodeWire {
    Char(char),
    Enter,
    Esc,
    Backspace,
    Tab,
    BackTab,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    Insert,
    F(u8),
    /// Anything this enum does not name. Kept as a variant rather than
    /// dropped at the sender so the daemon still sees *a* key event where
    /// one happened - `handle_key` ignores it, exactly as it ignores the
    /// unnamed `KeyCode` variants today.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyKindWire {
    Press,
    Repeat,
    Release,
}

impl KeyWire {
    pub fn from_crossterm(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> Self {
        Self {
            code: KeyCodeWire::from_crossterm(code),
            modifiers: modifiers.bits(),
            kind: match kind {
                KeyEventKind::Press => KeyKindWire::Press,
                KeyEventKind::Repeat => KeyKindWire::Repeat,
                KeyEventKind::Release => KeyKindWire::Release,
            },
        }
    }

    pub fn to_crossterm(&self) -> (KeyCode, KeyModifiers, KeyEventKind) {
        (
            self.code.to_crossterm(),
            // `from_bits_truncate`, not `from_bits`: a daemon and a client
            // built from different revisions could disagree about which
            // modifier bits exist, and dropping an unknown bit is right
            // where refusing the whole keystroke would not be.
            KeyModifiers::from_bits_truncate(self.modifiers),
            match self.kind {
                KeyKindWire::Press => KeyEventKind::Press,
                KeyKindWire::Repeat => KeyEventKind::Repeat,
                KeyKindWire::Release => KeyEventKind::Release,
            },
        )
    }
}

impl KeyCodeWire {
    pub fn from_crossterm(code: KeyCode) -> Self {
        match code {
            KeyCode::Char(c) => Self::Char(c),
            KeyCode::Enter => Self::Enter,
            KeyCode::Esc => Self::Esc,
            KeyCode::Backspace => Self::Backspace,
            KeyCode::Tab => Self::Tab,
            KeyCode::BackTab => Self::BackTab,
            KeyCode::Left => Self::Left,
            KeyCode::Right => Self::Right,
            KeyCode::Up => Self::Up,
            KeyCode::Down => Self::Down,
            KeyCode::Home => Self::Home,
            KeyCode::End => Self::End,
            KeyCode::PageUp => Self::PageUp,
            KeyCode::PageDown => Self::PageDown,
            KeyCode::Delete => Self::Delete,
            KeyCode::Insert => Self::Insert,
            KeyCode::F(n) => Self::F(n),
            _ => Self::Other,
        }
    }

    pub fn to_crossterm(&self) -> KeyCode {
        match self {
            Self::Char(c) => KeyCode::Char(*c),
            Self::Enter => KeyCode::Enter,
            Self::Esc => KeyCode::Esc,
            Self::Backspace => KeyCode::Backspace,
            Self::Tab => KeyCode::Tab,
            Self::BackTab => KeyCode::BackTab,
            Self::Left => KeyCode::Left,
            Self::Right => KeyCode::Right,
            Self::Up => KeyCode::Up,
            Self::Down => KeyCode::Down,
            Self::Home => KeyCode::Home,
            Self::End => KeyCode::End,
            Self::PageUp => KeyCode::PageUp,
            Self::PageDown => KeyCode::PageDown,
            Self::Delete => KeyCode::Delete,
            Self::Insert => KeyCode::Insert,
            Self::F(n) => KeyCode::F(*n),
            // `Null` is crossterm's own "nothing meaningful" code, which
            // `handle_key` already falls through on.
            Self::Other => KeyCode::Null,
        }
    }
}

// ---------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------

/// Client -> daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachMessage {
    /// Always the first message. `supports_key_release` is the attaching
    /// terminal's own answer, not the daemon's - a daemon has no terminal
    /// to ask, and the answer decides whether a held Space is allowed to
    /// be auto-released on silence (`UiState::tick_recording_timeout`).
    Attach {
        cols: u16,
        rows: u16,
        supports_key_release: bool,
    },
    Key(KeyWire),
    Resize { cols: u16, rows: u16 },
    /// The viewer is leaving; the daemon keeps running. Sent on Ctrl+C in
    /// the attached terminal, which the client answers itself rather than
    /// forwarding - so quitting a viewer can never kill the session.
    Detach,
    /// Ask for a one-line summary without attaching (`--daemon-status`).
    Status,
    /// Ask the daemon to shut down (`--daemon-stop`).
    Shutdown,
}

/// Daemon -> client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonMessage {
    /// The attach was accepted; frames follow.
    Attached,
    /// Someone else is already attached. Only one viewer at a time: two
    /// would need a shared cursor and a shared idea of the terminal size,
    /// which is a different feature from resuming a session.
    Busy,
    /// One complete frame of ANSI, to be written to the viewer's stdout
    /// verbatim.
    Frame(Vec<u8>),
    /// The daemon ended the attachment - `/daemon` was typed, or it is
    /// shutting down. Carries the reason so the client can say which.
    Detached { reason: String },
    Status(String),
}

// ---------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------

/// Encodes one message with the same 4-byte big-endian length prefix and
/// bincode payload `crate::proto` uses on the network.
pub fn encode_frame<T: Serialize>(msg: &T) -> crate::proto::Result<Vec<u8>> {
    crate::proto::frame(&crate::proto::encode(msg)?)
}

/// Pulls the first complete message out of `buf`, returning it and how
/// many bytes it consumed. `Ok(None)` means "not enough bytes yet".
pub fn decode_frame<T: for<'de> Deserialize<'de>>(
    buf: &[u8],
) -> crate::proto::Result<Option<(T, usize)>> {
    let Some((payload, consumed)) = crate::proto::parse_frame(buf)? else {
        return Ok(None);
    };
    Ok(Some((crate::proto::decode(payload)?, consumed)))
}

// ---------------------------------------------------------------------
// Socket lifecycle
// ---------------------------------------------------------------------

/// The longest a Unix socket path may be, in bytes.
///
/// Not a limit this app chose: `sockaddr_un.sun_path` is a fixed 108-byte
/// array on Linux (104 on the BSDs and macOS), so the kernel refuses
/// anything longer. 100 is the conservative floor across both, leaving
/// room for the terminating NUL.
#[cfg(unix)]
pub const MAX_SOCKET_PATH_LEN: usize = 100;

/// Refuses an over-long socket path with an error that says what to do
/// about it.
///
/// The raw failure is `path must be shorter than SUN_LEN`, which names a C
/// constant and nothing a user can act on. The path is only ever this long
/// because `ALOO_HOME` points somewhere deep, so that is what the message
/// names - and it is checked here, up front, rather than left to surface
/// from inside `bind` where it reads as an unexplained refusal to start.
#[cfg(unix)]
pub fn check_socket_path_length(path: &Path) -> io::Result<()> {
    let len = path.as_os_str().len();
    if len <= MAX_SOCKET_PATH_LEN {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "the daemon's socket path is too long for this system: {len} bytes, \
             and a Unix socket path cannot exceed {MAX_SOCKET_PATH_LEN}.\n  {}\n\
             This is normally only reachable by pointing ALOO_HOME at a deep \
             directory - set it somewhere shorter and start the daemon again.",
            path.display()
        ),
    ))
}

/// Whether a daemon is listening on `path` *right now*.
///
/// Answered by actually connecting, not by the socket file existing: a
/// daemon killed with SIGKILL leaves the file behind, and a stale file is
/// indistinguishable from a live one by inspection alone. A refused
/// connection means the file is debris.
pub async fn is_daemon_running(path: &Path) -> bool {
    connect(path).await.is_ok()
}

#[cfg(unix)]
pub async fn connect(path: &Path) -> io::Result<ClientStream> {
    // Refuse a socket this user does not own before speaking to it: it
    // would otherwise be a way for another local account to feed a chosen
    // session to whoever ran `aloo`.
    if let Ok(meta) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `getuid` is always safe - it reads a process property
        // and cannot fail.
        let own = unsafe { libc::getuid() };
        if meta.uid() != own {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not owned by this user", path.display()),
            ));
        }
    }
    tokio::net::UnixStream::connect(path).await
}

/// Binds the daemon's listening socket, replacing a stale socket file if
/// one is there.
///
/// The permissions are the security model, so they are applied with
/// `set_permissions` immediately after binding rather than left to the
/// process umask - a permissive umask would otherwise publish the session
/// to every account on the machine. There is a brief window between bind
/// and chmod; closing it entirely would mean binding inside a
/// private-mode directory, and `~/.aloo` is already the user's own.
#[cfg(unix)]
pub fn bind_listener(path: &Path) -> io::Result<Listener> {
    check_socket_path_length(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Only ever removes a socket nothing is listening on - callers check
    // `is_daemon_running` first, which is what distinguishes debris from a
    // second daemon.
    let _ = std::fs::remove_file(path);
    let inner = tokio::net::UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(Listener { inner })
}

/// Windows has no Unix domain sockets; a named pipe is the equivalent
/// local, permissioned channel. Scoped by username so two accounts on one
/// machine get two independent daemons, the same separation the socket's
/// `0600` gives on Unix.
#[cfg(windows)]
pub fn pipe_name() -> String {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
    format!(r"\\.\pipe\aloo-daemon-{user}")
}

#[cfg(windows)]
pub async fn connect(_path: &Path) -> io::Result<ClientStream> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name())
}

/// The first pipe instance, which is what makes the name exist at all -
/// `first_pipe_instance` is the flag that refuses a *second* process
/// claiming the same name, so this is also Windows' half of the
/// single-instance check the socket file performs on Unix. Every later
/// instance is created by `Listener::accept`.
#[cfg(windows)]
pub fn bind_listener(_path: &Path) -> io::Result<Listener> {
    let pending = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_name())?;
    Ok(Listener { pending })
}

// ---------------------------------------------------------------------
// One shape for two transports
// ---------------------------------------------------------------------

/// A live attach connection, as the daemon holds it: the accepted end of
/// a Unix socket, or the connected pipe instance on Windows. Both are
/// `AsyncRead + AsyncWrite`, which is all `serve_attachments` ever asks
/// of them.
#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;
#[cfg(windows)]
pub type Stream = tokio::net::windows::named_pipe::NamedPipeServer;

/// The same connection as the *viewer* holds it. Identical to `Stream` on
/// Unix, where one type is both ends of a socket; Windows names the two
/// ends apart, so the attaching client gets its own alias.
#[cfg(unix)]
pub type ClientStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;

/// What the daemon accepts attaching viewers on.
///
/// A type of its own rather than the platform's listener directly,
/// because the two do not have the same shape: a Unix listener accepts
/// connections while staying itself, whereas a named pipe *is* one
/// connection and the server has to keep a fresh idle instance ready
/// behind it. `accept` hides that difference, so the daemon's serve loop
/// is one piece of code on both.
#[derive(Debug)]
pub struct Listener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(windows)]
    pending: tokio::net::windows::named_pipe::NamedPipeServer,
}

impl Listener {
    /// Waits for the next viewer and hands back its connection.
    ///
    /// The peer address a Unix `accept` also returns is dropped: an
    /// attach socket has no meaningful peer name (it is unnamed, and the
    /// permissions are what say who may connect), and there is nothing
    /// equivalent to hand back on Windows.
    #[cfg(unix)]
    pub async fn accept(&mut self) -> io::Result<Stream> {
        let (stream, _peer) = self.inner.accept().await?;
        Ok(stream)
    }

    /// Windows: waiting *is* `connect` on the idle instance, and the
    /// instance that just connected is the connection. A replacement is
    /// created before this returns rather than at the top of the next
    /// `accept`, so the name never goes momentarily unservable: a second
    /// viewer arriving while the first is being served connects to the
    /// replacement and waits there, which is what the socket's accept
    /// backlog does on Unix.
    #[cfg(windows)]
    pub async fn accept(&mut self) -> io::Result<Stream> {
        self.pending.connect().await?;
        let next = tokio::net::windows::named_pipe::ServerOptions::new().create(pipe_name())?;
        Ok(std::mem::replace(&mut self.pending, next))
    }
}
