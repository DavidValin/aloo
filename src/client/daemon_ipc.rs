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
//! again. There is no encryption and no authentication: access control
//! *is* the transport's own permissions, on both platforms, achieved by
//! different means - Unix's `bind_listener` creates the socket `0600` and
//! `connect` refuses one this user does not own; Windows' `bind_listener`
//! grants the pipe's DACL to its creator alone (SDDL `D:(A;;GA;;;OW)`) and
//! `connect` refuses a pipe whose owning process's token names a different
//! user's SID.
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

/// A security descriptor allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, released
/// (`LocalFree`) on drop - the cleanup that function's own docs require of
/// its caller.
#[cfg(windows)]
struct OwnedSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `self.0` was allocated by
        // ConvertStringSecurityDescriptorToSecurityDescriptorW below, whose
        // docs name LocalFree as the required release.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(
                self.0 as windows_sys::Win32::Foundation::HLOCAL,
            );
        }
    }
}

/// A security descriptor whose DACL grants access to nobody but the pipe's
/// own creator - `bind_listener`'s counterpart to the Unix side's `0600`.
/// SDDL `"D:(A;;GA;;;OW)"`: a DACL (`D:`) with one ACE granting (`A;;`)
/// generic-all (`GA`) to `OWNER_RIGHTS` (`OW`), SDDL's alias for "whoever
/// creates this object" - so no SID lookup is needed to name the current
/// user explicitly, the same way Unix's `0600` needs no uid named in it
/// either.
#[cfg(windows)]
fn owner_only_security_descriptor() -> io::Result<OwnedSecurityDescriptor> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    let sddl: Vec<u16> = "D:(A;;GA;;;OW)\0".encode_utf16().collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: `sddl` is a valid NUL-terminated UTF-16 string for the
    // duration of this call; `descriptor` is an out-param this API
    // populates only when it returns nonzero, checked immediately below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedSecurityDescriptor(descriptor))
}

/// The `Sid` bytes copied out of `process`'s own token (`TOKEN_USER`, via
/// `OpenProcessToken` + the standard two-call `GetTokenInformation` sizing
/// dance), so the caller can compare SIDs (`EqualSid`) without keeping the
/// token buffer itself alive.
#[cfg(windows)]
fn process_user_sid(process: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::OpenProcessToken;

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid, open handle for the duration of this
    // call; `token` is an out-param populated only on success.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut needed = 0u32;
    // SAFETY: a null buffer with a zero length is the documented way to
    // ask GetTokenInformation how large a buffer it actually needs; it
    // always reports failure here (ERROR_INSUFFICIENT_BUFFER) by design -
    // only the `needed` out-param this call fills in is used.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
    // A `u64`-backed buffer, not `Vec<u8>`: `TOKEN_USER` holds a `PSID`
    // pointer field, and reading one back through a buffer that isn't
    // guaranteed pointer-aligned (a `Vec<u8>`'s allocation only promises
    // 1-byte alignment) is undefined behavior even where it happens to
    // work in practice.
    let mut buf: Vec<u64> = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `needed` bytes, matching what the
    // sizing call above reported.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            needed,
            &mut needed,
        )
    };
    // SAFETY: `token` was opened above and is closed exactly once, here,
    // regardless of whether the call below succeeded.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `buf` holds a fully-populated TOKEN_USER as of the
    // successful call above; the `Sid` it names points within that same
    // allocation, which `buf` still owns.
    let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
    let len = unsafe { GetLengthSid(sid) };
    // SAFETY: `sid` is the valid pointer read above (still inside `buf`,
    // which is not dropped until this function returns), and `len` is
    // what GetLengthSid itself reports that exact SID occupies.
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, len as usize) }.to_vec())
}

/// Mirrors the Unix side's `libc::getuid()` comparison in `connect` above:
/// refuses a pipe this account did not create. Belt-and-suspenders next to
/// `bind_listener`'s DACL the same way the Unix side keeps its uid check
/// even though `0600` alone would ordinarily be enough - see that
/// function's doc for why (a permissive umask can weaken a permissions-only
/// guarantee); here, the closer analogue is a pipe name some other,
/// unrelated program claimed first, before this account's own daemon ever
/// started.
#[cfg(windows)]
fn verify_pipe_owner_is_current_user(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::EqualSid;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut server_pid = 0u32;
    // SAFETY: `pipe`'s handle is open and valid for the duration of this
    // call.
    let handle = pipe.as_raw_handle() as HANDLE;
    if unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) } == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: enough access to read the token below and nothing more
    // invasive; a null return is a real failure, checked immediately.
    let server_process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
    if server_process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let server_sid = process_user_sid(server_process);
    // SAFETY: closed exactly once, right after the only use of the handle
    // opened just above.
    unsafe { CloseHandle(server_process) };
    let server_sid = server_sid?;

    // SAFETY: GetCurrentProcess returns a pseudo-handle - always valid,
    // and never closed (it does not name a real handle table entry).
    let own_sid = process_user_sid(unsafe { GetCurrentProcess() })?;

    // SAFETY: both slices came from a successful
    // GetTokenInformation(TokenUser) call in process_user_sid and are held
    // alive by `server_sid`/`own_sid` for the duration of this comparison.
    let equal = unsafe {
        EqualSid(
            server_sid.as_ptr() as *mut core::ffi::c_void,
            own_sid.as_ptr() as *mut core::ffi::c_void,
        )
    };
    if equal == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the daemon's pipe is not owned by this user",
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub async fn connect(_path: &Path) -> io::Result<ClientStream> {
    let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_name())?;
    verify_pipe_owner_is_current_user(&stream)?;
    Ok(stream)
}

/// Creates one pipe instance under the DACL `owner_only_security_descriptor`
/// builds - Windows' counterpart to Unix's `0600` - passed through tokio's
/// raw hook rather than the plain `create`, which would leave the pipe at
/// its OS default (Microsoft's own docs: full control to
/// LocalSystem/Administrators/Creator-Owner, but also *read* access to
/// Everyone - enough for another local account to observe a live session).
///
/// Shared by `bind_listener` (the first instance) and `Listener::accept`
/// (every replacement instance after it, one per connection) - a named
/// pipe's security descriptor is per-instance, not inherited from the
/// first one, so every instance needs this applied for the hardened ACL to
/// hold for the pipe's whole lifetime rather than only its first
/// connection.
#[cfg(windows)]
fn create_owner_only_pipe_instance(
    first: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let descriptor = owner_only_security_descriptor()?;
    let mut attrs = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attrs` is a fully-initialized SECURITY_ATTRIBUTES whose
    // `lpSecurityDescriptor` (`descriptor`) is not dropped (which would
    // free it) until after this call returns.
    unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(
                pipe_name(),
                &mut attrs as *mut _ as *mut core::ffi::c_void,
            )
    }
}

/// `first_pipe_instance(true)` (inside `create_owner_only_pipe_instance`)
/// is what refuses a *second* process claiming the same name, backstopping
/// the single-instance check the socket file performs on Unix.
#[cfg(windows)]
pub fn bind_listener(_path: &Path) -> io::Result<Listener> {
    let pending = create_owner_only_pipe_instance(true)?;
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
        let next = create_owner_only_pipe_instance(false)?;
        Ok(std::mem::replace(&mut self.pending, next))
    }
}
