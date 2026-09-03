//! Cross-platform resolution of this app's `~/.aloo` directory, shared by
//! every local store's `default_path`. Always under the user's home
//! directory, never the current working directory, without pulling in a
//! crate just for that: `$HOME` covers Linux/macOS (and most Windows
//! shells), `%USERPROFILE%` is Windows' native convention.
//! `std::env::home_dir` is deliberately avoided - documented-deprecated
//! since Rust 1.29 for giving wrong answers on Windows.

use std::ffi::OsStr;
use std::path::PathBuf;

/// The directory both stores default to a file under: `ALOO_HOME` if set
/// (the exact directory, not joined with `.aloo` - the point of setting it
/// is to name the whole thing), else resolved home (`resolve_home_dir`)
/// joined with `.aloo`. Falls back to `.aloo` relative to the current
/// directory - still never a bare loose file - if neither the override nor
/// either environment variable is usable, a degenerate case this app has
/// no real answer for.
///
/// The override exists because *every* piece of this app's local state -
/// `id_store`, the connect cache, `settings`, and the OTP layer's
/// `otp_store`/`otp/.keychain/` - lives under this one directory: two
/// `aloo` clients on the same machine (the ordinary way to test or demo
/// two peers before deploying across real machines) otherwise silently
/// share it, which is harmless for most of those stores but actively
/// breaks the OTP layer - its keychain and per-contact ack-gate state are
/// only ever meant to represent *one* party's own view, and a second
/// process serving a different identity out of the same directory
/// corrupts both parties' views of what should be independent state.
/// Pointing each instance at its own `ALOO_HOME` gives each one a fully
/// separate `~/.aloo`, exactly as if they were on separate machines.
pub fn aloo_dir() -> PathBuf {
    resolve_aloo_dir(
        std::env::var_os("ALOO_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("USERPROFILE").as_deref(),
    )
}

/// Pure decision behind `aloo_dir`, split out the same way `resolve_home_dir`
/// is - testable against synthetic values without mutating the real
/// process environment (unsafe under parallel tests). An empty `ALOO_HOME`
/// counts as unset, same treatment `resolve_home_dir` gives `HOME`/
/// `USERPROFILE`.
pub fn resolve_aloo_dir(
    aloo_home: Option<&OsStr>,
    home: Option<&OsStr>,
    userprofile: Option<&OsStr>,
) -> PathBuf {
    if let Some(dir) = aloo_home
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    match resolve_home_dir(home, userprofile) {
        Some(home) => home.join(".aloo"),
        None => PathBuf::from(".aloo"),
    }
}

/// Pure home-directory resolution, split from `aloo_dir` so it's testable
/// against synthetic values without mutating the real process environment
/// (unsafe under parallel tests). `home` is preferred, `userprofile` the
/// fallback; a variable that is *set but empty* (a real quirk of some
/// container environments) counts as unset rather than resolving to a
/// bare `.aloo` at the filesystem root.
pub fn resolve_home_dir(home: Option<&OsStr>, userprofile: Option<&OsStr>) -> Option<PathBuf> {
    [home, userprofile]
        .into_iter()
        .flatten()
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Resolves a leading `~` (or `~/...`) against the same home directory
/// `aloo_dir` uses, leaving any other path untouched. Settings that name
/// files outside `ALOO_HOME` - the TLS certificate pair, an extra CA - are
/// written with a literal `~` so the file reads the same on every machine.
pub fn expand_tilde(path: &str) -> PathBuf {
    expand_tilde_with(
        path,
        resolve_home_dir(
            std::env::var_os("HOME").as_deref(),
            std::env::var_os("USERPROFILE").as_deref(),
        ),
    )
}

/// Pure half of `expand_tilde`, testable with a synthetic home. With no
/// home to resolve against the path is returned as written - a literal
/// `~` directory is the least surprising reading of an unanswerable
/// question.
pub fn expand_tilde_with(path: &str, home: Option<PathBuf>) -> PathBuf {
    if path == "~" {
        return home.unwrap_or_else(|| PathBuf::from(path));
    }
    match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(path),
    }
}

/// Creates `path`'s parent directory if it names one, so a write to a
/// store that has never been written before succeeds on a fresh machine.
///
/// The empty-parent guard is what makes this safe for a bare relative
/// filename: `Path::new("store").parent()` is `Some("")`, and
/// `create_dir_all("")` fails. Every flat-file store here (`idstore`,
/// `otp_store`, `ip_ban`, `device_id`, the connect cache, `settings`)
/// opened its `save` with exactly this block.
pub(crate) fn ensure_parent_dir(path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Replaces `path`'s contents in one step: written to a `.new` sibling,
/// flushed to disk, then renamed over `path`.
///
/// `fs::write` truncates first and fills in afterwards, so a process that
/// dies (or loses power) between the two leaves an empty or half-written
/// file - and for a store like `otp_store`, whose every line is a pad
/// position or an acknowledgement gate, "empty" reads as "start every
/// counter from zero", which is a permanent desync at the next send. With
/// the rename the old contents stay intact until the new ones are wholly
/// on disk, and a crash costs at most the single most recent mutation -
/// exactly the window the OTP layer's write-ahead intent already
/// tolerates. A leftover `.new` is simply overwritten by the next save;
/// nothing reads it.
pub(crate) fn write_atomic(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    ensure_parent_dir(path)?;
    let mut staged = path.as_os_str().to_owned();
    staged.push(".new");
    let staged = std::path::PathBuf::from(staged);
    {
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::rename(&staged, path)
}

/// `path`'s contents, or `None` if it does not exist yet.
///
/// A store that has never been written is not an error - it is an empty
/// store, which is the first run. Every other I/O failure still is one: a
/// permissions problem or a bad disk must not be read as "no data", which
/// would silently start a store from scratch over a file that is really
/// still there.
pub(crate) fn read_to_string_optional(path: &std::path::Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// An exclusive, process-lifetime claim on one aloo home directory
/// (`aloo_dir`), so at most one session ever runs against it.
///
/// Every piece of local state under that directory - the identity pins,
/// the settings, and above all the OTP layer's `otp_store` and its
/// keychain - is written by the session that owns it as if it were the only
/// writer. Two sessions on one home (a daemon plus an `aloo --no-attach`,
/// or two terminals) each keep their own in-memory copy of the pad
/// counters and overwrite the same file in turn: both believe the next
/// position is theirs, both seal against the same keychain (the per-call
/// keychain lock only stops them from doing so *simultaneously*), and the
/// tool's one-deep `.last_sent` copy is clobbered across the two - a
/// permanent desync with nothing left to recover from. The lock turns that
/// into a refusal at startup instead: a second session needs a second
/// home (`ALOO_HOME=... aloo`), which is the only arrangement under which
/// two sessions can hold two consistent views.
///
/// OS-advisory (`File::try_lock`), so a session killed with no chance to
/// clean up leaves nothing behind that blocks the next start.
#[derive(Debug)]
pub struct HomeLock {
    _file: std::fs::File,
}

/// Where `HomeLock` lives inside a home: a sibling of every store, never
/// inside `otp/` (the keychain tool treats that directory as its own).
pub fn home_lock_path(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".session.lock")
}

impl HomeLock {
    /// Claims `home`. `Ok(None)` means another live process already holds
    /// it - the caller refuses to start; an `Err` is a genuine I/O failure
    /// (an unwritable home), which the caller reports the same way.
    pub fn acquire(home: &std::path::Path) -> std::io::Result<Option<Self>> {
        std::fs::create_dir_all(home)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(home_lock_path(home))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// The refusal a second session is shown - one sentence naming the
    /// directory and the way out.
    pub fn busy_message(home: &std::path::Path) -> String {
        format!(
            "another aloo session is already running against {} - attach to it with a bare \
             'aloo', stop it, or run a separate session under its own home: ALOO_HOME=<dir> aloo",
            home.display()
        )
    }
}
