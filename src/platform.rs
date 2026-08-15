//! Cross-platform resolution of this app's `~/.aloo` directory, shared by
//! `idstore::default_path` and `own_next_keys::default_path` (see
//! `docs/SPEC.md` "Not connected UI", `id_store`/`own_next_keys` fields).
//!
//! Both stores must always resolve under the user's home directory - never
//! a loose file in the current working directory - on Linux, macOS *and*
//! Windows, without pulling in a whole crate just for that. `$HOME` covers
//! Linux/macOS (and is also set by most Windows shells, e.g. Git Bash);
//! `%USERPROFILE%` is Windows' own native convention. `std::env::home_dir`
//! is deliberately not used here - it's been documented-deprecated since
//! Rust 1.29 for giving wrong answers on Windows in exactly this scenario.

use std::ffi::OsStr;
use std::path::PathBuf;

/// The directory both stores default to a file under: resolved home
/// (`resolve_home_dir`) joined with `.aloo`. Falls back to `.aloo`
/// relative to the current directory - still never a bare loose file - if
/// neither environment variable is usable, a degenerate case this app has
/// no real answer for.
pub fn aloo_dir() -> PathBuf {
    match resolve_home_dir(std::env::var_os("HOME").as_deref(), std::env::var_os("USERPROFILE").as_deref()) {
        Some(home) => home.join(".aloo"),
        None => PathBuf::from(".aloo"),
    }
}

/// Pure home-directory resolution, split out from `aloo_dir` so it's
/// testable against synthetic values for every OS's convention without
/// touching the real process environment (global mutable state shared
/// across every test binary, and thus unsafe to mutate from a parallel
/// test run). `home` (`$HOME`) is preferred; `userprofile`
/// (`%USERPROFILE%`) is the fallback. A variable that is *set but empty* -
/// a real quirk of some container/service environments - is treated the
/// same as unset, rather than resolving to a bare `.aloo` at the
/// filesystem root.
pub fn resolve_home_dir(home: Option<&OsStr>, userprofile: Option<&OsStr>) -> Option<PathBuf> {
    [home, userprofile].into_iter().flatten().find(|v| !v.is_empty()).map(PathBuf::from)
}
