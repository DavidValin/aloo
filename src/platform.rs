//! Cross-platform resolution of this app's `~/.aloo` directory, shared by
//! every local store's `default_path`. Always under the user's home
//! directory, never the current working directory, without pulling in a
//! crate just for that: `$HOME` covers Linux/macOS (and most Windows
//! shells), `%USERPROFILE%` is Windows' native convention.
//! `std::env::home_dir` is deliberately avoided - documented-deprecated
//! since Rust 1.29 for giving wrong answers on Windows.

use std::ffi::OsStr;
use std::path::PathBuf;

/// The directory both stores default to a file under: resolved home
/// (`resolve_home_dir`) joined with `.aloo`. Falls back to `.aloo`
/// relative to the current directory - still never a bare loose file - if
/// neither environment variable is usable, a degenerate case this app has
/// no real answer for.
pub fn aloo_dir() -> PathBuf {
    match resolve_home_dir(
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("USERPROFILE").as_deref(),
    ) {
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
