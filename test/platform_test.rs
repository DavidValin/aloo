use std::ffi::OsStr;
use std::path::PathBuf;

use aloo::platform::resolve_home_dir;

/// @requirement TB-122
#[test]
fn resolve_home_dir_prefers_home_over_userprofile() {
    let home = OsStr::new("/home/dave");
    let userprofile = OsStr::new(r"C:\Users\dave");
    assert_eq!(resolve_home_dir(Some(home), Some(userprofile)), Some(PathBuf::from("/home/dave")));
}

/// @requirement TB-122
#[test]
fn resolve_home_dir_falls_back_to_userprofile_when_home_is_unset() {
    let userprofile = OsStr::new(r"C:\Users\dave");
    assert_eq!(resolve_home_dir(None, Some(userprofile)), Some(PathBuf::from(r"C:\Users\dave")));
}

/// @requirement TB-122
#[test]
fn resolve_home_dir_treats_an_empty_home_as_unset_and_falls_back() {
    let userprofile = OsStr::new(r"C:\Users\dave");
    assert_eq!(
        resolve_home_dir(Some(OsStr::new("")), Some(userprofile)),
        Some(PathBuf::from(r"C:\Users\dave")),
        "some container/service environments export HOME=\"\" - that must not win over a usable USERPROFILE"
    );
}

/// @requirement TB-122
#[test]
fn resolve_home_dir_treats_an_empty_userprofile_as_unset() {
    assert_eq!(resolve_home_dir(None, Some(OsStr::new(""))), None);
}

/// @requirement TB-122
#[test]
fn resolve_home_dir_is_none_when_neither_is_set() {
    assert_eq!(resolve_home_dir(None, None), None);
}

/// @requirement TB-122
#[test]
fn aloo_dir_resolves_under_the_real_process_home_directory() {
    // Exercises the real env-reading path (`aloo_dir`, not the pure
    // `resolve_home_dir` above) - this test's own process always has a
    // real HOME (Linux/macOS CI/dev) or USERPROFILE (Windows CI), so the
    // fallback-to-relative-.aloo branch never fires here; that branch is
    // covered indirectly by `resolve_home_dir_is_none_when_neither_is_set`.
    let dir = aloo::platform::aloo_dir();
    assert_eq!(dir.file_name(), Some(OsStr::new(".aloo")));
}
