use aloo::global_ptt::{is_wayland_session, resolve_hotkey};
use aloo::settings::DEFAULT_GLOBAL_PTT_SHORTCUT;
use global_hotkey::hotkey::HotKey;

/// @requirement TB-136
#[test]
fn resolve_hotkey_parses_a_valid_configured_shortcut() {
    let hotkey = resolve_hotkey("shift+alt+KeyV");
    assert_eq!(hotkey, "shift+alt+KeyV".parse::<HotKey>().unwrap());
}

/// @requirement TB-136
#[test]
fn resolve_hotkey_falls_back_to_the_default_on_an_invalid_shortcut() {
    let hotkey = resolve_hotkey("not a real shortcut");
    assert_eq!(hotkey, DEFAULT_GLOBAL_PTT_SHORTCUT.parse::<HotKey>().unwrap());
}

/// @requirement TB-136
#[test]
fn resolve_hotkey_of_the_documented_default_matches_the_default_directly() {
    assert_eq!(resolve_hotkey(DEFAULT_GLOBAL_PTT_SHORTCUT), DEFAULT_GLOBAL_PTT_SHORTCUT.parse::<HotKey>().unwrap());
}

/// @requirement TB-137
#[test]
fn is_wayland_session_detects_session_type_wayland() {
    assert!(is_wayland_session(Some("wayland"), false));
    assert!(is_wayland_session(Some("Wayland"), false), "the check should be case-insensitive");
}

/// @requirement TB-137
#[test]
fn is_wayland_session_detects_a_set_wayland_display_even_without_session_type() {
    assert!(is_wayland_session(None, true));
}

/// @requirement TB-137
#[test]
fn is_wayland_session_false_for_a_plain_x11_session() {
    assert!(!is_wayland_session(Some("x11"), false));
    assert!(!is_wayland_session(None, false));
}
