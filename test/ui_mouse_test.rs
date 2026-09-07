//! Mouse click support: enabled at the terminal level
//! (`tui::terminal::setup`'s `EnableMouseCapture`, not exercised here - no
//! real terminal in a test) and handled at the `UiState` level
//! (`UiState::handle_mouse`), hit-tested against wherever the input bar
//! and the channel view's member sidebar were actually last drawn.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use std::time::{Duration, Instant};

use aloo::client::tui::ui::{Focus, RECORD_HOLD_TIMEOUT, TOUCH_HOLD_THRESHOLD, UiAction, UiState};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

fn left_click(col: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: col,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

/// Finds the first `(x, y)` cell whose row contains `needle` - used to
/// locate a real on-screen target without hard-coding layout geometry
/// that might shift.
fn find_text(rows: &[String], needle: &str) -> (u16, u16) {
    let y = rows
        .iter()
        .position(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("expected to find {needle:?} on screen: {rows:?}"));
    let x = rows[y].find(needle).unwrap();
    (x as u16, y as u16)
}

/// @requirement AC-395
#[test]
fn clicking_the_input_bar_focuses_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    let rows = rendered_rows(&state);
    let (x, y) = find_text(&rows, "Message");

    let action = state.handle_mouse(left_click(x, y));
    assert!(action.is_none());
    assert_eq!(state.focus, Focus::Input);
}

/// @requirement AC-395
#[test]
fn clicking_a_sidebar_row_selects_that_member_and_focuses_the_sidebar() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.focus = Focus::Input;
    let rows = rendered_rows(&state);
    let (x, y) = find_text(&rows, "carol");

    let action = state.handle_mouse(left_click(x, y));
    assert!(action.is_none());
    assert_eq!(state.focus, Focus::Sidebar);
    assert_eq!(
        state.channels[state.selected_channel].members[state.sidebar_selected].name,
        "carol"
    );
}

/// A click that lands on neither known target does nothing - no panic,
/// no focus change.
/// @requirement AC-395
#[test]
fn clicking_empty_space_does_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    let _ = rendered_rows(&state);

    let action = state.handle_mouse(left_click(0, 0));
    assert!(action.is_none());
    assert_eq!(state.focus, Focus::Sidebar, "an unrelated corner click changes nothing");
}

/// Something else is absorbing every key right now (a popup, here Ctrl+S's
/// settings modal) - a click must not reach through it to whatever
/// it's covering.
/// @requirement AC-395
#[test]
fn a_click_is_ignored_while_an_overlay_is_open() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    state.open_settings();
    let rows = rendered_rows(&state);
    // Whatever cell the compose bar's own label would occupy behind the
    // popup - the popup covers the whole screen, so any coordinate works;
    // pick one from inside the rendered popup itself.
    let (x, y) = find_text(&rows, "Direct Punch");

    let action = state.handle_mouse(left_click(x, y));
    assert!(action.is_none());
    assert_eq!(state.focus, Focus::Sidebar, "a popup click must not reach the view behind it");
}

/// Right clicks, releases, drags and scrolls are not handled - only a
/// left button press is.
/// @requirement AC-395
#[test]
fn only_a_left_button_press_is_handled() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    let rows = rendered_rows(&state);
    let (x, y) = find_text(&rows, "Message");

    let right_click = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Right),
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    };
    assert!(state.handle_mouse(right_click).is_none());
    assert_eq!(state.focus, Focus::Sidebar);

    let release = MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    };
    assert!(state.handle_mouse(release).is_none());
    assert_eq!(state.focus, Focus::Sidebar);
}

/// The sidebar area recorded while viewing a channel is stale once a DM is
/// open instead (`render_private_room` draws no sidebar at all) - a click
/// at that leftover position must not resurrect a channel-view action.
/// @requirement AC-395
#[test]
fn a_stale_sidebar_position_is_ignored_while_viewing_a_dm() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Input;
    let rows = rendered_rows(&state);
    let (x, y) = find_text(&rows, "bob");

    state.active_private_room = Some(aloo::proto::UserId(2));
    let _ = rendered_rows(&state); // the DM view renders now, no sidebar

    let action = state.handle_mouse(left_click(x, y));
    assert!(action.is_none());
    assert_eq!(state.focus, Focus::Input, "unaffected by the stale sidebar coordinates");
}

// ---------------------------------------------------------------------
// Hold-to-talk by touch: a left button held anywhere past
// `TOUCH_HOLD_THRESHOLD` records; a tap does not (AC-447).
// ---------------------------------------------------------------------

fn left_release(col: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: col,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

/// Presses at `t0` and ticks one threshold later, returning the tick's
/// action - a hold that just crossed the line.
fn hold_from(state: &mut UiState, t0: Instant) -> Option<UiAction> {
    assert!(state.handle_mouse_at(left_click(0, 0), t0).is_none(), "the press itself starts nothing");
    assert!(state.tick_touch_hold(t0).is_none(), "not a hold yet");
    assert!(
        state.tick_touch_hold(t0 + TOUCH_HOLD_THRESHOLD - Duration::from_millis(1)).is_none(),
        "still not a hold, a millisecond short of the threshold"
    );
    state.tick_touch_hold(t0 + TOUCH_HOLD_THRESHOLD)
}

/// @requirement AC-447
#[test]
fn a_press_held_past_the_threshold_records_and_its_release_stops_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let t0 = Instant::now();

    let started = hold_from(&mut state, t0);
    assert!(matches!(started, Some(UiAction::VoiceRecordStart(_))), "got {started:?}");
    assert!(state.recording);
    assert!(state.tick_touch_hold(t0 + Duration::from_secs(5)).is_none(), "one hold is one recording");

    let stopped = state.handle_mouse_at(left_release(0, 0), t0 + Duration::from_secs(5));
    assert_eq!(stopped, Some(UiAction::VoiceRecordStop));
    assert!(!state.recording);
}

/// A tap - down and up inside the threshold - is the click it always
/// was: the focus change happens on the press, and nothing records once
/// the threshold passes.
/// @requirement AC-447
#[test]
fn a_tap_is_a_click_and_never_records() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    let rows = rendered_rows(&state);
    let (x, y) = find_text(&rows, "Message");
    let t0 = Instant::now();

    assert!(state.handle_mouse_at(left_click(x, y), t0).is_none());
    assert_eq!(state.focus, Focus::Input, "the click is honored on the press");
    assert!(state.handle_mouse_at(left_release(x, y), t0 + Duration::from_millis(80)).is_none());
    assert!(state.tick_touch_hold(t0 + TOUCH_HOLD_THRESHOLD).is_none());
    assert!(state.tick_touch_hold(t0 + Duration::from_secs(2)).is_none());
    assert!(!state.recording);
}

/// @requirement AC-447
#[test]
fn a_hold_with_nowhere_to_send_does_not_record() {
    let mut state = UiState::new("me".into()); // no channels joined, no active DM
    let t0 = Instant::now();
    assert!(hold_from(&mut state, t0).is_none());
    assert!(!state.recording);
}

/// @requirement AC-447
#[test]
fn a_hold_does_not_start_while_an_overlay_is_open() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_settings();
    let t0 = Instant::now();
    assert!(state.handle_mouse_at(left_click(0, 0), t0).is_none());
    assert!(state.tick_touch_hold(t0 + TOUCH_HOLD_THRESHOLD).is_none());
    assert!(!state.recording, "a press on a popup must not record through it");

    // Armed on the plain view, but an overlay came up before the hold
    // matured: the press is dropped rather than recording under it.
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let t0 = Instant::now();
    assert!(state.handle_mouse_at(left_click(0, 0), t0).is_none());
    state.open_settings();
    assert!(state.tick_touch_hold(t0 + TOUCH_HOLD_THRESHOLD).is_none());
    assert!(!state.recording);
    state.handle_key(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.tick_touch_hold(t0 + Duration::from_secs(3)).is_none(), "and it stays dropped");
}

/// Each trigger only ever ends its own recording: a hold while Space is
/// recording neither restarts nor stops it, and a release stops nothing
/// Space started.
/// @requirement AC-447
#[test]
fn a_hold_never_interrupts_a_space_recording_and_a_release_never_stops_one() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    let started = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(matches!(started, Some(UiAction::VoiceRecordStart(_))));
    let t0 = Instant::now();

    assert!(state.handle_mouse_at(left_click(0, 0), t0).is_none());
    assert!(state.tick_touch_hold(t0 + TOUCH_HOLD_THRESHOLD).is_none());
    assert!(state.recording, "Space's recording is untouched");
    assert!(state.handle_mouse_at(left_release(0, 0), t0 + Duration::from_secs(1)).is_none());
    assert!(state.recording, "a release ends only a touch recording");

    let stopped = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Release);
    assert_eq!(stopped, Some(UiAction::VoiceRecordStop));
}

/// The terminal kept the release for its own long-press gesture, so the
/// recording is stuck: the next press ends it instead of starting another.
/// @requirement AC-447
#[test]
fn a_press_during_a_touch_recording_ends_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let t0 = Instant::now();
    assert!(matches!(hold_from(&mut state, t0), Some(UiAction::VoiceRecordStart(_))));

    let t1 = t0 + Duration::from_secs(4);
    assert_eq!(state.handle_mouse_at(left_click(0, 0), t1), Some(UiAction::VoiceRecordStop));
    assert!(!state.recording);
    assert!(state.tick_touch_hold(t1 + TOUCH_HOLD_THRESHOLD).is_none(), "that press armed no new hold");
    assert!(state.handle_mouse_at(left_release(0, 0), t1 + Duration::from_secs(1)).is_none());
}

/// A held finger has no keypress heartbeat to go quiet, so Space's
/// idle-silence guess must never end a touch recording.
/// @requirement AC-447
#[test]
fn the_idle_silence_guess_never_applies_to_a_touch_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let t0 = Instant::now();
    assert!(matches!(hold_from(&mut state, t0), Some(UiAction::VoiceRecordStart(_))));

    assert!(state.tick_recording_timeout(t0 + RECORD_HOLD_TIMEOUT * 5).is_none());
    assert!(state.recording);
}

/// @requirement AC-447
#[test]
fn a_hold_arms_nothing_while_touch_ptt_is_off() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.touch_ptt_enabled = false;
    state.focus = Focus::Sidebar;
    let rows = rendered_rows(&state);
    let (x, y) = find_text(&rows, "Message");
    let t0 = Instant::now();

    assert!(state.handle_mouse_at(left_click(x, y), t0).is_none());
    assert_eq!(state.focus, Focus::Input, "a click still clicks");
    assert!(state.tick_touch_hold(t0 + Duration::from_secs(5)).is_none());
    assert!(!state.recording);
}
