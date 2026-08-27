//! Mouse click support: enabled at the terminal level
//! (`tui::terminal::setup`'s `EnableMouseCapture`, not exercised here - no
//! real terminal in a test) and handled at the `UiState` level
//! (`UiState::handle_mouse`), hit-tested against wherever the input bar
//! and the channel view's member sidebar were actually last drawn.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::tui::ui::Focus;
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

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
/// Direct Punches modal) - a click must not reach through it to whatever
/// it's covering.
/// @requirement AC-395
#[test]
fn a_click_is_ignored_while_an_overlay_is_open() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    state.open_direct_punches();
    let rows = rendered_rows(&state);
    // Whatever cell the compose bar's own label would occupy behind the
    // popup - the popup covers the whole screen, so any coordinate works;
    // pick one from inside the rendered popup itself.
    let (x, y) = find_text(&rows, "Direct Punches");

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
