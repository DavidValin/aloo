//! The `Ctrl+E` export popup (US-054): opening it populated from what's
//! already in memory, navigating and checking rows, and what Confirm/
//! Cancel actually produce.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::tui::ui::{CallConfirmChoice, Mode, UiAction};
use aloo::proto::UserId;
use crossterm::event::KeyCode;

// ---------------------------------------------------------------------
// Opening the popup
// ---------------------------------------------------------------------

/// @requirement AC-358
#[test]
fn ctrl_e_opens_the_popup_listing_every_joined_channel_and_open_dm() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_private_room(user(2, "bob"));
    let action = ctrl(&mut state, KeyCode::Char('e'));
    assert_eq!(action, None, "purely local - no UiAction needed just to open it");
    assert_eq!(state.mode, Mode::ExportPopup);

    let popup = state.export_popup.as_ref().unwrap();
    assert_eq!(popup.channels, vec![("general".to_string(), false)]);
    assert_eq!(popup.dms, vec![(UserId(2), "bob".to_string(), false)]);
    assert!(!popup.on_buttons);
    assert_eq!(popup.confirm_focus, CallConfirmChoice::Cancel, "Cancel is focused by default");
}

/// @requirement AC-358
#[test]
fn opening_with_nothing_joined_or_open_still_opens_a_popup_with_empty_lists() {
    let mut state = joined_general_with(vec![]);
    state.channels.clear();
    ctrl(&mut state, KeyCode::Char('e'));
    let popup = state.export_popup.as_ref().unwrap();
    assert!(popup.channels.is_empty());
    assert!(popup.dms.is_empty());
}

// ---------------------------------------------------------------------
// Navigating and toggling the checkbox list
// ---------------------------------------------------------------------

/// @requirement AC-358
#[test]
fn enter_toggles_the_row_under_the_cursor_without_moving_focus() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Enter);
    let popup = state.export_popup.as_ref().unwrap();
    assert!(popup.channels[0].1, "checked after one Enter");
    assert!(!popup.on_buttons);

    press(&mut state, KeyCode::Enter);
    assert!(!state.export_popup.as_ref().unwrap().channels[0].1, "Enter toggles back off");
}

/// @requirement AC-358
#[test]
fn down_moves_through_channels_then_dms_then_onto_the_button_row() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_private_room(user(2, "bob"));
    ctrl(&mut state, KeyCode::Char('e'));
    assert_eq!(state.export_popup.as_ref().unwrap().cursor, 0);

    press(&mut state, KeyCode::Down);
    let popup = state.export_popup.as_ref().unwrap();
    assert_eq!(popup.cursor, 1, "the one DM row");
    assert!(!popup.on_buttons);

    press(&mut state, KeyCode::Down);
    assert!(state.export_popup.as_ref().unwrap().on_buttons, "Down past the last row reaches the buttons");
}

/// @requirement AC-358
#[test]
fn up_from_the_button_row_returns_to_the_last_list_row() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Tab); // straight to the buttons
    assert!(state.export_popup.as_ref().unwrap().on_buttons);

    press(&mut state, KeyCode::Up);
    let popup = state.export_popup.as_ref().unwrap();
    assert!(!popup.on_buttons);
    assert_eq!(popup.cursor, 0);
}

// ---------------------------------------------------------------------
// The Confirm/Cancel row
// ---------------------------------------------------------------------

/// @requirement AC-358
#[test]
fn left_right_and_tab_all_toggle_between_confirm_and_cancel() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Tab);
    assert_eq!(state.export_popup.as_ref().unwrap().confirm_focus, CallConfirmChoice::Cancel);

    press(&mut state, KeyCode::Left);
    assert_eq!(state.export_popup.as_ref().unwrap().confirm_focus, CallConfirmChoice::Confirm);

    press(&mut state, KeyCode::Right);
    assert_eq!(state.export_popup.as_ref().unwrap().confirm_focus, CallConfirmChoice::Cancel);

    press(&mut state, KeyCode::Tab);
    assert_eq!(state.export_popup.as_ref().unwrap().confirm_focus, CallConfirmChoice::Confirm);
}

/// @requirement AC-358
#[test]
fn enter_on_cancel_closes_with_no_action() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Enter); // check #general
    press(&mut state, KeyCode::Tab); // to the buttons, Cancel focused by default

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert!(state.export_popup.is_none());
    assert_eq!(state.mode, Mode::Normal);
}

/// @requirement AC-358
#[test]
fn enter_on_confirm_with_nothing_checked_closes_with_no_action() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Left); // focus Confirm

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "nothing checked means nothing to export");
    assert!(state.export_popup.is_none());
}

/// @requirement AC-358
#[test]
fn enter_on_confirm_exports_every_checked_channel_and_dm() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_private_room(user(2, "bob"));
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Enter); // check #general
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Enter); // check bob's DM
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Left); // focus Confirm

    match press(&mut state, KeyCode::Enter).expect("Confirm with a checked row should emit an action") {
        UiAction::ExportSelected { prefix, channels, dms } => {
            assert_eq!(prefix.len(), 8);
            assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
            assert_eq!(channels, vec!["general".to_string()]);
            assert_eq!(dms, vec![UserId(2)]);
        }
        other => panic!("expected ExportSelected, got {other:?}"),
    }
    assert!(state.export_popup.is_none());
    assert_eq!(state.mode, Mode::Normal);
}

// ---------------------------------------------------------------------
// Esc always backs out with no action
// ---------------------------------------------------------------------

/// @requirement AC-358
#[test]
fn esc_from_the_list_closes_with_no_action() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Enter); // check #general - should not matter
    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, None);
    assert!(state.export_popup.is_none());
    assert_eq!(state.mode, Mode::Normal);
}

/// @requirement AC-358
#[test]
fn esc_from_the_buttons_closes_with_no_action() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('e'));
    press(&mut state, KeyCode::Tab);
    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, None);
    assert!(state.export_popup.is_none());
}
