//! The Ctrl+S "Direct Punches" popup (US-039): opening it, navigating and
//! editing the list, and what saving/deleting a row actually produces.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::tui::direct_punch_popup::DirectPunchField;
use aloo::client::tui::ui::{Mode, UiAction};
use aloo::settings::{DEFAULT_DIRECT_PUNCH_PORT, DirectPunchTarget, PunchFrequency};
use crossterm::event::KeyCode;

fn target(nickname: &str, host: &str, port: u16, frequency_minutes: u32) -> DirectPunchTarget {
    DirectPunchTarget {
        nickname: nickname.to_string(),
        host: host.to_string(),
        port,
        frequency: PunchFrequency::parse(&format!("every_{frequency_minutes}m")).unwrap(),
    }
}

// ---------------------------------------------------------------------
// Opening the popup
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn ctrl_s_opens_the_modal_empty_and_requests_a_load() {
    let mut state = joined_general_with(vec![]);
    let action = ctrl(&mut state, KeyCode::Char('s'));
    assert_eq!(action, Some(UiAction::OpenDirectPunches));
    assert_eq!(state.mode, Mode::DirectPunches);
    assert!(state.direct_punches.as_ref().unwrap().rows.is_empty());
}

/// @requirement AC-291
#[test]
fn set_direct_punch_rows_populates_the_modal_and_clamps_selection() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    state.set_direct_punch_rows(vec![
        target("bob", "bobhost.example", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("carol", "carolhost.example", DEFAULT_DIRECT_PUNCH_PORT, 5),
    ]);
    assert_eq!(state.direct_punches.as_ref().unwrap().rows.len(), 2);
    assert_eq!(state.direct_punches.as_ref().unwrap().selected, 0);
}

/// @requirement AC-291
#[test]
fn set_direct_punch_rows_is_a_no_op_once_the_modal_is_closed() {
    let mut state = joined_general_with(vec![]);
    state.set_direct_punch_rows(vec![target("bob", "bobhost.example", DEFAULT_DIRECT_PUNCH_PORT, 1)]);
    assert!(state.direct_punches.is_none());
}

// ---------------------------------------------------------------------
// Navigating and closing the list
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn up_and_down_wrap_around_the_row_list() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    state.set_direct_punch_rows(vec![
        target("bob", "h1", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("carol", "h2", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("dave", "h3", DEFAULT_DIRECT_PUNCH_PORT, 1),
    ]);

    press(&mut state, KeyCode::Down);
    assert_eq!(state.direct_punches.as_ref().unwrap().selected, 1);
    press(&mut state, KeyCode::Up);
    assert_eq!(state.direct_punches.as_ref().unwrap().selected, 0);
    press(&mut state, KeyCode::Up);
    assert_eq!(
        state.direct_punches.as_ref().unwrap().selected,
        2,
        "Up from the first row wraps to the last"
    );
}

/// @requirement AC-291
#[test]
fn esc_on_the_list_closes_the_whole_modal() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Esc);
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.direct_punches.is_none());
}

// ---------------------------------------------------------------------
// The add/edit form
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn a_opens_a_blank_add_form() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    let edit = state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap();
    assert_eq!(edit.editing_index, None);
    assert_eq!(edit.nickname, "");
    assert_eq!(edit.focus, DirectPunchField::Nickname);
}

/// @requirement AC-291
#[test]
fn enter_on_a_row_opens_it_prefilled_for_editing() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    state.set_direct_punch_rows(vec![target("bob", "bobhost.example", 9000, 5)]);

    press(&mut state, KeyCode::Enter);
    let edit = state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap();
    assert_eq!(edit.editing_index, Some(0));
    assert_eq!(edit.nickname, "bob");
    assert_eq!(edit.host, "bobhost.example");
    assert_eq!(edit.port, "9000");
}

/// @requirement AC-291
#[test]
fn esc_on_the_edit_form_returns_to_the_list_without_losing_other_rows() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    state.set_direct_punch_rows(vec![target("bob", "h", DEFAULT_DIRECT_PUNCH_PORT, 1)]);
    press(&mut state, KeyCode::Char('a'));
    assert!(state.direct_punches.as_ref().unwrap().edit.is_some());

    press(&mut state, KeyCode::Esc);
    assert_eq!(state.mode, Mode::DirectPunches, "Esc on the form must not close the whole popup");
    assert!(state.direct_punches.as_ref().unwrap().edit.is_none());
    assert_eq!(state.direct_punches.as_ref().unwrap().rows.len(), 1);
}

/// @requirement AC-291
#[test]
fn tab_cycles_focus_through_every_field_and_wraps() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));

    let expect = [
        DirectPunchField::Host,
        DirectPunchField::Port,
        DirectPunchField::Frequency,
        DirectPunchField::Save,
        DirectPunchField::Nickname,
    ];
    for want in expect {
        press(&mut state, KeyCode::Tab);
        assert_eq!(state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap().focus, want);
    }
}

/// @requirement AC-291
#[test]
fn typing_fills_the_focused_text_field() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "bobhost.example");

    let edit = state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap();
    assert_eq!(edit.nickname, "bob");
    assert_eq!(edit.host, "bobhost.example");
}

/// @requirement AC-291
#[test]
fn the_port_field_only_accepts_digits() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    press(&mut state, KeyCode::Tab); // -> Host
    press(&mut state, KeyCode::Tab); // -> Port
    type_str(&mut state, "90a00");
    assert_eq!(state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap().port, "9000");
}

/// @requirement AC-291
#[test]
fn left_right_cycle_the_frequency_selector_and_wrap() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Frequency, starts at index 0 (every_1m)

    press(&mut state, KeyCode::Left);
    assert_eq!(
        state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap().frequency_index,
        12,
        "Left from the first frequency wraps to the last"
    );
    press(&mut state, KeyCode::Right);
    assert_eq!(state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap().frequency_index, 0);
}

/// @requirement AC-291
#[test]
fn enter_on_a_non_save_field_does_nothing() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert!(state.direct_punches.as_ref().unwrap().edit.is_some(), "the form must still be open");
}

// ---------------------------------------------------------------------
// Saving and deleting
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn saving_a_valid_new_target_appends_it_and_requests_a_save() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "bobhost.example");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Save

    let action = press(&mut state, KeyCode::Enter);
    match action {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].nickname, "bob");
            assert_eq!(targets[0].host, "bobhost.example");
            assert_eq!(targets[0].port, DEFAULT_DIRECT_PUNCH_PORT);
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
    assert!(state.direct_punches.as_ref().unwrap().edit.is_none(), "the form closes on a successful save");
    assert_eq!(state.direct_punches.as_ref().unwrap().rows.len(), 1);
}

/// @requirement AC-291
#[test]
fn saving_edits_an_existing_target_in_place_rather_than_appending() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    state.set_direct_punch_rows(vec![
        target("bob", "oldhost", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("carol", "carolhost", DEFAULT_DIRECT_PUNCH_PORT, 5),
    ]);

    press(&mut state, KeyCode::Enter); // edit bob (row 0)
    press(&mut state, KeyCode::Tab); // -> Host
    for _ in 0.."oldhost".len() {
        press(&mut state, KeyCode::Backspace);
    }
    type_str(&mut state, "newhost");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Save
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 2, "editing must not add a new row");
            assert_eq!(targets[0].nickname, "bob");
            assert_eq!(targets[0].host, "newhost");
            assert_eq!(targets[1].nickname, "carol", "the other row is untouched");
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
}

/// @requirement AC-291
#[test]
fn an_invalid_nickname_shows_an_inline_error_and_does_not_save() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    press(&mut state, KeyCode::Char('a'));
    // Left empty - not a storable nickname - then straight to Save.
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "somehost");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    let edit = state.direct_punches.as_ref().unwrap().edit.as_ref().unwrap();
    assert!(edit.error.is_some(), "an empty nickname must be refused with an inline error");
}

/// @requirement AC-291
#[test]
fn d_deletes_the_selected_row_and_requests_a_save() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    state.set_direct_punch_rows(vec![
        target("bob", "h1", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("carol", "h2", DEFAULT_DIRECT_PUNCH_PORT, 5),
    ]);

    let action = press(&mut state, KeyCode::Char('d'));
    match action {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].nickname, "carol");
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
    assert_eq!(state.direct_punches.as_ref().unwrap().rows.len(), 1);
}

/// @requirement AC-291
#[test]
fn d_on_an_empty_list_does_nothing() {
    let mut state = joined_general_with(vec![]);
    state.open_direct_punches();
    let action = press(&mut state, KeyCode::Char('d'));
    assert_eq!(action, None);
}
