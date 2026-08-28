//! The "configured punches" list on the Ctrl+S settings popup's Direct
//! Punch tab (US-039): reaching it, navigating and editing the list, and
//! what saving/deleting a row actually produces. The tabs and the rest of
//! the settings around it are `ui_settings_popup_test.rs`.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::tui::direct_punch_popup::DirectPunchField;
use aloo::client::tui::settings_popup::SettingsField;
use aloo::client::tui::ui::{Mode, UiAction, UiState, render};
use aloo::settings::{DEFAULT_DIRECT_PUNCH_PORT, DirectPunchTarget, PunchFrequency};
use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn target(nickname: &str, host: &str, port: u16, frequency_minutes: u32) -> DirectPunchTarget {
    DirectPunchTarget {
        nickname: nickname.to_string(),
        device_id: None,
        host: host.to_string(),
        port,
        frequency: PunchFrequency::parse(&format!("every_{frequency_minutes}m")).unwrap(),
    }
}

/// Opens the Ctrl+S popup and puts the focus on the Direct Punch tab's
/// punch list, which is where every key below is pressed. The list is the
/// second field on that tab, under the `direct_punch` master switch.
fn open_punches(state: &mut UiState) {
    state.open_settings();
    press(state, KeyCode::Tab);
    press(state, KeyCode::Down);
}

// ---------------------------------------------------------------------
// Opening the popup
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn ctrl_s_opens_the_modal_with_an_empty_punch_list_and_requests_a_load() {
    let mut state = joined_general_with(vec![]);
    let action = ctrl(&mut state, KeyCode::Char('s'));
    assert_eq!(action, Some(UiAction::OpenSettings));
    assert_eq!(state.mode, Mode::Settings);
    assert!(state.settings_popup.as_ref().unwrap().punches.rows.is_empty());
}

/// @requirement AC-291
#[test]
fn set_direct_punch_rows_populates_the_modal_and_clamps_selection() {
    let mut state = joined_general_with(vec![]);
    state.open_settings();
    state.set_direct_punch_rows(vec![
        target("bob", "bobhost.example", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("carol", "carolhost.example", DEFAULT_DIRECT_PUNCH_PORT, 5),
    ]);
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.rows.len(), 2);
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.selected, 0);
}

/// @requirement AC-291
#[test]
fn set_direct_punch_rows_is_a_no_op_once_the_modal_is_closed() {
    let mut state = joined_general_with(vec![]);
    state.set_direct_punch_rows(vec![target("bob", "bobhost.example", DEFAULT_DIRECT_PUNCH_PORT, 1)]);
    assert!(state.settings_popup.is_none());
}

// ---------------------------------------------------------------------
// Navigating and closing the list
// ---------------------------------------------------------------------

/// Up/Down walk the rows while there is another one to move onto, and
/// hand the key back to the tab at either end - one set of arrows drives
/// both the field column and the list inside it, with no mode to enter.
/// @requirement AC-291, AC-397
#[test]
fn up_and_down_walk_the_row_list_and_then_leave_it() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    state.set_direct_punch_rows(vec![
        target("bob", "h1", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("carol", "h2", DEFAULT_DIRECT_PUNCH_PORT, 1),
        target("dave", "h3", DEFAULT_DIRECT_PUNCH_PORT, 1),
    ]);

    press(&mut state, KeyCode::Down);
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.selected, 1);
    press(&mut state, KeyCode::Up);
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.selected, 0);

    press(&mut state, KeyCode::Up);
    assert_eq!(
        state.settings_popup.as_ref().unwrap().focused_field(),
        SettingsField::DirectPunchEnabled,
        "Up from the first row leaves the list for the field above it"
    );
    press(&mut state, KeyCode::Down);
    assert_eq!(
        state.settings_popup.as_ref().unwrap().focused_field(),
        SettingsField::Punches,
        "and Down comes straight back into it"
    );
    assert_eq!(
        state.settings_popup.as_ref().unwrap().punches.selected,
        0,
        "entering from above starts at the first row"
    );
}

/// @requirement AC-291
#[test]
fn esc_on_the_list_closes_the_whole_modal() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Esc);
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.settings_popup.is_none());
}

// ---------------------------------------------------------------------
// The add/edit form
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn a_opens_a_blank_add_form() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.editing_index, None);
    assert_eq!(edit.nickname, "");
    assert_eq!(edit.focus, DirectPunchField::Nickname);
}

/// The add form opens with the blinking terminal cursor visibly in the
/// nickname box - the same styling and cursor convention the connect
/// popup's own bordered fields already use, so it's obvious where typing
/// lands the instant the form appears.
/// @requirement AC-393
#[test]
fn the_add_form_opens_with_the_cursor_in_the_nickname_box() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    assert_eq!(
        state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().focus,
        DirectPunchField::Nickname
    );

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();

    let buffer = terminal.backend().buffer().clone();
    let nickname_title_row = (0..buffer.area.height)
        .find(|&y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .contains("nickname")
        })
        .expect("expected a visible \"nickname\" box title");

    let cursor = terminal
        .get_cursor_position()
        .expect("cursor should be set while the nickname field is focused");
    assert_eq!(
        cursor.y,
        nickname_title_row + 1,
        "the cursor sits in the nickname box's content row, just like the connect popup's fields"
    );
}

/// Each field is its own bordered, titled box - not a bare reversed-text
/// line - the same look every other popup's text fields already use.
/// @requirement AC-393
#[test]
fn every_field_renders_as_a_titled_bordered_box() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));

    let rows = rendered_rows(&state);
    for title in ["nickname", "host", "port", "frequency"] {
        assert!(
            rows.iter().any(|r| r.contains(title)),
            "expected a {title} box title: {rows:?}"
        );
    }
    // A bordered box draws its own top/bottom rule - at least one row
    // must be pure border-drawing characters, distinguishing this from
    // the old single reversed-text-per-field layout.
    assert!(
        rows.iter().any(|r| r.chars().filter(|c| !c.is_whitespace()).all(|c| "\u{2500}\u{250c}\u{2510}\u{2514}\u{2518}\u{2502}".contains(c)) && r.contains('\u{2500}')),
        "expected at least one field's own border rule: {rows:?}"
    );
}

/// Saving from the add/edit form shows a confirmation, not a silent close.
/// @requirement AC-393
#[test]
fn saving_shows_a_confirmation_notice() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "bobhost.example");
    while state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().focus != DirectPunchField::Save {
        press(&mut state, KeyCode::Tab);
    }
    let action = press(&mut state, KeyCode::Enter);
    assert!(matches!(action, Some(UiAction::SaveDirectPunchTargets(_))));

    // The popup itself only requests the save; the confirmation is shown
    // once the session actually persists it (`session::handle_ui_action`'s
    // `SaveDirectPunchTargets` arm) - simulated here the same way other
    // session-side answers are in these UI-level tests.
    state.push_status_notice("direct punch targets saved".to_string(), true);
    let (message, success) = state.status_notice.clone().expect("expected a confirmation notice");
    assert!(success);
    assert_eq!(message, "direct punch targets saved");
}

/// Pasting into a focused text field inserts it exactly like typing it
/// character by character would - the popup is one of the many overlays
/// `handle_paste` now routes through `handle_key` instead of silently
/// dropping (previously, paste only worked in the plain chat compose bar).
/// @requirement AC-394
#[test]
fn pasting_into_the_nickname_field_types_it() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    assert_eq!(
        state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().focus,
        DirectPunchField::Nickname
    );

    let action = state.handle_paste("bob".to_string());
    assert!(action.is_none(), "typing a nickname produces no action");
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().nickname, "bob");
}

/// The port field's own digit-only filter still applies to pasted text,
/// exactly as it does to typed text - pasting garbage does not bypass it.
/// @requirement AC-394
#[test]
fn pasting_into_the_port_field_still_only_keeps_digits() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    press(&mut state, KeyCode::Tab); // nickname -> host
    press(&mut state, KeyCode::Tab); // host -> port
    assert_eq!(
        state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().focus,
        DirectPunchField::Port
    );

    state.handle_paste("12a3b4".to_string());
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().port, "1234");
}

/// @requirement AC-291
#[test]
fn enter_on_a_row_opens_it_prefilled_for_editing() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    state.set_direct_punch_rows(vec![target("bob", "bobhost.example", 9000, 5)]);

    press(&mut state, KeyCode::Enter);
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.editing_index, Some(0));
    assert_eq!(edit.nickname, "bob");
    assert_eq!(edit.host, "bobhost.example");
    assert_eq!(edit.port, "9000");
}

/// @requirement AC-291
#[test]
fn esc_on_the_edit_form_returns_to_the_list_without_losing_other_rows() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    state.set_direct_punch_rows(vec![target("bob", "h", DEFAULT_DIRECT_PUNCH_PORT, 1)]);
    press(&mut state, KeyCode::Char('a'));
    assert!(state.settings_popup.as_ref().unwrap().punches.edit.is_some());

    press(&mut state, KeyCode::Esc);
    assert_eq!(state.mode, Mode::Settings, "Esc on the form must not close the whole popup");
    assert!(state.settings_popup.as_ref().unwrap().punches.edit.is_none());
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.rows.len(), 1);
}

/// @requirement AC-291
#[test]
fn tab_cycles_focus_through_every_field_and_wraps() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
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
        assert_eq!(state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().focus, want);
    }
}

/// @requirement AC-291
#[test]
fn typing_fills_the_focused_text_field() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "bobhost.example");

    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.nickname, "bob");
    assert_eq!(edit.host, "bobhost.example");
}

/// @requirement AC-291
#[test]
fn the_port_field_only_accepts_digits() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    press(&mut state, KeyCode::Tab); // -> Host
    press(&mut state, KeyCode::Tab); // -> Port
    type_str(&mut state, "90a00");
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().port, "9000");
}

/// @requirement AC-291
#[test]
fn left_right_cycle_the_frequency_selector_and_wrap() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Frequency, starts at index 0 (every_1m)

    press(&mut state, KeyCode::Left);
    assert_eq!(
        state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().frequency_index,
        12,
        "Left from the first frequency wraps to the last"
    );
    press(&mut state, KeyCode::Right);
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().frequency_index, 0);
}

/// @requirement AC-291
#[test]
fn enter_on_a_non_save_field_does_nothing() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert!(state.settings_popup.as_ref().unwrap().punches.edit.is_some(), "the form must still be open");
}

// ---------------------------------------------------------------------
// Saving and deleting
// ---------------------------------------------------------------------

/// @requirement AC-291
#[test]
fn saving_a_valid_new_target_appends_it_and_requests_a_save() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
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
    assert!(state.settings_popup.as_ref().unwrap().punches.edit.is_none(), "the form closes on a successful save");
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.rows.len(), 1);
}

/// @requirement AC-291
#[test]
fn saving_edits_an_existing_target_in_place_rather_than_appending() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
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
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    // Left empty - not a storable nickname - then straight to Save.
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "somehost");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert!(edit.error.is_some(), "an empty nickname must be refused with an inline error");
}

/// @requirement AC-291
#[test]
fn d_deletes_the_selected_row_and_requests_a_save() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
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
    assert_eq!(state.settings_popup.as_ref().unwrap().punches.rows.len(), 1);
}

/// @requirement AC-291
#[test]
fn d_on_an_empty_list_does_nothing() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    let action = press(&mut state, KeyCode::Char('d'));
    assert_eq!(action, None);
}
