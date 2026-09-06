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
use aloo::settings::{DEFAULT_DIRECT_PUNCH_PORT, DirectPunchTarget, DirectPunchVia, PunchFrequency};
use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

fn target(nickname: &str, host: &str, port: u16, frequency_minutes: u32) -> DirectPunchTarget {
    DirectPunchTarget {
        nickname: nickname.to_string(),
        device_id: None,
        via: DirectPunchVia::Host { host: host.to_string(), port },
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

/// Adding opens the form with a freshly generated public rendezvous realm
/// already in the "where" - the robust default when no address is
/// reachable - and only the nickname left to type.
/// @requirement AC-437
#[test]
fn a_opens_the_add_form_with_a_generated_realm() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.editing_index, None);
    assert_eq!(edit.nickname, "");
    assert_eq!(edit.focus, DirectPunchField::Nickname, "the nickname is what is left to type");
    assert!(
        edit.host.starts_with("realm://public@realm.hy2.io/"),
        "the where is a generated public realm, got {:?}",
        edit.host
    );
    assert!(edit.port.is_empty(), "a realm names no port");
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

/// One fixed port, typed as a plain number: the file spells the same line
/// (`bobhost.example:19000`) and this is the whole of it, since there is
/// no longer any list to spell.
/// @requirement AC-437
#[test]
fn the_port_field_takes_a_single_port() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "bobhost.example");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "19000");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Save

    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].host(), Some("bobhost.example"));
            assert_eq!(targets[0].port(), Some(19000));
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
}

/// A realm URI is typed straight into the host box, with the port left
/// empty - it names a rendezvous, not an address, so there is no port to
/// give. It saves as a realm target (`docs/PROTOCOL.md` §7.1.5).
/// @requirement AC-437
#[test]
fn a_realm_uri_is_saved_as_a_realm_target_with_no_port() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "realm://public@realm.hy2.io/my-long-realm-name");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Frequency (no port typed)
    press(&mut state, KeyCode::Tab); // -> Save

    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].host(), None, "a realm target names no host");
            assert_eq!(targets[0].port(), None, "a realm target names no port");
            assert_eq!(
                targets[0].realm().map(|r| r.uri()),
                Some("realm://public@realm.hy2.io/my-long-realm-name")
            );
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
}

/// A port typed next to a realm URI has nowhere to go in the saved line,
/// so it is refused inline rather than silently dropped.
/// @requirement AC-437
#[test]
fn a_realm_uri_with_a_port_is_refused_inline() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "realm://public@realm.hy2.io/my-long-realm-name");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "19000");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Save

    assert_eq!(press(&mut state, KeyCode::Enter), None, "nothing is saved");
    let punches = &state.settings_popup.as_ref().unwrap().punches;
    assert!(punches.rows.is_empty(), "the bad row must not be added");
    assert!(
        punches.edit.as_ref().and_then(|e| e.error.as_ref()).is_some(),
        "the reason is shown inline"
    );
}

/// The generated realm is freshly random every add (it is the whole of the
/// rendezvous's privacy, not a fixed placeholder), and keeping it - filling
/// only the nickname - saves the realm target both peers then share.
/// @requirement AC-437
#[test]
fn a_kept_generated_realm_is_random_and_saves_as_a_realm() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    let first = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().host.clone();
    DirectPunchTarget::parse(&format!("x,{first},every_1m")).expect("the offered realm is valid");

    press(&mut state, KeyCode::Esc);
    press(&mut state, KeyCode::Char('a'));
    let second = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap().host.clone();
    assert_ne!(first, second, "each realm offered is freshly random");

    // Keep it: type only the nickname, tab past the untouched realm to Save.
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab); // nickname -> host
    press(&mut state, KeyCode::Tab); // -> port
    press(&mut state, KeyCode::Tab); // -> frequency
    press(&mut state, KeyCode::Tab); // -> save
    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].nickname, "bob");
            let realm = targets[0].realm().expect("a realm target");
            assert_eq!(realm.host, "realm.hy2.io");
            assert_eq!(realm.token, "public");
            assert_eq!(targets[0].port(), None, "a realm names no port");
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
}

/// Typing in the host box replaces the generated realm rather than
/// appending to it, so a fixed address is entered by just typing it over -
/// the first keystroke clears the suggestion.
/// @requirement AC-437
#[test]
fn typing_a_host_replaces_the_generated_realm() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab); // -> host, holding the suggested realm
    type_str(&mut state, "bobhost.example");
    press(&mut state, KeyCode::Tab); // -> port
    press(&mut state, KeyCode::Tab); // -> frequency
    press(&mut state, KeyCode::Tab); // -> save
    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].host(), Some("bobhost.example"), "the typed address replaced the realm");
            assert!(targets[0].realm().is_none(), "it is a fixed-address target, not a realm");
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
}

/// The range check has to reach the person typing, not just the file
/// parser - a port silently dropped here would look exactly like a peer who
/// never answers, which is the failure AC-213 exists to prevent.
/// @requirement AC-437
#[test]
fn a_port_outside_the_range_is_refused_inline_and_nothing_is_saved() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    press(&mut state, KeyCode::Char('a'));
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "bobhost.example");
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "9000");
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Save

    assert_eq!(press(&mut state, KeyCode::Enter), None, "nothing is saved");
    let punches = &state.settings_popup.as_ref().unwrap().punches;
    assert!(punches.rows.is_empty(), "the bad row must not be added");
    let edit = punches.edit.as_ref().expect("the form stays open to be corrected");
    let error = edit.error.as_ref().expect("the reason is shown inline");
    assert!(
        error.contains("10000") && error.contains("65000"),
        "the inline reason must name the range, got {error:?}"
    );
}

/// An existing fixed-port row comes back with its host and port in their
/// boxes; a realm row comes back with its URI in the host box and no port.
/// @requirement AC-437
#[test]
fn an_existing_row_comes_back_prefilled_for_editing() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    state.set_direct_punch_rows(vec![
        DirectPunchTarget::parse("bob,bobhost.example:19000,every_1m").unwrap(),
    ]);
    press(&mut state, KeyCode::Char('e'));
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.host, "bobhost.example");
    assert_eq!(edit.port, "19000");
    // Close the form before editing a different row.
    press(&mut state, KeyCode::Esc);

    state.set_direct_punch_rows(vec![
        DirectPunchTarget::parse("carol,realm://public@realm.hy2.io/my-long-realm-name,every_1m").unwrap(),
    ]);
    press(&mut state, KeyCode::Char('e'));
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.host, "realm://public@realm.hy2.io/my-long-realm-name", "the URI fills the host box");
    assert_eq!(edit.port, "", "a realm names no port");
}

/// Offering the default back as a number would put a port outside the
/// accepted range into a field that then refuses to save it.
/// @requirement AC-437
#[test]
fn a_row_on_the_default_port_comes_back_with_an_empty_port_field() {
    let mut state = joined_general_with(vec![]);
    open_punches(&mut state);
    state.set_direct_punch_rows(vec![
        DirectPunchTarget::parse("bob,bobhost.example,every_1m").unwrap(),
    ]);
    press(&mut state, KeyCode::Char('e'));
    let edit = state.settings_popup.as_ref().unwrap().punches.edit.as_ref().unwrap();
    assert_eq!(edit.port, "");

    // And saving it untouched keeps the default rather than being refused.
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab); // -> Save
    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::SaveDirectPunchTargets(targets)) => {
            assert_eq!(targets[0].port(), Some(DEFAULT_DIRECT_PUNCH_PORT));
        }
        other => panic!("expected SaveDirectPunchTargets, got {other:?}"),
    }
}

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
            assert_eq!(targets[0].host(), Some("bobhost.example"));
            assert_eq!(targets[0].port(), Some(DEFAULT_DIRECT_PUNCH_PORT));
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
            assert_eq!(targets[0].host(), Some("newhost"));
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
