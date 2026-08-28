//! The Ctrl+S settings popup (US-039): its three tabs, moving between
//! them and between the fields on them, what each key does to a toggle or
//! a text box, and the draft that every one of those changes hands the
//! session to persist.
//!
//! The Direct Punch tab's target list itself is
//! `ui_direct_punch_popup_test.rs`.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::tui::settings_popup::{SettingsDraft, SettingsField, SettingsTab};
use aloo::client::tui::ui::{Mode, UiAction, UiState};
use aloo::settings::Settings;
use crossterm::event::KeyCode;

/// Opens the popup with everything at its compiled-in default, the state
/// `OpenSettings`'s answer would leave it in on a fresh machine.
fn open_settings() -> UiState {
    let mut state = joined_general_with(vec![]);
    state.open_settings();
    state
}

fn draft(state: &UiState) -> &SettingsDraft {
    &state.settings_popup.as_ref().expect("the popup is open").draft
}

fn focused(state: &UiState) -> SettingsField {
    state.settings_popup.as_ref().expect("the popup is open").focused_field()
}

/// Moves the focus down until `field` has it, so a test can name the field
/// it cares about instead of counting keystrokes to it.
fn focus_on(state: &mut UiState, field: SettingsField) {
    for _ in 0..32 {
        if focused(state) == field {
            return;
        }
        press(state, KeyCode::Down);
    }
    panic!("{field:?} is not on the tab that is open");
}

/// The action a change produces, with the popup's own draft in it.
fn saved(action: Option<UiAction>) -> SettingsDraft {
    match action {
        Some(UiAction::SaveSettings(draft)) => draft,
        other => panic!("expected SaveSettings, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Opening, tabs, focus
// ---------------------------------------------------------------------

/// @requirement AC-397
#[test]
fn ctrl_s_opens_the_settings_popup_on_its_first_tab_and_requests_a_load() {
    let mut state = joined_general_with(vec![]);
    let action = ctrl(&mut state, KeyCode::Char('s'));
    assert_eq!(action, Some(UiAction::OpenSettings));
    assert_eq!(state.mode, Mode::Settings);
    let popup = state.settings_popup.as_ref().unwrap();
    assert_eq!(popup.tab, SettingsTab::General);
    assert_eq!(popup.focus, 0);
}

/// @requirement AC-397
#[test]
fn tab_and_backtab_cycle_the_three_tabs_and_wrap() {
    let mut state = open_settings();
    for want in [SettingsTab::DirectPunch, SettingsTab::Otp, SettingsTab::General] {
        press(&mut state, KeyCode::Tab);
        assert_eq!(state.settings_popup.as_ref().unwrap().tab, want);
    }
    press(&mut state, KeyCode::BackTab);
    assert_eq!(state.settings_popup.as_ref().unwrap().tab, SettingsTab::Otp);
}

/// Every tab starts on its own first field, whichever field the previous
/// tab was left on - the field index is an index into *this* tab's list.
/// @requirement AC-397
#[test]
fn switching_tabs_puts_the_focus_on_the_new_tabs_first_field() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::ResumeFromLog);
    press(&mut state, KeyCode::Tab);
    assert_eq!(focused(&state), SettingsField::DirectPunchEnabled);
    press(&mut state, KeyCode::Tab);
    assert_eq!(focused(&state), SettingsField::OtpLowKeyWarnPct);
}

/// @requirement AC-397
#[test]
fn up_and_down_wrap_around_the_fields_of_a_tab() {
    let mut state = open_settings();
    assert_eq!(focused(&state), SettingsField::GlobalPttEnabled);
    press(&mut state, KeyCode::Up);
    assert_eq!(
        focused(&state),
        SettingsField::QueueSendMessages,
        "Up from the first field wraps to the last"
    );
    press(&mut state, KeyCode::Down);
    assert_eq!(focused(&state), SettingsField::GlobalPttEnabled);
}

/// @requirement AC-397
#[test]
fn esc_closes_the_popup() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Esc);
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.settings_popup.is_none());
}

// ---------------------------------------------------------------------
// Toggles
// ---------------------------------------------------------------------

/// The three sound switches and the global push-to-talk one are on out of
/// the box; the two log ones are off. That is what a fresh
/// `~/.aloo/settings` says, and the popup shows the file rather than a
/// second opinion about it.
/// @requirement AC-398
#[test]
fn the_defaults_the_popup_opens_with_are_the_settings_files_own() {
    let state = open_settings();
    let d = draft(&state);
    assert!(d.global_ptt_enabled);
    assert!(d.voice_autoplay);
    assert!(d.roger_beep);
    assert!(d.sound_notifications);
    assert!(!d.autosave_messages);
    assert!(!d.resume_from_log);
    assert_eq!(d, &SettingsDraft::from_settings(&Settings::default()));
}

/// Space belongs to the popup while it is open, not to push-to-talk -
/// which sits above every other mode in `handle_key` and would otherwise
/// swallow it and start recording instead of flipping the switch.
/// @requirement AC-404
#[test]
fn space_in_the_popup_flips_a_switch_rather_than_starting_a_recording() {
    let mut state = open_settings();
    let action = press(&mut state, KeyCode::Char(' '));
    assert!(
        !matches!(action, Some(UiAction::VoiceRecordStart(_))),
        "Space must not start a recording while the settings are open: {action:?}"
    );
    assert!(!state.recording, "and no recording may be in progress");
    assert!(!saved(action).global_ptt_enabled, "it flipped the focused switch instead");
}

/// @requirement AC-398
#[test]
fn space_flips_the_focused_toggle_and_asks_for_a_save() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::RogerBeep);
    let action = press(&mut state, KeyCode::Char(' '));
    assert!(!saved(action).roger_beep);
    assert!(!draft(&state).roger_beep, "the popup shows the new value straight away");

    let action = press(&mut state, KeyCode::Char(' '));
    assert!(saved(action).roger_beep, "and flips back");
}

/// Enter does what Space does on a toggle - there is no separate
/// "activate", so the two obvious keys must not disagree.
/// @requirement AC-398
#[test]
fn enter_flips_a_toggle_the_same_way_space_does() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::VoiceAutoplay);
    let action = press(&mut state, KeyCode::Enter);
    assert!(!saved(action).voice_autoplay);
}

/// Each toggle is its own field: flipping one must not disturb another.
/// @requirement AC-398
#[test]
fn each_toggle_changes_only_itself() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::SoundNotifications);
    let saved = saved(press(&mut state, KeyCode::Char(' ')));
    assert!(!saved.sound_notifications);
    assert!(saved.roger_beep, "the roger beep is a separate switch");
    assert!(saved.voice_autoplay);
    assert!(saved.global_ptt_enabled);
}

/// @requirement AC-398
#[test]
fn the_log_switches_are_on_the_general_tab_and_flip_too() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::AutosaveMessages);
    assert!(saved(press(&mut state, KeyCode::Char(' '))).autosave_messages);
    focus_on(&mut state, SettingsField::ResumeFromLog);
    assert!(saved(press(&mut state, KeyCode::Char(' '))).resume_from_log);
}

/// @requirement AC-399
#[test]
fn the_direct_punch_and_noip_switches_live_on_the_direct_punch_tab() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    assert_eq!(focused(&state), SettingsField::DirectPunchEnabled);
    assert!(saved(press(&mut state, KeyCode::Char(' '))).direct_punch);

    focus_on(&mut state, SettingsField::NoipEnabled);
    assert!(saved(press(&mut state, KeyCode::Char(' '))).noip_enabled);
}

// ---------------------------------------------------------------------
// Text fields
// ---------------------------------------------------------------------

/// @requirement AC-398
#[test]
fn typing_into_a_text_field_fills_it_and_asks_for_a_save_per_keystroke() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::GlobalPttShortcut);
    // The default is already in the box - clear it first.
    for _ in 0..Settings::default().global_ptt_shortcut.len() {
        press(&mut state, KeyCode::Backspace);
    }
    assert_eq!(draft(&state).global_ptt_shortcut, "");

    let action = press(&mut state, KeyCode::Char('f'));
    assert_eq!(saved(action).global_ptt_shortcut, "f");
    type_str(&mut state, "8");
    assert_eq!(draft(&state).global_ptt_shortcut, "f8");
}

/// @requirement AC-399
#[test]
fn the_noip_boxes_are_three_independent_text_fields() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::NoipHostname);
    type_str(&mut state, "me.ddns.net");
    focus_on(&mut state, SettingsField::NoipUsername);
    type_str(&mut state, "alice");
    focus_on(&mut state, SettingsField::NoipPassword);
    type_str(&mut state, "hunter2");

    let d = draft(&state);
    assert_eq!(d.noip_hostname, "me.ddns.net");
    assert_eq!(d.noip_username, "alice");
    assert_eq!(d.noip_password, "hunter2");
}

/// A settings line is one `key=value` on one line, so the character that
/// would split it in two is the one character a text box refuses.
/// @requirement AC-398
#[test]
fn a_text_field_refuses_the_one_character_that_would_break_its_line() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::NoipHostname);
    type_str(&mut state, "a=b");
    assert_eq!(draft(&state).noip_hostname, "ab");
}

/// @requirement AC-400
#[test]
fn the_otp_tab_holds_the_warning_threshold_and_the_binary_path() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    assert_eq!(focused(&state), SettingsField::OtpLowKeyWarnPct);
    press(&mut state, KeyCode::Down);
    assert_eq!(focused(&state), SettingsField::OtpBinaryPath);
    type_str(&mut state, "/opt/otp");
    assert_eq!(draft(&state).otp_binary_path, "/opt/otp");
}

/// @requirement AC-400
#[test]
fn the_percentage_field_takes_digits_only_and_no_more_than_three() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::OtpLowKeyWarnPct);
    while !draft(&state).otp_low_key_warn_pct.is_empty() {
        press(&mut state, KeyCode::Backspace);
    }
    type_str(&mut state, "2x5");
    assert_eq!(draft(&state).otp_low_key_warn_pct, "25");
    type_str(&mut state, "789");
    assert_eq!(draft(&state).otp_low_key_warn_pct, "257", "three digits is the cap");
}

/// Backspace on an already-empty box is not a change, so it must not
/// produce a save - otherwise every stray keypress rewrites the file.
/// @requirement AC-398
#[test]
fn backspace_on_an_empty_field_asks_for_nothing() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::NoipHostname);
    assert_eq!(press(&mut state, KeyCode::Backspace), None);
}

// ---------------------------------------------------------------------
// Turning a draft back into settings
// ---------------------------------------------------------------------

/// @requirement AC-398
#[test]
fn applying_a_draft_writes_every_field_it_owns() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::VoiceAutoplay);
    press(&mut state, KeyCode::Char(' '));
    focus_on(&mut state, SettingsField::AutosaveMessages);
    press(&mut state, KeyCode::Char(' '));

    let mut settings = Settings::default();
    draft(&state).apply_to(&mut settings);
    assert!(!settings.voice_autoplay);
    assert!(settings.autosave_messages);
    assert!(settings.roger_beep, "an untouched field keeps its value");
}

/// A half-typed percentage is not a value to save: the file keeps what it
/// had rather than being written a zero (or a 300).
/// @requirement AC-400
#[test]
fn a_percentage_that_is_not_one_leaves_the_stored_value_alone() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::OtpLowKeyWarnPct);
    while !draft(&state).otp_low_key_warn_pct.is_empty() {
        press(&mut state, KeyCode::Backspace);
    }

    let mut settings = Settings {
        otp_low_key_warn_pct: 30,
        ..Settings::default()
    };
    draft(&state).apply_to(&mut settings);
    assert_eq!(settings.otp_low_key_warn_pct, 30, "an empty box saves nothing");

    type_str(&mut state, "300");
    draft(&state).apply_to(&mut settings);
    assert_eq!(settings.otp_low_key_warn_pct, 30, "and neither does an impossible one");

    while !draft(&state).otp_low_key_warn_pct.is_empty() {
        press(&mut state, KeyCode::Backspace);
    }
    type_str(&mut state, "7");
    draft(&state).apply_to(&mut settings);
    assert_eq!(settings.otp_low_key_warn_pct, 7);
}

/// An emptied `otp_binary_path` box means "find it on PATH", which is
/// `None` - not an empty string that would be looked for as a filename.
/// @requirement AC-400
#[test]
fn an_empty_binary_path_box_means_no_override_at_all() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::OtpBinaryPath);
    type_str(&mut state, "/opt/otp");

    let mut settings = Settings::default();
    draft(&state).apply_to(&mut settings);
    assert_eq!(settings.otp_binary_path.as_deref(), Some("/opt/otp"));

    for _ in 0.."/opt/otp".len() {
        press(&mut state, KeyCode::Backspace);
    }
    draft(&state).apply_to(&mut settings);
    assert_eq!(settings.otp_binary_path, None);
}

/// An emptied shortcut box is not a shortcut: `Settings::parse` ignores an
/// empty value for that key, so writing one would leave the file and the
/// popup disagreeing about what is configured.
/// @requirement AC-398
#[test]
fn an_empty_shortcut_box_leaves_the_stored_shortcut_alone() {
    let mut state = open_settings();
    focus_on(&mut state, SettingsField::GlobalPttShortcut);
    for _ in 0..Settings::default().global_ptt_shortcut.len() {
        press(&mut state, KeyCode::Backspace);
    }

    let mut settings = Settings::default();
    draft(&state).apply_to(&mut settings);
    assert_eq!(settings.global_ptt_shortcut, Settings::default().global_ptt_shortcut);
}

/// `set_settings_draft` is how the session hands the file's real contents
/// to a popup that opened on the defaults.
/// @requirement AC-397
#[test]
fn the_session_can_replace_the_draft_with_what_is_on_disk() {
    let mut state = open_settings();
    let on_disk = Settings {
        roger_beep: false,
        noip_hostname: "me.ddns.net".to_string(),
        ..Settings::default()
    };
    state.set_settings_draft(SettingsDraft::from_settings(&on_disk));

    assert!(!draft(&state).roger_beep);
    assert_eq!(draft(&state).noip_hostname, "me.ddns.net");
}

/// @requirement AC-397
#[test]
fn set_settings_draft_is_a_no_op_once_the_popup_is_closed() {
    let mut state = joined_general_with(vec![]);
    state.set_settings_draft(SettingsDraft::default());
    assert!(state.settings_popup.is_none());
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// @requirement AC-397
#[test]
fn every_tab_names_itself_and_the_open_one_is_marked() {
    let state = open_settings();
    let rows = rendered_rows_at(&state, 100, 46);
    let tab_row = rows
        .iter()
        .find(|r| r.contains("General") && r.contains("Direct Punch") && r.contains("OTP"))
        .expect("expected a tab row naming all three tabs");
    assert!(tab_row.contains("General"), "{tab_row}");
}

/// The open tab is drawn as a filled tab, not as one of three words that
/// happens to be bold - a background colour the other two do not have.
/// @requirement AC-405
#[test]
fn the_open_tab_is_drawn_with_a_background_of_its_own() {
    let mut state = open_settings();
    let background_of = |state: &UiState, title: &str| {
        let buffer = buffer_at(state, 100, 46);
        let (x, y) = find_text_start(&buffer, title);
        buffer[(x, y)].style().bg
    };

    let general = background_of(&state, "General");
    let otp = background_of(&state, "OTP");
    assert!(general.is_some(), "the open tab should be filled: {general:?}");
    assert_ne!(general, otp, "an unopened tab must not share that fill");

    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    assert_eq!(
        background_of(&state, "OTP"),
        general,
        "the fill follows whichever tab is open"
    );
    assert_ne!(background_of(&state, "General"), general);
}

/// @requirement AC-406
#[test]
fn the_queue_switch_is_the_last_field_on_the_general_tab_and_defaults_on() {
    let mut state = open_settings();
    assert!(draft(&state).queue_send_messages);
    focus_on(&mut state, SettingsField::QueueSendMessages);
    assert!(!saved(press(&mut state, KeyCode::Char(' '))).queue_send_messages);

    let mut settings = Settings::default();
    draft(&state).apply_to(&mut settings);
    assert!(!settings.queue_send_messages);
}

/// Each bordered area is separated from the next by a blank row, and the
/// shortcut box from the switches under it - grouping the eye can follow
/// without reading a single label.
/// @requirement AC-405
#[test]
fn a_blank_row_separates_each_area_and_follows_the_shortcut_box() {
    let state = open_settings();
    let rows = rendered_rows_at(&state, 100, 46);
    let row_of = |needle: &str| {
        rows.iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("expected {needle:?} on screen: {rows:?}"))
    };
    // Inside the popup a "blank" row is the two side borders and spaces.
    let is_blank_inside_popup = |i: usize| {
        let inner: String = rows[i].chars().filter(|c| *c != '\u{2502}').collect();
        inner.trim().is_empty()
    };

    // The shortcut box's bottom rule, then a gap, then voice_autoplay.
    let autoplay = row_of("voice_autoplay");
    assert!(
        is_blank_inside_popup(autoplay - 1),
        "expected a blank row under the shortcut box: {:?}",
        rows[autoplay - 1]
    );
    // Every area's own top rule has a gap above it.
    for title in ["notifications", "logs", "delivery"] {
        let at = row_of(title);
        assert!(
            is_blank_inside_popup(at - 1),
            "expected a blank row above the {title:?} area: {:?}",
            rows[at - 1]
        );
    }
}

/// Each tab draws its fields inside titled, bordered areas - the grouping
/// the settings file's own comment headers give it.
/// @requirement AC-397
#[test]
fn the_general_tab_draws_its_three_bordered_areas() {
    let state = open_settings();
    let rows = rendered_rows_at(&state, 100, 40);
    for title in ["voice / ptt", "notifications", "logs", "delivery"] {
        assert!(rows.iter().any(|r| r.contains(title)), "expected a {title:?} area: {rows:?}");
    }
}

/// @requirement AC-399
#[test]
fn the_direct_punch_tab_draws_its_two_bordered_areas_and_the_punch_list() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    let rows = rendered_rows_at(&state, 100, 40);
    for title in ["direct_punch", "configured punches", "noip"] {
        assert!(rows.iter().any(|r| r.contains(title)), "expected a {title:?} area: {rows:?}");
    }
}

/// Everything the popup has drawn, as one whitespace-collapsed string
/// with the box-drawing rules taken out - so an assertion can name a
/// sentence without caring which row the wrap put each half of it on.
fn popup_text(state: &UiState) -> String {
    rendered_rows_at(state, 100, 46)
        .iter()
        .map(|row| {
            row.chars()
                .map(|c| if "\u{2500}\u{2502}\u{250c}\u{2510}\u{2514}\u{2518}".contains(c) { ' ' } else { c })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Every field on the open tab gets its short gray explanation at the end
/// of it - the reason each switch exists, without leaving the popup.
/// @requirement AC-401
#[test]
fn each_tab_ends_with_a_short_description_of_every_field_on_it() {
    for (tab_presses, tab) in [(0, SettingsTab::General), (1, SettingsTab::DirectPunch), (2, SettingsTab::Otp)] {
        let mut state = open_settings();
        for _ in 0..tab_presses {
            press(&mut state, KeyCode::Tab);
        }
        let text = popup_text(&state);
        for field in tab.fields() {
            let want = format!("{}: {}", field.label(), field.description());
            assert!(
                text.contains(&want),
                "expected {want:?} on the {tab:?} tab, got: {text}"
            );
        }
    }
}

/// A toggle reads as on or off at a glance, in words and in colour -
/// green filled for on, red for off - without having to know which way
/// round a highlight means.
/// @requirement AC-398, AC-405
#[test]
fn a_toggle_draws_its_state_in_words_and_in_colour() {
    let row_with = |state: &UiState, word: &str| {
        rendered_rows_at(state, 130, 46)
            .iter()
            .any(|r| r.contains("global_ptt_enabled") && r.contains(word))
    };
    let value_colour = |state: &UiState, word: &str| {
        let buffer = buffer_at(state, 130, 46);
        let (x, y) = find_text_start(&buffer, word);
        buffer[(x, y)].style().bg
    };

    let mut state = open_settings();
    assert!(row_with(&state, "ON"));
    assert_eq!(value_colour(&state, "ON"), Some(ratatui::style::Color::Green));

    press(&mut state, KeyCode::Char(' '));
    assert!(row_with(&state, "OFF"));
    assert_eq!(value_colour(&state, "OFF"), Some(ratatui::style::Color::Red));
}

/// Every field's explanation fits on one line at the popup's own width -
/// the reason that width is what it is.
/// @requirement AC-401
#[test]
fn every_description_fits_on_one_line() {
    for tab_presses in 0..3 {
        let mut state = open_settings();
        for _ in 0..tab_presses {
            press(&mut state, KeyCode::Tab);
        }
        let tab = state.settings_popup.as_ref().unwrap().tab;
        let rows = rendered_rows_at(&state, 130, 46);
        for field in tab.fields() {
            let want = format!("{}: {}", field.label(), field.description());
            assert!(
                rows.iter().any(|r| r.contains(&want)),
                "{want:?} should sit on one row, unwrapped: {rows:?}"
            );
        }
    }
}

/// The No-IP password is the one settings value worth not showing to
/// whoever is behind you - it is dotted out unless it is the box being
/// typed into.
/// @requirement AC-399
#[test]
fn the_noip_password_is_hidden_unless_it_is_the_focused_box() {
    let mut state = open_settings();
    press(&mut state, KeyCode::Tab);
    focus_on(&mut state, SettingsField::NoipPassword);
    type_str(&mut state, "hunter2");
    assert!(
        rendered_rows_at(&state, 100, 44).iter().any(|r| r.contains("hunter2")),
        "the box being typed into shows what is being typed"
    );

    focus_on(&mut state, SettingsField::NoipHostname);
    let rows = rendered_rows_at(&state, 100, 44);
    assert!(!rows.iter().any(|r| r.contains("hunter2")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("\u{2022}\u{2022}\u{2022}")), "{rows:?}");
}




