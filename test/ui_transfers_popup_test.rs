//! The global transfers popup (US-066): the configurable shortcut that
//! opens it, what it lists in both directions, and cancelling, resuming,
//! removing and clearing from it.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::transfer_log::{TransferDirection, TransferRecord, TransferStatus};
use aloo::client::tui::ui::{Mode, UiAction, UiState};
use aloo::settings::KeyChord;
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

fn record(
    direction: TransferDirection,
    id: u64,
    peer: &str,
    status: TransferStatus,
    started: u64,
) -> TransferRecord {
    TransferRecord {
        request_id: id,
        direction,
        peer_name: peer.into(),
        share: "Photos".into(),
        rel_path: "holiday".into(),
        status,
        files_total: Some(4),
        bytes_total: Some(4_000),
        files_done: 1,
        bytes_done: 1_000,
        files_skipped: 0,
        started_unix: started,
    }
}

/// One download still running from alice, one finished upload to bob.
fn state_with_transfers() -> UiState {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.transfers.start(record(
        TransferDirection::Download,
        1,
        "alice",
        TransferStatus::Running,
        200,
    ));
    state.transfers.start(record(
        TransferDirection::Upload,
        2,
        "bob",
        TransferStatus::Completed,
        100,
    ));
    state
}

/// Presses a chord the way a terminal delivers it.
fn chord(state: &mut UiState, code: KeyCode, modifiers: KeyModifiers) -> Option<UiAction> {
    state.handle_key(code, modifiers, KeyEventKind::Press)
}

const CTRL_ALT: KeyModifiers = KeyModifiers::from_bits_truncate(
    KeyModifiers::CONTROL.bits() | KeyModifiers::ALT.bits(),
);

/// @requirement AC-468
#[test]
fn the_default_shortcut_opens_and_closes_the_popup_from_anywhere() {
    let mut state = state_with_transfers();
    assert!(state.transfers_popup.is_none());

    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    assert!(state.transfers_popup.is_some(), "ctrl+alt+d opens it");
    assert_eq!(state.mode, Mode::Transfers);

    // Pressing it again closes it, like Ctrl+H does for help.
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    assert!(state.transfers_popup.is_none());
    assert_eq!(state.mode, Mode::Normal);

    // And Esc closes it too.
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    press(&mut state, KeyCode::Esc);
    assert!(state.transfers_popup.is_none());
}

/// A different chord in the settings file is the one that works, and the
/// default then does not.
/// @requirement AC-468
#[test]
fn the_shortcut_is_whatever_the_settings_say() {
    let mut state = state_with_transfers();
    state.transfers_shortcut = KeyChord::parse("alt+t").expect("parses");

    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    assert!(state.transfers_popup.is_none(), "the old default no longer opens it");

    chord(&mut state, KeyCode::Char('t'), KeyModifiers::ALT);
    assert!(state.transfers_popup.is_some(), "the configured chord does");

    // A letter matches whichever case the terminal reports.
    press(&mut state, KeyCode::Esc);
    chord(&mut state, KeyCode::Char('T'), KeyModifiers::ALT);
    assert!(state.transfers_popup.is_some());
}

/// The popup can be raised over anything, and closing it gives back
/// what was there rather than dropping the user somewhere else.
/// @requirement AC-468
#[test]
fn closing_the_popup_gives_back_the_view_it_was_opened_over() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_peer_shares(aloo::proto::UserId(2), vec!["Photos".into()]);
    state.focus = aloo::client::tui::ui::Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    type_str(&mut state, "/info");
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Enter);
    assert_eq!(state.mode, Mode::SharedFiles, "the browser is up");

    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    assert_eq!(state.mode, Mode::Transfers);
    press(&mut state, KeyCode::Esc);
    assert_eq!(state.mode, Mode::SharedFiles, "the browser is back");
    assert!(state.shared_browser.is_some());
}

/// A chord naming more modifiers than were pressed must not fire.
/// @requirement AC-468
#[test]
fn a_chord_needs_exactly_its_own_modifiers() {
    let mut state = state_with_transfers();
    chord(&mut state, KeyCode::Char('d'), KeyModifiers::CONTROL);
    assert!(state.transfers_popup.is_none(), "ctrl alone is not ctrl+alt");
    chord(&mut state, KeyCode::Char('d'), KeyModifiers::ALT);
    assert!(state.transfers_popup.is_none(), "nor is alt alone");
    chord(&mut state, KeyCode::Char('d'), KeyModifiers::NONE);
    assert!(state.transfers_popup.is_none(), "nor is a bare d");
}

/// @requirement AC-467
#[test]
fn the_popup_lists_both_directions_with_who_and_which_way() {
    let mut state = state_with_transfers();
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    let rows = rendered_rows_at(&state, 110, 44);
    let joined = rows.join("\n");

    assert!(joined.contains("Photos/holiday"), "{joined}");
    assert!(joined.contains("from alice"), "a download says who it is from: {joined}");
    assert!(joined.contains("to bob"), "an upload says who it is to: {joined}");
    assert!(joined.contains('\u{2193}') && joined.contains('\u{2191}'), "both arrows: {joined}");
    assert!(joined.contains("1 running"), "the title counts what is live: {joined}");
    assert!(joined.contains('\u{2588}'), "each row has a progress bar: {joined}");
}

/// Tab narrows the list to one direction and back again.
/// @requirement AC-467
#[test]
fn tab_filters_the_list_by_direction() {
    let mut state = state_with_transfers();
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    assert_eq!(state.transfers_popup_rows().len(), 2);

    press(&mut state, KeyCode::Tab);
    let rows = state.transfers_popup_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].direction, TransferDirection::Download);

    press(&mut state, KeyCode::Tab);
    let rows = state.transfers_popup_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].direction, TransferDirection::Upload);

    press(&mut state, KeyCode::Tab);
    assert_eq!(state.transfers_popup_rows().len(), 2, "back to everything");
}

/// Either side can stop its own transfer, and each says so its own way.
/// @requirement AC-469
#[test]
fn c_cancels_a_download_or_an_upload_depending_on_the_row() {
    let mut state = state_with_transfers();
    // A running upload as well, so both kinds can be selected.
    state.transfers.start(record(
        TransferDirection::Upload,
        3,
        "carol",
        TransferStatus::Running,
        300,
    ));
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);

    // Rows are live-first, most recent first: the upload to carol, then
    // the download from alice, then the finished upload to bob.
    let action = press(&mut state, KeyCode::Char('c'));
    assert_eq!(action, Some(UiAction::CancelSharedUpload { request_id: 3 }));

    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Char('c'));
    assert_eq!(action, Some(UiAction::CancelSharedDownload { request_id: 1 }));

    // Nothing to cancel on a finished row.
    press(&mut state, KeyCode::Down);
    assert!(press(&mut state, KeyCode::Char('c')).is_none());
}

/// @requirement AC-469
#[test]
fn r_resumes_only_a_stopped_download() {
    let mut state = state_with_transfers();
    state.transfers.start(record(
        TransferDirection::Download,
        4,
        "alice",
        TransferStatus::Cancelled,
        400,
    ));
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);

    // The running download is first; resume does not apply to it.
    assert!(press(&mut state, KeyCode::Char('r')).is_none());
    // The cancelled download does.
    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Char('r'));
    assert_eq!(action, Some(UiAction::ResumeSharedDownload { request_id: 4 }));
    // A finished upload has nothing to resume - only the requester can
    // ask again.
    press(&mut state, KeyCode::Down);
    assert!(press(&mut state, KeyCode::Char('r')).is_none());
}

/// @requirement AC-469
#[test]
fn x_removes_a_finished_row_and_capital_x_clears_them_all() {
    let mut state = state_with_transfers();
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);

    // On the running download: refused.
    assert!(press(&mut state, KeyCode::Char('x')).is_none());
    assert_eq!(state.transfers.records().len(), 2);

    // On the finished upload: removed, and the history written back.
    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Char('x'));
    assert_eq!(action, Some(UiAction::SaveTransferHistory));
    assert_eq!(state.transfers.records().len(), 1);
    assert_eq!(state.transfers.records()[0].request_id, 1);

    state.transfers.start(record(
        TransferDirection::Upload,
        5,
        "dan",
        TransferStatus::Failed("gone".into()),
        500,
    ));
    let action = press(&mut state, KeyCode::Char('X'));
    assert_eq!(action, Some(UiAction::SaveTransferHistory));
    assert_eq!(state.transfers.records().len(), 1, "the running one is left");
    assert!(state.transfers.records()[0].status.is_active());
}

/// @requirement AC-467
#[test]
fn an_empty_history_says_so() {
    let mut state = joined_general_with(vec![]);
    chord(&mut state, KeyCode::Char('d'), CTRL_ALT);
    let rows = rendered_rows_at(&state, 110, 44);
    assert!(
        rows.iter().any(|r| r.contains("no file-share transfers yet")),
        "{rows:?}"
    );
}

/// The chord spelling accepted in the settings file, and what it refuses.
/// @requirement AC-468
#[test]
fn a_shortcut_is_parsed_and_written_back_the_same_way() {
    for (text, expected) in [
        ("ctrl+alt+d", "ctrl+alt+d"),
        ("CTRL+ALT+D", "ctrl+alt+d"),
        ("control+option+d", "ctrl+alt+d"),
        ("alt+t", "alt+t"),
        ("f5", "f5"),
        ("shift+ctrl+q", "ctrl+shift+q"),
    ] {
        let chord = KeyChord::parse(text).unwrap_or_else(|| panic!("{text} should parse"));
        assert_eq!(chord.to_setting_value(), expected, "{text}");
        assert_eq!(
            KeyChord::parse(&chord.to_setting_value()),
            Some(chord),
            "{text} should round-trip"
        );
    }
    for bad in ["", "ctrl", "ctrl+", "ctrl+alt", "ctrl+ab", "ctrl+f99", "d+t"] {
        assert!(KeyChord::parse(bad).is_none(), "{bad:?} should be refused");
    }
    assert_eq!(KeyChord::default().to_setting_value(), "ctrl+alt+d");
}
