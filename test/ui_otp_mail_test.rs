//! The OTP mail surface at the `UiState` level (docs/PROTOCOL.md §17):
//! the `/mail` compose view, live recipient validation, the realtime key
//! budget, attachments (browser + hold-Space recording), the confirm
//! popups, the mailbox and the reader - all driven through `handle_key`
//! exactly as the terminal would, with the session-side answers injected
//! through the same setters `session.rs` uses.

#[path = "ui_common.rs"]
mod ui_common;

use aloo::client::file_browser::FileBrowserState;
use aloo::client::otp_mail::{MAIL_OVERHEAD_ESTIMATE, RecipientCheck};
use aloo::client::otp_mail_store::{ReceivedMailRef, SentMailRef, SentMailStatus};
use aloo::client::tui::otp_mail::{MailAttachment, MailDeviceOption, MailFocus, MailboxRow};
use aloo::client::tui::ui::{UiAction, UiState, VoiceTarget, render};
use aloo::crypto::otp::{OtpMailFile, OtpMailPayload, OtpMailVoice};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ui_common::{ctrl, joined_general_with, press, type_str, user};

/// `/mail` only asks the session to open the view
/// (`UiAction::RequestOpenOtpMail`) - only it can check the local `otp`
/// binary is available (`client::otp_mail::handle_open_otp_mail`), which
/// `UiState` alone has no way to do. The call here simulates that session
/// answering with the binary present, the same way these UI-level tests
/// simulate every other session-side answer (module doc).
fn open_mail(state: &mut UiState) {
    type_str(state, "/mail");
    assert_eq!(
        press(state, KeyCode::Enter),
        Some(UiAction::RequestOpenOtpMail),
        "/mail asks the session to check the binary before opening"
    );
    assert!(state.input.is_empty(), "the command is consumed");
    assert!(
        state.otp_mail.is_none(),
        "not open yet - only the session's answer opens it"
    );
    state.open_otp_mail();
    assert!(state.otp_mail.is_some(), "/mail should open the mail view");
}

fn open_mailbox(state: &mut UiState) {
    type_str(state, "/mailbox");
    assert_eq!(
        press(state, KeyCode::Enter),
        Some(UiAction::OpenOtpMailbox),
        "/mailbox asks the session for the rows"
    );
    assert!(state.otp_mail.is_some(), "and opens the mail view as backdrop");
}

fn ok_check(remaining: u64) -> RecipientCheck {
    RecipientCheck::Ok {
        contact_name: "abc-def".into(),
        enc_key_remaining: remaining,
    }
}

fn rows_of(state: &UiState) -> Vec<String> {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

fn sent_ref(status: SentMailStatus) -> SentMailRef {
    SentMailRef {
        mail_id: "aa".repeat(16),
        to: "bob".into(),
        contact_name: "abc-def".into(),
        seq: 0,
        sent_at_utc: 1_700_000_000,
        status,
    }
}

fn received_ref() -> ReceivedMailRef {
    ReceivedMailRef {
        mail_id: "bb".repeat(16),
        from: "alice".into(),
        sent_at_utc: 1_700_000_100,
        received_at_utc: 1_700_000_200,
        size: 42,
        read: false,
    }
}

fn make_file(size: usize, name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-ui-otp-mail-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), vec![0u8; size]).unwrap();
    dir
}

// ---------------------------------------------------------------------
// Opening / closing / fields (AC-154)
// ---------------------------------------------------------------------

/// @requirement AC-154
#[test]
fn slash_mail_opens_the_full_screen_compose_view() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    let rows = rows_of(&state);
    assert!(
        rows.iter().any(|r| r.contains("New OTP mail")),
        "the compose view replaces the whole screen: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("from me")),
        "From is fixed to the user's own nickname: {rows:?}"
    );
    for field in ["To", "Subtext", "Content", "Attachments"] {
        assert!(
            rows.iter().any(|r| r.contains(field)),
            "the {field} field should be visible: {rows:?}"
        );
    }
    assert!(
        !rows.iter().any(|r| r.contains("general")),
        "the channel view is fully replaced: {rows:?}"
    );
}

/// @requirement AC-154
#[test]
fn esc_discards_the_compose_view() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    assert!(press(&mut state, KeyCode::Esc).is_none());
    assert!(state.otp_mail.is_none());
}

/// @requirement AC-154
#[test]
fn fields_are_entered_independently_in_any_order() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    // Straight past To into Content first, then Subtext, then back to To -
    // nothing forces an order and nothing is lost.
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "body first");
    press(&mut state, KeyCode::Enter); // a newline inside Content
    type_str(&mut state, "second line");
    press(&mut state, KeyCode::BackTab);
    type_str(&mut state, "subject later");
    press(&mut state, KeyCode::BackTab);
    type_str(&mut state, "bob");
    let compose = &state.otp_mail.as_ref().unwrap().compose;
    assert_eq!(compose.to, "bob");
    assert_eq!(compose.subtext, "subject later");
    assert_eq!(compose.content, "body first\nsecond line");
}

// ---------------------------------------------------------------------
// Recipient validation (AC-155)
// ---------------------------------------------------------------------

/// @requirement AC-155
#[test]
fn typing_in_to_emits_a_recipient_check_per_keystroke() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    assert_eq!(
        press(&mut state, KeyCode::Char('b')),
        Some(UiAction::CheckOtpMailRecipient { nickname: "b".into() })
    );
    assert_eq!(
        press(&mut state, KeyCode::Char('o')),
        Some(UiAction::CheckOtpMailRecipient { nickname: "bo".into() })
    );
    // Backspace re-checks what remains; emptying the field checks nothing.
    assert_eq!(
        press(&mut state, KeyCode::Backspace),
        Some(UiAction::CheckOtpMailRecipient { nickname: "b".into() })
    );
    assert_eq!(press(&mut state, KeyCode::Backspace), None);
}

/// @requirement AC-155
#[test]
fn a_failed_check_renders_the_to_field_red_with_a_cross() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "stranger");
    state.otp_mail_set_check("stranger", RecipientCheck::NotPinned);

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut found_cross = false;
    let mut nickname_fg = None;
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            if buffer[(x, y)].symbol().contains('\u{274C}') {
                found_cross = true;
            }
            if buffer[(x, y)].symbol() == "s" && nickname_fg.is_none() && y > 0 {
                nickname_fg = Some(buffer[(x, y)].fg);
            }
        }
    }
    assert!(found_cross, "an invalid recipient renders a cross emoji");
    assert_eq!(
        nickname_fg,
        Some(ratatui::style::Color::Red),
        "and the field renders red"
    );
    let rows = rows_of(&state);
    assert!(
        rows.iter().any(|r| r.contains("no pinned user")),
        "the reason is named: {rows:?}"
    );
}

/// @requirement AC-155
#[test]
fn a_passing_check_renders_green_with_a_tick() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(5 * 1024 * 1024));

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut found_tick = false;
    let mut nickname_fg = None;
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            if buffer[(x, y)].symbol().contains('\u{2705}') {
                found_tick = true;
            }
            if buffer[(x, y)].symbol() == "b" && nickname_fg.is_none() && y > 0 {
                nickname_fg = Some(buffer[(x, y)].fg);
            }
        }
    }
    assert!(found_tick, "a valid recipient renders a tick emoji");
    assert_eq!(
        nickname_fg,
        Some(ratatui::style::Color::Green),
        "and the field renders green"
    );
}

/// @requirement AC-155
#[test]
fn a_stale_check_result_for_an_edited_nickname_is_ignored() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    // The user typed one more character before the "bob" check came back.
    press(&mut state, KeyCode::Char('x'));
    state.otp_mail_set_check("bob", ok_check(5 * 1024 * 1024));
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.check,
        None,
        "a result for an outdated nickname must not overwrite the newer edit's"
    );
    state.otp_mail_set_check("bobx", RecipientCheck::NotPinned);
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.check,
        Some(RecipientCheck::NotPinned)
    );
}

// ---------------------------------------------------------------------
// The device selector (AC-336)
// ---------------------------------------------------------------------

fn device_option(id: &str, last_seen: Option<u64>, has_key: bool) -> MailDeviceOption {
    MailDeviceOption {
        device_id: id.into(),
        last_seen_unix: last_seen,
        contact_name: format!("contact-{id}"),
        has_mail_key: has_key,
        enc_key_remaining: if has_key { 1024 } else { 0 },
    }
}

/// @requirement AC-336
#[test]
fn otp_mail_set_devices_defaults_to_the_most_recently_seen_device_with_a_mail_key() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_devices(
        "bob",
        vec![
            device_option("newer-no-key", Some(200), false),
            device_option("older-with-key", Some(100), true),
        ],
    );
    let compose = &state.otp_mail.as_ref().unwrap().compose;
    assert_eq!(
        compose.devices[compose.selected_device].device_id, "older-with-key",
        "a device with a mail key beats a more-recently-seen one with none"
    );
}

/// @requirement AC-336
#[test]
fn otp_mail_set_devices_falls_back_to_most_recently_seen_when_none_has_a_mail_key() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_devices(
        "bob",
        vec![
            device_option("older", Some(100), false),
            device_option("newer", Some(200), false),
        ],
    );
    let compose = &state.otp_mail.as_ref().unwrap().compose;
    assert_eq!(
        compose.devices[compose.selected_device].device_id, "newer",
        "with no key anywhere, falls back to most-recently-seen so NoMailKey still explains why"
    );
}

/// @requirement AC-336
#[test]
fn otp_mail_set_devices_is_a_noop_for_a_stale_nickname() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    press(&mut state, KeyCode::Char('x')); // now editing "bobx"
    // A sentinel standing in for whatever the view held before a late
    // "bob" result arrives - proves the setter's own guard, not merely
    // that typing already cleared the list.
    {
        let compose = &mut state.otp_mail.as_mut().unwrap().compose;
        compose.devices = vec![device_option("sentinel", Some(1), true)];
        compose.devices_for = Some("bobx".into());
    }
    state.otp_mail_set_devices("bob", vec![device_option("late", Some(2), true)]);
    let compose = &state.otp_mail.as_ref().unwrap().compose;
    assert_eq!(
        compose.devices,
        vec![device_option("sentinel", Some(1), true)],
        "a device list for an outdated nickname must not overwrite the newer edit's"
    );
    assert_eq!(compose.devices_for.as_deref(), Some("bobx"));
}

/// @requirement AC-336
#[test]
fn up_and_down_in_the_device_focus_move_selection_and_clamp_at_the_ends() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_devices(
        "bob",
        vec![
            device_option("a", Some(1), true),
            device_option("b", Some(2), true),
            device_option("c", Some(3), true),
        ],
    );
    {
        let compose = &mut state.otp_mail.as_mut().unwrap().compose;
        compose.focus = MailFocus::Device;
        compose.selected_device = 0;
    }

    assert_eq!(
        press(&mut state, KeyCode::Up),
        None,
        "already at the top - clamps without re-checking"
    );
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.selected_device, 0);

    assert_eq!(
        press(&mut state, KeyCode::Down),
        Some(UiAction::SelectOtpMailDevice {
            nickname: "bob".into(),
            device_id: "b".into()
        })
    );
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.selected_device, 1);

    press(&mut state, KeyCode::Down);
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.selected_device, 2);
    assert_eq!(
        press(&mut state, KeyCode::Down),
        None,
        "already at the bottom - clamps without wrapping or re-checking"
    );
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.selected_device, 2);
}

/// @requirement AC-336
#[test]
fn tab_skips_the_device_row_when_no_devices_are_known_yet() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "stranger");
    state.otp_mail_set_check("stranger", RecipientCheck::NotPinned);
    assert!(state.otp_mail.as_ref().unwrap().compose.devices.is_empty());
    press(&mut state, KeyCode::Tab);
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.focus,
        MailFocus::Subtext,
        "Tab goes straight from To to Subtext when nothing was found to select"
    );
}

/// @requirement AC-336
#[test]
fn tab_stops_at_the_device_row_once_devices_exist() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_devices("bob", vec![device_option("a", Some(1), true)]);
    press(&mut state, KeyCode::Tab);
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.focus,
        MailFocus::Device
    );
    press(&mut state, KeyCode::Tab);
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.focus,
        MailFocus::Subtext
    );
    // BackTab retraces the same stop.
    press(&mut state, KeyCode::BackTab);
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.focus,
        MailFocus::Device
    );
}

/// @requirement AC-336
#[test]
fn an_empty_device_list_renders_a_placeholder_not_a_panic() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "stranger");
    state.otp_mail_set_check("stranger", RecipientCheck::NotPinned);
    let rows = rows_of(&state);
    assert!(
        rows.iter().any(|r| r.contains("no pinned devices") || r.contains("type a recipient")),
        "an empty device list shows an explanatory placeholder, not a blank row: {rows:?}"
    );
}

/// @requirement AC-336
#[test]
fn the_device_rows_render_a_check_or_cross_per_has_mail_key() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_devices(
        "bob",
        vec![
            device_option("has-key", Some(1), true),
            device_option("no-key", Some(2), false),
        ],
    );
    let rows = rows_of(&state);
    let ticks = rows.iter().filter(|r| r.contains('\u{2705}')).count();
    let crosses = rows.iter().filter(|r| r.contains('\u{274C}')).count();
    assert!(ticks >= 1, "the device with a mail key shows a tick: {rows:?}");
    assert!(crosses >= 1, "the device without one shows a cross: {rows:?}");
}

// ---------------------------------------------------------------------
// The hard mail-key gate: no way to write or send without one (AC-297)
// ---------------------------------------------------------------------

/// The exact wording required: `no otp mail key available for <nickname> -
/// install one manually from /contacts or exchange one with the user if
/// he is online using /new-otp-mail-key (requires pinned contact)`.
/// @requirement AC-297
#[test]
fn no_mail_key_renders_a_centered_red_modal_with_the_exact_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", RecipientCheck::NoMailKey);

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
        .collect();
    let joined = rows.join(" ");
    assert!(
        joined.contains("no otp mail key available for bob"),
        "names the nickname: {rows:?}"
    );
    assert!(
        joined.contains("install one manually from"),
        "the /contacts instruction: {rows:?}"
    );
    assert!(joined.contains("/contacts"), "names /contacts: {rows:?}");
    assert!(
        joined.contains("/new-otp-mail-key"),
        "names the command: {rows:?}"
    );
    assert!(
        joined.contains("requires pinned contact"),
        "names the precondition: {rows:?}"
    );

    let mut found_red = false;
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            let cell = &buffer[(x, y)];
            if !cell.symbol().trim().is_empty() && cell.fg == ratatui::style::Color::Red {
                found_red = true;
            }
        }
    }
    assert!(found_red, "the message renders in red");
}

/// @requirement AC-297
#[test]
fn the_gate_absorbs_typing_tab_and_ctrl_s_while_blocked() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", RecipientCheck::NoMailKey);

    assert!(press(&mut state, KeyCode::Char('x')).is_none());
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.content,
        "",
        "typing must not reach the content field while blocked"
    );
    assert!(press(&mut state, KeyCode::Tab).is_none());
    assert_eq!(
        state.otp_mail.as_ref().unwrap().compose.focus,
        aloo::client::tui::otp_mail::MailFocus::To,
        "Tab must not move focus while blocked"
    );
    assert!(ctrl(&mut state, KeyCode::Char('s')).is_none());
    assert!(
        !state.otp_mail.as_ref().unwrap().compose.send_confirm,
        "Ctrl+S must not open the send confirm while blocked"
    );
}

/// @requirement AC-297
#[test]
fn esc_on_the_gate_closes_both_the_modal_and_the_whole_compose_view() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", RecipientCheck::NoMailKey);

    assert!(press(&mut state, KeyCode::Esc).is_none());
    assert!(
        state.otp_mail.is_none(),
        "Esc must close the whole /mail view in one step, not just the modal"
    );
}

/// @requirement AC-297
#[test]
fn a_recipient_with_a_mail_key_is_never_blocked() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(5 * 1024 * 1024));

    let rows = rows_of(&state);
    assert!(
        !rows.iter().any(|r| r.contains("no otp mail key available")),
        "a valid recipient never shows the gate: {rows:?}"
    );
    press(&mut state, KeyCode::Tab); // To -> Subtext
    press(&mut state, KeyCode::Tab); // Subtext -> Content
    press(&mut state, KeyCode::Char('y'));
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.content, "y", "typing works normally");
}

// ---------------------------------------------------------------------
// The realtime key budget (AC-156)
// ---------------------------------------------------------------------

/// @requirement AC-156
#[test]
fn the_remaining_key_appears_top_right_once_valid() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    let rows = rows_of(&state);
    assert!(
        !rows.iter().any(|r| r.contains("Key left:")),
        "no indicator before the nickname validates: {rows:?}"
    );
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(5 * 1024 * 1024));
    let rows = rows_of(&state);
    let header = &rows[0];
    assert!(
        header.contains("Key left:") && header.contains("MB"),
        "the remaining key in MB sits on the top row: {header:?}"
    );
    assert!(
        header.trim_end().ends_with("MB"),
        "and at its right edge: {header:?}"
    );
}

/// @requirement AC-156
#[test]
fn the_remaining_key_shrinks_as_the_mail_grows() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(1024 * 1024));
    let left_empty = state
        .otp_mail
        .as_ref()
        .unwrap()
        .compose
        .key_left_after_mail()
        .unwrap();
    assert_eq!(left_empty, 1024 * 1024 - MAIL_OVERHEAD_ESTIMATE);

    fn left(state: &UiState) -> u64 {
        state
            .otp_mail
            .as_ref()
            .unwrap()
            .compose
            .key_left_after_mail()
            .unwrap()
    }

    // Typing content eats budget character by character...
    press(&mut state, KeyCode::Tab);
    press(&mut state, KeyCode::Tab);
    type_str(&mut state, "hello");
    assert_eq!(left(&state), left_empty - 5);

    // ...an attached recording eats its PCM size...
    assert!(state.otp_mail_add_voice(500, vec![0u8; 1000]));
    assert_eq!(left(&state), left_empty - 5 - 1000);

    // ...and removing it gives the budget straight back.
    state
        .otp_mail
        .as_mut()
        .unwrap()
        .compose
        .attachments
        .clear();
    assert_eq!(left(&state), left_empty - 5);
}

// ---------------------------------------------------------------------
// Attachments (AC-157, AC-158)
// ---------------------------------------------------------------------

/// @requirement AC-157
#[test]
fn space_in_the_attachments_pane_drives_a_mail_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    // Space inside a text field is just a typed character, never a
    // recording.
    press(&mut state, KeyCode::Tab); // Subtext
    assert_eq!(press(&mut state, KeyCode::Char(' ')), None);
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.subtext, " ");
    assert!(!state.recording);

    press(&mut state, KeyCode::Tab); // Content
    press(&mut state, KeyCode::Tab); // Attachments
    assert_eq!(
        press(&mut state, KeyCode::Char(' ')),
        Some(UiAction::VoiceRecordStart(VoiceTarget::MailAttachment)),
        "holding Space in the attachments pane records for the mail"
    );
    assert!(state.recording);
    // Releasing stops it, exactly like the channel/DM recording flow.
    assert_eq!(
        state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Release),
        Some(UiAction::VoiceRecordStop)
    );
    assert!(!state.recording);
}

/// @requirement AC-157
#[test]
fn a_voice_recording_larger_than_the_remaining_key_is_cancelled() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(MAIL_OVERHEAD_ESTIMATE + 100));
    assert!(
        !state.otp_mail_add_voice(9_000, vec![0u8; 200]),
        "a recording that outgrows the key is refused"
    );
    assert!(state.otp_mail.as_ref().unwrap().compose.attachments.is_empty());
    assert!(
        state.otp_mail_add_voice(500, vec![0u8; 50]),
        "one that fits attaches"
    );
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.attachments.len(), 1);
}

/// @requirement AC-157
#[test]
fn attaching_a_file_larger_than_the_remaining_key_is_cancelled() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(MAIL_OVERHEAD_ESTIMATE + 100));

    let dir = make_file(300, "big.bin");
    let mail = state.otp_mail.as_mut().unwrap();
    mail.compose.browser = Some(FileBrowserState::open(dir.clone()).unwrap());
    // Select big.bin in the browser and confirm it.
    while state
        .otp_mail
        .as_ref()
        .unwrap()
        .compose
        .browser
        .as_ref()
        .unwrap()
        .selected_entry()
        .map(|e| e.name != "big.bin")
        .unwrap_or(true)
    {
        press(&mut state, KeyCode::Down);
    }
    assert!(press(&mut state, KeyCode::Enter).is_none());
    let compose = &state.otp_mail.as_ref().unwrap().compose;
    assert!(compose.attachments.is_empty(), "the operation was cancelled");
    assert!(compose.browser.is_none(), "the browser closed with it");
    let (notice, ok) = state.status_notice.clone().expect("a notice says why");
    assert!(notice.contains("larger than the remaining key"), "{notice:?}");
    assert!(!ok);
    let _ = std::fs::remove_dir_all(dir);
}

/// @requirement AC-157
#[test]
fn a_fitting_file_attaches() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(MAIL_OVERHEAD_ESTIMATE + 100));

    let dir = make_file(10, "small.bin");
    state.otp_mail.as_mut().unwrap().compose.browser =
        Some(FileBrowserState::open(dir.clone()).unwrap());
    while state
        .otp_mail
        .as_ref()
        .unwrap()
        .compose
        .browser
        .as_ref()
        .unwrap()
        .selected_entry()
        .map(|e| e.name != "small.bin")
        .unwrap_or(true)
    {
        press(&mut state, KeyCode::Down);
    }
    press(&mut state, KeyCode::Enter);
    let compose = &state.otp_mail.as_ref().unwrap().compose;
    assert_eq!(compose.attachments.len(), 1);
    assert!(
        matches!(&compose.attachments[0], MailAttachment::File { filename, size: 10, .. } if filename == "small.bin")
    );
    assert!(compose.browser.is_none());
    let _ = std::fs::remove_dir_all(dir);
}

/// @requirement AC-158
#[test]
fn d_removes_the_selected_attachment_only_after_confirming() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    assert!(state.otp_mail_add_voice(500, vec![0u8; 50]));
    press(&mut state, KeyCode::Tab); // Subtext
    press(&mut state, KeyCode::Tab); // Content
    press(&mut state, KeyCode::Tab); // Attachments

    press(&mut state, KeyCode::Char('d'));
    let rows = rows_of(&state);
    assert!(
        rows.iter().any(|r| r.contains("Remove attachment")),
        "a confirm popup opens: {rows:?}"
    );
    // Enter on the default (Cancel) keeps it.
    press(&mut state, KeyCode::Enter);
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.attachments.len(), 1);

    // Confirming Remove deletes it.
    press(&mut state, KeyCode::Char('d'));
    press(&mut state, KeyCode::Left);
    press(&mut state, KeyCode::Enter);
    assert!(state.otp_mail.as_ref().unwrap().compose.attachments.is_empty());
}

// ---------------------------------------------------------------------
// Sending (AC-159)
// ---------------------------------------------------------------------

/// @requirement AC-159
#[test]
fn ctrl_s_opens_the_send_confirm_only_when_valid() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    // Invalid (no recipient at all): refused with a notice.
    assert!(ctrl(&mut state, KeyCode::Char('s')).is_none());
    assert!(!state.otp_mail.as_ref().unwrap().compose.send_confirm);
    assert!(state.status_notice.is_some());

    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(5 * 1024 * 1024));
    assert!(ctrl(&mut state, KeyCode::Char('s')).is_none());
    assert!(state.otp_mail.as_ref().unwrap().compose.send_confirm);
    let rows = rows_of(&state);
    assert!(
        rows.iter().any(|r| r.contains("Send this mail to bob")),
        "the confirm names the recipient: {rows:?}"
    );
}

/// @requirement AC-159
#[test]
fn send_emits_only_after_confirming() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    state.otp_mail_set_check("bob", ok_check(5 * 1024 * 1024));

    ctrl(&mut state, KeyCode::Char('s'));
    // Enter on the default (Cancel) sends nothing.
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(!state.otp_mail.as_ref().unwrap().compose.send_confirm);
    assert!(state.otp_mail.is_some(), "still composing");

    ctrl(&mut state, KeyCode::Char('s'));
    press(&mut state, KeyCode::Tab); // move to Send
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::SendOtpMail),
        "only an explicit confirm produces the send action"
    );
}

// ---------------------------------------------------------------------
// The mailbox and the reader (AC-162, AC-163)
// ---------------------------------------------------------------------

/// @requirement AC-162
#[test]
fn slash_mailbox_opens_the_mailbox() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mailbox(&mut state);
    state.otp_mail_set_mailbox_rows(vec![MailboxRow::Sent(sent_ref(SentMailStatus::Delivered))]);
    assert!(state.otp_mailbox_open());
    // Esc closes the popup - and, since the compose form underneath was
    // opened only as the popup's backdrop and never touched, the whole
    // view with it.
    assert!(press(&mut state, KeyCode::Esc).is_none());
    assert!(state.otp_mail.is_none());
}

/// @requirement AC-162
#[test]
fn esc_from_the_mailbox_keeps_a_draft_in_progress() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    type_str(&mut state, "bob");
    // The mailbox can only be reached by command, so a draft in progress
    // means the popup was opened by the session refreshing rows - simulate
    // that directly.
    state.otp_mail_set_mailbox_rows(vec![MailboxRow::Sent(sent_ref(SentMailStatus::Delivered))]);
    assert!(state.otp_mailbox_open());
    press(&mut state, KeyCode::Esc);
    assert!(!state.otp_mailbox_open());
    assert!(state.otp_mail.is_some(), "the typed draft survives");
    assert_eq!(state.otp_mail.as_ref().unwrap().compose.to, "bob");
}

/// @requirement AC-162
#[test]
fn the_mailbox_lists_sent_status_and_received_rows() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mailbox(&mut state);
    state.otp_mail_set_mailbox_rows(vec![
        MailboxRow::Received(received_ref()),
        MailboxRow::Sent(sent_ref(SentMailStatus::Delivered)),
        MailboxRow::Sent(SentMailRef {
            mail_id: "cc".repeat(16),
            status: SentMailStatus::AwaitingServerAck,
            ..sent_ref(SentMailStatus::AwaitingServerAck)
        }),
    ]);
    let rows = rows_of(&state);
    assert!(rows.iter().any(|r| r.contains("from alice")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("to bob") && r.contains("delivered")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("awaiting server")), "{rows:?}");
    // Status, never content: nothing of a mail's subtext/body is here to
    // show - the row type itself carries no content fields.
}

/// @requirement AC-162
#[test]
fn enter_on_a_received_row_asks_to_read_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mailbox(&mut state);
    let received = received_ref();
    state.otp_mail_set_mailbox_rows(vec![
        MailboxRow::Sent(sent_ref(SentMailStatus::StoredOnServer)),
        MailboxRow::Received(received.clone()),
    ]);
    // Enter on a *sent* row does nothing - there is no content to read.
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    press(&mut state, KeyCode::Down);
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::ReadOtpMail {
            mail_id: received.mail_id
        })
    );
}

/// @requirement AC-163
#[test]
fn d_on_a_mailbox_row_requires_confirm_before_delete() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mailbox(&mut state);
    let received = received_ref();
    state.otp_mail_set_mailbox_rows(vec![MailboxRow::Received(received.clone())]);

    press(&mut state, KeyCode::Char('d'));
    let rows = rows_of(&state);
    assert!(
        rows.iter().any(|r| r.contains("ciphertext and pad are both"))
            && rows.iter().any(|r| r.contains("cannot be read again")),
        "removing a received mail spells out what dies with it: {rows:?}"
    );
    // The default answer keeps it.
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    // Confirming produces the delete action.
    press(&mut state, KeyCode::Char('d'));
    press(&mut state, KeyCode::Left);
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::DeleteOtpMail {
            mail_id: received.mail_id
        })
    );
}

/// @requirement AC-162
#[test]
fn the_reader_plays_voice_parts_and_saves_attachments() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mailbox(&mut state);
    state.otp_mail_set_mailbox_rows(vec![MailboxRow::Received(received_ref())]);
    let payload = OtpMailPayload {
        from: "alice".into(),
        to: "me".into(),
        sent_at_utc: 1_700_000_100,
        subtext: "the plan".into(),
        content: "read me".into(),
        voices: vec![OtpMailVoice {
            duration_ms: 700,
            pcm: vec![3u8; 64],
        }],
        attachments: vec![OtpMailFile {
            filename: "notes.txt".into(),
            bytes: b"attached".to_vec(),
        }],
    };
    state.otp_mail_open_reader("bb".repeat(16), payload);
    let rows = rows_of(&state);
    assert!(rows.iter().any(|r| r.contains("Mail from alice")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("the plan")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("read me")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("notes.txt")), "{rows:?}");

    // Enter on the first part (the voice) replays it through the existing
    // mixer action, and Escape while it plays stops the playback rather
    // than closing anything.
    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::ReplayVoice { duration_ms: 700, pcm, .. }) => assert_eq!(pcm, vec![3u8; 64]),
        other => panic!("expected ReplayVoice, got {other:?}"),
    }
    assert!(state.replaying);
    assert_eq!(press(&mut state, KeyCode::Esc), Some(UiAction::StopPlayback));
    assert!(!state.replaying);
    assert!(
        state.otp_mail.as_ref().unwrap().reader.is_some(),
        "stopping playback leaves the reader open"
    );
    // Enter on the attachment asks to save it.
    press(&mut state, KeyCode::Down);
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::SaveOtpMailAttachment { index: 0 })
    );
    // Esc closes the reader (dropping the in-memory plaintext), then the
    // mailbox - taking the untouched backdrop compose form with it.
    press(&mut state, KeyCode::Esc);
    assert!(state.otp_mail.as_ref().unwrap().reader.is_none());
    press(&mut state, KeyCode::Esc);
    assert!(state.otp_mail.is_none());
}

/// @requirement AC-157
#[test]
fn enter_plays_a_voice_attachment_and_esc_stops_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    assert!(state.otp_mail_add_voice(700, vec![3u8; 64]));
    press(&mut state, KeyCode::Tab); // Subtext
    press(&mut state, KeyCode::Tab); // Content
    press(&mut state, KeyCode::Tab); // Attachments

    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::ReplayVoice { duration_ms: 700, pcm, .. }) => assert_eq!(pcm, vec![3u8; 64]),
        other => panic!("expected ReplayVoice, got {other:?}"),
    }
    assert!(state.replaying);
    // Escape stops the playback and nothing else - the compose view (and
    // everything typed into it) stays.
    assert_eq!(press(&mut state, KeyCode::Esc), Some(UiAction::StopPlayback));
    assert!(!state.replaying);
    assert!(state.otp_mail.is_some(), "the compose view survives the stop");
    // Only the next Escape discards the view.
    press(&mut state, KeyCode::Esc);
    assert!(state.otp_mail.is_none());
}

/// @requirement AC-157
#[test]
fn enter_on_a_file_attachment_plays_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_mail(&mut state);
    state
        .otp_mail
        .as_mut()
        .unwrap()
        .compose
        .attachments
        .push(MailAttachment::File {
            filename: "notes.txt".into(),
            path: std::path::PathBuf::from("/nonexistent/notes.txt"),
            size: 10,
        });
    press(&mut state, KeyCode::Tab); // Subtext
    press(&mut state, KeyCode::Tab); // Content
    press(&mut state, KeyCode::Tab); // Attachments
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(!state.replaying);
    assert!(
        state.otp_mail.as_ref().unwrap().compose.browser.is_none(),
        "Enter never opens the browser - that's 'a'"
    );
}
