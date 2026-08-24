#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::p2p_proto::ReceiptStage;
use aloo::proto::UserId;
use aloo::client::tui::ui::{
    DeliveryProof,
    CallMemberState, CallTarget, DELIVERED_LABEL, DELIVERY_ARROW, DeliveryStatus, Focus,
    LISTENED_LABEL, SAVED_LABEL,
    END_CALL_CONFIRM_TITLE, ENCRYPTION_LABEL, HELP_POPUP_TITLE, HOST_LEFT_NOTICE, IdentityCase,
    KEY_FILE_LABEL,
    KEY_LABEL, KEY_OFFSET_LABEL, KEY_PER_RECIPIENT, KEY_SEQ_LABEL, MessageBody, Mode,
    NO_CRYPTO_INFO, NO_DELIVERY_INFO, NO_ONE_INVITED_NOTICE, PendingFileOffer,
    OTP_CALL_REFUSAL, PendingCallInvite, RECEIVED_AT_LABEL, RECORD_HOLD_TIMEOUT, SENT_AT_LABEL,
    UNDELIVERED_LABEL, UiAction, UiState, render,
};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------
// Offline users (SPEC.md: private-message history keeps them, grayed out)
// ---------------------------------------------------------------------

/// @requirement AC-052
#[test]
fn user_offline_with_dm_history_keeps_them_in_every_channel_they_were_in() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    assert!(!state.private_rooms[&UserId(2)].log.is_empty());

    state.on_user_offline(UserId(2));

    assert!(state.offline.contains(&UserId(2)));
    assert_eq!(
        state.channels[0].members.len(),
        1,
        "bob should still be listed - there's DM history with him"
    );
    assert_eq!(state.channels[0].members[0].id, UserId(2));
}

/// @requirement AC-052
#[test]
fn user_offline_without_dm_history_is_removed_from_channels_like_an_explicit_leave() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert!(
        !state.private_rooms.contains_key(&UserId(2)),
        "no DM history with bob yet"
    );

    state.on_user_offline(UserId(2));

    assert!(
        state.offline.contains(&UserId(2)),
        "still tracked as offline even though removed from the sidebar"
    );
    assert!(state.channels[0].members.is_empty());
}

/// A disconnect logs a yellow, timestamped "disconnected" notice into every
/// channel the user was a member of, and into an already-open DM room -
/// docs/SPEC.md Functionality #7. Logged before membership is touched, so
/// this holds even for the "no DM history" case where the peer is then
/// dropped from the channel's member list.
///
/// @requirement AC-151
#[test]
fn user_offline_logs_a_disconnected_notice_in_every_shared_channel_and_an_open_dm() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens (and so creates) an empty DM room with bob

    state.on_user_offline(UserId(2));

    match &state.channels[0].log.last().expect("expected a notice").body {
        MessageBody::Presence(text) => assert!(
            text.ends_with("bob disconnected"),
            "expected a disconnected notice in the channel, got {text:?}"
        ),
        other => panic!("expected MessageBody::Presence, got {other:?}"),
    }
    match &state.private_rooms[&UserId(2)]
        .log
        .last()
        .expect("expected a notice")
        .body
    {
        MessageBody::Presence(text) => assert!(
            text.ends_with("bob disconnected"),
            "expected a disconnected notice in the DM room, got {text:?}"
        ),
        other => panic!("expected MessageBody::Presence, got {other:?}"),
    }
}

/// @requirement TB-104
#[test]
fn user_offline_with_an_open_but_empty_dm_room_is_still_removed_from_channels() {
    // Opening a DM (Enter on a sidebar member) creates an empty `PrivateRoom`
    // struct immediately, but SPEC.md's envelope/retention rule keys off
    // actual message history, not merely the room having been opened.
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens an empty DM with bob
    assert!(state.private_rooms[&UserId(2)].log.is_empty());

    state.on_user_offline(UserId(2));

    assert!(state.channels[0].members.is_empty());
}

/// @requirement AC-055, TB-020
#[test]
fn user_offline_is_permanent_for_the_session_since_a_user_id_is_never_reused() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_user_offline(UserId(2));
    assert!(state.offline.contains(&UserId(2)));
    // a later UserJoined for the same id (shouldn't happen per protocol, but
    // nothing in on_user_joined should clear the offline flag if it did)
    state.on_user_joined("general", user(2, "bob"));
    assert!(state.offline.contains(&UserId(2)));
}

// ---------------------------------------------------------------------
// Focus / navigation
// ---------------------------------------------------------------------

/// @requirement AC-062
#[test]
fn tab_cycles_focus_sidebar_messages_input() {
    let mut state = UiState::new("me".into());
    assert_eq!(state.focus, Focus::Input);
    press(&mut state, KeyCode::Tab);
    assert_eq!(state.focus, Focus::Sidebar);
    press(&mut state, KeyCode::Tab);
    assert_eq!(state.focus, Focus::Messages);
    press(&mut state, KeyCode::Tab);
    assert_eq!(state.focus, Focus::Input);
}

/// @requirement AC-063
#[test]
fn sidebar_up_down_wraps_selection() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Up);
    // Wraps to the last row, which is always our own synthetic "(me)" row
    // appended after every real member (`channel::render_sidebar`) - here,
    // index 2 (bob=0, carol=1, own row=2).
    assert_eq!(state.sidebar_selected, 2);
    press(&mut state, KeyCode::Down);
    assert_eq!(state.sidebar_selected, 0);
}

// ---------------------------------------------------------------------
// Ctrl+H help overlay
// ---------------------------------------------------------------------

/// @requirement AC-056
#[test]
fn ctrl_h_opens_and_closes_the_help_overlay() {
    let mut state = UiState::new("me".into());
    assert!(!state.help_open);
    let action = ctrl(&mut state, KeyCode::Char('h'));
    assert_eq!(action, None);
    assert!(state.help_open);
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(!state.help_open);
}

/// @requirement AC-056
#[test]
fn ctrl_h_uppercase_also_toggles_help() {
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('H'));
    assert!(state.help_open);
}

/// @requirement AC-056
#[test]
fn escape_also_closes_the_help_overlay() {
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(state.help_open);
    assert_eq!(press(&mut state, KeyCode::Esc), None);
    assert!(!state.help_open);
    // The paired Release a kitty-protocol terminal delivers afterwards is
    // inert - the DM-closing Esc branch is Press-gated, so nothing leaks.
    assert_eq!(
        state.handle_key(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release),
        None
    );
    assert!(!state.help_open);
}

/// @requirement AC-141
#[test]
fn the_status_notice_clears_after_thirty_seconds() {
    use std::time::{Duration, Instant};
    let mut state = UiState::new("me".into());
    state.push_status_notice("OTP session started".into(), true);
    let now = Instant::now();
    state.tick_status_notice(now);
    assert!(state.status_notice.is_some(), "still fresh");
    state.tick_status_notice(now + Duration::from_secs(29));
    assert!(state.status_notice.is_some(), "just under the timeout");
    state.tick_status_notice(now + aloo::client::tui::ui::STATUS_NOTICE_TIMEOUT);
    assert!(state.status_notice.is_none(), "cleared at the timeout");
    // A fresh notice restarts the clock rather than inheriting the old one.
    state.push_status_notice("another".into(), false);
    state.tick_status_notice(Instant::now());
    assert!(state.status_notice.is_some());
}

/// @requirement TB-107
#[test]
fn ctrl_h_release_event_does_not_re_toggle_help() {
    // On a Kitty-keyboard-protocol terminal the Release for this same
    // keystroke also reaches handle_key - it must be absorbed, not treated
    // as a second toggle that immediately cancels the Press.
    let mut state = UiState::new("me".into());
    state.handle_key(
        KeyCode::Char('h'),
        KeyModifiers::CONTROL,
        KeyEventKind::Press,
    );
    assert!(state.help_open);
    let action = state.handle_key(
        KeyCode::Char('h'),
        KeyModifiers::CONTROL,
        KeyEventKind::Release,
    );
    assert_eq!(action, None);
    assert!(
        state.help_open,
        "the paired Release must not flip help back off"
    );
}

/// @requirement TB-106
#[test]
fn help_absorbs_other_keys_while_open() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(state.help_open);

    let focus_before = state.focus;
    let action = press(&mut state, KeyCode::Tab);
    assert_eq!(
        action, None,
        "keys other than Ctrl+H must be swallowed while help is open"
    );
    assert_eq!(
        state.focus, focus_before,
        "focus must not change while help absorbs input"
    );
    assert!(state.help_open);

    type_str(&mut state, "hello");
    assert!(
        state.input.is_empty(),
        "typing must not reach the compose bar while help is open"
    );
}

/// @requirement TB-106
#[test]
fn esc_while_help_open_only_closes_help_not_the_private_room_underneath() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // open a DM with bob
    assert_eq!(state.active_private_room, Some(UserId(2)));

    ctrl(&mut state, KeyCode::Char('h'));
    assert!(state.help_open);

    // Esc closes help - and only help: it must never fall through to the
    // normal "Esc closes the private room" handling underneath, neither on
    // the Press that closed it nor on the paired Release a kitty-protocol
    // terminal delivers afterwards.
    press(&mut state, KeyCode::Esc);
    assert!(!state.help_open, "Esc closes help");
    state.handle_key(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release);
    assert_eq!(
        state.active_private_room,
        Some(UserId(2)),
        "the private room underneath must be untouched"
    );
}

/// @requirement AC-056
#[test]
fn ctrl_h_works_regardless_of_current_view_or_mode() {
    // from the join-channel popup
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('j'));
    assert_eq!(state.mode, Mode::JoinPrivatePopup);
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(
        state.help_open,
        "Ctrl+H should open help even with the join popup active"
    );

    // from an open private room
    ctrl(&mut state, KeyCode::Char('h')); // close it again
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    assert!(state.active_private_room.is_some());
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(
        state.help_open,
        "Ctrl+H should open help from inside a private room"
    );
}

/// Renders `state` and returns whatever immediately follows "Ctrl+H: Help"
/// on the header row (trimmed of the two separating spaces).
fn after_help_hint(state: &UiState) -> String {
    let rows = rendered_rows(state);
    let header = rows[HEADER_TEXT_ROW].clone();
    let idx = header
        .find("Ctrl+H: Help")
        .expect("expected the help hint on the header row");
    header[idx + "Ctrl+H: Help".len()..].trim_end().to_string()
}

/// @requirement AC-058
#[test]
fn header_shows_only_the_help_hint_after_conn_and_cpu() {
    let state = joined_general_with(vec![]);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        header.contains("Ctrl+H: Help"),
        "expected the help hint: {header:?}"
    );
    assert!(
        after_help_hint(&state).is_empty(),
        "nothing should follow the help hint: {:?}",
        after_help_hint(&state)
    );
}

// ---------------------------------------------------------------------
// Sending a message: shared guard behavior
// ---------------------------------------------------------------------

/// @requirement AC-026
#[test]
fn enter_with_empty_input_does_not_send() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
}

// ---------------------------------------------------------------------
// Push-to-talk voice
// ---------------------------------------------------------------------

/// @requirement AC-033
#[test]
fn space_types_a_literal_space_while_composing_a_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "hello all");
    assert_eq!(state.input, "hello all");
}

/// @requirement AC-034
#[test]
fn space_press_without_a_joined_channel_or_active_dm_does_not_start_recording_and_shows_an_error() {
    let mut state = UiState::new("me".into()); // no channels joined, no active DM
    state.focus = Focus::Messages;
    let action = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert_eq!(
        action, None,
        "there's nowhere to address a stream to, so no recording should start"
    );
    assert!(!state.recording);
    assert_eq!(
        state.audio_error.as_deref(),
        Some("not joined to a channel yet")
    );
}

/// @requirement AC-090
#[test]
fn global_record_start_without_a_joined_channel_or_active_dm_does_nothing() {
    let mut state = UiState::new("me".into()); // no channels joined, no active DM
    let action = state.global_record_start();
    assert_eq!(
        action, None,
        "there's nowhere to address a stream to, so no recording should start"
    );
    assert!(!state.recording);
    assert_eq!(
        state.audio_error.as_deref(),
        Some("not joined to a channel yet")
    );
}

/// @requirement AC-091
#[test]
fn global_record_start_is_a_no_op_while_already_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert!(state.global_record_start().is_some());
    assert!(state.recording);
    assert_eq!(
        state.global_record_start(),
        None,
        "a second press must not start a second stream"
    );
}

/// @requirement AC-091
#[test]
fn global_record_stop_does_nothing_to_a_space_started_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.recording);

    assert_eq!(
        state.global_record_stop(),
        None,
        "the global shortcut must only ever stop a recording it itself started"
    );
    assert!(state.recording, "a Space-started recording must keep going");
}

/// @requirement AC-091
#[test]
fn space_release_does_nothing_to_a_global_started_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    assert!(state.global_record_start().is_some());
    assert!(state.recording);

    let action = state.handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert_eq!(
        action, None,
        "Space letting go must not stop a recording it never started"
    );
    assert!(
        state.recording,
        "a globally-started recording must keep going"
    );
}

/// @requirement AC-092
#[test]
fn tick_recording_timeout_never_touches_a_global_started_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert!(state.global_record_start().is_some());
    assert!(state.recording);

    // There's no repeat-keypress heartbeat for a held OS-level hotkey, so
    // `recording_last_seen` is never refreshed for a Global recording - if
    // the idle-silence guess applied here it would auto-stop this almost
    // immediately. It must not: only a real `Released` event
    // (`global_record_stop`) may end it.
    let far_future = Instant::now() + RECORD_HOLD_TIMEOUT * 100;
    assert_eq!(state.tick_recording_timeout(far_future), None);
    assert!(
        state.recording,
        "a global recording must never be auto-stopped by the idle-silence guess"
    );
}

/// @requirement TB-043
#[test]
fn recording_failed_clears_the_misleading_recording_indicator_and_shows_why() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.recording);

    state.recording_failed("no input device available".into());
    assert!(
        !state.recording,
        "a failed start must not leave the UI claiming to record"
    );
    assert_eq!(
        state.audio_error.as_deref(),
        Some("no input device available")
    );
}

/// @requirement TB-043
#[test]
fn starting_a_new_recording_clears_a_previous_audio_error() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.audio_error = Some("stale error from last attempt".into());

    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert_eq!(state.audio_error, None);
}

/// @requirement TB-044
#[test]
fn playback_failed_shows_the_reason_without_touching_recording_state() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.recording);

    state.playback_failed("no output device available".into());
    assert_eq!(
        state.audio_error.as_deref(),
        Some("no output device available")
    );
    assert!(
        state.recording,
        "a playback failure is unrelated to an in-progress recording"
    );
}

// ---------------------------------------------------------------------
// Terminal-agnostic push-to-talk: idle-timeout auto-stop
//
// Most terminals never send KeyEventKind::Release for a physically held
// key - only ones supporting the Kitty keyboard protocol do. What every
// terminal *does* do is forward the OS's keyboard auto-repeat as a stream
// of Press events roughly every 30-50ms while a key stays down. These
// tests simulate that: repeated Press events with small gaps keep
// recording alive, and only a gap as long as RECORD_HOLD_TIMEOUT with no
// further Space event is treated as "released".
// ---------------------------------------------------------------------

/// @requirement TB-041
#[test]
fn repeated_space_presses_do_not_auto_stop_before_the_timeout() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.recording);

    // still well inside the timeout window - simulating OS key-repeat
    let soon = Instant::now();
    assert_eq!(state.tick_recording_timeout(soon), None);
    assert!(
        state.recording,
        "a held key must not be treated as released early"
    );
}

/// @requirement TB-041
#[test]
fn idle_gap_past_the_timeout_auto_stops_and_sends() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.recording);

    let released_by_now = Instant::now() + RECORD_HOLD_TIMEOUT + Duration::from_millis(1);
    let action = state.tick_recording_timeout(released_by_now);
    assert!(
        !state.recording,
        "idle past the timeout must be treated as released"
    );
    assert_eq!(action, Some(UiAction::VoiceRecordStop));
}

/// @requirement TB-041
#[test]
fn a_fresh_press_resets_the_idle_clock() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);

    // simulate several repeat events spaced well under the timeout, like
    // real OS key-repeat while the key is actually held down
    for _ in 0..5 {
        state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
        assert_eq!(state.tick_recording_timeout(Instant::now()), None);
        assert!(state.recording);
    }
}

/// @requirement TB-042
#[test]
fn tick_recording_timeout_is_a_noop_when_not_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let far_future = Instant::now() + RECORD_HOLD_TIMEOUT * 10;
    assert_eq!(state.tick_recording_timeout(far_future), None);
}

/// @requirement TB-041
#[test]
fn keyboard_release_reporting_disables_the_idle_timeout_entirely() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_keyboard_release_reporting(true);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert!(state.recording);

    // No amount of silence should stop it - only a genuine Release may.
    let far_future = Instant::now() + RECORD_HOLD_TIMEOUT * 100;
    assert_eq!(state.tick_recording_timeout(far_future), None);
    assert!(
        state.recording,
        "must keep recording through silence when release reporting is trustworthy"
    );

    let action = state.handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert!(!state.recording);
    assert!(matches!(action, Some(UiAction::VoiceRecordStop)));
}

/// @requirement TB-041
#[test]
fn explicit_release_event_still_stops_immediately_without_waiting_for_the_timeout() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    let action = state.handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert!(!state.recording);
    assert!(matches!(action, Some(UiAction::VoiceRecordStop)));
    // and the now-defused idle timer must not fire a second stop later
    assert_eq!(
        state.tick_recording_timeout(Instant::now() + RECORD_HOLD_TIMEOUT * 10),
        None
    );
}

/// @requirement TB-042
#[test]
fn space_release_without_prior_press_does_nothing() {
    let mut state = joined_general_with(vec![]);
    state.focus = Focus::Messages;
    let action = state.handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert_eq!(action, None);
}

// ---------------------------------------------------------------------
// Message log scrolling
//
// SPEC.md: "both the channel view and the private-message room" - the
// selection/scrolling logic under test (`handle_messages_key`,
// `current_log`, `render_messages`) is defined here in `crate::client::tui::ui`,
// not in either view's own module. A channel is used only as the cheapest
// fixture for getting entries into a log.
// ---------------------------------------------------------------------

/// @requirement AC-059
#[test]
fn message_selection_defaults_to_the_newest_entry() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 5);
    assert_eq!(
        state.message_selected, 4,
        "should be following the newest message by default"
    );
}

/// @requirement AC-060
#[test]
fn new_messages_auto_follow_when_already_viewing_the_bottom() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 3);
    assert_eq!(state.message_selected, 2);
    push_n_channel_texts(&mut state, 1);
    assert_eq!(
        state.message_selected, 3,
        "a 4th message should pull the selection along with it"
    );
}

/// @requirement AC-060
#[test]
fn scrolled_up_history_is_not_yanked_down_by_a_new_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 3);
    state.focus = Focus::Messages;
    press(&mut state, KeyCode::Home); // scroll up to the oldest message
    assert_eq!(state.message_selected, 0);

    push_n_channel_texts(&mut state, 1);
    assert_eq!(
        state.message_selected, 0,
        "a new message must not jerk a scrolled-up view back to the bottom"
    );
}

// ---------------------------------------------------------------------
// Opening a link in the focused message (AC-285, AC-286)
// ---------------------------------------------------------------------

/// @requirement AC-285
#[test]
fn a_message_with_a_link_underlines_it_in_blue() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("see https://example.com/x for details".into()),
    );

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (lx, ly) = find_text_start(&buffer, "https://example.com/x");
    assert_eq!(buffer[(lx, ly)].fg, ratatui::style::Color::Blue);
    assert!(buffer[(lx, ly)].modifier.contains(ratatui::style::Modifier::UNDERLINED));

    let (sx, sy) = find_text_start(&buffer, "see ");
    assert_ne!(buffer[(sx, sy)].fg, ratatui::style::Color::Blue, "plain text stays unstyled");
    assert!(!buffer[(sx, sy)].modifier.contains(ratatui::style::Modifier::UNDERLINED));
}

/// @requirement AC-285
#[test]
fn a_message_with_no_link_renders_as_plain_text() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hello there".into()),
    );

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "hello there");
    assert!(!buffer[(x, y)].modifier.contains(ratatui::style::Modifier::UNDERLINED));
}

/// @requirement AC-286
#[test]
fn ctrl_o_opens_the_only_link_in_the_focused_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("see https://example.com/x for details".into()),
    );
    assert_eq!(state.message_selected, 0);

    let action = ctrl(&mut state, KeyCode::Char('o'));
    assert_eq!(action, Some(UiAction::OpenUrl("https://example.com/x".to_string())));
}

/// @requirement AC-286
#[test]
fn ctrl_o_cycles_through_a_messages_several_links() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("first https://a.example second https://b.example".into()),
    );

    assert_eq!(
        ctrl(&mut state, KeyCode::Char('o')),
        Some(UiAction::OpenUrl("https://a.example".to_string()))
    );
    assert_eq!(
        ctrl(&mut state, KeyCode::Char('o')),
        Some(UiAction::OpenUrl("https://b.example".to_string()))
    );
    assert_eq!(
        ctrl(&mut state, KeyCode::Char('o')),
        Some(UiAction::OpenUrl("https://a.example".to_string())),
        "a third press wraps back to the first link"
    );
}

/// @requirement AC-286
#[test]
fn ctrl_o_on_a_message_with_no_link_does_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message("general", UserId(2), "bob".into(), MessageBody::Text("hi".into()));

    assert_eq!(ctrl(&mut state, KeyCode::Char('o')), None);
}

/// @requirement AC-286
#[test]
fn ctrl_o_on_a_different_message_starts_over_at_its_first_link() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("https://first.example".into()),
    );
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("https://second.example".into()),
    );
    state.message_selected = 0;
    assert_eq!(
        ctrl(&mut state, KeyCode::Char('o')),
        Some(UiAction::OpenUrl("https://first.example".to_string()))
    );

    state.message_selected = 1;
    assert_eq!(
        ctrl(&mut state, KeyCode::Char('o')),
        Some(UiAction::OpenUrl("https://second.example".to_string())),
        "moving to a different message must not continue the previous message's cycle"
    );
}

/// @requirement AC-061
#[test]
fn up_down_clamp_at_the_ends_instead_of_wrapping() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 2);
    state.focus = Focus::Messages;
    assert_eq!(state.message_selected, 1);

    press(&mut state, KeyCode::Up);
    assert_eq!(state.message_selected, 0);
    press(&mut state, KeyCode::Up);
    assert_eq!(
        state.message_selected, 0,
        "Up at the top must clamp, not wrap to the bottom"
    );

    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Down);
    assert_eq!(state.message_selected, 1);
    press(&mut state, KeyCode::Down);
    assert_eq!(
        state.message_selected, 1,
        "Down at the bottom must clamp, not wrap to the top"
    );
}

/// @requirement AC-061
#[test]
fn page_up_page_down_home_and_end_jump_the_selection() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let total = aloo::client::tui::ui::MESSAGE_PAGE_JUMP + 5;
    push_n_channel_texts(&mut state, total);
    state.focus = Focus::Messages;
    assert_eq!(state.message_selected, total - 1);

    press(&mut state, KeyCode::Home);
    assert_eq!(state.message_selected, 0);

    press(&mut state, KeyCode::PageDown);
    assert_eq!(state.message_selected, aloo::client::tui::ui::MESSAGE_PAGE_JUMP);

    press(&mut state, KeyCode::End);
    assert_eq!(state.message_selected, total - 1);

    press(&mut state, KeyCode::PageUp);
    assert_eq!(
        state.message_selected,
        total - 1 - aloo::client::tui::ui::MESSAGE_PAGE_JUMP
    );
}

/// @requirement TB-109
#[test]
fn the_rendered_viewport_follows_the_selection_instead_of_always_showing_the_top() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    // enough messages that they can't all fit in a short terminal
    push_n_channel_texts(&mut state, 40);

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();

    assert!(
        rows.iter().any(|r| r.contains("msg39")),
        "the newest message should be visible by default: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("msg0")),
        "the oldest message should have scrolled out of view: {rows:?}"
    );

    // scroll all the way back up to the oldest message
    state.focus = Focus::Messages;
    press(&mut state, KeyCode::Home);
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();
    assert!(
        rows.iter().any(|r| r.contains("msg0")),
        "scrolling to Home should bring the oldest message into view: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("msg39")),
        "the newest message should have scrolled out of view: {rows:?}"
    );
}

/// @requirement AC-190
#[test]
fn scroll_keys_reach_the_log_from_the_compose_bar() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let total = 40;
    push_n_channel_texts(&mut state, total);
    assert_eq!(state.focus, Focus::Input, "focus starts at the compose bar");

    press(&mut state, KeyCode::Up);
    assert_eq!(state.message_selected, total - 2);
    assert_eq!(state.focus, Focus::Input, "scrolling shouldn't steal focus");
    assert!(
        state.input.is_empty(),
        "a scroll key must not type into the message being composed"
    );

    press(&mut state, KeyCode::PageUp);
    assert_eq!(
        state.message_selected,
        total - 2 - aloo::client::tui::ui::MESSAGE_PAGE_JUMP
    );
    press(&mut state, KeyCode::PageDown);
    assert_eq!(state.message_selected, total - 2);
    press(&mut state, KeyCode::Down);
    assert_eq!(state.message_selected, total - 1);
}

/// @requirement AC-190
#[test]
fn a_dm_room_that_cannot_be_typed_in_can_still_be_scrolled() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    for i in 0..5 {
        state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text(format!("m{i}")));
    }
    state.active_private_room = Some(UserId(2));
    state.message_selected = 4;
    // An offline peer's room takes no input at all - reading back what was
    // said before they dropped still has to work.
    state.on_user_offline(UserId(2));

    // Their disconnect notice lands in the room too, and the view follows
    // it - the point is only that Up still walks back from wherever the
    // selection ended up.
    let before = state.message_selected;
    press(&mut state, KeyCode::Up);
    assert_eq!(state.message_selected, before - 1);
}

/// @requirement AC-191
#[test]
fn an_overflowing_log_draws_a_scrollbar_and_a_short_one_does_not() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 40);
    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let (thumb, track) = message_scrollbar(terminal.backend().buffer())
        .expect("40 messages can't fit a 15-row terminal");
    assert!(
        thumb.len() < track.len(),
        "a thumb filling its track would say the log fits: {thumb:?} of {track:?}"
    );

    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 2);
    terminal.draw(|f| render(f, &state)).unwrap();
    assert!(
        message_scrollbar(terminal.backend().buffer()).is_none(),
        "a log that fits shouldn't give up a column to a scrollbar"
    );
}

/// @requirement TB-211
#[test]
fn the_scrollbar_thumb_tracks_the_viewport() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 40);
    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();

    terminal.draw(|f| render(f, &state)).unwrap();
    let (thumb, track) = message_scrollbar(terminal.backend().buffer()).expect("a scrollbar");
    assert_eq!(
        thumb.last(),
        track.last(),
        "on the newest message the thumb sits at the bottom: {thumb:?} of {track:?}"
    );

    state.focus = Focus::Messages;
    press(&mut state, KeyCode::Home);
    terminal.draw(|f| render(f, &state)).unwrap();
    let (thumb, track) = message_scrollbar(terminal.backend().buffer()).expect("a scrollbar");
    assert_eq!(
        thumb.first(),
        track.first(),
        "on the oldest message it sits at the top: {thumb:?} of {track:?}"
    );
}

// ---------------------------------------------------------------------
// Replaying a voice message / message-log Enter behavior
// ---------------------------------------------------------------------

/// @requirement AC-036
#[test]
fn enter_on_voice_message_in_messages_focus_requests_replay() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Voice {
            duration_ms: 4200,
            pcm: vec![1, 2, 3, 4],
        },
    );
    state.focus = Focus::Messages;
    let action = press(&mut state, KeyCode::Enter).unwrap();
    assert_eq!(
        action,
        UiAction::ReplayVoice {
            duration_ms: 4200,
            pcm: vec![1, 2, 3, 4],
            from: UserId(2),
            // Nothing is owed: this clip played on arrival.
            owed_receipt: None,
        }
    );
    assert!(
        state.replaying,
        "a non-empty clip should be tracked as playing"
    );
}

/// @requirement AC-036
#[test]
fn replaying_an_empty_clip_does_not_set_the_replaying_flag() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Voice {
            duration_ms: 0,
            pcm: vec![],
        },
    );
    state.focus = Focus::Messages;
    press(&mut state, KeyCode::Enter);
    assert!(
        !state.replaying,
        "nothing actually starts playing for an empty clip - Escape must not be hijacked"
    );
}

/// @requirement AC-098
#[test]
fn escape_stops_playback_of_a_voice_message_being_replayed() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Voice {
            duration_ms: 4200,
            pcm: vec![1, 2, 3, 4],
        },
    );
    state.focus = Focus::Messages;
    press(&mut state, KeyCode::Enter);
    assert!(state.replaying);

    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, Some(UiAction::StopPlayback));
    assert!(!state.replaying);
}

/// A terminal reporting genuine key-up events sends both `Press` and
/// `Release` for one physical keystroke - the `Release` must be absorbed,
/// not treated as a second Escape that falls through to closing the private
/// room now that `replaying` was already cleared by the `Press`.
///
/// @requirement AC-098
#[test]
fn escape_release_after_stopping_playback_does_not_also_close_the_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens a private room with bob
    assert!(state.active_private_room.is_some());
    state.on_direct_message(
        UserId(2),
        "bob".into(),
        MessageBody::Voice {
            duration_ms: 500,
            pcm: vec![9, 9],
        },
    );
    state.focus = Focus::Messages;
    press(&mut state, KeyCode::Enter); // start replay
    assert!(state.replaying);

    let press_action = state.handle_key(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Press);
    assert_eq!(press_action, Some(UiAction::StopPlayback));
    let release_action = state.handle_key(KeyCode::Esc, KeyModifiers::NONE, KeyEventKind::Release);
    assert_eq!(release_action, None);
    assert!(
        state.active_private_room.is_some(),
        "the room must still be open after the trailing Release"
    );
}

/// @requirement AC-036
#[test]
fn enter_on_text_message_in_messages_focus_does_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hi".into()),
    );
    state.focus = Focus::Messages;
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
}

// ---------------------------------------------------------------------
// Rendering smoke tests / help popup / identity banner (generic)
// ---------------------------------------------------------------------

/// @requirement AC-057
#[test]
fn render_help_popup_shows_expected_content_when_open() {
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("Help")),
        "expected a help popup title: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("Ctrl+J")),
        "expected help on joining a hidden channel: {rows:?}"
    );
    // Past the first screenful now that the two selectors and the log's
    // scroll keys have their own lines above them - reached the same way
    // the sections below are.
    let rows = scroll_help_until(&mut state, "Space");
    assert!(
        rows.iter().any(|r| r.contains("Space")),
        "expected help on sending a voice message: {rows:?}"
    );
    let rows = scroll_help_until(&mut state, "/file");
    assert!(
        rows.iter().any(|r| r.contains("/file")),
        "expected help on sending a file: {rows:?}"
    );
    // The encryption tags and identity pinning both sit far enough down the
    // (now longer) help text that a typical terminal does not show them
    // without scrolling - see docs/SPEC.md Functionality #7's scrollable
    // overlay. Scrolled to incrementally (rather than jumping straight to
    // End) since each section's exact distance from the bottom shifts
    // whenever HELP_BODY's content changes - the two sections are no
    // longer guaranteed to land in the same screenful.
    let rows = scroll_help_until(&mut state, "PQH");
    assert!(
        rows.iter().any(|r| r.contains("PQH")),
        "expected the encryption tags explained: {rows:?}"
    );
    let rows = scroll_help_until(&mut state, "Contacts & Keys");
    assert!(
        rows.iter().any(|r| r.contains("Contacts & Keys")),
        "expected id_store identity pinning and /contacts explained after scrolling further down: {rows:?}"
    );
}

/// @requirement AC-056
#[test]
fn help_headings_are_yellow_and_descriptions_gray() {
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    let backend = TestBackend::new(100, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    // Walk the buffer rows as (text, per-cell styles) pairs.
    let mut heading_fg = None;
    let mut key_fg = None;
    let mut desc_fg = None;
    for y in 0..buffer.area.height {
        let row: String = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect();
        if let Some(x) = row.find("Channels")
            && heading_fg.is_none()
        {
            heading_fg = Some(buffer[(x as u16, y)].fg);
        }
        if let Some(x) = row.find("Ctrl+J") {
            key_fg = Some(buffer[(x as u16, y)].fg);
            if let Some(dx) = row.find("join/create") {
                desc_fg = Some(buffer[(dx as u16, y)].fg);
            }
        }
    }
    assert_eq!(
        heading_fg,
        Some(ratatui::style::Color::Yellow),
        "section headings render yellow"
    );
    assert_eq!(
        desc_fg,
        Some(ratatui::style::Color::DarkGray),
        "a shortcut's description renders gray"
    );
    assert_ne!(
        key_fg, desc_fg,
        "the shortcut itself keeps the brighter default color"
    );
}

/// Presses PageDown until `text` appears on screen (or the help overlay's
/// scroll position stops advancing, i.e. it hit bottom) - a content-length-
/// independent way to reach a specific help section, since exactly how far
/// down any given line sits shifts whenever `HELP_BODY` changes.
fn scroll_help_until(state: &mut UiState, text: &str) -> Vec<String> {
    for _ in 0..40 {
        let rows = rendered_rows(state);
        if rows.iter().any(|r| r.contains(text)) {
            return rows;
        }
        let before = state.help_scroll();
        press(state, KeyCode::PageDown);
        if state.help_scroll() == before {
            break;
        }
    }
    rendered_rows(state)
}

/// @requirement TB-126
#[test]
fn help_scroll_moves_by_one_line_and_by_a_page_and_clamps_at_both_ends() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('h'));
    assert_eq!(state.help_scroll(), 0);

    press(&mut state, KeyCode::Down);
    assert_eq!(state.help_scroll(), 1, "Down moves one line");
    press(&mut state, KeyCode::Up);
    assert_eq!(state.help_scroll(), 0, "Up moves back one line");
    press(&mut state, KeyCode::Up);
    assert_eq!(state.help_scroll(), 0, "Up at the top must not go negative");

    press(&mut state, KeyCode::PageDown);
    assert_eq!(
        state.help_scroll(),
        aloo::client::tui::ui::HELP_SCROLL_PAGE,
        "PageDown jumps a full page"
    );

    press(&mut state, KeyCode::End);
    let bottom = state.help_scroll();
    assert!(
        bottom > aloo::client::tui::ui::HELP_SCROLL_PAGE,
        "End should jump past a single page"
    );
    press(&mut state, KeyCode::PageDown);
    assert_eq!(
        state.help_scroll(),
        bottom,
        "PageDown at the bottom must not scroll past the last line"
    );
    press(&mut state, KeyCode::Down);
    assert_eq!(
        state.help_scroll(),
        bottom,
        "Down at the bottom must not scroll past the last line either"
    );

    press(&mut state, KeyCode::Home);
    assert_eq!(state.help_scroll(), 0, "Home jumps back to the top");
}

/// @requirement TB-126
#[test]
fn help_always_reopens_scrolled_to_the_top() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('h'));
    press(&mut state, KeyCode::End);
    assert!(state.help_scroll() > 0, "should have scrolled down");

    ctrl(&mut state, KeyCode::Char('h')); // close
    assert!(!state.help_open);
    ctrl(&mut state, KeyCode::Char('h')); // reopen
    assert!(state.help_open);
    assert_eq!(
        state.help_scroll(),
        0,
        "reopening must not resume wherever it was left last time"
    );
}

// ---------------------------------------------------------------------
// Identity review popup (docs/PROTOCOL.md §12: manual Accept/Reject)
// ---------------------------------------------------------------------

fn static_mismatch() -> IdentityCase {
    IdentityCase::StaticMismatch {
        new_public_key_der: vec![9, 9, 9],
        previous_public_key_der: vec![1, 1, 1],
    }
}

/// @requirement AC-049, AC-064
#[test]
fn no_identity_review_popup_is_shown_when_nothing_is_pending() {
    let state = joined_general_with(vec![]);
    assert!(state.identity_review_open().is_none());
    let rows = rendered_rows(&state);
    assert!(
        !rows.iter().any(|r| r.contains("Identity review")),
        "no popup should render without a pending review"
    );
}

/// @requirement AC-064
#[test]
fn identity_review_popup_auto_opens_and_shows_the_case_specific_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "bob's key changed unexpectedly".into(),
        static_mismatch(),
    );

    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("bob")
    );
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("Identity review: bob")),
        "expected a popup titled with the nickname: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|r| r.contains("bob's key changed unexpectedly")),
        "expected the case-specific message: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("Accept")),
        "expected an Accept button: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("Reject")),
        "expected a Reject button: {rows:?}"
    );
}

/// @requirement AC-065
#[test]
fn accepting_an_identity_review_clears_it_and_reveals_held_messages() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        static_mismatch(),
    );
    // A message from bob while he's Pending is held, not shown.
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hi".into()),
    );
    assert!(
        state.channels[0].log.is_empty(),
        "held message must not appear in the visible log yet"
    );
    assert!(state.is_trust_gated(UserId(2)));

    state.resolve_identity_accept(UserId(2));

    assert!(
        !state.is_trust_gated(UserId(2)),
        "accepted peer is trusted again"
    );
    assert!(state.identity_review_open().is_none());
    assert_eq!(
        state.channels[0].log.len(),
        1,
        "the held message must be revealed on accept"
    );
    assert_eq!(
        state.channels[0].log[0].body,
        MessageBody::Text("hi".into())
    );
}

/// @requirement AC-065
#[test]
fn rejecting_an_identity_review_keeps_it_and_leaves_messages_held() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        static_mismatch(),
    );
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hi".into()),
    );

    state.resolve_identity_reject(UserId(2));

    assert!(
        state.is_trust_gated(UserId(2)),
        "a rejected peer is still not trusted"
    );
    assert!(
        state.channels[0].log.is_empty(),
        "a rejected sender's message stays held, never revealed"
    );
    assert!(
        state
            .pending_messages
            .get(&UserId(2))
            .is_some_and(|h| !h.is_empty())
    );
}

/// @requirement AC-066
#[test]
fn enter_on_a_trust_gated_sidebar_member_reopens_the_review_popup_instead_of_the_dm() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        static_mismatch(),
    );
    state.resolve_identity_reject(UserId(2)); // popup closes, bob stays Rejected
    assert!(state.identity_review_open().is_none());

    state.focus = Focus::Sidebar;
    state.sidebar_selected = 0;
    press(&mut state, KeyCode::Enter);

    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("bob")
    );
    assert_eq!(
        state.active_private_room, None,
        "must not open the private room for an unverified peer"
    );
}

/// @requirement AC-049, AC-067
#[test]
fn a_second_mismatch_queues_behind_the_open_one_and_is_shown_once_it_resolves() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "bob mismatch".into(),
        static_mismatch(),
    );
    state.push_identity_review(
        UserId(3),
        "carol".into(),
        "carol mismatch".into(),
        static_mismatch(),
    );

    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("bob"),
        "bob's arrived first"
    );

    state.resolve_identity_reject(UserId(2));

    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("carol"),
        "carol's queued review should open once bob's is resolved"
    );
}

/// @requirement TB-117
#[test]
fn a_silently_resolved_review_is_removed_even_when_it_is_not_the_one_shown() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "bob unverified".into(),
        static_mismatch(),
    );
    state.push_identity_review(
        UserId(3),
        "carol".into(),
        "carol unverified".into(),
        static_mismatch(),
    );
    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("bob"),
        "bob's arrived first"
    );

    // Carol's identity gets resolved programmatically (not through the
    // popup) while bob's review is still the one on screen. Must clear
    // carol specifically, not whichever review happens to be at the front.
    state.resolve_identity_accept(UserId(3));

    assert!(
        !state.is_trust_gated(UserId(3)),
        "carol should be trusted again"
    );
    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("bob"),
        "bob's still-open review must not be disturbed by resolving carol's"
    );
}

/// @requirement AC-068
#[test]
fn sending_a_channel_message_excludes_a_pending_or_rejected_member() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        static_mismatch(),
    );
    // Resolve the review (as if the user had already answered the popup)
    // before exercising the send path - while a review is genuinely
    // pending, the popup absorbs every keystroke (see
    // `identity_review_popup_auto_opens_and_shows_the_case_specific_message`),
    // so there's nothing to type into until it's decided. `Rejected` still
    // excludes bob from the send afterward, same as `Pending` would.
    state.resolve_identity_reject(UserId(2));
    state.focus = Focus::Input;
    type_str(&mut state, "hello");
    let action = press(&mut state, KeyCode::Enter);

    match action {
        Some(UiAction::SendChannelText { recipients, .. }) => {
            assert!(
                !recipients.iter().any(|(id, ..)| *id == UserId(2)),
                "the pending member must be excluded"
            );
            assert!(
                recipients.iter().any(|(id, ..)| *id == UserId(3)),
                "everyone else still gets the message"
            );
        }
        other => panic!("expected SendChannelText, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Deferred identity review: begin/reveal (docs/PROTOCOL.md §12.7)
// ---------------------------------------------------------------------

/// @requirement AC-166
#[test]
fn a_begun_review_gates_messaging_but_shows_no_popup_yet() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_identity_review(UserId(2), "bob".into(), static_mismatch());

    assert!(
        state.is_trust_gated(UserId(2)),
        "messaging must be gated the instant a mismatch is detected"
    );
    assert!(
        state.identity_review_open().is_none(),
        "nothing should be shown until the review is revealed"
    );
    let rows = rendered_rows(&state);
    assert!(
        !rows.iter().any(|r| r.contains("Identity review")),
        "no popup should render for an AwaitingPeerInfo review: {rows:?}"
    );
}

/// @requirement AC-166
#[test]
fn revealing_a_begun_review_shows_the_popup_and_chimes() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_identity_review(UserId(2), "bob".into(), static_mismatch());

    let revealed = state.reveal_identity_review(UserId(2), "last known vs. new address".into());

    assert!(revealed, "a pending AwaitingPeerInfo review must reveal");
    assert_eq!(
        state.identity_review_open().map(|r| r.nickname.as_str()),
        Some("bob")
    );
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("last known vs. new address")),
        "expected the revealed message to render: {rows:?}"
    );
}

/// @requirement AC-166
#[test]
fn revealing_a_review_that_was_never_begun_is_a_no_op() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let revealed = state.reveal_identity_review(UserId(2), "message".into());
    assert!(!revealed);
    assert!(state.identity_review_open().is_none());
}

/// @requirement AC-166
#[test]
fn revealing_an_already_revealed_review_is_a_no_op_second_time() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_identity_review(UserId(2), "bob".into(), static_mismatch());
    assert!(state.reveal_identity_review(UserId(2), "first".into()));
    // A second `LinkStatusChanged` for the same peer (e.g. the link later
    // flaps and re-punches) must not re-reveal or re-chime.
    assert!(!state.reveal_identity_review(UserId(2), "second".into()));
    assert_eq!(
        state.identity_review_open().map(|r| r.message.as_str()),
        Some("first"),
        "the message from the second call must not overwrite the first"
    );
}

/// @requirement AC-166
#[test]
fn enter_on_a_still_awaiting_sidebar_member_does_not_open_anything() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_identity_review(UserId(2), "bob".into(), static_mismatch());

    state.focus = Focus::Sidebar;
    state.sidebar_selected = 0;
    press(&mut state, KeyCode::Enter);

    assert!(
        state.identity_review_open().is_none(),
        "there is nothing to show yet, so Enter must not force it open"
    );
}

/// @requirement TB-108
#[test]
fn help_popup_widens_enough_to_show_its_longest_line_without_clipping_it() {
    // The pq_hybrid encryption line is a good proxy for whether the popup
    // widened correctly - on a narrower terminal a fixed popup would clip
    // it. Rendered at 130 columns (wider than the default 100 `rendered_rows`
    // uses) so the line's ~98-cell width comfortably clears the popup's own
    // 90%-of-terminal cap - that cap is exercised deliberately narrow by
    // `help_popup_never_exceeds_90_percent_of_the_terminal_width` instead.
    // Checked without the emoji itself, since a 2-cell-wide emoji leaves a
    // padding cell in ratatui's buffer that would otherwise break a plain
    // substring match. It sits below the fold on the first screen, so this
    // scrolls to it first - same precedent as
    // `render_help_popup_shows_expected_content_when_open`.
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    let tail = "the only scheme there is: ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM, \
                loaded from a file";
    let rows_130 = |state: &UiState| -> Vec<String> {
        let backend = ratatui::backend::TestBackend::new(130, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    };
    // Scrolled to incrementally rather than jumping to End - see
    // `scroll_help_until`'s doc for why the exact distance to this line
    // isn't assumed fixed.
    let mut rows = rows_130(&state);
    for _ in 0..40 {
        if rows.iter().any(|r| r.contains(tail)) {
            break;
        }
        let before = state.help_scroll();
        press(&mut state, KeyCode::PageDown);
        if state.help_scroll() == before {
            break;
        }
        rows = rows_130(&state);
    }
    assert!(
        rows.iter().any(|r| r.contains(tail)),
        "expected the longest help line in full, unclipped: {rows:?}"
    );
}

/// @requirement TB-108
#[test]
fn the_help_popup_fills_the_whole_frame() {
    // Narrower and shorter than the help text needs, so nothing but the
    // frame itself can be deciding the popup's size here.
    let (width, height) = (60u16, 20u16);
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    let buffer = buffer_at(&state, width, height);

    let (x, y, popup_width, popup_height) = popup_rect(&buffer, HELP_POPUP_TITLE);
    assert_eq!(
        (x, y),
        (0, 0),
        "help starts at the very top left, above the header: {:?}",
        rows_of(&buffer)
    );
    assert_eq!(
        (popup_width, popup_height),
        (width, height),
        "help covers the whole frame, compose bar included: {:?}",
        rows_of(&buffer)
    );
}

/// The compose bar is the one part of the view furthest from where the
/// overlay starts, so it gets its own check rather than being folded into
/// the geometry assertion above.
/// @requirement TB-108
#[test]
fn the_help_popup_covers_the_compose_bar() {
    let mut state = joined_general_with(vec![]);
    type_str(&mut state, "half-typed message");
    let before = rendered_rows(&state);
    assert!(
        before.iter().any(|r| r.contains("half-typed message")),
        "the compose bar should be showing before help opens: {before:?}"
    );

    state.help_open = true;
    let after = rendered_rows(&state);
    assert!(
        !after.iter().any(|r| r.contains("half-typed message")),
        "the compose bar must be covered while help is open: {after:?}"
    );
}

/// @requirement AC-038
#[test]
fn render_shows_recording_indicator_while_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("recording")),
        "expected a recording indicator: {rows:?}"
    );
}

/// @requirement AC-038
#[test]
fn render_does_not_show_recording_or_playback_errors() {
    // Deliberate: this environment's audio stack surfaces plenty of
    // transient, self-recovering errors (buffer under/overruns,
    // PulseAudio status-query hiccups) that aren't worth interrupting the
    // screen for. The state is still tracked internally (see
    // `recording_failed_clears_the_misleading_recording_indicator_and_shows_why`
    // and `playback_failed_shows_the_reason_without_touching_recording_state`)
    // - it's only the on-screen rendering that's suppressed.
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.recording_failed("no input device available".into());
    let rows = rendered_rows(&state);
    assert!(
        !rows.iter().any(|r| r.contains("no input device available")),
        "{rows:?}"
    );

    state.playback_failed("no output device available".into());
    let rows = rendered_rows(&state);
    assert!(
        !rows
            .iter()
            .any(|r| r.contains("no output device available")),
        "{rows:?}"
    );
}

/// @requirement TB-101
#[test]
fn render_empty_state_does_not_panic() {
    let state = UiState::new("me".into());
    let backend = ratatui::backend::TestBackend::new(80, 24);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
}

// ---------------------------------------------------------------------
// Live voice calls (US-036) - distinct from push-to-talk
// (`test/cucumber/steps/voice.rs` has the Gherkin-level coverage for the
// same behavior; these pin the exact `UiState` mechanics). The network/
// audio orchestration (`crate::client::voice_call`) needs a live session
// and a real microphone, so it isn't covered here - see docs/TESTING.md's
// "Known coverage gaps".
// ---------------------------------------------------------------------

/// @requirement AC-167
#[test]
fn incoming_call_invite_shows_a_popup_naming_the_caller_with_accept_focused() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert!(state.call_invite_open().is_none());

    let shown = state.push_call_invite(PendingCallInvite {
        call_id: 42,
        from: UserId(2),
        from_name: "bob".into(),
        channel: Some("general".into()),
        ended: false,
    });
    assert!(shown, "the first invite becomes the one shown");
    assert_eq!(
        state.call_invite_open().map(|i| i.from_name.as_str()),
        Some("bob")
    );

    let rows = rendered_rows(&state);
    assert!(
        rows.iter()
            .any(|r| r.contains("Voice call incoming from bob")),
        "{rows:?}"
    );
    assert!(rows.iter().any(|r| r.contains("Accept")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("Reject")), "{rows:?}");

    // Accept is focused by default - a bare Enter accepts.
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::AcceptCallInvite { call_id: 42 }));
}

/// @requirement AC-167
#[test]
fn a_call_invite_from_a_trust_gated_sender_is_held_until_accepted() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(UserId(2), "bob".into(), "mismatch".into(), static_mismatch());
    assert!(state.is_trust_gated(UserId(2)));

    state.hold_call_invite(PendingCallInvite {
        call_id: 7,
        from: UserId(2),
        from_name: "bob".into(),
        channel: Some("general".into()),
        ended: false,
    });
    assert!(
        state.call_invite_open().is_none(),
        "held, not shown, while trust-gated"
    );

    let played_bell = state.resolve_identity_accept(UserId(2));
    assert!(
        played_bell,
        "the revealed invite becomes the one shown, so the caller should chime"
    );
    assert_eq!(state.call_invite_open().map(|i| i.call_id), Some(7));
}

/// @requirement AC-168
#[test]
fn rejecting_a_call_invite_clears_it_and_shows_the_next_queued_one() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_call_invite(PendingCallInvite {
        call_id: 1,
        from: UserId(2),
        from_name: "bob".into(),
        channel: None,
        ended: false,
    });
    state.push_call_invite(PendingCallInvite {
        call_id: 2,
        from: UserId(3),
        from_name: "carol".into(),
        channel: None,
        ended: false,
    });

    press(&mut state, KeyCode::Left); // move focus onto Reject
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::RejectCallInvite { call_id: 1 }));

    // `session::handle_ui_action` applies the decision over the network;
    // its local half is just this.
    state.take_call_invite(1);

    assert_eq!(
        state.call_invite_open().map(|i| i.call_id),
        Some(2),
        "carol's invite is shown next"
    );
}

/// @requirement AC-169
#[test]
fn the_permanent_call_indicator_tracks_participants_and_mute_state() {
    let mut state = joined_general_with(vec![]);
    assert!(state.call.is_none());
    assert!(!rendered_rows(&state).iter().any(|r| r.contains("On a call")));

    state.begin_call(99, Some("general".into()), UserId(1));
    assert!(state.call.is_some());
    let rows = rendered_rows(&state);
    assert!(rows.iter().any(|r| r.contains("On a call")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("0 connected")), "{rows:?}");

    state.on_call_participant_joined(UserId(2), "bob".into());
    assert!(
        rendered_rows(&state)
            .iter()
            .any(|r| r.contains("1 connected"))
    );

    state.set_call_muted(true);
    assert!(rendered_rows(&state).iter().any(|r| r.contains("muted")));

    state.on_call_participant_left(UserId(2));
    assert!(
        rendered_rows(&state)
            .iter()
            .any(|r| r.contains("0 connected"))
    );

    state.end_call();
    assert!(state.call.is_none());
    assert!(!rendered_rows(&state).iter().any(|r| r.contains("On a call")));
}

/// The permanent call indicator and the transient status notice
/// (`STATUS_NOTICE_TIMEOUT`) occupy the same top-right corner but must
/// never clobber each other - see `render_status_notice`'s `y` parameter.
///
/// @requirement AC-169
#[test]
fn the_call_indicator_and_a_status_notice_are_both_visible_at_once() {
    let mut state = joined_general_with(vec![]);
    state.begin_call(1, None, UserId(1));
    state.push_status_notice("bob left the call".into(), true);

    let rows = rendered_rows(&state);
    assert!(rows.iter().any(|r| r.contains("On a call")), "{rows:?}");
    assert!(
        rows.iter().any(|r| r.contains("bob left the call")),
        "{rows:?}"
    );
}

/// Muting ourselves is the modal's own `m`, on our own row - the only way
/// to do it, and available to every participant, not just the host.
///
/// @requirement AC-170
#[test]
fn m_on_our_own_row_toggles_our_own_microphone() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());

    // Row 0 is us - our own row, whether or not we happen to be the host.
    assert_eq!(
        press(&mut state, KeyCode::Char('m')),
        Some(UiAction::ToggleCallMute)
    );

    // And as a plain participant, on someone else's call, just the same.
    let mut guest = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    guest.begin_call(1, Some("general".into()), UserId(3));
    guest.on_call_participant_joined(UserId(3), "carol".into());
    // The cursor follows whoever it was on as the roster sorts, so walk it
    // onto our own row from wherever it actually is.
    let call = guest.call.as_ref().unwrap();
    let own_row = call
        .members
        .iter()
        .position(|m| Some(m.id) == guest.own_id)
        .expect("our own row");
    let steps = (own_row + call.members.len() - call.selected) % call.members.len();
    for _ in 0..steps {
        press(&mut guest, KeyCode::Down);
    }
    assert_eq!(
        press(&mut guest, KeyCode::Char('m')),
        Some(UiAction::ToggleCallMute)
    );
}

/// @requirement AC-171
#[test]
fn slash_endcall_is_refused_off_a_call_and_works_on_one() {
    let mut state = joined_general_with(vec![]);
    state.focus = Focus::Input;

    type_str(&mut state, "/endcall");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some("not on a call")
    );

    on_call_minimized(&mut state, 1, None);
    type_str(&mut state, "/endcall");
    assert_eq!(press(&mut state, KeyCode::Enter), Some(UiAction::EndCall));
}

/// @requirement AC-171
#[test]
fn slash_call_is_refused_while_already_on_a_call_or_mid_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Input;

    on_call_minimized(&mut state, 1, None);
    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some("already on a call")
    );
    state.end_call();

    state.recording = true;
    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some("can't start a call while recording a voice message")
    );
}

/// @requirement AC-171
#[test]
fn slash_call_with_nowhere_to_call_shows_a_notice() {
    let mut state = UiState::new("me".into());
    state.focus = Focus::Input;
    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some("nobody to call here")
    );
}

/// @requirement AC-167
#[test]
fn slash_call_addresses_the_viewed_channel_or_an_open_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Input;

    // `/call` opens the confirmation first - a second Enter (Call is
    // focused) is what actually starts it.
    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::StartCall(CallTarget::Channel {
            channel: "general".into()
        }))
    );

    // `known_users`/`channel.members` are already seeded with bob
    // (`joined_general_with`) - opening a private room with him is just
    // pointing `active_private_room` at his id, same as
    // `direct_message::open_private_room` does before this ever runs.
    state.active_private_room = Some(UserId(2));
    type_str(&mut state, "/call");
    press(&mut state, KeyCode::Enter);
    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::StartCall(CallTarget::Direct { to, .. })) => {
            assert_eq!(to, UserId(2))
        }
        other => panic!("expected a direct call target, got {other:?}"),
    }
}

/// @requirement AC-171
#[test]
fn push_to_talk_is_unavailable_while_on_a_call() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages;
    on_call_minimized(&mut state, 1, None);

    let action = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert_eq!(action, None);
    assert!(!state.recording, "the mic is already spoken for by the call");
}


/// The call modal (`docs/SPEC.md` "Live voice calls") opens the moment a
/// call starts and shows every roster label the spec calls for: the host
/// named `<nickname> (host)` rather than labelled, then IN CALL / INVITED
/// / REJECTED on where each person stands, MUTED on anyone the host has
/// silenced.
///
/// @requirement AC-175
#[test]
fn the_call_modal_lists_the_host_first_and_labels_every_participant() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol"), user(4, "dave")]);
    // dave hosts: the roster must put him first even though we join it
    // holding only our own row.
    state.begin_call(7, Some("general".into()), UserId(4));
    state.on_call_participant_joined(UserId(4), "dave".into());
    state.on_call_participant_joined(UserId(2), "bob".into());
    state.on_call_invite_sent(UserId(3), "carol".into());
    state.on_call_invite_rejected(UserId(3));
    state.set_call_member_host_muted(UserId(2), true);

    let call = state.call.as_ref().unwrap();
    assert_eq!(
        call.members.first().map(|m| m.id),
        Some(UserId(4)),
        "the host is always the first row"
    );
    assert_eq!(
        call.members.iter().find(|m| m.id == UserId(3)).unwrap().state,
        CallMemberState::Rejected
    );

    let rows = rendered_rows(&state);
    let joined = rows.join("\n");
    for label in ["IN CALL", "REJECTED", "MUTED", "END CALL"] {
        assert!(joined.contains(label), "missing {label} in {rows:?}");
    }
    assert!(
        !joined.contains("HOST"),
        "the host carries no label of its own: {rows:?}"
    );
    assert!(
        joined.contains("dave (host)"),
        "the host is named instead: {rows:?}"
    );
    assert!(
        joined.contains("bob") && joined.contains("carol"),
        "{rows:?}"
    );
}

/// Every row pads its name and its labels to a fixed width, so a `MUTED`
/// appearing on one row never slides that row's voice bar out of line with
/// the others (`docs/SPEC.md` "Live voice calls").
///
/// @requirement AC-175
#[test]
fn every_roster_row_starts_its_voice_bar_in_the_same_column() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());
    state.on_call_invite_sent(UserId(3), "carol".into());
    state.set_call_member_host_muted(UserId(2), true);

    let rows = rendered_rows(&state);
    let bar_columns: Vec<usize> = rows
        .iter()
        .filter(|r| r.contains(['\u{2591}', '\u{2588}']))
        .map(|r| r.find(['\u{2591}', '\u{2588}']).expect("a bar on this row"))
        .collect();
    assert_eq!(bar_columns.len(), 3, "one bar per roster row: {rows:?}");
    assert!(
        bar_columns.iter().all(|c| *c == bar_columns[0]),
        "every bar starts in the same column: {bar_columns:?} in {rows:?}"
    );
}

/// An invite that hasn't been answered yet reads INVITED - the only state
/// the host ever sees that no other participant can.
///
/// @requirement AC-175
#[test]
fn an_unanswered_invitee_is_listed_as_invited() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_invite_sent(UserId(2), "bob".into());

    assert_eq!(
        state
            .call
            .as_ref()
            .unwrap()
            .members
            .iter()
            .find(|m| m.id == UserId(2))
            .unwrap()
            .state,
        CallMemberState::Invited
    );
    assert!(
        rendered_rows(&state).join("\n").contains("INVITED"),
        "an unanswered invite is labelled INVITED"
    );
}

/// The duration readout ticks in whole seconds and rolls over into hours,
/// driven off the session's clock rather than read at render time.
///
/// @requirement AC-176
#[test]
fn the_call_modal_shows_a_live_duration() {
    let mut state = joined_general_with(vec![]);
    state.begin_call(1, None, UserId(1));
    assert_eq!(state.call.as_ref().unwrap().duration_label(), "00:00");

    let started = state.call.as_ref().unwrap().started_at;
    state.tick_call_duration(started + Duration::from_secs(65));
    assert_eq!(state.call.as_ref().unwrap().duration_label(), "01:05");
    assert!(rendered_rows(&state).join("\n").contains("01:05"));

    state.tick_call_duration(started + Duration::from_secs(3_725));
    assert_eq!(state.call.as_ref().unwrap().duration_label(), "01:02:05");
}

/// Every participant carries a live voice meter, and our own reads flat
/// zero while we're muted - the meter shows what is actually being sent.
///
/// @requirement AC-176
#[test]
fn each_participant_has_a_live_voice_meter() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, None, UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());

    state.set_call_level(UserId(2), 100);
    assert_eq!(
        state
            .call
            .as_ref()
            .unwrap()
            .members
            .iter()
            .find(|m| m.id == UserId(2))
            .unwrap()
            .level,
        100
    );
    assert!(
        rendered_rows(&state).join("\n").contains("\u{2588}"),
        "a full meter draws filled blocks"
    );

    // Levels are clamped, and a host mute zeroes the meter it silences.
    state.set_call_level(UserId(2), 250);
    state.set_call_member_host_muted(UserId(2), true);
    let bob = state
        .call
        .as_ref()
        .unwrap()
        .members
        .iter()
        .find(|m| m.id == UserId(2))
        .unwrap()
        .clone();
    assert_eq!(bob.level, 0);
}

/// Escape folds the modal away into the top row's `Call Ctrl+R`
/// indicator - which stays on screen for the whole call, next to the
/// status figures - and Ctrl+R brings the modal back.
///
/// @requirement AC-177
#[test]
fn escape_folds_the_call_modal_into_the_header_indicator() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    assert!(state.call_modal_showing());

    assert_eq!(press(&mut state, KeyCode::Esc), None);
    assert!(state.call.as_ref().unwrap().minimized);
    assert!(!state.call_modal_showing(), "folded away, not showing");
    // The indicator advertising the way back is in the top row.
    let rows = rendered_rows(&state);
    assert!(rows[HEADER_TEXT_ROW].contains("Call"), "{rows:?}");
    assert!(rows[HEADER_TEXT_ROW].contains("Ctrl+R"), "{rows:?}");
    // The ordinary layout is usable again - the modal is not in the way.
    assert!(rows.iter().any(|r| r.contains("Users")), "{rows:?}");
    assert!(
        rows.iter().any(|r| r.contains("Message")),
        "the compose bar is back: {rows:?}"
    );

    // Ctrl+R brings it back up, over that same layout.
    ctrl(&mut state, KeyCode::Char('r'));
    assert!(state.call_modal_showing());
    let rows = rendered_rows(&state);
    assert!(rows.join("\n").contains("END CALL"), "{rows:?}");
}

/// The roster scrolls rather than truncating: with more members than fit,
/// moving the cursor down keeps it on screen.
///
/// @requirement AC-177
#[test]
fn the_call_roster_scrolls_to_keep_the_selection_visible() {
    let members: Vec<_> = (2..40).map(|i| user(i, &format!("user{i}"))).collect();
    let mut state = joined_general_with(members);
    state.begin_call(1, Some("general".into()), UserId(1));
    for i in 2..40u64 {
        state.on_call_participant_joined(UserId(i), format!("user{i}"));
    }

    for _ in 0..38 {
        press(&mut state, KeyCode::Down);
    }
    assert_eq!(state.call.as_ref().unwrap().selected, 38);
    assert!(
        rendered_rows(&state).join("\n").contains("user39"),
        "the selected row scrolled into view"
    );
    // Up from the top wraps to the bottom, same as every other list here.
    press(&mut state, KeyCode::Down);
    assert_eq!(state.call.as_ref().unwrap().selected, 0);
}

/// END CALL is what the modal's Enter presses, and it asks before it
/// leaves; `/endcall` still works from anywhere once the modal is out of
/// the way.
///
/// @requirement AC-178
#[test]
fn the_modal_end_call_button_asks_before_it_ends_the_call() {
    let mut state = joined_general_with(vec![]);
    state.begin_call(1, None, UserId(1));
    assert!(rendered_rows(&state).join("\n").contains("END CALL"));

    // The button itself only opens the question.
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains(END_CALL_CONFIRM_TITLE)),
        "pressing END CALL asks first: {rows:?}"
    );
    assert!(
        state.call.is_some(),
        "and nothing about the call has changed yet"
    );

    // Cancel is the default answer, so Enter straight away backs out.
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(
        !rendered_rows(&state)
            .iter()
            .any(|r| r.contains(END_CALL_CONFIRM_TITLE)),
        "answering closes the question"
    );
    assert!(state.call.is_some(), "cancelling leaves the call running");

    // Moving onto END CALL and confirming is what actually leaves.
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Left);
    assert_eq!(press(&mut state, KeyCode::Enter), Some(UiAction::EndCall));
}

/// The question absorbs every key while it is open, so no roster key can
/// be mistaken for an answer to it - and Escape backs out of it rather
/// than folding the modal away underneath it.
///
/// @requirement AC-178
#[test]
fn the_end_call_question_absorbs_every_other_key() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());
    press(&mut state, KeyCode::Enter);

    assert_eq!(press(&mut state, KeyCode::Down), None);
    assert_eq!(
        state.call.as_ref().unwrap().selected,
        0,
        "the roster must not move under an unanswered question"
    );
    assert_eq!(press(&mut state, KeyCode::Char('m')), None, "nor mute anyone");

    press(&mut state, KeyCode::Esc);
    assert!(
        !rendered_rows(&state)
            .iter()
            .any(|r| r.contains(END_CALL_CONFIRM_TITLE)),
        "Escape answers the question"
    );
    assert!(
        !state.call.as_ref().unwrap().minimized,
        "and stops there rather than folding the modal away too"
    );
}

/// `m` on the roster is the host's mute toggle, and only the host's - a
/// participant pressing it produces nothing, which is what "only the host
/// can restore it" rests on.
///
/// @requirement AC-179
#[test]
fn only_the_host_can_mute_a_participant_from_the_roster() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());

    // Row 0 is us: `m` there is our own mute, not a host mute of anyone.
    assert_eq!(
        press(&mut state, KeyCode::Char('m')),
        Some(UiAction::ToggleCallMute)
    );
    press(&mut state, KeyCode::Down);
    assert_eq!(
        press(&mut state, KeyCode::Char('m')),
        Some(UiAction::HostMuteCallMember {
            peer: UserId(2),
            muted: true
        })
    );
    // Once applied, the same key lifts it - still host-only.
    state.set_call_member_host_muted(UserId(2), true);
    assert_eq!(
        press(&mut state, KeyCode::Char('m')),
        Some(UiAction::HostMuteCallMember {
            peer: UserId(2),
            muted: false
        })
    );

    // Same roster, but carol hosts: `m` does nothing at all for us now.
    let mut guest = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    guest.begin_call(1, Some("general".into()), UserId(3));
    guest.on_call_participant_joined(UserId(3), "carol".into());
    guest.on_call_participant_joined(UserId(2), "bob".into());
    // Cursor onto bob (not us, not the host): nothing to do without the
    // host's authority.
    press(&mut guest, KeyCode::Down);
    let on_bob = guest
        .call
        .as_ref()
        .unwrap()
        .members
        .get(guest.call.as_ref().unwrap().selected)
        .map(|m| m.id);
    assert_eq!(on_bob, Some(UserId(2)), "cursor is on bob");
    assert_eq!(press(&mut guest, KeyCode::Char('m')), None);
}

/// `i` opens the host's invite picker, listing only people we share a
/// channel or DM with and who aren't already invited or on the call - the
/// "one active invitation at a time per user" rule.
///
/// @requirement AC-180
#[test]
fn the_host_can_invite_someone_who_shares_a_channel_and_only_once() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    // A stranger we share nothing with is never a candidate.
    state.known_users.insert(UserId(9), user(9, "stranger"));
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());

    let candidates = state.call_invite_candidates();
    let names: Vec<&str> = candidates.iter().map(|(_, n)| n.as_str()).collect();
    assert_eq!(names, vec!["carol"], "bob is already on the call");

    assert_eq!(press(&mut state, KeyCode::Char('i')), None);
    assert!(state.call.as_ref().unwrap().invite_picker.is_some());
    assert!(rendered_rows(&state).join("\n").contains("Invite to call"));
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::InviteToCall { to: UserId(3) })
    );

    // Once invited, carol is no longer offerable - one active invitation
    // per user at a time.
    state.on_call_invite_sent(UserId(3), "carol".into());
    assert!(state.call_invite_candidates().is_empty());
    assert_eq!(press(&mut state, KeyCode::Char('i')), None);
    assert!(state.call.as_ref().unwrap().invite_picker.is_none());
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some("nobody left to invite to this call")
    );
}

/// A participant who isn't the host has no invite picker at all.
///
/// @requirement AC-180
#[test]
fn only_the_host_can_open_the_invite_picker() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.begin_call(1, Some("general".into()), UserId(2));
    state.on_call_participant_joined(UserId(2), "bob".into());

    assert!(!state.open_call_invite_picker());
    assert!(state.call.as_ref().unwrap().invite_picker.is_none());
}

/// `/call` confirms first, saying in so many words how many people it is
/// about to ring - nothing is sent until that is answered.
///
/// @requirement AC-181
#[test]
fn slash_call_confirms_how_many_users_it_will_invite() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.focus = Focus::Input;

    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let pending = state.call_confirm.as_ref().expect("confirmation opened");
    assert_eq!(pending.invitee_count, 2);
    let rows = rendered_rows(&state);
    assert!(rows.join("\n").contains("2 users"), "{rows:?}");

    // Cancel leaves nothing behind and rings nobody.
    press(&mut state, KeyCode::Left);
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(state.call_confirm.is_none());
    assert!(state.call.is_none());

    // Confirming is what produces the actual StartCall.
    type_str(&mut state, "/call");
    press(&mut state, KeyCode::Enter);
    assert_eq!(
        press(&mut state, KeyCode::Enter),
        Some(UiAction::StartCall(CallTarget::Channel {
            channel: "general".into()
        }))
    );
}

/// A `/call` with nobody reachable never opens a confirmation at all -
/// it says so and stops.
///
/// @requirement AC-182
#[test]
fn slash_call_with_no_reachable_members_says_no_one_was_invited() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Input;
    state.on_user_offline(UserId(2));

    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(state.call_confirm.is_none(), "nothing to confirm");
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some(NO_ONE_INVITED_NOTICE)
    );
}

/// The host hanging up ends the call for everyone, with a notice saying
/// so - unlike any other participant leaving, which just removes a row.
///
/// @requirement AC-183
#[test]
fn the_hosts_departure_notice_reads_as_the_call_ending() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(2));
    state.on_call_participant_joined(UserId(2), "bob".into());

    // What `voice_call::on_call_end` does on the host's `CallEnd`.
    state.end_call();
    state.push_status_notice(HOST_LEFT_NOTICE.to_string(), false);

    assert!(state.call.is_none());
    let rows = rendered_rows(&state);
    assert!(
        !rows[HEADER_TEXT_ROW].contains("Ctrl+R"),
        "the header's call indicator goes with it: {rows:?}"
    );
    assert!(rows.join("\n").contains(HOST_LEFT_NOTICE));
}

/// The OTP layer has no live-streaming concept at all, so a DM call to a
/// peer under an active session is refused outright - and refused *before*
/// the confirmation, not after it: asking "invite 1 user?" only to refuse
/// the moment it is agreed to would be worse than no confirmation at all.
/// A channel call takes the other route the spec gives it, silently
/// leaving such a member out of the count and the invite.
///
/// @requirement AC-184
#[test]
fn a_call_to_an_otp_active_peer_is_refused_without_a_confirmation() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.focus = Focus::Input;
    state.mark_otp_active(UserId(2));

    state.active_private_room = Some(UserId(2));
    type_str(&mut state, "/call");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(
        state.call_confirm.is_none(),
        "an impossible call must not be confirmable"
    );
    assert_eq!(
        state.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some(OTP_CALL_REFUSAL)
    );
    assert!(state.call.is_none());

    // In a channel, the same peer is simply left out - carol is still
    // reachable, so the call goes ahead naming one invitee, not two.
    state.active_private_room = None;
    type_str(&mut state, "/call");
    press(&mut state, KeyCode::Enter);
    let pending = state.call_confirm.as_ref().expect("confirmation opened");
    assert_eq!(pending.invitee_count, 1, "bob is under OTP and excluded");
    assert!(rendered_rows(&state).join("\n").contains("1 user"));

    // And with nobody else left, a channel call has nobody to invite at
    // all rather than an OTP-only roster.
    let mut alone = joined_general_with(vec![user(2, "bob")]);
    alone.focus = Focus::Input;
    alone.mark_otp_active(UserId(2));
    type_str(&mut alone, "/call");
    assert_eq!(press(&mut alone, KeyCode::Enter), None);
    assert_eq!(
        alone.status_notice.as_ref().map(|(m, _)| m.as_str()),
        Some(NO_ONE_INVITED_NOTICE)
    );
}

/// The folded-away call keeps a red-bordered box of its own in the top
/// row - filling the header band's height, immediately left of the status
/// figures (`docs/SPEC.md` "Live voice calls").
///
/// @requirement AC-177
#[test]
fn the_call_indicator_is_a_bordered_box_beside_the_status_figures() {
    let mut state = joined_general_with(vec![]);
    on_call_minimized(&mut state, 1, Some("general".into()));
    let rows = rendered_rows(&state);

    let marker_row = HEADER_TEXT_ROW;
    let marker = rows[marker_row]
        .find("Call")
        .expect("the marker names the call");
    let conn = rows[marker_row].find("Conn:").expect("the status figures");
    assert!(marker < conn, "the box sits left of them: {rows:?}");
    // Its own borders sit on the blank lines above and below the row.
    for y in [marker_row - 1, marker_row + 1] {
        assert!(
            rows[y].contains('\u{2500}'),
            "expected a horizontal border on row {y}: {rows:?}"
        );
    }
    assert!(
        rows[marker_row].contains('\u{2502}'),
        "and vertical borders beside the text: {rows:?}"
    );
}

/// A call that ends while its invitation is still on screen takes the
/// invitation with it: accepting afterwards joins nothing and says so
/// (`docs/SPEC.md` "Live voice calls").
///
/// @requirement AC-188
#[test]
fn a_call_end_marks_an_unanswered_invite_from_that_caller() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_call_invite(PendingCallInvite {
        call_id: 42,
        from: UserId(2),
        from_name: "bob".into(),
        channel: Some("general".into()),
        ended: false,
    });
    assert!(!state.call_invite_open().expect("shown").ended);

    assert!(
        !state.mark_call_invite_ended(7),
        "a call we hold no invite for is not ours to mark"
    );
    assert!(state.mark_call_invite_ended(42));
    let invite = state.call_invite_open().expect("still on screen");
    assert!(
        invite.ended,
        "the popup stays up - it just can no longer join anything"
    );
    assert_eq!(state.call_invite_for(42).map(|i| i.from), Some(UserId(2)));
}

/// @requirement AC-188
#[test]
fn a_hosts_invitees_are_told_when_the_call_ends() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());
    state.on_call_invite_sent(UserId(3), "carol".into());

    assert_eq!(
        state.call_invitees_awaiting_answer(),
        vec![UserId(3)],
        "only the one who has not answered yet"
    );
    state.on_call_invite_rejected(UserId(3));
    assert!(
        state.call_invitees_awaiting_answer().is_empty(),
        "an answered invite needs no CallEnd of its own"
    );
}

/// Our own mute reads on the roster exactly like anyone else's - the row
/// answers "can this person be heard", whoever silenced them
/// (`docs/SPEC.md` "Live voice calls").
///
/// @requirement AC-170
#[test]
fn muting_ourselves_shows_on_the_roster_like_any_other_mute() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_call(1, Some("general".into()), UserId(1));
    state.on_call_participant_joined(UserId(2), "bob".into());
    assert!(!rendered_rows(&state).join("\n").contains("MUTED"));

    // What the session writes back once our own toggle has been applied.
    state.set_call_muted(true);
    assert!(
        rendered_rows(&state).join("\n").contains("MUTED"),
        "our own row says so"
    );

    // And a peer announcing their own mute reads the same, without any
    // host authority behind it.
    state.set_call_muted(false);
    state.set_call_member_self_muted(UserId(2), true);
    // The modal's own row for bob, not the sidebar entry with the same name.
    let bob_row = rendered_rows(&state)
        .into_iter()
        .find(|r| r.contains("bob") && r.contains("IN CALL"))
        .expect("bob's roster row");
    assert!(bob_row.contains("MUTED"), "{bob_row:?}");
}

// ---------------------------------------------------------------------
// Muting a person's voice messages (SPEC.md Functionality #16)
// ---------------------------------------------------------------------

/// @requirement AC-195
#[test]
fn mute_voice_command_produces_a_mute_action() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/mute-voice bob");
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(
        action,
        Some(UiAction::SetVoiceMuted {
            nickname: "bob".into(),
            muted: true
        })
    );
    assert!(state.input.is_empty(), "a recognized command clears the bar");
    assert!(
        state.muted_voice.contains("bob"),
        "applied locally right away, so a stream starting this instant sees it"
    );
    let (notice, ok) = state.status_notice.clone().expect("must confirm");
    assert!(notice.contains("bob") && notice.contains("muted"), "{notice}");
    assert!(ok);
}

/// @requirement AC-195
#[test]
fn unmute_voice_command_produces_an_unmute_action() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_muted_voice(["bob".to_string()].into_iter().collect());

    type_str(&mut state, "/unmute-voice bob");
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(
        action,
        Some(UiAction::SetVoiceMuted {
            nickname: "bob".into(),
            muted: false
        })
    );
    assert!(!state.muted_voice.contains("bob"));
}

/// @requirement AC-195
#[test]
fn a_bare_mute_voice_command_lists_who_is_muted() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_muted_voice(["bob".to_string(), "alice".to_string()].into_iter().collect());

    type_str(&mut state, "/mute-voice");
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(action, None, "listing produces no action to persist");
    let (notice, _) = state.status_notice.clone().expect("must list");
    assert!(
        notice.contains("alice") && notice.contains("bob"),
        "the bare command is the only place that answers 'who have I muted?': {notice}"
    );
    assert!(state.input.is_empty());
}

/// @requirement AC-195
#[test]
fn a_bare_mute_voice_command_with_nothing_muted_says_so() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/mute-voice");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let (notice, _) = state.status_notice.clone().expect("must say something");
    assert!(notice.contains("no voices muted"), "{notice}");
}

/// Muting someone already muted must not rewrite the settings file for a
/// no-op - it produces a notice and no action at all.
/// @requirement AC-195
#[test]
fn re_muting_an_already_muted_nickname_produces_no_action() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_muted_voice(["bob".to_string()].into_iter().collect());

    type_str(&mut state, "/mute-voice bob");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let (notice, _) = state.status_notice.clone().expect("must say so");
    assert!(notice.contains("already muted"), "{notice}");

    type_str(&mut state, "/unmute-voice alice");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let (notice, _) = state.status_notice.clone().expect("must say so");
    assert!(notice.contains("not muted"), "{notice}");
}

/// A nickname never contains whitespace, so a second word is a typo rather
/// than part of the name - muting the first word of it silently would be
/// worse than refusing.
/// @requirement AC-195
#[test]
fn mute_voice_refuses_more_than_one_word() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/mute-voice bob carol");
    assert_eq!(press(&mut state, KeyCode::Enter), None);

    assert!(state.muted_voice.is_empty());
    let (notice, ok) = state.status_notice.clone().expect("must refuse");
    assert!(notice.contains("one nickname"), "{notice}");
    assert!(!ok);
}

/// These are the first commands in this app that take an argument, so the
/// thing most likely to break is the unknown-command catch-all swallowing
/// them. Also guards the neighbouring commands from the new prefix match.
/// @requirement AC-195
#[test]
fn the_mute_commands_are_not_swallowed_as_unknown_commands() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/mute-voice bob");
    press(&mut state, KeyCode::Enter);
    let (notice, _) = state.status_notice.clone().unwrap();
    assert!(
        !notice.contains("unknown command"),
        "must be handled before the catch-all: {notice}"
    );

    // A near-miss still has to reach the catch-all.
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/mute-voic bob");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let (notice, _) = state.status_notice.clone().unwrap();
    assert!(notice.contains("unknown command"), "{notice}");

    // `/mute-voice` must not capture a shorter command that merely
    // shares its prefix. `/mute` itself no longer exists (muting your own
    // microphone is `m` on the call roster), so it reaches the
    // unknown-command notice - which is exactly the check that matters:
    // the prefix match did not swallow it.
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/mute");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let (notice, _) = state.status_notice.clone().unwrap();
    assert!(notice.contains("unknown command"), "{notice}");
}

/// @requirement AC-196
#[test]
fn suppress_playback_from_covers_both_the_trust_gate_and_a_mute() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    assert!(!state.suppress_playback_from(UserId(2)));

    state.set_muted_voice(["bob".to_string()].into_iter().collect());
    assert!(state.suppress_playback_from(UserId(2)), "muted");
    assert!(!state.suppress_playback_from(UserId(3)), "untouched");

    // The trust gate still suppresses on its own, mute or no mute.
    state.push_identity_review(
        UserId(3),
        "carol".into(),
        "carol's key changed unexpectedly".into(),
        static_mismatch(),
    );
    assert!(state.suppress_playback_from(UserId(3)));
}

/// @requirement AC-196
#[test]
fn a_muted_peer_suppresses_playback_but_not_logging() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_muted_voice(["bob".to_string()].into_iter().collect());

    // The stream still opens a row and still finalizes into a replayable
    // Voice entry - muting is only ever about live playback.
    state.on_channel_stream_start("general", UserId(2), "bob".into(), 7);
    state.on_channel_stream_finished("general", UserId(2), 7, 1200, vec![0u8; 64]);

    let log = &state.channels[state.selected_channel].log;
    let has_voice = log
        .iter()
        .any(|e| matches!(&e.body, MessageBody::Voice { duration_ms, .. } if *duration_ms == 1200));
    assert!(
        has_voice,
        "a muted message must still be in the log to replay: {log:?}"
    );
}

/// @requirement AC-198
#[test]
fn muting_an_offline_or_unknown_nickname_is_accepted() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    // "dave" is not in `known_users` at all.
    type_str(&mut state, "/mute-voice dave");
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(
        action,
        Some(UiAction::SetVoiceMuted {
            nickname: "dave".into(),
            muted: true
        }),
        "a mute is by nickname, so it can be set before they ever connect"
    );
    assert!(state.muted_voice.contains("dave"));

    // And it takes effect the moment someone by that name shows up.
    state.on_user_joined("general", user(4, "dave"));
    assert!(state.is_voice_muted(UserId(4)));
}

/// A peer we hold no UserInfo for has no name to have matched, so is never
/// muted - the lookup must not panic or guess.
/// @requirement AC-198
#[test]
fn an_unknown_user_id_is_never_reported_as_muted() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_muted_voice(["bob".to_string()].into_iter().collect());
    assert!(!state.is_voice_muted(UserId(99)));
}

// ---------------------------------------------------------------------
// /daemon (SPEC.md "Running in background mode")
// ---------------------------------------------------------------------

/// @requirement AC-203
#[test]
fn slash_daemon_hands_the_session_back_when_running_as_one() {
    let mut state = joined_general_with(vec![]);
    state.daemon_mode = true;

    type_str(&mut state, "/daemon");
    assert_eq!(press(&mut state, KeyCode::Enter), Some(UiAction::Detach));
    assert!(state.input.is_empty());
}

/// A foreground session cannot background itself - that would mean
/// re-parenting a live process along with its open TCP control connection
/// and UDP peer links - so it explains itself rather than half-working.
/// @requirement AC-203
#[test]
fn slash_daemon_explains_itself_outside_daemon_mode() {
    let mut state = joined_general_with(vec![]);
    assert!(!state.daemon_mode, "a plain client is not a daemon");

    type_str(&mut state, "/daemon");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
    let (notice, ok) = state.status_notice.clone().expect("must explain");
    assert!(notice.contains("not running as a daemon"), "{notice}");
    assert!(!ok);
}

// ---------------------------------------------------------------------
// Delivery acknowledgments: the details popup and the routing behind it
// (US-041)
// ---------------------------------------------------------------------

/// Sends one text into `general` and leaves focus on the message log, on
/// that row - what `i` acts on.
fn sent_and_selected(members: Vec<aloo::proto::UserInfo>, text: &str) -> (UiState, u64) {
    let mut state = joined_general_with(members);
    type_str(&mut state, text);
    let msg_id = match press(&mut state, KeyCode::Enter).expect("a send was produced") {
        UiAction::SendChannelText { msg_id, .. } => msg_id,
        other => panic!("expected SendChannelText, got {other:?}"),
    };
    state.focus = Focus::Messages;
    state.message_selected = state.channels[0].log.len() - 1;
    (state, msg_id)
}

/// @requirement AC-232
#[test]
fn i_opens_the_details_of_the_selected_message() {
    let (mut state, _) = sent_and_selected(vec![user(2, "bob")], "status check");
    assert!(
        !rendered_rows(&state).iter().any(|r| r.contains("Message details")),
        "nothing is open before the key is pressed"
    );

    assert_eq!(press(&mut state, KeyCode::Char('i')), None);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("Message details")),
        "i opens the popup: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains(SENT_AT_LABEL)),
        "it opens with when the message was sent: {rows:?}"
    );
}

/// One line per recipient, each carrying that recipient's own state -
/// which is the point of the popup over the row's single aggregate arrow.
/// @requirement AC-232
#[test]
fn the_details_popup_names_every_recipient_with_its_own_state() {
    let (mut state, msg_id) =
        sent_and_selected(vec![user(2, "bob"), user(3, "carol")], "status check");
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    press(&mut state, KeyCode::Char('i'));

    let rows = rendered_rows(&state);
    let names = |name: &str, label: &str| {
        rows.iter()
            .any(|r| r.contains(name) && r.contains(label))
    };
    assert!(
        names("bob", DELIVERED_LABEL),
        "the one who acknowledged it reads DELIVERED: {rows:?}"
    );
    assert!(
        names("carol", UNDELIVERED_LABEL),
        "the one who has not reads UNDELIVERED: {rows:?}"
    );
    // The same arrow, in the same colours, as the row it was opened from.
    assert!(
        rows.iter()
            .any(|r| r.contains(&format!("{DELIVERY_ARROW} {DELIVERED_LABEL}"))),
        "each status is written with the arrow: {rows:?}"
    );
}

/// @requirement AC-232
#[test]
fn the_details_popup_absorbs_other_keys_and_closes_on_escape() {
    let (mut state, _) = sent_and_selected(vec![user(2, "bob")], "one");
    push_n_channel_texts(&mut state, 3);
    state.message_selected = 0;
    press(&mut state, KeyCode::Char('i'));

    assert_eq!(press(&mut state, KeyCode::Down), None);
    assert_eq!(
        state.message_selected, 0,
        "a key the popup does not handle is absorbed, not acted on underneath it"
    );
    assert!(
        rendered_rows(&state).iter().any(|r| r.contains("Message details")),
        "and does not close it either"
    );

    press(&mut state, KeyCode::Esc);
    assert!(
        !rendered_rows(&state).iter().any(|r| r.contains("Message details")),
        "Escape closes it"
    );

    // `i` is a toggle, same as the key that opened it.
    press(&mut state, KeyCode::Char('i'));
    press(&mut state, KeyCode::Char('i'));
    assert!(
        !rendered_rows(&state).iter().any(|r| r.contains("Message details")),
        "i closes it again"
    );
}

/// A row with nothing to report says so, rather than opening an empty list
/// that reads like a message nobody received.
/// @requirement AC-232
#[test]
fn an_incoming_message_has_no_delivery_information_to_show() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hello".into()),
    );
    state.focus = Focus::Messages;
    state.message_selected = 0;
    press(&mut state, KeyCode::Char('i'));

    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains(NO_DELIVERY_INFO)),
        "it says there is nothing to report: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains(RECEIVED_AT_LABEL)),
        "and calls the time what it actually is: {rows:?}"
    );
}

/// @requirement AC-230
#[test]
fn only_messages_this_client_sent_carry_an_indicator() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    // One of every other row kind that can share a log with a sent text.
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hello".into()),
    );
    state.on_user_joined("general", user(3, "carol"));
    state.log_own_file_offer_channel("general", 7, "notes.txt".into(), 10, None);
    type_str(&mut state, "mine");
    press(&mut state, KeyCode::Enter);

    let log = &state.channels[0].log;
    let tracked: Vec<bool> = log.iter().map(|e| e.delivery_status().is_some()).collect();
    assert_eq!(
        tracked,
        vec![false, false, false, true],
        "only the text this client sent tracks a delivery: {:?}",
        log.iter().map(|e| &e.body).collect::<Vec<_>>()
    );

    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("bob: hello")),
        "an incoming message keeps the plain separator: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains(&format!("me {DELIVERY_ARROW} mine"))),
        "and a sent one reads with the arrow: {rows:?}"
    );
}

/// An acknowledgement names a peer and an id, never a conversation, so the
/// id has to be enough to find the row wherever it lives.
/// @requirement TB-231
#[test]
fn an_acknowledgement_finds_its_row_in_any_conversation() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "to the channel");
    let channel_id = match press(&mut state, KeyCode::Enter).expect("a send") {
        UiAction::SendChannelText { msg_id, .. } => msg_id,
        other => panic!("expected SendChannelText, got {other:?}"),
    };
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens bob's room
    state.focus = Focus::Input;
    type_str(&mut state, "and to bob");
    let dm_id = match press(&mut state, KeyCode::Enter).expect("a send") {
        UiAction::SendDirectText { msg_id, .. } => msg_id,
        other => panic!("expected SendDirectText, got {other:?}"),
    };
    assert_ne!(
        channel_id, dm_id,
        "ids are handed out across the whole session, not per conversation"
    );

    state.mark_delivered(UserId(2), dm_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.private_rooms[&UserId(2)].log[0].delivery_status(),
        Some(DeliveryStatus::All)
    );
    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::None),
        "the channel row is a different message and is untouched"
    );

    state.mark_delivered(UserId(2), channel_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::All)
    );
}

/// Acknowledgements arrive off a retrying transport and after reconnects,
/// so a repeat and a stale id both have to be ordinary no-ops.
/// @requirement TB-231
#[test]
fn marking_delivered_is_idempotent_and_ignores_unknown_ids() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    type_str(&mut state, "hello all");
    let msg_id = match press(&mut state, KeyCode::Enter).expect("a send") {
        UiAction::SendChannelText { msg_id, .. } => msg_id,
        other => panic!("expected SendChannelText, got {other:?}"),
    };

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::Some),
        "a repeated acknowledgement from one recipient does not count twice"
    );

    // An id from before a reconnect, and a peer who was never a recipient.
    state.mark_delivered(UserId(2), msg_id + 999, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    state.mark_delivered(UserId(9), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::Some)
    );
}

/// A voice message and a file transfer are messages too - their rows carry
/// the same arrow, in the same place, as a text row.
/// @requirement AC-230
#[test]
fn a_voice_row_and_a_file_row_carry_the_arrow_too() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let (voice_id, voice_delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_voice_stream_start_channel("general", 7, Some(voice_delivery));
    let (file_id, file_delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_file_offer_channel("general", 8, "notes.txt".into(), 10, Some(file_delivery));

    let statuses: Vec<Option<DeliveryStatus>> = state.channels[0]
        .log
        .iter()
        .map(|e| e.delivery_status())
        .collect();
    assert_eq!(
        statuses,
        vec![Some(DeliveryStatus::None), Some(DeliveryStatus::None)],
        "both start undelivered, like any other message"
    );

    // The rows read `me -> <body>` rather than `me: <body>`.
    let rows = rendered_rows(&state);
    assert_eq!(
        rows.iter()
            .filter(|r| r.contains(&format!("me {DELIVERY_ARROW} ")))
            .count(),
        2,
        "both rows carry the arrow: {rows:?}"
    );

    state.mark_delivered(UserId(2), voice_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::All),
        "the voice row turns green when its recipient decoded it"
    );
    assert_eq!(
        state.channels[0].log[1].delivery_status(),
        Some(DeliveryStatus::None),
        "and the file row is a different message, untouched"
    );

    state.mark_delivered(UserId(2), file_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.channels[0].log[1].delivery_status(),
        Some(DeliveryStatus::All)
    );
}

/// A live voice row becomes a finished one in place - the same row, so it
/// keeps the delivery it was already tracking.
/// @requirement AC-230
#[test]
fn a_voice_row_keeps_its_delivery_when_the_stream_finishes() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let (msg_id, delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_voice_stream_start_channel("general", 7, Some(delivery));
    let me = state.own_id.expect("own id");

    state.on_channel_stream_finished("general", me, 7, 1200, vec![0; 8]);
    assert!(
        matches!(state.channels[0].log[0].body, MessageBody::Voice { .. }),
        "the placeholder was finalized in place"
    );
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::All),
        "finalizing must not lose which message this row is"
    );
}

/// A row that went out under the pad reports its delivery through the
/// pad's own proof-carrying acknowledgement, and nothing weaker - a plain
/// `DeliveryReceipt` is an unsigned payload naming a `msg_id`, which anyone
/// on the link can say.
///
/// @requirement AC-251
#[test]
fn a_pad_protected_row_ignores_a_plain_receipt_and_waits_for_the_pad_ack() {
    let (mut state, msg_id) = sent_and_selected(vec![user(2, "bob")], "under the pad");
    state.mark_awaiting_pad_ack(UserId(2), msg_id);

    let arrow_status = |s: &UiState| {
        s.channels[0]
            .log
            .iter()
            .find_map(|e| e.delivery.as_ref().map(|d| d.status()))
            .expect("the row tracks its own delivery")
    };

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    press(&mut state, KeyCode::Char('i'));
    assert!(
        rendered_rows(&state)
            .iter()
            .any(|r| r.contains(UNDELIVERED_LABEL)),
        "an unproven receipt must not be able to claim they read a pad-protected message"
    );
    assert_eq!(
        arrow_status(&state),
        DeliveryStatus::None,
        "so the arrow stays gray"
    );

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::PadAck);
    assert!(
        rendered_rows(&state)
            .iter()
            .any(|r| r.contains(DELIVERED_LABEL)),
        "the pad's own ack is what turns it green"
    );
    assert_eq!(arrow_status(&state), DeliveryStatus::All);
}

/// An ordinary row is unaffected - there is no pad behind it to insist on,
/// so its receipt is the only acknowledgement there ever was.
///
/// @requirement AC-251
#[test]
fn a_row_that_never_went_under_the_pad_still_answers_to_its_receipt() {
    let (mut state, msg_id) = sent_and_selected(vec![user(2, "bob")], "in the clear");

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    press(&mut state, KeyCode::Char('i'));
    assert!(
        rendered_rows(&state)
            .iter()
            .any(|r| r.contains(DELIVERED_LABEL))
    );
}

/// Consuming ordinarily implies decrypting, so a `Consumed` receipt sets
/// both. On a pad-protected leg that shortcut would hand the untrusted
/// path a way in through the back door, so it only ever records what the
/// pad ack has already established.
///
/// @requirement AC-251
#[test]
fn a_consumed_receipt_cannot_turn_a_pad_protected_row_green_on_its_own() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let (msg_id, delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_voice_stream_start_channel("general", 7, Some(delivery));
    state.mark_awaiting_pad_ack(UserId(2), msg_id);
    state.focus = Focus::Messages;
    state.message_selected = 0;

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Consumed, DeliveryProof::Receipt);
    press(&mut state, KeyCode::Char('i'));
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains(UNDELIVERED_LABEL)),
        "a Consumed receipt must not imply delivery here: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains(LISTENED_LABEL)),
        "and it must not claim they heard something they never proved receiving"
    );

    // Once the pad ack lands, a later replay receipt reads normally again.
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::PadAck);
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Consumed, DeliveryProof::Receipt);
    assert!(
        rendered_rows(&state)
            .iter()
            .any(|r| r.contains(LISTENED_LABEL)),
        "the pad ack proves receipt; what they then did with it is theirs to report"
    );
}

/// The details popup is the one place the extra state shows: a voice
/// message the recipient has actually heard, and a file they have on disk,
/// read differently from one merely decrypted (docs/PROTOCOL.md 7.2.1).
/// @requirement AC-236
#[test]
fn the_details_popup_distinguishes_heard_from_merely_decrypted() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let (msg_id, delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_voice_stream_start_channel("general", 7, Some(delivery));
    state.focus = Focus::Messages;
    state.message_selected = 0;

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    press(&mut state, KeyCode::Char('i'));
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains(DELIVERED_LABEL)),
        "decoded, but not heard: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains(LISTENED_LABEL)),
        "and it must not claim they heard it"
    );

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Consumed, DeliveryProof::Receipt);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains(LISTENED_LABEL)),
        "once they play it, the popup says so: {rows:?}"
    );
}

/// @requirement AC-236
#[test]
fn the_details_popup_says_saved_for_a_file_the_recipient_has_on_disk() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let (msg_id, delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_file_offer_channel("general", 8, "notes.txt".into(), 10, Some(delivery));
    state.focus = Focus::Messages;
    state.message_selected = 0;

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    press(&mut state, KeyCode::Char('i'));
    assert!(
        rendered_rows(&state).iter().any(|r| r.contains(DELIVERED_LABEL)),
        "they could read the offer"
    );

    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Consumed, DeliveryProof::Receipt);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains(SAVED_LABEL)),
        "and once the whole file is on their disk it says that instead: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains(LISTENED_LABEL)),
        "a file is saved, not listened to"
    );
}

/// A text message has no further state to reach, so it never grows one -
/// and the log's own arrow stays a three-state summary either way.
/// @requirement AC-236
#[test]
fn a_text_message_has_no_extra_state_and_the_arrow_is_unchanged_by_one() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "hello");
    let msg_id = match press(&mut state, KeyCode::Enter).expect("a send") {
        UiAction::SendChannelText { msg_id, .. } => msg_id,
        other => panic!("expected SendChannelText, got {other:?}"),
    };
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Consumed, DeliveryProof::Receipt);

    assert_eq!(
        state.channels[0].log[0].delivery_status(),
        Some(DeliveryStatus::All),
        "the arrow is about who has the message, not what they did with it"
    );
    state.focus = Focus::Messages;
    state.message_selected = 0;
    press(&mut state, KeyCode::Char('i'));
    let rows = rendered_rows(&state);
    assert!(rows.iter().any(|r| r.contains(DELIVERED_LABEL)));
    assert!(
        !rows.iter().any(|r| r.contains(LISTENED_LABEL) || r.contains(SAVED_LABEL)),
        "there is no such thing as listening to, or saving, a text message: {rows:?}"
    );
}

/// A muted sender's clip decodes but is not played, so the debt to tell
/// them moves onto the row - and replaying it later is what pays it.
/// @requirement AC-236
#[test]
fn replaying_a_clip_that_was_never_heard_pays_its_sender() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_stream_start("general", UserId(2), "bob".into(), 7);
    state.owe_replay_receipt(UserId(2), 7, Some(99));
    state.on_channel_stream_finished("general", UserId(2), 7, 1200, vec![0; 8]);
    state.focus = Focus::Messages;
    state.message_selected = 0;

    match press(&mut state, KeyCode::Enter).expect("Enter replays a voice row") {
        UiAction::ReplayVoice {
            from,
            owed_receipt,
            ..
        } => {
            assert_eq!(from, UserId(2), "the debt is owed to whoever sent it");
            assert_eq!(owed_receipt, Some(99));
        }
        other => panic!("expected ReplayVoice, got {other:?}"),
    }

    // Replaying again owes nothing: hearing it twice is still hearing it.
    match press(&mut state, KeyCode::Enter).expect("still replayable") {
        UiAction::ReplayVoice { owed_receipt, .. } => assert_eq!(owed_receipt, None),
        other => panic!("expected ReplayVoice, got {other:?}"),
    }
}

/// The ordinary case: a clip that played on arrival owes nothing, so
/// replaying it says nothing to anybody.
/// @requirement AC-236
#[test]
fn replaying_a_clip_that_was_already_heard_owes_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_stream_start("general", UserId(2), "bob".into(), 7);
    state.on_channel_stream_finished("general", UserId(2), 7, 1200, vec![0; 8]);
    state.focus = Focus::Messages;
    state.message_selected = 0;

    match press(&mut state, KeyCode::Enter).expect("Enter replays a voice row") {
        UiAction::ReplayVoice { owed_receipt, .. } => assert_eq!(owed_receipt, None),
        other => panic!("expected ReplayVoice, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// The call modal's three columns (docs/SPEC.md "Live voice calls")
// ---------------------------------------------------------------------

/// The title a channel call's modal carries, and how these tests find its
/// box on screen.
fn call_modal_title(channel: &str) -> String {
    format!("Call \u{2014} #{channel}")
}

/// A call in `general` hosted by us, with one row per name given.
fn hosting_a_call_with(names: &[&str]) -> UiState {
    let members: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| user(i as u64 + 2, name))
        .collect();
    let mut state = joined_general_with(members);
    state.begin_call(1, Some("general".into()), UserId(1));
    for (i, name) in names.iter().enumerate() {
        state.on_call_participant_joined(UserId(i as u64 + 2), (*name).to_string());
    }
    state
}

/// The modal is as narrow as the call in it allows: sizing for the widest
/// roster a call could ever hold would leave a block of blank columns
/// down the middle of every row of an ordinary two-person one.
///
/// @requirement AC-175
#[test]
fn the_call_modal_narrows_to_the_names_actually_in_the_call() {
    // Longer than our own `me (you) (host)` row, which is otherwise the
    // widest name in either call and would make the two come out equal.
    let short = hosting_a_call_with(&["bo"]);
    let long = hosting_a_call_with(&["bartholomew-the-longer"]);

    let short_width = popup_rect(&buffer_at(&short, 100, 30), &call_modal_title("general")).2;
    let long_width = popup_rect(&buffer_at(&long, 100, 30), &call_modal_title("general")).2;

    assert!(
        short_width < long_width,
        "a call between short names needs a narrower modal than one with a long name \
         ({short_width} vs {long_width})"
    );
    assert!(
        long_width < 100,
        "and neither takes the whole screen ({long_width})"
    );
}

/// All three columns line up down the list, and the meters are the one
/// that lines up against the modal's own right edge rather than against
/// whatever the labels before it came to.
///
/// @requirement AC-175
#[test]
fn the_roster_columns_line_up_and_the_meters_sit_flush_right() {
    let mut state = hosting_a_call_with(&["bo", "bartholomew"]);
    // One row carries a second label and one does not - the case a
    // per-row label width would slide out of line.
    state.set_call_member_host_muted(UserId(2), true);

    let buffer = buffer_at(&state, 100, 30);
    let (x, _, width, _) = popup_rect(&buffer, &call_modal_title("general"));
    let body = popup_body(&buffer, &call_modal_title("general"));
    let roster: Vec<&String> = body
        .iter()
        .filter(|r| r.contains(['\u{2591}', '\u{2588}']))
        .collect();
    assert_eq!(roster.len(), 3, "one row per participant: {body:?}");

    // Every meter ends on the last column inside the border. Counted in
    // characters, not bytes: the meter glyphs are multi-byte and exactly
    // one cell each.
    for row in &roster {
        let chars: Vec<char> = row.chars().collect();
        let last_bar = chars
            .iter()
            .rposition(|c| matches!(c, '\u{2591}' | '\u{2588}'))
            .expect("a meter on this row");
        assert_eq!(
            last_bar + 1,
            chars.len(),
            "the meter runs to the modal's inner right edge: {row:?}"
        );
    }

    // And the labels all start in one column, whatever each name's length.
    let label_columns: Vec<usize> = roster
        .iter()
        .map(|r| {
            let byte = r
                .find("IN CALL")
                .unwrap_or_else(|| panic!("every row is IN CALL here: {r:?}"));
            r[..byte].chars().count()
        })
        .collect();
    assert!(
        label_columns.iter().all(|c| *c == label_columns[0]),
        "the label column is the same on every row: {label_columns:?} in {roster:?}"
    );

    // Sanity: the box really is narrower than the frame it was given, so
    // the flush-right assertion above is about the modal and not about
    // the screen.
    assert!(x > 0 && width < 100, "the modal is centered, not full width");
}

// ---------------------------------------------------------------------
// What the details popup says about a message's encryption
// (docs/SPEC.md "Delivery acknowledgments")
// ---------------------------------------------------------------------

/// The one thing a DM to one person can always name: the scheme its
/// envelope was built with, and the key it was sealed to.
/// @requirement AC-242
#[test]
fn the_details_popup_names_the_scheme_and_the_key_a_dm_was_sealed_to() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    // Opened the way a user does: cursor on bob in the sidebar, Enter.
    state.focus = Focus::Sidebar;
    state.sidebar_selected = 0;
    press(&mut state, KeyCode::Enter);
    type_str(&mut state, "hello");
    press(&mut state, KeyCode::Enter);
    state.focus = Focus::Messages;
    state.message_selected = state.private_rooms[&UserId(2)].log.len() - 1;
    press(&mut state, KeyCode::Char('i'));

    let key_id = aloo::crypto::short_fingerprint_der(&state.known_users[&UserId(2)].public_key_der);
    let rows = rendered_rows_at(&state, 140, 30);
    assert!(
        rows.iter()
            .any(|r| r.contains(ENCRYPTION_LABEL) && r.contains("ML-KEM-1024")),
        "the scheme is named by its mechanism, not by the my_key tag: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains(KEY_LABEL) && r.contains(&key_id)),
        "and the key it was sealed to, short enough to read ({key_id}): {rows:?}"
    );
    assert_eq!(
        key_id.len(),
        aloo::crypto::SHORT_FINGERPRINT_HEX,
        "a short representation, not a full SHA-256"
    );
}

/// A channel send is sealed once per member with that member's own key,
/// so there is no single key to name and the popup says as much rather
/// than picking one.
/// @requirement AC-242
#[test]
fn a_channel_send_to_several_people_names_no_single_key() {
    let (mut state, _) = sent_and_selected(
        vec![pq_hybrid_user(2, "bob"), pq_hybrid_user(3, "carol")],
        "everyone",
    );
    press(&mut state, KeyCode::Char('i'));

    let rows = rendered_rows_at(&state, 140, 30);
    assert!(
        rows.iter()
            .any(|r| r.contains(KEY_LABEL) && r.contains(KEY_PER_RECIPIENT)),
        "one key id would be a lie about the other recipients: {rows:?}"
    );
}

/// A line this client wrote itself never travelled, so there is nothing
/// to report about how it was protected.
/// @requirement AC-242
#[test]
fn a_presence_notice_reports_no_encryption_at_all() {
    let mut state = joined_general_with(vec![]);
    state.on_user_joined("general", user(2, "bob"));
    state.focus = Focus::Messages;
    state.message_selected = state.channels[0].log.len() - 1;
    press(&mut state, KeyCode::Char('i'));

    let rows = rendered_rows_at(&state, 140, 30);
    assert!(
        rows.iter().any(|r| r.contains(NO_CRYPTO_INFO)),
        "a presence line is not an encrypted message: {rows:?}"
    );
}

/// Under an OTP session the pad is what actually protects the content, so
/// the popup reports the pad position this message spent and the key file
/// it came out of (`docs/PROTOCOL.md` §16) - not the envelope underneath.
/// @requirement AC-243
#[test]
fn an_otp_message_reports_the_pad_position_and_key_file_it_used() {
    use aloo::client::otp_cli::ContactDetail;

    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.focus = Focus::Sidebar;
    state.sidebar_selected = 0;
    press(&mut state, KeyCode::Enter);
    state.mark_otp_active(UserId(2));
    // The pre-spend snapshot: four messages already sent, 480 bytes of pad
    // already consumed. The message about to be logged is therefore
    // sequence 5, starting at offset 480.
    state.set_otp_key_status(
        UserId(2),
        otp_status(ContactDetail {
            enc_sequence: 4,
            enc_offset: 480,
            enc_key_remaining: 2_000_000,
            dec_sequence: 9,
            dec_offset: 900,
            dec_key_remaining: 2_000_000,
        }),
    );

    type_str(&mut state, "under the pad");
    press(&mut state, KeyCode::Enter);
    state.focus = Focus::Messages;
    state.message_selected = state.private_rooms[&UserId(2)].log.len() - 1;
    press(&mut state, KeyCode::Char('i'));

    let rows = rendered_rows_at(&state, 160, 30);
    let says = |label: &str, value: &str| {
        rows.iter()
            .any(|r| r.contains(label) && r.contains(value))
    };
    assert!(
        rows.iter()
            .any(|r| r.contains(ENCRYPTION_LABEL) && r.contains("one-time pad")),
        "the pad is what protected it: {rows:?}"
    );
    assert!(says(KEY_SEQ_LABEL, "5"), "this message's sequence: {rows:?}");
    assert!(
        says(KEY_OFFSET_LABEL, "480"),
        "where its key bytes start: {rows:?}"
    );
    assert!(
        says(KEY_FILE_LABEL, &format!("{TEST_OTP_CONTACT}_enc.key")),
        "and which key file they came out of: {rows:?}"
    );
}

/// The details popup's whole job is to say how *this* message was
/// encrypted, so under the pad it must name which of §16.2's two framings
/// carried it - never assume the usual one. The peer's announced key is
/// what decides it: this client's own is always a real keybundle, so a
/// peer who announced one is `PqWrapped` and a peer who did not is
/// `Direct`.
/// @requirement AC-242, AC-082
#[test]
fn the_details_popup_names_which_pad_framing_carried_the_message() {
    use aloo::client::otp_cli::ContactDetail;
    use aloo::proto::UserInfo;

    let open_details = |peer: UserInfo| {
        let id = peer.id;
        let mut state = joined_general_with(vec![peer]);
        state.focus = Focus::Sidebar;
        state.sidebar_selected = 0;
        press(&mut state, KeyCode::Enter);
        state.mark_otp_active(id);
        state.set_otp_key_status(
            id,
            otp_status(ContactDetail {
                enc_sequence: 0,
                enc_offset: 0,
                enc_key_remaining: 2_000_000,
                dec_sequence: 0,
                dec_offset: 0,
                dec_key_remaining: 2_000_000,
            }),
        );
        type_str(&mut state, "under the pad");
        press(&mut state, KeyCode::Enter);
        state.focus = Focus::Messages;
        state.message_selected = state.private_rooms[&id].log.len() - 1;
        press(&mut state, KeyCode::Char('i'));
        rendered_rows_at(&state, 160, 30)
    };

    let wrapped = open_details(pq_hybrid_user(2, "bob"));
    assert!(
        wrapped
            .iter()
            .any(|r| r.contains(ENCRYPTION_LABEL) && r.contains("inside the pq_hybrid envelope")),
        "a peer who announced a keybundle is wrapped: {wrapped:?}"
    );

    let direct = open_details(pad_only_user(2, "bob"));
    assert!(
        direct
            .iter()
            .any(|r| r.contains(ENCRYPTION_LABEL) && r.contains("carrying the message directly")),
        "a peer who announced none has no envelope under the pad: {direct:?}"
    );
    assert!(
        !direct
            .iter()
            .any(|r| r.contains("inside the pq_hybrid envelope")),
        "and must not claim one: {direct:?}"
    );
}

/// The receiving side reads its own direction's figures and its own key
/// file - the two pads are independent, and reporting the sending one on
/// an incoming row would name key material that message never touched.
/// @requirement AC-243
#[test]
fn an_incoming_otp_message_reports_the_decryption_pad() {
    use aloo::client::otp_cli::ContactDetail;

    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.focus = Focus::Sidebar;
    state.sidebar_selected = 0;
    press(&mut state, KeyCode::Enter);
    state.mark_otp_active(UserId(2));
    state.set_otp_key_status(
        UserId(2),
        otp_status(ContactDetail {
            enc_sequence: 4,
            enc_offset: 480,
            enc_key_remaining: 2_000_000,
            dec_sequence: 9,
            dec_offset: 900,
            dec_key_remaining: 2_000_000,
        }),
    );
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.focus = Focus::Messages;
    state.message_selected = state.private_rooms[&UserId(2)].log.len() - 1;
    press(&mut state, KeyCode::Char('i'));

    let rows = rendered_rows_at(&state, 160, 30);
    assert!(
        rows.iter().any(|r| r.contains(KEY_SEQ_LABEL) && r.contains("10")),
        "the next sequence on the receiving pad: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|r| r.contains(KEY_OFFSET_LABEL) && r.contains("900")),
        "and that pad's own offset: {rows:?}"
    );
    assert!(
        rows.iter()
            .any(|r| r.contains(KEY_FILE_LABEL) && r.contains(&format!("{TEST_OTP_CONTACT}_dec.key"))),
        "read from the decryption key, not the encryption one: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// A popup replaces what is behind it (docs/SPEC.md "Connected UI")
// ---------------------------------------------------------------------

/// Every popup owns the cells it covers: whatever the view behind it drew
/// there is gone, not showing through around the popup's own words.
/// Checked by filling the message log with a marker no chrome contains and
/// looking for it inside each popup's own border.
///
/// One test over every popup rather than one each: the property is the
/// same for all of them, and a popup added without a `Clear` is exactly
/// the regression worth catching here.
/// @requirement AC-237
#[test]
fn no_popup_shows_the_view_behind_it() {
    let mismatch = || IdentityCase::StaticMismatch {
        new_public_key_der: vec![9, 9, 9],
        previous_public_key_der: vec![1, 1, 1],
    };
    let offer = || PendingFileOffer {
        from: UserId(2),
        from_name: "bob".into(),
        filename: "photo.png".into(),
        size: 2048,
        stream_id: 7,
        channel: None,
        otp_contact_name: None,
    };

    /// One popup under test: the title its border carries, and what opens
    /// it. The lifetime is what lets an opener borrow the two builders
    /// above rather than each repeating their literals.
    type PopupCase<'a> = (&'a str, Box<dyn Fn(&mut UiState) + 'a>);

    let cases: Vec<PopupCase> = vec![
        (
            HELP_POPUP_TITLE,
            Box::new(|s: &mut UiState| s.help_open = true),
        ),
        (
            "Identity review: bob",
            Box::new(|s: &mut UiState| {
                s.begin_identity_review(UserId(2), "bob".into(), mismatch());
                s.reveal_identity_review(UserId(2), "bob's key changed".into());
            }),
        ),
        (
            "Incoming file from bob",
            Box::new(move |s: &mut UiState| {
                s.push_file_offer(offer());
            }),
        ),
        (
            "Join or create a channel",
            Box::new(|s: &mut UiState| {
                ctrl(s, KeyCode::Char('j'));
            }),
        ),
        (
            "Public channels",
            Box::new(|s: &mut UiState| {
                type_str(s, "/channels");
                press(s, KeyCode::Enter);
            }),
        ),
        (
            "Message details",
            Box::new(|s: &mut UiState| {
                s.focus = Focus::Messages;
                press(s, KeyCode::Char('i'));
            }),
        ),
    ];

    for (title, open) in cases {
        let mut state = state_with_marker_behind();
        assert!(
            rendered_rows(&state)
                .iter()
                .any(|r| r.contains(BEHIND_MARKER)),
            "the marker must be on screen before {title:?} opens"
        );

        open(&mut state);
        let buffer = buffer_at(&state, 100, 30);
        let body = popup_body(&buffer, title);
        assert!(
            !body.is_empty(),
            "{title:?} should have opened, and have a body"
        );
        assert!(
            !body.iter().any(|r| r.contains(BEHIND_MARKER)),
            "{title:?} let the view behind it show through: {body:?}"
        );
    }
}

// ---------------------------------------------------------------------
// The help overlay's two columns (docs/SPEC.md Functionality #7)
// ---------------------------------------------------------------------

/// Every description in the whole page starts in the same column, and a
/// description too long for the width it has wraps back into that column
/// rather than under the keys.
/// @requirement TB-108
#[test]
fn help_descriptions_all_start_in_one_column_and_wrap_back_into_it() {
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    // Narrow enough that the longest descriptions have to wrap, wide
    // enough that the column itself is not being squeezed. Read inside
    // the overlay's own border, so a column figure is a column of the
    // page rather than of the screen.
    let rows = popup_body(&buffer_at(&state, 90, 40), HELP_POPUP_TITLE);

    // The column is wherever the widest command leaves it - read off the
    // rendered page rather than assumed, so the assertion is about
    // alignment and not about one particular figure.
    let column = |needle: &str| -> usize {
        let row = rows
            .iter()
            .find(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("no row contains {needle:?}: {rows:?}"));
        let byte = row.find(needle).expect("just found it");
        row[..byte].chars().count()
    };

    let ctrl_j = column("join/create");
    for description in ["list every public channel", "leave the selected channel tab"] {
        assert_eq!(
            column(description),
            ctrl_j,
            "{description:?} must start in the same column as every other description"
        );
    }

    // The `[  /  ]` entry is far too long for one line here, so the row
    // straight after it is a continuation of its description - and that is
    // what proves a wrap lands in the column rather than under the keys.
    let first = rows
        .iter()
        .position(|r| r.contains("move between the channel selector"))
        .expect("the first entry is on the first screenful");
    let continuation = &rows[first + 1];
    assert!(
        !continuation.trim().is_empty(),
        "the entry should have wrapped onto the next row: {continuation:?}"
    );
    assert_eq!(
        continuation.chars().take_while(|c| *c == ' ').count(),
        ctrl_j,
        "a wrapped line falls in the description column, not under the keys"
    );
}

/// The first column is reserved for commands and sized by the longest one,
/// so no command is ever pushed into the description column.
/// @requirement TB-108
#[test]
fn the_help_keys_column_is_as_wide_as_the_longest_command() {
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    let rows = popup_body(&buffer_at(&state, 120, 60), HELP_POPUP_TITLE);
    let joined = rows.join("\n");

    // The longest command in the page, and a short one: both keep their
    // whole text in the first column, and both descriptions line up.
    assert!(
        joined.contains("/unmute-voice <nickname>"),
        "the longest command is not clipped: {rows:?}"
    );
    let column = |needle: &str| -> usize {
        let row = rows
            .iter()
            .find(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("no row contains {needle:?}: {rows:?}"));
        row[..row.find(needle).unwrap()].chars().count()
    };
    assert_eq!(
        column("undo it; either"),
        column("join/create"),
        "the longest command and a short one leave their descriptions in the same column"
    );
}

/// A terminal narrow enough to squeeze the description column still
/// scrolls to the end of the page: `End` lands somewhere definite and a
/// further page does not move past it.
/// @requirement TB-126
#[test]
fn help_scrolls_to_the_end_of_the_wrapped_page() {
    let mut state = joined_general_with(vec![]);
    ctrl(&mut state, KeyCode::Char('h'));
    press(&mut state, KeyCode::End);
    let bottom = state.help_scroll();
    assert!(
        bottom + 1 >= aloo::client::tui::ui::help_total_lines(),
        "End reaches the last line of the laid-out page ({bottom} of {})",
        aloo::client::tui::ui::help_total_lines()
    );

    // And the last section is genuinely on screen there, at a width that
    // wraps a good deal of the page.
    let rows = rendered_rows_at(&state, 80, 30);
    assert!(
        rows.iter().any(|r| r.contains("scroll")),
        "the very last entry is reachable: {rows:?}"
    );
}

/// The name and the label columns are separated by a real gap, so a
/// nickname that fills its own column does not run straight into the
/// label after it.
/// @requirement AC-175
#[test]
fn the_call_roster_keeps_a_gap_between_the_name_and_the_labels() {
    // Two names of different lengths: the short one shows the padding, the
    // long one shows the gap that survives it.
    let state = hosting_a_call_with(&["bo", "bartholomew-the-longer"]);
    let body = popup_body(&buffer_at(&state, 100, 30), &call_modal_title("general"));
    let longest = body
        .iter()
        .find(|r| r.contains("bartholomew-the-longer"))
        .unwrap_or_else(|| panic!("no row for the longest name: {body:?}"));
    let after_name = longest
        .find("bartholomew-the-longer")
        .expect("just found it")
        + "bartholomew-the-longer".len();
    let label = longest.find("IN CALL").expect("its label");
    assert_eq!(
        label - after_name,
        4,
        "four columns between the widest name and its label: {longest:?}"
    );
}

/// The glyph on a person's row and the glyph on their messages are one
/// marker, so they can never drift apart into two different things
/// meaning the same thing.
/// @requirement AC-246
#[test]
fn otp_tag_and_icon_are_the_same_marker() {
    assert!(
        aloo::client::tui::ui::OTP_TAG.starts_with(aloo::client::tui::ui::OTP_ICON),
        "the tag is the icon plus the layer's name"
    );
    // And deliberately not pq_hybrid's own shield, which the pad always
    // runs over.
    assert!(!aloo::client::tui::ui::OTP_ICON.contains('\u{1F6E1}'));
}
