#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::proto::UserId;
use aloo::client::tui::ui::{
    Focus, IdentityCase, MessageBody, Mode, RECORD_HOLD_TIMEOUT, UiAction, UiState,
    render,
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
    assert_eq!(state.sidebar_selected, 1); // wraps to last
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

    // by design, only Ctrl+H closes help (see handle_key's doc comment) -
    // Esc while help is open must be a no-op, not fall through to the
    // normal "Esc closes the private room" handling underneath.
    press(&mut state, KeyCode::Esc);
    assert!(state.help_open, "Esc must not close help");
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
    let header = rows.first().expect("header row").clone();
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
    let header = rows.first().expect("header row");
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
            pcm: vec![1, 2, 3, 4]
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
    assert!(
        rows.iter().any(|r| r.contains("Space")),
        "expected help on sending a voice message: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("/file")),
        "expected help on sending a file: {rows:?}"
    );

    // The encryption tags and identity pinning both sit far enough down the
    // (now longer) help text that a typical terminal does not show them
    // without scrolling - see docs/SPEC.md Functionality #7's scrollable
    // overlay.
    press(&mut state, KeyCode::End);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("PQH")),
        "expected the encryption tags explained: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("Identity pinning")),
        "expected id_store identity pinning explained after scrolling to the bottom: {rows:?}"
    );
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
    press(&mut state, KeyCode::End);
    let backend = ratatui::backend::TestBackend::new(130, 30);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();
    let tail = "static: ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM, loaded from a file";
    assert!(
        rows.iter().any(|r| r.contains(tail)),
        "expected the longest help line in full, unclipped: {rows:?}"
    );
}

/// @requirement TB-108
#[test]
fn help_popup_never_exceeds_90_percent_of_the_terminal_width() {
    // Deliberately narrower than the popup's natural content width, so the
    // 90% cap is the thing actually constraining it here.
    let width = 60u16;
    let mut state = joined_general_with(vec![]);
    state.help_open = true;
    let backend = ratatui::backend::TestBackend::new(width, 30);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();
    // The popup's own top-left corner sits directly against its title (no
    // gap, e.g. "┌Help (Ctrl+H to close)---┐") - locate the corner-title
    // pair rather than just trimming whitespace, since the sidebar and
    // messages borders drawn underneath the (narrower-than-screen) popup
    // are visible in the same row and would otherwise be counted too.
    // Indexed by char, not byte, since the box-drawing glyphs are
    // multi-byte and each is still exactly one terminal cell.
    let border_row = rows
        .iter()
        .find(|r| r.contains("Help (Ctrl+H to close, arrows to scroll)"))
        .expect("expected the popup's title row");
    let row_chars: Vec<char> = border_row.chars().collect();
    let title: Vec<char> = "Help (Ctrl+H to close, arrows to scroll)".chars().collect();
    let title_start = row_chars
        .windows(title.len())
        .position(|w| w == title.as_slice())
        .expect("title in row");
    assert_eq!(
        row_chars[title_start - 1],
        '┌',
        "expected the corner right before the title: {border_row:?}"
    );
    let popup_start = title_start - 1;
    let popup_end = row_chars[popup_start..]
        .iter()
        .position(|&c| c == '┐')
        .expect("closing corner")
        + popup_start;
    let popup_width = popup_end - popup_start + 1;
    let max_allowed = (width as u32 * 9 / 10) as usize;
    assert!(
        popup_width <= max_allowed,
        "popup width {popup_width} exceeds 90% of the {width}-wide terminal ({max_allowed}): {border_row:?}"
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
