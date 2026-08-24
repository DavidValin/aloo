#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::netstats::ConnQuality;
use aloo::client::p2p::LinkStatus;
use aloo::p2p_proto::ReceiptStage;
use aloo::proto::{ChannelInfo, ChannelKind, UserId};
use aloo::client::reconnect::ServerLinkState;
use aloo::client::tui::channel::{HEADER_ROW_HEIGHT, messages_start_col};
use aloo::client::tui::ui::{
    DeliveryProof,
    DeliveryStatus, Focus, IdentityCase, MessageBody, SELECTOR_DROPDOWN_IDLE_TIMEOUT, UiAction,
    UiState, VoiceTarget, render, strike_through,
};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;


fn sidebar_rows(state: &UiState) -> Vec<String> {
    let backend = TestBackend::new(160, 30);
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

fn row_containing(rows: &[String], needle: &str) -> String {
    rows.iter()
        .find(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("no row contains {needle:?}: {rows:?}"))
        .clone()
}

/// `row_containing`, skipping the top row: that row names the selected DM
/// too (a speech balloon and the peer's nickname), so a sidebar assertion
/// about the same person would otherwise match the selector rather than
/// the roster entry.
fn sidebar_row_containing(rows: &[String], needle: &str) -> String {
    rows.iter()
        .skip(FIRST_ROW_BELOW_HEADER)
        .find(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("no row below the header contains {needle:?}: {rows:?}"))
        .clone()
}

// ---------------------------------------------------------------------
// Applying server events
// ---------------------------------------------------------------------

/// @requirement AC-018, TB-024
#[test]
fn channel_list_records_the_public_directory_without_duplicating() {
    let mut state = UiState::new("me".into());
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    assert_eq!(state.known_public_channels().len(), 1);
    assert!(
        state.channels.is_empty(),
        "the directory is not the tab row - only joining creates a tab"
    );
}

/// @requirement TB-024
#[test]
fn on_joined_marks_existing_channel_joined_or_creates_it() {
    let mut state = UiState::new("me".into());
    state.seed_member("general", user(2, "bob"));
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    assert!(state.channels[0].joined);

    state.on_joined(ChannelInfo {
        name: "secret".into(),
        kind: ChannelKind::Private,
    });
    assert!(
        state
            .channels
            .iter()
            .any(|c| c.name == "secret" && c.joined)
    );
}

/// @requirement TB-027
#[test]
fn user_joined_and_left_update_members_and_known_users() {
    let mut state = joined_general_with(vec![]);
    state.on_user_joined("general", user(2, "bob"));
    assert_eq!(state.channels[0].members.len(), 1);
    assert!(state.known_users.contains_key(&UserId(2)));

    // duplicate join is a no-op on the member list
    state.on_user_joined("general", user(2, "bob"));
    assert_eq!(state.channels[0].members.len(), 1);

    state.on_user_left("general", UserId(2));
    assert!(state.channels[0].members.is_empty());
    // known_users retains history (e.g. still needed to address old DMs)
    assert!(state.known_users.contains_key(&UserId(2)));
}

/// A live join (the channel is already joined, so this is not the
/// existing-member snapshot) logs a yellow, timestamped "joined" notice -
/// docs/SPEC.md Functionality #7.
///
/// @requirement AC-149
#[test]
fn a_live_join_logs_a_yellow_joined_presence_notice() {
    let mut state = joined_general_with(vec![]);
    state.on_user_joined("general", user(2, "bob"));

    assert_eq!(state.channels[0].log.len(), 1);
    match &state.channels[0].log[0].body {
        MessageBody::Presence(text) => assert!(
            text.ends_with("bob joined"),
            "expected a joined notice, got {text:?}"
        ),
        other => panic!("expected MessageBody::Presence, got {other:?}"),
    }

    // A duplicate join for an already-listed member logs no second notice.
    state.on_user_joined("general", user(2, "bob"));
    assert_eq!(
        state.channels[0].log.len(),
        1,
        "a duplicate join must not log a second notice"
    );
}

/// Someone leaving the channel logs a yellow, timestamped "left" notice.
///
/// @requirement AC-150
#[test]
fn on_user_left_logs_a_yellow_left_presence_notice() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_user_left("general", UserId(2));

    assert_eq!(state.channels[0].log.len(), 1);
    match &state.channels[0].log[0].body {
        MessageBody::Presence(text) => assert!(
            text.ends_with("bob left"),
            "expected a left notice, got {text:?}"
        ),
        other => panic!("expected MessageBody::Presence, got {other:?}"),
    }
}

/// A join/left presence notice is rendered in yellow - distinct from the
/// gray/italic `MessageBody::System` OTP narration already uses
/// (`render_messages`).
///
/// @requirement AC-149, TB-189
#[test]
fn presence_notice_is_rendered_in_yellow() {
    let mut state = joined_general_with(vec![]);
    state.on_user_joined("general", user(2, "bob"));

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "bob joined");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Yellow);
}

/// @requirement TB-159, TB-190
#[test]
fn on_user_joined_creates_the_tab_if_a_join_snapshot_arrives_before_joined() {
    let mut state = UiState::new("me".into());
    // The server sends the existing-member snapshot's UserJoined *before*
    // the final Joined confirmation (docs/PROTOCOL.md §6.1) - reproduce
    // that exact ordering for a channel with no local tab yet (e.g. a
    // private channel joined via Ctrl+J, which is never pre-known via
    // ChannelList).
    state.on_user_joined("secret-room", user(2, "bob"));
    state.on_joined(ChannelInfo {
        name: "secret-room".into(),
        kind: ChannelKind::Private,
    });

    let tab = state
        .channels
        .iter()
        .find(|c| c.name == "secret-room")
        .expect("tab created");
    assert!(tab.joined);
    assert_eq!(tab.kind, ChannelKind::Private);
    assert_eq!(
        tab.members.len(),
        1,
        "bob must not be lost when the snapshot preceded Joined"
    );
    assert_eq!(tab.members[0].id, UserId(2));
    assert!(
        tab.log.is_empty(),
        "the existing-member snapshot must not be logged as a join notice"
    );
}

/// @requirement TB-159
#[test]
fn on_user_joined_does_not_duplicate_an_existing_tab() {
    let mut state = joined_general_with(vec![]);
    state.on_user_joined("general", user(2, "bob"));
    assert_eq!(
        state.channels.len(),
        1,
        "must reuse the existing tab, not create a second one"
    );
}

/// @requirement TB-031
#[test]
fn channel_message_is_appended_to_the_right_channel_log() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hi".into()),
    );
    assert_eq!(state.channels[0].log.len(), 1);
    assert_eq!(state.channels[0].log[0].from_name, "bob");
}

// ---------------------------------------------------------------------
// Sending a channel message
// ---------------------------------------------------------------------

/// @requirement AC-025, TB-028
#[test]
fn typing_and_enter_sends_channel_text_excluding_self() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    type_str(&mut state, "hello all");
    let action = press(&mut state, KeyCode::Enter).expect("should produce an action");
    match action {
        UiAction::SendChannelText {
            channel,
            plaintext,
            recipients,
            msg_id: _,
        } => {
            assert_eq!(channel, "general");
            assert_eq!(plaintext, "hello all");
            let ids: Vec<UserId> = recipients.iter().map(|(id, _)| *id).collect();
            assert_eq!(ids, vec![UserId(2), UserId(3)]);
        }
        other => panic!("expected SendChannelText, got {other:?}"),
    }
    assert_eq!(state.input, "", "input should be cleared after sending");
    assert_eq!(
        state.channels[0].log.len(),
        1,
        "own message should be logged locally"
    );
    assert!(state.channels[0].log[0].outgoing);
}

/// @requirement AC-026
#[test]
fn enter_before_channel_is_joined_does_not_send_and_keeps_the_typed_text() {
    let mut state = UiState::new("me".into());
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    type_str(&mut state, "too early");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert_eq!(
        state.input, "too early",
        "unsent text must not be silently discarded"
    );
}

// ---------------------------------------------------------------------
// Ctrl+J private channel popup
// ---------------------------------------------------------------------

/// @requirement AC-021
#[test]
fn ctrl_j_then_typing_and_enter_requests_private_channel_join() {
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('j'));
    assert_eq!(state.mode, aloo::client::tui::ui::Mode::JoinPrivatePopup);
    type_str(&mut state, "secret-room");
    let action = press(&mut state, KeyCode::Enter).unwrap();
    assert_eq!(
        action,
        UiAction::JoinChannel {
            name: "secret-room".into(),
            kind: ChannelKind::Private,
            password: None
        }
    );
    assert_eq!(state.mode, aloo::client::tui::ui::Mode::Normal);
}

/// @requirement AC-021
#[test]
fn ctrl_j_popup_escape_cancels_without_action() {
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('j'));
    type_str(&mut state, "abandoned");
    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, None);
    assert_eq!(state.mode, aloo::client::tui::ui::Mode::Normal);
    assert_eq!(state.join_popup_input, "");
}

/// @requirement AC-021
#[test]
fn ctrl_j_popup_enter_with_blank_name_produces_no_action() {
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('j'));
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
}

// ---------------------------------------------------------------------
// Push-to-talk voice
// ---------------------------------------------------------------------

/// @requirement AC-032
#[test]
fn space_press_and_release_starts_and_stops_recording_for_channel() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Messages; // push-to-talk is only live outside the compose bar
    let start = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    match start {
        Some(UiAction::VoiceRecordStart(VoiceTarget::Channel {
            channel,
            recipients,
        })) => {
            assert_eq!(channel, "general");
            assert_eq!(
                recipients,
                vec![(UserId(2), user(2, "bob").public_key_der)]
            );
        }
        other => panic!("expected VoiceRecordStart(Channel), got {other:?}"),
    }
    assert!(state.recording);

    let stop = state.handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert_eq!(stop, Some(UiAction::VoiceRecordStop));
    assert!(!state.recording);
}

/// @requirement AC-089
#[test]
fn global_record_start_and_stop_streams_to_the_active_channel() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    // Deliberately not touching `state.focus` - the global shortcut fires
    // from the OS regardless of what this app's own internal focus is,
    // unlike Space which only matters while the terminal itself has it.
    let start = state.global_record_start();
    match start {
        Some(UiAction::VoiceRecordStart(VoiceTarget::Channel {
            channel,
            recipients,
        })) => {
            assert_eq!(channel, "general");
            assert_eq!(
                recipients,
                vec![(UserId(2), user(2, "bob").public_key_der)]
            );
        }
        other => panic!("expected VoiceRecordStart(Channel), got {other:?}"),
    }
    assert!(state.recording);

    let stop = state.global_record_stop();
    assert_eq!(stop, Some(UiAction::VoiceRecordStop));
    assert!(!state.recording);
}

/// `force_stop_recording` is what `session::run_connected_session`'s
/// `auto_stop_rx` arm calls when a recording hits
/// `voice::MAX_RECORDING_SAMPLES` - unlike `global_record_stop`, it stops
/// whatever is recording regardless of which trigger started it.
///
/// @requirement AC-099
#[test]
fn force_stop_recording_stops_regardless_of_trigger_and_is_a_noop_when_idle() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert_eq!(
        state.force_stop_recording(),
        None,
        "nothing to stop when idle"
    );

    state.global_record_start();
    assert!(state.recording);
    let action = state.force_stop_recording();
    assert_eq!(action, Some(UiAction::VoiceRecordStop));
    assert!(!state.recording);
}

// ---------------------------------------------------------------------
// [ / ] tab switching
// ---------------------------------------------------------------------

/// The first occurrence of `text` at or below row `min_y` - the same
/// cell-by-cell scan as `ui_common::find_text_start`, bounded so a popup
/// row can be told apart from an identical string elsewhere on screen.
fn find_text_start_below(
    buffer: &ratatui::buffer::Buffer,
    text: &str,
    min_y: u16,
) -> (u16, u16) {
    let want: Vec<String> = text.chars().map(|c| c.to_string()).collect();
    for y in min_y..buffer.area.height {
        for x in 0..buffer.area.width {
            let matches = want.iter().enumerate().all(|(i, ch)| {
                let xi = x + i as u16;
                xi < buffer.area.width && buffer[(xi, y)].symbol() == ch
            });
            if matches {
                return (x, y);
            }
        }
    }
    panic!("text {text:?} not found at or below row {min_y}");
}

/// Joins `names` as public channels, in order, and leaves the selector on
/// the first of them - joining lands the user in the channel joined
/// (`on_joined`), so this describes a membership arrived at earlier
/// rather than a join happening right now.
fn joined_public(names: &[&str]) -> UiState {
    let mut state = UiState::new("me".into());
    for name in names {
        state.on_joined(ChannelInfo {
            name: (*name).into(),
            kind: ChannelKind::Public,
        });
    }
    state.select_channel_at(0);
    state
}

/// @requirement AC-020
#[test]
fn opening_bracket_opens_the_channel_dropdown_and_down_switches_channel() {
    let mut state = joined_public(&["general", "random"]);
    assert_eq!(state.selected_channel, 0);
    assert!(!state.selector_dropdown_open);

    // `[` on the leftmost selector has nowhere further left to go, so it
    // opens that selector's own dropdown instead of wrapping around.
    press(&mut state, KeyCode::Char('['));
    assert!(state.selector_dropdown_open);
    assert_eq!(
        state.selected_channel, 0,
        "opening the dropdown changes nothing by itself"
    );

    let action = press(&mut state, KeyCode::Down);
    assert_eq!(
        state.selected_channel, 1,
        "Down switches the selection straight away, with the overlay still up"
    );
    assert!(state.selector_dropdown_open);
    assert_eq!(
        action, None,
        "every entry is a channel already joined - switching never requests a join"
    );

    assert_eq!(press(&mut state, KeyCode::Enter), None);
    assert!(!state.selector_dropdown_open, "Enter just closes it");
    assert_eq!(state.selected_channel, 1, "keeping what Down landed on");
}

/// @requirement AC-020
#[test]
fn up_in_the_channel_dropdown_selects_the_previous_channel() {
    let mut state = joined_public(&["general", "random"]);
    press(&mut state, KeyCode::Char('['));

    press(&mut state, KeyCode::Up);
    assert_eq!(
        state.selected_channel, 1,
        "Up wraps around within the selector's own list"
    );

    press(&mut state, KeyCode::Esc);
    assert!(!state.selector_dropdown_open, "Escape closes it too");
    assert_eq!(state.selected_channel, 1);
}

/// The dropdown lists what the selector is *not* naming - there is no
/// point offering the entry already on screen.
///
/// @requirement AC-185
#[test]
fn the_channel_dropdown_lists_every_joined_channel_except_the_selected_one() {
    let mut state = joined_public(&["general", "random", "lobby"]);
    press(&mut state, KeyCode::Char('['));

    let labels: Vec<String> = state
        .selector_dropdown_entries()
        .into_iter()
        .map(|e| e.label)
        .collect();
    assert_eq!(labels.len(), 2, "{labels:?}");
    assert!(labels.iter().any(|l| l.contains("random")), "{labels:?}");
    assert!(labels.iter().any(|l| l.contains("lobby")), "{labels:?}");
    assert!(
        !labels.iter().any(|l| l.contains("general")),
        "the selected channel is not offered again: {labels:?}"
    );

    let rows = sidebar_rows(&state);
    assert!(
        rows.iter().skip(FIRST_ROW_BELOW_HEADER).any(|r| r.contains("random")),
        "the dropdown is drawn under the selector: {rows:?}"
    );
}

/// With nothing else to switch to there is no dropdown to open - an empty
/// overlay would only be in the way.
///
/// @requirement AC-185
#[test]
fn the_channel_dropdown_does_not_open_with_only_one_channel_joined() {
    let mut state = joined_public(&["general"]);
    press(&mut state, KeyCode::Char('['));
    assert!(!state.selector_dropdown_open);
}

/// @requirement AC-185
#[test]
fn the_channel_selector_counts_everything_it_is_not_naming() {
    let mut state = joined_public(&["general"]);
    let top = sidebar_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains("general"), "{top:?}");
    assert!(
        !top.contains("more..."),
        "one channel joined, nothing else to count: {top:?}"
    );

    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    state.on_joined(ChannelInfo {
        name: "lobby".into(),
        kind: ChannelKind::Public,
    });
    // Back to general: joining lands on the channel joined, and what this
    // is about is the count of everything the selector is *not* naming.
    state.select_channel_at(0);
    let top = sidebar_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains("general"), "still naming the selected one: {top:?}");
    assert!(top.contains("+2 more..."), "{top:?}");
    assert!(
        !top.contains("random"),
        "the others are only named in the dropdown: {top:?}"
    );
}

/// @requirement AC-187
#[test]
fn a_message_in_an_unselected_channel_blinks_an_envelope_until_it_is_opened() {
    let mut state = joined_public(&["general", "random"]);
    state.seed_member("random", user(2, "bob"));
    state.on_channel_message(
        "random",
        UserId(2),
        "bob".into(),
        MessageBody::Text("over here".into()),
    );
    assert!(state.any_channel_unread());

    state.blink_on = true;
    let top = sidebar_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(
        top.contains('\u{2709}'),
        "the envelope shows on the blink-on frame: {top:?}"
    );
    state.blink_on = false;
    let top = sidebar_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(
        !top.contains('\u{2709}'),
        "and is hidden on the blink-off frame - that is the blink: {top:?}"
    );

    // While the dropdown is open it moves onto the row it belongs to.
    press(&mut state, KeyCode::Char('['));
    state.blink_on = true;
    let rows = sidebar_rows(&state);
    assert!(
        !rows[HEADER_TEXT_ROW].contains('\u{2709}'),
        "not on the selector while its own dropdown is open: {rows:?}"
    );
    let row = row_containing(&rows, "random");
    assert!(row.contains('\u{2709}'), "on the unread row instead: {row:?}");

    // Opening it is what clears it.
    press(&mut state, KeyCode::Down);
    assert!(!state.any_channel_unread());
    let rows = sidebar_rows(&state);
    assert!(!rows[HEADER_TEXT_ROW].contains('\u{2709}'), "{rows:?}");
}

/// A presence notice is not a message: joining and leaving must not raise
/// an envelope on a channel nobody has written in.
///
/// @requirement AC-187
#[test]
fn a_presence_notice_does_not_mark_a_channel_unread() {
    let mut state = joined_public(&["general", "random"]);
    state.on_user_joined("random", user(2, "bob"));
    state.on_user_left("random", UserId(2));
    assert!(!state.any_channel_unread());
}

/// @requirement TB-026
#[test]
fn focusing_the_channel_selector_closes_any_open_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    assert!(state.active_private_room.is_some());

    // `[` from the DM selector steps back onto the channel one, which is
    // the channel view - the room itself stays on the DM selector.
    press(&mut state, KeyCode::Char('['));
    assert_eq!(state.active_private_room, None);
    assert_eq!(state.selected_dm, Some(UserId(2)));
}

// ---------------------------------------------------------------------
// Live-streamed voice: placeholder log entries and finalize-in-place
// ---------------------------------------------------------------------

/// @requirement AC-035
#[test]
fn on_channel_stream_start_and_finished_swap_the_placeholder_body_in_place() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_stream_start("general", UserId(2), "bob".into(), 42);
    assert_eq!(state.channels[0].log.len(), 1);
    assert_eq!(
        state.channels[0].log[0].body,
        MessageBody::VoiceStreaming { stream_id: 42 }
    );

    state.on_channel_stream_finished("general", UserId(2), 42, 4200, vec![1, 2, 3, 4]);
    assert_eq!(
        state.channels[0].log.len(),
        1,
        "must swap in place, not append a second entry"
    );
    assert_eq!(
        state.channels[0].log[0].body,
        MessageBody::Voice {
            duration_ms: 4200,
            pcm: vec![1, 2, 3, 4]
        }
    );
}

/// @requirement AC-035
#[test]
fn log_own_voice_stream_start_channel_appears_immediately_and_finalizes() {
    let mut state = joined_general_with(vec![]);
    state.log_own_voice_stream_start_channel("general", 7, None);
    assert_eq!(
        state.channels[0].log[0].body,
        MessageBody::VoiceStreaming { stream_id: 7 }
    );
    assert!(state.channels[0].log[0].outgoing);

    state.on_channel_stream_finished("general", UserId(1), 7, 900, vec![9, 9]);
    assert_eq!(
        state.channels[0].log[0].body,
        MessageBody::Voice {
            duration_ms: 900,
            pcm: vec![9, 9]
        }
    );
}

/// @requirement TB-040
#[test]
fn finalize_matches_by_from_and_stream_id_not_stream_id_alone() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    // Two different senders happen to reuse the same numeric stream_id -
    // each one's is only unique per-connection, so this can genuinely
    // happen.
    state.on_channel_stream_start("general", UserId(2), "bob".into(), 1);
    state.on_channel_stream_start("general", UserId(3), "carol".into(), 1);
    assert_eq!(state.channels[0].log.len(), 2);

    state.on_channel_stream_finished("general", UserId(3), 1, 2000, vec![7, 7]);

    let bob_entry = state.channels[0]
        .log
        .iter()
        .find(|e| e.from == UserId(2))
        .unwrap();
    let carol_entry = state.channels[0]
        .log
        .iter()
        .find(|e| e.from == UserId(3))
        .unwrap();
    assert_eq!(
        bob_entry.body,
        MessageBody::VoiceStreaming { stream_id: 1 },
        "bob's placeholder must be untouched by carol's finish"
    );
    assert_eq!(
        carol_entry.body,
        MessageBody::Voice {
            duration_ms: 2000,
            pcm: vec![7, 7]
        }
    );
}

// ---------------------------------------------------------------------
// Message log scrolling, channel-specific part
//
// The generic selection/scrolling behavior itself lives in
// `crate::client::tui::ui` (shared with the private-room view), so its tests are in
// `ui_test.rs` - only the "which channel's log am I even looking at"
// interaction belongs here.
// ---------------------------------------------------------------------

/// @requirement TB-110
#[test]
fn a_message_arriving_in_a_different_channel_does_not_move_the_current_selection() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_list(vec![
        ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "random".into(),
            kind: ChannelKind::Public,
        },
    ]);
    push_n_channel_texts(&mut state, 2);
    assert_eq!(state.message_selected, 1);

    // a message lands in "random", which isn't the selected tab
    state.on_channel_message(
        "random",
        UserId(2),
        "bob".into(),
        MessageBody::Text("elsewhere".into()),
    );
    assert_eq!(
        state.message_selected, 1,
        "a background channel's traffic must not touch our current position"
    );
}

// ---------------------------------------------------------------------
// Encryption method label next to a username
// ---------------------------------------------------------------------

/// @requirement AC-051
#[test]
fn sidebar_shows_each_users_encryption_tag_after_their_name() {
    let state = joined_general_with(vec![
        pq_hybrid_user(2, "bob"),
        pq_hybrid_user(4, "dan"),
        pq_hybrid_user(5, "eve"),
    ]);
    // the sidebar is a fixed 20% of the frame width (SPEC.md) - a narrow
    // terminal clips long labels just like it clips any other long text
    // in this TUI, so this needs enough width to assert on the full text.
    let backend = TestBackend::new(160, 30);
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
        appears_before(&rows, "bob", "PQH"),
        "expected bob's tag rendered after his name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "dan", "PQH"),
        "expected dan's tag rendered after his name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "eve", "PQH"),
        "expected eve's tag rendered after her name: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// Sidebar DM envelope indicator
// ---------------------------------------------------------------------

/// @requirement AC-030
#[test]
fn sidebar_shows_no_envelope_for_a_dm_room_that_has_no_messages_yet() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens an empty DM with bob
    press(&mut state, KeyCode::Esc); // back to channel view; the room struct still exists but is empty
    assert!(
        state.private_rooms.contains_key(&UserId(2)),
        "opening a DM should still create the room struct"
    );
    assert!(state.private_rooms[&UserId(2)].log.is_empty());

    let row = sidebar_row_containing(&sidebar_rows(&state), "bob");
    assert!(
        !row.contains('\u{2709}'),
        "no envelope should show for a DM with zero messages: {row:?}"
    );
}

/// @requirement AC-030, TB-034
#[test]
fn sidebar_shows_a_solid_envelope_once_an_outgoing_message_exists_even_after_leaving_the_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // open DM with bob
    type_str(&mut state, "hi bob");
    press(&mut state, KeyCode::Enter); // send it
    press(&mut state, KeyCode::Esc); // back to channel view
    assert!(!state.private_rooms[&UserId(2)].log.is_empty());
    assert!(
        !state.private_rooms[&UserId(2)].unread,
        "our own outgoing message must not mark the room unread"
    );

    // a read/solid envelope must show regardless of the blink phase.
    for blink in [false, true] {
        state.blink_on = blink;
        let row = sidebar_row_containing(&sidebar_rows(&state), "bob");
        assert!(
            row.contains('\u{2709}'),
            "expected a steady envelope with blink_on={blink}: {row:?}"
        );
    }
}

/// @requirement AC-030
#[test]
fn sidebar_blinks_the_envelope_only_while_a_dm_message_is_unread() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    // bob sends a DM while we're not viewing it - marks the room unread.
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hey".into()));
    assert!(state.private_rooms[&UserId(2)].unread);

    state.blink_on = true;
    let row = sidebar_row_containing(&sidebar_rows(&state), "bob");
    assert!(
        row.contains('\u{2709}'),
        "expected the envelope visible on the blink-on frame: {row:?}"
    );

    state.blink_on = false;
    let row = sidebar_row_containing(&sidebar_rows(&state), "bob");
    assert!(
        !row.contains('\u{2709}'),
        "expected the envelope hidden on the blink-off frame while unread: {row:?}"
    );
}

/// @requirement AC-030
#[test]
fn sidebar_envelope_stops_blinking_and_stays_solid_once_the_dm_is_reopened() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hey".into()));
    assert!(state.private_rooms[&UserId(2)].unread);

    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // reopen bob's DM - marks it read
    press(&mut state, KeyCode::Esc); // back to channel view
    assert!(!state.private_rooms[&UserId(2)].unread);
    assert!(
        !state.private_rooms[&UserId(2)].log.is_empty(),
        "the earlier message must still be in history"
    );

    for blink in [true, false] {
        state.blink_on = blink;
        let row = sidebar_row_containing(&sidebar_rows(&state), "bob");
        assert!(
            row.contains('\u{2709}'),
            "expected a solid (non-blinking) envelope once read, blink_on={blink}: {row:?}"
        );
    }
}

/// @requirement AC-052
#[test]
fn sidebar_renders_an_offline_member_in_gray_instead_of_green() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into())); // gives bob DM history
    state.on_user_offline(UserId(2)); // bob goes offline, carol stays online
    // Green means "reachable over a direct link" (AC-135), so carol needs
    // one for this test's "still green" half to mean what it says.
    state.set_link_status(UserId(3), LinkStatus::Active);

    let backend = TestBackend::new(160, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (bx, by) = find_text_start_below(&buffer, "bob", HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(bx, by)].fg,
        ratatui::style::Color::DarkGray,
        "offline member should render in soft gray"
    );

    let (cx, cy) = find_text_start_below(&buffer, "carol", HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(cx, cy)].fg,
        ratatui::style::Color::Green,
        "still-connected member should stay green"
    );
}

// ---------------------------------------------------------------------
// The own user's row (always last, never a real DM target)
// ---------------------------------------------------------------------

/// Our own row is appended after every real member, named plainly and
/// suffixed `(me)` in gray - the suffix's colour never following whatever
/// colour the name itself renders in.
#[test]
fn sidebar_lists_the_own_user_last_with_a_gray_me_suffix() {
    let state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    let backend = TestBackend::new(160, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (nx, ny) = find_text_start_below(&buffer, "me (me)", HEADER_ROW_HEIGHT);
    // "me (me)": own name at [0..2), the gray " (me)" suffix from [2..7).
    assert_eq!(
        buffer[(nx, ny)].fg,
        ratatui::style::Color::Green,
        "own name renders reachable-green (you are always reachable to yourself)"
    );
    assert_eq!(
        buffer[(nx + 3, ny)].fg,
        ratatui::style::Color::DarkGray,
        "the (me) suffix is always gray regardless of the name's own colour"
    );

    // It comes after both real members, not before or between them.
    let rows = popup_body(&buffer, "Users");
    let bob_row = rows.iter().position(|r| r.contains("bob")).unwrap();
    let carol_row = rows.iter().position(|r| r.contains("carol")).unwrap();
    let me_row = rows.iter().position(|r| r.contains("(me)")).unwrap();
    assert!(me_row > bob_row && me_row > carol_row);
}

/// Enter on the own row must never open a "DM with yourself" - it is the
/// last sidebar index (`channel.members.len()`), one past every real
/// member.
#[test]
fn enter_on_the_own_row_does_not_open_a_dm() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.focus = Focus::Sidebar;
    state.sidebar_selected = 2; // one past bob (0) and carol (1)
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert_eq!(state.active_private_room, None);
}

/// A channel with nobody else in it still shows our own row - it is never
/// swallowed by the "waiting for direct peers" placeholder, which is about
/// there being no real member yet, not about the sidebar being visually
/// empty.
#[test]
fn the_own_row_still_shows_with_no_other_members() {
    let state = joined_general_with(vec![]);
    let rows = rendered_rows(&state);
    assert!(rows.iter().any(|r| r.contains("(me)")));
}

/// The sidebar's colour is the state of the *direct link* to each person,
/// not merely their presence on the server (AC-135): someone can be
/// perfectly online and completely unreachable, which is exactly the case
/// worth showing. Green once messages can actually reach them, red once
/// they cannot - whether the punch is still in flight or the link is gone,
/// since both answer the only question being asked the same way.
///
/// @requirement AC-135
#[test]
fn sidebar_colours_each_member_by_the_state_of_the_direct_link_to_them() {
    let mut state = joined_general_with(vec![
        user(2, "bob"),
        user(3, "carol"),
        user(4, "dave"),
    ]);
    state.set_link_status(UserId(2), LinkStatus::Active);
    state.set_link_status(UserId(3), LinkStatus::Lost);
    state.set_link_status(UserId(4), LinkStatus::Connecting);

    let backend = TestBackend::new(160, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    for (name, expected) in [
        ("bob", ratatui::style::Color::Green),
        ("carol", ratatui::style::Color::DarkGray),
        ("dave", ratatui::style::Color::DarkGray),
    ] {
        let (x, y) = find_text_start(&buffer, name);
        assert_eq!(
            buffer[(x, y)].fg, expected,
            "{name} should render in {expected:?} for their link state"
        );
    }
}

/// A peer nobody has a link record for yet reads the same as one being
/// established - never green. A pre-warm starts the moment they are
/// learned about (§7.1), so "no record" means the handshake has not got
/// anywhere yet, and showing green there would promise a delivery path
/// that does not exist.
///
/// @requirement AC-135
#[test]
fn a_member_with_no_link_record_yet_is_not_shown_as_reachable() {
    let state = joined_general_with(vec![user(2, "bob")]);

    let backend = TestBackend::new(160, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "bob");
    assert_eq!(
        buffer[(x, y)].fg,
        ratatui::style::Color::DarkGray,
        "an unknown link state must not claim the peer is reachable"
    );
}

// ---------------------------------------------------------------------
// Rendering smoke tests
// ---------------------------------------------------------------------

/// @requirement TB-101
#[test]
fn render_channel_view_does_not_panic() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.on_channel_message(
        "general",
        UserId(2),
        "bob".into(),
        MessageBody::Text("hello".into()),
    );
    state.on_channel_message(
        "general",
        UserId(3),
        "carol".into(),
        MessageBody::Voice {
            duration_ms: 9000,
            pcm: vec![],
        },
    );
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    assert!(buffer.content().iter().any(|c| c.symbol() != " "));
}

/// @requirement AC-058
#[test]
fn render_channel_view_shows_the_ctrl_h_hint_after_the_channel_tabs() {
    let state = joined_general_with(vec![]);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter()
            .any(|r| r.contains("Ctrl+H") && r.contains("Help")),
        "expected a help hint: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// CPU / Conn header indicators (US-018)
// ---------------------------------------------------------------------

/// @requirement AC-071
#[test]
fn header_shows_cpu_usage_right_before_the_ctrl_h_hint() {
    let mut state = joined_general_with(vec![]);
    state.set_cpu_usage(24.0);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        header.contains("CPU:24%  Ctrl+H: Help"),
        "expected CPU right before the help hint: {header:?}"
    );
}

/// @requirement AC-072
#[test]
fn header_shows_conn_quality_right_before_the_cpu_indicator() {
    let mut state = joined_general_with(vec![]);
    state.set_conn_quality(ConnQuality::Good);
    state.set_cpu_usage(24.0);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        header.contains("Conn:GOOD  CPU:24%"),
        "expected Conn right before CPU: {header:?}"
    );
}

/// @requirement AC-293
#[test]
fn header_shows_nothing_about_otp_mail_when_there_is_none_unread() {
    let state = joined_general_with(vec![]);
    assert_eq!(state.unread_otp_mail_count, 0);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        !header.contains("unread OTP Mail"),
        "nothing should be shown with zero unread: {header:?}"
    );
}

/// @requirement AC-293
#[test]
fn header_shows_the_unread_otp_mail_count_right_before_conn_quality() {
    let mut state = joined_general_with(vec![]);
    state.set_unread_otp_mail_count(3);
    state.blink_on = true;
    state.set_conn_quality(ConnQuality::Good);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        header.contains("3 unread OTP Mails") && header.contains("Conn:GOOD"),
        "expected the unread count somewhere before Conn: {header:?}"
    );
    assert!(
        header.find("unread OTP Mails").unwrap() < header.find("Conn:").unwrap(),
        "the unread count should sit before Conn: {header:?}"
    );
}

/// @requirement AC-293
#[test]
fn the_unread_otp_mail_indicator_blinks() {
    let mut state = joined_general_with(vec![]);
    state.set_unread_otp_mail_count(1);

    state.blink_on = true;
    let rows_on = rendered_rows(&state);
    assert!(rows_on[HEADER_TEXT_ROW].contains("\u{2709}"));

    state.blink_on = false;
    let rows_off = rendered_rows(&state);
    assert!(!rows_off[HEADER_TEXT_ROW].contains("\u{2709}"));
    assert!(
        rows_off[HEADER_TEXT_ROW].contains("1 unread OTP Mails"),
        "the count itself must not blink away, only the envelope: {:?}",
        rows_off[HEADER_TEXT_ROW]
    );
}

/// @requirement AC-290
#[test]
fn header_shows_nothing_about_direct_punching_when_it_is_not_configured() {
    let state = joined_general_with(vec![]);
    assert_eq!(state.direct_punch_status, None);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        !header.contains("direct punches"),
        "nothing should be shown when direct punching is not set up: {header:?}"
    );
}

/// @requirement AC-290
#[test]
fn header_shows_the_direct_punch_summary_right_before_conn_quality() {
    let mut state = joined_general_with(vec![]);
    state.set_direct_punch_status(Some((1, 2, Some(std::time::Duration::from_secs(37)))));
    state.set_conn_quality(ConnQuality::Good);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        header.contains("1/2 direct punches, next try in 37s (Control+s)  Conn:GOOD"),
        "expected the direct-punch summary right before Conn: {header:?}"
    );
}

/// @requirement AC-290
#[test]
fn the_direct_punch_summary_is_green_when_everything_is_active_and_yellow_otherwise() {
    let mut state = joined_general_with(vec![]);
    state.set_direct_punch_status(Some((2, 2, None)));
    let buffer = {
        let backend = TestBackend::new(100, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &state)).unwrap();
        terminal.backend().buffer().clone()
    };
    let (x, y) = find_text_start(&buffer, "2/2 direct punches");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Green);

    state.set_direct_punch_status(Some((1, 2, Some(std::time::Duration::from_secs(5)))));
    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let (x, y) = find_text_start(&buffer, "1/2 direct punches");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Yellow);
}

/// @requirement AC-072
#[test]
fn header_defaults_conn_quality_to_a_white_dash_before_any_traffic() {
    let state = joined_general_with(vec![]);
    assert_eq!(state.conn_quality, ConnQuality::Unknown);
    let rows = rendered_rows(&state);
    let header = &rows[HEADER_TEXT_ROW];
    assert!(
        header.contains("Conn:-"),
        "expected the default 'Conn:-': {header:?}"
    );

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let (x, y) = find_text_start(&buffer, "Conn:-");
    assert_eq!(
        buffer[(x, y)].fg,
        ratatui::style::Color::White,
        "Conn:- should render in white"
    );
}

// ---------------------------------------------------------------------
// The header's server-state element (docs/PROTOCOL.md 4.2)
// ---------------------------------------------------------------------

/// A reconnect ends every relationship the old connection's ids named -
/// but nobody went anywhere, so nothing may claim they did. The ids are
/// dropped wholesale instead, including the offline set: it belonged to
/// that connection, whose server may not even be the same process next
/// time.
/// @requirement AC-227
#[test]
fn a_reconnect_drops_what_the_old_connection_said_without_marking_anyone_offline() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.on_user_offline(UserId(3));
    assert!(state.offline.contains(&UserId(3)));

    state.forget_server_presence();

    assert!(
        state.channels[0].members.is_empty(),
        "memberships came from the connection that ended"
    );
    assert!(state.known_users.is_empty(), "so did the identities");
    assert!(
        state.offline.is_empty(),
        "and so did the record of who had gone - those ids mean nothing now"
    );
}

/// A direct-punch peer is named by its own identity rather than by
/// anything a server handed out, so no server coming or going touches it.
/// @requirement AC-227
#[test]
fn a_reconnect_leaves_direct_punch_peers_exactly_where_they_are() {
    let direct = aloo::client::p2p::direct_peer_id("bob");
    let mut state = joined_general_with(vec![user(2, "carol")]);
    state.seed_member("general", user(direct.0, "bob"));

    state.forget_server_presence();

    assert_eq!(
        state.channels[0].members.len(),
        1,
        "the direct peer stays, the server-named one goes"
    );
    assert_eq!(state.channels[0].members[0].id, direct);
    assert!(state.known_users.contains_key(&direct));
}

/// @requirement AC-223
#[test]
fn the_server_state_is_the_first_thing_on_the_header_row() {
    let state = joined_general_with(vec![]);
    let header = header_row(&state);
    let connected = header
        .find("Connected to server!")
        .expect("the header must say what the server connection is doing");
    let selector = header.find("general").expect("the channel selector");
    assert!(
        connected < selector,
        "the server state comes before the selectors: {header:?}"
    );
}

/// @requirement AC-223
#[test]
fn the_selectors_start_where_the_message_list_below_them_does() {
    // Wide enough for the server state to fit in the sidebar's share of
    // it; a terminal too narrow for that is the next test.
    const WIDTH: u16 = 140;
    let state = joined_general_with(vec![]);
    let backend = TestBackend::new(WIDTH, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    // The selector's own first cell: its `#name` (a public channel carries
    // no kind icon, so this is where its text starts). One column past the
    // message pane's own left edge, which is where the messages *inside*
    // that pane's border begin - so the two columns of text line up.
    let (x, y) = find_text_start(&buffer, "#general");
    assert_eq!(y as usize, HEADER_TEXT_ROW, "the selector is on the header row");
    assert_eq!(
        x,
        messages_start_col(WIDTH) + 1,
        "the channel selector must line up with the message list under it"
    );
}

/// A countdown that has lost its number tells the user nothing, so an
/// over-long state pushes the selectors right rather than being cut off.
/// @requirement AC-223
#[test]
fn a_state_too_long_for_the_sidebar_width_pushes_the_selectors_rather_than_truncating() {
    let mut state = joined_general_with(vec![]);
    state.set_server_link(ServerLinkState::Down { seconds_left: 30 });
    let header = header_row(&state);
    assert!(
        header.contains("Server down (reconnecting in 30 sec...)"),
        "the whole state must survive: {header:?}"
    );
    let state_end = header.find("sec...)").expect("the countdown") + "sec...)".len();
    let selector = header.find("general").expect("the channel selector");
    assert!(
        selector > state_end,
        "the selectors move aside instead of being written over: {header:?}"
    );
}

/// @requirement AC-223
#[test]
fn every_server_state_renders_in_its_own_colour() {
    let cases = [
        (
            ServerLinkState::Connected,
            "Connected to server!",
            ratatui::style::Color::Green,
        ),
        (
            ServerLinkState::Reconnecting,
            "Reconnecting...",
            ratatui::style::Color::Red,
        ),
        (
            ServerLinkState::RetryingIn { seconds_left: 5 },
            "Reconnecting in 5s...",
            ratatui::style::Color::Red,
        ),
        (
            ServerLinkState::Down { seconds_left: 12 },
            "Server down",
            ratatui::style::Color::Red,
        ),
        (
            ServerLinkState::NoServer,
            "No server mode",
            ratatui::style::Color::White,
        ),
    ];
    for (link, text, expected) in cases {
        let mut state = joined_general_with(vec![]);
        state.set_server_link(link);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let (x, y) = find_text_start(&buffer, text);
        assert_eq!(buffer[(x, y)].fg, expected, "{text} should render {expected:?}");
    }
}

/// @requirement AC-224
#[test]
fn no_server_mode_says_so_while_a_punch_is_in_flight() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_server_link(ServerLinkState::NoServer);
    assert!(header_row(&state).contains("No server mode"));
    assert!(
        !header_row(&state).contains("(punching)"),
        "nothing is being punched yet"
    );

    state.set_link_status(UserId(2), LinkStatus::Connecting);
    assert!(
        header_row(&state).contains("No server mode (punching)"),
        "a link being established is a punch in flight: {:?}",
        header_row(&state)
    );

    state.set_link_status(UserId(2), LinkStatus::Active);
    assert!(
        !header_row(&state).contains("(punching)"),
        "a link that is up is not a punch in flight"
    );
}

/// @requirement TB-118
#[test]
fn cpu_usage_renders_green_below_the_healthy_threshold_and_red_at_or_above_it() {
    let mut state = joined_general_with(vec![]);
    state.set_cpu_usage(24.0);
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let (x, y) = find_text_start(&buffer, "CPU:24%");
    assert_eq!(
        buffer[(x, y)].fg,
        ratatui::style::Color::Green,
        "below 25% should render green"
    );

    let mut state = joined_general_with(vec![]);
    state.set_cpu_usage(25.0);
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let (x, y) = find_text_start(&buffer, "CPU:25%");
    assert_eq!(
        buffer[(x, y)].fg,
        ratatui::style::Color::Red,
        "at or above 25% should render red"
    );
}

/// @requirement AC-072
#[test]
fn conn_quality_renders_one_color_per_variant() {
    let cases = [
        (ConnQuality::Bad, "Conn:BAD", ratatui::style::Color::Red),
        (
            ConnQuality::Normal,
            "Conn:NORMAL",
            ratatui::style::Color::Yellow,
        ),
        (ConnQuality::Good, "Conn:GOOD", ratatui::style::Color::Green),
    ];
    for (quality, text, expected) in cases {
        let mut state = joined_general_with(vec![]);
        state.set_conn_quality(quality);
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let (x, y) = find_text_start(&buffer, text);
        assert_eq!(
            buffer[(x, y)].fg,
            expected,
            "{text} should render {expected:?}"
        );
    }
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

/// @requirement AC-064
#[test]
fn push_identity_review_opens_a_popup_naming_the_peer_in_the_channel_view() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "'bob' connected with a different key than last time".into(),
        static_mismatch(),
    );
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("Identity review: bob")),
        "expected the review popup to be visible: {rows:?}"
    );
}

/// @requirement AC-064
#[test]
fn sidebar_renders_a_trust_gated_member_in_red_taking_priority_over_offline() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into())); // gives bob DM history
    state.on_user_offline(UserId(2)); // bob is offline *and* about to be trust-gated
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "mismatch".into(),
        static_mismatch(),
    );
    state.set_link_status(UserId(3), LinkStatus::Active);

    let backend = TestBackend::new(160, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (bx, by) = find_text_start_below(&buffer, "bob", HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(bx, by)].fg,
        ratatui::style::Color::Red,
        "a trust-gated member renders red even while also offline"
    );
    let (cx, cy) = find_text_start_below(&buffer, "carol", HEADER_ROW_HEIGHT);
    assert_eq!(
        buffer[(cx, cy)].fg,
        ratatui::style::Color::Green,
        "an unaffected member stays green"
    );
}

/// @requirement TB-101
#[test]
fn render_with_identity_review_popup_open_does_not_panic() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_identity_review(
        UserId(2),
        "bob".into(),
        "'bob' connected with a different key than last time".into(),
        static_mismatch(),
    );
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    assert!(buffer.content().iter().any(|c| c.symbol() != " "));
}

/// @requirement TB-101
#[test]
fn render_join_popup_overlay_does_not_panic() {
    let mut state = UiState::new("me".into());
    ctrl(&mut state, KeyCode::Char('j'));
    type_str(&mut state, "secret");
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
}

// ---------------------------------------------------------------------
// Channel tab emoji prefixes (AC-103)
// ---------------------------------------------------------------------

/// @requirement AC-103
#[test]
fn channel_tabs_are_prefixed_by_kind() {
    let mut state = UiState::new("me".into());
    state.on_joined(ChannelInfo {
        name: "the-hall".into(),
        kind: ChannelKind::Public,
    });
    state.on_joined(ChannelInfo {
        name: "secret-room".into(),
        kind: ChannelKind::Private,
    });
    // Joining lands on the channel joined, so put the selector back on the
    // public one - this is about how each kind is drawn, not about where a
    // join leaves you.
    state.select_channel_at(0);
    let rows = sidebar_rows(&state);
    let tab_row = row_containing(&rows, "the-hall");
    assert!(
        !tab_row.contains('\u{1F512}'),
        "a public channel tab should carry no lock emoji: {tab_row:?}"
    );
    assert!(
        tab_row.contains("#the-hall"),
        "public channel tab should show its name, unadorned: {tab_row:?}"
    );
    // The private one is behind the selector, so its lock shows on its
    // dropdown row - the selector names one channel at a time.
    press(&mut state, KeyCode::Char('['));
    let rows = sidebar_rows(&state);
    let tab_row = row_containing(&rows, "secret-room");
    assert!(
        tab_row.contains('\u{1F512}'),
        "private channel tab should show the lock emoji: {tab_row:?}"
    );
    assert!(
        tab_row.contains("secret-room"),
        "private channel tab should still show its name: {tab_row:?}"
    );
    // Each emoji must precede its own channel's name, not merely appear
    // somewhere on the same row.
    assert!(
        tab_row.find('\u{1F512}').unwrap() < tab_row.find("secret-room").unwrap(),
        "lock emoji should prefix the private channel's name: {tab_row:?}"
    );
    let top = rows[HEADER_TEXT_ROW].clone();
    let hash = top.find("#the-hall").expect("the selector should show #the-hall");
    assert_ne!(
        top[..hash].chars().next_back(),
        Some('\u{1F512}'),
        "a public channel's own #name should carry no lock icon ahead of it: {top:?}"
    );
}

// ---------------------------------------------------------------------
// P2P trust boundary (TB-155)
// ---------------------------------------------------------------------

/// @requirement TB-155
#[test]
fn shares_a_joined_channel_is_true_for_a_member_of_a_joined_channel() {
    let state = joined_general_with(vec![user(2, "bob")]);
    assert!(state.shares_a_joined_channel(UserId(2)));
}

/// @requirement TB-155, TB-149
#[test]
fn shares_a_joined_channel_is_true_for_a_member_of_an_unselected_joined_channel() {
    // Being joined is what counts, not being looked at: the link to
    // everyone in every joined channel is armed regardless of which tab
    // is on screen.
    let mut state = joined_general_with(vec![]);
    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    state.seed_member("random", user(2, "bob"));
    state.select_channel_at(0);
    assert_eq!(state.selected_channel, 0, "back to looking at general");
    assert!(state.shares_a_joined_channel(UserId(2)));
}

/// @requirement TB-155
#[test]
fn shares_a_joined_channel_is_false_for_a_stranger() {
    let state = joined_general_with(vec![user(2, "bob")]);
    assert!(!state.shares_a_joined_channel(UserId(999)));
}

/// @requirement TB-155
#[test]
fn shares_a_joined_channel_is_false_once_the_channel_is_left() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_user_left("general", UserId(2));
    assert!(!state.shares_a_joined_channel(UserId(2)));
}

/// The bar for *answering* a link request is the same one used for *keeping*
/// a link (TB-158), not the narrower shared-channel test: an open DM with
/// history is a supported reason to reach someone who has left every channel
/// you shared (SPEC.md's "Offline users"), and §7.1.2 already exempts the
/// initiating side for exactly that reason.
///
/// The two bars have to agree. Gating the answer on a shared channel while
/// retention kept the link on DM history left both sides holding a link
/// neither would ever re-signal: it survives only while the addresses learned
/// earlier still work, so the first time either peer's address moves - the
/// one situation signalling exists to recover from - the DM can never be
/// punched again.
///
/// @requirement TB-155
#[test]
fn a_link_request_is_answered_for_a_dm_peer_with_no_shared_channel() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hey".into()));
    // Bob leaves the only channel they had in common; the DM remains.
    state.on_user_left("general", UserId(2));

    assert!(
        !state.shares_a_joined_channel(UserId(2)),
        "precondition: no shared channel is left"
    );
    assert!(
        state.has_reason_to_keep_link(UserId(2)),
        "the DM is still a reason to reach them - so their link request must \
         be answered, or the link can never be re-established"
    );
}

// ---------------------------------------------------------------------
// Leaving a channel (US-026)
// ---------------------------------------------------------------------

/// @requirement AC-109
#[test]
fn slash_leave_on_a_private_channel_removes_its_tab() {
    let mut state = joined_general_with(vec![]);
    state.on_joined(ChannelInfo {
        name: "secret-room".into(),
        kind: ChannelKind::Private,
    });
    let idx = state
        .channels
        .iter()
        .position(|c| c.name == "secret-room")
        .unwrap();
    state.selected_channel = idx;

    type_str(&mut state, "/leave");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::LeaveChannel {
            name: "secret-room".into()
        })
    );

    let former_members = state.leave_channel_locally("secret-room");
    assert!(former_members.is_empty());
    assert!(!state.channels.iter().any(|c| c.name == "secret-room"));
}

/// @requirement AC-109
#[test]
fn slash_leave_on_a_public_channel_removes_its_tab_too() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == "general")
        .unwrap();

    type_str(&mut state, "/leave");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::LeaveChannel {
            name: "general".into()
        })
    );

    let former_members = state.leave_channel_locally("general");
    assert_eq!(former_members, vec![UserId(2)]);
    assert!(
        !state.channels.iter().any(|c| c.name == "general"),
        "a tab is a channel you are in - leaving removes it, public or not"
    );
}

/// @requirement AC-109
#[test]
fn slash_leave_is_a_noop_when_the_selected_channel_is_not_joined() {
    let mut state = joined_general_with(vec![]);
    // A tab whose `Joined` confirmation hasn't arrived yet - the
    // membership snapshot (§6.1) created it (`seed_member`).
    state.seed_member("random", user(3, "carol"));
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == "random")
        .unwrap();
    assert!(!state.channels[state.selected_channel].joined);

    type_str(&mut state, "/leave");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert_eq!(
        state.input, "/leave",
        "left untouched on failure, same as /file - the user isn't left wondering where it went"
    );
}

/// @requirement TB-158
#[test]
fn has_reason_to_keep_link_is_true_for_a_shared_channel() {
    let state = joined_general_with(vec![user(2, "bob")]);
    assert!(state.has_reason_to_keep_link(UserId(2)));
}

/// @requirement TB-158
#[test]
fn has_reason_to_keep_link_is_true_for_dm_history() {
    let mut state = joined_general_with(vec![]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hey".into()));
    assert!(state.has_reason_to_keep_link(UserId(2)));
}

/// @requirement TB-158
#[test]
fn has_reason_to_keep_link_is_false_with_neither() {
    let state = joined_general_with(vec![]);
    assert!(!state.has_reason_to_keep_link(UserId(2)));
}


// ---------------------------------------------------------------------
// The /channels public directory (US-004)
// ---------------------------------------------------------------------

/// @requirement AC-174
#[test]
fn only_the_hall_is_joined_automatically_however_many_channels_are_offered() {
    let mut state = UiState::new("me".into());
    state.on_channel_list(vec![
        ChannelInfo {
            name: "random".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "the-hall".into(),
            kind: ChannelKind::Public,
        },
    ]);
    assert_eq!(
        state.auto_join_channel(),
        Some(UiAction::JoinChannel {
            name: "the-hall".into(),
            kind: ChannelKind::Public,
            password: None,
        }),
        "the default channel is joined even when it isn't the first offered"
    );
    assert!(
        state.channels.is_empty(),
        "nothing is a tab until its Joined confirmation arrives"
    );
}

/// @requirement AC-174
#[test]
fn nothing_is_auto_joined_once_a_channel_has_been_joined() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![ChannelInfo {
        name: "the-hall".into(),
        kind: ChannelKind::Public,
    }]);
    assert_eq!(state.auto_join_channel(), None);
}

/// @requirement TB-206
#[test]
fn an_announced_public_channel_is_listed_without_becoming_a_tab() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    }]);
    assert!(
        state
            .known_public_channels()
            .iter()
            .any(|c| c.name == "random")
    );
    assert!(!state.channels.iter().any(|c| c.name == "random"));
    assert!(state.is_joined("general"));
    assert!(!state.is_joined("random"));
}

/// @requirement TB-206
#[test]
fn rendering_before_any_channel_is_joined_does_not_panic() {
    // Reachable for real now: between the `ChannelList` snapshot and the
    // `Joined` confirmation for the-hall there are no tabs at all.
    let mut state = UiState::new("me".into());
    state.set_own_id(UserId(1));
    state.on_channel_list(vec![ChannelInfo {
        name: "the-hall".into(),
        kind: ChannelKind::Public,
    }]);
    assert!(state.channels.is_empty());
    let rows = rendered_rows(&state);
    assert!(rows.iter().any(|r| r.contains("Ctrl+H: Help")));
}

/// @requirement TB-206
#[test]
fn a_public_channel_i_created_myself_appears_in_my_own_directory() {
    // The server's ChannelCreated announcement goes to every client
    // *except* the creator, so joining is the only signal we get about a
    // channel we opened with Ctrl+J.
    let mut state = joined_general_with(vec![]);
    state.on_joined(ChannelInfo {
        name: "watercooler".into(),
        kind: ChannelKind::Public,
    });
    assert!(
        state
            .known_public_channels()
            .iter()
            .any(|c| c.name == "watercooler"),
        "a public channel I created must be listed in my own /channels"
    );
    assert!(state.is_joined("watercooler"));
}

/// @requirement AC-022
#[test]
fn a_private_channel_i_created_is_never_listed_in_the_directory() {
    let mut state = joined_general_with(vec![]);
    state.on_joined(ChannelInfo {
        name: "secret-room".into(),
        kind: ChannelKind::Private,
    });
    assert!(
        !state
            .known_public_channels()
            .iter()
            .any(|c| c.name == "secret-room"),
        "a private channel is never advertised, not even to its own author"
    );
    assert!(
        state.channels.iter().any(|c| c.name == "secret-room"),
        "it is still a tab - being in it is exactly what a tab means"
    );
}

/// @requirement TB-206
#[test]
fn the_directory_does_not_duplicate_a_channel_already_announced() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![ChannelInfo {
        name: "watercooler".into(),
        kind: ChannelKind::Public,
    }]);
    state.on_joined(ChannelInfo {
        name: "watercooler".into(),
        kind: ChannelKind::Public,
    });
    assert_eq!(
        state
            .known_public_channels()
            .iter()
            .filter(|c| c.name == "watercooler")
            .count(),
        1
    );
}

/// @requirement AC-172
#[test]
fn slash_channels_opens_the_directory_modal() {
    let mut state = joined_general_with(vec![]);
    type_str(&mut state, "/channels");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "opening the directory joins nothing by itself");
    assert_eq!(state.mode, aloo::client::tui::ui::Mode::ChannelsPopup);
    assert!(state.input.is_empty(), "the command is consumed");
}

/// @requirement AC-172
#[test]
fn escape_closes_the_directory_without_joining_anything() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    }]);
    type_str(&mut state, "/channels");
    press(&mut state, KeyCode::Enter);
    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, None);
    assert_eq!(state.mode, aloo::client::tui::ui::Mode::Normal);
}

/// @requirement AC-172
#[test]
fn the_directory_renders_a_joined_channel_in_yellow_and_the_rest_plain() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![
        ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "random".into(),
            kind: ChannelKind::Public,
        },
    ]);
    type_str(&mut state, "/channels");
    press(&mut state, KeyCode::Enter);

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    // Below the modal's own title row, so the tab row's copy of "general"
    // (a joined channel is always a tab too) can't be what's measured.
    let (_, title_y) = find_text_start(&buffer, "Public channels");
    let (x, y) = find_text_start_below(&buffer, "general", title_y);
    assert_eq!(
        buffer[(x, y)].style().fg,
        Some(ratatui::style::Color::Yellow),
        "a channel I'm in is yellow in the directory"
    );
    let (x, y) = find_text_start_below(&buffer, "random", title_y);
    assert_ne!(
        buffer[(x, y)].style().fg,
        Some(ratatui::style::Color::Yellow),
        "a channel I'm not in is not"
    );
}

/// @requirement AC-173
#[test]
fn enter_in_the_directory_joins_the_selected_channel() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![
        ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "random".into(),
            kind: ChannelKind::Public,
        },
    ]);
    type_str(&mut state, "/channels");
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::JoinChannel {
            name: "random".into(),
            kind: ChannelKind::Public,
            password: None,
        })
    );
    assert_eq!(state.mode, aloo::client::tui::ui::Mode::Normal);
}

/// @requirement AC-173
#[test]
fn the_directory_selection_wraps_in_both_directions() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![
        ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "random".into(),
            kind: ChannelKind::Public,
        },
    ]);
    type_str(&mut state, "/channels");
    press(&mut state, KeyCode::Enter);
    press(&mut state, KeyCode::Up);
    assert_eq!(state.channels_popup_selected, 1, "Up wraps to the last row");
    press(&mut state, KeyCode::Down);
    assert_eq!(state.channels_popup_selected, 0);
}

/// @requirement TB-206
#[test]
fn enter_on_a_channel_i_am_already_in_selects_its_tab_instead_of_rejoining() {
    let mut state = joined_general_with(vec![]);
    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    state.on_channel_list(vec![
        ChannelInfo {
            name: "general".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "random".into(),
            kind: ChannelKind::Public,
        },
    ]);
    state.selected_channel = 1;
    type_str(&mut state, "/channels");
    press(&mut state, KeyCode::Enter);
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "already a member - no join is sent");
    assert_eq!(state.selected_channel, 0, "its tab is brought to the front");
}

/// @requirement AC-109
#[test]
fn a_left_public_channel_stays_in_the_directory_to_rejoin_from() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    state.leave_channel_locally("general");
    assert!(state.channels.is_empty());
    assert!(
        state
            .known_public_channels()
            .iter()
            .any(|c| c.name == "general")
    );
    assert!(!state.is_joined("general"));
}

/// @requirement AC-172
#[test]
fn rendering_the_directory_with_nothing_announced_does_not_panic() {
    // In a channel, but no *public* one: a private channel is never
    // advertised, so nothing has reached the directory yet.
    let mut state = UiState::new("me".into());
    state.set_own_id(UserId(1));
    state.on_joined(ChannelInfo {
        name: "secret-room".into(),
        kind: ChannelKind::Private,
    });
    assert!(state.known_public_channels().is_empty());
    type_str(&mut state, "/channels");
    press(&mut state, KeyCode::Enter);
    let rows = rendered_rows(&state);
    assert!(rows.join("").contains("no public channels announced yet"));
}

/// @requirement AC-140
#[test]
fn an_unrecognized_slash_command_is_never_sent_as_channel_text() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/nonsense");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "an unrecognized command must never produce a send action");
    assert!(state.input.is_empty());
    assert_eq!(
        state.status_notice,
        Some(("unknown command: /nonsense".to_string(), false))
    );
    assert!(state.channels[0].log.is_empty());
}

/// @requirement AC-283
#[test]
fn slash_clear_empties_the_current_channels_log() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    push_n_channel_texts(&mut state, 3);
    assert!(!state.channels[0].log.is_empty());

    type_str(&mut state, "/clear");
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(action, None);
    assert!(state.channels[0].log.is_empty());
    assert_eq!(state.message_selected, 0);
    assert!(state.input.is_empty());
    assert_eq!(
        state.status_notice,
        Some(("cleared this screen's messages".to_string(), true))
    );
}

/// `/clear` must only ever reach the screen that's actually open - a
/// second, unrelated channel's history is exactly what it must leave
/// alone.
///
/// @requirement AC-283
#[test]
fn slash_clear_does_not_touch_a_different_channels_log() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    push_n_channel_texts(&mut state, 2);
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == "random")
        .unwrap();
    type_str(&mut state, "/clear");
    press(&mut state, KeyCode::Enter);

    assert!(state.channels.iter().find(|c| c.name == "random").unwrap().log.is_empty());
    assert!(
        !state.channels.iter().find(|c| c.name == "general").unwrap().log.is_empty(),
        "clearing one channel must not empty a different one"
    );
}

/// @requirement AC-284
#[test]
fn slash_clear_all_empties_every_channel_and_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    push_n_channel_texts(&mut state, 2);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    assert!(!state.private_rooms.get(&UserId(2)).unwrap().log.is_empty());

    type_str(&mut state, "/clear-all");
    let action = press(&mut state, KeyCode::Enter);

    assert_eq!(action, None);
    assert!(state.channels.iter().all(|c| c.log.is_empty()));
    assert!(state.private_rooms.values().all(|r| r.log.is_empty()));
    assert_eq!(state.message_selected, 0);
    assert!(state.input.is_empty());
    assert_eq!(
        state.status_notice,
        Some(("cleared every screen's messages".to_string(), true))
    );
}

/// Joining a channel is a request to go there: it becomes the one the
/// channel selector names, and the view, so the compose bar is already
/// addressed to it (`docs/SPEC.md` Functionality #2).
///
/// @requirement AC-189
#[test]
fn joining_a_channel_lands_the_selector_on_it() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert_eq!(state.selected_channel, 0);

    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    assert_eq!(
        state.channels[state.selected_channel].name, "random",
        "the channel just joined is the one on screen"
    );
    let top = sidebar_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains("random"), "{top:?}");
}

/// Joining from inside a DM room leaves that room for the new channel -
/// the room stays on the DM selector, as any move to the channel selector
/// leaves it.
///
/// @requirement AC-189
#[test]
fn joining_a_channel_from_a_dm_room_leaves_the_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    assert!(state.active_private_room.is_some());

    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    assert_eq!(state.active_private_room, None);
    assert_eq!(state.selected_dm, Some(UserId(2)), "still on the DM selector");
    assert_eq!(state.channels[state.selected_channel].name, "random");
}

/// The focus highlight covers the selector's own name, and stops before
/// the unread envelope: reversing a glyph paints a block of background
/// around it (`docs/SPEC.md` "Connected UI").
///
/// @requirement AC-187
#[test]
fn the_unread_envelope_is_left_out_of_the_focus_highlight() {
    let mut state = joined_public(&["general", "random"]);
    state.seed_member("random", user(2, "bob"));
    state.on_channel_message(
        "random",
        UserId(2),
        "bob".into(),
        MessageBody::Text("over here".into()),
    );
    state.blink_on = true;

    let backend = TestBackend::new(100, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (nx, ny) = find_text_start_below(&buffer, "general", 0);
    assert!(
        buffer[(nx, ny)]
            .modifier
            .contains(ratatui::style::Modifier::REVERSED),
        "the focused selector's own name is highlighted"
    );
    let (ex, ey) = find_text_start_below(&buffer, "\u{2709}", 0);
    assert!(
        !buffer[(ex, ey)]
            .modifier
            .contains(ratatui::style::Modifier::REVERSED),
        "but the envelope beside it is not"
    );

    // Nor is the count of what the selector is not naming - grey, and
    // never behind a block of background.
    let (mx, my) = find_text_start_below(&buffer, "+1 more...", 0);
    assert!(
        !buffer[(mx, my)]
            .modifier
            .contains(ratatui::style::Modifier::REVERSED),
        "the +<n> more... count is left out of the highlight"
    );
    assert_eq!(
        buffer[(mx, my)].fg,
        ratatui::style::Color::DarkGray,
        "and stays grey"
    );
}

/// Tab is about the view *behind* the overlay (sidebar, log, compose bar),
/// so reaching for it means being done with the dropdown: it closes,
/// rather than cycling focus underneath (`docs/SPEC.md` "Connected UI").
///
/// @requirement AC-020
#[test]
fn tab_closes_an_open_dropdown_instead_of_cycling_focus() {
    let mut state = joined_public(&["general", "random"]);
    state.focus = Focus::Input;
    press(&mut state, KeyCode::Char('['));
    assert!(state.selector_dropdown_open);

    press(&mut state, KeyCode::Tab);
    assert!(!state.selector_dropdown_open, "Tab closes it");
    assert_eq!(
        state.focus,
        Focus::Input,
        "and leaves the focus underneath where it was"
    );

    // With nothing open it goes back to being the ordinary focus cycle.
    press(&mut state, KeyCode::Tab);
    assert_eq!(state.focus, Focus::Sidebar);
}

/// An overlay left open and forgotten would sit on top of the messages
/// arriving underneath, so an idle one folds itself away
/// (`SELECTOR_DROPDOWN_IDLE_TIMEOUT`).
///
/// @requirement AC-020
#[test]
fn an_idle_dropdown_closes_itself_after_the_timeout() {
    use std::time::{Duration, Instant};
    let mut state = joined_public(&["general", "random", "lobby"]);
    press(&mut state, KeyCode::Char('['));
    let now = Instant::now();

    state.tick_selector_dropdown(now);
    assert!(state.selector_dropdown_open, "still fresh");
    state.tick_selector_dropdown(now + Duration::from_secs(29));
    assert!(state.selector_dropdown_open, "just under the timeout");
    state.tick_selector_dropdown(now + SELECTOR_DROPDOWN_IDLE_TIMEOUT);
    assert!(!state.selector_dropdown_open, "closed at the timeout");
    assert_eq!(
        state.selected_channel, 0,
        "timing out keeps whatever was selected, like every other close"
    );

    // Driving the list is what "not idle" means: each Up/Down restarts it.
    press(&mut state, KeyCode::Char('['));
    press(&mut state, KeyCode::Down);
    state.tick_selector_dropdown(Instant::now() + Duration::from_secs(29));
    assert!(state.selector_dropdown_open, "the step restarted the clock");
}

// ---------------------------------------------------------------------
// Muted voices in the sidebar (SPEC.md Functionality #16)
// ---------------------------------------------------------------------

/// Without a marker, a channel that has gone quiet because someone is
/// muted looks exactly like one where nobody is talking.
/// @requirement AC-197
#[test]
fn a_muted_member_is_marked_in_the_sidebar() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.set_muted_voice(["bob".to_string()].into_iter().collect());

    let rows = sidebar_rows(&state);
    let bob = row_containing(&rows, "bob");
    let carol = row_containing(&rows, "carol");

    assert!(
        bob.contains('\u{1F507}'),
        "a muted member must be marked: {bob:?}"
    );
    assert!(
        !carol.contains('\u{1F507}'),
        "an unmuted member must not be: {carol:?}"
    );
}

/// @requirement AC-197
#[test]
fn unmuting_clears_the_sidebar_marker() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.set_muted_voice(["bob".to_string()].into_iter().collect());
    assert!(row_containing(&sidebar_rows(&state), "bob").contains('\u{1F507}'));

    state.set_muted_voice(Default::default());
    assert!(!row_containing(&sidebar_rows(&state), "bob").contains('\u{1F507}'));
}

/// An empty channel with no server behind it is one waiting to be punched
/// into, not an idle one - and nothing else is coming to say so (no roster
/// arrives, no presence notice). See docs/PROTOCOL.md §7.1.5.
///
/// @requirement AC-220
#[test]
fn an_empty_channel_without_a_server_says_it_is_waiting_for_direct_peers() {
    let mut state = UiState::new("alice".into());
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    state.serverless = true;

    let rows = sidebar_rows(&state);
    let joined = rows.join("\n");
    assert!(
        joined.contains("Waiting for other users"),
        "an empty serverless channel must explain itself: {joined}"
    );
}

/// The same channel with a server behind it is simply empty: a roster is
/// on its way, so inventing an explanation would be wrong.
///
/// @requirement AC-220
#[test]
fn an_empty_channel_with_a_server_says_nothing_extra() {
    let mut state = UiState::new("alice".into());
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    state.serverless = false;

    let joined = sidebar_rows(&state).join("\n");
    assert!(
        !joined.contains("Waiting for other users"),
        "a server-backed session must not claim to be waiting on direct peers: {joined}"
    );
}

/// Once someone is actually there, the waiting line goes away rather than
/// sitting above a populated conversation.
///
/// @requirement AC-220
#[test]
fn the_waiting_line_disappears_once_a_direct_peer_is_present() {
    let mut state = UiState::new("alice".into());
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    state.serverless = true;
    state.seed_member("general", user(2, "bob"));

    let joined = sidebar_rows(&state).join("\n");
    assert!(
        !joined.contains("Waiting for other users"),
        "the waiting line must not outlive the wait: {joined}"
    );
    assert!(joined.contains("bob"));
}

// ---------------------------------------------------------------------
// Delivery acknowledgments in a channel (US-041)
// ---------------------------------------------------------------------

/// Sends one text into `general` through the real compose path, handing
/// back the delivery tag both the row and the wire send carry.
fn send_to_general(state: &mut UiState, text: &str) -> u64 {
    type_str(state, text);
    match press(state, KeyCode::Enter).expect("a send was produced") {
        UiAction::SendChannelText { msg_id, .. } => msg_id,
        other => panic!("expected SendChannelText, got {other:?}"),
    }
}

/// A channel row is one row over many recipients, which is why it has a
/// third state a DM row can never reach.
/// @requirement AC-231
#[test]
fn a_channel_message_reads_orange_once_only_some_recipients_have_it() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    let msg_id = send_to_general(&mut state, "morning both");
    let status = |s: &UiState| s.channels[0].log[0].delivery_status();

    assert_eq!(status(&state), Some(DeliveryStatus::None));
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        status(&state),
        Some(DeliveryStatus::Some),
        "one of two recipients is partway, not delivered"
    );
    state.mark_delivered(UserId(3), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(status(&state), Some(DeliveryStatus::All));
}

/// @requirement AC-231
#[test]
fn a_channel_message_addressed_to_nobody_is_not_delivered() {
    let mut state = joined_general_with(vec![]);
    send_to_general(&mut state, "anyone there");
    let entry = &state.channels[0].log[0];

    assert_eq!(
        entry.delivery_status(),
        Some(DeliveryStatus::None),
        "nothing was acknowledged because nothing went anywhere"
    );
    assert!(entry.reached_nobody());
}

/// The strike is drawn rather than styled: ratatui's `CROSSED_OUT` is an
/// ANSI attribute plenty of terminals ignore, so the row carries a
/// combining overlay per character instead.
/// @requirement AC-231
#[test]
fn a_message_that_reached_nobody_is_struck_through() {
    let mut state = joined_general_with(vec![]);
    send_to_general(&mut state, "anyone there");

    let rows = rendered_rows(&state);
    assert!(
        rows.iter()
            .any(|r| r.contains(&strike_through("anyone there"))),
        "the row must be drawn struck through: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("anyone there")),
        "and not additionally drawn plainly anywhere"
    );
}

/// @requirement AC-231
#[test]
fn a_message_that_reached_somebody_is_not_struck_through() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    send_to_general(&mut state, "morning");
    assert!(!state.channels[0].log[0].reached_nobody());

    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("morning")),
        "a message that did reach somebody is drawn plainly: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// A dropdown longer than the screen (docs/SPEC.md "Connected UI")
// ---------------------------------------------------------------------

/// A client in more channels than the terminal has rows must still be able
/// to walk the whole list: the dropdown stops at the bottom edge and
/// scrolls inside it, rather than drawing off-screen rows that are simply
/// lost.
/// @requirement AC-238
#[test]
fn a_dropdown_taller_than_the_screen_stops_at_the_bottom_edge_and_scrolls() {
    let names: Vec<String> = (0..30).map(|i| format!("channel-{i:02}")).collect();
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let mut state = joined_public(&refs);
    press(&mut state, KeyCode::Char('['));

    let (height, width) = (14u16, 60u16);
    let buffer = buffer_at(&state, width, height);
    let (_, y, _, popup_height) = popup_rect(&buffer, "Channels");
    assert_eq!(
        y, HEADER_ROW_HEIGHT,
        "the dropdown still hangs off the bottom of the header block"
    );
    assert!(
        y + popup_height <= height,
        "it must not run off the bottom of the screen ({y} + {popup_height} > {height})"
    );

    // What does not fit is reachable rather than lost: the list is
    // scrolled to keep the row the selection sits at in view.
    let rows = popup_body(&buffer, "Channels");
    assert!(
        rows.iter().any(|r| r.contains("channel-01")),
        "the top of a list at its start is showing: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains(['\u{2591}', '\u{2588}'])),
        "an overflowing dropdown carries a scrollbar: {rows:?}"
    );

    // Step to the far end of the list (Up wraps): the selection is then
    // `channel-29`, which the dropdown no longer lists - but the rows
    // around where it came out of the list are on screen, which they
    // could not be without the list having scrolled to them.
    press(&mut state, KeyCode::Up);
    assert_eq!(state.channels[state.selected_channel].name, "channel-29");
    let rows = popup_body(&buffer_at(&state, width, height), "Channels");
    assert!(
        rows.iter().any(|r| r.contains("channel-28")),
        "the far end of the list is reachable: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("channel-00")),
        "and the list really moved rather than just growing: {rows:?}"
    );
}

/// A list that fits gives up no column to a scrollbar that would be
/// full-height anyway.
/// @requirement AC-238
#[test]
fn a_dropdown_that_fits_carries_no_scrollbar() {
    let mut state = joined_public(&["general", "random", "lobby"]);
    press(&mut state, KeyCode::Char('['));

    let rows = popup_body(&buffer_at(&state, 60, 30), "Channels");
    assert!(
        !rows.iter().any(|r| r.contains(['\u{2591}', '\u{2588}'])),
        "nothing to scroll, so no scrollbar: {rows:?}"
    );
}

/// A dropdown hangs under the selector it belongs to, not at the screen's
/// left edge: the header row opens with the server-state element, so a
/// dropdown positioned from the selector's own offset alone would land in
/// the wrong place entirely.
/// @requirement AC-238
#[test]
fn each_selector_dropdown_hangs_under_the_selector_it_belongs_to() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.on_joined(aloo::proto::ChannelInfo {
        name: "random".into(),
        kind: aloo::proto::ChannelKind::Public,
    });
    state.select_channel_at(0);
    // Two rooms open, so both selectors have something to drop down.
    for row in [0, 1] {
        state.focus = Focus::Sidebar;
        state.sidebar_selected = row;
        press(&mut state, KeyCode::Enter);
    }

    // The channel selector's own dropdown, under the channel selector.
    press(&mut state, KeyCode::Char('['));
    press(&mut state, KeyCode::Char('['));
    assert!(state.selector_dropdown_open, "the channel dropdown should be open");
    let buffer = buffer_at(&state, 120, 20);
    let (channel_x, _) = find_text_start(&buffer, "#general");
    let (dropdown_x, dropdown_y, ..) = popup_rect(&buffer, "Channels");
    assert_eq!(
        dropdown_y as usize, FIRST_ROW_BELOW_HEADER,
        "it still hangs off the bottom of the header block"
    );
    assert_eq!(
        dropdown_x, channel_x,
        "the channel dropdown lines up with the channel selector, \
         not with the left edge of the screen"
    );
    assert!(
        dropdown_x > 0,
        "and the header opens with the server state, so that column is not 0"
    );

    // The DM selector's, under the DM selector - a different column again.
    press(&mut state, KeyCode::Esc);
    press(&mut state, KeyCode::Char(']'));
    press(&mut state, KeyCode::Char(']'));
    assert!(state.selector_dropdown_open, "the DM dropdown should be open");
    let buffer = buffer_at(&state, 120, 20);
    let (dm_x, _) = find_text_start(&buffer, "\u{1F4AC}");
    let (dropdown_x, ..) = popup_rect(&buffer, "DMs");
    assert_eq!(
        dropdown_x, dm_x,
        "the DM dropdown lines up with the DM selector"
    );
    assert!(
        dm_x > channel_x,
        "which is further right than the channel one it sits beside"
    );
}

// ---------------------------------------------------------------------
// Encryption tags in the user list, and the OTP one (docs/SPEC.md
// "Connected UI")
// ---------------------------------------------------------------------

/// Every tag ends on the sidebar's own right edge, so they read as a
/// column of their own rather than starting wherever each nickname
/// happened to end - with the person still on the left.
/// @requirement AC-245
#[test]
fn the_user_lists_encryption_tags_are_flush_right_with_the_names_on_the_left() {
    let mut state = joined_general_with(vec![
        pq_hybrid_user(2, "bo"),
        pq_hybrid_user(3, "bartholomew"),
    ]);
    state.select_channel_at(0);

    let buffer = buffer_at(&state, 100, 14);
    let rows = popup_body(&buffer, "Users");
    let tagged: Vec<&String> = rows.iter().filter(|r| r.contains("PQH")).collect();
    assert_eq!(tagged.len(), 2, "one row per member: {rows:?}");

    for row in &tagged {
        let chars: Vec<char> = row.chars().collect();
        let last = chars
            .iter()
            .rposition(|c| !c.is_whitespace())
            .expect("a tag on this row");
        assert_eq!(
            last + 1,
            chars.len(),
            "the tag runs to the sidebar's right edge: {row:?}"
        );
    }
    // The names of both lengths still start in column zero.
    for (row, name) in tagged.iter().zip(["bo", "bartholomew"]) {
        assert!(
            row.starts_with(name),
            "the person stays on the left: {row:?} should start with {name:?}"
        );
    }
}

/// A pad session replaces that person's own tag with the OTP one, in the
/// user list and on both DM surfaces - the pad is what actually protects
/// what is said to them, and it only ever runs over pq_hybrid, so the tag
/// it displaces is always the same one.
/// @requirement AC-246
#[test]
fn an_otp_session_replaces_that_peers_tag_everywhere_they_are_named() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob"), pq_hybrid_user(3, "carol")]);
    state.select_channel_at(0);
    for row in [0, 1] {
        state.focus = Focus::Sidebar;
        state.sidebar_selected = row;
        press(&mut state, KeyCode::Enter);
    }
    state.mark_otp_active(UserId(2));

    // Back on the channel view - opening those rooms left the last one
    // showing, and the user list belongs to a channel.
    press(&mut state, KeyCode::Char('['));
    // The user list: bob's row carries OTP instead of PQH, carol's is
    // untouched.
    state.focus = Focus::Sidebar;
    let buffer = buffer_at(&state, 100, 14);
    let rows = popup_body(&buffer, "Users");
    let row_of = |name: &str| -> String {
        rows.iter()
            .find(|r| r.contains(name))
            .unwrap_or_else(|| panic!("no row for {name}: {rows:?}"))
            .clone()
    };
    assert!(
        row_of("bob").contains("OTP") && !row_of("bob").contains("PQH"),
        "the pad replaces the my_key tag rather than joining it: {rows:?}"
    );
    assert!(
        row_of("carol").contains("PQH") && !row_of("carol").contains("OTP"),
        "and only for the peer the session is with: {rows:?}"
    );

    // The DM selector, while it names bob.
    press(&mut state, KeyCode::Char(']'));
    press(&mut state, KeyCode::Char(']'));
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Char(']'));
    let header = rendered_rows_at(&state, 120, 14).remove(HEADER_TEXT_ROW);
    assert!(header.contains("bob"), "the selector should name bob: {header:?}");
    assert!(
        appears_before(std::slice::from_ref(&header), "bob", "OTP"),
        "the DM selector carries the tag after the nickname: {header:?}"
    );

    // And the dropdown row for the peer it is not naming.
    press(&mut state, KeyCode::Char(']'));
    press(&mut state, KeyCode::Down);
    press(&mut state, KeyCode::Char(']'));
    let buffer = buffer_at(&state, 120, 14);
    let rows = popup_body(&buffer, "DMs");
    let bob = rows
        .iter()
        .find(|r| r.contains("bob"))
        .unwrap_or_else(|| panic!("no dropdown row for bob: {rows:?}"));
    assert!(
        appears_before(std::slice::from_ref(bob), "bob", "OTP"),
        "the dropdown row carries it too: {bob:?}"
    );
}

/// The tag is drawn in the same cyan the room's own OTP session header
/// uses, so the two read as one fact rather than two.
/// @requirement AC-246
#[test]
fn the_otp_tag_is_drawn_in_the_session_headers_own_colour() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.select_channel_at(0);
    state.mark_otp_active(UserId(2));

    let buffer = buffer_at(&state, 100, 14);
    let (x, y) = find_text_start(&buffer, "OTP");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Cyan);
}

/// A channel is named `#name` wherever it can be picked, and a `#` typed
/// into the join form is that same decoration rather than part of the
/// name - so someone can type a channel exactly the way they just read it.
/// @requirement AC-247
#[test]
fn a_channel_is_shown_with_a_hash_and_a_typed_one_is_ignored() {
    let mut state = joined_public(&["general", "random"]);

    let header = rendered_rows_at(&state, 120, 14).remove(HEADER_TEXT_ROW);
    assert!(
        header.contains("#general"),
        "the channel selector names it with the hash: {header:?}"
    );
    press(&mut state, KeyCode::Char('['));
    let rows = popup_body(&buffer_at(&state, 120, 14), "Channels");
    assert!(
        rows.iter().any(|r| r.contains("#random")),
        "and so does its dropdown: {rows:?}"
    );
    press(&mut state, KeyCode::Esc);

    // Typed into the join form, the hash is accepted and then ignored:
    // what is asked for is the bare name the server knows.
    ctrl(&mut state, KeyCode::Char('j'));
    type_str(&mut state, "#secret-room");
    assert_eq!(
        state.join_popup_input, "#secret-room",
        "it is shown while typing, the way the channel itself is shown"
    );
    match press(&mut state, KeyCode::Enter) {
        Some(UiAction::JoinChannel { name, .. }) => assert_eq!(name, "secret-room"),
        other => panic!("expected a join for the bare name, got {other:?}"),
    }
}

/// Only in the first position: anywhere else a `#` is a genuine mistake,
/// and refusing the keystroke says so straight away.
/// @requirement AC-247
#[test]
fn a_hash_typed_anywhere_but_the_front_is_refused() {
    let mut state = joined_public(&["general"]);
    ctrl(&mut state, KeyCode::Char('j'));
    type_str(&mut state, "sec#ret");
    assert_eq!(
        state.join_popup_input, "secret",
        "the stray hash never reaches the field"
    );
}

#[test]
#[ignore]
fn zz_scratch_voice() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.select_channel_at(0);
    let (_msg_id, delivery) = state.start_delivery(&[UserId(2)]);
    state.log_own_voice_stream_start_channel("general", 7, Some(delivery));
    println!("after start: {:?}", state.channels[0].log.last().map(|e| (&e.body, e.from)));
    println!("own_id: {:?}", state.own_id);
    state.on_channel_stream_finished("general", UserId(1), 7, 1000, vec![0u8; 4]);
    println!("after finish: {:?}", state.channels[0].log.last().map(|e| &e.body));
}

// ---------------------------------------------------------------------
// A peer who reconnects (docs/SPEC.md Functionality #7)
// ---------------------------------------------------------------------

/// A `UserId` is per-connection and never reused, so someone who
/// reconnects arrives as a stranger by id. They must still take their own
/// row back rather than appearing beside the gray one they left behind.
/// @requirement AC-248
#[test]
fn a_peer_who_reconnects_takes_their_own_row_back() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.select_channel_at(0);
    // Something in bob's room, so he is kept listed while offline.
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.on_user_offline(UserId(2));
    assert!(state.offline.contains(&UserId(2)));
    assert_eq!(state.channels[0].members.len(), 2, "still listed while offline");
    let position = state.channels[0]
        .members
        .iter()
        .position(|m| m.name == "bob")
        .expect("bob is listed");

    // Back, under a fresh id the server just handed out.
    state.on_user_joined("general", user(9, "bob"));

    let names: Vec<&str> = state.channels[0].members.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        names.iter().filter(|n| **n == "bob").count(),
        1,
        "one bob, not two: {names:?}"
    );
    assert_eq!(
        state.channels[0].members[position].id,
        UserId(9),
        "the row he had is the row he takes back, in place"
    );
    assert!(
        !state.offline.contains(&UserId(2)) && !state.offline.contains(&UserId(9)),
        "and he is no longer offline under either id"
    );
    assert!(
        !state.known_users.contains_key(&UserId(2)),
        "the id he is no longer known by is dropped"
    );
}

/// The conversation continues in the same window: one room, its whole
/// history, still where it was on the DM selector.
/// @requirement AC-248
#[test]
fn a_reconnecting_peers_dm_room_continues_rather_than_starting_again() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.select_channel_at(0);
    for row in [0, 1] {
        state.focus = Focus::Sidebar;
        state.sidebar_selected = row;
        press(&mut state, KeyCode::Enter);
    }
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("before".into()));
    let order_before = state.dm_order.clone();

    state.on_user_offline(UserId(2));
    state.on_user_joined("general", user(9, "bob"));

    assert_eq!(state.dm_order.len(), order_before.len(), "no second room opened");
    assert_eq!(
        state.dm_order,
        order_before
            .iter()
            .map(|id| if *id == UserId(2) { UserId(9) } else { *id })
            .collect::<Vec<_>>(),
        "the room keeps its place on the selector"
    );
    let room = state
        .private_rooms
        .get(&UserId(9))
        .expect("the room moved onto the id he has now");
    assert_eq!(room.peer.id, UserId(9), "and it names him by that id");
    assert!(
        room.log.iter().any(|e| matches!(&e.body, MessageBody::Text(t) if t == "before")),
        "with everything said before he left still in it"
    );
    assert!(!state.private_rooms.contains_key(&UserId(2)));
}

/// A pad session survives a reconnect - only `/endotp` ever ends one
/// (`docs/PROTOCOL.md` §16.6) - so it moves across with the room.
/// @requirement AC-248
#[test]
fn a_pad_session_follows_a_peer_across_a_reconnect() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.select_channel_at(0);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.mark_otp_active(UserId(2));

    state.on_user_offline(UserId(2));
    state.on_user_joined("general", pq_hybrid_user(9, "bob"));

    assert!(state.is_otp_active(UserId(9)), "the session is still on");
    assert!(!state.is_otp_active(UserId(2)));
}

/// Two people who were never the same person stay separate - adoption is
/// by nickname, and only for a nickname this session actually saw go
/// offline.
/// @requirement AC-248
#[test]
fn a_different_nickname_is_never_adopted_and_neither_is_a_peer_still_online() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.select_channel_at(0);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.on_user_offline(UserId(2));

    // A different person joining takes nobody's row.
    state.on_user_joined("general", user(9, "carol"));
    assert!(state.private_rooms.contains_key(&UserId(2)), "bob's room is untouched");
    assert!(state.offline.contains(&UserId(2)));

    // And a second connection under a nickname nobody saw leave is not an
    // adoption either.
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.select_channel_at(0);
    state.on_user_joined("general", user(9, "bob"));
    assert_eq!(
        state.channels[0].members.len(),
        2,
        "nothing was offline, so nothing was taken over"
    );
}
