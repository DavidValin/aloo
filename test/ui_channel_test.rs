#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::netstats::ConnQuality;
use aloo::client::p2p::LinkStatus;
use aloo::proto::{ChannelInfo, ChannelKind, KeyMode, UserId};
use aloo::client::tui::channel::DWELL_DURATION;
use aloo::client::tui::ui::{Focus, IdentityCase, MessageBody, UiAction, UiState, VoiceTarget, render};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::time::{Duration, Instant};

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

// ---------------------------------------------------------------------
// Applying server events
// ---------------------------------------------------------------------

/// @requirement AC-018, TB-024
#[test]
fn channel_list_adds_unjoined_channels_without_duplicating() {
    let mut state = UiState::new("me".into());
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    assert_eq!(state.channels.len(), 1);
    assert!(!state.channels[0].joined);
}

/// @requirement TB-024
#[test]
fn on_joined_marks_existing_channel_joined_or_creates_it() {
    let mut state = UiState::new("me".into());
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
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

/// @requirement TB-159
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
        } => {
            assert_eq!(channel, "general");
            assert_eq!(plaintext, "hello all");
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
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
                vec![(UserId(2), KeyMode::Rsa, user(2, "bob").public_key_der)]
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
                vec![(UserId(2), KeyMode::Rsa, user(2, "bob").public_key_der)]
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
// [ / ] dwell-to-join
// ---------------------------------------------------------------------

/// @requirement AC-020
#[test]
fn bracket_key_selects_next_channel_immediately_but_does_not_join_yet() {
    let mut state = UiState::new("me".into());
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
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    assert_eq!(state.selected_channel, 0);

    press(&mut state, KeyCode::Char(']'));
    assert_eq!(
        state.selected_channel, 1,
        "] switches selection immediately"
    );
    assert!(!state.channels[1].joined, "but hasn't joined yet");

    let too_soon = state.tick_dwell(Instant::now());
    assert_eq!(too_soon, None);
}

/// @requirement AC-020
#[test]
fn opening_bracket_selects_the_previous_channel() {
    let mut state = UiState::new("me".into());
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
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    assert_eq!(state.selected_channel, 0);

    press(&mut state, KeyCode::Char('['));
    assert_eq!(
        state.selected_channel, 1,
        "[ wraps around to the previous (last) channel"
    );
}

/// @requirement AC-020
#[test]
fn dwell_fires_join_after_three_seconds() {
    let mut state = UiState::new("me".into());
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
    press(&mut state, KeyCode::Char(']'));
    let started = Instant::now();
    let later = started + DWELL_DURATION + Duration::from_millis(1);

    let action = state.tick_dwell(later);
    assert_eq!(
        action,
        Some(UiAction::JoinChannel {
            name: "random".into(),
            kind: ChannelKind::Public,
            password: None
        })
    );
}

/// @requirement TB-025
#[test]
fn dwell_does_not_refire_for_an_already_joined_channel() {
    let mut state = UiState::new("me".into());
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
    press(&mut state, KeyCode::Char(']'));
    state.on_joined(ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    });
    let later = Instant::now() + DWELL_DURATION + Duration::from_millis(1);
    assert_eq!(state.tick_dwell(later), None);
}

/// @requirement TB-026
#[test]
fn switching_tabs_closes_any_open_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_channel_list(vec![ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    }]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    assert!(state.active_private_room.is_some());

    press(&mut state, KeyCode::Char(']'));
    assert_eq!(state.active_private_room, None);
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
    state.log_own_voice_stream_start_channel("general", 7);
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
        user(2, "bob"), // KeyMode::Rsa
        per_msg_user(3, "carol"),
        password_user(4, "dan"),
        plain_user(5, "eve"),
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
        appears_before(&rows, "bob", "RSA"),
        "expected bob's tag rendered after his name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "carol", "RSAPM"),
        "expected carol's tag rendered after her name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "dan", "PWD"),
        "expected dan's tag rendered after his name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "eve", "PLAIN"),
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

    let row = row_containing(&sidebar_rows(&state), "bob");
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
        let row = row_containing(&sidebar_rows(&state), "bob");
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
    let row = row_containing(&sidebar_rows(&state), "bob");
    assert!(
        row.contains('\u{2709}'),
        "expected the envelope visible on the blink-on frame: {row:?}"
    );

    state.blink_on = false;
    let row = row_containing(&sidebar_rows(&state), "bob");
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
        let row = row_containing(&sidebar_rows(&state), "bob");
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

    let (bx, by) = find_text_start(&buffer, "bob");
    assert_eq!(
        buffer[(bx, by)].fg,
        ratatui::style::Color::DarkGray,
        "offline member should render in soft gray"
    );

    let (cx, cy) = find_text_start(&buffer, "carol");
    assert_eq!(
        buffer[(cx, cy)].fg,
        ratatui::style::Color::Green,
        "still-connected member should stay green"
    );
}

/// The sidebar's colour is the state of the *direct link* to each person,
/// not merely their presence on the server (AC-135): someone can be
/// perfectly online and completely unreachable, which is exactly the case
/// worth showing. Green once messages can actually reach them, red once
/// they can't, yellow while the punch is still being worked out.
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
        ("carol", ratatui::style::Color::Red),
        ("dave", ratatui::style::Color::Yellow),
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
        ratatui::style::Color::Yellow,
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
    let header = rows.first().expect("header row");
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
    let header = rows.first().expect("header row");
    assert!(
        header.contains("Conn:GOOD  CPU:24%"),
        "expected Conn right before CPU: {header:?}"
    );
}

/// @requirement AC-072
#[test]
fn header_defaults_conn_quality_to_a_white_dash_before_any_traffic() {
    let state = joined_general_with(vec![]);
    assert_eq!(state.conn_quality, ConnQuality::Unknown);
    let rows = rendered_rows(&state);
    let header = rows.first().expect("header row");
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

    let (bx, by) = find_text_start(&buffer, "bob");
    assert_eq!(
        buffer[(bx, by)].fg,
        ratatui::style::Color::Red,
        "a trust-gated member renders red even while also offline"
    );
    let (cx, cy) = find_text_start(&buffer, "carol");
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
    state.on_channel_list(vec![
        ChannelInfo {
            name: "the-hall".into(),
            kind: ChannelKind::Public,
        },
        ChannelInfo {
            name: "secret-room".into(),
            kind: ChannelKind::Private,
        },
    ]);
    let rows = sidebar_rows(&state);
    let tab_row = row_containing(&rows, "the-hall");
    assert!(
        tab_row.contains('\u{1F30D}'),
        "public channel tab should show the globe emoji: {tab_row:?}"
    );
    assert!(
        tab_row.contains("the-hall"),
        "public channel tab should still show its name: {tab_row:?}"
    );
    assert!(
        tab_row.contains('\u{1F512}'),
        "private channel tab should show the lock emoji: {tab_row:?}"
    );
    assert!(
        tab_row.contains("secret-room"),
        "private channel tab should still show its name: {tab_row:?}"
    );
    // the globe must precede its own channel's name, not merely appear
    // somewhere on the same row as the private channel's lock.
    assert!(
        tab_row.find('\u{1F30D}').unwrap() < tab_row.find("the-hall").unwrap(),
        "globe emoji should prefix the public channel's name: {tab_row:?}"
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

// ---------------------------------------------------------------------
// Leaving a channel (US-026)
// ---------------------------------------------------------------------

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

#[test]
fn slash_leave_on_a_public_channel_keeps_the_tab_but_marks_it_left() {
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
    let tab = state
        .channels
        .iter()
        .find(|c| c.name == "general")
        .expect("tab kept");
    assert!(!tab.joined);
    assert!(tab.left);
    assert!(tab.members.is_empty());
}

/// @requirement AC-109
#[test]
fn slash_leave_is_a_noop_when_the_selected_channel_is_not_joined() {
    let mut state = joined_general_with(vec![]);
    state.on_channel_list(vec![ChannelInfo {
        name: "random".into(),
        kind: ChannelKind::Public,
    }]);
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

/// @requirement AC-110
#[test]
fn left_channel_screen_enter_requests_rejoin() {
    let mut state = joined_general_with(vec![]);
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == "general")
        .unwrap();
    state.leave_channel_locally("general");

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        })
    );
}

/// @requirement AC-110
#[test]
fn left_channel_screen_ignores_keys_other_than_enter() {
    let mut state = joined_general_with(vec![]);
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == "general")
        .unwrap();
    state.leave_channel_locally("general");

    assert_eq!(press(&mut state, KeyCode::Char('x')), None);
    assert_eq!(press(&mut state, KeyCode::Tab), None);
}

/// @requirement AC-110
#[test]
fn render_left_channel_screen_does_not_panic() {
    let mut state = joined_general_with(vec![]);
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == "general")
        .unwrap();
    state.leave_channel_locally("general");
    let rows = sidebar_rows(&state);
    let all = rows.join("");
    assert!(all.contains("You left this public channel"));
}

/// @requirement TB-157
#[test]
fn dwell_does_not_refire_for_a_left_channel() {
    let mut state = UiState::new("me".into());
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
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    state.leave_channel_locally("random");
    press(&mut state, KeyCode::Char(']')); // select "random"
    let later = Instant::now() + DWELL_DURATION + Duration::from_millis(1);
    assert_eq!(state.tick_dwell(later), None);
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

/// @requirement AC-109
#[test]
fn on_joined_clears_the_left_flag() {
    let mut state = joined_general_with(vec![]);
    state.leave_channel_locally("general");
    assert!(state.channels[0].left);
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    assert!(!state.channels[0].left);
    assert!(state.channels[0].joined);
}
