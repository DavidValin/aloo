#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::proto::{KeyMode, UserId};
use aloo::client::tui::ui::{Focus, IdentityCase, MessageBody, UiAction, VoiceTarget, render};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

/// @requirement AC-029
#[test]
fn direct_message_creates_room_and_marks_unread_when_not_actively_viewed() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("psst".into()));
    let room = state.private_rooms.get(&UserId(2)).expect("room created");
    assert!(room.unread);
    assert_eq!(room.log.len(), 1);
}

/// @requirement AC-029
#[test]
fn direct_message_does_not_mark_unread_when_that_room_is_active() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    let room = state.private_rooms.get(&UserId(2)).unwrap();
    assert!(!room.unread);
}

// ---------------------------------------------------------------------
// Private messaging
// ---------------------------------------------------------------------

/// @requirement AC-028, TB-033
#[test]
fn opening_dm_from_sidebar_and_sending_a_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens DM with bob
    assert_eq!(state.active_private_room, Some(UserId(2)));
    assert_eq!(state.focus, Focus::Input);

    type_str(&mut state, "just us");
    let action = press(&mut state, KeyCode::Enter).unwrap();
    match action {
        UiAction::SendDirectText {
            to,
            plaintext,
            recipient_key_mode,
            recipient_pubkey_der,
        } => {
            assert_eq!(to, UserId(2));
            assert_eq!(plaintext, "just us");
            assert_eq!(recipient_key_mode, KeyMode::Password);
            assert_eq!(recipient_pubkey_der, user(2, "bob").public_key_der);
        }
        other => panic!("expected SendDirectText, got {other:?}"),
    }
    assert!(state.private_rooms[&UserId(2)].log[0].outgoing);
}

/// @requirement AC-031
#[test]
fn cannot_open_dm_with_yourself() {
    let mut state = joined_general_with(vec![user(1, "me"), user(2, "bob")]);
    // own_id is UserId(1); sidebar_selected starts at 0, which is "me"
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    assert_eq!(state.active_private_room, None);
}

/// @requirement AC-028
#[test]
fn escape_closes_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    assert!(state.active_private_room.is_some());
    press(&mut state, KeyCode::Esc);
    assert_eq!(state.active_private_room, None);
}

/// @requirement AC-029
#[test]
fn reopening_dm_clears_unread_flag() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    assert!(state.private_rooms[&UserId(2)].unread);

    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // reopen bob's room
    assert!(!state.private_rooms[&UserId(2)].unread);
}

/// @requirement AC-053
#[test]
fn compose_bar_ignores_typing_and_enter_while_the_open_dm_peer_is_offline() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into())); // gives bob DM history
    state.on_user_offline(UserId(2));
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // reopen bob's (offline) room
    assert_eq!(state.active_private_room, Some(UserId(2)));
    assert_eq!(state.focus, Focus::Input);

    type_str(&mut state, "are you there");
    assert_eq!(
        state.input, "",
        "typing must be a no-op while the DM peer is offline"
    );

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action, None,
        "Enter must not send while the DM peer is offline"
    );
    assert_eq!(
        state.private_rooms[&UserId(2)].log.len(),
        1,
        "only bob's earlier message, nothing sent by us"
    );
}

/// @requirement TB-105
#[test]
fn compose_bar_works_normally_again_after_leaving_and_reopening_an_online_peers_dm() {
    // Sanity check that offline-blocking is scoped to the offline peer, not
    // some global switch left flipped on.
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.on_user_offline(UserId(2));

    state.focus = Focus::Sidebar;
    // bob is offline-but-retained (index 0), carol is still online (index 1)
    state.sidebar_selected = 1;
    press(&mut state, KeyCode::Enter); // opens DM with carol, who is online
    assert_eq!(state.active_private_room, Some(UserId(3)));

    type_str(&mut state, "hey carol");
    let action = press(&mut state, KeyCode::Enter).expect("carol is online, this should send");
    assert!(matches!(action, UiAction::SendDirectText { to, .. } if to == UserId(3)));
}

// ---------------------------------------------------------------------
// Push-to-talk voice
// ---------------------------------------------------------------------

/// @requirement AC-032
#[test]
fn space_release_targets_active_private_room_instead_of_channel() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // open DM with bob
    state.focus = Focus::Messages; // push-to-talk is only live outside the compose bar

    let start = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    match start {
        Some(UiAction::VoiceRecordStart(VoiceTarget::Direct {
            to,
            recipient_key_mode,
            recipient_pubkey_der,
        })) => {
            assert_eq!(to, UserId(2));
            assert_eq!(recipient_key_mode, KeyMode::Password);
            assert_eq!(recipient_pubkey_der, user(2, "bob").public_key_der);
        }
        other => panic!("expected VoiceRecordStart(Direct), got {other:?}"),
    }
    let stop = state.handle_key(
        KeyCode::Char(' '),
        KeyModifiers::NONE,
        KeyEventKind::Release,
    );
    assert_eq!(stop, Some(UiAction::VoiceRecordStop));
}

/// @requirement AC-089
#[test]
fn global_record_start_targets_the_active_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // open DM with bob

    let start = state.global_record_start();
    match start {
        Some(UiAction::VoiceRecordStart(VoiceTarget::Direct {
            to,
            recipient_key_mode,
            recipient_pubkey_der,
        })) => {
            assert_eq!(to, UserId(2));
            assert_eq!(recipient_key_mode, KeyMode::Password);
            assert_eq!(recipient_pubkey_der, user(2, "bob").public_key_der);
        }
        other => panic!("expected VoiceRecordStart(Direct), got {other:?}"),
    }
    let stop = state.global_record_stop();
    assert_eq!(stop, Some(UiAction::VoiceRecordStop));
}

/// @requirement AC-054
#[test]
fn space_press_with_an_offline_dm_peer_is_ignored_and_does_not_start_recording() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into())); // gives bob DM history
    state.on_user_offline(UserId(2));
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // reopen bob's (now offline) room
    state.focus = Focus::Messages; // push-to-talk is only live outside the compose bar

    let action = state.handle_key(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
    assert_eq!(
        action, None,
        "voice recording to an offline peer must be ignored, not started"
    );
    assert!(!state.recording);
}

// ---------------------------------------------------------------------
// Live-streamed voice: placeholder log entries and finalize-in-place
// ---------------------------------------------------------------------

/// @requirement AC-035
#[test]
fn on_direct_stream_start_and_finished_swap_the_placeholder_body_in_place() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_stream_start(UserId(2), UserId(2), "bob".into(), 5);
    let room = state.private_rooms.get(&UserId(2)).unwrap();
    assert_eq!(
        room.log[0].body,
        MessageBody::VoiceStreaming { stream_id: 5 }
    );

    state.on_direct_stream_finished(UserId(2), UserId(2), 5, 1000, vec![1]);
    let room = state.private_rooms.get(&UserId(2)).unwrap();
    assert_eq!(
        room.log[0].body,
        MessageBody::Voice {
            duration_ms: 1000,
            pcm: vec![1]
        }
    );
}

// ---------------------------------------------------------------------
// Message log scrolling
// ---------------------------------------------------------------------

/// @requirement AC-059
#[test]
fn opening_a_private_room_with_existing_history_starts_on_the_newest_message() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    // three DMs arrive while we're looking at the channel, not the DM room
    for i in 0..3 {
        state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text(format!("dm{i}")));
    }
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens the DM with bob
    assert_eq!(state.active_private_room, Some(UserId(2)));
    assert_eq!(
        state.message_selected, 2,
        "opening the room should land on its newest message, not entry 0"
    );
}

// ---------------------------------------------------------------------
// Encryption method label next to a username
// ---------------------------------------------------------------------

/// @requirement AC-051, TB-035
#[test]
fn private_room_title_shows_the_peers_pq_hybrid_tag_after_their_name() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens DM with bob
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("Private: bob")),
        "expected the title to lead with the name: {rows:?}"
    );
    assert!(
        appears_before(&rows, "bob", "PQH"),
        "expected the private room title to show bob's tag after his name: {rows:?}"
    );
}

/// @requirement AC-053
#[test]
fn private_room_input_bar_shows_a_red_offline_notice_instead_of_the_compose_bar() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.on_user_offline(UserId(2));
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // reopen bob's (offline) room

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "(user offline)");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Red);
}

// ---------------------------------------------------------------------
// Identity review popup (docs/PROTOCOL.md §12: manual Accept/Reject)
// ---------------------------------------------------------------------

/// @requirement AC-064
#[test]
fn identity_review_popup_also_shows_over_an_open_private_room() {
    // bob is trusted and his room is already open; carol is the one whose
    // identity just mismatched. Unlike the old passive banner, a
    // trust-gated peer's own room can no longer be opened at all (Enter on
    // their sidebar entry reopens the review popup instead - see
    // `ui_test.rs`'s `enter_on_a_trust_gated_sidebar_member_...` test), so
    // this exercises the popup drawing on top of *some other* view, the
    // same "follows me anywhere" property the banner used to have.
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens DM with bob
    assert_eq!(state.active_private_room, Some(UserId(2)));

    state.push_identity_review(
        UserId(3),
        "carol".into(),
        "'carol' connected with a different key than last time".into(),
        IdentityCase::StaticMismatch {
            new_public_key_der: vec![9, 9, 9],
            previous_public_key_der: vec![1, 1, 1],
        },
    );
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("Identity review: carol")),
        "expected the review popup over the private room too: {rows:?}"
    );
}

// ---------------------------------------------------------------------
// Rendering smoke tests
// ---------------------------------------------------------------------

/// @requirement TB-036
#[test]
fn render_does_not_panic_with_help_open_over_a_private_room() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    state.help_open = true;
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    assert!(buffer.content().iter().any(|c| c.symbol() != " "));
}

/// @requirement TB-036
#[test]
fn render_private_room_full_screen_does_not_panic() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
}
