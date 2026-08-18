#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::proto::{KeyMode, UserId};
use aloo::client::tui::ui::{Focus, IdentityCase, MessageBody, PendingOtpInvite, UiAction, VoiceTarget, render};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use zeroize::Zeroize;

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
            log_index,
        } => {
            assert_eq!(to, UserId(2));
            assert_eq!(plaintext, "just us");
            assert_eq!(recipient_key_mode, KeyMode::Password);
            assert_eq!(recipient_pubkey_der, user(2, "bob").public_key_der);
            assert_eq!(log_index, Some(0), "the first message in a fresh room");
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
        2,
        "bob's earlier message plus his own disconnect notice - nothing sent by us"
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

// ---------------------------------------------------------------------
// OTP session: mutual-consent popups and the status notice (AC-139)
// ---------------------------------------------------------------------

/// @requirement AC-139
#[test]
fn generate_confirm_popup_opens_when_no_key_exists() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    assert!(state.status_notice.is_none());
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);

    // It absorbs every other key while open - typing doesn't reach the
    // compose bar, same as the identity-review/file-offer popups.
    press(&mut state, KeyCode::Char('x'));
    assert!(state.input.is_empty());

    // Accept moves to the size prompt rather than immediately producing an
    // action - see the tests below for that step.
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None);
    assert!(state.otp_generate_confirm_open().is_none());
    assert_eq!(
        state.otp_size_input_open().map(|p| p.peer),
        Some(UserId(2))
    );
}

/// @requirement AC-139
#[test]
fn declining_the_generate_confirm_cancels_locally_without_sending_anything() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);
    press(&mut state, KeyCode::Right); // Accept -> Reject
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::CancelOtpGenerate));
}

/// @requirement AC-144
#[test]
fn the_size_prompt_absorbs_input_and_submits_a_valid_size() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);
    press(&mut state, KeyCode::Enter); // Accept -> opens the size prompt

    // Absorbs everything else too, same as every other OTP popup.
    press(&mut state, KeyCode::Char('x'));
    assert!(state.input.is_empty());

    type_str(&mut state, "50");
    assert_eq!(state.otp_size_text, "50");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::ConfirmOtpGenerate { size_mb: 50 }));
    // Still open at this level - `client::otp::confirm_generate` is the
    // one that actually takes it, once this action reaches it.
    assert!(state.otp_size_input_open().is_some());
}

/// @requirement AC-144
#[test]
fn the_size_prompt_supports_backspace() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    type_str(&mut state, "123");
    press(&mut state, KeyCode::Backspace);
    assert_eq!(state.otp_size_text, "12");
}

/// @requirement AC-144
#[test]
fn the_size_prompt_rejects_a_value_outside_1_to_900000() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    type_str(&mut state, "0");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "0 MB is below the minimum");
    assert!(state.otp_size_error.is_some());
    // Still open, waiting for a corrected value - not silently dropped.
    assert!(state.otp_size_input_open().is_some());
}

/// @requirement AC-144
#[test]
fn the_size_prompt_rejects_more_than_six_digits() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    // 900001 would be the smallest 6-digit value past the max; typing a
    // 7th digit must simply not be accepted into the buffer at all.
    type_str(&mut state, "1234567");
    assert_eq!(state.otp_size_text, "123456");
}

/// @requirement AC-144
#[test]
fn escape_on_the_size_prompt_cancels_the_whole_session() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), KeyMode::PqHybrid, vec![9, 9]);
    press(&mut state, KeyCode::Enter);
    type_str(&mut state, "50");

    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, Some(UiAction::CancelOtpGenerate));
    // Still open at this level - `client::otp::cancel_generate` is the one
    // that actually takes it, once this action reaches it.
    assert!(state.otp_size_input_open().is_some());
}

/// @requirement AC-139
#[test]
fn incoming_invite_popup_absorbs_input_until_answered() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_otp_invite(
        UserId(2),
        "bob".into(),
        "abc-def".into(),
        Some(vec![1, 2, 3]),
        Some(vec![4, 5, 6]),
        Some(50),
    );
    assert!(state.otp_invite_open().is_some());

    // Ctrl+H is absorbed too - same "nothing else happens" guarantee the
    // identity-review popup gives, since this decision has to be explicit.
    ctrl(&mut state, KeyCode::Char('h'));
    assert!(!state.help_open);
}

/// @requirement AC-144
#[test]
fn the_invite_popup_shows_the_pad_size_the_sender_chose() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_otp_invite(
        UserId(2),
        "bob".into(),
        "abc-def".into(),
        Some(vec![1, 2, 3]),
        Some(vec![4, 5, 6]),
        Some(50),
    );
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("50MB")),
        "the offered pad size should be visible before deciding: {rows:?}"
    );
}

/// @requirement AC-139
#[test]
fn accepting_an_invite_produces_accept_otp_invite_action() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_otp_invite(UserId(2), "bob".into(), "abc-def".into(), None, None, None);
    let action = press(&mut state, KeyCode::Enter); // Accept is the default focus
    assert_eq!(action, Some(UiAction::AcceptOtpInvite));
}

/// @requirement AC-139
#[test]
fn rejecting_an_invite_produces_reject_otp_invite_action() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_otp_invite(UserId(2), "bob".into(), "abc-def".into(), None, None, None);
    press(&mut state, KeyCode::Tab); // Accept -> Reject
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::RejectOtpInvite));
}

/// @requirement AC-139
#[test]
fn a_second_invite_from_a_different_sender_queues_behind_the_first() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_otp_invite(UserId(2), "bob".into(), "bob-contact".into(), None, None, None);
    state.push_otp_invite(UserId(3), "carol".into(), "carol-contact".into(), None, None, None);
    assert_eq!(state.otp_invite_open().unwrap().from, UserId(2));

    let _ = state.take_otp_invite();
    assert_eq!(state.otp_invite_open().unwrap().from, UserId(3));
}

/// @requirement AC-139
#[test]
fn otp_status_notice_is_rendered_in_the_configured_color() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_status_notice("OTP session started at 2026-08-18T00:00:00Z".to_string(), true);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("OTP session started")),
        "{rows:?}"
    );

    state.push_status_notice("OTP session cancelled".to_string(), false);
    let rows = rendered_rows(&state);
    assert!(
        rows.iter().any(|r| r.contains("OTP session cancelled")),
        "{rows:?}"
    );
}

/// @requirement AC-141
#[test]
fn an_otp_system_message_is_logged_into_the_named_peers_dm_room() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.push_otp_system_message(UserId(2), "bob", "OTP: setup sent to bob...".to_string());
    let room = state.private_rooms.get(&UserId(2)).expect("room created");
    assert_eq!(room.log.len(), 1);
    assert_eq!(room.log[0].body, MessageBody::System("OTP: setup sent to bob...".to_string()));
    // Same "not actively viewed" unread treatment as any other DM arrival
    // (direct_message_creates_room_and_marks_unread_when_not_actively_viewed) -
    // a session outcome the user hasn't seen yet is exactly as unread as a
    // message they haven't seen yet.
    assert!(room.unread);
}

/// @requirement AC-141
#[test]
fn an_otp_system_message_does_not_mark_unread_when_that_room_is_active() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.push_otp_system_message(UserId(2), "bob", "OTP session started".to_string());
    let room = state.private_rooms.get(&UserId(2)).unwrap();
    assert!(!room.unread);
}

/// @requirement AC-141
#[test]
fn otp_active_peers_default_to_inactive_until_marked() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    assert!(!state.is_otp_active(UserId(2)));
    state.mark_otp_active(UserId(2));
    assert!(state.is_otp_active(UserId(2)));
}

/// @requirement AC-141
#[test]
fn messages_in_an_otp_active_dm_get_the_shield_prefix_but_system_lines_never_do() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.mark_otp_active(UserId(2));
    state.push_otp_system_message(UserId(2), "bob", "OTP session started at now".to_string());
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hello under the pad".into()));

    let rows = rendered_rows(&state);
    assert!(
        appears_before(&rows, "\u{1F6E1}", "bob: hello under the pad"),
        "a real message in an OTP-active DM should carry the shield prefix: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| {
            let Some(system_at) = r.find("OTP session started at now") else {
                return false;
            };
            r[..system_at].contains('\u{1F6E1}')
        }),
        "an app system line must never itself get the shield prefix: {rows:?}"
    );
}

/// @requirement AC-141
#[test]
fn messages_in_a_dm_without_an_active_otp_session_get_no_shield() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("plain hello".into()));

    // Checked against the message row specifically, not the whole screen -
    // the room title itself already carries a shield glyph as bob's
    // pq_hybrid tag (`KeyMode::format_with_name`), unrelated to this one.
    let rows = rendered_rows(&state);
    assert!(
        !rows.iter().any(|r| r.contains("bob: plain hello") && r.contains('\u{1F6E1}')),
        "no shield should appear without an active OTP session: {rows:?}"
    );
}

/// @requirement AC-153
#[test]
fn the_otp_header_is_not_shown_without_an_active_session() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hello".into()));

    let rows = rendered_rows(&state);
    assert!(
        !rows.iter().any(|r| r.contains("OTP SESSION")),
        "no header should render without an active OTP session: {rows:?}"
    );
}

/// @requirement AC-153
#[test]
fn the_otp_header_shows_the_highlighted_title_and_yellow_nickname() {
    use aloo::client::otp_cli::ContactDetail;

    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.mark_otp_active(UserId(2));
    state.set_otp_key_status(
        UserId(2),
        ContactDetail {
            enc_sequence: 3,
            enc_offset: 300,
            enc_key_remaining: 2_000_000,
            dec_sequence: 5,
            dec_offset: 500,
            dec_key_remaining: 2_000_000,
        },
    );

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
        .collect();

    assert!(
        rows.iter().any(|r| r.contains(
            "OTP SESSION with bob - Receive Key (dec): 5 500 1.91MB - Send Key (enc): 3 300 1.91MB"
        )),
        "the header should show both directions' live figures: {rows:?}"
    );

    let (x, y) = find_text_start(&buffer, "OTP SESSION");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Cyan);

    let (x, y) = find_text_start(&buffer, "bob");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Yellow);
}

/// @requirement AC-153
#[test]
fn the_otp_header_colors_remaining_key_red_below_the_threshold_and_green_at_or_above_it() {
    use aloo::client::otp_cli::ContactDetail;

    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.mark_otp_active(UserId(2));
    state.set_otp_key_status(
        UserId(2),
        ContactDetail {
            enc_sequence: 0,
            enc_offset: 0,
            enc_key_remaining: 100_000, // well under 0.5MB - red
            dec_sequence: 0,
            dec_offset: 0,
            dec_key_remaining: 5_000_000, // well over 0.5MB - green
        },
    );

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "0.10MB");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Red);
    let (x, y) = find_text_start(&buffer, "4.77MB");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Green);
}

/// @requirement AC-143
#[test]
fn push_outgoing_dm_returns_the_index_the_entry_landed_at() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens (and so creates) bob's room
    assert_eq!(
        state.push_outgoing_dm(UserId(2), MessageBody::Text("one".into())),
        Some(0)
    );
    assert_eq!(
        state.push_outgoing_dm(UserId(2), MessageBody::Text("two".into())),
        Some(1)
    );
    assert_eq!(state.private_rooms[&UserId(2)].log.len(), 2);

    // No room exists yet for a peer nothing has been sent to or received
    // from - nothing to return an index into.
    assert_eq!(
        state.push_outgoing_dm(UserId(3), MessageBody::Text("nobody".into())),
        None
    );
}

/// @requirement AC-143
#[test]
fn mark_dm_message_failed_flags_only_the_targeted_row() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens (and so creates) bob's room
    let first = state
        .push_outgoing_dm(UserId(2), MessageBody::Text("ok".into()))
        .unwrap();
    let second = state
        .push_outgoing_dm(UserId(2), MessageBody::Text("will fail".into()))
        .unwrap();

    state.mark_dm_message_failed(UserId(2), second);
    let log = &state.private_rooms[&UserId(2)].log;
    assert!(!log[first].failed);
    assert!(log[second].failed);

    // Defensive no-ops: an out-of-range index and an unknown peer must
    // never panic - this is called from an async send-completion path with
    // no way to guarantee the room still looks exactly like it did when
    // the index was captured.
    state.mark_dm_message_failed(UserId(2), 99);
    state.mark_dm_message_failed(UserId(3), 0);
}

/// A failed OTP send (`client::otp::send_now`'s failure paths) must never
/// look identical to one that actually reached the peer - the whole
/// row, including the shield prefix an active OTP session would add, is
/// rendered in red.
///
/// @requirement AC-143
#[test]
fn a_failed_message_is_rendered_in_red() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens (and so creates) bob's room
    state.mark_otp_active(UserId(2));
    let index = state
        .push_outgoing_dm(UserId(2), MessageBody::Text("never arrived".into()))
        .unwrap();
    state.mark_dm_message_failed(UserId(2), index);

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "never arrived");
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::Red);
}

/// The un-failed counterpart of the test above - an ordinary delivered
/// message stays whatever color it would otherwise be, never red.
///
/// @requirement AC-143
#[test]
fn a_successful_message_is_not_rendered_in_red() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens (and so creates) bob's room
    state
        .push_outgoing_dm(UserId(2), MessageBody::Text("arrived fine".into()))
        .unwrap();

    let backend = TestBackend::new(100, 15);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "arrived fine");
    assert_ne!(buffer[(x, y)].fg, ratatui::style::Color::Red);
}

/// @requirement TB-184
#[test]
fn an_invite_holding_key_material_can_be_zeroized() {
    let mut invite = PendingOtpInvite {
        from: UserId(2),
        from_name: "bob".into(),
        contact_name: "abc-def".into(),
        peer_encryption_key: Some(vec![1, 2, 3, 4]),
        peer_decryption_key: Some(vec![5, 6, 7, 8]),
        pad_size_mb: Some(1),
    };
    invite.zeroize();
    if let Some(bytes) = &invite.peer_encryption_key {
        assert!(bytes.iter().all(|&b| b == 0));
    }
    if let Some(bytes) = &invite.peer_decryption_key {
        assert!(bytes.iter().all(|&b| b == 0));
    }
    // The non-sensitive fields are `#[zeroize(skip)]` - still readable
    // normally afterward, not wiped alongside the key material.
    assert_eq!(invite.from, UserId(2));
    assert_eq!(invite.from_name, "bob");
}

// ---------------------------------------------------------------------
// Unknown slash commands never become chat text (AC-140)
// ---------------------------------------------------------------------

/// @requirement AC-140
#[test]
fn an_unrecognized_slash_command_is_never_sent_as_direct_text() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens DM with bob
    type_str(&mut state, "/frobnicate");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "an unrecognized command must never produce a send action");
    assert!(state.input.is_empty());
    assert_eq!(
        state.status_notice,
        Some(("unknown command: /frobnicate".to_string(), false))
    );
    assert!(state.private_rooms.get(&UserId(2)).map(|r| r.log.is_empty()).unwrap_or(true));
}

/// @requirement AC-140
#[test]
fn a_recognized_slash_command_still_works_after_the_guard_was_added() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    type_str(&mut state, "/otp");
    let action = press(&mut state, KeyCode::Enter);
    match action {
        Some(UiAction::RequestOtpSession { peer, .. }) => assert_eq!(peer, UserId(2)),
        other => panic!("expected RequestOtpSession, got {other:?}"),
    }
}
