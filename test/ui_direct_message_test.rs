#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::p2p::LinkStatus;
use aloo::p2p_proto::ReceiptStage;
use aloo::proto::UserId;
use aloo::client::tui::ui::{
    DeliveryProof, OtpPadPhase,
    DELIVERY_ARROW, DeliveryStatus, Focus, IdentityCase, MessageBody, OTP_ICON, PendingOtpInvite,
    UiAction, UiState, VoiceTarget, render,
};
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
            recipient_pubkey_der,
            log_index,
            msg_id: _,
        } => {
            assert_eq!(to, UserId(2));
            assert_eq!(plaintext, "just us");
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
fn compose_bar_refuses_to_send_a_plain_message_to_an_offline_dm_peer() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into())); // gives bob DM history
    state.on_user_offline(UserId(2));
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // reopen bob's (offline) room
    assert_eq!(state.active_private_room, Some(UserId(2)));
    assert_eq!(state.focus, Focus::Input);

    type_str(&mut state, "are you there");
    assert_eq!(
        state.input, "are you there",
        "typing itself is no longer blocked while a DM peer is offline - only sending is \
         (`/endotp` needs to still be composable and submittable in this state)"
    );

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action, None,
        "Enter must not send a plain message while the DM peer is offline"
    );
    assert_eq!(
        state.input, "are you there",
        "a refused send leaves the typed text in place, same as any other refusal"
    );
    assert_eq!(
        state.private_rooms[&UserId(2)].log.len(),
        2,
        "bob's earlier message plus his own disconnect notice - nothing sent by us"
    );
}

/// @requirement AC-053
#[test]
fn endotp_can_still_be_typed_and_submitted_while_the_open_dm_peer_is_offline() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens DM with bob while he's still online
    assert_eq!(state.active_private_room, Some(UserId(2)));
    // Disconnects *after* the room is open - with no prior DM history, bob
    // going offline before this would drop him from the sidebar entirely
    // (`on_user_offline`'s "nothing to keep them around for" branch), which
    // isn't the case this test is about: an *already-open* room's peer
    // disconnecting mid-session, the scenario `/endotp` needs to survive.
    state.on_user_offline(UserId(2));

    type_str(&mut state, "/endotp");
    assert_eq!(
        state.input, "/endotp",
        "unlike every other command, /endotp must be typeable while the peer is offline"
    );

    let action = press(&mut state, KeyCode::Enter);
    match action {
        Some(UiAction::EndOtpSession { peer, .. }) => assert_eq!(peer, UserId(2)),
        other => panic!("expected EndOtpSession even while the peer is offline, got {other:?}"),
    }
    assert_eq!(state.input, "", "a recognized command always clears input");
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
            recipient_pubkey_der,
        })) => {
            assert_eq!(to, UserId(2));
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
            recipient_pubkey_der,
        })) => {
            assert_eq!(to, UserId(2));
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
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);

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
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
    press(&mut state, KeyCode::Right); // Accept -> Reject
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, Some(UiAction::CancelOtpGenerate));
}

/// @requirement AC-144
#[test]
fn the_size_prompt_absorbs_input_and_submits_a_valid_size() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
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
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    type_str(&mut state, "123");
    press(&mut state, KeyCode::Backspace);
    assert_eq!(state.otp_size_text, "12");
}

/// @requirement AC-144
#[test]
fn the_size_prompt_rejects_a_value_outside_the_allowed_range() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    type_str(&mut state, "0");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "0 MB is below the minimum");
    assert!(state.otp_size_error.is_some());
    // Still open, waiting for a corrected value - not silently dropped.
    assert!(state.otp_size_input_open().is_some());
}

/// A 7-digit value inside the range is accepted; the digit cap only exists
/// to stop an 8th digit - which could never be in range - being typed at
/// all.
///
/// @requirement AC-144
#[test]
fn the_size_prompt_accepts_the_maximum_and_rejects_more_than_seven_digits() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    // The max itself (1TB per key) is 7 digits and must be typeable; an 8th
    // digit must simply not be accepted into the buffer at all.
    type_str(&mut state, "10485768");
    assert_eq!(state.otp_size_text, "1048576");

    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::ConfirmOtpGenerate {
            size_mb: aloo::crypto::otp::OTP_SIZE_MB_MAX
        }),
        "the documented maximum must be submittable"
    );
}

/// A value past the maximum that still fits the digit cap is caught by the
/// range check on submit, not by the cap.
///
/// @requirement AC-144
#[test]
fn the_size_prompt_rejects_a_seven_digit_value_past_the_maximum() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
    press(&mut state, KeyCode::Enter);

    type_str(&mut state, "9999999");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(action, None, "past the maximum, even at 7 digits");
    assert!(state.otp_size_error.is_some());
    assert!(state.otp_size_input_open().is_some());
}

/// @requirement AC-144
#[test]
fn escape_on_the_size_prompt_cancels_the_whole_session() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_generate_confirm(UserId(2), "bob".into(), vec![9, 9]);
    press(&mut state, KeyCode::Enter);
    type_str(&mut state, "50");

    let action = press(&mut state, KeyCode::Esc);
    assert_eq!(action, Some(UiAction::CancelOtpGenerate));
    // Still open at this level - `client::otp::cancel_generate` is the one
    // that actually takes it, once this action reaches it.
    assert!(state.otp_size_input_open().is_some());
}

// ---------------------------------------------------------------------
// The generation spinner (a pad large enough to be worth choosing takes
// long enough that silence would read as a hang)
// ---------------------------------------------------------------------

#[test]
fn the_keygen_spinner_opens_with_the_chosen_size_and_no_progress_yet() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 4);

    let progress = state.otp_keygen_open().expect("the spinner should be open");
    assert_eq!(progress.peer, UserId(2));
    assert_eq!(progress.size_mb, 4);
    assert_eq!(progress.written_bytes, 0);
    assert_eq!(
        progress.total_bytes,
        4 * 1024 * 1024 * 2,
        "a pad is two independent keys, so the randomness is double the per-key size"
    );
    assert_eq!(progress.percent(), 0);
}

#[test]
fn keygen_progress_moves_the_bar_and_clamps_at_a_hundred_percent() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 1);

    state.set_otp_keygen_progress(1024 * 1024, 1024 * 1024 * 2);
    assert_eq!(state.otp_keygen_open().unwrap().percent(), 50);

    // A report past the total (never expected, but the bar must not draw
    // wider than itself if one ever arrives) reads as complete, not more.
    state.set_otp_keygen_progress(9_999_999, 1024 * 1024 * 2);
    assert_eq!(state.otp_keygen_open().unwrap().percent(), 100);
    assert_eq!(state.otp_keygen_open().unwrap().fraction(), 1.0);
}

/// Removing the old 16MB ceiling means a user can now ask for a pad that
/// takes hours to send. Refusing was the wrong answer - the transport
/// genuinely delivers it - but so is saying nothing, so the prompt costs
/// the choice out before they commit to generating it.
///
/// @requirement AC-253
#[test]
fn the_size_prompt_says_how_long_that_size_takes_to_send() {
    use aloo::client::otp::transfer_estimate_text;
    // Coarse on purpose: the figure is a guess about someone else's
    // network, so it must not read more precisely than it knows.
    assert_eq!(transfer_estimate_text(1), "about 6s");
    assert!(transfer_estimate_text(1024).ends_with('h'), "a 1GB pad is hours");
    assert!(transfer_estimate_text(64).ends_with('m'), "a 64MB pad is minutes");
    assert!(
        transfer_estimate_text(1024 * 512).ends_with('h'),
        "a 512GB pad is hours, and saying so is the point"
    );
    // Monotonic - a bigger pad never reads as quicker.
    let mut previous = 0;
    for mb in [1u32, 16, 256, 4096, 65536] {
        let secs = aloo::client::otp::transfer_estimate(mb).as_secs();
        assert!(secs > previous, "{mb}MB must not estimate under a smaller pad");
        previous = secs;
    }
}

/// The pad's second slow phase. Generation finishing used to close the
/// popup outright, leaving the screen empty for however long the transfer
/// took - and since the peer is only asked to accept once the whole pad
/// has arrived and verified, that gap is the entire transfer.
///
/// @requirement AC-253
#[test]
fn the_popup_moves_from_generating_to_transferring_rather_than_closing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 4);
    assert_eq!(
        state.otp_keygen_open().unwrap().phase,
        OtpPadPhase::Generating
    );

    state.set_otp_keygen_progress(8 * 1024 * 1024, 8 * 1024 * 1024);
    state.begin_otp_pad_transfer(UserId(2), "bob".into(), 4, OtpPadPhase::Sending);

    let progress = state.otp_keygen_open().expect("still open, now transferring");
    assert_eq!(progress.phase, OtpPadPhase::Sending);
    assert_eq!(progress.percent(), 0, "the transfer's own bar starts at zero");
    assert_eq!(
        progress.total_bytes,
        4 * 1024 * 1024 * 2,
        "both halves cross the link, so the transfer is twice the per-key size"
    );
}

/// The receiving side gets the same popup, for the same reason: nothing
/// else on their screen says a pad is on its way.
///
/// @requirement AC-253
#[test]
fn the_receiving_side_sees_its_own_transfer_progress() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_otp_pad_transfer(UserId(2), "bob".into(), 1, OtpPadPhase::Receiving);
    state.set_otp_pad_transfer_progress(UserId(2), 1024 * 1024);
    assert_eq!(state.otp_keygen_open().unwrap().percent(), 50);
    assert_eq!(
        state.otp_keygen_open().unwrap().phase,
        OtpPadPhase::Receiving
    );
}

/// A transfer report for somebody else must not drive this popup's bar,
/// and a stale one ending must not tear it down - two pads can be in
/// flight with different peers.
///
/// @requirement AC-253
#[test]
fn a_transfer_popup_only_answers_to_the_peer_it_is_reporting_on() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.begin_otp_pad_transfer(UserId(2), "bob".into(), 1, OtpPadPhase::Receiving);

    state.set_otp_pad_transfer_progress(UserId(3), 2 * 1024 * 1024);
    assert_eq!(
        state.otp_keygen_open().unwrap().percent(),
        0,
        "carol's transfer must not move bob's bar"
    );

    state.close_otp_keygen_for(UserId(3));
    assert!(
        state.otp_keygen_open().is_some(),
        "nor should carol's ending close bob's popup"
    );

    state.close_otp_keygen_for(UserId(2));
    assert!(state.otp_keygen_open().is_none());
}

/// A late generation report must not rewind a bar that has already moved
/// on to the transfer - the two phases share one popup but not one total.
///
/// @requirement AC-253
#[test]
fn a_late_generation_report_cannot_rewind_the_transfer_bar() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.begin_otp_pad_transfer(UserId(2), "bob".into(), 1, OtpPadPhase::Sending);
    state.set_otp_pad_transfer_progress(UserId(2), 2 * 1024 * 1024);
    assert_eq!(state.otp_keygen_open().unwrap().percent(), 100);

    state.set_otp_keygen_progress(0, 2 * 1024 * 1024);
    assert_eq!(
        state.otp_keygen_open().unwrap().percent(),
        100,
        "the transfer had already finished; a stale keygen report says nothing about it"
    );
}

#[test]
fn the_keygen_spinner_animates_on_the_ticker_even_without_progress() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 1);
    let first = state.otp_keygen_open().unwrap().frame;

    state.tick_otp_keygen_spinner();
    assert_ne!(
        state.otp_keygen_open().unwrap().frame,
        first,
        "the spinner must keep moving while waiting, not only when bytes land"
    );

    // Wraps rather than growing without bound.
    for _ in 0..aloo::client::tui::ui::SPINNER_FRAMES.len() {
        state.tick_otp_keygen_spinner();
    }
    assert!(
        state.otp_keygen_open().unwrap().frame < aloo::client::tui::ui::SPINNER_FRAMES.len()
    );
}

#[test]
fn ticking_the_spinner_with_no_generation_running_is_a_no_op() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.tick_otp_keygen_spinner();
    state.set_otp_keygen_progress(1, 2);
    assert!(state.otp_keygen_open().is_none());
}

/// Nothing is decidable mid-generation and nothing is safe to cancel (the
/// pad is already being written to disk), so the popup absorbs every key
/// without producing an action.
#[test]
fn the_keygen_spinner_absorbs_every_key_except_escape() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 1);

    // There is nothing to decide while a pad is being made or sent, so
    // every ordinary key is swallowed rather than leaking into the message
    // input behind the popup.
    for code in [
        KeyCode::Enter,
        KeyCode::Char('y'),
        KeyCode::Left,
        KeyCode::Tab,
    ] {
        assert_eq!(press(&mut state, code), None, "{code:?} must do nothing");
        assert!(
            state.otp_keygen_open().is_some(),
            "{code:?} must not close the spinner"
        );
    }
}

/// Escape is the exception, and has to be: generation and transfer run for
/// minutes and consume gigabytes, so a user who realises they picked the
/// wrong size must be able to stop rather than wait it out. Cancelling is
/// what erases the staged material - see `otp::cancel_pad`.
///
/// @requirement AC-255
#[test]
fn escape_during_generation_or_transfer_cancels_the_pad() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 1);
    assert_eq!(
        press(&mut state, KeyCode::Esc),
        Some(UiAction::CancelOtpPad { peer: UserId(2) }),
        "Escape must reach the generation phase"
    );

    state.begin_otp_pad_transfer(UserId(2), "bob".into(), 1, OtpPadPhase::Sending);
    assert_eq!(
        press(&mut state, KeyCode::Esc),
        Some(UiAction::CancelOtpPad { peer: UserId(2) }),
        "and the transfer phase, which is the longer of the two"
    );

    state.begin_otp_pad_transfer(UserId(2), "bob".into(), 1, OtpPadPhase::Receiving);
    assert_eq!(
        press(&mut state, KeyCode::Esc),
        Some(UiAction::CancelOtpPad { peer: UserId(2) }),
        "and it must work from the receiving side too - either side may give up"
    );
}

#[test]
fn the_keygen_spinner_renders_the_peer_the_size_and_the_percentage() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 3);
    state.set_otp_keygen_progress(1024 * 1024 * 3, 1024 * 1024 * 6);

    // The peer is named in the popup's title, the figures in its body.
    let rows = rendered_rows_at(&state, 100, 30).join("\n");
    assert!(
        rows.contains("Generating a pad for bob"),
        "names who the pad is for: {rows:?}"
    );

    let body = popup_body(&buffer_at(&state, 100, 30), "Generating a pad").join("\n");
    assert!(body.contains("3MB per key"), "names the chosen size: {body:?}");
    assert!(body.contains("6MB"), "names the total randomness: {body:?}");
    assert!(body.contains("50%"), "shows how far along it is: {body:?}");
}

#[test]
fn closing_the_keygen_spinner_takes_it_away() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_otp_keygen(UserId(2), "bob".into(), 1);
    state.close_otp_keygen();
    assert!(state.otp_keygen_open().is_none());
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

// ---------------------------------------------------------------------
// /endotp - ending a session, and surviving a reconnect (docs/PROTOCOL.md 16.6)
// ---------------------------------------------------------------------

/// @requirement AC-192
#[test]
fn clear_otp_active_reverses_mark_otp_active_and_drops_the_key_status_snapshot() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.mark_otp_active(UserId(2));
    state.set_otp_key_status(UserId(2), Default::default());
    assert!(state.is_otp_active(UserId(2)));
    assert!(state.otp_key_status_for(UserId(2)).is_some());

    state.clear_otp_active(UserId(2));

    assert!(!state.is_otp_active(UserId(2)));
    assert!(
        state.otp_key_status_for(UserId(2)).is_none(),
        "a session started fresh with this peer later must not show a stale reading from the \
         one just ended"
    );
}

/// The per-connection `otp_active_peers` flag must never be cleared by a
/// mere disconnect - only `/endotp`, on either side, may end a session
/// (`docs/PROTOCOL.md` 16.6). `on_user_offline` is the one call site every
/// disconnect goes through (`session::handle_server_message`'s
/// `UserOffline` arm), so this pins the actual regression the reconnect
/// requirement is about.
///
/// @requirement AC-193
#[test]
fn a_disconnect_alone_does_not_end_an_active_otp_session() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.mark_otp_active(UserId(2));

    state.on_user_offline(UserId(2));

    assert!(
        state.is_otp_active(UserId(2)),
        "bob disconnecting must not by itself end the session - only /endotp may"
    );
}

/// `submit_input`'s counterpart to `/otp`'s own
/// `accepting_an_invite_produces_accept_otp_invite_action`-style tests:
/// `/endotp` for the currently open DM room produces `EndOtpSession`
/// addressed to that exact peer, with their current key material attached
/// (`send_end_session_payload` needs it to build the outer `pq_hybrid`
/// envelope).
///
/// @requirement AC-192
#[test]
fn endotp_in_an_open_dm_room_produces_end_otp_session_for_that_peer() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens DM with bob
    assert_eq!(state.active_private_room, Some(UserId(2)));

    type_str(&mut state, "/endotp");
    let action = press(&mut state, KeyCode::Enter);
    match action {
        Some(UiAction::EndOtpSession {
            peer,
            pubkey_der,
        }) => {
            assert_eq!(peer, UserId(2));
            assert_eq!(pubkey_der, pq_hybrid_user(2, "bob").public_key_der);
        }
        other => panic!("expected EndOtpSession, got {other:?}"),
    }
    assert_eq!(state.input, "");
}

/// @requirement AC-192
#[test]
fn endotp_outside_any_open_dm_room_is_a_no_op() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    assert_eq!(state.active_private_room, None);
    type_str(&mut state, "/endotp");
    assert_eq!(press(&mut state, KeyCode::Enter), None);
}

/// @requirement AC-141
#[test]
fn messages_in_an_otp_active_dm_get_the_pad_prefix_but_system_lines_never_do() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.mark_otp_active(UserId(2));
    state.push_otp_system_message(UserId(2), "bob", "OTP session started at now".to_string());
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hello under the pad".into()));

    let rows = rendered_rows(&state);
    assert!(
        appears_before(&rows, OTP_ICON, "bob: hello under the pad"),
        "a real message in an OTP-active DM should carry the pad prefix: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("bob: hello under the pad") && r.contains('\u{1F6E1}')),
        "and not the shield, which is pq_hybrid's own tag: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| {
            let Some(system_at) = r.find("OTP session started at now") else {
                return false;
            };
            r[..system_at].contains(OTP_ICON)
        }),
        "an app system line must never itself get the pad prefix: {rows:?}"
    );
}

/// @requirement AC-141
#[test]
fn messages_in_a_dm_without_an_active_otp_session_get_no_pad_marker() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    state.active_private_room = Some(UserId(2));
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("plain hello".into()));

    // Checked against the message row specifically, not the whole screen -
    // the room title carries bob's own pq_hybrid tag
    // (`KeyMode::format_with_name`), which is a different marker entirely.
    let rows = rendered_rows(&state);
    assert!(
        !rows.iter().any(|r| r.contains("bob: plain hello") && r.contains(OTP_ICON)),
        "no pad marker should appear without an active OTP session: {rows:?}"
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
        otp_status(ContactDetail {
            enc_sequence: 3,
            enc_offset: 300,
            enc_key_remaining: 2_000_000,
            dec_sequence: 5,
            dec_offset: 500,
            dec_key_remaining: 2_000_000,
        }),
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
        otp_status(ContactDetail {
            enc_sequence: 0,
            enc_offset: 0,
            enc_key_remaining: 100_000, // well under 0.5MB - red
            dec_sequence: 0,
            dec_offset: 0,
            dec_key_remaining: 5_000_000, // well over 0.5MB - green
        }),
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
        state.push_outgoing_dm(UserId(2), MessageBody::Text("one".into()), None),
        Some(0)
    );
    assert_eq!(
        state.push_outgoing_dm(UserId(2), MessageBody::Text("two".into()), None),
        Some(1)
    );
    assert_eq!(state.private_rooms[&UserId(2)].log.len(), 2);

    // No room exists yet for a peer nothing has been sent to or received
    // from - nothing to return an index into.
    assert_eq!(
        state.push_outgoing_dm(UserId(3), MessageBody::Text("nobody".into()), None),
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
        .push_outgoing_dm(UserId(2), MessageBody::Text("ok".into()), None)
        .unwrap();
    let second = state
        .push_outgoing_dm(UserId(2), MessageBody::Text("will fail".into()), None)
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
        .push_outgoing_dm(UserId(2), MessageBody::Text("never arrived".into()), None)
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
        .push_outgoing_dm(UserId(2), MessageBody::Text("arrived fine".into()), None)
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

// ---------------------------------------------------------------------
// The top row's DM selector (AC-020, AC-186, AC-187, TB-026, TB-210)
// ---------------------------------------------------------------------

/// Opens a DM with `peer` the way a user does: cursor on them in the
/// sidebar, Enter.
fn open_dm_with(state: &mut UiState, row: usize) {
    state.focus = Focus::Sidebar;
    state.sidebar_selected = row;
    press(state, KeyCode::Enter);
}

/// The DM selector names one person, and an open room is the one view
/// with no user list of its own - so the same colour their name carries in
/// the channel sidebar has to be on it, or nothing on screen says whether
/// what is being typed can reach them.
/// @requirement AC-229
#[test]
fn the_dm_selector_colours_its_peer_by_the_direct_link_to_them() {
    let cases = [
        (LinkStatus::Active, ratatui::style::Color::Green),
        (LinkStatus::Connecting, ratatui::style::Color::DarkGray),
        (LinkStatus::Lost, ratatui::style::Color::DarkGray),
    ];
    for (link, expected) in cases {
        let mut state = joined_general_with(vec![user(2, "bob")]);
        open_dm_with(&mut state, 0);
        // Back onto the channel selector, so the DM name is not also
        // carrying the focus highlight while its colour is read.
        press(&mut state, KeyCode::Char('['));
        state.set_link_status(UserId(2), link);

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let (x, y) = find_text_start(&buffer, "bob");
        assert_eq!(
            y as usize, HEADER_TEXT_ROW,
            "the first `bob` on screen is the one on the DM selector"
        );
        assert_eq!(
            buffer[(x, y)].fg,
            expected,
            "a {link:?} link must colour the DM selector {expected:?}"
        );
    }
}

/// The same two overrides the sidebar applies, in the same order.
/// @requirement AC-229
#[test]
fn an_offline_or_unverified_peer_overrides_the_link_colour_on_the_dm_selector() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_dm_with(&mut state, 0);
    press(&mut state, KeyCode::Char('['));
    state.set_link_status(UserId(2), LinkStatus::Active);
    // Something in the room, so an offline peer is kept listed rather than
    // dropped outright.
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("hi".into()));
    state.on_user_offline(UserId(2));

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let (x, y) = find_text_start(&buffer, "bob");
    assert_eq!(y as usize, HEADER_TEXT_ROW);
    assert_eq!(
        buffer[(x, y)].fg,
        ratatui::style::Color::DarkGray,
        "a peer whose connection closed reads as gone, whatever their link last did"
    );
}

/// @requirement AC-229
#[test]
fn the_dm_dropdown_colours_every_room_it_lists_the_same_way() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_dm_with(&mut state, 0);
    open_dm_with(&mut state, 1);
    state.set_link_status(UserId(2), LinkStatus::Active);

    let entries = state.selector_dropdown_entries();
    // The dropdown lists every room *except* the one the selector names.
    assert!(!entries.is_empty(), "the other open room must be listed");
    for entry in entries {
        assert!(
            entry.presence.is_some(),
            "a DM row names a person and must carry their presence: {:?}",
            entry.label
        );
    }
}

/// @requirement AC-186
#[test]
fn the_dm_selector_is_absent_until_a_room_has_been_opened() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    let top = rendered_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(!top.contains("bob"), "nothing to name yet: {top:?}");
    assert_eq!(state.selected_dm, None);

    // `]` has nowhere to go while it isn't there.
    press(&mut state, KeyCode::Char(']'));
    assert_eq!(state.active_private_room, None);

    open_dm_with(&mut state, 0);
    press(&mut state, KeyCode::Char('['));
    let top = rendered_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains("bob"), "the room is named on it now: {top:?}");
}

/// `]` from the channel selector focuses the DM one - it does *not* open
/// its dropdown, and it does not wrap back round to the channels.
///
/// @requirement AC-020
#[test]
fn closing_bracket_moves_between_the_two_selectors_without_wrapping() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_dm_with(&mut state, 0);
    press(&mut state, KeyCode::Char('[')); // back onto the channel selector
    assert_eq!(state.active_private_room, None);

    press(&mut state, KeyCode::Char(']'));
    assert_eq!(
        state.active_private_room,
        Some(UserId(2)),
        "] focuses the DM selector, which opens the room it names"
    );
    assert!(!state.selector_dropdown_open, "without opening its dropdown");

    press(&mut state, KeyCode::Char('['));
    assert_eq!(state.active_private_room, None, "and [ steps back");
    assert!(!state.selector_dropdown_open);
}

/// @requirement AC-020, AC-186
#[test]
fn closing_bracket_on_the_dm_selector_opens_its_dropdown_and_up_down_switch_rooms() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_dm_with(&mut state, 0); // bob
    open_dm_with(&mut state, 1); // carol - now the selected DM
    assert_eq!(state.selected_dm, Some(UserId(3)));

    press(&mut state, KeyCode::Char(']'));
    assert!(state.selector_dropdown_open);

    let labels: Vec<String> = state
        .selector_dropdown_entries()
        .into_iter()
        .map(|e| e.label)
        .collect();
    assert_eq!(labels.len(), 1, "{labels:?}");
    assert!(labels[0].contains("bob"), "{labels:?}");
    assert!(
        !labels.iter().any(|l| l.contains("carol")),
        "the room already on screen is not offered again: {labels:?}"
    );

    press(&mut state, KeyCode::Down);
    assert_eq!(
        state.active_private_room,
        Some(UserId(2)),
        "Down switches the room behind the overlay straight away"
    );
    press(&mut state, KeyCode::Char('['));
    assert!(!state.selector_dropdown_open, "[ closes the DM dropdown");
    assert_eq!(
        state.active_private_room,
        Some(UserId(2)),
        "closing it keeps what Down landed on, and stays in the room"
    );
}

/// A room that was opened and never written in still counts - "every DM
/// you have open", not "every DM with something in it".
///
/// @requirement AC-186
#[test]
fn an_empty_room_still_counts_on_the_dm_selector() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_dm_with(&mut state, 0);
    open_dm_with(&mut state, 1);
    assert!(state.private_rooms[&UserId(2)].log.is_empty());

    let top = rendered_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains("carol"), "{top:?}");
    assert!(top.contains("+1 more..."), "{top:?}");
}

/// @requirement AC-187
#[test]
fn an_unread_dm_blinks_an_envelope_on_the_dm_selector_until_it_is_opened() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_dm_with(&mut state, 1); // reading carol's room
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("psst".into()));
    assert!(state.any_dm_unread());

    state.blink_on = true;
    let top = rendered_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains('\u{2709}'), "{top:?}");
    state.blink_on = false;
    let top = rendered_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(!top.contains('\u{2709}'), "{top:?}");

    // Open dropdown: the envelope moves onto bob's own row.
    press(&mut state, KeyCode::Char(']'));
    state.blink_on = true;
    let rows = rendered_rows(&state);
    assert!(!rows[HEADER_TEXT_ROW].contains('\u{2709}'), "{rows:?}");
    let row = rows
        .iter()
        .skip(FIRST_ROW_BELOW_HEADER)
        .find(|r| r.contains("bob"))
        .unwrap_or_else(|| panic!("no dropdown row for bob: {rows:?}"));
    assert!(row.contains('\u{2709}'), "{row:?}");

    press(&mut state, KeyCode::Down); // onto bob's room - reading it
    assert!(!state.any_dm_unread());
}

/// A message from someone else never yanks the selector off the room being
/// read - it raises that room's envelope instead.
///
/// @requirement TB-210
#[test]
fn an_incoming_dm_never_takes_the_selector_off_the_room_being_read() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    open_dm_with(&mut state, 1); // carol
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("psst".into()));

    assert_eq!(state.selected_dm, Some(UserId(3)));
    assert_eq!(state.active_private_room, Some(UserId(3)));
    assert_eq!(
        state.dm_order,
        vec![UserId(3), UserId(2)],
        "rooms keep the order they were first opened in"
    );
}

/// The very first room to exist is what the selector names - it has to
/// name something the moment it appears.
///
/// @requirement TB-210
#[test]
fn the_first_room_created_becomes_what_the_dm_selector_names() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("psst".into()));
    assert_eq!(state.selected_dm, Some(UserId(2)));
    assert_eq!(
        state.active_private_room, None,
        "named, but not opened - it is still unread"
    );
    assert!(state.private_rooms[&UserId(2)].unread);
}

/// @requirement TB-026
#[test]
fn escape_leaves_the_room_but_keeps_it_on_the_dm_selector() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_dm_with(&mut state, 0);

    press(&mut state, KeyCode::Esc);
    assert_eq!(state.active_private_room, None);
    assert_eq!(state.selected_dm, Some(UserId(2)));
    let top = rendered_rows(&state).remove(HEADER_TEXT_ROW);
    assert!(top.contains("bob"), "still on the DM selector: {top:?}");
}

/// A room is reached through the top row, so the row is part of its view -
/// the user can see where they are and `[` takes them back.
///
/// @requirement AC-186
#[test]
fn the_private_room_view_draws_the_same_top_row() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    open_dm_with(&mut state, 0);
    let rows = rendered_rows(&state);
    assert!(rows[HEADER_TEXT_ROW].contains("general"), "{rows:?}");
    assert!(rows[HEADER_TEXT_ROW].contains("bob"), "{rows:?}");
    assert!(rows[HEADER_TEXT_ROW].contains("Ctrl+H: Help"), "{rows:?}");
}

// ---------------------------------------------------------------------
// Delivery acknowledgments (US-041)
// ---------------------------------------------------------------------

/// Opens bob's room and sends one text through the real compose path, so
/// the row and the action agree on the same `msg_id` - which is the whole
/// mechanism (docs/PROTOCOL.md 7.2.1).
fn send_dm_to_bob(text: &str) -> (UiState, u64) {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens bob's room
    state.focus = Focus::Input;
    type_str(&mut state, text);
    let action = press(&mut state, KeyCode::Enter).expect("a send was produced");
    let msg_id = match action {
        UiAction::SendDirectText { msg_id, .. } => msg_id,
        other => panic!("expected SendDirectText, got {other:?}"),
    };
    (state, msg_id)
}

/// @requirement AC-230
#[test]
fn a_sent_direct_message_starts_undelivered_and_turns_delivered() {
    let (mut state, msg_id) = send_dm_to_bob("did you get this");
    let status = |s: &UiState| s.private_rooms[&UserId(2)].log[0].delivery_status();

    assert_eq!(
        status(&state),
        Some(DeliveryStatus::None),
        "a message nobody has acknowledged yet is undelivered"
    );
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        status(&state),
        Some(DeliveryStatus::All),
        "a DM has one recipient, so their acknowledgement is the whole of it"
    );
}

/// @requirement AC-230
#[test]
fn the_arrow_is_coloured_by_how_far_the_message_has_got() {
    let (mut state, msg_id) = send_dm_to_bob("did you get this");

    let arrow_fg = |s: &UiState| {
        let backend = TestBackend::new(100, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, s)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let (x, y) = find_text_start(&buffer, DELIVERY_ARROW);
        buffer[(x, y)].fg
    };

    assert_eq!(
        arrow_fg(&state),
        DeliveryStatus::None.color(),
        "the arrow starts in the not-yet colour"
    );
    state.mark_delivered(UserId(2), msg_id, ReceiptStage::Decrypted, DeliveryProof::Receipt);
    assert_eq!(
        arrow_fg(&state),
        DeliveryStatus::All.color(),
        "and turns to the delivered colour once the recipient acknowledges it"
    );
}

/// The shield marks the *content* as OTP-wrapped, so it stays at the very
/// start of the row - the arrow is about delivery and belongs where the
/// separator always was.
/// @requirement AC-230
#[test]
fn the_shield_prefix_stays_at_the_start_of_the_row() {
    let (mut state, _) = send_dm_to_bob("under the pad");
    state.mark_otp_active(UserId(2));

    // Ordering rather than exact columns: the pad marker is a wide glyph,
    // so per-cell reconstruction is only reliable for relative position
    // (see `appears_before`'s doc).
    let rows = rendered_rows(&state);
    assert!(
        appears_before(&rows, OTP_ICON, DELIVERY_ARROW),
        "the pad marker opens the row; the arrow separates the nickname from the text: {rows:?}"
    );
}

/// The envelope blinks right beside the nickname it belongs to, so it
/// carries that nickname's own colour rather than the generic unread
/// yellow: two colours on one name read as two separate facts about it
/// instead of one person with unread messages
/// (`docs/SPEC.md` "Connected UI").
/// @requirement AC-239
#[test]
fn the_dm_selectors_unread_envelope_takes_the_peers_own_colour() {
    let cases = [
        (LinkStatus::Active, ratatui::style::Color::Green),
        (LinkStatus::Connecting, ratatui::style::Color::DarkGray),
        (LinkStatus::Lost, ratatui::style::Color::DarkGray),
    ];
    for (link, expected) in cases {
        let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
        open_dm_with(&mut state, 1); // reading carol's room
        press(&mut state, KeyCode::Char('['));
        state.set_link_status(UserId(3), link);
        state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("psst".into()));
        state.blink_on = true;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, &state)).unwrap();
        let buffer = terminal.backend().buffer().clone();

        let (name_x, name_y) = find_text_start(&buffer, "carol");
        let (envelope_x, envelope_y) = find_text_start(&buffer, "\u{2709}");
        assert_eq!(
            envelope_y as usize, HEADER_TEXT_ROW,
            "the envelope under test is the one on the DM selector"
        );
        assert_eq!(
            buffer[(envelope_x, envelope_y)].fg,
            buffer[(name_x, name_y)].fg,
            "the envelope must match the nickname it sits beside"
        );
        assert_eq!(
            buffer[(envelope_x, envelope_y)].fg,
            expected,
            "a {link:?} link colours both {expected:?}"
        );
    }
}

/// The channel selector's envelope is plain white: a channel is a room,
/// not a person, and has no reachability to say anything about.
/// @requirement AC-239
#[test]
fn the_channel_selectors_envelope_is_plain_white() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.on_joined(aloo::proto::ChannelInfo {
        name: "random".into(),
        kind: aloo::proto::ChannelKind::Public,
    });
    // Back on `general`, so the message below lands in a channel that is
    // not the one being read - which is what raises an envelope at all.
    state.select_channel_at(0);
    state.on_channel_message(
        "random",
        UserId(2),
        "bob".into(),
        MessageBody::Text("over here".into()),
    );
    assert!(state.any_channel_unread());
    state.blink_on = true;

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let (x, y) = find_text_start(&buffer, "\u{2709}");
    assert_eq!(y as usize, HEADER_TEXT_ROW);
    assert_eq!(buffer[(x, y)].fg, ratatui::style::Color::White);
}

// ---------------------------------------------------------------------
// One marker for a pad session, everywhere it applies (docs/SPEC.md
// "Connected UI")
// ---------------------------------------------------------------------

/// A room under the pad is marked as such wherever it is named: on every
/// message, on the DM selector, on its dropdown row, in the room's own
/// title, and in the compose bar the next message is typed into.
/// @requirement AC-246
#[test]
fn a_pad_session_marks_every_surface_of_the_room_it_is_with() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob"), pq_hybrid_user(3, "carol")]);
    for row in [0, 1] {
        state.focus = Focus::Sidebar;
        state.sidebar_selected = row;
        press(&mut state, KeyCode::Enter);
    }
    state.mark_otp_active(UserId(2));
    state.mark_otp_active(UserId(3));
    state.on_direct_message(UserId(2), "bob".into(), MessageBody::Text("under the pad".into()));
    open_dm_with(&mut state, 0);
    state.focus = Focus::Input;
    type_str(&mut state, "typing");

    let rows = rendered_rows(&state);
    let row_with = |needle: &str| -> String {
        rows.iter()
            .find(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("no row contains {needle:?}: {rows:?}"))
            .clone()
    };

    // The message itself, and the room's own title.
    assert!(
        appears_before(&rows, OTP_ICON, "bob: under the pad"),
        "the pad marks the message: {rows:?}"
    );
    let title = row_with("Private: bob");
    assert!(
        title.contains("OTP") && !title.contains('\u{1F6E1}'),
        "the title carries the pad tag, not the layer under it: {title:?}"
    );
    // The compose bar, before what is being typed.
    let compose = row_with("typing");
    assert!(
        appears_before(std::slice::from_ref(&compose), OTP_ICON, "typing"),
        "the bar says what will happen to the next message too: {compose:?}"
    );
    // The DM selector names bob; the dropdown row names carol.
    assert!(
        appears_before(&[rows[HEADER_TEXT_ROW].clone()], "bob", "OTP"),
        "the DM selector: {:?}",
        rows[HEADER_TEXT_ROW]
    );
    press(&mut state, KeyCode::Char(']'));
    press(&mut state, KeyCode::Char(']'));
    // Read inside the dropdown's own border: it overlays the room title,
    // whose tag would otherwise be mistaken for the row's.
    let dropdown = popup_body(&buffer_at(&state, 100, 30), "DMs");
    let carol = dropdown
        .iter()
        .find(|r| r.contains("carol"))
        .unwrap_or_else(|| panic!("no dropdown row for carol: {dropdown:?}"));
    assert!(
        appears_before(std::slice::from_ref(carol), "carol", "OTP"),
        "and every other room under a pad carries it too: {carol:?}"
    );
}

/// The compose bar is unmarked in a room with no session, so the marker
/// means something when it is there.
/// @requirement AC-246
#[test]
fn the_compose_bar_is_unmarked_without_a_pad_session() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob")]);
    open_dm_with(&mut state, 0);
    state.focus = Focus::Input;
    type_str(&mut state, "typing");

    let rows = rendered_rows(&state);
    let compose = rows
        .iter()
        .find(|r| r.contains("typing"))
        .expect("the compose bar");
    assert!(!compose.contains(OTP_ICON), "{compose:?}");
}

/// Agreeing a session opens the room it is with: both sides just decided
/// deliberately, and the conversation it was for is what they want next.
/// @requirement AC-249
#[test]
fn agreeing_a_pad_session_opens_the_room_it_is_with() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob"), pq_hybrid_user(3, "carol")]);
    // Reading carol's room when bob's session is agreed.
    open_dm_with(&mut state, 1);
    assert_eq!(state.active_private_room, Some(UserId(3)));

    state.open_otp_session(UserId(2));

    assert_eq!(
        state.active_private_room,
        Some(UserId(2)),
        "the room the session is with is what is on screen"
    );
    assert_eq!(state.selected_dm, Some(UserId(2)), "and what the selector names");
    assert!(state.is_otp_active(UserId(2)));
    assert_eq!(state.focus, Focus::Input, "ready to type into it");
}

/// A session resumed because its peer reconnected is not a moment anyone
/// asked for, so it must never take the view off whatever is being read.
/// @requirement AC-249
#[test]
fn a_session_resumed_on_reconnect_does_not_steal_the_view() {
    let mut state = joined_general_with(vec![pq_hybrid_user(2, "bob"), pq_hybrid_user(3, "carol")]);
    open_dm_with(&mut state, 1);
    assert_eq!(state.active_private_room, Some(UserId(3)));

    state.mark_otp_active(UserId(2));

    assert_eq!(
        state.active_private_room,
        Some(UserId(3)),
        "resuming a session leaves the reader where they were"
    );
    assert!(state.is_otp_active(UserId(2)));
}

/// A superseded proposal must not still be sitting in front of the user.
///
/// The sending side already retires its own stale state when `/otp` runs
/// again; the receiver did not, so a second attempt left the first
/// attempt's popup queued behind the new one - one `/otp`, two decision
/// popups. Worse, accepting the stale one reports digests for a pad whose
/// staging directory has already been erased.
///
/// @requirement AC-256
#[test]
fn a_second_proposal_from_one_peer_replaces_the_first_rather_than_queueing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.push_otp_invite(UserId(2), "bob".into(), "contact-a".into(), None, None, None);
    state.push_otp_invite(
        UserId(2),
        "bob".into(),
        "contact-a".into(),
        None,
        None,
        Some(500),
    );

    let open = state.otp_invite_open().expect("a proposal is open");
    assert_eq!(
        open.pad_size_mb,
        Some(500),
        "the newer proposal is the one that stands"
    );
    state.take_otp_invite();
    assert!(
        state.otp_invite_open().is_none(),
        "answering it must leave nothing queued behind - one proposal, one decision"
    );
}

/// And retiring one explicitly clears it, which is what a superseded pad
/// transfer relies on (`otp::on_pad_start`).
///
/// @requirement AC-256
#[test]
fn retiring_a_peers_proposal_removes_it_from_the_queue() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.push_otp_invite(UserId(2), "bob".into(), "c-b".into(), None, None, None);
    state.push_otp_invite(UserId(3), "carol".into(), "c-c".into(), None, None, None);

    assert!(state.take_otp_invite_from(UserId(2)));
    let open = state.otp_invite_open().expect("carol's is untouched");
    assert_eq!(open.from, UserId(3), "only the named peer's proposal goes");
    assert!(
        !state.take_otp_invite_from(UserId(2)),
        "retiring one that is already gone reports nothing to retire"
    );
}
