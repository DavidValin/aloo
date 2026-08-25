//! The user-info popup (`i` on a channel member, `/info` in an open DM):
//! a read-only snapshot of one live peer's pinned identity. Opening/
//! closing, dispatch and rendering are pure `UiState` tests here, the
//! same split `ui_contacts_test.rs` uses for its own popup - the
//! session-side gather (`client::contacts::handle_request_user_info`) is
//! exercised against a real `SessionState` in `user_info_test.rs`.

#[path = "ui_common.rs"]
mod ui_common;
use ui_common::*;

use aloo::client::tui::contacts::{ContactKeyKind, UserInfoKeyRow};
use aloo::client::tui::ui::{Focus, UiAction};
use aloo::proto::UserId;
use crossterm::event::KeyCode;

/// @requirement AC-324
#[test]
fn i_on_a_sidebar_member_opens_user_info() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    let action = press(&mut state, KeyCode::Char('i'));
    assert_eq!(
        action,
        Some(UiAction::RequestUserInfo { peer: UserId(2), nickname: "bob".to_string() })
    );
    let info = state.user_info.as_ref().expect("popup open");
    assert_eq!(info.peer, UserId(2));
    assert_eq!(info.nickname, "bob");
    assert!(info.keys.is_empty(), "nothing gathered yet - the session's answer hasn't arrived");
}

/// @requirement AC-324
#[test]
fn i_on_our_own_sidebar_row_does_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    // Our own row is always last (`handle_sidebar_key`'s +1).
    press(&mut state, KeyCode::Down);
    let action = press(&mut state, KeyCode::Char('i'));
    assert!(action.is_none());
    assert!(state.user_info.is_none());
}

/// @requirement AC-324
#[test]
fn esc_closes_the_user_info_popup() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Char('i'));
    assert!(state.user_info.is_some());
    press(&mut state, KeyCode::Esc);
    assert!(state.user_info.is_none());
}

/// @requirement AC-324
#[test]
fn i_again_also_closes_it_same_as_message_info() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Char('i'));
    assert!(state.user_info.is_some());
    press(&mut state, KeyCode::Char('i'));
    assert!(state.user_info.is_none());
}

/// @requirement AC-324
#[test]
fn the_popup_absorbs_every_other_key_while_open() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Char('i'));
    let action = press(&mut state, KeyCode::Down);
    assert!(action.is_none());
    assert!(state.user_info.is_some(), "an unrelated key must not close it either");
}

/// @requirement AC-324
#[test]
fn slash_info_inside_an_open_dm_opens_the_same_popup() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter); // opens the DM room with bob
    type_str(&mut state, "/info");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::RequestUserInfo { peer: UserId(2), nickname: "bob".to_string() })
    );
    assert!(state.user_info.is_some());
    assert_eq!(state.input, "", "the typed command is cleared, same as every other slash command");
}

/// @requirement AC-324
#[test]
fn slash_info_with_no_dm_open_does_nothing() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    type_str(&mut state, "/info");
    let action = press(&mut state, KeyCode::Enter);
    assert!(action.is_none());
    assert!(state.user_info.is_none());
}

/// `/info` is deliberately never gated on the peer being reachable - it's
/// a local, read-only lookup, same reasoning as `/endotp`.
/// @requirement AC-324
#[test]
fn slash_info_works_even_for_an_offline_peer() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.focus = Focus::Sidebar;
    press(&mut state, KeyCode::Enter);
    state.on_user_offline(UserId(2));
    type_str(&mut state, "/info");
    let action = press(&mut state, KeyCode::Enter);
    assert_eq!(
        action,
        Some(UiAction::RequestUserInfo { peer: UserId(2), nickname: "bob".to_string() })
    );
}

/// `set_user_info` (the session's answer) must not clobber a popup
/// reopened for someone else in the meantime, or write into a closed one.
/// @requirement AC-324
#[test]
fn set_user_info_is_a_no_op_for_the_wrong_peer_or_a_closed_popup() {
    let mut state = joined_general_with(vec![user(2, "bob"), user(3, "carol")]);
    state.open_user_info(UserId(2), "bob".to_string());
    state.set_user_info(UserId(3), None, None, vec![]);
    assert_eq!(
        state.user_info.as_ref().unwrap().nickname,
        "bob",
        "an answer for a different peer must not overwrite what's showing"
    );

    state.user_info = None;
    state.set_user_info(UserId(2), None, None, vec![]);
    assert!(state.user_info.is_none(), "no popup to fill in once it's been closed");
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// @requirement AC-324
#[test]
fn the_popup_shows_nickname_device_last_seen_and_every_key() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_user_info(UserId(2), "bob".to_string());
    state.set_user_info(
        UserId(2),
        Some("laptop".to_string()),
        Some(0),
        vec![
            UserInfoKeyRow { kind: ContactKeyKind::Pqh, id: "fp-abcd1234".to_string() },
            UserInfoKeyRow { kind: ContactKeyKind::Otp, id: "otp-contact-name".to_string() },
        ],
    );

    let body = popup_body(&buffer_at(&state, 140, 30), "bob").join("\n");
    assert!(body.contains("laptop"), "the device id: {body:?}");
    assert!(body.contains("PQH"), "the PQH row's label: {body:?}");
    assert!(body.contains("fp-abcd1234"), "the PQH row's id: {body:?}");
    assert!(body.contains("OTP"), "the OTP row's label: {body:?}");
    assert!(body.contains("otp-contact-name"), "the OTP row's id: {body:?}");
    assert!(!body.contains("OTP MAIL"), "no OTP MAIL row - none was gathered");
}

/// @requirement AC-324
#[test]
fn an_unbound_peer_shows_the_placeholder_device() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_user_info(UserId(2), "bob".to_string());
    state.set_user_info(UserId(2), None, None, vec![]);

    let body = popup_body(&buffer_at(&state, 140, 30), "bob").join("\n");
    assert!(body.contains("(unbound)"));
}

/// @requirement AC-324
#[test]
fn an_active_otp_session_is_named_at_the_end() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_user_info(UserId(2), "bob".to_string());
    state.set_user_info(UserId(2), Some("laptop".to_string()), None, vec![]);
    state.mark_otp_active(UserId(2));

    let body = popup_body(&buffer_at(&state, 140, 30), "bob").join("\n");
    assert!(body.contains("OTP session is currently active"));
}

/// @requirement AC-324
#[test]
fn no_active_otp_session_says_nothing_about_one() {
    let mut state = joined_general_with(vec![user(2, "bob")]);
    state.open_user_info(UserId(2), "bob".to_string());
    state.set_user_info(UserId(2), Some("laptop".to_string()), None, vec![]);

    let body = popup_body(&buffer_at(&state, 140, 30), "bob").join("\n");
    assert!(!body.contains("OTP session is currently active"));
}
