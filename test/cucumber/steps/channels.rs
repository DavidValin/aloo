//! Channel-switching steps (US-004, client side), plus password-protected
//! private channels (US-025) and the P2P trust boundary (TB-155).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use cucumber::{given, then, when};

use aloo::proto::{ChannelJoinRejection, ChannelKind, UserId};
use aloo::server::CHANNEL_MAX_PASSWORD_ATTEMPTS;
use aloo::client::tui::channel::DWELL_DURATION;
use aloo::client::tui::ui::{Mode, UiAction};

use crate::steps::ui_common::id_for;
use crate::world::AlooWorld;

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

#[when("I wait on that tab for longer than the join delay")]
async fn wait_out_dwell(w: &mut AlooWorld) {
    let later = Instant::now() + DWELL_DURATION + Duration::from_millis(1);
    let action = w.ui_mut().tick_dwell(later);
    w.action_was_none = action.is_none();
    w.last_action = action;
}

#[when("I check the dwell timer straight away")]
async fn check_dwell_now(w: &mut AlooWorld) {
    let action = w.ui_mut().tick_dwell(Instant::now());
    w.action_was_none = action.is_none();
    w.last_action = action;
}

#[then(expr = "the selected channel is {string}")]
async fn selected_channel_is(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let selected = &state.channels[state.selected_channel];
    assert_eq!(
        selected.name, name,
        "the tab selection should have moved immediately"
    );
}

#[then(expr = "{string} has not been joined yet")]
async fn not_joined_yet(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let ch = state
        .channels
        .iter()
        .find(|c| c.name == name)
        .expect("no such channel");
    assert!(
        !ch.joined,
        "selecting a tab must not join it - the dwell delay has not elapsed"
    );
}

#[then("no join is requested yet")]
async fn no_join_yet(w: &mut AlooWorld) {
    assert!(
        w.action_was_none,
        "the dwell timer should not fire before the delay has passed"
    );
}

#[then(expr = "joining {string} is requested")]
async fn join_requested(w: &mut AlooWorld, name: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::JoinChannel {
            name: got, kind, ..
        } => {
            assert_eq!(got, &name);
            assert_eq!(
                *kind,
                ChannelKind::Public,
                "a tab from the server's list is a public channel"
            );
        }
        other => panic!("expected a JoinChannel request, got {other:?}"),
    }
}

#[then(expr = "joining the private channel {string} is requested")]
async fn private_join_requested(w: &mut AlooWorld, name: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::JoinChannel {
            name: got, kind, ..
        } => {
            assert_eq!(got, &name);
            assert_eq!(
                *kind,
                ChannelKind::Private,
                "Ctrl+J creates private channels, not public ones"
            );
        }
        other => panic!("expected a JoinChannel request, got {other:?}"),
    }
    assert_eq!(
        w.ui_ref().mode,
        Mode::Normal,
        "the popup should close once the name is submitted"
    );
}

#[then(expr = "joining the private channel {string} with password {string} is requested")]
async fn private_join_with_password_requested(w: &mut AlooWorld, name: String, password: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::JoinChannel {
            name: got,
            kind,
            password: got_pw,
        } => {
            assert_eq!(got, &name);
            assert_eq!(*kind, ChannelKind::Private);
            assert_eq!(got_pw.as_deref(), Some(password.as_str()));
        }
        other => panic!("expected a JoinChannel request, got {other:?}"),
    }
}

#[then("the join-channel popup is open")]
async fn popup_open(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().mode,
        Mode::JoinPrivatePopup,
        "Ctrl+J should open the join popup"
    );
}

#[then("the join-channel popup is closed and forgotten")]
async fn popup_cancelled(w: &mut AlooWorld) {
    let state = w.ui_ref();
    assert_eq!(state.mode, Mode::Normal, "Esc should close the popup");
    assert_eq!(
        state.join_popup_input, "",
        "the abandoned name must not linger"
    );
    assert!(w.action_was_none, "cancelling must not request a join");
}

#[then("no private room is open")]
async fn no_private_room(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().active_private_room,
        None,
        "switching tabs should close any private room"
    );
}

// ---------------------------------------------------------------------
// Leaving a channel (US-026)
// ---------------------------------------------------------------------

/// Applies the `UiAction::LeaveChannel` `last_action` produced by pressing
/// Enter on `/leave` - stands in for `channel::handle_leave`'s local half,
/// which normally runs inside `session.rs` once the wire message is sent.
#[when("the leave completes")]
async fn leave_completes(w: &mut AlooWorld) {
    let name = match w.last_action.take() {
        Some(UiAction::LeaveChannel { name }) => name,
        other => panic!("expected a LeaveChannel action, got {other:?}"),
    };
    w.ui_mut().leave_channel_locally(&name);
}

#[then(expr = "the channel {string} is no longer shown")]
async fn channel_no_longer_shown(w: &mut AlooWorld, channel: String) {
    assert!(
        !w.ui_ref().channels.iter().any(|c| c.name == channel),
        "expected {channel:?}'s tab to be gone"
    );
}

#[then(expr = "the channel {string} is still shown")]
async fn channel_still_shown(w: &mut AlooWorld, channel: String) {
    assert!(
        w.ui_ref().channels.iter().any(|c| c.name == channel),
        "expected {channel:?}'s tab to still be there"
    );
}

#[then(expr = "the channel {string} is not joined")]
async fn channel_not_joined(w: &mut AlooWorld, channel: String) {
    let tab = w
        .ui_ref()
        .channels
        .iter()
        .find(|c| c.name == channel)
        .unwrap_or_else(|| panic!("no such channel {channel:?}"));
    assert!(!tab.joined);
    assert!(tab.left);
}

// ---------------------------------------------------------------------
// Password-protected private channels (US-025)
// ---------------------------------------------------------------------

fn ensure_registered(w: &mut AlooWorld, name: &str) -> UserId {
    if let Some(&id) = w.ids.get(name) {
        return id;
    }
    let id = w
        .registry_mut()
        .register(name.to_string(), vec![1, 2, 3], aloo::proto::KeyMode::Password);
    w.ids.insert(name.to_string(), id);
    id
}

#[when(expr = "{word} creates the private channel {string} with the password {string}")]
async fn create_private_with_password(
    w: &mut AlooWorld,
    who: String,
    channel: String,
    password: String,
) {
    let id = ensure_registered(w, &who);
    w.registry_mut()
        .join_channel(id, &channel, ChannelKind::Private, Some(&password), TEST_IP)
        .expect("channel creation should succeed");
}

#[when(expr = "{word} joins the private channel {string} with the password {string}")]
async fn join_private_with_password(
    w: &mut AlooWorld,
    who: String,
    channel: String,
    password: String,
) {
    let id = ensure_registered(w, &who);
    let out = w
        .registry_mut()
        .join_channel(id, &channel, ChannelKind::Private, Some(&password), TEST_IP)
        .expect("join should not error");
    w.emitted = out;
}

#[given(
    expr = "{word} is a registered user who created the private channel {string} with the password {string}"
)]
async fn given_created_private_with_password(
    w: &mut AlooWorld,
    who: String,
    channel: String,
    password: String,
) {
    create_private_with_password(w, who, channel, password).await;
}

#[then(expr = "bob is confirmed as joined to {string}")]
async fn bob_confirmed_joined_to(w: &mut AlooWorld, channel: String) {
    let bob = w.id_of("bob");
    assert!(
        w.emitted
            .iter()
            .any(|o| o.to == bob && matches!(&o.message, aloo::proto::ServerMessage::Joined { channel: c } if c.name == channel)),
        "expected bob to receive a Joined confirmation for {channel}: {:?}",
        w.emitted
    );
}

#[when(expr = "the server reports that {string} requires a password")]
async fn server_reports_password_required(w: &mut AlooWorld, channel: String) {
    w.ui_mut()
        .on_channel_join_rejected(channel, ChannelJoinRejection::PasswordRequired);
}

#[when(expr = "the server reports that the password for {string} was wrong")]
async fn server_reports_wrong_password(w: &mut AlooWorld, channel: String) {
    w.ui_mut()
        .on_channel_join_rejected(channel, ChannelJoinRejection::WrongPassword);
}

#[then(expr = "the channel password popup is open for {string}")]
async fn password_popup_open_for(w: &mut AlooWorld, channel: String) {
    let state = w.ui_ref();
    assert_eq!(state.mode, Mode::ChannelPasswordPopup);
    assert_eq!(
        state.channel_password_target.as_deref(),
        Some(channel.as_str())
    );
}

#[then("no password error is shown")]
async fn no_password_error(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().channel_password_error, None);
}

#[then(expr = "the password error {string} is shown")]
async fn password_error_shown(w: &mut AlooWorld, message: String) {
    assert_eq!(
        w.ui_ref().channel_password_error.as_deref(),
        Some(message.as_str())
    );
}

#[when(
    expr = "{word} attempts to join {string} with the wrong password 8 times from the same address"
)]
async fn attempts_wrong_password_eight_times(w: &mut AlooWorld, who: String, channel: String) {
    assert!(
        CHANNEL_MAX_PASSWORD_ATTEMPTS < 8,
        "scenario assumes the ban trips before the 8th attempt"
    );
    let id = ensure_registered(w, &who);
    let mut last = Vec::new();
    for _ in 0..8 {
        last = w
            .registry_mut()
            .join_channel(id, &channel, ChannelKind::Private, Some("wrong"), TEST_IP)
            .expect("join should not error");
    }
    w.emitted = last;
}

#[then("the eighth attempt is reported as banned, not merely wrong")]
async fn eighth_attempt_banned(w: &mut AlooWorld) {
    assert!(
        w.emitted.iter().any(|o| matches!(
            &o.message,
            aloo::proto::ServerMessage::ChannelJoinRejected {
                kind: ChannelJoinRejection::Banned,
                ..
            }
        )),
        "expected the 8th attempt to be reported as Banned: {:?}",
        w.emitted
    );
}

// ---------------------------------------------------------------------
// P2P trust boundary (TB-155)
// ---------------------------------------------------------------------

#[then(expr = "I would accept a direct link request from {word}")]
async fn would_accept_link_from(w: &mut AlooWorld, who: String) {
    assert!(w.ui_ref().shares_a_joined_channel(UserId(id_for(&who))));
}

#[then(expr = "I would not accept a direct link request from a stranger")]
async fn would_not_accept_link_from_stranger(w: &mut AlooWorld) {
    // An id no channel member in these scenarios ever uses.
    assert!(!w.ui_ref().shares_a_joined_channel(UserId(999_999)));
}
