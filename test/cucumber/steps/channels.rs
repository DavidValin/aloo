//! Channel-switching steps (US-004, client side), plus password-protected
//! private channels (US-025) and the P2P trust boundary (TB-155).

use std::net::{IpAddr, Ipv4Addr};

use cucumber::{given, then, when};

use aloo::proto::{ChannelInfo, ChannelJoinRejection, ChannelKind, UserId};
use aloo::server::CHANNEL_MAX_PASSWORD_ATTEMPTS;
use aloo::client::tui::ui::{MessageBody, Mode, SelectorFocus, UiAction};

use crate::steps::ui_common::id_for;
use crate::support::{header_row, ui_rows_wide};
use crate::world::AlooWorld;

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

/// The connect-time `ChannelList` snapshot's one automatic join
/// (`UiState::auto_join_channel`) - `client::channel::on_list`'s decision,
/// reachable here without a live session.
#[when("the client applies the connect-time channel list")]
async fn apply_channel_list(w: &mut AlooWorld) {
    let action = w.ui_ref().auto_join_channel();
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

#[then("no join is requested")]
async fn no_join_requested(w: &mut AlooWorld) {
    assert!(
        w.action_was_none,
        "nothing here should have requested a join"
    );
}

// ---------------------------------------------------------------------
// The /channels directory (AC-172, AC-173, AC-174, TB-206)
// ---------------------------------------------------------------------

#[given(expr = "the server has announced the public channel {string}")]
async fn server_announced_channel(w: &mut AlooWorld, name: String) {
    w.ui_mut().on_channel_list(vec![aloo::proto::ChannelInfo {
        name,
        kind: ChannelKind::Public,
    }]);
}

#[given(expr = "a server offering {string} and {string}")]
async fn server_offering_two(w: &mut AlooWorld, first: String, second: String) {
    let mut state = aloo::client::tui::ui::UiState::new("me".into());
    state.set_own_id(UserId(1));
    state.on_channel_list(vec![
        aloo::proto::ChannelInfo {
            name: first,
            kind: ChannelKind::Public,
        },
        aloo::proto::ChannelInfo {
            name: second,
            kind: ChannelKind::Public,
        },
    ]);
    w.ui = Some(state);
}

#[then("the channels modal is open")]
async fn channels_modal_open(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().mode, Mode::ChannelsPopup);
}

#[then("the channels modal is closed")]
async fn channels_modal_closed(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().mode, Mode::Normal);
}

#[then(expr = "the channels modal lists {string}")]
async fn channels_modal_lists(w: &mut AlooWorld, name: String) {
    assert!(
        w.ui_ref()
            .known_public_channels()
            .iter()
            .any(|c| c.name == name),
        "expected {name:?} in the public channel directory"
    );
}

#[then(expr = "the channels modal shows {string} as one of mine")]
async fn channels_modal_shows_mine(w: &mut AlooWorld, name: String) {
    assert!(
        w.ui_ref().is_joined(&name),
        "expected {name:?} to render as joined (yellow)"
    );
}

#[then(expr = "the channels modal shows {string} as one I have not joined")]
async fn channels_modal_shows_not_mine(w: &mut AlooWorld, name: String) {
    assert!(
        !w.ui_ref().is_joined(&name),
        "expected {name:?} to render as not joined"
    );
}

#[then(expr = "the channel {string} is not on the channel selector")]
async fn channel_not_on_selector(w: &mut AlooWorld, name: String) {
    assert!(
        !w.ui_ref().channels.iter().any(|c| c.name == name),
        "the channel selector holds exactly the channels you have joined - {name:?} is not one"
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
        "focusing the channel selector should close any private room"
    );
}

#[when(expr = "the server confirms I joined {string}")]
async fn server_confirms_join(w: &mut AlooWorld, channel: String) {
    w.ui_mut().on_joined(ChannelInfo {
        name: channel,
        kind: ChannelKind::Public,
    });
}

#[then(expr = "the private room with {word} is open")]
async fn private_room_is_open(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.ui_ref().active_private_room,
        Some(UserId(id_for(&name))),
        "expected {name}'s room to be the view"
    );
}

// ---------------------------------------------------------------------
// The top row's two selectors (US-004)
// ---------------------------------------------------------------------

#[then("the channel dropdown is open")]
async fn channel_dropdown_open(w: &mut AlooWorld) {
    let state = w.ui_ref();
    assert!(state.selector_dropdown_open, "no dropdown is open");
    assert_eq!(
        state.selector_focus,
        SelectorFocus::Channels,
        "the open dropdown should be the channel selector's"
    );
}

#[then("the DM dropdown is open")]
async fn dm_dropdown_open(w: &mut AlooWorld) {
    let state = w.ui_ref();
    assert!(state.selector_dropdown_open, "no dropdown is open");
    assert_eq!(
        state.selector_focus,
        SelectorFocus::Dms,
        "the open dropdown should be the DM selector's"
    );
}

#[then("no dropdown is open")]
async fn no_dropdown_open(w: &mut AlooWorld) {
    assert!(
        !w.ui_ref().selector_dropdown_open,
        "a selector dropdown is still open over the view"
    );
}

#[then(expr = "the top row shows {string}")]
async fn top_row_shows(w: &mut AlooWorld, text: String) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        header_row(&rows).contains(&text),
        "expected {text:?} in the top row: {:?}",
        header_row(&rows)
    );
}

#[then(expr = "the top row does not show {string}")]
async fn top_row_does_not_show(w: &mut AlooWorld, text: String) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        !header_row(&rows).contains(&text),
        "did not expect {text:?} in the top row: {:?}",
        header_row(&rows)
    );
}

/// Blinking is one frame on, one frame off - what makes it a blink rather
/// than a steady marker (`docs/SPEC.md` "Connected UI").
#[then("the top row's envelope blinks")]
async fn top_row_envelope_blinks(w: &mut AlooWorld) {
    w.ui_mut().blink_on = true;
    assert!(
        header_row(&ui_rows_wide(w.ui_ref())).contains('\u{2709}'),
        "expected the envelope on the blink-on frame"
    );
    w.ui_mut().blink_on = false;
    assert!(
        !header_row(&ui_rows_wide(w.ui_ref())).contains('\u{2709}'),
        "and gone again on the blink-off frame"
    );
}

#[then("the top row shows no envelope")]
async fn top_row_no_envelope(w: &mut AlooWorld) {
    for blink in [true, false] {
        w.ui_mut().blink_on = blink;
        assert!(
            !header_row(&ui_rows_wide(w.ui_ref())).contains('\u{2709}'),
            "expected no envelope at all (blink_on={blink})"
        );
    }
}

#[when(expr = "a message arrives in the channel {string}")]
async fn message_arrives_in(w: &mut AlooWorld, channel: String) {
    w.ui_mut().on_channel_message(
        &channel,
        UserId(id_for("bob")),
        "bob".into(),
        MessageBody::Text("over here".into()),
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

#[then(expr = "the channel {string} is still listed in the directory")]
async fn channel_still_in_directory(w: &mut AlooWorld, channel: String) {
    assert!(
        w.ui_ref()
            .known_public_channels()
            .iter()
            .any(|c| c.name == channel),
        "a left public channel stays in the /channels directory to rejoin from"
    );
}

#[then(expr = "there is no reason to keep the link to {word}")]
async fn no_reason_to_keep_link(w: &mut AlooWorld, who: String) {
    assert!(
        !w.ui_ref().has_reason_to_keep_link(UserId(id_for(&who))),
        "the P2P link to {who} should be dropped once nothing justifies it"
    );
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
