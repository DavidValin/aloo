//! Channel-switching steps (US-004, client side).

use std::time::{Duration, Instant};

use cucumber::{then, when};

use aloo::proto::ChannelKind;
use aloo::ui::channel::DWELL_DURATION;
use aloo::ui::ui::{Mode, UiAction};

use crate::world::AlooWorld;

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
    assert_eq!(selected.name, name, "the tab selection should have moved immediately");
}

#[then(expr = "{string} has not been joined yet")]
async fn not_joined_yet(w: &mut AlooWorld, name: String) {
    let state = w.ui_ref();
    let ch = state.channels.iter().find(|c| c.name == name).expect("no such channel");
    assert!(!ch.joined, "selecting a tab must not join it - the dwell delay has not elapsed");
}

#[then("no join is requested yet")]
async fn no_join_yet(w: &mut AlooWorld) {
    assert!(w.action_was_none, "the dwell timer should not fire before the delay has passed");
}

#[then(expr = "joining {string} is requested")]
async fn join_requested(w: &mut AlooWorld, name: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::JoinChannel { name: got, kind } => {
            assert_eq!(got, &name);
            assert_eq!(*kind, ChannelKind::Public, "a tab from the server's list is a public channel");
        }
        other => panic!("expected a JoinChannel request, got {other:?}"),
    }
}

#[then(expr = "joining the private channel {string} is requested")]
async fn private_join_requested(w: &mut AlooWorld, name: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::JoinChannel { name: got, kind } => {
            assert_eq!(got, &name);
            assert_eq!(*kind, ChannelKind::Private, "Ctrl+J creates private channels, not public ones");
        }
        other => panic!("expected a JoinChannel request, got {other:?}"),
    }
    assert_eq!(w.ui_ref().mode, Mode::Normal, "the popup should close once the name is submitted");
}

#[then("the join-channel popup is open")]
async fn popup_open(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().mode, Mode::JoinPrivatePopup, "Ctrl+J should open the join popup");
}

#[then("the join-channel popup is closed and forgotten")]
async fn popup_cancelled(w: &mut AlooWorld) {
    let state = w.ui_ref();
    assert_eq!(state.mode, Mode::Normal, "Esc should close the popup");
    assert_eq!(state.join_popup_input, "", "the abandoned name must not linger");
    assert!(w.action_was_none, "cancelling must not request a join");
}

#[then("no private room is open")]
async fn no_private_room(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().active_private_room, None, "switching tabs should close any private room");
}
