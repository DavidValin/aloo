//! Composing and reading messages (US-005, US-006, US-015).

use cucumber::then;

use aloo::proto::UserId;
use aloo::client::tui::ui::{Focus, UiAction};

use crate::steps::ui_common::id_for;
use crate::support::{sidebar_row_containing, ui_rows_wide};
use crate::world::AlooWorld;

// ---------------------------------------------------------------------
// Channel messages
// ---------------------------------------------------------------------

#[then(expr = "sending {string} to the channel is requested, addressed to {word} and {word}")]
async fn send_requested(w: &mut AlooWorld, body: String, a: String, b: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendChannelText {
            channel,
            plaintext,
            recipients,
        } => {
            assert_eq!(channel, "general");
            assert_eq!(plaintext, &body);
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert_eq!(
                ids,
                vec![UserId(id_for(&a)), UserId(id_for(&b))],
                "every other member is addressed individually, and I am not among them"
            );
            assert!(
                recipients.iter().all(|(_, _, key)| !key.is_empty()),
                "each recipient must come with the key needed to encrypt to them"
            );
        }
        other => panic!("expected SendChannelText, got {other:?}"),
    }
}

#[then("my message is shown in the channel log as mine")]
async fn own_message_logged(w: &mut AlooWorld) {
    let state = w.ui_ref();
    let log = &state.channels[0].log;
    assert_eq!(
        log.len(),
        1,
        "my own message should be logged locally straight away"
    );
    assert!(
        log[0].outgoing,
        "and marked as outgoing rather than received"
    );
}

#[then("nothing is sent")]
async fn nothing_sent(w: &mut AlooWorld) {
    assert!(w.action_was_none, "no send should have been requested");
}

// ---------------------------------------------------------------------
// Private rooms
// ---------------------------------------------------------------------

#[then(expr = "a private room with {word} is open")]
async fn room_open(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.ui_ref().active_private_room,
        Some(UserId(id_for(&name))),
        "the private room for that user should be the active view"
    );
}

#[then("no private room opens")]
async fn room_not_open(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().active_private_room, None);
}

#[then("focus moves to the compose bar")]
async fn focus_on_compose(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().focus,
        Focus::Input,
        "opening a room should leave me ready to type"
    );
}

#[then("I am back in the channel view")]
async fn back_in_channel(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().active_private_room,
        None,
        "Esc should close the private room"
    );
}

#[then(expr = "sending the private message {string} to {word} is requested")]
async fn dm_send_requested(w: &mut AlooWorld, body: String, name: String) {
    let want = UserId(id_for(&name));
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendDirectText {
            to,
            plaintext,
            recipient_key_mode: _,
            recipient_pubkey_der,
            log_index: _,
        } => {
            assert_eq!(*to, want);
            assert_eq!(plaintext, &body);
            assert_eq!(
                recipient_pubkey_der,
                &vec![id_for(&name) as u8; 4],
                "an outgoing DM must carry the receiver's own public key to encrypt with"
            );
        }
        other => panic!("expected SendDirectText, got {other:?}"),
    }
    let state = w.ui_ref();
    assert!(
        state.private_rooms[&want]
            .log
            .last()
            .expect("nothing logged")
            .outgoing,
        "my own DM should be logged in that room as outgoing"
    );
}

#[then(expr = "{word}'s room is marked unread")]
async fn room_unread(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let room = w
        .ui_ref()
        .private_rooms
        .get(&id)
        .expect("no room for that user");
    assert!(
        room.unread,
        "a message arriving while I am elsewhere should be flagged unread"
    );
    assert!(
        !room.log.is_empty(),
        "and the message itself should be in the room's history"
    );
}

#[then(expr = "{word}'s room is not marked unread")]
async fn room_read(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let room = w
        .ui_ref()
        .private_rooms
        .get(&id)
        .expect("no room for that user");
    assert!(!room.unread, "the room should not be flagged unread");
}

#[then(expr = "{word}'s earlier messages are still in the room")]
async fn history_kept(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let room = w
        .ui_ref()
        .private_rooms
        .get(&id)
        .expect("no room for that user");
    assert!(
        !room.log.is_empty(),
        "marking a room read must not discard its history"
    );
}

// ---------------------------------------------------------------------
// Sidebar envelope
// ---------------------------------------------------------------------

fn envelope_shown(w: &mut AlooWorld, blink_on: bool, name: &str) -> bool {
    w.ui_mut().blink_on = blink_on;
    let rows = ui_rows_wide(w.ui_ref());
    sidebar_row_containing(&rows, name).contains('\u{2709}')
}

#[then(expr = "{word} shows no envelope in the sidebar")]
async fn no_envelope(w: &mut AlooWorld, name: String) {
    for blink in [false, true] {
        assert!(
            !envelope_shown(w, blink, &name),
            "an envelope must be earned by an actual message, not by opening an empty room"
        );
    }
}

#[then(expr = "{word} shows a steady envelope in the sidebar")]
async fn steady_envelope(w: &mut AlooWorld, name: String) {
    for blink in [false, true] {
        assert!(
            envelope_shown(w, blink, &name),
            "a read conversation keeps a solid envelope on every blink phase (blink_on={blink})"
        );
    }
}

#[then(expr = "{word}'s envelope blinks")]
async fn blinking_envelope(w: &mut AlooWorld, name: String) {
    assert!(
        envelope_shown(w, true, &name),
        "the envelope should be visible on the blink-on frame"
    );
    assert!(
        !envelope_shown(w, false, &name),
        "and hidden on the blink-off frame while there is something unread"
    );
}

// ---------------------------------------------------------------------
// History and scrolling
// ---------------------------------------------------------------------

#[then(expr = "message {int} is selected")]
async fn message_selected(w: &mut AlooWorld, index: usize) {
    assert_eq!(w.ui_ref().message_selected, index, "selected message index");
}

#[then("the newest message is selected")]
async fn newest_selected(w: &mut AlooWorld) {
    let state = w.ui_ref();
    let len = match state.active_private_room {
        Some(id) => state.private_rooms[&id].log.len(),
        None => state.channels[state.selected_channel].log.len(),
    };
    assert!(len > 0, "there should be something in the log to select");
    assert_eq!(
        state.message_selected,
        len - 1,
        "the view should open on the newest message"
    );
}

#[then(expr = "the selection is {int} entries below the newest")]
async fn selection_below_newest(w: &mut AlooWorld, offset: usize) {
    let state = w.ui_ref();
    let len = state.channels[state.selected_channel].log.len();
    assert_eq!(state.message_selected, len - 1 - offset);
}

#[then("the selection sits one page from the oldest")]
async fn one_page_from_oldest(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().message_selected,
        aloo::client::tui::ui::MESSAGE_PAGE_JUMP,
        "PageDown from the oldest should move exactly one page"
    );
}

#[then("the selection sits one page from the newest")]
async fn one_page_from_newest(w: &mut AlooWorld) {
    let state = w.ui_ref();
    let len = state.channels[state.selected_channel].log.len();
    assert_eq!(
        state.message_selected,
        len - 1 - aloo::client::tui::ui::MESSAGE_PAGE_JUMP,
        "PageUp from the newest should move exactly one page"
    );
}

#[then("the oldest message is selected")]
async fn oldest_selected(w: &mut AlooWorld) {
    assert_eq!(
        w.ui_ref().message_selected,
        0,
        "Home should jump to the oldest message"
    );
}

#[then("the oldest message is visible and the newest has scrolled away")]
async fn viewport_follows(w: &mut AlooWorld) {
    let state = w.ui_ref();
    let rows = crate::support::rows_of(&crate::support::ui_buffer(state, 100, 15));
    assert!(
        rows.iter().any(|r| r.contains("msg0")),
        "scrolling home should bring the oldest into view: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("msg39")),
        "and push the newest out of the viewport: {rows:?}"
    );
}

#[then("the newest message is visible and the oldest has scrolled away")]
async fn viewport_at_bottom(w: &mut AlooWorld) {
    let state = w.ui_ref();
    let rows = crate::support::rows_of(&crate::support::ui_buffer(state, 100, 15));
    assert!(
        rows.iter().any(|r| r.contains("msg39")),
        "the newest message should be on screen: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("msg0")),
        "the oldest should have scrolled out of view: {rows:?}"
    );
}
