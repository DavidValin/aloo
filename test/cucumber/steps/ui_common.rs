//! Setup and input steps shared by every connected-UI feature.
//!
//! cucumber registers steps globally, so these phrasings are available to all
//! the feature files regardless of which module a scenario "belongs" to.

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use cucumber::{given, then, when};

use aloo::client::tui::ui::{Focus, MessageBody, UiState};
use aloo::proto::{ChannelInfo, ChannelKind, KeyMode, UserId, UserInfo};

use crate::support::{popup_body, ui_buffer};
use crate::world::AlooWorld;

pub fn user_with_mode(id: u64, name: &str, key_mode: KeyMode) -> UserInfo {
    UserInfo {
        id: UserId(id),
        name: name.to_string(),
        public_key_der: vec![id as u8; 4],
        key_mode,
    }
}

/// Stable ids so scenarios can name people rather than numbers. `me` is 1,
/// matching `set_own_id` below.
pub fn id_for(name: &str) -> u64 {
    match name {
        "me" => 1,
        "bob" => 2,
        "carol" => 3,
        "dan" => 4,
        "eve" => 5,
        "frank" => 6,
        other => panic!("no id assigned to {other:?}"),
    }
}

fn key_mode_named(mode: &str) -> KeyMode {
    match mode {
        "pq_hybrid" => KeyMode::PqHybrid,
        other => panic!("unknown key mode {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given("I am connected and viewing a channel")]
async fn connected_viewing(w: &mut AlooWorld) {
    let mut state = UiState::new("me".into());
    state.set_own_id(UserId(1));
    state.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    state.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });
    w.ui = Some(state);
}

#[given("I am connected but have not joined any channel")]
async fn connected_no_channel(w: &mut AlooWorld) {
    let mut state = UiState::new("me".into());
    state.set_own_id(UserId(1));
    w.ui = Some(state);
}

#[given("I am connected and the server has offered a second channel")]
async fn connected_two_channels(w: &mut AlooWorld) {
    let mut state = UiState::new("me".into());
    state.set_own_id(UserId(1));
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
    w.ui = Some(state);
}

// `seed_member`, not `on_user_joined`: these describe the channel's
// starting roster (world-building for the scenario), not a live join
// happening during it - see `seed_member`'s doc. Using `on_user_joined`
// here would spuriously log a yellow "joined" notice into every scenario
// using this near-universal step, since by the time it runs the channel
// is normally already marked joined via "I am connected and viewing a
// channel".

#[given(expr = "{word} is in the channel with me")]
async fn member_present(w: &mut AlooWorld, name: String) {
    let info = user_with_mode(id_for(&name), &name, KeyMode::PqHybrid);
    w.ui_mut().seed_member("general", info);
}

#[given(expr = "{word} is in the channel with me using {word}")]
async fn member_present_mode(w: &mut AlooWorld, name: String, mode: String) {
    let info = user_with_mode(id_for(&name), &name, key_mode_named(&mode));
    w.ui_mut().seed_member("general", info);
}

/// A membership arrived at earlier, not a join happening now: joining
/// lands the user in the channel joined (`UiState::on_joined`), so the
/// selector is put back on whatever it was naming before.
#[given(expr = "the channel already has joined {string}")]
async fn already_joined(w: &mut AlooWorld, channel: String) {
    let state = w.ui_mut();
    let was = state.selected_channel;
    state.on_joined(ChannelInfo {
        name: channel,
        kind: ChannelKind::Public,
    });
    state.select_channel_at(was);
}

#[given(expr = "I have joined the private channel {string}")]
async fn already_joined_private(w: &mut AlooWorld, channel: String) {
    w.ui_mut().on_joined(ChannelInfo {
        name: channel,
        kind: ChannelKind::Private,
    });
}

#[when(expr = "I select the channel {string}")]
async fn select_channel(w: &mut AlooWorld, channel: String) {
    let state = w.ui_mut();
    state.selected_channel = state
        .channels
        .iter()
        .position(|c| c.name == channel)
        .unwrap_or_else(|| panic!("no such channel {channel:?}"));
}

#[given(expr = "I have left the channel {string}")]
async fn already_left(w: &mut AlooWorld, channel: String) {
    w.ui_mut().leave_channel_locally(&channel);
}

#[given(expr = "the message log holds {int} messages")]
#[when(expr = "{int} more messages arrive")]
async fn log_holds(w: &mut AlooWorld, n: usize) {
    let state = w.ui_mut();
    let existing = state.channels[0].log.len();
    for i in existing..existing + n {
        state.on_channel_message(
            "general",
            UserId(2),
            "bob".into(),
            MessageBody::Text(format!("msg{i}")),
        );
    }
}

#[given(expr = "the message log holds more than a page of messages")]
async fn log_holds_a_page_and_a_half(w: &mut AlooWorld) {
    let total = aloo::client::tui::ui::MESSAGE_PAGE_JUMP + 5;
    let state = w.ui_mut();
    for i in 0..total {
        state.on_channel_message(
            "general",
            UserId(2),
            "bob".into(),
            MessageBody::Text(format!("msg{i}")),
        );
    }
}

#[given(expr = "{word} sends the channel message {string}")]
#[when(expr = "{word} sends the channel message {string}")]
async fn peer_sends_channel_message(w: &mut AlooWorld, name: String, body: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_channel_message("general", id, name, MessageBody::Text(body));
}

#[given(expr = "{word} has sent me the private message {string}")]
#[when(expr = "{word} has sent me the private message {string}")]
async fn peer_sent_dm(w: &mut AlooWorld, name: String, body: String) {
    let id = UserId(id_for(&name));
    w.ui_mut()
        .on_direct_message(id, name, MessageBody::Text(body));
}

#[given(expr = "{word} has sent me {int} private messages")]
async fn peer_sent_several_dms(w: &mut AlooWorld, name: String, n: usize) {
    let id = UserId(id_for(&name));
    let state = w.ui_mut();
    for i in 0..n {
        state.on_direct_message(id, name.clone(), MessageBody::Text(format!("dm{i}")));
    }
}

// ---------------------------------------------------------------------
// When - focus and input
// ---------------------------------------------------------------------

#[given(expr = "focus is on the {word}")]
#[when(expr = "I move focus to the {word}")]
async fn set_focus(w: &mut AlooWorld, area: String) {
    let focus = match area.as_str() {
        "sidebar" => Focus::Sidebar,
        "log" | "messages" => Focus::Messages,
        "compose" | "input" => Focus::Input,
        other => panic!("unknown focus target {other:?}"),
    };
    w.ui_mut().focus = focus;
}

/// Routes a key to whichever screen the scenario is on. A scenario is either
/// still at the connect form or already connected, never both, so one set of
/// "I press X" phrasings can serve every feature without each screen needing
/// its own near-identical wording.
pub fn press_key(w: &mut AlooWorld, code: KeyCode, mods: KeyModifiers) {
    if w.popup.is_some() {
        let action = w
            .popup_mut()
            .handle_key(code)
            .expect("popup key handling should not fail");
        w.popup_error = w.popup_mut().error.clone();
        w.action_was_none = matches!(action, aloo::client::tui::ui_connect_popup::Action::None);
        w.popup_action = Some(action);
        return;
    }
    let action = w.ui_mut().handle_key(code, mods, KeyEventKind::Press);
    w.action_was_none = action.is_none();
    if action.is_some() {
        w.last_action = action;
    }
}

/// One step for every named key, including the modified ones: cucumber
/// expressions treat `Ctrl+H` as a single `{word}`, so a separate literal step
/// for it would be an ambiguous match against this one rather than a
/// refinement of it.
#[given(expr = "I press {word}")]
#[when(expr = "I press {word}")]
async fn press_named(w: &mut AlooWorld, key: String) {
    let (code, mods) = match key.as_str() {
        "Enter" => (KeyCode::Enter, KeyModifiers::NONE),
        "Escape" | "Esc" => (KeyCode::Esc, KeyModifiers::NONE),
        "Tab" => (KeyCode::Tab, KeyModifiers::NONE),
        "Backspace" => (KeyCode::Backspace, KeyModifiers::NONE),
        "Up" => (KeyCode::Up, KeyModifiers::NONE),
        "Down" => (KeyCode::Down, KeyModifiers::NONE),
        "Left" => (KeyCode::Left, KeyModifiers::NONE),
        "Right" => (KeyCode::Right, KeyModifiers::NONE),
        "Home" => (KeyCode::Home, KeyModifiers::NONE),
        "End" => (KeyCode::End, KeyModifiers::NONE),
        "PageUp" => (KeyCode::PageUp, KeyModifiers::NONE),
        "PageDown" => (KeyCode::PageDown, KeyModifiers::NONE),
        "Ctrl+H" => (KeyCode::Char('h'), KeyModifiers::CONTROL),
        "Ctrl+Shift+H" => (KeyCode::Char('H'), KeyModifiers::CONTROL),
        "Ctrl+J" => (KeyCode::Char('j'), KeyModifiers::CONTROL),
        "Ctrl+O" => (KeyCode::Char('o'), KeyModifiers::CONTROL),
        "Ctrl+R" => (KeyCode::Char('r'), KeyModifiers::CONTROL),
        "Ctrl+S" => (KeyCode::Char('s'), KeyModifiers::CONTROL),
        "Ctrl+E" => (KeyCode::Char('e'), KeyModifiers::CONTROL),
        other => panic!("unknown key {other:?}"),
    };
    press_key(w, code, mods);
}

#[when(expr = "I press the {word} key")]
async fn press_char(w: &mut AlooWorld, ch: String) {
    let c = ch.chars().next().expect("empty key");
    press_key(w, KeyCode::Char(c), KeyModifiers::NONE);
}

#[when(expr = "I type {string} into the compose bar")]
#[when(expr = "I type {string}")]
async fn type_text(w: &mut AlooWorld, text: String) {
    for c in text.chars() {
        press_key(w, KeyCode::Char(c), KeyModifiers::NONE);
    }
}

/// A whole paste (`UiState::handle_paste`), delivered atomically the way a
/// bracketed-paste-enabled terminal's `Event::Paste` would - contrast
/// `type_text` above, which presses one `KeyCode::Char` per character and
/// so would fragment on any embedded newline the way plain typing does.
#[when(expr = "I paste {string}")]
async fn paste_text(w: &mut AlooWorld, text: String) {
    let action = w.ui_mut().handle_paste(text);
    w.action_was_none = action.is_none();
    if action.is_some() {
        w.last_action = action;
    }
}

/// A Gherkin quoted string can't itself carry a literal newline on one
/// line, so a multi-line paste is spelled as two lines joined here - still
/// exercises the exact same `handle_paste` call, with the embedded `\n`
/// intact in the text it receives.
#[when(expr = "I paste {string} and {string} as one block")]
async fn paste_two_lines(w: &mut AlooWorld, first: String, second: String) {
    paste_text(w, format!("{first}\n{second}")).await;
}

#[when(expr = "I open a private room with {word}")]
#[given(expr = "I have opened a private room with {word}")]
async fn open_private_room(w: &mut AlooWorld, name: String) {
    let want = UserId(id_for(&name));
    let state = w.ui_mut();
    state.focus = Focus::Sidebar;
    // Select that member rather than assuming index 0.
    let index = state.channels[state.selected_channel]
        .members
        .iter()
        .position(|m| m.id == want)
        .unwrap_or_else(|| panic!("{name} is not in the member list"));
    state.sidebar_selected = index;
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
}

// ---------------------------------------------------------------------
// Then - generic
// ---------------------------------------------------------------------

#[then("nothing happens")]
async fn nothing_happens(w: &mut AlooWorld) {
    assert!(
        w.action_was_none,
        "the key press should not have produced any action"
    );
}

#[then(expr = "the compose bar holds {string}")]
async fn compose_holds(w: &mut AlooWorld, expected: String) {
    assert_eq!(w.ui_ref().input, expected, "compose bar contents");
}

#[then("the compose bar is empty")]
async fn compose_empty(w: &mut AlooWorld) {
    assert_eq!(w.ui_ref().input, "", "compose bar should be empty");
}

/// Typed one keystroke at a time, same as `type_text` - a block this long
/// spelled out literally in a `.feature` file would be unreadable, so it's
/// generated here instead. Exercises the exact per-keystroke cap
/// (`UiState::handle_input_key`), not a shortcut around it.
#[when(expr = "I type a block of {int} characters")]
async fn type_a_block(w: &mut AlooWorld, count: usize) {
    for _ in 0..count {
        press_key(w, KeyCode::Char('a'), KeyModifiers::NONE);
    }
}

#[then(expr = "the compose bar holds exactly {int} characters")]
async fn compose_holds_exactly(w: &mut AlooWorld, count: usize) {
    assert_eq!(
        w.ui_ref().input.chars().count(),
        count,
        "compose bar character count"
    );
}

// ---------------------------------------------------------------------
// A popup owns the cells it covers (AC-237)
// ---------------------------------------------------------------------

/// A marker nothing in the UI's own chrome contains, so any cell a popup
/// fails to clear shows it.
pub const BEHIND_MARKER: &str = "ZZQQ-behind-marker-ZZQQ";

#[given("the channel log is full of messages")]
async fn log_full_of_marker(w: &mut AlooWorld) {
    let id = UserId(id_for("bob"));
    let channel = w.ui_ref().channels[w.ui_ref().selected_channel]
        .name
        .clone();
    let state = w.ui_mut();
    for _ in 0..40 {
        state.on_channel_message(
            &channel,
            id,
            "bob".into(),
            MessageBody::Text(BEHIND_MARKER.repeat(6)),
        );
    }
}

#[then("nothing of the view behind the popup shows through it")]
async fn nothing_shows_through(w: &mut AlooWorld) {
    let buffer = ui_buffer(w.ui_ref(), 100, 30);
    let body = popup_body(&buffer, "Join or create a channel");
    assert!(!body.is_empty(), "the popup should have a body");
    assert!(
        !body.iter().any(|r| r.contains(BEHIND_MARKER)),
        "the view behind the popup showed through it: {body:?}"
    );
}
