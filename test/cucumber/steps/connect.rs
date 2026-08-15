//! Connect-popup steps (US-001).

use std::path::PathBuf;

use cucumber::{given, then, when};
use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::Color;

use aloo::ui::ui_connect_popup::{
    Action, ConnectPopupState, Field, FileBrowserState, FileBrowserTarget, KeyType, MyKeySelection,
    MyKeyType, NICKNAME_MAX_LEN, ServerKeySelection, render,
};

use crate::support::popup_rows;
use crate::world::AlooWorld;

fn field_of(name: &str) -> Field {
    match name {
        "host" => Field::Host,
        "port" => Field::Port,
        "nickname" => Field::Nickname,
        "id_store" => Field::IdStorePath,
        "own_next_keys" => Field::OwnNextKeysPath,
        "server_key value" => Field::ServerKeyValue,
        "Connect" => Field::Connect,
        other => panic!("unknown field {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given("the connect form is open")]
async fn form_open(w: &mut AlooWorld) {
    w.popup = Some(ConnectPopupState::new());
}

#[given("the connect form is filled in with valid details")]
async fn form_valid(w: &mut AlooWorld) {
    let p = w.popup_mut();
    p.host = "chat.example.com".into();
    p.port = "6667".into();
    p.nickname = "dave".into();
}

fn my_key_type_named(kind: &str) -> MyKeyType {
    match kind {
        "rsa" => MyKeyType::Rsa,
        "password" => MyKeyType::Password,
        "none" => MyKeyType::None,
        "rsa_per_msg" => MyKeyType::RsaPerMessage,
        "pq_hybrid" => MyKeyType::PqHybrid,
        other => panic!("unknown my_key type {other:?}"),
    }
}

// Registered for both keywords: selecting a key type is sometimes the
// scenario's setup and sometimes the action it is exercising.
#[given(expr = "my_key is set to {word}")]
#[when(expr = "my_key is set to {word}")]
async fn my_key_is(w: &mut AlooWorld, kind: String) {
    w.popup_mut().my_key.key_type = my_key_type_named(&kind);
}

#[then(expr = "my_key defaults to {word}")]
async fn my_key_defaults_to(w: &mut AlooWorld, kind: String) {
    assert_eq!(w.popup_mut().my_key.key_type, my_key_type_named(&kind), "unexpected default my_key type");
}

#[given(expr = "server_key is set to {word}")]
#[when(expr = "server_key is set to {word}")]
async fn server_key_is(w: &mut AlooWorld, kind: String) {
    let p = w.popup_mut();
    p.server_key.key_type = match kind.as_str() {
        "rsa" => KeyType::Rsa,
        "password" => KeyType::Password,
        "none" => KeyType::None,
        other => panic!("unknown server_key type {other:?}"),
    };
}

#[given("a directory holding one sub-directory and one file")]
async fn a_directory_tree(w: &mut AlooWorld) {
    let root = w.temp_path("browser");
    let sub = root.join("subdir");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(root.join("file.txt"), b"hello").unwrap();
    std::fs::write(sub.join("nested.txt"), b"world").unwrap();
    w.browser_root = Some(root);
}

#[given("a directory holding more files than fit in the file browser popup")]
async fn a_directory_with_many_files(w: &mut AlooWorld) {
    let root = w.temp_path("browser-scroll");
    std::fs::create_dir_all(&root).unwrap();
    for i in 0..30 {
        std::fs::write(root.join(format!("file{i:02}.txt")), b"x").unwrap();
    }
    w.browser_root = Some(root);
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when(expr = "I focus the {string} field")]
async fn focus_field(w: &mut AlooWorld, name: String) {
    w.popup_mut().focus = field_of(&name);
}

#[when(expr = "I clear the {string} field")]
async fn clear_field(w: &mut AlooWorld, name: String) {
    let p = w.popup_mut();
    match field_of(&name) {
        Field::Host => p.host.clear(),
        Field::Port => p.port.clear(),
        Field::Nickname => p.nickname.clear(),
        Field::IdStorePath => p.id_store_path.clear(),
        Field::OwnNextKeysPath => p.my_key.own_next_keys_path.clear(),
        other => panic!("cannot clear {other:?}"),
    }
}

#[when(expr = "I type {string} into the form")]
async fn type_into_form(w: &mut AlooWorld, text: String) {
    let p = w.popup_mut();
    for c in text.chars() {
        p.handle_key(KeyCode::Char(c)).unwrap();
    }
}

// Named-key presses are handled once, for every screen, by
// `ui_common::press_named` - it routes to the connect form whenever a
// scenario has one open.

#[when("I submit the form")]
async fn submit_form(w: &mut AlooWorld) {
    w.popup_mut().focus = Field::Connect;
    let action = w.popup_mut().handle_key(KeyCode::Enter).unwrap();
    w.popup_error = w.popup_mut().error.clone();
    w.popup_action = Some(action);
}

#[when("I open the file browser on that directory and pick the file")]
async fn browse_and_pick(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let p = w.popup_mut();
    p.server_key.key_type = KeyType::Rsa;
    p.focus = Field::ServerKeyValue;
    p.handle_key(KeyCode::Enter).unwrap();
    assert!(p.browser.is_some(), "Enter on an rsa file field must open the in-app browser");

    // Point it at the known tree so the scenario does not depend on the cwd.
    p.browser = Some((FileBrowserTarget::ServerKeyFile, FileBrowserState::open(root).unwrap()));
    // entries are "..", "subdir", "file.txt"
    p.handle_key(KeyCode::Down).unwrap();
    p.handle_key(KeyCode::Down).unwrap();
    p.handle_key(KeyCode::Enter).unwrap();
}

#[when("I open the file browser on that directory and select the last entry")]
async fn browse_and_select_last(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let mut browser = FileBrowserState::open(root).unwrap();
    let last = browser.entries.len() - 1;
    browser.selected = last;
    w.popup_mut().server_key.key_type = KeyType::Rsa;
    w.popup_mut().browser = Some((FileBrowserTarget::ServerKeyFile, browser));
}

#[when("I walk into the sub-directory and back out again")]
async fn walk_in_and_out(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let mut browser = FileBrowserState::open(root).unwrap();
    browser.selected = 1;
    assert_eq!(browser.selected_entry().unwrap().name, "subdir", "index 1 should be the sub-directory");
    browser.navigate_into_selected().unwrap();
    assert!(
        browser.entries.iter().any(|e| e.name == "nested.txt"),
        "walking in should list the sub-directory's contents"
    );
    w.popup_mut().browser = Some((FileBrowserTarget::ServerKeyFile, browser));
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then("the host field has the cursor in it")]
async fn host_has_cursor(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    assert_eq!(state.focus, Field::Host, "host must be the default focus when the form opens");

    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let host_title_row = (0..buffer.area.height)
        .find(|&y| {
            (0..buffer.area.width).map(|x| buffer[(x, y)].symbol()).collect::<String>().contains("host")
        })
        .expect("expected a visible \"host\" box title");
    let cursor = terminal
        .get_cursor_position()
        .expect("a cursor should be set while a text field is focused");
    assert_eq!(
        cursor.y,
        host_title_row + 1,
        "the cursor should sit on the host field's own content row, not elsewhere"
    );
}

#[then(expr = "the {string} field contains {string}")]
async fn field_contains(w: &mut AlooWorld, name: String, expected: String) {
    let p = w.popup.as_ref().expect("no form");
    let actual = match field_of(&name) {
        Field::Host => &p.host,
        Field::Port => &p.port,
        Field::Nickname => &p.nickname,
        Field::IdStorePath => &p.id_store_path,
        Field::OwnNextKeysPath => &p.my_key.own_next_keys_path,
        Field::ServerKeyValue => &p.server_key.password,
        other => panic!("cannot read {other:?}"),
    };
    assert_eq!(actual, &expected, "{name} field");
}

#[then(expr = "the nickname is capped at {int} characters")]
async fn nickname_capped(w: &mut AlooWorld, cap: usize) {
    let p = w.popup.as_ref().expect("no form");
    assert_eq!(cap, NICKNAME_MAX_LEN, "the scenario and the constant must agree");
    assert_eq!(p.nickname.chars().count(), NICKNAME_MAX_LEN, "nickname should be exactly at the cap");
}

#[then("host, port and nickname are each in their own titled box")]
async fn each_boxed(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    for title in ["host", "port", "nickname"] {
        assert!(rows.iter().any(|r| r.contains(title)), "expected a {title:?} box title: {rows:?}");
    }
    // Each titled box is bordered in its own right rather than sharing the
    // outer popup border, so there is more than one top-left corner.
    let corner_rows = rows.iter().filter(|r| r.contains('┌')).count();
    assert!(
        corner_rows >= 4,
        "expected the outer popup plus host/port/nickname to each own a top border: {rows:?}"
    );
}

#[then(expr = "the id_store path is prefilled with the default {word} location")]
async fn id_store_prefilled(w: &mut AlooWorld, _which: String) {
    let p = w.popup.as_ref().expect("no form");
    assert!(!p.id_store_path.is_empty(), "id_store should be prefilled, not left blank");
    assert_eq!(p.id_store_path, aloo::idstore::default_path().display().to_string());
}

#[then("the own_next_keys path is prefilled with its default location")]
async fn own_next_prefilled(w: &mut AlooWorld) {
    let p = w.popup.as_ref().expect("no form");
    assert!(!p.my_key.own_next_keys_path.is_empty());
    assert_eq!(
        p.my_key.own_next_keys_path,
        aloo::own_next_keys::default_path().display().to_string()
    );
}

#[then("the own_next_keys field is offered")]
async fn own_next_offered(w: &mut AlooWorld) {
    assert!(
        w.popup.as_ref().unwrap().focus_order().contains(&Field::OwnNextKeysPath),
        "own_next_keys must be reachable for rsa_per_msg"
    );
    let rows = popup_rows(w.popup.as_ref().unwrap(), 80, 30);
    assert!(rows.iter().any(|r| r.contains("own_next_keys")), "expected the field on screen: {rows:?}");
}

#[then("the own_next_keys field is not offered")]
async fn own_next_not_offered(w: &mut AlooWorld) {
    assert!(
        !w.popup.as_ref().unwrap().focus_order().contains(&Field::OwnNextKeysPath),
        "own_next_keys is only meaningful for rsa_per_msg"
    );
}

#[then("connecting begins with the details I entered")]
async fn connecting_begins(w: &mut AlooWorld) {
    match w.popup_action.as_ref().expect("no action") {
        Action::Connect(req) => {
            assert_eq!(req.host, "chat.example.com");
            assert_eq!(req.port, 6667);
            assert_eq!(req.nickname, "dave");
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

#[then("a visible Connect button is offered")]
async fn connect_button_visible(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(rows.iter().any(|r| r.contains("Connect")), "expected a visible Connect button: {rows:?}");
}

#[then(expr = "connecting is refused with an error mentioning {string}")]
async fn refused_with(w: &mut AlooWorld, needle: String) {
    assert_eq!(w.popup_action, Some(Action::None), "an invalid form must not connect");
    let err = w
        .popup
        .as_ref()
        .and_then(|p| p.error.clone())
        .expect("an invalid form must show a validation error");
    assert!(err.contains(&needle), "error {err:?} should mention {needle:?}");
}

#[then(expr = "building the request fails mentioning {string}")]
async fn build_fails(w: &mut AlooWorld, needle: String) {
    let err = w.popup.as_ref().unwrap().build_request().unwrap_err();
    assert!(err.contains(&needle), "error {err:?} should mention {needle:?}");
}

#[then("the form is cancelled")]
async fn form_cancelled(w: &mut AlooWorld) {
    assert_eq!(w.popup_action, Some(Action::Cancel), "Esc must cancel the connect popup");
}

#[then("the picked file fills the server_key field")]
async fn picked_file_fills(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let p = w.popup.as_ref().expect("no form");
    assert!(p.browser.is_none(), "picking a file should close the browser");
    assert_eq!(
        p.server_key.file,
        root.join("file.txt").display().to_string(),
        "the chosen path must land in the field that opened the browser"
    );
}

#[then("the browser can step back and then forward again")]
async fn browser_back_forward(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let p = w.popup_mut();
    let (_, browser) = p.browser.as_mut().expect("no open browser");
    assert_eq!(browser.current_dir, root.join("subdir"), "should be inside the sub-directory");

    assert!(browser.go_back().unwrap(), "back should succeed when there is history");
    assert_eq!(browser.current_dir, root, "back should land in the parent");

    assert!(browser.go_forward().unwrap(), "forward should return where we came from");
    assert_eq!(browser.current_dir, root.join("subdir"));
}

#[then("the last entry is visible in the file browser")]
async fn last_entry_visible(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    let rows = popup_rows(state, 80, 24);
    assert!(
        rows.iter().any(|r| r.contains("file29.txt")),
        "the selected (last) entry must have scrolled into view: {rows:?}"
    );
}

#[then("the first entry has scrolled out of view")]
async fn first_entry_out_of_view(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    let rows = popup_rows(state, 80, 24);
    assert!(
        !rows.iter().any(|r| r.contains("file00.txt")),
        "an entry far from the current scroll position should not still be shown: {rows:?}"
    );
}

#[then("a fresh browser has nowhere to step back or forward to")]
async fn browser_no_history(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let mut browser = FileBrowserState::open(root).unwrap();
    assert!(!browser.go_back().unwrap(), "no history means back does nothing, rather than erroring");
    assert!(!browser.go_forward().unwrap(), "and neither does forward");
}

#[then("the focused Connect button is highlighted but its border is not")]
async fn highlight_not_bleeding(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    let buffer = crate::support::buffer_of(80, 30, |f| render(f, state));

    // The popup's own title also reads "Connect"; the button is the last
    // (bottommost) occurrence.
    let mut last_match: Option<(u16, u16)> = None;
    for y in 1..buffer.area.height {
        for x in 0..buffer.area.width.saturating_sub(6) {
            let word: String = (0..7).map(|i| buffer[(x + i, y)].symbol().to_string()).collect();
            if word == "Connect" {
                last_match = Some((x, y));
            }
        }
    }
    let (x, y) = last_match.expect("expected to find the rendered Connect button label");
    assert_eq!(
        buffer[(x, y)].style().bg,
        Some(Color::Green),
        "the focused button's text should be highlighted"
    );
    assert_ne!(
        buffer[(x, y - 1)].style().bg,
        Some(Color::Green),
        "the button's border must stay outside the highlight, not be filled by it"
    );
}

#[then(expr = "the request carries the own_next_keys path {string}")]
async fn request_carries_own_next(w: &mut AlooWorld, expected: String) {
    let req = w.popup.as_ref().unwrap().build_request().expect("form should be valid");
    match req.my_key {
        MyKeySelection::RsaPerMessage { own_next_keys_path } => {
            assert_eq!(own_next_keys_path, PathBuf::from(&expected));
        }
        other => panic!("expected RsaPerMessage, got {other:?}"),
    }
}

#[then("the request carries no key material for either key")]
async fn request_carries_none(w: &mut AlooWorld) {
    let req = w.popup.as_ref().unwrap().build_request().expect("form should be valid");
    assert_eq!(req.server_key, ServerKeySelection::None);
    assert_eq!(req.my_key, MyKeySelection::None);
    assert_eq!(req.host, "chat.example.com");
    assert_eq!(req.port, 6667);
    assert_eq!(req.nickname, "dave");
}
