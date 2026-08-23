//! Connect-popup steps (US-001).

use crossterm::event::KeyCode;
use cucumber::{given, then, when};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::Color;

use aloo::client::connect::{ConnectCache, MyKeySelection, prefill_connect_defaults};
use aloo::client::file_browser::FileBrowserState;
use aloo::client::tui::ui_connect_popup::{
    ALOO_HOME_LABEL, Action, ConnectPopupState, Field, FileBrowserTarget, NICKNAME_MAX_LEN, render,
};

use crate::support::popup_rows;
use crate::world::AlooWorld;

fn field_of(name: &str) -> Field {
    match name {
        "host" => Field::Host,
        "port" => Field::Port,
        "nickname" => Field::Nickname,
        "password" => Field::Password,
        "email" => Field::Email,
        "Connect" => Field::Connect,
        "Register" => Field::Register,
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
    p.password = "hunter2".into();
}

#[given("my_key points at a keybundle pair")]
#[when("my_key points at a keybundle pair")]
async fn my_key_points_at_files(w: &mut AlooWorld) {
    let p = w.popup_mut();
    p.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    p.my_key.file_priv = "/keys/pq_hybrid".into();
}

/// `my_key` has no type selector at all any more: `pq_hybrid` is the only
/// peer-to-peer scheme, so the group is just its two keybundle paths and
/// the focus order always offers both.
#[then("my_key is pq_hybrid with no type to choose")]
async fn my_key_is_pq_hybrid(w: &mut AlooWorld) {
    let order = w.popup_mut().focus_order();
    assert!(order.contains(&Field::MyKeyValuePub));
    assert!(order.contains(&Field::MyKeyValuePriv));
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
        Field::Password => p.password.clear(),
        Field::Email => p.email.clear(),
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
    p.focus = Field::MyKeyValuePub;
    p.handle_key(KeyCode::Enter).unwrap();
    assert!(
        p.browser.is_some(),
        "Enter on a my_key file field must open the in-app browser"
    );

    // Point it at the known tree so the scenario does not depend on the cwd.
    p.browser = Some((
        FileBrowserTarget::MyKeyFilePub,
        FileBrowserState::open(root).unwrap(),
    ));
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
    w.popup_mut().browser = Some((FileBrowserTarget::MyKeyFilePub, browser));
}

#[when("I walk into the sub-directory and back out again")]
async fn walk_in_and_out(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let mut browser = FileBrowserState::open(root).unwrap();
    browser.selected = 1;
    assert_eq!(
        browser.selected_entry().unwrap().name,
        "subdir",
        "index 1 should be the sub-directory"
    );
    browser.navigate_into_selected().unwrap();
    assert!(
        browser.entries.iter().any(|e| e.name == "nested.txt"),
        "walking in should list the sub-directory's contents"
    );
    w.popup_mut().browser = Some((FileBrowserTarget::MyKeyFilePub, browser));
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then("the host field has the cursor in it")]
async fn host_has_cursor(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    assert_eq!(
        state.focus,
        Field::Host,
        "host must be the default focus when the form opens"
    );

    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let host_title_row = (0..buffer.area.height)
        .find(|&y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                .contains("host")
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
        Field::Password => &p.password,
        Field::Email => &p.email,
        other => panic!("cannot read {other:?}"),
    };
    assert_eq!(actual, &expected, "{name} field");
}

#[then("the form has no id_store field")]
async fn no_id_store_field(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(
        !rows.iter().any(|r| r.contains("id_store")),
        "no id_store box on the form: {rows:?}"
    );
}

/// `ssl` is not a popup field at all - like `server_ssl` on the server
/// side, it is settings-only (`connect_ssl`).
#[then("the form has no ssl field")]
async fn no_ssl_field(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(
        !rows.iter().any(|r| r.contains("ssl")),
        "no ssl box or switch on the form: {rows:?}"
    );
}

#[then("the form has no email field")]
async fn no_email_field(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(
        !rows.iter().any(|r| r.contains("email")),
        "no email box while registration is unavailable: {rows:?}"
    );
}

#[then("no Register button is offered")]
async fn no_register_button(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(
        !rows.iter().any(|r| r.contains("Register")),
        "no Register button while registration is unavailable: {rows:?}"
    );
}

#[then("an email field and a Register button are offered")]
async fn email_field_and_register_button(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(rows.iter().any(|r| r.contains("email")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("Register")), "{rows:?}");
}

/// Simulates what `prefill_connect_defaults` does when
/// `settings.server_allow_registration` is on - set directly on the
/// popup rather than through a real settings file, the same way
/// `my_key_points_at_files` sets fields directly.
#[given("the server allows registration")]
#[when("the server allows registration")]
async fn server_allows_registration(w: &mut AlooWorld) {
    w.popup_mut().registration_available = true;
}

#[then("the password field is shown masked")]
async fn password_shown_masked(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    let rows = popup_rows(state, 80, 30);
    assert!(
        !rows.iter().any(|r| r.contains(&state.password) && !state.password.is_empty()),
        "the raw password must never appear on screen: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains(&"*".repeat(state.password.chars().count()))),
        "expected asterisks in place of the password: {rows:?}"
    );
}

#[then("ssl is off")]
async fn ssl_is_off(w: &mut AlooWorld) {
    assert!(!w.popup.as_ref().expect("no form").ssl);
}

#[then(expr = "the nickname is capped at {int} characters")]
async fn nickname_capped(w: &mut AlooWorld, cap: usize) {
    let p = w.popup.as_ref().expect("no form");
    assert_eq!(
        cap, NICKNAME_MAX_LEN,
        "the scenario and the constant must agree"
    );
    assert_eq!(
        p.nickname.chars().count(),
        NICKNAME_MAX_LEN,
        "nickname should be exactly at the cap"
    );
}

#[then("host, port and nickname are each in their own titled box")]
async fn each_boxed(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    for title in ["host", "port", "nickname"] {
        assert!(
            rows.iter().any(|r| r.contains(title)),
            "expected a {title:?} box title: {rows:?}"
        );
    }
    // Each titled box is bordered in its own right rather than sharing the
    // outer popup border, so there is more than one top-left corner.
    let corner_rows = rows.iter().filter(|r| r.contains('┌')).count();
    assert!(
        corner_rows >= 4,
        "expected the outer popup plus host/port/nickname to each own a top border: {rows:?}"
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

#[then("registering begins with the email I entered")]
async fn registering_begins(w: &mut AlooWorld) {
    w.popup_mut().focus = Field::Register;
    let action = w.popup_mut().handle_key(KeyCode::Enter).unwrap();
    match action {
        Action::Register(req) => assert_eq!(req.email, "dave@example.com"),
        other => panic!("expected Register, got {other:?}"),
    }
}

#[then(expr = "registering is refused with an error mentioning {string}")]
async fn registering_refused_with(w: &mut AlooWorld, needle: String) {
    w.popup_mut().focus = Field::Register;
    let action = w.popup_mut().handle_key(KeyCode::Enter).unwrap();
    assert_eq!(action, Action::None, "an invalid registration must not submit");
    let err = w
        .popup
        .as_ref()
        .and_then(|p| p.error.clone())
        .expect("an invalid registration must show a validation error");
    assert!(
        err.contains(&needle),
        "error {err:?} should mention {needle:?}"
    );
}

#[then("a visible Connect button is offered")]
async fn connect_button_visible(w: &mut AlooWorld) {
    let rows = popup_rows(w.popup.as_ref().expect("no form"), 80, 30);
    assert!(
        rows.iter().any(|r| r.contains("Connect")),
        "expected a visible Connect button: {rows:?}"
    );
}

#[then(expr = "connecting is refused with an error mentioning {string}")]
async fn refused_with(w: &mut AlooWorld, needle: String) {
    assert_eq!(
        w.popup_action,
        Some(Action::None),
        "an invalid form must not connect"
    );
    let err = w
        .popup
        .as_ref()
        .and_then(|p| p.error.clone())
        .expect("an invalid form must show a validation error");
    assert!(
        err.contains(&needle),
        "error {err:?} should mention {needle:?}"
    );
}

#[then(expr = "building the request fails mentioning {string}")]
async fn build_fails(w: &mut AlooWorld, needle: String) {
    let err = w.popup.as_ref().unwrap().build_request().unwrap_err();
    assert!(
        err.contains(&needle),
        "error {err:?} should mention {needle:?}"
    );
}

#[then("the form is cancelled")]
async fn form_cancelled(w: &mut AlooWorld) {
    assert_eq!(
        w.popup_action,
        Some(Action::Cancel),
        "Esc must cancel the connect popup"
    );
}

#[then("the picked file fills the my_key field")]
async fn picked_file_fills(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let p = w.popup.as_ref().expect("no form");
    assert!(
        p.browser.is_none(),
        "picking a file should close the browser"
    );
    assert_eq!(
        p.my_key.file_pub,
        root.join("file.txt").display().to_string(),
        "the chosen path must land in the field that opened the browser"
    );
}

#[then("the browser can step back and then forward again")]
async fn browser_back_forward(w: &mut AlooWorld) {
    let root = w.browser_root.clone().expect("no directory tree");
    let p = w.popup_mut();
    let (_, browser) = p.browser.as_mut().expect("no open browser");
    assert_eq!(
        browser.current_dir,
        root.join("subdir"),
        "should be inside the sub-directory"
    );

    assert!(
        browser.go_back().unwrap(),
        "back should succeed when there is history"
    );
    assert_eq!(browser.current_dir, root, "back should land in the parent");

    assert!(
        browser.go_forward().unwrap(),
        "forward should return where we came from"
    );
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
    assert!(
        !browser.go_back().unwrap(),
        "no history means back does nothing, rather than erroring"
    );
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
            let word: String = (0..7)
                .map(|i| buffer[(x + i, y)].symbol().to_string())
                .collect();
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

#[then("the request carries the details as typed")]
async fn request_carries_details(w: &mut AlooWorld) {
    let req = w
        .popup
        .as_ref()
        .unwrap()
        .build_request()
        .expect("form should be valid");
    assert_eq!(
        req.my_key,
        MyKeySelection {
            file_pub: std::path::PathBuf::from("/keys/pq_hybrid.pub"),
            file_priv: std::path::PathBuf::from("/keys/pq_hybrid"),
        }
    );
    assert_eq!(req.host, "chat.example.com");
    assert_eq!(req.port, 6667);
    assert_eq!(req.nickname, "dave");
    assert_eq!(req.password, "hunter2");
    assert!(!req.ssl);
}

/// The read-only line above the Connect button (`docs/SPEC.md` "Not
/// connected UI") - gray, so it reads as a note about where this client's
/// local state lives rather than as another thing to fill in.
#[then("the form shows the ALOO_HOME it resolved, in gray")]
async fn form_shows_aloo_home(w: &mut AlooWorld) {
    let state = w.popup.as_ref().expect("no form");
    let expected = format!("{ALOO_HOME_LABEL}{}", state.aloo_home);
    let buffer = crate::support::buffer_of(80, 30, |f| render(f, state));
    let (x, y) = crate::support::find_text_start(&buffer, &expected);
    assert_eq!(
        buffer[(x, y)].fg,
        ratatui::style::Color::DarkGray,
        "the ALOO_HOME line is gray"
    );
}

// ---------------------------------------------------------------------
// The form comes back as whoever connected last (AC-240)
// ---------------------------------------------------------------------

/// The `connect_*` keys `Settings::remember_connection` wrote the last
/// time this machine connected. Held on the world rather than written to
/// a real file: `prefill_connect_defaults` takes the settings it prefills
/// from, so a scenario has no reason to involve the filesystem.
#[given(expr = "a settings file recording a connection as {string} to {string} port {int}")]
async fn settings_record_connection(w: &mut AlooWorld, nickname: String, host: String, port: u16) {
    w.direct_settings = Some(aloo::settings::Settings {
        connect_nickname: Some(nickname),
        connect_host: Some(host),
        connect_port: Some(port),
        ..aloo::settings::Settings::default()
    });
}

#[given("a settings file with no connection recorded")]
async fn settings_record_nothing(w: &mut AlooWorld) {
    w.direct_settings = Some(aloo::settings::Settings::default());
}

/// The client's own start (`connect::run_client_inner`): a fresh form
/// proposing the local user, then prefilled from what this machine
/// remembers.
#[when("the connect form opens on that machine")]
async fn form_opens_on_that_machine(w: &mut AlooWorld) {
    let settings = w.direct_settings.clone().unwrap_or_default();
    let mut popup = ConnectPopupState::new();
    popup.nickname = "whoami".to_string();
    let cache = ConnectCache::new_empty(w.temp_path("connect-prefill-cache"));
    let dir = w.temp_path("connect-prefill-dir");
    prefill_connect_defaults(&mut popup, &settings, &cache, &dir);
    w.popup = Some(popup);
}
