use aloo::client::connect::{ConnectRequest, MyKeySelection, ServerKeySelection};
use aloo::client::file_browser::FileBrowserState;
use aloo::client::tui::ui_connect_popup::{
    ALOO_HOME_LABEL, Action, ConnectPopupState, Field, KeyType, NICKNAME_MAX_LEN, render,
};
use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use std::path::PathBuf;

fn type_str(state: &mut ConnectPopupState, s: &str) {
    for c in s.chars() {
        state.handle_key(KeyCode::Char(c)).unwrap();
    }
}

// ---------------------------------------------------------------------
// KeyType
// ---------------------------------------------------------------------

/// @requirement TB-001
#[test]
fn key_type_cycles_rsa_password_none_and_back() {
    assert_eq!(KeyType::Rsa.cycle_next(), KeyType::Password);
    assert_eq!(KeyType::Password.cycle_next(), KeyType::None);
    assert_eq!(KeyType::None.cycle_next(), KeyType::Rsa);
}

/// @requirement TB-001
#[test]
fn key_type_defaults_to_none() {
    assert_eq!(KeyType::default(), KeyType::None);
}

// ---------------------------------------------------------------------
// Focus order
// ---------------------------------------------------------------------

/// @requirement TB-002, TB-003
#[test]
fn focus_order_with_a_none_server_key_has_no_server_value_field() {
    let state = ConnectPopupState::new();
    let order = state.focus_order();
    assert_eq!(
        order,
        vec![
            Field::Host,
            Field::Port,
            Field::Nickname,
            Field::IdStorePath,
            Field::ServerKeyType,
            Field::MyKeyValuePub,
            Field::MyKeyValuePriv,
            Field::Connect
        ],
        "my_key always contributes both keybundle paths - there is only one scheme"
    );
}

/// @requirement TB-003
#[test]
fn focus_order_includes_server_key_value_when_not_none() {
    let mut state = ConnectPopupState::new();
    state.server_key.key_type = KeyType::Password;
    assert!(state.focus_order().contains(&Field::ServerKeyValue));
}

/// @requirement AC-084, TB-002, TB-003
#[test]
fn focus_order_includes_both_my_key_files() {
    let state = ConnectPopupState::new();
    let order = state.focus_order();
    assert!(order.contains(&Field::MyKeyValuePub));
    assert!(order.contains(&Field::MyKeyValuePriv));
}

/// @requirement TB-004
#[test]
fn focus_next_and_prev_wrap_around() {
    let mut state = ConnectPopupState::new();
    assert_eq!(state.focus, Field::Host);
    state.focus_prev();
    assert_eq!(
        state.focus,
        Field::Connect,
        "prev from the first field wraps to the last"
    );
    state.focus_next();
    assert_eq!(state.focus, Field::Host);
}

/// @requirement TB-004
#[test]
fn tab_key_advances_focus() {
    let mut state = ConnectPopupState::new();
    state.handle_key(KeyCode::Tab).unwrap();
    assert_eq!(state.focus, Field::Port);
    state.handle_key(KeyCode::BackTab).unwrap();
    assert_eq!(state.focus, Field::Host);
}

/// Cycling the server_key type takes its value field in and out of the
/// focus order; whatever it does, focus must land on a field that is
/// actually there.
/// @requirement TB-003
#[test]
fn cycling_the_server_key_type_always_leaves_focus_on_a_field_that_exists() {
    let mut state = ConnectPopupState::new();
    state.server_key.key_type = KeyType::Password;
    state.focus = Field::ServerKeyType;
    assert!(state.focus_order().contains(&Field::ServerKeyValue));

    state.handle_key(KeyCode::Left).unwrap(); // Password -> None
    assert_eq!(state.server_key.key_type, KeyType::None);
    assert!(
        !state.focus_order().contains(&Field::ServerKeyValue),
        "a none server_key shows no value field"
    );
    assert!(
        state.focus_order().contains(&state.focus),
        "focus must never be left on a field that is no longer shown"
    );
}

/// `my_key` has no type selector to cycle, so its two fields can never be
/// orphaned - a Left/Right anywhere in the group is simply a no-op.
/// @requirement TB-002, TB-003
#[test]
fn my_key_fields_are_never_orphaned_by_a_type_change() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::MyKeyValuePriv;
    state.handle_key(KeyCode::Left).unwrap();
    assert_eq!(state.focus, Field::MyKeyValuePriv);
    assert!(state.focus_order().contains(&Field::MyKeyValuePriv));
}

// ---------------------------------------------------------------------
// Typing into fields
// ---------------------------------------------------------------------

/// @requirement AC-002, TB-012
#[test]
fn typing_fills_host_field() {
    let mut state = ConnectPopupState::new();
    type_str(&mut state, "localhost");
    assert_eq!(state.host, "localhost");
    state.handle_key(KeyCode::Backspace).unwrap();
    assert_eq!(state.host, "localhos");
}

/// @requirement AC-003
#[test]
fn typing_fills_nickname_field_and_rejects_whitespace() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Nickname;
    type_str(&mut state, "dave the");
    assert_eq!(
        state.nickname, "davethe",
        "spaces must not be allowed in a nickname"
    );
}

/// @requirement AC-003
#[test]
fn nickname_field_is_capped_at_ten_characters() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Nickname;
    type_str(&mut state, "davethegreatgatsby");
    assert_eq!(state.nickname.chars().count(), NICKNAME_MAX_LEN);
    assert_eq!(state.nickname, "davethegre");
    // once at the cap, further typing is a no-op, not silent truncation elsewhere
    type_str(&mut state, "x");
    assert_eq!(state.nickname, "davethegre");
}

/// @requirement AC-005
#[test]
fn id_store_path_is_prefilled_from_the_default_path() {
    let state = ConnectPopupState::new();
    assert!(
        !state.id_store_path.is_empty(),
        "id_store should be prefilled, not left blank"
    );
    assert_eq!(
        state.id_store_path,
        aloo::client::idstore::default_path().display().to_string()
    );
}

/// @requirement AC-005, TB-012
#[test]
fn id_store_path_field_is_freely_editable() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::IdStorePath;
    state.id_store_path.clear();
    type_str(&mut state, "/tmp/my_ids_store");
    assert_eq!(state.id_store_path, "/tmp/my_ids_store");
    state.handle_key(KeyCode::Backspace).unwrap();
    assert_eq!(state.id_store_path, "/tmp/my_ids_stor");
}

/// @requirement AC-004
#[test]
fn port_field_only_accepts_digits() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Port;
    type_str(&mut state, "8a0b0");
    assert_eq!(state.port, "800");
}

/// @requirement TB-003
#[test]
fn password_field_only_editable_when_key_type_is_password() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::ServerKeyValue;
    // key_type is still None, so ServerKeyValue isn't a real editable field yet
    type_str(&mut state, "secret");
    assert_eq!(state.server_key.password, "");

    state.server_key.key_type = KeyType::Password;
    type_str(&mut state, "secret");
    assert_eq!(state.server_key.password, "secret");
}

/// @requirement TB-001
#[test]
fn enter_on_key_type_field_cycles_it() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::ServerKeyType;
    state.handle_key(KeyCode::Enter).unwrap();
    assert_eq!(state.server_key.key_type, KeyType::Rsa);
    state.handle_key(KeyCode::Right).unwrap();
    assert_eq!(state.server_key.key_type, KeyType::Password);
}

// ---------------------------------------------------------------------
// Validation / Connect
// ---------------------------------------------------------------------

/// @requirement TB-005
#[test]
fn build_request_rejects_empty_host() {
    let state = ConnectPopupState::new();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("host"));
}

/// @requirement TB-005
#[test]
fn build_request_rejects_bad_port() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "not-a-number".into();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("port"));
}

/// @requirement TB-005
#[test]
fn build_request_rejects_missing_rsa_files() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.server_key.key_type = KeyType::Rsa; // file left blank
    let err = state.build_request().unwrap_err();
    assert!(err.contains("server_key file"));
}

/// @requirement TB-005
#[test]
fn build_request_rejects_missing_nickname() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("nickname"));
}

/// @requirement TB-005
#[test]
fn build_request_rejects_empty_id_store_path() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.id_store_path.clear();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("id_store"));
}

/// @requirement TB-006
#[test]
fn build_request_carries_a_custom_id_store_path() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();
    state.id_store_path = "/custom/ids_store".into();
    let req = state.build_request().expect("should be valid");
    assert_eq!(req.id_store_path, PathBuf::from("/custom/ids_store"));
}

/// @requirement TB-006
#[test]
fn build_request_succeeds_with_a_none_server_key() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();
    let req = state.build_request().expect("should be valid");
    assert_eq!(
        req,
        ConnectRequest {
            host: "localhost".into(),
            port: 9000,
            nickname: "dave".into(),
            server_key: ServerKeySelection::None,
            my_key: MyKeySelection {
                file_pub: PathBuf::from("/keys/pq_hybrid.pub"),
                file_priv: PathBuf::from("/keys/pq_hybrid.priv"),
            },
            id_store_path: PathBuf::from(&state.id_store_path),
        }
    );
}

/// @requirement TB-006
#[test]
fn build_request_succeeds_with_a_password_server_key() {
    let mut state = ConnectPopupState::new();
    state.host = "10.0.0.5".into();
    state.port = "4444".into();
    state.nickname = "dave".into();
    state.server_key.key_type = KeyType::Password;
    state.server_key.password = "hunter2".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();

    let req = state.build_request().expect("should be valid");
    assert_eq!(
        req.server_key,
        ServerKeySelection::Password("hunter2".into())
    );
    assert_eq!(
        req.my_key,
        MyKeySelection {
            file_pub: PathBuf::from("/keys/pq_hybrid.pub"),
            file_priv: PathBuf::from("/keys/pq_hybrid.priv"),
        }
    );
}

/// @requirement AC-084, TB-006
#[test]
fn build_request_succeeds_with_pq_hybrid_files() {
    let mut state = ConnectPopupState::new();
    state.host = "10.0.0.5".into();
    state.port = "4444".into();
    state.nickname = "dave".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid".into();

    let req = state.build_request().expect("should be valid");
    assert_eq!(
        req.my_key,
        MyKeySelection {
            file_pub: PathBuf::from("/keys/pq_hybrid.pub"),
            file_priv: PathBuf::from("/keys/pq_hybrid"),
        }
    );
}

/// @requirement AC-084, TB-005
#[test]
fn build_request_rejects_missing_pq_hybrid_files() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.my_key.file_pub.clear(); // both files left blank
    state.my_key.file_priv.clear();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("file_pub") && err.contains("file_priv"));
}

/// @requirement AC-008
#[test]
fn enter_on_connect_field_with_invalid_form_sets_error_and_does_not_connect() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Connect;
    let action = state.handle_key(KeyCode::Enter).unwrap();
    assert_eq!(action, Action::None);
    assert!(state.error.is_some());
}

/// @requirement AC-007
#[test]
fn enter_on_connect_field_with_valid_form_returns_connect_action() {
    let mut state = ConnectPopupState::new();
    state.host = "chat.example.com".into();
    state.port = "6667".into();
    state.nickname = "dave".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();
    state.focus = Field::Connect;
    let action = state.handle_key(KeyCode::Enter).unwrap();
    match action {
        Action::Connect(req) => {
            assert_eq!(req.host, "chat.example.com");
            assert_eq!(req.port, 6667);
        }
        other => panic!("expected Connect, got {other:?}"),
    }
}

/// @requirement AC-009
#[test]
fn escape_cancels() {
    let mut state = ConnectPopupState::new();
    let action = state.handle_key(KeyCode::Esc).unwrap();
    assert_eq!(action, Action::Cancel);
}

/// @requirement AC-010
#[test]
fn enter_on_rsa_server_key_value_opens_file_browser() {
    let mut state = ConnectPopupState::new();
    state.server_key.key_type = KeyType::Rsa;
    state.focus = Field::ServerKeyValue;
    state.handle_key(KeyCode::Enter).unwrap();
    assert!(state.browser.is_some());
}

// ---------------------------------------------------------------------
// FileBrowserState
// ---------------------------------------------------------------------

fn make_tree() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "aloo-ui-popup-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ));
    let sub = root.join("subdir");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(root.join("file.txt"), b"hello").unwrap();
    std::fs::write(sub.join("nested.txt"), b"world").unwrap();
    root
}

// tiny non-cryptographic unique suffix so parallel test runs don't collide
fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// @requirement TB-007
#[test]
fn file_browser_lists_parent_dirs_then_files_sorted() {
    let root = make_tree();
    let browser = FileBrowserState::open(root.clone()).unwrap();
    let names: Vec<&str> = browser.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["..", "subdir", "file.txt"]);
    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-011
#[test]
fn file_browser_navigates_into_subdir_and_back() {
    let root = make_tree();
    let mut browser = FileBrowserState::open(root.clone()).unwrap();

    // select "subdir" (index 1: "..", "subdir", "file.txt")
    browser.selected = 1;
    assert_eq!(browser.selected_entry().unwrap().name, "subdir");
    browser.navigate_into_selected().unwrap();
    assert_eq!(browser.current_dir, root.join("subdir"));
    assert!(browser.entries.iter().any(|e| e.name == "nested.txt"));

    assert!(browser.go_back().unwrap());
    assert_eq!(browser.current_dir, root);

    assert!(browser.go_forward().unwrap());
    assert_eq!(browser.current_dir, root.join("subdir"));

    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-011
#[test]
fn file_browser_go_back_with_no_history_returns_false() {
    let root = make_tree();
    let mut browser = FileBrowserState::open(root.clone()).unwrap();
    assert!(!browser.go_back().unwrap());
    assert!(!browser.go_forward().unwrap());
    std::fs::remove_dir_all(&root).ok();
}

/// @requirement TB-009
#[test]
fn file_browser_new_navigation_clears_forward_history() {
    let root = make_tree();
    let mut browser = FileBrowserState::open(root.clone()).unwrap();
    browser.selected = 1; // subdir
    browser.navigate_into_selected().unwrap();
    browser.go_back().unwrap();
    // now there is forward history (subdir); navigating elsewhere should clear it
    browser.selected = 0; // ".." — navigate to parent, a fresh navigation
    browser.navigate_into_selected().unwrap();
    assert!(
        !browser.go_forward().unwrap(),
        "forward history should have been invalidated"
    );
    std::fs::remove_dir_all(&root).ok();
}

/// @requirement TB-008
#[test]
fn file_browser_selected_path_resolves_dotdot_to_parent() {
    let root = make_tree();
    let browser = FileBrowserState::open(root.clone()).unwrap();
    assert_eq!(browser.selected_entry().unwrap().name, "..");
    assert_eq!(
        browser.selected_path().unwrap(),
        root.parent().unwrap().to_path_buf()
    );
    std::fs::remove_dir_all(&root).ok();
}

/// @requirement TB-008
#[test]
fn file_browser_select_next_prev_wrap_around() {
    let root = make_tree();
    let mut browser = FileBrowserState::open(root.clone()).unwrap();
    let len = browser.entries.len();
    browser.select_prev();
    assert_eq!(browser.selected, len - 1);
    browser.select_next();
    assert_eq!(browser.selected, 0);
    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-010
#[test]
fn selecting_a_file_in_browser_applies_it_to_the_popup_field() {
    let root = make_tree();
    let mut state = ConnectPopupState::new();
    state.server_key.key_type = KeyType::Rsa;
    state.focus = Field::ServerKeyValue;
    state.handle_key(KeyCode::Enter).unwrap(); // opens browser at process cwd

    // force the browser into our known temp tree so the test is deterministic
    state.browser = Some((
        aloo::client::tui::ui_connect_popup::FileBrowserTarget::ServerKeyFile,
        FileBrowserState::open(root.clone()).unwrap(),
    ));
    // move selection to "file.txt" (index 2: "..", "subdir", "file.txt")
    state.handle_key(KeyCode::Down).unwrap();
    state.handle_key(KeyCode::Down).unwrap();
    state.handle_key(KeyCode::Enter).unwrap();

    assert!(
        state.browser.is_none(),
        "selecting a file should close the browser"
    );
    assert_eq!(
        state.server_key.file,
        root.join("file.txt").display().to_string()
    );

    std::fs::remove_dir_all(&root).ok();
}

// ---------------------------------------------------------------------
// Rendering smoke tests (no assertions on pixels, just "it doesn't panic
// and produces a non-blank frame")
// ---------------------------------------------------------------------

/// @requirement TB-010
#[test]
fn render_does_not_panic_for_every_server_key_type() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    for server_kind in [KeyType::None, KeyType::Password, KeyType::Rsa] {
        let mut state = ConnectPopupState::new();
        state.server_key.key_type = server_kind;
        terminal.draw(|f| render(f, &state)).unwrap();
    }
}

/// @requirement TB-010
#[test]
fn render_draws_something_when_popup_is_shown() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let state = ConnectPopupState::new();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let has_content = buffer.content().iter().any(|cell| cell.symbol() != " ");
    assert!(has_content, "connect popup should render visible content");
}

/// @requirement AC-007
#[test]
fn render_shows_a_connect_button() {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let state = ConnectPopupState::new();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let mut rows = Vec::new();
    for y in 0..buffer.area.height {
        let mut row = String::new();
        for x in 0..buffer.area.width {
            row.push_str(buffer[(x, y)].symbol());
        }
        rows.push(row);
    }
    assert!(
        rows.iter().any(|row| row.contains("Connect")),
        "expected a visible Connect button"
    );
}

/// The read-only line above the Connect button (`docs/SPEC.md` "Not
/// connected UI"). Gray, so it reads as a note about where this client's
/// local state lives rather than as another thing to fill in.
/// @requirement AC-258
#[test]
fn render_shows_the_resolved_aloo_home_in_gray() {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = ConnectPopupState::new();
    // A value of our own rather than whatever this machine resolves, so
    // the assertion is about the rendering rather than about $HOME.
    state.aloo_home = "/tmp/aloo-bob".to_string();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let expected = format!("{ALOO_HOME_LABEL}/tmp/aloo-bob");
    let mut found = None;
    for y in 0..buffer.area.height {
        let mut row = String::new();
        for x in 0..buffer.area.width {
            row.push_str(buffer[(x, y)].symbol());
        }
        if let Some(x) = row.find(&expected) {
            found = Some((x as u16, y));
        }
    }
    let (x, y) = found.expect("expected an ALOO_HOME line in the popup");
    assert_eq!(
        buffer[(x, y)].fg,
        Color::DarkGray,
        "the ALOO_HOME line is gray, not another field to fill in"
    );

    // It sits above the Connect button, which is what makes it read as a
    // note about the connection that is about to happen.
    let button_y = (0..buffer.area.height)
        .find(|&by| {
            by > y
                && (0..buffer.area.width.saturating_sub(6)).any(|bx| {
                    (0..7)
                        .map(|i| buffer[(bx + i, by)].symbol().to_string())
                        .collect::<String>()
                        == "Connect"
                })
        })
        .expect("the Connect button should be below the ALOO_HOME line");
    assert!(button_y > y);
}

/// @requirement AC-258
#[test]
fn a_fresh_popup_captures_the_aloo_home_it_resolved() {
    let state = ConnectPopupState::new();
    assert_eq!(
        state.aloo_home,
        aloo::platform::aloo_dir().display().to_string(),
        "the popup names the directory this process actually uses"
    );
}

/// @requirement AC-001
#[test]
fn popup_opens_with_the_cursor_focused_in_the_host_box() {
    let state = ConnectPopupState::new();
    assert_eq!(
        state.focus,
        Field::Host,
        "host must be the default focus when the popup opens"
    );

    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();

    // the host box is titled "host" and bordered - its content row is the
    // one right below that title/border, one row below the popup's own
    // top border.
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
        .expect("cursor should be set while a text field is focused");
    assert_eq!(
        cursor.y,
        host_title_row + 1,
        "cursor should sit on the host field's content row"
    );
}

/// @requirement AC-002
#[test]
fn host_port_and_nickname_are_each_individually_bordered() {
    let state = ConnectPopupState::new();
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();

    for title in ["host", "port", "nickname"] {
        assert!(
            rows.iter().any(|r| r.contains(title)),
            "expected a \"{title}\" box title: {rows:?}"
        );
    }
    // each titled box is bordered on its own, not just sharing the outer
    // popup border - i.e. there's more than one box-drawing top-left
    // corner in the popup besides the outer one.
    let corner_rows = rows.iter().filter(|r| r.contains('┌')).count();
    assert!(
        corner_rows >= 4,
        "expected the outer popup plus host/port/nickname to each have their own top border: {rows:?}"
    );
}

/// @requirement TB-011
#[test]
fn popup_is_wider_than_the_original_fifty_columns() {
    let state = ConnectPopupState::new();
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let top_border_width = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .filter(|&x| buffer[(x, y)].symbol() == "─")
                .count()
        })
        .max()
        .unwrap_or(0);
    assert!(
        top_border_width > 48,
        "popup should be wider than the original 50-column box: {top_border_width}"
    );
}

/// @requirement AC-012
#[test]
fn connect_button_highlight_does_not_bleed_into_its_border() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.focus = Field::Connect;

    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    // The popup's own title (its outer border) also reads "Connect" -
    // the button is the *last* (bottommost) occurrence, not the first.
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
    let (x, y) = last_match.expect("expected to find the rendered \"Connect\" button label");
    let text_bg = buffer[(x, y)].style().bg;
    assert_eq!(
        text_bg,
        Some(Color::Green),
        "the focused button's text should be highlighted"
    );
    let border_bg = buffer[(x, y - 1)].style().bg;
    assert_ne!(
        border_bg,
        Some(Color::Green),
        "the button's border must stay outside the highlight, not filled with it"
    );
}

/// @requirement TB-010
#[test]
fn render_with_open_file_browser_does_not_panic() {
    let root = make_tree();
    let mut state = ConnectPopupState::new();
    state.server_key.key_type = KeyType::Rsa;
    state.browser = Some((
        aloo::client::tui::ui_connect_popup::FileBrowserTarget::ServerKeyFile,
        FileBrowserState::open(root.clone()).unwrap(),
    ));
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    std::fs::remove_dir_all(&root).ok();
}

/// @requirement AC-093
#[test]
fn file_browser_render_scrolls_to_keep_the_selection_visible() {
    // More files than fit in the browser popup's visible height, so a
    // selection near the end starts out scrolled off screen.
    let root = std::env::temp_dir().join(format!(
        "aloo-ui-popup-scroll-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ));
    std::fs::create_dir_all(&root).unwrap();
    for i in 0..30 {
        std::fs::write(root.join(format!("file{i:02}.txt")), b"x").unwrap();
    }

    let mut browser = FileBrowserState::open(root.clone()).unwrap();
    // entries: "..", file00.txt, ..., file29.txt (31 total) - move selection
    // all the way to the last one.
    for _ in 0..30 {
        browser.select_next();
    }
    assert_eq!(browser.selected_entry().unwrap().name, "file29.txt");

    let mut state = ConnectPopupState::new();
    state.server_key.key_type = KeyType::Rsa;
    state.browser = Some((
        aloo::client::tui::ui_connect_popup::FileBrowserTarget::ServerKeyFile,
        browser,
    ));

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();

    assert!(
        rows.iter().any(|r| r.contains("file29.txt")),
        "the selected entry must have scrolled into view: {rows:?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("file00.txt")),
        "an unselected entry far from the current scroll position should not still be shown: {rows:?}"
    );

    std::fs::remove_dir_all(&root).ok();
}

