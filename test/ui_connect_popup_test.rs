use aloo::client::connect::{ConnectRequest, MyKeySelection, RegisterRequest};
use aloo::client::file_browser::FileBrowserState;
use aloo::client::tui::ui_connect_popup::{
    ACTIVATION_CODE_LEN, ALOO_HOME_LABEL, Action, ActivationAction, ActivationPopupState,
    ConnectPopupState, Field, NICKNAME_MAX_LEN, render, render_activation,
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
// Focus order
// ---------------------------------------------------------------------

/// One way to authenticate and one `my_key` scheme: nothing in the focus
/// order is conditional any more, and there is no `server_key` or
/// `id_store` field in it at all. `email`/`Register` only join the order
/// once the server takes registrations at all.
/// @requirement TB-002, TB-003, AC-270
#[test]
fn focus_order_lists_every_field_once_with_register_last_when_registration_is_available() {
    let mut state = ConnectPopupState::new();
    state.registration_available = true;
    let order = state.focus_order();
    assert_eq!(
        order,
        vec![
            Field::Host,
            Field::Port,
            Field::Nickname,
            Field::Password,
            Field::Email,
            Field::MyKeyValuePub,
            Field::MyKeyValuePriv,
            Field::Connect,
            Field::Register,
        ],
        "my_key always contributes both keybundle paths - there is only one scheme"
    );
    assert_eq!(order.last(), Some(&Field::Register), "Register sits at the end");
}

/// A server that takes no registrations has nothing for `email`/Register
/// to do, so neither is reachable at all - not shown, not tabbed to.
/// @requirement AC-270
#[test]
fn focus_order_excludes_email_and_register_unless_registration_is_available() {
    let state = ConnectPopupState::new();
    assert!(!state.registration_available, "off unless settings say otherwise");
    let order = state.focus_order();
    assert!(!order.contains(&Field::Email));
    assert!(!order.contains(&Field::Register));
    assert_eq!(order.last(), Some(&Field::Connect), "Connect is the last field with no Register");
}

/// @requirement AC-084, TB-002
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
        "prev from the first field wraps to the last - Connect, with registration unavailable"
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

/// `my_key` has no type selector to cycle, so its two fields can never be
/// orphaned - a Left/Right anywhere in the group is simply a no-op.
/// @requirement TB-002
#[test]
fn my_key_fields_are_never_orphaned_by_a_type_change() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::MyKeyValuePriv;
    state.handle_key(KeyCode::Left).unwrap();
    assert_eq!(state.focus, Field::MyKeyValuePriv);
    assert!(state.focus_order().contains(&Field::MyKeyValuePriv));
}

/// `ssl` is not a popup field at all - like `server_ssl` on the server
/// side, it is settings-only (`connect_ssl`). The popup only ever carries
/// whatever value was captured from settings when it opened, silently,
/// into the request it builds; no key anywhere in the popup can change it.
/// @requirement AC-269, TB-001
#[test]
fn ssl_is_settings_only_and_cannot_be_toggled_from_the_popup() {
    let mut state = ConnectPopupState::new();
    assert!(!state.ssl, "plain TCP unless connect_ssl said otherwise");
    // Every key a user could press, on every field, leaves it alone.
    for field in state.focus_order() {
        state.focus = field;
        for key in [KeyCode::Left, KeyCode::Right, KeyCode::Enter, KeyCode::Char('x')] {
            let _ = state.handle_key(key);
        }
    }
    assert!(!state.ssl, "nothing in the popup ever touches ssl");

    // What settings captured is still carried into the built request.
    state.ssl = true;
    state.host = "chat.example.com".into();
    state.port = "6667".into();
    state.nickname = "dave".into();
    state.password = "hunter2".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid".into();
    assert!(state.build_request().unwrap().ssl);
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

/// There is no `id_store` field: the store has exactly one home
/// (`idstore::default_path`, under `ALOO_HOME`), and the popup neither
/// shows nor lets anyone edit it.
/// @requirement AC-005
#[test]
fn the_popup_has_no_id_store_field() {
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
    assert!(
        !rows.iter().any(|r| r.contains("id_store")),
        "no id_store box on the form: {rows:?}"
    );
    let req = {
        let mut state = state;
        state.host = "localhost".into();
        state.port = "9000".into();
        state.nickname = "dave".into();
        state.password = "pw".into();
        state.my_key.file_pub = "/keys/a.pub".into();
        state.my_key.file_priv = "/keys/a.priv".into();
        state.build_request().unwrap()
    };
    // Nothing in the request names a store path either.
    assert_eq!(
        format!("{req:?}").contains("id_store"),
        false,
        "the request carries no id_store path: {req:?}"
    );
}

/// @requirement AC-269, TB-012
#[test]
fn password_field_takes_any_character_and_backspaces() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Password;
    type_str(&mut state, "s3cret pass!");
    assert_eq!(state.password, "s3cret pass!", "a password may contain anything");
    state.handle_key(KeyCode::Backspace).unwrap();
    assert_eq!(state.password, "s3cret pass");
}

/// @requirement AC-269
#[test]
fn the_password_is_rendered_masked() {
    let mut state = ConnectPopupState::new();
    state.password = "hunter2".into();
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
    assert!(!rows.iter().any(|r| r.contains("hunter2")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("*******")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("password")), "{rows:?}");
}

/// @requirement AC-270, TB-012
#[test]
fn email_field_refuses_whitespace_and_backspaces() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Email;
    type_str(&mut state, "dave @example.com");
    assert_eq!(state.email, "dave@example.com");
    state.handle_key(KeyCode::Backspace).unwrap();
    assert_eq!(state.email, "dave@example.co");
}

/// @requirement AC-004
#[test]
fn port_field_only_accepts_digits() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Port;
    type_str(&mut state, "8a0b0");
    assert_eq!(state.port, "800");
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
fn build_request_rejects_missing_nickname() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("nickname"));
}

/// @requirement TB-005, AC-269
#[test]
fn build_request_rejects_a_missing_password() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();
    let err = state.build_request().unwrap_err();
    assert!(err.contains("password"), "{err}");
}

/// @requirement TB-006
#[test]
fn build_request_maps_the_form_onto_a_connect_request() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.password = "hunter2".into();
    state.email = "ignored@example.com".into();
    state.ssl = true;
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();
    let req = state.build_request().expect("should be valid");
    assert_eq!(
        req,
        ConnectRequest {
            host: "localhost".into(),
            port: 9000,
            ssl: true,
            ssl_ca: None,
            nickname: "dave".into(),
            password: "hunter2".into(),
            my_key: MyKeySelection {
                file_pub: PathBuf::from("/keys/pq_hybrid.pub"),
                file_priv: PathBuf::from("/keys/pq_hybrid.priv"),
            },
            activation_code: None,
        }
    );
}

/// Connect never needs an email; Register always does, and a plausible
/// one.
/// @requirement AC-270, TB-005
#[test]
fn register_needs_an_email_where_connect_does_not() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "dave".into();
    state.password = "hunter2".into();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".into();
    state.my_key.file_priv = "/keys/pq_hybrid.priv".into();
    assert!(state.build_request().is_ok());
    let err = state.build_register_request().unwrap_err();
    assert!(err.contains("email"), "{err}");

    state.email = "not-an-address".into();
    let err = state.build_register_request().unwrap_err();
    assert!(err.contains("email"), "{err}");

    state.email = "dave@example.com".into();
    assert_eq!(
        state.build_register_request().unwrap(),
        RegisterRequest {
            host: "localhost".into(),
            port: 9000,
            ssl: false,
            ssl_ca: None,
            nickname: "dave".into(),
            password: "hunter2".into(),
            email: "dave@example.com".into(),
        }
    );
}

/// A registrable nickname is the registry's alphabet, checked on the
/// form before a round trip to the server says the same thing.
/// @requirement AC-270
#[test]
fn register_refuses_a_nickname_the_registry_could_not_hold() {
    let mut state = ConnectPopupState::new();
    state.host = "localhost".into();
    state.port = "9000".into();
    state.nickname = "da/ve".into();
    state.password = "hunter2".into();
    state.email = "dave@example.com".into();
    let err = state.build_register_request().unwrap_err();
    assert!(err.contains("nickname"), "{err}");
}

/// @requirement AC-270
#[test]
fn enter_on_register_returns_a_register_action_or_an_error() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Register;
    assert_eq!(state.handle_key(KeyCode::Enter).unwrap(), Action::None);
    assert!(state.error.is_some(), "an empty form is refused with a reason");

    state.host = "chat.example.com".into();
    state.port = "6667".into();
    state.nickname = "dave".into();
    state.password = "hunter2".into();
    state.email = "dave@example.com".into();
    match state.handle_key(KeyCode::Enter).unwrap() {
        Action::Register(req) => assert_eq!(req.email, "dave@example.com"),
        other => panic!("expected Register, got {other:?}"),
    }
}

/// @requirement AC-084, TB-006
#[test]
fn build_request_succeeds_with_pq_hybrid_files() {
    let mut state = ConnectPopupState::new();
    state.host = "10.0.0.5".into();
    state.port = "4444".into();
    state.nickname = "dave".into();
    state.password = "hunter2".into();
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
    state.password = "hunter2".into();
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
    state.password = "hunter2".into();
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
fn enter_on_a_my_key_file_field_opens_file_browser() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::MyKeyValuePub;
    state.handle_key(KeyCode::Enter).unwrap();
    assert!(state.browser.is_some());
}

// ---------------------------------------------------------------------
// Activation popup
// ---------------------------------------------------------------------

/// @requirement AC-271
#[test]
fn activation_popup_takes_exactly_twelve_digits() {
    let mut popup = ActivationPopupState::new("dave");
    for c in "12a3-4567 890123".chars() {
        popup.handle_key(KeyCode::Char(c));
    }
    assert_eq!(popup.code, "123456789012", "digits only, capped at the code length");
    assert_eq!(popup.code.len(), ACTIVATION_CODE_LEN);
    popup.handle_key(KeyCode::Backspace);
    assert_eq!(popup.code, "12345678901");
}

/// @requirement AC-271
#[test]
fn activation_popup_submits_a_complete_code_and_refuses_a_short_one() {
    let mut popup = ActivationPopupState::new("dave");
    for c in "1234".chars() {
        popup.handle_key(KeyCode::Char(c));
    }
    assert_eq!(popup.handle_key(KeyCode::Enter), ActivationAction::None);
    assert!(popup.error.is_some(), "a short code is refused with a reason");
    for c in "56789012".chars() {
        popup.handle_key(KeyCode::Char(c));
    }
    assert_eq!(
        popup.handle_key(KeyCode::Enter),
        ActivationAction::Submit("123456789012".into())
    );
    assert_eq!(popup.handle_key(KeyCode::Esc), ActivationAction::Cancel);
}

/// @requirement AC-271
#[test]
fn activation_popup_renders_the_nickname_the_code_and_the_error() {
    let mut popup = ActivationPopupState::new("dave");
    popup.code = "1234".into();
    popup.error = Some("wrong activation code".into());
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_activation(f, &popup)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect();
    assert!(rows.iter().any(|r| r.contains("dave")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("1234")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("wrong activation code")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("activation code")), "{rows:?}");
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
    state.focus = Field::MyKeyValuePub;
    state.handle_key(KeyCode::Enter).unwrap(); // opens browser at process cwd

    // force the browser into our known temp tree so the test is deterministic
    state.browser = Some((
        aloo::client::tui::ui_connect_popup::FileBrowserTarget::MyKeyFilePub,
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
        state.my_key.file_pub,
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
fn render_does_not_panic_with_ssl_on_or_off_or_a_notice_showing() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    for ssl in [false, true] {
        let mut state = ConnectPopupState::new();
        state.ssl = ssl;
        state.notice = Some("registered - check your email".into());
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

fn rows_of(state: &ConnectPopupState) -> Vec<String> {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render(f, state)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect()
}

/// The Register button (and the email field it needs) only appears once
/// the server this popup was opened for takes registrations at all.
/// @requirement AC-270
#[test]
fn register_button_and_email_field_only_show_when_registration_is_available() {
    let state = ConnectPopupState::new();
    let rows = rows_of(&state);
    assert!(
        !rows.iter().any(|row| row.contains("Register")),
        "no Register button while registration is unavailable: {rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row.contains("email")),
        "no email field while registration is unavailable: {rows:?}"
    );

    let mut state = ConnectPopupState::new();
    state.registration_available = true;
    let rows = rows_of(&state);
    assert!(rows.iter().any(|row| row.contains("Register")), "{rows:?}");
    assert!(rows.iter().any(|row| row.contains("email")), "{rows:?}");
}

/// The hint line shows an error in red, else a notice in green, else the
/// key hint - and an error wins over a notice.
/// @requirement AC-270
#[test]
fn render_shows_a_registration_notice_in_green_unless_an_error_replaces_it() {
    fn hint_cells(state: &ConnectPopupState, needle: &str) -> Option<Color> {
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, state)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        for y in 0..buffer.area.height {
            let row: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect();
            if let Some(x) = row.find(needle) {
                return buffer[(x as u16, y)].style().fg;
            }
        }
        None
    }
    let mut state = ConnectPopupState::new();
    state.notice = Some("registered - check your mail".into());
    assert_eq!(hint_cells(&state, "registered"), Some(Color::Green));
    state.error = Some("registration failed".into());
    assert_eq!(hint_cells(&state, "registration failed"), Some(Color::Red));
    assert_eq!(hint_cells(&state, "registered -"), None, "the error replaces the notice");
}

/// The keyboard-shortcut hint is the last thing in the popup's own layout
/// (after the buttons, in the trailing `Min(1)` chunk) and centered
/// horizontally, not flush left.
/// @requirement TB-244
#[test]
fn the_shortcut_hint_is_centered() {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let state = ConnectPopupState::new();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let needle: Vec<char> = "Tab: next field  Enter: select/connect  Esc: quit"
        .chars()
        .collect();
    let mut found = None;
    for y in 0..buffer.area.height {
        let row_chars: Vec<char> = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol().chars().next().unwrap_or(' '))
            .collect();
        if let Some(start) = row_chars.windows(needle.len()).position(|w| w == needle.as_slice()) {
            found = Some((start, y, row_chars.iter().collect::<String>()));
        }
    }
    let (start, _, row) = found.expect("expected the shortcut hint in the popup");
    let end = start + needle.len();
    let text_mid = (start + end) as i32 / 2;
    let screen_mid = buffer.area.width as i32 / 2;
    assert!(
        (text_mid - screen_mid).abs() <= 1,
        "the shortcut hint should be centered, not flush left: {row:?}"
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

/// The line is set apart from the form around it: centered horizontally
/// rather than flush left, with a blank row of its own directly above and
/// directly below it.
/// @requirement AC-258
#[test]
fn aloo_home_line_is_centered_with_a_blank_line_above_and_below() {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = ConnectPopupState::new();
    state.aloo_home = "/tmp/aloo-bob".to_string();
    terminal.draw(|f| render(f, &state)).unwrap();
    let buffer = terminal.backend().buffer().clone();

    let expected: Vec<char> = format!("{ALOO_HOME_LABEL}/tmp/aloo-bob").chars().collect();
    let mut found = None;
    for y in 0..buffer.area.height {
        let row_chars: Vec<char> = (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol().chars().next().unwrap_or(' '))
            .collect();
        // Column indices, not byte offsets - `str::find` would be thrown
        // off by the popup's own multi-byte box-drawing border characters
        // sharing the row.
        if let Some(start) = row_chars.windows(expected.len()).position(|w| w == expected.as_slice()) {
            found = Some((start, y, row_chars.iter().collect::<String>()));
        }
    }
    let (start, y, row) = found.expect("expected an ALOO_HOME line in the popup");
    let end = start + expected.len();
    let text_mid = (start + end) as i32 / 2;
    let screen_mid = buffer.area.width as i32 / 2;
    assert!(
        (text_mid - screen_mid).abs() <= 1,
        "the ALOO_HOME line should be centered, not flush left: {row:?}"
    );

    for neighbour_y in [y - 1, y + 1] {
        let neighbour: String = (0..buffer.area.width)
            .map(|x| buffer[(x, neighbour_y)].symbol())
            .collect();
        // The popup's own left/right border (│) still crosses every
        // interior row - "blank" means no other visible content beside it.
        assert!(
            neighbour.chars().all(|c| c == ' ' || c == '│'),
            "row {neighbour_y} beside the ALOO_HOME line should be blank: {neighbour:?}"
        );
    }
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
    let mut state = ConnectPopupState::new();
    state.registration_available = true; // so the email box is on screen too
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

    for title in ["host", "port", "nickname", "password", "email"] {
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
        corner_rows >= 6,
        "expected the outer popup plus host/port/nickname/password/email to each have their own top border: {rows:?}"
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
    state.password = "pw".into();
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
    state.browser = Some((
        aloo::client::tui::ui_connect_popup::FileBrowserTarget::MyKeyFilePriv,
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
    state.browser = Some((
        aloo::client::tui::ui_connect_popup::FileBrowserTarget::MyKeyFilePub,
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

