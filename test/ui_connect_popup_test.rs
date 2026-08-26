use aloo::client::connect::{ConnectRequest, MyKeySelection, RegisterRequest};
use aloo::client::file_browser::FileBrowserState;
use aloo::client::tui::ui_connect_popup::{
    ACTIVATION_CODE_LEN, ALOO_HOME_LABEL, Action, ActivationAction, ActivationPopupState,
    ConnectPopupState, Field, NICKNAME_MAX_LEN, render, render_activation, render_processing,
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
/// `id_store` field in it at all. `email`/`Register` are always in it too,
/// and `my_key`'s own two fields never are - they are read-only
/// information now, not something to tab to.
/// @requirement TB-002, TB-003, AC-270
#[test]
fn focus_order_lists_every_field_once() {
    let state = ConnectPopupState::new();
    let order = state.focus_order();
    assert_eq!(
        order,
        vec![
            Field::Host,
            Field::Port,
            Field::Nickname,
            Field::Password,
            Field::Email,
            Field::Connect,
            Field::Register,
        ],
    );
}

/// @requirement TB-004
#[test]
fn focus_next_and_prev_wrap_around() {
    let mut state = ConnectPopupState::new();
    assert_eq!(state.focus, Field::Host);
    state.focus_prev();
    assert_eq!(state.focus, Field::Register, "prev from the first field wraps to the last");
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

/// `ssl` is not a popup field at all - like `server_ssl` on the server
/// side, it is settings-only (`connect_using_ssl`, shared with daemon
/// mode, with no CLI override either). The popup only ever carries
/// whatever value was captured from settings when it opened, silently,
/// into the request it builds; no key anywhere in the popup can change it.
/// @requirement AC-269, TB-001
#[test]
fn ssl_is_settings_only_and_cannot_be_toggled_from_the_popup() {
    let mut state = ConnectPopupState::new();
    assert!(!state.ssl, "plain TCP unless connect_using_ssl said otherwise");
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
fn nickname_field_is_capped_at_eleven_characters() {
    let mut state = ConnectPopupState::new();
    state.focus = Field::Nickname;
    type_str(&mut state, "davethegreatgatsby");
    assert_eq!(state.nickname.chars().count(), NICKNAME_MAX_LEN);
    assert_eq!(state.nickname, "davethegrea");
    // once at the cap, further typing is a no-op, not silent truncation elsewhere
    type_str(&mut state, "x");
    assert_eq!(state.nickname, "davethegrea");
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

/// A successful Register goes straight into the activation popup with a
/// different, shorter message than the pending-login path above - it
/// already knows why it's here, so it doesn't re-explain.
/// @requirement AC-271
#[test]
fn activation_popup_after_registration_carries_the_exact_wording() {
    let popup = ActivationPopupState::new_after_registration("dave");
    assert_eq!(popup.message, "Enter the activation code you received by email");
    assert_ne!(
        popup.message,
        ActivationPopupState::new("dave").message,
        "the post-registration wording must differ from the pending-login wording"
    );

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
    assert!(
        rows.iter().any(|r| r.contains("Enter the activation code you received by email")),
        "{rows:?}"
    );
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

/// The Register button and the email field are always rendered, on every
/// server - whether registration is actually open is answered by the
/// server itself when Register is pressed (`register_account`), never by
/// hiding either field.
/// @requirement AC-270
#[test]
fn register_button_and_email_field_always_show() {
    let state = ConnectPopupState::new();
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

/// An SSL-mismatch diagnosis (`connect::with_ssl_diagnosis`) composes the
/// connect failure with a second sentence naming the exact setting to
/// flip, well past what one 64-column row can hold - it must wrap onto
/// the hint area's later rows rather than being silently clipped, or the
/// one piece of text that actually explains the failure never reaches
/// the user.
/// @requirement AC-270
#[test]
fn a_long_ssl_mismatch_error_wraps_instead_of_being_clipped() {
    let mut state = ConnectPopupState::new();
    state.error = Some(
        "connect to chat.example.com:7878 timed out after 15s - this server appears to \
         require SSL - turn connect_using_ssl=on in ~/.aloo/settings"
            .to_string(),
    );
    let rows = rows_of(&state).join("\n");
    // Checked as separate substrings, not one contiguous string: word-wrap
    // is free to break the line anywhere between them, and only *that* -
    // not the exact break point - is what a real terminal would also do.
    for needle in ["require SSL", "connect_using_ssl=on", "~/.aloo/settings"] {
        assert!(rows.contains(needle), "{needle:?} missing from wrapped hint: {rows:?}");
    }
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

/// The whole read-only info block - `file_pub`, `file_priv`, then
/// `ALOO_HOME` right below it - is set apart from the form around it: the
/// `ALOO_HOME` line itself is centered horizontally, and there's a blank
/// row directly above `file_pub` (the block's own top) and directly below
/// `ALOO_HOME` (the block's own bottom). `file_priv` sits directly above
/// `ALOO_HOME` with no blank line between them - they read as one block,
/// not three separate notes.
/// @requirement AC-258
#[test]
fn the_read_only_info_block_is_centered_with_a_blank_line_above_and_below() {
    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = ConnectPopupState::new();
    state.aloo_home = "/tmp/aloo-bob".to_string();
    state.my_key.file_pub = "/keys/pq_hybrid.pub".to_string();
    state.my_key.file_priv = "/keys/pq_hybrid".to_string();
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

    let row_at = |yi: u16| -> String { (0..buffer.area.width).map(|x| buffer[(x, yi)].symbol()).collect() };
    assert!(row_at(y - 1).contains("file_priv"), "file_priv sits directly above ALOO_HOME: {:?}", row_at(y - 1));

    // Only the popup's own interior (strictly between its left and right
    // border) needs to be blank here - outside it is the background
    // animation's territory (`DigitalRain`), which this test isn't about.
    let is_blank_inside_popup = |s: &str| {
        let chars: Vec<char> = s.chars().collect();
        match (chars.iter().position(|&c| c == '│'), chars.iter().rposition(|&c| c == '│')) {
            (Some(left), Some(right)) if left < right => {
                chars[left + 1..right].iter().all(|&c| c == ' ')
            }
            _ => false,
        }
    };
    assert!(
        is_blank_inside_popup(&row_at(y + 1)),
        "a blank row directly below ALOO_HOME (the block's bottom): {:?}",
        row_at(y + 1)
    );
    // Walk up from file_priv, past file_pub, to the block's own top -
    // exactly one blank row separates it from the form above.
    assert!(row_at(y - 2).contains("file_pub"), "file_pub sits directly above file_priv: {:?}", row_at(y - 2));
    assert!(
        is_blank_inside_popup(&row_at(y - 3)),
        "a blank row directly above file_pub (the block's top): {:?}",
        row_at(y - 3)
    );
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
fn render_does_not_panic_with_a_notice_or_error_showing() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = ConnectPopupState::new();
    state.notice = Some("registered - check your email".into());
    terminal.draw(|f| render(f, &state)).unwrap();
    state.notice = None;
    state.error = Some("host is required".into());
    terminal.draw(|f| render(f, &state)).unwrap();
}

// ---------------------------------------------------------------------
// The "processing..." screen (shown in place of `render` while a
// Connect/Register attempt is in flight) and the digital-rain background
// it shares with `render`
// ---------------------------------------------------------------------

fn non_blank_fraction(buffer: &ratatui::buffer::Buffer) -> f64 {
    let total = buffer.content().len();
    let non_blank = buffer.content().iter().filter(|c| c.symbol() != " ").count();
    non_blank as f64 / total as f64
}

/// @requirement AC-371
#[test]
fn render_processing_does_not_panic_and_shows_the_label() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 0, "connecting...")).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().chars().next().unwrap_or(' '))
                .collect()
        })
        .collect();
    assert!(
        rows.iter().any(|r| r.contains("connecting...")),
        "expected a centered \"connecting...\" line: {rows:?}"
    );
}

/// `run_with_processing_screen`'s two call sites each pass their own
/// label - Connect's own attempt (`connect_with_reconnect`) says
/// "connecting...", Register's (`register_account`) says "one moment...".
/// Padded with 3 blank columns on each side either way.
/// @requirement AC-371
#[test]
fn render_processing_shows_whichever_label_it_was_given_padded_by_three() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 0, "one moment...")).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().chars().next().unwrap_or(' '))
                .collect()
        })
        .collect();
    let line = rows
        .iter()
        .find(|r| r.contains("one moment..."))
        .expect("expected a centered \"one moment...\" line");
    let padded = "   one moment...   ";
    assert!(
        line.contains(padded),
        "expected exactly 3 blank columns on each side of the label: {line:?}"
    );
}

/// The 3-cell clearing is a real box, not just 3 literal space characters
/// sharing the label's own row: 3 whole blank rows above the label and 3
/// below it too, with no rain drawn through any of them - `DigitalRain`
/// draws nothing at all inside the clearing (`avoid_popup`), rather than
/// the label merely overwriting one row of whatever rain was already
/// there.
/// @requirement AC-371
#[test]
fn render_processing_clears_blank_rows_above_and_below_the_label_too() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 3, "connecting...")).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let rows: Vec<String> = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().chars().next().unwrap_or(' '))
                .collect()
        })
        .collect();
    let label_row = rows
        .iter()
        .position(|r| r.contains("connecting..."))
        .expect("expected a centered \"connecting...\" line");
    // Same horizontal span the clearing box occupies on the label's own
    // row (found via its leading/trailing runs of blanks either side of
    // the label text) - checked on the 3 rows directly above and below
    // too, where nothing but blanks is expected at all.
    let line = &rows[label_row];
    let start = line.find("connecting...").unwrap() - 3;
    let end = start + "   connecting...   ".chars().count();
    for offset in 1..=3 {
        for (name, row) in [("above", &rows[label_row - offset]), ("below", &rows[label_row + offset])] {
            let span: String = row.chars().skip(start).take(end - start).collect();
            assert!(
                span.chars().all(|c| c == ' '),
                "expected a blank row {offset} cell(s) {name} the label, got {span:?}"
            );
        }
    }
}

/// Each column's own fall speed and trail length are periodically
/// reseeded, staggered so columns don't all reseed on the same tick -
/// the animation should keep producing a fresh pattern over an extended
/// stretch of frames rather than settling into a short repeating loop.
/// @requirement AC-372
#[test]
fn the_background_animation_does_not_settle_into_a_short_repeating_cycle() {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    let buffers: Vec<_> = (0..60u64)
        .map(|frame| {
            terminal.draw(|f| render_processing(f, frame, "connecting...")).unwrap();
            terminal.backend().buffer().clone()
        })
        .collect();
    for i in 0..buffers.len() {
        for j in (i + 1)..buffers.len() {
            assert_ne!(
                buffers[i], buffers[j],
                "frames {i} and {j} rendered identically - the animation has settled into \
                 a repeating cycle within just {} frames",
                buffers.len()
            );
        }
    }
}

/// Degenerate terminal sizes must not panic - the same guard `render`
/// itself already relies on via `centered_rect`/layout clamping.
/// @requirement AC-371
#[test]
fn render_processing_does_not_panic_on_a_zero_sized_or_tiny_terminal() {
    let backend = TestBackend::new(1, 1);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 5, "connecting...")).unwrap();

    let backend = TestBackend::new(80, 1);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 5, "connecting...")).unwrap();
}

/// The processing screen's animation must still advance frame to frame,
/// same as the popup's own background does.
/// @requirement AC-371
#[test]
fn render_processing_animates_across_frames() {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 0, "connecting...")).unwrap();
    let first = terminal.backend().buffer().clone();
    terminal.draw(|f| render_processing(f, 20, "connecting...")).unwrap();
    let second = terminal.backend().buffer().clone();
    assert_ne!(first, second, "the animation must visibly move between frames");
}

/// The digital-rain background (shared by `render` and `render_processing`)
/// must be dense - not just sparse falling streaks over empty space - and
/// include glyphs scattered independently of any column's own falling
/// trail, closer to a real "matrix screen."
/// @requirement AC-372
#[test]
fn the_background_animation_is_dense_with_scattered_glyphs_not_just_thin_streaks() {
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| render_processing(f, 37, "connecting...")).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let fraction = non_blank_fraction(&buffer);
    assert!(
        fraction > 0.35,
        "expected a dense background (>35% of cells lit, including scattered background \
         glyphs outside the falling trails), got {:.1}%",
        fraction * 100.0
    );
    assert!(fraction < 1.0, "still sparse enough to read as \"rain,\" not a solid fill");
}

