//! The "not connected" screen: a centered modal collecting host/port, the
//! nickname and its password, an optional email for registering, the
//! `ssl` switch and the `my_key` keybundle, including an in-TUI file
//! browser (no OS file dialog exists in a terminal) for the key files.
//! Also the small activation-code popup a first login into an unactivated
//! account opens (`ActivationPopupState`).
//!
//! State transitions (`ConnectPopupState::handle_key`,
//! `crate::client::file_browser::FileBrowserState` navigation) are plain
//! functions independent of rendering, so they're unit tested without a
//! terminal.

use std::io;
use std::path::PathBuf;

use crossterm::event::{Event, KeyCode, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::ui::{centered_rect, focus_border_style, render_file_browser};
use crate::client::connect::{ConnectRequest, MyKeySelection, RegisterRequest};
use crate::client::file_browser::FileBrowserState;

/// `my_key` has no type selector: `pq_hybrid` (ML-DSA-87+RSA4096 signing,
/// ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption - §13) is the
/// only peer-to-peer scheme this app has, so the group is just the two
/// keybundle files. Generated with `aloo --keygen-pq-hybrid` (no `openssl`
/// exists for ML-DSA/ML-KEM), though connecting auto-generates a missing
/// bundle (`crypto::pq::ensure_bundle_at`), so no manual step is required.
#[derive(Debug, Clone, Default)]
pub struct MyKeyFields {
    pub file_pub: String,
    pub file_priv: String,
}

/// Prefix of the read-only line above the buttons naming the directory
/// every piece of this client's local state lives under
/// (`crate::platform::aloo_dir`). Spelled as the environment variable
/// that sets it, so the line doubles as the answer to "how do I run a
/// second client on this machine": `ALOO_HOME=/tmp/aloo-bob aloo`.
pub const ALOO_HOME_LABEL: &str = "ALOO_HOME=";

/// Nicknames are capped at this many characters (sidebar/private-room
/// labels also show each user's encryption method after the name, so a
/// long nickname would crowd that out fast). The same cap the server's
/// users registry applies (`validation::NICKNAME_MAX_LEN`).
pub const NICKNAME_MAX_LEN: usize = crate::validation::NICKNAME_MAX_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Host,
    Port,
    Nickname,
    Password,
    /// Only read by Register; Connect ignores it. Not in the focus order
    /// at all unless `ConnectPopupState::registration_available` is true.
    Email,
    MyKeyValuePub,
    MyKeyValuePriv,
    Connect,
    /// Not in the focus order unless `ConnectPopupState::registration_available`.
    Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrowserTarget {
    MyKeyFilePub,
    MyKeyFilePriv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Cancel,
    Connect(ConnectRequest),
    Register(RegisterRequest),
}

/// What `run` comes back with: the popup never returns `Action::None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    Cancel,
    Connect(ConnectRequest),
    Register(RegisterRequest),
}

pub struct ConnectPopupState {
    pub host: String,
    pub port: String,
    pub nickname: String,
    /// The nickname's password on this server (docs/PROTOCOL.md §5.1).
    /// Rendered as asterisks, never remembered between runs.
    pub password: String,
    /// Where a registration's activation code should go (§5.3). Needed
    /// by Register only; Connect never reads it.
    pub email: String,
    /// Dial over TLS (§1.4). Not a popup field at all - like `server_ssl`
    /// on the server side, this is settings-only (`connect_ssl` in
    /// `~/.aloo/settings`); captured once when the popup opens and carried
    /// silently into the built request, the same way `ssl_ca` already is.
    pub ssl: bool,
    /// Whether this server takes registrations at all
    /// (`server_allow_registration`), captured once from local settings
    /// when the popup opens - the email field and the Register button are
    /// only shown, and only focusable, while this is true.
    pub registration_available: bool,
    pub my_key: MyKeyFields,
    /// The `ALOO_HOME` this process actually resolved
    /// (`crate::platform::aloo_dir`) - every local store lives under it,
    /// and running two clients on one machine means giving each its own.
    /// Shown read-only above the buttons so it is visible at the moment
    /// it matters, rather than only in `Ctrl+H` and the README. Captured
    /// once when the popup opens: a field, not a call at render time, so
    /// the rendering stays a pure function of this state.
    pub aloo_home: String,
    pub focus: Field,
    pub browser: Option<(FileBrowserTarget, FileBrowserState)>,
    pub error: Option<String>,
    /// A non-error message for the hint line - "registered, check your
    /// email" - shown in green where an error would be red. An error set
    /// later replaces it.
    pub notice: Option<String>,
}

impl Default for ConnectPopupState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectPopupState {
    pub fn new() -> Self {
        Self {
            host: String::new(),
            port: String::new(),
            nickname: String::new(),
            password: String::new(),
            email: String::new(),
            ssl: false,
            registration_available: false,
            my_key: MyKeyFields::default(),
            aloo_home: crate::platform::aloo_dir().display().to_string(),
            focus: Field::Host,
            browser: None,
            error: None,
            notice: None,
        }
    }

    /// Every focusable field, in Tab order. `email`/`Register` only appear
    /// while `registration_available` is true - otherwise this server
    /// takes no registrations, so there is nothing for either to do.
    pub fn focus_order(&self) -> Vec<Field> {
        let mut order = vec![
            Field::Host,
            Field::Port,
            Field::Nickname,
            Field::Password,
        ];
        if self.registration_available {
            order.push(Field::Email);
        }
        order.push(Field::MyKeyValuePub);
        order.push(Field::MyKeyValuePriv);
        order.push(Field::Connect);
        if self.registration_available {
            order.push(Field::Register);
        }
        order
    }

    pub fn focus_next(&mut self) {
        let order = self.focus_order();
        let idx = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        self.focus = order[(idx + 1) % order.len()];
    }

    pub fn focus_prev(&mut self) {
        let order = self.focus_order();
        let idx = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        self.focus = order[(idx + order.len() - 1) % order.len()];
    }

    /// Handles one key event. Touches the filesystem only when it opens or
    /// navigates the file browser.
    pub fn handle_key(&mut self, code: KeyCode) -> io::Result<Action> {
        if self.browser.is_some() {
            return self.handle_browser_key(code);
        }
        match code {
            KeyCode::Tab => {
                self.focus_next();
                Ok(Action::None)
            }
            KeyCode::BackTab => {
                self.focus_prev();
                Ok(Action::None)
            }
            KeyCode::Esc => Ok(Action::Cancel),
            KeyCode::Enter => self.activate_focused(),
            KeyCode::Backspace => {
                self.backspace_focused();
                Ok(Action::None)
            }
            KeyCode::Char(c) => {
                self.push_char_focused(c);
                Ok(Action::None)
            }
            _ => Ok(Action::None),
        }
    }

    fn activate_focused(&mut self) -> io::Result<Action> {
        match self.focus {
            Field::MyKeyValuePub => self.open_browser(FileBrowserTarget::MyKeyFilePub),
            Field::MyKeyValuePriv => self.open_browser(FileBrowserTarget::MyKeyFilePriv),
            Field::Connect => match self.build_request() {
                Ok(req) => Ok(Action::Connect(req)),
                Err(e) => {
                    self.error = Some(e);
                    Ok(Action::None)
                }
            },
            Field::Register => match self.build_register_request() {
                Ok(req) => Ok(Action::Register(req)),
                Err(e) => {
                    self.error = Some(e);
                    Ok(Action::None)
                }
            },
            _ => Ok(Action::None),
        }
    }

    fn open_browser(&mut self, target: FileBrowserTarget) -> io::Result<Action> {
        let start = std::env::current_dir()?;
        let browser = FileBrowserState::open(start)?;
        self.browser = Some((target, browser));
        Ok(Action::None)
    }

    fn handle_browser_key(&mut self, code: KeyCode) -> io::Result<Action> {
        let Some((target, browser)) = self.browser.as_mut() else {
            return Ok(Action::None);
        };
        match code {
            KeyCode::Up => {
                browser.select_prev();
                Ok(Action::None)
            }
            KeyCode::Down => {
                browser.select_next();
                Ok(Action::None)
            }
            KeyCode::Left => {
                browser.go_back()?;
                Ok(Action::None)
            }
            KeyCode::Right => {
                browser.go_forward()?;
                Ok(Action::None)
            }
            KeyCode::Esc => {
                self.browser = None;
                Ok(Action::None)
            }
            KeyCode::Enter => {
                let Some(entry) = browser.selected_entry() else {
                    return Ok(Action::None);
                };
                if entry.is_dir {
                    browser.navigate_into_selected()?;
                    Ok(Action::None)
                } else {
                    let path = browser.selected_path().expect("file entry has a path");
                    let target = *target;
                    self.apply_selected_file(target, path);
                    self.browser = None;
                    Ok(Action::None)
                }
            }
            _ => Ok(Action::None),
        }
    }

    fn apply_selected_file(&mut self, target: FileBrowserTarget, path: PathBuf) {
        let s = path.display().to_string();
        match target {
            FileBrowserTarget::MyKeyFilePub => self.my_key.file_pub = s,
            FileBrowserTarget::MyKeyFilePriv => self.my_key.file_priv = s,
        }
    }

    fn backspace_focused(&mut self) {
        match self.focus {
            Field::Host => {
                self.host.pop();
            }
            Field::Port => {
                self.port.pop();
            }
            Field::Nickname => {
                self.nickname.pop();
            }
            Field::Password => {
                self.password.pop();
            }
            Field::Email => {
                self.email.pop();
            }
            _ => {}
        }
    }

    fn push_char_focused(&mut self, c: char) {
        match self.focus {
            Field::Host => self.host.push(c),
            Field::Port if c.is_ascii_digit() => self.port.push(c),
            Field::Nickname
                if !c.is_whitespace() && self.nickname.chars().count() < NICKNAME_MAX_LEN =>
            {
                self.nickname.push(c)
            }
            Field::Password => self.password.push(c),
            Field::Email if !c.is_whitespace() => self.email.push(c),
            _ => {}
        }
    }

    /// The host/port/nickname/password checks Connect and Register share.
    fn validate_common(&self) -> Result<u16, String> {
        if self.host.trim().is_empty() {
            return Err("host is required".to_string());
        }
        let port: u16 = self
            .port
            .parse()
            .map_err(|_| "port must be a number 1-65535".to_string())?;
        if port == 0 {
            return Err("port must be nonzero".to_string());
        }
        if self.nickname.trim().is_empty() {
            return Err("nickname is required".to_string());
        }
        if self.password.is_empty() {
            return Err("password is required".to_string());
        }
        Ok(port)
    }

    pub fn build_request(&self) -> Result<ConnectRequest, String> {
        let port = self.validate_common()?;
        if self.my_key.file_pub.is_empty() || self.my_key.file_priv.is_empty() {
            return Err("my_key file_pub and file_priv are both required".to_string());
        }
        let my_key = MyKeySelection {
            file_pub: PathBuf::from(&self.my_key.file_pub),
            file_priv: PathBuf::from(&self.my_key.file_priv),
        };

        Ok(ConnectRequest {
            host: self.host.clone(),
            port,
            ssl: self.ssl,
            ssl_ca: None,
            nickname: self.nickname.clone(),
            password: self.password.clone(),
            my_key,
            activation_code: None,
        })
    }

    /// Register needs everything Connect does except the keybundle, plus
    /// a plausible email to send the activation code to.
    pub fn build_register_request(&self) -> Result<RegisterRequest, String> {
        let port = self.validate_common()?;
        if self.email.trim().is_empty() {
            return Err("email is required to register".to_string());
        }
        if !crate::validation::email_is_plausible(self.email.trim()) {
            return Err("that does not look like an email address".to_string());
        }
        if !crate::validation::nickname_is_registrable(&self.nickname) {
            return Err(format!(
                "a nickname is 1-{NICKNAME_MAX_LEN} letters, digits, '-' or '_'"
            ));
        }
        Ok(RegisterRequest {
            host: self.host.clone(),
            port,
            ssl: self.ssl,
            ssl_ca: None,
            nickname: self.nickname.clone(),
            password: self.password.clone(),
            email: self.email.trim().to_string(),
        })
    }
}

// ---------------------------------------------------------------------
// Activation popup
// ---------------------------------------------------------------------

/// Activation codes are this many digits
/// (`crate::server::users_registry::ACTIVATION_CODE_LEN`).
pub const ACTIVATION_CODE_LEN: usize = crate::server::users_registry::ACTIVATION_CODE_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationAction {
    None,
    Cancel,
    Submit(String),
}

/// The popup a first login into an unactivated account opens
/// (docs/PROTOCOL.md §5.2): one box for the code from the email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationPopupState {
    pub nickname: String,
    pub code: String,
    pub error: Option<String>,
}

impl ActivationPopupState {
    pub fn new(nickname: &str) -> Self {
        Self {
            nickname: nickname.to_string(),
            code: String::new(),
            error: None,
        }
    }

    /// Digits only, up to `ACTIVATION_CODE_LEN` of them; Enter submits a
    /// complete code, Esc gives up.
    pub fn handle_key(&mut self, code: KeyCode) -> ActivationAction {
        match code {
            KeyCode::Esc => ActivationAction::Cancel,
            KeyCode::Enter => {
                if self.code.len() == ACTIVATION_CODE_LEN {
                    ActivationAction::Submit(self.code.clone())
                } else {
                    self.error = Some(format!(
                        "the activation code is {ACTIVATION_CODE_LEN} digits"
                    ));
                    ActivationAction::None
                }
            }
            KeyCode::Backspace => {
                self.code.pop();
                ActivationAction::None
            }
            KeyCode::Char(c) if c.is_ascii_digit() && self.code.len() < ACTIVATION_CODE_LEN => {
                self.code.push(c);
                ActivationAction::None
            }
            _ => ActivationAction::None,
        }
    }
}

/// Drives the activation popup: `Some(code)` to try, `None` if the user
/// gave up.
pub fn run_activation(
    surface: &mut super::surface::Surface,
    popup: &mut ActivationPopupState,
) -> Result<Option<String>, crate::BoxError> {
    loop {
        surface.draw(|f| render_activation(f, popup))?;
        let key = match crossterm::event::read()? {
            Event::Key(key) => key,
            Event::Resize(cols, rows) => {
                surface.resize(super::surface::TerminalSize::new(cols, rows))?;
                continue;
            }
            _ => continue,
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match popup.handle_key(key.code) {
            ActivationAction::Submit(code) => return Ok(Some(code)),
            ActivationAction::Cancel => return Ok(None),
            ActivationAction::None => {}
        }
    }
}

pub fn render_activation(frame: &mut Frame, state: &ActivationPopupState) {
    let area = frame.area();
    let popup = centered_rect(60, 9, area);
    let block = Block::default()
        .title("Activate your account")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // explanation
            Constraint::Length(3), // code box
            Constraint::Min(1),    // error / hint
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(format!(
            "{} is registered but not activated yet. Enter the {ACTIVATION_CODE_LEN}-digit code from the activation email.",
            state.nickname
        )),
        chunks[0],
    );
    let code_inner = render_bordered_field(frame, chunks[1], "activation code", &state.code, true);
    place_text_cursor(frame, code_inner, 0, &state.code);
    let (hint, style) = match &state.error {
        Some(e) => (e.clone(), Style::default().fg(Color::Red)),
        None => (
            "Enter: activate  Esc: cancel".to_string(),
            Style::default().fg(Color::DarkGray),
        ),
    };
    frame.render_widget(Paragraph::new(hint).style(style), chunks[2]);
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

fn key_field_line(label: &str, value: &str, focused: bool) -> Line<'static> {
    let style = if focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(value.to_string(), style),
    ])
}

/// Renders `value` in its own titled, bordered box - used for the
/// top-level `host`/`port`/`nickname` inputs (SPEC.md: "styled with a
/// border around the box"). Returns the box's inner `Rect`, which the
/// caller uses to place the text cursor when this field is focused.
fn render_bordered_field(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    value: &str,
    focused: bool,
) -> Rect {
    let block = Block::default()
        .title(label)
        .borders(Borders::ALL)
        .border_style(focus_border_style(focused));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(value), inner);
    inner
}

/// Places the blinking terminal cursor at the end of the currently typed
/// text in `inner`, `offset` columns in (non-zero for the `server_key`
/// password field, which shares its line with a `"value: "` label rather
/// than living in its own bordered box) - mirroring
/// `ui::render_input_bar`'s cursor logic. Without this, a focused text
/// field only *looks* focused (reversed value) but never actually shows
/// where typing lands.
fn place_text_cursor(frame: &mut Frame, inner: Rect, offset: u16, value: &str) {
    let cursor_x =
        inner.x + (offset + value.chars().count() as u16).min(inner.width.saturating_sub(1));
    frame.set_cursor_position((cursor_x, inner.y));
}

/// Drives the popup to completion: render, block on the next key event,
/// dispatch to `ConnectPopupState::handle_key`, repeat - until the user
/// either submits a complete request (Connect or Register) or cancels.
pub fn run(
    surface: &mut super::surface::Surface,
    popup: &mut ConnectPopupState,
) -> Result<Submission, crate::BoxError> {
    loop {
        surface.draw(|f| render(f, popup))?;
        let key = match crossterm::event::read()? {
            Event::Key(key) => key,
            // Same handling the connected session gives its own resize
            // (`session::run_connected_session`): discard the buffer laid
            // out for the old size, so the redraw at the top of the next
            // iteration repaints every cell rather than diffing against a
            // window that no longer exists.
            Event::Resize(cols, rows) => {
                surface.resize(super::surface::TerminalSize::new(cols, rows))?;
                continue;
            }
            _ => continue,
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match popup.handle_key(key.code)? {
            Action::Connect(req) => return Ok(Submission::Connect(req)),
            Action::Register(req) => return Ok(Submission::Register(req)),
            Action::Cancel => return Ok(Submission::Cancel),
            Action::None => {}
        }
    }
}

pub fn render(frame: &mut Frame, state: &ConnectPopupState) {
    let area = frame.area();
    let popup = centered_rect(64, 30, area);
    let block = Block::default().title("Connect").borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // Built up rather than a fixed-length array: the email field only
    // takes a row while `registration_available` (there is nothing for it
    // to do on a server that takes no registrations), and every index
    // used below is recorded as it's pushed so the two can never drift
    // apart.
    let mut constraints = vec![
        Constraint::Length(3), // host
        Constraint::Length(3), // port
        Constraint::Length(3), // nickname
        Constraint::Length(3), // password
    ];
    let email_idx = state.registration_available.then(|| {
        constraints.push(Constraint::Length(3)); // email
        constraints.len() - 1
    });
    constraints.push(Constraint::Length(1)); // spacer
    constraints.push(Constraint::Length(4)); // my_key group
    let my_key_idx = constraints.len() - 1;
    constraints.push(Constraint::Length(1)); // spacer
    constraints.push(Constraint::Length(1)); // blank line above ALOO_HOME
    constraints.push(Constraint::Length(1)); // ALOO_HOME
    let aloo_home_idx = constraints.len() - 1;
    constraints.push(Constraint::Length(1)); // blank line below ALOO_HOME
    constraints.push(Constraint::Length(3)); // buttons
    let buttons_idx = constraints.len() - 1;
    constraints.push(Constraint::Min(1)); // error / hint
    let hint_idx = constraints.len() - 1;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let host_inner = render_bordered_field(
        frame,
        chunks[0],
        "host",
        &state.host,
        state.focus == Field::Host,
    );
    let port_inner = render_bordered_field(
        frame,
        chunks[1],
        "port",
        &state.port,
        state.focus == Field::Port,
    );
    let nickname_inner = render_bordered_field(
        frame,
        chunks[2],
        "nickname",
        &state.nickname,
        state.focus == Field::Nickname,
    );
    let password_masked = "*".repeat(state.password.chars().count());
    let password_inner = render_bordered_field(
        frame,
        chunks[3],
        "password",
        &password_masked,
        state.focus == Field::Password,
    );
    let email_inner = email_idx.map(|i| {
        render_bordered_field(
            frame,
            chunks[i],
            "email (to register)",
            &state.email,
            state.focus == Field::Email,
        )
    });

    // The group's title names the one scheme there is rather than
    // spending a row on a selector that can only ever say `pq_hybrid`.
    let my_key_block = Block::default()
        .title("my_key (pq_hybrid)")
        .borders(Borders::ALL);
    let my_key_inner = my_key_block.inner(chunks[my_key_idx]);
    frame.render_widget(my_key_block, chunks[my_key_idx]);
    let my_key_lines = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(my_key_inner);
    let pub_display = if state.my_key.file_pub.is_empty() {
        "<press Enter to browse>".to_string()
    } else {
        state.my_key.file_pub.clone()
    };
    let priv_display = if state.my_key.file_priv.is_empty() {
        "<press Enter to browse>".to_string()
    } else {
        state.my_key.file_priv.clone()
    };
    frame.render_widget(
        Paragraph::new(key_field_line(
            "file_pub",
            &pub_display,
            state.focus == Field::MyKeyValuePub,
        )),
        my_key_lines[0],
    );
    frame.render_widget(
        Paragraph::new(key_field_line(
            "file_priv",
            &priv_display,
            state.focus == Field::MyKeyValuePriv,
        )),
        my_key_lines[1],
    );

    // The cursor always follows whichever text field currently has focus,
    // starting on `host` the moment the popup opens (its default focus).
    match state.focus {
        Field::Host => place_text_cursor(frame, host_inner, 0, &state.host),
        Field::Port => place_text_cursor(frame, port_inner, 0, &state.port),
        Field::Nickname => place_text_cursor(frame, nickname_inner, 0, &state.nickname),
        Field::Password => place_text_cursor(frame, password_inner, 0, &password_masked),
        Field::Email => {
            if let Some(email_inner) = email_inner {
                place_text_cursor(frame, email_inner, 0, &state.email);
            }
        }
        _ => {}
    }

    // Read-only, gray so it reads as a note about where this client's
    // local state lives rather than as another thing to fill in, and
    // centered with a blank line of its own above and below so it reads
    // as a note set apart from the form rather than crowding the buttons.
    frame.render_widget(
        Paragraph::new(format!("{ALOO_HOME_LABEL}{}", state.aloo_home))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center),
        chunks[aloo_home_idx],
    );

    if state.registration_available {
        let buttons = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[buttons_idx]);
        render_button(frame, buttons[0], "Connect", state.focus == Field::Connect);
        render_button(frame, buttons[1], "Register", state.focus == Field::Register);
    } else {
        render_button(frame, chunks[buttons_idx], "Connect", state.focus == Field::Connect);
    }

    let (hint, hint_style) = match (&state.error, &state.notice) {
        (Some(error), _) => (error.clone(), Style::default().fg(Color::Red)),
        (None, Some(notice)) => (notice.clone(), Style::default().fg(Color::Green)),
        (None, None) => (
            "Tab: next field  Enter: select/connect  Esc: quit".to_string(),
            Style::default().fg(Color::DarkGray),
        ),
    };
    frame.render_widget(
        Paragraph::new(hint)
            .style(hint_style)
            .alignment(Alignment::Center),
        chunks[hint_idx],
    );

    if let Some((_, browser)) = &state.browser {
        render_file_browser(frame, area, browser, "Select file");
    }
}

/// One of the two buttons under the form - Connect, Register - centered
/// in `area`.
fn render_button(frame: &mut Frame, area: Rect, label: &str, focused: bool) {
    // The border and the highlight are rendered as two separate widgets on
    // purpose: the border (block) always keeps its own plain/yellow-focus
    // style, and only the *inner* area gets the solid highlight fill when
    // focused - so the highlight stays inside the button, with the border
    // visible around the outside of it rather than swallowed into it.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_border_style(focused));
    let text_style = if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };
    // a fixed, modest width keeps it looking like a button rather than a
    // full-width bar, centered in its half of the row
    let width = 14.min(area.width);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let button_area = Rect {
        x,
        y: area.y,
        width,
        height: area.height,
    };
    let inner = block.inner(button_area);
    frame.render_widget(block, button_area);
    frame.render_widget(
        Paragraph::new(label)
            .alignment(Alignment::Center)
            .style(text_style),
        inner,
    );
}
