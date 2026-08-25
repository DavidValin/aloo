//! The "not connected" screen: a centered modal collecting host/port, the
//! nickname and its password, an optional email for registering, the
//! `ssl` switch and the `my_key` keybundle. Also the small activation-code
//! popup a first login into an unactivated account opens
//! (`ActivationPopupState`).
//!
//! State transitions (`ConnectPopupState::handle_key`) are plain functions
//! independent of rendering, so they're unit tested without a terminal.

use std::io;
use std::path::PathBuf;

use crossterm::event::{Event, KeyCode, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::ui::{centered_rect, focus_border_style};
use crate::client::connect::{ConnectRequest, MyKeySelection, RegisterRequest};

/// `my_key` has no type selector: `pq_hybrid` (ML-DSA-87+RSA4096 signing,
/// ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption - §13) is the
/// only peer-to-peer scheme this app has, so the group is just the two
/// keybundle files. Generated with `aloo --keygen-pq-hybrid` (no `openssl`
/// exists for ML-DSA/ML-KEM), though connecting auto-generates a missing
/// bundle (`crypto::pq::ensure_bundle_at`), so no manual step is required.
/// Never editable from this popup - shown read-only, alongside
/// `ALOO_HOME`, as information about where this client's identity
/// actually lives, not as something to fill in here.
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
    /// Only read by Register; Connect ignores it. Always in the focus
    /// order and always on screen - a server that refuses registration
    /// says so when Register is actually pressed
    /// (`build_register_request`), not by hiding the field.
    Email,
    Connect,
    Register,
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
    /// when the popup opens. The email field and the Register button are
    /// always shown and always focusable regardless - only pressing
    /// Register while this is false is refused, in red, the same way any
    /// other invalid submission is (`build_register_request`).
    pub registration_available: bool,
    /// Never editable here - shown read-only, alongside `aloo_home` below.
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
            error: None,
            notice: None,
        }
    }

    /// Every focusable field, in Tab order. `email`/`Register` are always
    /// included - `registration_available` no longer hides either; it only
    /// decides what pressing Register actually does.
    pub fn focus_order(&self) -> Vec<Field> {
        vec![
            Field::Host,
            Field::Port,
            Field::Nickname,
            Field::Password,
            Field::Email,
            Field::Connect,
            Field::Register,
        ]
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

    /// Handles one key event.
    pub fn handle_key(&mut self, code: KeyCode) -> io::Result<Action> {
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
    /// a plausible email to send the activation code to. Checked first,
    /// ahead of every field validation below: the email/Register field and
    /// button are always on screen now regardless of
    /// `registration_available` (`server_allow_registration`), so this is
    /// the one place left that actually refuses a registration this
    /// server won't accept - in red, the same as any other invalid
    /// submission, rather than a network round trip that would only fail
    /// the same way server-side.
    pub fn build_register_request(&self) -> Result<RegisterRequest, String> {
        if !self.registration_available {
            return Err("this server does not accept registrations right now".to_string());
        }
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

    // A fixed layout now - the email field and both buttons are always on
    // screen, regardless of `registration_available` (only pressing
    // Register on an unavailable server is refused, not the field hidden).
    let constraints = [
        Constraint::Length(3), // host
        Constraint::Length(3), // port
        Constraint::Length(3), // nickname
        Constraint::Length(3), // password
        Constraint::Length(3), // email
        Constraint::Length(1), // spacer
        Constraint::Length(1), // blank line above the read-only info block
        Constraint::Length(1), // file_pub
        Constraint::Length(1), // file_priv
        Constraint::Length(1), // ALOO_HOME
        Constraint::Length(1), // blank line below the read-only info block
        Constraint::Length(3), // buttons
        Constraint::Min(1),    // error / hint
    ];
    let email_idx = 4;
    let file_pub_idx = 7;
    let file_priv_idx = 8;
    let aloo_home_idx = 9;
    let buttons_idx = 11;
    let hint_idx = 12;

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
    let email_inner = render_bordered_field(
        frame,
        chunks[email_idx],
        "email (to register)",
        &state.email,
        state.focus == Field::Email,
    );

    // Never editable here (see `MyKeyFields`'s own doc) - shown the same
    // way as `ALOO_HOME` below: read-only, gray, information about where
    // this client's identity actually lives rather than something to fill
    // in on this screen.
    let pub_display = if state.my_key.file_pub.is_empty() {
        "(not yet generated)".to_string()
    } else {
        state.my_key.file_pub.clone()
    };
    let priv_display = if state.my_key.file_priv.is_empty() {
        "(not yet generated)".to_string()
    } else {
        state.my_key.file_priv.clone()
    };
    frame.render_widget(
        Paragraph::new(format!("file_pub: {pub_display}"))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center),
        chunks[file_pub_idx],
    );
    frame.render_widget(
        Paragraph::new(format!("file_priv: {priv_display}"))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Center),
        chunks[file_priv_idx],
    );

    // The cursor always follows whichever text field currently has focus,
    // starting on `host` the moment the popup opens (its default focus).
    match state.focus {
        Field::Host => place_text_cursor(frame, host_inner, 0, &state.host),
        Field::Port => place_text_cursor(frame, port_inner, 0, &state.port),
        Field::Nickname => place_text_cursor(frame, nickname_inner, 0, &state.nickname),
        Field::Password => place_text_cursor(frame, password_inner, 0, &password_masked),
        Field::Email => place_text_cursor(frame, email_inner, 0, &state.email),
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

    // Always both, side by side - a server that refuses registration says
    // so when Register is actually pressed (`build_register_request`),
    // not by the button being absent.
    let buttons = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[buttons_idx]);
    render_button(frame, buttons[0], "Connect", state.focus == Field::Connect);
    render_button(frame, buttons[1], "Register", state.focus == Field::Register);

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
