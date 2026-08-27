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
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Widget, Wrap};

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
    /// on the server side, this is settings-only (`connect_using_ssl` in
    /// `~/.aloo/settings`, the same one setting a daemon start reads too);
    /// captured once when the popup opens and carried silently into the
    /// built request, the same way `ssl_ca` already is.
    pub ssl: bool,
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
    /// Advances by one every animation tick (`run`'s event-poll timeout,
    /// not a key press), purely to drive `DigitalRain`'s background
    /// animation - has no bearing on anything else, and wraps rather than
    /// ever needing to be bounded.
    pub animation_frame: u64,
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
            my_key: MyKeyFields::default(),
            aloo_home: crate::platform::aloo_dir().display().to_string(),
            focus: Field::Host,
            error: None,
            notice: None,
            animation_frame: 0,
        }
    }

    /// Every focusable field, in Tab order. `email`/`Register` are always
    /// included, on every server - whether registration is actually open
    /// is the server's answer to the `Register` attempt itself, not
    /// something this form hides fields over.
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
    /// a plausible email to send the activation code to. Whether *this*
    /// server actually takes registrations is deliberately not checked
    /// here: `server_allow_registration` lives in `~/.aloo/settings` on
    /// whichever machine runs `--server`, which has nothing to do with
    /// the machine running this popup - the two are almost always
    /// different computers. The server's `Hello.registration_open`
    /// (`crate::client::connect::register_account`) is the only thing
    /// that actually knows the answer, so this only validates the form's
    /// own fields and lets the real attempt fail server-side when it must.
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
/// (docs/PROTOCOL.md §5.2), and the popup a successful Register opens
/// directly: one box for the code from the email. The two paths differ
/// only in `message` - `new` explains why the popup appeared (a login was
/// refused), `new_after_registration` doesn't need to, since the user just
/// registered and knows why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationPopupState {
    pub nickname: String,
    pub code: String,
    pub error: Option<String>,
    pub message: String,
}

impl ActivationPopupState {
    pub fn new(nickname: &str) -> Self {
        Self {
            nickname: nickname.to_string(),
            code: String::new(),
            error: None,
            message: format!(
                "{nickname} is registered but not activated yet. Enter the \
                 {ACTIVATION_CODE_LEN}-digit code from the activation email."
            ),
        }
    }

    /// Opened the instant Register succeeds (`connect.rs`'s
    /// `Submission::Register` handling) - the user just submitted the
    /// registration form, so the popup states the ask plainly rather than
    /// re-explaining that the account isn't activated yet.
    pub fn new_after_registration(nickname: &str) -> Self {
        Self {
            nickname: nickname.to_string(),
            code: String::new(),
            error: None,
            message: "Enter the activation code you received by email".to_string(),
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
            // A pasted code, fed through the same per-character path a
            // typed one takes - `handle_key` already only keeps digits up
            // to `ACTIVATION_CODE_LEN`, so anything else pasted alongside
            // it (whitespace, a trailing newline) is simply ignored.
            Event::Paste(text) => {
                for c in text.chars() {
                    match popup.handle_key(KeyCode::Char(c)) {
                        ActivationAction::Submit(code) => return Ok(Some(code)),
                        ActivationAction::Cancel => return Ok(None),
                        ActivationAction::None => {}
                    }
                }
                continue;
            }
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
    frame.render_widget(Paragraph::new(state.message.clone()), chunks[0]);
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

/// How long `run` waits for a real event before giving up and advancing
/// the background animation by one frame instead - short enough that
/// `DigitalRain` reads as continuous motion, long enough not to burn CPU
/// redrawing an idle screen needlessly. Slightly longer than a snappier
/// tick would use, since a slower-paced fall (combined with
/// `DigitalRain`'s own reduced per-tick row speed) reads calmer.
pub(crate) const ANIMATION_TICK: std::time::Duration = std::time::Duration::from_millis(110);

/// Drives the popup to completion: render, wait for the next key event or
/// `ANIMATION_TICK` (whichever comes first - a timeout just advances
/// `animation_frame` and redraws, so the background animation moves even
/// with nobody touching a key), dispatch to `ConnectPopupState::handle_key`,
/// repeat - until the user either submits a complete request (Connect or
/// Register) or cancels.
pub fn run(
    surface: &mut super::surface::Surface,
    popup: &mut ConnectPopupState,
) -> Result<Submission, crate::BoxError> {
    loop {
        surface.draw(|f| render(f, popup))?;
        if !crossterm::event::poll(ANIMATION_TICK)? {
            popup.animation_frame = popup.animation_frame.wrapping_add(1);
            continue;
        }
        let key = match crossterm::event::read()? {
            Event::Key(key) => key,
            // A whole paste, delivered atomically by the bracketed-paste-
            // enabled terminal (`tui::terminal::setup`) - fed through the
            // same per-character path a real keystroke takes, into
            // whichever field currently has focus, so a pasted password
            // or hostname lands exactly like typing it would. Embedded
            // line breaks are dropped: every field here is single-line.
            Event::Paste(text) => {
                for c in text.chars().filter(|c| *c != '\n' && *c != '\r') {
                    match popup.handle_key(KeyCode::Char(c))? {
                        Action::Connect(req) => return Ok(Submission::Connect(req)),
                        Action::Register(req) => return Ok(Submission::Register(req)),
                        Action::Cancel => return Ok(Submission::Cancel),
                        Action::None => {}
                    }
                }
                continue;
            }
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
    // A one-line title strip above the modal itself, not inside its
    // border - a blank row of actual terminal space separates the two, so
    // this reads as a banner the popup sits under rather than a squeezed
    // extra header row. Skipped rather than underflowing/panicking if the
    // terminal is too short to fit both above the popup.
    let version_rect =
        (popup.y >= 2).then(|| Rect { x: popup.x, y: popup.y - 2, width: popup.width, height: 1 });
    // Drawn first, everything else on top of it. `popup` itself is
    // excluded outright rather than relied on to be overwritten: several
    // rows inside it (the spacer lines, the blank line around the
    // read-only info block) are never painted by any other widget, so
    // anything drawn under them would otherwise show straight through.
    // `version_rect` (padded 2 cells every direction) is excluded the
    // same way, since it sits outside the popup with nothing else to
    // cover it either.
    frame.render_widget(
        DigitalRain {
            frame: state.animation_frame,
            avoid_popup: popup,
            keep_clear: version_rect.map(|r| padded(r, 2, area)),
        },
        area,
    );
    if let Some(version_rect) = version_rect {
        frame.render_widget(
            Paragraph::new(format!("aloo {} - secure link", env!("CARGO_PKG_VERSION")))
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center),
            version_rect,
        );
    }
    let block = Block::default().title("Connect").borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // A fixed layout - the email field and both buttons are always on
    // screen, on every server: whether registration is actually open is
    // for the server to answer when Register is pressed, not something
    // this form knows in advance.
    let constraints = [
        Constraint::Length(3), // host + port (same row)
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
        Constraint::Min(0),    // flexible spacer - absorbs whatever room is left, so
                                // the hint row below lands flush on the popup's last
                                // line instead of floating right under the buttons
        // 3 rows and wrapped (below): an SSL-mismatch diagnosis
        // (`with_ssl_diagnosis`) composes the connect failure with a
        // second sentence naming the exact setting to flip, easily past
        // 100 characters - one unwrapped row silently clipped it.
        Constraint::Length(3), // error / hint
    ];
    let email_idx = 3;
    let file_pub_idx = 6;
    let file_priv_idx = 7;
    let aloo_home_idx = 8;
    let buttons_idx = 10;
    let hint_idx = 12;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // Port never needs more than 6 columns (`65535` plus a spare digit),
    // so it takes a fixed-width slice on the right of the shared row and
    // host gets whatever's left rather than the usual full-width field.
    let host_port_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(10), Constraint::Length(8)])
        .split(chunks[0]);
    let host_inner = render_bordered_field(
        frame,
        host_port_cols[0],
        "host",
        &state.host,
        state.focus == Field::Host,
    );
    let port_inner = render_bordered_field(
        frame,
        host_port_cols[1],
        "port",
        &state.port,
        state.focus == Field::Port,
    );
    let nickname_inner = render_bordered_field(
        frame,
        chunks[1],
        "nickname",
        &state.nickname,
        state.focus == Field::Nickname,
    );
    let password_masked = "*".repeat(state.password.chars().count());
    let password_inner = render_bordered_field(
        frame,
        chunks[2],
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
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        chunks[hint_idx],
    );
}

/// `render_processing`'s clearing around `label` on every side - blank
/// rows above and below, blank columns left and right, with no rain drawn
/// through any of it at all. 3 cells each direction.
const PROCESSING_PAD: u16 = 3;

/// The screen shown in place of `render` while a `Connect`/`Register`
/// attempt is actually in flight (`connect::run_with_processing_screen`):
/// the popup and version title are hidden entirely - there is nothing
/// left to edit or read while the network is being waited on - but the
/// background animation keeps running exactly as it does behind the
/// popup, so the screen never simply freezes on its last frame for
/// however long the round-trip takes. A single centered line naming
/// what's happening, in the same yellow the version banner already uses
/// for status-adjacent text, surrounded by `PROCESSING_PAD` blank
/// rows/columns on every side where `DigitalRain` draws nothing at all.
/// `connect::run_with_processing_screen`'s two call sites each pass
/// their own label ("connecting..." / "one moment...").
pub fn render_processing(frame: &mut Frame, animation_frame: u64, label: &str) {
    let area = frame.area();
    let label_width = label.chars().count() as u16;
    let clearing = centered_rect(
        label_width.saturating_add(PROCESSING_PAD * 2),
        1 + PROCESSING_PAD * 2,
        area,
    );
    frame.render_widget(
        DigitalRain { frame: animation_frame, avoid_popup: clearing, keep_clear: None },
        area,
    );
    if clearing.height == 0 {
        return;
    }
    let row = Rect {
        x: clearing.x,
        y: clearing.y + (clearing.height / 2),
        width: clearing.width,
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(label)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center),
        row,
    );
}

/// `r` expanded by `margin` cells on every side, clamped to stay inside
/// `bounds` - used to carve a no-draw zone around the version banner
/// wider than the banner's own text so `DigitalRain` never crowds it.
fn padded(r: Rect, margin: u16, bounds: Rect) -> Rect {
    let x = r.x.saturating_sub(margin).max(bounds.x);
    let y = r.y.saturating_sub(margin).max(bounds.y);
    let right = (r.x + r.width + margin).min(bounds.x + bounds.width);
    let bottom = (r.y + r.height + margin).min(bounds.y + bounds.height);
    Rect {
        x,
        y,
        width: right.saturating_sub(x),
        height: bottom.saturating_sub(y),
    }
}

/// A dense "digital rain" animation filling the screen behind the
/// connect popup - purely decorative, themed to "secure link" the same
/// way the version banner above the popup is. Reads `frame` (advanced
/// once per tick by `run`'s event-poll timeout, not by a key press, so it
/// moves on its own) and draws nothing inside `keep_clear`, which
/// `render` sets to the version banner's own area padded 2 cells wider on
/// every side. Every column always carries a falling trail (below), and
/// - unlike a plainer rain effect where everything *not* falling is
/// blank - the cells between trails are their own sparse, independently
/// flickering field of `0`/`1` glyphs, closer to a real "matrix screen"
/// than falling streaks over empty space.
struct DigitalRain {
    frame: u64,
    /// The popup's own footprint - excluded outright, not just relied on
    /// to be painted over, since several rows inside it are never touched
    /// by any other widget (see `render`'s call site).
    avoid_popup: Rect,
    keep_clear: Option<Rect>,
}

impl DigitalRain {
    /// How many rows a column's falling trail spans, brightest at the
    /// head and fading out over the rest - longer than a sparser rain
    /// effect would use, so more of each column is lit at any given
    /// moment.
    const TRAIL_LEN: i64 = 10;
    /// How many ticks a background glyph (outside every column's active
    /// trail) holds its state before a fresh hash decides its next one -
    /// independent per cell, not tied to any column's falling head, so
    /// the background flickers on its own rather than merely trailing
    /// the streaks. Small enough to read as "alive," large enough not to
    /// strobe.
    const BACKGROUND_FLICKER_TICKS: u64 = 6;
    /// 1-in-this-many background cells (outside a trail) is lit on a
    /// given flicker tick - sparse enough that the falling trails still
    /// read as the main motion, dense enough that the background is
    /// visibly textured rather than empty.
    const BACKGROUND_DENSITY: u64 = 5;
    /// How many ticks a column's own fall speed and trail length hold
    /// steady before a fresh hash reseeds them - each column staggered by
    /// its own offset (`render`'s `stagger`) so columns reseed at
    /// different times instead of every one twitching together on the
    /// same tick. Keeps every column's rhythm drifting over time instead
    /// of settling into one fixed, spottable loop.
    const RESEED_PERIOD: u64 = 45;

    fn in_rect(r: Rect, x: u16, y: u16) -> bool {
        x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height
    }

    fn excluded(&self, x: u16, y: u16) -> bool {
        Self::in_rect(self.avoid_popup, x, y) || self.keep_clear.is_some_and(|r| Self::in_rect(r, x, y))
    }

    /// A cheap but well-mixed hash (SplitMix64's own finalizer), not real
    /// randomness - decoration has no need for a `rand` call, and a
    /// deterministic pattern renders identically for the same `frame`,
    /// which is what makes this paintable in a test. The three
    /// xor-shift/multiply rounds give every output bit, low ones
    /// included, a genuine avalanche from every input bit, so two
    /// adjacent `x` (or `x`, `epoch`) values land nowhere near each
    /// other - neighbouring columns end up with independent-looking fall
    /// speeds and phases rather than any visible correlation with `x`.
    fn hash(n: u64) -> u64 {
        let mut n = n.wrapping_add(0x9E37_79B9_7F4A_7C15);
        n = (n ^ (n >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        n = (n ^ (n >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        n ^ (n >> 31)
    }

    /// One independently-flickering background glyph, or `None` for a
    /// cell that happens to be dark this tick - checked only for cells a
    /// column's own falling trail doesn't already cover.
    fn background_glyph(&self, x: u16, y: u16) -> Option<char> {
        let epoch = self.frame / Self::BACKGROUND_FLICKER_TICKS;
        let h = Self::hash((x as u64).wrapping_mul(97).wrapping_add((y as u64).wrapping_mul(31)).wrapping_add(epoch));
        if h % Self::BACKGROUND_DENSITY != 0 {
            return None;
        }
        Some(if (h / Self::BACKGROUND_DENSITY) % 2 == 0 { '0' } else { '1' })
    }
}

impl Widget for DigitalRain {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        for x in area.left()..area.right() {
            // Staggered per column (`stagger`, 0..RESEED_PERIOD) so every
            // column reseeds its own speed/trail length at its own tick
            // rather than the whole screen twitching in sync every
            // RESEED_PERIOD ticks.
            let stagger = Self::hash(x as u64) % Self::RESEED_PERIOD;
            let epoch = (self.frame + stagger) / Self::RESEED_PERIOD;
            let seed = Self::hash((x as u64).wrapping_mul(97).wrapping_add(epoch.wrapping_mul(7_919)));
            let speed = 1 + (seed % 2) as i64; // rows per tick, 1..=2 - a bit slower than a faster rain would use
            let phase = (seed / 2 % 251) as i64;
            let trail_len = Self::TRAIL_LEN - 2 + ((seed / 253) % 5) as i64; // 8..=12, varies per reseed
            let cycle = area.height as i64 + trail_len;
            let head = (self.frame as i64 * speed + phase).rem_euclid(cycle) - trail_len;
            for y in area.top()..area.bottom() {
                if self.excluded(x, y) {
                    continue;
                }
                let dist = head - (y - area.top()) as i64;
                if !(0..trail_len).contains(&dist) {
                    if let Some(glyph) = self.background_glyph(x, y) {
                        buf.set_string(
                            x,
                            y,
                            glyph.to_string(),
                            Style::default().fg(Color::Green).add_modifier(Modifier::DIM),
                        );
                    }
                    continue;
                }
                let glyph = if (x as i64 + dist) % 2 == 0 { '0' } else { '1' };
                let style = match dist {
                    0 => Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                    1 | 2 => Style::default().fg(Color::LightGreen),
                    _ => Style::default().fg(Color::Green).add_modifier(Modifier::DIM),
                };
                buf.set_string(x, y, glyph.to_string(), style);
            }
        }
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
