//! The "not connected" screen: a centered modal collecting host/port and
//! the `server_key` / `my_key` credentials, including an in-TUI file
//! browser (no OS file dialog exists in a terminal) for key files.
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
use crate::client::connect::{ConnectRequest, MyKeySelection, ServerKeySelection};
use crate::client::file_browser::FileBrowserState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    Rsa,
    Password,
    #[default]
    None,
}

impl KeyType {
    pub fn cycle_next(self) -> Self {
        match self {
            KeyType::Rsa => KeyType::Password,
            KeyType::Password => KeyType::None,
            KeyType::None => KeyType::Rsa,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyType::Rsa => "rsa",
            KeyType::Password => "password",
            KeyType::None => "none",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerKeyFields {
    pub key_type: KeyType,
    pub password: String,
    pub file: String,
}

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

/// Prefix of the read-only line above the Connect button naming the
/// directory every piece of this client's local state lives under
/// (`crate::platform::aloo_dir`). Spelled as the environment variable
/// that sets it, so the line doubles as the answer to "how do I run a
/// second client on this machine": `ALOO_HOME=/tmp/aloo-bob aloo`.
pub const ALOO_HOME_LABEL: &str = "ALOO_HOME=";

/// Nicknames are capped at this many characters (sidebar/private-room
/// labels also show each user's encryption method after the name, so a
/// long nickname would crowd that out fast).
pub const NICKNAME_MAX_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Host,
    Port,
    Nickname,
    IdStorePath,
    ServerKeyType,
    ServerKeyValue,
    MyKeyValuePub,
    MyKeyValuePriv,
    Connect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrowserTarget {
    ServerKeyFile,
    MyKeyFilePub,
    MyKeyFilePriv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Cancel,
    Connect(ConnectRequest),
}

pub struct ConnectPopupState {
    pub host: String,
    pub port: String,
    pub nickname: String,
    /// Text of the `id_store` field - the path to the local identity
    /// pinning store (`aloo::idstore`). Prefilled from
    /// `idstore::default_path()` when the popup opens, but a plain
    /// editable text field like `host`/`port`/`nickname` after that.
    pub id_store_path: String,
    pub server_key: ServerKeyFields,
    pub my_key: MyKeyFields,
    /// The `ALOO_HOME` this process actually resolved
    /// (`crate::platform::aloo_dir`) - every local store lives under it,
    /// and running two clients on one machine means giving each its own.
    /// Shown read-only above the Connect button so it is visible at the
    /// moment it matters, rather than only in `Ctrl+H` and the README.
    /// Captured once when the popup opens: a field, not a call at render
    /// time, so the rendering stays a pure function of this state.
    pub aloo_home: String,
    pub focus: Field,
    pub browser: Option<(FileBrowserTarget, FileBrowserState)>,
    pub error: Option<String>,
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
            id_store_path: crate::client::idstore::default_path().display().to_string(),
            server_key: ServerKeyFields::default(),
            my_key: MyKeyFields::default(),
            aloo_home: crate::platform::aloo_dir().display().to_string(),
            focus: Field::Host,
            browser: None,
            error: None,
        }
    }

    /// The focusable fields for the *current* `server_key` selection: its
    /// value field only appears once it's actually shown. `my_key` always
    /// contributes both of its keybundle paths - there is only one scheme,
    /// so nothing about that group is conditional.
    pub fn focus_order(&self) -> Vec<Field> {
        let mut v = vec![
            Field::Host,
            Field::Port,
            Field::Nickname,
            Field::IdStorePath,
            Field::ServerKeyType,
        ];
        if self.server_key.key_type != KeyType::None {
            v.push(Field::ServerKeyValue);
        }
        v.push(Field::MyKeyValuePub);
        v.push(Field::MyKeyValuePriv);
        v.push(Field::Connect);
        v
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
            KeyCode::Left | KeyCode::Right if self.focus == Field::ServerKeyType => {
                self.server_key.key_type = self.server_key.key_type.cycle_next();
                self.clamp_focus_after_type_change();
                Ok(Action::None)
            }
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

    /// If the field we were on just disappeared (`server_key` switched to
    /// `none` while focus was on its value), fall back to a field that's
    /// always present instead of an orphaned one.
    fn clamp_focus_after_type_change(&mut self) {
        if !self.focus_order().contains(&self.focus) {
            self.focus = Field::Connect;
        }
    }

    fn activate_focused(&mut self) -> io::Result<Action> {
        match self.focus {
            Field::ServerKeyType => {
                self.server_key.key_type = self.server_key.key_type.cycle_next();
                self.clamp_focus_after_type_change();
                Ok(Action::None)
            }
            Field::ServerKeyValue if self.server_key.key_type == KeyType::Rsa => {
                self.open_browser(FileBrowserTarget::ServerKeyFile)
            }
            Field::MyKeyValuePub => self.open_browser(FileBrowserTarget::MyKeyFilePub),
            Field::MyKeyValuePriv => self.open_browser(FileBrowserTarget::MyKeyFilePriv),
            Field::Connect => match self.build_request() {
                Ok(req) => Ok(Action::Connect(req)),
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
            FileBrowserTarget::ServerKeyFile => self.server_key.file = s,
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
            Field::IdStorePath => {
                self.id_store_path.pop();
            }
            Field::ServerKeyValue if self.server_key.key_type == KeyType::Password => {
                self.server_key.password.pop();
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
            Field::IdStorePath => self.id_store_path.push(c),
            Field::ServerKeyValue if self.server_key.key_type == KeyType::Password => {
                self.server_key.password.push(c)
            }
            _ => {}
        }
    }

    pub fn build_request(&self) -> Result<ConnectRequest, String> {
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
        if self.id_store_path.trim().is_empty() {
            return Err("id_store path is required".to_string());
        }

        let server_key = match self.server_key.key_type {
            KeyType::None => ServerKeySelection::None,
            KeyType::Password => {
                if self.server_key.password.is_empty() {
                    return Err("server_key password is required".to_string());
                }
                ServerKeySelection::Password(self.server_key.password.clone())
            }
            KeyType::Rsa => {
                if self.server_key.file.is_empty() {
                    return Err("server_key file is required".to_string());
                }
                ServerKeySelection::Rsa(PathBuf::from(&self.server_key.file))
            }
        };

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
            nickname: self.nickname.clone(),
            server_key,
            my_key,
            id_store_path: PathBuf::from(&self.id_store_path),
        })
    }
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
/// either submits a complete `ConnectRequest` or cancels.
pub fn run(
    surface: &mut super::surface::Surface,
    popup: &mut ConnectPopupState,
) -> Result<Option<ConnectRequest>, crate::BoxError> {
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
            Action::Connect(req) => return Ok(Some(req)),
            Action::Cancel => return Ok(None),
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

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // host
            Constraint::Length(3), // port
            Constraint::Length(3), // nickname
            Constraint::Length(3), // id_store
            Constraint::Length(1), // spacer
            Constraint::Length(4), // server_key group
            Constraint::Length(1), // spacer
            Constraint::Length(4), // my_key group
            Constraint::Length(1), // spacer
            Constraint::Length(1), // ALOO_HOME
            Constraint::Length(3), // connect button
            Constraint::Min(1),    // error / hint
        ])
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
    let id_store_inner = render_bordered_field(
        frame,
        chunks[3],
        "id_store",
        &state.id_store_path,
        state.focus == Field::IdStorePath,
    );

    let server_key_value = match state.server_key.key_type {
        KeyType::None => String::new(),
        KeyType::Password => "*".repeat(state.server_key.password.len()),
        KeyType::Rsa => {
            if state.server_key.file.is_empty() {
                "<press Enter to browse>".into()
            } else {
                state.server_key.file.clone()
            }
        }
    };
    let server_key_block = Block::default().title("server_key").borders(Borders::ALL);
    let server_key_inner = server_key_block.inner(chunks[5]);
    frame.render_widget(server_key_block, chunks[5]);
    let server_key_lines = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(server_key_inner);
    frame.render_widget(
        Paragraph::new(key_field_line(
            "type",
            state.server_key.key_type.label(),
            state.focus == Field::ServerKeyType,
        )),
        server_key_lines[0],
    );
    if state.server_key.key_type != KeyType::None {
        frame.render_widget(
            Paragraph::new(key_field_line(
                "value",
                &server_key_value,
                state.focus == Field::ServerKeyValue,
            )),
            server_key_lines[1],
        );
    }

    // The group's title names the one scheme there is rather than
    // spending a row on a selector that can only ever say `pq_hybrid`.
    let my_key_block = Block::default()
        .title("my_key (pq_hybrid)")
        .borders(Borders::ALL);
    let my_key_inner = my_key_block.inner(chunks[7]);
    frame.render_widget(my_key_block, chunks[7]);
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
    const VALUE_LABEL_LEN: u16 = 7; // "value: "
    match state.focus {
        Field::Host => place_text_cursor(frame, host_inner, 0, &state.host),
        Field::Port => place_text_cursor(frame, port_inner, 0, &state.port),
        Field::Nickname => place_text_cursor(frame, nickname_inner, 0, &state.nickname),
        Field::IdStorePath => place_text_cursor(frame, id_store_inner, 0, &state.id_store_path),
        Field::ServerKeyValue if state.server_key.key_type == KeyType::Password => {
            place_text_cursor(
                frame,
                server_key_lines[1],
                VALUE_LABEL_LEN,
                &server_key_value,
            )
        }
        _ => {}
    }

    // Read-only, and gray so it reads as a note about where this client's
    // local state lives rather than as another thing to fill in.
    frame.render_widget(
        Paragraph::new(format!("{ALOO_HOME_LABEL}{}", state.aloo_home))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(Alignment::Left),
        chunks[9],
    );

    render_connect_button(frame, chunks[10], state.focus == Field::Connect);

    let hint = state
        .error
        .clone()
        .unwrap_or_else(|| "Tab: next field  Enter: select/connect  Esc: quit".to_string());
    let hint_style = if state.error.is_some() {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    frame.render_widget(
        Paragraph::new(hint)
            .style(hint_style)
            .alignment(Alignment::Left),
        chunks[11],
    );

    if let Some((_, browser)) = &state.browser {
        render_file_browser(frame, area, browser, "Select file");
    }
}

fn render_connect_button(frame: &mut Frame, area: Rect, focused: bool) {
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
    // full-width bar, centered under the fields above it
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
        Paragraph::new("Connect")
            .alignment(Alignment::Center)
            .style(text_style),
        inner,
    );
}
