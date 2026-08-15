//! The "not connected" screen: a centered modal collecting host/port and
//! the `server_key` / `my_key` credentials, including an in-TUI file
//! browser (no OS file dialog exists in a terminal) for RSA key files.
//!
//! State transitions (`ConnectPopupState::handle_key`,
//! `FileBrowserState` navigation) are plain functions independent of
//! rendering, so they're unit tested without a terminal.

use std::io;
use std::path::PathBuf;

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

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

/// `my_key`'s type selector is a separate enum from `server_key`'s
/// (`KeyType`): only `my_key` can be `rsa_per_msg` (SPEC.md Functionality
/// #6) - it controls the ongoing per-session key-rotation protocol
/// (PROTOCOL.md §11), which has no meaning for the server auth challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MyKeyType {
    Rsa,
    Password,
    None,
    /// Forward-secret (a fresh key every message, §11) and still
    /// cross-session verifiable via `own_next_keys` (§12.6), without
    /// requiring the user to already have a key file or remember a
    /// password before they can connect at all.
    RsaPerMessage,
    /// The default `my_key` selection: ML-DSA-87+RSA4096 signing,
    /// ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption
    /// (`docs/PROTOCOL.md` §13) - a static, file-loaded keybundle like
    /// `Rsa` (not rotating like `RsaPerMessage`), generated with
    /// `aloo --keygen-pq-hybrid` since there's no `openssl` for
    /// ML-DSA/ML-KEM. Reuses `Rsa`'s exact `file_pub`/`file_priv` shape.
    /// Unlike the previous default (`RsaPerMessage`), this one needs a
    /// keybundle prepared *before* connecting - chosen anyway as the
    /// default because it's the strongest identity this app can offer, at
    /// the cost of a first-time user needing to run `aloo
    /// --keygen-pq-hybrid` before the form can actually validate.
    #[default]
    PqHybrid,
}

impl MyKeyType {
    pub fn cycle_next(self) -> Self {
        match self {
            MyKeyType::Rsa => MyKeyType::Password,
            MyKeyType::Password => MyKeyType::None,
            MyKeyType::None => MyKeyType::RsaPerMessage,
            MyKeyType::RsaPerMessage => MyKeyType::PqHybrid,
            MyKeyType::PqHybrid => MyKeyType::Rsa,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MyKeyType::Rsa => "rsa",
            MyKeyType::Password => "password",
            MyKeyType::None => "none",
            MyKeyType::RsaPerMessage => "rsa_per_msg",
            MyKeyType::PqHybrid => "pq_hybrid",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ServerKeyFields {
    pub key_type: KeyType,
    pub password: String,
    pub file: String,
}

#[derive(Debug, Clone, Default)]
pub struct MyKeyFields {
    pub key_type: MyKeyType,
    pub password: String,
    pub file_pub: String,
    pub file_priv: String,
    /// `rsa_per_msg` only - path to this client's own per-peer continuity
    /// key store (`aloo::own_next_keys`). Prefilled from
    /// `own_next_keys::default_path()` at popup-open time, same as
    /// `ConnectPopupState::id_store_path` - only actually shown/used once
    /// `key_type` is `RsaPerMessage`, but harmless to have ready before then.
    pub own_next_keys_path: String,
}

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
    MyKeyType,
    MyKeyValuePub,
    MyKeyValuePriv,
    /// Shown only when `my_key.key_type == MyKeyType::RsaPerMessage` -
    /// occupies the same line `MyKeyValuePub`/`ServerKeyValue` would, since
    /// it's the one field `rsa_per_msg` needs (`docs/PROTOCOL.md` §12.6).
    OwnNextKeysPath,
    Connect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBrowserTarget {
    ServerKeyFile,
    MyKeyFilePub,
    MyKeyFilePriv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKeySelection {
    None,
    Password(String),
    Rsa(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MyKeySelection {
    None,
    Password(String),
    Rsa {
        file_pub: PathBuf,
        file_priv: PathBuf,
    },
    /// `rsa_per_msg` (SPEC.md Functionality #6, PROTOCOL.md §11): the
    /// bootstrap keypair itself is always freshly autogenerated in-process
    /// at connect time, same as `None` - but `own_next_keys_path` still
    /// needs collecting, since it's where this client's own per-peer
    /// continuity private keys are persisted across reconnects
    /// (`docs/PROTOCOL.md` §12.6), letting a peer verify "it's still me"
    /// after this client comes back online.
    RsaPerMessage {
        own_next_keys_path: PathBuf,
    },
    /// `pq_hybrid` (`docs/PROTOCOL.md` §13): both files are keybundles
    /// produced by `aloo --keygen-pq-hybrid`, not PEM - same two-file
    /// shape as `Rsa`, different file format underneath.
    PqHybrid {
        file_pub: PathBuf,
        file_priv: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub nickname: String,
    pub server_key: ServerKeySelection,
    pub my_key: MyKeySelection,
    /// Where the local identity-pinning store lives (see
    /// `aloo::idstore`, `docs/PROTOCOL.md` §12) - the file that remembers
    /// each nickname's full public key from the last time it was seen (for
    /// `rsa`/`password`), so a reconnecting peer whose key suddenly changed
    /// can be flagged instead of silently trusted. Prefilled from
    /// `idstore::default_path` but freely editable.
    pub id_store_path: PathBuf,
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
            id_store_path: crate::idstore::default_path().display().to_string(),
            server_key: ServerKeyFields::default(),
            my_key: MyKeyFields {
                own_next_keys_path: crate::own_next_keys::default_path().display().to_string(),
                ..MyKeyFields::default()
            },
            focus: Field::Host,
            browser: None,
            error: None,
        }
    }

    /// The focusable fields for the *current* key type selections: a
    /// field only appears once it's actually shown (e.g. `MyKeyValuePriv`
    /// only exists while `my_key.key_type == Rsa`).
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
        v.push(Field::MyKeyType);
        match self.my_key.key_type {
            MyKeyType::None => {}
            MyKeyType::RsaPerMessage => v.push(Field::OwnNextKeysPath),
            MyKeyType::Password => v.push(Field::MyKeyValuePub),
            MyKeyType::Rsa | MyKeyType::PqHybrid => {
                v.push(Field::MyKeyValuePub);
                v.push(Field::MyKeyValuePriv);
            }
        }
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
            KeyCode::Left | KeyCode::Right if self.focus == Field::MyKeyType => {
                self.my_key.key_type = self.my_key.key_type.cycle_next();
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

    /// If the field we were on just disappeared (e.g. `my_key` switched
    /// away from `rsa` while focus was on `file_priv`), fall back to a
    /// field that's always present instead of an orphaned one.
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
            Field::MyKeyType => {
                self.my_key.key_type = self.my_key.key_type.cycle_next();
                self.clamp_focus_after_type_change();
                Ok(Action::None)
            }
            Field::ServerKeyValue if self.server_key.key_type == KeyType::Rsa => {
                self.open_browser(FileBrowserTarget::ServerKeyFile)
            }
            Field::MyKeyValuePub
                if matches!(self.my_key.key_type, MyKeyType::Rsa | MyKeyType::PqHybrid) =>
            {
                self.open_browser(FileBrowserTarget::MyKeyFilePub)
            }
            Field::MyKeyValuePriv
                if matches!(self.my_key.key_type, MyKeyType::Rsa | MyKeyType::PqHybrid) =>
            {
                self.open_browser(FileBrowserTarget::MyKeyFilePriv)
            }
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
            Field::OwnNextKeysPath => {
                self.my_key.own_next_keys_path.pop();
            }
            Field::ServerKeyValue if self.server_key.key_type == KeyType::Password => {
                self.server_key.password.pop();
            }
            Field::MyKeyValuePub if self.my_key.key_type == MyKeyType::Password => {
                self.my_key.password.pop();
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
            Field::OwnNextKeysPath => self.my_key.own_next_keys_path.push(c),
            Field::ServerKeyValue if self.server_key.key_type == KeyType::Password => {
                self.server_key.password.push(c)
            }
            Field::MyKeyValuePub if self.my_key.key_type == MyKeyType::Password => {
                self.my_key.password.push(c)
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

        let my_key = match self.my_key.key_type {
            MyKeyType::None => MyKeySelection::None,
            MyKeyType::Password => {
                if self.my_key.password.is_empty() {
                    return Err("my_key password is required".to_string());
                }
                MyKeySelection::Password(self.my_key.password.clone())
            }
            MyKeyType::Rsa => {
                if self.my_key.file_pub.is_empty() || self.my_key.file_priv.is_empty() {
                    return Err("my_key file_pub and file_priv are both required".to_string());
                }
                MyKeySelection::Rsa {
                    file_pub: PathBuf::from(&self.my_key.file_pub),
                    file_priv: PathBuf::from(&self.my_key.file_priv),
                }
            }
            MyKeyType::RsaPerMessage => {
                if self.my_key.own_next_keys_path.trim().is_empty() {
                    return Err("own_next_keys path is required".to_string());
                }
                MyKeySelection::RsaPerMessage {
                    own_next_keys_path: PathBuf::from(&self.my_key.own_next_keys_path),
                }
            }
            MyKeyType::PqHybrid => {
                if self.my_key.file_pub.is_empty() || self.my_key.file_priv.is_empty() {
                    return Err("my_key file_pub and file_priv are both required".to_string());
                }
                MyKeySelection::PqHybrid {
                    file_pub: PathBuf::from(&self.my_key.file_pub),
                    file_priv: PathBuf::from(&self.my_key.file_priv),
                }
            }
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
// In-TUI file browser
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
}

/// A directory listing with browser-style back/forward history (distinct
/// from the `..` entry, which just moves up one level like any other
/// navigation and is itself recorded on the back stack).
pub struct FileBrowserState {
    pub current_dir: PathBuf,
    pub entries: Vec<DirEntryInfo>,
    pub selected: usize,
    history_back: Vec<PathBuf>,
    history_forward: Vec<PathBuf>,
}

impl FileBrowserState {
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        let entries = read_entries(&dir)?;
        Ok(Self {
            current_dir: dir,
            entries,
            selected: 0,
            history_back: Vec::new(),
            history_forward: Vec::new(),
        })
    }

    fn reload(&mut self) -> io::Result<()> {
        self.entries = read_entries(&self.current_dir)?;
        self.selected = 0;
        Ok(())
    }

    pub fn selected_entry(&self) -> Option<&DirEntryInfo> {
        self.entries.get(self.selected)
    }

    pub fn selected_path(&self) -> Option<PathBuf> {
        let entry = self.selected_entry()?;
        if entry.name == ".." {
            Some(
                self.current_dir
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| self.current_dir.clone()),
            )
        } else {
            Some(self.current_dir.join(&entry.name))
        }
    }

    pub fn select_next(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + self.entries.len() - 1) % self.entries.len();
        }
    }

    /// Enters the currently selected directory, pushing the old location
    /// onto the back-history stack and discarding any forward-history
    /// (a fresh navigation invalidates a stale "forward").
    pub fn navigate_into_selected(&mut self) -> io::Result<()> {
        let Some(target) = self.selected_path() else {
            return Ok(());
        };
        self.history_back.push(self.current_dir.clone());
        self.history_forward.clear();
        self.current_dir = target;
        self.reload()
    }

    pub fn go_back(&mut self) -> io::Result<bool> {
        let Some(prev) = self.history_back.pop() else {
            return Ok(false);
        };
        self.history_forward.push(self.current_dir.clone());
        self.current_dir = prev;
        self.reload()?;
        Ok(true)
    }

    pub fn go_forward(&mut self) -> io::Result<bool> {
        let Some(next) = self.history_forward.pop() else {
            return Ok(false);
        };
        self.history_back.push(self.current_dir.clone());
        self.current_dir = next;
        self.reload()?;
        Ok(true)
    }
}

fn read_entries(dir: &std::path::Path) -> io::Result<Vec<DirEntryInfo>> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.file_type()?.is_dir();
        if is_dir {
            dirs.push(DirEntryInfo { name, is_dir: true });
        } else {
            files.push(DirEntryInfo {
                name,
                is_dir: false,
            });
        }
    }
    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let mut entries = Vec::with_capacity(dirs.len() + files.len() + 1);
    if dir.parent().is_some() {
        entries.push(DirEntryInfo {
            name: "..".to_string(),
            is_dir: true,
        });
    }
    entries.extend(dirs);
    entries.extend(files);
    Ok(entries)
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

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

/// Border style shared by every bordered element in this popup: yellow
/// while focused, same convention as the connected-session UI
/// (`ui::focus_border_style`).
fn focus_border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
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
/// text in `inner`, `offset` columns in (non-zero for the `server_key`/
/// `my_key` password fields, which share their line with a `"value: "`
/// label rather than living in their own bordered box) - mirroring
/// `ui::render_input_bar`'s cursor logic. Without this, a focused text
/// field only *looks* focused (reversed value) but never actually shows
/// where typing lands.
fn place_text_cursor(frame: &mut Frame, inner: Rect, offset: u16, value: &str) {
    let cursor_x =
        inner.x + (offset + value.chars().count() as u16).min(inner.width.saturating_sub(1));
    frame.set_cursor_position((cursor_x, inner.y));
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
            Constraint::Length(5), // my_key group
            Constraint::Length(1), // spacer
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

    let my_key_block = Block::default().title("my_key").borders(Borders::ALL);
    let my_key_inner = my_key_block.inner(chunks[7]);
    frame.render_widget(my_key_block, chunks[7]);
    let my_key_lines = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(my_key_inner);
    frame.render_widget(
        Paragraph::new(key_field_line(
            "type",
            state.my_key.key_type.label(),
            state.focus == Field::MyKeyType,
        )),
        my_key_lines[0],
    );
    match state.my_key.key_type {
        MyKeyType::None => {}
        MyKeyType::RsaPerMessage => {
            frame.render_widget(
                Paragraph::new(key_field_line(
                    "own_next_keys",
                    &state.my_key.own_next_keys_path,
                    state.focus == Field::OwnNextKeysPath,
                )),
                my_key_lines[1],
            );
        }
        MyKeyType::Password => {
            let masked = "*".repeat(state.my_key.password.len());
            frame.render_widget(
                Paragraph::new(key_field_line(
                    "value",
                    &masked,
                    state.focus == Field::MyKeyValuePub,
                )),
                my_key_lines[1],
            );
        }
        MyKeyType::Rsa | MyKeyType::PqHybrid => {
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
                my_key_lines[1],
            );
            frame.render_widget(
                Paragraph::new(key_field_line(
                    "file_priv",
                    &priv_display,
                    state.focus == Field::MyKeyValuePriv,
                )),
                my_key_lines[2],
            );
        }
    }

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
        Field::MyKeyValuePub if state.my_key.key_type == MyKeyType::Password => {
            let masked = "*".repeat(state.my_key.password.len());
            place_text_cursor(frame, my_key_lines[1], VALUE_LABEL_LEN, &masked)
        }
        Field::OwnNextKeysPath => {
            const OWN_NEXT_KEYS_LABEL_LEN: u16 = 15; // "own_next_keys: "
            place_text_cursor(
                frame,
                my_key_lines[1],
                OWN_NEXT_KEYS_LABEL_LEN,
                &state.my_key.own_next_keys_path,
            )
        }
        _ => {}
    }

    render_connect_button(frame, chunks[9], state.focus == Field::Connect);

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
        chunks[10],
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

/// Shared by this popup's own `render` above and `ui::file_send`'s
/// send-a-file browser - the same generic, fs-backed directory browser
/// (`FileBrowserState`), just titled differently for whichever popup is
/// currently using it (`"Select file"` here, `"Send file"` there).
///
/// Uses `ListState` rather than a fixed style-per-item (same fix as
/// `ui::render_message_log`'s `list_state`): without it, `List` always
/// starts drawing at entry 0 and simply clips whatever doesn't fit, so
/// selecting past the bottom of the visible area moved `browser.selected`
/// but never scrolled the view to show it - `ListState` makes ratatui
/// compute whatever offset keeps the selected entry on screen.
pub(crate) fn render_file_browser(
    frame: &mut Frame,
    area: Rect,
    browser: &FileBrowserState,
    title_prefix: &str,
) {
    let popup = centered_rect(60, 20, area);
    let title = format!("{title_prefix} - {}", browser.current_dir.display());
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let items: Vec<ListItem> = browser
        .entries
        .iter()
        .map(|e| {
            ListItem::new(if e.is_dir {
                format!("{}/", e.name)
            } else {
                e.name.clone()
            })
        })
        .collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    if !browser.entries.is_empty() {
        list_state.select(Some(browser.selected.min(browser.entries.len() - 1)));
    }
    frame.render_stateful_widget(list, inner, &mut list_state);
}
