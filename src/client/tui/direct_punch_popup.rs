//! The Ctrl+S "Direct Punches" popup: every configured `direct_punch_to`
//! peer, one row each, with add/edit/delete - the in-app counterpart to
//! hand-editing `~/.aloo/settings` (`docs/PROTOCOL.md` §7.1.5). Saving
//! (or deleting) persists the whole list back to that file and reconfigures
//! `PeerLinkManager`'s scheduler immediately, so a change takes effect the
//! same tick it's made rather than waiting for a restart.
//!
//! Mirrors `crate::client::tui::contacts`'s split: state/handling here as
//! `impl UiState`, rendering as free functions taking `&UiState`. Unlike
//! contacts, the row data *is* just settings already loaded elsewhere - the
//! popup asks for a fresh copy on open (`UiAction::OpenDirectPunches`) the
//! same way `/contacts` asks the session to gather its rows, since
//! `UiState` itself never touches the filesystem.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs};

use crate::settings::{DirectPunchTarget, PUNCH_FREQUENCIES, PunchFrequency};

use super::ui::{Mode, UiAction, UiState, centered_rect, render_popup_button};
use super::widgets::field::{place_text_cursor, render_bordered_field};

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

/// Which field is focused inside the add/edit form - Tab/BackTab cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPunchField {
    Nickname,
    Host,
    Port,
    Frequency,
    Save,
}

/// The add/edit form. `editing_index` is `None` while adding a new target,
/// `Some(i)` while editing `rows[i]` in place - the same distinction
/// `contacts::InstallOtpState` would need if it ever grew an "edit" mode,
/// kept here from the start since both add and edit share one form.
pub struct DirectPunchEditState {
    pub editing_index: Option<usize>,
    pub nickname: String,
    pub host: String,
    pub port: String,
    /// Index into `PUNCH_FREQUENCIES`, cycled with Left/Right - a bounded
    /// selector rather than free text, since only those 13 values are
    /// representable at all (`PunchFrequency::parse`).
    pub frequency_index: usize,
    pub focus: DirectPunchField,
    pub error: Option<String>,
}

pub struct DirectPunchPopupState {
    pub rows: Vec<DirectPunchTarget>,
    pub selected: usize,
    /// `Some` while the add/edit form is open over the list.
    pub edit: Option<DirectPunchEditState>,
}

impl UiState {
    /// Opens the modal empty and returns `UiAction::OpenDirectPunches` so
    /// the session fills it in from `~/.aloo/settings` - mirrors
    /// `open_contacts` + `OpenContacts`'s same split.
    pub fn open_direct_punches(&mut self) {
        self.mode = Mode::DirectPunches;
        self.direct_punches = Some(DirectPunchPopupState {
            rows: Vec::new(),
            selected: 0,
            edit: None,
        });
    }

    /// `OpenDirectPunches`/a completed save's answer: replaces the row set
    /// in place, clamping the selection rather than resetting it. A no-op
    /// if the modal was closed in the meantime.
    pub fn set_direct_punch_rows(&mut self, rows: Vec<DirectPunchTarget>) {
        let Some(state) = self.direct_punches.as_mut() else {
            return;
        };
        state.rows = rows;
        state.selected = if state.rows.is_empty() {
            0
        } else {
            state.selected.min(state.rows.len() - 1)
        };
    }

    /// The save form's failure path - shown inline, same convention as
    /// `contacts::InstallOtpState::error`.
    pub fn set_direct_punch_error(&mut self, message: String) {
        if let Some(edit) = self.direct_punches.as_mut().and_then(|d| d.edit.as_mut()) {
            edit.error = Some(message);
        }
    }

    pub(crate) fn handle_direct_punches_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let has_edit = self
            .direct_punches
            .as_ref()
            .map(|d| d.edit.is_some())
            .unwrap_or(false);
        if has_edit {
            return self.handle_direct_punches_edit_key(code);
        }
        self.handle_direct_punches_list_key(code)
    }

    fn handle_direct_punches_list_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let len = self.direct_punches.as_ref()?.rows.len();
        match code {
            KeyCode::Esc => {
                self.direct_punches = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Up => {
                if len > 0
                    && let Some(state) = self.direct_punches.as_mut()
                {
                    state.selected = (state.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                if len > 0
                    && let Some(state) = self.direct_punches.as_mut()
                {
                    state.selected = (state.selected + 1) % len;
                }
                None
            }
            KeyCode::Char('a') | KeyCode::Char('n') => {
                if let Some(state) = self.direct_punches.as_mut() {
                    state.edit = Some(blank_edit_state());
                }
                None
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                let target = {
                    let state = self.direct_punches.as_ref()?;
                    state.rows.get(state.selected)?.clone()
                };
                if let Some(state) = self.direct_punches.as_mut() {
                    state.edit = Some(edit_state_for(state.selected, &target));
                }
                None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if len == 0 {
                    return None;
                }
                let state = self.direct_punches.as_mut()?;
                let removed = state.selected;
                state.rows.remove(removed);
                state.selected = state.selected.min(state.rows.len().saturating_sub(1));
                Some(UiAction::SaveDirectPunchTargets(state.rows.clone()))
            }
            _ => None,
        }
    }

    fn handle_direct_punches_edit_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.direct_punches.as_mut() {
                    state.edit = None;
                }
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if let Some(edit) = self.direct_punches.as_mut().and_then(|d| d.edit.as_mut()) {
                    edit.focus = next_field(edit.focus, code == KeyCode::BackTab);
                }
                None
            }
            KeyCode::Left | KeyCode::Right => {
                if let Some(edit) = self.direct_punches.as_mut().and_then(|d| d.edit.as_mut())
                    && edit.focus == DirectPunchField::Frequency
                {
                    let len = PUNCH_FREQUENCIES.len();
                    edit.frequency_index = if code == KeyCode::Left {
                        (edit.frequency_index + len - 1) % len
                    } else {
                        (edit.frequency_index + 1) % len
                    };
                }
                None
            }
            KeyCode::Backspace => {
                if let Some(edit) = self.direct_punches.as_mut().and_then(|d| d.edit.as_mut()) {
                    match edit.focus {
                        DirectPunchField::Nickname => {
                            edit.nickname.pop();
                        }
                        DirectPunchField::Host => {
                            edit.host.pop();
                        }
                        DirectPunchField::Port => {
                            edit.port.pop();
                        }
                        DirectPunchField::Frequency | DirectPunchField::Save => {}
                    }
                }
                None
            }
            KeyCode::Char(c) => {
                if let Some(edit) = self.direct_punches.as_mut().and_then(|d| d.edit.as_mut()) {
                    match edit.focus {
                        DirectPunchField::Nickname => edit.nickname.push(c),
                        DirectPunchField::Host => edit.host.push(c),
                        DirectPunchField::Port if c.is_ascii_digit() => edit.port.push(c),
                        DirectPunchField::Port | DirectPunchField::Frequency | DirectPunchField::Save => {}
                    }
                }
                None
            }
            KeyCode::Enter => self.submit_direct_punch_edit(),
            _ => None,
        }
    }

    /// Only `Save` actually does anything on Enter - the text fields have
    /// no activation of their own, same as `contacts::InstallOtpState`'s
    /// path/browser fields being the only ones Enter acts on there.
    fn submit_direct_punch_edit(&mut self) -> Option<UiAction> {
        let state = self.direct_punches.as_ref()?;
        let edit = state.edit.as_ref()?;
        if edit.focus != DirectPunchField::Save {
            return None;
        }
        let frequency = PUNCH_FREQUENCIES[edit.frequency_index];
        let host = if edit.port.trim().is_empty() {
            edit.host.clone()
        } else {
            format!("{}:{}", edit.host, edit.port.trim())
        };
        let line = format!("{},{},every_{}m", edit.nickname.trim(), host, frequency);
        let target = match DirectPunchTarget::parse(&line) {
            Ok(target) => target,
            Err(message) => {
                self.set_direct_punch_error(message);
                return None;
            }
        };

        let state = self.direct_punches.as_mut()?;
        match state.edit.as_ref()?.editing_index {
            Some(i) => state.rows[i] = target,
            None => state.rows.push(target),
        }
        state.edit = None;
        Some(UiAction::SaveDirectPunchTargets(state.rows.clone()))
    }
}

fn next_field(focus: DirectPunchField, backwards: bool) -> DirectPunchField {
    use DirectPunchField::*;
    let order = [Nickname, Host, Port, Frequency, Save];
    let pos = order.iter().position(|f| *f == focus).unwrap_or(0);
    let len = order.len();
    let next = if backwards { (pos + len - 1) % len } else { (pos + 1) % len };
    order[next]
}

fn blank_edit_state() -> DirectPunchEditState {
    DirectPunchEditState {
        editing_index: None,
        nickname: String::new(),
        host: String::new(),
        port: String::new(),
        frequency_index: 0,
        focus: DirectPunchField::Nickname,
        error: None,
    }
}

fn edit_state_for(index: usize, target: &DirectPunchTarget) -> DirectPunchEditState {
    let frequency_index = PUNCH_FREQUENCIES
        .iter()
        .position(|m| *m == target.frequency.minutes())
        .unwrap_or(0);
    DirectPunchEditState {
        editing_index: Some(index),
        // `target_key`, not the bare nickname, so re-editing a device-
        // suffixed row (§5a) round-trips its `+<device_id>` suffix rather
        // than silently dropping it.
        nickname: target.target_key(),
        host: target.host.clone(),
        port: target.port.to_string(),
        frequency_index,
        focus: DirectPunchField::Nickname,
        error: None,
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_direct_punches_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(popup) = &state.direct_punches else { return };

    let outer = centered_rect(70, 22, area);
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(outer);
    frame.render_widget(ratatui::widgets::Clear, outer);
    frame.render_widget(block, outer);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(inner);

    let tabs = Tabs::new(vec!["Direct Punches"])
        .select(0)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, rows[0]);

    if let Some(edit) = &popup.edit {
        render_edit_form(frame, rows[1], edit);
    } else {
        render_list(frame, rows[1], popup);
    }
}

fn render_list(frame: &mut Frame, area: Rect, popup: &DirectPunchPopupState) {
    let help = Rect { height: 1.min(area.height), ..area };
    frame.render_widget(
        Paragraph::new("a: add  Enter/e: edit  d: delete  Esc: close")
            .style(Style::default().fg(Color::DarkGray)),
        help,
    );
    let list_area = Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    };

    if popup.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("no direct punches configured yet - press 'a' to add one")
                .style(Style::default().fg(Color::DarkGray)),
            list_area,
        );
        return;
    }

    let items: Vec<ListItem> = popup
        .rows
        .iter()
        .map(|t| {
            ListItem::new(Line::from(format!(
                "{}  {}:{}  {}",
                t.target_key(),
                t.host,
                t.port,
                t.frequency
            )))
        })
        .collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    list_state.select(Some(popup.selected.min(popup.rows.len() - 1)));
    frame.render_stateful_widget(list, list_area, &mut list_state);
}

/// A bordered field, styled exactly like `ui_connect_popup`'s own
/// `render_bordered_field` - the focused one's border highlighted, its
/// value drawn inside - so every popup's text fields read the same way.
/// Returns the inner `Rect`, for placing the blinking cursor in it.
fn render_edit_form(frame: &mut Frame, area: Rect, edit: &DirectPunchEditState) {
    let mut constraints = vec![
        Constraint::Length(3), // nickname
        Constraint::Length(3), // host
        Constraint::Length(3), // port
        Constraint::Length(3), // frequency
        Constraint::Length(3), // save button
    ];
    if edit.error.is_some() {
        constraints.push(Constraint::Min(1));
    }
    let rows = Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);

    let nickname_inner = render_bordered_field(
        frame,
        rows[0],
        "nickname (optionally nick+device_id)",
        &edit.nickname,
        edit.focus == DirectPunchField::Nickname,
    );
    let host_inner =
        render_bordered_field(frame, rows[1], "host", &edit.host, edit.focus == DirectPunchField::Host);
    let port_display = if edit.port.is_empty() {
        format!("<default {}>", crate::settings::DEFAULT_DIRECT_PUNCH_PORT)
    } else {
        edit.port.clone()
    };
    let port_inner =
        render_bordered_field(frame, rows[2], "port", &port_display, edit.focus == DirectPunchField::Port);
    let frequency = PunchFrequency::parse(&format!("every_{}m", PUNCH_FREQUENCIES[edit.frequency_index]))
        .expect("every PUNCH_FREQUENCIES entry parses");
    render_bordered_field(
        frame,
        rows[3],
        "frequency (\u{2190}/\u{2192})",
        &frequency.to_string(),
        edit.focus == DirectPunchField::Frequency,
    );

    // Only the free-text fields get a blinking cursor - frequency is a
    // bounded Left/Right selector, not something typed into.
    match edit.focus {
        DirectPunchField::Nickname => place_text_cursor(frame, nickname_inner, &edit.nickname),
        DirectPunchField::Host => place_text_cursor(frame, host_inner, &edit.host),
        DirectPunchField::Port => place_text_cursor(frame, port_inner, &edit.port),
        DirectPunchField::Frequency | DirectPunchField::Save => {}
    }

    render_popup_button(frame, rows[4], 16, "Save", edit.focus == DirectPunchField::Save);

    if let Some(err) = &edit.error {
        frame.render_widget(Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)), rows[5]);
    }
}
