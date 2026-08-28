//! The `Ctrl+E` "Export" popup: checkbox-pick any joined channel or open
//! DM, then Confirm (Cancel focused by default, same destructive-action-
//! default convention `ChannelCommandConfirm` already uses) to dump each
//! selected surface's current in-memory log to
//! `~/.aloo/exports/<server>/{channels,dms}/*.log` (plus a `.wav` per
//! voice entry), files prefixed with one `client::export::short_uuid()`
//! shared across the whole export - see `client::export::export_log`.
//! Independent of `autosave_messages`: this works whether or not
//! continuous autosave is on.
//!
//! Modeled on `direct_punch_popup`'s `Mode`-based shape (state behind
//! `Option<T>` on `UiState`, `open_x`/`handle_x_key`/`render_x_popup`),
//! with the Confirm/Cancel row drawn by the shared
//! `widgets::confirm_popup::render_confirm_row`, exactly as
//! `render_channel_command_confirm_popup` does. The checkbox list itself
//! is new - nothing else in this app lets more than one row be selected
//! at once.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState};

use crate::proto::UserId;

use super::ui::{Mode, UiAction, UiState, centered_rect, focus_border_style};
use super::widgets::confirm_popup::{BUTTON_WIDTH, Confirm, ConfirmLabels, render_confirm_row};

pub struct ExportPopupState {
    /// Every joined channel, checked state initially off.
    pub channels: Vec<(String, bool)>,
    /// Every open DM, in `dm_order`, checked state initially off.
    pub dms: Vec<(UserId, String, bool)>,
    /// Row index into the two lists laid end to end (`channels` then
    /// `dms`) - meaningful only while `on_buttons` is `false`.
    pub cursor: usize,
    /// `false` while the checkbox list has focus, `true` once it's moved
    /// onto the Confirm/Cancel row.
    pub on_buttons: bool,
    pub confirm_focus: Confirm,
}

impl ExportPopupState {
    fn row_count(&self) -> usize {
        self.channels.len() + self.dms.len()
    }

    fn toggle(&mut self, index: usize) {
        if index < self.channels.len() {
            self.channels[index].1 = !self.channels[index].1;
        } else if let Some((_, _, checked)) = self.dms.get_mut(index - self.channels.len()) {
            *checked = !*checked;
        }
    }
}

impl UiState {
    /// Opens the popup populated straight from what's already in memory -
    /// unlike `DirectPunches`, nothing here lives on disk, so there's no
    /// `UiAction` round trip needed just to fill it in.
    pub fn open_export_popup(&mut self) {
        let channels = self.channels.iter().map(|c| (c.name.clone(), false)).collect();
        let dms = self
            .dm_order
            .iter()
            .filter_map(|id| self.private_rooms.get(id).map(|r| (*id, r.peer.name.clone(), false)))
            .collect();
        self.mode = Mode::ExportPopup;
        self.export_popup = Some(ExportPopupState {
            channels,
            dms,
            cursor: 0,
            on_buttons: false,
            confirm_focus: Confirm::No,
        });
    }

    pub(crate) fn handle_export_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let state = self.export_popup.as_mut()?;
        if code == KeyCode::Esc {
            self.export_popup = None;
            self.mode = Mode::Normal;
            return None;
        }
        if state.on_buttons {
            return match code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    state.confirm_focus.toggle();
                    None
                }
                KeyCode::Up => {
                    if state.row_count() > 0 {
                        state.on_buttons = false;
                        state.cursor = state.row_count() - 1;
                    }
                    None
                }
                KeyCode::Enter => {
                    let confirm_focus = state.confirm_focus;
                    if confirm_focus == Confirm::No {
                        self.export_popup = None;
                        self.mode = Mode::Normal;
                        return None;
                    }
                    let state = self.export_popup.take()?;
                    self.mode = Mode::Normal;
                    let channels: Vec<String> =
                        state.channels.into_iter().filter(|(_, checked)| *checked).map(|(name, _)| name).collect();
                    let dms: Vec<UserId> =
                        state.dms.into_iter().filter(|(_, _, checked)| *checked).map(|(id, _, _)| id).collect();
                    if channels.is_empty() && dms.is_empty() {
                        return None;
                    }
                    Some(UiAction::ExportSelected {
                        prefix: crate::client::export::short_uuid(),
                        channels,
                        dms,
                    })
                }
                _ => None,
            };
        }
        let len = state.row_count();
        match code {
            KeyCode::Up => {
                state.cursor = state.cursor.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if state.cursor + 1 < len {
                    state.cursor += 1;
                } else {
                    state.on_buttons = true;
                }
                None
            }
            KeyCode::Tab => {
                state.on_buttons = true;
                None
            }
            KeyCode::Enter => {
                if len > 0 {
                    state.toggle(state.cursor);
                }
                None
            }
            _ => None,
        }
    }
}

pub(crate) fn render_export_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(popup_state) = state.export_popup.as_ref() else {
        return;
    };
    let popup = centered_rect(60, 18, area);
    let block = Block::default()
        .title("Export channels/DMs")
        .borders(Borders::ALL)
        .border_style(focus_border_style(true));
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    let mut items: Vec<ListItem> = Vec::new();
    if !popup_state.channels.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "Channels",
            Style::default().add_modifier(Modifier::BOLD),
        ))));
    }
    for (name, checked) in &popup_state.channels {
        let mark = if *checked { "x" } else { " " };
        items.push(ListItem::new(format!("  [{mark}] #{name}")));
    }
    if !popup_state.dms.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "Direct Messages",
            Style::default().add_modifier(Modifier::BOLD),
        ))));
    }
    for (_, name, checked) in &popup_state.dms {
        let mark = if *checked { "x" } else { " " };
        items.push(ListItem::new(format!("  [{mark}] {name}")));
    }
    if items.is_empty() {
        items.push(ListItem::new("(no channels joined or DMs open)"));
    }

    // The header rows above ("Channels"/"Direct Messages") don't occupy a
    // `cursor` slot - offset the highlighted row past whichever of them
    // precede the selected entry.
    let header_offset = if !popup_state.channels.is_empty() { 1 } else { 0 }
        + if popup_state.cursor >= popup_state.channels.len() && !popup_state.dms.is_empty() {
            1
        } else {
            0
        };
    let mut list_state = ListState::default();
    if !popup_state.on_buttons && popup_state.row_count() > 0 {
        list_state.select(Some(popup_state.cursor + header_offset));
    }
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, rows[0], &mut list_state);

    // Neither button is focused while the checkbox list still has the
    // cursor - `None`, rather than a focus that would highlight a button
    // the user has not moved to yet.
    render_confirm_row(
        frame,
        rows[1],
        ConfirmLabels::CONFIRM_CANCEL,
        popup_state.on_buttons.then_some(popup_state.confirm_focus),
        BUTTON_WIDTH,
    );
}
