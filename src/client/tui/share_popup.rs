//! The "shared folders" list on the Ctrl+S settings popup's File Sharing
//! tab: every `share=` line, one row each, with add/edit/delete - the
//! in-app counterpart to hand-editing `~/.aloo/settings`
//! (`docs/PROTOCOL.md` §7.8). Saving (or deleting) persists the whole
//! list back to that file and re-announces it to every linked peer at
//! once, so a folder shared or withdrawn here is seen on the other side
//! without a restart.
//!
//! `direct_punch_popup`'s twin: a row and its editor, with where the list
//! sits and when it has focus left to `super::settings_popup`.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};

use crate::settings::SharedFolder;

use super::ui::{UiAction, UiState, focus_border_style};
use super::widgets::confirm_popup::render_popup_button;
use super::widgets::field::{place_text_cursor, render_bordered_field};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareField {
    Path,
    Access,
    Save,
}

/// The add/edit form - `editing_index` is `None` while adding.
pub struct ShareEditState {
    pub editing_index: Option<usize>,
    pub path: String,
    /// `all`, or nicknames comma-separated - exactly the text after the
    /// path on the settings line.
    pub access: String,
    pub focus: ShareField,
    pub error: Option<String>,
}

pub struct SharePopupState {
    pub rows: Vec<SharedFolder>,
    pub selected: usize,
    pub edit: Option<ShareEditState>,
}

impl SharePopupState {
    /// See `DirectPunchPopupState::step_selection`.
    pub fn step_selection(&mut self, up: bool) -> bool {
        if up {
            if self.selected == 0 {
                return false;
            }
            self.selected -= 1;
        } else {
            if self.selected + 1 >= self.rows.len() {
                return false;
            }
            self.selected += 1;
        }
        true
    }
}

impl UiState {
    /// `OpenSettings`/a completed save's answer for the share list - a
    /// no-op if the modal was closed in the meantime.
    pub fn set_share_rows(&mut self, rows: Vec<SharedFolder>) {
        let Some(state) = self.settings_popup.as_mut() else { return };
        state.shares.rows = rows;
        state.shares.selected = if state.shares.rows.is_empty() {
            0
        } else {
            state.shares.selected.min(state.shares.rows.len() - 1)
        };
    }

    pub(crate) fn handle_share_edit_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let edit = self.settings_popup.as_mut()?.shares.edit.as_mut()?;
        match code {
            KeyCode::Esc => {
                self.settings_popup.as_mut()?.shares.edit = None;
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                edit.focus = next_field(edit.focus, code == KeyCode::BackTab);
                None
            }
            KeyCode::Backspace => {
                match edit.focus {
                    ShareField::Path => {
                        edit.path.pop();
                    }
                    ShareField::Access => {
                        edit.access.pop();
                    }
                    ShareField::Save => {}
                }
                None
            }
            KeyCode::Char(c) if c != '\n' && !c.is_control() => {
                match edit.focus {
                    ShareField::Path => edit.path.push(c),
                    ShareField::Access => edit.access.push(c),
                    ShareField::Save => {}
                }
                None
            }
            KeyCode::Enter => self.submit_share_edit(),
            _ => None,
        }
    }

    /// Only `Save` acts on Enter. The line is built exactly as the
    /// settings file spells it and put through the same parser, so what
    /// the popup accepts and what a hand-edited file accepts can never
    /// drift apart.
    fn submit_share_edit(&mut self) -> Option<UiAction> {
        let state = self.settings_popup.as_ref()?;
        let edit = state.shares.edit.as_ref()?;
        if edit.focus != ShareField::Save {
            return None;
        }
        let access: Vec<&str> = edit
            .access
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let line = format!("{},{}", edit.path.trim(), access.join(","));
        let folder = match SharedFolder::parse(&line) {
            Ok(folder) => folder,
            Err(message) => {
                self.set_share_error(message);
                return None;
            }
        };
        let taken = state
            .shares
            .rows
            .iter()
            .enumerate()
            .any(|(i, row)| Some(i) != edit.editing_index && row.name() == folder.name());
        if taken {
            self.set_share_error(format!("a folder named {:?} is already shared", folder.name()));
            return None;
        }
        // A folder nobody can read is a share nobody can browse, and the
        // person who can fix it is standing right here - said now, in the
        // form, rather than as a red "not found" on the other side's
        // screen much later (`shared_folders::share_root_problem`).
        if let Some(problem) = crate::client::shared_folders::share_root_problem(&folder) {
            self.set_share_error(problem);
            return None;
        }
        let state = self.settings_popup.as_mut()?;
        match state.shares.edit.as_ref()?.editing_index {
            Some(i) => state.shares.rows[i] = folder,
            None => state.shares.rows.push(folder),
        }
        state.shares.edit = None;
        Some(UiAction::SaveShares(state.shares.rows.clone()))
    }

    fn set_share_error(&mut self, message: String) {
        if let Some(edit) = self.settings_popup.as_mut().and_then(|s| s.shares.edit.as_mut()) {
            edit.error = Some(message);
        }
    }

    /// The list's own keys once it has focus - add/edit/delete; Up/Down
    /// are `move_settings_focus`'s.
    pub(crate) fn handle_shares_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Char('a') | KeyCode::Char('n') => {
                self.settings_popup.as_mut()?.shares.edit = Some(ShareEditState {
                    editing_index: None,
                    path: String::new(),
                    access: "all".to_string(),
                    focus: ShareField::Path,
                    error: None,
                });
                None
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                let (index, row) = {
                    let shares = &self.settings_popup.as_ref()?.shares;
                    (shares.selected, shares.rows.get(shares.selected)?.clone())
                };
                self.settings_popup.as_mut()?.shares.edit = Some(ShareEditState {
                    editing_index: Some(index),
                    path: row.path.clone(),
                    access: row.access_text(),
                    focus: ShareField::Path,
                    error: None,
                });
                None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let state = self.settings_popup.as_mut()?;
                if state.shares.rows.is_empty() {
                    return None;
                }
                state.shares.rows.remove(state.shares.selected);
                state.shares.selected =
                    state.shares.selected.min(state.shares.rows.len().saturating_sub(1));
                Some(UiAction::SaveShares(state.shares.rows.clone()))
            }
            _ => None,
        }
    }
}

fn next_field(focus: ShareField, backwards: bool) -> ShareField {
    use ShareField::*;
    let order = [Path, Access, Save];
    let pos = order.iter().position(|f| *f == focus).unwrap_or(0);
    let len = order.len();
    order[if backwards { (pos + len - 1) % len } else { (pos + 1) % len }]
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_share_list(frame: &mut Frame, area: Rect, popup: &SharePopupState, focused: bool) {
    let help = Rect { height: 1.min(area.height), ..area };
    frame.render_widget(
        Paragraph::new("a: add  Enter/e: edit  d: delete").style(focus_border_style(focused)),
        help,
    );
    let list_area = Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    };
    if popup.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("no folders shared yet - press 'a' to share one")
                .style(Style::default().fg(Color::DarkGray)),
            list_area,
        );
        return;
    }
    let items: Vec<ListItem> = popup
        .rows
        .iter()
        .map(|s| ListItem::new(Line::from(format!("{}  {}  {}", s.name(), s.path, s.access_text()))))
        .collect();
    let highlight = if focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    let mut list_state = ListState::default();
    list_state.select(Some(popup.selected.min(popup.rows.len() - 1)));
    frame.render_stateful_widget(List::new(items).highlight_style(highlight), list_area, &mut list_state);
}

pub(crate) fn render_share_edit_form(frame: &mut Frame, area: Rect, edit: &ShareEditState) {
    let mut constraints = vec![
        Constraint::Length(3), // path
        Constraint::Length(3), // access
        Constraint::Length(3), // save
        Constraint::Length(3), // instruction
    ];
    if edit.error.is_some() {
        constraints.push(Constraint::Min(1));
    }
    let rows = Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);
    let path_inner = render_bordered_field(frame, rows[0], "folder path", &edit.path, edit.focus == ShareField::Path);
    let access_inner = render_bordered_field(
        frame,
        rows[1],
        "who may see it: all, or nicknames comma-separated",
        &edit.access,
        edit.focus == ShareField::Access,
    );
    match edit.focus {
        ShareField::Path => place_text_cursor(frame, path_inner, &edit.path),
        ShareField::Access => place_text_cursor(frame, access_inner, &edit.access),
        ShareField::Save => {}
    }
    render_popup_button(frame, rows[2], 16, "Save", edit.focus == ShareField::Save);
    frame.render_widget(
        Paragraph::new(
            "An absolute path, or one starting ~/ - a shell variable like $HOME or %USERPROFILE% is not expanded. \
             Peers you list (or everyone, with `all`) see this folder by its name, can browse it and download from \
             it. Nobody else is ever told it exists.",
        )
        .style(Style::default().fg(Color::Cyan))
        .wrap(Wrap { trim: true }),
        rows[3],
    );
    if let Some(err) = &edit.error {
        frame.render_widget(Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)), rows[4]);
    }
}
