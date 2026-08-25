//! The `/lock-joins` popup: locks (or unlocks) who may join the current
//! channel from now on (`docs/PROTOCOL.md` §6.7). Structural mirror of
//! `direct_punch_popup`'s list+add/delete+immediate-apply shape, cut down
//! to the one field a nickname needs (no multi-field edit form).
//!
//! Unlike `direct_punch_popup`, opening this needs no round trip to the
//! session: the channel's current member list is already local
//! (`UiState::channels`), so `submit_input`'s `/lock-joins` branch fills
//! it in directly rather than returning a `UiAction` first.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use super::ui::{Mode, UiAction, UiState, centered_rect};

pub struct ChannelLockPopupState {
    pub channel: String,
    /// `false` is "All users" - the list below is ignored and Apply
    /// clears the lock entirely.
    pub locked: bool,
    /// The allowlist while `locked` - prefilled with the channel's
    /// current members (`docs/PROTOCOL.md` §6.7's own words), editable
    /// with `a`/`d`.
    pub rows: Vec<String>,
    pub selected: usize,
    /// `Some` while typing a nickname to add.
    pub add: Option<String>,
}

impl UiState {
    /// Opens the popup prefilled with `channel`'s current members, locked
    /// by default (the spec's own "by default the current users joined
    /// should be included"). Purely local - see the module doc for why
    /// this needs no `UiAction` to fill itself in.
    pub fn open_channel_lock_popup(&mut self, channel: String, current_members: Vec<String>) {
        self.mode = Mode::ChannelLockPopup;
        self.channel_lock = Some(ChannelLockPopupState {
            channel,
            locked: true,
            rows: current_members,
            selected: 0,
            add: None,
        });
    }

    pub(crate) fn handle_channel_lock_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let has_add = self.channel_lock.as_ref().map(|s| s.add.is_some()).unwrap_or(false);
        if has_add {
            return self.handle_channel_lock_add_key(code);
        }
        self.handle_channel_lock_list_key(code)
    }

    fn handle_channel_lock_list_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let len = self.channel_lock.as_ref()?.rows.len();
        match code {
            KeyCode::Esc => {
                self.channel_lock = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Up => {
                if len > 0
                    && let Some(state) = self.channel_lock.as_mut()
                {
                    state.selected = (state.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                if len > 0
                    && let Some(state) = self.channel_lock.as_mut()
                {
                    state.selected = (state.selected + 1) % len;
                }
                None
            }
            // Toggles between the allowlist and "All users" - the spec's
            // two options for this popup.
            KeyCode::Left | KeyCode::Right | KeyCode::Char('u') => {
                if let Some(state) = self.channel_lock.as_mut() {
                    state.locked = !state.locked;
                }
                None
            }
            KeyCode::Char('a') | KeyCode::Char('n') => {
                if let Some(state) = self.channel_lock.as_mut() {
                    state.add = Some(String::new());
                }
                None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if len == 0 {
                    return None;
                }
                if let Some(state) = self.channel_lock.as_mut() {
                    let removed = state.selected;
                    state.rows.remove(removed);
                    state.selected = state.selected.min(state.rows.len().saturating_sub(1));
                }
                None
            }
            // Apply: takes effect immediately (docs/PROTOCOL.md §6.7).
            KeyCode::Enter => {
                let state = self.channel_lock.as_ref()?;
                let channel = state.channel.clone();
                let allowed = if state.locked { Some(state.rows.clone()) } else { None };
                self.channel_lock = None;
                self.mode = Mode::Normal;
                Some(UiAction::SetChannelJoinLock { channel, allowed })
            }
            _ => None,
        }
    }

    fn handle_channel_lock_add_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.channel_lock.as_mut() {
                    state.add = None;
                }
                None
            }
            KeyCode::Backspace => {
                if let Some(state) = self.channel_lock.as_mut()
                    && let Some(add) = state.add.as_mut()
                {
                    add.pop();
                }
                None
            }
            KeyCode::Char(c)
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' =>
            {
                if let Some(state) = self.channel_lock.as_mut()
                    && let Some(add) = state.add.as_mut()
                    && add.chars().count() < crate::validation::NICKNAME_MAX_LEN
                {
                    add.push(c);
                }
                None
            }
            KeyCode::Enter => {
                if let Some(state) = self.channel_lock.as_mut() {
                    let name = state.add.take().unwrap_or_default();
                    if !name.is_empty() && !state.rows.iter().any(|r| r == &name) {
                        state.rows.push(name);
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_channel_lock_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(popup) = &state.channel_lock else { return };

    let outer = centered_rect(60, 18, area);
    let block = Block::default()
        .title(format!("Lock joins: #{}", popup.channel))
        .borders(Borders::ALL);
    let inner = block.inner(outer);
    frame.render_widget(ratatui::widgets::Clear, outer);
    frame.render_widget(block, outer);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Min(1)])
        .split(inner);

    let mode_line = Line::from(vec![
        Span::raw("Mode (\u{2190}/\u{2192}/u): "),
        Span::styled(
            "All users",
            if !popup.locked {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Color::DarkGray)
            },
        ),
        Span::raw("  "),
        Span::styled(
            "Only listed",
            if popup.locked {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Color::DarkGray)
            },
        ),
    ]);
    frame.render_widget(Paragraph::new(mode_line), rows[0]);

    frame.render_widget(
        Paragraph::new("a: add  d: delete  Enter: Apply  Esc: cancel")
            .style(Style::default().fg(Color::DarkGray)),
        rows[1],
    );

    if let Some(adding) = &popup.add {
        let field = Line::from(vec![
            Span::styled("nickname: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(adding.clone(), Style::default().add_modifier(Modifier::REVERSED)),
        ]);
        frame.render_widget(Paragraph::new(field), rows[2]);
        return;
    }

    if !popup.locked {
        frame.render_widget(
            Paragraph::new("anyone may join - the list below is ignored while \"All users\" is selected")
                .style(Style::default().fg(Color::DarkGray))
                .wrap(ratatui::widgets::Wrap { trim: true }),
            rows[2],
        );
        return;
    }

    if popup.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("nobody on the list yet - press 'a' to add a nickname")
                .style(Style::default().fg(Color::DarkGray)),
            rows[2],
        );
        return;
    }
    let items: Vec<ListItem> = popup.rows.iter().map(|n| ListItem::new(Line::from(n.as_str()))).collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    list_state.select(Some(popup.selected.min(popup.rows.len() - 1)));
    frame.render_stateful_widget(list, rows[2], &mut list_state);
}
