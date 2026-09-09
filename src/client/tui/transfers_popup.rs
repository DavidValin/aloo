//! The global transfers popup (`Ctrl+D` by default, see
//! `settings::transfers_shortcut`): every shared-folder transfer this
//! client has taken part in, both directions and every peer, live rows
//! above finished ones.
//!
//! The per-peer Downloads tab (`super::shared_browser`) shows one side of
//! one relationship; this shows the whole history, which is what someone
//! sharing folders with several people actually needs - who is pulling
//! what from them, alongside what they are pulling from everyone else.
//! Both are drawn from the one durable log (`client::transfer_log`), so
//! neither can disagree with the other or with what is on disk.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};

use crate::client::shared_folders::format_size;
use crate::client::transfer_log::{TransferDirection, TransferStatus};

use super::ui::{Mode, UiAction, UiState, centered_rect};
use super::widgets::progress_bar::{DEFAULT_BAR_CELLS, percent_of, progress_line};
use super::widgets::text::elide_start;

/// Wide, because every row is a path and a path is what a reader is
/// scanning for - the columns after it are short and fixed.
const POPUP_WIDTH: u16 = 120;
const POPUP_HEIGHT: u16 = 28;
/// What the fixed part of a row costs: the marker, the arrow, the
/// preposition and peer, the state and the counts. What is left is the
/// path's (`elide_start`).
const ROW_FURNITURE: usize = 46;
/// What the ", N already had" note adds to a row when any download has
/// skipped something.
const SKIPPED_FURNITURE: usize = 18;

/// Which rows are on screen. Everything, or one direction of it - a
/// person sharing a lot of folders wants to see what is going out
/// without their own downloads in the way, and the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransfersFilter {
    All,
    Downloads,
    Uploads,
}

impl TransfersFilter {
    /// The three, in the order the tab strip shows them.
    pub const ALL: [TransfersFilter; 3] = [Self::All, Self::Downloads, Self::Uploads];

    fn next(self) -> Self {
        match self {
            Self::All => Self::Downloads,
            Self::Downloads => Self::Uploads,
            Self::Uploads => Self::All,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Downloads => "Downloads",
            Self::Uploads => "Uploads",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|f| *f == self).unwrap_or(0)
    }

    fn keeps(self, direction: TransferDirection) -> bool {
        match self {
            Self::All => true,
            Self::Downloads => direction == TransferDirection::Download,
            Self::Uploads => direction == TransferDirection::Upload,
        }
    }
}

pub struct TransfersPopupState {
    pub filter: TransfersFilter,
    pub selected: usize,
    /// What was on screen before this opened, restored when it closes -
    /// the popup can be raised from anywhere, including over the shared
    /// files browser, and closing it must give that back rather than
    /// dropping the user somewhere else.
    pub previous_mode: Mode,
}

impl UiState {
    /// Opens the popup over whatever is on screen - an overlay like the
    /// user-info popup, not a mode that replaces the view.
    pub fn open_transfers_popup(&mut self) {
        self.transfers_popup = Some(TransfersPopupState {
            filter: TransfersFilter::All,
            selected: 0,
            previous_mode: self.mode,
        });
        self.mode = Mode::Transfers;
    }

    pub fn close_transfers_popup(&mut self) {
        if let Some(state) = self.transfers_popup.take() {
            self.mode = state.previous_mode;
        }
    }

    /// The rows the popup is showing, under its current filter.
    pub fn transfers_popup_rows(&self) -> Vec<&crate::client::transfer_log::TransferRecord> {
        let filter = self
            .transfers_popup
            .as_ref()
            .map(|p| p.filter)
            .unwrap_or(TransfersFilter::All);
        self.transfers
            .rows()
            .into_iter()
            .filter(|r| filter.keeps(r.direction))
            .collect()
    }

    pub(crate) fn handle_transfers_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let rows: Vec<(TransferDirection, String, u64, bool, bool)> = self
            .transfers_popup_rows()
            .iter()
            .map(|r| {
                (
                    r.direction,
                    r.peer_name.clone(),
                    r.request_id,
                    r.status.is_active(),
                    r.is_clearable(),
                )
            })
            .collect();
        let state = self.transfers_popup.as_mut()?;
        state.selected = state.selected.min(rows.len().saturating_sub(1));
        let selected = rows.get(state.selected).cloned();
        match code {
            KeyCode::Esc => {
                self.close_transfers_popup();
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                state.filter = state.filter.next();
                state.selected = 0;
                None
            }
            KeyCode::Up => {
                state.selected = state.selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if state.selected + 1 < rows.len() {
                    state.selected += 1;
                }
                None
            }
            KeyCode::Char('c') => {
                let (direction, peer_name, request_id, active, _) = selected?;
                if !active {
                    return None;
                }
                // Either side can stop it, and each says so its own way -
                // a requester tells the owner to stop offering, an owner
                // tells the requester to stop waiting (§7.8).
                Some(match direction {
                    TransferDirection::Download => UiAction::CancelSharedDownload { request_id },
                    TransferDirection::Upload => UiAction::CancelSharedUpload {
                        peer_name,
                        request_id,
                    },
                })
            }
            KeyCode::Char('r') => {
                let (direction, _peer_name, request_id, active, _) = selected?;
                (!active && direction == TransferDirection::Download)
                    .then_some(UiAction::ResumeSharedDownload { request_id })
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                let (direction, peer_name, request_id, _, clearable) = selected?;
                if clearable {
                    self.clear_transfer(direction, &peer_name, request_id);
                    return Some(UiAction::SaveTransferHistory);
                }
                None
            }
            KeyCode::Char('X') => {
                if self.transfers.clear_finished() > 0 {
                    return Some(UiAction::SaveTransferHistory);
                }
                None
            }
            _ => None,
        }
    }
}

pub(crate) fn render_transfers_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(popup_state) = &state.transfers_popup else { return };
    let rows = state.transfers_popup_rows();
    let active = state.transfers.active();
    let title = if active > 0 {
        format!("Transfers - {active} running")
    } else {
        "Transfers".to_string()
    };
    let popup = centered_rect(POPUP_WIDTH, POPUP_HEIGHT, area);
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    // The two directions read as tabs across the top, the same shape the
    // settings popup uses, rather than as a hint buried in the title -
    // which way you are looking is the first thing to see.
    let tab_row = Rect { height: 2.min(inner.height), ..inner };
    let titles: Vec<String> = TransfersFilter::ALL
        .iter()
        .map(|f| {
            let running = match f {
                TransfersFilter::All => state.transfers.active(),
                TransfersFilter::Downloads => {
                    state.transfers.active_in(TransferDirection::Download)
                }
                TransfersFilter::Uploads => state.transfers.active_in(TransferDirection::Upload),
            };
            if running > 0 {
                format!(" {} ({running}) ", f.title())
            } else {
                format!(" {} ", f.title())
            }
        })
        .collect();
    frame.render_widget(
        Tabs::new(titles)
            .select(popup_state.filter.index())
            .style(Style::default().fg(Color::DarkGray))
            .highlight_style(
                Style::default()
                    .bg(Color::Yellow)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(" "),
        tab_row,
    );

    let help = Rect {
        y: inner.y.saturating_add(2),
        height: 1.min(inner.height.saturating_sub(2)),
        ..inner
    };
    frame.render_widget(
        Paragraph::new(
            "Tab: switch \u{2502} c: cancel \u{2502} r: resume a download \u{2502} x: remove \u{2502} X: clear finished \u{2502} Esc: close",
        )
        .style(Style::default().fg(Color::DarkGray)),
        help,
    );
    let body = Rect {
        y: inner.y.saturating_add(4),
        height: inner.height.saturating_sub(4),
        ..inner
    };
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new("no file-share transfers yet")
                .style(Style::default().fg(Color::DarkGray)),
            body,
        );
        return;
    }

    // The "already had" note only appears once something has been
    // skipped, so the paths keep their full width until it does.
    let furniture = if rows.iter().any(|r| r.files_skipped > 0) {
        ROW_FURNITURE + SKIPPED_FURNITURE
    } else {
        ROW_FURNITURE
    };
    let path_width = (inner.width as usize).saturating_sub(furniture).max(12);
    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in rows.iter().enumerate() {
        let marker = if i == popup_state.selected { "\u{25b8} " } else { "  " };
        let (color, status) = match &item.status {
            TransferStatus::Asking | TransferStatus::Running => (Color::Yellow, item.status.label()),
            TransferStatus::Completed => (Color::Green, item.status.label()),
            TransferStatus::Cancelled => (Color::DarkGray, item.status.label()),
            TransferStatus::Failed(_) => (Color::Red, item.status.label()),
        };
        // The arrow says which way it went and the preposition says who
        // with, so a row reads without having to know the convention.
        let preposition = match item.direction {
            TransferDirection::Download => "from",
            TransferDirection::Upload => "to",
        };
        let counted = match item.files_total {
            Some(total) => format!("{}/{total} files", item.files_done),
            None => format!("{} files", item.files_done),
        };
        // A resumed download offers the whole folder again and refuses
        // what is already on disk, so its count climbs straight back up
        // without a byte moving. Saying how many were skipped is what
        // makes that read as resuming rather than starting over - the
        // browser's own Downloads tab has said so all along, and this
        // popup is where the user actually watches a transfer.
        let skipped = if item.files_skipped > 0 {
            format!(", {} already had", item.files_skipped)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker}{} ", item.direction.marker()),
                Style::default().fg(color),
            ),
            // The tail of the path, not the head: the last components
            // say which file this is, the first ones repeat down the
            // whole list.
            Span::styled(
                elide_start(&item.label(), path_width),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {preposition} {}", item.peer_name),
                Style::default().fg(Color::Gray),
            ),
            Span::raw("  "),
            Span::styled(status, Style::default().fg(color)),
            Span::styled(format!("  {counted}{skipped}"), Style::default().fg(Color::DarkGray)),
        ]));
        let suffix = match item.fraction() {
            Some(f) => format!("  {}%  {}", percent_of(f), format_size(item.bytes_done)),
            None => format!("  {}", format_size(item.bytes_done)),
        };
        let mut bar =
            progress_line(item.fraction().unwrap_or(0.0), DEFAULT_BAR_CELLS, color, &suffix).spans;
        bar.insert(0, Span::raw("  "));
        lines.push(Line::from(bar));
        lines.push(Line::from(""));
    }
    frame.render_widget(Paragraph::new(lines), body);
}
