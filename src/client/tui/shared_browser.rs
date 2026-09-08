//! The "Browse shared files" popup (`docs/SPEC.md` "Shared folders"):
//! reached from the `/info` popup of a peer who has shared folders with
//! us, it walks their shares the way `file_send`'s browser walks the
//! local disk - except every listing is asked of the peer
//! (`UiAction::RequestSharedListing`, `docs/PROTOCOL.md` §7.8) and
//! arrives later (`UiState::set_shared_listing`), so a view can be
//! "loading". `d` asks for the selected file, or every file under the
//! selected folder (`UiAction::DownloadShared`); the transfers then show
//! up as ordinary file rows in that peer's DM, accepted without a popup.
//!
//! Mirrors `crate::client::tui::file_send`'s split: state and key handling
//! here as `impl UiState`, rendering as a free function over `&UiState`.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::client::shared_folders::{self, SharedEntry, SharedError, format_size};
use crate::proto::UserId;

use super::shared_downloads::SharedDownloadStatus;
use super::ui::{Mode, UiAction, UiState, centered_rect};
use super::widgets::progress_bar::{DEFAULT_BAR_CELLS, percent_of, progress_line};

/// Which half of the popup is showing. Downloads are a tab rather than a
/// popup of their own because they are the other half of one activity:
/// you browse, you pull, you watch it arrive (§7.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedBrowserTab {
    Files,
    Downloads,
}

pub struct SharedBrowserState {
    pub tab: SharedBrowserTab,
    /// Which download row is selected, on the Downloads tab.
    pub download_selected: usize,
    pub peer: UserId,
    pub peer_name: String,
    /// `None` at the top level, which lists the peer's share names;
    /// `Some(share)` once one has been entered.
    pub share: Option<String>,
    /// Where inside `share` the view is - `/`-separated, empty at the
    /// share's root. Meaningless while `share` is `None`.
    pub rel_path: String,
    pub entries: Vec<SharedEntry>,
    pub selected: usize,
    /// A listing has been asked for and not yet answered.
    pub loading: bool,
    /// The peer cut the listing at `MAX_SHARED_ENTRIES_PER_RESPONSE`.
    pub truncated: bool,
    pub error: Option<String>,
}

impl SharedBrowserState {
    /// The top-level rows: each share the peer announced, as a folder.
    fn share_rows(names: &[String]) -> Vec<SharedEntry> {
        names
            .iter()
            .map(|name| SharedEntry {
                name: name.clone(),
                is_dir: true,
                size: 0,
                created_unix: None,
                modified_unix: None,
            })
            .collect()
    }

    fn selected_entry(&self) -> Option<&SharedEntry> {
        self.entries.get(self.selected)
    }

    /// `<share>/<rel_path>`, or `/` at the top - the popup's title.
    pub fn location(&self) -> String {
        match &self.share {
            None => "/".to_string(),
            Some(share) if self.rel_path.is_empty() => format!("/{share}"),
            Some(share) => format!("/{share}/{}", self.rel_path),
        }
    }
}

impl UiState {
    /// Opens the browser at `peer`'s top level - every share they have
    /// announced to us. Nothing is asked of them yet; that happens once a
    /// share is entered. Does nothing for a peer who shares nothing.
    pub fn open_shared_browser(&mut self, peer: UserId) -> bool {
        let names = match self.peer_shares.get(&peer) {
            Some(names) if !names.is_empty() => names.clone(),
            _ => return false,
        };
        let peer_name = self
            .known_users
            .get(&peer)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| peer.0.to_string());
        self.shared_browser = Some(SharedBrowserState {
            tab: SharedBrowserTab::Files,
            download_selected: 0,
            peer,
            peer_name,
            share: None,
            rel_path: String::new(),
            entries: SharedBrowserState::share_rows(&names),
            selected: 0,
            loading: false,
            truncated: false,
            error: None,
        });
        self.mode = Mode::SharedFiles;
        true
    }

    /// A listing's answer. Applied only if the browser is still open on
    /// exactly the location it was asked for - a slow answer to a view
    /// the user has already left is dropped, never shown over the wrong
    /// folder.
    pub fn set_shared_listing(
        &mut self,
        peer: UserId,
        share: &str,
        rel_path: &str,
        entries: Vec<SharedEntry>,
        truncated: bool,
        error: Option<SharedError>,
    ) {
        let Some(state) = self.shared_browser.as_mut() else { return };
        if state.peer != peer || state.share.as_deref() != Some(share) || state.rel_path != rel_path {
            return;
        }
        state.loading = false;
        state.truncated = truncated;
        state.error = error.map(|e| e.describe().to_string());
        state.entries = entries;
        state.selected = 0;
    }

    /// The peer's announced shares changed while the browser is open on
    /// their top level: redraw that level from the new list. A share the
    /// browser is *inside* being withdrawn is answered by the next
    /// listing request failing, not here.
    pub(crate) fn refresh_shared_browser_top_level(&mut self, peer: UserId) {
        let names = self.peer_shares.get(&peer).cloned().unwrap_or_default();
        if let Some(state) = self.shared_browser.as_mut()
            && state.peer == peer
            && state.share.is_none()
        {
            state.entries = SharedBrowserState::share_rows(&names);
            state.selected = state.selected.min(state.entries.len().saturating_sub(1));
        }
    }

    pub(crate) fn handle_shared_browser_key(&mut self, code: KeyCode) -> Option<UiAction> {
        if code == KeyCode::Tab || code == KeyCode::BackTab {
            let state = self.shared_browser.as_mut()?;
            state.tab = match state.tab {
                SharedBrowserTab::Files => SharedBrowserTab::Downloads,
                SharedBrowserTab::Downloads => SharedBrowserTab::Files,
            };
            return None;
        }
        if self.shared_browser.as_ref()?.tab == SharedBrowserTab::Downloads {
            return self.handle_shared_downloads_key(code);
        }
        let state = self.shared_browser.as_mut()?;
        match code {
            KeyCode::Esc => {
                self.shared_browser = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Up => {
                state.selected = state.selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if state.selected + 1 < state.entries.len() {
                    state.selected += 1;
                }
                None
            }
            KeyCode::Enter | KeyCode::Right => {
                let entry = state.selected_entry()?.clone();
                if !entry.is_dir {
                    return None;
                }
                match state.share.clone() {
                    None => {
                        state.share = Some(entry.name);
                        state.rel_path = String::new();
                    }
                    Some(_) => {
                        state.rel_path = shared_folders::join_rel(&state.rel_path, &entry.name);
                    }
                }
                Some(Self::ask_listing(state))
            }
            KeyCode::Backspace | KeyCode::Left => {
                let share = state.share.clone()?;
                if state.rel_path.is_empty() {
                    // Back to the top level, which needs no request.
                    state.share = None;
                    state.loading = false;
                    state.error = None;
                    state.truncated = false;
                    let names = self.peer_shares.get(&state.peer).cloned().unwrap_or_default();
                    state.entries = SharedBrowserState::share_rows(&names);
                    state.selected = names.iter().position(|n| *n == share).unwrap_or(0);
                    return None;
                }
                let leaving = state
                    .rel_path
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                state.rel_path = shared_folders::parent_rel(&state.rel_path);
                // The folder just left is reselected once its parent's
                // listing lands - see `set_shared_listing`'s reset to 0;
                // the name is kept only for that.
                let _ = leaving;
                Some(Self::ask_listing(state))
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                let entry = state.selected_entry()?.clone();
                let (share, rel_path) = match &state.share {
                    None => (entry.name.clone(), String::new()),
                    Some(share) => (
                        share.clone(),
                        shared_folders::join_rel(&state.rel_path, &entry.name),
                    ),
                };
                Some(UiAction::DownloadShared {
                    peer: state.peer,
                    share,
                    rel_path,
                })
            }
            _ => None,
        }
    }

    /// The Downloads tab's own keys: move the selection, and act on the
    /// row it is on. Every one of them is named on screen, since none is
    /// a convention a user could be expected to guess.
    fn handle_shared_downloads_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let rows: Vec<(u64, bool, bool)> = self
            .shared_download_rows()
            .iter()
            .map(|d| (d.request_id, d.status.is_active(), d.is_clearable()))
            .collect();
        let state = self.shared_browser.as_mut()?;
        state.download_selected = state.download_selected.min(rows.len().saturating_sub(1));
        let selected = rows.get(state.download_selected).copied();
        match code {
            KeyCode::Esc => {
                self.shared_browser = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Up => {
                state.download_selected = state.download_selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if state.download_selected + 1 < rows.len() {
                    state.download_selected += 1;
                }
                None
            }
            KeyCode::Char('c') => {
                let (request_id, active, _) = selected?;
                active.then_some(UiAction::CancelSharedDownload { request_id })
            }
            KeyCode::Char('r') => {
                let (request_id, active, _) = selected?;
                (!active).then_some(UiAction::ResumeSharedDownload { request_id })
            }
            KeyCode::Char('x') | KeyCode::Delete => {
                let (request_id, _, clearable) = selected?;
                if clearable {
                    self.clear_shared_download(request_id);
                }
                None
            }
            KeyCode::Char('X') => {
                self.clear_finished_shared_downloads();
                None
            }
            _ => None,
        }
    }

    fn ask_listing(state: &mut SharedBrowserState) -> UiAction {
        state.loading = true;
        state.error = None;
        state.truncated = false;
        state.entries.clear();
        state.selected = 0;
        UiAction::RequestSharedListing {
            peer: state.peer,
            share: state.share.clone().unwrap_or_default(),
            rel_path: state.rel_path.clone(),
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

const POPUP_WIDTH: u16 = 96;
const POPUP_HEIGHT: u16 = 26;
const TIME_WIDTH: usize = 16;
const SIZE_WIDTH: usize = 10;

/// `YYYY-MM-DD HH:MM` in local time, or `-` where the filesystem
/// recorded nothing - the two time columns.
pub fn format_entry_time(unix: Option<u64>) -> String {
    match unix {
        Some(ts) => super::contacts::format_last_seen(Some(ts)),
        None => "-".to_string(),
    }
}

/// One row as the list shows it: name, created, updated, size - the
/// name given whatever width the other three leave.
pub fn format_entry_row(entry: &SharedEntry, width: usize) -> String {
    let name_width = width.saturating_sub(TIME_WIDTH * 2 + SIZE_WIDTH + 6).max(8);
    let mut name: String = if entry.is_dir {
        format!("{}/", entry.name)
    } else {
        entry.name.clone()
    };
    if name.chars().count() > name_width {
        name = name.chars().take(name_width.saturating_sub(1)).collect::<String>() + "\u{2026}";
    }
    let size = if entry.is_dir { String::new() } else { format_size(entry.size) };
    format!(
        "{name:<name_width$}  {:<TIME_WIDTH$}  {:<TIME_WIDTH$}  {size:>SIZE_WIDTH$}",
        format_entry_time(entry.created_unix),
        format_entry_time(entry.modified_unix),
    )
}

pub(crate) fn render_shared_browser_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(browser) = &state.shared_browser else { return };
    let popup = centered_rect(POPUP_WIDTH, POPUP_HEIGHT, area);
    // The title says what is going on elsewhere in the popup, so a
    // download running behind the Files tab is not invisible.
    let active = state.active_shared_downloads();
    let downloads_tab = if active > 0 {
        format!("Downloading {active}...")
    } else {
        "Downloads".to_string()
    };
    let title = match browser.tab {
        SharedBrowserTab::Files => format!(
            "{}'s shared files: {} \u{2502} Tab: {downloads_tab}",
            browser.peer_name,
            browser.location()
        ),
        SharedBrowserTab::Downloads => format!("{downloads_tab} \u{2502} Tab: files"),
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    if browser.tab == SharedBrowserTab::Downloads {
        render_downloads_tab(frame, inner, state, browser.download_selected);
        return;
    }

    let help = Rect { height: 1.min(inner.height), ..inner };
    frame.render_widget(
        Paragraph::new("Enter: open folder \u{2502} Backspace: up \u{2502} d: download file or folder \u{2502} Esc: close")
            .style(Style::default().fg(Color::DarkGray)),
        help,
    );
    let header = Rect {
        y: inner.y.saturating_add(1),
        height: 1.min(inner.height.saturating_sub(1)),
        ..inner
    };
    let width = inner.width as usize;
    let name_width = width.saturating_sub(TIME_WIDTH * 2 + SIZE_WIDTH + 6).max(8);
    frame.render_widget(
        Paragraph::new(format!(
            "{:<name_width$}  {:<TIME_WIDTH$}  {:<TIME_WIDTH$}  {:>SIZE_WIDTH$}",
            "name", "created", "updated", "size"
        ))
        .style(Style::default().add_modifier(Modifier::BOLD)),
        header,
    );
    let body = Rect {
        y: inner.y.saturating_add(2),
        height: inner.height.saturating_sub(3),
        ..inner
    };
    if browser.loading {
        frame.render_widget(
            Paragraph::new("loading\u{2026}").style(Style::default().fg(Color::DarkGray)),
            body,
        );
    } else if let Some(error) = &browser.error {
        // The way out is named with the failure: a folder that would not
        // open leaves nothing on screen to act on, so the keys that still
        // do something are worth repeating here.
        let lines = vec![
            Line::from(Span::styled(error.clone(), Style::default().fg(Color::Red))),
            Line::from(""),
            Line::from(Span::styled(
                if browser.share.is_some() {
                    "Backspace: back to their folders \u{2502} Esc: close"
                } else {
                    "Esc: close"
                },
                Style::default().fg(Color::DarkGray),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), body);
    } else if browser.entries.is_empty() {
        frame.render_widget(
            Paragraph::new("(empty)").style(Style::default().fg(Color::DarkGray)),
            body,
        );
    } else {
        let items: Vec<ListItem> = browser
            .entries
            .iter()
            .map(|e| {
                let style = if e.is_dir {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(format_entry_row(e, width), style)))
            })
            .collect();
        let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        let mut list_state = ListState::default();
        list_state.select(Some(browser.selected.min(browser.entries.len() - 1)));
        frame.render_stateful_widget(list, body, &mut list_state);
    }
    if browser.truncated {
        let foot = Rect {
            y: inner.y.saturating_add(inner.height.saturating_sub(1)),
            height: 1.min(inner.height),
            ..inner
        };
        frame.render_widget(
            Paragraph::new(format!(
                "only the first {} entries are shown",
                shared_folders::MAX_SHARED_ENTRIES_PER_RESPONSE
            ))
            .style(Style::default().fg(Color::Yellow)),
            foot,
        );
    }
}

/// The Downloads tab: one block per download, everything still going
/// above everything finished with (`UiState::shared_download_rows`), each
/// with the same progress bar a pad transfer draws
/// (`widgets::progress_bar`).
fn render_downloads_tab(frame: &mut Frame, inner: Rect, state: &UiState, selected: usize) {
    let help = Rect { height: 1.min(inner.height), ..inner };
    frame.render_widget(
        Paragraph::new(
            "c: cancel \u{2502} r: resume \u{2502} x: remove \u{2502} X: clear finished \u{2502} Tab: files \u{2502} Esc: close",
        )
        .style(Style::default().fg(Color::DarkGray)),
        help,
    );
    let body = Rect {
        y: inner.y.saturating_add(2),
        height: inner.height.saturating_sub(2),
        ..inner
    };
    let rows = state.shared_download_rows();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new("nothing downloaded from them yet - press Tab, pick a folder, and press d")
                .style(Style::default().fg(Color::DarkGray)),
            body,
        );
        return;
    }

    // Two rows each: what it is and where it is up to, then its bar.
    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in rows.iter().enumerate() {
        let marker = if i == selected { "\u{25b8} " } else { "  " };
        let (color, status) = match &item.status {
            SharedDownloadStatus::Asking | SharedDownloadStatus::Running => {
                (Color::Yellow, item.status.label())
            }
            SharedDownloadStatus::Completed => (Color::Green, item.status.label()),
            SharedDownloadStatus::Cancelled => (Color::DarkGray, item.status.label()),
            SharedDownloadStatus::Failed(_) => (Color::Red, item.status.label()),
        };
        let counted = match item.files_total {
            Some(total) => format!("{}/{total} files", item.files_done),
            None => format!("{} files", item.files_done),
        };
        let skipped = if item.files_skipped > 0 {
            format!(", {} already had", item.files_skipped)
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{marker}{} ", item.label()),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("from {}", item.peer_name), Style::default().fg(Color::Gray)),
            Span::raw("  "),
            Span::styled(status, Style::default().fg(color)),
            Span::styled(format!("  {counted}{skipped}"), Style::default().fg(Color::DarkGray)),
        ]));
        let suffix = match item.fraction() {
            Some(f) => format!("  {}%  {}", percent_of(f), format_size(item.bytes_done)),
            None => format!("  {}", format_size(item.bytes_done)),
        };
        let mut bar = progress_line(item.fraction().unwrap_or(0.0), DEFAULT_BAR_CELLS, color, &suffix)
            .spans;
        bar.insert(0, Span::raw("  "));
        lines.push(Line::from(bar));
        lines.push(Line::from(""));
    }
    frame.render_widget(Paragraph::new(lines), body);
}
