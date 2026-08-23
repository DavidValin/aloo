//! The `/file` send flow: browse the local filesystem for a file, then
//! confirm ("Send file" / "Discard", Discard focused by default) before it's
//! actually read, encrypted and sent. Mirrors `crate::client::tui::channel`/
//! `crate::client::tui::direct_message`'s split (state/rendering for one concern,
//! `impl UiState` on top of the struct defined in `crate::client::tui::ui`) rather
//! than living inline there.
//!
//! Reuses `crate::client::file_browser::FileBrowserState` as-is (a generic,
//! fs-backed directory browser with back/forward history) instead of a
//! second copy of the same widget.

use std::path::PathBuf;

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::proto::UserId;

use super::ui::{Mode, UiAction, UiState, centered_rect, render_file_browser, render_popup_button};
use crate::client::file_browser::FileBrowserState;

/// Who a file send is addressed to - just the identity, not a frozen
/// recipient list: recipients are recomputed fresh at confirm-time (see
/// `UiState::confirm_file_send`), since a file-browsing session can run
/// long and channel membership/offline/trust state keeps updating in the
/// background the whole time it's open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileSendTarget {
    Channel(String),
    Direct(UserId),
}

/// Which button is focused in the Send file/Discard confirmation box -
/// `Discard` by default, same reasoning as `ui::IdentityChoice`'s
/// `Reject`-first default: the safer action should never be a single
/// accidental Enter away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileConfirmChoice {
    Send,
    #[default]
    Discard,
}

pub struct FileSendState {
    pub target: FileSendTarget,
    pub browser: FileBrowserState,
    /// `Some(path)` once a file has been selected from the browser - the
    /// confirmation box replaces the browser popup while this is set,
    /// exactly as specified: pressing Esc (or choosing Discard) clears just
    /// this field, returning to the browser at the same directory rather
    /// than closing the whole flow.
    pub confirm: Option<PathBuf>,
    pub confirm_focus: FileConfirmChoice,
    /// Set when the selected file can't even be stat'd (e.g. removed or
    /// permissions changed between being picked in the browser and Send
    /// being confirmed) - shown inline on the confirmation box, same
    /// convention as `ui_connect_popup::ConnectPopupState::error`. There is
    /// no size cap to fail here (`docs/PROTOCOL.md`'s file transfer
    /// section) - a file transfer is streamed, not read whole.
    pub error: Option<String>,
}

impl UiState {
    /// Entry point for `/file` + Enter (`UiState::submit_input`). Resolves
    /// a target with the same addressability guards as
    /// `current_voice_target`, then opens the browser rooted at the
    /// current directory (real filesystem I/O, same precedent as
    /// `ConnectPopupState::open_browser`). On any failure, `input` is left
    /// untouched so the user can see what they typed and retry.
    pub(crate) fn start_file_send(&mut self) -> Option<UiAction> {
        let target = if let Some(peer_id) = self.active_private_room {
            if self.offline.contains(&peer_id) || self.is_trust_gated(peer_id) {
                return None;
            }
            self.known_users.get(&peer_id)?;
            FileSendTarget::Direct(peer_id)
        } else {
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            FileSendTarget::Channel(channel.name.clone())
        };
        let start_dir = std::env::current_dir().ok()?;
        let browser = FileBrowserState::open(start_dir).ok()?;
        self.input.clear();
        self.file_send = Some(FileSendState {
            target,
            browser,
            confirm: None,
            confirm_focus: FileConfirmChoice::Discard,
            error: None,
        });
        self.mode = Mode::FileSend;
        None
    }

    pub(crate) fn handle_file_send_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let is_confirming = self
            .file_send
            .as_ref()
            .map(|s| s.confirm.is_some())
            .unwrap_or(false);
        if is_confirming {
            return self.handle_file_confirm_key(code);
        }
        self.handle_file_browser_key(code)
    }

    fn handle_file_browser_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let Some(state) = self.file_send.as_mut() else {
            return None;
        };
        match code {
            KeyCode::Up => {
                state.browser.select_prev();
                None
            }
            KeyCode::Down => {
                state.browser.select_next();
                None
            }
            KeyCode::Left => {
                let _ = state.browser.go_back();
                None
            }
            KeyCode::Right => {
                let _ = state.browser.go_forward();
                None
            }
            KeyCode::Esc => {
                self.file_send = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Enter => {
                let Some(entry) = state.browser.selected_entry() else {
                    return None;
                };
                if entry.is_dir {
                    let _ = state.browser.navigate_into_selected();
                } else if let Some(path) = state.browser.selected_path() {
                    state.confirm = Some(path);
                    state.confirm_focus = FileConfirmChoice::Discard;
                    state.error = None;
                }
                None
            }
            _ => None,
        }
    }

    fn handle_file_confirm_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.file_send.as_mut() {
                    state.confirm = None;
                    state.error = None;
                }
                None
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                if let Some(state) = self.file_send.as_mut() {
                    state.confirm_focus = match state.confirm_focus {
                        FileConfirmChoice::Send => FileConfirmChoice::Discard,
                        FileConfirmChoice::Discard => FileConfirmChoice::Send,
                    };
                }
                None
            }
            KeyCode::Enter => {
                let focus = self.file_send.as_ref()?.confirm_focus;
                match focus {
                    FileConfirmChoice::Discard => {
                        if let Some(state) = self.file_send.as_mut() {
                            state.confirm = None;
                            state.error = None;
                        }
                        None
                    }
                    FileConfirmChoice::Send => self.confirm_file_send(),
                }
            }
            _ => None,
        }
    }

    /// Stats the selected file (never reads its contents - streaming only
    /// starts once the recipient accepts) and emits the send action,
    /// closing the `/file` flow. Outgoing log rows aren't pushed here: the
    /// `stream_id` they're keyed by isn't allocated until the
    /// `handle_send_file`s run - whoever allocates the stream id logs the
    /// row, as with voice. Recipients are resolved fresh rather than from
    /// when `/file` was typed: the browse+confirm detour can take a while
    /// and membership/offline/trust state keeps updating meanwhile.
    fn confirm_file_send(&mut self) -> Option<UiAction> {
        let path = self.file_send.as_ref()?.confirm.clone()?;

        let size = match std::fs::metadata(&path) {
            Ok(meta) => meta.len(),
            Err(e) => {
                if let Some(state) = self.file_send.as_mut() {
                    state.error = Some(format!("{e}"));
                }
                return None;
            }
        };

        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());
        let filename = crate::client::file_transfer::truncate_filename(&filename);

        let target = self.file_send.as_ref()?.target.clone();
        let action = match target {
            FileSendTarget::Channel(name) => {
                let tab = self.channels.iter().find(|c| c.name == name)?;
                let recipients = self.recipients_for_channel(tab);
                UiAction::SendFileChannel {
                    channel: name,
                    path,
                    filename,
                    size,
                    recipients,
                }
            }
            FileSendTarget::Direct(peer_id) => {
                if self.offline.contains(&peer_id) || self.is_trust_gated(peer_id) {
                    self.file_send = None;
                    self.mode = Mode::Normal;
                    return None;
                }
                let peer = self.known_users.get(&peer_id)?.clone();
                UiAction::SendFileDirect {
                    to: peer_id,
                    path,
                    filename,
                    size,
                    recipient_pubkey_der: peer.public_key_der,
                }
            }
        };

        self.file_send = None;
        self.mode = Mode::Normal;
        Some(action)
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_file_send_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(fs) = &state.file_send else { return };
    match &fs.confirm {
        None => render_file_browser(frame, area, &fs.browser, "Send file"),
        Some(path) => render_confirm(frame, area, state, fs, path),
    }
}

fn render_confirm(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    fs: &FileSendState,
    path: &std::path::Path,
) {
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let target_label = match &fs.target {
        FileSendTarget::Channel(name) => format!("#{name}"),
        FileSendTarget::Direct(peer_id) => state
            .known_users
            .get(peer_id)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| "?".to_string()),
    };

    let popup = centered_rect(64, 9, area);
    let block = Block::default().title("Send file").borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    let mut lines = vec![Line::from(format!(
        "Send \"{filename}\" to {target_label}?"
    ))];
    if let Some(err) = &fs.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[0]);

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(
        frame,
        button_cols[0],
        18,
        "Send file",
        fs.confirm_focus == FileConfirmChoice::Send,
    );
    render_popup_button(
        frame,
        button_cols[1],
        18,
        "Discard",
        fs.confirm_focus == FileConfirmChoice::Discard,
    );
}
