//! The `/contacts` modal: every pinned identity (`idstore.rs`), one row
//! each - nickname, when it was last confirmed reachable, how it's
//! encrypted, and - for a contact that also has a one-time-pad set up -
//! that pad's live figures in each direction, read the same way the
//! `/otp` DM header does
//! (`crate::client::tui::direct_message::render_otp_header`). The key
//! files themselves aren't shown here - a full path per direction made
//! rows too wide to read at a glance - though `i` on a message still
//! names the one file that message's own encryption used.
//!
//! Two actions live here: deleting a contact outright (its identity pin,
//! and its OTP keychain entry if it has one), and installing an OTP key
//! manually - the UI counterpart to running the real `otp` command
//! yourself and placing the keys under `~/.aloo/otp/.keychain/`, already
//! documented in the help overlay's OTP section, now with a form instead
//! of hand-editing file paths.
//!
//! Mirrors `crate::client::tui::file_send`'s split: state/handling here as
//! `impl UiState`, rendering as free functions taking `&UiState`. Row data
//! is never gathered in this module - `client::contacts::gather_contact_rows`
//! is session-side (it shells out to the real `otp` binary to read each
//! contact's live pad figures) - `UiState::set_contacts_rows` is simply
//! handed whatever the session last computed.

use std::path::PathBuf;

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::client::contacts::{ContactOtpDetail, ContactRow};
use crate::client::file_browser::FileBrowserState;
use crate::proto::KeyMode;

use super::direct_message::OTP_KEY_LOW_THRESHOLD_BYTES;
use super::ui::{
    Mode, UiAction, UiState, centered_rect, display_width, render_file_browser,
    render_popup_button,
};

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

/// Which button is focused on the delete-confirmation popup - `Cancel` by
/// default, the same "a destructive action is never one accidental Enter
/// away" reasoning as `file_send::FileConfirmChoice`'s `Discard` default
/// and `ui::IdentityChoice`'s `Reject` default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeleteChoice {
    Delete,
    #[default]
    Cancel,
}

/// Which field is focused inside the "Install OTP key" popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallField {
    EncPath,
    DecPath,
    Install,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallBrowserTarget {
    Enc,
    Dec,
}

/// The "Install OTP key" popup's state: two file paths (picked with the
/// same in-TUI browser every other key-file field in this app uses -
/// `ui_connect_popup`/`file_send`), a submit button, and an inline error
/// for whatever `otp --add-contact` refuses.
pub struct InstallOtpState {
    pub enc_path: String,
    pub dec_path: String,
    pub focus: InstallField,
    /// `pub`, not `pub(crate)`, same reasoning as
    /// `ui_connect_popup::ConnectPopupState::browser`/
    /// `file_send::FileSendState::browser`: a test opening this popup
    /// needs to overwrite the browser with a deterministic temp directory
    /// after `open_contacts_install_browser` opens one at the process's
    /// real current directory.
    pub browser: Option<(InstallBrowserTarget, FileBrowserState)>,
    pub error: Option<String>,
}

pub struct ContactsState {
    pub rows: Vec<ContactRow>,
    pub selected: usize,
    /// `Some` while the delete-confirmation popup is open, over the row
    /// selected when `d`/Delete was pressed.
    pub confirm_delete: Option<DeleteChoice>,
    /// `Some` while the "Install OTP key" popup is open, over the row
    /// selected when `o` was pressed.
    pub install: Option<InstallOtpState>,
}

impl UiState {
    /// Opens the modal empty and lets the caller (`submit_input`'s
    /// `/contacts` arm) also return `UiAction::OpenContacts` so the
    /// session fills it in - mirrors `open_otp_mail` + `OpenOtpMailbox`'s
    /// same split.
    pub fn open_contacts(&mut self) {
        self.mode = Mode::Contacts;
        self.contacts = Some(ContactsState {
            rows: Vec::new(),
            selected: 0,
            confirm_delete: None,
            install: None,
        });
    }

    /// `OpenContacts`/`RefreshContacts`'s answer: replaces the row set in
    /// place, clamping the selection rather than resetting it so a manual
    /// refresh doesn't jump back to the top of a long list. A no-op if the
    /// modal was closed in the meantime (the session's answer arrived
    /// after Esc).
    pub fn set_contacts_rows(&mut self, rows: Vec<ContactRow>) {
        let Some(state) = self.contacts.as_mut() else {
            return;
        };
        state.rows = rows;
        state.selected = if state.rows.is_empty() {
            0
        } else {
            state.selected.min(state.rows.len() - 1)
        };
    }

    /// The install popup's failure path - shown inline, same convention as
    /// `file_send::FileSendState::error`. A no-op if the popup isn't open
    /// any more (closed before the session's answer arrived).
    pub fn set_contacts_install_error(&mut self, message: String) {
        if let Some(install) = self.contacts.as_mut().and_then(|c| c.install.as_mut()) {
            install.error = Some(message);
        }
    }

    /// The install popup's success path - drops back to the list, which
    /// the caller (`client::contacts::handle_install_otp_key`) refreshes
    /// right after.
    pub fn close_contacts_install(&mut self) {
        if let Some(state) = self.contacts.as_mut() {
            state.install = None;
        }
    }

    pub(crate) fn handle_contacts_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let has_install = self
            .contacts
            .as_ref()
            .map(|c| c.install.is_some())
            .unwrap_or(false);
        if has_install {
            return self.handle_contacts_install_key(code);
        }
        let has_confirm = self
            .contacts
            .as_ref()
            .map(|c| c.confirm_delete.is_some())
            .unwrap_or(false);
        if has_confirm {
            return self.handle_contacts_delete_confirm_key(code);
        }
        self.handle_contacts_list_key(code)
    }

    fn handle_contacts_list_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let len = self.contacts.as_ref()?.rows.len();
        match code {
            KeyCode::Esc => {
                self.contacts = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Up => {
                if len > 0
                    && let Some(state) = self.contacts.as_mut()
                {
                    state.selected = (state.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                if len > 0
                    && let Some(state) = self.contacts.as_mut()
                {
                    state.selected = (state.selected + 1) % len;
                }
                None
            }
            KeyCode::Char('r') => Some(UiAction::RefreshContacts),
            KeyCode::Char('d') | KeyCode::Delete => {
                if len == 0 {
                    return None;
                }
                if let Some(state) = self.contacts.as_mut() {
                    state.confirm_delete = Some(DeleteChoice::default());
                }
                None
            }
            KeyCode::Char('o') => {
                let row = self.contacts.as_ref()?.rows.get(self.contacts.as_ref()?.selected)?.clone();
                if row.otp_contact_name.is_none() {
                    self.push_status_notice(
                        "no keychain name could be derived for this contact".to_string(),
                        false,
                    );
                    return None;
                }
                if let Some(state) = self.contacts.as_mut() {
                    state.install = Some(InstallOtpState {
                        enc_path: String::new(),
                        dec_path: String::new(),
                        focus: InstallField::EncPath,
                        browser: None,
                        error: None,
                    });
                }
                None
            }
            _ => None,
        }
    }

    fn handle_contacts_delete_confirm_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.contacts.as_mut() {
                    state.confirm_delete = None;
                }
                None
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                if let Some(state) = self.contacts.as_mut() {
                    state.confirm_delete = Some(match state.confirm_delete {
                        Some(DeleteChoice::Delete) => DeleteChoice::Cancel,
                        _ => DeleteChoice::Delete,
                    });
                }
                None
            }
            KeyCode::Enter => {
                let (choice, nickname) = {
                    let state = self.contacts.as_ref()?;
                    (state.confirm_delete?, state.rows.get(state.selected)?.nickname.clone())
                };
                if let Some(state) = self.contacts.as_mut() {
                    state.confirm_delete = None;
                }
                match choice {
                    DeleteChoice::Cancel => None,
                    DeleteChoice::Delete => Some(UiAction::DeleteContact { nickname }),
                }
            }
            _ => None,
        }
    }

    fn handle_contacts_install_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let has_browser = self
            .contacts
            .as_ref()
            .and_then(|c| c.install.as_ref())
            .map(|i| i.browser.is_some())
            .unwrap_or(false);
        if has_browser {
            return self.handle_contacts_install_browser_key(code);
        }
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.contacts.as_mut() {
                    state.install = None;
                }
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if let Some(install) = self.contacts.as_mut().and_then(|c| c.install.as_mut()) {
                    install.focus = match (install.focus, code) {
                        (InstallField::EncPath, KeyCode::BackTab) => InstallField::Install,
                        (InstallField::EncPath, _) => InstallField::DecPath,
                        (InstallField::DecPath, KeyCode::BackTab) => InstallField::EncPath,
                        (InstallField::DecPath, _) => InstallField::Install,
                        (InstallField::Install, KeyCode::BackTab) => InstallField::DecPath,
                        (InstallField::Install, _) => InstallField::EncPath,
                    };
                }
                None
            }
            KeyCode::Backspace => {
                if let Some(install) = self.contacts.as_mut().and_then(|c| c.install.as_mut()) {
                    match install.focus {
                        InstallField::EncPath => {
                            install.enc_path.pop();
                        }
                        InstallField::DecPath => {
                            install.dec_path.pop();
                        }
                        InstallField::Install => {}
                    }
                }
                None
            }
            KeyCode::Char(c) => {
                if let Some(install) = self.contacts.as_mut().and_then(|c| c.install.as_mut()) {
                    match install.focus {
                        InstallField::EncPath => install.enc_path.push(c),
                        InstallField::DecPath => install.dec_path.push(c),
                        InstallField::Install => {}
                    }
                }
                None
            }
            KeyCode::Enter => self.activate_contacts_install_focused(),
            _ => None,
        }
    }

    fn activate_contacts_install_focused(&mut self) -> Option<UiAction> {
        let focus = self.contacts.as_ref()?.install.as_ref()?.focus;
        match focus {
            InstallField::EncPath => self.open_contacts_install_browser(InstallBrowserTarget::Enc),
            InstallField::DecPath => self.open_contacts_install_browser(InstallBrowserTarget::Dec),
            InstallField::Install => self.confirm_install_otp_key(),
        }
    }

    fn open_contacts_install_browser(&mut self, target: InstallBrowserTarget) -> Option<UiAction> {
        let start = std::env::current_dir().ok()?;
        let browser = FileBrowserState::open(start).ok()?;
        if let Some(install) = self.contacts.as_mut().and_then(|c| c.install.as_mut()) {
            install.browser = Some((target, browser));
        }
        None
    }

    fn handle_contacts_install_browser_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Up => {
                if let Some(browser) = self.contacts_install_browser_mut() {
                    browser.select_prev();
                }
                None
            }
            KeyCode::Down => {
                if let Some(browser) = self.contacts_install_browser_mut() {
                    browser.select_next();
                }
                None
            }
            KeyCode::Left => {
                if let Some(browser) = self.contacts_install_browser_mut() {
                    let _ = browser.go_back();
                }
                None
            }
            KeyCode::Right => {
                if let Some(browser) = self.contacts_install_browser_mut() {
                    let _ = browser.go_forward();
                }
                None
            }
            KeyCode::Esc => {
                if let Some(install) = self.contacts.as_mut().and_then(|c| c.install.as_mut()) {
                    install.browser = None;
                }
                None
            }
            KeyCode::Enter => {
                let install = self.contacts.as_mut()?.install.as_mut()?;
                let (target, browser) = install.browser.as_mut()?;
                let target = *target;
                let entry = browser.selected_entry()?;
                if entry.is_dir {
                    let _ = browser.navigate_into_selected();
                } else if let Some(path) = browser.selected_path() {
                    let s = path.display().to_string();
                    match target {
                        InstallBrowserTarget::Enc => install.enc_path = s,
                        InstallBrowserTarget::Dec => install.dec_path = s,
                    }
                    install.browser = None;
                }
                None
            }
            _ => None,
        }
    }

    fn contacts_install_browser_mut(&mut self) -> Option<&mut FileBrowserState> {
        self.contacts
            .as_mut()?
            .install
            .as_mut()?
            .browser
            .as_mut()
            .map(|(_, browser)| browser)
    }

    /// Both paths are required and, up front, must at least exist -
    /// `client::contacts::validate_key_file` re-checks this session-side
    /// too (never trust a UI-layer check alone for something about to
    /// reach a subprocess), but failing fast here means a typo'd path
    /// never even leaves this process.
    fn confirm_install_otp_key(&mut self) -> Option<UiAction> {
        let (nickname, enc_path, dec_path) = {
            let state = self.contacts.as_ref()?;
            let row = state.rows.get(state.selected)?;
            let install = state.install.as_ref()?;
            (
                row.nickname.clone(),
                install.enc_path.trim().to_string(),
                install.dec_path.trim().to_string(),
            )
        };
        if enc_path.is_empty() || dec_path.is_empty() {
            self.set_contacts_install_error("both key files are required".to_string());
            return None;
        }
        Some(UiAction::InstallOtpKey {
            nickname,
            enc_path: PathBuf::from(enc_path),
            dec_path: PathBuf::from(dec_path),
        })
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// Converts a stored `last_seen_unix` into a short local-time string -
/// `"never"` (gray) if the contact has never been confirmed reachable.
/// Uses the *current* local UTC offset even for an old timestamp (no DST
/// transition history is tracked) - the same simplification
/// `otp_mail::format_utc_short` already makes for UTC, just localized;
/// falls back to a UTC-labeled rendering if the local offset can't be
/// determined at all (`time::UtcOffset::current_local_offset`'s doc).
fn format_last_seen(last_seen_unix: Option<u64>) -> String {
    let Some(ts) = last_seen_unix else {
        return "never".to_string();
    };
    let Ok(utc) = time::OffsetDateTime::from_unix_timestamp(ts as i64) else {
        return "never".to_string();
    };
    let (dt, suffix) = match time::UtcOffset::current_local_offset() {
        Ok(offset) => (utc.to_offset(offset), ""),
        Err(_) => (utc, " UTC"),
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}{suffix}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

fn encryption_label(key_mode: Option<KeyMode>) -> &'static str {
    match key_mode {
        Some(mode) => mode.label(),
        None => "\u{2753} unknown",
    }
}

/// One direction's three OTP sub-columns (`seq`/`offset`/`remaining`),
/// measured independently so `12 340 1.23MB` and `4 8000 0.40MB` still line
/// their three fields up under each other, rather than only the row as a
/// whole coming out the same width.
#[derive(Debug, Clone, Copy, Default)]
struct OtpDirectionColumns {
    seq: usize,
    offset: usize,
    remaining: usize,
}

impl OtpDirectionColumns {
    /// `get` pulls this one direction's `(seq, offset, remaining_bytes)`
    /// out of a contact that has OTP installed - rows without one
    /// contribute nothing to the measurement, same as every other column
    /// here only widening for the values actually shown.
    fn measure(rows: &[ContactRow], get: impl Fn(&ContactOtpDetail) -> (u64, u64, u64)) -> Self {
        let values: Vec<(u64, u64, u64)> = rows.iter().filter_map(|r| r.otp.as_ref().map(&get)).collect();
        let seq = values
            .iter()
            .map(|(s, _, _)| digit_width(*s))
            .max()
            .unwrap_or(0)
            .max(display_width("seq") as usize);
        let offset = values
            .iter()
            .map(|(_, o, _)| digit_width(*o))
            .max()
            .unwrap_or(0)
            .max(display_width("offset") as usize);
        let remaining = values
            .iter()
            .map(|(_, _, r)| display_width(&fmt_mb(*r)) as usize)
            .max()
            .unwrap_or(0)
            .max(display_width("remaining") as usize);
        Self { seq, offset, remaining }
    }

    /// This direction's total width, the label included: `"dec: "` (or
    /// `"enc: "`) plus its three padded fields and the single-space gaps
    /// between them.
    fn width(self) -> usize {
        DIRECTION_LABEL_WIDTH + self.seq + 1 + self.offset + 1 + self.remaining
    }
}

/// `"dec: "` / `"enc: "` - both exactly this wide, so neither direction's
/// label ever throws off the other's alignment.
const DIRECTION_LABEL_WIDTH: usize = 5;

fn digit_width(n: u64) -> usize {
    display_width(&n.to_string()) as usize
}

/// `<remaining>MB`, formatted exactly like
/// `direct_message::push_otp_key_spans` - the same figure the `/otp` DM
/// header shows, so a contact's remaining-key reads identically wherever
/// it appears.
fn fmt_mb(remaining_bytes: u64) -> String {
    format!("{:.2}MB", remaining_bytes as f64 / (1024.0 * 1024.0))
}

/// The widths of every column, measured across the whole row set so they
/// line up down the list - the same idiom `ui::CallColumns` uses for the
/// call modal's roster.
struct ContactsColumns {
    nickname: usize,
    last_seen: usize,
    encryption: usize,
    dec: OtpDirectionColumns,
    enc: OtpDirectionColumns,
}

impl ContactsColumns {
    fn measure(rows: &[ContactRow]) -> Self {
        let nickname = rows
            .iter()
            .map(|r| display_width(&r.nickname) as usize)
            .max()
            .unwrap_or(0)
            .max(display_width("nickname") as usize);
        let last_seen = rows
            .iter()
            .map(|r| display_width(&format_last_seen(r.last_seen_unix)) as usize)
            .max()
            .unwrap_or(0)
            .max(display_width("last seen") as usize);
        let encryption = rows
            .iter()
            .map(|r| display_width(encryption_label(r.key_mode)) as usize)
            .max()
            .unwrap_or(0)
            .max(display_width("encryption") as usize);
        let dec = OtpDirectionColumns::measure(rows, |o| {
            (o.dec_sequence, o.dec_offset, o.dec_key_remaining)
        });
        let enc = OtpDirectionColumns::measure(rows, |o| {
            (o.enc_sequence, o.enc_offset, o.enc_key_remaining)
        });
        Self {
            nickname,
            last_seen,
            encryption,
            dec,
            enc,
        }
    }

    /// The whole OTP section's width (both directions plus the gap
    /// between them) - what `render_contacts_popup` adds to the other four
    /// columns to size the modal, instead of a guessed constant.
    fn otp_section_width(&self) -> usize {
        self.dec.width() + COL_GAP + self.enc.width()
    }
}

/// One column's gap to the next.
const COL_GAP: usize = 2;

fn pad_to(spans: &mut Vec<Span<'static>>, width: usize) {
    let used: usize = spans.iter().map(|s| display_width(&s.content) as usize).sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
}

/// Right-aligns `text` to `width` display columns - numeric fields read
/// naturally lined up on their ones digit, the same convention a plain
/// table would use.
fn pad_right_align(text: &str, width: usize) -> String {
    let used = display_width(text) as usize;
    if used < width {
        format!("{}{text}", " ".repeat(width - used))
    } else {
        text.to_string()
    }
}

/// Pushes one direction's `label: seq offset remainingMB`, every field
/// right-aligned to `cols`' measured widths - the row-level counterpart of
/// `direct_message::push_otp_key_spans`, which only ever draws one
/// direction with nothing else around it to line up against.
fn push_otp_direction_columns(
    spans: &mut Vec<Span<'static>>,
    label: &str,
    seq: u64,
    offset: u64,
    remaining_bytes: u64,
    cols: OtpDirectionColumns,
) {
    spans.push(Span::styled(
        format!("{label}: "),
        Style::default().fg(Color::Gray),
    ));
    spans.push(Span::styled(
        pad_right_align(&seq.to_string(), cols.seq),
        Style::default().fg(Color::Gray),
    ));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        pad_right_align(&offset.to_string(), cols.offset),
        Style::default().fg(Color::Gray),
    ));
    spans.push(Span::raw(" "));
    let remaining_color = if remaining_bytes < OTP_KEY_LOW_THRESHOLD_BYTES {
        Color::Red
    } else {
        Color::Green
    };
    spans.push(Span::styled(
        pad_right_align(&fmt_mb(remaining_bytes), cols.remaining),
        Style::default().fg(remaining_color),
    ));
}

/// The same direction block, headed by column labels rather than values -
/// `seq`/`offset`/`remaining`, each right-aligned the same way the data
/// rows are, so the header sits directly above the figures it names.
fn push_otp_direction_header(spans: &mut Vec<Span<'static>>, label: &str, cols: OtpDirectionColumns) {
    let style = Style::default().add_modifier(Modifier::BOLD);
    spans.push(Span::styled(format!("{label}: "), style));
    spans.push(Span::styled(pad_right_align("seq", cols.seq), style));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(pad_right_align("offset", cols.offset), style));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(pad_right_align("remaining", cols.remaining), style));
}

fn header_row(columns: &ContactsColumns) -> Line<'static> {
    let mut spans = vec![Span::styled(
        "nickname",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    pad_to(&mut spans, columns.nickname);
    spans.push(Span::raw(" ".repeat(COL_GAP)));
    let start = spans.iter().map(|s| display_width(&s.content) as usize).sum::<usize>();
    spans.push(Span::styled(
        "last seen",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    pad_to(&mut spans, start + columns.last_seen);
    spans.push(Span::raw(" ".repeat(COL_GAP)));
    let start = spans.iter().map(|s| display_width(&s.content) as usize).sum::<usize>();
    spans.push(Span::styled(
        "encryption",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    pad_to(&mut spans, start + columns.encryption);
    spans.push(Span::raw(" ".repeat(COL_GAP)));
    push_otp_direction_header(&mut spans, "dec", columns.dec);
    spans.push(Span::raw(" ".repeat(COL_GAP)));
    push_otp_direction_header(&mut spans, "enc", columns.enc);
    Line::from(spans)
}

fn contact_row_line(row: &ContactRow, columns: &ContactsColumns) -> Line<'static> {
    let mut spans = vec![Span::raw(row.nickname.clone())];
    pad_to(&mut spans, columns.nickname);
    spans.push(Span::raw(" ".repeat(COL_GAP)));

    let last_seen = format_last_seen(row.last_seen_unix);
    let last_seen_style = if row.last_seen_unix.is_some() {
        Style::default()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let start = spans.iter().map(|s| display_width(&s.content) as usize).sum::<usize>();
    spans.push(Span::styled(last_seen.clone(), last_seen_style));
    pad_to(&mut spans, start + columns.last_seen);
    spans.push(Span::raw(" ".repeat(COL_GAP)));

    let encryption = encryption_label(row.key_mode);
    let start = spans.iter().map(|s| display_width(&s.content) as usize).sum::<usize>();
    spans.push(Span::raw(encryption));
    pad_to(&mut spans, start + columns.encryption);
    spans.push(Span::raw(" ".repeat(COL_GAP)));

    match &row.otp {
        Some(otp) => {
            push_otp_direction_columns(
                &mut spans,
                "dec",
                otp.dec_sequence,
                otp.dec_offset,
                otp.dec_key_remaining,
                columns.dec,
            );
            spans.push(Span::raw(" ".repeat(COL_GAP)));
            push_otp_direction_columns(
                &mut spans,
                "enc",
                otp.enc_sequence,
                otp.enc_offset,
                otp.enc_key_remaining,
                columns.enc,
            );
        }
        None if row.otp_contact_name.is_some() => {
            spans.push(Span::styled(
                "no OTP key installed (o to install)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        None => {
            spans.push(Span::styled(
                "OTP not available (needs pq_hybrid)",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }

    Line::from(spans)
}

pub(crate) fn render_contacts_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(contacts) = &state.contacts else { return };
    if let Some(install) = &contacts.install {
        render_install_popup(frame, area, contacts, install);
        return;
    }
    if contacts.confirm_delete.is_some() {
        render_delete_confirm(frame, area, contacts);
        return;
    }

    let columns = ContactsColumns::measure(&contacts.rows);
    let content_width = columns.nickname
        + columns.last_seen
        + columns.encryption
        + COL_GAP * 3
        + columns.otp_section_width();
    let width = (content_width as u16 + 4).clamp(60, area.width.saturating_sub(2));
    let height = (contacts.rows.len().max(1) as u16 + 4).min(area.height.saturating_sub(2));
    let popup = centered_rect(width, height, area);
    let block = Block::default()
        .title("Contacts (o: install OTP key  d: delete  r: refresh  Esc: close)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    if contacts.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("no contacts pinned yet - one appears the first time you connect to someone")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let header_area = Rect {
        height: 1.min(inner.height),
        ..inner
    };
    frame.render_widget(Paragraph::new(header_row(&columns)), header_area);
    let list_area = Rect {
        y: inner.y.saturating_add(1),
        height: inner.height.saturating_sub(1),
        ..inner
    };

    let items: Vec<ListItem> = contacts
        .rows
        .iter()
        .map(|row| ListItem::new(contact_row_line(row, &columns)))
        .collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    list_state.select(Some(contacts.selected.min(contacts.rows.len() - 1)));
    frame.render_stateful_widget(list, list_area, &mut list_state);
}

fn render_delete_confirm(frame: &mut Frame, area: Rect, contacts: &ContactsState) {
    let nickname = contacts
        .rows
        .get(contacts.selected)
        .map(|r| r.nickname.as_str())
        .unwrap_or("?");
    let has_otp = contacts
        .rows
        .get(contacts.selected)
        .map(|r| r.otp.is_some())
        .unwrap_or(false);
    let popup = centered_rect(56, 9, area);
    let block = Block::default().title("Delete contact").borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    let mut lines = vec![Line::from(format!(
        "Delete {nickname}? Their pinned identity is forgotten - the next \
         time they connect, this looks like the first time."
    ))];
    if has_otp {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Their OTP key is deleted too - this cannot be undone.",
            Style::default().fg(Color::Red),
        )));
    }
    let rows = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Min(3),
            ratatui::layout::Constraint::Length(3),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            ratatui::layout::Constraint::Percentage(50),
            ratatui::layout::Constraint::Percentage(50),
        ])
        .split(rows[1]);
    render_popup_button(
        frame,
        button_cols[0],
        18,
        "Delete",
        contacts.confirm_delete == Some(DeleteChoice::Delete),
    );
    render_popup_button(
        frame,
        button_cols[1],
        18,
        "Cancel",
        contacts.confirm_delete == Some(DeleteChoice::Cancel),
    );
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

fn render_install_popup(
    frame: &mut Frame,
    area: Rect,
    contacts: &ContactsState,
    install: &InstallOtpState,
) {
    if let Some((_, browser)) = &install.browser {
        render_file_browser(frame, area, browser, "Select key file");
        return;
    }
    let nickname = contacts
        .rows
        .get(contacts.selected)
        .map(|r| r.nickname.as_str())
        .unwrap_or("?");

    let popup = centered_rect(72, 15, area);
    let block = Block::default()
        .title(format!("Install OTP key for {nickname}"))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![
        ratatui::layout::Constraint::Length(6), // explanation
        ratatui::layout::Constraint::Length(1), // enc_path
        ratatui::layout::Constraint::Length(1), // dec_path
        ratatui::layout::Constraint::Length(1), // spacer
        ratatui::layout::Constraint::Length(3), // install button
    ];
    if install.error.is_some() {
        constraints.push(ratatui::layout::Constraint::Min(1));
    }
    let rows = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let explanation = format!(
        "Generate a key pair yourself with the real 'otp' command \
         (github.com/DavidValin/otp-toolkit): otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>. \
         Send one part to {nickname} and keep the other. Below, point encryption key \
         to your own sending half and decryption key to your own receiving half.\n\
         Both sides must install their matching keys before messaging - a mismatch \
         decrypts to garbage, not an error."
    );
    frame.render_widget(
        Paragraph::new(explanation)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .style(Style::default().fg(Color::DarkGray)),
        rows[0],
    );

    let enc_display = if install.enc_path.is_empty() {
        "<press Enter to browse>".to_string()
    } else {
        install.enc_path.clone()
    };
    let dec_display = if install.dec_path.is_empty() {
        "<press Enter to browse>".to_string()
    } else {
        install.dec_path.clone()
    };
    frame.render_widget(
        Paragraph::new(key_field_line(
            "encryption key",
            &enc_display,
            install.focus == InstallField::EncPath,
        )),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new(key_field_line(
            "decryption key",
            &dec_display,
            install.focus == InstallField::DecPath,
        )),
        rows[2],
    );

    render_popup_button(frame, rows[4], 16, "Install", install.focus == InstallField::Install);

    if let Some(err) = &install.error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
            rows[5],
        );
    }
}
