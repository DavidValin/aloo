//! The OTP mail surface (docs/PROTOCOL.md §17): the full-screen compose
//! view the `/mail` command opens, the mailbox popup `/mailbox` lays over
//! it, and the reader for a received mail. Mirrors
//! `crate::client::tui::file_send`'s split: state + key handling + rendering for
//! one concern, `impl UiState` on top of the struct defined here, with the
//! session-side effects (validation subprocess calls, encrypt/upload,
//! disk) living in `crate::client::otp_mail` and reached through `UiAction`s.
//!
//! Reuses the existing building blocks wholesale: the file browser widget
//! for attachments (`crate::client::file_browser`), the hold-Space recording
//! machinery for voice attachments (same `recording`/`VoiceRecordStart`
//! flags and timeouts the channel/DM views drive), and `ReplayVoice` for
//! playing a received mail's voice parts.

use std::path::PathBuf;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::client::file_browser::FileBrowserState;
use crate::client::otp_mail::{MAIL_OVERHEAD_ESTIMATE, RecipientCheck};
use crate::client::otp_mail_store::{ReceivedMailRef, SentMailRef, SentMailStatus};
use crate::crypto::otp::{OTP_MAIL_MAX_BYTES, OtpMailPayload};

use super::ui::{
    RecordSource, UiAction, UiState, VoiceTarget, centered_rect, focus_border_style,
    format_duration_label, format_file_size, render_file_browser,
};
use super::widgets::confirm_popup::{BUTTON_WIDTH, Confirm, ConfirmLabels, render_confirm_row};

/// Which part of the compose form has focus - Tab cycles in this order.
/// `Device` is only ever a stop on that cycle while `ComposeState::devices`
/// is non-empty (`handle_mail_compose_key`) - an unpinned or
/// not-yet-checked recipient has nothing to select, so Tab skips straight
/// from `To` to `Subtext`, exactly as it always has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailFocus {
    To,
    Device,
    Subtext,
    Content,
    Attachments,
}

/// One device of the To field's resolved nickname, and whether it has a
/// mail-purpose otp key - what the device selector row lists
/// (`UiState::otp_mail_set_devices`, `client::otp_mail::enumerate_mail_devices`).
#[derive(Debug, Clone, PartialEq)]
pub struct MailDeviceOption {
    pub device_id: String,
    pub last_seen_unix: Option<u64>,
    /// `crypto::otp::contact_name_for_mail`'s output for `(own, this
    /// device)` - what `check_recipient`/`handle_send` actually seal
    /// under once this device is selected.
    pub contact_name: String,
    pub has_mail_key: bool,
    pub enc_key_remaining: u64,
}

/// One attachment on a mail being composed. A file's bytes are *not* read
/// here - only its size is, for the live budget; the bytes are read once,
/// at send time (`client::otp_mail::handle_send`).
#[derive(Debug, Clone, PartialEq)]
pub enum MailAttachment {
    Voice { duration_ms: u32, pcm: Vec<u8> },
    File { filename: String, path: PathBuf, size: u64 },
}

impl MailAttachment {
    pub fn byte_size(&self) -> u64 {
        match self {
            MailAttachment::Voice { pcm, .. } => pcm.len() as u64,
            MailAttachment::File { size, .. } => *size,
        }
    }

    fn label(&self) -> String {
        match self {
            MailAttachment::Voice { duration_ms, pcm } => format!(
                "\u{1F3A4} voice {} ({})",
                format_duration_label(*duration_ms),
                format_file_size(pcm.len() as u64)
            ),
            MailAttachment::File { filename, size, .. } => {
                format!("\u{1F4CE} {filename} ({})", format_file_size(*size))
            }
        }
    }
}

/// The compose form's state. Fields are entered independently, in any
/// order; nothing is validated at typing time except the recipient (whose
/// check result lands in `check`) and the live pad budget derived from it.
pub struct ComposeState {
    pub to: String,
    /// Every device `to` resolves to that carries a pinned identity -
    /// gathered once per distinct nickname (`devices_for` is the memo
    /// key), never re-enumerated per keystroke while it stays the same.
    /// Empty until `to` resolves to at least one pinned device.
    pub devices: Vec<MailDeviceOption>,
    /// The nickname `devices` was last gathered for - `None`, or stale
    /// (not equal to `to`) after an edit, is what tells
    /// `UiState::otp_mail_set_devices`'s caller a fresh enumeration is
    /// actually needed instead of reusing what's already here.
    pub devices_for: Option<String>,
    /// Index into `devices` - meaningless while `devices` is empty.
    pub selected_device: usize,
    pub subtext: String,
    pub content: String,
    pub attachments: Vec<MailAttachment>,
    pub selected_attachment: usize,
    pub focus: MailFocus,
    /// The latest recipient check for `to`, against whichever device is
    /// currently selected - `None` until the first edit (or while `to` is
    /// empty). Set by `session` via `UiState::otp_mail_set_check` in
    /// response to `UiAction::CheckOtpMailRecipient`/`SelectOtpMailDevice`.
    pub check: Option<RecipientCheck>,
    /// `Some` while the attach-a-file browser popup is open.
    pub browser: Option<FileBrowserState>,
    /// `Some(index)` while the remove-attachment confirm popup is open.
    pub delete_confirm: Option<usize>,
    pub delete_confirm_focus: Confirm,
    /// Whether the send confirm popup is open.
    pub send_confirm: bool,
    pub send_confirm_focus: Confirm,
}

impl ComposeState {
    fn new() -> Self {
        Self {
            to: String::new(),
            devices: Vec::new(),
            devices_for: None,
            selected_device: 0,
            subtext: String::new(),
            content: String::new(),
            attachments: Vec::new(),
            selected_attachment: 0,
            focus: MailFocus::To,
            check: None,
            browser: None,
            delete_confirm: None,
            delete_confirm_focus: Confirm::No,
            send_confirm: false,
            send_confirm_focus: Confirm::No,
        }
    }

    /// Estimated encoded payload size right now: every field and
    /// attachment, plus a fixed allowance for the signature and bincode
    /// framing (`MAIL_OVERHEAD_ESTIMATE`). What the "key left" display and
    /// the attach-time budget check both use; the send path re-measures
    /// the *real* encoded bytes before spending any pad.
    pub fn estimated_bytes(&self) -> u64 {
        self.subtext.len() as u64
            + self.content.len() as u64
            + self
                .attachments
                .iter()
                .map(|a| a.byte_size())
                .sum::<u64>()
            + MAIL_OVERHEAD_ESTIMATE
    }

    /// The contact's remaining pad after this mail, if the recipient check
    /// has passed - what the top-right indicator shows. `None` until then.
    pub fn key_left_after_mail(&self) -> Option<u64> {
        match &self.check {
            Some(RecipientCheck::Ok { enc_key_remaining, .. }) => {
                Some(enc_key_remaining.saturating_sub(self.estimated_bytes()))
            }
            _ => None,
        }
    }

    /// Whether the mail can be composed/sent to `to` right now: the
    /// recipient check passed *and* the key is strictly longer than the
    /// estimated mail, and under the hard cap. This is what the To field's
    /// tick/cross reflects - it can flip back to a cross just by typing
    /// enough content to outgrow the pad.
    pub fn valid_for_composing(&self) -> bool {
        match &self.check {
            Some(RecipientCheck::Ok { enc_key_remaining, .. }) => {
                let estimated = self.estimated_bytes();
                estimated < *enc_key_remaining && estimated <= OTP_MAIL_MAX_BYTES as u64
            }
            _ => false,
        }
    }

    /// Whether nothing has been entered at all - what lets Esc out of a
    /// `/mailbox`-opened popup close the whole view instead of stranding
    /// the user in an empty compose form they never asked for.
    pub fn is_pristine(&self) -> bool {
        self.to.is_empty()
            && self.subtext.is_empty()
            && self.content.is_empty()
            && self.attachments.is_empty()
    }

    /// Whether `extra` more bytes would still fit - the attach-time check:
    /// an attachment that would push the mail past the remaining key (or
    /// the hard cap) is cancelled outright. With no passed recipient check
    /// yet only the hard cap applies - the pad bound re-applies live the
    /// moment the recipient validates.
    pub fn fits_budget(&self, extra: u64) -> bool {
        let would_be = self.estimated_bytes().saturating_add(extra);
        if would_be > OTP_MAIL_MAX_BYTES as u64 {
            return false;
        }
        match &self.check {
            Some(RecipientCheck::Ok { enc_key_remaining, .. }) => would_be < *enc_key_remaining,
            _ => true,
        }
    }
}

/// One row of the mailbox popup - a sent mail's delivery status, or a
/// received mail (readable via Enter). Snapshotted from
/// `client::otp_mail_store` by the session whenever the popup opens or a
/// mail event lands (`UiState::otp_mail_set_mailbox_rows`).
#[derive(Debug, Clone, PartialEq)]
pub enum MailboxRow {
    Sent(SentMailRef),
    Received(ReceivedMailRef),
}

impl MailboxRow {
    pub fn mail_id(&self) -> &str {
        match self {
            MailboxRow::Sent(r) => &r.mail_id,
            MailboxRow::Received(r) => &r.mail_id,
        }
    }
}

pub struct MailboxState {
    pub rows: Vec<MailboxRow>,
    pub selected: usize,
    /// `Some(mail_id)` while the remove-mail confirm popup is open.
    pub delete_confirm: Option<String>,
    pub delete_confirm_focus: Confirm,
}

/// A received mail opened for reading: its payload, decrypted in memory by
/// the session (`client::otp_mail::read_mail`) and held only here, only
/// while the reader is open - closing the reader drops the plaintext, and
/// the on-disk (ciphertext, pad) pair stays put until the user removes the
/// mail.
pub struct ReaderState {
    pub mail_id: String,
    pub payload: OtpMailPayload,
    /// Selected row in the voice/attachment part list (empty list = no
    /// selection to move).
    pub selected_part: usize,
    /// Content scroll, in lines.
    pub scroll: u16,
}

/// Everything the `/mail`/`/mailbox` commands own. `compose` always exists while the view is open;
/// `mailbox`/`reader` stack over it.
pub struct OtpMailState {
    pub compose: ComposeState,
    pub mailbox: Option<MailboxState>,
    pub reader: Option<ReaderState>,
}

impl UiState {
    /// Opens the full-screen compose view (the `/mail` command; `/mailbox`
    /// opens it too, as the mailbox popup's backdrop) - a no-op if
    /// it's already open.
    pub fn open_otp_mail(&mut self) {
        if self.otp_mail.is_none() {
            self.otp_mail = Some(OtpMailState {
                compose: ComposeState::new(),
                mailbox: None,
                reader: None,
            });
        }
    }

    /// Applies a recipient check result - only if the To field still holds
    /// the nickname it was computed for, so a stale result from an earlier
    /// keystroke can't overwrite a newer edit's.
    pub fn otp_mail_set_check(&mut self, nickname: &str, check: RecipientCheck) {
        if let Some(mail) = self.otp_mail.as_mut()
            && mail.compose.to == nickname
        {
            mail.compose.check = Some(check);
        }
    }

    /// Applies a freshly gathered device list - only if the To field still
    /// holds `nickname` (the same stale-edit guard `otp_mail_set_check`
    /// uses). Picks the default selection: the most-recently-seen device
    /// that actually has a mail key, or - if none does - the
    /// most-recently-seen device overall, so the existing `NoMailKey` gate
    /// still explains why rather than the selector silently landing on an
    /// arbitrary row.
    pub fn otp_mail_set_devices(&mut self, nickname: &str, devices: Vec<MailDeviceOption>) {
        let Some(mail) = self.otp_mail.as_mut() else {
            return;
        };
        if mail.compose.to != nickname {
            return;
        }
        let default_idx = devices
            .iter()
            .enumerate()
            .filter(|(_, d)| d.has_mail_key)
            .max_by_key(|(_, d)| (d.last_seen_unix.is_some(), d.last_seen_unix.unwrap_or(0)))
            .map(|(i, _)| i)
            .or_else(|| {
                devices
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, d)| (d.last_seen_unix.is_some(), d.last_seen_unix.unwrap_or(0)))
                    .map(|(i, _)| i)
            })
            .unwrap_or(0);
        mail.compose.devices = devices;
        mail.compose.devices_for = Some(nickname.to_string());
        mail.compose.selected_device = default_idx;
    }

    /// The currently selected device's id for `nickname` - `None` if the
    /// gathered list is stale (a different/no nickname) or empty.
    pub fn otp_mail_selected_device_id(&self, nickname: &str) -> Option<String> {
        let mail = self.otp_mail.as_ref()?;
        if mail.compose.devices_for.as_deref() != Some(nickname) {
            return None;
        }
        mail.compose
            .devices
            .get(mail.compose.selected_device)
            .map(|d| d.device_id.clone())
    }

    /// Moves the device selection to `device_id`, if the gathered list is
    /// current for `nickname` and actually names it. Returns whether it
    /// did - `false` leaves the selection untouched (the caller then has
    /// nothing to re-check).
    pub fn otp_mail_set_selected_device(&mut self, nickname: &str, device_id: &str) -> bool {
        let Some(mail) = self.otp_mail.as_mut() else {
            return false;
        };
        if mail.compose.devices_for.as_deref() != Some(nickname) {
            return false;
        }
        let Some(idx) = mail
            .compose
            .devices
            .iter()
            .position(|d| d.device_id == device_id)
        else {
            return false;
        };
        mail.compose.selected_device = idx;
        true
    }

    /// Adds a finished voice recording as an attachment - `false` (nothing
    /// added) if the compose view is gone or the recording doesn't fit the
    /// remaining budget, which the caller reports as a cancelled operation.
    pub fn otp_mail_add_voice(&mut self, duration_ms: u32, pcm: Vec<u8>) -> bool {
        let Some(mail) = self.otp_mail.as_mut() else {
            return false;
        };
        if !mail.compose.fits_budget(pcm.len() as u64) {
            return false;
        }
        mail.compose
            .attachments
            .push(MailAttachment::Voice { duration_ms, pcm });
        true
    }

    /// Replaces the mailbox rows (opening it if it wasn't open), keeping
    /// the selection stable where possible.
    pub fn otp_mail_set_mailbox_rows(&mut self, rows: Vec<MailboxRow>) {
        let Some(mail) = self.otp_mail.as_mut() else {
            return;
        };
        match mail.mailbox.as_mut() {
            Some(mb) => {
                mb.rows = rows;
                mb.selected = mb.selected.min(mb.rows.len().saturating_sub(1));
            }
            None => {
                mail.mailbox = Some(MailboxState {
                    rows,
                    selected: 0,
                    delete_confirm: None,
                    delete_confirm_focus: Confirm::No,
                });
            }
        }
    }

    /// Whether the mailbox popup is currently showing (so the session
    /// knows to refresh its rows when a mail event lands).
    pub fn otp_mailbox_open(&self) -> bool {
        self.otp_mail.as_ref().is_some_and(|m| m.mailbox.is_some())
    }

    /// Opens the reader over the mailbox with a just-decrypted payload.
    pub fn otp_mail_open_reader(&mut self, mail_id: String, payload: OtpMailPayload) {
        if let Some(mail) = self.otp_mail.as_mut() {
            mail.reader = Some(ReaderState {
                mail_id,
                payload,
                selected_part: 0,
                scroll: 0,
            });
        }
    }

    /// Closes the whole mail view after a successful send.
    pub fn otp_mail_close(&mut self) {
        self.otp_mail = None;
    }

    /// Key handling while the mail view is open - every key lands here
    /// (`handle_key` routes before any channel/DM handling), layered
    /// innermost-popup-first exactly like `render_otp_mail_view` draws.
    pub(crate) fn handle_otp_mail_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        kind: KeyEventKind,
    ) -> Option<UiAction> {
        // While a voice clip is playing (an attachment from the compose
        // pane, or a received mail's voice part in the reader), Escape
        // means "stop playback" before it means anything else - the same
        // meaning it has over the channel/DM views, checked here first for
        // the same reason: whatever Esc would otherwise close stays open.
        if code == KeyCode::Esc && self.replaying {
            if kind == KeyEventKind::Press {
                self.replaying = false;
                return Some(UiAction::StopPlayback);
            }
            return None;
        }
        // The reader sits on top of everything else in this view.
        if self
            .otp_mail
            .as_ref()
            .is_some_and(|m| m.reader.is_some())
        {
            if kind == KeyEventKind::Press || kind == KeyEventKind::Repeat {
                return self.handle_mail_reader_key(code);
            }
            return None;
        }
        // Then the mailbox popup.
        if self
            .otp_mail
            .as_ref()
            .is_some_and(|m| m.mailbox.is_some())
        {
            if kind == KeyEventKind::Press || kind == KeyEventKind::Repeat {
                return self.handle_mailbox_key(code);
            }
            return None;
        }
        self.handle_mail_compose_key(code, modifiers, kind)
    }

    fn handle_mail_reader_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let mail = self.otp_mail.as_mut()?;
        let reader = mail.reader.as_mut()?;
        let parts = reader.payload.voices.len() + reader.payload.attachments.len();
        match code {
            KeyCode::Esc => {
                // Dropping ReaderState drops the only in-memory plaintext.
                mail.reader = None;
                None
            }
            KeyCode::Up if parts > 0 => {
                reader.selected_part = reader.selected_part.saturating_sub(1);
                None
            }
            KeyCode::Down if parts > 0 => {
                reader.selected_part = (reader.selected_part + 1).min(parts - 1);
                None
            }
            KeyCode::PageUp => {
                reader.scroll = reader.scroll.saturating_sub(5);
                None
            }
            KeyCode::PageDown => {
                reader.scroll = reader.scroll.saturating_add(5);
                None
            }
            KeyCode::Up => {
                reader.scroll = reader.scroll.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                reader.scroll = reader.scroll.saturating_add(1);
                None
            }
            KeyCode::Enter if parts > 0 => {
                let voices = reader.payload.voices.len();
                if reader.selected_part < voices {
                    let v = &reader.payload.voices[reader.selected_part];
                    let (duration_ms, pcm) = (v.duration_ms, v.pcm.clone());
                    // Same replay path and empty-clip guard as everywhere
                    // else a voice clip plays from - Escape stops it.
                    if !pcm.is_empty() {
                        self.replaying = true;
                    }
                    Some(UiAction::ReplayVoice {
                        duration_ms,
                        pcm,
                        // A mail attachment is not a peer's live voice
                        // message and owes nobody a receipt (7.2.1) - a
                        // mail's own delivery is reported over the server
                        // instead (17.3).
                        from: crate::proto::UserId(0),
                        owed_receipt: None,
                    })
                } else {
                    Some(UiAction::SaveOtpMailAttachment {
                        index: reader.selected_part - voices,
                    })
                }
            }
            _ => None,
        }
    }

    fn handle_mailbox_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let mail = self.otp_mail.as_mut()?;
        let mb = mail.mailbox.as_mut()?;

        // The remove-mail confirm absorbs everything while open.
        if let Some(mail_id) = mb.delete_confirm.clone() {
            match code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    mb.delete_confirm_focus = mb.delete_confirm_focus.toggled();
                }
                KeyCode::Esc => {
                    mb.delete_confirm = None;
                    mb.delete_confirm_focus = Confirm::No;
                }
                KeyCode::Enter => {
                    let choice = mb.delete_confirm_focus;
                    mb.delete_confirm = None;
                    mb.delete_confirm_focus = Confirm::No;
                    if choice == Confirm::Yes {
                        return Some(UiAction::DeleteOtpMail { mail_id });
                    }
                }
                _ => {}
            }
            return None;
        }

        match code {
            KeyCode::Esc => {
                // Closing the popup falls back to the compose form - unless
                // the form is completely untouched (the `/mailbox` command
                // opens it only as the popup's backdrop), in which case the
                // whole view closes rather than stranding the user in a
                // compose screen they never asked for.
                mail.mailbox = None;
                if mail.compose.is_pristine() {
                    self.otp_mail = None;
                }
                None
            }
            KeyCode::Up => {
                mb.selected = mb.selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if !mb.rows.is_empty() {
                    mb.selected = (mb.selected + 1).min(mb.rows.len() - 1);
                }
                None
            }
            KeyCode::Enter => match mb.rows.get(mb.selected) {
                Some(MailboxRow::Received(r)) => Some(UiAction::ReadOtpMail {
                    mail_id: r.mail_id.clone(),
                }),
                _ => None,
            },
            KeyCode::Char('d') => {
                if let Some(row) = mb.rows.get(mb.selected) {
                    mb.delete_confirm = Some(row.mail_id().to_string());
                    mb.delete_confirm_focus = Confirm::No;
                }
                None
            }
            _ => None,
        }
    }

    fn handle_mail_compose_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        kind: KeyEventKind,
    ) -> Option<UiAction> {
        // A recipient with no OTP mail key blocks the entire compose form -
        // typing, attaching, recording, everything - checked ahead of every
        // other branch below. Esc is the only key that does anything, and
        // it closes the whole view in one step (not just this gate): there
        // is nothing to "go back" to here, since fixing this means
        // installing a key from /contacts or /new-otp-mail-key and starting
        // a fresh /mail, not editing the current recipient in place.
        if self
            .otp_mail
            .as_ref()
            .is_some_and(|m| matches!(m.compose.check, Some(RecipientCheck::NoMailKey)))
        {
            if kind == KeyEventKind::Press && code == KeyCode::Esc {
                self.otp_mail = None;
            }
            return None;
        }

        // Hold-Space voice recording, only while the attachments pane has
        // focus (a space in To/Subtext/Content is just a typed character).
        // Mirrors `handle_key`'s Space branch exactly - same flags, same
        // press/release/timeout machinery - just addressed to the mail.
        let attachments_focused = self
            .otp_mail
            .as_ref()
            .is_some_and(|m| {
                m.compose.focus == MailFocus::Attachments
                    && m.compose.browser.is_none()
                    && m.compose.delete_confirm.is_none()
                    && !m.compose.send_confirm
            });
        if code == KeyCode::Char(' ') && attachments_focused {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => {
                    self.recording_last_seen = Some(Instant::now());
                    if self.recording {
                        None
                    } else {
                        self.recording = true;
                        self.recording_source = Some(RecordSource::Space);
                        self.audio_error = None;
                        Some(UiAction::VoiceRecordStart(VoiceTarget::MailAttachment))
                    }
                }
                KeyEventKind::Release
                    if self.recording && self.recording_source == Some(RecordSource::Space) =>
                {
                    self.recording = false;
                    self.recording_source = None;
                    self.recording_last_seen = None;
                    Some(UiAction::VoiceRecordStop)
                }
                _ => None,
            };
        }
        if kind != KeyEventKind::Press && kind != KeyEventKind::Repeat {
            return None;
        }

        let mail = self.otp_mail.as_mut()?;
        let compose = &mut mail.compose;

        // Innermost popups first: attach browser, then the two confirms.
        if compose.browser.is_some() {
            return self.handle_mail_browser_key(code);
        }
        if compose.delete_confirm.is_some() {
            match code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    compose.delete_confirm_focus = compose.delete_confirm_focus.toggled();
                }
                KeyCode::Esc => {
                    compose.delete_confirm = None;
                    compose.delete_confirm_focus = Confirm::No;
                }
                KeyCode::Enter => {
                    let choice = compose.delete_confirm_focus;
                    let index = compose.delete_confirm.take();
                    compose.delete_confirm_focus = Confirm::No;
                    if choice == Confirm::Yes
                        && let Some(index) = index
                        && index < compose.attachments.len()
                    {
                        compose.attachments.remove(index);
                        compose.selected_attachment = compose
                            .selected_attachment
                            .min(compose.attachments.len().saturating_sub(1));
                    }
                }
                _ => {}
            }
            return None;
        }
        if compose.send_confirm {
            match code {
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    compose.send_confirm_focus = compose.send_confirm_focus.toggled();
                }
                KeyCode::Esc => {
                    compose.send_confirm = false;
                    compose.send_confirm_focus = Confirm::No;
                }
                KeyCode::Enter => {
                    let choice = compose.send_confirm_focus;
                    compose.send_confirm = false;
                    compose.send_confirm_focus = Confirm::No;
                    if choice == Confirm::Yes {
                        return Some(UiAction::SendOtpMail);
                    }
                }
                _ => {}
            }
            return None;
        }

        if modifiers.contains(KeyModifiers::CONTROL) {
            match code {
                // Ctrl+S asks to send - only ever through the confirm.
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    if compose.valid_for_composing() {
                        compose.send_confirm = true;
                        compose.send_confirm_focus = Confirm::No;
                    } else {
                        self.push_status_notice(
                            "OTP mail: recipient must be valid and the mail must fit the remaining key".to_string(),
                            false,
                        );
                    }
                    return None;
                }
                _ => return None,
            }
        }

        match code {
            KeyCode::Esc => {
                self.otp_mail = None;
                return None;
            }
            KeyCode::Tab => {
                let has_devices = !compose.devices.is_empty();
                compose.focus = match compose.focus {
                    MailFocus::To if has_devices => MailFocus::Device,
                    MailFocus::To => MailFocus::Subtext,
                    MailFocus::Device => MailFocus::Subtext,
                    MailFocus::Subtext => MailFocus::Content,
                    MailFocus::Content => MailFocus::Attachments,
                    MailFocus::Attachments => MailFocus::To,
                };
                return None;
            }
            KeyCode::BackTab => {
                let has_devices = !compose.devices.is_empty();
                compose.focus = match compose.focus {
                    MailFocus::To => MailFocus::Attachments,
                    MailFocus::Device => MailFocus::To,
                    MailFocus::Subtext if has_devices => MailFocus::Device,
                    MailFocus::Subtext => MailFocus::To,
                    MailFocus::Content => MailFocus::Subtext,
                    MailFocus::Attachments => MailFocus::Content,
                };
                return None;
            }
            _ => {}
        }

        match compose.focus {
            MailFocus::To => match code {
                KeyCode::Char(c) => {
                    compose.to.push(c);
                    let nickname = compose.to.clone();
                    compose.check = None;
                    compose.devices.clear();
                    compose.devices_for = None;
                    compose.selected_device = 0;
                    Some(UiAction::CheckOtpMailRecipient { nickname })
                }
                KeyCode::Backspace => {
                    compose.to.pop();
                    compose.check = None;
                    compose.devices.clear();
                    compose.devices_for = None;
                    compose.selected_device = 0;
                    if compose.to.is_empty() {
                        None
                    } else {
                        let nickname = compose.to.clone();
                        Some(UiAction::CheckOtpMailRecipient { nickname })
                    }
                }
                _ => None,
            },
            MailFocus::Device => match code {
                KeyCode::Up => {
                    let before = compose.selected_device;
                    compose.selected_device = compose.selected_device.saturating_sub(1);
                    (compose.selected_device != before)
                        .then(|| compose.devices.get(compose.selected_device))
                        .flatten()
                        .map(|d| UiAction::SelectOtpMailDevice {
                            nickname: compose.to.clone(),
                            device_id: d.device_id.clone(),
                        })
                }
                KeyCode::Down => {
                    let before = compose.selected_device;
                    if !compose.devices.is_empty() {
                        compose.selected_device =
                            (compose.selected_device + 1).min(compose.devices.len() - 1);
                    }
                    (compose.selected_device != before)
                        .then(|| compose.devices.get(compose.selected_device))
                        .flatten()
                        .map(|d| UiAction::SelectOtpMailDevice {
                            nickname: compose.to.clone(),
                            device_id: d.device_id.clone(),
                        })
                }
                _ => None,
            },
            MailFocus::Subtext => match code {
                KeyCode::Char(c) => {
                    compose.subtext.push(c);
                    None
                }
                KeyCode::Backspace => {
                    compose.subtext.pop();
                    None
                }
                _ => None,
            },
            MailFocus::Content => match code {
                KeyCode::Char(c) => {
                    compose.content.push(c);
                    None
                }
                KeyCode::Backspace => {
                    compose.content.pop();
                    None
                }
                KeyCode::Enter => {
                    compose.content.push('\n');
                    None
                }
                _ => None,
            },
            MailFocus::Attachments => match code {
                KeyCode::Up => {
                    compose.selected_attachment = compose.selected_attachment.saturating_sub(1);
                    None
                }
                KeyCode::Down => {
                    if !compose.attachments.is_empty() {
                        compose.selected_attachment =
                            (compose.selected_attachment + 1).min(compose.attachments.len() - 1);
                    }
                    None
                }
                KeyCode::Char('a') => {
                    // Same real-filesystem entry point `/file` uses.
                    if let Ok(dir) = std::env::current_dir()
                        && let Ok(browser) = FileBrowserState::open(dir)
                    {
                        compose.browser = Some(browser);
                    }
                    None
                }
                // Enter replays the selected voice attachment through the
                // same mixer path a logged voice message uses; a file
                // attachment has nothing to play. Same empty-clip guard as
                // the message log's replay: a clip the mixer won't start
                // must not set `replaying`, or Escape would be stuck
                // stealing its "stop playback" meaning with nothing to
                // stop.
                KeyCode::Enter => {
                    let voice = match compose.attachments.get(compose.selected_attachment) {
                        Some(MailAttachment::Voice { duration_ms, pcm }) => {
                            Some((*duration_ms, pcm.clone()))
                        }
                        _ => None,
                    };
                    voice.map(|(duration_ms, pcm)| {
                        if !pcm.is_empty() {
                            self.replaying = true;
                        }
                        UiAction::ReplayVoice {
                            duration_ms,
                            pcm,
                            from: crate::proto::UserId(0),
                            owed_receipt: None,
                        }
                    })
                }
                KeyCode::Char('d') => {
                    if !compose.attachments.is_empty() {
                        compose.delete_confirm = Some(compose.selected_attachment);
                        compose.delete_confirm_focus = Confirm::No;
                    }
                    None
                }
                _ => None,
            },
        }
    }

    fn handle_mail_browser_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let mail = self.otp_mail.as_mut()?;
        let compose = &mut mail.compose;
        let browser = compose.browser.as_mut()?;
        match code {
            KeyCode::Up => browser.select_prev(),
            KeyCode::Down => browser.select_next(),
            KeyCode::Left => {
                let _ = browser.go_back();
            }
            KeyCode::Right => {
                let _ = browser.go_forward();
            }
            KeyCode::Esc => {
                compose.browser = None;
            }
            KeyCode::Enter => {
                let entry = browser.selected_entry()?;
                if entry.is_dir {
                    let _ = browser.navigate_into_selected();
                } else if let Some(path) = browser.selected_path() {
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    // An attachment longer than the remaining key cancels
                    // the whole operation - the browser closes with
                    // nothing attached, and the notice says why.
                    if !compose.fits_budget(size) {
                        compose.browser = None;
                        self.push_status_notice(
                            "OTP mail: attachment is larger than the remaining key - cancelled"
                                .to_string(),
                            false,
                        );
                        return None;
                    }
                    let filename = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "file".to_string());
                    let filename = crate::client::file_transfer::truncate_filename(&filename);
                    compose.attachments.push(MailAttachment::File {
                        filename,
                        path,
                        size,
                    });
                    compose.browser = None;
                }
            }
            _ => {}
        }
        None
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// Formats a byte count as `NN.NN MB` - the unit the remaining-key
/// indicator is specified in, regardless of magnitude.
pub(crate) fn format_mb(bytes: u64) -> String {
    format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
}

/// Shortens a device id (8 hex characters, `client::device_id::load_or_create`)
/// to its first 12 for the device selector's compact row - a no-op for a
/// real one, but still cropped for a longer hand-picked test/device label,
/// same "still effectively unique for telling entries apart at a glance"
/// rationale `session::short_fingerprint` already uses for fingerprints.
fn short_device_id(id: &str) -> String {
    match id.get(..12) {
        Some(prefix) if prefix.len() < id.len() => format!("{prefix}\u{2026}"),
        _ => id.to_string(),
    }
}

/// Short UTC render of a unix timestamp for mailbox rows and the reader
/// header - always UTC and labeled as such, since `SendAtInUTC` is the
/// field's own contract.
pub(crate) fn format_utc_short(ts: u64) -> String {
    let Ok(dt) = time::OffsetDateTime::from_unix_timestamp(ts as i64) else {
        return "-".to_string();
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute()
    )
}

fn sent_status_span(status: SentMailStatus) -> Span<'static> {
    match status {
        SentMailStatus::AwaitingServerAck => {
            Span::styled("awaiting server", Style::default().fg(Color::Yellow))
        }
        SentMailStatus::StoredOnServer => {
            Span::styled("on server", Style::default().fg(Color::Cyan))
        }
        SentMailStatus::Delivered => {
            Span::styled("delivered \u{2713}", Style::default().fg(Color::Green))
        }
        SentMailStatus::Failed => Span::styled("failed", Style::default().fg(Color::Red)),
    }
}

/// The full-screen mail view: the compose form, with whichever popups are
/// open stacked over it (browser, confirms, mailbox, reader) in the same
/// order `handle_otp_mail_key` gives them priority.
pub(crate) fn render_otp_mail_view(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(mail) = &state.otp_mail else { return };
    let compose = &mail.compose;

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Length(3), // to
            Constraint::Length(5), // device (up to 3 rows visible)
            Constraint::Length(3), // subtext
            Constraint::Min(5),    // content
            Constraint::Length(6), // attachments
            Constraint::Length(1), // hints
        ])
        .split(area);

    // Header: title left, remaining key top-right (only once the
    // recipient check has passed - the field's own spec).
    let mut header_spans = vec![Span::styled(
        format!(" \u{2709} New OTP mail  (from {})", state.own_name),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if let Some(left) = compose.key_left_after_mail() {
        let label = format!("Key left: {} ", format_mb(left));
        let fill = (rows[0].width as usize)
            .saturating_sub(header_spans[0].content.len() + label.len());
        header_spans.push(Span::raw(" ".repeat(fill)));
        header_spans.push(Span::styled(
            label,
            Style::default().fg(if compose.valid_for_composing() {
                Color::Green
            } else {
                Color::Red
            }),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(header_spans)), rows[0]);

    // To field: emoji + colour reflect the live validity.
    let (to_suffix, to_color) = match (&compose.check, compose.to.is_empty()) {
        (_, true) => (String::new(), Color::White),
        (Some(RecipientCheck::Ok { .. }), false) if compose.valid_for_composing() => {
            (" \u{2705}".to_string(), Color::Green)
        }
        (Some(_), false) => (" \u{274C}".to_string(), Color::Red),
        (None, false) => (String::new(), Color::White),
    };
    let to_block = Block::default()
        .title("To")
        .borders(Borders::ALL)
        .border_style(
            focus_border_style(compose.focus == MailFocus::To)
                .patch(Style::default().fg(to_color)),
        );
    let to_inner = to_block.inner(rows[1]);
    let mut to_line = vec![Span::styled(
        compose.to.clone(),
        Style::default().fg(to_color),
    )];
    if !to_suffix.is_empty() {
        to_line.push(Span::raw(to_suffix));
    }
    if let Some(reason) = check_failure_label(compose) {
        to_line.push(Span::styled(
            format!("  ({reason})"),
            Style::default().fg(Color::Red),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(to_line)).block(to_block), rows[1]);
    if compose.focus == MailFocus::To {
        place_text_cursor(frame, to_inner, &compose.to);
    }

    // Device selector: which of the resolved nickname's pinned devices
    // the mail is sealed for. Height is always reserved (never collapses
    // to zero) so the view doesn't jump around while the nickname is
    // still being typed/checked; before any devices are known it shows a
    // dim placeholder instead of an empty list.
    let device_block = Block::default()
        .title("Device")
        .borders(Borders::ALL)
        .border_style(focus_border_style(compose.focus == MailFocus::Device));
    let device_inner = device_block.inner(rows[2]);
    frame.render_widget(device_block, rows[2]);
    if compose.devices.is_empty() {
        frame.render_widget(
            Paragraph::new(if compose.to.is_empty() {
                "(type a recipient above)"
            } else {
                "(no pinned devices for this recipient)"
            })
            .style(Style::default().fg(Color::DarkGray)),
            device_inner,
        );
    } else {
        let items: Vec<ListItem> = compose
            .devices
            .iter()
            .map(|d| {
                let (badge, badge_color) = if d.has_mail_key {
                    ("\u{2705}", Color::Green)
                } else {
                    ("\u{274C}", Color::Red)
                };
                let seen = super::contacts::format_last_seen(d.last_seen_unix);
                ListItem::new(Line::from(vec![
                    Span::raw(format!("{}  last seen {seen}  ", short_device_id(&d.device_id))),
                    Span::styled(badge, Style::default().fg(badge_color)),
                ]))
            })
            .collect();
        let list =
            List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        let mut list_state = ListState::default();
        if compose.focus == MailFocus::Device {
            list_state.select(Some(compose.selected_device.min(compose.devices.len() - 1)));
        }
        frame.render_stateful_widget(list, device_inner, &mut list_state);
    }

    let subtext_block = Block::default()
        .title("Subtext")
        .borders(Borders::ALL)
        .border_style(focus_border_style(compose.focus == MailFocus::Subtext));
    let subtext_inner = subtext_block.inner(rows[3]);
    frame.render_widget(
        Paragraph::new(compose.subtext.clone()).block(subtext_block),
        rows[3],
    );
    if compose.focus == MailFocus::Subtext {
        place_text_cursor(frame, subtext_inner, &compose.subtext);
    }

    let content_block = Block::default()
        .title("Content")
        .borders(Borders::ALL)
        .border_style(focus_border_style(compose.focus == MailFocus::Content));
    frame.render_widget(
        Paragraph::new(compose.content.clone())
            .wrap(Wrap { trim: false })
            .block(content_block),
        rows[4],
    );

    let attach_title = if state.recording {
        "Attachments (recording\u{2026})".to_string()
    } else {
        format!("Attachments ({})", compose.attachments.len())
    };
    let attach_block = Block::default()
        .title(attach_title)
        .borders(Borders::ALL)
        .border_style(focus_border_style(compose.focus == MailFocus::Attachments));
    let inner = attach_block.inner(rows[5]);
    frame.render_widget(attach_block, rows[5]);
    let items: Vec<ListItem> = compose
        .attachments
        .iter()
        .map(|a| ListItem::new(a.label()))
        .collect();
    let list =
        List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    if compose.focus == MailFocus::Attachments && !compose.attachments.is_empty() {
        list_state.select(Some(
            compose
                .selected_attachment
                .min(compose.attachments.len() - 1),
        ));
    }
    frame.render_stateful_widget(list, inner, &mut list_state);

    frame.render_widget(
        Paragraph::new(
            " Tab: next field \u{2502} a: attach file \u{2502} hold Space (in attachments): record voice \u{2502} Enter: play voice \u{2502} d: remove \u{2502} Up/Down (device): choose which device to address \u{2502} Ctrl+S: send \u{2502} Esc: discard",
        )
        .style(Style::default().fg(Color::DarkGray)),
        rows[6],
    );

    if let Some(browser) = &compose.browser {
        render_file_browser(frame, area, browser, "Attach file");
    }
    if let Some(index) = compose.delete_confirm {
        let what = compose
            .attachments
            .get(index)
            .map(|a| a.label())
            .unwrap_or_default();
        render_mail_confirm(
            frame,
            area,
            "Remove attachment",
            &format!("Remove {what} from this mail?"),
            "Remove",
            compose.delete_confirm_focus,
        );
    }
    if compose.send_confirm {
        render_mail_confirm(
            frame,
            area,
            "Send OTP mail",
            &format!(
                "Send this mail to {} ({} to encrypt with their key)?",
                compose.to,
                format_file_size(compose.estimated_bytes())
            ),
            "Send",
            compose.send_confirm_focus,
        );
    }
    if let Some(mb) = &mail.mailbox {
        render_mailbox(frame, area, mb);
        if let Some(mail_id) = &mb.delete_confirm {
            let is_received = mb
                .rows
                .iter()
                .any(|r| r.mail_id() == mail_id && matches!(r, MailboxRow::Received(_)));
            let message = if is_received {
                "Remove this mail? Its stored ciphertext and pad are both destroyed - it cannot be read again."
            } else {
                "Remove this sent mail's local reference?"
            };
            render_mail_confirm(
                frame,
                area,
                "Remove mail",
                message,
                "Remove",
                mb.delete_confirm_focus,
            );
        }
    }
    if let Some(reader) = &mail.reader {
        render_mail_reader(frame, area, reader);
    }
    // Highest layer: a recipient with no mail key blocks composing outright.
    // Skipped while the mailbox/reader are open - those are about *other*
    // mail and stay reachable; only writing/sending is gated.
    if mail.reader.is_none()
        && mail.mailbox.is_none()
        && matches!(compose.check, Some(RecipientCheck::NoMailKey))
    {
        render_mail_key_blocked_modal(frame, area, &compose.to);
    }
}

/// Places the terminal's own blinking cursor right after `value`'s text
/// inside `inner`, the same convention `ui_connect_popup`'s own
/// `place_text_cursor` uses - what makes it obvious which single-line
/// field (`To`/`Subtext`) is about to receive typed characters, the same
/// way the connect popup's fields already do. `Content` wraps across
/// multiple lines and is not covered by this simple offset-from-start
/// placement.
fn place_text_cursor(frame: &mut Frame, inner: Rect, value: &str) {
    let cursor_x = inner.x + (value.chars().count() as u16).min(inner.width.saturating_sub(1));
    frame.set_cursor_position((cursor_x, inner.y));
}

/// The hard stop for composing to a recipient with no OTP mail key -
/// renders over the whole compose view (mirroring `render_help_popup`'s
/// full-frame `Clear` convention) in red, per the exact wording asked for.
/// Absorbed by `handle_mail_compose_key`'s matching gate; only Esc does
/// anything, and it closes the whole `/mail` view, not just this popup.
fn render_mail_key_blocked_modal(frame: &mut Frame, area: Rect, nickname: &str) {
    let popup = centered_rect(64, 9, area);
    let block = Block::default()
        .title("OTP mail key required")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(1)])
        .split(inner);
    let message = format!(
        "no otp mail key available for {nickname} - install one manually from /contacts or exchange one with the user if he is online using /new-otp-mail-key (requires pinned contact)"
    );
    frame.render_widget(
        Paragraph::new(message)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::Red)),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new("Esc: close").style(Style::default().fg(Color::Red)),
        rows[1],
    );
}

/// The specific reason the To field is invalid, for the inline label -
/// `None` while empty, unchecked, or valid.
fn check_failure_label(compose: &ComposeState) -> Option<&'static str> {
    if compose.to.is_empty() {
        return None;
    }
    match compose.check.as_ref()? {
        RecipientCheck::Ok { .. } => {
            if compose.valid_for_composing() {
                None
            } else {
                Some("mail is larger than the remaining key")
            }
        }
        RecipientCheck::NotPinned => Some("no pinned user with this nickname"),
        RecipientCheck::NoMailKey => Some("no otp mail key for this nickname"),
        RecipientCheck::CliUnavailable => Some("the 'otp' command isn't installed"),
    }
}

fn render_mail_confirm(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    message: &str,
    proceed_label: &str,
    focus: Confirm,
) {
    let popup = centered_rect(64, 9, area);
    let block = Block::default().title(title.to_string()).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);
    frame.render_widget(
        Paragraph::new(message.to_string()).wrap(Wrap { trim: true }),
        rows[0],
    );
    render_confirm_row(
        frame,
        rows[1],
        ConfirmLabels::new(proceed_label, "Cancel"),
        Some(focus),
        BUTTON_WIDTH,
    );
}

fn render_mailbox(frame: &mut Frame, area: Rect, mb: &MailboxState) {
    let popup = centered_rect(72, 18, area);
    let block = Block::default()
        .title("OTP mail \u{2014} sent & received (Enter: read \u{2502} d: remove \u{2502} Esc: close)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    if mb.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("No OTP mail yet.").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }
    let items: Vec<ListItem> = mb
        .rows
        .iter()
        .map(|row| match row {
            MailboxRow::Sent(r) => ListItem::new(Line::from(vec![
                Span::raw(format!(
                    "\u{2192} to {}  {}  ",
                    r.to,
                    format_utc_short(r.sent_at_utc)
                )),
                sent_status_span(r.status),
            ])),
            MailboxRow::Received(r) => ListItem::new(Line::from(vec![Span::raw(format!(
                "\u{2190} from {}  {}  {}",
                r.from,
                format_utc_short(r.sent_at_utc),
                format_file_size(r.size)
            ))])),
        })
        .collect();
    let list =
        List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    list_state.select(Some(mb.selected.min(mb.rows.len() - 1)));
    frame.render_stateful_widget(list, inner, &mut list_state);
}

fn render_mail_reader(frame: &mut Frame, area: Rect, reader: &ReaderState) {
    let popup = centered_rect(76, 22, area);
    let p = &reader.payload;
    let block = Block::default()
        .title(format!(
            "Mail from {} \u{2014} {}",
            p.from,
            format_utc_short(p.sent_at_utc)
        ))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    let parts = p.voices.len() + p.attachments.len();
    let parts_height = if parts > 0 { (parts as u16 + 2).min(6) } else { 0 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),            // subtext
            Constraint::Min(3),               // content
            Constraint::Length(parts_height), // parts
            Constraint::Length(1),            // hints
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Subtext: ", Style::default().fg(Color::DarkGray)),
            Span::styled(p.subtext.clone(), Style::default().add_modifier(Modifier::BOLD)),
        ])),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(p.content.clone())
            .wrap(Wrap { trim: false })
            .scroll((reader.scroll, 0)),
        rows[1],
    );
    if parts > 0 {
        let parts_block = Block::default().title("Voice & attachments").borders(Borders::TOP);
        let parts_inner = parts_block.inner(rows[2]);
        frame.render_widget(parts_block, rows[2]);
        let items: Vec<ListItem> = p
            .voices
            .iter()
            .map(|v| {
                ListItem::new(format!(
                    "\u{1F3A4} voice {} (Enter to play)",
                    format_duration_label(v.duration_ms)
                ))
            })
            .chain(p.attachments.iter().map(|a| {
                ListItem::new(format!(
                    "\u{1F4CE} {} ({}) (Enter to save)",
                    a.filename,
                    format_file_size(a.bytes.len() as u64)
                ))
            }))
            .collect();
        let list =
            List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        let mut list_state = ListState::default();
        list_state.select(Some(reader.selected_part.min(parts - 1)));
        frame.render_stateful_widget(list, parts_inner, &mut list_state);
    }
    frame.render_widget(
        Paragraph::new(" Up/Down: select \u{2502} Enter: play/save \u{2502} PgUp/PgDn: scroll \u{2502} Esc: close")
            .style(Style::default().fg(Color::DarkGray)),
        rows[3],
    );
}
