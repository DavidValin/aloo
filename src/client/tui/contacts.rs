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

use crate::client::contacts::ContactRow;
use crate::client::file_browser::FileBrowserState;
use crate::crypto::otp::OtpPurpose;
use crate::proto::{KeyMode, UserId};

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
/// for whatever `otp --add-contact` refuses. `nickname`/`purpose` are
/// fixed at the moment this is opened (the list's top-level `o` shortcut
/// always sends `Live` for the row selected at that moment; the key detail
/// popup's own "Install manually" sends whichever of `Otp`/`OtpMail` it
/// was showing) rather than re-derived from `ContactsState::selected` at
/// submit time, so the two entry points can share every field-handling
/// function below unchanged.
pub struct InstallOtpState {
    pub nickname: String,
    /// Which of `nickname`'s devices this installs against - the row this
    /// was opened from, snapshotted the same way `nickname` is
    /// (device-pinning plan §3). `None` is the unbound row.
    pub device_id: Option<String>,
    pub purpose: OtpPurpose,
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

/// The three keys `/contacts` tracks per contact - Left/Right on the list
/// cycles which one is highlighted (`ContactsState::selected_key`), and
/// Enter opens the selected row's `ContactKeyDetailState` for whichever key
/// is currently selected. Selection is a genuine (row, key) grid: only the
/// button that is both `ContactsState::selected` and `selected_key` is
/// highlighted, never the same key across every row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactKeyKind {
    Pqh,
    Otp,
    OtpMail,
}

impl ContactKeyKind {
    pub fn label(self) -> &'static str {
        match self {
            ContactKeyKind::Pqh => "PQH",
            ContactKeyKind::Otp => "OTP",
            ContactKeyKind::OtpMail => "OTP MAIL",
        }
    }

    pub fn next(self) -> Self {
        match self {
            ContactKeyKind::Pqh => ContactKeyKind::Otp,
            ContactKeyKind::Otp => ContactKeyKind::OtpMail,
            ContactKeyKind::OtpMail => ContactKeyKind::Pqh,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            ContactKeyKind::Pqh => ContactKeyKind::OtpMail,
            ContactKeyKind::Otp => ContactKeyKind::Pqh,
            ContactKeyKind::OtpMail => ContactKeyKind::Otp,
        }
    }

    /// The exact explanatory sentence the details popup shows in yellow -
    /// verbatim, one per key, as specified for this feature.
    fn explanation(self) -> &'static str {
        match self {
            ContactKeyKind::Pqh => {
                "this key allows you to pin the identity of a user with a nickname ensuring you can communicate using pqh encryption (text, voice, files and calls)"
            }
            ContactKeyKind::Otp => {
                "this key allows you to have live One Time Pad sessions with the user when both of you are online (text, voice, files)"
            }
            ContactKeyKind::OtpMail => {
                "this key allows you to deliver Mails encrypted using One Time Pad and be automatically delivered to them when they come online on the same server"
            }
        }
    }
}

/// One key's row in the user-info popup (`i` on a channel member, `/info`
/// in an open DM) - only keys that genuinely exist get a row, unlike
/// `/contacts`' own list, which always shows all three with a ✅/❌ badge.
pub struct UserInfoKeyRow {
    pub kind: ContactKeyKind,
    /// PQH's short fingerprint, or OTP/OTP MAIL's contact name - the
    /// closest thing each key kind has to an id of its own.
    pub id: String,
}

/// A read-only snapshot of one live peer's pinned identity - nickname,
/// the device this connection actually announced, when it was last seen,
/// and every key that exists for that `(nickname, device_id)`. Never
/// edits anything; `/contacts` is where keys are managed. Opened empty
/// (`UiState::open_user_info`) and filled in once
/// `client::contacts::handle_request_user_info` has gathered it, the same
/// split `ContactsState::rows` uses.
pub struct UserInfoState {
    pub peer: UserId,
    pub nickname: String,
    /// `None` until the session-side gather resolves it (device-pinning
    /// plan §5's live-announce for a `pq_hybrid` peer,
    /// `PeerLinkManager::direct_device_id_of` for a serverless one) - also
    /// genuinely `None` for a peer met over a server with no `pq_hybrid`
    /// identity pinned at all.
    pub device_id: Option<String>,
    pub last_seen_unix: Option<u64>,
    pub keys: Vec<UserInfoKeyRow>,
}

/// The key-details popup, opened with Enter on a row - see the docs on
/// each field's owning action (`UiAction::PinIdentityCard`/`InstallOtpKey`/
/// `DeleteContact`/`DeleteContactKey`) for what "Create"/"Install
/// manually"/"Delete key" actually do.
pub struct ContactKeyDetailState {
    /// The row this was opened for - a `(nickname, device_id)` pair rather
    /// than an index, so this still finds the right row (or, if it
    /// vanished, notices) across a `RefreshContacts` triggered by one of
    /// its own actions.
    pub nickname: String,
    /// `None` is the unbound row (device-pinning plan §3).
    pub device_id: Option<String>,
    pub kind: ContactKeyKind,
    /// `Some` once "Delete key" is pressed with the key present - the same
    /// "destructive action is never one Enter away" confirm every other
    /// delete in this app uses.
    pub confirm: Option<DeleteChoice>,
    /// `Some` while picking an identity-card file for PQH's "Create key" -
    /// `pub` for the same test-determinism reason `InstallOtpState::browser`
    /// is.
    pub pqh_browser: Option<FileBrowserState>,
    /// An imported card that didn't validate, or named the wrong nickname
    /// - shown inline, same convention as `InstallOtpState::error`.
    pub pqh_error: Option<String>,
    /// `true` when this popup was opened from "Add contact"
    /// (`AddContactState`) rather than Enter on an existing row - nothing
    /// has been pinned for `(nickname, device_id)` yet, so PQH's "Create
    /// key" must bind directly to `device_id`
    /// (`UiAction::PinIdentityCardForDevice`) instead of the nickname's
    /// shared unbound entry the ordinary per-row "Create key" targets,
    /// and a successful pin must never close this popup - the whole point
    /// of Add Contact is adding OTP/OTP MAIL right after, in one sitting.
    pub new_contact: bool,
}

/// The "Add contact" popup (device-pinning plan §3): lets the user pin a
/// brand-new nickname+device before ever connecting to them. Nothing is
/// written to `id_store` just from opening or filling in this form - only
/// actually adding a key does that (`ContactKeyDetailState::new_contact`
/// takes over once the fields validate), so cancelling at any point
/// (`Esc`) leaves nothing behind.
pub struct AddContactState {
    pub nickname: String,
    pub device_id: String,
    pub focus: AddContactField,
    /// An empty/invalid field, an already-pinned `(nickname, device_id)`
    /// pair, or nothing yet - shown inline, same convention as
    /// `InstallOtpState::error`.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddContactField {
    Nickname,
    DeviceId,
}

pub struct ContactsState {
    pub rows: Vec<ContactRow>,
    pub selected: usize,
    /// Which key column Left/Right currently points at, within whichever
    /// row `selected` names - together they're a (row, key) grid cursor,
    /// so only one button in the whole list is ever highlighted at once.
    pub selected_key: ContactKeyKind,
    /// `Some` while the delete-confirmation popup is open, over the row
    /// selected when `d`/Delete was pressed.
    pub confirm_delete: Option<DeleteChoice>,
    /// `Some` while the "Install OTP key" popup is open, over the row
    /// selected when `o` was pressed.
    pub install: Option<InstallOtpState>,
    /// `Some` while the "Add contact" popup (`a`) is open.
    pub add_contact: Option<AddContactState>,
    /// `Some` while a key's details popup (Enter on a row) is open.
    pub detail: Option<ContactKeyDetailState>,
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
            selected_key: ContactKeyKind::Pqh,
            confirm_delete: None,
            install: None,
            add_contact: None,
            detail: None,
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

    /// Opens the user-info popup (`i` on a channel member, `/info` in an
    /// open DM) empty, and lets the caller also return
    /// `UiAction::RequestUserInfo` so the session fills it in - the same
    /// `open_contacts`/`OpenContacts` split. Deliberately does not touch
    /// `mode` - unlike `/contacts`, this is an overlay over whatever view
    /// is already on screen, the same as the message-info popup.
    pub fn open_user_info(&mut self, peer: UserId, nickname: String) {
        self.user_info = Some(UserInfoState { peer, nickname, device_id: None, last_seen_unix: None, keys: Vec::new() });
    }

    /// `RequestUserInfo`'s answer. A no-op if the popup was closed (or
    /// reopened for someone else) before the session's answer arrived.
    pub fn set_user_info(
        &mut self,
        peer: UserId,
        device_id: Option<String>,
        last_seen_unix: Option<u64>,
        keys: Vec<UserInfoKeyRow>,
    ) {
        let Some(info) = self.user_info.as_mut() else { return };
        if info.peer != peer {
            return;
        }
        info.device_id = device_id;
        info.last_seen_unix = last_seen_unix;
        info.keys = keys;
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

    /// PQH's "Create key" success path - closes the whole key-details
    /// popup, same as `close_contacts_install`'s reasoning: the caller
    /// (`client::contacts::handle_pin_identity_card`) refreshes the row
    /// set right after, and there is nothing left in the details popup to
    /// show once the identity it was about has just been replaced.
    pub fn close_contacts_pqh_create(&mut self) {
        if let Some(state) = self.contacts.as_mut() {
            state.detail = None;
        }
    }

    /// The PQH "Create key" failure path - shown inline over the file
    /// browser closing back to the details popup, same convention as
    /// `set_contacts_install_error`. A no-op if the details popup isn't
    /// open any more.
    pub fn set_contacts_pqh_create_error(&mut self, message: String) {
        if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
            detail.pqh_error = Some(message);
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
        let has_detail = self.contacts.as_ref().map(|c| c.detail.is_some()).unwrap_or(false);
        if has_detail {
            return self.handle_contacts_detail_key(code);
        }
        let has_add_contact = self.contacts.as_ref().map(|c| c.add_contact.is_some()).unwrap_or(false);
        if has_add_contact {
            return self.handle_contacts_add_key(code);
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
            KeyCode::Left => {
                if let Some(state) = self.contacts.as_mut() {
                    state.selected_key = state.selected_key.prev();
                }
                None
            }
            KeyCode::Right => {
                if let Some(state) = self.contacts.as_mut() {
                    state.selected_key = state.selected_key.next();
                }
                None
            }
            KeyCode::Enter => {
                if len == 0 {
                    return None;
                }
                let (nickname, device_id, kind) = {
                    let state = self.contacts.as_ref()?;
                    let row = state.rows.get(state.selected)?;
                    (row.nickname.clone(), row.device_id.clone(), state.selected_key)
                };
                if let Some(state) = self.contacts.as_mut() {
                    state.detail = Some(ContactKeyDetailState {
                        nickname,
                        device_id,
                        kind,
                        confirm: None,
                        pqh_browser: None,
                        pqh_error: None,
                        new_contact: false,
                    });
                }
                None
            }
            KeyCode::Char('a') => {
                if let Some(state) = self.contacts.as_mut() {
                    state.add_contact = Some(AddContactState {
                        nickname: String::new(),
                        device_id: String::new(),
                        focus: AddContactField::Nickname,
                        error: None,
                    });
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
                        nickname: row.nickname,
                        device_id: row.device_id,
                        purpose: OtpPurpose::Live,
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

    fn handle_contacts_add_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.contacts.as_mut() {
                    state.add_contact = None;
                }
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if let Some(add) = self.contacts.as_mut().and_then(|c| c.add_contact.as_mut()) {
                    add.focus = match add.focus {
                        AddContactField::Nickname => AddContactField::DeviceId,
                        AddContactField::DeviceId => AddContactField::Nickname,
                    };
                }
                None
            }
            KeyCode::Backspace => {
                if let Some(add) = self.contacts.as_mut().and_then(|c| c.add_contact.as_mut()) {
                    match add.focus {
                        AddContactField::Nickname => {
                            add.nickname.pop();
                        }
                        AddContactField::DeviceId => {
                            add.device_id.pop();
                        }
                    }
                }
                None
            }
            KeyCode::Char(c) => {
                if let Some(add) = self.contacts.as_mut().and_then(|c| c.add_contact.as_mut()) {
                    match add.focus {
                        AddContactField::Nickname => add.nickname.push(c),
                        AddContactField::DeviceId => add.device_id.push(c),
                    }
                }
                None
            }
            KeyCode::Enter => self.submit_add_contact(),
            _ => None,
        }
    }

    /// Validates the typed nickname/device_id (same rules
    /// `DirectPunchTarget::parse` already applies to a manually-typed
    /// nickname+device pair: non-empty, `is_storable`) and that no row
    /// already pins this exact `(nickname, device_id)`. On success, opens
    /// the *same* key-details popup Enter-on-a-row does, marked
    /// `new_contact: true` - nothing is written to `id_store` by this
    /// step alone, only by actually adding a key from there.
    fn submit_add_contact(&mut self) -> Option<UiAction> {
        let (nickname, device_id) = {
            let add = self.contacts.as_ref()?.add_contact.as_ref()?;
            (add.nickname.clone(), add.device_id.clone())
        };
        let error = if nickname.is_empty() || !crate::validation::is_storable(&nickname) {
            Some(format!("not a valid nickname: {nickname:?}"))
        } else if device_id.is_empty() || !crate::validation::is_storable(&device_id) {
            Some(format!("not a valid device id: {device_id:?}"))
        } else if self
            .contacts
            .as_ref()?
            .rows
            .iter()
            .any(|r| r.nickname == nickname && r.device_id.as_deref() == Some(device_id.as_str()))
        {
            Some(format!(
                "{nickname}'s device {device_id:?} is already pinned - open that row instead"
            ))
        } else {
            None
        };
        if let Some(message) = error {
            if let Some(add) = self.contacts.as_mut().and_then(|c| c.add_contact.as_mut()) {
                add.error = Some(message);
            }
            return None;
        }
        if let Some(state) = self.contacts.as_mut() {
            state.add_contact = None;
            state.detail = Some(ContactKeyDetailState {
                nickname,
                device_id: Some(device_id),
                kind: ContactKeyKind::Pqh,
                confirm: None,
                pqh_browser: None,
                pqh_error: None,
                new_contact: true,
            });
        }
        None
    }

    fn handle_contacts_detail_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let has_browser = self
            .contacts
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .map(|d| d.pqh_browser.is_some())
            .unwrap_or(false);
        if has_browser {
            return self.handle_contacts_pqh_browser_key(code);
        }
        let has_confirm = self
            .contacts
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .map(|d| d.confirm.is_some())
            .unwrap_or(false);
        if has_confirm {
            return self.handle_contacts_detail_confirm_key(code);
        }
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.contacts.as_mut() {
                    state.detail = None;
                }
                None
            }
            KeyCode::Left => {
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.kind = detail.kind.prev();
                    detail.pqh_error = None;
                }
                None
            }
            KeyCode::Right => {
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.kind = detail.kind.next();
                    detail.pqh_error = None;
                }
                None
            }
            KeyCode::Enter => self.activate_contacts_detail_action(),
            _ => None,
        }
    }

    /// Whether the row `detail` was opened for still has the key it names
    /// - decides whether Enter offers Create/Install or Delete. Read fresh
    /// from `rows` (never cached on `detail` itself) so an install/delete
    /// that ran while this same popup stayed open is reflected the moment
    /// `RefreshContacts` answers, exactly the "takes effect immediately"
    /// requirement this whole popup exists for.
    /// `None` only when there is no `detail` popup open at all to ask
    /// about - a genuinely absent row (a brand-new contact from "Add
    /// Contact", before any key has been pinned for it yet) answers
    /// `Some(false)`, the same as a real row missing that one key, rather
    /// than short-circuiting to "nothing to determine": that distinction
    /// is exactly what lets `activate_contacts_detail_action` reach
    /// "Create key"/"Install manually" for a contact that does not exist
    /// in `rows` yet.
    fn contacts_detail_key_present(&self) -> Option<bool> {
        let state = self.contacts.as_ref()?;
        let detail = state.detail.as_ref()?;
        let Some(row) =
            state.rows.iter().find(|r| r.nickname == detail.nickname && r.device_id == detail.device_id)
        else {
            return Some(false);
        };
        Some(match detail.kind {
            ContactKeyKind::Pqh => row.key_mode == Some(KeyMode::PqHybrid),
            ContactKeyKind::Otp => row.otp.is_some(),
            ContactKeyKind::OtpMail => row.otp_mail.is_some(),
        })
    }

    fn activate_contacts_detail_action(&mut self) -> Option<UiAction> {
        let present = self.contacts_detail_key_present()?;
        if present {
            if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                detail.confirm = Some(DeleteChoice::default());
            }
            return None;
        }
        let (nickname, device_id, kind) = {
            let detail = self.contacts.as_ref()?.detail.as_ref()?;
            (detail.nickname.clone(), detail.device_id.clone(), detail.kind)
        };
        match kind {
            ContactKeyKind::Pqh => self.open_contacts_pqh_browser(),
            ContactKeyKind::Otp => self.open_contacts_detail_install(nickname, device_id, OtpPurpose::Live),
            ContactKeyKind::OtpMail => {
                self.open_contacts_detail_install(nickname, device_id, OtpPurpose::Mail)
            }
        }
    }

    fn open_contacts_detail_install(
        &mut self,
        nickname: String,
        device_id: Option<String>,
        purpose: OtpPurpose,
    ) -> Option<UiAction> {
        if let Some(state) = self.contacts.as_mut() {
            state.install = Some(InstallOtpState {
                nickname,
                device_id,
                purpose,
                enc_path: String::new(),
                dec_path: String::new(),
                focus: InstallField::EncPath,
                browser: None,
                error: None,
            });
        }
        None
    }

    fn open_contacts_pqh_browser(&mut self) -> Option<UiAction> {
        let start = std::env::current_dir().ok()?;
        let browser = FileBrowserState::open(start).ok()?;
        if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
            detail.pqh_browser = Some(browser);
            detail.pqh_error = None;
        }
        None
    }

    fn handle_contacts_pqh_browser_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Up => {
                if let Some(b) = self.contacts_pqh_browser_mut() {
                    b.select_prev();
                }
                None
            }
            KeyCode::Down => {
                if let Some(b) = self.contacts_pqh_browser_mut() {
                    b.select_next();
                }
                None
            }
            KeyCode::Left => {
                if let Some(b) = self.contacts_pqh_browser_mut() {
                    let _ = b.go_back();
                }
                None
            }
            KeyCode::Right => {
                if let Some(b) = self.contacts_pqh_browser_mut() {
                    let _ = b.go_forward();
                }
                None
            }
            KeyCode::Esc => {
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.pqh_browser = None;
                }
                None
            }
            KeyCode::Enter => {
                let (nickname, device_id, new_contact) = {
                    let detail = self.contacts.as_ref()?.detail.as_ref()?;
                    (detail.nickname.clone(), detail.device_id.clone(), detail.new_contact)
                };
                let detail = self.contacts.as_mut()?.detail.as_mut()?;
                let browser = detail.pqh_browser.as_mut()?;
                let entry = browser.selected_entry()?;
                if entry.is_dir {
                    let _ = browser.navigate_into_selected();
                    return None;
                }
                let path = browser.selected_path()?;
                detail.pqh_browser = None;
                if new_contact {
                    Some(UiAction::PinIdentityCardForDevice {
                        nickname,
                        device_id: device_id.unwrap_or_default(),
                        path,
                    })
                } else {
                    Some(UiAction::PinIdentityCard { nickname, path })
                }
            }
            _ => None,
        }
    }

    fn contacts_pqh_browser_mut(&mut self) -> Option<&mut FileBrowserState> {
        self.contacts.as_mut()?.detail.as_mut()?.pqh_browser.as_mut()
    }

    fn handle_contacts_detail_confirm_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.confirm = None;
                }
                None
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.confirm = Some(match detail.confirm {
                        Some(DeleteChoice::Delete) => DeleteChoice::Cancel,
                        _ => DeleteChoice::Delete,
                    });
                }
                None
            }
            KeyCode::Enter => {
                let (choice, nickname, device_id, kind) = {
                    let detail = self.contacts.as_ref()?.detail.as_ref()?;
                    (detail.confirm?, detail.nickname.clone(), detail.device_id.clone(), detail.kind)
                };
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.confirm = None;
                }
                if choice != DeleteChoice::Delete {
                    return None;
                }
                match kind {
                    ContactKeyKind::Pqh => {
                        // Deleting this device's identity pin necessarily
                        // takes both purposes' keychain entries *for this
                        // device* with it (they become unnameable the
                        // instant it's gone) - but leaves every sibling
                        // device's own pin and keys untouched
                        // (device-pinning plan §3's additive delete) -
                        // nothing left in this popup to show afterward.
                        if let Some(state) = self.contacts.as_mut() {
                            state.detail = None;
                        }
                        Some(UiAction::DeleteContactDevice { nickname, device_id })
                    }
                    ContactKeyKind::Otp => Some(UiAction::DeleteContactKey {
                        nickname,
                        device_id,
                        purpose: OtpPurpose::Live,
                    }),
                    ContactKeyKind::OtpMail => Some(UiAction::DeleteContactKey {
                        nickname,
                        device_id,
                        purpose: OtpPurpose::Mail,
                    }),
                }
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
        let (nickname, device_id, purpose, enc_path, dec_path) = {
            let install = self.contacts.as_ref()?.install.as_ref()?;
            (
                install.nickname.clone(),
                install.device_id.clone(),
                install.purpose,
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
            device_id,
            purpose,
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

/// `<remaining>MB`, formatted exactly like
/// `direct_message::push_otp_key_spans` - the same figure the `/otp` DM
/// header shows, so a contact's remaining-key reads identically wherever
/// it appears.
fn fmt_mb(remaining_bytes: u64) -> String {
    format!("{:.2}MB", remaining_bytes as f64 / (1024.0 * 1024.0))
}

/// The widths of every column, measured across the whole row set so they
/// line up down the list - the same idiom `ui::CallColumns` uses for the
/// call modal's roster. The three keys' badges (`push_key_badges`) are a
/// fixed width, so unlike `nickname`/`last_seen`/`encryption` they need no
/// measuring.
struct ContactsColumns {
    nickname: usize,
    device: usize,
    last_seen: usize,
    encryption: usize,
}

/// The device column's text - the device id verbatim for a bound row, or a
/// fixed placeholder for the unbound row (device-pinning plan §3: never
/// editable from here, only ever learned from a live connection or a
/// pad's own device claim).
/// A real device_id (`~/.aloo/d_id`) is a 50-character random string - far
/// too wide for a list column - so it's cropped here, not just measured
/// short; a test device's short, human-chosen name (e.g. "laptop") passes
/// through unchanged.
const DEVICE_LABEL_MAX_CHARS: usize = 10;

fn device_label(device_id: &Option<String>) -> String {
    match device_id {
        Some(id) if id.chars().count() > DEVICE_LABEL_MAX_CHARS => {
            let cropped: String = id.chars().take(DEVICE_LABEL_MAX_CHARS).collect();
            format!("{cropped}...")
        }
        Some(id) => id.clone(),
        None => "(unbound)".to_string(),
    }
}

impl ContactsColumns {
    fn measure(rows: &[ContactRow]) -> Self {
        let nickname = rows
            .iter()
            .map(|r| display_width(&r.nickname) as usize)
            .max()
            .unwrap_or(0)
            .max(display_width("nickname") as usize);
        let device = rows
            .iter()
            .map(|r| display_width(&device_label(&r.device_id)) as usize)
            .max()
            .unwrap_or(0)
            .max(display_width("device") as usize);
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
        Self {
            nickname,
            device,
            last_seen,
            encryption,
        }
    }
}

/// One column's gap to the next.
const COL_GAP: usize = 2;

/// Extra breathing room between the encryption column and the keys
/// buttons, on top of `COL_GAP` - the buttons' own brackets already read
/// as a boundary, so without this they crowd right up against
/// "encryption"/its value.
const KEYS_COL_EXTRA_GAP: usize = 2;

/// The three keys' button row, e.g. `[\u{2705}PQH] [\u{274c}OTP] [\u{274c}OTP MAIL]` -
/// `selected_key` is `ContactsState::selected_key`, `row_selected` is
/// whether *this* row is `ContactsState::selected` (`i == selected` at the
/// call site). Only the one cell that is both this row and this key gets
/// the gray background - a genuine per-(row, key) grid cursor, `Up`/`Down`
/// moving between rows and `Left`/`Right` moving between keys, so it's
/// never ambiguous which device's key `Enter` is about to open.
const KEY_BADGES_SAMPLE: &str = "[\u{2705}PQH] [\u{2705}OTP] [\u{2705}OTP MAIL]";

/// The ✅/❌ + color a key badge renders with, whether present or not -
/// shared by the contacts-list badges and the user-info popup (`i`/
/// `/info`), which reuses only the "present" half since it lists nothing
/// but keys that exist.
fn key_presence_icon(present: bool) -> (&'static str, Color) {
    if present { ("\u{2705}", Color::Green) } else { ("\u{274c}", Color::Red) }
}

fn push_key_badge(
    spans: &mut Vec<Span<'static>>,
    label: &'static str,
    present: bool,
    kind: ContactKeyKind,
    selected_key: ContactKeyKind,
    row_selected: bool,
) {
    let (icon, color) = key_presence_icon(present);
    let mut style = Style::default().fg(color);
    if row_selected && kind == selected_key {
        style = style.bg(Color::Gray);
    }
    spans.push(Span::styled(format!("[{icon}{label}]"), style));
}

fn push_key_badges(
    spans: &mut Vec<Span<'static>>,
    row: &ContactRow,
    selected_key: ContactKeyKind,
    row_selected: bool,
) {
    push_key_badge(spans, "PQH", row.key_mode == Some(KeyMode::PqHybrid), ContactKeyKind::Pqh, selected_key, row_selected);
    spans.push(Span::raw(" "));
    push_key_badge(spans, "OTP", row.otp.is_some(), ContactKeyKind::Otp, selected_key, row_selected);
    spans.push(Span::raw(" "));
    push_key_badge(spans, "OTP MAIL", row.otp_mail.is_some(), ContactKeyKind::OtpMail, selected_key, row_selected);
}

fn pad_to(spans: &mut Vec<Span<'static>>, width: usize) {
    let used: usize = spans.iter().map(|s| display_width(&s.content) as usize).sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
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
        "device",
        Style::default().add_modifier(Modifier::BOLD),
    ));
    pad_to(&mut spans, start + columns.device);
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
    spans.push(Span::raw(" ".repeat(COL_GAP + KEYS_COL_EXTRA_GAP)));
    spans.push(Span::styled("keys", Style::default().add_modifier(Modifier::BOLD)));
    Line::from(spans)
}

/// `row_selected` reverses only the nickname/last-seen/encryption columns -
/// never the keys column, which is why `push_key_badges` is appended
/// *after* that reversal is patched on, untouched by it. The keys column
/// carries its own indicator instead: a gray background, but only on the
/// one button that is both this row (`row_selected`) and the highlighted
/// key (`selected_key`) - never on the same key in a different row, so
/// which device's key `Enter` would open is never ambiguous.
fn contact_row_line(
    row: &ContactRow,
    columns: &ContactsColumns,
    selected_key: ContactKeyKind,
    row_selected: bool,
) -> Line<'static> {
    let mut spans = vec![Span::raw(row.nickname.clone())];
    pad_to(&mut spans, columns.nickname);
    spans.push(Span::raw(" ".repeat(COL_GAP)));

    let device_text = device_label(&row.device_id);
    let device_style = if row.device_id.is_some() {
        Style::default()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let start = spans.iter().map(|s| display_width(&s.content) as usize).sum::<usize>();
    spans.push(Span::styled(device_text, device_style));
    pad_to(&mut spans, start + columns.device);
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

    if row_selected {
        for span in &mut spans {
            span.style = span.style.patch(Style::default().add_modifier(Modifier::REVERSED));
        }
    }

    spans.push(Span::raw(" ".repeat(KEYS_COL_EXTRA_GAP)));
    push_key_badges(&mut spans, row, selected_key, row_selected);

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
    if let Some(detail) = &contacts.detail {
        render_contact_key_detail_popup(frame, area, contacts, detail);
        return;
    }
    if let Some(add) = &contacts.add_contact {
        render_add_contact_popup(frame, area, add);
        return;
    }

    let columns = ContactsColumns::measure(&contacts.rows);
    let content_width = columns.nickname
        + columns.device
        + columns.last_seen
        + columns.encryption
        + COL_GAP * 4
        + display_width(KEY_BADGES_SAMPLE) as usize;
    let width = (content_width as u16 + 4).clamp(60, area.width.saturating_sub(2));
    // At least 7 lines even with a single (or no) contact - short enough to
    // still shrink-wrap a long list, tall enough that the popup never reads
    // as a cramped sliver.
    let height = (contacts.rows.len().max(1) as u16 + 4)
        .max(7)
        .min(area.height.saturating_sub(2));
    let popup = centered_rect(width, height, area);
    let block = Block::default()
        .title(Line::from(vec![
            Span::raw("Contacts "),
            Span::styled(
                "(\u{2190}/\u{2192}: switch key  Enter: key details  a: add contact  o: install OTP key  d: delete  r: refresh  Esc: close)",
                Style::default().fg(Color::Cyan),
            ),
        ]))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    if contacts.rows.is_empty() {
        frame.render_widget(
            Paragraph::new(
                "no contacts pinned yet - one appears the first time you connect to someone, \
                 or press 'a' to add one manually",
            )
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

    let selected = contacts.selected.min(contacts.rows.len() - 1);
    let items: Vec<ListItem> = contacts
        .rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            ListItem::new(contact_row_line(row, &columns, contacts.selected_key, i == selected))
        })
        .collect();
    // No `highlight_style` - the selected row's reverse-video is already
    // patched onto its own spans above (stopping before the keys column),
    // and `list_state` only drives auto-scroll-to-selection here.
    let list = List::new(items);
    let mut list_state = ListState::default();
    list_state.select(Some(selected));
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
        .map(|r| r.otp.is_some() || r.otp_mail.is_some())
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
            "Their OTP and OTP mail keys are deleted too - this cannot be undone.",
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

/// One direction's `seq <n> offset <n> remaining <mb>` line, the same
/// figures the `/otp` DM header shows (`direct_message::render_otp_header`)
/// - the key detail popup's metadata section, one call per direction.
fn otp_direction_detail_line(label: &str, seq: u64, offset: u64, remaining_bytes: u64) -> Line<'static> {
    let remaining_color = if remaining_bytes < OTP_KEY_LOW_THRESHOLD_BYTES {
        Color::Red
    } else {
        Color::Green
    };
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::Gray)),
        Span::raw(format!("seq {seq} offset {offset} ")),
        Span::styled(format!("remaining {}", fmt_mb(remaining_bytes)), Style::default().fg(remaining_color)),
    ])
}

/// The user-info popup (`i` on a channel member, `/info` in an open DM):
/// nickname, device id, last-seen, one row per key that exists (icon and
/// color matching the contacts list's own badges), and, live rather than
/// from the gathered snapshot, whether an OTP session is active right now.
pub(crate) fn render_user_info_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(info) = &state.user_info else { return };
    let otp_active = state.is_otp_active(info.peer);
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("device: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(info.device_id.as_deref().unwrap_or("(unbound)").to_string()),
        ]),
        Line::from(vec![
            Span::styled("last seen: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_last_seen(info.last_seen_unix)),
        ]),
        Line::from(""),
    ];
    if info.keys.is_empty() {
        lines.push(Line::from(Span::styled("no keys pinned yet", Style::default().fg(Color::DarkGray))));
    }
    for key in &info.keys {
        let (icon, color) = key_presence_icon(true);
        lines.push(Line::from(vec![
            Span::styled(format!("{icon} {} ", key.kind.label()), Style::default().fg(color)),
            Span::raw(key.id.clone()),
        ]));
    }
    if otp_active {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "OTP session is currently active",
            Style::default().fg(Color::Green),
        )));
    }

    let height = (lines.len() as u16 + 2).max(7).min(area.height.saturating_sub(2));
    let popup = centered_rect(64, height, area);
    let block = Block::default()
        .title(format!("{} (Esc: close)", info.nickname))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }), inner);
}

/// The key-details popup (Enter on a row) - the yellow explanation for
/// `detail.kind`, then either the key's path(s)/metadata and a "Delete
/// key" prompt, or "not installed" and a "Create"/"Install manually"
/// prompt. Never both at once, mirroring the request's own "Create key
/// (if not existing...) or Delete key" as mutually exclusive.
fn render_contact_key_detail_popup(
    frame: &mut Frame,
    area: Rect,
    contacts: &ContactsState,
    detail: &ContactKeyDetailState,
) {
    if let Some(browser) = &detail.pqh_browser {
        render_file_browser(frame, area, browser, "Select identity card file");
        return;
    }
    let row = contacts
        .rows
        .iter()
        .find(|r| r.nickname == detail.nickname && r.device_id == detail.device_id);
    let kind = detail.kind;
    let present = match kind {
        ContactKeyKind::Pqh => row.is_some_and(|r| r.key_mode == Some(KeyMode::PqHybrid)),
        ContactKeyKind::Otp => row.is_some_and(|r| r.otp.is_some()),
        ContactKeyKind::OtpMail => row.is_some_and(|r| r.otp_mail.is_some()),
    };

    let height: u16 = if detail.confirm.is_some() {
        9
    } else if present && kind != ContactKeyKind::Pqh {
        16
    } else {
        12
    };
    let popup = centered_rect(72, height, area);
    let block = Block::default()
        .title(format!(
            "{} \u{2014} {} (\u{2190}/\u{2192}: switch key  Esc: close)",
            detail.nickname,
            kind.label()
        ))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    if detail.confirm.is_some() {
        let rows = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([ratatui::layout::Constraint::Min(3), ratatui::layout::Constraint::Length(3)])
            .split(inner);
        frame.render_widget(
            Paragraph::new(format!("Delete the {} key for {}? This cannot be undone.", kind.label(), detail.nickname))
                .wrap(ratatui::widgets::Wrap { trim: true }),
            rows[0],
        );
        let button_cols = ratatui::layout::Layout::default()
            .direction(ratatui::layout::Direction::Horizontal)
            .constraints([ratatui::layout::Constraint::Percentage(50), ratatui::layout::Constraint::Percentage(50)])
            .split(rows[1]);
        render_popup_button(frame, button_cols[0], 18, "Delete", detail.confirm == Some(DeleteChoice::Delete));
        render_popup_button(frame, button_cols[1], 18, "Cancel", detail.confirm == Some(DeleteChoice::Cancel));
        return;
    }

    // The list column crops a long device_id for width (`device_label`) -
    // this popup is exactly where that ambiguity must not follow, since
    // it is what a destructive action (delete key) or an install actually
    // targets.
    let device_display = match &detail.device_id {
        Some(id) => id.as_str(),
        None => "(unbound)",
    };
    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(kind.explanation(), Style::default().fg(Color::Yellow))),
        Line::from(format!("device: {device_display}")),
        Line::from(""),
    ];
    if present {
        match kind {
            ContactKeyKind::Pqh => {
                if let Some(fp) = row.and_then(|r| r.pqh_fingerprint.as_deref()) {
                    lines.push(Line::from(format!("id: {fp}")));
                }
                let path = row
                    .and_then(|r| r.pqh_pinned_from.as_ref())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "received over the wire (trust-on-first-use)".to_string());
                lines.push(Line::from(format!("path: {path}")));
            }
            ContactKeyKind::Otp | ContactKeyKind::OtpMail => {
                let otp = match kind {
                    ContactKeyKind::Otp => row.and_then(|r| r.otp.as_ref()),
                    _ => row.and_then(|r| r.otp_mail.as_ref()),
                };
                if let Some(otp) = otp {
                    lines.push(Line::from(format!("enc key file: {}", otp.enc_key_path.display())));
                    lines.push(Line::from(format!("dec key file: {}", otp.dec_key_path.display())));
                    lines.push(Line::from(""));
                    lines.push(otp_direction_detail_line("dec", otp.dec_sequence, otp.dec_offset, otp.dec_key_remaining));
                    lines.push(otp_direction_detail_line("enc", otp.enc_sequence, otp.enc_offset, otp.enc_key_remaining));
                }
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Enter: Delete key",
            Style::default().add_modifier(Modifier::BOLD),
        )));
    } else {
        lines.push(Line::from(Span::styled("not installed", Style::default().fg(Color::DarkGray))));
        lines.push(Line::from(""));
        let action = if kind == ContactKeyKind::Pqh { "Create key" } else { "Install manually" };
        lines.push(Line::from(Span::styled(
            format!("Enter: {action}"),
            Style::default().add_modifier(Modifier::BOLD),
        )));
    }
    if let Some(err) = &detail.pqh_error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(err.as_str(), Style::default().fg(Color::Red))));
    }
    frame.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }), inner);
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

fn render_add_contact_popup(frame: &mut Frame, area: Rect, add: &AddContactState) {
    let popup = centered_rect(60, if add.error.is_some() { 10 } else { 8 }, area);
    let block = Block::default()
        .title("Add contact (Tab: switch field  Enter: continue  Esc: cancel)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![
        ratatui::layout::Constraint::Length(3), // explanation
        ratatui::layout::Constraint::Length(1), // nickname
        ratatui::layout::Constraint::Length(1), // device_id
    ];
    if add.error.is_some() {
        constraints.push(ratatui::layout::Constraint::Length(1)); // spacer
        constraints.push(ratatui::layout::Constraint::Min(1)); // error
    }
    let rows = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    frame.render_widget(
        Paragraph::new(
            "Pin a nickname and device before ever connecting to them, so you can \
             attach a PQH, OTP or OTP mail key right away.",
        )
        .wrap(ratatui::widgets::Wrap { trim: true })
        .style(Style::default().fg(Color::DarkGray)),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(key_field_line("nickname", &add.nickname, add.focus == AddContactField::Nickname)),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new(key_field_line("device id", &add.device_id, add.focus == AddContactField::DeviceId)),
        rows[2],
    );
    if let Some(err) = &add.error {
        frame.render_widget(Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)), rows[4]);
    }
}

fn render_install_popup(
    frame: &mut Frame,
    area: Rect,
    _contacts: &ContactsState,
    install: &InstallOtpState,
) {
    if let Some((_, browser)) = &install.browser {
        render_file_browser(frame, area, browser, "Select key file");
        return;
    }
    let nickname = install.nickname.as_str();
    let label = install.purpose.label();

    let popup = centered_rect(72, 15, area);
    let block = Block::default()
        .title(format!("Install {label} for {nickname}"))
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
         Send one part to {nickname} and keep the other - this installs it as their {label}. \
         Below, point encryption key to your own sending half and decryption key to your own receiving half.\n\
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
