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
/// for whatever `otp --add-contact` refuses. `nickname`/`purpose` are
/// fixed at the moment this is opened (the list's top-level `o` shortcut
/// always sends `Live` for the row selected at that moment; the key detail
/// popup's own "Install manually" sends whichever of `Otp`/`OtpMail` it
/// was showing) rather than re-derived from `ContactsState::selected` at
/// submit time, so the two entry points can share every field-handling
/// function below unchanged.
pub struct InstallOtpState {
    pub nickname: String,
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
/// cycles which one is highlighted (`ContactsState::selected_key`,
/// independent of which *row* the cursor is on), and Enter opens that
/// row's `ContactKeyDetailState` for whichever key is currently selected.
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

/// The key-details popup, opened with Enter on a row - see the docs on
/// each field's owning action (`UiAction::PinIdentityCard`/`InstallOtpKey`/
/// `DeleteContact`/`DeleteContactKey`) for what "Create"/"Install
/// manually"/"Delete key" actually do.
pub struct ContactKeyDetailState {
    /// The row this was opened for - a nickname rather than an index, so
    /// this still finds the right row (or, if it vanished, notices) across
    /// a `RefreshContacts` triggered by one of its own actions.
    pub nickname: String,
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
}

pub struct ContactsState {
    pub rows: Vec<ContactRow>,
    pub selected: usize,
    /// Which key type Left/Right is currently pointing the whole list at -
    /// independent of `selected`, so paging through rows keeps comparing
    /// the same key across contacts.
    pub selected_key: ContactKeyKind,
    /// `Some` while the delete-confirmation popup is open, over the row
    /// selected when `d`/Delete was pressed.
    pub confirm_delete: Option<DeleteChoice>,
    /// `Some` while the "Install OTP key" popup is open, over the row
    /// selected when `o` was pressed.
    pub install: Option<InstallOtpState>,
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
                let (nickname, kind) = {
                    let state = self.contacts.as_ref()?;
                    (state.rows.get(state.selected)?.nickname.clone(), state.selected_key)
                };
                if let Some(state) = self.contacts.as_mut() {
                    state.detail = Some(ContactKeyDetailState {
                        nickname,
                        kind,
                        confirm: None,
                        pqh_browser: None,
                        pqh_error: None,
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
    fn contacts_detail_key_present(&self) -> Option<bool> {
        let state = self.contacts.as_ref()?;
        let detail = state.detail.as_ref()?;
        let row = state.rows.iter().find(|r| r.nickname == detail.nickname)?;
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
        let (nickname, kind) = {
            let detail = self.contacts.as_ref()?.detail.as_ref()?;
            (detail.nickname.clone(), detail.kind)
        };
        match kind {
            ContactKeyKind::Pqh => self.open_contacts_pqh_browser(),
            ContactKeyKind::Otp => self.open_contacts_detail_install(nickname, OtpPurpose::Live),
            ContactKeyKind::OtpMail => self.open_contacts_detail_install(nickname, OtpPurpose::Mail),
        }
    }

    fn open_contacts_detail_install(&mut self, nickname: String, purpose: OtpPurpose) -> Option<UiAction> {
        if let Some(state) = self.contacts.as_mut() {
            state.install = Some(InstallOtpState {
                nickname,
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
                let nickname = self.contacts.as_ref()?.detail.as_ref()?.nickname.clone();
                let detail = self.contacts.as_mut()?.detail.as_mut()?;
                let browser = detail.pqh_browser.as_mut()?;
                let entry = browser.selected_entry()?;
                if entry.is_dir {
                    let _ = browser.navigate_into_selected();
                    return None;
                }
                let path = browser.selected_path()?;
                detail.pqh_browser = None;
                Some(UiAction::PinIdentityCard { nickname, path })
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
                let (choice, nickname, kind) = {
                    let detail = self.contacts.as_ref()?.detail.as_ref()?;
                    (detail.confirm?, detail.nickname.clone(), detail.kind)
                };
                if let Some(detail) = self.contacts.as_mut().and_then(|c| c.detail.as_mut()) {
                    detail.confirm = None;
                }
                if choice != DeleteChoice::Delete {
                    return None;
                }
                match kind {
                    ContactKeyKind::Pqh => {
                        // Deleting the identity pin necessarily takes both
                        // purposes' keychain entries with it (they become
                        // unnameable the instant it's gone) - nothing left
                        // in this popup to show afterward.
                        if let Some(state) = self.contacts.as_mut() {
                            state.detail = None;
                        }
                        Some(UiAction::DeleteContact { nickname })
                    }
                    ContactKeyKind::Otp => Some(UiAction::DeleteContactKey {
                        nickname,
                        purpose: OtpPurpose::Live,
                    }),
                    ContactKeyKind::OtpMail => Some(UiAction::DeleteContactKey {
                        nickname,
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
        let (nickname, purpose, enc_path, dec_path) = {
            let install = self.contacts.as_ref()?.install.as_ref()?;
            (
                install.nickname.clone(),
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
    last_seen: usize,
    encryption: usize,
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
        Self {
            nickname,
            last_seen,
            encryption,
        }
    }
}

/// One column's gap to the next.
const COL_GAP: usize = 2;

/// The three keys' badge row, e.g. `\u{2705}PQH \u{274c}OTP \u{274c}OTP MAIL` - `selected`
/// names whichever one `ContactsState::selected_key` currently points at,
/// with a gray background on *every* row so it reads as "this key, across
/// the whole list" rather than a per-row selection - deliberately never
/// reverse-video, so it stays visible independent of the row-selection
/// highlight (which stops before this column entirely, see
/// `contact_row_line`).
const KEY_BADGES_SAMPLE: &str = "\u{2705}PQH \u{2705}OTP \u{2705}OTP MAIL";

fn push_key_badge(
    spans: &mut Vec<Span<'static>>,
    label: &'static str,
    present: bool,
    kind: ContactKeyKind,
    selected: ContactKeyKind,
) {
    let (icon, color) = if present {
        ("\u{2705}", Color::Green)
    } else {
        ("\u{274c}", Color::Red)
    };
    let mut style = Style::default().fg(color);
    if kind == selected {
        style = style.bg(Color::Gray);
    }
    spans.push(Span::styled(format!("{icon}{label}"), style));
}

fn push_key_badges(spans: &mut Vec<Span<'static>>, row: &ContactRow, selected: ContactKeyKind) {
    push_key_badge(spans, "PQH", row.key_mode == Some(KeyMode::PqHybrid), ContactKeyKind::Pqh, selected);
    spans.push(Span::raw(" "));
    push_key_badge(spans, "OTP", row.otp.is_some(), ContactKeyKind::Otp, selected);
    spans.push(Span::raw(" "));
    push_key_badge(spans, "OTP MAIL", row.otp_mail.is_some(), ContactKeyKind::OtpMail, selected);
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
    spans.push(Span::styled("keys", Style::default().add_modifier(Modifier::BOLD)));
    Line::from(spans)
}

/// `row_selected` reverses only the nickname/last-seen/encryption columns -
/// never the keys column, which is why `push_key_badges` is appended
/// *after* that reversal is patched on, untouched by it. The keys column
/// has its own, separate indicator (a gray background on the currently
/// highlighted key, `push_key_badge`) that has nothing to do with which
/// row the cursor is on.
fn contact_row_line(
    row: &ContactRow,
    columns: &ContactsColumns,
    selected_key: ContactKeyKind,
    row_selected: bool,
) -> Line<'static> {
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

    if row_selected {
        for span in &mut spans {
            span.style = span.style.patch(Style::default().add_modifier(Modifier::REVERSED));
        }
    }

    push_key_badges(&mut spans, row, selected_key);

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

    let columns = ContactsColumns::measure(&contacts.rows);
    let content_width = columns.nickname
        + columns.last_seen
        + columns.encryption
        + COL_GAP * 3
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
                "(\u{2190}/\u{2192}: switch key  Enter: key details  o: install OTP key  d: delete  r: refresh  Esc: close)",
                Style::default().fg(Color::Cyan),
            ),
        ]))
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
    let row = contacts.rows.iter().find(|r| r.nickname == detail.nickname);
    let kind = detail.kind;
    let present = match kind {
        ContactKeyKind::Pqh => row.is_some_and(|r| r.key_mode == Some(KeyMode::PqHybrid)),
        ContactKeyKind::Otp => row.is_some_and(|r| r.otp.is_some()),
        ContactKeyKind::OtpMail => row.is_some_and(|r| r.otp_mail.is_some()),
    };

    let height: u16 = if detail.confirm.is_some() {
        9
    } else if present && kind != ContactKeyKind::Pqh {
        15
    } else {
        11
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

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(kind.explanation(), Style::default().fg(Color::Yellow))),
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
