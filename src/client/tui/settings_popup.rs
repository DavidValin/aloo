//! The Ctrl+S "Settings" popup: the in-app editor for `~/.aloo/settings`,
//! split across three tabs - **General** (push-to-talk, the sounds, the
//! message log), **Direct Punch** (the serverless punching configuration
//! and the No-IP updater that keeps a moving address reachable, see
//! `docs/PROTOCOL.md` §7.1.5) and **OTP**.
//!
//! Only the fields a user has a reason to change while the app is running
//! live here. Everything a server reads (`server_*`), everything a daemon
//! is configured with (`daemon_*`), and the connect cache
//! (`connect_*`) stay hand-edited: the first two are read by a process
//! this popup is not part of, and the third is written *by* connecting
//! rather than typed.
//!
//! Every change is persisted the moment it is made - there is no Save
//! button and no "discard" path, the same immediate-apply contract the
//! direct-punch list already had - and every one of them takes effect on
//! the spot rather than at the next start. What that costs, per field, is
//! `session::ui_action::save_settings_draft`: the sound switches and
//! `voice_autoplay` are mirrored onto the session and the UI, the log
//! switches are read per message anyway, the direct-punch scheduler and
//! the No-IP updater are rebuilt, the `otp` binary is re-resolved, and
//! `global_ptt_enabled` is answered per hotkey event.
//!
//! One field cannot be, and says so: turning `global_ptt_enabled` back on
//! in a run that *started* with it off has no OS-level shortcut to
//! re-enable, because none was registered - see
//! `client::global_ptt::set_enabled`.
//!
//! Mirrors `crate::client::tui::contacts`'s split: state and key handling
//! here as `impl UiState`, rendering as free functions taking `&UiState`.
//! The Direct Punch tab's list of targets is `direct_punch_popup`'s,
//! unchanged - this module owns where it sits and when it has focus, that
//! one owns what a row is and what editing it means.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};

use crate::settings::Settings;

use super::direct_punch_popup::{DirectPunchPopupState, render_edit_form, render_punch_list};
use super::ui::{Mode, UiAction, UiState, centered_rect};
use super::widgets::field::{place_text_cursor, render_bordered_field};

/// How long a free-text settings value may get. Generous for every field
/// that has one (a hotkey string, a hostname, a No-IP login, a path) and
/// short enough that a runaway paste can't grow the settings file without
/// bound.
pub const SETTINGS_TEXT_MAX_LEN: usize = 200;

/// `otp_low_key_warn_pct` is a percentage, so three digits is the whole
/// range it could ever need.
const PERCENT_MAX_DIGITS: usize = 3;

// ---------------------------------------------------------------------
// Tabs and fields
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsTab {
    General,
    DirectPunch,
    Otp,
}

impl SettingsTab {
    pub const ALL: [SettingsTab; 3] = [SettingsTab::General, SettingsTab::DirectPunch, SettingsTab::Otp];

    pub fn title(self) -> &'static str {
        match self {
            SettingsTab::General => "General",
            SettingsTab::DirectPunch => "Direct Punch",
            SettingsTab::Otp => "OTP",
        }
    }

    fn index(self) -> usize {
        SettingsTab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// The focusable fields on this tab, top to bottom - the same order
    /// Up/Down walks and the same order they are drawn in, so the two can
    /// never disagree.
    pub fn fields(self) -> &'static [SettingsField] {
        use SettingsField::*;
        match self {
            SettingsTab::General => &[
                GlobalPttEnabled,
                GlobalPttShortcut,
                VoiceAutoplay,
                RogerBeep,
                SoundNotifications,
                AutosaveMessages,
                ResumeFromLog,
                QueueSendMessages,
            ],
            SettingsTab::DirectPunch => &[
                DirectPunchEnabled,
                Punches,
                NoipEnabled,
                NoipHostname,
                NoipUsername,
                NoipPassword,
            ],
            SettingsTab::Otp => &[OtpLowKeyWarnPct, OtpBinaryPath],
        }
    }
}

/// One editable thing on a tab. The name is the settings-file key it
/// writes, so what the popup shows and what a user hand-editing the file
/// would look for are the same word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsField {
    GlobalPttEnabled,
    GlobalPttShortcut,
    VoiceAutoplay,
    RogerBeep,
    SoundNotifications,
    AutosaveMessages,
    ResumeFromLog,
    QueueSendMessages,
    DirectPunchEnabled,
    /// The configured `direct_punch_to` list itself - one focus stop that
    /// then behaves like a list (see `handle_punches_key`), not a value.
    Punches,
    NoipEnabled,
    NoipHostname,
    NoipUsername,
    NoipPassword,
    OtpLowKeyWarnPct,
    OtpBinaryPath,
}

/// What a field is, which decides how it is drawn and which keys mean
/// something on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Space/Enter flips it.
    Toggle,
    /// Typed into, drawn as a bordered box.
    Text,
    /// Digits only, drawn as a bordered box.
    Digits,
    /// The direct-punch list.
    List,
}

impl SettingsField {
    /// The settings-file key this field writes, used as its on-screen
    /// label too.
    pub fn label(self) -> &'static str {
        match self {
            SettingsField::GlobalPttEnabled => "global_ptt_enabled",
            SettingsField::GlobalPttShortcut => "global_ptt_shortcut",
            SettingsField::VoiceAutoplay => "voice_autoplay",
            SettingsField::RogerBeep => "roger_beep",
            SettingsField::SoundNotifications => "sound_notifications",
            SettingsField::AutosaveMessages => "autosave_messages",
            SettingsField::ResumeFromLog => "resume_from_log",
            SettingsField::QueueSendMessages => "queue_send_messages",
            SettingsField::DirectPunchEnabled => "direct_punch",
            SettingsField::Punches => "configured punches",
            SettingsField::NoipEnabled => "noip_when_no_server_and_direct_punch_is_active",
            SettingsField::NoipHostname => "noip_hostname",
            SettingsField::NoipUsername => "noip_username",
            SettingsField::NoipPassword => "noip_password",
            SettingsField::OtpLowKeyWarnPct => "otp_low_key_warn_pct",
            SettingsField::OtpBinaryPath => "otp_binary_path",
        }
    }

    /// The one-line gray explanation listed under the tab. Kept to a
    /// single short sentence each: this is a reminder of what the switch
    /// does, not the documentation (`docs/SPEC.md`, and `Ctrl+H`, are).
    pub fn description(self) -> &'static str {
        match self {
            SettingsField::GlobalPttEnabled => {
                "push to talk from any app (on, from off at startup: next run)"
            }
            SettingsField::GlobalPttShortcut => "which OS-wide combo does it",
            SettingsField::VoiceAutoplay => "play arriving voice messages as they land",
            SettingsField::RogerBeep => "the end-of-message tone, sent and received",
            SettingsField::SoundNotifications => "event sounds: file offers, joins, @mentions",
            SettingsField::AutosaveMessages => "append every message to ~/.aloo/exports",
            SettingsField::ResumeFromLog => "scroll back into that saved history as you scroll up",
            SettingsField::QueueSendMessages => {
                "hold text and voice for someone unreachable, deliver in order"
            }
            SettingsField::DirectPunchEnabled => "punch links from the schedule below, no server",
            SettingsField::Punches => "who to punch at, where, and how often",
            SettingsField::NoipEnabled => "keep a No-IP hostname pointed here while serverless",
            SettingsField::NoipHostname => "the No-IP hostname to update",
            SettingsField::NoipUsername => "the No-IP account it belongs to",
            SettingsField::NoipPassword => "its password, stored as plain text like every other",
            SettingsField::OtpLowKeyWarnPct => "warn when this % of a one-time pad is left",
            SettingsField::OtpBinaryPath => "the otp binary to run (empty: found on PATH)",
        }
    }

    pub fn kind(self) -> FieldKind {
        match self {
            SettingsField::GlobalPttEnabled
            | SettingsField::VoiceAutoplay
            | SettingsField::RogerBeep
            | SettingsField::SoundNotifications
            | SettingsField::AutosaveMessages
            | SettingsField::ResumeFromLog
            | SettingsField::QueueSendMessages
            | SettingsField::DirectPunchEnabled
            | SettingsField::NoipEnabled => FieldKind::Toggle,
            SettingsField::GlobalPttShortcut
            | SettingsField::NoipHostname
            | SettingsField::NoipUsername
            | SettingsField::NoipPassword
            | SettingsField::OtpBinaryPath => FieldKind::Text,
            SettingsField::OtpLowKeyWarnPct => FieldKind::Digits,
            SettingsField::Punches => FieldKind::List,
        }
    }
}

// ---------------------------------------------------------------------
// The editable values
// ---------------------------------------------------------------------

/// The subset of `Settings` this popup edits, in the shape the popup
/// edits it in - the two numeric/optional fields as the text the user is
/// typing, so a half-typed value is representable without ever being a
/// half-valid `Settings`.
///
/// `apply_to` is the one place that turns it back into settings, so a
/// value that cannot be parsed (an empty percentage mid-edit) leaves the
/// stored setting as it was rather than writing a nonsense one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsDraft {
    pub global_ptt_enabled: bool,
    pub global_ptt_shortcut: String,
    pub voice_autoplay: bool,
    pub roger_beep: bool,
    pub sound_notifications: bool,
    pub autosave_messages: bool,
    pub resume_from_log: bool,
    pub queue_send_messages: bool,
    pub direct_punch: bool,
    pub noip_enabled: bool,
    pub noip_hostname: String,
    pub noip_username: String,
    pub noip_password: String,
    pub otp_low_key_warn_pct: String,
    pub otp_binary_path: String,
}

impl Default for SettingsDraft {
    fn default() -> Self {
        Self::from_settings(&Settings::default())
    }
}

impl SettingsDraft {
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            global_ptt_enabled: settings.global_ptt_enabled,
            global_ptt_shortcut: settings.global_ptt_shortcut.clone(),
            voice_autoplay: settings.voice_autoplay,
            roger_beep: settings.roger_beep,
            sound_notifications: settings.sound_notifications,
            autosave_messages: settings.autosave_messages,
            resume_from_log: settings.resume_from_log,
            queue_send_messages: settings.queue_send_messages,
            direct_punch: settings.direct_punch,
            noip_enabled: settings.noip_when_no_server_and_direct_punch_is_active,
            noip_hostname: settings.noip_hostname.clone(),
            noip_username: settings.noip_username.clone(),
            noip_password: settings.noip_password.clone(),
            otp_low_key_warn_pct: settings.otp_low_key_warn_pct.to_string(),
            otp_binary_path: settings.otp_binary_path.clone().unwrap_or_default(),
        }
    }

    /// Writes this draft over `settings`, leaving every key the popup
    /// does not own untouched - it is handed to `Settings::update`, whose
    /// merging write is what keeps a concurrently-running daemon's own
    /// keys intact.
    pub fn apply_to(&self, settings: &mut Settings) {
        settings.global_ptt_enabled = self.global_ptt_enabled;
        // An empty shortcut would be unparseable, and `Settings::parse`
        // already ignores an empty value for this key - so refusing it
        // here keeps the file and the popup saying the same thing.
        if !self.global_ptt_shortcut.trim().is_empty() {
            settings.global_ptt_shortcut = self.global_ptt_shortcut.trim().to_string();
        }
        settings.voice_autoplay = self.voice_autoplay;
        settings.roger_beep = self.roger_beep;
        settings.sound_notifications = self.sound_notifications;
        settings.autosave_messages = self.autosave_messages;
        settings.resume_from_log = self.resume_from_log;
        settings.queue_send_messages = self.queue_send_messages;
        settings.direct_punch = self.direct_punch;
        settings.noip_when_no_server_and_direct_punch_is_active = self.noip_enabled;
        settings.noip_hostname = self.noip_hostname.trim().to_string();
        settings.noip_username = self.noip_username.trim().to_string();
        settings.noip_password = self.noip_password.trim().to_string();
        // Mid-edit the box can be empty, or hold a number no percentage
        // could be. Neither is a value to save: the stored one stays.
        if let Ok(pct) = self.otp_low_key_warn_pct.parse::<u8>()
            && (1..=100).contains(&pct)
        {
            settings.otp_low_key_warn_pct = pct;
        }
        settings.otp_binary_path = match self.otp_binary_path.trim() {
            "" => None,
            path => Some(path.to_string()),
        };
    }

    fn toggle_mut(&mut self, field: SettingsField) -> Option<&mut bool> {
        Some(match field {
            SettingsField::GlobalPttEnabled => &mut self.global_ptt_enabled,
            SettingsField::VoiceAutoplay => &mut self.voice_autoplay,
            SettingsField::RogerBeep => &mut self.roger_beep,
            SettingsField::SoundNotifications => &mut self.sound_notifications,
            SettingsField::AutosaveMessages => &mut self.autosave_messages,
            SettingsField::ResumeFromLog => &mut self.resume_from_log,
            SettingsField::QueueSendMessages => &mut self.queue_send_messages,
            SettingsField::DirectPunchEnabled => &mut self.direct_punch,
            SettingsField::NoipEnabled => &mut self.noip_enabled,
            _ => return None,
        })
    }

    pub fn toggle_value(&self, field: SettingsField) -> bool {
        match field {
            SettingsField::GlobalPttEnabled => self.global_ptt_enabled,
            SettingsField::VoiceAutoplay => self.voice_autoplay,
            SettingsField::RogerBeep => self.roger_beep,
            SettingsField::SoundNotifications => self.sound_notifications,
            SettingsField::AutosaveMessages => self.autosave_messages,
            SettingsField::ResumeFromLog => self.resume_from_log,
            SettingsField::QueueSendMessages => self.queue_send_messages,
            SettingsField::DirectPunchEnabled => self.direct_punch,
            SettingsField::NoipEnabled => self.noip_enabled,
            _ => false,
        }
    }

    fn text_mut(&mut self, field: SettingsField) -> Option<&mut String> {
        Some(match field {
            SettingsField::GlobalPttShortcut => &mut self.global_ptt_shortcut,
            SettingsField::NoipHostname => &mut self.noip_hostname,
            SettingsField::NoipUsername => &mut self.noip_username,
            SettingsField::NoipPassword => &mut self.noip_password,
            SettingsField::OtpLowKeyWarnPct => &mut self.otp_low_key_warn_pct,
            SettingsField::OtpBinaryPath => &mut self.otp_binary_path,
            _ => return None,
        })
    }

    pub fn text_value(&self, field: SettingsField) -> &str {
        match field {
            SettingsField::GlobalPttShortcut => &self.global_ptt_shortcut,
            SettingsField::NoipHostname => &self.noip_hostname,
            SettingsField::NoipUsername => &self.noip_username,
            SettingsField::NoipPassword => &self.noip_password,
            SettingsField::OtpLowKeyWarnPct => &self.otp_low_key_warn_pct,
            SettingsField::OtpBinaryPath => &self.otp_binary_path,
            _ => "",
        }
    }
}

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

pub struct SettingsPopupState {
    pub tab: SettingsTab,
    /// Index into `tab.fields()` - always in range, since every path that
    /// changes the tab resets it.
    pub focus: usize,
    pub draft: SettingsDraft,
    /// The Direct Punch tab's target list, add/edit form and all - see
    /// `super::direct_punch_popup`.
    pub punches: DirectPunchPopupState,
}

impl SettingsPopupState {
    pub fn focused_field(&self) -> SettingsField {
        self.tab.fields()[self.focus.min(self.tab.fields().len() - 1)]
    }
}

impl UiState {
    /// Opens the modal on its first tab with the compiled-in defaults, and
    /// returns `UiAction::OpenSettings` so the session fills it in from
    /// `~/.aloo/settings` - mirrors `open_contacts` + `OpenContacts`'s
    /// same split, and for the same reason: `UiState` never touches the
    /// filesystem itself.
    pub fn open_settings(&mut self) {
        self.mode = Mode::Settings;
        self.settings_popup = Some(SettingsPopupState {
            tab: SettingsTab::General,
            focus: 0,
            draft: SettingsDraft::default(),
            punches: DirectPunchPopupState {
                rows: Vec::new(),
                selected: 0,
                edit: None,
            },
        });
    }

    /// `OpenSettings`'s answer: the values as they are on disk right now.
    /// A no-op if the modal was closed in the meantime.
    pub fn set_settings_draft(&mut self, draft: SettingsDraft) {
        if let Some(state) = self.settings_popup.as_mut() {
            state.draft = draft;
        }
    }

    /// The popup's whole key surface, dispatched by what is open: the
    /// direct-punch add/edit form if there is one, else the focused
    /// field.
    pub(crate) fn handle_settings_key(&mut self, code: KeyCode) -> Option<UiAction> {
        if self.settings_popup.as_ref()?.punches.edit.is_some() {
            return self.handle_direct_punches_edit_key(code);
        }
        match code {
            KeyCode::Esc => {
                self.settings_popup = None;
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.cycle_settings_tab(code == KeyCode::BackTab);
                None
            }
            KeyCode::Up => self.move_settings_focus(true),
            KeyCode::Down => self.move_settings_focus(false),
            _ => self.handle_settings_field_key(code),
        }
    }

    fn cycle_settings_tab(&mut self, backwards: bool) {
        let Some(state) = self.settings_popup.as_mut() else {
            return;
        };
        let len = SettingsTab::ALL.len();
        let pos = state.tab.index();
        let next = if backwards { (pos + len - 1) % len } else { (pos + 1) % len };
        state.tab = SettingsTab::ALL[next];
        state.focus = 0;
    }

    /// Up/Down over the tab's fields, wrapping - except on the punch
    /// list, which absorbs the key while there is another row to move
    /// onto and hands it back at either end. That is what lets one set of
    /// arrows drive both the field column and the list inside it without
    /// a mode to enter and leave.
    fn move_settings_focus(&mut self, up: bool) -> Option<UiAction> {
        let state = self.settings_popup.as_mut()?;
        if state.focused_field() == SettingsField::Punches && state.punches.step_selection(up) {
            return None;
        }
        let len = state.tab.fields().len();
        state.focus = if up { (state.focus + len - 1) % len } else { (state.focus + 1) % len };
        // Entering the list from above starts at its first row, from
        // below at its last - so a continued Up/Down keeps travelling in
        // the direction it was going rather than jumping to the far end.
        if state.focused_field() == SettingsField::Punches {
            state.punches.selected = if up {
                state.punches.rows.len().saturating_sub(1)
            } else {
                0
            };
        }
        None
    }

    /// Whatever the focused field itself makes of a key. Every branch
    /// that changes a value returns the save that persists it: there is
    /// no separate Save button, so a change that produced no action would
    /// simply be lost on Esc.
    fn handle_settings_field_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let field = self.settings_popup.as_ref()?.focused_field();
        if field == SettingsField::Punches {
            return self.handle_punches_key(code);
        }
        let state = self.settings_popup.as_mut()?;
        match code {
            KeyCode::Char(' ') | KeyCode::Enter if field.kind() == FieldKind::Toggle => {
                let value = state.draft.toggle_mut(field)?;
                *value = !*value;
                Some(UiAction::SaveSettings(state.draft.clone()))
            }
            KeyCode::Backspace => {
                let value = state.draft.text_mut(field)?;
                value.pop()?;
                Some(UiAction::SaveSettings(state.draft.clone()))
            }
            KeyCode::Char(c) => {
                let (max_len, accepted) = match field.kind() {
                    FieldKind::Digits => (PERCENT_MAX_DIGITS, c.is_ascii_digit()),
                    // A settings line is one `key=value` on one line, so
                    // the two characters that would break that shape are
                    // the two this refuses.
                    FieldKind::Text => (SETTINGS_TEXT_MAX_LEN, c != '=' && !c.is_control()),
                    FieldKind::Toggle | FieldKind::List => return None,
                };
                let value = state.draft.text_mut(field)?;
                if !accepted || value.chars().count() >= max_len {
                    return None;
                }
                value.push(c);
                Some(UiAction::SaveSettings(state.draft.clone()))
            }
            _ => None,
        }
    }

    /// The punch list's own keys, once it has focus. Add/edit/delete
    /// exactly as the standalone popup had them; Up/Down are handled a
    /// level up (`move_settings_focus`) since they may leave the list.
    fn handle_punches_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Char('a') | KeyCode::Char('n') => {
                self.settings_popup.as_mut()?.punches.edit = Some(super::direct_punch_popup::blank_edit_state());
                None
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                let (index, target) = {
                    let punches = &self.settings_popup.as_ref()?.punches;
                    (punches.selected, punches.rows.get(punches.selected)?.clone())
                };
                self.settings_popup.as_mut()?.punches.edit =
                    Some(super::direct_punch_popup::edit_state_for(index, &target));
                None
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let state = self.settings_popup.as_mut()?;
                if state.punches.rows.is_empty() {
                    return None;
                }
                let removed = state.punches.selected;
                state.punches.rows.remove(removed);
                state.punches.selected =
                    state.punches.selected.min(state.punches.rows.len().saturating_sub(1));
                Some(UiAction::SaveDirectPunchTargets(state.punches.rows.clone()))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// The popup's own size: exactly what the largest tab (Direct Punch)
/// needs, descriptions included. Fixed rather than per-tab, so the box
/// does not resize under the cursor as `Tab` moves through it, and
/// clipped from the bottom by `Stack` on a terminal with less room -
/// which drops the descriptions first, since they are the part a user can
/// do without.
///
/// The width is set by the longest `<key>: <description>` line, so every
/// field's explanation fits on one row rather than wrapping onto a second
/// - `centered_rect` clamps it to the terminal on anything narrower, and
/// `render_descriptions` still wraps when it has to.
const POPUP_WIDTH: u16 = 102;
const POPUP_HEIGHT: u16 = 36;

/// Hands out rows from the top of an area, refusing anything that no
/// longer fits.
///
/// Deliberately not `Layout`: with fixed `Length` constraints that
/// over-subscribe their area, ratatui shrinks the boxes near the top
/// rather than dropping the ones at the bottom, so a short terminal
/// garbles the fields instead of simply cutting the descriptions off.
struct Stack {
    area: Rect,
    y: u16,
}

impl Stack {
    fn new(area: Rect) -> Self {
        Self { area, y: area.y }
    }

    fn take(&mut self, height: u16) -> Option<Rect> {
        let bottom = self.area.y.saturating_add(self.area.height);
        if self.y.saturating_add(height) > bottom {
            return None;
        }
        let rect = Rect {
            x: self.area.x,
            y: self.y,
            width: self.area.width,
            height,
        };
        self.y = self.y.saturating_add(height);
        Some(rect)
    }

    /// One blank row, if there is room for one - the separator between
    /// two bordered areas, and between the last of them and the
    /// descriptions. Silently nothing when the terminal is too short,
    /// which is the right thing to lose first.
    fn gap(&mut self) {
        self.take(1);
    }

    fn remaining(&self) -> u16 {
        self.area.y.saturating_add(self.area.height).saturating_sub(self.y)
    }
}

pub(crate) fn render_settings_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(popup) = &state.settings_popup else { return };

    let outer = centered_rect(POPUP_WIDTH, POPUP_HEIGHT, area);
    let block = Block::default().title("Settings").borders(Borders::ALL);
    let inner = block.inner(outer);
    frame.render_widget(ratatui::widgets::Clear, outer);
    frame.render_widget(block, outer);

    let mut stack = Stack::new(inner);
    if let Some(row) = stack.take(2) {
        // Padded titles and a filled background, so the open tab reads as
        // a tab rather than as one of three words that happens to be
        // bold - the same "selected thing is inverted" cue the rest of
        // this app's lists use, given room to actually show.
        let titles: Vec<String> = SettingsTab::ALL
            .iter()
            .map(|t| format!(" {} ", t.title()))
            .collect();
        let tabs = Tabs::new(titles)
            .select(popup.tab.index())
            .style(Style::default().fg(Color::DarkGray))
            .highlight_style(
                Style::default()
                    .bg(Color::Yellow)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .divider(" ");
        frame.render_widget(tabs, row);
    }
    if let Some(row) = stack.take(1) {
        frame.render_widget(
            Paragraph::new(
                "Tab: next tab \u{2502} \u{2191}/\u{2193}: field \u{2502} Space: toggle \u{2502} Esc: close",
            )
            .style(Style::default().fg(Color::DarkGray)),
            row,
        );
    }

    // The add/edit form takes over the body, exactly as it did when the
    // punch list was a popup of its own.
    if let Some(edit) = &popup.punches.edit {
        if let Some(row) = stack.take(stack.remaining()) {
            render_edit_form(frame, row, edit);
        }
        return;
    }

    match popup.tab {
        SettingsTab::General => render_general_tab(frame, &mut stack, popup),
        SettingsTab::DirectPunch => render_direct_punch_tab(frame, &mut stack, popup),
        SettingsTab::Otp => render_otp_tab(frame, &mut stack, popup),
    }
    render_descriptions(frame, &mut stack, popup.tab);
}

/// One bordered group, and a `Stack` over its inside - the "bordered
/// area" every section of every tab is drawn as.
fn group(frame: &mut Frame, stack: &mut Stack, title: &str, height: u16) -> Option<Stack> {
    let outer = stack.take(height)?;
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(outer);
    frame.render_widget(block, outer);
    Some(Stack::new(inner))
}

/// A toggle as one row: its key on the left, a filled `ON`/`OFF` block on
/// the right - green or red, so the state reads as colour before it reads
/// as a word - and the key highlighted while focused. Deliberately not a
/// bordered box: a screen of nothing but three-row boxes is unreadable,
/// and only the values that are typed into need somewhere to put a
/// cursor.
fn render_toggle(frame: &mut Frame, stack: &mut Stack, popup: &SettingsPopupState, field: SettingsField) {
    let Some(row) = stack.take(1) else { return };
    let focused = popup.focused_field() == field;
    let on = popup.draft.toggle_value(field);
    // The value reads as a filled state rather than as three characters:
    // green for on, red for off, black on both so it stays legible
    // whatever the terminal's own palette does with those two.
    // Both words centred in the same six columns, so the two filled
    // blocks line up down the tab whichever state each row is in.
    let value = if on { format!("{:^6}", "ON") } else { format!("{:^6}", "OFF") };
    let value_style = Style::default()
        .bg(if on { Color::Green } else { Color::Red })
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD);
    let label_style = if focused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let marker = if focused { "\u{25b8} " } else { "  " };
    let label = field.label();
    let used = marker.len() + label.len() + value.len();
    let gap = (row.width as usize).saturating_sub(used).max(1);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!("{marker}{label}"), label_style),
            Span::raw(" ".repeat(gap)),
            Span::styled(value.clone(), value_style),
        ])),
        row,
    );
}

/// A typed-into value as a bordered box, styled exactly like every other
/// text field in the app (`widgets::field`). Placing the cursor is the
/// caller's job - only one field on screen may have it.
fn render_text_field(
    frame: &mut Frame,
    stack: &mut Stack,
    popup: &SettingsPopupState,
    field: SettingsField,
) -> Option<Rect> {
    let row = stack.take(3)?;
    let focused = popup.focused_field() == field;
    let value = popup.draft.text_value(field);
    // A password is the one value that must not be readable over a
    // shoulder while every other settings row is: shown as dots unless it
    // is the field being typed into.
    let shown = if field == SettingsField::NoipPassword && !focused {
        "\u{2022}".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    let inner = render_bordered_field(frame, row, field.label(), &shown, focused);
    if focused {
        place_text_cursor(frame, inner, value);
    }
    Some(inner)
}

fn render_general_tab(frame: &mut Frame, stack: &mut Stack, popup: &SettingsPopupState) {
    use SettingsField::*;
    // 9, not 8: a blank row under the shortcut box, so the two switches
    // below it do not read as belonging to it.
    if let Some(mut inner) = group(frame, stack, "voice / ptt", 9) {
        render_toggle(frame, &mut inner, popup, GlobalPttEnabled);
        render_text_field(frame, &mut inner, popup, GlobalPttShortcut);
        inner.gap();
        render_toggle(frame, &mut inner, popup, VoiceAutoplay);
        render_toggle(frame, &mut inner, popup, RogerBeep);
    }
    stack.gap();
    if let Some(mut inner) = group(frame, stack, "notifications", 3) {
        render_toggle(frame, &mut inner, popup, SoundNotifications);
    }
    stack.gap();
    if let Some(mut inner) = group(frame, stack, "logs", 4) {
        render_toggle(frame, &mut inner, popup, AutosaveMessages);
        render_toggle(frame, &mut inner, popup, ResumeFromLog);
    }
    stack.gap();
    // Its own area rather than filed under "logs": holding a message for
    // someone who is not there is about delivery, not about what is
    // written down.
    if let Some(mut inner) = group(frame, stack, "delivery", 3) {
        render_toggle(frame, &mut inner, popup, QueueSendMessages);
    }
    stack.gap();
}

fn render_direct_punch_tab(frame: &mut Frame, stack: &mut Stack, popup: &SettingsPopupState) {
    use SettingsField::*;
    let focused = popup.focused_field();
    if let Some(mut inner) = group(frame, stack, "direct_punch", 9) {
        render_toggle(frame, &mut inner, popup, DirectPunchEnabled);
        if let Some(mut list) = group(frame, &mut inner, "configured punches", 6)
            && let Some(area) = list.take(list.remaining())
        {
            render_punch_list(frame, area, &popup.punches, focused == Punches);
        }
    }
    stack.gap();
    if let Some(mut inner) = group(frame, stack, "noip", 12) {
        render_toggle(frame, &mut inner, popup, NoipEnabled);
        render_text_field(frame, &mut inner, popup, NoipHostname);
        render_text_field(frame, &mut inner, popup, NoipUsername);
        render_text_field(frame, &mut inner, popup, NoipPassword);
    }
    stack.gap();
}

fn render_otp_tab(frame: &mut Frame, stack: &mut Stack, popup: &SettingsPopupState) {
    use SettingsField::*;
    if let Some(mut inner) = group(frame, stack, "otp", 8) {
        render_text_field(frame, &mut inner, popup, OtpLowKeyWarnPct);
        render_text_field(frame, &mut inner, popup, OtpBinaryPath);
    }
    stack.gap();
}

/// Every field on this tab, in gray, at the end of it - what the settings
/// file's own comments would say if it had room for them.
///
/// Wrapped rather than clipped, and sized from the wrap: the longest key
/// here (`noip_when_no_server_and_direct_punch_is_active`) is most of a
/// line on its own, so a one-row-per-field rule would cut the sentence
/// that explains it off mid-word.
fn render_descriptions(frame: &mut Frame, stack: &mut Stack, tab: SettingsTab) {
    for field in tab.fields() {
        let text = format!("{}: {}", field.label(), field.description());
        let width = stack.area.width.max(1) as usize;
        let rows = text.chars().count().div_ceil(width) as u16;
        let Some(row) = stack.take(rows) else { return };
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: true })
                .style(Style::default().fg(Color::DarkGray)),
            row,
        );
    }
}
