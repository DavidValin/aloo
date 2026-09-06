//! The "configured punches" list on the Ctrl+S settings popup's Direct
//! Punch tab: every configured `direct_punch_to` peer, one row each, with
//! add/edit/delete - the in-app counterpart to hand-editing
//! `~/.aloo/settings` (`docs/PROTOCOL.md` §7.1.5). Saving (or deleting)
//! persists the whole list back to that file and reconfigures
//! `PeerLinkManager`'s scheduler immediately, so a change takes effect the
//! same tick it's made rather than waiting for a restart.
//!
//! This module is a row and its editor. Where the list sits, when it has
//! focus, and the tab around it belong to `super::settings_popup`, which
//! was Ctrl+S in its entirety until the rest of the settings joined it.
//!
//! Mirrors `crate::client::tui::contacts`'s split: state/handling here as
//! `impl UiState`, rendering as free functions taking `&UiState`. Unlike
//! contacts, the row data *is* just settings already loaded elsewhere - the
//! popup asks for a fresh copy on open (`UiAction::OpenSettings`) the
//! same way `/contacts` asks the session to gather its rows, since
//! `UiState` itself never touches the filesystem.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};

use crate::settings::{DirectPunchTarget, PUNCH_FREQUENCIES, PunchFrequency};

use super::ui::{UiAction, UiState, focus_border_style, render_popup_button};
use super::widgets::field::{place_text_cursor, render_bordered_field};

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

/// Which field is focused inside the add/edit form - Tab/BackTab cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPunchField {
    Nickname,
    Host,
    Port,
    Frequency,
    Save,
}

/// The add/edit form. `editing_index` is `None` while adding a new target,
/// `Some(i)` while editing `rows[i]` in place - the same distinction
/// `contacts::InstallOtpState` would need if it ever grew an "edit" mode,
/// kept here from the start since both add and edit share one form.
pub struct DirectPunchEditState {
    pub editing_index: Option<usize>,
    pub nickname: String,
    pub host: String,
    pub port: String,
    /// Index into `PUNCH_FREQUENCIES`, cycled with Left/Right - a bounded
    /// selector rather than free text, since only those 13 values are
    /// representable at all (`PunchFrequency::parse`).
    pub frequency_index: usize,
    pub focus: DirectPunchField,
    pub error: Option<String>,
    /// True while `host` still holds the realm the add form filled in for
    /// the person rather than anything they typed: the first edit of the
    /// host field clears it whole, so typing a fixed address over the
    /// suggestion just works instead of appending to a 40-character realm.
    pub host_is_suggested: bool,
}

pub struct DirectPunchPopupState {
    pub rows: Vec<DirectPunchTarget>,
    pub selected: usize,
    /// `Some` while the add/edit form is open over the settings popup.
    pub edit: Option<DirectPunchEditState>,
}

impl DirectPunchPopupState {
    /// Moves the selection one row towards the top (`up`) or the bottom,
    /// reporting whether there was a row to move onto.
    ///
    /// `false` at either end is what lets the settings popup's Up/Down
    /// walk *out* of the list and on to the next field without the list
    /// needing a mode to enter and leave - see
    /// `UiState::move_settings_focus`.
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
    /// `OpenSettings`/a completed save's answer: replaces the row set
    /// in place, clamping the selection rather than resetting it. A no-op
    /// if the modal was closed in the meantime.
    pub fn set_direct_punch_rows(&mut self, rows: Vec<DirectPunchTarget>) {
        let Some(state) = self.settings_popup.as_mut() else {
            return;
        };
        state.punches.rows = rows;
        state.punches.selected = if state.punches.rows.is_empty() {
            0
        } else {
            state.punches.selected.min(state.punches.rows.len() - 1)
        };
    }

    /// The save form's failure path - shown inline, same convention as
    /// `contacts::InstallOtpState::error`.
    pub fn set_direct_punch_error(&mut self, message: String) {
        if let Some(edit) = self.settings_popup.as_mut().and_then(|s| s.punches.edit.as_mut()) {
            edit.error = Some(message);
        }
    }

    pub(crate) fn handle_direct_punches_edit_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                if let Some(state) = self.settings_popup.as_mut() {
                    state.punches.edit = None;
                }
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if let Some(edit) = self.settings_popup.as_mut().and_then(|s| s.punches.edit.as_mut()) {
                    edit.focus = next_field(edit.focus, code == KeyCode::BackTab);
                }
                None
            }
            KeyCode::Left | KeyCode::Right => {
                if let Some(edit) = self.settings_popup.as_mut().and_then(|s| s.punches.edit.as_mut())
                    && edit.focus == DirectPunchField::Frequency
                {
                    let len = PUNCH_FREQUENCIES.len();
                    edit.frequency_index = if code == KeyCode::Left {
                        (edit.frequency_index + len - 1) % len
                    } else {
                        (edit.frequency_index + 1) % len
                    };
                }
                None
            }
            KeyCode::Backspace => {
                if let Some(edit) = self.settings_popup.as_mut().and_then(|s| s.punches.edit.as_mut()) {
                    match edit.focus {
                        DirectPunchField::Nickname => {
                            edit.nickname.pop();
                        }
                        DirectPunchField::Host => {
                            // Backspace on the untouched suggestion drops it
                            // whole - nobody edits a random realm by character.
                            if edit.host_is_suggested {
                                edit.host.clear();
                                edit.host_is_suggested = false;
                            } else {
                                edit.host.pop();
                            }
                        }
                        DirectPunchField::Port => {
                            edit.port.pop();
                        }
                        DirectPunchField::Frequency | DirectPunchField::Save => {}
                    }
                }
                None
            }
            KeyCode::Char(c) => {
                if let Some(edit) = self.settings_popup.as_mut().and_then(|s| s.punches.edit.as_mut()) {
                    match edit.focus {
                        DirectPunchField::Nickname => edit.nickname.push(c),
                        DirectPunchField::Host => {
                            // The first keystroke replaces the generated realm
                            // rather than appending to it.
                            if edit.host_is_suggested {
                                edit.host.clear();
                                edit.host_is_suggested = false;
                            }
                            edit.host.push(c);
                        }
                        DirectPunchField::Port if c.is_ascii_digit() => edit.port.push(c),
                        DirectPunchField::Port | DirectPunchField::Frequency | DirectPunchField::Save => {}
                    }
                }
                None
            }
            KeyCode::Enter => self.submit_direct_punch_edit(),
            _ => None,
        }
    }

    /// Only `Save` actually does anything on Enter - the text fields have
    /// no activation of their own, same as `contacts::InstallOtpState`'s
    /// path/browser fields being the only ones Enter acts on there.
    fn submit_direct_punch_edit(&mut self) -> Option<UiAction> {
        let state = self.settings_popup.as_ref()?;
        let edit = state.punches.edit.as_ref()?;
        if edit.focus != DirectPunchField::Save {
            return None;
        }
        let frequency = PUNCH_FREQUENCIES[edit.frequency_index];
        let host = edit.host.trim();
        let port = edit.port.trim();
        // A realm URI names no address, so a port typed next to one is a
        // mistake to point out rather than a number to append: the
        // settings line has nowhere to put it.
        if crate::settings::DirectPunchVia::is_realm_uri(host) && !port.is_empty() {
            self.set_direct_punch_error(
                "a realm URI has no port to name - leave the port empty".to_string(),
            );
            return None;
        }
        let place = if port.is_empty() {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let line = format!("{},{place},every_{frequency}m", edit.nickname.trim());
        let target = match DirectPunchTarget::parse(&line) {
            Ok(target) => target,
            Err(message) => {
                self.set_direct_punch_error(message);
                return None;
            }
        };

        let state = self.settings_popup.as_mut()?;
        match state.punches.edit.as_ref()?.editing_index {
            Some(i) => state.punches.rows[i] = target,
            None => state.punches.rows.push(target),
        }
        state.punches.edit = None;
        // Naming someone to punch at is asking to punch at them: the
        // session's own `SaveDirectPunchTargets` handler turns
        // `direct_punch` on with the list, so the toggle above the list
        // has to agree or the popup would show `off` over a scheduler
        // that is running.
        state.draft.direct_punch = true;
        Some(UiAction::SaveDirectPunchTargets(state.punches.rows.clone()))
    }
}

fn next_field(focus: DirectPunchField, backwards: bool) -> DirectPunchField {
    use DirectPunchField::*;
    let order = [Nickname, Host, Port, Frequency, Save];
    let pos = order.iter().position(|f| *f == focus).unwrap_or(0);
    let len = order.len();
    let next = if backwards { (pos + len - 1) % len } else { (pos + 1) % len };
    order[next]
}

/// The add form. Its "where" starts as a freshly generated public
/// rendezvous realm (`hysteria_realm::suggested_realm_uri`), the robust
/// default when no address is reachable: someone who wants a realm keeps it
/// and just types the nickname (focus starts there), someone who wants a
/// fixed address types it straight over the suggestion, which the first
/// keystroke in the host box clears. The realm name is generated rather
/// than left to a person because it is the whole of the rendezvous's
/// privacy and an invented one would likely be guessable.
pub(crate) fn blank_edit_state() -> DirectPunchEditState {
    DirectPunchEditState {
        editing_index: None,
        nickname: String::new(),
        host: crate::client::hysteria_realm::suggested_realm_uri(),
        port: String::new(),
        frequency_index: 0,
        focus: DirectPunchField::Nickname,
        error: None,
        host_is_suggested: true,
    }
}

pub(crate) fn edit_state_for(index: usize, target: &DirectPunchTarget) -> DirectPunchEditState {
    let frequency_index = PUNCH_FREQUENCIES
        .iter()
        .position(|m| *m == target.frequency.minutes())
        .unwrap_or(0);
    DirectPunchEditState {
        editing_index: Some(index),
        // `target_key`, not the bare nickname, so re-editing a device-
        // suffixed row (§5a) round-trips its `+<device_id>` suffix rather
        // than silently dropping it.
        nickname: target.target_key(),
        // A realm line comes back as its URI in the host box, with no
        // port - exactly the shape it is typed in.
        host: match &target.via {
            crate::settings::DirectPunchVia::Host { host, .. } => host.clone(),
            crate::settings::DirectPunchVia::Realm(realm) => realm.uri().to_string(),
        },
        // The implicit default is shown as an empty field, the way it was
        // entered - offering it back as a number would put a port outside
        // the accepted range into a field that then refuses to save.
        port: match target.port() {
            Some(port) if port != crate::settings::DEFAULT_DIRECT_PUNCH_PORT => port.to_string(),
            _ => String::new(),
        },
        frequency_index,
        focus: DirectPunchField::Nickname,
        error: None,
        // An existing row's host is real, not a suggestion to type over.
        host_is_suggested: false,
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// The list of configured targets, inside whatever area the Direct Punch
/// tab gave it. `focused` is whether the list is the tab's focused field,
/// which is what decides whether its keys (a/e/d) are live - so it also
/// decides whether the selection is drawn as a selection.
pub(crate) fn render_punch_list(
    frame: &mut Frame,
    area: Rect,
    popup: &DirectPunchPopupState,
    focused: bool,
) {
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
            Paragraph::new("no direct punches configured yet - press 'a' to add one")
                .style(Style::default().fg(Color::DarkGray)),
            list_area,
        );
        return;
    }

    let items: Vec<ListItem> = popup
        .rows
        .iter()
        .map(|t| {
            ListItem::new(Line::from(format!(
                "{}  {}  {}",
                t.target_key(),
                host_display(t),
                t.frequency
            )))
        })
        .collect();
    let highlight = if focused {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    let list = List::new(items).highlight_style(highlight);
    let mut list_state = ListState::default();
    list_state.select(Some(popup.selected.min(popup.rows.len() - 1)));
    frame.render_stateful_widget(list, list_area, &mut list_state);
}

/// One row's "where", spelled the way the settings line spells it so the
/// list reads the same in both places - the host with its port, or the
/// realm URI.
fn host_display(t: &DirectPunchTarget) -> String {
    match &t.via {
        crate::settings::DirectPunchVia::Host { host, port } => format!("{host}:{port}"),
        crate::settings::DirectPunchVia::Realm(realm) => realm.uri().to_string(),
    }
}

/// The line under the form when the "where" is a realm: it names the two
/// third parties a punch actually touches - the rendezvous host and the
/// STUN servers this very realm would use - and says plainly that both
/// only introduce the peers, so a reader can see exactly who learns their
/// address before committing to it. Falls back to the public defaults
/// while a realm is still being typed and does not yet parse.
fn realm_instruction(host: &str) -> String {
    use crate::client::hysteria_realm::{DEFAULT_STUN_SERVERS, PUBLIC_RENDEZVOUS_HOST, RealmAddr};
    let (rendezvous, stun) = match RealmAddr::parse(host) {
        Ok(realm) => (realm.host.clone(), realm.stun_servers().join(", ")),
        Err(_) => (PUBLIC_RENDEZVOUS_HOST.to_string(), DEFAULT_STUN_SERVERS.join(", ")),
    };
    format!(
        "Share this exact realm with the peer - you meet only if both carry the same one. \
         You are introduced through {rendezvous} and STUN ({stun}); these only introduce \
         you to each other - no messages ever pass through them."
    )
}

/// A bordered field, styled exactly like `ui_connect_popup`'s own
/// `render_bordered_field` - the focused one's border highlighted, its
/// value drawn inside - so every popup's text fields read the same way.
/// Returns the inner `Rect`, for placing the blinking cursor in it.
pub(crate) fn render_edit_form(frame: &mut Frame, area: Rect, edit: &DirectPunchEditState) {
    // A realm is a shared secret both peers must carry identically, so the
    // form says so the moment the "where" reads as one - the value is no
    // use to a person who does not also give it to the other side.
    let is_realm = crate::settings::DirectPunchVia::is_realm_uri(edit.host.trim());
    let mut constraints = vec![
        Constraint::Length(3), // nickname
        Constraint::Length(3), // host
        Constraint::Length(3), // port
        Constraint::Length(3), // frequency
        Constraint::Length(3), // save button
    ];
    if is_realm {
        constraints.push(Constraint::Length(4)); // realm-sharing instruction
    }
    if edit.error.is_some() {
        constraints.push(Constraint::Min(1));
    }
    let rows = Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);

    let nickname_inner = render_bordered_field(
        frame,
        rows[0],
        "nickname (optionally nick+device_id)",
        &edit.nickname,
        edit.focus == DirectPunchField::Nickname,
    );
    let host_inner = render_bordered_field(
        frame,
        rows[1],
        "host, or realm://token@host/name",
        &edit.host,
        edit.focus == DirectPunchField::Host,
    );
    let port_display = if edit.port.is_empty() {
        format!("<default {}>", crate::settings::DEFAULT_DIRECT_PUNCH_PORT)
    } else {
        edit.port.clone()
    };
    let port_inner = render_bordered_field(
        frame,
        rows[2],
        "port (none for a realm)",
        &port_display,
        edit.focus == DirectPunchField::Port,
    );
    let frequency = PunchFrequency::parse(&format!("every_{}m", PUNCH_FREQUENCIES[edit.frequency_index]))
        .expect("every PUNCH_FREQUENCIES entry parses");
    render_bordered_field(
        frame,
        rows[3],
        "frequency (\u{2190}/\u{2192})",
        &frequency.to_string(),
        edit.focus == DirectPunchField::Frequency,
    );

    // Only the free-text fields get a blinking cursor - frequency is a
    // bounded Left/Right selector, not something typed into.
    match edit.focus {
        DirectPunchField::Nickname => place_text_cursor(frame, nickname_inner, &edit.nickname),
        DirectPunchField::Host => place_text_cursor(frame, host_inner, &edit.host),
        DirectPunchField::Port => place_text_cursor(frame, port_inner, &edit.port),
        DirectPunchField::Frequency | DirectPunchField::Save => {}
    }

    render_popup_button(frame, rows[4], 16, "Save", edit.focus == DirectPunchField::Save);

    // The realm-sharing instruction sits between Save and any error, so its
    // row index shifts the error down by one when it is shown.
    let mut next_row = 5;
    if is_realm {
        frame.render_widget(
            Paragraph::new(realm_instruction(edit.host.trim()))
                .style(Style::default().fg(Color::Cyan))
                .wrap(Wrap { trim: true }),
            rows[next_row],
        );
        next_row += 1;
    }

    if let Some(err) = &edit.error {
        frame.render_widget(Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)), rows[next_row]);
    }
}
