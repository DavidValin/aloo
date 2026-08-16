//! Channel-tab state and rendering: the `ChannelTab` log/membership model,
//! dwell-to-join tab switching, and the channel view / sidebar / Ctrl+J
//! popup rendering. Shared/mixed UI plumbing (`UiState` itself, `Focus`,
//! `Mode`, message-log rendering, the input bar, ...) stays in
//! `crate::client::tui::ui`; DM-room state/rendering is the mirror image in
//! `crate::client::tui::direct_message`.

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Tabs};

use crate::client::netstats::ConnQuality;
use crate::client::p2p::LinkStatus;
use crate::proto::{ChannelInfo, ChannelJoinRejection, ChannelKind, UserId, UserInfo};
use crate::client::sysstats::CPU_HEALTHY_MAX_PCT;
use crate::validation;

use super::ui::{
    FileTransferStatus, JoinPopupFocus, LogEntry, MessageBody, Mode, UiAction, UiState,
    finalize_held_stream, finalize_stream_entry, focus_border_style, push_log_entry,
    render_input_bar, render_messages,
};

/// How long a tab has to stay selected (`[`/`]`) before it's actually
/// joined on the network.
pub const DWELL_DURATION: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct ChannelTab {
    pub name: String,
    pub kind: ChannelKind,
    /// Whether we've actually joined (vs. just knowing it exists from the
    /// channel list / dwell not having fired yet).
    pub joined: bool,
    /// Set when the user explicitly `/leave`t a *public* channel whose tab
    /// is still showing (`UiState::leave_channel_locally`) - distinguishes
    /// "left on purpose" from "never joined yet" so dwelling here doesn't
    /// silently re-fire a join (`tick_dwell`) and the channel view instead
    /// shows a rejoin prompt (`render_left_channel_screen`). Always `false`
    /// for a private channel, which has no tab left to mark - leaving one
    /// removes it outright. Cleared by `on_joined` once the user rejoins.
    pub left: bool,
    pub members: Vec<UserInfo>,
    pub log: Vec<LogEntry>,
}

pub(crate) struct DwellState {
    pub(crate) target_index: usize,
    pub(crate) started_at: Instant,
}

impl UiState {
    /// Handles Ctrl+J's popup: a channel name, a Public/Private selector
    /// (Tab/BackTab cycles focus among the fields; Left/Right toggles the
    /// selector while it's focused, mirroring `file_send::FileConfirmChoice`'s
    /// toggle convention), and - only while Private is selected - an
    /// optional password field. Per-keystroke charset/length guards mirror
    /// `ui_connect_popup`'s `NICKNAME_MAX_LEN` guard-clause style.
    pub(crate) fn handle_join_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.join_popup_input.clear();
                self.join_popup_password.clear();
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.join_popup_focus = match self.join_popup_focus {
                    JoinPopupFocus::Name => JoinPopupFocus::Kind,
                    JoinPopupFocus::Kind if self.join_popup_kind == ChannelKind::Private => {
                        JoinPopupFocus::Password
                    }
                    JoinPopupFocus::Kind => JoinPopupFocus::Name,
                    JoinPopupFocus::Password => JoinPopupFocus::Name,
                };
                None
            }
            KeyCode::Left | KeyCode::Right if self.join_popup_focus == JoinPopupFocus::Kind => {
                self.join_popup_kind = match self.join_popup_kind {
                    ChannelKind::Public => ChannelKind::Private,
                    ChannelKind::Private => ChannelKind::Public,
                };
                if self.join_popup_kind == ChannelKind::Public {
                    self.join_popup_password.clear();
                }
                None
            }
            KeyCode::Enter => {
                let name = self.join_popup_input.trim().to_string();
                let kind = self.join_popup_kind;
                let password = (kind == ChannelKind::Private
                    && !self.join_popup_password.is_empty())
                .then(|| self.join_popup_password.clone());
                self.mode = Mode::Normal;
                self.join_popup_input.clear();
                self.join_popup_password.clear();
                (!name.is_empty()).then_some(UiAction::JoinChannel {
                    name,
                    kind,
                    password,
                })
            }
            KeyCode::Backspace => {
                match self.join_popup_focus {
                    JoinPopupFocus::Name => {
                        self.join_popup_input.pop();
                    }
                    JoinPopupFocus::Password => {
                        self.join_popup_password.pop();
                    }
                    JoinPopupFocus::Kind => {}
                }
                None
            }
            KeyCode::Char(c) => {
                match self.join_popup_focus {
                    JoinPopupFocus::Name
                        if validation::channel_name_char_allowed(c)
                            && self.join_popup_input.chars().count()
                                < validation::CHANNEL_NAME_MAX_LEN =>
                    {
                        self.join_popup_input.push(c);
                    }
                    JoinPopupFocus::Password
                        if self.join_popup_kind == ChannelKind::Private
                            && validation::channel_password_char_allowed(c)
                            && self.join_popup_password.chars().count()
                                < validation::CHANNEL_PASSWORD_MAX_LEN =>
                    {
                        self.join_popup_password.push(c);
                    }
                    _ => {}
                }
                None
            }
            _ => None,
        }
    }

    /// Handles the password-entry popup shown after a `ChannelJoinRejected`
    /// (`on_channel_join_rejected`) - lets the user retype a password and
    /// resubmit the same `JoinChannel` against `channel_password_target`.
    pub(crate) fn handle_channel_password_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.channel_password_target = None;
                self.channel_password_input.clear();
                self.channel_password_error = None;
                None
            }
            KeyCode::Enter => {
                let name = self.channel_password_target.clone()?;
                let password = (!self.channel_password_input.is_empty())
                    .then(|| self.channel_password_input.clone());
                self.mode = Mode::Normal;
                self.channel_password_input.clear();
                self.channel_password_error = None;
                Some(UiAction::JoinChannel {
                    name,
                    kind: ChannelKind::Private,
                    password,
                })
            }
            KeyCode::Backspace => {
                self.channel_password_input.pop();
                None
            }
            KeyCode::Char(c)
                if validation::channel_password_char_allowed(c)
                    && self.channel_password_input.chars().count()
                        < validation::CHANNEL_PASSWORD_MAX_LEN =>
            {
                self.channel_password_input.push(c);
                None
            }
            _ => None,
        }
    }

    /// Handles `ServerMessage::ChannelJoinRejected` - opens the password
    /// popup, pre-filling an error message for a retry (`WrongPassword`/
    /// `Banned`) or leaving it blank for a first-time `PasswordRequired`.
    pub fn on_channel_join_rejected(&mut self, name: String, kind: ChannelJoinRejection) {
        self.channel_password_error = match kind {
            ChannelJoinRejection::PasswordRequired => None,
            ChannelJoinRejection::WrongPassword => Some("wrong password".to_string()),
            ChannelJoinRejection::Banned => Some("too many attempts - try again later".to_string()),
        };
        self.channel_password_target = Some(name);
        self.channel_password_input.clear();
        self.mode = Mode::ChannelPasswordPopup;
    }

    /// Excludes ourselves, any offline member (kept in `channel.members`
    /// only so the sidebar can still show their grayed-out history entry -
    /// they have no live connection to actually deliver a message to), and
    /// any member whose identity is `Pending`/`Rejected` review
    /// (`docs/PROTOCOL.md` §12) - we won't encrypt to a peer we haven't
    /// verified. Unlike an offline member this doesn't fail the whole send:
    /// the message still goes out to everyone else in the channel.
    pub(crate) fn recipients_for_channel(
        &self,
        channel: &ChannelTab,
    ) -> Vec<crate::client::tui::ui::Recipient> {
        channel
            .members
            .iter()
            .filter(|m| {
                Some(m.id) != self.own_id
                    && !self.offline.contains(&m.id)
                    && !self.is_trust_gated(m.id)
            })
            .map(|m| (m.id, m.key_mode, m.public_key_der.clone()))
            .collect()
    }

    /// Whether channel `name` is the log currently on screen (no private
    /// room open, and it's the selected tab) - used to decide whether an
    /// incoming/outgoing message should auto-follow `message_selected` to
    /// the bottom (`push_log_entry`), since that only makes sense for
    /// whatever the user is actually looking at right now.
    pub(crate) fn is_viewing_channel(&self, name: &str) -> bool {
        self.active_private_room.is_none()
            && self
                .channels
                .get(self.selected_channel)
                .map(|c| c.name == name)
                .unwrap_or(false)
    }

    /// Whether `peer` is a member of any channel `self` has actually
    /// joined (`ChannelTab::joined`, not merely known-about from the
    /// server's list) - the trust boundary a P2P link request must clear
    /// before this client will respond to it (docs/PROTOCOL.md §7.1.2):
    /// the server's `PeerCandidates` relay performs no relationship
    /// checking of its own (any registered client can name any other
    /// `UserId` as the peer), so this is the only place that boundary is
    /// actually enforced.
    pub fn shares_a_joined_channel(&self, peer: UserId) -> bool {
        self.channels
            .iter()
            .any(|c| c.joined && c.members.iter().any(|m| m.id == peer))
    }

    /// Whether there's still a reason to keep a P2P link to `peer` alive: a
    /// currently-joined channel in common, or DM history with them - the
    /// same bar `on_user_offline` already uses to decide whether to keep a
    /// departed user listed (`!log.is_empty()`, not merely "a room was
    /// opened"). Checked the instant a channel departure (ours, via
    /// `/leave`, or theirs, via `UserLeft`) could have made a link
    /// purposeless (docs/PROTOCOL.md §7.1.3) - unlike `UserOffline`, which
    /// always forgets the link unconditionally since the peer is gone
    /// either way.
    pub fn has_reason_to_keep_link(&self, peer: UserId) -> bool {
        self.shares_a_joined_channel(peer)
            || self
                .private_rooms
                .get(&peer)
                .map(|r| !r.log.is_empty())
                .unwrap_or(false)
    }

    /// Local, optimistic half of leaving `name` - there is no server
    /// acknowledgment to wait for, `LeaveChannel` only notifies whoever
    /// *remains* (docs/PROTOCOL.md §6.2). A private channel's tab is
    /// removed outright (it's never re-advertised, so there's no reason to
    /// keep a ghost tab around); a public channel's tab stays but is
    /// marked `left` (`render_left_channel_screen` takes over its view).
    /// Returns the peer ids who were in this channel with us, for the
    /// caller to run the P2P link-relevance sweep against
    /// (`has_reason_to_keep_link`).
    pub fn leave_channel_locally(&mut self, name: &str) -> Vec<UserId> {
        let Some(idx) = self.channels.iter().position(|c| c.name == name) else {
            return Vec::new();
        };
        let former_members: Vec<UserId> = self.channels[idx].members.iter().map(|m| m.id).collect();
        if self.channels[idx].kind == ChannelKind::Private {
            self.channels.remove(idx);
            self.selected_channel = if self.channels.is_empty() {
                0
            } else {
                self.selected_channel.min(self.channels.len() - 1)
            };
            self.sidebar_selected = 0;
        } else {
            let tab = &mut self.channels[idx];
            tab.joined = false;
            tab.left = true;
            tab.members.clear();
        }
        former_members
    }

    // -------------------------------------------------------------
    // [ / ] dwell-to-join
    // -------------------------------------------------------------

    /// `forward` selects `]` (next channel) vs `[` (previous channel).
    pub(crate) fn start_or_advance_dwell(&mut self, forward: bool) {
        if self.channels.is_empty() {
            return;
        }
        let len = self.channels.len();
        let base = match &self.dwell {
            Some(d) => d.target_index,
            None => self.selected_channel,
        };
        let next = if forward {
            (base + 1) % len
        } else {
            (base + len - 1) % len
        };
        self.selected_channel = next;
        self.active_private_room = None;
        self.sidebar_selected = 0;
        // Start scrolled to the newest message in the newly-selected tab.
        self.message_selected = self.channels[next].log.len().saturating_sub(1);
        self.dwell = Some(DwellState {
            target_index: next,
            started_at: Instant::now(),
        });
    }

    /// Call periodically from the UI loop; fires the actual `JoinChannel`
    /// once the dwell timer has elapsed.
    pub fn tick_dwell(&mut self, now: Instant) -> Option<UiAction> {
        let d = self.dwell.as_ref()?;
        if now.duration_since(d.started_at) < DWELL_DURATION {
            return None;
        }
        let idx = d.target_index;
        self.dwell = None;
        let channel = self.channels.get(idx)?;
        // A channel explicitly `/leave`t (`left`) never dwell-auto-rejoins -
        // only the explicit Enter-on-the-rejoin-prompt path does
        // (`handle_key`, `render_left_channel_screen`). A never-joined one
        // (`left == false`) still dwells exactly as before.
        if channel.joined || channel.left {
            return None;
        }
        Some(UiAction::JoinChannel {
            name: channel.name.clone(),
            kind: channel.kind,
            password: None,
        })
    }

    /// The tab currently being dwelled on (Ctrl+Tab held past it), if any -
    /// useful for rendering a "joining..." indicator.
    pub fn dwell_target(&self) -> Option<usize> {
        self.dwell.as_ref().map(|d| d.target_index)
    }

    // -------------------------------------------------------------
    // Applying incoming server events (already decrypted by the caller)
    // -------------------------------------------------------------

    pub fn on_channel_list(&mut self, list: Vec<ChannelInfo>) {
        for info in list {
            if !self.channels.iter().any(|c| c.name == info.name) {
                self.channels.push(ChannelTab {
                    name: info.name,
                    kind: info.kind,
                    joined: false,
                    left: false,
                    members: Vec::new(),
                    log: Vec::new(),
                });
            }
        }
    }

    pub fn on_joined(&mut self, channel: ChannelInfo) {
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel.name) {
            tab.joined = true;
            tab.left = false;
            tab.kind = channel.kind;
        } else {
            self.channels.push(ChannelTab {
                name: channel.name,
                kind: channel.kind,
                joined: true,
                left: false,
                members: Vec::new(),
                log: Vec::new(),
            });
        }
    }

    /// Records `user` as a member of `channel`, creating a tab if none
    /// exists yet. The tab must be *created* here, not just found: when we
    /// join an already-populated channel, the existing-member `UserJoined`
    /// snapshot arrives *before* the `Joined` confirmation (§6.1), and no
    /// local tab exists yet - dropping that info would lose every member
    /// already in the channel. `kind` is a placeholder (`Public`) when
    /// created this way; `on_joined` corrects it moments later from the
    /// authoritative `ChannelInfo`.
    pub fn on_user_joined(&mut self, channel: &str, user: UserInfo) {
        self.known_users.insert(user.id, user.clone());
        let tab = match self.channels.iter().position(|c| c.name == channel) {
            Some(idx) => &mut self.channels[idx],
            None => {
                self.channels.push(ChannelTab {
                    name: channel.to_string(),
                    kind: ChannelKind::Public,
                    joined: false,
                    left: false,
                    members: Vec::new(),
                    log: Vec::new(),
                });
                self.channels.last_mut().expect("just pushed")
            }
        };
        if !tab.members.iter().any(|m| m.id == user.id) {
            tab.members.push(user);
        }
    }

    pub fn on_user_left(&mut self, channel: &str, user_id: UserId) {
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            tab.members.retain(|m| m.id != user_id);
        }
    }

    pub fn on_channel_message(
        &mut self,
        channel: &str,
        from: UserId,
        from_name: String,
        body: MessageBody,
    ) {
        let entry = LogEntry {
            from,
            from_name,
            to_name: None,
            body,
            outgoing: false,
        };
        // A Pending/Rejected sender's message decrypts fine (it's encrypted
        // with *our* key, not theirs) but is held back rather than shown -
        // docs/PROTOCOL.md §12 "hold and reveal" - until they're Accepted.
        if self.is_trust_gated(from) {
            self.hold_message(from, Some(channel.to_string()), entry);
            return;
        }
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(&mut tab.log, &mut self.message_selected, is_current, entry);
        }
    }

    pub fn log_own_voice_channel(&mut self, channel: &str, duration_ms: u32, pcm: Vec<u8>) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from,
                    from_name,
                    to_name: None,
                    body: MessageBody::Voice { duration_ms, pcm },
                    outgoing: true,
                },
            );
        }
    }

    /// Called the instant our own recording starts (before we know its
    /// eventual duration/content), so the sender sees their own message
    /// appear live rather than only after they release Space - mirroring
    /// what the receiving side sees via `on_channel_stream_start`.
    pub fn log_own_voice_stream_start_channel(&mut self, channel: &str, stream_id: u64) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from,
                    from_name,
                    to_name: None,
                    body: MessageBody::VoiceStreaming { stream_id },
                    outgoing: true,
                },
            );
        }
    }

    /// Called when another user starts a live voice stream to the
    /// channel, so their in-progress message appears immediately instead
    /// of only once it's finished. A Pending/Rejected sender's placeholder
    /// goes into the held buffer instead of the visible log (§12
    /// "hold and reveal") - nothing is shown streaming live for someone
    /// not yet trusted; `on_channel_stream_finished` finds it there and
    /// finalizes it in place, same as the visible-log case.
    pub fn on_channel_stream_start(
        &mut self,
        channel: &str,
        from: UserId,
        from_name: String,
        stream_id: u64,
    ) {
        let entry = LogEntry {
            from,
            from_name,
            to_name: None,
            body: MessageBody::VoiceStreaming { stream_id },
            outgoing: false,
        };
        if self.is_trust_gated(from) {
            self.hold_message(from, Some(channel.to_string()), entry);
            return;
        }
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(&mut tab.log, &mut self.message_selected, is_current, entry);
        }
    }

    /// Swaps the `VoiceStreaming{stream_id}` placeholder for a finished
    /// `Voice{duration_ms, pcm}` in place once the stream ends (own or
    /// remote). Matches on **both** `from` and `stream_id` - `stream_id`
    /// is a per-connection counter, so two senders' counters can collide.
    /// Checks the visible log first, then the held buffer (the
    /// placeholder may be in either, depending on the sender's trust
    /// state *when the stream started* - which can change mid-stream).
    pub fn on_channel_stream_finished(
        &mut self,
        channel: &str,
        from: UserId,
        stream_id: u64,
        duration_ms: u32,
        pcm: Vec<u8>,
    ) {
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel)
            && finalize_stream_entry(&mut tab.log, from, stream_id, duration_ms, pcm.clone())
        {
            return;
        }
        if let Some(held) = self.pending_messages.get_mut(&from) {
            finalize_held_stream(held, from, stream_id, duration_ms, pcm);
        }
    }

    /// Logs an outgoing entry of any body type (text, or a file send - see
    /// `crate::client::tui::file_send`) as our own, straight away rather than
    /// waiting for a server round-trip - the same optimistic-echo pattern
    /// `log_own_voice_channel` already uses for voice.
    pub(crate) fn push_outgoing_channel(&mut self, channel: &str, body: MessageBody) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from,
                    from_name,
                    to_name: None,
                    body,
                    outgoing: true,
                },
            );
        }
    }

    /// Creates one recipient's pending outgoing file-transfer row in the
    /// channel log, straight away (before that recipient's Accept/Reject
    /// response arrives) - mirrors `log_own_voice_stream_start_channel`'s
    /// "show it live" precedent. A channel file send creates one of these
    /// per recipient (`docs/PROTOCOL.md`'s file transfer section), `to_name`
    /// naming which one this row is addressed to; later
    /// progress/completion events find it again by `(from, stream_id)`
    /// (`update_file_entry`).
    pub fn log_own_file_offer_channel(
        &mut self,
        channel: &str,
        to_name: &str,
        stream_id: u64,
        filename: String,
        total: u64,
    ) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from,
                    from_name,
                    to_name: Some(to_name.to_string()),
                    body: MessageBody::File {
                        filename,
                        total,
                        stream_id,
                        status: FileTransferStatus::Pending,
                    },
                    outgoing: true,
                },
            );
        }
    }

    /// Creates the receiving side's row the moment a file offer is
    /// accepted (`docs/PROTOCOL.md`'s file transfer section) - there is no
    /// row at all while it was only `Pending` in the offer popup.
    pub fn on_channel_file_offer_accepted(
        &mut self,
        channel: &str,
        from: UserId,
        from_name: String,
        stream_id: u64,
        filename: String,
        total: u64,
    ) {
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from,
                    from_name,
                    to_name: None,
                    body: MessageBody::File {
                        filename,
                        total,
                        stream_id,
                        status: FileTransferStatus::InProgress { bytes: 0 },
                    },
                    outgoing: false,
                },
            );
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_channel_view(frame: &mut Frame, area: Rect, state: &UiState) {
    let constraints = [
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(3),
    ];
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    let tabs_row = 0;
    let messages_row = 1;
    let input_row = 2;

    // The tab row is split so the status area - Conn quality, CPU usage,
    // the help hint, and (while a key is being regenerated) the spinner
    // right after it - sits flush right, past the end of the channel
    // tabs, regardless of how many tabs there are. Widest realistic
    // content: "Conn:NORMAL  CPU:100%  Ctrl+H: Help  _" (38 cols); a
    // little slack is kept above that.
    let header_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(40)])
        .split(rows[tabs_row]);

    let titles: Vec<Line> = state
        .channels
        .iter()
        .map(|c| {
            let prefix = if c.kind == ChannelKind::Private {
                "\u{1F512}"
            } else {
                "\u{1F30D}"
            };
            Line::from(format!("{prefix} {}", c.name))
        })
        .collect();
    let tabs = Tabs::new(titles).select(state.selected_channel);
    frame.render_widget(tabs, header_cols[0]);

    // Conn comes first (right before CPU), CPU right before the help hint
    // - docs/SPEC.md "Connected UI".
    let mut status_spans = vec![
        Span::styled(
            format!("Conn:{}", state.conn_quality.label()),
            Style::default().fg(conn_color(state.conn_quality)),
        ),
        Span::raw("  "),
        Span::styled(
            format!("CPU:{}%", cpu_pct_rounded(state.cpu_usage_pct)),
            Style::default().fg(cpu_color(state.cpu_usage_pct)),
        ),
        Span::raw("  "),
    ];
    if state.key_regenerating {
        status_spans.push(Span::styled(
            "Ctrl+H: Help  ",
            Style::default().fg(Color::DarkGray),
        ));
        status_spans.push(Span::styled(
            state.spinner_char().to_string(),
            Style::default().fg(Color::White),
        ));
    } else {
        status_spans.push(Span::styled(
            "Ctrl+H: Help",
            Style::default().fg(Color::DarkGray),
        ));
    }
    let help_hint_line = Line::from(status_spans);
    frame.render_widget(
        Paragraph::new(help_hint_line).alignment(ratatui::layout::Alignment::Right),
        header_cols[1],
    );

    // A public channel the user has explicitly `/leave`t shows a rejoin
    // prompt instead of the normal sidebar+messages+compose view - the tab
    // row above stays, so `[`/`]` navigation is still visible, but nothing
    // below it is usable until they rejoin (`handle_key`'s `left` branch).
    if state
        .channels
        .get(state.selected_channel)
        .map(|c| c.left)
        .unwrap_or(false)
    {
        let content_area = Rect {
            x: rows[messages_row].x,
            y: rows[messages_row].y,
            width: rows[messages_row].width,
            height: rows[messages_row].height + rows[input_row].height,
        };
        render_left_channel_screen(
            frame,
            content_area,
            &state.channels[state.selected_channel].name,
        );
        return;
    }

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(rows[messages_row]);

    render_sidebar(frame, cols[0], state);
    render_messages(frame, cols[1], state, None);
    render_input_bar(frame, rows[input_row], state);
}

/// Shown in place of the sidebar+messages+compose view while the selected
/// channel tab is `left` (`ChannelTab::left`) - a public channel the user
/// explicitly `/leave`t. `Enter` (handled in `UiState::handle_key`, not
/// here) re-requests joining it.
fn render_left_channel_screen(frame: &mut Frame, area: Rect, channel_name: &str) {
    let popup = super::ui::centered_rect(56, 5, area);
    let block = Block::default().borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!("You left this public channel: {channel_name}"))
            .alignment(ratatui::layout::Alignment::Center),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new("Do you want to join?").alignment(ratatui::layout::Alignment::Center),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new("[ Enter to join ]")
            .alignment(ratatui::layout::Alignment::Center)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        rows[2],
    );
}

/// `state.cpu_usage_pct` rounded to the nearest whole percent for display -
/// shared by the label text and `cpu_color` so the two never disagree at a
/// rounding boundary (e.g. a raw 24.6% would round to "25%" but still
/// compare as healthy against the raw value).
fn cpu_pct_rounded(pct: f32) -> i64 {
    pct.round().clamp(0.0, 100.0) as i64
}

/// Color for the `CPU:<pct>%` header indicator: green below
/// `CPU_HEALTHY_MAX_PCT`, red at or above it (docs/SPEC.md "Connected UI").
/// Takes the already-rounded display value (see `cpu_pct_rounded`) so the
/// color always matches what's actually shown on screen.
pub(crate) fn cpu_color(pct: f32) -> Color {
    if (cpu_pct_rounded(pct) as f32) < CPU_HEALTHY_MAX_PCT {
        Color::Green
    } else {
        Color::Red
    }
}

/// Color for the `Conn:<quality>` header indicator - one fixed color per
/// `netstats::ConnQuality` variant (docs/SPEC.md "Connected UI").
pub(crate) fn conn_color(quality: ConnQuality) -> Color {
    match quality {
        ConnQuality::Unknown => Color::White,
        ConnQuality::Bad => Color::Red,
        ConnQuality::Normal => Color::Yellow,
        ConnQuality::Good => Color::Green,
    }
}

fn render_sidebar(frame: &mut Frame, area: Rect, state: &UiState) {
    let border_style = focus_border_style(state.focus == super::ui::Focus::Sidebar);
    let block = Block::default()
        .title("Users")
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(channel) = state.channels.get(state.selected_channel) else {
        return;
    };
    let items: Vec<ListItem> = channel
        .members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            // A room is created (empty) the moment its DM tab is opened
            // (`open_private_room`) - the envelope must only show once
            // there's actually a message in it (sent or received), not
            // just because that struct exists. Otherwise merely opening
            // an empty DM and switching back would show an envelope for a
            // conversation that never happened.
            let room = state.private_rooms.get(&m.id).filter(|r| !r.log.is_empty());
            let envelope = match room {
                Some(r) if r.unread => {
                    if state.blink_on {
                        "\u{2709} "
                    } else {
                        "  "
                    }
                }
                Some(_) => "\u{2709} ",
                None => "",
            };
            let label = format!("{envelope}{}", m.key_mode.format_with_name(&m.name));
            // A Pending/Rejected identity (docs/PROTOCOL.md §12) takes
            // priority over everything below - it's the most urgent,
            // actionable state (open the review popup via Enter), whether
            // or not they also happen to be offline or unreachable.
            // Offline members are otherwise only ever kept around because
            // there's DM history worth preserving (`on_user_offline`) -
            // shown in a soft gray, the same dim tone the help
            // hint/spinner label already use elsewhere in this screen.
            //
            // For everyone still connected, the colour is the state of the
            // *direct link* to them (§7.1), not merely their presence on
            // the server: green once messages can actually reach them, red
            // once they can't, yellow while the punch is still being
            // worked out. Presence alone would be the misleading thing to
            // show here - a peer can be perfectly online and completely
            // unreachable, which is exactly the case this is here to make
            // visible.
            let mut style = if state.is_trust_gated(m.id) {
                Style::default().fg(Color::Red)
            } else if state.offline.contains(&m.id) {
                Style::default().fg(Color::DarkGray)
            } else {
                match state.link_status_of(m.id) {
                    LinkStatus::Active => Style::default().fg(Color::Green),
                    LinkStatus::Lost => Style::default().fg(Color::Red),
                    LinkStatus::Connecting => Style::default().fg(Color::Yellow),
                }
            };
            if state.focus == super::ui::Focus::Sidebar && i == state.sidebar_selected {
                style = style.add_modifier(Modifier::REVERSED);
            }
            ListItem::new(label).style(style)
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

/// Ctrl+J's popup: a channel name field, a Public/Private selector (the
/// currently selected side shown reversed), and - only while Private is
/// selected - a masked password field. The focused field (Tab/BackTab
/// cycles) is marked with a leading `>`, mirroring the plain-text-cursor
/// convention `> {input}` this popup already used before the selector
/// existed.
pub(crate) fn render_join_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let show_password = state.join_popup_kind == ChannelKind::Private;
    let height = if show_password { 5 } else { 4 };
    let popup = super::ui::centered_rect(44, height, area);
    let block = Block::default()
        .title("Join or create a channel (Tab to move, Enter to confirm, Esc to cancel)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![Constraint::Length(1), Constraint::Length(1)];
    if show_password {
        constraints.push(Constraint::Length(1));
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let cursor = |focused: bool| if focused { "> " } else { "  " };

    let name_line = format!(
        "{}Name: {}",
        cursor(state.join_popup_focus == JoinPopupFocus::Name),
        state.join_popup_input
    );
    frame.render_widget(Paragraph::new(name_line), rows[0]);

    let selected_style = Style::default().add_modifier(Modifier::REVERSED);
    let kind_line = Line::from(vec![
        Span::raw(cursor(state.join_popup_focus == JoinPopupFocus::Kind)),
        Span::raw("Kind: "),
        Span::styled(
            "Public",
            if state.join_popup_kind == ChannelKind::Public {
                selected_style
            } else {
                Style::default()
            },
        ),
        Span::raw(" / "),
        Span::styled(
            "Private",
            if state.join_popup_kind == ChannelKind::Private {
                selected_style
            } else {
                Style::default()
            },
        ),
    ]);
    frame.render_widget(Paragraph::new(kind_line), rows[1]);

    if show_password {
        let masked = "*".repeat(state.join_popup_password.chars().count());
        let password_line = format!(
            "{}Password: {masked}",
            cursor(state.join_popup_focus == JoinPopupFocus::Password)
        );
        frame.render_widget(Paragraph::new(password_line), rows[2]);
    }
}

/// The password-entry popup shown after a `ChannelJoinRejected` -
/// `UiState::on_channel_join_rejected` sets `channel_password_target`/
/// `channel_password_error` to drive this.
pub(crate) fn render_channel_password_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let has_error = state.channel_password_error.is_some();
    let height = if has_error { 4 } else { 3 };
    let popup = super::ui::centered_rect(44, height, area);
    let target = state.channel_password_target.as_deref().unwrap_or("");
    let block = Block::default()
        .title(format!(
            "Password for '{target}' (Enter to submit, Esc to cancel)"
        ))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![Constraint::Length(1)];
    if has_error {
        constraints.push(Constraint::Length(1));
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let masked = "*".repeat(state.channel_password_input.chars().count());
    frame.render_widget(Paragraph::new(format!("> {masked}")), rows[0]);

    if let Some(err) = &state.channel_password_error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
            rows[1],
        );
    }
}
