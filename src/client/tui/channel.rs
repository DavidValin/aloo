//! Channel state and rendering: the `ChannelTab` log/membership model, the
//! top row (both selectors, the call indicator and the status figures), and
//! the channel view / sidebar / Ctrl+J popup rendering. Shared/mixed UI plumbing (`UiState` itself, `Focus`,
//! `Mode`, message-log rendering, the input bar, ...) stays in
//! `crate::client::tui::ui`; DM-room state/rendering is the mirror image in
//! `crate::client::tui::direct_message`.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};

use crate::client::netstats::ConnQuality;
use crate::client::presence::Presence;
use crate::client::reconnect::ServerLinkState;
use crate::proto::{ChannelInfo, ChannelJoinRejection, ChannelKind, UserId, UserInfo};
use crate::client::sysstats::CPU_HEALTHY_MAX_PCT;
use crate::validation;

use super::ui::{
    DM_ICON, FileTransferStatus, JoinPopupFocus, LogEntry, MessageBody,
    MessageDelivery, Mode, OTP_TAG, OTP_TAG_COLOR, SelectorFocus, UNREAD_ENVELOPE, UiAction,
    UiState, channel_label, display_width, finalize_held_stream, finalize_stream_entry,
    focus_border_style, local_time_short, local_time_stamp, push_log_entry, render_input_bar,
    render_messages, unread_envelope,
};

#[derive(Debug, Clone)]
pub struct ChannelTab {
    pub name: String,
    pub kind: ChannelKind,
    /// Whether the server's `Joined` confirmation has arrived yet. A tab
    /// only exists for a channel being joined, but the membership snapshot
    /// (§6.1) can create it a moment before that confirmation
    /// (`seed_member`), and until then there's nothing to send to.
    pub joined: bool,
    pub members: Vec<UserInfo>,
    pub log: Vec<LogEntry>,
    /// Whether a message has landed here since this channel was last on
    /// screen - what makes the channel selector's envelope blink
    /// (`docs/SPEC.md` "Connected UI"). Set only by real messages (text,
    /// voice, a file arriving), never by presence notices, and cleared the
    /// moment the channel is selected again (`select_channel_at`).
    pub unread: bool,
    /// This channel's current admin nickname, or `None` (permanently, for
    /// `the-hall`; as a placeholder until the real value arrives, for a
    /// tab created early by `seed_member`). Set by `UiState::set_channel_admin`,
    /// called from `ServerMessage::Joined`'s `admin` field and again on
    /// every later `ChannelAdminChanged` - never by `on_joined` itself, so
    /// every existing caller that only cares about kind/membership is
    /// unaffected.
    pub admin: Option<String>,
    /// `resume_from_log`'s reader for this channel's `.log` file - `None`
    /// until the first history load (either the initial one on first
    /// viewing, or a scroll-triggered one), and forever `None` if the
    /// setting is off. See `UiState::load_history_chunk`.
    pub history_cursor: Option<crate::client::export::LogHistoryCursor>,
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
                let name =
                    validation::normalize_channel_name(&self.join_popup_input).to_string();
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
                    // A leading `#` is accepted and then ignored on
                    // submit (`validation::normalize_channel_name`): the
                    // selector names channels with one, so someone typing
                    // a channel in has every reason to type it the way
                    // they just read it. Only in the first position -
                    // anywhere else it is a genuine mistake, and refusing
                    // the keystroke says so straight away.
                    JoinPopupFocus::Name
                        if c == validation::CHANNEL_DISPLAY_PREFIX
                            && self.join_popup_input.is_empty() =>
                    {
                        self.join_popup_input.push(c);
                    }
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

    /// Handles `ServerMessage::ChannelJoinRejected`. The three
    /// password-flow outcomes open the password popup, pre-filling an
    /// error message for a retry (`WrongPassword`/`Banned`) or leaving it
    /// blank for a first-time `PasswordRequired` - retyping a password
    /// can never fix `UserBanned` or `NotOnAllowlist`, so those two are
    /// just a status notice instead, with no popup at all.
    pub fn on_channel_join_rejected(&mut self, name: String, kind: ChannelJoinRejection) {
        let password_error = match kind {
            ChannelJoinRejection::PasswordRequired => None,
            ChannelJoinRejection::WrongPassword => Some("wrong password".to_string()),
            ChannelJoinRejection::Banned => Some("too many attempts - try again later".to_string()),
            ChannelJoinRejection::UserBanned => {
                self.push_status_notice(format!("you are banned from #{name}"), false);
                return;
            }
            ChannelJoinRejection::NotOnAllowlist => {
                self.push_status_notice(
                    format!("#{name} is locked - you're not on the join list"),
                    false,
                );
                return;
            }
        };
        self.channel_password_error = password_error;
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
            .map(|m| (m.id, m.public_key_der.clone()))
            .collect()
    }

    /// Whether channel `name` is the log currently on screen (no private
    /// room open, and it's the one the channel selector names) - used to decide whether an
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
    /// *remains* (docs/PROTOCOL.md §6.2). It is dropped from `channels`
    /// outright, public or private alike: that list is exactly the
    /// channels the user is currently joined to (`on_joined` is the only thing that creates
    /// one), and a public channel the user left is still listed in the
    /// `/channels` directory (`known_channels`) to rejoin from.
    /// Returns the peer ids who were in this channel with us, for the
    /// caller to run the P2P link-relevance sweep against
    /// (`has_reason_to_keep_link`).
    pub fn leave_channel_locally(&mut self, name: &str) -> Vec<UserId> {
        let Some(idx) = self.channels.iter().position(|c| c.name == name) else {
            return Vec::new();
        };
        let former_members: Vec<UserId> = self.channels[idx].members.iter().map(|m| m.id).collect();
        self.channels.remove(idx);
        self.selected_channel = if self.channels.is_empty() {
            0
        } else {
            self.selected_channel.min(self.channels.len() - 1)
        };
        self.sidebar_selected = 0;
        self.message_selected = self
            .channels
            .get(self.selected_channel)
            .map(|c| c.log.len().saturating_sub(1))
            .unwrap_or(0);
        former_members
    }

    // -------------------------------------------------------------
    // What the channel selector names
    // -------------------------------------------------------------

    /// Makes the channel at `idx` the one the left-hand selector names -
    /// every joined channel is already joined (`on_joined` is the only
    /// thing that creates one), so this never joins anything; joining is
    /// `/channels` or Ctrl+J. Clears that channel's unread envelope, since
    /// it is now the log being looked at, and starts it scrolled to its
    /// newest message rather than wherever the last visit left off. Out of
    /// range (no channels joined at all) is a no-op.
    pub fn select_channel_at(&mut self, idx: usize) {
        if self.channels.get(idx).is_none() {
            return;
        }
        self.channels[idx].unread = false;
        self.selected_channel = idx;
        // Seed this channel with its first `resume_from_log` chunk the
        // very first time it's viewed - guarded on `history_cursor` still
        // being `None` so revisiting an already-seeded tab doesn't load
        // another chunk every time (that's what scrolling up is for,
        // `handle_messages_key`).
        if self.resume_from_log && self.channels[idx].history_cursor.is_none() {
            self.load_history_chunk();
        }
        let log_len = self.channels[idx].log.len();
        self.message_selected = log_len.saturating_sub(1);
    }

    // -------------------------------------------------------------
    // The /channels directory popup
    // -------------------------------------------------------------

    /// Every public channel the server has announced (`ChannelList` at
    /// connect, `ChannelCreated` afterwards), in announcement order - the
    /// rows of the `/channels` modal. Kept separate from `channels` (what
    /// the channel selector offers), which only ever holds channels the
    /// user is actually joined to.
    pub fn known_public_channels(&self) -> &[ChannelInfo] {
        &self.known_channels
    }

    /// Whether `name` is one of the user's own joined channels - what
    /// colours its `/channels` row yellow (`render_channels_popup`).
    pub fn is_joined(&self, name: &str) -> bool {
        self.channels.iter().any(|c| c.name == name && c.joined)
    }

    /// The one channel joined automatically on connecting: the server's
    /// default public channel, `DEFAULT_CHANNEL_NAME` ("the-hall"),
    /// and only while no channel has been joined yet. Every other public
    /// channel the server offers is left for the user to pick out of
    /// `/channels` - being on the channel selector means "I am in this
    /// room", so joining all of them on the user's behalf would be wrong
    /// (docs/PROTOCOL.md §6.3).
    pub fn auto_join_channel(&self) -> Option<UiAction> {
        if !self.channels.is_empty() {
            return None;
        }
        let hall = self
            .known_channels
            .iter()
            .find(|c| c.name == crate::server::DEFAULT_CHANNEL_NAME)?;
        Some(UiAction::JoinChannel {
            name: hall.name.clone(),
            kind: hall.kind,
            password: None,
        })
    }

    /// Opens the `/channels` modal, selecting the first row.
    pub(crate) fn open_channels_popup(&mut self) {
        self.mode = Mode::ChannelsPopup;
        self.channels_popup_selected = 0;
    }

    /// Handles the `/channels` modal: Up/Down move the selection, Enter
    /// joins the selected channel (a no-op for one already joined - it's
    /// shown yellow precisely so the user can tell), Esc closes it.
    pub(crate) fn handle_channels_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let len = self.known_channels.len();
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                None
            }
            KeyCode::Up => {
                if len > 0 {
                    self.channels_popup_selected = (self.channels_popup_selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                if len > 0 {
                    self.channels_popup_selected = (self.channels_popup_selected + 1) % len;
                }
                None
            }
            KeyCode::Enter => {
                let info = self.known_channels.get(self.channels_popup_selected)?.clone();
                self.mode = Mode::Normal;
                if self.is_joined(&info.name) {
                    // Already a member: selecting it just brings that
                    // channel to the front of the channel selector rather
                    // than re-sending a join the server would treat as a
                    // no-op anyway (§6.1).
                    if let Some(idx) = self.channels.iter().position(|c| c.name == info.name) {
                        self.selected_channel = idx;
                        self.focus_channel_selector();
                    }
                    return None;
                }
                Some(UiAction::JoinChannel {
                    name: info.name,
                    kind: info.kind,
                    password: None,
                })
            }
            _ => None,
        }
    }

    // -------------------------------------------------------------
    // Applying incoming server events (already decrypted by the caller)
    // -------------------------------------------------------------

    /// Records the server's public channel directory (`ChannelList` at
    /// connect, one-element `ChannelCreated` announcements afterwards),
    /// de-duplicating by name. This never creates a `ChannelTab`: those
    /// are exactly the joined channels (`on_joined`), and the directory is
    /// what the `/channels` modal lists.
    pub fn on_channel_list(&mut self, list: Vec<ChannelInfo>) {
        for info in list {
            if !self.known_channels.iter().any(|c| c.name == info.name) {
                self.known_channels.push(info);
            }
        }
    }

    pub fn on_joined(&mut self, channel: ChannelInfo) {
        // A public channel we're in belongs in the `/channels` directory
        // too, and this is the only place that learns about one we
        // created ourselves: the server's `ChannelCreated` announcement
        // goes to every client *except* the creator (§6.3), so a channel
        // opened with Ctrl+J would otherwise never appear in its own
        // author's directory. A private channel is deliberately left out -
        // it is never advertised to anyone (§6.3/AC-022).
        if channel.kind == ChannelKind::Public
            && !self.known_channels.iter().any(|c| c.name == channel.name)
        {
            self.known_channels.push(channel.clone());
        }
        let name = channel.name.clone();
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel.name) {
            tab.joined = true;
            tab.kind = channel.kind;
        } else {
            self.channels.push(ChannelTab {
                name: channel.name,
                kind: channel.kind,
                joined: true,
                members: Vec::new(),
                log: Vec::new(),
                unread: false,
                admin: None,
                history_cursor: None,
            });
        }
        // Landing in the channel just joined is the whole point of joining
        // it: it becomes the one the channel selector names, and the view,
        // so the compose bar is already addressed to it. Any open DM room
        // closes with that, the same as any other move to the channel
        // selector.
        if let Some(idx) = self.channels.iter().position(|c| c.name == name) {
            self.selected_channel = idx;
            self.focus_channel_selector();
            // A genuine "this surface just became the view" moment - same
            // `resume_from_log` seed `select_channel_at` gives a channel
            // reached through the selector, needed here too since landing
            // straight in a freshly-joined channel never goes through that
            // function at all.
            if self.resume_from_log && self.channels[idx].history_cursor.is_none() {
                self.load_history_chunk();
                let log_len = self.channels[idx].log.len();
                self.message_selected = log_len.saturating_sub(1);
            }
        }
    }

    /// Records `user` as a member of `channel`, creating a tab if none
    /// exists yet, without touching the log - shared by `on_user_joined`
    /// below (the real, notice-emitting entry point) and test/scenario
    /// setup (`test/ui_common.rs`, the cucumber `{word} is in the channel
    /// with me` step) that wants to describe a channel's *starting*
    /// roster rather than simulate a join happening during the test. The
    /// tab must be *created* here, not just found: when we join an
    /// already-populated channel, the existing-member `UserJoined`
    /// snapshot arrives *before* the `Joined` confirmation (§6.1), and no
    /// local tab exists yet - dropping that info would lose every member
    /// already in the channel. `kind` is a placeholder (`Public`) when
    /// created this way; `on_joined` corrects it moments later from the
    /// authoritative `ChannelInfo`. Returns whether `user` was actually new
    /// to the channel (`false` on a duplicate join, which is a no-op here).
    /// Every joined channel `peer` is currently listed in - the local
    /// half of reconciling a serverless peer's announced membership
    /// (`docs/PROTOCOL.md` §7.1.5).
    pub fn channels_containing_member(&self, peer: UserId) -> Vec<String> {
        self.channels
            .iter()
            .filter(|c| c.joined && c.members.iter().any(|m| m.id == peer))
            .map(|c| c.name.clone())
            .collect()
    }

    /// Whether `peer` is already listed in `channel`.
    pub fn is_member_of_channel(&self, channel: &str, peer: UserId) -> bool {
        self.channels
            .iter()
            .any(|c| c.name == channel && c.members.iter().any(|m| m.id == peer))
    }

    /// Whether `nickname` is a server superadmin (`server_superadmin`,
    /// from the connect-time `ChannelList.superadmins`) - drives the ⚡
    /// marker shown next to their name everywhere, in any channel.
    pub fn is_superadmin(&self, nickname: &str) -> bool {
        self.superadmins.contains(nickname)
    }

    pub fn seed_member(&mut self, channel: &str, user: UserInfo) -> bool {
        // Someone who went offline and is now back takes their own place
        // again rather than appearing beside it
        // (`UiState::adopt_returning_peer`). Done before anything is keyed
        // by the new id, so the room and the selector move across in one
        // step.
        if let Some(previous) = self.returning_peer_id(&user) {
            self.adopt_returning_peer(previous, &user);
        }
        self.known_users.insert(user.id, user.clone());
        // Their own row from before the reconnect: this nickname under an
        // id this session no longer knows anyone by, which is exactly what
        // `adopt_returning_peer` leaves behind. Read here rather than
        // carried out of that call because a reconnect produces one
        // `UserJoined` per channel and the adoption only runs on the
        // first - every other channel finds its own stale row this way.
        // The `known_users` check is what keeps it to genuinely departed
        // connections: a nickname is unique among connected clients
        // (`docs/PROTOCOL.md` §5.4), so one still known is somebody else's
        // live row and not ours to take.
        let stale_row = self
            .channels
            .iter()
            .find(|c| c.name == channel)
            .and_then(|c| {
                c.members
                    .iter()
                    .find(|m| m.name == user.name && m.id != user.id)
            })
            .map(|m| m.id)
            .filter(|id| !self.known_users.contains_key(id));
        let tab = match self.channels.iter().position(|c| c.name == channel) {
            Some(idx) => &mut self.channels[idx],
            None => {
                self.channels.push(ChannelTab {
                    name: channel.to_string(),
                    kind: ChannelKind::Public,
                    joined: false,
                    members: Vec::new(),
                    log: Vec::new(),
                    unread: false,
                    admin: None,
                    history_cursor: None,
                });
                self.channels.last_mut().expect("just pushed")
            }
        };
        // Replaced in place, so they keep their position in the list
        // rather than moving to the end - and reported as an arrival,
        // because that is what it is: they really did just rejoin.
        if let Some(previous) = stale_row
            && let Some(slot) = tab.members.iter_mut().find(|m| m.id == previous)
        {
            *slot = user;
            return true;
        }
        let is_new = !tab.members.iter().any(|m| m.id == user.id);
        if is_new {
            tab.members.push(user);
        }
        is_new
    }

    /// `seed_member` plus a yellow "`<time>` `<name>` joined" log entry
    /// (`MessageBody::Presence`, `docs/SPEC.md` Functionality #12) - but only
    /// when `channel` was already joined *before* this call, i.e. this is a
    /// genuine live join rather than the existing-member snapshot a fresh
    /// join receives (see `seed_member`'s doc): that snapshot's `UserJoined`
    /// batch always arrives while the tab is still `joined == false`, since
    /// the confirming `Joined` hasn't landed yet - the exact ordering
    /// `on_user_joined_creates_the_tab_if_a_join_snapshot_arrives_before_joined`
    /// (`test/ui_channel_test.rs`) pins down. This is the only entry point
    /// `session.rs` calls for `ServerMessage::UserJoined`.
    pub fn on_user_joined(&mut self, channel: &str, user: UserInfo) {
        let already_joined = self
            .channels
            .iter()
            .find(|c| c.name == channel)
            .map(|c| c.joined)
            .unwrap_or(false);
        let id = user.id;
        let name = user.name.clone();
        let is_new = self.seed_member(channel, user);
        if already_joined && is_new {
            let text = format!("{} {name} joined", local_time_short());
            let is_current = self.is_viewing_channel(channel);
            let autosave = self.autosave_messages.then(|| self.server_label.clone());
            if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
                push_log_entry(
                    &mut tab.log,
                    &mut self.message_selected,
                    is_current,
                    LogEntry {
                        from: id,
                        from_name: name,
                        to_name: None,
                        body: MessageBody::Presence(text),
                        outgoing: false,
                        failed: false,
                        sent_at: local_time_stamp(),
                        sent_at_utc: crate::client::export::utc_time_stamp(),
                        owed_receipt: None,
                        listened: true,
                        delivery: None,
                        // This client wrote the line itself out of a
                        // `UserJoined`; nothing about it was encrypted.
                        crypto: None,
                    },
                );
                if let Some(server_label) = &autosave {
                    crate::client::export::autosave_entry(
                        server_label,
                        crate::client::export::Surface::Channel(channel),
                        tab.log.last().unwrap(),
                    );
                }
            }
        }
    }

    /// Removes `user_id` from `channel`'s member list and, if we knew their
    /// name, logs a yellow "`<time>` `<name>` left" entry
    /// (`MessageBody::Presence`) into that channel - always a genuine event
    /// (unlike `on_user_joined`, a `UserLeft` is only ever sent for a
    /// channel the recipient is already joined to, so there's no snapshot
    /// case to exclude here).
    pub fn on_user_left(&mut self, channel: &str, user_id: UserId) {
        let name = self
            .channels
            .iter()
            .find(|c| c.name == channel)
            .and_then(|c| c.members.iter().find(|m| m.id == user_id))
            .map(|m| m.name.clone())
            .or_else(|| self.known_users.get(&user_id).map(|u| u.name.clone()));
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            tab.members.retain(|m| m.id != user_id);
        }
        if let Some(name) = name {
            let text = format!("{} {name} left", local_time_short());
            let is_current = self.is_viewing_channel(channel);
            let autosave = self.autosave_messages.then(|| self.server_label.clone());
            if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
                push_log_entry(
                    &mut tab.log,
                    &mut self.message_selected,
                    is_current,
                    LogEntry {
                        from: user_id,
                        from_name: name,
                        to_name: None,
                        body: MessageBody::Presence(text),
                        outgoing: false,
                        failed: false,
                        sent_at: local_time_stamp(),
                        sent_at_utc: crate::client::export::utc_time_stamp(),
                        owed_receipt: None,
                        listened: true,
                        delivery: None,
                        crypto: None,
                    },
                );
                if let Some(server_label) = &autosave {
                    crate::client::export::autosave_entry(
                        server_label,
                        crate::client::export::Surface::Channel(channel),
                        tab.log.last().unwrap(),
                    );
                }
            }
        }
    }

    /// Sets `channel`'s current admin - called from `ServerMessage::Joined`'s
    /// `admin` field and again on every later `ChannelAdminChanged`. A
    /// no-op if the tab doesn't exist (there is nothing to correct).
    pub fn set_channel_admin(&mut self, channel: &str, admin: Option<String>) {
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            tab.admin = admin;
        }
    }

    /// The shared shape `on_user_joined`/`on_user_left` already use for a
    /// yellow presence line, reused for every channel-moderation notice.
    /// `who`/`who_name` are cosmetic only: a `MessageBody::Presence` line
    /// renders its `text` alone (`ui.rs`'s `render_messages`), never
    /// `from`/`from_name` - so an event with no single "about" user (a
    /// join-lock update, an admin handoff) may pass `UserId(0)` and an
    /// empty name safely.
    fn push_presence_notice(&mut self, channel: &str, who: UserId, who_name: String, text: String) {
        let is_current = self.is_viewing_channel(channel);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from: who,
                    from_name: who_name,
                    to_name: None,
                    body: MessageBody::Presence(text),
                    outgoing: false,
                    failed: false,
                    sent_at: local_time_stamp(),
                    sent_at_utc: crate::client::export::utc_time_stamp(),
                    owed_receipt: None,
                    listened: true,
                    delivery: None,
                    crypto: None,
                },
            );
            if let Some(server_label) = &autosave {
                crate::client::export::autosave_entry(
                    server_label,
                    crate::client::export::Surface::Channel(channel),
                    tab.log.last().unwrap(),
                );
            }
        }
    }

    /// `ServerMessage::UserBanned` for someone other than ourselves (the
    /// caller already branches on that): force-removes them from
    /// `channel`'s member list, mirroring `on_user_left`, and logs a
    /// distinctly-worded presence line.
    pub fn on_user_banned(&mut self, channel: &str, user_id: UserId, nickname: String) {
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            tab.members.retain(|m| m.id != user_id);
        }
        let text = format!("{} {nickname} was banned from this channel", local_time_short());
        self.push_presence_notice(channel, user_id, nickname, text);
    }

    /// `ServerMessage::UserUnbanned` - membership is unaffected; `nickname`
    /// simply may join again from now on.
    pub fn on_user_unbanned(&mut self, channel: &str, nickname: String) {
        let text = format!("{} {nickname} was unbanned", local_time_short());
        self.push_presence_notice(channel, UserId(0), nickname, text);
    }

    /// `ServerMessage::ChannelJoinLockUpdated`.
    pub fn on_join_lock_updated(&mut self, channel: &str, by: String) {
        let text = format!("{} join list updated by {by}", local_time_short());
        self.push_presence_notice(channel, UserId(0), by, text);
    }

    /// `ServerMessage::ChannelAdminChanged` - a *later* change while
    /// already joined; the admin at join time itself arrives on `Joined`
    /// and is applied via `set_channel_admin` directly, with no notice
    /// (there's nobody else in the channel yet to notify).
    pub fn on_channel_admin_changed(&mut self, channel: &str, admin: Option<String>) {
        let text = match &admin {
            Some(name) => format!("{} {name} is now the admin of this channel", local_time_short()),
            None => format!("{} this channel has no admin", local_time_short()),
        };
        self.set_channel_admin(channel, admin);
        self.push_presence_notice(channel, UserId(0), String::new(), text);
    }

    /// `ServerMessage::ChannelRemoved` - the tab simply disappears, exactly
    /// as leaving one already does; `reason` is shown as a status notice
    /// by the caller, not logged into a tab that's about to be gone.
    pub fn on_channel_removed(&mut self, name: &str) {
        if let Some(idx) = self.channels.iter().position(|c| c.name == name) {
            self.channels.remove(idx);
            if self.selected_channel >= self.channels.len() {
                self.selected_channel = self.channels.len().saturating_sub(1);
            }
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
            failed: false,
            sent_at: local_time_stamp(),
            sent_at_utc: crate::client::export::utc_time_stamp(),
            owed_receipt: None,
            listened: true,
            delivery: None,
            crypto: self.message_crypto(from, false),
        };
        // A Pending/Rejected sender's message decrypts fine (it's encrypted
        // with *our* key, not theirs) but is held back rather than shown -
        // docs/PROTOCOL.md §12 "hold and reveal" - until they're Accepted.
        if self.is_trust_gated(from) {
            self.hold_message(from, Some(channel.to_string()), entry);
            return;
        }
        let is_current = self.is_viewing_channel(channel);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(&mut tab.log, &mut self.message_selected, is_current, entry);
            if !is_current {
                tab.unread = true;
            }
            if let Some(server_label) = &autosave {
                crate::client::export::autosave_entry(
                    server_label,
                    crate::client::export::Surface::Channel(channel),
                    tab.log.last().unwrap(),
                );
            }
        }
    }

    pub fn log_own_voice_channel(&mut self, channel: &str, duration_ms: u32, pcm: Vec<u8>) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        let crypto = self.channel_send_crypto(channel);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
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
                    failed: false,
                    sent_at: local_time_stamp(),
                    sent_at_utc: crate::client::export::utc_time_stamp(),
                    owed_receipt: None,
                    listened: true,
                    delivery: None,
                    crypto,
                },
            );
            if let Some(server_label) = &autosave {
                crate::client::export::autosave_entry(
                    server_label,
                    crate::client::export::Surface::Channel(channel),
                    tab.log.last().unwrap(),
                );
            }
        }
    }

    /// Called the instant our own recording starts (before we know its
    /// eventual duration/content), so the sender sees their own message
    /// appear live rather than only after they release Space - mirroring
    /// what the receiving side sees via `on_channel_stream_start`.
    pub fn log_own_voice_stream_start_channel(
        &mut self,
        channel: &str,
        stream_id: u64,
        delivery: Option<MessageDelivery>,
    ) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        let crypto = self.channel_send_crypto(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            // No autosave hook here: a `VoiceStreaming` placeholder has no
            // audio yet, and `autosave_entry` is a no-op for one anyway -
            // `on_channel_stream_finished`'s `finalize_stream_entry` call
            // is where this same row gets autosaved, once it is real.
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
                    failed: false,
                    sent_at: local_time_stamp(),
                    sent_at_utc: crate::client::export::utc_time_stamp(),
                    owed_receipt: None,
                    listened: true,
                    delivery,
                    crypto,
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
        suppress_playback: bool,
    ) {
        let entry = LogEntry {
            from,
            from_name,
            to_name: None,
            body: MessageBody::VoiceStreaming { stream_id },
            outgoing: false,
            failed: false,
            sent_at: local_time_stamp(),
            sent_at_utc: crate::client::export::utc_time_stamp(),
            owed_receipt: None,
            listened: !suppress_playback,
            delivery: None,
            crypto: self.message_crypto(from, false),
        };
        if self.is_trust_gated(from) {
            self.hold_message(from, Some(channel.to_string()), entry);
            return;
        }
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            // No autosave hook here either - see the sibling comment in
            // `log_own_voice_stream_start_channel` above.
            push_log_entry(&mut tab.log, &mut self.message_selected, is_current, entry);
            if !is_current {
                tab.unread = true;
            }
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
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            if let Some(entry) = finalize_stream_entry(&mut tab.log, from, stream_id, duration_ms, pcm.clone()) {
                if let Some(server_label) = &autosave {
                    crate::client::export::autosave_entry(
                        server_label,
                        crate::client::export::Surface::Channel(channel),
                        entry,
                    );
                }
                return;
            }
        }
        if let Some(held) = self.pending_messages.get_mut(&from) {
            finalize_held_stream(held, from, stream_id, duration_ms, pcm);
        }
    }

    /// Logs an outgoing entry of any body type (text, or a file send - see
    /// `crate::client::tui::file_send`) as our own, straight away rather than
    /// waiting for a server round-trip - the same optimistic-echo pattern
    /// `log_own_voice_channel` already uses for voice.
    /// `delivery` gives the row its indicator over the members this send
    /// was actually addressed to (`docs/PROTOCOL.md` 7.2.1) - build it with
    /// `UiState::start_delivery`. One row covers all of them, which is why
    /// a channel row has three states rather than two: nobody has
    /// acknowledged it, some have, or all have (`DeliveryStatus`). Every
    /// one of those sends carries the same id, so each recipient's receipt
    /// finds this same row (`UiState::mark_delivered`). `None` leaves the
    /// row untracked.
    pub(crate) fn push_outgoing_channel(
        &mut self,
        channel: &str,
        body: MessageBody,
        delivery: Option<MessageDelivery>,
    ) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        let crypto = self.channel_send_crypto(channel);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
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
                    failed: false,
                    sent_at: local_time_stamp(),
                    sent_at_utc: crate::client::export::utc_time_stamp(),
                    owed_receipt: None,
                    listened: true,
                    delivery,
                    crypto,
                },
            );
            if let Some(server_label) = &autosave {
                crate::client::export::autosave_entry(
                    server_label,
                    crate::client::export::Surface::Channel(channel),
                    tab.log.last().unwrap(),
                );
            }
        }
    }

    /// Creates the pending outgoing file-transfer row in the channel log,
    /// straight away (before any recipient's Accept/Reject response
    /// arrives) - mirrors `log_own_voice_stream_start_channel`'s "show it
    /// live" precedent, and its shape: **one** row for the whole send,
    /// with `delivery` naming every recipient it went out to, so the
    /// details popup lists them individually while the log stays one line.
    /// `stream_id` is the row's own identity, which every transfer behind
    /// it is registered against (`UiState::register_file_row_stream`);
    /// later progress/completion events find it again through that.
    pub fn log_own_file_offer_channel(
        &mut self,
        channel: &str,
        stream_id: u64,
        filename: String,
        total: u64,
        delivery: Option<MessageDelivery>,
    ) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_channel(channel);
        let crypto = self.channel_send_crypto(channel);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(
                &mut tab.log,
                &mut self.message_selected,
                is_current,
                LogEntry {
                    from,
                    from_name,
                    // Addressed to the channel, not to one person - the
                    // details popup is where the recipients are named.
                    to_name: None,
                    body: MessageBody::File {
                        filename,
                        total,
                        stream_id,
                        status: FileTransferStatus::Pending,
                    },
                    outgoing: true,
                    failed: false,
                    sent_at: local_time_stamp(),
                    sent_at_utc: crate::client::export::utc_time_stamp(),
                    owed_receipt: None,
                    listened: true,
                    delivery,
                    crypto,
                },
            );
            if let Some(server_label) = &autosave {
                crate::client::export::autosave_entry(
                    server_label,
                    crate::client::export::Surface::Channel(channel),
                    tab.log.last().unwrap(),
                );
            }
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
        let crypto = self.message_crypto(from, false);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
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
                    failed: false,
                    sent_at: local_time_stamp(),
                    sent_at_utc: crate::client::export::utc_time_stamp(),
                    owed_receipt: None,
                    listened: true,
                    delivery: None,
                    crypto,
                },
            );
            if !is_current {
                tab.unread = true;
            }
            if let Some(server_label) = &autosave {
                crate::client::export::autosave_entry(
                    server_label,
                    crate::client::export::Surface::Channel(channel),
                    tab.log.last().unwrap(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// The top row's two selectors and which of them is focused: the channel
/// one on the left, the DM one on the right - the latter absent entirely
/// until a room has been opened. Each names its own current selection,
/// adds a grey `+<n> more...` for everything else it holds, and blinks an
/// envelope while any of that has unseen messages (`docs/SPEC.md`
/// "Connected UI"). The envelope is left off the selector whose dropdown
/// is open, since it is then shown on the individual rows instead.
fn selector_titles(state: &UiState) -> (Vec<SelectorTitle>, usize) {
    let mut titles = vec![channel_selector_title(state)];
    if let Some(dm) = dm_selector_title(state) {
        titles.push(dm);
    }
    let selected = match state.selector_focus {
        SelectorFocus::Channels => 0,
        SelectorFocus::Dms => titles.len().saturating_sub(1),
    };
    (titles, selected)
}

/// One selector's row content, split by whether the focus highlight may
/// cover it. Only `name` - the entry the selector currently names - is
/// ever highlighted. Everything in `trailing` (the grey `+<n> more...`
/// count, then the blinking unread envelope) is deliberately left out of
/// it: reversing them paints a block of background behind text that is
/// meant to read as quiet, which comes out as a smear rather than a
/// marker.
struct SelectorTitle {
    name: Vec<Span<'static>>,
    trailing: Vec<Span<'static>>,
}

/// The whole selector row as one line, laid out exactly as the tab row has
/// always been - `\u{2423}<selector>\u{2423}\u{2502}\u{2423}<selector>\u{2423}` - together with each
/// selector's own start column, which is where its dropdown hangs from.
/// Built by hand rather than with `Tabs` for the reason `SelectorTitle`
/// gives: the focus highlight has to stop before the envelope.
fn selector_line(state: &UiState) -> (Line<'static>, Vec<u16>) {
    let (titles, selected) = selector_titles(state);
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut starts: Vec<u16> = Vec::new();
    let mut x: u16 = 0;
    let push = |spans: &mut Vec<Span<'static>>, x: &mut u16, span: Span<'static>| {
        *x += span.width() as u16;
        spans.push(span);
    };
    for (i, title) in titles.into_iter().enumerate() {
        push(
            &mut spans,
            &mut x,
            Span::raw(if i == 0 { " " } else { " \u{2502} " }),
        );
        starts.push(x);
        for span in title.name {
            let span = if i == selected {
                span.patch_style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                span
            };
            push(&mut spans, &mut x, span);
        }
        for span in title.trailing {
            push(&mut spans, &mut x, span);
        }
    }
    push(&mut spans, &mut x, Span::raw(" "));
    (Line::from(spans), starts)
}

fn channel_selector_title(state: &UiState) -> SelectorTitle {
    let name = match state.channels.get(state.selected_channel) {
        Some(c) => vec![Span::raw(channel_label(c.kind, &c.name))],
        // Every joined channel left behind (`/leave`): the selector keeps
        // the row's left slot, with nothing to name in it.
        None => vec![Span::styled(
            "no channel",
            Style::default().fg(Color::DarkGray),
        )],
    };
    let mut trailing = Vec::new();
    push_more_span(&mut trailing, state.channels.len());
    trailing.extend(envelope_spans(
        state,
        SelectorFocus::Channels,
        state.any_channel_unread(),
        // A channel is a room, not a person: there is no reachability to
        // colour its envelope by, so it says nothing about one - plain
        // white, where a DM's says who it is from.
        CHANNEL_UNREAD_COLOR,
    ));
    SelectorTitle { name, trailing }
}

/// `None` - i.e. no DM selector in the row at all - until a room has been
/// opened; there is nothing for it to name before that, and `]` from the
/// channel selector has nowhere to go.
fn dm_selector_title(state: &UiState) -> Option<SelectorTitle> {
    let peer = state.selected_dm?;
    let nickname = state.private_rooms.get(&peer)?.peer.name.clone();
    // The named peer carries the same presence colour their name has in
    // the channel sidebar (`presence_color`): an open DM is the one view
    // with no user list of its own, so without this the whole time a room
    // is open there is nothing on screen saying whether what is being
    // typed into it can actually get there.
    let presence = presence_color(state.presence_of(peer));
    // The pad tag sits directly after the nickname, before the quiet
    // count and the envelope: it is a fact about that person, not about
    // what else the selector is holding. Outside the focus highlight for
    // the reason `SelectorTitle` gives - reversing an emoji paints a block
    // behind it.
    let mut trailing = Vec::new();
    if state.is_otp_active(peer) {
        trailing.push(Span::raw(" "));
        trailing.push(Span::styled(
            OTP_TAG,
            Style::default().fg(OTP_TAG_COLOR),
        ));
    }
    push_more_span(&mut trailing, state.dm_order.len());
    // The envelope beside a person is that same colour, not the generic
    // unread yellow (`docs/SPEC.md` "Connected UI"): it blinks right next
    // to the nickname it belongs to, and two colours on one name read as
    // two separate facts rather than one person with unread messages.
    trailing.extend(envelope_spans(
        state,
        SelectorFocus::Dms,
        state.any_dm_unread(),
        presence,
    ));
    Some(SelectorTitle {
        name: vec![Span::styled(
            format!("{DM_ICON} {nickname}"),
            Style::default().fg(presence),
        )],
        trailing,
    })
}

/// The `+<n> more...` a selector carries for everything it holds besides
/// the one entry it names - nothing at all when it names the only one
/// there is. Always grey and never highlighted (see `SelectorTitle`): it
/// is a count of what is *not* on screen, and should read that way.
fn push_more_span(spans: &mut Vec<Span<'static>>, total: usize) {
    let others = total.saturating_sub(1);
    if others > 0 {
        spans.push(Span::styled(
            format!(" +{others} more..."),
            Style::default().fg(Color::DarkGray),
        ));
    }
}

/// One selector's blinking unread envelope, in `color` - the colour the
/// thing it stands for is already named in (`dm_selector_title` for why a
/// person's is their presence colour).
/// The colour a channel's unread envelope blinks in - plain white, for
/// the reason `channel_selector_title` gives. A DM's takes the peer's own
/// colour instead (`dm_selector_title`).
pub(crate) const CHANNEL_UNREAD_COLOR: Color = Color::White;

fn envelope_spans(
    state: &UiState,
    which: SelectorFocus,
    unread: bool,
    color: Color,
) -> Vec<Span<'static>> {
    let own_dropdown_open = state.selector_dropdown_open && state.selector_focus == which;
    if unread && !own_dropdown_open {
        vec![Span::styled(
            unread_envelope(state.blink_on),
            Style::default().fg(color),
        )]
    } else {
        Vec::new()
    }
}

/// How many rows the header block occupies: one blank line, the selectors
/// and status figures, one blank line - so the row reads as indented from
/// everything around it rather than pinned to the top edge
/// (`docs/SPEC.md` "Connected UI"). Its content is inset by
/// `HEADER_SIDE_PAD` columns on each side for the same reason.
pub const HEADER_ROW_HEIGHT: u16 = 3;

/// Which of `HEADER_ROW_HEIGHT`'s rows carries the text.
const HEADER_TEXT_ROW: u16 = 1;

const HEADER_SIDE_PAD: u16 = 1;

/// The folded-away call's own marker in the top row: `\u{23FA} Call` and the
/// `Ctrl+R` that brings its modal back, in a red-bordered box of its own
/// filling the header band's full height (`docs/SPEC.md` "Live voice
/// calls"). Only drawn while a call is on. The plain record-circle glyph
/// rather than a multicolour emoji, so its colour is always exactly the
/// `Style` it's painted with (`Color::Red`, below), never one fixed inside
/// the character itself. Blinks (`render_call_marker`'s `blink_on`) the
/// same way a live recording's own indicator does - a permanent, always-on
/// dot would read as decoration rather than as "something is live right
/// now".
const CALL_MARKER_DOT: &str = "\u{23FA}";
const CALL_MARKER_SUFFIX: &str = " Call";
const CALL_MARKER_KEY: &str = "Ctrl+R";

/// Its box's outer width: both labels, the space between them, one column
/// of padding each side, and the two border columns.
const CALL_MARKER_WIDTH: u16 = 18;

/// How much of the channel view's width the sidebar takes, and therefore
/// the column its message list starts at - the one the header's selectors
/// line up with (`server_state_width`).
pub const SIDEBAR_PERCENT: u16 = 20;

/// The column the message list starts at in a view `width` columns wide,
/// computed through the very same `Layout` the view itself is split with
/// so the two can never round apart by a column.
pub fn messages_start_col(width: u16) -> u16 {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(view_columns())
        .split(Rect {
            x: 0,
            y: 0,
            width,
            height: 1,
        })[1]
        .x
}

/// The channel view's own sidebar/messages split, named once so
/// `messages_start_col` measures exactly what `render_channel_view` draws.
fn view_columns() -> [Constraint; 2] {
    [
        Constraint::Percentage(SIDEBAR_PERCENT),
        Constraint::Percentage(100 - SIDEBAR_PERCENT),
    ]
}

/// How wide the header's server-state element is, given the header row's
/// own (already inset) width and the label that has to fit in it.
///
/// Normally the message list's start column, so the selectors beside it
/// begin exactly where the messages below them do. A label too long for
/// that - "Server down (reconnecting in 30 sec...)" on a narrow terminal -
/// pushes the selectors right instead of being cut off: a countdown that
/// has lost its number tells the user nothing, and the selectors moving is
/// the cheaper of the two costs.
fn server_state_width(area_width: u16, label_width: u16) -> u16 {
    messages_start_col(area_width)
        .saturating_sub(HEADER_SIDE_PAD)
        .max(label_width + 1)
}

/// The top row, shared by the channel view and an open DM room
/// (`direct_message::render_private_room`): the server-state element
/// first, then both selectors - starting where the message list below them
/// does - and flush right the red-bordered `\u{23FA} Call Ctrl+R` box while a
/// call is on (Escape folds the modal away into it, Ctrl+R brings it back),
/// then Conn quality, CPU usage and the help hint, in that order
/// (`docs/SPEC.md` "Connected UI").
pub(crate) fn render_header_row(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(line) = header_text_row(area) else {
        return;
    };
    let call_width = if state.call.is_some() {
        CALL_MARKER_WIDTH
    } else {
        0
    };
    // The status figures claim exactly what they need, plus one column of
    // gap, so the call box sits right against them however long
    // "Conn:NORMAL  CPU:100%  Ctrl+H: Help" happens to be this frame.
    let status = status_line(state);
    let status_width = status.width() as u16 + 1;
    let server_state = server_state_line(state);
    let server_state_width = server_state_width(area.width, server_state.width() as u16);
    let header_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(server_state_width),
            Constraint::Min(0),
            Constraint::Length(call_width),
            Constraint::Length(status_width),
        ])
        .split(line);

    frame.render_widget(Paragraph::new(server_state), header_cols[0]);
    let (selectors, _) = selector_line(state);
    frame.render_widget(Paragraph::new(selectors), header_cols[1]);

    if let Some(call) = &state.call {
        // The box is the one thing here that uses the whole three-row
        // band: its borders sit on the blank lines the selectors leave
        // above and below themselves.
        render_call_marker(
            frame,
            Rect {
                x: header_cols[2].x,
                y: area.y,
                width: header_cols[2].width,
                height: area.height.min(HEADER_ROW_HEIGHT),
            },
            state.blink_on,
            call.muted,
        );
    }

    frame.render_widget(
        Paragraph::new(status).alignment(ratatui::layout::Alignment::Right),
        header_cols[3],
    );
}

/// The header's first element: what the control connection is doing
/// (`crate::client::reconnect::ServerLinkState`), in the one colour that
/// state carries.
fn server_state_line(state: &UiState) -> Line<'static> {
    Line::from(Span::styled(
        state.server_link_label(),
        Style::default().fg(server_link_color(state.server_link)),
    ))
}

/// Colour for the header's server-state element: green connected, red
/// while anything is wrong with a server that is meant to be there, white
/// when there is deliberately none (`docs/SPEC.md` "Connected UI").
pub(crate) fn server_link_color(state: ServerLinkState) -> Color {
    match state {
        ServerLinkState::Connected => Color::Green,
        ServerLinkState::Reconnecting
        | ServerLinkState::RetryingIn { .. }
        | ServerLinkState::Down { .. } => Color::Red,
        ServerLinkState::NoServer => Color::White,
    }
}

/// Direct punching, Conn quality, CPU usage and the help hint, in that
/// order (`docs/SPEC.md` "Connected UI") - built up front so the row can be
/// laid out around its real width. The direct-punch element is the one
/// piece that's conditional: nothing is shown for it at all unless direct
/// punching is actually configured.
fn status_line(state: &UiState) -> Line<'static> {
    let mut spans = Vec::new();
    if state.unread_otp_mail_count > 0 {
        spans.push(Span::styled(
            format!(
                "{} {} unread OTP Mails",
                super::ui::unread_envelope(state.blink_on),
                state.unread_otp_mail_count
            ),
            Style::default().fg(Color::Yellow),
        ));
        spans.push(Span::raw("  "));
    }
    if let Some((active, total, next_in)) = state.direct_punch_status {
        let next = next_in
            .map(human_duration)
            .unwrap_or_else(|| "-".to_string());
        spans.push(Span::styled(
            format!("{active}/{total} direct punches, next try in {next} (Control+s)"),
            Style::default().fg(if active == total {
                Color::Green
            } else {
                Color::Yellow
            }),
        ));
        spans.push(Span::raw("  "));
    }
    spans.push(Span::styled(
        format!("Conn:{}", state.conn_quality.label()),
        Style::default().fg(conn_color(state.conn_quality)),
    ));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!("CPU:{}%", cpu_pct_rounded(state.cpu_usage_pct)),
        Style::default().fg(cpu_color(state.cpu_usage_pct)),
    ));
    spans.push(Span::raw("  "));
    spans.push(Span::styled("Ctrl+H: Help", Style::default().fg(Color::DarkGray)));
    Line::from(spans)
}

/// Renders a duration the way the status line names "next try in": whole
/// seconds under a minute, whole minutes under an hour, whole hours
/// beyond - the same granularity `docs/PROTOCOL.md` §7.1.5's slot grid
/// itself is expressed in, so it never claims more precision than the grid
/// actually has.
fn human_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

fn render_call_marker(frame: &mut Frame, area: Rect, blink_on: bool, self_muted: bool) {
    if area.width < 4 || area.height < 3 {
        return;
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    // Muted is a standing state, not an in-progress activity, so it never
    // blinks - it replaces the dot outright rather than alternating with it.
    let dot = if self_muted {
        "\u{1F507}"
    } else if blink_on {
        CALL_MARKER_DOT
    } else {
        " "
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{dot}{CALL_MARKER_SUFFIX}"),
                Style::default().fg(Color::Red),
            ),
            Span::raw(" "),
            Span::styled(CALL_MARKER_KEY, Style::default().fg(Color::DarkGray)),
        ]))
        .alignment(ratatui::layout::Alignment::Center),
        inner,
    );
}

/// The absolute column the header's two selectors begin at: past the
/// server-state element on their left, and inset by `HEADER_SIDE_PAD` like
/// the rest of the row.
///
/// The same figure `render_header_row`'s layout puts them at, and the one
/// each selector's own dropdown hangs from - measured through the very
/// same `server_state_width` so the row and the dropdown under it cannot
/// round apart by a column. `None` on a terminal too small to draw the
/// header at all, where there is no selector to hang anything from
/// either.
fn selectors_start_col(area: Rect, state: &UiState) -> Option<u16> {
    let line = header_text_row(area)?;
    let label_width = server_state_line(state).width() as u16;
    Some(line.x + server_state_width(area.width, label_width))
}

/// The one row of `area` the header's text sits on, already inset by
/// `HEADER_SIDE_PAD` on both sides. `None` on a terminal too small to hold
/// the block or too narrow to inset - nothing is drawn rather than drawn
/// crooked.
fn header_text_row(area: Rect) -> Option<Rect> {
    (area.height > HEADER_TEXT_ROW && area.width > 2 * HEADER_SIDE_PAD).then(|| Rect {
        x: area.x + HEADER_SIDE_PAD,
        y: area.y + HEADER_TEXT_ROW,
        width: area.width - 2 * HEADER_SIDE_PAD,
        height: 1,
    })
}

/// The focused selector's dropdown, hanging directly under it in the top
/// row: every entry that selector holds *except* the one it names, each
/// with its own blinking envelope if it has unseen messages. Up/Down move
/// the selection (and the view behind this overlay with it), Enter, Escape
/// or the opposite bracket close it.
pub(crate) fn render_selector_dropdown(frame: &mut Frame, area: Rect, state: &UiState) {
    let entries = state.selector_dropdown_entries();
    if entries.is_empty() || area.height <= HEADER_ROW_HEIGHT {
        return;
    }
    let rows: Vec<Line<'static>> = entries
        .iter()
        .map(|e| {
            // A DM row names a person, and is coloured by whether they can
            // be reached, exactly as the selector above it and the channel
            // sidebar are. A channel row has nobody to say that about.
            // Its envelope follows the row's own colour, exactly as the
            // selector above it does (`envelope_spans`).
            let color = e.presence.map(presence_color);
            let mut spans = vec![match color {
                Some(color) => Span::styled(e.label.clone(), Style::default().fg(color)),
                None => Span::raw(e.label.clone()),
            }];
            // The same pad tag the DM selector above carries, on the row
            // it belongs to (`UiState::encryption_tag`).
            if e.otp {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(OTP_TAG, Style::default().fg(OTP_TAG_COLOR)));
            }
            if e.unread {
                spans.push(Span::styled(
                    unread_envelope(state.blink_on),
                    Style::default().fg(color.unwrap_or(CHANNEL_UNREAD_COLOR)),
                ));
            }
            Line::from(spans)
        })
        .collect();

    // Hangs from the focused selector's own start column: where the
    // selectors begin on the row (`selectors_start_col`), plus that
    // selector's own offset within them (`selector_line` measures it).
    // Both parts matter - the row opens with the server-state element, so
    // a dropdown positioned from the offset alone lands at the screen's
    // left edge instead of under the selector it belongs to.
    let Some(selectors_x) = selectors_start_col(area, state) else {
        return;
    };
    let (_, starts) = selector_line(state);
    let (_, selected) = selector_titles(state);
    let x = selectors_x + starts.get(selected).copied().unwrap_or(0);
    let title = match state.selector_focus {
        SelectorFocus::Channels => "Channels",
        SelectorFocus::Dms => "DMs",
    };
    let content_width = rows
        .iter()
        .map(|r| r.width())
        .chain(std::iter::once(title.chars().count()))
        .max()
        .unwrap_or(0) as u16;
    let x = x.min(area.width.saturating_sub(1));
    let width = (content_width + 3).min(area.width - x);
    // Hangs off the bottom of the header block, so the blank line under
    // the selectors stays blank - and never past the bottom of the
    // screen, however many entries the selector holds. What does not fit
    // is scrolled to rather than cut off (see below).
    let height = ((rows.len() as u16) + 2).min(area.height - HEADER_ROW_HEIGHT);
    let popup = Rect {
        x,
        y: area.y + HEADER_ROW_HEIGHT,
        width,
        height,
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);

    // Scrolls exactly the way the message log does (`render_messages`):
    // a `ListState` whose selection ratatui keeps on screen, computing
    // the offset itself, and the rightmost column given up to a scrollbar
    // only while there is genuinely more list than viewport. A list that
    // merely stopped at the bottom edge would put every entry past it out
    // of reach - including, once Up/Down walked that far, the part of the
    // list the selection is moving through.
    //
    // Nothing is *highlighted*: the row kept in view marks where the
    // current selection was taken out of the list, not a row of it (see
    // `UiState::selector_dropdown_focus_row`), so the default (empty)
    // highlight style is what this list wants.
    let visible = inner.height as usize;
    let overflows = rows.len() > visible && inner.width > 1;
    let list_area = if overflows {
        Rect {
            width: inner.width - 1,
            ..inner
        }
    } else {
        inner
    };
    let total = rows.len();
    let mut list_state = ListState::default();
    list_state.select(Some(state.selector_dropdown_focus_row()));
    frame.render_stateful_widget(
        List::new(rows.into_iter().map(ListItem::new).collect::<Vec<_>>()),
        list_area,
        &mut list_state,
    );

    if overflows {
        let mut scrollbar_state = ScrollbarState::new(total - visible + 1)
            .viewport_content_length(visible)
            .position(list_state.offset());
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .track_symbol(Some("\u{2591}"))
                .thumb_symbol("\u{2588}")
                .track_style(Style::default().fg(Color::DarkGray))
                .thumb_style(Style::default().fg(Color::Gray)),
            Rect {
                x: inner.right() - 1,
                width: 1,
                ..inner
            },
            &mut scrollbar_state,
        );
    }
}

pub(crate) fn render_channel_view(frame: &mut Frame, area: Rect, state: &UiState) {
    let constraints = [
        Constraint::Length(HEADER_ROW_HEIGHT),
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

    render_header_row(frame, rows[tabs_row], state);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(view_columns())
        .split(rows[messages_row]);

    render_sidebar(frame, cols[0], state);
    render_messages(frame, cols[1], state, None);
    render_input_bar(frame, rows[input_row], state);
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

/// One colour per `presence::Presence` (`docs/SPEC.md` "Connected UI"),
/// shared by every place a person is named: the channel sidebar and the
/// top row's DM selector.
pub(crate) fn presence_color(presence: Presence) -> Color {
    match presence {
        // Not a reachability state at all: an unresolved or rejected
        // identity is the one thing here with something to *do* about it
        // (Enter opens the review), so it keeps a colour of its own.
        Presence::Unverified => Color::Red,
        // Reachability is a yes-or-no question, and the answer is all
        // anyone about to type needs: green once what is typed reaches
        // them, grey until it does. A punch in flight and a link that is
        // gone are the same answer - no - and giving each its own colour
        // only invites reading transport detail into a name
        // (`docs/SPEC.md` "Connected UI").
        Presence::Reachable => Color::Green,
        Presence::Offline | Presence::Connecting | Presence::Unreachable => Color::DarkGray,
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

/// Shown in place of an empty member list, and of an empty conversation,
/// while running with no server (`docs/PROTOCOL.md` §7.1.5). Without it a
/// perfectly-configured client that simply has not been punched into yet
/// is indistinguishable from a broken one - there is no roster arriving
/// from anywhere to fill the gap, and no presence notice to explain it.
pub(crate) const WAITING_FOR_DIRECT_PEERS: &str =
    "Waiting for other users to connect directly to you";

fn render_sidebar(frame: &mut Frame, area: Rect, state: &UiState) {
    let border_style = focus_border_style(state.focus == super::ui::Focus::Sidebar);
    let block = Block::default()
        .title("Users")
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    state
        .last_sidebar_area
        .store(super::ui::pack_rect(inner), std::sync::atomic::Ordering::Relaxed);

    let Some(channel) = state.channels.get(state.selected_channel) else {
        return;
    };
    let mut items: Vec<ListItem> = channel
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
            // The same glyph the selectors use (`UNREAD_ENVELOPE`), in a
            // fixed two-cell slot so a blink never shifts the name.
            let envelope = match room {
                Some(r) if r.unread && !state.blink_on => "  ".to_string(),
                Some(_) => format!("{UNREAD_ENVELOPE} "),
                None => String::new(),
            };
            // A muted voice (`/mute-voice`, docs/SPEC.md Functionality
            // #16) is otherwise completely invisible: their messages still
            // arrive and still log, they just never play. Without a marker
            // here, a channel that has gone quiet is indistinguishable
            // from one where nobody is talking.
            let muted = if state.is_voice_muted(m.id) {
                "\u{1F507} "
            } else {
                ""
            };
            // ☀️ marks this channel's admin; ⚡ marks a server superadmin,
            // in every channel alike - independent markers, both shown
            // together when they happen to be the same person.
            let superadmin = if state.is_superadmin(&m.name) {
                "\u{26A1} "
            } else {
                ""
            };
            let admin = if channel.admin.as_deref() == Some(m.name.as_str()) {
                "\u{2600}\u{FE0F} "
            } else {
                ""
            };
            // The person on the left, their encryption tag flush against
            // the sidebar's right edge (`docs/SPEC.md` "Connected UI") -
            // so the tags line up down one column and can be read as a
            // column, rather than starting wherever each nickname
            // happened to end. On a sidebar too narrow to hold both the
            // gap floors at one space and the row clips at its right
            // edge, exactly as an overlong entry always has.
            let name = format!("{superadmin}{admin}{muted}{envelope}{}", m.name);
            let tag = state.encryption_tag(m.id, m.key_mode);
            let gap = (inner.width as usize)
                .saturating_sub((display_width(&name) + display_width(tag)) as usize)
                .max(1);
            // The tag is the row's own colour - the direct-link state
            // below - except while a pad session is open, which is loud
            // enough to say in its own colour wherever it appears.
            let tag_style = if tag == OTP_TAG {
                Style::default().fg(OTP_TAG_COLOR)
            } else {
                Style::default()
            };
            let label = Line::from(vec![
                Span::raw(name),
                Span::raw(" ".repeat(gap)),
                Span::styled(tag, tag_style),
            ]);
            // A Pending/Rejected identity (docs/PROTOCOL.md §12) takes
            // priority over everything below - it's the most urgent,
            // actionable state (open the review popup via Enter), whether
            // or not they also happen to be offline or unreachable.
            // Offline members are otherwise only ever kept around because
            // there's DM history worth preserving (`on_user_offline`) -
            // shown in a soft gray, the same dim tone the help hint
            // already uses elsewhere in this screen.
            //
            // For everyone still connected, the colour is the state of the
            // *direct link* to them (§7.1), not merely their presence on
            // the server: green once messages can actually reach them, red
            // once they can't, yellow while the punch is still being
            // worked out. Presence alone would be the misleading thing to
            // show here - a peer can be perfectly online and completely
            // unreachable, which is exactly the case this is here to make
            // visible.
            let mut style = Style::default().fg(presence_color(state.presence_of(m.id)));
            if state.focus == super::ui::Focus::Sidebar && i == state.sidebar_selected {
                style = style.add_modifier(Modifier::REVERSED);
            }
            ListItem::new(label).style(style)
        })
        .collect();
    // Nobody here yet. With a server, an empty channel is simply empty and
    // says so by being blank; with none, it is a channel waiting to be
    // punched into - which is a state worth naming, since otherwise a
    // correctly-configured client that is merely early looks broken.
    //
    // Checked against the real roster, before our own row (always added
    // below) would otherwise make this look non-empty.
    if items.is_empty() && state.serverless {
        frame.render_widget(
            Paragraph::new(WAITING_FOR_DIRECT_PEERS)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }
    // Our own row, always last - so every real member keeps the same index
    // it already had (what `handle_sidebar_key`, and every test that seeks
    // a member by index, already assume). Not a real `UserInfo` (we have no
    // direct link, encryption tag or presence to report about ourselves),
    // so it is built here rather than folded into `channel.members` -
    // `handle_sidebar_key`'s Enter arm treats this last index the same way,
    // as a no-op rather than opening a DM with ourselves. The name is
    // always green (`Presence::Reachable`'s colour) - you are always
    // reachable to yourself - with `(me)` trailing in gray regardless, so
    // it never reads as part of whatever colour the name itself happens to
    // be.
    let own_index = channel.members.len();
    let mut own_style =
        Style::default().fg(presence_color(crate::client::presence::Presence::Reachable));
    if state.focus == super::ui::Focus::Sidebar && state.sidebar_selected == own_index {
        own_style = own_style.add_modifier(Modifier::REVERSED);
    }
    let own_label = Line::from(vec![
        Span::raw(state.own_name.clone()),
        Span::styled(" (me)", Style::default().fg(Color::DarkGray)),
    ]);
    items.push(ListItem::new(own_label).style(own_style));
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
    frame.render_widget(ratatui::widgets::Clear, popup);
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

/// `/channels`' modal directory of every public channel the server has
/// announced (`UiState::known_channels`). A channel the user is already
/// joined to is drawn yellow, so "where am I" and "where could I go" read
/// off the same list; the selected row is reversed. Up/Down move, Enter
/// joins, Esc closes (`handle_channels_popup_key`).
pub(crate) fn render_channels_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let rows: Vec<ListItem> = state
        .known_channels
        .iter()
        .enumerate()
        .map(|(i, info)| {
            let mut style = if state.is_joined(&info.name) {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            if i == state.channels_popup_selected {
                style = style.add_modifier(Modifier::REVERSED);
            }
            ListItem::new(Line::from(Span::styled(info.name.clone(), style)))
        })
        .collect();
    let height = (rows.len().max(1) as u16).saturating_add(2);
    let popup = super::ui::centered_rect(44, height, area);
    let block = Block::default()
        .title("Public channels (Enter to join, Esc to close)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(block, popup);
    if rows.is_empty() {
        frame.render_widget(Paragraph::new("no public channels announced yet"), inner);
        return;
    }
    // `ListState` (same reason `render_file_browser` uses one) so a
    // selection past the bottom of a long directory scrolls into view
    // instead of being clipped.
    let mut list_state = ratatui::widgets::ListState::default();
    list_state.select(Some(state.channels_popup_selected.min(rows.len() - 1)));
    frame.render_stateful_widget(List::new(rows), inner, &mut list_state);
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
    frame.render_widget(ratatui::widgets::Clear, popup);
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
