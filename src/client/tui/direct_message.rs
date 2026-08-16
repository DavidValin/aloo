//! Private-room (DM) state and rendering: the `PrivateRoom` log model and
//! the full-screen private-room view. Shared/mixed UI plumbing (`UiState`
//! itself, `Focus`, `Mode`, message-log rendering, the input bar, ...)
//! stays in `crate::client::tui::ui`; channel-tab state/rendering is the mirror
//! image in `crate::client::tui::channel`.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};

use crate::proto::{KeyMode, UserId, UserInfo};

use super::ui::{
    FileTransferStatus, Focus, LogEntry, MessageBody, UiState, finalize_held_stream,
    finalize_stream_entry, push_log_entry, render_input_bar, render_messages,
};

#[derive(Debug, Clone)]
pub struct PrivateRoom {
    pub peer: UserInfo,
    pub log: Vec<LogEntry>,
    pub unread: bool,
}

impl UiState {
    /// Whether the currently-open private room's peer is offline - gates
    /// the compose bar (`handle_input_key`) and its rendering
    /// (`render_input_bar`). `false` whenever no private room is open, so
    /// callers don't need to check `active_private_room` separately.
    pub(crate) fn active_dm_peer_offline(&self) -> bool {
        self.active_private_room
            .map(|id| self.offline.contains(&id))
            .unwrap_or(false)
    }

    /// Whether the currently-open private room's peer has a Pending/Rejected
    /// identity review (`docs/PROTOCOL.md` §12) - same gating role as
    /// `active_dm_peer_offline`, for a room that was already open before the
    /// mismatch arrived (normal navigation can no longer open a new one).
    pub(crate) fn active_dm_peer_trust_gated(&self) -> bool {
        self.active_private_room
            .map(|id| self.is_trust_gated(id))
            .unwrap_or(false)
    }

    pub(crate) fn open_private_room(&mut self, peer: UserInfo) {
        let id = peer.id;
        self.known_users.insert(id, peer.clone());
        let room = self.private_rooms.entry(id).or_insert_with(|| PrivateRoom {
            peer: peer.clone(),
            log: Vec::new(),
            unread: false,
        });
        room.peer = peer;
        room.unread = false;
        let log_len = room.log.len();
        self.active_private_room = Some(id);
        // Start scrolled to the newest message, like opening any chat app -
        // not stuck at the oldest one.
        self.message_selected = log_len.saturating_sub(1);
        self.focus = Focus::Input;
    }

    /// Whether the private room with `peer` is the one currently open.
    fn is_viewing_dm(&self, peer: UserId) -> bool {
        self.active_private_room == Some(peer)
    }

    pub fn on_direct_message(&mut self, from: UserId, from_name: String, body: MessageBody) {
        let entry = LogEntry {
            from,
            from_name: from_name.clone(),
            to_name: None,
            body,
            outgoing: false,
        };
        // Same hold-and-reveal treatment as a channel message
        // (docs/PROTOCOL.md §12) - decrypts fine (our own key), but not
        // shown until `from` is Accepted. The room still isn't created yet
        // in this case (nothing to open it for until there's a real,
        // revealed message in it).
        if self.is_trust_gated(from) {
            self.hold_message(from, None, entry);
            return;
        }
        let unread = self.active_private_room != Some(from);
        let is_current = self.is_viewing_dm(from);
        let fallback_peer = self
            .known_users
            .get(&from)
            .cloned()
            .unwrap_or_else(|| UserInfo {
                id: from,
                name: from_name.clone(),
                public_key_der: Vec::new(),
                key_mode: KeyMode::None,
            });
        let room = self
            .private_rooms
            .entry(from)
            .or_insert_with(|| PrivateRoom {
                peer: fallback_peer,
                log: Vec::new(),
                unread: false,
            });
        push_log_entry(&mut room.log, &mut self.message_selected, is_current, entry);
        if unread {
            room.unread = true;
        }
    }

    pub fn log_own_voice_dm(&mut self, to: UserId, duration_ms: u32, pcm: Vec<u8>) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_dm(to);
        if let Some(room) = self.private_rooms.get_mut(&to) {
            push_log_entry(
                &mut room.log,
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

    pub fn log_own_voice_stream_start_dm(&mut self, to: UserId, stream_id: u64) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_dm(to);
        if let Some(room) = self.private_rooms.get_mut(&to) {
            push_log_entry(
                &mut room.log,
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

    pub fn on_direct_stream_start(
        &mut self,
        peer_id: UserId,
        from: UserId,
        from_name: String,
        stream_id: u64,
    ) {
        let entry = LogEntry {
            from,
            from_name: from_name.clone(),
            to_name: None,
            body: MessageBody::VoiceStreaming { stream_id },
            outgoing: false,
        };
        if self.is_trust_gated(peer_id) {
            self.hold_message(peer_id, None, entry);
            return;
        }
        let unread = self.active_private_room != Some(peer_id);
        let is_current = self.is_viewing_dm(peer_id);
        let fallback_peer = self
            .known_users
            .get(&peer_id)
            .cloned()
            .unwrap_or_else(|| UserInfo {
                id: peer_id,
                name: from_name.clone(),
                public_key_der: Vec::new(),
                key_mode: KeyMode::None,
            });
        let room = self
            .private_rooms
            .entry(peer_id)
            .or_insert_with(|| PrivateRoom {
                peer: fallback_peer,
                log: Vec::new(),
                unread: false,
            });
        push_log_entry(&mut room.log, &mut self.message_selected, is_current, entry);
        if unread {
            room.unread = true;
        }
    }

    /// Checks the visible room's log first, then the held buffer
    /// (`docs/PROTOCOL.md` §12) - `on_direct_stream_start` may have placed
    /// the placeholder in either, depending on the peer's trust state at
    /// the time the stream started.
    pub fn on_direct_stream_finished(
        &mut self,
        peer_id: UserId,
        from: UserId,
        stream_id: u64,
        duration_ms: u32,
        pcm: Vec<u8>,
    ) {
        if let Some(room) = self.private_rooms.get_mut(&peer_id)
            && finalize_stream_entry(&mut room.log, from, stream_id, duration_ms, pcm.clone())
        {
            return;
        }
        if let Some(held) = self.pending_messages.get_mut(&peer_id) {
            finalize_held_stream(held, from, stream_id, duration_ms, pcm);
        }
    }

    /// `push_outgoing_channel`'s DM counterpart - see there for why this
    /// takes a `MessageBody` rather than just `String` text.
    pub(crate) fn push_outgoing_dm(&mut self, to: UserId, body: MessageBody) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_dm(to);
        if let Some(room) = self.private_rooms.get_mut(&to) {
            push_log_entry(
                &mut room.log,
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

    /// DM counterpart of `channel::log_own_file_offer_channel` - a DM room
    /// only ever has one recipient, so there's nothing for `to_name` to
    /// name (the room itself already does).
    pub fn log_own_file_offer_dm(
        &mut self,
        to: UserId,
        stream_id: u64,
        filename: String,
        total: u64,
    ) {
        let from = self.own_id.unwrap_or(UserId(0));
        let from_name = self.own_name.clone();
        let is_current = self.is_viewing_dm(to);
        if let Some(room) = self.private_rooms.get_mut(&to) {
            push_log_entry(
                &mut room.log,
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
                        status: FileTransferStatus::Pending,
                    },
                    outgoing: true,
                },
            );
        }
    }

    /// DM counterpart of `channel::on_channel_file_offer_accepted`.
    pub fn on_direct_file_offer_accepted(
        &mut self,
        from: UserId,
        from_name: String,
        stream_id: u64,
        filename: String,
        total: u64,
    ) {
        let unread = self.active_private_room != Some(from);
        let is_current = self.is_viewing_dm(from);
        let fallback_peer = self
            .known_users
            .get(&from)
            .cloned()
            .unwrap_or_else(|| UserInfo {
                id: from,
                name: from_name.clone(),
                public_key_der: Vec::new(),
                key_mode: KeyMode::None,
            });
        let room = self
            .private_rooms
            .entry(from)
            .or_insert_with(|| PrivateRoom {
                peer: fallback_peer,
                log: Vec::new(),
                unread: false,
            });
        push_log_entry(
            &mut room.log,
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
        if unread {
            room.unread = true;
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_private_room(frame: &mut Frame, area: Rect, state: &UiState, peer_id: UserId) {
    let constraints = [Constraint::Min(3), Constraint::Length(3)];
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);
    render_messages(frame, rows[0], state, Some(peer_id));
    render_input_bar(frame, rows[1], state);
}
