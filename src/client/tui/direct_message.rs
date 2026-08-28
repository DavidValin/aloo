//! Private-room (DM) state and rendering: the `PrivateRoom` log model, the
//! rooms the top row's DM selector names, and the private-room view. Shared/mixed UI plumbing (`UiState`
//! itself, `Focus`, `Mode`, message-log rendering, the input bar, ...)
//! stays in `crate::client::tui::ui`; channel-tab state/rendering is the mirror
//! image in `crate::client::tui::channel`.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::proto::{UserId, UserInfo};

use super::ui::{
    FileTransferStatus, Focus, LogEntry, MessageBody, MessageCrypto, MessageDelivery, UiState,
    Unread, finalize_held_stream, finalize_stream_entry, render_input_bar, render_messages,
};

#[derive(Debug, Clone)]
pub struct PrivateRoom {
    pub peer: UserInfo,
    pub log: Vec<LogEntry>,
    /// Whether something has landed here since this room was last on
    /// screen - what makes the DM selector's envelope blink, and the
    /// sidebar's next to the peer (`docs/SPEC.md` "Connected UI").
    /// Cleared the moment the room is selected again (`select_dm`).
    pub unread: bool,
    /// `resume_from_log`'s reader for this DM's `.log` file - see
    /// `ChannelTab::history_cursor`'s doc, same lifetime/meaning.
    pub history_cursor: Option<crate::client::export::LogHistoryCursor>,
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

    /// The one way a `PrivateRoom` is ever created - every caller that
    /// needs a room to write into goes through here, which is what keeps
    /// `dm_order` (the DM selector's stable order) in step with
    /// `private_rooms`. `fallback` is only used if the room is new; an
    /// existing one keeps whatever `peer` it already had. Deliberately
    /// returns nothing: callers pair it with their own
    /// `private_rooms.get_mut(..)` so they can still borrow
    /// `message_selected` alongside the room (disjoint fields).
    pub(crate) fn ensure_private_room(&mut self, peer: UserId, fallback: UserInfo) {
        if self.private_rooms.contains_key(&peer) {
            return;
        }
        self.private_rooms.insert(
            peer,
            PrivateRoom {
                peer: fallback,
                log: Vec::new(),
                unread: false,
                history_cursor: None,
            },
        );
        self.dm_order.push(peer);
        // The DM selector appears with the very first room and names it
        // from then on. A later room only becomes the named one when the
        // user actually goes to it - an incoming message never yanks the
        // selector off whatever it was showing; it raises that room's
        // envelope instead.
        if self.selected_dm.is_none() {
            self.selected_dm = Some(peer);
        }
    }

    /// Makes `peer`'s room the one the DM selector names and the view on
    /// screen, marking it read - the DM half of `select_channel_at`.
    /// Starts scrolled to the newest message, like opening any chat app,
    /// rather than wherever the last visit left off.
    pub(crate) fn select_dm(&mut self, peer: UserId) {
        self.selected_dm = Some(peer);
        self.active_private_room = Some(peer);
        self.focus = Focus::Input;
        let needs_initial_history = self.resume_from_log
            && self.private_rooms.get(&peer).is_some_and(|r| r.history_cursor.is_none());
        if let Some(room) = self.private_rooms.get_mut(&peer) {
            room.unread = false;
        }
        // Same "first viewing only" guard as `select_channel_at` - see its
        // doc for why a plain revisit must not trigger this too.
        if needs_initial_history {
            self.load_history_chunk();
        }
        let log_len = self.private_rooms.get(&peer).map(|r| r.log.len()).unwrap_or(0);
        self.message_selected = log_len.saturating_sub(1);
    }

    /// Enter on a sidebar user: opens (creating if needed) their room and
    /// moves the top row's focus onto the DM selector, which names it from
    /// then on - `[` goes back to the channel selector, and the room stays
    /// on the DM one either way.
    pub fn open_private_room(&mut self, peer: UserInfo) {
        let id = peer.id;
        self.known_users.insert(id, peer.clone());
        self.ensure_private_room(id, peer.clone());
        if let Some(room) = self.private_rooms.get_mut(&id) {
            room.peer = peer;
        }
        self.selected_dm = Some(id);
        self.focus_dm_selector();
    }

    /// Whether the private room with `peer` is the one currently open.
    pub(crate) fn is_viewing_dm(&self, peer: UserId) -> bool {
        self.active_private_room == Some(peer)
    }

    pub fn on_direct_message(&mut self, from: UserId, from_name: String, body: MessageBody) {
        self.push_incoming_dm(from, from_name, body, true);
    }

    /// `on_direct_message`'s counterpart for a `MessageBody::Voice` that
    /// arrived already fully decrypted rather than through
    /// `on_direct_stream_start`/`on_direct_stream_finished` - OTP voice
    /// never live-streams (docs/PROTOCOL.md §16), so there is no per-chunk
    /// mixer push to gate; the caller (`otp::finish_incoming_file`) decides
    /// `listened` up front the same way `on_direct_stream_start` derives it
    /// from `suppress_playback` for a live pq_hybrid stream, and has
    /// already pushed the clip to the mixer itself when `listened` is
    /// `true`.
    pub fn on_direct_voice_message(
        &mut self,
        from: UserId,
        from_name: String,
        duration_ms: u32,
        pcm: Vec<u8>,
        listened: bool,
    ) {
        self.push_incoming_dm(
            from,
            from_name,
            MessageBody::Voice { duration_ms, pcm },
            listened,
        );
    }

    fn push_incoming_dm(
        &mut self,
        from: UserId,
        from_name: String,
        body: MessageBody,
        listened: bool,
    ) {
        let entry = LogEntry::incoming(from, from_name.clone(), body, self.message_crypto(from, false))
            .with_listened(listened);
        // Same hold-and-reveal treatment as a channel message
        // (docs/PROTOCOL.md §12) - decrypts fine (our own key), but not
        // shown until `from` is Accepted. The room still isn't created yet
        // in this case (nothing to open it for until there's a real,
        // revealed message in it).
        if self.is_trust_gated(from) {
            self.hold_message(from, None, entry);
            return;
        }
        let fallback_peer = self.peer_or_fallback(from, &from_name);
        self.ensure_private_room(from, fallback_peer);
        self.append_to_dm(from, &from_name, entry, Unread::Mark);
    }

    /// The name of the peer whose DM room `to` names, if that room is
    /// open. `None` when it is not - and every `log_own_*_dm` below
    /// returns silently on that, because a row for a room that does not
    /// exist has nowhere to be shown.
    fn dm_peer_name(&self, to: UserId) -> Option<String> {
        self.private_rooms.get(&to).map(|r| r.peer.name.clone())
    }

    pub fn log_own_voice_dm(&mut self, to: UserId, duration_ms: u32, pcm: Vec<u8>) {
        let Some(peer_name) = self.dm_peer_name(to) else {
            return;
        };
        let entry = LogEntry::outgoing(
            self.own_id.unwrap_or(UserId(0)),
            self.own_name.clone(),
            MessageBody::Voice { duration_ms, pcm },
            None,
            self.message_crypto(to, true),
        );
        self.append_to_dm(to, &peer_name, entry, Unread::Leave);
    }

    pub fn log_own_voice_stream_start_dm(
        &mut self,
        to: UserId,
        stream_id: u64,
        delivery: Option<MessageDelivery>,
    ) {
        let Some(peer_name) = self.dm_peer_name(to) else {
            return;
        };
        // The autosave is a no-op for a `VoiceStreaming` placeholder - see
        // the sibling note in `channel::log_own_voice_stream_start_channel`.
        let entry = LogEntry::outgoing(
            self.own_id.unwrap_or(UserId(0)),
            self.own_name.clone(),
            MessageBody::VoiceStreaming { stream_id },
            delivery,
            self.message_crypto(to, true),
        );
        self.append_to_dm(to, &peer_name, entry, Unread::Leave);
    }

    pub fn on_direct_stream_start(
        &mut self,
        peer_id: UserId,
        from: UserId,
        from_name: String,
        stream_id: u64,
        suppress_playback: bool,
    ) {
        let entry = LogEntry::incoming(
            from,
            from_name.clone(),
            MessageBody::VoiceStreaming { stream_id },
            self.message_crypto(from, false),
        )
        .with_listened(!suppress_playback);
        if self.is_trust_gated(peer_id) {
            self.hold_message(peer_id, None, entry);
            return;
        }
        let fallback_peer = self.peer_or_fallback(peer_id, &from_name);
        self.ensure_private_room(peer_id, fallback_peer);
        // The autosave is a no-op for a `VoiceStreaming` placeholder - see
        // the sibling note in `channel::log_own_voice_stream_start_channel`.
        let peer_name = self
            .private_rooms
            .get(&peer_id)
            .map(|r| r.peer.name.clone())
            .unwrap_or_default();
        self.append_to_dm(peer_id, &peer_name, entry, Unread::Mark);
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
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        if let Some(room) = self.private_rooms.get_mut(&peer_id) {
            let peer_name = room.peer.name.clone();
            if let Some(entry) = finalize_stream_entry(&mut room.log, from, stream_id, duration_ms, pcm.clone()) {
                if let Some(server_label) = &autosave {
                    crate::client::export::autosave_entry(
                        server_label,
                        crate::client::export::Surface::Dm(&peer_name),
                        entry,
                    );
                }
                return;
            }
        }
        if let Some(held) = self.pending_messages.get_mut(&peer_id) {
            finalize_held_stream(held, from, stream_id, duration_ms, pcm);
        }
    }

    /// Logs an app-generated line (`MessageBody::System`) into `peer`'s DM
    /// room - currently only the OTP layer's own errors/confirmations
    /// (`client::otp::notify`), mirroring the same text already shown in
    /// the top-right status notice so it survives in the conversation's own
    /// history after that notice clears. Creates the room if it doesn't
    /// exist yet (a peer can otherwise-silently propose or fail an OTP
    /// session before the user has ever opened a DM with them), same as
    /// `on_direct_message`.
    pub fn push_otp_system_message(&mut self, peer: UserId, peer_name: &str, text: String) {
        let fallback_peer = self.peer_or_fallback(peer, peer_name);
        self.ensure_private_room(peer, fallback_peer);
        let entry = LogEntry::system(peer, peer_name.to_string(), text);
        self.append_to_dm(peer, peer_name, entry, Unread::Mark);
    }

    /// `push_outgoing_channel`'s DM counterpart - see there for why this
    /// takes a `MessageBody` rather than just `String` text.
    /// Returns the index this entry landed at in `to`'s room log - the
    /// room's log is append-only (nothing ever inserts/removes into the
    /// middle of it), so that index stays a valid, stable way to find this
    /// exact row again later, e.g. to mark it failed
    /// (`mark_dm_message_failed`) once an async send outcome comes back.
    /// `None` only if the room doesn't exist yet, which shouldn't happen
    /// for a room the compose bar was just used in.
    /// `delivery` gives the row its indicator (`docs/PROTOCOL.md` 7.2.1) -
    /// build it with `UiState::start_delivery`, whose id the send itself
    /// must carry so the recipient's receipt finds this exact row again
    /// (`UiState::mark_delivered`). `None` leaves the row untracked, which
    /// is what an outgoing row with nothing to report wants.
    pub fn push_outgoing_dm(
        &mut self,
        to: UserId,
        body: MessageBody,
        delivery: Option<MessageDelivery>,
    ) -> Option<usize> {
        let peer_name = self.private_rooms.get(&to)?.peer.name.clone();
        let entry = LogEntry::outgoing(
            self.own_id.unwrap_or(UserId(0)),
            self.own_name.clone(),
            body,
            delivery,
            self.message_crypto(to, true),
        );
        self.append_to_dm(to, &peer_name, entry, Unread::Leave)
    }

    /// Marks the log row at `log_index` in `peer`'s room failed (rendered
    /// in red - `render_messages`) - the async-send-failed counterpart of
    /// `push_outgoing_dm`'s optimistic log write. A no-op if the room or
    /// that row no longer exists (defensive only; the log is append-only,
    /// so in practice both always still exist).
    pub fn mark_dm_message_failed(&mut self, peer: UserId, log_index: usize) {
        if let Some(room) = self.private_rooms.get_mut(&peer)
            && let Some(entry) = room.log.get_mut(log_index)
        {
            entry.failed = true;
        }
    }

    /// Corrects the log row at `log_index` in `peer`'s room to the crypto
    /// scheme actually used, once the send path has genuinely decided and
    /// performed it (`client::otp::send_now`, `client::direct_message::handle_send_text`'s
    /// plain-envelope branch) - the async-decision counterpart of
    /// `mark_dm_message_failed`.
    ///
    /// `push_outgoing_dm` stamps a row's `crypto` synchronously, on the UI
    /// thread, the instant Enter is pressed - from `is_otp_active` *at that
    /// exact moment*. The real encryption path is decided later, once the
    /// queued send action actually reaches the session task
    /// (`otp::contact_name_for_sending`, re-checking `is_otp_active` fresh).
    /// Between those two moments a session can genuinely start or end, so
    /// the two checks can disagree: a message typed the instant a session
    /// resumes could be logged as sent under `pq_hybrid` while actually
    /// sent, correctly, under the pad - or the reverse. Real remote round
    /// trips (the confirmation that flips `is_otp_active`) widen this
    /// window far past what a loopback test ever shows; this call is what
    /// makes the row's own label agree with what genuinely went out, no
    /// matter which way the race fell.
    pub fn set_dm_message_crypto(
        &mut self,
        peer: UserId,
        log_index: usize,
        crypto: Option<MessageCrypto>,
    ) {
        if let Some(room) = self.private_rooms.get_mut(&peer)
            && let Some(entry) = room.log.get_mut(log_index)
        {
            entry.crypto = crypto;
        }
    }

    /// DM counterpart of `channel::log_own_file_offer_channel` - a DM room
    /// only ever has one recipient, which the room itself already names.
    pub fn log_own_file_offer_dm(
        &mut self,
        to: UserId,
        stream_id: u64,
        filename: String,
        total: u64,
        delivery: Option<MessageDelivery>,
    ) {
        let Some(peer_name) = self.dm_peer_name(to) else {
            return;
        };
        let entry = LogEntry::outgoing(
            self.own_id.unwrap_or(UserId(0)),
            self.own_name.clone(),
            MessageBody::File {
                filename,
                total,
                stream_id,
                status: FileTransferStatus::Pending,
            },
            delivery,
            self.message_crypto(to, true),
        );
        self.append_to_dm(to, &peer_name, entry, Unread::Leave);
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
        let entry = LogEntry::incoming(
            from,
            from_name.clone(),
            MessageBody::File {
                filename,
                total,
                stream_id,
                status: FileTransferStatus::InProgress { bytes: 0 },
            },
            self.message_crypto(from, false),
        );
        let fallback_peer = self.peer_or_fallback(from, &from_name);
        self.ensure_private_room(from, fallback_peer);
        self.append_to_dm(from, &from_name, entry, Unread::Mark);
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// A room is reached through the top row's DM selector, so the row itself
/// is drawn here exactly as the channel view draws it
/// (`channel::render_header_row`) - the user can see where they are, and
/// `[` takes them back to the channel selector. There is no sidebar: the
/// conversation has exactly one other person in it.
pub(crate) fn render_private_room(frame: &mut Frame, area: Rect, state: &UiState, peer_id: UserId) {
    let show_otp_header = state.is_otp_active(peer_id);
    let mut constraints = vec![Constraint::Length(
        crate::client::tui::channel::HEADER_ROW_HEIGHT,
    )];
    if show_otp_header {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Min(3));
    constraints.push(Constraint::Length(3));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    super::channel::render_header_row(frame, rows[0], state);
    let mut idx = 1;
    if show_otp_header {
        render_otp_header(frame, rows[idx], state, peer_id);
        idx += 1;
    }
    render_messages(frame, rows[idx], state, Some(peer_id));
    render_input_bar(frame, rows[idx + 1], state);
}

/// Below this many remaining bytes (0.5MB) a direction's key figure is
/// rendered in red instead of green - the same "running low" line the pad
/// itself has no concept of (it just refuses once truly empty), surfaced
/// here so the user sees it coming. Also what the contacts list's own OTP
/// columns use (`client::tui::contacts`), so a contact's remaining-key
/// figure reads exactly the same everywhere it appears.
pub(crate) const OTP_KEY_LOW_THRESHOLD_BYTES: u64 = 512 * 1024;

/// `<seq> <offset> <remaining>MB` - `remaining` on its own since only that
/// figure gets the red/green threshold color; `seq`/`offset` are always
/// grey. `pub(crate)` so the contacts list (`client::tui::contacts`) can
/// render the exact same figures the same way.
pub(crate) fn push_otp_key_spans(
    spans: &mut Vec<Span<'static>>,
    seq: u64,
    offset: u64,
    remaining_bytes: u64,
) {
    spans.push(Span::styled(
        format!("{seq} {offset} "),
        Style::default().fg(Color::Gray),
    ));
    let remaining_color = if remaining_bytes < OTP_KEY_LOW_THRESHOLD_BYTES {
        Color::Red
    } else {
        Color::Green
    };
    spans.push(Span::styled(
        format!("{:.2}MB", remaining_bytes as f64 / (1024.0 * 1024.0)),
        Style::default().fg(remaining_color),
    ));
}

/// The 1-line OTP session header shown above the message log while this
/// peer's session is active (`UiState::is_otp_active`) - see
/// `UiState::otp_key_status`'s doc for how its figures stay live.
fn render_otp_header(frame: &mut Frame, area: Rect, state: &UiState, peer_id: UserId) {
    let nickname = state
        .known_users
        .get(&peer_id)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let detail = state
        .otp_key_status_for(peer_id)
        .map(|s| s.detail.clone())
        .unwrap_or_default();

    let mut spans = vec![
        Span::styled(
            "OTP SESSION",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" with "),
        Span::styled(nickname, Style::default().fg(Color::Yellow)),
        Span::raw(" - Receive Key (dec): "),
    ];
    push_otp_key_spans(
        &mut spans,
        detail.dec_sequence,
        detail.dec_offset,
        detail.dec_key_remaining,
    );
    spans.push(Span::raw(" - Send Key (enc): "));
    push_otp_key_spans(
        &mut spans,
        detail.enc_sequence,
        detail.enc_offset,
        detail.enc_key_remaining,
    );

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
