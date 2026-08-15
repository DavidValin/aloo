//! Channel-tab state and rendering: the `ChannelTab` log/membership model,
//! dwell-to-join tab switching, and the channel view / sidebar / Ctrl+J
//! popup rendering. Shared/mixed UI plumbing (`UiState` itself, `Focus`,
//! `Mode`, message-log rendering, the input bar, ...) stays in
//! `crate::ui::ui`; DM-room state/rendering is the mirror image in
//! `crate::ui::direct_message`.

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Tabs};
use ratatui::Frame;

use crate::netstats::ConnQuality;
use crate::proto::{ChannelInfo, ChannelKind, UserId, UserInfo};
use crate::sysstats::CPU_HEALTHY_MAX_PCT;

use super::ui::{
    finalize_held_stream, finalize_stream_entry, focus_border_style, push_log_entry, render_input_bar,
    render_messages, LogEntry, MessageBody, Mode, UiAction, UiState,
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
    pub members: Vec<UserInfo>,
    pub log: Vec<LogEntry>,
}

pub(crate) struct DwellState {
    pub(crate) target_index: usize,
    pub(crate) started_at: Instant,
}

impl UiState {
    pub(crate) fn handle_join_popup_key(&mut self, code: KeyCode) -> Option<UiAction> {
        match code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.join_popup_input.clear();
                None
            }
            KeyCode::Enter => {
                let name = self.join_popup_input.trim().to_string();
                self.mode = Mode::Normal;
                self.join_popup_input.clear();
                if name.is_empty() {
                    None
                } else {
                    Some(UiAction::JoinChannel { name, kind: ChannelKind::Private })
                }
            }
            KeyCode::Backspace => {
                self.join_popup_input.pop();
                None
            }
            KeyCode::Char(c) => {
                self.join_popup_input.push(c);
                None
            }
            _ => None,
        }
    }

    /// Excludes ourselves, any offline member (kept in `channel.members`
    /// only so the sidebar can still show their grayed-out history entry -
    /// they have no live connection to actually deliver a message to), and
    /// any member whose identity is `Pending`/`Rejected` review
    /// (`docs/PROTOCOL.md` §12) - we won't encrypt to a peer we haven't
    /// verified. Unlike an offline member this doesn't fail the whole send:
    /// the message still goes out to everyone else in the channel.
    pub(crate) fn recipients_for_channel(&self, channel: &ChannelTab) -> Vec<crate::ui::ui::Recipient> {
        channel
            .members
            .iter()
            .filter(|m| {
                Some(m.id) != self.own_id && !self.offline.contains(&m.id) && !self.is_trust_gated(m.id)
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
            && self.channels.get(self.selected_channel).map(|c| c.name == name).unwrap_or(false)
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
        let next = if forward { (base + 1) % len } else { (base + len - 1) % len };
        self.selected_channel = next;
        self.active_private_room = None;
        self.sidebar_selected = 0;
        // Start scrolled to the newest message in the newly-selected tab.
        self.message_selected = self.channels[next].log.len().saturating_sub(1);
        self.dwell = Some(DwellState { target_index: next, started_at: Instant::now() });
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
        if channel.joined {
            return None;
        }
        Some(UiAction::JoinChannel { name: channel.name.clone(), kind: channel.kind })
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
                    members: Vec::new(),
                    log: Vec::new(),
                });
            }
        }
    }

    pub fn on_joined(&mut self, channel: ChannelInfo) {
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
            });
        }
    }

    pub fn on_user_joined(&mut self, channel: &str, user: UserInfo) {
        self.known_users.insert(user.id, user.clone());
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            if !tab.members.iter().any(|m| m.id == user.id) {
                tab.members.push(user);
            }
        }
    }

    pub fn on_user_left(&mut self, channel: &str, user_id: UserId) {
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            tab.members.retain(|m| m.id != user_id);
        }
    }

    pub fn on_channel_message(&mut self, channel: &str, from: UserId, from_name: String, body: MessageBody) {
        let entry = LogEntry { from, from_name, body, outgoing: false };
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
                LogEntry { from, from_name, body: MessageBody::Voice { duration_ms, pcm }, outgoing: true },
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
                LogEntry { from, from_name, body: MessageBody::VoiceStreaming { stream_id }, outgoing: true },
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
    pub fn on_channel_stream_start(&mut self, channel: &str, from: UserId, from_name: String, stream_id: u64) {
        let entry = LogEntry { from, from_name, body: MessageBody::VoiceStreaming { stream_id }, outgoing: false };
        if self.is_trust_gated(from) {
            self.hold_message(from, Some(channel.to_string()), entry);
            return;
        }
        let is_current = self.is_viewing_channel(channel);
        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
            push_log_entry(&mut tab.log, &mut self.message_selected, is_current, entry);
        }
    }

    /// Swaps the `VoiceStreaming{stream_id}` placeholder left by
    /// `log_own_voice_stream_start_channel`/`on_channel_stream_start` for
    /// a finished `Voice{duration_ms, pcm}` in place, once the stream
    /// ends (from either direction - our own or a remote sender's).
    /// Matches on **both** `from` and `stream_id`: `stream_id` alone
    /// isn't unique, since it's just a per-connection counter and two
    /// different senders' counters can coincidentally collide. Checks the
    /// visible log first, then the held buffer (`on_channel_stream_start`
    /// may have placed the placeholder in either, depending on the
    /// sender's trust state *at the time the stream started* - which can
    /// change mid-stream).
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
    /// `crate::ui::file_send`) as our own, straight away rather than
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
                LogEntry { from, from_name, body, outgoing: true },
            );
        }
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub(crate) fn render_channel_view(frame: &mut Frame, area: Rect, state: &UiState) {
    let constraints = [Constraint::Length(1), Constraint::Min(3), Constraint::Length(3)];
    let rows = Layout::default().direction(Direction::Vertical).constraints(constraints).split(area);
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
            let prefix = if c.kind == ChannelKind::Private { "\u{1F512}" } else { "#" };
            Line::from(format!("{prefix}{}", c.name))
        })
        .collect();
    let tabs = Tabs::new(titles).select(state.selected_channel);
    frame.render_widget(tabs, header_cols[0]);

    // Conn comes first (right before CPU), CPU right before the help hint
    // - docs/SPEC.md "Connected UI".
    let mut status_spans = vec![
        Span::styled(format!("Conn:{}", state.conn_quality.label()), Style::default().fg(conn_color(state.conn_quality))),
        Span::raw("  "),
        Span::styled(format!("CPU:{}%", cpu_pct_rounded(state.cpu_usage_pct)), Style::default().fg(cpu_color(state.cpu_usage_pct))),
        Span::raw("  "),
    ];
    if state.key_regenerating {
        status_spans.push(Span::styled("Ctrl+H: Help  ", Style::default().fg(Color::DarkGray)));
        status_spans.push(Span::styled(state.spinner_char().to_string(), Style::default().fg(Color::White)));
    } else {
        status_spans.push(Span::styled("Ctrl+H: Help", Style::default().fg(Color::DarkGray)));
    }
    let help_hint_line = Line::from(status_spans);
    frame.render_widget(Paragraph::new(help_hint_line).alignment(ratatui::layout::Alignment::Right), header_cols[1]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
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
    let block = Block::default().title("Users").borders(Borders::ALL).border_style(border_style);
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
            // priority over the offline dimming below - it's the more
            // urgent, actionable state (open the review popup via Enter),
            // whether or not they also happen to be offline right now.
            // Offline members are otherwise only ever kept around because
            // there's DM history worth preserving (`on_user_offline`) -
            // shown in a soft gray instead of the usual green for a
            // connected user, same dim tone the help hint/spinner label
            // already use elsewhere in this screen.
            let mut style = if state.is_trust_gated(m.id) {
                Style::default().fg(Color::Red)
            } else if state.offline.contains(&m.id) {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::Green)
            };
            if state.focus == super::ui::Focus::Sidebar && i == state.sidebar_selected {
                style = style.add_modifier(Modifier::REVERSED);
            }
            ListItem::new(label).style(style)
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

pub(crate) fn render_join_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let popup = super::ui::centered_rect(40, 3, area);
    let block =
        Block::default().title("Join private channel (Enter to confirm, Esc to cancel)").borders(Borders::ALL);
    let text = format!("> {}", state.join_popup_input);
    frame.render_widget(Paragraph::new(text).block(block), popup);
}
