//! The "connected" screen: the top row's channel/DM selectors, a user
//! sidebar, the message log, and the compose bar - plus the private-message
//! room, which the DM selector opens in place of the channel view.
//!
//! `UiState` is pure interaction/presentation state: it never touches the
//! network or does any crypto (its one filesystem touch is stat-ing the
//! file chosen in the `/file` flow - `file_send`; directory listing itself
//! lives in `crate::client::file_browser`). It hands back `UiAction`s (e.g.
//! "send this plaintext to these recipients") for the caller
//! (`crate::client::session`, dispatching into `crate::client::channel` /
//! `crate::client::direct_message`) to actually encrypt and put on the wire, and
//! is fed incoming server
//! events (already decrypted) through `on_*` methods. That split is what
//! makes it unit testable without a socket or an audio device.
//!
//! Channel-tab state/rendering lives in `crate::client::tui::channel`, private-room
//! (DM) state/rendering in `crate::client::tui::direct_message` - both add their
//! own `impl UiState` blocks on top of the struct defined here. This file
//! keeps the shared/mixed plumbing: the struct itself, focus/mode/dwell-
//! agnostic key handling, and rendering helpers used by both views.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use crate::client::p2p::LinkStatus;
use crate::proto::{ChannelInfo, ChannelKind, KeyMode, UserId, UserInfo};

use super::channel::ChannelTab;
use super::direct_message::PrivateRoom;

/// How long after the most recent Space press/repeat to conclude the key
/// was released. Most terminals never send `Release` for a held key but
/// do forward OS auto-repeat as a stream of Press events, so an idle gap
/// wider than any realistic gap between repeats means the key came up -
/// this is what makes push-to-talk work beyond Kitty-protocol terminals.
/// Must exceed the OS's *initial* repeat delay (commonly 500-650ms before
/// the first repeat, only then the fast cadence), not just the
/// steady-state rate: 400ms was tried and measurably too short, firing
/// mid-hold and producing a burst of short clips instead of one
/// continuous recording.
pub const RECORD_HOLD_TIMEOUT: Duration = Duration::from_millis(900);

/// How many entries `PageUp`/`PageDown` move the message-log selection by
/// in one press, while focus is on the message log.
pub const MESSAGE_PAGE_JUMP: usize = 10;

/// How many lines `PageUp`/`PageDown` scroll the help overlay by in one
/// press - see `UiState::help_scroll`.
pub const HELP_SCROLL_PAGE: usize = 10;

/// How long the top-right status notice stays on screen before
/// `UiState::tick_status_notice` clears it - long enough to be read after
/// looking away, short enough that a stale outcome doesn't linger forever.
pub const STATUS_NOTICE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a selector dropdown stays open with nothing driving it before
/// it folds itself away (`UiState::tick_selector_dropdown`). It is an
/// overlay over the conversation, not a modal: left open and forgotten it
/// would sit on top of the messages arriving underneath, so an idle one
/// gets out of the way on its own.
pub const SELECTOR_DROPDOWN_IDLE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// The help overlay's own text, `Up`/`Down`/`PageUp`/`PageDown`/`Home`/`End`-
/// scrollable (`UiState::help_scroll`) since it easily runs longer than a
/// typical terminal window - module-level (not local to
/// `render_help_popup`) so `UiState::handle_key`'s scroll clamping and the
/// renderer share one source of truth for how many lines there are.
/// What a `/call` that could reach nobody says (`docs/SPEC.md` "Live
/// voice calls") - one string, because both sides can conclude it: the UI
/// when its own count comes out at zero, and the session a moment later
/// when its authoritative recount does
/// (`crate::client::channel::handle_start_call`).
pub const NO_ONE_INVITED_NOTICE: &str = "Call has ended: no one was invited";

/// What a `/call` aimed at a peer under an active OTP session says. The
/// OTP layer has no live-streaming concept at all (`docs/PROTOCOL.md`
/// 16.2), so this is a refusal, not a partial delivery - one string,
/// because three places can reach the same conclusion: `/call` itself,
/// `direct_message::handle_start_call`'s authoritative recheck, and
/// `voice_call::invite_to_call`.
pub const OTP_CALL_REFUSAL: &str = "voice calls aren't supported over an OTP session";

/// What every participant is told when the host hangs up - the host
/// leaving ends the call for everyone (`docs/PROTOCOL.md` 7.7), unlike
/// any other participant leaving.
pub const HOST_LEFT_NOTICE: &str = "Call has ended: the host left the call";

/// What accepting an invite to a call that has already ended says
/// (`crate::client::voice_call::accept_invite`): the answer is taken -
/// the popup closes - but there is nothing left to join, so no call
/// starts and this is shown instead.
pub const CALL_ALREADY_ENDED_NOTICE: &str = "that call has already ended";

const HELP_HEADINGS: [&str; 10] = [
    "Channels",
    "Messaging",
    "Private messages",
    "Voice messages",
    "File transfer",
    "Live voice calls",
    "Encryption (tag shown after each username)",
    "One-time-pad layer (optional, per contact)",
    "OTP mail (async, stored encrypted on the server)",
    "Identity pinning (id_store)",
];
const HELP_BODY: &[&str] = &[
    "Channels",
    "  [  /  ]    move between the channel selector (left) and the DM one (right);",
    "             at either end it opens that selector's dropdown instead - every",
    "             other channel you joined (\u{1F30D} public / \u{1F512} private), or room you",
    "             have open. Up/Down pick one (the view follows straight away),",
    "             Enter, Esc, Tab or the opposite key close it again, and so",
    "             does leaving it alone for 30 seconds",
    "  /channels  list every public channel (yours in yellow); Enter joins, Esc closes",
    "  Ctrl+J     join/create a channel: name, Public/Private (Left/Right), optional password",
    "  /leave     leave the selected channel tab (its tab disappears)",
    "",
    "Messaging",
    "  Tab        cycle focus: sidebar -> messages -> compose bar",
    "  Enter      send the typed message (compose bar focused)",
    "",
    "Private messages",
    "  Up / Down    pick a user (sidebar focused)",
    "  Enter      open a private room with the selected user",
    "  Esc        back to the channel selector (the room stays on the DM selector)",
    "  \u{2709}          blinks on a selector while a channel/DM behind it has unseen",
    "             messages, and on the dropdown row they landed in",
    "",
    "Voice messages",
    "  Space      hold to record & send live (not while composing); release to stop",
    "  Ctrl+Alt+P   same, from anywhere - edit/disable in ~/.aloo/settings",
    "  Enter      replay a voice message (messages focused)",
    "  Esc        stop a replay while it is playing",
    "  Capped at 4 minutes - recording stops itself on reaching it, and a",
    "  received stream longer than that is never accepted past 4 minutes.",
    "",
    "File transfer",
    "  /file      type this and press Enter to browse for a file to send",
    "  Left/Right/Tab   choose Send file / Discard on the confirmation box (Discard by default)",
    "  The recipient sees a popup (with a chime) naming you and the file,",
    "  Accept focused by default; Left/Right/Tab/Enter same as above.",
    "  Accepting streams the file straight to ~/.aloo/downloads with a",
    "  live progress bar - nothing is held whole in memory on either side,",
    "  and there is no size cap. Declining shows as rejected in your log.",
    "",
    "Live voice calls",
    "  /call      start a continuous, multi-user call in the selected channel",
    "             or open private room - distinct from a voice message: not",
    "             push-to-talk, no time cap, and every current member/the",
    "             peer gets an Accept/Reject popup (with a chime) naming you.",
    "             You confirm first, told how many people it will ring.",
    "  /endcall   leave the call - a permanent red banner (top right) marks",
    "             the whole time you're on one",
    "  The call modal opens with the call: live duration on top, then",
    "  everyone on it - HOST first, each labelled IN CALL / INVITED /",
    "  REJECTED (+ MUTED), with a live voice bar. Up/Down walk the list,",
    "  Enter or e is END CALL, Esc folds it away into the \u{1F534} Call",
    "  indicator at the top right (Ctrl+R brings the modal back).",
    "  m on your own row mutes your microphone (yours to lift, nobody",
    "  else is told). As the host, m on anyone else's row mutes them",
    "  instead - only you can lift that - and i invites one more person",
    "  you share a channel or DM with.",
    "  Leaving as the host ends the call for everyone. One call at a time.",
    "  Not available over an OTP session (that layer has no live-streaming",
    "  concept at all - see the OTP section below).",
    "",
    "Encryption (tag shown after each username)",
    "  name \u{1F6A8} PWD    static: one RSA keypair derived from a password",
    "  name \u{1F6A8} PLAIN  static: one RSA keypair auto-generated when you connected",
    "  name \u{1F6E1}\u{FE0F} PQH    static: ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM, loaded from a file",
    "",
    "One-time-pad layer (optional, per contact)",
    "  /otp       inside an open DM room: proposes an extra one-time-pad",
    "             layer on top of pq_hybrid for that contact only. Never",
    "             starts on its own say-so - always ends in an explicit",
    "             Accept/Reject on the other side, confirmed back to you.",
    "  If no key exists yet, you're asked to confirm generating one and",
    "  sharing it automatically over pq_hybrid (or you can run 'otp'",
    "  yourself and place the keys under ~/.aloo/otp/.keychain/ instead).",
    "  Confirming asks for a size next, 1-900000 MB per key. An incoming",
    "  proposal shows an Accept/Reject popup naming the sender and, for a",
    "  fresh key, the size offered.",
    "  Requires both sides to use pq_hybrid, and the real 'otp' command",
    "  (github.com/DavidValin/otp-toolkit) installed. Once started, a message to",
    "  that contact waits for the previous one to be genuinely acknowledged",
    "  before the next can send. \"OTP session started at <time>\" (green) or",
    "  \"OTP session cancelled\" (red) is shown to both sides.",
    "  Text, file and voice content sent to that contact are all protected",
    "  under the pad while active - a file's name/size still travel unwrapped",
    "  (only its bytes are, once accepted); voice is recorded fully and sent",
    "  once instead of live, arriving playable once it fully lands.",
    "  While active, a 1-line header above the messages shows both",
    "  directions' Seq/Offset/remaining-MB live, updated about once a",
    "  second - remaining turns red below 0.5MB per direction.",
    "",
    "OTP mail (async, stored encrypted on the server)",
    "  /mail      full-screen compose view: To / Subtext / Content, plus",
    "             voice recordings (hold Space, only while the attachments",
    "             pane is focused) and file attachments ('a' opens the",
    "             browser; 'd' removes the selected one, after confirming).",
    "  Needs a pinned recipient you hold an otp key for, longer than the",
    "  whole mail - the To field shows \u{2705}/\u{274C} live and the remaining key",
    "  (MB) shows top-right, updating as you type and attach. Ctrl+S sends,",
    "  only after a confirm popup. The mail travels one-time-pad encrypted",
    "  and waits on the server (which cannot read it) until the recipient",
    "  connects.",
    "  /mailbox   opens the mailbox: each sent mail's delivery status, and",
    "             received mail - Enter reads one (decrypted in memory",
    "             only), 'd' removes it, destroying its stored",
    "             ciphertext+pad.",
    "",
    "Identity pinning (id_store)",
    "  Remembers each nickname's full public key across sessions (not",
    "  just a hash) - exact match for password/pq_hybrid. none is",
    "  untracked. A mismatch opens a popup naming the peer with",
    "  Accept/Reject buttons; messaging with them is blocked until you",
    "  decide. Accept saves to disk right away and reveals anything of",
    "  theirs held while unresolved; Reject saves nothing and isn't",
    "  permanent - select them again to reconsider. Path set in the",
    "  connect popup's id_store field.",
    "",
    "  All local state (id_store, settings, the OTP keychain) lives under",
    "  ~/.aloo by default. Set ALOO_HOME to use a different directory -",
    "  needed if you run more than one client on this same machine, since",
    "  they'd otherwise collide by sharing one ~/.aloo.",
    "",
    "  Ctrl+C         quit",
    "  Ctrl+H / Esc   close this help",
    "  Up/Down        scroll",
];

/// Where one file transfer's log row currently stands
/// (`docs/PROTOCOL.md`'s file transfer section) - `Pending` only ever shown
/// on the *sender's* side (the receiver never gets a row at all until they
/// decide; see `PendingFileOffer`/`file_offer_queue`), the other three
/// apply to either direction.
#[derive(Debug, Clone, PartialEq)]
pub enum FileTransferStatus {
    /// Offer sent, waiting for the recipient's Accept/Reject.
    Pending,
    /// Accepted; bytes are actively flowing (sent, if this is our own
    /// outgoing row, or written to disk, if incoming).
    InProgress { bytes: u64 },
    /// Every byte sent (outgoing) or written to `~/.aloo/downloads`
    /// (incoming).
    Completed,
    /// The recipient declined the offer - outgoing rows only.
    Rejected,
    /// A local error ended the transfer early (disk/read/write failure) -
    /// surfaced rather than left stuck mid-progress forever.
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageBody {
    Text(String),
    /// A finished voice message: `pcm` is decoded, decrypted PCM16 (see
    /// `voice::pcm_from_bytes`), ready to replay through `voice::MixerCmd`.
    Voice {
        duration_ms: u32,
        pcm: Vec<u8>,
    },
    /// A voice message that's still being recorded/received live - see
    /// `log_own_voice_stream_start_channel`/`on_channel_stream_start` and
    /// their `_finished` counterparts, which swap this in place for a
    /// `Voice` once the stream ends. `stream_id` alone doesn't identify
    /// which stream this is - callers must always also match on the
    /// entry's `from`, since two different senders' independent
    /// per-connection counters can coincidentally collide.
    VoiceStreaming {
        stream_id: u64,
    },
    /// One file transfer, consent-gated and streamed
    /// (`docs/PROTOCOL.md`'s file transfer section) - `stream_id` identifies
    /// it the same way `VoiceStreaming`'s does (paired with the entry's
    /// `from`, never alone), so a later progress/completion event can find
    /// and update this exact row (`UiState::update_file_entry`).
    File {
        filename: String,
        total: u64,
        stream_id: u64,
        status: FileTransferStatus,
    },
    /// An app-generated line about the conversation itself rather than
    /// something either party said - currently only the OTP layer's own
    /// errors/confirmations (`client::otp::notify`), mirrored here from the
    /// same text shown in the top-right status notice so the history of a
    /// session's setup isn't lost the moment that notice clears. Never
    /// given the OTP shield prefix (`render_messages`) - it would be
    /// redundant on a line that already names OTP explicitly, and the
    /// prefix is meant to mark *content*, not the app's own narration.
    System(String),
    /// A peer joining a channel, leaving one, or disconnecting entirely -
    /// rendered in yellow (`render_messages`), unlike the gray/italic
    /// `System` above, so it stands out as a presence change rather than
    /// app narration. Already-formatted text (`local_time_short` prefix
    /// plus the peer's name and the event) built by
    /// `channel::on_user_joined`/`on_user_left`/`ui::on_user_offline` -
    /// see `docs/SPEC.md` Functionality #12. Excluded from the OTP shield
    /// prefix for the same reason `System` is.
    Presence(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogEntry {
    pub from: UserId,
    pub from_name: String,
    /// Set only for an outgoing file-transfer row addressed to one specific
    /// recipient (a channel file send creates one row per recipient - see
    /// `docs/PROTOCOL.md`'s file transfer section) - lets that row render
    /// who it's addressed to. `None` for every other kind of entry,
    /// including a DM file send (the room itself already names the peer).
    pub to_name: Option<String>,
    pub body: MessageBody,
    pub outgoing: bool,
    /// Set after the fact, once an async send this row was optimistically
    /// logged for (`push_outgoing_dm`) turns out to have failed - currently
    /// only OTP sends, the one case that can fail per-message after the
    /// row is already showing (`client::otp::send_now`'s failure paths via
    /// `UiState::mark_dm_message_failed`). Never true for anything but an
    /// `outgoing` entry.
    pub failed: bool,
}

/// Which anchor a peer's identity mismatch failed against - drives the
/// review popup's case-specific wording and what `AcceptIdentity` needs
/// to install the new key. `StaticMismatch` (§12.4, `password`/`pq_hybrid`)
/// is a byte comparison with a definite "old key" to show.
#[derive(Debug, Clone, PartialEq)]
pub enum IdentityCase {
    StaticMismatch {
        new_public_key_der: Vec<u8>,
        previous_public_key_der: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStatus {
    /// Detected, but the popup itself is still withheld: this connection's
    /// own address/device id (docs/PROTOCOL.md §12.7) haven't arrived yet
    /// from the P2P handshake, and showing the review before they do would
    /// give the user only half the picture. Never queued/shown
    /// (`push_identity_review`/`reopen_identity_review` skip it), but
    /// `is_trust_gated` is already true - messaging with this peer is
    /// blocked from the moment the mismatch is detected, not from whenever
    /// the popup happens to become visible. `reveal_identity_review`
    /// (`session::reveal_pending_identity_review`) is what moves this to
    /// `Pending` and actually opens the popup.
    AwaitingPeerInfo,
    /// Detected, not yet decided - shown in the popup (now or once queued
    /// reviews ahead of it resolve) and blocks messaging like `Rejected`
    /// does in the meantime.
    Pending,
    /// Explicitly rejected: never persisted to `id_store` (`docs/PROTOCOL.md`
    /// §12.4/§12.6 no longer apply to this key), kept red in the sidebar,
    /// and re-openable via Enter for reconsideration - not a permanent
    /// block, since this app never silently locks a peer out for good
    /// (`docs/PROTOCOL.md` §12.1).
    Rejected,
}

/// One peer's outstanding identity decision. Kept in `UiState::identity_reviews`
/// even after being `Rejected` (not just while `Pending`) so re-opening the
/// popup via Enter on a red sidebar entry can re-render the same case
/// instead of having nothing left to show.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityReview {
    pub nickname: String,
    /// Case-specific text already formatted by the caller (`session::
    /// check_identity`/`handle_key_rotated`) - `UiState` doesn't know
    /// anything about fingerprints, only how to show a string, same
    /// division of labor the old banner used.
    pub message: String,
    pub case: IdentityCase,
    pub status: IdentityStatus,
}

/// Which button currently has focus in the identity review popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityChoice {
    Accept,
    Reject,
}

/// A message received from a peer whose identity is `Pending`/`Rejected` at
/// the moment it arrived - held here instead of the visible channel/DM log
/// (`docs/PROTOCOL.md` §12 "hold and reveal") until that peer is Accepted,
/// at which point it's drained into the real log in arrival order.
/// `channel: None` means a DM.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldMessage {
    pub channel: Option<String>,
    pub entry: LogEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Sidebar,
    Messages,
    Input,
}

/// Which of the top row's two selectors - the channel one on the left, the
/// DM one on the right - is focused, i.e. whose own selection is the view
/// on screen (`docs/SPEC.md` "Connected UI"). `[`/`]` move between them
/// and open the focused one's dropdown at the outer end; neither key ever
/// wraps around from one end of the row to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorFocus {
    Channels,
    Dms,
}

/// The icon each kind of entry carries in the top row and in a dropdown:
/// the channel's own kind for a channel (as `docs/SPEC.md` "Connected UI"
/// has always shown it), and one shared marker for every DM.
pub(crate) fn channel_kind_icon(kind: ChannelKind) -> &'static str {
    match kind {
        ChannelKind::Public => "\u{1F30D}",
        ChannelKind::Private => "\u{1F512}",
    }
}

pub(crate) const DM_ICON: &str = "\u{1F4AC}";

/// The one envelope glyph this UI ever draws for unseen messages - the
/// plain text-style U+2709, never an emoji-presentation variant, so a
/// terminal renders it as one flat character with no colour block of its
/// own behind it.
pub(crate) const UNREAD_ENVELOPE: &str = "\u{2709}";

/// That envelope as the top row and the dropdowns draw it: a fixed
/// two-cell slot - a leading space and the glyph, or two spaces on the
/// blink-off frame - so nothing shifts sideways as it blinks.
pub(crate) fn unread_envelope(blink_on: bool) -> &'static str {
    if blink_on { " \u{2709}" } else { "  " }
}

/// One row of an open selector dropdown - `label` already carries its
/// kind prefix (\u{1F30D}/\u{1F512} for a channel, \u{1F4AC} for a DM), `unread` drives the
/// blinking envelope beside it (`render_selector_dropdown`).
pub struct SelectorEntry {
    pub label: String,
    pub unread: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    JoinPrivatePopup,
    /// Shown after a `ChannelJoinRejected` (`PasswordRequired`/
    /// `WrongPassword`/`Banned`) naming `UiState::channel_password_target` -
    /// lets the user type a password and resubmit the same `JoinChannel`.
    /// See `crate::client::tui::channel::handle_channel_password_popup_key`.
    ChannelPasswordPopup,
    /// `/channels`' modal directory of the server's public channels -
    /// joined ones shown yellow, Enter joins, Esc closes. Data lives in
    /// `UiState::known_channels`/`channels_popup_selected`, the same split
    /// `JoinPrivatePopup`/`join_popup_input` use. See
    /// `crate::client::tui::channel::handle_channels_popup_key`.
    ChannelsPopup,
    /// The `/file` send flow (browse -> confirm) is open - see
    /// `crate::client::tui::file_send`. Data lives in `UiState::file_send`, not
    /// here, same split `JoinPrivatePopup`/`join_popup_input` already use.
    FileSend,
}

/// Which field is focused inside the Ctrl+J popup - Tab/BackTab cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JoinPopupFocus {
    Name,
    Kind,
    Password,
}

/// One incoming file offer awaiting an Accept/Reject decision
/// (`docs/PROTOCOL.md`'s file transfer section) - shown as a popup (with
/// `assets/bell.wav`) the instant it becomes the front of
/// `UiState::file_offer_queue`, mirroring the identity review popup's
/// modal-queue idiom. Nothing is written to disk, and no log row exists,
/// until this is resolved - `Accept` is what creates both.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingFileOffer {
    pub from: UserId,
    pub from_name: String,
    pub filename: String,
    pub size: u64,
    pub stream_id: u64,
    /// `Some(channel)` if this offer arrived via a channel send, `None` for
    /// a DM - decides which log the accepted row goes into.
    pub channel: Option<String>,
    /// `Some(contact_name)` if this offer arrived via
    /// `client::otp::on_file_offer` - accepting it then routes the
    /// incoming content through the OTP-decrypt path
    /// (`session::accept_file_offer`) instead of writing chunks straight
    /// to the final destination. The content phase's own OTP `seq` isn't
    /// known yet at this point - it's a separate pad spend, reserved only
    /// once the sender's `FileAccepted` handling runs, and arrives
    /// separately as `P2pEvent::OtpFileContentSeq` (docs/PROTOCOL.md
    /// 16.2). `None` here for an ordinary (non-OTP) offer.
    pub otp_contact_name: Option<String>,
}

/// Which button is focused in the file-offer popup - `Accept` by default
/// (the opposite of the identity review popup's `Reject`-first default),
/// per the file transfer spec: accepting an offer is the common case and
/// shouldn't need an extra keystroke past Enter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOfferChoice {
    Accept,
    Reject,
}

/// Which button is focused in either OTP popup below - `Accept` by
/// default, same reasoning as `FileOfferChoice`: you either just typed
/// `/otp` yourself (wanting to proceed is the common case) or a peer is
/// asking for something you'd typically grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpChoice {
    Accept,
    Reject,
}

/// One incoming live-call invite awaiting an Accept/Reject decision
/// (`docs/PROTOCOL.md` "Live voice calls") - mirrors `PendingFileOffer`'s
/// queued-popup idiom exactly, down to `Accept` being the default focus.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingCallInvite {
    pub call_id: u64,
    pub from: UserId,
    pub from_name: String,
    /// `Some(channel)` for a channel call, `None` for a DM.
    pub channel: Option<String>,
    /// Set once the host's `CallEnd` for this call has arrived while the
    /// invite was still unanswered (`mark_call_invite_ended`): accepting
    /// it then starts nothing and says so (`CALL_ALREADY_ENDED_NOTICE`),
    /// since there is no longer a call to join.
    pub ended: bool,
}

/// Which button is focused in the call-invite popup - `Accept` by default,
/// same reasoning as `FileOfferChoice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallInviteChoice {
    Accept,
    Reject,
}

/// Where `/call` should be addressed, resolved at command-submit time (same
/// "known now, not deferred" reasoning as `VoiceTarget`) - `session::
/// handle_ui_action` dispatches into `crate::client::channel`/
/// `crate::client::direct_message`'s `handle_start_call`, which resolve the
/// actual recipient list (channel membership is looked up fresh there,
/// rather than snapshotted here, since a call invite tolerates the extra
/// few milliseconds a bounded live recording can't - see
/// `voice_call::addressable_channel_members`).
#[derive(Debug, Clone, PartialEq)]
pub enum CallTarget {
    Channel {
        channel: String,
    },
    Direct {
        to: UserId,
        recipient_key_mode: KeyMode,
        recipient_pubkey_der: Vec<u8>,
    },
}

/// The `/call` confirmation (`docs/SPEC.md` "Live voice calls"): nobody
/// is rung until this is answered, and it says up front how many people
/// that will be. Holds the already-resolved `CallTarget` so the answer
/// acts on exactly what `/call` was typed against, even if membership
/// shifts while the popup is up.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingCallConfirm {
    pub target: CallTarget,
    /// How many people the invite fan-out will reach - the count the
    /// popup prints, in yellow.
    pub invitee_count: usize,
}

/// Which button is focused in the `/call` confirmation - `Confirm` by
/// default: the user just typed `/call` themselves, so wanting to proceed
/// is the common case (same reasoning as `FileOfferChoice`'s
/// `Accept`-first default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallConfirmChoice {
    Confirm,
    Cancel,
}

/// Where one person stands on a call we are on - the roster label the
/// call modal draws next to their name (`docs/SPEC.md` "Live voice
/// calls"). Only the host ever sees `Invited`/`Rejected`: a participant
/// learns about other participants purely from the `CallAccept`s that
/// converge the mesh (`docs/PROTOCOL.md` 7.7), which say nothing about
/// anyone who has not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallMemberState {
    /// Accepted and exchanging audio with us.
    InCall,
    /// Sent a `CallInvite`, no answer yet.
    Invited,
    /// Answered with `CallReject`.
    Rejected,
}

/// One row of the call modal's roster. Includes ourselves - the modal
/// shows every person on the call, us among them, unlike
/// `voice_call::ActiveCall::participants` (network plumbing, which by
/// definition can only hold *other* people).
#[derive(Debug, Clone, PartialEq)]
pub struct CallMember {
    pub id: UserId,
    pub name: String,
    pub state: CallMemberState,
    /// Muted *by the host* (`p2p_proto::P2pPayload::CallMute`) - a
    /// different thing from this person muting themselves: only the host
    /// can lift this one.
    pub host_muted: bool,
    /// Muted *by themselves* - announced to everyone on the call the
    /// moment they toggle it (`crate::client::voice_call::toggle_mute`),
    /// so every roster says who can currently be heard. Theirs alone to
    /// lift again.
    pub self_muted: bool,
    /// Live 0-100 meter reading for this person's voice
    /// (`crate::client::voice::level_from_pcm`), refreshed every audio
    /// chunk by whichever worker produced it.
    pub level: u8,
}

/// The host-only "invite someone else to this call" picker, opened with
/// `i` from the call modal. Candidates are resolved once at open time
/// (`UiState::open_call_invite_picker`) rather than live, so the list
/// can't shift under the selection between keystrokes.
#[derive(Debug, Clone, PartialEq)]
pub struct CallInvitePicker {
    pub candidates: Vec<(UserId, String)>,
    pub selected: usize,
}

/// Everything on screen about the call we are currently on: the permanent
/// top-right indicator (`docs/SPEC.md` "Live voice calls" requires it stay
/// up for the call's whole duration, in red) *and* the call modal the
/// indicator summarises - roster, live duration, per-person voice meters,
/// and the host's mute/invite controls.
#[derive(Debug, Clone, PartialEq)]
pub struct CallUiState {
    pub call_id: u64,
    pub channel: Option<String>,
    /// Whether we have muted ourselves (`m` on our own row). It gates our
    /// own capture locally and is announced to the call so everyone's
    /// roster shows it (`docs/PROTOCOL.md` 7.7); it stays ours alone to
    /// lift, unlike `CallMember::host_muted`.
    pub muted: bool,
    /// Who started this call: the initiator for a call we started, the
    /// sender of the `CallInvite` for one we accepted. Named
    /// `<nickname> (host)` on the roster, and the only person allowed to
    /// mute anyone else or invite more people.
    pub host: UserId,
    /// The roster, host first, then everyone else in the order we learned
    /// about them - includes our own row.
    pub members: Vec<CallMember>,
    /// Which roster row the modal's cursor is on.
    pub selected: usize,
    /// When we joined, for the live duration readout.
    pub started_at: Instant,
    /// Whole seconds since `started_at`, refreshed by
    /// `UiState::tick_call_duration` off the session's ticker rather than
    /// read from the clock at render time, so the rendered value is
    /// deterministic for a given tick.
    pub elapsed_secs: u64,
    /// `true` once Escape has folded the modal away into the header row's
    /// `\u{1F534} Call Ctrl+R` indicator, leaving the ordinary
    /// sidebar/messages/compose layout usable again. Ctrl+R brings it back.
    pub minimized: bool,
    /// The host's invite picker, while it is open.
    pub invite_picker: Option<CallInvitePicker>,
}

impl CallUiState {
    /// Whether *we* are the host - gates the modal's `m` (mute someone)
    /// and `i` (invite someone) keys.
    pub fn we_are_host(&self, own_id: Option<UserId>) -> bool {
        own_id == Some(self.host)
    }

    /// How many *other* people are actually on the call right now - what
    /// the permanent banner counts.
    pub fn connected_count(&self, own_id: Option<UserId>) -> usize {
        self.members
            .iter()
            .filter(|m| m.state == CallMemberState::InCall && Some(m.id) != own_id)
            .count()
    }

    /// `MM:SS`, or `HH:MM:SS` once a call runs past an hour.
    pub fn duration_label(&self) -> String {
        let secs = self.elapsed_secs;
        let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
        if h > 0 {
            format!("{h:02}:{m:02}:{s:02}")
        } else {
            format!("{m:02}:{s:02}")
        }
    }
}

/// The local "generate and share a fresh pad?" decision after `/otp` finds
/// no existing keychain entry (`client::otp::handle_otp_command`) - never
/// acted on without this confirmation, see `docs/PROTOCOL.md` §16.1.
#[derive(Debug, Clone)]
pub struct PendingOtpGenerate {
    pub peer: UserId,
    pub peer_name: String,
    pub key_mode: KeyMode,
    pub pubkey_der: Vec<u8>,
}

/// One incoming OTP session proposal awaiting an Accept/Reject decision -
/// the peer-initiated counterpart of `PendingOtpGenerate`, mirroring
/// `PendingFileOffer`'s queued-popup idiom. `peer_encryption_key`/
/// `peer_decryption_key` are `Some` only for a fresh-key invitation
/// (`Content::OtpKeySetup`); both `None` means a session request against
/// an already-existing keychain contact (`Content::OtpSessionRequest`).
/// Holds raw one-time-pad key bytes while awaiting a decision, so - like
/// `crypto::otp::OtpKeySetupPayload` - this is zeroized on drop.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct PendingOtpInvite {
    #[zeroize(skip)]
    pub from: UserId,
    #[zeroize(skip)]
    pub from_name: String,
    #[zeroize(skip)]
    pub contact_name: String,
    pub peer_encryption_key: Option<Vec<u8>>,
    pub peer_decryption_key: Option<Vec<u8>>,
    /// The pad size (MB per key) the sender chose - `Some` alongside the
    /// key material for a fresh-key invitation, always `None` for a bare
    /// session request (nothing was generated, so there's no size to
    /// report). Shown in the invite popup so the deciding side isn't
    /// asked to accept sight-unseen - a much larger pad takes longer to
    /// receive (`OtpKeySetupChunk`'s doc) and ties up more disk/keychain
    /// space than a small one.
    #[zeroize(skip)]
    pub pad_size_mb: Option<u32>,
}

/// A recipient's addressing info: their id, announced `KeyMode` (which
/// scheme to encrypt under - see `envelope::encrypt_for_one` vs
/// `envelope::encrypt_hybrid_envelope_for`), and their raw public key bytes
/// (RSA DER, or a bincode-encoded `crypto::pq::PqPublicBundle` for
/// `KeyMode::PqHybrid` - opaque either way until paired with `KeyMode`).
pub type Recipient = (UserId, KeyMode, Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub enum VoiceTarget {
    Channel {
        channel: String,
        recipients: Vec<Recipient>,
    },
    Direct {
        to: UserId,
        recipient_key_mode: KeyMode,
        recipient_pubkey_der: Vec<u8>,
    },
    /// A recording destined for the mail being composed (docs/PROTOCOL.md
    /// §17.1) - nothing goes on the wire at all: the accumulate worker
    /// reports the finished PCM and it lands in the compose form's
    /// attachment list (`UiState::otp_mail_add_voice`).
    MailAttachment,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UiAction {
    JoinChannel {
        name: String,
        kind: ChannelKind,
        password: Option<String>,
    },
    /// Sent by the `/leave` command (`submit_input`) for the currently
    /// selected channel tab.
    LeaveChannel {
        name: String,
    },
    SendChannelText {
        channel: String,
        plaintext: String,
        recipients: Vec<Recipient>,
    },
    SendDirectText {
        to: UserId,
        plaintext: String,
        recipient_key_mode: KeyMode,
        recipient_pubkey_der: Vec<u8>,
        /// Where this text landed in the DM's log when it was optimistically
        /// shown (`push_outgoing_dm`) - lets a later async failure
        /// (currently only an OTP send) find and mark that exact row
        /// (`UiState::mark_dm_message_failed`) rather than leaving a
        /// message that was never delivered looking identical to one that
        /// was.
        log_index: Option<usize>,
    },
    /// The target is captured at press-time (not release-time): live
    /// streaming needs to know who to address the wire `StreamXStart` to
    /// the moment recording starts, not just once it's done.
    VoiceRecordStart(VoiceTarget),
    VoiceRecordStop,
    ReplayVoice {
        duration_ms: u32,
        pcm: Vec<u8>,
    },
    /// Escape while a replayed (previously-received) voice message is
    /// playing - `session::handle_ui_action` stops it on the mixer, since
    /// `UiState` has no access to audio.
    StopPlayback,
    /// The user confirmed Accept/Reject in the identity review popup for
    /// this peer (`docs/PROTOCOL.md` §12) - `session::handle_ui_action`
    /// does the actual `id_store`/`rekey` side effects, since `UiState`
    /// has no access to either.
    AcceptIdentity(UserId),
    RejectIdentity(UserId),
    /// A file send confirmed in the `/file` popup (`crate::client::tui::file_send`) -
    /// `crate::client::channel::handle_send_file` builds and sends one `FileOffer`
    /// per ready recipient (rotating-key readiness is snapshotted here,
    /// same as a voice stream's recipients - see `docs/PROTOCOL.md`'s file
    /// transfer section); nothing is read from `path` until each recipient
    /// individually accepts.
    SendFileChannel {
        channel: String,
        path: std::path::PathBuf,
        filename: String,
        size: u64,
        recipients: Vec<Recipient>,
    },
    SendFileDirect {
        to: UserId,
        path: std::path::PathBuf,
        filename: String,
        size: u64,
        recipient_key_mode: KeyMode,
        recipient_pubkey_der: Vec<u8>,
    },
    /// The user confirmed Accept/Reject in the file-offer popup for
    /// `(from, stream_id)` - `session::handle_ui_action` does the actual
    /// `FileAccept`/`FileReject` wire send and, on Accept, spawns the
    /// receiving worker (`UiState` has no access to the network or disk).
    AcceptFileOffer {
        from: UserId,
        stream_id: u64,
    },
    RejectFileOffer {
        from: UserId,
        stream_id: u64,
    },
    /// Sent by the `/otp` command (`submit_input`) for the currently open
    /// DM room - the one and only trigger for starting an OTP session
    /// (`client::otp::handle_otp_command`). Never sent automatically.
    RequestOtpSession {
        peer: UserId,
        key_mode: KeyMode,
        pubkey_der: Vec<u8>,
    },
    /// The user confirmed "generate and share a fresh OTP pad?"
    /// (`otp_generate_confirm`) and then chose a size for it
    /// (`otp_size_input`, MB per key, `crypto::otp::OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX`)
    /// - `client::otp::confirm_generate` does the actual generation and
    /// send.
    ConfirmOtpGenerate {
        size_mb: u32,
    },
    /// The user declined generating a pad, at either step
    /// (`otp_generate_confirm`'s Reject, or Escape out of `otp_size_input`)
    /// - purely local, nothing was ever sent.
    CancelOtpGenerate,
    /// The user accepted an incoming OTP session proposal
    /// (`otp_invite_open`) - `client::otp::accept_invite`.
    AcceptOtpInvite,
    /// The user rejected it - `client::otp::reject_invite`.
    RejectOtpInvite,
    /// Emitted on every keystroke in the mail compose view's To field
    /// (docs/PROTOCOL.md §17.1) - `client::otp_mail::check_recipient` runs
    /// the pinned-user + keychain + remaining-key checks (which need
    /// `SessionState` and the `otp` CLI, neither of which `UiState` has)
    /// and answers through `UiState::otp_mail_set_check`.
    CheckOtpMailRecipient {
        nickname: String,
    },
    /// The `/mailbox` command (`submit_input`) - the session snapshots
    /// the mail store into mailbox rows
    /// (`UiState::otp_mail_set_mailbox_rows`), shown over the mail view
    /// the command just opened as their backdrop.
    OpenOtpMailbox,
    /// The user confirmed Send in the mail confirm popup - the *only*
    /// path that ever encrypts and uploads a mail
    /// (`client::otp_mail::handle_send`).
    SendOtpMail,
    /// Enter on a received mailbox row - the session XORs the stored
    /// (ciphertext, pad) pair in memory and opens the reader
    /// (`client::otp_mail::handle_read`).
    ReadOtpMail {
        mail_id: String,
    },
    /// The user confirmed removing a mail in the mailbox - for a received
    /// mail this securely destroys its stored ciphertext *and* pad
    /// (`client::otp_mail::handle_delete`).
    DeleteOtpMail {
        mail_id: String,
    },
    /// Enter on an attachment row in the mail reader - the session writes
    /// its bytes (already in memory with the open payload) to the
    /// downloads directory.
    SaveOtpMailAttachment {
        index: usize,
    },
    /// The `/call` command (`submit_input`) - starts a live voice call
    /// addressed to `target`. Never sent while already on a call or mid
    /// push-to-talk recording (`submit_input` refuses those itself, with a
    /// status notice); OTP-gating (a DM contact we currently have an OTP
    /// session with) is checked session-side, where `SessionState` is
    /// available (`crate::client::direct_message::handle_start_call`).
    StartCall(CallTarget),
    /// The user accepted an incoming call invite (`docs/PROTOCOL.md` "Live
    /// voice calls") - `crate::client::voice_call::accept_invite`.
    AcceptCallInvite {
        call_id: u64,
    },
    /// The user rejected it - `crate::client::voice_call::reject_invite`.
    RejectCallInvite {
        call_id: u64,
    },
    /// `m` on our own row in the call modal - toggles our own microphone,
    /// ours alone to lift, and announced to everyone on the call
    /// (`crate::client::voice_call::toggle_mute`).
    ToggleCallMute,
    /// The `/endcall` command, or the call modal's END CALL button -
    /// leaves the call we're currently on
    /// (`crate::client::voice_call::end_own_call`).
    EndCall,
    /// The host invited one more person from the call modal - only ever
    /// produced for the host of the call we're on
    /// (`crate::client::voice_call::invite_to_call`).
    InviteToCall {
        to: UserId,
    },
    /// The host muted (or unmuted) one participant with `m` on the call
    /// modal's roster - only the host can lift it again
    /// (`crate::client::voice_call::host_set_muted`).
    HostMuteCallMember {
        peer: UserId,
        muted: bool,
    },
}

/// Which trigger started the current recording - `handle_key`'s Space
/// branch and `global_record_start`/`global_record_stop` (the global
/// Ctrl+Alt+P shortcut, see `crate::client::global_ptt`) both drive the same
/// `recording`/`VoiceRecordStart`/`VoiceRecordStop` machinery, but need to
/// stay distinguishable: `tick_recording_timeout`'s idle-silence guess
/// must never apply to a `Global` recording (there's no repeat-keypress
/// heartbeat for a held OS hotkey to go quiet - it only ever ends on a
/// real `Released` event), and each trigger should only ever be able to
/// stop a recording it itself started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordSource {
    Space,
    Global,
}

pub struct UiState {
    pub own_id: Option<UserId>,
    pub own_name: String,
    /// The tab row: exactly the channels the user is currently joined to
    /// (`on_joined` creates a tab, `leave_channel_locally` removes it).
    /// The server's wider public directory lives in `known_channels`.
    pub channels: Vec<ChannelTab>,
    pub selected_channel: usize,
    /// Which of the top row's two selectors is focused - whichever it is,
    /// its own selection (`selected_channel` or `selected_dm`) is what the
    /// view below renders. Kept in step with `active_private_room`:
    /// `Channels` always means no room is open, `Dms` always means
    /// `selected_dm`'s room is.
    pub selector_focus: SelectorFocus,
    /// Whether the focused selector's dropdown - the list of every entry
    /// it holds *except* the one it names - is open over the view. Opened
    /// by the focused selector's own outward key (`[` on the left one, `]`
    /// on the right one), closed by Escape, Enter, Tab, the opposite key,
    /// or `SELECTOR_DROPDOWN_IDLE_TIMEOUT` of nothing driving it.
    pub selector_dropdown_open: bool,
    /// When the open dropdown was last driven - opened, or moved with
    /// Up/Down - which `tick_selector_dropdown` measures its idle timeout
    /// from. `None` whenever no dropdown is open.
    selector_dropdown_since: Option<Instant>,
    /// Every public channel the server has announced (`ChannelList` at
    /// connect, `ChannelCreated` live) - the rows of the `/channels`
    /// modal, whether or not the user has joined them.
    pub known_channels: Vec<ChannelInfo>,
    /// Selected row of the `/channels` modal, into `known_channels`.
    pub channels_popup_selected: usize,
    pub known_users: HashMap<UserId, UserInfo>,
    /// Users whose connection has closed entirely (`on_user_offline`), as
    /// opposed to merely leaving one channel while staying connected
    /// (`on_user_left`). A `UserId` is never reused (PROTOCOL.md §3), so
    /// once inserted here an entry is never removed for the rest of the
    /// session - there's no way for the same identity to come back online.
    pub offline: HashSet<UserId>,
    /// The state of the direct peer-to-peer link to each peer, as reported
    /// by `p2p::PeerLinkManager` through `P2pEvent::LinkStatusChanged` -
    /// what colours a name in the sidebar (`render_sidebar`). A peer with
    /// no entry has no link yet, which reads the same as `Connecting`:
    /// content addressed to them is queued, not delivered.
    pub link_status: HashMap<UserId, LinkStatus>,
    pub private_rooms: HashMap<UserId, PrivateRoom>,
    /// Every open DM in the order it was first opened - `private_rooms` is
    /// a `HashMap`, and the DM selector needs one stable order to name a
    /// "next" and a "previous" room by. Every insertion into
    /// `private_rooms` goes through `ensure_private_room`, which is what
    /// keeps the two in step.
    pub dm_order: Vec<UserId>,
    /// The DM the right-hand selector currently names, whether or not that
    /// selector is the focused one. `None` only while no room has ever
    /// been opened - which is also when that selector isn't rendered at
    /// all.
    pub selected_dm: Option<UserId>,
    pub active_private_room: Option<UserId>,
    pub focus: Focus,
    pub sidebar_selected: usize,
    pub message_selected: usize,
    pub input: String,
    pub mode: Mode,
    pub join_popup_input: String,
    /// Ctrl+J popup's Public/Private selector - defaults to `Private`,
    /// matching this popup's pre-existing (private-only) behavior before
    /// this selector existed.
    pub join_popup_kind: ChannelKind,
    /// Ctrl+J popup's optional password field, shown/typeable only while
    /// `join_popup_kind == ChannelKind::Private`. Plaintext in memory,
    /// masked (`"*".repeat(...)`) at render time only - mirrors
    /// `ui_connect_popup::ServerKeyFields::password`.
    pub join_popup_password: String,
    pub(crate) join_popup_focus: JoinPopupFocus,
    /// Which channel name the password-entry popup
    /// (`Mode::ChannelPasswordPopup`) is currently retrying - set by
    /// `on_channel_join_rejected`, cleared on Esc or on submitting.
    pub channel_password_target: Option<String>,
    /// The password-entry popup's typed input.
    pub channel_password_input: String,
    /// A short message ("wrong password" / "too many attempts - try again
    /// later") shown on the popup - `None` on a fresh `PasswordRequired`
    /// with no prior guess yet.
    pub channel_password_error: Option<String>,
    /// The `/file` send flow's state (browse -> confirm), while `mode ==
    /// Mode::FileSend` - see `crate::client::tui::file_send`. `pub`, not
    /// `pub(crate)`, same as `ui_connect_popup::ConnectPopupState::browser`
    /// - tests need to overwrite the browser with a deterministic temp
    /// directory after `start_file_send` opens one at the process's real
    /// current directory (see that struct's tests).
    pub file_send: Option<super::file_send::FileSendState>,
    /// Every incoming file offer currently awaiting a decision, keyed by
    /// `(from, stream_id)` - the popup always shows whichever's at the
    /// front of `file_offer_queue`. Analogous to `identity_reviews`/
    /// `identity_review_queue`, but simpler: a decision here is final
    /// (`Accept`/`Reject` both remove the entry outright), there is no
    /// `Rejected`-but-reconsiderable state the way an identity review has.
    pub file_offers: HashMap<(UserId, u64), PendingFileOffer>,
    file_offer_queue: VecDeque<(UserId, u64)>,
    /// Reset to `Accept` every time a different offer becomes the one
    /// shown, same "always starts on the safe/common default" precedent
    /// `identity_review_focus` sets (there, `Reject`; here, `Accept` - see
    /// `PendingFileOffer`'s doc for why the default flips).
    file_offer_focus: FileOfferChoice,
    /// File offers received from a `Pending`/`Rejected` identity-review
    /// sender (`docs/PROTOCOL.md` §12), held back the same way
    /// `pending_messages` holds ordinary messages - queued for real
    /// (`push_file_offer`, popup + bell) only once that sender is
    /// `Accept`ed (`resolve_identity_accept`).
    pending_file_offers: HashMap<UserId, Vec<PendingFileOffer>>,
    /// Every incoming call invite currently awaiting a decision, keyed by
    /// `call_id` - mirrors `file_offers`/`file_offer_queue` exactly
    /// (queued-popup idiom, `Accept`-first default).
    pub call_invites: HashMap<u64, PendingCallInvite>,
    call_invite_queue: VecDeque<u64>,
    call_invite_focus: CallInviteChoice,
    /// Call invites received from a `Pending`/`Rejected` identity-review
    /// sender, held back the same way `pending_file_offers` holds a file
    /// offer - queued for real (`push_call_invite`, popup + bell) only once
    /// that sender is `Accept`ed (`resolve_identity_accept`).
    pending_call_invites: HashMap<UserId, Vec<PendingCallInvite>>,
    /// The live voice call we're currently on, if any - the permanent
    /// top-right indicator (`docs/SPEC.md` "Live voice calls") renders from
    /// this; the actual network/audio plumbing lives on `SessionState`
    /// (`crate::client::voice_call::ActiveCall`), which this mirrors
    /// read-only for presentation, same split every other feature here
    /// uses.
    pub call: Option<CallUiState>,
    /// The "/call will ring <n> users - go ahead?" confirmation, opened by
    /// `/call` before a single invite is sent. `None` when nothing is
    /// pending; only ever one at a time, same as every other popup here.
    pub call_confirm: Option<PendingCallConfirm>,
    call_confirm_focus: CallConfirmChoice,
    /// The local "generate and share a fresh OTP pad?" confirmation opened
    /// by `/otp` when no keychain entry exists yet
    /// (`client::otp::handle_otp_command`) - `None` when nothing is
    /// pending. Only ever one at a time: `/otp` itself is unreachable while
    /// any modal popup (including this one) is already absorbing input.
    otp_generate_confirm: Option<PendingOtpGenerate>,
    otp_generate_focus: OtpChoice,
    /// The pad-size prompt shown right after accepting `otp_generate_confirm`
    /// - carries the same peer info forward (nothing about who/what was
    /// asked changes, only whether a size has been chosen yet). `None`
    /// whenever `otp_generate_confirm` is, and vice versa - they're never
    /// both open, see `handle_key`'s ordering.
    otp_size_input: Option<PendingOtpGenerate>,
    /// Digits typed so far for `otp_size_input` - a plain `String` rather
    /// than a parsed number so an in-progress, momentarily-invalid edit
    /// (a leading digit before more follow, or a backspace mid-edit) is
    /// never rejected while still being typed; only Enter validates.
    pub otp_size_text: String,
    /// Set by an out-of-range or unparseable submission
    /// (`crypto::otp::otp_size_mb_in_range`) - shown under the input,
    /// cleared the next time the popup opens or a key changes the text.
    pub otp_size_error: Option<String>,
    /// Every incoming OTP session proposal currently awaiting a decision,
    /// keyed by the sender - mirrors `file_offers`/`file_offer_queue`
    /// exactly (queued-popup idiom, `Accept`-first default).
    otp_invites: HashMap<UserId, PendingOtpInvite>,
    otp_invite_queue: VecDeque<UserId>,
    otp_invite_focus: OtpChoice,
    /// The most recent OTP session outcome ("OTP session started at ..."
    /// in green, or a cancellation/failure in red) - a small always-visible
    /// notice, independent of `audio_error`'s suppressed-by-design banner
    /// (see that field's callers) since this one must actually be seen:
    /// "both parties should be aware if OTP session started/failed" is a
    /// hard requirement, not a best-effort one. Also used for the "unknown
    /// command" notice (`submit_input`). Auto-clears
    /// `STATUS_NOTICE_TIMEOUT` after it was pushed (`tick_status_notice`)
    /// so a stale outcome never squats on the corner of the screen.
    pub status_notice: Option<(String, bool)>,
    /// When `status_notice` was last pushed - what `tick_status_notice`
    /// measures the timeout from. `None` whenever `status_notice` is.
    status_notice_since: Option<Instant>,
    /// Peers a mutual-consent OTP session has genuinely started with in
    /// this connection (set alongside the "OTP session started" notice,
    /// `client::otp::accept_invite`/`on_key_setup_ack`) - drives the shield
    /// prefix a DM room's messages get while it's active
    /// (`render_messages`). Scoped to DMs: OTP's own UI surface (`/otp`,
    /// both popups) only ever exists inside a private room, so that is
    /// where "in OTP mode" has an unambiguous meaning - a channel send may
    /// wrap per-recipient under a contact's pad too, but a channel log has
    /// no single peer for a shield to describe.
    otp_active_peers: HashSet<UserId>,
    /// Live `otp --show-contact` snapshots for peers in `otp_active_peers`,
    /// driving the OTP session header's Seq/Offset/remaining figures
    /// (`direct_message::render_otp_header`). Populated once immediately
    /// when a session starts (`client::otp::accept_invite`/`on_key_setup_ack`),
    /// then kept live two ways: event-driven, refreshed the instant this
    /// contact's pad is actually spent in either direction (every genuine
    /// send/receive in `client::otp.rs` calls `refresh_otp_key_status` right
    /// after it succeeds), and as a roughly-once-a-second safety net for
    /// whichever peer's private room is currently open (`session.rs`'s tick
    /// loop, `otp::poll_key_status`) - covering anything that isn't this
    /// app's own send/receive. Never cleared once set: a stale-but-correct
    /// figure for a peer navigated away from and back to is a better first
    /// frame than a blank one while the next update is in flight.
    otp_key_status: HashMap<UserId, crate::client::otp_cli::ContactDetail>,
    /// Whether a previously-received voice message is currently being
    /// replayed (Enter on a `MessageBody::Voice` log entry) - while `true`,
    /// Escape stops that playback instead of its usual meaning (closing the
    /// current private room). Set when `ReplayVoice` is produced, cleared
    /// either by Escape itself or by `session.rs` once the mixer reports
    /// that source has actually finished playing
    /// (`voice::MixerCmd`'s `on_finished` callback) - so this stays
    /// accurate even if the clip finishes on its own.
    pub replaying: bool,
    pub recording: bool,
    /// Which trigger started the current recording - `None` whenever
    /// `recording` is `false`. See `RecordSource`.
    pub(crate) recording_source: Option<RecordSource>,
    /// Timestamp of the most recent Space press/repeat while recording;
    /// `tick_recording_timeout` watches this to detect release on
    /// terminals that never send `KeyEventKind::Release`. `pub(crate)`
    /// because the mail compose view's own Space branch
    /// (`crate::client::tui::otp_mail`) drives the same machinery.
    pub(crate) recording_last_seen: Option<Instant>,
    /// The OTP mail surface (compose view + mailbox popup + reader),
    /// `Some` while the `/mail`//`/mailbox` full-screen view is open - see
    /// `crate::client::tui::otp_mail`. Every key routes there while open
    /// (`handle_key`), and `render` swaps the whole screen for it.
    pub otp_mail: Option<super::otp_mail::OtpMailState>,
    /// Whether this terminal actually delivers a real `KeyEventKind::Release`
    /// for Space (queried once at startup via `crossterm::terminal::
    /// supports_keyboard_enhancement`; see `set_keyboard_release_reporting`).
    /// When `true`, `tick_recording_timeout` never auto-stops on its own -
    /// recording only ever ends on that genuine release, never on a guess
    /// from silence. Defaults to `false` (the safe assumption) so a
    /// terminal that can't report release at all still has some way to
    /// stop a recording.
    keyboard_release_reporting: bool,
    /// Set when the last recording attempt or an incoming/replayed voice
    /// playback failed (e.g. no microphone/speaker). Tracked internally
    /// (e.g. so `recording_failed` still turns off the misleading
    /// "recording..." indicator) but deliberately not rendered: this
    /// environment's audio stack surfaces plenty of transient,
    /// self-recovering errors (buffer under/overruns, PulseAudio status-
    /// query hiccups) that aren't worth interrupting the screen for.
    /// Cleared as soon as another recording starts.
    pub audio_error: Option<String>,
    pub blink_on: bool,
    /// Whether the `Ctrl+H` help overlay is showing. Deliberately a flag
    /// independent of `Mode`/`focus` rather than another `Mode` variant:
    /// it needs to open and close on top of *any* view or mode (including
    /// mid-recording or with the join-channel popup up) and return things
    /// to exactly whatever they were underneath, rather than replacing
    /// them.
    pub help_open: bool,
    /// First visible line index into `HELP_BODY` while the help overlay is
    /// open - `Up`/`Down`/`PageUp`/`PageDown`/`Home`/`End` adjust it
    /// (`handle_key`), reset to `0` every time the overlay is freshly
    /// opened (`tick`-independent, done right in the Ctrl+H toggle) so it
    /// never reopens mid-scroll from last time. Clamped loosely here
    /// (against the total line count) and precisely at render time
    /// (`render_help_popup`, against the popup's actual visible height,
    /// which `UiState` has no reason to know) - see there.
    help_scroll: usize,
    /// Every peer with an outstanding or resolved-as-`Rejected` identity
    /// mismatch this session (`docs/PROTOCOL.md` §12) - absence means
    /// "trusted normally" (never mismatched, or `Accepted`, which removes
    /// the entry entirely). Populated by `push_identity_review` (called
    /// from `session::check_identity`/`handle_key_rotated` on a mismatch),
    /// resolved by `resolve_identity_accept`/`resolve_identity_reject`
    /// (called from `session::handle_ui_action`'s `AcceptIdentity`/
    /// `RejectIdentity` arms once the actual `id_store`/`rekey` side
    /// effects are done).
    pub identity_reviews: HashMap<UserId, IdentityReview>,
    /// Peers with a `Pending` review not yet shown, front-first - the popup
    /// always shows `identity_review_queue.front()`; resolving it (Accept
    /// or Reject) pops it and reveals the next one, if any, so several
    /// mismatches arriving close together are shown one at a time rather
    /// than clobbering each other.
    identity_review_queue: VecDeque<UserId>,
    /// Which button is focused in the currently-open popup. Reset to
    /// `Reject` (the non-trusting default) every time a different peer's
    /// review becomes the one shown, so accepting always takes a deliberate
    /// move off the safe default rather than an accidental double-Enter.
    identity_review_focus: IdentityChoice,
    /// Messages/streams received from a `Pending`/`Rejected` peer, held
    /// back from the visible channel/DM log until they're `Accepted`
    /// (`docs/PROTOCOL.md` §12 "hold and reveal") - see `HeldMessage`.
    pub pending_messages: HashMap<UserId, Vec<HeldMessage>>,
    /// System-wide CPU usage percentage, refreshed roughly every
    /// `sysstats::CPU_HEALTHY_MAX_PCT`-adjacent cadence by
    /// `session::run_connected_session` (`sysstats::CpuMonitor`) and shown
    /// in the channel view's header as `CPU:<pct>%`, right before the
    /// `Ctrl+H: Help` hint. `UiState` itself has no idea how this is
    /// measured, only how to render it - same division of labor as
    /// `key_regenerating`.
    pub cpu_usage_pct: f32,
    /// Rolling classification of how quickly protocol messages are moving
    /// over the socket, refreshed once a second by `session::
    /// run_connected_session` from `SessionState`'s `netstats::ConnStats`
    /// and shown in the header as `Conn:<quality>`, right before the CPU
    /// indicator. Defaults to `Unknown` (rendered `-`) until the first
    /// message of the session is observed.
    pub conn_quality: crate::client::netstats::ConnQuality,
}

impl UiState {
    pub fn new(own_name: String) -> Self {
        Self {
            own_id: None,
            own_name,
            channels: Vec::new(),
            selected_channel: 0,
            selector_focus: SelectorFocus::Channels,
            selector_dropdown_open: false,
            selector_dropdown_since: None,
            known_channels: Vec::new(),
            channels_popup_selected: 0,
            known_users: HashMap::new(),
            offline: HashSet::new(),
            link_status: HashMap::new(),
            private_rooms: HashMap::new(),
            dm_order: Vec::new(),
            selected_dm: None,
            active_private_room: None,
            focus: Focus::Input,
            sidebar_selected: 0,
            message_selected: 0,
            input: String::new(),
            mode: Mode::Normal,
            join_popup_input: String::new(),
            join_popup_kind: ChannelKind::Private,
            join_popup_password: String::new(),
            join_popup_focus: JoinPopupFocus::Name,
            channel_password_target: None,
            channel_password_input: String::new(),
            channel_password_error: None,
            file_send: None,
            file_offers: HashMap::new(),
            file_offer_queue: VecDeque::new(),
            file_offer_focus: FileOfferChoice::Accept,
            pending_file_offers: HashMap::new(),
            call_invites: HashMap::new(),
            call_invite_queue: VecDeque::new(),
            call_invite_focus: CallInviteChoice::Accept,
            pending_call_invites: HashMap::new(),
            call: None,
            call_confirm: None,
            call_confirm_focus: CallConfirmChoice::Confirm,
            otp_generate_confirm: None,
            otp_generate_focus: OtpChoice::Accept,
            otp_size_input: None,
            otp_size_text: String::new(),
            otp_size_error: None,
            otp_invites: HashMap::new(),
            otp_invite_queue: VecDeque::new(),
            otp_invite_focus: OtpChoice::Accept,
            status_notice: None,
            status_notice_since: None,
            otp_active_peers: HashSet::new(),
            otp_key_status: HashMap::new(),
            replaying: false,
            recording: false,
            recording_source: None,
            recording_last_seen: None,
            otp_mail: None,
            keyboard_release_reporting: false,
            audio_error: None,
            blink_on: false,
            help_open: false,
            help_scroll: 0,
            identity_reviews: HashMap::new(),
            identity_review_queue: VecDeque::new(),
            identity_review_focus: IdentityChoice::Reject,
            pending_messages: HashMap::new(),
            cpu_usage_pct: 0.0,
            conn_quality: crate::client::netstats::ConnQuality::Unknown,
        }
    }

    /// Called periodically by `session::run_connected_session` with a
    /// freshly-sampled CPU percentage (`sysstats::CpuMonitor::refresh`).
    /// Clamped defensively to `0.0..=100.0`, same bound `CpuMonitor`
    /// itself already applies - a second clamp here costs nothing and
    /// keeps `UiState` correct even if a future caller feeds it a raw
    /// unclamped value.
    pub fn set_cpu_usage(&mut self, pct: f32) {
        self.cpu_usage_pct = pct.clamp(0.0, 100.0);
    }

    /// Called once a second by `session::run_connected_session` with the
    /// freshly-classified connection quality (`netstats::ConnStats::quality`).
    pub fn set_conn_quality(&mut self, quality: crate::client::netstats::ConnQuality) {
        self.conn_quality = quality;
    }

    // -------------------------------------------------------------
    // Identity review (docs/PROTOCOL.md §12): manual Accept/Reject
    // -------------------------------------------------------------

    /// Records a newly-detected identity mismatch for `peer` and, if no
    /// review is currently on screen, opens this one immediately (auto-pop
    /// on detection). If `peer` already had a review pending or rejected
    /// (e.g. another mismatched rotation attempt arrives before the first
    /// was decided), its case/message are updated in place and it's
    /// re-queued as `Pending` rather than duplicated - always reflects the
    /// *latest* attempt.
    pub fn push_identity_review(
        &mut self,
        peer: UserId,
        nickname: String,
        message: String,
        case: IdentityCase,
    ) {
        let already_queued = self.identity_review_queue.contains(&peer);
        self.identity_reviews.insert(
            peer,
            IdentityReview {
                nickname,
                message,
                case,
                status: IdentityStatus::Pending,
            },
        );
        if !already_queued {
            self.identity_review_queue.push_back(peer);
        }
        if self.identity_review_queue.front() == Some(&peer) {
            self.identity_review_focus = IdentityChoice::Reject;
        }
    }

    /// Starts a mismatch review the instant it's detected, without
    /// showing anything yet (`session::check_identity`'s mismatch arm) -
    /// gates messaging with `peer` immediately (`is_trust_gated`), same as
    /// `push_identity_review` does, but leaves the popup itself for
    /// `reveal_identity_review` once this connection's address/device id
    /// are known (docs/PROTOCOL.md §12.7). Never queued: `identity_review_open`
    /// only ever shows the queue front, and this is deliberately kept out
    /// of it until revealed.
    pub fn begin_identity_review(&mut self, peer: UserId, nickname: String, case: IdentityCase) {
        self.identity_reviews.insert(
            peer,
            IdentityReview {
                nickname,
                message: String::new(),
                case,
                status: IdentityStatus::AwaitingPeerInfo,
            },
        );
    }

    /// Finishes a review `begin_identity_review` started, once its caller
    /// has a `message` worth showing (old vs. new address/device id
    /// filled in) - moves it to `Pending`, queues it, and chimes exactly
    /// as `push_identity_review` would have. Returns whether there was
    /// actually an `AwaitingPeerInfo` review to reveal (`false` if `peer`
    /// has no review, or it was already revealed/resolved) - a caller
    /// only plays the chime on `true`, so this never re-alerts on a
    /// second, later transition for the same peer.
    pub fn reveal_identity_review(&mut self, peer: UserId, message: String) -> bool {
        match self.identity_reviews.get_mut(&peer) {
            Some(review) if review.status == IdentityStatus::AwaitingPeerInfo => {
                review.message = message;
                review.status = IdentityStatus::Pending;
            }
            _ => return false,
        }
        if !self.identity_review_queue.contains(&peer) {
            self.identity_review_queue.push_back(peer);
        }
        if self.identity_review_queue.front() == Some(&peer) {
            self.identity_review_focus = IdentityChoice::Reject;
        }
        true
    }

    /// The review currently shown in the popup, if any.
    pub fn identity_review_open(&self) -> Option<&IdentityReview> {
        let peer = self.identity_review_queue.front()?;
        self.identity_reviews.get(peer)
    }

    /// Whether `peer` currently has an unresolved-trust review (`Pending`
    /// or `Rejected` - both gate messaging identically, see `docs/PROTOCOL.md`
    /// §12). Absence (`None`/normal peer) is the common case.
    pub fn is_trust_gated(&self, peer: UserId) -> bool {
        self.identity_reviews.contains_key(&peer)
    }

    /// Buffers a message/stream-placeholder from a trust-gated `from`
    /// instead of it going into the visible log - called by
    /// `on_channel_message`/`on_direct_message` and their stream
    /// counterparts whenever `is_trust_gated(from)`.
    pub(crate) fn hold_message(&mut self, from: UserId, channel: Option<String>, entry: LogEntry) {
        self.pending_messages
            .entry(from)
            .or_default()
            .push(HeldMessage { channel, entry });
    }

    /// Held-message counterpart for an incoming file offer from a
    /// `Pending`/`Rejected` identity-review sender - see
    /// `pending_file_offers`'s doc.
    pub fn hold_file_offer(&mut self, offer: PendingFileOffer) {
        self.pending_file_offers
            .entry(offer.from)
            .or_default()
            .push(offer);
    }

    /// Held-invite counterpart for an incoming call invite from a
    /// `Pending`/`Rejected` identity-review sender - see
    /// `pending_call_invites`'s doc.
    pub fn hold_call_invite(&mut self, invite: PendingCallInvite) {
        self.pending_call_invites
            .entry(invite.from)
            .or_default()
            .push(invite);
    }

    /// Removes `peer` from the review queue wherever it is - not
    /// necessarily the front - resetting focus if the popup on screen
    /// changed. Removing by identity rather than a plain `pop_front` keeps
    /// this correct even if a future resolution path ever resolves
    /// something other than the front entry.
    fn remove_from_identity_review_queue(&mut self, peer: UserId) {
        let was_front = self.identity_review_queue.front() == Some(&peer);
        self.identity_review_queue.retain(|p| *p != peer);
        if was_front {
            self.identity_review_focus = IdentityChoice::Reject;
        }
    }

    /// Applies an Accept decision already carried out by the caller
    /// (`session::handle_ui_action`'s `AcceptIdentity` arm has already
    /// installed the key and persisted `id_store`) - removes `peer` from
    /// review entirely (back to normal/trusted), drains anything held for
    /// them (messages into the real channel/DM logs, file offers into
    /// `file_offer_queue`) in arrival order, and opens the next queued
    /// review if any. Returns whether the caller (which owns audio) should
    /// play the file-offer bell - true iff a held offer just became the
    /// front of `file_offer_queue`.
    pub fn resolve_identity_accept(&mut self, peer: UserId) -> bool {
        self.identity_reviews.remove(&peer);
        self.remove_from_identity_review_queue(peer);
        if let Some(held) = self.pending_messages.remove(&peer) {
            for HeldMessage { channel, entry } in held {
                match channel {
                    Some(name) => {
                        let is_current = self.is_viewing_channel(&name);
                        if let Some(tab) = self.channels.iter_mut().find(|c| c.name == name) {
                            push_log_entry(
                                &mut tab.log,
                                &mut self.message_selected,
                                is_current,
                                entry,
                            );
                            if !is_current {
                                tab.unread = true;
                            }
                        }
                    }
                    None => {
                        // The room may not exist yet - a held DM never creates
                        // one (mirrors `on_direct_message`'s trust-gated path).
                        let is_current = self.active_private_room == Some(peer);
                        let from_name = entry.from_name.clone();
                        let fallback_peer =
                            self.known_users
                                .get(&peer)
                                .cloned()
                                .unwrap_or_else(|| UserInfo {
                                    id: peer,
                                    name: from_name,
                                    public_key_der: Vec::new(),
                                    key_mode: crate::proto::KeyMode::None,
                                });
                        self.ensure_private_room(peer, fallback_peer);
                        let Some(room) = self.private_rooms.get_mut(&peer) else {
                            continue;
                        };
                        push_log_entry(
                            &mut room.log,
                            &mut self.message_selected,
                            is_current,
                            entry,
                        );
                        if !is_current {
                            room.unread = true;
                        }
                    }
                }
            }
        }
        let mut play_bell = false;
        if let Some(offers) = self.pending_file_offers.remove(&peer) {
            for offer in offers {
                if self.push_file_offer(offer) {
                    play_bell = true;
                }
            }
        }
        if let Some(invites) = self.pending_call_invites.remove(&peer) {
            for invite in invites {
                if self.push_call_invite(invite) {
                    play_bell = true;
                }
            }
        }
        play_bell
    }

    /// Applies a Reject decision: flips `peer`'s review to `Rejected` (kept,
    /// not removed - stays red, re-openable via Enter) and opens the next
    /// queued review if any. Held messages stay held.
    pub fn resolve_identity_reject(&mut self, peer: UserId) {
        if let Some(review) = self.identity_reviews.get_mut(&peer) {
            review.status = IdentityStatus::Rejected;
        }
        self.remove_from_identity_review_queue(peer);
    }

    /// Re-opens the popup for an already-`Rejected` peer (Enter on their
    /// red sidebar entry) - a no-op if they're not actually in review,
    /// already the one showing, or still `AwaitingPeerInfo` (there is
    /// nothing to show yet; `is_trust_gated` already blocks messaging with
    /// them in the meantime, and `reveal_identity_review` is what will
    /// actually open this once it has something to display).
    pub(crate) fn reopen_identity_review(&mut self, peer: UserId) {
        match self.identity_reviews.get(&peer) {
            Some(review) if review.status != IdentityStatus::AwaitingPeerInfo => {}
            _ => return,
        }
        if self.identity_review_queue.front() == Some(&peer) {
            return;
        }
        self.identity_review_queue.retain(|p| *p != peer);
        self.identity_review_queue.push_front(peer);
        self.identity_review_focus = IdentityChoice::Reject;
    }

    // -------------------------------------------------------------
    // File transfer (`docs/PROTOCOL.md`'s file transfer section):
    // consent-gated Accept/Reject, same modal-queue idiom as identity
    // review above.
    // -------------------------------------------------------------

    /// Queues `offer` and, if nothing else is currently showing, makes it
    /// the one shown right away. Returns whether it became the front of
    /// the queue - the caller (`session.rs`, which owns audio) uses this to
    /// decide whether to play the bell.
    pub fn push_file_offer(&mut self, offer: PendingFileOffer) -> bool {
        let key = (offer.from, offer.stream_id);
        self.file_offers.insert(key, offer);
        self.file_offer_queue.push_back(key);
        let is_front = self.file_offer_queue.front() == Some(&key);
        if is_front {
            self.file_offer_focus = FileOfferChoice::Accept;
        }
        is_front
    }

    /// The offer currently shown in the popup, if any.
    pub fn file_offer_open(&self) -> Option<&PendingFileOffer> {
        let key = self.file_offer_queue.front()?;
        self.file_offers.get(key)
    }

    /// Removes and returns the offer for `(from, stream_id)` - a decision
    /// here is always final (unlike an identity review, there's no
    /// `Rejected`-but-reconsiderable state), so nothing is kept around
    /// afterward.
    pub fn take_file_offer(&mut self, from: UserId, stream_id: u64) -> Option<PendingFileOffer> {
        let key = (from, stream_id);
        self.file_offer_queue.retain(|k| *k != key);
        self.file_offer_focus = FileOfferChoice::Accept;
        self.file_offers.remove(&key)
    }

    // -------------------------------------------------------------
    // Live voice calls (`docs/PROTOCOL.md` "Live voice calls"): the invite
    // Accept/Reject popup is the same modal-queue idiom as file transfer's
    // above; `call` (below) is the separate, always-visible "on a call
    // right now" indicator, unrelated to the popup queue.
    // -------------------------------------------------------------

    /// Queues `invite` and, if nothing else is currently showing, makes it
    /// the one shown right away - mirrors `push_file_offer` exactly.
    pub fn push_call_invite(&mut self, invite: PendingCallInvite) -> bool {
        let key = invite.call_id;
        self.call_invites.insert(key, invite);
        self.call_invite_queue.push_back(key);
        let is_front = self.call_invite_queue.front() == Some(&key);
        if is_front {
            self.call_invite_focus = CallInviteChoice::Accept;
        }
        is_front
    }

    /// The invite currently shown in the popup, if any.
    pub fn call_invite_open(&self) -> Option<&PendingCallInvite> {
        let key = self.call_invite_queue.front()?;
        self.call_invites.get(key)
    }

    /// Accept on the invite popup. An invite whose call has already ended
    /// (`mark_call_invite_ended`) is taken off screen with
    /// `CALL_ALREADY_ENDED_NOTICE` instead of starting anything - the
    /// answer is still spent, there is simply nothing left to join. The
    /// session repeats the check when it handles the action
    /// (`crate::client::voice_call::accept_invite`), for the case where
    /// the `CallEnd` lands in between.
    fn accept_call_invite(&mut self, call_id: u64) -> Option<UiAction> {
        if self.call_invites.get(&call_id).is_some_and(|i| i.ended) {
            self.take_call_invite(call_id);
            self.push_status_notice(CALL_ALREADY_ENDED_NOTICE.to_string(), false);
            return None;
        }
        Some(UiAction::AcceptCallInvite { call_id })
    }

    /// The invite we hold for `call_id`, answered or not - lets the
    /// session check who sent it before acting on a `CallEnd` naming it
    /// (`crate::client::voice_call::on_call_end`).
    pub fn call_invite_for(&self, call_id: u64) -> Option<&PendingCallInvite> {
        self.call_invites.get(&call_id)
    }

    /// Everyone on our own call's roster who was invited and has not
    /// answered yet - who `end_own_call` must also tell, on top of the
    /// participants it is actually exchanging audio with.
    pub fn call_invitees_awaiting_answer(&self) -> Vec<UserId> {
        self.call
            .as_ref()
            .map(|call| {
                call.members
                    .iter()
                    .filter(|m| m.state == CallMemberState::Invited)
                    .map(|m| m.id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Marks the still-unanswered invite for `call_id` as belonging to a
    /// call that has since ended, if we hold one. Returns whether it did -
    /// the caller (`crate::client::voice_call::on_call_end`) uses that to
    /// tell "this named an invite of ours" from "this named nothing we
    /// know about". The popup stays up: the user is still owed an answer,
    /// it just can no longer join anything.
    pub fn mark_call_invite_ended(&mut self, call_id: u64) -> bool {
        match self.call_invites.get_mut(&call_id) {
            Some(invite) => {
                invite.ended = true;
                true
            }
            None => false,
        }
    }

    /// Removes and returns the invite for `call_id` - a decision here is
    /// always final, same as a file offer's.
    pub fn take_call_invite(&mut self, call_id: u64) -> Option<PendingCallInvite> {
        self.call_invite_queue.retain(|k| *k != call_id);
        self.call_invite_focus = CallInviteChoice::Accept;
        self.call_invites.remove(&call_id)
    }

    /// Starts showing the call modal and the permanent top-right "on a
    /// call" indicator - called once we become an active participant,
    /// whether as the initiator or an accepter
    /// (`crate::client::voice_call::begin_own_call`). `host` is whoever
    /// started the call: ourselves for a `/call`, the inviter for an
    /// invite we accepted. The modal opens up front (`minimized: false`)
    /// rather than folded away - a call starting is exactly the moment its
    /// roster matters most; Escape folds it into its tab from there.
    pub fn begin_call(&mut self, call_id: u64, channel: Option<String>, host: UserId) {
        let mut members = Vec::new();
        if let Some(own_id) = self.own_id {
            members.push(CallMember {
                id: own_id,
                name: self.own_display_name(),
                state: CallMemberState::InCall,
                host_muted: false,
                self_muted: false,
                level: 0,
            });
        }
        self.call = Some(CallUiState {
            call_id,
            channel,
            muted: false,
            host,
            members,
            selected: 0,
            started_at: Instant::now(),
            elapsed_secs: 0,
            minimized: false,
            invite_picker: None,
        });
        self.sort_call_members();
    }

    /// Clears the modal, the header's `\u{1F534} Call Ctrl+R` indicator and the
    /// permanent banner - called once we've left the call
    /// (`crate::client::voice_call::end_own_call`).
    pub fn end_call(&mut self) {
        self.call = None;
    }

    pub fn set_call_muted(&mut self, muted: bool) {
        if let Some(call) = self.call.as_mut() {
            call.muted = muted;
        }
        // Our own row says the same thing to us as it does to everyone
        // else, without waiting for our own announcement to come back.
        if let Some(own_id) = self.own_id {
            self.set_call_member_self_muted(own_id, muted);
        }
    }

    /// Refreshes the modal's live duration readout - driven off the
    /// session's ticker with `Instant::now()`, taken as a parameter rather
    /// than read here so the whole readout is deterministic under test.
    pub fn tick_call_duration(&mut self, now: Instant) {
        if let Some(call) = self.call.as_mut() {
            call.elapsed_secs = now.saturating_duration_since(call.started_at).as_secs();
        }
    }

    /// Our own nickname, as the roster should print it: the name the
    /// server accepted, from `known_users` when it has our own entry and
    /// otherwise the one we connected under (`own_name`) - a call can
    /// start before we have ever appeared in a channel roster.
    fn own_display_name(&self) -> String {
        self.own_id
            .and_then(|id| self.known_users.get(&id))
            .map(|u| u.name.clone())
            .unwrap_or_else(|| self.own_name.clone())
    }

    /// Host first, everyone else in the order we learned about them - the
    /// order `docs/SPEC.md` "Live voice calls" specifies for the roster.
    /// Keeps the cursor on whoever it was on rather than on an index.
    fn sort_call_members(&mut self) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        let cursor_on = call.members.get(call.selected).map(|m| m.id);
        if let Some(idx) = call.members.iter().position(|m| m.id == call.host)
            && idx != 0
        {
            let host = call.members.remove(idx);
            call.members.insert(0, host);
        }
        call.selected = cursor_on
            .and_then(|id| call.members.iter().position(|m| m.id == id))
            .unwrap_or(0);
    }

    /// Upserts one roster row, leaving an existing row's host-mute state
    /// and meter alone (only its `state`/`name` are refreshed) - every
    /// roster mutation below funnels through this so the host-first
    /// ordering is maintained in exactly one place.
    fn upsert_call_member(&mut self, peer: UserId, name: String, state: CallMemberState) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        match call.members.iter_mut().find(|m| m.id == peer) {
            Some(existing) => {
                existing.name = name;
                existing.state = state;
            }
            None => call.members.push(CallMember {
                id: peer,
                name,
                state,
                host_muted: false,
                self_muted: false,
                level: 0,
            }),
        }
        self.sort_call_members();
    }

    /// Records a newly-connected participant on the roster - a no-op if
    /// we're not actually shown as on a call (defensive; shouldn't happen,
    /// since `crate::client::voice_call` only ever adds a participant to an
    /// `ActiveCall` that already exists).
    pub fn on_call_participant_joined(&mut self, peer: UserId, name: String) {
        self.upsert_call_member(peer, name, CallMemberState::InCall);
    }

    /// Records an invite we (as host) have just sent - the row shows
    /// `INVITED` until they answer.
    pub fn on_call_invite_sent(&mut self, peer: UserId, name: String) {
        self.upsert_call_member(peer, name, CallMemberState::Invited);
    }

    /// Records a `CallReject` from someone we invited. Only ever moves an
    /// `Invited` row to `Rejected`: a stale reject from someone who has
    /// since joined (a second invite they answered twice) must not knock
    /// them off the call.
    pub fn on_call_invite_rejected(&mut self, peer: UserId) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
            && member.state == CallMemberState::Invited
        {
            member.state = CallMemberState::Rejected;
            member.level = 0;
        }
    }

    /// Drops someone who left the call outright (`CallEnd`, or a dead
    /// link) - unlike a reject, there is no lingering row: they were on
    /// the call and now are not.
    pub fn on_call_participant_left(&mut self, peer: UserId) {
        let Some(call) = self.call.as_mut() else {
            return;
        };
        call.members.retain(|m| m.id != peer);
        call.selected = call.selected.min(call.members.len().saturating_sub(1));
    }

    /// Applies `peer`'s own mute state to the roster - see
    /// `CallMember::self_muted`. Never touches anyone's capture: this is
    /// what that person says about their own microphone, which everyone
    /// on the call is shown.
    pub fn set_call_member_self_muted(&mut self, peer: UserId, muted: bool) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
        {
            member.self_muted = muted;
            if muted {
                member.level = 0;
            }
        }
    }

    /// Applies the host's mute decision for `peer` to the roster - see
    /// `CallMember::host_muted`. Whether *we* are the one it silences is
    /// the session's business (`voice_call::on_call_mute`); this is only
    /// what everyone sees.
    pub fn set_call_member_host_muted(&mut self, peer: UserId, muted: bool) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
        {
            member.host_muted = muted;
            if muted {
                member.level = 0;
            }
        }
    }

    /// Feeds one voice meter (`crate::client::voice::level_from_pcm`) -
    /// called for our own captured audio and for every participant's
    /// decoded audio, from the workers that already hold that PCM.
    pub fn set_call_level(&mut self, peer: UserId, level: u8) {
        if let Some(call) = self.call.as_mut()
            && let Some(member) = call.members.iter_mut().find(|m| m.id == peer)
        {
            member.level = level.min(100);
        }
    }

    /// Everyone we could invite to the call we're hosting: someone we
    /// share a joined channel or DM history with (`has_reason_to_keep_link`,
    /// the same relationship bar a direct link already has to clear),
    /// online, not trust-gated, not under an OTP session (which has no
    /// live-streaming concept at all, `docs/PROTOCOL.md` 16), and not
    /// already on the roster. That last one is what makes "only one active
    /// invitation at a time per user" hold.
    pub fn call_invite_candidates(&self) -> Vec<(UserId, String)> {
        let Some(call) = self.call.as_ref() else {
            return Vec::new();
        };
        let mut out: Vec<(UserId, String)> = self
            .known_users
            .values()
            .filter(|u| {
                Some(u.id) != self.own_id
                    && !self.offline.contains(&u.id)
                    && !self.is_trust_gated(u.id)
                    && !self.is_otp_active(u.id)
                    && self.has_reason_to_keep_link(u.id)
                    && !call.members.iter().any(|m| {
                        m.id == u.id
                            && matches!(
                                m.state,
                                CallMemberState::InCall | CallMemberState::Invited
                            )
                    })
            })
            .map(|u| (u.id, u.name.clone()))
            .collect();
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out
    }

    /// Opens the host-only invite picker, snapshotting its candidate list.
    /// Returns whether it actually opened - `false` when we aren't the
    /// host, or nobody is left to invite (a notice is pushed for the
    /// latter, so the keypress is never silently ignored).
    pub fn open_call_invite_picker(&mut self) -> bool {
        let own_id = self.own_id;
        let Some(call) = self.call.as_ref() else {
            return false;
        };
        if !call.we_are_host(own_id) {
            return false;
        }
        let candidates = self.call_invite_candidates();
        if candidates.is_empty() {
            self.push_status_notice("nobody left to invite to this call".to_string(), false);
            return false;
        }
        if let Some(call) = self.call.as_mut() {
            call.invite_picker = Some(CallInvitePicker {
                candidates,
                selected: 0,
            });
        }
        true
    }

    /// Opens the local "generate and share a fresh OTP pad?" confirmation
    /// (`/otp` found no existing keychain entry) - see
    /// `client::otp::handle_otp_command`.
    pub fn open_otp_generate_confirm(
        &mut self,
        peer: UserId,
        peer_name: String,
        key_mode: KeyMode,
        pubkey_der: Vec<u8>,
    ) {
        self.otp_generate_confirm = Some(PendingOtpGenerate {
            peer,
            peer_name,
            key_mode,
            pubkey_der,
        });
        self.otp_generate_focus = OtpChoice::Accept;
    }

    pub fn take_otp_generate_confirm(&mut self) -> Option<PendingOtpGenerate> {
        self.otp_generate_focus = OtpChoice::Accept;
        self.otp_generate_confirm.take()
    }

    /// Read-only counterpart of `take_otp_generate_confirm`, for a caller
    /// that only wants to observe whether the prompt is showing (and who it
    /// names) without answering it - mirrors `otp_invite_open`.
    pub fn otp_generate_confirm_open(&self) -> Option<&PendingOtpGenerate> {
        self.otp_generate_confirm.as_ref()
    }

    /// Opens the pad-size prompt (`handle_key`'s Accept branch for
    /// `otp_generate_confirm`) - carries `pending`'s peer info forward
    /// unchanged, since accepting only decided *that* a pad gets
    /// generated, not how big.
    pub fn open_otp_size_input(&mut self, pending: PendingOtpGenerate) {
        self.otp_size_input = Some(pending);
        self.otp_size_text.clear();
        self.otp_size_error = None;
    }

    pub fn take_otp_size_input(&mut self) -> Option<PendingOtpGenerate> {
        self.otp_size_text.clear();
        self.otp_size_error = None;
        self.otp_size_input.take()
    }

    /// Read-only counterpart of `take_otp_size_input`, mirroring
    /// `otp_generate_confirm_open`.
    pub fn otp_size_input_open(&self) -> Option<&PendingOtpGenerate> {
        self.otp_size_input.as_ref()
    }

    /// Queues an incoming OTP session proposal - mirrors `push_file_offer`
    /// exactly, one sender at a time (a second proposal from the same
    /// sender while one is already queued simply replaces it, since only
    /// the latest is still meaningful).
    #[allow(clippy::too_many_arguments)]
    pub fn push_otp_invite(
        &mut self,
        from: UserId,
        from_name: String,
        contact_name: String,
        peer_encryption_key: Option<Vec<u8>>,
        peer_decryption_key: Option<Vec<u8>>,
        pad_size_mb: Option<u32>,
    ) {
        self.otp_invites.insert(
            from,
            PendingOtpInvite {
                from,
                from_name,
                contact_name,
                peer_encryption_key,
                peer_decryption_key,
                pad_size_mb,
            },
        );
        if !self.otp_invite_queue.contains(&from) {
            self.otp_invite_queue.push_back(from);
        }
        if self.otp_invite_queue.front() == Some(&from) {
            self.otp_invite_focus = OtpChoice::Accept;
        }
    }

    pub fn otp_invite_open(&self) -> Option<&PendingOtpInvite> {
        let from = self.otp_invite_queue.front()?;
        self.otp_invites.get(from)
    }

    pub fn take_otp_invite(&mut self) -> Option<PendingOtpInvite> {
        let from = self.otp_invite_queue.pop_front()?;
        self.otp_invite_focus = OtpChoice::Accept;
        self.otp_invites.remove(&from)
    }

    /// Sets the always-visible OTP/command status line - see
    /// `status_notice`'s field doc for why this is a separate, actually-
    /// rendered surface rather than reusing `audio_error`/`push_notice`.
    pub fn push_status_notice(&mut self, message: String, success: bool) {
        self.status_notice = Some((message, success));
        self.status_notice_since = Some(Instant::now());
    }

    /// Clears a status notice that has been showing for
    /// `STATUS_NOTICE_TIMEOUT` - called from the session's ticker, the
    /// same cadence `tick_recording_timeout` rides. A notice whose
    /// timestamp is missing (set by writing the pub field directly, as
    /// tests do) is adopted from `now` rather than left immortal.
    pub fn tick_status_notice(&mut self, now: Instant) {
        if self.status_notice.is_none() {
            self.status_notice_since = None;
            return;
        }
        match self.status_notice_since {
            Some(since) if now.duration_since(since) >= STATUS_NOTICE_TIMEOUT => {
                self.status_notice = None;
                self.status_notice_since = None;
            }
            None => self.status_notice_since = Some(now),
            _ => {}
        }
    }

    /// Records that a mutual-consent OTP session has genuinely started with
    /// `peer` - see `otp_active_peers`'s doc.
    pub fn mark_otp_active(&mut self, peer: UserId) {
        self.otp_active_peers.insert(peer);
    }

    /// Whether `peer`'s messages should carry the OTP shield prefix right
    /// now.
    pub fn is_otp_active(&self, peer: UserId) -> bool {
        self.otp_active_peers.contains(&peer)
    }

    /// Records `peer`'s latest `otp --show-contact` snapshot - see
    /// `otp_key_status`'s doc for who calls this and how often.
    pub fn set_otp_key_status(&mut self, peer: UserId, detail: crate::client::otp_cli::ContactDetail) {
        self.otp_key_status.insert(peer, detail);
    }

    /// `peer`'s most recently fetched key-metadata snapshot, if any -
    /// `render_otp_header` falls back to `ContactDetail::default()` (all
    /// zeros) when `None`, e.g. the brief window before a session's own
    /// first fetch completes.
    pub fn otp_key_status_for(&self, peer: UserId) -> Option<&crate::client::otp_cli::ContactDetail> {
        self.otp_key_status.get(&peer)
    }

    /// Finds the file-transfer log row matching `(from, stream_id)`
    /// (embedded in `MessageBody::File`, same `(from, stream_id)` matching
    /// `finalize_stream_entry` already uses for voice) wherever it lives -
    /// a channel tab or a private room - and applies `f` to its body.
    /// Nothing tracks which one a given transfer's row is in, so every
    /// tab/room is checked; a no-op if the row isn't found (e.g. already
    /// scrolled out - it never actually leaves the log, just stops
    /// matching once found once).
    fn update_file_entry(
        &mut self,
        from: UserId,
        stream_id: u64,
        f: impl FnOnce(&mut MessageBody),
    ) {
        let matches = |e: &&mut LogEntry| {
            e.from == from
                && matches!(&e.body, MessageBody::File { stream_id: sid, .. } if *sid == stream_id)
        };
        for tab in &mut self.channels {
            if let Some(entry) = tab.log.iter_mut().find(matches) {
                f(&mut entry.body);
                return;
            }
        }
        for room in self.private_rooms.values_mut() {
            if let Some(entry) = room.log.iter_mut().find(matches) {
                f(&mut entry.body);
                return;
            }
        }
    }

    pub fn set_file_progress(&mut self, from: UserId, stream_id: u64, bytes: u64) {
        self.update_file_entry(from, stream_id, |body| {
            if let MessageBody::File { status, .. } = body {
                *status = FileTransferStatus::InProgress { bytes };
            }
        });
    }

    pub fn set_file_completed(&mut self, from: UserId, stream_id: u64) {
        self.update_file_entry(from, stream_id, |body| {
            if let MessageBody::File { status, .. } = body {
                *status = FileTransferStatus::Completed;
            }
        });
    }

    pub fn set_file_rejected(&mut self, from: UserId, stream_id: u64) {
        self.update_file_entry(from, stream_id, |body| {
            if let MessageBody::File { status, .. } = body {
                *status = FileTransferStatus::Rejected;
            }
        });
    }

    pub fn set_file_failed(&mut self, from: UserId, stream_id: u64) {
        self.update_file_entry(from, stream_id, |body| {
            if let MessageBody::File { status, .. } = body {
                *status = FileTransferStatus::Failed;
            }
        });
    }

    /// Called by the caller (`session`/`channel`/`direct_message`) when
    /// starting the recorder itself failed (e.g. no audio input device).
    /// Turns off the misleading "recording..." indicator immediately
    /// instead of waiting for the user to release Space, and surfaces why.
    pub fn recording_failed(&mut self, reason: String) {
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        self.audio_error = Some(reason);
    }

    /// Called when playing back an incoming or replayed voice message
    /// failed (e.g. no speaker/output device). Doesn't touch recording
    /// state - this is purely about output.
    pub fn playback_failed(&mut self, reason: String) {
        self.audio_error = Some(reason);
    }

    /// Called when a direct peer-to-peer link (`crate::client::p2p`) fails to
    /// establish or dies mid-session - there is no relay fallback, so
    /// whatever was pending against `peer_name` (a message, a call, a file)
    /// did not go through. Reuses the same error banner `recording_failed`/
    /// `playback_failed` use rather than inventing a new UI surface for it.
    pub fn p2p_link_failed(&mut self, peer_name: &str, reason: &str) {
        self.audio_error = Some(format!("direct connection to {peer_name} failed: {reason}"));
    }

    /// Records the current state of the direct link to `peer`, which is
    /// what `render_sidebar` colours their name by: green once messages
    /// can actually reach them, red once they can't.
    pub fn set_link_status(&mut self, peer: UserId, status: LinkStatus) {
        self.link_status.insert(peer, status);
    }

    /// Forgets a peer's link state, for when the link itself is dropped
    /// (`p2p::PeerLinkManager::forget`) - a stale entry would otherwise
    /// keep colouring a name by a link that no longer exists.
    pub fn forget_link_status(&mut self, peer: UserId) {
        self.link_status.remove(&peer);
    }

    /// How `peer`'s direct link should be shown right now. A peer we have
    /// no link record for at all is `Connecting`: one is pre-warmed the
    /// moment they're learned about (§7.1), so "no record" means the
    /// handshake simply hasn't got anywhere yet, never that content would
    /// reach them.
    pub fn link_status_of(&self, peer: UserId) -> LinkStatus {
        self.link_status
            .get(&peer)
            .copied()
            .unwrap_or(LinkStatus::Connecting)
    }

    /// Notes something the user should see but need not act on - currently
    /// only a peer moving to a new identity and proving it (§12.6), which
    /// deliberately does *not* open a review.
    ///
    /// Shares the banner `recording_failed`/`p2p_link_failed` use rather
    /// than adding a second transient surface. That banner is already the
    /// app's one "here is something that just happened" line despite its
    /// field name, and a note that quietly said nothing would defeat the
    /// point: the user should know their pin moved, just not be stopped.
    pub fn push_notice(&mut self, message: String) {
        self.audio_error = Some(message);
    }

    pub fn set_own_id(&mut self, id: UserId) {
        self.own_id = Some(id);
    }

    /// Called once per session (`session::run_connected_session`) with the
    /// result of querying the terminal's actual Kitty keyboard protocol
    /// support, as determined by `super::terminal::setup`. When `true`,
    /// `tick_recording_timeout` stops guessing from silence and leaves
    /// stopping entirely to the real `KeyEventKind::Release` event.
    pub fn set_keyboard_release_reporting(&mut self, supported: bool) {
        self.keyboard_release_reporting = supported;
    }

    pub fn toggle_blink(&mut self) {
        self.blink_on = !self.blink_on;
    }

    /// The help overlay's current scroll offset (first visible line index
    /// into `HELP_BODY`) - loosely clamped here, precisely at render time
    /// against the popup's actual visible height (`render_help_popup`).
    pub fn help_scroll(&self) -> usize {
        self.help_scroll
    }

    // -------------------------------------------------------------
    // Key handling
    // -------------------------------------------------------------

    /// Handles one key event. Space is push-to-talk everywhere *except*
    /// with focus on the compose bar, where it types a literal space.
    /// Release detection doesn't rely on `KeyEventKind::Release` (Kitty
    /// terminals only): every Press/Repeat refreshes `recording_last_seen`
    /// and `tick_recording_timeout` auto-stops once that goes quiet for
    /// `RECORD_HOLD_TIMEOUT`; a real `Release` still stops immediately as
    /// a fast path.
    pub fn handle_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
        kind: KeyEventKind,
    ) -> Option<UiAction> {
        // An outstanding identity review takes priority over *everything*
        // else, including Ctrl+H - a peer's identity needs an explicit
        // decision before anything else happens, and unlike the help
        // overlay there is deliberately no dismiss key: `Left`/`Right`/`Tab`
        // move the Accept/Reject focus, `Enter` confirms it, nothing else
        // does anything (docs/PROTOCOL.md §12).
        if let Some(&peer) = self.identity_review_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.identity_review_focus = match self.identity_review_focus {
                            IdentityChoice::Accept => IdentityChoice::Reject,
                            IdentityChoice::Reject => IdentityChoice::Accept,
                        };
                        None
                    }
                    KeyCode::Enter => match self.identity_review_focus {
                        IdentityChoice::Accept => Some(UiAction::AcceptIdentity(peer)),
                        IdentityChoice::Reject => Some(UiAction::RejectIdentity(peer)),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An outstanding OTP session proposal from a peer is next -
        // "accepted by both parties" means this decision can't be
        // deferred behind ordinary typing, same absorb-everything shape as
        // identity review/file offer.
        if self.otp_invite_queue.front().is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.otp_invite_focus = match self.otp_invite_focus {
                            OtpChoice::Accept => OtpChoice::Reject,
                            OtpChoice::Reject => OtpChoice::Accept,
                        };
                        None
                    }
                    KeyCode::Enter => match self.otp_invite_focus {
                        OtpChoice::Accept => Some(UiAction::AcceptOtpInvite),
                        OtpChoice::Reject => Some(UiAction::RejectOtpInvite),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // The pad-size prompt, shown right after Accept below - same
        // priority tier, and mutually exclusive with `otp_generate_confirm`
        // (checked first only because it's the one more likely to be open
        // once both exist, not because order matters here).
        if self.otp_size_input.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Esc => Some(UiAction::CancelOtpGenerate),
                    KeyCode::Enter => match self.otp_size_text.parse::<u32>() {
                        Ok(size_mb) if crate::crypto::otp::otp_size_mb_in_range(size_mb) => {
                            Some(UiAction::ConfirmOtpGenerate { size_mb })
                        }
                        _ => {
                            self.otp_size_error = Some(format!(
                                "enter a whole number between {} and {}",
                                crate::crypto::otp::OTP_SIZE_MB_MIN,
                                crate::crypto::otp::OTP_SIZE_MB_MAX
                            ));
                            None
                        }
                    },
                    KeyCode::Backspace => {
                        self.otp_size_text.pop();
                        self.otp_size_error = None;
                        None
                    }
                    // 6 digits covers the max (900000) with no room for a
                    // typo'd extra digit to even be entered.
                    KeyCode::Char(c) if c.is_ascii_digit() && self.otp_size_text.len() < 6 => {
                        self.otp_size_text.push(c);
                        self.otp_size_error = None;
                        None
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The local "generate and share a fresh pad?" confirmation - same
        // priority tier as the invite popup above (they can never both be
        // open at once: typing `/otp` is itself unreachable while any
        // modal popup, including an invite, is absorbing every key).
        if self.otp_generate_confirm.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.otp_generate_focus = match self.otp_generate_focus {
                            OtpChoice::Accept => OtpChoice::Reject,
                            OtpChoice::Reject => OtpChoice::Accept,
                        };
                        None
                    }
                    KeyCode::Enter => match self.otp_generate_focus {
                        OtpChoice::Accept => {
                            // Confirming only decides "yes, generate one" -
                            // the size prompt above is the next step, not
                            // an immediate `ConfirmOtpGenerate`.
                            let pending = self
                                .take_otp_generate_confirm()
                                .expect("otp_generate_confirm.is_some() was just checked");
                            self.open_otp_size_input(pending);
                            None
                        }
                        OtpChoice::Reject => Some(UiAction::CancelOtpGenerate),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An outstanding file offer is next-highest priority - below an
        // identity review (trust is the more fundamental concern) but
        // above everything else, including Ctrl+H, same reasoning and same
        // shape as the identity review block above: every other key is
        // absorbed while one is showing.
        if let Some(&(from, stream_id)) = self.file_offer_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.file_offer_focus = match self.file_offer_focus {
                            FileOfferChoice::Accept => FileOfferChoice::Reject,
                            FileOfferChoice::Reject => FileOfferChoice::Accept,
                        };
                        None
                    }
                    KeyCode::Enter => match self.file_offer_focus {
                        FileOfferChoice::Accept => {
                            Some(UiAction::AcceptFileOffer { from, stream_id })
                        }
                        FileOfferChoice::Reject => {
                            Some(UiAction::RejectFileOffer { from, stream_id })
                        }
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An incoming call invite is the same priority tier as a file
        // offer - both are "someone needs a consent decision before
        // anything else happens" popups, absorbing every key the same way.
        if let Some(&call_id) = self.call_invite_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.call_invite_focus = match self.call_invite_focus {
                            CallInviteChoice::Accept => CallInviteChoice::Reject,
                            CallInviteChoice::Reject => CallInviteChoice::Accept,
                        };
                        None
                    }
                    KeyCode::Enter => match self.call_invite_focus {
                        CallInviteChoice::Accept => self.accept_call_invite(call_id),
                        CallInviteChoice::Reject => Some(UiAction::RejectCallInvite { call_id }),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // The `/call` confirmation is the same "absorb everything until
        // it's answered" tier as the popups above - nothing is rung until
        // it is resolved.
        if self.call_confirm.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.call_confirm_focus = match self.call_confirm_focus {
                            CallConfirmChoice::Confirm => CallConfirmChoice::Cancel,
                            CallConfirmChoice::Cancel => CallConfirmChoice::Confirm,
                        };
                        None
                    }
                    KeyCode::Esc => {
                        self.call_confirm = None;
                        None
                    }
                    KeyCode::Enter => {
                        let pending = self.call_confirm.take()?;
                        match self.call_confirm_focus {
                            CallConfirmChoice::Confirm => {
                                Some(UiAction::StartCall(pending.target))
                            }
                            CallConfirmChoice::Cancel => None,
                        }
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The call modal owns every key while it is actually on screen -
        // either overlaid (not yet minimized) or as its own selected tab.
        // Below the consent popups above (a trust decision always comes
        // first) and above everything else, including Ctrl+H.
        if self.call_modal_showing() && kind != KeyEventKind::Release {
            return self.handle_call_modal_key(code);
        }

        // Ctrl+H toggles the help overlay from any view/mode/focus, taking
        // priority over everything below. Gated on `Press`: on a Kitty
        // terminal the matching `Release` also reaches here, and toggling
        // on both would open and instantly close it. Both kinds return
        // `None` so the `Release` is absorbed rather than falling through
        // to a bare 'h'.
        if modifiers.contains(KeyModifiers::CONTROL)
            && matches!(code, KeyCode::Char('h') | KeyCode::Char('H'))
        {
            if kind == KeyEventKind::Press {
                self.help_open = !self.help_open;
                // Always reopen at the top rather than wherever it was
                // scrolled to last time it was closed.
                self.help_scroll = 0;
            }
            return None;
        }
        if self.help_open {
            // Only scrolling and closing are honored while the overlay is
            // up; every other key is swallowed. Closing is Ctrl+H (the
            // toggle above) or Esc - the Esc close is gated on `Press`,
            // and its paired `Release` on a kitty-protocol terminal is
            // still absorbed safely below even though `help_open` has
            // already flipped: the DM-closing Esc branch further down is
            // itself `Press`-gated, so no second side effect can leak.
            if code == KeyCode::Esc {
                if kind == KeyEventKind::Press {
                    self.help_open = false;
                }
                return None;
            }
            let max_scroll = HELP_BODY.len().saturating_sub(1);
            match code {
                KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
                KeyCode::Down => self.help_scroll = (self.help_scroll + 1).min(max_scroll),
                KeyCode::PageUp => {
                    self.help_scroll = self.help_scroll.saturating_sub(HELP_SCROLL_PAGE)
                }
                KeyCode::PageDown => {
                    self.help_scroll = (self.help_scroll + HELP_SCROLL_PAGE).min(max_scroll)
                }
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::End => self.help_scroll = max_scroll,
                _ => {}
            }
            return None;
        }

        // The OTP mail view owns every key while open (below the modal
        // popups and Ctrl+H above, which must stay reachable over it) -
        // including its own Space handling, since Space types text in its
        // fields but records in its attachments pane. Opened only by the
        // `/mail` and `/mailbox` commands (`submit_input`) - deliberately
        // no key chord: Ctrl+M is indistinguishable from Enter on
        // terminals without the kitty keyboard protocol (both are 0x0D).
        if self.otp_mail.is_some() {
            return self.handle_otp_mail_key(code, modifiers, kind);
        }

        if code == KeyCode::Char(' ') && self.focus != Focus::Input {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => {
                    self.recording_last_seen = Some(Instant::now());
                    if self.recording {
                        None
                    } else {
                        // The target has to be known now, at press-time,
                        // not deferred to release: a live stream needs
                        // somewhere to address its Start message to the
                        // instant recording begins. Without anywhere to
                        // send it, don't start the recorder at all -
                        // previously this started local capture
                        // unconditionally and only discovered there was
                        // nowhere to send it at release, leaving the
                        // recorder running with no way to stop it.
                        match self.current_voice_target() {
                            Some(target) => {
                                self.recording = true;
                                self.recording_source = Some(RecordSource::Space);
                                self.audio_error = None;
                                Some(UiAction::VoiceRecordStart(target))
                            }
                            None => {
                                self.audio_error = Some("not joined to a channel yet".to_string());
                                None
                            }
                        }
                    }
                }
                // Only ends a recording Space itself started - a
                // Global-triggered one (see `global_record_stop`) only
                // ever ends on its own release, never on Space.
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

        if self.mode == Mode::JoinPrivatePopup {
            return self.handle_join_popup_key(code);
        }
        if self.mode == Mode::ChannelPasswordPopup {
            return self.handle_channel_password_popup_key(code);
        }
        if self.mode == Mode::ChannelsPopup {
            return self.handle_channels_popup_key(code);
        }
        if self.mode == Mode::FileSend {
            return self.handle_file_send_key(code);
        }

        // The top row's two selectors (`docs/SPEC.md` "Connected UI"):
        // `[` walks left, `]` walks right, and the outermost press on
        // either side opens that selector's own dropdown instead of
        // wrapping around to the other end of the row.
        match code {
            KeyCode::Char('[') => {
                self.selector_left();
                return None;
            }
            KeyCode::Char(']') => {
                self.selector_right();
                return None;
            }
            _ => {}
        }

        // An open dropdown owns Up/Down (which move the selection, and
        // with it the view behind the overlay, straight away) and
        // Enter/Escape/Tab (which close it, keeping whatever Up/Down
        // landed on). Tab is in that group because its usual job - moving
        // focus between the sidebar, the log and the compose bar - is
        // about the view *behind* the overlay: getting on with it means
        // being done with the dropdown, so it closes rather than cycling
        // underneath. Everything else still falls through - this is an
        // overlay, not a modal.
        if self.selector_dropdown_open {
            match code {
                KeyCode::Up => {
                    self.selector_step(false);
                    return None;
                }
                KeyCode::Down => {
                    self.selector_step(true);
                    return None;
                }
                KeyCode::Enter | KeyCode::Esc | KeyCode::Tab => {
                    self.close_selector_dropdown();
                    return None;
                }
                _ => {}
            }
        }

        if modifiers.contains(KeyModifiers::CONTROL) {
            match code {
                // Brings a folded-away call modal back up - the header's
                // `\u{1F534} Call Ctrl+R` indicator is what advertises it
                // (`docs/SPEC.md` "Live voice calls"). A no-op with no
                // call on; it can only be reached while the modal is
                // down, since the modal absorbs keys before this.
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    if let Some(call) = self.call.as_mut() {
                        call.minimized = false;
                    }
                    return None;
                }
                KeyCode::Char('j') | KeyCode::Char('J') => {
                    self.mode = Mode::JoinPrivatePopup;
                    self.join_popup_input.clear();
                    self.join_popup_kind = ChannelKind::Private;
                    self.join_popup_password.clear();
                    self.join_popup_focus = JoinPopupFocus::Name;
                    return None;
                }
                _ => {}
            }
        }

        if code == KeyCode::Esc {
            // Gated on `Press` only (same reasoning as the Ctrl+H toggle
            // above): a terminal that also reports `Release` for this key
            // must not act on it a second time, which matters here because
            // - unlike `focus_channel_selector` below, idempotent either
            // way - stopping playback is a real state transition that a
            // second, redundant firing must not follow through the
            // fallback branch and additionally close the room.
            if kind != KeyEventKind::Press {
                return None;
            }
            if self.replaying {
                self.replaying = false;
                return Some(UiAction::StopPlayback);
            }
            self.focus_channel_selector();
            return None;
        }

        if code == KeyCode::Tab && !modifiers.contains(KeyModifiers::CONTROL) {
            self.cycle_focus();
            return None;
        }

        match self.focus {
            Focus::Input => self.handle_input_key(code),
            Focus::Sidebar => self.handle_sidebar_key(code),
            Focus::Messages => self.handle_messages_key(code),
        }
    }

    /// Whether the call modal is the thing currently owning the screen -
    /// i.e. a call is on and Escape has not folded its modal away into the
    /// header's `\u{1F534} Call Ctrl+R` indicator (which is what brings it back).
    pub fn call_modal_showing(&self) -> bool {
        self.call.as_ref().is_some_and(|c| !c.minimized)
    }

    /// Every key the call modal handles (`docs/SPEC.md` "Live voice
    /// calls"): Up/Down walk the roster, `m` is the host's mute toggle for
    /// whoever the cursor is on, `i` opens the host's invite picker,
    /// Enter/`e` press END CALL, and Escape folds the modal away into its
    /// tab. Every other key is absorbed - it is a modal.
    fn handle_call_modal_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let own_id = self.own_id;
        if self.call.as_ref()?.invite_picker.is_some() {
            return self.handle_call_invite_picker_key(code);
        }
        match code {
            KeyCode::Up => {
                let call = self.call.as_mut()?;
                if !call.members.is_empty() {
                    let len = call.members.len();
                    call.selected = (call.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                let call = self.call.as_mut()?;
                if !call.members.is_empty() {
                    call.selected = (call.selected + 1) % call.members.len();
                }
                None
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                self.open_call_invite_picker();
                None
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                let call = self.call.as_ref()?;
                let member = call.members.get(call.selected)?;
                // Our own row toggles our own microphone: ours alone to
                // lift again, though everyone's roster is told. Anyone
                // else's row is the host's mute instead - a different
                // thing entirely, and only the host may use it.
                if Some(member.id) == own_id {
                    return Some(UiAction::ToggleCallMute);
                }
                if !call.we_are_host(own_id) {
                    return None;
                }
                Some(UiAction::HostMuteCallMember {
                    peer: member.id,
                    muted: !member.host_muted,
                })
            }
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => Some(UiAction::EndCall),
            // Selector navigation keeps working through the modal - it is
            // how the user gets on with reading a channel or a DM without
            // ending anything. It folds the modal away first, so it
            // doesn't simply reappear on top of whatever was navigated to
            // (Ctrl+R brings it back).
            KeyCode::Char('[') | KeyCode::Char(']') => {
                if let Some(call) = self.call.as_mut() {
                    call.minimized = true;
                }
                if code == KeyCode::Char(']') {
                    self.selector_right();
                } else {
                    self.selector_left();
                }
                None
            }
            KeyCode::Esc => {
                if let Some(call) = self.call.as_mut() {
                    call.minimized = true;
                }
                None
            }
            _ => None,
        }
    }

    /// The host's invite picker, while it is open over the modal: Up/Down
    /// pick, Enter invites, Escape closes it without inviting anyone.
    fn handle_call_invite_picker_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let call = self.call.as_mut()?;
        let picker = call.invite_picker.as_mut()?;
        match code {
            KeyCode::Up => {
                let len = picker.candidates.len();
                if len > 0 {
                    picker.selected = (picker.selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                let len = picker.candidates.len();
                if len > 0 {
                    picker.selected = (picker.selected + 1) % len;
                }
                None
            }
            KeyCode::Enter => {
                let &(to, _) = picker.candidates.get(picker.selected)?;
                call.invite_picker = None;
                Some(UiAction::InviteToCall { to })
            }
            KeyCode::Esc => {
                call.invite_picker = None;
                None
            }
            _ => None,
        }
    }

    // -------------------------------------------------------------
    // The top row's two selectors
    // -------------------------------------------------------------

    /// `[`. From the DM selector it steps left onto the channel one; on
    /// the channel selector - already the leftmost thing in the row -
    /// there is nothing further left to step onto, so it opens that
    /// selector's own dropdown instead. With a dropdown already open it is
    /// the *DM* dropdown's close key, mirroring the side each selector
    /// sits on (`docs/SPEC.md` "Connected UI").
    pub(crate) fn selector_left(&mut self) {
        if self.selector_dropdown_open {
            if self.selector_focus == SelectorFocus::Dms {
                self.close_selector_dropdown();
            }
            return;
        }
        match self.selector_focus {
            SelectorFocus::Channels => self.open_selector_dropdown(),
            SelectorFocus::Dms => self.focus_channel_selector(),
        }
    }

    /// `]` - `selector_left`'s mirror image: from the channel selector it
    /// steps right onto the DM one (which isn't there at all until a room
    /// has been opened, in which case nothing happens), and on the DM
    /// selector it opens that selector's dropdown. With the *channel*
    /// dropdown open it closes it.
    pub(crate) fn selector_right(&mut self) {
        if self.selector_dropdown_open {
            if self.selector_focus == SelectorFocus::Channels {
                self.close_selector_dropdown();
            }
            return;
        }
        match self.selector_focus {
            SelectorFocus::Channels => self.focus_dm_selector(),
            SelectorFocus::Dms => self.open_selector_dropdown(),
        }
    }

    /// Opens the focused selector's dropdown - unless it would be empty,
    /// which is exactly when there is nothing else to switch to (one
    /// channel joined, one room open), and an empty overlay in the way
    /// would be pure obstruction.
    fn open_selector_dropdown(&mut self) {
        if !self.selector_dropdown_entries().is_empty() {
            self.selector_dropdown_open = true;
            self.selector_dropdown_since = Some(Instant::now());
        }
    }

    /// The one way a dropdown is ever put away - every closing key and the
    /// idle timeout alike - so its timer never outlives it.
    pub(crate) fn close_selector_dropdown(&mut self) {
        self.selector_dropdown_open = false;
        self.selector_dropdown_since = None;
    }

    /// Folds an open dropdown away once `SELECTOR_DROPDOWN_IDLE_TIMEOUT`
    /// has passed with nothing driving it - called from the session's
    /// ticker, the same cadence `tick_status_notice` rides. An open
    /// dropdown whose timestamp is missing (set by writing the pub field
    /// directly, as tests do) is adopted from `now` rather than left
    /// immortal.
    pub fn tick_selector_dropdown(&mut self, now: Instant) {
        if !self.selector_dropdown_open {
            self.selector_dropdown_since = None;
            return;
        }
        match self.selector_dropdown_since {
            Some(since) if now.duration_since(since) >= SELECTOR_DROPDOWN_IDLE_TIMEOUT => {
                self.close_selector_dropdown();
            }
            None => self.selector_dropdown_since = Some(now),
            _ => {}
        }
    }

    /// Up/Down while a dropdown is open: moves the focused selector's own
    /// selection one entry on, wrapping at both ends the way the sidebar
    /// and the `/channels` modal already do. The view behind the overlay
    /// follows immediately - the dropdown lists everything *except* the
    /// selection, so the row that was picked leaves the list and the one
    /// stepped off rejoins it.
    pub(crate) fn selector_step(&mut self, forward: bool) {
        // Driving the list is what "not idle" means (`tick_selector_dropdown`).
        self.selector_dropdown_since = Some(Instant::now());
        match self.selector_focus {
            SelectorFocus::Channels => {
                let len = self.channels.len();
                if len == 0 {
                    return;
                }
                let next = if forward {
                    (self.selected_channel + 1) % len
                } else {
                    (self.selected_channel + len - 1) % len
                };
                self.select_channel_at(next);
            }
            SelectorFocus::Dms => {
                let len = self.dm_order.len();
                if len == 0 {
                    return;
                }
                let current = self
                    .selected_dm
                    .and_then(|id| self.dm_order.iter().position(|d| *d == id))
                    .unwrap_or(0);
                let next = if forward {
                    (current + 1) % len
                } else {
                    (current + len - 1) % len
                };
                self.select_dm(self.dm_order[next]);
            }
        }
    }

    /// Focuses the left-hand selector: its channel becomes the view, so
    /// any open room is closed (it stays on the DM selector, one `]`
    /// away). Also where Escape lands from inside a room.
    pub(crate) fn focus_channel_selector(&mut self) {
        self.selector_focus = SelectorFocus::Channels;
        self.close_selector_dropdown();
        self.active_private_room = None;
        self.sidebar_selected = 0;
        self.select_channel_at(self.selected_channel);
    }

    /// Focuses the right-hand selector, opening the room it names. A no-op
    /// while no room has ever been opened - that selector isn't rendered
    /// at all then, and `]` from the channel one has nowhere to go.
    pub(crate) fn focus_dm_selector(&mut self) {
        let Some(peer) = self.selected_dm else {
            return;
        };
        self.selector_focus = SelectorFocus::Dms;
        self.close_selector_dropdown();
        self.select_dm(peer);
    }

    /// The focused selector's dropdown rows: every entry it holds *except*
    /// the one it currently names, in that selector's own order
    /// (`channels`, `dm_order`). Also what decides whether there is a
    /// dropdown worth opening at all (`open_selector_dropdown`).
    pub fn selector_dropdown_entries(&self) -> Vec<SelectorEntry> {
        match self.selector_focus {
            SelectorFocus::Channels => self
                .channels
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != self.selected_channel)
                .map(|(_, c)| SelectorEntry {
                    label: format!("{} {}", channel_kind_icon(c.kind), c.name),
                    unread: c.unread,
                })
                .collect(),
            SelectorFocus::Dms => self
                .dm_order
                .iter()
                .filter(|id| Some(**id) != self.selected_dm)
                .filter_map(|id| self.private_rooms.get(id))
                .map(|room| SelectorEntry {
                    label: format!("{DM_ICON} {}", room.peer.name),
                    unread: room.unread,
                })
                .collect(),
        }
    }

    /// Whether any channel behind the left-hand selector holds messages
    /// the user has not seen - what makes its envelope blink. The channel
    /// on screen is never one of them: selecting it clears the flag, and
    /// nothing sets it again while it is the log being looked at.
    pub fn any_channel_unread(&self) -> bool {
        self.channels.iter().any(|c| c.unread)
    }

    /// `any_channel_unread`'s DM counterpart, for the right-hand selector.
    pub fn any_dm_unread(&self) -> bool {
        self.private_rooms.values().any(|r| r.unread)
    }

    fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Sidebar => Focus::Messages,
            Focus::Messages => Focus::Input,
            Focus::Input => Focus::Sidebar,
        };
    }

    fn handle_input_key(&mut self, code: KeyCode) -> Option<UiAction> {
        // An offline DM peer can't receive anything: no typing, no send.
        // The compose bar renders "(user offline)" instead in this state
        // (`render_input_bar`), so there's nothing meaningful to edit. Same
        // for a Pending/Rejected identity (docs/PROTOCOL.md §12) - normal
        // navigation can no longer even open this room, but a room already
        // open before the mismatch arrived must stop accepting input too.
        if self.active_dm_peer_offline() || self.active_dm_peer_trust_gated() {
            return None;
        }
        match code {
            KeyCode::Backspace => {
                self.input.pop();
                None
            }
            KeyCode::Char(c) => {
                self.input.push(c);
                None
            }
            KeyCode::Enter => self.submit_input(),
            _ => None,
        }
    }

    /// Only clears `input` once we know the message can actually be
    /// produced - otherwise (not joined yet, unknown DM peer) the user's
    /// typed text would silently vanish instead of just staying put.
    fn submit_input(&mut self) -> Option<UiAction> {
        if self.input.trim().is_empty() {
            return None;
        }
        if self.input.trim() == "/file" {
            // Leaves `input` untouched on failure (no addressable target,
            // or the directory listing itself failed) - same as every
            // other "can't send right now" path below, so the user isn't
            // left wondering where their typed command went.
            return self.start_file_send();
        }
        if self.input.trim() == "/otp" {
            // Only meaningful inside an open DM room - OTP is provisioned
            // pairwise, per contact, never for a whole channel at once
            // (see `client::otp`'s module doc). A no-op if the peer is
            // trust-gated (docs/PROTOCOL.md §12) - the same guard the
            // compose bar itself already applies before any send.
            let peer_id = self.active_private_room?;
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            self.input.clear();
            return Some(UiAction::RequestOtpSession {
                peer: peer_id,
                key_mode: peer.key_mode,
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/mail" {
            // The one way to compose an OTP mail (docs/PROTOCOL.md §17.1) -
            // a command rather than a key chord, since the natural chord
            // (Ctrl+M) is indistinguishable from Enter on terminals
            // without the kitty keyboard protocol (both are 0x0D).
            self.input.clear();
            self.open_otp_mail();
            return None;
        }
        if self.input.trim() == "/mailbox" {
            // The one way to open the mailbox: opens the mail view with
            // the mailbox popup on top - the session answers the action
            // with the current rows (`client::otp_mail::handle_open_mailbox`).
            self.input.clear();
            self.open_otp_mail();
            return Some(UiAction::OpenOtpMailbox);
        }
        if self.input.trim() == "/channels" {
            // The one way to see the server's public channel directory:
            // the tab row only ever shows the channels already joined
            // (docs/PROTOCOL.md §6.3), so this modal is where the rest
            // are, and where joining one from the list happens.
            self.input.clear();
            self.open_channels_popup();
            return None;
        }
        if self.input.trim() == "/leave" {
            // Always the currently selected channel tab - `/leave` takes
            // no argument. A no-op if that tab isn't actually joined yet
            // (its `Joined` confirmation still in flight) - nothing to
            // leave.
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            let name = channel.name.clone();
            self.input.clear();
            return Some(UiAction::LeaveChannel { name });
        }
        if self.input.trim() == "/call" {
            // Distinct from push-to-talk: a continuous, multi-user call
            // (`docs/PROTOCOL.md` "Live voice calls"), never available under
            // OTP - that gate needs `SessionState`, so it's checked
            // session-side (`crate::client::direct_message::handle_start_call`)
            // once this actually reaches it.
            if self.call.is_some() {
                self.push_status_notice("already on a call".to_string(), false);
                self.input.clear();
                return None;
            }
            if self.recording {
                self.push_status_notice(
                    "can't start a call while recording a voice message".to_string(),
                    false,
                );
                self.input.clear();
                return None;
            }
            let Some(target) = self.current_call_target() else {
                self.push_status_notice("nobody to call here".to_string(), false);
                self.input.clear();
                return None;
            };
            self.input.clear();
            // A DM call to a peer under an active OTP session can never
            // happen, so it must not be confirmed either: asking "invite 1
            // user?" and refusing the moment it is agreed to would be
            // worse than the plain refusal this had before there was a
            // confirmation at all. `direct_message::handle_start_call`
            // still rechecks against `SessionState` - the authority - but
            // by then this has already spared the user the popup.
            if let CallTarget::Direct { to, .. } = &target
                && self.is_otp_active(*to)
            {
                self.push_status_notice(OTP_CALL_REFUSAL.to_string(), false);
                return None;
            }
            // Nobody is rung before the user has seen how many people that
            // is (`docs/SPEC.md` "Live voice calls") - except when the
            // answer is nobody at all, which needs no decision, only the
            // same notice the session side would have produced a moment
            // later once its own recount agreed.
            let invitee_count = self.call_invitee_count(&target);
            if invitee_count == 0 {
                self.push_status_notice(NO_ONE_INVITED_NOTICE.to_string(), false);
                return None;
            }
            self.call_confirm = Some(PendingCallConfirm {
                target,
                invitee_count,
            });
            self.call_confirm_focus = CallConfirmChoice::Confirm;
            return None;
        }
        if self.input.trim() == "/endcall" {
            if self.call.is_none() {
                self.push_status_notice("not on a call".to_string(), false);
                self.input.clear();
                return None;
            }
            self.input.clear();
            return Some(UiAction::EndCall);
        }
        // Anything else starting with `/` is an attempted command, not a
        // message - even one this build doesn't recognize, or a typo of a
        // real one. It must never leak into a channel or DM as literal
        // text: silently falling through to the send paths below would
        // send "/otpp" (or worse, "/leave" typed one keystroke wrong) as a
        // plain chat message every recipient sees.
        if self.input.trim().starts_with('/') {
            let attempted = std::mem::take(&mut self.input);
            self.push_status_notice(format!("unknown command: {}", attempted.trim()), false);
            return None;
        }
        if let Some(peer_id) = self.active_private_room {
            // Defensive: normal navigation can no longer reach a compose
            // bar for a Pending/Rejected peer's room (Enter on their
            // sidebar entry opens the review popup instead), but a room
            // opened before the mismatch arrived must not keep accepting
            // sends either (docs/PROTOCOL.md §12).
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            let text = std::mem::take(&mut self.input);
            let log_index = self.push_outgoing_dm(peer_id, MessageBody::Text(text.clone()));
            let action = UiAction::SendDirectText {
                to: peer_id,
                plaintext: text,
                recipient_key_mode: peer.key_mode,
                recipient_pubkey_der: peer.public_key_der,
                log_index,
            };
            Some(action)
        } else {
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            let name = channel.name.clone();
            let recipients = self.recipients_for_channel(channel);
            let text = std::mem::take(&mut self.input);
            let action = UiAction::SendChannelText {
                channel: name.clone(),
                plaintext: text.clone(),
                recipients,
            };
            self.push_outgoing_channel(&name, MessageBody::Text(text));
            Some(action)
        }
    }

    fn handle_sidebar_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let channel = self.channels.get(self.selected_channel)?;
        let len = channel.members.len();
        match code {
            KeyCode::Up => {
                if len > 0 {
                    self.sidebar_selected = (self.sidebar_selected + len - 1) % len;
                }
                None
            }
            KeyCode::Down => {
                if len > 0 {
                    self.sidebar_selected = (self.sidebar_selected + 1) % len;
                }
                None
            }
            KeyCode::Enter => {
                let member = channel.members.get(self.sidebar_selected)?.clone();
                if Some(member.id) == self.own_id {
                    return None;
                }
                // A Pending/Rejected identity opens the review popup
                // instead of the private room - can't vouch for who's
                // actually on the other end yet (docs/PROTOCOL.md §12).
                if self.is_trust_gated(member.id) {
                    self.reopen_identity_review(member.id);
                    return None;
                }
                self.open_private_room(member);
                None
            }
            _ => None,
        }
    }

    /// `Up`/`Down` move one entry at a time, `PageUp`/`PageDown` jump by
    /// `MESSAGE_PAGE_JUMP`, and `Home`/`End` jump straight to the oldest/
    /// newest message - all clamped at the ends of the log rather than
    /// wrapping around (unlike the sidebar's `Up`/`Down`), since a
    /// scrollback history has a genuine top and bottom.
    fn handle_messages_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let len = self.current_log().len();
        match code {
            KeyCode::Up => {
                self.message_selected = self.message_selected.saturating_sub(1);
                None
            }
            KeyCode::Down => {
                if len > 0 {
                    self.message_selected = (self.message_selected + 1).min(len - 1);
                }
                None
            }
            KeyCode::PageUp => {
                self.message_selected = self.message_selected.saturating_sub(MESSAGE_PAGE_JUMP);
                None
            }
            KeyCode::PageDown => {
                if len > 0 {
                    self.message_selected =
                        (self.message_selected + MESSAGE_PAGE_JUMP).min(len - 1);
                }
                None
            }
            KeyCode::Home => {
                self.message_selected = 0;
                None
            }
            KeyCode::End => {
                if len > 0 {
                    self.message_selected = len - 1;
                }
                None
            }
            // A file entry has nothing left to do on Enter - it's already
            // either mid-transfer or saved under `~/.aloo/downloads` (or
            // rejected/failed); unlike the old whole-file-in-memory
            // approach, there's no separate save step to trigger here.
            KeyCode::Enter => {
                let replay = match self.current_log().get(self.message_selected) {
                    Some(LogEntry {
                        body: MessageBody::Voice { duration_ms, pcm },
                        ..
                    }) => Some((*duration_ms, pcm.clone())),
                    _ => None,
                };
                replay.map(|(duration_ms, pcm)| {
                    // An empty clip (0 playable samples) never actually
                    // starts anything on the mixer (see `handle_ui_action`'s
                    // `ReplayVoice` arm) - `replaying` must not be set in
                    // that case, or Escape would be stuck stealing its
                    // "stop playback" meaning with nothing to stop.
                    if !pcm.is_empty() {
                        self.replaying = true;
                    }
                    UiAction::ReplayVoice { duration_ms, pcm }
                })
            }
            _ => None,
        }
    }

    fn current_voice_target(&self) -> Option<VoiceTarget> {
        // The microphone is already spoken for by the live call - push-to-
        // talk and a call both ultimately open the same `voice::Recorder`,
        // and layering a bounded recording's own send path on top of a
        // continuous call's would be confusing at best. Muting yourself
        // (`m` on your own row) is how you temporarily stop talking on a
        // call, not Space.
        if self.call.is_some() {
            return None;
        }
        if let Some(peer_id) = self.active_private_room {
            // An offline peer can't receive a live stream either - ignore
            // Space entirely rather than starting a recording with nowhere
            // to deliver it (SPEC.md). Same for a Pending/Rejected identity
            // (docs/PROTOCOL.md §12) - we won't encrypt to a key we haven't
            // verified.
            if self.offline.contains(&peer_id) || self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?;
            Some(VoiceTarget::Direct {
                to: peer_id,
                recipient_key_mode: peer.key_mode,
                recipient_pubkey_der: peer.public_key_der.clone(),
            })
        } else {
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            Some(VoiceTarget::Channel {
                channel: channel.name.clone(),
                recipients: self.recipients_for_channel(channel),
            })
        }
    }

    /// Resolves what `/call` should address, mirroring
    /// `current_voice_target`'s DM branch (same offline/trust-gate checks)
    /// but, unlike it, not resolving a channel's recipient list here -
    /// `crate::client::channel::handle_start_call` recomputes that fresh
    /// (`crate::client::voice_call::addressable_channel_members`), since an
    /// invite (unlike an already-flowing recording) tolerates the extra
    /// few milliseconds that costs.
    fn current_call_target(&self) -> Option<CallTarget> {
        if let Some(peer_id) = self.active_private_room {
            if self.offline.contains(&peer_id) || self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?;
            return Some(CallTarget::Direct {
                to: peer_id,
                recipient_key_mode: peer.key_mode,
                recipient_pubkey_der: peer.public_key_der.clone(),
            });
        }
        let channel = self.channels.get(self.selected_channel)?;
        if !channel.joined {
            return None;
        }
        Some(CallTarget::Channel {
            channel: channel.name.clone(),
        })
    }

    /// How many people `/call` against `target` will actually ring -
    /// what the confirmation popup prints. Mirrors
    /// `crate::client::voice_call::addressable_channel_members`'s own
    /// filter (an ordinary channel send's recipients, minus anyone under
    /// an OTP session) so the number the user agrees to is the number that
    /// gets invited; the session side recounts for real a moment later,
    /// since membership can shift while the popup is up.
    fn call_invitee_count(&self, target: &CallTarget) -> usize {
        match target {
            CallTarget::Direct { to, .. } => usize::from(!self.is_otp_active(*to)),
            CallTarget::Channel { channel } => self
                .channels
                .iter()
                .find(|c| &c.name == channel)
                .map(|tab| {
                    self.recipients_for_channel(tab)
                        .into_iter()
                        .filter(|(id, ..)| !self.is_otp_active(*id))
                        .count()
                })
                .unwrap_or(0),
        }
    }

    /// Starts a recording from the global Ctrl+Alt+P shortcut. Deliberately
    /// mirrors `handle_key`'s Space branch (same target resolution, same
    /// "nowhere to send it" bail-out) rather than sharing code: they
    /// differ only in `RecordSource` tagging, and Space's branch
    /// interleaves with focus/mode handling that's meaningless for a
    /// shortcut fired while the app isn't focused. A no-op while any
    /// recording is in progress.
    pub fn global_record_start(&mut self) -> Option<UiAction> {
        if self.recording {
            return None;
        }
        match self.current_voice_target() {
            Some(target) => {
                self.recording = true;
                self.recording_source = Some(RecordSource::Global);
                self.audio_error = None;
                Some(UiAction::VoiceRecordStart(target))
            }
            None => {
                self.audio_error = Some("not joined to a channel yet".to_string());
                None
            }
        }
    }

    /// Stops a recording the global shortcut itself started - a no-op if
    /// nothing is recording, or if the current recording was started by
    /// Space instead (that one only ever ends on Space's own release; see
    /// `handle_key`).
    pub fn global_record_stop(&mut self) -> Option<UiAction> {
        if !self.recording || self.recording_source != Some(RecordSource::Global) {
            return None;
        }
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        Some(UiAction::VoiceRecordStop)
    }

    /// Stops whatever recording is currently in progress, regardless of
    /// which trigger started it (unlike `global_record_stop`, which only
    /// ever stops one it itself started) or whether the physical key is
    /// still held. Used when the recording worker hits
    /// `voice::MAX_RECORDING_SAMPLES` and needs to end on its own instead
    /// of waiting for a release event that may not come for a while yet -
    /// see `session::run_connected_session`'s `auto_stop_rx` arm.
    pub fn force_stop_recording(&mut self) -> Option<UiAction> {
        if !self.recording {
            return None;
        }
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        Some(UiAction::VoiceRecordStop)
    }

    fn current_log(&self) -> &[LogEntry] {
        if let Some(peer_id) = self.active_private_room {
            self.private_rooms
                .get(&peer_id)
                .map(|r| r.log.as_slice())
                .unwrap_or(&[])
        } else {
            self.channels
                .get(self.selected_channel)
                .map(|c| c.log.as_slice())
                .unwrap_or(&[])
        }
    }

    /// Call periodically; auto-stops a recording once Space has been quiet
    /// for `RECORD_HOLD_TIMEOUT`, for terminals that never send `Release`
    /// (see `handle_key`). A no-op when `keyboard_release_reporting` is
    /// `true` - a real `Release` is guaranteed there, so the guess must
    /// never fire. Also a no-op for a `Global`-sourced recording: a held
    /// OS hotkey has no repeat heartbeat to go quiet, and its backends all
    /// deliver a real release - the idle guess would wrongly auto-stop
    /// every global recording after ~`RECORD_HOLD_TIMEOUT`.
    pub fn tick_recording_timeout(&mut self, now: Instant) -> Option<UiAction> {
        if !self.recording
            || self.keyboard_release_reporting
            || self.recording_source != Some(RecordSource::Space)
        {
            return None;
        }
        let last = self.recording_last_seen?;
        if now.duration_since(last) < RECORD_HOLD_TIMEOUT {
            return None;
        }
        self.recording = false;
        self.recording_source = None;
        self.recording_last_seen = None;
        Some(UiAction::VoiceRecordStop)
    }

    // -------------------------------------------------------------
    // Applying incoming server events (already decrypted by the caller)
    // -------------------------------------------------------------

    /// `user_id`'s connection closed entirely (as opposed to `on_user_left`,
    /// which only means they left one specific channel). Per SPEC.md: if
    /// there's private-message history with them, they're kept (grayed
    /// out via `offline`) in every channel they were a member of, rather
    /// than removed - otherwise the channel member list drops them exactly
    /// like an explicit leave. Either way `offline` gets the entry, since
    /// that's also what gates the private-room compose bar and voice
    /// recording regardless of channel membership.
    pub fn on_user_offline(&mut self, user_id: UserId) {
        self.offline.insert(user_id);
        let has_dm_history = self
            .private_rooms
            .get(&user_id)
            .map(|r| !r.log.is_empty())
            .unwrap_or(false);
        // Logged into every channel that had them as a member, and into an
        // already-open DM room, before membership is touched below - a
        // disconnect is global, unlike `on_user_left` (one channel), so it
        // reaches every shared context at once (`docs/SPEC.md` Functionality
        // #7). Skipped only if we never actually learned their name (should
        // not happen in practice: `known_users` is populated the moment
        // `on_user_joined` first sees them).
        if let Some(name) = self.known_users.get(&user_id).map(|u| u.name.clone()) {
            let text = format!("{} {name} disconnected", local_time_short());
            let member_channels: Vec<String> = self
                .channels
                .iter()
                .filter(|c| c.members.iter().any(|m| m.id == user_id))
                .map(|c| c.name.clone())
                .collect();
            for channel in member_channels {
                let is_current = self.is_viewing_channel(&channel);
                if let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) {
                    push_log_entry(
                        &mut tab.log,
                        &mut self.message_selected,
                        is_current,
                        LogEntry {
                            from: user_id,
                            from_name: name.clone(),
                            to_name: None,
                            body: MessageBody::Presence(text.clone()),
                            outgoing: false,
                            failed: false,
                        },
                    );
                }
            }
            if self.private_rooms.contains_key(&user_id) {
                let is_current = self.active_private_room == Some(user_id);
                if let Some(room) = self.private_rooms.get_mut(&user_id) {
                    push_log_entry(
                        &mut room.log,
                        &mut self.message_selected,
                        is_current,
                        LogEntry {
                            from: user_id,
                            from_name: name,
                            to_name: None,
                            body: MessageBody::Presence(text),
                            outgoing: false,
                            failed: false,
                        },
                    );
                }
            }
        }
        if !has_dm_history {
            for tab in &mut self.channels {
                tab.members.retain(|m| m.id != user_id);
            }
        }
    }

}

/// This machine's local wall-clock time as `HH:MM:SS`, for the presence
/// notices in `MessageBody::Presence`. Falls back to UTC, labeled, on the
/// rare platforms/thread-shapes where the local offset can't be read
/// safely - same fallback, and the same reason, as `client::otp::format_now`.
/// Deliberately hand-formatted rather than via `time`'s `format_description`
/// machinery: only `hour`/`minute`/`second` accessors are needed, which
/// avoids pulling in the crate's `macros` feature just for this.
pub(crate) fn local_time_short() -> String {
    match time::OffsetDateTime::now_local() {
        Ok(dt) => format!("{:02}:{:02}:{:02}", dt.hour(), dt.minute(), dt.second()),
        Err(_) => {
            let dt = time::OffsetDateTime::now_utc();
            format!("{:02}:{:02}:{:02} UTC", dt.hour(), dt.minute(), dt.second())
        }
    }
}

/// Pushes `entry` onto `log`. If the caller is currently viewing this
/// exact log (`is_current`) and was already positioned on its last entry
/// (or the log was empty) - i.e. "stuck to the bottom" - advances
/// `*message_selected` to keep following the newest message, the same way
/// a normal chat app auto-scrolls unless you've scrolled back through
/// history. Leaves `*message_selected` untouched otherwise (including
/// whenever `!is_current`, since it then refers to a *different* log
/// entirely and has nothing to do with this push).
pub(crate) fn push_log_entry(
    log: &mut Vec<LogEntry>,
    message_selected: &mut usize,
    is_current: bool,
    entry: LogEntry,
) {
    let follow = is_current && (log.is_empty() || *message_selected + 1 >= log.len());
    log.push(entry);
    if follow {
        *message_selected = log.len() - 1;
    }
}

/// Shared by `channel::on_channel_stream_finished`/
/// `direct_message::on_direct_stream_finished`: finds the `VoiceStreaming`
/// placeholder matching both `from` and `stream_id` in `log` and swaps it
/// for a finished `Voice` entry. Returns whether a matching placeholder was
/// actually found - callers that also maintain a held-message buffer
/// (`finalize_held_stream`) use this to fall through to it when the
/// placeholder isn't in the visible log.
pub(crate) fn finalize_stream_entry(
    log: &mut [LogEntry],
    from: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) -> bool {
    if let Some(entry) = log.iter_mut().find(|e| {
        e.from == from
            && matches!(e.body, MessageBody::VoiceStreaming { stream_id: sid } if sid == stream_id)
    }) {
        entry.body = MessageBody::Voice { duration_ms, pcm };
        true
    } else {
        false
    }
}

/// `finalize_stream_entry`'s counterpart for the held-message buffer
/// (`docs/PROTOCOL.md` §12 "hold and reveal") - same matching rule, applied
/// to a `Pending`/`Rejected` sender's `VoiceStreaming` placeholder instead
/// of the visible log.
pub(crate) fn finalize_held_stream(
    held: &mut [HeldMessage],
    from: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) {
    if let Some(hm) = held.iter_mut().find(|h| {
        h.entry.from == from && matches!(h.entry.body, MessageBody::VoiceStreaming { stream_id: sid } if sid == stream_id)
    }) {
        hm.entry.body = MessageBody::Voice { duration_ms, pcm };
    }
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

pub fn render(frame: &mut Frame, state: &UiState) {
    let area = frame.area();
    if state.otp_mail.is_some() {
        // The mail view replaces the whole screen (its popups included) -
        // the global popups/notice below still overlay it, same priority
        // order `handle_key` applies.
        super::otp_mail::render_otp_mail_view(frame, area, state);
    } else if let Some(peer_id) = state.active_private_room {
        super::direct_message::render_private_room(frame, area, state, peer_id);
    } else {
        super::channel::render_channel_view(frame, area, state);
    }
    // The focused selector's dropdown, when open: an overlay hanging off
    // the top row over whichever view is behind it - which keeps updating
    // live as Up/Down move the selection - and below every popup.
    if state.selector_dropdown_open {
        super::channel::render_selector_dropdown(frame, area, state);
    }
    if state.mode == Mode::JoinPrivatePopup {
        super::channel::render_join_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelPasswordPopup {
        super::channel::render_channel_password_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelsPopup {
        super::channel::render_channels_popup(frame, area, state);
    }
    if state.mode == Mode::FileSend {
        super::file_send::render_file_send_popup(frame, area, state);
    }
    // Drawn last, and independent of `mode`/the private-vs-channel view
    // above, so it overlays whatever's currently showing rather than
    // replacing it - matches `Ctrl+H` working from any view (`handle_key`).
    if state.help_open {
        render_help_popup(frame, area, state);
    }
    // A file offer sits above help but below an identity review, same
    // priority order `handle_key` applies.
    if let Some(offer) = state.file_offer_open() {
        render_file_offer_popup(frame, area, offer, state.file_offer_focus);
    }
    // A call invite is the same tier as a file offer, same reasoning
    // `handle_key` applies.
    if let Some(invite) = state.call_invite_open() {
        render_call_invite_popup(frame, area, invite, state.call_invite_focus);
    }
    // The call modal, whenever it isn't already the whole view above -
    // i.e. a call that has not been minimized away yet. Drawn under the
    // consent popups (which must stay answerable over it) for the same
    // reason `handle_key` lets them absorb keys first.
    if let Some(call) = &state.call
        && !call.minimized
    {
        render_call_modal(frame, centered_rect(70, 20, area), state, call);
    }
    if let Some(pending) = &state.call_confirm {
        render_call_confirm_popup(frame, area, pending, state.call_confirm_focus);
    }
    // The OTP popups sit above the file offer, same tier `handle_key` gives
    // them (below only an identity review).
    if let Some(pending) = &state.otp_generate_confirm {
        render_otp_generate_popup(frame, area, pending, state.otp_generate_focus);
    }
    if let Some(pending) = state.otp_size_input_open() {
        render_otp_size_popup(frame, area, pending, state);
    }
    if let Some(invite) = state.otp_invite_open() {
        render_otp_invite_popup(frame, area, invite, state.otp_invite_focus);
    }
    // Drawn last of all - takes priority over even the help overlay, same
    // as it does in `handle_key`, so it's always interactable regardless
    // of what else happened to be open when the mismatch arrived.
    if let Some(review) = state.identity_review_open() {
        render_identity_review_popup(frame, area, review, state.identity_review_focus);
    }
    // The permanent "on a call" indicator (`docs/SPEC.md` "Live voice
    // calls") is drawn in the same top-right corner the status notice
    // uses, just above it - unlike that notice it never auto-clears, so it
    // claims the corner first and pushes the notice down rather than the
    // other way around.
    // Both hang just below the header block rather than inside it - that
    // band is the selectors' own (`docs/SPEC.md` "Connected UI").
    let mut status_notice_y = super::channel::HEADER_ROW_HEIGHT;
    if let Some(call) = &state.call {
        status_notice_y = render_call_banner(frame, area, call, state.own_id);
    }
    // The status notice is a small non-modal banner, not a popup - drawn
    // absolutely last so a session outcome is always visible even over
    // everything above, without ever blocking input the way those do.
    if let Some((message, success)) = &state.status_notice {
        render_status_notice(frame, area, status_notice_y, message, *success);
    }
}

/// The Accept/Reject popup for one incoming file offer
/// (`docs/PROTOCOL.md`'s file transfer section) - visual shape mirrors
/// `render_identity_review_popup`, `Accept` focused by default (see
/// `FileOfferChoice`'s doc for why the default flips from the identity
/// review's `Reject`-first one).
fn render_file_offer_popup(
    frame: &mut Frame,
    area: Rect,
    offer: &PendingFileOffer,
    focus: FileOfferChoice,
) {
    let title = format!("Incoming file from {}", offer.from_name);
    let popup = centered_rect(64, 9, area);
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    let location = match &offer.channel {
        Some(name) => format!("#{name}"),
        None => "a private message".to_string(),
    };
    let message = format!(
        "{} is sending \"{}\" ({}) via {location}. Do you accept it?",
        offer.from_name,
        offer.filename,
        format_file_size(offer.size)
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(
        frame,
        button_cols[0],
        16,
        "Accept",
        focus == FileOfferChoice::Accept,
    );
    render_popup_button(
        frame,
        button_cols[1],
        16,
        "Reject",
        focus == FileOfferChoice::Reject,
    );
}

/// The Accept/Reject popup for one incoming call invite
/// (`docs/PROTOCOL.md` "Live voice calls") - visual shape mirrors
/// `render_file_offer_popup` exactly, same `Accept`-first default.
fn render_call_invite_popup(
    frame: &mut Frame,
    area: Rect,
    invite: &PendingCallInvite,
    focus: CallInviteChoice,
) {
    let title = format!("Voice call incoming from {}", invite.from_name);
    let popup = centered_rect(64, 9, area);
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    let location = match &invite.channel {
        Some(name) => format!("#{name}"),
        None => "a private message".to_string(),
    };
    let message = format!(
        "{} is calling via {location}. Do you accept?",
        invite.from_name
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(
        frame,
        button_cols[0],
        16,
        "Accept",
        focus == CallInviteChoice::Accept,
    );
    render_popup_button(
        frame,
        button_cols[1],
        16,
        "Reject",
        focus == CallInviteChoice::Reject,
    );
}

fn render_otp_generate_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingOtpGenerate,
    focus: OtpChoice,
) {
    let popup = centered_rect(64, 11, area);
    let block = Block::default()
        .title("Start an OTP session")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(6), Constraint::Length(3)])
        .split(inner);

    let message = format!(
        "No OTP key found for {}. Generate one now and share it automatically \
         over the encrypted pq_hybrid channel? Alternatively, run the 'otp' \
         command yourself and place the keys under ~/.aloo/otp/.keychain/, \
         then try /otp again.",
        pending.peer_name
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(frame, button_cols[0], 16, "Accept", focus == OtpChoice::Accept);
    render_popup_button(frame, button_cols[1], 16, "Reject", focus == OtpChoice::Reject);
}

fn render_otp_invite_popup(
    frame: &mut Frame,
    area: Rect,
    invite: &PendingOtpInvite,
    focus: OtpChoice,
) {
    let popup = centered_rect(64, 9, area);
    let block = Block::default()
        .title(format!("OTP session request from {}", invite.from_name))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    // The size, when there is one (a fresh-key invitation, not a bare
    // resume request), is exactly what the sender chose in their own size
    // prompt - shown so this decision isn't made sight-unseen (see
    // `PendingOtpInvite::pad_size_mb`'s doc).
    let size_clause = match invite.pad_size_mb {
        Some(mb) => format!(" using a fresh {mb}MB pad"),
        None => String::new(),
    };
    let message = format!(
        "{} wants to start an OTP session with you{size_clause}, layered on top of \
         pq_hybrid for extra secrecy. Accept it?",
        invite.from_name
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(frame, button_cols[0], 16, "Accept", focus == OtpChoice::Accept);
    render_popup_button(frame, button_cols[1], 16, "Reject", focus == OtpChoice::Reject);
}

/// Follows `render_otp_generate_popup`'s Accept - asks how large a pad to
/// generate (MB per key, `crypto::otp::OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX`),
/// same shape as `channel::render_channel_password_popup`'s text-entry
/// popup (a live input line, an error line only when there's an error to
/// show).
fn render_otp_size_popup(frame: &mut Frame, area: Rect, pending: &PendingOtpGenerate, state: &UiState) {
    let has_error = state.otp_size_error.is_some();
    let popup = centered_rect(64, if has_error { 8 } else { 7 }, area);
    let block = Block::default()
        .title(format!("Pad size for {} (MB per key)", pending.peer_name))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![Constraint::Min(3), Constraint::Length(1)];
    if has_error {
        constraints.push(Constraint::Length(1));
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let message = format!(
        "Choose a size between {} and {} MB, then press Enter. \
         Esc cancels the whole session.",
        crate::crypto::otp::OTP_SIZE_MB_MIN,
        crate::crypto::otp::OTP_SIZE_MB_MAX
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );
    frame.render_widget(Paragraph::new(format!("> {}", state.otp_size_text)), rows[1]);
    if let Some(err) = &state.otp_size_error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
            rows[2],
        );
    }
}

/// A small, non-modal one-line banner in the top-right corner reporting the
/// most recent OTP session outcome (green on success, red otherwise) - see
/// `UiState::status_notice`'s field doc for why this exists as its own
/// always-rendered surface. `y` is where the permanent call banner (drawn
/// just above this one, when there is a call) leaves off -
/// `render_call_banner`'s return value, or `1` when there is none.
fn render_status_notice(frame: &mut Frame, area: Rect, y: u16, message: &str, success: bool) {
    let width = (message.len() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(width),
        y,
        width,
        height: 3,
    };
    let color = if success { Color::Green } else { Color::Red };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        inner,
    );
}

/// The permanent, always-visible top-right "on a call" indicator
/// (`docs/SPEC.md` "Live voice calls") - unlike `render_status_notice`,
/// never auto-clears while `state.call` is `Some`. Always red regardless of
/// mute state: the red means "a call is live", not "something went wrong"
/// the way `render_status_notice`'s red does. Returns the height it
/// occupied (including its top margin) so `render` can draw the status
/// notice just below it instead of overlapping.
/// How wide one voice meter is, in cells - `LEVEL_BAR_CELLS` filled
/// blocks at 100, none at 0. Narrow on purpose: it sits at the end of a
/// roster row that already carries a name and up to three labels.
const LEVEL_BAR_CELLS: usize = 10;

/// One participant's live voice meter (`CallMember::level`) as a bar of
/// block characters - the "audio bar with the voice levels from the user"
/// `docs/SPEC.md` "Live voice calls" puts next to every roster row.
fn level_bar(level: u8) -> String {
    let filled = (level as usize * LEVEL_BAR_CELLS).div_ceil(100).min(LEVEL_BAR_CELLS);
    format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(LEVEL_BAR_CELLS - filled)
    )
}

/// How wide a roster row's name column is: the longest nickname
/// (`ui_connect_popup::NICKNAME_MAX_LEN`) plus both suffixes it can carry
/// at once - ` (host)` and ` (you)` - and one space of separation. Every
/// row pads to it so the labels, and with them the voice bars, all start
/// in the same column.
const CALL_NAME_COL: usize = super::ui_connect_popup::NICKNAME_MAX_LEN + 7 + 6 + 1;

/// The same for the label column: `REJECTED MUTED` is the widest anything
/// there can read, so a row carrying nothing but `IN CALL` still leaves
/// the space a later `MUTED` would take rather than sliding its bar left.
const CALL_LABEL_COL: usize = 14;

/// The roster labels one member's row carries, already coloured
/// (`docs/SPEC.md` "Live voice calls"): `IN CALL` green / `INVITED`
/// yellow / `REJECTED` grey for where they stand, then `MUTED` red if
/// they cannot currently be heard - whether they muted themselves or the
/// host did. The host is not labelled here - their row is named
/// `<nickname> (host)` instead (`call_member_name`).
fn call_member_labels(member: &CallMember) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let (text, color) = match member.state {
        CallMemberState::InCall => ("IN CALL", Color::Green),
        CallMemberState::Invited => ("INVITED", Color::Yellow),
        CallMemberState::Rejected => ("REJECTED", Color::DarkGray),
    };
    spans.push(Span::styled(text, Style::default().fg(color)));
    // One label for either kind of silence - the roster answers "can this
    // person be heard right now", and both answers are no. Which of the
    // two it is only matters for who may lift it (`CallMember::host_muted`
    // vs `self_muted`), not for reading the row.
    if member.host_muted || member.self_muted {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            "MUTED",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    pad_to(&mut spans, CALL_LABEL_COL);
    spans
}

/// How a roster row names one member: their nickname, marked `(you)` for
/// ourselves and `(host)` for whoever started the call - the host carries
/// no separate label of its own (`docs/SPEC.md` "Live voice calls").
fn call_member_name(member: &CallMember, host: UserId, own_id: Option<UserId>) -> String {
    let mut name = member.name.clone();
    if Some(member.id) == own_id {
        name.push_str(" (you)");
    }
    if member.id == host {
        name.push_str(" (host)");
    }
    name
}

/// Pads `spans` out to `width` display columns with one trailing blank
/// span, leaving it alone if it is already at least that wide - what keeps
/// a column of variable-length labels from shifting whatever follows it.
fn pad_to(spans: &mut Vec<Span<'static>>, width: usize) {
    let used: usize = spans.iter().map(|s| display_width(&s.content) as usize).sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
}

/// The call modal (`docs/SPEC.md` "Live voice calls"): live duration on
/// top in yellow, the scrollable roster below it - host first, everyone
/// else after - each row labelled and metered, and the END CALL button at
/// the bottom. Drawn both as an overlay over the ordinary view and, when
/// the call's tab is selected, as the whole view; `area` is whichever of
/// those the caller decided on.
pub(crate) fn render_call_modal(frame: &mut Frame, area: Rect, state: &UiState, call: &CallUiState) {
    let title = match &call.channel {
        Some(name) => format!("Call \u{2014} #{name}"),
        None => "Call".to_string(),
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(3),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            call.duration_label(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )))
        .alignment(ratatui::layout::Alignment::Center),
        rows[0],
    );

    // The roster scrolls rather than truncating - the selection is always
    // kept in view, the same "follow the cursor" scrolling the message log
    // and the /channels directory already use.
    let visible = rows[1].height as usize;
    let scroll = if visible == 0 || call.selected < visible {
        0
    } else {
        call.selected + 1 - visible
    };
    let lines: Vec<Line> = call
        .members
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(idx, member)| {
            let mut spans = vec![Span::styled(
                if idx == call.selected { "> " } else { "  " },
                Style::default().fg(Color::Yellow),
            )];
            let is_us = Some(member.id) == state.own_id;
            let name = call_member_name(member, call.host, state.own_id);
            spans.push(Span::styled(
                format!("{name:<CALL_NAME_COL$}"),
                if idx == call.selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ));
            spans.extend(call_member_labels(member));
            // Our own row meters what we are actually sending: muting
            // ourselves (`m` on our own row) stops that at the source, so
            // the bar must read empty rather than keep twitching along
            // with a microphone nobody hears.
            let level = if is_us && call.muted { 0 } else { member.level };
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                level_bar(level),
                Style::default().fg(Color::Green),
            ));
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rows[1]);

    let host_hint = if call.we_are_host(state.own_id) {
        "  m: mute  i: invite"
    } else {
        ""
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("Esc: minimize{host_hint}"),
            Style::default().fg(Color::DarkGray),
        ))),
        rows[2],
    );
    render_popup_button(frame, rows[3], 14, "END CALL", true);

    if let Some(picker) = &call.invite_picker {
        render_call_invite_picker(frame, area, picker);
    }
}

/// The host-only invite picker, drawn over the modal it was opened from.
fn render_call_invite_picker(frame: &mut Frame, area: Rect, picker: &CallInvitePicker) {
    let height = (picker.candidates.len() as u16 + 2).clamp(3, area.height);
    let popup = centered_rect(40, height, area);
    let block = Block::default()
        .title("Invite to call")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let visible = inner.height as usize;
    let scroll = if visible == 0 || picker.selected < visible {
        0
    } else {
        picker.selected + 1 - visible
    };
    let lines: Vec<Line> = picker
        .candidates
        .iter()
        .enumerate()
        .skip(scroll)
        .take(visible)
        .map(|(idx, (_, name))| {
            let style = if idx == picker.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(Span::styled(format!("  {name}"), style))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The `/call` confirmation (`docs/SPEC.md` "Live voice calls") - nothing
/// is rung until it is answered, and the number of people it is about to
/// ring is spelled out in yellow.
fn render_call_confirm_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingCallConfirm,
    focus: CallConfirmChoice,
) {
    let popup = centered_rect(60, 9, area);
    let block = Block::default().title("Start a call").borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    let where_clause = match &pending.target {
        CallTarget::Channel { channel } => format!("in #{channel}"),
        CallTarget::Direct { .. } => "in this private room".to_string(),
    };
    let plural = if pending.invitee_count == 1 {
        "user"
    } else {
        "users"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("This will invite "),
            Span::styled(
                format!("{} {plural}", pending.invitee_count),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" {where_clause} to a live call. Go ahead?")),
        ]))
        .wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(
        frame,
        button_cols[0],
        16,
        "Call",
        focus == CallConfirmChoice::Confirm,
    );
    render_popup_button(
        frame,
        button_cols[1],
        16,
        "Cancel",
        focus == CallConfirmChoice::Cancel,
    );
}

fn render_call_banner(
    frame: &mut Frame,
    area: Rect,
    call: &CallUiState,
    own_id: Option<UserId>,
) -> u16 {
    let where_clause = match &call.channel {
        Some(name) => format!(" in #{name}"),
        None => String::new(),
    };
    let mute_clause = if call.muted { " \u{1F507} muted" } else { "" };
    let message = format!(
        "\u{1F534} On a call{where_clause} ({} connected){mute_clause}",
        call.connected_count(own_id)
    );
    let width = (message.chars().count() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(width),
        y: super::channel::HEADER_ROW_HEIGHT,
        width,
        height: 3,
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    frame.render_widget(
        Paragraph::new(message)
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        inner,
    );
    rect.y + rect.height
}

/// Renders the label the UI shows on a finalized voice message block, e.g.
/// `voice (12sec)`. A non-zero duration under one second still rounds up
/// to `1sec` so a short clip is never shown as `0sec`.
pub fn format_duration_label(duration_ms: u32) -> String {
    let secs = if duration_ms == 0 {
        0
    } else {
        (duration_ms as f64 / 1000.0).ceil() as u32
    };
    format!("voice ({secs}sec)")
}

/// Renders a byte count as a short human-readable size, e.g. `842 B`,
/// `128.0 KB`, `4.2 MB`, `1.10 GB` - used only for the file-offer popup and
/// in-progress log rows, so this doesn't need to handle anything past GB.
pub(crate) fn format_file_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else {
        format!("{:.2} GB", b / GB)
    }
}

/// A fixed-width ASCII progress bar, e.g. `[####------]`, for an
/// in-progress file transfer's log row.
fn progress_bar(pct: u32) -> String {
    const WIDTH: u32 = 10;
    let filled = (pct.min(100) * WIDTH / 100) as usize;
    format!(
        "[{}{}]",
        "#".repeat(filled),
        "-".repeat(WIDTH as usize - filled)
    )
}

/// The Accept/Reject popup for one peer's identity mismatch
/// (`docs/PROTOCOL.md` §12) - auto-opened by `push_identity_review`,
/// re-openable via Enter on a red sidebar entry. Visual style matches the
/// help popup (bordered box, centered) and the connect popup's single
/// button (`ui_connect_popup::render_connect_button`): a plain border, a
/// solid-fill interior when focused.
fn render_identity_review_popup(
    frame: &mut Frame,
    area: Rect,
    review: &IdentityReview,
    focus: IdentityChoice,
) {
    let title = format!("Identity review: {}", review.nickname);
    // Taller than the other single-button popups (64x9): the message now
    // also carries the last-known vs. new address/device id
    // (docs/PROTOCOL.md §12.7), several lines longer than the original
    // one-line fingerprint warning.
    let popup = centered_rect(70, 13, area);
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(inner);

    let mut lines = vec![Line::from(review.message.as_str())];
    if review.status == IdentityStatus::Rejected {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "(previously rejected - messaging with them is blocked)",
            Style::default().fg(Color::Red),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let button_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    render_popup_button(
        frame,
        button_cols[0],
        16,
        "Accept",
        focus == IdentityChoice::Accept,
    );
    render_popup_button(
        frame,
        button_cols[1],
        16,
        "Reject",
        focus == IdentityChoice::Reject,
    );
}

/// One popup button (identity review's and the file offer's Accept/Reject,
/// file send's Send/Discard) - same border-vs-fill focus convention as
/// `ui_connect_popup::render_connect_button`: the border (block) always
/// keeps its own plain/yellow-focus style, and only the *inner* area gets
/// the solid highlight fill when focused, via the `Paragraph`'s own
/// `.style()` rather than a separate widget underneath it. `width` is the
/// button's fixed width, centered in `area`.
pub(crate) fn render_popup_button(
    frame: &mut Frame,
    area: Rect,
    width: u16,
    label: &str,
    focused: bool,
) {
    let popup = centered_rect(width, 3, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_border_style(focused));
    let text_style = if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(label)
            .alignment(ratatui::layout::Alignment::Center)
            .style(text_style),
        inner,
    );
}

pub(crate) fn render_messages(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    dm_peer: Option<UserId>,
) {
    let title = if let Some(id) = dm_peer {
        state
            .known_users
            .get(&id)
            .map(|u| format!("Private: {}", u.key_mode.format_with_name(&u.name)))
            .unwrap_or_else(|| "Private".to_string())
    } else {
        "Messages".to_string()
    };
    let border_style = focus_border_style(state.focus == Focus::Messages);
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let log: &[LogEntry] = if let Some(peer) = dm_peer {
        state
            .private_rooms
            .get(&peer)
            .map(|r| r.log.as_slice())
            .unwrap_or(&[])
    } else {
        state
            .channels
            .get(state.selected_channel)
            .map(|c| c.log.as_slice())
            .unwrap_or(&[])
    };

    // OTP's own UI surface only exists inside a private room (see
    // `otp_active_peers`'s doc) - a channel log never gets the shield
    // prefix, regardless of any individual member's OTP status.
    let shield_active = dm_peer.is_some_and(|peer| state.is_otp_active(peer));

    let items: Vec<ListItem> = log
        .iter()
        .map(|entry| {
            let mut line = match &entry.body {
                MessageBody::Text(text) => Line::from(format!("{}: {}", entry.from_name, text)),
                MessageBody::Voice { duration_ms, .. } => {
                    let label = format_duration_label(*duration_ms);
                    Line::from(vec![
                        Span::raw(format!("{}: ", entry.from_name)),
                        Span::styled(
                            format!("\u{1F534} {label}"),
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ),
                    ])
                }
                MessageBody::VoiceStreaming { .. } => {
                    let dot = if state.blink_on {
                        "\u{1F534}"
                    } else {
                        "\u{26AA}"
                    };
                    Line::from(vec![
                        Span::raw(format!("{}: ", entry.from_name)),
                        Span::styled(
                            format!("{dot} voice (streaming...)"),
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ),
                    ])
                }
                MessageBody::File {
                    filename,
                    total,
                    status,
                    ..
                } => {
                    let mut spans = vec![Span::raw(format!("{}: ", entry.from_name))];
                    if let Some(to_name) = &entry.to_name {
                        spans.push(Span::raw(format!("\u{2192} {to_name} ")));
                    }
                    match status {
                        FileTransferStatus::Pending => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (waiting for accept...)"),
                            Style::default().fg(Color::Cyan),
                        )),
                        FileTransferStatus::InProgress { bytes } => {
                            let pct = if *total == 0 {
                                100
                            } else {
                                ((*bytes as f64 / *total as f64) * 100.0).clamp(0.0, 100.0) as u32
                            };
                            spans.push(Span::styled(
                                format!("\u{1F4CE} {filename} {} {pct}%", progress_bar(pct)),
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ));
                        }
                        FileTransferStatus::Completed => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename}"),
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )),
                        FileTransferStatus::Rejected => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (rejected)"),
                            Style::default().fg(Color::DarkGray),
                        )),
                        FileTransferStatus::Failed => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (failed)"),
                            Style::default().fg(Color::Red),
                        )),
                    }
                    Line::from(spans)
                }
                MessageBody::System(text) => Line::from(Span::styled(
                    text.clone(),
                    Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
                )),
                MessageBody::Presence(text) => {
                    Line::from(Span::styled(text.clone(), Style::default().fg(Color::Yellow)))
                }
            };
            if shield_active
                && !matches!(entry.body, MessageBody::System(_) | MessageBody::Presence(_))
            {
                line.spans.insert(0, Span::raw("\u{1F6E1}\u{FE0F} "));
            }
            // A row whose async send turned out to have failed
            // (`UiState::mark_dm_message_failed`) is shown in red, same as
            // every other "this needs your attention" red the app already
            // uses - a failed send must never look identical to a
            // delivered one. The line's own style is a fallback under each
            // span's, but none of the spans built above (including the
            // shield prefix) set their own color, so this reliably paints
            // the whole row.
            if entry.failed {
                line.style = Style::default().fg(Color::Red);
            }
            ListItem::new(line)
        })
        .collect();

    // `highlight_style` only shows while this pane actually has focus
    // (matching the old per-item behavior); `ListState` is what makes the
    // log genuinely scrollable - ratatui computes whatever offset is
    // needed to keep `message_selected` on screen, rather than always
    // starting the view at the oldest message and cutting off anything
    // that doesn't fit.
    let highlight_style = if state.focus == Focus::Messages {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    let list = List::new(items).highlight_style(highlight_style);
    let mut list_state = ListState::default();
    if !log.is_empty() {
        list_state.select(Some(state.message_selected.min(log.len() - 1)));
    }
    frame.render_stateful_widget(list, inner, &mut list_state);
}

pub(crate) fn render_input_bar(frame: &mut Frame, area: Rect, state: &UiState) {
    let dm_peer_offline = state.active_dm_peer_offline();
    let dm_peer_trust_gated = state.active_dm_peer_trust_gated();
    let title = if state.recording {
        "Recording..."
    } else {
        "Message"
    };
    let border_style = if state.recording {
        Style::default().fg(Color::Red)
    } else {
        focus_border_style(state.focus == Focus::Input)
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(border_style);
    let inner = block.inner(area);

    // An offline DM peer can't receive anything typed here (`handle_input_key`
    // already refuses it) - replace whatever's in `input` with a clear,
    // red notice instead of showing a compose bar that looks usable but
    // silently does nothing. Same treatment for a Pending/Rejected identity
    // (docs/PROTOCOL.md §12).
    let mut spans = if dm_peer_offline {
        vec![Span::styled(
            "(user offline)",
            Style::default().fg(Color::Red),
        )]
    } else if dm_peer_trust_gated {
        vec![Span::styled(
            "(identity not verified)",
            Style::default().fg(Color::Red),
        )]
    } else {
        vec![Span::raw(state.input.as_str())]
    };
    if state.recording {
        spans.push(Span::styled(
            " \u{1F3A4} recording...",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);

    // Only show a blinking cursor here when this bar is actually focused,
    // nothing else (e.g. the join-channel popup) is drawn on top of it, and
    // there's actually text to edit (not the offline notice above).
    if state.focus == Focus::Input
        && state.mode == Mode::Normal
        && !dm_peer_offline
        && !dm_peer_trust_gated
    {
        let cursor_x =
            inner.x + (state.input.chars().count() as u16).min(inner.width.saturating_sub(1));
        frame.set_cursor_position((cursor_x, inner.y));
    }
}

/// Border style shared by every bordered region: yellow while it holds
/// focus, so it's obvious at a glance which one keystrokes go to; the
/// input bar overrides this with red while actively recording.
pub(crate) fn focus_border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

/// Terminal cell width of `s`, correcting `.chars().count()` for the
/// 2-cell-wide emoji this help text uses (\u{1F512}/\u{1F6A8}) - every other
/// character in here is a normal 1-cell one. Used only to size the help
/// popup to fit its own longest line; see `render_help_popup`.
fn display_width(s: &str) -> u16 {
    let wide = s
        .chars()
        .filter(|c| matches!(*c, '\u{1F512}' | '\u{1F6A8}'))
        .count();
    (s.chars().count() + wide) as u16
}

fn render_help_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    // Wide enough for the longest line plus the block's borders and a
    // 1-column breathing margin on each side, but capped at 90% of the
    // available width even if that clips the longest lines - a popup that
    // fills the whole screen is worse than one that clips a little text.
    let content_width = HELP_BODY
        .iter()
        .map(|l| display_width(l))
        .max()
        .unwrap_or(0);
    let max_allowed = (area.width as u32 * 9 / 10) as u16;
    let popup_width = (content_width + 4).min(max_allowed);

    // Tall enough for the whole text when the terminal allows it, capped
    // at 90% of the available height so the view underneath stays visible
    // as context - scrolling covers whatever doesn't fit.
    let popup_height = (HELP_BODY.len() as u16 + 2).min((area.height as u32 * 9 / 10) as u16);
    let popup = centered_rect(popup_width, popup_height, area);
    let block = Block::default()
        .title("Help (Ctrl+H / Esc to close, arrows to scroll)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    // The popup's actual on-screen height (and hence how many lines fit)
    // depends on the terminal size at render time, which `UiState` has no
    // reason to know - so the scroll offset stored in state is clamped
    // precisely here, against `inner.height`, rather than in `handle_key`
    // (which only loosely clamps against the total line count). This is
    // what actually makes the content scrollable rather than just
    // truncated: without it, a terminal shorter than the full help text
    // would permanently hide everything past the bottom of the popup.
    let visible_rows = inner.height as usize;
    let max_scroll = HELP_BODY.len().saturating_sub(visible_rows);
    let scroll = state.help_scroll.min(max_scroll);

    let lines: Vec<Line> = HELP_BODY.iter().map(|&text| help_line(text)).collect();
    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

/// Styles one help line: section headings in yellow (bold), a
/// shortcut/command item's keys in the default (bright) color with its
/// description in gray - so the shortcut itself is what stands out - and
/// plain prose/continuation lines entirely in gray. An item line is
/// recognised by its shape: a two-space indent, then the keys, then a run
/// of three-plus spaces before the description (every key column in
/// `HELP_BODY` keeps at least that gap; anything narrower is prose).
fn help_line(text: &'static str) -> Line<'static> {
    if HELP_HEADINGS.contains(&text) {
        return Line::from(Span::styled(
            text,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if text.is_empty() {
        return Line::from(text);
    }
    let is_item = text.starts_with("  ") && !text.starts_with("   ");
    if is_item
        && let Some(gap) = text[2..].find("   ").map(|i| i + 2)
    {
        let (keys, description) = text.split_at(gap);
        return Line::from(vec![
            Span::styled(keys, Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(description, Style::default().fg(Color::DarkGray)),
        ]);
    }
    Line::from(Span::styled(text, Style::default().fg(Color::DarkGray)))
}

pub(crate) fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

/// Shared by `ui_connect_popup`'s key-file picker and `file_send`'s
/// send-a-file browser - the same generic, fs-backed directory browser
/// (`FileBrowserState`), just titled differently for whichever popup is
/// currently using it (`"Select file"` there, `"Send file"` here).
///
/// Uses `ListState` rather than a fixed style-per-item (same fix as
/// `render_messages`' `list_state`): without it, `List` always starts
/// drawing at entry 0 and simply clips whatever doesn't fit, so selecting
/// past the bottom of the visible area moved `browser.selected` but never
/// scrolled the view to show it - `ListState` makes ratatui compute
/// whatever offset keeps the selected entry on screen.
pub(crate) fn render_file_browser(
    frame: &mut Frame,
    area: Rect,
    browser: &crate::client::file_browser::FileBrowserState,
    title_prefix: &str,
) {
    let popup = centered_rect(60, 20, area);
    let title = format!("{title_prefix} - {}", browser.current_dir.display());
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let items: Vec<ListItem> = browser
        .entries
        .iter()
        .map(|e| {
            ListItem::new(if e.is_dir {
                format!("{}/", e.name)
            } else {
                e.name.clone()
            })
        })
        .collect();
    let list = List::new(items).highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default();
    if !browser.entries.is_empty() {
        list_state.select(Some(browser.selected.min(browser.entries.len() - 1)));
    }
    frame.render_stateful_widget(list, inner, &mut list_state);
}
