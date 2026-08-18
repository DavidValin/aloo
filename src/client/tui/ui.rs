//! The "connected" screen: channel tabs, a user sidebar, the message log,
//! and the compose bar - plus the full-screen private-message room.
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
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::client::p2p::LinkStatus;
use crate::proto::{ChannelKind, KeyMode, UserId, UserInfo};

use super::channel::{ChannelTab, DwellState};
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

/// The help overlay's own text, `Up`/`Down`/`PageUp`/`PageDown`/`Home`/`End`-
/// scrollable (`UiState::help_scroll`) since it easily runs longer than a
/// typical terminal window - module-level (not local to
/// `render_help_popup`) so `UiState::handle_key`'s scroll clamping and the
/// renderer share one source of truth for how many lines there are.
const HELP_HEADINGS: [&str; 8] = [
    "Channels",
    "Messaging",
    "Private messages",
    "Voice messages",
    "File transfer",
    "Encryption (tag shown after each username)",
    "One-time-pad layer (optional, per contact)",
    "Identity pinning (id_store)",
];
const HELP_BODY: &[&str] = &[
    "Channels",
    "  \u{1F30D} public / \u{1F512} private   tab prefix shows a channel's kind at a glance",
    "  ]  /  [    switch tabs (joins after staying on one for 3s)",
    "  Ctrl+J     join/create a channel: name, Public/Private (Left/Right), optional password",
    "  /leave     leave the selected channel tab (a public one stays, offering to rejoin)",
    "",
    "Messaging",
    "  Tab        cycle focus: sidebar -> messages -> compose bar",
    "  Enter      send the typed message (compose bar focused)",
    "",
    "Private messages",
    "  Up / Down  pick a user (sidebar focused)",
    "  Enter      open a private room with the selected user",
    "  Esc        close the private room",
    "",
    "Voice messages",
    "  Space      hold to record & send live (not while composing); release to stop",
    "  Ctrl+Alt+P same, from anywhere - edit/disable in ~/.aloo/settings",
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
    "  Ctrl+C  quit      Ctrl+H  toggle this help      Up/Down  scroll",
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
    /// see `docs/SPEC.md` Functionality #7. Excluded from the OTP shield
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    JoinPrivatePopup,
    /// Shown after a `ChannelJoinRejected` (`PasswordRequired`/
    /// `WrongPassword`/`Banned`) naming `UiState::channel_password_target` -
    /// lets the user type a password and resubmit the same `JoinChannel`.
    /// See `crate::client::tui::channel::handle_channel_password_popup_key`.
    ChannelPasswordPopup,
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
    pub channels: Vec<ChannelTab>,
    pub selected_channel: usize,
    pub(crate) dwell: Option<DwellState>,
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
    /// command" notice (`submit_input`).
    pub status_notice: Option<(String, bool)>,
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
    /// terminals that never send `KeyEventKind::Release`.
    recording_last_seen: Option<Instant>,
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
            dwell: None,
            known_users: HashMap::new(),
            offline: HashSet::new(),
            link_status: HashMap::new(),
            private_rooms: HashMap::new(),
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
            otp_generate_confirm: None,
            otp_generate_focus: OtpChoice::Accept,
            otp_size_input: None,
            otp_size_text: String::new(),
            otp_size_error: None,
            otp_invites: HashMap::new(),
            otp_invite_queue: VecDeque::new(),
            otp_invite_focus: OtpChoice::Accept,
            status_notice: None,
            otp_active_peers: HashSet::new(),
            replaying: false,
            recording: false,
            recording_source: None,
            recording_last_seen: None,
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
                        let room = self
                            .private_rooms
                            .entry(peer)
                            .or_insert_with(|| PrivateRoom {
                                peer: fallback_peer,
                                log: Vec::new(),
                                unread: false,
                            });
                        push_log_entry(
                            &mut room.log,
                            &mut self.message_selected,
                            is_current,
                            entry,
                        );
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
    /// red sidebar entry) - a no-op if they're not actually in review, or
    /// already the one showing.
    pub(crate) fn reopen_identity_review(&mut self, peer: UserId) {
        if !self.identity_reviews.contains_key(&peer) {
            return;
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
            // Only scrolling is honored while the overlay is up; every
            // other key is swallowed. Closing is Ctrl+H only (not Esc
            // too): Esc already means "close the current private room" a
            // few branches down, and since that branch isn't gated on
            // `kind`, closing help via Esc could leak a second, unwanted
            // "close the DM" side effect once its paired `Release` arrives
            // and `help_open` has already flipped back to `false`. Keeping
            // open/close on the same keystroke sidesteps that entirely.
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
        if self.mode == Mode::FileSend {
            return self.handle_file_send_key(code);
        }

        match code {
            KeyCode::Char('[') => {
                self.start_or_advance_dwell(false);
                return None;
            }
            KeyCode::Char(']') => {
                self.start_or_advance_dwell(true);
                return None;
            }
            _ => {}
        }

        if modifiers.contains(KeyModifiers::CONTROL) {
            match code {
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

        // A public channel tab we've explicitly `/leave`t shows a rejoin
        // prompt instead of the normal sidebar+messages+compose view
        // (`render_left_channel_screen`) - the only thing Enter here does
        // is re-request joining it; every other key (besides `[`/`]`/
        // Ctrl+H/Ctrl+J, already handled above) is inert, since none of
        // the panes those would otherwise operate on are shown.
        if self.active_private_room.is_none()
            && let Some(channel) = self.channels.get(self.selected_channel)
            && channel.left
        {
            return match code {
                KeyCode::Enter => Some(UiAction::JoinChannel {
                    name: channel.name.clone(),
                    kind: ChannelKind::Public,
                    password: None,
                }),
                _ => None,
            };
        }

        if code == KeyCode::Esc {
            // Gated on `Press` only (same reasoning as the Ctrl+H toggle
            // above): a terminal that also reports `Release` for this key
            // must not act on it a second time, which matters here because
            // - unlike the plain `active_private_room = None` below,
            // idempotent either way - stopping playback is a real state
            // transition that a second, redundant firing must not follow
            // through the fallback branch and additionally close the room.
            if kind != KeyEventKind::Press {
                return None;
            }
            if self.replaying {
                self.replaying = false;
                return Some(UiAction::StopPlayback);
            }
            self.active_private_room = None;
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
        if self.input.trim() == "/leave" {
            // Always the currently selected channel tab - `/leave` takes
            // no argument. A no-op if that tab isn't actually joined (an
            // unjoined public tab, or one already `left`) - nothing to
            // leave.
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            let name = channel.name.clone();
            self.input.clear();
            return Some(UiAction::LeaveChannel { name });
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
    if let Some(peer_id) = state.active_private_room {
        super::direct_message::render_private_room(frame, area, state, peer_id);
    } else {
        super::channel::render_channel_view(frame, area, state);
    }
    if state.mode == Mode::JoinPrivatePopup {
        super::channel::render_join_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelPasswordPopup {
        super::channel::render_channel_password_popup(frame, area, state);
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
    // The status notice is a small non-modal banner, not a popup - drawn
    // absolutely last so a session outcome is always visible even over
    // everything above, without ever blocking input the way those do.
    if let Some((message, success)) = &state.status_notice {
        render_status_notice(frame, area, message, *success);
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
/// always-rendered surface.
fn render_status_notice(frame: &mut Frame, area: Rect, message: &str, success: bool) {
    let width = (message.len() as u16 + 4).min(area.width);
    let rect = Rect {
        x: area.width.saturating_sub(width),
        y: 1,
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
    let popup = centered_rect(64, 9, area);
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

    let popup = centered_rect(popup_width, 32, area);
    let block = Block::default()
        .title("Help (Ctrl+H to close, arrows to scroll)")
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

    let lines: Vec<Line> = HELP_BODY
        .iter()
        .map(|&text| {
            if HELP_HEADINGS.contains(&text) {
                Line::from(Span::styled(
                    text,
                    Style::default().add_modifier(Modifier::BOLD),
                ))
            } else {
                Line::from(text)
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
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
