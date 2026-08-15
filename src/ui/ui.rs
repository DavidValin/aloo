//! The "connected" screen: channel tabs, a user sidebar, the message log,
//! and the compose bar - plus the full-screen private-message room.
//!
//! `UiState` is pure interaction/presentation state: it never touches the
//! network or does any crypto. It hands back `UiAction`s (e.g.
//! "send this plaintext to these recipients") for the caller
//! (`crate::session`, dispatching into `crate::channel` /
//! `crate::direct_message`) to actually encrypt and put on the wire, and
//! is fed incoming server
//! events (already decrypted) through `on_*` methods. That split is what
//! makes it unit testable without a socket or an audio device.
//!
//! Channel-tab state/rendering lives in `crate::ui::channel`, private-room
//! (DM) state/rendering in `crate::ui::direct_message` - both add their
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

use crate::proto::{ChannelKind, KeyMode, UserId, UserInfo};

use super::channel::{ChannelTab, DwellState};
use super::direct_message::PrivateRoom;

/// Animation frames for the "regenerating a key" spinner shown at the top
/// right of the screen, right after the `Ctrl+H: Help` hint - see
/// `UiState::tick_spinner`. One full cycle per 6 calls to `tick_spinner`
/// while regenerating. Rendered in white (see `crate::ui::channel::render_channel_view`),
/// regardless of the surrounding hint text's own (dimmer) color.
pub const SPINNER_FRAMES: [char; 6] = ['_', '-', '\\', '|', '/', '-'];

/// How long to wait, after the most recent Space press/repeat, before
/// concluding the key was released. Most terminals only ever send
/// `KeyEventKind::Press` (never `Release`) for a physically held key, but
/// they *do* forward the OS's keyboard auto-repeat as a stream of Press
/// events while the key stays down - so an idle gap longer than the
/// widest realistic gap *between* those events means the key genuinely
/// came up. This is what makes push-to-talk work on any terminal, not
/// just ones that support the Kitty keyboard protocol's release
/// reporting.
///
/// Must be comfortably longer than the OS's initial repeat delay, not
/// just its steady-state repeat rate: after the first Press, the OS
/// waits one delay period (commonly 500-650ms - Linux/GNOME defaults to
/// 500ms, Windows and macOS default in the same range) before the
/// *first* repeat, and only then settles into the fast ~30-50ms cadence.
/// A threshold shorter than that initial delay (400ms was tried and
/// measurably too short) fires while the key is still held, sending a
/// truncated clip and then mistaking the eventual first repeat for a
/// brand new press - producing a burst of short clips instead of one
/// continuous recording for as long as Space stays down.
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
const HELP_HEADINGS: [&str; 7] = [
    "Channels",
    "Messaging",
    "Private messages",
    "Voice messages",
    "File transfer",
    "Encryption (tag shown after each username)",
    "Identity pinning (id_store / own_next_keys)",
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
    "  name \u{1F512} RSAPM  rsa_per_msg: a fresh key every message, signed by the one it replaces",
    "  name \u{1F512} RSA    static: one RSA keypair loaded from a file, for the whole session",
    "  name \u{1F6A8} PWD    static: one RSA keypair derived from a password",
    "  name \u{1F6A8} PLAIN  static: one RSA keypair auto-generated when you connected",
    "  name \u{1F6E1}\u{FE0F} PQH    static: ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM, loaded from a file",
    "",
    "Identity pinning (id_store / own_next_keys)",
    "  Remembers each nickname's full public key across sessions (not",
    "  just a hash) - exact match for rsa/password/pq_hybrid, or signature-",
    "  verified continuity for rsa_per_msg via own_next_keys (its key",
    "  changes every connect, so it needs proof, not comparison). none",
    "  is untracked. A mismatch opens a popup naming the peer with",
    "  Accept/Reject buttons; messaging with them is blocked until you",
    "  decide. Accept saves to disk right away and reveals anything of",
    "  theirs held while unresolved; Reject saves nothing and isn't",
    "  permanent - select them again to reconsider. Paths set in the",
    "  connect popup's id_store / own_next_keys fields.",
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
}

/// Which anchor a peer's identity mismatch failed against - drives the
/// case-specific wording `render_identity_review_popup` shows, and what
/// `session::handle_ui_action`'s `AcceptIdentity` arm needs to install the
/// new key. `docs/PROTOCOL.md` §12.4 (`StaticMismatch`, `rsa`/`password`)
/// and §12.6.3/§12.6.4 (`ResumeFailed`, `rsa_per_msg`) are two genuinely
/// different checks - a byte comparison vs. a signature that failed (or
/// simply hasn't yet happened) to verify against either anchor - so there's
/// no single "old key" to show for the resume case the way there is for a
/// static one. `ResumeFailed` covers three trigger points that all end up
/// needing the identical Accept behavior (install whatever key is
/// currently attached): an explicit resume signature that failed to verify
/// (`handle_key_rotated`'s `Failed` arm), a nickname with a pinned
/// continuity key seen again with no resume attempt at all yet
/// (`check_identity`'s `PerMessage` branch, checked the instant it's seen -
/// see §12.6.3), and an ordinary self-consistent (`Live`) rotation arriving
/// for a peer who's *already* gated for either of the first two reasons -
/// self-consistency alone never proves cross-session identity, so it must
/// not silently clear a gate that was opened because of it.
#[derive(Debug, Clone, PartialEq)]
pub enum IdentityCase {
    StaticMismatch {
        new_public_key_der: Vec<u8>,
        previous_public_key_der: Vec<u8>,
    },
    ResumeFailed {
        new_public_key_der: Vec<u8>,
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
    /// See `crate::ui::channel::handle_channel_password_popup_key`.
    ChannelPasswordPopup,
    /// The `/file` send flow (browse -> confirm) is open - see
    /// `crate::ui::file_send`. Data lives in `UiState::file_send`, not
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

/// A recipient's addressing info: their id, announced `KeyMode` (which
/// scheme to encrypt under - see `session::encrypt_for_one` vs
/// `session::encrypt_hybrid_envelope_for`), and their raw public key bytes
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
    /// A file send confirmed in the `/file` popup (`crate::ui::file_send`) -
    /// `crate::channel::handle_send_file` builds and sends one `FileOffer`
    /// per ready recipient (rsa_per_msg readiness is snapshotted here, same
    /// as a voice stream's recipients - see `docs/PROTOCOL.md`'s file
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
}

/// Which trigger started the current recording - `handle_key`'s Space
/// branch and `global_record_start`/`global_record_stop` (the global
/// Ctrl+Alt+P shortcut, see `crate::global_ptt`) both drive the same
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
    /// Mode::FileSend` - see `crate::ui::file_send`. `pub`, not
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
    /// Whether an `rsa_per_msg` key is currently being regenerated on
    /// `session::spawn_rotation_worker`'s background thread right now -
    /// drives the spinner shown at the top right of the screen. Set each
    /// tick by `tick_spinner`, which `session::run_connected_session` calls
    /// with whatever it reads off `SessionState`'s pending-rotation
    /// counter; `UiState` itself has no idea what a rotation *is*, only
    /// whether to animate.
    pub key_regenerating: bool,
    /// Index into `SPINNER_FRAMES`, advanced by `tick_spinner`.
    spinner_frame: usize,
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
    pub conn_quality: crate::netstats::ConnQuality,
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
            replaying: false,
            recording: false,
            recording_source: None,
            recording_last_seen: None,
            keyboard_release_reporting: false,
            audio_error: None,
            blink_on: false,
            help_open: false,
            help_scroll: 0,
            key_regenerating: false,
            spinner_frame: 0,
            identity_reviews: HashMap::new(),
            identity_review_queue: VecDeque::new(),
            identity_review_focus: IdentityChoice::Reject,
            pending_messages: HashMap::new(),
            cpu_usage_pct: 0.0,
            conn_quality: crate::netstats::ConnQuality::Unknown,
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
    pub fn set_conn_quality(&mut self, quality: crate::netstats::ConnQuality) {
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

    /// Removes `peer` from the review queue, wherever it is - not
    /// necessarily the front - and resets focus for whatever's now shown if
    /// the popup on screen actually changed. Shared by
    /// `resolve_identity_accept`/`resolve_identity_reject`.
    ///
    /// A person's Accept/Reject always targets `identity_review_queue.front()`
    /// (the only review the popup ever lets them act on), but `rsa_per_msg`'s
    /// silent auto-trust (`docs/PROTOCOL.md` §12.6.3, `session::
    /// handle_key_rotated`'s `Resumed` case calling `resolve_identity_accept`
    /// directly) can resolve *any* queued peer - a second peer's resume can
    /// verify while a first peer's review is still the one on screen. A
    /// plain `pop_front` here would silently disappear the wrong review.
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

    /// Called when a direct peer-to-peer link (`crate::p2p`) fails to
    /// establish or dies mid-session - there is no relay fallback, so
    /// whatever was pending against `peer_name` (a message, a call, a file)
    /// did not go through. Reuses the same error banner `recording_failed`/
    /// `playback_failed` use rather than inventing a new UI surface for it.
    pub fn p2p_link_failed(&mut self, peer_name: &str, reason: &str) {
        self.audio_error = Some(format!("direct connection to {peer_name} failed: {reason}"));
    }

    pub fn set_own_id(&mut self, id: UserId) {
        self.own_id = Some(id);
    }

    /// Called once per session (`session::run_connected_session`) with the
    /// result of querying the terminal's actual Kitty keyboard protocol
    /// support, as determined by `main.rs::setup_terminal`. When `true`,
    /// `tick_recording_timeout` stops guessing from silence and leaves
    /// stopping entirely to the real `KeyEventKind::Release` event.
    pub fn set_keyboard_release_reporting(&mut self, supported: bool) {
        self.keyboard_release_reporting = supported;
    }

    pub fn toggle_blink(&mut self) {
        self.blink_on = !self.blink_on;
    }

    /// Call periodically (same cadence as `toggle_blink`) with whether a
    /// key is being regenerated right now. Advances the spinner one frame
    /// per call while `is_regenerating`; resets to the first frame as soon
    /// as it stops, so the next time it starts it always begins from
    /// `SPINNER_FRAMES[0]` rather than resuming mid-cycle.
    pub fn tick_spinner(&mut self, is_regenerating: bool) {
        if is_regenerating {
            if self.key_regenerating {
                // was already spinning as of the last call - advance.
                self.spinner_frame = (self.spinner_frame + 1) % SPINNER_FRAMES.len();
            }
            // else: this is the first tick of a fresh run. `spinner_frame`
            // is already 0 (either never touched, or reset by the last
            // `false` call below), so the very first frame shown is
            // always `SPINNER_FRAMES[0]`, never a skipped-ahead frame.
        } else {
            self.spinner_frame = 0;
        }
        self.key_regenerating = is_regenerating;
    }

    /// The spinner character for the current frame - only meaningful
    /// while `key_regenerating` is `true`; renderers should check that
    /// first rather than relying on this alone.
    pub(crate) fn spinner_char(&self) -> char {
        SPINNER_FRAMES[self.spinner_frame]
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
    /// while focus is on the compose bar, where it types a literal space
    /// instead (otherwise you could never put a space in a message).
    ///
    /// Actually detecting "released" doesn't rely on
    /// `KeyEventKind::Release` (which only terminals supporting the Kitty
    /// keyboard protocol ever send) - every Press/Repeat just refreshes
    /// `recording_last_seen`, and `tick_recording_timeout` (polled
    /// periodically by `session::run_connected_session`'s tick) auto-stops
    /// once that goes quiet for
    /// `RECORD_HOLD_TIMEOUT`. A real `Release`, when a terminal does send
    /// one, still stops it immediately as a fast path.
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

        // Ctrl+H toggles the help overlay and takes priority over
        // everything else below, so it works from any view/mode/focus,
        // even mid-recording or with another popup already open. Gated on
        // `Press`: on a terminal with the Kitty keyboard protocol enabled
        // (see `set_keyboard_release_reporting`), the matching `Release`
        // for this same keystroke also reaches here - toggling on both
        // would open it and immediately close it again in one keystroke.
        // Both `Press` and `Release` return `None` here unconditionally,
        // so the `Release` is absorbed rather than falling through to
        // whatever a bare `KeyCode::Char('h')` might otherwise do.
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
            let action = UiAction::SendDirectText {
                to: peer_id,
                plaintext: text.clone(),
                recipient_key_mode: peer.key_mode,
                recipient_pubkey_der: peer.public_key_der,
            };
            self.push_outgoing_dm(peer_id, MessageBody::Text(text));
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

    /// Starts a recording from the global (works-anywhere) Ctrl+Alt+P
    /// shortcut - `session::run_connected_session`'s `hotkey_rx` select arm
    /// calls this on every `GlobalPttEvent::Pressed`. Deliberately mirrors
    /// `handle_key`'s Space branch (same target resolution, same "nowhere
    /// to send it" bail-out as AC-034) rather than sharing code with it:
    /// the two differ in exactly one place (`RecordSource` tagging) and
    /// Space's branch also has to interleave with focus/mode handling that
    /// has no meaning for a shortcut that fires while this app isn't even
    /// the focused window. A no-op while a recording (from either source)
    /// is already in progress, so a second press can't stomp on it.
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

    /// Call periodically from the UI loop; auto-stops a recording once
    /// Space has been quiet for `RECORD_HOLD_TIMEOUT`, for terminals that
    /// never send `KeyEventKind::Release` (see `handle_key`). A no-op when
    /// `keyboard_release_reporting` is `true`: on those terminals, a real
    /// `Release` event is guaranteed, so this idle guess is never needed
    /// and must never fire - the recording keeps going through any pause
    /// or silence and only ends when Space is actually let go.
    ///
    /// Also a no-op for a `Global`-sourced recording (`RecordSource`),
    /// unconditionally - there's no repeat-keypress heartbeat for a held
    /// OS-level hotkey to go quiet, so `recording_last_seen` is never
    /// refreshed for one, and every platform backend behind the global
    /// shortcut delivers a real release event, so this idle guess is both
    /// meaningless and unsafe to apply there (it would auto-stop the
    /// recording ~`RECORD_HOLD_TIMEOUT` after it started, every time).
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
        if !has_dm_history {
            for tab in &mut self.channels {
                tab.members.retain(|m| m.id != user_id);
            }
        }
    }

    /// Applies a validated `rsa_per_msg` key rotation (PROTOCOL.md §11) for
    /// `user_id`: every place a `UserInfo` for them is cached - not just
    /// `known_users`, but every channel's `members` list and any open
    /// `PrivateRoom`'s `peer` - is a separate clone (`on_user_joined`,
    /// `open_private_room`), so all of them need updating in place or the
    /// stale copies would keep being used to encrypt (`recipients_for_channel`,
    /// `current_voice_target` both read from `channel.members`, not
    /// `known_users`). A no-op if `user_id` isn't known yet.
    pub fn on_user_key_rotated(&mut self, user_id: UserId, new_public_key_der: Vec<u8>) {
        if let Some(user) = self.known_users.get_mut(&user_id) {
            user.public_key_der = new_public_key_der.clone();
        }
        for tab in &mut self.channels {
            if let Some(member) = tab.members.iter_mut().find(|m| m.id == user_id) {
                member.public_key_der = new_public_key_der.clone();
            }
        }
        if let Some(room) = self.private_rooms.get_mut(&user_id) {
            room.peer.public_key_der = new_public_key_der;
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
    // Drawn last of all - takes priority over even the help overlay, same
    // as it does in `handle_key`, so it's always interactable regardless
    // of what else happened to be open when the mismatch arrived.
    if let Some(review) = state.identity_review_open() {
        render_identity_review_popup(frame, area, review, state.identity_review_focus);
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
    render_identity_button(
        frame,
        button_cols[0],
        "Accept",
        focus == FileOfferChoice::Accept,
    );
    render_identity_button(
        frame,
        button_cols[1],
        "Reject",
        focus == FileOfferChoice::Reject,
    );
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
    render_identity_button(
        frame,
        button_cols[0],
        "Accept",
        focus == IdentityChoice::Accept,
    );
    render_identity_button(
        frame,
        button_cols[1],
        "Reject",
        focus == IdentityChoice::Reject,
    );
}

/// One Accept/Reject button - same border-vs-fill focus convention as
/// `ui_connect_popup::render_connect_button`: the border (block) always
/// keeps its own plain/yellow-focus style, and only the *inner* area gets
/// the solid highlight fill when focused, via the `Paragraph`'s own
/// `.style()` rather than a separate widget underneath it.
fn render_identity_button(frame: &mut Frame, area: Rect, label: &str, focused: bool) {
    let popup = centered_rect(16, 3, area);
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

    let items: Vec<ListItem> = log
        .iter()
        .map(|entry| {
            let line = match &entry.body {
                MessageBody::Text(text) => Line::from(format!("{}: {}", entry.from_name, text)),
                MessageBody::Voice { duration_ms, .. } => {
                    let label = crate::voice::format_duration_label(*duration_ms);
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
            };
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
