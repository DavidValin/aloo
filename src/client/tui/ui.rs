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
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ratatui::style::Color;

use crate::client::p2p::LinkStatus;
use crate::p2p_proto::ReceiptStage;
use crate::proto::{ChannelInfo, ChannelKind, Envelope, KeyMode, UserId, UserInfo};

use super::widgets::confirm_popup::Confirm;

/// Re-exported so the popup modules that already reach for it through
/// `super::ui` keep doing so - it lives in
/// `super::widgets::confirm_popup` now, beside the confirmation row it is
/// the building block of.
pub(crate) use super::widgets::confirm_popup::render_popup_button;

use super::channel::ChannelTab;
use super::direct_message::PrivateRoom;

// The render half of this module now lives in `super::render`. These are
// the pieces the rest of the app reaches for through `ui::` - re-exported
// so the split stayed a move, with no import churn in the modules that
// name them.
pub use super::help::{HELP_POPUP_TITLE, help_total_lines};
// `UiAction` and the log-row types moved to `super::action` and
// `super::log_entry`; re-exported here so the modules naming them through
// `ui::` did not have to change.
pub use super::action::UiAction;
pub use super::log_entry::{
    DeliveryRecipient, DeliveryStatus, FileRowProgress, FileTransferStatus, LogEntry,
    MessageBody, MessageCrypto, MessageDelivery,
};

// The live-call surface moved to `super::call`; re-exported here so the
// modules that reach for these through `ui::` did not have to change.
pub use super::call::{
    CallInvitePicker, CallMember, CallMemberState, CallTarget, CallUiState, PendingCallConfirm,
    PendingCallInvite,
};

pub use super::render::{
    CallColumns, ENCRYPTION_LABEL, END_CALL_CONFIRM_TITLE, KEY_FILE_LABEL, KEY_LABEL, KEY_OFFSET_LABEL, KEY_PER_RECIPIENT, KEY_SEQ_LABEL, NO_CRYPTO_INFO, NO_DELIVERY_INFO, RECEIVED_AT_LABEL, SENT_AT_LABEL, format_duration_label, render,
};
pub(crate) use super::render::{
    centered_rect, display_width, find_urls, focus_border_style, format_file_size, pack_rect, rect_contains, render_file_browser, render_input_bar, render_messages, unpack_rect,
};


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

/// `UiState::last_messages_area_height`'s value before any frame has ever
/// rendered - a reasonable-sized initial `resume_from_log` chunk rather
/// than loading nothing at all.
pub const DEFAULT_HISTORY_CHUNK_LINES: u16 = 24;

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
pub const SELECTOR_DROPDOWN_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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



/// What the `.txt` preview popup is showing (`UiState::file_preview`) -
/// content already loaded and, if oversized, already capped by
/// `session::handle_ui_action` before it ever reaches here, so rendering
/// stays pure (`render_txt_preview_popup`).
#[derive(Debug, Clone, PartialEq)]
pub struct FilePreviewState {
    pub from: UserId,
    pub stream_id: u64,
    pub filename: String,
    pub content: String,
    /// `true` if `content` was cut short of the file's real length
    /// (`file_transfer::PREVIEW_MAX_BYTES`) - shown as a notice at the
    /// bottom of the popup. `d` still saves the complete, untruncated
    /// file regardless: only the in-memory preview is capped.
    pub truncated: bool,
    pub scroll: usize,
}





/// Which acknowledgement is claiming a recipient read a message - the two
/// are not equally believable, and a row that can insist on the stronger
/// one does.
///
/// An ordinary `DeliveryReceipt` is an unsigned payload naming a `msg_id`,
/// with nothing tying it to the message's content: anyone on the link can
/// say it. An `OtpDeliveryAck` carries `sha256` of the nonce buried under
/// that message's pad, which only a party that actually decrypted it can
/// name (`docs/SPEC.md` "Proving an acknowledgement", AC-250). So on a
/// pad-protected leg the receipt is not accepted as proof of reading; the
/// pad's own ack is what turns the arrow green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryProof {
    /// The peer's `DeliveryReceipt` - their unproven word.
    Receipt,
    /// A verified `OtpDeliveryAck` (`client::otp::on_delivery_ack` has
    /// already checked the proof against what was recorded for the
    /// outstanding sequence; a mismatch never reaches here).
    PadAck,
}


/// What separates a nickname from the message body on a row whose
/// delivery this client tracks: an arrow, coloured by how far the message
/// has got (`DeliveryStatus::color`). A glyph every terminal draws
/// identically in one cell each, unlike an emoji, and one the colour can
/// actually be trusted to reach - which is the whole job here.
pub const DELIVERY_ARROW: &str = "->";
/// What separates them on every other row - an incoming message, a system
/// or presence line, an outgoing voice or file row. There is no delivery
/// to report on those, so the plain separator says nothing about one.
pub const PLAIN_SEPARATOR: &str = ":";

/// What the info popup writes beside each recipient, after that
/// recipient's own arrow (`render_message_info_popup`).
pub const DELIVERED_LABEL: &str = "DELIVERED";
pub const UNDELIVERED_LABEL: &str = "UNDELIVERED";
/// What a leg reads while it is waiting on disk for that recipient to
/// become reachable (`queue_send_messages`, `client::outbox`) - a
/// stronger claim than `UNDELIVERED_LABEL`, which says only that nothing
/// has come back yet: this one says it is being kept and will go.
pub const QUEUED_LABEL: &str = "QUEUED";

/// The speaker-with-no-waves glyph both mute indicators use: beside one
/// name in the sidebar for a `/mute-voice`d person (`docs/SPEC.md`
/// Functionality #16), and once in the header while `voice_autoplay` is
/// off and nobody's voice is playing at all (Functionality #32).
pub const VOICE_MUTED_MARKER: &str = "\u{1F507}";
/// What a voice message reads once the recipient has actually heard it -
/// on arrival, or later if it was muted at the time and they replayed it.
pub const LISTENED_LABEL: &str = "DELIVERED+LISTENED";
/// What a file transfer reads once the recipient has the whole of it on
/// disk, rather than merely having been able to read the offer.
pub const SAVED_LABEL: &str = "DELIVERED+SAVED";
/// What a `.txt` file transfer reads once the recipient has opened it in
/// the preview popup without saving it - a weaker claim than `SAVED_LABEL`,
/// which always wins once true (`recipient_label`).
pub const VIEWED_LABEL: &str = "DELIVERED+VIEWED";

/// What one recipient's line of the details popup says, and the colour to
/// say it in. `body` decides the wording of the consumed state: the extra
/// state a voice message can reach is not the one a file reaches, and a
/// text message has no further state at all.
pub fn recipient_label(recipient: &DeliveryRecipient, body: &MessageBody) -> (&'static str, Color) {
    if !recipient.delivered {
        // Held for them rather than merely unacknowledged - the same
        // "partway there" colour a channel send wears while only some of
        // its recipients have it, since this one really is on its way.
        if recipient.queued {
            return (QUEUED_LABEL, DeliveryStatus::Some.color());
        }
        return (UNDELIVERED_LABEL, DeliveryStatus::None.color());
    }
    let green = DeliveryStatus::All.color();
    if !recipient.consumed {
        // SAVED always outranks VIEWED once it's true, so this branch is
        // the only place VIEWED can ever be reported.
        if recipient.viewed && matches!(body, MessageBody::File { .. }) {
            return (VIEWED_LABEL, green);
        }
        return (DELIVERED_LABEL, green);
    }
    match body {
        MessageBody::Voice { .. } | MessageBody::VoiceStreaming { .. } => (LISTENED_LABEL, green),
        MessageBody::File { .. } => (SAVED_LABEL, green),
        // Nothing else ever reports being consumed; if one somehow did,
        // saying only what is certain beats inventing a word for it.
        _ => (DELIVERED_LABEL, green),
    }
}







/// Whether appending a row should raise its surface's unread flag.
///
/// A `bool` at twenty call sites reads as nothing at all - `true` could
/// as easily mean "this row is unread" as "this surface now is". Only
/// ever *sets* the flag, never clears it: reading a surface is what
/// clears it (`select_channel_at`/`select_dm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unread {
    /// Someone else's content arriving somewhere the user is not looking.
    Mark,
    /// This client's own row, or a notice it wrote itself - neither is
    /// news to the person who caused it.
    Leave,
}


/// The combining long stroke overlay - one per character is what draws a
/// line through text in a terminal, which has no styling for it (ratatui's
/// `Modifier::CROSSED_OUT` is an ANSI attribute plenty of terminals ignore).
pub const STRIKE_OVERLAY: char = '\u{0336}';

/// `s` with `STRIKE_OVERLAY` after every character, so it renders struck
/// through. A combining mark attaches to the character *before* it, so the
/// order matters and an empty string stays empty rather than growing a
/// stroke attached to nothing.
pub fn strike_through(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        out.push(c);
        out.push(STRIKE_OVERLAY);
    }
    out
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


/// Whatever a `direct_punch_to` nickname with no pinned key sent that would
/// normally have proved who they are - captured instead of being silently
/// dropped, so a "Yes" to `render_unknown_peer_popup` has something real to
/// scan (`session::scan_pinned_keys_for_match`) rather than nothing at all.
/// Holds exactly what the ordinary registration path would otherwise have
/// consumed, so a confirmed match can finish registration from it without a
/// second decrypt (`docs/PROTOCOL.md` §7.1.5).
#[derive(Debug, Clone, PartialEq)]
pub enum UnverifiedDirectProof {
    /// A `Content::ChannelPresence` envelope, exactly as
    /// `session::on_channel_presence` receives it.
    ChannelPresence { envelope: Envelope },
    /// An OTP-wrapped `P2pEvent::OtpMessage`'s payload, exactly as
    /// `client::otp::on_message` receives it. Only ever matched against a
    /// candidate whose pin decodes as a `pq_hybrid` keybundle - a `pq_hybrid`
    /// identity with an OTP session layered on top of it - never against a
    /// pad-only pin, which would mean running every locally-held one-time
    /// pad's own decrypt against an unverified ciphertext.
    OtpMessage {
        channel: Option<String>,
        seq: u64,
        msg_id: Option<u64>,
        envelope: Envelope,
    },
}

/// Which screen an unknown-direct-peer review is showing - two sequential
/// questions about the same review, not a withheld-vs-shown distinction
/// like `IdentityStatus`.
#[derive(Debug, Clone, PartialEq)]
pub enum UnknownPeerStage {
    /// "A connection was received directly ... unknown nickname ... check
    /// which of your local keys matches?" - Yes runs the real scan.
    Initial,
    /// The scan found exactly one match; showing "I found that the request
    /// from <requested_nickname> matches your local key for <nickname> ...
    /// use it?" - Yes pins, No discards just this offer. Carries what the
    /// scan already recovered so confirming never decrypts a second time -
    /// for an OTP match the pad's own position has already moved past that
    /// ciphertext by the time this stage exists.
    ConfirmMatch {
        matched_nickname: String,
        matched_key_der: Vec<u8>,
        recovered: RecoveredProof,
    },
}

/// What a successful scan already recovered from `UnverifiedDirectProof` -
/// held on `UnknownPeerStage::ConfirmMatch` so `session::handle_ui_action`'s
/// `ConfirmUnknownPeerKey` arm can finish registration from it directly.
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveredProof {
    ChannelPresence {
        plaintext: Vec<u8>,
    },
    OtpMessage {
        plaintext: Vec<u8>,
        ack_proof: crate::crypto::otp::AckProof,
        contact_name: String,
    },
}

/// One outstanding unknown-direct-peer review, keyed by the `UserId` the
/// punched link is filed under (same keying `identity_reviews` uses).
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownPeerReview {
    /// The nickname the punch actually named - not yet pinned to anything.
    pub requested_nickname: String,
    pub stage: UnknownPeerStage,
    /// Held so a "Yes" on `Initial` has something to scan without a second
    /// round trip through `session.rs`'s event handling.
    pub proof: UnverifiedDirectProof,
    /// The link's address at the moment this review was first opened
    /// (`PeerLinkManager::active_addr`) - what `record_direct_proof_failure`
    /// bans against if the scan comes back with no match.
    pub source_addr: std::net::SocketAddr,
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

/// The icon a private channel carries in the top row and in a dropdown,
/// ahead of its `#name` - a public one carries none at all, so an
/// unadorned `#name` is itself the "this is public" signal
/// (`docs/SPEC.md` "Connected UI").
pub(crate) fn channel_kind_icon(kind: ChannelKind) -> &'static str {
    match kind {
        ChannelKind::Public => "",
        ChannelKind::Private => "\u{1F512} ",
    }
}

/// How a channel is named wherever it can be picked: its kind icon (empty
/// for a public one), then the `#` that says "this is a channel" and the
/// name itself (`docs/SPEC.md` "Connected UI"). The `#` is decoration -
/// what is stored and sent is the bare name
/// (`validation::normalize_channel_name`).
pub(crate) fn channel_label(kind: ChannelKind, name: &str) -> String {
    format!(
        "{}{}{name}",
        channel_kind_icon(kind),
        crate::validation::CHANNEL_DISPLAY_PREFIX
    )
}

pub(crate) const DM_ICON: &str = "\u{1F4AC}";

/// The one glyph a one-time-pad session is marked with, wherever it is
/// marked (`docs/PROTOCOL.md` §16): on the row of every message the pad
/// protects, and in the `OTP_TAG` those same people carry in the user
/// list, on the DM selector and on their dropdown row.
///
/// A key rather than a shield, and deliberately not the \u{1F6E1}\u{FE0F}
/// one `pq_hybrid` already carries (`proto::KeyMode::label`): the pad
/// normally runs *over* pq_hybrid, so sharing a glyph would mean the marker
/// for the extra layer and the marker for the layer under it were the same
/// character - and the whole job of both is telling them apart. A one-time
/// pad is key material spent once and destroyed, which is what the key
/// says and what nothing else in this UI claims.
pub const OTP_ICON: &str = "\u{1F511}";

/// The tag a peer carries while a pad session is open with them, in place
/// of the `my_key` tag they would otherwise show. `OTP_ICON` plus the name
/// of the layer, so the glyph on their row and the glyph on their messages
/// are recognisably one thing (`otp_tag_and_icon_are_the_same_marker`
/// keeps the two from drifting apart).
pub const OTP_TAG: &str = "\u{1F511} OTP";

/// The colour that tag is drawn in, wherever it appears - the same cyan
/// the room's own OTP session header uses for `OTP SESSION`
/// (`direct_message::render_otp_header`), so the two read as one fact.
pub const OTP_TAG_COLOR: Color = Color::Cyan;

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
/// kind prefix (\u{1F512} for a private channel, none for a public one, \u{1F4AC} for a DM), `unread` drives the
/// blinking envelope beside it (`render_selector_dropdown`).
pub struct SelectorEntry {
    pub label: String,
    pub unread: bool,
    /// Whether a one-time-pad session is open with this row's peer, which
    /// makes it carry `OTP_TAG` (`UiState::encryption_tag`). Always
    /// `false` for a channel row: a pad is provisioned per contact, and a
    /// channel is not one.
    pub otp: bool,
    /// `Some` only for a DM row: how reachable that peer is, coloured the
    /// same way their name is everywhere else. A channel is not a person
    /// and has nobody's reachability to report.
    pub presence: Option<crate::client::presence::Presence>,
}

/// Whether `text` mentions `nickname` as `@<nickname>`.
///
/// **Case-sensitive**, deliberately: the server treats `bob` and `Bob` as
/// two different people (`users_registry` compares nicknames exactly, and
/// only email addresses case-insensitively), so a case-folded match would
/// sound one person's ping for a message addressed to another.
///
/// Both ends of the match are bounded so a mention is a whole word:
/// the `@` may not follow a nickname character (`alice@bob` is an address,
/// not a mention), and the nickname may not be followed by one
/// (`@bobby` is not `@bob`). Nickname characters are exactly what
/// `validation::nickname_is_registrable` allows - ASCII alphanumerics,
/// `-` and `_`.
pub fn text_mentions(text: &str, nickname: &str) -> bool {
    if nickname.is_empty() {
        return false;
    }
    let is_nick_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let needle_len = nickname.len();
    for (at, _) in text.match_indices('@') {
        if text[..at].chars().next_back().is_some_and(is_nick_char) {
            continue;
        }
        let rest = &text[at + 1..];
        if !rest.starts_with(nickname) {
            continue;
        }
        if rest[needle_len..].chars().next().is_some_and(is_nick_char) {
            continue;
        }
        return true;
    }
    false
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
    /// The `/contacts` modal is open - see `crate::client::tui::contacts`.
    /// Data lives in `UiState::contacts`, same split as `FileSend`/
    /// `file_send`.
    Contacts,
    /// The Ctrl+S "Settings" popup is open - see
    /// `crate::client::tui::settings_popup`. Data lives in
    /// `UiState::settings_popup`, same split as `FileSend`/`file_send`.
    Settings,
    /// The channel admin's `/lock-joins` popup is open - see
    /// `crate::client::tui::channel_lock_popup`. Data lives in
    /// `UiState::channel_lock`, same split as `FileSend`/`file_send`.
    ChannelLockPopup,
    /// The `Ctrl+E` export popup is open - see
    /// `crate::client::tui::export_popup`. Data lives in
    /// `UiState::export_popup`, same split as `FileSend`/`file_send`.
    ExportPopup,
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








/// A pending `/delete-channel` or `/assign-admin` confirmation - built
/// once, right when the command is typed, so the popup itself stays
/// generic (one title, one question, one action to fire on Confirm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelCommandConfirm {
    pub title: &'static str,
    pub question: String,
    pub action: ChannelCommandConfirmAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelCommandConfirmAction {
    DeleteChannel { name: String },
    AssignAdmin { channel: String, nickname: String },
}






/// The local "generate and share a fresh pad?" decision after `/otp` finds
/// no existing keychain entry (`client::otp::handle_otp_command`) - never
/// acted on without this confirmation, see `docs/PROTOCOL.md` §16.1.
#[derive(Debug, Clone)]
pub struct PendingOtpGenerate {
    pub peer: UserId,
    pub peer_name: String,
    pub pubkey_der: Vec<u8>,
    /// Which key this popup is generating - the contact name that decides
    /// it (`crypto::otp::contact_name_for`/`_mail`) doesn't exist yet at
    /// this point in the flow, so unlike `PendingOtpInvite` this can't be
    /// recovered from one later and has to be carried explicitly.
    pub purpose: crate::crypto::otp::OtpPurpose,
}

/// How far a pad generation has got, driving the spinner popup
/// (`render_otp_keygen_popup`). Generation runs off the event loop in its
/// own task (`client::otp::confirm_generate`), reporting through
/// `SessionState::otp_keygen_tx`, so the UI keeps redrawing and stays
/// responsive throughout - which is the whole point: at the sizes this now
/// allows (up to 1TB per key), a blocked, silent event loop would be
/// indistinguishable from a crash.
/// Which of a pad's two slow phases the popup is reporting on.
///
/// They are separate because they fail, and wait, for entirely different
/// reasons - generation is bounded by how fast this machine produces true
/// randomness, transfer by the link's round-trip time - and because a user
/// watching a bar that restarts at zero deserves to be told why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpPadPhase {
    /// `otp --new-key-pair` is still reading randomness.
    Generating,
    /// The pad exists here and is streaming to the peer.
    Sending,
    /// The peer's pad is streaming to us.
    Receiving,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpKeygenProgress {
    pub peer: UserId,
    pub peer_name: String,
    pub purpose: crate::crypto::otp::OtpPurpose,
    pub phase: OtpPadPhase,
    /// MB per key, as chosen in the size prompt - shown so the popup names
    /// what is being waited on, not just that something is.
    pub size_mb: u32,
    /// Randomness handed to `otp --new-key-pair` so far, and the total it
    /// will be handed (`2 * size_mb` MB - a pad is two independent keys).
    pub written_bytes: u64,
    pub total_bytes: u64,
    /// Advanced once per UI tick by `tick_otp_keygen_spinner`; indexes
    /// `SPINNER_FRAMES`. A spinner rather than only a percentage because
    /// the two answer different questions - "is it still going" and "how
    /// far" - and the first one matters most while waiting.
    pub frame: usize,
}

impl OtpKeygenProgress {
    /// `0.0..=1.0`, or `0.0` before the total is known (never divides by
    /// zero - `total_bytes` is `2 * size_mb` MB, so only a zero size could
    /// produce one, which the size prompt already refuses).
    pub fn fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.written_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
    }

    pub fn percent(&self) -> u16 {
        (self.fraction() * 100.0).round() as u16
    }
}

/// The spinner's animation frames, advanced one per UI tick.
pub const SPINNER_FRAMES: [&str; 8] = [
    "\u{280B}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283C}", "\u{2834}", "\u{2826}", "\u{2827}",
];

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

/// A recipient's addressing info: their id and their bootstrap keybundle
/// as announced (a bincode-encoded `crypto::pq::PqPublicBundle` - opaque
/// bytes until `envelope::encrypt_envelope_for` seals against it).
pub type Recipient = (UserId, Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub enum VoiceTarget {
    Channel {
        channel: String,
        recipients: Vec<Recipient>,
    },
    Direct {
        to: UserId,
        recipient_pubkey_der: Vec<u8>,
    },
    /// A recording destined for the mail being composed (docs/PROTOCOL.md
    /// §17.1) - nothing goes on the wire at all: the accumulate worker
    /// reports the finished PCM and it lands in the compose form's
    /// attachment list (`UiState::otp_mail_add_voice`).
    MailAttachment,
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

/// Where a session is pointed right now (`UiState::current_focus`) - the
/// live answer, as opposed to the `--initial-focus` a daemon was started with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentFocus {
    /// A channel tab is selected and joined.
    Channel(String),
    /// A private room is open, which takes precedence over any tab
    /// behind it - the same order `current_voice_target` resolves in.
    Dm(UserId),
    /// Nothing addressable: no tabs, or the selected one is still
    /// waiting on its `Joined` confirmation.
    Nowhere,
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
    pub(crate) selector_dropdown_since: Option<Instant>,
    /// Every public channel the server has announced (`ChannelList` at
    /// connect, `ChannelCreated` live) - the rows of the `/channels`
    /// modal, whether or not the user has joined them.
    pub known_channels: Vec<ChannelInfo>,
    /// Every nickname `server_superadmin` names, from the connect-time
    /// `ChannelList.superadmins` - fixed for the session, since the
    /// setting is fixed for the server's uptime. Drives the ⚡ marker
    /// shown next to a superadmin's name everywhere it appears, and the
    /// user-info popup's "is a ⚡ superadmin" line.
    pub superadmins: std::collections::BTreeSet<String>,
    /// Running with no server (`--no-server`, docs/PROTOCOL.md §7.1.5).
    /// Changes what the channel affordances can honestly offer: there is
    /// no directory to browse and nothing to create, so the only channels
    /// that exist are the ones `direct_punch_channel` names.
    pub serverless: bool,
    /// `<server>` component of `~/.aloo/exports/<server>/...`
    /// (`client::export`) - `export::DIRECT_LABEL` for a `--no-server`
    /// session, else `export::server_label(host, port)`. Set once at
    /// session start (`session::run_connected_session`) and never changed
    /// afterward, same lifetime as `serverless` above.
    pub server_label: String,
    /// `Settings::autosave_messages`, read once at session start
    /// (`session::run_connected_session`) - whether every arriving/sent
    /// log entry gets appended to `~/.aloo/exports/<server>/...` as it
    /// happens (`client::export::autosave_entry`). Like every other
    /// settings value this app reads at startup, a change to the file
    /// mid-session takes effect on the next run, not live.
    pub autosave_messages: bool,
    /// `Settings::resume_from_log`, read once at session start
    /// (`session::run_connected_session`) - whether opening a channel/DM,
    /// or scrolling to the top of what's currently loaded, pulls another
    /// chunk of older history back in from that surface's
    /// `autosave_messages` `.log` file (`UiState::load_history_chunk`,
    /// `client::export::LogHistoryCursor`).
    pub resume_from_log: bool,
    /// `Settings::voice_autoplay`, seeded at session start and written
    /// through live by the Ctrl+S settings popup - whether an arriving
    /// voice message plays itself at all. Off is a blanket version of
    /// `muted_voice`: it suppresses every sender rather than named ones,
    /// which is why both are asked through the one predicate
    /// (`suppress_playback_from`) rather than at each call site.
    pub voice_autoplay: bool,
    /// `Settings::queue_send_messages`, seeded at session start and
    /// written through live by the Ctrl+S settings popup.
    ///
    /// Read here for one decision only: whether a plain message to a DM
    /// peer who is currently offline may be composed and sent at all.
    /// With a durable queue behind it, "they are not here" stops being a
    /// reason to refuse the send - it is exactly the case the queue
    /// exists for (`client::outbox`). Everything that genuinely needs
    /// them present - a file transfer, `/otp`, a call - stays refused
    /// either way.
    pub queue_send_messages: bool,
    /// The message log's rendered height as of the last frame
    /// (`render_messages`, where `inner.height` is already computed) -
    /// interior mutability because `render` only ever receives `&UiState`,
    /// never `&mut`, so this is the one way key-handling code (which never
    /// sees a `Frame`) learns how many rows a history chunk should be
    /// sized to (`history_chunk_size`). `AtomicU16`, not `Cell`: a daemon
    /// session runs `run_daemon_session` inside `tokio::spawn`
    /// (`daemon.rs`), which needs the whole future - and so `UiState` -
    /// `Send`, which for a type held behind `&UiState` across an `.await`
    /// also needs it `Sync`; `Cell` isn't. `Ordering::Relaxed` throughout:
    /// this is a best-effort sizing hint, not a synchronization point.
    /// Starts at `DEFAULT_HISTORY_CHUNK_LINES` before the first frame has
    /// ever rendered.
    pub last_messages_area_height: AtomicU16,
    /// Where the input bar was last drawn, packed as a `Rect` (see
    /// `pack_rect`) - `AtomicU64` for the same `Sync`-without-`Cell`
    /// reason `last_messages_area_height` is an atomic, not a plain
    /// field. `UiState::handle_mouse` hit-tests a click against this
    /// instead of every popup's rendering code separately recording
    /// where it drew each clickable thing - recomputing from the actual
    /// last-drawn position rather than re-deriving the layout math by
    /// hand a second time, which would drift the moment one changed
    /// without the other. `u64::MAX` (never a real `Rect`, `height`
    /// alone already exceeds any real terminal) before the first frame.
    pub last_input_bar_area: AtomicU64,
    /// Where the channel view's member sidebar's *inner* area (inside its
    /// border) was last drawn - `handle_mouse` derives which row a click
    /// landed on from this alone, since every row is exactly one line
    /// tall in top-to-bottom order. Stale (the channel view's last
    /// position) while a DM or the mail view is showing instead, which
    /// render nothing here - `handle_mouse` only ever consults this while
    /// actually viewing a channel, the same guard that keeps it from
    /// honoring a click that landed on a popup drawn on top of it.
    pub last_sidebar_area: AtomicU64,
    /// Selected row of the `/channels` modal, into `known_channels`.
    pub channels_popup_selected: usize,
    pub known_users: HashMap<UserId, UserInfo>,
    /// Users whose connection has closed entirely (`on_user_offline`), as
    /// opposed to merely leaving one channel while staying connected
    /// (`on_user_left`). A `UserId` is never reused (PROTOCOL.md §3), so
    /// once inserted here an entry is never removed for the rest of the
    /// connection - there's no way for the same identity to come back
    /// online.
    ///
    /// A *reconnect* is the one thing that empties it wholesale
    /// (`forget_server_presence`), and does not contradict that: the ids in
    /// it belonged to the connection that ended, and the server behind the
    /// new one may not even be the same process. Nothing moves an id from
    /// offline back to online; the whole id space is dropped at once.
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
    /// `(message_selected, index into that message's links)` last opened
    /// with Ctrl+O - lets a repeated press cycle through a message with
    /// more than one link instead of reopening the first one every time.
    /// Compared against the *current* `message_selected` rather than reset
    /// on every cursor move, so no other navigation code needs to know
    /// about it.
    pub(crate) last_opened_url: Option<(usize, usize)>,
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
    /// The `/contacts` modal's state, while `mode == Mode::Contacts` - see
    /// `crate::client::tui::contacts`. `pub`, not `pub(crate)`, same
    /// reasoning as `file_send`: a test opening the "Install OTP key"
    /// sub-popup needs to overwrite its file browser with a deterministic
    /// temp directory.
    pub contacts: Option<super::contacts::ContactsState>,
    /// The Ctrl+S "Settings" popup's state, while
    /// `mode == Mode::Settings` - see
    /// `crate::client::tui::settings_popup`. Carries the direct-punch
    /// target list too, as that popup's Direct Punch tab.
    pub settings_popup: Option<super::settings_popup::SettingsPopupState>,
    /// The `/lock-joins` popup's state, while
    /// `mode == Mode::ChannelLockPopup` - see
    /// `crate::client::tui::channel_lock_popup`.
    pub channel_lock: Option<super::channel_lock_popup::ChannelLockPopupState>,
    /// The `Ctrl+E` export popup's state, while `mode == Mode::ExportPopup`
    /// - see `crate::client::tui::export_popup`.
    pub export_popup: Option<super::export_popup::ExportPopupState>,
    /// A pending `/delete-channel` or `/assign-admin` confirmation -
    /// answered the same way `call_confirm` is, reusing `Confirm`
    /// since both are a plain Confirm/Cancel over a one-line question.
    pub channel_command_confirm: Option<ChannelCommandConfirm>,
    pub(crate) channel_command_confirm_focus: Confirm,
    /// Every incoming file offer currently awaiting a decision, keyed by
    /// `(from, stream_id)` - the popup always shows whichever's at the
    /// front of `file_offer_queue`. Analogous to `identity_reviews`/
    /// `identity_review_queue`, but simpler: a decision here is final
    /// (`Accept`/`Reject` both remove the entry outright), there is no
    /// `Rejected`-but-reconsiderable state the way an identity review has.
    /// Which outgoing file row each transfer belongs to, and what those
    /// transfers have reported so far - see `FileRowProgress`. Empty for
    /// every send that is one transfer (a DM, and anything incoming),
    /// where a stream id is already its own row.
    file_row_of_stream: HashMap<u64, u64>,
    file_rows: HashMap<u64, FileRowProgress>,
    pub file_offers: HashMap<(UserId, u64), PendingFileOffer>,
    pub(crate) file_offer_queue: VecDeque<(UserId, u64)>,
    /// Reset to `Accept` every time a different offer becomes the one
    /// shown, same "always starts on the safe/common default" precedent
    /// `identity_review_focus` sets (there, `Reject`; here, `Accept` - see
    /// `PendingFileOffer`'s doc for why the default flips).
    pub(crate) file_offer_focus: Confirm,
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
    pub(crate) call_invite_queue: VecDeque<u64>,
    pub(crate) call_invite_focus: Confirm,
    /// Call invites received from a `Pending`/`Rejected` identity-review
    /// sender, held back the same way `pending_file_offers` holds a file
    /// offer - queued for real (`push_call_invite`, popup + bell) only once
    /// that sender is `Accept`ed (`resolve_identity_accept`).
    pub(crate) pending_call_invites: HashMap<UserId, Vec<PendingCallInvite>>,
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
    pub(crate) call_confirm_focus: Confirm,
    /// The local "generate and share a fresh OTP pad?" confirmation opened
    /// by `/otp` when no keychain entry exists yet
    /// (`client::otp::handle_otp_command`) - `None` when nothing is
    /// pending. Only ever one at a time: `/otp` itself is unreachable while
    /// any modal popup (including this one) is already absorbing input.
    pub(crate) otp_generate_confirm: Option<PendingOtpGenerate>,
    pub(crate) otp_generate_focus: Confirm,
    /// The pad-size prompt shown right after accepting `otp_generate_confirm`
    /// - carries the same peer info forward (nothing about who/what was
    /// asked changes, only whether a size has been chosen yet). `None`
    /// whenever `otp_generate_confirm` is, and vice versa - they're never
    /// both open, see `handle_key`'s ordering.
    pub(crate) otp_size_input: Option<PendingOtpGenerate>,
    /// Digits typed so far for `otp_size_input` - a plain `String` rather
    /// than a parsed number so an in-progress, momentarily-invalid edit
    /// (a leading digit before more follow, or a backspace mid-edit) is
    /// never rejected while still being typed; only Enter validates.
    pub otp_size_text: String,
    /// Set by an out-of-range or unparseable submission
    /// (`crypto::otp::otp_size_mb_in_range`) - shown under the input,
    /// cleared the next time the popup opens or a key changes the text.
    pub otp_size_error: Option<String>,
    /// `Some` while a pad is actually being generated
    /// (`client::otp::confirm_generate` through to the background
    /// generation task finishing) - drives the spinner popup, since a pad
    /// large enough to be worth choosing can take minutes and silence
    /// there is indistinguishable from a hang.
    pub(crate) otp_keygen: Option<OtpKeygenProgress>,
    /// Every incoming OTP session proposal currently awaiting a decision,
    /// keyed by the sender - mirrors `file_offers`/`file_offer_queue`
    /// exactly (queued-popup idiom, `Accept`-first default).
    pub(crate) otp_invites: HashMap<UserId, PendingOtpInvite>,
    pub(crate) otp_invite_queue: VecDeque<UserId>,
    pub(crate) otp_invite_focus: Confirm,
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
    pub(crate) status_notice_since: Option<Instant>,
    /// Peers a mutual-consent OTP session has genuinely started with in
    /// this connection (set alongside the "OTP session started" notice,
    /// `client::otp::accept_invite`/`on_key_setup_ack`) - drives the pad
    /// prefix a DM room's messages get while it's active
    /// (`render_messages`). Scoped to DMs: OTP's own UI surface (`/otp`,
    /// both popups) only ever exists inside a private room, so that is
    /// where "in OTP mode" has an unambiguous meaning - a channel send may
    /// wrap per-recipient under a contact's pad too, but a channel log has
    /// no single peer for a pad marker to describe.
    ///
    /// Keyed by connection-lifetime `UserId`, unlike the actual send-path
    /// gate (`SessionState::otp_store`, keyed by the fingerprint-derived
    /// contact name, which is what genuinely decides whether a send gets
    /// OTP-wrapped and survives a reconnect on its own). This set alone
    /// would therefore go stale - showing "inactive" - the instant a peer's
    /// `UserId` changes, even though the underlying session is still very
    /// much alive; `mark_otp_active` is re-called for the fresh `UserId` the
    /// moment we learn a reconnected peer is provisioned again
    /// (`session::handle_server_message`'s `UserJoined` arm), which is what
    /// makes this set track the persistent session rather than the
    /// connection. The only thing that ever removes an entry is `/endotp`
    /// (`clear_otp_active`), on either side - never a disconnect.
    pub(crate) otp_active_peers: HashSet<UserId>,
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
    pub(crate) otp_key_status: HashMap<UserId, crate::client::otp_cli::OtpKeyStatus>,
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
    pub(crate) keyboard_release_reporting: bool,
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
    /// A superadmin's `/deactivate` just landed against this account,
    /// carrying the reason - drives the full-screen red takeover modal
    /// (`render_account_deactivated_modal`), checked as the very top
    /// priority tier in `handle_key`, above even `identity_review_queue`.
    /// Independent of `Mode`/`focus` for the same reason `help_open` is:
    /// it must override *any* view or mode, and there is nothing to
    /// "return to" once it's shown - Escape ends the whole session.
    pub account_deactivated: Option<String>,
    /// First visible line index into the overlay's laid-out lines while it is
    /// open - `Up`/`Down`/`PageUp`/`PageDown`/`Home`/`End` adjust it
    /// (`handle_key`), reset to `0` every time the overlay is freshly
    /// opened (`tick`-independent, done right in the Ctrl+H toggle) so it
    /// never reopens mid-scroll from last time. Clamped loosely here
    /// (against the total line count) and precisely at render time
    /// (`render_help_popup`, against the popup's actual visible height,
    /// which `UiState` has no reason to know) - see there.
    pub(crate) help_scroll: usize,
    /// The staged `.txt` receive currently open in the preview popup
    /// (`Enter` on a `FileTransferStatus::Received` row -
    /// `UiAction::RequestFilePreview`), or `None` when it's closed. The
    /// content itself is loaded by `session::handle_ui_action` (`UiState`
    /// has no disk access) and handed back via `open_file_preview`.
    pub file_preview: Option<FilePreviewState>,
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
    pub(crate) identity_review_queue: VecDeque<UserId>,
    /// Which button is focused in the currently-open popup. Reset to
    /// `Reject` (the non-trusting default) every time a different peer's
    /// review becomes the one shown, so accepting always takes a deliberate
    /// move off the safe default rather than an accidental double-Enter.
    pub(crate) identity_review_focus: Confirm,
    /// One outstanding "an unknown direct-punch nickname sent proof" review
    /// per peer (`docs/PROTOCOL.md` §7.1.5) - a different question from
    /// `identity_reviews` (no identity at all, rather than one that
    /// changed), so it is its own independent family rather than a case of
    /// `IdentityCase`. Populated by `push_unknown_peer_review` (called from
    /// `session::on_channel_presence`/`client::otp::on_message` when a
    /// `direct_punch_to` nickname with no pinned key sends whatever would
    /// normally prove it), resolved by `session::handle_ui_action`'s
    /// `CheckUnknownPeerIdentity`/`DeclineUnknownPeerIdentity`/
    /// `ConfirmUnknownPeerKey`/`DeclineUnknownPeerKey` arms.
    pub unknown_peer_reviews: HashMap<UserId, UnknownPeerReview>,
    /// Peers with a review not yet shown, front-first - same one-at-a-time
    /// shape as `identity_review_queue`.
    pub(crate) unknown_peer_review_queue: VecDeque<UserId>,
    /// Which button is focused in the currently-open popup. Reset to `No`
    /// every time a different peer's review becomes the one shown, for the
    /// same reason `identity_review_focus` resets to `Reject`.
    pub(crate) unknown_peer_review_focus: Confirm,
    /// Messages/streams received from a `Pending`/`Rejected` peer, held
    /// back from the visible channel/DM log until they're `Accepted`
    /// (`docs/PROTOCOL.md` §12 "hold and reveal") - see `HeldMessage`.
    pub pending_messages: HashMap<UserId, Vec<HeldMessage>>,
    /// Source of `MessageDelivery::msg_id`. Session-scoped and
    /// monotonic, which is all a delivery tag has to be: it is only ever
    /// compared against ids this same client handed out, and never
    /// survives a restart (a message whose acknowledgement has not arrived
    /// by then never gets one - see `docs/PROTOCOL.md` 7.2.1).
    next_msg_id: u64,
    /// Which row of the current log the message info popup is open on, as
    /// an index into `current_log` (`docs/SPEC.md` "Delivery
    /// acknowledgments"). An index rather than a snapshot, so the
    /// delivery states it shows keep updating while it is open; safe
    /// because logs are append-only and the popup absorbs every key that
    /// could change which conversation is on screen.
    pub(crate) message_info: Option<usize>,
    /// The user-info popup (`i` on a channel member, `/info` in an open
    /// DM) - opened empty (`open_user_info`), filled in once
    /// `client::contacts::handle_request_user_info` has gathered it
    /// (`set_user_info`), same split `ContactsState::rows` uses.
    pub user_info: Option<super::contacts::UserInfoState>,
    /// The superadmin `/users` popup - every registered user and the
    /// channels each administers. Opened empty (`open_users_admin`),
    /// filled in once `ServerMessage::UsersList` answers
    /// (`set_users_admin`), same split `ContactsState::rows` uses. `None`
    /// for anyone who never ran `/users` - there is nothing to gate on
    /// client-side beyond that, since the server refuses the request
    /// itself for a non-superadmin (`server::mod::require_superadmin`).
    pub users_admin: Option<Vec<crate::proto::UserAdminInfo>>,
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
    /// `(active, total, next attempt in)` from `PeerLinkManager::direct_punch_summary`,
    /// refreshed once a second by `session::run_connected_session` the same
    /// way `conn_quality` is, and shown at the left of the status line as
    /// "<active>/<total> (next: <time>)".
    /// `None` when direct punching is not configured at all - nothing is
    /// shown, rather than a permanent "0/0".
    pub direct_punch_status: Option<(usize, usize, Option<std::time::Duration>)>,
    /// How many received OTP mails haven't been opened yet
    /// (`otp_mail_store::OtpMailStore::unread_received_count`), refreshed
    /// whenever the received set can have changed (arrival, read, delete)
    /// and once at session start. Shown at the header's leftmost as
    /// "<n> unread OTP Mails" behind a blinking envelope; `0` shows nothing.
    pub unread_otp_mail_count: usize,
    /// What the control connection is doing, shown as the header's very
    /// first element (`docs/SPEC.md` "Connected UI"). Driven by
    /// `session::run_connected_session` from the reconnect supervisor's
    /// events (`crate::client::reconnect`), and fixed at `NoServer` for
    /// the whole of a `--no-server` session, which has no supervisor and
    /// nothing to reconnect to.
    pub server_link: crate::client::reconnect::ServerLinkState,
    /// Nicknames whose incoming voice messages must not autoplay
    /// (`/mute-voice`, docs/SPEC.md Functionality #15), mirroring
    /// `settings::Settings::muted_voice` - loaded from `~/.aloo/settings`
    /// at session start and written straight back through
    /// `Settings::update_muted_voice` on every change.
    ///
    /// Lives here, beside `identity_reviews`, because this is the other
    /// half of the same question `is_trust_gated` answers: whether audio
    /// from a given peer is allowed to reach the mixer. Keyed by nickname
    /// rather than `UserId` - see that field's own doc for why.
    pub muted_voice: std::collections::BTreeSet<String>,
    /// Whether this session is running inside a daemon (`aloo --daemon`),
    /// which is what makes `/daemon` meaningful: only a session that has
    /// somewhere to go back *to* can be sent to the background.
    ///
    /// A foreground session cannot background itself - doing so would mean
    /// re-parenting a live process along with its open TCP control
    /// connection and UDP peer links - so there `/daemon` explains itself
    /// rather than half-working.
    pub daemon_mode: bool,
}

impl UiState {
    pub fn new(own_name: String) -> Self {
        Self {
            own_id: None,
            own_name,
            muted_voice: std::collections::BTreeSet::new(),
            daemon_mode: false,
            channels: Vec::new(),
            selected_channel: 0,
            selector_focus: SelectorFocus::Channels,
            selector_dropdown_open: false,
            selector_dropdown_since: None,
            known_channels: Vec::new(),
            superadmins: std::collections::BTreeSet::new(),
            serverless: false,
            server_label: crate::client::export::DIRECT_LABEL.to_string(),
            autosave_messages: false,
            resume_from_log: false,
            voice_autoplay: true,
            queue_send_messages: true,
            last_messages_area_height: AtomicU16::new(DEFAULT_HISTORY_CHUNK_LINES),
            last_input_bar_area: AtomicU64::new(u64::MAX),
            last_sidebar_area: AtomicU64::new(u64::MAX),
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
            last_opened_url: None,
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
            contacts: None,
            settings_popup: None,
            channel_lock: None,
            export_popup: None,
            channel_command_confirm: None,
            channel_command_confirm_focus: Confirm::Yes,
            file_row_of_stream: HashMap::new(),
            file_rows: HashMap::new(),
            file_offers: HashMap::new(),
            file_offer_queue: VecDeque::new(),
            file_offer_focus: Confirm::Yes,
            pending_file_offers: HashMap::new(),
            call_invites: HashMap::new(),
            call_invite_queue: VecDeque::new(),
            call_invite_focus: Confirm::Yes,
            pending_call_invites: HashMap::new(),
            call: None,
            call_confirm: None,
            call_confirm_focus: Confirm::Yes,
            otp_generate_confirm: None,
            otp_generate_focus: Confirm::Yes,
            otp_size_input: None,
            otp_size_text: String::new(),
            otp_size_error: None,
            otp_keygen: None,
            otp_invites: HashMap::new(),
            otp_invite_queue: VecDeque::new(),
            otp_invite_focus: Confirm::Yes,
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
            account_deactivated: None,
            help_scroll: 0,
            file_preview: None,
            identity_reviews: HashMap::new(),
            identity_review_queue: VecDeque::new(),
            identity_review_focus: Confirm::No,
            unknown_peer_reviews: HashMap::new(),
            unknown_peer_review_queue: VecDeque::new(),
            unknown_peer_review_focus: Confirm::No,
            pending_messages: HashMap::new(),
            next_msg_id: 0,
            message_info: None,
            user_info: None,
            users_admin: None,
            cpu_usage_pct: 0.0,
            conn_quality: crate::client::netstats::ConnQuality::Unknown,
            direct_punch_status: None,
            unread_otp_mail_count: 0,
            server_link: crate::client::reconnect::ServerLinkState::Connected,
        }
    }

    /// Called by `session::run_connected_session` as the reconnect
    /// supervisor reports, and once at session start for `--no-server`.
    pub fn set_server_link(&mut self, state: crate::client::reconnect::ServerLinkState) {
        self.server_link = state;
    }

    /// How reachable `peer` is right now - the one answer every place
    /// that names a person renders from (the channel sidebar, the top
    /// row's DM selector), so none of them can disagree about who can be
    /// reached. See `crate::client::presence`.
    pub fn presence_of(&self, peer: UserId) -> crate::client::presence::Presence {
        crate::client::presence::Presence::of(
            self.is_trust_gated(peer),
            self.offline.contains(&peer),
            self.link_status_of(peer),
        )
    }

    /// The header's first element, exactly as rendered.
    ///
    /// Whether a direct link is being punched right now is read off
    /// `link_status` rather than tracked separately - `LinkStatus::
    /// Connecting` *is* "being established (or re-established)", which is
    /// what a punch in flight is.
    pub fn server_link_label(&self) -> String {
        let punching = self
            .link_status
            .values()
            .any(|s| *s == crate::client::p2p::LinkStatus::Connecting);
        self.server_link.label(punching)
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

    /// Called once a second by `session::run_connected_session` with the
    /// freshly-computed `PeerLinkManager::direct_punch_summary`.
    pub fn set_direct_punch_status(
        &mut self,
        status: Option<(usize, usize, Option<std::time::Duration>)>,
    ) {
        self.direct_punch_status = status;
    }


    // -------------------------------------------------------------
    // Identity review (docs/PROTOCOL.md §12): manual Accept/Reject
    // -------------------------------------------------------------










    /// Where the session is pointed *right now* - the open private room if
    /// there is one, otherwise the selected channel tab.
    ///
    /// Deliberately the live answer rather than whatever `--initial-focus` asked
    /// for at startup (`daemon::DaemonFocus`). The two agree until someone
    /// attaches and moves, and after that this one is the truth: it is
    /// what `current_voice_target` addresses, so it is also what the
    /// daemon's join sound has to follow, or the sound would be announcing
    /// arrivals somewhere the next held shortcut is not going to reach.
    pub fn current_focus(&self) -> CurrentFocus {
        if let Some(peer) = self.active_private_room {
            return CurrentFocus::Dm(peer);
        }
        match self.channels.get(self.selected_channel) {
            Some(channel) if channel.joined => CurrentFocus::Channel(channel.name.clone()),
            // Not joined yet, or no tabs at all: there is nowhere a held
            // shortcut would go, so there is nothing to announce either.
            _ => CurrentFocus::Nowhere,
        }
    }


    /// How many records a `resume_from_log` chunk should pull in at a
    /// time - the message log's last-rendered height (`Cell`, set every
    /// frame by `render_messages`), floored at a small minimum so a
    /// not-yet-rendered or pathologically short terminal still loads
    /// something meaningful rather than nothing.
    pub fn history_chunk_size(&self) -> usize {
        self.last_messages_area_height.load(Ordering::Relaxed).max(5) as usize
    }

    /// `resume_from_log`'s one entry point for pulling more history in -
    /// used both to seed a surface with its first chunk the moment it's
    /// opened (`select_channel_at`/`select_dm`, only while its
    /// `history_cursor` is still `None`) and to pull another chunk once
    /// scrolling reaches the top of what's already loaded
    /// (`handle_messages_key`'s `Up`/`PageUp`/`Home`, every time). Prepends
    /// straight onto the front of the surface's live `log` and returns how
    /// many entries were added - `0` if the feature is off, there's
    /// nothing left on disk, or there's no surface to load into at all
    /// (`CurrentFocus::Nowhere`).
    pub fn load_history_chunk(&mut self) -> usize {
        if !self.resume_from_log {
            return 0;
        }
        let server_label = self.server_label.clone();
        let chunk_size = self.history_chunk_size();
        // Only entries this *session* actually wrote to disk (via
        // `autosave_messages`) can already be sitting at the tail of the
        // file - skipping `log.len()` regardless of that would, with
        // autosave off, silently drop that many genuine never-seen records
        // instead of pre-existing live ones that were never mirrored.
        let autosave_messages = self.autosave_messages;
        match self.current_focus() {
            CurrentFocus::Channel(name) => {
                let Some(tab) = self.channels.iter_mut().find(|c| c.name == name) else {
                    return 0;
                };
                let already_loaded = if autosave_messages { tab.log.len() } else { 0 };
                let cursor = tab.history_cursor.get_or_insert_with(|| {
                    crate::client::export::LogHistoryCursor::open(
                        &server_label,
                        crate::client::export::Surface::Channel(&name),
                        already_loaded,
                    )
                });
                if !cursor.has_more() {
                    return 0;
                }
                let entries = cursor.next_chunk(chunk_size);
                let n = entries.len();
                tab.log.splice(0..0, entries);
                n
            }
            CurrentFocus::Dm(peer) => {
                let Some(room) = self.private_rooms.get_mut(&peer) else {
                    return 0;
                };
                let already_loaded = if autosave_messages { room.log.len() } else { 0 };
                let peer_name = room.peer.name.clone();
                let cursor = room.history_cursor.get_or_insert_with(|| {
                    crate::client::export::LogHistoryCursor::open(
                        &server_label,
                        crate::client::export::Surface::Dm(&peer_name),
                        already_loaded,
                    )
                });
                if !cursor.has_more() {
                    return 0;
                }
                let entries = cursor.next_chunk(chunk_size);
                let n = entries.len();
                room.log.splice(0..0, entries);
                n
            }
            CurrentFocus::Nowhere => 0,
        }
    }

    /// Whether audio arriving from `peer` right now must be kept off the
    /// mixer - the single predicate every reason funnels through, so a
    /// caller can never remember one and forget another: `voice_autoplay`
    /// off (everyone), an unresolved identity, or a `/mute-voice`d sender.
    /// Snapshotted once per stream at `*Start` (docs/PROTOCOL.md §11.2),
    /// so a decision made when a stream opens holds for the whole of it.
    pub fn suppress_playback_from(&self, peer: UserId) -> bool {
        !self.voice_autoplay || self.is_trust_gated(peer) || self.is_voice_muted(peer)
    }

    /// Whether an arriving message names this client's own nickname with
    /// an `@` (`docs/SPEC.md` Functionality #33) - what makes
    /// `assets/ping.wav` sound. Only a text body can mention anyone; a
    /// voice or file row never does.
    ///
    /// Asked of *incoming* messages only. This client's own sends never
    /// reach `on_channel_message`/`on_direct_message`, so writing
    /// `@yourself` cannot ping you.
    pub fn message_mentions_me(&self, body: &MessageBody) -> bool {
        match body {
            MessageBody::Text(text) => text_mentions(text, &self.own_name),
            _ => false,
        }
    }


    /// Hands out the next `MessageDelivery::msg_id`. Called once per
    /// outgoing text message, just before the row is logged, so the id can
    /// go on the wire as that send's delivery tag
    /// (`p2p::PeerLinkManager::send_reliable_tagged`).
    pub(crate) fn alloc_msg_id(&mut self) -> u64 {
        let id = self.next_msg_id;
        self.next_msg_id += 1;
        id
    }

    /// Opens a delivery record for a message about to be sent to
    /// `recipients`, returning the id the wire must carry alongside the
    /// record the log row must hold - the two are the same number, which
    /// is what lets a receipt find its row again (`mark_delivered`).
    pub fn start_delivery(&mut self, recipients: &[UserId]) -> (u64, MessageDelivery) {
        let msg_id = self.alloc_msg_id();
        let recipients = recipients
            .iter()
            .map(|id| DeliveryRecipient {
                id: *id,
                name: self.peer_display_name(*id),
                delivered: false,
                queued: false,
                awaits_pad_ack: false,
                consumed: false,
                viewed: false,
            })
            .collect();
        (msg_id, MessageDelivery { msg_id, recipients })
    }

    /// A peer's nickname as it is right now, for snapshotting into a
    /// `DeliveryRecipient`. Falls back to an open room's own record of
    /// them, then to empty - a message is still addressed to someone the
    /// roster has since forgotten.
    fn peer_display_name(&self, id: UserId) -> String {
        self.known_users
            .get(&id)
            .map(|u| u.name.clone())
            .or_else(|| self.private_rooms.get(&id).map(|r| r.peer.name.clone()))
            .unwrap_or_default()
    }

    /// The delivery id of this client's own row for `stream_id` - a voice
    /// message or a file transfer, whose row is created when the stream
    /// starts but whose wire payload may be built much later (an OTP voice
    /// message is only sent once recording stops). Lets that later send
    /// name the row that is already on screen rather than threading the id
    /// through every intermediate structure.
    pub fn own_stream_msg_id(&self, stream_id: u64) -> Option<u64> {
        let logs = self
            .channels
            .iter()
            .map(|c| &c.log)
            .chain(self.private_rooms.values().map(|r| &r.log));
        for log in logs {
            for entry in log.iter() {
                if !entry.outgoing {
                    continue;
                }
                let matches = match &entry.body {
                    MessageBody::VoiceStreaming { stream_id: sid }
                    | MessageBody::File { stream_id: sid, .. } => *sid == stream_id,
                    _ => false,
                };
                if matches {
                    return entry.delivery.as_ref().map(|d| d.msg_id);
                }
            }
        }
        None
    }

    /// Marks the still-streaming incoming row `(from, stream_id)` as
    /// owing its sender a `Consumed` receipt for `msg_id`, because its
    /// audio decoded but was not played - the sender is muted, or is still
    /// under identity review (`docs/PROTOCOL.md` 7.2.1). Replaying that
    /// row later is what pays it (`handle_messages_key`'s Enter).
    ///
    /// Called while the row is still a `VoiceStreaming` placeholder, which
    /// is the only form that carries `stream_id`; a held row (§12) is
    /// covered too, since it becomes visible unchanged when its sender is
    /// accepted. A no-op when the sender asked for no receipt.
    pub fn owe_replay_receipt(&mut self, from: UserId, stream_id: u64, msg_id: Option<u64>) {
        let Some(msg_id) = msg_id else {
            return;
        };
        let is_this_stream = |e: &LogEntry| {
            e.from == from
                && matches!(e.body, MessageBody::VoiceStreaming { stream_id: sid } if sid == stream_id)
        };
        let visible = self
            .channels
            .iter_mut()
            .map(|c| &mut c.log)
            .chain(self.private_rooms.values_mut().map(|r| &mut r.log));
        for log in visible {
            if let Some(entry) = log.iter_mut().find(|e| is_this_stream(e)) {
                entry.owed_receipt = Some(msg_id);
                return;
            }
        }
        for held in self.pending_messages.values_mut() {
            if let Some(h) = held.iter_mut().find(|h| is_this_stream(&h.entry)) {
                h.entry.owed_receipt = Some(msg_id);
                return;
            }
        }
    }

    /// Records how far `peer` has got with the message `msg_id` names
    /// (`docs/PROTOCOL.md` 7.2.1) - the sole thing that turns a row's
    /// indicator from gray towards green, and the sole thing that fills in
    /// the extra state its details popup can show. Searches every channel log and
    /// private room because a `msg_id` is unique across all of them and
    /// the acknowledgement says nothing about which conversation it came
    /// from. Idempotent: a duplicate acknowledgement changes nothing, and
    /// an id from before a reconnect simply matches nothing.
    pub fn mark_delivered(
        &mut self,
        peer: UserId,
        msg_id: u64,
        stage: ReceiptStage,
        proof: DeliveryProof,
    ) {
        let logs = self
            .channels
            .iter_mut()
            .map(|c| &mut c.log)
            .chain(self.private_rooms.values_mut().map(|r| &mut r.log));
        for log in logs {
            for entry in log.iter_mut() {
                let Some(delivery) = entry.delivery.as_mut() else {
                    continue;
                };
                if delivery.msg_id != msg_id {
                    continue;
                }
                for recipient in delivery.recipients.iter_mut() {
                    if recipient.id != peer {
                        continue;
                    }
                    if recipient.awaits_pad_ack && proof == DeliveryProof::Receipt {
                        // A pad-protected leg answers only to the pad's own
                        // proof-carrying ack. A plain receipt may still
                        // record that they played or saved it - but only
                        // once that ack has genuinely landed, so a receipt
                        // can never be what turns this leg green.
                        recipient.consumed |=
                            recipient.delivered && stage == ReceiptStage::Consumed;
                        recipient.viewed |=
                            recipient.delivered && stage == ReceiptStage::Viewed;
                        continue;
                    }
                    // Consuming implies decrypting, and the two receipts
                    // can arrive in either order after a re-punch, so
                    // `Consumed` sets both rather than assuming the first
                    // one landed.
                    recipient.delivered = true;
                    recipient.consumed |= stage == ReceiptStage::Consumed;
                    // Never regresses: once a file is genuinely saved,
                    // `viewed` staying true (or a later `Viewed` re-arriving)
                    // must not put `SAVED_LABEL` back behind `VIEWED_LABEL` -
                    // `recipient_label` already only ever consults `viewed`
                    // when `!consumed`, so simply latching it here is safe.
                    recipient.viewed |= stage == ReceiptStage::Viewed;
                }
                return;
            }
        }
    }

    /// Records that this client's send to `peer` on row `msg_id` is
    /// waiting on disk for them rather than in flight
    /// (`queue_send_messages`, `client::outbox`), so `i` on that row
    /// reads `QUEUED` instead of `UNDELIVERED`.
    ///
    /// `queued` of `false` is the same call in reverse, made when that
    /// queue is flushed to them - a leg genuinely back on the wire must
    /// stop claiming to be waiting. Searches every log for the same
    /// reason `mark_delivered` does: a `msg_id` is unique across all of
    /// them, and nothing about the queue says which conversation it came
    /// from. Idempotent, and an id that matches nothing is a no-op.
    pub fn mark_queued(&mut self, peer: UserId, msg_id: u64, queued: bool) {
        let logs = self
            .channels
            .iter_mut()
            .map(|c| &mut c.log)
            .chain(self.private_rooms.values_mut().map(|r| &mut r.log));
        for log in logs {
            for entry in log.iter_mut() {
                let Some(delivery) = entry.delivery.as_mut() else {
                    continue;
                };
                if delivery.msg_id != msg_id {
                    continue;
                }
                for recipient in delivery.recipients.iter_mut() {
                    if recipient.id == peer {
                        recipient.queued = queued;
                    }
                }
                return;
            }
        }
    }

    /// Marks this client's own send to `peer` on row `msg_id` as one that
    /// went out under the pad - so from here on only a verified
    /// `OtpDeliveryAck` can report it read (`mark_delivered`).
    ///
    /// Called by `client::otp` at the moment the pad-wrapped payload
    /// genuinely reaches the wire, never earlier: a send that failed to
    /// encrypt never left, and must not leave its row waiting on an
    /// acknowledgement that can no longer be coming.
    pub fn mark_awaiting_pad_ack(&mut self, peer: UserId, msg_id: u64) {
        let logs = self
            .channels
            .iter_mut()
            .map(|c| &mut c.log)
            .chain(self.private_rooms.values_mut().map(|r| &mut r.log));
        for log in logs {
            for entry in log.iter_mut() {
                let Some(delivery) = entry.delivery.as_mut() else {
                    continue;
                };
                if delivery.msg_id != msg_id {
                    continue;
                }
                for recipient in delivery.recipients.iter_mut() {
                    if recipient.id == peer {
                        recipient.awaits_pad_ack = true;
                    }
                }
                return;
            }
        }
    }

    /// Buffers a message/stream-placeholder from a trust-gated `from`
    /// instead of it going into the visible log - called by
    /// `on_channel_message`/`on_direct_message` and their stream
    /// counterparts whenever `is_trust_gated(from)`.
    /// `channel`'s tab, read-only.
    pub(crate) fn channel_tab(&self, channel: &str) -> Option<&ChannelTab> {
        self.channels.iter().find(|c| c.name == channel)
    }

    /// `channel`'s tab, if it is one this client has open.
    ///
    /// The `.find(|c| c.name == ..)` this replaces appeared seventeen
    /// times in `tui::channel` alone - `channels` is a `Vec` because the
    /// tab order is the selector's order, so a lookup by name is a scan
    /// and every caller was writing it out.
    pub(crate) fn channel_tab_mut(&mut self, channel: &str) -> Option<&mut ChannelTab> {
        self.channels.iter_mut().find(|c| c.name == channel)
    }

    /// What is known about `peer`, or a placeholder standing in for them.
    ///
    /// A room has to be openable for someone who is not in `known_users`
    /// yet - a peer whose `Identify` has not arrived, or one reached with
    /// no server at all (`docs/PROTOCOL.md` §7.1.5). The placeholder
    /// carries no key, which is exactly what it means: nothing is known
    /// beyond the name they announced.
    pub(crate) fn peer_or_fallback(&self, peer: UserId, name: &str) -> UserInfo {
        self.known_users
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| UserInfo {
                id: peer,
                name: name.to_string(),
                public_key_der: Vec::new(),
                key_mode: KeyMode::PqHybrid,
            })
    }

    /// Appends `entry` to `channel`'s log, following the selection if the
    /// user is looking at it, and autosaving the row if that is on.
    ///
    /// This is the whole of what writing a row into a channel involves,
    /// and it was open-coded at every site: snapshot whether the channel
    /// is on screen, snapshot the autosave label, find the tab, push,
    /// maybe raise unread, maybe autosave. The snapshots have to happen
    /// before the tab is borrowed mutably, which is the detail that made
    /// each copy look unavoidable.
    ///
    /// A channel with no tab open is a no-op, matching the `if let Some`
    /// every call site already guarded with.
    pub(crate) fn append_to_channel(&mut self, channel: &str, entry: LogEntry, unread: Unread) {
        let is_current = self.is_viewing_channel(channel);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        let Some(tab) = self.channels.iter_mut().find(|c| c.name == channel) else {
            return;
        };
        push_log_entry(&mut tab.log, &mut self.message_selected, is_current, entry);
        if unread == Unread::Mark && !is_current {
            tab.unread = true;
        }
        if let Some(server_label) = &autosave {
            crate::client::export::autosave_entry(
                server_label,
                crate::client::export::Surface::Channel(channel),
                tab.log.last().expect("just pushed"),
            );
        }
    }

    /// `append_to_channel`'s DM counterpart, returning where the row
    /// landed - the log is append-only, so that index stays a stable
    /// handle for marking the row failed or correcting its crypto later
    /// (`mark_dm_message_failed`, `set_dm_message_crypto`).
    ///
    /// `surface_name` names the `.log` file the row is autosaved to and is
    /// passed rather than read off the room, because the call sites do not
    /// agree on it: an incoming row files under the name its *sender*
    /// announced, an outgoing one under the room's peer. Making that a
    /// parameter keeps each site's existing choice visible instead of
    /// silently picking one.
    ///
    /// A peer with no room open is a no-op returning `None` - callers that
    /// need one call `ensure_private_room` first.
    pub(crate) fn append_to_dm(
        &mut self,
        peer: UserId,
        surface_name: &str,
        entry: LogEntry,
        unread: Unread,
    ) -> Option<usize> {
        let is_current = self.is_viewing_dm(peer);
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
        let room = self.private_rooms.get_mut(&peer)?;
        let index = room.log.len();
        push_log_entry(&mut room.log, &mut self.message_selected, is_current, entry);
        if unread == Unread::Mark && !is_current {
            room.unread = true;
        }
        if let Some(server_label) = &autosave {
            crate::client::export::autosave_entry(
                server_label,
                crate::client::export::Surface::Dm(surface_name),
                room.log.last().expect("just pushed"),
            );
        }
        Some(index)
    }

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
                    Some(name) => self.append_to_channel(&name, entry, Unread::Mark),
                    None => {
                        // The room may not exist yet - a held DM never creates
                        // one (mirrors `on_direct_message`'s trust-gated path).
                        let fallback_peer = self.peer_or_fallback(peer, &entry.from_name);
                        self.ensure_private_room(peer, fallback_peer);
                        let Some(peer_name) =
                            self.private_rooms.get(&peer).map(|r| r.peer.name.clone())
                        else {
                            continue;
                        };
                        self.append_to_dm(peer, &peer_name, entry, Unread::Mark);
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
            self.file_offer_focus = Confirm::Yes;
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
        self.file_offer_focus = Confirm::Yes;
        self.file_offers.remove(&key)
    }

    // -------------------------------------------------------------
    // Live voice calls (`docs/PROTOCOL.md` "Live voice calls"): the invite
    // Accept/Reject popup is the same modal-queue idiom as file transfer's
    // above; `call` (below) is the separate, always-visible "on a call
    // right now" indicator, unrelated to the popup queue.
    // -------------------------------------------------------------

    /// Our own nickname, as the roster should print it: the name the
    /// server accepted, from `known_users` when it has our own entry and
    /// otherwise the one we connected under (`own_name`) - a call can
    /// start before we have ever appeared in a channel roster.
    pub(crate) fn own_display_name(&self) -> String {
        self.own_id
            .and_then(|id| self.known_users.get(&id))
            .map(|u| u.name.clone())
            .unwrap_or_else(|| self.own_name.clone())
    }

























    /// The id this session last knew `user` by, if they are someone who
    /// went offline and has now come back.
    ///
    /// Matched on the *nickname*, because that is the only thing about a
    /// person that survives a reconnect at all: a `UserId` is handed out
    /// per connection and never reused (`docs/PROTOCOL.md` §3), so a
    /// returning peer arrives as a complete stranger by id. The nickname
    /// is already this app's continuity anchor everywhere it matters -
    /// `id_store` pins by it (§12), `/mute-voice` remembers by it - and
    /// pinning is what makes trusting it safe here: someone taking a
    /// departed user's nickname is caught by the identity check that runs
    /// on this very `UserJoined`, which gates messaging until it is
    /// answered. Adopting the row is a *display* decision; whether that
    /// person may be talked to is decided separately, and independently.
    ///
    /// A pure lookup: the caller decides what to do with the answer, and
    /// `adopt_returning_peer` is what acts on it.
    pub(crate) fn returning_peer_id(&self, user: &UserInfo) -> Option<UserId> {
        self.known_users
            .values()
            .find(|known| {
                known.id != user.id && known.name == user.name && self.offline.contains(&known.id)
            })
            .map(|known| known.id)
    }


    /// A pad session has just been agreed with `peer` - what both sides
    /// call the moment their handshake completes
    /// (`client::otp::on_session_request`'s accept, `on_key_setup_ack`).
    ///
    /// Marks it active and opens that room, because a session is something
    /// two people just deliberately agreed to and the conversation it was
    /// for is the next thing either of them wants to be looking at.
    ///
    /// Deliberately not folded into `mark_otp_active`: that is also how a
    /// still-live session is resumed when its peer reconnects
    /// (`session::handle_server_message`'s `UserJoined` arm), which nobody
    /// asked for at that moment - taking the view off whatever they were
    /// reading would be wrong there.
    pub fn open_otp_session(&mut self, peer: UserId) {
        self.mark_otp_active(peer);
        if let Some(info) = self.known_users.get(&peer).cloned() {
            self.open_private_room(info);
        }
    }

    /// The encryption tag `peer` carries right now: `OTP_TAG` while a pad
    /// session is open with them, otherwise the tag for the `my_key` they
    /// connected with (`docs/SPEC.md` "Connected UI").
    ///
    /// The pad replaces the tag rather than being added beside it. It is
    /// the layer that actually protects what is being said to that person
    /// (`docs/PROTOCOL.md` §16.2 - there is no way to send them a plain
    /// message while one is active). The tag it displaces is always the
    /// same one, `pq_hybrid`'s, since that is the only `my_key` there is -
    /// whether or not the pad actually has an envelope under it.
    pub fn encryption_tag(&self, peer: UserId, key_mode: KeyMode) -> &'static str {
        if self.is_otp_active(peer) {
            OTP_TAG
        } else {
            key_mode.label()
        }
    }



    /// How a message logged for `peer` right now is protected, as the
    /// details popup reports it (`render_message_info_popup`).
    ///
    /// Both figures an OTP row carries are read from the snapshot *before*
    /// this message spends its own key, which is what makes them describe
    /// this message rather than the state after it: `otp --show-contact`
    /// reports the sequence already written and the offset already
    /// consumed, so the message about to be (or just being) logged is the
    /// next sequence, starting at exactly that offset. Every OTP path
    /// takes its pre-spend snapshot before the row is pushed and refreshes
    /// again afterwards (`client::otp::send_now`, `client::otp::on_message`),
    /// so this holds for both directions.
    pub fn message_crypto(&self, peer: UserId, outgoing: bool) -> Option<MessageCrypto> {
        // A snapshot always exists for an active session - every
        // `mark_otp_active` is followed immediately by a refresh - except
        // where `otp --show-contact` itself would not answer. There is
        // then nothing true to say about the pad, so the row falls through
        // to the envelope underneath it, which is at least a fact.
        let otp_status = self
            .otp_key_status_for(peer)
            .filter(|_| self.is_otp_active(peer));
        if let Some(status) = otp_status {
            let (sequence, offset, key_path) = if outgoing {
                (
                    status.detail.enc_sequence,
                    status.detail.enc_offset,
                    &status.enc_key_path,
                )
            } else {
                (
                    status.detail.dec_sequence,
                    status.detail.dec_offset,
                    &status.dec_key_path,
                )
            };
            return Some(MessageCrypto::Otp {
                seq: sequence + 1,
                offset,
                key_path: key_path.display().to_string(),
                // `otp::framing_for` reads both sides' keys; this client's
                // own is always a real keybundle, so from here the answer
                // turns entirely on whether the peer announced one.
                inside_envelope: self
                    .known_users
                    .get(&peer)
                    .is_some_and(|u| {
                        crate::crypto::pq::fingerprint_of_encoded(&u.public_key_der).is_some()
                    }),
            });
        }
        let user = self.known_users.get(&peer)?;
        Some(MessageCrypto::Envelope {
            key_id: Some(crate::crypto::short_fingerprint_der(&user.public_key_der)),
        })
    }

    /// `message_crypto` for a message this client is about to send to
    /// `channel`: it is sealed once for every member of that channel
    /// except ourselves, which is exactly the tab's own roster.
    pub fn channel_send_crypto(&self, channel: &str) -> Option<MessageCrypto> {
        let recipients: Vec<UserId> = self
            .channel_tab(channel)
            .map(|c| {
                c.members
                    .iter()
                    .map(|m| m.id)
                    .filter(|id| Some(*id) != self.own_id)
                    .collect()
            })
            .unwrap_or_default();
        self.channel_message_crypto(&recipients)
    }

    /// `message_crypto` for the one member of a channel a per-recipient row
    /// is addressed to - a channel file send makes one row per recipient
    /// (`channel::log_own_file_offer_channel`), and a name is all that row
    /// carries. `None` for a name nobody currently connected holds.
    pub fn message_crypto_for_name(&self, name: &str, outgoing: bool) -> Option<MessageCrypto> {
        let id = self
            .known_users
            .values()
            .find(|u| u.name == name)
            .map(|u| u.id)?;
        self.message_crypto(id, outgoing)
    }

    /// `message_crypto` for a message going out to a whole channel, which
    /// is sealed once per member with *that member's* own key
    /// (`client::envelope::encrypt_envelope_for`).
    ///
    /// One key id is only meaningful where there is one key, so a send to
    /// several members names the scheme without one; a channel whose
    /// members do not even share a scheme names nothing at all, and the
    /// popup's per-recipient list is what carries the detail there.
    pub fn channel_message_crypto(&self, recipients: &[UserId]) -> Option<MessageCrypto> {
        match recipients {
            [] => None,
            [one] => self.message_crypto(*one, true),
            many => many
                .iter()
                .all(|id| self.known_users.contains_key(id))
                .then_some(MessageCrypto::Envelope { key_id: None }),
        }
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

    /// Records that the transfer `stream_id` is one of those behind the
    /// file row `row` - called once per recipient of a channel file send,
    /// including for the transfer whose own id names the row
    /// (`channel::handle_send_file`).
    pub fn register_file_row_stream(&mut self, row: u64, stream_id: u64) {
        self.file_row_of_stream.insert(stream_id, row);
        self.file_rows
            .entry(row)
            .or_default()
            .sent
            .entry(stream_id)
            .or_insert(0);
    }

    /// The row a transfer belongs to - itself, for every transfer that is
    /// its own row (a DM send, and anything incoming).
    fn file_row_of(&self, stream_id: u64) -> u64 {
        self.file_row_of_stream
            .get(&stream_id)
            .copied()
            .unwrap_or(stream_id)
    }

    /// Applies `record` to the row's aggregate and writes back whatever
    /// status that leaves it in. A transfer with no aggregate is its own
    /// row, and `fallback` is the status it takes directly.
    fn update_file_row(
        &mut self,
        from: UserId,
        stream_id: u64,
        fallback: FileTransferStatus,
        record: impl FnOnce(&mut FileRowProgress),
    ) {
        let row = self.file_row_of(stream_id);
        let status = match self.file_rows.get_mut(&row) {
            Some(progress) => {
                record(progress);
                progress.status()
            }
            None => fallback,
        };
        self.update_file_entry(from, row, |body| {
            if let MessageBody::File { status: slot, .. } = body {
                *slot = status;
            }
        });
    }

    pub fn set_file_progress(&mut self, from: UserId, stream_id: u64, bytes: u64) {
        self.update_file_row(
            from,
            stream_id,
            FileTransferStatus::InProgress { bytes },
            |progress| {
                progress.sent.insert(stream_id, bytes);
            },
        );
    }

    pub fn set_file_completed(&mut self, from: UserId, stream_id: u64) {
        self.update_file_row(from, stream_id, FileTransferStatus::Completed, |progress| {
            progress.done.insert(stream_id);
        });
    }

    pub fn set_file_rejected(&mut self, from: UserId, stream_id: u64) {
        self.update_file_row(from, stream_id, FileTransferStatus::Rejected, |progress| {
            progress.rejected.insert(stream_id);
        });
    }

    pub fn set_file_failed(&mut self, from: UserId, stream_id: u64) {
        self.update_file_row(from, stream_id, FileTransferStatus::Failed, |progress| {
            progress.failed.insert(stream_id);
        });
    }

    /// A staged `.txt` receive has fully arrived (`FileEvent::ReceiveDone`,
    /// staged rather than saved) - bypasses `update_file_row`'s
    /// `FileRowProgress` aggregation deliberately: that machinery exists
    /// for an *outgoing* channel send's multiple recipients, and an
    /// incoming receive is always its own row.
    pub fn set_file_received_staged(
        &mut self,
        from: UserId,
        stream_id: u64,
        staged_path: std::path::PathBuf,
    ) {
        self.update_file_entry(from, stream_id, |body| {
            if let MessageBody::File { status, .. } = body {
                *status = FileTransferStatus::Received { staged_path };
            }
        });
    }

    /// The staged path and offered filename of the `.txt` receive
    /// `(from, stream_id)`, if its row is currently
    /// `FileTransferStatus::Received` - what `session::handle_ui_action`'s
    /// `RequestFilePreview`/`SaveStagedFile` arms read from disk (`UiState`
    /// does none of its own I/O).
    pub fn staged_file(
        &self,
        from: UserId,
        stream_id: u64,
    ) -> Option<(std::path::PathBuf, String)> {
        let matches = |e: &&LogEntry| {
            e.from == from
                && matches!(&e.body, MessageBody::File { stream_id: sid, .. } if *sid == stream_id)
        };
        let entry = self
            .channels
            .iter()
            .find_map(|tab| tab.log.iter().find(matches))
            .or_else(|| {
                self.private_rooms
                    .values()
                    .find_map(|room| room.log.iter().find(matches))
            })?;
        match &entry.body {
            MessageBody::File {
                filename,
                status: FileTransferStatus::Received { staged_path },
                ..
            } => Some((staged_path.clone(), filename.clone())),
            _ => None,
        }
    }

    /// Opens the preview popup with content `session::handle_ui_action`
    /// has already read (and, if oversized, capped) from disk.
    pub fn open_file_preview(
        &mut self,
        from: UserId,
        stream_id: u64,
        filename: String,
        content: String,
        truncated: bool,
    ) {
        self.file_preview = Some(FilePreviewState {
            from,
            stream_id,
            filename,
            content,
            truncated,
            scroll: 0,
        });
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

    /// Drops everything the connection that just ended said about other
    /// people (`docs/PROTOCOL.md` §4.2): channel memberships, who they
    /// were, and who among them had gone offline.
    ///
    /// Wholesale rather than per-peer, and *not* by marking anyone offline:
    /// every `UserId` here belonged to that connection, the server behind
    /// the next one may not even be the same process, and this client
    /// simply does not know who is present any more. Whoever is still there
    /// arrives again in the membership snapshot the re-joins bring back
    /// (§6.1). Peers named by their own identity rather than by anything a
    /// server handed out - direct-punch peers (§7.1.5) - are untouched:
    /// no server coming or going has any bearing on them.
    ///
    /// Private rooms are left alone. Their logs are the conversation, and
    /// a room whose peer does not come back stays readable exactly as one
    /// whose peer went offline does.
    pub fn forget_server_presence(&mut self) {
        for tab in &mut self.channels {
            tab.members
                .retain(|m| crate::client::p2p::is_direct_peer_id(m.id));
        }
        self.known_users
            .retain(|id, _| crate::client::p2p::is_direct_peer_id(*id));
        self.offline
            .retain(|id| crate::client::p2p::is_direct_peer_id(*id));
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


    // -------------------------------------------------------------
    // Key handling
    // -------------------------------------------------------------


    pub fn current_voice_target(&self) -> Option<VoiceTarget> {
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
            // Being offline only stops a recording when there is nowhere
            // to put it. With `queue_send_messages` on there is: a
            // pq_hybrid stream's chunks are sealed and held like any other
            // content, and a pad-wrapped recording is sealed when it is
            // recorded and held in the pad queue (`docs/SPEC.md`
            // Functionality #34). Refusing Space in that case was the old
            // rule outliving the reason for it - the user records
            // something for a person who is away, which is precisely what
            // the queue exists for, and nothing happened.
            //
            // A Pending/Rejected identity still refuses outright
            // (docs/PROTOCOL.md §12): no queue makes it acceptable to
            // encrypt to a key we have not verified.
            if self.is_trust_gated(peer_id) {
                return None;
            }
            if self.offline.contains(&peer_id) && !self.queue_send_messages {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?;
            Some(VoiceTarget::Direct {
                to: peer_id,
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




    /// `current_log`'s mutable twin, for the one thing that writes back
    /// into the row under the cursor: paying off an incoming voice
    /// message's `owed_receipt` when it is replayed.
    pub(crate) fn current_log_mut(&mut self) -> Option<&mut Vec<LogEntry>> {
        match self.active_private_room {
            Some(peer) => self.private_rooms.get_mut(&peer).map(|r| &mut r.log),
            None => self
                .channels
                .get_mut(self.selected_channel)
                .map(|c| &mut c.log),
        }
    }

    pub(crate) fn current_log(&self) -> &[LogEntry] {
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

    /// The next not-yet-opened http(s) URL in the focused message
    /// (`message_selected`), for Ctrl+O. A message with more than one link
    /// cycles through them on repeated presses; moving the cursor to a
    /// different message starts back at its first link, since
    /// `last_opened_url`'s row no longer matches.
    pub(crate) fn next_url_in_focused_message(&mut self) -> Option<String> {
        let selected = self.message_selected;
        let url = {
            let MessageBody::Text(text) = &self.current_log().get(selected)?.body else {
                return None;
            };
            let urls = find_urls(text);
            if urls.is_empty() {
                return None;
            }
            let next = match self.last_opened_url {
                Some((row, url_idx)) if row == selected => (url_idx + 1) % urls.len(),
                _ => 0,
            };
            (next, text[urls[next].clone()].to_string())
        };
        self.last_opened_url = Some((selected, url.0));
        Some(url.1)
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
                let entry = LogEntry::presence(user_id, name.clone(), text.clone());
                self.append_to_channel(&channel, entry, Unread::Leave);
            }
            if self.private_rooms.contains_key(&user_id) {
                let entry = LogEntry::presence(user_id, name.clone(), text);
                self.append_to_dm(user_id, &name, entry, Unread::Leave);
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

/// This machine's local wall-clock date and time, for a log row's
/// `sent_at` - the full stamp rather than `local_time_short`'s time alone,
/// since the message info popup is read long after the fact, when which
/// day it was is exactly what is being asked. Same UTC fallback, and the
/// same reason for it, as `local_time_short`.
pub(crate) fn local_time_stamp() -> String {
    match time::OffsetDateTime::now_local() {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            dt.year(),
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => {
            let dt = time::OffsetDateTime::now_utc();
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                dt.year(),
                u8::from(dt.month()),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second()
            )
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
/// for a finished `Voice` entry. Returns the finalized entry when a
/// matching placeholder was found - callers that also maintain a
/// held-message buffer (`finalize_held_stream`) use a `None` return to
/// fall through to it when the placeholder isn't in the visible log; a
/// `Some` return is also `client::export::autosave_entry`'s hook for a
/// freshly-completed voice message (it has no audio to write before this
/// point - see that function's doc).
pub(crate) fn finalize_stream_entry(
    log: &mut [LogEntry],
    from: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) -> Option<&LogEntry> {
    let entry = log.iter_mut().find(|e| {
        e.from == from
            && matches!(e.body, MessageBody::VoiceStreaming { stream_id: sid } if sid == stream_id)
    })?;
    entry.body = MessageBody::Voice { duration_ms, pcm };
    Some(&*entry)
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
