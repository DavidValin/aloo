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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};

use crate::client::p2p::LinkStatus;
use crate::p2p_proto::ReceiptStage;
use crate::proto::{ChannelInfo, ChannelKind, Envelope, KeyMode, UserId, UserInfo};

use super::widgets::confirm_popup::{Confirm, ConfirmLabels, ConfirmPopup};

/// Re-exported so the popup modules that already reach for it through
/// `super::ui` keep doing so - it lives in
/// `super::widgets::confirm_popup` now, beside the confirmation row it is
/// the building block of.
pub(crate) use super::widgets::confirm_popup::render_popup_button;

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

/// One line of the help overlay's source text, before it is laid out.
///
/// Written unwrapped: an `Item`'s `text` is one sentence-flow string, and
/// where it breaks is decided at render time against the terminal actually
/// in front of the user (`help_rendered_lines`), not by hand here. That is
/// what keeps every description inside one column - a hand-wrapped line
/// can only be right for one width.
pub enum HelpLine {
    /// A section title, on a line of its own and flush left.
    Heading(&'static str),
    Blank,
    /// A key, a key combination or a slash command, and what it does.
    /// `keys` fills the first column, `text` wraps inside the second.
    Item {
        keys: &'static str,
        text: &'static str,
    },
    /// Prose belonging to the section rather than to any one key. Sits in
    /// the description column with the first one empty, so a section reads
    /// as one block down the page.
    Note(&'static str),
}

const HELP_BODY: &[HelpLine] = &[
    HelpLine::Heading("Channels"),
    HelpLine::Item {
        keys: "[  /  ]",
        text: "move between the channel selector (left) and the DM one (right); at either \
               end it opens that selector's dropdown instead - every other channel you \
               joined (private ones prefixed \u{1F512}), or room you have open. Up/Down pick one \
               (the view follows straight away), Enter, Esc, Tab or the opposite key close \
               it again, and so does leaving it alone for 30 seconds",
    },
    HelpLine::Item {
        keys: "/channels",
        text: "list every public channel (yours in yellow); Enter joins, Esc closes",
    },
    HelpLine::Item {
        keys: "Ctrl+J",
        text: "join/create a channel: name, Public/Private (Left/Right), optional password.                Channels are shown as #name - typing the # is fine, it is ignored.",
    },
    HelpLine::Item {
        keys: "/leave",
        text: "leave the selected channel tab (its tab disappears)",
    },
    HelpLine::Blank,
    HelpLine::Heading("Channel administration"),
    HelpLine::Note(
        "A channel always belongs to whoever created it (shown as \u{2600}\u{FE0F} in the sidebar \
         and \"(admin: name)\" in the messages pane) - except the-hall, which belongs to \
         nobody. Only that channel's own admin may use the commands below in it; \
         everyone else is refused with a reason.",
    ),
    HelpLine::Item {
        keys: "/delete-channel",
        text: "delete the selected public channel (with a confirmation popup) - anyone may \
               recreate it later by joining the name again",
    },
    HelpLine::Item {
        keys: "/ban <nickname>",
        text: "remove them from the selected channel and refuse their future joins to it",
    },
    HelpLine::Item {
        keys: "/unban <nickname>",
        text: "reverse a ban - they may join again",
    },
    HelpLine::Item {
        keys: "/lock-joins",
        text: "open a popup choosing who may join the selected channel from now on: \"All \
               users\" (Left/Right/u to toggle) or a specific list, prefilled with the \
               current members - a/n adds a nickname, d deletes one, Enter applies \
               immediately. Already-joined members are never removed by this.",
    },
    HelpLine::Item {
        keys: "/assign-admin <nickname>",
        text: "hand your admin rights for the selected channel to a current member (with a \
               confirmation popup) - you are no longer its admin afterward",
    },
    HelpLine::Blank,
    HelpLine::Heading("Messaging"),
    HelpLine::Item {
        keys: "Tab",
        text: "cycle focus: sidebar -> messages -> compose bar",
    },
    HelpLine::Item {
        keys: "Enter",
        text: "send the typed message (compose bar focused)",
    },
    HelpLine::Item {
        keys: "Up / Down",
        text: "scroll the message log one message, from the compose bar too",
    },
    HelpLine::Item {
        keys: "PgUp/PgDn",
        text: "scroll it ten at a time; Home/End jump to the oldest/newest (log focused). \
               A log taller than its pane shows a scrollbar down its right edge.",
    },
    HelpLine::Item {
        keys: "i",
        text: "message details: when it was sent, how it was encrypted (the scheme, and a \
               short id of the key it was sealed to - or, under /otp, that message's own \
               pad sequence, offset and key file), and every user it went to with their \
               own DELIVERED / UNDELIVERED state (log focused). i or Esc closes it again.",
    },
    HelpLine::Item {
        keys: "->",
        text: "each message you send reads `you -> message`, the arrow coloured by how far \
               it has got: gray until anyone has decrypted it, green once everyone has, \
               and in a channel orange while only some have. Voice messages and file \
               transfers carry it too - a file turns green once the whole of it has \
               arrived decrypted on their side. A message that reached nobody is struck \
               through. Messages from other people keep a plain `name: message`.",
    },
    HelpLine::Blank,
    HelpLine::Heading("Private messages"),
    HelpLine::Item {
        keys: "Up / Down",
        text: "pick a user (sidebar focused)",
    },
    HelpLine::Item {
        keys: "Enter",
        text: "open a private room with the selected user",
    },
    HelpLine::Item {
        keys: "i",
        text: "user info (sidebar focused; /info does the same from inside an open DM room): \
               nickname, the device this connection announced, when they were last seen, \
               and every PQH/OTP/OTP MAIL key pinned for that device - shown read-only, \
               never editable here (/contacts is where keys are managed). Names an active \
               /otp session too, if one is on right now. i or Esc closes it again.",
    },
    HelpLine::Item {
        keys: "/info",
        text: "inside an open DM room: the same user-info popup as 'i' on a sidebar \
               member, for whoever the room is with.",
    },
    HelpLine::Item {
        keys: "Esc",
        text: "back to the channel selector (the room stays on the DM selector)",
    },
    HelpLine::Item {
        keys: "\u{2709}",
        text: "blinks on a selector while a channel/DM behind it has unseen messages, and \
               on the dropdown row they landed in. Beside a person it takes their own \
               colour, so it reads as part of the name rather than as a separate mark; a \
               channel's is plain white, having no reachability to report.",
    },
    HelpLine::Blank,
    HelpLine::Heading("Voice messages"),
    HelpLine::Item {
        keys: "Space",
        text: "hold to record & send live (not while composing); release to stop",
    },
    HelpLine::Item {
        keys: "Ctrl+Alt+P",
        text: "same, from anywhere - edit/disable in ~/.aloo/settings",
    },
    HelpLine::Item {
        keys: "Enter",
        text: "replay a voice message (messages focused)",
    },
    HelpLine::Item {
        keys: "Esc",
        text: "stop a replay while it is playing",
    },
    HelpLine::Note(
        "Capped at 4 minutes - recording stops itself on reaching it, and a received \
         stream longer than that is never accepted past 4 minutes.",
    ),
    HelpLine::Item {
        keys: "/mute-voice <nickname>",
        text: "stop their voice messages playing themselves on arrival - they still arrive \
               and still show in the log, so Enter replays them; muted users are marked \
               \u{1F507} in the sidebar. Kept in ~/.aloo/settings. Never affects a call.",
    },
    HelpLine::Item {
        keys: "/unmute-voice <nickname>",
        text: "undo it; either, with no nickname, lists who is currently muted.",
    },
    HelpLine::Blank,
    HelpLine::Heading("File transfer"),
    HelpLine::Item {
        keys: "/file",
        text: "type this and press Enter to browse for a file to send. In a channel it goes \
               to everyone at once and reads as one line in your log; press i on it to see \
               each person's own progress.",
    },
    HelpLine::Item {
        keys: "Left/Right/Tab",
        text: "choose Send file / Discard on the confirmation box (Discard by default)",
    },
    HelpLine::Note(
        "The recipient sees a popup (with a chime) naming you and the file, Accept \
         focused by default; Left/Right/Tab/Enter same as above.",
    ),
    HelpLine::Note(
        "Accepting streams the file straight to ~/.aloo/downloads with a live progress \
         bar - nothing is held whole in memory on either side, and there is no size cap. \
         Declining shows as rejected in your log.",
    ),
    HelpLine::Blank,
    HelpLine::Heading("Live voice calls"),
    HelpLine::Item {
        keys: "/call",
        text: "start a continuous, multi-user call in the selected channel or open private \
               room - distinct from a voice message: not push-to-talk, no time cap, and \
               every current member/the peer gets an Accept/Reject popup (with a chime) \
               naming you. You confirm first, told how many people it will ring.",
    },
    HelpLine::Item {
        keys: "/endcall",
        text: "leave the call - a permanent red banner (top right) marks the whole time \
               you're on one",
    },
    HelpLine::Note(
        "The call modal opens with the call: live duration on top, then everyone on it - \
         host first, each labelled IN CALL / INVITED / REJECTED (+ MUTED), with a live \
         voice bar. Up/Down walk the list, Enter or e is END CALL (which asks before it \
         leaves), Esc folds it away into the \u{23FA} Call indicator at the top right \
         (Ctrl+R brings the modal back).",
    ),
    HelpLine::Note(
        "m on your own row mutes your microphone (yours to lift, nobody else is told). As \
         the host, m on anyone else's row mutes them instead - only you can lift that - \
         and i invites one more person you share a channel or DM with.",
    ),
    HelpLine::Note(
        "Leaving as the host ends the call for everyone. One call at a time. Not \
         available over an OTP session (that layer has no live-streaming concept at all - \
         see the OTP section below).",
    ),
    HelpLine::Blank,
    HelpLine::Heading("Encryption (tag shown after each username)"),
    HelpLine::Item {
        keys: "name \u{1F6E1}\u{FE0F} PQH",
        text: "the only scheme there is: ML-DSA-87+RSA4096/ML-KEM-1024+RSA4096/AES-256-GCM, loaded from a file",
    },
    HelpLine::Item {
        keys: "name \u{1F511} OTP",
        text: "a one-time-pad session is open with this person (/otp below), so that pad -                not the tag above - is what protects everything said to them. Shown in                place of their own tag in the user list, on the DM selector and on their                dropdown row.",
    },
    HelpLine::Note(
        "Everyone carries the shield: it is the only scheme, and the keys that encrypt to a \
         person rotate as you talk, so a stolen key file does not open what was already \
         said. The tags sit flush against the user list's right edge, so they read as a \
         column of their own rather than starting wherever each nickname happens to end. A name is \
         green while what you type reaches that person and gray until it does; red means \
         their identity is unresolved, which is the one thing here to act on.",
    ),
    HelpLine::Blank,
    HelpLine::Heading("One-time-pad layer (optional, per contact)"),
    HelpLine::Item {
        keys: "/otp",
        text: "inside an open DM room: proposes an extra one-time-pad layer on top of \
               pq_hybrid for that contact only. Never starts on its own say-so - always \
               ends in an explicit Accept/Reject on the other side, confirmed back to you. \
               Refused outright if a session with them is already active - /endotp first.",
    },
    HelpLine::Item {
        keys: "/endotp",
        text: "ends (pauses) an active session with that contact, in sync on both sides: \
               it needs them online, and takes effect only once they confirm receiving \
               the end notice - until then the session stays on and new sends to them are \
               refused (/otp cancels a pending end). No accept/reject - the peer is told, \
               not asked. The pad itself is kept, not destroyed - a later /otp with the \
               same contact resumes the exact same key rather than generating a new one. \
               A disconnect alone never ends a session - only /endotp does - and the DM \
               keeps working either way, just without that extra layer once it's off.",
    },
    HelpLine::Note(
        "If no key exists yet, you're asked to confirm generating one and sharing it \
         automatically over pq_hybrid (or you can run 'otp' yourself and place the keys \
         under ~/.aloo/otp/.keychain/ instead). Confirming asks for a size next, \
         1-1048576 MB per key (1TB, the real 'otp' command's own streaming limit) - a \
         spinner shows the generation's progress, since a large pad takes a while. An \
         incoming proposal shows an Accept/Reject popup naming the sender and, for a \
         fresh key, the size offered.",
    ),
    HelpLine::Note(
        "Requires both sides to use pq_hybrid, and the real 'otp' command \
         (github.com/DavidValin/otp-toolkit) installed. Once started, a message to that \
         contact waits for the previous one to be genuinely acknowledged before the next \
         can send. \"OTP session started at <time>\" (green) or \"OTP session cancelled\" \
         (red) is shown to both sides.",
    ),
    HelpLine::Note(
        "Text, file and voice content sent to that contact are all protected under the \
         pad while active - a file's name/size still travel unwrapped (only its bytes \
         are, once accepted); voice is recorded fully and sent once instead of live, \
         arriving playable once it fully lands.",
    ),
    HelpLine::Note(
        "While active, a 1-line header above the messages shows both directions' \
         Seq/Offset/remaining-MB live, updated about once a second - remaining turns red \
         below 0.5MB per direction.",
    ),
    HelpLine::Blank,
    HelpLine::Heading("OTP mail (async, stored encrypted on the server)"),
    HelpLine::Item {
        keys: "/mail",
        text: "full-screen compose view: To / Subtext / Content, plus voice recordings \
               (hold Space, only while the attachments pane is focused) and file \
               attachments ('a' opens the browser; 'd' removes the selected one, after \
               confirming).",
    },
    HelpLine::Note(
        "Needs a pinned recipient you hold an OTP MAIL key for specifically - its own, \
         entirely independent of any live /otp session with them - longer than the \
         whole mail. With no mail key at all, a centered red message blocks the whole \
         compose view until Esc closes it (and the view with it); /new-otp-mail-key or \
         /contacts is how you get one. The To field otherwise shows \u{2705}/\u{274C} live and the \
         remaining key (MB) shows top-right, updating as you type and attach. Ctrl+S \
         sends, only after a confirm popup. The mail travels one-time-pad encrypted and \
         waits on the server (which cannot read it) until the recipient connects.",
    ),
    HelpLine::Item {
        keys: "/mailbox",
        text: "opens the mailbox: each sent mail's delivery status, and received mail - \
               Enter reads one (decrypted in memory only), 'd' removes it, destroying its \
               stored ciphertext+pad.",
    },
    HelpLine::Blank,
    HelpLine::Heading("Contacts & Keys"),
    HelpLine::Note(
        "id_store remembers each pinned nickname's full public key across sessions (not \
         just a hash) - exact match, since an identity is loaded from a file and never \
         changes on its own. A mismatch opens a popup naming the peer with Accept/Reject \
         buttons; messaging with them is blocked until you decide. Accept saves to disk \
         right away and reveals anything of theirs held while unresolved; Reject saves \
         nothing and isn't permanent - select them again to reconsider. Path set in the \
         connect popup's id_store field.",
    ),
    HelpLine::Item {
        keys: "/contacts",
        text: "one row per pinned *device* of a nickname, not one per nickname - a \
               multi-device contact gets one row each, its device id (8 characters, so \
               this rarely crops in practice) cropped to 10 characters for width if \
               longer (never in a details popup, which always shows it in full). Its \
               three keys - PQH (the pinned identity itself), OTP (a live /otp session), \
               OTP MAIL (a /mail-only key, entirely separate from the live one) - render \
               as small buttons, \u{2705}/\u{274C} coloured, e.g. [\u{2705}PQH]. Up/Down \
               picks the row, Left/Right the key within it - a genuine grid, so only one \
               button in the whole list is ever highlighted, never the same key across \
               every row at once. Enter opens that exact button's own details: what the \
               key is for, its path and live figures if it exists, and a Create (PQH, \
               from an identity card file) / Install manually (OTP or OTP MAIL, from \
               files you generated yourself) / Delete action, taking effect immediately \
               in the list. 'd' deletes the whole contact (every device, every key with \
               it); 'r' refreshes; 'a' opens Add contact; 'x', or the Export identity card \
               button that is always the list's own last entry, exports your own identity \
               card.",
    },
    HelpLine::Item {
        keys: "a",
        text: "(inside /contacts) Add contact: pin a nickname before ever connecting to \
               them, so keys can be attached ahead of time. Device id and identity card \
               are both optional - leave the device id blank for the nickname's shared \
               unbound slot. Confirming pins the contact right away, even with no key at \
               all yet (all three badges show \u{274C} until you add one), and opens the \
               same key-details popup Enter does, where PQH's Create key binds straight \
               to the device just typed (or the unbound slot, if left blank) - unlike \
               the ordinary case above - and, once it succeeds, stays open rather than \
               closing so OTP/OTP MAIL can be added right after in the same sitting. Esc \
               at any point just leaves the contact keyless for now - add a key from this \
               same row whenever you're ready.",
    },
    HelpLine::Item {
        keys: "x",
        text: "(inside /contacts) export your own identity card (own pqhybrid key) - the \
               live equivalent of 'aloo --export-identity-card', no arguments needed. The \
               same action is also always the list's own last entry, an Export identity \
               card button reachable by Up/Down and Enter even with no contacts pinned \
               yet. Writes ~/.aloo/exports/<your-nickname>.aloo-card and shows its safety \
               phrase; send the file to someone by any means and they have you pinned \
               and verified before you've ever spoken.",
    },
    HelpLine::Item {
        keys: "/new-otp-mail-key",
        text: "inside an open DM room: the /otp-style handshake, but for the OTP MAIL \
               key specifically - entirely independent of any live /otp session with \
               the same person. Refused with no network round trip if a mail key \
               already exists for that contact (delete it from /contacts first, or \
               just use /mail).",
    },
    HelpLine::Blank,
    HelpLine::Heading("Server superadmin"),
    HelpLine::Note(
        "Only nicknames the server's server_superadmin setting names may use these - \
         everyone else is refused with a reason. A \u{26A1} marks a superadmin's name in \
         every channel's sidebar and its own user-info popup.",
    ),
    HelpLine::Item {
        keys: "/activate <nickname>",
        text: "clear whatever blocks that account's login: a still-pending emailed \
               activation code, a previous /deactivate, or both",
    },
    HelpLine::Item {
        keys: "/deactivate <nickname> <reason>",
        text: "lock that account out of logging in, naming why. If they're connected right \
               now, their own screen takes over with the reason and Escape as its only key.",
    },
    HelpLine::Item {
        keys: "/remove-account <nickname>",
        text: "delete that account outright, and every channel it administers (their \
               members are told and removed)",
    },
    HelpLine::Item {
        keys: "/remove-channel <name>",
        text: "delete any public channel by name, whether or not you administer it",
    },
    HelpLine::Item {
        keys: "/users",
        text: "open a popup listing every registered user and which channels each \
               currently administers (\"no channels\" for one administering none). \
               Read-only; Esc closes it.",
    },
    HelpLine::Blank,
    HelpLine::Heading("Your password"),
    HelpLine::Item {
        keys: "/password <old> <new>",
        text: "change your own password - no superadmin needed. The server re-checks \
               <old> exactly like logging in would before accepting <new>; a wrong one \
               is refused and nothing changes. Both are exactly one word each - a \
               password containing a space isn't supported here.",
    },
    HelpLine::Blank,
    HelpLine::Note(
        "All local state (id_store, settings, the OTP keychain) lives under ~/.aloo by \
         default. Set ALOO_HOME to use a different directory - needed if you run more \
         than one client on this same machine, since they'd otherwise collide by sharing \
         one ~/.aloo.",
    ),
    HelpLine::Blank,
    HelpLine::Item {
        keys: "Ctrl+S",
        text: "reach someone with no server involved: opens the \"Direct Punches\" popup - \
               'a' adds a target with their nickname, and where their client is (an IPv4/ \
               IPv6 address or hostname, optionally :port), and how often to try - \
               every_1m, every_5m, ... every_55m or every_1h. Every schedule restarts at \
               the top of the hour, so every_1m tries at :00, :01, :02... and every_1h at \
               :00 only - both sides trying at the same clock moments, with nothing \
               coordinating it but that. It only works if they've added you back the same \
               way - your nickname, your public host/IP, and the *same* frequency - \
               otherwise your two attempts never land at the same moment. Shown only once \
               you've configured at least one. If your own address moves (an ordinary \
               home connection), set noip_when_no_server_and_direct_punch_is_active=on plus \
               noip_hostname/noip_username/noip_password (a No-IP account) in \
               ~/.aloo/settings - aloo keeps that hostname pointed at wherever you \
               currently are, so you can give the other person a fixed hostname to punch \
               at instead of a raw address that might change.",
    },
    HelpLine::Item {
        keys: "Ctrl+C",
        text: "quit",
    },
    HelpLine::Item {
        keys: "Ctrl+H / Esc",
        text: "close this help",
    },
    HelpLine::Item {
        keys: "Up/Down",
        text: "scroll",
    },
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
    /// Incoming only: a `.txt` offer whose bytes have fully arrived, but
    /// staged under `file_transfer::incoming_preview_dir()` rather than
    /// `~/.aloo/downloads` - previewable (`UiAction::RequestFilePreview`)
    /// without being considered saved. Becomes `Completed` the moment the
    /// user actually saves it (`UiAction::SaveStagedFile`, the `d` key
    /// inside the preview popup) - the only way out of this state besides
    /// leaving it, which the next startup's sweep quietly cleans up.
    Received { staged_path: std::path::PathBuf },
    /// The recipient declined the offer - outgoing rows only.
    Rejected,
    /// A local error ended the transfer early (disk/read/write failure) -
    /// surfaced rather than left stuck mid-progress forever.
    Failed,
}

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
    /// A voice row reconstructed from `resume_from_log` history that
    /// hasn't been loaded into memory yet - `client::export`'s reader
    /// deliberately never decodes the referenced `.wav` up front (see its
    /// own module doc). `wav_path` is `None` when the original autosave
    /// couldn't write the audio at the time (its `.log` line names a
    /// duration but no file) - replaying that row can only report that
    /// nothing was saved, not play anything. Replaying a `Some` row
    /// (`handle_messages_key`'s `Enter`) decodes it on the spot and
    /// mutates this entry into an ordinary `Voice` in place, so a second
    /// replay of the same row is instant.
    VoiceOnDisk {
        duration_ms: u32,
        wav_path: Option<PathBuf>,
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
    /// given the OTP prefix (`render_messages`) - it would be
    /// redundant on a line that already names OTP explicitly, and the
    /// prefix is meant to mark *content*, not the app's own narration.
    System(String),
    /// A peer joining a channel, leaving one, or disconnecting entirely -
    /// rendered in yellow (`render_messages`), unlike the gray/italic
    /// `System` above, so it stands out as a presence change rather than
    /// app narration. Already-formatted text (`local_time_short` prefix
    /// plus the peer's name and the event) built by
    /// `channel::on_user_joined`/`on_user_left`/`ui::on_user_offline` -
    /// see `docs/SPEC.md` Functionality #12. Excluded from the OTP
    /// prefix for the same reason `System` is.
    Presence(String),
}

/// What the transfers behind one outgoing file row have reported.
///
/// A channel file send is one row - the same shape a channel voice message
/// has, and what the details popup lists every recipient of - but the
/// transfer underneath it is per recipient: each has its own `stream_id`,
/// its own worker, and its own accept/reject/progress/completion. This is
/// how those separate answers become the single status that row shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileRowProgress {
    /// Every transfer this row covers, and how many bytes each has sent.
    /// A transfer that has not started yet is present with `0`.
    sent: HashMap<u64, u64>,
    done: HashSet<u64>,
    failed: HashSet<u64>,
    rejected: HashSet<u64>,
}

impl FileRowProgress {
    /// The one status the row shows, from what every transfer behind it
    /// has said so far.
    ///
    /// While any are still going, the row reports the *least* advanced of
    /// them: the row means "this file, to these people", and it is not
    /// sent until it is sent to all of them. Once none are left, the row
    /// is Completed if any recipient took it, Rejected if they all
    /// declined, and Failed otherwise - a send nobody took because
    /// something broke is not the same as one everybody turned down.
    fn status(&self) -> FileTransferStatus {
        let outstanding: Vec<u64> = self
            .sent
            .keys()
            .copied()
            .filter(|s| {
                !self.done.contains(s) && !self.failed.contains(s) && !self.rejected.contains(s)
            })
            .collect();
        if outstanding.is_empty() {
            if !self.done.is_empty() {
                return FileTransferStatus::Completed;
            }
            if self.failed.is_empty() && !self.rejected.is_empty() {
                return FileTransferStatus::Rejected;
            }
            return FileTransferStatus::Failed;
        }
        let bytes = outstanding
            .iter()
            .map(|s| self.sent.get(s).copied().unwrap_or(0))
            .min()
            .unwrap_or(0);
        FileTransferStatus::InProgress { bytes }
    }
}

/// One recipient of an outgoing message, and whether that recipient has
/// acknowledged it yet (`docs/PROTOCOL.md` 7.2.1). A DM has exactly one of
/// these; a channel send has one per member it was addressed to, which is
/// what lets the row distinguish "nobody yet" from "some of them" from
/// "everyone" (`DeliveryStatus`).
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryRecipient {
    pub id: UserId,
    /// The nickname as it was at send time. Snapshotted rather than looked
    /// up when the info popup renders, so a recipient who has since left
    /// is still named rather than disappearing from the list of who a
    /// message went to.
    pub name: String,
    /// They could read it (`p2p_proto::ReceiptStage::Decrypted`).
    pub delivered: bool,
    /// Whether this leg went out under the one-time-pad layer, and so
    /// answers to the pad's own acknowledgement rather than to an ordinary
    /// delivery receipt (`DeliveryProof`).
    ///
    /// Per recipient rather than per row, because a channel send can be
    /// mixed: some members reachable under a pad, others not, all sharing
    /// one `msg_id`.
    pub awaits_pad_ack: bool,
    /// They have since done the thing the message was for - played the
    /// audio, saved the file (`p2p_proto::ReceiptStage::Consumed`). Only
    /// ever true for a voice or file row, and shown only in the details
    /// popup: the log's own arrow stays a three-state summary of who has
    /// the message, not of what they did with it.
    pub consumed: bool,
    /// They opened this file in the preview popup without saving it
    /// (`p2p_proto::ReceiptStage::Viewed`) - a weaker claim than
    /// `consumed`, which always wins once true (`recipient_label`). File
    /// rows only.
    pub viewed: bool,
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

/// What one message row's indicator says, aggregated over its recipients
/// (`docs/SPEC.md` "Delivery acknowledgments"). `Some` never applies to a
/// DM - one recipient is either delivered or not - so a DM row's arrow is
/// only ever gray or green.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Not one recipient has acknowledged it yet.
    None,
    /// At least one has, but not all of them.
    Some,
    /// Every recipient has.
    All,
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

impl DeliveryStatus {
    /// The colour this status paints `DELIVERY_ARROW` in: gray for
    /// nothing acknowledged yet, orange while only some of a channel's
    /// recipients have, green once all of them have.
    pub fn color(self) -> Color {
        match self {
            DeliveryStatus::None => Color::DarkGray,
            // Ratatui's `Yellow` is the terminal's colour 3, which every
            // palette renders as an orange/amber - this app's existing
            // "partway there" colour (a reconnect in progress, a peer
            // still being punched at).
            DeliveryStatus::Some => Color::Yellow,
            DeliveryStatus::All => Color::Green,
        }
    }
}

/// How one logged message's content was actually protected, as the
/// details popup reports it (`docs/SPEC.md` "Delivery acknowledgments").
///
/// Recorded on the row when it is logged rather than derived when the
/// popup opens: an OTP session's pad walks forward with every message, so
/// by the time anyone presses `i` the live figures describe some later
/// message, not this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageCrypto {
    /// The ordinary per-recipient PQ-hybrid envelope
    /// (`client::envelope`). `key_id` is a short fingerprint of the one
    /// public key involved (`crypto::short_fingerprint_der`), or `None`
    /// for a channel send addressed to several keys at once.
    Envelope { key_id: Option<String> },
    /// The one-time-pad layer (`docs/PROTOCOL.md` §16): which sequence
    /// this message is, the pad offset its key bytes start at, and the key
    /// file they were taken from.
    Otp {
        seq: u64,
        offset: u64,
        key_path: String,
        /// Whether a sealed envelope was built around the pad
        /// (`PqWrapped`) or the pad ciphertext travelled on its own
        /// (`Direct`, §16.2) - the one thing about a pad-protected message
        /// that is not the same on every pair, so the popup must not
        /// assume it.
        inside_envelope: bool,
    },
}

/// What the details popup calls each layer - the mechanism, not the
/// `my_key` tag `KeyMode::label` shows in the sidebar. Someone asking how
/// one specific message was encrypted is asking about the cipher.
impl MessageCrypto {
    pub fn method_label(&self) -> &'static str {
        match self {
            MessageCrypto::Envelope { .. } => {
                "ML-KEM-1024 + RSA-4096 -> AES-256-GCM, ML-DSA-87 signed"
            }
            MessageCrypto::Otp {
                inside_envelope: true,
                ..
            } => "one-time pad (XOR) inside the pq_hybrid envelope",
            MessageCrypto::Otp {
                inside_envelope: false,
                ..
            } => "one-time pad (XOR), carrying the message directly",
        }
    }
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
    /// When this row was created, in local time - what the info popup
    /// shows (`docs/SPEC.md` "Delivery acknowledgments"). Formatted at
    /// creation (`local_time_stamp`) rather than stored as an instant, the
    /// same way presence notices already carry their own formatted time.
    pub sent_at: String,
    /// The same instant as `sent_at`, in UTC (`export::utc_time_stamp`) -
    /// `sent_at` is local-time-only, and `client::export`'s autosave/manual
    /// export log lines need real UTC rather than whatever timezone this
    /// machine happens to be in.
    pub sent_at_utc: String,
    /// Set only on an outgoing message whose delivery this client tracks
    /// (`docs/PROTOCOL.md` 7.2.1). `None` everywhere else, including
    /// everything incoming (which was delivered to us by the fact of being
    /// here), so those rows show no indicator rather than a misleading
    /// gray one.
    pub delivery: Option<MessageDelivery>,
    /// The mirror image, on an *incoming* voice row: what this side still
    /// owes its sender a `Consumed` receipt for, because the audio decoded
    /// but was not played at the time - the sender had been muted, or was
    /// still under identity review. Taken and sent if the user ever
    /// replays the row (`handle_messages_key`'s Enter); `None` on every
    /// row that owes nothing, which is almost all of them.
    pub owed_receipt: Option<u64>,
    /// How this row's content was protected, for the details popup
    /// (`MessageCrypto`). `None` on a row there is nothing to say it
    /// about: a system or presence line this client wrote itself, or a
    /// channel send whose members do not share one scheme.
    pub crypto: Option<MessageCrypto>,
    /// Whether this row's voice has actually been heard - either it
    /// autoplayed live (the sending channel/DM was the one on screen when
    /// it arrived), or it was later replayed manually (`Enter` in
    /// `handle_messages_key`). `true` on every non-voice row, and on every
    /// outgoing voice row (the marker below only ever applies to something
    /// received - `render_messages` also gates on `!entry.outgoing` as a
    /// second safeguard). Drives the red "not listened" end-of-line
    /// marker for a received `MessageBody::Voice` row that never got
    /// either.
    pub listened: bool,
}

/// One outgoing message's delivery state: who it was addressed to, and
/// which of them have acknowledged it (`docs/PROTOCOL.md` 7.2.1).
#[derive(Debug, Clone, PartialEq)]
pub struct MessageDelivery {
    /// This message's own identifier within this client, handed out by
    /// `UiState::alloc_msg_id`. It goes on the wire as the reliable
    /// frame's delivery tag, so a recipient's acknowledgement can be routed
    /// straight back to this row (`UiState::mark_delivered`) - which a log
    /// index could not do, since a row lives in one of many logs.
    pub msg_id: u64,
    pub recipients: Vec<DeliveryRecipient>,
}

impl MessageDelivery {
    /// This message's aggregate status, over every recipient it was
    /// addressed to. A send that reached nobody - every member filtered
    /// out by the key-mode policy, or an empty channel - is `None` rather
    /// than a vacuous `All`: nothing was acknowledged because nothing went
    /// anywhere, and the row must not claim otherwise.
    pub fn status(&self) -> DeliveryStatus {
        let delivered = self.recipients.iter().filter(|r| r.delivered).count();
        if delivered == 0 || self.recipients.is_empty() {
            DeliveryStatus::None
        } else if delivered == self.recipients.len() {
            DeliveryStatus::All
        } else {
            DeliveryStatus::Some
        }
    }
}

impl LogEntry {
    /// This row's delivery status, or `None` for a row that tracks no
    /// delivery at all - such a row shows no indicator.
    pub fn delivery_status(&self) -> Option<DeliveryStatus> {
        self.delivery.as_ref().map(MessageDelivery::status)
    }

    /// Whether this row was sent and reached nobody at all - an empty
    /// channel, or every member excluded by the key-mode policy. Distinct
    /// from merely undelivered: there is no acknowledgement still to come,
    /// so the row is struck through rather than left looking like it is
    /// waiting (`render_messages`).
    pub fn reached_nobody(&self) -> bool {
        self.delivery
            .as_ref()
            .is_some_and(|d| d.recipients.is_empty())
    }
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
    /// The Ctrl+S "Direct Punches" popup is open - see
    /// `crate::client::tui::direct_punch_popup`. Data lives in
    /// `UiState::direct_punches`, same split as `FileSend`/`file_send`.
    DirectPunches,
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
    /// `\u{23FA} Call Ctrl+R` indicator, leaving the ordinary
    /// sidebar/messages/compose layout usable again. Ctrl+R brings it back.
    pub minimized: bool,
    /// The host's invite picker, while it is open.
    pub invite_picker: Option<CallInvitePicker>,
    /// `true` while END CALL is waiting on its own confirmation
    /// (`docs/SPEC.md` "Live voice calls"). The button is focused from the
    /// moment the modal opens and Enter is the modal's most reachable key,
    /// so without this a stray Enter leaves a call with no way back into
    /// it. `Confirm::No` is the default answer, same as the
    /// identity review's `Reject`: the safe one.
    pub end_confirm: Option<Confirm>,
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

#[derive(Debug, Clone, PartialEq)]
pub enum UiAction {
    /// Ctrl+O on the focused message: open this URL in the OS default
    /// browser (`session::handle_ui_action`, `client::open_url`).
    OpenUrl(String),
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
        /// This send's delivery tag, shared by every per-recipient frame
        /// it turns into and matching the log row's own
        /// `MessageDelivery::msg_id` - what routes each recipient's
        /// acknowledgement back to that one row (`docs/PROTOCOL.md` 7.2.1).
        msg_id: u64,
    },
    SendDirectText {
        to: UserId,
        plaintext: String,
        recipient_pubkey_der: Vec<u8>,
        /// Where this text landed in the DM's log when it was optimistically
        /// shown (`push_outgoing_dm`) - lets a later async failure
        /// (currently only an OTP send) find and mark that exact row
        /// (`UiState::mark_dm_message_failed`) rather than leaving a
        /// message that was never delivered looking identical to one that
        /// was.
        log_index: Option<usize>,
        /// This send's delivery tag - see `SendChannelText::msg_id`.
        msg_id: u64,
    },
    /// The target is captured at press-time (not release-time): live
    /// streaming needs to know who to address the wire `StreamXStart` to
    /// the moment recording starts, not just once it's done.
    VoiceRecordStart(VoiceTarget),
    VoiceRecordStop,
    ReplayVoice {
        duration_ms: u32,
        pcm: Vec<u8>,
        /// Who sent the clip being replayed - who `owed_receipt` is owed
        /// to.
        from: UserId,
        /// Set when this replay is the first time the clip has actually
        /// been heard, because playback was suppressed when it arrived
        /// (`docs/PROTOCOL.md` 7.2.1). The session sends that peer a
        /// `Consumed` receipt for it; `None` means nothing is owed -
        /// either it played on arrival, or it has been replayed before.
        owed_receipt: Option<u64>,
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
    /// "Yes" on the first unknown-direct-peer popup (`docs/PROTOCOL.md`
    /// §7.1.5) - `session::handle_ui_action` runs the real cryptographic
    /// scan, since `UiState` has no crypto/session access.
    CheckUnknownPeerIdentity(UserId),
    /// "No" on the first popup - no scan runs, no ban-counting; the
    /// captured proof is simply discarded.
    DeclineUnknownPeerIdentity(UserId),
    /// "Yes" on the second ("use <nickname>'s key?") popup - pins the
    /// matched key under the new nickname and completes registration from
    /// the plaintext the scan already recovered.
    ConfirmUnknownPeerKey(UserId),
    /// "No" on the second popup - discards this specific match; a later,
    /// distinct proof re-triggers the whole flow from the top.
    DeclineUnknownPeerKey(UserId),
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
    /// `Enter` on a staged `.txt` receive (`FileTransferStatus::Received`)
    /// - `session::handle_ui_action` reads the file (capped, if oversized)
    /// and hands it back via `UiState::open_file_preview`, and sends a
    /// `Viewed` receipt the first time this row is opened (`UiState` has
    /// no disk/network access to do either itself).
    RequestFilePreview {
        from: UserId,
        stream_id: u64,
    },
    /// `d` inside the preview popup - identical in effect to accepting any
    /// other file transfer's default save (`session::handle_ui_action`):
    /// moves the staged file into `~/.aloo/downloads` and settles delivery
    /// as `Consumed`, exactly as an ordinary (non-`.txt`) receive already
    /// does on arrival.
    SaveStagedFile {
        from: UserId,
        stream_id: u64,
    },
    /// Sent by the `/otp` command (`submit_input`) for the currently open
    /// DM room - the one and only trigger for starting an OTP session
    /// (`client::otp::handle_provisioning_command`). Never sent automatically.
    RequestOtpSession {
        peer: UserId,
        pubkey_der: Vec<u8>,
    },
    /// Sent by the `/new-otp-mail-key` command (`submit_input`) for the
    /// currently open DM room - the one and only trigger for provisioning a
    /// mail-only key (`client::otp::handle_provisioning_command`, same
    /// mechanics as `RequestOtpSession`, different purpose).
    RequestOtpMailKey {
        peer: UserId,
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
    /// Escape during generation or transfer: abandon the pad on both sides
    /// and erase whatever has been staged for it.
    CancelOtpPad {
        peer: UserId,
    },
    /// The user accepted an incoming OTP session proposal
    /// (`otp_invite_open`) - `client::otp::accept_invite`.
    AcceptOtpInvite,
    /// The user rejected it - `client::otp::reject_invite`.
    RejectOtpInvite,
    /// Sent by the `/endotp` command (`submit_input`) for the currently
    /// open DM room - unilaterally ends an active OTP session with that
    /// peer (`client::otp::handle_end_otp_command`), no accept/reject round
    /// trip the way starting one needs. The one DM action `submit_input`
    /// still allows while that peer is offline - see its doc.
    EndOtpSession {
        peer: UserId,
        pubkey_der: Vec<u8>,
    },
    /// Emitted on every keystroke in the mail compose view's To field
    /// (docs/PROTOCOL.md §17.1) - `client::otp_mail::check_recipient` runs
    /// the pinned-user + keychain + remaining-key checks (which need
    /// `SessionState` and the `otp` CLI, neither of which `UiState` has)
    /// and answers through `UiState::otp_mail_set_check`.
    CheckOtpMailRecipient {
        nickname: String,
    },
    /// Up/Down inside the compose view's device selector
    /// (`MailFocus::Device`) - re-runs `check_recipient` against the
    /// newly highlighted device only, never a full re-enumeration
    /// (`client::otp_mail::handle_select_device`).
    SelectOtpMailDevice {
        nickname: String,
        device_id: String,
    },
    /// The `/mail` command (`submit_input`) - checks the local `otp`
    /// binary is actually available before opening the compose view at all
    /// (`client::otp_mail::handle_open_otp_mail`), the same guard
    /// `RequestOtpSession`/`RequestOtpMailKey` already apply for
    /// `/otp`/`/new-otp-mail-key`. Never opens `UiState::open_otp_mail`
    /// directly from the UI layer, which has no way to check for itself.
    RequestOpenOtpMail,
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
    /// `/mute-voice <nickname>` / `/unmute-voice <nickname>`: stop (or
    /// resume) that nickname's voice messages playing themselves on
    /// arrival (docs/SPEC.md Functionality #15).
    ///
    /// An action rather than a change `UiState` applies itself, because it
    /// has to reach `~/.aloo/settings` - and every other persisted
    /// mutation in this app is likewise carried out session-side
    /// (`id_store`, `otp_store`), leaving `UiState` free of file I/O so
    /// tests can construct one without a filesystem. The session writes
    /// through and hands the stored set back via `set_muted_voice`, so
    /// what is in memory is always what is on disk.
    ///
    /// Deliberately carries a nickname, not a `UserId`: muting someone who
    /// is offline (or has never connected) is meaningful and expected.
    SetVoiceMuted {
        nickname: String,
        muted: bool,
    },
    /// The `/contacts` command - gathers every pinned identity
    /// (`idstore.rs`) merged with its live OTP keychain state, if any
    /// (`client::contacts::gather_contact_rows`), and hands the rows to
    /// the modal `open_contacts` already opened empty.
    OpenContacts,
    /// Ctrl+S - reads `direct_punch_to` fresh from `~/.aloo/settings` and
    /// hands the rows to the modal `open_direct_punches` already opened
    /// empty, same split as `OpenContacts`.
    OpenDirectPunches,
    /// `Ctrl+E`'s popup was confirmed with at least one channel/DM
    /// checked - dumps each one's current in-memory log to
    /// `~/.aloo/exports/<server>/...` (`client::export::export_log`),
    /// every file from this one export sharing the `prefix` shortuuid.
    ExportSelected {
        prefix: String,
        channels: Vec<String>,
        dms: Vec<UserId>,
    },
    /// An add, edit or delete on the "Direct Punches" popup - persists the
    /// whole replacement list to `~/.aloo/settings` (a merging write, so a
    /// concurrent daemon's own keys are untouched) and immediately
    /// reconfigures `PeerLinkManager`'s scheduler with it.
    SaveDirectPunchTargets(Vec<crate::settings::DirectPunchTarget>),
    /// `r` on the contacts modal - re-runs the same gather, e.g. after the
    /// remaining OTP key has moved since it was last opened.
    RefreshContacts,
    /// `i` on a channel member, or `/info` in an open DM - gathers exactly
    /// one `(nickname, device_id)`'s pinned identity
    /// (`client::contacts::handle_request_user_info`, a narrower
    /// `gather_contact_rows`) and hands it to the popup `open_user_info`
    /// already opened empty. `nickname` is carried directly rather than
    /// re-read from `known_users` session-side, the same reasoning every
    /// other `UiAction` already follows.
    RequestUserInfo { peer: UserId, nickname: String },
    /// The user confirmed "delete contact" on the contacts modal's list -
    /// forgets `nickname` outright, every device (device-pinning plan §3):
    /// every device's identity pin, and each one's OTP keychain entries
    /// too if it had any (`client::contacts::handle_delete`). See
    /// `DeleteContactDevice` for the per-device counterpart, sent instead
    /// from a specific row's own PQH key detail popup.
    DeleteContact {
        nickname: String,
    },
    /// The contacts modal's PQH key detail popup, "Delete key" - removes
    /// just the one device that popup was opened for: its identity pin,
    /// and that device's own OTP/mail keychain entries, leaving every
    /// sibling device's pin and keys untouched
    /// (`client::contacts::handle_delete_contact_device`, device-pinning
    /// plan §3's additive delete). `None` is the unbound row.
    DeleteContactDevice {
        nickname: String,
        device_id: Option<String>,
    },
    /// The user confirmed "Install OTP key" on the contacts modal, having
    /// picked both key files with its own file browser - runs
    /// `otp --add-contact` against them directly
    /// (`client::contacts::handle_install_otp_key`), the manual
    /// counterpart to `/otp`'s handshake-driven provisioning.
    InstallOtpKey {
        nickname: String,
        /// Which of `nickname`'s devices this installs against - the row
        /// this was opened from; `None` is the unbound row, filed under
        /// the not-yet-qualified name and claimed on first use like any
        /// other unbound entry (device-pinning plan §3).
        device_id: Option<String>,
        /// Which of the two independent keychain entries this installs -
        /// `Live` for the plain `/otp` key, `Mail` for the OTP-mail-only
        /// key (`crypto::otp::contact_name_for_mail`). The contacts
        /// modal's top-level `o` shortcut always sends `Live`; the newer
        /// per-key detail popup (`ContactKeyKind::Otp`/`OtpMail`) can send
        /// either.
        purpose: crate::crypto::otp::OtpPurpose,
        enc_path: std::path::PathBuf,
        dec_path: std::path::PathBuf,
    },
    /// The contacts modal's OTP or OTP-mail key detail popup, "Delete
    /// key" - removes just that one purpose's keychain entry for the
    /// specific device that popup was opened for
    /// (`client::contacts::handle_delete_otp_key`), leaving the identity
    /// pin, the *other* purpose's key, and every sibling device untouched.
    /// `DeleteContactDevice` above is what the PQH key's own "Delete key"
    /// sends instead, since removing the identity pin necessarily takes
    /// both purposes with it.
    DeleteContactKey {
        nickname: String,
        device_id: Option<String>,
        purpose: crate::crypto::otp::OtpPurpose,
    },
    /// The PQH key detail popup's "Create key": imports an identity card
    /// file, pinning it as `Verified` if its self-signed nickname matches
    /// the contact row this was opened from
    /// (`client::contacts::handle_pin_identity_card`).
    PinIdentityCard {
        nickname: String,
        path: std::path::PathBuf,
    },
    /// The "Add contact" popup's PQH step (`client::tui::contacts::
    /// AddContactState`, device-pinning plan §3): the same import, but
    /// binding directly to `device_id` - typed by the user, not learned
    /// live - rather than the nickname's shared unbound entry
    /// (`client::contacts::handle_pin_identity_card_for_device`).
    PinIdentityCardForDevice {
        nickname: String,
        device_id: String,
        path: std::path::PathBuf,
    },
    /// The "Add contact" popup's own submit, before any key is ever
    /// chosen: reserves `(nickname, device_id)` (`device_id` empty for the
    /// nickname's shared unbound slot) as a bare placeholder with no key
    /// at all - `client::contacts::handle_add_bare_contact` - so the
    /// contact already exists and shows in the list even if the user
    /// leaves the key-details popup that opens right after without ever
    /// adding one; the identity card import that popup still offers is
    /// optional, not a precondition for creating the contact.
    AddBareContact {
        nickname: String,
        device_id: String,
    },
    /// `/contacts`' `x`: writes this client's own identity card - the
    /// live-session equivalent of `aloo --export-identity-card`
    /// (`client::contacts::handle_export_own_identity_card`), signed with
    /// the same `pq_hybrid` keybundle already loaded for this session,
    /// no separate prefix/nickname arguments needed. Purely local - never
    /// reaches the server.
    ExportOwnIdentityCard,
    /// A superadmin's `/users` (`UiState::try_superadmin_command`): sends
    /// `ClientMessage::RequestUsersList`, answered with
    /// `ServerMessage::UsersList` (`session::handle_server_message` ->
    /// `UiState::set_users_admin`).
    RequestUsersList,
    /// `/password <old> <new>` (`UiState::try_password_command`): sends
    /// `ClientMessage::ChangePassword`. The result comes back as
    /// `ServerMessage::ChangePasswordResult`, surfaced as a status notice
    /// (`session::handle_server_message`) - there is no local validation
    /// of `old` to skip a round trip, since only the server holds
    /// anything to check it against.
    ChangePassword {
        old_password: String,
        new_password: String,
    },
    /// `/daemon`: stop drawing and hand this session back to the
    /// background, leaving every connection, link and key exactly as they
    /// are (docs/SPEC.md "Running in background mode").
    ///
    /// Answered by `session::run_connected_session`'s own input arm rather
    /// than by `handle_ui_action`: it acts on the `Surface`, which that
    /// loop owns and the action handler - which is about network sends -
    /// has no business holding.
    Detach,
    /// Escape on the full-screen account-deactivated modal
    /// (`UiState::account_deactivated`) - the one key it answers.
    /// Answered by `session::run_connected_session`'s own input arm, the
    /// same way `Detach` is: it ends the whole session (the same exit an
    /// ordinary Ctrl+C already uses), which is a loop-level effect
    /// `handle_ui_action` - about network sends - has no business having.
    Quit,
    /// The channel admin's `/delete-channel` (after its confirmation
    /// popup), `/ban`, `/unban`, `/lock-joins`' Apply, or `/assign-admin`
    /// (after its confirmation popup) - see `docs/PROTOCOL.md`'s
    /// channel-ownership section.
    DeleteChannel {
        name: String,
    },
    BanFromChannel {
        channel: String,
        nickname: String,
    },
    UnbanFromChannel {
        channel: String,
        nickname: String,
    },
    SetChannelJoinLock {
        channel: String,
        allowed: Option<Vec<String>>,
    },
    AssignChannelAdmin {
        channel: String,
        nickname: String,
    },
    /// A superadmin's `/activate`/`/deactivate`/`/remove-account`/
    /// `/remove-channel` (`docs/PROTOCOL.md` §5.5) - see
    /// `UiState::try_superadmin_command`.
    AdminActivate {
        nickname: String,
    },
    AdminDeactivate {
        nickname: String,
        reason: String,
    },
    AdminRemoveAccount {
        nickname: String,
    },
    AdminRemoveChannel {
        name: String,
    },
}

impl UiAction {
    /// What this action needs a server for, or `None` if it can happen
    /// with nothing but a direct link (`docs/PROTOCOL.md` §7.1.5).
    ///
    /// Named rather than boolean because the answer is shown to the user:
    /// "joining a channel needs a server" is actionable, "unavailable" is
    /// not. Everything absent from this list works serverlessly, which is
    /// most of the app - text, voice, files, calls and live OTP sessions
    /// are all peer-to-peer and never involved a server in the first place.
    pub fn needs_server(&self) -> Option<&'static str> {
        match self {
            // Membership is server state. With no server, a channel is a
            // name both sides declare in their settings instead.
            Self::JoinChannel { .. } => Some("joining a channel"),
            // OTP *mail* is stored on the server for an offline recipient;
            // a live OTP session is peer-to-peer and stays available.
            Self::CheckOtpMailRecipient { .. }
            | Self::SelectOtpMailDevice { .. }
            | Self::RequestOpenOtpMail
            | Self::OpenOtpMailbox
            | Self::SendOtpMail
            | Self::ReadOtpMail { .. }
            | Self::DeleteOtpMail { .. }
            | Self::SaveOtpMailAttachment { .. } => Some("OTP mail"),
            // Channel ownership/moderation is server-arbitrated state -
            // there is nobody to enforce a ban, a lock, or an admin
            // handoff against an uncooperative peer with no server.
            Self::DeleteChannel { .. } => Some("deleting a channel"),
            Self::BanFromChannel { .. } | Self::UnbanFromChannel { .. } => {
                Some("banning or unbanning a channel member")
            }
            Self::SetChannelJoinLock { .. } => Some("locking channel joins"),
            Self::AssignChannelAdmin { .. } => Some("changing a channel's admin"),
            // Superadmin actions are server-side account/registry state -
            // there is no "without a server" meaning for any of them.
            Self::AdminActivate { .. } => Some("activating an account"),
            Self::AdminDeactivate { .. } => Some("deactivating an account"),
            Self::AdminRemoveAccount { .. } => Some("removing an account"),
            Self::AdminRemoveChannel { .. } => Some("removing a channel"),
            Self::RequestUsersList => Some("listing registered users"),
            // A password is server-registry state (`server::users_registry`)
            // - there is no account, and so nothing to change, without one.
            Self::ChangePassword { .. } => Some("changing your password"),
            // Everything else is peer-to-peer. Leaving is deliberately not
            // here: with no server a channel is a local declaration, so
            // leaving one is a local act that needs nobody's permission.
            _ => None,
        }
    }
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
    selector_dropdown_since: Option<Instant>,
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
    /// The Ctrl+S "Direct Punches" popup's state, while
    /// `mode == Mode::DirectPunches` - see
    /// `crate::client::tui::direct_punch_popup`.
    pub direct_punches: Option<super::direct_punch_popup::DirectPunchPopupState>,
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
    channel_command_confirm_focus: Confirm,
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
    file_offer_queue: VecDeque<(UserId, u64)>,
    /// Reset to `Accept` every time a different offer becomes the one
    /// shown, same "always starts on the safe/common default" precedent
    /// `identity_review_focus` sets (there, `Reject`; here, `Accept` - see
    /// `PendingFileOffer`'s doc for why the default flips).
    file_offer_focus: Confirm,
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
    call_invite_focus: Confirm,
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
    call_confirm_focus: Confirm,
    /// The local "generate and share a fresh OTP pad?" confirmation opened
    /// by `/otp` when no keychain entry exists yet
    /// (`client::otp::handle_otp_command`) - `None` when nothing is
    /// pending. Only ever one at a time: `/otp` itself is unreachable while
    /// any modal popup (including this one) is already absorbing input.
    otp_generate_confirm: Option<PendingOtpGenerate>,
    otp_generate_focus: Confirm,
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
    /// `Some` while a pad is actually being generated
    /// (`client::otp::confirm_generate` through to the background
    /// generation task finishing) - drives the spinner popup, since a pad
    /// large enough to be worth choosing can take minutes and silence
    /// there is indistinguishable from a hang.
    otp_keygen: Option<OtpKeygenProgress>,
    /// Every incoming OTP session proposal currently awaiting a decision,
    /// keyed by the sender - mirrors `file_offers`/`file_offer_queue`
    /// exactly (queued-popup idiom, `Accept`-first default).
    otp_invites: HashMap<UserId, PendingOtpInvite>,
    otp_invite_queue: VecDeque<UserId>,
    otp_invite_focus: Confirm,
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
    otp_key_status: HashMap<UserId, crate::client::otp_cli::OtpKeyStatus>,
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
    help_scroll: usize,
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
    identity_review_queue: VecDeque<UserId>,
    /// Which button is focused in the currently-open popup. Reset to
    /// `Reject` (the non-trusting default) every time a different peer's
    /// review becomes the one shown, so accepting always takes a deliberate
    /// move off the safe default rather than an accidental double-Enter.
    identity_review_focus: Confirm,
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
    unknown_peer_review_queue: VecDeque<UserId>,
    /// Which button is focused in the currently-open popup. Reset to `No`
    /// every time a different peer's review becomes the one shown, for the
    /// same reason `identity_review_focus` resets to `Reject`.
    unknown_peer_review_focus: Confirm,
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
    /// "<active>/<total> direct punches, next try in <time> (Control+s)".
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
            direct_punches: None,
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

    /// Called by `client::otp_mail::refresh_unread_mail_count` whenever the
    /// received set can have changed.
    pub fn set_unread_otp_mail_count(&mut self, count: usize) {
        self.unread_otp_mail_count = count;
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
            self.identity_review_focus = Confirm::No;
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
            self.identity_review_focus = Confirm::No;
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

    /// Opens a review for a `direct_punch_to` nickname with no pinned key
    /// that just sent proof of an identity (`docs/PROTOCOL.md` §7.1.5) -
    /// called from `session::on_channel_presence`/`client::otp::on_message`
    /// the moment that gap is detected. Refuses a second review for a
    /// `peer` that already has one outstanding: a retried proof arriving
    /// while the first popup is still up is simply dropped, the same
    /// "silently drop" convention already used everywhere on this path.
    /// Returns whether it was actually queued.
    pub fn push_unknown_peer_review(
        &mut self,
        peer: UserId,
        requested_nickname: String,
        proof: UnverifiedDirectProof,
        source_addr: std::net::SocketAddr,
    ) -> bool {
        if self.unknown_peer_reviews.contains_key(&peer) {
            return false;
        }
        self.unknown_peer_reviews.insert(
            peer,
            UnknownPeerReview {
                requested_nickname,
                stage: UnknownPeerStage::Initial,
                proof,
                source_addr,
            },
        );
        self.unknown_peer_review_queue.push_back(peer);
        if self.unknown_peer_review_queue.front() == Some(&peer) {
            self.unknown_peer_review_focus = Confirm::No;
        }
        true
    }

    /// The review currently shown in the popup, if any.
    pub fn unknown_peer_review_open(&self) -> Option<&UnknownPeerReview> {
        let peer = self.unknown_peer_review_queue.front()?;
        self.unknown_peer_reviews.get(peer)
    }

    /// Moves a review from `Initial` to `ConfirmMatch` in place - same
    /// queue position, so it stays exactly where it was rather than being
    /// re-queued behind anything that arrived in the meantime.
    pub fn advance_to_confirm_match(
        &mut self,
        peer: UserId,
        matched_nickname: String,
        matched_key_der: Vec<u8>,
        recovered: RecoveredProof,
    ) {
        if let Some(review) = self.unknown_peer_reviews.get_mut(&peer) {
            review.stage = UnknownPeerStage::ConfirmMatch {
                matched_nickname,
                matched_key_der,
                recovered,
            };
            self.unknown_peer_review_focus = Confirm::No;
        }
    }

    /// Removes a review on every terminal outcome: declining either popup,
    /// confirming a match, or a completed scan finding nothing to offer.
    pub fn resolve_unknown_peer_review(&mut self, peer: UserId) {
        self.unknown_peer_reviews.remove(&peer);
        self.unknown_peer_review_queue.retain(|&p| p != peer);
    }

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

    /// Whether `peer`'s voice messages are muted (`/mute-voice`,
    /// docs/SPEC.md Functionality #15) - resolved through their *current*
    /// nickname, since that is what the user muted and what persists.
    /// A peer we hold no `UserInfo` for is never muted: there is no name
    /// to have matched.
    ///
    /// Paired with `is_trust_gated` at every incoming-audio decision:
    /// either being true means the stream is still decrypted and still
    /// logged, but never reaches the mixer.
    pub fn is_voice_muted(&self, peer: UserId) -> bool {
        self.known_users
            .get(&peer)
            .is_some_and(|u| self.muted_voice.contains(&u.name))
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
    /// mixer - the single predicate both reasons funnel through, so a
    /// caller can never remember one and forget the other. Snapshotted
    /// once per stream at `*Start` (docs/PROTOCOL.md §11.2), so a decision
    /// made when a stream opens holds for the whole of it.
    pub fn suppress_playback_from(&self, peer: UserId) -> bool {
        self.is_trust_gated(peer) || self.is_voice_muted(peer)
    }

    /// Replaces the muted-voice set - used once at session start to seed
    /// it from `~/.aloo/settings`.
    pub fn set_muted_voice(&mut self, muted: std::collections::BTreeSet<String>) {
        self.muted_voice = muted;
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
            self.identity_review_focus = Confirm::No;
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
        let autosave = self.autosave_messages.then(|| self.server_label.clone());
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
                            if let Some(server_label) = &autosave {
                                crate::client::export::autosave_entry(
                                    server_label,
                                    crate::client::export::Surface::Channel(&name),
                                    tab.log.last().unwrap(),
                                );
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
                                    key_mode: crate::proto::KeyMode::PqHybrid,
                                });
                        self.ensure_private_room(peer, fallback_peer);
                        let Some(room) = self.private_rooms.get_mut(&peer) else {
                            continue;
                        };
                        let peer_name = room.peer.name.clone();
                        push_log_entry(
                            &mut room.log,
                            &mut self.message_selected,
                            is_current,
                            entry,
                        );
                        if !is_current {
                            room.unread = true;
                        }
                        if let Some(server_label) = &autosave {
                            crate::client::export::autosave_entry(
                                server_label,
                                crate::client::export::Surface::Dm(&peer_name),
                                room.log.last().unwrap(),
                            );
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
        self.identity_review_focus = Confirm::No;
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

    /// Queues `invite` and, if nothing else is currently showing, makes it
    /// the one shown right away - mirrors `push_file_offer` exactly.
    pub fn push_call_invite(&mut self, invite: PendingCallInvite) -> bool {
        let key = invite.call_id;
        self.call_invites.insert(key, invite);
        self.call_invite_queue.push_back(key);
        let is_front = self.call_invite_queue.front() == Some(&key);
        if is_front {
            self.call_invite_focus = Confirm::Yes;
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
        self.call_invite_focus = Confirm::Yes;
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
            end_confirm: None,
        });
        self.sort_call_members();
    }

    /// Clears the modal, the header's `\u{23FA} Call Ctrl+R` indicator and the
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
                            && matches!(m.state, CallMemberState::InCall | CallMemberState::Invited)
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
        pubkey_der: Vec<u8>,
        purpose: crate::crypto::otp::OtpPurpose,
    ) {
        self.otp_generate_confirm = Some(PendingOtpGenerate {
            peer,
            peer_name,
            pubkey_der,
            purpose,
        });
        self.otp_generate_focus = Confirm::Yes;
    }

    pub fn take_otp_generate_confirm(&mut self) -> Option<PendingOtpGenerate> {
        self.otp_generate_focus = Confirm::Yes;
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

    /// Opens the generation spinner for `peer`'s pad, at 0 of
    /// `2 * size_mb` MB - called by `client::otp::confirm_generate` the
    /// moment it hands generation to its background task.
    pub fn open_otp_keygen(
        &mut self,
        peer: UserId,
        peer_name: String,
        size_mb: u32,
        purpose: crate::crypto::otp::OtpPurpose,
    ) {
        self.otp_keygen = Some(OtpKeygenProgress {
            phase: OtpPadPhase::Generating,
            peer,
            peer_name,
            purpose,
            size_mb,
            written_bytes: 0,
            total_bytes: size_mb as u64 * 1024 * 1024 * 2,
            frame: 0,
        });
    }

    /// Moves the spinner's bar - one `otp_keygen_tx` progress report. A
    /// no-op once the popup is closed (a late report arriving after the
    /// generation was already resolved), and equally once it has moved on
    /// to the transfer: generation reports are counted against a different
    /// total, so applying one there would rewind a bar that has genuinely
    /// advanced.
    pub fn set_otp_keygen_progress(&mut self, written_bytes: u64, total_bytes: u64) {
        if let Some(progress) = self.otp_keygen.as_mut()
            && progress.phase == OtpPadPhase::Generating
        {
            progress.written_bytes = written_bytes;
            progress.total_bytes = total_bytes;
        }
    }

    /// Switches the popup to the transfer phase, bar back to zero.
    ///
    /// Generating a pad and pushing it across a link are both slow, for
    /// unrelated reasons, and this is the moment between them. Without it
    /// the popup vanished the instant generation finished and the peer's
    /// invitation appeared minutes later with nothing in between - which
    /// read as the handshake having silently failed.
    ///
    /// `size_mb` is per key; the transfer is both halves, so the total is
    /// twice it (`otp_pad::spawn_send_pad_worker` sends enc then dec).
    pub fn begin_otp_pad_transfer(
        &mut self,
        peer: UserId,
        peer_name: String,
        size_mb: u32,
        phase: OtpPadPhase,
        purpose: crate::crypto::otp::OtpPurpose,
    ) {
        self.otp_keygen = Some(OtpKeygenProgress {
            phase,
            peer,
            peer_name,
            purpose,
            size_mb,
            written_bytes: 0,
            total_bytes: size_mb as u64 * 1024 * 1024 * 2,
            frame: 0,
        });
    }

    /// Closes the spinner - generation finished, failed, or was abandoned.
    pub fn close_otp_keygen(&mut self) {
        self.otp_keygen = None;
    }

    /// Closes it only if it is reporting on `peer` - so a stale transfer
    /// ending cannot tear down a popup that has since moved on to another
    /// contact.
    pub fn close_otp_keygen_for(&mut self, peer: UserId) {
        if self.otp_keygen.as_ref().is_some_and(|p| p.peer == peer) {
            self.otp_keygen = None;
        }
    }

    /// Moves the transfer bar, if the popup is still reporting on `peer`.
    pub fn set_otp_pad_transfer_progress(&mut self, peer: UserId, sent_bytes: u64) {
        if let Some(progress) = self.otp_keygen.as_mut()
            && progress.peer == peer
            && progress.phase != OtpPadPhase::Generating
        {
            progress.written_bytes = sent_bytes.min(progress.total_bytes);
        }
    }

    pub fn otp_keygen_open(&self) -> Option<&OtpKeygenProgress> {
        self.otp_keygen.as_ref()
    }

    /// Advances the spinner one frame - driven by the session ticker, the
    /// same cadence `toggle_blink` rides, so the animation keeps moving
    /// even while no progress report has arrived (which is exactly when a
    /// user most needs to see it is still alive).
    pub fn tick_otp_keygen_spinner(&mut self) {
        if let Some(progress) = self.otp_keygen.as_mut() {
            progress.frame = (progress.frame + 1) % SPINNER_FRAMES.len();
        }
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
            self.otp_invite_focus = Confirm::Yes;
        }
    }

    pub fn otp_invite_open(&self) -> Option<&PendingOtpInvite> {
        let from = self.otp_invite_queue.front()?;
        self.otp_invites.get(from)
    }

    pub fn take_otp_invite(&mut self) -> Option<PendingOtpInvite> {
        let from = self.otp_invite_queue.pop_front()?;
        self.otp_invite_focus = Confirm::Yes;
        self.otp_invites.remove(&from)
    }

    /// Drops one specific peer's unanswered invitation, wherever it sits in
    /// the queue - unlike `take_otp_invite`, which only ever takes the one
    /// currently showing.
    ///
    /// Used when a fresh `/otp` to that same peer supersedes it
    /// (`client::otp::handle_otp_command`): answering their proposal and
    /// making our own at once would leave two live proposals for one
    /// contact name. Returns whether there was anything to drop. The
    /// returned invite is dropped here rather than handed back, so its key
    /// material is zeroized immediately (`PendingOtpInvite` is
    /// `ZeroizeOnDrop`).
    pub fn take_otp_invite_from(&mut self, from: UserId) -> bool {
        self.otp_invite_queue.retain(|queued| *queued != from);
        if self.otp_invites.remove(&from).is_some() {
            self.otp_invite_focus = Confirm::Yes;
            return true;
        }
        false
    }

    /// Whether `from` has an invite queued at all, at any position - not
    /// just the one on top (`otp_invite_open`). Used to refuse starting a
    /// second provisioning handshake (of either purpose) with a peer who
    /// already has one outstanding.
    pub fn has_otp_invite_from(&self, from: UserId) -> bool {
        self.otp_invites.contains_key(&from)
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
    /// `peer` - see `otp_active_peers`'s doc. Also (re-)called, idempotently,
    /// the moment a peer we already have a provisioned OTP contact for
    /// reconnects under a fresh `UserId` (`session::handle_server_message`'s
    /// `UserJoined` arm) - this per-connection flag would otherwise forget
    /// an otherwise still-active session across every reconnect, which is
    /// exactly what `/endotp` (and nothing else) is supposed to end.
    pub fn mark_otp_active(&mut self, peer: UserId) {
        self.otp_active_peers.insert(peer);
    }

    /// The reverse of `mark_otp_active` - `/endotp` ending the session, on
    /// either side (`client::otp::handle_end_otp_command`/`on_end_session`).
    /// Also drops any stale key-metadata snapshot (`otp_key_status`) for
    /// this peer, so a session started fresh with them afterward shows only
    /// its own figures, never a leftover reading from the one just ended.
    pub fn clear_otp_active(&mut self, peer: UserId) {
        self.otp_active_peers.remove(&peer);
        self.otp_key_status.remove(&peer);
    }

    /// Whether `peer`'s messages should carry the `OTP_ICON` prefix right
    /// now.
    pub fn is_otp_active(&self, peer: UserId) -> bool {
        self.otp_active_peers.contains(&peer)
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

    /// Moves everything this session holds about `previous` onto the id
    /// `user` has now, so a peer who reconnects continues in the very same
    /// DM room rather than opening a second one beside it
    /// (`docs/SPEC.md` "Connected UI").
    ///
    /// Only what is genuinely *about the person* moves: their room and its
    /// history, where it sits on the DM selector, and any one-time-pad
    /// session, which by design outlives a disconnect and only `/endotp`
    /// ever ends (`docs/PROTOCOL.md` §16.6). Everything that belongs to the
    /// connection that just closed - an unanswered identity review, held
    /// messages, a file offer or call invite in flight - is deliberately
    /// left behind: those are transactions with a session that is over,
    /// and the new connection gets its own, including its own identity
    /// check.
    pub(crate) fn adopt_returning_peer(&mut self, previous: UserId, user: &UserInfo) {
        let id = user.id;
        self.offline.remove(&previous);
        self.link_status.remove(&previous);
        self.known_users.remove(&previous);
        if let Some(mut room) = self.private_rooms.remove(&previous) {
            // The room keeps its whole log; only who it is *with* is
            // restated, since their key material and id are both new.
            room.peer = user.clone();
            self.private_rooms.insert(id, room);
        }
        for entry in &mut self.dm_order {
            if *entry == previous {
                *entry = id;
            }
        }
        if self.selected_dm == Some(previous) {
            self.selected_dm = Some(id);
        }
        if self.active_private_room == Some(previous) {
            self.active_private_room = Some(id);
        }
        if self.otp_active_peers.remove(&previous) {
            self.otp_active_peers.insert(id);
        }
        if let Some(status) = self.otp_key_status.remove(&previous) {
            self.otp_key_status.insert(id, status);
        }
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

    /// Records `peer`'s latest `otp --show-contact` snapshot - see
    /// `otp_key_status`'s doc for who calls this and how often.
    pub fn set_otp_key_status(
        &mut self,
        peer: UserId,
        status: crate::client::otp_cli::OtpKeyStatus,
    ) {
        self.otp_key_status.insert(peer, status);
    }

    /// `peer`'s most recently fetched key-metadata snapshot, if any -
    /// `render_otp_header` falls back to `OtpKeyStatus::default()` (all
    /// zeros) when `None`, e.g. the brief window before a session's own
    /// first fetch completes.
    pub fn otp_key_status_for(
        &self,
        peer: UserId,
    ) -> Option<&crate::client::otp_cli::OtpKeyStatus> {
        self.otp_key_status.get(&peer)
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
            .channels
            .iter()
            .find(|c| c.name == channel)
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

    /// The help overlay's current scroll offset (first visible line index
    /// into the overlay's laid-out lines) - loosely clamped here, precisely at render time
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
        // A live account deactivation outranks everything, including an
        // outstanding identity review: the account is locked out right
        // now, so nothing else this session could still do matters.
        // Absorbs every key but Escape, which ends the whole session (no
        // `UiAction` can express a loop-level exit, so this is answered
        // directly by `session::run_connected_session`'s own input arm,
        // the same way `Detach` already is).
        if self.account_deactivated.is_some() {
            return match (kind, code) {
                (KeyEventKind::Press | KeyEventKind::Repeat, KeyCode::Esc) => Some(UiAction::Quit),
                _ => None,
            };
        }

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
                        self.identity_review_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.identity_review_focus {
                        Confirm::Yes => Some(UiAction::AcceptIdentity(peer)),
                        Confirm::No => Some(UiAction::RejectIdentity(peer)),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // An outstanding unknown-direct-peer review is next: still an
        // absorb-everything decision (docs/PROTOCOL.md §7.1.5), but a
        // genuine identity-mismatch warning above still wins if both are
        // somehow open at once, since impersonation outranks a peer this
        // side has simply never met yet.
        if let Some(&peer) = self.unknown_peer_review_queue.front() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.unknown_peer_review_focus.toggle();
                        None
                    }
                    KeyCode::Enter => {
                        let stage = self.unknown_peer_reviews.get(&peer).map(|r| &r.stage);
                        match (stage, self.unknown_peer_review_focus) {
                            (Some(UnknownPeerStage::Initial), Confirm::Yes) => {
                                Some(UiAction::CheckUnknownPeerIdentity(peer))
                            }
                            (Some(UnknownPeerStage::Initial), Confirm::No) => {
                                Some(UiAction::DeclineUnknownPeerIdentity(peer))
                            }
                            (Some(UnknownPeerStage::ConfirmMatch { .. }), Confirm::Yes) => {
                                Some(UiAction::ConfirmUnknownPeerKey(peer))
                            }
                            (Some(UnknownPeerStage::ConfirmMatch { .. }), Confirm::No) => {
                                Some(UiAction::DeclineUnknownPeerKey(peer))
                            }
                            (None, _) => None,
                        }
                    }
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
                        self.otp_invite_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.otp_invite_focus {
                        Confirm::Yes => Some(UiAction::AcceptOtpInvite),
                        Confirm::No => Some(UiAction::RejectOtpInvite),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // Generation actually running - the step after the size prompt
        // below. Absorbs every key without acting on any: there is nothing
        // to decide here, and no cancel either, because the pad is already
        // being written to disk by a real subprocess (abandoning it
        // half-written is exactly the stale-half-pad state
        // `stage_pending_setup` exists to avoid). It closes itself when the
        // generation reports back.
        // Generation and transfer are both long enough to be regretted -
        // minutes, and gigabytes of disk - so Escape has to reach them.
        // Everything else is still absorbed: there is nothing else to
        // decide while one is running.
        if let Some(progress) = self.otp_keygen.as_ref() {
            return match (kind, code) {
                (KeyEventKind::Press | KeyEventKind::Repeat, KeyCode::Esc) => {
                    Some(UiAction::CancelOtpPad {
                        peer: progress.peer,
                    })
                }
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
                    // 7 digits covers the max (1048576 - 1TB per key) with no
                    // room for a typo'd extra digit to even be entered.
                    KeyCode::Char(c) if c.is_ascii_digit() && self.otp_size_text.len() < 7 => {
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
                        self.otp_generate_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.otp_generate_focus {
                        Confirm::Yes => {
                            // Confirming only decides "yes, generate one" -
                            // the size prompt above is the next step, not
                            // an immediate `ConfirmOtpGenerate`.
                            let pending = self
                                .take_otp_generate_confirm()
                                .expect("otp_generate_confirm.is_some() was just checked");
                            self.open_otp_size_input(pending);
                            None
                        }
                        Confirm::No => Some(UiAction::CancelOtpGenerate),
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
                        self.file_offer_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.file_offer_focus {
                        Confirm::Yes => {
                            Some(UiAction::AcceptFileOffer { from, stream_id })
                        }
                        Confirm::No => {
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
                        self.call_invite_focus.toggle();
                        None
                    }
                    KeyCode::Enter => match self.call_invite_focus {
                        Confirm::Yes => self.accept_call_invite(call_id),
                        Confirm::No => Some(UiAction::RejectCallInvite { call_id }),
                    },
                    _ => None,
                },
                _ => None,
            };
        }

        // `/delete-channel`/`/assign-admin`'s confirmation - same tier and
        // shape as `/call`'s just below, reusing `Confirm`.
        if self.channel_command_confirm.is_some() {
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                        self.channel_command_confirm_focus.toggle();
                        None
                    }
                    KeyCode::Esc => {
                        self.channel_command_confirm = None;
                        None
                    }
                    KeyCode::Enter => {
                        let pending = self.channel_command_confirm.take()?;
                        match self.channel_command_confirm_focus {
                            Confirm::Yes => Some(match pending.action {
                                ChannelCommandConfirmAction::DeleteChannel { name } => {
                                    UiAction::DeleteChannel { name }
                                }
                                ChannelCommandConfirmAction::AssignAdmin { channel, nickname } => {
                                    UiAction::AssignChannelAdmin { channel, nickname }
                                }
                            }),
                            Confirm::No => None,
                        }
                    }
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
                        self.call_confirm_focus.toggle();
                        None
                    }
                    KeyCode::Esc => {
                        self.call_confirm = None;
                        None
                    }
                    KeyCode::Enter => {
                        let pending = self.call_confirm.take()?;
                        match self.call_confirm_focus {
                            Confirm::Yes => Some(UiAction::StartCall(pending.target)),
                            Confirm::No => None,
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

        // The message info popup owns every key while it is open
        // (`docs/SPEC.md` "Delivery acknowledgments"): Esc and `i` close
        // it, everything else is absorbed. Above Ctrl+H so it is a real
        // popup rather than something the help overlay can be stacked on
        // top of, and below the consent popups above, which must always
        // stay answerable.
        if self.message_info.is_some() {
            if kind == KeyEventKind::Press
                && matches!(code, KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('I'))
            {
                self.message_info = None;
            }
            return None;
        }

        // The `.txt` preview popup - same "absorb everything, Esc closes
        // it" tier as message-info above, plus scrolling and `d` to save
        // (identical effect to any other file transfer's default save;
        // `session::handle_ui_action` does the actual move + receipt,
        // since `UiState` has no disk/network access). Closes itself on
        // `d` rather than waiting for a round trip - the save is a local
        // move, not something that can meaningfully fail from here.
        if let Some(preview) = self.file_preview.as_ref() {
            let (from, stream_id) = (preview.from, preview.stream_id);
            return match kind {
                KeyEventKind::Press | KeyEventKind::Repeat => match code {
                    KeyCode::Esc => {
                        self.file_preview = None;
                        None
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') => {
                        self.file_preview = None;
                        Some(UiAction::SaveStagedFile { from, stream_id })
                    }
                    KeyCode::Up => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll = preview.scroll.saturating_sub(1);
                        }
                        None
                    }
                    KeyCode::Down => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll += 1;
                        }
                        None
                    }
                    KeyCode::PageUp => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll = preview.scroll.saturating_sub(HELP_SCROLL_PAGE);
                        }
                        None
                    }
                    KeyCode::PageDown => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll += HELP_SCROLL_PAGE;
                        }
                        None
                    }
                    KeyCode::Home => {
                        if let Some(preview) = self.file_preview.as_mut() {
                            preview.scroll = 0;
                        }
                        None
                    }
                    _ => None,
                },
                _ => None,
            };
        }

        // The user-info popup (`i`/`/info`) is the same "absorb every key,
        // Esc or `i` closes it" tier as message-info above.
        if self.user_info.is_some() {
            if kind == KeyEventKind::Press
                && matches!(code, KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('I'))
            {
                self.user_info = None;
            }
            return None;
        }

        // The superadmin `/users` popup - same tier, but Esc-only, since
        // there is no single letter shortcut that opened it the way `i`
        // did above.
        if self.users_admin.is_some() {
            if kind == KeyEventKind::Press && code == KeyCode::Esc {
                self.users_admin = None;
            }
            return None;
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
            // The bound the overlay can ever reach at any width - the
            // exact one for this frame is applied when it renders (see
            // `help_total_lines`).
            let max_scroll = help_total_lines().saturating_sub(1);
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
        if self.mode == Mode::Contacts {
            return self.handle_contacts_key(code);
        }
        if self.mode == Mode::DirectPunches {
            return self.handle_direct_punches_key(code);
        }
        if self.mode == Mode::ChannelLockPopup {
            return self.handle_channel_lock_popup_key(code);
        }
        if self.mode == Mode::ExportPopup {
            return self.handle_export_popup_key(code);
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
                // `\u{23FA} Call Ctrl+R` indicator is what advertises it
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
                    // With no server there is nothing to create and no
                    // directory to search, so the free-text form would only
                    // ever be a way to type a name that cannot work. The
                    // configured channels are the only ones that exist, so
                    // this shows exactly those - the same modal `/channels`
                    // uses, over the same list.
                    if self.serverless {
                        self.mode = Mode::ChannelsPopup;
                        self.channels_popup_selected = 0;
                        return None;
                    }
                    self.mode = Mode::JoinPrivatePopup;
                    self.join_popup_input.clear();
                    self.join_popup_kind = ChannelKind::Private;
                    self.join_popup_password.clear();
                    self.join_popup_focus = JoinPopupFocus::Name;
                    return None;
                }
                // Opens the first not-yet-opened http(s) link in the
                // focused message (`message_selected`) in the OS default
                // browser; pressing it again cycles to that same
                // message's next link before starting over.
                KeyCode::Char('o') | KeyCode::Char('O') => {
                    return self.next_url_in_focused_message().map(UiAction::OpenUrl);
                }
                // Opens the "Direct Punches" popup - only worth reaching
                // for once direct punching is at least worth looking at,
                // but the popup itself (`open_direct_punches`) is where
                // adding the very first one from scratch happens too, so
                // it's never gated on any already being configured.
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.open_direct_punches();
                    return Some(UiAction::OpenDirectPunches);
                }
                // Opens the export popup - checkbox-pick any joined
                // channel or open DM, Confirm to dump each one's current
                // log to `~/.aloo/exports/<server>/...`
                // (`client::export::export_log`). Purely local, so unlike
                // `Ctrl+S` this never needs a `UiAction` just to populate
                // itself.
                KeyCode::Char('e') | KeyCode::Char('E') => {
                    self.open_export_popup();
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
    /// header's `\u{23FA} Call Ctrl+R` indicator (which is what brings it back).
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
        // Answered before anything else the modal does, the same tier its
        // invite picker sits at: nothing about the call changes while
        // either is open.
        if self.call.as_ref()?.end_confirm.is_some() {
            return self.handle_end_call_confirm_key(code);
        }
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
            // END CALL asks first (see `CallUiState::end_confirm`); the
            // answer is what actually leaves.
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => {
                self.call.as_mut()?.end_confirm = Some(Confirm::No);
                None
            }
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

    /// END CALL's confirmation, while it is open over the modal:
    /// Left/Right/Tab move between the two buttons, Enter answers, Escape
    /// is the same as answering Cancel. Nothing else reaches the modal
    /// underneath, so no roster key can be mistaken for an answer.
    fn handle_end_call_confirm_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let call = self.call.as_mut()?;
        let focus = call.end_confirm?;
        match code {
            KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                call.end_confirm = Some(focus.toggled());
                None
            }
            KeyCode::Esc => {
                call.end_confirm = None;
                None
            }
            KeyCode::Enter => {
                call.end_confirm = None;
                match focus {
                    Confirm::Yes => Some(UiAction::EndCall),
                    Confirm::No => None,
                }
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
                    label: channel_label(c.kind, &c.name),
                    unread: c.unread,
                    otp: false,
                    presence: None,
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
                    otp: self.is_otp_active(room.peer.id),
                    presence: Some(self.presence_of(room.peer.id)),
                })
                .collect(),
        }
    }

    /// Which dropdown row the list has to keep on screen when it holds
    /// more entries than fit (`render_selector_dropdown`).
    ///
    /// The dropdown lists everything *except* the current selection, so
    /// there is no selected row in it to follow. What there is instead is
    /// the *gap* the selection left: the number of entries ahead of it in
    /// the selector's own order. Keeping that position in view is what
    /// makes Up/Down walk a long list continuously - the row stepped onto
    /// leaves the list and the one stepped off rejoins it right there, so
    /// the neighbourhood of the gap is exactly where the movement is
    /// visible.
    pub fn selector_dropdown_focus_row(&self) -> usize {
        let entries = self.selector_dropdown_entries().len();
        let gap = match self.selector_focus {
            SelectorFocus::Channels => self.selected_channel,
            SelectorFocus::Dms => self
                .selected_dm
                .and_then(|id| self.dm_order.iter().position(|d| *d == id))
                .unwrap_or(0),
        };
        gap.min(entries.saturating_sub(1))
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
        // Reading back history is the one thing the compose bar hands
        // straight to the log: focus starts here and stays here while
        // typing, so requiring a Tab round-trip to scroll would leave the
        // history effectively unreachable in normal use. None of these keys
        // mean anything to a single-line, append-only compose buffer.
        // Deliberately ahead of the guards below - a log stays readable
        // even in a room that can no longer be typed in.
        if matches!(
            code,
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown
        ) {
            return self.handle_messages_key(code);
        }
        // A Pending/Rejected identity (docs/PROTOCOL.md §12) blocks typing
        // outright - normal navigation can no longer even open this room,
        // but a room already open before the mismatch arrived must stop
        // accepting input too. An offline DM peer, by contrast, no longer
        // blocks typing here: `/endotp` must still be composable and
        // submitted for a peer who isn't currently reachable (ending a
        // session must not require them to be reachable - see
        // `client::otp`'s module doc), so `submit_input` itself is what
        // refuses every *other* command/plain send to an offline peer, with
        // `/endotp` the one deliberate exception. `render_input_bar` shows
        // whatever's actually typed once it's non-empty, offline or not.
        if self.active_dm_peer_trust_gated() {
            return None;
        }
        match code {
            KeyCode::Backspace => {
                self.input.pop();
                None
            }
            KeyCode::Char(c) => {
                // `proto::TEXT_MESSAGE_MAX_LEN` - same per-keystroke cap
                // shape as `ui_connect_popup`'s nickname field. A paste
                // long enough to matter here is always diverted to a file
                // first (`handle_paste`), so this only ever bites manually
                // typed text.
                if self.input.chars().count() < crate::proto::TEXT_MESSAGE_MAX_LEN {
                    self.input.push(c);
                }
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
        if self.input.trim() == "/endotp" {
            // Ending is a synchronised, two-party operation now
            // (docs/PROTOCOL.md §16.6): it takes effect only when the
            // peer's proof-carrying acknowledgement comes back, so both
            // sides leave the session together. A peer who is offline
            // cannot confirm anything, so this is refused out loud rather
            // than silently swallowed like other DM actions - the user
            // asked for something specific and deserves to know why it
            // didn't happen. Still a no-op for a trust-gated peer
            // (docs/PROTOCOL.md §12), same as every other DM action.
            let peer_id = self.active_private_room?;
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            // Checked against the direct link too, not only
            // `active_dm_peer_offline` (`ui_state.offline`, gated behind the
            // server's `HEARTBEAT_TIMEOUT`) - the same race
            // `handle_end_otp_command`'s authoritative guard closes further,
            // narrowed here as well so the refusal is immediate rather than
            // a round trip through session handling.
            if self.active_dm_peer_offline() || self.link_status_of(peer_id) != LinkStatus::Active
            {
                self.input.clear();
                self.push_status_notice(
                    format!(
                        "OTP: {} is offline - /endotp needs both sides online so the end \
                         is confirmed on both; try again when they are back",
                        peer.name
                    ),
                    false,
                );
                return None;
            }
            self.input.clear();
            return Some(UiAction::EndOtpSession {
                peer: peer_id,
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/info" {
            // Read-only and purely local (`id_store`/keychain), so - like
            // `/endotp` above - never gated on the peer being reachable:
            // there is nothing here that needs them online, and it works
            // even for a trust-gated peer, same reasoning as `i` in the
            // sidebar.
            let Some(peer_id) = self.active_private_room else {
                return None;
            };
            let Some(peer) = self.known_users.get(&peer_id).cloned() else {
                return None;
            };
            self.input.clear();
            self.open_user_info(peer_id, peer.name.clone(), None);
            return Some(UiAction::RequestUserInfo { peer: peer_id, nickname: peer.name });
        }
        // Everything below requires the open DM's peer (if any) to actually
        // be reachable - `/endotp` above is the one deliberate exception.
        // `active_dm_peer_offline` is `false` whenever no DM room is open at
        // all, so this never touches a channel send.
        if self.active_dm_peer_offline() || self.active_dm_peer_trust_gated() {
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
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/new-otp-mail-key" {
            // The one way to provision OTP mail's own key, independent of
            // any live `/otp` session with the same person - same
            // provisioning mechanics as `/otp` just above, same guards.
            let peer_id = self.active_private_room?;
            if self.is_trust_gated(peer_id) {
                return None;
            }
            let peer = self.known_users.get(&peer_id)?.clone();
            self.input.clear();
            return Some(UiAction::RequestOtpMailKey {
                peer: peer_id,
                pubkey_der: peer.public_key_der,
            });
        }
        if self.input.trim() == "/mail" {
            // The one way to compose an OTP mail (docs/PROTOCOL.md §17.1) -
            // a command rather than a key chord, since the natural chord
            // (Ctrl+M) is indistinguishable from Enter on terminals
            // without the kitty keyboard protocol (both are 0x0D). Routed
            // through the session rather than opening the compose view
            // directly - only it can check the local `otp` binary is
            // actually available (`client::otp_mail::handle_open_otp_mail`),
            // which `UiState` has no way to do for itself.
            self.input.clear();
            return Some(UiAction::RequestOpenOtpMail);
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
        if self.input.trim() == "/clear" {
            // Wipes the log of whichever screen is open right now - not
            // just what's on screen, the `Vec<LogEntry>` backing it, so a
            // scrollback of anything cleared this way is genuinely gone,
            // not merely scrolled past.
            self.input.clear();
            if let Some(log) = self.current_log_mut() {
                log.clear();
            }
            self.message_selected = 0;
            self.message_info = None;
            self.push_status_notice("cleared this screen's messages".to_string(), true);
            return None;
        }
        if self.input.trim() == "/clear-all" {
            // Same as `/clear`, but for every channel tab and every DM
            // room at once - not just the one currently open.
            self.input.clear();
            for channel in self.channels.iter_mut() {
                channel.log.clear();
            }
            for room in self.private_rooms.values_mut() {
                room.log.clear();
            }
            self.message_selected = 0;
            self.message_info = None;
            self.push_status_notice("cleared every screen's messages".to_string(), true);
            return None;
        }
        if self.input.trim() == "/contacts" {
            // The one way to see every pinned identity (`idstore.rs`) -
            // unlike `/otp`/`/file`/`/endotp` above, this is never scoped
            // to an open DM room: a contacts list is precisely the roster
            // of people the app knows about *without* requiring one to be
            // reachable, or even a room to be open, right now.
            self.input.clear();
            self.open_contacts();
            return Some(UiAction::OpenContacts);
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
        if self.input.trim() == "/delete-channel" {
            // Always the currently selected channel, same "no argument"
            // convention `/leave` uses - and the same confirmation tier
            // `/call` uses just below, since deleting a channel is
            // destructive and not one Enter away.
            let channel = self.channels.get(self.selected_channel)?;
            let name = channel.name.clone();
            self.input.clear();
            self.channel_command_confirm = Some(ChannelCommandConfirm {
                title: "Delete channel?",
                question: format!("Delete #{name}? This cannot be undone."),
                action: ChannelCommandConfirmAction::DeleteChannel { name },
            });
            self.channel_command_confirm_focus = Confirm::No;
            return None;
        }
        if self.input.trim() == "/lock-joins" {
            // Purely local to open (see `channel_lock_popup`'s module
            // doc) - prefilled with the channel's current members, per
            // the spec's own "by default the current users joined should
            // be included".
            let channel = self.channels.get(self.selected_channel)?;
            let name = channel.name.clone();
            let members: Vec<String> = channel.members.iter().map(|m| m.name.clone()).collect();
            self.input.clear();
            self.open_channel_lock_popup(name, members);
            return None;
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
            self.call_confirm_focus = Confirm::Yes;
            return None;
        }
        if self.input.trim() == "/daemon" {
            self.input.clear();
            if !self.daemon_mode {
                self.push_status_notice(
                    "not running as a daemon - start one with: aloo --daemon".to_string(),
                    false,
                );
                return None;
            }
            return Some(UiAction::Detach);
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
        // The first commands in this app that take an argument - every
        // other one above matches on whole-string equality, and `/leave`
        // makes a point of taking none. Both must be handled before the
        // unknown-command catch-all below, or they'd be swallowed as
        // typos of a real command.
        if let Some(action) = self.try_voice_mute_command() {
            return action;
        }
        if let Some(action) = self.try_channel_moderation_command() {
            return action;
        }
        if let Some(action) = self.try_superadmin_command() {
            return action;
        }
        if let Some(action) = self.try_password_command() {
            return action;
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
        // Checked *before* taking `input` - a send that can't actually go
        // through (channel not joined, DM peer unknown) must leave the
        // typed text in place rather than silently discarding it (AC-026),
        // and `submit_text` itself can't tell the difference between "not
        // sent because unaddressable" and "not sent for some other reason"
        // from the outside.
        if !self.can_submit_text() {
            return None;
        }
        let text = std::mem::take(&mut self.input);
        self.submit_text(text)
    }

    /// Whether `submit_text` would actually produce a send right now -
    /// `submit_input`'s guard for AC-026 (see its call site). Mirrors the
    /// addressability checks `submit_text` makes internally; kept as its
    /// own read-only check because `submit_input` needs the answer before
    /// it decides whether to touch `input` at all, and `handle_paste` has
    /// no equivalent "must preserve unsent text" concern (a paste that
    /// can't be sent was never staged anywhere to lose).
    fn can_submit_text(&self) -> bool {
        if let Some(peer_id) = self.active_private_room {
            !self.is_trust_gated(peer_id) && self.known_users.contains_key(&peer_id)
        } else {
            self.channels
                .get(self.selected_channel)
                .is_some_and(|c| c.joined)
        }
    }

    /// Shared tail of `submit_input`: send `text` verbatim to whichever
    /// room is open (the active DM peer, or the selected channel tab if
    /// none is). Split out so `handle_paste` can reach the exact same send
    /// path for a full paste's content without going through the
    /// single-line `input` buffer at all - a paste already arrives as one
    /// atomic string, embedded newlines included, so there is nothing to
    /// stage there first.
    fn submit_text(&mut self, text: String) -> Option<UiAction> {
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
            // Allocated here, before the row exists, because the row and
            // the send have to agree on it: it is both this row's identity
            // and the tag the wire frame carries (`docs/PROTOCOL.md` 7.2.1).
            let (msg_id, delivery) = self.start_delivery(&[peer_id]);
            let log_index =
                self.push_outgoing_dm(peer_id, MessageBody::Text(text.clone()), Some(delivery));
            let action = UiAction::SendDirectText {
                to: peer_id,
                plaintext: text,
                recipient_pubkey_der: peer.public_key_der,
                log_index,
                msg_id,
            };
            Some(action)
        } else {
            let channel = self.channels.get(self.selected_channel)?;
            if !channel.joined {
                return None;
            }
            let name = channel.name.clone();
            let recipients = self.recipients_for_channel(channel);
            let recipient_ids: Vec<UserId> = recipients.iter().map(|(id, ..)| *id).collect();
            let (msg_id, delivery) = self.start_delivery(&recipient_ids);
            let action = UiAction::SendChannelText {
                channel: name.clone(),
                plaintext: text.clone(),
                recipients,
                msg_id,
            };
            self.push_outgoing_channel(&name, MessageBody::Text(text), Some(delivery));
            Some(action)
        }
    }

    /// The set of states `handle_key` checks, in priority order, before it
    /// ever reaches the ordinary compose bar (`handle_input_key`) - reused
    /// by `handle_paste` to route a paste through `handle_key` itself
    /// (into whichever field one of these is actually offering, if any)
    /// rather than misreading it as a message send while one of these is
    /// absorbing every key instead (an open identity review, an invite, a
    /// popup, the help screen, ...).
    fn overlay_absorbing_input(&self) -> bool {
        self.identity_review_queue.front().is_some()
            || self.unknown_peer_review_queue.front().is_some()
            || self.otp_invite_queue.front().is_some()
            || self.otp_keygen.is_some()
            || self.otp_size_input.is_some()
            || self.otp_generate_confirm.is_some()
            || self.file_offer_queue.front().is_some()
            || self.call_invite_queue.front().is_some()
            || self.call_confirm.is_some()
            || self.call_modal_showing()
            || self.message_info.is_some()
            || self.file_preview.is_some()
            || self.user_info.is_some()
            || self.users_admin.is_some()
            || self.help_open
            || self.otp_mail.is_some()
            || self.mode != Mode::Normal
            || self.selector_dropdown_open
    }

    /// A whole paste (`Event::Paste`, delivered atomically by a
    /// bracketed-paste-enabled terminal - `tui::terminal::setup` - with any
    /// embedded newlines intact). While some overlay (a popup, `/mail`, a
    /// decision queue, any non-`Normal` mode) is in front of the compose
    /// bar, it is instead forwarded character-by-character through
    /// `handle_key` - see `overlay_absorbing_input`'s doc. Reaching the
    /// ordinary compose bar itself, two thresholds apply, in order:
    ///
    /// - Longer than `client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD`:
    ///   converted to a `.txt` file and sent as a file transfer instead of
    ///   a message - the same "this is clearly a document, not a chat
    ///   line" judgment call, just made automatically rather than asking.
    /// - Otherwise: sent immediately as a single message, newlines and
    ///   all, rather than staged in the single-line `input` buffer (which
    ///   has no way to hold or display one) for a manual Enter.
    ///
    /// Reaching the compose bar, a no-op for a peer this side currently
    /// can't send to, same as an ordinary keystroke would be.
    pub fn handle_paste(&mut self, text: String) -> Option<UiAction> {
        if text.is_empty() {
            return None;
        }
        // Something other than the plain compose bar owns every keystroke
        // right now - a popup, `/mail`, any non-`Normal` mode, or one of
        // the decision overlays `handle_key` absorbs everything for. Fed
        // through the very same per-character path a real keystroke takes
        // (`handle_key`, one `KeyCode::Char` per pasted character), so it
        // lands in whichever field currently has focus with that field's
        // own validation applied - a digits-only port field still refuses
        // non-digits, for instance - exactly as if it had been typed one
        // key at a time. Harmless for a decision overlay with no text
        // field at all (an identity review, an invite, ...): those match
        // only specific non-`Char` `KeyCode`s (`Left`/`Enter`/...), so an
        // arbitrary pasted character never has anything to accidentally
        // trigger there. Only the last of possibly several actions
        // produced along the way is returned, matching `handle_key`'s own
        // one-event-one-action shape and the "final state wins" semantics
        // already correct for a field that re-validates on every
        // keystroke (e.g. the mail compose `To` field's recipient check).
        if self.overlay_absorbing_input() {
            let mut action = None;
            for c in text.chars().filter(|c| *c != '\r') {
                if let Some(a) = self.handle_key(KeyCode::Char(c), KeyModifiers::NONE, KeyEventKind::Press) {
                    action = Some(a);
                }
            }
            return action;
        }
        if self.focus != Focus::Input {
            return None;
        }
        if self.active_dm_peer_offline() || self.active_dm_peer_trust_gated() {
            return None;
        }
        // Bracketed paste's line endings are not reliably `\n`: many
        // terminals (tmux's own `paste-buffer -p` included) send a lone
        // `\r` for each embedded line break, since that is historically
        // what "pressing Enter" sends. Everything downstream - the
        // message-log renderer splitting into one row per line, a
        // receiving peer's own renderer, a `.txt` file's line endings -
        // only ever recognizes `\n`, so it is normalized exactly once,
        // here at the paste boundary, rather than every consumer having
        // to know about `\r` too.
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        if text.chars().count() > crate::client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD {
            let target = self.current_file_send_target()?;
            let path = crate::client::file_transfer::write_pasted_text_file(&text).ok()?;
            return self.confirm_pasted_file_send(target, path);
        }
        // Never actually trims anything in practice - anything this long
        // was already diverted to a file above, since
        // `PASTE_TO_FILE_CHAR_THRESHOLD` is well under `TEXT_MESSAGE_MAX_LEN`
        // - kept as a defensive second enforcement point rather than
        // relying on the ordering above never changing silently.
        let capped: String = text
            .chars()
            .take(crate::proto::TEXT_MESSAGE_MAX_LEN)
            .collect();
        self.submit_text(capped)
    }

    /// A left click, hit-tested against wherever the input bar and (while
    /// actually viewing a channel) the member sidebar were last drawn
    /// (`render_input_bar`/`render_sidebar`, via `last_input_bar_area`/
    /// `last_sidebar_area`) - clicking either moves focus there, and a
    /// sidebar click also selects whichever member row it landed on, the
    /// same one line per member every row already is. A no-op while some
    /// overlay is in front of the view (a popup, `/mail`, an open decision
    /// queue, ...) - clicking through it to whatever it's covering would
    /// be indistinguishable from actually answering it - or while viewing
    /// a DM (`render_private_room` draws no sidebar, so the stored area is
    /// stale, left over from the channel view).
    ///
    /// Right clicks, scrolling, and drags do nothing yet - this covers the
    /// two targets a click most obviously means "go here", not every
    /// clickable thing in the app.
    pub fn handle_mouse(&mut self, event: MouseEvent) -> Option<UiAction> {
        if !matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
            return None;
        }
        if self.overlay_absorbing_input() {
            return None;
        }
        let (x, y) = (event.column, event.row);
        let input_area = unpack_rect(self.last_input_bar_area.load(Ordering::Relaxed));
        if rect_contains(input_area, x, y) {
            self.focus = Focus::Input;
            return None;
        }
        if self.active_private_room.is_none() {
            let sidebar_area = unpack_rect(self.last_sidebar_area.load(Ordering::Relaxed));
            if rect_contains(sidebar_area, x, y) {
                let member_count = self
                    .channels
                    .get(self.selected_channel)
                    .map(|c| c.members.len())
                    .unwrap_or(0);
                let clicked_row = y.saturating_sub(sidebar_area.y) as usize;
                if clicked_row < member_count {
                    self.focus = Focus::Sidebar;
                    self.sidebar_selected = clicked_row;
                }
            }
        }
        None
    }

    /// Handles `/mute-voice [nickname]` and `/unmute-voice [nickname]`
    /// (docs/SPEC.md Functionality #15).
    ///
    /// The nested `Option` distinguishes two things `submit_input` must
    /// tell apart: the outer one is "this input *was* one of these
    /// commands, stop looking", the inner is the action (if any) it
    /// produced. Without that, a recognized-but-actionless command - a
    /// bare `/mute-voice`, which only prints the current list - would fall
    /// through to the unknown-command notice and then to the send paths.
    fn try_voice_mute_command(&mut self) -> Option<Option<UiAction>> {
        // Owned up front: everything below both reads the parsed pieces
        // and clears `self.input`, which cannot borrow from it at once.
        let (verb, rest) = {
            let input = self.input.trim();
            match input.split_once(char::is_whitespace) {
                Some((verb, rest)) => (verb.to_string(), rest.trim().to_string()),
                None => (input.to_string(), String::new()),
            }
        };
        let muted = match verb.as_str() {
            "/mute-voice" => true,
            "/unmute-voice" => false,
            _ => return None,
        };
        let rest = rest.as_str();

        // A bare command lists what is currently muted instead of erroring.
        // Nothing else in the UI answers "who have I muted?", and an
        // argument-less command is the natural place to ask it.
        if rest.is_empty() {
            let notice = if self.muted_voice.is_empty() {
                "no voices muted".to_string()
            } else {
                format!(
                    "voices muted: {} (/unmute-voice <nickname> to undo)",
                    self.muted_voice
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            self.input.clear();
            self.push_status_notice(notice, true);
            return Some(None);
        }

        // A nickname never contains whitespace, so anything past the first
        // word is a typo rather than part of the name - refused outright
        // instead of silently muting the first word of it.
        if rest.split_whitespace().count() > 1 {
            self.input.clear();
            self.push_status_notice(
                format!("{verb} takes one nickname, with no spaces in it"),
                false,
            );
            return Some(None);
        }
        // Guards the flat-file store the set is written to, exactly as
        // `IdStore::check_and_pin` guards its own.
        if !crate::validation::is_storable(rest) {
            self.input.clear();
            self.push_status_notice(format!("{rest:?} is not a usable nickname"), false);
            return Some(None);
        }

        let already = self.muted_voice.contains(rest);
        self.input.clear();
        if already == muted {
            // Not an error - just say so, and produce no action, so
            // nothing is rewritten to disk for a no-op.
            self.push_status_notice(
                if muted {
                    format!("{rest} is already muted")
                } else {
                    format!("{rest} is not muted")
                },
                true,
            );
            return Some(None);
        }

        // Applied locally right away so the sidebar marker and any stream
        // starting this instant see it; the session mirrors back whatever
        // actually landed on disk (`SetVoiceMuted`'s doc).
        if muted {
            self.muted_voice.insert(rest.to_string());
        } else {
            self.muted_voice.remove(rest);
        }
        self.push_status_notice(
            if muted {
                format!("{rest}'s voice messages muted")
            } else {
                format!("{rest}'s voice messages unmuted")
            },
            true,
        );
        Some(Some(UiAction::SetVoiceMuted {
            nickname: rest.to_string(),
            muted,
        }))
    }

    /// `/ban <nickname>`, `/unban <nickname>`, `/assign-admin <nickname>` -
    /// admin commands against the currently-selected channel, each taking
    /// one nickname argument, same shape `try_voice_mute_command`
    /// establishes above. `/assign-admin` alone doesn't emit its
    /// `UiAction` directly - it opens the same confirmation tier
    /// `/delete-channel` uses (`docs/PROTOCOL.md` §6.7's own "with popup
    /// confirmation"). None of the three is gated on the local user
    /// actually being this channel's admin - the server is the sole
    /// authority (`Registry::require_caller_is_admin`), and a non-admin's
    /// attempt is simply refused with a reason (`ServerMessage::Error`,
    /// now surfaced as a status notice).
    fn try_channel_moderation_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = {
            let input = self.input.trim();
            match input.split_once(char::is_whitespace) {
                Some((verb, rest)) => (verb.to_string(), rest.trim().to_string()),
                None => (input.to_string(), String::new()),
            }
        };
        if !matches!(verb.as_str(), "/ban" | "/unban" | "/assign-admin") {
            return None;
        }
        let Some(channel) = self.channels.get(self.selected_channel) else {
            self.input.clear();
            return Some(None);
        };
        let channel_name = channel.name.clone();
        if rest.is_empty() || rest.split_whitespace().count() > 1 {
            self.input.clear();
            self.push_status_notice(
                format!("{verb} takes one nickname, with no spaces in it"),
                false,
            );
            return Some(None);
        }
        let nickname = rest;
        self.input.clear();
        Some(Some(match verb.as_str() {
            "/ban" => UiAction::BanFromChannel {
                channel: channel_name,
                nickname,
            },
            "/unban" => UiAction::UnbanFromChannel {
                channel: channel_name,
                nickname,
            },
            _ => {
                // "/assign-admin"
                self.channel_command_confirm = Some(ChannelCommandConfirm {
                    title: "Assign admin?",
                    question: format!(
                        "Make {nickname} the admin of #{channel_name}? You will no longer be its admin."
                    ),
                    action: ChannelCommandConfirmAction::AssignAdmin {
                        channel: channel_name,
                        nickname,
                    },
                });
                self.channel_command_confirm_focus = Confirm::No;
                return Some(None);
            }
        }))
    }

    /// A superadmin's `/activate <nickname>`, `/deactivate <nickname>
    /// <reason>`, `/remove-account <nickname>`, `/remove-channel <name>`
    /// (`docs/PROTOCOL.md` §5.5). Shown and sendable regardless of
    /// whether the local user actually is one - the server is the sole
    /// authority (`require_superadmin`), matching this codebase's own
    /// "the server never trusts the client" principle; a non-superadmin's
    /// attempt is simply refused with a reason.
    fn try_superadmin_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = {
            let input = self.input.trim();
            match input.split_once(char::is_whitespace) {
                Some((verb, rest)) => (verb.to_string(), rest.trim().to_string()),
                None => (input.to_string(), String::new()),
            }
        };
        match verb.as_str() {
            "/activate" | "/remove-account" => {
                if rest.is_empty() || rest.split_whitespace().count() > 1 {
                    self.input.clear();
                    self.push_status_notice(
                        format!("{verb} takes one nickname, with no spaces in it"),
                        false,
                    );
                    return Some(None);
                }
                self.input.clear();
                Some(Some(if verb == "/activate" {
                    UiAction::AdminActivate { nickname: rest }
                } else {
                    UiAction::AdminRemoveAccount { nickname: rest }
                }))
            }
            "/remove-channel" => {
                if rest.is_empty() || rest.split_whitespace().count() > 1 {
                    self.input.clear();
                    self.push_status_notice(
                        format!("{verb} takes one channel name, with no spaces in it"),
                        false,
                    );
                    return Some(None);
                }
                self.input.clear();
                Some(Some(UiAction::AdminRemoveChannel { name: rest }))
            }
            "/users" => {
                if !rest.is_empty() {
                    self.input.clear();
                    self.push_status_notice("/users takes no arguments".to_string(), false);
                    return Some(None);
                }
                self.input.clear();
                self.open_users_admin();
                Some(Some(UiAction::RequestUsersList))
            }
            "/deactivate" => {
                // The reason may contain spaces - only the nickname
                // itself is a single word.
                let (nickname, reason) = match rest.split_once(char::is_whitespace) {
                    Some((n, r)) => (n.to_string(), r.trim().to_string()),
                    None => (rest, String::new()),
                };
                if nickname.is_empty() || reason.is_empty() {
                    self.input.clear();
                    self.push_status_notice("/deactivate <nickname> <reason>".to_string(), false);
                    return Some(None);
                }
                self.input.clear();
                Some(Some(UiAction::AdminDeactivate { nickname, reason }))
            }
            _ => None,
        }
    }

    /// `/password <old> <new>`: unlike `try_superadmin_command`, available
    /// to every user, gated on nothing client-side - the server is what
    /// actually re-checks `old` (`ClientMessage::ChangePassword`,
    /// `server::mod::client_loop`), so a wrong one is refused there, not
    /// silently swallowed here. Both fields are exactly one word each,
    /// the same limitation `/deactivate`'s nickname (not its reason) and
    /// every other space-delimited argument in this app already has - a
    /// password containing a space has no way to disambiguate where it
    /// ends and the other one begins.
    fn try_password_command(&mut self) -> Option<Option<UiAction>> {
        let (verb, rest) = {
            let input = self.input.trim();
            match input.split_once(char::is_whitespace) {
                Some((verb, rest)) => (verb.to_string(), rest.trim().to_string()),
                None => (input.to_string(), String::new()),
            }
        };
        if verb != "/password" {
            return None;
        }
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() != 2 {
            self.input.clear();
            self.push_status_notice("/password <old> <new>".to_string(), false);
            return Some(None);
        }
        let old_password = parts[0].to_string();
        let new_password = parts[1].to_string();
        self.input.clear();
        Some(Some(UiAction::ChangePassword { old_password, new_password }))
    }

    /// The last index (`channel.members.len()`) is always our own row
    /// (`channel::render_sidebar`'s synthetic "you" entry, appended after
    /// every real member rather than folded into `channel.members`
    /// itself), so every index below it is a real member at exactly the
    /// same index it already had.
    fn handle_sidebar_key(&mut self, code: KeyCode) -> Option<UiAction> {
        let channel = self.channels.get(self.selected_channel)?;
        // +1 for our own row, always present and always last.
        let len = channel.members.len() + 1;
        match code {
            KeyCode::Up => {
                self.sidebar_selected = (self.sidebar_selected + len - 1) % len;
                None
            }
            KeyCode::Down => {
                self.sidebar_selected = (self.sidebar_selected + 1) % len;
                None
            }
            KeyCode::Enter => {
                let Some(member) = channel.members.get(self.sidebar_selected) else {
                    // Our own row - nothing to open a DM with.
                    return None;
                };
                let member = member.clone();
                // Belt and braces: real members are never supposed to
                // include our own id, but Enter must still never open a
                // "DM" with ourselves if one somehow did.
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
            // Read-only, so unlike Enter this works even for a trust-gated
            // member - seeing what's already pinned for them can only help
            // a decision, never leak anything beyond it.
            KeyCode::Char('i') | KeyCode::Char('I') => {
                let Some(member) = channel.members.get(self.sidebar_selected) else {
                    return None;
                };
                if Some(member.id) == self.own_id {
                    return None;
                }
                let (id, name) = (member.id, member.name.clone());
                self.open_user_info(id, name.clone(), Some(channel.name.clone()));
                Some(UiAction::RequestUserInfo { peer: id, nickname: name })
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
                // Reaching the top of what's loaded, with `resume_from_log`
                // on, pulls one more chunk in first - `load_history_chunk`
                // is a no-op (returns 0) when the setting is off or there's
                // nothing left on disk, so `message_selected` then just
                // clamps at 0 exactly as it always did.
                if self.message_selected == 0 {
                    self.message_selected += self.load_history_chunk();
                }
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
                if self.message_selected == 0 {
                    self.message_selected += self.load_history_chunk();
                }
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
                // Jumps straight to the top of what's loaded - if that
                // triggers a load, the new top (index 0) is still the
                // right landing spot, so `= 0` below is unconditional.
                if self.message_selected == 0 {
                    self.load_history_chunk();
                }
                self.message_selected = 0;
                None
            }
            KeyCode::End => {
                if len > 0 {
                    self.message_selected = len - 1;
                }
                None
            }
            // Opens this row's details - who it was sent to, and which of
            // them have acknowledged it (`docs/SPEC.md` "Delivery
            // acknowledgments"). Available on every row, not just the
            // tracked ones: a row that carries no delivery information
            // says so, which is itself the answer to the question being
            // asked.
            KeyCode::Char('i') | KeyCode::Char('I') => {
                if len > 0 {
                    self.message_info = Some(self.message_selected.min(len - 1));
                }
                None
            }
            // A file entry has nothing left to do on Enter once it's
            // mid-transfer, saved under `~/.aloo/downloads`, rejected, or
            // failed (unlike the old whole-file-in-memory approach, there's
            // no separate save step to trigger for those) - except a
            // staged `.txt` receive, which Enter opens for preview
            // (`UiAction::RequestFilePreview`; `session::handle_ui_action`
            // reads the file, since `UiState` has no disk access).
            KeyCode::Enter => {
                let selected = self.message_selected;
                if let Some(LogEntry {
                    body:
                        MessageBody::File {
                            status: FileTransferStatus::Received { .. },
                            stream_id,
                            ..
                        },
                    from,
                    ..
                }) = self.current_log().get(selected)
                {
                    return Some(UiAction::RequestFilePreview {
                        from: *from,
                        stream_id: *stream_id,
                    });
                }
                // A `resume_from_log` row nobody has asked to hear yet -
                // load it from disk right here (a rare, user-initiated,
                // bounded-size read, not a hot path) and mutate it into an
                // ordinary `Voice` in place, so a second replay of the same
                // row is instant and the row otherwise behaves exactly
                // like any other from then on. `wav_path: None` (the
                // original autosave couldn't write the audio) or a file
                // that no longer decodes both report the reason and stop -
                // there's nothing to fall through into.
                if let Some(LogEntry {
                    body: MessageBody::VoiceOnDisk { duration_ms, wav_path },
                    ..
                }) = self.current_log().get(selected)
                {
                    let duration_ms = *duration_ms;
                    match wav_path.clone() {
                        Some(path) => {
                            let loaded = std::fs::read(&path)
                                .ok()
                                .and_then(|bytes| crate::client::voice::decode_wav_to_mono(&bytes));
                            match loaded {
                                Some(samples) => {
                                    let pcm = crate::client::voice::pcm_to_bytes(&samples);
                                    if let Some(entry) =
                                        self.current_log_mut().and_then(|log| log.get_mut(selected))
                                    {
                                        entry.body = MessageBody::Voice { duration_ms, pcm };
                                    }
                                }
                                None => {
                                    self.push_status_notice(
                                        "could not load this voice message's audio".to_string(),
                                        false,
                                    );
                                    return None;
                                }
                            }
                        }
                        None => {
                            self.push_status_notice("no audio was saved for this message".to_string(), false);
                            return None;
                        }
                    }
                }
                let replay = match self.current_log().get(selected) {
                    Some(LogEntry {
                        body: MessageBody::Voice { duration_ms, pcm },
                        from,
                        ..
                    }) => Some((*duration_ms, pcm.clone(), *from)),
                    _ => None,
                };
                let (duration_ms, pcm, from) = replay?;
                // An empty clip (0 playable samples) never actually starts
                // anything on the mixer (see `handle_ui_action`'s
                // `ReplayVoice` arm) - `replaying` must not be set in that
                // case, or Escape would be stuck stealing its "stop
                // playback" meaning with nothing to stop. Nor is a clip
                // that never played worth telling the sender about.
                if pcm.is_empty() {
                    return Some(UiAction::ReplayVoice {
                        duration_ms,
                        pcm,
                        from,
                        owed_receipt: None,
                    });
                }
                self.replaying = true;
                // Taken, not read: hearing it twice is still hearing it
                // once, and the sender has already been told.
                let owed_receipt = self.current_log_mut().and_then(|log| log.get_mut(selected)).and_then(
                    |entry| {
                        entry.listened = true;
                        entry.owed_receipt.take()
                    },
                );
                Some(UiAction::ReplayVoice {
                    duration_ms,
                    pcm,
                    from,
                    owed_receipt,
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

    /// `current_log`'s mutable twin, for the one thing that writes back
    /// into the row under the cursor: paying off an incoming voice
    /// message's `owed_receipt` when it is replayed.
    fn current_log_mut(&mut self) -> Option<&mut Vec<LogEntry>> {
        match self.active_private_room {
            Some(peer) => self.private_rooms.get_mut(&peer).map(|r| &mut r.log),
            None => self
                .channels
                .get_mut(self.selected_channel)
                .map(|c| &mut c.log),
        }
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

    /// The next not-yet-opened http(s) URL in the focused message
    /// (`message_selected`), for Ctrl+O. A message with more than one link
    /// cycles through them on repeated presses; moving the cursor to a
    /// different message starts back at its first link, since
    /// `last_opened_url`'s row no longer matches.
    fn next_url_in_focused_message(&mut self) -> Option<String> {
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
            let autosave = self.autosave_messages.then(|| self.server_label.clone());
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
                            crate::client::export::Surface::Channel(&channel),
                            tab.log.last().unwrap(),
                        );
                    }
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
                            from_name: name.clone(),
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
                            crate::client::export::Surface::Dm(&name),
                            room.log.last().unwrap(),
                        );
                    }
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
    if state.mode == Mode::Contacts {
        super::contacts::render_contacts_popup(frame, area, state);
    }
    if state.mode == Mode::DirectPunches {
        super::direct_punch_popup::render_direct_punches_popup(frame, area, state);
    }
    if state.mode == Mode::ChannelLockPopup {
        super::channel_lock_popup::render_channel_lock_popup(frame, area, state);
    }
    if state.mode == Mode::ExportPopup {
        super::export_popup::render_export_popup(frame, area, state);
    }
    // One message's delivery details, drawn under the help overlay and
    // every consent popup for the same reason `handle_key` lets those
    // absorb keys first.
    if state.message_info.is_some() {
        render_message_info_popup(frame, area, state);
    }
    // Same tier as message-info above - a staged `.txt` receive's preview.
    if state.file_preview.is_some() {
        render_txt_preview_popup(frame, area, state);
    }
    // Same tier as message-info above - `i`/`/info`'s read-only snapshot.
    if state.user_info.is_some() {
        super::contacts::render_user_info_popup(frame, area, state);
    }
    // Same tier as user-info above - the superadmin `/users` popup.
    if state.users_admin.is_some() {
        super::contacts::render_users_admin_popup(frame, area, state);
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
        render_call_modal(frame, area, state, call);
    }
    if let Some(pending) = &state.call_confirm {
        render_call_confirm_popup(frame, area, pending, state.call_confirm_focus);
    }
    if let Some(pending) = &state.channel_command_confirm {
        render_channel_command_confirm_popup(frame, area, pending, state.channel_command_confirm_focus);
    }
    // The OTP popups sit above the file offer, same tier `handle_key` gives
    // them (below only an identity review).
    if let Some(pending) = &state.otp_generate_confirm {
        render_otp_generate_popup(frame, area, pending, state.otp_generate_focus);
    }
    if let Some(pending) = state.otp_size_input_open() {
        render_otp_size_popup(frame, area, pending, state);
    }
    if let Some(progress) = state.otp_keygen_open() {
        render_otp_keygen_popup(frame, area, progress);
    }
    if let Some(invite) = state.otp_invite_open() {
        render_otp_invite_popup(frame, area, invite, state.otp_invite_focus);
    }
    // Drawn just below the identity review, for the same reason it is
    // checked just below it in `handle_key`: impersonation still wins the
    // screen if both are somehow open for different peers at once.
    if let Some(review) = state.unknown_peer_review_open() {
        render_unknown_peer_popup(frame, area, review, state.unknown_peer_review_focus);
    }
    // Drawn last of all - takes priority over even the help overlay, same
    // as it does in `handle_key`, so it's always interactable regardless
    // of what else happened to be open when the mismatch arrived.
    if let Some(review) = state.identity_review_open() {
        render_identity_review_popup(frame, area, review, state.identity_review_focus);
    }
    // Outranks even the identity review, same as in `handle_key`: once
    // the account is deactivated nothing else this session could still do
    // matters, so this is always what's on screen from here on.
    if let Some(reason) = &state.account_deactivated {
        render_account_deactivated_modal(frame, area, reason);
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
/// `Confirm`'s doc for why the default flips from the identity
/// review's `Reject`-first one).
fn render_file_offer_popup(
    frame: &mut Frame,
    area: Rect,
    offer: &PendingFileOffer,
    focus: Confirm,
) {
    let title = format!("Incoming file from {}", offer.from_name);
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
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

/// The Accept/Reject popup for one incoming call invite
/// (`docs/PROTOCOL.md` "Live voice calls") - visual shape mirrors
/// `render_file_offer_popup` exactly, same `Accept`-first default.
fn render_call_invite_popup(
    frame: &mut Frame,
    area: Rect,
    invite: &PendingCallInvite,
    focus: Confirm,
) {
    let title = format!("Voice call incoming from {}", invite.from_name);
    let location = match &invite.channel {
        Some(name) => format!("#{name}"),
        None => "a private message".to_string(),
    };
    let message = format!(
        "{} is calling via {location}. Do you accept?",
        invite.from_name
    );
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

fn render_otp_generate_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingOtpGenerate,
    focus: Confirm,
) {
    let label = pending.purpose.label();
    let title = format!("Start an {label}");

    let retry_command = match pending.purpose {
        crate::crypto::otp::OtpPurpose::Live => "/otp",
        crate::crypto::otp::OtpPurpose::Mail => "/new-otp-mail-key",
    };
    let message = format!(
        "No {label} found for {}. Generate one now and share it automatically \
         over the encrypted pq_hybrid channel? Alternatively, run the 'otp' \
         command yourself and place the keys under ~/.aloo/otp/.keychain/, \
         then try {retry_command} again.",
        pending.peer_name
    );
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        size: (64, 11),
        body_min_height: 6,
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

fn render_otp_invite_popup(
    frame: &mut Frame,
    area: Rect,
    invite: &PendingOtpInvite,
    focus: Confirm,
) {
    let purpose = crate::crypto::otp::OtpPurpose::of_contact_name(&invite.contact_name);
    let label = purpose.label();
    let title = format!("{label} request from {}", invite.from_name);

    // The size, when there is one (a fresh-key invitation, not a bare
    // resume request), is exactly what the sender chose in their own size
    // prompt - shown so this decision isn't made sight-unseen (see
    // `PendingOtpInvite::pad_size_mb`'s doc).
    let size_clause = match invite.pad_size_mb {
        Some(mb) => format!(" using a fresh {mb}MB pad"),
        None => String::new(),
    };
    // The trailing clause differs by purpose too, not just the verb: a
    // live session genuinely layers the pad on top of pq_hybrid for every
    // message afterward, but a mail key never layers onto anything - it's
    // its own, separate delivery mechanism (`/mail`), so describing it as
    // "layered on top of pq_hybrid" would misdescribe what accepting it
    // actually does.
    let message = match purpose {
        crate::crypto::otp::OtpPurpose::Live => format!(
            "{} wants to start an OTP session with you{size_clause}, layered on top of \
             pq_hybrid for extra secrecy. Accept it?",
            invite.from_name
        ),
        crate::crypto::otp::OtpPurpose::Mail => format!(
            "{} wants to exchange an OTP mail key with you{size_clause}. Accept it?",
            invite.from_name
        ),
    };
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

/// Follows `render_otp_generate_popup`'s Accept - asks how large a pad to
/// generate (MB per key, `crypto::otp::OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX`),
/// same shape as `channel::render_channel_password_popup`'s text-entry
/// popup (a live input line, an error line only when there's an error to
/// show).
fn render_otp_size_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &PendingOtpGenerate,
    state: &UiState,
) {
    let has_error = state.otp_size_error.is_some();
    let popup = centered_rect(64, if has_error { 8 } else { 7 }, area);
    let block = Block::default()
        .title(format!(
            "{} pad size for {} (MB per key)",
            pending.purpose.label(),
            pending.peer_name
        ))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let mut constraints = vec![Constraint::Min(3), Constraint::Length(1)];
    if has_error {
        constraints.push(Constraint::Length(1));
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    // The estimate is the whole reason a ceiling is no longer imposed
    // here: any size can be delivered, but a large one takes real time and
    // that is the user's call to make knowingly rather than ours to refuse.
    let estimate = state
        .otp_size_text
        .parse::<u32>()
        .ok()
        .filter(|mb| crate::crypto::otp::otp_size_mb_in_range(*mb))
        .map(|mb| {
            format!(
                " {} MB per key is {} to send over the link once generated.",
                mb,
                crate::client::otp::transfer_estimate_text(mb)
            )
        })
        .unwrap_or_default();
    let message = format!(
        "Choose a size between {} and {} MB, then press Enter. \
         Esc cancels the whole session.{estimate}",
        crate::crypto::otp::OTP_SIZE_MB_MIN,
        crate::crypto::otp::OTP_SIZE_MB_MAX
    );
    frame.render_widget(
        Paragraph::new(message).wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(format!("> {}", state.otp_size_text)),
        rows[1],
    );
    if let Some(err) = &state.otp_size_error {
        frame.render_widget(
            Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red)),
            rows[2],
        );
    }
}

/// How wide the keygen popup's progress bar is drawn, in cells.
const KEYGEN_BAR_CELLS: usize = 40;

/// Follows `render_otp_size_popup`'s Enter - the pad is now genuinely
/// being generated (`client::otp::confirm_generate`'s background task), so
/// this shows a live spinner and progress bar until it finishes.
///
/// Absorbs input without offering any action (see `handle_key`): there is
/// nothing to decide and nothing safe to cancel mid-generation. Its whole
/// job is to make a long wait legible - at the sizes now allowed, a pad can
/// take minutes, and a silent frozen screen is the failure mode this
/// replaces.
fn render_otp_keygen_popup(frame: &mut Frame, area: Rect, progress: &OtpKeygenProgress) {
    let popup = centered_rect(64, 8, area);
    let label = progress.purpose.label();
    let (title, what, reassurance) = match progress.phase {
        OtpPadPhase::Generating => (
            format!("Generating an {label} pad for {}", progress.peer_name),
            format!(
                "{}MB per key ({}MB of true randomness in total)",
                progress.size_mb,
                progress.size_mb as u64 * 2
            ),
            "Generating and sharing happen once - the pad is then reused for every message \
             with this contact until it runs out.",
        ),
        OtpPadPhase::Sending => (
            format!("Sending the {label} pad to {}", progress.peer_name),
            format!(
                "{}MB per key, both halves ({}MB over the link)",
                progress.size_mb,
                progress.size_mb as u64 * 2
            ),
            "They are asked to accept only once the whole pad has arrived and both sides \
             agree it matches - so their prompt appears when this finishes, not before.",
        ),
        OtpPadPhase::Receiving => (
            format!("Receiving an {label} pad from {}", progress.peer_name),
            format!(
                "{}MB per key, both halves ({}MB over the link)",
                progress.size_mb,
                progress.size_mb as u64 * 2
            ),
            "Nothing is installed yet. Once it has all arrived and matches what they sent, \
             you will be asked whether to accept it.",
        ),
    };
    let block = Block::default().title(title).borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // spinner + what is happening
            Constraint::Length(1), // bar
            Constraint::Min(1),    // reassurance
        ])
        .split(inner);

    let spinner = SPINNER_FRAMES[progress.frame % SPINNER_FRAMES.len()];
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{spinner} "),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(what),
        ]))
        .wrap(ratatui::widgets::Wrap { trim: true }),
        rows[0],
    );

    let filled = (progress.fraction() * KEYGEN_BAR_CELLS as f64).round() as usize;
    let filled = filled.min(KEYGEN_BAR_CELLS);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("\u{2588}".repeat(filled), Style::default().fg(Color::Green)),
            Span::styled(
                "\u{2591}".repeat(KEYGEN_BAR_CELLS - filled),
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw(format!("  {}%", progress.percent())),
        ])),
        rows[1],
    );

    frame.render_widget(
        Paragraph::new(reassurance)
            .style(Style::default().fg(Color::DarkGray))
            .wrap(ratatui::widgets::Wrap { trim: true }),
        rows[2],
    );
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
    let filled = (level as usize * LEVEL_BAR_CELLS)
        .div_ceil(100)
        .min(LEVEL_BAR_CELLS);
    format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(LEVEL_BAR_CELLS - filled)
    )
}

/// The `> ` / `  ` selection marker every roster row opens with.
const CALL_MARKER_COL: usize = 2;

/// The gap between the name column and the label column. Four columns
/// rather than one: on the row whose name fills the whole column the two
/// would otherwise touch, and a long nickname running straight into
/// `IN CALL` reads as one string rather than as two columns.
const CALL_COL_GAP: usize = 4;

/// The narrowest gap ever left between the labels and the voice meter that
/// ends the row. Wider than `CALL_COL_GAP` because the meter is right
/// aligned and the labels are not: on the widest row in the list these two
/// columns are all that separates them, and one space there reads as one
/// run of text rather than two columns.
const CALL_LEVEL_GAP: usize = 2;

/// A call roster's two measured column widths - the third column, the
/// voice meter, is `LEVEL_BAR_CELLS` wide and always sits flush against
/// the modal's right edge.
///
/// Both are measured from the roster actually on screen rather than fixed
/// at the widest they could ever be (a 10-character nickname carrying both
/// ` (you)` and ` (host)`, a `REJECTED MUTED` label pair). A call is
/// usually two or three people with short names and one label each, so
/// the worst case is mostly blank columns down the middle of every row.
/// Measuring makes the modal as narrow as the call in it allows, and -
/// because both figures are taken across the *whole* list, not per row -
/// keeps all three columns lined up down it (`docs/SPEC.md` "Live voice
/// calls").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallColumns {
    pub name: usize,
    pub label: usize,
}

impl CallColumns {
    /// Measures both columns across `call`'s whole roster.
    pub fn measure(call: &CallUiState, own_id: Option<UserId>) -> Self {
        let name = call
            .members
            .iter()
            .map(|m| display_width(&call_member_name(m, call.host, own_id)) as usize)
            .max()
            .unwrap_or(0);
        let label = call
            .members
            .iter()
            .map(|m| {
                call_member_labels(m)
                    .iter()
                    .map(|s| display_width(&s.content) as usize)
                    .sum()
            })
            .max()
            .unwrap_or(0);
        Self { name, label }
    }

    /// How many columns one roster row needs end to end: marker, name,
    /// gap, labels, the gap before the meter, and the meter itself.
    pub fn row_width(self) -> usize {
        CALL_MARKER_COL + self.name + CALL_COL_GAP + self.label + CALL_LEVEL_GAP + LEVEL_BAR_CELLS
    }
}

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
    let used: usize = spans
        .iter()
        .map(|s| display_width(&s.content) as usize)
        .sum();
    if used < width {
        spans.push(Span::raw(" ".repeat(width - used)));
    }
}

/// The call modal (`docs/SPEC.md` "Live voice calls"): live duration on
/// top in yellow, the scrollable roster below it - host first, everyone
/// else after - each row labelled and metered, and the END CALL button at
/// the bottom.
///
/// `area` is the space the modal may use, not the modal: it sizes itself
/// to the call in it (`call_modal_rect`) and centers in what it was given,
/// so a three-person call on a wide terminal is a small box rather than a
/// fixed slab of mostly-blank columns.
pub(crate) fn render_call_modal(
    frame: &mut Frame,
    area: Rect,
    state: &UiState,
    call: &CallUiState,
) {
    let title = match &call.channel {
        Some(name) => format!("Call \u{2014} #{name}"),
        None => "Call".to_string(),
    };
    let columns = CallColumns::measure(call, state.own_id);
    let hint = call_modal_hint(call, state.own_id);
    let area = call_modal_rect(call, &title, &hint, columns, area);
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
            let name_col = columns.name;
            spans.push(Span::styled(
                format!("{name:<name_col$}"),
                if idx == call.selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ));
            spans.push(Span::raw(" ".repeat(CALL_COL_GAP)));
            let mut labels = call_member_labels(member);
            pad_to(&mut labels, columns.label);
            spans.extend(labels);
            // Our own row meters what we are actually sending: muting
            // ourselves (`m` on our own row) stops that at the source, so
            // the bar must read empty rather than keep twitching along
            // with a microphone nobody hears.
            let level = if is_us && call.muted { 0 } else { member.level };
            // Flush right against the modal's inner edge, whatever the
            // two measured columns before it came to - so the meters read
            // as one column of their own rather than tracking the ragged
            // right edge of the labels.
            let used = CALL_MARKER_COL + name_col + CALL_COL_GAP + columns.label;
            let gap = (inner.width as usize)
                .saturating_sub(used + LEVEL_BAR_CELLS)
                .max(CALL_LEVEL_GAP);
            spans.push(Span::raw(" ".repeat(gap)));
            spans.push(Span::styled(
                level_bar(level),
                Style::default().fg(Color::Green),
            ));
            Line::from(spans)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), rows[1]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        ))),
        rows[2],
    );
    render_popup_button(frame, rows[3], CALL_END_BUTTON_WIDTH, "END CALL", true);

    if let Some(picker) = &call.invite_picker {
        render_call_invite_picker(frame, area, picker);
    }
    if let Some(focus) = call.end_confirm {
        render_end_call_confirm_popup(frame, area, focus);
    }
}

/// What END CALL asks before it leaves a call
/// (`CallUiState::end_confirm`). Drawn over the modal it was pressed on,
/// like the invite picker, so the roster it is about stays in view.
fn render_end_call_confirm_popup(frame: &mut Frame, area: Rect, focus: Confirm) {
    // The one confirmation whose question is centered rather than
    // left-aligned, so it renders its own body rather than using
    // `render_message`.
    ConfirmPopup {
        title: END_CALL_CONFIRM_TITLE,
        labels: ConfirmLabels::new("END CALL", "Cancel"),
        focus: Some(focus),
        size: (48, 6),
        border_style: Some(Style::default().fg(Color::Red)),
        body_min_height: 1,
        ..Default::default()
    }
    .render(frame, area, |frame, body| {
        frame.render_widget(
            Paragraph::new(END_CALL_CONFIRM_QUESTION)
                .wrap(ratatui::widgets::Wrap { trim: true })
                .alignment(ratatui::layout::Alignment::Center),
            body,
        );
    });
}

/// The confirmation's title and question, named so a test reads the same
/// strings the popup draws.
pub const END_CALL_CONFIRM_TITLE: &str = "Leave this call?";
pub const END_CALL_CONFIRM_QUESTION: &str = "Leaving is immediate and cannot be undone.";

/// The width of the modal's own END CALL button, which is also a floor on
/// how narrow the modal may get - a button clipped in half reads as a
/// rendering fault rather than as a small window.
const CALL_END_BUTTON_WIDTH: u16 = 14;

/// The key line under the roster. The host's two extra keys are only shown
/// to the host, since only they do anything for anyone else.
fn call_modal_hint(call: &CallUiState, own_id: Option<UserId>) -> String {
    let host_hint = if call.we_are_host(own_id) {
        "  m: mute  i: invite"
    } else {
        ""
    };
    format!("Esc: minimize{host_hint}")
}

/// The rectangle the call modal actually occupies inside `area`: as narrow
/// and as short as its own contents allow, centered, and never larger than
/// what it was given.
///
/// Width is the widest thing that has to fit on one line - a roster row
/// (`CallColumns::row_width`), the key hint, the title in its border, or
/// the END CALL button. Height is one row per participant plus the fixed
/// furniture around them (duration, hint, button, borders), so a two-person
/// call is a small box and a twelve-person one grows until it runs out of
/// screen, at which point the roster scrolls inside it as it already did.
pub(crate) fn call_modal_rect(
    call: &CallUiState,
    title: &str,
    hint: &str,
    columns: CallColumns,
    area: Rect,
) -> Rect {
    let content = columns
        .row_width()
        .max(display_width(hint) as usize)
        .max(display_width(title) as usize)
        .max(CALL_END_BUTTON_WIDTH as usize);
    let width = (content as u16).saturating_add(2);
    // 1 duration + roster + 1 hint + 3 button + 2 borders. The roster
    // floors at one row: a modal with no room for even one participant
    // would be a border around nothing.
    let height = (call.members.len().max(1) as u16).saturating_add(7);
    centered_rect(width, height, area)
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
    focus: Confirm,
) {
    let where_clause = match &pending.target {
        CallTarget::Channel { channel } => format!("in #{channel}"),
        CallTarget::Direct { .. } => "in this private room".to_string(),
    };
    let plural = if pending.invitee_count == 1 {
        "user"
    } else {
        "users"
    };
    // The invitee count is highlighted, so this is a styled `Line` rather
    // than the plain message `render_message` takes.
    ConfirmPopup {
        title: "Start a call",
        labels: ConfirmLabels::new("Call", "Cancel"),
        focus: Some(focus),
        size: (60, 9),
        ..Default::default()
    }
    .render(frame, area, |frame, body| {
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
            body,
        );
    });
}

/// `/delete-channel`/`/assign-admin`'s confirmation - a red-bordered
/// mirror of `render_call_confirm_popup`, generic over `pending.question`
/// rather than building the sentence itself, since the two commands ask
/// two different questions over the same Confirm/Cancel shape.
fn render_channel_command_confirm_popup(
    frame: &mut Frame,
    area: Rect,
    pending: &ChannelCommandConfirm,
    focus: Confirm,
) {
    ConfirmPopup {
        title: pending.title,
        labels: ConfirmLabels::CONFIRM_CANCEL,
        focus: Some(focus),
        size: (60, 9),
        border_style: Some(Style::default().fg(Color::Red)),
        ..Default::default()
    }
    .render_message(frame, area, pending.question.as_str());
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
    // The plain record-circle glyph, not a multicolour emoji - its colour
    // is entirely the `Style` painted below, never fixed in the character.
    let message = format!(
        "\u{23FA} On a call{where_clause} ({} connected){mute_clause}",
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
    focus: Confirm,
) {
    let title = format!("Identity review: {}", review.nickname);
    // Taller than the other single-button popups (64x9): the message now
    // also carries the last-known vs. new address/device id
    // (docs/PROTOCOL.md §12.7), several lines longer than the original
    // one-line fingerprint warning.
    let mut lines = vec![Line::from(review.message.as_str())];
    if review.status == IdentityStatus::Rejected {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "(previously rejected - messaging with them is blocked)",
            Style::default().fg(Color::Red),
        )));
    }
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::ACCEPT_REJECT,
        focus: Some(focus),
        size: (70, 13),
        ..Default::default()
    }
    .render(frame, area, |frame, body| {
        frame.render_widget(
            Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: true }),
            body,
        );
    });
}

/// The Yes/No popup for a `direct_punch_to` nickname with no pinned key
/// that just sent proof of an identity (`docs/PROTOCOL.md` §7.1.5) -
/// opened by `push_unknown_peer_review`. Same visual style as
/// `render_identity_review_popup`; the wording switches on `review.stage`,
/// since this is two sequential questions about the same review rather
/// than a case-specific message the caller pre-formats.
fn render_unknown_peer_popup(
    frame: &mut Frame,
    area: Rect,
    review: &UnknownPeerReview,
    focus: Confirm,
) {
    let title = format!("Unknown direct connection: {}", review.requested_nickname);
    let message = match &review.stage {
        UnknownPeerStage::Initial => format!(
            "A connection was received directly to your public ip from an unknown \
             nickname (\"{}\"). Do you want to check which of your local keys \
             matches this request?",
            review.requested_nickname
        ),
        UnknownPeerStage::ConfirmMatch {
            matched_nickname, ..
        } => format!(
            "I found that the request from {} matches your local key for {}. \
             Do you want to use {}'s key to talk to {}?",
            review.requested_nickname, matched_nickname, matched_nickname, review.requested_nickname
        ),
    };
    ConfirmPopup {
        title: &title,
        labels: ConfirmLabels::YES_NO,
        focus: Some(focus),
        size: (70, 11),
        ..Default::default()
    }
    .render_message(frame, area, &message);
}

/// The `<nickname><separator> ` a user-content row opens with. On a row
/// whose delivery is tracked the separator is `DELIVERY_ARROW`, coloured
/// by how far the message has got (`docs/SPEC.md` "Delivery
/// acknowledgments"); on every other row it is the plain `:` this app has
/// always used. Shared by text, voice and file rows so one message kind
/// can never disagree with another about where the indicator lives.
fn sender_prefix(entry: &LogEntry) -> Vec<Span<'static>> {
    match entry.delivery_status() {
        Some(status) => vec![
            Span::raw(format!("{} ", entry.from_name)),
            Span::styled(
                DELIVERY_ARROW,
                Style::default()
                    .fg(status.color())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ],
        None => vec![Span::raw(format!("{}{PLAIN_SEPARATOR} ", entry.from_name))],
    }
}

/// Every `http://`/`https://` URL in `text`, as byte ranges - shared by
/// message rendering (underlines each one) and Ctrl+O (opens one). A link
/// is a whitespace-delimited token starting with one of those schemes, so
/// no regex is needed: `split_whitespace`'s tokens are relocated by
/// scanning forward from where the last one ended, since it doesn't hand
/// back byte offsets itself.
fn find_urls(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let mut from = 0;
    for token in text.split_whitespace() {
        let Some(rel) = text[from..].find(token) else {
            continue;
        };
        let start = from + rel;
        let end = start + token.len();
        from = end;
        if token.starts_with("http://") || token.starts_with("https://") {
            out.push(start..end);
        }
    }
    out
}

/// Appends `text` to `spans`, with every link `find_urls` finds in it
/// rendered blue and underlined instead of the surrounding plain text.
fn push_text_with_links(spans: &mut Vec<Span<'static>>, text: &str) {
    let mut pos = 0;
    for range in find_urls(text) {
        if range.start > pos {
            spans.push(Span::raw(text[pos..range.start].to_string()));
        }
        spans.push(Span::styled(
            text[range.clone()].to_string(),
            Style::default().fg(Color::Blue).add_modifier(Modifier::UNDERLINED),
        ));
        pos = range.end;
    }
    if pos < text.len() {
        spans.push(Span::raw(text[pos..].to_string()));
    }
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
            // The same tag they carry in the user list and on the DM
            // selector (`UiState::encryption_tag`), so one person is not
            // labelled two different ways on one screen.
            .map(|u| {
                format!(
                    "Private: {} {}",
                    u.name,
                    state.encryption_tag(id, u.key_mode)
                )
            })
            .unwrap_or_else(|| "Private".to_string())
    } else {
        // The channel's own name, `🔒`-prefixed for a private one, the
        // same convention the (unbordered) header selector already uses
        // (`channel_label`) - plus its admin, when it has one (never
        // `the-hall`, whose `admin` is always `None`).
        match state.channels.get(state.selected_channel) {
            Some(c) => {
                let base = channel_label(c.kind, &c.name);
                match &c.admin {
                    Some(admin) => format!("{base} (admin: {admin})"),
                    None => base,
                }
            }
            None => "Messages".to_string(),
        }
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

    // An empty conversation with no server behind it is a conversation
    // waiting on a punch, not an idle one: nothing is going to arrive from
    // a roster or a presence notice to explain the silence, so it is said
    // here (see `channel::WAITING_FOR_DIRECT_PEERS`). Only while the peer
    // is genuinely not reachable yet - once a link is up, an empty log
    // means exactly what it always did.
    if log.is_empty() && state.serverless {
        let reachable = match dm_peer {
            Some(peer) => state.link_status_of(peer) == crate::client::p2p::LinkStatus::Active,
            None => state
                .channels
                .get(state.selected_channel)
                .is_some_and(|c| !c.members.is_empty()),
        };
        if !reachable {
            frame.render_widget(
                Paragraph::new(super::channel::WAITING_FOR_DIRECT_PEERS)
                    .style(Style::default().fg(Color::DarkGray))
                    .wrap(ratatui::widgets::Wrap { trim: true }),
                inner,
            );
            return;
        }
    }

    let items: Vec<ListItem> = log
        .iter()
        .map(|entry| {
            // One `LogEntry` is always exactly one selectable `ListItem`,
            // however many visual rows its content takes - a multiline
            // paste (`MessageBody::Text` containing `\n`) renders as
            // several rows of the *same* message, not several messages:
            // Up/Down still moves one log entry at a time (`ListState`
            // selects by item, not by rendered row) and `i` still opens
            // the details of the one entry under the cursor regardless of
            // which of its rows that is.
            let mut lines: Vec<Line<'static>> = match &entry.body {
                MessageBody::Text(text) => {
                    let mut physical_lines: Vec<Line<'static>> = text
                        .split('\n')
                        .map(|part| {
                            let mut spans = Vec::new();
                            push_text_with_links(&mut spans, part);
                            Line::from(spans)
                        })
                        .collect();
                    // The sender prefix belongs on the first row only.
                    if let Some(first) = physical_lines.first_mut() {
                        let mut prefix = sender_prefix(entry);
                        prefix.append(&mut first.spans);
                        first.spans = prefix;
                    }
                    physical_lines
                }
                MessageBody::Voice { duration_ms, .. } => {
                    let label = format_duration_label(*duration_ms);
                    let mut spans = sender_prefix(entry);
                    spans.push(Span::styled(
                        format!("\u{1F534} {label}"),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                    // A received voice message nobody has actually heard
                    // yet - never autoplayed (muted, trust-gated, or this
                    // wasn't the focused channel/DM when it arrived) and
                    // never manually replayed either (`handle_messages_key`'s
                    // Enter, which is the only other place `listened` is
                    // ever set). Right-padded to the row's own width so the
                    // marker lands flush with the right edge.
                    if !entry.outgoing && !entry.listened {
                        const NOT_LISTENED: &str = "not listened";
                        let used: u16 = spans.iter().map(|s| display_width(s.content.as_ref())).sum();
                        let marker_width = display_width(NOT_LISTENED);
                        let pad = inner.width.saturating_sub(used + marker_width);
                        if pad > 0 {
                            spans.push(Span::raw(" ".repeat(pad as usize)));
                        }
                        spans.push(Span::styled(
                            NOT_LISTENED,
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        ));
                    }
                    vec![Line::from(spans)]
                }
                // A `resume_from_log` history row nobody has asked to hear
                // yet - dimmed rather than the solid red `Voice` circle,
                // to read at a glance as "not loaded" rather than "not
                // listened" (no marker either: `listened` is always `true`
                // here, see `export::parse_log_entry`'s doc for why).
                MessageBody::VoiceOnDisk { duration_ms, wav_path } => {
                    let label = format_duration_label(*duration_ms);
                    let mut spans = sender_prefix(entry);
                    let hint = if wav_path.is_some() {
                        "(Enter to load)"
                    } else {
                        "(no audio saved)"
                    };
                    spans.push(Span::styled(
                        format!("\u{25CB} {label} {hint}"),
                        Style::default().fg(Color::DarkGray),
                    ));
                    vec![Line::from(spans)]
                }
                MessageBody::VoiceStreaming { .. } => {
                    let dot = if state.blink_on { "\u{23FA}" } else { " " };
                    let mut spans = sender_prefix(entry);
                    spans.push(Span::styled(
                        format!("{dot} voice (streaming...)"),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ));
                    vec![Line::from(spans)]
                }
                MessageBody::File {
                    filename,
                    total,
                    status,
                    ..
                } => {
                    let mut spans = sender_prefix(entry);
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
                        FileTransferStatus::Received { .. } => spans.push(Span::styled(
                            format!("\u{1F4CE} {filename} (Enter: preview)"),
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
                    vec![Line::from(spans)]
                }
                MessageBody::System(text) => vec![Line::from(Span::styled(
                    text.clone(),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ))],
                MessageBody::Presence(text) => vec![Line::from(Span::styled(
                    text.clone(),
                    Style::default().fg(Color::Yellow),
                ))],
            };
            // A message that reached nobody is struck through: it is not
            // waiting on anybody's acknowledgement, because it was never
            // addressed to anybody (`docs/SPEC.md` "Delivery
            // acknowledgments"). Applied before the pad prefix below,
            // so a combining overlay never lands on that emoji. Every row
            // of a multiline message is struck through together, since
            // they are all the one message that reached nobody.
            if entry.reached_nobody() {
                for line in lines.iter_mut() {
                    for span in line.spans.iter_mut() {
                        span.content = strike_through(&span.content).into();
                    }
                }
            }
            // The tag reflects what actually protected THIS message
            // (`entry.crypto`, stamped once at push time by
            // `UiState::message_crypto`), never the room's current live
            // OTP session state - a message sent under OTP keeps its key
            // icon in the log even after `/endotp` ends the session, since
            // ending the session changes nothing about how that message
            // was actually encrypted. Only the first row carries it - one
            // tag per message, not one per row.
            if matches!(entry.crypto, Some(MessageCrypto::Otp { .. }))
                && !matches!(
                    entry.body,
                    MessageBody::System(_) | MessageBody::Presence(_)
                )
            {
                if let Some(first) = lines.first_mut() {
                    first.spans.insert(0, Span::raw(format!("{OTP_ICON} ")));
                }
            }
            // A row whose async send turned out to have failed
            // (`UiState::mark_dm_message_failed`) is shown in red, same as
            // every other "this needs your attention" red the app already
            // uses - a failed send must never look identical to a
            // delivered one. Every row of a multiline message gets it, so
            // a failed send is never half-red.
            if entry.failed {
                for line in lines.iter_mut() {
                    line.style = Style::default().fg(Color::Red);
                }
            }
            ListItem::new(Text::from(lines))
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
    // The rightmost column is given up to the scrollbar, but only while the
    // log actually overflows - an unscrollable pane shouldn't lose a column
    // of text to a bar that would be full-height anyway.
    let visible = inner.height as usize;
    // Cached for `UiState::history_chunk_size` - key-handling code (Up/
    // PageUp/Home, tab switches) never sees a `Frame`/`Rect` of its own.
    state.last_messages_area_height.store(inner.height, Ordering::Relaxed);
    let overflows = log.len() > visible && inner.width > 1;
    let list_area = if overflows {
        Rect {
            width: inner.width - 1,
            ..inner
        }
    } else {
        inner
    };

    let list = List::new(items).highlight_style(highlight_style);
    let mut list_state = ListState::default();
    if !log.is_empty() {
        list_state.select(Some(state.message_selected.min(log.len() - 1)));
    }
    frame.render_stateful_widget(list, list_area, &mut list_state);

    if overflows {
        // Read after the list has rendered: the offset that keeps the
        // selection on screen is ratatui's to compute, so the thumb tracks
        // the viewport itself rather than a guess made from the selection.
        // ratatui counts `content_length` in scroll *positions*, not items:
        // the last one shows the final viewport-worth of entries, so with
        // `log.len()` passed straight in the thumb would stop a step short
        // of the bottom of its track on the newest message.
        let mut scrollbar_state = ScrollbarState::new(log.len() - visible + 1)
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

/// Packs a `Rect` into one `u64` (16 bits per field, `x`/`y`/`width`/
/// `height` from the high end down) - what lets a rendered position be
/// recorded in a plain `AtomicU64` field (`Sync`-friendly, unlike `Cell`;
/// see `UiState::last_input_bar_area`'s doc) rather than four separate
/// `AtomicU16`s.
pub(crate) fn pack_rect(r: Rect) -> u64 {
    ((r.x as u64) << 48) | ((r.y as u64) << 32) | ((r.width as u64) << 16) | (r.height as u64)
}

/// `pack_rect`'s inverse.
pub(crate) fn unpack_rect(v: u64) -> Rect {
    Rect {
        x: (v >> 48) as u16,
        y: (v >> 32) as u16,
        width: (v >> 16) as u16,
        height: v as u16,
    }
}

/// Whether `(x, y)` falls inside `r` - `u64::MAX`'s unpacked sentinel
/// (`{65535, 65535, 65535, 65535}`, before any frame has stored a real
/// area, or one this session's terminal will never actually be) contains
/// nothing a real click can ever land on, so callers need no separate
/// "not drawn yet" check.
fn rect_contains(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x.saturating_add(r.width) && y >= r.y && y < r.y.saturating_add(r.height)
}

pub(crate) fn render_input_bar(frame: &mut Frame, area: Rect, state: &UiState) {
    state.last_input_bar_area.store(pack_rect(area), Ordering::Relaxed);
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

    // A Pending/Rejected identity (docs/PROTOCOL.md §12) always replaces
    // whatever's in `input` with a clear, red notice - nothing typed there
    // can ever be submitted (`handle_input_key` refuses it outright). An
    // offline DM peer gets the same red placeholder only while `input` is
    // actually empty: typing is no longer blocked for that case alone
    // (`/endotp` must still be composable and submitted while a peer is
    // unreachable - `handle_input_key`'s doc), so the moment there's
    // something typed, show it rather than hiding it behind a fixed notice
    // the user would otherwise be typing blind past.
    // The pad marks the bar it is typed into, not just the rows it has
    // already protected: while a session is open, everything sent from
    // here goes under it (`docs/PROTOCOL.md` §16.2 - there is no way to
    // send that person a plain message meanwhile), and this says so at the
    // moment it matters rather than only afterwards. Shown even over the
    // placeholders below, since it is a fact about the room rather than
    // about what is currently typed.
    let pad_prefix = state
        .active_private_room
        .is_some_and(|peer| state.is_otp_active(peer))
        .then(|| format!("{OTP_ICON} "));

    let mut spans = if dm_peer_trust_gated {
        vec![Span::styled(
            "(identity not verified)",
            Style::default().fg(Color::Red),
        )]
    } else if dm_peer_offline && state.input.is_empty() {
        vec![Span::styled(
            "(user offline)",
            Style::default().fg(Color::Red),
        )]
    } else {
        vec![Span::raw(state.input.as_str())]
    };
    if let Some(prefix) = &pad_prefix {
        spans.insert(
            0,
            Span::styled(prefix.clone(), Style::default().fg(OTP_TAG_COLOR)),
        );
    }
    if state.recording {
        let dot = if state.blink_on { "\u{23FA}" } else { " " };
        spans.push(Span::styled(
            format!(" {dot} recording..."),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);

    // Only show a blinking cursor here when this bar is actually focused,
    // nothing else (e.g. the join-channel popup) is drawn on top of it, and
    // there's actually text to edit (not one of the placeholders above).
    if state.focus == Focus::Input
        && state.mode == Mode::Normal
        && !dm_peer_trust_gated
        && (!dm_peer_offline || !state.input.is_empty())
    {
        // Past the pad marker, when there is one - the cursor belongs
        // where the next character will actually land.
        let offset = pad_prefix.as_deref().map(display_width).unwrap_or(0)
            + state.input.chars().count() as u16;
        let cursor_x = inner.x + offset.min(inner.width.saturating_sub(1));
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
/// How many terminal cells `s` takes up, measured exactly the way ratatui
/// measures it when laying the same text out. Anything sized from this and
/// the text drawn into it therefore agree by construction, however many
/// double-width emoji are in the string - which a `chars().count()` would
/// not, and which every column this app aligns depends on (the call
/// roster, the help overlay's two columns, the details popup).
pub(crate) fn display_width(s: &str) -> u16 {
    Span::raw(s).width() as u16
}

/// What the info popup calls the time a row carries, per direction: a row
/// this client sent was sent then, a row that arrived was received then,
/// and claiming otherwise would put words in the sender's mouth.
pub const SENT_AT_LABEL: &str = "sent_at";
pub const RECEIVED_AT_LABEL: &str = "received_at";

/// What the info popup says on a row that tracks no delivery at all - an
/// incoming message, a presence notice, or an outgoing row that is not a
/// text message.
pub const NO_DELIVERY_INFO: &str = "no delivery information for this message";

/// The labels down the info popup's encryption block, in the order they
/// appear. The three `Key *` ones are the OTP layer's alone
/// (`MessageCrypto::Otp`) - which sequence of the pad this message was,
/// where in the pad its key bytes started, and which key file they came
/// out of (`docs/PROTOCOL.md` §16).
pub const ENCRYPTION_LABEL: &str = "encryption";
pub const KEY_LABEL: &str = "key";
pub const KEY_SEQ_LABEL: &str = "key_seq";
pub const KEY_OFFSET_LABEL: &str = "key_offset";
pub const KEY_FILE_LABEL: &str = "key_file";

/// What stands in for a key id on a channel send, which is sealed once per
/// member with that member's own key - there is no single key to name.
pub const KEY_PER_RECIPIENT: &str = "one per recipient";

/// What the popup says on a row this client wrote itself - a presence
/// notice, or the app's own narration of an OTP handshake. Nothing about
/// those lines travelled, so there is no encryption to report.
pub const NO_CRYPTO_INFO: &str = "not an encrypted message";

/// The encryption block for one row, as `(label, value)` pairs in display
/// order. Split out from the rendering so the popup can size itself off
/// the same lines it is about to draw, and so a test can read what a row
/// reports without going through a frame.
pub fn crypto_lines(crypto: Option<&MessageCrypto>) -> Vec<(&'static str, String)> {
    let Some(crypto) = crypto else {
        return vec![(ENCRYPTION_LABEL, NO_CRYPTO_INFO.to_string())];
    };
    let mut lines = vec![(ENCRYPTION_LABEL, crypto.method_label().to_string())];
    match crypto {
        MessageCrypto::Envelope { key_id, .. } => {
            lines.push((
                KEY_LABEL,
                key_id
                    .clone()
                    .unwrap_or_else(|| KEY_PER_RECIPIENT.to_string()),
            ));
        }
        MessageCrypto::Otp {
            seq,
            offset,
            key_path,
            ..
        } => {
            lines.push((KEY_SEQ_LABEL, seq.to_string()));
            lines.push((KEY_OFFSET_LABEL, offset.to_string()));
            lines.push((KEY_FILE_LABEL, key_path.clone()));
        }
    }
    lines
}

/// One message's details: when it happened, and - for a message this
/// client sent - every user it was sent to with that user's own delivery
/// state (`docs/SPEC.md` "Delivery acknowledgments"). Opened with `i` on
/// the message log and closed with `i` or Esc. Reads the row live rather
/// than from a snapshot, so a recipient acknowledging while it is open
/// turns their line green under the cursor.
fn render_message_info_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(index) = state.message_info else {
        return;
    };
    let Some(entry) = state.current_log().get(index) else {
        return;
    };

    let time_label = if entry.outgoing {
        SENT_AT_LABEL
    } else {
        RECEIVED_AT_LABEL
    };
    let time_line = format!("{time_label}: {}", entry.sent_at);
    let recipients: &[DeliveryRecipient] = entry
        .delivery
        .as_ref()
        .map(|d| d.recipients.as_slice())
        .unwrap_or_default();

    // How this row's content was protected (`MessageCrypto`), as a block
    // of `label: value` lines with the values in one column - the same
    // shape the OTP session header uses for the same figures.
    let crypto = crypto_lines(entry.crypto.as_ref());
    let crypto_label_width = crypto.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let crypto_rendered: Vec<String> = crypto
        .iter()
        .map(|(label, value)| format!("{label:<crypto_label_width$}  {value}"))
        .collect();

    // Every status column is the same width, so the words line up under
    // each other however uneven the nicknames are; the names column is
    // sized by the longest name so nothing is truncated that fits.
    let status_width = [
        UNDELIVERED_LABEL,
        DELIVERED_LABEL,
        LISTENED_LABEL,
        SAVED_LABEL,
    ]
    .iter()
    .map(|l| l.len())
    .max()
    .unwrap_or(0)
        + DELIVERY_ARROW.len()
        + 1;
    let name_width = recipients
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    let content_width = (name_width + GAP_COLUMNS + status_width)
        .max(time_line.chars().count())
        .max(NO_DELIVERY_INFO.len())
        .max(
            crypto_rendered
                .iter()
                .map(|l| l.chars().count())
                .max()
                .unwrap_or(0),
        );
    let max_allowed = (area.width as u32 * 9 / 10) as u16;
    let popup_width = ((content_width + 4) as u16).min(max_allowed);
    // The time line, a blank, the encryption block, a blank, then one line
    // per recipient - or the single "nothing to report" line, which is why
    // that part floors at one rather than sizing straight off
    // `recipients.len()`.
    let body_lines = 3 + crypto_rendered.len() + recipients.len().max(1);
    let popup_height = ((body_lines + 2) as u16).min((area.height as u32 * 9 / 10) as u16);
    let popup = centered_rect(popup_width, popup_height, area);

    let block = Block::default()
        .title("Message details (i / Esc to close)")
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let mut lines = vec![
        Line::from(Span::styled(
            time_line,
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    for line in &crypto_rendered {
        lines.push(Line::from(Span::styled(
            line.clone(),
            Style::default().fg(Color::Cyan),
        )));
    }
    lines.push(Line::from(""));
    if recipients.is_empty() {
        lines.push(Line::from(Span::styled(
            NO_DELIVERY_INFO,
            Style::default().fg(Color::DarkGray),
        )));
    }
    for recipient in recipients {
        let (label, color) = recipient_label(recipient, &entry.body);
        // The status is right-aligned against the popup's own inner width,
        // so it stays flush with the right edge rather than with whatever
        // the longest nickname happened to be. Same arrow, same colour, as
        // the log row this popup was opened from.
        let status = format!("{DELIVERY_ARROW} {label}");
        let used = recipient.name.chars().count() + status.len();
        let pad = (inner.width as usize).saturating_sub(used).max(1);
        lines.push(Line::from(vec![
            Span::raw(recipient.name.clone()),
            Span::raw(" ".repeat(pad)),
            Span::styled(
                status,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Minimum space kept between a nickname and its status column when the
/// popup is sized, so the two never touch.
const GAP_COLUMNS: usize = 2;

/// The help overlay's own title, which is also how a test finds the box.
pub const HELP_POPUP_TITLE: &str = "Help (Ctrl+H / Esc to close, arrows to scroll)";

/// The two-space indent every entry under a heading carries, and the gap
/// between the keys column and the description column.
const HELP_INDENT: usize = 2;
const HELP_COL_GAP: usize = 2;

/// The narrowest the description column is ever squeezed to. Below this
/// the overlay lets its lines run past the border and be clipped rather
/// than wrapping every other word onto a line of its own - and, because
/// the wrapped line count therefore stops growing here, it is also what
/// makes `help_total_lines` a genuine bound at every width.
const HELP_MIN_DESC_COL: usize = 24;

/// How wide the overlay's first column is: the widest keys or command in
/// it, so every description in the whole page starts in the same column
/// (`docs/SPEC.md` Functionality #7).
fn help_keys_col() -> usize {
    HELP_BODY
        .iter()
        .filter_map(|line| match line {
            HelpLine::Item { keys, .. } => Some(display_width(keys) as usize),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

/// What is left for the description column inside an overlay `inner_width`
/// columns wide, floored at `HELP_MIN_DESC_COL`.
fn help_desc_col(inner_width: u16) -> usize {
    (inner_width as usize)
        .saturating_sub(HELP_INDENT + help_keys_col() + HELP_COL_GAP)
        .max(HELP_MIN_DESC_COL)
}

/// `text` broken at spaces into pieces of at most `width` display columns.
///
/// A single word wider than the column - a path, a URL - is left over-long
/// on a line of its own rather than cut mid-word: half a path is worse to
/// read than one that runs to the edge, and it is the only case where a
/// line can exceed the column at all.
fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_width = 0usize;
    for word in text.split_whitespace() {
        let word_width = display_width(word) as usize;
        let needed = if current.is_empty() {
            word_width
        } else {
            current_width + 1 + word_width
        };
        if !current.is_empty() && needed > width {
            lines.push(std::mem::take(&mut current));
            current_width = 0;
        }
        if !current.is_empty() {
            current.push(' ');
            current_width += 1;
        }
        current.push_str(word);
        current_width += word_width;
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

/// The whole overlay laid out for a description column `desc_col` wide:
/// headings flush left, everything else with its keys in the first column
/// and its description - wrapped, every continuation line included -
/// in the second.
fn help_lines_for_column(desc_col: usize) -> Vec<Line<'static>> {
    let keys_col = help_keys_col();
    let indent = " ".repeat(HELP_INDENT);
    let hanging = " ".repeat(HELP_INDENT + keys_col + HELP_COL_GAP);
    let heading_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let description_style = Style::default().fg(Color::DarkGray);

    let mut lines: Vec<Line<'static>> = Vec::new();
    for entry in HELP_BODY {
        match entry {
            HelpLine::Heading(title) => {
                lines.push(Line::from(Span::styled(*title, heading_style)));
            }
            HelpLine::Blank => lines.push(Line::from("")),
            // The keys are what the eye is looking for, so they keep the
            // brighter default colour and the description behind them is
            // gray.
            HelpLine::Item { keys, text } => {
                let pad = " ".repeat(keys_col.saturating_sub(display_width(keys) as usize));
                for (i, chunk) in wrap_to_width(text, desc_col).into_iter().enumerate() {
                    if i == 0 {
                        lines.push(Line::from(vec![
                            Span::raw(indent.clone()),
                            Span::styled(*keys, Style::default().add_modifier(Modifier::BOLD)),
                            Span::raw(format!("{pad}{}", " ".repeat(HELP_COL_GAP))),
                            Span::styled(chunk, description_style),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::raw(hanging.clone()),
                            Span::styled(chunk, description_style),
                        ]));
                    }
                }
            }
            HelpLine::Note(text) => {
                for chunk in wrap_to_width(text, desc_col) {
                    lines.push(Line::from(vec![
                        Span::raw(hanging.clone()),
                        Span::styled(chunk, description_style),
                    ]));
                }
            }
        }
    }
    lines
}

/// The overlay laid out for the terminal actually in front of the user.
fn help_rendered_lines(inner_width: u16) -> Vec<Line<'static>> {
    help_lines_for_column(help_desc_col(inner_width))
}

/// The most lines the overlay can ever come to, which is its length at the
/// narrowest description column it will use (`HELP_MIN_DESC_COL`) -
/// wrapping only ever produces fewer lines as the column widens.
///
/// `UiState::handle_key` needs a bound that does not depend on a terminal
/// it cannot see, so that `End` lands somewhere definite and a further
/// `PageDown` moves nothing; the exact figure for this frame is clamped
/// again at render time.
pub fn help_total_lines() -> usize {
    static TOTAL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *TOTAL.get_or_init(|| help_lines_for_column(HELP_MIN_DESC_COL).len())
}

/// A staged `.txt` receive's content, read-only and scrollable
/// (`UiState::file_preview`, opened by `Enter` on a
/// `FileTransferStatus::Received` row). Modeled directly on
/// `render_help_popup` below: the whole frame rather than a centered box
/// (plenty of terminals are narrower than one real line of typed text),
/// a stored scroll offset clamped against the actual rendered height here
/// rather than in `handle_key` (which has no reason to know the terminal
/// size), and a bottom hint line rather than a separate status bar.
fn render_txt_preview_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    let Some(preview) = state.file_preview.as_ref() else {
        return;
    };
    let popup = area;
    let block = Block::default()
        .title(format!("Preview: {}", preview.filename))
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let width = inner.width as usize;
    let mut lines: Vec<Line<'static>> = Vec::new();
    for line in preview.content.split('\n') {
        if line.is_empty() {
            lines.push(Line::from(""));
            continue;
        }
        for chunk in wrap_to_width(line, width) {
            lines.push(Line::from(chunk));
        }
    }
    if preview.truncated {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "--- preview truncated - the saved file will still be complete ---",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "d: save   Esc: close",
        Style::default().fg(Color::DarkGray),
    )));

    let visible_rows = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_rows);
    let scroll = preview.scroll.min(max_scroll);

    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

fn render_help_popup(frame: &mut Frame, area: Rect, state: &UiState) {
    // The whole screen, from the row above the header down through the
    // compose bar (`docs/SPEC.md` Functionality #7). Help is the one
    // overlay nothing behind it can usefully be read alongside: it is a
    // page to read, several screens long on a small terminal, and every
    // column it does not take is a column its key table has to wrap in.
    // Taking the frame outright also means the widest line is clipped
    // only by a terminal genuinely too narrow for it.
    let popup = area;
    let block = Block::default()
        .title(HELP_POPUP_TITLE)
        .borders(Borders::ALL);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    // Both the number of lines the text comes to and how many of them fit
    // depend on the terminal size at render time, which `UiState` has no
    // reason to know - so the scroll offset stored in state is clamped
    // precisely here rather than in `handle_key` (which only loosely
    // clamps against `help_total_lines`). This is what actually makes the
    // content scrollable rather than just truncated: without it, a
    // terminal shorter than the full help text would permanently hide
    // everything past the bottom of the popup.
    let lines = help_rendered_lines(inner.width);
    let visible_rows = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_rows);
    let scroll = state.help_scroll.min(max_scroll);

    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

/// The full-screen, red-bordered takeover shown once a superadmin's
/// `/deactivate` lands against this account. Structural copy of
/// `render_help_popup` - the only other place this codebase takes
/// `frame.area()` directly rather than `centered_rect`, for the same
/// reason: nothing behind it should be readable, or in this case even
/// visible, once it's up. Escape is the only key `handle_key`'s matching
/// top-priority tier answers, which ends the whole session - there is
/// nothing to "return to" underneath, unlike `help_open`.
fn render_account_deactivated_modal(frame: &mut Frame, area: Rect, reason: &str) {
    let popup = area;
    let block = Block::default()
        .title("Account deactivated")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let text = format!("Your account has been deactivated (\"{reason}\")\n\nPress ESCAPE to close aloo");
    let paragraph = Paragraph::new(text)
        .style(Style::default().fg(Color::Red))
        .alignment(Alignment::Center)
        .wrap(ratatui::widgets::Wrap { trim: true });
    // Vertically centered within the bordered area, the same way a small
    // confirm popup centers itself in its own box - just at the scale of
    // the whole screen here.
    let centered = Rect {
        y: inner.y + inner.height / 3,
        height: inner.height.saturating_sub(inner.height / 3),
        ..inner
    };
    frame.render_widget(paragraph, centered);
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
    frame.render_widget(Clear, popup);
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
