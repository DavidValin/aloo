//! The help overlay's source text, and the layout that fits it to a
//! terminal.
//!
//! Two halves that belong together and to nothing else. [`HELP_BODY`] is
//! the text itself, written unwrapped: where a description breaks is
//! decided at render time against the terminal actually in front of the
//! user, never by hand here - a hand-wrapped line can only be right for
//! one width. The functions below are that decision.
//!
//! `render.rs` draws the result; nothing else in the app reads any of it.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::render::display_width;

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

pub(crate) const HELP_BODY: &[HelpLine] = &[
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
        text: "leave the selected channel: its tab disappears, and everything said in it \
               goes with it - message history lives in memory only. Inside a private room \
               it closes that conversation instead, on the same terms: the room is \
               forgotten and drops off the DM selector. That is not a block and not an \
               unfriending - their next message opens the room again, empty. Anything you \
               want to keep, keep with autosave_messages or Ctrl+E before leaving.",
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
               own DELIVERED / UNDELIVERED state (log focused). QUEUED there means it is \
               being held on disk until that person is reachable again, rather than \
               merely unacknowledged (queue_send_messages, Ctrl+S). i or Esc closes it \
               again.",
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
    HelpLine::Item {
        keys: "@nickname",
        text: "writing @<someone's nickname> in a channel or a DM makes their client play \
               a sound as it lands, so they notice a message meant for them without \
               watching every channel. It has to be their whole nickname - bob@host is an \
               address, and @bobby is not @bob - and it is case-sensitive, since the \
               server tells bob and Bob apart. Silence it with sound_notifications \
               (Ctrl+S, General).",
    },
    HelpLine::Note(
        "Someone unreachable does not cost you the message: it is held on disk and sent \
         the moment they are back, in the order you wrote it, surviving a restart of aloo \
         (queue_send_messages, on by default - press i on the row to see QUEUED). Text and \
         voice only; a file transfer needs them there to accept it.",
    ),
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
        text: "same, from anywhere - this one really is OS-wide, working while another \
               window has focus. Change the combo or turn it off under Ctrl+S (General), \
               or in ~/.aloo/settings.",
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
               \u{1F507} in the sidebar. Kept in ~/.aloo/settings. Never affects a call. \
               voice_autoplay (Ctrl+S, General) is the blanket version of this: with it \
               off nobody's voice plays itself, so a per-person mute only decides \
               anything while it is on.",
    },
    HelpLine::Item {
        keys: "/unmute-voice <nickname>",
        text: "undo it; either, with no nickname, lists who is currently muted.",
    },
    HelpLine::Item {
        keys: "\u{1F507}",
        text: "beside a name in the sidebar, that one person's voice is muted. On its own \
               in the header, red, followed by 'playback off': voice_autoplay is off \
               (Ctrl+S, General) and *nobody's* voice is playing - messages still arrive \
               and still log, Enter still replays them. Only one of the two ever shows: \
               with playback off there is no point singling anyone out, so the sidebar \
               marks nobody and the header speaks instead. Your mute list is untouched \
               either way and applies again the moment playback comes back.",
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
        text: "settings, in three tabs (Tab switches, \u{2191}/\u{2193} pick a field, Space \
               flips a switch, typing fills a box, Esc closes). Every change is saved to \
               ~/.aloo/settings the moment you make it - there is no Save button, and a \
               gray line under each tab says what every field does, including whether it \
               takes effect now or on the next start. General: whether push-to-talk works \
               while another window has focus and with which shortcut, whether arriving \
               voice messages play themselves, whether the end-of-message tone sounds, \
               whether event sounds do, whether messages are written to (and read back \
               from) ~/.aloo/exports, and whether a message for someone unreachable is \
               held on disk until they are back (queue_send_messages, on by default - \
               text and voice, in the order you sent them; files are not queued). In an \
               /otp session writing a message spends its pad there and then, and the \
               sealed messages go out one at a time in order, each waiting for the \
               previous one's acknowledgement; with queueing off a message to someone \
               unreachable is refused instead, so no pad is spent. OTP: \
               the low-key warning threshold \
               and which otp binary to run. Direct Punch: reach someone with no server \
               involved - 'a' adds a target with their nickname, and where their client is \
               (an IPv4/IPv6 address or hostname, optionally :port), and how often to try \
               - every_1m, every_5m, ... every_55m or every_1h. Every schedule restarts at \
               the top of the hour, so every_1m tries at :00, :01, :02... and every_1h at \
               :00 only - both sides trying at the same clock moments, with nothing \
               coordinating it but that. It only works if they've added you back the same \
               way - your nickname, your public host/IP, and the *same* frequency - \
               otherwise your two attempts never land at the same moment. If your own \
               address moves (an ordinary home connection), turn on \
               noip_when_no_server_and_direct_punch_is_active on that same tab and fill in \
               the No-IP hostname/username/password - aloo keeps that hostname pointed at \
               wherever you currently are, so you can give the other person a fixed \
               hostname to punch at instead of a raw address that might change. Once at \
               least one target is configured the header shows <active>/<total> (next: \
               <time>) - how many of them have a link right now, out of how many you \
               configured, and how long until the next attempt - green once every one is \
               connected, yellow otherwise. Nothing is shown when none are configured.",
    },
    HelpLine::Item {
        keys: "Ctrl+M",
        text: "mute/unmute your own microphone while on a call, from wherever you are in \
               aloo - no need to open the call modal and find your own row first. Unlike \
               the push-to-talk shortcut this is not an OS-wide one: it only works while \
               aloo has focus. Does nothing when you are not on a call. Needs a terminal \
               that can tell Ctrl+M apart from Enter (the two are the same byte \
               otherwise); where it can't, 'm' on your own row in the call roster does \
               the same thing and always works.",
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
pub(crate) fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
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
pub(crate) fn help_rendered_lines(inner_width: u16) -> Vec<Line<'static>> {
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
