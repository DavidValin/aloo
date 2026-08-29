//! Wire protocol shared by the client and the server.
//!
//! Every message is bincode-encoded and sent over TCP as a frame:
//! a 4-byte big-endian length prefix followed by that many payload bytes.
//! The server never needs to see plaintext: `Envelope` always carries a
//! sealed PQ-hybrid send addressed to exactly one recipient (see
//! `crypto::pq::seal_send`), so channel messages are relayed once per
//! recipient rather than broadcast as a single shared ciphertext.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Refuse to allocate for a frame larger than this many bytes. Generous
/// enough for a chunky voice message's worth of sealed chunks, small
/// enough to stop a corrupt/hostile length prefix from exhausting memory.
pub const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

/// The longest a `Content::Text` body may be, in `char`s. Enforced
/// client-side only - a text message's plaintext never reaches the server
/// (it travels inside `Envelope::blocks`, sealed before it ever leaves the
/// sender), so there is no server-side check to add; this constant is the
/// p2p-protocol-level convention every client honors before encrypting.
/// `UiState::handle_input_key` refuses further keystrokes at this length,
/// and `UiState::handle_paste` applies the same cap defensively (though a
/// paste long enough to reach it is always diverted to a file transfer
/// first - see `client::file_transfer::PASTE_TO_FILE_CHAR_THRESHOLD`,
/// which is well under this).
pub const TEXT_MESSAGE_MAX_LEN: usize = 10_000;

/// What the server answers a relay whose target is not connected
/// (`server::route_peer_link_request`, `route_key_rotation`).
///
/// A shared constant rather than two independent strings because the
/// client matches on it: these two relays are internal protocol
/// plumbing - a link being signalled, a key rotation being offered - that
/// nobody typed a command to trigger, so their failure is logged but must
/// never reach the screen as if it answered something the user did. Every
/// other `ServerMessage::Error` does reach it (a channel-admin refusal,
/// a superadmin refusal), which is exactly why the two need telling
/// apart. See `client::session`'s `ServerMessage::Error` arm.
pub const UNKNOWN_RECIPIENT: &str = "unknown recipient";
/// The counterpart for a relay whose *sender* the server no longer knows,
/// which reaches the screen for the same reason: it never answered
/// anything the user typed.
pub const UNKNOWN_SENDER: &str = "unknown sender";

/// How often a connected client sends `ClientMessage::Heartbeat` on the
/// control channel (docs/PROTOCOL.md §4.1). Actual message content never
/// touches the server (it travels peer-to-peer, §7.1), so without this a
/// perfectly healthy session that is just quietly chatting would leave the
/// control channel silent for its entire lifetime - the heartbeat is what
/// gives the server anything at all to measure liveness by.
pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the server waits for *any* message - a heartbeat or otherwise -
/// before deciding a client's connection is dead and disconnecting it (same
/// cleanup path as a clean TCP close: §4, §6.4). Three missed heartbeats'
/// worth, the same 1:3 interval-to-timeout ratio `client::p2p` uses between
/// `KEEPALIVE_INTERVAL` and `LINK_IDLE_TIMEOUT`, so a couple of lost beats
/// from network jitter alone don't cost a user their session.
pub const HEARTBEAT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("frame of {0} bytes exceeds MAX_FRAME_LEN")]
    FrameTooLarge(u32),
}

pub type Result<T> = std::result::Result<T, ProtoError>;

/// The decode limit is not decoration - without it, decoding is a remote
/// denial of service.
///
/// Bincode reads a length prefix before every `Vec`/`String` and reserves
/// that much straight away. Those prefixes are inside the payload, so
/// `MAX_FRAME_LEN` never sees them: a frame of a dozen bytes can claim a
/// vector of billions and abort the process on the failed allocation
/// before a single field is read. Capping the decoder at the largest a
/// frame may legitimately be turns that into an ordinary decode error.
///
/// Encoding shares the config, which is right: a message too large to
/// decode is one there is no point sending.
fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<{ MAX_FRAME_LEN as usize }>()
}

/// Bincode-encodes `msg` (no length prefix).
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(msg, bincode_config())
        .map_err(|e| ProtoError::Encode(e.to_string()))
}

/// Decodes a value previously produced by `encode`.
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, bincode_config())
        .map_err(|e| ProtoError::Decode(e.to_string()))?;
    Ok(value)
}

/// Prepends a 4-byte big-endian length prefix to `payload`.
pub fn frame(payload: &[u8]) -> Result<Vec<u8>> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| ProtoError::FrameTooLarge(u32::MAX))?;
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// If `buf` starts with a complete frame, returns the payload slice and the
/// total number of bytes (prefix + payload) it occupied.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(&[u8], usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let total = 4 + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((&buf[4..total], total)))
}

/// Encodes and writes one framed message to an async stream.
pub async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let payload = encode(msg)?;
    let framed = frame(&payload)?;
    writer.write_all(&framed).await?;
    Ok(())
}

/// Reads and decodes one framed message from an async stream.
/// Returns `Ok(None)` on a clean EOF before any bytes of a new frame arrive.
pub async fn read_message<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<Option<T>> {
    let mut len_buf = [0u8; 4];
    if let Err(e) = reader.read_exact(&mut len_buf).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(ProtoError::Io(e));
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(ProtoError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(decode(&payload)?))
}

// ---------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UserId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: UserId,
    pub name: String,
    /// Bincode-encoded `crypto::pq::PqPublicBundle` - this user's
    /// bootstrap keybundle, used by peers to seal messages to them (see
    /// `crypto::pq::seal_send`) and to pin their identity (§13). The
    /// field keeps its historical `_der` name because the wire shape is
    /// unchanged: it is still just opaque bytes to the server.
    pub public_key_der: Vec<u8>,
    pub key_mode: KeyMode,
}

/// Which `my_key` type a user connected with - broadcast (via `Identify`
/// → `UserInfo`) so every peer can show it next to that user's name
/// (`label()` below). `PqHybrid` is the only one there is - peer-to-peer
/// traffic is always post-quantum hybrid, optionally wrapped in a
/// one-time pad (§16). The field stays on the wire so a peer
/// implementation still announces *which* scheme it speaks rather than
/// leaving it implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMode {
    /// `pq_hybrid`: a static keybundle loaded from a file, signed with
    /// ML-DSA-87+RSA4096 and encrypted with AES-256-GCM under an
    /// ML-KEM-1024+RSA4096-wrapped key, whose encryption keys rotate per
    /// peer during the session (§13, §13.10).
    PqHybrid,
}

impl KeyMode {
    /// This mode's tag, exactly as rendered (SPEC.md Functionality #3);
    /// `format_with_name` combines it with a name. `🛡️` marks the one
    /// tier this app offers: quantum-resistant signing *and* key
    /// exchange, each hedged with RSA-4096 (§13).
    pub fn label(self) -> &'static str {
        match self {
            KeyMode::PqHybrid => "\u{1F6E1}\u{FE0F} PQH",
        }
    }

    /// Combines `name` with this mode's tag: `name TAG` - the tag always
    /// trails the name as an annotation on it, rather than a
    /// classification label sitting in front of it.
    pub fn format_with_name(self, name: &str) -> String {
        format!("{name} {}", self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelKind {
    Public,
    Private,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub kind: ChannelKind,
}

/// One row of `ServerMessage::UsersList` - a registered nickname and
/// which channels it currently administers, empty for one that
/// administers none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAdminInfo {
    pub nickname: String,
    pub admin_of: Vec<String>,
}

/// Why a password-protected private channel's `JoinChannel` was rejected
/// (see `ServerMessage::ChannelJoinRejected`, docs/PROTOCOL.md §6.5/§6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelJoinRejection {
    /// The channel is password-protected and this `JoinChannel` carried no
    /// password at all - the client should open the password-entry popup
    /// so the user can type one and resubmit.
    PasswordRequired,
    /// A password was supplied but it doesn't match.
    WrongPassword,
    /// `CHANNEL_MAX_PASSWORD_ATTEMPTS` wrong attempts against this (source
    /// address, channel name) pair already tripped the ban within the last
    /// `CHANNEL_PASSWORD_BAN_DURATION` - further attempts are refused
    /// without even checking the password given. Scoped to (source IP,
    /// channel name), never a nickname - see `UserBanned` for that.
    Banned,
    /// The channel admin has `/ban`-ed this nickname - distinct from
    /// `Banned` above, which is the unrelated IP-scoped brute-force
    /// protection. A future `/unban` reverses this.
    UserBanned,
    /// The channel is currently locked to an allowlist (`/lock-joins`)
    /// and this nickname isn't on it (the admin is always implicitly
    /// allowed into their own channel, regardless of the list).
    NotOnAllowlist,
}

/// One message body (text, file, or voice), encrypted for a single
/// recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub content: Content,
    /// The sealed send, as a single bincode-encoded
    /// `crypto::pq::HybridEnvelope` element (`crypto::pq::seal_send` /
    /// `open_send`). `Vec<Vec<u8>>` rather than one `Vec<u8>` because the
    /// field predates PQ-hybrid being the only scheme, and peers already
    /// concatenate every block's plaintext in order.
    pub blocks: Vec<Vec<u8>>,
}

/// `FileOffer` carries the *offer* of a file transfer as an ordinary
/// envelope, giving the offer (who's sending what, how big) the same
/// per-recipient PQ-hybrid privacy as a text message; its decrypted plaintext
/// is a bincode-encoded `file_transfer::FileOfferPayload`. The file bytes
/// themselves are never enveloped - once accepted they stream as raw
/// `FileChunk` blocks like voice's PCM (§7.3), so there's no
/// `Content::File` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    /// A plain chat message. The text itself lives in `Envelope::blocks`,
    /// never here - capped client-side at `TEXT_MESSAGE_MAX_LEN` chars
    /// before it is ever encrypted.
    Text,
    FileOffer,
    /// Carries a bincode-encoded `crypto::otp::OtpKeySetupPayload`: one side
    /// of the OTP-layer provisioning handshake, sent over an ordinary
    /// `pq_hybrid` envelope (`client::otp::initiate_provisioning`). Trailing
    /// and matched only via `!=` elsewhere in this codebase, so this is
    /// non-breaking - an old peer that doesn't recognise it simply never
    /// completes provisioning.
    OtpKeySetup,
    /// Carries a bincode-encoded `crypto::otp::OtpSessionRequestPayload`:
    /// the "already have a key" branch of the `/otp` command - proposes
    /// starting a session on an existing keychain contact, no key material
    /// attached. Still requires an explicit accept, answered the same way
    /// as `OtpKeySetup` is - via `OtpKeySetupAck`.
    OtpSessionRequest,
    /// Carries a bincode-encoded `crypto::otp::OtpKeySetupAckPayload`, the
    /// reply to `OtpKeySetup` or `OtpSessionRequest`
    /// (`client::otp::accept_invite`/`reject_invite`).
    OtpKeySetupAck,
    /// `FileOffer`'s voice counterpart, only ever sent when OTP is active
    /// for the recipient (a non-OTP contact keeps live-streamed voice,
    /// which has no offer/accept step at all). Its plaintext is a
    /// bincode-encoded `client::otp::VoiceOfferPayload` - kept out of this
    /// cleartext tag, same reasoning as `FileOffer`'s size/filename - and
    /// the whole offer then goes through the pad exactly as a file offer
    /// does, which is what keeps the duration hidden under `Direct`
    /// framing too (§16.2). Always auto-accepted on arrival
    /// (`client::otp::on_voice_offer`) - unlike a file offer, there's no
    /// reject path - but it still spends and acknowledges a slot of its
    /// own, with the recording a second one.
    VoiceOffer,
    /// Carries the sender's `client::device_id` as raw UTF-8 bytes -
    /// purely informational (docs/PROTOCOL.md §12.7), shown in an
    /// impersonation review popup next to the last one recorded for that
    /// nickname. A distinct `Content` tag (rather than reusing `Text`)
    /// keeps it out of the visible chat log dispatch path - like every
    /// other `Content` variant, this tag itself is unauthenticated
    /// metadata alongside the encrypted `blocks`, not part of any
    /// signature (`session::on_device_id_announce` checks it defensively
    /// before trusting the plaintext, same as any other receiver-side
    /// sanity check).
    DeviceIdAnnounce,
    /// Carries the sender's currently-joined channel names, bincode
    /// encoded - how a peer reached with no server involved
    /// (`docs/PROTOCOL.md` §7.1.5) is placed in the channels both sides
    /// share, since no server is tracking membership for either of them.
    /// Sealed and signed like every other content type, which is what
    /// makes it an identity claim rather than an assertion: a nickname on
    /// an unauthenticated punch datagram names nobody, while an envelope
    /// that opens under a pinned key proves who sent it.
    ChannelPresence,
    /// Carries a bincode-encoded `crypto::otp::OtpEndSessionPayload`: either
    /// participant's `/endotp` unilaterally tearing the session down
    /// (`client::otp::handle_end_otp_command`). Sent over an ordinary
    /// `pq_hybrid` envelope, never pad-wrapped, the same reasoning
    /// `OtpKeySetup`'s doc gives - the pad layer cannot protect a message
    /// that ends its own session, and by the time this is sent the local
    /// pad may already be destroyed. Trailing and matched only via `!=`
    /// elsewhere, so this is non-breaking - an old peer that doesn't
    /// recognise it simply never receives the notice.
    OtpEndSession,
    /// Carries a bincode-encoded `crypto::otp::OtpEndSessionPayload`, the
    /// reply to `OtpEndSession` (`client::otp::on_end_session`) - purely an
    /// acknowledgement (ending is unilateral, never refused), so the
    /// initiator's own durably-retried notice (`OtpStore::pending_end_notices`)
    /// stops resending once this arrives.
    OtpEndSessionAck,
}

/// Messages the client sends to the server - pure signaling: auth,
/// identify, channel membership, and helping two clients find each
/// other's address. Message/voice/file *content* never passes through
/// here; it travels the direct UDP link instead (`crate::client::p2p`,
/// `crate::p2p_proto`, PROTOCOL.md "Direct peer-to-peer transport").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Transports a secret to the server's `Hello` offer, turning the
    /// control channel on. Must be the client's first message; everything
    /// after it, in both directions, is sealed (`crate::control`).
    SecureChannel(crate::control::ControlAccept),
    /// The one way in (docs/PROTOCOL.md §5): the nickname this client
    /// wants to be known as and that nickname's password, checked against
    /// the server's users registry (`crate::server::users_registry`). The
    /// first message sent *inside* the tunnel `SecureChannel` established,
    /// so the password is never on the wire in the clear.
    Auth {
        nickname: String,
        password: String,
    },
    /// Answers an `AuthResult { activation_pending: true }` (§5.2): the
    /// activation code the server emailed at registration. Accepted only
    /// at that exact point in the handshake, and only once per connection
    /// - a wrong code closes the connection, so guessing costs a
    /// reconnect per attempt.
    Activate {
        code: String,
    },
    /// Asks the server to create an account (§5.3). Sent instead of `Auth`,
    /// right after `SecureChannel`, and answered with `RegisterResult`
    /// after which the server closes the connection either way - a
    /// registration is never also a login. Refused outright on a server
    /// whose `Hello` said `registration_open: false`.
    Register {
        nickname: String,
        password: String,
        email: String,
    },
    /// Sent once auth succeeds: this client's `my_key` public key. The
    /// nickname is the one `Auth` already authenticated - there is nothing
    /// to choose here any more.
    Identify {
        public_key_der: Vec<u8>,
        key_mode: KeyMode,
    },
    /// `/password <old> <new>`: changes the sender's own password
    /// (`server::users_registry::UsersRegistry::change_password`). Only
    /// reachable once already fully connected (past `Auth`/`Identify`),
    /// so the account is necessarily active already - `old_password` is
    /// re-checked anyway, exactly like `Auth` would, rather than trusting
    /// that this connection once authenticated with the current one; this
    /// is a fresh proof, not an admin override. Answered with
    /// `ChangePasswordResult`; the connection is otherwise unaffected
    /// either way - not even the credentials it originally authenticated
    /// with, since a live connection is never re-checked after `Auth`.
    ChangePassword {
        old_password: String,
        new_password: String,
    },
    /// Joins `name`, creating it first if needed. `kind` only matters for
    /// creation. `password` is `Some` only for a private join/create with
    /// a password typed - it either sets a new private channel's password
    /// or is compared against the existing one (docs/PROTOCOL.md §6.5).
    JoinChannel {
        name: String,
        kind: ChannelKind,
        password: Option<String>,
    },
    LeaveChannel {
        name: String,
    },

    /// The channel admin's `/delete-channel`: `name` must be a public
    /// channel currently administered by the sender - checked
    /// server-side regardless of the client's own idea of who's admin.
    /// Only ever targets the sender's currently-selected channel; there
    /// is no way to delete one by name alone.
    DeleteChannel {
        name: String,
    },
    /// The channel admin's `/ban <nickname>`. Force-removes `nickname`
    /// from `channel` if currently a member, and refuses their future
    /// joins to it until a matching `UnbanFromChannel`.
    BanFromChannel {
        channel: String,
        nickname: String,
    },
    /// The channel admin's `/unban <nickname>` - reverses `BanFromChannel`
    /// only; the nickname must still rejoin, which will now succeed.
    UnbanFromChannel {
        channel: String,
        nickname: String,
    },
    /// The channel admin's `/lock-joins`. `allowed: None` is the "All
    /// users" option - clears the lock entirely; `Some(list)` restricts
    /// *future* joins to that list (plus the admin, always implicitly).
    /// Already-joined members are unaffected either way.
    SetChannelJoinLock {
        channel: String,
        allowed: Option<Vec<String>>,
    },
    /// The channel admin's `/assign-admin <nickname>`: `nickname` must
    /// currently be a member of `channel`. Releases the sender's own
    /// admin status in the same stroke - a channel has exactly one admin.
    AssignChannelAdmin {
        channel: String,
        nickname: String,
    },

    /// A superadmin's `/deactivate <nickname> <reason>` - checked against
    /// `server_superadmin` server-side. Locks the named account out of
    /// logging in (`AuthCheck::Deactivated`) until a matching
    /// `AdminActivate`, and, if currently connected, pushes
    /// `ServerMessage::AccountDeactivated` to it.
    AdminDeactivate {
        nickname: String,
        reason: String,
    },
    /// A superadmin's `/activate <nickname>` - clears whatever is
    /// currently blocking that account's login: a still-pending emailed
    /// registration code, a prior `AdminDeactivate`, or both. Deliberately
    /// the same underlying "make this account able to log in right now"
    /// concept either way.
    AdminActivate {
        nickname: String,
    },
    /// A superadmin's `/remove-account <nickname>`: deletes the account
    /// outright and removes every channel it currently administers,
    /// notifying that channel's members.
    AdminRemoveAccount {
        nickname: String,
    },
    /// A superadmin's `/remove-channel <name>`: removes any channel
    /// outright (never `DEFAULT_CHANNEL_NAME`, even for a superadmin).
    /// Public-only in practice - a private channel's existence is never
    /// advertised to anyone outside its membership, so a superadmin has
    /// no name to act on for one it isn't already in.
    AdminRemoveChannel {
        name: String,
    },
    /// A superadmin's `/users`: every registered nickname on the server
    /// (`server::users_registry::UsersRegistry::nicknames`) and which
    /// channels each currently administers
    /// (`server::channels_registry::ChannelsRegistry::channels_administered_by`).
    /// Checked against `server_superadmin` server-side exactly like every
    /// other `Admin*` message; answered with `UsersList`.
    RequestUsersList,

    /// `pq_hybrid` only (`KeyMode::PqHybrid`, PROTOCOL.md §13.10): tells
    /// `to` to trust a freshly-rotated encryption key from now on.
    /// `new_public_key_der` and `signature` carry a bincode-encoded
    /// `crypto::pq::PqRotation` and its signature respectively - see
    /// `crypto::pq::sign_rotation`.
    RotateKey {
        to: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Proposes (or accepts, when replying to one) a direct UDP link to
    /// `peer`: `candidates` are this client's host and server-reflexive
    /// addresses, `link_nonce` its opaque token for the attempt (echoed in
    /// its `Ping`s). The server only relays this - it never sees anything
    /// from the resulting link itself. See `crate::client::p2p`.
    RequestPeerLink {
        peer: UserId,
        candidates: Vec<std::net::SocketAddr>,
        link_nonce: u64,
    },

    /// Sent every `HEARTBEAT_INTERVAL` for as long as the connection is
    /// open, so the server always has *something* to measure liveness by
    /// even during a session where no other control-channel message is
    /// ever sent (§4.1). Carries no data and gets no reply - receiving it
    /// (like receiving anything else) simply resets the server's
    /// `HEARTBEAT_TIMEOUT` clock for this connection.
    Heartbeat,

    /// Uploads one OTP mail for the server to hold until its recipient
    /// connects (docs/PROTOCOL.md §17) - the one deliberate exception to
    /// "content never touches the server", and even here only as an opaque
    /// blob: `ciphertext` is the whole mail sealed through the sender's
    /// one-time pad, which the server has no key material for. The sender's
    /// own registered nickname is what the server records as "from" - never
    /// anything client-claimed. Answered with `OtpMailResult`; a sender
    /// that never receives one retries with the *same* `mail_id` and the
    /// exact ciphertext recovered from `otp --recover-last --sent`, so the
    /// id doubles as the dedup key.
    OtpMailSend {
        /// Sender-generated, `crypto::otp::mail_id_is_valid`-shaped.
        mail_id: String,
        /// Recipient nickname, exactly as pinned by the sender.
        to: String,
        /// The pairwise `otp` keychain contact this was sealed under
        /// (`crypto::otp::contact_name_for`) - carried so the receiver can
        /// refuse outright (touching no pad) if it doesn't match the
        /// contact the receiver derives from its *own* pinned key for the
        /// claimed sender.
        contact_name: String,
        /// This mail's position in the contact's OTP send counter - the
        /// same counter `P2pPayload::OtpEnvelope::seq` uses, because a mail
        /// spends the same sequential pad (§17.2).
        seq: u64,
        /// Unix seconds, UTC, at the moment the user confirmed the send.
        sent_at_utc: u64,
        ciphertext: Vec<u8>,
    },
    /// Asks the server for everything §17.3 owes this client: every stored
    /// mail addressed to its nickname (delivered as `OtpMailDeliver`s), and
    /// every delivered-but-unnotified receipt for mail it previously sent
    /// (delivered as `OtpMailDelivered`s). Sent once after identify by any
    /// client with a local OTP keychain; harmless for one without.
    OtpMailFetch,
    /// Receiver -> server: this mail was decrypted and persisted locally -
    /// the server deletes its stored ciphertext and records a delivery
    /// receipt for the sender (§17.3).
    OtpMailAck {
        mail_id: String,
    },
    /// Sender -> server: the `OtpMailDelivered` receipt was seen and local
    /// state updated - the server may forget the receipt instead of
    /// re-notifying on every future connect.
    OtpMailDeliveredAck {
        mail_id: String,
    },
}

/// Messages the server sends to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    Hello {
        /// Whether this server accepts `Register` at all
        /// (`server_allow_registration`, §5.3) - told up front so a client
        /// can say "this server does not take registrations" before the
        /// user types an email address for nothing.
        registration_open: bool,
        /// Ephemeral encryption keys for this connection's control channel
        /// (`crate::control`). The last thing either side sends in the
        /// clear. Nothing vouches for them at this layer: authenticating
        /// the server is TLS's job (`crate::server::ssl`).
        control: crate::control::ControlOffer,
    },
    /// Answers `Auth` and `Activate`. `ok: false` with
    /// `activation_pending: false` and `deactivated: None` closes the
    /// connection; `ok: false` with `activation_pending: true` means the
    /// credentials were right but the account has not been activated yet
    /// - the client may send exactly one `Activate` (§5.2), answered with
    /// another `AuthResult`. `ok: false` with `deactivated: Some(reason)`
    /// means the credentials were right but a superadmin has locked the
    /// account out - a dedicated typed field, not folded into `reason`,
    /// the same way `activation_pending` already isn't, so the client can
    /// route to a distinctly-worded refusal rather than a generic one.
    AuthResult {
        ok: bool,
        activation_pending: bool,
        deactivated: Option<String>,
        reason: Option<String>,
    },
    /// Answers `Register` (§5.3). The connection closes right after either
    /// way. `ok: true` means the account exists and an activation code is
    /// on its way to the email given.
    RegisterResult {
        ok: bool,
        reason: Option<String>,
    },
    /// Answers `ChangePassword`. `ok: false` names why in `reason` -
    /// "wrong current password" or an empty new one; the connection stays
    /// open either way, unlike `RegisterResult`.
    ChangePasswordResult {
        ok: bool,
        reason: Option<String>,
    },
    /// Answers a superadmin's `RequestUsersList` - every registered
    /// nickname and which channels each administers. Refused (`Error`,
    /// not this) for anyone else.
    UsersList {
        users: Vec<UserAdminInfo>,
    },
    /// Answers `Identify`. Nicknames must be unique among connected
    /// clients; `ok: false` means the server closes the connection right
    /// after sending this. On success `you` is the assigned `UserId`,
    /// needed so the client can exclude itself from a channel message's
    /// per-recipient list.
    IdentifyResult {
        ok: bool,
        you: Option<UserId>,
        reason: Option<String>,
    },
    /// The public channel directory, plus every nickname
    /// `server_superadmin` names - folded into this one message, rather
    /// than a second one sent right after it, specifically so the
    /// connect-time message *count* never changes: several tests and the
    /// daemon's own connect path read a fixed sequence ending at
    /// `ChannelList` and start doing other things immediately after,
    /// so an additional message here would land as an unexpected reply
    /// to whatever they asked next. `superadmins` is fixed for the
    /// server's uptime like the setting it comes from, so unlike
    /// `channels` there is no later live-update message for it - every
    /// client, superadmin or not, learns the whole list exactly once.
    ChannelList {
        channels: Vec<ChannelInfo>,
        superadmins: Vec<String>,
    },
    /// Confirms a successful join. `admin` is the channel's current
    /// admin nickname at the moment of joining (`None` only for
    /// `DEFAULT_CHANNEL_NAME`, which belongs to nobody) - carried here
    /// rather than on `ChannelInfo` itself, since `ChannelInfo` is also
    /// what the public directory (`ChannelList`/`ChannelCreated`) uses,
    /// and the directory has no use for it. A later change of admin
    /// while already joined arrives instead as `ChannelAdminChanged`.
    Joined {
        channel: ChannelInfo,
        admin: Option<String>,
    },
    ChannelJoinFailed {
        name: String,
        reason: String,
    },
    /// A typed alternative to `ChannelJoinFailed`'s free-text `reason` for
    /// the password-protected-channel flow (§6.5/§6.6), so the client can
    /// branch on *why* rather than parsing English. Sent to the requester
    /// only - nothing about a private channel's existence or password
    /// state leaks to anyone else.
    ChannelJoinRejected {
        name: String,
        kind: ChannelJoinRejection,
    },
    /// Sent to every other currently-connected client the instant a new
    /// *public* channel is created - never for a private one, which stays
    /// unadvertised (§6.3). `ChannelList` (above) is only
    /// ever sent once, right after `IdentifyResult`, so without this a
    /// channel created after that snapshot would stay permanently invisible
    /// to anyone who didn't create or join it themselves.
    ChannelCreated {
        channel: ChannelInfo,
    },
    UserJoined {
        channel: String,
        user: UserInfo,
    },
    UserLeft {
        channel: String,
        user_id: UserId,
    },
    /// The admin removed `name` outright, via `/delete-channel` or a
    /// superadmin's removal/account-removal cascade - `reason` names
    /// which. Sent to every member who was in it; the client drops the
    /// tab. A later `JoinChannel` for the same name simply recreates it
    /// fresh, exactly like any other emptied channel.
    ChannelRemoved {
        name: String,
        reason: String,
    },
    /// The admin `/ban`-ed `nickname` (whose current `UserId` is
    /// `user_id`) from `channel`, force-removing them if they were a
    /// member. Sent to every member who was in the channel, the banned
    /// one included - a client compares `user_id` to its own to tell a
    /// personal notice from an ordinary channel-log line.
    UserBanned {
        channel: String,
        user_id: UserId,
        nickname: String,
    },
    /// The admin `/unban`-ed `nickname` from `channel` - membership is
    /// unaffected either way; this only reverses the future-join refusal.
    UserUnbanned {
        channel: String,
        nickname: String,
    },
    /// The admin applied `/lock-joins` - `by` names who, for the
    /// notification. Carries no list: the effect (locked/unlocked, and to
    /// whom) is only ever queried by joining.
    ChannelJoinLockUpdated {
        channel: String,
        by: String,
    },
    /// `channel`'s admin changed via `/assign-admin` - `admin` is the new
    /// one. Sent to every current member.
    ChannelAdminChanged {
        channel: String,
        admin: Option<String>,
    },
    /// Sent once per peer sharing any channel with `user_id` when their
    /// connection closes entirely (vs `UserLeft`: left one channel, still
    /// connected). Unlike `UserLeft`, the recipient does *not* drop
    /// `user_id` from membership lists - a client with DM history keeps
    /// them listed, grayed out (SPEC.md "offline" behavior).
    UserOffline {
        user_id: UserId,
    },
    /// Relayed mirror of `ClientMessage::RotateKey` - the `to` field isn't
    /// repeated since it's implicitly "whoever the server delivers this
    /// to" (see PROTOCOL.md §13.10 for how the recipient verifies the
    /// signed rotation before trusting the new key).
    KeyRotated {
        from: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Relayed mirror of `ClientMessage::RequestPeerLink` - see there and
    /// `crate::client::p2p`. `from`'s candidates are exactly what `from` sent; the
    /// server neither validates nor stores them.
    PeerCandidates {
        from: UserId,
        candidates: Vec<std::net::SocketAddr>,
        link_nonce: u64,
    },

    Error {
        message: String,
    },

    /// A superadmin's `/deactivate` just took effect against this
    /// currently-connected account. There is no server-side way to force
    /// a socket closed, so the client is expected to react to this
    /// itself: tear down its own session (the same exit path an ordinary
    /// quit already uses) after showing `reason`, rather than waiting for
    /// anything further from the server.
    AccountDeactivated {
        reason: String,
    },

    /// Answers one `OtpMailSend` (docs/PROTOCOL.md §17.2): `ok: true` means
    /// the ciphertext is durably stored (or was already - a retried id is
    /// acknowledged again, never stored twice) and the sender may treat the
    /// mail's pad spend as delivered-to-server. `ok: false` is exceptional
    /// (malformed id, oversized ciphertext, a disk failure): the pad bytes
    /// this mail consumed are gone either way, so the sender reports it as
    /// a hard failure rather than retrying.
    OtpMailResult {
        mail_id: String,
        ok: bool,
        reason: Option<String>,
    },
    /// One stored mail, handed to the nickname it's addressed to - in
    /// response to that client's `OtpMailFetch`, or pushed immediately if
    /// the recipient happens to be connected when `OtpMailSend` arrives.
    /// Every field is the stored mirror of the original `OtpMailSend`,
    /// except `from`, which is the nickname the server itself registered
    /// for the sender's connection. Mails from one sender are always
    /// delivered in ascending `seq` order (§17.3) - the pad is sequential,
    /// so the receiver cannot decrypt them in any other order.
    OtpMailDeliver {
        mail_id: String,
        from: String,
        contact_name: String,
        seq: u64,
        sent_at_utc: u64,
        ciphertext: Vec<u8>,
    },
    /// Tells the original sender their mail was genuinely received and
    /// decrypted by its recipient (who acknowledged it via `OtpMailAck`).
    /// Re-sent on every `OtpMailFetch` until the sender answers with
    /// `OtpMailDeliveredAck` (§17.3).
    OtpMailDelivered {
        mail_id: String,
    },
}
