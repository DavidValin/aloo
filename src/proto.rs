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
    /// without even checking the password given.
    Banned,
}

/// What kind of `server_key` credential the server expects on connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthKind {
    None,
    Password,
    Rsa,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthResponse {
    None,
    Password(String),
    /// The auth challenge nonce, encrypted (in one or more OAEP blocks)
    /// with the server's public key.
    Rsa {
        blocks: Vec<Vec<u8>>,
    },
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
    /// Answers the server's `Hello` challenge - the first message sent
    /// *inside* the tunnel `SecureChannel` established.
    Auth(AuthResponse),
    /// Sent once auth succeeds: chosen display name and `my_key` public key.
    Identify {
        display_name: String,
        public_key_der: Vec<u8>,
        key_mode: KeyMode,
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
        auth: AuthKind,
        /// Present only when `auth == AuthKind::Rsa`: a random nonce the
        /// client must encrypt with the server's public key and echo back.
        challenge: Option<Vec<u8>>,
        /// Ephemeral encryption keys for this connection's control channel
        /// (`crate::control`), signed with the server's long-term key when
        /// it has one. The last thing either side sends in the clear.
        control: crate::control::ControlOffer,
    },
    AuthResult {
        ok: bool,
        reason: Option<String>,
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
    ChannelList(Vec<ChannelInfo>),
    Joined {
        channel: ChannelInfo,
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
