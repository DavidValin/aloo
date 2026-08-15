//! Wire protocol shared by the client and the server.
//!
//! Every message is bincode-encoded and sent over TCP as a frame:
//! a 4-byte big-endian length prefix followed by that many payload bytes.
//! The server never needs to see plaintext: `Envelope` always carries
//! RSA-OAEP encrypted blocks addressed to exactly one recipient (see
//! `crypto::encrypt_chunked`), so channel messages are relayed once per
//! recipient rather than broadcast as a single shared ciphertext.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Refuse to allocate for a frame larger than this many bytes. Generous
/// enough for a chunky voice message's worth of RSA blocks, small enough
/// to stop a corrupt/hostile length prefix from exhausting memory.
pub const MAX_FRAME_LEN: u32 = 64 * 1024 * 1024;

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

fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
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
    /// DER-encoded RSA public key, used by peers to encrypt messages to
    /// this user (see `crypto::encrypt_chunked` / `public_key_from_der`).
    /// Under `KeyMode::PerMessage` this is only ever the bootstrap key
    /// from that user's `Identify` - see `rekey` and PROTOCOL.md §11.
    pub public_key_der: Vec<u8>,
    pub key_mode: KeyMode,
}

/// Which `my_key` type a user connected with - broadcast (via `Identify`
/// → `UserInfo`) so every peer can show it next to that user's name
/// (SPEC.md Functionality #3/#6's `name icon TAG` convention, `label()`
/// below). `Rsa`/`Password`/`None` are all "static" for protocol purposes,
/// meaning exactly one keypair for the whole session with no rotation,
/// and behave identically everywhere except this label; only
/// `PerMessage` (i.e. `rsa_per_msg`) changes actual wire behavior (§11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyMode {
    /// `my_key` type `rsa`: a static keypair loaded from a file.
    Rsa,
    /// `my_key` type `password`: a static keypair deterministically
    /// derived from a password (§8.3).
    Password,
    /// `my_key` type `none`: a static keypair freshly autogenerated at
    /// connect time (not loaded, not password-derived), kept for the
    /// whole session.
    None,
    /// `rsa_per_msg`: see PROTOCOL.md §11.
    PerMessage,
    /// `pq_hybrid`: a static keybundle loaded from a file (like `Rsa`, not
    /// rotating like `PerMessage`), signed with ML-DSA-87+RSA4096 and
    /// encrypted with AES-256-GCM under an ML-KEM-1024+RSA4096-wrapped key.
    /// See PROTOCOL.md §13.
    PqHybrid,
}

impl KeyMode {
    /// This mode's tag, exactly as rendered (SPEC.md Functionality
    /// #3/#6), with no surrounding brackets or whitespace of its own -
    /// `format_with_name` is what actually combines it with a name. `🔒`
    /// marks a persistent or rotating RSA identity (`Rsa`, `PerMessage`);
    /// `🚨` flags the two weaker/less-durable sourcings (`Password`,
    /// `None`) - every `KeyMode` still encrypts every message with real
    /// RSA (§8.3), the icon is about identity durability, not
    /// "unencrypted". `🛡️` is `PqHybrid` alone: also a persistent,
    /// file-loaded identity like `Rsa`, but deliberately given its own icon
    /// to read as the strongest tier (quantum-resistant signing *and*
    /// key exchange, each additionally hedged with RSA-4096 - see §13).
    pub fn label(self) -> &'static str {
        match self {
            KeyMode::PerMessage => "\u{1F512} RSAPM",
            KeyMode::Rsa => "\u{1F512} RSA",
            KeyMode::Password => "\u{1F6A8} PWD",
            KeyMode::None => "\u{1F6A8} PLAIN",
            KeyMode::PqHybrid => "\u{1F6E1}\u{FE0F} PQH",
        }
    }

    /// Combines `name` with this mode's tag: `name TAG`, one shared
    /// convention for all five modes - the tag always trails the name as
    /// an annotation on it, the way `PerMessage`'s always has, rather than
    /// a classification label sitting in front of it.
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
    /// RSA-OAEP encrypted blocks; concatenating the decryption of each
    /// block (see `crypto::decrypt_chunked`) yields the plaintext.
    pub blocks: Vec<Vec<u8>>,
}

/// `FileOffer` is the one non-streamed content type this enum carries - the
/// *offer* of a file transfer (`docs/PROTOCOL.md`'s file transfer section),
/// sent as one ordinary `SendChannel`/`SendDirect`-style envelope so the
/// offer itself (who's sending what, how big) gets the same per-recipient
/// RSA/PQ privacy as a text message. The actual file bytes are never
/// wrapped in an `Envelope` at all - once accepted, they're streamed as raw
/// `FileChunk` blocks, exactly like voice's PCM (§7.3), so there's no
/// `Content::File` variant. The plaintext recovered by decrypting
/// `Envelope::blocks` for `FileOffer` is a bincode encoding
/// (`proto::encode`/`decode`) of `crate::file_transfer::FileOfferPayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    Text,
    FileOffer,
}

/// Messages the client sends to the server.
///
/// Everyone's actual message/voice/file *content* used to be relayed here
/// too (`SendChannel`/`SendDirect`, the `Stream*`/`File*` families) - see
/// `docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section for why
/// that moved to a direct, server-assisted-but-not-server-carried UDP link
/// (`crate::p2p`, `crate::p2p_proto`) instead. The server's job here is now
/// pure signaling: auth, identify, channel membership, and helping two
/// clients find each other's address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// First message after connecting, answering the server's `Hello`.
    Auth(AuthResponse),
    /// Sent once auth succeeds: chosen display name and `my_key` public key.
    Identify {
        display_name: String,
        public_key_der: Vec<u8>,
        key_mode: KeyMode,
    },
    /// Joins `name`, creating it first if it doesn't exist yet. `kind`
    /// only matters for creation: selecting an existing top tab (public)
    /// sends `ChannelKind::Public`, Ctrl+J's popup sends
    /// `ChannelKind::Private`. `password` is `Some` only when Ctrl+J's
    /// popup had Private selected and a non-empty password typed - it
    /// either sets a new private channel's password (creation) or is
    /// compared against an existing one (join); see docs/PROTOCOL.md §6.5.
    JoinChannel {
        name: String,
        kind: ChannelKind,
        password: Option<String>,
    },
    LeaveChannel {
        name: String,
    },

    /// `rsa_per_msg` only (`KeyMode::PerMessage`, PROTOCOL.md §11): tells
    /// `to` to trust a freshly-rotated per-peer key from now on.
    /// `signature` is computed over `to`'s raw bytes concatenated with
    /// `new_public_key_der`, signed with the private key this rotation
    /// replaces for `to` specifically - see `rekey::rotation_signing_payload`.
    RotateKey {
        to: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Proposes (or accepts, when replying to one already received) a
    /// direct UDP link to `peer`: `candidates` is this client's own host
    /// and server-reflexive addresses, `link_nonce` is this client's own
    /// opaque token for the attempt (echoed in its own `Ping`s - see
    /// `p2p_proto::PunchDatagram`). The server only ever relays this to
    /// `peer` (`Registry::route_peer_link_request`) - it never sees
    /// anything from the resulting link itself. See `crate::p2p`.
    RequestPeerLink {
        peer: UserId,
        candidates: Vec<std::net::SocketAddr>,
        link_nonce: u64,
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
    },
    AuthResult {
        ok: bool,
        reason: Option<String>,
    },
    /// Answers `Identify`. Nicknames must be unique among currently
    /// connected clients; `ok: false` (e.g. "nickname already taken") means
    /// the server closes the connection right after sending this - the
    /// client should reconnect with a different `display_name`. On
    /// success, `you` is the `UserId` the server assigned, needed so the
    /// client can exclude itself when building a channel message's
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
    /// A typed alternative to `ChannelJoinFailed`'s free-text `reason`,
    /// specific to the password-protected-private-channel flow (§6.5/§6.6),
    /// so the client can branch on *why* (open the password popup, show a
    /// "wrong password" message, or show a "too many attempts" message)
    /// rather than parsing English. Sent to the requester only - like
    /// `ChannelJoinFailed`, nothing about a private channel's existence or
    /// password state leaks to anyone else through this.
    ChannelJoinRejected {
        name: String,
        kind: ChannelJoinRejection,
    },
    /// Sent to every other currently-connected client the instant a new
    /// *public* channel is created - never for a private one, which stays
    /// unadvertised (§6.3) exactly as before. `ChannelList` (above) is only
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
    /// Sent once per peer who shares any channel with `user_id`, when
    /// `user_id`'s connection closes entirely (as opposed to `UserLeft`,
    /// which means they left one specific channel while staying
    /// connected elsewhere). Unlike `UserLeft`, this does *not* mean the
    /// recipient should drop `user_id` from its channel membership lists -
    /// see SPEC.md's "offline" behavior: a client with private-message
    /// history with `user_id` keeps them listed (grayed out) rather than
    /// removing them.
    UserOffline {
        user_id: UserId,
    },
    /// Relayed mirror of `ClientMessage::RotateKey` - the `to` field isn't
    /// repeated since it's implicitly "whoever the server delivers this
    /// to" (see PROTOCOL.md §11.3/§11.4 for how the recipient reconstructs
    /// the signed payload and verifies it before trusting the new key).
    KeyRotated {
        from: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    },

    /// Relayed mirror of `ClientMessage::RequestPeerLink` - see there and
    /// `crate::p2p`. `from`'s candidates are exactly what `from` sent; the
    /// server neither validates nor stores them.
    PeerCandidates {
        from: UserId,
        candidates: Vec<std::net::SocketAddr>,
        link_nonce: u64,
    },

    Error {
        message: String,
    },
}
