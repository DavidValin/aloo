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
    bincode::serde::encode_to_vec(msg, bincode_config()).map_err(|e| ProtoError::Encode(e.to_string()))
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
pub async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, msg: &T) -> Result<()> {
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
    Rsa { blocks: Vec<Vec<u8>> },
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

/// Live-streamed voice never goes through `Envelope` (see §7.3) - `File` is
/// the "future non-streamed content type" this enum was always meant to
/// grow (see the doc comment above): a whole file is a discrete, already
/// complete blob, so it's sent exactly like `Text` - one ordinary
/// `SendChannel`/`SendDirect`, no new wire message types. The plaintext
/// recovered by decrypting `Envelope::blocks` is, by convention (mirroring
/// how voice's raw-PCM plaintext convention is documented rather than
/// wire-enforced, §7.3), a bincode encoding (`proto::encode`/`decode`) of
/// `crate::file_transfer::FilePayload` - see `docs/PROTOCOL.md`'s file
/// transfer section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Content {
    Text,
    File,
}

/// Messages the client sends to the server.
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
    /// `ChannelKind::Private`.
    JoinChannel { name: String, kind: ChannelKind },
    LeaveChannel { name: String },
    /// One independently-encrypted envelope per recipient in the channel.
    SendChannel {
        channel: String,
        per_recipient: Vec<(UserId, Envelope)>,
    },
    SendDirect { to: UserId, envelope: Envelope },

    // -------------------------------------------------------------
    // Live-streamed voice: a Start, then zero or more Chunks, then an
    // End, in that order, all sharing one `stream_id`. `stream_id` alone
    // is only unique per sender (a simple per-connection counter) - every
    // consumer must key by `(from, stream_id)`, never `stream_id` alone,
    // since two different senders' counters can coincidentally collide.
    // Chunks carry raw RSA-OAEP `blocks` rather than a full `Envelope`:
    // there's no meaningful per-chunk `Content` to attach. `seq` is
    // advisory only - TCP plus the server's single-writer relay already
    // guarantee in-order delivery, so receivers just accumulate in
    // arrival order rather than reordering or rejecting on it.
    // -------------------------------------------------------------
    StreamChannelStart { channel: String, stream_id: u64 },
    StreamChannelChunk {
        channel: String,
        stream_id: u64,
        seq: u32,
        per_recipient: Vec<(UserId, Vec<Vec<u8>>)>,
    },
    StreamChannelEnd { channel: String, stream_id: u64, duration_ms: u32 },
    StreamDirectStart { to: UserId, stream_id: u64 },
    StreamDirectChunk { to: UserId, stream_id: u64, seq: u32, blocks: Vec<Vec<u8>> },
    StreamDirectEnd { to: UserId, stream_id: u64, duration_ms: u32 },

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
    AuthResult { ok: bool, reason: Option<String> },
    /// Answers `Identify`. Nicknames must be unique among currently
    /// connected clients; `ok: false` (e.g. "nickname already taken") means
    /// the server closes the connection right after sending this - the
    /// client should reconnect with a different `display_name`. On
    /// success, `you` is the `UserId` the server assigned, needed so the
    /// client can exclude itself when building a channel message's
    /// per-recipient list.
    IdentifyResult { ok: bool, you: Option<UserId>, reason: Option<String> },
    ChannelList(Vec<ChannelInfo>),
    Joined { channel: ChannelInfo },
    ChannelJoinFailed { name: String, reason: String },
    UserJoined { channel: String, user: UserInfo },
    UserLeft { channel: String, user_id: UserId },
    /// Sent once per peer who shares any channel with `user_id`, when
    /// `user_id`'s connection closes entirely (as opposed to `UserLeft`,
    /// which means they left one specific channel while staying
    /// connected elsewhere). Unlike `UserLeft`, this does *not* mean the
    /// recipient should drop `user_id` from its channel membership lists -
    /// see SPEC.md's "offline" behavior: a client with private-message
    /// history with `user_id` keeps them listed (grayed out) rather than
    /// removing them.
    UserOffline { user_id: UserId },
    ChannelMessage {
        channel: String,
        from: UserId,
        from_name: String,
        envelope: Envelope,
    },
    DirectMessage {
        from: UserId,
        from_name: String,
        envelope: Envelope,
    },

    /// Relayed mirror of the `ClientMessage::Stream*` family - see there
    /// for the `(from, stream_id)` identity and `seq` caveats.
    ChannelStreamStart { channel: String, from: UserId, from_name: String, stream_id: u64 },
    ChannelStreamChunk { channel: String, from: UserId, stream_id: u64, seq: u32, blocks: Vec<Vec<u8>> },
    ChannelStreamEnd { channel: String, from: UserId, stream_id: u64, duration_ms: u32 },
    DirectStreamStart { from: UserId, from_name: String, stream_id: u64 },
    DirectStreamChunk { from: UserId, stream_id: u64, seq: u32, blocks: Vec<Vec<u8>> },
    DirectStreamEnd { from: UserId, stream_id: u64, duration_ms: u32 },

    /// Relayed mirror of `ClientMessage::RotateKey` - the `to` field isn't
    /// repeated since it's implicitly "whoever the server delivers this
    /// to" (see PROTOCOL.md §11.3/§11.4 for how the recipient reconstructs
    /// the signed payload and verifies it before trusting the new key).
    KeyRotated {
        from: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    },

    Error { message: String },
}
