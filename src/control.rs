//! Encrypting the client↔server control channel.
//!
//! Message *content* never touches the server (§7.1/§10), but the control
//! channel that sets a session up has always been plain TCP - and it
//! carries plenty a passive observer would like: a `--password` credential
//! in the clear (§5.2), nicknames, which channels exist, who is in them,
//! and the timing of every key rotation. Encrypting it does not change what
//! the *server* learns (it still has to route by these), only what anyone
//! watching the wire does.
//!
//! The construction is deliberately not new. The server offers ephemeral
//! ML-KEM-1024 + X25519 encryption keys, the client transports a random
//! secret to them through `crypto::pq`'s existing hybrid wrap - the same
//! code, and the same "a break of either primitive alone is not enough"
//! property, as a message send. From that secret both sides derive two
//! directional AES-256-GCM keys and seal each frame's payload in place; the
//! length-prefix framing itself (§1.1) is untouched.
//!
//! **Server authentication.** The server's offer is ephemeral, so it needs
//! something long-lived to vouch for it or a man in the middle could simply
//! substitute their own. That vouching is not done at this layer: a
//! deployment that wants it runs the control connection over TLS
//! (`server_ssl=on`, `crate::server::ssl`), whose certificate is what the
//! client checks before a single frame of this channel is exchanged. Over
//! plain TCP the channel is **encrypted but unauthenticated**: it defeats
//! a passive observer, not an active man in the middle. That is a real
//! limit and is stated as one rather than implied away.
//!
//! Because the offer is per connection and thrown away with it, recording a
//! session and later stealing the server's TLS key still does not decrypt
//! it.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::CryptoError;
use crate::crypto::pq::{PqEncapKeys, fresh_data_key, unwrap_key, wrap_key_for};
use crate::proto::{self, ProtoError, Result};

/// HKDF labels for the two directions. Separate keys per direction so a
/// frame captured in one direction cannot be replayed back in the other.
const LABEL_C2S: &[u8] = b"aloo/control/v1/client-to-server";
const LABEL_S2C: &[u8] = b"aloo/control/v1/server-to-client";

/// The server's ephemeral encryption keys for one connection. Nothing at
/// this layer vouches for them (see the module doc): a deployment that
/// needs the server authenticated runs the connection over TLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlOffer {
    pub encap: PqEncapKeys,
}

/// The client's reply: a secret transported to the server's offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlAccept {
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_key: [u8; 32],
    pub eph_x25519_pub: [u8; 32],
}

/// Builds the offer for one connection.
pub fn make_offer(encap: PqEncapKeys) -> ControlOffer {
    ControlOffer { encap }
}

/// Derives the two directional keys from the transported secret. Part of
/// the wire contract - pinned by test vectors (`docs/SECURITY.md`).
pub fn derive(secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(LABEL_C2S, &mut c2s)
        .expect("32 bytes is well within HKDF-SHA256's limit");
    hk.expand(LABEL_S2C, &mut s2c)
        .expect("32 bytes is well within HKDF-SHA256's limit");
    (c2s, s2c)
}

/// Client side: transports a fresh secret to `offer`, returning what to
/// send and the keys to use once it is sent.
pub fn accept_offer(offer: &ControlOffer) -> Result<(ControlAccept, ControlKeys)> {
    let secret = fresh_data_key();
    let (kem_ciphertext, wrapped_key, eph_x25519_pub) = wrap_key_for(&offer.encap, &secret)
        .map_err(|e: CryptoError| ProtoError::Decode(e.to_string()))?;
    let (c2s, s2c) = derive(&secret);
    Ok((
        ControlAccept {
            kem_ciphertext,
            wrapped_key,
            eph_x25519_pub,
        },
        ControlKeys {
            send: c2s,
            recv: s2c,
        },
    ))
}

/// Server side: recovers the secret a client transported.
pub fn open_accept(
    decap: &crate::crypto::pq::PqDecapKeys,
    accept: &ControlAccept,
) -> Option<ControlKeys> {
    let secret = unwrap_key(
        decap,
        &accept.kem_ciphertext,
        &accept.wrapped_key,
        &accept.eph_x25519_pub,
    )?;
    let (c2s, s2c) = derive(&secret);
    Some(ControlKeys {
        send: s2c,
        recv: c2s,
    })
}

/// One side's pair of directional keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

/// Counter-based nonce. The key is already per direction and per
/// connection, so a counter that never repeats under it is all the
/// uniqueness AES-GCM needs.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_be_bytes());
    n
}

fn seal(key: &[u8; 32], counter: u64, payload: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    cipher
        .encrypt(&Nonce::from(nonce(counter)), payload)
        .map_err(|e| ProtoError::Decode(e.to_string()))
}

fn open(key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    cipher
        .decrypt(&Nonce::from(nonce(counter)), ciphertext)
        .map_err(|_| ProtoError::Decode("control frame failed to authenticate".into()))
}

/// A framed-message writer that seals payloads once the tunnel is up.
///
/// Starts in the clear, because the handshake that establishes the tunnel
/// has to travel somehow, and switches over via `enable` - after which
/// every frame is sealed. There is no way back: a tunnel that could be
/// turned off mid-session would be a downgrade attack waiting to happen.
pub struct ControlWriter<W> {
    inner: W,
    key: Option<[u8; 32]>,
    counter: u64,
}

impl<W: AsyncWrite + Unpin> ControlWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            key: None,
            counter: 0,
        }
    }

    pub fn enable(&mut self, key: [u8; 32]) {
        self.key = Some(key);
        self.counter = 0;
    }

    pub fn is_encrypted(&self) -> bool {
        self.key.is_some()
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let payload = proto::encode(msg)?;
        let payload = match &self.key {
            Some(key) => {
                let sealed = seal(key, self.counter, &payload)?;
                self.counter += 1;
                sealed
            }
            None => payload,
        };
        let framed = proto::frame(&payload)?;
        self.inner.write_all(&framed).await?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// The reading counterpart of `ControlWriter`.
pub struct ControlReader<R> {
    inner: R,
    key: Option<[u8; 32]>,
    counter: u64,
}

impl<R: AsyncRead + Unpin> ControlReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            key: None,
            counter: 0,
        }
    }

    pub fn enable(&mut self, key: [u8; 32]) {
        self.key = Some(key);
        self.counter = 0;
    }

    /// Reads one framed message, `Ok(None)` on a clean EOF before any byte
    /// of a new frame arrives. A frame that fails to authenticate is a hard
    /// error, never a skip: on an encrypted channel it means either
    /// tampering or desynchronised counters, and both are fatal.
    pub async fn recv<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>> {
        let mut len_buf = [0u8; 4];
        if let Err(e) = self.inner.read_exact(&mut len_buf).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(ProtoError::Io(e));
        }
        let len = u32::from_be_bytes(len_buf);
        if len > proto::MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge(len));
        }
        let mut payload = vec![0u8; len as usize];
        self.inner.read_exact(&mut payload).await?;

        let payload = match &self.key {
            Some(key) => {
                let opened = open(key, self.counter, &payload)?;
                self.counter += 1;
                opened
            }
            None => payload,
        };
        Ok(Some(proto::decode(&payload)?))
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Both directions of an encrypted control channel over a single stream.
///
/// `ControlReader`/`ControlWriter` exist as separate halves because the
/// live client and server both read and write concurrently. Anything using
/// one connection *sequentially* - a test, a script, a tool - wants this
/// instead: one object that owns the stream and keeps both counters in
/// step, with the client side of the handshake spelled out once in
/// `client_handshake` rather than re-derived by every caller.
pub struct ControlEndpoint<S> {
    stream: S,
    send_key: Option<[u8; 32]>,
    send_counter: u64,
    recv_key: Option<[u8; 32]>,
    recv_counter: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ControlEndpoint<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            send_key: None,
            send_counter: 0,
            recv_key: None,
            recv_counter: 0,
        }
    }

    pub fn enable(&mut self, keys: ControlKeys) {
        self.send_key = Some(keys.send);
        self.recv_key = Some(keys.recv);
        self.send_counter = 0;
        self.recv_counter = 0;
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let payload = proto::encode(msg)?;
        let payload = match &self.send_key {
            Some(key) => {
                let sealed = seal(key, self.send_counter, &payload)?;
                self.send_counter += 1;
                sealed
            }
            None => payload,
        };
        let framed = proto::frame(&payload)?;
        self.stream.write_all(&framed).await?;
        Ok(())
    }

    pub async fn recv<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>> {
        let mut len_buf = [0u8; 4];
        if let Err(e) = self.stream.read_exact(&mut len_buf).await {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(ProtoError::Io(e));
        }
        let len = u32::from_be_bytes(len_buf);
        if len > proto::MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge(len));
        }
        let mut payload = vec![0u8; len as usize];
        self.stream.read_exact(&mut payload).await?;

        let payload = match &self.recv_key {
            Some(key) => {
                let opened = open(key, self.recv_counter, &payload)?;
                self.recv_counter += 1;
                opened
            }
            None => payload,
        };
        Ok(Some(proto::decode(&payload)?))
    }

    /// Reads the server's `Hello`, turns the channel on, and hands back
    /// whether the server takes registrations - the one thing the caller
    /// may still want to know before choosing between `Auth` and
    /// `Register`. After this returns, every message in either direction
    /// is sealed. `None` if the server closed before saying hello.
    pub async fn client_handshake(&mut self) -> Result<Option<bool>> {
        let Some(proto::ServerMessage::Hello {
            registration_open,
            control,
        }) = self.recv().await?
        else {
            return Ok(None);
        };
        let (accept, keys) = accept_offer(&control)?;
        self.send(&proto::ClientMessage::SecureChannel(accept)).await?;
        self.enable(keys);
        Ok(Some(registration_open))
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

/// Anything that can put one client message on the control channel.
///
/// The live client holds a `ControlWriter` (one half of a split stream, so
/// it can read and write at once); anything driving a connection
/// sequentially holds a `ControlEndpoint`. The send paths - joining a
/// channel, requesting a peer link, rotating a key - do not care which,
/// so they take this instead of naming either.
pub trait ControlSink {
    fn send_control(
        &mut self,
        msg: &proto::ClientMessage,
    ) -> impl std::future::Future<Output = Result<()>>;
}

/// A `ControlSink` with no server behind it: every send is discarded.
///
/// Used only by a session started with no server at all
/// (`docs/PROTOCOL.md` §7.1.5). Discarding is safe *because nothing
/// user-visible reaches it*: an action that needs a server is refused at
/// the point it is asked for, with a reason, rather than being allowed to
/// proceed into a message that vanishes here - which would look to the
/// user like the app silently ignoring them.
///
/// Everything that would otherwise arrive is stopped upstream instead of
/// being dropped here: joining a channel and OTP mail are refused
/// (`UiAction::needs_server`), the connect-time mail fetch and the
/// heartbeat are skipped, a key rotation is rerouted onto the peer link,
/// a candidate relay is never signalled for a peer no server named, and
/// a channel departure goes through `session::send_if_server`. This type
/// is therefore a backstop for a path nobody has thought of, not the
/// mechanism - if something starts relying on it to swallow a message a
/// user asked for, that is the bug, not the fix.
pub struct NullSink;

impl ControlSink for NullSink {
    async fn send_control(&mut self, _msg: &proto::ClientMessage) -> Result<()> {
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin> ControlSink for ControlWriter<W> {
    async fn send_control(&mut self, msg: &proto::ClientMessage) -> Result<()> {
        self.send(msg).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> ControlSink for ControlEndpoint<S> {
    async fn send_control(&mut self, msg: &proto::ClientMessage) -> Result<()> {
        self.send(msg).await
    }
}
