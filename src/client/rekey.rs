//! `rsa_per_msg` (`KeyMode::PerMessage`, PROTOCOL.md §11): per-peer RSA key
//! rotation. Pure state/logic, no I/O - the caller (`crate::client::session`) is
//! responsible for actually writing `ClientMessage::RotateKey` to the wire
//! and for sourcing the "currently trusted" public key for a peer (which
//! lives in `ui::UiState`'s `known_users`/`channel.members`, kept in sync
//! via `ui::UiState::on_user_key_rotated`).
//!
//! Two independent pieces of state, since a client can be a `PerMessage`
//! sender to some peers while also *receiving from* `PerMessage` peers
//! regardless of its own mode:
//!
//! - [`OwnKeys`]: only used when *this* client's own `key_mode` is
//!   `PerMessage`. Tracks one rotating keypair per peer relationship, plus
//!   enough retired keys to decrypt a small batch of late-arriving
//!   messages (§11.7).
//! - [`RemoteKeys`]: tracks, for any peer whose `key_mode` is
//!   `PerMessage` (regardless of this client's own mode), whether the key
//!   currently on file for them is fresh (unused) or stale, and queues
//!   outgoing messages while stale (§11.5).

use std::collections::{HashMap, VecDeque};

use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::crypto;
use crate::proto::{ClientMessage, UserId};

/// How many superseded per-peer private keys `OwnKeys` retains, to tolerate
/// a sender flushing a small backlog of queued messages under one key
/// before we've had a chance to rotate away from it (PROTOCOL.md §11.7).
pub const KEY_RETENTION: usize = 8;

/// The bytes actually signed/verified for a key rotation: `to`'s raw
/// `UserId` bytes concatenated with the new key's DER encoding. Binding
/// `to` in prevents a rotation signed for one peer (while they still share
/// the same not-yet-superseded key) from being replayed as if addressed to
/// a different peer - see PROTOCOL.md §11.3.
pub fn rotation_signing_payload(to: UserId, new_public_key_der: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + new_public_key_der.len());
    buf.extend_from_slice(&to.0.to_be_bytes());
    buf.extend_from_slice(new_public_key_der);
    buf
}

/// Signs a rotation to `to` with the private key it replaces.
pub fn sign_rotation(
    old_private: &RsaPrivateKey,
    to: UserId,
    new_public_key_der: &[u8],
) -> crypto::Result<Vec<u8>> {
    crypto::sign(
        old_private,
        &rotation_signing_payload(to, new_public_key_der),
    )
}

/// Verifies a rotation addressed to `to` (the verifier's own id) against
/// the public key currently trusted for its sender.
pub fn verify_rotation(
    trusted_public: &RsaPublicKey,
    to: UserId,
    new_public_key_der: &[u8],
    signature: &[u8],
) -> bool {
    crypto::verify(
        trusted_public,
        &rotation_signing_payload(to, new_public_key_der),
        signature,
    )
}

/// Verifies a rotation and, only if valid, parses the new DER-encoded
/// public key - the one call site `session.rs` needs on receiving
/// `ServerMessage::KeyRotated`.
pub fn verify_and_parse_rotation(
    trusted_public: &RsaPublicKey,
    to: UserId,
    new_public_key_der: &[u8],
    signature: &[u8],
) -> Option<RsaPublicKey> {
    if !verify_rotation(trusted_public, to, new_public_key_der, signature) {
        return None;
    }
    crypto::public_key_from_der(new_public_key_der).ok()
}

/// The result of checking an incoming `KeyRotated` against the two anchors
/// a receiver might have for its sender: whatever key is currently trusted
/// *within this live connection* (`live_trusted` - the ordinary, already-
/// established in-session chain, §11.3/§11.4), and, independently, a
/// cross-session continuity key persisted for that sender's *nickname*
/// (`continuity_trusted` - see `docs/PROTOCOL.md` §12.6, `own_next_keys`).
/// `UserId` resets on every reconnect, so a legitimate peer reconnecting
/// necessarily fails the `live_trusted` check (there is no live state for
/// their brand-new connection yet) - `continuity_trusted` is what lets that
/// specific, expected case be told apart from an actual forged claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeVerification {
    /// Verified against the ordinary in-session key - ranges over every
    /// regular rotation that happens while already talking to someone,
    /// completely unrelated to reconnecting.
    Live(RsaPublicKey),
    /// The in-session check failed (or there wasn't one to check, e.g. a
    /// peer just seen for the first time this connection), but it verified
    /// against the persisted continuity key - a legitimate resume after a
    /// reconnect.
    Resumed(RsaPublicKey),
    /// Neither anchor verified it. On its own this is not evidence of
    /// anything - most peers have no continuity key at all (first-ever
    /// contact, or their own `my_key` isn't `rsa_per_msg`, §12.6) - the
    /// caller should only treat this as suspicious when it already knows
    /// `continuity_trusted` was `Some` (i.e. a resume was actually
    /// expected to be verifiable and wasn't).
    Failed,
}

/// Tries `live_trusted` first, then `continuity_trusted`, returning
/// whichever anchor (if either) the rotation verifies against. Pure
/// decision logic - no I/O, no knowledge of *why* either input is `None` or
/// what the caller should do with `Failed` - see `ResumeVerification`'s own
/// docs and `session.rs::handle_key_rotated` for how the result is used.
pub fn verify_with_fallback(
    live_trusted: Option<&RsaPublicKey>,
    continuity_trusted: Option<&RsaPublicKey>,
    to: UserId,
    new_public_key_der: &[u8],
    signature: &[u8],
) -> ResumeVerification {
    if let Some(live) = live_trusted
        && let Some(key) = verify_and_parse_rotation(live, to, new_public_key_der, signature)
    {
        return ResumeVerification::Live(key);
    }
    if let Some(continuity) = continuity_trusted
        && let Some(key) = verify_and_parse_rotation(continuity, to, new_public_key_der, signature)
    {
        return ResumeVerification::Resumed(key);
    }
    ResumeVerification::Failed
}

/// The CPU-heavy half of a rotation: generates a fresh `RSA_PER_MSG_KEY_BITS`
/// keypair and signs its public half with `old_private` (the key it's
/// about to replace for `peer`). Deliberately takes no `OwnKeys` access at
/// all and returns everything the caller needs (including the new private
/// key) so it can run on a background thread without holding any lock for
/// the expensive part - only the subsequent `OwnKeys::install_rotated_key`
/// call needs synchronized access, and that's cheap. See
/// `session.rs::spawn_rotation_worker`.
pub fn generate_and_sign_rotation(
    old_private: &RsaPrivateKey,
    peer: UserId,
) -> crypto::Result<(Vec<u8>, Vec<u8>, RsaPrivateKey)> {
    let new_kp = crypto::KeyPair::generate_with_bits(crypto::RSA_PER_MSG_KEY_BITS)?;
    let new_der = crypto::public_key_to_der(&new_kp.public)?;
    let signature = sign_rotation(old_private, peer, &new_der)?;
    Ok((new_der, signature, new_kp.private))
}

// ---------------------------------------------------------------------
// OwnKeys: this client's own rotating per-peer keypairs
// ---------------------------------------------------------------------

struct OwnPeerKeys {
    current: RsaPrivateKey,
    current_public_der: Vec<u8>,
    /// Newest-first; bounded to `KEY_RETENTION`.
    retained: VecDeque<RsaPrivateKey>,
}

/// This client's own `rsa_per_msg` state: only constructed/used when the
/// local `key_mode` is `PerMessage`. `bootstrap` is the keypair announced
/// in this client's own `Identify` - shared by every peer relationship
/// until that specific relationship's first rotation (§11.2), and
/// retained for the whole session since other, not-yet-rotated peers may
/// still depend on it.
pub struct OwnKeys {
    bootstrap: RsaPrivateKey,
    per_peer: HashMap<UserId, OwnPeerKeys>,
}

impl OwnKeys {
    pub fn new(bootstrap: RsaPrivateKey) -> Self {
        Self {
            bootstrap,
            per_peer: HashMap::new(),
        }
    }

    /// Tries the private key currently active for `peer` first, then
    /// retired-but-retained keys (newest first), then the shared bootstrap
    /// key - covering both a peer who has never triggered a rotation and
    /// one whose messages arrive slightly out of step with our own
    /// rotations (§11.7).
    pub fn decrypt_from(&self, peer: UserId, blocks: &[Vec<u8>]) -> Option<Vec<u8>> {
        if let Some(state) = self.per_peer.get(&peer) {
            if let Ok(pt) = crypto::decrypt_chunked(&state.current, blocks) {
                return Some(pt);
            }
            for key in &state.retained {
                if let Ok(pt) = crypto::decrypt_chunked(key, blocks) {
                    return Some(pt);
                }
            }
        }
        crypto::decrypt_chunked(&self.bootstrap, blocks).ok()
    }

    /// Generates a fresh keypair for `peer`, signs it with whichever key
    /// was active for `peer` before this call (the per-peer key if one
    /// already exists, otherwise the bootstrap key), and returns
    /// `(new_public_key_der, signature)` for the caller to wrap in a
    /// `ClientMessage::RotateKey` - see `rotate_and_build_message`, the
    /// usual entry point.
    ///
    /// This does the RSA-4096 keygen (`generate_and_sign_rotation`)
    /// synchronously, in line - fine for tests and other short-lived
    /// callers, but `session.rs` does **not** call this directly on its
    /// event-loop task: keygen at that size commonly takes on the order of
    /// 100ms-1s+, and running it inline would stall UI redraw and network
    /// processing for that long (PROTOCOL.md §11.6 already documents this
    /// cost as the reason voice is exempted from per-chunk rotation; the
    /// same cost applies to the per-message rotation this method performs,
    /// just less frequently). Instead, `session.rs` runs
    /// `generate_and_sign_rotation` on a dedicated background thread and
    /// only calls `install_rotated_key` - a fast, lock-brief operation -
    /// back on the shared `OwnKeys` (see `spawn_rotation_worker`).
    pub fn rotate_for_peer(&mut self, peer: UserId) -> crypto::Result<(Vec<u8>, Vec<u8>)> {
        let old_private = self.current_private_for(peer);
        let (new_der, signature, new_private) = generate_and_sign_rotation(&old_private, peer)?;
        self.install_rotated_key(peer, new_private, new_der.clone());
        Ok((new_der, signature))
    }

    /// The bookkeeping half of a rotation: installs an already-generated
    /// keypair as current for `peer`, retiring whatever was current before
    /// into the bounded retention ring (§11.7). No RSA computation happens
    /// here - just `HashMap`/`VecDeque` updates - so this is safe and fast
    /// to call while holding a shared lock (`session.rs`'s `Arc<Mutex<OwnKeys>>`).
    pub fn install_rotated_key(
        &mut self,
        peer: UserId,
        new_private: RsaPrivateKey,
        new_public_der: Vec<u8>,
    ) {
        match self.per_peer.get_mut(&peer) {
            Some(state) => {
                let previous = std::mem::replace(&mut state.current, new_private);
                state.current_public_der = new_public_der;
                state.retained.push_front(previous);
                state.retained.truncate(KEY_RETENTION);
            }
            None => {
                self.per_peer.insert(
                    peer,
                    OwnPeerKeys {
                        current: new_private,
                        current_public_der: new_public_der,
                        retained: VecDeque::new(),
                    },
                );
            }
        }
    }

    /// `rotate_for_peer`, packaged as the `ClientMessage` ready to send.
    pub fn rotate_and_build_message(&mut self, peer: UserId) -> crypto::Result<ClientMessage> {
        let (new_public_key_der, signature) = self.rotate_for_peer(peer)?;
        Ok(ClientMessage::RotateKey {
            to: peer,
            new_public_key_der,
            signature,
        })
    }

    /// The public key currently advertised to `peer`, if we've rotated for
    /// them at least once (test/debug convenience).
    pub fn current_public_der_for(&self, peer: UserId) -> Option<&[u8]> {
        self.per_peer
            .get(&peer)
            .map(|s| s.current_public_der.as_slice())
    }

    /// The private key that would currently decrypt a brand-new message
    /// from `peer` right now (the per-peer key if we've rotated for them
    /// at least once, otherwise the shared bootstrap key). Used to sign a
    /// new rotation against (`rotate_for_peer`) - there, "our own most
    /// recent key for this peer" really is the one right answer, since
    /// we're the one who installed it.
    pub fn current_private_for(&self, peer: UserId) -> RsaPrivateKey {
        match self.per_peer.get(&peer) {
            Some(state) => state.current.clone(),
            None => self.bootstrap.clone(),
        }
    }

    /// Every private key worth trying to decrypt an incoming message from
    /// `peer` with, in the same priority order `decrypt_from` already uses
    /// (current, then retained newest-first, then bootstrap) - cheap to
    /// clone (no RSA computation, just moving key material already held in
    /// memory).
    ///
    /// Live voice (`voice_stream::start_incoming_stream`) snapshots a
    /// single key once at stream `*Start` rather than retrying per chunk
    /// the way `decrypt_from` can for text (PROTOCOL.md §11.6 keeps a
    /// whole stream on one key). `current_private_for` alone isn't safe for
    /// that snapshot: `session::send_resume_rotation_if_available`
    /// installs a resumed key into `OwnKeys` optimistically, before the
    /// peer has had any chance to accept or reject it (PROTOCOL.md
    /// §12.6.2) - if they don't, the peer keeps encrypting with whatever it
    /// still trusts (typically our bootstrap key), while `current_private_for`
    /// would keep pointing at the rejected resumed key, silently failing
    /// every chunk of the stream with no recourse. This method hands the
    /// caller the whole candidate list up front so a stream's decrypt
    /// worker can try each in turn per chunk, exactly mirroring what
    /// `decrypt_from` already does for text.
    pub fn candidate_privates_for(&self, peer: UserId) -> Vec<RsaPrivateKey> {
        let mut keys = Vec::new();
        if let Some(state) = self.per_peer.get(&peer) {
            keys.push(state.current.clone());
            keys.extend(state.retained.iter().cloned());
        }
        keys.push(self.bootstrap.clone());
        keys
    }
}

// ---------------------------------------------------------------------
// RemoteKeys: freshness/queueing for peers who use rsa_per_msg
// ---------------------------------------------------------------------

/// One plaintext message held back because the recipient's `rsa_per_msg`
/// key isn't fresh yet (§11.5). Voice streams are deliberately not
/// represented here - see PROTOCOL.md §11.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueuedOutbound {
    Channel { channel: String, plaintext: String },
    Direct { plaintext: String },
}

struct RemotePeerState {
    fresh: bool,
    queue: VecDeque<QueuedOutbound>,
}

/// Tracks freshness/queueing for every peer known to use `rsa_per_msg`,
/// independent of this client's own `key_mode`. A peer never tracked here
/// (a `Static` peer, or one not yet learned about) is always considered
/// sendable - see `try_use`.
#[derive(Default)]
pub struct RemoteKeys {
    peers: HashMap<UserId, RemotePeerState>,
}

impl RemoteKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts tracking `peer` as a `rsa_per_msg` user, if not already
    /// tracked. Their bootstrap key (already known via `UserInfo`) is
    /// immediately usable once, so starts fresh. Idempotent.
    pub fn track(&mut self, peer: UserId) {
        self.peers.entry(peer).or_insert_with(|| RemotePeerState {
            fresh: true,
            queue: VecDeque::new(),
        });
    }

    pub fn is_tracked(&self, peer: UserId) -> bool {
        self.peers.contains_key(&peer)
    }

    /// Whether it's OK to encrypt-and-send to `peer` right now. An
    /// untracked (`Static`) peer is always OK. A tracked peer with a fresh
    /// key is OK too - and this call consumes that freshness, so a second
    /// call before the next rotation returns `false`. A tracked peer
    /// without a fresh key returns `false` without changing anything - the
    /// caller must queue the message instead (`enqueue`).
    pub fn try_use(&mut self, peer: UserId) -> bool {
        match self.peers.get_mut(&peer) {
            None => true,
            Some(state) if state.fresh => {
                state.fresh = false;
                true
            }
            Some(_) => false,
        }
    }

    /// Queues a message for `peer` to send once their next fresh key
    /// arrives (§11.5). Also starts tracking `peer` if this is somehow the
    /// first we've heard of them (defensive - `track` should already have
    /// run from their `UserJoined`).
    pub fn enqueue(&mut self, peer: UserId, item: QueuedOutbound) {
        self.peers
            .entry(peer)
            .or_insert_with(|| RemotePeerState {
                fresh: false,
                queue: VecDeque::new(),
            })
            .queue
            .push_back(item);
    }

    /// Call once a `KeyRotated` from `peer` has been validated and
    /// applied. Marks the key fresh and drains+returns the entire queue,
    /// in FIFO order, for the caller to encrypt and send as one batch
    /// under that single key (§11.5). If the caller actually sends
    /// anything from the returned batch, it must call `mark_used`
    /// afterward.
    pub fn on_rotated(&mut self, peer: UserId) -> Vec<QueuedOutbound> {
        let state = self.peers.entry(peer).or_insert_with(|| RemotePeerState {
            fresh: true,
            queue: VecDeque::new(),
        });
        state.fresh = true;
        std::mem::take(&mut state.queue).into_iter().collect()
    }

    /// Marks `peer`'s current key stale again, e.g. after flushing a batch
    /// returned by `on_rotated`, or after a single ad-hoc send accepted by
    /// `try_use` (which already does this itself - `mark_used` is only
    /// needed for the batch-flush path).
    pub fn mark_used(&mut self, peer: UserId) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.fresh = false;
        }
    }

    pub fn queue_len(&self, peer: UserId) -> usize {
        self.peers.get(&peer).map(|s| s.queue.len()).unwrap_or(0)
    }
}
