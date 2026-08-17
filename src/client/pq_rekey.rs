//! Per-peer rotation of `pq_hybrid` encryption keys - what makes a stolen
//! keybundle useless against traffic already captured (`docs/PROTOCOL.md`
//! §13.10).
//!
//! Rotates once per message sent to and once per message received from a
//! peer, keeps a bounded window of superseded keys so a burst sent under
//! one key still opens, and treats a whole voice stream as a single
//! message. The identity itself (ML-DSA-87 + RSA-4096) never rotates and
//! stays pinned; only the *encryption* keys move, and every rotation is
//! signed by that unchanging identity - so each one is independently
//! verifiable, and reconnecting needs nothing special.
//!
//! ML-KEM-1024 and X25519 keygen are microseconds, so rotation runs inline
//! on the event loop rather than needing a background worker, and voice
//! needs no carve-out. Freshness/queueing while a rotation is in flight is
//! tracked separately, by `rekey::RemoteKeys`.

use std::collections::{HashMap, VecDeque};

use crate::crypto::pq::{PqDecapKeys, PqEncapKeys, PqRotation, generate_encryption_keys};
use crate::proto::UserId;

/// How many superseded decryption keys to keep per peer.
///
/// Bounded on purpose, and the bound *is* the forward-secrecy guarantee: a
/// key that falls out of this window is gone, so nothing can reopen what it
/// protected. Kept at all because a sender can flush several queued
/// messages under one key (`rekey::RemoteKeys::on_rotated`) and because a
/// message already in flight when we rotate must still open.
pub const PQ_KEY_RETENTION: usize = 8;

struct PeerKeys {
    current: PqDecapKeys,
    retained: VecDeque<PqDecapKeys>,
    generation: u64,
}

/// Our own encryption keys: one rotating set per peer, plus the bootstrap
/// pair from the keybundle for peers we have not rotated with yet.
pub struct PqOwnKeys {
    bootstrap: PqDecapKeys,
    per_peer: HashMap<UserId, PeerKeys>,
}

impl PqOwnKeys {
    pub fn new(bootstrap: PqDecapKeys) -> Self {
        Self {
            bootstrap,
            per_peer: HashMap::new(),
        }
    }

    /// Generates fresh encryption keys for `peer`, installs them, and
    /// returns the rotation to send. The key they supersede moves into the
    /// retention window; whatever falls out of that window is dropped, and
    /// with it any ability to reopen what it protected.
    pub fn rotate_for(&mut self, peer: UserId) -> PqRotation {
        let (encap, decap) = generate_encryption_keys();
        let entry = self.per_peer.entry(peer).or_insert_with(|| PeerKeys {
            current: self.bootstrap.clone(),
            retained: VecDeque::new(),
            generation: 0,
        });
        let superseded = std::mem::replace(&mut entry.current, decap);
        entry.retained.push_front(superseded);
        while entry.retained.len() > PQ_KEY_RETENTION {
            entry.retained.pop_back();
        }
        entry.generation += 1;
        PqRotation {
            encap,
            generation: entry.generation,
        }
    }

    /// Every decryption key still worth trying for `peer`, newest first:
    /// the current one, then the retention window, then the bootstrap.
    ///
    /// The bootstrap is always included because a peer who has not rotated
    /// with us yet is still encrypting to it - it is the one encryption key
    /// that legitimately outlives rotation, and the one the keybundle file
    /// holds.
    pub fn candidates_for(&self, peer: UserId) -> Vec<PqDecapKeys> {
        let mut out = Vec::new();
        if let Some(entry) = self.per_peer.get(&peer) {
            out.push(entry.current.clone());
            out.extend(entry.retained.iter().cloned());
        }
        out.push(self.bootstrap.clone());
        out
    }

    /// Drops everything remembered for `peer` - called when their
    /// connection ends, so nothing survives into a later one.
    pub fn forget(&mut self, peer: UserId) {
        self.per_peer.remove(&peer);
    }

    /// How many times we have rotated for `peer`.
    pub fn generation_for(&self, peer: UserId) -> u64 {
        self.per_peer.get(&peer).map_or(0, |e| e.generation)
    }
}

/// The peers' side: which encryption keys we currently encrypt to for each
/// `pq_hybrid` peer, and how far along their rotation counter we have seen.
///
/// Freshness and queueing are *not* here - `rekey::RemoteKeys` already does
/// exactly that job, keyed by `UserId` and indifferent to what kind of key
/// is being waited on, so `pq_hybrid` reuses it rather than growing a
/// parallel copy.
#[derive(Default)]
pub struct PqPeerKeys {
    current: HashMap<UserId, (PqEncapKeys, u64)>,
    /// Each peer's durable identity fingerprint, which every send and
    /// rotation addressed to them has to name.
    fingerprints: HashMap<UserId, [u8; 32]>,
}

impl PqPeerKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a peer's bootstrap keys, learned from their `Identify`
    /// bundle when we first see them. Never overwrites keys they have
    /// already rotated to.
    pub fn bootstrap(&mut self, peer: UserId, encap: PqEncapKeys, fingerprint: [u8; 32]) {
        self.current.entry(peer).or_insert((encap, 0));
        self.fingerprints.insert(peer, fingerprint);
    }

    /// `peer`'s identity fingerprint, learned when we first saw them.
    pub fn fingerprint_for(&self, peer: UserId) -> Option<[u8; 32]> {
        self.fingerprints.get(&peer).copied()
    }

    /// Installs a verified rotation, unless it is older than one already
    /// accepted - which is what stops a captured rotation being re-injected
    /// to force a peer back onto a key an attacker has since obtained.
    /// Returns whether it was installed.
    pub fn install(&mut self, peer: UserId, rotation: PqRotation) -> bool {
        match self.current.get(&peer) {
            Some((_, seen)) if rotation.generation <= *seen => false,
            _ => {
                self.current
                    .insert(peer, (rotation.encap, rotation.generation));
                true
            }
        }
    }

    /// The keys to encrypt to for `peer` right now.
    pub fn encap_for(&self, peer: UserId) -> Option<&PqEncapKeys> {
        self.current.get(&peer).map(|(encap, _)| encap)
    }

    pub fn forget(&mut self, peer: UserId) {
        self.current.remove(&peer);
        self.fingerprints.remove(&peer);
    }

    /// The highest rotation generation accepted from `peer`.
    pub fn generation_for(&self, peer: UserId) -> Option<u64> {
        self.current.get(&peer).map(|(_, seen)| *seen)
    }
}
