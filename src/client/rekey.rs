//! Per-peer freshness/queueing for recipients whose encryption key rotates
//! during the session (currently `pq_hybrid` only, PROTOCOL.md §13.10):
//! whether their key on file is fresh or stale right now, and queueing
//! outgoing messages while it's stale. Pure state/logic, no I/O -
//! `crate::client::session`/`pq_rekey` own the actual rotation signing and
//! verification; this module only tracks whether the *result* of a
//! rotation has arrived yet for a given peer.

use std::collections::{HashMap, VecDeque};

use crate::proto::UserId;

/// One plaintext message held back because the recipient's key isn't fresh
/// yet (§13.10). Voice streams are deliberately not represented here - a
/// live stream is never queued, only sent or excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueuedOutbound {
    Channel { channel: String, plaintext: String },
    Direct { plaintext: String },
}

struct RemotePeerState {
    fresh: bool,
    queue: VecDeque<QueuedOutbound>,
}

/// Tracks freshness/queueing for every peer known to use a rotating key
/// scheme. A peer never tracked here (a static-key peer, or one not yet
/// learned about) is always considered sendable - see `try_use`.
#[derive(Default)]
pub struct RemoteKeys {
    peers: HashMap<UserId, RemotePeerState>,
}

impl RemoteKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts tracking `peer`, if not already tracked. Idempotent.
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
    /// untracked (static-key) peer is always OK. A tracked peer with a
    /// fresh key is OK too - and this call consumes that freshness, so a
    /// second call before the next rotation returns `false`. A tracked
    /// peer without a fresh key returns `false` without changing anything
    /// - the caller must queue the message instead (`enqueue`).
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
    /// arrives. Also starts tracking `peer` if this is somehow the first
    /// we've heard of them (defensive - `track` should already have run).
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

    /// Call once a rotation from `peer` has been validated and applied.
    /// Marks the key fresh and drains+returns the entire queue, in FIFO
    /// order, for the caller to encrypt and send as one batch under that
    /// single key. If the caller actually sends anything from the returned
    /// batch, it must call `mark_used` afterward.
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
