//! Per-peer freshness/queueing for recipients whose encryption key rotates
//! during the session (currently `pq_hybrid` only, PROTOCOL.md §13.10):
//! whether their key on file is fresh or stale right now, and queueing
//! outgoing messages while it's stale. Pure state/logic, no I/O -
//! `crate::client::session`/`pq_rekey` own the actual rotation signing and
//! verification; this module only tracks whether the *result* of a
//! rotation has arrived yet for a given peer.

use std::collections::{HashMap, VecDeque};

use crate::proto::UserId;

/// How many times one queued message may be handed back for sending
/// before it is given up on. A message waits here for a rotation that may
/// simply never come - the peer may have stopped rotating, or may no
/// longer be addressable at all - and a queue that retries forever is a
/// message that never resolves either way. Small, because each attempt
/// costs a whole rotation round trip: five of those is already a long time
/// to leave a message looking undelivered.
pub const MAX_QUEUED_SEND_ATTEMPTS: u32 = 5;

/// One plaintext message held back because the recipient's key isn't fresh
/// yet (§13.10). Voice streams are deliberately not represented here - a
/// live stream is never queued, only sent or excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueuedOutbound {
    Channel {
        channel: String,
        plaintext: String,
        /// The row this message is already showing on, so a send that
        /// finally goes out can still be acknowledged back to it
        /// (docs/PROTOCOL.md 7.2.1) - and so a message given up on can be
        /// marked failed rather than left looking like it is still on its
        /// way.
        msg_id: u64,
        /// How many times this has been handed back for sending, bounded
        /// by `MAX_QUEUED_SEND_ATTEMPTS`.
        attempts: u32,
    },
    Direct {
        plaintext: String,
        msg_id: u64,
        /// Where this text landed in the DM's log, so giving up on it can
        /// mark that exact row (`UiState::mark_dm_message_failed`).
        log_index: Option<usize>,
        attempts: u32,
    },
}

impl QueuedOutbound {
    pub fn msg_id(&self) -> u64 {
        match self {
            QueuedOutbound::Channel { msg_id, .. } | QueuedOutbound::Direct { msg_id, .. } => {
                *msg_id
            }
        }
    }

    pub fn attempts(&self) -> u32 {
        match self {
            QueuedOutbound::Channel { attempts, .. }
            | QueuedOutbound::Direct { attempts, .. } => *attempts,
        }
    }

    fn bump(&mut self) {
        match self {
            QueuedOutbound::Channel { attempts, .. }
            | QueuedOutbound::Direct { attempts, .. } => *attempts += 1,
        }
    }

    /// Whether this has been handed back as many times as it is allowed to
    /// be. Checked on the way *out* of the queue, so an item is always
    /// tried `MAX_QUEUED_SEND_ATTEMPTS` times before being given up on.
    fn exhausted(&self) -> bool {
        self.attempts() >= MAX_QUEUED_SEND_ATTEMPTS
    }
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
    /// Marks the key fresh and drains the entire queue, in FIFO order, for
    /// the caller to encrypt and send as one batch under that single key.
    /// If the caller actually sends anything from the returned batch, it
    /// must call `mark_used` afterward.
    ///
    /// Returns `(to_send, given_up)`: every item still within its attempt
    /// budget, and every item that has now exhausted
    /// `MAX_QUEUED_SEND_ATTEMPTS`. Both leave the queue - the second kind
    /// is the caller's to report, not to retry.
    ///
    /// The attempt count is incremented here, on the way out, so a message
    /// that goes out successfully on its first pass has cost one attempt
    /// and one only.
    pub fn on_rotated(&mut self, peer: UserId) -> (Vec<QueuedOutbound>, Vec<QueuedOutbound>) {
        let state = self.peers.entry(peer).or_insert_with(|| RemotePeerState {
            fresh: true,
            queue: VecDeque::new(),
        });
        state.fresh = true;
        let mut to_send = Vec::new();
        let mut given_up = Vec::new();
        for mut item in std::mem::take(&mut state.queue) {
            if item.exhausted() {
                given_up.push(item);
                continue;
            }
            item.bump();
            to_send.push(item);
        }
        (to_send, given_up)
    }

    /// Puts an item drained by `on_rotated` back, because the caller could
    /// not send it after all - it waits for the next rotation with its
    /// attempt count already spent. Purely a re-queue: whether it has run
    /// out of attempts is decided the next time it comes back out.
    pub fn requeue(&mut self, peer: UserId, item: QueuedOutbound) {
        self.enqueue(peer, item);
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
