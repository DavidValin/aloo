//! Refusing a send that has already arrived once.
//!
//! Every `pq_hybrid` send is signed over a binding that names the sender's
//! own `send_id` (`crypto::pq::SendBinding`), so a captured message can't be
//! edited - but it could still be re-injected verbatim onto the same link.
//! This is what stops that: a send is accepted once and only once.
//!
//! It is a *window*, not a high-water mark, because sends no longer
//! necessarily arrive in the order they were sealed. A message written to
//! somebody who is offline is sealed - `send_id` and all - when it is
//! written, and then waits on disk (`client::outbox`, `client::otp_outbox`)
//! until they come back. By then the sender has sealed newer things, so the
//! one that was waiting arrives *after* ids above it. A high-water mark
//! reads that as a replay and drops it silently, which is the one outcome a
//! durable queue exists to prevent.
//!
//! So the rule is "not seen before, and not older than `WINDOW` behind the
//! newest", tracked as a bitmap of the last `WINDOW` ids. Re-injecting a
//! captured send still fails: its bit is already set. Anything that falls
//! out of the window behind is refused rather than risked - the queue would
//! have to have been overtaken by `WINDOW` newer sends to that peer's
//! connection for that to happen.
//!
//! Gaps are expected, not suspicious. The counter is per connection rather
//! than per recipient, so a channel message addressed to five people
//! consumes one value for all of them, and a message to somebody else
//! consumes a value this peer never sees.
//!
//! State is keyed by the live `UserId` and lives only as long as the
//! session, which is deliberate on both counts: a peer who reconnects gets a
//! fresh `UserId` and starts their counter over, so keying by identity
//! instead would reject everything they sent after reconnecting.

use std::collections::HashMap;

use crate::proto::UserId;

/// How far behind the newest accepted `send_id` a straggler may still be.
/// Sized for the queue it exists to serve: the sender would have to seal
/// this many newer sends on one connection, while the waiting one is still
/// undelivered, before it is given up on.
pub const WINDOW: u64 = 4096;

const WORDS: usize = (WINDOW / 64) as usize;

/// One peer's window: the newest id accepted, and a bit per id in the
/// `WINDOW` positions ending there saying whether it was already taken.
struct PeerWindow {
    highest: u64,
    seen: [u64; WORDS],
}

impl PeerWindow {
    fn new(send_id: u64) -> Self {
        let mut window = Self {
            highest: send_id,
            seen: [0; WORDS],
        };
        window.set(send_id);
        window
    }

    /// Ids map onto the bitmap by wrapping, so advancing means clearing
    /// the slots the window has just moved onto rather than shifting.
    fn slot(send_id: u64) -> (usize, u64) {
        let position = (send_id % WINDOW) as usize;
        (position / 64, 1u64 << (position % 64))
    }

    fn set(&mut self, send_id: u64) {
        let (word, bit) = Self::slot(send_id);
        self.seen[word] |= bit;
    }

    fn is_set(&self, send_id: u64) -> bool {
        let (word, bit) = Self::slot(send_id);
        self.seen[word] & bit != 0
    }

    fn clear(&mut self, send_id: u64) {
        let (word, bit) = Self::slot(send_id);
        self.seen[word] &= !bit;
    }

    fn accept(&mut self, send_id: u64) -> bool {
        if send_id > self.highest {
            // The window moves up to it. Everything it moves onto is
            // unseen by definition, and must not inherit the bit of the
            // id that used to occupy that slot.
            if send_id - self.highest >= WINDOW {
                self.seen = [0; WORDS];
            } else {
                for passed in (self.highest + 1)..=send_id {
                    self.clear(passed);
                }
            }
            self.highest = send_id;
            self.set(send_id);
            true
        } else if self.highest - send_id >= WINDOW || self.is_set(send_id) {
            false
        } else {
            self.set(send_id);
            true
        }
    }
}

#[derive(Default)]
pub struct ReplayGuard {
    peers: HashMap<UserId, PeerWindow>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `send_id` as seen from `peer`, returning whether it was
    /// genuinely new. A repeat - or anything so far behind that it has
    /// fallen out of the window - returns `false` and changes nothing.
    pub fn accept(&mut self, peer: UserId, send_id: u64) -> bool {
        match self.peers.get_mut(&peer) {
            Some(window) => window.accept(send_id),
            None => {
                self.peers.insert(peer, PeerWindow::new(send_id));
                true
            }
        }
    }

    /// The highest `send_id` accepted from `peer` so far, if any.
    pub fn highest(&self, peer: UserId) -> Option<u64> {
        self.peers.get(&peer).map(|window| window.highest)
    }

    /// Forgets a peer entirely - used when their connection ends, so a
    /// later connection under a new `UserId` never inherits this one's
    /// window.
    pub fn forget(&mut self, peer: UserId) {
        self.peers.remove(&peer);
    }
}
