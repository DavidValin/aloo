//! Refusing a send that has already arrived once.
//!
//! Every `pq_hybrid` send is signed over a binding that names the sender's
//! own `send_id` (`crypto::pq::SendBinding`), so a captured message can't be
//! edited - but it could still be re-injected verbatim onto the same link.
//! This is what stops that: a send must strictly exceed everything already
//! accepted from that peer.
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

#[derive(Default)]
pub struct ReplayGuard {
    last: HashMap<UserId, u64>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `send_id` as seen from `peer`, returning whether it was
    /// genuinely new. A repeat - or anything older than what has already
    /// been accepted - returns `false` and changes nothing.
    pub fn accept(&mut self, peer: UserId, send_id: u64) -> bool {
        match self.last.get(&peer) {
            Some(&seen) if send_id <= seen => false,
            _ => {
                self.last.insert(peer, send_id);
                true
            }
        }
    }

    /// The highest `send_id` accepted from `peer` so far, if any.
    pub fn highest(&self, peer: UserId) -> Option<u64> {
        self.last.get(&peer).copied()
    }

    /// Forgets a peer entirely - used when their connection ends, so a
    /// later connection under a new `UserId` never inherits this one's
    /// counter.
    pub fn forget(&mut self, peer: UserId) {
        self.last.remove(&peer);
    }
}
