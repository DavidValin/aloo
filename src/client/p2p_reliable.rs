//! Minimal reliable-delivery layer for the direct UDP peer link: sequence
//! numbers, acks, and timeout-based retransmission for text and file
//! chunks (`docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section) -
//! the same "arrives complete, in order" guarantee TCP gives, built at the
//! application layer since the underlying link is raw UDP. Deliberately
//! minimal, with no congestion control, no selective-repeat, and no
//! cumulative acks, since this operates at chat-message/file-chunk
//! granularity, not bulk throughput. Pure state/logic, no sockets -
//! `crate::client::p2p` drives it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Initial retransmit backoff; doubles per retry up to `MAX_RETRANSMIT`.
const INITIAL_RETRANSMIT: Duration = Duration::from_millis(400);
const MAX_RETRANSMIT: Duration = Duration::from_secs(3);
/// Giving up after this many retries treats the link as dead - there is no
/// relay fallback, so a sender that stops getting acks must surface a
/// failure rather than retry forever.
pub const MAX_RETRIES: u32 = 10;
/// Bound on how many out-of-order frames a receiver buffers before giving
/// up and failing the link, rather than growing unbounded on a hostile or
/// badly reordering path.
const REORDER_BUFFER_LIMIT: usize = 64;

struct Unacked {
    payload: Vec<u8>,
    sent_at: Instant,
    backoff: Duration,
    retries: u32,
}

/// One peer link's outgoing reliable frames.
#[derive(Default)]
pub struct ArqSender {
    next_seq: u32,
    unacked: BTreeMap<u32, Unacked>,
}

impl ArqSender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assigns the next sequence number to `payload` and records it as
    /// awaiting an ack - returns the assigned `seq` for the caller to
    /// actually transmit as a `PunchDatagram::Reliable { seq, payload }`.
    pub fn send(&mut self, payload: Vec<u8>) -> u32 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.unacked.insert(
            seq,
            Unacked {
                payload,
                sent_at: Instant::now(),
                backoff: INITIAL_RETRANSMIT,
                retries: 0,
            },
        );
        seq
    }

    /// Retires a frame once its `Ack` arrives. A no-op for an unknown or
    /// already-retired `seq` (a duplicate ack, or one for a frame from
    /// before a link reset).
    pub fn on_ack(&mut self, seq: u32) {
        self.unacked.remove(&seq);
    }

    /// Frames due for retransmission right now, in ascending `seq` order.
    /// Returns `Err(())` once any single frame has exhausted `MAX_RETRIES`,
    /// which the caller must treat as the link failing entirely, per the
    /// no-relay-fallback rule, rather than retrying that frame forever.
    pub fn due_for_retransmit(&mut self, now: Instant) -> Result<Vec<(u32, Vec<u8>)>, ()> {
        let mut due = Vec::new();
        for (&seq, unacked) in self.unacked.iter_mut() {
            if now.duration_since(unacked.sent_at) >= unacked.backoff {
                if unacked.retries >= MAX_RETRIES {
                    return Err(());
                }
                unacked.retries += 1;
                unacked.sent_at = now;
                unacked.backoff = (unacked.backoff * 2).min(MAX_RETRANSMIT);
                due.push((seq, unacked.payload.clone()));
            }
        }
        Ok(due)
    }

    pub fn has_pending(&self) -> bool {
        !self.unacked.is_empty()
    }

    /// Clears all state and hands back every still-unacked payload, oldest
    /// first, for the caller to re-queue. Called when a link is re-punched:
    /// the sequence space belongs to one punched link, so a new one has to
    /// start from zero on both sides - but the content that was in flight
    /// when the old one died was never delivered and must not be lost with
    /// it (`p2p::PeerLinkManager::reset_transport`).
    pub fn reset(&mut self) -> Vec<Vec<u8>> {
        self.next_seq = 0;
        std::mem::take(&mut self.unacked)
            .into_values()
            .map(|u| u.payload)
            .collect()
    }
}

/// One peer link's incoming reliable frames: reassembles them into delivery
/// order regardless of arrival order. Every frame should be acked by the
/// caller as soon as `receive` is called, even a duplicate or one received
/// after the link already failed - that's what lets the sender retire it.
#[derive(Default)]
pub struct ArqReceiver {
    expected: u32,
    reorder: BTreeMap<u32, Vec<u8>>,
    failed: bool,
}

impl ArqReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one received `(seq, payload)` frame. Returns every payload
    /// that becomes deliverable, in order, as a result - zero (a duplicate,
    /// a not-yet-contiguous out-of-order arrival, or the link already
    /// failed), one (the common case), or more if this frame fills a gap
    /// ahead of already-buffered ones.
    pub fn receive(&mut self, seq: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if self.failed {
            return Vec::new();
        }
        if seq_lt(seq, self.expected) {
            return Vec::new(); // old duplicate
        }
        if seq == self.expected {
            let mut out = vec![payload];
            self.expected = self.expected.wrapping_add(1);
            while let Some(next) = self.reorder.remove(&self.expected) {
                out.push(next);
                self.expected = self.expected.wrapping_add(1);
            }
            out
        } else {
            if !self.reorder.contains_key(&seq) {
                if self.reorder.len() >= REORDER_BUFFER_LIMIT {
                    self.failed = true;
                    return Vec::new();
                }
                self.reorder.insert(seq, payload);
            }
            Vec::new()
        }
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Clears all state, including the `failed` latch, so a re-punched
    /// link starts expecting sequence zero again - the counterpart of
    /// `ArqSender::reset` on the receiving side.
    pub fn reset(&mut self) {
        self.expected = 0;
        self.reorder.clear();
        self.failed = false;
    }
}

/// `u32` sequence comparison ("is `a` before `b`?") using wrapping
/// distance, so wraparound near `u32::MAX` isn't misread as a huge jump
/// backward. A stream would need over four billion frames to actually wrap
/// - this is defensive, not load-bearing.
fn seq_lt(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) > (u32::MAX / 2)
}
