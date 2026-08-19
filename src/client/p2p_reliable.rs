//! Minimal reliable-delivery layer for the direct UDP peer link: sequence
//! numbers, acks, and timeout-based retransmission for text and file
//! chunks (`docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section) -
//! the same "arrives complete, in order" guarantee TCP gives, built at the
//! application layer since the underlying link is raw UDP. Deliberately
//! minimal, with no selective-repeat and no cumulative acks, since this
//! operates at chat-message/file-chunk granularity, not bulk throughput.
//! The one concession to bulk is `SEND_WINDOW` (see its doc): an OTP pad
//! provisioning arrives here as hundreds of frames handed over in one go,
//! and blasting all of them at the socket at once is not something the
//! path - or the peer's reorder buffer - survives. Pure state/logic, no
//! sockets - `crate::client::p2p` drives it.

use std::collections::{BTreeMap, VecDeque};
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
/// badly reordering path. Comfortably above `SEND_WINDOW`, so a well-behaved
/// sender can never drive a receiver into it on reordering alone.
const REORDER_BUFFER_LIMIT: usize = 64;
/// How many frames may be in flight (sent, not yet acked) at once. Anything
/// beyond it waits in `ArqSender::backlog` and goes out as acks retire the
/// frames ahead of it.
///
/// Without this, a caller that hands over many frames in one pass - an OTP
/// pad is 64 frames *per megabyte per key*, all queued by a single
/// `/otp` confirmation - had every one of them put on the wire in the same
/// instant: megabytes into a UDP socket with nothing pacing it. The tail of
/// that burst is dropped (by the socket's own send buffer, by the first
/// router that sees it, or by the receiver's buffer), and because the
/// receiver has to hold every frame after a lost one, it blows through
/// `REORDER_BUFFER_LIMIT` and fails the whole link instead. Small enough to
/// stay well under both that limit and any plausible socket buffer.
pub const SEND_WINDOW: usize = 16;

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
    /// Frames accepted from the caller but not yet on the wire, oldest
    /// first, because `SEND_WINDOW` frames were already in flight when they
    /// were handed over. Sequence numbers are assigned on the way *out* of
    /// here, not on the way in, so what the peer sees is still one gapless
    /// ascending run.
    backlog: VecDeque<Vec<u8>>,
}

impl ArqSender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Offers one payload for reliable delivery. Returns the
    /// `(seq, payload)` the caller must transmit as a
    /// `PunchDatagram::Reliable` right now, or `None` if `SEND_WINDOW`
    /// frames are already in flight - in which case this one is held in the
    /// backlog and comes back out of `on_ack` later. Nothing is ever
    /// dropped here; `None` means "not yet", never "lost".
    pub fn send(&mut self, payload: Vec<u8>) -> Option<(u32, Vec<u8>)> {
        if self.unacked.len() >= SEND_WINDOW {
            self.backlog.push_back(payload);
            return None;
        }
        Some(self.admit(payload))
    }

    /// Assigns the next sequence number to `payload` and records it as
    /// awaiting an ack, handing back what to put on the wire.
    fn admit(&mut self, payload: Vec<u8>) -> (u32, Vec<u8>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.unacked.insert(
            seq,
            Unacked {
                payload: payload.clone(),
                sent_at: Instant::now(),
                backoff: INITIAL_RETRANSMIT,
                retries: 0,
            },
        );
        (seq, payload)
    }

    /// Retires every frame up to and including `seq` - the ack is
    /// *cumulative*, naming the last frame the peer has actually delivered
    /// in order rather than the last one it happened to receive (see
    /// `ArqReceiver::ack_seq`). Returns whatever that frees from the
    /// backlog for the caller to transmit, oldest first.
    ///
    /// Cumulative is what ties the send window to delivery instead of to
    /// arrival. Acking each frame as it arrived meant a frame sitting in the
    /// peer's reorder buffer - received, but undeliverable behind a gap -
    /// retired a slot and released the next frame, so the window slid
    /// forward on data the peer could not yet use: the whole burst streamed
    /// out, piled into that buffer, and blew `REORDER_BUFFER_LIMIT` anyway.
    /// Worse, the sender had by then retired frames the peer discards when
    /// the failed link resets, so they were never retransmitted and the
    /// stream simply stopped. Behind a gap, a cumulative ack repeats the
    /// frontier and retires nothing, which is exactly the intended stall.
    ///
    /// A duplicate or stale ack retires nothing and releases nothing, so a
    /// replayed one cannot pull the backlog forward.
    pub fn on_ack(&mut self, seq: u32) -> Vec<(u32, Vec<u8>)> {
        let retired: Vec<u32> = self
            .unacked
            .range(..=seq)
            .map(|(&s, _)| s)
            .collect();
        for s in &retired {
            self.unacked.remove(s);
        }
        let mut released = Vec::new();
        while self.unacked.len() < SEND_WINDOW {
            let Some(next) = self.backlog.pop_front() else {
                break;
            };
            released.push(self.admit(next));
        }
        released
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
        !self.unacked.is_empty() || !self.backlog.is_empty()
    }

    /// Clears all state and hands back every still-unacked payload, oldest
    /// first, for the caller to re-queue. Called when a link is re-punched:
    /// the sequence space belongs to one punched link, so a new one has to
    /// start from zero on both sides - but the content that was in flight
    /// when the old one died was never delivered and must not be lost with
    /// it (`p2p::PeerLinkManager::reset_transport`).
    pub fn reset(&mut self) -> Vec<Vec<u8>> {
        self.next_seq = 0;
        // In-flight frames first (`BTreeMap` iterates them in `seq` order),
        // then anything that never got a sequence number at all - which is
        // exactly the order they were handed over in, and the order a
        // chunked payload has to be re-sent in to reassemble.
        std::mem::take(&mut self.unacked)
            .into_values()
            .map(|u| u.payload)
            .chain(std::mem::take(&mut self.backlog))
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

    /// The last sequence number delivered in order - what an `Ack` must
    /// name, since a cumulative ack is a statement about delivery, not
    /// arrival (`ArqSender::on_ack`). `None` while nothing has been
    /// delivered yet: there is nothing to acknowledge, and the sender
    /// retransmitting frame zero until it lands is the correct outcome.
    pub fn ack_seq(&self) -> Option<u32> {
        (self.expected != 0).then(|| self.expected.wrapping_sub(1))
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
