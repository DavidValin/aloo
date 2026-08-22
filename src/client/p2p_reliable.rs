//! Minimal reliable-delivery layer for the direct UDP peer link: sequence
//! numbers, acks, and timeout-based retransmission for text and file
//! chunks (`docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section) -
//! the same "arrives complete, in order" guarantee TCP gives, built at the
//! application layer since the underlying link is raw UDP. Deliberately
//! minimal, with no selective-repeat and no congestion control, since this
//! operates at chat-message/file-chunk granularity, not bulk throughput.
//! The acks are cumulative and name what has been *delivered in order*
//! (`ArqSender::on_ack`), which is what ties the send window to delivery -
//! but they say nothing about whether the recipient could read what
//! arrived, so they are not what the UI's delivery indicator is built on
//! (`docs/PROTOCOL.md` 7.2.1).
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
/// sender can never drive a receiver into it on reordering alone - the two
/// are raised together for that reason.
pub const REORDER_BUFFER_LIMIT: usize = 512;
/// How many frames may be in flight (sent, not yet acked) at once. Anything
/// beyond it waits in `ArqSender::backlog` and goes out as acks retire the
/// frames ahead of it.
///
/// Without this, a caller that hands over many frames in one pass - an OTP
/// pad is 2048 frames *per megabyte per key*, all queued by a single
/// `/otp` confirmation - had every one of them put on the wire in the same
/// instant: megabytes into a UDP socket with nothing pacing it. The tail of
/// that burst is dropped (by the socket's own send buffer, by the first
/// router that sees it, or by the receiver's buffer), and because the
/// receiver has to hold every frame after a lost one, it blows through
/// `REORDER_BUFFER_LIMIT` and fails the whole link instead.
///
/// It is also, directly, this link's throughput: acks are cumulative and
/// arrive a round trip after the frames they cover, so a sender moves at
/// most one window per RTT no matter how much it has to send. At 16
/// frames of 512 bytes that was ~100KB/s to a peer 80ms away, which made
/// even a modest pad a multi-minute wait and a large one impractical.
///
/// This is the *frame* half of the window, and it exists to keep the
/// receiver's `REORDER_BUFFER_LIMIT` out of reach. The half that actually
/// protects the socket is `SEND_WINDOW_BYTES` - see there for why counting
/// frames alone was not enough.
pub const SEND_WINDOW: usize = 128;

/// How many *bytes* may be in flight at once - the other half of the
/// window, and the one that decides whether a burst survives.
///
/// Counting frames alone is the wrong unit, because frames are not one
/// size: a pad chunk is ~1KB and an OTP setup chunk ~32KB, so a window of
/// 128 frames is 128KB of the first and 4MB of the second. The socket
/// buffer, the first router, and the peer's receive buffer all care about
/// the second number. A 4MB burst into a UDP socket loses roughly a third
/// of itself, which `p2p_test`'s burst test pins directly - and because
/// acks are cumulative, the receiver then has to hold every frame behind
/// the first casualty.
///
/// So the sender is bounded by both, and a bulk transfer of small frames
/// gets the parallelism it needs without a large-frame burst turning the
/// same window into megabytes. 256KB is comfortably under a default UDP
/// socket buffer (~212KB is the usual `wmem_default`, and the kernel
/// doubles what it accounts) while leaving small frames the full
/// `SEND_WINDOW`.
///
/// Beyond this is where the absence of congestion control starts to matter
/// (see the module doc): nothing here measures the path, so the window is
/// the only thing bounding how hard a transfer leans on it.
pub const SEND_WINDOW_BYTES: usize = 256 * 1024;

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
    /// Sum of `unacked`'s payload lengths, maintained alongside it so the
    /// byte half of the window is a comparison rather than a walk of the
    /// whole map on every send.
    unacked_bytes: usize,
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
    /// `PunchDatagram::Reliable` right now, or `None` if the window is
    /// already full - in which case this one is held in the backlog and
    /// comes back out of `on_ack` later. Nothing is ever dropped here;
    /// `None` means "not yet", never "lost".
    pub fn send(&mut self, payload: Vec<u8>) -> Option<(u32, Vec<u8>)> {
        if !self.window_admits(payload.len()) {
            self.backlog.push_back(payload);
            return None;
        }
        Some(self.admit(payload))
    }

    /// Whether a frame of `len` bytes fits the window right now - both
    /// halves must agree (`SEND_WINDOW`, `SEND_WINDOW_BYTES`).
    ///
    /// An empty window always admits, whatever the size: a frame larger
    /// than the whole byte budget would otherwise never be sent at all,
    /// and stalling forever is worse than one oversized burst.
    fn window_admits(&self, len: usize) -> bool {
        if self.unacked.is_empty() {
            return true;
        }
        self.unacked.len() < SEND_WINDOW && self.unacked_bytes + len <= SEND_WINDOW_BYTES
    }

    /// Assigns the next sequence number to `payload` and records it as
    /// awaiting an ack, handing back what to put on the wire.
    fn admit(&mut self, payload: Vec<u8>) -> (u32, Vec<u8>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.unacked_bytes += payload.len();
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
            if let Some(frame) = self.unacked.remove(s) {
                self.unacked_bytes = self.unacked_bytes.saturating_sub(frame.payload.len());
            }
        }
        let mut released = Vec::new();
        while let Some(next) = self.backlog.front() {
            if !self.window_admits(next.len()) {
                break;
            }
            let next = self.backlog.pop_front().expect("just checked the front");
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

    /// How many frames this sender is still carrying - in flight plus
    /// waiting behind the window. The backpressure signal a bulk producer
    /// throttles against (`p2p::PeerLinkManager::outbound_depth`): without
    /// it, something that can generate frames faster than the link retires
    /// them - a one-time pad being streamed to a peer, which may be
    /// terabytes - simply grows `backlog` until memory runs out.
    pub fn depth(&self) -> usize {
        self.unacked.len() + self.backlog.len()
    }

    /// Clears all state and hands back every still-unacked payload, oldest
    /// first, for the caller to re-queue. Called when a link is re-punched:
    /// the sequence space belongs to one punched link, so a new one has to
    /// start from zero on both sides - but the content that was in flight
    /// when the old one died was never delivered and must not be lost with
    /// it (`p2p::PeerLinkManager::reset_transport`).
    pub fn reset(&mut self) -> Vec<Vec<u8>> {
        self.next_seq = 0;
        self.unacked_bytes = 0;
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
