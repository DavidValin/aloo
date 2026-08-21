//! Which incoming voice message or file transfer still owes its sender a
//! `Consumed` receipt (`docs/PROTOCOL.md` 7.2.1), and when that debt comes
//! due.
//!
//! A text message is answered once, the instant its envelope opens, so it
//! needs nothing tracked: the decision and the answer happen in the same
//! place (`client::channel::on_message`). Voice and files are answered
//! twice, and the second answer comes much later than the first - a file
//! is decrypted when its *offer* opens but only saved once every chunk has
//! landed on disk, and audio is decrypted when its stream ends but may sit
//! unheard until the user replays it. The sender's `msg_id` is parked here
//! for that second answer, and settled once the outcome is known.
//!
//! Pure state, no I/O: `client::session` owns the socket and does the
//! actual sending. That split is what makes the timing rule - the whole
//! point of this module - testable without a link or a decoder.

use std::collections::HashMap;

use crate::proto::UserId;

/// Deliberately keyed by `(sender, stream_id)` rather than `stream_id`
/// alone: a `stream_id` is only unique per sender (each peer counts its
/// own), the same pairing every other per-stream map in this client uses.
#[derive(Default)]
pub struct PendingReceipts {
    owed: HashMap<(UserId, u64), u64>,
}

impl PendingReceipts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes that `(from, stream_id)` will owe `from` a `Consumed`
    /// receipt for `msg_id` if it gets that far. `None` means the sender
    /// asked for no receipt at all, and nothing is tracked.
    pub fn remember(&mut self, from: UserId, stream_id: u64, msg_id: Option<u64>) {
        if let Some(msg_id) = msg_id {
            self.owed.insert((from, stream_id), msg_id);
        }
    }

    /// The `msg_id` `(from, stream_id)` belongs to, without settling it -
    /// what the *first* (`Decrypted`) receipt names, which is owed before
    /// the transfer is over and must not consume the entry.
    pub fn msg_id_of(&self, from: UserId, stream_id: u64) -> Option<u64> {
        self.owed.get(&(from, stream_id)).copied()
    }

    /// Settles `(from, stream_id)`, returning the `msg_id` to send a
    /// `Consumed` receipt for - but only if it actually got that far.
    ///
    /// The entry is removed either way, so one transfer earns at most one
    /// `Consumed` receipt however many times an outcome is reported for
    /// it, and one that failed, was rejected, or was never played simply
    /// leaves the sender's row at `DELIVERED`, which is the truth about
    /// it.
    pub fn settle(&mut self, from: UserId, stream_id: u64, consumed: bool) -> Option<u64> {
        let msg_id = self.owed.remove(&(from, stream_id))?;
        consumed.then_some(msg_id)
    }

    /// How many transfers are still outstanding - only ever read by tests
    /// and assertions; nothing in the client branches on it.
    pub fn len(&self) -> usize {
        self.owed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owed.is_empty()
    }
}
