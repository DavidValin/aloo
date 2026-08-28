//! The durable send queue: what a message addressed to someone
//! unreachable waits in until they come back (`queue_send_messages`,
//! `docs/SPEC.md` Functionality #34).
//!
//! The transport already keeps a short in-memory queue per link
//! (`p2p::PENDING_MAX`/`PENDING_MAX_AGE` - a thousand payloads, a minute
//! each). That covers a link blinking. It does not cover the case this
//! module exists for: the other person is simply not there, for an hour
//! or a day, and this process may be restarted in the meantime.
//!
//! **What is stored is exactly what would have gone on the wire** - the
//! already-sealed payload (or, for a voice message, its already-sealed
//! chunks), byte for byte. So a queued message keeps whatever layering it
//! was sent under: `pq_hybrid`, or the
//! one-time pad if an OTP session was open with that peer when it was
//! written (`docs/PROTOCOL.md` §16). Nothing here can read any of it, and
//! neither can anyone who takes the file: it is ciphertext addressed to
//! the recipient. That is also why a queued message is never re-sealed on
//! the way out - re-sealing would mean keeping the plaintext instead.
//!
//! Two consequences of sealing at *write* time, both deliberate:
//!
//! - A pad-wrapped message spends its pad position when it is queued, not
//!   when it is delivered. Order is therefore load-bearing, and this queue
//!   is strictly ordered per peer for exactly that reason: the receiver's
//!   pad expects the sequence it was given.
//! - A `pq_hybrid` message is sealed against the recipient's key as it was
//!   then. A peer who rotates their identity while away (§12.4) can no
//!   longer open what was queued for them, and it fails visibly like any
//!   other undecryptable message rather than being silently re-sealed
//!   behind the user's back.
//!
//! **Keyed by nickname, not `UserId`.** A `UserId` is handed out by the
//! server per connection and never survives a reconnect (`docs/PROTOCOL.md`
//! §3), so it cannot name the thing this queue outlives. Same choice, and
//! the same caveat, as `settings::Settings::muted_voice`: a nickname is
//! unique only among currently-connected clients.
//!
//! **Nothing ages out, and nothing is evicted.** A held entry waits as
//! long as it has to: how long it has been there says nothing about
//! whether it should still go, and appending a newer message never costs
//! an older one its place. `retain_contacts` is the only thing that ever
//! removes an entry, and it removes one for exactly one reason - the
//! contact it was sealed for is no longer on this machine, so nothing
//! queued for them could be delivered or read back. The cost of that
//! choice is honest and worth stating: a contact you keep but never reach
//! again accumulates on disk without limit.
//!
//! **Files are not queued.** A transfer is a live, consent-gated,
//! chunked conversation with the receiver (`docs/PROTOCOL.md` §9) - an
//! offer they must accept before a single chunk is sent. Replaying half
//! of one an hour later is not a delivery, so a file payload is left to
//! fail the way it always did. `is_queueable` is the one place that
//! decides.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::p2p_proto::P2pPayload;

/// One thing that was going to the peer: either a reliable payload, or
/// one sealed chunk of a voice message (which travels unreliably and so
/// has no `P2pPayload` of its own - see `p2p::send_unreliable_voice`).
///
/// A local type, never on the wire: it is serialized only into this
/// machine's own queue files, so adding a variant costs no protocol
/// compatibility.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OutboxItem {
    Reliable(P2pPayload),
    VoiceChunk {
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
}

/// One queued send: what was going out, and when it was written.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxEntry {
    /// Seconds since the Unix epoch. Wall-clock rather than an `Instant`
    /// because this outlives the process that wrote it.
    pub queued_at: u64,
    pub item: OutboxItem,
}

/// Whether `item` is a kind this queue keeps.
///
/// Text (`Envelope`, `OtpEnvelope`) and a whole voice message - its
/// reliable `StreamStart`/`StreamKeySetup`/`StreamEnd` plus its sealed
/// chunks - are. Everything else is not: files (see the module doc),
/// and every receipt, ack, pad-provisioning chunk and call-control
/// payload, each of which is either a live conversation with the peer
/// that cannot be replayed out of its moment, or a statement about right
/// now that would be a lie an hour later.
pub fn is_queueable(item: &OutboxItem) -> bool {
    match item {
        OutboxItem::VoiceChunk { .. } => true,
        OutboxItem::Reliable(payload) => matches!(
            payload,
            // Text, either layering (`docs/PROTOCOL.md` §7.2, §16.4).
            P2pPayload::Envelope { .. }
                | P2pPayload::OtpEnvelope { .. }
                // A pq_hybrid voice message: the reliable frame around
                // its chunks.
                | P2pPayload::StreamStart { .. }
                | P2pPayload::StreamKeySetup { .. }
                | P2pPayload::StreamEnd { .. }
                // A pad-wrapped voice message is recorded whole and sent
                // as one payload rather than streamed (§16.5), so this
                // single entry is the entire message.
                | P2pPayload::OtpVoiceOffer { .. }
        ),
    }
}

/// How often the queue is swept for contacts this machine no longer
/// holds keys for (`session::sweep_outbox`), on top of the sweep every
/// session start already does. Twelve hours: what this catches is a
/// contact being deleted, which is a deliberate act a user makes at most
/// a handful of times, so the cost of noticing it late is a file sitting
/// on disk a little longer than it needed to.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(12 * 60 * 60);

/// Where the queue lives by default: `~/.aloo/outbox/`.
pub fn default_dir() -> PathBuf {
    crate::platform::aloo_dir().join("outbox")
}

/// One file per peer, every entry in the order it was written.
///
/// Held open as an in-memory mirror of the directory, so the common case
/// (nothing queued for anyone) costs nothing per send. Append-only:
/// queueing adds one line to the end of a file and nothing ever rewrites
/// one, which is both why a queue keeps its order and why a message is
/// on disk before the call that queued it returns - the whole point is to
/// survive a process that stops without warning.
pub struct Outbox {
    dir: PathBuf,
    /// `nickname -> entries, oldest first`. `BTreeMap` so a listing is
    /// stable, the same reason `muted_voice` is a `BTreeSet`.
    queues: BTreeMap<String, Vec<OutboxEntry>>,
}

impl Outbox {
    /// Reads whatever is on disk. A directory that does not exist yet is
    /// an empty outbox, not an error - that is the first run. An entry
    /// that does not parse is skipped rather than failing the load, the
    /// same tolerance `IdStore::load` and `Settings::parse` apply.
    pub fn load(dir: &Path) -> Self {
        let mut queues = BTreeMap::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("q") {
                    continue;
                }
                let Some(nickname) = path.file_stem().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Ok(contents) = fs::read_to_string(&path) else {
                    continue;
                };
                let parsed = parse_entries(&contents);
                if !parsed.is_empty() {
                    queues.insert(nickname.to_string(), parsed);
                }
            }
        }
        Self {
            dir: dir.to_path_buf(),
            queues,
        }
    }

    /// How many entries are waiting for `nickname`.
    pub fn len_for(&self, nickname: &str) -> usize {
        self.queues.get(nickname).map(Vec::len).unwrap_or(0)
    }

    /// Every nickname with something waiting.
    pub fn peers(&self) -> Vec<String> {
        self.queues.keys().cloned().collect()
    }

    /// Total entries across every peer - what the status notice counts.
    pub fn total(&self) -> usize {
        self.queues.values().map(Vec::len).sum()
    }

    /// Appends one sealed payload to the **end** of `nickname`'s queue.
    ///
    /// Always the end, and never in place of something already there: a
    /// pad-wrapped run is delivered in the order it was sealed, because
    /// that is the order the receiver's pad expects (`docs/PROTOCOL.md`
    /// §16.4). A message that jumped the queue would put every one behind
    /// it out of step with the pad.
    ///
    /// Nothing here evicts, ages out, or otherwise drops what is already
    /// queued - see `retain_contacts` for the one thing that ever
    /// removes an entry.
    ///
    /// A nickname that could not round-trip through a filename is refused
    /// rather than written somewhere unexpected - the same rule
    /// `IdStore::check_and_pin` applies to what it stores.
    pub fn queue(&mut self, nickname: &str, item: OutboxItem) -> io::Result<()> {
        if !crate::validation::nickname_is_registrable(nickname) {
            return Ok(());
        }
        let entry = OutboxEntry {
            queued_at: now_secs(),
            item,
        };
        self.queues
            .entry(nickname.to_string())
            .or_default()
            .push(entry.clone());
        // One line on the end of a file, never a rewrite of everything in
        // it - which is what keeps queueing a message the same cost
        // whether one or ten thousand are already waiting.
        self.append(nickname, &entry)
    }

    /// Drops everything queued for every contact `still_holds_key` says
    /// this client no longer has key material for, and reports how many
    /// entries went.
    ///
    /// **The only thing that ever removes a queued message.** An entry is
    /// ciphertext sealed for one specific contact; while the keys that
    /// pair with it are still here, it can still be delivered, and how
    /// long it has waited says nothing about whether it should be. Once
    /// that contact is gone from this machine - deleted from `/contacts`,
    /// which takes their identity pin and their OTP keychain entries with
    /// it - nothing queued for them can ever be delivered *or* read back,
    /// so it is dead weight and goes.
    ///
    /// Called at session start and every `SWEEP_INTERVAL` after it
    /// (`session::sweep_outbox`).
    pub fn retain_contacts(&mut self, still_holds_key: impl Fn(&str) -> bool) -> usize {
        let dropped: Vec<String> = self
            .queues
            .keys()
            .filter(|nickname| !still_holds_key(nickname))
            .cloned()
            .collect();
        let mut count = 0;
        for nickname in dropped {
            count += self.queues.remove(&nickname).map(|q| q.len()).unwrap_or(0);
            let _ = fs::remove_file(self.path_for(&nickname));
        }
        count
    }

    /// Appends one entry's line to `nickname`'s file, creating it if this
    /// is the first thing queued for them.
    fn append(&self, nickname: &str, entry: &OutboxEntry) -> io::Result<()> {
        let Some(line) = entry_line(entry) else {
            return Ok(());
        };
        let path = self.path_for(nickname);
        crate::platform::ensure_parent_dir(&path)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(line.as_bytes())
    }

    /// Hands back everything waiting for `nickname`, oldest first, and
    /// forgets it - the caller is now responsible for sending it, which
    /// is why this is a take rather than a peek: a message must not be
    /// left behind to be sent twice if the link drops mid-drain.
    ///
    /// Everything comes back, however long it has waited: age is not a
    /// reason to drop a message here (`retain_contacts` is the only one).
    pub fn take(&mut self, nickname: &str) -> Vec<OutboxEntry> {
        let Some(queue) = self.queues.remove(nickname) else {
            return Vec::new();
        };
        let _ = fs::remove_file(self.path_for(nickname));
        queue
    }

    /// Drops everything waiting for `nickname` without sending it.
    pub fn clear(&mut self, nickname: &str) {
        self.queues.remove(nickname);
        let _ = fs::remove_file(self.path_for(nickname));
    }

    fn path_for(&self, nickname: &str) -> PathBuf {
        self.dir.join(format!("{nickname}.q"))
    }

}

/// One entry as the line it is stored as, or `None` if it could not be
/// encoded at all (which nothing this app queues ever is - the payload
/// came off the same encoder on its way to the socket).
fn entry_line(entry: &OutboxEntry) -> Option<String> {
    let bytes = crate::proto::encode(&entry.item).ok()?;
    Some(format!(
        "{} {}\n",
        entry.queued_at,
        crate::crypto::hex_encode(&bytes)
    ))
}

/// One `<queued_at> <hex payload>` line per entry, in order. Hex rather
/// than raw bytes so the file stays line-oriented like every other store
/// this app writes, and so a truncated final write costs one entry rather
/// than the whole file.
fn parse_entries(contents: &str) -> Vec<OutboxEntry> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((queued_at, hex)) = line.split_once(' ') else {
            continue;
        };
        let Ok(queued_at) = queued_at.parse::<u64>() else {
            continue;
        };
        let Some(bytes) = crate::crypto::hex_decode(hex.trim()) else {
            continue;
        };
        let Ok(item) = crate::proto::decode::<OutboxItem>(&bytes) else {
            continue;
        };
        entries.push(OutboxEntry { queued_at, item });
    }
    entries
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
