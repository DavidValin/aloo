//! The durable send queue for a one-time-pad session: sealed messages
//! waiting their turn on the wire (`queue_send_messages`, `docs/SPEC.md`
//! Functionality #34).
//!
//! The pq_hybrid queue next door (`client::outbox`) holds content for a
//! peer who is not there and flushes all of it the moment their link
//! opens. A pad session cannot work that way, and this exists because of
//! the two properties that make it different:
//!
//! - **Encrypting is spending.** A message sealed through `otp --encrypt`
//!   has already consumed its pad position, whether or not it ever
//!   reaches anyone. There is no un-spending it, so what is queued here
//!   is *ciphertext* - never the words, which is also why nothing
//!   readable is ever at rest.
//! - **Delivery is strictly one at a time.** The receiver's pad decrypts
//!   in the order it was written, and this side sends the next message
//!   only once the previous one's acknowledgement has come back under
//!   that pad (`otp_store`'s `pending_unacked_out_seq`). So this queue is
//!   drained one entry per ack, in order - never emptied in one go.
//!
//! **Keyed by contact name**, the same key everything else in the OTP
//! layer uses (`crypto::otp::contact_name_for`): derived from the two
//! identity fingerprints and device ids, so it survives a reconnect, a
//! new `UserId`, and a restart of this process - all three of which are
//! the ordinary case for a queue that exists to outlive an absence.
//!
//! **What is here is a spent pad position.** It is discarded for exactly
//! one reason: the contact's keys are gone from this machine, so nothing
//! queued under them could ever be delivered or read back
//! (`retain_contacts`, the same rule and the same sweep
//! `client::outbox` follows). Nothing ages out, and nothing is evicted to
//! make room.
//!
//! Ciphertext is zeroized when it leaves memory and the queue file is
//! overwritten before it is unlinked (`secure_fs`) - the same treatment
//! every other file in this app that ever held pad output gets.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::p2p_proto::P2pPayload;

/// Everything one sealed message needs, both to go on the wire and to
/// arm the acknowledgement gate behind it - all of it per message, which
/// is why it travels with the entry rather than in `otp_store`'s
/// single-outstanding fields.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredEntry {
    /// This message's own pad sequence number: what the receiver's
    /// acknowledgement names, and what `record_sent` arms the gate with
    /// once it is genuinely transmitted.
    seq: u64,
    /// The delivery tag its log row carries, if it has one.
    msg_id: Option<u64>,
    /// `Some(name)` for a channel send, `None` for a DM - rebuilt into
    /// `PendingOtpContent::Text` at transmit time.
    channel: Option<String>,
    /// The proof the peer's acknowledgement must carry to retire this
    /// message (`crypto::otp::ack_proof_for`).
    ack_proof: [u8; 32],
    /// The sealed `P2pPayload`, encoded. Empty for a sealed recording,
    /// whose ciphertext is the file `recording` names rather than an
    /// inline payload - see `StoredRecording`.
    payload: Vec<u8>,
    /// `Some` when this entry is a sealed voice recording. The ciphertext
    /// is a file because that is what `otp --encrypt` produces for one
    /// (file in, file out - it can be megabytes), so the queue keeps a
    /// reference where an inline copy would just duplicate it. The file
    /// lives in this queue's own directory and is owned by it outright:
    /// secure-deleted when the entry is retired or swept, never by
    /// anything else.
    recording: Option<StoredRecording>,
}

/// The on-disk half of a queued voice recording - where its sealed bytes
/// are, and which stream carries them once its turn comes.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRecording {
    /// The ciphertext file, inside the queue's own directory.
    path: String,
    /// The chunk stream the recording travels on when released - the same
    /// id its offer announced, which is how the receiver ties the two
    /// together.
    stream_id: u64,
}

/// One sealed message waiting its turn, and when it was sealed.
///
/// Held as the encoded bytes rather than a decoded `P2pPayload` so the
/// whole of it can be `Zeroizing`: those bytes are pad output, and they
/// are wiped when this entry is dropped.
pub struct OtpOutboxEntry {
    /// Seconds since the Unix epoch, for reporting only - nothing here
    /// expires (see the module doc).
    pub queued_at: u64,
    stored: Zeroizing<Vec<u8>>,
}

impl OtpOutboxEntry {
    fn decode(&self) -> Option<StoredEntry> {
        crate::proto::decode::<StoredEntry>(&self.stored).ok()
    }

    /// This message's pad sequence number.
    pub fn seq(&self) -> Option<u64> {
        self.decode().map(|e| e.seq)
    }

    /// The delivery tag of the row it was logged under, if any.
    pub fn msg_id(&self) -> Option<u64> {
        self.decode().and_then(|e| e.msg_id)
    }

    /// `Some(channel)` for a channel send, `None` for a DM.
    pub fn channel(&self) -> Option<String> {
        self.decode().and_then(|e| e.channel)
    }

    /// The proof this message's acknowledgement must carry.
    pub fn ack_proof(&self) -> Option<[u8; 32]> {
        self.decode().map(|e| e.ack_proof)
    }

    /// The payload to put on the wire. Decoded on demand rather than
    /// held decoded, so the only long-lived copy is the zeroizing one.
    /// `None` for a sealed recording, whose bytes are the file
    /// `recording()` names.
    pub fn payload(&self) -> Option<P2pPayload> {
        let stored = self.decode()?;
        if stored.payload.is_empty() {
            return None;
        }
        crate::proto::decode::<P2pPayload>(&stored.payload).ok()
    }

    /// `Some((ciphertext path, stream_id))` when this entry is a sealed
    /// voice recording rather than an inline payload.
    pub fn recording(&self) -> Option<(PathBuf, u64)> {
        let stored = self.decode()?;
        stored
            .recording
            .map(|r| (PathBuf::from(r.path), r.stream_id))
    }
}

impl std::fmt::Debug for OtpOutboxEntry {
    /// Never prints the payload: it is pad output, and a debug line is
    /// exactly the kind of accidental copy the zeroizing above exists to
    /// prevent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpOutboxEntry")
            .field("queued_at", &self.queued_at)
            .field("bytes", &self.stored.len())
            .finish()
    }
}

/// Where the queue lives by default: `~/.aloo/otp_outbox/`.
pub fn default_dir() -> PathBuf {
    crate::platform::aloo_dir().join("otp_outbox")
}

/// This queue's directory for the client whose `id_store` is at
/// `id_store_path` - its sibling, for the reason `outbox::dir_beside`
/// gives in full.
pub fn dir_beside(id_store_path: &Path) -> PathBuf {
    id_store_path
        .parent()
        .map(|home| home.join("otp_outbox"))
        .unwrap_or_else(default_dir)
}

/// One file per contact, every sealed message in the order it was sealed.
pub struct OtpOutbox {
    dir: PathBuf,
    queues: BTreeMap<String, Vec<OtpOutboxEntry>>,
}

impl OtpOutbox {
    /// Reads whatever is on disk. A directory that does not exist yet is
    /// an empty queue, not an error, and an entry that does not parse is
    /// skipped rather than failing the load - the same tolerance every
    /// other store in this app applies.
    pub fn load(dir: &Path) -> Self {
        // A `.q.new` with no `.q` beside it is a rewrite the process died
        // inside, after the old file was scrubbed and before the new one
        // took its name (`persist`) - it holds the whole surviving queue,
        // so it is adopted, never discarded. With a `.q` still present the
        // stale `.q` wins instead and the sibling is dropped: its extra
        // front entry costs one no-pad retry, where a half-ordering
        // ambiguity could cost a position.
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let staged = entry.path();
                if staged.extension().and_then(|e| e.to_str()) != Some("new") {
                    continue;
                }
                let Some(final_path) = staged.file_stem().map(|stem| dir.join(stem)) else {
                    continue;
                };
                if final_path.extension().and_then(|e| e.to_str()) != Some("q") {
                    continue;
                }
                if final_path.exists() {
                    crate::secure_fs::secure_remove_file(&staged);
                } else if let Err(e) = fs::rename(&staged, &final_path) {
                    crate::log_warn!(
                        "could not adopt a half-rewritten OTP queue file {} ({e})",
                        staged.display()
                    );
                }
            }
        }
        let mut queues = BTreeMap::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("q") {
                    continue;
                }
                let Some(contact) = path.file_stem().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Ok(contents) = fs::read_to_string(&path) else {
                    continue;
                };
                let parsed = parse_entries(&contents);
                if !parsed.is_empty() {
                    queues.insert(contact.to_string(), parsed);
                }
            }
        }
        let out = Self {
            dir: dir.to_path_buf(),
            queues,
        };
        out.sweep_orphaned_recordings();
        out
    }

    /// Securely deletes any `.rec` file no queue entry references - the
    /// residue of a crash between encrypting a recording and appending
    /// its entry. The pad side of that window is `otp_store`'s
    /// write-ahead intent's problem; the ciphertext itself is simply pad
    /// output that will never be sent from here, so it goes.
    fn sweep_orphaned_recordings(&self) {
        let referenced: std::collections::BTreeSet<PathBuf> = self
            .queues
            .values()
            .flatten()
            .filter_map(|entry| entry.recording().map(|(path, _)| path))
            .collect();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("rec")
                && !referenced.contains(&path)
            {
                crate::secure_fs::secure_remove_file(&path);
            }
        }
    }

    /// How many sealed messages are waiting for `contact_name`.
    pub fn len_for(&self, contact_name: &str) -> usize {
        self.queues.get(contact_name).map(Vec::len).unwrap_or(0)
    }

    /// Every contact with something waiting.
    pub fn contacts(&self) -> Vec<String> {
        self.queues.keys().cloned().collect()
    }

    pub fn total(&self) -> usize {
        self.queues.values().map(Vec::len).sum()
    }

    /// Appends one sealed payload to the **end** of `contact_name`'s
    /// queue.
    ///
    /// Always the end: the receiver's pad decrypts in the order these
    /// were sealed, so a message that jumped the queue would put every
    /// one behind it out of step with that pad.
    ///
    /// The write is what makes the pad spend durable - the caller seals
    /// first and enqueues immediately after, so a crash between the two
    /// is the one case `otp_store`'s write-ahead encrypt intent already
    /// exists to reconcile.
    #[allow(clippy::too_many_arguments)]
    pub fn queue(
        &mut self,
        contact_name: &str,
        payload: &P2pPayload,
        seq: u64,
        msg_id: Option<u64>,
        channel: Option<String>,
        ack_proof: [u8; 32],
    ) -> io::Result<bool> {
        // Whether the entry was *accepted* - which the caller must know,
        // because by the time it asks the pad position has already been
        // spent. A refusal here that looked like success would lose the
        // only copy of a message whose pad can never be un-spent, leaving
        // the two ends' pads permanently out of step. Every refusal is
        // decided here, before anything is mutated, so "not accepted"
        // really does mean nothing was kept.
        if !is_filename_safe(contact_name) {
            return Ok(false);
        }
        let Ok(payload) = crate::proto::encode(payload) else {
            return Ok(false);
        };
        let Ok(bytes) = crate::proto::encode(&StoredEntry {
            seq,
            msg_id,
            channel,
            ack_proof,
            payload,
            recording: None,
        }) else {
            return Ok(false);
        };
        let entry = OtpOutboxEntry {
            queued_at: now_secs(),
            stored: Zeroizing::new(bytes),
        };
        let line = entry_line(&entry);
        self.queues
            .entry(contact_name.to_string())
            .or_default()
            .push(entry);
        let path = self.path_for(contact_name);
        crate::platform::ensure_parent_dir(&path)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(line.as_bytes())?;
        Ok(true)
    }

    /// Where `contact_name`'s recording for pad position `seq` belongs:
    /// inside this queue's own directory, named by the two things that
    /// identify it. The caller encrypts straight into this path and then
    /// queues it (`queue_recording`), so there is never a copy anywhere a
    /// different sweep could reach - this queue is the file's one owner.
    pub fn recording_path_for(&self, contact_name: &str, seq: u64) -> Option<PathBuf> {
        if !is_filename_safe(contact_name) {
            return None;
        }
        let path = self.dir.join(format!("{contact_name}.{seq}.rec"));
        // The directory has to exist before `otp --encrypt` can open its
        // destination inside it - on a fresh install nothing else has
        // created it yet (an inline entry's append does so lazily).
        crate::platform::ensure_parent_dir(&path).ok()?;
        Some(path)
    }

    /// Appends a sealed voice recording to the end of `contact_name`'s
    /// queue - `queue`'s counterpart for ciphertext that is a file rather
    /// than an inline payload, on the same terms: the pad position is
    /// already spent by the time this is asked, so `Ok(false)` means the
    /// caller still holds the only copy and must not drop it.
    ///
    /// `path` must be the one `recording_path_for` gave out; from here on
    /// the queue owns that file, secure-deleting it when the entry is
    /// retired (`take_front`) or its contact swept (`retain_contacts`).
    pub fn queue_recording(
        &mut self,
        contact_name: &str,
        path: &Path,
        stream_id: u64,
        seq: u64,
        msg_id: Option<u64>,
        ack_proof: [u8; 32],
    ) -> io::Result<bool> {
        if !is_filename_safe(contact_name) {
            return Ok(false);
        }
        let Ok(bytes) = crate::proto::encode(&StoredEntry {
            seq,
            msg_id,
            channel: None,
            ack_proof,
            payload: Vec::new(),
            recording: Some(StoredRecording {
                path: path.to_string_lossy().into_owned(),
                stream_id,
            }),
        }) else {
            return Ok(false);
        };
        let entry = OtpOutboxEntry {
            queued_at: now_secs(),
            stored: Zeroizing::new(bytes),
        };
        let line = entry_line(&entry);
        self.queues
            .entry(contact_name.to_string())
            .or_default()
            .push(entry);
        let file_path = self.path_for(contact_name);
        crate::platform::ensure_parent_dir(&file_path)?;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        file.write_all(line.as_bytes())?;
        Ok(true)
    }

    /// Every entry waiting for `contact_name`, front first - read-only,
    /// for callers that need to see the whole line rather than only the
    /// front (a test above all).
    pub fn entries_for(&self, contact_name: &str) -> &[OtpOutboxEntry] {
        self.queues
            .get(contact_name)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The next sealed message for `contact_name`, without removing it -
    /// what the caller puts on the wire and then waits for an ack on.
    ///
    /// A peek rather than a take, deliberately: the entry is only retired
    /// once the peer has acknowledged it (`take_front`). A send that left
    /// the machine but was never acknowledged is exactly what has to be
    /// retried, and a taken-then-lost entry could not be.
    pub fn front(&self, contact_name: &str) -> Option<&OtpOutboxEntry> {
        self.queues.get(contact_name)?.first()
    }

    /// Retires the message at the front of `contact_name`'s queue - its
    /// acknowledgement has come back, so it is genuinely delivered.
    ///
    /// The file is rewritten without it, and securely erased once the
    /// queue is empty: what was in it is pad output.
    pub fn take_front(&mut self, contact_name: &str) -> io::Result<()> {
        let Some(queue) = self.queues.get_mut(contact_name) else {
            return Ok(());
        };
        if queue.is_empty() {
            return Ok(());
        }
        // Dropped here, which is what zeroizes it - and a recording's
        // ciphertext file goes with it: its acknowledgement just proved
        // the peer holds the bytes, so this copy is pad output with no
        // remaining purpose.
        let retired = queue.remove(0);
        if let Some((path, _)) = retired.recording() {
            crate::secure_fs::secure_remove_file(&path);
        }
        if queue.is_empty() {
            self.queues.remove(contact_name);
            crate::secure_fs::secure_remove_file(&self.path_for(contact_name));
            return Ok(());
        }
        self.persist(contact_name)
    }

    /// Drops everything queued for every contact `still_holds_key` says
    /// this machine no longer has key material for.
    ///
    /// The only thing that ever removes a queued message - see the module
    /// doc. Each file is securely erased rather than merely unlinked.
    pub fn retain_contacts(&mut self, still_holds_key: impl Fn(&str) -> bool) -> usize {
        let gone: Vec<String> = self
            .queues
            .keys()
            .filter(|contact| !still_holds_key(contact))
            .cloned()
            .collect();
        let mut count = 0;
        for contact in gone {
            if let Some(queue) = self.queues.remove(&contact) {
                count += queue.len();
                // Each queued recording's ciphertext goes with its entry -
                // sealed for keys this machine no longer holds, so nobody
                // could ever read it, and it is pad output either way.
                for entry in &queue {
                    if let Some((path, _)) = entry.recording() {
                        crate::secure_fs::secure_remove_file(&path);
                    }
                }
            }
            crate::secure_fs::secure_remove_file(&self.path_for(&contact));
        }
        count
    }

    fn path_for(&self, contact_name: &str) -> PathBuf {
        self.dir.join(format!("{contact_name}.q"))
    }

    /// Rewrites one contact's whole file - only ever after an entry is
    /// retired from the front, which is the one change a plain append
    /// cannot express.
    ///
    /// Ordered so no crash instant loses more than it must: the new
    /// contents go to a sibling `.q.new` file first, then the old file -
    /// which held one more piece of pad output than the new one does - is
    /// scrubbed, then the sibling takes its name. A crash before the
    /// scrub leaves both (the stale `.q` wins, and its extra front entry
    /// is a retry the receiver answers from its recorded ack at no pad
    /// cost); a crash between scrub and rename leaves only `.q.new`,
    /// which `load` adopts. The old order - scrub, then write - had a
    /// window where the whole remaining queue died with the process:
    /// every entry in it a spent position nothing could account for.
    fn persist(&self, contact_name: &str) -> io::Result<()> {
        let path = self.path_for(contact_name);
        let Some(queue) = self.queues.get(contact_name) else {
            crate::secure_fs::secure_remove_file(&path);
            return Ok(());
        };
        crate::platform::ensure_parent_dir(&path)?;
        let contents: String = queue.iter().map(entry_line).collect();
        let staged = staged_path(&path);
        fs::write(&staged, contents)?;
        crate::secure_fs::secure_remove_file(&path);
        fs::rename(&staged, &path)
    }
}

/// The sibling a rewrite stages its new contents in before taking the
/// real name (`persist`, and `load`'s adoption of one left behind).
fn staged_path(path: &Path) -> PathBuf {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".new");
    PathBuf::from(staged)
}

/// Whether `contact_name` may be used as this store's filename.
///
/// Stricter than `validation::is_storable`, which only refuses line
/// breaks: this value becomes a path component, so anything that could
/// climb out of the directory or name a different file must be refused
/// outright rather than sanitized into something that collides with a
/// real contact.
///
/// A genuine contact name is lowercase hex joined by `-`
/// (`crypto::otp::contact_name_for`), optionally behind a `mail-` prefix,
/// so this admits every real one and nothing else.
fn is_filename_safe(contact_name: &str) -> bool {
    !contact_name.is_empty()
        && contact_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn entry_line(entry: &OtpOutboxEntry) -> String {
    format!(
        "{} {}\n",
        entry.queued_at,
        crate::crypto::hex_encode(&entry.stored)
    )
}

/// One `<queued_at> <hex sealed payload>` line per entry, in order - the
/// same line-oriented shape every other store here writes, so a truncated
/// final write costs one entry rather than the file.
fn parse_entries(contents: &str) -> Vec<OtpOutboxEntry> {
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
        // Refused rather than kept: an entry that cannot be decoded can
        // never be sent, and holding it would stall the whole queue
        // behind it forever. Never silent, though - a dropped entry is a
        // spent pad position that will now never reach its peer, and the
        // pair's pads will disagree until the contact is re-provisioned.
        if crate::proto::decode::<StoredEntry>(&bytes).is_err() {
            crate::log_warn!(
                "an OTP queue entry could not be decoded and was dropped - its pad \
                 position is spent and will never be delivered; if this contact's \
                 messages stop arriving, re-provision the pad"
            );
            continue;
        }
        entries.push(OtpOutboxEntry {
            queued_at,
            stored: Zeroizing::new(bytes),
        });
    }
    entries
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
