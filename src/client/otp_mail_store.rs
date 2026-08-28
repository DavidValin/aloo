//! The client's persistent OTP mail state (docs/PROTOCOL.md §17): one flat
//! index file in the `idstore`/`otp_store` convention, plus - for received
//! mail only - a pair of blob files per mail. Everything lives under one
//! directory (`~/.aloo/otp_mail/` by default) so removing a mail can't
//! orphan half of it somewhere else.
//!
//! **Sent** mail keeps only a reference (id, recipient, contact, seq,
//! timestamp, delivery status) - never any content. The ciphertext a retry
//! needs is the `otp` CLI's own `.last_sent` safety copy
//! (`otp --recover-last`), not a second copy here; content the *user* might
//! want back was theirs to begin with.
//!
//! **Received** mail is stored as `<mail_id>.ct` + `<mail_id>.pad`: the
//! decrypted payload re-encrypted under a locally-generated one-time pad
//! (`crypto::otp::repad`) the moment it arrives, because the keychain pad
//! that carried it is physically destroyed by the one genuine
//! `otp --decrypt` (that's the tool's whole contract) and can never decrypt
//! it again. Reading a mail XORs the two files in memory; removing it
//! securely deletes both, after which the content is unrecoverable - the
//! exact "ciphertext and pad on disk until the user removes the email"
//! lifecycle the feature specifies. Plaintext is never at rest.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::validation::is_storable;

/// Where a sent mail currently stands in its delivery lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentMailStatus {
    /// Uploaded (or upload attempted), no `OtpMailResult` seen yet - the
    /// state a retry acts on (`client::otp_mail::resend_pending`).
    AwaitingServerAck,
    /// The server acknowledged durable storage; the recipient hasn't
    /// fetched it yet.
    StoredOnServer,
    /// The recipient genuinely decrypted it (`OtpMailDelivered`).
    Delivered,
    /// The server refused it (`OtpMailResult { ok: false }`) - terminal,
    /// never retried: the pad bytes are spent either way.
    Failed,
}

impl SentMailStatus {
    fn as_str(self) -> &'static str {
        match self {
            SentMailStatus::AwaitingServerAck => "awaiting",
            SentMailStatus::StoredOnServer => "stored",
            SentMailStatus::Delivered => "delivered",
            SentMailStatus::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "awaiting" => Some(SentMailStatus::AwaitingServerAck),
            "stored" => Some(SentMailStatus::StoredOnServer),
            "delivered" => Some(SentMailStatus::Delivered),
            "failed" => Some(SentMailStatus::Failed),
            _ => None,
        }
    }
}

/// One sent mail's local reference - everything needed to show its
/// delivery status and to retry it, nothing of its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMailRef {
    pub mail_id: String,
    pub to: String,
    pub contact_name: String,
    /// The OTP send-counter position this mail spent
    /// (`otp_store::OtpContactState::next_out_seq` at send time) - what a
    /// later `OtpMailResult` acknowledges through
    /// `OtpStore::record_acked`.
    pub seq: u64,
    pub sent_at_utc: u64,
    pub status: SentMailStatus,
}

/// One received mail's index entry; its content is the `.ct`/`.pad` blob
/// pair beside the index (`OtpMailStore::read_received_payload`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedMailRef {
    pub mail_id: String,
    pub from: String,
    pub sent_at_utc: u64,
    pub received_at_utc: u64,
    /// Payload size in bytes (each blob file's length) - shown in the
    /// mailbox without opening the blobs.
    pub size: u64,
    /// Whether `handle_read` has opened this mail yet - what the header's
    /// "<n> unread OTP Mails" counts. `false` the moment it arrives;
    /// `mark_read` is the only thing that ever flips it back.
    pub read: bool,
}

/// The index + blob directory. Like `OtpStore`, saved synchronously after
/// every mutation: a mail acknowledged to the server but missing from this
/// index would be gone for good (the server deleted its copy on ack).
pub struct OtpMailStore {
    dir: PathBuf,
    sent: HashMap<String, SentMailRef>,
    received: HashMap<String, ReceivedMailRef>,
}

impl OtpMailStore {
    /// `~/.aloo/otp_mail` (`crate::platform::aloo_dir`).
    pub fn default_dir() -> PathBuf {
        crate::platform::aloo_dir().join("otp_mail")
    }

    pub fn new_empty(dir: PathBuf) -> Self {
        Self {
            dir,
            sent: HashMap::new(),
            received: HashMap::new(),
        }
    }

    /// Loads the index at `dir/index` if it exists; a missing file or
    /// directory just starts empty. Malformed lines are skipped, same
    /// tolerance as every other flat-file store here.
    pub fn load(dir: PathBuf) -> io::Result<Self> {
        let mut store = Self::new_empty(dir);
        if let Some(contents) = crate::platform::read_to_string_optional(&store.index_path())? {
            for line in contents.lines() {
                store.parse_line(line);
            }
        }
        Ok(store)
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index")
    }

    fn ct_path(&self, mail_id: &str) -> PathBuf {
        self.dir.join(format!("{mail_id}.ct"))
    }

    fn pad_path(&self, mail_id: &str) -> PathBuf {
        self.dir.join(format!("{mail_id}.pad"))
    }

    fn parse_line(&mut self, line: &str) {
        let mut parts = line.split('\t');
        match parts.next() {
            Some("S") => {
                let (Some(mail_id), Some(to), Some(contact_name), Some(seq), Some(sent), Some(status)) = (
                    parts.next(),
                    parts.next(),
                    parts.next(),
                    parts.next().and_then(|s| s.parse().ok()),
                    parts.next().and_then(|s| s.parse().ok()),
                    parts.next().and_then(SentMailStatus::parse),
                ) else {
                    return;
                };
                self.sent.insert(
                    mail_id.to_string(),
                    SentMailRef {
                        mail_id: mail_id.to_string(),
                        to: to.to_string(),
                        contact_name: contact_name.to_string(),
                        seq,
                        sent_at_utc: sent,
                        status,
                    },
                );
            }
            Some("R") => {
                let (Some(mail_id), Some(from), Some(sent), Some(received), Some(size)) = (
                    parts.next(),
                    parts.next(),
                    parts.next().and_then(|s| s.parse().ok()),
                    parts.next().and_then(|s| s.parse().ok()),
                    parts.next().and_then(|s| s.parse().ok()),
                ) else {
                    return;
                };
                // A line written before `read` existed loads as already
                // read - the safe, quiet default (same reasoning as
                // `otp_store`'s own pre-existing fields loading as "nothing
                // owed"), so upgrading never surfaces a stampede of
                // "new" mail that was really just never marked either way.
                let read = parts.next().and_then(|s| s.parse::<u8>().ok()).unwrap_or(1) != 0;
                self.received.insert(
                    mail_id.to_string(),
                    ReceivedMailRef {
                        mail_id: mail_id.to_string(),
                        from: from.to_string(),
                        sent_at_utc: sent,
                        received_at_utc: received,
                        size,
                        read,
                    },
                );
            }
            _ => {}
        }
    }

    /// Persists the index (`S`/`R`-tagged tab-delimited lines, sorted by
    /// id so the file diffs cleanly). Blob files are written separately by
    /// `store_received_payload` - this only records what exists.
    pub fn save(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut out = String::new();
        let mut sent_ids: Vec<&String> = self.sent.keys().collect();
        sent_ids.sort();
        for id in sent_ids {
            let r = &self.sent[id];
            if !is_storable(&r.to) || !is_storable(&r.contact_name) {
                continue;
            }
            out.push_str(&format!(
                "S\t{}\t{}\t{}\t{}\t{}\t{}\n",
                r.mail_id,
                r.to,
                r.contact_name,
                r.seq,
                r.sent_at_utc,
                r.status.as_str()
            ));
        }
        let mut received_ids: Vec<&String> = self.received.keys().collect();
        received_ids.sort();
        for id in received_ids {
            let r = &self.received[id];
            if !is_storable(&r.from) {
                continue;
            }
            out.push_str(&format!(
                "R\t{}\t{}\t{}\t{}\t{}\t{}\n",
                r.mail_id, r.from, r.sent_at_utc, r.received_at_utc, r.size, r.read as u8
            ));
        }
        fs::write(self.index_path(), out)
    }

    // ---------------------------------------------------------------
    // Sent references
    // ---------------------------------------------------------------

    pub fn record_sent(&mut self, r: SentMailRef) {
        self.sent.insert(r.mail_id.clone(), r);
    }

    pub fn sent_ref(&self, mail_id: &str) -> Option<&SentMailRef> {
        self.sent.get(mail_id)
    }

    /// Moves `mail_id`'s status forward. A `Delivered` ref never regresses
    /// (a late/duplicate `OtpMailResult` after delivery must not un-deliver
    /// it); any other transition is applied as given. Returns whether
    /// anything changed.
    pub fn set_sent_status(&mut self, mail_id: &str, status: SentMailStatus) -> bool {
        match self.sent.get_mut(mail_id) {
            Some(r) if r.status == SentMailStatus::Delivered && status != SentMailStatus::Delivered => {
                false
            }
            Some(r) if r.status != status => {
                r.status = status;
                true
            }
            _ => false,
        }
    }

    /// Every sent mail still waiting for the server's storage
    /// acknowledgement - `client::otp_mail::resend_pending`'s input on
    /// (re)connect.
    pub fn awaiting_server_ack(&self) -> Vec<SentMailRef> {
        let mut v: Vec<SentMailRef> = self
            .sent
            .values()
            .filter(|r| r.status == SentMailStatus::AwaitingServerAck)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.mail_id.cmp(&b.mail_id));
        v
    }

    /// Drops a sent mail's local reference (the user removing it from the
    /// mailbox) - purely local bookkeeping; nothing about the mail itself
    /// changes anywhere else.
    pub fn remove_sent(&mut self, mail_id: &str) -> bool {
        self.sent.remove(mail_id).is_some()
    }

    // ---------------------------------------------------------------
    // Received mail
    // ---------------------------------------------------------------

    pub fn received_ref(&self, mail_id: &str) -> Option<&ReceivedMailRef> {
        self.received.get(mail_id)
    }

    pub fn has_received(&self, mail_id: &str) -> bool {
        self.received.contains_key(mail_id)
    }

    /// Writes a received mail's re-padded blob pair (0600 on unix) and
    /// records its index entry. `ciphertext`/`pad` are `crypto::otp::repad`'s
    /// two halves; the caller has already destroyed the plaintext. The
    /// caller saves the index via `save` - kept separate so a caller can
    /// batch it with other mutations.
    pub fn store_received_payload(
        &mut self,
        r: ReceivedMailRef,
        ciphertext: &[u8],
        pad: &[u8],
    ) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mail_id = r.mail_id.clone();
        fs::write(self.ct_path(&mail_id), ciphertext)?;
        fs::write(self.pad_path(&mail_id), pad)?;
        restrict_file_permissions(&self.ct_path(&mail_id));
        restrict_file_permissions(&self.pad_path(&mail_id));
        self.received.insert(mail_id, r);
        Ok(())
    }

    /// Reads a received mail's blob pair back and XORs them in memory -
    /// the only way its plaintext ever exists again, and only for as long
    /// as the caller holds the returned bytes. `None` if either file is
    /// missing/unreadable or the two lengths disagree.
    pub fn read_received_payload(&self, mail_id: &str) -> Option<Vec<u8>> {
        if !self.received.contains_key(mail_id) {
            return None;
        }
        let ct = fs::read(self.ct_path(mail_id)).ok()?;
        let pad = fs::read(self.pad_path(mail_id)).ok()?;
        crate::crypto::otp::xor_pad(&ct, &pad)
    }

    /// Removes a received mail: both blob files are overwritten with zeros
    /// before deletion (the pad half is genuine one-time-pad material -
    /// same handling `client::otp::secure_remove_file` gives every other
    /// pad-carrying temp file) and the index entry is dropped. After this
    /// the mail's content is unrecoverable anywhere. Returns whether the
    /// mail existed.
    pub fn remove_received(&mut self, mail_id: &str) -> bool {
        if self.received.remove(mail_id).is_none() {
            return false;
        }
        secure_remove(&self.ct_path(mail_id));
        secure_remove(&self.pad_path(mail_id));
        true
    }

    /// Marks a received mail read - `handle_read`'s side effect on opening
    /// it. Returns whether it actually changed anything (an unknown id, or
    /// one already read, is a no-op) so the caller only re-saves and
    /// refreshes the header count when something genuinely did.
    pub fn mark_read(&mut self, mail_id: &str) -> bool {
        match self.received.get_mut(mail_id) {
            Some(r) if !r.read => {
                r.read = true;
                true
            }
            _ => false,
        }
    }

    /// What the header's "<n> unread OTP Mails" counts.
    pub fn unread_received_count(&self) -> usize {
        self.received.values().filter(|r| !r.read).count()
    }

    /// Mailbox rows: every sent ref and received entry, newest first by
    /// timestamp (sent mails by sent time, received by received time) so
    /// the popup reads like any mailbox.
    pub fn sent_refs(&self) -> Vec<SentMailRef> {
        let mut v: Vec<SentMailRef> = self.sent.values().cloned().collect();
        v.sort_by(|a, b| b.sent_at_utc.cmp(&a.sent_at_utc).then(a.mail_id.cmp(&b.mail_id)));
        v
    }

    pub fn received_refs(&self) -> Vec<ReceivedMailRef> {
        let mut v: Vec<ReceivedMailRef> = self.received.values().cloned().collect();
        v.sort_by(|a, b| {
            b.received_at_utc
                .cmp(&a.received_at_utc)
                .then(a.mail_id.cmp(&b.mail_id))
        });
        v
    }
}

use crate::secure_fs::{restrict_file_permissions, secure_remove_file as secure_remove};
