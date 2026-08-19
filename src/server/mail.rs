//! Disk-backed storage for OTP mail awaiting delivery (docs/PROTOCOL.md
//! §17) - the one piece of state this server keeps on disk, and the one
//! deliberate exception to "content never touches the server". Even here
//! the exception is narrow: what's stored is an opaque one-time-pad
//! ciphertext the server holds no key material for, plus the minimum
//! routing metadata (from/to nickname, sequence, timestamp) needed to hand
//! it to the right client in the right order.
//!
//! Two directories under one root:
//!
//! - `pending/<mail_id>` - mails whose recipient hasn't acknowledged them
//!   yet. Deleted the moment `OtpMailAck` arrives.
//! - `delivered/<mail_id>` - delivery receipts for the *sender*: proof the
//!   recipient genuinely decrypted the mail, kept only until the sender
//!   sees it (`OtpMailDeliveredAck`) so a sender who was offline at
//!   delivery time still learns of it on a later connect.
//!
//! Every operation validates the mail id (`crypto::otp::mail_id_is_valid`)
//! before building any path from it - an id is client-supplied and becomes
//! a filename, so anything but exact lowercase hex is refused outright.
//! All I/O is synchronous `std::fs` on small files, the same style every
//! client-side flat-file store already uses.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{Outgoing, Registry};
use crate::crypto::otp::{OTP_MAIL_MAX_CIPHERTEXT_BYTES, mail_id_is_valid};
use crate::proto::{self, ServerMessage, UserId};
use crate::validation::is_storable;

/// One stored mail, exactly as received in `ClientMessage::OtpMailSend`
/// plus the server-assigned `from` (the sender's registered nickname - the
/// server never trusts a client-claimed sender name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMail {
    pub mail_id: String,
    pub from: String,
    pub to: String,
    pub contact_name: String,
    pub seq: u64,
    pub sent_at_utc: u64,
    pub ciphertext: Vec<u8>,
}

/// One delivery receipt: `mail_id`'s mail was acknowledged by its
/// recipient. `from` is who to notify; `to` is kept so the receipt still
/// reads meaningfully if a server operator inspects the directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveredReceipt {
    pub mail_id: String,
    pub from: String,
    pub to: String,
}

/// `~/.aloo/server_otp_mail` (`crate::platform::aloo_dir`) - the default
/// root a production server stores mail under; tests pass a temp dir.
pub fn default_mail_dir() -> PathBuf {
    crate::platform::aloo_dir().join("server_otp_mail")
}

pub struct MailStore {
    dir: PathBuf,
}

impl MailStore {
    /// Opens (creating if needed) the store rooted at `dir`.
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(dir.join("pending"))?;
        std::fs::create_dir_all(dir.join("delivered"))?;
        Ok(Self { dir })
    }

    fn pending_path(&self, mail_id: &str) -> PathBuf {
        self.dir.join("pending").join(mail_id)
    }

    fn delivered_path(&self, mail_id: &str) -> PathBuf {
        self.dir.join("delivered").join(mail_id)
    }

    /// Stores `mail` under `pending/`, validating everything
    /// client-supplied first. Idempotent for a retried id: the sender only
    /// ever retries with the exact recovered ciphertext, so overwriting is
    /// a byte-identical no-op, and the retry gets its acknowledgement
    /// instead of an error. Returns `Err` with a human-readable reason on
    /// any validation or disk failure.
    pub fn store(&self, mail: &StoredMail) -> Result<(), String> {
        if !mail_id_is_valid(&mail.mail_id) {
            return Err("malformed mail id".to_string());
        }
        if mail.to.is_empty() || !is_storable(&mail.to) || !is_storable(&mail.from) {
            return Err("malformed nickname".to_string());
        }
        if !is_storable(&mail.contact_name) {
            return Err("malformed contact name".to_string());
        }
        if mail.ciphertext.is_empty() {
            return Err("empty mail".to_string());
        }
        if mail.ciphertext.len() > OTP_MAIL_MAX_CIPHERTEXT_BYTES {
            return Err(format!(
                "mail exceeds the {}MB limit",
                OTP_MAIL_MAX_CIPHERTEXT_BYTES / (1024 * 1024)
            ));
        }
        let bytes = proto::encode(mail).map_err(|e| e.to_string())?;
        std::fs::write(self.pending_path(&mail.mail_id), bytes).map_err(|e| e.to_string())
    }

    /// Whether `mail_id` already has a delivery receipt - the retry-after-
    /// delivery race: a sender whose `OtpMailResult` was lost may retry an
    /// id whose mail has meanwhile been delivered and deleted; the answer
    /// it needs then is `OtpMailDelivered`, not a second store.
    pub fn is_delivered(&self, mail_id: &str) -> bool {
        mail_id_is_valid(mail_id) && self.delivered_path(mail_id).exists()
    }

    /// Every pending mail addressed to `to`, in ascending (`from`, `seq`)
    /// order - the pad each mail was sealed with is strictly sequential per
    /// sender, so the receiver can only ever decrypt one sender's mails in
    /// `seq` order (docs/PROTOCOL.md §17.3). A file that fails to decode is
    /// skipped rather than failing the whole fetch, same tolerance every
    /// flat-file store in this codebase gives corrupt entries.
    pub fn pending_for(&self, to: &str) -> Vec<StoredMail> {
        let mut mails: Vec<StoredMail> = self
            .read_dir_decoded::<StoredMail>(&self.dir.join("pending"))
            .into_iter()
            .filter(|m| m.to == to)
            .collect();
        mails.sort_by(|a, b| (&a.from, a.seq).cmp(&(&b.from, b.seq)));
        mails
    }

    /// Every delivery receipt for mail sent by `from` - what an
    /// `OtpMailFetch` re-notifies until the sender acknowledges each.
    pub fn receipts_from(&self, from: &str) -> Vec<DeliveredReceipt> {
        let mut receipts: Vec<DeliveredReceipt> = self
            .read_dir_decoded::<DeliveredReceipt>(&self.dir.join("delivered"))
            .into_iter()
            .filter(|r| r.from == from)
            .collect();
        receipts.sort_by(|a, b| a.mail_id.cmp(&b.mail_id));
        receipts
    }

    fn read_dir_decoded<T: for<'de> Deserialize<'de>>(&self, dir: &Path) -> Vec<T> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let bytes = std::fs::read(entry.path()).ok()?;
                proto::decode::<T>(&bytes).ok()
            })
            .collect()
    }

    /// Applies a recipient's `OtpMailAck`: if `mail_id` is pending *and*
    /// addressed to `claimant` (the acking connection's registered
    /// nickname - anyone else's ack is refused), deletes the stored
    /// ciphertext and writes the delivery receipt in its place. Returns the
    /// sender's nickname so the caller can notify them immediately if
    /// they're connected. `None` for an unknown id, a mismatched claimant,
    /// or an id already acknowledged (idempotent - the receipt survives).
    pub fn mark_delivered(&self, mail_id: &str, claimant: &str) -> Option<String> {
        if !mail_id_is_valid(mail_id) {
            return None;
        }
        let bytes = std::fs::read(self.pending_path(mail_id)).ok()?;
        let mail = proto::decode::<StoredMail>(&bytes).ok()?;
        if mail.to != claimant {
            return None;
        }
        let receipt = DeliveredReceipt {
            mail_id: mail.mail_id.clone(),
            from: mail.from.clone(),
            to: mail.to.clone(),
        };
        let encoded = proto::encode(&receipt).ok()?;
        // Receipt first, then delete: a crash between the two leaves both
        // files, which re-acks harmlessly (the recipient's own store
        // deduplicates by id) - the reverse order could lose the receipt
        // and leave the sender never learning of the delivery.
        std::fs::write(self.delivered_path(mail_id), encoded).ok()?;
        let _ = std::fs::remove_file(self.pending_path(mail_id));
        Some(mail.from)
    }

    /// Applies a sender's `OtpMailDeliveredAck`: forgets the receipt if it
    /// exists and genuinely belongs to `claimant`. Returns whether anything
    /// was removed.
    pub fn forget_receipt(&self, mail_id: &str, claimant: &str) -> bool {
        if !mail_id_is_valid(mail_id) {
            return false;
        }
        let Ok(bytes) = std::fs::read(self.delivered_path(mail_id)) else {
            return false;
        };
        let Ok(receipt) = proto::decode::<DeliveredReceipt>(&bytes) else {
            return false;
        };
        if receipt.from != claimant {
            return false;
        }
        std::fs::remove_file(self.delivered_path(mail_id)).is_ok()
    }
}

// ---------------------------------------------------------------------
// Routing: what each mail-related ClientMessage produces. Pure functions
// of (registry, store, message) -> outgoing messages, mirroring how
// Registry's own mutations return Vec<Outgoing> - client_loop just calls
// these under its existing lock, and tests exercise them with no socket.
// ---------------------------------------------------------------------

fn deliver_message(to: UserId, m: StoredMail) -> Outgoing {
    Outgoing {
        to,
        message: ServerMessage::OtpMailDeliver {
            mail_id: m.mail_id,
            from: m.from,
            contact_name: m.contact_name,
            seq: m.seq,
            sent_at_utc: m.sent_at_utc,
            ciphertext: m.ciphertext,
        },
    }
}

/// Applies one `ClientMessage::OtpMailSend` from `sender` (docs/PROTOCOL.md
/// §17.2): stores the mail under the sender's *registered* nickname and
/// acknowledges it - or, for an id whose mail was already delivered (the
/// sender is retrying because the earlier acknowledgement was lost),
/// answers with the delivery receipt instead of storing anything. If the
/// recipient happens to be connected right now, the mail is additionally
/// pushed to them immediately rather than waiting for their next fetch.
#[allow(clippy::too_many_arguments)]
pub fn on_mail_send(
    reg: &Registry,
    store: &MailStore,
    sender: UserId,
    mail_id: String,
    to: String,
    contact_name: String,
    seq: u64,
    sent_at_utc: u64,
    ciphertext: Vec<u8>,
) -> Vec<Outgoing> {
    let Some(sender_info) = reg.user_info(sender) else {
        return Vec::new();
    };
    if store.is_delivered(&mail_id) {
        return vec![Outgoing {
            to: sender,
            message: ServerMessage::OtpMailDelivered { mail_id },
        }];
    }
    let mail = StoredMail {
        mail_id: mail_id.clone(),
        from: sender_info.name,
        to: to.clone(),
        contact_name,
        seq,
        sent_at_utc,
        ciphertext,
    };
    match store.store(&mail) {
        Ok(()) => {
            let mut out = vec![Outgoing {
                to: sender,
                message: ServerMessage::OtpMailResult {
                    mail_id,
                    ok: true,
                    reason: None,
                },
            }];
            if let Some(recipient_id) = reg.id_by_name(&to) {
                out.push(deliver_message(recipient_id, mail));
            }
            out
        }
        Err(reason) => vec![Outgoing {
            to: sender,
            message: ServerMessage::OtpMailResult {
                mail_id,
                ok: false,
                reason: Some(reason),
            },
        }],
    }
}

/// Applies one `ClientMessage::OtpMailFetch` (docs/PROTOCOL.md §17.3): both
/// halves of what a freshly-connected client is owed - every pending mail
/// addressed to its nickname (in per-sender `seq` order), and every
/// delivery receipt for mail it sent that it hasn't acknowledged seeing.
pub fn on_mail_fetch(reg: &Registry, store: &MailStore, requester: UserId) -> Vec<Outgoing> {
    let Some(info) = reg.user_info(requester) else {
        return Vec::new();
    };
    let mut out: Vec<Outgoing> = store
        .pending_for(&info.name)
        .into_iter()
        .map(|m| deliver_message(requester, m))
        .collect();
    out.extend(store.receipts_from(&info.name).into_iter().map(|r| Outgoing {
        to: requester,
        message: ServerMessage::OtpMailDelivered { mail_id: r.mail_id },
    }));
    out
}

/// Applies one `ClientMessage::OtpMailAck` from a recipient: deletes the
/// stored ciphertext, records the delivery receipt, and - if the original
/// sender is connected right now - notifies them immediately instead of
/// waiting for their next fetch.
pub fn on_mail_ack(
    reg: &Registry,
    store: &MailStore,
    requester: UserId,
    mail_id: String,
) -> Vec<Outgoing> {
    let Some(info) = reg.user_info(requester) else {
        return Vec::new();
    };
    let Some(from) = store.mark_delivered(&mail_id, &info.name) else {
        return Vec::new();
    };
    match reg.id_by_name(&from) {
        Some(sender_id) => vec![Outgoing {
            to: sender_id,
            message: ServerMessage::OtpMailDelivered { mail_id },
        }],
        None => Vec::new(),
    }
}

/// Applies one `ClientMessage::OtpMailDeliveredAck` from a sender: the
/// receipt did its job and is forgotten. Nothing to send back.
pub fn on_mail_delivered_ack(
    reg: &Registry,
    store: &MailStore,
    requester: UserId,
    mail_id: String,
) -> Vec<Outgoing> {
    if let Some(info) = reg.user_info(requester) {
        store.forget_receipt(&mail_id, &info.name);
    }
    Vec::new()
}
