//! The client's OTP mail store (docs/PROTOCOL.md §17): sent references,
//! the received-mail (ciphertext, pad) blob pair, and the index file's
//! round-trip - the `otp_store_test.rs` conventions applied to
//! `client::otp_mail_store`.

use std::path::PathBuf;

use aloo::client::otp_mail_store::{OtpMailStore, ReceivedMailRef, SentMailRef, SentMailStatus};
use aloo::crypto::otp::repad;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aloo-mailstore-{tag}-{}-{nanos}", std::process::id()))
}

/// Deletes its directory when the test ends; the store itself is built
/// per test from `dir` (a `Drop` type can't have fields moved out).
struct TempStore {
    dir: PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        Self { dir: temp_dir(tag) }
    }

    fn store(&self) -> OtpMailStore {
        OtpMailStore::new_empty(self.dir.clone())
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sent(id_byte: u8, status: SentMailStatus) -> SentMailRef {
    SentMailRef {
        mail_id: format!("{:02x}", id_byte).repeat(16),
        to: "bob".to_string(),
        contact_name: "abc-def".to_string(),
        seq: id_byte as u64,
        sent_at_utc: 5_000 + id_byte as u64,
        status,
    }
}

fn received(id_byte: u8) -> ReceivedMailRef {
    ReceivedMailRef {
        mail_id: format!("{:02x}", id_byte).repeat(16),
        from: "alice".to_string(),
        sent_at_utc: 4_000,
        received_at_utc: 6_000 + id_byte as u64,
        size: 3,
        read: false,
    }
}

/// @requirement AC-159
#[test]
fn sent_refs_round_trip_through_save_and_load() {
    let t = TempStore::new("sentroundtrip");
    let mut store = t.store();
    let r1 = sent(0x01, SentMailStatus::AwaitingServerAck);
    let r2 = sent(0x02, SentMailStatus::Delivered);
    store = {
        store.record_sent(r1.clone());
        store.record_sent(r2.clone());
        store.save().expect("save");
        OtpMailStore::load(t.dir.clone()).expect("load")
    };
    assert_eq!(store.sent_ref(&r1.mail_id), Some(&r1));
    assert_eq!(store.sent_ref(&r2.mail_id), Some(&r2));
}

/// @requirement AC-161
#[test]
fn set_sent_status_never_regresses_delivered() {
    let t = TempStore::new("noregress");
    let mut store = t.store();
    let r = sent(0x03, SentMailStatus::AwaitingServerAck);
    store.record_sent(r.clone());
    assert!(store.set_sent_status(&r.mail_id, SentMailStatus::StoredOnServer));
    assert!(store.set_sent_status(&r.mail_id, SentMailStatus::Delivered));
    // A late/duplicate storage acknowledgement after delivery must not
    // walk the status backwards.
    assert!(!store.set_sent_status(&r.mail_id, SentMailStatus::StoredOnServer));
    assert_eq!(
        store.sent_ref(&r.mail_id).unwrap().status,
        SentMailStatus::Delivered
    );
}

/// @requirement AC-159
#[test]
fn awaiting_server_ack_lists_only_unacknowledged() {
    let t = TempStore::new("awaiting");
    let mut store = t.store();
    let waiting = sent(0x04, SentMailStatus::AwaitingServerAck);
    store.record_sent(waiting.clone());
    store.record_sent(sent(0x05, SentMailStatus::StoredOnServer));
    store.record_sent(sent(0x06, SentMailStatus::Delivered));
    store.record_sent(sent(0x07, SentMailStatus::Failed));
    assert_eq!(store.awaiting_server_ack(), vec![waiting]);
}

/// @requirement AC-163
#[test]
fn received_payload_stores_ciphertext_and_pad_and_reads_back_by_xor() {
    let t = TempStore::new("blobs");
    let mut store = t.store();
    let payload = b"the mail's decoded payload bytes".to_vec();
    let (ct, pad) = repad(&payload);
    let r = received(0x11);
    store
        .store_received_payload(r.clone(), &ct, &pad)
        .expect("store blobs");
    store.save().expect("save index");

    // Exactly two blob files exist, named by the id.
    assert!(t.dir.join(format!("{}.ct", r.mail_id)).is_file());
    assert!(t.dir.join(format!("{}.pad", r.mail_id)).is_file());

    // A reloaded store (a restarted client) reads the payload back by
    // XORing the pair in memory.
    let reloaded = OtpMailStore::load(t.dir.clone()).expect("load");
    assert_eq!(reloaded.received_ref(&r.mail_id), Some(&r));
    assert_eq!(reloaded.read_received_payload(&r.mail_id), Some(payload));
}

/// @requirement AC-163
#[test]
fn stored_blob_files_are_never_the_plaintext() {
    let t = TempStore::new("notplain");
    let mut store = t.store();
    let payload = b"never at rest in the clear".to_vec();
    let (ct, pad) = repad(&payload);
    let r = received(0x12);
    store.store_received_payload(r.clone(), &ct, &pad).unwrap();
    let on_disk_ct = std::fs::read(t.dir.join(format!("{}.ct", r.mail_id))).unwrap();
    let on_disk_pad = std::fs::read(t.dir.join(format!("{}.pad", r.mail_id))).unwrap();
    assert_ne!(on_disk_ct, payload, "the ciphertext half is not the payload");
    assert_ne!(on_disk_pad, payload, "the pad half is not the payload");
}

/// @requirement AC-163
#[test]
fn remove_received_destroys_both_files() {
    let t = TempStore::new("remove");
    let mut store = t.store();
    let (ct, pad) = repad(b"short-lived");
    let r = received(0x13);
    store.store_received_payload(r.clone(), &ct, &pad).unwrap();
    assert!(store.remove_received(&r.mail_id));
    assert!(!t.dir.join(format!("{}.ct", r.mail_id)).exists());
    assert!(!t.dir.join(format!("{}.pad", r.mail_id)).exists());
    assert_eq!(store.read_received_payload(&r.mail_id), None);
    assert!(!store.remove_received(&r.mail_id), "already gone");
}

/// @requirement AC-159
#[test]
fn loading_a_missing_directory_starts_empty_not_an_error() {
    let dir = temp_dir("missing");
    let store = OtpMailStore::load(dir).expect("missing dir is a fresh start");
    assert!(store.sent_refs().is_empty());
    assert!(store.received_refs().is_empty());
}

/// @requirement AC-162
#[test]
fn refs_list_newest_first() {
    let t = TempStore::new("order");
    let mut store = t.store();
    store.record_sent(sent(0x01, SentMailStatus::Delivered)); // sent_at 5001
    store.record_sent(sent(0x09, SentMailStatus::Delivered)); // sent_at 5009
    let sent_ids: Vec<u64> = store.sent_refs().iter().map(|r| r.sent_at_utc).collect();
    assert_eq!(sent_ids, vec![5009, 5001]);
}

// ---------------------------------------------------------------------
// Unread tracking (header's "<n> unread OTP Mails")
// ---------------------------------------------------------------------

/// @requirement AC-292
#[test]
fn a_freshly_stored_mail_is_unread() {
    let t = TempStore::new("fresh-unread");
    let mut store = t.store();
    let (ct, pad) = repad(b"hi");
    store.store_received_payload(received(0x01), &ct, &pad).unwrap();
    assert_eq!(store.unread_received_count(), 1);
}

/// @requirement AC-292
#[test]
fn mark_read_flips_the_flag_and_is_idempotent() {
    let t = TempStore::new("mark-read");
    let mut store = t.store();
    let (ct, pad) = repad(b"hi");
    let r = received(0x02);
    store.store_received_payload(r.clone(), &ct, &pad).unwrap();

    assert!(store.mark_read(&r.mail_id), "the first read genuinely changes it");
    assert_eq!(store.unread_received_count(), 0);
    assert!(!store.mark_read(&r.mail_id), "reading an already-read mail changes nothing");
    assert!(
        !store.mark_read("no-such-id"),
        "an unknown id is a no-op, not a panic"
    );
}

/// @requirement AC-292
#[test]
fn unread_received_count_counts_only_the_ones_still_unread() {
    let t = TempStore::new("mixed-unread");
    let mut store = t.store();
    let (ct, pad) = repad(b"hi");
    let a = received(0x03);
    let b = received(0x04);
    store.store_received_payload(a.clone(), &ct, &pad).unwrap();
    store.store_received_payload(b, &ct, &pad).unwrap();
    assert_eq!(store.unread_received_count(), 2);

    store.mark_read(&a.mail_id);
    assert_eq!(store.unread_received_count(), 1);
}

/// @requirement AC-292
#[test]
fn the_read_flag_round_trips_through_save_and_load() {
    let t = TempStore::new("read-roundtrip");
    let mut store = t.store();
    let (ct, pad) = repad(b"hi");
    let r = received(0x05);
    store.store_received_payload(r.clone(), &ct, &pad).unwrap();
    store.mark_read(&r.mail_id);
    store.save().unwrap();

    let reloaded = OtpMailStore::load(t.dir.clone()).unwrap();
    assert_eq!(reloaded.unread_received_count(), 0);
    assert!(reloaded.received_ref(&r.mail_id).unwrap().read);
}

/// A line written before `read` existed loads as already read - the safe,
/// quiet default, so upgrading never surfaces a stampede of "new" mail
/// that predates the concept.
///
/// @requirement AC-292
#[test]
fn a_line_written_before_read_existed_loads_as_read() {
    let t = TempStore::new("legacy-line");
    std::fs::create_dir_all(&t.dir).unwrap();
    std::fs::write(
        t.dir.join("index"),
        "R\tid0000\talice\t100\t200\t3\n", // five fields, no trailing `read`
    )
    .unwrap();
    let store = OtpMailStore::load(t.dir.clone()).unwrap();
    assert_eq!(store.unread_received_count(), 0);
    assert!(store.received_ref("id0000").unwrap().read);
}

/// The index is replaced by rename, never truncated in place - the same
/// guarantee `otp_store` gives, for the same reason: a mail already
/// acknowledged to the server but lost from a half-written index is gone
/// for good.
///
/// @requirement TB-285
#[cfg(unix)]
#[test]
fn the_index_is_replaced_by_rename_never_truncated_in_place() {
    use std::os::unix::fs::MetadataExt;
    let temp = TempStore::new("atomic-index");
    let mut store = temp.store();
    store.record_sent(sent(1, SentMailStatus::AwaitingServerAck));
    store.save().unwrap();
    let index = temp.dir.join("index");
    let before = std::fs::metadata(&index).unwrap().ino();

    store.record_sent(sent(2, SentMailStatus::StoredOnServer));
    store.save().unwrap();

    assert_ne!(
        before,
        std::fs::metadata(&index).unwrap().ino(),
        "each save is a fresh file renamed over the index"
    );
    assert!(!temp.dir.join("index.new").exists());
    assert_eq!(OtpMailStore::load(temp.dir.clone()).unwrap().sent_refs().len(), 2);
}
