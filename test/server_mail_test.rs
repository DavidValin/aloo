//! The server side of OTP mail (docs/PROTOCOL.md §17): `MailStore`'s disk
//! lifecycle and the routing functions `client_loop` calls - all pure of
//! sockets, exactly like the `Registry` tests in `server_test.rs`.

use std::path::PathBuf;

use aloo::crypto::otp::OTP_MAIL_MAX_CIPHERTEXT_BYTES;
use aloo::proto::{KeyMode, ServerMessage};
use aloo::server::mail::{self, MailStore, StoredMail};
use aloo::server::Registry;

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aloo-mail-{tag}-{}-{nanos}", std::process::id()))
}

/// A store rooted in a fresh temp dir, removed when the guard drops.
struct TempStore {
    dir: PathBuf,
    store: MailStore,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let dir = temp_dir(tag);
        let store = MailStore::open(dir.clone()).expect("open mail store");
        Self { dir, store }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn mail(id_byte: u8, from: &str, to: &str, seq: u64) -> StoredMail {
    StoredMail {
        mail_id: format!("{:02x}", id_byte).repeat(16),
        from: from.to_string(),
        to: to.to_string(),
        contact_name: "abc-def".to_string(),
        seq,
        sent_at_utc: 1_000 + seq,
        ciphertext: vec![id_byte; 64],
    }
}

// ---------------------------------------------------------------------
// MailStore lifecycle
// ---------------------------------------------------------------------

/// @requirement AC-160
#[test]
fn store_and_pending_for_round_trip_on_disk() {
    let t = TempStore::new("roundtrip");
    let m = mail(0xaa, "alice", "bob", 0);
    t.store.store(&m).expect("store");
    // On disk, not just in memory: a second store handle over the same
    // directory (a restarted server) sees it.
    let reopened = MailStore::open(t.dir.clone()).expect("reopen");
    assert_eq!(reopened.pending_for("bob"), vec![m]);
    assert!(reopened.pending_for("alice").is_empty());
}

/// @requirement TB-196
#[test]
fn store_rejects_a_malformed_mail_id_before_touching_disk() {
    let t = TempStore::new("badid");
    for bad in [
        "",
        "short",
        "../../../../etc/passwd0000000000",             // path traversal shape
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",             // uppercase
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",             // non-hex
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",           // too long
    ] {
        let mut m = mail(0x01, "alice", "bob", 0);
        m.mail_id = bad.to_string();
        assert!(t.store.store(&m).is_err(), "{bad:?} must be refused");
    }
    // Nothing crept into either directory.
    assert!(t.store.pending_for("bob").is_empty());
}

/// @requirement TB-196
#[test]
fn store_rejects_oversized_ciphertext() {
    let t = TempStore::new("oversize");
    let mut m = mail(0x02, "alice", "bob", 0);
    m.ciphertext = vec![0u8; OTP_MAIL_MAX_CIPHERTEXT_BYTES + 1];
    assert!(t.store.store(&m).is_err());
    // Empty is refused too - nothing legitimate encrypts to zero bytes.
    m.ciphertext = Vec::new();
    assert!(t.store.store(&m).is_err());
}

/// @requirement TB-197
#[test]
fn store_is_idempotent_for_a_retried_id() {
    let t = TempStore::new("idempotent");
    let m = mail(0x03, "alice", "bob", 0);
    t.store.store(&m).expect("first store");
    t.store.store(&m).expect("retry stores again without error");
    assert_eq!(t.store.pending_for("bob").len(), 1, "never duplicated");
}

/// @requirement AC-160
#[test]
fn pending_for_orders_one_senders_mails_by_seq() {
    let t = TempStore::new("order");
    // Stored deliberately out of order - the pad is sequential, so
    // delivery order must be seq order regardless of arrival order.
    for (byte, seq) in [(0x11u8, 2u64), (0x12, 0), (0x13, 1)] {
        t.store.store(&mail(byte, "alice", "bob", seq)).unwrap();
    }
    let seqs: Vec<u64> = t.store.pending_for("bob").iter().map(|m| m.seq).collect();
    assert_eq!(seqs, vec![0, 1, 2]);
}

/// @requirement AC-160
#[test]
fn mark_delivered_deletes_the_pending_file_and_records_a_receipt() {
    let t = TempStore::new("deliver");
    let m = mail(0x04, "alice", "bob", 0);
    t.store.store(&m).unwrap();
    assert_eq!(t.store.mark_delivered(&m.mail_id, "bob").as_deref(), Some("alice"));
    assert!(t.store.pending_for("bob").is_empty(), "ciphertext deleted from disk");
    assert!(t.store.is_delivered(&m.mail_id));
    let receipts = t.store.receipts_from("alice");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].mail_id, m.mail_id);
    // Idempotent: a second ack finds nothing pending and changes nothing.
    assert_eq!(t.store.mark_delivered(&m.mail_id, "bob"), None);
    assert!(t.store.is_delivered(&m.mail_id));
}

/// @requirement TB-197
#[test]
fn mark_delivered_refuses_a_claimant_other_than_the_recipient() {
    let t = TempStore::new("claimant");
    let m = mail(0x05, "alice", "bob", 0);
    t.store.store(&m).unwrap();
    assert_eq!(t.store.mark_delivered(&m.mail_id, "mallory"), None);
    assert_eq!(t.store.pending_for("bob").len(), 1, "still stored");
    assert!(!t.store.is_delivered(&m.mail_id));
}

/// @requirement TB-197, AC-161
#[test]
fn forget_receipt_only_for_the_original_sender() {
    let t = TempStore::new("receipt");
    let m = mail(0x06, "alice", "bob", 0);
    t.store.store(&m).unwrap();
    t.store.mark_delivered(&m.mail_id, "bob").unwrap();
    assert!(!t.store.forget_receipt(&m.mail_id, "mallory"));
    assert!(t.store.is_delivered(&m.mail_id), "a stranger cannot erase it");
    assert!(t.store.forget_receipt(&m.mail_id, "alice"));
    assert!(!t.store.is_delivered(&m.mail_id));
    assert!(!t.store.forget_receipt(&m.mail_id, "alice"), "already gone");
}

// ---------------------------------------------------------------------
// Routing: what each mail message produces (no sockets)
// ---------------------------------------------------------------------

/// @requirement AC-160
#[test]
fn on_mail_send_stores_and_acknowledges() {
    let t = TempStore::new("send");
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let m = mail(0x07, "alice", "bob", 0);
    let out = mail::on_mail_send(
        &reg,
        &t.store,
        alice,
        m.mail_id.clone(),
        m.to.clone(),
        m.contact_name.clone(),
        m.seq,
        m.sent_at_utc,
        m.ciphertext.clone(),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, alice);
    assert!(
        matches!(
            &out[0].message,
            ServerMessage::OtpMailResult { mail_id, ok: true, .. } if *mail_id == m.mail_id
        ),
        "got {:?}",
        out[0].message
    );
    assert_eq!(t.store.pending_for("bob"), vec![m]);
}

/// @requirement TB-196
#[test]
fn on_mail_send_records_the_registered_sender_nickname() {
    let t = TempStore::new("fromname");
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let m = mail(0x08, "IGNORED-CLAIM", "bob", 0);
    mail::on_mail_send(
        &reg,
        &t.store,
        alice,
        m.mail_id.clone(),
        m.to.clone(),
        m.contact_name.clone(),
        m.seq,
        m.sent_at_utc,
        m.ciphertext.clone(),
    );
    // `from` on the stored mail is the server's own record of who this
    // connection identified as - the routing arm never even receives a
    // client-claimed sender name to be misled by.
    assert_eq!(t.store.pending_for("bob")[0].from, "alice");
}

/// @requirement AC-160
#[test]
fn on_mail_send_pushes_immediately_to_a_connected_recipient() {
    let t = TempStore::new("push");
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![2], KeyMode::PqHybrid);
    let m = mail(0x09, "alice", "bob", 0);
    let out = mail::on_mail_send(
        &reg,
        &t.store,
        alice,
        m.mail_id.clone(),
        m.to.clone(),
        m.contact_name.clone(),
        m.seq,
        m.sent_at_utc,
        m.ciphertext.clone(),
    );
    assert_eq!(out.len(), 2, "result to the sender plus a live delivery");
    assert_eq!(out[1].to, bob);
    assert!(
        matches!(
            &out[1].message,
            ServerMessage::OtpMailDeliver { mail_id, from, seq: 0, .. }
                if *mail_id == m.mail_id && from == "alice"
        ),
        "got {:?}",
        out[1].message
    );
    // Still stored: only the recipient's own OtpMailAck deletes it.
    assert_eq!(t.store.pending_for("bob").len(), 1);
}

/// @requirement TB-197, AC-161
#[test]
fn on_mail_send_answers_a_retry_after_delivery_with_delivered() {
    let t = TempStore::new("retryrace");
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let m = mail(0x0a, "alice", "bob", 0);
    t.store.store(&m).unwrap();
    t.store.mark_delivered(&m.mail_id, "bob").unwrap();
    // The sender's OtpMailResult was lost; it retries the same id after
    // the mail was already delivered and deleted.
    let out = mail::on_mail_send(
        &reg,
        &t.store,
        alice,
        m.mail_id.clone(),
        m.to.clone(),
        m.contact_name.clone(),
        m.seq,
        m.sent_at_utc,
        m.ciphertext.clone(),
    );
    assert_eq!(out.len(), 1);
    assert!(
        matches!(
            &out[0].message,
            ServerMessage::OtpMailDelivered { mail_id } if *mail_id == m.mail_id
        ),
        "a retried already-delivered id is answered with the receipt, got {:?}",
        out[0].message
    );
    assert!(t.store.pending_for("bob").is_empty(), "never re-stored");
}

/// @requirement AC-160, AC-161
#[test]
fn on_mail_fetch_delivers_pending_and_receipts() {
    let t = TempStore::new("fetch");
    let mut reg = Registry::new();
    let bob = reg.register("bob".into(), vec![2], KeyMode::PqHybrid);
    // One mail waiting *for* bob, one receipt for a mail bob *sent*.
    t.store.store(&mail(0x0b, "alice", "bob", 0)).unwrap();
    let sent_by_bob = mail(0x0c, "bob", "carol", 0);
    t.store.store(&sent_by_bob).unwrap();
    t.store.mark_delivered(&sent_by_bob.mail_id, "carol").unwrap();

    let out = mail::on_mail_fetch(&reg, &t.store, bob);
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|o| o.to == bob));
    assert!(matches!(&out[0].message, ServerMessage::OtpMailDeliver { from, .. } if from == "alice"));
    assert!(
        matches!(&out[1].message, ServerMessage::OtpMailDelivered { mail_id } if *mail_id == sent_by_bob.mail_id)
    );
}

/// The server has no way to tell which of a nickname's devices a mail was
/// actually sealed for (`contact_name` is opaque to it) - so it must keep
/// offering the same still-pending mail on every fetch, whichever device
/// happens to be connected, until a genuine `OtpMailAck` arrives. A wrong
/// device that received but could not decrypt/ack it must see the mail
/// handed straight back out again, not silently dropped or marked-tried.
/// @requirement AC-335
#[test]
fn on_mail_fetch_redelivers_the_same_pending_mail_until_acked() {
    let t = TempStore::new("redeliver");
    let mut reg = Registry::new();
    let bob = reg.register("bob".into(), vec![2], KeyMode::PqHybrid);
    let m = mail(0x0f, "alice", "bob", 0);
    t.store.store(&m).unwrap();

    let first = mail::on_mail_fetch(&reg, &t.store, bob);
    assert!(
        matches!(&first[0].message, ServerMessage::OtpMailDeliver { mail_id, .. } if *mail_id == m.mail_id),
        "got {:?}",
        first
    );

    // No ack sent in between - simulating a device that received it but
    // could not decrypt/ack it (a mail sealed for a different device).
    let second = mail::on_mail_fetch(&reg, &t.store, bob);
    assert!(
        matches!(&second[0].message, ServerMessage::OtpMailDeliver { mail_id, .. } if *mail_id == m.mail_id),
        "the same still-pending mail must be handed out again, got {:?}",
        second
    );
}

/// The direct counterpart of the above: a mere delivery attempt, with no
/// ack, must never remove the mail from storage - only a genuine
/// `OtpMailAck` from the registered recipient nickname does
/// (`on_mail_ack_notifies_a_connected_sender`, below).
/// @requirement AC-335
#[test]
fn a_delivery_attempt_alone_never_removes_a_pending_mail() {
    let t = TempStore::new("attempt-not-consume");
    let mut reg = Registry::new();
    let bob = reg.register("bob".into(), vec![2], KeyMode::PqHybrid);
    let m = mail(0x10, "alice", "bob", 0);
    t.store.store(&m).unwrap();

    let _ = mail::on_mail_fetch(&reg, &t.store, bob);

    assert_eq!(
        t.store.pending_for("bob"),
        vec![m],
        "a mere delivery attempt must not remove the mail from storage"
    );
}

/// @requirement AC-161
#[test]
fn on_mail_ack_notifies_a_connected_sender() {
    let t = TempStore::new("acknotify");
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![2], KeyMode::PqHybrid);
    let m = mail(0x0d, "alice", "bob", 0);
    t.store.store(&m).unwrap();
    let out = mail::on_mail_ack(&reg, &t.store, bob, m.mail_id.clone());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, alice);
    assert!(
        matches!(&out[0].message, ServerMessage::OtpMailDelivered { mail_id } if *mail_id == m.mail_id)
    );
    assert!(t.store.pending_for("bob").is_empty());
    // An ack from anyone but the stored recipient does nothing at all.
    let m2 = mail(0x0e, "alice", "bob", 1);
    t.store.store(&m2).unwrap();
    assert!(mail::on_mail_ack(&reg, &t.store, alice, m2.mail_id.clone()).is_empty());
    assert_eq!(t.store.pending_for("bob").len(), 1);
}

/// @requirement AC-161
#[test]
fn on_mail_delivered_ack_forgets_the_receipt() {
    let t = TempStore::new("deliveredack");
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let m = mail(0x0f, "alice", "bob", 0);
    t.store.store(&m).unwrap();
    t.store.mark_delivered(&m.mail_id, "bob").unwrap();
    let out = mail::on_mail_delivered_ack(&reg, &t.store, alice, m.mail_id.clone());
    assert!(out.is_empty(), "nothing to send back");
    assert!(!t.store.is_delivered(&m.mail_id), "receipt forgotten");
}
