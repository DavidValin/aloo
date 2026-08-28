//! The durable send queue (`client::outbox`, US-064): what it keeps, what
//! it refuses, the order it keeps it in, and that it survives the process
//! that wrote it.

use aloo::client::outbox::{Outbox, OutboxItem, is_queueable};
use aloo::p2p_proto::{P2pPayload, ReceiptStage};
use aloo::proto::{Content, Envelope};

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-outbox-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A sealed text payload. The bytes are opaque here on purpose: the queue
/// stores what was already encrypted for the recipient and never looks
/// inside it, which is exactly what keeps a queued message under whatever
/// layering it was sent with.
fn text(body: &[u8]) -> OutboxItem {
    OutboxItem::Reliable(P2pPayload::Envelope {
        channel: Some("general".into()),
        msg_id: Some(1),
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![body.to_vec()],
        },
    })
}

fn otp_text(seq: u64) -> OutboxItem {
    OutboxItem::Reliable(P2pPayload::OtpEnvelope {
        channel: None,
        msg_id: Some(seq),
        seq,
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![vec![7u8; 32]],
        },
        sender_device_id: "laptop".into(),
    })
}

// ---------------------------------------------------------------------
// What is kept, and what is not
// ---------------------------------------------------------------------

/// @requirement AC-408
#[test]
fn text_and_voice_are_queueable_and_files_are_not() {
    assert!(is_queueable(&text(b"hello")));
    assert!(is_queueable(&otp_text(1)));
    assert!(is_queueable(&OutboxItem::Reliable(P2pPayload::StreamStart {
        channel: None,
        stream_id: 1,
        msg_id: Some(1),
    })));
    assert!(is_queueable(&OutboxItem::Reliable(P2pPayload::StreamEnd {
        stream_id: 1,
        duration_ms: 500,
    })));
    assert!(is_queueable(&OutboxItem::VoiceChunk {
        stream_id: 1,
        seq: 0,
        blocks: vec![vec![1, 2, 3]],
    }));

    // A file transfer is a live, consent-gated conversation - replaying
    // half of one an hour later is not a delivery.
    assert!(!is_queueable(&OutboxItem::Reliable(P2pPayload::FileOffer {
        channel: None,
        stream_id: 1,
        msg_id: Some(1),
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![vec![0u8; 4]],
        },
    })));
    assert!(!is_queueable(&OutboxItem::Reliable(P2pPayload::FileChunk {
        stream_id: 1,
        seq: 0,
        blocks: vec![vec![0u8; 4]],
    })));
    assert!(!is_queueable(&OutboxItem::Reliable(P2pPayload::FileEnd {
        stream_id: 1
    })));
}

/// A statement about right now would be a lie an hour later, so none of
/// them are kept either.
/// @requirement AC-408
#[test]
fn a_receipt_is_never_queued() {
    assert!(!is_queueable(&OutboxItem::Reliable(
        P2pPayload::DeliveryReceipt {
            msg_id: 1,
            stage: ReceiptStage::Decrypted,
        }
    )));
}

// ---------------------------------------------------------------------
// Order, and surviving the process
// ---------------------------------------------------------------------

/// The order is the contract: a pad-wrapped message spends its sequence
/// position when it is queued, so the receiver's pad expects exactly this
/// order back.
/// @requirement AC-409
#[test]
fn entries_come_back_in_the_order_they_were_written() {
    let dir = scratch_dir("order");
    let mut outbox = Outbox::load(&dir);
    for seq in 1..=5 {
        outbox.queue("bob", otp_text(seq)).unwrap();
    }
    let taken = outbox.take("bob");
    let seqs: Vec<u64> = taken
        .iter()
        .map(|e| match &e.item {
            OutboxItem::Reliable(P2pPayload::OtpEnvelope { seq, .. }) => *seq,
            other => panic!("unexpected entry {other:?}"),
        })
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-409
#[test]
fn what_was_queued_is_still_there_after_a_restart() {
    let dir = scratch_dir("restart");
    {
        let mut outbox = Outbox::load(&dir);
        outbox.queue("bob", text(b"first")).unwrap();
        outbox.queue("bob", text(b"second")).unwrap();
        outbox.queue("carol", text(b"hers")).unwrap();
    }

    // A brand-new process reading the same directory.
    let mut reopened = Outbox::load(&dir);
    assert_eq!(reopened.len_for("bob"), 2);
    assert_eq!(reopened.len_for("carol"), 1);
    assert_eq!(reopened.peers(), vec!["bob".to_string(), "carol".to_string()]);
    assert_eq!(reopened.total(), 3);

    let taken = reopened.take("bob");
    assert_eq!(taken.len(), 2);
    assert_eq!(taken[0].item, text(b"first"), "still in order, still byte-identical");
    assert_eq!(taken[1].item, text(b"second"));
    std::fs::remove_dir_all(&dir).ok();
}

/// Taking is a take, not a peek: the caller now owns delivering it, and a
/// copy left behind would be sent twice.
/// @requirement AC-409
#[test]
fn taking_a_peers_queue_empties_it_on_disk_too() {
    let dir = scratch_dir("take");
    let mut outbox = Outbox::load(&dir);
    outbox.queue("bob", text(b"one")).unwrap();
    assert_eq!(outbox.take("bob").len(), 1);
    assert_eq!(outbox.len_for("bob"), 0);
    assert!(Outbox::load(&dir).peers().is_empty(), "and nothing is left on disk");
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-409
#[test]
fn taking_an_empty_queue_is_not_an_error() {
    let dir = scratch_dir("empty");
    let mut outbox = Outbox::load(&dir);
    assert!(outbox.take("nobody").is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// Nothing ages out, and nothing is evicted to make room: while the key
/// is still here the message can still be delivered, and how long it has
/// waited says nothing about whether it should be.
/// @requirement AC-409
#[test]
fn nothing_is_dropped_for_age_or_for_room() {
    let dir = scratch_dir("no-expiry");
    let mut outbox = Outbox::load(&dir);
    for seq in 1..=5_000 {
        outbox.queue("bob", otp_text(seq)).unwrap();
    }
    assert_eq!(outbox.len_for("bob"), 5_000, "every one of them is still queued");

    // Reading it back from disk keeps every one of them too.
    assert_eq!(Outbox::load(&dir).len_for("bob"), 5_000);

    let taken = outbox.take("bob");
    let first = match &taken[0].item {
        OutboxItem::Reliable(P2pPayload::OtpEnvelope { seq, .. }) => *seq,
        other => panic!("unexpected entry {other:?}"),
    };
    assert_eq!(first, 1, "including the very oldest");
    std::fs::remove_dir_all(&dir).ok();
}

/// A message written now goes on the *end*, behind everything already
/// waiting - which is what keeps a pad-wrapped run in the sequence its
/// receiver's pad expects.
/// @requirement AC-409
#[test]
fn a_new_message_joins_the_back_of_an_existing_queue() {
    let dir = scratch_dir("append");
    let mut outbox = Outbox::load(&dir);
    outbox.queue("bob", otp_text(1)).unwrap();
    outbox.queue("bob", otp_text(2)).unwrap();
    // ...and one written by a later run, onto the same file.
    Outbox::load(&dir).queue("bob", otp_text(3)).unwrap();

    let seqs: Vec<u64> = Outbox::load(&dir)
        .take("bob")
        .iter()
        .map(|e| match &e.item {
            OutboxItem::Reliable(P2pPayload::OtpEnvelope { seq, .. }) => *seq,
            other => panic!("unexpected entry {other:?}"),
        })
        .collect();
    assert_eq!(seqs, vec![1, 2, 3]);
    std::fs::remove_dir_all(&dir).ok();
}

/// The one thing that ever removes a queued message: this machine no
/// longer holds key material for that contact, so nothing queued for them
/// could be delivered or read back.
/// @requirement AC-413
#[test]
fn a_sweep_drops_only_the_contacts_whose_keys_are_gone() {
    let dir = scratch_dir("sweep");
    let mut outbox = Outbox::load(&dir);
    outbox.queue("bob", text(b"for bob")).unwrap();
    outbox.queue("bob", text(b"also for bob")).unwrap();
    outbox.queue("carol", text(b"for carol")).unwrap();

    // carol is still a contact here; bob has been deleted.
    let dropped = outbox.retain_contacts(|nickname| nickname == "carol");
    assert_eq!(dropped, 2, "both of bob's went");
    assert_eq!(outbox.len_for("bob"), 0);
    assert_eq!(outbox.len_for("carol"), 1, "carol's key is here, so carol's message stays");
    assert!(!dir.join("bob.q").exists(), "and bob's file is gone from disk too");
    assert!(dir.join("carol.q").exists());
    std::fs::remove_dir_all(&dir).ok();
}

/// A sweep that finds every key still present removes nothing at all.
/// @requirement AC-413
#[test]
fn a_sweep_removes_nothing_while_every_key_is_still_here() {
    let dir = scratch_dir("sweep-noop");
    let mut outbox = Outbox::load(&dir);
    outbox.queue("bob", text(b"one")).unwrap();
    outbox.queue("carol", text(b"two")).unwrap();
    assert_eq!(outbox.retain_contacts(|_| true), 0);
    assert_eq!(outbox.total(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

/// Each peer's queue is their own - draining one must not touch another.
/// @requirement AC-409
#[test]
fn one_peers_queue_is_independent_of_anothers() {
    let dir = scratch_dir("independent");
    let mut outbox = Outbox::load(&dir);
    outbox.queue("bob", text(b"bob's")).unwrap();
    outbox.queue("carol", text(b"carol's")).unwrap();
    outbox.take("bob");
    assert_eq!(outbox.len_for("carol"), 1);
    assert_eq!(outbox.len_for("bob"), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// A nickname that could not round-trip through a filename is refused
/// rather than written somewhere unexpected - the same rule every other
/// store this app writes applies to what it stores.
/// @requirement AC-409
#[test]
fn a_nickname_that_is_not_storable_is_refused() {
    let dir = scratch_dir("unstorable");
    let mut outbox = Outbox::load(&dir);
    for bad in ["", "../escape", "with space", "sub/dir"] {
        outbox.queue(bad, text(b"nope")).unwrap();
        assert_eq!(outbox.len_for(bad), 0, "{bad:?} should not be queueable");
    }
    assert!(outbox.peers().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// A half-written final line costs that one entry, not the whole file -
/// which is the reason the format is one line per entry in the first
/// place.
/// @requirement AC-409
#[test]
fn a_truncated_file_loses_one_entry_and_keeps_the_rest() {
    let dir = scratch_dir("truncated");
    {
        let mut outbox = Outbox::load(&dir);
        outbox.queue("bob", text(b"first")).unwrap();
        outbox.queue("bob", text(b"second")).unwrap();
    }
    let path = dir.join("bob.q");
    let contents = std::fs::read_to_string(&path).unwrap();
    // Cut the last line in half, the way a killed process would.
    let cut = contents.len() - 10;
    std::fs::write(&path, &contents[..cut]).unwrap();

    let reopened = Outbox::load(&dir);
    assert_eq!(reopened.len_for("bob"), 1, "the intact entry survives");
    std::fs::remove_dir_all(&dir).ok();
}
