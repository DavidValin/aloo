//! The pad session's durable send queue (`client::otp_outbox`, US-064):
//! what it keeps, the order it keeps it in, that it survives the process
//! that sealed it, and that it is drained one message per acknowledgement
//! rather than all at once.
//!
//! Every entry here is a *spent pad position* - sealing is spending - so
//! the properties this pins are about not losing one and not sending one
//! twice.

use aloo::client::otp_outbox::OtpOutbox;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{Content, Envelope};

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-outbox-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A sealed pad-wrapped message. Opaque here on purpose: the queue keeps
/// ciphertext and never looks inside it.
fn sealed(seq: u64) -> P2pPayload {
    P2pPayload::OtpEnvelope {
        channel: None,
        msg_id: Some(seq),
        seq,
        envelope: Envelope {
            content: Content::Text,
            blocks: vec![vec![seq as u8; 48]],
        },
        sender_device_id: "laptop".into(),
    }
}

fn proof(seq: u64) -> [u8; 32] {
    [seq as u8; 32]
}

fn queue_n(outbox: &mut OtpOutbox, contact: &str, n: u64) {
    for seq in 0..n {
        outbox
            .queue(contact, &sealed(seq), seq, Some(seq), None, proof(seq))
            .unwrap();
    }
}

/// The order is the whole contract: the receiver's pad decrypts in the
/// order these were sealed.
/// @requirement AC-418
#[test]
fn sealed_messages_come_back_in_the_order_they_were_sealed() {
    let dir = scratch_dir("order");
    let mut outbox = OtpOutbox::load(&dir);
    queue_n(&mut outbox, "alice-bob", 5);

    for seq in 0..5 {
        let front = outbox.front("alice-bob").expect("a message is waiting");
        assert_eq!(front.seq(), Some(seq), "strictly in order");
        assert_eq!(front.ack_proof(), Some(proof(seq)), "each carries its own proof");
        outbox.take_front("alice-bob").unwrap();
    }
    assert_eq!(outbox.len_for("alice-bob"), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// A peek, not a take: the front stays put until its own acknowledgement
/// arrives, so a message that left but was never answered is retried
/// rather than skipped past.
/// @requirement AC-418
#[test]
fn the_front_stays_until_its_own_acknowledgement_retires_it() {
    let dir = scratch_dir("front");
    let mut outbox = OtpOutbox::load(&dir);
    queue_n(&mut outbox, "alice-bob", 3);

    assert_eq!(outbox.front("alice-bob").unwrap().seq(), Some(0));
    assert_eq!(
        outbox.front("alice-bob").unwrap().seq(),
        Some(0),
        "reading it again does not consume it"
    );
    assert_eq!(outbox.len_for("alice-bob"), 3);

    outbox.take_front("alice-bob").unwrap();
    assert_eq!(outbox.front("alice-bob").unwrap().seq(), Some(1));
    assert_eq!(outbox.len_for("alice-bob"), 2);
    std::fs::remove_dir_all(&dir).ok();
}

/// A spent pad position must not be lost to a restart - that is the whole
/// reason this is on disk.
/// @requirement AC-418
#[test]
fn sealed_messages_survive_the_process_that_sealed_them() {
    let dir = scratch_dir("restart");
    {
        let mut outbox = OtpOutbox::load(&dir);
        queue_n(&mut outbox, "alice-bob", 3);
        outbox.take_front("alice-bob").unwrap(); // one was acked before the crash
    }

    let reopened = OtpOutbox::load(&dir);
    assert_eq!(reopened.len_for("alice-bob"), 2);
    assert_eq!(
        reopened.front("alice-bob").unwrap().seq(),
        Some(1),
        "and resumes at the one that was never acknowledged"
    );
    assert_eq!(reopened.contacts(), vec!["alice-bob".to_string()]);
    assert_eq!(reopened.total(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

/// The payload comes back byte for byte - it is ciphertext, and nothing
/// here re-seals or re-encodes it.
/// @requirement AC-418
#[test]
fn the_sealed_payload_comes_back_exactly_as_it_went_in() {
    let dir = scratch_dir("identical");
    let mut outbox = OtpOutbox::load(&dir);
    outbox
        .queue("alice-bob", &sealed(7), 7, Some(42), Some("general".into()), proof(7))
        .unwrap();

    let front = OtpOutbox::load(&dir);
    let entry = front.front("alice-bob").expect("waiting");
    assert_eq!(entry.payload(), Some(sealed(7)));
    assert_eq!(entry.seq(), Some(7));
    assert_eq!(entry.msg_id(), Some(42));
    assert_eq!(entry.channel(), Some("general".into()));
    std::fs::remove_dir_all(&dir).ok();
}

/// One contact's queue is their own.
/// @requirement AC-418
#[test]
fn one_contacts_queue_is_independent_of_anothers() {
    let dir = scratch_dir("independent");
    let mut outbox = OtpOutbox::load(&dir);
    queue_n(&mut outbox, "alice-bob", 2);
    queue_n(&mut outbox, "alice-carol", 1);

    outbox.take_front("alice-bob").unwrap();
    assert_eq!(outbox.len_for("alice-bob"), 1);
    assert_eq!(outbox.len_for("alice-carol"), 1);
    std::fs::remove_dir_all(&dir).ok();
}

/// Nothing ages out and nothing is evicted - the only removal is the
/// contact's keys being gone, after which nothing sealed under them could
/// ever be decrypted by anyone.
/// @requirement AC-419
#[test]
fn only_a_contact_whose_keys_are_gone_loses_its_queue() {
    let dir = scratch_dir("sweep");
    let mut outbox = OtpOutbox::load(&dir);
    queue_n(&mut outbox, "alice-bob", 3);
    queue_n(&mut outbox, "alice-carol", 1);

    assert_eq!(outbox.retain_contacts(|_| true), 0, "every key still here");
    assert_eq!(outbox.total(), 4);

    let dropped = outbox.retain_contacts(|contact| contact == "alice-carol");
    assert_eq!(dropped, 3);
    assert_eq!(outbox.len_for("alice-bob"), 0);
    assert_eq!(outbox.len_for("alice-carol"), 1);
    assert!(
        !dir.join("alice-bob.q").exists(),
        "and the file that held that pad output is gone from disk"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Draining the last entry takes the file with it, rather than leaving an
/// empty one where pad output used to be.
/// @requirement AC-419
#[test]
fn an_emptied_queue_leaves_no_file_behind() {
    let dir = scratch_dir("emptied");
    let mut outbox = OtpOutbox::load(&dir);
    queue_n(&mut outbox, "alice-bob", 1);
    assert!(dir.join("alice-bob.q").exists());

    outbox.take_front("alice-bob").unwrap();
    assert!(!dir.join("alice-bob.q").exists());
    assert!(OtpOutbox::load(&dir).contacts().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// A half-written final line costs that one entry, not the queue behind
/// it - the reason the format is one line per message.
/// @requirement AC-418
#[test]
fn a_truncated_file_loses_one_entry_and_keeps_the_rest() {
    let dir = scratch_dir("truncated");
    {
        let mut outbox = OtpOutbox::load(&dir);
        queue_n(&mut outbox, "alice-bob", 2);
    }
    let path = dir.join("alice-bob.q");
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, &contents[..contents.len() - 12]).unwrap();

    let reopened = OtpOutbox::load(&dir);
    assert_eq!(reopened.len_for("alice-bob"), 1);
    assert_eq!(reopened.front("alice-bob").unwrap().seq(), Some(0));
    std::fs::remove_dir_all(&dir).ok();
}

/// A contact name that could not round-trip through a filename is
/// refused rather than written somewhere unexpected - and *says* it
/// refused, which is the part that matters: by the time the caller asks,
/// the pad position is already spent, so a refusal reported as success
/// would lose the only copy of a message that can never be re-sealed and
/// leave the two ends' pads out of step for good.
/// @requirement AC-418
/// @requirement AC-421
#[test]
fn an_unstorable_contact_name_is_refused_and_says_so() {
    let dir = scratch_dir("unstorable");
    let mut outbox = OtpOutbox::load(&dir);
    for bad in ["", "../escape", "with space", "sub/dir"] {
        let accepted = outbox.queue(bad, &sealed(0), 0, None, None, proof(0)).unwrap();
        assert!(!accepted, "{bad:?} must report that it was not taken");
        assert_eq!(outbox.len_for(bad), 0, "{bad:?} should not be queueable");
    }
    assert!(outbox.contacts().is_empty());

    let accepted = outbox
        .queue("alice-bob", &sealed(0), 0, None, None, proof(0))
        .unwrap();
    assert!(accepted, "a storable name is taken, and says so");
    std::fs::remove_dir_all(&dir).ok();
}

/// A queued recording is an ordinary entry - its place in line, its
/// sequence, its acknowledgement proof - whose ciphertext is a file the
/// queue owns rather than inline bytes.
/// @requirement AC-423
#[test]
fn a_recording_waits_in_line_like_any_other_entry() {
    let dir = scratch_dir("recording-order");
    let mut outbox = OtpOutbox::load(&dir);
    outbox
        .queue("alice-bob", &sealed(0), 0, Some(0), None, proof(0))
        .unwrap();
    let rec_path = outbox.recording_path_for("alice-bob", 1).expect("safe name");
    std::fs::write(&rec_path, b"sealed recording bytes").unwrap();
    assert!(outbox
        .queue_recording("alice-bob", &rec_path, 7, 1, Some(1), proof(1))
        .unwrap());
    outbox
        .queue("alice-bob", &sealed(2), 2, Some(2), None, proof(2))
        .unwrap();

    let entries = outbox.entries_for("alice-bob");
    assert_eq!(entries.len(), 3);
    assert!(entries[0].recording().is_none());
    let (path, stream_id) = entries[1].recording().expect("the recording sits in line");
    assert_eq!((path, stream_id), (rec_path.clone(), 7));
    assert_eq!(entries[1].seq(), Some(1));
    assert_eq!(entries[1].ack_proof(), Some(proof(1)));
    assert!(
        entries[1].payload().is_none(),
        "its bytes are the file, never an inline payload"
    );
    assert!(entries[2].recording().is_none());
    std::fs::remove_dir_all(&dir).ok();
}

/// The reference and the file it names both survive the process that
/// sealed them - that is the whole reason either is on disk.
/// @requirement AC-423
#[test]
fn a_queued_recording_survives_a_restart() {
    let dir = scratch_dir("recording-restart");
    let rec_path;
    {
        let mut outbox = OtpOutbox::load(&dir);
        rec_path = outbox.recording_path_for("alice-bob", 0).unwrap();
        std::fs::write(&rec_path, b"sealed recording bytes").unwrap();
        outbox
            .queue_recording("alice-bob", &rec_path, 3, 0, None, proof(0))
            .unwrap();
    }
    let reopened = OtpOutbox::load(&dir);
    assert_eq!(reopened.len_for("alice-bob"), 1);
    assert_eq!(
        reopened.front("alice-bob").unwrap().recording(),
        Some((rec_path.clone(), 3))
    );
    assert!(rec_path.exists(), "the ciphertext file is still there");
    std::fs::remove_dir_all(&dir).ok();
}

/// Retiring a recording takes its ciphertext file with it: the
/// acknowledgement just proved the peer holds the bytes, and this copy is
/// pad output with no remaining purpose.
/// @requirement AC-419
#[test]
fn retiring_a_recording_deletes_its_ciphertext_file() {
    let dir = scratch_dir("recording-retire");
    let mut outbox = OtpOutbox::load(&dir);
    let rec_path = outbox.recording_path_for("alice-bob", 0).unwrap();
    std::fs::write(&rec_path, b"sealed recording bytes").unwrap();
    outbox
        .queue_recording("alice-bob", &rec_path, 3, 0, None, proof(0))
        .unwrap();

    outbox.take_front("alice-bob").unwrap();
    assert!(!rec_path.exists(), "the file goes with its entry");
    assert_eq!(outbox.len_for("alice-bob"), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// A swept contact's recordings go too - sealed for keys this machine no
/// longer holds, nobody could ever read them.
/// @requirement AC-419
#[test]
fn sweeping_a_contact_deletes_its_recording_files() {
    let dir = scratch_dir("recording-sweep");
    let mut outbox = OtpOutbox::load(&dir);
    let rec_path = outbox.recording_path_for("alice-bob", 0).unwrap();
    std::fs::write(&rec_path, b"sealed recording bytes").unwrap();
    outbox
        .queue_recording("alice-bob", &rec_path, 3, 0, None, proof(0))
        .unwrap();

    assert_eq!(outbox.retain_contacts(|_| false), 1);
    assert!(!rec_path.exists());
    std::fs::remove_dir_all(&dir).ok();
}

/// A `.rec` file nothing references - the residue of a crash between
/// encrypting and appending the entry - is swept at load rather than left
/// as unaccounted pad output.
/// @requirement AC-419
#[test]
fn an_orphaned_recording_file_is_swept_at_load() {
    let dir = scratch_dir("recording-orphan");
    {
        let mut outbox = OtpOutbox::load(&dir);
        let kept = outbox.recording_path_for("alice-bob", 0).unwrap();
        std::fs::write(&kept, b"referenced").unwrap();
        outbox
            .queue_recording("alice-bob", &kept, 3, 0, None, proof(0))
            .unwrap();
        std::fs::write(dir.join("alice-bob.9.rec"), b"orphaned").unwrap();
    }
    let reopened = OtpOutbox::load(&dir);
    assert!(
        !dir.join("alice-bob.9.rec").exists(),
        "the orphan is gone"
    );
    assert!(
        reopened
            .front("alice-bob")
            .unwrap()
            .recording()
            .map(|(p, _)| p.exists())
            .unwrap_or(false),
        "and the referenced file is untouched"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The rewrite a retirement does must never be able to lose the whole
/// remaining queue. It stages the new contents beside the file first, so
/// the worst crash instant leaves either the stale file (whose extra
/// front entry is a free retry) or the staged one, which load adopts.
/// @requirement AC-418
#[test]
fn a_rewrite_killed_at_its_worst_instant_loses_nothing() {
    let dir = scratch_dir("rewrite-crash");
    {
        let mut outbox = OtpOutbox::load(&dir);
        queue_n(&mut outbox, "alice-bob", 3);
        outbox.take_front("alice-bob").unwrap();
    }
    // Reconstruct the crash: the staged sibling written, the real file
    // scrubbed, the process dead before the rename.
    let real = dir.join("alice-bob.q");
    let staged = dir.join("alice-bob.q.new");
    std::fs::rename(&real, &staged).unwrap();

    let adopted = OtpOutbox::load(&dir);
    assert_eq!(
        adopted.len_for("alice-bob"),
        2,
        "the staged file is the whole surviving queue, and load adopts it"
    );
    assert_eq!(adopted.front("alice-bob").unwrap().seq(), Some(1));
    assert!(real.exists(), "under its real name again");
    assert!(!staged.exists());
    std::fs::remove_dir_all(&dir).ok();
}

/// The other crash instant: staged written, old file still present. The
/// stale file wins - its extra front entry costs one retry the receiver
/// answers from its recorded ack, where guessing could cost a position.
/// @requirement AC-418
#[test]
fn a_stale_file_beside_a_staged_one_wins() {
    let dir = scratch_dir("rewrite-stale");
    {
        let mut outbox = OtpOutbox::load(&dir);
        queue_n(&mut outbox, "alice-bob", 2);
    }
    std::fs::write(dir.join("alice-bob.q.new"), "garbage that must not be adopted\n").unwrap();

    let reopened = OtpOutbox::load(&dir);
    assert_eq!(reopened.len_for("alice-bob"), 2, "the real file is untouched");
    assert!(
        !dir.join("alice-bob.q.new").exists(),
        "and the sibling is scrubbed, not left to be adopted later"
    );
    std::fs::remove_dir_all(&dir).ok();
}
