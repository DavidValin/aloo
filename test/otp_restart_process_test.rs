//! Surviving a *real* process kill, not a simulated one.
//!
//! Every other restart test here drops a struct and reloads it, which
//! proves the file is readable but not that a live process is ever killed
//! at a moment that leaves the file half-written. This one actually spawns
//! a second process, lets it arm a pad send, and `SIGKILL`s it - no
//! unwinding, no destructors, no flush - then checks that a fresh process
//! finds the send still outstanding and still re-sendable.
//!
//! Written self-contained rather than on `otp_ack_wiring_test`'s helpers
//! on purpose: that file's `scratch_root` deletes itself on first use, so a
//! child sharing it would wipe the parent's own state out from under it.

use aloo::client::otp_outbox::OtpOutbox;
use aloo::client::otp_store::{OtpStore, PendingOtpContent};
use aloo::p2p_proto::P2pPayload;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "ALOO_RESTART_CHILD_DIR";
const CONTACT: &str = "restart-contact";
const SEQ: u64 = 7;
const PROOF: [u8; 32] = [0x5a; 32];

fn store_path(dir: &Path) -> PathBuf {
    dir.join("otp_store")
}

fn outbox_dir(dir: &Path) -> PathBuf {
    dir.join("outbox")
}

fn sealed_payload() -> P2pPayload {
    P2pPayload::OtpEnvelope {
        channel: None,
        msg_id: Some(1),
        seq: SEQ,
        envelope: aloo::proto::Envelope {
            content: aloo::proto::Content::Text,
            blocks: vec![vec![0xAB; 32]],
        },
        sender_device_id: "test-device".into(),
    }
}

/// What the doomed process does: arm the gate and queue the sealed bytes,
/// exactly as a real send does, then say it is ready and never exit.
fn be_the_doomed_process(dir: PathBuf) {
    let mut store = OtpStore::new_empty(store_path(&dir));
    // The write-ahead half first, then the spend it accounts for - the
    // order a real send uses, so a kill between them is representable.
    store.set_encrypt_intent(CONTACT, PendingOtpContent::Text { channel: None });
    store.record_sealed(CONTACT, SEQ);
    store.clear_encrypt_intent(CONTACT);
    store.record_sent(
        CONTACT,
        SEQ,
        PendingOtpContent::Text { channel: None },
        Some(PROOF),
    );
    store.save().expect("the doomed process must get its state to disk");

    let mut outbox = OtpOutbox::load(&outbox_dir(&dir));
    outbox
        .queue(CONTACT, &sealed_payload(), SEQ, Some(1), None, PROOF)
        .expect("queueing the sealed bytes must reach disk");

    std::fs::write(dir.join("ready"), b"armed").expect("readiness marker");
    // Nothing here will ever run a destructor: the parent kills this.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// @requirement AC-440
#[test]
fn an_outstanding_send_survives_a_real_process_kill() {
    if let Ok(dir) = std::env::var(CHILD_ENV) {
        be_the_doomed_process(PathBuf::from(dir));
        return;
    }

    let dir = std::env::temp_dir().join(format!(
        "aloo-restart-kill-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");

    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["an_outstanding_send_survives_a_real_process_kill", "--exact", "--nocapture"])
        .env(CHILD_ENV, &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawning a second process");

    // Wait for it to have genuinely written its state.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dir.join("ready").exists() {
        assert!(
            Instant::now() < deadline,
            "the child never armed its send; nothing to kill"
        );
        assert!(
            child.try_wait().expect("child status").is_none(),
            "the child exited instead of parking"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // SIGKILL: no unwinding, no flush, no chance to tidy up.
    child.kill().expect("kill the child");
    let status = child.wait().expect("reap the child");
    assert!(!status.success(), "the child was killed, not allowed to finish");

    // A fresh process reads what the killed one left behind.
    let store = OtpStore::load(&store_path(&dir)).expect("the store must survive the kill");
    let state = store
        .get(CONTACT)
        .expect("the contact's state must survive the kill");
    assert_eq!(
        state.pending_unacked_out_seq,
        Some(SEQ),
        "the gate has to still name the send the killed process left outstanding - \
         losing it would strand every message behind it"
    );
    assert_eq!(
        state.pending_ack_proof,
        Some(PROOF),
        "and its proof, or no acknowledgement could ever satisfy it again"
    );
    assert!(
        state.encrypt_intent.is_none(),
        "the write-ahead intent was cleared before the kill, so nothing is orphaned"
    );

    // And the sealed bytes are still there to re-send, which is what the
    // retry does - it never re-encrypts.
    let outbox = OtpOutbox::load(&outbox_dir(&dir));
    let front = outbox
        .front(CONTACT)
        .expect("the sealed message must survive the kill");
    assert_eq!(
        front.seq(),
        Some(SEQ),
        "the queue front is the very message the gate is waiting on, so the \
         restarted process can put it back on the wire from disk alone"
    );
    assert!(
        front.ack_proof().is_some(),
        "with the proof its acknowledgement will have to carry"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
