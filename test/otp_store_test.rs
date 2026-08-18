use aloo::client::otp_store::{OtpStore, PendingOtpContent};
use std::path::PathBuf;

fn temp_store_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-otp-store-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ))
}

fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

/// @requirement TB-182
#[test]
fn loading_a_missing_file_starts_empty_not_an_error() {
    let path = temp_store_path();
    let store = OtpStore::load(&path).expect("missing file should not be an error");
    assert_eq!(store.get("alice-bob"), None);
}

/// @requirement TB-182
#[test]
fn mark_provisioned_round_trips_through_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.save().unwrap();

    let loaded = OtpStore::load(&path).unwrap();
    assert!(loaded.get("alice-bob").unwrap().provisioned);

    std::fs::remove_file(&path).ok();
}

/// @requirement AC-137
#[test]
fn record_sent_sets_the_pending_ack_gate() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.mark_provisioned("alice-bob");
    store.record_sent("alice-bob", 0, PendingOtpContent::Text { channel: None });
    let state = store.get("alice-bob").unwrap();
    assert_eq!(state.pending_unacked_out_seq, Some(0));
    assert_eq!(state.next_out_seq, 1);
}

/// @requirement AC-137
#[test]
fn record_acked_clears_the_gate_only_on_a_matching_sequence() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.record_sent("alice-bob", 5, PendingOtpContent::Text { channel: None });

    // A stale/mismatched ack must not clear a different outstanding message.
    assert!(!store.record_acked("alice-bob", 4));
    assert_eq!(
        store.get("alice-bob").unwrap().pending_unacked_out_seq,
        Some(5)
    );

    assert!(store.record_acked("alice-bob", 5));
    assert_eq!(store.get("alice-bob").unwrap().pending_unacked_out_seq, None);

    // A second ack for the same (now cleared) sequence is a no-op, not an
    // error - there's nothing left to clear.
    assert!(!store.record_acked("alice-bob", 5));
}

/// @requirement AC-137
#[test]
fn record_received_only_accepts_the_exact_next_sequence() {
    let mut store = OtpStore::new_empty(temp_store_path());

    assert!(store.record_received("alice-bob", 0));
    assert_eq!(store.get("alice-bob").unwrap().next_expected_in_seq, 1);

    // A duplicate/replayed sequence is refused.
    assert!(!store.record_received("alice-bob", 0));
    // An out-of-order jump ahead is refused too - only the exact next value.
    assert!(!store.record_received("alice-bob", 2));

    assert!(store.record_received("alice-bob", 1));
    assert_eq!(store.get("alice-bob").unwrap().next_expected_in_seq, 2);
}

/// @requirement TB-187
#[test]
fn forget_removes_a_provisioned_entry() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.mark_provisioned("alice-bob");
    assert!(store.forget("alice-bob"));
    assert_eq!(store.get("alice-bob"), None);
}

/// @requirement TB-187
#[test]
fn forget_returns_false_when_there_was_nothing_to_forget() {
    let mut store = OtpStore::new_empty(temp_store_path());
    assert!(!store.forget("nobody"));
}

/// @requirement TB-188
#[test]
fn is_next_expected_is_read_only() {
    let mut store = OtpStore::new_empty(temp_store_path());
    // An unknown contact expects sequence 0, same as `record_received`'s
    // default - and checking never mutates anything.
    assert!(store.is_next_expected("alice-bob", 0));
    assert!(!store.is_next_expected("alice-bob", 1));
    assert!(store.is_next_expected("alice-bob", 0), "a peek must not consume the check");

    assert!(store.record_received("alice-bob", 0));
    assert!(!store.is_next_expected("alice-bob", 0), "already accepted - no longer expected");
    assert!(store.is_next_expected("alice-bob", 1));
}

/// @requirement TB-188
#[test]
fn is_next_expected_rejects_a_resend_of_an_already_accepted_sequence() {
    // The scenario `recover_and_resend` can create: a message the peer
    // already decrypted successfully gets resent (only the ack was lost).
    // The receiver must reject it *before* ever running `otp --decrypt`
    // again - `otp` itself has no way to detect the duplicate and would
    // silently consume more pad. This is checked at the `otp_store` level
    // since that's the gate `client::otp::on_message` now consults first.
    let mut store = OtpStore::new_empty(temp_store_path());
    assert!(store.record_received("alice-bob", 0));
    // A resend of seq 0 must not look like the next expected message.
    assert!(!store.is_next_expected("alice-bob", 0));
}

/// @requirement TB-188, AC-147
#[test]
fn pending_content_round_trips_through_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.record_sent("text-contact", 0, PendingOtpContent::Text { channel: None });
    store.record_sent(
        "text-channel-contact",
        0,
        PendingOtpContent::Text {
            channel: Some("general".to_string()),
        },
    );
    store.record_sent(
        "file-contact",
        3,
        PendingOtpContent::File {
            stream_id: 9,
            filename: "report.pdf".to_string(),
            size: 123456,
        },
    );
    store.record_sent(
        "file-content-contact",
        4,
        PendingOtpContent::FileContent { stream_id: 9 },
    );
    store.record_sent("voice-contact", 1, PendingOtpContent::Voice { duration_ms: 4200 });
    store.save().unwrap();

    let loaded = OtpStore::load(&path).unwrap();
    assert_eq!(
        loaded.get("text-contact").unwrap().pending_content,
        Some(PendingOtpContent::Text { channel: None })
    );
    assert_eq!(
        loaded.get("text-channel-contact").unwrap().pending_content,
        Some(PendingOtpContent::Text {
            channel: Some("general".to_string())
        })
    );
    assert_eq!(
        loaded.get("file-contact").unwrap().pending_content,
        Some(PendingOtpContent::File {
            stream_id: 9,
            filename: "report.pdf".to_string(),
            size: 123456
        })
    );
    assert_eq!(
        loaded.get("file-content-contact").unwrap().pending_content,
        Some(PendingOtpContent::FileContent { stream_id: 9 })
    );
    assert_eq!(
        loaded.get("voice-contact").unwrap().pending_content,
        Some(PendingOtpContent::Voice { duration_ms: 4200 })
    );

    std::fs::remove_file(&path).ok();
}

/// @requirement TB-188
#[test]
fn a_line_written_before_pending_content_existed_still_loads() {
    // Backward compatibility: a store file saved by an older build has no
    // trailing pending-content field at all, not just an empty one.
    let path = temp_store_path();
    std::fs::write(&path, "alice-bob\t1\t2\t3\t4\n").unwrap();
    let loaded = OtpStore::load(&path).unwrap();
    let state = loaded.get("alice-bob").unwrap();
    assert!(state.provisioned);
    assert_eq!(state.pending_unacked_out_seq, Some(2));
    assert_eq!(state.pending_content, None);
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-188, AC-147
#[test]
fn record_acked_clears_pending_content() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.record_sent("acked", 0, PendingOtpContent::Text { channel: None });
    assert!(store.record_acked("acked", 0));
    assert_eq!(store.get("acked").unwrap().pending_content, None);
}

/// @requirement TB-188, AC-147
#[test]
fn pending_sends_yields_only_contacts_with_something_outstanding() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.mark_provisioned("idle-contact");
    store.record_sent(
        "busy-contact",
        2,
        PendingOtpContent::Voice { duration_ms: 900 },
    );

    let pending: Vec<_> = store.pending_sends().collect();
    assert_eq!(pending.len(), 1);
    let (name, seq, content) = pending[0];
    assert_eq!(name, "busy-contact");
    assert_eq!(seq, 2);
    assert_eq!(content, &PendingOtpContent::Voice { duration_ms: 900 });
}

/// @requirement TB-182
#[test]
fn a_malformed_line_is_skipped_rather_than_failing_the_whole_load() {
    let path = temp_store_path();
    std::fs::write(&path, "good\t1\t\t3\t4\nnot-enough-columns\n").unwrap();
    let store = OtpStore::load(&path).expect("a bad line must not fail the whole load");
    let state = store.get("good").expect("the well-formed line should still load");
    assert!(state.provisioned);
    assert_eq!(state.pending_unacked_out_seq, None);
    assert_eq!(state.next_out_seq, 3);
    assert_eq!(state.next_expected_in_seq, 4);
    assert_eq!(store.get("not-enough-columns"), None);

    std::fs::remove_file(&path).ok();
}
