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
    store.record_sent("alice-bob", 0, PendingOtpContent::Text { channel: None }, None);
    let state = store.get("alice-bob").unwrap();
    assert_eq!(state.pending_unacked_out_seq, Some(0));
    assert_eq!(state.next_out_seq, 1);
}

/// @requirement AC-137
#[test]
fn record_acked_clears_the_gate_only_on_a_matching_sequence() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.record_sent("alice-bob", 5, PendingOtpContent::Text { channel: None }, None);

    // A stale/mismatched ack must not clear a different outstanding message.
    assert!(!store.record_acked("alice-bob", 4, None));
    assert_eq!(
        store.get("alice-bob").unwrap().pending_unacked_out_seq,
        Some(5)
    );

    assert!(store.record_acked("alice-bob", 5, None));
    assert_eq!(store.get("alice-bob").unwrap().pending_unacked_out_seq, None);

    // A second ack for the same (now cleared) sequence is a no-op, not an
    // error - there's nothing left to clear.
    assert!(!store.record_acked("alice-bob", 5, None));
}

/// The gate is what stops aloo passing `-y` to the next `otp --encrypt`,
/// so what opens it has to be unforgeable. A sequence number alone is
/// visible to anyone who saw the packet; the proof is not, because reaching
/// it requires the nonce that only the pad reveals.
///
/// @requirement AC-250
#[test]
fn record_acked_refuses_an_ack_that_cannot_name_the_message() {
    let mut store = OtpStore::new_empty(temp_store_path());
    let proof = aloo::crypto::otp::ack_proof_for(b"the nonce that rode under the pad");
    store.record_sent(
        "alice-bob",
        7,
        PendingOtpContent::Text { channel: None },
        Some(proof),
    );

    // Right sequence, wrong proof - an observer quoting back what it saw.
    assert!(!store.record_acked("alice-bob", 7, Some([0u8; 32])));
    // Right sequence, no proof at all.
    assert!(!store.record_acked("alice-bob", 7, None));
    assert_eq!(
        store.get("alice-bob").unwrap().pending_unacked_out_seq,
        Some(7),
        "a refused ack must leave the message outstanding, not silently drop it"
    );

    assert!(store.record_acked("alice-bob", 7, Some(proof)));
    let state = store.get("alice-bob").unwrap();
    assert_eq!(state.pending_unacked_out_seq, None);
    assert_eq!(
        state.pending_ack_proof, None,
        "the expectation is spent along with the gate it guarded"
    );
}

/// A message recorded without an expectation - written by a build predating
/// this check, or a mail spend the server acknowledges - must still be
/// clearable, or the contact would wedge permanently.
///
/// @requirement AC-250
#[test]
fn record_acked_still_clears_a_message_that_recorded_no_expectation() {
    let mut store = OtpStore::new_empty(temp_store_path());
    store.record_sent("alice-bob", 1, PendingOtpContent::Text { channel: None }, None);
    assert!(store.record_acked("alice-bob", 1, Some([9u8; 32])));
    assert_eq!(store.get("alice-bob").unwrap().pending_unacked_out_seq, None);
}

/// The gate outlives a restart, so the expectation guarding it has to as
/// well - otherwise an ack arriving after a restart could only be trusted
/// blindly or refused forever.
///
/// @requirement AC-250
#[test]
fn a_pending_ack_proof_survives_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    let proof = aloo::crypto::otp::ack_proof_for(b"nonce");
    store.record_sent(
        "alice-bob",
        2,
        PendingOtpContent::Text { channel: None },
        Some(proof),
    );
    store.save().unwrap();

    let mut loaded = OtpStore::load(&path).unwrap();
    assert_eq!(loaded.get("alice-bob").unwrap().pending_ack_proof, Some(proof));
    assert!(!loaded.record_acked("alice-bob", 2, Some([0u8; 32])));
    assert!(loaded.record_acked("alice-bob", 2, Some(proof)));
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
    store.record_sent("text-contact", 0, PendingOtpContent::Text { channel: None }, None);
    store.record_sent(
        "text-channel-contact",
        0,
        PendingOtpContent::Text {
            channel: Some("general".to_string()),
        },
        None,
    );
    store.record_sent(
        "file-contact",
        3,
        PendingOtpContent::File {
            stream_id: 9,
            filename: "report.pdf".to_string(),
            size: 123456,
        },
        None,
    );
    store.record_sent(
        "file-content-contact",
        4,
        PendingOtpContent::FileContent { stream_id: 9 },
        None,
    );
    store.record_sent("voice-contact", 1, PendingOtpContent::Voice {
            stream_id: 77,
            duration_ms: 4200,
        }, None);
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
        Some(PendingOtpContent::Voice {
            stream_id: 77,
            duration_ms: 4200,
        })
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
    store.record_sent("acked", 0, PendingOtpContent::Text { channel: None }, None);
    assert!(store.record_acked("acked", 0, None));
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
        PendingOtpContent::Voice {
            stream_id: 77,
            duration_ms: 900,
        },
        None,
    );

    let pending: Vec<_> = store.pending_sends().collect();
    assert_eq!(pending.len(), 1);
    let (name, seq, content) = pending[0];
    assert_eq!(name, "busy-contact");
    assert_eq!(seq, 2);
    assert_eq!(content, &PendingOtpContent::Voice {
            stream_id: 77,
            duration_ms: 900,
        });
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

// ---------------------------------------------------------------------
// A pad owed to a peer, so an undelivered invitation is retried rather
// than regenerated
// ---------------------------------------------------------------------

/// @requirement AC-142
#[test]
fn a_pending_setup_survives_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_setup_pending("alice-bob", 4);
    store.save().unwrap();

    // Reloaded, because the whole point is surviving a restart - a peer who
    // never received their pad is owed it just as much tomorrow.
    let loaded = OtpStore::load(&path).unwrap();
    assert_eq!(
        loaded.get("alice-bob").unwrap().pending_setup_size_mb,
        Some(4)
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-142
#[test]
fn clearing_a_pending_setup_reports_whether_anything_was_owed() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_setup_pending("alice-bob", 1);
    assert!(
        store.clear_pending_setup("alice-bob"),
        "the first answer to an outstanding invitation clears it"
    );
    assert!(
        !store.clear_pending_setup("alice-bob"),
        "a duplicate or stray answer must be distinguishable from a real one"
    );
    assert!(!store.clear_pending_setup("someone-else"));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-142
#[test]
fn pending_setups_yields_only_contacts_still_owed_a_pad() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_setup_pending("owed", 2);
    store.mark_provisioned("settled");
    let owed: Vec<(String, u32)> = store
        .pending_setups()
        .map(|(n, s)| (n.to_string(), s))
        .collect();
    assert_eq!(owed, vec![("owed".to_string(), 2)]);
    std::fs::remove_file(&path).ok();
}

/// A store written before pads could be owed has no such field at all;
/// loading one must mean "nothing owed", not a parse failure that would
/// discard the delivery-gate state on the same line.
///
/// @requirement AC-142
#[test]
fn a_line_written_before_pending_setup_existed_still_loads() {
    let path = temp_store_path();
    std::fs::write(&path, "alice-bob\t1\t2\t3\t4\tT\n").unwrap();
    let loaded = OtpStore::load(&path).unwrap();
    let state = loaded.get("alice-bob").unwrap();
    assert_eq!(state.pending_setup_size_mb, None);
    assert_eq!(state.pending_unacked_out_seq, Some(2));
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// /endotp - pausing a session (docs/PROTOCOL.md 16.6)
// ---------------------------------------------------------------------

/// @requirement TB-212
#[test]
fn mark_end_requested_owes_the_notice_and_touches_nothing_else() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_sent("alice-bob", 3, PendingOtpContent::Text { channel: None }, None);
    store.record_received("alice-bob", 0);
    store.mark_setup_pending("alice-bob", 2);

    store.mark_end_requested("alice-bob");

    let state = store.get("alice-bob").unwrap();
    assert!(state.pending_end_notice, "the end is owed to the peer, durably");
    assert!(
        state.provisioned,
        "nothing else moves at request time - /endotp is two-phase and pauses nothing \
         until the peer confirms"
    );
    assert_eq!(
        state.pending_unacked_out_seq,
        Some(3),
        "an in-flight send's pad was already spent - the peer's decoder is waiting on \
         exactly that ciphertext, so requesting the end must keep it recoverable"
    );
    assert_eq!(
        state.pending_content,
        Some(PendingOtpContent::Text { channel: None })
    );
    assert_eq!(
        state.pending_setup_size_mb,
        Some(2),
        "even the owed setup survives the request - teardown happens only at confirmation"
    );
    assert_eq!(state.next_out_seq, 4);
    assert_eq!(state.next_expected_in_seq, 1);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-194
#[test]
fn a_pending_end_notice_survives_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.mark_end_requested("alice-bob");
    store.save().unwrap();

    // Reloaded, because the whole point is surviving a restart - a peer who
    // dropped mid-handshake is still owed the notice tomorrow.
    let loaded = OtpStore::load(&path).unwrap();
    assert!(loaded.get("alice-bob").unwrap().pending_end_notice);
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-212
#[test]
fn pause_after_peer_ended_keeps_the_inflight_send_and_owes_no_notice_of_its_own() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_sent("alice-bob", 1, PendingOtpContent::Text { channel: None }, None);

    store.pause_after_peer_ended("alice-bob");

    let state = store.get("alice-bob").unwrap();
    assert!(state.provisioned, "the pad itself is kept on the receiving side too");
    assert_eq!(
        state.pending_unacked_out_seq,
        Some(1),
        "this side's own in-flight send survives being told the session ended - its pad \
         was already spent, and the peer's decoder still expects exactly that ciphertext"
    );
    assert_eq!(
        state.next_out_seq, 2,
        "the sequence counters survive a pause on this side too"
    );
    assert!(
        !state.pending_end_notice,
        "the receiving side was told, not the one telling - it owes no notice of its own"
    );
    assert!(
        state.paused,
        "and the pause itself is recorded, so nothing re-deriving 'in use' from \
         'provisioned' can switch the session back on"
    );
    std::fs::remove_file(&path).ok();
}

/// The pause is durable and distinct from provisioning: it survives a
/// save/load, `provisioned` stays true underneath it, and only a genuine
/// (re)start lifts it - the resume handshake (`mark_provisioned`) or a
/// pad-only pair's local `/otp` (`resume_session`). A reconnect that
/// re-derived "active" from `provisioned` alone used to switch a
/// confirmed-ended session back on, on the one side that saw the other
/// reconnect.
///
/// @requirement AC-443
#[test]
fn a_confirmed_pause_survives_save_and_load_until_a_resume_lifts_it() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    assert!(!store.is_paused("alice-bob"), "a fresh session is in use");

    store.pause_after_peer_ended("alice-bob");
    store.save().unwrap();
    let mut loaded = OtpStore::load(&path).unwrap();
    assert!(loaded.is_paused("alice-bob"), "the pause survives a restart");
    assert!(
        loaded.get("alice-bob").unwrap().provisioned,
        "paused is not un-provisioned: the pad is still there to resume"
    );

    // The resume handshake completing, on either side of it.
    loaded.mark_provisioned("alice-bob");
    assert!(!loaded.is_paused("alice-bob"), "a session just agreed to is in use again");

    // A pad-only pair's local resume, which runs no handshake.
    loaded.pause_after_peer_ended("alice-bob");
    assert!(loaded.resume_session("alice-bob"), "reports the pause it lifted");
    assert!(!loaded.is_paused("alice-bob"));
    assert!(!loaded.resume_session("alice-bob"), "nothing to lift twice");
    assert!(!loaded.is_paused("nobody"), "an unknown contact is not paused, just absent");

    std::fs::remove_file(&path).ok();
    std::fs::remove_file(format!("{}.pending_content", path.display())).ok();
}

/// @requirement AC-443
#[test]
fn a_line_written_before_the_pause_was_durable_still_loads_as_in_use() {
    let path = temp_store_path();
    // Every column up to and including the two proof columns, none for
    // `paused` - a store written by the build before it.
    std::fs::write(&path, "alice-bob\t1\t\t3\t2\t\t\t\t\t\t\t\t\t\t\t\t\t\n").unwrap();
    let store = OtpStore::load(&path).unwrap();
    let state = store.get("alice-bob").expect("the line still parses");
    assert!(state.provisioned);
    assert_eq!(state.next_out_seq, 3);
    assert!(!state.paused, "an older store never recorded a pause, so it never meant one");
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-194
#[test]
fn clear_end_notice_reports_whether_anything_was_owed() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.mark_end_requested("alice-bob");
    assert!(
        store.clear_end_notice("alice-bob"),
        "the first genuine ack clears it"
    );
    assert!(
        !store.clear_end_notice("alice-bob"),
        "a duplicate or stray ack must be distinguishable from a real one"
    );
    assert!(!store.clear_end_notice("someone-else"));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-194
#[test]
fn pending_end_notices_yields_only_contacts_still_owed_one() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("owed");
    store.mark_end_requested("owed");
    store.mark_provisioned("settled");
    let owed: Vec<String> = store.pending_end_notices().map(str::to_string).collect();
    assert_eq!(owed, vec!["owed".to_string()]);
    std::fs::remove_file(&path).ok();
}

/// A store written before `/endotp` existed has no such field at all;
/// loading one must mean "no notice owed", not a parse failure that would
/// discard the rest of that line's state.
///
/// @requirement AC-194
#[test]
fn a_line_written_before_pending_end_notice_existed_still_loads_as_false() {
    let path = temp_store_path();
    std::fs::write(&path, "alice-bob\t1\t2\t3\t4\tT\t7\n").unwrap();
    let loaded = OtpStore::load(&path).unwrap();
    let state = loaded.get("alice-bob").unwrap();
    assert!(!state.pending_end_notice);
    assert_eq!(state.pending_setup_size_mb, Some(7));
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-212
#[test]
fn pausing_one_contacts_session_does_not_touch_another_contacts_state() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.mark_provisioned("alice-carol");
    store.record_sent("alice-carol", 5, PendingOtpContent::Text { channel: None }, None);

    store.pause_after_peer_ended("alice-bob");

    assert!(
        store.get("alice-bob").unwrap().provisioned,
        "the paused contact's own pad is kept"
    );
    let carol = store.get("alice-carol").unwrap();
    assert!(
        carol.provisioned,
        "a wholly independent contact - a different pinned nickname, a different otp key - must \
         be untouched by pausing this one"
    );
    assert_eq!(carol.pending_unacked_out_seq, Some(5));
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-212
#[test]
fn pausing_or_requesting_an_end_never_fabricates_a_provisioned_contact() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.pause_after_peer_ended("stranger");
    assert!(
        !store.get("stranger").unwrap().provisioned,
        "pausing must never make an unprovisioned contact look provisioned"
    );
    store.mark_end_requested("other-stranger");
    let state = store.get("other-stranger").unwrap();
    assert!(!state.provisioned, "nor may requesting an end");
    assert!(state.pending_end_notice);
    std::fs::remove_file(&path).ok();
}

/// `/endotp` is two-phase, so an active contact and an unconfirmed end
/// request can coexist - which means `/otp` has to be able to cancel that
/// request, or it would be re-driven on the next link transition and end
/// the session just reopened (`client::otp::handle_provisioning_command`
/// clears it before proposing).
#[test]
fn a_pending_end_request_can_be_cancelled_and_the_contact_stays_provisioned() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_sent("alice-bob", 3, PendingOtpContent::Text { channel: None }, None);
    store.mark_end_requested("alice-bob");
    assert!(store.get("alice-bob").unwrap().pending_end_notice);

    // Reopening cancels the debt without touching the pad.
    assert!(store.clear_end_notice("alice-bob"));

    let state = store.get("alice-bob").unwrap();
    assert!(!state.pending_end_notice, "the contradictory notice is gone");
    assert!(state.provisioned, "the pad is still there to resume");
    assert_eq!(
        state.next_out_seq, 4,
        "and it resumes where it left off, not from zero"
    );
    assert!(
        store.pending_end_notices().next().is_none(),
        "nothing is owed, so the retry pass has nothing to re-send"
    );
    std::fs::remove_file(&path).ok();
}

/// The whole point of pausing: after `/endotp`, the contact is still
/// provisioned, so `/otp` finds an existing key and proposes resuming it
/// rather than generating a fresh pad.
#[test]
fn a_paused_contact_is_still_provisioned_so_otp_resumes_instead_of_regenerating() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_received("alice-bob", 0);
    store.record_sent("alice-bob", 0, PendingOtpContent::Text { channel: None }, None);
    store.record_acked("alice-bob", 0, None);

    store.pause_after_peer_ended("alice-bob");
    store.save().unwrap();

    // Reloaded, because resuming usually happens in a later session.
    let reloaded = OtpStore::load(&path).unwrap();
    let state = reloaded.get("alice-bob").unwrap();
    assert!(
        state.provisioned,
        "`detect_or_adopt_existing` keys off this - false would mean generating a new pad"
    );
    assert_eq!(state.next_out_seq, 1);
    assert_eq!(state.next_expected_in_seq, 1);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-304
#[test]
fn ack_to_resend_answers_only_the_exact_last_acked_sequence() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    assert_eq!(
        store.ack_to_resend("alice-bob", 0),
        None,
        "nothing has been acked yet"
    );

    store.record_last_received_ack("alice-bob", 3, [0x42; 32]);
    assert_eq!(
        store.ack_to_resend("alice-bob", 3),
        Some([0x42; 32]),
        "the exact sequence just recorded must be answered"
    );
    assert_eq!(
        store.ack_to_resend("alice-bob", 2),
        None,
        "anything older than the last-acked sequence is a stale replay, not this one"
    );
    assert_eq!(store.ack_to_resend("someone-else", 3), None);
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-304
#[test]
fn record_last_received_ack_overwrites_rather_than_accumulates() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_last_received_ack("alice-bob", 3, [0x42; 32]);
    store.record_last_received_ack("alice-bob", 4, [0x43; 32]);

    assert_eq!(
        store.ack_to_resend("alice-bob", 3),
        None,
        "only the single most recent message could ever legitimately reappear"
    );
    assert_eq!(store.ack_to_resend("alice-bob", 4), Some([0x43; 32]));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-304
#[test]
fn last_received_ack_survives_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_last_received_ack("alice-bob", 7, [0x99; 32]);
    store.save().unwrap();

    let loaded = OtpStore::load(&path).unwrap();
    assert_eq!(loaded.ack_to_resend("alice-bob", 7), Some([0x99; 32]));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-313
#[test]
fn an_encrypt_intent_round_trips_and_record_sent_retires_it() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.set_encrypt_intent("alice-bob", PendingOtpContent::Text { channel: None });
    assert!(store.encrypt_in_flight("alice-bob"));
    store.save().unwrap();

    // Reloaded, because the whole point is surviving the kill it records.
    let mut loaded = OtpStore::load(&path).unwrap();
    let intents: Vec<(String, PendingOtpContent)> = loaded
        .encrypt_intents()
        .map(|(n, c)| (n.to_string(), c.clone()))
        .collect();
    assert_eq!(
        intents,
        vec![("alice-bob".to_string(), PendingOtpContent::Text { channel: None })]
    );

    loaded.record_sent("alice-bob", 0, PendingOtpContent::Text { channel: None }, None);
    assert!(
        !loaded.encrypt_in_flight("alice-bob"),
        "the finalising record_sent retires the write-ahead intent"
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-311
#[test]
fn a_pending_commit_survives_save_and_load_and_clears_exactly_once() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.mark_commit_owed("alice-bob");
    store.save().unwrap();

    // Reloaded, because the whole point is surviving a restart: a peer who
    // dropped before confirming their install is still owed the commit
    // tomorrow.
    let mut loaded = OtpStore::load(&path).unwrap();
    let owed: Vec<String> = loaded.pending_commits().map(str::to_string).collect();
    assert_eq!(owed, vec!["alice-bob".to_string()]);

    assert!(loaded.clear_commit_owed("alice-bob"), "the first genuine ack clears it");
    assert!(
        !loaded.clear_commit_owed("alice-bob"),
        "a duplicate or stray ack is distinguishable from a real one"
    );
    assert!(loaded.pending_commits().next().is_none());
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-308
#[test]
fn an_end_notice_pending_send_round_trips_through_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_sent("alice-bob", 5, PendingOtpContent::EndNotice, Some([0x21; 32]));
    store.mark_end_requested("alice-bob");
    store.save().unwrap();

    let loaded = OtpStore::load(&path).unwrap();
    let state = loaded.get("alice-bob").unwrap();
    assert_eq!(state.pending_unacked_out_seq, Some(5));
    assert_eq!(
        state.pending_content,
        Some(PendingOtpContent::EndNotice),
        "the notice occupies the gate like any other spend, and survives a restart there"
    );
    assert!(state.pending_end_notice);
    let recovered: Vec<(String, u64, PendingOtpContent)> = loaded
        .pending_sends()
        .map(|(n, s, c)| (n.to_string(), s, c.clone()))
        .collect();
    assert_eq!(
        recovered,
        vec![("alice-bob".to_string(), 5, PendingOtpContent::EndNotice)],
        "recover_and_resend's own input yields it, so the reconnect retry finds it"
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-309
#[test]
fn reset_for_new_pad_zeroes_every_counter_and_remnant_of_the_old_pad() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.record_sent("alice-bob", 7, PendingOtpContent::Text { channel: None }, Some([1; 32]));
    store.record_received("alice-bob", 0);
    store.record_last_received_ack("alice-bob", 0, [2; 32]);
    store.mark_end_requested("alice-bob");

    store.reset_for_new_pad("alice-bob", Some([9; 32]));

    let state = store.get("alice-bob").unwrap();
    assert!(state.provisioned);
    assert_eq!(state.installed_pad_digest, Some([9; 32]));
    assert_eq!(
        state.next_out_seq, 0,
        "the new pad is a new stream - stale counters would silently drop its every message"
    );
    assert_eq!(state.next_expected_in_seq, 0);
    assert_eq!(state.pending_unacked_out_seq, None);
    assert_eq!(state.pending_content, None);
    assert_eq!(
        state.last_received_ack, None,
        "an old pad's recorded proof must never answer a new pad's sequence"
    );
    assert!(!state.pending_end_notice);
    std::fs::remove_file(&path).ok();
}

/// A store written before this field existed has no such trailing columns
/// at all; loading one must mean "nothing to re-ack", not a parse failure
/// that would discard the rest of that line's state.
///
/// @requirement AC-304
#[test]
fn a_line_written_before_last_received_ack_existed_still_loads() {
    let path = temp_store_path();
    std::fs::write(&path, "alice-bob\t1\t2\t3\t4\tT\t7\n").unwrap();
    let store = OtpStore::load(&path).unwrap();
    let state = store.get("alice-bob").unwrap();
    assert_eq!(state.last_received_ack, None);
    assert_eq!(store.ack_to_resend("alice-bob", 3), None);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Content sends staged awaiting the peer's acceptance (AC-316)
// ---------------------------------------------------------------------

/// @requirement AC-316
#[test]
fn a_staged_content_send_survives_save_and_load_in_its_own_sibling_file() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.stage_content_send(7, "alice-bob", PathBuf::from("/tmp/otp-voice-plain-123"));
    store.save().unwrap();

    // Reloaded, because the whole point is surviving a restart.
    let loaded = OtpStore::load(&path).unwrap();
    let staged: Vec<(u64, String, PathBuf)> = loaded
        .content_sends()
        .map(|(id, t)| (id, t.contact_name.clone(), t.path.clone()))
        .collect();
    assert_eq!(
        staged,
        vec![(7, "alice-bob".to_string(), PathBuf::from("/tmp/otp-voice-plain-123"))]
    );

    // It lives in its own sibling file, genuinely separate from the main
    // store's per-contact lines.
    let sibling = path.with_file_name(format!(
        "{}.pending_content",
        path.file_name().unwrap().to_string_lossy()
    ));
    assert!(sibling.is_file(), "staged content sends persist to their own file");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&sibling).ok();
}

/// @requirement AC-316
#[test]
fn taking_a_staged_content_send_clears_it_and_reports_absence_afterward() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.stage_content_send(3, "alice-bob", PathBuf::from("/tmp/x"));
    store.stage_content_send(4, "alice-carol", PathBuf::from("/tmp/y"));

    let taken = store.take_content_send(3).expect("it was staged");
    assert_eq!(taken.contact_name, "alice-bob");
    assert!(store.take_content_send(3).is_none(), "a second take finds nothing");

    let remaining: Vec<u64> = store.content_sends().map(|(id, _)| id).collect();
    assert_eq!(remaining, vec![4], "taking one must not disturb another contact's own");
}

/// A store with no sibling file at all (every store predating this
/// feature) must load as "nothing staged", not a parse failure that would
/// discard the rest of the store.
///
/// @requirement AC-316
#[test]
fn a_store_with_no_pending_content_sibling_file_loads_with_nothing_staged() {
    let path = temp_store_path();
    std::fs::write(&path, "alice-bob\t1\t2\t3\t4\tT\t7\n").unwrap();
    let store = OtpStore::load(&path).unwrap();
    assert_eq!(store.content_sends().count(), 0);
    std::fs::remove_file(&path).ok();
}

/// The store is replaced by rename, never truncated and refilled in place:
/// a crash between those two steps used to leave an empty file, which
/// loads as "every counter at zero, no gate armed" - the one state that
/// makes the very next send permanently desync the pair. A rename swaps
/// the inode; an in-place truncate keeps it.
///
/// @requirement TB-285
#[cfg(unix)]
#[test]
fn save_replaces_the_store_by_rename_never_truncating_it_in_place() {
    use std::os::unix::fs::MetadataExt;
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.save().unwrap();
    let before = std::fs::metadata(&path).unwrap().ino();

    store.record_sent("alice-bob", 4, PendingOtpContent::Text { channel: None }, None);
    store.stage_content_send(7, "alice-bob", PathBuf::from("/tmp/staged.pcm"));
    store.save().unwrap();

    let after = std::fs::metadata(&path).unwrap().ino();
    assert_ne!(
        before, after,
        "a save must land as a fresh file renamed into place, so the old contents \
         stay whole until the new ones are entirely on disk"
    );
    let staged = PathBuf::from(format!("{}.new", path.display()));
    assert!(!staged.exists(), "the staging sibling is consumed by the rename");
    let sibling_staged = PathBuf::from(format!("{}.pending_content.new", path.display()));
    assert!(!sibling_staged.exists(), "and so is the content-sends file's");

    let loaded = OtpStore::load(&path).unwrap();
    assert_eq!(loaded.get("alice-bob").unwrap().pending_unacked_out_seq, Some(4));
    assert_eq!(loaded.content_sends().count(), 1);

    std::fs::remove_file(&path).ok();
    std::fs::remove_file(format!("{}.pending_content", path.display())).ok();
}

/// The proof written ahead with an intent, and a spend parked for later
/// promotion with its own, both survive a restart - they are the only
/// record of what a promoted orphan's acknowledgement must match.
///
/// @requirement TB-291
#[test]
fn an_intent_proof_and_a_parked_spend_round_trip_through_save_and_load() {
    let path = temp_store_path();
    let mut store = OtpStore::new_empty(path.clone());
    store.mark_provisioned("alice-bob");
    store.set_encrypt_intent_with_proof(
        "alice-bob",
        PendingOtpContent::Text { channel: None },
        Some([7; 32]),
    );
    store.save().unwrap();
    let loaded = OtpStore::load(&path).unwrap();
    assert_eq!(loaded.encrypt_intent_proof("alice-bob"), Some([7; 32]));

    // Parked: the intent and its proof move together, and hold new seals.
    store.defer_encrypt_intent("alice-bob");
    assert!(store.encrypt_in_flight("alice-bob"), "a parked spend holds every new seal");
    assert_eq!(store.encrypt_intent_proof("alice-bob"), None, "the intent slot is free again");
    store.save().unwrap();
    let mut loaded = OtpStore::load(&path).unwrap();
    assert!(loaded.encrypt_in_flight("alice-bob"));
    assert_eq!(
        loaded.take_deferred_spend("alice-bob"),
        Some((PendingOtpContent::Text { channel: None }, Some([7; 32]))),
        "promotion gets the very proof the intent recorded"
    );
    assert!(!loaded.encrypt_in_flight("alice-bob"));

    std::fs::remove_file(&path).ok();
    std::fs::remove_file(format!("{}.pending_content", path.display())).ok();
}
