use aloo::crypto::{self, KeyPair, RSA_PER_MSG_KEY_BITS};
use aloo::proto::{ClientMessage, UserId};
use aloo::rekey::{
    generate_and_sign_rotation, rotation_signing_payload, sign_rotation, verify_and_parse_rotation,
    verify_rotation, verify_with_fallback, OwnKeys, QueuedOutbound, RemoteKeys, ResumeVerification,
    KEY_RETENTION,
};
use rsa::traits::PublicKeyParts;

// Tests that call `OwnKeys::rotate_for_peer`/`rotate_and_build_message` or
// `generate_and_sign_rotation` directly perform a real RSA-4096 keygen
// (`RSA_PER_MSG_KEY_BITS`) - observed taking 60s+ *each* in this pure-Rust,
// non-hardware-accelerated environment, with no way to speed up a single
// keygen via test parallelism. They're tagged `#[ignore]` so a plain
// `cargo test` (and this file's other 16, genuinely fast tests - signing,
// `RemoteKeys`' pure state machine, decrypt against an *unrotated*
// bootstrap key) stays fast; run them explicitly with
// `cargo test --test rekey_test -- --ignored` (add `--test-threads=1` or
// `2` too - many of these running concurrently is what previously drove
// this environment to an OOM SIGKILL).

// ---------------------------------------------------------------------
// rotation_signing_payload / sign_rotation / verify_rotation
// ---------------------------------------------------------------------

/// @requirement AC-044
#[test]
fn verify_rotation_accepts_a_valid_signature() {
    let signer = KeyPair::generate().unwrap();
    let new_key_der = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_key_der.public).unwrap();
    let sig = sign_rotation(&signer.private, UserId(7), &new_der).unwrap();
    assert!(verify_rotation(&signer.public, UserId(7), &new_der, &sig));
}

/// @requirement TB-069
#[test]
fn verify_rotation_rejects_replay_against_a_different_recipient() {
    let signer = KeyPair::generate().unwrap();
    let new_key_der = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_key_der.public).unwrap();
    // signed for peer 7...
    let sig = sign_rotation(&signer.private, UserId(7), &new_der).unwrap();
    // ...must not verify when replayed as if addressed to peer 8.
    assert!(!verify_rotation(&signer.public, UserId(8), &new_der, &sig));
}

/// @requirement AC-044
#[test]
fn verify_rotation_rejects_tampered_key_bytes() {
    let signer = KeyPair::generate().unwrap();
    let new_key_der = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_key_der.public).unwrap();
    let sig = sign_rotation(&signer.private, UserId(1), &new_der).unwrap();
    let mut tampered = new_der.clone();
    tampered[0] ^= 0xFF;
    assert!(!verify_rotation(&signer.public, UserId(1), &tampered, &sig));
}

/// @requirement TB-068
#[test]
fn rotation_signing_payload_differs_by_recipient() {
    let der = b"some-der-bytes".to_vec();
    assert_ne!(rotation_signing_payload(UserId(1), &der), rotation_signing_payload(UserId(2), &der));
}

/// @requirement TB-070
#[test]
fn verify_and_parse_rotation_returns_a_usable_key_on_success() {
    let signer = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let sig = sign_rotation(&signer.private, UserId(3), &new_der).unwrap();

    let parsed = verify_and_parse_rotation(&signer.public, UserId(3), &new_der, &sig)
        .expect("valid rotation should parse");
    let blocks = crypto::encrypt_chunked(&parsed, b"hello via rotated key").unwrap();
    let out = crypto::decrypt_chunked(&new_kp.private, &blocks).unwrap();
    assert_eq!(out, b"hello via rotated key");
}

/// @requirement AC-044, TB-070
#[test]
fn verify_and_parse_rotation_returns_none_on_bad_signature() {
    let signer = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    assert!(verify_and_parse_rotation(&signer.public, UserId(3), &new_der, &[1, 2, 3]).is_none());
}

// ---------------------------------------------------------------------
// verify_with_fallback / ResumeVerification (docs/PROTOCOL.md §12.6 - the
// continuity/resume mechanism, entirely pure decision logic, no keygen
// involved so none of these need #[ignore].)
// ---------------------------------------------------------------------

/// @requirement TB-096
#[test]
fn fallback_prefers_the_live_key_when_it_verifies() {
    let live = KeyPair::generate().unwrap();
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let sig = sign_rotation(&live.private, UserId(1), &new_der).unwrap();

    let result = verify_with_fallback(Some(&live.public), Some(&continuity.public), UserId(1), &new_der, &sig);
    match result {
        ResumeVerification::Live(k) => assert_eq!(crypto::public_key_to_der(&k).unwrap(), new_der),
        other => panic!("expected Live, got {other:?}"),
    }
}

/// @requirement TB-096
#[test]
fn fallback_falls_through_to_continuity_when_live_check_fails() {
    let wrong_live = KeyPair::generate().unwrap();
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    // signed with the continuity key, not the (unrelated) live one - this
    // is exactly the reconnect/resume shape: the sender's fresh bootstrap
    // key (whatever `wrong_live` stands in for here) has nothing to do
    // with the persisted continuity key they're actually resuming with.
    let sig = sign_rotation(&continuity.private, UserId(1), &new_der).unwrap();

    let result =
        verify_with_fallback(Some(&wrong_live.public), Some(&continuity.public), UserId(1), &new_der, &sig);
    match result {
        ResumeVerification::Resumed(k) => assert_eq!(crypto::public_key_to_der(&k).unwrap(), new_der),
        other => panic!("expected Resumed, got {other:?}"),
    }
}

/// @requirement AC-050, TB-096
#[test]
fn fallback_verifies_via_continuity_when_there_is_no_live_key_at_all() {
    // the common real case: a peer just seen for the first time this
    // connection (via UserJoined) has no live-registered rotation state
    // yet at all - `live_trusted` is `None`, not just "wrong".
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let sig = sign_rotation(&continuity.private, UserId(1), &new_der).unwrap();

    let result = verify_with_fallback(None, Some(&continuity.public), UserId(1), &new_der, &sig);
    assert!(matches!(result, ResumeVerification::Resumed(_)));
}

/// @requirement TB-097
#[test]
fn fallback_fails_when_neither_anchor_is_available() {
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let unrelated = KeyPair::generate().unwrap();
    let sig = sign_rotation(&unrelated.private, UserId(1), &new_der).unwrap();

    assert_eq!(verify_with_fallback(None, None, UserId(1), &new_der, &sig), ResumeVerification::Failed);
}

/// @requirement TB-097
#[test]
fn fallback_fails_when_both_anchors_are_present_but_neither_verifies() {
    let live = KeyPair::generate().unwrap();
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let forger = KeyPair::generate().unwrap(); // neither live's nor continuity's key
    let sig = sign_rotation(&forger.private, UserId(1), &new_der).unwrap();

    let result = verify_with_fallback(Some(&live.public), Some(&continuity.public), UserId(1), &new_der, &sig);
    assert_eq!(result, ResumeVerification::Failed);
}

/// @requirement TB-097
#[test]
fn fallback_fails_when_live_is_none_and_continuity_check_fails() {
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let forger = KeyPair::generate().unwrap();
    let sig = sign_rotation(&forger.private, UserId(1), &new_der).unwrap();

    assert_eq!(
        verify_with_fallback(None, Some(&continuity.public), UserId(1), &new_der, &sig),
        ResumeVerification::Failed
    );
}

/// @requirement TB-069
#[test]
fn fallback_does_not_verify_continuity_signature_replayed_against_a_different_recipient() {
    // the same `to`-binding property `verify_rotation` already guarantees
    // (rotation_signing_payload_differs_by_recipient) must hold through
    // the fallback path too - a resume signed for peer 1 must not verify
    // as if addressed to peer 2, even via the continuity anchor.
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let sig = sign_rotation(&continuity.private, UserId(1), &new_der).unwrap();

    assert_eq!(
        verify_with_fallback(None, Some(&continuity.public), UserId(2), &new_der, &sig),
        ResumeVerification::Failed
    );
}

/// @requirement TB-097
#[test]
fn fallback_rejects_tampered_new_key_bytes_via_either_anchor() {
    let live = KeyPair::generate().unwrap();
    let continuity = KeyPair::generate().unwrap();
    let new_kp = KeyPair::generate().unwrap();
    let new_der = crypto::public_key_to_der(&new_kp.public).unwrap();
    let sig = sign_rotation(&continuity.private, UserId(1), &new_der).unwrap();
    let mut tampered = new_der.clone();
    tampered[0] ^= 0xFF;

    assert_eq!(
        verify_with_fallback(Some(&live.public), Some(&continuity.public), UserId(1), &tampered, &sig),
        ResumeVerification::Failed
    );
}

/// @requirement AC-050, TB-098
#[test]
fn fallback_a_self_reasserted_key_verifies_the_same_way_as_a_freshly_rotated_one() {
    // the actual resume shape main.rs uses: the persisted continuity
    // *private* key signs its own matching public key (proof of
    // possession bound to the recipient), rather than generating a brand
    // new keypair the way an ordinary in-session rotation does.
    let continuity = KeyPair::generate().unwrap();
    let self_der = crypto::public_key_to_der(&continuity.public).unwrap();
    let sig = sign_rotation(&continuity.private, UserId(5), &self_der).unwrap();

    let result = verify_with_fallback(None, Some(&continuity.public), UserId(5), &self_der, &sig);
    assert!(matches!(result, ResumeVerification::Resumed(_)));
}

// ---------------------------------------------------------------------
// OwnKeys
// ---------------------------------------------------------------------

/// @requirement TB-075
#[test]
fn decrypt_from_uses_bootstrap_key_before_any_rotation() {
    let bootstrap = KeyPair::generate().unwrap();
    let bootstrap_public = bootstrap.public.clone();
    let own = OwnKeys::new(bootstrap.private);

    let blocks = crypto::encrypt_chunked(&bootstrap_public, b"first ever message").unwrap();
    assert_eq!(own.decrypt_from(UserId(1), &blocks).as_deref(), Some(b"first ever message".as_slice()));
}

/// @requirement TB-071
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn rotate_for_peer_signs_with_bootstrap_on_first_rotation() {
    let bootstrap = KeyPair::generate().unwrap();
    let bootstrap_public = bootstrap.public.clone();
    let mut own = OwnKeys::new(bootstrap.private);

    let (new_der, sig) = own.rotate_for_peer(UserId(1)).unwrap();
    assert!(verify_rotation(&bootstrap_public, UserId(1), &new_der, &sig));
    assert_eq!(own.current_public_der_for(UserId(1)), Some(new_der.as_slice()));
}

/// @requirement TB-072
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn rotate_for_peer_generates_keys_at_the_rsa_per_msg_key_size() {
    // the bootstrap key itself may be whatever size the caller sourced it
    // at (main.rs sources it at RSA_PER_MSG_KEY_BITS too, but OwnKeys
    // doesn't care) - it's every key `rotate_for_peer` *generates* that
    // must be 4096 bits, larger than this app's usual 2048-bit default.
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let (new_der, _) = own.rotate_for_peer(UserId(1)).unwrap();
    let new_public = crypto::public_key_from_der(&new_der).unwrap();
    assert_eq!(new_public.size() * 8, RSA_PER_MSG_KEY_BITS);
}

// ---------------------------------------------------------------------
// generate_and_sign_rotation / OwnKeys::install_rotated_key
//
// `rotate_for_peer` is implemented in terms of these two - main.rs's
// `spawn_rotation_worker` calls them separately instead (keygen with no
// lock held, then a brief locked call to install the result), so they're
// exercised directly here too, not just indirectly through `rotate_for_peer`.
// ---------------------------------------------------------------------

/// @requirement TB-072, TB-074
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn generate_and_sign_rotation_produces_a_verifiable_4096_bit_key() {
    let old = KeyPair::generate().unwrap();
    let (new_der, signature, new_private) = generate_and_sign_rotation(&old.private, UserId(1)).unwrap();

    assert!(verify_rotation(&old.public, UserId(1), &new_der, &signature));

    let new_public = crypto::public_key_from_der(&new_der).unwrap();
    assert_eq!(new_public.size() * 8, RSA_PER_MSG_KEY_BITS);

    // the returned private key must actually match the returned public der
    let blocks = crypto::encrypt_chunked(&new_public, b"generated off to the side").unwrap();
    let out = crypto::decrypt_chunked(&new_private, &blocks).unwrap();
    assert_eq!(out, b"generated off to the side");
}

/// @requirement TB-074
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn install_rotated_key_alone_updates_state_the_same_way_rotate_for_peer_does() {
    let bootstrap = KeyPair::generate().unwrap();
    let bootstrap_public = bootstrap.public.clone();
    let mut own = OwnKeys::new(bootstrap.private);

    // simulate exactly what spawn_rotation_worker does: read the key to
    // sign against, generate+sign with no OwnKeys access at all, then only
    // touch OwnKeys again for the cheap bookkeeping step.
    let old_private = own.current_private_for(UserId(1));
    let (new_der, signature, new_private) = generate_and_sign_rotation(&old_private, UserId(1)).unwrap();
    assert!(verify_rotation(&bootstrap_public, UserId(1), &new_der, &signature));

    assert_eq!(own.current_public_der_for(UserId(1)), None, "not installed yet");
    own.install_rotated_key(UserId(1), new_private, new_der.clone());
    assert_eq!(own.current_public_der_for(UserId(1)), Some(new_der.as_slice()));

    let new_public = crypto::public_key_from_der(&new_der).unwrap();
    let blocks = crypto::encrypt_chunked(&new_public, b"installed separately").unwrap();
    assert_eq!(own.decrypt_from(UserId(1), &blocks).as_deref(), Some(b"installed separately".as_slice()));
}

/// @requirement TB-071
#[test]
#[ignore = "real RSA-4096 keygen x2, 60s+ each in this environment - see module doc"]
fn rotate_for_peer_signs_second_rotation_with_the_first_per_peer_key() {
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let (first_der, _) = own.rotate_for_peer(UserId(1)).unwrap();
    let first_public = crypto::public_key_from_der(&first_der).unwrap();

    let (second_der, second_sig) = own.rotate_for_peer(UserId(1)).unwrap();
    // must verify against the *first* per-peer key, not the bootstrap key
    assert!(verify_rotation(&first_public, UserId(1), &second_der, &second_sig));
}

/// @requirement TB-073
#[test]
#[ignore = "real RSA-4096 keygen x2, 60s+ each in this environment - see module doc"]
fn rotate_for_peer_is_independent_per_peer() {
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let (der_for_bob, _) = own.rotate_for_peer(UserId(1)).unwrap();
    let (der_for_carol, _) = own.rotate_for_peer(UserId(2)).unwrap();
    assert_ne!(der_for_bob, der_for_carol);
    assert_eq!(own.current_public_der_for(UserId(1)), Some(der_for_bob.as_slice()));
    assert_eq!(own.current_public_der_for(UserId(2)), Some(der_for_carol.as_slice()));
}

/// @requirement TB-075
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn decrypt_from_works_with_the_newly_rotated_key() {
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let (new_der, _) = own.rotate_for_peer(UserId(1)).unwrap();
    let new_public = crypto::public_key_from_der(&new_der).unwrap();
    let blocks = crypto::encrypt_chunked(&new_public, b"after rotation").unwrap();
    assert_eq!(own.decrypt_from(UserId(1), &blocks).as_deref(), Some(b"after rotation".as_slice()));
}

/// @requirement TB-075
#[test]
#[ignore = "real RSA-4096 keygen x2, 60s+ each in this environment - see module doc"]
fn decrypt_from_falls_back_to_a_recently_retired_key() {
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let (first_der, _) = own.rotate_for_peer(UserId(1)).unwrap();
    let first_public = crypto::public_key_from_der(&first_der).unwrap();
    // a message encrypted under the first per-peer key, but not decrypted
    // until after we've already rotated once more (simulating two queued
    // messages flushed under the same key, or simple reordering).
    let blocks = crypto::encrypt_chunked(&first_public, b"queued before second rotation").unwrap();

    own.rotate_for_peer(UserId(1)).unwrap(); // now `first_der`'s key is retired, not current

    assert_eq!(
        own.decrypt_from(UserId(1), &blocks).as_deref(),
        Some(b"queued before second rotation".as_slice()),
        "a recently-retired key must still be tried"
    );
}

/// @requirement TB-075
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn decrypt_from_still_falls_back_to_bootstrap_after_rotating_for_a_peer() {
    let bootstrap = KeyPair::generate().unwrap();
    let bootstrap_public = bootstrap.public.clone();
    let mut own = OwnKeys::new(bootstrap.private);

    own.rotate_for_peer(UserId(1)).unwrap();

    // a message from a *different*, not-yet-rotated peer, still under the
    // shared bootstrap key.
    let blocks = crypto::encrypt_chunked(&bootstrap_public, b"from a peer who hasn't rotated").unwrap();
    assert_eq!(
        own.decrypt_from(UserId(2), &blocks).as_deref(),
        Some(b"from a peer who hasn't rotated".as_slice())
    );
}

/// @requirement TB-116
#[test]
fn candidate_privates_for_lists_current_retained_and_bootstrap_in_priority_order() {
    // Deliberately avoids `rotate_for_peer`/`generate_and_sign_rotation`
    // (real RSA-4096 keygen, see module doc) - `install_rotated_key` takes
    // already-generated keys, so plain 2048-bit `KeyPair::generate()` is
    // enough to exercise the candidate-list ordering without the slow path.
    let bootstrap = KeyPair::generate().unwrap();
    let bootstrap_public = bootstrap.public.clone();
    let mut own = OwnKeys::new(bootstrap.private);

    let retained_kp = KeyPair::generate().unwrap();
    let retained_public = retained_kp.public.clone();
    let retained_der = crypto::public_key_to_der(&retained_public).unwrap();
    own.install_rotated_key(UserId(1), retained_kp.private, retained_der);

    let current_kp = KeyPair::generate().unwrap();
    let current_public = current_kp.public.clone();
    let current_der = crypto::public_key_to_der(&current_public).unwrap();
    own.install_rotated_key(UserId(1), current_kp.private, current_der);

    let candidates = own.candidate_privates_for(UserId(1));
    assert_eq!(candidates.len(), 3, "current + one retained + bootstrap");

    let current_blocks = crypto::encrypt_chunked(&current_public, b"under current key").unwrap();
    assert_eq!(
        crypto::decrypt_chunked(&candidates[0], &current_blocks).unwrap(),
        b"under current key",
        "current key must be first"
    );

    let retained_blocks = crypto::encrypt_chunked(&retained_public, b"under retained key").unwrap();
    assert_eq!(
        crypto::decrypt_chunked(&candidates[1], &retained_blocks).unwrap(),
        b"under retained key",
        "retained key must be second"
    );

    let bootstrap_blocks = crypto::encrypt_chunked(&bootstrap_public, b"under bootstrap key").unwrap();
    assert_eq!(
        crypto::decrypt_chunked(&candidates[2], &bootstrap_blocks).unwrap(),
        b"under bootstrap key",
        "bootstrap key must be last"
    );
}

/// @requirement TB-116
#[test]
fn candidate_privates_for_an_untracked_peer_is_bootstrap_only() {
    let bootstrap = KeyPair::generate().unwrap();
    let own = OwnKeys::new(bootstrap.private);
    assert_eq!(own.candidate_privates_for(UserId(1)).len(), 1, "no per-peer state yet - bootstrap alone");
}

/// @requirement TB-076
#[test]
#[ignore = "real RSA-4096 keygen x11, 60s+ each in this environment - see module doc"]
fn retention_window_is_bounded_and_oldest_keys_eventually_become_undecryptable() {
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let (first_der, _) = own.rotate_for_peer(UserId(1)).unwrap();
    let first_public = crypto::public_key_from_der(&first_der).unwrap();
    let stale_blocks = crypto::encrypt_chunked(&first_public, b"very old message").unwrap();

    // rotate enough more times to push the first key out of the retention window
    for _ in 0..(KEY_RETENTION + 2) {
        own.rotate_for_peer(UserId(1)).unwrap();
    }

    assert!(
        own.decrypt_from(UserId(1), &stale_blocks).is_none(),
        "a key retired long enough ago should no longer decrypt (bounded retention)"
    );
}

/// @requirement TB-077
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - see module doc"]
fn rotate_and_build_message_produces_a_rotate_key_client_message_addressed_correctly() {
    let bootstrap = KeyPair::generate().unwrap();
    let mut own = OwnKeys::new(bootstrap.private);

    let msg = own.rotate_and_build_message(UserId(42)).unwrap();
    match msg {
        ClientMessage::RotateKey { to, new_public_key_der, signature } => {
            assert_eq!(to, UserId(42));
            assert!(!new_public_key_der.is_empty());
            assert!(!signature.is_empty());
        }
        other => panic!("expected RotateKey, got {other:?}"),
    }
}

/// @requirement TB-078
#[test]
fn current_public_der_for_is_none_before_any_rotation() {
    let bootstrap = KeyPair::generate().unwrap();
    let own = OwnKeys::new(bootstrap.private);
    assert_eq!(own.current_public_der_for(UserId(1)), None);
}

// ---------------------------------------------------------------------
// RemoteKeys
// ---------------------------------------------------------------------

/// @requirement TB-079
#[test]
fn untracked_peer_is_always_sendable() {
    let mut remote = RemoteKeys::new();
    assert!(remote.try_use(UserId(1)));
    assert!(remote.try_use(UserId(1)), "an untracked (Static) peer is never gated");
    assert!(!remote.is_tracked(UserId(1)));
}

/// @requirement TB-080
#[test]
fn tracked_peer_is_fresh_once_then_stale() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1)), "bootstrap key should be usable once");
    assert!(!remote.try_use(UserId(1)), "key must not be reused after one send");
}

/// @requirement TB-080
#[test]
fn track_is_idempotent_and_does_not_reset_freshness() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1)));
    remote.track(UserId(1)); // re-track, e.g. re-joining a channel
    assert!(!remote.try_use(UserId(1)), "re-tracking must not resurrect a stale key");
}

/// @requirement AC-045
#[test]
fn queued_messages_flush_in_fifo_order_on_rotation() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1))); // consume the initial fresh key

    remote.enqueue(UserId(1), QueuedOutbound::Direct { plaintext: "first".into() });
    remote.enqueue(UserId(1), QueuedOutbound::Channel { channel: "general".into(), plaintext: "second".into() });
    assert_eq!(remote.queue_len(UserId(1)), 2);

    let flushed = remote.on_rotated(UserId(1));
    assert_eq!(
        flushed,
        vec![
            QueuedOutbound::Direct { plaintext: "first".into() },
            QueuedOutbound::Channel { channel: "general".into(), plaintext: "second".into() },
        ]
    );
    assert_eq!(remote.queue_len(UserId(1)), 0, "queue must be drained, not just peeked");
}

/// @requirement TB-080
#[test]
fn on_rotated_marks_fresh_and_mark_used_consumes_it_again() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1)));

    let flushed = remote.on_rotated(UserId(1));
    assert!(flushed.is_empty());
    // the rotation made the key fresh again even with nothing queued
    assert!(remote.try_use(UserId(1)));

    // simulate a second rotation with something queued, batch-flushed and marked used
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(UserId(1), QueuedOutbound::Direct { plaintext: "queued".into() });
    let flushed = remote.on_rotated(UserId(1));
    assert_eq!(flushed.len(), 1);
    remote.mark_used(UserId(1));
    assert!(!remote.try_use(UserId(1)), "batch flush must consume freshness like any other send");
}

/// @requirement TB-081
#[test]
fn on_rotated_on_a_never_tracked_peer_starts_tracking_it() {
    let mut remote = RemoteKeys::new();
    assert!(!remote.is_tracked(UserId(9)));
    let flushed = remote.on_rotated(UserId(9));
    assert!(flushed.is_empty());
    assert!(remote.is_tracked(UserId(9)));
}

/// @requirement TB-081
#[test]
fn enqueue_on_untracked_peer_starts_tracking_it_as_stale() {
    let mut remote = RemoteKeys::new();
    remote.enqueue(UserId(5), QueuedOutbound::Direct { plaintext: "x".into() });
    assert!(remote.is_tracked(UserId(5)));
    assert!(!remote.try_use(UserId(5)), "a peer we just had to queue for should not appear fresh");
    assert_eq!(remote.queue_len(UserId(5)), 1);
}

/// @requirement AC-045
#[test]
fn full_lifecycle_track_use_queue_rotate_flush() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));

    // first message goes out immediately on the bootstrap key
    assert!(remote.try_use(UserId(1)));

    // two more typed while waiting for the peer's next key
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(UserId(1), QueuedOutbound::Direct { plaintext: "a".into() });
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(UserId(1), QueuedOutbound::Direct { plaintext: "b".into() });

    // the peer's rotation finally arrives: flush both at once
    let batch = remote.on_rotated(UserId(1));
    assert_eq!(batch.len(), 2);
    remote.mark_used(UserId(1));

    // and we're back to stale until the next rotation
    assert!(!remote.try_use(UserId(1)));
}
