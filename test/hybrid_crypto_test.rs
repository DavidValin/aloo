//! Tests for `KeyMode::PqHybrid` (`docs/PROTOCOL.md` §13): ML-DSA-87+RSA4096
//! signing, ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption.
//!
//! Every test that calls `crypto::pq::generate_bundle` does real RSA-4096
//! keygen (x2) plus ML-DSA-87/ML-KEM-1024 keygen, same cost class as
//! `crypto_test.rs`'s `generate_with_bits(RSA_PER_MSG_KEY_BITS)` test - so,
//! following the same convention, those are `#[ignore]`d and run via
//! `cargo slow`. The chunk-level tests need no bundle at all (just a raw
//! `[u8; 32]` key), so they stay fast and ungated.

use aloo::client::keymode_policy::can_address;
use aloo::crypto::pq::{
    decrypt_hybrid, decrypt_hybrid_chunk, encrypt_hybrid_chunk, encrypt_hybrid_for_one,
    ensure_bundle_at, generate_bundle, load_private_bundle, load_public_bundle,
    save_private_bundle, save_public_bundle, unwrap_key_for_stream, wrap_key_for_stream,
};
use aloo::proto::{self, KeyMode};
use aloo::client::keymode_policy::uses_byte_comparison_pinning;

// ---------------------------------------------------------------------
// Chunk-level (voice) primitives - fast, no bundle/keygen needed
// ---------------------------------------------------------------------

/// @requirement TB-128
#[test]
fn same_plaintext_produces_different_ciphertext_under_different_seq() {
    let k_data = [7u8; 32];
    let c0 = encrypt_hybrid_chunk(&k_data, 42, 0, b"pcm-chunk");
    let c1 = encrypt_hybrid_chunk(&k_data, 42, 1, b"pcm-chunk");
    assert_ne!(
        c0, c1,
        "different seq must produce a different nonce, hence different ciphertext"
    );
}

/// @requirement AC-083
#[test]
fn hybrid_voice_chunk_round_trips() {
    let k_data = [9u8; 32];
    let ciphertext = encrypt_hybrid_chunk(&k_data, 100, 5, b"raw pcm bytes");
    let plaintext =
        decrypt_hybrid_chunk(&k_data, 100, 5, &ciphertext).expect("decrypt should succeed");
    assert_eq!(plaintext, b"raw pcm bytes");
}

/// @requirement TB-128
#[test]
fn decrypting_a_chunk_with_the_wrong_seq_fails() {
    let k_data = [3u8; 32];
    let ciphertext = encrypt_hybrid_chunk(&k_data, 1, 0, b"pcm");
    assert!(
        decrypt_hybrid_chunk(&k_data, 1, 1, &ciphertext).is_none(),
        "wrong seq means wrong nonce, must not decrypt"
    );
}

/// @requirement TB-128
#[test]
fn decrypting_a_chunk_with_the_wrong_stream_id_fails() {
    let k_data = [3u8; 32];
    let ciphertext = encrypt_hybrid_chunk(&k_data, 1, 0, b"pcm");
    assert!(decrypt_hybrid_chunk(&k_data, 2, 0, &ciphertext).is_none());
}

/// @requirement TB-128
#[test]
fn decrypting_a_chunk_with_the_wrong_key_fails() {
    let k_data_a = [1u8; 32];
    let k_data_b = [2u8; 32];
    let ciphertext = encrypt_hybrid_chunk(&k_data_a, 1, 0, b"pcm");
    assert!(decrypt_hybrid_chunk(&k_data_b, 1, 0, &ciphertext).is_none());
}

// ---------------------------------------------------------------------
// can_address / uses_byte_comparison_pinning - fast, pure predicates
// ---------------------------------------------------------------------

/// @requirement AC-082
#[test]
fn a_non_pq_hybrid_sender_cannot_address_a_pq_hybrid_recipient() {
    assert!(
        !can_address(KeyMode::PqHybrid, KeyMode::Rsa),
        "an rsa sender has no ML-DSA-87/RSA-sign identity"
    );
    assert!(!can_address(KeyMode::PqHybrid, KeyMode::Password));
    assert!(!can_address(KeyMode::PqHybrid, KeyMode::None));
    assert!(!can_address(KeyMode::PqHybrid, KeyMode::PerMessage));
    assert!(
        can_address(KeyMode::PqHybrid, KeyMode::PqHybrid),
        "a pq_hybrid sender can address a pq_hybrid recipient"
    );
}

/// @requirement AC-082
#[test]
fn every_sender_can_address_a_non_pq_hybrid_recipient() {
    for recipient in [
        KeyMode::Rsa,
        KeyMode::Password,
        KeyMode::None,
        KeyMode::PerMessage,
    ] {
        for sender in [
            KeyMode::Rsa,
            KeyMode::Password,
            KeyMode::None,
            KeyMode::PerMessage,
            KeyMode::PqHybrid,
        ] {
            assert!(
                can_address(recipient, sender),
                "RSA-OAEP needs no sender identity at all"
            );
        }
    }
}

/// @requirement AC-081
#[test]
fn key_mode_pq_hybrid_participates_in_byte_comparison_pinning_like_rsa() {
    assert!(uses_byte_comparison_pinning(KeyMode::Rsa));
    assert!(uses_byte_comparison_pinning(KeyMode::Password));
    assert!(uses_byte_comparison_pinning(KeyMode::PqHybrid));
    assert!(
        !uses_byte_comparison_pinning(KeyMode::PerMessage),
        "PerMessage has its own signature-based §12.6 mechanism"
    );
    assert!(
        !uses_byte_comparison_pinning(KeyMode::None),
        "None has no continuity mechanism at all, by design"
    );
}

/// @requirement AC-081
#[test]
fn pq_hybrid_tag_is_the_shield() {
    assert_eq!(KeyMode::PqHybrid.label(), "\u{1F6E1}\u{FE0F} PQH");
    assert_eq!(
        KeyMode::PqHybrid.format_with_name("alice"),
        "alice \u{1F6E1}\u{FE0F} PQH"
    );
}

// ---------------------------------------------------------------------
// Full bundle round trips - real keygen, #[ignore]d (see module doc)
// ---------------------------------------------------------------------

/// @requirement AC-079
#[test]
#[ignore = "real ML-DSA-87/ML-KEM-1024/RSA-4096 x2 keygen, several seconds - see module doc, run with cargo slow"]
fn encrypt_then_decrypt_hybrid_round_trips() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let msg = b"a message long enough to span more than one internal AES block, for good measure";
    let envelope = encrypt_hybrid_for_one(&alice_private, &bob_public, msg).expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode envelope");

    let out =
        decrypt_hybrid(&bob_private, &alice_public, &blob).expect("decrypt+verify should succeed");
    assert_eq!(out, msg);
}

/// @requirement AC-079, TB-131
#[test]
#[ignore = "real ML-DSA-87/ML-KEM-1024/RSA-4096 x2 keygen, several seconds - see module doc, run with cargo slow"]
fn encrypt_hybrid_for_one_round_trips_via_wire_encoding() {
    // Exercises the exact path `session::encrypt_hybrid_envelope_for`/
    // `decrypt_hybrid` use: the recipient's public bundle carried opaquely
    // as bincode-encoded bytes (as it would sit in `UserInfo.public_key_der`),
    // and the hybrid blob carried as `Envelope.blocks`' single element.
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let bob_public_der = proto::encode(&bob_public).expect("encode bob's public bundle");
    let bob_public_decoded: aloo::crypto::pq::PqPublicBundle =
        proto::decode(&bob_public_der).expect("decode");

    let envelope = encrypt_hybrid_for_one(
        &alice_private,
        &bob_public_decoded,
        b"hello via wire encoding",
    )
    .expect("encrypt");
    let block = proto::encode(&envelope).expect("encode");
    assert_eq!(
        vec![block.clone()].len(),
        1,
        "the whole hybrid blob is one Envelope.blocks element"
    );

    let out = decrypt_hybrid(&bob_private, &alice_public, &block).expect("decrypt");
    assert_eq!(out, b"hello via wire encoding");
}

/// @requirement AC-080
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn tampered_ciphertext_is_rejected() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");
    let _ = &alice_public;

    let mut envelope =
        encrypt_hybrid_for_one(&alice_private, &bob_public, b"original").expect("encrypt");
    envelope.ciphertext[0] ^= 0xFF;
    let blob = proto::encode(&envelope).expect("encode");

    assert!(
        decrypt_hybrid(&bob_private, &alice_public, &blob).is_none(),
        "a flipped ciphertext byte must fail the AEAD tag"
    );
}

/// @requirement AC-080
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn tampered_signature_is_rejected() {
    // A tampered AEAD ciphertext is caught by AES-256-GCM's own tag before
    // signatures are ever checked (see `tampered_ciphertext_is_rejected`).
    // To exercise the *signature* check specifically, decrypt correctly
    // (mallory re-wraps the same plaintext for herself) then substitute a
    // signature that won't verify against alice's claimed identity - the
    // same effect a bit-flipped signature field would have.
    let (alice_public, _alice_private) = generate_bundle().expect("alice bundle");
    let (mallory_public, mallory_private) = generate_bundle().expect("mallory bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    // Mallory signs and sends her own envelope, but claims to be alice by
    // having bob verify against alice's public bundle instead of hers.
    let envelope =
        encrypt_hybrid_for_one(&mallory_private, &bob_public, b"pretend this is from alice")
            .expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode");

    assert!(
        decrypt_hybrid(&bob_private, &alice_public, &blob).is_none(),
        "a message signed by mallory must not verify against alice's public bundle"
    );
    let _ = mallory_public;
}

/// @requirement AC-080
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn wrong_sender_public_bundle_is_rejected() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (carol_public, _carol_private) = generate_bundle().expect("carol bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let envelope =
        encrypt_hybrid_for_one(&alice_private, &bob_public, b"from alice").expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode");

    // bob mistakenly verifies against carol's public bundle instead of alice's.
    assert!(decrypt_hybrid(&bob_private, &carol_public, &blob).is_none());
    let _ = alice_public;
}

/// @requirement AC-080
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn wrong_recipient_cannot_decrypt() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, _bob_private) = generate_bundle().expect("bob bundle");
    let (mallory_public, mallory_private) = generate_bundle().expect("mallory bundle");
    let _ = mallory_public;

    let envelope =
        encrypt_hybrid_for_one(&alice_private, &bob_public, b"only for bob").expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode");

    assert!(
        decrypt_hybrid(&mallory_private, &alice_public, &blob).is_none(),
        "mallory holds neither bob's ML-KEM-1024 nor RSA-4096-enc private key"
    );
}

/// @requirement TB-127
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn wrap_key_for_and_unwrap_key_round_trip() {
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");
    let k_data = aloo::crypto::pq::fresh_data_key();

    let (kem_ciphertext, wrapped_key, wrapped_key_rsa) =
        aloo::crypto::pq::wrap_key_for(&bob_public, &k_data).expect("wrap");
    let recovered = aloo::crypto::pq::unwrap_key(
        &bob_private,
        &kem_ciphertext,
        &wrapped_key,
        &wrapped_key_rsa,
    )
    .expect("unwrap");

    assert_eq!(recovered, k_data);
}

/// @requirement AC-083, TB-129
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn wrap_key_for_stream_and_unwrap_key_for_stream_round_trip() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let stream_id = 4242u64;
    let k_data = aloo::crypto::pq::fresh_data_key();
    let setup = wrap_key_for_stream(&alice_private, &bob_public, stream_id, &k_data)
        .expect("wrap for stream");

    let recovered = unwrap_key_for_stream(&bob_private, &alice_public, stream_id, &setup)
        .expect("unwrap+verify should succeed");
    assert_eq!(recovered, k_data);
}

/// @requirement AC-080, TB-129
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn unwrap_key_for_stream_rejects_a_tampered_commitment() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let stream_id = 1u64;
    let k_data = aloo::crypto::pq::fresh_data_key();
    let setup = wrap_key_for_stream(&alice_private, &bob_public, stream_id, &k_data)
        .expect("wrap for stream");

    // Bob receives the setup but for the wrong stream_id (e.g. a replayed
    // key-setup against a different recording) - the signed commitment
    // binds stream_id, so this must fail to verify.
    assert!(unwrap_key_for_stream(&bob_private, &alice_public, stream_id + 1, &setup).is_none());
}

/// @requirement AC-084, TB-130
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn save_and_load_bundle_files_roundtrip() {
    let (public, private) = generate_bundle().expect("keygen");
    let dir = std::env::temp_dir().join(format!("aloo-pq-hybrid-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let priv_path = dir.join("pq_hybrid");
    let pub_path = dir.join("pq_hybrid.pub");

    save_private_bundle(&private, &priv_path).expect("save private");
    save_public_bundle(&public, &pub_path).expect("save public");

    let loaded_private = load_private_bundle(&priv_path).expect("load private");
    let loaded_public = load_public_bundle(&pub_path).expect("load public");

    let envelope = encrypt_hybrid_for_one(&loaded_private, &loaded_public, b"round trip via files")
        .expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode");
    let out = decrypt_hybrid(&loaded_private, &loaded_public, &blob).expect("decrypt");
    assert_eq!(out, b"round trip via files");

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-130
#[test]
#[cfg(unix)]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn save_private_bundle_sets_owner_only_permissions_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let (_public, private) = generate_bundle().expect("keygen");
    let dir = std::env::temp_dir().join(format!("aloo-pq-hybrid-perm-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let priv_path = dir.join("pq_hybrid");

    save_private_bundle(&private, &priv_path).expect("save private");
    let mode = std::fs::metadata(&priv_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the private keybundle must be owner-only");

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement AC-086
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn ensure_bundle_at_generates_a_bundle_when_missing() {
    let dir =
        std::env::temp_dir().join(format!("aloo-ensure-bundle-missing-{}", std::process::id()));
    let pub_path = dir.join("gen.pub");
    let priv_path = dir.join("gen.priv");
    assert!(!pub_path.exists() && !priv_path.exists());

    ensure_bundle_at(&pub_path, &priv_path).expect("should generate and save");
    assert!(pub_path.is_file());
    assert!(priv_path.is_file());

    let public = load_public_bundle(&pub_path).expect("load public");
    let private = load_private_bundle(&priv_path).expect("load private");
    let envelope =
        encrypt_hybrid_for_one(&private, &public, b"self-addressed round trip").expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode");
    let out = decrypt_hybrid(&private, &public, &blob).expect("decrypt");
    assert_eq!(out, b"self-addressed round trip");

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-134
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn ensure_bundle_at_is_a_no_op_when_both_files_already_exist() {
    let dir = std::env::temp_dir().join(format!("aloo-ensure-bundle-noop-{}", std::process::id()));
    let pub_path = dir.join("gen.pub");
    let priv_path = dir.join("gen.priv");
    ensure_bundle_at(&pub_path, &priv_path).expect("first call generates");
    let pub_bytes_before = std::fs::read(&pub_path).unwrap();
    let priv_bytes_before = std::fs::read(&priv_path).unwrap();

    ensure_bundle_at(&pub_path, &priv_path).expect("second call should be a no-op");
    assert_eq!(
        std::fs::read(&pub_path).unwrap(),
        pub_bytes_before,
        "must not regenerate when both files exist"
    );
    assert_eq!(std::fs::read(&priv_path).unwrap(), priv_bytes_before);

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-134
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn ensure_bundle_at_regenerates_both_when_only_one_file_exists() {
    let dir =
        std::env::temp_dir().join(format!("aloo-ensure-bundle-partial-{}", std::process::id()));
    let pub_path = dir.join("gen.pub");
    let priv_path = dir.join("gen.priv");
    ensure_bundle_at(&pub_path, &priv_path).expect("first call generates");
    let pub_bytes_before = std::fs::read(&pub_path).unwrap();

    // Simulate the private half being deleted (e.g. by hand) - the
    // surviving public half must not be trusted as still matching whatever
    // gets generated next.
    std::fs::remove_file(&priv_path).unwrap();
    ensure_bundle_at(&pub_path, &priv_path).expect("should regenerate both");
    assert_ne!(
        std::fs::read(&pub_path).unwrap(),
        pub_bytes_before,
        "the public half must be regenerated too, not reused alone"
    );

    // The freshly (re)generated pair must actually work together.
    let public = load_public_bundle(&pub_path).expect("load public");
    let private = load_private_bundle(&priv_path).expect("load private");
    let envelope = encrypt_hybrid_for_one(&private, &public, b"still works after partial deletion")
        .expect("encrypt");
    let blob = proto::encode(&envelope).expect("encode");
    let out = decrypt_hybrid(&private, &public, &blob).expect("decrypt");
    assert_eq!(out, b"still works after partial deletion");

    std::fs::remove_dir_all(&dir).ok();
}
