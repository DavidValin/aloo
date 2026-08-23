use aloo::crypto::{
    CryptoError, KeyPair, RSA_KEY_BITS, RSA_PER_MSG_KEY_BITS, constant_time_eq, decrypt_chunked,
    encrypt_chunked, fingerprint, fingerprint_der, max_chunk_len, private_key_from_der,
    private_key_to_der, public_key_from_der, public_key_to_der, random_bytes, sign, verify,
};
use rand_core::OsRng;
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;

/// @requirement AC-040, AC-041
#[test]
fn encrypt_decrypt_roundtrip_short_message() {
    let kp = KeyPair::generate().expect("keygen");
    let msg = b"hello channel";
    let blocks = encrypt_chunked(&kp.public, msg).expect("encrypt");
    assert_eq!(blocks.len(), 1);
    let out = decrypt_chunked(&kp.private, &blocks).expect("decrypt");
    assert_eq!(out, msg);
}

/// @requirement AC-041, TB-052
#[test]
fn encrypt_decrypt_roundtrip_empty_message() {
    let kp = KeyPair::generate().expect("keygen");
    let blocks = encrypt_chunked(&kp.public, b"").expect("encrypt");
    let out = decrypt_chunked(&kp.private, &blocks).expect("decrypt");
    assert_eq!(out, b"");
}

/// @requirement AC-041, TB-051
#[test]
fn long_message_is_split_into_multiple_blocks_and_reassembled() {
    let kp = KeyPair::generate().expect("keygen");
    let chunk = max_chunk_len(&kp.public);
    // enough bytes to require at least 3 blocks
    let msg: Vec<u8> = (0..chunk * 2 + 37).map(|i| (i % 256) as u8).collect();
    let blocks = encrypt_chunked(&kp.public, &msg).expect("encrypt");
    assert!(
        blocks.len() >= 3,
        "expected multiple blocks, got {}",
        blocks.len()
    );
    let out = decrypt_chunked(&kp.private, &blocks).expect("decrypt");
    assert_eq!(out, msg);
}

/// @requirement AC-040
#[test]
fn wrong_key_cannot_decrypt() {
    let kp_a = KeyPair::generate().expect("keygen a");
    let kp_b = KeyPair::generate().expect("keygen b");
    let blocks = encrypt_chunked(&kp_a.public, b"secret for A only").expect("encrypt");
    let result = decrypt_chunked(&kp_b.private, &blocks);
    assert!(result.is_err());
}

/// @requirement TB-115
#[test]
fn encrypt_chunked_rejects_a_key_too_small_for_oaep() {
    // 128 bits -> a 16-byte modulus, well under the 66 bytes OAEP/SHA-256
    // needs (2 * 32-byte hash + 2), so max_chunk_len saturates to 0.
    let tiny = RsaPrivateKey::new(&mut OsRng, 128).expect("tiny keygen");
    let public = tiny.to_public_key();
    assert_eq!(max_chunk_len(&public), 0);

    let err = encrypt_chunked(&public, b"hi").unwrap_err();
    assert!(
        matches!(err, CryptoError::Encrypt(_)),
        "expected an Encrypt error, got {err:?}"
    );
}

/// @requirement TB-054
#[test]
fn public_key_der_roundtrip_preserves_usability() {
    let kp = KeyPair::generate().expect("keygen");
    let der = public_key_to_der(&kp.public).expect("to der");
    let restored = public_key_from_der(&der).expect("from der");
    let blocks = encrypt_chunked(&restored, b"via restored key").expect("encrypt");
    let out = decrypt_chunked(&kp.private, &blocks).expect("decrypt");
    assert_eq!(out, b"via restored key");
}

/// @requirement TB-054
#[test]
fn private_key_der_roundtrip_preserves_usability() {
    let kp = KeyPair::generate().expect("keygen");
    let der = private_key_to_der(&kp.private).expect("to der");
    let restored = private_key_from_der(&der).expect("from der");
    let blocks = encrypt_chunked(&kp.public, b"via restored private key").expect("encrypt");
    let out = decrypt_chunked(&restored, &blocks).expect("decrypt");
    assert_eq!(out, b"via restored private key");
}

/// @requirement TB-055
#[test]
fn private_key_from_der_rejects_garbage() {
    assert!(private_key_from_der(b"not a real der-encoded key").is_err());
}

/// @requirement TB-057
#[test]
fn fingerprint_is_stable_and_distinguishes_keys() {
    let kp1 = KeyPair::generate().expect("keygen 1");
    let kp2 = KeyPair::generate().expect("keygen 2");
    let fp1a = fingerprint(&kp1.public).unwrap();
    let fp1b = fingerprint(&kp1.public).unwrap();
    let fp2 = fingerprint(&kp2.public).unwrap();
    assert_eq!(fp1a, fp1b);
    assert_ne!(fp1a, fp2);
    assert_eq!(fp1a.len(), 64, "sha256 hex digest should be 64 chars");
}

/// @requirement TB-057
#[test]
fn fingerprint_der_matches_fingerprint_of_the_parsed_key() {
    let kp = KeyPair::generate().expect("keygen");
    let der = public_key_to_der(&kp.public).unwrap();
    assert_eq!(fingerprint_der(&der), fingerprint(&kp.public).unwrap());
}

/// @requirement TB-058
#[test]
fn fingerprint_der_is_infallible_even_on_garbage_bytes() {
    // Unlike `fingerprint`, `fingerprint_der` never needs the bytes to
    // parse as a real key - it just hashes whatever's given, which is
    // exactly what lets `idstore` show a fingerprint for a possibly
    // corrupted/hand-edited store entry without a `Result` to unwrap.
    let garbage = b"not a real der-encoded key";
    let fp1 = fingerprint_der(garbage);
    let fp2 = fingerprint_der(garbage);
    assert_eq!(fp1, fp2);
    assert_eq!(fp1.len(), 64);
}

/// @requirement TB-056
#[test]
fn save_and_load_keypair_files_roundtrip() {
    let kp = KeyPair::generate().expect("keygen");
    let dir = std::env::temp_dir().join(format!("aloo-crypto-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let priv_path = dir.join("id_rsa");
    let pub_path = dir.join("id_rsa.pub");

    kp.save_to_files(&priv_path, &pub_path).expect("save");
    let loaded = aloo::crypto::KeyPair::load_from_files(&priv_path, &pub_path).expect("load");

    let blocks = encrypt_chunked(&loaded.public, b"file backed key").expect("encrypt");
    let out = decrypt_chunked(&kp.private, &blocks).expect("decrypt");
    assert_eq!(out, b"file backed key");

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-016
#[test]
fn random_bytes_have_requested_length_and_are_not_trivially_constant() {
    let a = random_bytes(32);
    let b = random_bytes(32);
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_ne!(a, b, "two independent random draws should not collide");
}

/// @requirement TB-015
#[test]
fn constant_time_eq_matches_regular_equality() {
    assert!(constant_time_eq(b"same-password", b"same-password"));
    assert!(!constant_time_eq(b"same-password", b"different-pw"));
    assert!(!constant_time_eq(b"short", b"much-longer-value"));
    assert!(constant_time_eq(b"", b""));
}

/// @requirement TB-059
#[test]
fn sign_verify_roundtrip() {
    let kp = KeyPair::generate().expect("keygen");
    let sig = sign(&kp.private, b"new-key-der-bytes").expect("sign");
    assert!(verify(&kp.public, b"new-key-der-bytes", &sig));
}

/// @requirement TB-059
#[test]
fn verify_rejects_tampered_data() {
    let kp = KeyPair::generate().expect("keygen");
    let sig = sign(&kp.private, b"original payload").expect("sign");
    assert!(!verify(&kp.public, b"tampered payload", &sig));
}

/// @requirement TB-059
#[test]
fn verify_rejects_signature_from_a_different_key() {
    let kp_a = KeyPair::generate().expect("keygen a");
    let kp_b = KeyPair::generate().expect("keygen b");
    let sig = sign(&kp_a.private, b"payload").expect("sign");
    assert!(!verify(&kp_b.public, b"payload", &sig));
}

/// @requirement TB-059
#[test]
fn verify_rejects_garbage_signature_bytes() {
    let kp = KeyPair::generate().expect("keygen");
    assert!(!verify(&kp.public, b"payload", &[1, 2, 3, 4]));
    assert!(!verify(&kp.public, b"payload", &[]));
}

/// RSA-PSS salts every signature, so signing the same bytes twice gives
/// two different signatures that both verify. Nothing in this app ever
/// compares signatures for equality - it only ever verifies them - so the
/// randomness costs nothing and is what distinguishes PSS from the
/// deterministic PKCS#1 v1.5 scheme it replaced.
/// @requirement TB-162
#[test]
fn signing_the_same_payload_twice_gives_different_signatures() {
    let kp = KeyPair::generate().expect("keygen");
    let first = sign(&kp.private, b"same payload").expect("sign");
    let second = sign(&kp.private, b"same payload").expect("sign again");

    assert_ne!(
        first, second,
        "PSS is randomised - two signatures over one payload must differ"
    );
    assert!(verify(&kp.public, b"same payload", &first));
    assert!(verify(&kp.public, b"same payload", &second));
}

/// @requirement TB-162
#[test]
fn a_pss_signature_does_not_verify_against_tampered_bytes() {
    let kp = KeyPair::generate().expect("keygen");
    let sig = sign(&kp.private, b"the original bytes").expect("sign");
    let mut tampered = sig.clone();
    tampered[0] ^= 0xFF;

    assert!(!verify(&kp.public, b"the original bytes", &tampered));
}

/// @requirement TB-053
#[test]
fn generate_uses_the_default_rsa_key_bits() {
    let kp = KeyPair::generate().expect("keygen");
    assert_eq!(kp.public.size() * 8, RSA_KEY_BITS);
}

/// @requirement TB-053
#[test]
#[ignore = "real RSA-4096 keygen, 60s+ in this environment - run with `cargo test -- --ignored`"]
fn generate_with_bits_produces_a_key_of_the_requested_size_and_is_still_usable() {
    let kp = KeyPair::generate_with_bits(RSA_PER_MSG_KEY_BITS)
        .expect("keygen at pq_hybrid's RSA hedge size");
    assert_eq!(kp.public.size() * 8, RSA_PER_MSG_KEY_BITS);

    let blocks = encrypt_chunked(&kp.public, b"round trip at 4096 bits").expect("encrypt");
    let out = decrypt_chunked(&kp.private, &blocks).expect("decrypt");
    assert_eq!(out, b"round trip at 4096 bits");
}

/// Signatures are verified, never compared, so nothing in this app depends
/// on signing being reproducible - which is what lets `sign` use PSS's
/// random salt. The property that *is* depended on is covered by
/// `signing_the_same_payload_twice_gives_different_signatures`.
/// @requirement TB-059, TB-162
#[test]
fn a_signature_verifies_no_matter_which_signing_call_produced_it() {
    let kp = KeyPair::generate().expect("keygen");
    let sig1 = sign(&kp.private, b"same payload every time").expect("sign 1");
    let sig2 = sign(&kp.private, b"same payload every time").expect("sign 2");

    assert!(verify(&kp.public, b"same payload every time", &sig1));
    assert!(verify(&kp.public, b"same payload every time", &sig2));
}
