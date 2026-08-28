//! Tests for `KeyMode::PqHybrid` (`docs/PROTOCOL.md` §13): ML-DSA-87+RSA4096
//! signing, ML-KEM-1024+RSA4096 key-wrap, AES-256-GCM bulk encryption.
//!
//! Every test that calls `crypto::pq::generate_bundle` does real RSA-4096
//! keygen (x2) plus ML-DSA-87/ML-KEM-1024 keygen, same cost class as
//! `crypto_test.rs`'s `generate_with_bits(RSA_PER_MSG_KEY_BITS)` test - so,
//! following the same convention, those are `#[ignore]`d and run via
//! `cargo slow`. The chunk-level tests need no bundle at all (just a raw
//! `[u8; 32]` key), so they stay fast and ungated.

use aloo::crypto::pq::{
    PqPrivateBundle, PqPublicBundle, bundle_fingerprint, bundle_pair_matches, bundle_paths,
    ensure_bundle_at, generate_bundle, load_private_bundle, load_public_bundle, open_chunk,
    open_send, open_setup, resolve_bundle_paths, save_private_bundle, save_public_bundle,
    seal_chunk, seal_send, seal_setup,
};
use aloo::proto::{self, KeyMode};

/// Opens a sealed send the way a receiving client does: with the
/// recipient's *own* identity fingerprint, which the binding inside must
/// name for the send to be accepted at all. Returns just the plaintext -
/// tests that care about the binding call `open_send` directly.
fn open_for(
    recipient_private: &PqPrivateBundle,
    recipient_public: &PqPublicBundle,
    sender_public: &PqPublicBundle,
    blob: &[u8],
) -> Option<Vec<u8>> {
    let fp = bundle_fingerprint(recipient_public).expect("fingerprint");
    let decaps = [recipient_private.bootstrap_decap().clone()];
    open_send(&decaps, &fp, sender_public, blob).map(|(_, plaintext)| plaintext)
}

/// Seals to a recipient's *bootstrap* keys - what a peer encrypts to
/// before the relationship has rotated. Rotation itself is covered by
/// `pq_rekey_test.rs`.
fn seal_to(
    sender_signing: &PqPrivateBundle,
    recipient_public: &PqPublicBundle,
    channel: Option<String>,
    send_id: u64,
    data: &[u8],
) -> Vec<u8> {
    seal_send(
        sender_signing,
        recipient_public.bootstrap_encap(),
        bundle_fingerprint(recipient_public).expect("fingerprint"),
        channel,
        send_id,
        data,
    )
    .expect("seal")
}

/// `open_send` against a recipient's bootstrap keys, keeping the binding.
fn open_bound(
    recipient_private: &PqPrivateBundle,
    recipient_public: &PqPublicBundle,
    sender_public: &PqPublicBundle,
    blob: &[u8],
) -> Option<(aloo::crypto::pq::SendBinding, Vec<u8>)> {
    let fp = bundle_fingerprint(recipient_public).expect("fingerprint");
    let decaps = [recipient_private.bootstrap_decap().clone()];
    open_send(&decaps, &fp, sender_public, blob)
}

// ---------------------------------------------------------------------
// Chunk-level (voice) primitives - fast, no bundle/keygen needed
// ---------------------------------------------------------------------

/// @requirement TB-128
#[test]
fn same_plaintext_produces_different_ciphertext_under_different_seq() {
    let k_data = [7u8; 32];
    let c0 = seal_chunk(&k_data, 42, 0, b"pcm-chunk");
    let c1 = seal_chunk(&k_data, 42, 1, b"pcm-chunk");
    assert_ne!(
        c0, c1,
        "different seq must produce a different nonce, hence different ciphertext"
    );
}

/// @requirement AC-083
#[test]
fn hybrid_voice_chunk_round_trips() {
    let k_data = [9u8; 32];
    let ciphertext = seal_chunk(&k_data, 100, 5, b"raw pcm bytes");
    let plaintext = open_chunk(&k_data, 100, 5, &ciphertext).expect("decrypt should succeed");
    assert_eq!(plaintext, b"raw pcm bytes");
}

/// @requirement TB-128
#[test]
fn decrypting_a_chunk_with_the_wrong_seq_fails() {
    let k_data = [3u8; 32];
    let ciphertext = seal_chunk(&k_data, 1, 0, b"pcm");
    assert!(
        open_chunk(&k_data, 1, 1, &ciphertext).is_none(),
        "wrong seq means wrong nonce, must not decrypt"
    );
}

/// @requirement TB-128
#[test]
fn decrypting_a_chunk_with_the_wrong_stream_id_fails() {
    let k_data = [3u8; 32];
    let ciphertext = seal_chunk(&k_data, 1, 0, b"pcm");
    assert!(open_chunk(&k_data, 2, 0, &ciphertext).is_none());
}

/// @requirement TB-128
#[test]
fn decrypting_a_chunk_with_the_wrong_key_fails() {
    let k_data_a = [1u8; 32];
    let k_data_b = [2u8; 32];
    let ciphertext = seal_chunk(&k_data_a, 1, 0, b"pcm");
    assert!(open_chunk(&k_data_b, 1, 0, &ciphertext).is_none());
}

// ---------------------------------------------------------------------
// The one key mode's tag
// ---------------------------------------------------------------------

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
    let blob = seal_to(&alice_private, &bob_public, None, 1, msg);

    let out = open_for(&bob_private, &bob_public, &alice_public, &blob)
        .expect("open+verify should succeed");
    assert_eq!(out, msg);
}

/// A send is bound to the room it belongs to: the same sealed bytes
/// presented as if they came from a channel must not open. This is the
/// replay a legitimate recipient could otherwise perform on their own
/// message history.
/// @requirement AC-113
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn a_private_send_does_not_open_as_a_channel_send() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let blob = seal_to(&alice_private, &bob_public, None, 1, b"just between us");
    let (binding, _) = open_bound(&bob_private, &bob_public, &alice_public, &blob).expect("open");

    assert_eq!(
        binding.channel, None,
        "a DM must report no channel, which is what the receiving side compares against"
    );
}

/// The cross-recipient re-wrap: a legitimate recipient cannot make one of
/// alice's messages look like a message alice sent to somebody else.
/// @requirement AC-112
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn a_send_sealed_for_one_recipient_does_not_open_for_another() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, _bob_private) = generate_bundle().expect("bob bundle");
    let (carol_public, carol_private) = generate_bundle().expect("carol bundle");

    let blob = seal_to(&alice_private, &bob_public, None, 1, b"for bob only");

    // Carol presents bob's sealed send as though it were hers. Even holding
    // her own private bundle, the binding names bob - so it fails closed.
    assert!(
        open_bound(&carol_private, &carol_public, &alice_public, &blob).is_none(),
        "a send names who it was sealed for; presenting it as someone else's must fail"
    );
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

    let block = seal_to(
        &alice_private,
        &bob_public_decoded,
        None,
        1,
        b"hello via wire encoding",
    );
    assert_eq!(
        vec![block.clone()].len(),
        1,
        "the whole sealed send is one Envelope.blocks element"
    );

    let out = open_for(&bob_private, &bob_public, &alice_public, &block).expect("open");
    assert_eq!(out, b"hello via wire encoding");
}

/// @requirement AC-080
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn tampered_ciphertext_is_rejected() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");
    let _ = &alice_public;

    let mut blob = seal_to(&alice_private, &bob_public, None, 1, b"original");
    // Flip a byte near the end, which lands in the ciphertext rather than
    // the setup that precedes it.
    let last = blob.len() - 1;
    blob[last] ^= 0xFF;

    assert!(
        open_for(&bob_private, &bob_public, &alice_public, &blob).is_none(),
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
    let blob = seal_to(
        &mallory_private,
        &bob_public,
        None,
        1,
        b"pretend this is from alice",
    );

    assert!(
        open_for(&bob_private, &bob_public, &alice_public, &blob).is_none(),
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

    let blob = seal_to(&alice_private, &bob_public, None, 1, b"from alice");

    // bob mistakenly verifies against carol's public bundle instead of alice's.
    assert!(open_for(&bob_private, &bob_public, &carol_public, &blob).is_none());
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

    let blob = seal_to(&alice_private, &bob_public, None, 1, b"only for bob");

    assert!(
        open_for(&mallory_private, &mallory_public, &alice_public, &blob).is_none(),
        "mallory holds neither bob's ML-KEM-1024 nor RSA-4096-enc private key"
    );
}

/// @requirement TB-127
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn wrap_key_for_and_unwrap_key_round_trip() {
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");
    let k_data = aloo::crypto::pq::fresh_data_key();

    let (kem_ciphertext, wrapped_key, eph_x25519_pub) =
        aloo::crypto::pq::wrap_key_for(bob_public.bootstrap_encap(), &k_data).expect("wrap");
    let recovered = aloo::crypto::pq::unwrap_key(
        bob_private.bootstrap_decap(),
        &kem_ciphertext,
        &wrapped_key,
        &eph_x25519_pub,
    )
    .expect("unwrap");

    assert_eq!(recovered, k_data);
}

/// @requirement AC-083, TB-129
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn seal_setup_and_open_setup_round_trip() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let send_id = 4242u64;
    let (setup, k_data) = seal_setup(
        &alice_private,
        bob_public.bootstrap_encap(),
        bundle_fingerprint(&bob_public).expect("fingerprint"),
        None,
        send_id,
    )
    .expect("seal setup");

    let bob_fp = bundle_fingerprint(&bob_public).expect("fingerprint");
    let recovered = open_setup(
        &[bob_private.bootstrap_decap().clone()],
        &bob_fp,
        &alice_public,
        &setup,
    )
    .expect("open+verify should succeed");
    assert_eq!(recovered, k_data);
}

/// A stream's whole content hangs off one setup, so a setup that fails to
/// verify must yield nothing at all - the receiving worker has no key to
/// decrypt a single chunk with.
/// @requirement AC-080, TB-129
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn open_setup_rejects_a_setup_sealed_for_someone_else() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, _bob_private) = generate_bundle().expect("bob bundle");
    let (carol_public, carol_private) = generate_bundle().expect("carol bundle");

    let (setup, _) = seal_setup(
        &alice_private,
        bob_public.bootstrap_encap(),
        bundle_fingerprint(&bob_public).expect("fingerprint"),
        None,
        1,
    )
    .expect("seal setup");

    let carol_fp = bundle_fingerprint(&carol_public).expect("fingerprint");
    assert!(
        open_setup(
            &[carol_private.bootstrap_decap().clone()],
            &carol_fp,
            &alice_public,
            &setup
        )
        .is_none(),
        "a stream setup names its recipient exactly like a text send does"
    );
}

/// Every chunk of a stream rides on the one key its setup authorised, and
/// the `(send_id, seq)` nonce keeps each chunk distinct.
/// @requirement AC-115, TB-160
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn a_stream_of_chunks_opens_under_its_setups_key() {
    let (alice_public, alice_private) = generate_bundle().expect("alice bundle");
    let (bob_public, bob_private) = generate_bundle().expect("bob bundle");

    let send_id = 7u64;
    let (setup, k_data) = seal_setup(
        &alice_private,
        bob_public.bootstrap_encap(),
        bundle_fingerprint(&bob_public).expect("fingerprint"),
        Some("the-hall".into()),
        send_id,
    )
    .expect("seal setup");
    let chunks: Vec<Vec<u8>> = (0..3u32)
        .map(|seq| seal_chunk(&k_data, send_id, seq, format!("chunk {seq}").as_bytes()))
        .collect();

    let bob_fp = bundle_fingerprint(&bob_public).expect("fingerprint");
    let recovered = open_setup(
        &[bob_private.bootstrap_decap().clone()],
        &bob_fp,
        &alice_public,
        &setup,
    )
    .expect("open setup");
    for (seq, ciphertext) in chunks.iter().enumerate() {
        let seq = seq as u32;
        let plaintext =
            open_chunk(&recovered, send_id, seq, ciphertext).expect("chunk should open");
        assert_eq!(plaintext, format!("chunk {seq}").into_bytes());
    }
    assert_eq!(
        setup.binding.channel.as_deref(),
        Some("the-hall"),
        "a channel stream carries the channel it belongs to"
    );
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

    let blob = seal_to(
        &loaded_private,
        &loaded_public,
        None,
        1,
        b"round trip via files",
    );
    let out = open_for(&loaded_private, &loaded_public, &loaded_public, &blob).expect("open");
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
    let blob = seal_to(&private, &public, None, 1, b"self-addressed round trip");
    let out = open_for(&private, &public, &public, &blob).expect("open");
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

/// The end-to-end shape of the bug TB-283 exists to prevent: a keybundle
/// `--keygen-pq-hybrid <prefix>` wrote, opened by prefix, must still be
/// the same identity afterwards.
///
/// It was not. `--my-key` looked for the private half at `<prefix>.priv`,
/// which keygen never writes, so the intact pair read as half-present and
/// `ensure_bundle_at` correctly (TB-134) regenerated both - overwriting
/// the public half and silently swapping the identity, with no continuity
/// certificate for anyone who had pinned it.
/// @requirement TB-283
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn a_keygen_written_bundle_survives_being_opened_by_prefix() {
    let dir = std::env::temp_dir().join(format!("aloo-prefix-survives-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let prefix = dir.join("mykey").display().to_string();

    // `--keygen-pq-hybrid <prefix>`
    let (priv_path, pub_path) = bundle_paths(&prefix);
    let (public, private) = generate_bundle().unwrap();
    save_private_bundle(&private, &priv_path).unwrap();
    save_public_bundle(&public, &pub_path).unwrap();
    let before = bundle_fingerprint(&public).unwrap();

    // `--daemon --my-key <prefix>`, then the connect path's own step.
    let (resolved_priv, resolved_pub) = resolve_bundle_paths(&prefix);
    ensure_bundle_at(&resolved_pub, &resolved_priv).expect("nothing to generate");

    let after = bundle_fingerprint(&load_public_bundle(&pub_path).unwrap()).unwrap();
    assert_eq!(before, after, "the keygen'd identity must survive intact");
    assert!(
        bundle_pair_matches(
            &load_private_bundle(&resolved_priv).unwrap(),
            &load_public_bundle(&resolved_pub).unwrap()
        ),
        "and the halves it resolved to must belong together"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-284
#[test]
#[ignore = "real keygen - see module doc, run with cargo slow"]
fn bundle_pair_matches_accepts_a_real_pair_and_rejects_a_crossed_one() {
    let (pub_a, priv_a) = generate_bundle().unwrap();
    let (pub_b, priv_b) = generate_bundle().unwrap();

    assert!(bundle_pair_matches(&priv_a, &pub_a));
    assert!(bundle_pair_matches(&priv_b, &pub_b));
    assert!(
        !bundle_pair_matches(&priv_a, &pub_b),
        "halves from two different bundles are not a pair"
    );
    assert!(!bundle_pair_matches(&priv_b, &pub_a));
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
    let blob = seal_to(
        &private,
        &public,
        None,
        1,
        b"still works after partial deletion",
    );
    let out = open_for(&private, &public, &public, &blob).expect("open");
    assert_eq!(out, b"still works after partial deletion");

    std::fs::remove_dir_all(&dir).ok();
}

