//! Tests for the parts of `client::voice_stream` that are pure data
//! transformation - specifically `ChunkDecryptor`, which decides what an
//! incoming stream's chunks decrypt to and what happens to chunks that
//! arrive before the setup they depend on (`docs/PROTOCOL.md`, US-027).
//!
//! The rest of the module needs a live audio device or socket and is
//! covered at the acceptance layer instead (see `docs/TESTING.md`).
//!
//! Uses `generate_bundle_with_bits` at a small modulus for the same reason
//! `test/cucumber/world.rs` does: nothing here asserts anything about RSA
//! key size, and two RSA-4096 keygens per identity would make this slow
//! enough to skip. `hybrid_crypto_test.rs` covers the real sizes.

use aloo::client::voice_stream::{ChunkDecryptor, IncomingStreamKey};
use aloo::crypto::pq::{
    PqPublicBundle, bundle_fingerprint, generate_bundle_with_bits, seal_chunk, seal_setup,
};
use aloo::proto;

const TEST_BITS: usize = 1024;
const SEND_ID: u64 = 9;

/// Alice sealing a stream for bob, plus the decryptor bob would use.
fn stream_fixture() -> (ChunkDecryptor, Vec<u8>, [u8; 32], PqPublicBundle) {
    let (alice_public, alice_private) = generate_bundle_with_bits(TEST_BITS).expect("alice");
    let (bob_public, bob_private) = generate_bundle_with_bits(TEST_BITS).expect("bob");
    let bob_fp = bundle_fingerprint(&bob_public).expect("fingerprint");

    let (setup, k_data) = seal_setup(
        &alice_private,
        bob_public.bootstrap_encap(),
        bob_fp,
        None,
        SEND_ID,
    )
    .expect("seal setup");
    let encoded = proto::encode(&setup).expect("encode setup");

    let decryptor = ChunkDecryptor::new(IncomingStreamKey::Pq {
        my_decaps: vec![bob_private.bootstrap_decap().clone()],
        my_fp: bob_fp,
        sender_public: alice_public.clone(),
    });
    (decryptor, encoded, k_data, alice_public)
}

/// @requirement AC-115
#[test]
fn chunks_open_once_the_setup_has_been_installed() {
    let (mut decryptor, setup, k_data, _) = stream_fixture();

    let replayed = decryptor
        .install_setup(SEND_ID, &setup)
        .expect("a genuine setup must install");
    assert!(
        replayed.is_empty(),
        "nothing was waiting, so nothing should be replayed"
    );

    let chunk = seal_chunk(&k_data, SEND_ID, 0, b"hello");
    assert_eq!(
        decryptor.decrypt(SEND_ID, 0, &[chunk]),
        Some(b"hello".to_vec())
    );
}

/// Voice chunks travel unreliably, so they can beat the reliable setup they
/// belong to. They must wait rather than being lost.
/// @requirement TB-163
#[test]
fn chunks_arriving_before_the_setup_are_replayed_once_it_lands() {
    let (mut decryptor, setup, k_data, _) = stream_fixture();

    // Three chunks arrive first - none can decrypt yet.
    for seq in 0..3u32 {
        let chunk = seal_chunk(&k_data, SEND_ID, seq, format!("chunk {seq}").as_bytes());
        assert_eq!(
            decryptor.decrypt(SEND_ID, seq, &[chunk]),
            None,
            "nothing can decrypt before the setup arrives"
        );
    }

    let replayed = decryptor
        .install_setup(SEND_ID, &setup)
        .expect("setup must install");

    assert_eq!(replayed.len(), 3, "every held chunk must come back");
    for (i, (seq, plaintext)) in replayed.iter().enumerate() {
        assert_eq!(*seq, i as u32, "chunks must be replayed in arrival order");
        assert_eq!(plaintext, format!("chunk {i}").as_bytes());
    }
}

/// @requirement TB-163
#[test]
fn a_stream_whose_setup_never_verifies_decrypts_nothing() {
    let (mut decryptor, _, k_data, _) = stream_fixture();

    let chunk = seal_chunk(&k_data, SEND_ID, 0, b"never readable");
    assert_eq!(decryptor.decrypt(SEND_ID, 0, &[chunk]), None);

    assert!(
        decryptor.install_setup(SEND_ID, b"not a setup at all").is_none(),
        "a setup that doesn't even decode must not install"
    );
}

/// A setup is bound to its own send, so one captured from a different
/// stream cannot be used to open this one.
/// @requirement AC-115
#[test]
fn a_setup_for_a_different_send_is_refused() {
    let (mut decryptor, setup, _, _) = stream_fixture();

    assert!(
        decryptor.install_setup(SEND_ID + 1, &setup).is_none(),
        "the setup names its own send_id and must not install against another"
    );
}

/// An RSA-family stream has no setup at all - its chunks decrypt (or fail)
/// on arrival, and installing a setup is meaningless.
/// @requirement TB-160
#[test]
fn an_rsa_stream_has_no_setup_to_install() {
    let mut decryptor = ChunkDecryptor::new(IncomingStreamKey::Rsa(Vec::new()));

    assert!(
        decryptor.install_setup(SEND_ID, b"anything").is_none(),
        "only a pq_hybrid stream is introduced by a setup"
    );
    assert_eq!(
        decryptor.decrypt(SEND_ID, 0, &[vec![1, 2, 3]]),
        None,
        "with no candidate keys nothing decrypts, but it must not panic"
    );
}
