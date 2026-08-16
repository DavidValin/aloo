//! Known-answer tests for aloo's *own* constructions
//! (`docs/SECURITY.md`, "Test vectors").
//!
//! These deliberately do not re-test ML-KEM-1024 or ML-DSA-87 against the
//! NIST vectors: the `ml-kem`/`ml-dsa` crates already do that upstream, and
//! duplicating it here would prove nothing about this codebase. What no
//! upstream crate can check is the layer aloo builds on top - how the two
//! shared secrets are combined, exactly which bytes a signature covers, how
//! a chunk nonce is derived. Those are the parts an independent
//! implementation has to match byte for byte, and the parts that would
//! break interoperability silently if they ever drifted.
//!
//! Every value here is committed in `docs/SECURITY.md`. If one of these
//! fails, the wire format changed - which may be intended, but never
//! accidentally.

use aloo::control;
use aloo::crypto::hex_encode;
use aloo::crypto::pq::{SendBinding, chunk_nonce, hkdf_combine, seal_chunk, send_commitment};
use aloo::crypto::safety;

/// The chunk nonce is `send_id` then `seq`, both big-endian, zero-padded
/// to AES-GCM's 12 bytes.
/// @requirement TB-174
#[test]
fn chunk_nonce_vectors() {
    assert_eq!(hex_encode(&chunk_nonce(0, 0)), "000000000000000000000000");
    assert_eq!(hex_encode(&chunk_nonce(1, 0)), "000000000000000100000000");
    assert_eq!(hex_encode(&chunk_nonce(0, 1)), "000000000000000000000001");
    assert_eq!(
        hex_encode(&chunk_nonce(0x0102030405060708, 0x090a0b0c)),
        "0102030405060708090a0b0c"
    );
    assert_eq!(
        hex_encode(&chunk_nonce(u64::MAX, u32::MAX)),
        "ffffffffffffffffffffffff"
    );
}

/// The HKDF combiner: neither shared secret alone determines the result,
/// and the order they are fed in is part of the contract.
/// @requirement TB-174
#[test]
fn key_wrap_combiner_vectors() {
    let kem = [0x11u8; 32];
    let classical = [0x22u8; 32];

    assert_eq!(
        hex_encode(&hkdf_combine(&kem, &classical)),
        "ae7d19601a44a54105e83a3b82ee0304e308fede5e2e049775fb7d14fab0d7bf"
    );
    assert_ne!(
        hkdf_combine(&kem, &classical),
        hkdf_combine(&classical, &kem),
        "the two halves are not interchangeable"
    );
    assert_ne!(
        hkdf_combine(&kem, &classical),
        hkdf_combine(&kem, &[0x23u8; 32]),
        "changing either half must change the wrap key"
    );
}

/// The exact bytes a send's two signatures cover.
/// @requirement TB-174
#[test]
fn send_commitment_vectors() {
    let binding = SendBinding {
        recipient_fp: [0xAA; 32],
        channel: None,
        send_id: 1,
    };
    let k_data = [0xBB; 32];
    let dm = send_commitment(&binding, &k_data).expect("commitment");

    assert!(
        dm.starts_with(b"aloo/pq-hybrid/v2/send"),
        "the domain tag leads, so a send commitment cannot be mistaken for any other signature"
    );

    let channel = SendBinding {
        recipient_fp: [0xAA; 32],
        channel: Some("the-hall".into()),
        send_id: 1,
    };
    let channel = send_commitment(&channel, &k_data).expect("commitment");
    assert_ne!(dm, channel, "a DM and a channel send commit to different bytes");

    let other_recipient = SendBinding {
        recipient_fp: [0xAB; 32],
        channel: None,
        send_id: 1,
    };
    assert_ne!(
        dm,
        send_commitment(&other_recipient, &k_data).expect("commitment"),
        "who the send is for is covered"
    );

    let later = SendBinding {
        recipient_fp: [0xAA; 32],
        channel: None,
        send_id: 2,
    };
    assert_ne!(
        dm,
        send_commitment(&later, &k_data).expect("commitment"),
        "which send it is, is covered"
    );

    assert_eq!(hex_encode(&dm), aloo_test_vectors::SEND_COMMITMENT_DM);
}

/// One chunk sealed under a fixed key and counter - the only fully
/// deterministic end-to-end step in a send, and so the one an independent
/// implementation can check its AES-GCM wiring against.
/// @requirement TB-174
#[test]
fn sealed_chunk_vector() {
    let k_data = [0x42u8; 32];
    let sealed = seal_chunk(&k_data, 7, 0, b"hello aloo");
    assert_eq!(hex_encode(&sealed), aloo_test_vectors::SEALED_CHUNK);
}

/// The control channel's two directional keys.
/// @requirement TB-174
#[test]
fn control_channel_key_vectors() {
    let secret = [0x33u8; 32];
    let (c2s, s2c) = control::derive(&secret);

    assert_eq!(hex_encode(&c2s), aloo_test_vectors::CONTROL_C2S);
    assert_eq!(hex_encode(&s2c), aloo_test_vectors::CONTROL_S2C);
    assert_ne!(c2s, s2c, "the directions must not share a key");
}

/// Safety phrases, which a human reads aloud - so the mapping from bytes
/// to words is as much a contract as any of the above.
/// @requirement TB-174
#[test]
fn safety_phrase_vectors() {
    assert_eq!(
        safety::phrase(&[0u8; 32]),
        "acid acid acid acid acid acid acid acid"
    );
    assert_eq!(
        safety::phrase(&[0xFFu8; 32]),
        "lattice lattice lattice lattice lattice lattice lattice lattice"
    );

    let mut fp = [0u8; 32];
    for (i, b) in fp.iter_mut().enumerate().take(8) {
        *b = i as u8;
    }
    assert_eq!(safety::phrase(&fp), aloo_test_vectors::SAFETY_PHRASE_0_TO_7);
}

/// The committed values, kept together so `docs/SECURITY.md` and this
/// file cannot drift apart unnoticed.
mod aloo_test_vectors {
    pub const SEND_COMMITMENT_DM: &str = "616c6f6f2f70712d6879627269642f76322f73656e64aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0001bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    pub const SEALED_CHUNK: &str =
        "28a135e1f244540831e19b02cf68cfea51a6350cda3e77bcac8d";
    pub const CONTROL_C2S: &str =
        "de690a94c27db09c2bf69fcd349863415d873378e39b3ece4c132bdc84a159e4";
    pub const CONTROL_S2C: &str =
        "c180b4f467ad13ebe1e47ba832e9e4126bb66f7d356b506dd049918d02d9fe6d";
    pub const SAFETY_PHRASE_0_TO_7: &str = "acid acorn album alien amber anchor angle apple";
}
