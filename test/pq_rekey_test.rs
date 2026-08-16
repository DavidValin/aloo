//! Tests for `client::pq_rekey` - rotating `pq_hybrid` encryption keys per
//! peer so a stolen keybundle cannot open past traffic
//! (`docs/PROTOCOL.md` §13.10).
//!
//! Uses `generate_bundle_with_bits` at a small modulus for the same reason
//! the other PQ tests do: nothing here asserts anything about RSA key size,
//! and the RSA half is only the signing hedge. The rotating keys under test
//! are the real ML-KEM-1024 and X25519.

use aloo::client::pq_rekey::{PQ_KEY_RETENTION, PqOwnKeys, PqPeerKeys};
use aloo::crypto::pq::{
    PqPublicBundle, bundle_fingerprint, generate_bundle_with_bits, generate_encryption_keys,
    open_send, seal_send, sign_rotation, verify_rotation,
};
use aloo::proto::UserId;

const TEST_BITS: usize = 1024;
const ALICE: UserId = UserId(1);
const BOB: UserId = UserId(2);

fn bundle() -> (PqPublicBundle, aloo::crypto::pq::PqPrivateBundle) {
    generate_bundle_with_bits(TEST_BITS).expect("bundle")
}

/// A message sealed to a peer's freshly rotated keys still opens - the
/// ordinary case, which must keep working or nothing else matters.
/// @requirement AC-116
#[test]
fn a_message_opens_under_the_key_the_peer_rotated_to() {
    let (alice_public, alice_private) = bundle();
    let (bob_public, bob_private) = bundle();
    let bob_fp = bundle_fingerprint(&bob_public).expect("fp");

    // Bob rotates for alice; alice seals to whatever he rotated to.
    let mut bob_own = PqOwnKeys::new(bob_private.bootstrap_decap().clone());
    let rotation = bob_own.rotate_for(ALICE);

    let blob = seal_send(
        &alice_private,
        &rotation.encap,
        bob_fp,
        None,
        1,
        b"after rotating",
    )
    .expect("seal");

    let candidates = bob_own.candidates_for(ALICE);
    let (_, plaintext) =
        open_send(&candidates, &bob_fp, &alice_public, &blob).expect("bob must be able to open it");
    assert_eq!(plaintext, b"after rotating");
}

/// The forward-secrecy property itself: once a key has fallen out of the
/// retention window, nothing that survives - including the keybundle file -
/// can reopen what it protected.
/// @requirement AC-117
#[test]
fn a_key_pushed_out_of_the_retention_window_cannot_open_its_message() {
    let (alice_public, alice_private) = bundle();
    let (bob_public, bob_private) = bundle();
    let bob_fp = bundle_fingerprint(&bob_public).expect("fp");

    let mut bob_own = PqOwnKeys::new(bob_private.bootstrap_decap().clone());
    let rotation = bob_own.rotate_for(ALICE);
    let blob = seal_send(
        &alice_private,
        &rotation.encap,
        bob_fp,
        None,
        1,
        b"yesterday's secret",
    )
    .expect("seal");

    // It opens right now.
    assert!(open_send(&bob_own.candidates_for(ALICE), &bob_fp, &alice_public, &blob).is_some());

    // Rotate far enough that the key it was sealed to is discarded.
    for _ in 0..=PQ_KEY_RETENTION {
        bob_own.rotate_for(ALICE);
    }

    assert!(
        open_send(&bob_own.candidates_for(ALICE), &bob_fp, &alice_public, &blob).is_none(),
        "a key past the retention window is gone, so its message must stay unreadable"
    );
    // And the on-disk identity is no help either - it never held that key.
    let from_file = [bob_private.bootstrap_decap().clone()];
    assert!(
        open_send(&from_file, &bob_fp, &alice_public, &blob).is_none(),
        "the keybundle file must not open a message sealed to a rotated key"
    );
}

/// A burst sent under one key still opens after a single rotation - which
/// is what the retention window is for.
/// @requirement TB-164
#[test]
fn recent_keys_are_retained_so_a_burst_still_opens() {
    let (alice_public, alice_private) = bundle();
    let (bob_public, bob_private) = bundle();
    let bob_fp = bundle_fingerprint(&bob_public).expect("fp");

    let mut bob_own = PqOwnKeys::new(bob_private.bootstrap_decap().clone());
    let rotation = bob_own.rotate_for(ALICE);

    let blobs: Vec<Vec<u8>> = (0..3u64)
        .map(|i| {
            seal_send(
                &alice_private,
                &rotation.encap,
                bob_fp,
                None,
                i + 1,
                format!("message {i}").as_bytes(),
            )
            .expect("seal")
        })
        .collect();

    bob_own.rotate_for(ALICE);

    let candidates = bob_own.candidates_for(ALICE);
    for (i, blob) in blobs.iter().enumerate() {
        let (_, plaintext) = open_send(&candidates, &bob_fp, &alice_public, blob)
            .expect("a retained key must still open a message sealed just before rotating");
        assert_eq!(plaintext, format!("message {i}").into_bytes());
    }
}

/// A peer who has not rotated with us yet is still encrypting to the
/// bootstrap keys, so those have to keep working.
/// @requirement AC-116
#[test]
fn the_bootstrap_key_still_opens_a_message_from_a_peer_who_never_rotated() {
    let (alice_public, alice_private) = bundle();
    let (bob_public, bob_private) = bundle();
    let bob_fp = bundle_fingerprint(&bob_public).expect("fp");

    let blob = seal_send(
        &alice_private,
        bob_public.bootstrap_encap(),
        bob_fp,
        None,
        1,
        b"first contact",
    )
    .expect("seal");

    // Bob has rotated for a *different* peer - that must not affect this.
    let mut bob_own = PqOwnKeys::new(bob_private.bootstrap_decap().clone());
    bob_own.rotate_for(BOB);

    let (_, plaintext) = open_send(
        &bob_own.candidates_for(ALICE),
        &bob_fp,
        &alice_public,
        &blob,
    )
    .expect("the bootstrap key must still open a first-contact message");
    assert_eq!(plaintext, b"first contact");
}

/// Rotations are signed by the durable identity, not by the key they
/// replace - so anyone else's signature is refused.
/// @requirement AC-118
#[test]
fn a_rotation_is_trusted_only_if_the_identity_signed_it() {
    let (alice_public, alice_private) = bundle();
    let (mallory_public, mallory_private) = bundle();
    let (bob_public, _) = bundle();
    let bob_fp = bundle_fingerprint(&bob_public).expect("fp");

    let mut alice_own = PqOwnKeys::new(alice_private.bootstrap_decap().clone());
    let rotation = alice_own.rotate_for(BOB);
    let (encoded, signature) =
        sign_rotation(&alice_private, BOB, &bob_fp, &rotation).expect("sign");

    assert!(
        verify_rotation(&alice_public, BOB, &bob_fp, &encoded, &signature).is_some(),
        "alice's own rotation must verify against alice's identity"
    );
    assert!(
        verify_rotation(&mallory_public, BOB, &bob_fp, &encoded, &signature).is_none(),
        "it must not verify against anybody else's identity"
    );

    // Mallory signing her own rotation and passing it off as alice's.
    let (m_encoded, m_signature) =
        sign_rotation(&mallory_private, BOB, &bob_fp, &rotation).expect("sign");
    assert!(
        verify_rotation(&alice_public, BOB, &bob_fp, &m_encoded, &m_signature).is_none(),
        "a rotation signed by mallory must not pass as alice's"
    );
}

/// A rotation names who it is for, so one peer cannot replay another's.
/// @requirement AC-119
#[test]
fn a_rotation_meant_for_one_peer_is_refused_by_another() {
    let (alice_public, alice_private) = bundle();
    let (bob_public, _) = bundle();
    let (carol_public, _) = bundle();
    let bob_fp = bundle_fingerprint(&bob_public).expect("fp");
    let carol_fp = bundle_fingerprint(&carol_public).expect("fp");

    let mut alice_own = PqOwnKeys::new(alice_private.bootstrap_decap().clone());
    let rotation = alice_own.rotate_for(BOB);
    let (encoded, signature) =
        sign_rotation(&alice_private, BOB, &bob_fp, &rotation).expect("sign");

    assert!(
        verify_rotation(&alice_public, BOB, &carol_fp, &encoded, &signature).is_none(),
        "carol's fingerprint is not what was signed"
    );
    assert!(
        verify_rotation(&alice_public, ALICE, &bob_fp, &encoded, &signature).is_none(),
        "a different recipient UserId is not what was signed either"
    );
}

/// An older rotation arriving late must not drag a peer back onto a key
/// they have already moved past.
/// @requirement AC-118
#[test]
fn an_older_rotation_generation_is_not_installed() {
    let mut peers = PqPeerKeys::new();
    let (encap_a, _) = generate_encryption_keys();
    let (encap_b, _) = generate_encryption_keys();

    peers.bootstrap(ALICE, encap_a.clone(), [0u8; 32]);
    assert_eq!(peers.generation_for(ALICE), Some(0));

    assert!(peers.install(
        ALICE,
        aloo::crypto::pq::PqRotation {
            encap: encap_b.clone(),
            generation: 2,
        }
    ));
    assert_eq!(peers.encap_for(ALICE), Some(&encap_b));

    assert!(
        !peers.install(
            ALICE,
            aloo::crypto::pq::PqRotation {
                encap: encap_a.clone(),
                generation: 1,
            }
        ),
        "a stale generation must be refused"
    );
    assert_eq!(
        peers.encap_for(ALICE),
        Some(&encap_b),
        "and must leave the current key untouched"
    );
}

/// Each peer relationship rotates on its own schedule.
/// @requirement AC-116
#[test]
fn rotation_is_independent_per_peer() {
    let (_, private) = bundle();
    let mut own = PqOwnKeys::new(private.bootstrap_decap().clone());

    own.rotate_for(ALICE);
    own.rotate_for(ALICE);
    own.rotate_for(BOB);

    assert_eq!(own.generation_for(ALICE), 2);
    assert_eq!(own.generation_for(BOB), 1);
}

/// A peer's connection ending takes their keys with it.
/// @requirement AC-117
#[test]
fn forgetting_a_peer_drops_their_keys() {
    let (_, private) = bundle();
    let mut own = PqOwnKeys::new(private.bootstrap_decap().clone());
    own.rotate_for(ALICE);
    assert_eq!(own.generation_for(ALICE), 1);

    own.forget(ALICE);
    assert_eq!(
        own.generation_for(ALICE),
        0,
        "nothing about the old connection may survive into a new one"
    );
}

/// Both halves of the wrap are load-bearing: damaging either the ML-KEM
/// ciphertext or the ephemeral X25519 public key yields a different wrap
/// key, so the message stops opening. A break of one primitive alone is
/// not enough to recover what was sealed.
/// @requirement TB-165
#[test]
fn the_wrap_needs_both_the_kem_and_the_x25519_halves() {
    let (bob_public, bob_private) = bundle();
    let k_data = [42u8; 32];

    let (kem_ciphertext, wrapped_key, eph_x25519_pub) =
        aloo::crypto::pq::wrap_key_for(bob_public.bootstrap_encap(), &k_data).expect("wrap");
    let decap = bob_private.bootstrap_decap();

    assert_eq!(
        aloo::crypto::pq::unwrap_key(decap, &kem_ciphertext, &wrapped_key, &eph_x25519_pub),
        Some(k_data),
        "an intact wrap must recover exactly the key that went in"
    );

    // Substitute a different ephemeral X25519 public key: the KEM half is
    // untouched, so only the classical half has been defeated.
    let (other_encap, _) = generate_encryption_keys();
    let recovered = aloo::crypto::pq::unwrap_key(
        decap,
        &kem_ciphertext,
        &wrapped_key,
        &other_encap.x25519_pub,
    );
    assert_ne!(
        recovered,
        Some(k_data),
        "the X25519 half must contribute to the wrap key"
    );

    // And the other way round: a different KEM ciphertext, same X25519.
    let (other_kem, _, _) =
        aloo::crypto::pq::wrap_key_for(bob_public.bootstrap_encap(), &k_data).expect("wrap");
    let recovered =
        aloo::crypto::pq::unwrap_key(decap, &other_kem, &wrapped_key, &eph_x25519_pub);
    assert_ne!(
        recovered,
        Some(k_data),
        "the ML-KEM half must contribute to the wrap key"
    );
}

/// Rotation is self-contained: one call produces genuinely new keys and
/// advances the generation, with no worker, queue or shared state behind
/// it. That is what lets it run inline on the event loop where
/// `rsa_per_msg`'s RSA-4096 keygen cannot.
/// @requirement TB-166
#[test]
fn every_rotation_produces_new_keys_with_no_machinery_behind_it() {
    let (_, private) = bundle();
    let mut own = PqOwnKeys::new(private.bootstrap_decap().clone());

    let mut seen = Vec::new();
    for expected_generation in 1..=5u64 {
        let rotation = own.rotate_for(ALICE);
        assert_eq!(
            rotation.generation, expected_generation,
            "each rotation advances the generation by exactly one"
        );
        assert!(
            !seen.contains(&rotation.encap),
            "every rotation must produce keys never handed out before"
        );
        seen.push(rotation.encap);
    }
    assert_eq!(own.generation_for(ALICE), 5);
}
