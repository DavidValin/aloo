//! Tests for the three things that make a pin worth more than
//! "these bytes differ from last time" (`docs/PROTOCOL.md` §12.7):
//! verified pins, continuity certificates, and identity cards.

use aloo::client::idstore::{IdStore, Trust};
use aloo::crypto::pq::{
    bundle_fingerprint, generate_bundle_with_bits, load_identity_card, make_identity_card,
    open_identity_card, save_identity_card, sign_continuity, verify_continuity,
};
use aloo::crypto::safety;

const TEST_BITS: usize = 1024;

fn bundle() -> (
    aloo::crypto::pq::PqPublicBundle,
    aloo::crypto::pq::PqPrivateBundle,
) {
    generate_bundle_with_bits(TEST_BITS).expect("bundle")
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aloo-continuity-{tag}-{}-{nanos}", std::process::id()))
}

// ---------------------------------------------------------------------
// Safety phrases
// ---------------------------------------------------------------------

/// @requirement AC-120
#[test]
fn a_safety_phrase_is_stable_and_distinguishes_identities() {
    let fp_a = [7u8; 32];
    let fp_b = [8u8; 32];

    assert_eq!(
        safety::phrase(&fp_a),
        safety::phrase(&fp_a),
        "a phrase must read the same every time or comparing it proves nothing"
    );
    assert_ne!(safety::phrase(&fp_a), safety::phrase(&fp_b));
}

/// @requirement AC-120
#[test]
fn a_safety_phrase_is_eight_readable_words() {
    let phrase = safety::phrase(&[1u8; 32]);
    let words: Vec<&str> = phrase.split(' ').collect();
    assert_eq!(words.len(), 8, "eight words is what a person will read out");
    for w in words {
        assert!(!w.is_empty());
        assert!(
            w.chars().all(|c| c.is_ascii_lowercase()),
            "words must survive being read aloud and typed back: {w:?}"
        );
    }
}

/// The phrase must actually depend on the fingerprint it came from - a
/// single differing byte within the read-out prefix has to show up.
/// @requirement AC-120
#[test]
fn a_single_changed_byte_changes_the_phrase() {
    let mut fp = [3u8; 32];
    let before = safety::phrase(&fp);
    fp[0] = 4;
    assert_ne!(before, safety::phrase(&fp));
}

// ---------------------------------------------------------------------
// Verified pins
// ---------------------------------------------------------------------

/// @requirement AC-121
#[test]
fn a_pin_starts_trusted_on_sight_and_can_be_raised_to_verified() {
    let mut store = IdStore::new_empty(temp_path("verified"));

    store.check_and_pin("alice", b"key-a");
    assert_eq!(store.trust("alice"), Some(Trust::Tofu));

    assert!(store.mark_verified("alice"));
    assert_eq!(store.trust("alice"), Some(Trust::Verified));
}

/// @requirement AC-121
#[test]
fn marking_an_unknown_nickname_verified_does_nothing() {
    let mut store = IdStore::new_empty(temp_path("unknown"));
    assert!(!store.mark_verified("nobody"));
    assert_eq!(store.trust("nobody"), None);
}

/// Re-pinning must not quietly undo a human's verification.
/// @requirement AC-121
#[test]
fn re_pinning_does_not_silently_demote_a_verified_pin() {
    let mut store = IdStore::new_empty(temp_path("demote"));
    store.check_and_pin("alice", b"key-a");
    store.mark_verified("alice");

    store.check_and_pin("alice", b"key-b");
    assert_eq!(
        store.trust("alice"),
        Some(Trust::Verified),
        "a later sighting must not downgrade what a person confirmed"
    );
}

/// @requirement AC-121
#[test]
fn trust_survives_a_save_and_load_round_trip() {
    let path = temp_path("roundtrip");
    let mut store = IdStore::new_empty(path.clone());
    store.check_and_pin("alice", b"key-a");
    store.mark_verified("alice");
    store.check_and_pin("bob", b"key-b");
    store.save().expect("save");

    let loaded = IdStore::load(&path).expect("load");
    assert_eq!(loaded.trust("alice"), Some(Trust::Verified));
    assert_eq!(loaded.trust("bob"), Some(Trust::Tofu));
    assert_eq!(loaded.get("alice"), Some(b"key-a".as_slice()));

    std::fs::remove_file(&path).ok();
}

/// A store written before trust levels existed must keep its pins rather
/// than being discarded - losing them would cost real security.
/// @requirement AC-121
#[test]
fn a_store_without_a_trust_column_loads_as_trusted_on_sight() {
    let path = temp_path("legacy");
    std::fs::write(&path, "alice\t6b65792d61\n").expect("write");

    let loaded = IdStore::load(&path).expect("load");
    assert_eq!(loaded.get("alice"), Some(b"key-a".as_slice()));
    assert_eq!(loaded.trust("alice"), Some(Trust::Tofu));

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Continuity certificates
// ---------------------------------------------------------------------

/// @requirement AC-122
#[test]
fn a_replacement_identity_proves_it_succeeded_the_pinned_one() {
    let (old_public, old_private) = bundle();
    let (new_public, _) = bundle();

    let cert = sign_continuity(&old_private, &old_public, &new_public).expect("sign");
    let new_public = new_public.with_continuity(cert);

    assert!(
        verify_continuity(&old_public, &new_public),
        "a certificate signed by the pinned identity must verify against it"
    );
}

/// @requirement AC-123
#[test]
fn an_unrelated_identity_cannot_prove_continuity() {
    let (old_public, _) = bundle();
    let (stranger_public, _) = bundle();

    assert!(
        !verify_continuity(&old_public, &stranger_public),
        "a bundle with no certificate at all must not pass as a successor"
    );
}

/// Forging continuity needs the *old private keys*. Knowing the old public
/// identity - which anyone who has met alice does - is not enough.
/// @requirement AC-123
#[test]
fn a_certificate_signed_by_the_wrong_keys_is_refused() {
    let (old_public, _old_private) = bundle();
    let (mallory_public, mallory_private) = bundle();
    let (new_public, _) = bundle();

    // Mallory signs her own certificate and claims it succeeds alice.
    let cert = sign_continuity(&mallory_private, &mallory_public, &new_public).expect("sign");
    let forged = new_public.with_continuity(cert);

    assert!(
        !verify_continuity(&old_public, &forged),
        "a certificate must not verify against an identity that did not sign it"
    );
}

/// A genuine certificate cannot be lifted onto a different successor.
/// @requirement AC-123
#[test]
fn a_certificate_does_not_transfer_to_another_bundle() {
    let (old_public, old_private) = bundle();
    let (new_public, _) = bundle();
    let (other_public, _) = bundle();

    let cert = sign_continuity(&old_private, &old_public, &new_public).expect("sign");
    let stolen = other_public.with_continuity(cert);

    assert!(
        !verify_continuity(&old_public, &stolen),
        "the certificate names which successor it vouches for"
    );
}

/// A chain of two planned rekeys: each step verifies against the one
/// immediately before it.
/// @requirement AC-122
#[test]
fn continuity_holds_across_successive_rekeys() {
    let (first_public, first_private) = bundle();
    let (second_public, second_private) = bundle();
    let (third_public, _) = bundle();

    let cert = sign_continuity(&first_private, &first_public, &second_public).expect("sign");
    let second_public = second_public.with_continuity(cert);
    assert!(verify_continuity(&first_public, &second_public));

    let cert = sign_continuity(&second_private, &second_public, &third_public).expect("sign");
    let third_public = third_public.with_continuity(cert);
    assert!(verify_continuity(&second_public, &third_public));

    assert!(
        !verify_continuity(&first_public, &third_public),
        "skipping a link must not verify - each step vouches only for the next"
    );
}

// ---------------------------------------------------------------------
// Identity cards
// ---------------------------------------------------------------------

/// @requirement AC-124
#[test]
fn an_identity_card_round_trips_and_names_its_owner() {
    let (public, private) = bundle();
    let card = make_identity_card(&private, &public, "alice").expect("card");

    let (nickname, bundle) = open_identity_card(&card).expect("a genuine card must open");
    assert_eq!(nickname, "alice");
    assert_eq!(
        bundle_fingerprint(bundle).unwrap(),
        bundle_fingerprint(&public).unwrap()
    );
}

/// @requirement AC-124
#[test]
fn an_identity_card_survives_being_written_and_read_back() {
    let (public, private) = bundle();
    let card = make_identity_card(&private, &public, "alice").expect("card");
    let path = temp_path("card");

    save_identity_card(&card, &path).expect("save");
    let loaded = load_identity_card(&path).expect("load");
    let (nickname, _) = open_identity_card(&loaded).expect("open");
    assert_eq!(nickname, "alice");

    std::fs::remove_file(&path).ok();
}

/// @requirement AC-125
#[test]
fn a_card_whose_nickname_was_altered_is_refused() {
    let (public, private) = bundle();
    let mut card = make_identity_card(&private, &public, "alice").expect("card");

    card.nickname = "mallory".into();

    assert!(
        open_identity_card(&card).is_none(),
        "the signature covers the nickname, so renaming a card must break it"
    );
}

/// Swapping in someone else's keys is the attack a card exists to stop:
/// the fingerprint the signature covers no longer matches.
/// @requirement AC-125
#[test]
fn a_card_whose_bundle_was_swapped_is_refused() {
    let (public, private) = bundle();
    let (other_public, _) = bundle();
    let mut card = make_identity_card(&private, &public, "alice").expect("card");

    card.bundle = other_public;

    assert!(open_identity_card(&card).is_none());
}

/// @requirement AC-125
#[test]
fn a_corrupted_card_file_is_refused_rather_than_trusted() {
    let path = temp_path("corrupt");
    std::fs::write(&path, b"this is not a card at all").expect("write");

    assert!(load_identity_card(&path).is_err());

    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// What the identity fingerprint covers
// ---------------------------------------------------------------------

/// Attaching a continuity certificate must not change who the identity
/// *is*. If it did, the certificate would have to sign the fingerprint of
/// a bundle that already contained it, and every contact's pin and safety
/// phrase would shift for no reason.
/// @requirement TB-168
#[test]
fn attaching_a_certificate_does_not_change_the_fingerprint() {
    let (old_public, old_private) = bundle();
    let (new_public, _) = bundle();

    let before = bundle_fingerprint(&new_public).expect("fingerprint");
    let cert = sign_continuity(&old_private, &old_public, &new_public).expect("sign");
    let after = bundle_fingerprint(&new_public.with_continuity(cert)).expect("fingerprint");

    assert_eq!(
        before, after,
        "a certificate describes how an identity arrived, not who it is"
    );
}

/// @requirement TB-168
#[test]
fn a_fingerprint_is_the_same_whether_taken_from_a_bundle_or_its_announced_bytes() {
    let (public, _) = bundle();
    let encoded = aloo::proto::encode(&public).expect("encode");

    assert_eq!(
        aloo::crypto::pq::fingerprint_of_encoded(&encoded),
        Some(bundle_fingerprint(&public).expect("fingerprint")),
    );
    assert_eq!(
        aloo::crypto::pq::fingerprint_of_encoded(b"not a bundle"),
        None,
        "bytes that are not a bundle have no identity fingerprint to give"
    );
}
