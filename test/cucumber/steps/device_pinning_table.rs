//! Reference-table rows (device-pinning plan §7) with no other Gherkin
//! coverage yet: the "Server introduces" table's rows 3-5 (a pre-existing
//! otp-only pin never collides with a fresh `pq_hybrid` first sighting -
//! `key_mode`-scoping, plan §1) and row 7 (an identical key announced under
//! a brand-new device still opens a review, never silently merging).
//!
//! Rows 1/2/6 of that table, and the whole "No server" table's rows
//! 1/2/4/5, are already covered by `identity_pinning.feature`/
//! `becoming_a_real_peer.feature`, tagged `@with_server`/
//! `@without_reachable_server` precisely because the mechanism they
//! exercise doesn't care which table it's read from. "No server" row 3 -
//! the cleartext device-claim gate - lives in `otp.rs` instead, since it
//! needs the real pad-only harness (`pad_only_pair`).

use cucumber::{given, then, when};

use aloo::client::idstore::{IdStore, Trust, compare_key, KeyCheck};
use aloo::proto::KeyMode;

use crate::world::AlooWorld;

fn otp_only_key(name: &str) -> Vec<u8> {
    format!("otp-key-for-{name}").into_bytes()
}

fn pq_hybrid_key(name: &str) -> Vec<u8> {
    format!("pq-hybrid-key-for-{name}").into_bytes()
}

fn ensure_store(w: &mut AlooWorld, who: &str) {
    if !w.id_stores.contains_key(who) {
        let path = w.temp_path(&format!("idstore-{who}"));
        w.id_stores.insert(
            who.to_string(),
            IdStore::load(&path).expect("a missing store file must not be an error"),
        );
    }
}

#[given(expr = "{word} already holds an otp-only pin for {word}")]
async fn holds_otp_only_pin(w: &mut AlooWorld, who: String, other: String) {
    ensure_store(w, &who);
    let key = otp_only_key(&other);
    w.id_stores
        .get_mut(&who)
        .expect("just ensured")
        .pin_new_device(&other, "otp-device", &key, Trust::Tofu);
}

#[given(expr = "{word} has nothing pinned for {word} at all")]
async fn nothing_pinned_for(w: &mut AlooWorld, who: String, _other: String) {
    ensure_store(w, &who);
}

#[given(expr = "{word} already has {word}'s real key pinned")]
async fn already_has_real_key_pinned(w: &mut AlooWorld, who: String, other: String) {
    ensure_store(w, &who);
    let key = pq_hybrid_key(&other);
    w.id_stores.get_mut(&who).expect("just ensured").pin_new_device_with_key_mode(
        &other,
        "srv-device",
        &key,
        Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );
}

/// Mirrors `check_identity`'s `key_mode`-scoped comparison: only the
/// nickname's `PqHybrid` entries are ever compared against a real
/// `pq_hybrid` announce, so a pre-existing `Direct`-framed (otp-only) entry
/// is invisible to it and is therefore left completely alone - the crux
/// property device-pinning plan §1 calls "independent, non-colliding trust
/// dimensions."
fn introduce_one(w: &mut AlooWorld, who: &str, other: &str) {
    ensure_store(w, who);
    let key = pq_hybrid_key(other);
    let store = w.id_stores.get_mut(who).expect("just ensured");
    let pq_only: Vec<&[u8]> = store
        .devices_of(other)
        .filter(|d| d.key_mode == Some(KeyMode::PqHybrid))
        .map(|d| d.key.as_slice())
        .collect();
    match compare_key(pq_only.into_iter(), &key) {
        KeyCheck::New => {
            store.pin_new_device_with_key_mode(other, "srv-device", &key, Trust::Tofu, Some(KeyMode::PqHybrid));
        }
        KeyCheck::Match => {}
        KeyCheck::Mismatch { .. } => panic!("unexpected pq_hybrid mismatch introducing {other} to {who}"),
    }
}

#[when(expr = "a server introduces {word} and {word} with their real pq_hybrid identities")]
async fn server_introduces(w: &mut AlooWorld, a: String, b: String) {
    introduce_one(w, &a, &b);
    introduce_one(w, &b, &a);
}

#[then(expr = "{word} now has two independent pins for {word}: the otp-only one, untouched, and a fresh pq_hybrid one")]
async fn has_two_independent_pins(w: &mut AlooWorld, who: String, other: String) {
    let store = w.id_stores.get(&who).expect("no store for this perspective");
    let otp_only = store
        .devices_of(&other)
        .find(|d| d.key_mode.is_none())
        .expect("the pre-existing otp-only pin must still be present");
    let pq = store
        .devices_of(&other)
        .find(|d| d.key_mode == Some(KeyMode::PqHybrid))
        .expect("a fresh pq_hybrid pin must have been created");
    assert_eq!(otp_only.key, otp_only_key(&other), "the otp-only pin's key must be untouched");
    assert_eq!(pq.key, pq_hybrid_key(&other), "the fresh pin must carry the real pq_hybrid key");
    assert_eq!(
        store.devices_of(&other).count(),
        2,
        "exactly these two - nothing merged, nothing extra"
    );
}

#[then(expr = "{word} has a plain first-sighting pq_hybrid pin for {word}")]
async fn has_plain_first_sighting(w: &mut AlooWorld, who: String, other: String) {
    let store = w.id_stores.get(&who).expect("no store for this perspective");
    assert_eq!(
        store.devices_of(&other).count(),
        1,
        "exactly one entry - nothing pre-existing for it to coexist with"
    );
    let entry = store.devices_of(&other).next().expect("just asserted count == 1");
    assert_eq!(entry.key, pq_hybrid_key(&other));
    assert_eq!(entry.key_mode, Some(KeyMode::PqHybrid));
}

#[then(expr = "{word}'s pin for {word} is an ordinary silent match")]
async fn pin_is_silent_match(w: &mut AlooWorld, who: String, other: String) {
    let store = w.id_stores.get(&who).expect("no store for this perspective");
    assert_eq!(
        store.devices_of(&other).count(),
        1,
        "no review, no second entry - the pre-existing pin simply matched"
    );
    let entry = store.devices_of(&other).next().expect("just asserted count == 1");
    assert_eq!(entry.key, pq_hybrid_key(&other));
    assert_eq!(entry.device_id, "srv-device", "the original entry, not a new one");
}

// ---------------------------------------------------------------------
// Row 7: an identical key announced under a brand-new device still opens
// a review - identical bytes never silently merge into an unproven device.
// ---------------------------------------------------------------------

#[when(expr = "{word} is seen on device {string} with the pq_hybrid key {string}")]
async fn seen_on_device_pq(w: &mut AlooWorld, name: String, device: String, key: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    store.pin_new_device_with_key_mode(&name, &device, key.as_bytes(), Trust::Tofu, Some(KeyMode::PqHybrid));
}

#[then(expr = "{word}'s device {string} announcing the key {string} is not silently claimed")]
async fn not_silently_claimed(w: &mut AlooWorld, name: String, device: String, key: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    assert!(
        !store.claim_unbound(&name, &device, key.as_bytes(), Some(KeyMode::PqHybrid)),
        "identical bytes under a brand-new device_id must never auto-claim a bound entry"
    );
    assert_eq!(
        store.get_for_device(&name, &device),
        None,
        "nothing pinned yet for the new device - only a human Accept adds it"
    );
}

#[when(expr = "{word}'s device {string} is accepted with the key {string}")]
async fn device_accepted_with_key(w: &mut AlooWorld, name: String, device: String, key: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    store.accept_identity_review(&name, &device, key.as_bytes(), KeyMode::PqHybrid, Trust::Tofu);
}
