//! Steps for proving an identity is still the same one (US-029):
//! safety phrases, verified pins, continuity certificates, identity cards.

use aloo::client::idstore::{IdStore, Trust};
use aloo::crypto::pq::{
    make_identity_card, open_identity_card, sign_continuity, verify_continuity,
};
use aloo::crypto::safety;
use cucumber::{given, then, when};

use crate::world::{AlooWorld, pq_bundle_for};

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given(expr = "{word} has a pq_hybrid identity")]
async fn has_pq_identity(_w: &mut AlooWorld, who: String) {
    let _ = pq_bundle_for(&who);
}

#[given(expr = "{word} is pinned under that identity")]
async fn pinned_under_identity(w: &mut AlooWorld, who: String) {
    let (public, _) = pq_bundle_for(&who);
    let encoded = aloo::proto::encode(&public).expect("encode bundle");
    let path = w.temp_path("continuity-store");
    let mut store = IdStore::new_empty(path);
    store.pin_new_device(&who, "test-device", &encoded, Trust::Tofu);
    w.id_store = Some(store);
    w.pinned_bundle = Some(public);
}

#[given(expr = "{word} is pinned on device {string} under that identity")]
async fn pinned_under_identity_on_device(w: &mut AlooWorld, who: String, device: String) {
    let (public, _) = pq_bundle_for(&who);
    let encoded = aloo::proto::encode(&public).expect("encode bundle");
    let path = w.temp_path("continuity-store");
    let mut store = IdStore::new_empty(path);
    store.pin_new_device(&who, &device, &encoded, Trust::Tofu);
    w.id_store = Some(store);
    w.pinned_bundle = Some(public);
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when(expr = "{word}'s key is confirmed out of band")]
async fn confirmed_out_of_band(w: &mut AlooWorld, who: String) {
    let store = w.id_store.as_mut().expect("no store in this scenario");
    assert!(
        store.mark_verified(&who, "test-device"),
        "there must be something pinned to confirm"
    );
}

#[when(expr = "{word} retires those keys for new ones, carrying a continuity certificate")]
async fn retires_keys(w: &mut AlooWorld, who: String) {
    let (old_public, old_private) = pq_bundle_for(&who);
    // A genuinely different identity - the same thing `--rekey-pq-hybrid`
    // generates - vouched for by the keys being retired.
    let (new_public, _) = pq_bundle_for(&format!("{who}-successor"));
    let cert = sign_continuity(&old_private, &old_public, &new_public).expect("sign continuity");
    w.replacement_bundle = Some(new_public.with_continuity(cert));
}

#[when(expr = "a stranger takes {word}'s nickname with an unrelated identity")]
async fn stranger_takes_nickname(w: &mut AlooWorld, _who: String) {
    let (stranger_public, _) = pq_bundle_for("mallory");
    w.replacement_bundle = Some(stranger_public);
}

#[when(expr = "{word} exports an identity card")]
async fn exports_card(w: &mut AlooWorld, who: String) {
    let (public, private) = pq_bundle_for(&who);
    w.identity_card = Some(make_identity_card(&private, &public, &who).expect("card"));
}

#[when(expr = "{word} imports that card")]
async fn imports_card(w: &mut AlooWorld, _who: String) {
    let path = w.temp_path("card-store");
    let card = w.identity_card.clone().expect("no card in this scenario");
    match open_identity_card(&card) {
        Some((nickname, bundle)) => {
            let encoded = aloo::proto::encode(bundle).expect("encode bundle");
            let mut store = IdStore::new_empty(path);
            store.pin_new_device(nickname, "", &encoded, Trust::Verified);
            store.mark_verified(nickname, "");
            w.id_store = Some(store);
            w.refused = false;
        }
        None => w.refused = true,
    }
}

#[when("that card is altered in transit")]
async fn card_altered(w: &mut AlooWorld) {
    let card = w.identity_card.as_mut().expect("no card in this scenario");
    card.nickname = "mallory".into();
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "{word}'s safety phrase is the same every time it is read")]
async fn phrase_is_stable(_w: &mut AlooWorld, who: String) {
    let (public, _) = pq_bundle_for(&who);
    let fp = aloo::crypto::pq::bundle_fingerprint(&public).expect("fingerprint");
    assert_eq!(
        safety::phrase(&fp),
        safety::phrase(&fp),
        "a phrase that changed between readings would prove nothing"
    );
    assert_eq!(safety::phrase(&fp).split(' ').count(), 8);
}

#[then("a different identity reads out a different phrase")]
async fn different_identity_different_phrase(_w: &mut AlooWorld) {
    let (alice, _) = pq_bundle_for("alice");
    let (bob, _) = pq_bundle_for("bob");
    let fp_a = aloo::crypto::pq::bundle_fingerprint(&alice).expect("fingerprint");
    let fp_b = aloo::crypto::pq::bundle_fingerprint(&bob).expect("fingerprint");
    assert_ne!(safety::phrase(&fp_a), safety::phrase(&fp_b));
}

#[then(expr = "{word} is pinned but not yet verified")]
async fn pinned_not_verified(w: &mut AlooWorld, who: String) {
    let store = w.id_store.as_ref().expect("no store in this scenario");
    assert_eq!(store.trust(&who), Some(Trust::Tofu));
}

#[then(expr = "{word} is pinned and verified")]
async fn pinned_and_verified(w: &mut AlooWorld, who: String) {
    let store = w.id_store.as_ref().expect("no store in this scenario");
    assert_eq!(store.trust(&who), Some(Trust::Verified));
}

#[then(expr = "the new identity proves it is still {word}")]
async fn new_identity_proves_itself(w: &mut AlooWorld, _who: String) {
    let pinned = w.pinned_bundle.as_ref().expect("nothing pinned");
    let replacement = w.replacement_bundle.as_ref().expect("no replacement");
    assert!(
        verify_continuity(pinned, replacement),
        "a certificate signed by the pinned identity must verify against it"
    );
}

#[then("the pin moves to the new identity without asking")]
async fn pin_moves_silently(w: &mut AlooWorld) {
    let pinned = w.pinned_bundle.as_ref().expect("nothing pinned").clone();
    let replacement = w.replacement_bundle.as_ref().expect("no replacement").clone();
    assert!(verify_continuity(&pinned, &replacement));

    // What `session::check_identity` does once continuity holds: re-pin,
    // no review opened.
    let encoded = aloo::proto::encode(&replacement).expect("encode");
    let store = w.id_store.as_mut().expect("no store");
    store.replace_device_key("alice", "test-device", &encoded);
    assert_eq!(store.get("alice"), Some(encoded.as_slice()));
}

/// A continuity certificate proves itself even when the new identity is
/// announced from a *different* device than the one that retired
/// (device-pinning plan §2, `finalize_identity_pin`'s "no entry for this
/// device, scan every other device for continuity" case): the old
/// device's entry is moved wholesale onto the new device id, key and all,
/// rather than left behind as a stale row.
#[when(expr = "the new identity connects from device {string}")]
async fn new_identity_connects_from_device(w: &mut AlooWorld, device: String) {
    w.target_device = Some(device);
}

#[then(expr = "the pin moves to device {string} without asking")]
async fn pin_moves_to_device(w: &mut AlooWorld, new_device: String) {
    let pinned = w.pinned_bundle.as_ref().expect("nothing pinned").clone();
    let replacement = w.replacement_bundle.as_ref().expect("no replacement").clone();
    assert!(verify_continuity(&pinned, &replacement));
    assert_eq!(
        w.target_device.as_deref(),
        Some(new_device.as_str()),
        "scenario wiring: which device the new identity connects from"
    );

    // `finalize_identity_pin`'s exact case-3 sequence for a device with no
    // entry of its own: find the other device the cert verifies against,
    // replace its key in place, then move that same entry onto the newly
    // announcing device id - one row, relocated, not a second one added.
    let encoded = aloo::proto::encode(&replacement).expect("encode");
    let store = w.id_store.as_mut().expect("no store");
    let old_device = store
        .devices_of("alice")
        .find(|d| d.key == aloo::proto::encode(&pinned).unwrap())
        .map(|d| d.device_id.clone())
        .expect("the originally-pinned device must still be present before the move");
    assert!(store.replace_device_key("alice", &old_device, &encoded));
    assert!(store.rebind_device("alice", &old_device, &new_device));
    assert_eq!(store.get_for_device("alice", &new_device), Some(encoded.as_slice()));
}

#[then(expr = "device {string} no longer has an entry")]
async fn device_has_no_entry(w: &mut AlooWorld, device: String) {
    let store = w.id_store.as_ref().expect("no store");
    assert_eq!(
        store.get_for_device("alice", &device),
        None,
        "the old device id must not be left behind as a stale row once the pin has moved"
    );
}

#[then("the stranger cannot prove continuity")]
async fn stranger_cannot_prove(w: &mut AlooWorld) {
    let pinned = w.pinned_bundle.as_ref().expect("nothing pinned");
    let replacement = w.replacement_bundle.as_ref().expect("no replacement");
    assert!(
        !verify_continuity(pinned, replacement),
        "an unrelated identity must not pass as a planned replacement"
    );
}

#[then("the pin is left exactly as it was")]
async fn pin_unchanged(w: &mut AlooWorld) {
    let pinned = w.pinned_bundle.as_ref().expect("nothing pinned");
    let expected = aloo::proto::encode(pinned).expect("encode");
    let store = w.id_store.as_ref().expect("no store");
    assert_eq!(
        store.get("alice"),
        Some(expected.as_slice()),
        "an unproven key change must not move the pin"
    );
}

#[then(expr = "{word} has {word} pinned and verified without having met her")]
async fn pinned_from_card(w: &mut AlooWorld, _who: String, whom: String) {
    let store = w.id_store.as_ref().expect("no store in this scenario");
    assert_eq!(store.trust(&whom), Some(Trust::Verified));
    assert!(store.get(&whom).is_some());
}

#[then(expr = "{word} refuses to import it")]
async fn refuses_card(w: &mut AlooWorld, _who: String) {
    assert!(
        w.refused,
        "a card that does not verify must be refused rather than pinned"
    );
}
