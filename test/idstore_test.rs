use aloo::client::idstore::{IdStore, Trust, default_path};
use aloo::proto::KeyMode;
use std::net::SocketAddr;
use std::path::PathBuf;

fn temp_store_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-idstore-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ))
}

fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

// ---------------------------------------------------------------------
// Loading / basic pinning
// ---------------------------------------------------------------------

/// @requirement AC-047, TB-093
#[test]
fn loading_a_missing_file_starts_empty_not_an_error() {
    let path = temp_store_path();
    let store = IdStore::load(&path).expect("missing file should not be an error");
    assert_eq!(store.get("alice"), None);
}

/// @requirement TB-093
#[test]
fn new_empty_starts_with_nothing_and_can_still_save() {
    let path = temp_store_path();
    let mut store = IdStore::new_empty(path.clone());
    assert_eq!(store.get("alice"), None);
    store.pin_new_device("alice", "dev-a", b"key-a", Trust::Tofu);
    store
        .save()
        .expect("save should succeed even though the store started as new_empty rather than load");
    assert!(path.is_file());
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Per-device pinning (§1/§2 of the device-pinning plan)
// ---------------------------------------------------------------------

/// @requirement AC-047
#[test]
fn first_sighting_of_a_device_is_retrievable_by_that_exact_device() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"key-a".as_slice()));
}

/// @requirement AC-047
#[test]
fn a_device_with_no_entry_is_none() {
    let path = temp_store_path();
    let store = IdStore::load(&path).unwrap();
    assert_eq!(store.get_for_device("alice", "laptop"), None);
}

/// Two devices for the same nickname are independent slots - pinning one
/// never touches the other. This is the additive rule (§1's "never
/// replacing") at the storage layer.
/// @requirement TB-087
#[test]
fn two_devices_for_one_nickname_are_pinned_independently() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-laptop", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert_eq!(
        store.get_for_device("alice", "laptop"),
        Some(b"key-laptop".as_slice())
    );
    assert_eq!(
        store.get_for_device("alice", "phone"),
        Some(b"key-phone".as_slice())
    );
    assert_eq!(
        store.devices_of("alice").count(),
        2,
        "both devices coexist"
    );
}

/// @requirement TB-087
#[test]
fn different_nicknames_are_tracked_independently() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "dev-a", b"key-a", Trust::Tofu);
    store.pin_new_device("bob", "dev-b", b"key-b", Trust::Tofu);
    assert_eq!(store.get_for_device("alice", "dev-a"), Some(b"key-a".as_slice()));
    assert_eq!(store.get_for_device("bob", "dev-b"), Some(b"key-b".as_slice()));
}

/// `replace_device_key` overwrites just the named device's key, leaving
/// every sibling device - and every other field of that same entry -
/// untouched. This is what `session::finalize_identity_pin`'s continuity
/// and mismatch-`Accept` paths are built from.
/// @requirement AC-048, TB-086
#[test]
fn replace_device_key_overwrites_only_the_named_device() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert!(store.replace_device_key("alice", "laptop", b"key-a-2"));
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"key-a-2".as_slice()));
    assert_eq!(
        store.get_for_device("alice", "phone"),
        Some(b"key-phone".as_slice()),
        "sibling device untouched"
    );
}

#[test]
fn replace_device_key_on_a_nonexistent_device_reports_nothing_updated() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(!store.replace_device_key("alice", "laptop", b"key-a"));
}

// ---------------------------------------------------------------------
// Unbound entries and claiming (§1's "filled in on first use")
// ---------------------------------------------------------------------

/// A key pinned with no device (the empty-string sentinel) is retrievable
/// under that exact empty device_id - the representation `claim_unbound`
/// resolves later.
#[test]
fn an_unbound_entry_is_stored_under_the_empty_device_id() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
    assert_eq!(store.get_for_device("alice", ""), Some(b"key-a".as_slice()));
}

/// The core "filled in on first use" behavior: an unbound entry whose key
/// matches a live connection's announced key is claimed in place - same
/// key, now attributed to a real device - rather than duplicated.
#[test]
fn claim_unbound_rewrites_the_device_id_in_place_on_a_matching_key() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
    assert!(store.claim_unbound("alice", "laptop", b"key-a", None));
    assert_eq!(store.get_for_device("alice", ""), None, "no longer unbound");
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"key-a".as_slice()));
    assert_eq!(store.devices_of("alice").count(), 1, "rewritten in place, not duplicated");
}

#[test]
fn claim_unbound_refuses_a_key_that_does_not_match() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
    assert!(!store.claim_unbound("alice", "laptop", b"key-b", None));
    assert_eq!(
        store.get_for_device("alice", ""),
        Some(b"key-a".as_slice()),
        "left exactly as it was"
    );
}

#[test]
fn claim_unbound_is_scoped_by_key_mode() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    // An unbound Direct-framed pin (key_mode None) must never be claimed
    // by a search for a pq_hybrid (Some) unbound entry with the same key
    // bytes, or the two independent trust dimensions (§1) would collide.
    store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
    assert!(!store.claim_unbound("alice", "laptop", b"key-a", Some(KeyMode::PqHybrid)));
}

// ---------------------------------------------------------------------
// accept_identity_review (AcceptIdentity handler / pin_identity_card):
// key_mode-scoped so the unbound sentinel, shared by every unbound entry
// regardless of kind, can never let one dimension corrupt the other.
// ---------------------------------------------------------------------

/// The ordinary, bound-device case: a device already known under a
/// different key gets that key overwritten in place.
#[test]
fn accept_identity_review_overwrites_a_known_devices_key_in_place() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-old", Trust::Tofu);
    store.set_key_mode("alice", "laptop", KeyMode::PqHybrid);
    store.accept_identity_review("alice", "laptop", b"key-new", KeyMode::PqHybrid, Trust::Tofu);
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"key-new".as_slice()));
    assert_eq!(store.devices_of("alice").count(), 1, "overwritten, not duplicated");
}

/// A genuinely new device is added additively, leaving siblings untouched.
#[test]
fn accept_identity_review_adds_a_new_device_without_touching_a_sibling() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-laptop", Trust::Tofu);
    store.set_key_mode("alice", "laptop", KeyMode::PqHybrid);
    store.accept_identity_review("alice", "phone", b"key-phone", KeyMode::PqHybrid, Trust::Tofu);
    assert_eq!(store.get_for_device("alice", "phone"), Some(b"key-phone".as_slice()));
    assert_eq!(
        store.get_for_device("alice", "laptop"),
        Some(b"key-laptop".as_slice()),
        "sibling device untouched"
    );
}

/// The rare unbound fallback (a review accepted before this connection's
/// device id was ever learned) must never corrupt an unrelated `Direct`
/// pin sharing the same empty device_id sentinel - the exact bug this
/// method exists to close (a blind `get_for_device(nickname, "")` lookup
/// would have found the `Direct` entry first and overwritten it with the
/// unrelated `pq_hybrid` key).
#[test]
fn accept_identity_review_on_the_unbound_fallback_never_touches_an_unrelated_direct_pin() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    // An unbound Direct-framed pin already exists (key_mode None) - e.g.
    // from the unknown-peer-confirm flow, §7.1.5.
    store.pin_new_device("alice", "", b"direct-key", Trust::Tofu);

    store.accept_identity_review("alice", "", b"pq-key", KeyMode::PqHybrid, Trust::Tofu);

    assert_eq!(
        store
            .devices_of("alice")
            .find(|d| d.key_mode.is_none())
            .map(|d| d.key.as_slice()),
        Some(b"direct-key".as_slice()),
        "the pre-existing Direct pin must survive untouched"
    );
    assert_eq!(
        store
            .devices_of("alice")
            .find(|d| d.key_mode == Some(KeyMode::PqHybrid))
            .map(|d| d.key.as_slice()),
        Some(b"pq-key".as_slice()),
        "the pq_hybrid review lands as its own, separate unbound entry"
    );
    assert_eq!(store.devices_of("alice").count(), 2);
}

/// Device-pinning plan §2/§7's reference table, server row 7: a nickname
/// pinned under two devices (d1, d2); a third device (d3) announces the
/// key **already pinned under d1** - identical bytes, copied rather than
/// regenerated (e.g. a `my_key` file literally copied to a second
/// machine). This must still open an impersonation review; identical key
/// bytes never silently merge into a device that never itself proved it
/// holds them. Mirrors `finalize_identity_pin`'s exact decision sequence
/// for "no entry for this device": `claim_unbound` first (fails - d1 is
/// bound, not unbound), then a continuity scan across every other device
/// (fails - nobody signs a continuity certificate for their own unchanged
/// key), so the only path left is the ordinary review; only a human
/// `Accept` (`accept_identity_review`) ever actually adds d3.
///
/// @requirement AC-048
#[test]
fn an_identical_key_already_pinned_under_a_different_device_still_requires_a_review() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "d1", b"key-a", Trust::Tofu);
    store.set_key_mode("alice", "d1", KeyMode::PqHybrid);
    store.pin_new_device("alice", "d2", b"key-b", Trust::Tofu);
    store.set_key_mode("alice", "d2", KeyMode::PqHybrid);

    // d3 announces exactly d1's key bytes - `claim_unbound` only ever
    // matches an *unbound* entry, so a bound d1 can never be silently
    // claimed by a new device_id no matter how exactly its key matches.
    assert!(
        !store.claim_unbound("alice", "d3", b"key-a", Some(KeyMode::PqHybrid)),
        "identical bytes must not let claim_unbound treat d3 as an unbound pin's owner"
    );
    assert_eq!(store.get_for_device("alice", "d3"), None, "d3 has no entry yet - nothing auto-added");
    // d1's and d2's own entries are completely undisturbed by d3's mere
    // announcement.
    assert_eq!(store.get_for_device("alice", "d1"), Some(b"key-a".as_slice()));
    assert_eq!(store.get_for_device("alice", "d2"), Some(b"key-b".as_slice()));
    assert_eq!(store.devices_of("alice").count(), 2, "still only the two devices a human actually vouched for");

    // Only an explicit Accept adds d3 - additively, leaving d1 and d2
    // exactly as they were.
    store.accept_identity_review("alice", "d3", b"key-a", KeyMode::PqHybrid, Trust::Tofu);
    assert_eq!(store.get_for_device("alice", "d3"), Some(b"key-a".as_slice()));
    assert_eq!(store.get_for_device("alice", "d1"), Some(b"key-a".as_slice()), "d1 untouched by d3's addition");
    assert_eq!(store.get_for_device("alice", "d2"), Some(b"key-b".as_slice()), "d2 untouched by d3's addition");
    assert_eq!(store.devices_of("alice").count(), 3);
}

#[test]
fn claim_unbound_on_an_unknown_nickname_reports_nothing_claimed() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(!store.claim_unbound("nobody", "laptop", b"key-a", None));
}

/// @requirement TB-090
#[test]
fn claim_unbound_refuses_an_unstorable_device_id() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
    assert!(!store.claim_unbound("alice", "evil\tdevice", b"key-a", None));
    assert_eq!(store.get_for_device("alice", ""), Some(b"key-a".as_slice()));
}

// ---------------------------------------------------------------------
// Rebinding (continuity certificates moving devices)
// ---------------------------------------------------------------------

#[test]
fn rebind_device_moves_an_entry_to_a_new_device_id() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "old-laptop", b"key-a", Trust::Tofu);
    assert!(store.rebind_device("alice", "old-laptop", "new-laptop"));
    assert_eq!(store.get_for_device("alice", "old-laptop"), None);
    assert_eq!(store.get_for_device("alice", "new-laptop"), Some(b"key-a".as_slice()));
}

#[test]
fn rebind_device_refuses_to_collide_with_an_existing_device() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-laptop", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert!(
        !store.rebind_device("alice", "laptop", "phone"),
        "would silently merge two distinct devices' history into one row"
    );
    assert_eq!(
        store.get_for_device("alice", "phone"),
        Some(b"key-phone".as_slice()),
        "phone's own entry is untouched by the refused rebind"
    );
}

#[test]
fn rebind_device_on_an_unknown_device_reports_nothing_rebound() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert!(!store.rebind_device("alice", "nonexistent", "new-name"));
}

// ---------------------------------------------------------------------
// `get`'s "most recently seen, or most recently pinned" default
// ---------------------------------------------------------------------

/// @requirement TB-094
#[test]
fn get_on_an_unknown_nickname_is_none() {
    let path = temp_store_path();
    let store = IdStore::load(&path).unwrap();
    assert_eq!(store.get("nobody"), None);
}

#[test]
fn get_returns_the_only_device_when_there_is_just_one() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert_eq!(store.get("alice"), Some(b"key-a".as_slice()));
}

/// When neither device has ever been confirmed reachable (`last_seen_unix`
/// unset for both), `get` falls back to whichever was pinned most
/// recently - the later `pin_new_device` call.
#[test]
fn get_prefers_the_most_recently_pinned_device_when_neither_has_been_seen() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-laptop", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert_eq!(store.get("alice"), Some(b"key-phone".as_slice()));
}

/// A device confirmed reachable more recently wins over one pinned more
/// recently but never (or less recently) seen - "most-recently-seen"
/// takes priority over pin order.
#[test]
fn get_prefers_the_most_recently_seen_device_over_pin_order() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-laptop", Trust::Tofu);
    let addr: SocketAddr = "203.0.113.7:9999".parse().unwrap();
    store.set_last_seen("alice", "laptop", addr);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert_eq!(
        store.get("alice"),
        Some(b"key-laptop".as_slice()),
        "laptop was actually confirmed reachable; phone never has been"
    );
}

// ---------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------

#[test]
fn mark_verified_upgrades_a_specific_devices_trust() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert!(store.mark_verified("alice", "laptop"));
    assert_eq!(store.trust_for_device("alice", "laptop"), Some(Trust::Verified));
    assert_eq!(
        store.trust_for_device("alice", "phone"),
        Some(Trust::Tofu),
        "sibling device's trust is untouched"
    );
}

#[test]
fn mark_verified_on_an_unpinned_device_reports_nothing_marked() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(!store.mark_verified("alice", "laptop"));
}

// ---------------------------------------------------------------------
// key_mode / pinned_from (per device)
// ---------------------------------------------------------------------

#[test]
fn set_key_mode_records_it_for_the_named_device_only() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    store.set_key_mode("alice", "laptop", KeyMode::PqHybrid);
    let laptop = store
        .devices_of("alice")
        .find(|d| d.device_id == "laptop")
        .unwrap();
    let phone = store
        .devices_of("alice")
        .find(|d| d.device_id == "phone")
        .unwrap();
    assert_eq!(laptop.key_mode, Some(KeyMode::PqHybrid));
    assert_eq!(phone.key_mode, None);
}

#[test]
fn set_pinned_from_records_it_for_the_named_device_only() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
    store.set_pinned_from("alice", "", PathBuf::from("/tmp/alice.card"));
    assert_eq!(
        store.pinned_from("alice"),
        Some(std::path::Path::new("/tmp/alice.card"))
    );
}

// ---------------------------------------------------------------------
// Deletion: whole-nickname vs. per-device (§3's additive delete)
// ---------------------------------------------------------------------

#[test]
fn remove_forgets_every_device_of_a_nickname() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert!(store.remove("alice"));
    assert_eq!(store.devices_of("alice").count(), 0);
    assert!(!store.nicknames().contains(&"alice".to_string()));
}

#[test]
fn remove_on_an_unknown_nickname_reports_nothing_removed() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(!store.remove("nobody"));
}

/// The additive rule applied to deletion: removing one device's entry
/// never touches its siblings.
#[test]
fn remove_device_removes_only_that_device_leaving_siblings_untouched() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    assert!(store.remove_device("alice", "laptop"));
    assert_eq!(store.get_for_device("alice", "laptop"), None);
    assert_eq!(
        store.get_for_device("alice", "phone"),
        Some(b"key-phone".as_slice()),
        "sibling untouched"
    );
}

#[test]
fn remove_device_drops_the_nickname_entirely_once_its_last_device_is_gone() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert!(store.remove_device("alice", "laptop"));
    assert!(
        !store.nicknames().contains(&"alice".to_string()),
        "no device left, so nicknames() must not list an empty entry"
    );
}

#[test]
fn remove_device_on_a_nonexistent_device_reports_nothing_removed() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert!(!store.remove_device("alice", "phone"));
}

// ---------------------------------------------------------------------
// nicknames()
// ---------------------------------------------------------------------

#[test]
fn nicknames_lists_every_pinned_contact_sorted_once_each() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("carol", "d1", b"key-c", Trust::Tofu);
    store.pin_new_device("alice", "d1", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "d2", b"key-a2", Trust::Tofu);
    store.pin_new_device("bob", "d1", b"key-b", Trust::Tofu);
    assert_eq!(store.nicknames(), vec!["alice", "bob", "carol"]);
}

#[test]
fn nicknames_is_empty_for_a_fresh_store() {
    let path = temp_store_path();
    let store = IdStore::load(&path).unwrap();
    assert!(store.nicknames().is_empty());
}

// ---------------------------------------------------------------------
// Injection guards
// ---------------------------------------------------------------------

/// @requirement TB-090
#[test]
fn a_nickname_containing_a_tab_is_never_pinned() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice\tevil", "dev", b"key-a", Trust::Tofu);
    assert_eq!(store.get_for_device("alice\tevil", "dev"), None, "never actually pinned");
}

#[test]
fn a_nickname_containing_a_newline_is_never_pinned() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice\nevil", "dev", b"key-a", Trust::Tofu);
    assert_eq!(store.get_for_device("alice\nevil", "dev"), None);
}

/// A device_id is peer-reported exactly like a nickname, so it gets the
/// same injection guard.
#[test]
fn a_device_id_containing_a_tab_is_never_pinned() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "evil\tdevice", b"key-a", Trust::Tofu);
    assert_eq!(store.get_for_device("alice", "evil\tdevice"), None);
}

// ---------------------------------------------------------------------
// Save / load round trips and on-disk format
// ---------------------------------------------------------------------

/// @requirement TB-088
#[test]
fn save_then_load_round_trips_the_full_key_bytes_per_device() {
    let path = temp_store_path();
    // Bytes that aren't valid UTF-8 or printable text - a real DER blob is
    // arbitrary binary, so the round trip needs to survive that, not just
    // ASCII-ish placeholder strings.
    let key_a: Vec<u8> = (0..=255u8).collect();
    let key_b: Vec<u8> = vec![0x00, 0xff, 0x10, 0xab, 0x00, 0x00];
    {
        let mut store = IdStore::load(&path).unwrap();
        store.pin_new_device("alice", "laptop", &key_a, Trust::Tofu);
        store.pin_new_device("bob", "phone", &key_b, Trust::Tofu);
        store.save().expect("save should succeed");
    }
    {
        let store = IdStore::load(&path).unwrap();
        assert_eq!(store.get_for_device("alice", "laptop"), Some(key_a.as_slice()));
        assert_eq!(store.get_for_device("bob", "phone"), Some(key_b.as_slice()));
    }
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-089
#[test]
fn save_creates_missing_parent_directories() {
    let dir = std::env::temp_dir().join(format!(
        "aloo-idstore-dir-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ));
    let path = dir.join("nested").join("ids_store");
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "dev", b"key-a", Trust::Tofu);
    store.save().expect("save should create parent dirs");
    assert!(path.is_file());
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-091
#[test]
fn default_path_always_resolves_under_the_dot_aloo_home_directory() {
    let path = default_path();
    assert_eq!(
        path.file_name(),
        Some(std::ffi::OsStr::new("ids_store")),
        "unexpected file name: {path:?}"
    );
    assert_eq!(
        path.parent().and_then(|p| p.file_name()),
        Some(std::ffi::OsStr::new(".aloo")),
        "the store must always live under ~/.aloo, never a local/cwd file: {path:?}"
    );
}

/// @requirement TB-092
#[test]
fn corrupted_lines_in_an_existing_file_are_skipped_not_fatal() {
    let path = temp_store_path();
    // "alice\tlaptop\t<hex for key-a>" is a valid line; "not-a-valid-line"
    // has no tabs so it's skipped; "carol" has an odd-length (invalid)
    // hex half; "bob\tphone\t<hex for key-b>" is valid again.
    std::fs::write(
        &path,
        "alice\tlaptop\t6b65792d61\nnot-a-valid-line\ncarol\tdev\tabc\nbob\tphone\t6b65792d62\n",
    )
    .unwrap();
    let store = IdStore::load(&path).expect("a partially-corrupt file should still load");
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"key-a".as_slice()));
    assert_eq!(store.get_for_device("bob", "phone"), Some(b"key-b".as_slice()));
    assert_eq!(store.get_for_device("carol", "dev"), None, "the corrupt line should not have been pinned");
    std::fs::remove_file(&path).ok();
}

/// This store's format is a breaking change with no migration path
/// (deliberate - see the device-pinning plan's §6): a file written by
/// the old, device-less format simply doesn't parse under the new
/// `nickname<TAB>device_id<TAB>hex<TAB>...` column shape and loads as
/// empty, exactly like any other unparseable line.
#[test]
fn an_old_format_file_predating_devices_loads_as_empty_not_an_error() {
    let path = temp_store_path();
    // Old format: nickname<TAB>hex<TAB>trust<TAB>... - no device_id
    // column, so `hex` (old column 2) is read as `device_id` here and
    // fails `is_storable`/parses as garbage hex, and the line is skipped.
    std::fs::write(&path, "alice\t6b65792d61\ttofu\t\t\t\tpqhybrid\t\n").unwrap();
    let store = IdStore::load(&path).expect("an unparseable file must still load, just empty");
    assert_eq!(store.get("alice"), None);
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-094
#[test]
fn get_reads_without_mutating_anything() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert_eq!(store.get("alice"), None, "nothing pinned yet");
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert_eq!(store.get("alice"), Some(b"key-a".as_slice()));
    assert_eq!(store.get("alice"), Some(b"key-a".as_slice()), "calling get again changes nothing");
}

/// @requirement TB-091
#[test]
fn on_disk_format_is_hex_encoded_not_raw_or_base64() {
    let path = temp_store_path();
    {
        let mut store = IdStore::load(&path).unwrap();
        store.pin_new_device("alice", "laptop", &[0xde, 0xad, 0xbe, 0xef], Trust::Tofu);
        store.save().unwrap();
    }
    let contents = std::fs::read_to_string(&path).unwrap();
    // nickname<TAB>device_id<TAB>hex<TAB>trust<TAB>last_addr<TAB>
    // last_seen_unix<TAB>key_mode<TAB>pinned_from - trailing five columns
    // empty until this device's key has gone `Active` at least once, been
    // recorded via `set_key_mode`, or been imported from a file.
    assert_eq!(contents, "alice\tlaptop\tdeadbeef\ttofu\t\t\t\t\n");
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Last-seen address (docs/PROTOCOL.md §12.7), per device
// ---------------------------------------------------------------------

/// @requirement AC-165
#[test]
fn last_addr_is_none_until_set() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert_eq!(store.last_addr("alice"), None);
}

/// @requirement AC-165
#[test]
fn set_last_seen_is_a_no_op_for_an_unpinned_device() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    let addr: SocketAddr = "203.0.113.7:9999".parse().unwrap();
    store.set_last_seen("nobody", "dev", addr);
    assert_eq!(store.last_addr("nobody"), None);
}

/// @requirement AC-165
#[test]
fn set_last_seen_records_address_for_the_named_device_only() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    store.pin_new_device("alice", "phone", b"key-phone", Trust::Tofu);
    let addr: SocketAddr = "203.0.113.7:9999".parse().unwrap();
    store.set_last_seen("alice", "laptop", addr);
    assert_eq!(store.last_addr("alice"), Some(addr), "laptop is the most-recently-seen default");
    let phone = store.devices_of("alice").find(|d| d.device_id == "phone").unwrap();
    assert_eq!(phone.last_addr, None, "phone untouched");
}

/// @requirement AC-165
#[test]
fn last_seen_survives_a_save_and_load_round_trip() {
    let path = temp_store_path();
    let addr: SocketAddr = "[::1]:4242".parse().unwrap();
    {
        let mut store = IdStore::load(&path).unwrap();
        store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
        store.set_last_seen("alice", "laptop", addr);
        store.save().unwrap();
    }
    let store = IdStore::load(&path).unwrap();
    assert_eq!(store.last_addr("alice"), Some(addr));
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-165, TB-198
#[test]
fn a_store_without_the_trailing_optional_columns_still_loads() {
    let path = temp_store_path();
    // Only nickname/device_id/hex/trust - every trailing column absent.
    std::fs::write(&path, "alice\tlaptop\t6b65792d61\ttofu\n").unwrap();
    let store = IdStore::load(&path).expect("must still load");
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"key-a".as_slice()));
    assert_eq!(store.last_addr("alice"), None);
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// key_mode / last_seen_unix survive round trips
// ---------------------------------------------------------------------

#[test]
fn key_mode_and_last_seen_survive_a_save_and_load_round_trip() {
    let path = temp_store_path();
    let addr: SocketAddr = "[::1]:4242".parse().unwrap();
    {
        let mut store = IdStore::load(&path).unwrap();
        store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
        store.set_key_mode("alice", "laptop", KeyMode::PqHybrid);
        store.set_last_seen("alice", "laptop", addr);
        store.save().unwrap();
    }
    let store = IdStore::load(&path).unwrap();
    assert_eq!(store.key_mode("alice"), Some(KeyMode::PqHybrid));
    assert!(store.last_seen_unix("alice").is_some());
    std::fs::remove_file(&path).ok();
}

#[test]
fn set_last_seen_stamps_a_wall_clock_time() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "laptop", b"key-a", Trust::Tofu);
    assert_eq!(store.last_seen_unix("alice"), None);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let addr: SocketAddr = "203.0.113.7:9999".parse().unwrap();
    store.set_last_seen("alice", "laptop", addr);
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let seen = store.last_seen_unix("alice").expect("stamped by set_last_seen");
    assert!(seen >= before && seen <= after, "{seen} not in [{before}, {after}]");
}

// ---------------------------------------------------------------------
// pinned_from survives round trips
// ---------------------------------------------------------------------

/// @requirement AC-301
#[test]
fn pinned_from_survives_a_save_and_load_round_trip() {
    let path = temp_store_path();
    {
        let mut store = IdStore::load(&path).unwrap();
        store.pin_new_device("alice", "", b"key-a", Trust::Tofu);
        store.set_pinned_from("alice", "", PathBuf::from("/tmp/alice.card"));
        store.save().unwrap();
    }
    let store = IdStore::load(&path).unwrap();
    assert_eq!(store.pinned_from("alice"), Some(std::path::Path::new("/tmp/alice.card")));
    std::fs::remove_file(&path).ok();
}

// ---------------------------------------------------------------------
// Bare contacts (Add Contact with no identity card - device-pinning
// plan §3's "the identity card is optional")
// ---------------------------------------------------------------------

/// A bound placeholder shows up as a device of its nickname (so it's a
/// real row in the Contacts list) but is invisible to `get_for_device` -
/// it has no key, so there is nothing to "get".
/// @requirement AC-366
#[test]
fn pin_bare_contact_reserves_a_bound_device_with_no_key() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(store.pin_bare_contact("alice", "laptop"));
    assert_eq!(store.get_for_device("alice", "laptop"), None);
    assert_eq!(store.devices_of("alice").count(), 1, "the placeholder is still a real row");
    std::fs::remove_file(&path).ok();
}

/// A blank device_id reserves the nickname's shared unbound slot instead.
/// @requirement AC-366
#[test]
fn pin_bare_contact_with_no_device_id_reserves_the_unbound_slot() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(store.pin_bare_contact("alice", ""));
    assert_eq!(store.get_for_device("alice", ""), None);
    assert_eq!(store.devices_of("alice").count(), 1);
    std::fs::remove_file(&path).ok();
}

/// Reserving the same bound device_id twice must not produce two rows.
/// @requirement AC-366
#[test]
fn pin_bare_contact_refuses_a_device_already_pinned_bare_or_real() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert!(store.pin_bare_contact("alice", "laptop"));
    assert!(!store.pin_bare_contact("alice", "laptop"), "already reserved - not a second placeholder");
    store.pin_new_device("bob", "phone", b"key-b", Trust::Tofu);
    assert!(!store.pin_bare_contact("bob", "phone"), "a real pin refuses a bare placeholder over it too");
    std::fs::remove_file(&path).ok();
}

/// A nickname that already has an unbound `Direct`-framed pin (key_mode
/// `None`, a real key) must refuse a bare unbound placeholder too - the
/// two would share the same slot and be indistinguishable.
/// @requirement AC-366
#[test]
fn pin_bare_contact_with_no_device_id_refuses_when_an_unbound_direct_pin_already_exists() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_new_device("alice", "", b"direct-key", Trust::Tofu);
    assert!(!store.pin_bare_contact("alice", ""));
    assert_eq!(store.devices_of("alice").count(), 1, "no second unbound entry was pushed");
    std::fs::remove_file(&path).ok();
}

/// The core invariant a bare placeholder exists to uphold: pinning a real
/// key at the exact same `(nickname, device_id)` later - whether via a
/// live TOFU sighting or an explicit card import, both go through
/// `pin_new_device_with_key_mode` - fills the placeholder in place rather
/// than leaving it behind as a second, ghost row.
/// @requirement AC-366
#[test]
fn pinning_a_real_key_over_a_bound_placeholder_fills_it_in_place_not_a_duplicate() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_bare_contact("alice", "laptop");
    store.pin_new_device_with_key_mode(
        "alice",
        "laptop",
        b"real-key",
        Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );
    assert_eq!(store.devices_of("alice").count(), 1, "the placeholder must be filled, not duplicated");
    assert_eq!(store.get_for_device("alice", "laptop"), Some(b"real-key".as_slice()));
    std::fs::remove_file(&path).ok();
}

/// Same invariant for the unbound slot: importing a card (or any other
/// unbound pin) over a bare unbound placeholder must resolve it in place.
/// @requirement AC-366
#[test]
fn pinning_a_real_key_over_an_unbound_placeholder_fills_it_in_place_not_a_duplicate() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_bare_contact("alice", "");
    store.pin_new_device_with_key_mode("alice", "", b"card-key", Trust::Verified, Some(KeyMode::PqHybrid));
    assert_eq!(store.devices_of("alice").count(), 1);
    assert_eq!(store.get_for_device("alice", ""), Some(b"card-key".as_slice()));
    std::fs::remove_file(&path).ok();
}

/// A nickname whose only entry is a bare placeholder must read as "no
/// candidates yet" (`New`), not `Mismatch` - a placeholder is not a real
/// key to compare a live connection's announced key against.
/// @requirement AC-366
#[test]
fn check_key_treats_a_nickname_with_only_a_bare_placeholder_as_new() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_bare_contact("alice", "laptop");
    assert_eq!(store.check_key("alice", b"anything"), aloo::client::idstore::KeyCheck::New);
    std::fs::remove_file(&path).ok();
}

/// `get`/`most_recent_device_id` must skip a bare placeholder too - it
/// has no key, so it can never be "the" key for a nickname.
/// @requirement AC-366
#[test]
fn get_skips_a_bare_placeholder_and_falls_back_to_a_real_device() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_bare_contact("alice", "phone");
    store.pin_new_device("alice", "laptop", b"real-key", Trust::Tofu);
    assert_eq!(store.get("alice"), Some(b"real-key".as_slice()));
    assert_eq!(store.most_recent_device_id("alice"), Some("laptop"));
    std::fs::remove_file(&path).ok();
}

/// If every device of a nickname is a bare placeholder, `get` must report
/// nothing rather than an empty slice.
/// @requirement AC-366
#[test]
fn get_returns_none_when_every_device_is_a_bare_placeholder() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.pin_bare_contact("alice", "phone");
    assert_eq!(store.get("alice"), None);
    std::fs::remove_file(&path).ok();
}
