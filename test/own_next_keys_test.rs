use aloo::crypto::{self, KeyPair};
use aloo::own_next_keys::{OwnNextKeys, default_path};
use std::path::PathBuf;

fn temp_store_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "aloo-own-next-keys-test-{}-{}",
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

/// @requirement TB-093
#[test]
fn loading_a_missing_file_starts_empty_not_an_error() {
    let path = temp_store_path();
    let store = OwnNextKeys::load(&path).expect("missing file should not be an error");
    assert!(store.get("alice").is_none());
}

/// @requirement TB-095
#[test]
fn set_then_get_returns_a_usable_key() {
    let path = temp_store_path();
    let mut store = OwnNextKeys::load(&path).unwrap();
    let kp = KeyPair::generate().unwrap();
    let public = kp.public.clone();
    store.set("alice", kp.private);

    let got = store.get("alice").expect("just set");
    let blocks = crypto::encrypt_chunked(&public, b"resume proof").unwrap();
    let out = crypto::decrypt_chunked(got, &blocks).unwrap();
    assert_eq!(out, b"resume proof");
}

/// @requirement TB-095
#[test]
fn set_overwrites_the_previous_key_for_the_same_nickname() {
    let path = temp_store_path();
    let mut store = OwnNextKeys::load(&path).unwrap();
    let kp1 = KeyPair::generate().unwrap();
    let kp2 = KeyPair::generate().unwrap();
    let der1 = crypto::private_key_to_der(&kp1.private).unwrap();
    let der2 = crypto::private_key_to_der(&kp2.private).unwrap();

    store.set("alice", kp1.private);
    assert_eq!(
        crypto::private_key_to_der(store.get("alice").unwrap()).unwrap(),
        der1
    );

    store.set("alice", kp2.private);
    let current = crypto::private_key_to_der(store.get("alice").unwrap()).unwrap();
    assert_eq!(current, der2);
    assert_ne!(current, der1, "the old key must not still be reachable");
}

/// @requirement TB-087
#[test]
fn different_nicknames_are_tracked_independently() {
    let path = temp_store_path();
    let mut store = OwnNextKeys::load(&path).unwrap();
    let kp_alice = KeyPair::generate().unwrap();
    let kp_bob = KeyPair::generate().unwrap();
    let der_alice = crypto::private_key_to_der(&kp_alice.private).unwrap();
    let der_bob = crypto::private_key_to_der(&kp_bob.private).unwrap();

    store.set("alice", kp_alice.private);
    store.set("bob", kp_bob.private);

    assert_eq!(
        crypto::private_key_to_der(store.get("alice").unwrap()).unwrap(),
        der_alice
    );
    assert_eq!(
        crypto::private_key_to_der(store.get("bob").unwrap()).unwrap(),
        der_bob
    );
}

/// @requirement TB-088
#[test]
fn save_then_load_round_trips_a_usable_private_key() {
    let path = temp_store_path();
    let kp = KeyPair::generate().unwrap();
    let public = kp.public.clone();
    {
        let mut store = OwnNextKeys::load(&path).unwrap();
        store.set("alice", kp.private);
        store.save().expect("save should succeed");
    }
    {
        let store = OwnNextKeys::load(&path).unwrap();
        let restored = store.get("alice").expect("should survive the round trip");
        let blocks = crypto::encrypt_chunked(&public, b"still works after reload").unwrap();
        let out = crypto::decrypt_chunked(restored, &blocks).unwrap();
        assert_eq!(out, b"still works after reload");
    }
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-089
#[test]
fn save_creates_missing_parent_directories() {
    let dir = std::env::temp_dir().join(format!(
        "aloo-own-next-keys-dir-test-{}-{}",
        std::process::id(),
        fastrand_seed()
    ));
    let path = dir.join("nested").join("own_next_keys");
    let mut store = OwnNextKeys::load(&path).unwrap();
    store.set("alice", KeyPair::generate().unwrap().private);
    store.save().expect("save should create parent dirs");
    assert!(path.is_file());
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-090
#[test]
fn a_nickname_containing_a_tab_is_never_stored() {
    let path = temp_store_path();
    let mut store = OwnNextKeys::load(&path).unwrap();
    store.set("alice\tevil", KeyPair::generate().unwrap().private);
    assert!(store.get("alice\tevil").is_none());
}

/// @requirement TB-091
#[test]
fn default_path_always_resolves_under_the_dot_aloo_home_directory() {
    let path = default_path();
    assert_eq!(
        path.file_name(),
        Some(std::ffi::OsStr::new("own_next_keys")),
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
    let kp = KeyPair::generate().unwrap();
    let der_hex = {
        let der = crypto::private_key_to_der(&kp.private).unwrap();
        der.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    std::fs::write(
        &path,
        format!("alice\t{der_hex}\nnot-a-valid-line\ncarol\tabc\nbob\tdeadbeef\n"),
    )
    .unwrap();
    let store = OwnNextKeys::load(&path).expect("a partially-corrupt file should still load");
    assert!(
        store.get("alice").is_some(),
        "the one genuinely valid entry should load"
    );
    assert!(
        store.get("carol").is_none(),
        "odd-length hex should be skipped"
    );
    assert!(
        store.get("bob").is_none(),
        "valid hex that isn't a real PKCS8 key should be skipped"
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-093
#[test]
fn new_empty_starts_with_nothing_and_can_still_save() {
    let path = temp_store_path();
    let mut store = OwnNextKeys::new_empty(path.clone());
    assert!(store.get("alice").is_none());
    store.set("alice", KeyPair::generate().unwrap().private);
    store.save().unwrap();
    assert!(path.is_file());
    std::fs::remove_file(&path).ok();
}
