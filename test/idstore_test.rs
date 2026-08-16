use aloo::client::idstore::{IdCheck, IdStore, default_path};
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

/// @requirement AC-047, TB-093
#[test]
fn loading_a_missing_file_starts_empty_not_an_error() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).expect("missing file should not be an error");
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::New);
}

/// @requirement TB-093
#[test]
fn new_empty_starts_with_nothing_and_can_still_save() {
    let path = temp_store_path();
    let mut store = IdStore::new_empty(path.clone());
    assert_eq!(store.get("alice"), None);
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::New);
    store
        .save()
        .expect("save should succeed even though the store started as new_empty rather than load");
    assert!(path.is_file());
    std::fs::remove_file(&path).ok();
}

/// @requirement AC-047
#[test]
fn first_sighting_of_a_nickname_is_new() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::New);
}

/// @requirement AC-047
#[test]
fn same_nickname_same_key_is_a_match() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.check_and_pin("alice", b"key-a");
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::Match);
}

/// @requirement AC-048, TB-086
#[test]
fn same_nickname_different_key_is_a_mismatch() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.check_and_pin("alice", b"key-a");
    let result = store.check_and_pin("alice", b"key-b");
    assert_eq!(
        result,
        IdCheck::Mismatch {
            previous_public_key_der: b"key-a".to_vec()
        }
    );
    // the nickname is re-pinned to the new key regardless
    assert_eq!(store.check_and_pin("alice", b"key-b"), IdCheck::Match);
}

/// @requirement TB-087
#[test]
fn different_nicknames_are_tracked_independently() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    store.check_and_pin("alice", b"key-a");
    assert_eq!(store.check_and_pin("bob", b"key-b"), IdCheck::New);
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::Match);
}

/// @requirement TB-088
#[test]
fn save_then_load_round_trips_the_full_key_bytes() {
    let path = temp_store_path();
    // Bytes that aren't valid UTF-8 or printable text - a real DER blob is
    // arbitrary binary, so the round trip needs to survive that, not just
    // ASCII-ish placeholder strings.
    let key_a: Vec<u8> = (0..=255u8).collect();
    let key_b: Vec<u8> = vec![0x00, 0xff, 0x10, 0xab, 0x00, 0x00];
    {
        let mut store = IdStore::load(&path).unwrap();
        store.check_and_pin("alice", &key_a);
        store.check_and_pin("bob", &key_b);
        store.save().expect("save should succeed");
    }
    {
        let mut store = IdStore::load(&path).unwrap();
        assert_eq!(store.check_and_pin("alice", &key_a), IdCheck::Match);
        assert_eq!(store.check_and_pin("bob", &key_b), IdCheck::Match);
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
    store.check_and_pin("alice", b"key-a");
    store.save().expect("save should create parent dirs");
    assert!(path.is_file());
    std::fs::remove_dir_all(&dir).ok();
}

/// @requirement TB-090
#[test]
fn a_nickname_containing_a_tab_is_never_pinned() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    // A malicious display_name could contain a tab/newline, which are the
    // on-disk delimiters - accepting it would let a remote peer inject
    // extra records into a purely local trust file.
    assert_eq!(store.check_and_pin("alice\tevil", b"key-a"), IdCheck::New);
    assert_eq!(
        store.check_and_pin("alice\tevil", b"key-a"),
        IdCheck::New,
        "never actually pinned"
    );
    assert_eq!(store.check_and_pin("alice\nevil", b"key-a"), IdCheck::New);
    assert_eq!(
        store.check_and_pin("alice\nevil", b"key-a"),
        IdCheck::New,
        "never actually pinned"
    );
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
    // "alice"/6b6579 61 = hex for "key-a"; "not-a-valid-line" has no tab so
    // it's skipped; "carol" has an odd-length (invalid) hex half.
    std::fs::write(
        &path,
        "alice\t6b65792d61\nnot-a-valid-line\ncarol\tabc\nbob\t6b65792d62\n",
    )
    .unwrap();
    let mut store = IdStore::load(&path).expect("a partially-corrupt file should still load");
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::Match);
    assert_eq!(store.check_and_pin("bob", b"key-b"), IdCheck::Match);
    assert_eq!(
        store.check_and_pin("carol", b"anything"),
        IdCheck::New,
        "the corrupt line should not have been pinned"
    );
    std::fs::remove_file(&path).ok();
}

/// @requirement TB-094
#[test]
fn get_reads_a_pinned_entry_without_mutating_anything() {
    let path = temp_store_path();
    let mut store = IdStore::load(&path).unwrap();
    assert_eq!(store.get("alice"), None, "nothing pinned yet");
    store.check_and_pin("alice", b"key-a");
    assert_eq!(store.get("alice"), Some(b"key-a".as_slice()));
    // calling get again must not change anything a subsequent check_and_pin sees
    assert_eq!(store.get("alice"), Some(b"key-a".as_slice()));
    assert_eq!(store.check_and_pin("alice", b"key-a"), IdCheck::Match);
}

/// @requirement TB-094
#[test]
fn get_on_an_unknown_nickname_is_none() {
    let path = temp_store_path();
    let store = IdStore::load(&path).unwrap();
    assert_eq!(store.get("nobody"), None);
}

/// @requirement TB-091
#[test]
fn on_disk_format_is_hex_encoded_not_raw_or_base64() {
    let path = temp_store_path();
    {
        let mut store = IdStore::load(&path).unwrap();
        store.check_and_pin("alice", &[0xde, 0xad, 0xbe, 0xef]);
        store.save().unwrap();
    }
    let contents = std::fs::read_to_string(&path).unwrap();
    // Third column is how much the pin is worth (docs/PROTOCOL.md 12.7);
    // a fresh sighting is trusted-on-first-use until a human says more.
    assert_eq!(contents, "alice\tdeadbeef\ttofu\n");
    std::fs::remove_file(&path).ok();
}
