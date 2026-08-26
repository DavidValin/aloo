//! `client::device_id`: the persistent per-nickname id sent alongside a P2P
//! connection attempt and shown in the impersonation review popup
//! (`docs/PROTOCOL.md` §12.7).

use aloo::client::device_id::{accept_announced, generate_unique_for_test, load_or_create};
use std::collections::HashSet;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_path(tag: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("aloo-device-id-{tag}-{}-{nanos}", std::process::id()))
}

/// @requirement AC-164
#[test]
fn creates_an_8_character_lowercase_hex_id_when_the_nickname_is_missing() {
    let path = temp_path("fresh");
    let id = load_or_create(&path, "alice").unwrap();
    assert_eq!(id.len(), 8);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert!(path.exists());
    let _ = fs::remove_file(&path);
}

/// @requirement AC-164
#[test]
fn reuses_the_existing_id_for_the_same_nickname_instead_of_regenerating() {
    let path = temp_path("reuse");
    let first = load_or_create(&path, "alice").unwrap();
    let second = load_or_create(&path, "alice").unwrap();
    assert_eq!(first, second);
    let _ = fs::remove_file(&path);
}

/// @requirement AC-164
#[test]
fn two_different_nicknames_on_the_same_machine_get_different_ids() {
    let path = temp_path("multi");
    let alice = load_or_create(&path, "alice").unwrap();
    let bob = load_or_create(&path, "bob").unwrap();
    assert_ne!(
        alice, bob,
        "device ids are scoped per nickname, not shared across a machine's nicknames"
    );
    assert_eq!(load_or_create(&path, "alice").unwrap(), alice);
    assert_eq!(load_or_create(&path, "bob").unwrap(), bob);
    let _ = fs::remove_file(&path);
}

#[test]
fn creates_missing_parent_directories() {
    let path = temp_path("nested").join("d_id");
    assert!(load_or_create(&path, "alice").is_ok());
    assert!(path.exists());
    let _ = fs::remove_dir_all(path.parent().unwrap());
}

/// @requirement AC-164
#[test]
fn a_pre_scoping_bare_id_line_is_ignored_and_a_fresh_scoped_one_is_generated() {
    let path = temp_path("legacy");
    fs::write(&path, "3f9a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60\n").unwrap();
    let id = load_or_create(&path, "alice").unwrap();
    assert_eq!(
        id.len(),
        8,
        "an old un-keyed 50-char id has no nickname field to reuse under"
    );
    let _ = fs::remove_file(&path);
}

/// @requirement AC-164
#[test]
fn generate_unique_never_returns_an_id_already_on_file() {
    let taken: HashSet<String> = ["11111111", "22222222", "33333333"]
        .into_iter()
        .map(String::from)
        .collect();
    for _ in 0..200 {
        let id = generate_unique_for_test(&taken);
        assert!(!taken.contains(&id), "collision-avoidance loop must skip every taken id");
    }
}

#[test]
fn a_normal_device_id_is_accepted() {
    assert_eq!(accept_announced(b"3f9a1b2c"), Some("3f9a1b2c".to_string()));
}

#[test]
fn an_empty_announced_device_id_is_refused() {
    assert_eq!(
        accept_announced(b""),
        None,
        "empty is the unbound sentinel - a peer must never be able to claim it"
    );
}

#[test]
fn non_utf8_bytes_are_refused() {
    assert_eq!(accept_announced(&[0xff, 0xfe, 0xfd]), None);
}

#[test]
fn a_tab_containing_announced_device_id_is_refused() {
    assert_eq!(
        accept_announced(b"abc\tdef"),
        None,
        "a tab would corrupt this file's nickname\\tdevice_id line format"
    );
}
