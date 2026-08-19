//! `client::device_id`: the persistent per-machine id sent alongside a P2P
//! connection attempt and shown in the impersonation review popup
//! (`docs/PROTOCOL.md` §12.7).

use aloo::client::device_id::load_or_create;
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
fn creates_a_50_character_lowercase_hex_id_when_the_file_is_missing() {
    let path = temp_path("fresh");
    let id = load_or_create(&path).unwrap();
    assert_eq!(id.len(), 50);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    assert!(path.exists());
    let _ = fs::remove_file(&path);
}

/// @requirement AC-164
#[test]
fn reuses_the_existing_id_instead_of_regenerating() {
    let path = temp_path("reuse");
    let first = load_or_create(&path).unwrap();
    let second = load_or_create(&path).unwrap();
    assert_eq!(first, second);
    let _ = fs::remove_file(&path);
}

#[test]
fn creates_missing_parent_directories() {
    let path = temp_path("nested").join("d_id");
    assert!(load_or_create(&path).is_ok());
    assert!(path.exists());
    let _ = fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn trims_a_hand_edited_trailing_newline() {
    let path = temp_path("trim");
    fs::write(&path, "abc123\n").unwrap();
    assert_eq!(load_or_create(&path).unwrap(), "abc123");
    let _ = fs::remove_file(&path);
}
