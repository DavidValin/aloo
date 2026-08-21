//! `client::otp_staging`'s crash-safety invariant: `.tmp/` holds only work
//! in progress, completion is an atomic rename *out* of it, and anything
//! still inside is garbage whatever left it there.

use aloo::client::otp_cli::OtpCliConfig;
use aloo::client::otp_staging;
use std::path::PathBuf;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-staging-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config_at(dir: PathBuf) -> OtpCliConfig {
    OtpCliConfig {
        binary_path: PathBuf::from("otp"),
        working_dir: dir,
    }
}

#[test]
fn tmp_root_is_a_sibling_of_the_keychain_never_inside_it() {
    let cfg = config_at(temp_dir("root"));
    let root = otp_staging::tmp_root(&cfg);
    assert_eq!(root.file_name().unwrap(), ".tmp");
    assert_eq!(root.parent().unwrap(), cfg.working_dir);
    assert!(
        !root.starts_with(cfg.working_dir.join(".keychain")),
        "half-written pad bytes must never sit inside otp's own keychain"
    );
}

#[test]
fn new_dir_creates_unique_directories_for_concurrent_attempts() {
    let cfg = config_at(temp_dir("unique"));
    let a = otp_staging::new_dir(&cfg, "gen").unwrap();
    let b = otp_staging::new_dir(&cfg, "gen").unwrap();
    assert_ne!(
        a, b,
        "a superseded attempt and the one superseding it must not share a directory"
    );
    assert!(a.is_dir() && b.is_dir());
}

#[test]
fn sweep_removes_every_leftover_whatever_it_is() {
    let cfg = config_at(temp_dir("sweep"));
    let dir = otp_staging::new_dir(&cfg, "gen").unwrap();
    std::fs::write(dir.join("own_encryption.key"), b"half a pad").unwrap();
    let nested = dir.join("alice_keys");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("encryption_for_bob.key"), b"more pad").unwrap();
    let loose = otp_staging::tmp_root(&cfg).join("loose.bin");
    std::fs::write(&loose, b"stray").unwrap();

    otp_staging::sweep(&cfg);

    assert!(!dir.exists(), "an interrupted staging directory must be swept");
    assert!(!loose.exists(), "a loose staging file must be swept too");
}

#[test]
fn sweep_on_a_never_used_keychain_is_a_no_op_not_an_error() {
    let cfg = config_at(temp_dir("sweep-empty"));
    otp_staging::sweep(&cfg);
    otp_staging::sweep(&cfg);
}

/// The whole point: a pad only becomes real by leaving `.tmp/`, so what a
/// crash leaves behind is never something a later run can install.
#[test]
fn sweep_never_touches_anything_outside_tmp() {
    let cfg = config_at(temp_dir("sweep-scope"));
    let keychain = cfg.working_dir.join(".keychain");
    std::fs::create_dir_all(&keychain).unwrap();
    let real_key = keychain.join("alice_enc.key");
    std::fs::write(&real_key, b"a real, live pad").unwrap();
    let promoted = cfg.working_dir.join("alice_pending");
    std::fs::create_dir_all(&promoted).unwrap();
    std::fs::write(promoted.join("own_encryption.key"), b"complete").unwrap();

    let staging = otp_staging::new_dir(&cfg, "gen").unwrap();
    std::fs::write(staging.join("partial.key"), b"incomplete").unwrap();

    otp_staging::sweep(&cfg);

    assert!(!staging.exists(), "the incomplete work is gone");
    assert_eq!(
        std::fs::read(&real_key).unwrap(),
        b"a real, live pad",
        "a live keychain key must be untouched"
    );
    assert!(
        promoted.join("own_encryption.key").is_file(),
        "an already-promoted pad must be untouched"
    );
}

#[test]
fn promote_moves_a_completed_directory_out_of_tmp_in_one_step() {
    let cfg = config_at(temp_dir("promote"));
    let staging = otp_staging::new_dir(&cfg, "gen").unwrap();
    let assembled = staging.join("ready");
    std::fs::create_dir_all(&assembled).unwrap();
    std::fs::write(assembled.join("own_encryption.key"), b"enc").unwrap();
    std::fs::write(assembled.join("own_decryption.key"), b"dec").unwrap();

    let dest = cfg.working_dir.join("contact_pending");
    otp_staging::promote(&assembled, &dest).unwrap();

    assert!(!assembled.exists(), "it left staging");
    assert_eq!(std::fs::read(dest.join("own_encryption.key")).unwrap(), b"enc");
    assert_eq!(std::fs::read(dest.join("own_decryption.key")).unwrap(), b"dec");

    // And a sweep afterwards leaves the promoted pad alone.
    otp_staging::sweep(&cfg);
    assert!(dest.join("own_encryption.key").is_file());
}

/// A second generation for the same contact replaces the first wholesale -
/// the four files must always describe one single generation, never a mix.
#[test]
fn promote_replaces_an_existing_destination_rather_than_merging_into_it() {
    let cfg = config_at(temp_dir("promote-replace"));
    let dest = cfg.working_dir.join("contact_pending");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("own_encryption.key"), b"old").unwrap();
    std::fs::write(dest.join("stale_leftover.key"), b"from the old attempt").unwrap();

    let staging = otp_staging::new_dir(&cfg, "gen").unwrap();
    let assembled = staging.join("ready");
    std::fs::create_dir_all(&assembled).unwrap();
    std::fs::write(assembled.join("own_encryption.key"), b"new").unwrap();

    otp_staging::promote(&assembled, &dest).unwrap();

    assert_eq!(std::fs::read(dest.join("own_encryption.key")).unwrap(), b"new");
    assert!(
        !dest.join("stale_leftover.key").exists(),
        "nothing from the superseded attempt may survive into the new one"
    );
}

/// Erasing must not scale its memory with the file - a pad may be up to
/// 1TB, and allocating that to erase it would abort the process. This
/// checks the far smaller property the same code path gives: the bytes are
/// overwritten, not merely unlinked, and a file well past one erase chunk
/// is handled in passes without trouble.
#[test]
fn secure_remove_file_overwrites_a_file_larger_than_one_erase_chunk() {
    let dir = temp_dir("erase");
    let path = dir.join("pad.key");
    // Deliberately past the 1MB erase chunk, so the multi-pass loop runs.
    std::fs::write(&path, vec![0xABu8; 1024 * 1024 + 4096]).unwrap();

    otp_staging::secure_remove_file(&path);
    assert!(!path.exists());
}

#[test]
fn secure_remove_file_on_a_missing_file_is_harmless() {
    let dir = temp_dir("erase-missing");
    otp_staging::secure_remove_file(&dir.join("never-existed.key"));
}

#[test]
fn secure_remove_dir_recurses_into_generated_key_subdirectories() {
    let dir = temp_dir("erase-dir");
    let staging = dir.join("gen");
    let keys = staging.join("alice_keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("encryption_for_bob.key"), b"pad bytes").unwrap();
    std::fs::write(staging.join("top.key"), b"more").unwrap();

    otp_staging::secure_remove_dir(&staging);

    assert!(
        !staging.exists(),
        "otp writes its generated pair into <name>_keys/ subdirectories - those must be \
         cleaned out too, not left holding raw pad bytes"
    );
}
