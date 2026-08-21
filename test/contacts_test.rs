//! `client::contacts`'s gather/delete/install logic, exercised directly
//! against plain `IdStore`/`OtpStore`/`OtpCliConfig` values - no
//! `SessionState` needed, since none of this logic touches anything else
//! a session carries.

use std::path::PathBuf;

use aloo::client::contacts::{
    InstallOtpKeyOutcome, delete_contact, gather_contact_rows, install_otp_key,
    otp_contact_name_for,
};
use aloo::client::idstore::IdStore;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_store::OtpStore;
use aloo::proto::KeyMode;

const TEST_BITS: usize = 1024;

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-contacts-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn otp_cli_config(label: &str) -> OtpCliConfig {
    OtpCliConfig {
        binary_path: PathBuf::from("otp"),
        working_dir: scratch_dir(label),
    }
}

/// Only the tests that actually spawn the `otp` subprocess need this - same
/// helper (and rationale) as `test/otp_provisioning_test.rs::require_otp`.
fn require_otp() -> bool {
    let probe = OtpCliConfig {
        binary_path: PathBuf::from("otp"),
        working_dir: std::env::temp_dir(),
    };
    if otp_cli::binary_available(&probe) {
        return true;
    }
    eprintln!(
        "skipping: 'otp' binary not found on PATH (or ALOO_OTP_BIN) - install otp-toolkit to \
         run this test locally: https://github.com/DavidValin/otp-toolkit"
    );
    false
}

/// A fresh ML-KEM/ML-DSA fingerprint - real key material, not a stand-in,
/// since `otp_contact_name_for`/`gather_contact_rows` decode it with the
/// real `crypto::pq` parser.
fn pq_public_der() -> Vec<u8> {
    let (public, _private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("generating a pq_hybrid bundle");
    aloo::proto::encode(&public).expect("encoding the bundle")
}

fn pq_fingerprint(der: &[u8]) -> [u8; 32] {
    aloo::crypto::pq::fingerprint_of_encoded(der).expect("a real bundle must fingerprint")
}

fn pin(id_store: &mut IdStore, nickname: &str, der: &[u8], key_mode: KeyMode) {
    id_store.check_and_pin(nickname, der);
    id_store.set_key_mode(nickname, key_mode);
}

// ---------------------------------------------------------------------
// otp_contact_name_for: eligibility
// ---------------------------------------------------------------------

#[test]
fn a_password_pinned_contact_is_not_otp_eligible() {
    let mut id_store = IdStore::new_empty(scratch_dir("not-eligible-password"));
    pin(&mut id_store, "alice", b"some-rsa-der", KeyMode::Password);
    assert_eq!(otp_contact_name_for(&id_store, "alice", Some([7u8; 32])), None);
}

#[test]
fn a_pinned_contact_with_no_recorded_key_mode_is_not_otp_eligible() {
    let mut id_store = IdStore::new_empty(scratch_dir("not-eligible-unknown"));
    id_store.check_and_pin("alice", &pq_public_der());
    // key_mode deliberately never set.
    assert_eq!(otp_contact_name_for(&id_store, "alice", Some([7u8; 32])), None);
}

#[test]
fn otp_eligibility_needs_our_own_pq_fingerprint_too() {
    let mut id_store = IdStore::new_empty(scratch_dir("not-eligible-no-own-fp"));
    pin(&mut id_store, "alice", &pq_public_der(), KeyMode::PqHybrid);
    assert_eq!(otp_contact_name_for(&id_store, "alice", None), None);
}

#[test]
fn a_pq_hybrid_pinned_contact_is_otp_eligible() {
    let mut id_store = IdStore::new_empty(scratch_dir("eligible"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let own_fp = [7u8; 32];
    let name = otp_contact_name_for(&id_store, "alice", Some(own_fp));
    assert_eq!(
        name,
        Some(aloo::crypto::otp::contact_name_for(&own_fp, &pq_fingerprint(&der)))
    );
}

#[test]
fn an_unpinned_nickname_is_never_otp_eligible() {
    let id_store = IdStore::new_empty(scratch_dir("eligible-unpinned"));
    assert_eq!(otp_contact_name_for(&id_store, "nobody", Some([7u8; 32])), None);
}

// ---------------------------------------------------------------------
// gather_contact_rows
// ---------------------------------------------------------------------

#[tokio::test]
async fn gather_is_empty_for_a_fresh_store() {
    let id_store = IdStore::new_empty(scratch_dir("gather-empty"));
    let cfg = otp_cli_config("gather-empty");
    let rows = gather_contact_rows(&id_store, &cfg, Some([7u8; 32])).await;
    assert!(rows.is_empty());
}

#[tokio::test]
async fn gather_reports_every_pinned_contact_sorted_by_nickname() {
    let mut id_store = IdStore::new_empty(scratch_dir("gather-sorted"));
    pin(&mut id_store, "carol", b"key-c", KeyMode::Password);
    pin(&mut id_store, "alice", b"key-a", KeyMode::Password);
    pin(&mut id_store, "bob", b"key-b", KeyMode::None);
    let cfg = otp_cli_config("gather-sorted");
    let rows = gather_contact_rows(&id_store, &cfg, Some([7u8; 32])).await;
    let names: Vec<&str> = rows.iter().map(|r| r.nickname.as_str()).collect();
    assert_eq!(names, vec!["alice", "bob", "carol"]);
}

#[tokio::test]
async fn a_password_pinned_row_carries_no_otp_fields() {
    let mut id_store = IdStore::new_empty(scratch_dir("gather-password"));
    pin(&mut id_store, "alice", b"key-a", KeyMode::Password);
    let cfg = otp_cli_config("gather-password");
    let rows = gather_contact_rows(&id_store, &cfg, Some([7u8; 32])).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key_mode, Some(KeyMode::Password));
    assert_eq!(rows[0].otp_contact_name, None);
    assert!(rows[0].otp.is_none());
}

#[tokio::test]
async fn a_pq_hybrid_row_with_no_keychain_entry_has_a_contact_name_but_no_otp_detail() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("gather-pq-no-keychain"));
    pin(&mut id_store, "alice", &pq_public_der(), KeyMode::PqHybrid);
    let cfg = otp_cli_config("gather-pq-no-keychain");
    let rows = gather_contact_rows(&id_store, &cfg, Some([7u8; 32])).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].otp_contact_name.is_some());
    assert!(rows[0].otp.is_none(), "nothing installed yet");
}

// ---------------------------------------------------------------------
// delete_contact
// ---------------------------------------------------------------------

#[tokio::test]
async fn deleting_a_pinned_contact_forgets_its_identity_pin() {
    let mut id_store = IdStore::new_empty(scratch_dir("delete-basic"));
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-basic-otp"));
    pin(&mut id_store, "alice", b"key-a", KeyMode::Password);
    let cfg = otp_cli_config("delete-basic");

    let removed = delete_contact(&mut id_store, &mut otp_store, &cfg, Some([7u8; 32]), "alice").await;
    assert!(removed);
    assert_eq!(id_store.get("alice"), None);
}

#[tokio::test]
async fn deleting_an_unknown_contact_reports_nothing_removed() {
    let mut id_store = IdStore::new_empty(scratch_dir("delete-unknown"));
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-unknown-otp"));
    let cfg = otp_cli_config("delete-unknown");
    let removed = delete_contact(&mut id_store, &mut otp_store, &cfg, Some([7u8; 32]), "nobody").await;
    assert!(!removed);
}

#[tokio::test]
async fn deleting_a_provisioned_otp_contact_removes_the_keychain_entry_too() {
    if !require_otp() {
        return;
    }
    let cfg = otp_cli_config("delete-otp");
    let mut id_store = IdStore::new_empty(scratch_dir("delete-otp-ids"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let own_fp = [7u8; 32];
    let contact_name = otp_contact_name_for(&id_store, "alice", Some(own_fp)).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    otp_cli::add_contact(&cfg, &contact_name, &enc, &dec)
        .await
        .expect("add_contact should succeed with real key files");
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-otp-store"));
    otp_store.mark_provisioned(&contact_name);
    assert!(otp_cli::has_contact(&cfg, &contact_name).await.unwrap());

    delete_contact(&mut id_store, &mut otp_store, &cfg, Some(own_fp), "alice").await;

    assert!(!otp_cli::has_contact(&cfg, &contact_name).await.unwrap());
    assert!(otp_store.get(&contact_name).is_none());
}

/// Generates a real key pair with `otp --new-key-pair` and returns one
/// side's own (encryption, decryption) file paths - enough for
/// `otp --add-contact` to accept, regardless of which side of the pair it
/// nominally is (these tests never exercise cross-side decryption).
async fn make_key_pair(cfg: &OtpCliConfig, label: &str) -> (PathBuf, PathBuf) {
    otp_cli::new_key_pair(cfg, 1, "a", "b")
        .await
        .unwrap_or_else(|e| panic!("new_key_pair for {label}: {e}"));
    (
        cfg.working_dir.join("a_keys").join("encryption_for_b.key"),
        cfg.working_dir.join("a_keys").join("decryption_from_b.key"),
    )
}

// ---------------------------------------------------------------------
// install_otp_key
// ---------------------------------------------------------------------

#[tokio::test]
async fn installing_on_a_non_pq_hybrid_contact_is_refused_with_no_subprocess_spawned() {
    let mut id_store = IdStore::new_empty(scratch_dir("install-not-eligible"));
    pin(&mut id_store, "alice", b"key-a", KeyMode::Password);
    let mut otp_store = OtpStore::new_empty(scratch_dir("install-not-eligible-otp"));
    // A binary path that can never be spawned - proves nothing was even
    // attempted, since a spawn failure would surface as `Error`, not
    // `NotEligible`.
    let cfg = OtpCliConfig {
        binary_path: PathBuf::from("/no/such/otp/binary"),
        working_dir: scratch_dir("install-not-eligible-cwd"),
    };
    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        Some([7u8; 32]),
        "alice",
        &PathBuf::from("/dev/null"),
        &PathBuf::from("/dev/null"),
    )
    .await;
    assert_eq!(outcome, InstallOtpKeyOutcome::NotEligible);
}

#[tokio::test]
async fn installing_with_a_missing_key_file_is_an_error_and_installs_nothing() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("install-missing-file"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let mut otp_store = OtpStore::new_empty(scratch_dir("install-missing-file-otp"));
    let cfg = otp_cli_config("install-missing-file");
    let own_fp = [7u8; 32];

    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        Some(own_fp),
        "alice",
        &cfg.working_dir.join("no-such-enc.key"),
        &cfg.working_dir.join("no-such-dec.key"),
    )
    .await;
    match outcome {
        InstallOtpKeyOutcome::Error(msg) => assert!(msg.contains("encryption key")),
        other => panic!("expected Error, got {other:?}"),
    }
    let contact_name = otp_contact_name_for(&id_store, "alice", Some(own_fp)).unwrap();
    assert!(!otp_cli::has_contact(&cfg, &contact_name).await.unwrap());
}

#[tokio::test]
async fn installing_with_real_key_files_succeeds_and_marks_the_contact_provisioned() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("install-ok"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let mut otp_store = OtpStore::new_empty(scratch_dir("install-ok-otp"));
    let cfg = otp_cli_config("install-ok");
    let own_fp = [7u8; 32];
    let contact_name = otp_contact_name_for(&id_store, "alice", Some(own_fp)).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    let outcome = install_otp_key(&id_store, &mut otp_store, &cfg, Some(own_fp), "alice", &enc, &dec).await;
    assert_eq!(outcome, InstallOtpKeyOutcome::Ok);
    assert!(otp_cli::has_contact(&cfg, &contact_name).await.unwrap());
    assert!(
        otp_store.get(&contact_name).map(|s| s.provisioned).unwrap_or(false),
        "install_otp_key should mark the contact provisioned locally too"
    );

    // And it now shows up in gather_contact_rows with real OTP figures.
    let rows = gather_contact_rows(&id_store, &cfg, Some(own_fp)).await;
    assert_eq!(rows.len(), 1);
    let otp = rows[0].otp.as_ref().expect("otp detail should be present now");
    assert_eq!(otp.enc_sequence, 0);
    assert_eq!(otp.dec_sequence, 0);
    assert!(otp.enc_key_remaining > 0);
}
