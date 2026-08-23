//! `client::contacts`'s gather/delete/install logic, exercised directly
//! against plain `IdStore`/`OtpStore`/`OtpCliConfig` values - no
//! `SessionState` needed, since none of this logic touches anything else
//! a session carries.

use std::path::PathBuf;

use aloo::client::contacts::{
    InstallOtpKeyOutcome, OwnIdentity, delete_contact, gather_contact_rows, install_otp_key,
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
    let (public, _private) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS)
        .expect("generating a pq_hybrid bundle");
    aloo::proto::encode(&public).expect("encoding the bundle")
}

fn pq_fingerprint(der: &[u8]) -> [u8; 32] {
    aloo::crypto::pq::fingerprint_of_encoded(der).expect("a real bundle must fingerprint")
}

/// This side's own identity as the naming rules see it - a real keybundle
/// and the fingerprint *of that same bundle*, which is what a live session
/// always holds. Held as one value so the two can never drift apart, which
/// they must not: the naming rule reads both.
struct Own {
    der: Vec<u8>,
    fp: [u8; 32],
}

fn own_identity() -> Own {
    let der = pq_public_der();
    let fp = pq_fingerprint(&der);
    Own { der, fp }
}

impl Own {
    fn as_identity(&self) -> OwnIdentity<'_> {
        OwnIdentity {
            pq_fingerprint: &self.fp,
            pinned_public_der: &self.der,
        }
    }
}

fn pin(id_store: &mut IdStore, nickname: &str, der: &[u8], key_mode: KeyMode) {
    id_store.check_and_pin(nickname, der);
    id_store.set_key_mode(nickname, key_mode);
}

// ---------------------------------------------------------------------
// otp_contact_name_for: eligibility
// ---------------------------------------------------------------------

/// A pin whose key does not decode as a `pq_hybrid` bundle - a
/// `--no-server` direct-punch peer, which announces none - still gets a
/// keychain name, derived from the two *pinned keys* rather than from
/// fingerprints. Never from the nickname: see
/// `crypto::otp::contact_name_for_keys` for why.
#[test]
fn a_contact_pinned_without_a_readable_bundle_gets_a_key_derived_name() {
    let mut id_store = IdStore::new_empty(scratch_dir("nickname-direct"));
    pin(&mut id_store, "alice", b"not-a-bundle", KeyMode::PqHybrid);
    let me = own_identity();
    assert_eq!(
        otp_contact_name_for(&id_store, "alice", me.as_identity()),
        Some(aloo::crypto::otp::contact_name_for_keys(
            &me.der,
            b"not-a-bundle"
        )),
        "an unreadable pin is Direct framing, and Direct names the contact \
         from the two pinned keys"
    );
}

#[test]
fn a_pq_hybrid_pinned_contact_is_otp_eligible() {
    let mut id_store = IdStore::new_empty(scratch_dir("eligible"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let me = own_identity();
    let name = otp_contact_name_for(&id_store, "alice", me.as_identity());
    assert_eq!(
        name,
        Some(aloo::crypto::otp::contact_name_for(
            &me.fp,
            &pq_fingerprint(&der)
        )),
        "two readable bundles are PqWrapped, and PqWrapped names the \
         contact from the two fingerprints"
    );
}

/// Nothing pinned means nothing to bind a pad to.
#[test]
fn an_unpinned_nickname_resolves_to_no_name_at_all() {
    let id_store = IdStore::new_empty(scratch_dir("nickname-unpinned"));
    assert_eq!(
        otp_contact_name_for(&id_store, "nobody", own_identity().as_identity()),
        None
    );
}

// ---------------------------------------------------------------------
// gather_contact_rows
// ---------------------------------------------------------------------

#[tokio::test]
async fn gather_is_empty_for_a_fresh_store() {
    let id_store = IdStore::new_empty(scratch_dir("gather-empty"));
    let cfg = otp_cli_config("gather-empty");
    let rows =
        gather_contact_rows(&id_store, &cfg, own_identity().as_identity()).await;
    assert!(rows.is_empty());
}

#[tokio::test]
async fn gather_reports_every_pinned_contact_sorted_by_nickname() {
    let mut id_store = IdStore::new_empty(scratch_dir("gather-sorted"));
    pin(&mut id_store, "carol", b"key-c", KeyMode::PqHybrid);
    pin(&mut id_store, "alice", b"key-a", KeyMode::PqHybrid);
    pin(&mut id_store, "bob", b"key-b", KeyMode::PqHybrid);
    let cfg = otp_cli_config("gather-sorted");
    let rows =
        gather_contact_rows(&id_store, &cfg, own_identity().as_identity()).await;
    let names: Vec<&str> = rows.iter().map(|r| r.nickname.as_str()).collect();
    assert_eq!(names, vec!["alice", "bob", "carol"]);
}

/// A contact pinned under a key that is not a readable bundle can hold a
/// pad too - it just gets a key-derived keychain name (Direct framing),
/// and no pad is installed until someone installs one.
#[tokio::test]
async fn a_contact_with_an_unreadable_pin_can_still_hold_a_pad() {
    let mut id_store = IdStore::new_empty(scratch_dir("gather-direct"));
    pin(&mut id_store, "alice", b"key-a", KeyMode::PqHybrid);
    let cfg = otp_cli_config("gather-direct");
    let me = own_identity();
    let rows = gather_contact_rows(&id_store, &cfg, me.as_identity()).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key_mode, Some(KeyMode::PqHybrid));
    assert_eq!(
        rows[0].otp_contact_name,
        Some(aloo::crypto::otp::contact_name_for_keys(&me.der, b"key-a")),
        "named from the two pinned keys, so an impersonator derives a different one"
    );
    assert!(rows[0].otp.is_none(), "but nothing installed yet");
}

#[tokio::test]
async fn a_pq_hybrid_row_with_no_keychain_entry_has_a_contact_name_but_no_otp_detail() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("gather-pq-no-keychain"));
    pin(&mut id_store, "alice", &pq_public_der(), KeyMode::PqHybrid);
    let cfg = otp_cli_config("gather-pq-no-keychain");
    let rows =
        gather_contact_rows(&id_store, &cfg, own_identity().as_identity()).await;
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
    pin(&mut id_store, "alice", b"key-a", KeyMode::PqHybrid);
    let cfg = otp_cli_config("delete-basic");

    let removed = delete_contact(
        &mut id_store,
        &mut otp_store,
        &cfg,
        own_identity().as_identity(),
        "alice",
    )
    .await;
    assert!(removed);
    assert_eq!(id_store.get("alice"), None);
}

#[tokio::test]
async fn deleting_an_unknown_contact_reports_nothing_removed() {
    let mut id_store = IdStore::new_empty(scratch_dir("delete-unknown"));
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-unknown-otp"));
    let cfg = otp_cli_config("delete-unknown");
    let removed = delete_contact(
        &mut id_store,
        &mut otp_store,
        &cfg,
        own_identity().as_identity(),
        "nobody",
    )
    .await;
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
    let me = own_identity();
    let contact_name =
        otp_contact_name_for(&id_store, "alice", me.as_identity()).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    otp_cli::add_contact(&cfg, &contact_name, &enc, &dec)
        .await
        .expect("add_contact should succeed with real key files");
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-otp-store"));
    otp_store.mark_provisioned(&contact_name);
    assert!(otp_cli::has_contact(&cfg, &contact_name).await.unwrap());

    delete_contact(
        &mut id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
    )
    .await;

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

/// Installing a pad for a contact whose pin is not a readable keybundle is
/// allowed - that is the whole point of pure-OTP mode. It reaches the
/// subprocess rather than being refused up front.
#[tokio::test]
async fn installing_on_a_contact_with_an_unreadable_pin_is_allowed() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("install-nonpq"));
    pin(&mut id_store, "alice", b"key-a", KeyMode::PqHybrid);
    let mut otp_store = OtpStore::new_empty(scratch_dir("install-nonpq-otp"));
    let cfg = otp_cli_config("install-nonpq");
    let me = own_identity();
    let contact_name = otp_contact_name_for(&id_store, "alice", me.as_identity()).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
        &enc,
        &dec,
    )
    .await;
    assert_eq!(outcome, InstallOtpKeyOutcome::Ok);
    assert!(otp_cli::has_contact(&cfg, &contact_name).await.unwrap());
    assert!(
        otp_store
            .get(&contact_name)
            .map(|s| s.provisioned)
            .unwrap_or(false),
        "a pad installed without any pq identity is still a usable contact"
    );
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
    let me = own_identity();

    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
        &cfg.working_dir.join("no-such-enc.key"),
        &cfg.working_dir.join("no-such-dec.key"),
    )
    .await;
    match outcome {
        InstallOtpKeyOutcome::Error(msg) => assert!(msg.contains("encryption key")),
        other => panic!("expected Error, got {other:?}"),
    }
    let contact_name =
        otp_contact_name_for(&id_store, "alice", me.as_identity()).unwrap();
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
    let me = own_identity();
    let contact_name =
        otp_contact_name_for(&id_store, "alice", me.as_identity()).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
        &enc,
        &dec,
    )
    .await;
    assert_eq!(outcome, InstallOtpKeyOutcome::Ok);
    assert!(otp_cli::has_contact(&cfg, &contact_name).await.unwrap());
    assert!(
        otp_store
            .get(&contact_name)
            .map(|s| s.provisioned)
            .unwrap_or(false),
        "install_otp_key should mark the contact provisioned locally too"
    );

    // And it now shows up in gather_contact_rows with real OTP figures.
    let rows = gather_contact_rows(&id_store, &cfg, me.as_identity()).await;
    assert_eq!(rows.len(), 1);
    let otp = rows[0]
        .otp
        .as_ref()
        .expect("otp detail should be present now");
    assert_eq!(otp.enc_sequence, 0);
    assert_eq!(otp.dec_sequence, 0);
    assert!(otp.enc_key_remaining > 0);
}
