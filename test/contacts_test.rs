//! `client::contacts`'s gather/delete/install logic, exercised directly
//! against plain `IdStore`/`OtpStore`/`OtpCliConfig` values - no
//! `SessionState` needed, since none of this logic touches anything else
//! a session carries.

use std::path::PathBuf;

use aloo::client::contacts::{
    InstallOtpKeyOutcome, OwnIdentity, PinIdentityCardOutcome, delete_contact,
    delete_contact_device, delete_otp_key, gather_contact_rows, install_otp_key,
    otp_contact_name_for, pin_identity_card, pin_identity_card_for_device,
};
use aloo::client::idstore::IdStore;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_store::OtpStore;
use aloo::crypto::otp::OtpPurpose;
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
            own_device_id: "own-test-device",
        }
    }
}

fn pin(id_store: &mut IdStore, nickname: &str, der: &[u8], key_mode: KeyMode) {
    id_store.pin_new_device(nickname, "test-device", der, aloo::client::idstore::Trust::Tofu);
    id_store.set_key_mode(nickname, "test-device", key_mode);
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
        otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live),
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
    let name = otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live);
    assert_eq!(
        name,
        Some(aloo::crypto::otp::contact_name_for(
            &me.fp,
            "own-test-device",
            &pq_fingerprint(&der),
            "test-device"
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
        otp_contact_name_for(&id_store, "nobody", "test-device", own_identity().as_identity(), OtpPurpose::Live),
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

/// A nickname with several pinned devices produces one row per device
/// (device-pinning plan §3), not one row for the nickname - each with its
/// own device id, its own key, and its own keychain name derived from
/// *that* device specifically.
/// @requirement AC-322
#[tokio::test]
async fn gather_produces_one_row_per_device() {
    let mut id_store = IdStore::new_empty(scratch_dir("gather-multi-device"));
    id_store.pin_new_device("alice", "laptop", b"key-laptop", aloo::client::idstore::Trust::Tofu);
    id_store.pin_new_device("alice", "phone", b"key-phone", aloo::client::idstore::Trust::Tofu);
    let cfg = otp_cli_config("gather-multi-device");
    let me = own_identity();
    let mut rows = gather_contact_rows(&id_store, &cfg, me.as_identity()).await;
    rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));

    assert_eq!(rows.len(), 2, "one row per device, not one per nickname");
    assert!(rows.iter().all(|r| r.nickname == "alice"));
    let device_ids: Vec<Option<String>> = rows.iter().map(|r| r.device_id.clone()).collect();
    assert_eq!(device_ids, vec![Some("laptop".to_string()), Some("phone".to_string())]);
    assert_ne!(
        rows[0].otp_contact_name, rows[1].otp_contact_name,
        "each device's own keychain name, never shared"
    );
}

/// An unbound entry (no device confirmed yet) still produces its own row,
/// with `device_id: None` - distinct from a row naming an actual device.
/// @requirement AC-322
#[tokio::test]
async fn gather_produces_an_unbound_row_for_a_pin_with_no_confirmed_device() {
    let mut id_store = IdStore::new_empty(scratch_dir("gather-unbound"));
    id_store.pin_new_device("alice", "", b"key-a", aloo::client::idstore::Trust::Tofu);
    let cfg = otp_cli_config("gather-unbound");
    let rows = gather_contact_rows(&id_store, &cfg, own_identity().as_identity()).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].device_id, None);
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
        otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live).unwrap();

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

/// Forgetting a nickname outright (device-pinning plan §3's "every
/// device") must clean up *every* device's own keychain entry, not just
/// whichever one `IdStore`'s ordinary most-recently-seen default would
/// have picked - a nickname with two devices, each with its own installed
/// pad, must lose both.
/// @requirement AC-322
#[tokio::test]
async fn delete_contact_removes_every_devices_keychain_entries_not_just_one() {
    if !require_otp() {
        return;
    }
    let cfg = otp_cli_config("delete-multi");
    let mut id_store = IdStore::new_empty(scratch_dir("delete-multi-ids"));
    let laptop_der = pq_public_der();
    let phone_der = pq_public_der();
    id_store.pin_new_device("alice", "laptop", &laptop_der, aloo::client::idstore::Trust::Tofu);
    id_store.pin_new_device("alice", "phone", &phone_der, aloo::client::idstore::Trust::Tofu);
    let me = own_identity();
    let laptop_name =
        otp_contact_name_for(&id_store, "alice", "laptop", me.as_identity(), OtpPurpose::Live).unwrap();
    let phone_name =
        otp_contact_name_for(&id_store, "alice", "phone", me.as_identity(), OtpPurpose::Live).unwrap();
    assert_ne!(laptop_name, phone_name);

    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-multi-store"));
    for name in [&laptop_name, &phone_name] {
        // A fresh keygen scratch dir per device - `new_key_pair` always
        // writes to a fixed path within it, which would otherwise collide
        // across two devices sharing one directory.
        let keygen_cfg = otp_cli_config(&format!("delete-multi-keygen-{name}"));
        let (enc, dec) = make_key_pair(&keygen_cfg, name).await;
        otp_cli::add_contact(&cfg, name, &enc, &dec)
            .await
            .expect("add_contact should succeed with real key files");
        otp_store.mark_provisioned(name);
    }
    assert!(otp_cli::has_contact(&cfg, &laptop_name).await.unwrap());
    assert!(otp_cli::has_contact(&cfg, &phone_name).await.unwrap());

    delete_contact(&mut id_store, &mut otp_store, &cfg, me.as_identity(), "alice").await;

    assert!(
        !otp_cli::has_contact(&cfg, &laptop_name).await.unwrap(),
        "laptop's own keychain entry must be gone too"
    );
    assert!(!otp_cli::has_contact(&cfg, &phone_name).await.unwrap());
    assert!(otp_store.get(&laptop_name).is_none());
    assert!(otp_store.get(&phone_name).is_none());
}

/// The additive rule applied to deletion (device-pinning plan §3):
/// removing just one device's pin and keychain entries must leave every
/// sibling device's pin and keys exactly as they were.
/// @requirement AC-322
#[tokio::test]
async fn delete_contact_device_leaves_sibling_devices_and_their_keys_untouched() {
    if !require_otp() {
        return;
    }
    let cfg = otp_cli_config("delete-device");
    let mut id_store = IdStore::new_empty(scratch_dir("delete-device-ids"));
    let laptop_der = pq_public_der();
    let phone_der = pq_public_der();
    id_store.pin_new_device("alice", "laptop", &laptop_der, aloo::client::idstore::Trust::Tofu);
    id_store.pin_new_device("alice", "phone", &phone_der, aloo::client::idstore::Trust::Tofu);
    let me = own_identity();
    let laptop_name =
        otp_contact_name_for(&id_store, "alice", "laptop", me.as_identity(), OtpPurpose::Live).unwrap();
    let phone_name =
        otp_contact_name_for(&id_store, "alice", "phone", me.as_identity(), OtpPurpose::Live).unwrap();

    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-device-store"));
    for name in [&laptop_name, &phone_name] {
        let keygen_cfg = otp_cli_config(&format!("delete-device-keygen-{name}"));
        let (enc, dec) = make_key_pair(&keygen_cfg, name).await;
        otp_cli::add_contact(&cfg, name, &enc, &dec)
            .await
            .expect("add_contact should succeed with real key files");
        otp_store.mark_provisioned(name);
    }

    let removed =
        delete_contact_device(&mut id_store, &mut otp_store, &cfg, me.as_identity(), "alice", "laptop")
            .await;
    assert!(removed);

    assert!(
        !otp_cli::has_contact(&cfg, &laptop_name).await.unwrap(),
        "laptop's own keychain entry is gone"
    );
    assert_eq!(id_store.get_for_device("alice", "laptop"), None, "laptop's pin is gone");

    assert!(
        otp_cli::has_contact(&cfg, &phone_name).await.unwrap(),
        "phone's keychain entry must survive laptop's removal"
    );
    assert!(otp_store.get(&phone_name).is_some(), "phone's aloo-side bookkeeping must survive too");
    assert_eq!(
        id_store.get_for_device("alice", "phone"),
        Some(phone_der.as_slice()),
        "phone's pin must survive laptop's removal"
    );
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
    let contact_name = otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
        "test-device",
        OtpPurpose::Live,
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
        "test-device",
        OtpPurpose::Live,
        &cfg.working_dir.join("no-such-enc.key"),
        &cfg.working_dir.join("no-such-dec.key"),
    )
    .await;
    match outcome {
        InstallOtpKeyOutcome::Error(msg) => assert!(msg.contains("encryption key")),
        other => panic!("expected Error, got {other:?}"),
    }
    let contact_name =
        otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live).unwrap();
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
        otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live).unwrap();

    let (enc, dec) = make_key_pair(&cfg, &contact_name).await;
    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
        "test-device",
        OtpPurpose::Live,
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

// ---------------------------------------------------------------------
// install_otp_key: mail purpose is independent of the live key
// ---------------------------------------------------------------------

/// The same install path, run with `OtpPurpose::Mail`, must file the pad
/// under the *mail* contact name - never colliding with a `Live` key
/// installed for the same pair, and answering `otp_mail_contact_name`/
/// `otp_mail` in `gather_contact_rows`, not `otp_contact_name`/`otp`.
/// @requirement AC-295, TB-249
#[tokio::test]
async fn installing_a_mail_key_is_independent_of_the_live_key() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("install-mail"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let mut otp_store = OtpStore::new_empty(scratch_dir("install-mail-otp"));
    let cfg = otp_cli_config("install-mail");
    let me = own_identity();

    let live_name = otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live).unwrap();
    let mail_name = otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Mail).unwrap();
    assert_ne!(live_name, mail_name, "the two purposes must never share a keychain name");

    let (enc, dec) = make_key_pair(&cfg, &mail_name).await;
    let outcome = install_otp_key(
        &id_store,
        &mut otp_store,
        &cfg,
        me.as_identity(),
        "alice",
        "test-device",
        OtpPurpose::Mail,
        &enc,
        &dec,
    )
    .await;
    assert_eq!(outcome, InstallOtpKeyOutcome::Ok);
    assert!(otp_cli::has_contact(&cfg, &mail_name).await.unwrap());
    assert!(
        !otp_cli::has_contact(&cfg, &live_name).await.unwrap(),
        "installing the mail key must not create a live-key entry too"
    );

    let rows = gather_contact_rows(&id_store, &cfg, me.as_identity()).await;
    assert!(rows[0].otp.is_none(), "no live key was installed");
    assert!(rows[0].otp_mail.is_some(), "the mail key shows up under its own field");
}

// ---------------------------------------------------------------------
// delete_otp_key: one purpose only, identity pin untouched
// ---------------------------------------------------------------------

/// @requirement AC-300
#[tokio::test]
async fn delete_otp_key_removes_only_the_named_purpose() {
    if !require_otp() {
        return;
    }
    let mut id_store = IdStore::new_empty(scratch_dir("delete-one-purpose-ids"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-one-purpose-otp"));
    let cfg = otp_cli_config("delete-one-purpose");
    let me = own_identity();

    // Two *distinct* real key pairs - the real `otp` binary itself refuses
    // installing the same key material under two different contacts (a
    // pad reused across contacts is a broken one-time pad), so each
    // purpose needs its own, generated in its own scratch dir.
    for purpose in [OtpPurpose::Live, OtpPurpose::Mail] {
        let gen_cfg = otp_cli_config(&format!("delete-one-purpose-gen-{}", purpose.label()));
        let (enc, dec) = make_key_pair(&gen_cfg, purpose.label()).await;
        let outcome =
            install_otp_key(&id_store, &mut otp_store, &cfg, me.as_identity(), "alice", "test-device", purpose, &enc, &dec)
                .await;
        assert_eq!(outcome, InstallOtpKeyOutcome::Ok);
    }
    let live_name = otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Live).unwrap();
    let mail_name = otp_contact_name_for(&id_store, "alice", "test-device", me.as_identity(), OtpPurpose::Mail).unwrap();

    let removed =
        delete_otp_key(&id_store, &mut otp_store, &cfg, me.as_identity(), "alice", "test-device", OtpPurpose::Mail).await;
    assert!(removed);
    assert!(!otp_cli::has_contact(&cfg, &mail_name).await.unwrap(), "the mail key is gone");
    assert!(
        otp_cli::has_contact(&cfg, &live_name).await.unwrap(),
        "the live key is untouched by a mail-purpose delete"
    );
    assert!(id_store.get("alice").is_some(), "the identity pin itself is never touched");
}

/// @requirement AC-300
#[tokio::test]
async fn delete_otp_key_on_a_purpose_with_nothing_installed_reports_nothing_removed() {
    let mut id_store = IdStore::new_empty(scratch_dir("delete-nothing-ids"));
    let der = pq_public_der();
    pin(&mut id_store, "alice", &der, KeyMode::PqHybrid);
    let mut otp_store = OtpStore::new_empty(scratch_dir("delete-nothing-otp"));
    let cfg = otp_cli_config("delete-nothing");
    let me = own_identity();

    let removed =
        delete_otp_key(&id_store, &mut otp_store, &cfg, me.as_identity(), "alice", "test-device", OtpPurpose::Mail).await;
    assert!(!removed);
}

// ---------------------------------------------------------------------
// pin_identity_card: PQH's manual "Create key"
// ---------------------------------------------------------------------

fn write_identity_card(dir: &std::path::Path, nickname: &str) -> (PathBuf, aloo::crypto::pq::PqPublicBundle) {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS)
        .expect("generating a pq_hybrid bundle");
    let card = aloo::crypto::pq::make_identity_card(&private, &public, nickname)
        .expect("signing an identity card");
    let path = dir.join(format!("{nickname}.card"));
    aloo::crypto::pq::save_identity_card(&card, &path).expect("saving the card");
    (path, public)
}

/// @requirement AC-301
#[test]
fn pinning_a_matching_identity_card_pins_it_as_verified_pq_hybrid() {
    let dir = scratch_dir("pin-card-ok");
    let (path, public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));

    let outcome = pin_identity_card(&mut id_store, "alice", &path);
    assert_eq!(outcome, PinIdentityCardOutcome::Ok);
    assert_eq!(id_store.key_mode("alice"), Some(KeyMode::PqHybrid));
    assert_eq!(id_store.trust("alice"), Some(aloo::client::idstore::Trust::Verified));
    assert_eq!(id_store.pinned_from("alice"), Some(path.as_path()));
    let expected_der = aloo::proto::encode(&public).unwrap();
    assert_eq!(id_store.get("alice"), Some(expected_der.as_slice()));
}

/// @requirement AC-301
#[test]
fn pinning_a_card_for_a_different_nickname_is_refused() {
    let dir = scratch_dir("pin-card-mismatch");
    let (path, _public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));

    let outcome = pin_identity_card(&mut id_store, "bob", &path);
    match outcome {
        PinIdentityCardOutcome::NicknameMismatch { card_nickname } => {
            assert_eq!(card_nickname, "alice");
        }
        other => panic!("expected NicknameMismatch, got {other:?}"),
    }
    assert!(id_store.get("bob").is_none(), "a mismatched card is never pinned");
}

/// @requirement AC-301
#[test]
fn pinning_a_missing_file_is_invalid_not_a_panic() {
    let dir = scratch_dir("pin-card-missing");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));

    let outcome = pin_identity_card(&mut id_store, "alice", &dir.join("no-such.card"));
    match outcome {
        PinIdentityCardOutcome::Invalid(_) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
}

/// A card import is key_mode-scoped (device-pinning plan §1): it must
/// never touch an existing `Direct`-framed pin, even though both an
/// unbound `Direct` entry and a card-imported `pq_hybrid` entry share the
/// same empty device_id sentinel. The two are independent trust
/// dimensions for the same nickname, and importing a card is exactly the
/// case that would otherwise silently destroy the raw pairing key an
/// active OTP-only relationship depends on.
///
/// @requirement AC-301
#[test]
fn pinning_a_card_never_touches_an_existing_direct_framed_pin() {
    let dir = scratch_dir("pin-card-no-touch-direct");
    let (path, public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));
    // Starts out pinned via a raw Direct-framed key, no pq_hybrid at all -
    // the ❌PQH badge state this action exists to fix. Unbound (no device
    // known yet), same as any Direct-framed pin that arrived with no live
    // connection to attribute it to.
    id_store.pin_new_device("alice", "", b"some-raw-pinned-key", aloo::client::idstore::Trust::Tofu);
    assert_eq!(id_store.key_mode("alice"), None);

    let outcome = pin_identity_card(&mut id_store, "alice", &path);
    assert_eq!(outcome, PinIdentityCardOutcome::Ok);

    // The Direct pin survives, byte-for-byte, completely untouched...
    assert_eq!(
        id_store.devices_of("alice").find(|d| d.key_mode.is_none()).map(|d| d.key.as_slice()),
        Some(b"some-raw-pinned-key".as_slice()),
        "the pre-existing Direct-framed pin must not be overwritten by an unrelated card import"
    );
    // ...and the card lands as its own, separate pq_hybrid entry.
    let expected_der = aloo::proto::encode(&public).unwrap();
    assert_eq!(
        id_store
            .devices_of("alice")
            .find(|d| d.key_mode == Some(KeyMode::PqHybrid))
            .map(|d| d.key.as_slice()),
        Some(expected_der.as_slice())
    );
    assert_eq!(id_store.devices_of("alice").count(), 2, "two independent trust dimensions, not one merged entry");
}

/// The ordinary case: nothing pinned yet at all, so the card simply
/// creates the nickname's first (and only) entry.
///
/// @requirement AC-301
#[test]
fn pinning_a_card_creates_a_fresh_unbound_entry_when_nothing_was_pinned() {
    let dir = scratch_dir("pin-card-fresh");
    let (path, public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));

    let outcome = pin_identity_card(&mut id_store, "alice", &path);
    assert_eq!(outcome, PinIdentityCardOutcome::Ok);
    let expected_der = aloo::proto::encode(&public).unwrap();
    assert_eq!(id_store.get("alice"), Some(expected_der.as_slice()));
    assert_eq!(id_store.devices_of("alice").count(), 1);
}

/// Re-importing a card (or a later, replacement one) for a nickname that
/// already has an unbound `pq_hybrid` entry updates that entry in place -
/// still key_mode-scoped, so this is the "upgrade", not "always add a new
/// row", half of the behaviour.
///
/// @requirement AC-301
#[test]
fn pinning_a_second_card_overwrites_the_existing_unbound_pq_hybrid_entry_in_place() {
    let dir = scratch_dir("pin-card-overwrite");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));

    // `write_identity_card` always writes to the same `<nickname>.card`
    // path, so the first card must actually be pinned before the second
    // one is generated and overwrites that file on disk.
    let (first_path, _first_public) = write_identity_card(&dir, "alice");
    assert_eq!(pin_identity_card(&mut id_store, "alice", &first_path), PinIdentityCardOutcome::Ok);
    let (second_path, second_public) = write_identity_card(&dir, "alice");
    assert_eq!(pin_identity_card(&mut id_store, "alice", &second_path), PinIdentityCardOutcome::Ok);

    let expected_der = aloo::proto::encode(&second_public).unwrap();
    assert_eq!(id_store.get("alice"), Some(expected_der.as_slice()));
    assert_eq!(id_store.devices_of("alice").count(), 1, "in place, not a second row");
}

// ---------------------------------------------------------------------
// pin_identity_card_for_device: the "Add contact" popup's PQH step
// ---------------------------------------------------------------------

/// @requirement AC-323
#[test]
fn pin_identity_card_for_device_binds_directly_to_the_typed_device_not_the_unbound_entry() {
    let dir = scratch_dir("pin-card-device-ok");
    let (path, public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));

    let outcome = pin_identity_card_for_device(&mut id_store, "alice", "laptop", &path);
    assert_eq!(outcome, PinIdentityCardOutcome::Ok);
    assert_eq!(
        id_store.get_for_device("alice", ""),
        None,
        "unlike pin_identity_card, this must never touch the unbound entry"
    );
    let expected_der = aloo::proto::encode(&public).unwrap();
    assert_eq!(id_store.get_for_device("alice", "laptop"), Some(expected_der.as_slice()));
    assert_eq!(id_store.key_mode("alice"), Some(KeyMode::PqHybrid));
    assert_eq!(id_store.trust_for_device("alice", "laptop"), Some(aloo::client::idstore::Trust::Verified));
    assert_eq!(id_store.pinned_from("alice"), Some(path.as_path()));
}

/// Add Contact only ever creates a brand-new entry - it must refuse
/// rather than silently overwrite a device a live connection, another
/// card, or an earlier Add Contact already pinned.
///
/// @requirement AC-323
#[test]
fn pin_identity_card_for_device_refuses_an_already_pinned_device() {
    let dir = scratch_dir("pin-card-device-dup");
    let (path, _public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));
    id_store.pin_new_device_with_key_mode(
        "alice",
        "laptop",
        b"already-here",
        aloo::client::idstore::Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );

    let outcome = pin_identity_card_for_device(&mut id_store, "alice", "laptop", &path);
    match outcome {
        PinIdentityCardOutcome::Invalid(_) => {}
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert_eq!(
        id_store.get_for_device("alice", "laptop"),
        Some(b"already-here".as_slice()),
        "the existing pin for that device must be completely untouched"
    );
}

/// A device_id explicitly typed in Add Contact is additive, exactly like
/// any other new device (device-pinning plan §1) - it must sit alongside
/// an already-pinned sibling device, never disturb it.
///
/// @requirement AC-323
#[test]
fn pin_identity_card_for_device_leaves_sibling_devices_untouched() {
    let dir = scratch_dir("pin-card-device-sibling");
    let (path, public) = write_identity_card(&dir, "alice");
    let mut id_store = IdStore::new_empty(dir.join("ids_store"));
    id_store.pin_new_device_with_key_mode(
        "alice",
        "phone",
        b"phones-own-key",
        aloo::client::idstore::Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );

    let outcome = pin_identity_card_for_device(&mut id_store, "alice", "laptop", &path);
    assert_eq!(outcome, PinIdentityCardOutcome::Ok);
    assert_eq!(id_store.get_for_device("alice", "phone"), Some(b"phones-own-key".as_slice()));
    let expected_der = aloo::proto::encode(&public).unwrap();
    assert_eq!(id_store.get_for_device("alice", "laptop"), Some(expected_der.as_slice()));
    assert_eq!(id_store.devices_of("alice").count(), 2);
}
