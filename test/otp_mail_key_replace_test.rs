//! `/new-otp-mail-key` replacing an existing mail key (AC-384): unlike
//! `/otp`, which resumes an already-provisioned contact, a mail key has no
//! session to resume - `/new-otp-mail-key` always means "get me a fresh
//! one," even when one already exists (the exact situation a key running
//! low leaves the user in). Before this, `handle_provisioning_command`
//! refused outright the moment a mail key already existed, and even had it
//! not, the actual install step (`commit_pending_setup`/`on_pad_commit`)
//! would have failed anyway: `otp --add-contact` refuses to overwrite an
//! existing contact.
//!
//! These tests prove both halves: `handle_provisioning_command` no longer
//! refuses Mail purely because a key exists (it always takes the
//! fresh-generate branch), and the two install call sites genuinely
//! replace an old, different contact rather than failing forever against
//! it.
//!
//! @requirement AC-384

use aloo::client::connect::ResolvedIdentity;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::crypto::otp::OtpPurpose;
use aloo::control::NullSink;
use aloo::proto::{KeyMode, UserId, UserInfo};

const PEER: UserId = UserId(2);

fn require_otp() -> bool {
    let probe = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
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

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-mail-key-replace-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn session_with_real_otp(label: &str) -> (SessionState, Vec<u8>) {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    let session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity {
            private,
            public_der: public_der.clone(),
        },
        scratch: scratch(label),
        otp: Some(OtpCliConfig {
            binary_path: OtpCliConfig::resolve().binary_path,
            working_dir: scratch(&format!("{label}-otp")),
        }),
    })
    .await;
    (session, public_der)
}

fn known_bob(ui: &mut UiState) {
    ui.known_users.insert(
        PEER,
        UserInfo {
            id: PEER,
            name: "bob".into(),
            public_key_der: b"whatever bytes this peer announced".to_vec(),
            key_mode: KeyMode::PqHybrid,
        },
    );
}

/// Installs a small, distinctly-sized "old" contact directly (bypassing any
/// negotiation), standing in for whatever key `/new-otp-mail-key` is about
/// to replace - the exact shape a real running-low mail key has right
/// before the user asks for a fresh one.
async fn install_old_contact(cfg: &OtpCliConfig, contact_name: &str, old_key_bytes: usize) {
    let dir = cfg.working_dir.join("old-contact-staging");
    std::fs::create_dir_all(&dir).unwrap();
    let enc = dir.join("old_enc.key");
    let dec = dir.join("old_dec.key");
    std::fs::write(&enc, vec![0x11; old_key_bytes]).unwrap();
    std::fs::write(&dec, vec![0x22; old_key_bytes]).unwrap();
    otp_cli::add_contact(cfg, contact_name, &enc, &dec)
        .await
        .expect("installing the stand-in old contact should succeed");
}

/// The receiver side (`on_pad_commit`): a commit for a genuinely different
/// pad than whatever contact already exists under this name must replace
/// it, not fail forever against `add_contact`'s refusal to overwrite.
///
/// @requirement AC-384
#[tokio::test]
async fn on_pad_commit_replaces_an_existing_different_contact() {
    if !require_otp() {
        return;
    }
    const CONTACT: &str = "alice-bob-mail";
    let (mut session, _own_der) = session_with_real_otp("pad-commit-replace").await;
    let mut ui = UiState::new("me".into());
    known_bob(&mut ui);
    session
        .peer_link_mut()
        .ensure_link(&mut NullSink, PEER)
        .await;

    // An old contact already exists under this exact name, with a
    // distinctly small key size - the "running low" key `/new-otp-mail-key`
    // is meant to replace.
    install_old_contact(&session.otp_cli_cfg_for_test(), CONTACT, 1024).await;
    let before = otp_cli::show_contact(&session.otp_cli_cfg_for_test(), CONTACT)
        .await
        .expect("show-contact should not fail")
        .expect("the old contact should exist");
    assert!(before.enc_key_remaining < 2048, "sanity: this is the small old key");

    // A fresh, larger, genuinely different pad arrives and is committed -
    // `stage_incoming_pad_for_test` writes 4096-byte halves, distinctly
    // larger than the old 1024-byte one above.
    session.stage_incoming_pad_for_test(PEER, CONTACT.to_string());
    aloo::client::otp::on_pad_commit(&mut session, &mut ui, PEER, CONTACT.to_string()).await;

    assert!(
        !session.has_staged_incoming_pad_for_test(PEER),
        "a successful replace consumes the staged pad"
    );

    let after = otp_cli::show_contact(&session.otp_cli_cfg_for_test(), CONTACT)
        .await
        .expect("show-contact should not fail")
        .expect("the contact must still exist after the replace");
    assert!(
        after.enc_key_remaining > before.enc_key_remaining,
        "the new, larger pad must genuinely have replaced the old one, not been refused \
         silently while the old bytes stayed in place: before={}, after={}",
        before.enc_key_remaining,
        after.enc_key_remaining
    );
}

/// The originator side (`commit_pending_setup`, called from `on_pad_verify`
/// in real use): this side's own staged half must also replace an existing
/// different contact rather than failing.
///
/// @requirement AC-384
#[tokio::test]
async fn commit_pending_setup_replaces_an_existing_different_contact() {
    if !require_otp() {
        return;
    }
    const CONTACT: &str = "alice-bob-mail-originator";
    let cfg = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("commit-pending-replace"),
    };

    install_old_contact(&cfg, CONTACT, 1024).await;
    let before = otp_cli::show_contact(&cfg, CONTACT)
        .await
        .expect("show-contact should not fail")
        .expect("the old contact should exist");

    // Stage a genuinely fresh, distinctly-sized pair under
    // `pending_setup_dir` - the exact files `initiate_provisioning` would
    // have staged, and `commit_pending_setup` reads by that same layout.
    let dir = aloo::client::otp::pending_setup_dir(&cfg, CONTACT);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("own_encryption.key"), vec![0x33; 4096]).unwrap();
    std::fs::write(dir.join("own_decryption.key"), vec![0x44; 4096]).unwrap();

    let committed = aloo::client::otp::commit_pending_setup(&cfg, CONTACT).await;
    assert!(
        committed,
        "committing this side's own half must succeed even though a different contact already \
         exists under this name"
    );

    let after = otp_cli::show_contact(&cfg, CONTACT)
        .await
        .expect("show-contact should not fail")
        .expect("the contact must exist after the commit");
    assert!(
        after.enc_key_remaining > before.enc_key_remaining,
        "the freshly staged, larger pad must genuinely have replaced the old one: before={}, after={}",
        before.enc_key_remaining,
        after.enc_key_remaining
    );
}

/// `handle_provisioning_command`'s branch selection: Mail must never take
/// the "already have a key, refuse" exit it used to - it always proceeds
/// to the fresh-generate confirmation, exactly as a first-ever
/// `/new-otp-mail-key` would.
///
/// @requirement AC-384
#[tokio::test]
async fn new_otp_mail_key_never_refuses_just_because_a_key_already_exists() {
    if !require_otp() {
        return;
    }
    let (mut session, _own_der) = session_with_real_otp("mail-key-always-generates").await;
    let mut ui = UiState::new("me".into());
    let (peer_public, _peer_private) =
        aloo::crypto::pq::generate_bundle_with_bits(1024).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    ui.known_users.insert(
        PEER,
        UserInfo {
            id: PEER,
            name: "bob".into(),
            public_key_der: peer_der.clone(),
            key_mode: KeyMode::PqHybrid,
        },
    );
    session
        .id_store_mut()
        .pin_new_device("bob", "test-device", &peer_der, Trust::Verified);
    session.set_peer_device_id_for_test(PEER, "test-device".to_string());

    // Fake "a mail key already exists" purely at the aloo-side bookkeeping
    // layer (`detect_or_adopt_existing`'s first, cheapest check) - no real
    // keychain entry is needed to prove the *branch selection* never
    // refuses Mail for this reason any more.
    let own_fp = aloo::crypto::pq::fingerprint_of_encoded(&_own_der).expect("own test fp");
    let peer_fp = aloo::crypto::pq::fingerprint_of_encoded(&peer_der).expect("test peer fp");
    let contact = aloo::crypto::otp::contact_name_for_mail(&own_fp, "test-device", &peer_fp, "test-device");
    session.otp_store_mut().mark_provisioned(&contact);

    aloo::client::otp::handle_provisioning_command(
        &mut NullSink,
        &mut ui,
        &mut session,
        PEER,
        peer_der,
        OtpPurpose::Mail,
    )
    .await
    .expect("handle_provisioning_command should not fail");

    assert!(
        ui.otp_generate_confirm_open().is_some(),
        "an already-existing mail key must not refuse /new-otp-mail-key - it must open the same \
         fresh-generate confirmation a first-ever request would"
    );
    let notice = ui.status_notice.clone();
    assert!(
        !notice.as_ref().is_some_and(|(m, _)| m.contains("already exists")),
        "the old 'otp mail key already exists' refusal must be gone: {notice:?}"
    );
}
