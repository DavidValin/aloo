//! `client::otp_mail::check_recipient` against a real `SessionState` - the
//! one place that proves OTP mail actually spends its *own* independent
//! key (`crypto::otp::contact_name_for_mail`) rather than a live `/otp`
//! session's, the core change behind the "Independent OTP mail key"
//! feature. Everything else about `check_recipient`'s pure logic
//! (`RecipientCheck`'s variants, the stale-edit guard, the budget) is
//! covered without a session at all in `ui_otp_mail_test.rs`, via
//! `UiState::otp_mail_set_check` standing in for whatever this function
//! would have answered - this file is what proves the function itself
//! resolves to the right keychain name.
//!
//! @requirement AC-294

use aloo::client::connect::ResolvedIdentity;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_mail::{RecipientCheck, check_recipient};
use aloo::client::session::{SessionState, TestSessionSpec};

const TEST_BITS: usize = 1024;

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-mail-recipient-check-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn require_otp() -> bool {
    let probe = OtpCliConfig {
        binary_path: "otp".into(),
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

/// Generates a real key pair and returns one side's own (encryption,
/// decryption) file paths - same technique `contacts_test.rs::make_key_pair`
/// uses.
async fn make_key_pair(cfg: &OtpCliConfig) -> (std::path::PathBuf, std::path::PathBuf) {
    otp_cli::new_key_pair(cfg, 1, "a", "b").await.expect("new_key_pair");
    (
        cfg.working_dir.join("a_keys").join("encryption_for_b.key"),
        cfg.working_dir.join("a_keys").join("decryption_from_b.key"),
    )
}

async fn session_with_pinned_peer(
    label: &str,
    cfg: OtpCliConfig,
) -> (SessionState, [u8; 32], [u8; 32]) {
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let own_fp = aloo::crypto::pq::fingerprint_of_encoded(&own_public_der).expect("own fp");
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch(label),
        otp: Some(cfg),
    })
    .await;

    let (peer_public, _peer_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    let peer_fp = aloo::crypto::pq::fingerprint_of_encoded(&peer_der).expect("peer fp");
    session.id_store_mut().check_and_pin_with("bob", &peer_der, Trust::Verified);
    (session, own_fp, peer_fp)
}

/// @requirement AC-294
#[tokio::test]
async fn a_live_otp_key_alone_is_not_enough_to_send_mail() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("live-not-mail-otp") };
    let (session, own_fp, peer_fp) = session_with_pinned_peer("live-not-mail", cfg.clone()).await;

    // Install a key under the *live* contact name only.
    let live_name = aloo::crypto::otp::contact_name_for(&own_fp, &peer_fp);
    let (enc, dec) = make_key_pair(&cfg).await;
    otp_cli::add_contact(&cfg, &live_name, &enc, &dec).await.expect("add_contact (live)");

    let check = check_recipient(&session, "bob").await;
    assert_eq!(
        check,
        RecipientCheck::NoMailKey,
        "a live session key must never be mistaken for a mail key: {check:?}"
    );
}

/// @requirement AC-294
#[tokio::test]
async fn a_mail_key_installed_under_its_own_name_lets_mail_through() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("mail-key-ok-otp") };
    let (session, own_fp, peer_fp) = session_with_pinned_peer("mail-key-ok", cfg.clone()).await;

    let mail_name = aloo::crypto::otp::contact_name_for_mail(&own_fp, &peer_fp);
    let (enc, dec) = make_key_pair(&cfg).await;
    otp_cli::add_contact(&cfg, &mail_name, &enc, &dec).await.expect("add_contact (mail)");

    let check = check_recipient(&session, "bob").await;
    match check {
        RecipientCheck::Ok { contact_name, .. } => assert_eq!(contact_name, mail_name),
        other => panic!("expected Ok against the mail key, got {other:?}"),
    }
}

/// @requirement AC-294
#[tokio::test]
async fn having_both_keys_still_resolves_to_the_mail_key_specifically() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("both-keys-otp") };
    let (session, own_fp, peer_fp) = session_with_pinned_peer("both-keys", cfg.clone()).await;

    let live_name = aloo::crypto::otp::contact_name_for(&own_fp, &peer_fp);
    let mail_name = aloo::crypto::otp::contact_name_for_mail(&own_fp, &peer_fp);
    assert_ne!(live_name, mail_name);
    let (live_enc, live_dec) = make_key_pair(&cfg).await;
    otp_cli::add_contact(&cfg, &live_name, &live_enc, &live_dec).await.expect("add_contact (live)");
    // A second, distinct key pair - the real `otp` binary refuses reusing
    // one pad's bytes under two different contacts.
    let mail_cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("both-keys-mail-gen") };
    let (mail_enc, mail_dec) = make_key_pair(&mail_cfg).await;
    otp_cli::add_contact(&cfg, &mail_name, &mail_enc, &mail_dec).await.expect("add_contact (mail)");

    let check = check_recipient(&session, "bob").await;
    match check {
        RecipientCheck::Ok { contact_name, .. } => {
            assert_eq!(contact_name, mail_name, "mail must resolve to its own key, not the live one")
        }
        other => panic!("expected Ok against the mail key, got {other:?}"),
    }
}
