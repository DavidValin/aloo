//! "Takes effect immediately": installing, creating, or deleting any of a
//! contact's three keys from `/contacts` must be reflected in an *already
//! open* `/mail` compose view for that same nickname without the user
//! retyping anything -
//! `client::contacts::refresh_mail_recipient_check_if_open`, called from
//! every one of `handle_delete`/`handle_install_otp_key`/
//! `handle_delete_otp_key`/`handle_pin_identity_card`.
//!
//! A real `SessionState` and the real `otp` CLI are needed here (unlike
//! `ui_otp_mail_test.rs`, which injects a check result directly and never
//! exercises `check_recipient` itself) - skipped when the binary isn't
//! installed, same convention as every other test that shells out to it.
//!
//! @requirement AC-300

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_mail::{RecipientCheck, check_recipient};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::crypto::otp::OtpPurpose;

const TEST_BITS: usize = 1024;

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-contacts-mail-refresh-{label}-{}-{}",
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
    let probe = OtpCliConfig { binary_path: "otp".into(), working_dir: std::env::temp_dir() };
    if otp_cli::binary_available(&probe) {
        return true;
    }
    eprintln!(
        "skipping: 'otp' binary not found on PATH (or ALOO_OTP_BIN) - install otp-toolkit to \
         run this test locally: https://github.com/DavidValin/otp-toolkit"
    );
    false
}

async fn make_key_pair(cfg: &OtpCliConfig) -> (std::path::PathBuf, std::path::PathBuf) {
    otp_cli::new_key_pair(cfg, 1, "a", "b").await.expect("new_key_pair");
    (
        cfg.working_dir.join("a_keys").join("encryption_for_b.key"),
        cfg.working_dir.join("a_keys").join("decryption_from_b.key"),
    )
}

/// @requirement AC-300
#[tokio::test]
async fn installing_and_deleting_the_mail_key_refreshes_an_open_composes_recipient_check() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp") };
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch("session"),
        otp: Some(cfg.clone()),
    })
    .await;
    let (peer_public, _peer_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    session.id_store_mut().pin_new_device("bob", "test-device", &peer_der, Trust::Verified);

    let mut ui = UiState::new("me".into());
    ui.open_otp_mail();
    ui.otp_mail.as_mut().unwrap().compose.to = "bob".to_string();

    // Seeds the initial check exactly as the real `CheckOtpMailRecipient`
    // wiring would the moment "bob" was typed (`otp_mail::handle_check_recipient`
    // is `pub(crate)`; this is its exact body, inlined for an external test).
    let check = check_recipient(&session, "bob").await;
    ui.otp_mail_set_check("bob", check);
    assert_eq!(
        ui.otp_mail.as_ref().unwrap().compose.check,
        Some(RecipientCheck::NoMailKey),
        "no mail key exists yet"
    );

    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "bob".to_string(),
        Some("test-device".to_string()),
        OtpPurpose::Mail,
        enc,
        dec,
    )
    .await;
    match &ui.otp_mail.as_ref().unwrap().compose.check {
        Some(RecipientCheck::Ok { .. }) => {}
        other => panic!(
            "installing the mail key must refresh the already-open compose's check \
             without retyping anything, got {other:?}"
        ),
    }

    contacts::handle_delete_otp_key(
        &mut session,
        &mut ui,
        "bob".to_string(),
        Some("test-device".to_string()),
        OtpPurpose::Mail,
    )
    .await;
    assert_eq!(
        ui.otp_mail.as_ref().unwrap().compose.check,
        Some(RecipientCheck::NoMailKey),
        "deleting it must refresh the check back just as immediately"
    );
}

/// @requirement AC-300
#[tokio::test]
async fn installing_a_mail_key_does_not_refresh_a_compose_open_for_someone_else() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-other") };
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch("session-other"),
        otp: Some(cfg.clone()),
    })
    .await;
    let (bob_public, _) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("bob pq keygen");
    let bob_der = aloo::proto::encode(&bob_public).expect("bob pq der");
    session.id_store_mut().pin_new_device("bob", "test-device", &bob_der, Trust::Verified);
    let (carol_public, _) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("carol pq keygen");
    let carol_der = aloo::proto::encode(&carol_public).expect("carol pq der");
    session.id_store_mut().pin_new_device("carol", "test-device", &carol_der, Trust::Verified);

    let mut ui = UiState::new("me".into());
    ui.open_otp_mail();
    ui.otp_mail.as_mut().unwrap().compose.to = "carol".to_string();
    let check = check_recipient(&session, "carol").await;
    ui.otp_mail_set_check("carol", check);
    assert_eq!(ui.otp_mail.as_ref().unwrap().compose.check, Some(RecipientCheck::NoMailKey));

    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "bob".to_string(),
        Some("test-device".to_string()),
        OtpPurpose::Mail,
        enc,
        dec,
    )
    .await;
    assert_eq!(
        ui.otp_mail.as_ref().unwrap().compose.check,
        Some(RecipientCheck::NoMailKey),
        "installing bob's key must not touch a compose open for carol"
    );
}
