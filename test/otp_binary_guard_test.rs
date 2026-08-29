//! `/otp`, `/mail`, and `/new-otp-mail-key` must all refuse locally,
//! before touching the network or opening any popup, when the local `otp`
//! binary is not available - the same guard `client::otp::handle_provisioning_command`
//! already applied to `/otp`/`/new-otp-mail-key`, extended to `/mail`
//! (`client::otp_mail::handle_open_otp_mail`) so composing a mail can never
//! reach send time only to fail there, or worse, fail invisibly the way
//! the pad layer itself once could (see `otp_pad_commit_test.rs`,
//! `otp_ack_wiring_test.rs`'s `a_message_for_a_contact_never_installed_*`).
//!
//! @requirement AC-376

use aloo::client::connect::ResolvedIdentity;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::crypto::otp::OtpPurpose;
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
        "aloo-otp-binary-guard-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn session_with_otp(label: &str, otp: Option<OtpCliConfig>) -> SessionState {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    session_with_identity(label, ResolvedIdentity { private, public_der }, otp).await
}

/// Like `session_with_otp`, but with a caller-supplied identity - needed
/// whenever a test also computes a contact name from that same identity's
/// fingerprint outside the session (`crypto::otp::contact_name_for_mail`),
/// which must be built from the exact keypair the session itself holds as
/// `own_pq_fp`, not a second, unrelated one.
async fn session_with_identity(
    label: &str,
    identity: ResolvedIdentity,
    otp: Option<OtpCliConfig>,
) -> SessionState {
    SessionState::for_test(TestSessionSpec {
        identity,
        scratch: scratch(label),
        otp,
    })
    .await
}

fn known_bob(ui: &mut UiState, peer_der: Vec<u8>) {
    ui.known_users.insert(
        PEER,
        UserInfo {
            id: PEER,
            name: "bob".into(),
            public_key_der: peer_der,
            key_mode: KeyMode::PqHybrid,
        },
    );
}

// ---------------------------------------------------------------------
// Unhappy flow: no local binary
// ---------------------------------------------------------------------

/// @requirement AC-376
#[tokio::test]
async fn otp_is_refused_locally_without_the_binary() {
    let mut session = session_with_otp("otp-no-binary", None).await;
    let mut ui = UiState::new("me".into());
    let peer_der = b"whatever bytes this peer announced".to_vec();
    known_bob(&mut ui, peer_der.clone());

    aloo::client::otp::handle_provisioning_command(
        &mut NullSink,
        &mut ui,
        &mut session,
        PEER,
        peer_der,
        OtpPurpose::Live,
    )
    .await
    .expect("the guard itself never fails the call");

    let (message, success) = ui.status_notice.clone().expect("a notice must explain the refusal");
    assert_eq!(
        message,
        "OTP session failed: the 'otp' command isn't installed - see \
         github.com/DavidValin/otp-toolkit"
    );
    assert!(!success);
    assert!(!ui.is_otp_active(PEER), "nothing was ever started");
}

/// @requirement AC-376
#[tokio::test]
async fn new_otp_mail_key_is_refused_locally_without_the_binary() {
    let mut session = session_with_otp("mail-key-no-binary", None).await;
    let mut ui = UiState::new("me".into());
    let peer_der = b"whatever bytes this peer announced".to_vec();
    known_bob(&mut ui, peer_der.clone());

    aloo::client::otp::handle_provisioning_command(
        &mut NullSink,
        &mut ui,
        &mut session,
        PEER,
        peer_der,
        OtpPurpose::Mail,
    )
    .await
    .expect("the guard itself never fails the call");

    let (message, success) = ui.status_notice.expect("a notice must explain the refusal");
    assert_eq!(
        message,
        "OTP mail key failed: the 'otp' command isn't installed - see \
         github.com/DavidValin/otp-toolkit"
    );
    assert!(!success);
}

/// @requirement AC-376
#[tokio::test]
async fn mail_compose_is_refused_locally_without_the_binary() {
    let session = session_with_otp("mail-compose-no-binary", None).await;
    let mut ui = UiState::new("me".into());

    aloo::client::otp_mail::handle_open_otp_mail(&session, &mut ui);

    assert!(
        ui.otp_mail.is_none(),
        "the compose view must never open without the binary"
    );
    let (message, success) = ui.status_notice.expect("a notice must explain the refusal");
    assert_eq!(
        message,
        "OTP mail failed: the 'otp' command isn't installed - see \
         github.com/DavidValin/otp-toolkit"
    );
    assert!(!success);
}

// ---------------------------------------------------------------------
// Happy flow: the binary is present, so this guard is not what answers
// ---------------------------------------------------------------------

/// @requirement AC-376
#[tokio::test]
async fn mail_compose_opens_when_the_binary_is_available() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("mail-compose-with-binary"),
    };
    let session = session_with_otp("mail-compose-with-binary-session", Some(cfg)).await;
    let mut ui = UiState::new("me".into());

    aloo::client::otp_mail::handle_open_otp_mail(&session, &mut ui);

    assert!(
        ui.otp_mail.is_some(),
        "the compose view must open once the binary is available"
    );
    assert!(
        ui.status_notice.is_none(),
        "opening successfully shows no refusal notice"
    );
}

/// A contact already provisioned (mirrors
/// `otp_provisioning_concurrency_test.rs`'s identical setup for the
/// concurrency guard) proves the binary check is genuinely passed through
/// to the next stage, rather than merely absent because nothing else was
/// exercised.
///
/// @requirement AC-376
#[tokio::test]
async fn new_otp_mail_key_reaches_the_next_guard_when_the_binary_is_available() {
    if !require_otp() {
        return;
    }
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(1024).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let own_fp = aloo::crypto::pq::fingerprint_of_encoded(&own_public_der).expect("own fp");
    let cfg = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: scratch("mail-key-with-binary-otp"),
    };
    let mut session = session_with_identity(
        "mail-key-with-binary-session",
        ResolvedIdentity { private: own_private, public_der: own_public_der },
        Some(cfg),
    )
    .await;

    let (peer_public, _) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    let peer_fp = aloo::crypto::pq::fingerprint_of_encoded(&peer_der).expect("peer fp");
    session
        .id_store_mut()
        .pin_new_device("bob", "test-device", &peer_der, Trust::Verified);
    session.set_peer_device_id_for_test(PEER, "test-device".to_string());
    let mail_name = aloo::crypto::otp::contact_name_for_mail(
        &own_fp,
        session.own_device_id_for_test(),
        &peer_fp,
        "test-device",
    );
    session.otp_store_mut().mark_provisioned(&mail_name);

    let mut ui = UiState::new("me".into());
    known_bob(&mut ui, peer_der.clone());

    aloo::client::otp::handle_provisioning_command(
        &mut NullSink,
        &mut ui,
        &mut session,
        PEER,
        peer_der,
        OtpPurpose::Mail,
    )
    .await
    .expect("the function itself does not fail");

    if let Some((message, _)) = &ui.status_notice {
        assert!(
            !message.contains("isn't installed"),
            "with the binary available, this must not be what refuses it: {message:?}"
        );
    }
    assert!(
        ui.otp_generate_confirm_open().is_some(),
        "reaches the next guard down the chain, proving the binary check passed - an \
         already-existing mail key now proceeds to the fresh-generate confirmation (AC-384) \
         rather than refusing outright"
    );
}

