//! Deleting an OTP key from `/contacts` while a live session with that
//! exact contact is marked active (`UiState::is_otp_active`).
//!
//! Before this, none of the three deletion paths
//! (`handle_delete_otp_key`, `handle_delete_contact_device`,
//! `handle_delete`) ever touched the in-memory active flag - only the
//! keychain entry and the durable `otp_store` record. The user was left
//! stuck: the compose bar kept the 🔑 badge, every send still routed
//! through the OTP path and failed at encrypt time against a keychain
//! entry that no longer existed, `/otp` refused to restart ("already
//! active - use /endotp first"), and `/endotp` itself did not help - it
//! checks `otp_store`, which the deletion had already cleared too, so it
//! took the "no active session" branch and returned without ever
//! clearing the flag. Only a reconnect (which re-derives the flag from
//! scratch) ever recovered.
//!
//! @requirement AC-381

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::{KeyMode, UserId, UserInfo};

const PEER: UserId = UserId(2);
const TEST_BITS: usize = 1024;

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

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-delete-while-active-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn make_key_pair(cfg: &OtpCliConfig) -> (std::path::PathBuf, std::path::PathBuf) {
    otp_cli::new_key_pair(cfg, 1, "a", "b").await.expect("new_key_pair");
    (
        cfg.working_dir.join("a_keys").join("encryption_for_b.key"),
        cfg.working_dir.join("a_keys").join("decryption_from_b.key"),
    )
}

/// A session pinned to `alice`/`laptop`, with `alice` also known and
/// connected in `ui_state` (`is_otp_active`/`contact_name_for_peer` both
/// need a real, resolvable peer, not just an `id_store` pin).
async fn session_with_connected_peer(label: &str, otp: OtpCliConfig) -> (SessionState, UiState) {
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch(label),
        otp: Some(otp),
    })
    .await;
    let (peer_public, _) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    session.id_store_mut().pin_new_device_with_key_mode(
        "alice",
        "laptop",
        &peer_der,
        Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );
    session.set_peer_device_id_for_test(PEER, "laptop".to_string());

    let mut ui = UiState::new("me".into());
    ui.known_users.insert(
        PEER,
        UserInfo { id: PEER, name: "alice".into(), public_key_der: peer_der, key_mode: KeyMode::PqHybrid },
    );
    (session, ui)
}

/// @requirement AC-381
#[tokio::test]
async fn deleting_the_live_key_ends_an_active_session_and_clears_the_stuck_state() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, mut ui) = session_with_connected_peer("session", cfg.clone()).await;
    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
        enc,
        dec,
    )
    .await;
    ui.mark_otp_active(PEER);
    assert!(ui.is_otp_active(PEER), "sanity: the session is marked active before deleting");

    contacts::handle_delete_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
    )
    .await;

    assert!(
        !ui.is_otp_active(PEER),
        "the active flag must not survive the key that backed it being deleted"
    );
    let (message, success) = ui
        .status_notice
        .clone()
        .expect("ending the stuck-active session must be announced");
    assert!(success, "cleanly ending a stuck session is a successful cleanup, not a failure");
    assert!(
        message.contains("ended") && message.contains("alice"),
        "the notice should say the session ended and name who: {message:?}"
    );
}

/// Deleting a key for a contact that was never marked active must not
/// show a spurious "ended" notice - nothing needs ending.
///
/// @requirement AC-381
#[tokio::test]
async fn deleting_a_key_with_no_active_session_shows_no_ended_notice() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, mut ui) = session_with_connected_peer("session", cfg.clone()).await;
    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
        enc,
        dec,
    )
    .await;
    assert!(!ui.is_otp_active(PEER), "sanity: never marked active");

    contacts::handle_delete_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
    )
    .await;

    let notice = ui.status_notice.clone();
    assert!(
        notice.as_ref().is_none_or(|(m, _)| !m.contains("ended the live OTP session")),
        "no session was active, so nothing should claim one ended: {notice:?}"
    );
}

/// Deleting the *mail* key must never touch the live session's active
/// flag - mail has no "active" toggle of its own at all
/// (`client::otp`'s module doc), and the two purposes are otherwise
/// independent.
///
/// @requirement AC-381
#[tokio::test]
async fn deleting_the_mail_key_never_affects_an_active_live_session() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, mut ui) = session_with_connected_peer("session", cfg.clone()).await;
    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Mail,
        enc,
        dec,
    )
    .await;
    ui.mark_otp_active(PEER);

    contacts::handle_delete_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Mail,
    )
    .await;

    assert!(
        ui.is_otp_active(PEER),
        "deleting the mail key must never end the unrelated live session"
    );
}

/// Deleting the *whole device* (cascading both OTP purposes,
/// `UiAction::DeleteContactDevice`) must clear the stuck state exactly
/// like deleting the live key alone does.
///
/// @requirement AC-381
#[tokio::test]
async fn deleting_the_whole_device_ends_its_active_session_too() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, mut ui) = session_with_connected_peer("session", cfg.clone()).await;
    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
        enc,
        dec,
    )
    .await;
    ui.mark_otp_active(PEER);

    contacts::handle_delete_contact_device(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
    )
    .await;

    assert!(
        !ui.is_otp_active(PEER),
        "removing the whole device must end its active session the same way removing just the \
         live key does"
    );
}

/// Deleting the *whole contact* (`UiAction::DeleteContact`, every device
/// at once) must also clear an active session on any of its devices.
///
/// @requirement AC-381
#[tokio::test]
async fn deleting_the_whole_contact_ends_its_active_session_too() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, mut ui) = session_with_connected_peer("session", cfg.clone()).await;
    let (enc, dec) = make_key_pair(&cfg).await;
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
        enc,
        dec,
    )
    .await;
    ui.mark_otp_active(PEER);

    contacts::handle_delete(&mut session, &mut ui, "alice".to_string()).await;

    assert!(
        !ui.is_otp_active(PEER),
        "removing the whole contact must end its active session too"
    );
}
