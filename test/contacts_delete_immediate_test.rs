//! Proves the "immediate effect" half of AC-300 at the row level:
//! `handle_delete_otp_key`/`handle_delete_contact_device`/`handle_delete`
//! already call `handle_open` internally (`src/client/contacts.rs`), so
//! `ui_state.contacts.rows` must reflect a deletion the instant the
//! handler returns - no extra `open_contacts`/reopen call needed, and no
//! separate "refresh" step for the caller to remember. `contacts_test.rs`
//! already covers the lower-level `delete_contact`/`delete_contact_device`
//! keychain-removal logic directly against a plain `IdStore`;
//! `contacts_mail_refresh_test.rs` already covers the `/mail` compose
//! recipient-check refresh. This file is the missing third leg: the
//! Contacts list's own rows.

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::KeyMode;

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
    (cfg.working_dir.join("a_keys").join("encryption_for_b.key"), cfg.working_dir.join("a_keys").join("decryption_from_b.key"))
}

const TEST_BITS: usize = 1024;

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-contacts-delete-immediate-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn session_with_pinned_device(label: &str, otp: OtpCliConfig, nickname: &str, device_id: &str) -> SessionState {
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
        nickname,
        device_id,
        &peer_der,
        Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );
    session
}

/// Deleting a contact's OTP key must clear its `otp` badge in
/// `ui_state.contacts.rows` immediately - the very same call that removed
/// it from the keychain, not a later reopen of `/contacts`.
/// @requirement AC-300
#[tokio::test]
async fn deleting_an_otp_key_clears_the_row_immediately() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let mut session = session_with_pinned_device("session", cfg.clone(), "alice", "laptop").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();

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
    let row = ui
        .contacts
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop"))
        .expect("row exists after install");
    assert!(row.otp.is_some(), "OTP key must show installed before deleting it");

    contacts::handle_delete_otp_key(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
    )
    .await;

    // Deliberately no `ui.open_contacts()`/reopen here - the whole point
    // is that the handler's own internal `handle_open` already refreshed
    // `rows` by the time it returned.
    let row = ui
        .contacts
        .as_ref()
        .unwrap()
        .rows
        .iter()
        .find(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop"))
        .expect("the pqh-pinned row itself must still exist - only the otp key was deleted");
    assert!(
        row.otp.is_none(),
        "the otp badge must be gone the instant handle_delete_otp_key returns, with no reopen"
    );
}

/// Deleting a whole device (its PQH key, cascading both OTP purposes)
/// must remove its row from `ui_state.contacts.rows` immediately.
/// @requirement AC-300
#[tokio::test]
async fn deleting_a_contact_device_removes_its_row_immediately() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg-device") };
    let mut session = session_with_pinned_device("session-device", cfg, "alice", "laptop").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    contacts::handle_open(&session, &mut ui).await;
    assert!(
        ui.contacts
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .any(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop")),
        "row exists before deleting the device"
    );

    contacts::handle_delete_contact_device(
        &mut session,
        &mut ui,
        "alice".to_string(),
        Some("laptop".to_string()),
    )
    .await;

    assert!(
        !ui.contacts
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .any(|r| r.nickname == "alice" && r.device_id.as_deref() == Some("laptop")),
        "the row must be gone from ui_state immediately, with no reopen of /contacts"
    );
}

/// Deleting a whole nickname must remove every one of its rows from
/// `ui_state.contacts.rows` immediately.
/// @requirement AC-300
#[tokio::test]
async fn deleting_a_contact_removes_every_row_immediately() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg-nick") };
    let mut session = session_with_pinned_device("session-nick", cfg, "alice", "laptop").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();

    contacts::handle_delete(&mut session, &mut ui, "alice".to_string()).await;

    assert!(
        !ui.contacts.as_ref().unwrap().rows.iter().any(|r| r.nickname == "alice"),
        "every one of alice's rows must be gone from ui_state immediately"
    );
}
