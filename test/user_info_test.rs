//! The user-info popup's session-side gather
//! (`client::contacts::handle_request_user_info`, `i` on a channel
//! member/`/info` in an open DM): resolves the live peer's actual device,
//! then lists only the keys that genuinely exist for that
//! `(nickname, device_id)` - never the contacts list's always-three
//! ✅/❌ badges. `ui_user_info_test.rs` covers the pure `UiState` half
//! (opening/closing/dispatch) directly.

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::contacts::ContactKeyKind;
use aloo::client::tui::ui::UiState;
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::UserId;

const TEST_BITS: usize = 1024;
const BOB: UserId = UserId(2);

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-user-info-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
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
    (cfg.working_dir.join("a_keys").join("encryption_for_b.key"), cfg.working_dir.join("a_keys").join("decryption_from_b.key"))
}

async fn session_for_test(label: &str, otp: Option<OtpCliConfig>) -> SessionState {
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch(label),
        otp,
    })
    .await
}

fn find<'a>(kind: ContactKeyKind, keys: &'a [aloo::client::tui::contacts::UserInfoKeyRow]) -> Option<&'a str> {
    keys.iter().find(|k| k.kind == kind).map(|k| k.id.as_str())
}

/// Nothing pinned at all for this nickname - an empty, non-error result.
/// @requirement AC-324
#[tokio::test]
async fn a_peer_with_nothing_pinned_gathers_no_keys_and_no_device() {
    let session = session_for_test("nothing", None).await;
    let mut ui = UiState::new("me".into());
    ui.open_user_info(BOB, "bob".to_string());

    contacts::handle_request_user_info(&session, &mut ui, BOB, "bob".to_string()).await;

    let info = ui.user_info.as_ref().expect("still open - nothing closed it");
    assert!(info.keys.is_empty());
    assert!(info.device_id.is_none());
    assert!(info.last_seen_unix.is_none());
}

/// The PQH-only case: a fingerprint row, but no OTP/OTP MAIL rows even
/// though a device is pinned - `otp_contact_name` alone is not enough,
/// only a real keychain entry earns a row.
/// @requirement AC-324
#[tokio::test]
async fn only_pqh_present_shows_only_the_pqh_row() {
    let mut session = session_for_test("pqh-only", None).await;
    let (peer_public, _peer_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    session.id_store_mut().pin_new_device_with_key_mode(
        "bob",
        "laptop",
        &peer_der,
        Trust::Verified,
        Some(aloo::proto::KeyMode::PqHybrid),
    );
    session.set_peer_device_id_for_test(BOB, "laptop".to_string());

    let mut ui = UiState::new("me".into());
    ui.open_user_info(BOB, "bob".to_string());
    contacts::handle_request_user_info(&session, &mut ui, BOB, "bob".to_string()).await;

    let info = ui.user_info.as_ref().unwrap();
    assert_eq!(info.device_id, Some("laptop".to_string()));
    assert!(find(ContactKeyKind::Pqh, &info.keys).is_some(), "PQH must show up");
    assert!(find(ContactKeyKind::Otp, &info.keys).is_none(), "no OTP keychain entry exists yet");
    assert!(find(ContactKeyKind::OtpMail, &info.keys).is_none());
    assert_eq!(info.keys.len(), 1);
}

/// The full case: PQH pinned, OTP genuinely installed - both rows appear,
/// each with the right id (PQH's fingerprint, OTP's contact name).
/// @requirement AC-324
#[tokio::test]
async fn a_pinned_and_installed_key_shows_up_with_its_id() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp") };
    let mut session = session_for_test("full", Some(cfg.clone())).await;
    let (peer_public, _peer_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    session.id_store_mut().pin_new_device_with_key_mode(
        "bob",
        "laptop",
        &peer_der,
        Trust::Verified,
        Some(aloo::proto::KeyMode::PqHybrid),
    );
    session.set_peer_device_id_for_test(BOB, "laptop".to_string());

    let (enc, dec) = make_key_pair(&cfg).await;
    let mut ui = UiState::new("me".into());
    contacts::handle_install_otp_key(
        &mut session,
        &mut ui,
        "bob".to_string(),
        Some("laptop".to_string()),
        OtpPurpose::Live,
        enc,
        dec,
    )
    .await;

    ui.open_user_info(BOB, "bob".to_string());
    contacts::handle_request_user_info(&session, &mut ui, BOB, "bob".to_string()).await;

    let info = ui.user_info.as_ref().unwrap();
    let pqh_id = find(ContactKeyKind::Pqh, &info.keys).expect("PQH row");
    assert!(!pqh_id.is_empty());
    let otp_id = find(ContactKeyKind::Otp, &info.keys).expect("OTP row");
    assert!(!otp_id.is_empty(), "OTP's id (its contact name) must be filled in");
    assert!(find(ContactKeyKind::OtpMail, &info.keys).is_none(), "mail key was never installed");
}

/// A serverless peer's device resolves through `PeerLinkManager::
/// direct_device_id_of` when there's no live `pq_hybrid` announce to read
/// from `peer_device_ids` at all.
/// @requirement AC-324
#[tokio::test]
async fn a_direct_punch_peers_device_resolves_from_the_link_not_an_announce() {
    let mut session = session_for_test("direct", None).await;
    session.peer_link_mut().configure_direct_punch(
        "me".into(),
        vec![aloo::settings::DirectPunchTarget {
            nickname: "bob".into(),
            device_id: Some("phone".into()),
            host: "127.0.0.1".into(),
            port: 1,
            frequency: aloo::settings::PunchFrequency::parse("every_1h").unwrap(),
        }],
        0,
    );
    let peer = aloo::client::p2p::direct_peer_id("bob", Some("phone"));

    let mut ui = UiState::new("me".into());
    ui.open_user_info(peer, "bob".to_string());
    contacts::handle_request_user_info(&session, &mut ui, peer, "bob".to_string()).await;

    assert_eq!(ui.user_info.as_ref().unwrap().device_id, Some("phone".to_string()));
}
