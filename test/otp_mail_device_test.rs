//! `client::otp_mail::enumerate_mail_devices`/`check_recipient`'s
//! explicit-device resolution against a real `SessionState` and the real
//! `otp` CLI - the device-selector counterpart to
//! `otp_mail_recipient_check_test.rs`, which already covers
//! `check_recipient`'s live/mail-key distinction for a single device.
//! This file is what proves device *targeting* itself is load-bearing:
//! two devices of the same nickname, only one with a mail key, correctly
//! resolve to different `RecipientCheck`s depending on which device_id is
//! named - something the old "always most-recently-seen" resolution could
//! never have told apart.
//!
//! @requirement AC-336

use aloo::client::connect::ResolvedIdentity;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_mail::{RecipientCheck, check_recipient, enumerate_mail_devices, handle_send};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::proto::ClientMessage;

const TEST_BITS: usize = 1024;

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-mail-device-{label}-{}-{}",
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

/// Two devices pinned for "bob", each with its own independently
/// generated pq_hybrid key (two real devices never share one).
async fn session_with_two_devices(
    label: &str,
    cfg: OtpCliConfig,
) -> (SessionState, [u8; 32], [u8; 32], [u8; 32]) {
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

    let (device_a_public, _) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("device-a pq keygen");
    let device_a_der = aloo::proto::encode(&device_a_public).expect("device-a pq der");
    let device_a_fp = aloo::crypto::pq::fingerprint_of_encoded(&device_a_der).expect("device-a fp");
    session
        .id_store_mut()
        .pin_new_device("bob", "device-a", &device_a_der, Trust::Verified);

    let (device_b_public, _) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("device-b pq keygen");
    let device_b_der = aloo::proto::encode(&device_b_public).expect("device-b pq der");
    let device_b_fp = aloo::crypto::pq::fingerprint_of_encoded(&device_b_der).expect("device-b fp");
    session
        .id_store_mut()
        .pin_new_device("bob", "device-b", &device_b_der, Trust::Verified);

    (session, own_fp, device_a_fp, device_b_fp)
}

/// @requirement AC-336, TB-255
#[tokio::test]
async fn enumerate_mail_devices_lists_every_pinned_device_and_whether_each_has_a_mail_key() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("enumerate") };
    let (session, own_fp, device_a_fp, _device_b_fp) =
        session_with_two_devices("enumerate", cfg.clone()).await;

    // Only device-a gets a real mail key installed.
    let mail_name = aloo::crypto::otp::contact_name_for_mail(
        &own_fp,
        session.own_device_id_for_test(),
        &device_a_fp,
        "device-a",
    );
    let (enc, dec) = make_key_pair(&cfg).await;
    otp_cli::add_contact(&cfg, &mail_name, &enc, &dec).await.expect("add_contact");

    let devices = enumerate_mail_devices(&session, "bob").await;
    assert_eq!(devices.len(), 2, "both pinned devices are listed: {devices:?}");
    let a = devices.iter().find(|d| d.device_id == "device-a").expect("device-a present");
    assert!(a.has_mail_key, "device-a has a real mail key installed");
    assert_eq!(a.contact_name, mail_name);
    let b = devices.iter().find(|d| d.device_id == "device-b").expect("device-b present");
    assert!(!b.has_mail_key, "device-b has no mail key installed");
}

/// @requirement AC-336, TB-255
#[tokio::test]
async fn enumerate_mail_devices_skips_the_unbound_entry() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("unbound") };
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch("unbound-session"),
        otp: Some(cfg),
    })
    .await;
    let (peer_public, _) = aloo::crypto::pq::generate_bundle_with_bits(TEST_BITS).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    // Pinned with no device_id known yet - the "unbound" sentinel.
    session.id_store_mut().pin_new_device("bob", "", &peer_der, Trust::Verified);

    let devices = enumerate_mail_devices(&session, "bob").await;
    assert!(
        devices.is_empty(),
        "an unbound device_id can never be a valid mail target: {devices:?}"
    );
}

/// @requirement AC-336, TB-255
#[tokio::test]
async fn check_recipient_now_requires_an_explicit_device_and_distinguishes_two_devices() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("distinguish") };
    let (session, own_fp, device_a_fp, _device_b_fp) =
        session_with_two_devices("distinguish", cfg.clone()).await;

    // Only device-a (the OLDER one, by construction order here - the
    // point is that a naive "most recently seen" resolution used to be
    // the ONLY thing check_recipient could ever ask about, so it could
    // never have told these two devices apart) gets a mail key.
    let mail_name = aloo::crypto::otp::contact_name_for_mail(
        &own_fp,
        session.own_device_id_for_test(),
        &device_a_fp,
        "device-a",
    );
    let (enc, dec) = make_key_pair(&cfg).await;
    otp_cli::add_contact(&cfg, &mail_name, &enc, &dec).await.expect("add_contact");

    let check_a = check_recipient(&session, "bob", "device-a").await;
    match check_a {
        RecipientCheck::Ok { contact_name, .. } => assert_eq!(contact_name, mail_name),
        other => panic!("device-a has a mail key, expected Ok, got {other:?}"),
    }

    let check_b = check_recipient(&session, "bob", "device-b").await;
    assert_eq!(
        check_b,
        RecipientCheck::NoMailKey,
        "device-b has no mail key - must resolve differently from device-a, proving device \
         selection is now load-bearing"
    );
}

/// @requirement AC-336
#[tokio::test]
async fn handle_send_seals_and_uploads_under_the_explicitly_selected_devices_contact_name() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("send-selected") };
    let (mut session, own_fp, device_a_fp, device_b_fp) =
        session_with_two_devices("send-selected", cfg.clone()).await;

    let mail_name_a = aloo::crypto::otp::contact_name_for_mail(
        &own_fp,
        session.own_device_id_for_test(),
        &device_a_fp,
        "device-a",
    );
    let mail_name_b = aloo::crypto::otp::contact_name_for_mail(
        &own_fp,
        session.own_device_id_for_test(),
        &device_b_fp,
        "device-b",
    );
    assert_ne!(mail_name_a, mail_name_b);
    let (enc_a, dec_a) = make_key_pair(&cfg).await;
    otp_cli::add_contact(&cfg, &mail_name_a, &enc_a, &dec_a).await.expect("add_contact a");
    let cfg_b_gen = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("send-selected-gen-b") };
    let (enc_b, dec_b) = make_key_pair(&cfg_b_gen).await;
    otp_cli::add_contact(&cfg, &mail_name_b, &enc_b, &dec_b).await.expect("add_contact b");

    let mut ui = UiState::new("me".into());
    ui.open_otp_mail();
    {
        let compose = &mut ui.otp_mail.as_mut().unwrap().compose;
        compose.to = "bob".to_string();
        compose.content = "hello from the non-default device".to_string();
    }
    let devices = enumerate_mail_devices(&session, "bob").await;
    ui.otp_mail_set_devices("bob", devices);
    // The default would pick whichever device sorts first by last-seen
    // (both are `None` here, so index 0 - "device-a"); explicitly select
    // the OTHER one to prove Send actually honors the selection rather
    // than silently falling back to a default.
    assert!(
        ui.otp_mail_set_selected_device("bob", "device-b"),
        "device-b must be one of the enumerated devices"
    );

    let mut sink = RecordingSink::default();
    handle_send(&mut sink, &mut session, &mut ui).await.expect("handle_send");

    let sent = sink.sent.iter().find_map(|m| match m {
        ClientMessage::OtpMailSend { contact_name, .. } => Some(contact_name.clone()),
        _ => None,
    });
    assert_eq!(
        sent.as_deref(),
        Some(mail_name_b.as_str()),
        "the mail must be sealed under the explicitly selected device-b's contact name, \
         not device-a's (the default)"
    );
}

/// A `ControlSink` that records what would have gone to the server - the
/// same pattern `otp_mail_test.rs`'s own `RecordingSink` uses.
#[derive(Default)]
struct RecordingSink {
    sent: Vec<ClientMessage>,
}

impl aloo::control::ControlSink for RecordingSink {
    async fn send_control(&mut self, msg: &ClientMessage) -> aloo::proto::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
}
