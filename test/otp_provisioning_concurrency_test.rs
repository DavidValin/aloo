//! `client::otp::handle_provisioning_command`'s concurrency guard - the
//! scope decision from the "Independent OTP mail key" feature: rather than
//! fully purpose-tagging every piece of shared provisioning state
//! (`session.otp_incoming_setup`/`otp_incoming_pads`/`otp_outgoing_pads`,
//! `ui_state.otp_invites`, the singleton confirm/size/keygen popups) so a
//! live `/otp` and a mail-only `/new-otp-mail-key` handshake with the same
//! peer could run genuinely concurrently, a second handshake of *either*
//! purpose is refused outright while one is already in flight.
//!
//! The guard is checked before anything else in the function (before even
//! reading the peer's identity or checking for the `otp` binary), so a
//! session with no real identity, no `otp` binary, and no established pad
//! is enough to exercise it - exactly the "queued invite from this peer"
//! branch of the four-way check.
//!
//! @requirement AC-296

use aloo::client::connect::ResolvedIdentity;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::UserId;

const PEER: UserId = UserId(2);

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
        "aloo-otp-provisioning-concurrency-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn fresh_session(label: &str) -> SessionState {
    let (public, private) =
        aloo::crypto::pq::generate_bundle_with_bits(1024).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private, public_der },
        scratch: scratch(label),
        otp: None,
    })
    .await
}

/// @requirement AC-296
#[tokio::test]
async fn a_second_handshake_with_a_peer_who_already_has_a_queued_invite_is_refused() {
    let mut session = fresh_session("queued-invite").await;
    let mut ui = UiState::new("me".into());

    // Seeds exactly one of the guard's four conditions - a live/mail
    // provisioning invite already queued from this same peer - without
    // needing a real pad, identity, or `otp` binary to get there.
    ui.push_otp_invite(PEER, "bob".to_string(), "some-contact-name".to_string(), None, None, None);
    assert!(ui.has_otp_invite_from(PEER));

    let peer_der = b"whatever bytes this peer announced".to_vec();
    let result = aloo::client::otp::handle_provisioning_command(
        &mut NullSink,
        &mut ui,
        &mut session,
        PEER,
        peer_der,
        OtpPurpose::Mail,
    )
    .await;

    assert!(result.is_ok(), "the guard itself never fails the call");
    let (message, success) = ui.status_notice.clone().expect("a notice must explain the refusal");
    assert!(
        message.contains("already in progress"),
        "the refusal must say why: {message:?}"
    );
    assert!(!success, "a refusal is not a success notice");
    assert!(
        ui.otp_invite_open().is_some(),
        "the queued invite that triggered the refusal is untouched"
    );
}

/// @requirement AC-296
#[tokio::test]
async fn a_handshake_with_a_peer_who_has_nothing_queued_is_not_refused_by_the_guard() {
    let mut session = fresh_session("no-queued-invite").await;
    let mut ui = UiState::new("me".into());
    assert!(!ui.has_otp_invite_from(PEER));

    // No `otp` binary is configured (`otp: None`), so this still fails -
    // but *past* the concurrency guard, on the next check instead (proven
    // by the message no longer being the guard's own wording).
    let peer_der = b"whatever bytes this peer announced".to_vec();
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

    let (message, success) = ui.status_notice.expect("some notice is still shown");
    assert!(
        !message.contains("already in progress"),
        "with nothing queued, the guard must not be what refuses this: {message:?}"
    );
    assert!(!success);
}

/// `/new-otp-mail-key` on a contact that already has a mail key: unlike
/// `/otp`, which legitimately re-sends `OtpSessionRequest` even when a key
/// already exists (that is what resumes a session after `/endotp`), mail
/// has no session to resume - one call to `check_recipient` at compose
/// time already answers whether it's usable. So this must be refused
/// locally, with the exact wording asked for, before anything reaches the
/// network.
///
/// @requirement AC-302
#[tokio::test]
async fn a_mail_key_that_already_exists_is_refused_locally() {
    if !require_otp() {
        return;
    }
    let (own_public, own_private) =
        aloo::crypto::pq::generate_bundle_with_bits(1024).expect("own pq keygen");
    let own_public_der = aloo::proto::encode(&own_public).expect("own pq der");
    let own_fp = aloo::crypto::pq::fingerprint_of_encoded(&own_public_der).expect("own fp");
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("mail-exists-otp") };
    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private: own_private, public_der: own_public_der },
        scratch: scratch("mail-exists-session"),
        otp: Some(cfg),
    })
    .await;

    let (peer_public, _) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("peer pq keygen");
    let peer_der = aloo::proto::encode(&peer_public).expect("peer pq der");
    let peer_fp = aloo::crypto::pq::fingerprint_of_encoded(&peer_der).expect("peer fp");
    session.id_store_mut().check_and_pin_with("bob", &peer_der, Trust::Verified);

    // Marked provisioned directly - `detect_or_adopt_existing`'s own first
    // check is exactly this in-memory flag, so this reaches the same
    // "already have a key" state a real prior exchange would, without
    // needing one.
    let mail_name = aloo::crypto::otp::contact_name_for_mail(&own_fp, &peer_fp);
    session.otp_store_mut().mark_provisioned(&mail_name);

    let mut ui = UiState::new("me".into());
    ui.known_users.insert(
        PEER,
        aloo::proto::UserInfo {
            id: PEER,
            name: "bob".into(),
            public_key_der: peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );

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

    let (message, success) = ui.status_notice.expect("a notice must explain the refusal");
    assert_eq!(
        message, "otp mail key already exists. use /mail or delete existing in /contacts",
        "the exact wording asked for"
    );
    assert!(!success);
}
