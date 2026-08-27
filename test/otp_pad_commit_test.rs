//! `client::otp::on_pad_commit`'s install-failure/retry safety
//! (`docs/PROTOCOL.md` §16, the streamed pad's two-phase commit).
//!
//! A real remote bug report traced back here: the sender installs its own
//! half of a fresh pad and immediately marks the session live
//! (`on_pad_verify`), then hands the receiver the one remaining
//! authorization to install its half, `OtpPadCommit`, retried on every
//! reconnect until acknowledged (`resend_pending_commits`). If the
//! receiver's `otp` binary is unreachable exactly then, the install fails -
//! and used to unconditionally delete the staged pad and return without
//! acknowledging anything. The next retried commit then found nothing
//! staged and took the "already handled, nothing to do" branch meant for a
//! *genuinely* re-delivered commit, acknowledging a pad that was never
//! actually installed. The sender believed the exchange fully succeeded;
//! the receiver had nothing on disk for that contact at all - every
//! message the sender then sent failed to decrypt, with the receiver's own
//! copy of the pad already gone.
//!
//! These tests drive `on_pad_commit` directly against a staged pad
//! (`SessionState::stage_incoming_pad_for_test`), proving the fixed
//! behavior: a failed install leaves the staged pad and the map entry
//! exactly alone and never acknowledges, so an identical retry against a
//! now-working binary installs it for real.
//!
//! @requirement AC-374

use aloo::client::connect::ResolvedIdentity;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{KeyMode, UserId, UserInfo};

const PEER: UserId = UserId(2);
const CONTACT: &str = "test-contact-for-pad-commit";

/// This file's success-path test needs the real binary to prove an actual
/// install; the failure-path test does not (it deliberately never reaches
/// one), but is skipped alongside it for a suite that reads consistently
/// either way.
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
        "aloo-otp-pad-commit-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `otp: None` (`TestSessionSpec`'s own doc) already points at a binary
/// path that deliberately does not exist - exactly the "unreachable"
/// starting state every test here wants.
async fn session_with_no_otp_binary(label: &str) -> SessionState {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private, public_der },
        scratch: scratch(label),
        otp: None,
    })
    .await
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

/// @requirement AC-374
#[tokio::test]
async fn a_failed_install_keeps_the_staged_pad_and_sends_no_ack() {
    let mut session = session_with_no_otp_binary("install-fails").await;
    let mut ui = UiState::new("me".into());
    known_bob(&mut ui);

    // A real link to `from` always exists by the time `on_pad_commit` runs
    // in production - it is only ever reached by an event that just
    // arrived over one (`session::handle_p2p_event`'s `OtpPadCommit` arm).
    // Registered here so the "no ack" assertion below proves the fixed
    // code path chose not to send one, rather than trivially passing
    // because nothing had anywhere to queue to yet.
    session
        .peer_link_mut()
        .ensure_link(&mut aloo::control::NullSink, PEER)
        .await;

    session.stage_incoming_pad_for_test(PEER, CONTACT.to_string());
    assert!(session.has_staged_incoming_pad_for_test(PEER));

    aloo::client::otp::on_pad_commit(&mut session, &mut ui, PEER, CONTACT.to_string()).await;

    assert!(
        session.has_staged_incoming_pad_for_test(PEER),
        "a failed install must not delete the only copy of the staged pad"
    );
    assert!(
        !ui.is_otp_active(PEER),
        "a failed install must never mark the session live"
    );
    let acks = session
        .peer_link_mut()
        .pending_payloads(PEER)
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpPadCommitAck { .. }))
        .count();
    assert_eq!(
        acks, 0,
        "a failed install must never acknowledge a commit it did not actually honor"
    );
    let (message, success) = ui
        .status_notice
        .clone()
        .expect("a failed install must still tell the user something happened");
    assert!(!success, "an install failure is never a success notice");
    assert!(
        message.contains("bob"),
        "the notice should name who the pad came from: {message:?}"
    );
}

/// The exact scenario a real-world bug traced back to this function:
/// install fails once (`otp` unreachable), then the *same* commit arrives
/// again (`resend_pending_commits`, on the next reconnect) once the binary
/// works - proving the retry finds genuinely usable staged bytes rather
/// than the "nothing staged, ack anyway" fallback a deleted pad used to
/// fall into.
///
/// @requirement AC-374
#[tokio::test]
async fn a_retried_commit_after_the_binary_recovers_installs_for_real() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_no_otp_binary("install-then-retries").await;
    let mut ui = UiState::new("me".into());
    known_bob(&mut ui);
    session
        .peer_link_mut()
        .ensure_link(&mut aloo::control::NullSink, PEER)
        .await;

    session.stage_incoming_pad_for_test(PEER, CONTACT.to_string());

    // First attempt: binary unreachable, exactly as the previous test
    // proves in isolation.
    aloo::client::otp::on_pad_commit(&mut session, &mut ui, PEER, CONTACT.to_string()).await;
    assert!(session.has_staged_incoming_pad_for_test(PEER));

    // The binary becomes reachable (fixed PATH, package installed, ...) -
    // nothing else about the session changes, matching a real reconnect
    // retry rather than a fresh process.
    session.set_otp_binary_path_for_test(OtpCliConfig::resolve().binary_path);

    aloo::client::otp::on_pad_commit(&mut session, &mut ui, PEER, CONTACT.to_string()).await;

    assert!(
        !session.has_staged_incoming_pad_for_test(PEER),
        "a successful install consumes the staged pad"
    );
    assert!(
        ui.is_otp_active(PEER),
        "a successful install must mark the session live"
    );
    let acks = session
        .peer_link_mut()
        .pending_payloads(PEER)
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpPadCommitAck { .. }))
        .count();
    assert_eq!(
        acks, 1,
        "exactly one genuine install must produce exactly one acknowledgement"
    );

    // The contact really is installed and usable, not just marked so in
    // memory - the whole point of the retry.
    let status = otp_cli::show_contact(&session.otp_cli_cfg_for_test(), CONTACT)
        .await
        .expect("show-contact should not fail")
        .expect("the contact must genuinely exist in the keychain now");
    assert!(status.dec_key_remaining > 0, "the installed pad must have real key bytes");
}
