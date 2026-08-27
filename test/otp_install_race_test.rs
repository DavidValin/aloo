//! A manual `/contacts` key install racing an in-flight `/otp` negotiation
//! for the exact same contact name.
//!
//! `otp --add-contact` itself refuses once either side has actually
//! installed something under a name, so this can never corrupt a pad in
//! place. But letting a manual install win a race against a negotiation
//! that is already past that point turns the negotiated side's own
//! eventual install into a permanent, unexplained failure - or, for the
//! streamed-pad path (`client::otp::on_pad_commit`'s retry-safety), an
//! endless retry against a conflict that can never resolve itself, since
//! nothing ever removes the manually-installed contact on its own.
//! `handle_install_otp_key` now refuses the manual install outright,
//! before either of those states is ever reached, the same way a second
//! `/otp` is refused while one is already in flight.
//!
//! @requirement AC-379

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::{PendingOtpGenerate, UiState};
use aloo::crypto::otp::OtpPurpose;
use aloo::proto::{KeyMode, UserId};

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
        "aloo-otp-install-race-{label}-{}-{}",
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

/// A session pinned to `nickname`/`device_id`, with the real pq bundle
/// `otp_contact_name_for` needs to derive the exact same contact name
/// `handle_install_otp_key`'s new guard checks against.
async fn session_with_pinned_device(
    label: &str,
    otp: OtpCliConfig,
    nickname: &str,
    device_id: &str,
) -> (SessionState, Vec<u8>) {
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
    (session, peer_der)
}

fn contact_name_for(session: &SessionState, device_id: &str) -> String {
    let own_identity = aloo::client::contacts::own_identity_of(session);
    aloo::client::contacts::otp_contact_name_for(
        session.id_store_ref(),
        "alice",
        device_id,
        own_identity,
        OtpPurpose::Live,
    )
    .expect("contact name should be derivable for a pinned pq_hybrid device")
}

/// @requirement AC-379
#[tokio::test]
async fn a_manual_install_is_refused_while_our_own_proposal_is_awaiting_consent() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, peer_der) =
        session_with_pinned_device("session", cfg.clone(), "alice", "laptop").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    let contact_name = contact_name_for(&session, "laptop");

    // This side already proposed a fresh pad to this exact contact and is
    // waiting on the peer's answer (`confirm_generate`'s own insert).
    session.stage_awaiting_otp_consent_for_test(
        contact_name.clone(),
        PendingOtpGenerate {
            peer: PEER,
            peer_name: "alice".to_string(),
            pubkey_der: peer_der,
            purpose: OtpPurpose::Live,
        },
        1,
    );

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

    assert!(
        !otp_cli::has_contact(&cfg, &contact_name).await.unwrap(),
        "the manual install must not have touched the keychain while a proposal is outstanding"
    );
    assert!(
        session.has_awaiting_otp_consent_for_test(&contact_name),
        "the in-flight proposal itself must be untouched by the refused install"
    );
}

/// @requirement AC-379
#[tokio::test]
async fn a_manual_install_is_refused_while_the_peers_invite_is_open() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, _peer_der) =
        session_with_pinned_device("session", cfg.clone(), "alice", "laptop").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    let contact_name = contact_name_for(&session, "laptop");

    // The peer proposed a fresh pad to us, and it is sitting unanswered as
    // an open invite popup (`on_session_request`'s `push_otp_invite`).
    ui.push_otp_invite(PEER, "alice".to_string(), contact_name.clone(), None, None, Some(1));
    assert!(ui.otp_invite_open().is_some());

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

    assert!(
        !otp_cli::has_contact(&cfg, &contact_name).await.unwrap(),
        "the manual install must not have touched the keychain while the peer's invite is open"
    );
    assert!(
        ui.otp_invite_open().is_some(),
        "the open invite itself must be untouched by the refused install"
    );
}

/// The guard must never block an install for an unrelated contact - only
/// an exact contact-name match is refused.
///
/// @requirement AC-379
#[tokio::test]
async fn a_manual_install_for_a_different_contact_is_unaffected() {
    if !require_otp() {
        return;
    }
    let cfg = OtpCliConfig { binary_path: "otp".into(), working_dir: scratch("otp-cfg") };
    let (mut session, peer_der) =
        session_with_pinned_device("session", cfg.clone(), "alice", "laptop").await;
    let mut ui = UiState::new("me".into());
    ui.open_contacts();
    let contact_name = contact_name_for(&session, "laptop");

    // An in-flight proposal for a *different* contact name must not block
    // this one.
    session.stage_awaiting_otp_consent_for_test(
        "some-other-contact".to_string(),
        PendingOtpGenerate {
            peer: PEER,
            peer_name: "carol".to_string(),
            pubkey_der: peer_der,
            purpose: OtpPurpose::Live,
        },
        1,
    );

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

    assert!(
        otp_cli::has_contact(&cfg, &contact_name).await.unwrap(),
        "an unrelated in-flight proposal must never block installing this contact"
    );
}
