//! `client::otp::on_pad_event`'s `Received` arm: whether a fully-arrived,
//! digest-verified pad needs a *second* decision from the user on top of
//! the one already given when the exchange was first proposed
//! (`accept_invite`'s "agreeing to a fresh pad" branch, `otp::on_session_
//! request`).
//!
//! The user-reported bug: the receiver accepts once, and is then asked to
//! accept *again* once the pad finishes arriving. Root cause - a pad this
//! size can take a long time, and any interruption between this side
//! sending `OtpPadVerify` and the sender's matching `OtpPadCommit` makes
//! the sender re-offer the *whole* pad from scratch
//! (docs/PROTOCOL.md's reconnect-resend note for the streamed pad
//! transport), landing back in `Received` a second time for the very same
//! already-accepted proposal. The old code consumed the recorded consent
//! (`SessionState::otp_consented`) on its first use, so that second,
//! ordinary-reconnect arrival found no consent left and fell through to
//! `push_otp_invite` - a second popup for a decision already made.
//!
//! Fixed by checking membership rather than consuming it, clearing it for
//! real only once the exchange actually installs (`on_pad_commit`) or is
//! cancelled. The popup itself is not removed outright: it is still the
//! only consent gate for a pad that arrives with no prior proposal at all
//! (`on_pad_start` stages and streams unconditionally, with no popup of
//! its own - see its doc) - the second test below proves that gate still
//! stands.
//!
//! @requirement AC-391

use aloo::client::connect::ResolvedIdentity;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_pad::PadEvent;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{KeyMode, UserId, UserInfo};

const PEER: UserId = UserId(2);
const CONTACT: &str = "test-contact-for-pad-reverify";

fn require_otp() -> bool {
    let probe = OtpCliConfig { binary_path: OtpCliConfig::resolve().binary_path, working_dir: std::env::temp_dir() };
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
        "aloo-otp-pad-reverify-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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

fn received_event_for(session: &SessionState, from: UserId) -> PadEvent {
    let (stream_id, enc_digest, dec_digest) = session
        .staged_incoming_pad_identity_for_test(from)
        .expect("a pad must be staged first");
    PadEvent::Received { from, stream_id, enc_digest, dec_digest }
}

/// The exchange was already accepted (the first popup) - a pad that then
/// finishes arriving, even more than once (an ordinary reconnect-triggered
/// resend), auto-verifies without ever showing a second popup.
/// @requirement AC-391
#[tokio::test]
async fn an_already_consented_pad_reverifies_silently_even_on_a_resend() {
    let mut session = session_with_no_otp_binary("consented").await;
    let mut ui = UiState::new("me".into());
    known_bob(&mut ui);
    session.peer_link_mut().ensure_link(&mut aloo::control::NullSink, PEER).await;

    session.stage_incoming_pad_for_test(PEER, CONTACT.to_string());
    session.stage_otp_consented_for_test(CONTACT.to_string());
    let event = received_event_for(&session, PEER);

    aloo::client::otp::on_pad_event(&mut aloo::control::NullSink, &mut session, &mut ui, event)
        .await
        .unwrap();

    assert!(
        !ui.has_otp_invite_from(PEER),
        "an already-accepted proposal must not show a second decision popup"
    );
    assert!(
        session.has_otp_consented_for_test(CONTACT),
        "consent must survive being used - it is not a single-use token"
    );
    let verifies = session
        .peer_link_mut()
        .pending_payloads(PEER)
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpPadVerify { accepted: true, .. }))
        .count();
    assert_eq!(verifies, 1, "the pad must still be verified automatically");

    // The sender's matching `OtpPadCommit` never arrived (link dropped),
    // so it re-offers the whole pad from scratch - `on_pad_start` would
    // re-stage it in production; here the same staged pad simply
    // completes `Received` a second time, which is the scenario this test
    // exists to prove no longer double-prompts.
    let event = received_event_for(&session, PEER);
    aloo::client::otp::on_pad_event(&mut aloo::control::NullSink, &mut session, &mut ui, event)
        .await
        .unwrap();
    assert!(
        !ui.has_otp_invite_from(PEER),
        "a resend of an already-accepted pad must not prompt again either"
    );
    let verifies = session
        .peer_link_mut()
        .pending_payloads(PEER)
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpPadVerify { accepted: true, .. }))
        .count();
    assert_eq!(verifies, 2, "each arrival still verifies, just without asking again");
}

/// A pad that arrives with *no* prior proposal at all (nothing ever
/// consented to) still shows exactly one decision popup - the fix above
/// must not turn into skipping consent altogether, only into not asking
/// twice for the same one.
/// @requirement AC-391
#[tokio::test]
async fn a_pad_with_no_prior_consent_still_shows_one_popup() {
    let mut session = session_with_no_otp_binary("unconsented").await;
    let mut ui = UiState::new("me".into());
    known_bob(&mut ui);
    session.peer_link_mut().ensure_link(&mut aloo::control::NullSink, PEER).await;

    session.stage_incoming_pad_for_test(PEER, CONTACT.to_string());
    let event = received_event_for(&session, PEER);

    aloo::client::otp::on_pad_event(&mut aloo::control::NullSink, &mut session, &mut ui, event)
        .await
        .unwrap();

    assert!(
        ui.has_otp_invite_from(PEER),
        "a pad nobody agreed to must still be a decision, not an automatic yes"
    );
    let verifies = session
        .peer_link_mut()
        .pending_payloads(PEER)
        .into_iter()
        .filter(|p| matches!(p, P2pPayload::OtpPadVerify { .. }))
        .count();
    assert_eq!(verifies, 0, "nothing is verified until the user actually decides");
}

/// A genuine install (`on_pad_commit`) clears the recorded consent - it
/// does not leak past the exchange it was for.
/// @requirement AC-391
#[tokio::test]
async fn a_successful_install_clears_the_recorded_consent() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_no_otp_binary("clears-on-install").await;
    session.set_otp_binary_path_for_test(OtpCliConfig::resolve().binary_path);
    let mut ui = UiState::new("me".into());
    known_bob(&mut ui);
    session.peer_link_mut().ensure_link(&mut aloo::control::NullSink, PEER).await;

    session.stage_incoming_pad_for_test(PEER, CONTACT.to_string());
    session.stage_otp_consented_for_test(CONTACT.to_string());
    assert!(session.has_otp_consented_for_test(CONTACT));

    aloo::client::otp::on_pad_commit(&mut session, &mut ui, PEER, CONTACT.to_string()).await;

    assert!(
        !session.has_otp_consented_for_test(CONTACT),
        "an installed pad has nothing left to re-verify, so its consent must not outlive it"
    );
}
