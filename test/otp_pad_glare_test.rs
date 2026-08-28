//! Glare in the streamed-pad provisioning path: two people running `/otp`
//! with each other closely enough together that neither side's request
//! has arrived when the other sends its own.
//!
//! Before this, only the small-inline-key path (`on_key_setup_chunk`)
//! resolved this deterministically (`own_pad_wins_glare`) before any real
//! work happened. The streamed path - what any real, human-chosen pad
//! size actually uses - had no equivalent check anywhere: `on_pad_start`
//! never looked at `otp_outgoing_pads`, and neither did `accept_invite`.
//! Two people simultaneously running `/otp` for the first time (a
//! completely ordinary thing for two real people to do - "let's turn OTP
//! on now" in chat, both press Enter within a few seconds) could each
//! generate and stream their own pad to the other, and each independently
//! commit *the peer's* pad under the same contact name - leaving each
//! side's keychain holding a genuinely different set of bytes for what
//! both believe is the one shared contact. Every message either sent
//! afterward would fail to decrypt on the other side, permanently, with
//! no way out but `/endotp` and a fresh `/otp`.
//!
//! This is resolved as early as possible - at `on_session_request`,
//! before either side has generated or streamed a single byte - the same
//! way the small-key path already resolves it, and for the same reason:
//! cheaper to refuse a proposal than to discard gigabytes of already-sent
//! pad material.
//!
//! @requirement AC-378

use aloo::client::connect::ResolvedIdentity;
use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp::own_pad_wins_glare;
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::{PendingOtpGenerate, UiState};
use aloo::control::NullSink;
use aloo::crypto::otp::OtpPurpose;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{Content, Envelope, KeyMode, UserId, UserInfo};

const ALICE: UserId = UserId(1);
const BOB: UserId = UserId(2);

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
        "aloo-otp-pad-glare-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Side {
    session: SessionState,
    ui: UiState,
    own_info: UserInfo,
}

async fn fresh_side(label: &str, own_id: UserId, own_name: &str) -> Side {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    let session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private, public_der: public_der.clone() },
        scratch: scratch(label),
        otp: Some(OtpCliConfig {
            binary_path: OtpCliConfig::resolve().binary_path,
            working_dir: scratch(&format!("{label}-otp")),
        }),
    })
    .await;
    let mut ui = UiState::new(own_name.to_string());
    ui.own_id = Some(own_id);
    Side {
        session,
        ui,
        own_info: UserInfo {
            id: own_id,
            name: own_name.to_string(),
            public_key_der: public_der,
            key_mode: KeyMode::PqHybrid,
        },
    }
}

/// Pins each side to the other (a real, decodable `pq_hybrid` identity, so
/// this pair frames `PqWrapped` - the only framing a fresh pad needs the
/// consent round trip for at all), and records each other's device id -
/// both required before `contact_name_for` can even be computed
/// (device-pinning plan §4).
fn bootstrap_rotating_key(session: &mut SessionState, peer: UserId, peer_der: &[u8]) {
    let bundle = aloo::proto::decode::<aloo::crypto::pq::PqPublicBundle>(peer_der)
        .expect("test peer bundle decodes");
    let fingerprint = aloo::crypto::pq::bundle_fingerprint(&bundle).expect("test peer fingerprint");
    session.pq_peer_keys_mut().bootstrap(peer, bundle.bootstrap_encap().clone(), fingerprint);
}

fn cross_pin(alice: &mut Side, bob: &mut Side) {
    alice
        .session
        .id_store_mut()
        .pin_new_device("bob", "test-device", &bob.own_info.public_key_der, Trust::Verified);
    alice.session.set_peer_device_id_for_test(BOB, "test-device".to_string());
    alice.ui.known_users.insert(BOB, bob.own_info.clone());
    bootstrap_rotating_key(&mut alice.session, BOB, &bob.own_info.public_key_der);

    bob.session.id_store_mut().pin_new_device(
        "alice",
        "test-device",
        &alice.own_info.public_key_der,
        Trust::Verified,
    );
    bob.session.set_peer_device_id_for_test(ALICE, "test-device".to_string());
    bob.ui.known_users.insert(ALICE, alice.own_info.clone());
    bootstrap_rotating_key(&mut bob.session, ALICE, &alice.own_info.public_key_der);
}

/// Stages and confirms "generate a fresh 1MB pad for `peer`" on `side` -
/// everything a real `/otp` on a contact with no existing key does, up to
/// and including the request that goes out and the `otp_awaiting_consent`
/// record kept while waiting for an answer.
async fn propose_fresh_pad(side: &mut Side, peer: UserId, peer_der: Vec<u8>, peer_name: &str) {
    side.ui.open_otp_size_input(PendingOtpGenerate {
        peer,
        peer_name: peer_name.to_string(),
        pubkey_der: peer_der,
        purpose: OtpPurpose::Live,
    });
    aloo::client::otp::confirm_generate(&mut NullSink, &mut side.session, &mut side.ui, 1)
        .await
        .expect("proposing a fresh pad should not fail");
}

/// The one `OtpSessionRequest` envelope `propose_fresh_pad` queued for
/// `peer`, read (not drained) off the link exactly like
/// `otp_ack_wiring_test.rs`'s `take_envelope`.
fn take_session_request(side: &mut Side, peer: UserId) -> Envelope {
    side.session
        
        .sent_or_queued_payloads(peer)
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::Envelope { envelope, .. } if envelope.content == Content::OtpSessionRequest => {
                Some(envelope)
            }
            _ => None,
        })
        .expect("a fresh-pad proposal should have queued a session request")
}

fn fp_of(side: &Side) -> [u8; 32] {
    aloo::crypto::pq::fingerprint_of_encoded(&side.own_info.public_key_der).expect("test identity fingerprint")
}

fn contact_name_between(alice: &Side, bob: &Side) -> String {
    aloo::crypto::otp::contact_name_for(&fp_of(alice), "test-device", &fp_of(bob), "test-device")
}

/// @requirement AC-378
#[tokio::test]
async fn simultaneous_first_time_proposals_resolve_to_exactly_one_survivor() {
    if !require_otp() {
        return;
    }
    let mut alice = fresh_side("glare-alice", ALICE, "alice").await;
    let mut bob = fresh_side("glare-bob", BOB, "bob").await;
    cross_pin(&mut alice, &mut bob);
    let contact = contact_name_between(&alice, &bob);

    // Both users run `/otp` before either has heard from the other -
    // exactly what "let's both turn it on now" produces.
    propose_fresh_pad(&mut alice, BOB, bob.own_info.public_key_der.clone(), "bob").await;
    propose_fresh_pad(&mut bob, ALICE, alice.own_info.public_key_der.clone(), "alice").await;
    assert!(alice.session.has_awaiting_otp_consent_for_test(&contact));
    assert!(bob.session.has_awaiting_otp_consent_for_test(&contact));

    let alice_request = take_session_request(&mut alice, BOB);
    let bob_request = take_session_request(&mut bob, ALICE);

    // Alice's request arrives at Bob; Bob's arrives at Alice - the crossed
    // delivery a real network produces when neither side has seen the
    // other's yet.
    aloo::client::otp::on_session_request(
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        "alice".to_string(),
        &alice.own_info,
        alice_request,
    );
    aloo::client::otp::on_session_request(
        &mut alice.ui,
        &mut alice.session,
        BOB,
        "bob".to_string(),
        &bob.own_info,
        bob_request,
    );

    let alice_wins = own_pad_wins_glare(&fp_of(&alice), &fp_of(&bob));

    let (winner, loser) = if alice_wins { (&alice, &bob) } else { (&bob, &alice) };
    assert!(
        winner.session.has_awaiting_otp_consent_for_test(&contact),
        "the winning side's own proposal must still be waiting on the real answer"
    );
    assert!(
        !loser.session.has_awaiting_otp_consent_for_test(&contact),
        "the losing side's own proposal must be withdrawn, not left waiting forever"
    );
    assert!(
        loser.ui.otp_invite_open().is_some(),
        "the losing side sees the winner's proposal as an ordinary invite"
    );
    assert!(
        winner.ui.otp_invite_open().is_none(),
        "the winning side never sees the loser's proposal as a decision to make at all"
    );

    // The two computed independently, from each side's own perspective,
    // must agree on who won - the whole point of a fingerprint comparison
    // both sides can make without any round trip to negotiate it.
    let bob_wins_from_bobs_view = own_pad_wins_glare(&fp_of(&bob), &fp_of(&alice));
    assert_eq!(alice_wins, !bob_wins_from_bobs_view);
}

/// The loser's own `otp_awaiting_consent` entry is withdrawn immediately
/// at `on_session_request` (proven above), but the winner's refusal ack
/// still arrives later over the wire - `on_key_setup_ack`'s generic
/// rejection branch must not choke on an entry that is already gone.
///
/// @requirement AC-378
#[tokio::test]
async fn the_losers_refusal_ack_is_handled_cleanly_after_the_early_withdrawal() {
    if !require_otp() {
        return;
    }
    let mut alice = fresh_side("glare-ack-alice", ALICE, "alice").await;
    let mut bob = fresh_side("glare-ack-bob", BOB, "bob").await;
    cross_pin(&mut alice, &mut bob);
    let contact = contact_name_between(&alice, &bob);

    propose_fresh_pad(&mut alice, BOB, bob.own_info.public_key_der.clone(), "bob").await;
    propose_fresh_pad(&mut bob, ALICE, alice.own_info.public_key_der.clone(), "alice").await;
    let alice_request = take_session_request(&mut alice, BOB);
    let bob_request = take_session_request(&mut bob, ALICE);

    aloo::client::otp::on_session_request(
        &mut bob.ui,
        &mut bob.session,
        ALICE,
        "alice".to_string(),
        &alice.own_info,
        alice_request,
    );
    aloo::client::otp::on_session_request(
        &mut alice.ui,
        &mut alice.session,
        BOB,
        "bob".to_string(),
        &bob.own_info,
        bob_request,
    );

    let alice_wins = own_pad_wins_glare(&fp_of(&alice), &fp_of(&bob));
    let (winner, loser, loser_info) = if alice_wins {
        (&mut alice, &mut bob, BOB)
    } else {
        (&mut bob, &mut alice, ALICE)
    };

    // The winner's refusal of the loser's proposal is queued as an
    // encrypted `OtpKeySetupAck` the instant `on_session_request` resolved
    // the glare above - deliver it to the loser now, as the network
    // eventually would.
    let ack_envelope = winner
        .session
        
        .sent_or_queued_payloads(loser_info)
        .into_iter()
        .find_map(|p| match p {
            P2pPayload::Envelope { envelope, .. } if envelope.content == Content::OtpKeySetupAck => {
                Some(envelope)
            }
            _ => None,
        })
        .expect("the winner should have refused the loser's proposal");

    aloo::client::otp::on_key_setup_ack(&mut loser.ui, &mut loser.session, loser_info, &winner.own_info, ack_envelope)
        .await;

    assert!(
        !loser.session.has_awaiting_otp_consent_for_test(&contact),
        "still withdrawn - the late-arriving ack must not resurrect or double-remove anything"
    );
    let (message, success) = loser
        .ui
        .status_notice
        .clone()
        .expect("the refusal must still be shown");
    assert!(!success, "a refusal is not a success notice");
    assert!(
        message.contains("cancelled"),
        "the wording should read as an ordinary cancellation: {message:?}"
    );
}
