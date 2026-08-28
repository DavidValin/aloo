//! A key running fully dry, in both directions at once (AC-385): before
//! this, an exhausted contact just sat in the keychain unusable forever,
//! with nothing telling the user it had happened, and (for a live
//! session) with the far side possibly still believing the session was
//! alive. This does *not* delete anything - not the keychain entry, not
//! aloo's own per-contact bookkeeping - only a user's own explicit
//! `/contacts` delete, or a later `/otp`/`/new-otp-mail-key` replacing it
//! (AC-384's `commit_pending_setup`/`on_pad_commit`, which already remove
//! whatever is there before installing a fresh pad, exhausted or not),
//! ever touches the key material itself. What this closes is visibility
//! and convergence: a live session whose key just ran out ends locally
//! immediately (the pad can protect nothing further either way) and tries
//! to tell the peer directly too, so both sides converge on ended rather
//! than the peer being left to believe the session still works; a mail
//! key has no session to end, only the key, so its notice says only that
//! the key is gone.
//!
//! These tests drive the exhaustion-check functions directly
//! (`client::otp::is_contact_exhausted`/`end_live_session_if_exhausted`,
//! `client::otp_mail::notify_if_mail_key_exhausted`) against a real
//! installed contact, with a synthetic `ContactDetail` standing in for
//! "just spent the last byte" for the live tests - proving the mechanics
//! deterministically, without needing to engineer a real message whose
//! exact encrypted size happens to land on precisely zero bytes remaining
//! (impractical: a live send's `pq_hybrid` envelope and a mail's signed,
//! sealed payload are both several KB of essentially fixed-but-unstable
//! overhead). The mail test genuinely drains a real pad in both
//! directions instead, since its wrapper reads live status itself rather
//! than taking a `ContactDetail` parameter.
//!
//! @requirement AC-385

use aloo::client::connect::ResolvedIdentity;
use aloo::client::otp_cli::{self, ContactDetail, OtpCliConfig};
use aloo::client::session::{SessionState, TestSessionSpec};
use aloo::client::tui::ui::UiState;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{Content, KeyMode, UserId, UserInfo};

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
        "aloo-otp-key-exhaustion-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn session_with_real_otp(label: &str) -> SessionState {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("pq keygen");
    let public_der = aloo::proto::encode(&public).expect("pq der");
    SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity { private, public_der },
        scratch: scratch(label),
        otp: Some(OtpCliConfig {
            binary_path: OtpCliConfig::resolve().binary_path,
            working_dir: scratch(&format!("{label}-otp")),
        }),
    })
    .await
}

/// Registers `peer` in `known_users` with a real, decodable pq bundle - the
/// bare minimum `try_notify_peer_session_ended` needs to name a peer at
/// all - but does *not* bootstrap `pq_peer_keys` for them, so building the
/// outgoing sealed envelope fails and the notice cannot be sent: standing
/// in for a peer this side cannot currently reach.
fn known_unreachable_peer(ui: &mut UiState, peer: UserId, name: &str) -> Vec<u8> {
    let (public, _private) = aloo::crypto::pq::generate_bundle_with_bits(1024).expect("peer pq keygen");
    let der = aloo::proto::encode(&public).expect("peer pq der");
    ui.known_users.insert(
        peer,
        UserInfo {
            id: peer,
            name: name.to_string(),
            public_key_der: der.clone(),
            key_mode: KeyMode::PqHybrid,
        },
    );
    der
}

/// The same, but also bootstraps `pq_peer_keys` so an outgoing sealed
/// envelope to this peer can actually be built - standing in for a peer
/// this side *can* currently reach.
fn known_reachable_peer(session: &mut SessionState, ui: &mut UiState, peer: UserId, name: &str) {
    let der = known_unreachable_peer(ui, peer, name);
    let bundle = aloo::proto::decode::<aloo::crypto::pq::PqPublicBundle>(&der).expect("bundle decodes");
    let fingerprint = aloo::crypto::pq::bundle_fingerprint(&bundle).expect("peer fingerprint");
    session
        .pq_peer_keys_mut()
        .bootstrap(peer, bundle.bootstrap_encap().clone(), fingerprint);
}

/// Every contact needs genuinely independent key material - `otp` itself
/// refuses to add-contact a file that holds the same bytes as an existing
/// contact's key (a real safety check against a broken, reused pad), so
/// this draws fresh randomness per call rather than a fixed byte pattern.
async fn install_contact(cfg: &OtpCliConfig, contact_name: &str, key_bytes: usize) {
    let dir = cfg.working_dir.join(format!("staging-{contact_name}"));
    std::fs::create_dir_all(&dir).unwrap();
    let enc = dir.join("enc.key");
    let dec = dir.join("dec.key");
    std::fs::write(&enc, aloo::crypto::random_bytes(key_bytes)).unwrap();
    std::fs::write(&dec, aloo::crypto::random_bytes(key_bytes)).unwrap();
    otp_cli::add_contact(cfg, contact_name, &enc, &dec)
        .await
        .expect("installing the contact should succeed");
}

fn exhausted() -> ContactDetail {
    ContactDetail {
        enc_key_remaining: 0,
        dec_key_remaining: 0,
        ..Default::default()
    }
}

fn not_exhausted() -> ContactDetail {
    ContactDetail {
        enc_key_remaining: 4096,
        dec_key_remaining: 4096,
        ..Default::default()
    }
}

#[test]
fn is_contact_exhausted_requires_both_directions_at_zero() {
    assert!(aloo::client::otp::is_contact_exhausted(&exhausted()));
    assert!(!aloo::client::otp::is_contact_exhausted(&not_exhausted()));
    assert!(!aloo::client::otp::is_contact_exhausted(&ContactDetail {
        enc_key_remaining: 0,
        dec_key_remaining: 4096,
        ..Default::default()
    }));
    assert!(!aloo::client::otp::is_contact_exhausted(&ContactDetail {
        enc_key_remaining: 4096,
        dec_key_remaining: 0,
        ..Default::default()
    }));
}

/// The key thing this whole feature does *not* do: an exhausted, active
/// live session ends locally and tries to tell the peer - but the
/// keychain entry and aloo's own bookkeeping for it are left exactly as
/// they were. Reachable peer: the session ends on both sides (a real
/// sealed `OtpEndSession` genuinely goes out), and the notice says so.
///
/// @requirement AC-385
#[tokio::test]
async fn an_exhausted_active_session_ends_on_both_sides_when_the_peer_is_reachable() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_real_otp("live-exhausted-reachable").await;
    let mut ui = UiState::new("me".into());
    known_reachable_peer(&mut session, &mut ui, PEER, "bob");
    let cfg = session.otp_cli_cfg_for_test();
    install_contact(&cfg, "alice-bob", 4096).await;
    session.otp_store_mut().mark_provisioned("alice-bob");
    ui.mark_otp_active(PEER);
    // A real link to `PEER` always exists by the time this runs in
    // production - it is only ever reached from a genuine send/receive
    // over one. Registered here so the "told the peer" assertion below
    // proves the notify path actually queued something, rather than
    // trivially passing because nothing had anywhere to queue to yet
    // (`PeerLinkManager::send_reliable_or_queue` silently drops with no
    // link entry at all for the peer).
    session
        .peer_link_mut()
        .ensure_link(&mut aloo::control::NullSink, PEER)
        .await;

    aloo::client::otp::end_live_session_if_exhausted(
        &mut session,
        &mut ui,
        PEER,
        &exhausted(),
        "alice-bob",
    )
    .await;

    assert!(
        !ui.is_otp_active(PEER),
        "an exhausted key can protect nothing further - the session must end locally"
    );
    assert!(
        otp_cli::has_contact(&cfg, "alice-bob").await.unwrap(),
        "the keychain entry must NOT be removed - only the session ends, not the key"
    );
    assert!(
        session.otp_store_mut().get("alice-bob").is_some(),
        "aloo's own bookkeeping for the contact must survive too"
    );

    let told_peer = session
        
        .sent_or_queued_payloads(PEER)
        .into_iter()
        .any(|p| matches!(p, P2pPayload::Envelope { envelope, .. } if envelope.content == Content::OtpEndSession));
    assert!(told_peer, "a real end-of-session notice must genuinely be sent to the peer");

    let (message, success) = ui
        .status_notice
        .clone()
        .expect("the user must be told the key ran out");
    assert!(!success);
    assert!(
        message.contains("fully used up")
            && message.contains("session has ended")
            && message.contains("bob was told"),
        "must say the key is exhausted, the session ended, and that bob was told: {message:?}"
    );
}

/// Same trigger, but the peer cannot currently be reached (no bootstrapped
/// `pq_peer_keys` - standing in for a `Direct`-framed pair, or any peer
/// this side has no live channel to right now): this side still ends its
/// own session and says so honestly, without claiming to have told anyone.
///
/// @requirement AC-385
#[tokio::test]
async fn an_exhausted_active_session_ends_locally_even_when_the_peer_cannot_be_reached() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_real_otp("live-exhausted-unreachable").await;
    let mut ui = UiState::new("me".into());
    known_unreachable_peer(&mut ui, PEER, "bob");
    let cfg = session.otp_cli_cfg_for_test();
    install_contact(&cfg, "alice-bob", 4096).await;
    session.otp_store_mut().mark_provisioned("alice-bob");
    ui.mark_otp_active(PEER);

    aloo::client::otp::end_live_session_if_exhausted(
        &mut session,
        &mut ui,
        PEER,
        &exhausted(),
        "alice-bob",
    )
    .await;

    assert!(!ui.is_otp_active(PEER), "this side's own session still ends");
    assert!(
        otp_cli::has_contact(&cfg, "alice-bob").await.unwrap(),
        "the keychain entry must still not be removed"
    );
    let (message, _) = ui
        .status_notice
        .clone()
        .expect("the user must still be told the key ran out");
    assert!(
        message.contains("fully used up") && message.contains("could not be reached to tell"),
        "must not claim bob was told when he could not be reached: {message:?}"
    );
}

/// No session was active in the first place (a mail-purpose contact would
/// never reach this function at all, but a live one already paused by
/// `/endotp` could still see its key run out later): nothing happens -
/// no notice, no attempted peer notification, nothing touched.
///
/// @requirement AC-385
#[tokio::test]
async fn an_exhausted_contact_with_no_active_session_is_left_alone() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_real_otp("live-exhausted-inactive").await;
    let mut ui = UiState::new("me".into());
    known_reachable_peer(&mut session, &mut ui, PEER, "bob");
    let cfg = session.otp_cli_cfg_for_test();
    install_contact(&cfg, "alice-bob", 4096).await;
    session.otp_store_mut().mark_provisioned("alice-bob");
    // Deliberately not marked active.

    aloo::client::otp::end_live_session_if_exhausted(
        &mut session,
        &mut ui,
        PEER,
        &exhausted(),
        "alice-bob",
    )
    .await;

    assert!(otp_cli::has_contact(&cfg, "alice-bob").await.unwrap());
    assert!(
        ui.status_notice.is_none(),
        "nothing was active, so nothing should be announced or sent"
    );
    let attempted_notice = session
        
        .sent_or_queued_payloads(PEER)
        .into_iter()
        .any(|p| matches!(p, P2pPayload::Envelope { envelope, .. } if envelope.content == Content::OtpEndSession));
    assert!(!attempted_notice, "no session was ending, so nothing should be sent to the peer");
}

/// Not actually exhausted: no notice, no peer contact, session (if active)
/// stays active, nothing touched.
///
/// @requirement AC-385
#[tokio::test]
async fn a_live_contact_that_still_has_key_is_never_touched() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_real_otp("live-not-exhausted").await;
    let mut ui = UiState::new("me".into());
    known_reachable_peer(&mut session, &mut ui, PEER, "bob");
    let cfg = session.otp_cli_cfg_for_test();
    install_contact(&cfg, "alice-bob", 4096).await;
    session.otp_store_mut().mark_provisioned("alice-bob");
    ui.mark_otp_active(PEER);

    aloo::client::otp::end_live_session_if_exhausted(
        &mut session,
        &mut ui,
        PEER,
        &not_exhausted(),
        "alice-bob",
    )
    .await;

    assert!(otp_cli::has_contact(&cfg, "alice-bob").await.unwrap());
    assert!(ui.is_otp_active(PEER), "a live key with plenty left must stay active");
    assert!(ui.status_notice.is_none(), "nothing happened, so nothing should be announced");
}

async fn enc_remaining(cfg: &OtpCliConfig, contact: &str) -> u64 {
    otp_cli::show_contact(cfg, contact)
        .await
        .expect("show-contact should not fail")
        .expect("contact should exist")
        .enc_key_remaining
}

async fn dec_remaining(cfg: &OtpCliConfig, contact: &str) -> u64 {
    otp_cli::show_contact(cfg, contact)
        .await
        .expect("show-contact should not fail")
        .expect("contact should exist")
        .dec_key_remaining
}

/// Spends `contact`'s encryption key down to exactly zero remaining. The
/// tool's fixed per-message metadata overhead is *measured* from a first
/// one-byte encrypt rather than assumed, so the final, exactly-sized spend
/// that empties it works across otp-toolkit versions without hardcoding a
/// magic number.
async fn drain_enc_to_zero(cfg: &OtpCliConfig, contact: &str) -> u64 {
    let before = enc_remaining(cfg, contact).await;
    otp_cli::encrypt_retrying(cfg, contact, b"x", true)
        .await
        .expect("encrypt should not error");
    let after_one = enc_remaining(cfg, contact).await;
    let overhead = before - after_one - 1;
    if after_one > 0 {
        assert!(after_one > overhead, "not enough left to measure a final, exact spend");
        let filler = vec![b'y'; (after_one - overhead) as usize];
        otp_cli::encrypt_retrying(cfg, contact, &filler, true)
            .await
            .expect("the final calibrated encrypt should not error");
    }
    assert_eq!(enc_remaining(cfg, contact).await, 0, "calibration must land exactly on zero");
    overhead
}

/// `target`'s decryption key is mirrored by `mirror`'s encryption key (both
/// installed from the same generated pair) - so encrypting through
/// `mirror` and decrypting the result through `target` is exactly what a
/// real two-party exchange would do, on one keychain. Ciphertext length
/// equals key bytes consumed on *both* sides of an OTP spend, so the same
/// `overhead` already measured for the encrypt side (`drain_enc_to_zero`)
/// applies here too - one single calibrated spend lands exactly on zero,
/// no need to re-measure or loop in small increments (which would spawn a
/// subprocess per byte for a megabyte-sized pad).
async fn drain_dec_to_zero(cfg: &OtpCliConfig, target: &str, mirror: &str, overhead: u64) {
    let left = dec_remaining(cfg, target).await;
    assert!(left > overhead, "not enough left to land exactly on zero in one spend");
    let plaintext = vec![b'z'; (left - overhead) as usize];
    let ct = match otp_cli::encrypt_retrying(cfg, mirror, &plaintext, true)
        .await
        .expect("mirror encrypt should not error")
    {
        otp_cli::OtpCliOutcome::Ok(bytes) => bytes,
        other => panic!("mirror encrypt should succeed: {other:?}"),
    };
    otp_cli::decrypt_retrying(cfg, target, &ct, true)
        .await
        .expect("decrypt should not error");
    assert_eq!(dec_remaining(cfg, target).await, 0, "calibration must land exactly on zero");
}

/// The mail-side wrapper: an exhausted mail key is announced, with wording
/// distinct from the live-session one (no "session" to end) - and, like
/// the live side, the keychain entry is left exactly as it is. Genuinely
/// drains both directions through the real tool (rather than a synthetic
/// `ContactDetail`), since `notify_if_mail_key_exhausted` reads live status
/// itself - proving the whole path, not just the shared core.
///
/// @requirement AC-385
#[tokio::test]
async fn an_exhausted_mail_key_is_announced_but_not_removed() {
    if !require_otp() {
        return;
    }
    let mut session = session_with_real_otp("mail-exhausted").await;
    let mut ui = UiState::new("me".into());
    let cfg = session.otp_cli_cfg_for_test();

    otp_cli::new_key_pair(&cfg, 1, "target_side", "mirror_side")
        .await
        .expect("key generation should succeed");
    let target_dir = cfg.working_dir.join("target_side_keys");
    let mirror_dir = cfg.working_dir.join("mirror_side_keys");
    otp_cli::add_contact(
        &cfg,
        "alice-bob-mail",
        &target_dir.join("encryption_for_mirror_side.key"),
        &target_dir.join("decryption_from_mirror_side.key"),
    )
    .await
    .expect("installing the target contact should succeed");
    otp_cli::add_contact(
        &cfg,
        "mirror",
        &mirror_dir.join("encryption_for_target_side.key"),
        &mirror_dir.join("decryption_from_target_side.key"),
    )
    .await
    .expect("installing the mirror contact should succeed");
    session.otp_store_mut().mark_provisioned("alice-bob-mail");

    let overhead = drain_enc_to_zero(&cfg, "alice-bob-mail").await;
    drain_dec_to_zero(&cfg, "alice-bob-mail", "mirror", overhead).await;

    aloo::client::otp_mail::notify_if_mail_key_exhausted(
        &session,
        &mut ui,
        "bob",
        "alice-bob-mail",
    )
    .await;

    assert!(
        otp_cli::has_contact(&cfg, "alice-bob-mail").await.unwrap(),
        "the mail contact must NOT be removed - only announced"
    );
    let (message, success) = ui
        .status_notice
        .clone()
        .expect("the user must be told the mail key ran out");
    assert!(!success);
    assert!(
        message.contains("fully used up") && !message.contains("session"),
        "mail has no session to end, only a key: {message:?}"
    );
}

/// A mail key with plenty left produces no notice at all.
///
/// @requirement AC-385
#[tokio::test]
async fn a_mail_key_that_still_has_key_produces_no_notice() {
    if !require_otp() {
        return;
    }
    let session = session_with_real_otp("mail-not-exhausted").await;
    let mut ui = UiState::new("me".into());
    let cfg = session.otp_cli_cfg_for_test();
    install_contact(&cfg, "alice-bob-mail", 4096).await;

    aloo::client::otp_mail::notify_if_mail_key_exhausted(
        &session,
        &mut ui,
        "bob",
        "alice-bob-mail",
    )
    .await;

    assert!(otp_cli::has_contact(&cfg, "alice-bob-mail").await.unwrap());
    assert!(ui.status_notice.is_none());
}

/// Multiple contacts, multiple purposes: exhausting one live session's key
/// must never touch a second, unrelated live contact, nor the same peer's
/// separate mail key - each is keyed by its own distinct contact_name.
///
/// @requirement AC-385
#[tokio::test]
async fn exhausting_one_contact_never_touches_a_different_one() {
    if !require_otp() {
        return;
    }
    const CAROL_PEER: UserId = UserId(3);
    let mut session = session_with_real_otp("multi-contact-isolation").await;
    let mut ui = UiState::new("me".into());
    known_reachable_peer(&mut session, &mut ui, PEER, "bob");
    known_reachable_peer(&mut session, &mut ui, CAROL_PEER, "carol");
    let cfg = session.otp_cli_cfg_for_test();

    // Three independent contacts: bob's live session, bob's mail key, and
    // carol's live session - all distinct names, all currently healthy.
    install_contact(&cfg, "alice-bob-live", 4096).await;
    install_contact(&cfg, "alice-bob-mail", 4096).await;
    install_contact(&cfg, "alice-carol-live", 4096).await;
    session.otp_store_mut().mark_provisioned("alice-bob-live");
    session.otp_store_mut().mark_provisioned("alice-bob-mail");
    session.otp_store_mut().mark_provisioned("alice-carol-live");
    ui.mark_otp_active(PEER);
    ui.mark_otp_active(CAROL_PEER);

    // Only bob's live contact is exhausted.
    aloo::client::otp::end_live_session_if_exhausted(
        &mut session,
        &mut ui,
        PEER,
        &exhausted(),
        "alice-bob-live",
    )
    .await;

    assert!(!ui.is_otp_active(PEER), "bob's live session ended");
    assert!(
        otp_cli::has_contact(&cfg, "alice-bob-live").await.unwrap(),
        "even bob's own exhausted key is never removed automatically"
    );
    assert!(
        otp_cli::has_contact(&cfg, "alice-bob-mail").await.unwrap(),
        "bob's separate mail key must be untouched by his live key's exhaustion"
    );
    assert!(
        otp_cli::has_contact(&cfg, "alice-carol-live").await.unwrap(),
        "carol's entirely different contact must be untouched"
    );
    assert!(
        ui.is_otp_active(CAROL_PEER),
        "carol's own live session must stay active - only bob's ended"
    );
}
