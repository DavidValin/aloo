//! What accepting an impersonation review (`session::accept_identity_review`,
//! the device-pinning plan's Accept flow) actually touches, and - just as
//! important - what it deliberately leaves alone:
//!
//! - channel/DM sends already encrypt to whichever key that connection's
//!   `UserId` actually announced, live, independent of the trust review;
//! - `/info`/`i` already shows that same live device, independent of it too;
//! - an `/otp` session tied to an *old* device is a completely disjoint
//!   piece of state (keyed by a device-qualified contact name, never by
//!   `id_store`'s pin) and Accept never touches it.
//!
//! Driven directly against `session::accept_identity_review` (extracted
//! from `UiAction::AcceptIdentity`'s handler for exactly this reason) since
//! the live two-daemon cucumber harness cannot model two distinct devices
//! for one nickname within a single test process (both ends would resolve
//! their own device_id from the one ambient `~/.aloo/d_id` path).

use aloo::client::connect::ResolvedIdentity;
use aloo::client::contacts::handle_request_user_info;
use aloo::client::idstore::Trust;
use aloo::client::session::{self, SessionState, TestSessionSpec};
use aloo::client::tui::contacts::ContactKeyKind;
use aloo::client::tui::ui::{IdentityCase, UiAction, UiState};
use aloo::crypto::otp::contact_name_for;
use aloo::crypto::pq::{PqPrivateBundle, fingerprint_of_encoded, generate_bundle_with_bits};
use aloo::proto::{self, ChannelInfo, ChannelKind, KeyMode, UserId, UserInfo};
use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

/// Small enough to keep the suite quick - key *size* is not what any of
/// these assert (see `test/cucumber/world.rs`'s `SCENARIO_KEY_BITS` for
/// the same trade and the same reasoning).
const TEST_KEY_BITS: usize = 1024;

const BOB: UserId = UserId(2);

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-identity-accept-effects-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Identity {
    private: PqPrivateBundle,
    der: Vec<u8>,
}

fn identity() -> Identity {
    let (public, private) = generate_bundle_with_bits(TEST_KEY_BITS).expect("keygen");
    let der = proto::encode(&public).expect("encode bundle");
    Identity { private, der }
}

/// Bob's *new* device is already live - its key already seeded into
/// `known_users`/`channel.members` exactly as `check_identity` +
/// `seed_member` would have left it the moment that connection joined
/// (`session.rs`'s `UserJoined` handler runs `check_identity` before
/// `seed_member` populates these, so by the time any review is even shown
/// the "new" key is already what live sends use). Bob's *old* device is
/// separately pinned in `id_store` under a different device_id/key - the
/// state right after `check_identity` opened a `StaticMismatch` review,
/// before Accept is pressed.
async fn fixture(name: &str) -> (SessionState, UiState, Identity, Identity, Identity) {
    let me = identity();
    let old = identity();
    let new = identity();

    let mut session = SessionState::for_test(TestSessionSpec {
        identity: ResolvedIdentity {
            private: me.private.clone(),
            public_der: me.der.clone(),
        },
        scratch: scratch_dir(name),
        otp: None,
    })
    .await;

    let mut ui = UiState::new("me".into());
    ui.set_own_id(UserId(1));
    ui.on_channel_list(vec![ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    }]);
    ui.on_joined(ChannelInfo {
        name: "general".into(),
        kind: ChannelKind::Public,
    });

    let bob_live = UserInfo {
        id: BOB,
        name: "bob".into(),
        public_key_der: new.der.clone(),
        key_mode: KeyMode::PqHybrid,
    };
    ui.seed_member("general", bob_live.clone());
    ui.known_users.insert(BOB, bob_live);

    session.id_store_mut().pin_new_device_with_key_mode(
        "bob",
        "old-device",
        &old.der,
        Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );
    session.set_peer_device_id_for_test(BOB, "new-device".to_string());

    ui.push_identity_review(
        BOB,
        "bob".into(),
        "their key changed".into(),
        IdentityCase::StaticMismatch {
            new_public_key_der: new.der.clone(),
            previous_public_key_der: old.der.clone(),
        },
    );

    (session, ui, me, old, new)
}

/// @requirement AC-332
#[tokio::test]
async fn post_accept_channel_and_dm_sends_use_the_new_devices_key() {
    let (mut session, mut ui, _me, old, new) = fixture("channel-key").await;

    assert!(ui.is_trust_gated(BOB), "gated before accept");

    session::accept_identity_review(&mut session, &mut ui, BOB).await;

    assert!(!ui.is_trust_gated(BOB), "un-gated after accept");

    // DM path: `known_users` already, and still, carries the live new key -
    // nothing needed to change for a DM send to use it.
    assert_eq!(
        ui.known_users.get(&BOB).unwrap().public_key_der,
        new.der,
        "DM encryption already uses the new device's key"
    );

    // Channel path, driven through the real send action (not the
    // `pub(crate)` recipient-resolution helper directly).
    for c in "hello".chars() {
        ui.handle_key(KeyCode::Char(c), KeyModifiers::NONE, KeyEventKind::Press);
    }
    match ui.handle_key(KeyCode::Enter, KeyModifiers::NONE, KeyEventKind::Press) {
        Some(UiAction::SendChannelText { recipients, .. }) => {
            assert!(
                recipients.iter().any(|(id, key)| *id == BOB && *key == new.der),
                "channel send must encrypt to bob's new device key: {recipients:?}"
            );
        }
        other => panic!("expected SendChannelText, got {other:?}"),
    }

    // Additive: both devices coexist in id_store afterward.
    assert_eq!(session.id_store_mut().devices_of("bob").count(), 2);
    assert_eq!(
        session.id_store_mut().get_for_device("bob", "old-device"),
        Some(old.der.as_slice())
    );
    assert_eq!(
        session.id_store_mut().get_for_device("bob", "new-device"),
        Some(new.der.as_slice())
    );
}

/// @requirement AC-333
#[tokio::test]
async fn post_accept_user_info_shows_the_new_device() {
    let (session, mut ui, _me, _old, new) = fixture("info-device").await;

    // Live-connection-derived (`session.peer_device_ids`), never gated by
    // review state at all - already true before Accept.
    ui.open_user_info(BOB, "bob".into());
    handle_request_user_info(&session, &mut ui, BOB, "bob".into()).await;
    assert_eq!(
        ui.user_info.as_ref().unwrap().device_id.as_deref(),
        Some("new-device"),
        "device_id is live-derived, unaffected by a pending review"
    );

    let mut session = session;
    session::accept_identity_review(&mut session, &mut ui, BOB).await;

    ui.open_user_info(BOB, "bob".into());
    handle_request_user_info(&session, &mut ui, BOB, "bob".into()).await;
    let info = ui.user_info.as_ref().unwrap();
    assert_eq!(info.device_id.as_deref(), Some("new-device"));
    let pqh_fp = info
        .keys
        .iter()
        .find(|k| k.kind == ContactKeyKind::Pqh)
        .expect("a pqh row for the now-pinned new device");
    assert_eq!(pqh_fp.id, aloo::crypto::short_fingerprint_der(&new.der));
}

/// @requirement AC-334, TB-254
#[tokio::test]
async fn an_active_otp_session_under_the_old_device_survives_accept_untouched() {
    let (mut session, mut ui, me, old, new) = fixture("otp-independence").await;

    let own_fp = fingerprint_of_encoded(&me.der).expect("fp");
    let own_device_id = session.own_device_id_for_test().to_string();
    let old_peer_fp = fingerprint_of_encoded(&old.der).expect("fp");
    let new_peer_fp = fingerprint_of_encoded(&new.der).expect("fp");
    let old_contact = contact_name_for(&own_fp, &own_device_id, &old_peer_fp, "old-device");
    let new_contact = contact_name_for(&own_fp, &own_device_id, &new_peer_fp, "new-device");

    // Stands in for "an /otp session was opened" with the old device.
    session.otp_store_mut().mark_provisioned(&old_contact);
    let before = session.otp_store_mut().get(&old_contact).cloned();
    assert!(before.is_some(), "seeded state must exist before accept");

    session::accept_identity_review(&mut session, &mut ui, BOB).await;

    let after = session.otp_store_mut().get(&old_contact).cloned();
    assert_eq!(
        before, after,
        "the old device's OTP session must be byte-for-byte unchanged by Accept"
    );
    assert!(
        session.otp_store_mut().get(&new_contact).is_none(),
        "Accept must not fabricate OTP state for the new device - a fresh /otp is still required, matching pq_hybrid (not OTP) taking over the dm"
    );
}
