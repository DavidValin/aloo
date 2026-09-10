//! A serverless pair - two clients that know each other only through
//! pinned `pq_hybrid` keys and a `direct_punch_to` line, no server between
//! them (`docs/PROTOCOL.md` §7.1.5) - must be able to name a pad contact
//! for each other once their link is up. A `PqWrapped` contact name is
//! device-qualified, and the device id travels in a `DeviceIdAnnounce`
//! that each side sends the other over the link itself: nothing else can
//! carry it without a server. Until it lands, `/otp` has nothing to name
//! the pad by and refuses.

use aloo::client::idstore::Trust;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::p2p::{LinkStatus, P2pEvent, direct_peer_id};
use aloo::client::session::{SessionState, TestSessionSpec, drain_p2p_events};
use aloo::client::tui::ui::UiState;
use aloo::control::NullSink;
use aloo::p2p_proto::P2pPayload;
use aloo::proto::{KeyMode, UserId};
use aloo::settings::{DirectPunchTarget, DirectPunchVia, PunchFrequency};

const KEY_BITS: usize = 1024;

fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("aloo-serverless-otp-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn require_otp() -> bool {
    let probe = OtpCliConfig {
        binary_path: std::path::PathBuf::from("otp"),
        working_dir: std::env::temp_dir(),
    };
    if otp_cli::binary_available(&probe) {
        return true;
    }
    eprintln!("skipping: the `otp` binary is not installed");
    false
}

struct Side {
    session: SessionState,
    ui: UiState,
    /// This side's own id, as the peer names it (`direct_peer_id` of the
    /// nickname - the one id a serverless pair has for each other).
    me: UserId,
    them: UserId,
    them_der: Vec<u8>,
    delivered: usize,
}

/// One client started with `--no-server`, holding a pin for the other and
/// a `direct_punch_to` line naming them, with the link already punched.
async fn side(label: &str, own_name: &str, them_name: &str, them_der: Vec<u8>) -> Side {
    let (public, private) = aloo::crypto::pq::generate_bundle_with_bits(KEY_BITS).expect("keygen");
    let identity = aloo::client::connect::ResolvedIdentity {
        private,
        public_der: aloo::proto::encode(&public).unwrap(),
    };
    let root = scratch(&format!("{label}-{own_name}"));
    let otp = OtpCliConfig {
        binary_path: OtpCliConfig::resolve().binary_path,
        working_dir: root.join("otp"),
    };
    std::fs::create_dir_all(&otp.working_dir).unwrap();
    let mut session = SessionState::for_test(TestSessionSpec {
        identity,
        scratch: root,
        otp: Some(otp),
    })
    .await;
    let me = direct_peer_id(own_name, None);
    let them = direct_peer_id(them_name, None);
    // What a serverless client knows about its peer: a pinned keybundle...
    session.id_store_mut().pin_new_device_with_key_mode(
        them_name,
        "",
        &them_der,
        Trust::Tofu,
        Some(KeyMode::PqHybrid),
    );
    // ...and a `direct_punch_to` line naming them.
    session.peer_link_mut().configure_direct_punch(
        own_name.to_string(),
        vec![DirectPunchTarget {
            nickname: them_name.to_string(),
            device_id: None,
            via: DirectPunchVia::Host {
                host: "127.0.0.1".to_string(),
                port: 1,
            },
            frequency: PunchFrequency::parse("every_5m").unwrap(),
        }],
        0,
    );
    session.peer_link_mut().record_sent_payloads_for_test();
    session.peer_link_mut().mark_active_for_test(them);
    let mut ui = UiState::new(own_name.into());
    ui.set_own_id(me);
    Side {
        session,
        ui,
        me,
        them,
        them_der,
        delivered: 0,
    }
}

/// The punch just succeeded: what the session does at link-up.
async fn link_up(side: &mut Side) {
    let them = side.them;
    side.session.inject_p2p_event(P2pEvent::LinkStatusChanged {
        peer: them,
        status: LinkStatus::Active,
    });
    drain_p2p_events(&mut NullSink, &mut side.ui, &mut side.session)
        .await
        .expect("link-up is handled");
}

/// Carries what `from` has sent since the last call into `to`, the way
/// the link would.
async fn deliver(from: &mut Side, to: &mut Side) -> usize {
    deliver_ordered(from, to, |fresh| fresh).await
}

/// `deliver`, with the batch reordered by `order` first - for a test
/// about what happens when the link delivers things in a different order
/// than they were queued.
async fn deliver_ordered(
    from: &mut Side,
    to: &mut Side,
    order: impl FnOnce(Vec<P2pPayload>) -> Vec<P2pPayload>,
) -> usize {
    let all = from.session.peer_link_mut().sent_payloads_for_test(from.them);
    let fresh: Vec<P2pPayload> = all.into_iter().skip(from.delivered).collect();
    from.delivered += fresh.len();
    let sender = from.me;
    let carried = fresh.len();
    for payload in order(fresh) {
        let event = match payload {
            P2pPayload::ChannelPresence { envelope } => P2pEvent::ChannelPresence { from: sender, envelope },
            P2pPayload::DeviceIdAnnounce { envelope } => P2pEvent::DeviceIdAnnounce { from: sender, envelope },
            _ => continue,
        };
        to.session.inject_p2p_event(event);
        drain_p2p_events(&mut NullSink, &mut to.ui, &mut to.session)
            .await
            .expect("delivery is handled");
    }
    carried
}

/// Runs `/otp` on `side` towards its peer and reports what the user saw.
async fn slash_otp(side: &mut Side) -> Option<(String, bool)> {
    let them = side.them;
    let der = side.them_der.clone();
    side.ui.status_notice = None;
    aloo::client::otp::handle_provisioning_command(
        &mut NullSink,
        &mut side.ui,
        &mut side.session,
        them,
        der,
        aloo::crypto::otp::OtpPurpose::Live,
    )
    .await
    .expect("/otp is handled");
    side.ui.status_notice.clone()
}

/// Two serverless clients pinning each other, the way two people who met
/// through a server once carry each other's key.
async fn pair(label: &str) -> (Side, Side) {
    let mut alice = side(label, "alice", "bob", vec![]).await;
    let mut bob = side(label, "bob", "alice", vec![]).await;
    let alice_der = alice.session.own_pinned_der_for_test().to_vec();
    let bob_der = bob.session.own_pinned_der_for_test().to_vec();
    alice.them_der = bob_der.clone();
    bob.them_der = alice_der.clone();
    alice.session.id_store_mut().pin_new_device_with_key_mode("bob", "", &bob_der, Trust::Tofu, Some(KeyMode::PqHybrid));
    bob.session.id_store_mut().pin_new_device_with_key_mode("alice", "", &alice_der, Trust::Tofu, Some(KeyMode::PqHybrid));
    (alice, bob)
}

fn assert_otp_names_the_contact(who: &str, side: &Side, notice: &Option<(String, bool)>) {
    assert!(
        !matches!(notice, Some((_, false))),
        "{who}'s /otp must not be refused: {notice:?}"
    );
    assert!(
        side.ui.otp_generate_confirm_open().is_some(),
        "{who}'s /otp goes on to propose a fresh pad"
    );
}

/// Once the pair's link is up and each side has introduced itself, `/otp`
/// on either side names the pad contact and goes on to propose a pad -
/// never "could not read this peer's identity".
/// @requirement AC-473
#[tokio::test]
async fn a_pinned_serverless_pair_can_name_a_pad_contact_and_start_otp() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob) = pair("pair").await;

    link_up(&mut alice).await;
    link_up(&mut bob).await;
    // The link carries both sides' introductions, and whatever those
    // introductions prompt in return.
    for _ in 0..3 {
        deliver(&mut alice, &mut bob).await;
        deliver(&mut bob, &mut alice).await;
    }
    assert!(alice.ui.known_users.contains_key(&alice.them), "bob's presence registered him with alice");
    assert!(bob.ui.known_users.contains_key(&bob.them), "alice's presence registered her with bob");

    for (side, who) in [(&mut alice, "alice"), (&mut bob, "bob")] {
        let notice = slash_otp(side).await;
        assert_otp_names_the_contact(who, side, &notice);
    }
}

/// The link queues a side's presence and its device-id announce back to
/// back; a receiver that sees the announce first must not drop it for
/// coming from someone it has not registered yet - their pinned key is
/// what it is checked against either way.
/// @requirement AC-473
#[tokio::test]
async fn an_announce_arriving_ahead_of_the_presence_still_names_the_contact() {
    if !require_otp() {
        return;
    }
    let (mut alice, mut bob) = pair("early-announce").await;
    link_up(&mut alice).await;
    link_up(&mut bob).await;
    // Alice's presence registers her with bob, which is what makes bob
    // queue his announce to her - after his own presence.
    deliver(&mut alice, &mut bob).await;
    // Bob's batch reaches alice announce-first.
    deliver_ordered(&mut bob, &mut alice, |mut batch| {
        batch.sort_by_key(|p| !matches!(p, P2pPayload::DeviceIdAnnounce { .. }));
        batch
    })
    .await;
    assert!(alice.ui.known_users.contains_key(&alice.them), "bob's presence registered him");

    let notice = slash_otp(&mut alice).await;
    assert_otp_names_the_contact("alice", &alice, &notice);
}
