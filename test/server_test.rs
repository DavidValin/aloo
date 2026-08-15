use std::net::{IpAddr, Ipv4Addr};

use aloo::crypto::{self, KeyPair};
use aloo::proto::*;
use aloo::rekey;
use aloo::server::{
    AuthConfig, CHANNEL_MAX_PASSWORD_ATTEMPTS, CHANNEL_PASSWORD_BAN_DURATION, DEFAULT_CHANNEL_NAME,
    Outgoing, Registry, serve,
};
use tokio::net::{TcpListener, TcpStream};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const OTHER_TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

// ---------------------------------------------------------------------
// Registry: pure logic, no sockets
// ---------------------------------------------------------------------

/// @requirement TB-113
#[test]
fn join_channel_fails_for_an_unregistered_user() {
    let mut reg = Registry::new();
    let unknown = UserId(999_999); // never registered
    let err = reg
        .join_channel(unknown, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap_err();
    assert!(
        err.contains("unknown user"),
        "unexpected error message: {err}"
    );
}

/// @requirement AC-018
#[test]
fn fresh_registry_has_default_public_the_hall_channel() {
    let reg = Registry::new();
    let list = reg.channel_list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "the-hall");
    assert_eq!(list[0].kind, ChannelKind::Public);
}

/// @requirement TB-017
#[test]
fn register_stores_user_info() {
    let mut reg = Registry::new();
    let id = reg.register("dave".into(), vec![1, 2, 3], KeyMode::Rsa);
    let info = reg.user_info(id).expect("registered user");
    assert_eq!(info.name, "dave");
    assert_eq!(info.public_key_der, vec![1, 2, 3]);
}

/// @requirement TB-018
#[test]
fn name_taken_reflects_currently_registered_clients() {
    let mut reg = Registry::new();
    assert!(!reg.name_taken("dave"));
    reg.register("dave".into(), vec![], KeyMode::Rsa);
    assert!(reg.name_taken("dave"));
    assert!(
        !reg.name_taken("Dave"),
        "nickname matching is case-sensitive"
    );
}

/// @requirement AC-015, TB-019
#[test]
fn try_register_rejects_a_nickname_already_in_use() {
    let mut reg = Registry::new();
    let first = reg
        .try_register("dave".into(), vec![1], KeyMode::Rsa)
        .expect("first registration succeeds");
    let err = reg
        .try_register("dave".into(), vec![2], KeyMode::Rsa)
        .unwrap_err();
    assert!(err.contains("dave"));
    assert!(err.contains("taken"));

    // the rejected attempt must not have registered a second "dave"
    assert_eq!(reg.user_info(first).unwrap().public_key_der, vec![1]);
}

/// @requirement AC-016
#[test]
fn try_register_allows_the_name_again_once_the_holder_is_gone() {
    let mut reg = Registry::new();
    let first = reg
        .try_register("dave".into(), vec![1], KeyMode::Rsa)
        .unwrap();
    reg.unregister(first);
    let second = reg
        .try_register("dave".into(), vec![2], KeyMode::Rsa)
        .expect("name freed up after unregister");
    assert_eq!(reg.user_info(second).unwrap().public_key_der, vec![2]);
}

/// @requirement TB-022
#[test]
fn joining_new_channel_sends_confirmation_and_no_peer_events() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let out = reg
        .join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert_eq!(out.len(), 1);
    assert!(matches!(
        &out[0],
        Outgoing { to, message: ServerMessage::Joined { channel } }
            if *to == alice && channel.name == "general"
    ));
}

/// @requirement AC-019, TB-022
#[test]
fn second_joiner_gets_snapshot_and_first_gets_notified() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![9], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![8], KeyMode::Rsa);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    // bob should learn about alice, alice should learn about bob, then bob gets Joined.
    let bob_learns_alice = out.iter().any(|o| {
        matches!(&o.message, ServerMessage::UserJoined { channel, user }
            if *to_id(o) == bob && channel == "general" && user.id == alice)
    });
    let alice_learns_bob = out.iter().any(|o| {
        matches!(&o.message, ServerMessage::UserJoined { channel, user }
            if *to_id(o) == alice && channel == "general" && user.id == bob)
    });
    let bob_confirmed = out.iter().any(|o| {
        matches!(&o.message, ServerMessage::Joined { channel } if *to_id(o) == bob && channel.name == "general")
    });
    assert!(bob_learns_alice, "bob should receive alice's info: {out:?}");
    assert!(
        alice_learns_bob,
        "alice should be notified bob joined: {out:?}"
    );
    assert!(
        bob_confirmed,
        "bob should get a Joined confirmation: {out:?}"
    );

    fn to_id(o: &Outgoing) -> &UserId {
        &o.to
    }
}

/// @requirement TB-021
#[test]
fn rejoining_a_channel_is_a_noop() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let out = reg
        .join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(out.is_empty());
}

/// @requirement AC-022
#[test]
fn private_channel_is_created_on_join_but_not_listed() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    reg.join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    let list = reg.channel_list();
    assert!(list.iter().all(|c| c.name != "secret-room"));
}

/// @requirement AC-023
#[test]
fn leaving_notifies_remaining_members() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.leave_channel(alice, "general");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to, bob);
    assert!(
        matches!(&out[0].message, ServerMessage::UserLeft { channel, user_id }
        if channel == "general" && *user_id == alice)
    );
}

/// @requirement TB-023, AC-107
#[test]
fn empty_channel_is_deleted_unless_it_is_the_default_channel() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        DEFAULT_CHANNEL_NAME,
        ChannelKind::Public,
        None,
        TEST_IP,
    )
    .unwrap();
    reg.join_channel(
        alice,
        "another-public-room",
        ChannelKind::Public,
        None,
        TEST_IP,
    )
    .unwrap();
    reg.join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();

    reg.leave_channel(alice, DEFAULT_CHANNEL_NAME);
    reg.leave_channel(alice, "another-public-room");
    reg.leave_channel(alice, "secret-room");

    // The default channel survives being empty forever.
    assert!(
        reg.channel_list()
            .iter()
            .any(|c| c.name == DEFAULT_CHANNEL_NAME)
    );
    // Any other channel - public or private - is unregistered once empty:
    // re-joining either recreates it fresh, with no memory of prior
    // membership (just the Joined confirmation, no stale peers).
    let out = reg
        .join_channel(
            alice,
            "another-public-room",
            ChannelKind::Public,
            None,
            TEST_IP,
        )
        .unwrap();
    assert_eq!(out.len(), 1);
    let out = reg
        .join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    assert_eq!(out.len(), 1);
}

/// @requirement AC-108
#[test]
fn a_newly_created_public_channel_is_broadcast_to_other_connected_clients() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);

    let out = reg
        .join_channel(alice, "brand-new-room", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(
        out.iter().any(|o| o.to == bob
            && matches!(&o.message, ServerMessage::ChannelCreated { channel }
                if channel.name == "brand-new-room" && channel.kind == ChannelKind::Public)),
        "bob should learn about the new public channel without joining it: {out:?}"
    );
    // alice (the creator) already has her own `Joined` - no redundant
    // ChannelCreated addressed to herself.
    assert!(
        !out.iter()
            .any(|o| o.to == alice && matches!(&o.message, ServerMessage::ChannelCreated { .. })),
        "the creator shouldn't get a redundant ChannelCreated: {out:?}"
    );
}

/// @requirement TB-156
#[test]
fn creating_a_private_channel_never_broadcasts_channelcreated() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let _bob = reg.register("bob".into(), vec![], KeyMode::Rsa);

    let out = reg
        .join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    assert!(
        !out.iter()
            .any(|o| matches!(&o.message, ServerMessage::ChannelCreated { .. })),
        "a private channel must never be broadcast: {out:?}"
    );
}

/// @requirement AC-108
#[test]
fn joining_an_already_existing_public_channel_does_not_rebroadcast_it() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    let carol = reg.register("carol".into(), vec![], KeyMode::Rsa);

    reg.join_channel(alice, "already-there", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let out = reg
        .join_channel(bob, "already-there", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(
        !out.iter()
            .any(|o| o.to == carol && matches!(&o.message, ServerMessage::ChannelCreated { .. })),
        "only genuine creation should broadcast, not every later join: {out:?}"
    );
}

/// @requirement TB-102
#[test]
fn unregister_removes_user_from_every_channel_it_was_in() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    // A full disconnect notifies remaining peers with `UserOffline`, not
    // `UserLeft` - that's reserved for an explicit single-channel
    // `LeaveChannel` while still connected (see `leaving_notifies_remaining_members`).
    let out = reg.unregister(alice);
    assert!(out.iter().any(|o| o.to == bob
        && matches!(&o.message, ServerMessage::UserOffline { user_id } if *user_id == alice)));
    assert!(reg.user_info(alice).is_none());
}

/// @requirement TB-103
#[test]
fn unregister_sends_exactly_one_useroffline_per_peer_even_if_shared_multiple_channels() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(alice, "another-room", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "another-room", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.unregister(alice);
    let to_bob: Vec<_> = out
        .iter()
        .filter(|o| o.to == bob && matches!(&o.message, ServerMessage::UserOffline { .. }))
        .collect();
    assert_eq!(
        to_bob.len(),
        1,
        "bob shares two channels with alice but should get one UserOffline: {out:?}"
    );
}

/// @requirement AC-023, TB-102
#[test]
fn leave_channel_still_sends_userleft_while_the_user_stays_connected() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.leave_channel(alice, "general");
    assert!(
        out.iter()
            .any(|o| o.to == bob && matches!(&o.message, ServerMessage::UserLeft { .. }))
    );
    // alice is still a registered client - leaving a channel is not a disconnect.
    assert!(reg.user_info(alice).is_some());
}

// ---------------------------------------------------------------------
// Channel name validation (AC-102)
// ---------------------------------------------------------------------

/// @requirement AC-102
#[test]
fn join_channel_rejects_a_name_over_the_length_cap() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let too_long = "a".repeat(22);
    let err = reg
        .join_channel(alice, &too_long, ChannelKind::Public, None, TEST_IP)
        .unwrap_err();
    assert!(
        err.contains("channel name"),
        "unexpected error message: {err}"
    );
}

/// @requirement AC-102
#[test]
fn join_channel_rejects_a_name_with_disallowed_characters() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let err = reg
        .join_channel(alice, "has space", ChannelKind::Public, None, TEST_IP)
        .unwrap_err();
    assert!(
        err.contains("channel name"),
        "unexpected error message: {err}"
    );
}

// ---------------------------------------------------------------------
// Password-protected private channels and brute-force protection (US-025)
// ---------------------------------------------------------------------

/// @requirement AC-104, TB-151
#[test]
fn private_channel_created_with_a_password_can_be_joined_by_a_second_client_with_the_right_one() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();
    let out = reg
        .join_channel(bob, "vault", ChannelKind::Private, Some("s3cret!"), TEST_IP)
        .unwrap();
    assert!(out.iter().any(|o| o.to == bob
        && matches!(&o.message, ServerMessage::Joined { channel } if channel.name == "vault")));
}

/// @requirement AC-105
#[test]
fn private_channel_created_with_a_password_rejects_a_join_with_no_password() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();
    let out = reg
        .join_channel(bob, "vault", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    assert_eq!(out.len(), 1);
    assert!(matches!(
        &out[0],
        Outgoing { to, message: ServerMessage::ChannelJoinRejected { name, kind: ChannelJoinRejection::PasswordRequired } }
            if *to == bob && name == "vault"
    ));
}

/// @requirement AC-105, TB-151
#[test]
fn private_channel_created_with_a_password_rejects_a_join_with_the_wrong_password() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();
    let out = reg
        .join_channel(bob, "vault", ChannelKind::Private, Some("wrong"), TEST_IP)
        .unwrap();
    assert_eq!(out.len(), 1);
    assert!(matches!(
        &out[0],
        Outgoing { to, message: ServerMessage::ChannelJoinRejected { name, kind: ChannelJoinRejection::WrongPassword } }
            if *to == bob && name == "vault"
    ));
}

/// @requirement TB-152
#[test]
fn a_successful_password_join_resets_the_attempt_counter() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();

    for _ in 0..CHANNEL_MAX_PASSWORD_ATTEMPTS - 1 {
        reg.join_channel(bob, "vault", ChannelKind::Private, Some("wrong"), TEST_IP)
            .unwrap();
    }
    // succeed - this must reset the counter
    reg.join_channel(bob, "vault", ChannelKind::Private, Some("s3cret!"), TEST_IP)
        .unwrap();

    // now bob leaves and tries again from scratch: one wrong guess must not
    // be treated as already-near-the-ban-threshold.
    reg.leave_channel(bob, "vault");
    let out = reg
        .join_channel(bob, "vault", ChannelKind::Private, Some("wrong"), TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0].message,
        ServerMessage::ChannelJoinRejected {
            kind: ChannelJoinRejection::WrongPassword,
            ..
        }
    ));
}

/// @requirement AC-106, TB-153
#[test]
fn more_than_seven_wrong_attempts_from_one_ip_bans_that_ip_for_that_channel() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();

    let mut last = None;
    for _ in 0..CHANNEL_MAX_PASSWORD_ATTEMPTS + 1 {
        last = Some(
            reg.join_channel(bob, "vault", ChannelKind::Private, Some("wrong"), TEST_IP)
                .unwrap(),
        );
    }
    assert!(matches!(
        &last.unwrap()[0].message,
        ServerMessage::ChannelJoinRejected {
            kind: ChannelJoinRejection::Banned,
            ..
        }
    ));

    // even the right password is refused now.
    let out = reg
        .join_channel(bob, "vault", ChannelKind::Private, Some("s3cret!"), TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0].message,
        ServerMessage::ChannelJoinRejected {
            kind: ChannelJoinRejection::Banned,
            ..
        }
    ));
}

/// @requirement TB-153
#[test]
fn a_ban_is_scoped_to_ip_and_channel_not_userid() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();

    for _ in 0..CHANNEL_MAX_PASSWORD_ATTEMPTS + 1 {
        reg.join_channel(bob, "vault", ChannelKind::Private, Some("wrong"), TEST_IP)
            .unwrap();
    }

    // a different source address is unaffected by TEST_IP's ban.
    let out = reg
        .join_channel(
            bob,
            "vault",
            ChannelKind::Private,
            Some("wrong"),
            OTHER_TEST_IP,
        )
        .unwrap();
    assert!(matches!(
        &out[0].message,
        ServerMessage::ChannelJoinRejected {
            kind: ChannelJoinRejection::WrongPassword,
            ..
        }
    ));
    let _ = CHANNEL_PASSWORD_BAN_DURATION; // exercised via elapsed() inside Registry; referenced here for clarity
}

/// @requirement TB-154
#[test]
fn channel_join_rejected_is_sent_to_the_requester_only() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    reg.join_channel(
        alice,
        "vault",
        ChannelKind::Private,
        Some("s3cret!"),
        TEST_IP,
    )
    .unwrap();

    let out = reg
        .join_channel(bob, "vault", ChannelKind::Private, Some("wrong"), TEST_IP)
        .unwrap();
    assert_eq!(
        out.len(),
        1,
        "must be sent to bob only, not broadcast: {out:?}"
    );
    assert_eq!(out[0].to, bob);
}

// ---------------------------------------------------------------------
// Direct-link signaling: candidate-exchange relay (crate::p2p)
// ---------------------------------------------------------------------

/// @requirement AC-100, TB-143
#[test]
fn peer_link_request_relays_candidates_to_the_named_peer() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    let candidates = vec![
        "127.0.0.1:4000".parse().unwrap(),
        "203.0.113.5:51820".parse().unwrap(),
    ];

    let out = reg
        .route_peer_link_request(alice, bob, candidates.clone(), 42)
        .expect("route ok");

    assert_eq!(out.to, bob);
    assert!(
        matches!(&out.message, ServerMessage::PeerCandidates { from, candidates: got, link_nonce: 42 }
        if *from == alice && got == &candidates)
    );
}

/// @requirement TB-143
#[test]
fn peer_link_request_to_an_unknown_recipient_is_rejected() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let err = reg
        .route_peer_link_request(alice, UserId(9999), vec![], 1)
        .unwrap_err();
    assert!(err.contains("unknown recipient"));
}

// ---------------------------------------------------------------------
// rsa_per_msg: key_mode propagation and RotateKey relay
// ---------------------------------------------------------------------

/// @requirement TB-017
#[test]
fn user_info_reflects_registered_key_mode() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PerMessage);
    let bob = reg.register("bob".into(), vec![2], KeyMode::Rsa);
    assert_eq!(reg.user_info(alice).unwrap().key_mode, KeyMode::PerMessage);
    assert_eq!(reg.user_info(bob).unwrap().key_mode, KeyMode::Rsa);
}

/// @requirement TB-082
#[test]
fn key_rotation_is_delivered_to_recipient() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PerMessage);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    let out = reg
        .route_key_rotation(alice, bob, vec![9, 9, 9], vec![1, 1, 1])
        .expect("route ok");
    assert_eq!(out.to, bob);
    assert!(
        matches!(&out.message, ServerMessage::KeyRotated { from, new_public_key_der, signature }
        if *from == alice && new_public_key_der == &vec![9, 9, 9] && signature == &vec![1, 1, 1])
    );
}

/// @requirement TB-082
#[test]
fn key_rotation_from_a_static_mode_sender_is_rejected() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::Rsa);
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    let err = reg
        .route_key_rotation(alice, bob, vec![], vec![])
        .unwrap_err();
    assert!(err.contains("rsa_per_msg"));
}

/// @requirement TB-082
#[test]
fn key_rotation_to_unknown_recipient_is_rejected() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PerMessage);
    let err = reg
        .route_key_rotation(alice, UserId(9999), vec![], vec![])
        .unwrap_err();
    assert!(err.contains("unknown recipient"));
}

/// @requirement TB-082
#[test]
fn key_rotation_from_unknown_sender_is_rejected() {
    let mut reg = Registry::new();
    let bob = reg.register("bob".into(), vec![], KeyMode::Rsa);
    let err = reg
        .route_key_rotation(UserId(9999), bob, vec![], vec![])
        .unwrap_err();
    assert!(err.contains("unknown sender"));
}

// ---------------------------------------------------------------------
// AuthConfig
// ---------------------------------------------------------------------

/// @requirement AC-014, TB-013, TB-014
#[test]
fn none_auth_kind_and_no_challenge() {
    let cfg = AuthConfig::None;
    assert_eq!(cfg.kind(), AuthKind::None);
    assert!(cfg.make_challenge().is_none());
    assert!(cfg.verify(None, &AuthResponse::None));
    assert!(!cfg.verify(None, &AuthResponse::Password("x".into())));
}

/// @requirement AC-013, TB-013
#[test]
fn password_auth_accepts_correct_and_rejects_wrong() {
    let cfg = AuthConfig::Password("hunter2".into());
    assert_eq!(cfg.kind(), AuthKind::Password);
    assert!(cfg.make_challenge().is_none());
    assert!(cfg.verify(None, &AuthResponse::Password("hunter2".into())));
    assert!(!cfg.verify(None, &AuthResponse::Password("wrong".into())));
}

/// @requirement AC-013, TB-013
#[test]
fn rsa_auth_accepts_valid_challenge_response_and_rejects_wrong_key() {
    let server_kp = crypto::KeyPair::generate().unwrap();
    let impostor_kp = crypto::KeyPair::generate().unwrap();
    let cfg = AuthConfig::Rsa(Box::new(server_kp.private));
    assert_eq!(cfg.kind(), AuthKind::Rsa);

    let challenge = cfg.make_challenge().expect("rsa requires a challenge");

    // legitimate client: encrypts the nonce with the server's real public key
    let good_blocks = crypto::encrypt_chunked(&server_kp.public, &challenge).unwrap();
    assert!(cfg.verify(
        Some(&challenge),
        &AuthResponse::Rsa {
            blocks: good_blocks
        }
    ));

    // impostor: encrypts with a different keypair's public half, so the
    // server can't decrypt it back to the original nonce
    let bad_blocks = crypto::encrypt_chunked(&impostor_kp.public, &challenge).unwrap();
    assert!(!cfg.verify(Some(&challenge), &AuthResponse::Rsa { blocks: bad_blocks }));
}

/// @requirement TB-014
#[test]
fn rsa_auth_rejects_response_of_the_wrong_kind() {
    let server_kp = crypto::KeyPair::generate().unwrap();
    let cfg = AuthConfig::Rsa(Box::new(server_kp.private));
    let challenge = cfg.make_challenge().unwrap();
    assert!(!cfg.verify(Some(&challenge), &AuthResponse::None));
    assert!(!cfg.verify(Some(&challenge), &AuthResponse::Password("whatever".into())));
}

// ---------------------------------------------------------------------
// End-to-end over real TCP
// ---------------------------------------------------------------------

async fn handshake_no_auth(stream: &mut TcpStream, name: &str) -> UserId {
    handshake_no_auth_with_mode(stream, name, KeyMode::Rsa).await
}

async fn handshake_no_auth_with_mode(
    stream: &mut TcpStream,
    name: &str,
    key_mode: KeyMode,
) -> UserId {
    let hello: ServerMessage = read_message(stream).await.unwrap().unwrap();
    assert!(matches!(
        hello,
        ServerMessage::Hello {
            auth: AuthKind::None,
            challenge: None
        }
    ));

    write_message(stream, &ClientMessage::Auth(AuthResponse::None))
        .await
        .unwrap();
    let result: ServerMessage = read_message(stream).await.unwrap().unwrap();
    assert!(matches!(result, ServerMessage::AuthResult { ok: true, .. }));

    write_message(
        stream,
        &ClientMessage::Identify {
            display_name: name.into(),
            public_key_der: vec![],
            key_mode,
        },
    )
    .await
    .unwrap();

    let identify_result: ServerMessage = read_message(stream).await.unwrap().unwrap();
    let ServerMessage::IdentifyResult {
        ok: true,
        you: Some(you),
        ..
    } = identify_result
    else {
        panic!("expected a successful IdentifyResult, got {identify_result:?}");
    };

    let channel_list: ServerMessage = read_message(stream).await.unwrap().unwrap();
    assert!(matches!(channel_list, ServerMessage::ChannelList(_)));

    you
}

async fn spawn_test_server(auth: AuthConfig) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, auth).await;
    });
    addr
}

/// @requirement AC-019, AC-024
#[tokio::test]
async fn end_to_end_two_clients_join_and_learn_about_each_other() {
    let addr = spawn_test_server(AuthConfig::None).await;

    let mut a = TcpStream::connect(addr).await.unwrap();
    let alice_id = handshake_no_auth(&mut a, "alice").await;

    let mut b = TcpStream::connect(addr).await.unwrap();
    let bob_id = handshake_no_auth(&mut b, "bob").await;

    write_message(
        &mut a,
        &ClientMessage::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        },
    )
    .await
    .unwrap();
    let joined: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));

    // "general" didn't exist yet (the server only ever seeds "the-hall") -
    // alice creating it broadcasts ChannelCreated to bob, who's already
    // connected (AC-108), before he ever joins it himself.
    let created: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(
        matches!(created, ServerMessage::ChannelCreated { channel } if channel.name == "general")
    );

    write_message(
        &mut b,
        &ClientMessage::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        },
    )
    .await
    .unwrap();

    // alice should be told bob joined
    let notif: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    assert!(matches!(notif, ServerMessage::UserJoined { user, .. } if user.id == bob_id));

    // bob should learn about alice (snapshot), then get his own Joined confirmation
    let bob_snapshot: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(bob_snapshot, ServerMessage::UserJoined { user, .. } if user.id == alice_id));
    let bob_joined: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(bob_joined, ServerMessage::Joined { .. }));
}

/// @requirement AC-108
#[tokio::test]
async fn end_to_end_a_second_client_sees_a_newly_created_public_channel() {
    let addr = spawn_test_server(AuthConfig::None).await;

    let mut a = TcpStream::connect(addr).await.unwrap();
    handshake_no_auth(&mut a, "alice").await;
    let mut b = TcpStream::connect(addr).await.unwrap();
    handshake_no_auth(&mut b, "bob").await;

    write_message(
        &mut a,
        &ClientMessage::JoinChannel {
            name: "watercooler".into(),
            kind: ChannelKind::Public,
            password: None,
        },
    )
    .await
    .unwrap();
    let joined: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));

    // bob never joined "watercooler" - he should still be told it exists.
    let created: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    match created {
        ServerMessage::ChannelCreated { channel } => {
            assert_eq!(channel.name, "watercooler");
            assert_eq!(channel.kind, ChannelKind::Public);
        }
        other => panic!("expected ChannelCreated, got {other:?}"),
    }
}

/// @requirement AC-104, AC-105
#[tokio::test]
async fn end_to_end_password_protected_channel_join_flow() {
    let addr = spawn_test_server(AuthConfig::None).await;

    let mut a = TcpStream::connect(addr).await.unwrap();
    handshake_no_auth(&mut a, "alice").await;
    let mut b = TcpStream::connect(addr).await.unwrap();
    handshake_no_auth(&mut b, "bob").await;

    write_message(
        &mut a,
        &ClientMessage::JoinChannel {
            name: "vault".into(),
            kind: ChannelKind::Private,
            password: Some("s3cret!".into()),
        },
    )
    .await
    .unwrap();
    let joined: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));

    // bob tries with no password: told a password is required.
    write_message(
        &mut b,
        &ClientMessage::JoinChannel {
            name: "vault".into(),
            kind: ChannelKind::Private,
            password: None,
        },
    )
    .await
    .unwrap();
    let rejected: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(
        rejected,
        ServerMessage::ChannelJoinRejected {
            kind: ChannelJoinRejection::PasswordRequired,
            ..
        }
    ));

    // bob retries with the right password.
    write_message(
        &mut b,
        &ClientMessage::JoinChannel {
            name: "vault".into(),
            kind: ChannelKind::Private,
            password: Some("s3cret!".into()),
        },
    )
    .await
    .unwrap();
    let bob_snapshot: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(bob_snapshot, ServerMessage::UserJoined { .. }));
    let bob_joined: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(bob_joined, ServerMessage::Joined { .. }));
}

/// @requirement TB-082
#[tokio::test]
async fn end_to_end_key_rotation_is_relayed_and_rejected_appropriately() {
    let addr = spawn_test_server(AuthConfig::None).await;

    let mut a = TcpStream::connect(addr).await.unwrap();
    let alice_id = handshake_no_auth_with_mode(&mut a, "alice", KeyMode::PerMessage).await;
    let mut b = TcpStream::connect(addr).await.unwrap();
    let bob_id = handshake_no_auth_with_mode(&mut b, "bob", KeyMode::Rsa).await;

    // alice (rsa_per_msg) rotates her key for bob - relayed as KeyRotated.
    write_message(
        &mut a,
        &ClientMessage::RotateKey {
            to: bob_id,
            new_public_key_der: vec![4, 5, 6],
            signature: vec![7, 8],
        },
    )
    .await
    .unwrap();
    let rotated: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    match rotated {
        ServerMessage::KeyRotated {
            from,
            new_public_key_der,
            signature,
        } => {
            assert_eq!(from, alice_id);
            assert_eq!(new_public_key_der, vec![4, 5, 6]);
            assert_eq!(signature, vec![7, 8]);
        }
        other => panic!("expected KeyRotated, got {other:?}"),
    }

    // bob (Static) is not allowed to rotate: server sends him an Error back.
    write_message(
        &mut b,
        &ClientMessage::RotateKey {
            to: alice_id,
            new_public_key_der: vec![],
            signature: vec![],
        },
    )
    .await
    .unwrap();
    let err: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(&err, ServerMessage::Error { message } if message.contains("rsa_per_msg")));
}

/// The wire-level foundation of the `rsa_per_msg` continuity/resume
/// mechanism (`docs/PROTOCOL.md` §12.6, `own_next_keys`): a rotation
/// signed with a key established under one connection must relay and
/// verify identically when re-announced from an entirely new connection
/// (a fresh `UserId`) for the same nickname, addressed to a peer who never
/// reconnected in between. The server has no special-case logic for this
/// at all - it's the same `RotateKey`/`KeyRotated` relay every ordinary
/// rotation already uses (§7.5); this test exists to pin down that the
/// *server* side of "just reconnect and re-assert the old key" genuinely
/// requires nothing new, only client-side bookkeeping (main.rs) and
/// verification logic (rekey::verify_with_fallback, covered directly in
/// rekey_test.rs) do.
/// @requirement AC-050, TB-020, TB-098
#[tokio::test]
async fn end_to_end_resume_rotation_after_reconnect_verifies_against_the_continuity_key() {
    let addr = spawn_test_server(AuthConfig::None).await;

    let mut b = TcpStream::connect(addr).await.unwrap();
    let bob_id = handshake_no_auth_with_mode(&mut b, "bob", KeyMode::None).await;

    // First session: alice (rsa_per_msg) establishes a per-peer key with
    // bob - this is what a real client would later persist to
    // own_next_keys as the continuity key for "bob".
    let mut a1 = TcpStream::connect(addr).await.unwrap();
    let alice_id_1 = handshake_no_auth_with_mode(&mut a1, "alice", KeyMode::PerMessage).await;

    let continuity = KeyPair::generate().unwrap();
    let continuity_der = crypto::public_key_to_der(&continuity.public).unwrap();
    let bootstrap_signed =
        rekey::sign_rotation(&continuity.private, bob_id, &continuity_der).unwrap();
    write_message(
        &mut a1,
        &ClientMessage::RotateKey {
            to: bob_id,
            new_public_key_der: continuity_der.clone(),
            signature: bootstrap_signed,
        },
    )
    .await
    .unwrap();
    let first: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    match first {
        ServerMessage::KeyRotated {
            from,
            new_public_key_der,
            ..
        } => {
            assert_eq!(from, alice_id_1);
            assert_eq!(new_public_key_der, continuity_der);
        }
        other => panic!("expected KeyRotated, got {other:?}"),
    }

    // alice disconnects entirely (not just leaves a channel) and
    // reconnects - a brand new UserId, unrelated to alice_id_1.
    drop(a1);
    let mut a2 = TcpStream::connect(addr).await.unwrap();
    let alice_id_2 = handshake_no_auth_with_mode(&mut a2, "alice", KeyMode::PerMessage).await;
    assert_ne!(
        alice_id_1, alice_id_2,
        "UserId must not be reused across reconnects"
    );

    // Resume: self-assert the same continuity key, addressed to bob's
    // still-live UserId, signed by that same key (proof of possession).
    let resume_sig = rekey::sign_rotation(&continuity.private, bob_id, &continuity_der).unwrap();
    write_message(
        &mut a2,
        &ClientMessage::RotateKey {
            to: bob_id,
            new_public_key_der: continuity_der.clone(),
            signature: resume_sig.clone(),
        },
    )
    .await
    .unwrap();
    let resumed: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    match resumed {
        ServerMessage::KeyRotated {
            from,
            new_public_key_der,
            signature,
        } => {
            assert_eq!(
                from, alice_id_2,
                "relayed from alice's new connection, not the old one"
            );
            assert_eq!(new_public_key_der, continuity_der);
            // and it must actually verify against the continuity public
            // key bob would have pinned from the first session - this is
            // the exact check main.rs::handle_key_rotated's fallback path
            // performs (rekey::verify_with_fallback, unit-tested directly
            // in rekey_test.rs).
            assert!(rekey::verify_rotation(
                &continuity.public,
                bob_id,
                &new_public_key_der,
                &signature
            ));
        }
        other => panic!("expected KeyRotated, got {other:?}"),
    }
}

/// @requirement AC-013
#[tokio::test]
async fn end_to_end_wrong_password_is_rejected() {
    let addr = spawn_test_server(AuthConfig::Password("s3cret".into())).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();

    let hello: ServerMessage = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(
        hello,
        ServerMessage::Hello {
            auth: AuthKind::Password,
            ..
        }
    ));

    write_message(
        &mut stream,
        &ClientMessage::Auth(AuthResponse::Password("wrong".into())),
    )
    .await
    .unwrap();
    let result: ServerMessage = read_message(&mut stream).await.unwrap().unwrap();
    assert!(matches!(
        result,
        ServerMessage::AuthResult { ok: false, .. }
    ));
}

/// @requirement TB-112
#[tokio::test]
async fn end_to_end_stray_auth_and_identify_after_handshake_error_but_stay_connected() {
    let addr = spawn_test_server(AuthConfig::None).await;
    let mut a = TcpStream::connect(addr).await.unwrap();
    handshake_no_auth(&mut a, "dave").await;

    // a stray Auth once already connected: an Error, not a close
    write_message(&mut a, &ClientMessage::Auth(AuthResponse::None))
        .await
        .unwrap();
    let after_auth: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    match after_auth {
        ServerMessage::Error { message } => {
            assert!(message.contains("unexpected message after handshake"))
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // a stray Identify right after: also an Error, connection still open
    write_message(
        &mut a,
        &ClientMessage::Identify {
            display_name: "dave2".into(),
            public_key_der: vec![],
            key_mode: KeyMode::Rsa,
        },
    )
    .await
    .unwrap();
    let after_identify: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    match after_identify {
        ServerMessage::Error { message } => {
            assert!(message.contains("unexpected message after handshake"))
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // the connection is still fully usable afterward
    write_message(
        &mut a,
        &ClientMessage::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        },
    )
    .await
    .unwrap();
    let joined: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));
}

/// @requirement AC-015, AC-017
#[tokio::test]
async fn end_to_end_duplicate_nickname_is_rejected_and_connection_closes() {
    let addr = spawn_test_server(AuthConfig::None).await;

    let mut a = TcpStream::connect(addr).await.unwrap();
    let _alice_id = handshake_no_auth(&mut a, "dave").await;

    // a second client tries to identify with the same nickname
    let mut b = TcpStream::connect(addr).await.unwrap();
    let hello: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(
        hello,
        ServerMessage::Hello {
            auth: AuthKind::None,
            ..
        }
    ));
    write_message(&mut b, &ClientMessage::Auth(AuthResponse::None))
        .await
        .unwrap();
    let auth_result: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    assert!(matches!(
        auth_result,
        ServerMessage::AuthResult { ok: true, .. }
    ));

    write_message(
        &mut b,
        &ClientMessage::Identify {
            display_name: "dave".into(),
            public_key_der: vec![],
            key_mode: KeyMode::Rsa,
        },
    )
    .await
    .unwrap();

    let identify_result: ServerMessage = read_message(&mut b).await.unwrap().unwrap();
    match identify_result {
        ServerMessage::IdentifyResult {
            ok: false,
            you: None,
            reason: Some(reason),
        } => {
            assert!(reason.contains("dave"));
        }
        other => panic!("expected a rejected IdentifyResult, got {other:?}"),
    }

    // the server closes the connection after rejecting the nickname
    let after: Option<ServerMessage> = read_message(&mut b).await.unwrap();
    assert!(
        after.is_none(),
        "server should close the connection after rejecting the nickname"
    );

    // meanwhile the original "dave" is completely unaffected
    write_message(
        &mut a,
        &ClientMessage::JoinChannel {
            name: "general".into(),
            kind: ChannelKind::Public,
            password: None,
        },
    )
    .await
    .unwrap();
    let joined: ServerMessage = read_message(&mut a).await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));
}

/// @requirement AC-016
#[tokio::test]
async fn end_to_end_nickname_is_free_again_after_the_holder_disconnects() {
    let addr = spawn_test_server(AuthConfig::None).await;

    {
        let mut a = TcpStream::connect(addr).await.unwrap();
        handshake_no_auth(&mut a, "dave").await;
        // `a` drops here, closing the connection
    }

    // give the server a moment to notice the disconnect and unregister
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // succeeds without the server rejecting it as a duplicate; a hang or a
    // rejection here would fail this test via handshake_no_auth's asserts
    let mut b = TcpStream::connect(addr).await.unwrap();
    handshake_no_auth(&mut b, "dave").await;
}
