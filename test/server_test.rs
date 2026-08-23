#[path = "server_common.rs"]
mod server_common;

use std::net::{IpAddr, Ipv4Addr};

use aloo::proto::*;
use aloo::server::{
    CHANNEL_MAX_PASSWORD_ATTEMPTS, CHANNEL_PASSWORD_BAN_DURATION, DEFAULT_CHANNEL_NAME, Outgoing,
    Registry,
};
use server_common::{TestServer, login, password_for, test_options, test_users_registry};

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
    let id = reg.register("dave".into(), vec![1, 2, 3], KeyMode::PqHybrid);
    let info = reg.user_info(id).expect("registered user");
    assert_eq!(info.name, "dave");
    assert_eq!(info.public_key_der, vec![1, 2, 3]);
}

/// @requirement TB-018
#[test]
fn name_taken_reflects_currently_registered_clients() {
    let mut reg = Registry::new();
    assert!(!reg.name_taken("dave"));
    reg.register("dave".into(), vec![], KeyMode::PqHybrid);
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
        .try_register("dave".into(), vec![1], KeyMode::PqHybrid)
        .expect("first registration succeeds");
    let err = reg
        .try_register("dave".into(), vec![2], KeyMode::PqHybrid)
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
        .try_register("dave".into(), vec![1], KeyMode::PqHybrid)
        .unwrap();
    reg.unregister(first);
    let second = reg
        .try_register("dave".into(), vec![2], KeyMode::PqHybrid)
        .expect("name freed up after unregister");
    assert_eq!(reg.user_info(second).unwrap().public_key_der, vec![2]);
}

/// @requirement TB-022
#[test]
fn joining_new_channel_sends_confirmation_and_no_peer_events() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![9], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![8], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    let list = reg.channel_list();
    assert!(list.iter().all(|c| c.name != "secret-room"));
}

/// @requirement AC-023
#[test]
fn leaving_notifies_remaining_members() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);

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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let _bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);

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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    let carol = reg.register("carol".into(), vec![], KeyMode::PqHybrid);

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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
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
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let err = reg
        .route_peer_link_request(alice, UserId(9999), vec![], 1)
        .unwrap_err();
    assert!(err.contains("unknown recipient"));
}

// ---------------------------------------------------------------------
// pq_hybrid: key_mode propagation and RotateKey relay
// ---------------------------------------------------------------------

/// @requirement TB-017
#[test]
fn user_info_reflects_registered_key_mode() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![1], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![2], KeyMode::PqHybrid);
    assert_eq!(reg.user_info(alice).unwrap().key_mode, KeyMode::PqHybrid);
    assert_eq!(reg.user_info(bob).unwrap().key_mode, KeyMode::PqHybrid);
}

/// @requirement TB-082
#[test]
fn key_rotation_is_delivered_to_recipient() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    let out = reg
        .route_key_rotation(alice, bob, vec![9, 9, 9], vec![1, 1, 1])
        .expect("route ok");
    assert_eq!(out.to, bob);
    assert!(
        matches!(&out.message, ServerMessage::KeyRotated { from, new_public_key_der, signature }
        if *from == alice && new_public_key_der == &vec![9, 9, 9] && signature == &vec![1, 1, 1])
    );
}

/// The server has no notion of which senders rotate - every client runs
/// the one mode that does - and inspects neither the key nor the
/// signature it is relaying.
/// @requirement TB-167
#[test]
fn the_server_relays_a_rotation_without_inspecting_it() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    // Deliberately meaningless bytes: the server is not the thing that
    // checks them, the recipient is (docs/PROTOCOL.md 13.10).
    let out = reg
        .route_key_rotation(alice, bob, vec![7], vec![8])
        .expect("a registered sender's rotation is relayed");
    assert_eq!(out.to, bob);
    assert!(matches!(
        &out.message,
        ServerMessage::KeyRotated { from, .. } if *from == alice
    ));
}

/// @requirement TB-082
#[test]
fn key_rotation_to_unknown_recipient_is_rejected() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let err = reg
        .route_key_rotation(alice, UserId(9999), vec![], vec![])
        .unwrap_err();
    assert!(err.contains("unknown recipient"));
}

/// @requirement TB-082
#[test]
fn key_rotation_from_unknown_sender_is_rejected() {
    let mut reg = Registry::new();
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    let err = reg
        .route_key_rotation(UserId(9999), bob, vec![], vec![])
        .unwrap_err();
    assert!(err.contains("unknown sender"));
}

// ---------------------------------------------------------------------
// Logging in (docs/PROTOCOL.md §5)
// ---------------------------------------------------------------------

/// @requirement AC-013, TB-013
#[tokio::test]
async fn a_registered_nickname_with_its_password_is_let_in() {
    let server = TestServer::spawn(test_options("login-ok")).await;
    server.ensure_user("alice");
    let mut stream = server.connect().await;
    let result = login(&mut stream, "alice", &password_for("alice")).await;
    assert_eq!(
        result,
        ServerMessage::AuthResult {
            ok: true,
            activation_pending: false,
            reason: None
        }
    );
}

/// A wrong password and a nickname nobody registered get the very same
/// answer, so a login attempt cannot be used to list the accounts.
/// @requirement AC-013
#[tokio::test]
async fn a_wrong_password_and_an_unknown_nickname_are_refused_alike() {
    let server = TestServer::spawn(test_options("login-bad")).await;
    server.ensure_user("alice");

    let mut stream = server.connect().await;
    let wrong = login(&mut stream, "alice", "not-her-password").await;
    let ServerMessage::AuthResult {
        ok: false,
        activation_pending: false,
        reason: Some(wrong_reason),
    } = wrong
    else {
        panic!("expected a refusal, got {wrong:?}");
    };
    let closed: Option<ServerMessage> = stream.recv().await.unwrap();
    assert!(closed.is_none(), "the server hangs up after a refusal");

    let mut stream = server.connect().await;
    let unknown = login(&mut stream, "nobody", "whatever").await;
    let ServerMessage::AuthResult {
        ok: false,
        activation_pending: false,
        reason: Some(unknown_reason),
    } = unknown
    else {
        panic!("expected a refusal, got {unknown:?}");
    };
    assert_eq!(wrong_reason, unknown_reason, "one answer for both");
}

/// A nickname the registry could never hold is refused before any file is
/// looked at - it can name nothing under the users directory.
/// @requirement AC-013, TB-238
#[tokio::test]
async fn an_unregistrable_nickname_is_refused_without_touching_the_registry() {
    let server = TestServer::spawn(test_options("login-traversal")).await;
    let mut stream = server.connect().await;
    let result = login(&mut stream, "../etc", "x").await;
    assert!(matches!(result, ServerMessage::AuthResult { ok: false, .. }));
    assert!(!server.options.users.dir().join("..").join("etc").join("key").exists());
}

/// The right password on an account still awaiting its code is told so,
/// and may answer with the code once (§5.2).
/// @requirement AC-265
#[tokio::test]
async fn a_pending_account_is_asked_for_its_code_and_activated_by_the_right_one() {
    let options = test_options("login-activate");
    let registration = options
        .users
        .register("carol", "pw-carol", "carol@example.com", aloo::server::users_registry::now_utc())
        .unwrap();
    let server = TestServer::spawn(options).await;

    // Wrong code: refused, connection closed, account still pending.
    let mut stream = server.connect().await;
    let result = login(&mut stream, "carol", "pw-carol").await;
    assert_eq!(
        result,
        ServerMessage::AuthResult {
            ok: false,
            activation_pending: true,
            reason: None
        }
    );
    stream
        .send(&ClientMessage::Activate {
            code: "000000000000".into(),
        })
        .await
        .unwrap();
    let refused: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(refused, ServerMessage::AuthResult { ok: false, activation_pending: false, reason: Some(ref r) } if r.contains("wrong")),
        "{refused:?}"
    );
    assert!(stream.recv::<ServerMessage>().await.unwrap().is_none());
    assert!(server.options.users.pending_activation("carol").is_some());

    // Right code: activated, and the handshake continues into Identify.
    let mut stream = server.connect().await;
    let result = login(&mut stream, "carol", "pw-carol").await;
    assert!(matches!(result, ServerMessage::AuthResult { activation_pending: true, .. }));
    stream
        .send(&ClientMessage::Activate {
            code: registration.code.clone(),
        })
        .await
        .unwrap();
    let ok: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(matches!(ok, ServerMessage::AuthResult { ok: true, .. }), "{ok:?}");
    assert!(server.options.users.pending_activation("carol").is_none());
    stream
        .send(&ClientMessage::Identify {
            public_key_der: vec![],
            key_mode: KeyMode::PqHybrid,
        })
        .await
        .unwrap();
    let identify: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(matches!(identify, ServerMessage::IdentifyResult { ok: true, .. }));

    // From now on the login is an ordinary one.
    let mut again = server.connect().await;
    let result = login(&mut again, "carol", "pw-carol").await;
    assert!(matches!(result, ServerMessage::AuthResult { ok: true, activation_pending: false, .. }));
}

/// A code older than `ACTIVATION_VALIDITY_SECS` cannot activate anything;
/// the user is told to register again.
/// @requirement AC-265
#[tokio::test]
async fn an_expired_activation_is_refused_with_a_reason() {
    let options = test_options("login-expired");
    let long_ago = aloo::server::users_registry::now_utc()
        - aloo::server::users_registry::ACTIVATION_VALIDITY_SECS
        - 60;
    options
        .users
        .register("dan", "pw-dan", "dan@example.com", long_ago)
        .unwrap();
    let server = TestServer::spawn(options).await;
    let mut stream = server.connect().await;
    let result = login(&mut stream, "dan", "pw-dan").await;
    match result {
        ServerMessage::AuthResult {
            ok: false,
            activation_pending: false,
            reason: Some(reason),
        } => assert!(reason.contains("expired"), "{reason}"),
        other => panic!("expected an expiry refusal, got {other:?}"),
    }
}

/// `Hello` says whether registrations are taken, and a `Register` on a
/// server that does not take them is refused and hung up on.
/// @requirement AC-264
#[tokio::test]
async fn registration_is_advertised_in_hello_and_refused_when_off() {
    let server = TestServer::spawn(test_options("register-off")).await;
    let mut stream = server.connect().await;
    let open = stream.client_handshake().await.unwrap().unwrap();
    assert!(!open, "registration is off by default");
    stream
        .send(&ClientMessage::Register {
            nickname: "eve".into(),
            password: "pw".into(),
            email: "eve@example.com".into(),
        })
        .await
        .unwrap();
    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(result, ServerMessage::RegisterResult { ok: false, reason: Some(ref r) } if r.contains("registrations")),
        "{result:?}"
    );
    assert!(stream.recv::<ServerMessage>().await.unwrap().is_none());
    assert!(!server.options.users.is_registered("eve"));
}

/// Registration on, but no relay to send the code through: refused with
/// a reason, and no half-account left behind.
/// @requirement AC-264
#[tokio::test]
async fn registration_without_a_relay_is_refused_and_creates_nothing() {
    let server = TestServer::spawn(test_options("register-no-smtp").with_registration(None, None)).await;
    let mut stream = server.connect().await;
    let open = stream.client_handshake().await.unwrap().unwrap();
    assert!(open);
    stream
        .send(&ClientMessage::Register {
            nickname: "eve".into(),
            password: "pw".into(),
            email: "eve@example.com".into(),
        })
        .await
        .unwrap();
    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(result, ServerMessage::RegisterResult { ok: false, reason: Some(ref r) } if r.contains("email")),
        "{result:?}"
    );
    assert!(!server.options.users.is_registered("eve"));
}

/// The registry a server reads is the directory on disk, re-read per
/// login: a `--register-user` / `--change-password` made while it runs
/// is honoured by the very next connection.
/// @requirement AC-267
#[tokio::test]
async fn registry_edits_take_effect_on_the_next_login_without_a_restart() {
    let server = TestServer::spawn(test_options("live-edit")).await;
    let editor = test_users_registry(server.options.users.dir());

    let mut stream = server.connect().await;
    assert!(matches!(
        login(&mut stream, "fay", "first").await,
        ServerMessage::AuthResult { ok: false, .. }
    ));

    editor.register_manual("fay", "first").unwrap();
    let mut stream = server.connect().await;
    assert!(matches!(
        login(&mut stream, "fay", "first").await,
        ServerMessage::AuthResult { ok: true, .. }
    ));

    editor.change_password("fay", "second").unwrap();
    let mut stream = server.connect().await;
    assert!(matches!(
        login(&mut stream, "fay", "first").await,
        ServerMessage::AuthResult { ok: false, .. }
    ));
    let mut stream = server.connect().await;
    assert!(matches!(
        login(&mut stream, "fay", "second").await,
        ServerMessage::AuthResult { ok: true, .. }
    ));
}

// ---------------------------------------------------------------------
// End-to-end over real TCP
// ---------------------------------------------------------------------

/// @requirement AC-019, AC-024
#[tokio::test]
async fn end_to_end_two_clients_join_and_learn_about_each_other() {
    let server = TestServer::spawn(test_options("e2e")).await;

    let mut a = server.connect().await;
    let alice_id = server.handshake(&mut a, "alice").await;

    let mut b = server.connect().await;
    let bob_id = server.handshake(&mut b, "bob").await;

    a.send(&ClientMessage::JoinChannel {
        name: "general".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let joined: ServerMessage = a.recv().await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));

    // "general" didn't exist yet (the server only ever seeds "the-hall") -
    // alice creating it broadcasts ChannelCreated to bob, who's already
    // connected (AC-108), before he ever joins it himself.
    let created: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(
        matches!(created, ServerMessage::ChannelCreated { channel } if channel.name == "general")
    );

    b.send(&ClientMessage::JoinChannel {
        name: "general".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();

    // alice should be told bob joined
    let notif: ServerMessage = a.recv().await.unwrap().unwrap();
    assert!(matches!(notif, ServerMessage::UserJoined { user, .. } if user.id == bob_id));

    // bob should learn about alice (snapshot), then get his own Joined confirmation
    let bob_snapshot: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(matches!(bob_snapshot, ServerMessage::UserJoined { user, .. } if user.id == alice_id));
    let bob_joined: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(matches!(bob_joined, ServerMessage::Joined { .. }));
}

/// @requirement AC-108
#[tokio::test]
async fn end_to_end_a_second_client_sees_a_newly_created_public_channel() {
    let server = TestServer::spawn(test_options("e2e")).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    let mut b = server.connect().await;
    server.handshake(&mut b, "bob").await;

    a.send(&ClientMessage::JoinChannel {
        name: "watercooler".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let joined: ServerMessage = a.recv().await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));

    // bob never joined "watercooler" - he should still be told it exists.
    let created: ServerMessage = b.recv().await.unwrap().unwrap();
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
    let server = TestServer::spawn(test_options("e2e")).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    let mut b = server.connect().await;
    server.handshake(&mut b, "bob").await;

    a.send(&ClientMessage::JoinChannel {
        name: "vault".into(),
        kind: ChannelKind::Private,
        password: Some("s3cret!".into()),
    })
    .await
    .unwrap();
    let joined: ServerMessage = a.recv().await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));

    // bob tries with no password: told a password is required.
    b.send(&ClientMessage::JoinChannel {
        name: "vault".into(),
        kind: ChannelKind::Private,
        password: None,
    })
    .await
    .unwrap();
    let rejected: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(matches!(
        rejected,
        ServerMessage::ChannelJoinRejected {
            kind: ChannelJoinRejection::PasswordRequired,
            ..
        }
    ));

    // bob retries with the right password.
    b.send(&ClientMessage::JoinChannel {
        name: "vault".into(),
        kind: ChannelKind::Private,
        password: Some("s3cret!".into()),
    })
    .await
    .unwrap();
    let bob_snapshot: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(matches!(bob_snapshot, ServerMessage::UserJoined { .. }));
    let bob_joined: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(matches!(bob_joined, ServerMessage::Joined { .. }));
}

/// @requirement TB-082
#[tokio::test]
async fn end_to_end_key_rotation_is_relayed_and_rejected_appropriately() {
    let server = TestServer::spawn(test_options("e2e")).await;

    let mut a = server.connect().await;
    let alice_id = server.handshake_with_mode(&mut a, "alice", KeyMode::PqHybrid).await;
    let mut b = server.connect().await;
    let bob_id = server.handshake_with_mode(&mut b, "bob", KeyMode::PqHybrid).await;

    // alice rotates her key for bob - relayed verbatim as KeyRotated.
    a.send(&ClientMessage::RotateKey {
        to: bob_id,
        new_public_key_der: vec![4, 5, 6],
        signature: vec![7, 8],
    })
    .await
    .unwrap();
    let rotated: ServerMessage = b.recv().await.unwrap().unwrap();
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

    // A rotation naming a recipient the server has never heard of is
    // refused - the one thing it does check.
    b.send(&ClientMessage::RotateKey {
        to: UserId(9999),
        new_public_key_der: vec![],
        signature: vec![],
    })
    .await
    .unwrap();
    let err: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(
        matches!(&err, ServerMessage::Error { message } if message.contains("unknown recipient")),
        "expected an unknown-recipient error, got {err:?}"
    );
}

/// @requirement TB-112
#[tokio::test]
async fn end_to_end_stray_auth_and_identify_after_handshake_error_but_stay_connected() {
    let server = TestServer::spawn(test_options("e2e")).await;
    let mut a = server.connect().await;
    server.handshake(&mut a, "dave").await;

    // a stray Auth once already connected: an Error, not a close
    a.send(&ClientMessage::Auth {
        nickname: "dave".into(),
        password: password_for("dave"),
    })
    .await
    .unwrap();
    let after_auth: ServerMessage = a.recv().await.unwrap().unwrap();
    match after_auth {
        ServerMessage::Error { message } => {
            assert!(message.contains("unexpected message after handshake"))
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // a stray Identify right after: also an Error, connection still open
    a.send(&ClientMessage::Identify {
        public_key_der: vec![],
        key_mode: KeyMode::PqHybrid,
    })
    .await
    .unwrap();
    let after_identify: ServerMessage = a.recv().await.unwrap().unwrap();
    match after_identify {
        ServerMessage::Error { message } => {
            assert!(message.contains("unexpected message after handshake"))
        }
        other => panic!("expected Error, got {other:?}"),
    }

    // and the same for a stray Activate or Register
    for stray in [
        ClientMessage::Activate {
            code: "123456789012".into(),
        },
        ClientMessage::Register {
            nickname: "dave".into(),
            password: "x".into(),
            email: "dave@example.com".into(),
        },
    ] {
        a.send(&stray).await.unwrap();
        let answer: ServerMessage = a.recv().await.unwrap().unwrap();
        assert!(
            matches!(answer, ServerMessage::Error { ref message } if message.contains("unexpected message after handshake")),
            "{answer:?}"
        );
    }

    // the connection is still fully usable afterward
    a.send(&ClientMessage::JoinChannel {
        name: "general".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let joined: ServerMessage = a.recv().await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));
}

/// @requirement AC-015, AC-017
#[tokio::test]
async fn end_to_end_duplicate_nickname_is_rejected_and_connection_closes() {
    let server = TestServer::spawn(test_options("e2e")).await;

    let mut a = server.connect().await;
    let _alice_id = server.handshake(&mut a, "dave").await;

    // a second client logs in as the same nickname - the password is
    // right, so auth succeeds; it is Identify that is refused
    let mut b = server.connect().await;
    let auth_result = login(&mut b, "dave", &password_for("dave")).await;
    assert!(matches!(
        auth_result,
        ServerMessage::AuthResult { ok: true, .. }
    ));

    b.send(&ClientMessage::Identify {
        public_key_der: vec![],
        key_mode: KeyMode::PqHybrid,
    })
    .await
    .unwrap();

    let identify_result: ServerMessage = b.recv().await.unwrap().unwrap();
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
    let after: Option<ServerMessage> = b.recv().await.unwrap();
    assert!(
        after.is_none(),
        "server should close the connection after rejecting the nickname"
    );

    // meanwhile the original "dave" is completely unaffected
    a.send(&ClientMessage::JoinChannel {
        name: "general".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let joined: ServerMessage = a.recv().await.unwrap().unwrap();
    assert!(matches!(joined, ServerMessage::Joined { .. }));
}

/// @requirement AC-016
#[tokio::test]
async fn end_to_end_nickname_is_free_again_after_the_holder_disconnects() {
    let server = TestServer::spawn(test_options("e2e")).await;

    {
        let mut a = server.connect().await;
        server.handshake(&mut a, "dave").await;
        // `a` drops here, closing the connection
    }

    // give the server a moment to notice the disconnect and unregister
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // succeeds without the server rejecting it as a duplicate; a hang or a
    // rejection here would fail this test via handshake_no_auth's asserts
    let mut b = server.connect().await;
    server.handshake(&mut b, "dave").await;
}

/// @requirement AC-152
#[tokio::test]
async fn heartbeat_timeout_frees_the_nickname_without_a_clean_disconnect() {
    let heartbeat_timeout = std::time::Duration::from_millis(80);
    let server =
        TestServer::spawn(test_options("heartbeat").with_heartbeat_timeout(heartbeat_timeout)).await;

    // `a`'s socket is deliberately never closed or dropped for the rest of
    // this test - the server has to notice the silence itself, not a FIN.
    let mut a = server.connect().await;
    server.handshake(&mut a, "dave").await;

    tokio::time::sleep(heartbeat_timeout * 3).await;

    // succeeds even though `a` is still technically connected - proving the
    // server freed "dave" on its own via the heartbeat timeout, not via a
    // closed socket it never got.
    let mut b = server.connect().await;
    server.handshake(&mut b, "dave").await;
}

/// @requirement TB-191
#[tokio::test]
async fn ordinary_traffic_resets_the_heartbeat_timeout_clock() {
    let heartbeat_timeout = std::time::Duration::from_millis(150);
    let server =
        TestServer::spawn(test_options("heartbeat-reset").with_heartbeat_timeout(heartbeat_timeout)).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "dave").await;

    // Spread well past `heartbeat_timeout`'s total span, but never silent
    // for longer than it at a stretch - each Heartbeat should reset the
    // clock, so the connection must survive the whole thing.
    for _ in 0..4 {
        tokio::time::sleep(heartbeat_timeout / 2).await;
        a.send(&ClientMessage::Heartbeat).await.unwrap();
    }

    // still registered: a second "dave" is refused, not accepted.
    let mut b = server.connect().await;
    let _ = login(&mut b, "dave", &password_for("dave")).await;
    b.send(&ClientMessage::Identify {
        public_key_der: vec![],
        key_mode: KeyMode::PqHybrid,
    })
    .await
    .unwrap();
    let identify_result: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(
        matches!(
            identify_result,
            ServerMessage::IdentifyResult { ok: false, .. }
        ),
        "dave's original connection should still be alive, kept so by its heartbeats: {identify_result:?}"
    );
}
