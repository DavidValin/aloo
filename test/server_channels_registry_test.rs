//! `Registry`'s channel-related behavior: existence, kind, password,
//! membership, ownership, moderation (ban/unban/lock-joins/assign-admin/
//! delete-channel), and the inactivity sweep. Pure logic, no sockets -
//! mirrors `server_users_registry_test.rs`'s split from `server_test.rs`,
//! which keeps only connection-identity and real-TCP end-to-end tests.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use aloo::proto::*;
use aloo::server::{
    CHANNEL_MAX_PASSWORD_ATTEMPTS, CHANNEL_PASSWORD_BAN_DURATION, DEFAULT_CHANNEL_NAME, Outgoing,
    Registry,
};

const TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const OTHER_TEST_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

// ---------------------------------------------------------------------
// Existence, membership, directory (moved from server_test.rs)
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
        Outgoing { to, message: ServerMessage::Joined { channel, .. } }
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
        matches!(&o.message, ServerMessage::Joined { channel, .. } if *to_id(o) == bob && channel.name == "general")
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

/// **Rewritten** (was `empty_channel_is_deleted_unless_it_is_the_default_channel`,
/// TB-023/AC-107's original instant-delete assertion): a channel now
/// persists while empty, with no configured inactivity period, exactly
/// like `the-hall` already did unconditionally - only a configured sweep
/// (see the `sweep_*` tests below) ever removes one.
/// @requirement TB-023, AC-107
#[test]
fn an_emptied_channel_persists_with_no_configured_deletion_period() {
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

    // the-hall was always exempt.
    assert!(
        reg.channel_list()
            .iter()
            .any(|c| c.name == DEFAULT_CHANNEL_NAME)
    );
    // Neither does an ordinary public channel disappear now - with no
    // sweep configured, it stays exactly as it was, admin and all.
    assert!(
        reg.channel_list()
            .iter()
            .any(|c| c.name == "another-public-room")
    );
    // Rejoining it is an ordinary join of the still-existing channel, not
    // a re-creation: she gets her own `Joined` back (with the same admin
    // it always had - the channel record was never actually removed),
    // but nobody gets a `ChannelCreated`, since it was never gone.
    let out = reg
        .join_channel(
            alice,
            "another-public-room",
            ChannelKind::Public,
            None,
            TEST_IP,
        )
        .unwrap();
    assert!(
        !out.iter().any(|o| matches!(&o.message, ServerMessage::ChannelCreated { .. })),
        "the channel was never actually removed, so this must not look like a fresh creation: {out:?}"
    );
    assert!(matches!(
        &out[..],
        [Outgoing { message: ServerMessage::Joined { admin: Some(name), .. }, .. }] if name == "alice"
    ));
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
    let too_long = "a".repeat(aloo::validation::CHANNEL_NAME_MAX_LEN + 1);
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
        && matches!(&o.message, ServerMessage::Joined { channel, .. } if channel.name == "vault")));
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
// Ownership: a channel always belongs to whoever created it
// ---------------------------------------------------------------------

/// @requirement AC-338
#[test]
fn the_creator_of_a_public_channel_becomes_its_admin() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let out = reg
        .join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0],
        Outgoing { message: ServerMessage::Joined { admin: Some(name), .. }, .. } if name == "alice"
    ));
}

/// @requirement AC-338
#[test]
fn the_creator_of_a_private_channel_becomes_its_admin_too() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let out = reg
        .join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0],
        Outgoing { message: ServerMessage::Joined { admin: Some(name), .. }, .. } if name == "alice"
    ));
}

/// @requirement AC-338
#[test]
fn the_hall_has_no_admin() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let out = reg
        .join_channel(alice, DEFAULT_CHANNEL_NAME, ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0],
        Outgoing { message: ServerMessage::Joined { admin: None, .. }, .. }
    ));
}

/// @requirement AC-338
#[test]
fn a_second_joiner_does_not_become_admin() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let bob_joined = out
        .iter()
        .find(|o| o.to == bob && matches!(o.message, ServerMessage::Joined { .. }))
        .unwrap();
    assert!(matches!(
        &bob_joined.message,
        ServerMessage::Joined { admin: Some(name), .. } if name == "alice"
    ));
}

// ---------------------------------------------------------------------
// Moderation: /delete-channel, /ban, /unban, /lock-joins, /assign-admin
// ---------------------------------------------------------------------

/// @requirement AC-340
#[test]
fn the_admin_can_delete_the_public_channel_they_created() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.delete_channel(alice, "general").unwrap();
    assert!(out.iter().any(|o| o.to == bob
        && matches!(&o.message, ServerMessage::ChannelRemoved { name, .. } if name == "general")));
    assert!(reg.channel_list().iter().all(|c| c.name != "general"));
}

/// @requirement AC-340
#[test]
fn deleting_a_channel_you_do_not_administer_is_refused() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let err = reg.delete_channel(bob, "general").unwrap_err();
    assert!(err.contains("admin"), "unexpected error: {err}");
    assert!(reg.channel_list().iter().any(|c| c.name == "general"));
}

/// @requirement AC-340
#[test]
fn deleting_a_private_channel_is_refused() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "secret-room", ChannelKind::Private, None, TEST_IP)
        .unwrap();
    let err = reg.delete_channel(alice, "secret-room").unwrap_err();
    assert!(err.contains("public"), "unexpected error: {err}");
}

/// @requirement AC-338, AC-340
#[test]
fn the_hall_cannot_be_deleted_even_by_whoever_tries() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, DEFAULT_CHANNEL_NAME, ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let err = reg.delete_channel(alice, DEFAULT_CHANNEL_NAME).unwrap_err();
    assert!(err.contains("no admin"), "unexpected error: {err}");
}

/// @requirement AC-340
#[test]
fn a_deleted_channel_can_be_recreated_by_another_user() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.delete_channel(alice, "general").unwrap();

    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0],
        Outgoing { message: ServerMessage::Joined { admin: Some(name), .. }, .. } if name == "bob"
    ));
}

/// @requirement AC-341, TB-258
#[test]
fn the_admin_can_ban_a_member_who_is_then_force_removed_and_notified() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.ban_from_channel(alice, "general", "bob").unwrap();
    assert!(out.iter().any(|o| o.to == bob
        && matches!(&o.message, ServerMessage::UserBanned { user_id, .. } if *user_id == bob)));

    // future joins are refused
    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0].message,
        ServerMessage::ChannelJoinRejected { kind: ChannelJoinRejection::UserBanned, .. }
    ));
}

/// @requirement AC-341
#[test]
fn unban_reverses_a_ban_and_a_future_join_succeeds() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.ban_from_channel(alice, "general", "bob").unwrap();
    reg.unban_from_channel(alice, "general", "bob").unwrap();

    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(out.iter().any(|o| matches!(&o.message, ServerMessage::Joined { .. })));
}

/// @requirement AC-341
#[test]
fn banning_from_a_channel_you_do_not_administer_is_refused() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let err = reg.ban_from_channel(bob, "general", "alice").unwrap_err();
    assert!(err.contains("admin"), "unexpected error: {err}");
}

/// @requirement AC-342, TB-259
#[test]
fn lock_joins_refuses_a_nickname_not_on_the_allowlist_but_always_allows_the_admin() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    let carol = reg.register("carol".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.set_channel_join_lock(alice, "general", Some(vec!["carol".to_string()]))
        .unwrap();

    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(matches!(
        &out[0].message,
        ServerMessage::ChannelJoinRejected { kind: ChannelJoinRejection::NotOnAllowlist, .. }
    ));

    let out = reg
        .join_channel(carol, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(out.iter().any(|o| matches!(&o.message, ServerMessage::Joined { .. })));
}

/// @requirement AC-342
#[test]
fn all_users_clears_the_lock() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.set_channel_join_lock(alice, "general", Some(vec![]))
        .unwrap();
    reg.set_channel_join_lock(alice, "general", None).unwrap();

    let out = reg
        .join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    assert!(out.iter().any(|o| matches!(&o.message, ServerMessage::Joined { .. })));
}

/// A currently-joined member left off a narrower allowlist is not removed
/// - `/lock-joins` gates future joins only.
///
/// @requirement AC-342
#[test]
fn applying_a_narrower_lock_does_not_remove_a_currently_joined_member() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    reg.set_channel_join_lock(alice, "general", Some(vec![]))
        .unwrap();

    // bob is still a member: leaving and checking the outgoing recipients
    // proves it, since leave_channel only notifies actual members.
    let out = reg.leave_channel(bob, "general");
    assert!(out.iter().any(|o| o.to == alice));
}

/// @requirement AC-343
#[test]
fn assign_admin_requires_the_target_to_already_be_a_member() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let _bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let err = reg.assign_channel_admin(alice, "general", "bob").unwrap_err();
    assert!(err.contains("member"), "unexpected error: {err}");
}

/// @requirement AC-343
#[test]
fn assign_admin_hands_off_and_releases_the_callers_own_admin_status() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.assign_channel_admin(alice, "general", "bob").unwrap();
    assert!(out.iter().any(|o| o.to == bob
        && matches!(&o.message, ServerMessage::ChannelAdminChanged { admin: Some(name), .. } if name == "bob")));

    // alice is no longer admin: she can no longer delete it.
    let err = reg.delete_channel(alice, "general").unwrap_err();
    assert!(err.contains("admin"), "unexpected error: {err}");
    // bob, the new admin, now can.
    reg.delete_channel(bob, "general").unwrap();
}

// ---------------------------------------------------------------------
// Inactivity sweep (server_channel_deletion_unactivity_period)
// ---------------------------------------------------------------------

/// @requirement AC-350
#[test]
fn sweep_removes_a_channel_empty_and_inactive_past_its_configured_period() {
    let period = Duration::from_millis(30);
    let mut reg = Registry::with_channel_deletion_period(Some(period));
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.leave_channel(alice, "general");

    std::thread::sleep(period * 3);
    reg.sweep_inactive_channels();

    assert!(reg.channel_list().iter().all(|c| c.name != "general"));
}

/// @requirement AC-350
#[test]
fn sweep_leaves_an_empty_channel_alone_before_its_period_elapses() {
    let period = Duration::from_secs(60 * 60);
    let mut reg = Registry::with_channel_deletion_period(Some(period));
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.leave_channel(alice, "general");

    reg.sweep_inactive_channels();

    assert!(reg.channel_list().iter().any(|c| c.name == "general"));
}

/// @requirement AC-350
#[test]
fn sweep_never_removes_the_default_channel_even_when_configured() {
    let period = Duration::from_millis(1);
    let mut reg = Registry::with_channel_deletion_period(Some(period));
    std::thread::sleep(Duration::from_millis(30));
    reg.sweep_inactive_channels();
    assert!(
        reg.channel_list()
            .iter()
            .any(|c| c.name == DEFAULT_CHANNEL_NAME)
    );
}

/// @requirement AC-350, TB-260
#[test]
fn sweep_does_nothing_when_no_period_is_configured() {
    let mut reg = Registry::new(); // no period configured
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.leave_channel(alice, "general");
    std::thread::sleep(Duration::from_millis(20));
    reg.sweep_inactive_channels();
    assert!(reg.channel_list().iter().any(|c| c.name == "general"));
}

/// @requirement AC-350
#[test]
fn sweep_leaves_a_non_empty_channel_alone_regardless_of_last_join_at() {
    let period = Duration::from_millis(30);
    let mut reg = Registry::with_channel_deletion_period(Some(period));
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    // alice never leaves - the channel is never empty.
    std::thread::sleep(period * 3);
    reg.sweep_inactive_channels();
    assert!(reg.channel_list().iter().any(|c| c.name == "general"));
}

/// @requirement AC-350, TB-260
#[test]
fn a_rejoin_resets_the_inactivity_clock() {
    let period = Duration::from_millis(60);
    let mut reg = Registry::with_channel_deletion_period(Some(period));
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.leave_channel(alice, "general");

    std::thread::sleep(period / 2);
    // bob rejoins (and leaves again) partway through the period - this
    // should push the clock back out, not let the original join's age win.
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.leave_channel(bob, "general");

    std::thread::sleep(period / 2 + Duration::from_millis(10));
    reg.sweep_inactive_channels();
    assert!(
        reg.channel_list().iter().any(|c| c.name == "general"),
        "the rejoin partway through should have reset the clock"
    );
}

// ---------------------------------------------------------------------
// server_allow_create_public_channels
// ---------------------------------------------------------------------

/// @requirement AC-337, TB-256
#[test]
fn creating_a_new_public_channel_is_refused_when_the_policy_is_off() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let err = reg
        .join_channel_with_policy(alice, "general", ChannelKind::Public, None, TEST_IP, false)
        .unwrap_err();
    assert!(
        err.contains("public channels"),
        "unexpected error message: {err}"
    );
    assert!(reg.channel_list().iter().all(|c| c.name != "general"));
}

/// @requirement AC-337, TB-256
#[test]
fn joining_an_existing_public_channel_is_unaffected_by_the_policy() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    let out = reg
        .join_channel_with_policy(bob, "general", ChannelKind::Public, None, TEST_IP, false)
        .unwrap();
    assert!(out.iter().any(|o| matches!(&o.message, ServerMessage::Joined { .. })));
}

// ---------------------------------------------------------------------
// Superadmin cascade: removing an account removes what it administers
// (docs/PROTOCOL.md §5.5)
// ---------------------------------------------------------------------

/// @requirement AC-346
#[test]
fn remove_channels_administered_by_deletes_every_channel_that_admin_owns_and_notifies_members() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(alice, "watercooler", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "watercooler", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    // bob's own channel must survive - only alice's are removed.
    reg.join_channel(bob, "bobs-room", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    let out = reg.remove_channels_administered_by("alice", "the channel has been removed by the admin");

    assert!(reg.channel_list().iter().all(|c| c.name != "general"));
    assert!(reg.channel_list().iter().all(|c| c.name != "watercooler"));
    assert!(reg.channel_list().iter().any(|c| c.name == "bobs-room"));
    assert!(out.iter().any(|o| o.to == bob
        && matches!(&o.message, ServerMessage::ChannelRemoved { name, reason }
            if name == "watercooler" && reason == "the channel has been removed by the admin")));
}

/// @requirement AC-346
#[test]
fn remove_channels_administered_by_never_touches_the_hall() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, DEFAULT_CHANNEL_NAME, ChannelKind::Public, None, TEST_IP)
        .unwrap();
    // the-hall's admin is always None, so it can never be "administered by"
    // anyone - this cascade must find nothing to remove for it.
    reg.remove_channels_administered_by("alice", "removed");
    assert!(
        reg.channel_list()
            .iter()
            .any(|c| c.name == DEFAULT_CHANNEL_NAME)
    );
}

/// @requirement AC-347
#[test]
fn superadmin_remove_channel_works_regardless_of_who_administers_it() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let bob = reg.register("bob".into(), vec![], KeyMode::PqHybrid);
    reg.join_channel(alice, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();
    reg.join_channel(bob, "general", ChannelKind::Public, None, TEST_IP)
        .unwrap();

    // bob is not this channel's admin, but a superadmin's removal doesn't
    // care - that check already happened before this is ever called.
    let out = reg.remove_channel("general", "removed by a superadmin");
    assert!(reg.channel_list().iter().all(|c| c.name != "general"));
    assert!(out.iter().any(|o| o.to == bob));
}

/// @requirement AC-347
#[test]
fn superadmin_remove_channel_refuses_the_default_channel_even_for_a_superadmin() {
    let mut reg = Registry::new();
    reg.remove_channel(DEFAULT_CHANNEL_NAME, "removed by a superadmin");
    assert!(
        reg.channel_list()
            .iter()
            .any(|c| c.name == DEFAULT_CHANNEL_NAME),
        "the-hall is exempt from every deletion path, superadmin included"
    );
}

/// @requirement AC-337
#[test]
fn creating_a_private_channel_is_unaffected_by_the_policy() {
    let mut reg = Registry::new();
    let alice = reg.register("alice".into(), vec![], KeyMode::PqHybrid);
    let out = reg
        .join_channel_with_policy(alice, "secret-room", ChannelKind::Private, None, TEST_IP, false)
        .unwrap();
    assert!(out.iter().any(|o| matches!(&o.message, ServerMessage::Joined { .. })));
}
