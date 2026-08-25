#[path = "server_common.rs"]
mod server_common;

use aloo::proto::*;
use aloo::server::Registry;
use server_common::{TestServer, login, password_for, test_options, test_users_registry};

// ---------------------------------------------------------------------
// Registry: pure logic, no sockets (channel-specific tests moved to
// server_channels_registry_test.rs)
// ---------------------------------------------------------------------

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
            deactivated: None,
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
        deactivated: None,
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
        deactivated: None,
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
            deactivated: None,
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
        matches!(refused, ServerMessage::AuthResult { ok: false, activation_pending: false, deactivated: None, reason: Some(ref r) } if r.contains("wrong")),
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
            deactivated: None,
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

// ---------------------------------------------------------------------
// Superadmins (docs/PROTOCOL.md §5.5): Admin* messages, end to end
// ---------------------------------------------------------------------

/// @requirement AC-344, AC-348, TB-262
#[tokio::test]
async fn a_non_superadmin_admin_deactivate_is_refused_and_changes_nothing() {
    let mut options = test_options("admin-not-superadmin");
    options.superadmins.insert("alice".to_string());
    let server = TestServer::spawn(options).await;

    let mut a = server.connect().await; // alice IS the superadmin here
    server.handshake(&mut a, "alice").await;
    let mut b = server.connect().await; // mallory is not
    server.handshake(&mut b, "mallory").await;
    server.ensure_user("eve");

    b.send(&ClientMessage::AdminDeactivate {
        nickname: "eve".into(),
        reason: "not really an admin".into(),
    })
    .await
    .unwrap();
    let err: ServerMessage = b.recv().await.unwrap().unwrap();
    assert!(
        matches!(&err, ServerMessage::Error { message } if message.contains("superadmin")),
        "expected a superadmin-only refusal, got {err:?}"
    );

    // eve's account is completely unaffected.
    let mut c = server.connect().await;
    let result = login(&mut c, "eve", &password_for("eve")).await;
    assert!(matches!(result, ServerMessage::AuthResult { ok: true, .. }));
}

/// @requirement AC-344
#[tokio::test]
async fn a_superadmins_deactivate_blocks_the_next_login_with_the_reason() {
    let mut options = test_options("admin-deactivate-login");
    options.superadmins.insert("alice".to_string());
    let server = TestServer::spawn(options).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    server.ensure_user("eve");

    a.send(&ClientMessage::AdminDeactivate {
        nickname: "eve".into(),
        reason: "spamming".into(),
    })
    .await
    .unwrap();

    let mut b = server.connect().await;
    let result = login(&mut b, "eve", &password_for("eve")).await;
    assert_eq!(
        result,
        ServerMessage::AuthResult {
            ok: false,
            activation_pending: false,
            deactivated: Some("spamming".to_string()),
            reason: None,
        }
    );
}

/// @requirement AC-345
#[tokio::test]
async fn a_superadmins_deactivate_notifies_a_currently_connected_target_live() {
    let mut options = test_options("admin-deactivate-live");
    options.superadmins.insert("alice".to_string());
    let server = TestServer::spawn(options).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    let mut eve = server.connect().await;
    server.handshake(&mut eve, "eve").await;

    a.send(&ClientMessage::AdminDeactivate {
        nickname: "eve".into(),
        reason: "spamming".into(),
    })
    .await
    .unwrap();

    let pushed: ServerMessage = eve.recv().await.unwrap().unwrap();
    assert_eq!(
        pushed,
        ServerMessage::AccountDeactivated { reason: "spamming".to_string() }
    );
}

/// @requirement AC-344
#[tokio::test]
async fn a_superadmins_activate_reverses_a_deactivation() {
    let mut options = test_options("admin-activate");
    options.superadmins.insert("alice".to_string());
    let server = TestServer::spawn(options).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    server.ensure_user("eve");

    // Neither `AdminDeactivate` nor `AdminActivate` acknowledges the
    // sender (§5.5 - `require_superadmin`'s success path has nothing to
    // say back), and each is handled by connection `a`'s own task,
    // entirely independent of the brand-new connection `b` opens right
    // after - so, unlike the other superadmin tests above (which confirm
    // each command's effect by reading its own *consequence* off a
    // connection the command itself pushes to), there is nothing here to
    // synchronize on except giving both writes - each a blocking
    // filesystem call - time to actually land before `b` races them.
    a.send(&ClientMessage::AdminDeactivate {
        nickname: "eve".into(),
        reason: "spamming".into(),
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    a.send(&ClientMessage::AdminActivate { nickname: "eve".into() })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut b = server.connect().await;
    let result = login(&mut b, "eve", &password_for("eve")).await;
    assert!(matches!(result, ServerMessage::AuthResult { ok: true, .. }));
}

/// @requirement AC-346
#[tokio::test]
async fn a_superadmins_remove_account_cascades_into_channels_it_administers() {
    let mut options = test_options("admin-remove-account");
    options.superadmins.insert("alice".to_string());
    let server = TestServer::spawn(options).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    let mut eve = server.connect().await;
    server.handshake(&mut eve, "eve").await;
    let mut bob = server.connect().await;
    server.handshake(&mut bob, "bob").await;

    eve.send(&ClientMessage::JoinChannel {
        name: "eves-room".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let _: ServerMessage = eve.recv().await.unwrap().unwrap(); // Joined
    bob.send(&ClientMessage::JoinChannel {
        name: "eves-room".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let _: ServerMessage = bob.recv().await.unwrap().unwrap(); // snapshot/Joined may span two

    a.send(&ClientMessage::AdminRemoveAccount { nickname: "eve".into() })
        .await
        .unwrap();

    // bob, still connected, is told the channel is gone.
    let mut saw_removal = false;
    for _ in 0..4 {
        let Ok(Some(msg)) = tokio::time::timeout(std::time::Duration::from_secs(2), bob.recv())
            .await
            .unwrap_or(Ok(None))
        else {
            break;
        };
        if matches!(&msg, ServerMessage::ChannelRemoved { name, .. } if name == "eves-room") {
            saw_removal = true;
            break;
        }
    }
    assert!(saw_removal, "bob should be told eves-room was removed");

    // eve's account is gone entirely - even her own former password fails.
    let mut c = server.connect().await;
    let result = login(&mut c, "eve", &password_for("eve")).await;
    assert!(matches!(result, ServerMessage::AuthResult { ok: false, .. }));
}

/// @requirement AC-347
#[tokio::test]
async fn a_superadmins_remove_channel_works_on_any_public_channel() {
    let mut options = test_options("admin-remove-channel");
    options.superadmins.insert("alice".to_string());
    let server = TestServer::spawn(options).await;

    let mut a = server.connect().await;
    server.handshake(&mut a, "alice").await;
    let mut bob = server.connect().await;
    server.handshake(&mut bob, "bob").await;

    bob.send(&ClientMessage::JoinChannel {
        name: "bobs-room".into(),
        kind: ChannelKind::Public,
        password: None,
    })
    .await
    .unwrap();
    let _: ServerMessage = bob.recv().await.unwrap().unwrap();

    a.send(&ClientMessage::AdminRemoveChannel { name: "bobs-room".into() })
        .await
        .unwrap();

    let msg: ServerMessage = bob.recv().await.unwrap().unwrap();
    assert!(matches!(&msg, ServerMessage::ChannelRemoved { name, .. } if name == "bobs-room"));
}
