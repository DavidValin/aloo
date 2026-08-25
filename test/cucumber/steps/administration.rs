//! Server superadmin steps (US-052, `docs/PROTOCOL.md` §5.5): account
//! deactivation/activation and the authorization gate every `Admin*`
//! command shares. Drives a real server over loopback TCP, the same way
//! `server.rs`'s own live scenarios do - a superadmin's authority is
//! `require_superadmin`'s own server-side check, not anything the client
//! enforces, so nothing short of the real dispatch path proves it.

use std::collections::BTreeSet;

use cucumber::{given, then, when};
use tokio::net::TcpStream;

use aloo::control::ControlEndpoint;
use aloo::proto::{ClientMessage, ServerMessage};

use crate::steps::server::{expect_message, password_for, scratch_users, spawn_server_with_options};
use crate::world::AlooWorld;

#[given(expr = "a server with {word} as its only superadmin")]
async fn server_with_superadmin(w: &mut AlooWorld, superadmin: String) {
    let users = scratch_users();
    let mut superadmins = BTreeSet::new();
    superadmins.insert(superadmin);
    w.addr = Some(spawn_server_with_options(users.clone(), |o| o.with_superadmins(superadmins)).await);
    w.server_users = Some(users);
}

/// Registers `who` the same way an email-based sign-up would, but leaves
/// the activation code unclaimed - the pending state `/activate` is meant
/// to also be able to clear (docs/PROTOCOL.md §5.5's shared-vocabulary
/// design).
#[given(expr = "{word} has registered but not yet activated her account")]
async fn registered_but_pending(w: &mut AlooWorld, who: String) {
    let users = w.server_users.clone().expect("no server running");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    users
        .register(&who, &password_for(&who), &format!("{who}@example.com"), now)
        .expect("registration should succeed");
}

/// Registered in the live server's own `UsersRegistry` without opening a
/// connection - for scenarios that only need an account to exist and log
/// in *later*, as opposed to `{word} has connected` (`server.rs`), which
/// does both at once.
#[given(expr = "{word} is registered on the server")]
async fn registered_on_the_server(w: &mut AlooWorld, who: String) {
    let users = w.server_users.clone().expect("no server running");
    users.register_manual(&who, &password_for(&who)).unwrap();
}

/// Neither `AdminDeactivate` nor `AdminActivate` acknowledges its sender
/// (`require_superadmin`'s success path has nothing to say back), and each
/// is handled by the admin's own connection task, entirely independent of
/// whatever a later step does on a different connection - so a scenario
/// that checks this action's effect from a *different* connection (a
/// fresh login attempt, not a push read off the target's own socket) has
/// nothing to synchronize on except giving the write time to land first.
/// Exactly the same reasoning, and the same fix, as
/// `server_test.rs::a_superadmins_activate_reverses_a_deactivation`.
async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

#[when(expr = "{word} deactivates {word} with the reason {string}")]
async fn deactivate(w: &mut AlooWorld, admin: String, target: String, reason: String) {
    let client = w.client_mut(&admin);
    let stream = client.stream.as_mut().expect("client has no socket");
    stream
        .send(&ClientMessage::AdminDeactivate {
            nickname: target,
            reason,
        })
        .await
        .unwrap();
    settle().await;
}

#[when(expr = "{word} activates {word}")]
async fn activate(w: &mut AlooWorld, admin: String, target: String) {
    let client = w.client_mut(&admin);
    let stream = client.stream.as_mut().expect("client has no socket");
    stream
        .send(&ClientMessage::AdminActivate { nickname: target })
        .await
        .unwrap();
    settle().await;
}

/// A bare `Hello`/`Auth` - deliberately not the full `handshake` helper
/// `server.rs` uses elsewhere, since a deactivated attempt is refused
/// before there is anything to `Identify`.
#[when(expr = "{word} attempts to log in with her password")]
async fn attempt_login(w: &mut AlooWorld, who: String) {
    let addr = w.addr.expect("no server running");
    let mut stream = ControlEndpoint::new(TcpStream::connect(addr).await.unwrap());
    stream
        .client_handshake()
        .await
        .unwrap()
        .expect("server closed during handshake");
    stream
        .send(&ClientMessage::Auth {
            nickname: who.clone(),
            password: password_for(&who),
        })
        .await
        .unwrap();
    let result: ServerMessage = stream.recv().await.unwrap().unwrap();
    w.last_auth_result = Some(result);
}

#[then("the login succeeds")]
async fn login_succeeds(w: &mut AlooWorld) {
    let result = w.last_auth_result.take().expect("no login was attempted");
    assert!(
        matches!(result, ServerMessage::AuthResult { ok: true, .. }),
        "expected the login to succeed: {result:?}"
    );
}

#[then(expr = "the login is refused, citing {string}")]
async fn login_refused_citing(w: &mut AlooWorld, reason: String) {
    let result = w.last_auth_result.take().expect("no login was attempted");
    assert_eq!(
        result,
        ServerMessage::AuthResult {
            ok: false,
            activation_pending: false,
            deactivated: Some(reason),
            reason: None,
        }
    );
}

#[then(expr = "{word} is told the command is not allowed")]
async fn told_not_allowed(w: &mut AlooWorld, who: String) {
    let msg = expect_message(w, &who).await;
    assert!(
        matches!(&msg, ServerMessage::Error { message } if message.contains("superadmin")),
        "expected a superadmin-only refusal, got {msg:?}"
    );
}

#[then(expr = "{word} is told their account has been deactivated, citing {string}")]
async fn told_deactivated_live(w: &mut AlooWorld, who: String, reason: String) {
    let msg = expect_message(w, &who).await;
    assert_eq!(msg, ServerMessage::AccountDeactivated { reason });
}
