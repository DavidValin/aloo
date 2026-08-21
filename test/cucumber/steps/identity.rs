//! Freshness/queueing for a rotating peer, and identity pinning
//! (US-010, US-011).

use crossterm::event::{KeyCode, KeyModifiers};
use cucumber::{given, then, when};

use aloo::client::idstore::{IdCheck, IdStore};
use aloo::proto::UserId;
use aloo::client::rekey::{QueuedOutbound, RemoteKeys};
use aloo::client::tui::ui::{IdentityCase, MessageBody, UiAction};

use crate::steps::ui_common::{id_for, press_key};
use crate::support::ui_rows;
use crate::world::AlooWorld;

// ---------------------------------------------------------------------
// Queueing while waiting for a fresh key (US-010)
// ---------------------------------------------------------------------

#[given("bob uses a rotating key and I have already used his current key")]
async fn bob_key_used(w: &mut AlooWorld) {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(2));
    assert!(
        remote.try_use(UserId(2)),
        "his bootstrap key should be good for exactly one message"
    );
    assert!(!remote.try_use(UserId(2)), "and stale immediately after");
    w.remote_keys = Some(remote);
}

#[when(expr = "I type {string} and then {string} to him")]
async fn queue_two(w: &mut AlooWorld, first: String, second: String) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    remote.enqueue(
        UserId(2),
        QueuedOutbound::Direct {
            plaintext: first,
            msg_id: 1,
            log_index: Some(0),
            attempts: 0,
        },
    );
    remote.enqueue(
        UserId(2),
        QueuedOutbound::Channel {
            channel: "general".into(),
            plaintext: second,
            msg_id: 2,
            attempts: 0,
        },
    );
}

#[then(expr = "both messages are held, not sent")]
async fn both_held(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_ref().expect("no rotation state");
    assert_eq!(
        remote.queue_len(UserId(2)),
        2,
        "both should be waiting for his next key"
    );
}

#[when("bob's next key arrives")]
async fn bob_key_arrives(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    let (flushed, given_up) = remote.on_rotated(UserId(2));
    w.flushed = flushed;
    w.given_up = given_up;
    remote.mark_used(UserId(2));
}

#[then(expr = "they go out together, {string} before {string}")]
async fn flushed_in_order(w: &mut AlooWorld, first: String, second: String) {
    assert_eq!(
        w.flushed,
        vec![
            QueuedOutbound::Direct {
                plaintext: first,
                msg_id: 1,
                log_index: Some(0),
                // Handing an item out for sending is what spends an
                // attempt (`RemoteKeys::on_rotated`).
                attempts: 1,
            },
            QueuedOutbound::Channel {
                channel: "general".into(),
                plaintext: second,
                msg_id: 2,
                attempts: 1,
            },
        ],
        "the whole queue flushes at once, in the order it was typed"
    );
    let remote = w.remote_keys.as_ref().expect("no rotation state");
    assert_eq!(
        remote.queue_len(UserId(2)),
        0,
        "the queue must be drained, not merely read"
    );
}

#[then("his key is stale again until the next rotation")]
async fn stale_again(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    assert!(
        !remote.try_use(UserId(2)),
        "flushing a batch consumes freshness like any other send"
    );
}

// ---------------------------------------------------------------------
// Identity pinning (US-011)
// ---------------------------------------------------------------------

#[given("a local identity store with nothing pinned yet")]
async fn empty_store(w: &mut AlooWorld) {
    let path = w.temp_path("idstore");
    w.id_store = Some(IdStore::load(&path).expect("a missing store file must not be an error"));
}

#[when(expr = "{word} is seen with the key {string}")]
async fn seen_with_key(w: &mut AlooWorld, name: String, key: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    w.id_check = Some(store.check_and_pin(&name, key.as_bytes()));
}

#[then("it is a first sighting")]
async fn first_sighting(w: &mut AlooWorld) {
    assert_eq!(
        w.id_check,
        Some(IdCheck::New),
        "a nickname never seen before is simply pinned"
    );
}

#[then("it matches what was pinned")]
async fn pin_matches(w: &mut AlooWorld) {
    assert_eq!(
        w.id_check,
        Some(IdCheck::Match),
        "the same key as last time is not a warning"
    );
}

#[then(expr = "it is flagged as a mismatch against the previous key {string}")]
async fn pin_mismatch(w: &mut AlooWorld, previous: String) {
    assert_eq!(
        w.id_check,
        Some(IdCheck::Mismatch {
            previous_public_key_der: previous.into_bytes()
        }),
        "a different key must be reported, carrying the key it replaced"
    );
}

#[then(expr = "{word} is now pinned to the new key")]
async fn repinned(w: &mut AlooWorld, name: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    assert_eq!(
        store.check_and_pin(&name, b"key-b"),
        IdCheck::Match,
        "a mismatch re-pins regardless - the warning is a one-time signal, not a lasting block"
    );
}

// ---------------------------------------------------------------------
// Identity review popup: manual Accept/Reject (US-011, US-017)
// ---------------------------------------------------------------------

/// Simulates `session::check_identity` detecting a static (`password`/
/// `pq_hybrid`) key mismatch for an already-present channel member and opening a review
/// for it - the same `IdentityCase::StaticMismatch` the real check builds,
/// just with placeholder key bytes since these scenarios only care about
/// the UI consequences, not the byte comparison itself (covered separately
/// by the `IdStore` scenarios above).
#[when(expr = "{word}'s identity mismatches")]
async fn identity_mismatches(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let message = format!(
        "'{name}' connected with a different key than last time (was aaaaaaaaaaaaaaaa, now bbbbbbbbbbbbbbbb) - possible impersonation. Accept their new key, or reject it."
    );
    let case = IdentityCase::StaticMismatch {
        new_public_key_der: b"new-key".to_vec(),
        previous_public_key_der: b"old-key".to_vec(),
    };
    w.ui_mut().push_identity_review(id, name, message, case);
}

/// Simulates `session::check_identity`'s mismatch arm calling
/// `begin_identity_review` instead of `push_identity_review` -
/// (docs/PROTOCOL.md §12.7): the review exists and gates messaging, but
/// nothing is shown yet, mirroring the real gap between detecting a
/// mismatch and the P2P handshake delivering this connection's own
/// address/device id.
#[when(expr = "{word}'s identity mismatches but the new connection is not yet known")]
async fn identity_mismatches_pending(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let case = IdentityCase::StaticMismatch {
        new_public_key_der: b"new-key".to_vec(),
        previous_public_key_der: b"old-key".to_vec(),
    };
    w.ui_mut().begin_identity_review(id, name, case);
}

/// Simulates `session::reveal_pending_identity_review` finishing what
/// `identity_mismatches_pending` started, once this connection's
/// address/device id are known.
#[when(expr = "{word}'s new connection becomes known")]
async fn identity_review_revealed(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let message = format!(
        "'{name}' connected with a different key than last time (was aaaaaaaaaaaaaaaa, now bbbbbbbbbbbbbbbb) - possible impersonation.\nLast known from 203.0.113.1:4000 (device old-device).\nNow connecting from 203.0.113.2:4000 (device new-device).\nAccept their new key, or reject it."
    );
    assert!(
        w.ui_mut().reveal_identity_review(id, message),
        "expected a pending AwaitingPeerInfo review for {name} to reveal"
    );
}

/// A channel message from a peer whose review is still unresolved - held
/// rather than shown (docs/PROTOCOL.md §12 "hold and reveal").
#[when(expr = "{word} sends the channel message {string} while unresolved")]
async fn sends_while_unresolved(w: &mut AlooWorld, name: String, body: String) {
    let id = UserId(id_for(&name));
    w.ui_mut()
        .on_channel_message("general", id, name, MessageBody::Text(body));
}

#[then(expr = "the message {string} is not shown yet")]
async fn message_not_shown(w: &mut AlooWorld, body: String) {
    let log = &w.ui_ref().channels[0].log;
    assert!(
        !log.iter()
            .any(|e| e.body == MessageBody::Text(body.clone())),
        "a held message must not be in the visible log yet"
    );
}

#[then(expr = "the message {string} now appears in the channel")]
async fn message_now_shown(w: &mut AlooWorld, body: String) {
    let log = &w.ui_ref().channels[0].log;
    assert!(
        log.iter()
            .any(|e| e.body == MessageBody::Text(body.clone())),
        "the held message must be revealed once its sender is accepted: {log:?}"
    );
}

/// Confirms Accept in the review popup - `Left`/`Right`/`Tab` toggle focus
/// off the default, safer `Reject`, then `Enter` confirms. The popup itself
/// only returns the `UiAction`; applying its actual trust effect
/// (`resolve_identity_accept`) is normally `session::handle_ui_action`'s job
/// - simulated directly here the same way other identity-pinning scenarios
/// above bypass the network layer entirely.
#[when("I accept the review")]
async fn accept_review(w: &mut AlooWorld) {
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    match w.last_action {
        Some(UiAction::AcceptIdentity(peer)) => {
            w.ui_mut().resolve_identity_accept(peer);
        }
        ref other => panic!("expected AcceptIdentity, got {other:?}"),
    }
}

/// Confirms Reject - `Enter` alone, since `Reject` is the default focus.
#[when("I reject the review")]
async fn reject_review(w: &mut AlooWorld) {
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    match w.last_action {
        Some(UiAction::RejectIdentity(peer)) => w.ui_mut().resolve_identity_reject(peer),
        ref other => panic!("expected RejectIdentity, got {other:?}"),
    }
}

#[then(expr = "a review popup names {word} with Accept and Reject buttons")]
async fn review_names(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.ui_ref()
            .identity_review_open()
            .map(|r| r.nickname.as_str()),
        Some(name.as_str()),
        "expected the popup to be showing {name}'s review"
    );
    let rows = ui_rows(w.ui_ref());
    assert!(
        rows.iter()
            .any(|r| r.contains(&format!("Identity review: {name}"))),
        "expected a titled popup: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("Accept")),
        "expected an Accept button: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.contains("Reject")),
        "expected a Reject button: {rows:?}"
    );
}

#[then("no review popup is shown")]
async fn no_review_popup(w: &mut AlooWorld) {
    assert!(
        w.ui_ref().identity_review_open().is_none(),
        "no review should be open"
    );
}

#[then(expr = "{word} is no longer flagged")]
async fn no_longer_flagged(w: &mut AlooWorld, name: String) {
    assert!(
        !w.ui_ref().is_trust_gated(UserId(id_for(&name))),
        "{name} should be trusted again after being accepted"
    );
}

#[then(expr = "{word} is still flagged as unverified")]
async fn still_flagged(w: &mut AlooWorld, name: String) {
    assert!(
        w.ui_ref().is_trust_gated(UserId(id_for(&name))),
        "{name} should still be untrusted after a reject"
    );
}

// "no private room is open" is already defined in `channels.rs` - reused
// as-is here (selecting an unverified peer must not open their room,
// exactly the same assertion as switching tabs closing one).

#[then(expr = "the outgoing channel message excludes {word} but includes {word}")]
async fn send_excludes(w: &mut AlooWorld, excluded: String, included: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendChannelText { recipients, .. } => {
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert!(
                !ids.contains(&UserId(id_for(&excluded))),
                "{excluded} is unverified and must be excluded"
            );
            assert!(
                ids.contains(&UserId(id_for(&included))),
                "{included} should still receive the message"
            );
        }
        other => panic!("expected SendChannelText, got {other:?}"),
    }
}


// ---------------------------------------------------------------------
// A queue is a wait, not a life sentence (AC-234)
// ---------------------------------------------------------------------

#[when("every rotation hands them back but none of them can be sent")]
async fn rotations_never_help(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    for _ in 0..aloo::client::rekey::MAX_QUEUED_SEND_ATTEMPTS {
        let (flushed, given_up) = remote.on_rotated(UserId(2));
        assert!(given_up.is_empty(), "still within their budget");
        for item in flushed {
            remote.requeue(UserId(2), item);
        }
    }
    let (flushed, given_up) = remote.on_rotated(UserId(2));
    w.flushed = flushed;
    w.given_up = given_up;
}

#[then("both are given up on rather than held forever")]
async fn both_given_up(w: &mut AlooWorld) {
    assert_eq!(w.given_up.len(), 2, "both ran out of attempts");
    assert!(
        w.flushed.is_empty(),
        "neither is handed out to be tried again"
    );
    let remote = w.remote_keys.as_ref().expect("no rotation state");
    assert_eq!(
        remote.queue_len(UserId(2)),
        0,
        "and neither is left waiting on a key that never came"
    );
}

#[then("each names the row it was shown on, so it can be marked failed")]
async fn each_names_its_row(w: &mut AlooWorld) {
    let ids: Vec<u64> = w.given_up.iter().map(|i| i.msg_id()).collect();
    assert_eq!(
        ids,
        vec![1, 2],
        "the rows are named in the order they were typed"
    );
}
