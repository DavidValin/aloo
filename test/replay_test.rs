//! Tests for `client::replay` - refusing a send that already arrived once
//! (`docs/PROTOCOL.md`, US-027).

use aloo::client::replay::ReplayGuard;
use aloo::proto::UserId;

/// @requirement AC-114
#[test]
fn a_repeated_send_id_is_refused() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);

    assert!(guard.accept(alice, 1), "a first arrival is never a replay");
    assert!(
        !guard.accept(alice, 1),
        "the very same send arriving again must be refused"
    );
}

/// @requirement AC-114
#[test]
fn an_older_send_id_is_refused() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);

    assert!(guard.accept(alice, 5));
    assert!(
        !guard.accept(alice, 4),
        "anything at or below what was already accepted is a replay"
    );
    assert!(!guard.accept(alice, 5));
}

/// Gaps are ordinary: the counter is per connection, so a channel message
/// addressed to somebody else consumes a value this peer never sees.
/// @requirement AC-114
#[test]
fn a_gap_in_send_ids_is_accepted() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);

    assert!(guard.accept(alice, 1));
    assert!(
        guard.accept(alice, 9),
        "a gap means sends to other people, not a replay"
    );
    assert_eq!(guard.highest(alice), Some(9));
}

/// @requirement AC-114
#[test]
fn each_peer_is_tracked_independently() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);
    let bob = UserId(2);

    assert!(guard.accept(alice, 7));
    assert!(
        guard.accept(bob, 1),
        "bob's own counter starts wherever bob's connection started"
    );
    assert_eq!(guard.highest(alice), Some(7));
    assert_eq!(guard.highest(bob), Some(1));
}

/// A peer who reconnects gets a fresh `UserId` and starts counting again,
/// so nothing may be inherited from the connection that ended.
/// @requirement AC-114
#[test]
fn forgetting_a_peer_lets_a_new_connection_start_over() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);

    assert!(guard.accept(alice, 42));
    guard.forget(alice);

    assert_eq!(guard.highest(alice), None);
    assert!(
        guard.accept(alice, 1),
        "a reconnection starts its counter over and must not read as a replay"
    );
}
