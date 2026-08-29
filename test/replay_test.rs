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

/// The straggler a durable queue produces: sealed early, delivered after
/// ids above it. It is not a replay and must not be read as one.
/// @requirement AC-114
#[test]
fn a_send_that_arrives_out_of_order_is_still_accepted() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);

    assert!(guard.accept(alice, 5));
    assert!(
        guard.accept(alice, 4),
        "an earlier id nobody has used yet is a late arrival, not a replay"
    );
    assert!(!guard.accept(alice, 4), "but only once");
    assert!(!guard.accept(alice, 5));
    assert_eq!(
        guard.highest(alice),
        Some(5),
        "arriving late does not move the window backwards"
    );
}

/// The window is what bounds the memory, so there is a distance beyond
/// which a straggler is refused rather than risked.
/// @requirement AC-114
#[test]
fn a_send_that_has_fallen_out_of_the_window_is_refused() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);

    assert!(guard.accept(alice, 1));
    assert!(guard.accept(alice, aloo::client::replay::WINDOW + 1));
    assert!(
        !guard.accept(alice, 1),
        "exactly WINDOW behind the newest is out"
    );
    assert!(
        guard.accept(alice, 2),
        "and one place nearer is still in"
    );
}

/// Advancing must not let a straggler inherit the bit of the id that
/// previously occupied its slot in the bitmap.
/// @requirement AC-114
#[test]
fn advancing_the_window_frees_the_slots_it_moves_onto() {
    let mut guard = ReplayGuard::new();
    let alice = UserId(1);
    let window = aloo::client::replay::WINDOW;

    assert!(guard.accept(alice, 3));
    assert!(guard.accept(alice, window + 4), "a full lap of the bitmap");
    assert!(
        guard.accept(alice, window + 3),
        "the slot 3 used to hold must have been freed on the way past"
    );
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
