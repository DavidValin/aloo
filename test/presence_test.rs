//! `crate::client::presence` - whether one person can actually be reached
//! right now, and the order the three inputs are resolved in.
//!
//! The rendering that consumes this lives in `ui_channel_test.rs` (the
//! channel sidebar and the top row's DM selector, which must never
//! disagree about the same person).

use aloo::client::p2p::LinkStatus;
use aloo::client::presence::Presence;

/// @requirement AC-228
#[test]
fn presence_follows_the_direct_link_not_mere_membership() {
    assert_eq!(
        Presence::of(false, false, LinkStatus::Active),
        Presence::Reachable
    );
    assert_eq!(
        Presence::of(false, false, LinkStatus::Connecting),
        Presence::Connecting
    );
    assert_eq!(
        Presence::of(false, false, LinkStatus::Lost),
        Presence::Unreachable
    );
}

/// @requirement AC-228
#[test]
fn an_unresolved_identity_outranks_everything_else() {
    // Including a link that is perfectly fine: until the review is
    // answered nothing may be sent to them anyway, so what their link is
    // doing is not the state worth showing.
    for link in [LinkStatus::Active, LinkStatus::Connecting, LinkStatus::Lost] {
        for offline in [false, true] {
            assert_eq!(
                Presence::of(true, offline, link),
                Presence::Unverified,
                "an unverified identity must win over ({offline}, {link:?})"
            );
        }
    }
}

/// @requirement AC-228
#[test]
fn a_closed_connection_outranks_whatever_its_link_was_last_doing() {
    for link in [LinkStatus::Active, LinkStatus::Connecting, LinkStatus::Lost] {
        assert_eq!(Presence::of(false, true, link), Presence::Offline);
    }
}

/// @requirement TB-229
#[test]
fn only_a_live_link_counts_as_reachable() {
    assert!(Presence::Reachable.is_reachable());
    for other in [
        Presence::Unverified,
        Presence::Offline,
        Presence::Connecting,
        Presence::Unreachable,
    ] {
        assert!(
            !other.is_reachable(),
            "{other:?} must not read as reachable"
        );
    }
}
