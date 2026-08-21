//! Whether one person can actually be reached right now.
//!
//! Being connected to the server and being reachable are different
//! questions, and only the second one matters to someone about to type. A
//! peer can be perfectly present in a channel and completely unreachable
//! (no direct link punched yet, or one that has gone), and the whole point
//! of showing presence at all is to make that difference visible - so this
//! is derived from the *direct link* (`docs/PROTOCOL.md` §7.1.4), not from
//! membership.
//!
//! Two things override the link, in this order: an unresolved or rejected
//! identity (§12), which is the one state that needs acting on rather than
//! waiting out, and a connection that has closed entirely - someone kept
//! listed only because there is history worth reaching.
//!
//! Derived here rather than in the widgets so that every place a person is
//! named answers the question the same way: the channel sidebar, and the
//! top row's DM selector.

use crate::client::p2p::LinkStatus;

/// How reachable one person is, most urgent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Their identity has not been resolved, or was rejected (§12).
    /// Messaging them is gated until the review is answered, so nothing
    /// about their link matters yet.
    Unverified,
    /// Their connection closed. They are kept listed only because there is
    /// private-message history with them.
    Offline,
    /// The direct link is up: what is typed now reaches them now.
    Reachable,
    /// The direct link is being established or re-established - a punch in
    /// flight. Anything sent is queued until it opens.
    Connecting,
    /// The direct link is not there. It keeps being retried in the
    /// background; until it comes back, nothing reaches them.
    Unreachable,
}

impl Presence {
    /// The three inputs, resolved in priority order.
    ///
    /// `link` is only consulted once the first two are ruled out: an
    /// unverified peer's link state is not the user's problem to read, and
    /// an offline peer has no link to speak of.
    pub fn of(unverified: bool, offline: bool, link: LinkStatus) -> Self {
        if unverified {
            return Self::Unverified;
        }
        if offline {
            return Self::Offline;
        }
        match link {
            LinkStatus::Active => Self::Reachable,
            LinkStatus::Connecting => Self::Connecting,
            LinkStatus::Lost => Self::Unreachable,
        }
    }

    /// Whether a message typed right now would actually get there.
    pub fn is_reachable(self) -> bool {
        matches!(self, Self::Reachable)
    }
}
