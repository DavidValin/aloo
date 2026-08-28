//! The transient things the screen says, and the questions still waiting
//! for an answer.
//!
//! Two kinds, kept together because they share a rule: a status notice is
//! a line the app shows and then forgets, and a review queue is a
//! decision it must not forget until the user makes it. Both are
//! "something on screen that is not the conversation", and both are
//! cleared from exactly one place each.

use std::time::Instant;

use crate::proto::UserId;

use super::ui::*;
use super::widgets::confirm_popup::Confirm;

impl UiState {
    /// Records a newly-detected identity mismatch for `peer` and, if no
    /// review is currently on screen, opens this one immediately (auto-pop
    /// on detection). If `peer` already had a review pending or rejected
    /// (e.g. another mismatched rotation attempt arrives before the first
    /// was decided), its case/message are updated in place and it's
    /// re-queued as `Pending` rather than duplicated - always reflects the
    /// *latest* attempt.
    pub fn push_identity_review(
        &mut self,
        peer: UserId,
        nickname: String,
        message: String,
        case: IdentityCase,
    ) {
        let already_queued = self.identity_review_queue.contains(&peer);
        self.identity_reviews.insert(
            peer,
            IdentityReview {
                nickname,
                message,
                case,
                status: IdentityStatus::Pending,
            },
        );
        if !already_queued {
            self.identity_review_queue.push_back(peer);
        }
        if self.identity_review_queue.front() == Some(&peer) {
            self.identity_review_focus = Confirm::No;
        }
    }

    /// Starts a mismatch review the instant it's detected, without
    /// showing anything yet (`session::check_identity`'s mismatch arm) -
    /// gates messaging with `peer` immediately (`is_trust_gated`), same as
    /// `push_identity_review` does, but leaves the popup itself for
    /// `reveal_identity_review` once this connection's address/device id
    /// are known (docs/PROTOCOL.md §12.7). Never queued: `identity_review_open`
    /// only ever shows the queue front, and this is deliberately kept out
    /// of it until revealed.
    pub fn begin_identity_review(&mut self, peer: UserId, nickname: String, case: IdentityCase) {
        self.identity_reviews.insert(
            peer,
            IdentityReview {
                nickname,
                message: String::new(),
                case,
                status: IdentityStatus::AwaitingPeerInfo,
            },
        );
    }

    /// Finishes a review `begin_identity_review` started, once its caller
    /// has a `message` worth showing (old vs. new address/device id
    /// filled in) - moves it to `Pending`, queues it, and chimes exactly
    /// as `push_identity_review` would have. Returns whether there was
    /// actually an `AwaitingPeerInfo` review to reveal (`false` if `peer`
    /// has no review, or it was already revealed/resolved) - a caller
    /// only plays the chime on `true`, so this never re-alerts on a
    /// second, later transition for the same peer.
    pub fn reveal_identity_review(&mut self, peer: UserId, message: String) -> bool {
        match self.identity_reviews.get_mut(&peer) {
            Some(review) if review.status == IdentityStatus::AwaitingPeerInfo => {
                review.message = message;
                review.status = IdentityStatus::Pending;
            }
            _ => return false,
        }
        if !self.identity_review_queue.contains(&peer) {
            self.identity_review_queue.push_back(peer);
        }
        if self.identity_review_queue.front() == Some(&peer) {
            self.identity_review_focus = Confirm::No;
        }
        true
    }

    /// The review currently shown in the popup, if any.
    pub fn identity_review_open(&self) -> Option<&IdentityReview> {
        let peer = self.identity_review_queue.front()?;
        self.identity_reviews.get(peer)
    }

    /// Whether `peer` currently has an unresolved-trust review (`Pending`
    /// or `Rejected` - both gate messaging identically, see `docs/PROTOCOL.md`
    /// §12). Absence (`None`/normal peer) is the common case.
    pub fn is_trust_gated(&self, peer: UserId) -> bool {
        self.identity_reviews.contains_key(&peer)
    }

    /// Opens a review for a `direct_punch_to` nickname with no pinned key
    /// that just sent proof of an identity (`docs/PROTOCOL.md` §7.1.5) -
    /// called from `session::on_channel_presence`/`client::otp::on_message`
    /// the moment that gap is detected. Refuses a second review for a
    /// `peer` that already has one outstanding: a retried proof arriving
    /// while the first popup is still up is simply dropped, the same
    /// "silently drop" convention already used everywhere on this path.
    /// Returns whether it was actually queued.
    pub fn push_unknown_peer_review(
        &mut self,
        peer: UserId,
        requested_nickname: String,
        proof: UnverifiedDirectProof,
        source_addr: std::net::SocketAddr,
    ) -> bool {
        if self.unknown_peer_reviews.contains_key(&peer) {
            return false;
        }
        self.unknown_peer_reviews.insert(
            peer,
            UnknownPeerReview {
                requested_nickname,
                stage: UnknownPeerStage::Initial,
                proof,
                source_addr,
            },
        );
        self.unknown_peer_review_queue.push_back(peer);
        if self.unknown_peer_review_queue.front() == Some(&peer) {
            self.unknown_peer_review_focus = Confirm::No;
        }
        true
    }

    /// The review currently shown in the popup, if any.
    pub fn unknown_peer_review_open(&self) -> Option<&UnknownPeerReview> {
        let peer = self.unknown_peer_review_queue.front()?;
        self.unknown_peer_reviews.get(peer)
    }

    /// Moves a review from `Initial` to `ConfirmMatch` in place - same
    /// queue position, so it stays exactly where it was rather than being
    /// re-queued behind anything that arrived in the meantime.
    pub fn advance_to_confirm_match(
        &mut self,
        peer: UserId,
        matched_nickname: String,
        matched_key_der: Vec<u8>,
        recovered: RecoveredProof,
    ) {
        if let Some(review) = self.unknown_peer_reviews.get_mut(&peer) {
            review.stage = UnknownPeerStage::ConfirmMatch {
                matched_nickname,
                matched_key_der,
                recovered,
            };
            self.unknown_peer_review_focus = Confirm::No;
        }
    }

    /// Removes a review on every terminal outcome: declining either popup,
    /// confirming a match, or a completed scan finding nothing to offer.
    pub fn resolve_unknown_peer_review(&mut self, peer: UserId) {
        self.unknown_peer_reviews.remove(&peer);
        self.unknown_peer_review_queue.retain(|&p| p != peer);
    }

    /// Removes `peer` from the review queue wherever it is - not
    /// necessarily the front - resetting focus if the popup on screen
    /// changed. Removing by identity rather than a plain `pop_front` keeps
    /// this correct even if a future resolution path ever resolves
    /// something other than the front entry.
    pub(crate) fn remove_from_identity_review_queue(&mut self, peer: UserId) {
        let was_front = self.identity_review_queue.front() == Some(&peer);
        self.identity_review_queue.retain(|p| *p != peer);
        if was_front {
            self.identity_review_focus = Confirm::No;
        }
    }

    /// Applies a Reject decision: flips `peer`'s review to `Rejected` (kept,
    /// not removed - stays red, re-openable via Enter) and opens the next
    /// queued review if any. Held messages stay held.
    pub fn resolve_identity_reject(&mut self, peer: UserId) {
        if let Some(review) = self.identity_reviews.get_mut(&peer) {
            review.status = IdentityStatus::Rejected;
        }
        self.remove_from_identity_review_queue(peer);
    }

    /// Re-opens the popup for an already-`Rejected` peer (Enter on their
    /// red sidebar entry) - a no-op if they're not actually in review,
    /// already the one showing, or still `AwaitingPeerInfo` (there is
    /// nothing to show yet; `is_trust_gated` already blocks messaging with
    /// them in the meantime, and `reveal_identity_review` is what will
    /// actually open this once it has something to display).
    pub(crate) fn reopen_identity_review(&mut self, peer: UserId) {
        match self.identity_reviews.get(&peer) {
            Some(review) if review.status != IdentityStatus::AwaitingPeerInfo => {}
            _ => return,
        }
        if self.identity_review_queue.front() == Some(&peer) {
            return;
        }
        self.identity_review_queue.retain(|p| *p != peer);
        self.identity_review_queue.push_front(peer);
        self.identity_review_focus = Confirm::No;
    }

    /// Sets the always-visible OTP/command status line - see
    /// `status_notice`'s field doc for why this is a separate, actually-
    /// rendered surface rather than reusing `audio_error`/`push_notice`.
    pub fn push_status_notice(&mut self, message: String, success: bool) {
        self.status_notice = Some((message, success));
        self.status_notice_since = Some(Instant::now());
    }

    /// Clears a status notice that has been showing for
    /// `STATUS_NOTICE_TIMEOUT` - called from the session's ticker, the
    /// same cadence `tick_recording_timeout` rides. A notice whose
    /// timestamp is missing (set by writing the pub field directly, as
    /// tests do) is adopted from `now` rather than left immortal.
    pub fn tick_status_notice(&mut self, now: Instant) {
        if self.status_notice.is_none() {
            self.status_notice_since = None;
            return;
        }
        match self.status_notice_since {
            Some(since) if now.duration_since(since) >= STATUS_NOTICE_TIMEOUT => {
                self.status_notice = None;
                self.status_notice_since = None;
            }
            None => self.status_notice_since = Some(now),
            _ => {}
        }
    }

    /// The help overlay's current scroll offset (first visible line index
    /// into the overlay's laid-out lines) - loosely clamped here, precisely at render time
    /// against the popup's actual visible height (`render_help_popup`).
    pub fn help_scroll(&self) -> usize {
        self.help_scroll
    }
}
