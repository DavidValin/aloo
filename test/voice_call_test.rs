//! The parts of live voice calls (`src/client/voice_call.rs`) that can be
//! exercised without a live session and a real microphone. The rest of
//! that module - the roster convergence, the audio workers, the host's
//! mute/invite fan-out - takes a live `SessionState`/`ControlSink` and an
//! audio device; see docs/TESTING.md's "Known coverage gaps".

use aloo::client::voice_call::PendingCallSetups;
use aloo::proto::UserId;

/// A `pq_hybrid` participant sends its one `StreamKeySetup` the instant it
/// adds us, which is routinely *before* its own `CallAccept` has reached
/// us and let us add it. Holding that setup until the participant joins
/// our roster - rather than dropping it, as the first implementation did -
/// is what keeps a fresh call from being audible in one direction only.
///
/// @requirement TB-209
#[test]
fn a_call_key_setup_arriving_before_the_participant_is_replayed_once_they_join() {
    let mut pending = PendingCallSetups::default();
    assert!(pending.is_empty());
    assert_eq!(pending.take(UserId(2)), None, "nothing held yet");

    pending.hold(UserId(2), vec![1, 2, 3]);
    pending.hold(UserId(3), vec![9]);
    assert_eq!(pending.len(), 2);

    // Each peer's setup is replayed to that peer alone, and exactly once:
    // a second delivery would re-install a key the worker already has.
    assert_eq!(pending.take(UserId(2)), Some(vec![1, 2, 3]));
    assert_eq!(pending.take(UserId(2)), None);
    assert_eq!(pending.take(UserId(3)), Some(vec![9]));
    assert!(pending.is_empty());
}

/// A stream has exactly one setup, so a second arrival before the peer
/// joins can only be a fresher attempt - it replaces the stale one rather
/// than queueing behind it.
///
/// @requirement TB-209
#[test]
fn a_second_held_setup_replaces_the_first_rather_than_queueing() {
    let mut pending = PendingCallSetups::default();
    pending.hold(UserId(2), vec![1]);
    pending.hold(UserId(2), vec![2]);

    assert_eq!(pending.len(), 1);
    assert_eq!(pending.take(UserId(2)), Some(vec![2]));
}
