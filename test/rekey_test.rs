use aloo::proto::UserId;
use aloo::client::rekey::{MAX_QUEUED_SEND_ATTEMPTS, QueuedOutbound, RemoteKeys};

// ---------------------------------------------------------------------
// RemoteKeys
// ---------------------------------------------------------------------

/// @requirement TB-079
#[test]
fn untracked_peer_is_always_sendable() {
    let mut remote = RemoteKeys::new();
    assert!(remote.try_use(UserId(1)));
    assert!(
        remote.try_use(UserId(1)),
        "an untracked (Static) peer is never gated"
    );
    assert!(!remote.is_tracked(UserId(1)));
}

/// @requirement TB-080
#[test]
fn tracked_peer_is_fresh_once_then_stale() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(
        remote.try_use(UserId(1)),
        "bootstrap key should be usable once"
    );
    assert!(
        !remote.try_use(UserId(1)),
        "key must not be reused after one send"
    );
}

/// @requirement TB-080
#[test]
fn track_is_idempotent_and_does_not_reset_freshness() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1)));
    remote.track(UserId(1)); // re-track, e.g. re-joining a channel
    assert!(
        !remote.try_use(UserId(1)),
        "re-tracking must not resurrect a stale key"
    );
}

/// @requirement AC-045
#[test]
fn queued_messages_flush_in_fifo_order_on_rotation() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1))); // consume the initial fresh key

    remote.enqueue(
        UserId(1),
        QueuedOutbound::Direct {
            plaintext: "first".into(),
            msg_id: 0,
            log_index: None,
            attempts: 0,
        },
    );
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Channel {
            channel: "general".into(),
            plaintext: "second".into(),
            msg_id: 0,
            attempts: 0,
        },
    );
    assert_eq!(remote.queue_len(UserId(1)), 2);

    let (flushed, given_up) = remote.on_rotated(UserId(1));
    assert!(given_up.is_empty(), "neither has used up its attempts yet");
    // `attempts` comes back at 1: handing an item out for sending is what
    // spends an attempt (`RemoteKeys::on_rotated`).
    assert_eq!(
        flushed,
        vec![
            QueuedOutbound::Direct {
                plaintext: "first".into(),
                msg_id: 0,
                log_index: None,
                attempts: 1,
            },
            QueuedOutbound::Channel {
                channel: "general".into(),
                plaintext: "second".into(),
                msg_id: 0,
                attempts: 1,
            },
        ]
    );
    assert_eq!(
        remote.queue_len(UserId(1)),
        0,
        "queue must be drained, not just peeked"
    );
}

/// @requirement TB-080
#[test]
fn on_rotated_marks_fresh_and_mark_used_consumes_it_again() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));
    assert!(remote.try_use(UserId(1)));

    let (flushed, given_up) = remote.on_rotated(UserId(1));
    assert!(flushed.is_empty() && given_up.is_empty());
    // the rotation made the key fresh again even with nothing queued
    assert!(remote.try_use(UserId(1)));

    // simulate a second rotation with something queued, batch-flushed and marked used
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Direct {
            plaintext: "queued".into(),
            msg_id: 0,
            log_index: None,
            attempts: 0,
        },
    );
    let (flushed, _) = remote.on_rotated(UserId(1));
    assert_eq!(flushed.len(), 1);
    remote.mark_used(UserId(1));
    assert!(
        !remote.try_use(UserId(1)),
        "batch flush must consume freshness like any other send"
    );
}

/// @requirement TB-081
#[test]
fn on_rotated_on_a_never_tracked_peer_starts_tracking_it() {
    let mut remote = RemoteKeys::new();
    assert!(!remote.is_tracked(UserId(9)));
    let (flushed, given_up) = remote.on_rotated(UserId(9));
    assert!(flushed.is_empty() && given_up.is_empty());
    assert!(remote.is_tracked(UserId(9)));
}

/// @requirement TB-081
#[test]
fn enqueue_on_untracked_peer_starts_tracking_it_as_stale() {
    let mut remote = RemoteKeys::new();
    remote.enqueue(
        UserId(5),
        QueuedOutbound::Direct {
            plaintext: "x".into(),
            msg_id: 0,
            log_index: None,
            attempts: 0,
        },
    );
    assert!(remote.is_tracked(UserId(5)));
    assert!(
        !remote.try_use(UserId(5)),
        "a peer we just had to queue for should not appear fresh"
    );
    assert_eq!(remote.queue_len(UserId(5)), 1);
}

/// @requirement AC-045
#[test]
fn full_lifecycle_track_use_queue_rotate_flush() {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(1));

    // first message goes out immediately on the bootstrap key
    assert!(remote.try_use(UserId(1)));

    // two more typed while waiting for the peer's next key
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Direct {
            plaintext: "a".into(),
            msg_id: 0,
            log_index: None,
            attempts: 0,
        },
    );
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Direct {
            plaintext: "b".into(),
            msg_id: 0,
            log_index: None,
            attempts: 0,
        },
    );

    // the peer's rotation finally arrives: flush both at once
    let (batch, _) = remote.on_rotated(UserId(1));
    assert_eq!(batch.len(), 2);
    remote.mark_used(UserId(1));

    // and we're back to stale until the next rotation
    assert!(!remote.try_use(UserId(1)));
}

// ---------------------------------------------------------------------
// RemoteKeys: the queue is a wait, not a life sentence
// ---------------------------------------------------------------------

fn direct(plaintext: &str) -> QueuedOutbound {
    QueuedOutbound::Direct {
        plaintext: plaintext.into(),
        msg_id: 1,
        log_index: Some(0),
        attempts: 0,
    }
}

/// @requirement TB-232
#[test]
fn an_attempt_is_spent_when_an_item_is_handed_out() {
    let mut remote = RemoteKeys::new();
    remote.enqueue(UserId(1), direct("hello"));

    let (flushed, given_up) = remote.on_rotated(UserId(1));
    assert!(given_up.is_empty());
    assert_eq!(
        flushed[0].attempts(),
        1,
        "being handed out for sending is what costs an attempt"
    );
}

/// @requirement TB-232
#[test]
fn an_item_that_cannot_be_sent_keeps_its_spent_attempt() {
    let mut remote = RemoteKeys::new();
    remote.enqueue(UserId(1), direct("hello"));

    let (mut flushed, _) = remote.on_rotated(UserId(1));
    let item = flushed.pop().expect("one item");
    // The caller could not encrypt it after all, so back it goes.
    remote.requeue(UserId(1), item);

    let (flushed, _) = remote.on_rotated(UserId(1));
    assert_eq!(
        flushed[0].attempts(),
        2,
        "a re-queued item resumes from where it left off, not from zero"
    );
}

/// A peer may simply stop rotating, or stop being addressable at all. The
/// message the user already sees in their log has to resolve one way or
/// the other rather than waiting forever.
/// @requirement AC-234
#[test]
fn a_queued_message_is_given_up_on_after_its_attempts_run_out() {
    let mut remote = RemoteKeys::new();
    remote.enqueue(UserId(1), direct("hello"));

    // Every rotation hands it out and the caller fails to send it.
    for round in 1..=MAX_QUEUED_SEND_ATTEMPTS {
        let (mut flushed, given_up) = remote.on_rotated(UserId(1));
        assert!(
            given_up.is_empty(),
            "still within its budget on round {round}"
        );
        let item = flushed.pop().expect("still being tried");
        assert_eq!(item.attempts(), round);
        remote.requeue(UserId(1), item);
    }

    let (flushed, given_up) = remote.on_rotated(UserId(1));
    assert!(
        flushed.is_empty(),
        "it is not handed out again once its attempts are spent"
    );
    assert_eq!(
        given_up.len(),
        1,
        "it is reported as given up on, so the caller can mark the row failed"
    );
    assert_eq!(given_up[0].msg_id(), 1, "naming the row it belongs to");
    assert_eq!(
        remote.queue_len(UserId(1)),
        0,
        "and it leaves the queue rather than being retried forever"
    );
}

/// The bound is per message, not per queue: one message running out must
/// not take a freshly-typed one down with it.
/// @requirement AC-234
#[test]
fn giving_up_on_one_message_leaves_the_others_alone() {
    let mut remote = RemoteKeys::new();
    remote.enqueue(UserId(1), direct("old"));
    for _ in 0..MAX_QUEUED_SEND_ATTEMPTS {
        let (mut flushed, _) = remote.on_rotated(UserId(1));
        let item = flushed.pop().expect("still being tried");
        remote.requeue(UserId(1), item);
    }
    remote.enqueue(UserId(1), direct("new"));

    let (flushed, given_up) = remote.on_rotated(UserId(1));
    assert_eq!(given_up.len(), 1, "only the exhausted one is given up on");
    assert_eq!(flushed.len(), 1, "the fresh one is still being tried");
    assert!(matches!(
        &flushed[0],
        QueuedOutbound::Direct { plaintext, .. } if plaintext == "new"
    ));
}
