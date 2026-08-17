use aloo::proto::UserId;
use aloo::client::rekey::{QueuedOutbound, RemoteKeys};

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
        },
    );
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Channel {
            channel: "general".into(),
            plaintext: "second".into(),
        },
    );
    assert_eq!(remote.queue_len(UserId(1)), 2);

    let flushed = remote.on_rotated(UserId(1));
    assert_eq!(
        flushed,
        vec![
            QueuedOutbound::Direct {
                plaintext: "first".into()
            },
            QueuedOutbound::Channel {
                channel: "general".into(),
                plaintext: "second".into()
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

    let flushed = remote.on_rotated(UserId(1));
    assert!(flushed.is_empty());
    // the rotation made the key fresh again even with nothing queued
    assert!(remote.try_use(UserId(1)));

    // simulate a second rotation with something queued, batch-flushed and marked used
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Direct {
            plaintext: "queued".into(),
        },
    );
    let flushed = remote.on_rotated(UserId(1));
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
    let flushed = remote.on_rotated(UserId(9));
    assert!(flushed.is_empty());
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
        },
    );
    assert!(!remote.try_use(UserId(1)));
    remote.enqueue(
        UserId(1),
        QueuedOutbound::Direct {
            plaintext: "b".into(),
        },
    );

    // the peer's rotation finally arrives: flush both at once
    let batch = remote.on_rotated(UserId(1));
    assert_eq!(batch.len(), 2);
    remote.mark_used(UserId(1));

    // and we're back to stale until the next rotation
    assert!(!remote.try_use(UserId(1)));
}
