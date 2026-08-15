use std::time::{Duration, Instant};

use aloo::p2p_reliable::{ArqReceiver, ArqSender, MAX_RETRIES};

// ---------------------------------------------------------------------
// ArqReceiver: in-order delivery under reordering/duplication
// ---------------------------------------------------------------------

/// @requirement TB-144
#[test]
fn in_order_frames_deliver_immediately() {
    let mut rx = ArqReceiver::new();
    assert_eq!(rx.receive(0, vec![0]), vec![vec![0]]);
    assert_eq!(rx.receive(1, vec![1]), vec![vec![1]]);
    assert_eq!(rx.receive(2, vec![2]), vec![vec![2]]);
}

/// @requirement TB-144
#[test]
fn out_of_order_frames_are_buffered_then_delivered_once_the_gap_fills() {
    let mut rx = ArqReceiver::new();
    assert_eq!(
        rx.receive(1, vec![1]),
        Vec::<Vec<u8>>::new(),
        "seq 1 arrives before seq 0 - buffered"
    );
    assert_eq!(
        rx.receive(2, vec![2]),
        Vec::<Vec<u8>>::new(),
        "seq 2 also buffered"
    );
    // seq 0 fills the gap - 0, 1, 2 all deliver together, in order.
    assert_eq!(rx.receive(0, vec![0]), vec![vec![0], vec![1], vec![2]]);
}

/// @requirement TB-144
#[test]
fn duplicate_frames_are_dropped_without_redelivering() {
    let mut rx = ArqReceiver::new();
    assert_eq!(rx.receive(0, vec![0]), vec![vec![0]]);
    assert_eq!(
        rx.receive(0, vec![0]),
        Vec::<Vec<u8>>::new(),
        "already-delivered seq must not redeliver"
    );
    assert_eq!(rx.receive(1, vec![1]), vec![vec![1]]);
    assert_eq!(
        rx.receive(1, vec![1]),
        Vec::<Vec<u8>>::new(),
        "duplicate of the last-delivered seq"
    );
}

/// @requirement TB-144
#[test]
fn reorder_buffer_bound_fails_the_link_rather_than_growing_unbounded() {
    let mut rx = ArqReceiver::new();
    // Never send seq 0, so every one of these sits in the reorder buffer.
    for seq in 1..500 {
        rx.receive(seq, vec![]);
        if rx.failed() {
            break;
        }
    }
    assert!(
        rx.failed(),
        "an unbounded run of out-of-order frames must eventually fail the link"
    );
    // Once failed, further frames (even the one that would have unblocked
    // everything) are simply ignored - no delayed flood of buffered data.
    assert_eq!(rx.receive(0, vec![0]), Vec::<Vec<u8>>::new());
}

// ---------------------------------------------------------------------
// ArqSender: retransmit-on-timeout, ack retires, give-up-after-MAX_RETRIES
// ---------------------------------------------------------------------

/// @requirement TB-145
#[test]
fn unacked_frame_is_not_retransmitted_before_its_backoff_elapses() {
    let mut tx = ArqSender::new();
    tx.send(vec![1, 2, 3]);
    let due = tx.due_for_retransmit(Instant::now()).unwrap();
    assert!(
        due.is_empty(),
        "nothing should be due immediately after sending"
    );
}

/// @requirement TB-145
#[test]
fn acked_frame_is_never_retransmitted() {
    let mut tx = ArqSender::new();
    let seq = tx.send(vec![9]);
    tx.on_ack(seq);
    assert!(!tx.has_pending());
    let far_future = Instant::now() + Duration::from_secs(60);
    assert_eq!(tx.due_for_retransmit(far_future).unwrap(), Vec::new());
}

/// @requirement TB-145
#[test]
fn unacked_frame_is_retransmitted_after_its_backoff_elapses() {
    let mut tx = ArqSender::new();
    let seq = tx.send(vec![7, 7]);
    // Simulate time passing by checking well past the initial backoff.
    let later = Instant::now() + Duration::from_millis(500);
    let due = tx.due_for_retransmit(later).unwrap();
    assert_eq!(due, vec![(seq, vec![7, 7])]);
}

/// @requirement TB-145
#[test]
fn frame_exceeding_max_retries_fails_the_sender() {
    let mut tx = ArqSender::new();
    tx.send(vec![1]);
    let mut now = Instant::now();
    for _ in 0..MAX_RETRIES {
        now += Duration::from_secs(10); // comfortably past any backoff
        tx.due_for_retransmit(now)
            .expect("still within retry budget");
    }
    now += Duration::from_secs(10);
    assert!(
        tx.due_for_retransmit(now).is_err(),
        "exceeding MAX_RETRIES must fail the whole send"
    );
}
