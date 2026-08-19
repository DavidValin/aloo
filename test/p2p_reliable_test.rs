use std::time::{Duration, Instant};

use aloo::client::p2p_reliable::{ArqReceiver, ArqSender, MAX_RETRIES, SEND_WINDOW};

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
    tx.send(vec![1, 2, 3]).expect("first frame goes out immediately");
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
    let (seq, _) = tx.send(vec![9]).expect("first frame goes out immediately");
    tx.on_ack(seq);
    assert!(!tx.has_pending());
    let far_future = Instant::now() + Duration::from_secs(60);
    assert_eq!(tx.due_for_retransmit(far_future).unwrap(), Vec::new());
}

/// @requirement TB-145
#[test]
fn unacked_frame_is_retransmitted_after_its_backoff_elapses() {
    let mut tx = ArqSender::new();
    let (seq, _) = tx.send(vec![7, 7]).expect("first frame goes out immediately");
    // Simulate time passing by checking well past the initial backoff.
    let later = Instant::now() + Duration::from_millis(500);
    let due = tx.due_for_retransmit(later).unwrap();
    assert_eq!(due, vec![(seq, vec![7, 7])]);
}

/// @requirement TB-145
#[test]
fn frame_exceeding_max_retries_fails_the_sender() {
    let mut tx = ArqSender::new();
    tx.send(vec![1]).expect("first frame goes out immediately");
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

// ---------------------------------------------------------------------
// ArqSender: the send window that keeps a bulk hand-off (an OTP pad) from
// arriving as one unpaceable burst
// ---------------------------------------------------------------------

/// @requirement TB-202
#[test]
fn only_send_window_frames_go_out_at_once() {
    let mut tx = ArqSender::new();
    let sent: Vec<_> = (0..SEND_WINDOW + 20)
        .map(|i| tx.send(vec![i as u8]))
        .collect();
    assert!(
        sent[..SEND_WINDOW].iter().all(Option::is_some),
        "the first SEND_WINDOW frames go straight onto the wire"
    );
    assert!(
        sent[SEND_WINDOW..].iter().all(Option::is_none),
        "everything past the window waits rather than being blasted out"
    );
}

/// @requirement TB-202
#[test]
fn an_ack_releases_the_next_backlogged_frame_in_order() {
    let mut tx = ArqSender::new();
    let mut on_wire: Vec<(u32, Vec<u8>)> = (0..SEND_WINDOW + 3)
        .filter_map(|i| tx.send(vec![i as u8]))
        .collect();
    // Ack the in-flight frames oldest-first; each retires one and releases
    // exactly one backlogged frame.
    for i in 0..3u32 {
        let released = tx.on_ack(i);
        assert_eq!(
            released.len(),
            1,
            "each cumulative ack advancing the frontier by one frees exactly one slot"
        );
        on_wire.extend(released);
    }
    let order: Vec<u8> = on_wire.iter().map(|(_, p)| p[0]).collect();
    let expected: Vec<u8> = (0..SEND_WINDOW as u8 + 3).collect();
    assert_eq!(
        order, expected,
        "frames must reach the wire in the order they were handed over"
    );
    let seqs: Vec<u32> = on_wire.iter().map(|(seq, _)| *seq).collect();
    let expected_seqs: Vec<u32> = (0..SEND_WINDOW as u32 + 3).collect();
    assert_eq!(
        seqs, expected_seqs,
        "sequence numbers are assigned on the way out, so the peer sees one gapless run"
    );
}

/// @requirement TB-202
#[test]
fn a_duplicate_ack_does_not_pull_the_backlog_forward() {
    let mut tx = ArqSender::new();
    for i in 0..SEND_WINDOW + 2 {
        tx.send(vec![i as u8]);
    }
    assert_eq!(tx.on_ack(0).len(), 1, "the first ack releases a frame");
    assert!(
        tx.on_ack(0).is_empty(),
        "a replayed ack for an already-retired frame releases nothing"
    );
}

/// @requirement TB-202
#[test]
fn reset_hands_back_in_flight_and_backlogged_frames_in_order() {
    let mut tx = ArqSender::new();
    for i in 0..SEND_WINDOW + 5 {
        tx.send(vec![i as u8]);
    }
    let requeued: Vec<u8> = tx.reset().into_iter().map(|p| p[0]).collect();
    let expected: Vec<u8> = (0..SEND_WINDOW as u8 + 5).collect();
    assert_eq!(
        requeued, expected,
        "a re-punched link must re-send everything undelivered, in the original order"
    );
    assert!(!tx.has_pending(), "reset leaves nothing behind");
}

/// @requirement TB-202
#[test]
fn a_backlogged_frame_still_counts_as_pending() {
    let mut tx = ArqSender::new();
    for i in 0..SEND_WINDOW + 1 {
        tx.send(vec![i as u8]);
    }
    // Retire every in-flight frame; the one still backlogged is released by
    // the first of those acks, so something is always outstanding.
    for i in 0..SEND_WINDOW as u32 {
        tx.on_ack(i);
    }
    assert!(
        tx.has_pending(),
        "the frame released into the window is still awaiting its own ack"
    );
}

/// The window is what keeps a bulk sender from ever driving a well-behaved
/// receiver into `REORDER_BUFFER_LIMIT` - the failure an OTP pad transfer
/// used to hit head-on.
/// @requirement TB-202
#[test]
fn a_full_window_lost_in_flight_stays_within_the_receivers_reorder_bound() {
    let mut tx = ArqSender::new();
    let frames: Vec<_> = (0..SEND_WINDOW).filter_map(|i| tx.send(vec![i as u8])).collect();
    let mut rx = ArqReceiver::new();
    // Worst case: the very first frame is lost and every other frame of the
    // window arrives, so all of them have to be buffered.
    for (seq, payload) in frames.iter().skip(1) {
        rx.receive(*seq, payload.clone());
    }
    assert!(
        !rx.failed(),
        "a full window in flight must stay inside the receiver's reorder buffer"
    );
}
