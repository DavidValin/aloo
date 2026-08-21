//! When a voice message or a file transfer has earned its sender a
//! `Consumed` receipt - the file on disk, the audio heard - and when it
//! has not (docs/PROTOCOL.md 7.2.1).

use aloo::client::delivery::PendingReceipts;
use aloo::proto::UserId;

const ALICE: UserId = UserId(2);
const BOB: UserId = UserId(3);

/// The whole reason this is tracked rather than answered on the spot: the
/// second answer is owed from the moment the first one is given, and comes
/// due much later.
/// @requirement AC-235
#[test]
fn nothing_is_receipted_merely_for_arriving() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 7, Some(11));
    assert_eq!(pending.len(), 1, "it is owed, not paid");
    assert_eq!(
        pending.msg_id_of(ALICE, 7),
        Some(11),
        "and readable without paying it - the Decrypted receipt names the \
         same message long before this one comes due"
    );
    assert_eq!(pending.len(), 1, "reading it settles nothing");
}

/// @requirement AC-235
#[test]
fn a_file_is_receipted_only_once_it_has_all_arrived_decrypted() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 7, Some(11));
    assert_eq!(
        pending.settle(ALICE, 7, true),
        Some(11),
        "a transfer that completed decrypted earns its receipt"
    );
    assert!(pending.is_empty(), "and stops being owed");
}

/// @requirement AC-235
#[test]
fn a_failed_transfer_is_never_receipted() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 7, Some(11));
    assert_eq!(
        pending.settle(ALICE, 7, false),
        None,
        "a transfer that failed part way leaves the sender's row undelivered"
    );
    assert!(
        pending.is_empty(),
        "and is forgotten rather than left to be retried into a false receipt"
    );
}

/// A stream whose every chunk failed to open produces no audio at all -
/// the receiving side finished it, but decoded nothing, which is not
/// something to acknowledge.
/// @requirement AC-235
#[test]
fn a_voice_stream_that_decoded_nothing_is_never_receipted() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 9, Some(22));
    assert_eq!(pending.settle(ALICE, 9, false), None);
}

/// @requirement TB-230
#[test]
fn a_payload_naming_no_message_earns_no_receipt() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 7, None);
    assert!(pending.is_empty(), "a sender that asked for nothing is owed nothing");
    assert_eq!(pending.settle(ALICE, 7, true), None);
}

/// Outcomes arrive off worker threads and can be reported more than once
/// for the same transfer; a second one must not produce a second receipt.
/// @requirement AC-235
#[test]
fn one_transfer_earns_at_most_one_receipt() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 7, Some(11));
    assert_eq!(pending.settle(ALICE, 7, true), Some(11));
    assert_eq!(pending.settle(ALICE, 7, true), None);
}

/// A `stream_id` is only unique per sender - each peer counts its own -
/// so two peers using the same number must not settle each other's.
/// @requirement TB-231
#[test]
fn two_senders_using_the_same_stream_id_are_kept_apart() {
    let mut pending = PendingReceipts::new();
    pending.remember(ALICE, 7, Some(11));
    pending.remember(BOB, 7, Some(22));

    assert_eq!(pending.settle(BOB, 7, true), Some(22));
    assert_eq!(
        pending.settle(ALICE, 7, true),
        Some(11),
        "settling one sender's stream must leave the other's alone"
    );
}
