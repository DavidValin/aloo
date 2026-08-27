//! Tests for the parts of `client::voice_stream` that are pure data
//! transformation - specifically `ChunkDecryptor`, which decides what an
//! incoming stream's chunks decrypt to and what happens to chunks that
//! arrive before the setup they depend on (`docs/PROTOCOL.md`, US-027), and
//! `PendingChunkBuffer`, the same idea one layer up: chunks that arrive
//! before the stream itself has even started (`docs/PROTOCOL.md` 7.3,
//! US-007/TB-037).
//!
//! The rest of the module needs a live audio device or socket and is
//! covered at the acceptance layer instead (see `docs/TESTING.md`).
//!
//! Uses `generate_bundle_with_bits` at a small modulus for the same reason
//! `test/cucumber/world.rs` does: nothing here asserts anything about RSA
//! key size, and two RSA-4096 keygens per identity would make this slow
//! enough to skip. `hybrid_crypto_test.rs` covers the real sizes.

use aloo::client::voice_stream::{
    ChunkDecryptor, DirectStreamKey, IdleStreamAction, IncomingStreamKey, PendingChunkBuffer,
    encrypt_direct_chunk, idle_stream_action,
};
use aloo::crypto::pq::{
    PqPublicBundle, bundle_fingerprint, generate_bundle_with_bits, seal_chunk, seal_setup,
};
use aloo::proto;
use aloo::proto::UserId;
use std::time::{Duration, Instant};

const TEST_BITS: usize = 1024;
const SEND_ID: u64 = 9;

/// Alice sealing a stream for bob, plus the decryptor bob would use.
fn stream_fixture() -> (ChunkDecryptor, Vec<u8>, [u8; 32], PqPublicBundle) {
    let (alice_public, alice_private) = generate_bundle_with_bits(TEST_BITS).expect("alice");
    let (bob_public, bob_private) = generate_bundle_with_bits(TEST_BITS).expect("bob");
    let bob_fp = bundle_fingerprint(&bob_public).expect("fingerprint");

    let (setup, k_data) = seal_setup(
        &alice_private,
        bob_public.bootstrap_encap(),
        bob_fp,
        None,
        SEND_ID,
    )
    .expect("seal setup");
    let encoded = proto::encode(&setup).expect("encode setup");

    let decryptor = ChunkDecryptor::new(IncomingStreamKey::Pq {
        my_decaps: vec![bob_private.bootstrap_decap().clone()],
        my_fp: bob_fp,
        sender_public: alice_public.clone(),
    });
    (decryptor, encoded, k_data, alice_public)
}

/// @requirement AC-115
#[test]
fn chunks_open_once_the_setup_has_been_installed() {
    let (mut decryptor, setup, k_data, _) = stream_fixture();

    let replayed = decryptor
        .install_setup(SEND_ID, &setup)
        .expect("a genuine setup must install");
    assert!(
        replayed.is_empty(),
        "nothing was waiting, so nothing should be replayed"
    );

    let chunk = seal_chunk(&k_data, SEND_ID, 0, b"hello");
    assert_eq!(
        decryptor.decrypt(SEND_ID, 0, &[chunk]),
        Some(b"hello".to_vec())
    );
}

/// Voice chunks travel unreliably, so they can beat the reliable setup they
/// belong to. They must wait rather than being lost.
/// @requirement TB-163
#[test]
fn chunks_arriving_before_the_setup_are_replayed_once_it_lands() {
    let (mut decryptor, setup, k_data, _) = stream_fixture();

    // Three chunks arrive first - none can decrypt yet.
    for seq in 0..3u32 {
        let chunk = seal_chunk(&k_data, SEND_ID, seq, format!("chunk {seq}").as_bytes());
        assert_eq!(
            decryptor.decrypt(SEND_ID, seq, &[chunk]),
            None,
            "nothing can decrypt before the setup arrives"
        );
    }

    let replayed = decryptor
        .install_setup(SEND_ID, &setup)
        .expect("setup must install");

    assert_eq!(replayed.len(), 3, "every held chunk must come back");
    for (i, (seq, plaintext)) in replayed.iter().enumerate() {
        assert_eq!(*seq, i as u32, "chunks must be replayed in arrival order");
        assert_eq!(plaintext, format!("chunk {i}").as_bytes());
    }
}

/// @requirement TB-163
#[test]
fn a_stream_whose_setup_never_verifies_decrypts_nothing() {
    let (mut decryptor, _, k_data, _) = stream_fixture();

    let chunk = seal_chunk(&k_data, SEND_ID, 0, b"never readable");
    assert_eq!(decryptor.decrypt(SEND_ID, 0, &[chunk]), None);

    assert!(
        decryptor
            .install_setup(SEND_ID, b"not a setup at all")
            .is_none(),
        "a setup that doesn't even decode must not install"
    );
}

/// A setup is bound to its own send, so one captured from a different
/// stream cannot be used to open this one.
/// @requirement AC-115
#[test]
fn a_setup_for_a_different_send_is_refused() {
    let (mut decryptor, setup, _, _) = stream_fixture();

    assert!(
        decryptor.install_setup(SEND_ID + 1, &setup).is_none(),
        "the setup names its own send_id and must not install against another"
    );
}

/// A `Direct`-framed OTP stream carries its chunks verbatim: what the
/// transport is handed is *already* one-time-pad ciphertext, encrypted
/// whole before the first chunk left (`docs/PROTOCOL.md` §16.2), so
/// sealing it again would buy nothing and needs a keybundle this pair does
/// not have. This is the whole contract of `DirectStreamKey::Pad` /
/// `IncomingStreamKey::Pad` - a file's content phase and a voice message's
/// audio both ride it.
/// @requirement AC-252, AC-082
#[test]
fn a_pad_framed_stream_carries_its_chunks_verbatim_and_reads_them_back() {
    let pad_ciphertext: Vec<Vec<u8>> = vec![
        b"already-pad-ciphertext-chunk-0".to_vec(),
        b"chunk-1".to_vec(),
        // An empty chunk still has to survive the round trip.
        Vec::new(),
    ];

    let mut decryptor = ChunkDecryptor::new(IncomingStreamKey::Pad);
    for (seq, plain) in pad_ciphertext.iter().enumerate() {
        let seq = seq as u32;
        let blocks = encrypt_direct_chunk(&DirectStreamKey::Pad, SEND_ID, seq, plain)
            .expect("a Pad stream always produces a chunk");
        assert_eq!(
            blocks,
            vec![plain.clone()],
            "the bytes go on the wire untouched - nothing is sealed over them"
        );
        assert_eq!(
            decryptor.decrypt(SEND_ID, seq, &blocks).as_ref(),
            Some(plain),
            "and come back out of the decryptor exactly as they went in"
        );
    }
}

/// There is no per-stream key to introduce under `Pad`, so nothing is sent
/// ahead of the first chunk and nothing is waited for - unlike a sealed
/// stream, whose chunks are held until their setup verifies.
/// @requirement AC-252
#[test]
fn a_pad_framed_stream_has_no_setup_to_send_or_wait_for() {
    assert!(
        DirectStreamKey::Pad.setups().is_empty(),
        "nothing is negotiated for a stream the pad already protects"
    );

    let mut decryptor = ChunkDecryptor::new(IncomingStreamKey::Pad);
    // A chunk arriving first opens immediately rather than being buffered
    // against a setup that is never coming.
    assert_eq!(
        decryptor.decrypt(SEND_ID, 0, &[b"first".to_vec()]),
        Some(b"first".to_vec())
    );
    assert!(
        decryptor.install_setup(SEND_ID, b"anything").is_none(),
        "and a setup means nothing here if one somehow arrived"
    );
}

/// A stream whose sender announced no readable keybundle has no setup at
/// all - its chunks can never open, and installing a setup is meaningless.
/// @requirement TB-160
#[test]
fn an_rsa_stream_has_no_setup_to_install() {
    let mut decryptor = ChunkDecryptor::new(IncomingStreamKey::Undecryptable);

    assert!(
        decryptor.install_setup(SEND_ID, b"anything").is_none(),
        "only a pq_hybrid stream is introduced by a setup"
    );
    assert_eq!(
        decryptor.decrypt(SEND_ID, 0, &[vec![1, 2, 3]]),
        None,
        "with no candidate keys nothing decrypts, but it must not panic"
    );
}

// ---------------------------------------------------------------------
// Giving up on a stream nobody is going to finish (docs/PROTOCOL.md §7.3)
// ---------------------------------------------------------------------

/// A stream still receiving is left alone, however long it has been going.
/// @requirement TB-236
#[test]
fn a_stream_that_is_still_arriving_is_never_swept() {
    let now = Instant::now();
    assert_eq!(
        idle_stream_action(now, now, false, true),
        IdleStreamAction::Wait
    );
}

/// One that has gone quiet is asked to end - once. Asking again every
/// tick would be noise, and a worker that took the first ask reports back,
/// which is what actually finalizes the row.
/// @requirement TB-236
#[test]
fn a_quiet_stream_is_asked_to_end_exactly_once() {
    let now = Instant::now();
    let quiet = now - Duration::from_secs(30);
    assert_eq!(
        idle_stream_action(now, quiet, false, true),
        IdleStreamAction::Nudge
    );
    assert_eq!(
        idle_stream_action(now, quiet, true, true),
        IdleStreamAction::Wait,
        "already asked, and its worker is still there to answer"
    );
}

/// A worker that has gone without ever answering leaves nothing else to
/// finalize the row - so the sweep gives up on it, rather than leaving the
/// placeholder blinking "streaming..." for the rest of the session.
/// @requirement TB-236
#[test]
fn a_stream_whose_worker_is_gone_is_given_up_on() {
    let now = Instant::now();
    let quiet = now - Duration::from_secs(30);
    assert_eq!(
        idle_stream_action(now, quiet, true, false),
        IdleStreamAction::GiveUp
    );
    // But only once it has actually been asked, and only once it is quiet:
    // a worker exiting the instant after its last chunk is the ordinary
    // end of a stream, and its own report is what closes that row.
    assert_eq!(
        idle_stream_action(now, quiet, false, false),
        IdleStreamAction::Nudge
    );
    assert_eq!(
        idle_stream_action(now, now, true, false),
        IdleStreamAction::Wait
    );
}

// ---------------------------------------------------------------------
// Chunks that outrun their own StreamStart (docs/PROTOCOL.md 7.3)
// ---------------------------------------------------------------------
//
// `Chunk` travels unreliable UDP while `StreamStart` travels the reliable
// channel, so nothing guarantees the receiver *processes* `StreamStart`
// before the chunks that follow it - only that it was *sent* first. A
// recording short enough to finish (and send `StreamEnd`, itself reliable
// and therefore guaranteed to land only after `StreamStart`) before
// `StreamStart` is processed would otherwise lose every chunk it ever
// sent, since there would be no `active_streams` entry yet for any of
// them to attach to. `PendingChunkBuffer` is what a real session holds
// them in until that happens.

fn alice() -> UserId {
    UserId(1)
}

fn bob() -> UserId {
    UserId(2)
}

/// The chunks a short recording sent before `StreamStart` was processed
/// must all come back, in the order they arrived, once it is. The same
/// buffer is reused verbatim by `voice_call.rs` for a call participant's
/// audio arriving before their `CallAccept` is processed (TB-268).
/// @requirement TB-267, TB-268
#[test]
fn chunks_arriving_before_stream_start_are_replayed_in_arrival_order() {
    let mut pending = PendingChunkBuffer::new();

    for seq in 0..5u32 {
        pending.push(alice(), 1, seq, vec![format!("chunk {seq}").into_bytes()]);
    }

    let replayed = pending.take(alice(), 1);
    assert_eq!(replayed.len(), 5, "every buffered chunk must come back");
    for (i, (seq, blocks)) in replayed.iter().enumerate() {
        assert_eq!(*seq, i as u32, "chunks must be replayed in arrival order");
        assert_eq!(blocks, &vec![format!("chunk {i}").into_bytes()]);
    }

    // Taken once, not left behind for a second `StreamStart` (a
    // retransmitted one, say) to double-replay.
    assert!(pending.take(alice(), 1).is_empty());
}

/// A stream with nothing buffered for it - the ordinary case, since this
/// race is rare - replays as simply nothing, not an error.
/// @requirement TB-267
#[test]
fn taking_a_stream_with_nothing_buffered_is_empty_not_an_error() {
    let mut pending = PendingChunkBuffer::new();
    assert!(pending.take(alice(), 1).is_empty());
}

/// `stream_id` is only unique per sender (docs/PROTOCOL.md 7.3 "Stream
/// identity"), so the buffer must key by `(from, stream_id)` - never
/// `stream_id` alone - or one peer's `StreamStart` could release another
/// peer's buffered audio - the same reason `voice_call.rs` can key its own
/// use of this buffer by `(from, call_id)` and never worry about two
/// participants colliding (TB-268).
/// @requirement TB-267, TB-268
#[test]
fn pending_chunks_are_isolated_by_both_sender_and_stream_id() {
    let mut pending = PendingChunkBuffer::new();

    pending.push(alice(), 1, 0, vec![b"alice's stream 1".to_vec()]);
    pending.push(bob(), 1, 0, vec![b"bob's stream 1, same id".to_vec()]);
    pending.push(alice(), 2, 0, vec![b"alice's stream 2".to_vec()]);

    assert_eq!(
        pending.take(alice(), 1),
        vec![(0, vec![b"alice's stream 1".to_vec()])]
    );
    // Taking alice's stream 1 must not have touched bob's stream 1, nor
    // alice's own stream 2.
    assert_eq!(
        pending.take(bob(), 1),
        vec![(0, vec![b"bob's stream 1, same id".to_vec()])]
    );
    assert_eq!(
        pending.take(alice(), 2),
        vec![(0, vec![b"alice's stream 2".to_vec()])]
    );
}

/// A `StreamStart` that never arrives at all - lost, or a peer that
/// simply never sends one - must not let buffered chunks sit forever. A
/// call participant who never actually joins (invited but the call ends
/// first, say) leans on this same sweep to age their audio out (TB-268).
/// @requirement TB-267, TB-268
#[test]
fn a_stream_start_that_never_arrives_is_swept_after_its_timeout() {
    let mut pending = PendingChunkBuffer::new();
    let t0 = Instant::now();
    pending.push(alice(), 1, 0, vec![b"never claimed".to_vec()]);

    // Well under any reasonable timeout: still there.
    pending.sweep(t0 + Duration::from_secs(1));
    assert_eq!(
        pending.take(alice(), 1),
        vec![(0, vec![b"never claimed".to_vec()])],
        "a fresh buffer must not be swept away early"
    );

    // Re-buffer, then sweep well past any reasonable timeout.
    pending.push(alice(), 1, 0, vec![b"never claimed".to_vec()]);
    pending.sweep(t0 + Duration::from_secs(30));
    assert!(
        pending.take(alice(), 1).is_empty(),
        "a StreamStart that never came must not hold its chunks forever"
    );
}

/// A hostile or buggy peer racing chunks for many stream_ids that never
/// start, or flooding one stream_id with chunks that never get claimed,
/// must not grow this buffer without limit while waiting - including a
/// call participant flooding audio for a `call_id` under a host who never
/// actually adds them (TB-268).
/// @requirement TB-267, TB-268
#[test]
fn pending_chunks_stay_bounded_under_a_flood() {
    let mut pending = PendingChunkBuffer::new();

    // Far more chunks for one never-started stream than any real
    // recording would send before a `StreamStart` could plausibly land.
    for seq in 0..10_000u32 {
        pending.push(alice(), 1, seq, vec![vec![0u8]]);
    }
    assert!(
        pending.take(alice(), 1).len() < 10_000,
        "one stream's buffer must not grow to match an unbounded flood"
    );

    // Far more distinct never-started stream_ids than a real client would
    // ever have open at once.
    for stream_id in 0..1_000u64 {
        pending.push(alice(), stream_id, 0, vec![vec![0u8]]);
    }
    let claimed: usize = (0..1_000u64)
        .map(|stream_id| pending.take(alice(), stream_id).len())
        .sum();
    assert!(
        claimed < 1_000,
        "the number of distinct streams waiting at once must also stay bounded"
    );
}
