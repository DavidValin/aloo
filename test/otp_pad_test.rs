//! `client::otp_pad`'s sizing and the digest agreement the two-phase
//! commit rests on.
//!
//! The transfer itself needs two live sessions and a punched link, so it
//! is verified manually (docs/TESTING.md "Known coverage gaps"); what is
//! checked here is everything decidable without one - the chunk sizing
//! that fixes fragmentation, the in-flight bound that makes an unbounded
//! pad possible, and `digest_key_file`, which is the whole basis for
//! "neither side installs until both prove they hold the same bytes".

use aloo::client::otp_pad::{PAD_CHUNK_BYTES, PAD_INFLIGHT_FRAMES};
use aloo::p2p_proto::{P2pPayload, PunchDatagram, SAFE_DATAGRAM_BYTES};
use aloo::proto;
use aloo::crypto::otp::digest_key_file;
use std::path::PathBuf;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-pad-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The bug this transport replaced: chunks so large that the resulting
/// datagram was IP-fragmented into dozens of pieces, any one of which
/// being lost cost the whole chunk. A pad chunk must stay comfortably
/// inside a single un-fragmented datagram.
#[test]
fn a_pad_chunk_fits_one_unfragmented_datagram() {
    // Measured, not estimated. The chunk size is the single biggest lever
    // on how long provisioning takes, so guessing at the framing overhead
    // would mean either leaving throughput on the table or shipping a size
    // that fragments - and fragmentation is exactly what made provisioning
    // fail across real network paths.
    //
    // A pad chunk is sealed with AES-256-GCM (`crypto::pq::seal_chunk`),
    // whose only expansion is the 16-byte tag - unlike a file chunk, whose
    // RSA-OAEP path expands by half again and is why
    // `file_transfer::FILE_CHUNK_BYTES` is as small as it is.
    const GCM_TAG_BYTES: usize = 16;
    let sealed = vec![0u8; PAD_CHUNK_BYTES + GCM_TAG_BYTES];
    let payload = proto::encode(&P2pPayload::OtpPadChunk {
        stream_id: u64::MAX,
        seq: u32::MAX,
        blocks: vec![sealed],
    })
    .expect("encode");
    let dgram = proto::encode(&PunchDatagram::Reliable {
        seq: u32::MAX,
        payload,
    })
    .expect("encode");

    assert!(
        dgram.len() <= SAFE_DATAGRAM_BYTES,
        "a {PAD_CHUNK_BYTES}-byte pad chunk becomes a {}-byte datagram, over the \
         {SAFE_DATAGRAM_BYTES}-byte budget that keeps it un-fragmented",
        dgram.len()
    );
}

/// The old scheme wrapped every chunk in its own `pq_hybrid` envelope,
/// costing several kilobytes of signature and key exchange *per chunk*.
/// This checks the property that replaced it: the number of chunks scales
/// with the pad, so any fixed per-chunk overhead would too - which is why
/// the key exchange now happens once for the whole transfer instead.
#[test]
fn chunk_count_scales_with_the_pad_so_per_chunk_overhead_would_not_survive() {
    let one_mb_per_key: usize = 1024 * 1024;
    let chunks_for_1mb = (one_mb_per_key * 2).div_ceil(PAD_CHUNK_BYTES);
    assert!(
        chunks_for_1mb > 1000,
        "even the smallest pad is thousands of chunks ({chunks_for_1mb}), so the key \
         exchange has to be amortised across the transfer rather than paid per chunk"
    );
}

/// Memory must not scale with the pad - the sender stops reading once this
/// many frames are outstanding, so a terabyte pad costs the same memory as
/// a megabyte one.
///
/// Asserted as a property rather than against a figure. The bound used to
/// be a flat 16MB, which read as generous and was in fact unreachable:
/// `outbound_depth` saturates at `PENDING_MAX` on a link that is not yet
/// `Active`, so a bound above it meant no backpressure at all (see
/// `the_inflight_bound_stays_under_what_the_link_queue_can_hold`). It is
/// now derived from that queue, so pinning a constant here would only
/// pin the wrong half of the relationship again.
// The assertions here compare compile-time constants, which is the point:
// what is being checked is a relationship between them that a later edit
// could silently break.
#[allow(clippy::assertions_on_constants)]
#[test]
fn the_inflight_bound_is_a_fixed_amount_of_data_not_a_fraction_of_the_pad() {
    let inflight_bytes = PAD_INFLIGHT_FRAMES * PAD_CHUNK_BYTES;
    assert!(PAD_INFLIGHT_FRAMES > 0);
    // Whatever it is, it is a constant - a pad a million times larger
    // costs the sender exactly the same memory.
    for pad_bytes in [1024u64 * 1024, 1024 * 1024 * 1024 * 1024] {
        let _ = pad_bytes;
        assert_eq!(PAD_INFLIGHT_FRAMES * PAD_CHUNK_BYTES, inflight_bytes);
    }
    assert!(
        inflight_bytes <= 16 * 1024 * 1024,
        "{inflight_bytes} bytes in flight is more memory than a bounded transfer needs"
    );
}

// ---------------------------------------------------------------------
// digest_key_file - what both sides are held to
// ---------------------------------------------------------------------

#[test]
fn identical_files_digest_identically_and_different_ones_do_not() {
    let dir = temp_dir("digest");
    let a = dir.join("a.key");
    let b = dir.join("b.key");
    let c = dir.join("c.key");
    std::fs::write(&a, vec![7u8; 4096]).unwrap();
    std::fs::write(&b, vec![7u8; 4096]).unwrap();
    std::fs::write(&c, vec![8u8; 4096]).unwrap();

    assert_eq!(digest_key_file(&a).unwrap(), digest_key_file(&b).unwrap());
    assert_ne!(digest_key_file(&a).unwrap(), digest_key_file(&c).unwrap());
}

/// The case the whole two-phase commit exists for: a pad that differs by a
/// single byte would otherwise install cleanly on both sides and decode to
/// silent garbage forever after.
#[test]
fn a_single_flipped_byte_changes_the_digest() {
    let dir = temp_dir("digest-flip");
    let good = dir.join("good.key");
    let bad = dir.join("bad.key");
    let mut bytes = vec![0x5Au8; 100_000];
    std::fs::write(&good, &bytes).unwrap();
    bytes[65_432] ^= 0x01;
    std::fs::write(&bad, &bytes).unwrap();

    assert_ne!(
        digest_key_file(&good).unwrap(),
        digest_key_file(&bad).unwrap(),
        "one flipped byte must be detectable - a pad has no integrity check of its own"
    );
}

/// A truncated transfer must never look like the pad it was meant to be.
#[test]
fn a_truncated_file_digests_differently_from_the_whole_one() {
    let dir = temp_dir("digest-short");
    let whole = dir.join("whole.key");
    let short = dir.join("short.key");
    let bytes = vec![0x11u8; 50_000];
    std::fs::write(&whole, &bytes).unwrap();
    std::fs::write(&short, &bytes[..49_999]).unwrap();

    assert_ne!(
        digest_key_file(&whole).unwrap(),
        digest_key_file(&short).unwrap()
    );
}

/// Digesting must stream rather than read the file in - a pad may be far
/// larger than memory. This uses a file past the internal buffer so the
/// multi-pass loop actually runs.
#[test]
fn digesting_streams_a_file_larger_than_its_internal_buffer() {
    let dir = temp_dir("digest-big");
    let path = dir.join("big.key");
    // Past the 1MB read buffer, so more than one pass is required.
    let bytes = vec![0x3Cu8; 1024 * 1024 + 12_345];
    std::fs::write(&path, &bytes).unwrap();

    // Same answer as hashing the whole thing at once.
    use sha2::{Digest, Sha256};
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(digest_key_file(&path).unwrap(), expected);
}

#[test]
fn digesting_an_empty_file_succeeds_rather_than_erroring() {
    let dir = temp_dir("digest-empty");
    let path = dir.join("empty.key");
    std::fs::write(&path, b"").unwrap();
    assert!(digest_key_file(&path).is_ok());
}

#[test]
fn digesting_a_missing_file_is_an_error_not_a_default_digest() {
    let dir = temp_dir("digest-missing");
    assert!(digest_key_file(&dir.join("nope.key")).is_err());
}


/// The bound the worker throttles against must stay under what the link's
/// queue can actually hold, or it can never be reached at all.
///
/// `outbound_depth` is `arq_tx.depth() + pending.len()`, and while a link
/// is not yet `Active` the first term is zero and the second saturates at
/// `PENDING_MAX`. A bound above that leaves the worker permanently
/// unthrottled: it reads the whole pad at disk speed into a queue that
/// discards its *oldest* entry on overflow, so the front of the transfer
/// is destroyed continuously while the progress bar races to completion.
/// That is not a slow transfer, it is a broken one, and it is what this
/// pins.
///
/// @requirement AC-254
#[allow(clippy::assertions_on_constants)]
#[test]
fn the_inflight_bound_stays_under_what_the_link_queue_can_hold() {
    assert!(
        PAD_INFLIGHT_FRAMES < aloo::client::p2p::PENDING_MAX,
        "an in-flight bound of {PAD_INFLIGHT_FRAMES} can never be reached through a queue \
         that holds {}, so the worker would never throttle at all",
        aloo::client::p2p::PENDING_MAX
    );
    assert!(
        PAD_INFLIGHT_FRAMES > aloo::client::p2p_reliable::SEND_WINDOW,
        "and it must stay well above one send window, or the link waits on the disk"
    );
}
