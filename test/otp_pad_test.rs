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
    // The smallest MTU worth designing for is 1280 (IPv6's minimum);
    // subtract generous room for IP/UDP headers and this app's own framing
    // and the payload must still fit.
    const SAFE_PAYLOAD_BYTES: usize = 1024;
    assert!(
        PAD_CHUNK_BYTES <= SAFE_PAYLOAD_BYTES,
        "a pad chunk of {PAD_CHUNK_BYTES} bytes risks IP fragmentation, which is exactly \
         what made provisioning fail across real network paths"
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
#[test]
fn the_inflight_bound_is_a_fixed_amount_of_data_not_a_fraction_of_the_pad() {
    let inflight_bytes = PAD_INFLIGHT_FRAMES * PAD_CHUNK_BYTES;
    assert_eq!(
        inflight_bytes,
        16 * 1024 * 1024,
        "the sender should keep about 16MB in flight regardless of pad size"
    );
    assert!(PAD_INFLIGHT_FRAMES > 0);
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
