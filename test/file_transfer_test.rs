use aloo::file_transfer::{
    FILE_CHUNK_BYTES, FileOfferPayload, MAX_FILENAME_CHARS, default_download_dir, safe_filename,
    truncate_filename,
};
use aloo::p2p_proto::SAFE_DATAGRAM_BYTES;
use aloo::proto;

/// @requirement TB-123
#[test]
fn file_offer_payload_round_trips_through_proto_encode_decode() {
    let payload = FileOfferPayload {
        filename: "report.pdf".to_string(),
        size: 12345,
    };
    let bytes = proto::encode(&payload).expect("encode");
    let decoded: FileOfferPayload = proto::decode(&bytes).expect("decode");
    assert_eq!(decoded, payload);
}

/// @requirement TB-124
#[test]
fn safe_filename_reduces_a_path_to_its_final_component() {
    assert_eq!(safe_filename("../../etc/passwd"), "passwd");
    assert_eq!(safe_filename("/etc/passwd"), "passwd");
    assert_eq!(safe_filename("subdir/inner/notes.txt"), "notes.txt");
    assert_eq!(safe_filename("plain.txt"), "plain.txt");
}

/// @requirement TB-124
#[test]
fn safe_filename_falls_back_to_a_default_for_an_unusable_name() {
    assert_eq!(safe_filename(".."), "file");
    assert_eq!(safe_filename(""), "file");
    assert_eq!(safe_filename("/"), "file");
}

#[test]
fn default_download_dir_is_under_aloo_dir() {
    let dir = default_download_dir();
    assert_eq!(dir.file_name().unwrap(), "downloads");
    assert_eq!(dir.parent().unwrap().file_name().unwrap(), ".aloo");
}

/// @requirement TB-140
#[test]
fn truncate_filename_leaves_a_short_name_untouched() {
    assert_eq!(truncate_filename("report.pdf"), "report.pdf");
    assert_eq!(truncate_filename(""), "");
}

/// @requirement TB-140
#[test]
fn truncate_filename_crops_a_long_name_at_the_end() {
    let long = "a".repeat(500);
    let cropped = truncate_filename(&long);
    assert_eq!(cropped.chars().count(), MAX_FILENAME_CHARS);
    assert_eq!(cropped, "a".repeat(MAX_FILENAME_CHARS));

    // A name exactly at the limit is untouched; one character over is
    // cropped by exactly one character.
    let exact = "b".repeat(MAX_FILENAME_CHARS);
    assert_eq!(truncate_filename(&exact), exact);
    let one_over = "b".repeat(MAX_FILENAME_CHARS + 1);
    assert_eq!(
        truncate_filename(&one_over).chars().count(),
        MAX_FILENAME_CHARS
    );
}

/// @requirement TB-140
#[test]
fn truncate_filename_counts_unicode_scalar_values_not_bytes() {
    // Each of these is a multi-byte UTF-8 character but a single `char` -
    // truncation must crop by character count, not raw byte length, or a
    // multi-byte character could be split mid-encoding.
    let long = "\u{00e9}".repeat(MAX_FILENAME_CHARS + 10); // 'é', 2 bytes each
    let cropped = truncate_filename(&long);
    assert_eq!(cropped.chars().count(), MAX_FILENAME_CHARS);
    assert!(cropped.is_char_boundary(cropped.len()));
}

/// @requirement TB-125, TB-148
#[test]
fn file_chunk_bytes_stays_under_the_p2p_safe_datagram_budget() {
    // Worst-case RSA-OAEP expansion (2048-bit key, docs/PROTOCOL.md §8.1)
    // is ~256/190 per chunk. A `FileChunk` now travels as one direct
    // peer-to-peer UDP datagram (`docs/PROTOCOL.md` §7.0/§7.6), not a
    // TCP-relayed frame, so the constraint that actually matters is
    // `p2p_proto::SAFE_DATAGRAM_BYTES`, not the old `proto::MAX_FRAME_LEN`
    // (which a 64 KiB chunk would clear trivially without saying anything
    // about UDP safety). Leaves a 300-byte margin for the
    // `PunchDatagram::Reliable`/`P2pPayload::FileChunk` framing overhead
    // around the raw ciphertext bytes.
    let worst_case_ciphertext = (FILE_CHUNK_BYTES as f64) * (256.0 / 190.0);
    let framing_overhead = 300.0;
    assert!(
        worst_case_ciphertext + framing_overhead < SAFE_DATAGRAM_BYTES as f64,
        "worst-case {worst_case_ciphertext} + {framing_overhead} framing overhead must stay under SAFE_DATAGRAM_BYTES {}",
        SAFE_DATAGRAM_BYTES
    );
}
