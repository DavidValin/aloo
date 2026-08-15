use aloo::file_transfer::{
    default_download_dir, safe_filename, truncate_filename, FileOfferPayload, FILE_CHUNK_BYTES, MAX_FILENAME_CHARS,
};
use aloo::proto;

/// @requirement TB-123
#[test]
fn file_offer_payload_round_trips_through_proto_encode_decode() {
    let payload = FileOfferPayload { filename: "report.pdf".to_string(), size: 12345 };
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
    assert_eq!(truncate_filename(&one_over).chars().count(), MAX_FILENAME_CHARS);
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

/// @requirement TB-125
#[test]
fn file_chunk_bytes_is_well_under_the_frame_limit() {
    // Worst-case RSA-OAEP expansion (2048-bit key, docs/PROTOCOL.md §8.1)
    // is ~256/190 per chunk; a single-recipient `FileChunk` frame must stay
    // comfortably under `proto::MAX_FRAME_LEN`.
    let worst_case_ciphertext = (FILE_CHUNK_BYTES as f64) * (256.0 / 190.0);
    assert!(
        worst_case_ciphertext < proto::MAX_FRAME_LEN as f64,
        "worst-case {worst_case_ciphertext} must stay under MAX_FRAME_LEN {}",
        proto::MAX_FRAME_LEN
    );
}
