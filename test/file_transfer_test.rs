use aloo::client::file_transfer::{
    FILE_CHUNK_BYTES, FileOfferPayload, MAX_FILENAME_CHARS, PREVIEW_MAX_BYTES,
    default_download_dir, incoming_preview_dir, is_txt_filename, move_into_dir, read_txt_preview,
    safe_filename, truncate_filename,
};
use aloo::p2p_proto::SAFE_DATAGRAM_BYTES;
use aloo::proto;
use std::path::PathBuf;

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-file-transfer-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

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

/// @requirement AC-329
#[test]
fn incoming_preview_dir_is_under_aloo_tmp() {
    let dir = incoming_preview_dir();
    assert_eq!(dir.file_name().unwrap(), "incoming");
    assert_eq!(dir.parent().unwrap().file_name().unwrap(), "tmp");
    assert_eq!(
        dir.parent().unwrap().parent().unwrap().file_name().unwrap(),
        ".aloo"
    );
}

/// @requirement AC-329
#[test]
fn is_txt_filename_is_case_insensitive_and_requires_the_extension() {
    assert!(is_txt_filename("notes.txt"));
    assert!(is_txt_filename("NOTES.TXT"));
    assert!(is_txt_filename("archive.tar.txt"), "only the last extension matters");
    assert!(!is_txt_filename("notes.txt.gz"), "a .txt in the middle is not the extension");
    assert!(!is_txt_filename("notestxt"), "no dot at all");
    assert!(!is_txt_filename("notes"));
    assert!(!is_txt_filename(""));
}

/// @requirement AC-330
#[test]
fn read_txt_preview_returns_the_whole_file_under_the_cap() {
    let dir = scratch("small");
    let path = dir.join("notes.txt");
    std::fs::write(&path, "hello\nworld").unwrap();

    let (content, truncated) = read_txt_preview(&path).expect("read");
    assert_eq!(content, "hello\nworld");
    assert!(!truncated, "well under PREVIEW_MAX_BYTES");

    std::fs::remove_dir_all(&dir).ok();
}

/// The preview itself stays bounded to `PREVIEW_MAX_BYTES` regardless of
/// how large the real file is - there is no size cap on a file transfer
/// (`there_is_no_size_cap_on_a_file_send`), so a naive whole-file read
/// would be a memory-exhaustion risk for an in-memory preview.
/// @requirement AC-330
#[test]
fn read_txt_preview_caps_and_flags_a_file_over_the_limit() {
    let dir = scratch("large");
    let path = dir.join("big.txt");
    let real_len = PREVIEW_MAX_BYTES + 500;
    std::fs::write(&path, "a".repeat(real_len as usize)).unwrap();

    let (preview, truncated) = read_txt_preview(&path).expect("read");
    assert!(truncated, "the real file is longer than the cap");
    assert_eq!(
        preview.len(),
        PREVIEW_MAX_BYTES as usize,
        "the in-memory preview is bounded even though the file on disk is not"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        real_len,
        "reading a capped preview must not touch the file itself - 'd' still saves it whole"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// `d` inside the preview popup - moving a staged receive into its final
/// directory, keeping its name and content exactly.
/// @requirement AC-331
#[test]
fn move_into_dir_keeps_the_filename_and_content_and_removes_the_source() {
    let staging = scratch("stage-src");
    let dest_dir = scratch("stage-dest");
    let staged_path = staging.join("notes.txt");
    std::fs::write(&staged_path, "keep me exactly").unwrap();

    let dest = move_into_dir(&staged_path, &dest_dir).expect("move");
    assert_eq!(dest.file_name().unwrap(), "notes.txt");
    assert_eq!(dest.parent().unwrap(), dest_dir);
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "keep me exactly");
    assert!(!staged_path.exists(), "moved out of staging, not copied alongside it");

    std::fs::remove_dir_all(&staging).ok();
    std::fs::remove_dir_all(&dest_dir).ok();
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
    // peer-to-peer UDP datagram (`docs/PROTOCOL.md` §7.1/§7.6), not a
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
