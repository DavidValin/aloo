use aloo::file_transfer::{default_download_dir, safe_filename, FilePayload, MAX_FILE_BYTES};
use aloo::proto;

/// @requirement TB-123
#[test]
fn file_payload_round_trips_through_proto_encode_decode() {
    let payload = FilePayload { filename: "report.pdf".to_string(), data: vec![1, 2, 3, 4, 5] };
    let bytes = proto::encode(&payload).expect("encode");
    let decoded: FilePayload = proto::decode(&bytes).expect("decode");
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
    assert_eq!(dir.file_name().unwrap(), "download");
    assert_eq!(dir.parent().unwrap().file_name().unwrap(), ".aloo");
}

/// @requirement TB-125
#[test]
fn max_file_bytes_keeps_a_generously_sized_channel_under_the_frame_limit() {
    // Worst-case RSA-OAEP expansion (2048-bit key, docs/PROTOCOL.md §8.1)
    // is ~256/190; a 20-member channel's SendChannel frame must still fit
    // under proto::MAX_FRAME_LEN.
    let worst_case_ciphertext = (MAX_FILE_BYTES as f64) * (256.0 / 190.0) * 20.0;
    assert!(
        worst_case_ciphertext < proto::MAX_FRAME_LEN as f64,
        "worst-case {worst_case_ciphertext} must stay under MAX_FRAME_LEN {}",
        proto::MAX_FRAME_LEN
    );
}
