use aloo::client::otp::{apply_incoming_setup, detect_or_adopt_existing, format_now, initiate_provisioning};
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_store::OtpStore;
use aloo::crypto::otp::{
    contact_name_for, otp_size_mb_in_range, OtpKeySetupAckPayload, OtpKeySetupChunk,
    OtpKeySetupPayload, OtpKeySetupReassembly, OTP_SIZE_MB_MAX, OTP_SIZE_MB_MIN,
};
use aloo::proto;
use std::path::PathBuf;

fn fp(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-provisioning-test-{label}-{}-{}",
        std::process::id(),
        fastrand_seed()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fastrand_seed() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn config_at(dir: PathBuf) -> OtpCliConfig {
    OtpCliConfig {
        binary_path: PathBuf::from("otp"),
        working_dir: dir,
    }
}

/// @requirement AC-136
#[test]
fn contact_name_is_order_independent() {
    let a = fp(0x01);
    let b = fp(0x02);
    assert_eq!(contact_name_for(&a, &b), contact_name_for(&b, &a));
}

/// @requirement AC-136
#[test]
fn contact_name_is_deterministic() {
    let a = fp(0xaa);
    let b = fp(0xbb);
    let first = contact_name_for(&a, &b);
    let second = contact_name_for(&a, &b);
    assert_eq!(first, second);
}

/// @requirement AC-136
#[test]
fn contact_name_differs_for_different_pairs() {
    let a = fp(0x01);
    let b = fp(0x02);
    let c = fp(0x03);
    assert_ne!(contact_name_for(&a, &b), contact_name_for(&a, &c));
}

/// @requirement AC-136
#[test]
fn contact_name_satisfies_the_otp_cli_naming_rules() {
    // README: a contact name may not be `.`/`..`, contain a path separator,
    // any of `: * ? " < > | =`, or a control character.
    let name = contact_name_for(&fp(0x00), &fp(0xff));
    assert_ne!(name, ".");
    assert_ne!(name, "..");
    let forbidden = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '='];
    assert!(!name.chars().any(|c| forbidden.contains(&c) || c.is_control()));
}

/// @requirement TB-182
#[test]
fn setup_payload_round_trips_through_the_wire_encoding() {
    let payload = OtpKeySetupPayload {
        contact_name: "abcd-1234".to_string(),
        keypair_size_mb: 1,
        peer_encryption_key: vec![1, 2, 3, 4],
        peer_decryption_key: vec![5, 6, 7, 8],
    };
    let encoded = proto::encode(&payload).unwrap();
    let decoded: OtpKeySetupPayload = proto::decode(&encoded).unwrap();
    assert_eq!(decoded.contact_name, "abcd-1234");
    assert_eq!(decoded.keypair_size_mb, 1);
    assert_eq!(decoded.peer_encryption_key, vec![1, 2, 3, 4]);
    assert_eq!(decoded.peer_decryption_key, vec![5, 6, 7, 8]);
}

/// @requirement AC-138
#[tokio::test]
async fn initiate_provisioning_and_apply_incoming_setup_leave_both_sides_usable() {
    let own_fp = fp(0x10);
    let peer_fp = fp(0x20);
    let alice_cfg = config_at(temp_dir("handshake-alice"));
    let bob_cfg = config_at(temp_dir("handshake-bob"));

    let payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp)
        .await
        .expect("provisioning generation should succeed");
    let expected_contact_name = contact_name_for(&own_fp, &peer_fp);
    assert_eq!(payload.contact_name, expected_contact_name);

    // Alice's own half is already usable immediately after generation.
    assert!(otp_cli::has_contact(&alice_cfg, &expected_contact_name).await.unwrap());

    let ack = apply_incoming_setup(&bob_cfg, &payload).await;
    assert!(ack.accepted, "bob's add-contact should succeed: {:?}", ack.reason);
    assert_eq!(ack.contact_name, expected_contact_name);
    assert!(otp_cli::has_contact(&bob_cfg, &expected_contact_name).await.unwrap());
}

/// @requirement AC-138
#[tokio::test]
async fn detect_or_adopt_existing_finds_a_contact_provisioned_out_of_band() {
    let cfg = config_at(temp_dir("adopt"));
    let contact_name = "already-there";

    // Provision a contact directly through otp_cli, bypassing the
    // handshake entirely - standing in for a user who ran `otp
    // --add-contact` themselves, out-of-band.
    otp_cli::new_key_pair(&cfg, 1, "a", "b").await.unwrap();
    let keys = cfg.working_dir.join("a_keys");
    otp_cli::add_contact(
        &cfg,
        contact_name,
        &keys.join("encryption_for_b.key"),
        &keys.join("decryption_from_b.key"),
    )
    .await
    .unwrap();

    let mut store = OtpStore::new_empty(temp_dir("adopt-store").join("store"));
    assert!(store.get(contact_name).is_none());

    assert!(detect_or_adopt_existing(&cfg, &mut store, contact_name).await);
    assert!(store.get(contact_name).unwrap().provisioned);

    // A second call is a cheap no-op that doesn't need to touch the CLI
    // again - already recorded as provisioned locally.
    assert!(detect_or_adopt_existing(&cfg, &mut store, contact_name).await);
}

/// Reproduces the dead end this whole recovery exists for: alice believes a
/// shared pad already exists for bob (her own keychain genuinely has it -
/// exactly what `detect_or_adopt_existing` would find, e.g. left over from
/// an earlier attempt bob never completed his side of), but bob has
/// nothing. Without recovery, `client::otp::accept_invite`'s "already have
/// a key" branch on bob's side - reproduced directly here via
/// `otp_cli::has_contact` - fails, and a plain retry is a permanent wall:
/// `add_contact` refuses to overwrite alice's still-present stale entry.
///
/// @requirement AC-142
#[tokio::test]
async fn asymmetric_provisioning_is_a_dead_end_without_recovery() {
    let own_fp = fp(0x30);
    let peer_fp = fp(0x40);
    let alice_cfg = config_at(temp_dir("asym-dead-end-alice"));
    let bob_cfg = config_at(temp_dir("asym-dead-end-bob"));
    let contact_name = contact_name_for(&own_fp, &peer_fp);

    let _alice_payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp)
        .await
        .expect("alice's own provisioning should succeed");
    assert!(otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());
    assert!(
        !otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap(),
        "bob never received or applied a matching setup"
    );

    // bob's accept_invite, reproduced: no key material to apply (this would
    // have arrived as a bare OtpSessionRequest), so it falls to checking
    // his own keychain - which doesn't have it.
    assert!(!otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap());

    // A same-name retry (either side generating fresh) hits alice's
    // still-present stale entry rather than fixing anything.
    let retry = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp).await;
    assert!(
        retry.is_none(),
        "add_contact must refuse to overwrite alice's existing entry for this name"
    );
}

/// The actual recovery `client::otp::on_key_setup_ack` performs on
/// `NO_MATCHING_KEY_REASON`: remove the stale local entry, forget it in
/// the store, then a fresh handshake succeeds where it previously
/// deadlocked.
///
/// @requirement AC-142
#[tokio::test]
async fn asymmetric_provisioning_recovers_once_the_stale_contact_is_removed() {
    let own_fp = fp(0x50);
    let peer_fp = fp(0x60);
    let alice_cfg = config_at(temp_dir("asym-recover-alice"));
    let bob_cfg = config_at(temp_dir("asym-recover-bob"));
    let contact_name = contact_name_for(&own_fp, &peer_fp);

    let _stale_payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp)
        .await
        .expect("alice's own (stale) provisioning should succeed");
    assert!(otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());

    let mut alice_store = OtpStore::new_empty(temp_dir("asym-recover-store").join("store"));
    alice_store.mark_provisioned(&contact_name);

    // The recovery: remove alice's stale keychain entry and forget it
    // locally, exactly what on_key_setup_ack does on NO_MATCHING_KEY_REASON.
    otp_cli::remove_contact(&alice_cfg, &contact_name)
        .await
        .expect("removing the stale entry should succeed");
    assert!(alice_store.forget(&contact_name));
    assert!(!otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());
    assert!(alice_store.get(&contact_name).is_none());

    // Now a fresh handshake for the very same contact name succeeds.
    let fresh_payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp)
        .await
        .expect("provisioning should succeed once the stale entry is gone");
    let ack = apply_incoming_setup(&bob_cfg, &fresh_payload).await;
    assert!(ack.accepted, "bob's add-contact should now succeed: {:?}", ack.reason);
    assert!(otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap());
}

/// @requirement TB-184
#[test]
fn format_now_never_panics_and_always_returns_something() {
    let formatted = format_now();
    assert!(!formatted.is_empty());
    // Whichever branch ran (local wall-clock, or the UTC fallback this
    // async test binary is expected to trip - see format_now's doc), the
    // result always at least contains a plausible calendar year.
    assert!(formatted.contains("202") || formatted.contains("203"), "{formatted}");
}

/// @requirement TB-186
#[test]
fn key_setup_chunk_round_trips_through_the_wire_encoding() {
    let chunk = OtpKeySetupChunk {
        contact_name: "abcd-1234".to_string(),
        keypair_size_mb: 1,
        total_len: 4,
        offset: 0,
        enc_chunk: vec![1, 2, 3, 4],
        dec_chunk: vec![5, 6, 7, 8],
    };
    let encoded = proto::encode(&chunk).unwrap();
    let decoded: OtpKeySetupChunk = proto::decode(&encoded).unwrap();
    assert_eq!(decoded.contact_name, "abcd-1234");
    assert_eq!(decoded.keypair_size_mb, 1);
    assert_eq!(decoded.total_len, 4);
    assert_eq!(decoded.offset, 0);
    assert_eq!(decoded.enc_chunk, vec![1, 2, 3, 4]);
    assert_eq!(decoded.dec_chunk, vec![5, 6, 7, 8]);
}

/// Splits `enc`/`dec` (same length) into `chunk_len`-sized `OtpKeySetupChunk`s,
/// exactly like `client::otp::send_key_setup_chunked`'s sending loop.
fn split_into_chunks(
    contact_name: &str,
    enc: &[u8],
    dec: &[u8],
    chunk_len: usize,
) -> Vec<OtpKeySetupChunk> {
    let total_len = enc.len() as u32;
    let mut offset = 0usize;
    let mut chunks = Vec::new();
    loop {
        let end = (offset + chunk_len).min(enc.len());
        chunks.push(OtpKeySetupChunk {
            contact_name: contact_name.to_string(),
            keypair_size_mb: 1,
            total_len,
            offset: offset as u32,
            enc_chunk: enc[offset..end].to_vec(),
            dec_chunk: dec[offset..end].to_vec(),
        });
        if end >= enc.len() {
            return chunks;
        }
        offset = end;
    }
}

/// A whole pad is well past a single UDP datagram's ~65KB ceiling (the
/// default is 1MB per key) - this is the exact scenario that used to be
/// dropped silently on the wire before chunking existed (PROTOCOL.md 16.2).
/// Splitting a multi-megabyte pad into many small chunks and feeding them
/// through `OtpKeySetupReassembly` one at a time must reproduce the
/// original bytes exactly.
///
/// @requirement TB-186
#[test]
fn reassembly_of_a_multi_megabyte_pad_split_into_many_small_chunks_matches_the_original() {
    let contact_name = "abcd-1234";
    let enc: Vec<u8> = (0..2_000_000u32).map(|i| (i % 251) as u8).collect();
    let dec: Vec<u8> = (0..2_000_000u32).map(|i| (i.wrapping_mul(7) % 251) as u8).collect();
    let chunks = split_into_chunks(contact_name, &enc, &dec, 16 * 1024);
    assert!(chunks.len() > 1, "a 2MB pad must actually need more than one chunk");

    let mut reassembly: Option<OtpKeySetupReassembly> = None;
    for chunk in &chunks {
        let acc = reassembly.get_or_insert_with(|| OtpKeySetupReassembly::new(chunk));
        assert!(acc.accept(chunk), "every chunk in order must be accepted");
    }
    let mut acc = reassembly.unwrap();
    assert!(acc.is_complete());
    let (got_enc, got_dec) = acc.take_keys();
    assert_eq!(got_enc, enc);
    assert_eq!(got_dec, dec);
}

/// @requirement TB-186
#[test]
fn reassembly_is_not_complete_until_the_last_chunk_lands() {
    let enc = vec![1u8; 100];
    let dec = vec![2u8; 100];
    let chunks = split_into_chunks("abcd-1234", &enc, &dec, 30);
    assert!(chunks.len() > 1);

    let mut acc = OtpKeySetupReassembly::new(&chunks[0]);
    for chunk in &chunks[..chunks.len() - 1] {
        assert!(acc.accept(chunk));
        assert!(!acc.is_complete());
    }
    assert!(acc.accept(chunks.last().unwrap()));
    assert!(acc.is_complete());
}

/// A chunk from an unrelated, later setup attempt (different
/// `contact_name`) - or one that arrived out of the order the reliable P2P
/// layer is supposed to guarantee - must never be silently splices into an
/// in-progress reassembly.
///
/// @requirement TB-186
#[test]
fn reassembly_rejects_a_chunk_that_does_not_continue_it() {
    let enc = vec![1u8; 64];
    let dec = vec![2u8; 64];
    let chunks = split_into_chunks("abcd-1234", &enc, &dec, 16);
    assert!(chunks.len() > 2);

    let mut acc = OtpKeySetupReassembly::new(&chunks[0]);
    assert!(acc.accept(&chunks[0]));

    // Skips chunk[1] and jumps straight to chunk[2] - wrong offset.
    assert!(!acc.accept(&chunks[2]));

    // A chunk for a different contact entirely, otherwise identical to the
    // legitimate next chunk (same offset/total_len/bytes).
    let other_contact = OtpKeySetupChunk {
        contact_name: "other-contact".to_string(),
        keypair_size_mb: chunks[1].keypair_size_mb,
        total_len: chunks[1].total_len,
        offset: chunks[1].offset,
        enc_chunk: chunks[1].enc_chunk.clone(),
        dec_chunk: chunks[1].dec_chunk.clone(),
    };
    assert!(!acc.accept(&other_contact));
}

/// @requirement TB-182
#[test]
fn setup_ack_payload_round_trips_through_the_wire_encoding() {
    let ack = OtpKeySetupAckPayload {
        contact_name: "abcd-1234".to_string(),
        accepted: false,
        reason: Some("boom".to_string()),
    };
    let encoded = proto::encode(&ack).unwrap();
    let decoded: OtpKeySetupAckPayload = proto::decode(&encoded).unwrap();
    assert_eq!(decoded.contact_name, "abcd-1234");
    assert!(!decoded.accepted);
    assert_eq!(decoded.reason.as_deref(), Some("boom"));
}

/// @requirement AC-144
#[test]
fn otp_size_mb_in_range_matches_the_documented_bounds() {
    assert_eq!(OTP_SIZE_MB_MIN, 1);
    assert_eq!(OTP_SIZE_MB_MAX, 900_000);
    assert!(!otp_size_mb_in_range(0));
    assert!(otp_size_mb_in_range(OTP_SIZE_MB_MIN));
    assert!(otp_size_mb_in_range(500_000));
    assert!(otp_size_mb_in_range(OTP_SIZE_MB_MAX));
    assert!(!otp_size_mb_in_range(OTP_SIZE_MB_MAX + 1));
}
