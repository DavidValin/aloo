use aloo::client::otp::{
    apply_incoming_setup, commit_pending_setup, decide_end_otp, detect_or_adopt_existing,
    discard_pending_setup, format_now, initiate_provisioning, own_pad_wins_glare,
    pending_setup_dir, read_pending_setup, EndOtpDecision, OTP_SETUP_CHUNK_BYTES,
};
use aloo::client::p2p::PENDING_MAX;
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_store::{OtpContactState, OtpStore, PendingOtpContent};
use aloo::crypto::otp::{
    contact_name_for_keys,
    contact_name_for, contact_name_for_mail, otp_size_mb_in_range, OtpEndSessionPayload,
    OtpKeySetupAckPayload, OtpKeySetupChunk, OtpKeySetupPayload, OtpKeySetupReassembly,
    OtpPurpose, OTP_SIZE_MB_MAX, OTP_SIZE_MB_MIN,
};
use aloo::proto;
use std::path::PathBuf;

fn fp(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Every scratch directory this file makes lives under one root, wiped once
/// per process - these tests generate real pad material, and a test that
/// panics never reaches any cleanup of its own.
fn temp_root() -> &'static std::path::Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join("aloo-otp-provisioning-test");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        root
    })
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = temp_root().join(format!("{label}-{}-{}", std::process::id(), fastrand_seed()));
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

/// Only the tests below that actually spawn the `otp` subprocess need this -
/// see the matching helper (and rationale) in test/otp_cli_test.rs. The pure
/// crypto/wire-encoding tests in this file don't touch the binary at all.
fn require_otp() -> bool {
    let probe = OtpCliConfig {
        binary_path: PathBuf::from("otp"),
        working_dir: std::env::temp_dir(),
    };
    if otp_cli::binary_available(&probe) {
        return true;
    }
    eprintln!(
        "skipping: 'otp' binary not found on PATH (or ALOO_OTP_BIN) - install otp-toolkit to \
         run this test locally: https://github.com/DavidValin/otp-toolkit"
    );
    false
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
    if !require_otp() {
        return;
    }
    let own_fp = fp(0x10);
    let peer_fp = fp(0x20);
    let alice_cfg = config_at(temp_dir("handshake-alice"));
    let bob_cfg = config_at(temp_dir("handshake-bob"));

    let payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Live)
        .await
        .expect("provisioning generation should succeed");
    let expected_contact_name = contact_name_for(&own_fp, &peer_fp);
    assert_eq!(payload.contact_name, expected_contact_name);

    // Alice's own half is staged, deliberately *not* in her keychain yet -
    // nothing is committed there until bob has actually accepted.
    assert!(
        !otp_cli::has_contact(&alice_cfg, &expected_contact_name).await.unwrap(),
        "the initiating side must not hold a contact the peer has not accepted"
    );

    let ack = apply_incoming_setup(&bob_cfg, &payload).await;
    assert!(ack.accepted, "bob's add-contact should succeed: {:?}", ack.reason);
    assert_eq!(ack.contact_name, expected_contact_name);
    assert!(otp_cli::has_contact(&bob_cfg, &expected_contact_name).await.unwrap());

    // Bob's acceptance is what commits alice's half, leaving both usable.
    assert!(commit_pending_setup(&alice_cfg, &expected_contact_name).await);
    assert!(otp_cli::has_contact(&alice_cfg, &expected_contact_name).await.unwrap());
    assert!(
        !pending_setup_dir(&alice_cfg, &expected_contact_name).exists(),
        "the staged pad must be removed once it has been adopted"
    );
}

/// The exact regression `/new-otp-mail-key` hit: `initiate_provisioning`
/// used to compute the *live* contact name unconditionally, regardless of
/// `purpose` - so a freshly generated mail key was staged, and would
/// therefore have been installed, under the same name a live `/otp`
/// session uses. Both sides ending up with a "mail" key that was in fact
/// the live one is exactly what made every ordinary DM afterward wrongly
/// ride that pad instead of `pq_hybrid`.
///
/// @requirement AC-294, AC-295
#[tokio::test]
async fn initiate_provisioning_for_mail_purpose_stages_under_the_mail_contact_name() {
    if !require_otp() {
        return;
    }
    let own_fp = fp(0x30);
    let peer_fp = fp(0x40);
    let alice_cfg = config_at(temp_dir("mail-handshake-alice"));
    let bob_cfg = config_at(temp_dir("mail-handshake-bob"));

    let payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Mail)
        .await
        .expect("provisioning generation should succeed");
    let expected_mail_name = contact_name_for_mail(&own_fp, &peer_fp);
    let live_name = contact_name_for(&own_fp, &peer_fp);
    assert_eq!(payload.contact_name, expected_mail_name);
    assert_ne!(
        payload.contact_name, live_name,
        "a mail-purpose handshake must never stage its pad under the live contact name"
    );

    let ack = apply_incoming_setup(&bob_cfg, &payload).await;
    assert!(ack.accepted, "bob's add-contact should succeed: {:?}", ack.reason);
    assert_eq!(ack.contact_name, expected_mail_name);
    assert!(otp_cli::has_contact(&bob_cfg, &expected_mail_name).await.unwrap());
    assert!(
        !otp_cli::has_contact(&bob_cfg, &live_name).await.unwrap(),
        "installing a mail key must never also create a live-purpose keychain entry"
    );

    assert!(commit_pending_setup(&alice_cfg, &expected_mail_name).await);
    assert!(otp_cli::has_contact(&alice_cfg, &expected_mail_name).await.unwrap());
    assert!(
        !otp_cli::has_contact(&alice_cfg, &live_name).await.unwrap(),
        "the initiating side must not end up with a live-purpose entry either"
    );
}

/// @requirement AC-138
#[tokio::test]
async fn detect_or_adopt_existing_finds_a_contact_provisioned_out_of_band() {
    if !require_otp() {
        return;
    }
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
/// An invitation that is never accepted - the peer went offline, refused,
/// or simply never answered - must leave the initiating side exactly as it
/// found it. Nothing is committed to the keychain until the peer accepts,
/// so a later `/otp` between the same two people generates a fresh pad
/// instead of meeting a stale half of an abandoned one.
///
/// This used to be a dead end: the initiating side adopted its own half
/// immediately, and since the contact name is derived from both
/// fingerprints (so every retry produces the identical name) and
/// `add_contact` refuses to overwrite, every later attempt hit that stale
/// entry instead of fixing anything.
///
/// @requirement AC-142
#[tokio::test]
async fn an_invitation_that_is_never_accepted_leaves_no_stale_contact() {
    if !require_otp() {
        return;
    }
    let own_fp = fp(0x30);
    let peer_fp = fp(0x40);
    let alice_cfg = config_at(temp_dir("never-accepted-alice"));
    let bob_cfg = config_at(temp_dir("never-accepted-bob"));
    let contact_name = contact_name_for(&own_fp, &peer_fp);

    let _abandoned = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Live)
        .await
        .expect("alice's own provisioning should succeed");
    assert!(
        !otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap(),
        "an unaccepted invitation must not put anything in the keychain"
    );

    // Bob never received it, so neither side holds anything.
    assert!(!otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap());

    // The invitation is abandoned, and a second attempt succeeds where it
    // previously deadlocked - all the way to both sides being usable.
    discard_pending_setup(&alice_cfg, &contact_name);
    let retry = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Live)
        .await
        .expect("a fresh attempt must succeed after an abandoned one");
    let ack = apply_incoming_setup(&bob_cfg, &retry).await;
    assert!(ack.accepted, "bob should accept the fresh pad: {:?}", ack.reason);
    assert!(commit_pending_setup(&alice_cfg, &contact_name).await);
    assert!(otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());
    assert!(otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap());
}

/// A pad still owed to a peer is re-sent from what was staged on disk, so a
/// retry offers the *same* pad rather than a second one. Two different pads
/// under one contact name have no integrity check to tell them apart, and
/// would decode to silent garbage.
///
/// @requirement AC-142
#[tokio::test]
async fn a_pending_setup_is_re_readable_for_retries_and_identical_each_time() {
    if !require_otp() {
        return;
    }
    let own_fp = fp(0x31);
    let peer_fp = fp(0x41);
    let alice_cfg = config_at(temp_dir("retry-readback-alice"));
    let contact_name = contact_name_for(&own_fp, &peer_fp);

    let first = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Live)
        .await
        .expect("provisioning should succeed");
    let again = read_pending_setup(&alice_cfg, &contact_name, 1)
        .expect("a staged pad must be readable back for a retry");
    assert_eq!(
        (&again.peer_encryption_key, &again.peer_decryption_key),
        (&first.peer_encryption_key, &first.peer_decryption_key),
        "a retry must offer byte-identical key material, never a fresh pad"
    );

    // Once discarded there is nothing to retry, which is what stops a
    // finished invitation from being re-offered forever.
    discard_pending_setup(&alice_cfg, &contact_name);
    assert!(read_pending_setup(&alice_cfg, &contact_name, 1).is_none());
}

/// The actual recovery `client::otp::on_key_setup_ack` performs on
/// `NO_MATCHING_KEY_REASON`: remove the stale local entry, forget it in
/// the store, then a fresh handshake succeeds where it previously
/// deadlocked.
///
/// @requirement AC-142
#[tokio::test]
async fn asymmetric_provisioning_recovers_once_the_stale_contact_is_removed() {
    if !require_otp() {
        return;
    }
    let own_fp = fp(0x50);
    let peer_fp = fp(0x60);
    let alice_cfg = config_at(temp_dir("asym-recover-alice"));
    let bob_cfg = config_at(temp_dir("asym-recover-bob"));
    let contact_name = contact_name_for(&own_fp, &peer_fp);

    // A stale entry can still arise even though provisioning no longer
    // commits early: this is a contact that genuinely completed once (or was
    // provisioned out of band and adopted by `detect_or_adopt_existing`) and
    // whose counterpart has since lost their half.
    let _stale_payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Live)
        .await
        .expect("alice's own (stale) provisioning should succeed");
    assert!(commit_pending_setup(&alice_cfg, &contact_name).await);
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
    let fresh_payload = initiate_provisioning(&alice_cfg, 1, &own_fp, &peer_fp, OtpPurpose::Live)
        .await
        .expect("provisioning should succeed once the stale entry is gone");
    let ack = apply_incoming_setup(&bob_cfg, &fresh_payload).await;
    assert!(ack.accepted, "bob's add-contact should now succeed: {:?}", ack.reason);
    assert!(commit_pending_setup(&alice_cfg, &contact_name).await);
    assert!(otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap());
    assert!(otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());
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

/// The ceiling is the real `otp` binary's own documented streaming limit -
/// 1TB per key (README.md "Keychain Features") - expressed in MB.
///
/// @requirement AC-144
#[test]
fn otp_size_mb_in_range_matches_the_documented_bounds() {
    assert_eq!(OTP_SIZE_MB_MIN, 1);
    assert_eq!(OTP_SIZE_MB_MAX, 1_048_576, "1 TiB, in MB per key");
    assert!(!otp_size_mb_in_range(0));
    assert!(otp_size_mb_in_range(OTP_SIZE_MB_MIN));
    assert!(otp_size_mb_in_range(500_000));
    assert!(otp_size_mb_in_range(OTP_SIZE_MB_MAX));
    assert!(!otp_size_mb_in_range(OTP_SIZE_MB_MAX + 1));
}

/// The pad is handed to the direct link as one burst of chunked envelopes,
/// usually while that link is still being punched - so all of them queue.
/// Overflowing the link's queue drops its *oldest* entries, which is the
/// front of the pad: the receiving side then reassembles from a chunk that
/// isn't the first one and reports a malformed setup. The smallest pad the
/// size prompt allows must therefore still fit the queue whole, with room
/// left over for the ordinary traffic already sitting in it.
///
/// @requirement TB-203
#[test]
fn the_smallest_pad_fits_a_links_pending_queue_whole() {
    let bytes_per_key = OTP_SIZE_MB_MIN as usize * 1024 * 1024;
    let chunks = bytes_per_key.div_ceil(OTP_SETUP_CHUNK_BYTES);
    assert!(
        chunks < PENDING_MAX,
        "a {OTP_SIZE_MB_MIN}MB pad is {chunks} chunks but a link only queues {PENDING_MAX} - \
         its front would be dropped and the setup would arrive malformed"
    );
}

/// A pad whose first chunk never arrived cannot be reassembled from what
/// did: a fresh accumulation only ever starts at offset zero.
///
/// @requirement TB-203
#[test]
fn reassembly_cannot_start_from_anything_but_the_first_chunk() {
    let enc = vec![1u8; 4096];
    let dec = vec![2u8; 4096];
    let chunks = split_into_chunks("c", &enc, &dec, 1024);
    let mut acc = OtpKeySetupReassembly::new(&chunks[1]);
    assert!(
        !acc.accept(&chunks[1]),
        "a mid-pad chunk with nothing before it must be refused, not treated as a pad start"
    );
}

/// Both users press `/otp` before either has answered the other. The contact
/// name is derived from the pair, so the two generated pads compete for one
/// name and only one may ever be adopted - a pair that adopted one each
/// would hold halves of two different pads, which nothing can tell apart and
/// which would encrypt to silent garbage.
///
/// The tie is broken the way simultaneous link opens already are: the
/// smaller fingerprint's pad wins, computed identically on both sides from
/// values they already have.
///
/// @requirement AC-142
#[test]
fn simultaneous_invitations_are_resolved_the_same_way_by_both_sides() {
    let low = fp(0x70);
    let high = fp(0x71);
    assert!(
        own_pad_wins_glare(&low, &high),
        "the smaller fingerprint's pad wins"
    );
    assert!(
        !own_pad_wins_glare(&high, &low),
        "and the larger one's loses - so exactly one pad survives"
    );
    // The decisive property: the two sides never both believe they won, and
    // never both believe they lost.
    assert_ne!(
        own_pad_wins_glare(&low, &high),
        own_pad_wins_glare(&high, &low)
    );
}

/// The losing side drops its own staged pad, so only the winner's is ever
/// adopted and both keychains end up holding halves of the *same* pad.
///
/// @requirement AC-142
#[tokio::test]
async fn a_glare_leaves_both_sides_holding_halves_of_one_pad() {
    if !require_otp() {
        return;
    }
    let alice_fp = fp(0x70);
    let bob_fp = fp(0x71);
    let alice_cfg = config_at(temp_dir("glare-alice"));
    let bob_cfg = config_at(temp_dir("glare-bob"));
    let contact_name = contact_name_for(&alice_fp, &bob_fp);

    // Both generate before either has answered.
    let pad_a = initiate_provisioning(&alice_cfg, 1, &alice_fp, &bob_fp, OtpPurpose::Live)
        .await
        .expect("alice's pad");
    let _pad_b = initiate_provisioning(&bob_cfg, 1, &bob_fp, &alice_fp, OtpPurpose::Live)
        .await
        .expect("bob's pad");

    // alice's fingerprint is the smaller one, so her pad wins: bob concedes,
    // dropping his own staged pad rather than offering it.
    assert!(own_pad_wins_glare(&alice_fp, &bob_fp));
    discard_pending_setup(&bob_cfg, &contact_name);
    assert!(
        read_pending_setup(&bob_cfg, &contact_name, 1).is_none(),
        "the conceding side must not keep a pad it can never have adopted"
    );

    // bob accepts alice's pad, and alice commits her own half on his ack.
    let ack = apply_incoming_setup(&bob_cfg, &pad_a).await;
    assert!(ack.accepted, "bob should adopt the winning pad: {:?}", ack.reason);
    assert!(commit_pending_setup(&alice_cfg, &contact_name).await);

    assert!(otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());
    assert!(otp_cli::has_contact(&bob_cfg, &contact_name).await.unwrap());
}

/// Accepting a peer's invitation retires any pad of this side's own still
/// staged for the same contact. Otherwise it would be re-offered later and
/// its commit would collide with the pad just adopted - the sequential form
/// of the same race.
///
/// @requirement AC-142
#[tokio::test]
async fn accepting_a_peers_pad_retires_this_sides_own_staged_one() {
    if !require_otp() {
        return;
    }
    let alice_fp = fp(0x72);
    let bob_fp = fp(0x73);
    let alice_cfg = config_at(temp_dir("retire-alice"));
    let bob_cfg = config_at(temp_dir("retire-bob"));
    let contact_name = contact_name_for(&alice_fp, &bob_fp);

    let _mine = initiate_provisioning(&alice_cfg, 1, &alice_fp, &bob_fp, OtpPurpose::Live)
        .await
        .expect("alice's own pad");
    let theirs = initiate_provisioning(&bob_cfg, 1, &bob_fp, &alice_fp, OtpPurpose::Live)
        .await
        .expect("bob's pad");

    // alice adopts bob's pad; her own staged one is retired at that moment.
    let ack = apply_incoming_setup(&alice_cfg, &theirs).await;
    assert!(ack.accepted, "{:?}", ack.reason);
    discard_pending_setup(&alice_cfg, &contact_name);

    assert!(
        read_pending_setup(&alice_cfg, &contact_name, 1).is_none(),
        "a pad that can never be adopted must not survive to be re-offered"
    );
    assert!(otp_cli::has_contact(&alice_cfg, &contact_name).await.unwrap());
}

// ---------------------------------------------------------------------
// /endotp's pure decision (docs/PROTOCOL.md 16.6)
// ---------------------------------------------------------------------

/// @requirement TB-212
#[test]
fn decide_end_otp_refuses_when_nothing_is_provisioned() {
    assert_eq!(decide_end_otp(None), EndOtpDecision::NoActiveSession);
    let unprovisioned = OtpContactState::default();
    assert_eq!(
        decide_end_otp(Some(&unprovisioned)),
        EndOtpDecision::NoActiveSession
    );
}

/// A mail send still awaiting this contact's pad gate must never be stranded
/// by `/endotp` clearing that gate's own bookkeeping out from under it - see
/// `EndOtpDecision::MailInFlight`'s doc.
///
/// @requirement TB-212
#[test]
fn decide_end_otp_refuses_while_a_mail_is_in_flight() {
    let state = OtpContactState {
        provisioned: true,
        pending_unacked_out_seq: Some(3),
        pending_content: Some(PendingOtpContent::Mail {
            mail_id: "m1".to_string(),
        }),
        ..Default::default()
    };
    assert_eq!(decide_end_otp(Some(&state)), EndOtpDecision::MailInFlight);
}

/// Unlike a mail spend, a live P2P text/file/voice send outstanding for a
/// contact has no second store depending on that gate's bookkeeping
/// surviving, so it must not block `/endotp` - the far side simply never
/// gets that message's acknowledgement, the same outcome a permanently
/// vanished peer already produces today.
///
/// @requirement TB-212
#[test]
fn decide_end_otp_allows_ending_with_a_plain_pending_send() {
    let state = OtpContactState {
        provisioned: true,
        pending_unacked_out_seq: Some(3),
        pending_content: Some(PendingOtpContent::Text { channel: None }),
        ..Default::default()
    };
    assert_eq!(decide_end_otp(Some(&state)), EndOtpDecision::End);
}

/// @requirement TB-212
#[test]
fn decide_end_otp_allows_ending_a_quiescent_session() {
    let state = OtpContactState {
        provisioned: true,
        ..Default::default()
    };
    assert_eq!(decide_end_otp(Some(&state)), EndOtpDecision::End);
}

/// One shape carries both `Content::OtpEndSession` and its
/// `Content::OtpEndSessionAck` reply - see `OtpEndSessionPayload`'s doc.
///
/// @requirement AC-192
#[test]
fn end_session_payload_round_trips_through_the_wire_encoding() {
    let payload = OtpEndSessionPayload {
        contact_name: "abcd-1234".to_string(),
    };
    let encoded = proto::encode(&payload).unwrap();
    let decoded: OtpEndSessionPayload = proto::decode(&encoded).unwrap();
    assert_eq!(decoded.contact_name, "abcd-1234");
}

#[test]
fn zz_scratch_measure_chunk_dgram() {
    let chunk = OtpKeySetupChunk {
        contact_name: "aabbccddeeff001122334455-66778899aabbccddeeff0011".to_string(),
        keypair_size_mb: 1,
        total_len: 1024 * 1024,
        offset: 0,
        enc_chunk: vec![7u8; OTP_SETUP_CHUNK_BYTES],
        dec_chunk: vec![9u8; OTP_SETUP_CHUNK_BYTES],
    };
    let encoded = proto::encode(&chunk).unwrap();
    eprintln!("OTP_SETUP_CHUNK_BYTES = {}", OTP_SETUP_CHUNK_BYTES);
    eprintln!("bincode-encoded chunk plaintext = {} bytes", encoded.len());
    eprintln!("chunks for a 1MB/key pad = {}", (1024*1024usize).div_ceil(OTP_SETUP_CHUNK_BYTES));
}

// ---------------------------------------------------------------------
// Pure-OTP mode: which framing applies, and what each one rests on
// ---------------------------------------------------------------------

use aloo::client::otp::{OtpFraming, framing_for};

/// The bytes a `pq_hybrid` peer announces in `UserInfo::public_key_der`.
fn announced_bundle() -> Vec<u8> {
    let (public, _) =
        aloo::crypto::pq::generate_bundle_with_bits(1024).expect("bundle");
    proto::encode(&public).expect("encode")
}

/// Scenario 1 - both sides announced a readable `pq_hybrid` keybundle,
/// which is every pair reached through a server. The pad wraps an ordinary
/// envelope, and the envelope's own signature applies on top of the pad's
/// decrypt verdict.
/// @requirement AC-082
#[test]
fn two_readable_keybundles_get_the_wrapped_framing() {
    assert_eq!(
        framing_for(&announced_bundle(), &announced_bundle()),
        OtpFraming::PqWrapped
    );
}

/// Scenario 2 - one side or the other has no readable keybundle. An
/// envelope can only be built if this side can sign one *and* the other
/// can open it, so a single unreadable key is enough to drop to direct
/// framing. This is exactly a serverless direct-punch peer
/// (`docs/PROTOCOL.md` §7.1.5), known only by an `id_store` pin that is
/// not a bundle: a pad both sides already hold still carries the
/// conversation.
/// @requirement AC-082
#[test]
fn an_unreadable_key_on_either_side_means_direct_framing() {
    let readable = announced_bundle();
    for (own, peer) in [
        (readable.clone(), Vec::new()),
        (Vec::new(), readable.clone()),
        (Vec::new(), Vec::new()),
        (readable.clone(), b"not a bundle at all".to_vec()),
        (b"not a bundle at all".to_vec(), readable.clone()),
    ] {
        assert_eq!(
            framing_for(&own, &peer),
            OtpFraming::Direct,
            "neither side can carry an inner envelope unless both keys read"
        );
    }
}

/// The framing decision reads only the two keys, and reads them the same
/// way whichever order they arrive in - so both ends of one pair reach the
/// same answer, and one never wraps while the other expects bare
/// plaintext.
/// @requirement AC-082
#[test]
fn both_ends_of_a_pair_agree_on_the_framing() {
    let alice = announced_bundle();
    let bob = announced_bundle();
    let opaque = b"not a bundle at all".to_vec();
    for (a, b) in [
        (alice.clone(), bob.clone()),
        (alice.clone(), opaque.clone()),
        (opaque.clone(), opaque.clone()),
    ] {
        assert_eq!(
            framing_for(&a, &b),
            framing_for(&b, &a),
            "the pair must be framed identically from either side"
        );
    }
}

/// **The impersonation defence.** A pad is looked up by a name derived from
/// the two pinned keys, so someone who takes a familiar *nickname* but holds
/// a different key derives a different name - finds no pad under it, and
/// gets none of ours spent on them.
///
/// This matters even though they could never read what we sent: encrypting
/// consumes our key irreversibly, so a message sent to an impostor destroys
/// pad the real contact still needs and leaves the two sides' offsets out of
/// step. Confidentiality was never the exposure; the pad's survival was.
#[test]
fn an_impersonator_with_the_same_nickname_derives_a_different_contact_name() {
    let own = b"my-own-pinned-key";
    let real_bob = b"the-real-bobs-pinned-key";
    let impostor = b"an-impostor-who-took-the-name-bob";

    let real = contact_name_for_keys(own, real_bob);
    let fake = contact_name_for_keys(own, impostor);
    assert_ne!(
        real, fake,
        "an impersonator must never resolve to the pad we hold for the real contact"
    );
}

/// Both sides derive the identical name from their own and their peer's
/// key, with nothing negotiated - the same order-independence the
/// fingerprint-derived name has.
#[test]
fn a_key_derived_contact_name_is_order_independent_and_stable() {
    let a = b"alices-key";
    let b = b"bobs-key";
    assert_eq!(contact_name_for_keys(a, b), contact_name_for_keys(b, a));
    assert_eq!(contact_name_for_keys(a, b), contact_name_for_keys(a, b));
    assert_ne!(contact_name_for_keys(a, b), contact_name_for_keys(a, b"carols-key"));
}

/// A key-derived name has to satisfy the same CLI naming rules a
/// fingerprint-derived one does, or `otp --add-contact` would refuse the
/// pad it is meant to file.
#[test]
fn a_key_derived_contact_name_satisfies_the_otp_cli_naming_rules() {
    let forbidden = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '='];
    let name = contact_name_for_keys(b"own", b"peer");
    assert_ne!(name, ".");
    assert_ne!(name, "..");
    assert!(!name.chars().any(|c| forbidden.contains(&c) || c.is_control()));
    assert!(!name.is_empty());
}

// ---------------------------------------------------------------------
// The pad as a second factor: bounding what an unproved peer can extract
// ---------------------------------------------------------------------

/// Holding the identity key that *selects* a contact is not the same as
/// holding that contact's pad. Only the pad can produce a message `otp`
/// will accept - and only a party that opened one can name the nonce
/// buried inside it, which is exactly what the acknowledgement must carry.
///
/// So the bound falls out of the send gate itself: the first message goes
/// out on the strength of the identity, and the second waits on an
/// acknowledgement that a pad-less impersonator cannot produce.
///
/// @requirement AC-250
#[test]
fn a_peer_without_the_pad_cannot_unblock_a_second_message() {
    let mut store = OtpStore::new_empty(temp_dir("impostor").join("otp-store"));
    let nonce = b"the nonce alice buried under the pad";
    let proof = aloo::crypto::otp::ack_proof_for(nonce);
    let blocked = |s: &OtpStore| s.get("alice-bob").and_then(|c| c.pending_unacked_out_seq).is_some();

    store.record_sent(
        "alice-bob",
        0,
        PendingOtpContent::Text { channel: None },
        Some(proof),
    );
    assert!(blocked(&store), "the first message closes the gate behind it");

    // An impostor saw the packet, so it can quote the sequence number - but
    // the nonce was under the pad, and it has no pad.
    assert!(!store.record_acked("alice-bob", 0, Some([0xAB; 32])));
    assert!(
        blocked(&store),
        "a peer that cannot name the message must not receive a second one"
    );

    // The genuine contact decrypted it, so it can.
    assert!(store.record_acked("alice-bob", 0, Some(proof)));
    assert!(!blocked(&store), "real proof releases what was held behind the gate");
}

/// The bound is per contact - one contact's proof says nothing about
/// another's, because each has its own pad and its own nonce.
///
/// @requirement AC-250
#[test]
fn proving_one_contact_does_not_unblock_a_different_one() {
    let mut store = OtpStore::new_empty(temp_dir("two-contacts").join("otp-store"));
    let bob_proof = aloo::crypto::otp::ack_proof_for(b"bob nonce");
    let carol_proof = aloo::crypto::otp::ack_proof_for(b"carol nonce");
    store.record_sent("alice-bob", 0, PendingOtpContent::Text { channel: None }, Some(bob_proof));
    store.record_sent("alice-carol", 0, PendingOtpContent::Text { channel: None }, Some(carol_proof));

    assert!(store.record_acked("alice-bob", 0, Some(bob_proof)));
    assert!(
        !store.record_acked("alice-carol", 0, Some(bob_proof)),
        "bob's proof must not open carol's gate"
    );
    assert!(store.record_acked("alice-carol", 0, Some(carol_proof)));
}

/// A file transfer's content phase and a voice message carry the user's
/// bytes verbatim under the pad, so there is nowhere to bury a nonce. The
/// plaintext's own digest stands in, and it proves the same thing: it can
/// only be named by someone who decrypted the content.
///
/// @requirement AC-250
#[test]
fn a_whole_file_spend_proves_itself_with_the_plaintexts_digest() {
    let dir = temp_dir("ack-file");
    let a = dir.join("a.bin");
    let b = dir.join("b.bin");
    std::fs::write(&a, b"the recording that was actually sent").unwrap();
    std::fs::write(&b, b"the recording that was actually sent").unwrap();

    let sent = aloo::crypto::otp::ack_proof_for_file(&a).unwrap();
    let received = aloo::crypto::otp::ack_proof_for_file(&b).unwrap();
    assert_eq!(
        sent, received,
        "both sides must reach the same proof from the same plaintext, independently"
    );

    std::fs::write(&b, b"the recording that was actually sen_").unwrap();
    assert_ne!(
        sent,
        aloo::crypto::otp::ack_proof_for_file(&b).unwrap(),
        "a single differing byte must not be acknowledgeable as this message"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The pad tool writes *four* files of the chosen size, not two - both
/// halves land in both correspondents' key directories - so a pad needs
/// four times its per-key size on disk. Measured against the real binary
/// rather than assumed; nothing in its documentation states it.
///
/// Getting this wrong is expensive in the worst way: generation appears to
/// start, the disk fills partway through, and the failure surfaces from
/// inside the tool long after the user committed to waiting.
///
/// @requirement AC-254
#[test]
fn a_pads_disk_cost_is_four_times_its_per_key_size() {
    use aloo::client::otp_cli::keygen_disk_bytes;
    assert_eq!(keygen_disk_bytes(1), 4 * 1024 * 1024);
    assert_eq!(
        keygen_disk_bytes(2000),
        8_388_608_000,
        "a 2000MB pad is 8GB on disk, which is the figure worth refusing on"
    );
}

/// The check must fail *open*: a filesystem it cannot measure is not a
/// reason to refuse work that would have succeeded.
///
/// @requirement AC-254
#[test]
fn free_space_is_reported_for_a_real_directory_and_absent_for_a_missing_one() {
    use aloo::client::otp_cli::free_space_bytes;
    let dir = temp_dir("free-space");
    assert!(
        free_space_bytes(&dir).is_some_and(|free| free > 0),
        "a directory that exists must report something to compare against"
    );
    assert!(
        free_space_bytes(&dir.join("no-such-subdirectory")).is_none(),
        "an unmeasurable path must read as unknown, so the caller proceeds rather than refusing"
    );
}

/// Which pad is installed, not merely that one is - the discriminator that
/// keeps a re-delivery apart from a new proposal.
///
/// @requirement AC-256
#[test]
fn a_pads_identity_is_the_pair_of_its_half_digests() {
    use aloo::crypto::otp::pad_pair_digest;
    let a = [1u8; 32];
    let b = [2u8; 32];
    assert_eq!(pad_pair_digest(&a, &b), pad_pair_digest(&a, &b));
    assert_ne!(
        pad_pair_digest(&a, &b),
        pad_pair_digest(&b, &a),
        "the halves are not interchangeable - one encrypts, the other decrypts"
    );
    assert_ne!(
        pad_pair_digest(&a, &b),
        pad_pair_digest(&a, &[3u8; 32]),
        "a pad differing in either half is a different pad"
    );
}

/// A store records the pad it installed, and only that pad reads back as
/// installed - which is what stops a *new* pad being silently accepted as
/// a re-delivery and leaving the two sides holding different key material.
///
/// @requirement AC-256
#[test]
fn only_the_recorded_pad_reads_back_as_installed() {
    let mut store = OtpStore::new_empty(temp_dir("installed-pad").join("otp-store"));
    let installed = aloo::crypto::otp::pad_pair_digest(&[7u8; 32], &[8u8; 32]);
    let other = aloo::crypto::otp::pad_pair_digest(&[7u8; 32], &[9u8; 32]);

    store.mark_provisioned_with_pad("alice-bob", installed);
    assert!(store.is_installed_pad("alice-bob", installed));
    assert!(
        !store.is_installed_pad("alice-bob", other),
        "a different pad must never pass as the one already installed"
    );

    // A contact adopted from an existing keychain entry records no pad, so
    // it can only ever ask.
    store.mark_provisioned("alice-carol");
    assert!(!store.is_installed_pad("alice-carol", installed));
}

/// The size rides with the request, so the deciding side weighs it before
/// anything is generated rather than after it has all arrived.
///
/// @requirement AC-257
#[test]
fn a_session_request_carries_the_pad_size_it_is_proposing() {
    use aloo::crypto::otp::OtpSessionRequestPayload;
    let fresh = OtpSessionRequestPayload {
        contact_name: "alice-bob".to_string(),
        pad_size_mb: Some(500),
    };
    let decoded: OtpSessionRequestPayload =
        proto::decode(&proto::encode(&fresh).unwrap()).unwrap();
    assert_eq!(decoded.pad_size_mb, Some(500));
    assert_eq!(decoded.contact_name, "alice-bob");

    // A resume asks for no new pad, so there is no size to weigh.
    let resume = OtpSessionRequestPayload {
        contact_name: "alice-bob".to_string(),
        pad_size_mb: None,
    };
    let decoded: OtpSessionRequestPayload =
        proto::decode(&proto::encode(&resume).unwrap()).unwrap();
    assert_eq!(decoded.pad_size_mb, None);
}
