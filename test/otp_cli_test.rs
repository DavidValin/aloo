//! Exercises `client::otp_cli` against the real `otp` binary
//! (github.com/DavidValin/otp-toolkit) - aloo never reimplements one-time-pad
//! cryptography or keychain formats itself, so these tests need the actual
//! command installed and on `PATH` (or pointed at via `ALOO_OTP_BIN`).

use aloo::client::otp_cli::{self, FileCliOutcome, OtpCliConfig, OtpCliOutcome, RecoverDirection};
use std::path::PathBuf;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-cli-test-{label}-{}-{}",
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

/// @requirement TB-183
#[test]
fn binary_available_is_true_for_the_real_installed_otp() {
    let cfg = config_at(temp_dir("avail"));
    assert!(
        otp_cli::binary_available(&cfg),
        "this test suite requires the real 'otp' binary (github.com/DavidValin/otp-toolkit) on PATH"
    );
}

/// @requirement TB-183
#[tokio::test]
async fn has_contact_is_false_before_any_provisioning() {
    let cfg = config_at(temp_dir("hascontact"));
    assert!(!otp_cli::has_contact(&cfg, "nobody").await.unwrap());
}

/// @requirement TB-183
#[tokio::test]
async fn status_is_none_for_an_unknown_contact() {
    let cfg = config_at(temp_dir("statusnone"));
    assert!(otp_cli::status(&cfg, "nobody").await.unwrap().is_none());
}

/// Provisions a full "alice"/"bob" pair across two independent working
/// directories - the role-inversion the README documents - and returns
/// (alice's config using contact name "bob", bob's config using contact
/// name "alice").
async fn provision_pair(label: &str) -> (OtpCliConfig, OtpCliConfig) {
    let alice_cfg = config_at(temp_dir(&format!("{label}-alice")));
    let bob_cfg = config_at(temp_dir(&format!("{label}-bob")));

    otp_cli::new_key_pair(&alice_cfg, 1, "alice", "bob")
        .await
        .expect("key generation should succeed");

    let alice_keys = alice_cfg.working_dir.join("alice_keys");
    let bob_keys = alice_cfg.working_dir.join("bob_keys");

    otp_cli::add_contact(
        &alice_cfg,
        "bob",
        &alice_keys.join("encryption_for_bob.key"),
        &alice_keys.join("decryption_from_bob.key"),
    )
    .await
    .expect("alice's add-contact should succeed");

    otp_cli::add_contact(
        &bob_cfg,
        "alice",
        &bob_keys.join("encryption_for_alice.key"),
        &bob_keys.join("decryption_from_alice.key"),
    )
    .await
    .expect("bob's add-contact should succeed");

    (alice_cfg, bob_cfg)
}

/// @requirement AC-136
#[tokio::test]
async fn provisioning_then_has_contact_is_true_on_both_sides() {
    let (alice_cfg, bob_cfg) = provision_pair("provision").await;
    assert!(otp_cli::has_contact(&alice_cfg, "bob").await.unwrap());
    assert!(otp_cli::has_contact(&bob_cfg, "alice").await.unwrap());
}

/// @requirement AC-136
#[tokio::test]
async fn a_message_encrypted_by_alice_decrypts_to_the_same_bytes_for_bob() {
    let (alice_cfg, bob_cfg) = provision_pair("roundtrip").await;

    let ciphertext = match otp_cli::encrypt(&alice_cfg, "bob", b"hello bob", false)
        .await
        .unwrap()
    {
        OtpCliOutcome::Ok(bytes) => bytes,
        other => panic!("expected Ok, got {other:?}"),
    };
    assert_ne!(ciphertext, b"hello bob");

    let plaintext = match otp_cli::decrypt(&bob_cfg, "alice", &ciphertext, false)
        .await
        .unwrap()
    {
        OtpCliOutcome::Ok(bytes) => bytes,
        other => panic!("expected Ok, got {other:?}"),
    };
    assert_eq!(plaintext, b"hello bob");
}

/// @requirement AC-137
#[tokio::test]
async fn a_second_encrypt_without_assume_delivered_fails_closed() {
    let (alice_cfg, _bob_cfg) = provision_pair("gate").await;

    // First message in this direction needs no confirmation.
    match otp_cli::encrypt(&alice_cfg, "bob", b"first", false)
        .await
        .unwrap()
    {
        OtpCliOutcome::Ok(_) => {}
        other => panic!("expected Ok, got {other:?}"),
    }

    let status = otp_cli::status(&alice_cfg, "bob").await.unwrap().unwrap();
    assert!(
        status.enc_ack_outstanding,
        "the just-sent message should await confirmation before the next send"
    );

    // A second message, still without a genuine ack, must fail closed
    // rather than silently proceed - there's no controlling terminal to
    // answer the confirmation prompt in a test harness, so this exercises
    // the exact "no blind -y" property the send-path gate depends on.
    match otp_cli::encrypt(&alice_cfg, "bob", b"second", false)
        .await
        .unwrap()
    {
        OtpCliOutcome::Error(_) => {}
        other => panic!("expected Error (confirmation required), got {other:?}"),
    }

    // Only once the caller has genuine proof of delivery (assume_delivered)
    // does the next message actually go through, and the gate re-arms.
    match otp_cli::encrypt(&alice_cfg, "bob", b"second", true)
        .await
        .unwrap()
    {
        OtpCliOutcome::Ok(_) => {}
        other => panic!("expected Ok, got {other:?}"),
    }
    let status = otp_cli::status(&alice_cfg, "bob").await.unwrap().unwrap();
    assert!(status.enc_ack_outstanding);
    assert_eq!(status.enc_sequence, 2);
}

/// @requirement TB-187
#[tokio::test]
async fn remove_contact_deletes_an_existing_contact() {
    let (alice_cfg, _bob_cfg) = provision_pair("remove").await;
    assert!(otp_cli::has_contact(&alice_cfg, "bob").await.unwrap());

    otp_cli::remove_contact(&alice_cfg, "bob")
        .await
        .expect("removing a contact that exists should succeed");
    assert!(!otp_cli::has_contact(&alice_cfg, "bob").await.unwrap());
}

/// @requirement TB-187
#[tokio::test]
async fn remove_contact_on_an_unknown_contact_fails() {
    let cfg = config_at(temp_dir("remove-unknown"));
    assert!(otp_cli::remove_contact(&cfg, "nobody").await.is_err());
}

/// @requirement TB-187
#[tokio::test]
async fn a_removed_contacts_name_can_be_reprovisioned_from_scratch() {
    // The exact recovery `client::otp::on_key_setup_ack` relies on: a name
    // `add_contact` would otherwise refuse as already-existing becomes
    // usable again once the stale entry is actually gone.
    let (alice_cfg, _bob_cfg) = provision_pair("reprovision").await;
    otp_cli::remove_contact(&alice_cfg, "bob").await.unwrap();

    otp_cli::new_key_pair(&alice_cfg, 1, "x", "y")
        .await
        .expect("key generation should succeed");
    let keys = alice_cfg.working_dir.join("x_keys");
    otp_cli::add_contact(
        &alice_cfg,
        "bob",
        &keys.join("encryption_for_y.key"),
        &keys.join("decryption_from_y.key"),
    )
    .await
    .expect("re-adding the same contact name should succeed now that the stale entry is gone");
    assert!(otp_cli::has_contact(&alice_cfg, "bob").await.unwrap());
}

/// @requirement TB-183, AC-147
#[tokio::test]
async fn recover_last_sent_replays_without_consuming_key() {
    let (alice_cfg, _bob_cfg) = provision_pair("recover").await;
    let ciphertext = match otp_cli::encrypt(&alice_cfg, "bob", b"hello", false)
        .await
        .unwrap()
    {
        OtpCliOutcome::Ok(bytes) => bytes,
        other => panic!("expected Ok, got {other:?}"),
    };

    let recovered = otp_cli::recover_last(&alice_cfg, "bob", RecoverDirection::Sent)
        .await
        .unwrap()
        .expect("a safety copy should exist until the next confirmed send");
    assert_eq!(recovered, ciphertext);

    // Repeatable: recovering again doesn't consume or clear the copy.
    let recovered_again = otp_cli::recover_last(&alice_cfg, "bob", RecoverDirection::Sent)
        .await
        .unwrap();
    assert_eq!(recovered_again, Some(ciphertext));
}

/// @requirement AC-145, AC-146
#[tokio::test]
async fn encrypt_file_and_decrypt_file_round_trip_without_buffering_in_memory() {
    let (alice_cfg, bob_cfg) = provision_pair("file-roundtrip").await;

    let src = alice_cfg.working_dir.join("plaintext.bin");
    let big = vec![0xABu8; 200_000]; // large enough that "no in-memory buffering" actually matters
    std::fs::write(&src, &big).unwrap();

    let ciphertext_path = alice_cfg.working_dir.join("ciphertext.bin");
    match otp_cli::encrypt_file(&alice_cfg, "bob", &src, &ciphertext_path, false)
        .await
        .unwrap()
    {
        FileCliOutcome::Ok => {}
        other => panic!("expected Ok, got {other:?}"),
    }
    let ciphertext = std::fs::read(&ciphertext_path).unwrap();
    assert_ne!(ciphertext, big, "must not just be a copy of the plaintext");
    assert_eq!(ciphertext.len(), big.len(), "otp does not expand its input");

    let recovered_path = bob_cfg.working_dir.join("recovered.bin");
    match otp_cli::decrypt_file(&bob_cfg, "alice", &ciphertext_path, &recovered_path, false)
        .await
        .unwrap()
    {
        FileCliOutcome::Ok => {}
        other => panic!("expected Ok, got {other:?}"),
    }
    let recovered = std::fs::read(&recovered_path).unwrap();
    assert_eq!(recovered, big);
}

/// @requirement AC-145
#[tokio::test]
async fn decrypt_file_without_assume_delivered_twice_fails_closed_on_the_second_call() {
    let (alice_cfg, bob_cfg) = provision_pair("file-gate").await;
    let src = alice_cfg.working_dir.join("plaintext.bin");
    std::fs::write(&src, b"hello file gate").unwrap();
    let ciphertext_path = alice_cfg.working_dir.join("ciphertext.bin");
    otp_cli::encrypt_file(&alice_cfg, "bob", &src, &ciphertext_path, false)
        .await
        .unwrap();

    let dst = bob_cfg.working_dir.join("recovered.bin");
    match otp_cli::decrypt_file(&bob_cfg, "alice", &ciphertext_path, &dst, false)
        .await
        .unwrap()
    {
        FileCliOutcome::Ok => {}
        other => panic!("expected Ok, got {other:?}"),
    }

    // A second decrypt of the very same (already-consumed) ciphertext,
    // still without assume_delivered, must fail closed rather than
    // silently consuming more key or succeeding twice.
    match otp_cli::decrypt_file(&bob_cfg, "alice", &ciphertext_path, &dst, false)
        .await
        .unwrap()
    {
        FileCliOutcome::Error(_) => {}
        other => panic!("expected Error (confirmation required), got {other:?}"),
    }
}

/// @requirement TB-188, AC-147
#[tokio::test]
async fn recover_last_file_replays_the_last_sent_ciphertext_without_consuming_key() {
    let (alice_cfg, _bob_cfg) = provision_pair("recover-file").await;
    let src = alice_cfg.working_dir.join("plaintext.bin");
    let content = vec![0x5Au8; 50_000];
    std::fs::write(&src, &content).unwrap();

    let ciphertext_path = alice_cfg.working_dir.join("ciphertext.bin");
    match otp_cli::encrypt_file(&alice_cfg, "bob", &src, &ciphertext_path, false)
        .await
        .unwrap()
    {
        FileCliOutcome::Ok => {}
        other => panic!("expected Ok, got {other:?}"),
    }
    let ciphertext = std::fs::read(&ciphertext_path).unwrap();
    let remaining_after_encrypt = otp_cli::status(&alice_cfg, "bob")
        .await
        .unwrap()
        .unwrap()
        .enc_key_remaining;

    let recovered_path = alice_cfg.working_dir.join("recovered.bin");
    let outcome = otp_cli::recover_last_file(&alice_cfg, "bob", RecoverDirection::Sent, &recovered_path)
        .await
        .unwrap();
    assert_eq!(outcome, Some(()));
    assert_eq!(std::fs::read(&recovered_path).unwrap(), ciphertext);

    // Repeatable: recovering again doesn't consume or clear the safety copy.
    let recovered_path2 = alice_cfg.working_dir.join("recovered2.bin");
    let outcome2 = otp_cli::recover_last_file(&alice_cfg, "bob", RecoverDirection::Sent, &recovered_path2)
        .await
        .unwrap();
    assert_eq!(outcome2, Some(()));
    assert_eq!(std::fs::read(&recovered_path2).unwrap(), ciphertext);

    let remaining_after_recover = otp_cli::status(&alice_cfg, "bob")
        .await
        .unwrap()
        .unwrap()
        .enc_key_remaining;
    assert_eq!(
        remaining_after_encrypt, remaining_after_recover,
        "recovering must not spend any key"
    );
}
