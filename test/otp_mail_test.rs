//! OTP mail's building blocks (docs/PROTOCOL.md §17): mail ids, the local
//! re-pad primitive, the sealed payload's shape and identity signature,
//! the pre-decrypt gate, and - against the real `otp` binary, skipped when
//! it isn't installed (same convention as `otp_cli_test.rs`) - the
//! retry-relevant property that `.last_sent` replays a mail's exact
//! ciphertext.

use aloo::client::otp_cli::{self, OtpCliConfig, OtpCliOutcome, RecoverDirection};
use aloo::client::otp_mail::{MailGate, mail_gate};
use aloo::crypto::otp::{
    OtpMailFile, OtpMailPayload, OtpMailSealed, OtpMailVoice, mail_id_is_valid, new_mail_id,
    repad, xor_pad,
};
use aloo::crypto::pq::{generate_bundle_with_bits, sign_mail, verify_mail};
use aloo::proto;
use std::path::PathBuf;

const TEST_BITS: usize = 1024;

fn temp_dir(label: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "aloo-otp-mail-test-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config_at(dir: PathBuf) -> OtpCliConfig {
    OtpCliConfig {
        binary_path: PathBuf::from("otp"),
        working_dir: dir,
    }
}

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

fn payload() -> OtpMailPayload {
    OtpMailPayload {
        from: "alice".into(),
        to: "bob".into(),
        sent_at_utc: 1_766_000_000,
        subtext: "tonight".into(),
        content: "meet me at six\nby the old bridge".into(),
        voices: vec![OtpMailVoice {
            duration_ms: 1200,
            pcm: vec![7u8; 256],
        }],
        attachments: vec![OtpMailFile {
            filename: "map.png".into(),
            bytes: vec![9u8; 512],
        }],
    }
}

// ---------------------------------------------------------------------
// Mail ids
// ---------------------------------------------------------------------

/// @requirement TB-196
#[test]
fn mail_ids_are_lowercase_hex_and_validated_strictly() {
    let id = new_mail_id();
    assert_eq!(id.len(), 32);
    assert!(mail_id_is_valid(&id));
    assert_ne!(new_mail_id(), id, "ids are random, not sequential");

    for bad in [
        "",
        "abc",
        "ABCDEFABCDEFABCDEFABCDEFABCDEFAB",   // uppercase refused
        "gggggggggggggggggggggggggggggggg",   // non-hex refused
        "../../../etc/passwd/etc/pass0000",   // path shapes refused
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",    // 31 chars
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  // 33 chars
    ] {
        assert!(!mail_id_is_valid(bad), "{bad:?} must be refused");
    }
}

// ---------------------------------------------------------------------
// The local re-pad (ciphertext + pad at rest, plaintext never)
// ---------------------------------------------------------------------

/// @requirement AC-163
#[test]
fn repad_round_trips_and_neither_half_alone_is_the_plaintext() {
    let plaintext = b"the whole decoded mail payload".to_vec();
    let (ct, pad) = repad(&plaintext);
    assert_eq!(ct.len(), plaintext.len());
    assert_eq!(pad.len(), plaintext.len());
    assert_ne!(ct, plaintext);
    assert_ne!(pad, plaintext);
    assert_eq!(xor_pad(&ct, &pad), Some(plaintext));
    // Two re-pads of the same plaintext never share a pad.
    let (_, pad2) = repad(b"the whole decoded mail payload");
    assert_ne!(pad, pad2);
}

/// @requirement AC-163
#[test]
fn xor_pad_refuses_a_length_mismatch() {
    assert_eq!(xor_pad(b"abcd", b"abc"), None);
    assert_eq!(xor_pad(b"", b"a"), None);
    assert_eq!(xor_pad(b"", b""), Some(Vec::new()));
}

// ---------------------------------------------------------------------
// Payload shape and identity signature
// ---------------------------------------------------------------------

/// @requirement AC-154
#[test]
fn a_mail_payload_round_trips_with_voice_and_attachments() {
    let p = payload();
    let encoded = proto::encode(&p).expect("encode");
    let back: OtpMailPayload = proto::decode(&encoded).expect("decode");
    assert_eq!(back, p);
}

/// @requirement TB-195
#[test]
fn sign_mail_verifies_and_rejects_a_flipped_payload() {
    let (public, private) = generate_bundle_with_bits(TEST_BITS).expect("bundle");
    let encoded = proto::encode(&payload()).unwrap();
    let signature = sign_mail(&private, &encoded).expect("sign");
    assert!(verify_mail(&public, &encoded, &signature));

    // A one-time pad is malleable: flipping one ciphertext bit flips the
    // same payload bit undetected by the pad itself. The signature is what
    // catches it.
    let mut tampered = encoded.clone();
    let flip_at = tampered.len() / 2;
    tampered[flip_at] ^= 0x01;
    assert!(!verify_mail(&public, &tampered, &signature));

    // A different identity's signature never verifies either.
    let (other_public, _) = generate_bundle_with_bits(TEST_BITS).expect("bundle");
    assert!(!verify_mail(&other_public, &encoded, &signature));

    // And the sealed wrapper round-trips the pair intact.
    let sealed = OtpMailSealed {
        payload: encoded.clone(),
        signature: signature.clone(),
    };
    let wire = proto::encode(&sealed).unwrap();
    let back: OtpMailSealed = proto::decode(&wire).unwrap();
    assert_eq!(back.payload, encoded);
    assert_eq!(back.signature, signature);
}

/// @requirement TB-195
#[test]
fn mail_signature_domain_is_not_interchangeable_with_rotation() {
    // `sign_mail` commits to a mail-specific domain tag: its output over
    // some bytes must not verify as any other statement about the same
    // bytes. The cheapest cross-check available is that verifying a mail
    // signature against *different* content fails (domain separation's
    // observable half); the rotation/continuity paths have their own
    // domain-committed tests.
    let (public, private) = generate_bundle_with_bits(TEST_BITS).expect("bundle");
    let signature = sign_mail(&private, b"one payload").expect("sign");
    assert!(verify_mail(&public, b"one payload", &signature));
    assert!(!verify_mail(&public, b"another payload", &signature));
}

// ---------------------------------------------------------------------
// The pre-decrypt gate (docs/PROTOCOL.md 17.3)
// ---------------------------------------------------------------------

/// @requirement TB-194
#[test]
fn mail_gate_refuses_a_contact_mismatch_before_the_pad() {
    // Sealed under some other identity's pad - decrypting against the
    // local contact would consume the wrong pad range.
    assert_eq!(
        mail_gate(Some("aaa-bbb"), "aaa-ccc", 0, 0),
        MailGate::RefuseContact
    );
    // No usable pin at all reads the same way.
    assert_eq!(mail_gate(None, "aaa-bbb", 0, 0), MailGate::RefuseContact);
}

/// @requirement TB-194
#[test]
fn mail_gate_reacknowledges_an_already_consumed_sequence() {
    assert_eq!(mail_gate(Some("c"), "c", 5, 4), MailGate::AckOnly);
    assert_eq!(mail_gate(Some("c"), "c", 5, 0), MailGate::AckOnly);
}

/// @requirement TB-194
#[test]
fn mail_gate_waits_for_an_earlier_spend() {
    assert_eq!(mail_gate(Some("c"), "c", 5, 6), MailGate::Wait);
    assert_eq!(mail_gate(Some("c"), "c", 0, 3), MailGate::Wait);
}

/// @requirement TB-194
#[test]
fn mail_gate_admits_only_the_exact_next_sequence() {
    assert_eq!(mail_gate(Some("c"), "c", 0, 0), MailGate::Decrypt);
    assert_eq!(mail_gate(Some("c"), "c", 7, 7), MailGate::Decrypt);
}

// ---------------------------------------------------------------------
// Against the real `otp` binary: the retry property
// ---------------------------------------------------------------------

/// Provisions a full pair across two working directories, exactly like
/// `otp_cli_test::provision_pair`.
async fn provision_pair(label: &str) -> (OtpCliConfig, OtpCliConfig) {
    let alice_cfg = config_at(temp_dir(&format!("{label}-alice")));
    let bob_cfg = config_at(temp_dir(&format!("{label}-bob")));
    otp_cli::new_key_pair(&alice_cfg, 1, "alice", "bob")
        .await
        .expect("key generation");
    let alice_keys = alice_cfg.working_dir.join("alice_keys");
    let bob_keys = alice_cfg.working_dir.join("bob_keys");
    otp_cli::add_contact(
        &alice_cfg,
        "bob",
        &alice_keys.join("encryption_for_bob.key"),
        &alice_keys.join("decryption_from_bob.key"),
    )
    .await
    .expect("alice add-contact");
    otp_cli::add_contact(
        &bob_cfg,
        "alice",
        &bob_keys.join("encryption_for_alice.key"),
        &bob_keys.join("decryption_from_alice.key"),
    )
    .await
    .expect("bob add-contact");
    (alice_cfg, bob_cfg)
}

/// @requirement AC-159, TB-193
#[tokio::test]
async fn a_mails_last_sent_copy_replays_byte_identically_for_retry() {
    if !require_otp() {
        return;
    }
    let (alice_cfg, bob_cfg) = provision_pair("mail-retry").await;

    // Seal a real mail the way the send path does: payload, signature,
    // one otp --encrypt.
    let (_public, private) = generate_bundle_with_bits(TEST_BITS).expect("bundle");
    let encoded = proto::encode(&payload()).unwrap();
    let signature = sign_mail(&private, &encoded).expect("sign");
    let sealed_bytes = proto::encode(&OtpMailSealed {
        payload: encoded.clone(),
        signature,
    })
    .unwrap();
    let Ok(OtpCliOutcome::Ok(ciphertext)) =
        otp_cli::encrypt_retrying(&alice_cfg, "bob", &sealed_bytes, true).await
    else {
        panic!("mail encrypt should succeed");
    };
    assert_ne!(ciphertext, sealed_bytes, "the pad genuinely transformed it");

    // The retry path: `.last_sent` replays the exact ciphertext, byte for
    // byte, without consuming key - repeatably.
    let recovered = otp_cli::recover_last(&alice_cfg, "bob", RecoverDirection::Sent)
        .await
        .expect("recover runs")
        .expect("a copy exists while unconfirmed");
    assert_eq!(recovered, ciphertext);
    let again = otp_cli::recover_last(&alice_cfg, "bob", RecoverDirection::Sent)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again, ciphertext, "recovery is repeatable");

    // And the recipient's one genuine decrypt returns the sealed bytes
    // exactly - what `on_mail_deliver` then signature-checks and re-pads.
    let Ok(OtpCliOutcome::Ok(decrypted)) =
        otp_cli::decrypt_retrying(&bob_cfg, "alice", &ciphertext, true).await
    else {
        panic!("mail decrypt should succeed");
    };
    assert_eq!(decrypted, sealed_bytes);
}

// ---------------------------------------------------------------------
// The send gate opens on the storage ack alone (docs/PROTOCOL.md 17.2)
// ---------------------------------------------------------------------

/// A bare session with no `otp` binary configured - these tests drive the
/// gate through `OtpStore`/`OtpMailStore` directly and the real
/// `on_mail_result`, never through an actual encrypt, so nothing here
/// needs the CLI at all (unlike every test above this point).
async fn bare_session(label: &str) -> (aloo::client::session::SessionState, aloo::client::tui::ui::UiState) {
    let (public, private) = generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let public_der = proto::encode(&public).expect("own pq der");
    let session = aloo::client::session::SessionState::for_test(aloo::client::session::TestSessionSpec {
        identity: aloo::client::connect::ResolvedIdentity { private, public_der },
        scratch: temp_dir(label),
        otp: None,
    })
    .await;
    let ui = aloo::client::tui::ui::UiState::new("alice".into());
    (session, ui)
}

/// The exact property TB-193 describes: what clears a mail's stop-and-wait
/// gate is `OtpMailResult` alone - the server's fast storage
/// acknowledgement - never the recipient actually fetching or decrypting
/// it. Seeds the same `OtpStore`/`OtpMailStore` state `handle_send` would
/// have left behind, then drives the real `on_mail_result` (not a stand-in)
/// and checks the gate with the exact predicate `handle_send`'s own check
/// uses, so a regression in either function is caught.
///
/// @requirement TB-193
#[tokio::test]
async fn a_mails_gate_clears_on_the_storage_ack_alone_never_needing_delivery() {
    let (mut session, mut ui) = bare_session("mail-gate-storage-ack").await;
    let contact = "alice-bob-mail";
    let mail_id = new_mail_id();

    session.otp_store_mut().record_sent(
        contact,
        0,
        aloo::client::otp_store::PendingOtpContent::Mail {
            mail_id: mail_id.clone(),
        },
        None,
    );
    session.otp_mail_store_mut().record_sent(aloo::client::otp_mail_store::SentMailRef {
        mail_id: mail_id.clone(),
        to: "bob".into(),
        contact_name: contact.into(),
        seq: 0,
        sent_at_utc: 0,
        status: aloo::client::otp_mail_store::SentMailStatus::AwaitingServerAck,
    });

    // Before any ack: a second send to this contact is refused - the exact
    // check `otp_mail::handle_send` runs before it will encrypt anything.
    assert!(
        session
            .otp_store_mut()
            .get(contact)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_some(),
        "a previous send must still be held while unacknowledged"
    );

    aloo::client::otp_mail::on_mail_result(
        &mut aloo::control::NullSink,
        &mut session,
        &mut ui,
        mail_id,
        true,
        None,
    )
    .await
    .expect("on_mail_result should never error");

    // The server's storage ack alone opened it - nothing here ever touched
    // `on_mail_delivered`/`OtpMailDeliveredAck`.
    assert!(
        session
            .otp_store_mut()
            .get(contact)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_none(),
        "OtpMailResult alone must open the gate for the next send"
    );
}

/// The failure twin, now the opposite of what it once was (AC-383): a
/// refused storage ack must *not* open the gate. Clearing it used to be
/// justified as "the pad bytes are spent either way, so the contact must
/// not wedge forever" - but that let the *next* mail spend past the
/// refused one, which the receiver could then never decrypt (their
/// `next_expected_in_seq` can only ever be satisfied by this exact
/// ciphertext, docs/PROTOCOL.md 17.3's oldest-first rule) - trading a
/// sender-side wedge for a permanent, silent receiver-side one. Instead the
/// mail stays exactly `AwaitingServerAck` and the gate stays closed on this
/// seq, so the mail can be retried (immediately, or on the next reconnect)
/// until the server genuinely stores it.
///
/// @requirement TB-193, AC-383
#[tokio::test]
async fn a_refused_storage_ack_leaves_the_mail_pending_and_the_gate_closed() {
    let (mut session, mut ui) = bare_session("mail-gate-refused-ack").await;
    let contact = "alice-carol-mail";
    let mail_id = new_mail_id();

    session.otp_store_mut().record_sent(
        contact,
        0,
        aloo::client::otp_store::PendingOtpContent::Mail {
            mail_id: mail_id.clone(),
        },
        None,
    );
    session.otp_mail_store_mut().record_sent(aloo::client::otp_mail_store::SentMailRef {
        mail_id: mail_id.clone(),
        to: "carol".into(),
        contact_name: contact.into(),
        seq: 0,
        sent_at_utc: 0,
        status: aloo::client::otp_mail_store::SentMailStatus::AwaitingServerAck,
    });

    aloo::client::otp_mail::on_mail_result(
        &mut aloo::control::NullSink,
        &mut session,
        &mut ui,
        mail_id.clone(),
        false,
        Some("disk full".into()),
    )
    .await
    .expect("on_mail_result should never error");

    assert_eq!(
        session
            .otp_store_mut()
            .get(contact)
            .and_then(|s| s.pending_unacked_out_seq),
        Some(0),
        "a refusal must not open the gate - nothing may spend past a mail that was never durably stored"
    );
    assert_eq!(
        session.otp_mail_store_mut().sent_ref(&mail_id).map(|r| r.status),
        Some(aloo::client::otp_mail_store::SentMailStatus::AwaitingServerAck),
        "the mail must not be marked Failed - it stays live locally until the server genuinely \
         acknowledges it, exactly like any other still-unacknowledged send"
    );
}

/// A `ControlSink` that records what would have gone to the server, so a
/// test can assert on exactly what a handler decided to send.
#[derive(Default)]
struct RecordingSink {
    sent: Vec<proto::ClientMessage>,
}

impl aloo::control::ControlSink for RecordingSink {
    async fn send_control(&mut self, msg: &proto::ClientMessage) -> proto::Result<()> {
        self.sent.push(msg.clone());
        Ok(())
    }
}

/// The immediate-retry half of AC-383, against the real `otp` binary: not
/// just that the gate stays closed and the mail stays pending (the test
/// above), but that a genuine resend goes out right away, replaying the
/// exact ciphertext `otp --recover-last --sent` holds - proving
/// `resend_one` is really wired into `on_mail_result`'s failure branch,
/// never a fresh re-encode (which would spend a second range of pad for
/// one mail).
///
/// @requirement AC-383
#[tokio::test]
async fn a_refused_storage_ack_immediately_retries_the_exact_same_ciphertext() {
    if !require_otp() {
        return;
    }
    let (alice_cfg, _bob_cfg) = provision_pair("mail-refusal-retries").await;
    let contact = "bob";
    let mail_id = new_mail_id();

    let encoded = proto::encode(&payload()).unwrap();
    let (_public, signing_key) = generate_bundle_with_bits(TEST_BITS).expect("bundle");
    let signature = sign_mail(&signing_key, &encoded).expect("sign");
    let sealed_bytes =
        proto::encode(&OtpMailSealed { payload: encoded, signature }).unwrap();
    let Ok(OtpCliOutcome::Ok(ciphertext)) =
        otp_cli::encrypt_retrying(&alice_cfg, contact, &sealed_bytes, true).await
    else {
        panic!("mail encrypt should succeed");
    };

    let (own_public, own_private) = generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let own_public_der = proto::encode(&own_public).expect("own pq der");
    let mut session = aloo::client::session::SessionState::for_test(
        aloo::client::session::TestSessionSpec {
            identity: aloo::client::connect::ResolvedIdentity {
                private: own_private,
                public_der: own_public_der,
            },
            scratch: temp_dir("mail-refusal-retries-session"),
            otp: Some(alice_cfg.clone()),
        },
    )
    .await;
    let mut ui = aloo::client::tui::ui::UiState::new("alice".into());

    session.otp_store_mut().record_sent(
        contact,
        0,
        aloo::client::otp_store::PendingOtpContent::Mail {
            mail_id: mail_id.clone(),
        },
        None,
    );
    session.otp_mail_store_mut().record_sent(aloo::client::otp_mail_store::SentMailRef {
        mail_id: mail_id.clone(),
        to: "bob".into(),
        contact_name: contact.into(),
        seq: 0,
        sent_at_utc: 0,
        status: aloo::client::otp_mail_store::SentMailStatus::AwaitingServerAck,
    });

    let mut sink = RecordingSink::default();
    aloo::client::otp_mail::on_mail_result(
        &mut sink,
        &mut session,
        &mut ui,
        mail_id.clone(),
        false,
        Some("disk full".into()),
    )
    .await
    .expect("on_mail_result should never error");

    let resent = sink
        .sent
        .iter()
        .find_map(|m| match m {
            proto::ClientMessage::OtpMailSend {
                mail_id: id,
                ciphertext: ct,
                ..
            } if *id == mail_id => Some(ct.clone()),
            _ => None,
        })
        .expect("a refused mail must be retried immediately, not just left pending");
    assert_eq!(
        resent, ciphertext,
        "the retry must replay the exact same ciphertext, never a fresh encode"
    );
}

// ---------------------------------------------------------------------
// Wrong-device deliveries are refused before any ack (docs/PROTOCOL.md 17.3)
// ---------------------------------------------------------------------

/// Like `bare_session`, but also hands back this session's own pq
/// fingerprint - needed to compute the exact device-qualified contact
/// name `on_mail_deliver` will itself derive, for the matching-contact
/// counterpart below. Kept separate from `bare_session` rather than
/// changing its signature, since other tests above already depend on it.
async fn bare_session_with_own_fp(
    label: &str,
) -> (aloo::client::session::SessionState, aloo::client::tui::ui::UiState, [u8; 32]) {
    let (public, private) = generate_bundle_with_bits(TEST_BITS).expect("own pq keygen");
    let public_der = proto::encode(&public).expect("own pq der");
    let own_fp = aloo::crypto::pq::fingerprint_of_encoded(&public_der).expect("own fp");
    let session = aloo::client::session::SessionState::for_test(aloo::client::session::TestSessionSpec {
        identity: aloo::client::connect::ResolvedIdentity { private, public_der },
        scratch: temp_dir(label),
        otp: None,
    })
    .await;
    let ui = aloo::client::tui::ui::UiState::new("bob".into());
    (session, ui, own_fp)
}

/// A mail whose carried `contact_name` does not match what this session
/// derives for the claimed sender - standing in for a device other than
/// the one it was actually sealed for currently being connected under
/// that nickname - must never be acknowledged. No ack means the server
/// never deletes it and keeps offering it on every future fetch
/// (`server_mail_test.rs`'s
/// `on_mail_fetch_redelivers_the_same_pending_mail_until_acked`) until
/// the device that actually holds the matching pad connects.
///
/// @requirement AC-335
#[tokio::test]
async fn on_mail_deliver_never_acks_a_mail_sealed_for_a_different_device() {
    let (mut session, mut ui, _own_fp) = bare_session_with_own_fp("wrong-device").await;

    let (alice_public, _) = generate_bundle_with_bits(TEST_BITS).expect("alice pq keygen");
    let alice_der = proto::encode(&alice_public).expect("alice pq der");
    session.id_store_mut().pin_new_device_with_key_mode(
        "alice",
        "alice-device",
        &alice_der,
        aloo::client::idstore::Trust::Tofu,
        Some(proto::KeyMode::PqHybrid),
    );

    let mut sink = RecordingSink::default();
    aloo::client::otp_mail::on_mail_deliver(
        &mut sink,
        &mut session,
        &mut ui,
        "aa".repeat(16),
        "alice".into(),
        "definitely-not-the-derived-contact-name".into(),
        0,
        vec![1, 2, 3],
    )
    .await
    .expect("on_mail_deliver should never error");

    assert!(
        !sink
            .sent
            .iter()
            .any(|m| matches!(m, proto::ClientMessage::OtpMailAck { .. })),
        "a contact mismatch must never be acknowledged: {:?}",
        sink.sent
    );
}

/// The positive counterpart: a carried `contact_name` that DOES match
/// this session's own derivation is acknowledged - here via the
/// `AckOnly` branch (a sequence already behind `next_expected_in_seq`),
/// which needs no real pad material to exercise at all.
///
/// @requirement AC-335
#[tokio::test]
async fn on_mail_deliver_acks_a_mail_matching_the_locally_derived_contact() {
    let (mut session, mut ui, own_fp) = bare_session_with_own_fp("matching-device").await;
    let own_device_id = session.own_device_id_for_test().to_string();

    let (alice_public, _) = generate_bundle_with_bits(TEST_BITS).expect("alice pq keygen");
    let alice_der = proto::encode(&alice_public).expect("alice pq der");
    let alice_fp = aloo::crypto::pq::fingerprint_of_encoded(&alice_der).expect("alice fp");
    session.id_store_mut().pin_new_device_with_key_mode(
        "alice",
        "alice-device",
        &alice_der,
        aloo::client::idstore::Trust::Tofu,
        Some(proto::KeyMode::PqHybrid),
    );

    let contact = aloo::crypto::otp::contact_name_for_mail(&own_fp, &own_device_id, &alice_fp, "alice-device");
    session.otp_store_mut().record_received(&contact, 0);

    let mut sink = RecordingSink::default();
    let mail_id = "bb".repeat(16);
    aloo::client::otp_mail::on_mail_deliver(
        &mut sink,
        &mut session,
        &mut ui,
        mail_id.clone(),
        "alice".into(),
        contact,
        0,
        vec![1, 2, 3],
    )
    .await
    .expect("on_mail_deliver should never error");

    assert!(
        sink.sent
            .iter()
            .any(|m| matches!(m, proto::ClientMessage::OtpMailAck { mail_id: id } if *id == mail_id)),
        "a matching contact name must be acknowledged: {:?}",
        sink.sent
    );
}
