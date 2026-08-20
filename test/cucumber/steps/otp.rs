//! One-time-pad layer steps (US-033): provisioning, wrap/unwrap through the
//! real `otp` CLI, the ack-gate, and the mutual-consent popups.
//!
//! Split the same way `pq_hybrid.rs` is: provisioning/wrap/unwrap/the
//! ack-gate drive `client::otp`/`client::otp_store`/`crypto::otp` directly
//! rather than a live two-process session, because what these scenarios are
//! about - do both sides converge on the same contact, is a wrapped send
//! unreadable without unwrapping it, does a second send wait for a genuine
//! ack - is decided entirely by those functions. The popup scenarios drive
//! `UiState` directly, mirroring `ui_direct_message_test.rs`'s Rust tests -
//! the session-level wiring that calls into both of these from a live
//! connection is covered there and in `otp_provisioning_test.rs`.

use cucumber::{given, then, when};

use aloo::client::otp::{
    apply_incoming_setup, commit_pending_setup, detect_or_adopt_existing, discard_pending_setup,
    initiate_provisioning, own_pad_wins_glare, read_pending_setup, unwrap_incoming, wrap_outgoing,
};
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_store::{OtpStore, PendingOtpContent};
use aloo::client::tui::ui::UiAction;
use aloo::crypto::otp::{contact_name_for, OtpKeySetupChunk, OtpKeySetupReassembly};
use aloo::crypto::pq::{bundle_fingerprint, open_send, seal_send};
use aloo::proto::{KeyMode, UserId};

use crate::steps::ui_common::id_for;
use crate::world::{pq_bundle_for, AlooWorld};

fn cfg_at(dir: std::path::PathBuf) -> OtpCliConfig {
    std::fs::create_dir_all(&dir).expect("scenario working dir");
    OtpCliConfig {
        binary_path: "otp".into(),
        working_dir: dir,
    }
}

// ---------------------------------------------------------------------
// Given / When - provisioning, wrap/unwrap (AC-136)
// ---------------------------------------------------------------------

#[given(expr = "{word} and {word} have provisioned an otp contact for each other")]
async fn provisioned_contact(w: &mut AlooWorld, a: String, b: String) {
    let (pub_a, _) = pq_bundle_for(&a);
    let (pub_b, _) = pq_bundle_for(&b);
    let fp_a = bundle_fingerprint(&pub_a).expect("fingerprint");
    let fp_b = bundle_fingerprint(&pub_b).expect("fingerprint");

    let cfg_a = cfg_at(w.temp_path(&format!("otp-{a}")));
    let cfg_b = cfg_at(w.temp_path(&format!("otp-{b}")));

    let payload = initiate_provisioning(&cfg_a, 1, &fp_a, &fp_b)
        .await
        .expect("provisioning generation should succeed");
    let ack = apply_incoming_setup(&cfg_b, &payload).await;
    assert!(ack.accepted, "the handshake should succeed: {:?}", ack.reason);
    // The initiating side holds its own half staged, not in the keychain,
    // until the peer's acceptance comes back - `ack.accepted` here *is* that
    // acceptance, so this is the step that makes alice's side usable.
    assert!(
        commit_pending_setup(&cfg_a, &payload.contact_name).await,
        "the initiating side should adopt its own half once the peer accepts"
    );

    w.otp_contact_name = Some(payload.contact_name.clone());
    w.otp_cfgs.insert(a, cfg_a);
    w.otp_cfgs.insert(b, cfg_b);
}

#[then(expr = "{word} and {word} compute the very same otp contact name for each other")]
async fn same_contact_name(_w: &mut AlooWorld, a: String, b: String) {
    let (pub_a, _) = pq_bundle_for(&a);
    let (pub_b, _) = pq_bundle_for(&b);
    let fp_a = bundle_fingerprint(&pub_a).expect("fingerprint");
    let fp_b = bundle_fingerprint(&pub_b).expect("fingerprint");
    assert_eq!(contact_name_for(&fp_a, &fp_b), contact_name_for(&fp_b, &fp_a));
}

#[when(expr = "{word} seals {string} for {word} and wraps it under the pad")]
async fn seal_and_wrap(w: &mut AlooWorld, from: String, message: String, to: String) {
    let (_, from_private) = pq_bundle_for(&from);
    let (to_public, _) = pq_bundle_for(&to);
    let to_fp = bundle_fingerprint(&to_public).expect("fingerprint");
    let blob = seal_send(&from_private, to_public.bootstrap_encap(), to_fp, None, 1, message.as_bytes())
        .expect("sealing should succeed");

    let contact = w.otp_contact_name.clone().expect("no otp contact provisioned yet");
    let cfg = w.otp_cfgs.get(&from).expect("no otp config for this side").clone();
    w.otp_wrapped = wrap_outgoing(&cfg, blob, &contact)
        .await
        .expect("wrapping should succeed");
    w.plaintext = message.into_bytes();
}

#[then("the wrapped bytes do not open as a pq_hybrid send directly")]
async fn wrapped_not_directly_openable(w: &mut AlooWorld) {
    let (bob_public, bob_private) = pq_bundle_for("bob");
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&bob_public).expect("fingerprint");
    assert!(
        open_send(&[bob_private.bootstrap_decap().clone()], &fp, &alice_public, &w.otp_wrapped).is_none(),
        "otp-wrapped bytes must not parse as a pq_hybrid send until they are unwrapped"
    );
}

#[then(expr = "{word} unwraps it and reads back exactly what was sent")]
async fn unwraps_and_reads(w: &mut AlooWorld, who: String) {
    let contact = w.otp_contact_name.clone().expect("no otp contact provisioned yet");
    let cfg = w.otp_cfgs.get(&who).expect("no otp config for this side").clone();
    let blob = unwrap_incoming(&cfg, &w.otp_wrapped, &contact)
        .await
        .expect("unwrapping should succeed");

    let (their_public, their_private) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&their_public).expect("fingerprint");
    let (_, plaintext) = open_send(&[their_private.bootstrap_decap().clone()], &fp, &alice_public, &blob)
        .expect("the intended recipient must be able to open the unwrapped pq_hybrid send");
    assert_eq!(plaintext, w.plaintext, "what came out must be exactly what went in");
}

// ---------------------------------------------------------------------
// The ack-gate (AC-137)
// ---------------------------------------------------------------------

/// Mirrors the decision `client::otp::send_or_queue` makes: hold the
/// message if a previous send to this contact is still genuinely
/// unacknowledged, otherwise wrap and send it right away and record the
/// gate.
async fn attempt_send_under_pad(w: &mut AlooWorld, from: &str, message: &str) {
    let contact = w.otp_contact_name.clone().expect("no otp contact provisioned yet");
    if w.otp_store_mut().get(&contact).and_then(|s| s.pending_unacked_out_seq).is_some() {
        w.otp_held.push(message.to_string());
        return;
    }
    let cfg = w.otp_cfgs.get(from).expect("no otp config for this side").clone();
    let seq = w.otp_store_mut().get(&contact).map(|s| s.next_out_seq).unwrap_or(0);
    wrap_outgoing(&cfg, message.as_bytes().to_vec(), &contact)
        .await
        .expect("wrapping should succeed");
    w.otp_store_mut()
        .record_sent(&contact, seq, PendingOtpContent::Text { channel: None });
    w.otp_outstanding = Some((message.to_string(), seq));
    w.otp_sent.push(message.to_string());
}

#[when(expr = "{word} sends {string} to {word} under the pad")]
async fn send_under_pad(w: &mut AlooWorld, from: String, message: String, _to: String) {
    attempt_send_under_pad(w, &from, &message).await;
}

#[then(expr = "{string} was sent immediately")]
async fn was_sent_immediately(w: &mut AlooWorld, text: String) {
    assert_eq!(w.otp_sent.last(), Some(&text), "expected {text:?} to have been sent right away");
}

#[then(expr = "{string} is held back, not sent")]
async fn is_held_back(w: &mut AlooWorld, text: String) {
    assert_eq!(w.otp_held.last(), Some(&text), "expected {text:?} to be held back");
    assert!(!w.otp_sent.contains(&text), "{text:?} should not have been sent yet");
}

#[when(expr = "{word}'s delivery ack for {string} arrives")]
async fn delivery_ack_arrives(w: &mut AlooWorld, _who: String, text: String) {
    let contact = w.otp_contact_name.clone().expect("no otp contact provisioned yet");
    let (pending_text, seq) = w.otp_outstanding.clone().expect("nothing is outstanding");
    assert_eq!(pending_text, text, "the ack must name the message actually outstanding");
    assert!(
        w.otp_store_mut().record_acked(&contact, seq),
        "a genuine, matching ack must clear the gate"
    );
    w.otp_outstanding = None;
    if !w.otp_held.is_empty() {
        let next = w.otp_held.remove(0);
        attempt_send_under_pad(w, "alice", &next).await;
    }
}

#[then(expr = "the held message {string} is sent")]
async fn held_message_is_sent(w: &mut AlooWorld, text: String) {
    assert_eq!(w.otp_sent.last(), Some(&text), "expected the held message to have been sent");
    assert!(!w.otp_held.contains(&text), "it should no longer be held");
}

// ---------------------------------------------------------------------
// Adopting a pre-existing contact (AC-138)
// ---------------------------------------------------------------------

#[given(expr = "{word} has an otp contact for {word} provisioned out of band")]
async fn contact_provisioned_out_of_band(w: &mut AlooWorld, who: String, _peer: String) {
    let cfg = cfg_at(w.temp_path(&format!("otp-adopt-{who}")));
    otp_cli::new_key_pair(&cfg, 1, "a", "b").await.expect("keygen should succeed");
    let keys = cfg.working_dir.join("a_keys");
    let contact_name = "already-there".to_string();
    otp_cli::add_contact(
        &cfg,
        &contact_name,
        &keys.join("encryption_for_b.key"),
        &keys.join("decryption_from_b.key"),
    )
    .await
    .expect("add_contact should succeed");

    w.otp_contact_name = Some(contact_name);
    w.otp_store = Some(OtpStore::new_empty(w.temp_path("otp-adopt-store")));
    w.otp_cfgs.insert(who, cfg);
}

#[when(expr = "{word} checks whether that contact can be adopted")]
async fn checks_adoption(w: &mut AlooWorld, who: String) {
    let contact = w.otp_contact_name.clone().expect("no otp contact set up");
    let cfg = w.otp_cfgs.get(&who).expect("no otp config for this side").clone();
    w.otp_adopted = detect_or_adopt_existing(&cfg, w.otp_store_mut(), &contact).await;
}

#[then("it is adopted without generating a fresh pad")]
async fn adopted_without_generating(w: &mut AlooWorld) {
    assert!(w.otp_adopted, "an existing contact should be adopted");
    let contact = w.otp_contact_name.clone().expect("no otp contact set up");
    assert!(
        w.otp_store_mut().get(&contact).map(|s| s.provisioned).unwrap_or(false),
        "adopting must mark the contact provisioned locally"
    );
}

// ---------------------------------------------------------------------
// Mutual consent popups (AC-139)
// ---------------------------------------------------------------------

#[when(expr = "I am asked to generate a fresh otp pad for {word}")]
async fn asked_to_generate(w: &mut AlooWorld, who: String) {
    let id = UserId(id_for(&who));
    w.ui_mut().open_otp_generate_confirm(id, who, KeyMode::PqHybrid, vec![9, 9]);
}

#[then(expr = "a prompt asks whether to generate and share a fresh pad with {word}")]
async fn prompt_names(w: &mut AlooWorld, who: String) {
    let id = UserId(id_for(&who));
    let pending = w.ui_ref().otp_generate_confirm_open().expect("no generate-confirm prompt is open");
    assert_eq!(pending.peer, id);
}

#[then(expr = "generating the pad was confirmed with a {int}MB size")]
async fn generating_confirmed(w: &mut AlooWorld, size_mb: u32) {
    assert_eq!(w.last_action, Some(UiAction::ConfirmOtpGenerate { size_mb }));
}

#[then("generating the pad was cancelled")]
async fn generating_cancelled(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::CancelOtpGenerate));
}

#[when(expr = "{word} invites me to start an otp session")]
async fn invites_me(w: &mut AlooWorld, who: String) {
    let id = UserId(id_for(&who));
    w.ui_mut()
        .push_otp_invite(id, who.clone(), format!("{who}-contact"), None, None, None);
}

#[then(expr = "an invite popup names {word}")]
async fn invite_names(w: &mut AlooWorld, who: String) {
    let id = UserId(id_for(&who));
    let invite = w.ui_ref().otp_invite_open().expect("no invite popup is open");
    assert_eq!(invite.from, id);
}

#[when(expr = "{word}'s invite is answered")]
async fn invite_answered(w: &mut AlooWorld, _who: String) {
    let _ = w.ui_mut().take_otp_invite();
}

#[then("the otp invite was accepted")]
async fn invite_was_accepted(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::AcceptOtpInvite));
}

#[then("the otp invite was rejected")]
async fn invite_was_rejected(w: &mut AlooWorld) {
    assert_eq!(w.last_action, Some(UiAction::RejectOtpInvite));
}

#[then("no otp status notice is shown")]
async fn no_status_notice(w: &mut AlooWorld) {
    assert!(w.ui_ref().status_notice.is_none());
}

#[when(expr = "an otp session {word} notice arrives")]
async fn status_notice_arrives(w: &mut AlooWorld, outcome: String) {
    match outcome.as_str() {
        "started" => w
            .ui_mut()
            .push_status_notice("OTP session started at 2026-08-18T00:00:00Z".to_string(), true),
        "cancelled" => w.ui_mut().push_status_notice("OTP session cancelled".to_string(), false),
        other => panic!("unknown otp session outcome {other:?}"),
    }
}

#[then(expr = "an otp status notice says {string}")]
async fn status_notice_says(w: &mut AlooWorld, expected: String) {
    let (text, _) = w.ui_ref().status_notice.as_ref().expect("no status notice is shown");
    assert!(text.contains(&expected), "expected {expected:?} within {text:?}");
}

// ---------------------------------------------------------------------
// Chunked key-setup transfer (TB-186)
// ---------------------------------------------------------------------

#[given(expr = "{word} generates a fresh {int}MB pad for {word}")]
async fn generates_large_pad(w: &mut AlooWorld, _from: String, size_mb: u32, _to: String) {
    let total = (size_mb as usize) * 1024 * 1024;
    w.otp_pad_enc = (0..total as u32).map(|i| (i % 251) as u8).collect();
    w.otp_pad_dec = (0..total as u32).map(|i| (i.wrapping_mul(7) % 251) as u8).collect();
}

#[when("it is sent to bob in many small pieces")]
async fn split_into_pieces(w: &mut AlooWorld) {
    const CHUNK_BYTES: usize = 16 * 1024;
    let total_len = w.otp_pad_enc.len() as u32;
    let mut offset = 0usize;
    w.otp_chunks.clear();
    loop {
        let end = (offset + CHUNK_BYTES).min(w.otp_pad_enc.len());
        w.otp_chunks.push(OtpKeySetupChunk {
            contact_name: "abcd-1234".to_string(),
            keypair_size_mb: 1,
            total_len,
            offset: offset as u32,
            enc_chunk: w.otp_pad_enc[offset..end].to_vec(),
            dec_chunk: w.otp_pad_dec[offset..end].to_vec(),
        });
        if end >= w.otp_pad_enc.len() {
            break;
        }
        offset = end;
    }
    assert!(w.otp_chunks.len() > 1, "a large pad must actually need more than one piece");

    let mut reassembly = OtpKeySetupReassembly::new(&w.otp_chunks[0]);
    for chunk in &w.otp_chunks {
        assert!(reassembly.accept(chunk), "every piece in order must be accepted");
    }
    assert!(reassembly.is_complete());
    w.otp_reassembled = Some(reassembly.take_keys());
}

#[then("bob's reassembled pad is byte-identical to the one alice generated")]
async fn reassembled_matches(w: &mut AlooWorld) {
    let (enc, dec) = w.otp_reassembled.clone().expect("nothing was reassembled");
    assert_eq!(enc, w.otp_pad_enc);
    assert_eq!(dec, w.otp_pad_dec);
}

// ---------------------------------------------------------------------
// An invitation that is never accepted (AC-142)
// ---------------------------------------------------------------------

/// Shared by the "never accepted" and "refused" scenarios: the difference
/// between a peer who never answered and one who said no is, on this side,
/// only which message came back - in both cases the pad was never adopted,
/// which is exactly what the scenarios below assert.
async fn generate_unaccepted_pad(w: &mut AlooWorld, from: String, to: String) {
    let (pub_a, _) = pq_bundle_for(&from);
    let (pub_b, _) = pq_bundle_for(&to);
    let fp_a = bundle_fingerprint(&pub_a).expect("fingerprint");
    let fp_b = bundle_fingerprint(&pub_b).expect("fingerprint");
    let cfg_a = cfg_at(w.temp_path(&format!("otp-unaccepted-{from}")));
    let cfg_b = cfg_at(w.temp_path(&format!("otp-unaccepted-{to}")));

    let payload = initiate_provisioning(&cfg_a, 1, &fp_a, &fp_b)
        .await
        .expect("provisioning generation should succeed");
    w.otp_contact_name = Some(payload.contact_name.clone());
    w.otp_pad_enc = payload.peer_encryption_key.clone();
    w.otp_pad_dec = payload.peer_decryption_key.clone();
    w.otp_cfgs.insert(from, cfg_a);
    w.otp_cfgs.insert(to, cfg_b);
}

#[when(expr = "{word} generates a pad for {word} that {word} never accepts")]
async fn generates_pad_never_accepted(w: &mut AlooWorld, from: String, to: String, _who: String) {
    generate_unaccepted_pad(w, from, to).await;
}

#[when(expr = "{word} generates a pad for {word} that {word} refuses")]
async fn generates_pad_refused(w: &mut AlooWorld, from: String, to: String, _who: String) {
    generate_unaccepted_pad(w, from.clone(), to).await;
    // A refusal ends the invitation: the staged pad is dropped, exactly what
    // `on_key_setup_ack` does when the ack comes back not accepted.
    let contact = w.otp_contact_name.clone().expect("no otp contact set up");
    let cfg = w.otp_cfgs.get(&from).expect("no otp config").clone();
    discard_pending_setup(&cfg, &contact);
}

#[then(expr = "{word} holds no otp contact for {word}")]
async fn holds_no_contact(w: &mut AlooWorld, who: String, _peer: String) {
    let contact = w.otp_contact_name.clone().expect("no otp contact set up");
    let cfg = w.otp_cfgs.get(&who).expect("no otp config").clone();
    assert!(
        !otp_cli::has_contact(&cfg, &contact).await.unwrap_or(true),
        "an invitation that was never accepted must leave no keychain entry behind"
    );
}

#[then(expr = "a later invitation from {word} to {word} still succeeds")]
async fn later_invitation_succeeds(w: &mut AlooWorld, from: String, to: String) {
    let (pub_a, _) = pq_bundle_for(&from);
    let (pub_b, _) = pq_bundle_for(&to);
    let fp_a = bundle_fingerprint(&pub_a).expect("fingerprint");
    let fp_b = bundle_fingerprint(&pub_b).expect("fingerprint");
    let cfg_from = w.otp_cfgs.get(&from).expect("no otp config").clone();
    let cfg_to = w.otp_cfgs.get(&to).expect("no otp config").clone();

    // Whichever direction it runs in, the contact name is the same - which
    // is precisely why a leftover half used to make this impossible.
    let payload = initiate_provisioning(&cfg_from, 1, &fp_a, &fp_b)
        .await
        .expect("a later invitation must not be blocked by an abandoned one");
    let ack = apply_incoming_setup(&cfg_to, &payload).await;
    assert!(ack.accepted, "the peer should accept the fresh pad: {:?}", ack.reason);
    assert!(
        commit_pending_setup(&cfg_from, &payload.contact_name).await,
        "the initiating side should adopt its half once accepted"
    );
}

#[then("the pad alice would re-send is byte-identical to the one she generated")]
async fn resend_is_identical(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no otp contact set up");
    let cfg = w.otp_cfgs.get("alice").expect("no otp config").clone();
    let again = read_pending_setup(&cfg, &contact, 1).expect("a staged pad must be re-readable");
    assert_eq!(again.peer_encryption_key, w.otp_pad_enc);
    assert_eq!(again.peer_decryption_key, w.otp_pad_dec);
}

#[when("alice and bob both generate a pad for each other before either answers")]
async fn both_generate_at_once(w: &mut AlooWorld) {
    let (pub_a, _) = pq_bundle_for("alice");
    let (pub_b, _) = pq_bundle_for("bob");
    let fp_a = bundle_fingerprint(&pub_a).expect("fingerprint");
    let fp_b = bundle_fingerprint(&pub_b).expect("fingerprint");
    let cfg_a = cfg_at(w.temp_path("otp-glare-alice"));
    let cfg_b = cfg_at(w.temp_path("otp-glare-bob"));

    let pad_a = initiate_provisioning(&cfg_a, 1, &fp_a, &fp_b)
        .await
        .expect("alice's pad");
    initiate_provisioning(&cfg_b, 1, &fp_b, &fp_a)
        .await
        .expect("bob's pad");

    // The loser concedes, exactly as `on_key_setup` does when it sees a pad
    // arrive while one of its own is still owed.
    let (loser_cfg, loser) = if own_pad_wins_glare(&fp_a, &fp_b) {
        (cfg_b.clone(), "bob")
    } else {
        (cfg_a.clone(), "alice")
    };
    discard_pending_setup(&loser_cfg, &pad_a.contact_name);

    w.otp_contact_name = Some(pad_a.contact_name.clone());
    w.otp_glare_loser = Some(loser.to_string());
    w.otp_cfgs.insert("alice".to_string(), cfg_a);
    w.otp_cfgs.insert("bob".to_string(), cfg_b);
}

#[then("both sides agree on which pad survives")]
async fn both_agree_on_winner(_w: &mut AlooWorld) {
    let (pub_a, _) = pq_bundle_for("alice");
    let (pub_b, _) = pq_bundle_for("bob");
    let fp_a = bundle_fingerprint(&pub_a).expect("fingerprint");
    let fp_b = bundle_fingerprint(&pub_b).expect("fingerprint");
    assert_ne!(
        own_pad_wins_glare(&fp_a, &fp_b),
        own_pad_wins_glare(&fp_b, &fp_a),
        "exactly one side may believe its own pad won"
    );
}

#[then("the conceding side keeps no pad of its own")]
async fn loser_keeps_nothing(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no otp contact set up");
    let loser = w.otp_glare_loser.clone().expect("no glare loser recorded");
    let cfg = w.otp_cfgs.get(&loser).expect("no otp config").clone();
    assert!(
        read_pending_setup(&cfg, &contact, 1).is_none(),
        "the conceding side must not keep a pad it can never have adopted"
    );
    assert!(
        !otp_cli::has_contact(&cfg, &contact).await.unwrap_or(true),
        "and must not have adopted one either"
    );
}

// ---------------------------------------------------------------------
// /endotp - ending a session, and surviving a reconnect (AC-192, AC-193)
// ---------------------------------------------------------------------

#[given(expr = "the otp session with {word} is active")]
async fn otp_session_active(w: &mut AlooWorld, who: String) {
    w.ui_mut().mark_otp_active(UserId(id_for(&who)));
}

#[then(expr = "the otp session with {word} is still active")]
async fn otp_session_still_active(w: &mut AlooWorld, who: String) {
    assert!(
        w.ui_ref().is_otp_active(UserId(id_for(&who))),
        "a disconnect alone must never end an active session - only /endotp may"
    );
}

#[then("the otp session was ended")]
async fn otp_session_was_ended(w: &mut AlooWorld) {
    assert!(
        matches!(w.last_action, Some(UiAction::EndOtpSession { .. })),
        "expected /endotp to produce EndOtpSession, got {:?}",
        w.last_action
    );
}
