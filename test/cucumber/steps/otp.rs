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

use aloo::client::file_transfer::{OtpIncomingFileReceive, OtpIncomingKind};
use aloo::client::otp::{
    OtpFraming, apply_incoming_setup, commit_pending_setup, contact_name_if_active,
    detect_or_adopt_existing, discard_pending_setup, finish_incoming_file, framing_for,
    initiate_provisioning, own_pad_wins_glare, read_pending_setup, resume_pending_content_sends,
    send_or_queue, send_voice_offer, unwrap_incoming, wrap_outgoing,
};
use aloo::client::otp_cli::{self, OtpCliConfig};
use aloo::client::otp_store::{OtpStore, PendingOtpContent};
use aloo::client::tui::ui::{UiAction, UiState};
use aloo::crypto::otp::{contact_name_for, OtpKeySetupChunk, OtpKeySetupReassembly, OtpPurpose};
use aloo::crypto::pq::{
    HybridSend, bundle_fingerprint, open_send, open_send_blinded, seal_send_blinded,
};
use aloo::proto::UserId;

use crate::steps::ui_common::id_for;
use crate::support::{ui_buffer, ui_rows_wide};
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

    let payload = initiate_provisioning(&cfg_a, 1, &fp_a, &fp_b, OtpPurpose::Live)
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

/// The layer's one rule, in the order it actually happens: the pad goes on
/// the message, and the seal goes around the pad.
#[when(expr = "{word} pads {string} for {word} and seals the pad")]
async fn pad_and_seal(w: &mut AlooWorld, from: String, message: String, to: String) {
    let contact = w.otp_contact_name.clone().expect("no otp contact provisioned yet");
    let cfg = w.otp_cfgs.get(&from).expect("no otp config for this side").clone();
    let (padded, proof) = wrap_outgoing(&cfg, message.as_bytes().to_vec(), &contact)
        .await
        .expect("wrapping should succeed");
    w.otp_pad_bytes = padded.len();

    let (_, from_private) = pq_bundle_for(&from);
    let (to_public, _) = pq_bundle_for(&to);
    let to_fp = bundle_fingerprint(&to_public).expect("fingerprint");
    w.otp_wrapped =
        seal_send_blinded(&from_private, to_public.bootstrap_encap(), to_fp, 1, &padded)
            .expect("sealing should succeed");
    w.otp_ack_proof = Some(proof);
    w.plaintext = message.into_bytes();
}

#[then("the pad only ever covered the message, never the seal around it")]
async fn pad_covered_only_the_message(w: &mut AlooWorld) {
    assert!(
        w.otp_pad_bytes < 200,
        "the pad should cost about the length of the line, cost {}",
        w.otp_pad_bytes
    );
    assert!(
        w.otp_wrapped.len() > 5000,
        "and the seal - the part the pad no longer pays for - should be the bulk of the wire \
         block, which weighed {}",
        w.otp_wrapped.len()
    );
}

#[then("the sealed bytes name neither their recipient nor a room")]
async fn sealed_bytes_name_nobody(w: &mut AlooWorld) {
    let send: HybridSend =
        aloo::proto::decode(&w.otp_wrapped).expect("the wire block is a pq_hybrid send");
    assert_eq!(
        send.setup.binding.recipient_fp, [0u8; 32],
        "the recipient's fingerprint is signed but must not be transmitted"
    );
    assert!(
        send.setup.binding.channel.is_none(),
        "and the room travels under the pad, not in the binding"
    );
    let (bob_public, bob_private) = pq_bundle_for("bob");
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&bob_public).expect("fingerprint");
    assert!(
        open_send(&[bob_private.bootstrap_decap().clone()], &fp, &alice_public, &w.otp_wrapped)
            .is_none(),
        "a blinded send must not open by the ordinary path, which trusts the name on the wire"
    );
}

#[then(expr = "{word} opens the seal, unwraps the pad, and reads back exactly what was sent")]
async fn opens_and_unwraps(w: &mut AlooWorld, who: String) {
    let (their_public, their_private) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&their_public).expect("fingerprint");
    let (_, padded) = open_send_blinded(
        &[their_private.bootstrap_decap().clone()],
        &fp,
        &alice_public,
        &w.otp_wrapped,
    )
    .expect("the intended recipient must be able to open the seal");

    let contact = w.otp_contact_name.clone().expect("no otp contact provisioned yet");
    let cfg = w.otp_cfgs.get(&who).expect("no otp config for this side").clone();
    let plaintext = match unwrap_incoming(&cfg, &padded, &contact).await {
        aloo::client::otp::UnwrapOutcome::Ok(bytes, proof) => {
            w.otp_unwrapped_ack_proof = Some(proof);
            bytes
        }
        other => panic!("expected unwrapping to succeed, got {other:?}"),
    };
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
        .record_sent(&contact, seq, PendingOtpContent::Text { channel: None }, None);
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
        w.otp_store_mut().record_acked(&contact, seq, None),
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
    w.ui_mut()
        .open_otp_generate_confirm(id, who, vec![9, 9], aloo::crypto::otp::OtpPurpose::Live);
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

    let payload = initiate_provisioning(&cfg_a, 1, &fp_a, &fp_b, OtpPurpose::Live)
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
    let payload = initiate_provisioning(&cfg_from, 1, &fp_a, &fp_b, OtpPurpose::Live)
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

    let pad_a = initiate_provisioning(&cfg_a, 1, &fp_a, &fp_b, OtpPurpose::Live)
        .await
        .expect("alice's pad");
    initiate_provisioning(&cfg_b, 1, &fp_b, &fp_a, OtpPurpose::Live)
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

#[then("the end is refused because bob cannot confirm it")]
async fn otp_end_refused_offline(w: &mut AlooWorld) {
    assert!(
        !matches!(w.last_action, Some(UiAction::EndOtpSession { .. })),
        "an offline peer cannot confirm the end, so no EndOtpSession may be produced: {:?}",
        w.last_action
    );
    let (message, success) = w
        .ui_ref()
        .status_notice
        .clone()
        .expect("the refusal explains itself instead of silently doing nothing");
    assert!(
        message.contains("offline") && message.contains("both sides online"),
        "the notice names the reason: {message:?}"
    );
    assert!(!success);
}

/// The pre-spend `otp --show-contact` snapshot a session holds for a peer
/// (`UiState::set_otp_key_status`), which is what the message details
/// popup reads a row's pad position out of (AC-243).
#[given(
    expr = "{word}'s pad has sent {int} messages over {int} bytes and received {int} over {int}"
)]
async fn pad_position(
    w: &mut AlooWorld,
    who: String,
    enc_sequence: u64,
    enc_offset: u64,
    dec_sequence: u64,
    dec_offset: u64,
) {
    let contact = "abcd1234";
    let keychain = std::path::PathBuf::from("/tmp/aloo-test/otp/.keychain");
    w.ui_mut().set_otp_key_status(
        UserId(id_for(&who)),
        otp_cli::OtpKeyStatus {
            detail: otp_cli::ContactDetail {
                enc_sequence,
                enc_offset,
                enc_key_remaining: 2_000_000,
                dec_sequence,
                dec_offset,
                dec_key_remaining: 2_000_000,
            },
            contact_name: contact.to_string(),
            enc_key_path: keychain.join(format!("{contact}_enc.key")),
            dec_key_path: keychain.join(format!("{contact}_dec.key")),
        },
    );
}

// ---------------------------------------------------------------------
// The tag a pad session gives that person (AC-246)
// ---------------------------------------------------------------------

#[then(expr = "{word} carries the OTP tag in the user list instead of their own")]
async fn otp_tag_in_user_list(w: &mut AlooWorld, name: String) {
    let rows = crate::support::popup_body(&ui_buffer(w.ui_ref(), 100, 14), "Users");
    let row = rows
        .iter()
        .find(|r| r.contains(&name))
        .unwrap_or_else(|| panic!("no user-list row for {name}: {rows:?}"));
    assert!(row.contains("OTP"), "expected the pad tag: {row:?}");
    assert!(
        !row.contains("PQH"),
        "the pad replaces the my_key tag rather than joining it: {row:?}"
    );
}

#[then(expr = "{word} still carries their own tag")]
async fn own_tag_kept(w: &mut AlooWorld, name: String) {
    let rows = crate::support::popup_body(&ui_buffer(w.ui_ref(), 100, 14), "Users");
    let row = rows
        .iter()
        .find(|r| r.contains(&name))
        .unwrap_or_else(|| panic!("no user-list row for {name}: {rows:?}"));
    assert!(
        row.contains("PQH") && !row.contains("OTP"),
        "only the peer the session is with is marked: {row:?}"
    );
}

#[then(expr = "{word} carries the OTP tag on the DM selector")]
async fn otp_tag_on_dm_selector(w: &mut AlooWorld, name: String) {
    let rows = ui_rows_wide(w.ui_ref());
    assert!(
        crate::support::appears_before(&rows, &name, "OTP"),
        "the DM selector carries the tag after the nickname: {rows:?}"
    );
}

#[then("the acknowledgement proof the receiver computed matches the sender's")]
async fn ack_proof_matches(w: &mut AlooWorld) {
    let sent = w.otp_ack_proof.expect("nothing was wrapped in this scenario");
    let read_back = w
        .otp_unwrapped_ack_proof
        .expect("nothing was unwrapped in this scenario");
    assert_eq!(
        sent, read_back,
        "only a party that actually opened the pad can name this message's nonce, \
         so the two sides must arrive at the same proof independently"
    );
}

// ---------------------------------------------------------------------
// A serverless, pad-only pair (AC-259)
// ---------------------------------------------------------------------

/// What a peer nobody ever introduced is pinned under: not a keybundle,
/// because there was never a server to relay one. This is the `id_store`
/// entry a hand-installed contact leaves (`/contacts`, `o`).
fn pad_only_pin(who: &str) -> Vec<u8> {
    format!("pad-only-pin-for-{who}").into_bytes()
}

async fn pad_only_peer(
    w: &mut AlooWorld,
    own_name: &str,
    peer_name: &str,
    cfg: OtpCliConfig,
    contact: &str,
) -> crate::world::PadOnlyPeer {
    let (_, own_private) = pq_bundle_for(own_name);
    let (own_public, _) = pq_bundle_for(own_name);
    let mut session = aloo::client::session::SessionState::for_test(
        aloo::client::session::TestSessionSpec {
            identity: aloo::client::connect::ResolvedIdentity {
                private: own_private,
                public_der: aloo::proto::encode(&own_public).expect("encode bundle"),
            },
            scratch: w.temp_path(&format!("pad-only-{own_name}")),
            otp: Some(cfg),
        },
    )
    .await;
    // Neither side's key reads as a keybundle *to the other*, which is
    // exactly what makes this pair `Direct` from both ends.
    session.set_own_pinned_der_for_test(pad_only_pin(own_name));
    session
        .id_store_mut()
        .check_and_pin(peer_name, &pad_only_pin(peer_name));
    session.otp_store_mut().mark_provisioned(contact);

    // No server anywhere: a `direct_punch_to` entry is the only thing that
    // makes this peer addressable, and the only place their nickname comes
    // from (`p2p::direct_nickname_of`).
    session.peer_link_mut().configure_direct_punch(
        own_name.to_string(),
        vec![aloo::settings::DirectPunchTarget {
            nickname: peer_name.to_string(),
            host: "127.0.0.1".to_string(),
            port: 1,
            frequency: aloo::settings::PunchFrequency::parse("every_1m").expect("valid frequency"),
        }],
        0,
    );
    let peer = aloo::client::p2p::direct_peer_id(peer_name);
    session.peer_link_mut().open_unpunched_link_for_test(peer);

    let mut ui = UiState::new(own_name.into());
    // A serverless client is its own `direct_peer_id` too - there is no
    // server to assign one (`client::daemon::run`).
    ui.set_own_id(aloo::client::p2p::direct_peer_id(own_name));
    // A pair set up already holding a pad for each other is, by
    // definition, currently linked - individual scenarios modeling a peer
    // going unreachable override this explicitly.
    ui.set_link_status(peer, aloo::client::p2p::LinkStatus::Active);
    crate::world::PadOnlyPeer {
        session,
        ui,
        peer,
        peer_der: pad_only_pin(peer_name),
    }
}

#[given(expr = "{word} and {word} reach each other directly and hold a pad for each other")]
async fn pad_only_pair(w: &mut AlooWorld, a: String, b: String) {
    let contact =
        aloo::crypto::otp::contact_name_for_keys(&pad_only_pin(&a), &pad_only_pin(&b));
    let cfg_a = cfg_at(w.temp_path(&format!("pad-only-otp-{a}")));
    let cfg_b = cfg_at(w.temp_path(&format!("pad-only-otp-{b}")));
    // One real pad, split so each side holds the mirror of the other's.
    // One real pad, generated once and split: each side installs its own
    // half plus the mirror of the other's, exactly as two people exchanging
    // keys out of band would (`/contacts`, `o`).
    otp_cli::new_key_pair(&cfg_a, 1, "a", "b")
        .await
        .expect("generating a real pad");
    let a_keys = cfg_a.working_dir.join("a_keys");
    let b_keys = cfg_a.working_dir.join("b_keys");
    otp_cli::add_contact(
        &cfg_a,
        &contact,
        &a_keys.join("encryption_for_b.key"),
        &a_keys.join("decryption_from_b.key"),
    )
    .await
    .expect("alice adds the contact");
    otp_cli::add_contact(
        &cfg_b,
        &contact,
        &b_keys.join("encryption_for_a.key"),
        &b_keys.join("decryption_from_a.key"),
    )
    .await
    .expect("bob adds the mirror");

    let side_a = pad_only_peer(w, &a, &b, cfg_a, &contact).await;
    let side_b = pad_only_peer(w, &b, &a, cfg_b, &contact).await;
    w.otp_contact_name = Some(contact);
    w.pad_only = Some((side_a, side_b));
}

#[given("neither of them has ever learned the other's keybundle")]
async fn neither_has_a_keybundle(w: &mut AlooWorld) {
    let (a, b) = w.pad_only.as_ref().expect("no pad-only pair");
    for (side, who) in [(a, "alice"), (b, "bob")] {
        assert!(
            aloo::crypto::pq::fingerprint_of_encoded(&side.peer_der).is_none(),
            "{who}'s pin of their peer must not be a readable keybundle"
        );
    }
}

#[then("their pair is framed direct, with no envelope around the pad")]
async fn pair_is_direct(w: &mut AlooWorld) {
    let (a, b) = w.pad_only.as_ref().expect("no pad-only pair");
    for side in [a, b] {
        assert_eq!(
            framing_for(side.session.own_pinned_der_for_test(), &side.peer_der),
            OtpFraming::Direct,
        );
    }
}

#[then("each of them files the pad under the very same contact name")]
async fn same_pad_contact(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, b) = w.pad_only.as_ref().expect("no pad-only pair");
    for (side, who) in [(a, "alice"), (b, "bob")] {
        assert_eq!(
            contact_name_if_active(&side.session, &side.peer_der).as_deref(),
            Some(contact.as_str()),
            "{who} must find this pair's pad, with nothing negotiated"
        );
    }
}

#[when(expr = "{word}'s link to {word} comes up")]
async fn link_comes_up(w: &mut AlooWorld, _a: String, _b: String) {
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    assert!(
        !a.ui.known_users.contains_key(&a.peer),
        "nobody has introduced them yet"
    );
    aloo::client::session::register_pad_only_peer(&mut a.session, &mut a.ui, a.peer);
}

#[then(expr = "{word} is registered from the pad alone, with otp already active")]
async fn registered_from_the_pad(w: &mut AlooWorld, _b: String) {
    let (a, _) = w.pad_only.as_ref().expect("no pad-only pair");
    assert!(
        a.ui.known_users.contains_key(&a.peer),
        "an installed pad stands in for the handshake a keybundle would have run"
    );
    assert!(
        a.ui.is_otp_active(a.peer),
        "there is nothing left to negotiate - the pad is already shared"
    );
}

#[when(expr = "{word} sends {word} {string}")]
async fn pad_only_send(w: &mut AlooWorld, _a: String, _b: String, message: String) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    let (msg_id, delivery) = a.ui.start_delivery(&[a.peer]);
    a.ui.push_outgoing_dm(
        a.peer,
        aloo::client::tui::ui::MessageBody::Text(message.clone()),
        Some(delivery),
    );
    let peer_der = a.peer_der.clone();
    send_or_queue(
        &mut aloo::control::NullSink,
        &mut a.session,
        &mut a.ui,
        a.peer,
        &contact,
        &peer_der,
        message.as_bytes(),
        aloo::proto::Content::Text,
        None,
        None,
        Some(msg_id),
    )
    .await
    .expect("the pad-only send path should not fail");
}

#[then(expr = "{word} reads it, and registers {word} because the pad opened it")]
async fn pad_only_receive(w: &mut AlooWorld, _b: String, _a: String) {
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    let (seq, msg_id, envelope) = a
        .session
        .peer_link_mut()
        .pending_payloads(a.peer)
        .into_iter()
        .find_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                ..
            } => Some((seq, msg_id, envelope)),
            _ => None,
        })
        .expect("a pad-wrapped message should have gone out");
    assert_eq!(
        envelope.blocks.len(),
        1,
        "direct framing puts the message straight in the pad"
    );
    assert!(
        !b.ui.known_users.contains_key(&b.peer),
        "the receiving side has no reason to know them yet"
    );
    aloo::client::otp::on_message(
        &mut b.session,
        &mut b.ui,
        None,
        b.peer,
        "alice".into(),
        seq,
        msg_id,
        envelope,
    )
    .await
    .expect("the receive path should not fail");
    assert!(
        b.ui.known_users.contains_key(&b.peer),
        "opening the message is what proves who sent it, and registers them"
    );
    assert!(
        b.ui.private_rooms[&b.peer]
            .log
            .iter()
            .any(|e| matches!(&e.body, aloo::client::tui::ui::MessageBody::Text(_))),
        "and the message itself lands in their room"
    );
}

/// Hands whatever pad-wrapped payload one side queued to the other - the
/// control notices travel in both directions, unlike a text message.
async fn deliver_pad_envelope(
    from: &mut crate::world::PadOnlyPeer,
    to: &mut crate::world::PadOnlyPeer,
    from_name: &str,
) {
    let (seq, msg_id, envelope) = from
        .session
        .peer_link_mut()
        .pending_payloads(from.peer)
        .into_iter()
        .find_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                ..
            } => Some((seq, msg_id, envelope)),
            _ => None,
        })
        .expect("a pad-wrapped payload should have gone out");
    aloo::client::otp::on_message(
        &mut to.session,
        &mut to.ui,
        None,
        to.peer,
        from_name.into(),
        seq,
        msg_id,
        envelope,
    )
    .await
    .expect("the receive path should not fail");
}

#[when(expr = "{word} runs \\/endotp with {word}")]
async fn pad_only_endotp(w: &mut AlooWorld, _a: String, _b: String) {
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    // What a pad-only pair's link coming up establishes on both screens
    // (`session::register_pad_only_peer` marks OTP active immediately) -
    // `/endotp` now requires a genuinely active session to end.
    a.ui.mark_otp_active(a.peer);
    b.ui.mark_otp_active(b.peer);
    let peer_der = a.peer_der.clone();
    let peer = a.peer;
    aloo::client::otp::handle_end_otp_command(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        peer,
        peer_der,
    )
    .await
    .expect("/endotp should not fail");
}

#[given("bob has become unreachable for alice")]
async fn pad_only_peer_unreachable(w: &mut AlooWorld) {
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    let peer = a.peer;
    a.ui.offline.insert(peer);
    a.ui.set_link_status(peer, aloo::client::p2p::LinkStatus::Lost);
}

#[when("alice runs /endotp with bob expecting a refusal")]
async fn pad_only_endotp_refused(w: &mut AlooWorld) {
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    a.ui.mark_otp_active(a.peer);
    b.ui.mark_otp_active(b.peer);
    let peer_der = a.peer_der.clone();
    let peer = a.peer;
    aloo::client::otp::handle_end_otp_command(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        peer,
        peer_der,
    )
    .await
    .expect("a refusal is not an error");
}

#[then("the end is refused with nothing spent and the session still active")]
async fn pad_only_end_refused(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    let peer = a.peer;
    let envelopes = a
        .session
        .peer_link_mut()
        .pending_payloads(peer)
        .into_iter()
        .filter(|p| matches!(p, aloo::p2p_proto::P2pPayload::OtpEnvelope { .. }))
        .count();
    assert_eq!(envelopes, 0, "a refused end must put nothing on the wire");
    assert!(
        a.ui.is_otp_active(peer),
        "the session stays exactly as it was"
    );
    let state = a.session.otp_store_mut().get(&contact).expect("the contact exists");
    assert!(!state.pending_end_notice, "no end is owed - nothing entered the handshake");
    assert_eq!(
        state.next_out_seq, 0,
        "and not a byte of pad was spent on the refusal"
    );
    let (message, success) = a
        .ui
        .status_notice
        .clone()
        .expect("the refusal explains itself");
    assert!(
        message.contains("offline") && message.contains("both sides online"),
        "the notice says why and what to do: {message:?}"
    );
    assert!(!success);
}

#[when("bob drops before confirming, and later reconnects")]
async fn pad_only_peer_drops_and_reconnects(w: &mut AlooWorld) {
    // The queued notice is simply never handed to bob - his connection
    // handle from that moment is dead. On his return, alice knows him
    // again (what `register_pad_only_peer` does on the link coming up) and
    // her link-Active passes run exactly as `session.rs` runs them.
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    a.ui.known_users.insert(
        a.peer,
        aloo::proto::UserInfo {
            id: a.peer,
            name: "bob".into(),
            public_key_der: a.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );
    aloo::client::otp::recover_and_resend(&mut aloo::control::NullSink, &mut a.session, &mut a.ui)
        .await
        .expect("the recovery pass should not fail");
    aloo::client::otp::resend_pending_end_notices(
        &mut aloo::control::NullSink,
        &mut a.session,
        &mut a.ui,
    )
    .await
    .expect("the notice pass should not fail");
}

#[then("the very same notice is re-sent from recovery, and his confirmation ends it for both")]
async fn pad_only_end_recovered(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    let peer = a.peer;
    let envelopes: Vec<(u64, Option<u64>, aloo::proto::Envelope)> = a
        .session
        .peer_link_mut()
        .pending_payloads(peer)
        .into_iter()
        .filter_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpEnvelope {
                seq,
                msg_id,
                envelope,
                ..
            } => Some((seq, msg_id, envelope)),
            _ => None,
        })
        .collect();
    assert_eq!(
        envelopes.len(),
        2,
        "the original and exactly one recovered copy - the retry re-sends, never re-encodes"
    );
    assert_eq!(
        envelopes[0].0, envelopes[1].0,
        "both under the same slot: a re-encrypt would have taken a second one"
    );
    let state = a.session.otp_store_mut().get(&contact).expect("the contact exists");
    assert_eq!(
        state.next_out_seq, 1,
        "one spend total - the pair's pads stay in lockstep"
    );
    assert!(
        a.ui.is_otp_active(peer),
        "two-phase: alice is still in the session until bob confirms"
    );

    // Bob finally receives the recovered copy...
    let (seq, msg_id, envelope) = envelopes.into_iter().next_back().unwrap();
    aloo::client::otp::on_message(
        &mut b.session,
        &mut b.ui,
        None,
        b.peer,
        "alice".into(),
        seq,
        msg_id,
        envelope,
    )
    .await
    .expect("the receive path should not fail");
    assert!(!b.ui.is_otp_active(b.peer), "bob's side ends the moment it lands");

    // ...and his proof-carrying confirmation ends it on alice's side too.
    let (ack_seq, proof) = b
        .session
        .peer_link_mut()
        .pending_payloads(b.peer)
        .into_iter()
        .filter_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .next_back()
        .expect("the notice earns the same proof-carrying ack a message does");
    aloo::client::otp::on_delivery_ack(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        peer,
        ack_seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");
    assert!(!a.ui.is_otp_active(peer), "confirmed - both sides out together");
    assert!(
        a.session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice && s.pending_unacked_out_seq.is_none()),
        "nothing owed, nothing outstanding"
    );
}

#[then("the notice reaches bob under the pad, and his proof-carrying ack settles it")]
async fn pad_only_end_notice(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    assert!(
        a.session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| s.pending_end_notice),
        "the notice is owed until the peer confirms it"
    );
    assert!(
        a.session
            .otp_store_mut()
            .get(&contact)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_some(),
        "an ordinary gated send now: the gate closes behind the notice"
    );
    deliver_pad_envelope(a, b, "alice").await;
    assert!(
        !b.ui.is_otp_active(b.peer),
        "the peer converges to paused on reading it"
    );
    // Bob answers with the ordinary proof-carrying OtpDeliveryAck - free of
    // pad, like every message's ack - and that one ack settles both the
    // gate and the durable retry.
    let (seq, proof) = b
        .session
        .peer_link_mut()
        .pending_payloads(b.peer)
        .into_iter()
        .filter_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .next_back()
        .expect("the notice earns the same proof-carrying ack a message does");
    assert!(
        a.ui.is_otp_active(a.peer),
        "two-phase: alice's own side stays in the session until bob confirms"
    );
    aloo::client::otp::on_delivery_ack(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        a.peer,
        seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");
    assert!(
        a.session
            .otp_store_mut()
            .get(&contact)
            .is_some_and(|s| !s.pending_end_notice && s.pending_unacked_out_seq.is_none()),
        "his proof-carrying ack is what stops the retry and reopens the gate"
    );
    assert!(
        !a.ui.is_otp_active(a.peer),
        "and only that confirmation pauses alice's own side - both ends in sync"
    );
}

#[then(expr = "{word}'s acknowledgement proves he decrypted it")]
async fn pad_only_ack(w: &mut AlooWorld, _b: String) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    let (seq, proof) = b
        .session
        .peer_link_mut()
        .pending_payloads(b.peer)
        .into_iter()
        .find_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .expect("the receiving side acknowledges what it read");
    assert!(
        a.session
            .otp_store_mut()
            .get(&contact)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_some(),
        "the sender's gate is held until that ack lands"
    );
    aloo::client::otp::on_delivery_ack(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        a.peer,
        seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");
    assert!(
        a.session
            .otp_store_mut()
            .get(&contact)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_none(),
        "a proof the sender can verify is what reopens the gate"
    );
}

#[when(expr = "{word} runs \\/otp with {word}")]
async fn pad_only_slash_otp(w: &mut AlooWorld, _a: String, _b: String) {
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    let peer_der = a.peer_der.clone();
    aloo::client::otp::handle_provisioning_command(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        a.peer,
        peer_der,
        aloo::crypto::otp::OtpPurpose::Live,
    )
    .await
    .expect("/otp should not fail for a pad-only pair");
}

#[then(expr = "otp is active for {word} immediately, with nothing sent to negotiate it")]
async fn otp_active_with_nothing_sent(w: &mut AlooWorld, _b: String) {
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    assert!(
        a.ui.is_otp_active(a.peer),
        "both sides already hold the pad, so there is nothing to agree"
    );
    let peer = a.peer;
    assert!(
        a.session
            .peer_link_mut()
            .pending_payloads(peer)
            .iter()
            .all(|p| !matches!(
                p,
                aloo::p2p_proto::P2pPayload::Envelope { .. }
            )),
        "and no session request goes out - there is no envelope to carry one"
    );
}

// ---------------------------------------------------------------------
// A voice send's content phase surviving the sender's own restart (AC-316)
// ---------------------------------------------------------------------

#[when("alice records and sends a voice message to bob")]
async fn pad_only_send_voice(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    let pcm = b"the recording a restart must not lose".to_vec();
    let peer = a.peer;
    let peer_der = a.peer_der.clone();
    send_voice_offer(
        &mut aloo::control::NullSink,
        &mut a.session,
        &mut a.ui,
        peer,
        &contact,
        &peer_der,
        pcm.clone(),
        1200,
    )
    .await
    .expect("the voice offer should not fail");

    let (stream_id, seq, envelope) = a
        .session
        .peer_link_mut()
        .pending_payloads(peer)
        .into_iter()
        .find_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpVoiceOffer {
                stream_id,
                seq,
                envelope,
                ..
            } => Some((stream_id, seq, envelope)),
            _ => None,
        })
        .expect("the offer should have gone out");
    w.otp_stream_id = Some(stream_id);
    w.otp_voice_pcm = Some(pcm);

    // Bob receives it and auto-accepts - both his reply and his ack for
    // the offer sit queued, undelivered, exactly as they would if alice
    // were unreachable right now.
    aloo::client::otp::on_voice_offer(
        &mut aloo::control::NullSink,
        &mut b.session,
        &mut b.ui,
        b.peer,
        stream_id,
        seq,
        envelope,
    )
    .await;
}

#[when("alice's whole process restarts before bob's acceptance is processed")]
async fn pad_only_sender_restarts(w: &mut AlooWorld) {
    let (a, _) = w.pad_only.as_mut().expect("no pad-only pair");
    a.session.clear_own_file_targets_for_test();
    let store_path = a.session.otp_store_mut().path().to_path_buf();
    let reloaded =
        OtpStore::load(&store_path).expect("the staging record's file must reload");
    *a.session.otp_store_mut() = reloaded;
}

#[when("alice reconnects and bob's acceptance reaches her")]
async fn pad_only_resume_and_ack(w: &mut AlooWorld) {
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");
    // Alice's own restart also lost whatever she knew about bob being
    // reachable - `register_pad_only_peer` is what re-populates this on a
    // real reconnect's link-up; `resume_pending_content_sends` needs it to
    // resolve who to address.
    a.ui.known_users.insert(
        a.peer,
        aloo::proto::UserInfo {
            id: a.peer,
            name: "bob".into(),
            public_key_der: a.peer_der.clone(),
            key_mode: aloo::proto::KeyMode::PqHybrid,
        },
    );
    resume_pending_content_sends(&mut a.session, &mut a.ui)
        .await
        .expect("the resume pass should not fail");

    let (ack_seq, proof) = b
        .session
        .peer_link_mut()
        .pending_payloads(b.peer)
        .into_iter()
        .filter_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpDeliveryAck { seq, proof } => Some((seq, proof)),
            _ => None,
        })
        .next()
        .expect("bob acknowledged the offer");
    aloo::client::otp::on_delivery_ack(
        &mut aloo::control::NullSink,
        &mut a.ui,
        &mut a.session,
        a.peer,
        ack_seq,
        proof,
    )
    .await
    .expect("the ack path should not fail");
}

#[then("the recording still reaches bob, byte-identical, with no pad spent twice")]
async fn pad_only_recording_arrives_once(w: &mut AlooWorld) {
    let contact = w.otp_contact_name.clone().expect("no contact");
    let stream_id = w.otp_stream_id.expect("no stream_id recorded");
    let pcm = w.otp_voice_pcm.clone().expect("no pcm recorded");
    let arrived = w.temp_path("pad-only-content-restart-arrived");
    let (a, b) = w.pad_only.as_mut().expect("no pad-only pair");

    let peer = a.peer;
    let content_announcements: Vec<u64> = a
        .session
        .peer_link_mut()
        .pending_payloads(peer)
        .into_iter()
        .filter_map(|p| match p {
            aloo::p2p_proto::P2pPayload::OtpFileContentSeq {
                stream_id: s, seq, ..
            } if s == stream_id => Some(seq),
            _ => None,
        })
        .collect();
    assert_eq!(
        content_announcements.len(),
        1,
        "the content must be encrypted and announced exactly once, never twice"
    );
    let content_seq = content_announcements[0];

    let staged = a
        .session
        .otp_send_temp_file(stream_id)
        .expect("the content phase stages its ciphertext")
        .clone();
    std::fs::copy(&staged, &arrived).unwrap();

    finish_incoming_file(
        &mut b.session,
        &mut b.ui,
        b.peer,
        stream_id,
        OtpIncomingFileReceive {
            contact_name: contact,
            seq: Some(content_seq),
            temp_path: arrived,
            kind: OtpIncomingKind::Voice { duration_ms: 1200 },
        },
    )
    .await;

    let delivered = b
        .ui
        .private_rooms
        .values()
        .flat_map(|r| r.log.iter())
        .any(|e| {
            matches!(&e.body, aloo::client::tui::ui::MessageBody::Voice { pcm: p, .. } if *p == pcm)
        });
    assert!(delivered, "the recording arrives at bob, byte-identical");
}
