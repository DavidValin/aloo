//! Orchestration for OTP mail (docs/PROTOCOL.md §17): the session-side
//! half of the `/mail`//`/mailbox` surface in `crate::client::tui::otp_mail`. Everything here
//! either needs `SessionState` (the `otp` CLI, the stores, the identity
//! pin) or the control channel, which `UiState` deliberately has neither
//! of - so the UI emits `UiAction`s and these functions answer through
//! `UiState` setters.
//!
//! A mail spends the *same* sequential pad as the live P2P layer for that
//! contact, and passes through the same stop-and-wait gate
//! (`otp_store::OtpContactState::pending_unacked_out_seq`) - the only
//! difference is who acknowledges the spend: the server's durable-storage
//! `OtpMailResult` instead of the peer's `OtpDeliveryAck`. That sharing is
//! what makes the retry rule sound: while a mail is unacknowledged nothing
//! else can encrypt for that contact, so the `otp` CLI's `.last_sent`
//! safety copy is always exactly the mail, and `resend_pending` can replay
//! it byte-identically without ever spending fresh pad.

use zeroize::Zeroizing;

use crate::client::otp_cli;
use crate::client::otp_mail_store::{ReceivedMailRef, SentMailRef, SentMailStatus};
use crate::client::session::SessionState;
use crate::client::tui::otp_mail::{MailAttachment, MailboxRow};
use crate::client::tui::ui::UiState;
use crate::crypto;
use crate::crypto::otp::{
    OTP_MAIL_MAX_BYTES, OtpMailFile, OtpMailPayload, OtpMailSealed, OtpMailVoice, mail_id_is_valid,
    new_mail_id,
};
use crate::proto::{self, ClientMessage};

/// Fixed allowance the compose view's live size estimate adds on top of
/// the raw field/attachment bytes: the identity signature
/// (`crypto::pq::sign_mail`, ~5KB of ML-DSA-87 + RSA-4096 material) plus
/// bincode framing. Deliberately generous - the send path re-measures the
/// real encoded bytes before any pad is spent, so the estimate only has to
/// err on the safe side.
pub const MAIL_OVERHEAD_ESTIMATE: u64 = 8 * 1024;

/// The compose view's To-field verdict, computed fresh on every keystroke
/// (`UiAction::CheckOtpMailRecipient`). `Ok` means every *static*
/// precondition holds - a pinned user with that nickname, an `otp`
/// keychain contact for the pair - and carries the key bytes remaining, so
/// the "longer than the actual mail" comparison can then track every
/// content edit live without another subprocess call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientCheck {
    /// This client isn't running a `pq_hybrid` identity of its own, so no
    /// contact name can even be derived.
    NotPqIdentity,
    /// No `id_store` pin for that nickname (or its pinned key isn't a
    /// pq_hybrid bundle).
    NotPinned,
    /// Pinned, but the `otp` keychain has no contact for the pair.
    NoKeychainEntry,
    /// The `otp` binary couldn't be run at all.
    CliUnavailable,
    Ok {
        contact_name: String,
        enc_key_remaining: u64,
    },
}

fn now_utc_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The pre-decrypt verdict for one delivered mail - the layered refusal
/// rules of docs/PROTOCOL.md §17.3, pure so they're testable without a
/// live session. Every variant but `Decrypt` means `otp --decrypt` never
/// runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailGate {
    /// No pinned pq_hybrid identity for the claimed sender, or the mail's
    /// carried contact name isn't the one this client derives from its own
    /// pin - the mail was sealed under some other identity's pad, and
    /// decrypting it here would consume the wrong pad range. Left on the
    /// server, unacknowledged and untouched.
    RefuseContact,
    /// A spend this contact's counter already moved past - the pad range
    /// is consumed and redelivery can never work, so re-acknowledging is
    /// the only useful answer.
    AckOnly,
    /// A spend from the future - an earlier one is still in flight
    /// (§17.4); wait, unacknowledged.
    Wait,
    /// The exact next expected spend - the one genuine decrypt may run.
    Decrypt,
}

/// Applies §17.3's pre-decrypt checks: `expected_contact` is the contact
/// name derived from this client's *own pinned key* for the claimed
/// sender (`None` when no usable pin exists), `carried_contact` what the
/// mail claims, `next_expected` the contact's receive counter, `seq` the
/// mail's spend.
pub fn mail_gate(
    expected_contact: Option<&str>,
    carried_contact: &str,
    next_expected: u64,
    seq: u64,
) -> MailGate {
    match expected_contact {
        Some(expected) if expected == carried_contact => {
            if seq < next_expected {
                MailGate::AckOnly
            } else if seq > next_expected {
                MailGate::Wait
            } else {
                MailGate::Decrypt
            }
        }
        _ => MailGate::RefuseContact,
    }
}

/// Runs the recipient checks for `nickname` - see `RecipientCheck`.
pub(crate) async fn check_recipient(session: &SessionState, nickname: &str) -> RecipientCheck {
    let Some(own_fp) = session.own_pq_fp else {
        return RecipientCheck::NotPqIdentity;
    };
    let Some(pinned_der) = session.id_store.get(nickname) else {
        return RecipientCheck::NotPinned;
    };
    let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(pinned_der) else {
        return RecipientCheck::NotPinned;
    };
    let contact_name = crypto::otp::contact_name_for(&own_fp, &peer_fp);
    match otp_cli::status(&session.otp_cli_cfg, &contact_name).await {
        Ok(Some(status)) => RecipientCheck::Ok {
            contact_name,
            enc_key_remaining: status.enc_key_remaining,
        },
        Ok(None) => RecipientCheck::NoKeychainEntry,
        Err(_) => RecipientCheck::CliUnavailable,
    }
}

/// `UiAction::CheckOtpMailRecipient`'s handler.
pub(crate) async fn handle_check_recipient(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
) {
    let check = check_recipient(session, &nickname).await;
    ui_state.otp_mail_set_check(&nickname, check);
}

/// `UiAction::SendOtpMail`'s handler - the only path that ever encrypts
/// and uploads a mail, reached exclusively through the compose view's
/// confirm popup. Re-runs every validation from scratch rather than
/// trusting the UI's cached check (the same defensive re-check
/// `otp::confirm_generate` applies before committing real key material),
/// then: encode + sign + seal through `otp --encrypt`, reserve the
/// contact's gate, persist the local reference, and upload. On any
/// pre-encrypt failure the compose view stays open with a notice; only a
/// fully-sent mail closes it.
pub(crate) async fn handle_send(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(mail_view) = ui_state.otp_mail.as_ref() else {
        return Ok(());
    };
    let to = mail_view.compose.to.trim().to_string();
    let subtext = mail_view.compose.subtext.clone();
    let content = mail_view.compose.content.clone();
    let attachments = mail_view.compose.attachments.clone();

    let fail = |ui_state: &mut UiState, message: String| {
        ui_state.push_status_notice(message, false);
    };

    if to.is_empty() || !crate::validation::is_storable(&to) {
        fail(ui_state, "OTP mail: recipient nickname is not valid".to_string());
        return Ok(());
    }
    let check = check_recipient(session, &to).await;
    let RecipientCheck::Ok {
        contact_name,
        enc_key_remaining,
    } = check
    else {
        fail(
            ui_state,
            format!("OTP mail: '{to}' is not a pinned user you hold an otp key for"),
        );
        return Ok(());
    };
    // The same stop-and-wait gate every other spend for this contact obeys
    // - a mail must never encrypt while an earlier send still awaits its
    // acknowledgement, or `.last_sent` would no longer name that earlier
    // send and its recovery path would break.
    let unacked = session
        .otp_store
        .get(&contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
    if unacked {
        fail(
            ui_state,
            "OTP mail: a previous send to this contact hasn't been acknowledged yet - try again shortly"
                .to_string(),
        );
        return Ok(());
    }

    // Attachment bytes are read only now, at the moment of the confirmed
    // send - the compose view held paths and sizes only.
    let mut voices: Vec<OtpMailVoice> = Vec::new();
    let mut files: Vec<OtpMailFile> = Vec::new();
    for attachment in attachments {
        match attachment {
            MailAttachment::Voice { duration_ms, pcm } => {
                voices.push(OtpMailVoice { duration_ms, pcm });
            }
            MailAttachment::File { filename, path, .. } => match std::fs::read(&path) {
                Ok(bytes) => files.push(OtpMailFile { filename, bytes }),
                Err(e) => {
                    fail(ui_state, format!("OTP mail: could not read '{filename}': {e}"));
                    return Ok(());
                }
            },
        }
    }

    let payload = OtpMailPayload {
        from: ui_state.own_name.clone(),
        to: to.clone(),
        sent_at_utc: now_utc_secs(),
        subtext,
        content,
        voices,
        attachments: files,
    };
    let Ok(payload_bytes) = proto::encode(&payload) else {
        fail(ui_state, "OTP mail: could not encode the mail".to_string());
        return Ok(());
    };
    let payload_bytes = Zeroizing::new(payload_bytes);
    let Some(signing) = session.own_pq_private.as_ref() else {
        fail(ui_state, "OTP mail: this session has no pq_hybrid identity".to_string());
        return Ok(());
    };
    let Ok(signature) = crypto::pq::sign_mail(signing, &payload_bytes) else {
        fail(ui_state, "OTP mail: could not sign the mail".to_string());
        return Ok(());
    };
    let sealed = OtpMailSealed {
        payload: payload_bytes.to_vec(),
        signature,
    };
    let Ok(plaintext) = proto::encode(&sealed) else {
        fail(ui_state, "OTP mail: could not encode the mail".to_string());
        return Ok(());
    };
    let plaintext = Zeroizing::new(plaintext);
    // The real, measured bound - the compose view's estimate only
    // approximated this.
    if plaintext.len() > OTP_MAIL_MAX_BYTES {
        fail(
            ui_state,
            format!(
                "OTP mail: mail is {} but the limit is {}MB",
                crate::client::tui::ui::format_file_size(plaintext.len() as u64),
                OTP_MAIL_MAX_BYTES / (1024 * 1024)
            ),
        );
        return Ok(());
    }
    if plaintext.len() as u64 >= enc_key_remaining {
        fail(
            ui_state,
            "OTP mail: the mail is larger than the key remaining for this contact".to_string(),
        );
        return Ok(());
    }

    let outcome =
        otp_cli::encrypt_retrying(&session.otp_cli_cfg, &contact_name, &plaintext, true).await;
    let ciphertext = match outcome {
        Ok(otp_cli::OtpCliOutcome::Ok(bytes)) => bytes,
        _ => {
            fail(
                ui_state,
                "OTP mail: the otp command failed to encrypt this mail - not sent".to_string(),
            );
            return Ok(());
        }
    };

    // Pad genuinely spent - reserve the gate and persist the reference
    // *before* the upload, so a crash between the two still resends
    // (`resend_pending`) instead of losing track of a spend.
    let mail_id = new_mail_id();
    let seq = session
        .otp_store
        .get(&contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    session.otp_store.record_sent(
        &contact_name,
        seq,
        crate::client::otp_store::PendingOtpContent::Mail {
            mail_id: mail_id.clone(),
        },
    );
    let _ = session.otp_store.save();
    let sent_at_utc = payload.sent_at_utc;
    session.otp_mail_store.record_sent(SentMailRef {
        mail_id: mail_id.clone(),
        to: to.clone(),
        contact_name: contact_name.clone(),
        seq,
        sent_at_utc,
        status: SentMailStatus::AwaitingServerAck,
    });
    let _ = session.otp_mail_store.save();

    wr.send_control(&ClientMessage::OtpMailSend {
        mail_id,
        to: to.clone(),
        contact_name: contact_name.clone(),
        seq,
        sent_at_utc,
        ciphertext,
    })
    .await?;

    ui_state.otp_mail_close();
    ui_state.push_status_notice(
        format!("OTP mail to {to} sent - awaiting the server's confirmation"),
        true,
    );
    refresh_key_header_if_connected(session, ui_state, &to, &contact_name).await;
    Ok(())
}

/// Re-uploads every sent mail still awaiting the server's storage
/// acknowledgement, using the exact ciphertext `otp --recover-last --sent`
/// replays - never a fresh encode. Called once per (re)connect, right
/// after the initial `OtpMailFetch`. A mail whose contact gate no longer
/// names its seq is skipped outright: the gate having moved on means the
/// acknowledgement actually arrived (and a crash lost only the local
/// status update), and `.last_sent` may already be someone else's bytes -
/// resending those as this mail would be worse than leaving the status
/// stale for the fetch's `OtpMailDelivered` to eventually resolve.
pub(crate) async fn resend_pending(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<()> {
    let awaiting = session.otp_mail_store.awaiting_server_ack();
    for mail_ref in awaiting {
        let gate_holds_this = session
            .otp_store
            .get(&mail_ref.contact_name)
            .and_then(|s| s.pending_unacked_out_seq)
            == Some(mail_ref.seq);
        if !gate_holds_this {
            continue;
        }
        let Ok(Some(recovered)) = otp_cli::recover_last(
            &session.otp_cli_cfg,
            &mail_ref.contact_name,
            otp_cli::RecoverDirection::Sent,
        )
        .await
        else {
            continue;
        };
        wr.send_control(&ClientMessage::OtpMailSend {
            mail_id: mail_ref.mail_id,
            to: mail_ref.to,
            contact_name: mail_ref.contact_name,
            seq: mail_ref.seq,
            sent_at_utc: mail_ref.sent_at_utc,
            ciphertext: recovered,
        })
        .await?;
    }
    Ok(())
}

/// Rebuilds the mailbox rows from the store, newest first across both
/// directions - pushed to the UI whenever the popup opens or any mail
/// event lands while it's showing.
pub(crate) fn mailbox_rows(session: &SessionState) -> Vec<MailboxRow> {
    let mut rows: Vec<(u64, MailboxRow)> = session
        .otp_mail_store
        .received_refs()
        .into_iter()
        .map(|r| (r.received_at_utc, MailboxRow::Received(r)))
        .chain(
            session
                .otp_mail_store
                .sent_refs()
                .into_iter()
                .map(|r| (r.sent_at_utc, MailboxRow::Sent(r))),
        )
        .collect();
    rows.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
    rows.into_iter().map(|(_, row)| row).collect()
}

fn refresh_mailbox_if_open(session: &SessionState, ui_state: &mut UiState) {
    if ui_state.otp_mailbox_open() {
        ui_state.otp_mail_set_mailbox_rows(mailbox_rows(session));
    }
}

/// A mail encrypt/decrypt is a genuine pad spend, so it refreshes the
/// §16.5 live key-metadata header exactly like a live send/receive does -
/// best-effort, only possible when the mail's counterpart happens to be
/// connected right now (a `UserId` exists for `nickname`); the offline
/// case has no session header on screen to refresh.
async fn refresh_key_header_if_connected(
    session: &SessionState,
    ui_state: &mut UiState,
    nickname: &str,
    contact_name: &str,
) {
    let peer = ui_state
        .known_users
        .iter()
        .find(|(_, u)| u.name == nickname)
        .map(|(id, _)| *id);
    if let Some(peer) = peer {
        crate::client::otp::refresh_otp_key_status(
            &session.otp_cli_cfg,
            ui_state,
            peer,
            contact_name,
        )
        .await;
    }
}

/// `UiAction::OpenOtpMailbox`'s handler.
pub(crate) fn handle_open_mailbox(session: &SessionState, ui_state: &mut UiState) {
    ui_state.otp_mail_set_mailbox_rows(mailbox_rows(session));
}

/// Applies `ServerMessage::OtpMailResult`: moves the sent reference
/// forward (or to `Failed`) and clears the contact's gate for this spend;
/// since a cleared gate authorises exactly one more send, it also drains
/// one queued P2P item if any were waiting behind the mail.
pub(crate) async fn on_mail_result(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    mail_id: String,
    ok: bool,
    reason: Option<String>,
) -> proto::Result<()> {
    let Some(mail_ref) = session.otp_mail_store.sent_ref(&mail_id).cloned() else {
        return Ok(());
    };
    let status = if ok {
        SentMailStatus::StoredOnServer
    } else {
        SentMailStatus::Failed
    };
    if session.otp_mail_store.set_sent_status(&mail_id, status) {
        let _ = session.otp_mail_store.save();
    }
    // Either way the gate clears: on `ok` the spend reached its
    // destination; on failure no acknowledgement will ever come and the
    // contact must not stay wedged forever. The failure notice is loud
    // about what a refused-after-spend mail means for the pad.
    if session.otp_store.record_acked(&mail_ref.contact_name, mail_ref.seq) {
        let _ = session.otp_store.save();
        crate::client::otp::flush_one_queued(wr, ui_state, session, &mail_ref.contact_name).await?;
    }
    if ok {
        ui_state.push_status_notice(
            format!("OTP mail to {} is stored on the server", mail_ref.to),
            true,
        );
    } else {
        ui_state.push_status_notice(
            format!(
                "OTP mail to {} was refused by the server{} - its pad bytes are spent; the contact may need re-keying (/otp)",
                mail_ref.to,
                reason.map(|r| format!(": {r}")).unwrap_or_default()
            ),
            false,
        );
    }
    refresh_mailbox_if_open(session, ui_state);
    Ok(())
}

/// Applies `ServerMessage::OtpMailDelivered`: the recipient genuinely
/// decrypted the mail. Updates the reference, acknowledges the receipt so
/// the server can forget it, and - the one liveness edge the shared pad
/// counter has - re-runs the P2P recovery scan: a live send to this
/// contact refused by the receiver while the mail was still ahead of it in
/// their pad order (docs/PROTOCOL.md §17.4) becomes deliverable at exactly
/// this moment.
pub(crate) async fn on_mail_delivered(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    mail_id: String,
) -> proto::Result<()> {
    if let Some(mail_ref) = session.otp_mail_store.sent_ref(&mail_id).cloned() {
        // A delivery notice can arrive with the storage ack lost (crash
        // between the two) - the gate still clears, exactly as it would
        // have on the ack itself.
        if session.otp_store.record_acked(&mail_ref.contact_name, mail_ref.seq) {
            let _ = session.otp_store.save();
            crate::client::otp::flush_one_queued(wr, ui_state, session, &mail_ref.contact_name)
                .await?;
        }
        if session
            .otp_mail_store
            .set_sent_status(&mail_id, SentMailStatus::Delivered)
        {
            let _ = session.otp_mail_store.save();
            ui_state.push_status_notice(
                format!("OTP mail to {} was delivered \u{2713}", mail_ref.to),
                true,
            );
        }
    }
    // Acknowledged even with no local reference (the user may have removed
    // it) - otherwise the server re-notifies forever.
    wr.send_control(&ClientMessage::OtpMailDeliveredAck { mail_id })
        .await?;
    crate::client::otp::recover_and_resend(wr, session, ui_state).await?;
    refresh_mailbox_if_open(session, ui_state);
    Ok(())
}

/// Applies `ServerMessage::OtpMailDeliver` - one stored mail arriving from
/// the server. The pad-safety ordering here is deliberate and layered
/// (docs/PROTOCOL.md §17.3, §17.4); every check runs *before* `otp
/// --decrypt` ever touches the keychain:
///
/// 1. dedupe - an id already stored locally just re-acknowledges (the
///    earlier ack was lost);
/// 2. the pairwise contact is derived from this client's **own pinned
///    key** for the claimed sender - a mismatch with the carried contact
///    name means the mail was sealed under some other identity's pad, and
///    decrypting it against the local contact would corrupt that pad;
/// 3. the sequence guard - only the exact next expected spend for the
///    contact may reach the pad, exactly like a live P2P envelope: a
///    lower seq re-acknowledges (already consumed), a higher one waits
///    (an earlier spend is still in flight).
///
/// Only then is the one genuine decrypt run, the payload's identity
/// signature verified against the pinned bundle, and the mail re-padded
/// under fresh local randomness for storage - after which the ack tells
/// the server to delete its copy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn on_mail_deliver(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    mail_id: String,
    from: String,
    contact_name: String,
    seq: u64,
    ciphertext: Vec<u8>,
) -> proto::Result<()> {
    if !mail_id_is_valid(&mail_id) {
        return Ok(());
    }
    if session.otp_mail_store.has_received(&mail_id) {
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    }
    let pinned_der = session.id_store.get(&from).map(|d| d.to_vec());
    let expected_contact = session.own_pq_fp.and_then(|own_fp| {
        let peer_fp = crypto::pq::fingerprint_of_encoded(pinned_der.as_deref()?)?;
        Some(crypto::otp::contact_name_for(&own_fp, &peer_fp))
    });
    let next_expected = expected_contact
        .as_deref()
        .and_then(|c| session.otp_store.get(c))
        .map(|s| s.next_expected_in_seq)
        .unwrap_or(0);
    match mail_gate(expected_contact.as_deref(), &contact_name, next_expected, seq) {
        MailGate::RefuseContact => {
            ui_state.push_status_notice(
                format!(
                    "OTP mail from '{from}' held: it wasn't sealed for the identity pinned under that nickname"
                ),
                false,
            );
            return Ok(());
        }
        MailGate::AckOnly => {
            // Already consumed once (the ack was lost, or the local index
            // was written and the ack crashed) - the pad range is gone
            // either way, so acknowledging is the only useful answer.
            wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
            return Ok(());
        }
        MailGate::Wait => {
            ui_state.push_status_notice(
                format!("OTP mail from {from} is waiting for an earlier message to arrive first"),
                false,
            );
            return Ok(());
        }
        MailGate::Decrypt => {}
    }
    let expected_contact = expected_contact.expect("Decrypt implies a derived contact");
    let pinned_der = pinned_der.expect("Decrypt implies a pin");

    let outcome =
        otp_cli::decrypt_retrying(&session.otp_cli_cfg, &expected_contact, &ciphertext, true).await;
    let sealed_bytes = match outcome {
        Ok(otp_cli::OtpCliOutcome::Ok(bytes)) => Zeroizing::new(bytes),
        _ => {
            ui_state.push_status_notice(
                format!("OTP mail from {from} could not be decrypted - left on the server"),
                false,
            );
            return Ok(());
        }
    };
    // The pad range is consumed from here on - everything below ends in an
    // ack, because redelivering the same ciphertext can never work again.
    if !session.otp_store.record_received(&expected_contact, seq) {
        return Ok(());
    }
    let _ = session.otp_store.save();

    let discard = |ui_state: &mut UiState, why: &str| {
        ui_state.push_status_notice(
            format!("OTP mail claiming to be from {from} was discarded: {why}"),
            false,
        );
    };
    let Ok(sealed) = proto::decode::<OtpMailSealed>(&sealed_bytes) else {
        discard(ui_state, "malformed");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    };
    let Ok(pinned_bundle) = proto::decode::<crypto::pq::PqPublicBundle>(&pinned_der) else {
        discard(ui_state, "pinned key unreadable");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    };
    // A one-time pad authenticates nothing - this signature check against
    // the *pinned* identity is what stops a bit-flipped or forged payload
    // from ever being believed.
    if !crypto::pq::verify_mail(&pinned_bundle, &sealed.payload, &sealed.signature) {
        discard(ui_state, "its identity signature doesn't verify");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    }
    let Ok(payload) = proto::decode::<OtpMailPayload>(&sealed.payload) else {
        discard(ui_state, "malformed payload");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    };
    if payload.from != from || payload.to != ui_state.own_name {
        discard(ui_state, "its sealed addressing doesn't match");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    }

    // Re-pad for storage: ciphertext + pad on disk, plaintext nowhere.
    let (stored_ct, pad) = crypto::otp::repad(&sealed.payload);
    let size = sealed.payload.len() as u64;
    let record = ReceivedMailRef {
        mail_id: mail_id.clone(),
        from: from.clone(),
        sent_at_utc: payload.sent_at_utc,
        received_at_utc: now_utc_secs(),
        size,
    };
    if let Err(e) = session
        .otp_mail_store
        .store_received_payload(record, &stored_ct, &pad)
    {
        // Pad consumed but nothing persisted - the mail is genuinely lost.
        // Acknowledge anyway: the server redelivering the same ciphertext
        // can never decrypt again.
        discard(ui_state, &format!("could not be stored: {e}"));
        wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
        return Ok(());
    }
    let _ = session.otp_mail_store.save();
    wr.send_control(&ClientMessage::OtpMailAck { mail_id }).await?;
    ui_state.push_status_notice(
        format!("\u{1F4E8} OTP mail from {from} - type /mailbox to read it"),
        true,
    );
    crate::client::voice_stream::play_bell_chime(session);
    refresh_key_header_if_connected(session, ui_state, &from, &expected_contact).await;
    refresh_mailbox_if_open(session, ui_state);
    Ok(())
}

/// `UiAction::ReadOtpMail`'s handler: XORs the stored pair back together
/// in memory, decodes the payload, and opens the reader. The blob pair on
/// disk is untouched - it outlives every read until the user removes the
/// mail.
pub(crate) fn handle_read(session: &SessionState, ui_state: &mut UiState, mail_id: String) {
    let Some(bytes) = session.otp_mail_store.read_received_payload(&mail_id) else {
        ui_state.push_status_notice("OTP mail: could not read this mail's stored files".to_string(), false);
        return;
    };
    let bytes = Zeroizing::new(bytes);
    let Ok(payload) = proto::decode::<OtpMailPayload>(&bytes) else {
        ui_state.push_status_notice("OTP mail: this mail's stored files don't decode".to_string(), false);
        return;
    };
    ui_state.otp_mail_open_reader(mail_id, payload);
}

/// `UiAction::DeleteOtpMail`'s handler: a received id destroys its stored
/// ciphertext and pad (both overwritten before removal - after this the
/// content is unrecoverable); a sent id just drops the local reference.
pub(crate) fn handle_delete(session: &mut SessionState, ui_state: &mut UiState, mail_id: String) {
    let removed = if session.otp_mail_store.has_received(&mail_id) {
        session.otp_mail_store.remove_received(&mail_id)
    } else {
        session.otp_mail_store.remove_sent(&mail_id)
    };
    if removed {
        let _ = session.otp_mail_store.save();
    }
    refresh_mailbox_if_open(session, ui_state);
}

/// `UiAction::SaveOtpMailAttachment`'s handler: writes one attachment of
/// the mail currently open in the reader to `~/.aloo/downloads`, under the
/// same sanitized-filename rules an accepted file transfer uses.
pub(crate) fn handle_save_attachment(ui_state: &mut UiState, index: usize) {
    let Some(attachment) = ui_state
        .otp_mail
        .as_ref()
        .and_then(|m| m.reader.as_ref())
        .and_then(|r| r.payload.attachments.get(index))
    else {
        return;
    };
    let dest_name = crate::client::file_transfer::safe_filename(
        &crate::client::file_transfer::truncate_filename(&attachment.filename),
    );
    let dir = crate::client::file_transfer::default_download_dir();
    let dest = dir.join(&dest_name);
    let result = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&dest, &attachment.bytes));
    match result {
        Ok(()) => ui_state.push_status_notice(
            format!("Saved {dest_name} to {}", dir.display()),
            true,
        ),
        Err(e) => ui_state.push_status_notice(format!("Could not save {dest_name}: {e}"), false),
    }
}
