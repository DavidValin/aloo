//! Orchestration for OTP mail (docs/PROTOCOL.md §17): the session-side
//! half of the `/mail`//`/mailbox` surface in `crate::client::tui::otp_mail`. Everything here
//! either needs `SessionState` (the `otp` CLI, the stores, the identity
//! pin) or the control channel, which `UiState` deliberately has neither
//! of - so the UI emits `UiAction`s and these functions answer through
//! `UiState` setters.
//!
//! A mail spends its *own* pad - the `mail-` prefixed keychain contact
//! `crypto::otp::contact_name_for_mail` names, never the live session's -
//! and passes through that contact's own stop-and-wait gate
//! (`otp_store::OtpContactState::pending_unacked_out_seq`), acknowledged by
//! the server's durable-storage `OtpMailResult` rather than a peer's
//! `OtpDeliveryAck`. The gate is what makes the retry rule sound: while a
//! mail is unacknowledged nothing else can encrypt for that contact, so the
//! `otp` CLI's `.last_sent` safety copy is always exactly the mail, and
//! `resend_pending` can replay it byte-identically without ever spending
//! fresh pad.

use zeroize::Zeroizing;

use crate::client::otp_cli;
use crate::client::otp_mail_store::{ReceivedMailRef, SentMailRef, SentMailStatus};
use crate::client::session::SessionState;
use crate::client::tui::otp_mail::{MailAttachment, MailDeviceOption, MailboxRow};
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
    /// No `id_store` pin for that nickname (or its pinned key isn't a
    /// pq_hybrid bundle).
    NotPinned,
    /// Pinned, but the `otp` keychain has no *mail-purpose* contact for the
    /// pair yet (a live `/otp` session key, if any, does not count - mail
    /// always spends its own key, `crypto::otp::contact_name_for_mail`).
    NoMailKey,
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

/// Runs the recipient checks for `(nickname, device_id)` - see
/// `RecipientCheck`. No live connection is open at compose time, so the
/// caller must name a device explicitly - the compose view's device
/// selector (`ComposeState::devices`/`selected_device`,
/// `enumerate_mail_devices`) is what picks one; this function no longer
/// resolves "most recently seen" on its own the way it once did. A device
/// with no pinned key at all (a stale/unknown device_id) reads as
/// `NotPinned`.
pub async fn check_recipient(
    session: &SessionState,
    nickname: &str,
    device_id: &str,
) -> RecipientCheck {
    let own_fp = session.own_pq_fp;
    let Some(pinned_der) = session.id_store.get_for_device(nickname, device_id) else {
        return RecipientCheck::NotPinned;
    };
    let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(pinned_der) else {
        return RecipientCheck::NotPinned;
    };
    let contact_name =
        crypto::otp::contact_name_for_mail(&own_fp, &session.own_device_id, &peer_fp, device_id);
    match otp_cli::status(&session.otp_cli_cfg, &contact_name).await {
        Ok(Some(status)) => RecipientCheck::Ok {
            contact_name,
            enc_key_remaining: status.enc_key_remaining,
        },
        Ok(None) => RecipientCheck::NoMailKey,
        Err(_) => RecipientCheck::CliUnavailable,
    }
}

/// Every device `nickname` has a pinned identity for, each with whether it
/// has a mail-purpose otp key - what populates the compose view's device
/// selector. Skips a device pinned under the empty/unbound device_id: it
/// can never be a valid mail target, since `contact_name_for_mail` needs a
/// real device_id to qualify a name under. One `otp_cli::status` call per
/// candidate device - fine since this only runs once per distinct
/// nickname (`UiState::otp_mail_set_devices`'s memoization), never per
/// keystroke.
pub async fn enumerate_mail_devices(session: &SessionState, nickname: &str) -> Vec<MailDeviceOption> {
    let own_fp = session.own_pq_fp;
    let mut out = Vec::new();
    for device in session.id_store.devices_of(nickname) {
        if device.device_id.is_empty() {
            continue;
        }
        let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(&device.key) else {
            continue;
        };
        let contact_name = crypto::otp::contact_name_for_mail(
            &own_fp,
            &session.own_device_id,
            &peer_fp,
            &device.device_id,
        );
        let status = otp_cli::status(&session.otp_cli_cfg, &contact_name)
            .await
            .ok()
            .flatten();
        out.push(MailDeviceOption {
            device_id: device.device_id.clone(),
            last_seen_unix: device.last_seen_unix,
            contact_name,
            has_mail_key: status.is_some(),
            enc_key_remaining: status.map(|s| s.enc_key_remaining).unwrap_or(0),
        });
    }
    out
}

/// `UiAction::CheckOtpMailRecipient`'s handler - fired on every To-field
/// keystroke. Only re-enumerates the nickname's devices when the compose
/// view doesn't already have them (`devices_for` mismatch, cleared
/// alongside `check` on every edit), then re-checks against whichever
/// device ends up selected.
pub(crate) async fn handle_check_recipient(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
) {
    let already_have = ui_state
        .otp_mail
        .as_ref()
        .is_some_and(|m| m.compose.devices_for.as_deref() == Some(nickname.as_str()));
    if !already_have {
        let devices = enumerate_mail_devices(session, &nickname).await;
        ui_state.otp_mail_set_devices(&nickname, devices);
    }
    let Some(device_id) = ui_state.otp_mail_selected_device_id(&nickname) else {
        ui_state.otp_mail_set_check(&nickname, RecipientCheck::NotPinned);
        return;
    };
    let check = check_recipient(session, &nickname, &device_id).await;
    ui_state.otp_mail_set_check(&nickname, check);
}

/// `UiAction::SelectOtpMailDevice`'s handler - Up/Down inside the device
/// selector. Only re-runs the recipient check against the newly
/// highlighted device; the device list itself is already known, so no
/// re-enumeration.
pub(crate) async fn handle_select_device(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    device_id: String,
) {
    if !ui_state.otp_mail_set_selected_device(&nickname, &device_id) {
        return;
    }
    let check = check_recipient(session, &nickname, &device_id).await;
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
///
/// `pub` (not `pub(crate)`) so a test can drive it directly against a
/// `RecordingSink` and assert on the exact wire message it produces -
/// same rationale as `on_mail_deliver`'s own visibility
/// (`test/otp_mail_device_test.rs`'s device-selection proof needs to see
/// which device's contact name a send actually sealed under).
pub async fn handle_send(
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
        fail(
            ui_state,
            "OTP mail: recipient nickname is not valid".to_string(),
        );
        return Ok(());
    }
    let Some(device_id) = (mail_view.compose.devices_for.as_deref() == Some(mail_view.compose.to.as_str()))
        .then(|| mail_view.compose.devices.get(mail_view.compose.selected_device))
        .flatten()
        .map(|d| d.device_id.clone())
    else {
        fail(
            ui_state,
            "OTP mail: no device selected for this recipient".to_string(),
        );
        return Ok(());
    };
    let check = check_recipient(session, &to, &device_id).await;
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
        .is_some()
        || session.otp_store.encrypt_in_flight(&contact_name);
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
                    fail(
                        ui_state,
                        format!("OTP mail: could not read '{filename}': {e}"),
                    );
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
    let Ok(signature) = crypto::pq::sign_mail(&session.own_pq_private, &payload_bytes) else {
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

    // Written ahead of the encrypt, so a kill inside its window leaves a
    // reconcilable record instead of an orphaned spend
    // (`OtpContactState::encrypt_intent`) - the mail id is fixed now so the
    // promoted record still names the same mail.
    let mail_id = new_mail_id();
    if !crate::client::otp::stage_encrypt_intent(
        session,
        &contact_name,
        crate::client::otp_store::PendingOtpContent::Mail {
            mail_id: mail_id.clone(),
        },
        // Acknowledged by the server's storage, never by a pad proof.
        None,
    ) {
        fail(
            ui_state,
            "OTP mail: could not record this send before encrypting - not sent".to_string(),
        );
        return Ok(());
    }
    let outcome =
        otp_cli::encrypt_retrying(&session.otp_cli_cfg, &contact_name, &plaintext, true).await;
    let ciphertext = match outcome {
        Ok(otp_cli::OtpCliOutcome::Ok(bytes)) => bytes,
        _ => {
            session.otp_store.clear_encrypt_intent(&contact_name);
            let _ = session.otp_store.save();
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
        // No ack proof to expect. Every other spend is acknowledged by the
        // peer, who proves possession of the mirror pad by naming what was
        // buried under it; a mail's is acknowledged by the *server*, which
        // holds no pad and only ever claims to have stored the ciphertext.
        // Nothing weaker is on offer here, and nothing stronger is needed:
        // "stored" is exactly the property this spend waits on, and the
        // recipient's own binding still comes from the key-derived contact
        // name rather than from anything the server asserts.
        None,
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
    notify_if_mail_key_exhausted(session, ui_state, &to, &contact_name).await;
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
/// Rebuilds the `SentMailRef` for a mail spend promoted by startup
/// reconciliation (`client::otp::reconcile_orphaned_sends`): the process
/// died between the mail's `otp --encrypt` and its bookkeeping, so the
/// spend is real but the reference `resend_pending` retries from was never
/// written. The recipient nickname is re-derived the only honest way left -
/// scanning the pinned identities for the one whose mail-purpose contact
/// name matches - and the restored reference then retries exactly like any
/// other mail awaiting the server's acknowledgement, re-uploading the
/// tool's kept ciphertext. A contact name matching no pin (the pin was
/// deleted since) restores nothing; the promoted gate then holds until the
/// user replaces the mail key, which is already the manual recovery for a
/// deleted pin.
pub fn restore_orphaned_mail_ref(
    mail_store: &mut crate::client::otp_mail_store::OtpMailStore,
    id_store: &crate::client::idstore::IdStore,
    own_fp: &[u8; 32],
    own_device_id: &str,
    contact_name: &str,
    mail_id: String,
    seq: u64,
) {
    let Some(to) = id_store.nicknames().into_iter().find(|nick| {
        id_store
            .get(nick)
            .and_then(crate::crypto::pq::fingerprint_of_encoded)
            .zip(id_store.most_recent_device_id(nick).filter(|d| !d.is_empty()))
            .is_some_and(|(peer_fp, peer_device_id)| {
                crate::crypto::otp::contact_name_for_mail(own_fp, own_device_id, &peer_fp, peer_device_id)
                    == contact_name
            })
    }) else {
        return;
    };
    let sent_at_utc = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    mail_store.record_sent(SentMailRef {
        mail_id,
        to,
        contact_name: contact_name.to_string(),
        seq,
        sent_at_utc,
        status: SentMailStatus::AwaitingServerAck,
    });
    let _ = mail_store.save();
}

/// Re-uploads one still-`AwaitingServerAck` sent mail using the exact
/// ciphertext `otp --recover-last --sent` replays - never a fresh encode.
/// `false` when nothing was actually resent: either the contact's gate no
/// longer names this mail's seq (its acknowledgement already arrived, or a
/// concurrent resend already went out for it), or `.last_sent` has nothing
/// recoverable. Shared by the reconnect pass (`resend_pending`) and by
/// `on_mail_result`'s immediate retry the moment a storage failure comes
/// back, so a mail never needs a reconnect just to try again.
async fn resend_one(
    wr: &mut impl crate::control::ControlSink,
    session: &SessionState,
    mail_ref: &SentMailRef,
) -> proto::Result<bool> {
    let gate_holds_this = session
        .otp_store
        .get(&mail_ref.contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        == Some(mail_ref.seq);
    if !gate_holds_this {
        return Ok(false);
    }
    let Ok(Some(recovered)) = otp_cli::recover_last(
        &session.otp_cli_cfg,
        &mail_ref.contact_name,
        otp_cli::RecoverDirection::Sent,
    )
    .await
    else {
        return Ok(false);
    };
    wr.send_control(&ClientMessage::OtpMailSend {
        mail_id: mail_ref.mail_id.clone(),
        to: mail_ref.to.clone(),
        contact_name: mail_ref.contact_name.clone(),
        seq: mail_ref.seq,
        sent_at_utc: mail_ref.sent_at_utc,
        ciphertext: recovered,
    })
    .await?;
    Ok(true)
}

pub(crate) async fn resend_pending(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
) -> proto::Result<()> {
    let awaiting = session.otp_mail_store.awaiting_server_ack();
    for mail_ref in awaiting {
        resend_one(wr, session, &mail_ref).await?;
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

/// The header's "<n> unread OTP Mails" count - refreshed whenever the
/// received set can have changed (arrival, read, delete) and once at
/// session start, rather than derived lazily on every render.
pub(crate) fn refresh_unread_mail_count(session: &SessionState, ui_state: &mut UiState) {
    ui_state.set_unread_otp_mail_count(session.otp_mail_store.unread_received_count());
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

/// After a genuine mail encrypt/decrypt spend, tells the user once
/// `contact_name`'s mail key has nothing left in either direction - mail
/// has no session to end (unlike a live contact, `client::otp::
/// end_live_session_if_exhausted`), only the key itself, so this is purely
/// informational: neither the keychain entry nor aloo's own bookkeeping
/// for it is touched (`client::otp::is_contact_exhausted`'s doc) - a later
/// `/new-otp-mail-key` still replaces it correctly regardless. Unlike
/// `refresh_key_header_if_connected`, this runs regardless of whether the
/// mail's counterpart happens to be connected right now - mail is
/// store-and-forward, so exhaustion must be caught even while they're
/// offline.
///
/// `pub` (not `pub(crate)`) so `test/otp_key_exhaustion_test.rs` can drive
/// it directly against a real installed mail contact, the same reason
/// `client::otp::is_contact_exhausted` is.
pub async fn notify_if_mail_key_exhausted(
    session: &SessionState,
    ui_state: &mut UiState,
    nickname: &str,
    contact_name: &str,
) {
    let Ok(Some(detail)) = otp_cli::show_contact(&session.otp_cli_cfg, contact_name).await else {
        return;
    };
    if !crate::client::otp::is_contact_exhausted(&detail) {
        return;
    }
    ui_state.push_status_notice(
        format!(
            "OTP mail key for {nickname} is fully used up. Run /new-otp-mail-key for a fresh one."
        ),
        false,
    );
}

/// `UiAction::RequestOpenOtpMail`'s handler - the `/mail` command
/// (`submit_input`). Refuses to open the compose view at all without the
/// `otp` binary: every mail this view could send needs it (`handle_send`
/// spends a real pad through it), so opening anyway would only defer the
/// same failure to send time - or worse, past it silently, the exact
/// class of bug `client::otp::on_pad_commit`/`finish_opening_otp_envelope`
/// were hardened against. Freshly checked rather than cached, the same as
/// `client::otp::handle_provisioning_command`'s identical guard for
/// `/otp`/`/new-otp-mail-key`: a binary installed or removed mid-session
/// must be reflected immediately, not through a stale flag.
///
/// `pub` (not `pub(crate)`) so `test/otp_binary_guard_test.rs` can drive it
/// directly - the same reason `client::otp::handle_provisioning_command`
/// is already `pub`.
pub fn handle_open_otp_mail(session: &SessionState, ui_state: &mut UiState) {
    if !otp_cli::binary_available(&session.otp_cli_cfg) {
        ui_state.push_status_notice(
            "OTP mail failed: the 'otp' command isn't installed - see \
             github.com/DavidValin/otp-toolkit"
                .to_string(),
            false,
        );
        return;
    }
    ui_state.open_otp_mail();
}

/// `UiAction::OpenOtpMailbox`'s handler.
pub(crate) fn handle_open_mailbox(session: &SessionState, ui_state: &mut UiState) {
    ui_state.otp_mail_set_mailbox_rows(mailbox_rows(session));
}

/// Applies `ServerMessage::OtpMailResult`. On success, moves the sent
/// reference to `StoredOnServer` and clears the contact's gate for this
/// spend - since a cleared gate authorises exactly one more send, this also
/// drains one queued P2P item if any were waiting behind the mail.
///
/// On failure the mail stays exactly `AwaitingServerAck`, and the gate
/// stays closed on this exact seq: unlike a peer's `OtpDeliveryAck`, no
/// third party could ever separately prove this mail was stored, so there
/// is no such thing as "the spend happened but the acknowledgement was
/// lost" here - a storage failure means the spend genuinely never landed
/// anywhere durable, and the receiver's `next_expected_in_seq` for this
/// contact will never move past it either way. Clearing the gate and
/// giving up (the old behaviour) would let the *next* mail spend past this
/// one, which the receiver could then never decrypt - every mail after it
/// would sit forever behind a sequence number that can only ever be filled
/// by this exact ciphertext (docs/PROTOCOL.md §17.3's oldest-first rule).
/// So instead this retries immediately with the same recovered ciphertext
/// (`resend_one`), and falls back to the ordinary reconnect pass
/// (`resend_pending`) if that attempt also fails - both durable, since
/// nothing here is cleared until a `ok: true` genuinely arrives.
pub async fn on_mail_result(
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
    if ok {
        if session
            .otp_mail_store
            .set_sent_status(&mail_id, SentMailStatus::StoredOnServer)
        {
            let _ = session.otp_mail_store.save();
        }
        if session
            .otp_store
            .record_acked(&mail_ref.contact_name, mail_ref.seq, None)
        {
            let _ = session.otp_store.save();
            crate::client::otp::flush_one_queued(wr, ui_state, session, &mail_ref.contact_name)
                .await?;
        }
        ui_state.push_status_notice(
            format!("OTP mail to {} is stored on the server", mail_ref.to),
            true,
        );
    } else {
        let resent = resend_one(wr, session, &mail_ref).await?;
        ui_state.push_status_notice(
            format!(
                "OTP mail to {} was not stored by the server yet{} - {}",
                mail_ref.to,
                reason.map(|r| format!(": {r}")).unwrap_or_default(),
                if resent {
                    "retrying now"
                } else {
                    "will retry once reachable again"
                }
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
        if session
            .otp_store
            .record_acked(&mail_ref.contact_name, mail_ref.seq, None)
        {
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
pub async fn on_mail_deliver(
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
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
        return Ok(());
    }
    let pinned_der = session.id_store.get(&from).map(|d| d.to_vec());
    let own_fp = session.own_pq_fp;
    let own_device_id = session.own_device_id.clone();
    // Mail is server-relayed and asynchronous - the sender need not be
    // live right now, so like `check_recipient`'s compose-time check,
    // this always names `from`'s most-recently-seen (or most recently
    // pinned) device; an unbound pin can never resolve a name here
    // either.
    let peer_device_id = session
        .id_store
        .most_recent_device_id(&from)
        .filter(|d| !d.is_empty())
        .map(str::to_string);
    let expected_contact = pinned_der
        .as_deref()
        .and_then(crypto::pq::fingerprint_of_encoded)
        .zip(peer_device_id)
        .map(|(peer_fp, peer_device_id)| {
            crypto::otp::contact_name_for_mail(&own_fp, &own_device_id, &peer_fp, &peer_device_id)
        });
    let next_expected = expected_contact
        .as_deref()
        .and_then(|c| session.otp_store.get(c))
        .map(|s| s.next_expected_in_seq)
        .unwrap_or(0);
    match mail_gate(
        expected_contact.as_deref(),
        &contact_name,
        next_expected,
        seq,
    ) {
        MailGate::RefuseContact => {
            ui_state.push_status_notice(
                format!(
                    "An OTP mail from '{from}' is pending in your other device. Log in to receive it"
                ),
                false,
            );
            return Ok(());
        }
        MailGate::AckOnly => {
            // Already consumed once (the ack was lost, or the local index
            // was written and the ack crashed) - the pad range is gone
            // either way, so acknowledging is the only useful answer.
            wr.send_control(&ClientMessage::OtpMailAck { mail_id })
                .await?;
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
        // A rejection - the metadata check refused this exact mail, not a
        // transient failure - is worth naming specifically; see
        // `otp_cli::OtpCliOutcome::Rejected`'s doc.
        // A rejection with the tool's decrypt counter exactly one past this
        // store's is this side's own crash talking: the mail was decrypted
        // in a previous life of the process and only the record and the
        // ack were lost, so the server's faithful redelivery is refused as
        // already consumed. Healed from the tool's kept received-side copy
        // (`otp::recover_orphaned_decrypt_raw`), exactly as a live text is
        // - otherwise this mail was left on the server forever and every
        // later one from this sender waited behind it (§17.3).
        Ok(otp_cli::OtpCliOutcome::Rejected(reason)) => {
            match crate::client::otp::recover_orphaned_decrypt_raw(session, &expected_contact).await {
                Some(bytes) => Zeroizing::new(bytes),
                None => {
                    ui_state.push_status_notice(
                        format!(
                            "OTP mail from {from} was rejected ({}) - left on the server, keys untouched",
                            reason.trim().replace('\n', "; ")
                        ),
                        false,
                    );
                    return Ok(());
                }
            }
        }
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
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
        return Ok(());
    };
    let Ok(pinned_bundle) = proto::decode::<crypto::pq::PqPublicBundle>(&pinned_der) else {
        discard(ui_state, "pinned key unreadable");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
        return Ok(());
    };
    // A one-time pad authenticates nothing - this signature check against
    // the *pinned* identity is what stops a bit-flipped or forged payload
    // from ever being believed.
    if !crypto::pq::verify_mail(&pinned_bundle, &sealed.payload, &sealed.signature) {
        discard(ui_state, "its identity signature doesn't verify");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
        return Ok(());
    }
    let Ok(payload) = proto::decode::<OtpMailPayload>(&sealed.payload) else {
        discard(ui_state, "malformed payload");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
        return Ok(());
    };
    if payload.from != from || payload.to != ui_state.own_name {
        discard(ui_state, "its sealed addressing doesn't match");
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
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
        read: false,
    };
    if let Err(e) = session
        .otp_mail_store
        .store_received_payload(record, &stored_ct, &pad)
    {
        // Pad consumed but nothing persisted - the mail is genuinely lost.
        // Acknowledge anyway: the server redelivering the same ciphertext
        // can never decrypt again.
        discard(ui_state, &format!("could not be stored: {e}"));
        wr.send_control(&ClientMessage::OtpMailAck { mail_id })
            .await?;
        return Ok(());
    }
    let _ = session.otp_mail_store.save();
    wr.send_control(&ClientMessage::OtpMailAck { mail_id })
        .await?;
    ui_state.push_status_notice(
        format!("\u{1F4E8} OTP mail from {from} - type /mailbox to read it"),
        true,
    );
    crate::client::voice_stream::play_bell_chime(session);
    refresh_key_header_if_connected(session, ui_state, &from, &expected_contact).await;
    notify_if_mail_key_exhausted(session, ui_state, &from, &expected_contact).await;
    refresh_mailbox_if_open(session, ui_state);
    refresh_unread_mail_count(session, ui_state);
    Ok(())
}

/// `UiAction::ReadOtpMail`'s handler: XORs the stored pair back together
/// in memory, decodes the payload, and opens the reader. The blob pair on
/// disk is untouched - it outlives every read until the user removes the
/// mail.
pub(crate) fn handle_read(session: &mut SessionState, ui_state: &mut UiState, mail_id: String) {
    let Some(bytes) = session.otp_mail_store.read_received_payload(&mail_id) else {
        ui_state.push_status_notice(
            "OTP mail: could not read this mail's stored files".to_string(),
            false,
        );
        return;
    };
    let bytes = Zeroizing::new(bytes);
    let Ok(payload) = proto::decode::<OtpMailPayload>(&bytes) else {
        ui_state.push_status_notice(
            "OTP mail: this mail's stored files don't decode".to_string(),
            false,
        );
        return;
    };
    if session.otp_mail_store.mark_read(&mail_id) {
        let _ = session.otp_mail_store.save();
        refresh_unread_mail_count(session, ui_state);
    }
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
    refresh_unread_mail_count(session, ui_state);
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
    let result =
        std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&dest, &attachment.bytes));
    match result {
        Ok(()) => {
            ui_state.push_status_notice(format!("Saved {dest_name} to {}", dir.display()), true)
        }
        Err(e) => ui_state.push_status_notice(format!("Could not save {dest_name}: {e}"), false),
    }
}
