//! DM-specific send/receive handling for the connected session: sending
//! text/voice to a peer, and applying incoming DM-addressed server
//! messages. `crate::client::session` dispatches into these from its
//! `handle_ui_action`/`handle_server_message`; the generic
//! live-voice-streaming plumbing they use lives in `crate::client::voice_stream`.


use crate::crypto;
use crate::client::p2p::LinkReadiness;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, Content, Envelope, KeyMode, UserId};
use crate::client::rekey;
use crate::client::session::SessionState;
use crate::client::tui::ui::UiState;
use crate::client::voice;
use crate::client::voice_call;
use crate::client::voice_stream;

/// Encrypts `plaintext` for one recipient, dispatching by their `KeyMode` -
/// see `channel::encrypt_for_each`'s doc for the same split (this is its
/// single-recipient DM counterpart). Returns `None` if the recipient is
/// `PqHybrid` and we can't address them (`keymode_policy::can_address`), or if
/// encryption itself fails.
fn encrypt_for_recipient(
    session: &SessionState,
    to: UserId,
    key_mode: KeyMode,
    pubkey_der: &[u8],
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    if !crate::client::keymode_policy::can_address(key_mode, session.own_key_mode) {
        return None;
    }
    crate::client::envelope::encrypt_envelope_for(
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(to),
        key_mode,
        pubkey_der,
        // A DM is bound to no channel - which is itself the binding, and
        // what stops this being replayed into one.
        None,
        send_id,
        plaintext,
        content,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_send_text(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    to: UserId,
    plaintext: String,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
    log_index: Option<usize>,
) -> proto::Result<()> {
    if let Some(contact_name) =
        crate::client::otp::contact_name_if_active(session, &recipient_pubkey_der)
    {
        return crate::client::otp::send_or_queue(
            wr,
            session,
            ui_state,
            to,
            &contact_name,
            recipient_key_mode,
            &recipient_pubkey_der,
            plaintext.as_bytes(),
            Content::Text,
            None,
            log_index,
        )
        .await;
    }
    if session.remote_keys.try_use(to) {
        let send_id = session.next_stream_id;
        session.next_stream_id += 1;
        if let Some(envelope) = encrypt_for_recipient(
            session,
            to,
            recipient_key_mode,
            &recipient_pubkey_der,
            send_id,
            plaintext.as_bytes(),
            Content::Text,
        ) {
            session.peer_link.ensure_link(wr, to).await;
            session.peer_link.send_reliable_or_queue(
                to,
                P2pPayload::Envelope {
                    channel: None,
                    envelope,
                },
            );
            crate::client::session::request_rotation(session, to);
        }
    } else {
        session
            .remote_keys
            .enqueue(to, rekey::QueuedOutbound::Direct { plaintext });
    }
    Ok(())
}

/// DM counterpart of `channel::handle_send_file` - see there for the
/// offer/accept/reject/stream shape. A DM has only one recipient, so this
/// is a single transfer rather than a fan-out.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_send_file(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    to: UserId,
    path: std::path::PathBuf,
    filename: String,
    size: u64,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    if !crate::client::keymode_policy::can_address(recipient_key_mode, session.own_key_mode)
        || !session.remote_keys.try_use(to)
    {
        return Ok(());
    }
    if let Some(contact_name) = crate::client::otp::contact_name_if_active(session, &recipient_pubkey_der) {
        return crate::client::otp::send_file_offer(
            wr,
            session,
            ui_state,
            to,
            &contact_name,
            &recipient_pubkey_der,
            path,
            filename,
            size,
        )
        .await;
    }
    let payload = crate::client::file_transfer::FileOfferPayload {
        filename: filename.clone(),
        size,
    };
    let Ok(plaintext) = proto::encode(&payload) else {
        return Ok(());
    };
    let stream_id = session.next_stream_id;
    let Some(envelope) = encrypt_for_recipient(
        session,
        to,
        recipient_key_mode,
        &recipient_pubkey_der,
        stream_id,
        &plaintext,
        Content::FileOffer,
    ) else {
        return Ok(());
    };
    let Some(key) = voice_stream::resolve_direct_key(
        session,
        stream_id,
        to,
        recipient_key_mode,
        &recipient_pubkey_der,
    ) else {
        return Ok(());
    };
    session.next_stream_id += 1;
    ui_state.log_own_file_offer_dm(to, stream_id, filename.clone(), size);
    session.own_file_targets.insert(
        stream_id,
        crate::client::file_transfer::OwnFileTarget { to, path, key, otp: None },
    );
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::FileOffer {
            channel: None,
            stream_id,
            envelope,
        },
    );
    crate::client::session::request_rotation(session, to);
    Ok(())
}

pub(crate) async fn handle_voice_record_start(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    recorder: voice::Recorder,
    stream_id: u64,
    to: UserId,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    if !crate::client::keymode_policy::can_address(recipient_key_mode, session.own_key_mode)
        || !session.remote_keys.try_use(to)
    {
        ui_state.recording_failed("recipient's key isn't ready yet".to_string());
        return Ok(());
    }
    // Under an active OTP session, voice is recorded fully and sent once
    // finished (`client::otp::send_voice_offer`'s doc) rather than
    // live-streamed - no `StreamStart`/per-chunk network traffic at all
    // until the recording stops.
    if let Some(contact_name) = crate::client::otp::contact_name_if_active(session, &recipient_pubkey_der) {
        ui_state.log_own_voice_stream_start_dm(to, stream_id);
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        session.active_recording = Some(stop_tx);
        session.own_stream_targets.insert(
            stream_id,
            voice_stream::OwnStreamTarget::DirectOtp {
                to,
                contact_name,
                recipient_pubkey_der,
            },
        );
        voice_stream::spawn_record_accumulate_worker(
            recorder,
            stream_id,
            session.own_stream_done_tx.clone(),
            stop_rx,
            session.auto_stop_tx.clone(),
        );
        return Ok(());
    }
    // Voice is never queued (PROTOCOL.md §11.2) - a link that isn't already
    // `Active` right now (no relay fallback, and punching can take several
    // seconds) fails this recording outright, same as an unready key above.
    if session.peer_link.ensure_link(wr, to).await != LinkReadiness::Active {
        ui_state.recording_failed("no direct connection to recipient yet".to_string());
        return Ok(());
    }
    let key = match recipient_key_mode {
        KeyMode::PqHybrid => {
            let Some(pq) = voice_stream::build_pq_stream_out(
                session,
                None,
                stream_id,
                &[(to, recipient_pubkey_der.clone())],
            ) else {
                ui_state.recording_failed("failed to prepare pq_hybrid stream key".to_string());
                return Ok(());
            };
            voice_stream::DirectStreamKey::Pq(pq)
        }
        _ => match crypto::public_key_from_der(&recipient_pubkey_der) {
            Ok(k) => voice_stream::DirectStreamKey::Rsa(k),
            Err(e) => {
                ui_state.recording_failed(e.to_string());
                return Ok(());
            }
        },
    };
    ui_state.log_own_voice_stream_start_dm(to, stream_id);
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::StreamStart {
            channel: None,
            stream_id,
        },
    );
    // A pq_hybrid recipient's setup follows `StreamStart`, once and
    // reliably - see the channel counterpart for why it isn't per chunk.
    if let voice_stream::DirectStreamKey::Pq(pq) = &key {
        for (id, setup) in pq.setups() {
            session
                .peer_link
                .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
        }
    }
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    session.active_recording = Some(stop_tx);
    session
        .own_stream_targets
        .insert(stream_id, voice_stream::OwnStreamTarget::Direct(to));
    voice_stream::spawn_record_stream_worker(
        recorder,
        voice_stream::StreamRecipients::Direct { to, key },
        stream_id,
        session.record_out_tx.clone(),
        session.own_stream_done_tx.clone(),
        stop_rx,
        session.auto_stop_tx.clone(),
    );
    Ok(())
}

/// Starts a live voice call to `to` - refused outright (with a status
/// notice, no invite ever sent) if we currently have an OTP session with
/// them: that layer has no live-streaming concept at all (voice under OTP
/// is recorded whole and sent once, never continuous -
/// `docs/PROTOCOL.md` "Live voice calls"), so a DM call has nobody left to
/// reach once its one possible recipient is excluded. We become a
/// participant immediately (`voice_call::begin_own_call`), same as `to` if
/// they accept.
pub(crate) async fn handle_start_call(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    to: UserId,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    if crate::client::otp::contact_name_if_active(session, &recipient_pubkey_der).is_some() {
        ui_state.push_status_notice(
            crate::client::tui::ui::OTP_CALL_REFUSAL.to_string(),
            false,
        );
        return Ok(());
    }
    if !crate::client::keymode_policy::can_address(recipient_key_mode, session.own_key_mode) {
        ui_state.push_status_notice("can't call this recipient right now".to_string(), false);
        return Ok(());
    }
    let Some(host) = ui_state.own_id else {
        return Ok(());
    };
    let call_id = voice_call::new_call_id();
    if !voice_call::begin_own_call(session, ui_state, call_id, None, host) {
        return Ok(());
    }
    let name = ui_state
        .known_users
        .get(&to)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::CallInvite {
            call_id,
            channel: None,
        },
    );
    ui_state.on_call_invite_sent(to, name);
    Ok(())
}

pub(crate) async fn on_message(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    envelope: Envelope,
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    // The OTP-layer provisioning handshake rides ordinary (non-OTP)
    // `pq_hybrid` envelopes distinguished only by `Content` - see
    // `client::otp`'s module doc. Every other content type falls through
    // to the normal text-message path below unchanged.
    match envelope.content {
        Content::OtpKeySetup => {
            crate::client::otp::on_key_setup(ui_state, session, from, from_name, &sender, envelope);
            return;
        }
        Content::OtpSessionRequest => {
            crate::client::otp::on_session_request(ui_state, session, from, from_name, &sender, envelope);
            return;
        }
        Content::OtpKeySetupAck => {
            crate::client::otp::on_key_setup_ack(ui_state, session, from, &sender, envelope).await;
            return;
        }
        Content::OtpEndSession => {
            crate::client::otp::on_end_session(session, ui_state, from, from_name, &sender, envelope)
                .await;
            return;
        }
        Content::OtpEndSessionAck => {
            crate::client::otp::on_end_session_ack(session, from, &sender, envelope);
            return;
        }
        _ => {}
    }
    if let Some(body) =
        crate::client::session::decrypt_envelope_for(envelope, from, &sender, None, session)
    {
        ui_state.on_direct_message(from, from_name, body);
        crate::client::session::request_rotation(session, from);
    }
}

pub(crate) fn on_stream_start(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    stream_id: u64,
) {
    // Snapshotted once, same as the decrypt key set itself (PROTOCOL.md
    // §11.2/§12): a Pending/Rejected sender's stream is never played live.
    let suppress_playback = ui_state.is_trust_gated(from);
    let sender_public_key_der = ui_state
        .known_users
        .get(&from)
        .map(|u| u.public_key_der.clone())
        .unwrap_or_default();
    ui_state.on_direct_stream_start(from, from, from_name, stream_id);
    voice_stream::start_incoming_stream(
        session,
        from,
        stream_id,
        None,
        suppress_playback,
        &sender_public_key_der,
    );
}

pub(crate) fn on_own_stream_finished(
    ui_state: &mut UiState,
    session: &mut SessionState,
    you: UserId,
    to: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) {
    ui_state.on_direct_stream_finished(to, you, stream_id, duration_ms, pcm);
    crate::client::session::request_rotation(session, to);
}

pub(crate) fn on_stream_finished(
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) {
    ui_state.on_direct_stream_finished(from, from, stream_id, duration_ms, pcm);
}
