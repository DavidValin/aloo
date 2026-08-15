//! DM-specific send/receive handling for the connected session: sending
//! text/voice to a peer, and applying incoming DM-addressed server
//! messages. `crate::session` dispatches into these from its
//! `handle_ui_action`/`handle_server_message`; the generic
//! live-voice-streaming plumbing they use lives in `crate::voice_stream`.

use std::time::Instant;

use tokio::io::AsyncWrite;

use crate::crypto;
use crate::proto::{self, ClientMessage, Content, Envelope, KeyMode, UserId};
use crate::rekey;
use crate::session::SessionState;
use crate::ui::ui::UiState;
use crate::voice;
use crate::voice_stream;

/// Encrypts `plaintext` for one recipient, dispatching by their `KeyMode` -
/// see `channel::encrypt_for_each`'s doc for the same split (this is its
/// single-recipient DM counterpart). Returns `None` if the recipient is
/// `PqHybrid` and we can't address them (`channel::can_address`), or if
/// encryption itself fails.
fn encrypt_for_recipient(session: &SessionState, key_mode: KeyMode, pubkey_der: &[u8], plaintext: &[u8], content: Content) -> Option<Envelope> {
    if !crate::channel::can_address(key_mode, session.own_key_mode) {
        return None;
    }
    match key_mode {
        KeyMode::PqHybrid => {
            let signing = session.own_pq_private.as_ref()?;
            crate::session::encrypt_hybrid_envelope_for(signing, pubkey_der, plaintext, content)
        }
        _ => crate::session::encrypt_for_one(pubkey_der, plaintext, content),
    }
}

pub(crate) async fn handle_send_text(
    wr: &mut (impl AsyncWrite + Unpin),
    session: &mut SessionState,
    to: UserId,
    plaintext: String,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    if session.remote_keys.try_use(to) {
        if let Some(envelope) =
            encrypt_for_recipient(session, recipient_key_mode, &recipient_pubkey_der, plaintext.as_bytes(), Content::Text)
        {
            proto::write_message(wr, &ClientMessage::SendDirect { to, envelope }).await?;
            session.conn_stats.record_event(Instant::now());
            crate::session::request_rotation_if_per_message(session, to);
        }
    } else {
        session.remote_keys.enqueue(to, rekey::QueuedOutbound::Direct { plaintext });
    }
    Ok(())
}

/// DM counterpart of `channel::handle_send_file` - see there for the
/// offer/accept/reject/stream shape. A DM has only one recipient, so this
/// is a single transfer rather than a fan-out.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_send_file(
    wr: &mut (impl AsyncWrite + Unpin),
    ui_state: &mut UiState,
    session: &mut SessionState,
    to: UserId,
    path: std::path::PathBuf,
    filename: String,
    size: u64,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    if !crate::channel::can_address(recipient_key_mode, session.own_key_mode) || !session.remote_keys.try_use(to) {
        return Ok(());
    }
    let payload = crate::file_transfer::FileOfferPayload { filename: filename.clone(), size };
    let Ok(plaintext) = proto::encode(&payload) else { return Ok(()) };
    let Some(envelope) = encrypt_for_recipient(session, recipient_key_mode, &recipient_pubkey_der, &plaintext, Content::FileOffer)
    else {
        return Ok(());
    };
    let stream_id = session.next_stream_id;
    let Some(key) = voice_stream::resolve_direct_key(session, stream_id, to, recipient_key_mode, &recipient_pubkey_der) else {
        return Ok(());
    };
    session.next_stream_id += 1;
    ui_state.log_own_file_offer_dm(to, stream_id, filename.clone(), size);
    session.own_file_targets.insert(stream_id, crate::file_stream::OwnFileTarget { to, path, key });
    proto::write_message(wr, &ClientMessage::FileOffer { to, stream_id, channel: None, envelope }).await?;
    session.conn_stats.record_event(Instant::now());
    crate::session::request_rotation_if_per_message(session, to);
    Ok(())
}

pub(crate) async fn handle_voice_record_start(
    wr: &mut (impl AsyncWrite + Unpin),
    ui_state: &mut UiState,
    session: &mut SessionState,
    recorder: voice::Recorder,
    stream_id: u64,
    to: UserId,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    if !crate::channel::can_address(recipient_key_mode, session.own_key_mode) || !session.remote_keys.try_use(to) {
        ui_state.recording_failed("recipient's key isn't ready yet".to_string());
        return Ok(());
    }
    let key = match recipient_key_mode {
        KeyMode::PqHybrid => {
            let Ok(public): Result<crypto::pq::PqPublicBundle, _> = proto::decode(&recipient_pubkey_der) else {
                ui_state.recording_failed("malformed pq_hybrid public key".to_string());
                return Ok(());
            };
            let Some(pq) = voice_stream::build_pq_stream_out(session, stream_id, &[(to, public)]) else {
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
    proto::write_message(wr, &ClientMessage::StreamDirectStart { to, stream_id }).await?;
    session.conn_stats.record_event(Instant::now());
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    session.active_recording = Some(stop_tx);
    session.own_stream_targets.insert(stream_id, voice_stream::OwnStreamTarget::Direct(to));
    voice_stream::spawn_record_stream_worker(
        recorder,
        voice_stream::StreamRecipients::Direct { to, key },
        stream_id,
        session.record_out_tx.clone(),
        session.own_stream_done_tx.clone(),
        stop_rx,
    );
    Ok(())
}

pub(crate) fn on_message(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    envelope: Envelope,
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else { return };
    if let Some(body) = crate::session::decrypt_envelope_for(envelope, from, &sender, session) {
        ui_state.on_direct_message(from, from_name, body);
        crate::session::request_rotation_if_per_message(session, from);
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
    // §11.6/§12): a Pending/Rejected sender's stream is never played live.
    let suppress_playback = ui_state.is_trust_gated(from);
    let sender_public_key_der = ui_state.known_users.get(&from).map(|u| u.public_key_der.clone()).unwrap_or_default();
    ui_state.on_direct_stream_start(from, from, from_name, stream_id);
    voice_stream::start_incoming_stream(session, from, stream_id, None, suppress_playback, &sender_public_key_der);
}

pub(crate) fn on_stream_chunk(session: &mut SessionState, from: UserId, stream_id: u64, seq: u32, blocks: Vec<Vec<u8>>) {
    voice_stream::forward_chunk(session, from, stream_id, seq, blocks);
}

pub(crate) fn on_stream_end(session: &mut SessionState, from: UserId, stream_id: u64) {
    voice_stream::end_incoming_stream(session, from, stream_id);
}

pub(crate) fn on_own_stream_finished(
    ui_state: &mut UiState,
    session: &SessionState,
    you: UserId,
    to: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) {
    ui_state.on_direct_stream_finished(to, you, stream_id, duration_ms, pcm);
    crate::session::request_rotation_if_per_message(session, to);
}

pub(crate) fn on_stream_finished(ui_state: &mut UiState, from: UserId, stream_id: u64, duration_ms: u32, pcm: Vec<u8>) {
    ui_state.on_direct_stream_finished(from, from, stream_id, duration_ms, pcm);
}
