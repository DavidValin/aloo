//! Channel-specific send/receive handling for the connected session:
//! joining, sending text/voice to a channel, and applying incoming
//! channel-addressed server messages. `crate::session` dispatches into
//! these from its `handle_ui_action`/`handle_server_message`; the generic
//! live-voice-streaming plumbing they use lives in `crate::voice_stream`.

use std::time::Instant;

use rsa::RsaPublicKey;
use tokio::io::AsyncWrite;

use crate::crypto;
use crate::p2p::LinkReadiness;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, ChannelInfo, ChannelKind, ClientMessage, Content, Envelope, KeyMode, UserId};
use crate::rekey;
use crate::session::SessionState;
use crate::ui::ui::{Recipient, UiState};
use crate::voice;
use crate::voice_stream;

pub(crate) async fn handle_join(
    wr: &mut (impl AsyncWrite + Unpin),
    session: &mut SessionState,
    name: String,
    kind: ChannelKind,
) -> proto::Result<()> {
    proto::write_message(wr, &ClientMessage::JoinChannel { name, kind }).await?;
    session.conn_stats.record_event(Instant::now());
    Ok(())
}

pub(crate) async fn handle_send_text(
    wr: &mut (impl AsyncWrite + Unpin),
    session: &mut SessionState,
    channel: String,
    plaintext: String,
    recipients: Vec<Recipient>,
) -> proto::Result<()> {
    // Split by whether each recipient's rsa_per_msg key (if any) is
    // currently fresh (PROTOCOL.md §11.5) - a Static/untracked
    // recipient is always ready. Anyone not ready is queued rather
    // than dropped, and sent automatically once their next key
    // arrives (`session::handle_key_rotated`).
    let mut ready = Vec::new();
    for (id, key_mode, der) in recipients {
        if !can_address(key_mode, session.own_key_mode) {
            continue;
        }
        if session.remote_keys.try_use(id) {
            ready.push((id, key_mode, der));
        } else {
            session.remote_keys.enqueue(
                id,
                rekey::QueuedOutbound::Channel { channel: channel.clone(), plaintext: plaintext.clone() },
            );
        }
    }
    if !ready.is_empty() {
        let per_recipient = encrypt_for_each(session, &ready, plaintext.as_bytes(), Content::Text);
        for (id, envelope) in per_recipient {
            session.peer_link.ensure_link(wr, id).await;
            session.peer_link.send_reliable_or_queue(id, P2pPayload::Envelope { channel: Some(channel.clone()), envelope });
        }
        for (id, ..) in ready {
            crate::session::request_rotation_if_per_message(session, id);
        }
    }
    Ok(())
}

/// A `PqHybrid` recipient can only be addressed by a `PqHybrid` sender - the
/// hybrid scheme's signing step (`docs/PROTOCOL.md` §13) needs *our own*
/// ML-DSA-87+RSA-sign identity, which only exists when our own `my_key` is
/// also `pq_hybrid`. Every other `KeyMode` pair works exactly as before
/// (RSA-OAEP needs no sender identity at all). An unreachable recipient is
/// silently excluded, same as any other partial-delivery case in this app
/// (an offline member, a not-yet-fresh `rsa_per_msg` key, ...).
///
/// A pure, `SessionState`-free predicate (just the two `KeyMode`s involved)
/// so it's directly unit-testable without a live session
/// (`test/hybrid_crypto_test.rs`).
pub fn can_address(recipient_key_mode: KeyMode, own_key_mode: KeyMode) -> bool {
    recipient_key_mode != KeyMode::PqHybrid || own_key_mode == KeyMode::PqHybrid
}

/// Sends one `FileOffer` per ready recipient (`docs/PROTOCOL.md`'s file
/// transfer section) - a channel file send is N independent point-to-point
/// transfers, one per member, each with its own `stream_id` and its own
/// pending log row (`UiState::log_own_file_offer_channel`), rather than one
/// broadcast the way voice's channel streams work: accept/reject/progress
/// is inherently per-recipient here, so each row tracks its own recipient's
/// decision independently. Readiness is a snapshot-and-exclude, same as
/// `handle_voice_record_start` below (PROTOCOL.md §11.6): a `rsa_per_msg`
/// recipient without a fresh key right now is simply left out. Nothing is
/// read from `path` here - only once each recipient individually accepts
/// (`session::handle_server_message`'s `FileAccepted` arm).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_send_file(
    wr: &mut (impl AsyncWrite + Unpin),
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
    path: std::path::PathBuf,
    filename: String,
    size: u64,
    recipients: Vec<Recipient>,
) -> proto::Result<()> {
    let mut ready = Vec::new();
    for (id, key_mode, der) in recipients {
        if can_address(key_mode, session.own_key_mode) && session.remote_keys.try_use(id) {
            ready.push((id, key_mode, der));
        }
    }
    let payload = crate::file_transfer::FileOfferPayload { filename: filename.clone(), size };
    let Ok(plaintext) = proto::encode(&payload) else { return Ok(()) };
    for (id, key_mode, der) in ready {
        let envelope = match key_mode {
            KeyMode::PqHybrid => session
                .own_pq_private
                .as_ref()
                .and_then(|signing| crate::session::encrypt_hybrid_envelope_for(signing, &der, &plaintext, Content::FileOffer)),
            _ => crate::session::encrypt_for_one(&der, &plaintext, Content::FileOffer),
        };
        let Some(envelope) = envelope else { continue };
        let stream_id = session.next_stream_id;
        let Some(key) = voice_stream::resolve_direct_key(session, stream_id, id, key_mode, &der) else { continue };
        session.next_stream_id += 1;
        let to_name = ui_state.known_users.get(&id).map(|u| u.name.clone()).unwrap_or_default();
        ui_state.log_own_file_offer_channel(&channel, &to_name, stream_id, filename.clone(), size);
        session.own_file_targets.insert(stream_id, crate::file_stream::OwnFileTarget { to: id, path: path.clone(), key });
        session.peer_link.ensure_link(wr, id).await;
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::FileOffer { channel: Some(channel.clone()), stream_id, envelope },
        );
        crate::session::request_rotation_if_per_message(session, id);
    }
    Ok(())
}

pub(crate) async fn handle_voice_record_start(
    wr: &mut (impl AsyncWrite + Unpin),
    ui_state: &mut UiState,
    session: &mut SessionState,
    recorder: voice::Recorder,
    stream_id: u64,
    channel: String,
    recipients: Vec<Recipient>,
) -> proto::Result<()> {
    // Voice streams are never queued (PROTOCOL.md §11.6): a rsa_per_msg
    // recipient without a fresh key right now, or one whose direct link
    // isn't already `Active` right now (no relay fallback, and punching can
    // take up to several seconds - too long to make a live recording wait
    // on), is simply left out of this particular stream, same as any other
    // partial-delivery case.
    let mut ready = Vec::new();
    for (id, key_mode, der) in recipients {
        if !can_address(key_mode, session.own_key_mode) || !session.remote_keys.try_use(id) {
            continue;
        }
        if session.peer_link.ensure_link(wr, id).await == LinkReadiness::Active {
            ready.push((id, key_mode, der));
        }
    }
    let ready_ids: Vec<UserId> = ready.iter().map(|(id, ..)| *id).collect();
    let rsa = parse_recipients(&ready);
    let pq = voice_stream::build_pq_stream_out(session, stream_id, &parse_pq_recipients(&ready));
    ui_state.log_own_voice_stream_start_channel(&channel, stream_id);
    for &id in &ready_ids {
        session.peer_link.send_reliable_or_queue(id, P2pPayload::StreamStart { channel: Some(channel.clone()), stream_id });
    }
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    session.active_recording = Some(stop_tx);
    session
        .own_stream_targets
        .insert(stream_id, voice_stream::OwnStreamTarget::Channel { channel: channel.clone(), recipients: ready_ids });
    voice_stream::spawn_record_stream_worker(
        recorder,
        voice_stream::StreamRecipients::Channel { rsa, pq },
        stream_id,
        session.record_out_tx.clone(),
        session.own_stream_done_tx.clone(),
        stop_rx,
        session.auto_stop_tx.clone(),
    );
    Ok(())
}

fn parse_recipients(recipients: &[Recipient]) -> Vec<(UserId, RsaPublicKey)> {
    recipients
        .iter()
        .filter(|(_, key_mode, _)| *key_mode != KeyMode::PqHybrid)
        .filter_map(|(id, _, der)| crypto::public_key_from_der(der).ok().map(|k| (*id, k)))
        .collect()
}

fn parse_pq_recipients(recipients: &[Recipient]) -> Vec<(UserId, crypto::pq::PqPublicBundle)> {
    recipients
        .iter()
        .filter(|(_, key_mode, _)| *key_mode == KeyMode::PqHybrid)
        .filter_map(|(id, _, der)| proto::decode(der).ok().map(|b| (*id, b)))
        .collect()
}

/// Encrypts `plaintext` once per recipient, dispatching by *their*
/// `KeyMode` - RSA-OAEP (`session::encrypt_for_one`, needs nothing of ours)
/// or the PQ-hybrid scheme (`session::encrypt_hybrid_envelope_for`, needs
/// *our own* signing identity, `session.own_pq_private` - callers must have
/// already excluded recipients this session can't address, see
/// `can_address`).
fn encrypt_for_each(session: &SessionState, recipients: &[Recipient], plaintext: &[u8], content: Content) -> Vec<(UserId, Envelope)> {
    recipients
        .iter()
        .filter_map(|(id, key_mode, pubkey_der)| {
            let envelope = match key_mode {
                KeyMode::PqHybrid => {
                    let signing = session.own_pq_private.as_ref()?;
                    crate::session::encrypt_hybrid_envelope_for(signing, pubkey_der, plaintext, content.clone())?
                }
                _ => crate::session::encrypt_for_one(pubkey_der, plaintext, content.clone())?,
            };
            Some((*id, envelope))
        })
        .collect()
}

pub(crate) fn on_list(ui_state: &mut UiState, list: Vec<ChannelInfo>) -> Option<crate::ui::ui::UiAction> {
    let was_empty = ui_state.channels.is_empty();
    ui_state.on_channel_list(list);
    if was_empty {
        if let Some(first) = ui_state.channels.first() {
            return Some(crate::ui::ui::UiAction::JoinChannel { name: first.name.clone(), kind: first.kind });
        }
    }
    None
}

pub(crate) fn on_joined(ui_state: &mut UiState, channel: ChannelInfo) {
    ui_state.on_joined(channel);
}

pub(crate) fn on_join_failed(name: String, reason: String) {
    eprintln!("aloo: failed to join {name}: {reason}");
}

pub(crate) fn on_message(
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
    from: UserId,
    from_name: String,
    envelope: Envelope,
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else { return };
    if let Some(body) = crate::session::decrypt_envelope_for(envelope, from, &sender, session) {
        ui_state.on_channel_message(&channel, from, from_name, body);
        crate::session::request_rotation_if_per_message(session, from);
    }
}

pub(crate) fn on_stream_start(
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
    from: UserId,
    from_name: String,
    stream_id: u64,
) {
    // Snapshotted once, same as the decrypt key set itself (PROTOCOL.md
    // §11.6/§12): a Pending/Rejected sender's stream is never played live.
    let suppress_playback = ui_state.is_trust_gated(from);
    let sender_public_key_der = ui_state.known_users.get(&from).map(|u| u.public_key_der.clone()).unwrap_or_default();
    ui_state.on_channel_stream_start(&channel, from, from_name, stream_id);
    voice_stream::start_incoming_stream(session, from, stream_id, Some(channel), suppress_playback, &sender_public_key_der);
}

// Extracted verbatim from the `OwnStreamTarget::Channel` match arm that
// used to live inline in main.rs's event loop, where these were just
// locals, not function parameters - same shape of pre-existing exception
// as `session::run_connected_session`'s.
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_own_stream_finished(
    ui_state: &mut UiState,
    session: &SessionState,
    you: UserId,
    channel: String,
    recipients: Vec<UserId>,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) {
    ui_state.on_channel_stream_finished(&channel, you, stream_id, duration_ms, pcm);
    // one rotation per recipient this stream actually
    // reached, at the stream's natural end - not per
    // chunk (PROTOCOL.md §11.6).
    for peer in recipients {
        crate::session::request_rotation_if_per_message(session, peer);
    }
}

pub(crate) fn on_stream_finished(
    ui_state: &mut UiState,
    channel: &str,
    from: UserId,
    stream_id: u64,
    duration_ms: u32,
    pcm: Vec<u8>,
) {
    ui_state.on_channel_stream_finished(channel, from, stream_id, duration_ms, pcm);
}
