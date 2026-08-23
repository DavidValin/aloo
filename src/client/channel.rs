//! Channel-specific send/receive handling for the connected session:
//! joining, sending text/voice to a channel, and applying incoming
//! channel-addressed server messages. `crate::client::session` dispatches into
//! these from its `handle_ui_action`/`handle_server_message`; the generic
//! live-voice-streaming plumbing they use lives in `crate::client::voice_stream`.

use std::time::Instant;

use crate::client::p2p::LinkReadiness;
use crate::client::rekey;
use crate::client::session::SessionState;
use crate::client::tui::ui::{Recipient, UiState};
use crate::client::voice;
use crate::client::voice_call;
use crate::client::voice_stream;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, ChannelInfo, ChannelKind, ClientMessage, Content, Envelope, UserId};

pub(crate) async fn handle_join(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    name: String,
    kind: ChannelKind,
    password: Option<String>,
) -> proto::Result<()> {
    // Remembered for the life of the session so a reconnect can walk back
    // into this channel unaided (`session::on_server_reconnected`) - a
    // private channel the user typed a password for once should not
    // silently stop being one of theirs because the network blinked.
    match &password {
        Some(pw) => {
            session.channel_passwords.insert(name.clone(), pw.clone());
        }
        None => {
            session.channel_passwords.remove(&name);
        }
    }
    wr.send_control(&ClientMessage::JoinChannel {
        name,
        kind,
        password,
    })
    .await?;
    session.conn_stats.record_event(Instant::now());
    Ok(())
}

/// `LeaveChannel` has no server-side acknowledgment to the leaver - the
/// server only notifies the members who *remain* (docs/PROTOCOL.md §6.2) -
/// so the local half is applied optimistically, client-side, the moment
/// `/leave` is submitted (`UiState::leave_channel_locally`). Any peer from
/// that channel who's no longer reachable through any other joined channel
/// or an open DM (`UiState::has_reason_to_keep_link`) has its P2P link torn
/// down too (§7.1.3).
pub(crate) async fn handle_leave(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    name: String,
) -> proto::Result<()> {
    // Leaving is local work with a courtesy notice attached: without a
    // server to tell, the local half is the whole of it.
    crate::client::session::send_if_server(
        session,
        wr,
        &ClientMessage::LeaveChannel { name: name.clone() },
    )
    .await?;
    for peer in ui_state.leave_channel_locally(&name) {
        // A `direct_punch_to` peer is a reason of its own to hold a link:
        // it was opened from settings and a schedule, not from this
        // channel, so leaving the channel says nothing about it (§7.1.5).
        if !ui_state.has_reason_to_keep_link(peer)
            && session.peer_link.direct_nickname_of(peer).is_none()
        {
            session.peer_link.forget(peer);
        }
    }
    crate::client::session::broadcast_channel_presence(session, ui_state);
    Ok(())
}

/// `msg_id` is the delivery tag every per-recipient frame this send turns
/// into carries, and the id of the single log row already showing it
/// (docs/PROTOCOL.md 7.2.1) - so each recipient's acknowledgement lands
/// back on that row and moves its indicator gray -> orange -> green.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_send_text(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
    plaintext: String,
    recipients: Vec<Recipient>,
    msg_id: u64,
) -> proto::Result<()> {
    // OTP is pairwise, not a channel-wide concept: each recipient who has
    // individually provisioned an OTP contact with us gets an OTP-wrapped
    // copy via `client::otp::send_or_queue`, exactly like a DM to them
    // would; everyone else gets the plain per-recipient path below,
    // unchanged - the same way mixed `KeyMode`s already coexist in one
    // channel send.
    let mut plain_recipients = Vec::new();
    for (id, der) in recipients {
        match crate::client::otp::contact_name_if_active(session, &der) {
            Some(contact_name) => {
                crate::client::otp::send_or_queue(
                    wr,
                    session,
                    ui_state,
                    id,
                    &contact_name,
                    &der,
                    plaintext.as_bytes(),
                    Content::Text,
                    Some(channel.clone()),
                    None,
                    Some(msg_id),
                )
                .await?;
            }
            None => plain_recipients.push((id, der)),
        }
    }
    let recipients = plain_recipients;

    // Split by whether each recipient's rotating key is currently fresh.
    // Anyone not ready is queued rather than dropped, and sent
    // automatically once their next key arrives
    // (`session::handle_pq_key_rotated`).
    let mut ready = Vec::new();
    for (id, der) in recipients {
        if session.remote_keys.try_use(id) {
            ready.push((id, der));
        } else {
            session.remote_keys.enqueue(
                id,
                rekey::QueuedOutbound::Channel {
                    channel: channel.clone(),
                    plaintext: plaintext.clone(),
                    msg_id,
                    attempts: 0,
                },
            );
        }
    }
    if !ready.is_empty() {
        let send_id = session.next_stream_id;
        session.next_stream_id += 1;
        let per_recipient = encrypt_for_each(
            session,
            &ready,
            Some(channel.clone()),
            send_id,
            plaintext.as_bytes(),
            Content::Text,
        );
        for (id, envelope) in per_recipient {
            session.peer_link.ensure_link(wr, id).await;
            session.peer_link.send_reliable_or_queue(
                id,
                P2pPayload::Envelope {
                    channel: Some(channel.clone()),
                    msg_id: Some(msg_id),
                    envelope,
                },
            );
        }
        for (id, ..) in ready {
            crate::client::session::request_rotation(session, id);
        }
    }
    Ok(())
}

/// Sends one `FileOffer` per ready recipient - a channel file send is N
/// independent point-to-point transfers, each with its own `stream_id`,
/// since accept/reject/progress is inherently per-recipient and there is
/// no broadcast the way voice's channel streams have one.
///
/// The sender sees **one row** for all of them, exactly as a channel voice
/// message does: one delivery record over every recipient it went out to,
/// so the details popup lists them individually
/// (`docs/PROTOCOL.md` 7.2.1) while the log stays one line per thing sent.
/// The row's status is aggregated from all N transfers
/// (`UiState::register_file_row_stream`, `FileRowProgress`).
///
/// Readiness is snapshot-and-exclude: an unready rotating-key recipient is
/// simply left out. Nothing is read from `path` until a recipient
/// individually accepts.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_send_file(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
    path: std::path::PathBuf,
    filename: String,
    size: u64,
    recipients: Vec<Recipient>,
) -> proto::Result<()> {
    let mut ready = Vec::new();
    for (id, der) in recipients {
        if session.remote_keys.try_use(id) {
            ready.push((id, der));
        }
    }
    let payload = crate::client::file_transfer::FileOfferPayload {
        filename: filename.clone(),
        size,
    };
    let Ok(plaintext) = proto::encode(&payload) else {
        return Ok(());
    };
    // Everything that can actually be addressed, prepared before anything
    // is logged: the row names exactly who the offer went out to, which is
    // only known once every recipient has been through the two ways a send
    // to them can still fall through below.
    let mut prepared = Vec::new();
    for (id, der) in ready {
        let stream_id = session.next_stream_id;
        let envelope = crate::client::envelope::encrypt_envelope_for(
            &session.own_pq_private,
            session.pq_peer_keys.encap_for(id),
            &der,
            Some(channel.clone()),
            stream_id,
            &plaintext,
            Content::FileOffer,
        );
        let Some(envelope) = envelope else { continue };
        let Some(key) = voice_stream::resolve_direct_key(session, stream_id, id, &der) else {
            continue;
        };
        session.next_stream_id += 1;
        prepared.push((id, stream_id, envelope, key));
    }
    // The row is named by the first transfer's id and every other one is
    // registered against it, so all N report into one line.
    let Some(&(_, row, ..)) = prepared.first() else {
        return Ok(());
    };
    let recipient_ids: Vec<UserId> = prepared.iter().map(|(id, ..)| *id).collect();
    let (msg_id, delivery) = ui_state.start_delivery(&recipient_ids);
    ui_state.log_own_file_offer_channel(&channel, row, filename.clone(), size, Some(delivery));
    for (id, stream_id, envelope, key) in prepared {
        ui_state.register_file_row_stream(row, stream_id);
        session.own_file_targets.insert(
            stream_id,
            crate::client::file_transfer::OwnFileTarget {
                to: id,
                path: path.clone(),
                key,
                otp: None,
            },
        );
        session.peer_link.ensure_link(wr, id).await;
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::FileOffer {
                channel: Some(channel.clone()),
                stream_id,
                msg_id: Some(msg_id),
                envelope,
            },
        );
        crate::client::session::request_rotation(session, id);
    }
    Ok(())
}

pub(crate) async fn handle_voice_record_start(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    recorder: voice::Recorder,
    stream_id: u64,
    channel: String,
    recipients: Vec<Recipient>,
) -> proto::Result<()> {
    // Voice streams are never queued: a rotating-key recipient without a
    // fresh key right now, or one whose direct link
    // isn't already `Active` right now (no relay fallback, and punching can
    // take up to several seconds - too long to make a live recording wait
    // on), is simply left out of this particular stream, same as any other
    // partial-delivery case.
    let mut ready = Vec::new();
    for (id, der) in recipients {
        if !session.remote_keys.try_use(id) {
            continue;
        }
        if session.peer_link.ensure_link(wr, id).await == LinkReadiness::Active {
            ready.push((id, der));
        }
    }
    let ready_ids: Vec<UserId> = ready.iter().map(|(id, ..)| *id).collect();
    let Some(pq) =
        voice_stream::build_pq_stream_out(session, Some(channel.clone()), stream_id, &ready)
    else {
        return Ok(());
    };
    // One row for the whole stream, addressed to everyone it actually went
    // out to - so a channel voice message reads orange while only some of
    // them have decoded it, exactly like a channel text message.
    let (msg_id, delivery) = ui_state.start_delivery(&ready_ids);
    ui_state.log_own_voice_stream_start_channel(&channel, stream_id, Some(delivery));
    for &id in &ready_ids {
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::StreamStart {
                channel: Some(channel.clone()),
                stream_id,
                msg_id: Some(msg_id),
            },
        );
    }
    // Each recipient's setup follows its `StreamStart`, once and reliably
    // - the chunks after it carry ciphertext only.
    for (id, setup) in pq.setups() {
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
    }
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    session.active_recording = Some(stop_tx);
    session.own_stream_targets.insert(
        stream_id,
        voice_stream::OwnStreamTarget::Channel {
            channel: channel.clone(),
            recipients: ready_ids,
        },
    );
    voice_stream::spawn_record_stream_worker(
        recorder,
        voice_stream::StreamRecipients::Channel { pq },
        stream_id,
        session.record_out_tx.clone(),
        session.own_stream_done_tx.clone(),
        stop_rx,
        session.auto_stop_tx.clone(),
    );
    Ok(())
}

/// Starts a live voice call addressed to every member of `channel` we can
/// currently reach (`voice_call::addressable_channel_members` - excludes
/// self/offline/trust-gated the same way an ordinary send does, and anyone
/// we currently have an OTP session with, which a call can never reach at
/// all - `docs/PROTOCOL.md` "Live voice calls"). We become a participant
/// immediately (`voice_call::begin_own_call`), same as everyone who later
/// accepts; each invitee gets an Accept/Reject popup naming us.
pub(crate) async fn handle_start_call(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
) -> proto::Result<()> {
    let recipients = voice_call::addressable_channel_members(session, ui_state, &channel);
    // Recounted here, not trusted from the `/call` confirmation popup:
    // membership can shift while that popup is up, and a call with nobody
    // to ring is never started at all (`docs/SPEC.md` "Live voice calls").
    if recipients.is_empty() {
        ui_state.push_status_notice(
            crate::client::tui::ui::NO_ONE_INVITED_NOTICE.to_string(),
            false,
        );
        return Ok(());
    }
    let Some(host) = ui_state.own_id else {
        return Ok(());
    };
    let call_id = voice_call::new_call_id();
    if !voice_call::begin_own_call(session, ui_state, call_id, Some(channel.clone()), host) {
        return Ok(());
    }
    for (id, ..) in recipients {
        let name = ui_state
            .known_users
            .get(&id)
            .map(|u| u.name.clone())
            .unwrap_or_default();
        session.peer_link.ensure_link(wr, id).await;
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::CallInvite {
                call_id,
                channel: Some(channel.clone()),
            },
        );
        ui_state.on_call_invite_sent(id, name);
    }
    Ok(())
}

/// Encrypts `plaintext` once per recipient via
/// `envelope::encrypt_envelope_for`.
///
/// Every recipient's copy is bound to the same `channel` and `send_id`, but
/// each is sealed against that recipient's own identity, so one member's
/// copy cannot be re-wrapped and passed to another (`crypto::pq::SendBinding`).
fn encrypt_for_each(
    session: &SessionState,
    recipients: &[Recipient],
    channel: Option<String>,
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Vec<(UserId, Envelope)> {
    recipients
        .iter()
        .filter_map(|(id, pubkey_der)| {
            let envelope = crate::client::envelope::encrypt_envelope_for(
                &session.own_pq_private,
                session.pq_peer_keys.encap_for(*id),
                pubkey_der,
                channel.clone(),
                send_id,
                plaintext,
                content.clone(),
            )?;
            Some((*id, envelope))
        })
        .collect()
}

/// The connect-time `ChannelList` snapshot (docs/PROTOCOL.md §6.3):
/// recorded as the public-channel directory `/channels` lists, plus the
/// single automatic join it implies (`UiState::auto_join_channel`).
pub(crate) fn on_list(
    ui_state: &mut UiState,
    list: Vec<ChannelInfo>,
) -> Option<crate::client::tui::ui::UiAction> {
    ui_state.on_channel_list(list);
    ui_state.auto_join_channel()
}

pub(crate) fn on_joined(ui_state: &mut UiState, channel: ChannelInfo) {
    ui_state.on_joined(channel);
}

pub(crate) fn on_join_failed(name: String, reason: String) {
    crate::log_warn!("failed to join {name}: {reason}");
}

/// Handles `ServerMessage::ChannelJoinRejected` - the password-flow-specific
/// counterpart to `on_join_failed`, distinguished so the client can open the
/// password popup (or show a wrong-password/banned message on it) instead of
/// just logging to stderr.
pub(crate) fn on_join_rejected(
    ui_state: &mut UiState,
    name: String,
    kind: proto::ChannelJoinRejection,
) {
    ui_state.on_channel_join_rejected(name, kind);
}

/// `msg_id`, if the sender asked for one, is receipted here and nowhere
/// else: only this branch is reached, and it is reached only once the
/// envelope has actually been decrypted (docs/PROTOCOL.md 7.2.1). A
/// message that arrives but cannot be opened is deliberately left
/// unacknowledged - the sender's row stays undelivered, which is the
/// truth.
pub fn on_message(
    ui_state: &mut UiState,
    session: &mut SessionState,
    channel: String,
    from: UserId,
    from_name: String,
    msg_id: Option<u64>,
    envelope: Envelope,
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    if let Some(body) = crate::client::session::decrypt_envelope_for(
        envelope,
        from,
        &sender,
        Some(&channel),
        session,
    ) {
        ui_state.on_channel_message(&channel, from, from_name, body);
        crate::client::session::send_delivery_receipt(
            session,
            from,
            msg_id,
            crate::p2p_proto::ReceiptStage::Decrypted,
        );
        crate::client::session::request_rotation(session, from);
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
    // §11.2/§12): a Pending/Rejected sender's stream is never played live,
    // and neither is a `/mute-voice`d one (docs/SPEC.md Functionality #15).
    let suppress_playback = ui_state.suppress_playback_from(from);
    let sender_public_key_der = ui_state
        .known_users
        .get(&from)
        .map(|u| u.public_key_der.clone())
        .unwrap_or_default();
    ui_state.on_channel_stream_start(&channel, from, from_name, stream_id);
    voice_stream::start_incoming_stream(
        session,
        from,
        stream_id,
        Some(channel),
        suppress_playback,
        &sender_public_key_der,
    );
}

// Same pre-existing arity exception as `session::run_connected_session`'s.
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_own_stream_finished(
    ui_state: &mut UiState,
    session: &mut SessionState,
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
    // chunk (PROTOCOL.md §11.2).
    for peer in recipients {
        crate::client::session::request_rotation(session, peer);
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
