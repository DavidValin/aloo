//! Live, continuous, multi-user voice calls (`docs/PROTOCOL.md` "Live voice
//! calls") - distinct from push-to-talk voice messages
//! (`crate::client::voice_stream`), though it reuses that module's per-chunk
//! crypto dispatch (`resolve_direct_key`/`resolve_incoming_key`/
//! `encrypt_direct_chunk`/`ChunkDecryptor`) and `crate::client::voice`'s
//! recorder/mixer wholesale: a call's audio is, at the wire level, just an
//! unbounded stream per (us, one other participant) pair, addressed under
//! the call's own `call_id` standing in for `stream_id`
//! (`p2p_proto::P2pPayload::CallInvite`'s doc explains why that's safe).
//!
//! There is no server involvement (every message here is a
//! `p2p_proto::P2pPayload`, never a `proto::ClientMessage`/`ServerMessage`)
//! and no single participant coordinating the roster: every participant
//! learns about every other purely from `CallAccept`s exchanged directly
//! between them - see `on_call_accept`. Two rules are all it takes to
//! converge a full mesh regardless of join order:
//!
//! 1. On becoming an active participant (accepting an invite), broadcast
//!    `CallAccept` to every other member of the call's channel/DM we can
//!    currently address (`accept_invite`).
//! 2. On receiving a `CallAccept` for our own active call from someone not
//!    yet in our roster, add them *and* reply with our own `CallAccept`
//!    straight back to them alone (`on_call_accept`) - a "welcome" that
//!    reaches whoever became active too late to see our own broadcast.
//!
//! The initiator needs no special-casing: they never explicitly send a
//! `CallAccept` of their own, and are added to (and add) everyone else
//! purely through rule 2, exactly like any other participant.

use std::collections::HashMap;
use std::sync::mpsc::RecvTimeoutError;

use crate::client::p2p::P2pOutbound;
use crate::client::session::SessionState;
use crate::client::tui::ui::{self, UiState};
use crate::client::voice;
use crate::client::voice_stream::{self, ChunkDecryptor, DecryptJob, DirectStreamKey};
use crate::control::ControlSink;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, KeyMode, UserId};

/// One command to a running `spawn_call_audio_worker` thread - the call
/// counterpart of push-to-talk's plain `stop_rx: Receiver<()>`, richer
/// because a call's recipient set and mute state both change live, for as
/// long as the call runs (unlike a bounded recording's fixed
/// `voice_stream::StreamRecipients`, resolved once at start).
pub(crate) enum CallRecorderCmd {
    AddRecipient(UserId, Box<DirectStreamKey>),
    RemoveRecipient(UserId),
    SetMuted(bool),
    Stop,
}

/// One participant's incoming-audio bookkeeping.
pub(crate) struct ActiveCallPeer {
    job_tx: tokio::sync::mpsc::UnboundedSender<DecryptJob>,
    mixer_id: u64,
}

/// The call this client is currently in - inviting, ringing, or actively
/// talking; there is no separate state machine for those, since both the
/// initiator (`/call`) and an accepter are full participants from the
/// moment they join (see this module's doc). At most one at a time:
/// starting or accepting a second call while this is `Some` is refused
/// (`is_busy`), the same one-line-at-a-time simplification a phone makes.
pub(crate) struct ActiveCall {
    pub(crate) call_id: u64,
    /// Participants we are actively exchanging audio with - never includes
    /// ourselves.
    participants: HashMap<UserId, ActiveCallPeer>,
    muted: bool,
    /// Commands for the capture thread (`spawn_call_audio_worker`).
    cmd_tx: std::sync::mpsc::Sender<CallRecorderCmd>,
}

/// A fresh random call identifier - same construction as a link's
/// `link_nonce` (`p2p::random_token`): unguessable off-path, since it only
/// ever travels over an authenticated P2P link.
pub(crate) fn new_call_id() -> u64 {
    let bytes = crate::crypto::random_bytes(8);
    u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
}

/// Whether we're already on a call - gates starting or accepting another
/// one (`session::handle_ui_action`'s `StartCall`/`AcceptCallInvite` arms,
/// `on_call_invite`'s auto-decline).
pub(crate) fn is_busy(session: &SessionState) -> bool {
    session.active_call.is_some()
}

/// Every current member of `channel` we could plausibly call: the same
/// filter an ordinary channel send applies (self/offline/trust-gated
/// excluded, `UiState::recipients_for_channel`), further excluding anyone
/// we currently have an active OTP session with - OTP has no live-streaming
/// concept at all (voice under OTP is recorded whole and sent once, never
/// continuous), so a call can never reach them (`docs/PROTOCOL.md` "Live
/// voice calls"). Used both for the initiator's invite fan-out
/// (`crate::client::channel::handle_start_call`) and an accepter's
/// `CallAccept` broadcast (`accept_invite`) - the two places that need
/// "everyone else who could conceivably be on this call".
pub(crate) fn addressable_channel_members(
    session: &SessionState,
    ui_state: &UiState,
    channel: &str,
) -> Vec<ui::Recipient> {
    let Some(tab) = ui_state.channels.iter().find(|c| c.name == channel) else {
        return Vec::new();
    };
    ui_state
        .recipients_for_channel(tab)
        .into_iter()
        .filter(|(_, _, der)| crate::client::otp::contact_name_if_active(session, der).is_none())
        .collect()
}

/// Starts our own participation in call `call_id`: opens the microphone and
/// the continuous capture-and-fan-out thread (empty recipient set - audio
/// only starts reaching a participant once `add_participant` adds them),
/// and records the call in both `SessionState` (network/audio plumbing) and
/// `UiState` (the permanent top-right indicator, `docs/SPEC.md`). Called by
/// both the initiator (`/call`) and an accepter
/// (`accept_invite`) - see this module's doc for why neither role needs any
/// further distinction from here on. `false` (with a status notice already
/// pushed) if the microphone can't be opened, or we're already on a call.
pub(crate) fn begin_own_call(
    session: &mut SessionState,
    ui_state: &mut UiState,
    call_id: u64,
    channel: Option<String>,
) -> bool {
    if is_busy(session) {
        return false;
    }
    let err_tx = session.audio_err_tx.clone();
    let on_stream_error = move |e: String| {
        let _ = err_tx.send(e);
    };
    let recorder = match voice::Recorder::start(on_stream_error) {
        Ok(r) => r,
        Err(e) => {
            ui_state.push_status_notice(format!("couldn't start the call: {e}"), false);
            return false;
        }
    };
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    spawn_call_audio_worker(recorder, call_id, cmd_rx, session.record_out_tx.clone());
    session.active_call = Some(ActiveCall {
        call_id,
        participants: HashMap::new(),
        muted: false,
        cmd_tx,
    });
    ui_state.begin_call(call_id, channel);
    true
}

/// Runs on a dedicated thread for as long as we're on a call: captures
/// continuously (no `voice::MAX_RECORDING_SAMPLES` cap - a call is meant to
/// outlast any one voice message) and, every `voice::CHUNK_INTERVAL`,
/// encrypts and fans the captured audio out to every current recipient,
/// added/removed/muted live via `cmd_rx` rather than fixed at spawn time
/// the way a bounded recording's is. Always drains the recorder, even
/// while muted or between commands, so the OS-level capture buffer never
/// grows unbounded - muted samples are simply discarded instead of sent.
fn spawn_call_audio_worker(
    recorder: voice::Recorder,
    call_id: u64,
    cmd_rx: std::sync::mpsc::Receiver<CallRecorderCmd>,
    out_tx: tokio::sync::mpsc::UnboundedSender<P2pOutbound>,
) {
    std::thread::spawn(move || {
        let mut recipients: HashMap<UserId, DirectStreamKey> = HashMap::new();
        let mut muted = false;
        let mut seq: u32 = 0;
        'outer: loop {
            let mut pending_cmds = match cmd_rx.recv_timeout(voice::CHUNK_INTERVAL) {
                Ok(cmd) => vec![cmd],
                Err(RecvTimeoutError::Timeout) => Vec::new(),
                Err(RecvTimeoutError::Disconnected) => break,
            };
            while let Ok(cmd) = cmd_rx.try_recv() {
                pending_cmds.push(cmd);
            }
            for cmd in pending_cmds {
                match cmd {
                    CallRecorderCmd::AddRecipient(id, key) => {
                        recipients.insert(id, *key);
                    }
                    CallRecorderCmd::RemoveRecipient(id) => {
                        recipients.remove(&id);
                    }
                    CallRecorderCmd::SetMuted(m) => muted = m,
                    CallRecorderCmd::Stop => break 'outer,
                }
            }

            let pending = recorder.take_pending();
            if muted || pending.is_empty() || recipients.is_empty() {
                continue;
            }
            let pcm = voice::pcm_to_bytes(&pending);
            let per_recipient: Vec<(UserId, Vec<Vec<u8>>)> = recipients
                .iter()
                .filter_map(|(id, key)| {
                    voice_stream::encrypt_direct_chunk(key, call_id, seq, &pcm).map(|b| (*id, b))
                })
                .collect();
            if !per_recipient.is_empty() {
                let _ = out_tx.send(P2pOutbound::CallVoiceChunk {
                    call_id,
                    seq,
                    per_recipient,
                });
            }
            seq = seq.wrapping_add(1);
        } // `recorder` drops here, closing the input stream.
    });
}

/// Runs on a dedicated thread for as long as one call participant's
/// incoming audio needs decrypting - unlike
/// `voice_stream::spawn_stream_decrypt_worker`, never accumulates
/// plaintext (a call has no finished clip to produce) and never
/// self-finalizes on `voice::MAX_RECORDING_SAMPLES` (a call is meant to run
/// far longer than any one voice message). Simply exits once its returned
/// sender is dropped (`remove_participant`/`end_own_call`), the
/// direct-transport counterpart of closing a socket.
fn spawn_call_decrypt_worker(
    key: voice_stream::IncomingStreamKey,
    mixer_tx: tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>,
    mixer_id: u64,
    call_id: u64,
) -> tokio::sync::mpsc::UnboundedSender<DecryptJob> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DecryptJob>();
    std::thread::spawn(move || {
        let mut decryptor = ChunkDecryptor::new(key);
        let push = |pcm: Vec<u8>, mixer_tx: &tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>| {
            let samples = voice::pcm_from_bytes(&pcm);
            let _ = mixer_tx.send(voice::MixerCmd::Push {
                id: mixer_id,
                samples,
            });
        };
        while let Some(job) = rx.blocking_recv() {
            match job {
                DecryptJob::KeySetup(blob) => {
                    if let Some(waiting) = decryptor.install_setup(call_id, &blob) {
                        for (_, pcm) in waiting {
                            push(pcm, &mixer_tx);
                        }
                    }
                }
                DecryptJob::Chunk(seq, blocks) => {
                    if let Some(pcm) = decryptor.decrypt(call_id, seq, &blocks) {
                        push(pcm, &mixer_tx);
                    }
                }
                // Never sent for a call - see `is_call_stream`'s doc.
                DecryptJob::End => break,
            }
        }
    });
    tx
}

/// Whether `(from, stream_id)` names one of our current call's
/// participants - the routing check `session::handle_p2p_event` uses to
/// tell a call's audio apart from an ordinary push-to-talk stream sharing
/// the same generic `P2pEvent::StreamChunk`/`StreamKeySetup` wire events
/// (safe: a `call_id` and a push-to-talk `stream_id` are drawn from
/// disjoint generators - `new_call_id`'s full random 64 bits versus
/// `SessionState::next_stream_id`'s small sequential counter - so the two
/// can never collide in practice, and even if they did they're still keyed
/// apart by `from`).
pub(crate) fn is_call_stream(session: &SessionState, from: UserId, stream_id: u64) -> bool {
    session.active_call.as_ref().is_some_and(|c| {
        c.call_id == stream_id && c.participants.contains_key(&from)
    })
}

pub(crate) fn forward_key_setup(session: &SessionState, from: UserId, stream_id: u64, setup: Vec<u8>) {
    if let Some(call) = session.active_call.as_ref()
        && call.call_id == stream_id
        && let Some(peer) = call.participants.get(&from)
    {
        let _ = peer.job_tx.send(DecryptJob::KeySetup(setup));
    }
}

pub(crate) fn forward_chunk(
    session: &SessionState,
    from: UserId,
    stream_id: u64,
    seq: u32,
    blocks: Vec<Vec<u8>>,
) {
    if let Some(call) = session.active_call.as_ref()
        && call.call_id == stream_id
        && let Some(peer) = call.participants.get(&from)
    {
        let _ = peer.job_tx.send(DecryptJob::Chunk(seq, blocks));
    }
}

/// Adds `peer` to our call roster if they aren't already in it: resolves
/// their key material the same way a DM voice stream would
/// (`voice_stream::resolve_direct_key`, our call's `call_id` standing in
/// for `stream_id`), sends them a `pq_hybrid` setup if that's what they
/// need, tells our own capture thread to start including them, and spawns
/// a decrypt worker for their incoming audio under a fresh mixer id so
/// `voice::mix_output` sums them in with everyone else already on the
/// call. Returns whether `peer` was newly added - `false` for an
/// already-known participant (a harmless no-op - see this module's doc) or
/// a key-resolution failure.
async fn add_participant(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    peer_name: &str,
    key_mode: KeyMode,
    pubkey_der: &[u8],
) -> bool {
    let Some(call) = session.active_call.as_ref() else {
        return false;
    };
    let call_id = call.call_id;
    if call.participants.contains_key(&peer) {
        return false;
    }
    let Some(key) = voice_stream::resolve_direct_key(session, call_id, peer, key_mode, pubkey_der)
    else {
        return false;
    };
    session.peer_link.ensure_link(wr, peer).await;
    if let DirectStreamKey::Pq(pq) = &key {
        for (id, setup) in pq.setups() {
            session
                .peer_link
                .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id: call_id, setup });
        }
    }
    let mixer_id = session.next_mixer_id;
    session.next_mixer_id += 1;
    let incoming_key = voice_stream::resolve_incoming_key(session, peer, pubkey_der);
    let job_tx = spawn_call_decrypt_worker(incoming_key, session.mixer_tx.clone(), mixer_id, call_id);

    let Some(call) = session.active_call.as_mut() else {
        return false;
    };
    let _ = call.cmd_tx.send(CallRecorderCmd::AddRecipient(peer, Box::new(key)));
    call.participants.insert(peer, ActiveCallPeer { job_tx, mixer_id });
    ui_state.on_call_participant_joined(peer, peer_name.to_string());
    true
}

/// Tears down one participant's audio in both directions: our capture
/// thread stops including them, their incoming decrypt worker's channel is
/// dropped (which ends that thread), and their mixer source is stopped
/// outright - immediate silence, not a drained tail, since (unlike a voice
/// message finishing naturally) they are actually gone.
fn remove_participant(session: &mut SessionState, ui_state: &mut UiState, peer: UserId) {
    let Some(call) = session.active_call.as_mut() else {
        return;
    };
    let Some(removed) = call.participants.remove(&peer) else {
        return;
    };
    let _ = call.cmd_tx.send(CallRecorderCmd::RemoveRecipient(peer));
    let _ = session.mixer_tx.send(voice::MixerCmd::Stop { id: removed.mixer_id });
    ui_state.on_call_participant_left(peer);
}

/// `P2pEvent::CallInvite` - auto-declines if we're already busy (real
/// phones call this "busy", and it spares the caller a popup that could
/// never be accepted), holds it if `from` is a trust-gated identity (same
/// "decide on them before anything else" precedent a file offer/message
/// already follows), or queues it for the Accept/Reject popup. Returns
/// whether the caller should play the bell chime - true iff it became the
/// one actually shown.
pub(crate) async fn on_call_invite(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    from_name: String,
    call_id: u64,
    channel: Option<String>,
) -> bool {
    if is_busy(session) {
        session.peer_link.ensure_link(wr, from).await;
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::CallReject { call_id });
        return false;
    }
    let invite = ui::PendingCallInvite {
        call_id,
        from,
        from_name,
        channel,
    };
    if ui_state.is_trust_gated(from) {
        ui_state.hold_call_invite(invite);
        return false;
    }
    ui_state.push_call_invite(invite)
}

/// `P2pEvent::CallAccept` - the one mechanism that converges every
/// participant's roster with no coordinator (see this module's doc). A
/// no-op unless `call_id` names our own active call.
pub(crate) async fn on_call_accept(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    call_id: u64,
) -> proto::Result<()> {
    let busy_here = session
        .active_call
        .as_ref()
        .is_some_and(|c| c.call_id == call_id);
    if !busy_here {
        return Ok(());
    }
    let Some(user) = ui_state.known_users.get(&from).cloned() else {
        return Ok(());
    };
    let added = add_participant(
        wr,
        session,
        ui_state,
        from,
        &user.name,
        user.key_mode,
        &user.public_key_der,
    )
    .await;
    if added {
        session.peer_link.ensure_link(wr, from).await;
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::CallAccept { call_id });
    }
    Ok(())
}

/// `P2pEvent::CallReject` - purely informational: `from` was never added
/// as a participant (a popup is only ever shown to someone who can choose
/// Reject), so there is nothing structural to undo.
pub(crate) fn on_call_reject(session: &SessionState, ui_state: &mut UiState, from: UserId, call_id: u64) {
    let matches_ours = session
        .active_call
        .as_ref()
        .is_some_and(|c| c.call_id == call_id);
    if !matches_ours {
        return;
    }
    if let Some(name) = ui_state.known_users.get(&from).map(|u| u.name.clone()) {
        ui_state.push_status_notice(format!("{name} declined the call"), false);
    }
}

/// `P2pEvent::CallEnd` - a participant left; tear down their audio and say
/// so, unless this names some other call than the one we're actually on
/// (a stale message from one we already left ourselves).
pub(crate) fn on_call_end(session: &mut SessionState, ui_state: &mut UiState, from: UserId, call_id: u64) {
    let matches_ours = session
        .active_call
        .as_ref()
        .is_some_and(|c| c.call_id == call_id);
    if !matches_ours {
        return;
    }
    let name = ui_state.known_users.get(&from).map(|u| u.name.clone());
    remove_participant(session, ui_state, from);
    if let Some(name) = name {
        ui_state.push_status_notice(format!("{name} left the call"), true);
    }
}

/// The `AcceptCallInvite` UI action: joins the call named by a still-queued
/// invite (a no-op if it was already withdrawn, or we're on a call
/// already) and broadcasts our own `CallAccept` to everyone else who might
/// be on it - see this module's doc for why that alone, plus
/// `on_call_accept`'s reply-to-newcomers rule, is enough to converge the
/// whole mesh with no coordinator.
pub(crate) async fn accept_invite(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    call_id: u64,
) -> proto::Result<()> {
    let Some(invite) = ui_state.take_call_invite(call_id) else {
        return Ok(());
    };
    if is_busy(session) {
        session.peer_link.ensure_link(wr, invite.from).await;
        session
            .peer_link
            .send_reliable_or_queue(invite.from, P2pPayload::CallReject { call_id });
        return Ok(());
    }
    let others: Vec<UserId> = match &invite.channel {
        Some(channel) => addressable_channel_members(session, ui_state, channel)
            .into_iter()
            .map(|(id, ..)| id)
            .collect(),
        None => vec![invite.from],
    };
    if !begin_own_call(session, ui_state, call_id, invite.channel.clone()) {
        return Ok(());
    }
    for id in others {
        session.peer_link.ensure_link(wr, id).await;
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::CallAccept { call_id });
    }
    Ok(())
}

/// The `RejectCallInvite` UI action: declines a still-queued invite (a
/// no-op if it was already withdrawn) - answered only to whoever sent it,
/// mirrors `P2pPayload::CallReject`'s doc.
pub(crate) async fn reject_invite(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    call_id: u64,
) -> proto::Result<()> {
    let Some(invite) = ui_state.take_call_invite(call_id) else {
        return Ok(());
    };
    session.peer_link.ensure_link(wr, invite.from).await;
    session
        .peer_link
        .send_reliable_or_queue(invite.from, P2pPayload::CallReject { call_id });
    Ok(())
}

/// The `ToggleCallMute` UI action (`/mute`): flips our own mute state and
/// tells the capture thread - a purely local gate on whether captured audio
/// is ever encrypted/sent at all (see `spawn_call_audio_worker`), so
/// nothing is signalled to other participants.
pub(crate) fn toggle_mute(session: &mut SessionState, ui_state: &mut UiState) {
    let Some(call) = session.active_call.as_mut() else {
        return;
    };
    call.muted = !call.muted;
    let _ = call.cmd_tx.send(CallRecorderCmd::SetMuted(call.muted));
    ui_state.set_call_muted(call.muted);
}

/// The `EndCall` UI action (`/endcall`): tells every current participant we
/// left, tears down every incoming decrypt worker/mixer source, stops our
/// own capture thread, and clears both `SessionState`/`UiState`'s call
/// bookkeeping. The only path that ever removes our *own* `active_call` -
/// mirrors `/leave` being the only path that removes a joined channel.
pub(crate) async fn end_own_call(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(call) = session.active_call.take() else {
        return Ok(());
    };
    for &peer in call.participants.keys() {
        session.peer_link.ensure_link(wr, peer).await;
        session
            .peer_link
            .send_reliable_or_queue(peer, P2pPayload::CallEnd { call_id: call.call_id });
    }
    for peer in call.participants.into_values() {
        let _ = session.mixer_tx.send(voice::MixerCmd::Stop { id: peer.mixer_id });
    }
    let _ = call.cmd_tx.send(CallRecorderCmd::Stop);
    ui_state.end_call();
    Ok(())
}
