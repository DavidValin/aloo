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
//! 3. On adding someone, send them our own roster (`CallRoster`), which
//!    they answer with a `CallAccept` each - the only way a participant
//!    invited *mid-call* (`invite_to_call`, from the call modal) can
//!    reach people it could never have derived from the call's channel
//!    membership. A pure discovery aid: rules 1 and 2 still do the work.
//!
//! For audio and roster purposes the initiator needs no special-casing:
//! they never explicitly send a `CallAccept` of their own, and are added
//! to (and add) everyone else purely through rule 2, exactly like any
//! other participant. They are, however, the call's **host**
//! (`ActiveCall::host`), and three decisions are theirs alone: muting a
//! participant (`host_set_muted`/`on_call_mute`), inviting one more
//! person (`invite_to_call`), and ending the call for everyone by leaving
//! it (`on_call_end`'s host branch). Each is honoured only from the host
//! of the call we are actually on - that check is the whole of the host's
//! authority, since there is no server to enforce anything.

use std::collections::HashMap;
use std::sync::mpsc::RecvTimeoutError;

use crate::client::p2p::P2pOutbound;
use crate::client::session::SessionState;
use crate::client::tui::ui::{self, UiState};
use crate::client::voice;
use crate::client::voice_stream::{self, ChunkDecryptor, DecryptJob, DirectStreamKey};
use crate::control::ControlSink;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, UserId};

/// One command to a running `spawn_call_audio_worker` thread - the call
/// counterpart of push-to-talk's plain `stop_rx: Receiver<()>`, richer
/// because a call's recipient set and mute state both change live, for as
/// long as the call runs (unlike a bounded recording's fixed
/// `voice_stream::StreamRecipients`, resolved once at start).
pub(crate) enum CallRecorderCmd {
    AddRecipient(UserId, Box<DirectStreamKey>),
    RemoveRecipient(UserId),
    SetMuted(bool),
    /// The host's mute (`P2pPayload::CallMute`), tracked separately from
    /// `SetMuted` so lifting one never lifts the other - a participant the
    /// host muted stays silent through their own mute toggling.
    SetHostMuted(bool),
    Stop,
}

/// Key setups that arrived for a call participant we had not yet added to
/// our roster, held until we do (`forward_key_setup`/`add_participant`).
///
/// This is not an edge case but the *ordinary* order of events for a
/// `pq_hybrid` peer: `add_participant` sends its one `StreamKeySetup` the
/// instant it adds us, and the `CallAccept` that lets *us* add *them* is
/// still in flight at that moment. Dropping the setup - which is what
/// happened before this existed - left that peer permanently
/// undecryptable while our own audio reached them fine, i.e. a call
/// audible in one direction only.
///
/// At most one setup per peer: a stream has exactly one, and a second
/// arrival can only be a fresher attempt, so it replaces rather than
/// queues.
#[derive(Debug, Default)]
pub struct PendingCallSetups(HashMap<UserId, Vec<u8>>);

impl PendingCallSetups {
    /// Holds `from`'s setup until they join our roster.
    pub fn hold(&mut self, from: UserId, setup: Vec<u8>) {
        self.0.insert(from, setup);
    }

    /// Takes whatever was held for `from`, if anything - delivering it is
    /// the caller's job, and it is never delivered twice.
    pub fn take(&mut self, from: UserId) -> Option<Vec<u8>> {
        self.0.remove(&from)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
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
    /// Who started this call - the only participant allowed to mute
    /// others, invite more people, or end it for everyone. Ourselves for a
    /// call we started, whoever sent the `CallInvite` for one we accepted.
    pub(crate) host: UserId,
    /// Participants we are actively exchanging audio with - never includes
    /// ourselves.
    participants: HashMap<UserId, ActiveCallPeer>,
    /// Setups from participants we have not added yet - see
    /// `PendingCallSetups`.
    pending_setups: PendingCallSetups,
    /// Audio chunks from participants we have not added yet - the same
    /// ordinary-order race `PendingCallSetups` exists for (`add_participant`
    /// still needs their `CallAccept` before we can add them, but nothing
    /// stops their audio from reaching us first), except a stream of chunks
    /// rather than the single setup a `pq_hybrid` peer sends once. Reuses
    /// `voice_stream::PendingChunkBuffer` verbatim - `call_id` stands in for
    /// `stream_id` here exactly as it does everywhere else in this module.
    pending_chunks: voice_stream::PendingChunkBuffer,
    muted: bool,
    /// Silenced by the host (`P2pPayload::CallMute`) - unlike `muted`,
    /// only the host can lift it, and every participant is told.
    host_muted: bool,
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
        .filter(|(id, der)| {
            crate::client::otp::contact_name_for_sending(session, ui_state, *id, der).is_none()
        })
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
    host: UserId,
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
    let echo_ducking = voice_stream::effective_echo_ducking(&recorder, session.echo_ducking);
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    spawn_call_audio_worker(
        recorder,
        call_id,
        cmd_rx,
        session.record_out_tx.clone(),
        ui_state.own_id,
        session.call_level_tx.clone(),
        echo_ducking,
    );
    session.active_call = Some(ActiveCall {
        call_id,
        host,
        participants: HashMap::new(),
        pending_setups: PendingCallSetups::default(),
        pending_chunks: voice_stream::PendingChunkBuffer::new(),
        muted: false,
        host_muted: false,
        cmd_tx,
    });
    ui_state.begin_call(call_id, channel, host);
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
    // Ours, purely so our own captured level can be metered on the call
    // modal's roster under the right row - `None` only in the moment
    // before the server has told us who we are, which a call can't
    // realistically reach.
    own_id: Option<UserId>,
    level_tx: tokio::sync::mpsc::UnboundedSender<(UserId, u8)>,
    // `settings::Settings::voice_echo_ducking` - see `voice::EchoDucker`
    // and, under `Auto`, `voice::EchoProbe`.
    echo_ducking: crate::settings::EchoDucking,
) {
    std::thread::spawn(move || {
        let mut recipients: HashMap<UserId, DirectStreamKey> = HashMap::new();
        let mut muted = false;
        let mut host_muted = false;
        let mut seq: u32 = 0;
        let mut ducker = voice::EchoDucker::new();
        let mut probe = voice::EchoProbe::new();
        let mut silence = voice::SilenceGate::new();
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
                    CallRecorderCmd::SetHostMuted(m) => host_muted = m,
                    CallRecorderCmd::Stop => break 'outer,
                }
            }

            let mut pending = recorder.take_pending();
            // Attenuated before anything else looks at it, so the meter,
            // the silence gate and the wire all agree on what was
            // captured - and so what the other side hears back from their
            // own speakers is pushed under the noise floor
            // (`voice::EchoDucker`).
            if !pending.is_empty() {
                let playback = voice::playback_level();
                // Deliberately the *undicked* level, and deliberately not
                // fed while muted: `voice::EchoProbe`'s doc explains why
                // both would otherwise corrupt its evidence.
                let duck = match echo_ducking {
                    crate::settings::EchoDucking::Off => false,
                    crate::settings::EchoDucking::On => true,
                    crate::settings::EchoDucking::Auto => {
                        if !muted && !host_muted {
                            probe.observe(voice::level_from_pcm(&pending), playback);
                        }
                        probe.should_duck()
                    }
                };
                if duck {
                    ducker.process(&mut pending, playback);
                }
            }
            let level = voice::level_from_pcm(&pending);
            // The meter reads what we are actually sending, so a muted
            // microphone reads flat zero rather than freezing at whatever
            // it happened to show when mute was pressed.
            if let Some(own_id) = own_id {
                let _ = level_tx.send((own_id, if muted || host_muted { 0 } else { level }));
            }
            if muted || host_muted || pending.is_empty() || recipients.is_empty() {
                continue;
            }
            // Silence is not worth a packet to every participant. Unlike a
            // voice message - which is a recording, and whose pauses are
            // part of it - a call is a live stream, so a gap here is simply
            // a moment nobody spoke (`voice::SilenceGate`).
            let covered = std::time::Duration::from_millis(voice::samples_to_ms(
                pending.len(),
                voice::SAMPLE_RATE_HZ,
            ));
            if !silence.should_send(level, covered) {
                continue;
            }
            let coded = voice::encode_voice_chunk(&pending);
            let per_recipient: Vec<(UserId, Vec<Vec<u8>>)> = recipients
                .iter()
                .filter_map(|(id, key)| {
                    voice_stream::encrypt_direct_chunk(key, call_id, seq, &coded).map(|b| (*id, b))
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
    // Whose audio this is, and where to report its level - the call
    // modal's meter for this participant (`docs/SPEC.md` "Live voice
    // calls") is read off the same plaintext that goes to the mixer,
    // rather than estimated from ciphertext size.
    peer: UserId,
    level_tx: tokio::sync::mpsc::UnboundedSender<(UserId, u8)>,
) -> tokio::sync::mpsc::UnboundedSender<DecryptJob> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DecryptJob>();
    std::thread::spawn(move || {
        let mut decryptor = ChunkDecryptor::new(key);
        let push =
            |chunk: Vec<u8>, mixer_tx: &tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>| {
                // Coded on the wire (`voice::VOICE_CODEC_ADPCM`); an
                // undecodable chunk is dropped rather than metered or
                // played, since this is network input.
                let Some(samples) = voice::decode_voice_chunk(&chunk) else {
                    return;
                };
                let _ = level_tx.send((peer, voice::level_from_pcm(&samples)));
                let _ = mixer_tx.send(voice::MixerCmd::PushLive {
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
pub(crate) fn is_call_stream(session: &SessionState, _from: UserId, stream_id: u64) -> bool {
    session
        .active_call
        .as_ref()
        .is_some_and(|c| c.call_id == stream_id)
}

/// A call participant's `pq_hybrid` key setup. Held for later
/// (`ActiveCall::pending_setups`) rather than dropped when it arrives
/// before we have added `from` to our roster - which is the *normal*
/// order, not an edge case: the peer sends this the instant they add us,
/// and their `CallAccept` (what lets us add them) is still in flight at
/// that point. Dropping it left that peer permanently undecryptable while
/// our own audio reached them fine - a call audible in one direction only.
pub(crate) fn forward_key_setup(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    setup: Vec<u8>,
) {
    let Some(call) = session.active_call.as_mut() else {
        return;
    };
    if call.call_id != stream_id {
        return;
    }
    match call.participants.get(&from) {
        Some(peer) => {
            let _ = peer.job_tx.send(DecryptJob::KeySetup(setup));
        }
        None => {
            call.pending_setups.hold(from, setup);
        }
    }
}

/// A chunk from a participant already on our roster is handed straight to
/// their decrypt worker; one from a `from` we have not added yet - the
/// normal order, not an edge case, see `PendingCallSetups`'s doc for why -
/// is held in `pending_chunks` for `add_participant` to replay once they
/// actually join, rather than lost: unlike a short push-to-talk message
/// this doesn't cost a whole clip, but it would otherwise mean a
/// participant's first moment of audio is silently missing every time they
/// join a call already in progress.
pub(crate) fn forward_chunk(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    seq: u32,
    blocks: Vec<Vec<u8>>,
) {
    let Some(call) = session.active_call.as_mut() else {
        return;
    };
    if call.call_id != stream_id {
        return;
    }
    match call.participants.get(&from) {
        Some(peer) => {
            let _ = peer.job_tx.send(DecryptJob::Chunk(seq, blocks));
        }
        None => {
            call.pending_chunks.push(from, stream_id, seq, blocks);
        }
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
    pubkey_der: &[u8],
) -> bool {
    let Some(call) = session.active_call.as_ref() else {
        return false;
    };
    let call_id = call.call_id;
    if call.participants.contains_key(&peer) {
        return false;
    }
    let Some(key) = voice_stream::resolve_direct_key(session, call_id, peer, pubkey_der) else {
        return false;
    };
    session.peer_link.ensure_link(wr, peer).await;
    for (id, setup) in key.setups() {
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::StreamKeySetup {
                stream_id: call_id,
                setup,
            },
        );
    }
    let mixer_id = session.next_mixer_id;
    session.next_mixer_id += 1;
    let incoming_key = voice_stream::resolve_incoming_key(session, peer, pubkey_der);
    let job_tx = spawn_call_decrypt_worker(
        incoming_key,
        session.mixer_tx.clone(),
        mixer_id,
        call_id,
        peer,
        session.call_level_tx.clone(),
    );

    let Some(call) = session.active_call.as_mut() else {
        return false;
    };
    let _ = call
        .cmd_tx
        .send(CallRecorderCmd::AddRecipient(peer, Box::new(key)));
    // Anything this peer sent before we could add them - their one
    // `pq_hybrid` key setup, then whatever audio chunks followed it - goes
    // in first, in that order, ahead of any live chunk the worker is about
    // to be handed next. See `forward_key_setup`/`forward_chunk`.
    if let Some(setup) = call.pending_setups.take(peer) {
        let _ = job_tx.send(DecryptJob::KeySetup(setup));
    }
    for (seq, blocks) in call.pending_chunks.take(peer, call_id) {
        let _ = job_tx.send(DecryptJob::Chunk(seq, blocks));
    }
    call.participants
        .insert(peer, ActiveCallPeer { job_tx, mixer_id });
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
    let _ = session.mixer_tx.send(voice::MixerCmd::Stop {
        id: removed.mixer_id,
    });
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
        ended: false,
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
        &user.public_key_der,
    )
    .await;
    if added {
        session.peer_link.ensure_link(wr, from).await;
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::CallAccept { call_id });
        // Rule 1's broadcast only reaches the call's channel/DM members -
        // which is exactly who a mid-call invite (`invite_to_call`) is
        // *not* guaranteed to be. Handing the newcomer our own roster
        // closes that gap: they answer each name on it with an ordinary
        // `CallAccept`, and the two rules above converge the rest.
        let members: Vec<UserId> = session
            .active_call
            .as_ref()
            .map(|c| {
                c.participants
                    .keys()
                    .copied()
                    .filter(|id| *id != from)
                    .collect()
            })
            .unwrap_or_default();
        if !members.is_empty() {
            session
                .peer_link
                .send_reliable_or_queue(from, P2pPayload::CallRoster { call_id, members });
        }
        // Our own mute is ours alone to report, so it goes to a newcomer
        // whoever we are - otherwise their roster would show us speaking
        // freely while everyone else's shows us silenced.
        if session.active_call.as_ref().is_some_and(|c| c.muted)
            && let Some(own_id) = ui_state.own_id
        {
            session.peer_link.send_reliable_or_queue(
                from,
                P2pPayload::CallMute {
                    call_id,
                    target: own_id,
                    muted: true,
                },
            );
        }
        // A host-muted participant stays muted for whoever joins after
        // the fact, for the same reason - and only the host may say so.
        if session
            .active_call
            .as_ref()
            .is_some_and(|c| c.host == you(ui_state))
        {
            for (peer, muted) in muted_members(ui_state) {
                session.peer_link.send_reliable_or_queue(
                    from,
                    P2pPayload::CallMute {
                        call_id,
                        target: peer,
                        muted,
                    },
                );
            }
        }
    }
    Ok(())
}

/// Our own `UserId`, or a sentinel that matches nobody - `UiState::own_id`
/// is `None` only before the server has identified us, which no call can
/// reach.
fn you(ui_state: &UiState) -> UserId {
    ui_state.own_id.unwrap_or(UserId(u64::MAX))
}

/// Every participant the host currently has muted, for replaying to a
/// participant who joined after the fact.
fn muted_members(ui_state: &UiState) -> Vec<(UserId, bool)> {
    // Host mutes only: a participant's own mute is theirs to report, and
    // is relayed by nobody (`on_call_mute`'s `target == from` branch).
    ui_state
        .call
        .as_ref()
        .map(|c| {
            c.members
                .iter()
                .filter(|m| m.host_muted)
                .map(|m| (m.id, true))
                .collect()
        })
        .unwrap_or_default()
}

/// `P2pEvent::CallRoster` - someone who just added us handed over their
/// own view of the roster. Answer each name with an ordinary `CallAccept`
/// and let 7.7's convergence rules do the rest; anyone already in our own
/// roster is skipped, since a redundant `CallAccept` would only cost a
/// round trip to be no-opped on the far side.
pub(crate) async fn on_call_roster(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &UiState,
    from: UserId,
    call_id: u64,
    members: Vec<UserId>,
) -> proto::Result<()> {
    let Some(call) = session.active_call.as_ref() else {
        return Ok(());
    };
    if call.call_id != call_id {
        return Ok(());
    }
    let unknown: Vec<UserId> = members
        .into_iter()
        .filter(|id| {
            *id != from
                && Some(*id) != ui_state.own_id
                && !session
                    .active_call
                    .as_ref()
                    .is_some_and(|c| c.participants.contains_key(id))
        })
        .collect();
    for id in unknown {
        session.peer_link.ensure_link(wr, id).await;
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::CallAccept { call_id });
    }
    Ok(())
}

/// `P2pEvent::CallReject` - purely informational: `from` was never added
/// as a participant (a popup is only ever shown to someone who can choose
/// Reject), so there is nothing structural to undo.
pub(crate) fn on_call_reject(
    session: &SessionState,
    ui_state: &mut UiState,
    from: UserId,
    call_id: u64,
) {
    let matches_ours = session
        .active_call
        .as_ref()
        .is_some_and(|c| c.call_id == call_id);
    if !matches_ours {
        return;
    }
    ui_state.on_call_invite_rejected(from);
    if let Some(name) = ui_state.known_users.get(&from).map(|u| u.name.clone()) {
        ui_state.push_status_notice(format!("{name} declined the call"), false);
    }
}

/// `P2pEvent::CallEnd` - a participant left; tear down their audio and say
/// so, unless this names some other call than the one we're actually on
/// (a stale message from one we already left ourselves).
pub(crate) fn on_call_end(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    call_id: u64,
) {
    let on_this_call = session
        .active_call
        .as_ref()
        .is_some_and(|call| call.call_id == call_id);
    // Not a call we are on: it may still be one we were *invited* to and
    // have not answered yet, in which case the invite stays on screen but
    // can no longer join anything (`accept_invite`). Only the peer who
    // invited us can end it that way - the host is the only one whose
    // departure ends a call for everyone (`docs/PROTOCOL.md` 7.7).
    if !on_this_call {
        if ui_state
            .call_invite_for(call_id)
            .is_some_and(|invite| invite.from == from)
        {
            ui_state.mark_call_invite_ended(call_id);
        }
        return;
    }
    let Some(call) = session.active_call.as_ref() else {
        return;
    };
    // The host hanging up ends the call for everyone (`docs/PROTOCOL.md`
    // 7.7): they are the one participant whose departure isn't just one
    // fewer voice. Nothing is sent on - the host already told every
    // participant it knew of, and each of those tears itself down here.
    if call.host == from {
        teardown_own_call(session, ui_state);
        ui_state.push_status_notice(ui::HOST_LEFT_NOTICE.to_string(), false);
        return;
    }
    let name = ui_state.known_users.get(&from).map(|u| u.name.clone());
    remove_participant(session, ui_state, from);
    if let Some(name) = name {
        ui_state.push_status_notice(format!("{name} left the call"), true);
    }
}

/// `P2pEvent::CallMute` - someone's microphone went off or back on
/// (`docs/PROTOCOL.md` 7.7). Two cases, told apart by who it names:
/// `target == from` is a participant reporting their *own* mute, which
/// anyone may do about themselves and which only ever moves a roster row;
/// `target != from` is the host's decision about someone else, honoured
/// only from the actual host of the call we are on - any other
/// participant claiming it is ignored outright, which is what makes "only
/// the host can lift it" hold on the wire and not just in the UI. The
/// host's, when it names us, also reaches our own capture thread.
pub(crate) fn on_call_mute(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    call_id: u64,
    target: UserId,
    muted: bool,
) {
    let Some(call) = session.active_call.as_mut() else {
        return;
    };
    if call.call_id != call_id {
        return;
    }
    // Someone reporting their *own* microphone: a statement of fact about
    // what they are sending, which anyone may make about themselves and
    // nobody may make about anyone else. It only ever moves a roster row -
    // it can never gate our own capture, whoever it names.
    if from == target {
        ui_state.set_call_member_self_muted(target, muted);
        return;
    }
    if call.host != from {
        return;
    }
    if Some(target) == ui_state.own_id {
        call.host_muted = muted;
        let _ = call.cmd_tx.send(CallRecorderCmd::SetHostMuted(muted));
        ui_state.push_status_notice(
            if muted {
                "the host muted you".to_string()
            } else {
                "the host unmuted you".to_string()
            },
            !muted,
        );
    }
    ui_state.set_call_member_host_muted(target, muted);
}

/// The `HostMuteCallMember` UI action (`m` on the call modal's roster):
/// refused unless we really are the host, then told to every participant
/// we know of - including `peer` itself, whose capture thread is what
/// actually goes silent (`on_call_mute`).
pub(crate) async fn host_set_muted(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    muted: bool,
) -> proto::Result<()> {
    let Some(call) = session.active_call.as_ref() else {
        return Ok(());
    };
    if Some(call.host) != ui_state.own_id {
        return Ok(());
    }
    let call_id = call.call_id;
    let audience: Vec<UserId> = call.participants.keys().copied().collect();
    for id in audience {
        session.peer_link.ensure_link(wr, id).await;
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::CallMute {
                call_id,
                target: peer,
                muted,
            },
        );
    }
    ui_state.set_call_member_host_muted(peer, muted);
    Ok(())
}

/// The `InviteToCall` UI action (`i` on the call modal): rings one more
/// person mid-call. Host-only, and refused for a peer already on the
/// roster - the picker already excludes both, this is the same check on
/// the side that actually sends. Their `CallInvite` carries the call's own
/// channel, exactly as the initial fan-out's did, so accepting it puts
/// them on the same call rather than a parallel one.
pub(crate) async fn invite_to_call(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
) -> proto::Result<()> {
    let Some(call) = session.active_call.as_ref() else {
        return Ok(());
    };
    if Some(call.host) != ui_state.own_id || call.participants.contains_key(&to) {
        return Ok(());
    }
    let call_id = call.call_id;
    let channel = ui_state.call.as_ref().and_then(|c| c.channel.clone());
    let Some(user) = ui_state.known_users.get(&to).cloned() else {
        return Ok(());
    };
    if crate::client::otp::contact_name_for_sending(session, ui_state, to, &user.public_key_der)
        .is_some()
    {
        ui_state.push_status_notice(crate::client::tui::ui::OTP_CALL_REFUSAL.to_string(), false);
        return Ok(());
    }
    session.peer_link.ensure_link(wr, to).await;
    session
        .peer_link
        .send_reliable_or_queue(to, P2pPayload::CallInvite { call_id, channel });
    ui_state.on_call_invite_sent(to, user.name);
    Ok(())
}

/// Tears down every part of our own participation without telling anyone -
/// the half `end_own_call` does after it has sent its `CallEnd`s, and all
/// that is left to do when the host's `CallEnd` already ended the call for
/// everyone.
fn teardown_own_call(session: &mut SessionState, ui_state: &mut UiState) {
    let Some(call) = session.active_call.take() else {
        return;
    };
    for peer in call.participants.into_values() {
        let _ = session
            .mixer_tx
            .send(voice::MixerCmd::Stop { id: peer.mixer_id });
    }
    let _ = call.cmd_tx.send(CallRecorderCmd::Stop);
    ui_state.end_call();
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
    // The host hung up while this invite was still on screen
    // (`on_call_end`): the answer is taken, but there is no longer a call
    // to join, so nothing is started and nothing is sent - the inviter
    // has already torn its own side down.
    if invite.ended {
        ui_state.push_status_notice(ui::CALL_ALREADY_ENDED_NOTICE.to_string(), false);
        return Ok(());
    }
    if is_busy(session) {
        session.peer_link.ensure_link(wr, invite.from).await;
        session
            .peer_link
            .send_reliable_or_queue(invite.from, P2pPayload::CallReject { call_id });
        return Ok(());
    }
    // Rule 1's broadcast, plus the inviter unconditionally: for a
    // mid-call invite (`invite_to_call`) we may not even be in the call's
    // channel, and without the inviter in this list nobody would ever
    // learn we joined.
    let mut others: Vec<UserId> = match &invite.channel {
        Some(channel) => addressable_channel_members(session, ui_state, channel)
            .into_iter()
            .map(|(id, ..)| id)
            .collect(),
        None => Vec::new(),
    };
    if !others.contains(&invite.from) {
        others.push(invite.from);
    }
    if !begin_own_call(
        session,
        ui_state,
        call_id,
        invite.channel.clone(),
        invite.from,
    ) {
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

/// The `ToggleCallMute` UI action (`m` on our own row in the call modal):
/// flips our own mute state and tells the capture thread - a local gate on
/// whether captured audio is ever encrypted/sent at all (see
/// `spawn_call_audio_worker`) - then announces it to everyone on the call,
/// so a roster always says who can currently be heard
/// (`docs/PROTOCOL.md` 7.7). It stays ours to lift, unlike the host's
/// mute: the announcement is a statement of fact, not authority.
pub(crate) async fn toggle_mute(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(call) = session.active_call.as_mut() else {
        return Ok(());
    };
    call.muted = !call.muted;
    let muted = call.muted;
    let call_id = call.call_id;
    let _ = call.cmd_tx.send(CallRecorderCmd::SetMuted(muted));
    ui_state.set_call_muted(muted);
    let Some(own_id) = ui_state.own_id else {
        return Ok(());
    };
    ui_state.set_call_member_self_muted(own_id, muted);
    let audience: Vec<UserId> = session
        .active_call
        .as_ref()
        .map(|c| c.participants.keys().copied().collect())
        .unwrap_or_default();
    for id in audience {
        session.peer_link.ensure_link(wr, id).await;
        session.peer_link.send_reliable_or_queue(
            id,
            P2pPayload::CallMute {
                call_id,
                target: own_id,
                muted,
            },
        );
    }
    Ok(())
}

/// The `EndCall` UI action (`/endcall`, or the modal's END CALL button):
/// tells every current participant we left, tears down every incoming
/// decrypt worker/mixer source, stops our own capture thread, and clears
/// both `SessionState`/`UiState`'s call bookkeeping.
///
/// Identical whoever runs it - the *host* leaving ends the call for
/// everyone, but that asymmetry lives entirely on the receiving side
/// (`on_call_end`), which is what lets one `CallEnd` mean both things
/// without the leaver having to decide which it is.
pub(crate) async fn end_own_call(
    wr: &mut impl ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(call) = session.active_call.take() else {
        return Ok(());
    };
    // Everyone we exchange audio with, plus anyone still holding an
    // invitation we sent: without that second group an unanswered invite
    // would keep offering a call that no longer exists (`on_call_end`).
    let mut peers: Vec<UserId> = call.participants.keys().copied().collect();
    for peer in ui_state.call_invitees_awaiting_answer() {
        if !peers.contains(&peer) {
            peers.push(peer);
        }
    }
    for peer in peers {
        session.peer_link.ensure_link(wr, peer).await;
        session.peer_link.send_reliable_or_queue(
            peer,
            P2pPayload::CallEnd {
                call_id: call.call_id,
            },
        );
    }
    session.active_call = Some(call);
    teardown_own_call(session, ui_state);
    Ok(())
}
