//! Live voice streaming: the generic, target-agnostic session-scoped state
//! and background workers shared by both channel and DM voice messages
//! (`crate::client::channel`/`crate::client::direct_message` only add the thin "which log
//! entry does this stream belong to" bookkeeping on top of this).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::client::session::SessionState;
use crate::client::voice;
use crate::crypto;
use crate::proto::{self, UserId};

/// How long an incoming stream can go without a chunk/end before it's
/// treated as abandoned and force-finalized with whatever partial audio
/// arrived. Without this, a dropped sender would leave the placeholder
/// blinking "streaming..." forever and leak the decrypt worker thread -
/// the server keeps no per-stream state to notify from (by design), so
/// abandonment has to be detected client-side.
pub(crate) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// How many chunks a stream with no `StreamStart` yet may buffer before
/// further ones are simply dropped - mirrors `ChunkDecryptor`'s own
/// `MAX_PENDING_CHUNKS` bounded-buffer rule for the same reason: a
/// `StreamStart` that never arrives (lost, or a hostile peer that never
/// sends one) must not let this grow without bound.
const MAX_EARLY_CHUNKS: usize = 128;
/// How many distinct `(from, stream_id)` streams may have chunks waiting
/// on a `StreamStart` at once - bounds total memory one peer could occupy
/// by racing chunks for many stream_ids that never start, not just one.
const MAX_EARLY_STREAMS: usize = 8;
/// How long a stream's early chunks are held before being dropped - well
/// beyond any plausible `StreamStart` delivery delay (one network round
/// trip, plus retransmit), so this only ever fires for a `StreamStart`
/// that is genuinely never coming.
const EARLY_CHUNK_TIMEOUT: Duration = Duration::from_secs(3);

/// What a currently-recording (our own) stream is addressed to, remembered
/// from `VoiceRecordStart` so the eventual "recording finished" report
/// (which only carries `stream_id`, `duration_ms`, and `pcm`) knows which
/// `UiState` log to finalize. `Channel`'s `recipients` is the *readiness-
/// filtered* snapshot taken at record-start - who actually received this
/// stream, needed again at finish time to fire our own `pq_hybrid`
/// rotation once per recipient (`session::request_rotation`).
pub(crate) enum OwnStreamTarget {
    Channel {
        channel: String,
        recipients: Vec<UserId>,
    },
    Direct(UserId),
    /// A recording made under an active OTP session
    /// (`client::otp::send_voice_offer`'s doc) - `spawn_record_accumulate_worker`
    /// reports through this instead of `Direct` so `own_stream_done_rx`'s
    /// handler sends it OTP-wrapped, once fully recorded, instead of
    /// treating it as an already-live-streamed clip.
    DirectOtp {
        to: UserId,
        contact_name: String,
        recipient_pubkey_der: Vec<u8>,
    },
    /// A recording destined for the OTP mail being composed
    /// (docs/PROTOCOL.md §17.1) - accumulate-only like `DirectOtp`, but
    /// nothing network-related at all: the finished PCM lands in the
    /// compose form's attachment list (`UiState::otp_mail_add_voice`).
    MailAttachment,
}

/// The once-per-stream `PqHybrid` setup: each PQ recipient's own sealed
/// `SendSetup` and the `k_data` it authorises, computed once at
/// record-start. The setup travels once, as `P2pPayload::StreamKeySetup`;
/// the chunks that follow are ciphertext only.
///
/// Unlike a text send, each recipient here gets an independent `k_data`:
/// a setup is bound to one recipient, so sharing a key across them would
/// mean sharing a binding too.
pub struct PqStreamOut {
    per_recipient: Vec<(UserId, [u8; 32], crypto::pq::SendSetup)>,
}

impl PqStreamOut {
    /// Every recipient's encoded setup, for sending as `StreamKeySetup`
    /// right after `StreamStart`.
    pub fn setups(&self) -> Vec<(UserId, Vec<u8>)> {
        self.per_recipient
            .iter()
            .filter_map(|(id, _, setup)| crate::proto::encode(setup).ok().map(|b| (*id, b)))
            .collect()
    }
}

/// Builds the once-per-stream setup for `recipients`, signed with our own
/// PQ identity. A recipient whose wrap fails (malformed public bundle) is
/// simply left out, the same partial-delivery pattern as any other
/// unreachable recipient; `None` if that leaves nobody at all.
///
/// `recipients` pairs each peer with the encoded bundle they announced -
/// used only for their identity fingerprint. What the stream is actually
/// encrypted to is their *current* rotating key
/// (`SessionState::pq_peer_keys`), so a recipient we have no current key
/// for is left out rather than encrypted to a stale one.
pub(crate) fn build_pq_stream_out(
    session: &SessionState,
    channel: Option<String>,
    stream_id: u64,
    recipients: &[(UserId, Vec<u8>)],
) -> Option<PqStreamOut> {
    if recipients.is_empty() {
        return None;
    }
    let signing = &session.own_pq_private;
    let per_recipient: Vec<(UserId, [u8; 32], crypto::pq::SendSetup)> = recipients
        .iter()
        .filter_map(|(id, public_der)| {
            let encap = session.pq_peer_keys.encap_for(*id)?;
            let fp = crypto::pq::fingerprint_of_encoded(public_der)?;
            crypto::pq::seal_setup(signing, encap, fp, channel.clone(), stream_id)
                .ok()
                .map(|(setup, k_data)| (*id, k_data, setup))
        })
        .collect();
    if per_recipient.is_empty() {
        return None;
    }
    Some(PqStreamOut { per_recipient })
}

/// What a point-to-point stream's chunks are encrypted with - a DM voice
/// stream, a file transfer, a pad transfer (`file_transfer`, `otp_pad`,
/// `voice_call`).
pub enum DirectStreamKey {
    /// Sealed to the recipient's keybundle (§13.3): every ordinary
    /// transfer, and an OTP one whose pair is `PqWrapped`. A
    /// `PqStreamOut` of exactly one recipient.
    Pq(PqStreamOut),
    /// The bytes handed to the transport are *already* one-time-pad
    /// ciphertext, so they go on the wire verbatim
    /// (`client::otp::OtpFraming::Direct`). Under `Direct` there is no
    /// keybundle to seal to and none is needed: the pad is the whole
    /// protection, and the `otp` command's own decrypt verdict is the
    /// whole authentication - it refuses anything it cannot attribute to
    /// the holder of the mirror key at the expected offset (§16.2).
    Pad,
}

impl DirectStreamKey {
    /// The `StreamKeySetup`s to send before the first chunk, if any.
    /// Empty under `Pad`: there is no per-stream key to introduce.
    pub fn setups(&self) -> Vec<(UserId, Vec<u8>)> {
        match self {
            DirectStreamKey::Pq(pq) => pq.setups(),
            DirectStreamKey::Pad => Vec::new(),
        }
    }
}

/// Who a currently-recording stream is being encrypted for, with each
/// recipient's key material already resolved once at record-start rather
/// than on every chunk.
pub(crate) enum StreamRecipients {
    Channel { pq: PqStreamOut },
    Direct { to: UserId, key: DirectStreamKey },
}

/// One chunk-decrypt job for an incoming stream's dedicated worker thread.
/// `seq` reconstructs the deterministic per-chunk AES-GCM nonce
/// (`crypto::pq::open_chunk`).
pub(crate) enum DecryptJob {
    /// A `pq_hybrid` stream's encoded `crypto::pq::SendSetup`, arriving
    /// once - nothing in the stream decrypts until it does.
    KeySetup(Vec<u8>),
    Chunk(u32, Vec<Vec<u8>>),
    /// No more chunks are coming (a real `...End` arrived, or the idle
    /// sweep gave up on this stream) - finalize with whatever plaintext
    /// was actually accumulated, rather than trusting the sender's
    /// claimed duration.
    End,
}

/// What an incoming stream's decrypt worker uses to recover each chunk's
/// plaintext - resolved once at `start_incoming_stream`. A stream
/// addressed to us was encrypted against the key material *we* announced,
/// so this is derived from our own identity, not the sender's - same
/// reasoning as `session::decrypt_envelope_for`.
pub enum IncomingStreamKey {
    /// `sender_public` verifies the stream's `StreamKeySetup` signature and
    /// `my_fp` proves the setup was sealed for *us* (`k_data` is then cached
    /// for the rest of the stream - see `spawn_stream_decrypt_worker`).
    ///
    /// `my_decaps` is the snapshot of candidate decryption keys taken at
    /// stream start (`pq_rekey::PqOwnKeys::candidates_for`), not a single
    /// key: a stream begun just before we rotate must still open, which is
    /// what the retention window is for.
    Pq {
        my_decaps: Vec<crypto::pq::PqDecapKeys>,
        my_fp: [u8; 32],
        sender_public: crypto::pq::PqPublicBundle,
    },
    /// This stream's chunks are one-time-pad ciphertext carried verbatim
    /// (`client::otp::OtpFraming::Direct`) - the counterpart of
    /// `DirectStreamKey::Pad`. Each chunk passes through untouched; the
    /// reassembled whole is what `otp --decrypt` then opens, which is
    /// also what authenticates it (§16.2).
    Pad,
    /// The sender announced a keybundle that does not decode, so nothing
    /// in this stream can ever be opened. Kept as a state rather than
    /// refusing the stream outright so the arriving rows behave exactly
    /// like a stream whose chunks all fail their AEAD tag.
    Undecryptable,
}

/// Bookkeeping for one currently-arriving incoming stream.
pub(crate) struct ActiveStream {
    pub(crate) job_tx: tokio::sync::mpsc::UnboundedSender<DecryptJob>,
    /// `Some(channel)` for a channel stream, `None` for a DM.
    pub(crate) channel: Option<String>,
    pub(crate) last_seen: Instant,
    /// Whether the idle sweep has already asked this stream's worker to
    /// end (`IdleStreamAction`). One ask is all there is to make: a worker
    /// that took it reports back and the entry goes with it, so a stream
    /// still here afterwards is one whose worker is not answering.
    pub(crate) end_requested: bool,
}

pub(crate) struct PendingChunks {
    chunks: Vec<(u32, Vec<Vec<u8>>)>,
    first_seen: Instant,
}

/// Holds voice chunks that outran their own `StreamStart` - `Chunk` travels
/// unreliable UDP while `StreamStart` travels the reliable channel
/// (`docs/PROTOCOL.md` §7.3), and both cross the same socket, so nothing
/// guarantees the reliable one is *processed* first even though it is
/// always sent first. For an ordinary multi-second recording this is
/// harmless - the stream self-heals once `StreamStart` catches up a moment
/// later - but a recording short enough to finish (and send `StreamEnd`)
/// before `StreamStart` is processed would otherwise lose every chunk it
/// ever sent, since `StreamEnd` is on the same reliable, in-order channel
/// as `StreamStart` and so is guaranteed to finalize the stream
/// immediately after it starts. `take` replays whatever is held, in
/// arrival order, the moment that `StreamStart` lands.
///
/// Keyed by `(from, stream_id)` exactly like `active_streams` - never by
/// `stream_id` alone, since it is only unique per sender - so one peer's
/// buffered chunks can never be released by another peer's `StreamStart`:
/// `from` here is always the already-authenticated peer a punched link
/// resolved the datagram to, never a claim read out of the datagram
/// itself. Bounded two ways (`MAX_EARLY_CHUNKS` per stream,
/// `MAX_EARLY_STREAMS` distinct streams at once) and aged out by `sweep`
/// on `EARLY_CHUNK_TIMEOUT`, so a `StreamStart` that never arrives - lost,
/// or a hostile peer that never sends one - cannot grow this without
/// limit.
pub struct PendingChunkBuffer {
    streams: HashMap<(UserId, u64), PendingChunks>,
}

impl Default for PendingChunkBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingChunkBuffer {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Buffers one chunk for `(from, stream_id)` - dropped instead if
    /// that stream is already at `MAX_EARLY_CHUNKS`, or starting it would
    /// exceed `MAX_EARLY_STREAMS` distinct streams waiting at once.
    pub fn push(&mut self, from: UserId, stream_id: u64, seq: u32, blocks: Vec<Vec<u8>>) {
        let key = (from, stream_id);
        if !self.streams.contains_key(&key) {
            if self.streams.len() >= MAX_EARLY_STREAMS {
                return;
            }
            self.streams.insert(
                key,
                PendingChunks {
                    chunks: Vec::new(),
                    first_seen: Instant::now(),
                },
            );
        }
        if let Some(pending) = self.streams.get_mut(&key) {
            if pending.chunks.len() < MAX_EARLY_CHUNKS {
                pending.chunks.push((seq, blocks));
            }
        }
    }

    /// Removes and returns whatever is buffered for `(from, stream_id)`,
    /// in arrival order - empty if nothing was waiting. Called once when
    /// that stream's `StreamStart` lands.
    pub fn take(&mut self, from: UserId, stream_id: u64) -> Vec<(u32, Vec<Vec<u8>>)> {
        self.streams
            .remove(&(from, stream_id))
            .map(|p| p.chunks)
            .unwrap_or_default()
    }

    /// Drops any buffer that has waited longer than `EARLY_CHUNK_TIMEOUT`
    /// for a `StreamStart` that never came.
    pub fn sweep(&mut self, now: Instant) {
        self.streams.retain(|_, pending| {
            now.saturating_duration_since(pending.first_seen) < EARLY_CHUNK_TIMEOUT
        });
    }
}

/// What the idle sweep should do about one incoming stream that has gone
/// quiet (`session::run_connected_session`'s ticker).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleStreamAction {
    /// Still within its idle window, or already asked and its worker is
    /// still there to answer.
    Wait,
    /// Quiet past `STREAM_IDLE_TIMEOUT` and not yet asked: tell the worker
    /// to end, so it finalizes the row with whatever partial audio
    /// arrived.
    Nudge,
    /// Asked, and the worker is gone without ever answering. Nothing else
    /// will ever finalize this row, so the sweep closes it out itself -
    /// otherwise the placeholder blinks "streaming..." for the rest of the
    /// session and the entry leaks.
    GiveUp,
}

/// The decision above, as a function of the three things it depends on -
/// so the sweep's rule can be exercised without a socket, a worker thread
/// or an audio device.
pub fn idle_stream_action(
    now: Instant,
    last_seen: Instant,
    end_requested: bool,
    worker_alive: bool,
) -> IdleStreamAction {
    if now.saturating_duration_since(last_seen) < STREAM_IDLE_TIMEOUT {
        return IdleStreamAction::Wait;
    }
    if !end_requested {
        return IdleStreamAction::Nudge;
    }
    if worker_alive {
        IdleStreamAction::Wait
    } else {
        IdleStreamAction::GiveUp
    }
}

/// Encrypts one chunk of `pcm` for every recipient of `target`: cheap
/// AES-256-GCM under the stream's already-established `k_data`
/// (`crypto::pq::seal_chunk`), with no asymmetric crypto per chunk. Each
/// recipient's "blocks" is the single sealed blob.
fn build_chunk_recipients(
    target: &StreamRecipients,
    stream_id: u64,
    seq: u32,
    pcm: &[u8],
) -> Vec<(UserId, Vec<Vec<u8>>)> {
    match target {
        StreamRecipients::Channel { pq } => pq
            .per_recipient
            .iter()
            .map(|(id, k_data, _)| {
                (
                    *id,
                    vec![crypto::pq::seal_chunk(k_data, stream_id, seq, pcm)],
                )
            })
            .collect(),
        StreamRecipients::Direct { to, key } => encrypt_direct_chunk(key, stream_id, seq, pcm)
            .map(|blocks| vec![(*to, blocks)])
            .unwrap_or_default(),
    }
}

/// One recipient's worth of `build_chunk_recipients`' `Direct` arm, pulled
/// out so `file_transfer`'s sending worker can reuse it without
/// duplicating it - a file transfer is always a single `DirectStreamKey`
/// recipient (`docs/PROTOCOL.md`'s file transfer section), same shape as a
/// DM voice stream.
pub fn encrypt_direct_chunk(
    key: &DirectStreamKey,
    stream_id: u64,
    seq: u32,
    data: &[u8],
) -> Option<Vec<Vec<u8>>> {
    match key {
        DirectStreamKey::Pq(pq) => {
            let (_, k_data, _) = pq.per_recipient.first()?;
            Some(vec![crypto::pq::seal_chunk(k_data, stream_id, seq, data)])
        }
        // Already pad ciphertext - sealing it again would buy nothing and
        // needs a keybundle this pair does not have.
        DirectStreamKey::Pad => Some(vec![data.to_vec()]),
    }
}

/// Every `UserId` a stream's `target` addresses - every recipient of a
/// channel stream, the single recipient for a DM. Used at
/// `*End` time to fan `P2pOutbound::VoiceEnd` out to the same recipient set
/// `*Start` reached: the stream travels peer to peer (`docs/PROTOCOL.md`
/// §7.1), so there is no membership list on the receiving end to derive it
/// from.
fn stream_recipient_ids(target: &StreamRecipients) -> Vec<UserId> {
    match target {
        StreamRecipients::Channel { pq } => pq.per_recipient.iter().map(|(id, ..)| *id).collect(),
        StreamRecipients::Direct { to, .. } => vec![*to],
    }
}

/// Runs on a dedicated `std::thread` for one recording: every
/// `voice::CHUNK_INTERVAL`, flushes captured samples, encrypts them per
/// recipient, and hands a ready-to-send `P2pOutbound` to the main loop -
/// no crypto ever runs on the async select loop. `stop_rx.recv_timeout`
/// doubles as sleep and wake-on-release signal (tokio channels have no
/// blocking-with-timeout usable from a plain thread), which also means
/// release is reflected almost instantly.
/// Applies `mode` to one captured chunk, in place. Shared by both record
/// workers so a voice message ducks exactly the way a call does.
///
/// Under `Auto` the probe is fed the level of what was captured *before*
/// any attenuation - see `voice::EchoProbe`, where getting that backwards
/// is the difference between a decision and a feedback loop.
fn duck_capture(
    pending: &mut [i16],
    mode: crate::settings::EchoDucking,
    ducker: &mut voice::EchoDucker,
    probe: &mut voice::EchoProbe,
) {
    if pending.is_empty() {
        return;
    }
    let playback = voice::playback_level();
    let duck = match mode {
        crate::settings::EchoDucking::Off => false,
        crate::settings::EchoDucking::On => true,
        crate::settings::EchoDucking::Auto => {
            probe.observe(voice::level_from_pcm(pending), playback);
            probe.should_duck()
        }
    };
    if duck {
        ducker.process(pending, playback);
    }
}

/// Which ducking mode a recording should actually run under, given the
/// device it is being captured from.
///
/// A capture device that cancels echo itself makes `voice::EchoDucker`
/// redundant, and its attenuation is then pure cost to full duplex - so a
/// cancelling device always wins over whatever the setting says. Every
/// place that opens a `Recorder` asks this rather than re-deriving it:
/// voice messages (channel and DM), the OTP accumulate path, and live
/// calls all capture through the same microphone under the same rule.
pub(crate) fn effective_echo_ducking(
    recorder: &voice::Recorder,
    configured: crate::settings::EchoDucking,
) -> crate::settings::EchoDucking {
    if recorder.echo_cancelled() {
        crate::settings::EchoDucking::Off
    } else {
        configured
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_record_stream_worker(
    recorder: voice::Recorder,
    target: StreamRecipients,
    stream_id: u64,
    out_tx: tokio::sync::mpsc::UnboundedSender<crate::client::p2p::P2pOutbound>,
    done_tx: tokio::sync::mpsc::UnboundedSender<(u64, u32, Vec<u8>)>,
    stop_rx: std::sync::mpsc::Receiver<()>,
    // Notified (once) if this recording stops itself on reaching
    // `voice::MAX_RECORDING_SAMPLES`, rather than via an explicit Space/
    // global-shortcut release - the main loop uses this to reset the
    // recording indicator and play the end chime immediately, the same as
    // any other stop, instead of leaving the UI claiming to still be
    // recording until the next release event.
    auto_stop_tx: tokio::sync::mpsc::UnboundedSender<()>,
    // `settings::Settings::voice_echo_ducking` - see `voice::EchoDucker`
    // and, under `Auto`, `voice::EchoProbe`.
    echo_ducking: crate::settings::EchoDucking,
) {
    std::thread::spawn(move || {
        let mut seq: u32 = 0;
        let mut total_samples: u64 = 0;
        let mut plaintext_accum: Vec<u8> = Vec::new();
        let mut ducker = voice::EchoDucker::new();
        let mut probe = voice::EchoProbe::new();

        loop {
            let mut stopped = match stop_rx.recv_timeout(voice::CHUNK_INTERVAL) {
                Ok(()) => true,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
            };

            let mut pending = recorder.take_pending();
            if !pending.is_empty() {
                // Recording a voice message while someone else's audio is
                // coming out of the speakers otherwise captures it and
                // sends it back to them - the same echo path a call has,
                // for the same reason.
                duck_capture(&mut pending, echo_ducking, &mut ducker, &mut probe);
                total_samples += pending.len() as u64;
                // The accumulated clip stays PCM (it becomes the replayable
                // message); only what goes on the wire is coded.
                plaintext_accum.extend_from_slice(&voice::pcm_to_bytes(&pending));

                let coded = voice::encode_voice_chunk(&pending);
                let per_recipient = build_chunk_recipients(&target, stream_id, seq, &coded);
                let msg = match &target {
                    StreamRecipients::Channel { .. } => {
                        Some(crate::client::p2p::P2pOutbound::ChannelVoiceChunk {
                            stream_id,
                            seq,
                            per_recipient,
                        })
                    }
                    StreamRecipients::Direct { to, .. } => {
                        per_recipient.into_iter().next().map(|(_, blocks)| {
                            crate::client::p2p::P2pOutbound::DirectVoiceChunk {
                                to: *to,
                                stream_id,
                                seq,
                                blocks,
                            }
                        })
                    }
                };
                if let Some(msg) = msg {
                    let _ = out_tx.send(msg);
                }
                seq += 1;
            }

            // Hard cap: stop as if Space had just been released, but only
            // if nothing already requested a stop this tick - an explicit
            // release racing the cap on the same `CHUNK_INTERVAL` tick is
            // just an ordinary stop, no separate notification needed.
            if !stopped && voice::recording_at_max(total_samples) {
                stopped = true;
                let _ = auto_stop_tx.send(());
            }

            if stopped {
                let duration_ms = voice::duration_ms_of(total_samples);
                let recipients = stream_recipient_ids(&target);
                let _ = out_tx.send(crate::client::p2p::P2pOutbound::VoiceEnd {
                    stream_id,
                    duration_ms,
                    recipients,
                });
                let _ = done_tx.send((stream_id, duration_ms, plaintext_accum));
                break; // `recorder` drops here, closing the input stream.
            }
        }
    });
}

/// OTP counterpart of `spawn_record_stream_worker`: no live network sends,
/// no per-recipient key material - it purely accumulates the recording
/// (same `CHUNK_INTERVAL` polling and `MAX_RECORDING_SAMPLES` cap) and
/// reports the finished PCM once stopped, via the exact same `done_tx`
/// shape `spawn_record_stream_worker` uses. Voice under OTP isn't
/// live-streamed at all (`client::otp::send_voice_offer`'s doc): it's
/// recorded fully, encrypted whole, and only sent once recording stops.
pub(crate) fn spawn_record_accumulate_worker(
    recorder: voice::Recorder,
    stream_id: u64,
    done_tx: tokio::sync::mpsc::UnboundedSender<(u64, u32, Vec<u8>)>,
    stop_rx: std::sync::mpsc::Receiver<()>,
    auto_stop_tx: tokio::sync::mpsc::UnboundedSender<()>,
    // As `spawn_record_stream_worker` - a recording made under OTP, or for
    // a mail attachment, is captured through the same microphone while the
    // same speakers are playing.
    echo_ducking: crate::settings::EchoDucking,
) {
    std::thread::spawn(move || {
        let mut total_samples: u64 = 0;
        let mut plaintext_accum: Vec<u8> = Vec::new();
        let mut ducker = voice::EchoDucker::new();
        let mut probe = voice::EchoProbe::new();

        loop {
            let mut stopped = match stop_rx.recv_timeout(voice::CHUNK_INTERVAL) {
                Ok(()) => true,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
            };

            let mut pending = recorder.take_pending();
            if !pending.is_empty() {
                duck_capture(&mut pending, echo_ducking, &mut ducker, &mut probe);
                total_samples += pending.len() as u64;
                plaintext_accum.extend_from_slice(&voice::pcm_to_bytes(&pending));
            }

            if !stopped && voice::recording_at_max(total_samples) {
                stopped = true;
                let _ = auto_stop_tx.send(());
            }

            if stopped {
                let duration_ms = voice::duration_ms_of(total_samples);
                let _ = done_tx.send((stream_id, duration_ms, plaintext_accum));
                break; // `recorder` drops here, closing the input stream.
            }
        }
    });
}

/// Decrypts successive chunks of one incoming stream/transfer, keyed once
/// at start (`resolve_incoming_key`) - shared by voice's
/// `spawn_stream_decrypt_worker` and `file_transfer`'s receive worker so the
/// RSA-candidates-retry / PQ-`k_data`-cache-from-first-chunk logic isn't
/// duplicated between them.
/// How many chunks of a not-yet-set-up stream are held before the rest are
/// dropped. Voice chunks travel unreliably and can outrun the reliable
/// `StreamKeySetup` they belong to, so a handful must be able to wait; a
/// stream whose setup never arrives at all must not grow without bound.
/// Mirrors `p2p_reliable::ArqReceiver`'s own bounded-buffer rule.
const MAX_PENDING_CHUNKS: usize = 128;

pub struct ChunkDecryptor {
    key: IncomingStreamKey,
    // `PqHybrid` only: the stream's `k_data`, recovered and
    // signature-verified once from its `StreamKeySetup`
    // (`crypto::pq::open_setup`) and cached here - every chunk after that
    // only pays for cheap AES-256-GCM, never re-verifying or re-unwrapping.
    pq_k_data: Option<[u8; 32]>,
    // Chunks that arrived before the setup did, replayed in arrival order
    // once it lands. Empty for an RSA stream, which needs no setup.
    pending: Vec<(u32, Vec<Vec<u8>>)>,
}

impl ChunkDecryptor {
    pub fn new(key: IncomingStreamKey) -> Self {
        Self {
            key,
            pq_k_data: None,
            pending: Vec::new(),
        }
    }

    /// Verifies and installs a `pq_hybrid` stream's setup, returning the
    /// chunks that had been waiting on it (already decrypted, in arrival
    /// order). `None` if the setup fails to verify - a stream whose setup
    /// isn't authentic decrypts nothing at all, the same fail-closed
    /// behaviour as a bad signature on a text message.
    pub fn install_setup(&mut self, stream_id: u64, blob: &[u8]) -> Option<Vec<(u32, Vec<u8>)>> {
        let IncomingStreamKey::Pq {
            my_decaps,
            my_fp,
            sender_public,
        } = &self.key
        else {
            return None;
        };
        let setup: crypto::pq::SendSetup = proto::decode(blob).ok()?;
        if setup.binding.send_id != stream_id {
            return None;
        }
        let k_data = crypto::pq::open_setup(my_decaps, my_fp, sender_public, &setup)?;
        self.pq_k_data = Some(k_data);

        let waiting = std::mem::take(&mut self.pending);
        Some(
            waiting
                .into_iter()
                .filter_map(|(seq, blocks)| {
                    self.decrypt(stream_id, seq, &blocks).map(|pt| (seq, pt))
                })
                .collect(),
        )
    }

    /// Decrypts one chunk's `blocks`, `None` on any failure (wrong/stale
    /// key, corrupted chunk, bad AEAD tag, or - for `pq_hybrid` - a setup
    /// that hasn't arrived yet, in which case the chunk is held for
    /// `install_setup` to replay).
    pub fn decrypt(&mut self, stream_id: u64, seq: u32, blocks: &[Vec<u8>]) -> Option<Vec<u8>> {
        match &self.key {
            IncomingStreamKey::Pad => blocks.first().cloned(),
            IncomingStreamKey::Undecryptable => None,
            IncomingStreamKey::Pq { .. } => {
                let blob = blocks.first()?;
                let Some(k_data) = self.pq_k_data else {
                    if self.pending.len() < MAX_PENDING_CHUNKS {
                        self.pending.push((seq, blocks.to_vec()));
                    }
                    return None;
                };
                crypto::pq::open_chunk(&k_data, stream_id, seq, blob)
            }
        }
    }
}

/// Runs on a dedicated thread for the lifetime of one incoming stream -
/// each stream gets its own, rather than sharing one decrypt thread across
/// every incoming stream, because unwrap+AEAD is meaningfully costlier
/// than the sender's own encrypt: a single shared thread would start
/// lagging behind real time with just two or three simultaneous incoming
/// streams.
pub(crate) fn spawn_stream_decrypt_worker(
    key: IncomingStreamKey,
    mixer_tx: tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>,
    mixer_id: u64,
    from: UserId,
    stream_id: u64,
    // Snapshotted once at `*Start` (docs/PROTOCOL.md §11.2/§12): a
    // Pending/Rejected sender's audio is still decrypted and accumulated
    // (needed for the eventual `Voice` entry once revealed), just never
    // forwarded to the mixer, so nothing is heard live from someone not
    // yet trusted.
    suppress_playback: bool,
    finished_tx: tokio::sync::mpsc::UnboundedSender<(UserId, u64, u32, Vec<u8>)>,
) -> tokio::sync::mpsc::UnboundedSender<DecryptJob> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DecryptJob>();
    std::thread::spawn(move || {
        let mut plaintext_accum: Vec<u8> = Vec::new();
        let mut decryptor = ChunkDecryptor::new(key);
        // Accumulates one decrypted chunk and reports whether the stream has
        // hit its own length cap. Shared by chunks that decrypt on arrival
        // and chunks replayed out of `install_setup`'s backlog, so both
        // paths enforce the cap identically.
        let accept_pcm = |chunk: Vec<u8>, plaintext_accum: &mut Vec<u8>| -> bool {
            // Wire chunks are `voice::VOICE_CODEC_ADPCM`, not raw PCM
            // (docs/PROTOCOL.md 7.3). Decoded once here, before either
            // consumer: the accumulated clip is PCM, the same as every
            // other recording this app keeps, so replay/export/OTP voice
            // stay untouched by how a live chunk happens to travel. An
            // undecodable chunk is dropped rather than treated as audio -
            // this is network input.
            let Some(samples) = voice::decode_voice_chunk(&chunk) else {
                return false;
            };
            plaintext_accum.extend_from_slice(&voice::pcm_to_bytes(&samples));
            if !suppress_playback {
                let _ = mixer_tx.send(voice::MixerCmd::PushLive {
                    id: mixer_id,
                    samples,
                });
            }
            // Defense in depth (§7.3): never accept more than
            // `voice::MAX_RECORDING_SAMPLES` per stream regardless of the
            // sender's own cap - force-finalize as if a real `*End` had
            // arrived.
            voice::recording_at_max((plaintext_accum.len() / 2) as u64)
        };
        while let Some(job) = rx.blocking_recv() {
            match job {
                DecryptJob::KeySetup(blob) => {
                    let mut at_max = false;
                    if let Some(waiting) = decryptor.install_setup(stream_id, &blob) {
                        for (_, pcm) in waiting {
                            if accept_pcm(pcm, &mut plaintext_accum) {
                                at_max = true;
                                break;
                            }
                        }
                    }
                    if at_max {
                        let duration_ms =
                            voice::duration_ms_of((plaintext_accum.len() / 2) as u64);
                        let _ = mixer_tx.send(voice::MixerCmd::Finish { id: mixer_id });
                        let _ = finished_tx.send((from, stream_id, duration_ms, plaintext_accum));
                        break;
                    }
                }
                DecryptJob::Chunk(seq, blocks) => {
                    let pcm = decryptor.decrypt(stream_id, seq, &blocks);
                    if let Some(pcm) = pcm {
                        if accept_pcm(pcm, &mut plaintext_accum) {
                            let duration_ms =
                                voice::duration_ms_of((plaintext_accum.len() / 2) as u64);
                            let _ = mixer_tx.send(voice::MixerCmd::Finish { id: mixer_id });
                            let _ =
                                finished_tx.send((from, stream_id, duration_ms, plaintext_accum));
                            break;
                        }
                    }
                }
                DecryptJob::End => {
                    let duration_ms = voice::duration_ms_of((plaintext_accum.len() / 2) as u64);
                    let _ = mixer_tx.send(voice::MixerCmd::Finish { id: mixer_id });
                    let _ = finished_tx.send((from, stream_id, duration_ms, plaintext_accum));
                    break;
                }
            }
        }
    });
    tx
}

/// Plays one bundled chime through the mixer under a fresh source id -
/// the same `Push`+`Finish` pair `ReplayVoice` uses for a recording, since
/// a chime is just a very short one. Silent (and free) when the asset
/// failed to decode, which is what an empty sample set means.
///
/// The three named chimes below are the whole call surface; this exists so
/// they differ in nothing but which asset they play.
fn play_chime(session: &mut SessionState, samples: Vec<i16>) {
    if samples.is_empty() {
        return;
    }
    let id = session.next_mixer_id;
    session.next_mixer_id += 1;
    let _ = session.mixer_tx.send(voice::MixerCmd::Push { id, samples });
    let _ = session.mixer_tx.send(voice::MixerCmd::Finish { id });
}

/// The "message ended" chime - on the sender's release of Space and on an
/// incoming stream's completion, so both ends of a voice message get the
/// same audible cue.
///
/// Silent while `roger_beep=off` (`settings::Settings::roger_beep`). That
/// switch, not `sound_notifications`, is the one that owns this sound:
/// it punctuates speech rather than announcing an event.
pub(crate) fn play_end_chime(session: &mut SessionState) {
    if !session.roger_beep {
        return;
    }
    play_chime(session, voice::end_chime_samples());
}

/// The incoming-file-offer notification sound - played whenever a new
/// file-offer popup becomes the one shown (`docs/PROTOCOL.md`'s file
/// transfer section).
///
/// Silent while `sound_notifications=off`, like every other event sound.
pub(crate) fn play_bell_chime(session: &mut SessionState) {
    if !session.sound_notifications {
        return;
    }
    play_chime(session, voice::bell_chime_samples());
}

/// The daemon's "someone you are focused on is here" sound (`docs/SPEC.md`
/// "Daemon mode"). Only ever called with a daemon plan in effect.
///
/// Silent while `sound_notifications=off`, like every other event sound.
pub(crate) fn play_joined_chime(session: &mut SessionState) {
    if !session.sound_notifications {
        return;
    }
    play_chime(session, voice::joined_chime_samples());
}

/// The "someone wrote `@<your nickname>`" sound (`docs/SPEC.md`
/// Functionality #33) - played once per arriving channel/DM text message
/// that mentions this client's own nickname
/// (`UiState::message_mentions_me`).
///
/// Silent while `sound_notifications=off`, like every other event sound.
pub(crate) fn play_ping_chime(session: &mut SessionState) {
    if !session.sound_notifications {
        return;
    }
    play_chime(session, voice::ping_chime_samples());
}

/// Resolves one recipient's outgoing key material for a point-to-point
/// stream - shared by `channel`/`direct_message`'s `handle_send_file`.
/// A resolution failure is just `None` and the caller silently excludes
/// that recipient, like any other partial-delivery case - a file send has
/// no single "recording" UI element for a failure reason to attach to the
/// way voice's `audio_error` does.
pub(crate) fn resolve_direct_key(
    session: &SessionState,
    stream_id: u64,
    to: UserId,
    recipient_pubkey_der: &[u8],
) -> Option<DirectStreamKey> {
    // A direct stream belongs to no channel - the same binding a DM text
    // message carries, and what keeps it out of one.
    build_pq_stream_out(
        session,
        None,
        stream_id,
        &[(to, recipient_pubkey_der.to_vec())],
    )
    .map(DirectStreamKey::Pq)
}

/// Resolves which key to try for an incoming stream/transfer from `from`.
/// A stream addressed to us was encrypted against what *we* announced, so
/// this is derived from our own rotating keys; `sender_public_key_der`
/// verifies the once-per-stream signature. Shared by voice and file
/// transfer, both snapshotting once at start rather than per chunk.
pub(crate) fn resolve_incoming_key(
    session: &SessionState,
    from: UserId,
    sender_public_key_der: &[u8],
) -> IncomingStreamKey {
    match proto::decode(sender_public_key_der) {
        Ok(sender_public) => IncomingStreamKey::Pq {
            my_decaps: session.own_pq_keys.candidates_for(from),
            my_fp: session.own_pq_fp,
            sender_public,
        },
        // A malformed sender key leaves nothing decryptable, so every
        // chunk simply fails below rather than crashing anything.
        Err(_) => IncomingStreamKey::Undecryptable,
    }
}

pub(crate) fn start_incoming_stream(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    channel: Option<String>,
    suppress_playback: bool,
    // The sender's announced `UserInfo.public_key_der`, used to verify the
    // once-per-stream signature. Passed as raw bytes rather than requiring
    // a full `UserInfo` here so callers already holding just the field
    // don't need to reconstruct one.
    sender_public_key_der: &[u8],
) {
    let mixer_id = session.next_mixer_id;
    session.next_mixer_id += 1;
    // The whole stream stays on one key snapshot (PROTOCOL.md §11.2), so
    // this is resolved once here rather than per chunk.
    let key = resolve_incoming_key(session, from, sender_public_key_der);
    let job_tx = spawn_stream_decrypt_worker(
        key,
        session.mixer_tx.clone(),
        mixer_id,
        from,
        stream_id,
        suppress_playback,
        session.stream_finished_tx.clone(),
    );
    session.active_streams.insert(
        (from, stream_id),
        ActiveStream {
            job_tx: job_tx.clone(),
            channel,
            last_seen: Instant::now(),
            end_requested: false,
        },
    );
    // Replay, in arrival order, anything that outran this `StreamStart` -
    // see `PendingChunkBuffer`'s doc for why that can happen at all.
    for (seq, blocks) in session.pending_stream_chunks.take(from, stream_id) {
        let _ = job_tx.send(DecryptJob::Chunk(seq, blocks));
    }
}

pub(crate) fn forward_chunk(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    seq: u32,
    blocks: Vec<Vec<u8>>,
) {
    if let Some(s) = session.active_streams.get_mut(&(from, stream_id)) {
        s.last_seen = Instant::now();
        let _ = s.job_tx.send(DecryptJob::Chunk(seq, blocks));
        return;
    }
    session
        .pending_stream_chunks
        .push(from, stream_id, seq, blocks);
}

/// Hands a `pq_hybrid` stream's key setup to its decrypt worker. Like
/// `forward_chunk`, a setup for a stream we never started (or already
/// finished) is simply dropped.
pub(crate) fn forward_key_setup(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    setup: Vec<u8>,
) {
    if let Some(s) = session.active_streams.get_mut(&(from, stream_id)) {
        s.last_seen = Instant::now();
        let _ = s.job_tx.send(DecryptJob::KeySetup(setup));
        return;
    }
    // `StreamKeySetup` is shared wire framing for any pq_hybrid stream, not
    // just voice (`p2p_proto::P2pPayload::StreamKeySetup`'s doc) - a file
    // transfer's own `ChunkDecryptor` needs it applied exactly the same
    // way, or its `pq_k_data` never gets set and every chunk sits in
    // `ChunkDecryptor::pending` forever, silently, since nothing ever
    // replays it. `next_stream_id` is one shared per-connection counter
    // (never per-kind), so a given `(from, stream_id)` can only ever be a
    // live entry in one of these two maps at a time - checking the second
    // only when the first misses is unambiguous, not a fallback guess.
    if let Some(t) = session.active_file_transfers.get_mut(&(from, stream_id)) {
        t.last_seen = Instant::now();
        let _ = t.job_tx.send(DecryptJob::KeySetup(setup));
    }
}

pub(crate) fn end_incoming_stream(session: &mut SessionState, from: UserId, stream_id: u64) {
    if let Some(s) = session.active_streams.get_mut(&(from, stream_id)) {
        s.last_seen = Instant::now();
        let _ = s.job_tx.send(DecryptJob::End);
    }
}
