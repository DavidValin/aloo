//! Live voice streaming: the generic, target-agnostic session-scoped state
//! and background workers shared by both channel and DM voice messages
//! (`crate::channel`/`crate::direct_message` only add the thin "which log
//! entry does this stream belong to" bookkeeping on top of this).

use std::time::{Duration, Instant};

use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::crypto;
use crate::proto::{self, KeyMode, UserId};
use crate::session::SessionState;
use crate::voice;

/// How long an incoming stream can go without a chunk/end before it's
/// treated as abandoned (e.g. the sender disconnected mid-recording) and
/// force-finalized with whatever partial audio arrived. Without this, a
/// dropped sender would leave the receiver's placeholder blinking
/// "streaming..." forever and leak the decrypt worker thread - the server
/// has no per-stream state of its own to notify from (by design, see
/// `server.rs`), so this has to be detected client-side.
pub(crate) const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// What a currently-recording (our own) stream is addressed to, remembered
/// from `VoiceRecordStart` so the eventual "recording finished" report
/// (which only carries `stream_id`, `duration_ms`, and `pcm`) knows which
/// `UiState` log to finalize. `Channel`'s `recipients` is the *readiness-
/// filtered* snapshot taken at record-start (PROTOCOL.md §11.6) - who
/// actually received this stream, needed again at finish time to fire our
/// own per-peer rotation (`rekey::OwnKeys`) once per recipient.
pub(crate) enum OwnStreamTarget {
    Channel { channel: String, recipients: Vec<UserId> },
    Direct(UserId),
}

/// The recipient-independent, once-per-stream `PqHybrid` setup: a fresh
/// `k_data` plus each PQ recipient's key-wrap+signature
/// (`crypto::pq::HybridStreamKeySetup`), computed once at record-start
/// (mirrors the RSA path's "recipients' public keys parsed once at
/// record-start", `docs/PROTOCOL.md` §7.3/§11.6) and repeated verbatim in
/// every chunk sent to that recipient - see `HybridStreamKeySetup`'s doc
/// for the accepted bandwidth tradeoff.
pub(crate) struct PqStreamOut {
    k_data: [u8; 32],
    per_recipient: Vec<(UserId, crypto::pq::HybridStreamKeySetup)>,
}

/// Builds the once-per-stream `PqHybrid` setup for `recipients` (already
/// filtered to `KeyMode::PqHybrid` peers - see `channel::parse_pq_recipients`),
/// signed with our own PQ identity (`session.own_pq_private` - `None` if we
/// aren't ourselves `PqHybrid`, in which case there's nothing to build:
/// `channel::can_address` already excludes `PqHybrid` recipients for a
/// non-`PqHybrid` sender before this is ever called). A recipient whose
/// wrap fails (malformed public bundle) is simply left out, same
/// partial-delivery pattern as an RSA recipient with an unparseable key.
pub(crate) fn build_pq_stream_out(
    session: &SessionState,
    stream_id: u64,
    recipients: &[(UserId, crypto::pq::PqPublicBundle)],
) -> Option<PqStreamOut> {
    if recipients.is_empty() {
        return None;
    }
    let signing = session.own_pq_private.as_ref()?;
    let k_data = crypto::pq::fresh_data_key();
    let per_recipient: Vec<(UserId, crypto::pq::HybridStreamKeySetup)> = recipients
        .iter()
        .filter_map(|(id, public)| crypto::pq::wrap_key_for_stream(signing, public, stream_id, &k_data).ok().map(|s| (*id, s)))
        .collect();
    if per_recipient.is_empty() {
        return None;
    }
    Some(PqStreamOut { k_data, per_recipient })
}

/// A DM voice stream's single recipient is either RSA-family or `PqHybrid`
/// - unlike a channel, never a mix (there's only one recipient).
pub(crate) enum DirectStreamKey {
    Rsa(RsaPublicKey),
    Pq(PqStreamOut),
}

/// Who a currently-recording stream is being encrypted for, with each
/// recipient's key material already resolved once at record-start rather
/// than on every chunk. A channel stream can address a mix of RSA-family
/// and `PqHybrid` recipients at once - each gets whichever scheme their own
/// `KeyMode` needs, independent of the others (`docs/PROTOCOL.md` §13).
pub(crate) enum StreamRecipients {
    Channel { rsa: Vec<(UserId, RsaPublicKey)>, pq: Option<PqStreamOut> },
    Direct { to: UserId, key: DirectStreamKey },
}

/// One chunk-decrypt job for an incoming stream's dedicated worker thread.
/// `seq` is only needed by the `PqHybrid` path (reconstructing the
/// deterministic per-chunk AES-GCM nonce, `crypto::pq::decrypt_hybrid_chunk`)
/// - carried for every chunk regardless of scheme rather than only when
/// relevant, since a worker doesn't know its own scheme until it inspects
/// its `IncomingStreamKey`.
pub(crate) enum DecryptJob {
    Chunk(u32, Vec<Vec<u8>>),
    /// No more chunks are coming (a real `...End` arrived, or the idle
    /// sweep gave up on this stream) - finalize with whatever plaintext
    /// was actually accumulated, rather than trusting the sender's
    /// claimed duration.
    End,
}

/// What an incoming stream's decrypt worker uses to recover each chunk's
/// plaintext - resolved once at `start_incoming_stream`, based on *our own*
/// `session.own_key_mode` (a stream addressed to us was necessarily
/// encrypted against whichever public key material *we* announced,
/// regardless of the sender's own `my_key` - same reasoning as
/// `session::decrypt_envelope_for`).
pub(crate) enum IncomingStreamKey {
    Rsa(Vec<RsaPrivateKey>),
    /// `sender_public` is needed to verify the once-per-stream signature
    /// inside the first `HybridStreamKeySetup` seen (`k_data` is then
    /// cached for the rest of the stream - see `spawn_stream_decrypt_worker`).
    Pq { my_private: crypto::pq::PqPrivateBundle, sender_public: crypto::pq::PqPublicBundle },
}

/// Bookkeeping for one currently-arriving incoming stream.
pub(crate) struct ActiveStream {
    pub(crate) job_tx: tokio::sync::mpsc::UnboundedSender<DecryptJob>,
    /// `Some(channel)` for a channel stream, `None` for a DM.
    pub(crate) channel: Option<String>,
    pub(crate) last_seen: Instant,
}

/// Encrypts one chunk of `pcm` for every recipient of `target`, dispatching
/// per recipient by scheme - RSA-OAEP direct-encrypt (as ever) or, for a
/// `PqStreamOut`'s recipients, cheap AES-256-GCM under the stream's already-
/// established `k_data` (`crypto::pq::encrypt_hybrid_voice_chunk`, no
/// asymmetric crypto per chunk). The wire shape (`Vec<(UserId, Vec<Vec<u8>>)>`)
/// is scheme-agnostic already - a PQ recipient's "blocks" is just a single
/// bincode-encoded blob instead of N OAEP blocks.
fn build_chunk_recipients(target: &StreamRecipients, stream_id: u64, seq: u32, pcm: &[u8]) -> Vec<(UserId, Vec<Vec<u8>>)> {
    match target {
        StreamRecipients::Channel { rsa, pq, .. } => {
            let mut out: Vec<(UserId, Vec<Vec<u8>>)> =
                rsa.iter().filter_map(|(id, key)| crypto::encrypt_chunked(key, pcm).ok().map(|b| (*id, b))).collect();
            if let Some(pq) = pq {
                for (id, setup) in &pq.per_recipient {
                    let blob = crypto::pq::encrypt_hybrid_voice_chunk(setup, &pq.k_data, stream_id, seq, pcm);
                    out.push((*id, vec![blob]));
                }
            }
            out
        }
        StreamRecipients::Direct { to, key } => {
            encrypt_direct_chunk(key, stream_id, seq, pcm).map(|blocks| vec![(*to, blocks)]).unwrap_or_default()
        }
    }
}

/// One recipient's worth of `build_chunk_recipients`' `Direct` arm, pulled
/// out so `file_stream`'s sending worker can reuse the exact same RSA/PQ
/// dispatch without duplicating it - a file transfer is always a single
/// `DirectStreamKey` recipient (`docs/PROTOCOL.md`'s file transfer
/// section), same shape as a DM voice stream.
pub(crate) fn encrypt_direct_chunk(key: &DirectStreamKey, stream_id: u64, seq: u32, data: &[u8]) -> Option<Vec<Vec<u8>>> {
    match key {
        DirectStreamKey::Rsa(k) => crypto::encrypt_chunked(k, data).ok(),
        DirectStreamKey::Pq(pq) => {
            let (_, setup) = pq.per_recipient.first()?;
            let blob = crypto::pq::encrypt_hybrid_voice_chunk(setup, &pq.k_data, stream_id, seq, data);
            Some(vec![blob])
        }
    }
}

/// Every `UserId` a stream's `target` addresses - RSA and PQ recipients
/// combined for a channel stream, the single recipient for a DM. Used at
/// `*End` time to fan `P2pOutbound::VoiceEnd` out to the same recipient set
/// `*Start` reached, since (unlike the old server-relayed broadcast) there's
/// no membership list to derive it from on the receiving end anymore.
fn stream_recipient_ids(target: &StreamRecipients) -> Vec<UserId> {
    match target {
        StreamRecipients::Channel { rsa, pq, .. } => rsa
            .iter()
            .map(|(id, _)| *id)
            .chain(pq.iter().flat_map(|pq| pq.per_recipient.iter().map(|(id, _)| *id)))
            .collect(),
        StreamRecipients::Direct { to, .. } => vec![*to],
    }
}

/// Runs on a dedicated `std::thread` for the lifetime of one recording:
/// every `voice::CHUNK_INTERVAL`, flushes newly-captured samples, encrypts
/// them for each pre-resolved recipient (`build_chunk_recipients`), and
/// hands a ready-to-send `P2pOutbound` back to the main loop - no crypto
/// ever runs on the async `tokio::select!` loop. `stop_rx.recv_timeout`
/// doubles as both the sleep and the wake-on-release signal, since tokio's
/// channels have no blocking-with-timeout primitive usable from a plain
/// thread; this also means release is reflected almost instantly rather
/// than waiting out a full extra `CHUNK_INTERVAL`.
pub(crate) fn spawn_record_stream_worker(
    recorder: voice::Recorder,
    target: StreamRecipients,
    stream_id: u64,
    out_tx: tokio::sync::mpsc::UnboundedSender<crate::p2p::P2pOutbound>,
    done_tx: tokio::sync::mpsc::UnboundedSender<(u64, u32, Vec<u8>)>,
    stop_rx: std::sync::mpsc::Receiver<()>,
    // Notified (once) if this recording stops itself on reaching
    // `voice::MAX_RECORDING_SAMPLES`, rather than via an explicit Space/
    // global-shortcut release - the main loop uses this to reset the
    // recording indicator and play the end chime immediately, the same as
    // any other stop, instead of leaving the UI claiming to still be
    // recording until the next release event.
    auto_stop_tx: tokio::sync::mpsc::UnboundedSender<()>,
) {
    std::thread::spawn(move || {
        let mut seq: u32 = 0;
        let mut total_samples: u64 = 0;
        let mut plaintext_accum: Vec<u8> = Vec::new();

        loop {
            let mut stopped = match stop_rx.recv_timeout(voice::CHUNK_INTERVAL) {
                Ok(()) => true,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => false,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => true,
            };

            let pending = recorder.take_pending();
            if !pending.is_empty() {
                total_samples += pending.len() as u64;
                let pcm = voice::pcm_to_bytes(&pending);
                plaintext_accum.extend_from_slice(&pcm);

                let per_recipient = build_chunk_recipients(&target, stream_id, seq, &pcm);
                let msg = match &target {
                    StreamRecipients::Channel { .. } => {
                        Some(crate::p2p::P2pOutbound::ChannelVoiceChunk { stream_id, seq, per_recipient })
                    }
                    StreamRecipients::Direct { to, .. } => per_recipient
                        .into_iter()
                        .next()
                        .map(|(_, blocks)| crate::p2p::P2pOutbound::DirectVoiceChunk { to: *to, stream_id, seq, blocks }),
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
                let duration_ms = ((total_samples * 1000) / voice::SAMPLE_RATE_HZ as u64) as u32;
                let recipients = stream_recipient_ids(&target);
                let _ = out_tx.send(crate::p2p::P2pOutbound::VoiceEnd { stream_id, duration_ms, recipients });
                let _ = done_tx.send((stream_id, duration_ms, plaintext_accum));
                break; // `recorder` drops here, closing the input stream.
            }
        }
    });
}

/// Decrypts successive chunks of one incoming stream/transfer, keyed once
/// at start (`resolve_incoming_key`) - shared by voice's
/// `spawn_stream_decrypt_worker` and `file_stream`'s receive worker so the
/// RSA-candidates-retry / PQ-`k_data`-cache-from-first-chunk logic isn't
/// duplicated between them.
pub(crate) struct ChunkDecryptor {
    key: IncomingStreamKey,
    // `PqHybrid` only: the stream's `k_data`, recovered and
    // signature-verified from the *first* chunk's `HybridStreamKeySetup`
    // (`crypto::pq::unwrap_key_for_stream`) and cached here - every later
    // chunk only pays for cheap AES-256-GCM, never re-verifying or
    // re-unwrapping (`HybridStreamKeySetup`'s doc explains why the wire
    // still repeats it every chunk regardless).
    pq_k_data: Option<[u8; 32]>,
}

impl ChunkDecryptor {
    pub(crate) fn new(key: IncomingStreamKey) -> Self {
        Self { key, pq_k_data: None }
    }

    /// Decrypts one chunk's `blocks`, `None` on any failure (wrong/stale
    /// key, corrupted chunk, bad AEAD tag, ...).
    pub(crate) fn decrypt(&mut self, stream_id: u64, seq: u32, blocks: &[Vec<u8>]) -> Option<Vec<u8>> {
        match &self.key {
            // Tries each candidate key in turn (current, retained,
            // bootstrap - see `rekey::OwnKeys::candidate_privates_for`)
            // rather than a single key snapshotted at start, so a stream
            // started right after an optimistically-installed-but-not-yet-
            // accepted rsa_per_msg resume still decrypts correctly instead
            // of silently failing every chunk.
            IncomingStreamKey::Rsa(privates) => privates.iter().find_map(|k| crypto::decrypt_chunked(k, blocks).ok()),
            IncomingStreamKey::Pq { my_private, sender_public } => {
                let blob = blocks.first()?;
                let chunk: crypto::pq::HybridVoiceChunk = proto::decode(blob).ok()?;
                if self.pq_k_data.is_none() {
                    self.pq_k_data = crypto::pq::unwrap_key_for_stream(my_private, sender_public, stream_id, &chunk.key_setup);
                }
                let k_data = self.pq_k_data.as_ref()?;
                crypto::pq::decrypt_hybrid_chunk(k_data, stream_id, seq, &chunk.ciphertext)
            }
        }
    }
}

/// Runs on a dedicated thread for the lifetime of one incoming stream -
/// each stream gets its own, rather than sharing one decrypt thread across
/// every incoming stream, because private-key decrypt (RSA) or unwrap+AEAD
/// (`PqHybrid`) is meaningfully costlier than the sender's own encrypt: a
/// single shared thread would start lagging behind real time with just two
/// or three simultaneous incoming streams.
pub(crate) fn spawn_stream_decrypt_worker(
    key: IncomingStreamKey,
    mixer_tx: tokio::sync::mpsc::UnboundedSender<voice::MixerCmd>,
    mixer_id: u64,
    from: UserId,
    stream_id: u64,
    // Snapshotted once at `*Start` (docs/PROTOCOL.md §11.6/§12): a
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
        while let Some(job) = rx.blocking_recv() {
            match job {
                DecryptJob::Chunk(seq, blocks) => {
                    let pcm = decryptor.decrypt(stream_id, seq, &blocks);
                    if let Some(pcm) = pcm {
                        plaintext_accum.extend_from_slice(&pcm);
                        if !suppress_playback {
                            let samples = voice::pcm_from_bytes(&pcm);
                            let _ = mixer_tx.send(voice::MixerCmd::Push { id: mixer_id, samples });
                        }
                        // Defense in depth (docs/PROTOCOL.md §7.3): never
                        // accept more than `voice::MAX_RECORDING_SAMPLES` of
                        // audio for one stream, regardless of what the
                        // sender's own recording-length cap says - force-
                        // finalize with whatever arrived so far and stop
                        // accepting further chunks for this stream, exactly
                        // as if a real `*End` had just arrived.
                        let sample_count = (plaintext_accum.len() / 2) as u64;
                        if voice::recording_at_max(sample_count) {
                            let duration_ms = ((sample_count * 1000) / voice::SAMPLE_RATE_HZ as u64) as u32;
                            let _ = mixer_tx.send(voice::MixerCmd::Finish { id: mixer_id });
                            let _ = finished_tx.send((from, stream_id, duration_ms, plaintext_accum));
                            break;
                        }
                    }
                }
                DecryptJob::End => {
                    let sample_count = (plaintext_accum.len() / 2) as u64;
                    let duration_ms = ((sample_count * 1000) / voice::SAMPLE_RATE_HZ as u64) as u32;
                    let _ = mixer_tx.send(voice::MixerCmd::Finish { id: mixer_id });
                    let _ = finished_tx.send((from, stream_id, duration_ms, plaintext_accum));
                    break;
                }
            }
        }
    });
    tx
}

/// Plays the "message ended" chime through the mixer, same as any other
/// source (`ReplayVoice` does the identical Push+Finish pair) - on the
/// sender's release of Space and on an incoming stream's completion, so
/// both ends of a voice message get the same audible cue.
pub(crate) fn play_end_chime(session: &mut SessionState) {
    let samples = voice::end_chime_samples();
    if samples.is_empty() {
        return;
    }
    let id = session.next_mixer_id;
    session.next_mixer_id += 1;
    let _ = session.mixer_tx.send(voice::MixerCmd::Push { id, samples });
    let _ = session.mixer_tx.send(voice::MixerCmd::Finish { id });
}

/// Plays the incoming-file-offer notification sound, same `Push`/`Finish`
/// pattern as `play_end_chime` - called whenever a new file-offer popup
/// becomes the one shown (`docs/PROTOCOL.md`'s file transfer section).
pub(crate) fn play_bell_chime(session: &mut SessionState) {
    let samples = voice::bell_chime_samples();
    if samples.is_empty() {
        return;
    }
    let id = session.next_mixer_id;
    session.next_mixer_id += 1;
    let _ = session.mixer_tx.send(voice::MixerCmd::Push { id, samples });
    let _ = session.mixer_tx.send(voice::MixerCmd::Finish { id });
}

/// Resolves one recipient's outgoing key material for a point-to-point
/// stream - shared by `file_stream`'s sending setup (`channel`/
/// `direct_message`'s `handle_send_file`). Unlike
/// `direct_message::handle_voice_record_start`'s own inline version, a
/// resolution failure here (malformed `PqHybrid` public key, or an
/// unbuildable PQ stream setup - e.g. we aren't ourselves `PqHybrid`) has
/// no per-failure error message to surface: it's just `None`, and the
/// caller silently excludes that recipient, same as any other
/// partial-delivery case in this app (an offline member, a not-yet-fresh
/// `rsa_per_msg` key, ...) - a file send has no single "recording" UI
/// element for a failure reason to attach to the way voice's
/// `audio_error` does.
pub(crate) fn resolve_direct_key(
    session: &SessionState,
    stream_id: u64,
    to: UserId,
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: &[u8],
) -> Option<DirectStreamKey> {
    match recipient_key_mode {
        KeyMode::PqHybrid => {
            let public: crypto::pq::PqPublicBundle = proto::decode(recipient_pubkey_der).ok()?;
            let pq = build_pq_stream_out(session, stream_id, &[(to, public)])?;
            Some(DirectStreamKey::Pq(pq))
        }
        _ => crypto::public_key_from_der(recipient_pubkey_der).ok().map(DirectStreamKey::Rsa),
    }
}

/// Resolves which key(s) to try for an incoming stream/transfer from
/// `from`, decided by *our own* `session.own_key_mode` (a stream addressed
/// to us was necessarily encrypted against whichever public key material
/// *we* announced, regardless of the sender's own `my_key` - see
/// `IncomingStreamKey`'s doc). Shared by `start_incoming_stream` (voice) and
/// `file_stream`'s incoming-transfer setup, both of which snapshot this
/// once at start rather than per chunk (PROTOCOL.md §11.6).
///
/// `sender_public_key_der` is the sender's `UserInfo.public_key_der`
/// (whatever `key_mode` they announced) - only actually used when *our own*
/// `own_key_mode` is `PqHybrid`, to verify the once-per-stream signature.
pub(crate) fn resolve_incoming_key(session: &SessionState, from: UserId, sender_public_key_der: &[u8]) -> IncomingStreamKey {
    if session.own_key_mode == KeyMode::PqHybrid {
        match (session.own_pq_private.clone(), proto::decode(sender_public_key_der)) {
            (Some(my_private), Ok(sender_public)) => IncomingStreamKey::Pq { my_private, sender_public },
            // Malformed sender key, or (shouldn't happen) no own PQ
            // identity despite `own_key_mode == PqHybrid` - nothing
            // decryptable either way, so every chunk will just fail to
            // decrypt below rather than crashing anything.
            _ => IncomingStreamKey::Rsa(Vec::new()),
        }
    } else {
        let candidates = session
            .own_keys
            .as_ref()
            .map(|own_keys| own_keys.lock().unwrap().candidate_privates_for(from))
            .unwrap_or_default();
        IncomingStreamKey::Rsa(candidates)
    }
}

pub(crate) fn start_incoming_stream(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    channel: Option<String>,
    suppress_playback: bool,
    // The sender's `UserInfo.public_key_der` (whatever `key_mode` they
    // announced) - only actually used when *our own* `own_key_mode` is
    // `PqHybrid`, to verify the once-per-stream signature. Passed as raw
    // bytes rather than requiring a full `UserInfo` here so callers already
    // holding just the field don't need to reconstruct one.
    sender_public_key_der: &[u8],
) {
    let mixer_id = session.next_mixer_id;
    session.next_mixer_id += 1;
    // The whole stream stays on one key snapshot (PROTOCOL.md §11.6), so
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
    session.active_streams.insert((from, stream_id), ActiveStream { job_tx, channel, last_seen: Instant::now() });
}

pub(crate) fn forward_chunk(session: &mut SessionState, from: UserId, stream_id: u64, seq: u32, blocks: Vec<Vec<u8>>) {
    if let Some(s) = session.active_streams.get_mut(&(from, stream_id)) {
        s.last_seen = Instant::now();
        let _ = s.job_tx.send(DecryptJob::Chunk(seq, blocks));
    }
}

pub(crate) fn end_incoming_stream(session: &mut SessionState, from: UserId, stream_id: u64) {
    if let Some(s) = session.active_streams.get_mut(&(from, stream_id)) {
        s.last_seen = Instant::now();
        let _ = s.job_tx.send(DecryptJob::End);
    }
}
