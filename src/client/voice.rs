//! Push-to-talk voice messages, streamed live: audio captured while Space
//! is held is chunked and handed off (by the caller, in
//! `crate::client::voice_stream`) to the
//! network roughly every `CHUNK_INTERVAL`, rather than waiting for release
//! to send one whole clip. Playback mirrors that: decoded chunks are
//! pushed into the `Mixer` as they arrive and heard immediately, instead
//! of waiting for a complete message.
//!
//! The pure PCM<->bytes conversion, resampling, and duration formatting
//! below are unit tested directly. `Recorder`/`Mixer` talk to a real audio
//! device and are exercised manually (there's no microphone/speaker in a CI
//! sandbox), not by the automated test suite.
//!
//! Two backends provide `Recorder`/`spawn_mixer`, chosen by `target_env`:
//! everywhere except musl, both are implemented here on top of `cpal`'s
//! ALSA host. On musl they're re-exported from `crate::client::voice_pulse`
//! instead, which talks to PulseAudio/PipeWire directly - see that module's
//! doc comment for why. Both backends share the platform-independent
//! mixing logic below (`MixSource`, `mix_output`, `apply_mixer_cmd`) so the
//! jitter-buffer/multi-source-summing behavior is identical either way.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(not(target_env = "musl"))]
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
#[cfg(not(target_env = "musl"))]
use cpal::{SampleFormat, StreamConfig};
#[cfg(not(target_env = "musl"))]
use tokio::sync::mpsc::UnboundedSender;

/// Mono capture/playback rate. Low enough to keep RSA-chunked voice
/// messages small (see `crypto::encrypt_chunked`, which has no
/// bulk/session-key shortcut), high enough to stay intelligible.
pub const SAMPLE_RATE_HZ: u32 = 16_000;

/// How often a live recording flushes captured samples to the network as
/// a chunk. Total RSA-encrypt work per second of audio is the same
/// regardless (bytes-of-audio / bytes-per-block), so this is tuned for
/// latency and for keeping each chunk's encrypted size under
/// `p2p_proto::SAFE_DATAGRAM_BYTES` with margin: 15ms (the RTP/Opus
/// real-time framing range) is 32 bytes/ms × 15ms = 480 bytes plaintext,
/// at most 3 OAEP blocks (~768 bytes ciphertext) at the worst-case
/// 2048-bit key size (see `test/voice_test.rs`).
pub const CHUNK_INTERVAL: Duration = Duration::from_millis(15);

/// Hard cap on one voice message's length, in seconds - a recording stops
/// itself on reaching it rather than waiting for Space forever. An
/// incoming stream is independently force-finalized past the same cap
/// (`voice_stream::spawn_stream_decrypt_worker`): defense in depth
/// against a hostile peer that ignores its own cap.
pub const MAX_RECORDING_SECS: u64 = 4 * 60;

/// `MAX_RECORDING_SECS` expressed as a sample count at `SAMPLE_RATE_HZ`,
/// what the recording/decrypt workers actually compare against as audio
/// accumulates.
pub const MAX_RECORDING_SAMPLES: u64 = SAMPLE_RATE_HZ as u64 * MAX_RECORDING_SECS;

/// Whether a recording/incoming stream that has accumulated `total_samples`
/// so far has reached `MAX_RECORDING_SAMPLES` and must stop - a pure
/// predicate shared by both the sending and receiving workers (see
/// `MAX_RECORDING_SECS`'s doc), directly unit-testable without a thread or
/// audio device.
pub fn recording_at_max(total_samples: u64) -> bool {
    total_samples >= MAX_RECORDING_SAMPLES
}

#[derive(Debug, thiserror::Error)]
pub enum VoiceError {
    #[error("no default audio device available")]
    NoDevice,
    #[error("audio device error: {0}")]
    Device(String),
    #[error("unsupported sample format")]
    UnsupportedFormat,
}

/// Prefers a device driven by PulseAudio's ALSA plugin ("pulse") over
/// `default_*_device` when present: raw ALSA requires exclusive device
/// access, so two `aloo` clients on one machine (the normal way to test
/// locally) reliably fail with "device busy" through the ALSA default,
/// while "pulse" gets user-space mixing and both work at once. Harmless
/// where no "pulse" device exists - the search finds nothing and falls
/// through to the default. musl doesn't use this at all
/// (`crate::client::voice_pulse` talks to PulseAudio directly).
#[cfg(not(target_env = "musl"))]
fn prefer_pulse(
    devices: impl Iterator<Item = cpal::Device>,
    default: Option<cpal::Device>,
) -> Option<cpal::Device> {
    let mut devices: Vec<cpal::Device> = devices.collect();
    let pulse_pos = devices.iter().position(|d| {
        d.description()
            .ok()
            .and_then(|desc| desc.driver().map(str::to_string))
            .as_deref()
            == Some("pulse")
    });
    match pulse_pos {
        Some(pos) => Some(devices.swap_remove(pos)),
        None => default,
    }
}

#[cfg(not(target_env = "musl"))]
fn preferred_input_device(host: &cpal::Host) -> Option<cpal::Device> {
    let devices = host.input_devices().ok().into_iter().flatten();
    prefer_pulse(devices, host.default_input_device())
}

#[cfg(not(target_env = "musl"))]
fn preferred_output_device(host: &cpal::Host) -> Option<cpal::Device> {
    let devices = host.output_devices().ok().into_iter().flatten();
    prefer_pulse(devices, host.default_output_device())
}

pub type Result<T> = std::result::Result<T, VoiceError>;

pub fn pcm_to_bytes(samples: &[i16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len() * 2);
    for s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

/// Any trailing odd byte (a truncated/corrupt payload) is dropped rather
/// than panicking, since this decodes untrusted network input.
pub fn pcm_from_bytes(bytes: &[u8]) -> Vec<i16> {
    bytes
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// The loudness of one captured/decoded chunk as a 0-100 meter reading -
/// what the live call modal draws next to each participant
/// (`crate::client::tui::ui::CallMember::level`). Root-mean-square rather
/// than peak amplitude, so one stray sample can't paint a full bar, and
/// scaled against `LEVEL_FULL_SCALE_RMS` rather than `i16::MAX`: ordinary
/// speech sits an order of magnitude below full scale, and a meter that
/// never left its first tenth would show nothing useful.
pub fn level_from_pcm(samples: &[i16]) -> u8 {
    if samples.is_empty() {
        return 0;
    }
    let sum_sq: f64 = samples.iter().map(|s| (*s as f64) * (*s as f64)).sum();
    let rms = (sum_sq / samples.len() as f64).sqrt();
    ((rms / LEVEL_FULL_SCALE_RMS) * 100.0).round().clamp(0.0, 100.0) as u8
}

/// The RMS amplitude `level_from_pcm` treats as a full meter. Chosen from
/// what this app's own 16kHz mono capture actually produces: normal speech
/// lands around 2000-4000 RMS, so this puts a comfortable talking voice
/// near two thirds of the bar and leaves headroom above it.
const LEVEL_FULL_SCALE_RMS: f64 = 6000.0;

/// Linearly resamples mono `samples` from `from_rate` to `to_rate`. Used
/// both to normalize whatever rate the input device actually captures at
/// to `SAMPLE_RATE_HZ` (see `Recorder::take_pending`) and so playback can
/// target whatever rate the output device wants instead of forcing
/// `SAMPLE_RATE_HZ` on it - the latter is a common cause of ALSA/dmix
/// failing to open the device at all (its slave is usually locked to one
/// fixed rate, e.g. 48000Hz, and asking for something else can fail
/// rather than being converted).
pub fn resample(samples: &[i16], from_rate: u32, to_rate: u32) -> Vec<i16> {
    if samples.is_empty() || from_rate == 0 || to_rate == 0 || from_rate == to_rate {
        return samples.to_vec();
    }
    let ratio = to_rate as f64 / from_rate as f64;
    let out_len = ((samples.len() as f64) * ratio).round() as usize;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let src_pos = i as f64 / ratio;
        let idx = src_pos.floor() as usize;
        let frac = src_pos - idx as f64;
        let a = samples.get(idx).copied().unwrap_or(0) as f64;
        let b = samples.get(idx + 1).copied().unwrap_or(a as i16) as f64;
        out.push(
            (a + (b - a) * frac)
                .round()
                .clamp(i16::MIN as f64, i16::MAX as f64) as i16,
        );
    }
    out
}

/// Averages interleaved input frames down to one mono sample per frame.
/// Input devices commonly default to stereo-or-more even for a physically
/// mono mic; downstream consumers treat one buffer entry as one moment in
/// time, so without this the extra entries stretch the apparent duration -
/// playback at a fraction of the right speed and pitch, garbled since
/// unrelated channels become consecutive time steps.
pub fn downmix_i16_to_mono(samples: &[i16], channels: u16) -> Vec<i16> {
    if channels <= 1 {
        return samples.to_vec();
    }
    let channels = channels as usize;
    samples
        .chunks(channels)
        .map(|frame| (frame.iter().map(|&s| s as i32).sum::<i32>() / frame.len() as i32) as i16)
        .collect()
}

pub fn downmix_f32_to_mono_i16(samples: &[f32], channels: u16) -> Vec<i16> {
    let channels = channels.max(1) as usize;
    samples
        .chunks(channels)
        .map(|frame| {
            let avg = frame.iter().sum::<f32>() / frame.len() as f32;
            (avg.clamp(-1.0, 1.0) * i16::MAX as f32) as i16
        })
        .collect()
}

// ---------------------------------------------------------------------
// "End of message" chime
// ---------------------------------------------------------------------

/// Bundled as WAV rather than the project's original `assets/end.mp3` so
/// it can be decoded without pulling in an MP3-decoding crate: a WAV's
/// PCM payload can be read directly, no decoding library needed.
const END_CHIME_WAV: &[u8] = include_bytes!("../../assets/end.wav");

static END_CHIME_SAMPLES: OnceLock<Vec<i16>> = OnceLock::new();

/// Mono PCM16 samples, at `SAMPLE_RATE_HZ`, for the short "message ended"
/// chime. Decoded from `END_CHIME_WAV` once and cached; the caller
/// (`voice_stream::play_end_chime`) plays it both when the sender releases
/// Space and when an
/// incoming stream finishes, via `MixerCmd::Push`/`Finish` like any other
/// source. Empty (a silent no-op for callers) if the bundled asset is
/// ever missing/malformed, rather than failing the whole app over a
/// decorative sound effect.
pub fn end_chime_samples() -> Vec<i16> {
    END_CHIME_SAMPLES
        .get_or_init(|| decode_wav_to_mono(END_CHIME_WAV).unwrap_or_default())
        .clone()
}

/// Bundled the same way as `END_CHIME_WAV` - a plain WAV, no MP3-decoding
/// crate needed.
const BELL_CHIME_WAV: &[u8] = include_bytes!("../../assets/bell.wav");

static BELL_CHIME_SAMPLES: OnceLock<Vec<i16>> = OnceLock::new();

/// Mono PCM16 samples, at `SAMPLE_RATE_HZ`, for the incoming-file-offer
/// notification sound (`docs/PROTOCOL.md`'s file transfer section) - played
/// once whenever a new file-offer popup becomes the one shown
/// (`voice_stream::play_bell_chime`), the same `MixerCmd::Push`/`Finish`
/// pattern `play_end_chime` already uses. Empty if the bundled asset is
/// ever missing/malformed, same fallback as `end_chime_samples`.
pub fn bell_chime_samples() -> Vec<i16> {
    BELL_CHIME_SAMPLES
        .get_or_init(|| decode_wav_to_mono(BELL_CHIME_WAV).unwrap_or_default())
        .clone()
}

/// Bundled the same way as the other two chimes - a plain WAV, no
/// MP3-decoding crate needed.
const JOINED_CHIME_WAV: &[u8] = include_bytes!("../../assets/joined.wav");

static JOINED_CHIME_SAMPLES: OnceLock<Vec<i16>> = OnceLock::new();

/// Mono PCM16 samples for the sound a daemon plays when someone it is
/// focused on appears (`docs/SPEC.md` "Running in background mode") - the audible half of
/// "your contact is here", the other half being the desktop notification
/// (`client::global_notification`). Only ever played in daemon mode: a
/// foreground client shows the join in its own log, where a sound would be
/// noise. Empty if the bundled asset is ever missing/malformed, same
/// fallback as the other two.
pub fn joined_chime_samples() -> Vec<i16> {
    JOINED_CHIME_SAMPLES
        .get_or_init(|| decode_wav_to_mono(JOINED_CHIME_WAV).unwrap_or_default())
        .clone()
}

/// Plays `samples` and waits for them to finish, on a mixer of its own.
///
/// The chime helpers in `voice_stream` all push into the session's
/// long-lived mixer, which is exactly what a startup failure does not
/// have: it happens before there is a session, and the process is about to
/// exit. Without waiting, the exit would cut the sound off before it was
/// audible - which for the "your daemon did not start" tone would defeat
/// its whole purpose.
///
/// Capped at `MAX_STANDALONE_PLAYBACK` so a broken audio device can never
/// turn a failed start into a process that hangs instead of exiting.
pub fn play_samples_blocking(samples: Vec<i16>) {
    if samples.is_empty() {
        return;
    }
    let (finished_tx, finished_rx) = std::sync::mpsc::channel::<u64>();
    let mixer = spawn_mixer(
        |_| {},
        move |id| {
            let _ = finished_tx.send(id);
        },
    );
    let id = 1;
    let _ = mixer.send(MixerCmd::Push { id, samples });
    let _ = mixer.send(MixerCmd::Finish { id });
    let _ = finished_rx.recv_timeout(MAX_STANDALONE_PLAYBACK);
}

/// How long `play_samples_blocking` waits for a sound to finish before
/// giving up. Long enough for any bundled asset (the longest,
/// `joined.wav`, is under ten seconds) plus room for a slow device open.
pub const MAX_STANDALONE_PLAYBACK: std::time::Duration = std::time::Duration::from_secs(15);

/// Decodes a canonical PCM WAV file's audio into mono samples at
/// `SAMPLE_RATE_HZ`. Walks chunks generically rather than assuming fixed
/// offsets, so extra metadata chunks before `data` (e.g. ffmpeg's
/// LIST/INFO chunk) are tolerated. Only 16-bit integer PCM is supported -
/// this exists for one bundled UI sound effect, not as a general-purpose
/// WAV decoder, so unsupported/malformed input just yields `None` rather
/// than needing to handle every WAV variant (float samples, 24/32-bit,
/// compressed formats, ...).
pub fn decode_wav_to_mono(wav: &[u8]) -> Option<Vec<i16>> {
    if wav.len() < 12 || &wav[0..4] != b"RIFF" || &wav[8..12] != b"WAVE" {
        return None;
    }
    let mut pos = 12usize;
    let mut channels: u16 = 1;
    let mut sample_rate: u32 = SAMPLE_RATE_HZ;
    let mut bits_per_sample: u16 = 16;
    let mut data: Option<&[u8]> = None;

    while pos + 8 <= wav.len() {
        let id = &wav[pos..pos + 4];
        let size = u32::from_le_bytes(wav[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let body_start = pos + 8;
        let body_end = body_start.saturating_add(size).min(wav.len());
        let body = &wav[body_start..body_end];
        match id {
            b"fmt " if body.len() >= 16 => {
                channels = u16::from_le_bytes(body[2..4].try_into().unwrap());
                sample_rate = u32::from_le_bytes(body[4..8].try_into().unwrap());
                bits_per_sample = u16::from_le_bytes(body[14..16].try_into().unwrap());
            }
            b"data" => data = Some(body),
            _ => {}
        }
        // Chunks are word-aligned: an odd-sized chunk has one pad byte.
        pos = body_start.saturating_add(size).saturating_add(size % 2);
    }

    let data = data?;
    if bits_per_sample != 16 || channels == 0 || data.len() < 2 {
        return None;
    }
    let mono = downmix_i16_to_mono(&pcm_from_bytes(data), channels);
    Some(resample(&mono, sample_rate, SAMPLE_RATE_HZ))
}

/// Captures microphone audio into an in-memory buffer while alive.
/// Created when the user presses Space; `take_pending` is called
/// periodically by the caller's record-stream worker to flush chunks to
/// the network, and the `Recorder` is simply dropped (closing the input
/// stream) once recording stops.
///
/// musl gets a different `Recorder` entirely - see `crate::client::voice_pulse`,
/// re-exported below as this same name so callers never need to know
/// which backend is active.
#[cfg(not(target_env = "musl"))]
pub struct Recorder {
    // Never read again after `start` - held only so its `Drop` stops
    // capture when the `Recorder` itself is dropped.
    #[allow(dead_code)]
    stream: cpal::Stream,
    buffer: Arc<Mutex<Vec<i16>>>,
    sample_rate: u32,
}

#[cfg(not(target_env = "musl"))]
impl Recorder {
    /// `on_stream_error` reports errors raised asynchronously by the audio
    /// callback (e.g. a buffer under/overrun, or the device disappearing
    /// mid-recording) once capture is already under way. These can't be
    /// returned from `start` itself, and must not be written straight to
    /// the terminal: cpal invokes the callback from its own thread at any
    /// time, including while ratatui has the terminal in raw/alternate-screen
    /// mode. This callback reports into the UI instead; anything in this
    /// crate that has only a terminal to report to goes through
    /// `crate::log_warn!`, which is silenced for exactly as long as the TUI
    /// owns the screen.
    pub fn start(on_stream_error: impl Fn(String) + Send + 'static) -> Result<Self> {
        let host = cpal::default_host();
        let device = preferred_input_device(&host).ok_or(VoiceError::NoDevice)?;
        let config = device
            .default_input_config()
            .map_err(|e| VoiceError::Device(e.to_string()))?;
        let sample_rate = config.sample_rate();
        let sample_format = config.sample_format();
        // Interleaved frames must be averaged down to mono right here -
        // see `downmix_i16_to_mono`'s doc for what goes wrong otherwise.
        let channels = config.channels();
        let stream_config: StreamConfig = config.into();

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let buf = buffer.clone();

        let stream = match sample_format {
            SampleFormat::I16 => device.build_input_stream(
                stream_config,
                move |data: &[i16], _| {
                    buf.lock()
                        .unwrap()
                        .extend(downmix_i16_to_mono(data, channels));
                },
                move |err| on_stream_error(err.to_string()),
                None,
            ),
            SampleFormat::F32 => device.build_input_stream(
                stream_config,
                move |data: &[f32], _| {
                    buf.lock()
                        .unwrap()
                        .extend(downmix_f32_to_mono_i16(data, channels));
                },
                move |err| on_stream_error(err.to_string()),
                None,
            ),
            _ => return Err(VoiceError::UnsupportedFormat),
        }
        .map_err(|e| VoiceError::Device(e.to_string()))?;

        stream
            .play()
            .map_err(|e| VoiceError::Device(e.to_string()))?;

        Ok(Self {
            stream,
            buffer,
            sample_rate,
        })
    }

    /// Drains everything captured since the last call, resampled to
    /// `SAMPLE_RATE_HZ` - hardware commonly defaults to 44.1/48kHz, and
    /// the wire format has no per-chunk rate field, so unnormalized chunks
    /// would play back pitch/speed-distorted. Safe to call repeatedly
    /// while recording; leaves the input stream running.
    pub fn take_pending(&self) -> Vec<i16> {
        let raw = std::mem::take(&mut *self.buffer.lock().unwrap());
        resample(&raw, self.sample_rate, SAMPLE_RATE_HZ)
    }
}

// ---------------------------------------------------------------------
// Playback: a single persistent mixer for the whole session
// ---------------------------------------------------------------------

/// How much audio (in ms) a source must have queued - or how long to wait
/// regardless - before the mixer starts consuming it, so ordinary
/// network/decrypt-CPU jitter between chunk arrivals doesn't produce an
/// audible gap. A source that's already `finished` (a whole clip, or a
/// live stream that already ended) skips this wait entirely - there's no
/// more audio coming to wait for.
pub(crate) const JITTER_PREBUFFER_MS: u64 = 150;
pub(crate) const JITTER_MAX_WAIT_MS: u64 = 300;

pub enum MixerCmd {
    /// `samples` are mono PCM16 at `SAMPLE_RATE_HZ`; the mixer resamples
    /// to the output device's actual rate before queuing.
    Push { id: u64, samples: Vec<i16> },
    /// No more `Push`es will come for `id` - once its queue drains, drop it
    /// instead of waiting on a jitter prebuffer that will never fill.
    Finish { id: u64 },
    /// Immediately silences and drops `id`'s queued audio, rather than
    /// letting it drain - used to let the user interrupt a replay early
    /// (Escape while a previously-received voice message is playing).
    Stop { id: u64 },
}

pub(crate) struct MixSource {
    queue: VecDeque<i16>,
    finished: bool,
    started: bool,
    first_seen: Instant,
}

impl MixSource {
    pub(crate) fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            finished: false,
            started: false,
            first_seen: Instant::now(),
        }
    }

    /// A `Finish` with no prior `Push` (an empty clip, or a stream that
    /// ended before its first chunk) - already-finished and empty, so
    /// `mix_output` drops it on the next tick.
    pub(crate) fn new_finished() -> Self {
        Self {
            finished: true,
            ..Self::new()
        }
    }

    pub(crate) fn extend(&mut self, samples: &[i16]) {
        self.queue.extend(samples);
    }

    pub(crate) fn mark_finished(&mut self) {
        self.finished = true;
    }
}

/// Applies one `MixerCmd` to the shared source map - the command-handling
/// logic both the cpal and PulseAudio mixer backends share verbatim, so
/// their jitter-buffer/multi-source bookkeeping can never drift apart.
/// `out_rate` is the backend's actual output rate (device-negotiated for
/// cpal, always `SAMPLE_RATE_HZ` for `voice_pulse` since that backend asks
/// PulseAudio for `SAMPLE_RATE_HZ` directly), used to resample `Push`ed
/// audio once here rather than in every caller.
pub(crate) fn apply_mixer_cmd(
    sources: &Mutex<HashMap<u64, MixSource>>,
    out_rate: u32,
    cmd: MixerCmd,
) {
    match cmd {
        MixerCmd::Push { id, samples } => {
            let resampled = resample(&samples, SAMPLE_RATE_HZ, out_rate);
            sources
                .lock()
                .unwrap()
                .entry(id)
                .or_insert_with(MixSource::new)
                .extend(&resampled);
        }
        MixerCmd::Finish { id } => {
            let mut map = sources.lock().unwrap();
            match map.get_mut(&id) {
                Some(src) => src.mark_finished(),
                None => {
                    map.insert(id, MixSource::new_finished());
                }
            }
        }
        MixerCmd::Stop { id } => {
            // Dropped outright, not just marked finished - a
            // finished-but-not-yet-drained source would still play out its
            // queued tail; Stop means silence right away.
            sources.lock().unwrap().remove(&id);
        }
    }
}

/// Spawns the one persistent audio-output thread for the process: a
/// single `cpal` output stream opened lazily and kept for the session -
/// concurrent per-message opens are a common cause of ALSA/dmix "unable
/// to open slave". Every playback source (live chunks and history replay)
/// goes through this one mixer, so simultaneous sources actually mix
/// instead of queuing. musl gets a different `spawn_mixer` entirely
/// (`crate::client::voice_pulse`, re-exported under this name).
#[cfg(not(target_env = "musl"))]
pub fn spawn_mixer(
    on_stream_error: impl Fn(String) + Send + Clone + 'static,
    on_finished: impl Fn(u64) + Send + Clone + 'static,
) -> UnboundedSender<MixerCmd> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MixerCmd>();
    std::thread::spawn(move || {
        let sources: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut out_rate: Option<u32> = None;
        let mut open_failed = false;
        // Keeps the stream alive for the thread's lifetime; never read
        // again after opening.
        let mut _stream: Option<cpal::Stream> = None;

        while let Some(cmd) = rx.blocking_recv() {
            if out_rate.is_none() && !open_failed {
                match try_open_mixer_stream(
                    sources.clone(),
                    on_stream_error.clone(),
                    on_finished.clone(),
                ) {
                    Ok((stream, rate)) => {
                        out_rate = Some(rate);
                        _stream = Some(stream);
                    }
                    Err(e) => {
                        on_stream_error(e.to_string());
                        // Device unavailable for the rest of the session:
                        // stop accumulating into `sources` below rather
                        // than silently buffering forever into a queue
                        // nothing will ever drain.
                        open_failed = true;
                    }
                }
            }
            if open_failed {
                continue;
            }
            let out_rate = out_rate.expect("set just above when open succeeds");
            apply_mixer_cmd(&sources, out_rate, cmd);
        }
    });
    tx
}

#[cfg(not(target_env = "musl"))]
fn try_open_mixer_stream(
    sources: Arc<Mutex<HashMap<u64, MixSource>>>,
    on_stream_error: impl Fn(String) + Send + 'static,
    on_finished: impl Fn(u64) + Send + 'static,
) -> Result<(cpal::Stream, u32)> {
    let host = cpal::default_host();
    let device = preferred_output_device(&host).ok_or(VoiceError::NoDevice)?;

    // Target the device's own preferred rate/channel-count/format instead
    // of forcing ours: asking ALSA/dmix for an arbitrary rate it wasn't
    // configured for is a common cause of "unable to open slave" errors.
    let supported = device
        .default_output_config()
        .map_err(|e| VoiceError::Device(e.to_string()))?;
    let out_rate = supported.sample_rate();
    let out_channels = supported.channels().max(1);
    let sample_format = supported.sample_format();
    let stream_config: StreamConfig = supported.into();

    let stream = match sample_format {
        SampleFormat::I16 => {
            let sources_cb = sources.clone();
            let on_finished_cb = on_finished;
            device.build_output_stream(
                stream_config,
                move |data: &mut [i16], _| {
                    mix_output(
                        data,
                        out_channels,
                        out_rate,
                        &sources_cb,
                        &on_finished_cb,
                        |s| s,
                    )
                },
                move |err| on_stream_error(err.to_string()),
                None,
            )
        }
        SampleFormat::F32 => {
            let sources_cb = sources.clone();
            let on_finished_cb = on_finished;
            device.build_output_stream(
                stream_config,
                move |data: &mut [f32], _| {
                    mix_output(
                        data,
                        out_channels,
                        out_rate,
                        &sources_cb,
                        &on_finished_cb,
                        |s| s as f32 / i16::MAX as f32,
                    )
                },
                move |err| on_stream_error(err.to_string()),
                None,
            )
        }
        _ => return Err(VoiceError::UnsupportedFormat),
    }
    .map_err(|e| VoiceError::Device(e.to_string()))?;

    stream
        .play()
        .map_err(|e| VoiceError::Device(e.to_string()))?;
    Ok((stream, out_rate))
}

/// Sums every jitter-buffer-ready source into one output frame, clamping
/// to avoid wraparound distortion when multiple sources overlap loudly,
/// and duplicates the mixed mono sample across every output channel -
/// output devices are very often stereo-or-more even though sources are
/// always mono. Runs on the realtime output callback/thread (cpal's own
/// callback thread, or `voice_pulse`'s dedicated writer thread), so it
/// only pops pre-resampled samples and sums - no allocation, no
/// resampling here.
pub(crate) fn mix_output<T: Copy>(
    data: &mut [T],
    out_channels: u16,
    out_rate: u32,
    sources: &Arc<Mutex<HashMap<u64, MixSource>>>,
    on_finished: &(impl Fn(u64) + Send + 'static),
    convert: impl Fn(i16) -> T,
) {
    let mut map = sources.lock().unwrap();
    for frame in data.chunks_mut(out_channels as usize) {
        let mut sum: i32 = 0;
        for src in map.values_mut() {
            if !src.started {
                let queued_ms = (src.queue.len() as u64 * 1000) / out_rate.max(1) as u64;
                let waited_enough =
                    src.first_seen.elapsed().as_millis() as u64 >= JITTER_MAX_WAIT_MS;
                if src.finished || queued_ms >= JITTER_PREBUFFER_MS || waited_enough {
                    src.started = true;
                }
            }
            if src.started
                && let Some(s) = src.queue.pop_front()
            {
                sum += s as i32;
            }
        }
        // A source retired here drained naturally (as opposed to
        // `MixerCmd::Stop`, which removes it outright elsewhere) - reported
        // via `on_finished` so a caller tracking "is a specific id still
        // playing" (e.g. `session::SessionState::active_replay_id`) finds
        // out without polling.
        map.retain(|id, src| {
            let done = src.started && src.finished && src.queue.is_empty();
            if done {
                on_finished(*id);
            }
            !done
        });
        let s = convert(sum.clamp(i16::MIN as i32, i16::MAX as i32) as i16);
        for out in frame.iter_mut() {
            *out = s;
        }
    }
}

#[cfg(target_env = "musl")]
pub use crate::client::voice_pulse::{Recorder, spawn_mixer};
