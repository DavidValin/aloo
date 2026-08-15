//! Push-to-talk voice messages, streamed live: audio captured while Space
//! is held is chunked and handed off (by the caller, in
//! `crate::voice_stream`) to the
//! network roughly every `CHUNK_INTERVAL`, rather than waiting for release
//! to send one whole clip. Playback mirrors that: decoded chunks are
//! pushed into the `Mixer` as they arrive and heard immediately, instead
//! of waiting for a complete message.
//!
//! The pure PCM<->bytes conversion, resampling, and duration formatting
//! below are unit tested directly. `Recorder`/`Mixer` talk to a real audio
//! device via `cpal` and are exercised manually (there's no
//! microphone/speaker in a CI sandbox), not by the automated test suite.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};
use tokio::sync::mpsc::UnboundedSender;

/// Mono capture/playback rate. Low enough to keep RSA-chunked voice
/// messages small (see `crypto::encrypt_chunked`, which has no
/// bulk/session-key shortcut), high enough to stay intelligible.
pub const SAMPLE_RATE_HZ: u32 = 16_000;

/// How often a live recording flushes newly-captured samples to the
/// network as a chunk. Total RSA-encrypt work per second of audio is the
/// same regardless of this value (it's purely bytes-of-audio /
/// bytes-per-block); a shorter interval only lowers perceived latency at
/// the cost of more (smaller) messages, so this is tuned for latency, not
/// crypto cost.
pub const CHUNK_INTERVAL: Duration = Duration::from_millis(100);

/// Hard cap on one voice message's length, in seconds - a recording stops
/// itself automatically on reaching it
/// (`voice_stream::spawn_record_stream_worker`), rather than waiting
/// indefinitely for Space to be released. An incoming stream is
/// independently force-finalized with whatever arrived so far if it ever
/// exceeds this much audio (`voice_stream::spawn_stream_decrypt_worker`) -
/// defense in depth against a modified/hostile peer that ignores its own
/// cap, so the receiving side never accepts more than this regardless of
/// what the sender claims.
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

/// Prefers a device driven by PulseAudio's ALSA plugin (`cpal` exposes its
/// ALSA PCM id, "pulse", via `description().driver()`) over whatever
/// `default_*_device` returns, when one is present. `cpal`'s own docs spell
/// out why this matters on Linux: "the ALSA host API ... requires that
/// each process have exclusive access to the devices with which they
/// establish streams. PulseAudio ... solve[s] this issue by providing
/// user-space mixing." Two `aloo` clients on the same machine (the normal
/// way to test a channel/DM locally) both need to open the same physical
/// mic/speaker; going through the raw ALSA default reliably makes the
/// second one fail with a "device busy" error, while going through
/// "pulse" lets both play/record at once, confirmed by hand against this
/// project's own dev environment. Harmless everywhere a "pulse" device
/// doesn't exist (non-Linux, or Linux without PulseAudio/PipeWire's pulse
/// shim): the search just finds nothing and this falls through to
/// `default`.
fn prefer_pulse(devices: impl Iterator<Item = cpal::Device>, default: Option<cpal::Device>) -> Option<cpal::Device> {
    let mut devices: Vec<cpal::Device> = devices.collect();
    let pulse_pos = devices
        .iter()
        .position(|d| d.description().ok().and_then(|desc| desc.driver().map(str::to_string)).as_deref() == Some("pulse"));
    match pulse_pos {
        Some(pos) => Some(devices.swap_remove(pos)),
        None => default,
    }
}

fn preferred_input_device(host: &cpal::Host) -> Option<cpal::Device> {
    let devices = host.input_devices().ok().into_iter().flatten();
    prefer_pulse(devices, host.default_input_device())
}

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
        out.push((a + (b - a) * frac).round().clamp(i16::MIN as f64, i16::MAX as f64) as i16);
    }
    out
}

/// Averages interleaved input frames (however many channels the device
/// negotiated) down to one mono sample per frame. Without this, an input
/// device that defaults to stereo-or-more (very common even for a
/// physically mono mic) leaves the raw interleaved buffer with twice (or
/// more) as many "samples" as there are real time steps; every downstream
/// consumer (`Recorder::take_pending`, `resample`) treats one buffer
/// entry as one moment in time, so the extra entries stretch the apparent
/// duration - playing back at a fraction of the correct speed and pitch,
/// and garbled on top of that since unrelated channels get treated as
/// consecutive time steps.
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
const END_CHIME_WAV: &[u8] = include_bytes!("../assets/end.wav");

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
    END_CHIME_SAMPLES.get_or_init(|| decode_wav_to_mono(END_CHIME_WAV).unwrap_or_default()).clone()
}

/// Bundled the same way as `END_CHIME_WAV` - a plain WAV, no MP3-decoding
/// crate needed.
const BELL_CHIME_WAV: &[u8] = include_bytes!("../assets/bell.wav");

static BELL_CHIME_SAMPLES: OnceLock<Vec<i16>> = OnceLock::new();

/// Mono PCM16 samples, at `SAMPLE_RATE_HZ`, for the incoming-file-offer
/// notification sound (`docs/PROTOCOL.md`'s file transfer section) - played
/// once whenever a new file-offer popup becomes the one shown
/// (`voice_stream::play_bell_chime`), the same `MixerCmd::Push`/`Finish`
/// pattern `play_end_chime` already uses. Empty if the bundled asset is
/// ever missing/malformed, same fallback as `end_chime_samples`.
pub fn bell_chime_samples() -> Vec<i16> {
    BELL_CHIME_SAMPLES.get_or_init(|| decode_wav_to_mono(BELL_CHIME_WAV).unwrap_or_default()).clone()
}

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

/// Renders the label the UI shows on a finalized voice message block, e.g.
/// `voice (12sec)`. A non-zero duration under one second still rounds up
/// to `1sec` so a short clip is never shown as `0sec`.
pub fn format_duration_label(duration_ms: u32) -> String {
    let secs = if duration_ms == 0 {
        0
    } else {
        (duration_ms as f64 / 1000.0).ceil() as u32
    };
    format!("voice ({secs}sec)")
}

/// Captures microphone audio into an in-memory buffer while alive.
/// Created when the user presses Space; `take_pending` is called
/// periodically by the caller's record-stream worker to flush chunks to
/// the network, and the `Recorder` is simply dropped (closing the input
/// stream) once recording stops.
pub struct Recorder {
    // Never read again after `start` - held only so its `Drop` stops
    // capture when the `Recorder` itself is dropped.
    #[allow(dead_code)]
    stream: cpal::Stream,
    buffer: Arc<Mutex<Vec<i16>>>,
    sample_rate: u32,
}

impl Recorder {
    /// `on_stream_error` reports errors raised asynchronously by the audio
    /// callback (e.g. a buffer under/overrun, or the device disappearing
    /// mid-recording) once capture is already under way. These can't be
    /// returned from `start` itself, and must not be `eprintln!`'d: cpal
    /// invokes the callback from its own thread at any time, including
    /// while ratatui has the terminal in raw/alternate-screen mode, so
    /// writing straight to stderr corrupts the UI instead of being shown.
    pub fn start(on_stream_error: impl Fn(String) + Send + 'static) -> Result<Self> {
        let host = cpal::default_host();
        let device = preferred_input_device(&host).ok_or(VoiceError::NoDevice)?;
        let config = device
            .default_input_config()
            .map_err(|e| VoiceError::Device(e.to_string()))?;
        let sample_rate = config.sample_rate();
        let sample_format = config.sample_format();
        // Input devices very often default to stereo-or-more even for a
        // physically mono mic (confirmed on this project's own dev
        // machine: the HDA analog input negotiates 2 channels by
        // default). Every downstream consumer of `buffer` (`take_pending`,
        // `resample`) treats it as one sample per moment in time, so the
        // interleaved frames must be averaged down to mono right here -
        // otherwise the buffer ends up with twice as many "samples" as
        // there are real time steps, which plays back at half speed and
        // half pitch (and garbled, since unrelated channels get treated
        // as consecutive time steps).
        let channels = config.channels();
        let stream_config: StreamConfig = config.into();

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let buf = buffer.clone();

        let stream = match sample_format {
            SampleFormat::I16 => device.build_input_stream(
                stream_config,
                move |data: &[i16], _| {
                    buf.lock().unwrap().extend(downmix_i16_to_mono(data, channels));
                },
                move |err| on_stream_error(err.to_string()),
                None,
            ),
            SampleFormat::F32 => device.build_input_stream(
                stream_config,
                move |data: &[f32], _| {
                    buf.lock().unwrap().extend(downmix_f32_to_mono_i16(data, channels));
                },
                move |err| on_stream_error(err.to_string()),
                None,
            ),
            _ => return Err(VoiceError::UnsupportedFormat),
        }
        .map_err(|e| VoiceError::Device(e.to_string()))?;

        stream.play().map_err(|e| VoiceError::Device(e.to_string()))?;

        Ok(Self { stream, buffer, sample_rate })
    }

    /// Drains everything captured since the last call (or since `start`),
    /// resampled to `SAMPLE_RATE_HZ`. The device's default input config is
    /// not necessarily `SAMPLE_RATE_HZ` (44.1/48kHz is far more common
    /// hardware default), so without this normalization every chunk would
    /// carry mismatched-rate PCM and play back pitch/speed-distorted on
    /// the receiving end - the wire format has no per-chunk rate field to
    /// carry the real rate instead. Safe to call repeatedly while still
    /// recording; leaves the input stream itself running.
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
const JITTER_PREBUFFER_MS: u64 = 150;
const JITTER_MAX_WAIT_MS: u64 = 300;

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

struct MixSource {
    queue: VecDeque<i16>,
    finished: bool,
    started: bool,
    first_seen: Instant,
}

impl MixSource {
    fn new() -> Self {
        Self { queue: VecDeque::new(), finished: false, started: false, first_seen: Instant::now() }
    }
}

/// Spawns the one persistent audio-output thread for the process: opens a
/// single `cpal` output stream lazily on first use and keeps it open for
/// the rest of the session, rather than per message - repeatedly opening
/// concurrent output streams against the same device is a common cause of
/// ALSA/dmix failing with "unable to open slave". Every playback source -
/// live stream chunks and whole-clip history replay alike - goes through
/// this one mixer, so multiple simultaneous sources (e.g. two people
/// using push-to-talk near-simultaneously) actually mix together instead
/// of queuing behind one another.
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
                match try_open_mixer_stream(sources.clone(), on_stream_error.clone(), on_finished.clone()) {
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
            match cmd {
                MixerCmd::Push { id, samples } => {
                    let resampled = resample(&samples, SAMPLE_RATE_HZ, out_rate);
                    sources.lock().unwrap().entry(id).or_insert_with(MixSource::new).queue.extend(resampled);
                }
                MixerCmd::Finish { id } => {
                    let mut map = sources.lock().unwrap();
                    match map.get_mut(&id) {
                        Some(src) => src.finished = true,
                        // Finish with no prior Push (an empty clip, or a
                        // stream that ended before its first chunk) -
                        // insert an already-finished, empty placeholder;
                        // `mix_output` drops it on the next callback tick.
                        None => {
                            map.insert(id, MixSource { finished: true, ..MixSource::new() });
                        }
                    }
                }
                MixerCmd::Stop { id } => {
                    // Dropped outright, not just marked finished - a
                    // finished-but-not-yet-drained source would still play
                    // out its queued tail; Stop means silence right away.
                    sources.lock().unwrap().remove(&id);
                }
            }
        }
    });
    tx
}

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
                move |data: &mut [i16], _| mix_output(data, out_channels, out_rate, &sources_cb, &on_finished_cb, |s| s),
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
                    mix_output(data, out_channels, out_rate, &sources_cb, &on_finished_cb, |s| s as f32 / i16::MAX as f32)
                },
                move |err| on_stream_error(err.to_string()),
                None,
            )
        }
        _ => return Err(VoiceError::UnsupportedFormat),
    }
    .map_err(|e| VoiceError::Device(e.to_string()))?;

    stream.play().map_err(|e| VoiceError::Device(e.to_string()))?;
    Ok((stream, out_rate))
}

/// Sums every jitter-buffer-ready source into one output frame, clamping
/// to avoid wraparound distortion when multiple sources overlap loudly,
/// and duplicates the mixed mono sample across every output channel -
/// output devices are very often stereo-or-more even though sources are
/// always mono. Runs on cpal's realtime callback thread, so it only pops
/// pre-resampled samples and sums - no allocation, no resampling here.
fn mix_output<T: Copy>(
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
                let waited_enough = src.first_seen.elapsed().as_millis() as u64 >= JITTER_MAX_WAIT_MS;
                if src.finished || queued_ms >= JITTER_PREBUFFER_MS || waited_enough {
                    src.started = true;
                }
            }
            if src.started && let Some(s) = src.queue.pop_front() {
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
