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
use std::sync::atomic::{AtomicU8, Ordering};
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

/// Whether a capture device's name says it is an echo-cancelling source -
/// PulseAudio/PipeWire's `module-echo-cancel` source, or a driver that
/// exposes a hardware-cancelled endpoint.
///
/// Preferring one of these is the best echo fix available, because it is
/// real cancellation: it subtracts the known playback signal out of the
/// capture instead of merely attenuating everything
/// (`EchoDucker`), so the call stays full duplex. Matched by name because
/// no audio API here reports the property directly, and narrowly enough
/// ("echo cancel", however spelled) that it cannot plausibly select a
/// device the user did not mean.
pub fn is_echo_cancelling_device(name: &str) -> bool {
    let name: String = name
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    name.contains("echocancel")
}

/// The `module-echo-cancel` source name to try before falling back to the
/// default one. PulseAudio's own default for the module, and what
/// PipeWire's pulse shim uses too.
pub const PULSE_ECHO_CANCEL_SOURCE: &str = "echo-cancel-source";

/// How much audio one device period should hold, capture and playback
/// alike. Every backend here asks for this explicitly rather than taking
/// what the device offers by default: a default ALSA period is commonly
/// tens of milliseconds and a default `pa_simple` playback target latency
/// far more than that, and both sit directly in the path between someone
/// speaking and someone hearing it. Small enough to keep that cost down,
/// comfortably above the point where an ordinary desktop starts underrunning.
pub const DEVICE_BUFFER_MS: u32 = 20;

/// How many frames `DEVICE_BUFFER_MS` is at `rate`, clamped into the range
/// the device actually supports. `None` when the device publishes no range
/// at all, which means the caller should leave the backend on its own
/// default rather than guess a number the device may reject.
pub fn device_buffer_frames(rate: u32, range: Option<(u32, u32)>) -> Option<u32> {
    let (min, max) = range?;
    let (lo, hi) = (min.min(max), min.max(max));
    Some(((rate * DEVICE_BUFFER_MS) / 1000).clamp(lo, hi))
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

/// `device_buffer_frames` for a cpal device, translating its reported
/// support into the plain range that function takes.
#[cfg(not(target_env = "musl"))]
fn requested_buffer_size(supported: &cpal::SupportedBufferSize, rate: u32) -> Option<u32> {
    let range = match supported {
        cpal::SupportedBufferSize::Range { min, max } => Some((*min, *max)),
        cpal::SupportedBufferSize::Unknown => None,
    };
    device_buffer_frames(rate, range)
}

/// Builds a stream at `DEVICE_BUFFER_MS`, falling back to the device's own
/// default period if that is refused. `build` is called at most twice and
/// must therefore make its own copies of whatever it captures.
#[cfg(not(target_env = "musl"))]
fn build_with_buffer_fallback(
    base: &StreamConfig,
    frames: Option<u32>,
    mut build: impl FnMut(StreamConfig) -> std::result::Result<cpal::Stream, cpal::Error>,
) -> std::result::Result<cpal::Stream, cpal::Error> {
    if let Some(frames) = frames {
        let mut cfg = *base;
        cfg.buffer_size = cpal::BufferSize::Fixed(frames);
        if let Ok(stream) = build(cfg) {
            return Ok(stream);
        }
    }
    build(*base)
}

/// The capture device to use, and whether it cancels echo itself. An
/// echo-cancelling source wins over the `prefer_pulse` choice: it solves
/// the problem `EchoDucker` only mitigates, and solves it without costing
/// full duplex.
#[cfg(not(target_env = "musl"))]
fn preferred_input_device(host: &cpal::Host) -> Option<(cpal::Device, bool)> {
    let mut devices: Vec<cpal::Device> = host.input_devices().ok().into_iter().flatten().collect();
    let cancelling = devices.iter().position(|d| {
        d.description()
            .is_ok_and(|desc| is_echo_cancelling_device(desc.name()))
    });
    if let Some(pos) = cancelling {
        return Some((devices.swap_remove(pos), true));
    }
    prefer_pulse(devices.into_iter(), host.default_input_device()).map(|d| (d, false))
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

// ---------------------------------------------------------------------
// Live chunk codec (IMA ADPCM, 4:1)
// ---------------------------------------------------------------------
//
// Raw PCM at `SAMPLE_RATE_HZ` is 256kbit/s in each direction. A live call
// is a full mesh with no server in the middle (`docs/PROTOCOL.md` 7.7), so
// one participant sends that separately to every other participant: four
// other people is a megabit per second of upstream, continuously. Typical
// home upstream does not have it, and what happens when it does not is not
// a clean failure - the bottleneck queues instead, which is delay, and the
// delay grows for as long as the call lasts.
//
// So live chunks travel compressed. IMA ADPCM is 4 bits per sample - a flat
// 4:1, 256kbit/s down to 64 - and is chosen over a modern speech codec
// (Opus would manage 24kbit/s at better quality) for one specific reason:
// every Opus binding is a wrapper around libopus, and a native library here
// is not one dependency line. It is a hand-written static cross-build per
// target in `Cross.toml`, which is what libasound, libpulse, libsndfile and
// libltdl each already cost, and the reason `Cargo.toml` picks rustls'
// `ring` provider over `aws-lc-rs`. ADPCM is forty lines of arithmetic with
// no dependency at all, and 4:1 is the difference between a four-person
// call fitting in an ordinary uplink and not.
//
// Each chunk is decoded standalone - it carries its own predictor and step
// index rather than continuing the previous chunk's - because chunks travel
// unreliably (`p2p::send_unreliable_voice`) and one that is lost or
// reordered must not corrupt every chunk after it. The cost is the 4-byte
// header below and a slightly worse first sample per chunk; the benefit is
// that packet loss stays a moment of loss instead of a broken stream.

/// Codec tag in byte 0 of every live voice chunk. Present so a chunk is
/// self-describing on the wire, and so a future codec can be told apart
/// from this one rather than decoded as garbage.
pub const VOICE_CODEC_ADPCM: u8 = 1;

/// tag (1) + step index and odd-length flag (1) + initial predictor (2).
pub const VOICE_CHUNK_HEADER_BYTES: usize = 4;

/// Step sizes IMA ADPCM's index walks, and how each 4-bit code moves that
/// index. Both are the fixed tables from the IMA/DVI specification - they
/// are the format, not a tuning choice.
const IMA_STEP_TABLE: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

const IMA_INDEX_TABLE: [i32; 16] = [
    -1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8,
];

/// Applies one 4-bit code to the running state, returning the sample it
/// reconstructs. The single source of truth for what a code means: the
/// encoder advances its own state by calling this too, so encoder and
/// decoder predictors cannot drift apart no matter what the input is.
fn ima_apply(code: u8, predictor: &mut i32, index: &mut i32) -> i16 {
    let step = IMA_STEP_TABLE[*index as usize];
    let mut diff = step >> 3;
    if code & 4 != 0 {
        diff += step;
    }
    if code & 2 != 0 {
        diff += step >> 1;
    }
    if code & 1 != 0 {
        diff += step >> 2;
    }
    if code & 8 != 0 {
        *predictor -= diff;
    } else {
        *predictor += diff;
    }
    *predictor = (*predictor).clamp(i16::MIN as i32, i16::MAX as i32);
    *index = (*index + IMA_INDEX_TABLE[(code & 15) as usize]).clamp(0, 88);
    *predictor as i16
}

/// Chooses the 4-bit code that best approximates `sample`, then advances
/// the state through `ima_apply` exactly as the decoder will.
fn ima_encode(sample: i16, predictor: &mut i32, index: &mut i32) -> u8 {
    let step = IMA_STEP_TABLE[*index as usize];
    let mut diff = sample as i32 - *predictor;
    let mut code: u8 = 0;
    if diff < 0 {
        code = 8;
        diff = -diff;
    }
    let mut threshold = step;
    let mut bit: u8 = 4;
    for _ in 0..3 {
        if diff >= threshold {
            code |= bit;
            diff -= threshold;
        }
        threshold >>= 1;
        bit >>= 1;
    }
    ima_apply(code, predictor, index);
    code
}

/// The step index to start a chunk at, chosen from the chunk's own average
/// sample-to-sample movement.
///
/// This matters far more than it looks. ADPCM's step index normally adapts
/// over a continuous stream, but every chunk here decodes standalone, so
/// each one would otherwise restart from the smallest step in the table and
/// spend its first samples climbing - a burst of distortion at the start of
/// every chunk, 66 times a second, which is a buzz rather than an
/// occasional artefact. Starting where the chunk actually is worth roughly
/// 16dB of signal-to-noise on speech-like input, and costs nothing on the
/// wire: the header already carries the index, because the decoder always
/// had to be told where to start.
fn seed_step_index(samples: &[i16]) -> i32 {
    if samples.len() < 2 {
        return 0;
    }
    let total: i64 = samples
        .windows(2)
        .map(|w| (w[1] as i64 - w[0] as i64).abs())
        .sum();
    let mean = total / (samples.len() - 1) as i64;
    IMA_STEP_TABLE
        .iter()
        .position(|step| *step as i64 >= mean)
        .unwrap_or(IMA_STEP_TABLE.len() - 1) as i32
}

/// Encodes one chunk of mono PCM16 for the wire. The first sample is
/// carried verbatim in the header and is reproduced exactly; every sample
/// after it costs 4 bits.
pub fn encode_voice_chunk(samples: &[i16]) -> Vec<u8> {
    if samples.is_empty() {
        return Vec::new();
    }
    let mut predictor = samples[0] as i32;
    let seed = seed_step_index(samples);
    let mut index = seed;
    let coded = &samples[1..];
    let odd = coded.len() % 2 == 1;
    let mut out = Vec::with_capacity(VOICE_CHUNK_HEADER_BYTES + coded.len().div_ceil(2));
    out.push(VOICE_CODEC_ADPCM);
    // The step index is 0-88, so its byte has a spare top bit; it carries
    // whether the final byte holds one sample or two, which is otherwise
    // unrecoverable from a nibble count.
    out.push(seed as u8 | if odd { 0x80 } else { 0 });
    out.extend_from_slice(&samples[0].to_le_bytes());
    for pair in coded.chunks(2) {
        let lo = ima_encode(pair[0], &mut predictor, &mut index);
        let hi = match pair.get(1) {
            Some(&s) => ima_encode(s, &mut predictor, &mut index),
            None => 0,
        };
        out.push(lo | (hi << 4));
    }
    out
}

/// Decodes a chunk produced by `encode_voice_chunk` back to mono PCM16.
///
/// `None` for anything this does not recognise - a truncated payload, an
/// unknown codec tag, an out-of-range step index. This decodes attacker-
/// controlled network input, so every field is checked before it is used
/// (`IMA_STEP_TABLE` is indexed by it) rather than trusted.
pub fn decode_voice_chunk(bytes: &[u8]) -> Option<Vec<i16>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if bytes.len() < VOICE_CHUNK_HEADER_BYTES || bytes[0] != VOICE_CODEC_ADPCM {
        return None;
    }
    let odd = bytes[1] & 0x80 != 0;
    let mut index = (bytes[1] & 0x7f) as i32;
    if index > 88 {
        return None;
    }
    let first = i16::from_le_bytes([bytes[2], bytes[3]]);
    let payload = &bytes[VOICE_CHUNK_HEADER_BYTES..];
    let mut predictor = first as i32;
    let mut out = Vec::with_capacity(1 + payload.len() * 2);
    out.push(first);
    for (i, byte) in payload.iter().enumerate() {
        out.push(ima_apply(byte & 0x0f, &mut predictor, &mut index));
        let last = i + 1 == payload.len();
        if !(last && odd) {
            out.push(ima_apply(byte >> 4, &mut predictor, &mut index));
        }
    }
    Some(out)
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

/// `level_from_pcm` from an already-accumulated sum of squares - what the
/// realtime mix callback can afford, since it is summing samples anyway
/// and must not walk them a second time.
pub fn level_from_sum_sq(sum_sq: u64, count: u64) -> u8 {
    if count == 0 {
        return 0;
    }
    let rms = (sum_sq as f64 / count as f64).sqrt();
    ((rms / LEVEL_FULL_SCALE_RMS) * 100.0).round().clamp(0.0, 100.0) as u8
}

// ---------------------------------------------------------------------
// Echo control
// ---------------------------------------------------------------------

/// How loud the speakers are right now, as a `level_from_pcm` reading,
/// published by whichever mixer backend is running and read by the capture
/// workers for echo ducking.
///
/// A process-wide static rather than a value threaded through, because the
/// thing it describes is process-wide: there is exactly one output stream
/// for the whole session by construction (see `spawn_mixer`), and the
/// capture side does not care which sources it is made of. Relaxed ordering
/// throughout - this is an advisory level meter feeding a smoothed gain,
/// and a reader that sees a value one chunk stale is indistinguishable from
/// one that read a chunk earlier.
static PLAYBACK_LEVEL: AtomicU8 = AtomicU8::new(0);

pub fn publish_playback_level(level: u8) {
    PLAYBACK_LEVEL.store(level, Ordering::Relaxed);
}

pub fn playback_level() -> u8 {
    PLAYBACK_LEVEL.load(Ordering::Relaxed)
}

/// Playback level above which remote audio is treated as audible in the
/// room, and so as something the microphone is about to pick up again.
/// Just above the mixer's idle reading rather than at it, so dither and a
/// source's trailing silence don't hold the duck open indefinitely.
pub const ECHO_DUCK_TRIGGER_LEVEL: u8 = 3;

/// What the microphone is attenuated to while remote audio is playing:
/// -18dB. Attenuation rather than a hard gate, deliberately - the room has
/// already attenuated what it echoes back, so this puts the echo under the
/// noise floor, while someone who actually talks over the other side is
/// still audible instead of being cut out entirely.
pub const ECHO_DUCK_GAIN: f32 = 0.12;

/// Per-chunk fraction of the remaining distance to the target gain. Ducking
/// in is several times faster than coming back out: arriving late means
/// leaking a burst of echo, while leaving late costs only a slightly quiet
/// first syllable. At `CHUNK_INTERVAL` these are roughly 75ms down and
/// 750ms back up.
pub const ECHO_DUCK_ATTACK: f32 = 0.35;
pub const ECHO_DUCK_RELEASE: f32 = 0.06;

/// How much louder the microphone must read while the far end is talking
/// than while they are not, before the difference is judged to be the
/// speakers rather than coincidence. Two thresholds rather than one so the
/// decision has hysteresis and cannot flap chunk to chunk.
pub const ECHO_EVIDENCE_ENGAGE: f32 = 4.0;
pub const ECHO_EVIDENCE_RELEASE: f32 = 2.0;

/// How many chunks of *each* kind (far end talking, far end quiet) must be
/// observed before the probe will conclude anything. Roughly a second of
/// each at `CHUNK_INTERVAL`.
pub const ECHO_EVIDENCE_MIN_OBSERVATIONS: u32 = 64;

/// Weight of one new observation against the running average - a time
/// constant of roughly 50 chunks, long enough to average over whole talk
/// spurts rather than react to one loud syllable.
pub const ECHO_PROBE_SMOOTHING: f32 = 0.02;

/// Decides, from the audio itself, whether the microphone can actually hear
/// the speakers - so nobody has to tell the app whether they are wearing
/// headphones.
///
/// The trick is that *detecting* an echo path is a far smaller problem than
/// cancelling one. Cancellation needs the playback signal aligned to the
/// capture sample by sample, across two devices with independent clocks,
/// which is what makes it a native-library job. Detection only needs the
/// two loudness envelopes at chunk resolution, where alignment does not
/// matter at all: a talk spurt lasts seconds and the echo of it arrives
/// within a fraction of one.
///
/// So the microphone's own level is averaged separately over the chunks
/// where the far end is talking and the chunks where they are not. On
/// speakers the first average sits above the second, because the microphone
/// is picking their voice up. On headphones the two match. Our *own* speech
/// lands in both populations equally - we do not arrange our talking around
/// theirs - so it contributes to both averages and drops out of the
/// difference.
///
/// Two properties matter for this not to fool itself:
///
///   * it must observe the capture level from *before* `EchoDucker` has
///     attenuated it, or ducking would suppress the very evidence it is
///     judged by, the difference would collapse, ducking would release, and
///     the echo would come back - forever, at whatever period the loop
///     settles into; and
///   * it starts out ducking. The safe assumption before there is evidence
///     is the one whose failure is heard by everybody else in the call
///     rather than only by us, so headphones cost a second or two of
///     unnecessary ducking at the start and speakers cost nothing.
///
/// Its blind spot is someone who only ever talks at the same time as the
/// far end, which stops the two populations separating. That is what
/// `settings::EchoDucking::On`/`Off` are for.
pub struct EchoProbe {
    /// Mean capture level while the far end is talking, and while not.
    loud: f32,
    quiet: f32,
    loud_n: u32,
    quiet_n: u32,
    ducking: bool,
}

impl EchoProbe {
    pub fn new() -> Self {
        Self {
            loud: 0.0,
            quiet: 0.0,
            loud_n: 0,
            quiet_n: 0,
            // Ducking until the audio says otherwise - see the doc above.
            ducking: true,
        }
    }

    /// Feeds one chunk in. `capture_level` must be the level *before* any
    /// ducking was applied to it.
    pub fn observe(&mut self, capture_level: u8, playback_level: u8) {
        let capture = capture_level as f32;
        if playback_level > ECHO_DUCK_TRIGGER_LEVEL {
            accumulate(&mut self.loud, &mut self.loud_n, capture);
        } else {
            accumulate(&mut self.quiet, &mut self.quiet_n, capture);
        }
        if self.loud_n < ECHO_EVIDENCE_MIN_OBSERVATIONS
            || self.quiet_n < ECHO_EVIDENCE_MIN_OBSERVATIONS
        {
            return;
        }
        let excess = self.loud - self.quiet;
        if self.ducking {
            self.ducking = excess >= ECHO_EVIDENCE_RELEASE;
        } else {
            self.ducking = excess > ECHO_EVIDENCE_ENGAGE;
        }
    }

    /// Whether the microphone currently appears to be hearing the speakers.
    pub fn should_duck(&self) -> bool {
        self.ducking
    }

    /// How much louder the microphone reads while the far end is talking -
    /// the quantity the decision is made on, exposed for tests and for
    /// anyone diagnosing a room this gets wrong.
    pub fn excess_level(&self) -> f32 {
        self.loud - self.quiet
    }
}

impl Default for EchoProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Running mean that takes its first observation whole rather than easing
/// up from zero - without it the first `1/ECHO_PROBE_SMOOTHING` chunks of
/// each population read far too low, and the two populations warm up at
/// different rates depending on who happened to talk first.
fn accumulate(mean: &mut f32, count: &mut u32, value: f32) {
    if *count == 0 {
        *mean = value;
    } else {
        *mean += (value - *mean) * ECHO_PROBE_SMOOTHING;
    }
    *count = count.saturating_add(1);
}

/// Attenuates captured audio while the speakers are playing remote audio,
/// so the microphone does not send the other side their own voice back.
///
/// This is ducking, not cancellation: it does not model the room, and it
/// cannot subtract a known signal out of the capture the way a real
/// acoustic echo canceller does. What it does do is make the echo path lose
/// far more than it gains, which is what stops the loop - and it needs no
/// clock alignment between capture and playback, no adaptive filter, and no
/// native dependency. Headphones remain strictly better, and the setting
/// that turns this off (`voice_echo_ducking`) is there for people using
/// them.
pub struct EchoDucker {
    gain: f32,
}

impl EchoDucker {
    pub fn new() -> Self {
        Self { gain: 1.0 }
    }

    pub fn gain(&self) -> f32 {
        self.gain
    }

    /// Advances the gain one chunk towards what `playback_level` calls for
    /// and applies it across `samples` in place, ramping from the previous
    /// chunk's gain to this one's rather than stepping - a step between
    /// chunks is a discontinuity, and a discontinuity 66 times a second is
    /// an audible buzz.
    pub fn process(&mut self, samples: &mut [i16], playback_level: u8) {
        let target = if playback_level > ECHO_DUCK_TRIGGER_LEVEL {
            ECHO_DUCK_GAIN
        } else {
            1.0
        };
        let step = if target < self.gain {
            ECHO_DUCK_ATTACK
        } else {
            ECHO_DUCK_RELEASE
        };
        let from = self.gain;
        let to = from + (target - from) * step;
        self.gain = to;
        if samples.is_empty() || (from >= 1.0 && to >= 1.0) {
            return;
        }
        let n = samples.len() as f32;
        for (i, s) in samples.iter_mut().enumerate() {
            let g = from + (to - from) * (i as f32 / n);
            *s = ((*s as f32) * g).clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        }
    }
}

impl Default for EchoDucker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------
// Silence suppression
// ---------------------------------------------------------------------

/// Level at or below which a captured chunk is treated as silence worth not
/// sending at all.
pub const SILENCE_LEVEL: u8 = 2;

/// How long sending continues after the last chunk that was above
/// `SILENCE_LEVEL`. Without it, the quiet moments *inside* speech - the
/// closure before a plosive, the gap between words - would each cut the
/// stream, and the receiver would spend the whole conversation rebuilding
/// its prebuffer instead of playing.
pub const SILENCE_HANGOVER: Duration = Duration::from_millis(240);

/// Decides which captured chunks are worth putting on the wire at all.
///
/// Used on a *call* only, and deliberately not on a push-to-talk voice
/// message: a call is a real-time stream where an unsent chunk is simply a
/// moment nobody was speaking, while a voice message is a recording that
/// the receiver reassembles chunk by chunk into something replayable, so
/// dropping its silence would shorten the message and pull the audio either
/// side of a pause together.
pub struct SilenceGate {
    hangover_left: Duration,
}

impl SilenceGate {
    pub fn new() -> Self {
        Self {
            hangover_left: Duration::ZERO,
        }
    }

    /// Whether a chunk covering `chunk` of audio, measuring `level`, should
    /// be sent.
    pub fn should_send(&mut self, level: u8, chunk: Duration) -> bool {
        if level > SILENCE_LEVEL {
            self.hangover_left = SILENCE_HANGOVER;
            return true;
        }
        if self.hangover_left.is_zero() {
            return false;
        }
        self.hangover_left = self.hangover_left.saturating_sub(chunk);
        true
    }
}

impl Default for SilenceGate {
    fn default() -> Self {
        Self::new()
    }
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
    echo_cancelled: bool,
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
    pub fn start(on_stream_error: impl Fn(String) + Send + Sync + 'static) -> Result<Self> {
        let host = cpal::default_host();
        let (device, echo_cancelled) = preferred_input_device(&host).ok_or(VoiceError::NoDevice)?;
        let config = device
            .default_input_config()
            .map_err(|e| VoiceError::Device(e.to_string()))?;
        let sample_rate = config.sample_rate();
        let sample_format = config.sample_format();
        // Interleaved frames must be averaged down to mono right here -
        // see `downmix_i16_to_mono`'s doc for what goes wrong otherwise.
        let channels = config.channels();
        let requested = requested_buffer_size(config.buffer_size(), sample_rate);
        let stream_config: StreamConfig = config.into();

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let buf = buffer.clone();

        if !matches!(sample_format, SampleFormat::I16 | SampleFormat::F32) {
            return Err(VoiceError::UnsupportedFormat);
        }
        let on_stream_error = Arc::new(on_stream_error);

        // Tried with an explicit period first and again on the device's own
        // default if that is refused: a fixed size is not universally
        // honoured (some ALSA devices, and every host that reports
        // `SupportedBufferSize::Unknown`), and capture working at a worse
        // latency beats capture not starting.
        let stream = build_with_buffer_fallback(&stream_config, requested, |cfg: StreamConfig| {
            let buf = buf.clone();
            let on_err = on_stream_error.clone();
            match sample_format {
                SampleFormat::F32 => device.build_input_stream(
                    cfg,
                    move |data: &[f32], _| {
                        buf.lock()
                            .unwrap()
                            .extend(downmix_f32_to_mono_i16(data, channels));
                    },
                    move |err| on_err(err.to_string()),
                    None,
                ),
                _ => device.build_input_stream(
                    cfg,
                    move |data: &[i16], _| {
                        buf.lock()
                            .unwrap()
                            .extend(downmix_i16_to_mono(data, channels));
                    },
                    move |err| on_err(err.to_string()),
                    None,
                ),
            }
        })
        .map_err(|e| VoiceError::Device(e.to_string()))?;

        stream
            .play()
            .map_err(|e| VoiceError::Device(e.to_string()))?;

        Ok(Self {
            stream,
            buffer,
            sample_rate,
            echo_cancelled,
        })
    }

    /// Whether this recorder's device cancels echo itself, in which case
    /// `EchoDucker` is redundant and its cost to full duplex is not worth
    /// paying (see `is_echo_cancelling_device`).
    pub fn echo_cancelled(&self) -> bool {
        self.echo_cancelled
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

// ---------------------------------------------------------------------
// Jitter buffer policy
// ---------------------------------------------------------------------
//
// A live source (a call participant, or a push-to-talk stream still being
// spoken) is played out against the *output device's* clock, while it is
// filled from the network against the *sender's* capture clock. Nothing
// synchronises the two, so the queue between them is where every timing
// difference in the system accumulates: a network stall, a scheduling
// hiccup on either end, or plain crystal drift between two sound cards all
// leave audio sitting in it. Whatever sits in that queue *is* the delay the
// listener hears, and without the two rules below it is monotonic - every
// hiccup adds to it and nothing ever takes it away, which is what made a
// long call drift steadily further behind.
//
// So the queue is managed from both ends:
//
//   * it may not grow past `overflow_drop_samples` (the ceiling), and audio
//     beyond that is dropped rather than played late - a momentary artefact
//     instead of a permanent delay; and
//   * the prebuffer each source waits for before it starts is adaptive
//     (`grown_prebuffer`/`decayed_prebuffer`) rather than a fixed worst
//     case, so a clean path pays a small delay and only a path that
//     actually stutters pays a large one.
//
// A `finished` source - a whole received voice message being replayed, or a
// live stream whose `StreamEnd` already arrived - is exempt from all of it.
// It is a recording, not a real-time stream: there is no "late" to be, its
// queue is the message itself rather than accumulated delay, and trimming
// it would silently cut audio out of a message the user asked to hear.

/// Where a live source's prebuffer target starts, and the floor it decays
/// back to. Small enough that a clean path (a LAN, or two peers a few
/// milliseconds apart) is not made to sound distant for nothing; a path
/// that genuinely stutters grows its own target from here.
pub const JITTER_PREBUFFER_MIN_MS: u64 = 60;

/// Ceiling on the adaptive prebuffer target. Past this the delay is worse
/// than the gap it is buying, so a source that keeps underrunning is left
/// to underrun rather than pushed further and further behind.
pub const JITTER_PREBUFFER_MAX_MS: u64 = 400;

/// How much a source's prebuffer target grows on each underrun, and how
/// much it gives back after `JITTER_DECAY_INTERVAL` of clean playback.
/// Growth is deliberately several times the decay: the cost of growing too
/// slowly is an audible gap, the cost of decaying too slowly is a few tens
/// of milliseconds of delay for a few more seconds.
pub const JITTER_PREBUFFER_GROWTH_MS: u64 = 40;
pub const JITTER_PREBUFFER_DECAY_MS: u64 = 20;

/// How long a source must play without underrunning before it gives back
/// one `JITTER_PREBUFFER_DECAY_MS` step of prebuffer.
pub const JITTER_DECAY_INTERVAL: Duration = Duration::from_secs(5);

/// How long a source waits for its prebuffer target before starting
/// anyway. Bounds the damage when a sender stops talking mid-fill (with
/// silence suppression on a call, an ordinary event) - the queue would
/// otherwise sit unplayed until they spoke again.
pub const JITTER_MAX_WAIT_MS: u64 = 300;

/// How far past its prebuffer target a live source's queue may run before
/// `overflow_drop_samples` trims it back. Has to be well clear of the
/// target itself, or ordinary burstiness (several chunks arriving in one
/// scheduling slice, which is normal) would trim on every push and chop
/// audio continuously.
pub const JITTER_QUEUE_SLACK_MS: u64 = 120;

/// Duration of `samples` mono samples at `rate`, in whole milliseconds.
pub fn samples_to_ms(samples: usize, rate: u32) -> u64 {
    (samples as u64 * 1000) / rate.max(1) as u64
}

/// How many mono samples at `rate` make up `ms` of audio.
pub fn ms_to_samples(ms: u64, rate: u32) -> usize {
    ((ms * rate as u64) / 1000) as usize
}

/// Whether a source holding `queued_ms` of audio, having waited `waited`
/// since it started filling, may begin playing. A `finished` source never
/// waits: its queue is a whole recording, and there is no more audio coming
/// for a prebuffer to fill with.
pub fn jitter_ready_to_start(
    queued_ms: u64,
    waited: Duration,
    finished: bool,
    prebuffer_ms: u64,
) -> bool {
    finished || queued_ms >= prebuffer_ms || waited.as_millis() as u64 >= JITTER_MAX_WAIT_MS
}

/// The prebuffer target after an underrun - one growth step, capped.
pub fn grown_prebuffer(current_ms: u64) -> u64 {
    (current_ms + JITTER_PREBUFFER_GROWTH_MS).min(JITTER_PREBUFFER_MAX_MS)
}

/// The prebuffer target after `since_underrun` of playback with nothing
/// going wrong, or `None` when it is not yet time to give anything back
/// (or there is nothing left to give). Returning `None` rather than an
/// unchanged value is what lets the caller know whether to restart its
/// decay clock, so a source at the floor doesn't spin.
pub fn decayed_prebuffer(current_ms: u64, since_underrun: Duration) -> Option<u64> {
    if since_underrun < JITTER_DECAY_INTERVAL || current_ms <= JITTER_PREBUFFER_MIN_MS {
        return None;
    }
    Some(current_ms.saturating_sub(JITTER_PREBUFFER_DECAY_MS).max(JITTER_PREBUFFER_MIN_MS))
}

/// How many samples to drop off the front of a live source's queue holding
/// `queued` samples at `rate`. Zero until the queue passes its prebuffer
/// target plus `JITTER_QUEUE_SLACK_MS`; past that, enough to bring it back
/// to the target exactly.
///
/// Dropping is deliberate, and dropping from the *front* especially so.
/// Audio that has fallen this far behind is audio the listener would hear
/// late, and every later sample behind it later still - keeping it trades a
/// moment's artefact for a delay that never goes away. The front is what is
/// oldest and therefore most stale.
pub fn overflow_drop_samples(queued: usize, rate: u32, prebuffer_ms: u64) -> usize {
    let queued_ms = samples_to_ms(queued, rate);
    if queued_ms <= prebuffer_ms + JITTER_QUEUE_SLACK_MS {
        return 0;
    }
    queued.saturating_sub(ms_to_samples(prebuffer_ms, rate))
}

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

/// One playback source's jitter buffer: the audio queued for it, and the
/// adaptive state that decides when it starts and how much of a backlog it
/// is allowed to carry (see the jitter buffer policy section above).
///
/// `pub` rather than crate-private purely so the mixing behaviour built on
/// it is reachable from the test suite: `mix_output` and `apply_mixer_cmd`
/// are pure over a source map, so everything except the device itself can
/// be driven directly (`test/voice_test.rs`), which is what stops the
/// latency management here from silently regressing.
pub struct MixSource {
    queue: VecDeque<i16>,
    finished: bool,
    started: bool,
    /// When the current wait for a prebuffer began - reset on every
    /// underrun, not just at creation, since each talk spurt gets its own
    /// wait (see `note_underrun`).
    waiting_since: Instant,
    /// This source's own current prebuffer target, adapted to the path it
    /// is actually seeing rather than fixed at a worst case.
    prebuffer_ms: u64,
    /// When this source last underran (or was created), which is what
    /// `decayed_prebuffer` measures "clean playback" from.
    last_underrun: Instant,
}

impl MixSource {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            queue: VecDeque::new(),
            finished: false,
            started: false,
            waiting_since: now,
            prebuffer_ms: JITTER_PREBUFFER_MIN_MS,
            last_underrun: now,
        }
    }

    /// A `Finish` with no prior `Push` (an empty clip, or a stream that
    /// ended before its first chunk) - already-finished and empty, so
    /// `mix_output` drops it on the next tick.
    pub fn new_finished() -> Self {
        Self {
            finished: true,
            ..Self::new()
        }
    }

    pub fn extend(&mut self, samples: &[i16]) {
        self.queue.extend(samples);
    }

    pub fn mark_finished(&mut self) {
        self.finished = true;
    }

    pub fn queued_samples(&self) -> usize {
        self.queue.len()
    }

    pub fn prebuffer_ms(&self) -> u64 {
        self.prebuffer_ms
    }

    pub fn started(&self) -> bool {
        self.started
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Everything that happens to a live source when audio is added to it:
    /// give back a step of prebuffer if it has been playing cleanly for
    /// long enough, then trim any backlog past the ceiling. Returns how
    /// many samples were dropped, which is zero in the ordinary case.
    ///
    /// Runs on the *command* side rather than in `mix_output`, so the
    /// realtime output callback never pays for it: a push happens a few
    /// dozen times a second, an output frame tens of thousands of times.
    ///
    /// A `finished` source is left entirely alone - see the policy section.
    pub fn on_push(&mut self, out_rate: u32) -> usize {
        if self.finished {
            return 0;
        }
        if let Some(relaxed) = decayed_prebuffer(self.prebuffer_ms, self.last_underrun.elapsed()) {
            self.prebuffer_ms = relaxed;
            self.last_underrun = Instant::now();
        }
        let drop = overflow_drop_samples(self.queue.len(), out_rate, self.prebuffer_ms);
        if drop > 0 {
            self.queue.drain(..drop);
        }
        drop
    }

    /// Whether this source may hand out a sample on this output frame,
    /// starting it if its prebuffer is ready. Called once per source per
    /// frame from the realtime callback, so it does no more than the
    /// comparison it has to.
    fn ready(&mut self, out_rate: u32) -> bool {
        if !self.started
            && jitter_ready_to_start(
                samples_to_ms(self.queue.len(), out_rate),
                self.waiting_since.elapsed(),
                self.finished,
                self.prebuffer_ms,
            )
        {
            self.started = true;
        }
        self.started
    }

    /// A started live source ran out of audio: grow its prebuffer target
    /// and put it back to waiting, so the next talk spurt refills before it
    /// plays instead of stuttering its way through.
    ///
    /// Self-limiting despite running on the realtime thread - it clears
    /// `started`, so the frames that follow take the `ready` path instead
    /// and cannot grow the target again until the source has actually
    /// played and starved a second time.
    fn note_underrun(&mut self) {
        self.prebuffer_ms = grown_prebuffer(self.prebuffer_ms);
        self.started = false;
        let now = Instant::now();
        self.waiting_since = now;
        self.last_underrun = now;
    }
}

impl Default for MixSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Applies one `MixerCmd` to the shared source map - the command-handling
/// logic both the cpal and PulseAudio mixer backends share verbatim, so
/// their jitter-buffer/multi-source bookkeeping can never drift apart.
/// `out_rate` is the backend's actual output rate (device-negotiated for
/// cpal, always `SAMPLE_RATE_HZ` for `voice_pulse` since that backend asks
/// PulseAudio for `SAMPLE_RATE_HZ` directly), used to resample `Push`ed
/// audio once here rather than in every caller.
pub fn apply_mixer_cmd(
    sources: &Mutex<HashMap<u64, MixSource>>,
    out_rate: u32,
    cmd: MixerCmd,
) {
    match cmd {
        MixerCmd::Push { id, samples } => {
            let resampled = resample(&samples, SAMPLE_RATE_HZ, out_rate);
            let mut map = sources.lock().unwrap();
            let src = map.entry(id).or_default();
            src.extend(&resampled);
            // Where a live source's backlog - and so the delay the listener
            // hears - is bounded. See the jitter buffer policy section.
            src.on_push(out_rate);
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
    on_stream_error: impl Fn(String) + Send + Clone + 'static,
    on_finished: impl Fn(u64) + Send + Clone + 'static,
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
    if !matches!(sample_format, SampleFormat::I16 | SampleFormat::F32) {
        return Err(VoiceError::UnsupportedFormat);
    }
    let requested = requested_buffer_size(supported.buffer_size(), out_rate);
    let stream_config: StreamConfig = supported.into();

    // Same explicit-period-then-fall-back handling the capture side uses,
    // and it matters at least as much here: the output buffer is the last
    // thing between a decoded chunk and the speaker.
    let stream = build_with_buffer_fallback(&stream_config, requested, |cfg: StreamConfig| {
        let sources_cb = sources.clone();
        let on_finished_cb = on_finished.clone();
        let on_err = on_stream_error.clone();
        match sample_format {
            SampleFormat::F32 => device.build_output_stream(
                cfg,
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
                move |err| on_err(err.to_string()),
                None,
            ),
            _ => device.build_output_stream(
                cfg,
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
                move |err| on_err(err.to_string()),
                None,
            ),
        }
    })
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
pub fn mix_output<T: Copy>(
    data: &mut [T],
    out_channels: u16,
    out_rate: u32,
    sources: &Arc<Mutex<HashMap<u64, MixSource>>>,
    on_finished: &(impl Fn(u64) + Send + 'static),
    convert: impl Fn(i16) -> T,
) {
    let mut map = sources.lock().unwrap();
    let mut level_sum_sq: u64 = 0;
    let mut frames: u64 = 0;
    for frame in data.chunks_mut(out_channels as usize) {
        let mut sum: i32 = 0;
        for src in map.values_mut() {
            if !src.ready(out_rate) {
                continue;
            }
            match src.queue.pop_front() {
                Some(s) => sum += s as i32,
                // A started live source with nothing left to play has
                // fallen behind its sender: rebuild a prebuffer before the
                // next talk spurt rather than stuttering through it.
                None if !src.finished => src.note_underrun(),
                None => {}
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
        let mixed = sum.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
        level_sum_sq += (mixed as i64 * mixed as i64) as u64;
        frames += 1;
        let s = convert(mixed);
        for out in frame.iter_mut() {
            *out = s;
        }
    }
    // What the speakers are about to emit, published for the capture side's
    // echo ducking (`EchoDucker`). One multiply-add per frame here and one
    // atomic store per callback, rather than anything that could block the
    // realtime thread.
    publish_playback_level(level_from_sum_sq(level_sum_sq, frames));
}

#[cfg(target_env = "musl")]
pub use crate::client::voice_pulse::{Recorder, spawn_mixer};
