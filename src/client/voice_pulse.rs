//! `Recorder`/`spawn_mixer` for musl targets, talking to
//! PulseAudio/PipeWire directly via `libpulse` instead of
//! `crate::client::voice`'s `cpal`-on-ALSA backend.
//!
//! Why: cpal's ALSA backend only reaches PulseAudio/PipeWire through an
//! ALSA plugin that ALSA `dlopen()`s at runtime, and a fully static musl
//! binary can never `dlopen()` anything (musl hard-codes it to fail in a
//! static link - not fixable by installing alsa-plugins on the target).
//! Most distros route the *default* ALSA device through exactly that
//! shim, so a static ALSA binary can't do audio at all. Statically
//! linking `libpulse`/`libpulse-simple` themselves (built for musl in
//! `Cross.toml`) sidesteps the problem: the protocol client is simply
//! part of the binary. Every pure PCM/mixing helper (`resample`,
//! `mix_output`, `apply_mixer_cmd`, ...) is shared verbatim with the cpal
//! backend via `crate::client::voice`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use libpulse_binding::def::BufferAttr;
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use tokio::sync::mpsc::UnboundedSender;

use crate::client::voice::{
    DEVICE_BUFFER_MS, MixSource, MixerCmd, PULSE_ECHO_CANCEL_SOURCE, Result, SAMPLE_RATE_HZ,
    VoiceError, apply_mixer_cmd, mix_output, pcm_from_bytes, pcm_to_bytes,
};

/// Every stream this module opens is mono PCM16 at `SAMPLE_RATE_HZ` -
/// requested directly from the server rather than negotiated like cpal
/// does with a hardware device, so PulseAudio/PipeWire does any
/// rate-conversion itself and `crate::client::voice::resample` calls on this path
/// are no-ops (kept anyway for structural parity with the cpal backend,
/// and as a safety net if that ever stops being true).
fn spec() -> Spec {
    Spec {
        format: Format::S16le,
        channels: 1,
        rate: SAMPLE_RATE_HZ,
    }
}

/// Bytes one millisecond of this module's format occupies - mono PCM16 at
/// `SAMPLE_RATE_HZ`, so two bytes a frame.
const fn bytes_per_ms() -> u32 {
    (SAMPLE_RATE_HZ / 1000) * 2
}

/// Playback buffering, stated explicitly rather than left to the server's
/// default.
///
/// This matters more here than anywhere else in the audio path. `pa_simple`
/// with a null `BufferAttr` inherits the server's default target latency,
/// which is sized for gapless music playback and is routinely hundreds of
/// milliseconds - on a call it is pure delay between one person speaking
/// and another hearing it, and it dwarfed every other term in the budget.
/// `tlength` is the one that decides that: it is how much audio the server
/// tries to keep buffered ahead of the sink.
///
/// `NO_CHANGE` (`u32::MAX`) leaves a field at the server's default;
/// `maxlength` is left there deliberately, since capping it buys nothing
/// once `tlength` is set and only risks the write loop stalling.
fn playback_attr() -> BufferAttr {
    let period = bytes_per_ms() * DEVICE_BUFFER_MS;
    BufferAttr {
        maxlength: u32::MAX,
        tlength: period,
        // Start playing as soon as one period is in hand rather than
        // waiting for the buffer to fill.
        prebuf: period,
        minreq: period,
        fragsize: u32::MAX,
    }
}

/// Capture buffering: `fragsize` is the record-side counterpart of
/// `tlength`, deciding how much audio the server accumulates before handing
/// any of it over. Matched to `chunk_frames`, the amount one `read` moves.
fn capture_attr() -> BufferAttr {
    BufferAttr {
        maxlength: u32::MAX,
        tlength: u32::MAX,
        prebuf: u32::MAX,
        minreq: u32::MAX,
        fragsize: bytes_per_ms() * DEVICE_BUFFER_MS,
    }
}

/// How many mono PCM16 frames one `Simple::read`/`write` call moves - 20ms
/// worth. Small enough that `Recorder`'s `Drop` (which only sets a flag,
/// see below) is noticed promptly by the capture thread; there is no way
/// to cancel a blocked `pa_simple` call directly, so bounding each call's
/// duration is what keeps stop latency low instead.
fn chunk_frames() -> usize {
    ((SAMPLE_RATE_HZ * DEVICE_BUFFER_MS) / 1000) as usize
}

/// Captures microphone audio into an in-memory buffer while alive, the
/// same contract as `crate::client::voice`'s cpal-backed `Recorder` (re-exported
/// under that name on musl - see `voice.rs`).
pub struct Recorder {
    buffer: Arc<Mutex<Vec<i16>>>,
    stop: Arc<AtomicBool>,
    echo_cancelled: bool,
}

impl Recorder {
    /// `on_stream_error` is called at most once, from the capture thread,
    /// if the connection to the server fails while already recording -
    /// mirroring the cpal backend's contract (see its `Recorder::start`
    /// doc comment for why this can't just be an `eprintln!`).
    pub fn start(on_stream_error: impl Fn(String) + Send + Sync + 'static) -> Result<Self> {
        // `module-echo-cancel`'s source if the server has it loaded, the
        // default source otherwise. Real cancellation beats `EchoDucker`'s
        // attenuation outright, and asking costs one failed connect - the
        // module is not loaded by default anywhere, so the fallback is the
        // common path rather than the exception.
        let (simple, echo_cancelled) = match Simple::new(
            None,
            "aloo",
            Direction::Record,
            Some(PULSE_ECHO_CANCEL_SOURCE),
            "voice capture",
            &spec(),
            None,
            Some(&capture_attr()),
        ) {
            Ok(simple) => (simple, true),
            Err(_) => (
                Simple::new(
                    None,
                    "aloo",
                    Direction::Record,
                    None,
                    "voice capture",
                    &spec(),
                    None,
                    Some(&capture_attr()),
                )
                .map_err(|e| VoiceError::Device(format!("{e}")))?,
                false,
            ),
        };

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let buf = buffer.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();

        std::thread::spawn(move || {
            let mut raw = vec![0u8; chunk_frames() * 2];
            while !stop_thread.load(Ordering::Relaxed) {
                match simple.read(&mut raw) {
                    Ok(()) => buf.lock().unwrap().extend(pcm_from_bytes(&raw)),
                    Err(e) => {
                        on_stream_error(format!("{e}"));
                        break;
                    }
                }
            }
        });

        Ok(Self {
            buffer,
            stop,
            echo_cancelled,
        })
    }

    /// Whether capture is coming from `module-echo-cancel`'s source - the
    /// musl backend's counterpart of the cpal `Recorder`'s own
    /// `echo_cancelled`, with the same meaning for `EchoDucker`.
    pub fn echo_cancelled(&self) -> bool {
        self.echo_cancelled
    }

    /// Drains everything captured since the last call (or since `start`).
    /// Already at `SAMPLE_RATE_HZ` (see `spec`'s doc comment), so unlike
    /// the cpal backend this never actually resamples - it stays a plain
    /// drain for parity with that backend's contract.
    pub fn take_pending(&self) -> Vec<i16> {
        std::mem::take(&mut *self.buffer.lock().unwrap())
    }
}

impl Drop for Recorder {
    /// Only signals the capture thread; doesn't join it. The thread exits
    /// on its own within one `chunk_frames()` read (at most 20ms) and its
    /// only resources (the buffer `Arc`, the `Simple` connection) are
    /// cleaned up when it does - nothing here needs to block on that.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Spawns the one persistent audio-output thread for the process - same
/// contract as `crate::client::voice`'s cpal-backed `spawn_mixer` (see its
/// doc for why one persistent stream). Structurally different because of
/// how audio reaches the OS: cpal is callback-driven, while `pa_simple`'s
/// blocking `write` is pull-driven from a thread this function owns (the
/// block-until-buffer-space paces the loop like cpal's callback timing).
/// Command handling and mixing logic are shared
/// (`voice::apply_mixer_cmd`/`mix_output`).
pub fn spawn_mixer(
    on_stream_error: impl Fn(String) + Send + Clone + 'static,
    on_finished: impl Fn(u64) + Send + Clone + 'static,
) -> UnboundedSender<MixerCmd> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MixerCmd>();
    std::thread::spawn(move || {
        let sources: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));

        let simple = match Simple::new(
            None,
            "aloo",
            Direction::Playback,
            None,
            "voice playback",
            &spec(),
            None,
            Some(&playback_attr()),
        ) {
            Ok(s) => s,
            Err(e) => {
                // Mirrors the cpal backend's "device unavailable for the
                // rest of the session" behavior: report once and return
                // without spawning the writer thread or processing any
                // commands, rather than buffering into `sources` forever.
                on_stream_error(format!("{e}"));
                return;
            }
        };

        let writer_sources = sources.clone();
        let writer_on_finished = on_finished;
        let writer_on_error = on_stream_error;
        std::thread::spawn(move || {
            let mut buf = vec![0i16; chunk_frames()];
            loop {
                mix_output(
                    &mut buf,
                    1,
                    SAMPLE_RATE_HZ,
                    &writer_sources,
                    &writer_on_finished,
                    |s| s,
                );
                if let Err(e) = simple.write(&pcm_to_bytes(&buf)) {
                    writer_on_error(format!("{e}"));
                    break;
                }
            }
        });

        while let Some(cmd) = rx.blocking_recv() {
            apply_mixer_cmd(&sources, SAMPLE_RATE_HZ, cmd);
        }
    });
    tx
}
