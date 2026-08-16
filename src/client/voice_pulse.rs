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

use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use tokio::sync::mpsc::UnboundedSender;

use crate::client::voice::{
    MixSource, MixerCmd, Result, SAMPLE_RATE_HZ, VoiceError, apply_mixer_cmd, mix_output,
    pcm_from_bytes, pcm_to_bytes,
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

/// How many mono PCM16 frames one `Simple::read`/`write` call moves - 20ms
/// worth. Small enough that `Recorder`'s `Drop` (which only sets a flag,
/// see below) is noticed promptly by the capture thread; there is no way
/// to cancel a blocked `pa_simple` call directly, so bounding each call's
/// duration is what keeps stop latency low instead.
fn chunk_frames() -> usize {
    (SAMPLE_RATE_HZ as usize) / 50
}

/// Captures microphone audio into an in-memory buffer while alive, the
/// same contract as `crate::client::voice`'s cpal-backed `Recorder` (re-exported
/// under that name on musl - see `voice.rs`).
pub struct Recorder {
    buffer: Arc<Mutex<Vec<i16>>>,
    stop: Arc<AtomicBool>,
}

impl Recorder {
    /// `on_stream_error` is called at most once, from the capture thread,
    /// if the connection to the server fails while already recording -
    /// mirroring the cpal backend's contract (see its `Recorder::start`
    /// doc comment for why this can't just be an `eprintln!`).
    pub fn start(on_stream_error: impl Fn(String) + Send + 'static) -> Result<Self> {
        let simple = Simple::new(
            None,
            "aloo",
            Direction::Record,
            None,
            "voice capture",
            &spec(),
            None,
            None,
        )
        .map_err(|e| VoiceError::Device(format!("{e}")))?;

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

        Ok(Self { buffer, stop })
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
            None,
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
