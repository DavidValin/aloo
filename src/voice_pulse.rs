//! `Recorder`/`spawn_mixer` for musl targets, talking to PulseAudio (or
//! PipeWire's PulseAudio-compatible server) directly via `libpulse`'s own
//! protocol, instead of `crate::voice`'s default `cpal`-on-ALSA backend.
//!
//! Why: on Linux, `cpal`'s ALSA backend only reaches a running
//! PulseAudio/PipeWire server through an ALSA PCM plugin
//! (`libasound_module_pcm_pulse.so`) that ALSA loads with `dlopen()` at
//! runtime - see `crate::voice`'s `prefer_pulse` doc comment for why that
//! matters (exclusive-device-access without it). A fully static musl
//! binary (`Cross.toml`'s `x86_64-unknown-linux-musl`/
//! `aarch64-unknown-linux-musl` targets, built `-static-pie` for
//! single-file portability) can never `dlopen()` anything - musl's libc
//! hard-codes `dlopen` to fail with "Dynamic loading not supported" in a
//! static link, unconditionally. That's not fixable by installing
//! alsa-plugins on the target machine or adjusting `alsa.conf` search
//! paths; it means a static ALSA-based binary cannot reach
//! PulseAudio/PipeWire's ALSA shim at all, on any distro, ever - and most
//! desktop Linux distros route their *default* ALSA device through
//! exactly that shim, so this isn't limited to whatever explicitly asks
//! for a "pulse" device.
//!
//! Statically linking `libpulse`/`libpulse-simple` themselves (built from
//! source for musl in `Cross.toml`) sidesteps the problem entirely: no
//! plugin is `dlopen()`'d at runtime, because the PulseAudio protocol
//! client code is simply part of the binary. This module is the only
//! thing that talks to those crates; every pure PCM/mixing helper it uses
//! (`resample`, `mix_output`, `MixSource`, `apply_mixer_cmd`, ...) lives in
//! `crate::voice` and is shared verbatim with the cpal backend.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use tokio::sync::mpsc::UnboundedSender;

use crate::voice::{
    MixSource, MixerCmd, Result, SAMPLE_RATE_HZ, VoiceError, apply_mixer_cmd, mix_output,
    pcm_from_bytes, pcm_to_bytes,
};

/// Every stream this module opens is mono PCM16 at `SAMPLE_RATE_HZ` -
/// requested directly from the server rather than negotiated like cpal
/// does with a hardware device, so PulseAudio/PipeWire does any
/// rate-conversion itself and `crate::voice::resample` calls on this path
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
/// same contract as `crate::voice`'s cpal-backed `Recorder` (re-exported
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

/// Spawns the one persistent audio-output thread for the process, the same
/// contract as `crate::voice`'s cpal-backed `spawn_mixer` (re-exported
/// under that name on musl - see `voice.rs`'s doc comment on its own
/// `spawn_mixer` for why one persistent stream rather than one per
/// message).
///
/// Structurally different from the cpal version because of *how* audio
/// reaches the OS: cpal is callback-driven (it calls back into
/// `mix_output` whenever its output device wants more data), while
/// `pa_simple`'s blocking `write` is pull-driven from a thread this
/// function owns (it blocks until the server has buffer space, which
/// paces this loop the same way cpal's callback timing does). Both share
/// the exact same command handling and mixing logic
/// (`crate::voice::apply_mixer_cmd`, `crate::voice::mix_output`).
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
