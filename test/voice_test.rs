use aloo::client::tui::ui::format_duration_label;
use aloo::client::voice::{
    CHUNK_INTERVAL, DEVICE_BUFFER_MS, ECHO_DUCK_GAIN, ECHO_EVIDENCE_MIN_OBSERVATIONS, EchoDucker,
    EchoProbe, JITTER_PREBUFFER_MAX_MS,
    JITTER_PREBUFFER_MIN_MS, JITTER_QUEUE_SLACK_MS, MAX_RECORDING_SAMPLES, MAX_RECORDING_SECS,
    MixSource, MixerCmd, SAMPLE_RATE_HZ, SILENCE_HANGOVER, SilenceGate, VOICE_CHUNK_HEADER_BYTES,
    VOICE_CODEC_ADPCM, apply_mixer_cmd, decode_voice_chunk, decode_wav_to_mono, device_buffer_frames,
    downmix_f32_to_mono_i16, downmix_i16_to_mono, encode_voice_chunk, end_chime_samples,
    grown_prebuffer, is_echo_cancelling_device, jitter_ready_to_start, level_from_pcm,
    level_from_sum_sq, mix_output,
    ms_to_samples, overflow_drop_samples, pcm_from_bytes, pcm_to_bytes, recording_at_max, resample,
    samples_to_ms,
};
use aloo::p2p_proto::SAFE_DATAGRAM_BYTES;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A speech-like test signal: a tone at `freq` that a real capture could
/// plausibly produce, used wherever a test needs audio with actual
/// structure rather than silence or a constant.
fn tone(freq: f64, amplitude: f64, samples: usize) -> Vec<i16> {
    (0..samples)
        .map(|k| {
            (amplitude
                * (2.0 * std::f64::consts::PI * freq * k as f64 / SAMPLE_RATE_HZ as f64).sin())
                as i16
        })
        .collect()
}

/// Signal-to-noise ratio, in dB, of `coded` against `original`.
fn snr_db(original: &[i16], coded: &[i16]) -> f64 {
    let power: f64 = original.iter().map(|s| (*s as f64).powi(2)).sum();
    let noise: f64 = original
        .iter()
        .zip(coded)
        .map(|(a, b)| (*a as f64 - *b as f64).powi(2))
        .sum();
    10.0 * (power / noise.max(1.0)).log10()
}

/// Drives the mixer's realtime side for `frames` output frames, mono, at
/// `SAMPLE_RATE_HZ` - everything `mix_output` does except owning a device.
fn pump(sources: &Arc<Mutex<HashMap<u64, MixSource>>>, frames: usize) {
    let mut out = vec![0i16; frames];
    mix_output(&mut out, 1, SAMPLE_RATE_HZ, sources, &|_| {}, |s| s);
}

/// @requirement TB-148
#[test]
fn chunk_interval_stays_under_the_p2p_safe_datagram_budget() {
    // A voice chunk now travels as one direct peer-to-peer UDP datagram
    // (`docs/PROTOCOL.md` §7.1/§7.3), sent unreliably but still subject to
    // the same UDP-safety budget the reliable frames are - a fragmented
    // datagram is just as likely to be dropped either way. Worst-case
    // RSA-OAEP expansion (2048-bit key, `docs/PROTOCOL.md` §8.1) is
    // ~256/190 per block; leaves a 300-byte margin for
    // `PunchDatagram::Unreliable`'s framing overhead around the raw
    // ciphertext bytes.
    let bytes_per_ms = (SAMPLE_RATE_HZ as f64 / 1000.0) * 2.0; // mono, 16-bit
    let plaintext_per_chunk = CHUNK_INTERVAL.as_millis() as f64 * bytes_per_ms;
    let blocks_per_chunk = (plaintext_per_chunk / 190.0).ceil();
    let worst_case_ciphertext = blocks_per_chunk * 256.0;
    let framing_overhead = 300.0;
    assert!(
        worst_case_ciphertext + framing_overhead < SAFE_DATAGRAM_BYTES as f64,
        "worst-case {worst_case_ciphertext} + {framing_overhead} framing overhead must stay under SAFE_DATAGRAM_BYTES {} \
         for a {:?} CHUNK_INTERVAL",
        SAFE_DATAGRAM_BYTES,
        CHUNK_INTERVAL
    );
}

/// @requirement AC-099
#[test]
fn max_recording_samples_is_four_minutes_at_the_capture_rate() {
    assert_eq!(MAX_RECORDING_SECS, 240);
    assert_eq!(MAX_RECORDING_SAMPLES, SAMPLE_RATE_HZ as u64 * 240);
}

/// @requirement TB-142
#[test]
fn recording_at_max_triggers_exactly_at_the_boundary_not_before() {
    assert!(!recording_at_max(MAX_RECORDING_SAMPLES - 1));
    assert!(recording_at_max(MAX_RECORDING_SAMPLES));
    assert!(recording_at_max(MAX_RECORDING_SAMPLES + 1));
}

/// @requirement TB-045
#[test]
fn pcm_bytes_roundtrip() {
    let samples: Vec<i16> = vec![0, 1, -1, i16::MAX, i16::MIN, 12345, -12345];
    let bytes = pcm_to_bytes(&samples);
    assert_eq!(bytes.len(), samples.len() * 2);
    let back = pcm_from_bytes(&bytes);
    assert_eq!(back, samples);
}

/// @requirement TB-045
#[test]
fn pcm_from_bytes_drops_trailing_odd_byte_instead_of_panicking() {
    let bytes = vec![1, 0, 2, 0, 0xff]; // one full sample + a stray trailing byte
    let samples = pcm_from_bytes(&bytes);
    assert_eq!(samples, vec![1, 2]);
}

// ---------------------------------------------------------------------
// downmix_*_to_mono: input devices very often negotiate stereo-or-more
// even for a physically mono mic; without downmixing, the interleaved
// buffer ends up with more "samples" than real time steps, which plays
// back slow/low-pitched and garbled (see `Recorder::start`'s doc comment).
// ---------------------------------------------------------------------

/// @requirement TB-046
#[test]
fn downmix_i16_mono_input_is_a_no_op() {
    let samples = vec![1i16, 2, 3, -4];
    assert_eq!(downmix_i16_to_mono(&samples, 1), samples);
}

/// @requirement TB-046
#[test]
fn downmix_i16_stereo_averages_each_frame_and_halves_the_length() {
    // frames: (10,20) (30,40) (-10,-20)
    let interleaved = vec![10i16, 20, 30, 40, -10, -20];
    let mono = downmix_i16_to_mono(&interleaved, 2);
    assert_eq!(mono, vec![15, 35, -15]);
}

/// @requirement TB-046
#[test]
fn downmix_i16_identical_channels_preserves_the_signal_unchanged() {
    // a mono mic duplicated across both stereo channels (the common case)
    // should downmix back to exactly the original mono signal.
    let interleaved = vec![100i16, 100, -200, -200, 0, 0];
    assert_eq!(downmix_i16_to_mono(&interleaved, 2), vec![100, -200, 0]);
}

/// @requirement TB-046
#[test]
fn downmix_i16_surround_averages_all_channels_per_frame() {
    let interleaved = vec![4i16, 8, 12, 16]; // one 4-channel frame
    assert_eq!(downmix_i16_to_mono(&interleaved, 4), vec![10]);
}

/// @requirement TB-046
#[test]
fn downmix_f32_stereo_averages_and_converts_to_i16() {
    let interleaved = vec![0.5f32, 0.5, -1.0, -1.0];
    let mono = downmix_f32_to_mono_i16(&interleaved, 2);
    assert_eq!(mono, vec![(0.5 * i16::MAX as f32) as i16, i16::MIN + 1]);
}

/// @requirement TB-046
#[test]
fn downmix_f32_mono_input_is_a_straight_conversion() {
    let samples = vec![1.0f32, -1.0, 0.0];
    assert_eq!(
        downmix_f32_to_mono_i16(&samples, 1),
        vec![i16::MAX, i16::MIN + 1, 0]
    );
}

/// @requirement AC-037
#[test]
fn format_duration_label_matches_spec_example() {
    // SPEC.md's illustrative example: a ~12 second clip.
    assert_eq!(format_duration_label(12_000), "voice (12sec)");
}

/// @requirement TB-049
#[test]
fn format_duration_label_rounds_up_partial_seconds() {
    assert_eq!(format_duration_label(1), "voice (1sec)");
    assert_eq!(format_duration_label(999), "voice (1sec)");
    assert_eq!(format_duration_label(1001), "voice (2sec)");
}

/// @requirement TB-049
#[test]
fn format_duration_label_zero_is_zero_not_rounded_up() {
    assert_eq!(format_duration_label(0), "voice (0sec)");
}

/// @requirement AC-037
#[test]
fn format_duration_label_reflects_actual_length_not_a_fixed_value() {
    let labels: Vec<String> = [3_000, 12_000, 47_000]
        .iter()
        .map(|&ms| format_duration_label(ms))
        .collect();
    assert_eq!(
        labels,
        vec!["voice (3sec)", "voice (12sec)", "voice (47sec)"]
    );
}

// ---------------------------------------------------------------------
// resample: playback targets the output device's own rate instead of
// forcing SAMPLE_RATE_HZ on it (a common cause of ALSA/dmix failing to
// open the device at all).
// ---------------------------------------------------------------------

/// @requirement TB-047
#[test]
fn resample_same_rate_is_a_no_op() {
    let samples = vec![1i16, 2, 3, 4, 5];
    assert_eq!(resample(&samples, 16_000, 16_000), samples);
}

/// @requirement TB-047
#[test]
fn resample_upsampling_produces_proportionally_more_samples() {
    let one_second_at_16k = vec![0i16; 16_000];
    let out = resample(&one_second_at_16k, 16_000, 48_000);
    // upsampling 16kHz -> 48kHz (3x) should yield ~3x the samples, i.e.
    // still about one second's worth at the new rate
    assert_eq!(out.len(), 48_000);
}

/// @requirement TB-047
#[test]
fn resample_downsampling_produces_proportionally_fewer_samples() {
    let one_second_at_48k = vec![0i16; 48_000];
    let out = resample(&one_second_at_48k, 48_000, 16_000);
    assert_eq!(out.len(), 16_000);
}

/// @requirement TB-047
#[test]
fn resample_preserves_a_constant_signal() {
    // a DC-like constant signal should resample to (approximately) the
    // same constant value throughout, not introduce artifacts
    let samples = vec![1000i16; 1000];
    let out = resample(&samples, 16_000, 44_100);
    assert!(out.iter().all(|&s| (995..=1005).contains(&s)), "{out:?}");
}

/// @requirement TB-048
#[test]
fn resample_empty_input_stays_empty() {
    assert_eq!(resample(&[], 16_000, 48_000), Vec::<i16>::new());
}

/// @requirement TB-048
#[test]
fn resample_zero_rate_is_a_safe_no_op_not_a_panic() {
    let samples = vec![1i16, 2, 3];
    assert_eq!(resample(&samples, 0, 48_000), samples);
    assert_eq!(resample(&samples, 16_000, 0), samples);
}

/// @requirement TB-047
#[test]
fn resample_round_trip_stays_close_to_original_duration() {
    let original = vec![500i16; 16_000]; // 1 second at 16kHz
    let up = resample(&original, 16_000, 48_000);
    let back = resample(&up, 48_000, 16_000);
    // rounding at each step means it won't be pixel-perfect, but should
    // be within a handful of samples of the original length
    assert!(
        (back.len() as i64 - original.len() as i64).abs() <= 2,
        "{}",
        back.len()
    );
}

// ---------------------------------------------------------------------
// decode_wav_to_mono: the "end of message" chime is bundled as WAV
// specifically so it can be decoded without an MP3-decoding crate.
// ---------------------------------------------------------------------

/// Builds a minimal canonical WAV file (RIFF/WAVE/fmt /data, 16-bit PCM)
/// around raw interleaved `samples` at `sample_rate`/`channels`, with an
/// extra LIST/INFO-style chunk inserted before `data` - mirroring exactly
/// what ffmpeg emits for `assets/end.wav` - to prove the decoder walks
/// chunks generically rather than assuming a fixed offset.
fn build_wav(sample_rate: u32, channels: u16, samples: &[i16]) -> Vec<u8> {
    let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
    let extra_chunk: &[u8] = b"JUNK\x04\x00\x00\x00\xAA\xBB\xCC\xDD"; // id + size(4) + 4 filler bytes
    let byte_rate = sample_rate * channels as u32 * 2;
    let block_align = channels * 2;

    let mut fmt = Vec::new();
    fmt.extend_from_slice(&1u16.to_le_bytes()); // PCM
    fmt.extend_from_slice(&channels.to_le_bytes());
    fmt.extend_from_slice(&sample_rate.to_le_bytes());
    fmt.extend_from_slice(&byte_rate.to_le_bytes());
    fmt.extend_from_slice(&block_align.to_le_bytes());
    fmt.extend_from_slice(&16u16.to_le_bytes()); // bits per sample

    let mut body = Vec::new();
    body.extend_from_slice(b"WAVE");
    body.extend_from_slice(b"fmt ");
    body.extend_from_slice(&(fmt.len() as u32).to_le_bytes());
    body.extend_from_slice(&fmt);
    body.extend_from_slice(extra_chunk);
    body.extend_from_slice(b"data");
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    body.extend_from_slice(&data);

    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(body.len() as u32).to_le_bytes());
    wav.extend_from_slice(&body);
    wav
}

/// @requirement TB-050
#[test]
fn decode_wav_mono_same_rate_roundtrips_exactly() {
    let samples = vec![100i16, -200, 300, -400, 32000];
    let wav = build_wav(SAMPLE_RATE_HZ, 1, &samples);
    assert_eq!(decode_wav_to_mono(&wav), Some(samples));
}

/// @requirement TB-050
#[test]
fn decode_wav_stereo_is_downmixed_to_mono() {
    // interleaved (10,20) (30,40) -> mono (15, 35)
    let interleaved = vec![10i16, 20, 30, 40];
    let wav = build_wav(SAMPLE_RATE_HZ, 2, &interleaved);
    assert_eq!(decode_wav_to_mono(&wav), Some(vec![15, 35]));
}

/// @requirement TB-050
#[test]
fn decode_wav_resamples_a_different_rate_to_sample_rate_hz() {
    let samples = vec![0i16; 44_100]; // 1 second at 44.1kHz
    let wav = build_wav(44_100, 1, &samples);
    let decoded = decode_wav_to_mono(&wav).expect("valid wav");
    assert_eq!(
        decoded.len(),
        SAMPLE_RATE_HZ as usize,
        "should now be 1 second at SAMPLE_RATE_HZ"
    );
}

/// @requirement TB-050
#[test]
fn decode_wav_rejects_non_wav_input() {
    assert_eq!(decode_wav_to_mono(b"not a wav file at all"), None);
    assert_eq!(decode_wav_to_mono(&[]), None);
}

/// @requirement TB-050
#[test]
fn end_chime_samples_decodes_the_bundled_asset_and_is_non_empty() {
    let samples = end_chime_samples();
    assert!(
        !samples.is_empty(),
        "assets/end.wav should decode to a non-empty chime"
    );
    // calling again should return the same cached samples
    assert_eq!(end_chime_samples(), samples);
}

/// `assets/ping.wav` is the fourth bundled sound, converted once from the
/// original `ping.mp3` to a metadata-free 16 kHz mono WAV so it decodes
/// through the same path as the other three, with no MP3 crate.
/// @requirement AC-403
#[test]
fn ping_chime_samples_decodes_the_bundled_asset_and_is_non_empty() {
    let samples = aloo::client::voice::ping_chime_samples();
    assert!(!samples.is_empty(), "assets/ping.wav should decode to a non-empty chime");
    assert_eq!(aloo::client::voice::ping_chime_samples(), samples, "cached after the first decode");
}

/// The call modal's voice meter (`docs/SPEC.md` "Live voice calls") reads
/// RMS, not peak: silence is 0, a loud constant tone saturates, and one
/// stray spike in an otherwise quiet chunk barely moves it.
///
/// @requirement TB-208
#[test]
fn level_from_pcm_reads_rms_loudness_clamped_to_a_hundred() {
    assert_eq!(level_from_pcm(&[]), 0);
    assert_eq!(level_from_pcm(&[0; 512]), 0);

    let full = level_from_pcm(&[i16::MAX; 512]);
    assert_eq!(full, 100, "a full-scale tone saturates the meter");

    let quiet = level_from_pcm(&[300; 512]);
    let loud = level_from_pcm(&[3000; 512]);
    assert!(quiet < loud, "louder audio reads higher: {quiet} vs {loud}");
    assert!(loud <= 100);

    // One spike among 512 silent samples must not paint a full bar - the
    // reason this is RMS rather than peak amplitude.
    let mut spike = [0i16; 512];
    spike[0] = i16::MAX;
    assert!(
        level_from_pcm(&spike) < full / 3,
        "a single spike reads far below the same amplitude held throughout"
    );
}

// ---------------------------------------------------------------------
// Live chunk codec
// ---------------------------------------------------------------------

/// @requirement TB-270
#[test]
fn a_coded_chunk_round_trips_to_the_same_length_with_the_first_sample_exact() {
    for count in [1usize, 2, 3, 240, 241] {
        let samples = tone(300.0, 6000.0, count);
        let coded = encode_voice_chunk(&samples);
        let back = decode_voice_chunk(&coded).expect("our own encoder's output decodes");
        assert_eq!(back.len(), samples.len(), "length must survive {count} samples");
        // The first sample travels verbatim in the header, so it is the one
        // sample per chunk that is never approximated.
        assert_eq!(back[0], samples[0]);
    }
}

/// @requirement TB-270
#[test]
fn a_coded_chunk_is_about_a_quarter_the_size_of_the_pcm_it_replaces() {
    let samples = tone(300.0, 6000.0, ms_to_samples(15, SAMPLE_RATE_HZ));
    let pcm = pcm_to_bytes(&samples);
    let coded = encode_voice_chunk(&samples);
    // 4 bits a sample plus a fixed header, against 16 bits a sample.
    assert_eq!(coded.len(), VOICE_CHUNK_HEADER_BYTES + (samples.len() - 1).div_ceil(2));
    assert!(
        (pcm.len() as f64 / coded.len() as f64) > 3.5,
        "{} bytes of PCM must code to under a third of it, got {}",
        pcm.len(),
        coded.len()
    );
}

/// @requirement TB-271
#[test]
fn a_coded_chunk_reconstructs_speech_like_audio_faithfully() {
    // Each chunk decodes standalone, so what matters is the quality of a
    // chunk on its own - with no previous chunk's adaptation to inherit.
    // Well above the ~15dB an unseeded start index produces (see
    // `seed_step_index`), which is what this is really pinning.
    for (freq, amplitude) in [(200.0, 8000.0), (400.0, 3000.0), (1000.0, 12000.0)] {
        let samples = tone(freq, amplitude, ms_to_samples(15, SAMPLE_RATE_HZ));
        let back = decode_voice_chunk(&encode_voice_chunk(&samples)).expect("decodes");
        let snr = snr_db(&samples, &back);
        assert!(snr > 25.0, "{freq}Hz at {amplitude} coded at only {snr:.1}dB SNR");
    }
}

/// @requirement TB-272
#[test]
fn decoding_rejects_malformed_input_instead_of_panicking_or_inventing_audio() {
    // Every one of these is something a hostile or broken peer can put on
    // the wire once it holds the stream key.
    assert_eq!(decode_voice_chunk(&[]), Some(Vec::new()));
    assert_eq!(decode_voice_chunk(&[VOICE_CODEC_ADPCM]), None, "truncated header");
    assert_eq!(decode_voice_chunk(&[VOICE_CODEC_ADPCM, 0, 1]), None, "truncated header");
    assert_eq!(decode_voice_chunk(&[99, 0, 0, 0]), None, "unknown codec tag");
    // A step index past the end of the step table - the field is used to
    // index it, so an unchecked one would be an out-of-bounds panic.
    assert_eq!(decode_voice_chunk(&[VOICE_CODEC_ADPCM, 89, 0, 0, 0x11]), None);
    assert_eq!(decode_voice_chunk(&[VOICE_CODEC_ADPCM, 0x7f, 0, 0, 0x11]), None);
    // A well-formed header with a body of arbitrary bytes is audio, however
    // bad - every 4-bit code is a valid one - and must decode rather than fail.
    assert!(decode_voice_chunk(&[VOICE_CODEC_ADPCM, 40, 0, 0, 0xff, 0x0a]).is_some());
}

/// @requirement TB-148
#[test]
fn a_coded_chunk_stays_far_inside_the_p2p_safe_datagram_budget() {
    // TB-148's budget, recomputed for what actually goes on the wire now
    // that chunks are coded rather than raw PCM (docs/PROTOCOL.md 7.3).
    let samples = ms_to_samples(CHUNK_INTERVAL.as_millis() as usize as u64, SAMPLE_RATE_HZ);
    let coded = encode_voice_chunk(&tone(300.0, 6000.0, samples));
    // AES-256-GCM adds a fixed tag, not per-block expansion; 300 bytes of
    // framing margin, the same allowance TB-148 makes.
    assert!(
        coded.len() + 16 + 300 < SAFE_DATAGRAM_BYTES,
        "a {}-byte coded chunk must fit SAFE_DATAGRAM_BYTES {SAFE_DATAGRAM_BYTES}",
        coded.len()
    );
}

// ---------------------------------------------------------------------
// Jitter buffer
// ---------------------------------------------------------------------

/// @requirement TB-273
#[test]
fn a_live_sources_backlog_is_trimmed_back_to_its_prebuffer_target() {
    // The regression this exists for: without a ceiling, a queue that grows
    // (a network stall clearing, a sender running fast) stays grown, and
    // every sample behind it is played late for the rest of the call.
    let mut src = MixSource::new();
    src.mark_live();
    src.extend(&vec![0i16; (SAMPLE_RATE_HZ * 2) as usize]);
    let dropped = src.on_push(SAMPLE_RATE_HZ);
    assert!(dropped > 0, "two seconds of backlog must be trimmed");
    assert_eq!(
        samples_to_ms(src.queued_samples(), SAMPLE_RATE_HZ),
        src.prebuffer_ms(),
        "what is left must be exactly the prebuffer target"
    );
    assert!(src.prebuffer_ms() <= JITTER_PREBUFFER_MAX_MS);
}

/// @requirement TB-273
#[test]
fn ordinary_burstiness_under_the_ceiling_is_left_alone() {
    // Several chunks arriving in one scheduling slice is normal. Trimming
    // that would chop audio continuously rather than bound a backlog.
    let mut src = MixSource::new();
    src.mark_live();
    let under = JITTER_PREBUFFER_MIN_MS + JITTER_QUEUE_SLACK_MS;
    src.extend(&vec![0i16; ms_to_samples(under, SAMPLE_RATE_HZ)]);
    assert_eq!(src.on_push(SAMPLE_RATE_HZ), 0);
    assert_eq!(src.queued_samples(), ms_to_samples(under, SAMPLE_RATE_HZ));
}

/// @requirement TB-274
#[test]
fn a_whole_clip_survives_intact_through_the_real_push_then_finish_order() {
    // The order that matters, and the one an earlier version of this test
    // got wrong by marking the source finished up front: every chime and
    // every replayed voice message is pushed whole and only *then*
    // finished, so for that moment it is indistinguishable from a live
    // source carrying a large backlog. Inferring "recording" from
    // `finished` therefore trimmed all of them down to their last few
    // milliseconds - clips that audibly cut themselves off.
    let sources: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
    let clip = tone(300.0, 6000.0, (SAMPLE_RATE_HZ * 3) as usize);
    apply_mixer_cmd(&sources, SAMPLE_RATE_HZ, MixerCmd::Push { id: 1, samples: clip.clone() });
    assert_eq!(
        sources.lock().unwrap().get(&1).unwrap().queued_samples(),
        clip.len(),
        "a recording must never be trimmed, finished or not"
    );
    apply_mixer_cmd(&sources, SAMPLE_RATE_HZ, MixerCmd::Finish { id: 1 });

    // And it plays back in full, sample for sample.
    let mut out = vec![0i16; clip.len()];
    mix_output(&mut out, 1, SAMPLE_RATE_HZ, &sources, &|_| {}, |s| s);
    assert_eq!(out, clip);
}

/// @requirement TB-274
#[test]
fn only_a_live_source_is_latency_managed() {
    // Same oversized backlog, same push order - the only difference is
    // which command delivered it, which is the only thing that can tell a
    // real-time stream from a recording.
    let big = vec![0i16; (SAMPLE_RATE_HZ * 2) as usize];

    let recording: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
    apply_mixer_cmd(&recording, SAMPLE_RATE_HZ, MixerCmd::Push { id: 1, samples: big.clone() });
    let map = recording.lock().unwrap();
    let src = map.get(&1).unwrap();
    assert!(!src.is_live());
    assert_eq!(src.queued_samples(), big.len());
    drop(map);

    let live: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
    apply_mixer_cmd(&live, SAMPLE_RATE_HZ, MixerCmd::PushLive { id: 1, samples: big.clone() });
    let map = live.lock().unwrap();
    let src = map.get(&1).unwrap();
    assert!(src.is_live());
    assert!(src.queued_samples() < big.len(), "a live backlog must be trimmed");
    assert_eq!(samples_to_ms(src.queued_samples(), SAMPLE_RATE_HZ), src.prebuffer_ms());
}

/// @requirement TB-274
#[test]
fn a_recording_that_runs_dry_before_its_finish_does_not_re_prebuffer() {
    // A clip whose `Finish` has not arrived yet must simply wait, not be
    // treated as a live source that fell behind its sender.
    let sources: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
    let clip = tone(300.0, 6000.0, 400);
    apply_mixer_cmd(&sources, SAMPLE_RATE_HZ, MixerCmd::Push { id: 1, samples: clip.clone() });
    pump(&sources, clip.len() + 200);

    let map = sources.lock().unwrap();
    let src = map.get(&1).expect("still waiting for its Finish");
    assert!(src.started(), "a recording that ran dry stays started");
    assert_eq!(src.prebuffer_ms(), JITTER_PREBUFFER_MIN_MS, "and grows no prebuffer");
}

/// @requirement TB-275
#[test]
fn overflow_is_measured_against_the_target_plus_slack_and_trims_to_the_target() {
    let rate = SAMPLE_RATE_HZ;
    let target = JITTER_PREBUFFER_MIN_MS;
    let ceiling = target + JITTER_QUEUE_SLACK_MS;
    assert_eq!(overflow_drop_samples(ms_to_samples(ceiling, rate), rate, target), 0);
    let over = ms_to_samples(ceiling + 100, rate);
    let dropped = overflow_drop_samples(over, rate, target);
    assert_eq!(samples_to_ms(over - dropped, rate), target);
}

/// @requirement TB-276
#[test]
fn a_prebuffer_grows_on_an_underrun_and_stops_at_the_ceiling() {
    let mut at = JITTER_PREBUFFER_MIN_MS;
    let mut steps = 0;
    while at < JITTER_PREBUFFER_MAX_MS {
        at = grown_prebuffer(at);
        steps += 1;
        assert!(steps < 100, "growth must terminate");
    }
    assert_eq!(at, JITTER_PREBUFFER_MAX_MS);
    assert_eq!(grown_prebuffer(JITTER_PREBUFFER_MAX_MS), JITTER_PREBUFFER_MAX_MS);
}

/// @requirement TB-276
#[test]
fn a_finished_source_never_waits_for_a_prebuffer_it_will_never_fill() {
    // A whole clip, or a live stream whose end already arrived: there is no
    // more audio coming, so waiting for more is waiting forever.
    assert!(jitter_ready_to_start(0, Duration::ZERO, true, JITTER_PREBUFFER_MAX_MS));
    assert!(!jitter_ready_to_start(0, Duration::ZERO, false, JITTER_PREBUFFER_MIN_MS));
    assert!(jitter_ready_to_start(
        JITTER_PREBUFFER_MIN_MS,
        Duration::ZERO,
        false,
        JITTER_PREBUFFER_MIN_MS
    ));
    // ... and a live one starts anyway rather than sitting on audio forever
    // if its sender went quiet mid-fill.
    assert!(jitter_ready_to_start(1, Duration::from_secs(1), false, JITTER_PREBUFFER_MAX_MS));
}

/// @requirement TB-277
#[test]
fn a_starved_live_source_rebuilds_a_larger_prebuffer_before_it_plays_again() {
    let sources: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
    let filled = ms_to_samples(JITTER_PREBUFFER_MIN_MS, SAMPLE_RATE_HZ);
    apply_mixer_cmd(
        &sources,
        SAMPLE_RATE_HZ,
        MixerCmd::PushLive { id: 1, samples: vec![1000; filled] },
    );
    // Ask for more than it has: it plays what there is, then starves.
    pump(&sources, filled + 64);

    let map = sources.lock().unwrap();
    let src = map.get(&1).expect("a live source is never retired by starving");
    assert!(!src.started(), "a starved source goes back to waiting");
    assert_eq!(
        src.prebuffer_ms(),
        grown_prebuffer(JITTER_PREBUFFER_MIN_MS),
        "and asks for more headroom before the next talk spurt"
    );
}

/// @requirement TB-277
#[test]
fn a_finished_source_drains_completely_and_is_then_retired() {
    let sources: Arc<Mutex<HashMap<u64, MixSource>>> = Arc::new(Mutex::new(HashMap::new()));
    let clip = tone(300.0, 6000.0, 800);
    apply_mixer_cmd(&sources, SAMPLE_RATE_HZ, MixerCmd::Push { id: 7, samples: clip.clone() });
    apply_mixer_cmd(&sources, SAMPLE_RATE_HZ, MixerCmd::Finish { id: 7 });

    let mut out = vec![0i16; clip.len()];
    mix_output(&mut out, 1, SAMPLE_RATE_HZ, &sources, &|_| {}, |s| s);
    // Every sample of the clip came out, in order, none trimmed.
    assert_eq!(out, clip);
    pump(&sources, 1);
    assert!(sources.lock().unwrap().is_empty(), "a drained clip is retired");
}

// ---------------------------------------------------------------------
// Echo ducking and silence suppression
// ---------------------------------------------------------------------

/// @requirement TB-278
#[test]
fn the_ducker_reaches_useful_attenuation_within_the_first_chunks() {
    // The failure this pins: an attack slow enough to leave the microphone
    // near full gain through the *opening* of every far-end phrase leaks a
    // burst of echo on every utterance, which is indistinguishable from no
    // ducking at all.
    let mut ducker = EchoDucker::new();
    ducker.process(&mut vec![0i16; 240], 80);
    assert!(ducker.gain() < 0.3, "one chunk in, gain was still {}", ducker.gain());
    ducker.process(&mut vec![0i16; 240], 80);
    ducker.process(&mut vec![0i16; 240], 80);
    assert!(
        ducker.gain() < ECHO_DUCK_GAIN * 1.5,
        "three chunks in, gain was still {}",
        ducker.gain()
    );
}

/// @requirement TB-278
#[test]
fn the_ducker_attenuates_capture_while_the_speakers_are_playing() {
    let mut ducker = EchoDucker::new();
    for _ in 0..60 {
        ducker.process(&mut vec![10_000i16; 240], 80);
    }
    assert!(
        (ducker.gain() - ECHO_DUCK_GAIN).abs() < 0.01,
        "settled gain {} should be ECHO_DUCK_GAIN",
        ducker.gain()
    );
    let mut captured = vec![10_000i16; 240];
    ducker.process(&mut captured, 80);
    assert!(
        captured.iter().all(|s| *s < 2_000),
        "captured audio must actually be attenuated, not merely tracked"
    );
}

/// @requirement TB-278
#[test]
fn the_ducker_leaves_capture_untouched_when_nothing_is_playing() {
    let mut ducker = EchoDucker::new();
    let mut captured = vec![10_000i16; 240];
    ducker.process(&mut captured, 0);
    assert_eq!(captured, vec![10_000i16; 240]);
    assert_eq!(ducker.gain(), 1.0);
}

/// @requirement TB-278
#[test]
fn the_ducker_comes_back_to_full_gain_once_the_speakers_go_quiet() {
    let mut ducker = EchoDucker::new();
    for _ in 0..60 {
        ducker.process(&mut vec![10_000i16; 240], 80);
    }
    for _ in 0..400 {
        ducker.process(&mut vec![10_000i16; 240], 0);
    }
    assert!(ducker.gain() > 0.99, "gain stuck at {}", ducker.gain());
    // Release is deliberately slower than attack - arriving late costs a
    // burst of echo, leaving late costs a quiet syllable.
    let mut attack = EchoDucker::new();
    attack.process(&mut vec![0i16; 240], 80);
    let ducked = 1.0 - attack.gain();
    let mut release = EchoDucker::new();
    for _ in 0..60 {
        release.process(&mut vec![0i16; 240], 80);
    }
    let before = release.gain();
    release.process(&mut vec![0i16; 240], 0);
    assert!(release.gain() - before < ducked);
}

/// @requirement TB-279
#[test]
fn the_silence_gate_sends_speech_holds_through_a_pause_and_then_stops() {
    let mut gate = SilenceGate::new();
    // Nothing has been said yet: nothing to send.
    assert!(!gate.should_send(0, CHUNK_INTERVAL));
    assert!(gate.should_send(50, CHUNK_INTERVAL));
    // The quiet moments inside speech must not cut the stream, or the
    // receiver spends the conversation rebuilding its prebuffer.
    let mut held = 0;
    while gate.should_send(0, CHUNK_INTERVAL) {
        held += 1;
        assert!(held < 1000, "the hangover must expire");
    }
    assert_eq!(
        held as u128,
        SILENCE_HANGOVER.as_millis() / CHUNK_INTERVAL.as_millis()
    );
    // Speaking again re-arms it in full.
    assert!(gate.should_send(50, CHUNK_INTERVAL));
    assert!(gate.should_send(0, CHUNK_INTERVAL));
}

// ---------------------------------------------------------------------
// Device buffering
// ---------------------------------------------------------------------

/// @requirement TB-280
#[test]
fn a_device_period_is_asked_for_explicitly_and_clamped_to_what_it_supports() {
    // 20ms at the device's own rate, which is the whole point: the default
    // period is what put tens to hundreds of milliseconds in the path.
    assert_eq!(device_buffer_frames(48_000, Some((64, 4096))), Some(960));
    assert_eq!(device_buffer_frames(SAMPLE_RATE_HZ, Some((64, 4096))), Some(320));
    assert_eq!(
        device_buffer_frames(48_000, Some((64, 4096))),
        Some(48_000 * DEVICE_BUFFER_MS / 1000)
    );
    // Clamped rather than refused, either way.
    assert_eq!(device_buffer_frames(48_000, Some((2048, 4096))), Some(2048));
    assert_eq!(device_buffer_frames(48_000, Some((64, 256))), Some(256));
    // A device that publishes no range at all is left on its own default
    // rather than handed a number it may reject.
    assert_eq!(device_buffer_frames(48_000, None), None);
}

/// @requirement TB-208
#[test]
fn a_level_read_from_a_running_sum_matches_one_read_from_the_samples() {
    for samples in [tone(300.0, 6000.0, 240), tone(120.0, 500.0, 240), vec![0i16; 240]] {
        let sum_sq: u64 = samples.iter().map(|s| (*s as i64 * *s as i64) as u64).sum();
        assert_eq!(
            level_from_sum_sq(sum_sq, samples.len() as u64),
            level_from_pcm(&samples)
        );
    }
    assert_eq!(level_from_sum_sq(0, 0), 0);
}

/// @requirement TB-281
#[test]
fn an_echo_cancelling_capture_device_is_recognised_by_name_and_nothing_else_is() {
    // What PulseAudio/PipeWire's module-echo-cancel and the drivers that
    // expose a cancelled endpoint actually call themselves.
    assert!(is_echo_cancelling_device("echo-cancel-source"));
    assert!(is_echo_cancelling_device("Echo-Cancel Source"));
    assert!(is_echo_cancelling_device("echocancel"));
    assert!(is_echo_cancelling_device("Built-in Audio (echo cancelled)"));
    // Narrow enough that it cannot select a device the user did not mean.
    assert!(!is_echo_cancelling_device("Built-in Audio Analog Stereo"));
    assert!(!is_echo_cancelling_device("HD Webcam C920"));
    assert!(!is_echo_cancelling_device("default"));
    assert!(!is_echo_cancelling_device(""));
}

// ---------------------------------------------------------------------
// Deciding whether there is an echo path at all
// ---------------------------------------------------------------------

/// Feeds the probe `rounds` alternating talk spurts: the far end talking
/// (during which our microphone also reads `echo_leak` louder, if there is
/// an echo path), then quiet.
///
/// `own_speech` is spread evenly across both kinds of spurt, which is the
/// assumption the whole design rests on - we talk without regard to whose
/// turn it is, so our own voice raises both averages and drops out of the
/// difference between them. A test that put it disproportionately in one
/// population would be measuring the helper, not the probe.
fn observe_conversation(probe: &mut EchoProbe, rounds: usize, echo_leak: u8, own_speech: u8) {
    let spurt = ECHO_EVIDENCE_MIN_OBSERVATIONS as usize / 4 + 1;
    for _ in 0..rounds {
        for i in 0..spurt {
            let mine = if i % 2 == 0 { own_speech } else { 0 };
            probe.observe(20 + mine + echo_leak, 60);
        }
        for i in 0..spurt {
            let mine = if i % 2 == 0 { own_speech } else { 0 };
            probe.observe(20 + mine, 0);
        }
    }
}

/// @requirement TB-282
#[test]
fn the_probe_ducks_until_it_has_evidence_either_way() {
    // The safe assumption before there is evidence is the one whose failure
    // everyone else in the call hears, rather than only us.
    let mut probe = EchoProbe::new();
    assert!(probe.should_duck());
    // A handful of chunks is not evidence, whatever they say.
    for _ in 0..8 {
        probe.observe(20, 0);
    }
    assert!(probe.should_duck());
    // Nor is a long run of only one of the two populations - a call where
    // the far end has not spoken yet says nothing about the room.
    for _ in 0..(ECHO_EVIDENCE_MIN_OBSERVATIONS * 4) {
        probe.observe(20, 0);
    }
    assert!(probe.should_duck());
}

/// @requirement TB-282
#[test]
fn the_probe_releases_on_headphones_where_the_microphone_hears_nothing() {
    let mut probe = EchoProbe::new();
    observe_conversation(&mut probe, 12, 0, 25);
    assert!(
        !probe.should_duck(),
        "no echo leak should release ducking, excess was {}",
        probe.excess_level()
    );
    assert!(probe.excess_ratio() < 1.08, "ratio {}", probe.excess_ratio());
}

/// @requirement TB-282
#[test]
fn a_quiet_but_audible_echo_still_holds_ducking_on() {
    // The case an absolute margin got wrong: a room whose echo raises the
    // microphone by only a couple of meter points is still a room the far
    // end hears themselves in. Judged as a ratio, it is unambiguous.
    let mut probe = EchoProbe::new();
    observe_conversation(&mut probe, 12, 2, 0);
    assert!(
        probe.should_duck(),
        "a {:.2}x rise must still count as an echo path",
        probe.excess_ratio()
    );
    assert!(probe.excess_level() < 4.0, "and it is well under the old absolute threshold");
}

/// @requirement TB-282
#[test]
fn the_probe_keeps_ducking_on_speakers_where_the_microphone_hears_them() {
    let mut probe = EchoProbe::new();
    observe_conversation(&mut probe, 12, 15, 25);
    assert!(
        probe.should_duck(),
        "an audible echo path must hold ducking on, excess was {}",
        probe.excess_level()
    );
    assert!(probe.excess_level() > 4.0);
}

/// @requirement TB-282
#[test]
fn the_probe_re_engages_when_headphones_come_out_mid_call() {
    // The case no setting can handle: the room changes while the call runs.
    let mut probe = EchoProbe::new();
    observe_conversation(&mut probe, 12, 0, 25);
    assert!(!probe.should_duck());
    observe_conversation(&mut probe, 30, 20, 25);
    assert!(
        probe.should_duck(),
        "unplugging headphones must bring ducking back, excess was {}",
        probe.excess_level()
    );
}

/// @requirement TB-282
#[test]
fn the_probes_decision_has_hysteresis_so_it_cannot_flap() {
    // Between the release and engage thresholds the answer must be whatever
    // it already was, or a room sitting near the boundary would toggle the
    // microphone's gain every chunk.
    let mut ducking = EchoProbe::new();
    observe_conversation(&mut ducking, 12, 15, 0);
    assert!(ducking.should_duck());

    let mut released = EchoProbe::new();
    observe_conversation(&mut released, 12, 0, 0);
    assert!(!released.should_duck());

    // Same borderline evidence fed to both - they must disagree, each
    // keeping its own prior answer.
    for _ in 0..(ECHO_EVIDENCE_MIN_OBSERVATIONS * 4) {
        ducking.observe(23, 60);
        ducking.observe(20, 0);
        released.observe(23, 60);
        released.observe(20, 0);
    }
    assert!(ducking.should_duck(), "excess {}", ducking.excess_level());
    assert!(!released.should_duck(), "excess {}", released.excess_level());
}
