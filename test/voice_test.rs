use aloo::client::tui::ui::format_duration_label;
use aloo::client::voice::{
    CHUNK_INTERVAL, MAX_RECORDING_SAMPLES, MAX_RECORDING_SECS, SAMPLE_RATE_HZ, decode_wav_to_mono,
    downmix_f32_to_mono_i16, downmix_i16_to_mono, end_chime_samples, level_from_pcm,
    pcm_from_bytes, pcm_to_bytes,
    recording_at_max, resample,
};
use aloo::p2p_proto::SAFE_DATAGRAM_BYTES;

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
