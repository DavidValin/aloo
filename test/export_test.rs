//! `client::export`: path building, the WAV writer, and the two entry
//! points (`autosave_entry`/`export_log`) that `autosave_messages` and the
//! `Ctrl+E` popup use.
//!
//! All of these resolve their base directory through `platform::aloo_dir()`,
//! which honors `ALOO_HOME` - so every test here shares one temp
//! `ALOO_HOME` (`shared_home`, the same idiom `daemon_session_test.rs` uses)
//! rather than touching the real `~/.aloo`. Unlike that file, nothing here
//! needs serializing: each test writes under its own `server_label`
//! (derived from the test name), so parallel tests never touch the same
//! path.

use std::path::PathBuf;
use std::sync::OnceLock;

use aloo::client::export::{self, LogHistoryCursor, Surface};
use aloo::client::tui::ui::{FileTransferStatus, LogEntry, MessageBody};
use aloo::client::voice;
use aloo::proto::UserId;

fn shared_home() -> &'static std::path::Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "aloo-export-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        unsafe { std::env::set_var("ALOO_HOME", &dir) };
        dir
    })
}

fn exports_dir_for(server_label: &str) -> PathBuf {
    shared_home().join("exports").join(server_label)
}

fn text_entry(outgoing: bool, from_name: &str, text: &str) -> LogEntry {
    LogEntry {
        from: UserId(1),
        from_name: from_name.to_string(),
        body: MessageBody::Text(text.to_string()),
        outgoing,
        failed: false,
        sent_at: "12:00".to_string(),
        sent_at_utc: "2026-08-26T12:00:00Z".to_string(),
        owed_receipt: None,
        listened: true,
        delivery: None,
        crypto: None,
    }
}

fn voice_entry(from_name: &str, samples: &[i16]) -> LogEntry {
    let pcm = voice::pcm_to_bytes(samples);
    LogEntry {
        from: UserId(2),
        from_name: from_name.to_string(),
        body: MessageBody::Voice {
            duration_ms: (samples.len() as u32 * 1000) / voice::SAMPLE_RATE_HZ,
            pcm,
        },
        outgoing: false,
        failed: false,
        sent_at: "12:00".to_string(),
        sent_at_utc: "2026-08-26T12:00:00Z".to_string(),
        owed_receipt: None,
        listened: false,
        delivery: None,
        crypto: None,
    }
}

fn file_entry(from_name: &str, filename: &str) -> LogEntry {
    LogEntry {
        from: UserId(4),
        from_name: from_name.to_string(),
        body: MessageBody::File {
            filename: filename.to_string(),
            total: 100,
            stream_id: 1,
            status: FileTransferStatus::Completed,
        },
        outgoing: false,
        failed: false,
        sent_at: "12:00".to_string(),
        sent_at_utc: "2026-08-26T12:00:00Z".to_string(),
        owed_receipt: None,
        listened: true,
        delivery: None,
        crypto: None,
    }
}

fn presence_entry(text: &str) -> LogEntry {
    LogEntry {
        from: UserId(5),
        from_name: "carol".to_string(),
        body: MessageBody::Presence(text.to_string()),
        outgoing: false,
        failed: false,
        sent_at: "12:00".to_string(),
        sent_at_utc: "2026-08-26T12:00:00Z".to_string(),
        owed_receipt: None,
        listened: true,
        delivery: None,
        crypto: None,
    }
}

fn voice_streaming_entry(from_name: &str) -> LogEntry {
    LogEntry {
        from: UserId(3),
        from_name: from_name.to_string(),
        body: MessageBody::VoiceStreaming { stream_id: 1 },
        outgoing: false,
        failed: false,
        sent_at: "12:00".to_string(),
        sent_at_utc: "2026-08-26T12:00:00Z".to_string(),
        owed_receipt: None,
        listened: false,
        delivery: None,
        crypto: None,
    }
}

/// @requirement AC-352
#[test]
fn server_label_combines_a_sanitized_host_and_the_port() {
    let _ = shared_home();
    assert_eq!(export::server_label("chat.example.com", 7878), "chat.example.com_7878");
    // A bracket-free IPv6 literal's colons are not filesystem-safe on
    // every platform this app supports (Windows) - sanitized to `_`.
    assert_eq!(export::server_label("2001:db8::1", 7878), "2001_db8__1_7878");
    assert_eq!(export::DIRECT_LABEL, "DIRECT");
}

/// @requirement AC-352
#[test]
fn short_uuid_is_eight_hex_characters_and_not_constant() {
    let _ = shared_home();
    let a = export::short_uuid();
    let b = export::short_uuid();
    assert_eq!(a.len(), 8);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b, "two calls landing on the same 4 random bytes should not happen in practice");
}

/// @requirement AC-353
#[test]
fn autosave_entry_appends_a_text_line_naming_the_utc_timestamp_and_direction() {
    let _ = shared_home();
    let server_label = "autosave-text-basic_1";
    export::autosave_entry(server_label, Surface::Channel("general"), &text_entry(false, "alice", "hi"));
    let log_path = exports_dir_for(server_label).join("channels").join("general.log");
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(contents.contains("[2026-08-26T12:00:00Z]"), "{contents}");
    assert!(contents.contains("<- alice: hi"), "incoming should use the <- arrow: {contents}");
}

/// @requirement AC-353
#[test]
fn autosave_entry_marks_an_outgoing_line_with_the_other_arrow() {
    let _ = shared_home();
    let server_label = "autosave-text-outgoing_1";
    export::autosave_entry(server_label, Surface::Dm("bob"), &text_entry(true, "me", "yo"));
    let log_path = exports_dir_for(server_label).join("dms").join("bob.log");
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(contents.contains("-> me: yo"), "{contents}");
}

/// The whole point: a session that autosaves twice (e.g. across two
/// separate launches) must never replace what an earlier one wrote.
/// @requirement AC-353
#[test]
fn autosave_entry_keeps_adding_never_replacing() {
    let _ = shared_home();
    let server_label = "autosave-appends_1";
    export::autosave_entry(server_label, Surface::Channel("general"), &text_entry(false, "alice", "first"));
    export::autosave_entry(server_label, Surface::Channel("general"), &text_entry(false, "bob", "second"));
    let log_path = exports_dir_for(server_label).join("channels").join("general.log");
    let contents = std::fs::read_to_string(&log_path).unwrap();
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2, "{contents}");
    assert!(lines[0].contains("first"));
    assert!(lines[1].contains("second"));
}

/// A `VoiceStreaming` placeholder has no audio yet - nothing worth
/// writing, and `finalize_stream_entry`'s call site is what autosaves the
/// real thing once the stream ends.
/// @requirement AC-353
#[test]
fn autosave_entry_is_a_no_op_for_a_still_streaming_placeholder() {
    let _ = shared_home();
    let server_label = "autosave-streaming-skip_1";
    export::autosave_entry(server_label, Surface::Channel("general"), &voice_streaming_entry("carol"));
    let log_path = exports_dir_for(server_label).join("channels").join("general.log");
    assert!(!log_path.exists(), "a placeholder with no audio should write nothing");
}

/// @requirement AC-353
#[test]
fn autosave_entry_writes_a_wav_that_decodes_back_to_the_same_samples_and_references_it_by_name() {
    let _ = shared_home();
    let server_label = "autosave-voice-wav_1";
    let samples: Vec<i16> = (0..800).map(|n| (n % 100) as i16 * 100).collect();
    export::autosave_entry(server_label, Surface::Dm("dave"), &voice_entry("dave", &samples));

    let dms_dir = exports_dir_for(server_label).join("dms");
    let log_contents = std::fs::read_to_string(dms_dir.join("dave.log")).unwrap();

    let wav_name = std::fs::read_dir(&dms_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|name| name.ends_with(".wav"))
        .expect("autosave_entry should have written a .wav file next to the .log");
    assert!(
        log_contents.contains(&wav_name),
        "the log line should reference the wav file by name: {log_contents} / {wav_name}"
    );

    let wav_bytes = std::fs::read(dms_dir.join(&wav_name)).unwrap();
    let decoded = voice::decode_wav_to_mono(&wav_bytes).expect("the written file should be a valid WAV");
    assert_eq!(decoded, samples);
}

/// @requirement AC-354
#[test]
fn export_log_prefixes_every_file_it_writes_with_the_given_shortuuid() {
    let _ = shared_home();
    let server_label = "export-log-prefix_1";
    let log = vec![text_entry(false, "alice", "hello"), voice_entry("alice", &[1, 2, 3, 4])];
    export::export_log(server_label, Surface::Channel("general"), "abcd1234", &log).unwrap();

    let channels_dir = exports_dir_for(server_label).join("channels");
    assert!(channels_dir.join("abcd1234_general.log").exists());
    let has_prefixed_wav = std::fs::read_dir(&channels_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("abcd1234_") && e.file_name().to_string_lossy().ends_with(".wav"));
    assert!(has_prefixed_wav, "the voice entry's wav should also carry the prefix");
}

/// A manual export is a snapshot of what's in memory right now - a
/// still-streaming entry has nothing to snapshot.
/// @requirement AC-354
#[test]
fn export_log_skips_voice_streaming_entries() {
    let _ = shared_home();
    let server_label = "export-log-skip-streaming_1";
    let log = vec![voice_streaming_entry("erin")];
    export::export_log(server_label, Surface::Channel("general"), "ffff0000", &log).unwrap();
    let contents =
        std::fs::read_to_string(exports_dir_for(server_label).join("channels").join("ffff0000_general.log")).unwrap();
    assert!(contents.trim().is_empty(), "{contents}");
}

/// A manual export never overwrites a same-server autosave log - it always
/// lands beside it under its own uuid-prefixed name.
/// @requirement AC-354
#[test]
fn export_log_and_autosave_never_collide_on_the_same_file() {
    let _ = shared_home();
    let server_label = "export-vs-autosave_1";
    export::autosave_entry(server_label, Surface::Channel("general"), &text_entry(false, "alice", "autosaved"));
    export::export_log(
        server_label,
        Surface::Channel("general"),
        "12345678",
        &[text_entry(false, "alice", "exported")],
    )
    .unwrap();
    let channels_dir = exports_dir_for(server_label).join("channels");
    let autosave_contents = std::fs::read_to_string(channels_dir.join("general.log")).unwrap();
    let export_contents = std::fs::read_to_string(channels_dir.join("12345678_general.log")).unwrap();
    assert!(autosave_contents.contains("autosaved"));
    assert!(!autosave_contents.contains("exported"));
    assert!(export_contents.contains("exported"));
}

/// A DM peer's nickname is not filesystem-safe the way a channel name
/// already is (`validation::channel_name_is_valid`) - it gets sanitized
/// before becoming a path component.
/// @requirement AC-353
#[test]
fn a_dm_peer_name_with_unsafe_characters_is_sanitized_into_the_filename() {
    let _ = shared_home();
    let server_label = "autosave-dm-sanitize_1";
    export::autosave_entry(server_label, Surface::Dm("weird/name:here"), &text_entry(false, "weird/name:here", "hi"));
    let dms_dir = exports_dir_for(server_label).join("dms");
    let has_safe_log = std::fs::read_dir(&dms_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().ends_with(".log"));
    assert!(has_safe_log, "expected a sanitized .log filename under {dms_dir:?}");
    assert!(!dms_dir.join("weird/name:here.log").exists());
}

// ---------------------------------------------------------------------
// `LogHistoryCursor` (`resume_from_log`) - reading a `.log` file back.
// ---------------------------------------------------------------------

/// @requirement AC-360
#[test]
fn history_cursor_reads_back_a_text_entry_written_by_autosave() {
    let _ = shared_home();
    let server_label = "history-text-roundtrip_1";
    export::autosave_entry(server_label, Surface::Channel("general"), &text_entry(false, "alice", "hi there"));

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    assert!(cursor.has_more());
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1);
    assert_eq!(chunk[0].from_name, "alice");
    assert!(!chunk[0].outgoing);
    assert!(chunk[0].listened, "reconstructed rows never carry the not-listened marker");
    assert_eq!(chunk[0].body, MessageBody::Text("hi there".to_string()));
    assert!(!cursor.has_more());
}

/// @requirement AC-360
#[test]
fn history_cursor_reads_a_voice_entry_as_voice_on_disk_with_a_resolvable_wav_path() {
    let _ = shared_home();
    let server_label = "history-voice-roundtrip_1";
    // 32,000 samples at 16kHz is exactly 2000ms - a round number, so the
    // `{:.1}` formatting/parsing round trip is exact (avoids the format's
    // inherent 100ms rounding elsewhere - see `format_line`'s doc).
    let samples = vec![0i16; 32_000];
    export::autosave_entry(server_label, Surface::Dm("dave"), &voice_entry("dave", &samples));

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Dm("dave"), 0);
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1);
    match &chunk[0].body {
        MessageBody::VoiceOnDisk { duration_ms, wav_path } => {
            assert_eq!(*duration_ms, 2000);
            let path = wav_path.as_ref().expect("a wav was written, so a path should be recovered");
            assert!(path.exists(), "the resolved wav path should point at a real file: {path:?}");
            let decoded = voice::decode_wav_to_mono(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(decoded, samples);
        }
        other => panic!("expected VoiceOnDisk, got {other:?}"),
    }
}

/// A `.wav` write failure at autosave time leaves a duration-only voice
/// line with no filename - the reconstructed row must not invent a path
/// that was never written.
/// @requirement AC-360
#[test]
fn history_cursor_reads_a_voice_line_with_no_wav_reference_as_wav_path_none() {
    let _ = shared_home();
    let server_label = "history-voice-no-wav_1";
    let dir = exports_dir_for(server_label).join("channels");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("general.log"), "[2026-08-26T12:00:00Z] <- erin: voice (2.0s)\n").unwrap();

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1);
    match &chunk[0].body {
        MessageBody::VoiceOnDisk { duration_ms, wav_path } => {
            assert_eq!(*duration_ms, 2000);
            assert!(wav_path.is_none());
        }
        other => panic!("expected VoiceOnDisk, got {other:?}"),
    }
}

/// A `format_line`d `File` reference has no live stream/size/status left
/// to attach to it - it comes back as an inert text reference, not a real
/// (and misleadingly interactive) `MessageBody::File`.
/// @requirement AC-360
#[test]
fn history_cursor_reads_a_file_reference_as_plain_text() {
    let _ = shared_home();
    let server_label = "history-file-as-text_1";
    export::autosave_entry(server_label, Surface::Channel("general"), &file_entry("frank", "report.pdf"));

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1);
    assert_eq!(chunk[0].body, MessageBody::Text("[file] report.pdf".to_string()));
}

/// `System` and `Presence` are textually identical on disk (`format_line`
/// only ever writes `[<utc>] <text>` for both) - the distinction can't be
/// recovered, so both come back as `System`.
/// @requirement AC-360
#[test]
fn history_cursor_collapses_system_and_presence_into_system() {
    let _ = shared_home();
    let server_label = "history-presence-collapse_1";
    export::autosave_entry(
        server_label,
        Surface::Channel("general"),
        &presence_entry("carol disconnected"),
    );

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1);
    assert_eq!(chunk[0].body, MessageBody::System("carol disconnected".to_string()));
}

/// A pasted multi-line `Text` message's continuation lines carry no
/// `[<timestamp>] ...` prefix of their own on disk - the cursor must fold
/// them back into the one record they belong to, not read each as its own
/// (malformed) entry.
/// @requirement AC-360
#[test]
fn history_cursor_reassembles_a_multiline_pasted_text_entry() {
    let _ = shared_home();
    let server_label = "history-multiline_1";
    export::autosave_entry(
        server_label,
        Surface::Channel("general"),
        &text_entry(false, "alice", "line one\nline two\nline three"),
    );

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1, "the three physical lines should reassemble into one entry");
    assert_eq!(chunk[0].body, MessageBody::Text("line one\nline two\nline three".to_string()));
}

/// A malformed/unparseable line is skipped, never a hard failure - the
/// same tolerance `Settings::parse` gives a bad settings line.
/// @requirement AC-360
#[test]
fn history_cursor_skips_unparseable_lines() {
    let _ = shared_home();
    let server_label = "history-garbage-tolerant_1";
    let dir = exports_dir_for(server_label).join("channels");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("general.log"),
        "not a valid record at all\n[2026-08-26T12:00:00Z] <- alice: real message\n",
    )
    .unwrap();

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1, "the garbage line should be skipped, not returned or panicked on");
    assert_eq!(chunk[0].body, MessageBody::Text("real message".to_string()));
}

/// Chunks come back oldest-first, newest chunk first as the cursor is
/// drained, exactly the order needed to prepend onto the front of a live
/// log one chunk at a time while scrolling up.
/// @requirement AC-360
#[test]
fn history_cursor_chunks_across_multiple_calls_newest_chunk_first() {
    let _ = shared_home();
    let server_label = "history-chunking_1";
    for n in 1..=5 {
        export::autosave_entry(
            server_label,
            Surface::Channel("general"),
            &text_entry(false, "alice", &format!("message {n}")),
        );
    }

    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 0);
    let newest_two = cursor.next_chunk(2);
    assert_eq!(
        newest_two.iter().map(|e| &e.body).collect::<Vec<_>>(),
        vec![&MessageBody::Text("message 4".to_string()), &MessageBody::Text("message 5".to_string())]
    );
    assert!(cursor.has_more());
    let next_two = cursor.next_chunk(2);
    assert_eq!(
        next_two.iter().map(|e| &e.body).collect::<Vec<_>>(),
        vec![&MessageBody::Text("message 2".to_string()), &MessageBody::Text("message 3".to_string())]
    );
    assert!(cursor.has_more());
    let last_one = cursor.next_chunk(2);
    assert_eq!(last_one.iter().map(|e| &e.body).collect::<Vec<_>>(), vec![&MessageBody::Text("message 1".to_string())]);
    assert!(!cursor.has_more());
    assert!(cursor.next_chunk(10).is_empty(), "exhausted - nothing left to give");
}

/// The `already_loaded` skip rule (`resume_from_log` + `autosave_messages`
/// on together, in the same session): whatever's already mirrored into
/// memory at the moment history-reading starts must not come back a
/// second time from disk.
/// @requirement AC-360
#[test]
fn history_cursor_open_skips_already_loaded_records_from_the_end() {
    let _ = shared_home();
    let server_label = "history-skip-already-loaded_1";
    for n in 1..=3 {
        export::autosave_entry(
            server_label,
            Surface::Channel("general"),
            &text_entry(false, "alice", &format!("message {n}")),
        );
    }

    // Simulate "2 of these 3 are already live in memory" - only "message
    // 1" should ever be reachable through the cursor.
    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("general"), 2);
    assert!(cursor.has_more());
    let chunk = cursor.next_chunk(10);
    assert_eq!(chunk.len(), 1);
    assert_eq!(chunk[0].body, MessageBody::Text("message 1".to_string()));
    assert!(!cursor.has_more());
}

/// No `.log` file at all (nothing ever autosaved for this surface, or a
/// fresh server/channel) reads as having nothing to load - `resume_from_log`
/// must degrade to a no-op, not an error.
/// @requirement AC-360
#[test]
fn history_cursor_on_a_missing_file_has_nothing_to_load() {
    let _ = shared_home();
    let server_label = "history-missing-file_1";
    let mut cursor = LogHistoryCursor::open(server_label, Surface::Channel("nonexistent"), 0);
    assert!(!cursor.has_more());
    assert!(cursor.next_chunk(10).is_empty());
}
