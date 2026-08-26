//! Writing channel/DM history to disk under `~/.aloo/exports/<server>/`,
//! shared by two independent triggers: continuous autosave
//! (`autosave_messages=on`, one line appended per arriving/sent entry -
//! `crate::client::tui::channel`/`direct_message`'s `push_log_entry`/
//! `finalize_stream_entry` call sites) and the manual `Ctrl+E` popup
//! (`crate::client::tui::export_popup`, a one-shot dump of whatever is
//! currently in memory, files prefixed with a fresh `short_uuid`).
//!
//! `<server>` is `sanitize(host)_port`, or the literal `DIRECT` for a
//! `--no-server` session (`UiState::server_label`, set once at session
//! start - see `crate::client::session::run_connected_session`). Voice
//! entries get a `.wav` file alongside their `.log`, referenced from the
//! log line by filename - there is no WAV-*writing* code anywhere else in
//! this crate (`voice::decode_wav_to_mono` only reads the three bundled
//! chime assets), so `write_wav` below is a small hand-rolled RIFF/WAVE
//! encoder mirroring that reader's structure.

use crate::client::tui::ui::{LogEntry, MessageBody};
use crate::proto::UserId;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The `<server>` label a `--no-server` session's exports live under -
/// confirmed unused as a literal string anywhere else in this crate.
pub const DIRECT_LABEL: &str = "DIRECT";

/// Sanitizes one path component: keeps ASCII alphanumerics, `-`, `_`, `.`,
/// replaces everything else with `_`. Channel names are already
/// filesystem-safe (`validation::channel_name_is_valid`) and pass through
/// unchanged; a DM peer's nickname is not similarly constrained
/// (`ui_connect_popup.rs` only refuses whitespace while typing), and a
/// connect host can be an IPv6 literal (colons) or carry other punctuation
/// - this is the one place both get made safe. An empty result (every
/// character stripped) falls back to `_`, so no export path segment is
/// ever the empty string.
fn sanitize_component(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() { "_".to_string() } else { sanitized }
}

/// `<sanitized host>_<port>` - never collides between two servers sharing
/// a hostname on different ports, unlike a host-only label.
pub fn server_label(host: &str, port: u16) -> String {
    format!("{}_{port}", sanitize_component(host))
}

/// `~/.aloo/exports` - built on `platform::aloo_dir()` (respects
/// `ALOO_HOME`, the same override every other on-disk store honors) rather
/// than a literal `~/.aloo` path.
fn exports_root() -> PathBuf {
    crate::platform::aloo_dir().join("exports")
}

/// Which per-server subtree an entry belongs to.
#[derive(Debug, Clone, Copy)]
pub enum Surface<'a> {
    Channel(&'a str),
    Dm(&'a str),
}

impl Surface<'_> {
    fn dir_name(self) -> &'static str {
        match self {
            Surface::Channel(_) => "channels",
            Surface::Dm(_) => "dms",
        }
    }

    /// The `.log` file's base name (without extension) for this surface -
    /// the channel name as-is (already filesystem-safe), or the DM peer's
    /// nickname sanitized.
    fn base_name(self) -> String {
        match self {
            Surface::Channel(name) => name.to_string(),
            Surface::Dm(name) => sanitize_component(name),
        }
    }
}

fn surface_dir(server_label: &str, surface: Surface) -> PathBuf {
    exports_root()
        .join(sanitize_component(server_label))
        .join(surface.dir_name())
}

/// `2026-08-26T14:23:01Z` - real UTC, unlike `ui::local_time_stamp`/
/// `local_time_short` (local time, with a UTC-string fallback only when
/// the local offset can't be resolved). Falls back to `unknown-time` on
/// the near-impossible chance the system clock predates the Unix epoch,
/// rather than panicking over a timestamp.
pub fn utc_time_stamp() -> String {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown-time".to_string())
}

/// `20260826T142301Z` - the same instant as `utc_time_stamp`, colon-free
/// so it is a safe filename on every platform this app supports
/// (Windows forbids `:` in a path component).
pub fn utc_time_for_filename() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// `hex_encode(random_bytes(4))` - 8 hex characters, following this
/// crate's existing id-generation convention (`device_id::generate`,
/// `crypto::otp::new_mail_id`) rather than adding a `uuid`/`shortuuid`
/// dependency for one short random tag.
pub fn short_uuid() -> String {
    crate::crypto::hex_encode(&crate::crypto::random_bytes(4))
}

/// One line: `[<utc timestamp>] <arrow> <from_name>: <content>` for an
/// ordinary entry, or `[<utc timestamp>] <text>` for a `System`/`Presence`
/// notice (whose text is already a complete, self-describing sentence -
/// see `MessageBody::Presence`'s doc). `outgoing` picks the arrow so a
/// dump reads as one transcript rather than two interleaved monologues.
/// `voice_filename`, when given, is what a `Voice` entry's line points
/// readers at instead of inlining audio.
fn format_line(entry: &LogEntry, voice_filename: Option<&str>) -> String {
    match &entry.body {
        MessageBody::System(text) | MessageBody::Presence(text) => {
            format!("[{}] {text}", entry.sent_at_utc)
        }
        body => {
            let arrow = if entry.outgoing { "->" } else { "<-" };
            let content = match body {
                MessageBody::Text(text) => text.clone(),
                MessageBody::Voice { duration_ms, .. } => match voice_filename {
                    Some(name) => {
                        format!("voice ({:.1}s) -> {name}", *duration_ms as f64 / 1000.0)
                    }
                    None => format!("voice ({:.1}s)", *duration_ms as f64 / 1000.0),
                },
                MessageBody::VoiceStreaming { .. } => "voice (streaming...)".to_string(),
                // Never actually reached in practice - a `VoiceOnDisk` row
                // is prepended straight into a live log by
                // `UiState::load_history_chunk`, never routed through
                // `push_log_entry`/`autosave_entry`. Handled rather than
                // `unreachable!()`'d anyway: nothing about the type system
                // rules it out, and a future call site doing so should
                // degrade to a sensible line, not panic.
                MessageBody::VoiceOnDisk { duration_ms, .. } => {
                    format!("voice ({:.1}s) (unloaded)", *duration_ms as f64 / 1000.0)
                }
                MessageBody::File { filename, .. } => format!("[file] {filename}"),
                MessageBody::System(_) | MessageBody::Presence(_) => unreachable!(),
            };
            format!("[{}] {arrow} {}: {content}", entry.sent_at_utc, entry.from_name)
        }
    }
}

/// Hand-rolled mono 16-bit PCM RIFF/WAVE writer: a 44-byte canonical
/// header plus the raw samples, the simplest form `voice::decode_wav_to_mono`
/// (its read-side counterpart) already knows how to walk back. `pcm_bytes`
/// is already the right shape - `MessageBody::Voice.pcm` is
/// `voice::pcm_from_bytes`-decoded PCM16 LE mono, so this only ever
/// wraps it, never resamples or transcodes.
fn write_wav(path: &Path, pcm_bytes: &[u8], sample_rate: u32) -> io::Result<()> {
    const BITS_PER_SAMPLE: u16 = 16;
    const CHANNELS: u16 = 1;
    let block_align = CHANNELS * (BITS_PER_SAMPLE / 8);
    let byte_rate = sample_rate * block_align as u32;
    let data_len = pcm_bytes.len() as u32;

    let mut header = Vec::with_capacity(44);
    header.extend_from_slice(b"RIFF");
    header.extend_from_slice(&(36 + data_len).to_le_bytes());
    header.extend_from_slice(b"WAVE");
    header.extend_from_slice(b"fmt ");
    header.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    header.extend_from_slice(&1u16.to_le_bytes()); // PCM
    header.extend_from_slice(&CHANNELS.to_le_bytes());
    header.extend_from_slice(&sample_rate.to_le_bytes());
    header.extend_from_slice(&byte_rate.to_le_bytes());
    header.extend_from_slice(&block_align.to_le_bytes());
    header.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    header.extend_from_slice(b"data");
    header.extend_from_slice(&data_len.to_le_bytes());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(&header)?;
    file.write_all(pcm_bytes)?;
    Ok(())
}

/// Picks `<base>.wav`, or `<base>-2.wav`/`<base>-3.wav`/... the first name
/// under `dir` that doesn't already exist - two voice messages from the
/// same person in the same UTC second are rare but not impossible.
fn non_colliding_wav_path(dir: &Path, base: &str) -> PathBuf {
    let candidate = dir.join(format!("{base}.wav"));
    if !candidate.exists() {
        return candidate;
    }
    let mut n = 2u32;
    loop {
        let candidate = dir.join(format!("{base}-{n}.wav"));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

/// Writes `entry`'s `.wav` (if it is a finished `Voice` entry) into `dir`
/// and returns the filename actually used, ready to hand to `format_line`.
/// A no-op returning `None` for every other body - including
/// `VoiceStreaming`, which has no audio yet (the placeholder push through
/// `push_log_entry` reaches here before the stream finishes; the real
/// write happens once `finalize_stream_entry` swaps in the real `Voice`
/// body and its call site autosaves *that* entry).
fn write_voice_wav_if_any(dir: &Path, entry: &LogEntry, filename_prefix: &str) -> Option<String> {
    let MessageBody::Voice { pcm, .. } = &entry.body else {
        return None;
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        crate::log_warn!("could not create {} for voice export ({e})", dir.display());
        return None;
    }
    let base = format!(
        "{filename_prefix}{}_{}",
        utc_time_for_filename(),
        sanitize_component(&entry.from_name)
    );
    let path = non_colliding_wav_path(dir, &base);
    match write_wav(&path, pcm, crate::client::voice::SAMPLE_RATE_HZ) {
        Ok(()) => path.file_name().map(|n| n.to_string_lossy().into_owned()),
        Err(e) => {
            crate::log_warn!("could not write {} ({e})", path.display());
            None
        }
    }
}

fn append_line(path: &Path, line: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")
}

/// Appends one already-arrived-or-sent entry to the continuous per-surface
/// log (`autosave_messages=on`). A no-op for a `VoiceStreaming` placeholder
/// (nothing to write yet) and, on any I/O failure, a `log_warn!` rather
/// than a panic or a blocked UI - autosave must never be able to break a
/// session.
pub fn autosave_entry(server_label: &str, surface: Surface, entry: &LogEntry) {
    if matches!(entry.body, MessageBody::VoiceStreaming { .. }) {
        return;
    }
    let dir = surface_dir(server_label, surface);
    let voice_filename = write_voice_wav_if_any(&dir, entry, "");
    let line = format_line(entry, voice_filename.as_deref());
    let log_path = dir.join(format!("{}.log", surface.base_name()));
    if let Err(e) = append_line(&log_path, &line) {
        crate::log_warn!("could not autosave to {} ({e})", log_path.display());
    }
}

/// Dumps a whole in-memory log at once (the `Ctrl+E` manual export) into
/// `<prefix>_<surface base name>.log` plus one `<prefix>_<utc>_<nickname>.wav`
/// per finished voice entry - `prefix` is one `short_uuid()` shared by
/// every file a single export produces, so repeated exports (and the
/// continuous autosave files beside them) never collide. Reuses
/// `format_line`/`write_wav` so a line here is shaped identically to an
/// autosaved one; `VoiceStreaming` entries (a message still mid-flight at
/// export time) are skipped, same as autosave.
pub fn export_log(server_label: &str, surface: Surface, prefix: &str, log: &[LogEntry]) -> io::Result<()> {
    let dir = surface_dir(server_label, surface);
    let file_prefix = format!("{prefix}_");
    let mut lines = Vec::with_capacity(log.len());
    for entry in log {
        if matches!(entry.body, MessageBody::VoiceStreaming { .. }) {
            continue;
        }
        let voice_filename = write_voice_wav_if_any(&dir, entry, &file_prefix);
        lines.push(format_line(entry, voice_filename.as_deref()));
    }
    std::fs::create_dir_all(&dir)?;
    let log_path = dir.join(format!("{prefix}_{}.log", surface.base_name()));
    std::fs::write(&log_path, lines.join("\n") + if lines.is_empty() { "" } else { "\n" })
}

// ---------------------------------------------------------------------
// Resuming history back in (`resume_from_log`) - the read-side counterpart
// of everything above. Reads only ever touch the continuous per-surface
// `.log` (never a `Ctrl+E` export's uuid-prefixed one-off snapshot, which
// is a point-in-time dump, not a resumable stream).
// ---------------------------------------------------------------------

/// Whether `line` opens a new on-disk record - `[` + a strict 20-byte
/// `YYYY-MM-DDTHH:MM:SSZ` (`utc_time_stamp`'s exact shape) + `] `. Strict
/// on purpose: a loose check would misparse a continuation line of a
/// pasted multi-line message that happens to start with something
/// bracket-shaped.
fn is_record_boundary(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 23
        && b[0] == b'['
        && b[21] == b']'
        && b[22] == b' '
        && looks_like_utc_timestamp(&line[1..21])
}

fn looks_like_utc_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && b.iter().enumerate().all(|(i, &c)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || c.is_ascii_digit())
}

/// Reassembles a `.log` file's raw lines into logical records - `format_line`
/// writes a `MessageBody::Text` verbatim, so a pasted multi-line message's
/// continuation lines land in the file with no `[<timestamp>] ...` prefix
/// of their own; every such line is folded back into the record above it.
/// A file that starts mid-record (truncated/corrupted) keeps its first
/// line as its own record rather than panicking - `parse_log_entry` skips
/// whatever doesn't parse.
fn group_into_records(contents: &str) -> Vec<String> {
    let mut records: Vec<String> = Vec::new();
    for line in contents.lines() {
        if records.is_empty() || is_record_boundary(line) {
            records.push(line.to_string());
        } else {
            let last = records.last_mut().expect("just checked non-empty");
            last.push('\n');
            last.push_str(line);
        }
    }
    records
}

/// A stable-within-this-process id for a reconstructed sender - nothing on
/// disk names a real `UserId`, and a reconstructed row is inert (no
/// receipt, delivery, or crypto state ever keys off it), so all this needs
/// to do is give the same `from_name` the same colour/identity across the
/// rows of one load.
fn synthetic_user_id(from_name: &str) -> UserId {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    from_name.hash(&mut hasher);
    UserId(hasher.finish())
}

/// `format_line`'s inverse. `None` for anything that doesn't match one of
/// its shapes at all - a malformed line is skipped, never a hard failure,
/// the same tolerance `Settings::parse` gives a bad settings line.
///
/// What's necessarily lossy, all by design (see the plan's "design
/// decisions"): `System` and `Presence` are textually identical on disk
/// and both come back as `System`; a `[file] <name>` reference comes back
/// as plain `Text` (there is no live stream/size/status left to attach to
/// it); `sent_at` is set to the same string as `sent_at_utc` rather than
/// reconstructing a local-time rendering of that instant; every
/// receipt/delivery/crypto field is `None`, and `listened` is always
/// `true` (the "not listened" marker is about this session's live
/// arrivals, not a verdict on old history).
fn parse_log_entry(record: &str, log_dir: &Path) -> Option<LogEntry> {
    if !is_record_boundary(record) {
        return None;
    }
    let sent_at_utc = record[1..21].to_string();
    let rest = &record[23..];

    let (outgoing, rest) = if let Some(r) = rest.strip_prefix("-> ") {
        (true, r)
    } else if let Some(r) = rest.strip_prefix("<- ") {
        (false, r)
    } else {
        // System/Presence: no arrow, no name - the whole remainder is the
        // already-complete sentence `format_line` wrote.
        return Some(LogEntry {
            from: UserId(0),
            from_name: String::new(),
            to_name: None,
            body: MessageBody::System(rest.to_string()),
            outgoing: false,
            failed: false,
            sent_at: sent_at_utc.clone(),
            sent_at_utc,
            delivery: None,
            owed_receipt: None,
            crypto: None,
            listened: true,
        });
    };

    let (from_name, content) = rest.split_once(": ")?;
    let body = if let Some(after_voice) = content.strip_prefix("voice (") {
        let (secs, remainder) = after_voice.split_once("s)")?;
        let duration_ms = (secs.parse::<f64>().ok()? * 1000.0).round() as u32;
        let wav_path = remainder.strip_prefix(" -> ").map(|name| log_dir.join(name));
        MessageBody::VoiceOnDisk { duration_ms, wav_path }
    } else {
        MessageBody::Text(content.to_string())
    };

    Some(LogEntry {
        from: synthetic_user_id(from_name),
        from_name: from_name.to_string(),
        to_name: None,
        body,
        outgoing,
        failed: false,
        sent_at: sent_at_utc.clone(),
        sent_at_utc,
        delivery: None,
        owed_receipt: None,
        crypto: None,
        listened: true,
    })
}

/// Lazily reads a surface's `.log` file back-to-front, one chunk at a
/// time, for `resume_from_log`. The whole file's *text* is read once, up
/// front, at `open` - only ever its lines, never the audio a `Voice`
/// entry's `.wav` reference points at, which stays untouched on disk until
/// something actually asks to play that one row
/// (`UiState::handle_messages_key`'s `Enter` arm).
#[derive(Debug, Clone)]
pub struct LogHistoryCursor {
    records: Vec<String>,
    consumed_from_end: usize,
    log_dir: PathBuf,
}

impl LogHistoryCursor {
    /// `already_loaded` is how many of the file's own newest records to
    /// skip on open - this session's own `autosave_messages` writes may
    /// already be sitting at the tail of the file, mirrored 1:1 by
    /// whatever's already in this surface's in-memory log at the moment
    /// history-reading starts (see the plan for why `already_loaded` being
    /// exactly that count, rather than a heuristic, is correct). A file
    /// that doesn't exist yet reads as having no records at all - every
    /// method below then behaves exactly as if nothing were ever on disk.
    pub fn open(server_label: &str, surface: Surface, already_loaded: usize) -> Self {
        let log_dir = surface_dir(server_label, surface);
        let log_path = log_dir.join(format!("{}.log", surface.base_name()));
        let records = std::fs::read_to_string(&log_path)
            .map(|contents| group_into_records(&contents))
            .unwrap_or_default();
        let consumed_from_end = already_loaded.min(records.len());
        Self { records, consumed_from_end, log_dir }
    }

    pub fn has_more(&self) -> bool {
        self.consumed_from_end < self.records.len()
    }

    /// Takes up to `n` records immediately before what's already been
    /// consumed, oldest-first - ready to prepend directly onto the front
    /// of a live `log: Vec<LogEntry>`. Advances the cursor by however many
    /// records were actually examined even if some didn't parse, so a run
    /// of unparseable lines can never stall `has_more` into looping.
    pub fn next_chunk(&mut self, n: usize) -> Vec<LogEntry> {
        let end = self.records.len() - self.consumed_from_end;
        let start = end.saturating_sub(n);
        let taken = end - start;
        let entries = self.records[start..end]
            .iter()
            .filter_map(|record| parse_log_entry(record, &self.log_dir))
            .collect();
        self.consumed_from_end += taken;
        entries
    }
}
