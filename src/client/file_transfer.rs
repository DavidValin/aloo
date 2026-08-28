//! Consent-gated, streamed file transfer: the offer's plaintext shape,
//! filename truncation, the chunking granularity, the default download
//! location, and the sending/receiving background workers with their
//! session-scoped bookkeeping (`docs/PROTOCOL.md`'s file transfer section).
//!
//! The sender's `FileOffer` carries this module's `FileOfferPayload`
//! (filename + size) as an ordinary encrypted `Envelope`
//! (`Content::FileOffer`), exactly like a text message; only once the
//! receiver responds `FileAccept` does the sender start reading the file
//! and streaming it as `FileChunk` frames, chunked at `FILE_CHUNK_BYTES` -
//! never the whole file at once, on either side (the workers read and
//! write incrementally, so memory use stays bounded to one chunk
//! regardless of total file size).
//!
//! The worker plumbing mirrors `crate::client::voice_stream`'s, but a
//! transfer is always a single point-to-point recipient (never a channel
//! broadcast - a channel send is just N independent transfers, one per
//! recipient, see `crate::client::channel::handle_send_file`) and moves
//! bytes to/from disk instead of the audio mixer. Reuses `voice_stream`'s
//! RSA/PQ dispatch (`DirectStreamKey`, `IncomingStreamKey`,
//! `ChunkDecryptor`, `encrypt_direct_chunk`, `resolve_incoming_key`)
//! rather than duplicating it - a file chunk's plaintext is just arbitrary
//! bytes off disk, exactly as payload-agnostic to those functions as
//! voice's raw PCM already is.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::client::p2p::P2pOutbound;
use crate::client::voice_stream::{
    self, ChunkDecryptor, DecryptJob, DirectStreamKey, IncomingStreamKey,
};
use crate::proto::UserId;

/// The plaintext wrapped inside `Envelope::blocks` for a `FileOffer` -
/// naming the file and its size so the receiver's accept/reject popup can
/// show both before a single byte of file data is sent. Bundled into the
/// encrypted envelope (rather than a cleartext field on `ClientMessage::
/// FileOffer`) so the filename stays as private as the rest of the
/// message - the server never sees it, only an opaque blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOfferPayload {
    pub filename: String,
    pub size: u64,
}

/// `FileOfferPayload`'s voice counterpart, wrapped inside a
/// `Content::VoiceOffer` envelope and then, like a file offer, put through
/// the pad (`client::otp::send_voice_offer`) - so `duration_ms` lives here
/// rather than as a cleartext field, matching how `filename`/`size` stay
/// out of the wire tag above. Padding it is what keeps that true under
/// `Direct` framing, where there is no envelope to hide it in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceOfferPayload {
    pub duration_ms: u32,
}

/// Longest filename, in characters, this app will ever offer or accept -
/// longer names are cropped at the end (`truncate_filename`), applied both
/// when building the offer (sender) and again on whatever offer actually
/// arrives (receiver), so a peer that skips the sender-side crop can't use
/// an oversized name to break receiver-side rendering/paths.
pub const MAX_FILENAME_CHARS: usize = 230;

/// Plaintext bytes read from disk (and RSA/PQ-encrypted) per outgoing
/// `FileChunk` frame - bounds both sides' memory use to roughly one chunk
/// regardless of file size, and drives the progress bar's granularity.
///
/// Sized for the direct peer-to-peer transport: a `FileChunk` is a single
/// UDP datagram, so the budget is `p2p_proto::SAFE_DATAGRAM_BYTES`. 512
/// bytes plaintext expands to at most 3 OAEP blocks (~768 bytes) at the
/// worst-case 2048-bit key size, comfortably under budget with framing
/// overhead added (see `test/file_transfer_test.rs`). Small chunks mean
/// more frames and acks, but the reliable layer pipelines in-flight frames
/// rather than stop-and-wait - a small overhead traded for never risking
/// IP-fragmentation-related loss.
pub const FILE_CHUNK_BYTES: usize = 512;

/// `~/.aloo/downloads` - every accepted transfer is streamed straight here
/// as it arrives (no separate save-location prompt), never a loose file in
/// the current working directory. Created lazily, only once a file is
/// actually accepted.
pub fn default_download_dir() -> PathBuf {
    crate::platform::aloo_dir().join("downloads")
}

/// A paste longer than this many characters is converted to a `.txt` file
/// and sent as a file transfer instead of a message (`UiState::handle_paste`)
/// - well under `proto::TEXT_MESSAGE_MAX_LEN`, so the typed-character cap
/// on that constant never actually fires against pasted text; only
/// manually typed text can ever reach it.
pub const PASTE_TO_FILE_CHAR_THRESHOLD: usize = 5_000;

/// `~/.aloo/tmp` - scratch storage for a `.txt` file synthesized purely to
/// route a long paste through file transfer
/// (`write_pasted_text_file`/`UiState::handle_paste`). Distinct from
/// `default_download_dir` above (received content meant to be kept) and
/// from OTP's own `.tmp/` (`client::otp_staging` - pad material, held to a
/// stricter overwrite-before-remove erase since it is one-time-secret key
/// bytes): this holds ordinary plaintext the user already typed once into
/// the terminal and is about to send anyway, so a plain remove is enough.
pub fn paste_tmp_dir() -> PathBuf {
    crate::platform::aloo_dir().join("tmp")
}

/// Clears every leftover in `paste_tmp_dir()` - called once at session
/// start (`client::session::run_connected_session`), same "anything here
/// is garbage" reasoning as `otp_staging::sweep`: a file only ever lives
/// here between being synthesized and being handed to the file-transfer
/// sender, so anything still present didn't make it that far in some
/// earlier, interrupted run. Best-effort - a leftover that can't be
/// removed is skipped rather than failing session start.
pub fn sweep_paste_tmp_dir() {
    sweep_scratch_dir(&paste_tmp_dir());
}

/// Removes everything directly inside `dir`, best-effort - the shared body
/// of the two sweeps above and below. A plain remove, deliberately: unlike
/// `otp_staging`'s own sweep these directories hold ordinary content, never
/// one-time-pad key bytes, so there is nothing here to overwrite first.
fn sweep_scratch_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Writes `text` to a fresh file under `paste_tmp_dir()` (created if
/// needed) and returns its path - the synthesized `.txt` a long paste
/// becomes before being handed to the ordinary file-send path
/// (`UiState::handle_paste`). The pid+timestamp naming matches
/// `client::otp::temp_content_path`'s collision-free convention.
pub fn write_pasted_text_file(text: &str) -> std::io::Result<PathBuf> {
    let dir = paste_tmp_dir();
    std::fs::create_dir_all(&dir)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("pasted-{}-{nanos}.txt", std::process::id()));
    std::fs::write(&path, text)?;
    Ok(path)
}

/// `~/.aloo/tmp/incoming` - scratch storage for a `.txt` offer's content
/// once it has fully arrived, staged here rather than in
/// `default_download_dir()` so it can be previewed
/// (`UiState::open_file_preview`) without counting as saved
/// (`docs/PROTOCOL.md` 7.2.1a). Distinct from `paste_tmp_dir` (outgoing,
/// synthesized locally by this side) and from `default_download_dir` (a
/// file the user has actually chosen to keep): this holds a peer's
/// content that may never be kept at all.
pub fn incoming_preview_dir() -> PathBuf {
    crate::platform::aloo_dir().join("tmp").join("incoming")
}

/// Clears every leftover in `incoming_preview_dir()` - called once at
/// session start (`client::session::run_connected_session`), same
/// "anything here is garbage" reasoning as `sweep_paste_tmp_dir`: a staged
/// receive only ever sits here between arriving and being either saved
/// (moved out, via `d`) or left behind when the process ends - anything
/// still present didn't make it to either outcome in some earlier,
/// interrupted run.
pub fn sweep_incoming_preview_dir() {
    sweep_scratch_dir(&incoming_preview_dir());
}

/// Whether `name` (already through `safe_filename`) ends in `.txt`,
/// case-insensitively - the one extension the preview popup applies to
/// (`accept_file_offer`).
pub fn is_txt_filename(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
}

/// How much of a staged `.txt` file the preview popup ever reads into
/// memory, however large the real file is (there is no size cap on a file
/// transfer - `there_is_no_size_cap_on_a_file_send`) - `d` still saves the
/// complete, untruncated file regardless; only the in-memory preview is
/// bounded.
pub const PREVIEW_MAX_BYTES: u64 = 1_048_576;

/// Moves a staged `.txt` receive out of `incoming_preview_dir()` into
/// `default_download_dir()`, keeping its filename -
/// `UiAction::SaveStagedFile`'s `d`-in-preview save, identical in effect
/// to an ordinary (non-staged) receive's save on arrival. `rename` first
/// (the common case: both live under `platform::aloo_dir()`, ordinarily
/// one filesystem); falls back to copy-then-remove for the rare case of
/// `~/.aloo` split across filesystems.
pub fn save_staged_file(staged_path: &Path) -> std::io::Result<PathBuf> {
    move_into_dir(staged_path, &default_download_dir())
}

/// `save_staged_file`'s actual move, taking the destination directory as a
/// parameter rather than reading `default_download_dir()` itself - keeps
/// this testable against a scratch directory without touching the real
/// `~/.aloo/downloads` (mutating `ALOO_HOME` to redirect it would not be
/// safe under this crate's parallel test execution - see
/// `platform::aloo_dir`'s doc).
pub fn move_into_dir(staged_path: &Path, dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let name = staged_path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "staged path has no filename")
    })?;
    let dest = dir.join(name);
    if std::fs::rename(staged_path, &dest).is_err() {
        std::fs::copy(staged_path, &dest)?;
        std::fs::remove_file(staged_path)?;
    }
    Ok(dest)
}

/// Reads at most `PREVIEW_MAX_BYTES` of `path` and reports whether the real
/// file is longer than that - `session::handle_ui_action`'s
/// `RequestFilePreview` arm, the one caller (`UiState` does no I/O of its
/// own). Bounded by `metadata().len()` up front rather than reading the
/// whole file and truncating after, so memory use stays capped regardless
/// of how large the actual file is. Lossy UTF-8: a `.txt` file is not
/// guaranteed to be valid UTF-8, and a preview is exactly the place to be
/// forgiving about that rather than refusing to show anything.
pub fn read_txt_preview(path: &Path) -> std::io::Result<(String, bool)> {
    let total_len = std::fs::metadata(path)?.len();
    let cap = PREVIEW_MAX_BYTES.min(total_len) as usize;
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; cap];
    file.read_exact(&mut buf)?;
    Ok((
        String::from_utf8_lossy(&buf).into_owned(),
        total_len > PREVIEW_MAX_BYTES,
    ))
}

/// The name to show for a file the *user* picked, falling back to `"file"`
/// for a path with no final component at all.
///
/// Deliberately not `safe_filename` below: that one is for a filename a
/// *peer* supplied, and additionally strips path traversal and
/// Windows-illegal characters. This is only for display, and for the offer
/// this side is about to build from a path the user chose in a browser, so
/// there is nothing hostile to sanitize - the crop (`truncate_filename`)
/// stays a separate call at each site, exactly as before.
pub(crate) fn display_filename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string())
}

/// Crops `name` to `MAX_FILENAME_CHARS` characters, keeping the first
/// `MAX_FILENAME_CHARS` and discarding the rest - applied sender-side
/// before a `FileOffer` is built, and independently receiver-side on
/// whatever filename actually arrives (never trusted as already-short),
/// since nothing on the wire enforces this length itself.
pub fn truncate_filename(name: &str) -> String {
    name.chars().take(MAX_FILENAME_CHARS).collect()
}

/// Reduces a peer-supplied filename to just its final path component, so it
/// can never be used as-is to build a save path outside the intended
/// download directory (e.g. a sender naming their file `../../.bashrc` or
/// an absolute path). Falls back to `"file"` if that yields nothing usable
/// (an empty name, `..`, or a name that's entirely path separators).
///
/// Also makes the result safe to create *as a file* on Windows, regardless
/// of which OS this binary is actually running on: a sender on Linux/macOS
/// can freely name a file `CON`, `a<b>.txt` or `notes|log.txt` - all legal
/// there - and without this, a Windows receiver's `File::create` on the
/// result would simply fail, silently losing the transfer (logged, not a
/// crash, but no rename fallback exists downstream of this call). Applied
/// unconditionally rather than behind `#[cfg(windows)]`: a Windows-safe
/// filename is harmless on every other OS too, and this way the behavior
/// gets the same test coverage on every platform this suite actually runs
/// on, rather than adding one more Windows-only path nothing exercises.
pub fn safe_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "file".to_string());
    let sanitized = sanitize_windows_filename(&base);
    if sanitized.is_empty() {
        "file".to_string()
    } else {
        sanitized
    }
}

/// The Windows-unsafe part of `safe_filename`: replaces control bytes and
/// `< > : " | ? *` (illegal in a Windows filename, beyond the path
/// separators `file_name()` already stripped above) with `_`, trims
/// trailing `.`/` ` (which Windows silently strips at creation time -
/// trimming here up front means the name that lands in the download
/// directory is the one the offer displayed, not a silently-shortened
/// surprise), and prefixes a name that collides with a reserved device
/// name (`validation::is_windows_reserved_name`, checked against the stem
/// before any extension) with `_` so e.g. `CON.txt` becomes `_CON.txt`
/// rather than a file Windows refuses to create at all. Can return an
/// empty string (e.g. input was entirely `.`/space, like `"..."`) - callers
/// must still fall back to `"file"` in that case.
fn sanitize_windows_filename(name: &str) -> String {
    let replaced: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = replaced.trim_end_matches(['.', ' ']);
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    if crate::validation::is_windows_reserved_name(stem) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

/// What a currently-sending (our own) file transfer is addressed to,
/// remembered from the moment its `FileOffer` is sent so a later
/// `FileAccepted`/`FileRejected` (which only carry `stream_id`) know what to
/// act on. Nothing is read off disk until `FileAccepted` arrives - mirrors
/// `voice_stream::OwnStreamTarget`, keyed the same way (by our own
/// per-connection `stream_id` counter alone, never `(UserId, stream_id)`,
/// since it's always *our* stream).
pub(crate) struct OwnFileTarget {
    pub(crate) to: UserId,
    pub(crate) path: PathBuf,
    pub(crate) key: DirectStreamKey,
    /// `Some(contact_name)` if this transfer is under OTP - the *offer*
    /// already spent its own independent pad slot to reach the peer
    /// (`client::otp::send_file_offer`); `FileAccepted` then reserves a
    /// second, separate slot to OTP-encrypt `path` into a temp file and
    /// streams that instead (`client::otp::start_outgoing_file_content`) -
    /// two independent pad spends, two independent acks, since the pad
    /// tool never allows a second `--encrypt` before the first is
    /// confirmed delivered (docs/PROTOCOL.md 16.2). `None` for an ordinary
    /// (non-OTP) transfer, unchanged from before this field existed.
    pub(crate) otp: Option<String>,
}

/// Bookkeeping for one currently-arriving incoming file transfer - mirrors
/// `voice_stream::ActiveStream`, but with no idle-timeout sweep: a large
/// file over a slow link can legitimately go quiet far longer than voice
/// ever would, so a transfer that never gets a `FileEnd` (sender
/// disconnects mid-send) simply never finalizes; its worker thread is
/// cleaned up only when the process ends.
pub(crate) struct ActiveFileTransfer {
    pub(crate) job_tx: tokio::sync::mpsc::UnboundedSender<DecryptJob>,
    pub(crate) last_seen: Instant,
}

/// What an OTP-protected incoming transfer's content becomes once
/// decrypted - a file lands on disk at `final_path` exactly like a plain
/// transfer; a voice message has no destination file at all, and instead
/// becomes an ordinary `MessageBody::Voice` log entry once its bytes are
/// decoded (`client::otp::finish_incoming_file`).
pub enum OtpIncomingKind {
    File { final_path: PathBuf },
    Voice { duration_ms: u32 },
    /// A transfer re-registered from its wire retry alone
    /// (`client::otp::on_content_seq`): this side restarted after accepting
    /// the offer, so what the content originally was - a file's name and
    /// destination, a voice message's duration - died with the process.
    /// The bytes still land (written under the OTP working directory and
    /// named in a notice), the spend is still acknowledged, and the pads
    /// stay in lockstep - only the presentation is degraded.
    Recovered,
}

/// Bookkeeping for one currently-arriving OTP-protected transfer, kept
/// alongside its `ActiveFileTransfer` entry (same `(UserId, u64)` key).
/// The chunked receive worker writes to `temp_path` - ordinary ciphertext
/// as far as it's concerned - rather than the final destination directly;
/// once `FileEvent::ReceiveDone` fires, `client::otp`'s handling runs
/// `otp_cli::decrypt_file` from `temp_path` and finalizes per `kind`,
/// removes the temp file, and only then acknowledges `seq` back to the
/// sender.
///
/// `seq` is the *content* phase's own OTP sequence number, distinct from
/// the offer's - a file offer's `seq` only ever names the offer's own pad
/// slot (docs/PROTOCOL.md 16.2), so for a file this starts `None` at
/// accept time and is filled in once `P2pEvent::OtpFileContentSeq` arrives
/// (sent once, reliably, ahead of the first `FileChunk`). A voice message
/// has no separate accept step - its one offer/content seq is one and the
/// same, known immediately, so `on_voice_offer` sets this to `Some` right
/// away.
pub struct OtpIncomingFileReceive {
    pub contact_name: String,
    pub seq: Option<u64>,
    pub temp_path: PathBuf,
    pub kind: OtpIncomingKind,
}

/// Progress/completion events for both directions of file transfer,
/// polled by `session::run_connected_session`'s select loop and dispatched
/// into `UiState`'s log-row updates.
pub(crate) enum FileEvent {
    SendProgress {
        stream_id: u64,
        bytes: u64,
    },
    SendDone {
        stream_id: u64,
    },
    SendFailed {
        stream_id: u64,
    },
    ReceiveProgress {
        from: UserId,
        stream_id: u64,
        bytes: u64,
    },
    ReceiveDone {
        from: UserId,
        stream_id: u64,
    },
    ReceiveFailed {
        from: UserId,
        stream_id: u64,
    },
}

/// Runs on a dedicated thread for the lifetime of one accepted send:
/// reads `path` incrementally (one `FILE_CHUNK_BYTES` chunk at a time,
/// never the whole file), encrypting and sending each chunk as a
/// `P2pOutbound::FileChunk`, then a final `FileEnd`. `out_tx` is
/// `SessionState::record_out_tx`, the same channel the voice recorder
/// drains through, so sending needs no new select-loop arm.
pub(crate) fn spawn_send_file_worker(
    path: PathBuf,
    key: DirectStreamKey,
    to: UserId,
    stream_id: u64,
    out_tx: tokio::sync::mpsc::UnboundedSender<P2pOutbound>,
    events_tx: tokio::sync::mpsc::UnboundedSender<FileEvent>,
) {
    std::thread::spawn(move || {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                crate::log_warn!("failed to open {} for sending: {e}", path.display());
                let _ = events_tx.send(FileEvent::SendFailed { stream_id });
                return;
            }
        };
        let mut reader = BufReader::with_capacity(FILE_CHUNK_BYTES, file);
        let mut buf = vec![0u8; FILE_CHUNK_BYTES];
        let mut seq: u32 = 0;
        let mut sent: u64 = 0;
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    crate::log_warn!("read error sending {}: {e}", path.display());
                    let _ = events_tx.send(FileEvent::SendFailed { stream_id });
                    return;
                }
            };
            let Some(blocks) = voice_stream::encrypt_direct_chunk(&key, stream_id, seq, &buf[..n])
            else {
                let _ = events_tx.send(FileEvent::SendFailed { stream_id });
                return;
            };
            if out_tx
                .send(P2pOutbound::FileChunk {
                    to,
                    stream_id,
                    seq,
                    blocks,
                })
                .is_err()
            {
                return;
            }
            sent += n as u64;
            seq += 1;
            let _ = events_tx.send(FileEvent::SendProgress {
                stream_id,
                bytes: sent,
            });
        }
        let _ = out_tx.send(P2pOutbound::FileEnd { to, stream_id });
        let _ = events_tx.send(FileEvent::SendDone { stream_id });
    });
}

/// Runs on a dedicated thread for the lifetime of one accepted receive:
/// decrypts each chunk and writes it straight to `dest_path` as it
/// arrives, never buffered whole in memory. A chunk that fails to decrypt
/// is silently skipped rather than aborting the whole transfer - same
/// policy as voice's `ChunkDecryptor::decrypt` returning `None`.
pub(crate) fn spawn_receive_file_worker(
    key: IncomingStreamKey,
    dest_path: PathBuf,
    from: UserId,
    stream_id: u64,
    events_tx: tokio::sync::mpsc::UnboundedSender<FileEvent>,
) -> tokio::sync::mpsc::UnboundedSender<DecryptJob> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DecryptJob>();
    std::thread::spawn(move || {
        if let Some(parent) = dest_path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            crate::log_warn!(
                "failed to create download directory {}: {e}",
                parent.display()
            );
            let _ = events_tx.send(FileEvent::ReceiveFailed { from, stream_id });
            return;
        }
        let mut file = match File::create(&dest_path) {
            Ok(f) => f,
            Err(e) => {
                crate::log_warn!("failed to create {}: {e}", dest_path.display());
                let _ = events_tx.send(FileEvent::ReceiveFailed { from, stream_id });
                return;
            }
        };
        let mut decryptor = ChunkDecryptor::new(key);
        let mut written: u64 = 0;
        let mut failed = false;
        // One decrypted slice of the file, written and reported. Shared by
        // chunks decrypted on arrival and any replayed once the setup lands
        // (a file's chunks are reliable and ordered, so the backlog is
        // normally empty - but the decryptor's contract is the same either
        // way).
        let write_data = |data: Vec<u8>,
                              file: &mut File,
                              written: &mut u64,
                              failed: &mut bool| {
            if let Err(e) = file.write_all(&data) {
                crate::log_warn!("write error saving {}: {e}", dest_path.display());
                *failed = true;
                let _ = events_tx.send(FileEvent::ReceiveFailed { from, stream_id });
                return;
            }
            *written += data.len() as u64;
            let _ = events_tx.send(FileEvent::ReceiveProgress {
                from,
                stream_id,
                bytes: *written,
            });
        };
        while let Some(job) = rx.blocking_recv() {
            match job {
                DecryptJob::KeySetup(blob) => {
                    if failed {
                        continue;
                    }
                    if let Some(waiting) = decryptor.install_setup(stream_id, &blob) {
                        for (_, data) in waiting {
                            write_data(data, &mut file, &mut written, &mut failed);
                        }
                    }
                }
                DecryptJob::Chunk(seq, blocks) => {
                    if failed {
                        continue;
                    }
                    if let Some(data) = decryptor.decrypt(stream_id, seq, &blocks) {
                        write_data(data, &mut file, &mut written, &mut failed);
                    }
                }
                DecryptJob::End => {
                    if !failed {
                        let _ = events_tx.send(FileEvent::ReceiveDone { from, stream_id });
                    }
                    break;
                }
            }
        }
    });
    tx
}

/// Forwards one incoming `FileChunk`'s blocks to the transfer's decrypt-and-
/// write worker - mirrors `voice_stream::forward_chunk`.
pub(crate) fn forward_chunk(
    active: &mut std::collections::HashMap<(UserId, u64), ActiveFileTransfer>,
    from: UserId,
    stream_id: u64,
    seq: u32,
    blocks: Vec<Vec<u8>>,
) {
    if let Some(t) = active.get_mut(&(from, stream_id)) {
        t.last_seen = Instant::now();
        let _ = t.job_tx.send(DecryptJob::Chunk(seq, blocks));
    }
}

/// Signals a transfer's worker that no more chunks are coming - mirrors
/// `voice_stream::end_incoming_stream`.
pub(crate) fn end_incoming_transfer(
    active: &mut std::collections::HashMap<(UserId, u64), ActiveFileTransfer>,
    from: UserId,
    stream_id: u64,
) {
    if let Some(t) = active.get_mut(&(from, stream_id)) {
        t.last_seen = Instant::now();
        let _ = t.job_tx.send(DecryptJob::End);
    }
}
