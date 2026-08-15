//! Consent-gated, streamed file transfer: the sending/receiving background
//! workers and session-scoped bookkeeping for one file transfer
//! (`docs/PROTOCOL.md`'s file transfer section). Mirrors
//! `crate::voice_stream`'s shared plumbing, but a transfer is always a
//! single point-to-point recipient (never a channel broadcast - a channel
//! send is just N independent transfers, one per recipient, see
//! `crate::channel::handle_send_file`) and moves bytes to/from disk instead
//! of the audio mixer. Reuses `voice_stream`'s RSA/PQ dispatch
//! (`DirectStreamKey`, `IncomingStreamKey`, `ChunkDecryptor`,
//! `encrypt_direct_chunk`, `resolve_incoming_key`) rather than duplicating
//! it - a file chunk's plaintext is just arbitrary bytes off disk, exactly
//! as payload-agnostic to those functions as voice's raw PCM already is.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::time::Instant;

use crate::file_transfer::FILE_CHUNK_BYTES;
use crate::proto::{ClientMessage, UserId};
use crate::voice_stream::{self, ChunkDecryptor, DecryptJob, DirectStreamKey, IncomingStreamKey};

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
}

/// Bookkeeping for one currently-arriving incoming file transfer - mirrors
/// `voice_stream::ActiveStream`. Unlike a voice stream, a file transfer has
/// no idle-timeout sweep (`voice_stream::STREAM_IDLE_TIMEOUT`): a large file
/// over a slow link can legitimately go quiet between chunks far longer
/// than voice ever would, so - like the wire protocol's own "no
/// cancellation message" limitation for voice (`docs/PROTOCOL.md` §7.3) - a
/// transfer that never gets a `FileEnd` (sender disconnects mid-send)
/// simply never finalizes; its worker thread and channel are cleaned up
/// only when the process itself ends.
pub(crate) struct ActiveFileTransfer {
    pub(crate) job_tx: tokio::sync::mpsc::UnboundedSender<DecryptJob>,
    pub(crate) last_seen: Instant,
}

/// Progress/completion events for both directions of file transfer,
/// polled by `session::run_connected_session`'s select loop and dispatched
/// into `UiState`'s log-row updates.
pub(crate) enum FileEvent {
    SendProgress { stream_id: u64, bytes: u64 },
    SendDone { stream_id: u64 },
    SendFailed { stream_id: u64 },
    ReceiveProgress { from: UserId, stream_id: u64, bytes: u64 },
    ReceiveDone { from: UserId, stream_id: u64 },
    ReceiveFailed { from: UserId, stream_id: u64 },
}

/// Runs on a dedicated thread for the lifetime of one accepted send: reads
/// `path` incrementally (never the whole file at once - memory use stays
/// bounded to one `FILE_CHUNK_BYTES` chunk regardless of total file size),
/// encrypting and sending each chunk as a `ClientMessage::FileChunk`, then a
/// final `FileEnd`. `out_tx` is `SessionState::record_out_tx` - the same
/// generic "write this `ClientMessage` to the wire" channel the voice
/// recording worker already drains through, so no new select-loop arm is
/// needed for sending.
pub(crate) fn spawn_send_file_worker(
    path: PathBuf,
    key: DirectStreamKey,
    to: UserId,
    stream_id: u64,
    out_tx: tokio::sync::mpsc::UnboundedSender<ClientMessage>,
    events_tx: tokio::sync::mpsc::UnboundedSender<FileEvent>,
) {
    std::thread::spawn(move || {
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("aloo: failed to open {} for sending: {e}", path.display());
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
                    eprintln!("aloo: read error sending {}: {e}", path.display());
                    let _ = events_tx.send(FileEvent::SendFailed { stream_id });
                    return;
                }
            };
            let Some(blocks) = voice_stream::encrypt_direct_chunk(&key, stream_id, seq, &buf[..n]) else {
                let _ = events_tx.send(FileEvent::SendFailed { stream_id });
                return;
            };
            if out_tx.send(ClientMessage::FileChunk { to, stream_id, seq, blocks }).is_err() {
                return;
            }
            sent += n as u64;
            seq += 1;
            let _ = events_tx.send(FileEvent::SendProgress { stream_id, bytes: sent });
        }
        let _ = out_tx.send(ClientMessage::FileEnd { to, stream_id });
        let _ = events_tx.send(FileEvent::SendDone { stream_id });
    });
}

/// Runs on a dedicated thread for the lifetime of one accepted receive:
/// decrypts each chunk and writes it straight to `dest_path` as it arrives
/// (never buffered whole in memory - `create_dir_all` on the parent first,
/// same lazy-create precedent as `IdStore::save`). A chunk that fails to
/// decrypt is silently skipped (matches voice's same-shaped precedent -
/// `ChunkDecryptor::decrypt` returning `None`), rather than aborting the
/// whole transfer over one bad chunk.
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
            eprintln!("aloo: failed to create download directory {}: {e}", parent.display());
            let _ = events_tx.send(FileEvent::ReceiveFailed { from, stream_id });
            return;
        }
        let mut file = match File::create(&dest_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("aloo: failed to create {}: {e}", dest_path.display());
                let _ = events_tx.send(FileEvent::ReceiveFailed { from, stream_id });
                return;
            }
        };
        let mut decryptor = ChunkDecryptor::new(key);
        let mut written: u64 = 0;
        let mut failed = false;
        while let Some(job) = rx.blocking_recv() {
            match job {
                DecryptJob::Chunk(seq, blocks) => {
                    if failed {
                        continue;
                    }
                    if let Some(data) = decryptor.decrypt(stream_id, seq, &blocks) {
                        if let Err(e) = file.write_all(&data) {
                            eprintln!("aloo: write error saving {}: {e}", dest_path.display());
                            failed = true;
                            let _ = events_tx.send(FileEvent::ReceiveFailed { from, stream_id });
                            continue;
                        }
                        written += data.len() as u64;
                        let _ = events_tx.send(FileEvent::ReceiveProgress { from, stream_id, bytes: written });
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
