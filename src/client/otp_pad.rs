//! Streaming delivery of a one-time pad between two peers, and the
//! two-phase commit that decides whether either side may keep it.
//!
//! # Why a stream, and not envelopes
//!
//! Provisioning used to send the pad as a burst of `Content::OtpKeySetup`
//! envelopes, each carrying 16KB of each key. That could not work:
//!
//! * **Overhead.** Every `pq_hybrid` envelope carries an ML-DSA-87
//!   signature, an ML-KEM ciphertext and an RSA ciphertext - roughly 7KB,
//!   fixed, per chunk. Amortised over 32KB of payload that is tolerable; at
//!   `crypto::otp::OTP_SIZE_MB_MAX` it is terabytes of pure overhead.
//! * **Fragmentation.** The resulting datagrams were ~40KB, which IP
//!   fragments into ~28 pieces. Losing any one piece loses the whole
//!   chunk, and a great deal of NAT and firewall equipment drops UDP
//!   fragments outright - so on a real internet path the setup usually
//!   never arrived at all, while working perfectly on loopback.
//!
//! A pad now rides exactly what a file transfer rides: one
//! `StreamKeySetup` establishes a symmetric key, then the bytes stream as
//! small `OtpPadChunk`s that fit a single un-fragmented datagram. The key
//! exchange is paid once instead of per chunk.
//!
//! The two keys go back to back - the peer's encryption half first, then
//! its decryption half - so the transfer is `2 * key_len` bytes and the
//! receiver splits it at `key_len`. Nothing marks the boundary on the
//! wire; both sides know it from `OtpPadStart`.
//!
//! # Pacing
//!
//! The sender only hands over more chunks while the link's outbound depth
//! is under `PAD_INFLIGHT_FRAMES` (`p2p::PeerLinkManager::outbound_depth`).
//! Without that, a producer reading from disk outruns the link and the
//! reliable layer's backlog grows until memory runs out - which is exactly
//! what the old `PENDING_MAX`-derived 16MB ceiling was working around. With
//! it, the transfer paces itself to whatever the link actually drains and
//! the pad's size stops being bounded by memory at all.
//!
//! # The two-phase commit
//!
//! A one-time pad has no integrity check - that is the point of the cipher,
//! and it is why a mismatched pair is dangerous: two keys differing by one
//! byte produce ciphertext that decodes to silent garbage, with nothing
//! anywhere reporting an error. So **neither side installs until both have
//! proven they hold identical bytes**:
//!
//! ```text
//!   sender                                            receiver
//!     |  OtpPadStart { key_len, enc_digest, dec_digest }  |
//!     |-------------------------------------------------->|
//!     |  StreamKeySetup, then OtpPadChunk * n, OtpPadEnd  |
//!     |-------------------------------------------------->|  reassembles into .tmp,
//!     |                                                    |  checks length + digests,
//!     |                                                    |  asks the user
//!     |            OtpPadVerify { accepted, digests }      |
//!     |<--------------------------------------------------|  (still installs nothing)
//!  compares digests with its own;                          |
//!  installs its own half only if they match                |
//!     |            OtpPadCommit                            |
//!     |-------------------------------------------------->|  now installs its half
//!     |            OtpPadCommitAck                         |
//!     |<--------------------------------------------------|
//! ```
//!
//! Every file involved is written under `.tmp/` and only renamed out of it
//! once complete (`client::otp_staging`), so an interruption at any point
//! above leaves nothing installable behind.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::client::p2p::P2pOutbound;
use crate::client::voice_stream::{self, ChunkDecryptor, DecryptJob, DirectStreamKey, IncomingStreamKey};
use crate::crypto::otp::KeyDigest;
use crate::proto::UserId;

/// Plaintext pad bytes per `OtpPadChunk` frame.
///
/// Bounded by one un-fragmented datagram: `p2p_proto::SAFE_DATAGRAM_BYTES`
/// is 1200, and this frame's own encoding costs a measured 44 bytes on top
/// of the sealed chunk (`test/otp_pad_test.rs`), leaving 1156. 1024 takes
/// that with headroom to spare rather than shaving the last 12%.
///
/// It is deliberately *not* `file_transfer::FILE_CHUNK_BYTES` any more.
/// That constant is 512 because a file chunk may be RSA-OAEP sealed, which
/// expands 512 bytes to ~768; a pad chunk is always AES-256-GCM
/// (`start_pad_send` builds a `DirectStreamKey::Pq`, and
/// `crypto::pq::seal_chunk` adds only a 16-byte tag), so it inherited a
/// constraint that never applied to it. Since the reliable layer moves at
/// most `SEND_WINDOW` frames per round trip, that inherited 512 was
/// halving provisioning throughput for nothing.
pub const PAD_CHUNK_BYTES: usize = 1024;

/// How many frames the sender may have outstanding before it stops reading
/// more pad off disk.
///
/// **Must stay below `p2p::PENDING_MAX`**, and is derived from it so it
/// cannot drift. `outbound_depth` - the signal this throttles against - is
/// `arq_tx.depth() + pending.len()`, and on a link that is not yet `Active`
/// the first term is zero while the second *saturates* at `PENDING_MAX`.
/// A bound above that can therefore never be reached, so the worker sees
/// no backpressure at all and reads the entire pad at disk speed into a
/// queue that discards its oldest entry on overflow - shredding the front
/// of the transfer, continuously, while the progress bar races to 100%.
/// That is not a slow transfer; it is a destroyed one.
///
/// Half of `PENDING_MAX` leaves the queue as much room again for
/// everything else the link carries, and is still four times
/// `p2p_reliable::SEND_WINDOW`, so the link is never left waiting on the
/// disk.
pub const PAD_INFLIGHT_FRAMES: usize = crate::client::p2p::PENDING_MAX / 2;

/// How much pad must be handed over before the sender reports progress
/// again. Fine enough that the bar moves visibly on a small pad, coarse
/// enough that a large one does not drown the session loop in events.
pub const PAD_PROGRESS_BYTES: u64 = 256 * 1024;

/// One end of a pad transfer in progress on the *sending* side.
pub(crate) struct OutgoingPad {
    pub stream_id: u64,
    /// Set once the worker has streamed every byte; the commit may only be
    /// sent after the receiver has verified, never before.
    pub sent: bool,
    /// How much this peer's link is currently carrying, republished each
    /// tick by the session loop. The worker reads it to decide whether to
    /// pull more pad off disk - a plain shared counter rather than a
    /// closure into the link manager, which lives in `SessionState` and
    /// cannot be borrowed by another thread.
    pub depth: Arc<AtomicUsize>,
    /// Plaintext pad bytes the worker has read off disk and handed to the
    /// link. This is *not* what the progress bar shows: it runs ahead of
    /// delivery by whatever the link is still carrying, which is the whole
    /// point of `PAD_INFLIGHT_FRAMES`. Subtracting that backlog is what
    /// turns it into something honest to display
    /// (`client::otp::refresh_pad_send_progress`).
    pub read_bytes: u64,
}

/// A pad arriving from a peer, reassembled straight to disk.
pub(crate) struct IncomingPad {
    pub stream_id: u64,
    pub contact_name: String,
    pub keypair_size_mb: u32,
    /// What the sender says its halves hash to - checked against what we
    /// actually reassemble before the user is even asked.
    pub enc_digest: KeyDigest,
    pub dec_digest: KeyDigest,
    /// Where the two halves are being written, inside `.tmp/`.
    pub dir: PathBuf,
    pub job_tx: tokio::sync::mpsc::UnboundedSender<DecryptJob>,
    /// Ciphertext bytes handed to the worker so far - drives the transfer
    /// popup's bar and nothing else.
    pub received_bytes: u64,
}

/// What the receiving worker reports back when a pad transfer finishes.
#[derive(Debug)]
pub(crate) enum PadEvent {
    /// Every byte arrived and both halves hashed to what the sender
    /// declared. `dir` holds `enc.key`/`dec.key`, still inside `.tmp/`.
    Received {
        from: UserId,
        stream_id: u64,
        enc_digest: KeyDigest,
        dec_digest: KeyDigest,
    },
    /// The transfer ended without producing a usable pad - short, corrupt,
    /// or a digest that did not match. Nothing is installable; the staging
    /// directory has already been erased.
    Failed {
        from: UserId,
        stream_id: u64,
        reason: String,
    },
    /// The sending worker has handed over another slice of the pad.
    /// Emitted every `PAD_PROGRESS_BYTES` rather than per chunk: at
    /// `PAD_CHUNK_BYTES` each, a per-chunk event would be thousands of
    /// wakeups per megabyte for a bar that moves in whole percent.
    SendProgress {
        to: UserId,
        stream_id: u64,
        sent_bytes: u64,
    },
    /// The sending worker has streamed the whole pad.
    Sent { to: UserId, stream_id: u64 },
    /// The sending worker could not read the pad it was asked to send.
    SendFailed { to: UserId, stream_id: u64, reason: String },
}

/// The two files a reassembled pad is written to, inside its staging dir.
pub fn incoming_paths(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    (dir.join("enc.key"), dir.join("dec.key"))
}

/// Streams `enc_path` then `dec_path` to `to` as `OtpPadChunk`s, pacing
/// against `depth_of` so the link is never handed more than
/// `PAD_INFLIGHT_FRAMES` at once.
///
/// Runs on its own thread for the same reason the file sender does: it is
/// a blocking read loop over a file that may be enormous, and it must not
/// sit on the session's event loop. The depth is polled rather than
/// awaited because it lives behind the session's own state; the
/// sleep between polls is what turns "too full" into backpressure instead
/// of a spin.
///
/// `depth` is the shared counter the session loop republishes each tick -
/// see `OutgoingPad::depth`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_send_pad_worker(
    enc_path: PathBuf,
    dec_path: PathBuf,
    key: DirectStreamKey,
    to: UserId,
    stream_id: u64,
    out_tx: tokio::sync::mpsc::UnboundedSender<P2pOutbound>,
    events_tx: tokio::sync::mpsc::UnboundedSender<PadEvent>,
    depth: Arc<AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
) {
    std::thread::spawn(move || {
        let mut seq: u32 = 0;
        let mut sent: u64 = 0;
        let mut reported: u64 = 0;
        for path in [enc_path, dec_path] {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    let _ = events_tx.send(PadEvent::SendFailed {
                        to,
                        stream_id,
                        reason: format!("{}: {e}", path.display()),
                    });
                    return;
                }
            };
            let mut reader = std::io::BufReader::with_capacity(PAD_CHUNK_BYTES * 16, file);
            let mut buf = vec![0u8; PAD_CHUNK_BYTES];
            loop {
                // Checked per chunk rather than per file: a pad half can be
                // a terabyte, and a cancel the user has to wait out is not
                // a cancel. Returning here rather than breaking leaves no
                // `Sent` event behind, so nothing downstream believes the
                // transfer completed.
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                let read = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        let _ = events_tx.send(PadEvent::SendFailed {
                            to,
                            stream_id,
                            reason: format!("{}: {e}", path.display()),
                        });
                        return;
                    }
                };
                // Backpressure: wait for the link to drain rather than
                // queueing unboundedly ahead of it. A pad is far larger
                // than anything that could be held as frames.
                //
                // The session loop republishes the link's true depth here,
                // but only once per tick - and this loop can queue tens of
                // thousands of chunks in that time, so waiting on that
                // figure alone let the worker overshoot the bound many
                // times over before it ever saw a new value. Counting our
                // own sends between republishes closes that window: the
                // value is then never an *under*estimate, which is the only
                // direction that matters for a bound.
                while depth.load(Ordering::Relaxed) >= PAD_INFLIGHT_FRAMES {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                let Some(blocks) =
                    voice_stream::encrypt_direct_chunk(&key, stream_id, seq, &buf[..read])
                else {
                    let _ = events_tx.send(PadEvent::SendFailed {
                        to,
                        stream_id,
                        reason: "failed to encrypt a pad chunk".to_string(),
                    });
                    return;
                };
                if out_tx
                    .send(P2pOutbound::OtpPadChunk {
                        to,
                        stream_id,
                        seq,
                        blocks,
                    })
                    .is_err()
                {
                    return;
                }
                depth.fetch_add(1, Ordering::Relaxed);
                seq = seq.wrapping_add(1);
                sent += read as u64;
                if sent - reported >= PAD_PROGRESS_BYTES {
                    reported = sent;
                    let _ = events_tx.send(PadEvent::SendProgress {
                        to,
                        stream_id,
                        sent_bytes: sent,
                    });
                }
            }
        }
        let _ = out_tx.send(P2pOutbound::OtpPadEnd { to, stream_id });
        let _ = events_tx.send(PadEvent::Sent { to, stream_id });
    });
}

/// Decrypts arriving chunks and writes them straight to the two staging
/// files, splitting at `key_len`. Never holds the pad in memory: one chunk
/// at a time, exactly like the file receiver.
///
/// On `End` it checks what it actually wrote - both halves the full
/// `key_len`, and both hashing to what the sender declared - and reports
/// `Received` only if all of that holds. Anything else is `Failed` with the
/// staging directory erased, so a short or corrupted pad can never reach
/// the keychain.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_receive_pad_worker(
    key: IncomingStreamKey,
    dir: PathBuf,
    from: UserId,
    stream_id: u64,
    key_len: u64,
    expected_enc: KeyDigest,
    expected_dec: KeyDigest,
    events_tx: tokio::sync::mpsc::UnboundedSender<PadEvent>,
) -> tokio::sync::mpsc::UnboundedSender<DecryptJob> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DecryptJob>();
    std::thread::spawn(move || {
        let (enc_path, dec_path) = incoming_paths(&dir);
        let fail = |events_tx: &tokio::sync::mpsc::UnboundedSender<PadEvent>,
                    dir: &std::path::Path,
                    reason: String| {
            crate::client::otp_staging::secure_remove_dir(dir);
            let _ = events_tx.send(PadEvent::Failed {
                from,
                stream_id,
                reason,
            });
        };
        let (mut enc_file, mut dec_file) =
            match (std::fs::File::create(&enc_path), std::fs::File::create(&dec_path)) {
                (Ok(a), Ok(b)) => (a, b),
                _ => {
                    fail(&events_tx, &dir, "could not open pad staging files".to_string());
                    return;
                }
            };

        let mut decryptor = ChunkDecryptor::new(key);
        let mut written: u64 = 0;
        let mut failed = false;

        // Splits one decrypted run across the enc/dec boundary at
        // `key_len` - a chunk that straddles it is written to both halves,
        // since nothing on the wire marks where one key ends.
        let mut write_data = |data: Vec<u8>, written: &mut u64, failed: &mut bool| {
            if *failed {
                return;
            }
            let mut rest = data.as_slice();
            while !rest.is_empty() {
                let into_enc = written.saturating_sub(0) < key_len;
                let room = if into_enc {
                    (key_len - *written) as usize
                } else {
                    // Never write past the pad's declared total.
                    ((key_len * 2).saturating_sub(*written)) as usize
                };
                if room == 0 {
                    // More bytes than declared - a malformed or hostile
                    // sender. Refused rather than silently truncated.
                    *failed = true;
                    return;
                }
                let take = room.min(rest.len());
                let target: &mut std::fs::File = if into_enc { &mut enc_file } else { &mut dec_file };
                if target.write_all(&rest[..take]).is_err() {
                    *failed = true;
                    return;
                }
                *written += take as u64;
                rest = &rest[take..];
            }
        };

        while let Some(job) = rx.blocking_recv() {
            match job {
                DecryptJob::KeySetup(blob) => {
                    if failed {
                        continue;
                    }
                    if let Some(waiting) = decryptor.install_setup(stream_id, &blob) {
                        for (_, data) in waiting {
                            write_data(data, &mut written, &mut failed);
                        }
                    }
                }
                DecryptJob::Chunk(seq, blocks) => {
                    if failed {
                        continue;
                    }
                    if let Some(data) = decryptor.decrypt(stream_id, seq, &blocks) {
                        write_data(data, &mut written, &mut failed);
                    }
                }
                DecryptJob::End => break,
            }
        }

        let _ = enc_file.flush();
        let _ = dec_file.flush();
        // Durability before the digests are trusted: a half in the page
        // cache is not yet a half on disk, and the whole point of the
        // check is that what gets installed is what was verified.
        let _ = enc_file.sync_all();
        let _ = dec_file.sync_all();
        drop(enc_file);
        drop(dec_file);

        if failed {
            fail(&events_tx, &dir, "pad transfer failed mid-stream".to_string());
            return;
        }
        if written != key_len * 2 {
            fail(
                &events_tx,
                &dir,
                format!("pad arrived incomplete ({written} of {} bytes)", key_len * 2),
            );
            return;
        }
        let (Ok(enc_digest), Ok(dec_digest)) = (
            crate::crypto::otp::digest_key_file(&enc_path),
            crate::crypto::otp::digest_key_file(&dec_path),
        ) else {
            fail(&events_tx, &dir, "could not verify the received pad".to_string());
            return;
        };
        if enc_digest != expected_enc || dec_digest != expected_dec {
            // The two sides do not hold the same bytes. A pad has no
            // integrity check of its own, so installing this would mean
            // silent garbage later rather than an error now.
            fail(
                &events_tx,
                &dir,
                "the pad that arrived does not match what the sender sent".to_string(),
            );
            return;
        }
        let _ = events_tx.send(PadEvent::Received {
            from,
            stream_id,
            enc_digest,
            dec_digest,
        });
    });
    tx
}
