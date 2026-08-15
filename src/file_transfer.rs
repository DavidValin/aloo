//! File transfer: the offer's plaintext shape, filename truncation, the
//! chunking granularity, and the default download location - shared by the
//! sending side (`ui::file_send`, `file_stream`) and the receiving side
//! (`file_stream`, `session`).
//!
//! A file transfer is consent-gated and streamed (`docs/PROTOCOL.md`'s file
//! transfer section): the sender's `FileOffer` carries this module's
//! `FileOfferPayload` (filename + size) as an ordinary encrypted `Envelope`
//! (`Content::FileOffer`), exactly like a text message; only once the
//! receiver responds `FileAccept` does the sender start reading the file
//! and streaming it as `FileChunk` frames, chunked at `FILE_CHUNK_BYTES` -
//! never the whole file at once, on either side (`file_stream` reads and
//! writes incrementally, so memory use stays bounded to one chunk
//! regardless of total file size).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

/// Longest filename, in characters, this app will ever offer or accept -
/// longer names are cropped at the end (`truncate_filename`), applied both
/// when building the offer (sender) and again on whatever offer actually
/// arrives (receiver), so a peer that skips the sender-side crop can't use
/// an oversized name to break receiver-side rendering/paths.
pub const MAX_FILENAME_CHARS: usize = 230;

/// Plaintext bytes read from disk (and RSA/PQ-encrypted) per outgoing
/// `FileChunk` frame - small enough to keep both sender and receiver memory
/// use bounded to roughly one chunk regardless of total file size (unlike
/// the old whole-file-in-one-`Envelope` approach this replaces), and what
/// drives the progress bar's granularity. 64 KiB plaintext expands to
/// ~345 OAEP blocks (256 bytes each) at a 2048-bit key - comfortably under
/// `proto::MAX_FRAME_LEN` for a single-recipient frame.
pub const FILE_CHUNK_BYTES: usize = 64 * 1024;

/// `~/.aloo/downloads` (`platform::aloo_dir()` joined with `downloads`),
/// same convention as `idstore::default_path`/`own_next_keys::default_path`
/// - always under the resolved home directory, never a loose file in the
/// current working directory. Every accepted file transfer is streamed
/// straight here as it arrives (never held whole in memory) - there is no
/// separate save-location prompt. Not created until a file is actually
/// accepted (mirrors `IdStore::save`'s lazy `create_dir_all`).
pub fn default_download_dir() -> PathBuf {
    crate::platform::aloo_dir().join("downloads")
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
pub fn safe_filename(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "file".to_string())
}
