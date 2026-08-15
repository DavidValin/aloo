//! File transfer: the `Content::File` plaintext shape, the size bound a
//! send is checked against before encrypting, and the default save
//! location - shared by the sending side (`ui::file_send`) and the
//! receiving side (`ui::ui`'s save popup).
//!
//! A file is sent exactly like text (`docs/PROTOCOL.md`'s file transfer
//! section): one ordinary `ClientMessage::SendChannel`/`SendDirect` whose
//! `Envelope::content` is `Content::File` and whose encrypted plaintext -
//! recovered the same way `Content::Text`'s is, via
//! `crypto::decrypt_chunked` - is a bincode encoding (`proto::encode`/
//! `decode`) of `FilePayload`, defined here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The plaintext wrapped inside `Envelope::blocks` for `Content::File` -
/// bundling the filename with the data keeps it as private as the rest of
/// the message (unlike, say, `voice`'s duration, which is cleartext
/// metadata on the wire): the server never sees a filename at all, only an
/// opaque blob the same size (roughly) as any other message of that length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePayload {
    pub filename: String,
    pub data: Vec<u8>,
}

/// Largest raw file size (before RSA-OAEP encryption) a send is allowed to
/// start. A `ClientMessage::SendChannel` carries one independently-
/// encrypted `Envelope` per channel member in a *single* frame
/// (`docs/PROTOCOL.md` §7.1), so worst-case ciphertext size scales with
/// both file size and recipient count - unlike voice, which spreads the
/// same total bytes across many small `StreamChannelChunk` frames instead
/// (§7.3). Worst-case RSA-OAEP expansion is with a 2048-bit key (the
/// `Rsa`/`Password`/`None` `my_key` size, `crypto::RSA_KEY_BITS`): a
/// 256-byte ciphertext block per 190 bytes of plaintext, ~1.35x. Capping
/// raw file size at 1 MiB keeps even a generously-sized 20-member channel
/// (~27 MiB total) comfortably under `proto::MAX_FRAME_LEN` (64 MiB).
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// `~/.aloo/download` (`platform::aloo_dir()` joined with `download`),
/// same convention as `idstore::default_path`/`own_next_keys::default_path`
/// - always under the resolved home directory, never a loose file in the
/// current working directory. This is only the *default* prefill for the
/// receiving side's save-location field; like `id_store`/`own_next_keys`,
/// it's freely editable before the save is confirmed. Not created until a
/// file is actually saved into it (mirrors `IdStore::save`'s lazy
/// `create_dir_all`).
pub fn default_download_dir() -> PathBuf {
    crate::platform::aloo_dir().join("download")
}

/// Reduces a peer-supplied filename to just its final path component, so it
/// can never be used as-is to build a save path outside the intended
/// download directory (e.g. a sender naming their file `../../.bashrc` or
/// an absolute path). Falls back to `"file"` if that yields nothing usable
/// (an empty name, `..`, or a name that's entirely path separators) - the
/// save popup's path field is still freely editable afterward, exactly like
/// this app's other path fields (`id_store`, `own_next_keys`), so this only
/// has to protect the *default* prefill, not every possible path a user
/// might type in themselves.
pub fn safe_filename(name: &str) -> String {
    Path::new(name)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "file".to_string())
}
