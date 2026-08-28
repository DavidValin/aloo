//! Erasing a file that held a secret, and keeping one out of other users'
//! reach.
//!
//! Three modules needed these and each grew its own copy: `client::otp` and
//! `client::otp_staging` for one-time-pad key material, and
//! `client::otp_mail_store` for a received mail's `.ct`/`.pad` pair. The
//! copies had drifted - `otp_mail_store`'s erase allocated a buffer the
//! size of the whole file, which is exactly what `overwrite_with_zeros`
//! below documents itself as avoiding.
//!
//! # What an overwrite here does and does not promise
//!
//! It writes zeros over the bytes the filesystem currently maps for the
//! file, then unlinks it. On an ordinary journalled filesystem backed by a
//! spinning disk that genuinely replaces the data. On a copy-on-write
//! filesystem (btrfs, ZFS), on an SSD with wear levelling, or over a
//! snapshot, the old blocks may survive somewhere this cannot reach - no
//! userspace program can promise otherwise, and this does not pretend to.
//!
//! It is still worth doing: it removes the plain, obvious copy, which is
//! what a `remove_file` alone leaves behind in full.
//!
//! Everything here is best-effort by design. A file that cannot be
//! scrubbed is still unlinked, and a permissions call that fails is
//! ignored - the caller is always on a path where refusing to continue
//! would be worse than proceeding without the extra protection.

use std::io::Write;
use std::path::Path;

/// How much is written per pass when overwriting. Bounded so erasing
/// scales to a 1TB pad (`crypto::otp::OTP_SIZE_MB_MAX`) without scaling
/// memory with it - allocating a buffer that size would abort the process
/// outright.
const ERASE_CHUNK_BYTES: usize = 1024 * 1024;

/// Overwrite-then-unlink for one file. Best-effort: the unlink is
/// attempted even if the overwrite failed, so a file that could not be
/// scrubbed is still not left lying around.
pub fn secure_remove_file(path: &Path) {
    let _ = overwrite_with_zeros(path);
    let _ = std::fs::remove_file(path);
}

/// `secure_remove_file` for every file in `dir`, then the directory
/// itself. Recurses, so a staging directory that grew subdirectories (the
/// `otp` CLI writes its generated pair into `<name>_keys/` subdirectories)
/// is cleaned out entirely rather than leaving the secret bytes inside
/// them.
pub fn secure_remove_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            secure_remove_dir(&path);
        } else {
            secure_remove_file(&path);
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// Streams zeros over `path`'s existing length, in `ERASE_CHUNK_BYTES`
/// passes. Memory use is one buffer regardless of the file's size - see
/// that constant for why that matters here specifically.
fn overwrite_with_zeros(path: &Path) -> std::io::Result<()> {
    let len = std::fs::metadata(path)?.len();
    if len == 0 {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; ERASE_CHUNK_BYTES.min(len as usize)];
    let mut written = 0u64;
    while written < len {
        let this_pass = (len - written).min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..this_pass])?;
        written += this_pass as u64;
    }
    file.flush()?;
    // Best-effort durability: an overwrite the OS still holds in cache
    // when the machine loses power has not actually replaced anything on
    // the platter.
    let _ = file.sync_all();
    Ok(())
}

/// `0o600` - owner read/write, nothing else. For a file holding key
/// material or content that only this user should ever see.
#[cfg(unix)]
pub fn restrict_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
pub fn restrict_file_permissions(_path: &Path) {}

/// `0o700` - the directory counterpart. A directory needs its executable
/// bit to be traversable and writable into at all, so `0o600` (no `x`)
/// would make it impossible to create files inside, unlike a plain file
/// where `0o600` is exactly "owner read/write, nothing else"
/// (`restrict_file_permissions`).
#[cfg(unix)]
pub fn restrict_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
pub fn restrict_dir_permissions(_path: &Path) {}
