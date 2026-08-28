//! Crash-safe staging for one-time-pad key material that is still being
//! produced or still arriving.
//!
//! # The invariant
//!
//! `~/.aloo/otp/.tmp/` holds **only work in progress**. Key material
//! becomes real by being *renamed out* of it - one atomic `rename`, only
//! once every byte is present and checked. Nothing ever installs a pad
//! into `otp`'s keychain while it is still inside `.tmp/`.
//!
//! Two properties fall straight out of that:
//!
//! * **A half-transmitted key can never be used.** The only path from
//!   `.tmp/` to a usable contact runs through `promote`, and `promote` is
//!   only reached once the transfer reports itself complete. There is no
//!   other reader.
//! * **Anything found in `.tmp/` is garbage, unconditionally.** It does not
//!   matter *what* interrupted it - a superseded invitation, a dropped
//!   link, `kill -9`, a power cut mid-generation. If it is still in
//!   `.tmp/`, it never completed, so `sweep` deletes it at startup with no
//!   manifest to consult and no truth table to get wrong.
//!
//! That second property is what makes the cleanup survive a crash without
//! any bookkeeping of its own: the *location* is the record. Contrast the
//! `otp` binary's own crash recovery (README.md "Recovering from a crash"),
//! which has to reconcile a pending artifact against key file and metadata
//! precisely because its artifacts live alongside live state; here they
//! never do.
//!
//! # Erasing
//!
//! Pad bytes are the literal one-time secret, so staging files are
//! overwritten before being unlinked rather than just removed. The
//! overwrite streams a fixed-size zero buffer (`ERASE_CHUNK_BYTES`) rather
//! than building one the size of the file: a pad may be up to 1TB
//! (`crypto::otp::OTP_SIZE_MB_MAX`), and allocating that to erase it would
//! abort the process outright.

use std::path::{Path, PathBuf};

use crate::client::otp_cli::OtpCliConfig;

/// `~/.aloo/otp/.tmp/` - the one directory in-progress key material lives
/// in. A sibling of `otp`'s own `.keychain/` (both under
/// `OtpCliConfig::working_dir`), never inside it: `otp` treats every file
/// in `.keychain/` as its own to reconcile, and half-written pad bytes are
/// not something it should ever be asked to reason about.
pub fn tmp_root(cfg: &OtpCliConfig) -> PathBuf {
    cfg.working_dir.join(".tmp")
}

/// Removes every leftover in `.tmp/` - called once at session start
/// (`client::session`) and safe to call at any other time.
///
/// Unconditional by design: see the module doc. Anything here is
/// incomplete, whatever left it behind, so there is nothing to classify.
/// Best-effort throughout - a staging file that cannot be removed (a
/// permissions problem, a filesystem hiccup) is skipped rather than
/// failing the session start, since the invariant that protects the
/// *keychain* does not depend on the cleanup having succeeded: an
/// unswept leftover is still never read by anything.
pub fn sweep(cfg: &OtpCliConfig) {
    let root = tmp_root(cfg);
    let Ok(entries) = std::fs::read_dir(&root) else {
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
}

/// Removes every `<contact>_pending` directory whose contact is not still
/// owed a pad, at startup.
///
/// `sweep` above clears `.tmp/`, which only ever holds work in progress. A
/// `_pending` directory is different: it holds a pad this side generated
/// and must keep until the peer accepts it, so it deliberately survives
/// `sweep`. What nothing did until now was remove one whose handshake was
/// abandoned - and each is *four times* the per-key size, so a few
/// declined or interrupted `/otp` attempts silently consume tens of
/// gigabytes and never give it back. Found the hard way, on a disk with
/// 292KB left and 7.9GB of it stranded in one such directory.
///
/// `still_owed` answers "is this contact still mid-handshake" - in
/// practice `OtpStore::pending_setups`, the same record the retry pass
/// uses. Anything it does not name has no path back to being installed,
/// so keeping it only costs space.
pub fn sweep_abandoned_setups(cfg: &OtpCliConfig, still_owed: &[String]) -> u64 {
    let Ok(entries) = std::fs::read_dir(&cfg.working_dir) else {
        return 0;
    };
    let mut reclaimed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(contact) = name.strip_suffix("_pending") else {
            continue;
        };
        if still_owed.iter().any(|c| c == contact) {
            continue;
        }
        reclaimed += dir_bytes(&path);
        secure_remove_dir(&path);
    }
    reclaimed
}

/// Total size of the files directly inside `dir` - for reporting how much
/// an abandoned setup gave back, nothing more.
fn dir_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// A fresh, collision-free directory under `.tmp/` for one in-progress
/// piece of work. `label` only makes the directory recognisable while
/// debugging; uniqueness comes from the pid and a nanosecond timestamp, so
/// two attempts for the same contact - a superseded invitation and the one
/// superseding it - never share a directory and cannot corrupt each other.
pub fn new_dir(cfg: &OtpCliConfig, label: &str) -> std::io::Result<PathBuf> {
    let root = tmp_root(cfg);
    std::fs::create_dir_all(&root)?;
    restrict_dir_permissions(&root);
    let unique = format!(
        "{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let dir = root.join(unique);
    std::fs::create_dir_all(&dir)?;
    restrict_dir_permissions(&dir);
    Ok(dir)
}

/// Moves completed key material out of `.tmp/` and into its real place -
/// the one and only way anything leaves staging.
///
/// A plain `rename`, so the destination either does not exist yet or
/// appears complete in one step; there is no window where a reader could
/// observe half of it. Both paths are under `OtpCliConfig::working_dir`
/// and therefore on one filesystem, which is what lets `rename` be atomic
/// at all. Any pre-existing destination is securely removed first rather
/// than renamed over, so its pad bytes are erased rather than merely
/// unlinked.
pub fn promote(from: &Path, to: &Path) -> std::io::Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if to.exists() {
        if to.is_dir() {
            secure_remove_dir(to);
        } else {
            secure_remove_file(to);
        }
    }
    std::fs::rename(from, to)
}

pub use crate::secure_fs::{secure_remove_dir, secure_remove_file};

use crate::secure_fs::restrict_dir_permissions;
