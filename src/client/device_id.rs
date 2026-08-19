//! A persistent local device identifier (`~/.aloo/d_id`), generated once
//! and reused for the machine's whole lifetime. It exists purely to help a
//! human tell devices apart during an impersonation review (§12.7): a key
//! mismatch says a nickname's key changed, but says nothing about whether
//! this is the same physical device reconnecting under a new key or a
//! different one entirely. A device id sent alongside the new connection
//! (`p2p_proto::PunchDatagram::Ping`/`Pong`, `client::p2p`) gives the
//! review popup something else to compare against the value pinned
//! (`idstore::IdStore::last_device_id`) the last time this nickname's key
//! was confirmed reachable - matching ids are a point in favor of "same
//! device, key rotated on purpose"; a changed one is a point against.
//!
//! It is not a security credential: it's self-reported over the P2P link
//! by whoever holds it, exactly like a nickname is, so nothing stops a
//! peer from lying about theirs (see `idstore::IdStore::set_last_seen`'s
//! `is_storable` guard against a hostile value corrupting the local
//! store). Its value is purely informational.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{hex_encode, random_bytes};

/// How many random bytes back the id - hex-encoded, this yields exactly
/// 50 characters.
const DEVICE_ID_BYTES: usize = 25;

/// `~/.aloo/d_id` (`crate::platform::aloo_dir`).
pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("d_id")
}

/// Reads `path`, generating and writing a fresh id the first time (a
/// missing file, not an error) - every later call, on this or a future
/// run, reuses exactly what's already there rather than regenerating,
/// which is the entire point: a stable identifier for this device across
/// sessions. Whatever is on disk is trusted as-is (trimmed of surrounding
/// whitespace) rather than re-validated against the 50-character/hex
/// shape a freshly generated one has - a hand-edited or foreign value is
/// still a valid, stable string to identify this device by.
pub fn load_or_create(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let id = contents.trim();
            if !id.is_empty() {
                return Ok(id.to_string());
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let id = generate();
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &id)?;
    Ok(id)
}

/// A fresh 50-character lowercase-hex id - `crypto::random_bytes`
/// (`OsRng`-backed) hex-encoded, the same encoding/RNG convention
/// `idstore`'s keys and `p2p::random_token` already use.
fn generate() -> String {
    hex_encode(&random_bytes(DEVICE_ID_BYTES))
}
