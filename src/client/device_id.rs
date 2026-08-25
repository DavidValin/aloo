//! A persistent local device identifier (`~/.aloo/d_id`), generated once
//! and reused for the machine's whole lifetime.
//!
//! Since this app's own server never holds decryption keys, a client has
//! no way to tell "the same person reconnecting from a second machine"
//! apart from "an unrelated key change" except by asking the two devices
//! involved - which is what a self-reported device id is for. It's what
//! turns `idstore::IdStore`'s pinning from one key per nickname into one
//! key per `(nickname, device_id)` (the device-pinning plan): an
//! impersonation review still compares raw key bytes, exactly as before,
//! but now scoped to the specific device announcing them, so a genuinely
//! new device is additive (§2's algorithm) rather than colliding with
//! whatever another of the nickname's devices already has pinned. It also
//! feeds `crypto::otp::contact_name_for`/`contact_name_for_mail`'s
//! device-qualified OTP keychain naming (§4), so two of a nickname's
//! devices - or two of *this* machine's own, talking to the same peer -
//! never share one pad.
//!
//! It is not a security credential: it's self-reported over the P2P link
//! by whoever holds it, exactly like a nickname is, so nothing stops a
//! peer from lying about theirs. A self-reported value can only ever
//! *narrow* which already-pinned key is compared against or which
//! keychain slot is used - it can never grant trust or bypass a byte
//! comparison, which is what still does the actual authenticating. See
//! `accept_announced` for the one value a peer must never be allowed to
//! claim (`idstore::IdStore`'s reserved "unbound" sentinel), and
//! `idstore::IdStore::set_last_seen`'s `is_storable` guard against a
//! hostile value otherwise corrupting the local store.

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

/// Validates a peer's decrypted `DeviceIdAnnounce` plaintext
/// (`session::on_device_id_announce`) before it's ever cached or acted on:
/// `None` for anything that isn't valid UTF-8, or that decodes to an
/// **empty** string.
///
/// The empty-string rejection is the one that matters here, not the
/// UTF-8 check (which almost anything satisfies). An empty string is the
/// reserved sentinel `idstore::IdStore` uses for "no device known yet"
/// (device-pinning plan §1's "unbound entries") - accepting one from a
/// peer, deliberate or not, would let their connection be silently
/// mistaken for that sentinel and adopt whatever unbound entry the
/// nickname already happens to have pinned, rather than genuinely
/// resolving to "device unknown" the way a missing announce does. This
/// costs the peer nothing real either way - a device_id only ever
/// narrows which stored key is compared or used, never authenticates one
/// - but the ambiguity itself is worth refusing outright rather than
/// reasoning about case by case.
pub fn accept_announced(plaintext: &[u8]) -> Option<String> {
    let id = String::from_utf8(plaintext.to_vec()).ok()?;
    if id.is_empty() {
        return None;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_normal_device_id_is_accepted() {
        assert_eq!(
            accept_announced(b"3f9a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60"),
            Some("3f9a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60".to_string())
        );
    }

    #[test]
    fn an_empty_announced_device_id_is_refused() {
        assert_eq!(
            accept_announced(b""),
            None,
            "empty is the unbound sentinel - a peer must never be able to claim it"
        );
    }

    #[test]
    fn non_utf8_bytes_are_refused() {
        assert_eq!(accept_announced(&[0xff, 0xfe, 0xfd]), None);
    }
}
