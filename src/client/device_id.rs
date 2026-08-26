//! A persistent local device identifier, generated once per nickname this
//! machine has ever used and reused for that nickname's whole lifetime
//! (`~/.aloo/d_id`).
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
//! It is scoped per nickname, not per machine: a machine used to connect
//! as several different nicknames gets a distinct id for each one, stored
//! side by side in the same file (one `nickname\tdevice_id` line apiece).
//! This keeps a device_id from linking two otherwise-unrelated nicknames
//! run from the same install together.
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

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{hex_encode, random_bytes};
use crate::validation::is_storable;

/// How many random bytes back a freshly generated id - hex-encoded, this
/// yields exactly 8 characters.
const DEVICE_ID_BYTES: usize = 4;

/// How many candidates `generate_unique` tries before giving up and
/// returning its last candidate anyway. At `DEVICE_ID_BYTES` this is
/// astronomically more attempts than any realistic number of nicknames
/// one machine has ever used could need; it exists only so the loop has a
/// provable end rather than because it's expected to matter.
const MAX_GENERATE_ATTEMPTS: usize = 10_000;

/// `~/.aloo/d_id` (`crate::platform::aloo_dir`).
pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("d_id")
}

/// Reads `path` for `nickname`'s id, generating and storing a fresh one
/// the first time this nickname is seen (a missing file, or a file with
/// no entry for `nickname` yet, not an error) - every later call for the
/// same `nickname`, on this or a future run, reuses exactly what's
/// already there rather than regenerating, which is the entire point: a
/// stable identifier for this device across sessions. Freshly generated
/// ids are checked against every id already on file (any nickname) so
/// this one file never assigns the same id twice.
pub fn load_or_create(path: &Path, nickname: &str) -> io::Result<String> {
    let mut entries = read_entries(path)?;
    if let Some(id) = entries.iter().find(|(n, _)| n == nickname).map(|(_, id)| id.clone()) {
        return Ok(id);
    }
    let existing: HashSet<&str> = entries.iter().map(|(_, id)| id.as_str()).collect();
    let id = generate_unique(&existing);
    entries.push((nickname.to_string(), id.clone()));
    write_entries(path, &entries)?;
    Ok(id)
}

/// Parses whatever is currently on disk into `(nickname, device_id)`
/// pairs, tolerating a missing file (empty result) and skipping any line
/// that doesn't parse as exactly one tab-separated pair - including a
/// pre-existing single bare id from before device ids were scoped per
/// nickname, which has no nickname field to key it by and so cannot be
/// carried forward; a fresh id is generated per nickname instead.
fn read_entries(path: &Path) -> io::Result<Vec<(String, String)>> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(contents
        .lines()
        .filter_map(|line| {
            let (nickname, id) = line.split_once('\t')?;
            if nickname.is_empty() || id.is_empty() {
                return None;
            }
            Some((nickname.to_string(), id.to_string()))
        })
        .collect())
}

fn write_entries(path: &Path, entries: &[(String, String)]) -> io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut contents = String::new();
    for (nickname, id) in entries {
        contents.push_str(nickname);
        contents.push('\t');
        contents.push_str(id);
        contents.push('\n');
    }
    fs::write(path, contents)
}

/// A fresh 8-character lowercase-hex id - `crypto::random_bytes`
/// (`OsRng`-backed) hex-encoded, the same encoding/RNG convention
/// `idstore`'s keys and `p2p::random_token` already use - that does not
/// collide with anything in `existing`.
fn generate_unique(existing: &HashSet<&str>) -> String {
    let mut candidate = generate();
    for _ in 1..MAX_GENERATE_ATTEMPTS {
        if !existing.contains(candidate.as_str()) {
            break;
        }
        candidate = generate();
    }
    candidate
}

fn generate() -> String {
    hex_encode(&random_bytes(DEVICE_ID_BYTES))
}

/// Test-only seam onto the private collision-avoidance loop
/// (`test/device_id_test.rs`) - real callers only ever reach it through
/// `load_or_create`.
pub fn generate_unique_for_test(existing: &HashSet<String>) -> String {
    generate_unique(&existing.iter().map(String::as_str).collect())
}

/// Validates a peer's decrypted `DeviceIdAnnounce` plaintext
/// (`session::on_device_id_announce`) before it's ever cached or acted on:
/// `None` for anything that isn't valid UTF-8, that decodes to an
/// **empty** string, or that isn't `is_storable` (a tab/newline would
/// otherwise corrupt this file's own `nickname\tdevice_id` line format
/// and `idstore`'s equivalent).
///
/// The empty-string rejection is the one that matters most, not the
/// UTF-8/storability checks (which almost anything satisfies). An empty
/// string is the reserved sentinel `idstore::IdStore` uses for "no device
/// known yet" (device-pinning plan §1's "unbound entries") - accepting
/// one from a peer, deliberate or not, would let their connection be
/// silently mistaken for that sentinel and adopt whatever unbound entry
/// the nickname already happens to have pinned, rather than genuinely
/// resolving to "device unknown" the way a missing announce does. This
/// costs the peer nothing real either way - a device_id only ever narrows
/// which stored key is compared or used, never authenticates one - but
/// the ambiguity itself is worth refusing outright rather than reasoning
/// about case by case.
pub fn accept_announced(plaintext: &[u8]) -> Option<String> {
    let id = String::from_utf8(plaintext.to_vec()).ok()?;
    if id.is_empty() || !is_storable(&id) {
        return None;
    }
    Some(id)
}

