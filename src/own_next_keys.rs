//! Persists *this* client's own `rsa_per_msg` per-peer private keys across
//! reconnects, keyed by nickname - the half of the continuity mechanism
//! that lets a reconnecting `rsa_per_msg` user prove to a peer "it's still
//! me" (`docs/PROTOCOL.md` §12.6). Pairs with `idstore::IdStore`, which
//! holds the *other* half: the verification side, pinning a peer's
//! last-trusted rolling public key.
//!
//! Only the single *current* private key per peer is ever kept - never a
//! history. That's enough: on reconnecting, the client re-asserts this
//! same key (self-signed, bound to the peer's new `UserId`) as its current
//! key for that relationship, and ordinary per-message rotation (§11.3)
//! picks up again from there, unmodified. There is deliberately no
//! provision here for bridging a gap of several *missed* rotations - only
//! for resuming from whatever the key was the moment it was last written.
//!
//! This intentionally persists key material that PROTOCOL.md §11.8 has
//! always described as memory-only, discarded on disconnect - see
//! `docs/PROTOCOL.md` §12.6 for the tradeoff this accepts (a stolen copy
//! of this file lets an attacker impersonate the continuation of specific,
//! already-established peer relationships on the owner's next reconnect,
//! bounded to those relationships alone - past message content stays safe
//! either way, since the superseded keys that actually decrypted it are
//! still never written anywhere).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rsa::RsaPrivateKey;

use crate::crypto;

/// Resolves the store path to prefill the connect popup's `own_next_keys`
/// field with (shown only when `my_key` is `rsa_per_msg`):
/// `~/.aloo/own_next_keys`, always - same rule, and same reasoning, as
/// `idstore::default_path`, including cross-platform `~` resolution (see
/// `crate::platform`). Purely a suggestion - freely editable before
/// connecting.
pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("own_next_keys")
}

/// A nickname -> current-private-key store, backed by a small flat file
/// (`nickname<TAB><hex-encoded PKCS8 DER>` per line) - the mirror image of
/// `idstore::IdStore`'s format, but for private keys only this client ever
/// reads, one per peer relationship it has established `rsa_per_msg`
/// rotation with.
pub struct OwnNextKeys {
    path: PathBuf,
    entries: HashMap<String, RsaPrivateKey>,
}

impl OwnNextKeys {
    /// Starts an empty, in-memory-only store bound to `path` - used as a
    /// fallback when `load` fails for a reason other than the file simply
    /// not existing yet, mirroring `idstore::IdStore::new_empty`.
    pub fn new_empty(path: PathBuf) -> Self {
        Self { path, entries: HashMap::new() }
    }

    /// Loads `path` if it exists; a missing file isn't an error (first run)
    /// and just starts empty. A line that doesn't parse as `name<TAB>hex`,
    /// whose hex half doesn't decode, or whose bytes don't parse as a valid
    /// PKCS8 RSA private key, is skipped rather than failing the whole
    /// load - a hand-edited or partially-corrupted file doesn't block
    /// connecting, same policy as `IdStore::load`.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut entries = HashMap::new();
        match fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines() {
                    if let Some((name, hex)) = line.split_once('\t')
                        && is_storable(name)
                        && let Some(der) = hex_decode(hex)
                        && let Ok(key) = crypto::private_key_from_der(&der)
                    {
                        entries.insert(name.to_string(), key);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self { path: path.to_path_buf(), entries })
    }

    /// The private key currently on file for `nickname`, if this client has
    /// ever rotated with them before (this session or a previous one).
    pub fn get(&self, nickname: &str) -> Option<&RsaPrivateKey> {
        self.entries.get(nickname)
    }

    /// Records `private_key` as the current key for `nickname`, overwriting
    /// whatever was there before - callers still need to call `save` to
    /// persist that. A nickname containing a tab or newline is silently
    /// ignored (never stored), same reasoning as `IdStore::check_and_pin`:
    /// `display_name` is attacker-controlled, and those bytes are this
    /// file's own delimiters.
    pub fn set(&mut self, nickname: &str, private_key: RsaPrivateKey) {
        if !is_storable(nickname) {
            return;
        }
        self.entries.insert(nickname.to_string(), private_key);
    }

    /// Persists the current entries to `path`, creating parent directories
    /// if needed. Entries are written in sorted order so the file diffs
    /// cleanly, each key hex-encoded PKCS8 DER, one line per nickname -
    /// same conventions as `IdStore::save`.
    pub fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut names: Vec<&String> = self.entries.keys().collect();
        names.sort();
        let mut out = String::new();
        for name in names {
            let der = crypto::private_key_to_der(&self.entries[name])
                .map_err(|e| io::Error::other(e.to_string()))?;
            out.push_str(name);
            out.push('\t');
            out.push_str(&hex_encode(&der));
            out.push('\n');
        }
        fs::write(&self.path, out)
    }
}

/// Whether `s` is safe to use as the nickname half of a `name<TAB>hex` line
/// - no tab (field delimiter), no newline (record delimiter).
fn is_storable(s: &str) -> bool {
    !s.contains('\t') && !s.contains('\n') && !s.contains('\r')
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push((hi as u8) << 4 | lo as u8);
    }
    Some(out)
}
