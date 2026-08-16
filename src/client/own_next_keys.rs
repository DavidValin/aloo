//! Persists *this* client's own `rsa_per_msg` per-peer private keys across
//! reconnects, keyed by nickname - the assertion half of the §12.6
//! continuity mechanism ("it's still me"); `idstore::IdStore` holds the
//! verification half. Only the single *current* key per peer is kept: on
//! reconnect the client re-asserts it (self-signed, bound to the peer's
//! new `UserId`) and ordinary rotation (§11.3) resumes from there -
//! deliberately no provision for bridging missed rotations.
//!
//! This intentionally persists key material §11.8 otherwise treats as
//! memory-only; §12.6 documents the accepted tradeoff (a stolen file
//! allows impersonating the *continuation* of specific established
//! relationships on the next reconnect - past message content stays safe,
//! since the superseded keys that decrypted it are never written).

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rsa::RsaPrivateKey;

use crate::crypto::{self, hex_decode, hex_encode};
use crate::validation::is_storable;

/// `~/.aloo/own_next_keys` - prefill suggestion for the connect popup's
/// `own_next_keys` field (shown only when `my_key` is `rsa_per_msg`);
/// same rule and reasoning as `idstore::default_path`.
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
        Self {
            path,
            entries: HashMap::new(),
        }
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
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// The private key currently on file for `nickname`, if this client has
    /// ever rotated with them before (this session or a previous one).
    pub fn get(&self, nickname: &str) -> Option<&RsaPrivateKey> {
        self.entries.get(nickname)
    }

    /// Records `private_key` as the current key for `nickname` (callers
    /// persist via `save`). A nickname containing a tab or newline is
    /// silently ignored - same injection reasoning as
    /// `IdStore::check_and_pin`.
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
