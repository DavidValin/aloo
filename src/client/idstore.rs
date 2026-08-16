//! A local, client-side store pinning a peer's full public key to their
//! nickname across sessions - the same role `known_hosts` plays for SSH.
//! Nicknames are trust-on-first-use and freed on disconnect
//! (`docs/PROTOCOL.md` §5.4/§11.2), so nothing on the wire distinguishes
//! "the same person reconnecting" from "someone else who took a familiar
//! nickname"; this closes that gap locally. A changed key is flagged
//! loudly, never silently blocked - there is no "type yes to accept" flow,
//! and a false positive must never lock out a legitimate reconnect.
//!
//! The *full* DER key is stored rather than a fingerprint: a hash detects
//! a change just as well (and is still what the warning displays, via
//! `crypto::fingerprint_der`), but only the real bytes let a user verify a
//! pinned identity against a key file received out-of-band - and keys are
//! only a few hundred bytes.
//!
//! Byte comparison (`check_and_pin` returning `Mismatch`, driven by
//! `session::check_identity`) is only meaningful for `KeyMode`s whose key
//! is stable across connections (`Rsa`/`PqHybrid`: file-loaded;
//! `Password`: deterministically re-derived - see
//! `keymode_policy::uses_byte_comparison_pinning`). `None`/`PerMessage`
//! keys (including `PerMessage`'s bootstrap key) are freshly generated on
//! every connect, so comparing them would raise a false impersonation
//! warning on every reconnect - training users to dismiss the warning that
//! matters. `PerMessage` peers still get entries, refreshed by
//! `session::handle_key_rotated` and read back as the §12.6 resume
//! verification anchor: for them a byte difference is expected and
//! ignored - the alarm is a signature verifying against neither anchor.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::crypto::{hex_decode, hex_encode};
use crate::validation::is_storable;

/// `~/.aloo/ids_store` (`crate::platform::aloo_dir`) - only ever a
/// prefill suggestion for the connect popup; the session uses whatever
/// ends up in `ConnectRequest::id_store_path`, freely editable. The app
/// never writes a loose file in the current working directory.
pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("ids_store")
}

/// The result of checking one peer's announced identity against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdCheck {
    /// This nickname has never been pinned before; it has been now.
    New,
    /// This nickname was already pinned to exactly this public key.
    Match,
    /// This nickname was pinned to a *different* public key last time - the
    /// signal this module exists to raise. The nickname is re-pinned to the
    /// new key regardless (no "reject and keep the old one" flow), so a
    /// caller must act on this immediately; the previous key isn't
    /// recoverable from the store afterward.
    Mismatch { previous_public_key_der: Vec<u8> },
}

/// A nickname -> full-public-key pinning store, backed by a small flat file
/// (`nickname<TAB><hex-encoded DER>` per line).
pub struct IdStore {
    path: PathBuf,
    entries: HashMap<String, Vec<u8>>,
}

impl IdStore {
    /// Starts an empty, in-memory-only store bound to `path` - used as a
    /// fallback when `load` fails for a reason other than the file simply
    /// not existing yet (e.g. a permissions error), so a caller can still
    /// run the session with pinning checks disabled for it rather than
    /// refusing to connect at all.
    pub fn new_empty(path: PathBuf) -> Self {
        Self {
            path,
            entries: HashMap::new(),
        }
    }

    /// Loads `path` if it exists; a missing file isn't an error (first run
    /// against this store) and just starts empty. Lines that don't parse as
    /// `name<TAB>hex` (or whose hex half doesn't decode) are skipped rather
    /// than failing the whole load, so a hand-edited or partially-corrupted
    /// file doesn't block connecting.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut entries = HashMap::new();
        match fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines() {
                    if let Some((name, hex)) = line.split_once('\t')
                        && is_storable(name)
                        && let Some(der) = hex_decode(hex)
                    {
                        entries.insert(name.to_string(), der);
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

    /// Checks `nickname`'s announced `public_key_der` against what's pinned
    /// for it, re-pinning it in memory as a side effect (callers persist
    /// via `save`). A nickname containing a tab or newline is never pinned
    /// or looked up (always returns `New`): `display_name` is
    /// attacker-controlled and those bytes are the on-disk format's
    /// delimiters, so accepting one would let a remote peer inject records
    /// into this local file. The key itself is stored hex-encoded, which
    /// can't collide with either delimiter.
    pub fn check_and_pin(&mut self, nickname: &str, public_key_der: &[u8]) -> IdCheck {
        if !is_storable(nickname) {
            return IdCheck::New;
        }
        match self
            .entries
            .insert(nickname.to_string(), public_key_der.to_vec())
        {
            None => IdCheck::New,
            Some(previous) if previous == public_key_der => IdCheck::Match,
            Some(previous) => IdCheck::Mismatch {
                previous_public_key_der: previous,
            },
        }
    }

    /// Reads whatever is currently pinned for `nickname`, without pinning
    /// or mutating anything - used by the `rsa_per_msg` continuity/resume
    /// path (`docs/PROTOCOL.md` §12.6) to fetch a candidate verification
    /// anchor *before* deciding whether an incoming rotation is legitimate,
    /// which `check_and_pin` alone can't do (it always writes).
    pub fn get(&self, nickname: &str) -> Option<&[u8]> {
        self.entries.get(nickname).map(|v| v.as_slice())
    }

    /// Persists the current entries to `path`, creating parent directories
    /// if needed (e.g. `~/.aloo/` on first run). Entries are written in
    /// sorted order so the file diffs cleanly if the user inspects it, each
    /// key hex-encoded (rather than raw/base64) to match the plain-text,
    /// no-extra-dependency style already used elsewhere in this app
    /// (`crypto::fingerprint`'s own hex encoding).
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
            out.push_str(name);
            out.push('\t');
            out.push_str(&hex_encode(&self.entries[name]));
            out.push('\n');
        }
        fs::write(&self.path, out)
    }
}
