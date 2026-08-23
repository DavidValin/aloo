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
//! `session::check_identity`) is meaningful because a `pq_hybrid` identity
//! is file-loaded and so genuinely the same bytes on every connect. It is
//! the only identity this app has; a peer announcing bytes that do not
//! decode as a keybundle has nothing stable to compare and is left
//! unpinned rather than compared.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{hex_decode, hex_encode};
use crate::proto::KeyMode;
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

/// How much a pin is actually worth.
///
/// The distinction matters because a mismatch means very different things
/// in each case. On a `Tofu` pin it means "this differs from whatever
/// turned up first", which is worth a question. On a `Verified` pin it
/// means "this differs from what a human confirmed out of band", which is
/// worth a much louder one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Trust {
    /// Believed because it was the first thing seen under this nickname -
    /// nobody has checked it against anything.
    #[default]
    Tofu,
    /// Confirmed out of band: a safety phrase compared, or an identity
    /// card imported.
    Verified,
}

impl Trust {
    fn as_str(self) -> &'static str {
        match self {
            Trust::Tofu => "tofu",
            Trust::Verified => "verified",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "tofu" => Some(Trust::Tofu),
            "verified" => Some(Trust::Verified),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    key: Vec<u8>,
    trust: Trust,
    /// Where this nickname's pinned key was last confirmed reachable over
    /// the direct P2P link, and which device (`client::device_id`)
    /// announced it - purely informational, shown alongside a fresh
    /// connection's own address/device id in an impersonation review
    /// popup (`session::check_identity`/`reveal_pending_identity_review`)
    /// so a user judging a key change has more than two fingerprints to
    /// go on. `None` until the first P2P link under this pin goes
    /// `Active` - a pin just written from `Identify` (first sighting, or
    /// an `Accept`) has no address yet.
    last_addr: Option<SocketAddr>,
    last_device_id: Option<String>,
    /// Wall-clock time this pin was last confirmed reachable, stamped
    /// alongside `last_addr`/`last_device_id` by `set_last_seen` - a
    /// contacts list (`client::tui::contacts`) has no other source for
    /// "last seen" that survives a restart, since `presence::Presence` is
    /// derived live from the current session's link state and answers
    /// nothing about a contact who isn't connected right now.
    last_seen_unix: Option<u64>,
    /// Which `KeyMode` this nickname was last pinned under - recorded
    /// alongside every `check_and_pin`/`check_and_pin_with` call
    /// (`session::check_identity`/`AcceptIdentity`) purely for display
    /// (the contacts list's encryption column); pinning itself never reads
    /// it back. `None` for an entry pinned before this field existed, or
    /// one hand-edited without it.
    key_mode: Option<KeyMode>,
}

/// Current wall-clock time as Unix seconds - `0` on a clock that reports
/// before the epoch, which never happens on a real system and isn't worth
/// failing a save over.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn key_mode_as_str(mode: KeyMode) -> &'static str {
    match mode {
        KeyMode::PqHybrid => "pqhybrid",
    }
}

/// Anything but `pqhybrid` is `None` - including the `password`/`none`
/// tags older stores could hold, whose schemes this app no longer has.
fn parse_key_mode(s: &str) -> Option<KeyMode> {
    match s {
        "pqhybrid" => Some(KeyMode::PqHybrid),
        _ => None,
    }
}

/// A nickname -> full-public-key pinning store, backed by a small flat file
/// (`nickname<TAB><hex-encoded DER><TAB><trust><TAB><last addr><TAB><last
/// device id><TAB><last seen unix><TAB><key mode>` per line, every column
/// from `last addr` on optionally empty).
pub struct IdStore {
    path: PathBuf,
    entries: HashMap<String, Entry>,
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
                    // The trust/addr/device-id columns are all optional on
                    // the way in: a store written before one of them
                    // existed is still read successfully (trust defaults
                    // to trust-on-first-use, addr/device-id to "never seen
                    // yet") rather than discarded, since throwing away a
                    // user's pins would lose real security, not just
                    // convenience.
                    let mut fields = line.split('\t');
                    let Some(name) = fields.next() else {
                        continue;
                    };
                    let Some(hex) = fields.next() else {
                        continue;
                    };
                    let trust = fields.next().and_then(Trust::parse).unwrap_or_default();
                    let last_addr = fields
                        .next()
                        .filter(|s| !s.is_empty())
                        .and_then(|s| s.parse().ok());
                    let last_device_id =
                        fields.next().filter(|s| !s.is_empty()).map(str::to_string);
                    let last_seen_unix = fields
                        .next()
                        .filter(|s| !s.is_empty())
                        .and_then(|s| s.parse().ok());
                    let key_mode = fields.next().and_then(parse_key_mode);
                    if is_storable(name)
                        && let Some(der) = hex_decode(hex)
                    {
                        entries.insert(
                            name.to_string(),
                            Entry {
                                key: der,
                                trust,
                                last_addr,
                                last_device_id,
                                last_seen_unix,
                                key_mode,
                            },
                        );
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
        self.check_and_pin_with(nickname, public_key_der, Trust::Tofu)
    }

    /// `check_and_pin`, saying how much the new pin is worth. Re-pinning an
    /// already-`Verified` nickname never quietly demotes it to `Tofu`: only
    /// an explicit `Verified` write, or a fresh nickname, sets the level.
    pub fn check_and_pin_with(
        &mut self,
        nickname: &str,
        public_key_der: &[u8],
        trust: Trust,
    ) -> IdCheck {
        if !is_storable(nickname) {
            return IdCheck::New;
        }
        let previous = self.entries.get(nickname).cloned();
        let trust = match (&previous, trust) {
            (Some(prev), Trust::Tofu) => prev.trust,
            _ => trust,
        };
        // A re-pin (Accept, or a proven-continuous rotation) keeps
        // whatever address/device id was already recorded rather than
        // wiping it back to `None` - that metadata describes the
        // relationship, not any one key, and `set_last_seen` is what
        // actually refreshes it once the new key's own link goes Active.
        let (last_addr, last_device_id, last_seen_unix, key_mode) = previous
            .as_ref()
            .map(|prev| {
                (
                    prev.last_addr,
                    prev.last_device_id.clone(),
                    prev.last_seen_unix,
                    prev.key_mode,
                )
            })
            .unwrap_or_default();
        self.entries.insert(
            nickname.to_string(),
            Entry {
                key: public_key_der.to_vec(),
                trust,
                last_addr,
                last_device_id,
                last_seen_unix,
                key_mode,
            },
        );
        match previous {
            None => IdCheck::New,
            Some(prev) if prev.key == public_key_der => IdCheck::Match,
            Some(prev) => IdCheck::Mismatch {
                previous_public_key_der: prev.key,
            },
        }
    }

    /// Marks what is already pinned for `nickname` as confirmed out of
    /// band. Returns whether there was anything to mark.
    pub fn mark_verified(&mut self, nickname: &str) -> bool {
        match self.entries.get_mut(nickname) {
            Some(entry) => {
                entry.trust = Trust::Verified;
                true
            }
            None => false,
        }
    }

    /// How much `nickname`'s pin is worth, if anything is pinned at all.
    pub fn trust(&self, nickname: &str) -> Option<Trust> {
        self.entries.get(nickname).map(|e| e.trust)
    }

    /// Reads whatever is currently pinned for `nickname`, without pinning
    /// or mutating anything - used by `session::check_identity` to compare
    /// against an announced key without re-pinning it as a side effect,
    /// which `check_and_pin` alone can't do (it always writes).
    pub fn get(&self, nickname: &str) -> Option<&[u8]> {
        self.entries.get(nickname).map(|e| e.key.as_slice())
    }

    /// Records which `KeyMode` `nickname` was last pinned under - see
    /// `Entry::key_mode`'s doc. A no-op if `nickname` isn't pinned at all
    /// (nothing to attach this to yet), same guard `set_last_seen` uses.
    pub fn set_key_mode(&mut self, nickname: &str, key_mode: KeyMode) {
        if let Some(entry) = self.entries.get_mut(nickname) {
            entry.key_mode = Some(key_mode);
        }
    }

    /// Which `KeyMode` `nickname` was last pinned under, if known - `None`
    /// for an unpinned nickname or an entry written before this field
    /// existed.
    pub fn key_mode(&self, nickname: &str) -> Option<KeyMode> {
        self.entries.get(nickname)?.key_mode
    }

    /// Wall-clock time `nickname`'s pin was last confirmed reachable, as
    /// Unix seconds - see `Entry::last_seen_unix`'s doc. `None` if that has
    /// never happened (or `nickname` isn't pinned).
    pub fn last_seen_unix(&self, nickname: &str) -> Option<u64> {
        self.entries.get(nickname)?.last_seen_unix
    }

    /// Every pinned nickname, sorted - the contacts list's row order
    /// (`client::tui::contacts`), and the same order `save` already writes
    /// the file in.
    pub fn nicknames(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        names
    }

    /// Forgets `nickname` entirely - "delete contact" in the contacts
    /// list. Returns whether there was anything to forget. Never touches
    /// anything outside this store: a contact's OTP keychain entry (if
    /// any) is a separate deletion the caller drives itself
    /// (`otp_cli::remove_contact`/`otp_store::forget`), since this store
    /// has no idea whether one exists.
    pub fn remove(&mut self, nickname: &str) -> bool {
        self.entries.remove(nickname).is_some()
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
            let entry = &self.entries[name];
            out.push_str(name);
            out.push('\t');
            out.push_str(&hex_encode(&entry.key));
            out.push('\t');
            out.push_str(entry.trust.as_str());
            out.push('\t');
            if let Some(addr) = entry.last_addr {
                out.push_str(&addr.to_string());
            }
            out.push('\t');
            if let Some(id) = &entry.last_device_id {
                out.push_str(id);
            }
            out.push('\t');
            if let Some(seen) = entry.last_seen_unix {
                out.push_str(&seen.to_string());
            }
            out.push('\t');
            if let Some(mode) = entry.key_mode {
                out.push_str(key_mode_as_str(mode));
            }
            out.push('\n');
        }
        fs::write(&self.path, out)
    }

    /// The address `nickname`'s pinned key was last confirmed reachable at
    /// over the direct P2P link - `None` if that has never happened yet
    /// (or `nickname` isn't pinned at all). See `Entry::last_addr`'s doc.
    pub fn last_addr(&self, nickname: &str) -> Option<SocketAddr> {
        self.entries.get(nickname)?.last_addr
    }

    /// The device id `nickname`'s pinned key last announced alongside
    /// `last_addr` - see that method's doc.
    pub fn last_device_id(&self, nickname: &str) -> Option<&str> {
        self.entries.get(nickname)?.last_device_id.as_deref()
    }

    /// Records where, and which device, `nickname`'s *currently pinned*
    /// key was just confirmed reachable at - called once its P2P link
    /// goes `Active` (`session.rs`'s `LinkStatusChanged` handling) or once
    /// an impersonation review is `Accept`ed. A no-op if `nickname` isn't
    /// pinned (nothing to attach this to yet - it becomes meaningful the
    /// moment `check_and_pin`/`check_and_pin_with` first pins them).
    /// `device_id` is peer-supplied over the wire, exactly like a
    /// nickname is, so it's validated with the same `is_storable` guard
    /// before being written to this flat file; an unstorable value is
    /// silently dropped rather than failing the whole update, leaving
    /// whatever address was passed in still recorded.
    pub fn set_last_seen(&mut self, nickname: &str, addr: SocketAddr, device_id: &str) {
        let Some(entry) = self.entries.get_mut(nickname) else {
            return;
        };
        entry.last_addr = Some(addr);
        if is_storable(device_id) {
            entry.last_device_id = Some(device_id.to_string());
        }
        entry.last_seen_unix = Some(now_unix());
    }
}
