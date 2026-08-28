//! A local, client-side store pinning a peer's public key to their
//! `(nickname, device_id)` across sessions - the same role `known_hosts`
//! plays for SSH, extended with a device dimension so a user who owns
//! several machines can hold one nickname's key per device rather than
//! being forced into one slot for all of them. Nicknames are
//! trust-on-first-use and freed on disconnect (`docs/PROTOCOL.md`
//! §5.4/§11.2), so nothing on the wire distinguishes "the same person
//! reconnecting" from "someone else who took a familiar nickname"; this
//! closes that gap locally. A changed key is flagged loudly, never
//! silently blocked - there is no "type yes to accept" flow, and a false
//! positive must never lock out a legitimate reconnect.
//!
//! **Additive, never replacing**: pinning a new device's key for a
//! nickname never touches another device's already-pinned key for that
//! same nickname - see `client::session::check_identity` for the
//! algorithm that decides when a device is "new" versus a genuine key
//! change on a device already known. This module only holds the
//! low-level storage primitives that algorithm is built from; it makes no
//! decisions of its own about whether a key change is suspicious.
//!
//! **Scoped by key kind**: a nickname's `pq_hybrid`-decodable pin and its
//! `Direct`-framed (raw pad-only) pin are independent slots that are never
//! compared against each other - meeting the same person once serverless
//! and later through a server must never look like an unexplained key
//! change. `Entry::key_mode` is what distinguishes them; every accessor
//! and mutator below that reasons about "does this nickname already have
//! a device" is implicitly scoped to entries sharing the same `key_mode`
//! as the one being considered, left to callers to filter via
//! `devices_of` since this module has no opinion of its own about which
//! kind a caller cares about.
//!
//! **Unbound entries**: a key can be pinned for a nickname before its
//! device is known at all - a manually installed OTP key
//! (`client::contacts::install_otp_key`) or an imported identity card
//! (`client::contacts::pin_identity_card`), neither of which have a live
//! connection to learn a device_id from. Represented as `device_id
//! == ""`, a reserved sentinel a real device_id (8 hex characters, unique
//! per nickname - `client::device_id::load_or_create`) can never collide
//! with.
//! At most one unbound entry exists per `(nickname, key_mode)` at a time;
//! `claim_unbound` is what resolves it into a bound one, the first time a
//! live connection's key matches it exactly.
//!
//! The *full* DER key is stored rather than a fingerprint: a hash detects
//! a change just as well (and is still what the warning displays, via
//! `crypto::fingerprint_der`), but only the real bytes let a user verify a
//! pinned identity against a key file received out-of-band - and keys are
//! only a few hundred bytes.
//!
//! Byte comparison is meaningful because a `pq_hybrid` identity is
//! file-loaded and so genuinely the same bytes on every connect. It is
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

/// The result of comparing an announced key against a set of already
/// -pinned candidate keys - `compare_key`/`IdStore::check_key`'s result,
/// and the device-blind half of `session::check_identity`'s pinning
/// decision (see that function's doc for why the device-precise half has
/// to wait). Not itself a decision about whether to gate or pin anything;
/// see the callers that act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCheck {
    /// No candidates at all - nothing pinned yet for this nickname (of
    /// whichever key kind the caller cared about).
    New,
    /// Matches some candidate exactly.
    Match,
    /// Matches nothing. `previous_public_key_der` is the empty vec unless
    /// the caller supplies one worth showing (`IdStore::check_key`
    /// doesn't try to guess which candidate is most representative;
    /// `session::check_identity` fills this in itself from `IdStore::get`
    /// for display purposes).
    Mismatch { previous_public_key_der: Vec<u8> },
}

/// The comparison `KeyCheck` describes, given a plain iterator of
/// candidate keys rather than an `IdStore` lookup - what lets it be
/// exercised directly, with no `IdStore` state to stand up, and what lets
/// `session::check_identity` run it against a `key_mode`-filtered subset
/// of a nickname's devices instead of every one of them (§1's "scoped by
/// key kind").
pub fn compare_key<'a>(candidates: impl Iterator<Item = &'a [u8]>, key: &[u8]) -> KeyCheck {
    let mut any = false;
    for candidate in candidates {
        any = true;
        if candidate == key {
            return KeyCheck::Match;
        }
    }
    if any {
        KeyCheck::Mismatch {
            previous_public_key_der: Vec::new(),
        }
    } else {
        KeyCheck::New
    }
}

/// One `(nickname, device_id)` pin's full record - returned by
/// `IdStore::devices_of` for every caller that needs to reason about more
/// than one of a nickname's devices at once (the identity-check
/// algorithm, the Contacts modal's per-device rows).
#[derive(Debug, Clone)]
pub struct DeviceEntry {
    /// `UNBOUND` (empty) for a pin with no known device yet.
    pub device_id: String,
    pub key: Vec<u8>,
    pub trust: Trust,
    /// Where this device's key was last confirmed reachable over the
    /// direct P2P link - purely informational, shown alongside a fresh
    /// connection's own address in an impersonation review popup
    /// (`session::reveal_pending_identity_review`). `None` until this
    /// device's link first goes `Active`.
    pub last_addr: Option<SocketAddr>,
    /// Wall-clock time this device's key was last confirmed reachable,
    /// stamped alongside `last_addr` by `set_last_seen` - also what a
    /// nickname's devices are ranked by when a caller needs just one
    /// (`IdStore::get`'s "most-recently-seen, or most recently pinned"
    /// default).
    pub last_seen_unix: Option<u64>,
    /// Which `KeyMode` this device was pinned under - `None` for a
    /// `Direct`-framed (raw pad-only) pin, or an entry written before
    /// this field existed. Purely for display (the Contacts list's
    /// encryption column) and for the `key_mode`-scoping the module doc
    /// describes; pinning itself never reads it back to decide anything.
    pub key_mode: Option<KeyMode>,
    /// The identity-card file this pin was manually imported from
    /// (`client::contacts::pin_identity_card_file`) - purely
    /// informational, for the key-details popup's "path in disk" line.
    /// `None` for every pin that arrived the ordinary way, over the wire.
    pub pinned_from: Option<PathBuf>,
}

impl DeviceEntry {
    fn is_unbound(&self) -> bool {
        self.device_id.is_empty()
    }
}

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

/// A `nickname -> devices` pinning store, backed by a small flat file:
/// one line per pinned device, `nickname<TAB>device_id<TAB>
/// <hex-encoded DER><TAB>trust<TAB>last addr<TAB>last seen unix<TAB>
/// key mode<TAB>pinned from`, `device_id` empty for an unbound entry,
/// every column from `trust` on optionally empty.
pub struct IdStore {
    path: PathBuf,
    entries: HashMap<String, Vec<DeviceEntry>>,
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

    /// Where this store persists to - exposed for a test that needs to
    /// simulate a genuine process restart (drop this value, `load` a
    /// fresh one from the same file) rather than merely continuing in
    /// memory, the same reason `OtpStore::path` exists.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads `path` if it exists; a missing file isn't an error (first run
    /// against this store) and just starts empty. Lines that don't parse
    /// are skipped rather than failing the whole load, so a hand-edited or
    /// partially-corrupted file doesn't block connecting.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut entries: HashMap<String, Vec<DeviceEntry>> = HashMap::new();
        if let Some(contents) = crate::platform::read_to_string_optional(path)? {
            for line in contents.lines() {
                if let Some((name, entry)) = parse_line(line) {
                    entries.entry(name).or_default().push(entry);
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Every device pinned for `nickname`, in no particular guaranteed
    /// order beyond "most recently pinned last" - the identity-check
    /// algorithm (`session::check_identity`) and the Contacts modal's
    /// per-device rows are what actually need more than one at a time.
    pub fn devices_of(&self, nickname: &str) -> impl Iterator<Item = &DeviceEntry> {
        self.entries.get(nickname).into_iter().flatten()
    }

    /// The key pinned for `(nickname, device_id)` exactly, if any. An
    /// entry with an empty key is a bare contact placeholder
    /// (`pin_bare_contact` - Add Contact with no identity card, "the
    /// contact is created with no keys") rather than a real pin, so it is
    /// treated the same as no entry at all here.
    pub fn get_for_device(&self, nickname: &str, device_id: &str) -> Option<&[u8]> {
        self.entries
            .get(nickname)?
            .iter()
            .find(|e| e.device_id == device_id && !e.key.is_empty())
            .map(|e| e.key.as_slice())
    }

    /// A single "the" key for `nickname`, for the many call sites that
    /// have no live device_id to disambiguate with (serverless
    /// punch-by-nickname, the safety-phrase display, OTP mail's
    /// compose-time recipient check): the most-recently-seen device's
    /// key, or - if none of this nickname's devices has ever been seen
    /// reachable - whichever was pinned most recently. `None` if
    /// `nickname` has no devices pinned at all.
    pub fn get(&self, nickname: &str) -> Option<&[u8]> {
        self.most_recent_device(nickname).map(|e| e.key.as_slice())
    }

    /// `get`'s own device_id, for a caller that needs to name an OTP
    /// contact for `nickname` with no live connection (and so no specific
    /// device_id) in hand - `client::contacts::otp_contact_name_for`, the
    /// `/contacts` modal's own lookup, which is why this exists alongside
    /// `get` rather than only being derivable by a caller that already
    /// has a `DeviceEntry` in hand.
    pub fn most_recent_device_id(&self, nickname: &str) -> Option<&str> {
        self.most_recent_device(nickname)
            .map(|e| e.device_id.as_str())
    }

    fn most_recent_device(&self, nickname: &str) -> Option<&DeviceEntry> {
        let devices = self.entries.get(nickname)?;
        devices
            .iter()
            .filter(|e| !e.key.is_empty())
            .max_by_key(|e| (e.last_seen_unix.is_some(), e.last_seen_unix.unwrap_or(0)))
    }

    /// The device-blind half of `session::check_identity`'s pinning
    /// decision (see that function's doc for why device_id can't be
    /// known yet at this point): compares `key` against every one of
    /// `nickname`'s currently pinned devices, with no key-kind filtering
    /// of its own - a caller that needs the `key_mode`-scoping the module
    /// doc describes (§1) filters `devices_of` itself first and calls
    /// `compare_key` directly against that narrower set instead. On a
    /// `Mismatch`, fills in `previous_public_key_der` from `get`'s
    /// "most recently seen, or most recently pinned" default - purely for
    /// display, the same coarse approximation `session::check_identity`
    /// would otherwise compute by hand.
    pub fn check_key(&self, nickname: &str, key: &[u8]) -> KeyCheck {
        match compare_key(
            self.devices_of(nickname).filter(|d| !d.key.is_empty()).map(|d| d.key.as_slice()),
            key,
        ) {
            KeyCheck::Mismatch { .. } => KeyCheck::Mismatch {
                previous_public_key_der: self.get(nickname).unwrap_or_default().to_vec(),
            },
            other => other,
        }
    }

    /// Pins `key` under a brand-new `(nickname, device_id)` entry -
    /// first-ever sighting of this device (`device_id` non-empty), or a
    /// deliberately unbound pin with no device known yet (`device_id ==
    /// ""`, manual install or card import). Never overwrites an existing
    /// entry for the same pair; callers that need to replace an existing
    /// device's key use `replace_device_key`, and callers that need to
    /// resolve an unbound entry into a bound one use `claim_unbound` -
    /// keeping those three operations distinct is what makes "additive,
    /// never replacing" (the module doc) a property of the API itself
    /// rather than something every caller has to get right by hand.
    pub fn pin_new_device(&mut self, nickname: &str, device_id: &str, key: &[u8], trust: Trust) {
        self.pin_new_device_with_key_mode(nickname, device_id, key, trust, None);
    }

    /// `pin_new_device`, additionally stamping `key_mode` on the exact
    /// entry just created - never through a separate `set_key_mode` call
    /// afterward, which would re-resolve by `device_id` alone and could
    /// land on a *different* entry sharing that same device_id (in
    /// particular the empty "unbound" sentinel, which every unbound entry
    /// shares regardless of `key_mode` - `check_identity`'s device-blind
    /// first-sighting pin is exactly this case: a nickname can already
    /// have an unbound `Direct` entry from an unrelated relationship, and
    /// blindly re-resolving by `device_id == ""` after pushing this one
    /// risks stamping `pq_hybrid` onto that unrelated entry instead).
    pub fn pin_new_device_with_key_mode(
        &mut self,
        nickname: &str,
        device_id: &str,
        key: &[u8],
        trust: Trust,
        key_mode: Option<KeyMode>,
    ) {
        if !is_storable(nickname) || (!device_id.is_empty() && !is_storable(device_id)) {
            return;
        }
        let devices = self.entries.entry(nickname.to_string()).or_default();
        // A bare contact placeholder (`pin_bare_contact` - empty key, no
        // device confirmed to have a key at all yet) reserves exactly this
        // `(nickname, device_id)` slot ahead of time; the first real key
        // pinned to it fills it in place rather than pushing a sibling
        // entry that would leave the placeholder behind as a permanent
        // ghost row. A placeholder with a genuinely different device_id,
        // or a real (non-empty-key) entry sharing this one, is untouched.
        if let Some(placeholder) = devices.iter_mut().find(|e| e.device_id == device_id && e.key.is_empty())
        {
            placeholder.key = key.to_vec();
            placeholder.trust = trust;
            placeholder.key_mode = key_mode;
            return;
        }
        devices.push(DeviceEntry {
            device_id: device_id.to_string(),
            key: key.to_vec(),
            trust,
            last_addr: None,
            last_seen_unix: None,
            key_mode,
            pinned_from: None,
        });
    }

    /// Adds `nickname` as a contact with no key at all yet - Add Contact
    /// with no identity card imported (`client::tui::contacts`' "the
    /// identity card is optional" flow): a placeholder entry, empty key
    /// and `key_mode: None`, that shows up as an ordinary row (all three
    /// key badges red) and is silently filled in place - never left behind
    /// as a duplicate - the moment a real key is pinned to it the normal
    /// way (`pin_new_device_with_key_mode`'s placeholder handling above),
    /// whether that is this same device_id being TOFU-pinned by a live
    /// connection or a card/OTP key added later from this exact row.
    ///
    /// `device_id` empty reserves the nickname's shared unbound slot -
    /// refused if it already has an unbound entry with `key_mode: None`
    /// (a real `Direct`-framed pin or an earlier bare contact; the two
    /// would otherwise be indistinguishable, and this module's own "at
    /// most one unbound entry per key_mode" invariant would break).
    /// `device_id` non-empty reserves that exact device - refused if
    /// `(nickname, device_id)` already names a real, keyed pin. Returns
    /// whether a placeholder was actually reserved.
    pub fn pin_bare_contact(&mut self, nickname: &str, device_id: &str) -> bool {
        if !is_storable(nickname) || (!device_id.is_empty() && !is_storable(device_id)) {
            return false;
        }
        if device_id.is_empty() {
            let already_unbound_none = self
                .entries
                .get(nickname)
                .is_some_and(|devices| devices.iter().any(|e| e.is_unbound() && e.key_mode.is_none()));
            if already_unbound_none {
                return false;
            }
        } else if self
            .entries
            .get(nickname)
            .is_some_and(|devices| devices.iter().any(|e| e.device_id == device_id))
        {
            // Already reserved, bare or real alike - `get_for_device`
            // alone would miss an existing placeholder (invisible to it
            // by design), silently "succeeding" a second time with no
            // actual second row, which is harmless but not the refusal a
            // caller checking this return value expects.
            return false;
        }
        self.pin_new_device_with_key_mode(nickname, device_id, &[], Trust::Tofu, None);
        true
    }

    /// Overwrites the key already pinned for `(nickname, device_id)` in
    /// place - a genuine key change on a device already known, either
    /// because a continuity certificate proved it deliberate (silent) or
    /// because the user `Accept`ed an impersonation review for that exact
    /// device. Every other field (trust, last-seen, key_mode,
    /// pinned_from) is left as it was; the caller updates whichever of
    /// those the situation calls for separately. Returns whether there
    /// was an entry to update.
    pub fn replace_device_key(&mut self, nickname: &str, device_id: &str, key: &[u8]) -> bool {
        let Some(entry) = self
            .entries
            .get_mut(nickname)
            .and_then(|devices| devices.iter_mut().find(|e| e.device_id == device_id))
        else {
            return false;
        };
        entry.key = key.to_vec();
        true
    }

    /// An `AcceptIdentity` review's write: overwrites the matching
    /// device's key in place if one already exists, pins a fresh entry
    /// otherwise - key and `key_mode` set atomically on the same entry,
    /// never through a separate `set_key_mode` call afterward. For a real
    /// (non-empty) `device_id`, already unique per nickname by
    /// construction, "matching" means that exact device regardless of its
    /// current `key_mode` (a device's key_mode is display bookkeeping
    /// that follows whatever it's actually pinned under, never a second
    /// axis of identity for an already-known device). For the rare
    /// unbound (`""`) fallback - a review accepted before this
    /// connection's device id was ever learned - "matching" is scoped by
    /// `key_mode` too, since the empty sentinel is shared by every
    /// unbound entry regardless of kind, and a `StaticMismatch` review is
    /// always about the `pq_hybrid` dimension specifically; unlike the
    /// bound case, blindly touching whichever unbound entry happens to be
    /// first could silently corrupt an unrelated `Direct` pin.
    pub fn accept_identity_review(
        &mut self,
        nickname: &str,
        device_id: &str,
        key: &[u8],
        key_mode: KeyMode,
        trust: Trust,
    ) {
        let existing = self.entries.get_mut(nickname).and_then(|devices| {
            if device_id.is_empty() {
                devices.iter_mut().find(|e| e.is_unbound() && e.key_mode == Some(key_mode))
            } else {
                devices.iter_mut().find(|e| e.device_id == device_id)
            }
        });
        if let Some(entry) = existing {
            entry.key = key.to_vec();
            entry.key_mode = Some(key_mode);
            return;
        }
        self.pin_new_device_with_key_mode(nickname, device_id, key, trust, Some(key_mode));
    }

    /// Resolves `nickname`'s unbound `pq_hybrid` entry for an
    /// identity-card import (`contacts::pin_identity_card`): overwrites
    /// it in place, verified, if one already exists, or pins a fresh
    /// verified one otherwise - setting the key, trust and `pinned_from`
    /// all on the exact same entry in one step, never through a second,
    /// separately-looked-up call. That matters here specifically: the
    /// empty device_id sentinel is shared by *every* unbound entry
    /// regardless of `key_mode` - a nickname can genuinely have both an
    /// unbound `Direct` pin (e.g. from the unknown-peer-confirm flow,
    /// §7.1.5) and an unbound `pq_hybrid` first sighting
    /// (`check_identity`) at once - so this is `key_mode`-scoped to find
    /// the right one, and every field is set on that *same* borrow rather
    /// than re-resolved by a second, ambiguous `device_id == ""` lookup
    /// the way `set_key_mode`/`mark_verified`/`set_pinned_from` each do
    /// individually (which could each independently land on the sibling
    /// `Direct` entry instead, even with the initial lookup fixed).
    pub fn pin_unbound_pq_hybrid_card(&mut self, nickname: &str, key: &[u8], pinned_from: PathBuf) {
        if !is_storable(nickname) {
            return;
        }
        let devices = self.entries.entry(nickname.to_string()).or_default();
        if let Some(entry) =
            devices.iter_mut().find(|e| e.is_unbound() && e.key_mode == Some(KeyMode::PqHybrid))
        {
            entry.key = key.to_vec();
            entry.trust = Trust::Verified;
            entry.pinned_from = Some(pinned_from);
            return;
        }
        devices.push(DeviceEntry {
            device_id: String::new(),
            key: key.to_vec(),
            trust: Trust::Verified,
            last_addr: None,
            last_seen_unix: None,
            key_mode: Some(KeyMode::PqHybrid),
            pinned_from: Some(pinned_from),
        });
    }

    /// Resolves an unbound entry into a bound one by rewriting its
    /// `device_id` in place - the "filled in on first use" rule: the
    /// first live connection whose announced key matches an unbound pin
    /// exactly claims it, with no review, since this can only ever narrow
    /// an already-trusted pin rather than trust anything new. `key_mode`
    /// scopes which unbound entry (`None` for `Direct`-framed, `Some` for
    /// `pq_hybrid`) - the module doc's "scoped by key kind". Returns
    /// whether there was a matching unbound entry to claim; the caller is
    /// expected to have already confirmed the key matches (this only
    /// re-checks defensively).
    pub fn claim_unbound(
        &mut self,
        nickname: &str,
        device_id: &str,
        key: &[u8],
        key_mode: Option<KeyMode>,
    ) -> bool {
        if device_id.is_empty() || !is_storable(device_id) {
            return false;
        }
        let Some(entry) = self.entries.get_mut(nickname).and_then(|devices| {
            devices
                .iter_mut()
                .find(|e| e.is_unbound() && e.key_mode == key_mode && e.key == key)
        }) else {
            return false;
        };
        entry.device_id = device_id.to_string();
        true
    }

    /// Rebinds an existing entry to a different `device_id` in place - a
    /// continuity certificate proving the identity moved to (possibly) a
    /// new device in the same step it retired its keys, called alongside
    /// `replace_device_key` for that same entry. A no-op (`false`) if
    /// `old_device_id` isn't a known entry for `nickname`, or if
    /// `new_device_id` is already used by a different entry for it (that
    /// would silently merge two distinct devices' history into one row,
    /// which nothing in this design ever does).
    pub fn rebind_device(
        &mut self,
        nickname: &str,
        old_device_id: &str,
        new_device_id: &str,
    ) -> bool {
        if !new_device_id.is_empty() && !is_storable(new_device_id) {
            return false;
        }
        let Some(devices) = self.entries.get_mut(nickname) else {
            return false;
        };
        if old_device_id == new_device_id {
            return devices.iter().any(|e| e.device_id == old_device_id);
        }
        if devices.iter().any(|e| e.device_id == new_device_id) {
            return false;
        }
        let Some(entry) = devices.iter_mut().find(|e| e.device_id == old_device_id) else {
            return false;
        };
        entry.device_id = new_device_id.to_string();
        true
    }

    /// Marks `(nickname, device_id)` as confirmed out of band. Returns
    /// whether there was anything to mark.
    pub fn mark_verified(&mut self, nickname: &str, device_id: &str) -> bool {
        match self
            .entries
            .get_mut(nickname)
            .and_then(|devices| devices.iter_mut().find(|e| e.device_id == device_id))
        {
            Some(entry) => {
                entry.trust = Trust::Verified;
                true
            }
            None => false,
        }
    }

    /// How much `(nickname, device_id)`'s pin is worth, if it exists.
    pub fn trust_for_device(&self, nickname: &str, device_id: &str) -> Option<Trust> {
        self.entries
            .get(nickname)?
            .iter()
            .find(|e| e.device_id == device_id)
            .map(|e| e.trust)
    }

    /// `trust_for_device` against `get`'s "most recent" default device -
    /// for the same call sites that use `get` with no live device_id in
    /// hand.
    pub fn trust(&self, nickname: &str) -> Option<Trust> {
        self.most_recent_device(nickname).map(|e| e.trust)
    }

    /// Records which `KeyMode` `(nickname, device_id)` was pinned under -
    /// see `DeviceEntry::key_mode`'s doc. A no-op if that pair isn't
    /// pinned at all.
    pub fn set_key_mode(&mut self, nickname: &str, device_id: &str, key_mode: KeyMode) {
        if let Some(entry) = self
            .entries
            .get_mut(nickname)
            .and_then(|devices| devices.iter_mut().find(|e| e.device_id == device_id))
        {
            entry.key_mode = Some(key_mode);
        }
    }

    /// `key_mode` against `get`'s "most recent" default device.
    pub fn key_mode(&self, nickname: &str) -> Option<KeyMode> {
        self.most_recent_device(nickname)?.key_mode
    }

    /// Records the identity-card file `(nickname, device_id)`'s pin was
    /// manually imported from - see `DeviceEntry::pinned_from`'s doc. A
    /// no-op if that pair isn't pinned.
    pub fn set_pinned_from(&mut self, nickname: &str, device_id: &str, path: PathBuf) {
        if let Some(entry) = self
            .entries
            .get_mut(nickname)
            .and_then(|devices| devices.iter_mut().find(|e| e.device_id == device_id))
        {
            entry.pinned_from = Some(path);
        }
    }

    /// `pinned_from` against `get`'s "most recent" default device.
    pub fn pinned_from(&self, nickname: &str) -> Option<&Path> {
        self.most_recent_device(nickname)?.pinned_from.as_deref()
    }

    /// `last_seen_unix` against `get`'s "most recent" default device.
    pub fn last_seen_unix(&self, nickname: &str) -> Option<u64> {
        self.most_recent_device(nickname)?.last_seen_unix
    }

    /// `last_addr` against `get`'s "most recent" default device.
    pub fn last_addr(&self, nickname: &str) -> Option<SocketAddr> {
        self.most_recent_device(nickname)?.last_addr
    }

    /// Every pinned nickname, sorted, each at least once - the contacts
    /// list iterates this and then `devices_of` each one for its rows.
    pub fn nicknames(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        names
    }

    /// Forgets `nickname` entirely, every device - "delete contact" in
    /// the contacts list. Returns whether there was anything to forget.
    pub fn remove(&mut self, nickname: &str) -> bool {
        self.entries.remove(nickname).is_some()
    }

    /// Forgets just `(nickname, device_id)` - the per-device delete a
    /// single Contacts row offers, leaving every sibling device's entry
    /// untouched (the additive rule applied to deletion). Returns whether
    /// there was anything to forget; removes the nickname's whole entry
    /// from the map once its last device is gone, so `nicknames()` never
    /// lists a nickname with zero devices.
    pub fn remove_device(&mut self, nickname: &str, device_id: &str) -> bool {
        let Some(devices) = self.entries.get_mut(nickname) else {
            return false;
        };
        let before = devices.len();
        devices.retain(|e| e.device_id != device_id);
        let removed = devices.len() != before;
        if devices.is_empty() {
            self.entries.remove(nickname);
        }
        removed
    }

    /// Records where `(nickname, device_id)`'s key was just confirmed
    /// reachable over the direct P2P link - called once its P2P link goes
    /// `Active` (`session.rs`'s `LinkStatusChanged` handling) or once an
    /// impersonation review is `Accept`ed. A no-op if that pair isn't
    /// pinned.
    pub fn set_last_seen(&mut self, nickname: &str, device_id: &str, addr: SocketAddr) {
        let Some(entry) = self
            .entries
            .get_mut(nickname)
            .and_then(|devices| devices.iter_mut().find(|e| e.device_id == device_id))
        else {
            return;
        };
        entry.last_addr = Some(addr);
        entry.last_seen_unix = Some(now_unix());
    }

    /// Persists the current entries to `path`, creating parent directories
    /// if needed. Nicknames are written in sorted order, and each
    /// nickname's own devices in the order they're held internally
    /// (insertion order - a freshly pinned device is always pushed last),
    /// so the file diffs reasonably cleanly and `get`'s "most recently
    /// pinned" fallback stays meaningful across a save/load round trip.
    pub fn save(&self) -> io::Result<()> {
        crate::platform::ensure_parent_dir(&self.path)?;
        let mut names: Vec<&String> = self.entries.keys().collect();
        names.sort();
        let mut out = String::new();
        for name in names {
            for entry in &self.entries[name] {
                out.push_str(name);
                out.push('\t');
                out.push_str(&entry.device_id);
                out.push('\t');
                out.push_str(&hex_encode(&entry.key));
                out.push('\t');
                out.push_str(entry.trust.as_str());
                out.push('\t');
                if let Some(addr) = entry.last_addr {
                    out.push_str(&addr.to_string());
                }
                out.push('\t');
                if let Some(seen) = entry.last_seen_unix {
                    out.push_str(&seen.to_string());
                }
                out.push('\t');
                if let Some(mode) = entry.key_mode {
                    out.push_str(key_mode_as_str(mode));
                }
                out.push('\t');
                if let Some(path) = &entry.pinned_from {
                    out.push_str(&path.display().to_string());
                }
                out.push('\n');
            }
        }
        fs::write(&self.path, out)
    }

    /// `save`, with the one thing every caller in this app does about a
    /// failure: log it and carry on. Losing a pin write is bad, but not
    /// worth abandoning the action that prompted it - the entry is still
    /// live in memory for this session, and the next successful save
    /// writes it. Thirteen call sites spelled this out identically; the
    /// point of naming it is that they cannot drift into handling it
    /// three different ways.
    pub fn save_or_warn(&self) {
        if let Err(e) = self.save() {
            crate::log_warn!("failed to save id_store: {e}");
        }
    }
}

/// One line: `nickname<TAB>device_id<TAB>hex<TAB>trust<TAB>last addr<TAB>
/// last seen unix<TAB>key mode<TAB>pinned from`. `device_id` may be
/// empty (unbound); every column from `trust` on is independently
/// optional, same evolutionary tolerance the rest of this app's flat
/// files already use for their trailing columns.
fn parse_line(line: &str) -> Option<(String, DeviceEntry)> {
    let mut fields = line.split('\t');
    let name = fields.next()?;
    if !is_storable(name) {
        return None;
    }
    let device_id = fields.next()?;
    if !device_id.is_empty() && !is_storable(device_id) {
        return None;
    }
    let hex = fields.next()?;
    let key = hex_decode(hex)?;
    let trust = fields.next().and_then(Trust::parse).unwrap_or_default();
    let last_addr = fields
        .next()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());
    let last_seen_unix = fields
        .next()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());
    let key_mode = fields.next().and_then(parse_key_mode);
    let pinned_from = fields.next().filter(|s| !s.is_empty()).map(PathBuf::from);
    Some((
        name.to_string(),
        DeviceEntry {
            device_id: device_id.to_string(),
            key,
            trust,
            last_addr,
            last_seen_unix,
            key_mode,
            pinned_from,
        },
    ))
}
