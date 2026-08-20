//! Persistent per-contact state for the OTP layer (`client::otp`),
//! mirroring `idstore.rs`'s flat-file convention: one small text file under
//! `~/.aloo/`, loaded at session-build time and written back synchronously
//! after every mutation.
//!
//! Keyed by `crypto::otp::contact_name_for`'s stable, fingerprint-derived
//! name rather than `proto::UserId`: `UserId` is only a connection-lifetime
//! handle (a fresh one is assigned every reconnect), but whether a message
//! sent to this contact is still awaiting the peer's genuine network
//! acknowledgement is a correctness fact that must survive both a
//! reconnect and an app restart - losing it must never let aloo pass `-y`
//! to `otp --encrypt` without real proof of delivery. `save` is therefore
//! called synchronously right after every mutation here, not batched at a
//! few checkpoints the way `idstore.rs`'s laxer cadence is - this file is
//! the one piece of local state a stop-and-wait security property actually
//! depends on.
//!
//! `otp --status <contact> --porcelain` (`client::otp_cli::status`) is the
//! *other* source of truth this design leans on - its `enc_ack_outstanding`
//! field is the CLI's own record of whether the next `--encrypt` needs a
//! delivery confirmation at all. `pending_unacked_out_seq` here answers a
//! narrower, aloo-specific question on top of that: *which* outgoing
//! message, if any, is the one a real `OtpDeliveryAck` from the peer must
//! name before aloo may honestly pass `-y` for the next send - see
//! `client::otp`'s send-path gating.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Just enough about a pending outgoing OTP send to reconstruct and resend
/// it later using `otp_cli::recover_last`/`recover_last_file` - never the
/// ciphertext itself (`otp` already keeps that safety copy; duplicating it
/// here would be one more place for it to leak from) or a `UserId` (only a
/// connection-lifetime handle, unsafe to trust across a reconnect - the
/// peer is re-resolved fresh from `known_users` at recovery time instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingOtpContent {
    /// Always `Content::Text` in practice (the only content type
    /// `client::otp::send_now` is ever called with) - `channel` is the one
    /// piece that varies and must be reproduced exactly, since a channel
    /// send's outer `pq_hybrid` envelope is bound to it.
    Text { channel: Option<String> },
    /// The *offer* phase of a file send - `stream_id` lets recovery hand
    /// the resent offer back to the same `OwnFileTarget` entry rather than
    /// allocating a fresh one.
    File {
        stream_id: u64,
        filename: String,
        size: u64,
    },
    /// The *content* phase of an already-accepted file send - a wholly
    /// independent pad spend from `File`'s, reserved only once
    /// `FileAccepted` arrives (`client::otp::start_outgoing_file_content`).
    FileContent { stream_id: u64 },
    Voice { duration_ms: u32 },
    /// An OTP mail's pad spend (docs/PROTOCOL.md §17.2). Unlike every other
    /// variant it's acknowledged by the *server*'s `OtpMailResult` (storage
    /// is the delivery this spend waits on), and retried over the control
    /// channel by `client::otp_mail::resend_pending` rather than by
    /// `client::otp::recover_and_resend`'s P2P-link path - which therefore
    /// skips it.
    Mail { mail_id: String },
}

/// One contact's OTP state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtpContactState {
    /// Whether this contact's keychain entry is ready to use - either the
    /// PqHybrid-channel handshake completed, or an existing keychain entry
    /// was detected and adopted directly (`client::otp::detect_or_adopt_existing`).
    pub provisioned: bool,
    /// `Some(seq)` while one outgoing OTP message is genuinely awaiting the
    /// peer's network acknowledgement - the stop-and-wait gate itself.
    /// `None` means the next send may proceed (assuming `otp`'s own
    /// `enc_ack_outstanding` agrees - see the module doc).
    pub pending_unacked_out_seq: Option<u64>,
    /// `Some(size_mb)` while a pad this side generated is still waiting for
    /// the peer to accept it - the provisioning counterpart of
    /// `pending_unacked_out_seq`, and for the same reason: an invitation
    /// whose delivery was never confirmed must be retried rather than
    /// regenerated, since two different pads under one contact name have no
    /// integrity check to tell them apart and would decode to silent
    /// garbage. The pad itself lives on disk (`client::otp`'s pending
    /// staging directory), not here; this only records that it is owed. Kept
    /// keyed by contact name like everything else in this file, so a peer who
    /// reconnects under a fresh `UserId` - or an app restart - resumes rather
    /// than stranding a half-provisioned pair.
    pub pending_setup_size_mb: Option<u32>,
    /// What that outstanding send actually was, alongside
    /// `pending_unacked_out_seq` - `Some` exactly when that is, cleared the
    /// same way (`record_acked`). `client::otp::recover_and_resend` reads
    /// this to know what to rebuild around a recovered ciphertext.
    pub pending_content: Option<PendingOtpContent>,
    /// The wire-level sequence number (`P2pPayload::OtpEnvelope::seq`) the
    /// next outgoing message to this contact will use.
    pub next_out_seq: u64,
    /// The wire-level sequence number the next *incoming* message from this
    /// contact must carry - replay-guard-shaped rejection of anything
    /// stale or duplicate at the aloo layer (`otp` itself has no notion of
    /// message ordering beyond pad-offset consumption).
    pub next_expected_in_seq: u64,
    /// `true` while this side has locally ended the session with `/endotp`
    /// and the peer still hasn't confirmed receiving that notice
    /// (`OtpEndSessionAck`) - the durable counterpart of
    /// `pending_setup_size_mb`, for the same reason: a peer who is offline
    /// right now, or whose connection drops before the notice arrives, must
    /// still learn about it, so this is retried on every reconnect
    /// (`client::otp::resend_pending_end_notices`) rather than only
    /// attempted once. Never `true` at the same time as `provisioned` -
    /// `OtpStore::end_session` resets every other field the instant this is
    /// set, since ending is a full local teardown, not a pause.
    pub pending_end_notice: bool,
}

/// A `contact_name -> OtpContactState` store, backed by a small flat file:
/// `contact_name<TAB>provisioned<TAB>pending_unacked_out_seq<TAB>next_out_seq<TAB>next_expected_in_seq<TAB>pending_content<TAB>pending_setup_size_mb<TAB>pending_end_notice`
/// per line, `pending_unacked_out_seq` empty when `None`. `pending_content`
/// is empty when `None`, otherwise one of `T`/`T<US>channel`/
/// `F<US>stream_id<US>filename<US>size`/`C<US>stream_id`/`V<US>duration_ms`
/// (`<US>` = `\x1F`, chosen since a filename could in principle contain a
/// tab) - a trailing field missing entirely (an older file written before
/// this field existed) parses the same as present-but-empty, same
/// tolerance `parse_line` already gives every other field. `pending_end_notice`
/// is `1` when `true`, empty (or absent, for a file written before this
/// field existed) when `false` - same evolutionary tolerance
/// `pending_setup_size_mb` already established.
pub struct OtpStore {
    path: PathBuf,
    entries: HashMap<String, OtpContactState>,
}

impl OtpStore {
    /// `~/.aloo/otp_store` (`crate::platform::aloo_dir`).
    pub fn default_path() -> PathBuf {
        crate::platform::aloo_dir().join("otp_store")
    }

    pub fn new_empty(path: PathBuf) -> Self {
        Self {
            path,
            entries: HashMap::new(),
        }
    }

    /// Loads `path` if it exists; a missing file just starts empty (first
    /// run). A malformed line is skipped rather than failing the whole
    /// load, same tolerance as `idstore::IdStore::load`.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut entries = HashMap::new();
        match fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines() {
                    if let Some((name, state)) = parse_line(line) {
                        entries.insert(name, state);
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

    pub fn get(&self, contact_name: &str) -> Option<&OtpContactState> {
        self.entries.get(contact_name)
    }

    /// Every contact with a genuinely outstanding send right now - `client::otp::recover_and_resend`'s
    /// input, one per `LinkStatusChanged` transition to `Active`. Only
    /// entries with *both* halves set are yielded (`record_sent` always
    /// sets them together, `record_acked` always clears them together -
    /// this is just being explicit that the pairing is load-bearing, not
    /// assumed).
    pub fn pending_sends(&self) -> impl Iterator<Item = (&str, u64, &PendingOtpContent)> {
        self.entries.iter().filter_map(|(name, state)| {
            let seq = state.pending_unacked_out_seq?;
            let content = state.pending_content.as_ref()?;
            Some((name.as_str(), seq, content))
        })
    }

    pub fn mark_provisioned(&mut self, contact_name: &str) {
        self.entries
            .entry(contact_name.to_string())
            .or_default()
            .provisioned = true;
    }

    /// Records that a pad of `size_mb` per key has been generated for
    /// `contact_name` and is now owed to the peer until they accept it.
    pub fn mark_setup_pending(&mut self, contact_name: &str, size_mb: u32) {
        self.entries
            .entry(contact_name.to_string())
            .or_default()
            .pending_setup_size_mb = Some(size_mb);
    }

    /// Clears that debt - the peer accepted, refused, or the user gave up.
    /// Returns whether anything was actually owed, so a caller can tell a
    /// real answer to an outstanding invitation apart from a duplicate or
    /// stray one it should ignore.
    pub fn clear_pending_setup(&mut self, contact_name: &str) -> bool {
        match self.entries.get_mut(contact_name) {
            Some(state) => state.pending_setup_size_mb.take().is_some(),
            None => false,
        }
    }

    /// Every contact with a pad still owed to its peer, for the retry pass
    /// that runs whenever a direct link becomes reachable again.
    pub fn pending_setups(&self) -> impl Iterator<Item = (&str, u32)> {
        self.entries
            .iter()
            .filter_map(|(name, state)| Some((name.as_str(), state.pending_setup_size_mb?)))
    }

    /// Drops all local bookkeeping for `contact_name` - used only alongside
    /// `otp_cli::remove_contact` when the peer has just reported they don't
    /// actually have a matching key, so this side's belief that the
    /// contact is usable (`mark_provisioned`) doesn't outlive the keychain
    /// entry it described. Returns whether there was anything to forget.
    pub fn forget(&mut self, contact_name: &str) -> bool {
        self.entries.remove(contact_name).is_some()
    }

    /// The local half of `/endotp` (`client::otp::handle_end_otp_command`):
    /// resets `contact_name` all the way back to a never-provisioned-looking
    /// state (mirroring what `otp_cli::remove_contact` just did to the real
    /// keychain, so a later fresh `/otp` for the same pair - same derived
    /// name - starts genuinely clean, never resuming a stale sequence
    /// counter or gate from the session just ended) and records that the
    /// peer still needs to be told, durably - see `pending_end_notice`'s
    /// doc. Overwrites whatever was there rather than merging, the same way
    /// `client::otp::stage_pending_setup` treats a previous attempt for the
    /// same name as fully superseded.
    pub fn end_session(&mut self, contact_name: &str) {
        self.entries.insert(
            contact_name.to_string(),
            OtpContactState {
                pending_end_notice: true,
                ..Default::default()
            },
        );
    }

    /// The receiving side's counterpart to `end_session`
    /// (`client::otp::on_end_session`): the same full local reset, but
    /// without owing a notice of our own - we are the one being told, not
    /// the one telling.
    pub fn reset_after_peer_ended(&mut self, contact_name: &str) {
        self.entries
            .insert(contact_name.to_string(), OtpContactState::default());
    }

    /// The peer's `OtpEndSessionAck` arrived - stop retrying the notice.
    /// Returns whether one was actually outstanding, so a stray/duplicate
    /// ack can be told apart from a genuine one.
    pub fn clear_end_notice(&mut self, contact_name: &str) -> bool {
        match self.entries.get_mut(contact_name) {
            Some(state) => std::mem::take(&mut state.pending_end_notice),
            None => false,
        }
    }

    /// Every contact whose `/endotp` notice is still owed to its peer, for
    /// the retry pass that runs whenever a direct link becomes reachable
    /// again (`client::otp::resend_pending_end_notices`) - the `/endotp`
    /// counterpart of `pending_setups`.
    pub fn pending_end_notices(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter_map(|(name, state)| state.pending_end_notice.then_some(name.as_str()))
    }

    pub fn record_sent(&mut self, contact_name: &str, seq: u64, content: PendingOtpContent) {
        let state = self.entries.entry(contact_name.to_string()).or_default();
        state.pending_unacked_out_seq = Some(seq);
        state.pending_content = Some(content);
        state.next_out_seq = state.next_out_seq.max(seq + 1);
    }

    /// Clears `pending_unacked_out_seq` iff it currently equals `seq` -
    /// refusing a stale or mismatched ack rather than trusting it blindly.
    /// Returns whether it actually cleared anything.
    pub fn record_acked(&mut self, contact_name: &str, seq: u64) -> bool {
        match self.entries.get_mut(contact_name) {
            Some(state) if state.pending_unacked_out_seq == Some(seq) => {
                state.pending_unacked_out_seq = None;
                state.pending_content = None;
                true
            }
            _ => false,
        }
    }

    /// Whether `seq` is the exact next sequence expected from
    /// `contact_name` - read-only, no mutation. `otp` itself has no way to
    /// detect a duplicate input on `--decrypt` - feeding it the same
    /// ciphertext twice silently advances past the correct pad range and
    /// returns garbage the second time, rather than erroring (verified
    /// directly against the real binary). So a resent/duplicate ciphertext
    /// must be rejected *before* `otp --decrypt` ever runs, using this
    /// check - `record_received`'s own check happens too late for that,
    /// since by the time it runs the decrypt has already happened.
    pub fn is_next_expected(&self, contact_name: &str, seq: u64) -> bool {
        self.entries
            .get(contact_name)
            .map(|s| s.next_expected_in_seq)
            .unwrap_or(0)
            == seq
    }

    /// Replay-guard-shaped acceptance: `seq` must be exactly the next one
    /// expected from this contact. Returns whether it was accepted (and
    /// advances the expectation as a side effect iff so). Callers that can
    /// afford it should check `is_next_expected` *before* doing anything
    /// costly (or irreversible, like `otp --decrypt`) with the message,
    /// and only call this afterward to commit - see its doc.
    pub fn record_received(&mut self, contact_name: &str, seq: u64) -> bool {
        let state = self.entries.entry(contact_name.to_string()).or_default();
        if seq != state.next_expected_in_seq {
            return false;
        }
        state.next_expected_in_seq += 1;
        true
    }

    /// Persists the current entries to `path`, creating parent directories
    /// if needed. Called synchronously after every mutation above - see
    /// the module doc for why this file's cadence is stricter than
    /// `idstore.rs`'s.
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
            let state = &self.entries[name];
            out.push_str(name);
            out.push('\t');
            out.push_str(if state.provisioned { "1" } else { "0" });
            out.push('\t');
            if let Some(seq) = state.pending_unacked_out_seq {
                out.push_str(&seq.to_string());
            }
            out.push('\t');
            out.push_str(&state.next_out_seq.to_string());
            out.push('\t');
            out.push_str(&state.next_expected_in_seq.to_string());
            out.push('\t');
            if let Some(content) = &state.pending_content {
                out.push_str(&encode_pending_content(content));
            }
            out.push('\t');
            if let Some(size_mb) = state.pending_setup_size_mb {
                out.push_str(&size_mb.to_string());
            }
            out.push('\t');
            if state.pending_end_notice {
                out.push('1');
            }
            out.push('\n');
        }
        fs::write(&self.path, out)
    }
}

/// `\x1F` (ASCII unit separator) rather than a more typical `|`/`,` - a
/// filename could in principle contain either of those, but never a raw
/// control character, and the field itself is separated from its siblings
/// by `\t` already, so this only needs to avoid colliding with content a
/// user could plausibly type.
const PENDING_CONTENT_SEP: char = '\u{1f}';

fn encode_pending_content(content: &PendingOtpContent) -> String {
    match content {
        PendingOtpContent::Text { channel: None } => "T".to_string(),
        PendingOtpContent::Text {
            channel: Some(channel),
        } => format!("T{PENDING_CONTENT_SEP}{channel}"),
        PendingOtpContent::File {
            stream_id,
            filename,
            size,
        } => {
            format!("F{PENDING_CONTENT_SEP}{stream_id}{PENDING_CONTENT_SEP}{filename}{PENDING_CONTENT_SEP}{size}")
        }
        PendingOtpContent::FileContent { stream_id } => {
            format!("C{PENDING_CONTENT_SEP}{stream_id}")
        }
        PendingOtpContent::Voice { duration_ms } => {
            format!("V{PENDING_CONTENT_SEP}{duration_ms}")
        }
        PendingOtpContent::Mail { mail_id } => {
            format!("M{PENDING_CONTENT_SEP}{mail_id}")
        }
    }
}

fn decode_pending_content(s: &str) -> Option<PendingOtpContent> {
    if s.is_empty() {
        return None;
    }
    let mut parts = s.split(PENDING_CONTENT_SEP);
    match parts.next()? {
        "T" => Some(PendingOtpContent::Text {
            channel: parts.next().map(str::to_string),
        }),
        "F" => {
            let stream_id = parts.next()?.parse().ok()?;
            let filename = parts.next()?.to_string();
            let size = parts.next()?.parse().ok()?;
            Some(PendingOtpContent::File {
                stream_id,
                filename,
                size,
            })
        }
        "C" => {
            let stream_id = parts.next()?.parse().ok()?;
            Some(PendingOtpContent::FileContent { stream_id })
        }
        "V" => {
            let duration_ms = parts.next()?.parse().ok()?;
            Some(PendingOtpContent::Voice { duration_ms })
        }
        "M" => {
            let mail_id = parts.next()?.to_string();
            Some(PendingOtpContent::Mail { mail_id })
        }
        _ => None,
    }
}

fn parse_line(line: &str) -> Option<(String, OtpContactState)> {
    let mut parts = line.split('\t');
    let name = parts.next()?.to_string();
    let provisioned = parts.next()? == "1";
    let pending_unacked_out_seq = match parts.next()? {
        "" => None,
        s => s.parse().ok(),
    };
    let next_out_seq = parts.next()?.parse().ok()?;
    let next_expected_in_seq = parts.next()?.parse().ok()?;
    let pending_content = parts.next().and_then(decode_pending_content);
    // Absent entirely in a file written before this field existed, which
    // parses as "no setup owed" - the correct reading of an older store.
    let pending_setup_size_mb = parts.next().and_then(|s| s.parse().ok());
    // Same tolerance, one field newer still: absent (or empty) reads as
    // "no notice owed" - the correct reading of a store written before
    // `/endotp` existed at all.
    let pending_end_notice = parts.next() == Some("1");
    Some((
        name,
        OtpContactState {
            provisioned,
            pending_unacked_out_seq,
            pending_content,
            next_out_seq,
            next_expected_in_seq,
            pending_setup_size_mb,
            pending_end_notice,
        },
    ))
}
