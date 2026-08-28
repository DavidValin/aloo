//! Persistent per-contact state for the OTP layer (`client::otp`),
//! mirroring `idstore.rs`'s flat-file convention: one small text file under
//! `~/.aloo/`, loaded at session-build time and written back synchronously
//! after every mutation - plus one small sibling file next to it
//! (`<path>.pending_content`) holding whatever `PendingContentSend` entries
//! are currently staged; see that type's own doc for why this lives
//! separately rather than as a new line shape mixed into the main format.
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
    /// The *offer* phase of a voice message - padded exactly like
    /// `File`'s, so the duration never travels in the clear, and carrying
    /// `stream_id` for the same reason `File` does: recovery hands the
    /// resent offer back to the same `OwnFileTarget` rather than
    /// allocating a fresh one. The recording itself is a second,
    /// independent spend, recorded as `FileContent`.
    Voice { stream_id: u64, duration_ms: u32 },
    /// An OTP mail's pad spend (docs/PROTOCOL.md §17.2). Unlike every other
    /// variant it's acknowledged by the *server*'s `OtpMailResult` (storage
    /// is the delivery this spend waits on), and retried over the control
    /// channel by `client::otp_mail::resend_pending` rather than by
    /// `client::otp::recover_and_resend`'s P2P-link path - which therefore
    /// skips it.
    Mail { mail_id: String },
    /// The `/endotp` notice's pad spend (docs/PROTOCOL.md §16.6). An
    /// ordinary stop-and-wait send in every mechanical respect - it arms
    /// the gate, is acknowledged by the peer's proof-carrying
    /// `OtpDeliveryAck`, and is recovered (never re-encrypted) by
    /// `recover_and_resend` on every reconnect until that ack arrives -
    /// because anything less reintroduced the desync it once caused: a
    /// notice encrypted outside the gate could overwrite an in-flight
    /// message's recover-last safety copy, leapfrog it on the pad, or be
    /// spent again per retry. Its acknowledgement additionally clears
    /// `pending_end_notice` (`client::otp::on_delivery_ack`).
    EndNotice,
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
    /// `true` while this side has locally ended (paused) the session with
    /// `/endotp` and the peer still hasn't confirmed receiving that notice
    /// (`OtpEndSessionAck`) - the durable counterpart of
    /// `pending_setup_size_mb`, for the same reason: a peer who is offline
    /// right now, or whose connection drops before the notice arrives, must
    /// still learn about it, so this is retried on every reconnect
    /// (`client::otp::resend_pending_end_notices`) rather than only
    /// attempted once. Routinely `true` alongside `provisioned` - unlike
    /// this field's old "the keychain entry was just destroyed" meaning,
    /// `OtpStore::pause_session` deliberately leaves `provisioned` and the
    /// sequence counters untouched, since `/endotp` no longer removes the
    /// real keychain entry either: pausing is not a teardown, it's a
    /// contact this side has stopped actively using for now, resumable with
    /// its existing pad via `/otp`.
    pub pending_end_notice: bool,
    /// What the peer's acknowledgement of `pending_unacked_out_seq` must
    /// carry to be believed: `sha256` of the nonce buried inside that
    /// message (`crypto::otp::AckProof`).
    ///
    /// Persisted rather than kept in memory because the gate it guards is
    /// persisted: a message still awaiting acknowledgement across a restart
    /// must still be checkable when the ack finally arrives, or the only
    /// options would be trusting an unverified ack or wedging the contact
    /// forever.
    pub pending_ack_proof: Option<[u8; 32]>,
    /// Which pad is actually installed for this contact
    /// (`crypto::otp::pad_pair_digest`), when it arrived over the network.
    ///
    /// `provisioned` alone cannot tell a re-delivery of the installed pad
    /// from a *new* pad offered for the same contact, and the two must be
    /// answered oppositely: the first is re-verified silently so the sender
    /// can stop retrying, the second is a proposal the user has to decide.
    /// Conflating them let the sender install a new pad while this side
    /// kept the old one - two different pads under one name, decoding to
    /// garbage with nothing reporting it.
    ///
    /// `None` for a contact adopted from an existing keychain entry rather
    /// than received, where there is nothing to compare against; such a
    /// contact simply always asks.
    pub installed_pad_digest: Option<[u8; 32]>,
    /// The write-ahead half of every outgoing spend: what the *next*
    /// `otp --encrypt` for this contact is about to be, recorded (and
    /// saved) immediately before the encrypt runs and cleared by the
    /// `record_sent` that finalises it. At rest this is `None`; it is
    /// `Some` only inside the encrypt's own window - which is why a `Some`
    /// found at startup means the process died inside that window, and the
    /// tool's own encrypt counter then says on which side: still equal to
    /// `next_out_seq` and the encrypt never ran (the intent is dropped,
    /// nothing was spent); one ahead and the spend is real but unrecorded -
    /// the orphan every later send would silently leapfrog, poisoning the
    /// peer's decoder forever - so the intent is *promoted* to an ordinary
    /// pending send (`reconcile_orphaned_sends`), and the standard
    /// recovery machinery resends the tool's kept ciphertext under the
    /// right framing. Also doubles as a same-process guard: a second send
    /// entering while an encrypt is mid-flight queues behind it exactly as
    /// it would behind an armed gate (`client::otp::send_or_queue`).
    pub encrypt_intent: Option<PendingOtpContent>,
    /// `true` from the moment this side - the pad's *generator* - installs
    /// its half and sends `OtpPadCommit`, until the peer's
    /// `OtpPadCommitAck` confirms they installed theirs. The commit is the
    /// one provisioning payload whose loss splits the pair asymmetrically
    /// (this side provisioned and active, the peer holding only staged
    /// bytes), so like every other owed thing here it is recorded against
    /// the contact name and re-sent on every reconnect
    /// (`client::otp::resend_pending_commits`) until genuinely
    /// acknowledged - the receiving side already answers a repeated commit
    /// idempotently.
    pub pending_commit: bool,
    /// The `(seq, proof)` of the most recent incoming message this side
    /// actually accepted and acknowledged - the durable record
    /// `client::otp::on_message`/`on_file_offer`/`on_voice_offer` consult to
    /// answer a re-arrival of that exact message (the sender's own
    /// stop-and-wait gate never has more than one message outstanding, so
    /// only the single most recent one could ever legitimately reappear)
    /// by resending the very same ack, without re-decrypting anything or
    /// spending any further pad. `None` for a contact that has never had a
    /// message accepted, or whose peer has only ever sent session-control
    /// payloads (which ack each other, not through this field).
    pub last_received_ack: Option<(u64, [u8; 32])>,
    /// Which device this `Direct`-framed (pad-only) contact's peer has
    /// been confirmed to be, once known - device-pinning plan §5. Set the
    /// first time a message from them decrypts successfully (not merely
    /// on receiving one; a bare claim proves nothing on its own). Once
    /// set, a later message claiming a *different* device is refused
    /// before `otp --decrypt` ever runs (`client::otp`'s pre-decrypt
    /// gate) - a one-time pad has no safe multi-device story, unlike a
    /// `pq_hybrid` identity. Always `None` for a `PqWrapped` contact,
    /// which has no use for this field at all (§4's naming is already
    /// device-qualified, and its device data arrives over the separate
    /// `DeviceIdAnnounce`).
    pub bound_peer_device_id: Option<String>,
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
/// `pending_setup_size_mb` already established. Two more trailing columns,
/// `pending_ack_proof` and `installed_pad_digest` (both hex, empty when
/// `None`), a pair, `last_received_ack_seq`/`last_received_ack_proof`
/// (the latter hex too, both empty or absent together meaning `None`), and
/// finally `pending_commit` (`1`/empty like `pending_end_notice`),
/// `encrypt_intent` (the same encoding `pending_content` uses, empty when
/// `None`), and `bound_peer_device_id` (the raw device_id string, empty
/// when `None` - device-pinning plan §5) follow the same tolerance again.
pub struct OtpStore {
    path: PathBuf,
    entries: HashMap<String, OtpContactState>,
    pending_content_sends: HashMap<u64, PendingContentSend>,
}

/// What `send_file_offer`/`send_voice_offer` stage the instant their offer
/// is safely out (a genuine, durable, gated spend of its own - the offer
/// phase's own retry already covers *that*) but before the peer's
/// acceptance has arrived to trigger the *content* phase's separate spend:
/// the plaintext this side is holding onto meanwhile, and which contact it
/// belongs to. Never a `UserId`, for the same reason nothing else in this
/// file keeps one - only a connection-lifetime handle, unsafe to trust
/// across a reconnect; the peer is re-resolved fresh from `known_users`
/// once a `FileAccepted` (or a reconnect that might carry one) actually
/// needs it (`client::otp::begin_file_content`,
/// `resume_pending_content_sends`).
///
/// Without this, a sender whose own process restarted in this exact
/// window - offer sent, not yet accepted, or accepted by a peer whose
/// `FileAccepted` reply the old process never lived to see - lost the
/// recording or file silently: `own_file_targets` is in-memory only, so a
/// `FileAccepted` arriving (or already queued) after the restart found
/// nothing to act on. No pad was ever at risk either way - the content
/// phase's own spend only ever happens *after* this record would have
/// resolved it - but the message itself, and the plaintext staged for it,
/// were both lost with no notice to either side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingContentSend {
    pub contact_name: String,
    pub path: PathBuf,
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
            pending_content_sends: HashMap::new(),
        }
    }

    /// The sibling file `pending_content_sends` persists to - a small,
    /// separate flat file next to the main one rather than a new line
    /// shape mixed into it, so `parse_line`'s existing per-contact format
    /// (and every caller of `new_empty`/`load` with a single path) needs no
    /// change at all.
    fn content_sends_path(main_path: &Path) -> PathBuf {
        let name = main_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        main_path.with_file_name(format!("{name}.pending_content"))
    }

    /// Records that `stream_id`'s content is staged at `path`, awaiting the
    /// peer's acceptance - see `PendingContentSend`'s doc. The caller must
    /// save before the offer that announces it actually leaves, or the
    /// record protects nothing.
    pub fn stage_content_send(&mut self, stream_id: u64, contact_name: &str, path: PathBuf) {
        self.pending_content_sends.insert(
            stream_id,
            PendingContentSend {
                contact_name: contact_name.to_string(),
                path,
            },
        );
    }

    /// Takes (and clears) the staged record for `stream_id` - called the
    /// moment something else (an immediate encrypt, or the ordinary
    /// in-memory send queue) becomes the authoritative tracker of this
    /// content's fate, so a stale record can never shadow it.
    pub fn take_content_send(&mut self, stream_id: u64) -> Option<PendingContentSend> {
        self.pending_content_sends.remove(&stream_id)
    }

    /// Every content send still staged - what a reconnect's autoheal pass
    /// (`client::otp::resume_pending_content_sends`) resumes.
    pub fn content_sends(&self) -> impl Iterator<Item = (u64, &PendingContentSend)> {
        self.pending_content_sends
            .iter()
            .map(|(id, target)| (*id, target))
    }

    /// Where this store persists to - exposed for a test that needs to
    /// simulate a genuine process restart (drop this value, `load` a fresh
    /// one from the same file) rather than merely continuing in memory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads `path` if it exists; a missing file just starts empty (first
    /// run). A malformed line is skipped rather than failing the whole
    /// load, same tolerance as `idstore::IdStore::load`.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut entries = HashMap::new();
        if let Some(contents) = crate::platform::read_to_string_optional(path)? {
            for line in contents.lines() {
                if let Some((name, state)) = parse_line(line) {
                    entries.insert(name, state);
                }
            }
        }
        let mut pending_content_sends = HashMap::new();
        if let Some(contents) =
            crate::platform::read_to_string_optional(&Self::content_sends_path(path))?
        {
            for line in contents.lines() {
                if let Some((id, target)) = parse_content_send_line(line) {
                    pending_content_sends.insert(id, target);
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
            pending_content_sends,
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

    /// Records which pad is installed for `contact_name`, alongside marking
    /// it provisioned - see `installed_pad_digest`.
    pub fn mark_provisioned_with_pad(&mut self, contact_name: &str, digest: [u8; 32]) {
        self.mark_provisioned(contact_name);
        if let Some(state) = self.entries.get_mut(contact_name) {
            state.installed_pad_digest = Some(digest);
        }
    }

    /// Whether `digest` names the pad already installed for this contact -
    /// i.e. whether an arriving pad is a re-delivery rather than a new
    /// proposal. False for a contact with no recorded pad, which therefore
    /// always asks.
    pub fn is_installed_pad(&self, contact_name: &str, digest: [u8; 32]) -> bool {
        self.entries
            .get(contact_name)
            .and_then(|s| s.installed_pad_digest)
            .is_some_and(|installed| installed == digest)
    }

    /// Which device `contact_name`'s peer has been confirmed to be, for a
    /// `Direct`-framed pad-only pair - see `OtpContactState::
    /// bound_peer_device_id`'s doc. `None` for an unbound (or unknown)
    /// contact.
    pub fn bound_peer_device_id(&self, contact_name: &str) -> Option<&str> {
        self.entries.get(contact_name)?.bound_peer_device_id.as_deref()
    }

    /// Binds `contact_name`'s pad to `device_id`, the first time a message
    /// from them has genuinely decrypted (`client::otp`'s pre-decrypt
    /// gate) - a no-op if it's already bound to this exact device
    /// (idempotent, since every later message re-confirms rather than
    /// re-binds), and never overwrites a *different* existing binding:
    /// that decision belongs to the caller, which must have already
    /// refused the message before calling this at all.
    pub fn bind_peer_device(&mut self, contact_name: &str, device_id: &str) {
        let state = self.entries.entry(contact_name.to_string()).or_default();
        if state.bound_peer_device_id.is_none() {
            state.bound_peer_device_id = Some(device_id.to_string());
        }
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

    /// The pause a session converges to once its end is settled - run by
    /// the side being told the moment the notice arrives
    /// (`client::otp::apply_end_session`), and by the initiating side the
    /// moment the peer's confirmation comes back
    /// (`client::otp::on_delivery_ack` - `/endotp` is two-phase and takes
    /// no local effect before that). Pauses rather than destroys: it
    /// abandons only a pad still owed from an unfinished setup, and
    /// deliberately leaves `provisioned`, both sequence counters, *and any
    /// send still awaiting acknowledgement* exactly as they are. The pad
    /// survives - a later `/otp` with the same contact (same derived name)
    /// resumes it exactly where it left off - and an in-flight send's pad
    /// was already spent, so the peer's decoder is expecting exactly that
    /// ciphertext next: abandoning it would leave them permanently unable
    /// to decrypt anything this side says afterwards. It stays recoverable
    /// (`client::otp::recover_and_resend`) until genuinely acknowledged.
    pub fn pause_after_peer_ended(&mut self, contact_name: &str) {
        let state = self.entries.entry(contact_name.to_string()).or_default();
        state.pending_setup_size_mb = None;
    }

    /// Records what the next `otp --encrypt` for `contact_name` is about
    /// to be - the write-ahead half of a spend; see `encrypt_intent`'s doc.
    /// The caller must save before running the encrypt, or the record
    /// protects nothing.
    pub fn set_encrypt_intent(&mut self, contact_name: &str, content: PendingOtpContent) {
        self.entries
            .entry(contact_name.to_string())
            .or_default()
            .encrypt_intent = Some(content);
    }

    /// Drops a write-ahead intent whose encrypt never ran (it failed, or
    /// reconciliation found the tool's counter unmoved). Returns what was
    /// recorded, for a caller cleaning up whatever else the intent staged.
    pub fn clear_encrypt_intent(&mut self, contact_name: &str) -> Option<PendingOtpContent> {
        self.entries
            .get_mut(contact_name)?
            .encrypt_intent
            .take()
    }

    /// Whether an encrypt is mid-flight for `contact_name` right now - the
    /// same-process half of `encrypt_intent`'s guard.
    pub fn encrypt_in_flight(&self, contact_name: &str) -> bool {
        self.entries
            .get(contact_name)
            .is_some_and(|s| s.encrypt_intent.is_some())
    }

    /// Every contact holding a write-ahead intent - at startup, each one is
    /// a send the previous process died inside
    /// (`client::otp::reconcile_orphaned_sends`).
    pub fn encrypt_intents(&self) -> impl Iterator<Item = (&str, &PendingOtpContent)> {
        self.entries.iter().filter_map(|(name, state)| {
            Some((name.as_str(), state.encrypt_intent.as_ref()?))
        })
    }

    /// Records that this side has installed its half of a fresh pad and the
    /// peer's `OtpPadCommitAck` is now owed - see `pending_commit`'s doc.
    pub fn mark_commit_owed(&mut self, contact_name: &str) {
        self.entries
            .entry(contact_name.to_string())
            .or_default()
            .pending_commit = true;
    }

    /// The peer confirmed installing their half - stop re-sending the
    /// commit. Returns whether one was actually owed.
    pub fn clear_commit_owed(&mut self, contact_name: &str) -> bool {
        match self.entries.get_mut(contact_name) {
            Some(state) => std::mem::take(&mut state.pending_commit),
            None => false,
        }
    }

    /// Every contact whose `OtpPadCommit` is still unconfirmed, for the
    /// reconnect retry pass (`client::otp::resend_pending_commits`).
    pub fn pending_commits(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter_map(|(name, state)| state.pending_commit.then_some(name.as_str()))
    }

    /// Records that `/endotp` has been requested for `contact_name` and the
    /// peer's confirmation is now owed - the durable half of the two-phase
    /// end (`client::otp::handle_end_otp_command`): nothing is paused yet,
    /// nothing is torn down; the session stays fully active on this side
    /// until the peer's proof-carrying acknowledgement of the end notice
    /// arrives (`client::otp::on_delivery_ack`'s confirmation), however
    /// many reconnects that takes.
    pub fn mark_end_requested(&mut self, contact_name: &str) {
        self.entries
            .entry(contact_name.to_string())
            .or_default()
            .pending_end_notice = true;
    }

    /// The peer's acknowledgement of the notice arrived - stop retrying it.
    /// Returns whether one was actually outstanding, so a stray/duplicate
    /// ack can be told apart from a genuine one.
    pub fn clear_end_notice(&mut self, contact_name: &str) -> bool {
        match self.entries.get_mut(contact_name) {
            Some(state) => std::mem::take(&mut state.pending_end_notice),
            None => false,
        }
    }

    /// Drops this side's own outstanding end-notice *send* -
    /// `pending_unacked_out_seq`/`pending_content`/`pending_ack_proof` - but
    /// only when what is actually pending is the end notice itself
    /// (`PendingOtpContent::EndNotice`); an ordinary message still in
    /// flight for this contact has its own, unrelated resolution path
    /// (`client::otp::recover_and_resend`/the peer's real
    /// `OtpDeliveryAck`) and must not be silently discarded just because
    /// the session happens to be ending too.
    ///
    /// Used when a peer's own end-of-session notice arrives for this
    /// contact - whether a genuine `/endotp` or the substitute notice
    /// `client::otp::end_session_for_missing_contact` sends when it
    /// discovers this side's contact is gone - instead of the
    /// acknowledgement this side's own notice was waiting for: that ack
    /// (`client::otp::on_end_session_ack`/`apply_otp_message`'s
    /// `OtpEndSession` arm) will now never come for this exact send, since
    /// the peer answered with a fresh notice of their own rather than
    /// acknowledging this side's. Without this, `pending_end_notice` and
    /// the gate it armed would stay set forever, refusing every further
    /// send to this contact with "the session is ending" until the next
    /// `/otp` happened to reset it.
    pub fn clear_own_pending_end_notice_send(&mut self, contact_name: &str) {
        if let Some(state) = self.entries.get_mut(contact_name)
            && matches!(state.pending_content, Some(PendingOtpContent::EndNotice))
        {
            state.pending_unacked_out_seq = None;
            state.pending_content = None;
            state.pending_ack_proof = None;
        }
    }

    /// Replaces `contact_name`'s entry for a genuinely *new* pad just
    /// installed over it (`otp_cli::add_contact` ran): the tool's own
    /// per-contact state - sequence numbers, offsets, the recover-last
    /// copy - all reset with the keychain entry, so every aloo-level
    /// counter and remnant keyed to the old pad must reset with it.
    /// Keeping any of it was what left a replaced pad born desynced: stale
    /// `next_out_seq`/`next_expected_in_seq` silently dropped every message
    /// of the new pad's stream, and a stale `last_received_ack` could
    /// answer a new pad's sequence with the old pad's proof.
    pub fn reset_for_new_pad(&mut self, contact_name: &str, digest: Option<[u8; 32]>) {
        self.entries.insert(
            contact_name.to_string(),
            OtpContactState {
                provisioned: true,
                installed_pad_digest: digest,
                ..OtpContactState::default()
            },
        );
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

    pub fn record_sent(
        &mut self,
        contact_name: &str,
        seq: u64,
        content: PendingOtpContent,
        ack_proof: Option<[u8; 32]>,
    ) {
        let state = self.entries.entry(contact_name.to_string()).or_default();
        state.pending_unacked_out_seq = Some(seq);
        state.pending_content = Some(content);
        state.pending_ack_proof = ack_proof;
        state.next_out_seq = state.next_out_seq.max(seq + 1);
        // The spend this intent announced is now fully recorded - the
        // write-ahead record has done its job (`encrypt_intent`'s doc).
        state.encrypt_intent = None;
    }

    /// Clears `pending_unacked_out_seq` iff it currently equals `seq` -
    /// refusing a stale or mismatched ack rather than trusting it blindly.
    /// Returns whether it actually cleared anything.
    pub fn record_acked(
        &mut self,
        contact_name: &str,
        seq: u64,
        proof: Option<[u8; 32]>,
    ) -> bool {
        match self.entries.get_mut(contact_name) {
            Some(state) if state.pending_unacked_out_seq == Some(seq) => {
                // The acknowledgement has to prove it came from someone who
                // actually decrypted the message it names. A `seq` alone is
                // quotable by anyone who saw the packet; the proof is not,
                // since it needs the nonce that only the pad reveals.
                //
                // An expectation of `None` means the message predates this
                // check (sent by an older build, or recovered from a store
                // written before the field existed) - accepted, since
                // refusing would wedge the contact permanently.
                if let Some(expected) = state.pending_ack_proof
                    && proof != Some(expected)
                {
                    return false;
                }
                state.pending_unacked_out_seq = None;
                state.pending_content = None;
                state.pending_ack_proof = None;
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

    /// Records the ack this side sent for the most recent incoming message
    /// from `contact_name`, overwriting whatever was recorded before - with
    /// only one message ever outstanding on the sender's own stop-and-wait
    /// gate, only the latest could ever legitimately need re-acking again.
    pub fn record_last_received_ack(&mut self, contact_name: &str, seq: u64, proof: [u8; 32]) {
        let state = self.entries.entry(contact_name.to_string()).or_default();
        state.last_received_ack = Some((seq, proof));
    }

    /// What to re-send if `seq` (already consumed - see `is_next_expected`)
    /// arrives again: `Some(proof)` only when it matches the last message
    /// this side actually processed and acked, since that is the only
    /// re-arrival the peer's own single-outstanding-message gate could ever
    /// produce. Anything older is a genuinely stale replay, answered with
    /// silence exactly as before this existed.
    pub fn ack_to_resend(&self, contact_name: &str, seq: u64) -> Option<[u8; 32]> {
        let (last_seq, proof) = self.entries.get(contact_name)?.last_received_ack?;
        (last_seq == seq).then_some(proof)
    }

    /// Persists the current entries to `path`, creating parent directories
    /// if needed. Called synchronously after every mutation above - see
    /// the module doc for why this file's cadence is stricter than
    /// `idstore.rs`'s.
    pub fn save(&self) -> io::Result<()> {
        crate::platform::ensure_parent_dir(&self.path)?;
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
            out.push('\t');
            if let Some(proof) = state.pending_ack_proof {
                out.push_str(&crate::crypto::hex_encode(&proof));
            }
            out.push('\t');
            if let Some(digest) = state.installed_pad_digest {
                out.push_str(&crate::crypto::hex_encode(&digest));
            }
            out.push('\t');
            if let Some((seq, _)) = state.last_received_ack {
                out.push_str(&seq.to_string());
            }
            out.push('\t');
            if let Some((_, proof)) = state.last_received_ack {
                out.push_str(&crate::crypto::hex_encode(&proof));
            }
            out.push('\t');
            if state.pending_commit {
                out.push('1');
            }
            out.push('\t');
            if let Some(intent) = &state.encrypt_intent {
                out.push_str(&encode_pending_content(intent));
            }
            out.push('\t');
            if let Some(device_id) = &state.bound_peer_device_id {
                out.push_str(device_id);
            }
            out.push('\n');
        }
        fs::write(&self.path, out)?;
        self.save_content_sends()
    }

    fn save_content_sends(&self) -> io::Result<()> {
        let mut ids: Vec<&u64> = self.pending_content_sends.keys().collect();
        ids.sort();
        let mut out = String::new();
        for id in ids {
            let target = &self.pending_content_sends[id];
            out.push_str(&id.to_string());
            out.push('\t');
            out.push_str(&target.contact_name);
            out.push('\t');
            out.push_str(&target.path.to_string_lossy());
            out.push('\n');
        }
        fs::write(Self::content_sends_path(&self.path), out)
    }
}

/// `stream_id<TAB>contact_name<TAB>path` per line - a genuinely separate
/// tiny file (`PendingContentSend`'s doc) rather than a new shape mixed
/// into the per-contact lines above. `path` takes the rest of the line
/// (`splitn`, not `split`) since a real file's own path, unlike everything
/// else this store ever writes, is user-chosen and could in principle
/// contain a tab.
fn parse_content_send_line(line: &str) -> Option<(u64, PendingContentSend)> {
    let mut parts = line.splitn(3, '\t');
    let id = parts.next()?.parse().ok()?;
    let contact_name = parts.next()?.to_string();
    let path = PathBuf::from(parts.next()?);
    Some((id, PendingContentSend { contact_name, path }))
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
        PendingOtpContent::Voice {
            stream_id,
            duration_ms,
        } => {
            format!("V{PENDING_CONTENT_SEP}{stream_id}{PENDING_CONTENT_SEP}{duration_ms}")
        }
        PendingOtpContent::Mail { mail_id } => {
            format!("M{PENDING_CONTENT_SEP}{mail_id}")
        }
        PendingOtpContent::EndNotice => "E".to_string(),
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
            let stream_id = parts.next()?.parse().ok()?;
            let duration_ms = parts.next()?.parse().ok()?;
            Some(PendingOtpContent::Voice {
                stream_id,
                duration_ms,
            })
        }
        "M" => {
            let mail_id = parts.next()?.to_string();
            Some(PendingOtpContent::Mail { mail_id })
        }
        "E" => Some(PendingOtpContent::EndNotice),
        _ => None,
    }
}

/// The next tab-separated field as a 32-byte value, `None` for an absent,
/// empty or malformed one.
///
/// Every hex column in this file is a `[u8; 32]` (an ack proof, a pad
/// digest) and every one of them is optional the same way - absent in a
/// store written before that column existed, empty when the value is not
/// set. Written out four times before this, identically.
fn next_hex32<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Option<[u8; 32]> {
    parts
        .next()
        .filter(|s| !s.is_empty())
        .and_then(crate::crypto::hex_decode)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
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
    // Same evolutionary tolerance every trailing field here gets: absent or
    // empty reads as "no proof recorded", which `record_acked` treats as a
    // message predating the check rather than one to refuse.
    let pending_ack_proof = next_hex32(&mut parts);
    let installed_pad_digest = next_hex32(&mut parts);
    // Same evolutionary tolerance as every other trailing field: absent (an
    // older store, or a contact that has never had a message accepted)
    // reads as "nothing to re-ack", never as a store to reject.
    let last_received_ack_seq: Option<u64> =
        parts.next().filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let last_received_ack_proof = next_hex32(&mut parts);
    let last_received_ack = match (last_received_ack_seq, last_received_ack_proof) {
        (Some(seq), Some(proof)) => Some((seq, proof)),
        _ => None,
    };
    // Same tolerance again: absent (an older store) reads as "no commit
    // owed" - a pre-existing provisioned pair is by definition past its
    // commit exchange.
    let pending_commit = parts.next() == Some("1");
    let encrypt_intent = parts.next().and_then(decode_pending_content);
    // Same tolerance again: absent (an older store, or a `PqWrapped`
    // contact which never sets this at all) reads as "no device bound
    // yet".
    let bound_peer_device_id = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
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
            pending_ack_proof,
            installed_pad_digest,
            last_received_ack,
            pending_commit,
            encrypt_intent,
            bound_peer_device_id,
        },
    ))
}
