//! Orchestration glue for the OTP layer: the send/receive-path decisions
//! (`contact_name_if_active`, `wrap_outgoing`/`unwrap_incoming`) and the
//! PqHybrid-channel provisioning handshake
//! (`initiate_provisioning`/`apply_incoming_setup`). Parallels
//! `envelope.rs`'s role for plain `pq_hybrid` sends, one layer up: nothing
//! here touches `crypto::pq` directly, it only wraps/unwraps the finished
//! blob that path already produces.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::client::otp_cli::{self, OtpCliConfig, OtpCliOutcome};
use crate::client::otp_store::OtpStore;
use crate::client::session::SessionState;
use crate::client::tui::ui::{PendingOtpGenerate, UiState};
use crate::crypto;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, Content, Envelope, UserId, UserInfo};

/// Shows one OTP error/confirmation both ways: the small top-right status
/// notice (`UiState::push_status_notice`, unchanged and still the first
/// thing the user sees) and, mirroring the same text, a system line in
/// `peer`'s own DM room (`UiState::push_otp_system_message`) - the notice
/// clears itself, but a session's setup history (and any failure) staying
/// out of the conversation it's about was easy to lose track of.
fn notify(ui_state: &mut UiState, peer: UserId, peer_name: &str, message: String, success: bool) {
    ui_state.push_status_notice(message.clone(), success);
    ui_state.push_otp_system_message(peer, peer_name, message);
}

/// Writes the write-ahead intent that protects a pad spend, and reports
/// whether it actually reached the disk.
///
/// That record is the only thing that can later tell a reconciliation pass
/// a position was spent (`reconcile_orphaned_sends` compares the pad's own
/// `enc_sequence` against what this side recorded). Spending one it could
/// not protect trades a recoverable accident for an unrecoverable one: the
/// process dies, nothing says the position went, and the two ends' pads no
/// longer line up - which the receiver's gap-free counter
/// (`OtpStore::is_next_expected`) turns into every later message being
/// refused.
///
/// Worth asking rather than assuming, because the realistic way this fails
/// is a full disk: setting the intent in memory still succeeds and only the
/// save does not. The intent is rolled back on failure so nothing is left
/// claiming a spend that never happened.
#[must_use]
pub(crate) fn stage_encrypt_intent(
    session: &mut SessionState,
    contact_name: &str,
    content: crate::client::otp_store::PendingOtpContent,
) -> bool {
    session.otp_store.set_encrypt_intent(contact_name, content);
    match session.otp_store.save() {
        Ok(()) => true,
        Err(e) => {
            crate::log_warn!(
                "could not record an OTP encrypt intent ({e}) - refusing the send rather \
                 than spending a pad position nothing could account for"
            );
            session.otp_store.clear_encrypt_intent(contact_name);
            false
        }
    }
}

/// One plaintext message held back because a genuine network ack for the/// One plaintext message held back because a genuine network ack for the
/// contact's previous OTP message hasn't arrived yet. Mirrors
/// `rekey::QueuedOutbound`'s shape/role, one layer up.
#[derive(Debug, Clone)]
pub enum PendingOtpSend {
    Direct {
        to: UserId,
        plaintext: Vec<u8>,
        content: Content,
        /// Carried through so the row a queued message was optimistically
        /// logged under can still be found and marked failed
        /// (`UiState::mark_dm_message_failed`) if the send fails once it's
        /// finally attempted, not just an immediate one. Always `None` for
        /// `Channel` - see `send_or_queue`'s doc for why channel sends are
        /// out of scope for this.
        log_index: Option<usize>,
        /// The delivery tag the eventual send must carry, so the row this
        /// message is already showing on turns green when the recipient
        /// acknowledges it (docs/PROTOCOL.md 7.2.1). `None` for anything
        /// that is not a text message - only those are tracked.
        msg_id: Option<u64>,
    },
    Channel {
        channel: String,
        to: UserId,
        plaintext: Vec<u8>,
        content: Content,
        /// See `Direct::msg_id`. A channel row is one row over many
        /// recipients, so every queued recipient of the same message
        /// carries the same tag.
        msg_id: Option<u64>,
    },
    /// An accepted file's content-phase encrypt, held back because the
    /// contact's gate was busy at `FileAccepted` time - `to` is carried
    /// only for symmetry with the other variants (unused by the drain,
    /// which re-derives everything it needs from `session.own_file_targets`
    /// via `stream_id`, since the entry - key included - is left in place
    /// rather than removed while queued).
    FileContent { stream_id: u64, to: UserId },
}

/// In-memory only, unlike `OtpStore` - losing a queued-but-unsent message
/// on reconnect/crash is an acceptable UX loss (the user can just resend),
/// not a correctness issue the way losing `pending_unacked_out_seq` would
/// be.
#[derive(Default)]
pub struct OtpOutQueue {
    queue: HashMap<String, VecDeque<PendingOtpSend>>,
}

impl OtpOutQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, contact_name: String, item: PendingOtpSend) {
        self.queue.entry(contact_name).or_default().push_back(item);
    }

    pub fn pop_front(&mut self, contact_name: &str) -> Option<PendingOtpSend> {
        self.queue.get_mut(contact_name)?.pop_front()
    }

    /// How many plaintext sends are held for `contact_name`.
    pub fn len_for(&self, contact_name: &str) -> usize {
        self.queue.get(contact_name).map(VecDeque::len).unwrap_or(0)
    }

    /// Whether `stream_id`'s content-phase encrypt is already queued for
    /// `contact_name` - checked before enqueueing another copy
    /// (`start_outgoing_file_content`'s doc): a resumed accept
    /// (`resume_pending_content_sends`) and a genuinely re-delivered
    /// `FileAccepted` for the very same stream can both reach the "gate is
    /// busy, queue it" branch once each, and without this, both would
    /// enqueue their own copy - the drain would then attempt this same
    /// content a second time once some *later*, unrelated ack freed the
    /// gate again.
    pub fn has_queued_stream(&self, contact_name: &str, stream_id: u64) -> bool {
        self.queue.get(contact_name).is_some_and(|q| {
            q.iter()
                .any(|item| matches!(item, PendingOtpSend::FileContent { stream_id: s, .. } if *s == stream_id))
        })
    }

    /// Drops every send still queued for `contact_name` - once `/endotp`
    /// (either side's) has run, the session they were waiting to go out
    /// under no longer exists, so there is nothing left to flush them
    /// into.
    pub fn clear(&mut self, contact_name: &str) {
        self.queue.remove(contact_name);
    }
}

/// `Some(contact_name)` iff OTP is usable for this peer right now: their
/// keychain contact has been marked provisioned in `session.otp_store`,
/// either by a completed handshake (`apply_incoming_setup`/the ack path) or
/// by `detect_or_adopt_existing` finding it already there.
///
/// Named exactly the way every other path names this pair
/// (`contact_name_for_peer`), which is what makes a pure-OTP session
/// usable: `/otp` will start one between two peers with no `pq_hybrid`
/// between them so long as both identities survive a reconnect
/// (`handle_otp_command`), and this is the lookup an ordinary send uses to
/// find it. Deriving the name here from `pq` fingerprints alone would have
/// left such a session reading as active while every message quietly went
/// out without the pad.
/// `contact_name_if_active` for a caller that holds only the `UserId` -
/// resolving the peer's key from `known_users` itself.
///
/// Used where a pad session's queue has to be pumped for whoever's link
/// just came up (`session::link_events`), which knows the peer but not
/// their keybundle.
pub fn active_contact_name(
    session: &SessionState,
    ui_state: &UiState,
    peer: UserId,
) -> Option<String> {
    let der = ui_state.known_users.get(&peer)?.public_key_der.clone();
    contact_name_if_active(session, peer, &der)
}

pub fn contact_name_if_active(session: &SessionState, peer: UserId, peer_pubkey_der: &[u8]) -> Option<String> {
    let contact_name = contact_name_for_peer(session, peer, peer_pubkey_der)?;
    session
        .otp_store
        .get(&contact_name)
        .filter(|s| s.provisioned)
        .map(|_| contact_name)
}

/// What every *new* outgoing send (text, a voice recording, a file, a
/// call's own eligibility) must check before riding the pad -
/// `contact_name_if_active` alone answers "is a pad provisioned for this
/// pair", not "should this specific send use it right now", and those two
/// stopped being the same question the moment `/endotp` could pause a
/// session without erasing its pad (`handle_end_otp_command`'s doc: kept
/// on purpose, so `/otp` later resumes the identical key). Using
/// `contact_name_if_active` alone here left every one of those four
/// things believing a paused session was still live forever afterward -
/// text/file/voice kept spending the paused pad, and `/call` stayed
/// refused - since nothing about pausing touches `provisioned`.
///
/// A `Direct`-framed (pad-only) pair is the one case where that shortcut
/// is still exactly right: with no `pq_hybrid` identity on either side
/// there is no plain channel to fall back to at all, so for that pair
/// provisioned and active are the same thing by construction - the pad
/// *is* the relationship (`register_pad_only_peer`'s own doc). Only a
/// `PqWrapped` pair - which has pq_hybrid to fall back to - needs the live
/// toggle (`UiState::is_otp_active`) consulted at all.
pub fn contact_name_for_sending(
    session: &SessionState,
    ui_state: &UiState,
    peer: UserId,
    peer_pubkey_der: &[u8],
) -> Option<String> {
    let contact_name = contact_name_if_active(session, peer, peer_pubkey_der)?;
    if framing_for(&session.otp_own_pinned_der, peer_pubkey_der) == OtpFraming::Direct {
        return Some(contact_name);
    }
    ui_state.is_otp_active(peer).then_some(contact_name)
}

/// Checks `otp --has-contact <contact_name>` when `/otp` runs - if a
/// keychain entry already exists (the user provisioned it themselves
/// out-of-band, or a previous session's handshake already completed), it's
/// adopted immediately and `handle_otp_command` skips straight to sending
/// an `OtpSessionRequest` rather than generating a fresh pad. The peer
/// still has to accept that request before either side shows "started" -
/// this only decides which of the two proposals to send, never skips the
/// mutual-consent round trip itself. Returns whether OTP is now usable for
/// this contact, either because it already was or because this call just
/// adopted it.
pub async fn detect_or_adopt_existing(
    cfg: &OtpCliConfig,
    store: &mut OtpStore,
    contact_name: &str,
) -> bool {
    if store
        .get(contact_name)
        .map(|s| s.provisioned)
        .unwrap_or(false)
    {
        return true;
    }
    match otp_cli::has_contact(cfg, contact_name).await {
        Ok(true) => {
            store.mark_provisioned(contact_name);
            let _ = store.save();
            true
        }
        _ => false,
    }
}

/// Wraps an already-built `pq_hybrid` blob (`Envelope.blocks[0]`) for the
/// wire: `otp -c <contact_name> --encrypt -y`. Always passes
/// `assume_delivered: true` - correct **by construction**, since every call
/// site only reaches this once it has verified there is no outstanding
/// unacked message for this contact (either genuinely the first message
/// ever, or a real `OtpDeliveryAck` just cleared the gate) - see
/// `direct_message`/`channel`'s send-path integration.
pub async fn wrap_outgoing(
    cfg: &OtpCliConfig,
    pq_blob: Vec<u8>,
    contact_name: &str,
) -> Option<(Vec<u8>, crypto::otp::AckProof)> {
    // A fresh nonce rides inside every message, under the pad, so that its
    // acknowledgement can be bound to *this* message rather than to a
    // sequence number anyone could quote back. The sender keeps only the
    // proof (`ack_proof_for`), which is all it needs to check the ack
    // against - see `crypto::otp::AckProof`.
    let nonce = crate::crypto::random_bytes(crypto::otp::ACK_NONCE_BYTES);
    let proof = crypto::otp::ack_proof_for(&nonce);
    let mut framed = nonce;
    framed.extend_from_slice(&pq_blob);
    match otp_cli::encrypt_retrying(cfg, contact_name, &framed, true).await {
        Ok(OtpCliOutcome::Ok(bytes)) => Some((bytes, proof)),
        _ => None,
    }
}

/// `unwrap_incoming`'s result, split so a caller can tell a message the
/// real `otp` binary actively refused - a replayed, reordered, foreign or
/// corrupted ciphertext, caught by its origin/order metadata check before
/// any key was spent (`otp_cli::OtpCliOutcome::Rejected`'s doc) - apart
/// from an ordinary failure, and say so.
#[derive(Debug)]
pub enum UnwrapOutcome {
    /// The recovered payload, and the proof to acknowledge it with - the
    /// hash of the nonce the sender buried inside it, which only a
    /// successful decrypt could reveal.
    Ok(Vec<u8>, crypto::otp::AckProof),
    /// `otp`'s own metadata validation refused this message; `reason` is
    /// its `stderr` explanation of which field(s) didn't match.
    Rejected(String),
    /// Anything else that kept the message from being read: the `otp`
    /// binary could not even be launched (moved, uninstalled, a bad
    /// `ALOO_OTP_BIN`/`otp_binary_path` setting - `io::Error::to_string()`),
    /// it exited with a generic error (`OtpCliOutcome::Error`'s doc - a
    /// missing contact, a full disk, a corrupt keychain, redelivery retries
    /// exhausted), or the decrypted bytes were too short to be a real
    /// message. Distinct from `Rejected`: that is `otp` itself, working
    /// correctly, refusing one specific message on its own metadata: this
    /// is every case where no such verdict was ever reached at all. Both
    /// are shown to the user (`finish_opening_otp_envelope`) - silently
    /// dropping this one used to be indistinguishable from the message
    /// simply never arriving.
    Failed(String),
}

/// Unwraps wire bytes back to the `pq_hybrid` blob: `otp -c <contact_name>
/// --decrypt -y`. Always passes `assume_delivered: true` - local delivery
/// is immediate and self-vouching (the plaintext either reaches the local
/// application right now or this call already failed), the asymmetric
/// counterpart of the encrypt side's genuine-remote-ack requirement.
pub async fn unwrap_incoming(
    cfg: &OtpCliConfig,
    wire_bytes: &[u8],
    contact_name: &str,
) -> UnwrapOutcome {
    match otp_cli::decrypt_retrying(cfg, contact_name, wire_bytes, true).await {
        Ok(OtpCliOutcome::Ok(bytes)) => {
            // Every message begins with the sender's ack nonce; anything
            // shorter than one cannot be a message this build produced.
            if bytes.len() < crypto::otp::ACK_NONCE_BYTES {
                return UnwrapOutcome::Failed(
                    "decrypted payload shorter than the ack nonce".to_string(),
                );
            }
            let (nonce, payload) = bytes.split_at(crypto::otp::ACK_NONCE_BYTES);
            UnwrapOutcome::Ok(payload.to_vec(), crypto::otp::ack_proof_for(nonce))
        }
        Ok(OtpCliOutcome::Rejected(reason)) => UnwrapOutcome::Rejected(reason),
        Ok(OtpCliOutcome::Error(reason)) => UnwrapOutcome::Failed(reason),
        Ok(OtpCliOutcome::Redelivered) => {
            // `decrypt_retrying` only ever returns this to its own caller
            // after resolving every `Redelivered` it saw internally into
            // something else (`MAX_REDELIVER_RETRIES`'s doc) - reachable
            // only if that contract changes underneath this.
            UnwrapOutcome::Failed("otp: unexpected redelivery marker".to_string())
        }
        Err(e) => UnwrapOutcome::Failed(e.to_string()),
    }
}

/// Best-effort overwrite-then-remove of a staging directory holding raw
/// one-time-pad key bytes that have already been consumed into `otp`'s own
/// keychain (or are about to be discarded because they never got that
/// far) - this material is the actual one-time secret, so it doesn't just
/// get `remove_dir_all`'d.
///
/// Delegates to `otp_staging`, whose overwrite streams a bounded buffer
/// rather than allocating one the size of the file - the difference
/// between erasing a 1TB pad and aborting the process trying to.
fn secure_remove_dir(dir: &Path) {
    crate::secure_fs::secure_remove_dir(dir);
}

/// Best-effort overwrite-then-remove of one temp content file created via
/// `temp_content_path` - the single-file counterpart of `secure_remove_dir`,
/// for the plaintext/ciphertext staging files file/voice-under-OTP pipes
/// through `otp --encrypt`/`--decrypt` on disk (never buffered whole in
/// memory - see `otp_cli::encrypt_file`/`decrypt_file`).
pub(crate) fn secure_remove_file(path: &Path) {
    crate::secure_fs::secure_remove_file(path);
}

/// A fresh, collision-free path under the OTP working directory for a
/// file/voice send's plaintext-in or ciphertext-out staging file. Distinct
/// from the keychain-provisioning staging dirs (`initiate_provisioning`'s
/// `_a_keys`/`_b_keys`, `apply_incoming_setup`'s `_incoming`) - those hold
/// raw pad bytes, this holds one message's content - so it's a sibling
/// path, not shared, and gets `secure_remove_file`'d independently.
pub(crate) fn temp_content_path(cfg: &OtpCliConfig, label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    cfg.working_dir
        .join(format!("{label}-{}-{nanos}", std::process::id()))
}

use crate::secure_fs::{restrict_dir_permissions, restrict_file_permissions};

/// Where a generated-but-not-yet-accepted pad waits. Both halves live here
/// - this side's own and the peer's - until the peer actually accepts, at
/// which point `commit_pending_setup` moves this side's half into the
/// keychain and the directory is securely removed.
///
/// Nothing is written to the keychain before that point, which is what stops
/// a failed invitation from poisoning the next one: a pad the peer never
/// took is not a contact, so `/otp` afterwards finds no entry and simply
/// generates a fresh one (`detect_or_adopt_existing`). It also keeps the
/// peer's half re-readable, so a retry resends the *same* pad rather than
/// generating a second one under the same contact name - two different pads
/// under one name have no integrity check to tell them apart and would
/// decode to silent garbage.
pub fn pending_setup_dir(cfg: &OtpCliConfig, contact_name: &str) -> std::path::PathBuf {
    cfg.working_dir.join(format!("{contact_name}_pending"))
}

/// The four files `pending_setup_dir` holds, by role.
fn pending_paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    (
        dir.join("own_encryption.key"),
        dir.join("own_decryption.key"),
        dir.join("peer_encryption.key"),
        dir.join("peer_decryption.key"),
    )
}

/// Runs the initiating side of the PqHybrid-channel OTP handshake (plan
/// step 1-4): generates a fresh keypair, stages *both* halves under
/// `pending_setup_dir` without touching the keychain, and returns the
/// payload to send the peer over their existing `pq_hybrid` channel - the
/// *other* role's key files, respecting the role-inversion the `otp` CLI's
/// own key generation performs (README: "the roles are inverted between the
/// two parties" - what one party calls its encryption key, the other calls
/// its decryption key). Only ever called in response to an explicit user
/// "Enable OTP" action, never automatically.
///
/// This side's own half is deliberately *not* added to the keychain here.
/// Adding it would leave an invitation that never arrived holding one half
/// of a pad the peer knows nothing about - and since `add_contact` refuses
/// to overwrite, every later attempt under the same (fingerprint-derived,
/// therefore identical) contact name would hit that stale entry instead of
/// fixing anything. See `commit_pending_setup`.
pub async fn initiate_provisioning(
    cfg: &OtpCliConfig,
    size_mb: u32,
    own_fp: &[u8; 32],
    own_device_id: &str,
    peer_fp: &[u8; 32],
    peer_device_id: &str,
    purpose: crypto::otp::OtpPurpose,
) -> Option<crypto::otp::OtpKeySetupPayload> {
    initiate_provisioning_with_progress(
        cfg,
        size_mb,
        own_fp,
        own_device_id,
        peer_fp,
        peer_device_id,
        purpose,
        |_, _| {},
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .await
}

/// `initiate_provisioning`, reporting generation progress as it goes -
/// what `confirm_generate`'s background task drives the spinner popup
/// from. Only the `otp --new-key-pair` step reports: it is the one that
/// scales with `size_mb`, and so the only one worth watching.
#[allow(clippy::too_many_arguments)]
pub async fn initiate_provisioning_with_progress(
    cfg: &OtpCliConfig,
    size_mb: u32,
    own_fp: &[u8; 32],
    own_device_id: &str,
    peer_fp: &[u8; 32],
    peer_device_id: &str,
    purpose: crypto::otp::OtpPurpose,
    on_progress: impl FnMut(u64, u64),
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<crypto::otp::OtpKeySetupPayload> {
    // The one line this whole function exists to get right: a fresh mail
    // key must never be staged (and therefore never later installed or
    // streamed) under the *live* session's contact name, even though every
    // other step here - generation, staging, digesting - has no idea
    // purpose exists at all.
    let contact_name = match purpose {
        crypto::otp::OtpPurpose::Live => {
            crypto::otp::contact_name_for(own_fp, own_device_id, peer_fp, peer_device_id)
        }
        crypto::otp::OtpPurpose::Mail => {
            crypto::otp::contact_name_for_mail(own_fp, own_device_id, peer_fp, peer_device_id)
        }
    };
    let name_a = format!("{contact_name}_a");
    let name_b = format!("{contact_name}_b");

    // Everything below happens inside `.tmp/`, and only a completed pad is
    // renamed out of it - so a crash, a kill or a power cut anywhere in
    // here leaves nothing that any later run could mistake for a usable
    // pad (`client::otp_staging`'s module doc). Generation itself is
    // pointed at the staging directory by giving `otp` a working dir of
    // its own: `--new-key-pair` writes `<name>_keys/` relative to wherever
    // it runs, and those raw halves must not land next to the real
    // keychain.
    let staging = crate::client::otp_staging::new_dir(cfg, "gen").ok()?;
    let gen_cfg = OtpCliConfig {
        binary_path: cfg.binary_path.clone(),
        working_dir: staging.clone(),
    };
    let generated = otp_cli::new_key_pair_with_progress(
        &gen_cfg,
        size_mb,
        &name_a,
        &name_b,
        on_progress,
        cancelled,
    )
    .await;
    if generated.is_err() {
        crate::client::otp_staging::secure_remove_dir(&staging);
        return None;
    }

    let dir_a = staging.join(format!("{name_a}_keys"));
    let dir_b = staging.join(format!("{name_b}_keys"));
    let staged = stage_pending_setup(
        cfg,
        &staging,
        &contact_name,
        &dir_a.join(format!("encryption_for_{name_b}.key")),
        &dir_a.join(format!("decryption_from_{name_b}.key")),
        &dir_b.join(format!("encryption_for_{name_a}.key")),
        &dir_b.join(format!("decryption_from_{name_a}.key")),
    );
    crate::client::otp_staging::secure_remove_dir(&staging);
    staged?;

    read_pending_setup(cfg, &contact_name, size_mb)
}

/// Gathers a freshly generated pad's four key files under canonical names
/// and publishes them as this contact's pending setup in one atomic step,
/// so nothing downstream has to know the `otp` CLI's role-suffixed naming,
/// and - more importantly - so `<contact>_pending/` is only ever observed
/// absent or complete, never half-populated. A reader that caught it
/// mid-assembly would send a truncated pad, which is precisely the
/// half-a-key hazard staging exists to rule out.
///
/// The four files are *renamed* into place rather than copied: they are
/// already inside `staging`, on the same filesystem as their destination,
/// so this neither duplicates the bytes on disk nor spends time
/// proportional to a pad that may be a terabyte.
///
/// `None` if any part of it fails, in which case the caller removes the
/// staging directory and reports failure rather than sending half a pad.
fn stage_pending_setup(
    cfg: &OtpCliConfig,
    staging: &Path,
    contact_name: &str,
    own_enc: &Path,
    own_dec: &Path,
    peer_enc: &Path,
    peer_dec: &Path,
) -> Option<()> {
    // Assembled under `staging` (still inside `.tmp/`, still garbage if
    // interrupted), then promoted as a whole directory.
    let assembled = staging.join("ready");
    std::fs::create_dir_all(&assembled).ok()?;
    restrict_dir_permissions(&assembled);
    let (own_enc_to, own_dec_to, peer_enc_to, peer_dec_to) = pending_paths(&assembled);
    for (from, to) in [
        (own_enc, &own_enc_to),
        (own_dec, &own_dec_to),
        (peer_enc, &peer_enc_to),
        (peer_dec, &peer_dec_to),
    ] {
        std::fs::rename(from, to).ok()?;
        restrict_file_permissions(to);
    }
    // A pad already staged for this contact is a previous attempt that was
    // never accepted; `promote` securely removes it before renaming, so
    // the four files always describe one single generation.
    crate::client::otp_staging::promote(&assembled, &pending_setup_dir(cfg, contact_name)).ok()
}

/// Reads the peer's half back out of the pending directory as a sendable
/// payload - once when the pad is first generated, and again for every
/// retry, so a resend is always byte-identical to the original.
pub fn read_pending_setup(
    cfg: &OtpCliConfig,
    contact_name: &str,
    size_mb: u32,
) -> Option<crypto::otp::OtpKeySetupPayload> {
    let (_, _, peer_enc, peer_dec) = pending_paths(&pending_setup_dir(cfg, contact_name));
    Some(crypto::otp::OtpKeySetupPayload {
        contact_name: contact_name.to_string(),
        keypair_size_mb: size_mb,
        peer_encryption_key: std::fs::read(&peer_enc).ok()?,
        peer_decryption_key: std::fs::read(&peer_dec).ok()?,
    })
}

/// The peer accepted: this side's own half finally becomes a keychain
/// contact, and the staged pad is securely removed. Returns whether the
/// keychain entry is now genuinely usable - a `false` here means the pad is
/// lost on this side and the pair must start over, which is why it is
/// reported rather than assumed.
pub async fn commit_pending_setup(cfg: &OtpCliConfig, contact_name: &str) -> bool {
    let dir = pending_setup_dir(cfg, contact_name);
    let (own_enc, own_dec, _, _) = pending_paths(&dir);
    let committed = if own_enc.exists() && own_dec.exists() {
        // A contact under this name may already exist - a previous pad
        // being replaced (`/new-otp-mail-key` always proposes a fresh one
        // even over an existing key, and a live pair can reach the same
        // shape if one side deleted its own copy and re-ran `/otp`) - and
        // `otp --add-contact` refuses to overwrite one outright. Best
        // effort: a name that never held a contact simply has nothing to
        // remove, and any other removal failure only leaves `add_contact`
        // to fail exactly as it already would have.
        let _ = otp_cli::remove_contact(cfg, contact_name).await;
        otp_cli::add_contact(cfg, contact_name, &own_enc, &own_dec)
            .await
            .is_ok()
    } else {
        // Nothing staged: either this side adopted an existing keychain
        // entry rather than generating one (`detect_or_adopt_existing`), or
        // a previous ack already committed it. Both mean the contact should
        // already be there, which `has_contact` decides honestly.
        otp_cli::has_contact(cfg, contact_name)
            .await
            .unwrap_or(false)
    };
    secure_remove_dir(&dir);
    committed
}

/// The invitation is over without the pad ever being adopted - refused,
/// cancelled, or given up on. Removes the staged pad; there is deliberately
/// nothing to undo in the keychain, since nothing was written there.
pub fn discard_pending_setup(cfg: &OtpCliConfig, contact_name: &str) {
    secure_remove_dir(&pending_setup_dir(cfg, contact_name));
}

/// Runs the receiving side of the handshake (plan step 5-6): stages the
/// received key bytes under `.tmp/` just long enough for `otp
/// --add-contact` to consume them, then securely removes the staging
/// directory regardless of outcome.
///
/// Staged inside `.tmp/` rather than beside the keychain so that an
/// interruption anywhere here - between writing the two halves, or during
/// `--add-contact` itself - leaves nothing a later run could pick up and
/// install (`client::otp_staging`'s module doc). The contact only becomes
/// real through `--add-contact`, which is reached exactly once both halves
/// are fully written.
pub async fn apply_incoming_setup(
    cfg: &OtpCliConfig,
    payload: &crypto::otp::OtpKeySetupPayload,
) -> crypto::otp::OtpKeySetupAckPayload {
    let ack = |accepted: bool, reason: Option<String>| crypto::otp::OtpKeySetupAckPayload {
        contact_name: payload.contact_name.clone(),
        accepted,
        reason,
    };
    let staging_dir = match crate::client::otp_staging::new_dir(cfg, "incoming") {
        Ok(dir) => dir,
        Err(e) => return ack(false, Some(format!("staging directory: {e}"))),
    };

    let enc_path = staging_dir.join("encryption_for_peer.key");
    let dec_path = staging_dir.join("decryption_from_peer.key");
    let stage_result = std::fs::write(&enc_path, &payload.peer_encryption_key)
        .and_then(|_| std::fs::write(&dec_path, &payload.peer_decryption_key));
    if let Err(e) = stage_result {
        secure_remove_dir(&staging_dir);
        return ack(false, Some(format!("staging key files: {e}")));
    }
    restrict_file_permissions(&enc_path);
    restrict_file_permissions(&dec_path);

    let add_result = otp_cli::add_contact(cfg, &payload.contact_name, &enc_path, &dec_path).await;
    secure_remove_dir(&staging_dir);
    match add_result {
        Ok(()) => ack(true, None),
        Err(e) => ack(false, Some(e.to_string())),
    }
}

/// Formats the current moment for the "OTP session started at ..." notice:
/// this machine's local wall-clock time when it can be determined safely,
/// else UTC labeled as such. `OffsetDateTime::now_local` can legitimately
/// fail (the `time` crate refuses to read the platform timezone from a
/// process it can't prove is single-threaded, which this async app never
/// is) - that's an expected, not exceptional, outcome here.
pub fn format_now() -> String {
    use time::format_description::well_known::Rfc3339;
    match time::OffsetDateTime::now_local() {
        Ok(dt) => dt
            .replace_nanosecond(0)
            .unwrap_or(dt)
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown time".to_string()),
        Err(_) => {
            let dt = time::OffsetDateTime::now_utc();
            let formatted = dt
                .replace_nanosecond(0)
                .unwrap_or(dt)
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown time".to_string());
            format!("{formatted} (UTC)")
        }
    }
}

/// The `/otp` command's handler (`UiAction::RequestOtpSession`, the one and
/// only trigger for a session - never automatic). Every path through here
/// ends in an explicit accept/reject by **both** sides before anything is
/// considered active - see the module doc.
///
/// Shared with `/new-otp-mail-key` (`UiAction::RequestOtpMailKey`) via
/// `purpose` - the two commands run the identical consent/generate/transfer
/// machinery, differing only in which keychain contact name it ends up
/// naming (`crypto::otp::contact_name_for_peer`/`_mail`) and how it labels
/// itself to the user (`OtpPurpose::label`).
///
/// - No local keychain entry yet: opens `ui_state.otp_generate_confirm`, a
///   local Yes/No decision (`confirm_generate`/`cancel_generate` handle the
///   answer) - generating and sharing a fresh pad is never done without
///   this confirmation.
/// - An entry already exists: skips straight to sending an
///   `OtpSessionRequest` (no key material) - the peer still has to accept
///   it (`on_session_request`/the invite popup) before either side shows
///   "started", so a stale or one-sided local entry can never be silently
///   assumed to still work.
///
/// **Concurrency**: most of the state this drives is keyed by keychain
/// contact name, which is already purpose-distinct, so a live and a mail
/// handshake with two *different* peers never interfere. But a handful of
/// in-flight-transfer bookkeeping (`otp_incoming_setup`/`otp_incoming_pads`/
/// `otp_outgoing_pads`, and the invite queue) is keyed by peer alone, so a
/// live and a mail handshake to the *same* peer at the same time would
/// collide. Rather than threading purpose through all of that too, a second
/// handshake (of either purpose) is simply refused while one is already
/// outstanding with that peer.
pub async fn handle_provisioning_command(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    peer_pubkey_der: Vec<u8>,
    purpose: crypto::otp::OtpPurpose,
) -> proto::Result<()> {
    let peer_name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let label = purpose.label();

    if session.otp_incoming_setup.contains_key(&peer)
        || session.otp_incoming_pads.contains_key(&peer)
        || session.otp_outgoing_pads.contains_key(&peer)
        || ui_state.has_otp_invite_from(peer)
    {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!("a key exchange with {peer_name} is already in progress"),
            false,
        );
        return Ok(());
    }

    // A live session already active with this peer has nothing left for a
    // second `/otp` to negotiate - and re-running it anyway risks exactly
    // the desync this once produced: re-provisioning or re-confirming a
    // session that both sides already agree is running, right as the two
    // sides' own bookkeeping is what could disagree about that (a
    // reconnect mid-flight, a lost ack). `/endotp` is the only way to
    // leave this state, same as it is the only way to enter a fresh
    // negotiation afterward. Mail has no such state to conflict with - it
    // is never "active" the way a session is, only ever usable or not
    // (`otp_mail::check_recipient`) - so this never applies to it.
    if purpose == crypto::otp::OtpPurpose::Live && ui_state.is_otp_active(peer) {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!("an OTP session with {peer_name} is already active - use /endotp first"),
            false,
        );
        return Ok(());
    }

    // Asked before the contact is named, not after: without the tool
    // nothing here can work whatever the pairing looks like, so that is
    // the refusal worth showing. Naming first meant a peer whose device is
    // not bound yet was told its identity was unreadable while the real
    // and only obstacle was a missing binary.
    if !otp_cli::binary_available(&session.otp_cli_cfg) {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!(
                "{label} failed: the 'otp' command isn't installed - see github.com/DavidValin/otp-toolkit"
            ),
            false,
        );
        return Ok(());
    }

    let contact_name = match purpose {
        crypto::otp::OtpPurpose::Live => contact_name_for_peer(session, peer, &peer_pubkey_der),
        crypto::otp::OtpPurpose::Mail => contact_name_for_peer_mail(session, peer, &peer_pubkey_der),
    };
    let Some(contact_name) = contact_name else {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!("{label} failed: could not read this peer's identity"),
            false,
        );
        return Ok(());
    };

    // A `/endotp` notice still owed to this peer is a statement about the
    // session the user is now reopening - and the two contradict each
    // other. Left in place it would be re-sent on the next link
    // transition (`resend_pending_end_notices`) and tear down the very
    // session being started here, on both sides. Asking again is the newer
    // intent, so the older debt is dropped.
    //
    // Only reachable at all because `/endotp` now *pauses* rather than
    // destroying: the pad survives it, so a reopen and an unacknowledged
    // end notice can genuinely coexist for the same contact.
    if session.otp_store.clear_end_notice(&contact_name) {
        let _ = session.otp_store.save();
    }

    let already_have_key =
        detect_or_adopt_existing(&session.otp_cli_cfg, &mut session.otp_store, &contact_name).await;

    // Unlike `/otp`, which legitimately resumes an already-provisioned
    // contact (that round trip is what turns the *session* back on after
    // `/endotp`, over the identical pad), `/new-otp-mail-key` always means
    // "get me a fresh one" - resuming isn't a thing it can mean at all,
    // since mail has no session to resume in the first place, only a key
    // that is either usable or isn't (`check_recipient` at compose time).
    // So `already_have_key` never gates Mail's branch below the way it
    // gates Live's: Mail always takes the fresh-generate path, and the
    // commit step (`commit_pending_setup`/`on_pad_commit`) replaces
    // whatever was there before rather than refusing to touch it.
    let resuming = purpose == crypto::otp::OtpPurpose::Live && already_have_key;

    // Under `Direct` framing there is no channel to share a freshly
    // generated pad over - the handshake that carries one is itself an
    // ordinary `pq_hybrid` send, and this peer announced no bundle to seal
    // it to (a `--no-server` direct-punch peer, `docs/PROTOCOL.md` §7.1.5).
    // A pad *already* installed on both sides needs no such channel for
    // `/otp` to resume it, though - so this refuses only the
    // generate-and-share path. Mail can never resume (above), so for Mail
    // this refuses unconditionally: a pad-only pair's mail key can only
    // ever be replaced by installing a fresh one manually from /contacts,
    // the same as it was first provisioned.
    if framing_for(&session.otp_own_pinned_der, &peer_pubkey_der) == OtpFraming::Direct && !resuming {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!(
                "{label} failed: this peer announced no pq_hybrid identity, so a pad cannot be \
                 shared over the network - generate one with 'otp --new-key-pair' and install it \
                 on both sides from /contacts (o)"
            ),
            false,
        );
        return Ok(());
    }

    // Under `Direct` there is no envelope to carry a session request, and
    // none is wanted: both sides already hold the pad, so there is nothing
    // left to agree. `/otp` turns it on locally and the first message goes
    // straight under the pad - the peer's own `otp --decrypt` is what
    // accepts it, and their acknowledgement (§16.2) is the only consent a
    // pad-only pair can express or needs to. Only ever reached for Live
    // (`resuming` implies `purpose == Live`) - Mail already returned above.
    if framing_for(&session.otp_own_pinned_der, &peer_pubkey_der) == OtpFraming::Direct {
        ui_state.mark_otp_active(peer);
        refresh_otp_key_status(&session.otp_cli_cfg, ui_state, peer, &contact_name).await;
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session started (pad-only pair - every message to them now rides the pad)"
                .to_string(),
            true,
        );
        return Ok(());
    }

    if resuming {
        let payload = crypto::otp::OtpSessionRequestPayload {
            contact_name: contact_name.clone(),
            // A resume asks for no new pad, so there is no size to weigh.
            pad_size_mb: None,
        };
        let Ok(plaintext) = proto::encode(&payload) else {
            notify(
                ui_state,
                peer,
                &peer_name,
                format!("{label} failed: could not encode the session request"),
                false,
            );
            return Ok(());
        };
        let send_id = session.next_stream_id;
        session.next_stream_id += 1;
        let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
            &session.own_pq_private,
            session.pq_peer_keys.encap_for(peer),
            &peer_pubkey_der,
            None,
            send_id,
            &plaintext,
            Content::OtpSessionRequest,
        ) else {
            notify(
                ui_state,
                peer,
                &peer_name,
                format!("{label} failed: could not encrypt the session request"),
                false,
            );
            return Ok(());
        };
        let readiness = session.peer_link.ensure_link(wr, peer).await;
        session.peer_link.send_reliable_or_queue(
            peer,
            P2pPayload::Envelope {
                channel: None,
                // Provisioning traffic, not a message anybody sees - there
                // is no row for a receipt to land on (7.2.1).
                msg_id: None,
                envelope,
            },
        );
        // "Started" isn't shown yet either way - only on_key_setup_ack
        // shows that, once the peer has genuinely accepted - but the send
        // itself (or its lack) is now always visible.
        notify(
            ui_state,
            peer,
            &peer_name,
            link_readiness_notice(readiness, &peer_name, purpose),
            true,
        );
    } else {
        // An invitation already owed to this contact is a *previous*
        // attempt: one whose pad never arrived, was never answered, or was
        // superseded by the peer's own. It must never stand in the way of
        // asking again - a user who types `/otp` after nothing happened is
        // asking to start over, and leaving the old debt in place would
        // both keep re-offering a pad the peer may never have seen and
        // make the fresh one collide with it under the same (derived,
        // therefore identical) contact name. Dropped here, before anything
        // new is generated, so a retry is always a clean start. Nothing in
        // the keychain is touched: this only ever clears a pad that was
        // staged and never adopted.
        if session
            .otp_store
            .get(&contact_name)
            .is_some_and(|c| c.pending_setup_size_mb.is_some())
        {
            discard_pending_setup(&session.otp_cli_cfg, &contact_name);
            session.otp_store.clear_pending_setup(&contact_name);
            let _ = session.otp_store.save();
        }
        // Likewise an invitation from *them* still sitting unanswered on
        // this side: answering it and proposing our own at the same time
        // would leave two live proposals for one contact name. The fresh
        // `/otp` the user just asked for is the one that stands.
        session.otp_incoming_setup.remove(&peer);
        ui_state.take_otp_invite_from(peer);

        ui_state.open_otp_generate_confirm(peer, peer_name, peer_pubkey_der, purpose);
        // A decision popup just opened - chime, like every popup that
        // asks the user for an action does (the file-offer precedent).
        crate::client::voice_stream::play_bell_chime(session);
    }
    Ok(())
}

/// `UiAction::ConfirmOtpGenerate`'s handler: the user said yes to "generate
/// a pad and share it over pq_hybrid" (`ui_state.otp_generate_confirm`) and
/// then chose `size_mb` (MB per key) in the prompt that followed
/// (`ui_state.otp_size_input`).
///
/// Validates the size, then hands the generation itself to a background
/// task and returns immediately - nothing is sent from here. The task
/// reports through `SessionState::otp_keygen_tx`, and `on_keygen_event`
/// resumes the handshake once the pad exists: keeping this side's own
/// working half and sending the peer's - along with the size, so the
/// deciding side can see what it's agreeing to before it answers
/// (`PendingOtpInvite::pad_size_mb`) - as `Content::OtpKeySetup`. Still
/// does not become active on this side either, until the peer answers with
/// `OtpKeySetupAck{accepted: true}` (`on_key_setup_ack`).
///
/// Takes no `ControlSink`, unlike its sibling handlers: by the time
/// anything needs sending, this call has long returned.
/// Sends one `Content::OtpSessionRequest` and reports whether it got as far
/// as the link. Shared by the resume path and by the fresh-pad path, which
/// differ only in whether a `pad_size_mb` rides along.
#[allow(clippy::too_many_arguments)]
async fn send_session_request(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    peer_name: &str,
    peer_pubkey_der: &[u8],
    contact_name: &str,
    pad_size_mb: Option<u32>,
) -> bool {
    let purpose = crypto::otp::OtpPurpose::of_contact_name(contact_name);
    let label = purpose.label();
    let payload = crypto::otp::OtpSessionRequestPayload {
        contact_name: contact_name.to_string(),
        pad_size_mb,
    };
    let Ok(plaintext) = proto::encode(&payload) else {
        notify(
            ui_state,
            peer,
            peer_name,
            format!("{label} failed: could not encode the session request"),
            false,
        );
        return false;
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(peer),
        peer_pubkey_der,
        None,
        send_id,
        &plaintext,
        Content::OtpSessionRequest,
    ) else {
        notify(
            ui_state,
            peer,
            peer_name,
            format!("{label} failed: could not encrypt the session request"),
            false,
        );
        return false;
    };
    let readiness = session.peer_link.ensure_link(wr, peer).await;
    session.peer_link.send_reliable_or_queue(
        peer,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope,
        },
    );
    notify(
        ui_state,
        peer,
        peer_name,
        link_readiness_notice(readiness, peer_name, purpose),
        true,
    );
    true
}

/// `pub` (not `pub(crate)`): `test/otp_pad_glare_test.rs` drives this
/// directly, on both sides of a simulated pair, to produce the two real
/// `OtpSessionRequest` envelopes a genuine glare needs - the same reason
/// `on_session_request` is `pub` too.
pub async fn confirm_generate(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    size_mb: u32,
) -> proto::Result<()> {
    let Some(pending) = ui_state.take_otp_size_input() else {
        return Ok(());
    };
    // Defensive: the size popup already only ever submits a validated
    // value, but this is the actual point real pad material and a real
    // subprocess call get committed to it, so it's re-checked here too
    // rather than trusted blindly from the action.
    if !crypto::otp::otp_size_mb_in_range(size_mb) {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            format!(
                "OTP session failed: pad size must be between {} and {} MB",
                crypto::otp::OTP_SIZE_MB_MIN,
                crypto::otp::OTP_SIZE_MB_MAX
            ),
            false,
        );
        return Ok(());
    }
    let own_fp = session.own_pq_fp;
    let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(&pending.pubkey_der) else {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            "OTP session failed: could not read this peer's identity".to_string(),
            false,
        );
        return Ok(());
    };
    // A fresh pad's name is device-qualified (device-pinning plan §4), so
    // both device_ids must be known before generation can even be named -
    // their device_id arrives via `DeviceIdAnnounce`, which requires the
    // same `Active` link this whole handshake already does, so this is
    // normally already resolved by the time a user can reach this popup.
    let Some(peer_device_id) = session.peer_device_ids.get(&pending.peer).cloned() else {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            "OTP session failed: this peer's device is not known yet - try again in a moment"
                .to_string(),
            false,
        );
        return Ok(());
    };

    // Refused before generation, not after. `otp --new-key-pair` writes
    // four files of `size_mb` each (both halves into both correspondents'
    // directories), so a pad needs four times its per-key size on disk -
    // and a disk that cannot hold it fails somewhere inside the tool, after
    // the wait, with whatever partial state that leaves behind. Checking
    // costs one syscall.
    let needed = otp_cli::keygen_disk_bytes(size_mb);
    if let Some(free) = otp_cli::free_space_bytes(&session.otp_cli_cfg.working_dir)
        && free < needed
    {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            format!(
                "OTP session failed: {size_mb}MB per key needs {} of free disk to generate \
                 (the pad tool writes both halves into both key directories), and only {} \
                 is available. Choose a smaller size, or free some space.",
                human_bytes(needed),
                human_bytes(free)
            ),
            false,
        );
        return Ok(());
    }

    // Generation runs off the event loop, reporting progress back through
    // `otp_keygen_tx` - `on_keygen_event` picks it up and resumes the
    // handshake once it finishes. Inline, this call blocks every other
    // thing the session does (no redraw, no incoming message, no keypress)
    // for as long as it takes to read `2 * size_mb` MB of true randomness -
    // which at the sizes now allowed is minutes, indistinguishable from a
    // hang. The spinner popup opened here is what the user watches
    // meanwhile.
    // Asked before anything is generated, not after the pad arrives.
    //
    // The peer is the one who pays for this - minutes of transfer and
    // several gigabytes of disk - and the size is the only part of it they
    // can weigh. Asking once the pad is already on their machine is asking
    // when refusing saves nobody anything. It also stops this side
    // spending the same cost on a pad that is about to be declined.
    let contact_name = crypto::otp::contact_name_for(&own_fp, &session.own_device_id, &peer_fp, &peer_device_id);
    if !send_session_request(
        wr,
        session,
        ui_state,
        pending.peer,
        &pending.peer_name,
        &pending.pubkey_der,
        &contact_name,
        Some(size_mb),
    )
    .await
    {
        return Ok(());
    }
    session
        .otp_awaiting_consent
        .insert(contact_name, (pending, size_mb));
    Ok(())
}

/// Starts the generation this side promised once the peer has agreed to it
/// (`on_key_setup_ack`) - everything `confirm_generate` used to do inline
/// before the consent step was put in front of it.
pub(crate) async fn begin_promised_generation(
    session: &mut SessionState,
    ui_state: &mut UiState,
    pending: PendingOtpGenerate,
    size_mb: u32,
) {
    let own_fp = session.own_pq_fp;
    let own_device_id = session.own_device_id.clone();
    let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(&pending.pubkey_der) else {
        return;
    };
    let Some(peer_device_id) = session.peer_device_ids.get(&pending.peer).cloned() else {
        return;
    };
    ui_state.open_otp_keygen(pending.peer, pending.peer_name.clone(), size_mb, pending.purpose);
    let cfg = session.otp_cli_cfg.clone();
    let tx = session.otp_keygen_tx.clone();
    // One flag per peer, shared with the transfer worker that follows, so
    // Escape reaches whichever phase happens to be running.
    let cancelled = session
        .otp_cancelled
        .entry(pending.peer)
        .or_insert_with(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .clone();
    cancelled.store(false, std::sync::atomic::Ordering::Relaxed);
    tokio::spawn(async move {
        let progress_tx = tx.clone();
        let payload = initiate_provisioning_with_progress(
            &cfg,
            size_mb,
            &own_fp,
            &own_device_id,
            &peer_fp,
            &peer_device_id,
            pending.purpose,
            move |written, total| {
                let _ = progress_tx.send(OtpKeygenEvent::Progress {
                    written_bytes: written,
                    total_bytes: total,
                });
            },
            cancelled,
        )
        .await;
        let _ = tx.send(OtpKeygenEvent::Finished {
            pending: Box::new(pending),
            size_mb,
            payload: payload.map(Box::new),
        });
    });
}

/// What a background pad generation reports back to the session loop -
/// see `SessionState::otp_keygen_tx`.
pub enum OtpKeygenEvent {
    /// One chunk of randomness handed to `otp --new-key-pair`; moves the
    /// spinner popup's bar.
    Progress {
        written_bytes: u64,
        total_bytes: u64,
    },
    /// Generation is over. `payload` is `None` if it failed - `otp` refused,
    /// the disk filled, the binary vanished mid-run. Boxed because the
    /// payload carries a whole pad's worth of key bytes and this enum is
    /// otherwise tiny (clippy's `large_enum_variant`), and because keeping
    /// it behind one pointer means moving the event around never copies it.
    Finished {
        pending: Box<PendingOtpGenerate>,
        size_mb: u32,
        payload: Option<Box<crypto::otp::OtpKeySetupPayload>>,
    },
}

/// Applies one `OtpKeygenEvent` - the session loop's `otp_keygen_rx` arm.
/// On `Finished`, this is where the provisioning handshake `confirm_generate`
/// started actually resumes: the pad exists on disk now, so the debt is
/// recorded and the peer's half goes out.
pub(crate) async fn on_keygen_event(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    event: OtpKeygenEvent,
) -> proto::Result<()> {
    match event {
        OtpKeygenEvent::Progress {
            written_bytes,
            total_bytes,
        } => {
            ui_state.set_otp_keygen_progress(written_bytes, total_bytes);
            Ok(())
        }
        OtpKeygenEvent::Finished {
            pending,
            size_mb,
            payload,
        } => {
            ui_state.close_otp_keygen();
            let Some(payload) = payload else {
                notify(
                    ui_state,
                    pending.peer,
                    &pending.peer_name,
                    "OTP session failed: could not generate a keypair".to_string(),
                    false,
                );
                return Ok(());
            };
            // Recorded before the first chunk goes out, not after: if
            // delivery fails, the debt is what makes the retry pass pick it
            // up again, and a debt recorded only on success would be
            // exactly the case that never gets retried.
            session
                .otp_store
                .mark_setup_pending(&payload.contact_name, size_mb);
            let _ = session.otp_store.save();
            start_pad_send(
                wr,
                session,
                ui_state,
                pending.peer,
                &pending.peer_name,
                &pending.pubkey_der,
                &payload.contact_name,
                size_mb,
            )
            .await;
            Ok(())
        }
    }
}

/// One key's raw bytes sent per `OtpKeySetupChunk`. `pq_hybrid`'s own
/// per-send overhead (an ML-KEM ciphertext, an RSA ciphertext and two
/// signatures - several KB, constant regardless of content size) plus
/// bincode/ARQ framing must still fit alongside two chunks this size
/// inside one UDP datagram (~65KB hard ceiling, no fragmentation below
/// this layer) - 16KB leaves generous headroom.
pub const OTP_SETUP_CHUNK_BYTES: usize = 16 * 1024;

/// Roughly how many bytes per second a pad transfer sustains over a
/// hole-punched link, used only to *warn* about how long a large one will
/// take (`transfer_estimate`) - never to refuse a size.
///
/// There used to be a hard ceiling here (`PENDING_MAX * OTP_SETUP_CHUNK_BYTES`,
/// which worked out at 16MB per key). It existed because the pad was handed
/// to the link as one burst, so one that could not fit the queue whole had
/// its front dropped and arrived unreassemblable. That transport is gone:
/// `client::otp_pad` streams the pad from disk, pacing itself against the
/// link's own drain rate (`PAD_INFLIGHT_FRAMES`), so no size can overflow
/// anything any more and the ceiling outlived its reason. What remains is
/// not a correctness limit but a patience one, and that is the user's call
/// to make rather than ours.
///
/// The figure is deliberately pessimistic - the reliable layer's window
/// (`p2p_reliable::SEND_WINDOW`) makes throughput a function of round-trip
/// time, so a distant peer is slower than a nearby one and this estimates
/// for the distant case.
const PAD_TRANSFER_BYTES_PER_SEC: u64 = 400 * 1024;

/// How long `size_mb` per key is expected to take to cross the link, as
/// something to show a user before they commit to generating it.
///
/// Both halves cross, not one: the peer needs the half they encrypt with
/// *and* the half they decrypt with (`otp_pad::spawn_send_pad_worker` sends
/// `[enc_path, dec_path]` back to back), so the transfer is twice the
/// per-key size.
pub fn transfer_estimate(size_mb: u32) -> std::time::Duration {
    let bytes = 2 * u64::from(size_mb) * 1024 * 1024;
    std::time::Duration::from_secs(bytes.div_ceil(PAD_TRANSFER_BYTES_PER_SEC))
}

/// A byte count as something to put in a sentence - "8.0 GB", "512 MB".
/// Binary units, since that is what the sizes here are chosen in.
fn human_bytes(bytes: u64) -> String {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{} MB", bytes / MB)
    }
}

/// `transfer_estimate` as something to put in a prompt - "about 20s",
/// "about 4m", "about 3h". Coarse on purpose: the underlying figure is a
/// guess about someone else's network, and a precise-looking one would
/// claim more than it knows.
pub fn transfer_estimate_text(size_mb: u32) -> String {
    let secs = transfer_estimate(size_mb).as_secs();
    if secs < 60 {
        format!("about {secs}s")
    } else if secs < 3600 {
        format!("about {}m", secs.div_ceil(60))
    } else {
        format!("about {}h", secs.div_ceil(3600))
    }
}

/// Reports what happened to a just-queued OTP setup/session-request send:
/// `Active` means it genuinely went out on the wire right now, `Pending`
/// means it's held in the link's own queue until punching finishes - not
/// lost, but not sent yet either, and previously indistinguishable from
/// nothing having happened at all.
fn link_readiness_notice(
    readiness: crate::client::p2p::LinkReadiness,
    peer_name: &str,
    purpose: crypto::otp::OtpPurpose,
) -> String {
    let label = purpose.label();
    match readiness {
        crate::client::p2p::LinkReadiness::Active => {
            format!("{label}: setup sent to {peer_name}, waiting for their confirmation...")
        }
        crate::client::p2p::LinkReadiness::Pending => format!(
            "{label}: still establishing a direct connection to {peer_name} - will send as soon as it's up"
        ),
    }
}

/// `UiAction::CancelOtpGenerate`'s handler: the user said no. Nothing was
/// ever sent, so this is purely local.
pub(crate) fn cancel_generate(ui_state: &mut UiState) {
    // Reachable from either step: Reject on the first popup
    // (`otp_generate_confirm`), or Escape out of the size prompt that
    // follows it (`otp_size_input`) - at most one is ever actually open.
    let pending = ui_state
        .take_otp_generate_confirm()
        .or_else(|| ui_state.take_otp_size_input());
    let Some(pending) = pending else {
        return;
    };
    notify(
        ui_state,
        pending.peer,
        &pending.peer_name,
        "OTP session cancelled".to_string(),
        false,
    );
}

/// Applies an incoming `Content::OtpKeySetup` envelope
/// (`direct_message::on_message`'s content-dispatch): decrypts it via the
/// ordinary `pq_hybrid` path (this message *is* the provisioning
/// handshake, so it is never itself OTP-wrapped), decodes it as one
/// `OtpKeySetupChunk`, and accumulates it into `session.otp_incoming_setup`
/// (`crypto::otp::OtpKeySetupReassembly`'s doc explains why a whole pad has
/// to arrive as many chunks rather than one envelope). Only once the last
/// chunk lands
/// does this stage the reassembled key material as an incoming invitation
/// for the user to accept or reject (`ui_state.push_otp_invite`) - **nothing
/// is written to the keychain and no reply is sent yet**. See
/// `accept_invite`/`reject_invite`.
pub(crate) fn on_key_setup(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    sender: &UserInfo,
    envelope: Envelope,
) {
    let Some(plaintext) =
        crate::client::session::decrypt_own_envelope(&envelope, from, sender, None, session)
    else {
        // Said out loud rather than dropped: silently, a genuinely
        // lost or corrupted setup message and one that never arrived at
        // all look identical, and the difference between "nothing
        // arrived" and "something arrived but could not be opened" is
        // the whole of what a user can act on here.
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP: received a setup message from {from_name} but could not decrypt it"),
            false,
        );
        return;
    };
    // The decrypted bytes here are this chunk's actual pad material - an
    // ordinary `Vec<u8>` the moment `decrypt_own_envelope` returns it (that
    // path is shared with every other content type, most of which carry
    // nothing secret enough to warrant this). Wrapped immediately so it
    // doesn't just get freed unzeroized once decoded below.
    let plaintext = zeroize::Zeroizing::new(plaintext);
    let Ok(chunk) = proto::decode::<crypto::otp::OtpKeySetupChunk>(&plaintext) else {
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP: received a setup message from {from_name} but could not decode it"),
            false,
        );
        return;
    };

    let partial = session
        .otp_incoming_setup
        .entry(from)
        .or_insert_with(|| crypto::otp::OtpKeySetupReassembly::new(&chunk));
    if !partial.accept(&chunk) {
        // Doesn't continue what we had accumulated for this sender (e.g. a
        // stale, abandoned attempt) - start over from this chunk instead of
        // ever reassembling mismatched bytes into a "complete" payload.
        let mut fresh = crypto::otp::OtpKeySetupReassembly::new(&chunk);
        if !fresh.accept(&chunk) {
            session.otp_incoming_setup.remove(&from);
            // A chunk that isn't the start of a pad, with nothing
            // accumulated for it to continue: the chunks before it never
            // arrived. Reassembly cannot recover from that - say so in the
            // terms that let the sender act on it, rather than blaming the
            // one message that did arrive.
            notify(
                ui_state,
                from,
                &from_name,
                format!(
                    "OTP: the setup from {from_name} arrived incomplete (its first part is                      missing) - ask them to run /otp again"
                ),
                false,
            );
            return;
        }
        session.otp_incoming_setup.insert(from, fresh);
        return;
    }
    if !partial.is_complete() {
        return;
    }
    let Some(mut partial) = session.otp_incoming_setup.remove(&from) else {
        return;
    };
    // `chunk` implements `Drop` (it zeroizes its own key bytes on the way
    // out), so its name can only be cloned out, not moved.
    let contact_name = chunk.contact_name.clone();

    // A pad that arrives when this contact is already in the keychain is a
    // re-delivery, not a new invitation: the first copy landed and was
    // applied, and only the acknowledgement was lost, so the sender is
    // retrying. Asking the user to decide again would be asking about a
    // decision they already made - and answering "yes" would fail anyway,
    // since `add_contact` refuses to overwrite. Re-acknowledged instead, so
    // the sender can finally commit its own half and stop retrying.
    //
    // Checked before the keys are taken out of `partial`, so the duplicate
    // pad is wiped by that reassembly's own zeroize-on-drop rather than
    // surviving as the two plain `Vec`s `take_keys` hands back (only
    // `PendingOtpInvite`, which this branch never builds, zeroizes those).
    if session
        .otp_store
        .get(&contact_name)
        .is_some_and(|c| c.provisioned)
    {
        queue_key_setup_ack(session, ui_state, from, &contact_name, true, None);
        return;
    }

    // Simultaneous invitations: this pad arrived while one of our own for the
    // same contact is still owed, so both sides generated before either
    // answered. Exactly one may survive (`own_pad_wins_glare`).
    if session
        .otp_store
        .get(&contact_name)
        .is_some_and(|c| c.pending_setup_size_mb.is_some())
    {
        let own_fp = session.own_pq_fp;
        if let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(&sender.public_key_der) {
            if own_pad_wins_glare(&own_fp, &peer_fp) {
                // Ours wins: refuse theirs so they drop it, and let our own
                // invitation - already on its way to them - be the one they
                // answer. Refused before `take_keys`, so their pad is wiped
                // by the reassembly's own zeroize-on-drop.
                queue_key_setup_ack(
                    session,
                    ui_state,
                    from,
                    &contact_name,
                    false,
                    Some(GLARE_REASON.to_string()),
                );
                return;
            }
            // Theirs wins: drop ours before showing their invitation, so
            // accepting it cannot later collide with our own half, and
            // nothing re-offers a pad we have just conceded.
            discard_pending_setup(&session.otp_cli_cfg, &contact_name);
            session.otp_store.clear_pending_setup(&contact_name);
            let _ = session.otp_store.save();
        }
    }

    let (enc, dec) = partial.take_keys();
    // `partial`'s fields are zeroized on drop right here, now that the key
    // bytes it held have been moved out into `enc`/`dec` above.

    ui_state.push_otp_invite(
        from,
        from_name.clone(),
        contact_name,
        Some(enc),
        Some(dec),
        Some(chunk.keypair_size_mb),
    );
    // Same chime every decision popup plays on arrival.
    crate::client::voice_stream::play_bell_chime(session);
    notify(
        ui_state,
        from,
        &from_name,
        format!("OTP: {from_name} wants to start a session - see the popup"),
        true,
    );
}

/// Applies an incoming `Content::OtpSessionRequest` envelope - the
/// "already have a key" branch's counterpart to `on_key_setup`: stages an
/// invitation carrying no key material, since the receiving side is
/// expected to already have a matching keychain contact (verified only if
/// the user actually accepts - see `accept_invite`).
///
/// `pub` (not `pub(crate)`) so `test/otp_pad_glare_test.rs` can drive a
/// real, independently-generated request straight at this function,
/// exercising the glare check against a genuinely encrypted envelope
/// rather than a hand-built payload.
pub fn on_session_request(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    from_name: String,
    sender: &UserInfo,
    envelope: Envelope,
) {
    let Some(plaintext) =
        crate::client::session::decrypt_own_envelope(&envelope, from, sender, None, session)
    else {
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP: received a session request from {from_name} but could not decrypt it"),
            false,
        );
        return;
    };
    let Ok(payload) = proto::decode::<crypto::otp::OtpSessionRequestPayload>(&plaintext) else {
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP: received a session request from {from_name} but could not decode it"),
            false,
        );
        return;
    };
    // Glare: this side *also* proposed a fresh pad to the same contact and
    // is waiting on its own answer (`confirm_generate`'s `otp_awaiting_consent`
    // insert) - both users ran `/otp` with each other before either request
    // arrived. Resolved here, before either side has generated or streamed
    // a single byte, the same way the small-key path's `on_key_setup_chunk`
    // already resolves it for a pad small enough to send inline
    // (`own_pad_wins_glare`'s own doc: the numerically smaller fingerprint
    // wins, both sides compare the same two values and so reach the same
    // answer with no round trip to negotiate it). A resume request
    // (`pad_size_mb: None`) never reaches here: adopting the same
    // already-installed pad twice is a no-op on both sides, so there is
    // nothing to resolve.
    if payload.pad_size_mb.is_some()
        && session.otp_awaiting_consent.contains_key(&payload.contact_name)
    {
        let own_fp = session.own_pq_fp;
        if let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(&sender.public_key_der) {
            if own_pad_wins_glare(&own_fp, &peer_fp) {
                // Ours wins: refuse theirs outright, before it ever becomes
                // a decision popup - our own proposal, already on its way
                // to them, is the one they will answer instead.
                queue_key_setup_ack(
                    session,
                    ui_state,
                    from,
                    &payload.contact_name,
                    false,
                    Some(GLARE_REASON.to_string()),
                );
                notify(
                    ui_state,
                    from,
                    &from_name,
                    format!(
                        "OTP: {from_name} proposed a session at the same moment - keeping our \
                         own proposal"
                    ),
                    true,
                );
                return;
            }
            // Theirs wins: our own proposal is withdrawn - nothing was ever
            // generated for it (that only starts once an acceptance comes
            // back, `on_key_setup_ack`), so there is nothing on disk to
            // discard, only this in-memory record of having asked. Falls
            // through to show their invitation exactly as it would have
            // without any glare at all.
            session.otp_awaiting_consent.remove(&payload.contact_name);
        }
    }
    ui_state.push_otp_invite(
        from,
        from_name.clone(),
        payload.contact_name,
        None,
        None,
        payload.pad_size_mb,
    );
    // Same chime every decision popup plays on arrival.
    crate::client::voice_stream::play_bell_chime(session);
    notify(
        ui_state,
        from,
        &from_name,
        match payload.pad_size_mb {
            Some(mb) => format!(
                "OTP: {from_name} wants to start a session with a {mb}MB pad - see the popup"
            ),
            None => format!("OTP: {from_name} wants to resume a session - see the popup"),
        },
        true,
    );
}

async fn send_key_setup_ack(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &UiState,
    to: UserId,
    contact_name: &str,
    accepted: bool,
    reason: Option<String>,
) {
    session.peer_link.ensure_link(wr, to).await;
    queue_key_setup_ack(session, ui_state, to, contact_name, accepted, reason);
}

/// `send_key_setup_ack` without the `ensure_link` signalling round trip, for
/// the one caller that cannot signal: an ack sent straight back at a peer
/// whose setup message just arrived over the link. The link is by definition
/// already there in that case - their chunks came in on it - so signalling
/// would only re-propose a link that is up, and `send_reliable_or_queue`
/// covers the remaining case of one that has since dropped.
fn queue_key_setup_ack(
    session: &mut SessionState,
    ui_state: &UiState,
    to: UserId,
    contact_name: &str,
    accepted: bool,
    reason: Option<String>,
) {
    let Some(sender) = ui_state.known_users.get(&to).cloned() else {
        return;
    };
    let ack = crypto::otp::OtpKeySetupAckPayload {
        contact_name: contact_name.to_string(),
        accepted,
        reason,
    };
    let Ok(ack_plaintext) = proto::encode(&ack) else {
        return;
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(ack_envelope) = crate::client::envelope::encrypt_envelope_for(
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(to),
        &sender.public_key_der,
        None,
        send_id,
        &ack_plaintext,
        Content::OtpKeySetupAck,
    ) else {
        return;
    };
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope: ack_envelope,
        },
    );
}

/// `UiAction::AcceptOtpInvite`'s handler: applies whichever invitation is
/// currently shown (`ui_state.otp_invite_open`), replies with
/// `OtpKeySetupAck`, and shows the same green "started" notice
/// `on_key_setup_ack` shows the initiator, on success - "both parties
/// should be aware" holds symmetrically, not just for the side that asked.
/// Distinguishes "I was asked to resume a session but genuinely have no
/// matching keychain entry" from every other rejection reason -
/// `accept_invite` reports it verbatim in the ack it sends back, and
/// `on_key_setup_ack` matches on this exact string to tell an otherwise
/// ordinary cancellation apart from the one case that's actually
/// recoverable without the user starting over from scratch. See its doc.
const NO_MATCHING_KEY_REASON: &str = "no matching key found on my end";

/// Refusal reason for the losing half of a simultaneous invitation - see
/// `own_pad_wins_glare`. Distinct from `NO_MATCHING_KEY_REASON` because it
/// means the opposite thing: not "I have nothing", but "we both generated,
/// and mine is the one to keep".
const GLARE_REASON: &str = "we both proposed at once - keeping the other pad";

/// Which side's pad survives when both users press `/otp` before either has
/// answered. Both sides generate a pad for the *same* contact name (it is
/// derived from the pair's fingerprints), and only one of them can ever be
/// adopted: two different pads under one name have no integrity check to
/// tell them apart, so a pair that adopted one each would encrypt to silent
/// garbage.
///
/// Resolved the way simultaneous link opens already are (§7.1, the
/// numerically smaller `link_nonce` wins): the smaller fingerprint's pad
/// wins. Both sides compare the same two values and therefore reach the same
/// answer without exchanging anything - there is no round trip here to
/// negotiate with, since each side has already sent its pad by the time it
/// learns of the other's.
pub fn own_pad_wins_glare(own_fp: &[u8; 32], peer_fp: &[u8; 32]) -> bool {
    own_fp < peer_fp
}

/// What every point a provisioning handshake can converge from -
/// `accept_invite`, `on_key_setup_ack`, `on_pad_verify`, `on_pad_commit` -
/// does once the key is genuinely usable on this side: derives `purpose`
/// from `contact_name` (never trusted from anywhere else, since these are
/// the four functions that just finished writing the keychain entry that
/// name points at) and only marks the *live* session active - `is_otp_active`,
/// the DM's 🔑 tag, the key-status header - for `OtpPurpose::Live`. Mail has
/// no "active" toggle at all: it just checks the key exists
/// (`otp_mail::check_recipient`) whenever a mail is composed, so marking it
/// active here would do nothing for `/mail` but would wrongly route every
/// *ordinary* DM to this peer through the mail pad instead of `pq_hybrid` -
/// exactly the bug this function exists to prevent.
async fn finish_provisioning(
    cfg: &OtpCliConfig,
    ui_state: &mut UiState,
    peer: UserId,
    peer_name: &str,
    contact_name: &str,
) {
    let purpose = crypto::otp::OtpPurpose::of_contact_name(contact_name);
    let label = purpose.label();
    match purpose {
        crypto::otp::OtpPurpose::Live => {
            ui_state.open_otp_session(peer);
            refresh_otp_key_status(cfg, ui_state, peer, contact_name).await;
            notify(
                ui_state,
                peer,
                peer_name,
                format!("{label} started at {}", format_now()),
                true,
            );
        }
        crypto::otp::OtpPurpose::Mail => {
            notify(
                ui_state,
                peer,
                peer_name,
                format!("{label} ready - mail to {peer_name} now uses it"),
                true,
            );
        }
    }
}

pub(crate) async fn accept_invite(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(invite) = ui_state.take_otp_invite() else {
        return Ok(());
    };
    // A streamed pad (`client::otp_pad`) is already reassembled and
    // verified on disk by the time this popup appears - accepting it does
    // *not* install it. It reports back what was received, and only the
    // sender's matching commit authorises the install: neither side may
    // hold a pad the other does not (see `otp_pad`'s two-phase commit).
    if let Some(pad) = session.otp_incoming_pads.get(&invite.from)
        && pad.contact_name == invite.contact_name
    {
        let (enc_digest, dec_digest) = (pad.enc_digest, pad.dec_digest);
        let contact_name = pad.contact_name.clone();
        // Our own staged pad, if any, is retired here: only one pad can
        // ever live under this name, and we have just agreed to theirs.
        discard_pending_setup(&session.otp_cli_cfg, &contact_name);
        session.otp_store.clear_pending_setup(&contact_name);
        let _ = session.otp_store.save();
        send_pad_verify(
            session,
            invite.from,
            &contact_name,
            true,
            enc_digest,
            dec_digest,
        );
        return Ok(());
    }
    // Agreeing to a *fresh* pad the peer has not generated yet. There is
    // no key to look for and nothing to install - only an answer to send,
    // which is what lets them start. Recorded so the pad's later arrival
    // needs no second decision: this was the decision.
    if invite.peer_encryption_key.is_none() && invite.pad_size_mb.is_some() {
        session.otp_consented.insert(invite.contact_name.clone());
        send_key_setup_ack(
            wr,
            session,
            ui_state,
            invite.from,
            &invite.contact_name,
            true,
            None,
        )
        .await;
        notify(
            ui_state,
            invite.from,
            &invite.from_name,
            format!(
                "OTP: agreed - {} is generating the pad and will send it",
                invite.from_name
            ),
            true,
        );
        return Ok(());
    }

    let result: Result<(), String> =
        match (&invite.peer_encryption_key, &invite.peer_decryption_key) {
            (Some(enc), Some(dec)) => {
                let payload = crypto::otp::OtpKeySetupPayload {
                    contact_name: invite.contact_name.clone(),
                    keypair_size_mb: 0,
                    peer_encryption_key: enc.clone(),
                    peer_decryption_key: dec.clone(),
                };
                let ack = apply_incoming_setup(&session.otp_cli_cfg, &payload).await;
                if ack.accepted {
                    Ok(())
                } else {
                    Err(ack
                        .reason
                        .unwrap_or_else(|| "add-contact failed".to_string()))
                }
            }
            _ => match otp_cli::has_contact(&session.otp_cli_cfg, &invite.contact_name).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(NO_MATCHING_KEY_REASON.to_string()),
                Err(e) => Err(e.to_string()),
            },
        };

    let (accepted, reason) = match &result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e.clone())),
    };
    if accepted {
        // Adopting the peer's pad retires any pad of our own still staged for
        // this contact: only one can ever live under this name, and the one
        // just written to the keychain is it. Without this, our own would be
        // re-offered later and its commit would collide with what we just
        // adopted.
        discard_pending_setup(&session.otp_cli_cfg, &invite.contact_name);
        session.otp_store.clear_pending_setup(&invite.contact_name);
        session.otp_store.mark_provisioned(&invite.contact_name);
        // Agreeing to a session settles any `/endotp` notice this side was
        // still owed to send for the same contact - the mirror of
        // `handle_otp_command`'s own cancellation, for the case where *we*
        // ended it and the peer is the one reopening. Without this, the
        // stale notice goes out on the next link transition and tears down
        // the session just agreed to.
        session.otp_store.clear_end_notice(&invite.contact_name);
        let _ = session.otp_store.save();
    }
    send_key_setup_ack(
        wr,
        session,
        ui_state,
        invite.from,
        &invite.contact_name,
        accepted,
        reason.clone(),
    )
    .await;

    if accepted {
        finish_provisioning(
            &session.otp_cli_cfg,
            ui_state,
            invite.from,
            &invite.from_name,
            &invite.contact_name,
        )
        .await;
    } else {
        notify(
            ui_state,
            invite.from,
            &invite.from_name,
            format!("OTP session failed: {}", reason.unwrap_or_default()),
            false,
        );
    }
    Ok(())
}

/// `UiAction::RejectOtpInvite`'s handler: tells the peer no, and shows the
/// same "cancelled" notice locally that a declined local generate-confirm
/// does.
pub(crate) async fn reject_invite(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(invite) = ui_state.take_otp_invite() else {
        return Ok(());
    };
    // A streamed pad's refusal is reported the same way its acceptance is,
    // and the staging directory goes with it - nothing was installed on
    // either side, and the sender drops its own half on hearing this.
    if let Some(pad) = session.otp_incoming_pads.remove(&invite.from)
        && pad.contact_name == invite.contact_name
    {
        let (enc_digest, dec_digest) = (pad.enc_digest, pad.dec_digest);
        crate::client::otp_staging::secure_remove_dir(&pad.dir);
        send_pad_verify(
            session,
            invite.from,
            &invite.contact_name,
            false,
            enc_digest,
            dec_digest,
        );
        return Ok(());
    }
    // A keyless invitation is the sender saying "you already have this pad".
    // If this side doesn't, the sender's belief is simply wrong, and it must
    // hear *that* rather than a plain refusal - otherwise it keeps its stale
    // entry and every later `/otp` proposes the same impossible resume
    // forever. Reported on reject exactly as on accept: which button the
    // user pressed says nothing about whether the key exists, and pressing
    // "no" to an invitation you have no key for is the natural answer.
    let reason = match (&invite.peer_encryption_key, &invite.peer_decryption_key) {
        (Some(_), Some(_)) => None,
        _ => match otp_cli::has_contact(&session.otp_cli_cfg, &invite.contact_name).await {
            Ok(false) => Some(NO_MATCHING_KEY_REASON.to_string()),
            _ => None,
        },
    };
    send_key_setup_ack(
        wr,
        session,
        ui_state,
        invite.from,
        &invite.contact_name,
        false,
        reason,
    )
    .await;
    notify(
        ui_state,
        invite.from,
        &invite.from_name,
        "OTP session cancelled".to_string(),
        false,
    );
    Ok(())
}

/// Applies an incoming `Content::OtpKeySetupAck` (`direct_message::on_message`'s
/// content-dispatch) - the initiating side's half of the mutual-consent
/// handshake: only now, once the peer has genuinely accepted, does this
/// side mark itself provisioned and show "OTP session started".
///
/// A rejection carrying `NO_MATCHING_KEY_REASON` is different from an
/// ordinary cancellation: it means this side's own belief that a shared
/// pad already exists (`detect_or_adopt_existing`'s "already have a key"
/// branch in `handle_otp_command`) was wrong - the peer genuinely has
/// nothing on their end, and a plain `OtpSessionRequest` retry would only
/// hit the exact same wall forever, since it never carries key material to
/// fix that. Recovering means clearing the stale local entry (it isn't
/// usable half of a pad if the other half doesn't exist) and offering the
/// normal "generate and share a fresh one" confirmation again, the same
/// popup a first-ever `/otp` would have shown.
///
/// `pub` (not `pub(crate)`) so `test/otp_pad_glare_test.rs` can drive the
/// losing side's own receipt of its glare refusal directly.
pub async fn on_key_setup_ack(
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    sender: &UserInfo,
    envelope: Envelope,
) {
    let Some(plaintext) =
        crate::client::session::decrypt_own_envelope(&envelope, from, sender, None, session)
    else {
        return;
    };
    let Ok(ack) = proto::decode::<crypto::otp::OtpKeySetupAckPayload>(&plaintext) else {
        return;
    };
    if ack.accepted
        && let Some((pending, size_mb)) = session.otp_awaiting_consent.remove(&ack.contact_name)
    {
        // They agreed to a pad that does not exist yet - this is the point
        // it starts being made. Nothing has been generated or sent for this
        // contact, so there is no pending setup to commit below.
        begin_promised_generation(session, ui_state, pending, size_mb).await;
        return;
    }
    if ack.accepted {
        // The peer has the pad, so this side finally adopts its own half -
        // the first and only moment anything is written to the keychain for
        // this contact (`commit_pending_setup`).
        if !commit_pending_setup(&session.otp_cli_cfg, &ack.contact_name).await {
            session.otp_store.clear_pending_setup(&ack.contact_name);
            // Only tears down the local record if there is no usable contact
            // to protect. A commit can also fail because one is already
            // there - an acceptance arriving for a pad we have since
            // conceded - and forgetting *that* would break a session that
            // works, on both sides asymmetrically.
            if !otp_cli::has_contact(&session.otp_cli_cfg, &ack.contact_name)
                .await
                .unwrap_or(false)
            {
                session.otp_store.forget(&ack.contact_name);
            }
            let _ = session.otp_store.save();
            notify(
                ui_state,
                from,
                &sender.name,
                "OTP session failed: could not store this side's half of the pad - run /otp again"
                    .to_string(),
                false,
            );
            crate::client::session::daemon_otp_outcome(
                ui_state,
                session,
                from,
                false,
                "This side could not store its half of the pad.",
            );
            return;
        }
        session.otp_store.clear_pending_setup(&ack.contact_name);
        session.otp_store.mark_provisioned(&ack.contact_name);
        let _ = session.otp_store.save();
        finish_provisioning(&session.otp_cli_cfg, ui_state, from, &sender.name, &ack.contact_name)
            .await;
        crate::client::session::daemon_otp_outcome(ui_state, session, from, true, "");
    } else if ack.reason.as_deref() == Some(NO_MATCHING_KEY_REASON) {
        let _ = otp_cli::remove_contact(&session.otp_cli_cfg, &ack.contact_name).await;
        discard_pending_setup(&session.otp_cli_cfg, &ack.contact_name);
        session.otp_store.forget(&ack.contact_name);
        let _ = session.otp_store.save();
        ui_state.open_otp_generate_confirm(
            from,
            sender.name.clone(),
            sender.public_key_der.clone(),
            crypto::otp::OtpPurpose::of_contact_name(&ack.contact_name),
        );
        // Same chime every decision popup plays on arrival.
        crate::client::voice_stream::play_bell_chime(session);
        notify(
            ui_state,
            from,
            &sender.name,
            format!(
                "OTP: {} doesn't have a matching key after all - generate and share a fresh one?",
                sender.name
            ),
            true,
        );
    } else {
        // A refusal ends the invitation: the staged pad is dropped and the
        // debt cleared, so nothing retries it and - since the keychain was
        // never written - the next `/otp` from either side starts cleanly
        // with a freshly generated pad rather than meeting a stale entry.
        // A still-open proposal (`otp_awaiting_consent` - this side asked
        // to generate a fresh pad and hadn't heard back yet, most notably
        // the losing half of a glare resolution, `on_session_request`'s own
        // check) is withdrawn the same way: a refusal answers it either
        // way, so nothing is left waiting on a reply that already arrived,
        // just refusing something else.
        discard_pending_setup(&session.otp_cli_cfg, &ack.contact_name);
        session.otp_store.clear_pending_setup(&ack.contact_name);
        session.otp_awaiting_consent.remove(&ack.contact_name);
        let _ = session.otp_store.save();
        let reason = ack.reason.map(|r| format!(": {r}")).unwrap_or_default();
        notify(
            ui_state,
            from,
            &sender.name,
            format!("OTP session cancelled{reason}"),
            false,
        );
        crate::client::session::daemon_otp_outcome(
            ui_state,
            session,
            from,
            false,
            "They declined the session.",
        );
    }
}

// ---------------------------------------------------------------------
// Ending a session: /endotp (docs/PROTOCOL.md §16.6)
// ---------------------------------------------------------------------

/// What `/endotp` should do for one contact, decided *before*
/// `OtpStore::pause_session` clears anything - mirrors
/// `client::otp_mail::MailGate`'s shape: a small, pure decision kept
/// separate from `handle_end_otp_command` so it's directly testable without
/// a live `SessionState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndOtpDecision {
    /// No provisioned contact for this peer at all - nothing to end.
    NoActiveSession,
    /// A mail send is still awaiting this contact's pad gate
    /// (`PendingOtpContent::Mail`) - pausing now would clear that gate's
    /// bookkeeping (`OtpStore::pause_session`), so a late `OtpMailResult`
    /// arriving afterward would have nothing to reconcile against
    /// (`client::otp_mail::on_mail_result`'s `record_acked` call would
    /// simply find nothing pending), leaving the contact's pad-gate state
    /// out of step with what's actually still in flight to the server.
    MailInFlight,
    /// Safe to pause and notify.
    End,
}

/// The decision behind `handle_end_otp_command`'s early guards - see
/// `EndOtpDecision`'s doc for what each outcome protects.
pub fn decide_end_otp(state: Option<&crate::client::otp_store::OtpContactState>) -> EndOtpDecision {
    let Some(state) = state else {
        return EndOtpDecision::NoActiveSession;
    };
    if !state.provisioned {
        return EndOtpDecision::NoActiveSession;
    }
    if matches!(
        state.pending_content,
        Some(crate::client::otp_store::PendingOtpContent::Mail { .. })
    ) {
        return EndOtpDecision::MailInFlight;
    }
    EndOtpDecision::End
}

/// The `/endotp` command's handler (`UiAction::EndOtpSession`) - the one and
/// only way an OTP session ends (pauses) deliberately. Unlike starting one,
/// ending is unilateral: either participant may do it alone, with no round
/// trip to agree first. The pad itself, and the real keychain entry behind
/// it, are deliberately left alone - `/endotp` no longer calls
/// `otp_cli::remove_contact` - so what actually stops this side from
/// spending it again is every send-path gate no longer seeing this contact
/// as active (`ui_state.clear_otp_active`), the same "no double key pad
/// spending" property `send_or_queue`'s gate protects while the session is
/// live, now enforced by "OTP isn't attempted for this contact at all"
/// rather than "there is no pad left". The peer is *told*, not asked;
/// converges to the same paused state the moment `on_end_session` processes
/// the notice, whether that is seconds or days from now
/// (`resend_pending_end_notices`). A later `/otp` for the same contact
/// resumes the identical pad - see `OtpStore::pause_session`'s doc.
///
/// Refuses outright (a local-only notice, nothing torn down or sent) if
/// there is no active session with this peer, or if a mail send is still
/// awaiting the pad's stop-and-wait gate for this exact contact
/// (`PendingOtpContent::Mail`) - see `EndOtpDecision::MailInFlight`'s doc
/// for why pausing mid-mail is refused rather than allowed. Every other
/// pending send (a live P2P text/file/voice spend) has no second store
/// depending on that gate surviving, so it does not block ending.
pub async fn handle_end_otp_command(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    peer_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    let peer_name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let Some(contact_name) = contact_name_for_peer(session, peer, &peer_pubkey_der) else {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP: no active session with this user".to_string(),
            false,
        );
        return Ok(());
    };
    match decide_end_otp(session.otp_store.get(&contact_name)) {
        EndOtpDecision::NoActiveSession => {
            notify(
                ui_state,
                peer,
                &peer_name,
                "OTP: no active session with this user".to_string(),
                false,
            );
            return Ok(());
        }
        EndOtpDecision::MailInFlight => {
            notify(
                ui_state,
                peer,
                &peer_name,
                "OTP: a mail to this contact is still being delivered - try /endotp again shortly"
                    .to_string(),
                false,
            );
            return Ok(());
        }
        EndOtpDecision::End => {}
    }

    // An end handshake already in flight has nothing left for a second
    // `/endotp` to do - re-running the send step would spend a second range
    // of the pad on a duplicate notice, widening exactly the offset gap the
    // retry machinery exists to prevent.
    if session
        .otp_store
        .get(&contact_name)
        .is_some_and(|s| s.pending_end_notice)
    {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!("OTP: already ending - waiting for {peer_name} to confirm"),
            false,
        );
        return Ok(());
    }
    // Ending is a synchronised, two-party operation over an *active*
    // session - a contact that is merely provisioned (paused, or adopted
    // and never started) has nothing running to end.
    if !ui_state.is_otp_active(peer) {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP: no active session with this user".to_string(),
            false,
        );
        return Ok(());
    }
    // Both sides must be reachable right now: the end takes effect only
    // when the peer's proof-carrying acknowledgement of the notice
    // arrives, so the two sides leave the session together, in sync -
    // never one paused while the other unknowingly keeps spending the pad
    // at it. Checked against the *direct link*, not only `ui_state.offline`
    // (`ServerMessage::UserOffline`, gated behind `HEARTBEAT_TIMEOUT` - up
    // to 30s of a peer looking reachable after they are actually gone):
    // that lag is exactly wide enough for a human to run `/endotp` inside
    // it, still spending the pad against someone who cannot currently
    // receive or acknowledge it. Neither signal alone is fast enough on its
    // own (the link's own idle detection lags further still,
    // `p2p::LINK_IDLE_TIMEOUT`), so both are checked and either refuses.
    // This narrows the race; it cannot close it outright - only the
    // protocol-level durability (deferred/recovered notice, no local
    // effect before the peer's ack) makes a spend that slips through this
    // guard anyway still safe rather than merely less likely.
    if ui_state.offline.contains(&peer)
        || ui_state.link_status_of(peer) != crate::client::p2p::LinkStatus::Active
    {
        notify(
            ui_state,
            peer,
            &peer_name,
            format!(
                "OTP: {peer_name} is offline - /endotp needs both sides online so the end \
                 is confirmed on both; try again when they are back"
            ),
            false,
        );
        return Ok(());
    }

    // Two-phase from here (docs/PROTOCOL.md §16.6): nothing is paused or
    // torn down yet. The end is *requested* - durably, so a crash or link
    // drop mid-handshake still finishes it on reconnect - and this side
    // stays fully in the session until the peer's acknowledgement lands
    // (`on_delivery_ack`'s confirmation is the single point both sides'
    // ends become effective). New sends meanwhile are refused
    // (`send_or_queue`), never silently rerouted.
    session.otp_store.mark_end_requested(&contact_name);
    let _ = session.otp_store.save();
    notify(
        ui_state,
        peer,
        &peer_name,
        format!("OTP: ending session - waiting for {peer_name} to confirm"),
        true,
    );

    let gate_armed = session
        .otp_store
        .get(&contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
    if !gate_armed {
        send_end_notice_now(wr, session, peer, &peer_pubkey_der, &contact_name).await;
    }
    // else: deferred. An in-flight spend is still awaiting the peer's
    // acknowledgement - encrypting the notice now would overwrite that
    // message's only recover-last safety copy *and* leapfrog it on the pad;
    // if the peer never received it, they could then never decrypt the
    // notice (or anything else) again. The message stays recoverable
    // (`recover_and_resend`), the end request was recorded durably above,
    // and the moment the in-flight spend's genuine ack arrives - now or on
    // any later reconnect - `on_delivery_ack` sends this notice as the
    // gate's next occupant.
    Ok(())
}

/// Encrypts and sends the `/endotp` notice as the ordinary stop-and-wait
/// send it now is (`PendingOtpContent::EndNotice`): the pad goes on it, the
/// seal (where the pair has one) goes around the pad, `record_sent` arms
/// the gate behind it, and the peer's proof-carrying `OtpDeliveryAck` is
/// what clears it - at which point `on_delivery_ack` also clears
/// `pending_end_notice`, ending the durable retry. Until that ack arrives,
/// `recover_and_resend` retries the exact recorded ciphertext on every
/// reconnect, like any other unacknowledged spend - never a second encrypt.
///
/// Callers must only reach this with the gate clear (the same
/// reserve-after-genuinely-spent contract `send_now` has): the notice
/// deferred behind an in-flight message is `handle_end_otp_command`'s and
/// `on_delivery_ack`'s job to sequence, not this function's.
///
/// A contact whose pad cannot encrypt at all (gone, exhausted, or the
/// binary missing) falls back to a sealed, unpadded `Envelope` - no gate
/// armed, nothing recoverable - answered by the legacy sealed
/// `OtpEndSessionAck` (`on_end_session_ack`) rather than a pad proof;
/// `pending_end_notice` keeps the retry alive until either confirmation
/// arrives.
async fn send_end_notice_now(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    to: UserId,
    pubkey_der: &[u8],
    contact_name: &str,
) {
    let payload = crypto::otp::OtpEndSessionPayload {
        contact_name: contact_name.to_string(),
    };
    let Ok(plaintext) = proto::encode(&payload) else {
        return;
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    session.peer_link.ensure_link(wr, to).await;
    // Written ahead of the encrypt, so a kill inside its window leaves a
    // reconcilable record instead of an orphaned spend
    // (`OtpContactState::encrypt_intent`).
    let staged = stage_encrypt_intent(
        session,
        contact_name,
        crate::client::otp_store::PendingOtpContent::EndNotice,
    );
    // No breadcrumb, no spend: the padded attempt is skipped entirely and
    // this falls through to the unpadded notice below, exactly as it does
    // when the build itself fails.
    let sealed = if staged {
        build_otp_envelope(
            session,
            to,
            pubkey_der,
            contact_name,
            None,
            send_id,
            &plaintext,
            Content::OtpEndSession,
        )
        .await
    } else {
        None
    };
    if let Some((envelope, proof)) = sealed {
        let seq = session
            .otp_store
            .get(contact_name)
            .map(|s| s.next_out_seq)
            .unwrap_or(0);
        session.otp_store.record_sent(
            contact_name,
            seq,
            crate::client::otp_store::PendingOtpContent::EndNotice,
            Some(proof),
        );
        let _ = session.otp_store.save();
        session.peer_link.send_reliable_or_queue(
            to,
            P2pPayload::OtpEnvelope {
                channel: None,
                seq,
                msg_id: None,
                envelope,
                sender_device_id: session.own_device_id.clone(),
            },
        );
        return;
    }
    // The padded build failed - nothing was spent, so the intent comes
    // straight back off before the unpadded fallback goes out.
    session.otp_store.clear_encrypt_intent(contact_name);
    let _ = session.otp_store.save();
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(to),
        pubkey_der,
        None,
        send_id,
        &plaintext,
        Content::OtpEndSession,
    ) else {
        return;
    };
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope,
        },
    );
}

/// The legacy sealed reply to an *unpadded* `/endotp` notice
/// (`on_end_session`'s fallback shape): no pad was involved on the way in,
/// so there is no pad-derived proof to acknowledge with - a sealed,
/// unpadded `OtpEndSessionAck` is the only honest answer, and deliberately
/// spends no pad of this side's own either (the pair reached this shape
/// precisely because a pad is no longer usable between them). A padded
/// notice is acknowledged through the ordinary `OtpDeliveryAck` instead
/// (`apply_otp_message`'s `OtpEndSession` arm).
async fn send_sealed_end_session_ack(
    session: &mut SessionState,
    to: UserId,
    pubkey_der: &[u8],
    contact_name: &str,
) {
    let payload = crypto::otp::OtpEndSessionPayload {
        contact_name: contact_name.to_string(),
    };
    let Ok(plaintext) = proto::encode(&payload) else {
        return;
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(to),
        pubkey_der,
        None,
        send_id,
        &plaintext,
        Content::OtpEndSessionAck,
    ) else {
        return;
    };
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope,
        },
    );
}

/// Applies an incoming `Content::OtpEndSession` envelope that arrived
/// *unpadded* (`direct_message::on_message`'s content-dispatch) - the
/// fallback shape, for a pair with no usable pad left to carry it. The
/// padded shape is the ordinary one and reaches `apply_end_session` through
/// `on_message` instead. Either way: the peer has
/// unilaterally ended the session - there is nothing here to accept or
/// reject, only to converge to. Pauses this side exactly like
/// `handle_end_otp_command` paused the initiator's own side (the pad
/// itself, and this store's record of it, both survive - only the
/// "active" marker and anything genuinely mid-flight are cleared), then
/// always replies with the sealed legacy `OtpEndSessionAck` - even for a
/// contact that was already paused, since that is exactly what a retried
/// notice whose first ack got lost looks like on this end, and the
/// initiator's own retry only stops once one genuinely arrives. (A *padded*
/// notice is acknowledged with the ordinary proof-carrying `OtpDeliveryAck`
/// instead - `apply_otp_message`'s `OtpEndSession` arm.)
/// `pub` (not `pub(crate)`) so `test/otp_missing_key_test.rs` can deliver
/// the sealed, unpadded notice `end_session_for_missing_contact` sends
/// directly to it, the same reason several other otp.rs internals became
/// `pub` earlier this session.
pub async fn on_end_session(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    from_name: String,
    sender: &UserInfo,
    envelope: Envelope,
) {
    let Some(plaintext) =
        crate::client::session::decrypt_own_envelope(&envelope, from, sender, None, session)
    else {
        return;
    };
    let Ok(payload) = proto::decode::<crypto::otp::OtpEndSessionPayload>(&plaintext) else {
        return;
    };
    let contact_name = payload.contact_name.clone();
    let sender_pubkey_der = sender.public_key_der.clone();
    apply_end_session(session, ui_state, from, from_name, payload).await;
    send_sealed_end_session_ack(session, from, &sender_pubkey_der, &contact_name).await;
}

/// The state mutation behind ending a session locally, shared by every
/// path that does it: an incoming `/endotp` notice from the peer
/// (`apply_end_session`), and this side discovering on its own that the
/// pair can never talk again - the peer's message referenced a contact
/// this side no longer has any keychain entry for at all
/// (`end_session_for_missing_contact`). Returns whether there was a
/// session to end at all, so each caller can decide whether its own
/// notice is worth showing.
fn pause_session_locally(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    contact_name: &str,
) -> bool {
    let had_session = session.otp_store.get(contact_name).is_some_and(|s| s.provisioned);

    discard_pending_setup(&session.otp_cli_cfg, contact_name);
    session.otp_incoming_setup.remove(&from);
    session.otp_out_queue.clear(contact_name);
    session.otp_store.pause_after_peer_ended(contact_name);
    // Being told the session is ending - by whatever shape the notice took
    // - settles this side's own end-notice bookkeeping too, if any is
    // outstanding for the same contact: this side may have run its own
    // `/endotp` (or `end_session_for_missing_contact` may have sent its own
    // substitute notice) and still be waiting on an acknowledgement that,
    // now, will never specifically arrive for it - the peer's notice here
    // is the news that answer would have carried anyway.
    // `OtpStore::clear_own_pending_end_notice_send`'s doc.
    session.otp_store.clear_end_notice(contact_name);
    session.otp_store.clear_own_pending_end_notice_send(contact_name);
    let _ = session.otp_store.save();
    ui_state.clear_otp_active(from);
    had_session
}

/// `on_end_session`'s body once the notice is in the clear, whichever
/// layer got it there - the sealed-only path above, or the padded one
/// `on_message` dispatches (`Content::OtpEndSession`).
async fn apply_end_session(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    from_name: String,
    payload: crypto::otp::OtpEndSessionPayload,
) {
    let had_session = pause_session_locally(session, ui_state, from, &payload.contact_name);
    if had_session {
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP session ended by {from_name} (the pad is kept - /otp resumes it)"),
            false,
        );
    }

    // No acknowledgement is sent from here: how the notice is confirmed
    // depends on the shape it arrived in, which only the caller knows. A
    // padded notice earns the ordinary proof-carrying `OtpDeliveryAck`
    // (`apply_otp_message`'s `OtpEndSession` arm - costing this side no
    // pad and touching nothing of its own that might still be in flight);
    // the unpadded fallback earns the sealed legacy `OtpEndSessionAck`
    // (`on_end_session`).
}

/// This side just discovered, from a message it could not decrypt, that
/// it has no keychain entry at all for `contact_name` any more - deleted
/// (`contacts::handle_delete_otp_key` and friends), or never genuinely
/// installed. There is nothing left to protect anything with, in either
/// direction, so the session is over for real: paused locally exactly as
/// an incoming `/endotp` would (the durable state - sequences, the
/// last-received-ack record, any owed end notice - is meaningless once
/// the keychain entry it was tracking is gone, and `pause_after_peer_ended`
/// clears it the same way), and this side tries to tell the sender
/// directly with a real `OtpEndSession` notice - sealed and unpadded,
/// since there is no pad left here to protect it with.
///
/// That notice needs *some* channel to travel over, though, and a pair
/// with no readable `pq_hybrid` identity for each other (`OtpFraming::Direct`
/// - a pad-only pair, whose one and only shared secret was the very pad
/// that is now gone) has none left at all: no pad, no identity to seal a
/// plain envelope to, and by design no server relay either (that framing
/// exists specifically for peers who may have no server connection in
/// common). For that pairing this side still ends cleanly on its own, but
/// the sender is never told through this path - she finds out only
/// because her own messages here now go forever unacknowledged, exactly
/// as an undelivered send to an unreachable peer already looked before
/// this fix existed, not worse. A `PqWrapped` pair always has the
/// fallback envelope this needs, so it converges both sides in practice.
async fn end_session_for_missing_contact(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    from_name: &str,
    contact_name: &str,
) {
    let had_session = pause_session_locally(session, ui_state, from, contact_name);

    let told_sender = try_notify_peer_session_ended(session, ui_state, from, contact_name).await;
    if had_session {
        let reachable_note = told_sender.describe(from_name);
        notify(
            ui_state,
            from,
            from_name,
            format!(
                "OTP: a message from {from_name} could not be decrypted - this side has no \
                 matching key for it any more, ending the session ({reachable_note})"
            ),
            false,
        );
    }
}

/// What became of an `OtpEndSession` notice, and so what the user is
/// told about it.
///
/// Three states rather than two because the durable send queue
/// (`queue_send_messages`, `client::outbox`) put a real one between them:
/// a peer who is simply away is no longer someone the notice is lost on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndNoticeOutcome {
    /// Their link was up; it went to them.
    Delivered,
    /// Sealed and handed over, waiting on their link - they get it when
    /// they are back (`resend_pending_end_notices` covers the rest).
    Queued,
    /// Nothing could be sealed to them at all: a pair with no readable
    /// identity for each other (`OtpFraming::Direct`), or one this side
    /// no longer holds a `UserInfo` for.
    Unsendable,
}

impl EndNoticeOutcome {
    /// How the notice's fate reads inside the message shown to the user,
    /// as the parenthetical each caller appends after its own reason.
    fn describe(self, peer_name: &str) -> String {
        match self {
            EndNoticeOutcome::Delivered => format!("{peer_name} was told"),
            EndNoticeOutcome::Queued => {
                format!("{peer_name} is away - they will be told when they are back")
            }
            EndNoticeOutcome::Unsendable => format!("{peer_name} could not be reached to tell"),
        }
    }
}

/// The outgoing half of `end_session_for_missing_contact` and
/// `end_live_session_if_exhausted`: a sealed, unpadded `OtpEndSession`
/// notice to `from`, the same shape `Content::OtpEndSession`'s own doc
/// gives for a pad that cannot encrypt at all.
///
/// Returns whether the peer was actually **told** - the notice was built
/// *and* their link was up to carry it. `false` for a pair with no
/// readable identity to seal it to (`OtpFraming::Direct`), and for one
/// who simply is not there, which each caller explains for its own
/// trigger.
///
/// Reachability is asked of the link, not of the sealing. Those used to
/// be the same question by accident: a peer's rotating key is dropped
/// when they disconnect, so nothing could be sealed to someone who was
/// away. Sealing now falls back to their bundle's bootstrap key
/// (`envelope::encap_to_seal_to`) so a message *can* be built for an
/// absent peer and held for them - which means "it encoded" no longer
/// says anything about whether they heard it.
///
/// A `false` here is not the end of it: the notice is still queued, and
/// `resend_pending_end_notices` carries it to them on their next
/// reconnect. It only reports what is true at this moment, which is what
/// the callers put in front of the user.
async fn try_notify_peer_session_ended(
    session: &mut SessionState,
    ui_state: &UiState,
    from: UserId,
    contact_name: &str,
) -> EndNoticeOutcome {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return EndNoticeOutcome::Unsendable;
    };
    let payload = crypto::otp::OtpEndSessionPayload {
        contact_name: contact_name.to_string(),
    };
    let Ok(plaintext) = proto::encode(&payload) else {
        return EndNoticeOutcome::Unsendable;
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        &session.own_pq_private,
        session.pq_peer_keys.encap_for(from),
        &sender.public_key_der,
        None,
        send_id,
        &plaintext,
        Content::OtpEndSession,
    ) else {
        return EndNoticeOutcome::Unsendable;
    };
    let reached = session.peer_link.is_active(from);
    session.peer_link.send_reliable_or_queue(
        from,
        P2pPayload::Envelope {
            channel: None,
            msg_id: None,
            envelope,
        },
    );
    if reached {
        EndNoticeOutcome::Delivered
    } else {
        EndNoticeOutcome::Queued
    }
}

/// Applies an incoming `Content::OtpEndSessionAck` - the initiator's side of
/// the notice's confirmation: the peer has genuinely received the
/// `OtpEndSession` this side sent, immediately or after a retried resend on
/// some later reconnect, so the durable retry (`resend_pending_end_notices`)
/// can finally stop. Silent either way - "OTP session ended" was already
/// shown, locally and immediately, the moment `/endotp` itself ran; this is
/// background bookkeeping only.
pub(crate) fn on_end_session_ack(
    session: &mut SessionState,
    from: UserId,
    sender: &UserInfo,
    envelope: Envelope,
) {
    let Some(plaintext) =
        crate::client::session::decrypt_own_envelope(&envelope, from, sender, None, session)
    else {
        return;
    };
    let Ok(payload) = proto::decode::<crypto::otp::OtpEndSessionPayload>(&plaintext) else {
        return;
    };
    apply_end_session_ack(session, payload);
}

/// `on_end_session_ack`'s body once the ack is in the clear - shared with
/// the padded path the same way `apply_end_session` is.
fn apply_end_session_ack(session: &mut SessionState, payload: crypto::otp::OtpEndSessionPayload) {
    if session.otp_store.clear_end_notice(&payload.contact_name) {
        let _ = session.otp_store.save();
    }
}

/// Sends every `/endotp` notice still owed to a reachable peer whose pad
/// gate is free to carry it - the `/endotp` counterpart of
/// `resend_pending_setups`, driven by the same `LinkStatusChanged` ->
/// `Active` trigger and for the same reason: a peer who was offline (or
/// unreachable) when the session ended must still learn about it, however
/// long that takes, the instant they are reachable again.
///
/// A contact whose gate is armed is skipped outright, whichever spend holds
/// it. If it is the notice itself (`PendingOtpContent::EndNotice`),
/// `recover_and_resend` - which `session.rs` always runs *before* this pass
/// on the same transition - has just resent that exact ciphertext; encoding
/// a second one here is precisely the double-spend that used to desync the
/// two sides' pads. If it is an earlier message, that message must land
/// first (it holds the pad's next range), and its genuine ack is what sends
/// the notice next (`on_delivery_ack`). Only a contact owing a notice with
/// nothing in flight at all - `/endotp` deferred it and the app restarted
/// before the gate cleared, or the earlier send's ack landed on a link that
/// died in the same breath - gets it encrypted fresh here.
/// Re-sends every `OtpPadCommit` still unconfirmed to a reachable peer -
/// the commit-phase counterpart of `resend_pending_setups`, driven by the
/// same `LinkStatusChanged` -> `Active` trigger. The commit is the one
/// provisioning payload whose loss splits a fresh pair asymmetrically:
/// this side has installed and shows the session active, while the peer
/// still holds only staged bytes it was never authorised to install - so
/// like every other owed thing, it is retried against the durable contact
/// name until the peer's `OtpPadCommitAck` genuinely lands
/// (`on_pad_commit_ack`). The receiving side answers a repeated commit
/// idempotently - re-acknowledging one already installed, and finding its
/// staged pad by contact name even under a fresh `UserId` (`on_pad_commit`).
pub async fn resend_pending_commits(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let owed: Vec<String> = session
        .otp_store
        .pending_commits()
        .map(str::to_string)
        .collect();
    for contact_name in owed {
        let Some((peer, _pubkey_der)) = peer_for_contact_name(session, ui_state, &contact_name)
        else {
            continue; // not currently connected - a later transition retries
        };
        session.peer_link.ensure_link(wr, peer).await;
        session
            .peer_link
            .send_reliable_or_queue(peer, P2pPayload::OtpPadCommit { contact_name });
    }
    Ok(())
}

pub async fn resend_pending_end_notices(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let owed: Vec<String> = session
        .otp_store
        .pending_end_notices()
        .map(str::to_string)
        .collect();
    for contact_name in owed {
        let Some((peer, pubkey_der)) = peer_for_contact_name(session, ui_state, &contact_name)
        else {
            continue; // not currently connected - a later transition retries
        };
        let gate_armed = session
            .otp_store
            .get(&contact_name)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_some();
        if !gate_armed {
            send_end_notice_now(wr, session, peer, &pubkey_der, &contact_name).await;
        }
    }
    Ok(())
}

/// Fetches `contact_name`'s current `otp --show-contact` snapshot and
/// stores it as `peer`'s live key-metadata (`UiState::otp_key_status`) - the
/// header's actual "realtime" mechanism. Called from every place in this
/// file that genuinely spends this contact's pad in either direction
/// (`send_now`, `send_file_offer`, `send_voice_offer`,
/// `start_outgoing_file_content`, `on_message`, `on_file_offer`,
/// `finish_incoming_file`), right after that spend succeeds, so the figures
/// change the instant the action that changed them completes - never
/// waiting on `poll_key_status`'s timer for that. Also the one-shot fetch
/// `accept_invite`/`on_key_setup_ack` make right when a session starts, so
/// the header shows real numbers on its very first frame. A failed/erroring
/// call just leaves whatever snapshot was already there rather than
/// clearing it - a stale-but-real figure beats a blank one for a display
/// that's cosmetic, not a security decision.
/// `pub` (not `pub(crate)`): OTP mail's own pad spends (`client::otp_mail`)
/// refresh through here too, when the mail's counterpart happens to be
/// connected - and a test simulating `mark_otp_active` alone (without the
/// refresh production code always pairs it with) would leave
/// `otp_key_status_for` empty, silently defeating `message_crypto`'s OTP
/// branch (`test/otp_ack_wiring_test.rs`'s send/receive-crypto-race tests).
/// Returns the fetched detail (`None` on a failed/erroring call, or a
/// contact that doesn't exist), so a caller right after a genuine spend can
/// check for exhaustion (`end_live_session_if_exhausted`) without a second
/// `show_contact` subprocess call for the same figures this one already
/// fetched.
pub async fn refresh_otp_key_status(
    cfg: &otp_cli::OtpCliConfig,
    ui_state: &mut UiState,
    peer: UserId,
    contact_name: &str,
) -> Option<otp_cli::ContactDetail> {
    let detail = otp_cli::show_contact(cfg, contact_name).await.ok().flatten()?;
    ui_state.set_otp_key_status(peer, otp_cli::OtpKeyStatus::new(cfg, contact_name, detail.clone()));
    Some(detail)
}

/// Whether `detail` shows nothing left in *either* direction - a pad that
/// can no longer encrypt or decrypt a single byte. A pure check with no
/// side effects: the contact's keychain entry, and aloo's own bookkeeping
/// for it, are never touched just because it emptied out - only the
/// *session* riding on it (for a live contact) reacts, and only by
/// pausing, the same as any other way a session ends. A later `/otp`/
/// `/new-otp-mail-key` still replaces it correctly regardless:
/// `commit_pending_setup`/`on_pad_commit` already remove whatever
/// keychain entry is there before installing a fresh one (AC-384),
/// exhausted or not.
///
/// `pub` (not `pub(crate)`) so `test/otp_key_exhaustion_test.rs` can drive
/// it directly with a synthetic `ContactDetail`, proving the check
/// deterministically without engineering a real message whose exact
/// encrypted size happens to land on precisely zero bytes remaining.
pub fn is_contact_exhausted(detail: &otp_cli::ContactDetail) -> bool {
    detail.enc_key_remaining == 0 && detail.dec_key_remaining == 0
}

/// Reacts to a live contact found exhausted right after a genuine spend:
/// pauses the session locally exactly as discovering the peer's key is
/// *missing* already does (`end_session_for_missing_contact`, AC-380) - a
/// pad with nothing left in either direction can protect nothing further
/// either way - and tries to tell the peer directly too, with the same
/// sealed, unpadded `OtpEndSession` and the same limits: only a
/// `PqWrapped` pair has a readable identity to seal it to, so a pad-only
/// pair's key running out converges only on the discovering side, exactly
/// like its missing-contact case. Neither the keychain entry nor aloo's
/// own per-contact bookkeeping is removed - only the session riding on it
/// pauses (`is_contact_exhausted`'s doc). A no-op whenever no session was
/// actually active, so this never fires spuriously against a mail-purpose
/// contact (which has no `is_otp_active` state at all) or an
/// already-paused live one.
///
/// `pub` (not `pub(crate)`) so `test/otp_key_exhaustion_test.rs` can drive
/// it directly, the same reason `is_contact_exhausted` is.
pub async fn end_live_session_if_exhausted(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    detail: &otp_cli::ContactDetail,
    contact_name: &str,
) {
    if !is_contact_exhausted(detail) || !ui_state.is_otp_active(peer) {
        return;
    }
    let peer_name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    pause_session_locally(session, ui_state, peer, contact_name);
    let told_peer = try_notify_peer_session_ended(session, ui_state, peer, contact_name).await;
    notify(
        ui_state,
        peer,
        &peer_name,
        format!(
            "OTP key for {peer_name} is fully used up - the session has ended ({})",
            told_peer.describe(&peer_name)
        ),
        false,
    );
}

/// `session.rs`'s tick loop calls this roughly once a second for whichever
/// peer's private room is currently open - a safety-net refresh alongside
/// the event-driven ones above, covering anything that isn't this app's own
/// send/receive (e.g. the pad's remaining bytes changing because the user
/// ran `otp` themselves against the same keychain out of band). A no-op
/// whenever `peer`'s session isn't active or their contact name can't be
/// resolved, so the caller doesn't need to check `is_otp_active` itself.
pub(crate) async fn poll_key_status(session: &SessionState, ui_state: &mut UiState, peer: UserId) {
    if !ui_state.is_otp_active(peer) {
        return;
    }
    let Some(peer_pubkey) = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.public_key_der.clone())
    else {
        return;
    };
    let Some(contact_name) = contact_name_if_active(session, peer, &peer_pubkey) else {
        return;
    };
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, peer, &contact_name).await;
}

/// The `otp` keychain contact name to file this peer's pad under, derived
/// from their announced `public_key_der` and, for a `PqWrapped` pair,
/// both sides' device_id.
///
/// Two derivations, and which one applies is exactly this pair's
/// `OtpFraming`: a readable `pq_hybrid` bundle on their side gives a
/// fingerprint-and-device-derived name both machines compute identically
/// (device-pinning plan §4 - own device_id from `SessionState::
/// own_device_id`, the peer's from `SessionState::peer_device_ids`,
/// populated by `DeviceIdAnnounce` before any OTP action can reach this
/// point, since both require the same P2P link `Active`), and a peer
/// without one falls back to the two pinned public keys, deliberately
/// left device-unqualified (§5 - a raw pad is a single instance per
/// key-pair, not per device-pair). Never the nickname, which proves
/// nothing and would let an impersonator taking a familiar name spend the
/// real contact's pad - spending pad on the wrong person destroys it for
/// the right one, since the bytes are gone whether or not they could read
/// them (`crypto::otp::contact_name_for_keys`).
///
/// `None` for a `PqWrapped` pair whose device_id hasn't resolved yet (a
/// brief window right after the link reaches `Active`, before their
/// `DeviceIdAnnounce` has decrypted) - OTP simply reads as "not yet
/// ready" rather than naming a slot that would disagree with what the
/// peer computes once their announce does arrive.
pub(crate) fn contact_name_for_peer(
    session: &SessionState,
    peer: UserId,
    peer_pubkey_der: &[u8],
) -> Option<String> {
    match framing_for(&session.otp_own_pinned_der, peer_pubkey_der) {
        OtpFraming::PqWrapped => {
            let peer_fp = crypto::pq::fingerprint_of_encoded(peer_pubkey_der)?;
            let peer_device_id = session.peer_device_ids.get(&peer)?;
            Some(crypto::otp::contact_name_for(
                &session.own_pq_fp,
                &session.own_device_id,
                &peer_fp,
                peer_device_id,
            ))
        }
        OtpFraming::Direct => Some(crypto::otp::contact_name_for_keys(
            &session.otp_own_pinned_der,
            peer_pubkey_der,
        )),
    }
}

/// `contact_name_for_peer`'s OTP-mail counterpart - same framing decision,
/// but naming the mail-specific keychain contact (`crypto::otp::
/// contact_name_for_mail`/`contact_name_for_keys_mail`) so mail never
/// spends the pad a live `/otp` session would.
pub(crate) fn contact_name_for_peer_mail(
    session: &SessionState,
    peer: UserId,
    peer_pubkey_der: &[u8],
) -> Option<String> {
    match framing_for(&session.otp_own_pinned_der, peer_pubkey_der) {
        OtpFraming::PqWrapped => {
            let peer_fp = crypto::pq::fingerprint_of_encoded(peer_pubkey_der)?;
            let peer_device_id = session.peer_device_ids.get(&peer)?;
            Some(crypto::otp::contact_name_for_mail(
                &session.own_pq_fp,
                &session.own_device_id,
                &peer_fp,
                peer_device_id,
            ))
        }
        OtpFraming::Direct => Some(crypto::otp::contact_name_for_keys_mail(
            &session.otp_own_pinned_der,
            peer_pubkey_der,
        )),
    }
}

/// What actually goes under the pad: the payload plus the routing that
/// would otherwise ride in the clear.
///
/// A `pq_hybrid` seal binds `(recipient_fp, channel, send_id)`. With the pad
/// on the inside that binding is the outermost layer, so it is what an
/// observer would read - and `recipient_fp` names the recipient's identity,
/// which is more than the frame carrying it already says.
///
/// Two answers, both here rather than in the seal: `channel` travels under
/// the pad and the seal signs none, and `recipient_fp` is signed but sent
/// zeroed (`crypto::pq::seal_send_blinded`). Neither check is lost - the
/// recipient's own fingerprint is substituted back before the signatures
/// are verified, and `open_otp_envelope` compares the channel after
/// unwrapping, against pad ciphertext no third party can produce. What is
/// left in the clear is `send_id`, which nonces the chunk and so has to be
/// readable before anything opens.
///
/// `Direct` sends have no seal and so would need this shape regardless;
/// sharing it means both framings decode by the same path.
#[derive(Serialize, Deserialize)]
struct OtpInner {
    channel: Option<String>,
    payload: Vec<u8>,
}

/// Builds one OTP-layer message for the wire, applying this layer's single
/// rule: **the pad goes on the payload, and the seal goes around the pad.**
///
/// - `PqWrapped` → `seal(pad(payload))`. The recipient opens the seal
///   first, so an unsigned forgery never reaches the pad at all, and the
///   pad covers only the payload rather than the ~6.4KB of ML-DSA/ML-KEM/
///   RSA a sealed envelope weighs - which for a short chat line was almost
///   all of what each message used to cost.
/// - `Direct` → `pad(payload)`. There is no keybundle to seal to and none
///   is needed: the pad is the protection and `otp --decrypt` refusing
///   what it cannot attribute is the authentication (§16.2).
///
/// The same shape for every OTP payload - text, a file or voice offer, and
/// the session-control messages alike - which is what lets one receive
/// helper (`open_otp_envelope`) undo it. Streamed *content* is the one
/// thing that does not come through here: it is padded whole in a single
/// streaming pass and its chunks sealed individually
/// (`start_outgoing_file_content`), which is the same nesting arrived at a
/// different way.
///
/// Returns the envelope and the proof this side keeps to check the peer's
/// acknowledgement against (`crypto::otp::AckProof`).
async fn build_otp_envelope(
    session: &SessionState,
    to: UserId,
    recipient_pubkey_der: &[u8],
    contact_name: &str,
    channel: Option<String>,
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<(Envelope, crypto::otp::AckProof)> {
    let inner = proto::encode(&OtpInner {
        channel,
        payload: plaintext.to_vec(),
    })
    .ok()?;
    // Asked *before* the pad is spent, never after. `wrap_outgoing` is
    // irreversible - it advances this side's pad whether or not anything
    // is ever sent - so a framing that could not have worked must fail
    // here, while failing still costs nothing. Getting this order wrong
    // left the two ends out of step over a message that was never sent,
    // which is the one way to make a pad genuinely unusable.
    if !can_frame_padded(session, to, recipient_pubkey_der) {
        return None;
    }
    let (padded, proof) = wrap_outgoing(&session.otp_cli_cfg, inner, contact_name).await?;
    let envelope = frame_padded(session, to, recipient_pubkey_der, send_id, padded, content)?;
    Some((envelope, proof))
}

/// `build_otp_envelope`'s outer half on its own: puts this pair's framing
/// around pad ciphertext that already exists.
///
/// Split out for recovery (`recover_and_resend_*`), which resends the very
/// same pad ciphertext the original send spent - never a fresh encode -
/// but must still re-seal it, because the seal is the outer layer now and
/// was never what got stored. A fresh seal is exactly right: it carries a
/// new `send_id`, which is what the peer's replay window wants to see.
/// Whether `frame_padded` below could succeed for this pair - asked
/// before any pad is spent (`build_otp_envelope`).
///
/// Mirrors `frame_padded`'s own two branches: a `Direct` pair needs
/// nothing but the pad itself, and a `PqWrapped` pair needs a readable
/// keybundle to seal to. It does *not* need their rotating key, which is
/// dropped the moment they disconnect - `envelope::encap_to_seal_to`
/// falls back to the bundle's bootstrap key, which is what lets a message
/// be sealed for somebody who is away at all.
fn can_frame_padded(session: &SessionState, to: UserId, recipient_pubkey_der: &[u8]) -> bool {
    match framing_for(&session.otp_own_pinned_der, recipient_pubkey_der) {
        OtpFraming::Direct => true,
        OtpFraming::PqWrapped => {
            crypto::pq::fingerprint_of_encoded(recipient_pubkey_der).is_some()
                && crate::client::envelope::encap_to_seal_to(
                    session.pq_peer_keys.encap_for(to),
                    recipient_pubkey_der,
                )
                .is_some()
        }
    }
}

fn frame_padded(
    session: &SessionState,
    to: UserId,
    recipient_pubkey_der: &[u8],
    send_id: u64,
    padded: Vec<u8>,
    content: Content,
) -> Option<Envelope> {
    match framing_for(&session.otp_own_pinned_der, recipient_pubkey_der) {
        OtpFraming::PqWrapped => crate::client::envelope::encrypt_blinded_envelope_for(
            &session.own_pq_private,
            session.pq_peer_keys.encap_for(to),
            recipient_pubkey_der,
            send_id,
            &padded,
            content,
        ),
        OtpFraming::Direct => Some(Envelope {
            content,
            // Not a sealed blob: pad ciphertext, carried as-is. `Envelope`
            // is reused rather than a parallel shape so `content` still
            // routes the message the same way at the far end.
            blocks: vec![padded],
        }),
    }
}

/// `build_otp_envelope`'s exact inverse: opens the seal if there is one,
/// then the pad, yielding the payload and the proof this side can
/// acknowledge it with.
///
/// Opening the seal first is what makes a forged message free: it is
/// refused by its signature before a single pad byte is touched. A
/// `Direct` pair has no seal to check, and `otp --decrypt`'s own refusal
/// stands in for it - which is why that refusal is reported out loud
/// (`finish_opening_otp_envelope`'s rejection notice) rather than
/// swallowed.
/// The framing-dependent first half of opening an OTP envelope: recovers
/// the still-padded bytes, either by unwrapping the outer `pq_hybrid` seal
/// (`PqWrapped`) or reading the raw block directly (`Direct`).
///
/// Split out from `open_otp_envelope` so the unknown-nickname reconciliation
/// scan (`session::scan_pinned_keys_for_match`, `docs/PROTOCOL.md` §7.1.5)
/// can try this safe half against several *decodable* candidates without
/// ever touching a pad: the `PqWrapped` branch is an ordinary signature
/// check (`decrypt_own_blinded_envelope`), side-effect-free on a wrong
/// candidate for the same reason `decrypt_own_envelope` is, and the scan
/// never calls this for a candidate whose pin doesn't decode - which is
/// exactly what would fall to the `Direct` branch below, the one half of
/// this that reads real key material with no verification of its own.
/// Real pad bytes are only ever touched by `finish_opening_otp_envelope`,
/// and only once, for whichever single candidate this proved correct.
pub(crate) fn recover_padded_otp_bytes(
    session: &mut SessionState,
    from: UserId,
    sender: &UserInfo,
    envelope: &Envelope,
) -> Option<Vec<u8>> {
    match framing_for(&session.otp_own_pinned_der, &sender.public_key_der) {
        OtpFraming::PqWrapped => {
            crate::client::session::decrypt_own_blinded_envelope(envelope, from, sender, session)
        }
        OtpFraming::Direct => envelope.blocks.first().cloned(),
    }
}

/// The pad-decrypt half of opening an OTP envelope - the one place real key
/// material is actually spent, only ever for a sender already identified
/// (the ordinary caller has one from `otp_sender_of`; the unknown-nickname
/// scan has one because `recover_padded_otp_bytes` already proved it).
///
/// `claimed_device_id` is checked against this contact's
/// `OtpContactState::bound_peer_device_id` *before* `unwrap_incoming` is
/// ever called (device-pinning plan §5) - the whole reason this lives
/// here rather than in a caller: `otp --decrypt` is destructive the
/// instant it runs, so the check has to happen strictly before it, at the
/// one place every caller of this function funnels through. A mismatch
/// costs nothing but a wasted network round trip for whoever sent it -
/// the pad's own offset is never touched, so their retry (unchanged, per
/// the stop-and-wait gate) will succeed the moment the actually-bound
/// device answers instead. A `PqWrapped` contact's name is already
/// device-qualified (§4), so this never has anything to disagree with in
/// practice for one - binding still runs, harmlessly, rather than adding
/// a framing-specific branch here.
pub(crate) async fn finish_opening_otp_envelope(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    from_name: &str,
    contact_name: &str,
    channel: Option<&str>,
    padded: &[u8],
    claimed_device_id: &str,
) -> Option<(Vec<u8>, crypto::otp::AckProof)> {
    if let Some(bound) = session.otp_store.bound_peer_device_id(contact_name)
        && bound != claimed_device_id
    {
        notify(
            ui_state,
            from,
            from_name,
            format!(
                "OTP: a message from {from_name} claims a different device than this pad is \
                 bound to - held, not delivered, until the right device answers"
            ),
            false,
        );
        return None;
    }
    let (inner, proof) = match unwrap_incoming(&session.otp_cli_cfg, padded, contact_name).await {
        UnwrapOutcome::Ok(bytes, proof) => (bytes, proof),
        UnwrapOutcome::Rejected(reason) => {
            match recover_orphaned_decrypt(session, contact_name).await {
                Some(healed) => healed,
                None => {
                    let reason = reason.trim().replace('\n', "; ");
                    notify(
                        ui_state,
                        from,
                        from_name,
                        format!(
                            "OTP: a message from {from_name} was rejected ({reason}) - keys \
                             untouched"
                        ),
                        false,
                    );
                    return None;
                }
            }
        }
        UnwrapOutcome::Failed(reason) => {
            // Distinguished from every other decrypt failure: if this side
            // has no keychain entry for this contact at all any more (the
            // key was deleted, here or by a prior crash/edit, or was never
            // genuinely installed), there is nothing transient about
            // it - retrying, or waiting for `otp`/the disk/whatever else
            // `reason` names to recover, can never succeed. Ends the
            // session on both sides instead of leaving the sender to keep
            // believing it is still alive (`end_session_for_missing_contact`'s
            // own doc).
            if !otp_cli::has_contact(&session.otp_cli_cfg, contact_name)
                .await
                .unwrap_or(true)
            {
                end_session_for_missing_contact(session, ui_state, from, from_name, contact_name)
                    .await;
                return None;
            }
            let reason = reason.trim().replace('\n', "; ");
            notify(
                ui_state,
                from,
                from_name,
                format!("OTP: a message from {from_name} could not be decrypted ({reason})"),
                false,
            );
            return None;
        }
    };
    // A genuine decrypt just succeeded under this contact's pad - proof,
    // not a bare claim, that `claimed_device_id` really does hold it.
    // Binds it the first time (a no-op once already bound to this same
    // device); a mismatch was already refused above, before this ever ran.
    session
        .otp_store
        .bind_peer_device(contact_name, claimed_device_id);
    let _ = session.otp_store.save();
    let inner: OtpInner = proto::decode(&inner).ok()?;
    // The check the seal's own binding would have made, moved inside the
    // pad along with the value it is about: a channel message replayed as
    // a direct message (or into a different room) does not survive it.
    if inner.channel.as_deref() != channel {
        return None;
    }
    Some((inner.payload, proof))
}

/// The one benign shape a pad rejection can take: the process died (or was
/// killed) in the window between `otp --decrypt` succeeding and the
/// acceptance being persisted to the aloo store - the tool's decrypt state
/// advanced, this store's did not, and the sender's retry of that exact
/// message now decodes against the wrong pad range and is refused as
/// "corrupted or out of sync". Detected precisely: the tool's decrypt
/// counter sits exactly one past the number of messages this store has
/// accepted (the two advance 1:1, both starting at 0, and stop-and-wait
/// means at most one can ever be orphaned). The message itself is not
/// lost - the tool keeps a safety copy of the last *received* plaintext -
/// so the orphaned decrypt is recovered whole (`--recover-last
/// --received`), nonce included, and handed back as if the decrypt had
/// just happened: the caller then accepts, displays, and acknowledges it
/// with its true proof, and the pair is back in lockstep. Anything that
/// does not match this exact shape is a genuine rejection and reported as
/// one.
async fn recover_orphaned_decrypt(
    session: &mut SessionState,
    contact_name: &str,
) -> Option<(Vec<u8>, crypto::otp::AckProof)> {
    let recovered = recover_orphaned_decrypt_raw(session, contact_name).await?;
    if recovered.len() < crypto::otp::ACK_NONCE_BYTES {
        return None;
    }
    let (nonce, payload) = recovered.split_at(crypto::otp::ACK_NONCE_BYTES);
    Some((payload.to_vec(), crypto::otp::ack_proof_for(nonce)))
}

/// Whether `contact_name`'s tool-side decrypt counter sits exactly one
/// past what this store has accepted - the one shape a crash between a
/// decrypt and its record leaves (`recover_orphaned_decrypt`'s doc), and
/// the precondition every heal below shares. Anything else - equal, or
/// further apart - is not that crash, and nothing here may touch the
/// tool's kept copy on the strength of it.
async fn decrypt_was_orphaned(session: &SessionState, contact_name: &str) -> bool {
    let Ok(Some(detail)) = otp_cli::show_contact(&session.otp_cli_cfg, contact_name).await else {
        return false;
    };
    let accepted = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_expected_in_seq)
        .unwrap_or(0);
    detail.dec_sequence == accepted + 1
}

/// `recover_orphaned_decrypt` for a payload framed without a nonce: the
/// tool's kept received-side copy, whole, when and only when the crash
/// shape holds. OTP mail is sealed as `(payload, signature)` with no nonce
/// in front (`client::otp_mail::on_mail_deliver`), so it heals through
/// this rather than the nonce-splitting form above.
pub(crate) async fn recover_orphaned_decrypt_raw(
    session: &SessionState,
    contact_name: &str,
) -> Option<Vec<u8>> {
    if !decrypt_was_orphaned(session, contact_name).await {
        return None;
    }
    otp_cli::recover_last(
        &session.otp_cli_cfg,
        contact_name,
        otp_cli::RecoverDirection::Received,
    )
    .await
    .ok()?
}

/// `recover_orphaned_decrypt` for a file's or voice message's content
/// phase, whose plaintext is a file: the tool's kept received-side copy is
/// streamed to `dst` (`recover_last_file`), and `true` means `dst` now
/// holds exactly what the interrupted decrypt produced. Without this the
/// content path had no heal at all: a receiver killed between
/// `otp --decrypt` and the record refused the sender's retry forever
/// ("rejected - keys untouched"), never acknowledged it, and the pair
/// wedged on a spend both sides had in fact completed.
async fn recover_orphaned_decrypt_file(
    session: &SessionState,
    contact_name: &str,
    dst: &Path,
) -> bool {
    if !decrypt_was_orphaned(session, contact_name).await {
        return false;
    }
    matches!(
        otp_cli::recover_last_file(
            &session.otp_cli_cfg,
            contact_name,
            otp_cli::RecoverDirection::Received,
            dst,
        )
        .await,
        Ok(Some(()))
    )
}

#[allow(clippy::too_many_arguments)]
async fn open_otp_envelope(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    sender: &UserInfo,
    from_name: &str,
    contact_name: &str,
    channel: Option<&str>,
    envelope: &Envelope,
    claimed_device_id: &str,
) -> Option<(Vec<u8>, crypto::otp::AckProof)> {
    let padded = recover_padded_otp_bytes(session, from, sender, envelope)?;
    finish_opening_otp_envelope(
        session,
        ui_state,
        from,
        from_name,
        contact_name,
        channel,
        &padded,
        claimed_device_id,
    )
    .await
}

/// The chunk-transport key for an OTP content stream - a file's content
/// phase or a voice message.
///
/// Under `PqWrapped` the chunks are additionally sealed to the recipient's
/// keybundle, exactly like an ordinary transfer. Under `Direct` there is
/// no keybundle to seal to, and none is needed: what the transport carries
/// is already one-time-pad ciphertext, encrypted whole before the first
/// chunk leaves. The pad is the protection, and `otp --decrypt` refusing
/// anything it cannot attribute to the holder of the mirror key at the
/// expected offset is the authentication (§16.2).
///
/// Deliberately *not* folded into `voice_stream::resolve_direct_key`:
/// every non-OTP caller of that must keep failing closed when a recipient
/// has no keybundle, since nothing has encrypted their bytes yet at that
/// point. `start_pad_send` also keeps using the strict one - a pad
/// transfer carries raw key material and has no pad of its own to hide
/// behind, which is why it refuses `Direct` outright.
fn otp_stream_key(
    session: &SessionState,
    stream_id: u64,
    to: UserId,
    recipient_pubkey_der: &[u8],
) -> Option<crate::client::voice_stream::DirectStreamKey> {
    match framing_for(&session.otp_own_pinned_der, recipient_pubkey_der) {
        OtpFraming::PqWrapped => crate::client::voice_stream::resolve_direct_key(
            session,
            stream_id,
            to,
            recipient_pubkey_der,
        ),
        OtpFraming::Direct => Some(crate::client::voice_stream::DirectStreamKey::Pad),
    }
}

/// `otp_stream_key`'s receiving counterpart: what opens the chunks of an
/// arriving OTP content stream. `Pad` passes them through untouched, for
/// `otp --decrypt` to open the reassembled whole.
pub(crate) fn otp_incoming_stream_key(
    session: &SessionState,
    from: UserId,
    sender_public_key_der: &[u8],
) -> crate::client::voice_stream::IncomingStreamKey {
    match framing_for(&session.otp_own_pinned_der, sender_public_key_der) {
        OtpFraming::PqWrapped => {
            crate::client::voice_stream::resolve_incoming_key(session, from, sender_public_key_der)
        }
        OtpFraming::Direct => crate::client::voice_stream::IncomingStreamKey::Pad,
    }
}

/// Who an inbound OTP payload is from.
///
/// Ordinarily they are already in `known_users` - a server introduced
/// them, or `session::register_pad_only_peer` did when their link came up.
/// The fallback covers the case neither reached: a punched peer whose pin
/// is not a readable keybundle, arriving before this side had a link of
/// its own to them (a `Ping` that crossed a `Pong`, a restart on one side,
/// a serverless pair where only one end had the other in
/// `direct_punch_to`). Their nickname comes from the link itself, and the
/// key from this client's own pin for it - never from anything the sender
/// says - so an inbound payload can introduce someone, but never *rename*
/// them or change what this client encrypts to under that name.
///
/// Registering them is left to the caller, and deliberately only after the
/// pad has actually opened something: `otp --decrypt` refusing anything it
/// cannot attribute is what makes the claim worth acting on (§16.2).
pub(crate) fn otp_sender_of(
    session: &SessionState,
    ui_state: &UiState,
    from: UserId,
) -> Option<UserInfo> {
    if let Some(known) = ui_state.known_users.get(&from) {
        return Some(known.clone());
    }
    let nickname = session.peer_link.direct_nickname_of(from)?;
    let device_id = session.peer_link.direct_device_id_of(from);
    crate::client::session::direct_peer_identity(&session.id_store, &nickname, device_id.as_deref())
}

/// The two questions every inbound pad-protected frame opens with: who
/// sent it (`otp_sender_of`) and which pad contact that makes them
/// (`contact_name_for_peer`).
///
/// `None` when either half doesn't resolve, and every caller treats that
/// the same way - drop the frame in silence. Both halves fail for
/// ordinary, transient reasons (a peer whose `DeviceIdAnnounce` hasn't
/// decrypted yet, a `direct_punch_to` target with no key pinned), so
/// neither is an error worth telling anyone about; the frame is simply
/// not yet openable, and the sender's own retry brings it back.
///
/// `on_message` deliberately does *not* use this: it is the one caller
/// that reacts differently to the two failures, offering an unknown-peer
/// review when the sender is the half that didn't resolve.
pub(crate) fn otp_sender_and_contact(
    session: &SessionState,
    ui_state: &UiState,
    from: UserId,
) -> Option<(UserInfo, String)> {
    let sender = otp_sender_of(session, ui_state, from)?;
    let contact_name = contact_name_for_peer(session, from, &sender.public_key_der)?;
    Some((sender, contact_name))
}

/// Re-sends the `(seq, proof)` already recorded for a message this side
/// accepted before, and does nothing if there is none.
///
/// Reached when `OtpStore::is_next_expected` says no: the peer is
/// retrying something this contact's counter has already moved past,
/// because the ack for it never arrived. Their single-outstanding-send
/// gate (`pending_unacked_out_seq`) only ever opens on an ack, so staying
/// silent would wedge it forever - and re-sending the recorded ack costs
/// nothing, since it means no re-decrypt and, above all, no second pass
/// over the pad. That is also why the check happens *before*
/// `otp --decrypt` runs at every call site.
fn resend_recorded_ack(session: &mut SessionState, from: UserId, contact_name: &str, seq: u64) {
    if let Some(proof) = session.otp_store.ack_to_resend(contact_name, seq) {
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq, proof });
    }
}

/// Records a sender the pad has just vouched for, so the rest of the app
/// can treat them like any other peer - the sidebar, the DM room, and
/// above all the *send* path, which needs them in `known_users` to address
/// anything back. A no-op for a peer already registered.
fn adopt_pad_verified_sender(ui_state: &mut UiState, from: UserId, sender: &UserInfo) {
    if ui_state.known_users.contains_key(&from) {
        return;
    }
    ui_state.known_users.insert(from, sender.clone());
    ui_state.mark_otp_active(from);
}

/// What, if anything, is sealed around one contact's pad ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpFraming {
    /// The ordinary case: the pad ciphertext is sealed to the peer's
    /// `pq_hybrid` keybundle. The envelope's own signature and the pad's
    /// decrypt verdict both apply.
    PqWrapped,
    /// The peer announced no readable `pq_hybrid` keybundle, so there is
    /// nothing to seal to: the pad ciphertext travels as it is.
    ///
    /// Authentication is then entirely the decrypt verdict - a message is
    /// accepted only if `otp` confirms it was produced by the holder of the
    /// mirror key at the expected offset and is next in sequence
    /// (`docs/SPEC.md`, "How a pad-wrapped message authenticates itself").
    /// That is a *stronger* statement about who is speaking than an
    /// identity signature would be, since it is tied to the specific key
    /// position rather than merely to a keypair - so nothing is given up by
    /// dropping the envelope here.
    ///
    Direct,
}

/// Which framing applies between these two. `PqWrapped` needs a readable
/// `pq_hybrid` keybundle on *both* sides - an envelope can only be built
/// if this side can sign one and the other can open it - so anything else
/// is `Direct`.
///
/// Deliberately a function of the two keys rather than of the peer's
/// alone: both ends must reach the same answer, or one would wrap while
/// the other expected bare plaintext. Handing it the same unordered pair
/// from either side is what guarantees that, exactly as
/// `crypto::otp::contact_name_for_keys` is symmetric in its two arguments
/// - and the two decisions have to agree, since the framing is also what
/// decides how that name is derived. Read from the announced keys
/// themselves rather than from a stored key mode, so the two can never
/// disagree.
///
/// This side's own key is always a real bundle, so in practice the answer
/// turns on the peer's: one whose bytes do not decode is `Direct`, and a
/// pad both sides already hold still carries that conversation,
/// authenticated by the pad's decrypt verdict alone.
pub fn framing_for(own_public_key_der: &[u8], peer_public_key_der: &[u8]) -> OtpFraming {
    let readable = |der: &[u8]| crypto::pq::fingerprint_of_encoded(der).is_some();
    if readable(own_public_key_der) && readable(peer_public_key_der) {
        OtpFraming::PqWrapped
    } else {
        OtpFraming::Direct
    }
}

/// `id`'s display name, for a call site (`send_now`/`send_or_queue`) that
/// only has a `UserId` in hand - unlike the provisioning-handshake
/// functions above, which already carry a name alongside every `UserId`
/// they work with.
fn peer_name_for(ui_state: &UiState, id: UserId) -> String {
    ui_state
        .known_users
        .get(&id)
        .map(|u| u.name.clone())
        .unwrap_or_default()
}

/// Sends one OTP-wrapped message to `to` right now: builds the underlying
/// `pq_hybrid` envelope exactly like a plain send would, wraps its blob
/// through `otp`, and puts it on the wire as `P2pPayload::OtpEnvelope`.
/// Callers must have already verified there is no message still awaiting a
/// network ack for `contact_name` - see `send_or_queue`, the only
/// intended entry point from `direct_message`/`channel`.
#[allow(clippy::too_many_arguments)]
async fn send_now(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
    recipient_pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
    channel: Option<String>,
    log_index: Option<usize>,
    msg_id: Option<u64>,
) -> proto::Result<()> {
    // Corrects the row `push_outgoing_dm` already logged (UI thread, at
    // submit time) to match what is genuinely about to happen here: that
    // earlier snapshot and this send both read `is_otp_active`, but at two
    // different moments, and a session starting or ending in between
    // leaves them disagreeing - see `UiState::set_dm_message_crypto`'s doc.
    // Computed before the spend below, matching `message_crypto`'s own
    // pre-spend convention (seq/offset describe the message about to be
    // sent, not the one before it).
    if let Some(idx) = log_index {
        let crypto = ui_state.message_crypto(to, true);
        ui_state.set_dm_message_crypto(to, idx, crypto);
    }
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    // Written ahead of the encrypt, so a kill inside its window leaves a
    // reconcilable record instead of an orphaned spend
    // (`OtpContactState::encrypt_intent`).
    if !stage_encrypt_intent(
        session,
        contact_name,
        crate::client::otp_store::PendingOtpContent::Text {
            channel: channel.clone(),
        },
    ) {
        let peer_name = peer_name_for(ui_state, to);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: could not record this send before encrypting - message not sent".to_string(),
            false,
        );
        if let Some(idx) = log_index {
            ui_state.mark_dm_message_failed(to, idx);
        }
        return Ok(());
    }
    // The pad goes on the message, and the seal - if this pair has one -
    // goes around the pad (`build_otp_envelope`). Never a silent fallback
    // to an unpadded send: an `otp` binary that is missing, misconfigured
    // or exhausted is a hard error here.
    let Some((otp_envelope, ack_proof)) = build_otp_envelope(
        session,
        to,
        recipient_pubkey_der,
        contact_name,
        channel.clone(),
        send_id,
        plaintext,
        content,
    )
    .await
    else {
        session.otp_store.clear_encrypt_intent(contact_name);
        let _ = session.otp_store.save();
        let peer_name = peer_name_for(ui_state, to);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to encrypt this message - message not sent".to_string(),
            false,
        );
        if let Some(idx) = log_index {
            ui_state.mark_dm_message_failed(to, idx);
        }
        return Ok(());
    };
    let seq = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    let own_device_id = session.own_device_id.clone();
    let payload = P2pPayload::OtpEnvelope {
        channel: channel.clone(),
        seq,
        msg_id,
        envelope: otp_envelope,
        sender_device_id: own_device_id,
    };
    // The pad position is spent - `build_otp_envelope` already consumed
    // it - so what remains is to make that spend durable before anything
    // else can go wrong. `record_sealed` advances the sequence and
    // retires the write-ahead intent without arming the acknowledgement
    // gate: the gate belongs to whichever message is actually on the
    // wire, which `pump_otp_queue` decides below.
    session.otp_store.record_sealed(contact_name, seq);
    let _ = session.otp_store.save();
    // Whether the sealed message now belongs to the durable queue. If it
    // does not - no queue configured, or the queue would not take it - it
    // must go straight at the transport instead. There is no third
    // option: the pad position is spent, and a spend whose message is
    // never sent puts this pad permanently ahead of the peer's.
    let held_by_the_queue = match session.otp_outbox.as_mut() {
        None => false,
        Some(outbox) => {
            match outbox.queue(contact_name, &payload, seq, msg_id, channel.clone(), ack_proof) {
                Ok(accepted) => {
                    if !accepted {
                        crate::log_warn!(
                            "the durable OTP queue would not take a sealed message; \
                             sending it directly so the pad position it spent is not wasted"
                        );
                    }
                    accepted
                }
                // The entry is in memory and will still be pumped out;
                // only its survival across a restart was lost. Sending it
                // directly as well would put the same pad position on the
                // wire twice.
                Err(e) => {
                    crate::log_warn!("a sealed OTP message could not be written to disk ({e})");
                    true
                }
            }
        }
    };
    if !held_by_the_queue {
        // Straight at the transport, which keeps its own short in-memory
        // queue - the historical path, and the fallback whenever the
        // durable queue did not take responsibility for this message.
        session.otp_store.record_sent(
            contact_name,
            seq,
            crate::client::otp_store::PendingOtpContent::Text {
                channel: channel.clone(),
            },
            Some(ack_proof),
        );
        let _ = session.otp_store.save();
        session.peer_link.ensure_link(wr, to).await;
        session.peer_link.send_reliable_or_queue(to, payload);
        if let Some(msg_id) = msg_id {
            ui_state.mark_awaiting_pad_ack(to, msg_id);
            session
                .otp_ack_rows
                .insert((contact_name.to_string(), seq), msg_id);
        }
    }
    // Held by the queue, so its row says so until the pump releases it.
    // The in-memory path this replaced always surfaced a held message, for
    // a reason that did not stop being true when the queue became durable:
    // held back silently, a message looks exactly like one that was sent,
    // which is what makes a genuinely stuck gate indistinguishable from a
    // healthy round trip. `pump_otp_queue` clears it again the moment this
    // message actually reaches the wire, which is usually immediately.
    if held_by_the_queue
        && let Some(msg_id) = msg_id
    {
        ui_state.mark_queued(to, msg_id, true);
    }
    if let Some(detail) = refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await {
        end_live_session_if_exhausted(session, ui_state, to, &detail, contact_name).await;
    }
    pump_otp_queue(wr, session, ui_state, to, contact_name).await;
    crate::client::session::request_rotation(session, to);
    Ok(())
}

/// Puts the next sealed message on the wire, if the previous one has been
/// acknowledged and there is one waiting (`client::otp_outbox`).
///
/// This is where a pad session's strict order lives: exactly one message
/// is outstanding at a time, the front of the queue is the only one that
/// may go, and it stays at the front until its own acknowledgement comes
/// back - so a send that left but was never answered is retried rather
/// than skipped past.
///
/// Called after every seal, after every acknowledgement, and whenever a
/// peer's link comes up - the three moments at which "may the next one
/// go?" can newly become true.
pub async fn pump_otp_queue(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
) {
    let outstanding = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq);
    if outstanding.is_some() {
        return;
    }
    let Some(outbox) = session.otp_outbox.as_ref() else {
        return;
    };
    let Some(entry) = outbox.front(contact_name) else {
        return;
    };
    let (Some(seq), Some(ack_proof)) = (entry.seq(), entry.ack_proof()) else {
        // The entry cannot be read back - a truncated or corrupted queue
        // file. Left where it is rather than dropped: its pad position was
        // spent when it was sealed, and discarding it would put this side
        // permanently ahead of the peer's. But said out loud, because
        // returning here quietly is a queue that never moves again for this
        // contact, with nothing anywhere to say why.
        crate::log_warn!(
            "the OTP queue's front entry for {contact_name} cannot be decoded, so \
             nothing behind it can be sent; the file in ~/.aloo/otp-outbox is \
             damaged and needs removing by hand (its pad position is already spent)"
        );
        return;
    };
    let (msg_id, channel) = (entry.msg_id(), entry.channel());
    // A recording is released differently from an inline payload - it is
    // a chunk stream, not one datagram - but on identical terms: it takes
    // the gate with its own sequence, and its acknowledgement is what
    // lets the next entry go.
    if let Some((cipher_path, stream_id)) = entry.recording() {
        release_queued_recording(
            wr,
            session,
            ui_state,
            contact_name,
            cipher_path,
            stream_id,
            seq,
            msg_id,
            ack_proof,
        )
        .await;
        return;
    }
    let Some(payload) = entry.payload() else {
        // A recording is the one entry with no inline payload, and that
        // branch returned above - so reaching here means the bytes are
        // damaged. Same reasoning as above: kept, and reported.
        crate::log_warn!(
            "the OTP queue's front entry for {contact_name} (position {seq}) carries \
             no readable payload, so nothing behind it can be sent; the file in \
             ~/.aloo/otp-outbox is damaged and needs removing by hand"
        );
        return;
    };
    // Armed before the send, not after: the gate is what stops a second
    // message following this one, and a send that raced ahead of it would
    // be exactly the out-of-order pair the receiver's pad cannot take.
    // What is recorded has to match what is actually going out: a queued
    // *voice offer* released from here is not a text message, and
    // recording it as one makes every later decision that reads
    // `pending_content` - which kind to re-send on recovery above all -
    // act on the wrong thing.
    let pending = match &payload {
        P2pPayload::OtpVoiceOffer { stream_id, .. } => {
            crate::client::otp_store::PendingOtpContent::Voice {
                stream_id: *stream_id,
                // Never read back - recovery re-sends an offer from its
                // `stream_id` alone - so nothing is stored to look it up
                // from.
                duration_ms: 0,
            }
        }
        _ => crate::client::otp_store::PendingOtpContent::Text { channel },
    };
    session.otp_store.record_sent(contact_name, seq, pending, Some(ack_proof));
    let _ = session.otp_store.save();
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(to, payload);
    if let Some(msg_id) = msg_id {
        // On the wire now, so it has stopped waiting.
        ui_state.mark_queued(to, msg_id, false);
        ui_state.mark_awaiting_pad_ack(to, msg_id);
        session
            .otp_ack_rows
            .insert((contact_name.to_string(), seq), msg_id);
    }
}

/// Puts a queued recording on the wire, its turn having come: the offer
/// that announced it has been acknowledged, so the receiver has already
/// registered the incoming stream (`on_voice_offer`) and is waiting for
/// exactly this.
///
/// The recipient and the chunk-transport key are both resolved *now*,
/// from the contact name - never from anything captured when the
/// recording was made, because for a recording held across an absence
/// that capture names the id the peer will never hold again. Whoever
/// they are at this moment is who the setups, the sequence announcement,
/// and the chunks are addressed to.
///
/// Arms the gate with `FileContent`, which is what hands a lost
/// acknowledgement (or a link that dies mid-stream) to the recovery pass
/// every file-content spend already uses
/// (`recover_and_resend_file_content`, from the CLI's own last-sent
/// copy). The entry itself stays at the front until the acknowledgement
/// arrives; its ciphertext file is deleted only then (`take_front`).
#[allow(clippy::too_many_arguments)]
async fn release_queued_recording(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    contact_name: &str,
    cipher_path: std::path::PathBuf,
    stream_id: u64,
    seq: u64,
    msg_id: Option<u64>,
    ack_proof: [u8; 32],
) {
    // Not reachable right now (their link is up but this contact cannot
    // be named to a live peer, or the key will not derive): leave the
    // entry at the front, untouched. The pump runs again on the next
    // link-up, acknowledgement, or device announce - the same triggers
    // every entry waits on.
    let Some((to, recipient_pubkey_der)) = peer_for_contact_name(session, ui_state, contact_name)
    else {
        return;
    };
    let Some(key) = otp_stream_key(session, stream_id, to, &recipient_pubkey_der) else {
        return;
    };
    session.otp_store.record_sent(
        contact_name,
        seq,
        crate::client::otp_store::PendingOtpContent::FileContent { stream_id },
        Some(ack_proof),
    );
    let _ = session.otp_store.save();
    session.peer_link.ensure_link(wr, to).await;
    for (id, setup) in key.setups() {
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
    }
    session
        .peer_link
        .send_reliable_or_queue(to, P2pPayload::OtpFileContentSeq { stream_id, seq });
    if let Some(msg_id) = msg_id {
        ui_state.mark_queued(to, msg_id, false);
        ui_state.mark_awaiting_pad_ack(to, msg_id);
        session
            .otp_ack_rows
            .insert((contact_name.to_string(), seq), msg_id);
    }
    session.otp_sending_streams.insert(stream_id, std::time::Instant::now());
    crate::client::file_transfer::spawn_send_file_worker(
        cipher_path,
        key,
        to,
        stream_id,
        session.record_out_tx.clone(),
        session.file_events_tx.clone(),
    );
}

/// Puts the outstanding message back on the wire, if the one the gate is
/// waiting on is still sitting at the front of the queue.
///
/// The gate (`pending_unacked_out_seq`) only ever opens on an ack, and it
/// is durable - so a message that left but was never answered would
/// otherwise wedge this contact's queue for good: `pump_otp_queue`
/// refuses to release the next one, and nothing re-sends the one that is
/// stuck. That is reachable without anything going wrong at the peer:
/// the process can be killed between the send and the ack, or the
/// transport can give up on an undeliverable frame while the peer is
/// away. Both leave a spent pad position with no message behind it,
/// which is the one thing this layer must never do.
///
/// Re-sending costs nothing and risks nothing. If the peer never got it,
/// this is the delivery. If they did and only the ack was lost, their
/// side recognises a sequence number their counter has already passed and
/// replies with the ack it recorded - no second pass over the pad
/// (`resend_recorded_ack`, `OtpStore::is_next_expected`).
///
/// Called when a link comes up, which is the moment a stuck queue can
/// newly become unstuck, and deliberately not on every pump: within a
/// live session the reliable layer is already retransmitting.
/// Returns whether anything was actually put back on the wire.
/// How long an outstanding pad send waits for its acknowledgement before
/// it is put back on the wire, and the ceiling the backoff climbs to.
///
/// The gate only ever opens on an acknowledgement, so an acknowledgement
/// that is lost while the link stays up wedges a contact's queue for good
/// - the link-up retry never fires, because the link never went down.
pub const OTP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
pub const OTP_RETRY_MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(60);

/// Puts an un-acknowledged pad send back on the wire once its wait has run
/// out, for every peer whose link is up.
///
/// Safe to repeat because nothing here re-encrypts: `retry_outstanding_otp_send`
/// re-sends the bytes already sealed, under the position they were sealed
/// at, and a receiver that has consumed that position answers it from its
/// durable record rather than decrypting it twice
/// (`resend_recorded_ack`). So a retry can neither spend a second pad
/// position nor deliver a message twice.
///
/// Three things hold it back, each of which could turn a recoverable lost
/// acknowledgement into an unrecoverable desync:
///
/// - **an encrypt in flight** - a seal is mid-operation and the store's
///   write-ahead intent is standing; retrying across it would race the tool
///   over one pad.
/// - **a send worker still running for the front's stream** - re-releasing
///   a recording mid-stream would put two workers on one `stream_id`, and
///   their interleaved chunks decrypt to something neither side's
///   `ack_proof` matches, so the gate would never open again.
/// - **a link that is not up** - a peer who is simply away is the queue's
///   business, not the retry's.
pub async fn tick_otp_retries(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    now: std::time::Instant,
) {
    let peers: Vec<UserId> = ui_state
        .known_users
        .keys()
        .copied()
        .filter(|peer| session.peer_link.is_active(*peer))
        .collect();
    let mut needs_recovery = false;
    for peer in peers {
        let Some(contact) = active_contact_name(session, ui_state, peer) else {
            session.otp_retry.remove(&peer);
            continue;
        };
        let outstanding = session
            .otp_store
            .get(&contact)
            .and_then(|s| s.pending_unacked_out_seq);
        if outstanding.is_none() {
            // Nothing owed, so nothing to wait on - and the next thing that
            // is owed starts its wait from scratch.
            session.otp_retry.remove(&peer);
            continue;
        }
        if session.otp_store.encrypt_in_flight(&contact) {
            continue;
        }
        // A recording whose worker has not finished is still being
        // delivered; its acknowledgement is not late yet.
        let front_stream = session
            .otp_outbox
            .as_ref()
            .and_then(|outbox| outbox.front(&contact))
            .and_then(|entry| entry.recording())
            .map(|(_, stream_id)| stream_id);
        if front_stream.is_some_and(|id| session.is_stream_sending(id, now)) {
            continue;
        }
        let (due, attempts) = *session
            .otp_retry
            .entry(peer)
            .or_insert((now + OTP_RETRY_DELAY, 0));
        if now < due {
            continue;
        }
        let next = OTP_RETRY_DELAY
            .saturating_mul(1u32 << attempts.min(4))
            .min(OTP_RETRY_MAX_DELAY);
        session.otp_retry.insert(peer, (now + next, attempts.saturating_add(1)));
        // The queue's own bytes first. With `queue_send_messages` off there
        // is no queue at all and this does nothing, which is what the
        // `.last_sent` recovery below is for - without it, an unqueued send
        // whose acknowledgement is lost while the link stays up would wedge
        // that contact exactly as the queued one used to.
        if !retry_outstanding_otp_send(wr, session, ui_state, peer, &contact).await {
            needs_recovery = true;
        }
        pump_otp_queue(wr, session, ui_state, peer, &contact).await;
    }
    if needs_recovery {
        // Skips anything the queue holds, and anything still streaming.
        let _ = recover_and_resend(wr, session, ui_state).await;
    }
}

pub(crate) async fn retry_outstanding_otp_send(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
) -> bool {
    let Some(waiting_on) = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
    else {
        return false;
    };
    let Some(outbox) = session.otp_outbox.as_ref() else {
        return false;
    };
    // Only the front, and only if it is the very message the gate names.
    // Anything else means the gate belongs to a send this queue is not
    // responsible for, and re-sending from here would break the order.
    let Some(entry) = outbox.front(contact_name) else {
        return false;
    };
    if entry.seq() != Some(waiting_on) {
        return false;
    }
    // A recording front is put back on the wire from its own ciphertext
    // file, by re-running its release - fresh key, fresh recipient, full
    // chunk stream. Never from the CLI's `.last_sent` copy, which later
    // seals have overwritten (see `recover_and_resend`'s matching skip).
    if let Some((cipher_path, stream_id)) = entry.recording() {
        let (msg_id, ack_proof) = (entry.msg_id(), entry.ack_proof());
        let Some(ack_proof) = ack_proof else {
            return false;
        };
        release_queued_recording(
            wr,
            session,
            ui_state,
            contact_name,
            cipher_path,
            stream_id,
            waiting_on,
            msg_id,
            ack_proof,
        )
        .await;
        return true;
    }
    let Some(payload) = entry.payload() else {
        return false;
    };
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(to, payload);
    true
}

/// Whether a new spend for `contact_name` must wait as plaintext rather
/// than be sealed now (`send_or_queue`'s doc explains the why at length):
///
/// - an encrypt is mid-flight for the contact (`encrypt_intent` standing -
///   a same-process second seal would race the tool over one pad), or a
///   reconciled spend is parked awaiting promotion (`deferred_spend`);
/// - or a send is outstanding that the durable queue does *not* hold at
///   its front, so its only retry copy is the tool's one-deep `.last_sent`,
///   which the next seal would overwrite.
///
/// A send the queue front *is* imposes nothing: the queue owns its retry
/// bytes, so sealing more behind it is exactly what the queue is for.
pub(crate) fn must_hold_plaintext(session: &SessionState, contact_name: &str) -> bool {
    if session.otp_store.encrypt_in_flight(contact_name) {
        return true;
    }
    let Some(outstanding) = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
    else {
        return false;
    };
    let queue_front = session
        .otp_outbox
        .as_ref()
        .and_then(|outbox| outbox.front(contact_name))
        .and_then(|entry| entry.seq());
    queue_front != Some(outstanding)
}

/// Entry point for `direct_message::handle_send_text`/`channel::handle_send_text`
/// once they've established `contact_name_if_active` returns `Some` for a
/// recipient: sends immediately if the contact's previous OTP message has
/// already been acked, otherwise queues it for `on_delivery_ack` to flush.
///
/// `log_index` is the row this text was optimistically logged under
/// (`UiState::push_outgoing_dm`) - `Some` for a DM send, always `None` for
/// a channel send (`channel: Some(_)`), since a channel row can be OTP-wrapped
/// independently per recipient and there is no single row a "this one
/// failed" mark could unambiguously apply to.
#[allow(clippy::too_many_arguments)]
pub async fn send_or_queue(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
    recipient_pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
    channel: Option<String>,
    log_index: Option<usize>,
    msg_id: Option<u64>,
) -> proto::Result<()> {
    // An end handshake in flight: the session is still nominally active on
    // this side (it pauses only on the peer's confirmation -
    // `handle_end_otp_command`'s two-phase design), but nothing new may
    // enter a pad whose next occupant is the end notice - queueing it would
    // only have it sent, or silently discarded, after the session the user
    // just asked to end. Refused out loud instead; `/otp` cancels a pending
    // end if they change their mind.
    if session
        .otp_store
        .get(contact_name)
        .is_some_and(|s| s.pending_end_notice)
    {
        let peer_name = peer_name_for(ui_state, to);
        notify(
            ui_state,
            to,
            &peer_name,
            format!(
                "OTP: the session with {peer_name} is ending - waiting for their \
                 confirmation - message not sent"
            ),
            false,
        );
        if let Some(idx) = log_index {
            ui_state.mark_dm_message_failed(to, idx);
        }
        return Ok(());
    }
    // The pad as a second factor, folded into the same gate. Holding the
    // identity key that selects a contact is not the same as holding that
    // contact's pad, and the only way to clear `pending_unacked_out_seq` is
    // an acknowledgement carrying the proof buried under that pad. So one
    // message goes out on the strength of the identity alone, and
    // everything after it waits until the peer has demonstrated possession.
    //
    // The bound is what matters: a peer with a stolen identity key but no
    // pad extracts exactly one message, and even that is not lost - nothing
    // overwrites its `.last_sent` copy while this gate holds, so it is
    // still deliverable to the genuine contact afterwards.
    //
    // With the durable queue behind us, the gate no longer decides whether
    // to *encrypt* - a message is sealed the moment it is written, its pad
    // position spent there and then, and the gate decides only which
    // sealed message may be on the wire. With one exception, and it is the
    // whole of `must_hold_plaintext`: sealing ahead is only safe while the
    // outstanding message is one the queue holds, because the queue is
    // what retries it. A spend the queue never held - a file offer, a
    // file's content, the end notice, a text sent before the queue existed
    // - is retried from the tool's `.last_sent` copy, which is one deep and
    // overwritten by every seal; a text sealed behind it would replace the
    // only recoverable copy of a message the peer's decoder is still
    // waiting on, and recovery would then replay the text's bytes under
    // the offer's sequence forever. So while such a spend is outstanding
    // the text waits here as plaintext, in memory, and `flush_one_queued`
    // seals it the moment that spend's genuine acknowledgement arrives.
    if must_hold_plaintext(session, contact_name) {
        let item = match channel {
            Some(ch) => PendingOtpSend::Channel {
                channel: ch,
                to,
                plaintext: plaintext.to_vec(),
                content,
                msg_id,
            },
            None => PendingOtpSend::Direct {
                to,
                plaintext: plaintext.to_vec(),
                content,
                log_index,
                msg_id,
            },
        };
        session
            .otp_out_queue
            .enqueue(contact_name.to_string(), item);
        // The row says so too, the same as a message the durable queue
        // holds (AC-439) and the same as one the ordinary outbox holds.
        // Without it this is the only kind of held message that looks
        // exactly like one already on the wire.
        if let Some(msg_id) = msg_id {
            ui_state.mark_queued(to, msg_id, true);
        }
        // Always surfaced, even though the common case (a fast, healthy
        // round trip) clears almost immediately: held back silently, a
        // message looks identical to one that was never sent, which is
        // what would make a genuinely stuck gate (e.g. stale
        // pending_unacked_out_seq state) indistinguishable from things
        // working.
        let peer_name = peer_name_for(ui_state, to);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: message queued - waiting for the previous one to be acknowledged".to_string(),
            true,
        );
        Ok(())
    } else {
        send_now(
            wr,
            session,
            ui_state,
            to,
            contact_name,
            recipient_pubkey_der,
            plaintext,
            content,
            channel,
            log_index,
            msg_id,
        )
        .await
    }
}

/// Sends a file offer under an active OTP session - `direct_message::
/// handle_send_file`'s entry point once `contact_name_if_active` returns
/// `Some`. The *offer* (filename + size) is a genuine pad spend in its own
/// right - wrapped through `otp --encrypt` exactly like a text message
/// (`wrap_outgoing`) - see docs/PROTOCOL.md 16.2 for why paying a bit of
/// pad on every offer, including ones later rejected, is an accepted
/// tradeoff for keeping the filename off the wire in the clear.
///
/// This is the *offer* phase's pad spend only: `record_sent` fires right
/// after `wrap_outgoing` succeeds, the same reserve-after-genuinely-spent
/// ordering `send_now` uses for text, so there is never a window where the
/// gate is reserved but nothing was actually encrypted - a rejected offer
/// needs no local gate release, since the offer itself already earned its
/// own ack (sent the moment the peer decrypts and queues it for the
/// popup, `on_file_offer`) independent of whether the user has decided to
/// accept yet. If that ack is lost - the peer never replies, or goes
/// offline before it can - the only way forward is `recover_and_resend`:
/// the pad was genuinely spent the instant this function's
/// `wrap_outgoing` succeeded, so nothing may ever re-encrypt a fresh offer
/// for this contact until either a real ack arrives or the exact same
/// ciphertext is recovered and resent.
///
/// The file's actual *content* is a wholly separate, later pad spend, only
/// reserved once the offer is genuinely accepted
/// (`start_outgoing_file_content`, `P2pEvent::FileAccepted`'s handling in
/// `session.rs`) - two independent slots, two independent acks, since the
/// pad tool never allows a second `--encrypt` before the first is
/// confirmed delivered.
///
/// A busy gate is refused outright rather than queued the way `send_or_queue`
/// queues text - replaying a whole file path/filename/size through the
/// in-memory `PendingOtpSend` queue across a possible reconnect is a lot
/// of extra state for a case the user can simply retry a moment later.
#[allow(clippy::too_many_arguments)]
pub async fn send_file_offer(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
    recipient_pubkey_der: &[u8],
    path: std::path::PathBuf,
    filename: String,
    size: u64,
) -> proto::Result<()> {
    let peer_name = peer_name_for(ui_state, to);
    let unacked = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some()
        || session.otp_store.encrypt_in_flight(contact_name);
    if unacked {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: a previous send to this contact hasn't been acknowledged yet - try sending this file again shortly".to_string(),
            false,
        );
        return Ok(());
    }
    let file_payload = crate::client::file_transfer::FileOfferPayload {
        filename: filename.clone(),
        size,
    };
    let Ok(plaintext) = proto::encode(&file_payload) else {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to build the file offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let stream_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(key) = otp_stream_key(session, stream_id, to, recipient_pubkey_der) else {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to prepare the file transfer key - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    // Written ahead of the encrypt, so a kill inside its window leaves a
    // reconcilable record instead of an orphaned spend
    // (`OtpContactState::encrypt_intent`).
    if !stage_encrypt_intent(
        session,
        contact_name,
        crate::client::otp_store::PendingOtpContent::File {
            stream_id,
            filename: filename.clone(),
            size,
        },
    ) {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: could not record this send before encrypting - the file offer was not sent"
                .to_string(),
            false,
        );
        return Ok(());
    }
    let Some((otp_envelope, ack_proof)) = build_otp_envelope(
        session,
        to,
        recipient_pubkey_der,
        contact_name,
        None,
        stream_id,
        &plaintext,
        Content::FileOffer,
    )
    .await
    else {
        session.otp_store.clear_encrypt_intent(contact_name);
        let _ = session.otp_store.save();
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to encrypt this file offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let seq = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    session.otp_store.record_sent(
        contact_name,
        seq,
        crate::client::otp_store::PendingOtpContent::File {
            stream_id,
            filename: filename.clone(),
            size,
        },
        Some(ack_proof),
    );
    let _ = session.otp_store.save();
    if let Some(detail) = refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await {
        end_live_session_if_exhausted(session, ui_state, to, &detail, contact_name).await;
    }
    let (msg_id, delivery) = ui_state.start_delivery(&[to]);
    ui_state.log_own_file_offer_dm(to, stream_id, filename.clone(), size, Some(delivery));
    // Staged durably before the offer goes out, so a restart between now
    // and the peer's acceptance still resumes rather than silently losing
    // the file (`OtpStore::PendingContentSend`'s doc,
    // `resume_pending_content_sends`).
    session
        .otp_store
        .stage_content_send(stream_id, contact_name, path.clone());
    let _ = session.otp_store.save();
    session.own_file_targets.insert(
        stream_id,
        crate::client::file_transfer::OwnFileTarget {
            to,
            path,
            key,
            otp: Some(contact_name.to_string()),
        },
    );
    session.peer_link.ensure_link(wr, to).await;
    let own_device_id = session.own_device_id.clone();
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpFileOffer {
            channel: None,
            stream_id,
            seq,
            msg_id: Some(msg_id),
            envelope: otp_envelope,
            sender_device_id: own_device_id,
        },
    );
    ui_state.mark_awaiting_pad_ack(to, msg_id);
    session
        .otp_ack_rows
        .insert((contact_name.to_string(), seq), msg_id);
    crate::client::session::request_rotation(session, to);
    Ok(())
}

/// Sends one finished voice recording under OTP - `pcm` is the complete,
/// already-recorded PCM16 bytes (`voice_stream::spawn_record_accumulate_worker`'s
/// output), not a live stream. Unlike `send_file_offer`, there's no
/// separate accept step to defer content-encryption to (voice auto-accepts,
/// no popup - `Content::VoiceOffer`'s doc), so the one genuine `otp
/// --encrypt` for this send happens right here, before anything is
/// reserved or sent - simpler than the file path, and (like every other
/// pad spend in this module) only ever reserved *after* it genuinely
/// succeeds, so a failure here needs no gate release either. Once
/// encrypted, streams out exactly like a file: registers an
/// ordinary `OwnFileTarget` (with `otp: None` - the content is already
/// ciphertext, nothing left for `FileAccepted` to do) and sends
/// `OtpVoiceOffer`; the peer's `FileAccept` (auto-sent, no popup on their
/// end either) triggers the existing chunked send worker unchanged.
/// `send_voice_offer` when the durable queue is on: the voice message is
/// sealed *now* and held, so it reaches someone who is not there in
/// exactly the way a text message does.
///
/// Both of its pad positions are spent here, in the order the peer will
/// read them - the offer that announces the recording, then the recording
/// itself - because sealing is spending, and a position that is spent has
/// to be one the peer will eventually be given. Consequences, all
/// deliberate:
///
/// - Nothing readable waits on disk. Today's unqueued path stages the raw
///   recording and encrypts it when the peer accepts, which for someone
///   who is away could be days; this stages ciphertext instead.
/// - The remaining key is checked *first*. A recording is orders of
///   magnitude larger than a line of text, so "it did not fit" has to be
///   answered before any of it is spent rather than half way through.
/// - The offer joins the queue and the recording joins it right behind,
///   as its own entry referencing its own ciphertext file
///   (`otp_outbox::queue_recording`). One sequence, one store: nothing
///   can overtake the recording because nothing is ahead of its place in
///   line, and its acknowledgement - like any entry's - is what releases
///   whatever was written after it.
#[allow(clippy::too_many_arguments)]
async fn send_voice_offer_queued(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
    recipient_pubkey_der: &[u8],
    pcm: Vec<u8>,
    duration_ms: u32,
) -> proto::Result<()> {
    let peer_name = peer_name_for(ui_state, to);
    let fail = |ui_state: &mut UiState, message: String| {
        notify(ui_state, to, &peer_name, message, false);
    };

    // Sealing ahead is only safe behind a spend the queue itself holds
    // (`must_hold_plaintext`'s doc): behind a file offer, a file's content
    // or an end notice still awaiting its acknowledgement, these two seals
    // would overwrite the tool's one-deep `.last_sent` copy - the only bytes
    // that spend can be recovered from. Refused rather than held: unlike a
    // text there is no in-memory plaintext queue shaped for a recording,
    // and the user can simply record again once that send is acknowledged.
    if must_hold_plaintext(session, contact_name) {
        fail(
            ui_state,
            "OTP: a previous send to this contact hasn't been acknowledged yet - this voice message wasn't sent".to_string(),
        );
        return Ok(());
    }

    let payload = crate::client::file_transfer::VoiceOfferPayload { duration_ms };
    let Ok(offer_plaintext) = proto::encode(&payload) else {
        fail(ui_state, "OTP: failed to build the voice offer - not sent".to_string());
        return Ok(());
    };

    // Asked before anything is spent: the offer and the recording are
    // both about to come out of this contact's key, and half of a voice
    // message is worse than none of it.
    let needed = pcm.len() as u64 + offer_plaintext.len() as u64;
    let remaining = otp_cli::show_contact(&session.otp_cli_cfg, contact_name)
        .await
        .ok()
        .flatten()
        .map(|detail| detail.enc_key_remaining);
    if let Some(remaining) = remaining
        && needed >= remaining
    {
        fail(
            ui_state,
            format!(
                "OTP: not enough key left for a {} recording ({} remaining) - not sent",
                crate::client::tui::render::format_duration_label(duration_ms),
                crate::client::tui::ui::format_file_size(remaining)
            ),
        );
        return Ok(());
    }

    let stream_id = session.next_stream_id;
    session.next_stream_id += 1;
    // No stream key is derived here: the recording's chunk-transport key
    // is derived when its turn in the queue comes (`release_queued_recording`),
    // against whoever the peer is *then* - which is what makes a recording
    // held across their absence reach the id they return under.

    // --- the offer's position -------------------------------------------
    if !stage_encrypt_intent(
        session,
        contact_name,
        crate::client::otp_store::PendingOtpContent::Voice {
            stream_id,
            duration_ms,
        },
    ) {
        fail(
            ui_state,
            "OTP: could not record this send before encrypting - nothing was sent".to_string(),
        );
        return Ok(());
    }
    let Some((envelope, offer_proof)) = build_otp_envelope(
        session,
        to,
        recipient_pubkey_der,
        contact_name,
        None,
        stream_id,
        &offer_plaintext,
        Content::VoiceOffer,
    )
    .await
    else {
        session.otp_store.clear_encrypt_intent(contact_name);
        let _ = session.otp_store.save();
        fail(
            ui_state,
            "OTP: failed to encrypt this voice offer - not sent".to_string(),
        );
        return Ok(());
    };
    let offer_seq = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    session.otp_store.record_sealed(contact_name, offer_seq);
    let _ = session.otp_store.save();

    // --- the recording's position ---------------------------------------
    // Sealed now and queued as its own entry, right behind the offer that
    // announces it: one sequence, one store, delivered in order one
    // acknowledgement at a time exactly like a text message. Its
    // ciphertext is a *file* - that is what `otp --encrypt` produces for
    // one, and it can be megabytes - so the entry holds a reference to a
    // file the queue itself owns (`otp_outbox::recording_path_for`)
    // rather than an inline copy.
    let content_seq = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    let cipher_path = session
        .otp_outbox
        .as_ref()
        .and_then(|outbox| outbox.recording_path_for(contact_name, content_seq));
    // Staged plaintext only long enough to feed the encrypt, and wiped
    // immediately after: what waits for the peer is the ciphertext.
    let plain_path = temp_content_path(&session.otp_cli_cfg, "otp-voice-plain");
    let staged = std::fs::write(&plain_path, &pcm).is_ok();
    restrict_file_permissions(&plain_path);
    // Computed over the plaintext, as everywhere else: the recording's own
    // bytes are the pad plaintext, so there is no room to bury a nonce.
    let content_proof = crate::crypto::otp::ack_proof_for_file(&plain_path).ok();
    let (Some(cipher_path), Some(content_proof), true) = (cipher_path, content_proof, staged)
    else {
        secure_remove_file(&plain_path);
        // The offer's position is already spent and already queued, so it
        // still goes: the peer reads the announcement and the recording
        // simply never follows - visible and harmless. Nothing was spent
        // for the recording itself.
        fail(
            ui_state,
            "OTP: failed to stage this voice message - the offer was sent without it".to_string(),
        );
        return Ok(());
    };
    if !stage_encrypt_intent(
        session,
        contact_name,
        crate::client::otp_store::PendingOtpContent::FileContent { stream_id },
    ) {
        secure_remove_file(&plain_path);
        fail(
            ui_state,
            "OTP: could not record this send before encrypting - the recording was not sent"
                .to_string(),
        );
        return Ok(());
    }
    let encrypted = otp_cli::encrypt_file_retrying(
        &session.otp_cli_cfg,
        contact_name,
        &plain_path,
        &cipher_path,
        true,
    )
    .await;
    secure_remove_file(&plain_path);
    if !matches!(encrypted, Ok(otp_cli::FileCliOutcome::Ok)) {
        session.otp_store.clear_encrypt_intent(contact_name);
        let _ = session.otp_store.save();
        secure_remove_file(&cipher_path);
        // Returns here, and that is the whole point: nothing below may
        // run. Reserving a position for a recording that does not exist
        // would advance this side's counter past the pad, and the
        // receiver's own counter admits no gaps
        // (`OtpStore::is_next_expected`) - every later message would be
        // refused. Leaving it alone keeps the two in step: the offer's
        // position was genuinely spent and is genuinely queued, so the
        // peer reads the offer, expects the next position, and gets it
        // from whatever is written next. What they are left with is an
        // announcement for a recording that never arrives, which is
        // visible and harmless, rather than a pad that no longer lines
        // up, which is neither.
        fail(
            ui_state,
            "OTP: failed to encrypt this voice message - it was not sent".to_string(),
        );
        return Ok(());
    }
    restrict_file_permissions(&cipher_path);
    session.otp_store.record_sealed(contact_name, content_seq);
    let _ = session.otp_store.save();

    // --- queued, and sent when its turn comes ---------------------------
    let msg_id = ui_state.own_stream_msg_id(stream_id);
    let own_device_id = session.own_device_id.clone();
    let offer = P2pPayload::OtpVoiceOffer {
        stream_id,
        seq: offer_seq,
        msg_id,
        envelope,
        sender_device_id: own_device_id,
    };
    if let Some(outbox) = session.otp_outbox.as_mut() {
        match outbox.queue(contact_name, &offer, offer_seq, msg_id, None, offer_proof) {
            Ok(true) => {}
            // Same rule as a text message whose queue would not take it
            // (`send_now`): the position is spent, so it goes now rather
            // than being dropped.
            Ok(false) | Err(_) => {
                session.otp_store.record_sent(
                    contact_name,
                    offer_seq,
                    crate::client::otp_store::PendingOtpContent::Voice {
                        stream_id,
                        duration_ms,
                    },
                    Some(offer_proof),
                );
                let _ = session.otp_store.save();
                session.peer_link.ensure_link(wr, to).await;
                session.peer_link.send_reliable_or_queue(to, offer);
                if let Some(msg_id) = msg_id {
                    ui_state.mark_awaiting_pad_ack(to, msg_id);
                    session
                        .otp_ack_rows
                        .insert((contact_name.to_string(), offer_seq), msg_id);
                }
            }
        }
        // The recording itself, straight behind the offer that announces
        // it. Same row (`msg_id`): the row belongs to the voice message as
        // a whole, and it is this entry's acknowledgement - the bytes
        // themselves landing - that finally marks it delivered.
        match outbox.queue_recording(
            contact_name,
            &cipher_path,
            stream_id,
            content_seq,
            msg_id,
            content_proof,
        ) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                // The queue would not take it, but its position is spent
                // and its ciphertext exists. Leave the file in place and
                // warn: `recover_and_resend`'s FileContent arm can still
                // resend it from the CLI's own last-sent copy once the
                // gate reaches it. Losing the file here would orphan the
                // position for good.
                crate::log_warn!(
                    "the OTP queue would not take a sealed recording; it stays on disk at {}",
                    cipher_path.display()
                );
            }
        }
    }
    // A voice message the queue is holding says so on its row, exactly as
    // a text does. It never passes through `send_now`, so it would
    // otherwise be the one queued thing that looks identical to a message
    // already on the wire. `pump_otp_queue` clears it below the moment the
    // offer actually goes out.
    if let Some(msg_id) = msg_id {
        ui_state.mark_queued(to, msg_id, true);
    }
    if let Some(detail) =
        refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await
    {
        end_live_session_if_exhausted(session, ui_state, to, &detail, contact_name).await;
    }
    pump_otp_queue(wr, session, ui_state, to, contact_name).await;
    crate::client::session::request_rotation(session, to);
    Ok(())
}

pub async fn send_voice_offer(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    contact_name: &str,
    recipient_pubkey_der: &[u8],
    pcm: Vec<u8>,
    duration_ms: u32,
) -> proto::Result<()> {
    let peer_name = peer_name_for(ui_state, to);
    // With a durable queue behind us a voice message is held exactly like
    // a text one: sealed when it is recorded, queued, and delivered in
    // write order one acknowledgement at a time - so being unable to
    // reach them, or having something still unacknowledged, is no longer
    // a reason to refuse it.
    if session.queue_send_messages {
        return send_voice_offer_queued(
            wr,
            session,
            ui_state,
            to,
            contact_name,
            recipient_pubkey_der,
            pcm,
            duration_ms,
        )
        .await;
    }
    let unacked = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some()
        || session.otp_store.encrypt_in_flight(contact_name);
    if unacked {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: a previous send to this contact hasn't been acknowledged yet - this voice message wasn't sent".to_string(),
            false,
        );
        return Ok(());
    }
    // Staged as plaintext and left that way: the recording is the
    // *content* phase's payload, and that phase does its own `otp
    // --encrypt` once this offer has been acknowledged
    // (`start_outgoing_file_content`), exactly as a file's does. Encrypting
    // it here instead would reserve a pad slot before the offer that
    // announces it, so a lost offer would strand the later one.
    let plain_path = temp_content_path(&session.otp_cli_cfg, "otp-voice-plain");
    if std::fs::write(&plain_path, &pcm).is_err() {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to stage this voice message - not sent".to_string(),
            false,
        );
        return Ok(());
    }
    restrict_file_permissions(&plain_path);
    let payload = crate::client::file_transfer::VoiceOfferPayload { duration_ms };
    let Ok(plaintext) = proto::encode(&payload) else {
        secure_remove_file(&plain_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to build the voice offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let stream_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(key) = otp_stream_key(session, stream_id, to, recipient_pubkey_der) else {
        secure_remove_file(&plain_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to prepare the voice message key - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    // Written ahead of the encrypt, so a kill inside its window leaves a
    // reconcilable record instead of an orphaned spend
    // (`OtpContactState::encrypt_intent`).
    if !stage_encrypt_intent(
        session,
        contact_name,
        crate::client::otp_store::PendingOtpContent::Voice {
            stream_id,
            duration_ms,
        },
    ) {
        secure_remove_file(&plain_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: could not record this send before encrypting - not sent".to_string(),
            false,
        );
        return Ok(());
    }
    // The offer goes through the pad exactly like a file's, so
    // `duration_ms` never travels in the clear - under `Direct` there is no
    // envelope to hide it in, and under `PqWrapped` the pad is the layer
    // that actually protects what is said to this contact anyway.
    let Some((envelope, ack_proof)) = build_otp_envelope(
        session,
        to,
        recipient_pubkey_der,
        contact_name,
        None,
        stream_id,
        &plaintext,
        Content::VoiceOffer,
    )
    .await
    else {
        session.otp_store.clear_encrypt_intent(contact_name);
        let _ = session.otp_store.save();
        secure_remove_file(&plain_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to encrypt this voice offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let seq = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    session.otp_store.record_sent(
        contact_name,
        seq,
        crate::client::otp_store::PendingOtpContent::Voice {
            stream_id,
            duration_ms,
        },
        Some(ack_proof),
    );
    let _ = session.otp_store.save();
    if let Some(detail) = refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await {
        end_live_session_if_exhausted(session, ui_state, to, &detail, contact_name).await;
    }
    // Staged durably before the offer goes out, so a restart between now
    // and the peer's acceptance still resumes rather than silently losing
    // the recording (`OtpStore::PendingContentSend`'s doc,
    // `resume_pending_content_sends`).
    session
        .otp_store
        .stage_content_send(stream_id, contact_name, plain_path.clone());
    let _ = session.otp_store.save();
    session.own_file_targets.insert(
        stream_id,
        crate::client::file_transfer::OwnFileTarget {
            to,
            path: plain_path,
            key,
            otp: Some(contact_name.to_string()),
        },
    );
    session.peer_link.ensure_link(wr, to).await;
    let msg_id = ui_state.own_stream_msg_id(stream_id);
    let own_device_id = session.own_device_id.clone();
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpVoiceOffer {
            stream_id,
            seq,
            msg_id,
            envelope,
            sender_device_id: own_device_id,
        },
    );
    if let Some(msg_id) = msg_id {
        ui_state.mark_awaiting_pad_ack(to, msg_id);
        session
            .otp_ack_rows
            .insert((contact_name.to_string(), seq), msg_id);
    }
    crate::client::session::request_rotation(session, to);
    Ok(())
}

/// Applies an incoming `P2pEvent::OtpMessage`'s envelope: opens the seal
/// if this pair has one, then the pad (`open_otp_envelope`), then routes
/// the recovered payload by `envelope.content`.
///
/// Three payloads arrive this way - a text message and the two
/// session-control notices - because all three are padded the same way and
/// share the same sequence space. Only text earns an `OtpDeliveryAck`, and
/// only once local delivery has actually succeeded; see the module doc for
/// why that's always safe to do immediately and unconditionally, unlike
/// the encrypt side's ack-gating.
#[allow(clippy::too_many_arguments)]
pub async fn on_message(
    session: &mut SessionState,
    ui_state: &mut UiState,
    channel: Option<String>,
    from: UserId,
    from_name: String,
    seq: u64,
    // Carried for symmetry with an ordinary send, and read by the *sender*
    // to find this message's own row - never consumed here, because a
    // pad-protected leg reports its delivery through `OtpDeliveryAck`
    // rather than through the `DeliveryReceipt` this id would name
    // (`client::tui::ui::DeliveryProof`).
    msg_id: Option<u64>,
    envelope: Envelope,
    sender_device_id: String,
) -> proto::Result<()> {
    let Some(sender) = otp_sender_of(session, ui_state, from) else {
        // `otp_sender_of` fails for exactly two reasons: `direct_nickname_of`
        // fails (an unconfigured nickname, untouched by this feature), or it
        // succeeds but `direct_peer_identity`/`id_store.get` fails - a
        // `direct_punch_to` target with no key pinned at all. Offer to check
        // whether this proof matches a *pq_hybrid* key already pinned under a
        // different nickname (`docs/PROTOCOL.md` §7.1.5) - never against a
        // pad-only pin, which would mean running real key material against
        // an unverified ciphertext for every pad held, not just this one.
        if let Some(nickname) = session.peer_link.direct_nickname_of(from)
            && session.id_store.get(&nickname).is_none()
            && let Some(addr) = session.peer_link.active_addr(from)
        {
            ui_state.push_unknown_peer_review(
                from,
                nickname,
                crate::client::tui::ui::UnverifiedDirectProof::OtpMessage {
                    channel,
                    seq,
                    msg_id,
                    envelope,
                },
                addr,
            );
        }
        return Ok(());
    };
    let Some(contact_name) = contact_name_for_peer(session, from, &sender.public_key_der) else {
        return Ok(());
    };
    // Text and the two session-control payloads all arrive this way; the
    // pad does not care which, and neither does anything above until the
    // plaintext is back (`build_otp_envelope`).
    if !matches!(
        envelope.content,
        Content::Text | Content::OtpEndSession | Content::OtpEndSessionAck
    ) {
        return Ok(());
    }
    // Checked *before* `otp --decrypt` runs, not after - a resend of a
    // message this contact's counter already moved past (the peer decrypted
    // it fine; only the ack got lost) must never reach the pad a second
    // time. See `OtpStore::is_next_expected`'s doc.
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        // The peer only retries an already-accepted message because the
        // ack this side already sent for it never arrived - staying silent
        // would leave their single-outstanding-send gate
        // (`pending_unacked_out_seq`) wedged forever, since nothing else
        // will ever unstick it. Re-send the recorded ack instead, at no
        // further cost: no re-decrypt, no pad. A repeated `/endotp` notice
        // is answered by the exact same mechanism - it is an ordinary
        // gated send now, and its acceptance recorded the same durable
        // `(seq, proof)` every accepted text does
        // (`OtpStore::ack_to_resend`'s doc).
        if matches!(envelope.content, Content::Text | Content::OtpEndSession) {
            resend_recorded_ack(session, from, &contact_name, seq);
        }
        return Ok(());
    }
    // Taken *before* the decrypt spends this message's key bytes: the row
    // logged below records which part of the pad was this message's, and
    // `otp --show-contact` only ever reports where the pad has already
    // got to (`UiState::message_crypto`). The post-spend refresh that
    // keeps the room's own header live still happens, further down.
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &contact_name).await;
    let Some((plaintext, ack_proof)) = open_otp_envelope(
        session,
        ui_state,
        from,
        &sender,
        &from_name,
        &contact_name,
        channel.as_deref(),
        &envelope,
        &sender_device_id,
    )
    .await
    else {
        return Ok(());
    };
    if !session.otp_store.record_received(&contact_name, seq) {
        return Ok(());
    }
    apply_otp_message(
        session,
        ui_state,
        channel,
        from,
        from_name,
        seq,
        &sender,
        &contact_name,
        envelope.content,
        plaintext,
        ack_proof,
    )
    .await
}

/// The registration/dispatch half of `on_message`, factored out so a
/// confirmed unknown-peer match (`session::handle_ui_action`'s
/// `ConfirmUnknownPeerKey` arm, `docs/PROTOCOL.md` §7.1.5) can finish it
/// from the plaintext the scan already recovered. Never re-decrypt for that
/// case: the pad's own position has already moved past that ciphertext by
/// the time a match is found, so a second attempt would be rejected as a
/// replay rather than repeating the same result.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_otp_message(
    session: &mut SessionState,
    ui_state: &mut UiState,
    channel: Option<String>,
    from: UserId,
    from_name: String,
    seq: u64,
    sender: &UserInfo,
    contact_name: &str,
    content: Content,
    plaintext: Vec<u8>,
    ack_proof: crypto::otp::AckProof,
) -> proto::Result<()> {
    // The pad opened it, so this really is who the link claims - see
    // `otp_sender_of`. Registering here is what lets the reply go back.
    adopt_pad_verified_sender(ui_state, from, sender);
    match content {
        Content::Text => {
            let body = crate::client::tui::ui::MessageBody::Text(
                String::from_utf8_lossy(&plaintext).into_owned(),
            );
            // The pad layer carries ordinary text, so it earns the same
            // `@<nickname>` ping the pq_hybrid path gets (`channel::on_message`).
            let mentions_me = ui_state.message_mentions_me(&body);
            match &channel {
                Some(ch) => ui_state.on_channel_message(ch, from, from_name, body),
                None => ui_state.on_direct_message(from, from_name, body),
            }
            if mentions_me {
                crate::client::voice_stream::play_ping_chime(session);
            }
            refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, contact_name).await;
            // No ordinary `DeliveryReceipt` here. It would say exactly what
            // the ack below already says, except unprovenly - and the sender's
            // row would ignore it anyway, since a pad-protected leg accepts
            // only the pad's own acknowledgement (`DeliveryProof`).
            crate::client::session::request_rotation(session, from);
            session.peer_link.send_reliable_or_queue(
                from,
                P2pPayload::OtpDeliveryAck {
                    seq,
                    proof: ack_proof,
                },
            );
            // Durable so a repeat of this exact message (this ack lost in
            // transit) can be answered again later without re-decrypting -
            // see `on_message`'s duplicate branch and `ack_to_resend`'s doc.
            session
                .otp_store
                .record_last_received_ack(contact_name, seq, ack_proof);
            let _ = session.otp_store.save();
        }
        Content::OtpEndSession => {
            let Ok(payload) = proto::decode::<crypto::otp::OtpEndSessionPayload>(&plaintext) else {
                return Ok(());
            };
            apply_end_session(session, ui_state, from, from_name, payload).await;
            // The notice is an ordinary stop-and-wait send on the peer's
            // side now (`PendingOtpContent::EndNotice`), so it earns the
            // ordinary proof-carrying acknowledgement - and the same
            // durable re-ack record every other accepted message gets, so
            // a repeat of it (this ack lost) is answered again without a
            // re-decrypt (`on_message`'s duplicate branch).
            session.peer_link.send_reliable_or_queue(
                from,
                P2pPayload::OtpDeliveryAck {
                    seq,
                    proof: ack_proof,
                },
            );
            session
                .otp_store
                .record_last_received_ack(contact_name, seq, ack_proof);
            let _ = session.otp_store.save();
        }
        // Legacy: the sealed, unpadded fallback's confirmation used to
        // travel padded too, from peers running the older flow - still
        // honoured so their retries stop, but never sent padded any more.
        Content::OtpEndSessionAck => {
            let Ok(payload) = proto::decode::<crypto::otp::OtpEndSessionPayload>(&plaintext) else {
                return Ok(());
            };
            apply_end_session_ack(session, payload);
        }
        _ => {}
    }
    Ok(())
}

/// `on_message`'s file-offer counterpart, for `P2pEvent::OtpFileOffer` -
/// mirrors `session::handle_incoming_file_offer`'s Pending/Rejected-hold
/// and popup logic, but with `on_message`'s own OTP-unwrap-then-ack shape:
/// the envelope here is genuinely OTP-wrapped, exactly like a text message
/// (`send_file_offer`'s doc), so it must be unwrapped through `otp
/// --decrypt` before it can be opened, and once delivered - queued for the
/// popup, or held pending trust - earns its own `OtpDeliveryAck`
/// immediately, independent of whether the user has decided to accept yet.
/// That ack only closes the *offer* phase's gate; the file's actual
/// content, once accepted, reserves and acks a wholly separate slot
/// (`start_outgoing_file_content`, `finish_incoming_file`).
#[allow(clippy::too_many_arguments)]
pub async fn on_file_offer(
    session: &mut SessionState,
    ui_state: &mut UiState,
    channel: Option<String>,
    from: UserId,
    from_name: String,
    stream_id: u64,
    seq: u64,
    envelope: Envelope,
    sender_device_id: String,
) {
    let Some((sender, contact_name)) = otp_sender_and_contact(session, ui_state, from) else {
        return;
    };
    if envelope.content != Content::FileOffer {
        return;
    }
    // Checked *before* `otp --decrypt` runs, so a resend of an
    // already-processed offer never touches the pad a second time - see
    // `resend_recorded_ack`.
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        resend_recorded_ack(session, from, &contact_name, seq);
        return;
    }
    let Some((plaintext, ack_proof)) = open_otp_envelope(
        session,
        ui_state,
        from,
        &sender,
        &from_name,
        &contact_name,
        // Sealed with no channel and offered as a DM either way: an OTP
        // file offer names its room in `PendingFileOffer`, not in the
        // binding (`OtpInner`).
        None,
        &envelope,
        &sender_device_id,
    )
    .await
    else {
        return;
    };
    if !session.otp_store.record_received(&contact_name, seq) {
        return;
    }
    // Recorded before `contact_name` is moved into `PendingFileOffer` below
    // - see `on_message`'s identical bookkeeping for why this must survive
    // a repeat of this exact offer arriving again.
    session
        .otp_store
        .record_last_received_ack(&contact_name, seq, ack_proof);
    let _ = session.otp_store.save();
    adopt_pad_verified_sender(ui_state, from, &sender);
    if let Some(detail) = refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &contact_name).await {
        end_live_session_if_exhausted(session, ui_state, from, &detail, &contact_name).await;
    }
    let Ok(payload) = proto::decode::<crate::client::file_transfer::FileOfferPayload>(&plaintext)
    else {
        return;
    };
    let filename = crate::client::file_transfer::truncate_filename(&payload.filename);
    let offer = crate::client::tui::ui::PendingFileOffer {
        from,
        from_name,
        filename,
        size: payload.size,
        stream_id,
        channel,
        otp_contact_name: Some(contact_name),
    };
    if ui_state.is_trust_gated(from) {
        ui_state.hold_file_offer(offer);
    } else if ui_state.push_file_offer(offer) {
        crate::client::voice_stream::play_bell_chime(session);
    }
    crate::client::session::request_rotation(session, from);
    session.peer_link.send_reliable_or_queue(
        from,
        P2pPayload::OtpDeliveryAck {
            seq,
            proof: ack_proof,
        },
    );
}

/// `on_file_offer`'s voice counterpart, for `P2pEvent::OtpVoiceOffer`.
/// Unlike a file, an OTP voice message never goes through a popup
/// (`Content::VoiceOffer`'s doc) - this unwraps the offer, acknowledges
/// it, *and* immediately stages and accepts the transfer in one step:
/// registers the receive-side bookkeeping exactly like
/// `session::accept_file_offer` would, then sends `FileAccept` straight
/// back so the sender's existing, unmodified `FileAccepted` handling
/// starts encrypting and streaming the recording.
///
/// Two independent pad spends, exactly like a file's: this offer is one
/// (acknowledged here, the moment it opens), and the recording is a
/// second, named later by `OtpFileContentSeq` and acknowledged by
/// `finish_incoming_file`. The offer is padded rather than riding the
/// envelope so `duration_ms` never travels in the clear - under `Direct`
/// there is no envelope to hide it in.
pub async fn on_voice_offer(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    seq: u64,
    envelope: Envelope,
    sender_device_id: String,
) {
    let Some((sender, contact_name)) = otp_sender_and_contact(session, ui_state, from) else {
        return;
    };
    if envelope.content != Content::VoiceOffer {
        return;
    }
    // The same guard `on_message` and `on_file_offer` use, and before the
    // decrypt for the same reason - see `resend_recorded_ack`.
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        resend_recorded_ack(session, from, &contact_name, seq);
        return;
    }
    let from_name = sender.name.clone();
    let Some((plaintext, ack_proof)) = open_otp_envelope(
        session,
        ui_state,
        from,
        &sender,
        &from_name,
        &contact_name,
        // Always a DM - voice-under-OTP has no channel path.
        None,
        &envelope,
        &sender_device_id,
    )
    .await
    else {
        return;
    };
    if !session.otp_store.record_received(&contact_name, seq) {
        return;
    }
    // Recorded before `contact_name` is moved into `OtpIncomingFileReceive`
    // below - see `on_message`'s identical bookkeeping for why this must
    // survive a repeat of this exact offer arriving again.
    session
        .otp_store
        .record_last_received_ack(&contact_name, seq, ack_proof);
    let _ = session.otp_store.save();
    adopt_pad_verified_sender(ui_state, from, &sender);
    if let Some(detail) = refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &contact_name).await {
        end_live_session_if_exhausted(session, ui_state, from, &detail, &contact_name).await;
    }
    let Ok(payload) = proto::decode::<crate::client::file_transfer::VoiceOfferPayload>(&plaintext)
    else {
        return;
    };
    let key = otp_incoming_stream_key(session, from, &sender.public_key_der);
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-recv-voice-cipher");
    session.otp_incoming_file_receives.insert(
        (from, stream_id),
        crate::client::file_transfer::OtpIncomingFileReceive {
            contact_name,
            // Named by `OtpFileContentSeq` once the sender reserves the
            // recording's own slot - the same two-phase shape a file has.
            seq: None,
            temp_path: temp_path.clone(),
            kind: crate::client::file_transfer::OtpIncomingKind::Voice {
                duration_ms: payload.duration_ms,
            },
        },
    );
    let job_tx = crate::client::file_transfer::spawn_receive_file_worker(
        key,
        temp_path,
        from,
        stream_id,
        session.file_events_tx.clone(),
    );
    session.active_file_transfers.insert(
        (from, stream_id),
        crate::client::file_transfer::ActiveFileTransfer {
            job_tx,
            last_seen: std::time::Instant::now(),
        },
    );
    session.peer_link.ensure_link(wr, from).await;
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::FileAccept { stream_id });
    // This offer's own slot is closed the moment it opened, exactly as a
    // file offer's is - the recording's slot is acknowledged separately.
    session.peer_link.send_reliable_or_queue(
        from,
        P2pPayload::OtpDeliveryAck {
            seq,
            proof: ack_proof,
        },
    );
}

/// Applies an incoming `P2pEvent::OtpDeliveryAck`: clears the send-path
/// gate for `contact_name` if `seq` matches what's actually outstanding,
/// then flushes exactly one queued message (if any) - the same
/// one-permit-at-a-time drain shape as `rekey::RemoteKeys::on_rotated`,
/// except here only one item is ever released per ack rather than the
/// whole queue at once, since a fresh ack only ever authorises one more
/// send before the next ack is needed.
pub async fn on_delivery_ack(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    seq: u64,
    proof: crate::crypto::otp::AckProof,
) -> proto::Result<()> {
    let Some((sender, contact_name)) = otp_sender_and_contact(session, ui_state, from) else {
        return Ok(());
    };
    // Read before `record_acked` clears the gate: whether the send being
    // acknowledged is the `/endotp` notice itself, whose ack also settles
    // the durable retry debt below.
    let acked_end_notice = session.otp_store.get(&contact_name).is_some_and(|s| {
        s.pending_unacked_out_seq == Some(seq)
            && matches!(
                s.pending_content,
                Some(crate::client::otp_store::PendingOtpContent::EndNotice)
            )
    });
    // `record_acked` refuses a `proof` that doesn't match what was buried
    // under the pad of the message `seq` names, which is what keeps the
    // gate closed against anyone who saw the packet but could not open it.
    if !session
        .otp_store
        .record_acked(&contact_name, seq, Some(proof))
    {
        return Ok(());
    }
    // The wait this contact was serving is over; whatever goes out next
    // starts its own from scratch rather than inheriting a long backoff.
    session.otp_retry.remove(&from);
    // The proof held, so this is also the strongest statement available
    // that the peer read the message - and on a pad-protected leg it is
    // the *only* one the row will accept (`DeliveryProof`).
    if let Some(msg_id) = session.otp_ack_rows.remove(&(contact_name.clone(), seq)) {
        ui_state.mark_delivered(
            from,
            msg_id,
            crate::p2p_proto::ReceiptStage::Decrypted,
            crate::client::tui::ui::DeliveryProof::PadAck,
        );
    }
    let _ = session.otp_store.save();
    if acked_end_notice {
        // The peer has provably decrypted the end notice - this is the
        // moment `/endotp` takes effect on the initiating side, the whole
        // point of the two-phase design: both sides leave the session in
        // sync, or neither does. Guarded on the debt still standing, since
        // an `/otp` resume in the handshake's window cancels the end - the
        // ack then merely closes the notice's slot like any other.
        if session.otp_store.clear_end_notice(&contact_name) {
            discard_pending_setup(&session.otp_cli_cfg, &contact_name);
            session.otp_incoming_setup.remove(&from);
            session.otp_out_queue.clear(&contact_name);
            session.otp_store.pause_after_peer_ended(&contact_name);
            let _ = session.otp_store.save();
            ui_state.clear_otp_active(from);
            let peer_name = peer_name_for(ui_state, from);
            notify(
                ui_state,
                from,
                &peer_name,
                format!(
                    "OTP session ended - confirmed by {peer_name} (the pad is kept - /otp \
                     with them resumes it)"
                ),
                true,
            );
        }
        return Ok(());
    }
    // Its acknowledgement came back, so the sealed copy has done its job
    // and is retired - zeroized on the way out, and its line taken off
    // disk (`client::otp_outbox`).
    //
    // Only when the front really is the message being acknowledged. Every
    // queued send now lives here - a recording included, as its own entry
    // - so in the ordinary course the front always is. The check stays
    // because the cost of being wrong is not: an ack for something outside
    // the queue (a file's content phase, an unqueued send racing a
    // just-enabled queue) that retired the front would discard the next
    // queued message unsent, and the peer's gap-free counter
    // (`is_next_expected`) would then refuse everything after it.
    let front_is_this = session
        .otp_outbox
        .as_ref()
        .and_then(|outbox| outbox.front(&contact_name))
        .and_then(|entry| entry.seq())
        == Some(seq);
    if front_is_this
        && let Some(outbox) = session.otp_outbox.as_mut()
        && let Err(e) = outbox.take_front(&contact_name)
    {
        crate::log_warn!("could not retire a delivered OTP message ({e})");
    }
    pump_otp_queue(wr, session, ui_state, from, &contact_name).await;
    flush_one_queued(wr, ui_state, session, &contact_name).await?;
    // A notice `/endotp` deferred behind the send just acknowledged takes
    // the gate the moment it is genuinely free - which is *after* the flush
    // above, so a queued send that just re-armed the gate keeps its turn
    // (this hook simply fires again on that send's own ack). The peer is
    // evidently reachable: their ack just arrived on this very link.
    let owes_notice = session
        .otp_store
        .get(&contact_name)
        .is_some_and(|s| s.pending_end_notice && s.pending_unacked_out_seq.is_none());
    if owes_notice {
        send_end_notice_now(wr, session, from, &sender.public_key_der, &contact_name).await;
    }
    Ok(())
}

/// Releases exactly one queued send for `contact_name`, if any - the drain
/// step every genuine gate-clearing shares: a peer's `OtpDeliveryAck`
/// (`on_delivery_ack`) and the server's `OtpMailResult`/`OtpMailDelivered`
/// for a mail spend (`client::otp_mail`) all authorise exactly one more
/// send before the next acknowledgement is needed. The queued item's
/// recipient is re-resolved fresh from `known_users` - the queue only ever
/// holds a connection-lifetime `UserId`, so a recipient who disconnected
/// meanwhile simply drops the item (their `UserId` will never come back).
pub(crate) async fn flush_one_queued(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    contact_name: &str,
) -> proto::Result<()> {
    match session.otp_out_queue.pop_front(contact_name) {
        Some(PendingOtpSend::Direct {
            to,
            plaintext,
            content,
            log_index,
            msg_id,
        }) => {
            let Some(recipient) = ui_state.known_users.get(&to).cloned() else {
                return Ok(());
            };
            // Its turn has come, so it stops claiming to wait.
            if let Some(msg_id) = msg_id {
                ui_state.mark_queued(to, msg_id, false);
            }
            send_now(
                wr,
                session,
                ui_state,
                to,
                contact_name,
                &recipient.public_key_der,
                &plaintext,
                content,
                None,
                log_index,
                msg_id,
            )
            .await
        }
        Some(PendingOtpSend::Channel {
            channel,
            to,
            plaintext,
            content,
            msg_id,
        }) => {
            let Some(recipient) = ui_state.known_users.get(&to).cloned() else {
                return Ok(());
            };
            // Its turn has come, so it stops claiming to wait.
            if let Some(msg_id) = msg_id {
                ui_state.mark_queued(to, msg_id, false);
            }
            send_now(
                wr,
                session,
                ui_state,
                to,
                contact_name,
                &recipient.public_key_der,
                &plaintext,
                content,
                Some(channel),
                None,
                msg_id,
            )
            .await
        }
        Some(PendingOtpSend::FileContent { stream_id, .. }) => {
            start_outgoing_file_content(session, ui_state, stream_id).await
        }
        None => Ok(()),
    }
}

/// `P2pEvent::FileAccepted`'s OTP step - a wholly independent pad spend
/// from the offer's own (docs/PROTOCOL.md 16.2): checks whether this
/// contact's gate is free, and either reserves it right now (encrypts the
/// file whole into a fresh temp file via `otp_cli::encrypt_file_retrying`,
/// bounded memory, piped through the subprocess - never buffered in
/// aloo's own memory - then `record_sent`s only *after* that genuinely
/// succeeds, the same reserve-after-spent ordering `send_now`/
/// `send_file_offer` use) or, if something else currently holds the gate,
/// queues this stream for `on_delivery_ack` to retry once it frees.
///
/// Spawning the actual chunked send worker is this function's own
/// responsibility in every case (immediate, queued-then-drained, and the
/// plain non-OTP path alike) - the caller (`P2pEvent::FileAccepted`'s
/// handling in `session.rs`) never removes `target` from
/// `session.own_file_targets` itself, since a queued attempt needs the
/// entry - key included - to still be there whenever it's finally
/// retried.
///
/// On a genuine encrypt failure, nothing was ever reserved, so there is
/// no gate to release: just notify, mark the row failed, and clean up the
/// temp file. A non-OTP target spawns immediately, gate logic never
/// entering into it at all.

pub async fn start_outgoing_file_content(
    session: &mut SessionState,
    ui_state: &mut UiState,
    stream_id: u64,
) -> proto::Result<()> {
    let Some(target) = session.own_file_targets.get(&stream_id) else {
        return Ok(());
    };
    let Some(contact_name) = target.otp.clone() else {
        let target = session
            .own_file_targets
            .remove(&stream_id)
            .expect("just confirmed present above");
        session.otp_sending_streams.insert(stream_id, std::time::Instant::now());
        crate::client::file_transfer::spawn_send_file_worker(
            target.path,
            target.key,
            target.to,
            stream_id,
            session.record_out_tx.clone(),
            session.file_events_tx.clone(),
        );
        return Ok(());
    };
    let pinned = target.to;
    let to = retarget_to_current_peer(session, ui_state, stream_id, &contact_name)
        .unwrap_or(pinned);
    let unacked = session
        .otp_store
        .get(&contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
    if unacked {
        // Deliberately *not* cleared from `pending_content_sends` here:
        // `otp_out_queue` is in-memory only, so if the process restarts
        // while this sits queued, the durable record is what lets the next
        // reconnect's `resume_pending_content_sends` find it again and
        // re-enter this same function from scratch, exactly as if a fresh
        // `FileAccepted` had just arrived. That re-entry can coincide with
        // a genuinely re-delivered `FileAccepted` for this same stream (the
        // peer's own transport-level retry, if their first send's ack never
        // reached this side before it restarted) - `has_queued_stream`
        // guards against both landing here and queueing two copies, which
        // the drain would otherwise attempt as two separate sends.
        if !session.otp_out_queue.has_queued_stream(&contact_name, stream_id) {
            session
                .otp_out_queue
                .enqueue(contact_name, PendingOtpSend::FileContent { stream_id, to });
        }
        return Ok(());
    }
    // The gate is free and this function is about to reserve it - from
    // here on, `encrypt_intent` (just below) is what protects this spend
    // across a restart, so the staged-awaiting-accept record has done its
    // job.
    session.otp_store.take_content_send(stream_id);
    let target = session
        .own_file_targets
        .remove(&stream_id)
        .expect("just confirmed present above");
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-send");
    // Written ahead of the encrypt, so a kill inside its window leaves a
    // reconcilable record instead of an orphaned spend
    // (`OtpContactState::encrypt_intent`).
    if !stage_encrypt_intent(
        session,
        &contact_name,
        crate::client::otp_store::PendingOtpContent::FileContent { stream_id },
    ) {
        secure_remove_file(&temp_path);
        let me = ui_state.own_id.unwrap_or(UserId(0));
        ui_state.set_file_failed(me, stream_id);
        let peer_name = peer_name_for(ui_state, to);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: could not record this send before encrypting - not sent".to_string(),
            false,
        );
        return Ok(());
    }
    let outcome = otp_cli::encrypt_file_retrying(
        &session.otp_cli_cfg,
        &contact_name,
        &target.path,
        &temp_path,
        true,
    )
    .await;
    // Same substitute as a voice message's, for the same reason: the file's
    // own bytes are the pad plaintext, so there is no room to bury a nonce.
    let ack_proof = crate::crypto::otp::ack_proof_for_file(&target.path).ok();
    match outcome {
        Ok(otp_cli::FileCliOutcome::Ok) => {
            restrict_file_permissions(&temp_path);
            session
                .otp_send_temp_files
                .insert(stream_id, temp_path.clone());
            let seq = session
                .otp_store
                .get(&contact_name)
                .map(|s| s.next_out_seq)
                .unwrap_or(0);
            session.otp_store.record_sent(
                &contact_name,
                seq,
                crate::client::otp_store::PendingOtpContent::FileContent { stream_id },
                ack_proof,
            );
            let _ = session.otp_store.save();
            if let Some(detail) = refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, &contact_name).await {
                end_live_session_if_exhausted(session, ui_state, to, &detail, &contact_name).await;
            }
            session
                .peer_link
                .send_reliable_or_queue(to, P2pPayload::OtpFileContentSeq { stream_id, seq });
            // The content phase reports onto the offer's own row - there is
            // only ever one row per transfer, and it is not finished until
            // the bytes have actually landed.
            let row = ui_state.own_stream_msg_id(stream_id);
            if let Some(msg_id) = row {
                ui_state.mark_awaiting_pad_ack(to, msg_id);
                session
                    .otp_ack_rows
                    .insert((contact_name.to_string(), seq), msg_id);
            }
            session.otp_sending_streams.insert(stream_id, std::time::Instant::now());
            crate::client::file_transfer::spawn_send_file_worker(
                temp_path,
                target.key,
                to,
                stream_id,
                session.record_out_tx.clone(),
                session.file_events_tx.clone(),
            );
        }
        _ => {
            session.otp_store.clear_encrypt_intent(&contact_name);
            let _ = session.otp_store.save();
            secure_remove_file(&temp_path);
            let me = ui_state.own_id.unwrap_or(UserId(0));
            ui_state.set_file_failed(me, stream_id);
            let peer_name = peer_name_for(ui_state, to);
            notify(
                ui_state,
                to,
                &peer_name,
                "OTP: failed to encrypt this file's content - not sent".to_string(),
                false,
            );
        }
    }
    Ok(())
}

/// `P2pEvent::FileAccepted`'s full response: sends this stream's
/// chunk-transport key setup - freshly computed every time this runs
/// (`target.key`, from `otp_stream_key`, is a derivation, never reused
/// state, so re-running this after a restart is exactly as safe as the
/// first time - the peer has decrypted nothing yet to invalidate) - then
/// hands off to `start_outgoing_file_content` for the actual
/// gate-check-then-encrypt-or-queue decision. Shared by the real
/// `FileAccepted` handler (`session.rs`) and `resume_pending_content_sends`'s
/// autoheal below, so a reconstructed accept behaves identically to a live
/// one.
/// Points a staged content send at the `UserId` its recipient holds *now*,
/// re-deriving the stream's transport key for them, and reports it.
///
/// `own_file_targets` pins the id the recipient had when the *offer* was
/// recorded. For a voice message held for someone who was away that is the
/// id they had while offline - precisely the one that never comes back,
/// which is why the queues are keyed by contact name in the first place.
/// The offer itself goes out fine, since the queue pumps it to whoever
/// they are now; without this the *recording* went to the dead id, so the
/// announcement landed and the recording never did, and their pad sat
/// waiting on a position it would never be given - refusing every message
/// after it, because `is_next_expected` admits no gaps.
///
/// The same rule `flush_one_queued` already states for its own queue:
/// re-resolve the recipient, never trust a stored `UserId`.
fn retarget_to_current_peer(
    session: &mut SessionState,
    ui_state: &UiState,
    stream_id: u64,
    contact_name: &str,
) -> Option<UserId> {
    let (current, der) = peer_for_contact_name(session, ui_state, contact_name)?;
    let pinned = session.own_file_targets.get(&stream_id)?.to;
    if current != pinned
        && let Some(key) = otp_stream_key(session, stream_id, current, &der)
        && let Some(target) = session.own_file_targets.get_mut(&stream_id)
    {
        target.to = current;
        target.key = key;
    }
    Some(current)
}

pub async fn begin_file_content(
    session: &mut SessionState,
    ui_state: &mut UiState,
    stream_id: u64,
) -> proto::Result<()> {
    // Before the key setups go out, not after: they are addressed from the
    // stream key itself, so a key derived for the id this peer used to
    // hold would send them somewhere nobody is listening and the recording
    // could never be opened.
    if let Some(contact_name) = session
        .own_file_targets
        .get(&stream_id)
        .and_then(|t| t.otp.clone())
    {
        retarget_to_current_peer(session, ui_state, stream_id, &contact_name);
    }
    let Some(target) = session.own_file_targets.get(&stream_id) else {
        return Ok(());
    };
    for (id, setup) in target.key.setups() {
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
    }
    start_outgoing_file_content(session, ui_state, stream_id).await
}

/// Resumes every content send still staged as awaiting the peer's
/// acceptance (`OtpStore::content_sends` - `send_file_offer`/
/// `send_voice_offer` stage one the instant their offer is safely out)
/// whose peer has just become reachable again - the content-phase
/// counterpart of the other three reconnect passes (`recover_and_resend`,
/// `resend_pending_setups`, `resend_pending_commits`), driven by the same
/// `LinkStatusChanged` -> `Active` transition.
///
/// Covers the one gap none of those three close: a `FileAccepted` that
/// arrived - or was already queued behind another send - while this
/// side's own process was mid-restart, with `own_file_targets` (in-memory
/// only) gone by the time anything could act on it. Reconstructs the
/// target fresh and re-enters the exact same accept-handling path a live
/// `FileAccepted` would (`begin_file_content`) - so a peer who already
/// accepted before this side ever noticed needs to do nothing at all; the
/// recording or file still arrives once both sides are reachable again,
/// with no pad ever at risk either way (the content phase's own spend
/// only ever happens *after* this resolves, exactly as it would from a
/// fresh accept). Skips anything `own_file_targets` already has - a resume
/// already under way this same run.
pub async fn resume_pending_content_sends(
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let staged: Vec<(u64, crate::client::otp_store::PendingContentSend)> = session
        .otp_store
        .content_sends()
        .map(|(id, target)| (id, target.clone()))
        .collect();
    for (stream_id, target) in staged {
        if session.own_file_targets.contains_key(&stream_id) {
            continue;
        }
        let Some((to, recipient_pubkey_der)) =
            peer_for_contact_name(session, ui_state, &target.contact_name)
        else {
            continue; // not currently connected - a later transition retries
        };
        let Some(key) = otp_stream_key(session, stream_id, to, &recipient_pubkey_der) else {
            continue;
        };
        session.own_file_targets.insert(
            stream_id,
            crate::client::file_transfer::OwnFileTarget {
                to,
                path: target.path,
                key,
                otp: Some(target.contact_name),
            },
        );
        begin_file_content(session, ui_state, stream_id).await?;
    }
    Ok(())
}

/// `FileEvent::ReceiveDone`'s OTP step: the chunked transport just finished
/// writing `pending.temp_path` in full (ordinary per-chunk ciphertext,
/// exactly like a non-OTP transfer) - decrypts it whole into
/// `pending.final_path` via `otp_cli::decrypt_file_retrying`, removes the
/// temp copy either way, and only on success acknowledges `pending.seq`
/// back to the sender. That ack is what tells the sender's own reserved
/// gate (`send_file_offer`'s `record_sent`) it's genuinely safe to send
/// this contact something else - so a decrypt failure here must not send
/// one; it marks the row failed instead, same as any other genuinely lost
/// delivery.
pub async fn finish_incoming_file(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    pending: crate::client::file_transfer::OtpIncomingFileReceive,
) {
    use crate::client::file_transfer::OtpIncomingKind;
    // The same guard every other spend runs *before* `otp --decrypt`
    // (`on_message`, `on_file_offer`, `on_content_seq`'s unregistered
    // branch): only the exact next position may reach the pad. A content
    // transfer was the one path that decrypted first and asked afterwards -
    // so a retried stream for a position already consumed, or one whose
    // cleartext `OtpFileContentSeq` was garbled in transit, spent a pad
    // range the store then refused to record, leaving the tool a position
    // ahead for good. A consumed position is re-answered from its record
    // at no cost, exactly as a repeated text is; a stream that never named
    // its position at all is refused rather than spent on blindly.
    let Some(seq) = pending.seq else {
        secure_remove_file(&pending.temp_path);
        let from_name = peer_name_for(ui_state, from);
        notify(
            ui_state,
            from,
            &from_name,
            format!(
                "OTP: a transfer from {from_name} arrived without naming its pad position - \
                 not decrypted, keys untouched"
            ),
            false,
        );
        return;
    };
    if !session.otp_store.is_next_expected(&pending.contact_name, seq) {
        secure_remove_file(&pending.temp_path);
        resend_recorded_ack(session, from, &pending.contact_name, seq);
        return;
    }
    // A file decrypts straight to its real download location; a voice
    // message has no destination file at all, so it decrypts to a second
    // (plaintext) temp file that's read back into memory and deleted
    // immediately below - matches how a live-streamed voice message is
    // already held fully in memory (`plaintext_accum`), just skipping the
    // live part.
    let decrypt_dest = match &pending.kind {
        OtpIncomingKind::File { final_path } => final_path.clone(),
        OtpIncomingKind::Voice { .. } => temp_content_path(&session.otp_cli_cfg, "otp-recv-voice"),
        OtpIncomingKind::Recovered => session
            .otp_cli_cfg
            .working_dir
            .join(format!("recovered-{stream_id}")),
    };
    // `final_path` is under `~/.aloo/downloads`, which - unlike the OTP
    // working directory temp files live under - is created lazily, only
    // once a transfer actually lands (`file_transfer::spawn_receive_file_worker`
    // does this for the plain path); this decrypt writes there directly, so
    // it needs the same lazy creation, or a first-ever OTP file receive
    // fails outright with the destination directory missing.
    if let Some(parent) = decrypt_dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let outcome = otp_cli::decrypt_file_retrying(
        &session.otp_cli_cfg,
        &pending.contact_name,
        &pending.temp_path,
        &decrypt_dest,
        true,
    )
    .await;
    // What comes out of a decrypt is plaintext, and the tool writes it
    // under the process umask - 0644 on a typical machine - into a working
    // directory that is not itself private. Every plaintext this side
    // *writes* is already restricted (`otp-voice-plain`, `otp-send`,
    // `otp-recover-send`); the ones it *receives* were not, which left a
    // decoded voice message and a recovered transfer briefly readable by
    // any other account on the machine. Narrow, since both are erased
    // moments later - but a crash in between is exactly why the orphan
    // sweep exists, and "briefly world-readable" is the wrong default for
    // a tool whose whole premise is that plaintext does not rest on disk.
    restrict_file_permissions(&decrypt_dest);
    secure_remove_file(&pending.temp_path);
    // A rejection may be the receiver's own crash talking: the decrypt
    // already ran in a previous life of this process and only the record
    // was lost, so the sender's faithful retry is now one position behind
    // the tool. Recognised by the exact off-by-one and healed from the
    // tool's kept copy, the same way `finish_opening_otp_envelope` heals a
    // text - the plaintext lands in `decrypt_dest` as if the decrypt had
    // just happened, and everything below proceeds normally.
    let outcome = match outcome {
        Ok(otp_cli::FileCliOutcome::Rejected(reason)) => {
            if recover_orphaned_decrypt_file(session, &pending.contact_name, &decrypt_dest).await {
                restrict_file_permissions(&decrypt_dest);
                Ok(otp_cli::FileCliOutcome::Ok)
            } else {
                Ok(otp_cli::FileCliOutcome::Rejected(reason))
            }
        }
        other => other,
    };
    if !matches!(outcome, Ok(otp_cli::FileCliOutcome::Ok)) {
        let _ = std::fs::remove_file(&decrypt_dest);
        if matches!(pending.kind, OtpIncomingKind::File { .. }) {
            ui_state.set_file_failed(from, stream_id);
        }
        let from_name = peer_name_for(ui_state, from);
        let what = match pending.kind {
            OtpIncomingKind::File { .. } => "file",
            OtpIncomingKind::Voice { .. } => "voice message",
            OtpIncomingKind::Recovered => "recovered transfer",
        };
        // A rejection - the metadata check refused this exact transfer's
        // content, not merely a transient I/O failure - is worth naming
        // specifically; see `otp_cli::OtpCliOutcome::Rejected`'s doc.
        let message = match outcome {
            Ok(otp_cli::FileCliOutcome::Rejected(reason)) => {
                format!(
                    "OTP: an incoming {what} from {from_name} was rejected ({}) - keys untouched",
                    reason.trim().replace('\n', "; ")
                )
            }
            _ => format!("OTP: failed to decrypt an incoming {what} - it did not arrive"),
        };
        notify(ui_state, from, &from_name, message, false);
        return;
    }
    // Read off the plaintext before the Voice arm below wipes it - this is
    // the whole-file spend's stand-in for a nonce, and only a party that
    // genuinely decrypted the content can produce it
    // (`crypto::otp::ack_proof_for_file`).
    let ack_proof = crate::crypto::otp::ack_proof_for_file(&decrypt_dest).ok();
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &pending.contact_name).await;
    match pending.kind {
        OtpIncomingKind::File { .. } => ui_state.set_file_completed(from, stream_id),
        OtpIncomingKind::Voice { duration_ms } => {
            let pcm = std::fs::read(&decrypt_dest).unwrap_or_default();
            secure_remove_file(&decrypt_dest);
            let from_name = peer_name_for(ui_state, from);
            // The same autoplay gate `channel::on_stream_start`/
            // `direct_message::on_stream_start` snapshot for a live
            // pq_hybrid stream (muted/trust-gated, or this isn't the DM
            // currently on screen), just applied once to the whole clip
            // instead of per chunk - an OTP voice message never live-
            // streams (docs/PROTOCOL.md §16), it only ever shows up fully
            // decrypted, right here.
            let suppress_playback =
                ui_state.suppress_playback_from(from) || !ui_state.is_viewing_dm(from);
            let samples = crate::client::voice::pcm_from_bytes(&pcm);
            let played = !suppress_playback && !samples.is_empty();
            if played {
                let id = session.next_mixer_id;
                session.next_mixer_id += 1;
                let _ = session
                    .mixer_tx
                    .send(crate::client::voice::MixerCmd::Push { id, samples });
                let _ = session
                    .mixer_tx
                    .send(crate::client::voice::MixerCmd::Finish { id });
            }
            ui_state.on_direct_voice_message(from, from_name, duration_ms, pcm, played);
            crate::client::session::request_rotation(session, from);
        }
        OtpIncomingKind::Recovered => {
            let from_name = peer_name_for(ui_state, from);
            notify(
                ui_state,
                from,
                &from_name,
                format!(
                    "OTP: a transfer from {from_name} interrupted by a restart was recovered \
                     to {}",
                    decrypt_dest.display()
                ),
                true,
            );
        }
    }
    // `seq` is `None` only if a file's content genuinely finished
    // decrypting before its own `OtpFileContentSeq` ever arrived - not
    // possible over an ordered reliable link (it's always sent first), but
    // guarded rather than assumed; nothing to ack in that case.
    if let Some(proof) = ack_proof {
        // The content spend occupied a slot in the same, single sequence
        // space every other spend shares - so consuming it must advance
        // the expectation like every other slot, or the sender's very next
        // message would be silently dropped as out-of-order, wedging the
        // pair for good. And its acceptance leaves the same durable
        // `(seq, proof)` record every accepted message does, so a retry of
        // the content whose ack was lost is re-answered from it
        // (`on_content_seq`) rather than re-received. The guard above
        // already proved `seq` is the next expected, so this cannot refuse.
        if !session.otp_store.record_received(&pending.contact_name, seq) {
            crate::log_warn!(
                "a content spend at position {seq} for {} decrypted but could not be \
                 recorded - the pair's counters may now disagree",
                pending.contact_name
            );
        }
        session
            .otp_store
            .record_last_received_ack(&pending.contact_name, seq, proof);
        let _ = session.otp_store.save();
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq, proof });
    }
}

/// Applies an incoming `P2pEvent::OtpFileContentSeq` - the sender naming
/// which slot of the shared sequence space a content transfer's pad spend
/// took. Three cases, in order:
///
/// - **Registered** (the ordinary one): the accept-time bookkeeping is
///   waiting for exactly this; record the slot and let the chunks land.
/// - **Already consumed**: this side finished and acknowledged the content,
///   and the sender retries only because that ack was lost - re-answer from
///   the durable `(seq, proof)` record its acceptance left, at no cost, the
///   same duplicate machinery every other spend uses.
/// - **Owed but unregistered**: this side restarted after accepting the
///   offer, so the in-memory registration died with the process while the
///   sender's recovery legitimately retries. Rather than dropping the
///   retries forever - the sender's gate held and this side's expectation
///   stuck, wedging the pair for good - re-register the transfer
///   generically (`OtpIncomingKind::Recovered`): the bytes land under the
///   OTP working directory and are named in a notice, the spend is
///   acknowledged, and the pads stay in lockstep; only what the content
///   *was* (a file's name and destination, a voice message's duration) is
///   beyond recovering, since it died with the process.
pub async fn on_content_seq(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    seq: u64,
) {
    if let Some(pending) = session
        .otp_incoming_file_receives
        .get_mut(&(from, stream_id))
    {
        pending.seq = Some(seq);
        return;
    }
    let Some((sender, contact_name)) = otp_sender_and_contact(session, ui_state, from) else {
        return;
    };
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        resend_recorded_ack(session, from, &contact_name, seq);
        return;
    }
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-recv-recovered");
    session.otp_incoming_file_receives.insert(
        (from, stream_id),
        crate::client::file_transfer::OtpIncomingFileReceive {
            contact_name,
            seq: Some(seq),
            temp_path: temp_path.clone(),
            kind: crate::client::file_transfer::OtpIncomingKind::Recovered,
        },
    );
    let key = otp_incoming_stream_key(session, from, &sender.public_key_der);
    let job_tx = crate::client::file_transfer::spawn_receive_file_worker(
        key,
        temp_path,
        from,
        stream_id,
        session.file_events_tx.clone(),
    );
    session.active_file_transfers.insert(
        (from, stream_id),
        crate::client::file_transfer::ActiveFileTransfer {
            job_tx,
            last_seen: std::time::Instant::now(),
        },
    );
}

/// Reverse of `contact_name_for_peer`: which (if any) currently-known peer's
/// pq fingerprint reproduces `contact_name`. `OtpContactState` deliberately
/// persists no `UserId` (connection-lifetime only, unsafe to trust across a
/// reconnect) - `recover_and_resend` needs a live one, resolved fresh every
/// time it's actually about to act.
fn peer_for_contact_name(
    session: &SessionState,
    ui_state: &UiState,
    contact_name: &str,
) -> Option<(UserId, Vec<u8>)> {
    ui_state.known_users.iter().find_map(|(id, info)| {
        if contact_name_for_peer(session, *id, &info.public_key_der).as_deref() == Some(contact_name) {
            Some((*id, info.public_key_der.clone()))
        } else {
            None
        }
    })
}

/// Re-sends every pad that is still owed to a reachable peer - the
/// provisioning counterpart of `recover_and_resend`, driven by the same
/// `LinkStatusChanged` -> `Active` trigger, and for the same reason: an
/// invitation whose delivery was never confirmed is retried, never
/// regenerated. The bytes come back off disk (`read_pending_setup`), so a
/// resend is identical to the original attempt.
///
/// This is what makes a peer going offline mid-invitation a delay rather
/// than a dead end. They reconnect under a fresh `UserId`, but the debt is
/// keyed by contact name, so it is still found and re-offered - and if they
/// had in fact received the pad and only their acknowledgement was lost,
/// their side answers the re-delivery with a fresh ack instead of a second
/// popup (`on_key_setup`).
pub(crate) async fn resend_pending_setups(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let owed: Vec<(String, u32)> = session
        .otp_store
        .pending_setups()
        .map(|(name, size_mb)| (name.to_string(), size_mb))
        .collect();
    for (contact_name, size_mb) in owed {
        let Some((peer, pubkey_der)) = peer_for_contact_name(session, ui_state, &contact_name)
        else {
            continue; // not currently connected - a later transition retries
        };
        let Some(peer_info) = ui_state.known_users.get(&peer).cloned() else {
            continue;
        };
        // The staged pad is the source for every retry, so a resend is
        // byte-identical to the original rather than a fresh generation.
        // Gone from disk means there is nothing left to resend and nothing
        // was ever committed to the keychain - drop the debt rather than
        // retrying something that cannot succeed.
        let dir = pending_setup_dir(&session.otp_cli_cfg, &contact_name);
        let (_, _, peer_enc, _) = pending_paths(&dir);
        if !peer_enc.is_file() {
            session.otp_store.clear_pending_setup(&contact_name);
            let _ = session.otp_store.save();
            continue;
        }
        // A transfer already streaming to this peer is not restarted: the
        // link transition that triggered this pass may well be the very one
        // it is already using.
        if session.otp_outgoing_pads.contains_key(&peer) {
            continue;
        }
        let _ = pubkey_der;
        start_pad_send(
            wr,
            session,
            ui_state,
            peer,
            &peer_info.name.clone(),
            &peer_info.public_key_der.clone(),
            &contact_name,
            size_mb,
        )
        .await;
    }
    Ok(())
}

/// Recovers and resends `peer`'s one outstanding OTP send, if any -
/// `session.rs`'s `P2pEvent::LinkStatusChanged` handler calls this every
/// time a direct link genuinely transitions to `Active`, so a send whose
/// ciphertext already left the machine (this app restarted, the connection
/// dropped, or the peer's own ack simply never made it back) gets another
/// chance without ever spending fresh pad on it - see the module doc and
/// `OtpStore::is_next_expected`'s for why re-encoding instead would be
/// unsafe. A cheap no-op for the overwhelming majority of calls (no OTP
/// contact for this peer, or nothing pending).
///
/// The recovered bytes always carry the *same* `seq` as the original send.
/// If the peer already fully processed it and only the ack was lost, their
/// own `is_next_expected`/`record_received` check rejects this resend
/// before it touches their pad at all - a harmless, correct no-op, not a
/// failure.
/// Startup reconciliation for spends the previous process died inside -
/// the sender-side mirror of `recover_orphaned_decrypt`. A write-ahead
/// intent (`OtpContactState::encrypt_intent`) found at load time means the
/// process was killed somewhere between announcing an encrypt and
/// finalising it; the tool's own encrypt counter says on which side.
/// Still equal to the store's send count (`next_out_seq`): the encrypt
/// never ran, nothing was spent, the intent is dropped - the message was
/// simply never sent, exactly as if the kill had landed a moment earlier.
/// One ahead: the spend is real but unrecorded - the orphan every later
/// send would silently leapfrog, poisoning the peer's decoder for good -
/// so the intent is *promoted* to an ordinary recorded send (proof `None`,
/// which `record_acked` already tolerates as a record predating its
/// expectation), and the standard recovery machinery resends the tool's
/// kept ciphertext under the right framing on the next link-up. Any other
/// shape drops the intent and touches nothing. Returns what was promoted,
/// for the one content kind whose retry needs a second store mended
/// (`Mail` - `client::otp_mail::restore_orphaned_mail_ref`).
/// The acknowledgement proof for a send being promoted from its
/// write-ahead record, recovered from the tool's own kept copy.
///
/// Only for the kinds framed with a nonce (`wrap_outgoing`) - a text, an
/// end notice, or a file/voice *offer* - where the proof is the hash of
/// that nonce. A content transfer's proof is a hash of the plaintext file
/// instead (`ack_proof_for_file`), which the kept copy of the ciphertext
/// cannot yield, so those keep today's `None`.
async fn recovered_ack_proof(
    cfg: &otp_cli::OtpCliConfig,
    contact_name: &str,
    content: &crate::client::otp_store::PendingOtpContent,
) -> Option<crypto::otp::AckProof> {
    use crate::client::otp_store::PendingOtpContent as Kind;
    if matches!(content, Kind::FileContent { .. }) {
        return None;
    }
    let recovered = otp_cli::recover_last(cfg, contact_name, otp_cli::RecoverDirection::Sent)
        .await
        .ok()??;
    if recovered.len() < crypto::otp::ACK_NONCE_BYTES {
        return None;
    }
    let (nonce, _payload) = recovered.split_at(crypto::otp::ACK_NONCE_BYTES);
    Some(crypto::otp::ack_proof_for(nonce))
}

pub async fn reconcile_orphaned_sends(
    cfg: &otp_cli::OtpCliConfig,
    store: &mut crate::client::otp_store::OtpStore,
) -> Vec<(String, u64, crate::client::otp_store::PendingOtpContent)> {
    let intents: Vec<(String, crate::client::otp_store::PendingOtpContent)> = store
        .encrypt_intents()
        .map(|(name, content)| (name.to_string(), content.clone()))
        .collect();
    if intents.is_empty() {
        return Vec::new();
    }
    let mut promoted = Vec::new();
    for (contact_name, content) in intents {
        // A fully recorded send already outstanding means the intent is
        // stale bookkeeping from an older accident - the recorded send's
        // own recovery takes precedence, and a second promotion would
        // fabricate a spend that never happened.
        if store
            .get(&contact_name)
            .and_then(|s| s.pending_unacked_out_seq)
            .is_some()
        {
            store.clear_encrypt_intent(&contact_name);
            continue;
        }
        // Asked *before* the intent is cleared. The intent is the only
        // record that a position may have been spent without being
        // recorded; discarding it because the pad could not be read this
        // once would strand that spend for good, on this start and every
        // later one, with the store permanently a position behind the pad.
        // Kept instead, so the next start reconciles it - and sends for
        // this contact stay blocked meanwhile (`encrypt_in_flight`), which
        // is the safe way to be wrong: nothing new is spent against a pad
        // whose position is in doubt.
        let Ok(Some(detail)) = otp_cli::show_contact(cfg, &contact_name).await else {
            crate::log_warn!(
                "could not read the pad for {contact_name} while reconciling an \
                 interrupted send; keeping the record and leaving this contact's \
                 sends held until it can be read"
            );
            continue;
        };
        let next_out = store
            .get(&contact_name)
            .map(|s| s.next_out_seq)
            .unwrap_or(0);
        store.clear_encrypt_intent(&contact_name);
        if detail.enc_sequence == next_out + 1 {
            // Recovered so the promoted send keeps the proof requirement
            // every other send carries. Without one, `record_acked` accepts
            // *any* proof for this position - so anybody who merely saw the
            // packet could open the gate, which is the one thing the proof
            // exists to prevent. `--recover-last --sent` re-streams the
            // copy the tool already kept and consumes no key, so asking
            // costs nothing; a spend whose copy is genuinely gone falls
            // back to `None` rather than being left unrecoverable.
            let proof = recovered_ack_proof(cfg, &contact_name, &content).await;
            store.record_sent(&contact_name, next_out, content.clone(), proof);
            promoted.push((contact_name, next_out, content));
        } else if detail.enc_sequence != next_out {
            // Neither "spent once, unrecorded" nor "never spent" - the two
            // states an interrupted send can leave. Anything else means the
            // pad and this side's counter have already diverged by more
            // than one position, which nothing here can reconstruct: said
            // out loud rather than passed over, since this is the one place
            // positioned to notice it at all.
            crate::log_warn!(
                "the pad for {contact_name} is at position {} while this side \
                 recorded {next_out}; an interrupted send can only ever leave a \
                 difference of one, so these have diverged and messages to this \
                 contact will not decrypt until the pad is re-provisioned",
                detail.enc_sequence
            );
        }
    }
    let _ = store.save();
    promoted
}

pub async fn recover_and_resend(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    // Collect first - `peer_for_contact_name`/the loop body both need
    // `session`/`ui_state`, and there's at most a handful of OTP contacts,
    // so cloning the small set of (contact_name, seq, content) triples to
    // act on is simpler than fighting the borrow checker over one pass.
    let pending: Vec<(String, u64, crate::client::otp_store::PendingOtpContent)> = session
        .otp_store
        .pending_sends()
        .map(|(name, seq, content)| (name.to_string(), seq, content.clone()))
        .collect();
    for (contact_name, seq, content) in pending {
        // A message the durable queue still holds is retried from the
        // queue - its exact bytes are the entry (or the entry's `.rec`
        // file) - never from the CLI's `.last_sent` copy. That copy is
        // one deep and overwritten by every seal, and a queue exists
        // precisely to seal ahead: with three voice messages waiting it
        // holds only the sixth seal, so recovering an older outstanding
        // send from it would resend the wrong ciphertext under the right
        // sequence. (The receiver's metadata check refuses that without
        // spending pad, but the genuine message still never moves.)
        // `.last_sent` recovery is for the unqueued mode, whose
        // one-outstanding gate is exactly what makes a one-deep copy
        // always the right one.
        let queue_holds_it = session
            .otp_outbox
            .as_ref()
            .and_then(|outbox| outbox.front(&contact_name))
            .and_then(|entry| entry.seq())
            == Some(seq);
        if queue_holds_it {
            continue;
        }
        // A transfer whose worker is still pushing chunks must not be
        // started again: two workers on one `stream_id` interleave into a
        // decrypt whose `ack_proof` matches nothing, and the gate could
        // then never open. Harmless on the link-up path that has always
        // called this - a dropped link kills its transfers - but this now
        // also runs on a timer, with the link perfectly healthy.
        let streaming = match &content {
            crate::client::otp_store::PendingOtpContent::File { stream_id, .. }
            | crate::client::otp_store::PendingOtpContent::FileContent { stream_id }
            | crate::client::otp_store::PendingOtpContent::Voice { stream_id, .. } => {
                Some(*stream_id)
            }
            _ => None,
        };
        if streaming.is_some_and(|id| session.is_stream_sending(id, std::time::Instant::now())) {
            continue;
        }
        let Some((to, recipient_pubkey_der)) =
            peer_for_contact_name(session, ui_state, &contact_name)
        else {
            continue;
        };
        match content {
            crate::client::otp_store::PendingOtpContent::Text { channel } => {
                // The same row the original send named, so a recovery that
                // finally gets through turns it green rather than leaving
                // it undelivered forever.
                let msg_id = session
                    .otp_ack_rows
                    .get(&(contact_name.clone(), seq))
                    .copied();
                recover_and_resend_envelope(
                    wr,
                    session,
                    &contact_name,
                    seq,
                    to,
                    &recipient_pubkey_der,
                    Content::Text,
                    channel,
                    msg_id,
                )
                .await?;
            }
            crate::client::otp_store::PendingOtpContent::File { stream_id, .. } => {
                recover_and_resend_offer(
                    wr,
                    session,
                    ui_state,
                    &contact_name,
                    seq,
                    to,
                    &recipient_pubkey_der,
                    stream_id,
                    OfferKind::File,
                )
                .await?;
            }
            crate::client::otp_store::PendingOtpContent::FileContent { stream_id } => {
                recover_and_resend_file_content(
                    session,
                    &contact_name,
                    seq,
                    to,
                    &recipient_pubkey_der,
                    stream_id,
                )
                .await?;
            }
            crate::client::otp_store::PendingOtpContent::Voice { stream_id, .. } => {
                recover_and_resend_offer(
                    wr,
                    session,
                    ui_state,
                    &contact_name,
                    seq,
                    to,
                    &recipient_pubkey_der,
                    stream_id,
                    OfferKind::Voice,
                )
                .await?;
            }
            crate::client::otp_store::PendingOtpContent::Mail { .. } => {
                // A mail's retry rides the server control channel, not a
                // P2P link - `client::otp_mail::resend_pending` handles it
                // once per (re)connect; nothing to do on a link transition.
            }
            crate::client::otp_store::PendingOtpContent::EndNotice => {
                recover_and_resend_envelope(
                    wr,
                    session,
                    &contact_name,
                    seq,
                    to,
                    &recipient_pubkey_der,
                    Content::OtpEndSession,
                    None,
                    None,
                )
                .await?;
            }
        }
    }
    Ok(())
}

/// Envelope-shaped recovery, shared by the two spends that ride
/// `OtpEnvelope`: an ordinary text message and the `/endotp` notice
/// (`PendingOtpContent::EndNotice` - an ordinary stop-and-wait spend, so
/// its retry is this same path, not machinery of its own). Recovers the
/// very ciphertext the original spend produced - never a fresh encode,
/// which would spend a second range of the pad for a message the peer's
/// decoder was never told to expect and desync the pair for good - and
/// re-frames it (the seal is the outer layer and was never what got
/// stored) under the same `seq`, with `content` routing it identically to
/// the original at the far end. `msg_id` is the delivery row the original
/// named, for a text whose recovery finally getting through should turn
/// that row green (docs/PROTOCOL.md 7.2.1); `None` for the notice, which
/// has no row.
/// The kept safety copy of the last payload sent to `contact_name`, if
/// there is one (`otp --recover-last --sent`).
///
/// Every recovery below opens with this, and every one of them treats a
/// miss the same way: `None` covers both "nothing awaits confirmation"
/// and "the CLI failed", and the answer to either is to leave the gate
/// exactly as it stands - never to fall back on a fresh encode, which
/// would spend pad a second time for a message already spent for - and
/// try again on the next reconnect.
async fn recover_last_sent(session: &SessionState, contact_name: &str) -> Option<Vec<u8>> {
    otp_cli::recover_last(
        &session.otp_cli_cfg,
        contact_name,
        otp_cli::RecoverDirection::Sent,
    )
    .await
    .ok()
    .flatten()
}

async fn recover_and_resend_envelope(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    contact_name: &str,
    seq: u64,
    to: UserId,
    recipient_pubkey_der: &[u8],
    content: Content,
    channel: Option<String>,
    msg_id: Option<u64>,
) -> proto::Result<()> {
    let Some(recovered) = recover_last_sent(session, contact_name).await else {
        return Ok(());
    };
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = frame_padded(
        session,
        to,
        recipient_pubkey_der,
        send_id,
        recovered,
        content,
    ) else {
        return Ok(());
    };
    session.peer_link.ensure_link(wr, to).await;
    let own_device_id = session.own_device_id.clone();
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpEnvelope {
            channel,
            seq,
            msg_id,
            envelope,
            sender_device_id: own_device_id,
        },
    );
    Ok(())
}

/// Which of the two offers a recovery is replaying. They differ in
/// exactly two places - the `Content` the blob was sealed under and the
/// payload it goes back out in - and in nothing else, which is why
/// `recover_and_resend_offer` is one function rather than the two
/// near-identical ones it used to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OfferKind {
    File,
    Voice,
}

/// Offer-phase recovery, mirroring `recover_and_resend_envelope` exactly:
/// the offer is a genuine pad spend in its own right (`send_file_offer`'s
/// doc, and `send_voice_offer` alongside it), so recovering means
/// recovering that same ciphertext, never re-encoding a fresh one -
/// resent under the *same* `stream_id` the original offer used.
///
/// For a file, that same `stream_id` is what lets an eventual
/// `FileAccepted` still find the matching `OwnFileTarget` entry (only
/// ever missing if this process itself restarted mid-transfer, since that
/// map is in-memory only - a rarer, best-effort-only case this doesn't
/// try to solve).
///
/// For a voice message, this covers the offer alone. The recording itself
/// is a separate spend and recovers through
/// `recover_and_resend_file_content`.
#[allow(clippy::too_many_arguments)]
async fn recover_and_resend_offer(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &UiState,
    contact_name: &str,
    seq: u64,
    to: UserId,
    recipient_pubkey_der: &[u8],
    stream_id: u64,
    kind: OfferKind,
) -> proto::Result<()> {
    let Some(recovered) = recover_last_sent(session, contact_name).await else {
        return Ok(());
    };
    let Some(envelope) = frame_padded(
        session,
        to,
        recipient_pubkey_der,
        stream_id,
        recovered,
        match kind {
            OfferKind::File => Content::FileOffer,
            OfferKind::Voice => Content::VoiceOffer,
        },
    ) else {
        return Ok(());
    };
    let msg_id = ui_state.own_stream_msg_id(stream_id);
    session.peer_link.ensure_link(wr, to).await;
    let sender_device_id = session.own_device_id.clone();
    let payload = match kind {
        OfferKind::File => P2pPayload::OtpFileOffer {
            // Sealed with no channel and offered as a DM either way: an
            // OTP file offer names its room in `PendingFileOffer`, not in
            // the binding - see `on_file_offer`.
            channel: None,
            stream_id,
            seq,
            msg_id,
            envelope,
            sender_device_id,
        },
        OfferKind::Voice => P2pPayload::OtpVoiceOffer {
            stream_id,
            seq,
            msg_id,
            envelope,
            sender_device_id,
        },
    };
    session.peer_link.send_reliable_or_queue(to, payload);
    Ok(())
}

/// Content-phase recovery: the file was already accepted and its content
/// already genuinely OTP-encrypted before the connection dropped -
/// recovers that same ciphertext (`recover_last_file`, never a fresh
/// encrypt) and restarts the chunked send from the beginning under the
/// *same* `stream_id` the receiver already has `OtpIncomingFileReceive`
/// state for, with a freshly resolved chunk key and a resent
/// `StreamKeySetup`/`OtpFileContentSeq` ahead of the chunks - the receiving
/// side's existing worker is expected to accept a restarted stream for a
/// `stream_id` it already knows about.
#[allow(clippy::too_many_arguments)]
async fn recover_and_resend_file_content(
    session: &mut SessionState,
    contact_name: &str,
    seq: u64,
    to: UserId,
    recipient_pubkey_der: &[u8],
    stream_id: u64,
) -> proto::Result<()> {
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-recover-send");
    let Ok(Some(())) = otp_cli::recover_last_file(
        &session.otp_cli_cfg,
        contact_name,
        otp_cli::RecoverDirection::Sent,
        &temp_path,
    )
    .await
    else {
        secure_remove_file(&temp_path);
        return Ok(());
    };
    restrict_file_permissions(&temp_path);
    let Some(key) = otp_stream_key(session, stream_id, to, recipient_pubkey_der) else {
        secure_remove_file(&temp_path);
        return Ok(());
    };
    for (id, setup) in key.setups() {
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
    }
    session
        .otp_send_temp_files
        .insert(stream_id, temp_path.clone());
    session
        .peer_link
        .send_reliable_or_queue(to, P2pPayload::OtpFileContentSeq { stream_id, seq });
    session.otp_sending_streams.insert(stream_id, std::time::Instant::now());
    crate::client::file_transfer::spawn_send_file_worker(
        temp_path,
        key,
        to,
        stream_id,
        session.record_out_tx.clone(),
        session.file_events_tx.clone(),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Streamed pad delivery and its two-phase commit (`client::otp_pad`)
// ---------------------------------------------------------------------

use crate::client::otp_pad::{self, IncomingPad, OutgoingPad, PadEvent};
use crate::client::voice_stream::DecryptJob;

/// Begins streaming an already-generated pad to `to`.
///
/// Called once the pad exists on disk (`initiate_provisioning` has staged
/// it under `<contact>_pending/`), and again on every retry - the staged
/// files are the source both times, so a resend is byte-identical to the
/// original rather than a fresh generation.
///
/// Sends the announcement and the one-time key setup here, then hands the
/// bytes to a worker thread that paces itself against the link
/// (`otp_pad::spawn_send_pad_worker`).
pub(crate) async fn start_pad_send(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
    peer_name: &str,
    peer_pubkey_der: &[u8],
    contact_name: &str,
    size_mb: u32,
) {
    // Sharing a pad rides an ordinary `pq_hybrid` envelope, so it needs a
    // peer who announced a keybundle to seal one to (`OtpFraming`).
    if framing_for(&session.otp_own_pinned_der, peer_pubkey_der) != OtpFraming::PqWrapped {
        notify(
            ui_state,
            to,
            peer_name,
            "OTP session failed: sharing a pad needs pq_hybrid on both sides".to_string(),
            false,
        );
        return;
    }
    let dir = pending_setup_dir(&session.otp_cli_cfg, contact_name);
    let (_, _, peer_enc, peer_dec) = pending_paths(&dir);
    // Digested before anything is sent, and from the very files the worker
    // will read: this is what the receiver checks its own copy against, so
    // it has to describe exactly what goes on the wire.
    let (Ok(enc_digest), Ok(dec_digest), Ok(key_len)) = (
        crypto::otp::digest_key_file(&peer_enc),
        crypto::otp::digest_key_file(&peer_dec),
        std::fs::metadata(&peer_enc).map(|m| m.len()),
    ) else {
        notify(
            ui_state,
            to,
            peer_name,
            "OTP session failed: the generated pad could not be read".to_string(),
            false,
        );
        return;
    };

    let stream_id = session.next_stream_id;
    session.next_stream_id += 1;

    let Some(pq) = crate::client::voice_stream::build_pq_stream_out(
        session,
        None,
        stream_id,
        &[(to, peer_pubkey_der.to_vec())],
    ) else {
        notify(
            ui_state,
            to,
            peer_name,
            "OTP session failed: could not prepare the pad's stream key".to_string(),
            false,
        );
        return;
    };

    let readiness = session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpPadStart {
            stream_id,
            contact_name: contact_name.to_string(),
            keypair_size_mb: size_mb,
            key_len,
            enc_digest,
            dec_digest,
        },
    );
    for (id, setup) in pq.setups() {
        session
            .peer_link
            .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
    }

    // The worker polls this to decide when to read more off disk. It
    // borrows nothing from the session - just a snapshot channel into the
    // link's current depth - so the thread can outlive any one borrow.
    // Republished each tick by the session loop; the worker polls it for
    // backpressure (`OutgoingPad::depth`).
    let depth = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Shared with the generation task too, if one is still finishing: one
    // flag per peer, so Escape reaches whichever phase is running.
    let cancelled = session
        .otp_cancelled
        .entry(to)
        .or_insert_with(|| std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)))
        .clone();
    cancelled.store(false, std::sync::atomic::Ordering::Relaxed);
    otp_pad::spawn_send_pad_worker(
        peer_enc,
        peer_dec,
        crate::client::voice_stream::DirectStreamKey::Pq(pq),
        to,
        stream_id,
        session.record_out_tx.clone(),
        session.otp_pad_tx.clone(),
        depth.clone(),
        cancelled.clone(),
    );
    let (retransmits_at_start, peak_unacked_at_start) =
        session.peer_link.link_diagnostics(to).unwrap_or((0, 0));
    session.otp_outgoing_pads.insert(
        to,
        OutgoingPad {
            stream_id,
            sent: false,
            depth,
            read_bytes: 0,
            started_at: std::time::Instant::now(),
            retransmits_at_start,
            peak_unacked_at_start,
        },
    );
    // Generation just closed its own popup; this reopens it on the second
    // slow phase rather than leaving the screen empty until the peer
    // answers - which, because they are only asked once the whole pad has
    // arrived and verified (§16.1's two-phase commit), can be minutes.
    ui_state.begin_otp_pad_transfer(
        to,
        peer_name.to_string(),
        size_mb,
        crate::client::tui::ui::OtpPadPhase::Sending,
        crypto::otp::OtpPurpose::of_contact_name(contact_name),
    );
    notify(
        ui_state,
        to,
        peer_name,
        link_readiness_notice(readiness, peer_name, crypto::otp::OtpPurpose::of_contact_name(contact_name)),
        true,
    );
}

/// A peer is about to stream us a pad. Opens a staging directory and a
/// worker to write it into; nothing is decided or installed here.
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_pad_start(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    contact_name: String,
    keypair_size_mb: u32,
    key_len: u64,
    enc_digest: crypto::otp::KeyDigest,
    dec_digest: crypto::otp::KeyDigest,
) {
    // A pad already arriving from this peer is a superseded proposal -
    // they ran `/otp` again. Its staging directory goes now rather than
    // being left to the startup sweep, so two transfers never write to two
    // live directories for one contact.
    if let Some(previous) = session.otp_incoming_pads.remove(&from) {
        crate::client::otp_staging::secure_remove_dir(&previous.dir);
    }
    // And so does anything this peer had already put in front of the user.
    // A proposal that has been superseded must not still be sitting there
    // to answer: accepting it would report digests for a pad whose staging
    // directory was just erased, and leaving it queued is what made one
    // `/otp` produce two decision popups - the stale one and the real one.
    // The sending side already does exactly this for its own stale state
    // (`handle_otp_command`); this is the missing half on the receiver.
    ui_state.take_otp_invite_from(from);
    let Ok(dir) = crate::client::otp_staging::new_dir(&session.otp_cli_cfg, "pad-in") else {
        return;
    };
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        crate::client::otp_staging::secure_remove_dir(&dir);
        return;
    };
    let purpose = crypto::otp::OtpPurpose::of_contact_name(&contact_name);
    let key =
        crate::client::voice_stream::resolve_incoming_key(session, from, &sender.public_key_der);
    let job_tx = otp_pad::spawn_receive_pad_worker(
        key,
        dir.clone(),
        from,
        stream_id,
        key_len,
        enc_digest,
        dec_digest,
        session.otp_pad_tx.clone(),
    );
    session.otp_incoming_pads.insert(
        from,
        IncomingPad {
            stream_id,
            contact_name,
            keypair_size_mb,
            enc_digest,
            dec_digest,
            dir,
            job_tx,
            received_bytes: 0,
            started_at: std::time::Instant::now(),
        },
    );
    // The invitation cannot appear until all of this has arrived and both
    // digests match, so without a popup here the peer sees nothing at all
    // for the length of the transfer.
    ui_state.begin_otp_pad_transfer(
        from,
        sender.name.clone(),
        keypair_size_mb,
        crate::client::tui::ui::OtpPadPhase::Receiving,
        purpose,
    );
}

/// One arriving pad chunk, handed straight to that transfer's worker.
///
/// The byte count kept here is for the progress bar only - it counts
/// ciphertext handed over, not plaintext verified, and nothing decides
/// anything on it. What actually establishes the pad arrived intact is the
/// worker's own length and digest check (`PadEvent::Received`).
pub(crate) fn on_pad_chunk(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    seq: u32,
    blocks: Vec<Vec<u8>>,
) {
    if let Some(pad) = session.otp_incoming_pads.get_mut(&from)
        && pad.stream_id == stream_id
    {
        pad.received_bytes += blocks.iter().map(|b| b.len() as u64).sum::<u64>();
        let received = pad.received_bytes;
        let _ = pad.job_tx.send(DecryptJob::Chunk(seq, blocks));
        ui_state.set_otp_pad_transfer_progress(from, received);
    }
}

/// The sender says that was the last chunk - the worker now checks length
/// and digests and reports back through `on_pad_event`.
pub(crate) fn on_pad_end(session: &mut SessionState, from: UserId, stream_id: u64) {
    if let Some(pad) = session.otp_incoming_pads.get(&from)
        && pad.stream_id == stream_id
    {
        let _ = pad.job_tx.send(DecryptJob::End);
    }
}

/// Routes a `StreamKeySetup` to a pad transfer if one is expecting it -
/// returns whether it was consumed, so the ordinary stream handling only
/// sees setups that are not a pad's.
pub(crate) fn route_pad_key_setup(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    setup: &[u8],
) -> bool {
    if let Some(pad) = session.otp_incoming_pads.get(&from)
        && pad.stream_id == stream_id
    {
        let _ = pad.job_tx.send(DecryptJob::KeySetup(setup.to_vec()));
        return true;
    }
    false
}

/// Abandons an in-progress pad on this side and tells the peer to do the
/// same - the Escape key during either slow phase.
///
/// Everything staged is erased. That is the whole point: generation and
/// transfer between them can consume four times the per-key size on the
/// sender and twice it on the receiver, and a handshake nobody is waiting
/// for any more has no path back to being installed, so keeping any of it
/// only costs space (`otp_staging::sweep_abandoned_setups` exists because
/// that used to be exactly what happened).
///
/// Never touches the keychain: this only ever clears a pad that was staged
/// and never adopted. A contact already provisioned is not what a cancel
/// during setup can reach.
pub(crate) fn cancel_pad(session: &mut SessionState, ui_state: &mut UiState, peer: UserId) {
    let peer_name = peer_name_for(ui_state, peer);
    let mut had_anything = false;

    // Stops both background workers at their next chunk. They check this
    // rather than being killed, so each unwinds having released its file
    // handles - a thread torn down mid-write would leave the very
    // partial state this is trying to remove.
    if let Some(flag) = session.otp_cancelled.get(&peer) {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        had_anything = true;
    }

    if let Some(pad) = session.otp_outgoing_pads.remove(&peer) {
        session.peer_link.send_reliable_or_queue(
            peer,
            P2pPayload::OtpPadCancel {
                stream_id: pad.stream_id,
            },
        );
        had_anything = true;
    }
    if let Some(pad) = session.otp_incoming_pads.remove(&peer) {
        session.peer_link.send_reliable_or_queue(
            peer,
            P2pPayload::OtpPadCancel {
                stream_id: pad.stream_id,
            },
        );
        crate::client::otp_staging::secure_remove_dir(&pad.dir);
        had_anything = true;
    }

    // The sender's own generated halves, which outlive `.tmp/` by design.
    if let Some(contact) = contact_name_for_peer(session, peer, &peer_pubkey_der_of(ui_state, peer)) {
        if session
            .otp_store
            .get(&contact)
            .is_some_and(|c| c.pending_setup_size_mb.is_some())
        {
            discard_pending_setup(&session.otp_cli_cfg, &contact);
            session.otp_store.clear_pending_setup(&contact);
            let _ = session.otp_store.save();
            had_anything = true;
        }
        session.otp_ack_rows.retain(|(c, _), _| c != &contact);
    }
    session.otp_cancelled.remove(&peer);
    ui_state.close_otp_keygen_for(peer);
    if let Some(contact) = contact_name_for_peer(session, peer, &peer_pubkey_der_of(ui_state, peer)) {
        // A promise still waiting on their answer is abandoned too - the
        // answer, if it ever comes, must not start generating a pad the
        // user has just cancelled.
        had_anything |= session.otp_awaiting_consent.remove(&contact).is_some();
        session.otp_consented.remove(&contact);
    }

    if had_anything {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session cancelled - nothing was installed and the staged pad was erased"
                .to_string(),
            false,
        );
    }
}

/// Applies the peer's `OtpPadCancel`: they gave up, so this side stops
/// waiting and erases whatever it staged for them.
pub(crate) fn on_pad_cancel(session: &mut SessionState, ui_state: &mut UiState, from: UserId) {
    let peer_name = peer_name_for(ui_state, from);
    let mut had_anything = false;
    if let Some(flag) = session.otp_cancelled.get(&from) {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if session.otp_outgoing_pads.remove(&from).is_some() {
        had_anything = true;
    }
    if let Some(pad) = session.otp_incoming_pads.remove(&from) {
        crate::client::otp_staging::secure_remove_dir(&pad.dir);
        had_anything = true;
    }
    session.otp_cancelled.remove(&from);
    ui_state.close_otp_keygen_for(from);
    ui_state.take_otp_invite_from(from);
    if had_anything {
        notify(
            ui_state,
            from,
            &peer_name,
            format!("OTP session cancelled by {peer_name} - nothing was installed"),
            false,
        );
    }
}

/// This peer's announced public key, for the paths that only hold a
/// `UserId`. Empty when they are no longer known, which every caller
/// treats as "no contact name derivable".
fn peer_pubkey_der_of(ui_state: &UiState, peer: UserId) -> Vec<u8> {
    ui_state
        .known_users
        .get(&peer)
        .map(|u| u.public_key_der.clone())
        .unwrap_or_default()
}

/// Moves the sending side's transfer bar to what has actually been
/// *delivered*, rather than to what the worker has read off disk.
///
/// The two differ by whatever the link is still carrying, which is by
/// design (`otp_pad::PAD_INFLIGHT_FRAMES`) - so a bar drawn from disk
/// reads runs ahead, and reaches 100% while the peer may still be near
/// zero. That is worse than no bar at all: it says the transfer is done
/// when it has barely started, and then sits there for as long as the real
/// one takes.
pub(crate) fn refresh_pad_send_progress(
    session: &mut SessionState,
    ui_state: &mut UiState,
    to: UserId,
) {
    let Some(pad) = session.otp_outgoing_pads.get(&to) else {
        return;
    };
    let owed = session.peer_link.outbound_depth(to) as u64 * otp_pad::PAD_CHUNK_BYTES as u64;
    ui_state.set_otp_pad_transfer_progress(to, pad.read_bytes.saturating_sub(owed));
}

/// Applies one `PadEvent` - the session loop's `otp_pad_rx` arm, and where
/// the two-phase commit's *first* phase completes on each side. `pub` so a
/// test can drive it with a synthetic `PadEvent::Received` against a pad
/// staged via `SessionState::stage_incoming_pad_for_test`.
pub async fn on_pad_event(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    event: PadEvent,
) -> proto::Result<()> {
    match event {
        PadEvent::SendProgress {
            to,
            stream_id,
            sent_bytes,
        } => {
            if let Some(pad) = session.otp_outgoing_pads.get_mut(&to)
                && pad.stream_id == stream_id
            {
                pad.read_bytes = sent_bytes;
            }
            refresh_pad_send_progress(session, ui_state, to);
        }
        PadEvent::Sent { to, stream_id } => {
            // Nothing to announce: the receiver decides next, and only its
            // verification moves this forward. The popup stays up - the
            // link is still draining what the worker read, and the bar
            // keeps tracking that until it does.
            if let Some(pad) = session.otp_outgoing_pads.get_mut(&to)
                && pad.stream_id == stream_id
            {
                pad.sent = true;
            }
            refresh_pad_send_progress(session, ui_state, to);
        }
        PadEvent::SendFailed {
            to,
            stream_id,
            reason,
        } => {
            if session
                .otp_outgoing_pads
                .get(&to)
                .is_some_and(|p| p.stream_id == stream_id)
            {
                session.otp_outgoing_pads.remove(&to);
            }
            ui_state.close_otp_keygen_for(to);
            let peer_name = peer_name_for(ui_state, to);
            notify(
                ui_state,
                to,
                &peer_name,
                format!("OTP session failed: could not send the pad ({reason})"),
                false,
            );
        }
        PadEvent::Failed {
            from,
            stream_id,
            reason,
        } => {
            if session
                .otp_incoming_pads
                .get(&from)
                .is_some_and(|p| p.stream_id == stream_id)
            {
                session.otp_incoming_pads.remove(&from);
            }
            ui_state.close_otp_keygen_for(from);
            let from_name = peer_name_for(ui_state, from);
            notify(
                ui_state,
                from,
                &from_name,
                format!("OTP session failed: {reason}"),
                false,
            );
        }
        PadEvent::Received {
            from,
            stream_id,
            enc_digest,
            dec_digest,
        } => {
            // Every byte arrived and both halves match what the sender
            // declared. Still nothing installed - the user is asked first,
            // and even a yes only produces `OtpPadVerify`.
            let Some(pad) = session.otp_incoming_pads.get(&from) else {
                return Ok(());
            };
            if pad.stream_id != stream_id {
                return Ok(());
            }
            let contact_name = pad.contact_name.clone();
            let size_mb = pad.keypair_size_mb;
            // Temporary diagnostic - see `on_pad_verify`'s matching one on
            // the sending side. The receiver has no send window of its own
            // to measure, so this is elapsed time only.
            crate::log_warn!(
                "pad receive from {}: {size_mb}MB per key arrived in {:.1}s",
                peer_name_for(ui_state, from),
                pad.started_at.elapsed().as_secs_f64(),
            );
            let _ = (enc_digest, dec_digest);
            let from_name = peer_name_for(ui_state, from);
            // The transfer popup has done its job - what happens next is a
            // decision, not a wait, and the invite popup asks for it.
            ui_state.close_otp_keygen_for(from);

            // A re-delivery of the pad already installed - its commit was
            // lost - is re-verified straight away so the sender can finish
            // rather than retrying forever. Matched on the pad itself, not
            // merely on the contact being provisioned: a *different* pad
            // offered for the same contact is a new proposal, and silently
            // verifying it left the sender installing it while this side
            // kept the old one. Two pads under one name decode to garbage
            // with nothing anywhere reporting it, which is the exact
            // failure the two-phase commit exists to prevent.
            let pad_digest = crypto::otp::pad_pair_digest(&enc_digest, &dec_digest);
            // Or one the user already agreed to before it was generated,
            // knowing its size - the decision was made then, at the point
            // where declining still saved both sides the whole cost.
            // `contains`, not the `remove` this used to be: a pad this size
            // can take a long time, and any interruption between this
            // side's `OtpPadVerify` and the sender's matching `OtpPadCommit`
            // makes the sender re-offer the *whole* pad from scratch
            // (docs/PROTOCOL.md's reconnect-resend note), landing back here
            // a second time for the very same accepted proposal. Consuming
            // the consent on the first pass used to turn that ordinary
            // reconnect into a second decision popup for something already
            // agreed to; `on_pad_commit` clears it for real once the
            // exchange actually finishes installing.
            if session
                .otp_store
                .is_installed_pad(&contact_name, pad_digest)
                || session.otp_consented.contains(&contact_name)
            {
                send_pad_verify(session, from, &contact_name, true, enc_digest, dec_digest);
                return Ok(());
            }
            ui_state.push_otp_invite(from, from_name, contact_name, None, None, Some(size_mb));
            crate::client::voice_stream::play_bell_chime(session);
        }
    }
    let _ = wr;
    Ok(())
}

/// Sends this side's verification of a received pad - the receiver's half
/// of the two-phase commit. Never installs anything itself.
pub(crate) fn send_pad_verify(
    session: &mut SessionState,
    to: UserId,
    contact_name: &str,
    accepted: bool,
    enc_digest: crypto::otp::KeyDigest,
    dec_digest: crypto::otp::KeyDigest,
) {
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpPadVerify {
            contact_name: contact_name.to_string(),
            accepted,
            enc_digest,
            dec_digest,
        },
    );
}

/// The receiver reported what it reassembled. This is where the *sender*
/// decides: only if the digests match its own does it install its own half
/// and authorise the receiver to install theirs.
pub(crate) async fn on_pad_verify(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    contact_name: String,
    accepted: bool,
    enc_digest: crypto::otp::KeyDigest,
    dec_digest: crypto::otp::KeyDigest,
) {
    let peer_name = peer_name_for(ui_state, from);
    if let Some(pad) = session.otp_outgoing_pads.remove(&from) {
        // Temporary diagnostic: elapsed time plus the retransmit/window
        // deltas since the transfer began, so a slow send can be told
        // apart from a genuinely loss-stalled one (`p2p_reliable::ArqSender`'s
        // own doc - no selective-repeat, so one lost frame in a large
        // window stalls the whole thing until a retransmit timeout fires).
        let elapsed = pad.started_at.elapsed();
        let (retransmits_now, peak_unacked_now) =
            session.peer_link.link_diagnostics(from).unwrap_or((0, 0));
        crate::log_warn!(
            "pad send to {peer_name} finished in {:.1}s: {} retransmits, peak window {} frames",
            elapsed.as_secs_f64(),
            retransmits_now.saturating_sub(pad.retransmits_at_start),
            peak_unacked_now.max(pad.peak_unacked_at_start),
        );
    }
    // Whichever way they answered, this side has stopped waiting on the
    // link - the transfer popup comes down and the outcome is a notice.
    ui_state.close_otp_keygen_for(from);

    if !accepted {
        // Refused, or it did not survive the trip. Nothing was installed
        // on either side; the staged pad goes.
        discard_pending_setup(&session.otp_cli_cfg, &contact_name);
        session.otp_store.clear_pending_setup(&contact_name);
        let _ = session.otp_store.save();
        notify(
            ui_state,
            from,
            &peer_name,
            "OTP session cancelled".to_string(),
            false,
        );
        return;
    }

    // What *we* hold, recomputed from the staged files rather than
    // remembered: the comparison has to be against the bytes that would
    // actually be installed.
    let dir = pending_setup_dir(&session.otp_cli_cfg, &contact_name);
    let (_, _, peer_enc, peer_dec) = pending_paths(&dir);
    let (Ok(own_enc), Ok(own_dec)) = (
        crypto::otp::digest_key_file(&peer_enc),
        crypto::otp::digest_key_file(&peer_dec),
    ) else {
        notify(
            ui_state,
            from,
            &peer_name,
            "OTP session failed: the staged pad could not be verified".to_string(),
            false,
        );
        return;
    };
    if own_enc != enc_digest || own_dec != dec_digest {
        // The two sides do not hold the same pad. Refused on both sides
        // rather than installed - a mismatched pair produces silent
        // garbage, not an error, so this is the last point it can be
        // caught.
        discard_pending_setup(&session.otp_cli_cfg, &contact_name);
        session.otp_store.clear_pending_setup(&contact_name);
        let _ = session.otp_store.save();
        session.peer_link.send_reliable_or_queue(
            from,
            P2pPayload::OtpPadVerify {
                contact_name: contact_name.clone(),
                accepted: false,
                enc_digest: own_enc,
                dec_digest: own_dec,
            },
        );
        notify(
            ui_state,
            from,
            &peer_name,
            "OTP session failed: the pad did not match on both sides - nothing was installed"
                .to_string(),
            false,
        );
        return;
    }

    // Agreed. This side installs first, then authorises the other: a
    // commit that arrives is proof the sender already holds its half, so
    // the receiver can never end up the only one with a pad.
    if !commit_pending_setup(&session.otp_cli_cfg, &contact_name).await {
        notify(
            ui_state,
            from,
            &peer_name,
            "OTP session failed: could not install this side's half of the pad".to_string(),
            false,
        );
        return;
    }
    // A *new* pad was just installed over this contact name, resetting the
    // tool's own per-contact state - so every aloo-level counter keyed to
    // the old pad resets with it (`OtpStore::reset_for_new_pad`'s doc), or
    // the fresh pad would be born desynced at this layer. No digest is
    // recorded on the generating side, same as before: `installed_pad_digest`
    // answers "is an *arriving* pad a re-delivery", which only the
    // receiving side is ever asked.
    session.otp_store.reset_for_new_pad(&contact_name, None);
    purge_contact_for_new_pad(session, &contact_name);
    // The commit below is the one provisioning payload whose loss splits
    // the pair asymmetrically - this side provisioned and active, the peer
    // holding only staged bytes - so it is owed durably and re-sent on
    // every reconnect until `OtpPadCommitAck` confirms the install
    // (`resend_pending_commits`). Recorded *after* the reset, which starts
    // the entry from defaults.
    session.otp_store.mark_commit_owed(&contact_name);
    let _ = session.otp_store.save();
    finish_provisioning(&session.otp_cli_cfg, ui_state, from, &peer_name, &contact_name).await;
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::OtpPadCommit { contact_name });
}

/// Drops everything this side still holds for `contact_name` that was
/// produced under the pad a *replacement* has just been installed over -
/// the companion of `OtpStore::reset_for_new_pad`, run right after it by
/// every path that installs a new pad under an existing name
/// (`on_pad_verify`, `on_pad_commit`, `contacts::handle_install_otp_key`).
///
/// The reset zeroes the counters, but a queue is not a counter. Sealed
/// messages still waiting in the durable queue were spent on the old pad;
/// pumped after the reset they would go out as the new pad's first
/// positions, the peer's tool would refuse every one of them on its
/// metadata (right sequence, wrong key), nothing would ever be
/// acknowledged, and the new pad would be wedged at position zero before
/// it carried a single message. The same holds for a text held as
/// plaintext behind a spend of the old pad, a content send staged for an
/// offer the old pad carried, and the delivery rows waiting on old
/// acknowledgements. None of it can be delivered under the new pad, so all
/// of it goes - the positions it occupied belonged to a pad that no longer
/// exists on either side, which is the one case discarding a spent
/// position is correct.
pub(crate) fn purge_contact_for_new_pad(session: &mut SessionState, contact_name: &str) {
    if let Some(outbox) = session.otp_outbox.as_mut() {
        let dropped = outbox.retain_contacts(|c| c != contact_name);
        if dropped > 0 {
            crate::log_warn!(
                "{dropped} message(s) sealed under the pad being replaced for {contact_name} \
                 were dropped - they cannot be read under the new one"
            );
        }
    }
    session.otp_out_queue.clear(contact_name);
    session.otp_ack_rows.retain(|(c, _), _| c != contact_name);
    for staged in session.otp_store.take_content_sends_for(contact_name) {
        // Only a staged *recording* is this side's own working copy
        // (`temp_content_path`); a file offer points at the user's file.
        if staged.path.starts_with(&session.otp_cli_cfg.working_dir) {
            secure_remove_file(&staged.path);
        }
    }
}

/// The sender's digests matched and it has installed - so this side may
/// install too. The only path by which a received pad reaches the
/// keychain.
///
/// `pub` (not `pub(crate)`) for the same reason `on_pad_commit_ack` already
/// is: driving the install-failure/retry path directly needs a genuinely
/// staged pad and a real `otp` invocation, which only an integration test
/// outside this crate can set up realistically
/// (`SessionState::stage_incoming_pad_for_test`,
/// `test/otp_pad_commit_test.rs`).
pub async fn on_pad_commit(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    contact_name: String,
) {
    let peer_name = peer_name_for(ui_state, from);
    // The staged pad is looked up by the *contact name* the commit itself
    // carries, not by the sender's `UserId` alone: a commit retried across
    // a reconnect (`resend_pending_commits`) arrives from a fresh `UserId`,
    // while the staging that transfer left behind is still keyed under the
    // dead one - matching on the durable name is what lets the retry find
    // it anyway.
    let staged_key = session
        .otp_incoming_pads
        .iter()
        .find_map(|(key, pad)| (pad.contact_name == contact_name).then_some(*key));
    // Always acknowledged, even if already installed: that is exactly what
    // a retried commit whose first ack was lost looks like from here, and
    // answering again is what lets the sender stop.
    // Only a commit for the pad already installed is a no-op. A commit for
    // a *different* pad is the user's accepted replacement, and it has to
    // be installed - returning early there is what left the two sides
    // holding different pads under one name.
    let already_this_pad = staged_key
        .and_then(|key| session.otp_incoming_pads.get(&key))
        .map(|p| crypto::otp::pad_pair_digest(&p.enc_digest, &p.dec_digest))
        .is_some_and(|d| session.otp_store.is_installed_pad(&contact_name, d));
    if already_this_pad || staged_key.is_none() {
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpPadCommitAck { contact_name });
        if already_this_pad
            && let Some(key) = staged_key
            && let Some(pad) = session.otp_incoming_pads.remove(&key)
        {
            crate::client::otp_staging::secure_remove_dir(&pad.dir);
        }
        return;
    }
    let Some(key) = staged_key else {
        // Nothing staged for this contact - a commit for a transfer we no
        // longer have. Acknowledged so the sender stops retrying, but
        // nothing is installed from thin air.
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpPadCommitAck { contact_name });
        return;
    };
    // Borrowed, not removed: an install failure below (`otp` unreachable
    // right now, a full disk, ...) must leave the staged bytes exactly as
    // they were, so the next retried commit (`resend_pending_commits`, on
    // every reconnect) finds this same pad and genuinely tries the install
    // again - the self-healing this function's own doc above already
    // promises ("finding its staged pad by contact name"). Removing it
    // unconditionally here used to break that promise: the retry then hit
    // the "nothing staged" branch above, which acknowledges - a false
    // "installed" told to a sender that already believes the session is
    // live, while this side silently has nothing.
    let pad = session
        .otp_incoming_pads
        .get(&key)
        .expect("key was just found in this same map");
    let (enc_path, dec_path) = otp_pad::incoming_paths(&pad.dir);
    // Same reasoning as `commit_pending_setup`'s own removal: this exact
    // branch is reached for "a commit for a *different* pad ... the user's
    // accepted replacement" (this function's doc above), which
    // `add_contact` alone can never install over an existing entry -
    // without this, that replacement would fail every retry forever,
    // always reporting the misleading "will retry once the local otp
    // command works" below for a failure retrying can never fix.
    let _ = otp_cli::remove_contact(&session.otp_cli_cfg, &contact_name).await;
    let installed = otp_cli::add_contact(&session.otp_cli_cfg, &contact_name, &enc_path, &dec_path)
        .await
        .is_ok();
    if !installed {
        notify(
            ui_state,
            from,
            &peer_name,
            format!(
                "OTP: could not install the pad received from {peer_name} yet - will retry \
                 automatically once the local 'otp' command works"
            ),
            false,
        );
        return;
    }
    let pad = session
        .otp_incoming_pads
        .remove(&key)
        .expect("key was just found in this same map");
    crate::client::otp_staging::secure_remove_dir(&pad.dir);
    // The exchange is genuinely over now - nothing left to re-verify
    // without asking again, so the consent `on_pad_event`'s `Received`
    // arm checks no longer needs to (or should) outlive this pad.
    session.otp_consented.remove(&contact_name);
    // Recorded with the pad it actually is, so a later re-delivery of this
    // same pad is recognised as one and a different pad is not. A full
    // reset rather than a mark: the new pad replaced the tool's per-contact
    // state wholesale, so every aloo-level counter and remnant keyed to the
    // old pad resets with it (`OtpStore::reset_for_new_pad`'s doc).
    session.otp_store.reset_for_new_pad(
        &contact_name,
        Some(crypto::otp::pad_pair_digest(&pad.enc_digest, &pad.dec_digest)),
    );
    purge_contact_for_new_pad(session, &contact_name);
    let _ = session.otp_store.save();
    if let Some(peer) = ui_state.known_users.get(&from).cloned() {
        ui_state.open_private_room(peer);
    }
    finish_provisioning(&session.otp_cli_cfg, ui_state, from, &peer_name, &contact_name).await;
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::OtpPadCommitAck { contact_name });
}

/// The receiver has installed - the exchange is over.
pub fn on_pad_commit_ack(session: &mut SessionState, from: UserId, contact_name: String) {
    session.otp_outgoing_pads.remove(&from);
    // The peer has installed - the durable commit retry
    // (`resend_pending_commits`) is settled.
    if session.otp_store.clear_commit_owed(&contact_name) {
        let _ = session.otp_store.save();
    }
}
