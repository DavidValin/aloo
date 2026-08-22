//! Orchestration glue for the OTP layer: the send/receive-path decisions
//! (`contact_name_if_active`, `wrap_outgoing`/`unwrap_incoming`) and the
//! PqHybrid-channel provisioning handshake
//! (`initiate_provisioning`/`apply_incoming_setup`). Parallels
//! `envelope.rs`'s role for plain `pq_hybrid` sends, one layer up: nothing
//! here touches `crypto::pq` directly, it only wraps/unwraps the finished
//! blob that path already produces.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use crate::client::otp_cli::{self, OtpCliConfig, OtpCliOutcome};
use crate::client::otp_store::OtpStore;
use crate::client::session::SessionState;
use crate::client::tui::ui::{PendingOtpGenerate, UiState};
use crate::crypto;
use crate::p2p_proto::P2pPayload;
use crate::proto::{self, Content, Envelope, KeyMode, UserId, UserInfo};

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

/// One plaintext message held back because a genuine network ack for the
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
pub fn contact_name_if_active(session: &SessionState, peer_pubkey_der: &[u8]) -> Option<String> {
    let contact_name = contact_name_for_peer(session, peer_pubkey_der)?;
    session
        .otp_store
        .get(&contact_name)
        .filter(|s| s.provisioned)
        .map(|_| contact_name)
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
    if store.get(contact_name).map(|s| s.provisioned).unwrap_or(false) {
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
    Failed,
}

/// Unwraps wire bytes back to the `pq_hybrid` blob: `otp -c <contact_name>
/// --decrypt -y`. Always passes `assume_delivered: true` - local delivery
/// is immediate and self-vouching (the plaintext either reaches the local
/// application right now or this call already failed), the asymmetric
/// counterpart of the encrypt side's genuine-remote-ack requirement.
pub async fn unwrap_incoming(cfg: &OtpCliConfig, wire_bytes: &[u8], contact_name: &str) -> UnwrapOutcome {
    match otp_cli::decrypt_retrying(cfg, contact_name, wire_bytes, true).await {
        Ok(OtpCliOutcome::Ok(bytes)) => {
            // Every message begins with the sender's ack nonce; anything
            // shorter than one cannot be a message this build produced.
            if bytes.len() < crypto::otp::ACK_NONCE_BYTES {
                return UnwrapOutcome::Failed;
            }
            let (nonce, payload) = bytes.split_at(crypto::otp::ACK_NONCE_BYTES);
            UnwrapOutcome::Ok(payload.to_vec(), crypto::otp::ack_proof_for(nonce))
        }
        Ok(OtpCliOutcome::Rejected(reason)) => UnwrapOutcome::Rejected(reason),
        _ => UnwrapOutcome::Failed,
    }
}

/// `unwrap_incoming` plus the notice a rejection deserves - shared by
/// `on_message`/`on_file_offer`, the two receive paths where an incoming
/// envelope is genuinely OTP-wrapped. A rejection is worth saying out loud
/// (unlike an ordinary decode failure): it means this exact ciphertext was
/// not produced by the mirrored key at the position expected - a replay, a
/// reordered or duplicated message, or one from a source this pad doesn't
/// recognize - security-relevant on its own, distinct from a transient
/// failure.
async fn unwrap_or_notify(
    cfg: &OtpCliConfig,
    wire_bytes: &[u8],
    contact_name: &str,
    ui_state: &mut UiState,
    from: UserId,
    from_name: &str,
) -> Option<(Vec<u8>, crypto::otp::AckProof)> {
    match unwrap_incoming(cfg, wire_bytes, contact_name).await {
        UnwrapOutcome::Ok(bytes, proof) => Some((bytes, proof)),
        UnwrapOutcome::Rejected(reason) => {
            let reason = reason.trim().replace('\n', "; ");
            notify(
                ui_state,
                from,
                from_name,
                format!("OTP: a message from {from_name} was rejected ({reason}) - keys untouched"),
                false,
            );
            None
        }
        UnwrapOutcome::Failed => None,
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
    crate::client::otp_staging::secure_remove_dir(dir);
}

/// Best-effort overwrite-then-remove of one temp content file created via
/// `temp_content_path` - the single-file counterpart of `secure_remove_dir`,
/// for the plaintext/ciphertext staging files file/voice-under-OTP pipes
/// through `otp --encrypt`/`--decrypt` on disk (never buffered whole in
/// memory - see `otp_cli::encrypt_file`/`decrypt_file`).
pub(crate) fn secure_remove_file(path: &Path) {
    crate::client::otp_staging::secure_remove_file(path);
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
    cfg.working_dir.join(format!("{label}-{}-{nanos}", std::process::id()))
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) {}

/// A directory needs its executable bit to be traversable/writable-into at
/// all - `0o600` (no `x`) would make it impossible to create files inside,
/// unlike a plain file where `0o600` is exactly "owner read/write, nothing
/// else" (see `restrict_file_permissions`).
#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) {}

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
    peer_fp: &[u8; 32],
) -> Option<crypto::otp::OtpKeySetupPayload> {
    initiate_provisioning_with_progress(cfg, size_mb, own_fp, peer_fp, |_, _| {}).await
}

/// `initiate_provisioning`, reporting generation progress as it goes -
/// what `confirm_generate`'s background task drives the spinner popup
/// from. Only the `otp --new-key-pair` step reports: it is the one that
/// scales with `size_mb`, and so the only one worth watching.
pub async fn initiate_provisioning_with_progress(
    cfg: &OtpCliConfig,
    size_mb: u32,
    own_fp: &[u8; 32],
    peer_fp: &[u8; 32],
    on_progress: impl FnMut(u64, u64),
) -> Option<crypto::otp::OtpKeySetupPayload> {
    let contact_name = crypto::otp::contact_name_for(own_fp, peer_fp);
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
    let generated =
        otp_cli::new_key_pair_with_progress(&gen_cfg, size_mb, &name_a, &name_b, on_progress).await;
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
        otp_cli::add_contact(cfg, contact_name, &own_enc, &own_dec)
            .await
            .is_ok()
    } else {
        // Nothing staged: either this side adopted an existing keychain
        // entry rather than generating one (`detect_or_adopt_existing`), or
        // a previous ack already committed it. Both mean the contact should
        // already be there, which `has_contact` decides honestly.
        otp_cli::has_contact(cfg, contact_name).await.unwrap_or(false)
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
/// - No local keychain entry yet: opens `ui_state.otp_generate_confirm`, a
///   local Yes/No decision (`confirm_generate`/`cancel_generate` handle the
///   answer) - generating and sharing a fresh pad is never done without
///   this confirmation.
/// - An entry already exists: skips straight to sending an
///   `OtpSessionRequest` (no key material) - the peer still has to accept
///   it (`on_session_request`/the invite popup) before either side shows
///   "started", so a stale or one-sided local entry can never be silently
///   assumed to still work.
pub(crate) async fn handle_otp_command(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    key_mode: KeyMode,
    peer_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    let peer_name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let framing = framing_for(session.own_key_mode, key_mode);
    // Without `pq_hybrid` the pad is bound to the two pinned public keys,
    // so both sides must actually *have* one that survives a reconnect. A
    // `KeyMode::None` peer has no persistent identity by design
    // (docs/PROTOCOL.md §12.2), which means nothing distinguishes them from
    // anyone else who takes the same nickname - and spending pad on the
    // wrong person destroys it for the right one, since the bytes are gone
    // whether or not they could read them. Refused rather than risked.
    if framing == OtpFraming::Direct
        && !(crate::client::keymode_policy::uses_byte_comparison_pinning(key_mode)
            && crate::client::keymode_policy::uses_byte_comparison_pinning(session.own_key_mode))
    {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: without pq_hybrid, both sides need an identity that persists \
             across reconnects (password or pq_hybrid) - a 'none' identity cannot be told apart \
             from someone reusing the nickname"
                .to_string(),
            false,
        );
        return Ok(());
    }
    let Some(contact_name) = contact_name_for_peer(session, &peer_pubkey_der) else {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: could not read this peer's identity".to_string(),
            false,
        );
        return Ok(());
    };

    if !otp_cli::binary_available(&session.otp_cli_cfg) {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: the 'otp' command isn't installed - see github.com/DavidValin/otp-toolkit"
                .to_string(),
            false,
        );
        return Ok(());
    }

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

    // Without `pq_hybrid` on both sides there is no channel to share a
    // freshly generated pad over - the handshake that carries one is itself
    // an ordinary `pq_hybrid` send. A pad that is *already* installed on
    // both sides needs no such channel, though, so this refuses only the
    // generate-and-share path, never the resume path.
    if framing == OtpFraming::Direct && !already_have_key {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: without pq_hybrid a pad cannot be shared over the network - \
             generate one with 'otp --new-key-pair' and install it on both sides from /contacts (o)"
                .to_string(),
            false,
        );
        return Ok(());
    }

    if already_have_key {
        let payload = crypto::otp::OtpSessionRequestPayload {
            contact_name: contact_name.clone(),
        };
        let Ok(plaintext) = proto::encode(&payload) else {
            notify(
                ui_state,
                peer,
                &peer_name,
                "OTP session failed: could not encode the session request".to_string(),
                false,
            );
            return Ok(());
        };
        let send_id = session.next_stream_id;
        session.next_stream_id += 1;
        let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
            session.own_pq_private.as_ref(),
            session.pq_peer_keys.encap_for(peer),
            key_mode,
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
                "OTP session failed: could not encrypt the session request".to_string(),
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
        notify(ui_state, peer, &peer_name, link_readiness_notice(readiness, &peer_name), true);
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

        ui_state.open_otp_generate_confirm(peer, peer_name, key_mode, peer_pubkey_der);
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
pub(crate) async fn confirm_generate(
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
    let Some(own_fp) = session.own_pq_fp else {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            "OTP session failed: this session has no pq_hybrid identity".to_string(),
            false,
        );
        return Ok(());
    };
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

    if size_mb > OTP_MAX_PROVISIONABLE_MB {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            format!(
                "OTP session failed: {size_mb}MB per key is more than a direct link can \
                 deliver in one go - the limit for sharing over the network is \
                 {OTP_MAX_PROVISIONABLE_MB}MB per key. For a larger pad, generate it with \
                 'otp --new-key-pair' and install it from /contacts (o) on both sides"
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
    ui_state.open_otp_keygen(pending.peer, pending.peer_name.clone(), size_mb);
    let cfg = session.otp_cli_cfg.clone();
    let tx = session.otp_keygen_tx.clone();
    tokio::spawn(async move {
        let progress_tx = tx.clone();
        let payload = initiate_provisioning_with_progress(
            &cfg,
            size_mb,
            &own_fp,
            &peer_fp,
            move |written, total| {
                let _ = progress_tx.send(OtpKeygenEvent::Progress {
                    written_bytes: written,
                    total_bytes: total,
                });
            },
        )
        .await;
        let _ = tx.send(OtpKeygenEvent::Finished {
            pending: Box::new(pending),
            size_mb,
            payload: payload.map(Box::new),
        });
    });
    Ok(())
}

/// What a background pad generation reports back to the session loop -
/// see `SessionState::otp_keygen_tx`.
pub enum OtpKeygenEvent {
    /// One chunk of randomness handed to `otp --new-key-pair`; moves the
    /// spinner popup's bar.
    Progress { written_bytes: u64, total_bytes: u64 },
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
                pending.key_mode,
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

/// The largest pad (MB per key) the *automatic* `/otp` handshake can
/// deliver over a direct link, derived from how many chunks that link's
/// queue holds (`p2p::PENDING_MAX`) rather than picked: a pad is handed
/// over as one burst, and one that cannot fit whole would have its front
/// dropped and arrive unreassemblable.
///
/// This is deliberately far below `crypto::otp::OTP_SIZE_MB_MAX` (1TB per
/// key, what the real `otp` binary itself supports and what a pad may
/// actually *be*). The two limits answer different questions: how large a
/// pad this app can support at all, versus how large a one it can push
/// through a hole-punched UDP link in a single burst. A pad beyond this
/// ceiling is provisioned out of band instead - generate it with `otp
/// --new-key-pair` and install it from the contacts list (`/contacts`, `o`)
/// or by placing the files under the keychain directly - which has no size
/// ceiling of its own, since nothing crosses the network.
///
/// Checked before `otp --new-key-pair` runs, not after: generation reads
/// this many megabytes of true randomness *per key*, so discovering the
/// limit afterwards would mean spending all of that time to produce a pad
/// that is then refused.
pub const OTP_MAX_PROVISIONABLE_MB: u32 =
    (crate::client::p2p::PENDING_MAX * OTP_SETUP_CHUNK_BYTES / (1024 * 1024)) as u32;

/// Reports what happened to a just-queued OTP setup/session-request send:
/// `Active` means it genuinely went out on the wire right now, `Pending`
/// means it's held in the link's own queue until punching finishes - not
/// lost, but not sent yet either, and previously indistinguishable from
/// nothing having happened at all.
fn link_readiness_notice(readiness: crate::client::p2p::LinkReadiness, peer_name: &str) -> String {
    match readiness {
        crate::client::p2p::LinkReadiness::Active => {
            format!("OTP: setup sent to {peer_name}, waiting for their confirmation...")
        }
        crate::client::p2p::LinkReadiness::Pending => format!(
            "OTP: still establishing a direct connection to {peer_name} - will send as soon as it's up"
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
    if session.otp_store.get(&contact_name).is_some_and(|c| c.provisioned) {
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
        let peer_fp = crypto::pq::fingerprint_of_encoded(&sender.public_key_der);
        if let (Some(own_fp), Some(peer_fp)) = (own_fp, peer_fp) {
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
pub(crate) fn on_session_request(
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
    ui_state.push_otp_invite(from, from_name.clone(), payload.contact_name, None, None, None);
    // Same chime every decision popup plays on arrival.
    crate::client::voice_stream::play_bell_chime(session);
    notify(
        ui_state,
        from,
        &from_name,
        format!("OTP: {from_name} wants to resume a session - see the popup"),
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
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(to),
        sender.key_mode,
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
        send_pad_verify(session, invite.from, &contact_name, true, enc_digest, dec_digest);
        return Ok(());
    }
    let result: Result<(), String> = match (&invite.peer_encryption_key, &invite.peer_decryption_key) {
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
                Err(ack.reason.unwrap_or_else(|| "add-contact failed".to_string()))
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
        ui_state.open_otp_session(invite.from);
        refresh_otp_key_status(&session.otp_cli_cfg, ui_state, invite.from, &invite.contact_name).await;
        notify(
            ui_state,
            invite.from,
            &invite.from_name,
            format!("OTP session started at {}", format_now()),
            true,
        );
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
    notify(ui_state, invite.from, &invite.from_name, "OTP session cancelled".to_string(), false);
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
pub(crate) async fn on_key_setup_ack(
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
        ui_state.open_otp_session(from);
        refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &ack.contact_name).await;
        notify(
            ui_state,
            from,
            &sender.name,
            format!("OTP session started at {}", format_now()),
            true,
        );
        crate::client::session::daemon_otp_outcome(ui_state, session, from, true, "");
    } else if ack.reason.as_deref() == Some(NO_MATCHING_KEY_REASON) {
        let _ = otp_cli::remove_contact(&session.otp_cli_cfg, &ack.contact_name).await;
        discard_pending_setup(&session.otp_cli_cfg, &ack.contact_name);
        session.otp_store.forget(&ack.contact_name);
        let _ = session.otp_store.save();
        ui_state.open_otp_generate_confirm(
            from,
            sender.name.clone(),
            sender.key_mode,
            sender.public_key_der.clone(),
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
        discard_pending_setup(&session.otp_cli_cfg, &ack.contact_name);
        session.otp_store.clear_pending_setup(&ack.contact_name);
        let _ = session.otp_store.save();
        let reason = ack
            .reason
            .map(|r| format!(": {r}"))
            .unwrap_or_default();
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
pub fn decide_end_otp(
    state: Option<&crate::client::otp_store::OtpContactState>,
) -> EndOtpDecision {
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
pub(crate) async fn handle_end_otp_command(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    peer: UserId,
    key_mode: KeyMode,
    peer_pubkey_der: Vec<u8>,
) -> proto::Result<()> {
    let peer_name = ui_state
        .known_users
        .get(&peer)
        .map(|u| u.name.clone())
        .unwrap_or_default();
    let Some(contact_name) = contact_name_for_peer(session, &peer_pubkey_der) else {
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

    // Local teardown first, unconditionally - this side must never show
    // this session as active again, even if the notice below never reaches
    // the peer at all. The keychain entry itself is deliberately left
    // alone: `/endotp` pauses a session, it doesn't destroy the pad, so
    // `/otp` with the same contact later resumes the very same key exactly
    // where it left off (`OtpStore::pause_session`'s doc) instead of
    // generating a fresh one.
    discard_pending_setup(&session.otp_cli_cfg, &contact_name);
    session.otp_incoming_setup.remove(&peer);
    session.otp_out_queue.clear(&contact_name);
    session.otp_store.pause_session(&contact_name);
    let _ = session.otp_store.save();
    ui_state.clear_otp_active(peer);
    notify(
        ui_state,
        peer,
        &peer_name,
        "OTP session ended (the pad is kept - /otp with them resumes it)".to_string(),
        true,
    );

    send_end_session_payload(
        wr,
        session,
        peer,
        key_mode,
        &peer_pubkey_der,
        &contact_name,
        Content::OtpEndSession,
    )
    .await;
    Ok(())
}

/// Builds and sends `content` (`Content::OtpEndSession` or
/// `Content::OtpEndSessionAck`) to `to` over the ordinary `pq_hybrid`
/// channel - never pad-wrapped, since the pad may already be gone by the
/// time this runs. Signals the link first (`ensure_link`) for the two
/// callers that cannot assume one already exists: the initiator
/// (`handle_end_otp_command`) and the retry pass
/// (`resend_pending_end_notices`).
async fn send_end_session_payload(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    to: UserId,
    key_mode: KeyMode,
    pubkey_der: &[u8],
    contact_name: &str,
    content: Content,
) {
    session.peer_link.ensure_link(wr, to).await;
    queue_end_session_payload(session, to, key_mode, pubkey_der, contact_name, content);
}

/// `send_end_session_payload` without the `ensure_link` signalling round
/// trip - for the one caller that cannot signal: an ack sent straight back
/// at a peer whose `OtpEndSession` just arrived over the link, which is by
/// definition already up (their message just came in on it) - mirrors
/// `queue_key_setup_ack`'s identical reasoning.
fn queue_end_session_payload(
    session: &mut SessionState,
    to: UserId,
    key_mode: KeyMode,
    pubkey_der: &[u8],
    contact_name: &str,
    content: Content,
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
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(to),
        key_mode,
        pubkey_der,
        None,
        send_id,
        &plaintext,
        content,
    ) else {
        return;
    };
    session
        .peer_link
        .send_reliable_or_queue(
            to,
            P2pPayload::Envelope {
                channel: None,
                msg_id: None,
                envelope,
            },
        );
}

/// Applies an incoming `Content::OtpEndSession` envelope
/// (`direct_message::on_message`'s content-dispatch): the peer has
/// unilaterally ended the session - there is nothing here to accept or
/// reject, only to converge to. Pauses this side exactly like
/// `handle_end_otp_command` paused the initiator's own side (the pad
/// itself, and this store's record of it, both survive - only the
/// "active" marker and anything genuinely mid-flight are cleared), then
/// always replies with `OtpEndSessionAck` - even for a contact that was
/// already paused, since that is exactly what a retried notice whose first
/// ack got lost looks like on this end, and the initiator's own retry
/// (`resend_pending_end_notices`) only stops once one genuinely arrives.
pub(crate) async fn on_end_session(
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
    let had_session = session
        .otp_store
        .get(&payload.contact_name)
        .is_some_and(|s| s.provisioned);

    discard_pending_setup(&session.otp_cli_cfg, &payload.contact_name);
    session.otp_incoming_setup.remove(&from);
    session.otp_out_queue.clear(&payload.contact_name);
    session.otp_store.pause_after_peer_ended(&payload.contact_name);
    let _ = session.otp_store.save();
    ui_state.clear_otp_active(from);
    if had_session {
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP session ended by {from_name} (the pad is kept - /otp resumes it)"),
            false,
        );
    }

    queue_end_session_payload(
        session,
        from,
        sender.key_mode,
        &sender.public_key_der,
        &payload.contact_name,
        Content::OtpEndSessionAck,
    );
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
    if session.otp_store.clear_end_notice(&payload.contact_name) {
        let _ = session.otp_store.save();
    }
}

/// Re-sends every `/endotp` notice still owed to a reachable peer - the
/// `/endotp` counterpart of `resend_pending_setups`, driven by the same
/// `LinkStatusChanged` -> `Active` trigger and for the same reason: a peer
/// who was offline (or unreachable) when the session ended must still learn
/// about it, however long that takes, the instant they are reachable again.
pub(crate) async fn resend_pending_end_notices(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    if session.own_pq_fp.is_none() {
        return Ok(());
    }
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
        let Some(peer_info) = ui_state.known_users.get(&peer).cloned() else {
            continue;
        };
        send_end_session_payload(
            wr,
            session,
            peer,
            peer_info.key_mode,
            &pubkey_der,
            &contact_name,
            Content::OtpEndSession,
        )
        .await;
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
/// `pub(crate)`: OTP mail's own pad spends (`client::otp_mail`) refresh
/// through here too, when the mail's counterpart happens to be connected.
pub(crate) async fn refresh_otp_key_status(
    cfg: &otp_cli::OtpCliConfig,
    ui_state: &mut UiState,
    peer: UserId,
    contact_name: &str,
) {
    if let Ok(Some(detail)) = otp_cli::show_contact(cfg, contact_name).await {
        ui_state.set_otp_key_status(peer, otp_cli::OtpKeyStatus::new(cfg, contact_name, detail));
    }
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
    let Some(peer_pubkey) = ui_state.known_users.get(&peer).map(|u| u.public_key_der.clone()) else {
        return;
    };
    let Some(contact_name) = contact_name_if_active(session, &peer_pubkey) else {
        return;
    };
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, peer, &contact_name).await;
}

/// `crypto::otp::contact_name_for`, resolved from a peer's announced
/// `public_key_der` against our own `pq_hybrid` identity - `None` if either
/// fingerprint isn't available (we're not `pq_hybrid`, or the peer's bytes
/// don't decode as a `PqPublicBundle`).
fn contact_name_for_peer(session: &SessionState, peer_pubkey_der: &[u8]) -> Option<String> {
    match framing_for(session.own_key_mode, peer_key_mode_of(peer_pubkey_der, session)) {
        OtpFraming::PqWrapped => {
            let own_fp = session.own_pq_fp?;
            let peer_fp = crypto::pq::fingerprint_of_encoded(peer_pubkey_der)?;
            Some(crypto::otp::contact_name_for(&own_fp, &peer_fp))
        }
        // No pq identity on one side or the other, so there is no
        // fingerprint - the name comes from the two pinned public keys
        // instead. Never from the nickname: see
        // `crypto::otp::contact_name_for_keys` for what that would have
        // cost. `None` when this side has no stable key of its own to
        // derive from, which is exactly the `KeyMode::None` case
        // `handle_otp_command` refuses outright.
        OtpFraming::Direct => {
            let own_der = own_pinned_public_der(session)?;
            Some(crypto::otp::contact_name_for_keys(&own_der, peer_pubkey_der))
        }
    }
}

/// This side's own pinned public key, in the same encoding a peer would
/// announce it in - the local half of `contact_name_for_keys`.
///
/// `None` for `KeyMode::None`, whose keypair is generated fresh on every
/// connect: there is nothing stable to derive a contact name from, and a
/// name that changed every session would file each reconnect under a
/// different pad.
fn own_pinned_public_der(session: &SessionState) -> Option<Vec<u8>> {
    session.otp_own_pinned_der.clone()
}

/// Whether `peer_pubkey_der` parses as a `pq_hybrid` bundle - the only
/// thing that distinguishes a peer able to carry an inner envelope from one
/// that is not. Read from the key itself rather than a stored `KeyMode` so
/// the two can never disagree.
fn peer_key_mode_of(peer_pubkey_der: &[u8], _session: &SessionState) -> KeyMode {
    if crypto::pq::fingerprint_of_encoded(peer_pubkey_der).is_some() {
        KeyMode::PqHybrid
    } else {
        KeyMode::None
    }
}

/// The message body carried directly in a `Direct`-framed envelope - its
/// single block is the plaintext, not a sealed blob.
///
/// Mirrors `session::decrypt_envelope_for`'s contract exactly (only
/// `Content::Text` produces a body; anything else is routed elsewhere), so
/// the two framings behave identically from the caller's point of view.
fn direct_body(envelope: &Envelope) -> Option<crate::client::tui::ui::MessageBody> {
    if envelope.content != Content::Text {
        return None;
    }
    let plaintext = envelope.blocks.first()?;
    Some(crate::client::tui::ui::MessageBody::Text(
        String::from_utf8_lossy(plaintext).into_owned(),
    ))
}

/// `direct_body`'s file-offer counterpart - mirrors
/// `session::decrypt_file_offer`'s contract for `Direct` framing.
fn direct_file_offer(
    envelope: &Envelope,
) -> Option<crate::client::file_transfer::FileOfferPayload> {
    if envelope.content != Content::FileOffer {
        return None;
    }
    proto::decode(envelope.blocks.first()?).ok()
}

/// A voice offer's payload under `Direct` framing - `direct_file_offer`'s
/// counterpart, and for the same reason: without `pq_hybrid` there is no
/// sealed envelope to open, so the single block *is* the encoded payload.
fn direct_voice_offer(
    envelope: &Envelope,
) -> Option<crate::client::file_transfer::VoiceOfferPayload> {
    if envelope.content != Content::VoiceOffer {
        return None;
    }
    proto::decode(envelope.blocks.first()?).ok()
}

/// The envelope a stream-shaped OTP send (a file offer, a voice offer)
/// puts inside the pad, framed the way this pair's `OtpFraming` says.
///
/// Text has the same choice inline in `send_now`; this exists because the
/// two stream paths need it identically, and because getting it wrong is
/// silent: hardcoding `PqHybrid` here made every file and voice send fail
/// closed for a pure-OTP pair, with the text path beside it working.
fn offer_envelope(
    session: &SessionState,
    to: UserId,
    peer_key_mode: KeyMode,
    recipient_pubkey_der: &[u8],
    stream_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    match framing_for(session.own_key_mode, peer_key_mode) {
        OtpFraming::Direct => Some(Envelope {
            content,
            blocks: vec![plaintext.to_vec()],
        }),
        OtpFraming::PqWrapped => crate::client::envelope::encrypt_envelope_for(
            session.own_pq_private.as_ref(),
            session.pq_peer_keys.encap_for(to),
            KeyMode::PqHybrid,
            recipient_pubkey_der,
            None,
            stream_id,
            plaintext,
            content,
        ),
    }
}

/// How one contact's OTP traffic is framed inside the pad.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpFraming {
    /// The ordinary case: an ordinary `pq_hybrid` envelope is built first
    /// and *that* is what goes through `otp --encrypt`. The envelope's own
    /// signature and the pad's decrypt verdict both apply.
    PqWrapped,
    /// One side or the other has no `pq_hybrid` identity, so there is no
    /// envelope to build: the message's plaintext goes straight into the
    /// pad.
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
    /// It also stops a pad being spent on ~7KB of ML-DSA/ML-KEM/RSA
    /// overhead per message, which for a short chat line was the
    /// overwhelming majority of what each message cost.
    Direct,
}

/// Which framing applies between these two. `PqWrapped` needs `pq_hybrid`
/// on *both* sides - an envelope can only be built if this side can sign
/// one and the other can open it - so anything else is `Direct`.
pub fn framing_for(own_key_mode: KeyMode, peer_key_mode: KeyMode) -> OtpFraming {
    if own_key_mode == KeyMode::PqHybrid && peer_key_mode == KeyMode::PqHybrid {
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
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
    channel: Option<String>,
    log_index: Option<usize>,
    msg_id: Option<u64>,
) -> proto::Result<()> {
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
    // With `pq_hybrid` on both sides the pad wraps an ordinary envelope;
    // without it there is no envelope to build and the plaintext goes
    // straight into the pad, authenticated by the decrypt verdict alone -
    // see `OtpFraming`.
    let envelope = match framing_for(session.own_key_mode, recipient_key_mode) {
        OtpFraming::Direct => Envelope {
            content,
            // Not a sealed blob: this is the plaintext itself, and it is
            // safe here precisely because everything below is about to be
            // one-time-pad encrypted. `Envelope` is reused rather than a
            // parallel shape so `content` still routes the message the same
            // way at the far end.
            blocks: vec![plaintext.to_vec()],
        },
        OtpFraming::PqWrapped => {
            // Only meaningful for the framing that actually seals something
            // to their key: `can_address` refuses a `pq_hybrid` recipient
            // from a sender with no `pq_hybrid` signing identity of its own.
            // Under `Direct` there is no envelope and no signature - the pad
            // is the whole protection, and the two identities are only ever
            // used to *name* the contact - so applying it there silently
            // dropped every send from a password-pinned side to a
            // `pq_hybrid` one, in a session both ends showed as active.
            if !crate::client::keymode_policy::can_address(recipient_key_mode, session.own_key_mode)
            {
                return Ok(());
            }
            let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
                session.own_pq_private.as_ref(),
                session.pq_peer_keys.encap_for(to),
                recipient_key_mode,
                recipient_pubkey_der,
                channel.clone(),
                send_id,
                plaintext,
                content,
            ) else {
                let peer_name = peer_name_for(ui_state, to);
                notify(
                    ui_state,
                    to,
                    &peer_name,
                    "OTP: failed to build the underlying pq_hybrid envelope - message not sent"
                        .to_string(),
                    false,
                );
                if let Some(idx) = log_index {
                    ui_state.mark_dm_message_failed(to, idx);
                }
                return Ok(());
            };
            envelope
        }
    };
    let Some(pq_blob) = envelope.blocks.first().cloned() else {
        return Ok(());
    };
    let Some(wrapped) = wrap_outgoing(&session.otp_cli_cfg, pq_blob, contact_name).await else {
        // otp binary missing/misconfigured/exhausted - hard error. Never
        // silently fall back to sending the unwrapped pq_hybrid envelope.
        let peer_name = peer_name_for(ui_state, to);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: the otp command failed to encrypt this message - message not sent".to_string(),
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
    let (wrapped, ack_proof) = wrapped;
    let mut otp_envelope = envelope;
    otp_envelope.blocks = vec![wrapped];
    session.otp_store.record_sent(
        contact_name,
        seq,
        crate::client::otp_store::PendingOtpContent::Text {
            channel: channel.clone(),
        },
        Some(ack_proof),
    );
    let _ = session.otp_store.save();
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await;
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpEnvelope {
            channel,
            seq,
            msg_id,
            envelope: otp_envelope,
        },
    );
    if let Some(msg_id) = msg_id {
        ui_state.mark_awaiting_pad_ack(to, msg_id);
        session.otp_ack_rows.insert((contact_name.to_string(), seq), msg_id);
    }
    crate::client::session::request_rotation(session, to);
    Ok(())
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
    recipient_key_mode: KeyMode,
    recipient_pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
    channel: Option<String>,
    log_index: Option<usize>,
    msg_id: Option<u64>,
) -> proto::Result<()> {
    let unacked = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
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
    if unacked {
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
        session.otp_out_queue.enqueue(contact_name.to_string(), item);
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
            recipient_key_mode,
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
        .is_some();
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
    let peer_key_mode = peer_key_mode_of(recipient_pubkey_der, session);
    let Some(envelope) = offer_envelope(
        session,
        to,
        peer_key_mode,
        recipient_pubkey_der,
        stream_id,
        &plaintext,
        Content::FileOffer,
    ) else {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to build the file offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let Some(key) = crate::client::voice_stream::resolve_direct_key(
        session,
        stream_id,
        to,
        peer_key_mode,
        recipient_pubkey_der,
    ) else {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to prepare the file transfer key - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let Some(pq_blob) = envelope.blocks.first().cloned() else {
        return Ok(());
    };
    let Some(wrapped) = wrap_outgoing(&session.otp_cli_cfg, pq_blob, contact_name).await else {
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: the otp command failed to encrypt this file offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let seq = session
        .otp_store
        .get(contact_name)
        .map(|s| s.next_out_seq)
        .unwrap_or(0);
    let (wrapped, ack_proof) = wrapped;
    let mut otp_envelope = envelope;
    otp_envelope.blocks = vec![wrapped];
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
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await;
    let (msg_id, delivery) = ui_state.start_delivery(&[to]);
    ui_state.log_own_file_offer_dm(to, stream_id, filename.clone(), size, Some(delivery));
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
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpFileOffer {
            channel: None,
            stream_id,
            seq,
            msg_id: Some(msg_id),
            envelope: otp_envelope,
        },
    );
    ui_state.mark_awaiting_pad_ack(to, msg_id);
    session.otp_ack_rows.insert((contact_name.to_string(), seq), msg_id);
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
    let unacked = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
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
    let cipher_path = temp_content_path(&session.otp_cli_cfg, "otp-voice-cipher");
    let outcome =
        otp_cli::encrypt_file_retrying(&session.otp_cli_cfg, contact_name, &plain_path, &cipher_path, true).await;
    // Taken before the plaintext is wiped: the PCM *is* this spend's
    // payload, so its digest is what the receiver will be able to prove
    // (`crypto::otp::ack_proof_for_file`).
    let ack_proof = crate::crypto::otp::ack_proof_for_file(&plain_path).ok();
    secure_remove_file(&plain_path);
    if !matches!(outcome, Ok(otp_cli::FileCliOutcome::Ok)) {
        secure_remove_file(&cipher_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to encrypt this voice message - not sent".to_string(),
            false,
        );
        return Ok(());
    }
    restrict_file_permissions(&cipher_path);
    let payload = crate::client::file_transfer::VoiceOfferPayload { duration_ms };
    let Ok(plaintext) = proto::encode(&payload) else {
        secure_remove_file(&cipher_path);
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
    let peer_key_mode = peer_key_mode_of(recipient_pubkey_der, session);
    let Some(envelope) = offer_envelope(
        session,
        to,
        peer_key_mode,
        recipient_pubkey_der,
        stream_id,
        &plaintext,
        Content::VoiceOffer,
    ) else {
        secure_remove_file(&cipher_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to build the voice offer - not sent".to_string(),
            false,
        );
        return Ok(());
    };
    let Some(key) = crate::client::voice_stream::resolve_direct_key(
        session,
        stream_id,
        to,
        peer_key_mode,
        recipient_pubkey_der,
    ) else {
        secure_remove_file(&cipher_path);
        notify(
            ui_state,
            to,
            &peer_name,
            "OTP: failed to prepare the voice message key - not sent".to_string(),
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
        crate::client::otp_store::PendingOtpContent::Voice { duration_ms },
        ack_proof,
    );
    let _ = session.otp_store.save();
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, contact_name).await;
    session.otp_send_temp_files.insert(stream_id, cipher_path.clone());
    session.own_file_targets.insert(
        stream_id,
        crate::client::file_transfer::OwnFileTarget {
            to,
            path: cipher_path,
            key,
            otp: None,
        },
    );
    session.peer_link.ensure_link(wr, to).await;
    let msg_id = ui_state.own_stream_msg_id(stream_id);
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpVoiceOffer {
            stream_id,
            seq,
            msg_id,
            envelope,
        },
    );
    if let Some(msg_id) = msg_id {
        ui_state.mark_awaiting_pad_ack(to, msg_id);
        session.otp_ack_rows.insert((contact_name.to_string(), seq), msg_id);
    }
    crate::client::session::request_rotation(session, to);
    Ok(())
}

/// Applies an incoming `P2pEvent::OtpMessage`/`OtpFileOffer`'s envelope:
/// unwraps the OTP layer, then hands the recovered `pq_hybrid` blob to the
/// existing, unmodified decrypt pipeline exactly as a plain envelope would
/// use. Only sends `OtpDeliveryAck` back once local delivery has actually
/// succeeded - see the module doc for why that's always safe to do
/// immediately and unconditionally, unlike the encrypt side's ack-gating.
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
    _msg_id: Option<u64>,
    envelope: Envelope,
) -> proto::Result<()> {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return Ok(());
    };
    let Some(contact_name) = contact_name_for_peer(session, &sender.public_key_der) else {
        return Ok(());
    };
    let Some(blob) = envelope.blocks.first() else {
        return Ok(());
    };
    // Checked *before* `otp --decrypt` runs, not after - a resend of a
    // message this contact's counter already moved past (the peer decrypted
    // it fine; only the ack got lost) must never reach the pad a second
    // time. See `OtpStore::is_next_expected`'s doc.
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        return Ok(());
    }
    // Taken *before* the decrypt spends this message's key bytes: the row
    // logged below records which part of the pad was this message's, and
    // `otp --show-contact` only ever reports where the pad has already
    // got to (`UiState::message_crypto`). The post-spend refresh that
    // keeps the room's own header live still happens, further down.
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &contact_name).await;
    let Some(pq_blob) =
        unwrap_or_notify(&session.otp_cli_cfg, blob, &contact_name, ui_state, from, &from_name).await
    else {
        return Ok(());
    };
    let (pq_blob, ack_proof) = pq_blob;
    if !session.otp_store.record_received(&contact_name, seq) {
        return Ok(());
    }
    let mut inner = envelope;
    inner.blocks = vec![pq_blob];
    // With `pq_hybrid` there is a sealed envelope inside the pad to open;
    // without it the pad's plaintext *is* the message, already authenticated
    // by the decrypt verdict that got us here (`OtpFraming`).
    let body = match framing_for(session.own_key_mode, peer_key_mode_of(&sender.public_key_der, session)) {
        OtpFraming::Direct => direct_body(&inner),
        OtpFraming::PqWrapped => crate::client::session::decrypt_envelope_for(
            inner,
            from,
            &sender,
            channel.as_deref(),
            session,
        ),
    };
    if let Some(body) = body {
        match &channel {
            Some(ch) => ui_state.on_channel_message(ch, from, from_name, body),
            None => ui_state.on_direct_message(from, from_name, body),
        }
        refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &contact_name).await;
        // No ordinary `DeliveryReceipt` here. It would say exactly what
        // the ack below already says, except unprovenly - and the sender's
        // row would ignore it anyway, since a pad-protected leg accepts
        // only the pad's own acknowledgement (`DeliveryProof`).
        crate::client::session::request_rotation(session, from);
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq, proof: ack_proof });
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
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    let Some(contact_name) = contact_name_for_peer(session, &sender.public_key_der) else {
        return;
    };
    let Some(blob) = envelope.blocks.first() else {
        return;
    };
    // Checked *before* `otp --decrypt` runs - see `on_message`'s identical
    // guard for why a resend of an already-processed offer must never
    // touch the pad a second time.
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        return;
    }
    let Some(pq_blob) =
        unwrap_or_notify(&session.otp_cli_cfg, blob, &contact_name, ui_state, from, &from_name).await
    else {
        return;
    };
    let (pq_blob, ack_proof) = pq_blob;
    if !session.otp_store.record_received(&contact_name, seq) {
        return;
    }
    refresh_otp_key_status(&session.otp_cli_cfg, ui_state, from, &contact_name).await;
    let mut inner = envelope;
    inner.blocks = vec![pq_blob];
    // Same split as `on_message`: sealed envelope under `pq_hybrid`, bare
    // plaintext without it.
    let payload = match framing_for(session.own_key_mode, peer_key_mode_of(&sender.public_key_der, session)) {
        OtpFraming::Direct => direct_file_offer(&inner),
        OtpFraming::PqWrapped => crate::client::session::decrypt_file_offer(
            &inner,
            from,
            &sender,
            channel.as_deref(),
            session,
        ),
    };
    let Some(payload) = payload else {
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
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq, proof: ack_proof });
}

/// `on_file_offer`'s voice counterpart, for `P2pEvent::OtpVoiceOffer`.
/// Unlike a file, an OTP voice message never goes through a popup
/// (`Content::VoiceOffer`'s doc) - this both unwraps the offer *and*
/// immediately stages and accepts the transfer in one step: registers the
/// receive-side bookkeeping exactly like `session::accept_file_offer`
/// would, then sends `FileAccept` straight back so the sender's existing,
/// unmodified `FileAccepted` handling starts streaming the pre-encrypted
/// content right away. There is only ever one pad spend for the whole
/// message here (`send_voice_offer` already OTP-encrypted the recording
/// before this envelope was even sent, see its doc) - so no
/// `OtpDeliveryAck` here; only once the whole recording has arrived and
/// been decrypted (`finish_incoming_file`) is one sent.
pub async fn on_voice_offer(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    stream_id: u64,
    seq: u64,
    envelope: Envelope,
) {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return;
    };
    let Some(contact_name) = contact_name_for_peer(session, &sender.public_key_der) else {
        return;
    };
    if !session.otp_store.record_received(&contact_name, seq) {
        return;
    }
    let _ = session.otp_store.save();
    // Same split as `on_message`/`on_file_offer`: a sealed envelope under
    // `pq_hybrid`, the encoded payload itself without one.
    let payload = match framing_for(
        session.own_key_mode,
        peer_key_mode_of(&sender.public_key_der, session),
    ) {
        OtpFraming::Direct => direct_voice_offer(&envelope),
        OtpFraming::PqWrapped => {
            crate::client::session::decrypt_voice_offer(&envelope, from, &sender, session)
        }
    };
    let Some(payload) = payload else {
        return;
    };
    let key = crate::client::voice_stream::resolve_incoming_key(session, from, &sender.public_key_der);
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-recv-voice-cipher");
    session.otp_incoming_file_receives.insert(
        (from, stream_id),
        crate::client::file_transfer::OtpIncomingFileReceive {
            contact_name,
            seq: Some(seq),
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
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return Ok(());
    };
    let Some(contact_name) = contact_name_for_peer(session, &sender.public_key_der) else {
        return Ok(());
    };
    // `record_acked` refuses a `proof` that doesn't match what was buried
    // under the pad of the message `seq` names, which is what keeps the
    // gate closed against anyone who saw the packet but could not open it.
    if !session.otp_store.record_acked(&contact_name, seq, Some(proof)) {
        return Ok(());
    }
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
    flush_one_queued(wr, ui_state, session, &contact_name).await
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
            send_now(
                wr,
                session,
                ui_state,
                to,
                contact_name,
                recipient.key_mode,
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
            send_now(
                wr,
                session,
                ui_state,
                to,
                contact_name,
                recipient.key_mode,
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
    let to = target.to;
    let unacked = session
        .otp_store
        .get(&contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
    if unacked {
        session
            .otp_out_queue
            .enqueue(contact_name, PendingOtpSend::FileContent { stream_id, to });
        return Ok(());
    }
    let target = session
        .own_file_targets
        .remove(&stream_id)
        .expect("just confirmed present above");
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-send");
    let outcome =
        otp_cli::encrypt_file_retrying(&session.otp_cli_cfg, &contact_name, &target.path, &temp_path, true).await;
    // Same substitute as a voice message's, for the same reason: the file's
    // own bytes are the pad plaintext, so there is no room to bury a nonce.
    let ack_proof = crate::crypto::otp::ack_proof_for_file(&target.path).ok();
    match outcome {
        Ok(otp_cli::FileCliOutcome::Ok) => {
            restrict_file_permissions(&temp_path);
            session.otp_send_temp_files.insert(stream_id, temp_path.clone());
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
            refresh_otp_key_status(&session.otp_cli_cfg, ui_state, to, &contact_name).await;
            session
                .peer_link
                .send_reliable_or_queue(to, P2pPayload::OtpFileContentSeq { stream_id, seq });
            // The content phase reports onto the offer's own row - there is
            // only ever one row per transfer, and it is not finished until
            // the bytes have actually landed.
            let row = ui_state.own_stream_msg_id(stream_id);
            if let Some(msg_id) = row {
                ui_state.mark_awaiting_pad_ack(to, msg_id);
                session.otp_ack_rows.insert((contact_name.to_string(), seq), msg_id);
            }
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
    // A file decrypts straight to its real download location; a voice
    // message has no destination file at all, so it decrypts to a second
    // (plaintext) temp file that's read back into memory and deleted
    // immediately below - matches how a live-streamed voice message is
    // already held fully in memory (`plaintext_accum`), just skipping the
    // live part.
    let decrypt_dest = match &pending.kind {
        OtpIncomingKind::File { final_path } => final_path.clone(),
        OtpIncomingKind::Voice { .. } => temp_content_path(&session.otp_cli_cfg, "otp-recv-voice"),
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
    secure_remove_file(&pending.temp_path);
    if !matches!(outcome, Ok(otp_cli::FileCliOutcome::Ok)) {
        let _ = std::fs::remove_file(&decrypt_dest);
        if matches!(pending.kind, OtpIncomingKind::File { .. }) {
            ui_state.set_file_failed(from, stream_id);
        }
        let from_name = peer_name_for(ui_state, from);
        let what = match pending.kind {
            OtpIncomingKind::File { .. } => "file",
            OtpIncomingKind::Voice { .. } => "voice message",
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
            ui_state.on_direct_message(
                from,
                from_name,
                crate::client::tui::ui::MessageBody::Voice { duration_ms, pcm },
            );
            crate::client::session::request_rotation(session, from);
        }
    }
    // `seq` is `None` only if a file's content genuinely finished
    // decrypting before its own `OtpFileContentSeq` ever arrived - not
    // possible over an ordered reliable link (it's always sent first), but
    // guarded rather than assumed; nothing to ack in that case.
    if let (Some(seq), Some(proof)) = (pending.seq, ack_proof) {
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq, proof });
    }
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
    let own_fp = session.own_pq_fp?;
    ui_state.known_users.iter().find_map(|(id, info)| {
        let peer_fp = crypto::pq::fingerprint_of_encoded(&info.public_key_der)?;
        if crypto::otp::contact_name_for(&own_fp, &peer_fp) == contact_name {
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
    if session.own_pq_fp.is_none() {
        return Ok(());
    }
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
            peer_info.key_mode,
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
pub(crate) async fn recover_and_resend(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    if session.own_pq_fp.is_none() {
        return Ok(());
    }
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
        let Some((to, recipient_pubkey_der)) =
            peer_for_contact_name(session, ui_state, &contact_name)
        else {
            continue;
        };
        match content {
            crate::client::otp_store::PendingOtpContent::Text { channel } => {
                recover_and_resend_text(wr, session, &contact_name, seq, to, channel).await?;
            }
            crate::client::otp_store::PendingOtpContent::File { stream_id, .. } => {
                recover_and_resend_file_offer(wr, session, ui_state, &contact_name, seq, to, stream_id)
                    .await?;
            }
            crate::client::otp_store::PendingOtpContent::FileContent { stream_id } => {
                recover_and_resend_file_content(session, &contact_name, seq, to, &recipient_pubkey_der, stream_id)
                    .await?;
            }
            crate::client::otp_store::PendingOtpContent::Voice { duration_ms } => {
                recover_and_resend_voice(
                    wr,
                    session,
                    ui_state,
                    &contact_name,
                    seq,
                    to,
                    &recipient_pubkey_der,
                    duration_ms,
                )
                .await?;
            }
            crate::client::otp_store::PendingOtpContent::Mail { .. } => {
                // A mail's retry rides the server control channel, not a
                // P2P link - `client::otp_mail::resend_pending` handles it
                // once per (re)connect; nothing to do on a link transition.
            }
        }
    }
    Ok(())
}

async fn recover_and_resend_text(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    contact_name: &str,
    seq: u64,
    to: UserId,
    channel: Option<String>,
) -> proto::Result<()> {
    let Ok(Some(recovered)) =
        otp_cli::recover_last(&session.otp_cli_cfg, contact_name, otp_cli::RecoverDirection::Sent).await
    else {
        // Nothing to recover, or the CLI failed - leave the gate exactly as
        // it is (never fall back to a fresh encode) and try again on the
        // next reconnect.
        return Ok(());
    };
    let envelope = Envelope {
        content: Content::Text,
        blocks: vec![recovered],
    };
    // The same row the original send named, so a recovery that finally
    // gets through turns that row green rather than leaving it
    // undelivered forever (docs/PROTOCOL.md 7.2.1).
    let msg_id = session
        .otp_ack_rows
        .get(&(contact_name.to_string(), seq))
        .copied();
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpEnvelope {
            channel,
            seq,
            msg_id,
            envelope,
        },
    );
    Ok(())
}

/// Offer-phase recovery, mirroring `recover_and_resend_text` exactly: the
/// offer is a genuine pad spend in its own right (`send_file_offer`'s
/// doc), so recovering means recovering that same ciphertext, never
/// re-encoding a fresh one - resent under the *same*
/// `stream_id` the original offer used, so an eventual `FileAccepted` for
/// it still finds the matching `OwnFileTarget` entry (only ever missing if
/// this process itself restarted mid-transfer, since that map is
/// in-memory only - a rarer, best-effort-only case this doesn't try to
/// solve).
async fn recover_and_resend_file_offer(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &UiState,
    contact_name: &str,
    seq: u64,
    to: UserId,
    stream_id: u64,
) -> proto::Result<()> {
    let Ok(Some(recovered)) =
        otp_cli::recover_last(&session.otp_cli_cfg, contact_name, otp_cli::RecoverDirection::Sent).await
    else {
        return Ok(());
    };
    let envelope = Envelope {
        content: Content::FileOffer,
        blocks: vec![recovered],
    };
    let msg_id = ui_state.own_stream_msg_id(stream_id);
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpFileOffer {
            channel: None,
            stream_id,
            seq,
            msg_id,
            envelope,
        },
    );
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
    let Some(key) = crate::client::voice_stream::resolve_direct_key(
        session,
        stream_id,
        to,
        KeyMode::PqHybrid,
        recipient_pubkey_der,
    ) else {
        secure_remove_file(&temp_path);
        return Ok(());
    };
    if let crate::client::voice_stream::DirectStreamKey::Pq(pq) = &key {
        let setups = pq.setups();
        for (id, setup) in setups {
            session
                .peer_link
                .send_reliable_or_queue(id, P2pPayload::StreamKeySetup { stream_id, setup });
        }
    }
    session.otp_send_temp_files.insert(stream_id, temp_path.clone());
    session
        .peer_link
        .send_reliable_or_queue(to, P2pPayload::OtpFileContentSeq { stream_id, seq });
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

#[allow(clippy::too_many_arguments)]
async fn recover_and_resend_voice(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    contact_name: &str,
    seq: u64,
    to: UserId,
    recipient_pubkey_der: &[u8],
    duration_ms: u32,
) -> proto::Result<()> {
    let temp_path = temp_content_path(&session.otp_cli_cfg, "otp-recover-voice");
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
    let payload = crate::client::file_transfer::VoiceOfferPayload { duration_ms };
    let Ok(plaintext) = proto::encode(&payload) else {
        secure_remove_file(&temp_path);
        return Ok(());
    };
    let stream_id = session.next_stream_id;
    session.next_stream_id += 1;
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(to),
        KeyMode::PqHybrid,
        recipient_pubkey_der,
        None,
        stream_id,
        &plaintext,
        Content::VoiceOffer,
    ) else {
        secure_remove_file(&temp_path);
        return Ok(());
    };
    let Some(key) = crate::client::voice_stream::resolve_direct_key(
        session,
        stream_id,
        to,
        KeyMode::PqHybrid,
        recipient_pubkey_der,
    ) else {
        secure_remove_file(&temp_path);
        return Ok(());
    };
    session.otp_send_temp_files.insert(stream_id, temp_path.clone());
    session.own_file_targets.insert(
        stream_id,
        crate::client::file_transfer::OwnFileTarget {
            to,
            path: temp_path,
            key,
            otp: None,
        },
    );
    let msg_id = ui_state.own_stream_msg_id(stream_id);
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpVoiceOffer {
            stream_id,
            seq,
            msg_id,
            envelope,
        },
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
    key_mode: KeyMode,
    peer_pubkey_der: &[u8],
    contact_name: &str,
    size_mb: u32,
) {
    if key_mode != KeyMode::PqHybrid {
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
    otp_pad::spawn_send_pad_worker(
        peer_enc,
        peer_dec,
        crate::client::voice_stream::DirectStreamKey::Pq(pq),
        to,
        stream_id,
        session.record_out_tx.clone(),
        session.otp_pad_tx.clone(),
        depth.clone(),
    );
    session.otp_outgoing_pads.insert(
        to,
        OutgoingPad {
            stream_id,
            sent: false,
            depth,
        },
    );
    notify(
        ui_state,
        to,
        peer_name,
        link_readiness_notice(readiness, peer_name),
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
    let Ok(dir) = crate::client::otp_staging::new_dir(&session.otp_cli_cfg, "pad-in") else {
        return;
    };
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        crate::client::otp_staging::secure_remove_dir(&dir);
        return;
    };
    let key = crate::client::voice_stream::resolve_incoming_key(
        session,
        from,
        &sender.public_key_der,
    );
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
        },
    );
}

/// One arriving pad chunk, handed straight to that transfer's worker.
pub(crate) fn on_pad_chunk(
    session: &mut SessionState,
    from: UserId,
    stream_id: u64,
    seq: u32,
    blocks: Vec<Vec<u8>>,
) {
    if let Some(pad) = session.otp_incoming_pads.get(&from)
        && pad.stream_id == stream_id
    {
        let _ = pad.job_tx.send(DecryptJob::Chunk(seq, blocks));
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

/// Applies one `PadEvent` - the session loop's `otp_pad_rx` arm, and where
/// the two-phase commit's *first* phase completes on each side.
pub(crate) async fn on_pad_event(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    event: PadEvent,
) -> proto::Result<()> {
    match event {
        PadEvent::Sent { to, stream_id } => {
            // Nothing to announce: the receiver decides next, and only its
            // verification moves this forward.
            if let Some(pad) = session.otp_outgoing_pads.get_mut(&to)
                && pad.stream_id == stream_id
            {
                pad.sent = true;
            }
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
            let _ = (enc_digest, dec_digest);
            let from_name = peer_name_for(ui_state, from);

            // Already provisioned: this is a re-delivery whose commit was
            // lost, not a new proposal. Re-verified straight away so the
            // sender can finish rather than retrying forever.
            if session
                .otp_store
                .get(&contact_name)
                .is_some_and(|c| c.provisioned)
            {
                send_pad_verify(session, from, &contact_name, true, enc_digest, dec_digest);
                return Ok(());
            }
            ui_state.push_otp_invite(
                from,
                from_name,
                contact_name,
                None,
                None,
                Some(size_mb),
            );
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
    session.otp_outgoing_pads.remove(&from);

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
    session.otp_store.mark_provisioned(&contact_name);
    session.otp_store.clear_pending_setup(&contact_name);
    let _ = session.otp_store.save();
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::OtpPadCommit { contact_name });
    ui_state.mark_otp_active(from);
    notify(
        ui_state,
        from,
        &peer_name,
        format!("OTP session started at {}", format_now()),
        true,
    );
}

/// The sender's digests matched and it has installed - so this side may
/// install too. The only path by which a received pad reaches the
/// keychain.
pub(crate) async fn on_pad_commit(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    contact_name: String,
) {
    let peer_name = peer_name_for(ui_state, from);
    // Always acknowledged, even if already installed: that is exactly what
    // a retried commit whose first ack was lost looks like from here, and
    // answering again is what lets the sender stop.
    let already = session
        .otp_store
        .get(&contact_name)
        .is_some_and(|c| c.provisioned);
    if already {
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpPadCommitAck { contact_name });
        return;
    }
    let Some(pad) = session.otp_incoming_pads.remove(&from) else {
        // Nothing staged for this peer - a commit for a transfer we no
        // longer have. Acknowledged so the sender stops retrying, but
        // nothing is installed from thin air.
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpPadCommitAck { contact_name });
        return;
    };
    let (enc_path, dec_path) = otp_pad::incoming_paths(&pad.dir);
    let installed = otp_cli::add_contact(&session.otp_cli_cfg, &contact_name, &enc_path, &dec_path)
        .await
        .is_ok();
    crate::client::otp_staging::secure_remove_dir(&pad.dir);
    if !installed {
        notify(
            ui_state,
            from,
            &peer_name,
            "OTP session failed: could not install the received pad".to_string(),
            false,
        );
        return;
    }
    session.otp_store.mark_provisioned(&contact_name);
    let _ = session.otp_store.save();
    session
        .peer_link
        .send_reliable_or_queue(from, P2pPayload::OtpPadCommitAck { contact_name });
    ui_state.mark_otp_active(from);
    if let Some(peer) = ui_state.known_users.get(&from).cloned() {
        ui_state.open_private_room(peer);
    }
    notify(
        ui_state,
        from,
        &peer_name,
        format!("OTP session started at {}", format_now()),
        true,
    );
}

/// The receiver has installed - the exchange is over.
pub(crate) fn on_pad_commit_ack(session: &mut SessionState, from: UserId, contact_name: String) {
    let _ = (from, &contact_name);
    session.otp_outgoing_pads.remove(&from);
}
