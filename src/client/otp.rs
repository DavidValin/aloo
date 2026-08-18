//! Orchestration glue for the OTP layer: the send/receive-path decisions
//! (`contact_name_if_active`, `wrap_outgoing`/`unwrap_incoming`) and the
//! PqHybrid-channel provisioning handshake
//! (`initiate_provisioning`/`apply_incoming_setup`). Parallels
//! `envelope.rs`'s role for plain `pq_hybrid` sends, one layer up: nothing
//! here touches `crypto::pq` directly, it only wraps/unwraps the finished
//! blob that path already produces.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

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
    },
    Channel {
        channel: String,
        to: UserId,
        plaintext: Vec<u8>,
        content: Content,
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
}

/// `Some(contact_name)` iff OTP is usable for this peer right now: their
/// keychain contact has been marked provisioned in `session.otp_store`,
/// either by a completed handshake (`apply_incoming_setup`/the ack path) or
/// by `detect_or_adopt_existing` finding it already there. Implicitly
/// requires `own_key_mode == PqHybrid`, since `own_pq_fp` is only ever
/// `Some` in that case - OTP always rides on top of an established
/// `pq_hybrid` identity, never a `Password`/`None` one.
pub(crate) fn contact_name_if_active(session: &SessionState, peer_pubkey_der: &[u8]) -> Option<String> {
    let own_fp = session.own_pq_fp?;
    let peer_fp = crypto::pq::fingerprint_of_encoded(peer_pubkey_der)?;
    let contact_name = crypto::otp::contact_name_for(&own_fp, &peer_fp);
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
pub async fn wrap_outgoing(cfg: &OtpCliConfig, pq_blob: Vec<u8>, contact_name: &str) -> Option<Vec<u8>> {
    match otp_cli::encrypt_retrying(cfg, contact_name, &pq_blob, true).await {
        Ok(OtpCliOutcome::Ok(bytes)) => Some(bytes),
        _ => None,
    }
}

/// Unwraps wire bytes back to the `pq_hybrid` blob: `otp -c <contact_name>
/// --decrypt -y`. Always passes `assume_delivered: true` - local delivery
/// is immediate and self-vouching (the plaintext either reaches the local
/// application right now or this call already failed), the asymmetric
/// counterpart of the encrypt side's genuine-remote-ack requirement.
pub async fn unwrap_incoming(cfg: &OtpCliConfig, wire_bytes: &[u8], contact_name: &str) -> Option<Vec<u8>> {
    match otp_cli::decrypt_retrying(cfg, contact_name, wire_bytes, true).await {
        Ok(OtpCliOutcome::Ok(bytes)) => Some(bytes),
        _ => None,
    }
}

/// Best-effort overwrite-then-remove of a staging directory holding raw
/// one-time-pad key bytes that have already been consumed into `otp`'s own
/// keychain (or are about to be discarded because they never got that
/// far) - this material is the actual one-time secret, so it doesn't just
/// get `remove_dir_all`'d.
fn secure_remove_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(len) = std::fs::metadata(&path).map(|m| m.len()) {
                let _ = std::fs::write(&path, vec![0u8; len as usize]);
            }
            let _ = std::fs::remove_file(&path);
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// Best-effort overwrite-then-remove of one temp content file created via
/// `temp_content_path` - the single-file counterpart of `secure_remove_dir`,
/// for the plaintext/ciphertext staging files file/voice-under-OTP pipes
/// through `otp --encrypt`/`--decrypt` on disk (never buffered whole in
/// memory - see `otp_cli::encrypt_file`/`decrypt_file`).
pub(crate) fn secure_remove_file(path: &Path) {
    if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
        let _ = std::fs::write(path, vec![0u8; len as usize]);
    }
    let _ = std::fs::remove_file(path);
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

/// Runs the initiating side of the PqHybrid-channel OTP handshake (plan
/// step 1-4): generates a fresh keypair, keeps this side's own working
/// half, and returns the payload to send the peer over their existing
/// `pq_hybrid` channel - the *other* role's key files, respecting the
/// role-inversion the `otp` CLI's own key generation performs (README:
/// "the roles are inverted between the two parties" - what one party calls
/// its encryption key, the other calls its decryption key). Only ever
/// called in response to an explicit user "Enable OTP" action, never
/// automatically.
pub async fn initiate_provisioning(
    cfg: &OtpCliConfig,
    size_mb: u32,
    own_fp: &[u8; 32],
    peer_fp: &[u8; 32],
) -> Option<crypto::otp::OtpKeySetupPayload> {
    let contact_name = crypto::otp::contact_name_for(own_fp, peer_fp);
    let name_a = format!("{contact_name}_a");
    let name_b = format!("{contact_name}_b");

    otp_cli::new_key_pair(cfg, size_mb, &name_a, &name_b)
        .await
        .ok()?;

    let dir_a = cfg.working_dir.join(format!("{name_a}_keys"));
    let dir_b = cfg.working_dir.join(format!("{name_b}_keys"));

    let own_enc = dir_a.join(format!("encryption_for_{name_b}.key"));
    let own_dec = dir_a.join(format!("decryption_from_{name_b}.key"));
    let add_result = otp_cli::add_contact(cfg, &contact_name, &own_enc, &own_dec).await;
    secure_remove_dir(&dir_a);
    add_result.ok()?;

    let peer_enc_path = dir_b.join(format!("encryption_for_{name_a}.key"));
    let peer_dec_path = dir_b.join(format!("decryption_from_{name_a}.key"));
    let peer_encryption_key = std::fs::read(&peer_enc_path).ok();
    let peer_decryption_key = std::fs::read(&peer_dec_path).ok();
    secure_remove_dir(&dir_b);

    Some(crypto::otp::OtpKeySetupPayload {
        contact_name,
        keypair_size_mb: size_mb,
        peer_encryption_key: peer_encryption_key?,
        peer_decryption_key: peer_decryption_key?,
    })
}

/// Runs the receiving side of the handshake (plan step 5-6): stages the
/// received key bytes to temp files under `cfg.working_dir` just long
/// enough for `otp --add-contact` to consume them, then securely removes
/// the staging directory regardless of outcome.
pub async fn apply_incoming_setup(
    cfg: &OtpCliConfig,
    payload: &crypto::otp::OtpKeySetupPayload,
) -> crypto::otp::OtpKeySetupAckPayload {
    let staging_dir = cfg
        .working_dir
        .join(format!("{}_incoming", payload.contact_name));
    let ack = |accepted: bool, reason: Option<String>| crypto::otp::OtpKeySetupAckPayload {
        contact_name: payload.contact_name.clone(),
        accepted,
        reason,
    };
    if let Err(e) = std::fs::create_dir_all(&staging_dir) {
        return ack(false, Some(format!("staging directory: {e}")));
    }
    restrict_dir_permissions(&staging_dir);

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
    if key_mode != KeyMode::PqHybrid || session.own_key_mode != KeyMode::PqHybrid {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: both sides must use pq_hybrid".to_string(),
            false,
        );
        return Ok(());
    }
    let Some(own_fp) = session.own_pq_fp else {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: this session has no pq_hybrid identity".to_string(),
            false,
        );
        return Ok(());
    };
    let Some(peer_fp) = crypto::pq::fingerprint_of_encoded(&peer_pubkey_der) else {
        notify(
            ui_state,
            peer,
            &peer_name,
            "OTP session failed: could not read this peer's identity".to_string(),
            false,
        );
        return Ok(());
    };
    let contact_name = crypto::otp::contact_name_for(&own_fp, &peer_fp);

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

    let already_have_key =
        detect_or_adopt_existing(&session.otp_cli_cfg, &mut session.otp_store, &contact_name).await;

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
                envelope,
            },
        );
        // "Started" isn't shown yet either way - only on_key_setup_ack
        // shows that, once the peer has genuinely accepted - but the send
        // itself (or its lack) is now always visible.
        notify(ui_state, peer, &peer_name, link_readiness_notice(readiness, &peer_name), true);
    } else {
        ui_state.open_otp_generate_confirm(peer, peer_name, key_mode, peer_pubkey_der);
    }
    Ok(())
}

/// `UiAction::ConfirmOtpGenerate`'s handler: the user said yes to "generate
/// a pad and share it over pq_hybrid" (`ui_state.otp_generate_confirm`) and
/// then chose `size_mb` (MB per key) in the prompt that followed
/// (`ui_state.otp_size_input`). Generates the keypair at that size, keeps
/// this side's own working half (`initiate_provisioning`), and sends the
/// peer's half - along with the size, so the deciding side can see what
/// it's agreeing to before it answers (`PendingOtpInvite::pad_size_mb`) -
/// as `Content::OtpKeySetup`. Still does not become active on this side
/// either, until the peer answers with `OtpKeySetupAck{accepted: true}`
/// (`on_key_setup_ack`).
pub(crate) async fn confirm_generate(
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

    // Immediate feedback the moment a valid size is submitted - generating
    // the keypair and staging it into the keychain is a real subprocess
    // call that can take a moment (longer, the larger the size chosen),
    // and this whole event loop is blocked on it meanwhile (nothing else
    // redraws or processes until it returns), so silence here previously
    // looked identical to a hang.
    notify(
        ui_state,
        pending.peer,
        &pending.peer_name,
        format!(
            "OTP: generating a fresh {size_mb}MB keypair for {}...",
            pending.peer_name
        ),
        true,
    );
    let Some(payload) =
        initiate_provisioning(&session.otp_cli_cfg, size_mb, &own_fp, &peer_fp).await
    else {
        notify(
            ui_state,
            pending.peer,
            &pending.peer_name,
            "OTP session failed: could not generate a keypair".to_string(),
            false,
        );
        return Ok(());
    };
    send_key_setup_chunked(wr, session, ui_state, &pending, &payload).await
}

/// A whole pad (1MB per key by default, 2MB total) cannot go out as one
/// `pq_hybrid` envelope - it rides a single UDP datagram with no
/// fragmentation of its own beneath this layer, and the OS refuses a send
/// anywhere near that size outright. `OtpKeySetupChunk`'s doc has the full
/// reasoning; this splits both keys into `OTP_SETUP_CHUNK_BYTES`-sized
/// pieces and sends each as its own ordinary `pq_hybrid` send, exactly the
/// way a voice/file stream already sends many small chunks instead of one
/// huge one.
async fn send_key_setup_chunked(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
    pending: &PendingOtpGenerate,
    payload: &crypto::otp::OtpKeySetupPayload,
) -> proto::Result<()> {
    let total_len = payload.peer_encryption_key.len() as u32;
    let mut offset: u32 = 0;
    loop {
        let end = (offset as usize + OTP_SETUP_CHUNK_BYTES).min(total_len as usize) as u32;
        let chunk = crypto::otp::OtpKeySetupChunk {
            contact_name: payload.contact_name.clone(),
            keypair_size_mb: payload.keypair_size_mb,
            total_len,
            offset,
            enc_chunk: payload.peer_encryption_key[offset as usize..end as usize].to_vec(),
            dec_chunk: payload.peer_decryption_key[offset as usize..end as usize].to_vec(),
        };
        let is_last = end >= total_len;

        let Ok(plaintext) = proto::encode(&chunk) else {
            notify(
                ui_state,
                pending.peer,
                &pending.peer_name,
                "OTP session failed: could not encode the setup message".to_string(),
                false,
            );
            return Ok(());
        };
        // `chunk` (above) is zeroized on drop, but its encoded bytes - the
        // actual pad material, bincode-serialized - are an ordinary `Vec<u8>`
        // the moment `proto::encode` returns one; wrapped immediately so
        // this copy doesn't just get freed unzeroized once it's been sealed
        // below.
        let plaintext = zeroize::Zeroizing::new(plaintext);
        let send_id = session.next_stream_id;
        session.next_stream_id += 1;
        let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
            session.own_pq_private.as_ref(),
            session.pq_peer_keys.encap_for(pending.peer),
            pending.key_mode,
            &pending.pubkey_der,
            None,
            send_id,
            &plaintext,
            Content::OtpKeySetup,
        ) else {
            notify(
                ui_state,
                pending.peer,
                &pending.peer_name,
                "OTP session failed: could not encrypt the setup message".to_string(),
                false,
            );
            return Ok(());
        };
        let readiness = session.peer_link.ensure_link(wr, pending.peer).await;
        session.peer_link.send_reliable_or_queue(
            pending.peer,
            P2pPayload::Envelope {
                channel: None,
                envelope,
            },
        );
        if is_last {
            notify(
                ui_state,
                pending.peer,
                &pending.peer_name,
                link_readiness_notice(readiness, &pending.peer_name),
                true,
            );
            return Ok(());
        }
        offset = end;
    }
}

/// One key's raw bytes sent per `OtpKeySetupChunk`. `pq_hybrid`'s own
/// per-send overhead (an ML-KEM ciphertext, an RSA ciphertext and two
/// signatures - several KB, constant regardless of content size) plus
/// bincode/ARQ framing must still fit alongside two chunks this size
/// inside one UDP datagram (~65KB hard ceiling, no fragmentation below
/// this layer) - 16KB leaves generous headroom.
const OTP_SETUP_CHUNK_BYTES: usize = 16 * 1024;

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
        // Previously silent - a genuinely lost/corrupted setup message and
        // one that never arrived at all looked identical (nothing). Now
        // at least the difference between "nothing arrived" and "something
        // arrived but couldn't be opened" is visible.
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
            notify(
                ui_state,
                from,
                &from_name,
                format!("OTP: received a malformed setup message from {from_name}"),
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
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::Envelope {
            channel: None,
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

pub(crate) async fn accept_invite(
    wr: &mut impl crate::control::ControlSink,
    session: &mut SessionState,
    ui_state: &mut UiState,
) -> proto::Result<()> {
    let Some(invite) = ui_state.take_otp_invite() else {
        return Ok(());
    };
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
        session.otp_store.mark_provisioned(&invite.contact_name);
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
        ui_state.mark_otp_active(invite.from);
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
    send_key_setup_ack(
        wr,
        session,
        ui_state,
        invite.from,
        &invite.contact_name,
        false,
        None,
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
        session.otp_store.mark_provisioned(&ack.contact_name);
        let _ = session.otp_store.save();
        ui_state.mark_otp_active(from);
        notify(
            ui_state,
            from,
            &sender.name,
            format!("OTP session started at {}", format_now()),
            true,
        );
    } else if ack.reason.as_deref() == Some(NO_MATCHING_KEY_REASON) {
        let _ = otp_cli::remove_contact(&session.otp_cli_cfg, &ack.contact_name).await;
        session.otp_store.forget(&ack.contact_name);
        let _ = session.otp_store.save();
        ui_state.open_otp_generate_confirm(
            from,
            sender.name.clone(),
            sender.key_mode,
            sender.public_key_der.clone(),
        );
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
    }
}

/// `crypto::otp::contact_name_for`, resolved from a peer's announced
/// `public_key_der` against our own `pq_hybrid` identity - `None` if either
/// fingerprint isn't available (we're not `pq_hybrid`, or the peer's bytes
/// don't decode as a `PqPublicBundle`).
fn contact_name_for_peer(session: &SessionState, peer_pubkey_der: &[u8]) -> Option<String> {
    let own_fp = session.own_pq_fp?;
    let peer_fp = crypto::pq::fingerprint_of_encoded(peer_pubkey_der)?;
    Some(crypto::otp::contact_name_for(&own_fp, &peer_fp))
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
) -> proto::Result<()> {
    if !crate::client::keymode_policy::can_address(recipient_key_mode, session.own_key_mode) {
        return Ok(());
    }
    let send_id = session.next_stream_id;
    session.next_stream_id += 1;
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
            "OTP: failed to build the underlying pq_hybrid envelope - message not sent".to_string(),
            false,
        );
        if let Some(idx) = log_index {
            ui_state.mark_dm_message_failed(to, idx);
        }
        return Ok(());
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
    let mut otp_envelope = envelope;
    otp_envelope.blocks = vec![wrapped];
    session.otp_store.record_sent(
        contact_name,
        seq,
        crate::client::otp_store::PendingOtpContent::Text {
            channel: channel.clone(),
        },
    );
    let _ = session.otp_store.save();
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpEnvelope {
            channel,
            seq,
            envelope: otp_envelope,
        },
    );
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
pub(crate) async fn send_or_queue(
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
) -> proto::Result<()> {
    let unacked = session
        .otp_store
        .get(contact_name)
        .and_then(|s| s.pending_unacked_out_seq)
        .is_some();
    if unacked {
        let item = match channel {
            Some(ch) => PendingOtpSend::Channel {
                channel: ch,
                to,
                plaintext: plaintext.to_vec(),
                content,
            },
            None => PendingOtpSend::Direct {
                to,
                plaintext: plaintext.to_vec(),
                content,
                log_index,
            },
        };
        session.otp_out_queue.enqueue(contact_name.to_string(), item);
        // Previously silent: a message held back here looked identical to
        // one that was simply never sent, with no way to tell them apart -
        // this is exactly what made a genuinely stuck gate (e.g. stale
        // pending_unacked_out_seq state) indistinguishable from things
        // working. Always surfaced now, even though the common case (a
        // fast, healthy round trip) clears almost immediately.
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
pub(crate) async fn send_file_offer(
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
    let Some(envelope) = crate::client::envelope::encrypt_envelope_for(
        session.own_pq_private.as_ref(),
        session.pq_peer_keys.encap_for(to),
        KeyMode::PqHybrid,
        recipient_pubkey_der,
        None,
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
        KeyMode::PqHybrid,
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
    );
    let _ = session.otp_store.save();
    ui_state.log_own_file_offer_dm(to, stream_id, filename.clone(), size);
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
            envelope: otp_envelope,
        },
    );
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
pub(crate) async fn send_voice_offer(
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
        KeyMode::PqHybrid,
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
    );
    let _ = session.otp_store.save();
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
    session
        .peer_link
        .send_reliable_or_queue(to, P2pPayload::OtpVoiceOffer { stream_id, seq, envelope });
    crate::client::session::request_rotation(session, to);
    Ok(())
}

/// Applies an incoming `P2pEvent::OtpMessage`/`OtpFileOffer`'s envelope:
/// unwraps the OTP layer, then hands the recovered `pq_hybrid` blob to the
/// existing, unmodified decrypt pipeline exactly as a plain envelope would
/// use. Only sends `OtpDeliveryAck` back once local delivery has actually
/// succeeded - see the module doc for why that's always safe to do
/// immediately and unconditionally, unlike the encrypt side's ack-gating.
pub(crate) async fn on_message(
    session: &mut SessionState,
    ui_state: &mut UiState,
    channel: Option<String>,
    from: UserId,
    from_name: String,
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
    // Checked *before* `otp --decrypt` runs, not after - a resend of a
    // message this contact's counter already moved past (the peer decrypted
    // it fine; only the ack got lost) must never reach the pad a second
    // time. See `OtpStore::is_next_expected`'s doc.
    if !session.otp_store.is_next_expected(&contact_name, seq) {
        return;
    }
    let Some(pq_blob) = unwrap_incoming(&session.otp_cli_cfg, blob, &contact_name).await else {
        return;
    };
    if !session.otp_store.record_received(&contact_name, seq) {
        return;
    }
    let _ = session.otp_store.save();
    let mut inner = envelope;
    inner.blocks = vec![pq_blob];
    if let Some(body) = crate::client::session::decrypt_envelope_for(
        inner,
        from,
        &sender,
        channel.as_deref(),
        session,
    ) {
        match &channel {
            Some(ch) => ui_state.on_channel_message(ch, from, from_name, body),
            None => ui_state.on_direct_message(from, from_name, body),
        }
        crate::client::session::request_rotation(session, from);
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq });
    }
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
pub(crate) async fn on_file_offer(
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
    let Some(pq_blob) = unwrap_incoming(&session.otp_cli_cfg, blob, &contact_name).await else {
        return;
    };
    if !session.otp_store.record_received(&contact_name, seq) {
        return;
    }
    let _ = session.otp_store.save();
    let mut inner = envelope;
    inner.blocks = vec![pq_blob];
    let Some(payload) = crate::client::session::decrypt_file_offer(
        &inner,
        from,
        &sender,
        channel.as_deref(),
        session,
    ) else {
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
        .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq });
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
pub(crate) async fn on_voice_offer(
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
    let Some(payload) = crate::client::session::decrypt_voice_offer(&envelope, from, &sender, session) else {
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
pub(crate) async fn on_delivery_ack(
    wr: &mut impl crate::control::ControlSink,
    ui_state: &mut UiState,
    session: &mut SessionState,
    from: UserId,
    seq: u64,
) -> proto::Result<()> {
    let Some(sender) = ui_state.known_users.get(&from).cloned() else {
        return Ok(());
    };
    let Some(contact_name) = contact_name_for_peer(session, &sender.public_key_der) else {
        return Ok(());
    };
    if !session.otp_store.record_acked(&contact_name, seq) {
        return Ok(());
    }
    let _ = session.otp_store.save();
    match session.otp_out_queue.pop_front(&contact_name) {
        Some(PendingOtpSend::Direct {
            to,
            plaintext,
            content,
            log_index,
        }) => {
            send_now(
                wr,
                session,
                ui_state,
                to,
                &contact_name,
                sender.key_mode,
                &sender.public_key_der,
                &plaintext,
                content,
                None,
                log_index,
            )
            .await
        }
        Some(PendingOtpSend::Channel {
            channel,
            to,
            plaintext,
            content,
        }) => {
            send_now(
                wr,
                session,
                ui_state,
                to,
                &contact_name,
                sender.key_mode,
                &sender.public_key_der,
                &plaintext,
                content,
                Some(channel),
                None,
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
pub(crate) async fn start_outgoing_file_content(
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
            );
            let _ = session.otp_store.save();
            session
                .peer_link
                .send_reliable_or_queue(to, P2pPayload::OtpFileContentSeq { stream_id, seq });
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
pub(crate) async fn finish_incoming_file(
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
        notify(
            ui_state,
            from,
            &from_name,
            format!("OTP: failed to decrypt an incoming {what} - it did not arrive"),
            false,
        );
        return;
    }
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
    if let Some(seq) = pending.seq {
        session
            .peer_link
            .send_reliable_or_queue(from, P2pPayload::OtpDeliveryAck { seq });
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
                recover_and_resend_file_offer(wr, session, &contact_name, seq, to, stream_id).await?;
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
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpEnvelope {
            channel,
            seq,
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
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpFileOffer {
            channel: None,
            stream_id,
            seq,
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
    let _ = ui_state;
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
    session.peer_link.ensure_link(wr, to).await;
    session.peer_link.send_reliable_or_queue(
        to,
        P2pPayload::OtpVoiceOffer {
            stream_id,
            seq,
            envelope,
        },
    );
    Ok(())
}
