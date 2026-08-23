//! Data gathering and mutation for the Contacts modal
//! (`client::tui::contacts`, opened with `/contacts`): the roster of every
//! nickname pinned in `id_store` - this app's one persistent notion of
//! "someone I know", trust-on-first-use or verified (`idstore.rs`) - each
//! merged with whatever OTP keychain state (if any) that contact has.
//!
//! Queried fresh from `id_store` and, for OTP figures, the real `otp`
//! binary (`otp_cli::show_contact`) every time the modal opens or the user
//! asks it to refresh - never kept live in memory the way
//! `UiState::otp_key_status` is for an *active* DM session, since most
//! rows here are contacts nobody is currently connected to at all.
//!
//! The gather/delete/install logic (`gather_contact_rows`/`delete_contact`/
//! `install_otp_key`) takes `IdStore`/`OtpStore`/`OtpCliConfig` directly
//! rather than a whole `SessionState` - those three are all a contacts row
//! ever needs, and keeping the signatures that narrow is what lets them be
//! exercised directly in tests against plain values, with no session,
//! socket or terminal to stand up. `handle_open`/`handle_delete`/
//! `handle_install_otp_key` are the thin `SessionState`-shaped wrappers
//! `session::handle_ui_action` actually calls.

use std::path::{Path, PathBuf};

use crate::client::idstore::IdStore;
use crate::client::otp_cli::{self, OtpCliConfig};
use crate::client::otp_store::OtpStore;
use crate::client::session::SessionState;
use crate::client::tui::ui::UiState;
use crate::proto::KeyMode;

/// One contact's live OTP pad figures, in each direction - the same
/// `<seq> <offset> <remaining>` the `/otp` DM header shows
/// (`client::tui::direct_message::render_otp_header`), plus the two
/// keychain files those figures index into (`otp_cli::contact_key_paths`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactOtpDetail {
    pub enc_sequence: u64,
    pub enc_offset: u64,
    pub enc_key_remaining: u64,
    pub dec_sequence: u64,
    pub dec_offset: u64,
    pub dec_key_remaining: u64,
    pub enc_key_path: PathBuf,
    pub dec_key_path: PathBuf,
}

/// One row of the Contacts modal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRow {
    pub nickname: String,
    /// `idstore::IdStore::last_seen_unix` - `None` if this pin's key has
    /// never been confirmed reachable over the direct link.
    pub last_seen_unix: Option<u64>,
    /// `idstore::IdStore::key_mode` - `None` for a pin recorded before
    /// that field existed.
    pub key_mode: Option<KeyMode>,
    /// The contact name `otp --add-contact`/`--show-contact` uses for this
    /// nickname - fingerprint-derived for a `pq_hybrid` pin, pinned-key
    /// derived otherwise (`otp_contact_name_for`). Independent of whether
    /// OTP is
    /// actually provisioned yet (`otp: Some(_)` below); "Install OTP key"
    /// is offered whenever `otp` is `None`.
    pub otp_contact_name: Option<String>,
    /// `Some` iff `otp_contact_name` names a keychain entry that already
    /// exists.
    pub otp: Option<ContactOtpDetail>,
}

/// The `otp` keychain contact name to file `nickname`'s pad under.
///
/// Two derivations, and which one applies is exactly this pair's
/// `client::otp::OtpFraming`: a pin holding a readable `pq_hybrid` bundle
/// gives a fingerprint-derived name both machines compute identically,
/// and a pin without one (a `--no-server` direct-punch peer, which
/// announces no keybundle at all) falls back to the two pinned public
/// keys. Never the nickname, which proves nothing and would let an
/// impersonator taking a familiar name spend the real contact's pad
/// (`crypto::otp::contact_name_for_keys`).
///
/// `None` only when `nickname` is not pinned at all. Never touches the
/// keychain itself; just derives the name `otp_cli::has_contact`/
/// `show_contact`/`add_contact`/`remove_contact` would all use.
pub fn otp_contact_name_for(
    id_store: &IdStore,
    nickname: &str,
    own_identity: OwnIdentity<'_>,
) -> Option<String> {
    let peer_der = id_store.get(nickname)?;
    match crate::client::otp::framing_for(own_identity.pinned_public_der, peer_der) {
        crate::client::otp::OtpFraming::PqWrapped => {
            let peer_fp = crate::crypto::pq::fingerprint_of_encoded(peer_der)?;
            Some(crate::crypto::otp::contact_name_for(
                own_identity.pq_fingerprint,
                &peer_fp,
            ))
        }
        crate::client::otp::OtpFraming::Direct => Some(
            crate::crypto::otp::contact_name_for_keys(own_identity.pinned_public_der, peer_der),
        ),
    }
}

/// This side's own identity, as the contact-naming rules need to see it -
/// the `pq_hybrid` fingerprint and the pinned public key it was computed
/// from. Both are always present (`pq_hybrid` is this app's only `my_key`);
/// which one is used depends on what the *peer* announced.
#[derive(Debug, Clone, Copy)]
pub struct OwnIdentity<'a> {
    pub pq_fingerprint: &'a [u8; 32],
    pub pinned_public_der: &'a [u8],
}

/// This side's own identity as `SessionState` holds it - the one place the
/// two representations are read out of a live session.
pub fn own_identity_of(session: &SessionState) -> OwnIdentity<'_> {
    OwnIdentity {
        pq_fingerprint: &session.own_pq_fp,
        pinned_public_der: &session.otp_own_pinned_der,
    }
}

async fn otp_detail_for(cfg: &OtpCliConfig, contact_name: &str) -> Option<ContactOtpDetail> {
    let detail = otp_cli::show_contact(cfg, contact_name)
        .await
        .ok()
        .flatten()?;
    let (enc_key_path, dec_key_path) = otp_cli::contact_key_paths(cfg, contact_name);
    Some(ContactOtpDetail {
        enc_sequence: detail.enc_sequence,
        enc_offset: detail.enc_offset,
        enc_key_remaining: detail.enc_key_remaining,
        dec_sequence: detail.dec_sequence,
        dec_offset: detail.dec_offset,
        dec_key_remaining: detail.dec_key_remaining,
        enc_key_path,
        dec_key_path,
    })
}

/// Every pinned contact, each merged with its live OTP keychain state -
/// the Contacts modal's row set (`UiAction::OpenContacts`/
/// `RefreshContacts`). Queries the real `otp` binary once per
/// `pq_hybrid`-pinned contact, so this is only ever called when the modal
/// opens or the user asks it to refresh, never on a per-frame tick.
pub async fn gather_contact_rows(
    id_store: &IdStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
) -> Vec<ContactRow> {
    let mut rows = Vec::new();
    for nickname in id_store.nicknames() {
        let last_seen_unix = id_store.last_seen_unix(&nickname);
        let key_mode = id_store.key_mode(&nickname);
        let otp_contact_name = otp_contact_name_for(id_store, &nickname, own_identity);
        let otp = match &otp_contact_name {
            Some(name) => otp_detail_for(otp_cli_cfg, name).await,
            None => None,
        };
        rows.push(ContactRow {
            nickname,
            last_seen_unix,
            key_mode,
            otp_contact_name,
            otp,
        });
    }
    rows
}

/// `UiAction::OpenContacts`/`RefreshContacts`'s shared handler: re-gathers
/// every row and hands it to the modal.
pub async fn handle_open(session: &SessionState, ui_state: &mut UiState) {
    let rows = gather_contact_rows(
        &session.id_store,
        &session.otp_cli_cfg,
        own_identity_of(session),
    )
    .await;
    ui_state.set_contacts_rows(rows);
}

/// Forgets `nickname` outright - its identity pin, and, if it had one, its
/// OTP keychain entry and local bookkeeping. The OTP name is recomputed
/// fresh rather than trusted from whatever the modal last rendered, since
/// a destructive action should never act on a stale snapshot. Best-effort
/// on the keychain removal itself, same convention `otp_cli::remove_contact`
/// already documents: a failure there is logged, not fatal, and never
/// blocks forgetting the pin. Returns whether the identity pin itself was
/// actually there to remove.
pub async fn delete_contact(
    id_store: &mut IdStore,
    otp_store: &mut OtpStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
) -> bool {
    if let Some(contact_name) = otp_contact_name_for(id_store, nickname, own_identity) {
        if let Err(e) = otp_cli::remove_contact(otp_cli_cfg, &contact_name).await {
            crate::log_warn!("failed to remove otp keychain entry for {nickname}: {e}");
        }
        if otp_store.forget(&contact_name) {
            let _ = otp_store.save();
        }
    }
    let removed = id_store.remove(nickname);
    if let Err(e) = id_store.save() {
        crate::log_warn!("failed to save id_store: {e}");
    }
    removed
}

/// `UiAction::DeleteContact`'s handler.
pub async fn handle_delete(session: &mut SessionState, ui_state: &mut UiState, nickname: String) {
    let own_fp = session.own_pq_fp;
    let own_der = session.otp_own_pinned_der.clone();
    let own_identity = OwnIdentity {
        pq_fingerprint: &own_fp,
        pinned_public_der: &own_der,
    };
    let removed = delete_contact(
        &mut session.id_store,
        &mut session.otp_store,
        &session.otp_cli_cfg,
        own_identity,
        &nickname,
    )
    .await;
    if removed {
        ui_state.push_status_notice(format!("removed contact {nickname}"), true);
    }
    handle_open(session, ui_state).await;
}

/// What `install_otp_key` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOtpKeyOutcome {
    Ok,
    /// No keychain contact name could be derived for `nickname` at all.
    /// Unreachable in practice now that every contact has one
    /// (`otp_contact_name_for` always answers), but kept so a future
    /// derivation that *can* fail has somewhere honest to report it rather
    /// than being forced into `Error`.
    NotEligible,
    /// A file didn't validate, or `otp --add-contact` itself refused.
    Error(String),
}

/// Stat's `path` up front so a missing/unreadable file is reported as a
/// plain "no such file" in the popup rather than whatever stderr
/// `otp --add-contact` happens to produce for it.
fn validate_key_file(path: &Path) -> Result<(), String> {
    std::fs::metadata(path)
        .map(|_| ())
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The manual counterpart to `/otp`'s own handshake-driven provisioning -
/// runs `otp --add-contact` directly against two key files the user
/// already generated (with real `otp --new-key-pair`) and placed
/// themselves, exactly the alternative the help overlay's OTP section
/// already documents.
///
/// Works for any pinned contact, with or without a readable `pq_hybrid`
/// bundle: a pad installed here authenticates by itself, so no identity is
/// needed to hold one (`client::otp::OtpFraming::Direct`). Both key files
/// are stat'd before any subprocess runs, so a typo'd path fails here
/// rather than somewhere inside `otp`.
pub async fn install_otp_key(
    id_store: &IdStore,
    otp_store: &mut OtpStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
    enc_path: &Path,
    dec_path: &Path,
) -> InstallOtpKeyOutcome {
    let Some(contact_name) = otp_contact_name_for(id_store, nickname, own_identity) else {
        return InstallOtpKeyOutcome::NotEligible;
    };
    if let Err(e) = validate_key_file(enc_path) {
        return InstallOtpKeyOutcome::Error(format!("encryption key: {e}"));
    }
    if let Err(e) = validate_key_file(dec_path) {
        return InstallOtpKeyOutcome::Error(format!("decryption key: {e}"));
    }
    match otp_cli::add_contact(otp_cli_cfg, &contact_name, enc_path, dec_path).await {
        Ok(()) => {
            otp_store.mark_provisioned(&contact_name);
            let _ = otp_store.save();
            InstallOtpKeyOutcome::Ok
        }
        Err(e) => InstallOtpKeyOutcome::Error(format!("{e}")),
    }
}

/// `UiAction::InstallOtpKey`'s handler.
pub async fn handle_install_otp_key(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    enc_path: PathBuf,
    dec_path: PathBuf,
) {
    let own_fp = session.own_pq_fp;
    let own_der = session.otp_own_pinned_der.clone();
    let own_identity = OwnIdentity {
        pq_fingerprint: &own_fp,
        pinned_public_der: &own_der,
    };
    let outcome = install_otp_key(
        &session.id_store,
        &mut session.otp_store,
        &session.otp_cli_cfg,
        own_identity,
        &nickname,
        &enc_path,
        &dec_path,
    )
    .await;
    match outcome {
        InstallOtpKeyOutcome::Ok => {
            ui_state.push_status_notice(format!("installed OTP key for {nickname}"), true);
            ui_state.close_contacts_install();
            handle_open(session, ui_state).await;
        }
        InstallOtpKeyOutcome::NotEligible => {
            ui_state.set_contacts_install_error(
                "no keychain name could be derived for this contact".to_string(),
            );
        }
        InstallOtpKeyOutcome::Error(e) => {
            ui_state.set_contacts_install_error(e);
        }
    }
}
