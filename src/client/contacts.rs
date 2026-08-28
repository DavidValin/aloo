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
use crate::client::tui::contacts::{ContactKeyKind, UserInfoKeyRow};
use crate::client::tui::ui::UiState;
use crate::crypto::otp::OtpPurpose;
use crate::proto::{KeyMode, UserId};

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

/// One row of the Contacts modal - one per pinned device of a nickname
/// (device-pinning plan §3), not one per nickname: a multi-device contact
/// produces one row per device, so each can be inspected, keyed, and
/// deleted independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactRow {
    pub nickname: String,
    /// Which of `nickname`'s devices this row is - `None` for the
    /// "unbound" row (a key pinned with no device confirmed yet, e.g. from
    /// an identity card or a manual install with nothing live to attribute
    /// it to). Never editable from this row; only ever learned from a live
    /// connection or a pad's own §5 device claim.
    pub device_id: Option<String>,
    /// `idstore::DeviceEntry::last_seen_unix` - `None` if this device's key
    /// has never been confirmed reachable over the direct link.
    pub last_seen_unix: Option<u64>,
    /// `idstore::DeviceEntry::key_mode` - `None` for a `Direct`-framed pin,
    /// or an entry recorded before this field existed.
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
    /// `otp_contact_name`'s counterpart for OTP *mail* - the independent
    /// key `/mail` always spends (`crypto::otp::contact_name_for_mail`),
    /// never the live session key above.
    pub otp_mail_contact_name: Option<String>,
    /// `Some` iff `otp_mail_contact_name` names a keychain entry that
    /// already exists.
    pub otp_mail: Option<ContactOtpDetail>,
    /// This contact's `pq_hybrid` fingerprint, short form
    /// (`crypto::short_fingerprint_der` - the same form every other
    /// key-display surface uses) - the PQH key detail popup's "id" line.
    /// `Some` iff `key_mode` is `PqHybrid`; `None` for a pin that isn't
    /// (nothing to show as a PQH "id" for a raw Direct-framed pin with no
    /// pq_hybrid identity behind it at all).
    pub pqh_fingerprint: Option<String>,
    /// The identity-card file this pin was manually imported from
    /// (`idstore::IdStore::pinned_from`) - the PQH key detail popup's
    /// "path in disk". `None` for a pin that arrived over the wire
    /// instead.
    pub pqh_pinned_from: Option<PathBuf>,
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
/// `None` when `(nickname, device_id)` is not pinned at all, or (a
/// `PqWrapped` pin only) `device_id` is the empty "unbound" sentinel -
/// device-pinning plan §3, "Install manually" opened against the unbound
/// row files under the not-yet-qualified name instead, resolved once a
/// live connection claims the device. Never touches the keychain itself;
/// just derives the name
/// `otp_cli::has_contact`/`show_contact`/`add_contact`/`remove_contact`
/// would all use.
///
/// `device_id` names exactly which of the nickname's devices this name is
/// for - the row it came from in the Contacts modal, or the empty
/// "unbound" sentinel for a pin with no confirmed device at all. Own
/// device_id is this machine's own, always known
/// (`SessionState::own_device_id`).
pub fn otp_contact_name_for(
    id_store: &IdStore,
    nickname: &str,
    device_id: &str,
    own_identity: OwnIdentity<'_>,
    purpose: OtpPurpose,
) -> Option<String> {
    let peer_der = id_store.get_for_device(nickname, device_id)?;
    match crate::client::otp::framing_for(own_identity.pinned_public_der, peer_der) {
        crate::client::otp::OtpFraming::PqWrapped => {
            let peer_fp = crate::crypto::pq::fingerprint_of_encoded(peer_der)?;
            if device_id.is_empty() {
                // Unbound: no device confirmed for this pin yet, so there
                // is no device-qualified name to derive - see this
                // function's own doc.
                return None;
            }
            Some(match purpose {
                OtpPurpose::Live => crate::crypto::otp::contact_name_for(
                    own_identity.pq_fingerprint,
                    own_identity.own_device_id,
                    &peer_fp,
                    device_id,
                ),
                OtpPurpose::Mail => crate::crypto::otp::contact_name_for_mail(
                    own_identity.pq_fingerprint,
                    own_identity.own_device_id,
                    &peer_fp,
                    device_id,
                ),
            })
        }
        crate::client::otp::OtpFraming::Direct => Some(match purpose {
            OtpPurpose::Live => {
                crate::crypto::otp::contact_name_for_keys(own_identity.pinned_public_der, peer_der)
            }
            OtpPurpose::Mail => crate::crypto::otp::contact_name_for_keys_mail(
                own_identity.pinned_public_der,
                peer_der,
            ),
        }),
    }
}

/// This side's own identity, as the contact-naming rules need to see it -
/// the `pq_hybrid` fingerprint and the pinned public key it was computed
/// from, plus this machine's own device_id (device-pinning plan §4 -
/// always known, `client::device_id::load_or_create`, unlike a peer's).
/// The two key representations are always present (`pq_hybrid` is this
/// app's only `my_key`); which one is used depends on what the *peer*
/// announced.
#[derive(Debug, Clone, Copy)]
pub struct OwnIdentity<'a> {
    pub pq_fingerprint: &'a [u8; 32],
    pub pinned_public_der: &'a [u8],
    pub own_device_id: &'a str,
}

/// This side's own identity as `SessionState` holds it - the one place the
/// three representations are read out of a live session.
pub fn own_identity_of(session: &SessionState) -> OwnIdentity<'_> {
    OwnIdentity {
        pq_fingerprint: &session.own_pq_fp,
        pinned_public_der: &session.otp_own_pinned_der,
        own_device_id: &session.own_device_id,
    }
}

/// This side's own identity, copied out of the session rather than
/// borrowed from it.
///
/// `own_identity_of` hands back an `OwnIdentity<'_>` that borrows the
/// session for as long as it lives, which the `handle_*` entry points
/// below cannot afford - they go on to take `&mut session` for the very
/// registry writes the identity is being read *for*. Four of them were
/// writing the same copy out by hand for exactly that reason; this is
/// that copy, named.
pub struct OwnIdentitySnapshot {
    pq_fingerprint: [u8; 32],
    pinned_public_der: Vec<u8>,
    own_device_id: String,
}

impl OwnIdentitySnapshot {
    pub fn of(session: &SessionState) -> Self {
        Self {
            pq_fingerprint: session.own_pq_fp,
            pinned_public_der: session.otp_own_pinned_der.clone(),
            own_device_id: session.own_device_id.clone(),
        }
    }

    /// The borrowed form every contact helper takes.
    pub fn as_identity(&self) -> OwnIdentity<'_> {
        OwnIdentity {
            pq_fingerprint: &self.pq_fingerprint,
            pinned_public_der: &self.pinned_public_der,
            own_device_id: &self.own_device_id,
        }
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

/// Every pinned device of every nickname, each merged with its live OTP
/// keychain state - the Contacts modal's row set
/// (`UiAction::OpenContacts`/`RefreshContacts`), one row per device
/// (device-pinning plan §3). Queries the real `otp` binary once per
/// `pq_hybrid`-pinned device, so this is only ever called when the modal
/// opens or the user asks it to refresh, never on a per-frame tick.
/// One `(nickname, raw_device_id)` pair's full row - the per-device body
/// `gather_contact_rows` runs for every device of every nickname, factored
/// out so `gather_single_contact_row` (the user-info popup, `i`/`/info`)
/// can compute exactly one without re-deriving the other rows it doesn't
/// need. `raw_device_id` is the store's own convention: `""` for unbound.
async fn build_contact_row(
    id_store: &IdStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
    raw_device_id: &str,
    key_mode: Option<KeyMode>,
    last_seen_unix: Option<u64>,
    pqh_pinned_from: Option<PathBuf>,
) -> ContactRow {
    let otp_contact_name =
        otp_contact_name_for(id_store, nickname, raw_device_id, own_identity, OtpPurpose::Live);
    let otp = match &otp_contact_name {
        Some(name) => otp_detail_for(otp_cli_cfg, name).await,
        None => None,
    };
    let otp_mail_contact_name =
        otp_contact_name_for(id_store, nickname, raw_device_id, own_identity, OtpPurpose::Mail);
    let otp_mail = match &otp_mail_contact_name {
        Some(name) => otp_detail_for(otp_cli_cfg, name).await,
        None => None,
    };
    let pqh_fingerprint = if key_mode == Some(KeyMode::PqHybrid) {
        id_store.get_for_device(nickname, raw_device_id).map(crate::crypto::short_fingerprint_der)
    } else {
        None
    };
    ContactRow {
        nickname: nickname.to_string(),
        device_id: (!raw_device_id.is_empty()).then(|| raw_device_id.to_string()),
        last_seen_unix,
        key_mode,
        otp_contact_name,
        otp,
        otp_mail_contact_name,
        otp_mail,
        pqh_fingerprint,
        pqh_pinned_from,
    }
}

pub async fn gather_contact_rows(
    id_store: &IdStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
) -> Vec<ContactRow> {
    let mut rows = Vec::new();
    for nickname in id_store.nicknames() {
        let devices: Vec<(String, Option<KeyMode>, Option<u64>, Option<PathBuf>)> = id_store
            .devices_of(&nickname)
            .map(|d| (d.device_id.clone(), d.key_mode, d.last_seen_unix, d.pinned_from.clone()))
            .collect();
        for (raw_device_id, key_mode, last_seen_unix, pqh_pinned_from) in devices {
            rows.push(
                build_contact_row(
                    id_store,
                    otp_cli_cfg,
                    own_identity,
                    &nickname,
                    &raw_device_id,
                    key_mode,
                    last_seen_unix,
                    pqh_pinned_from,
                )
                .await,
            );
        }
    }
    rows
}

/// The user-info popup's data (`i` on a channel member, `/info` in an open
/// DM): exactly the one row naming `(nickname, device_id)`, or `None` if
/// nothing is pinned for them at all yet. `device_id` is the store's
/// "unbound" convention - `None` looks up the unbound (`""`) entry, same
/// as every other device-aware lookup in this module.
pub async fn gather_single_contact_row(
    id_store: &IdStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
    device_id: Option<&str>,
) -> Option<ContactRow> {
    let raw_device_id = device_id.unwrap_or("");
    let entry = id_store.devices_of(nickname).find(|d| d.device_id == raw_device_id)?;
    let (key_mode, last_seen_unix, pinned_from) = (entry.key_mode, entry.last_seen_unix, entry.pinned_from.clone());
    Some(
        build_contact_row(
            id_store,
            otp_cli_cfg,
            own_identity,
            nickname,
            raw_device_id,
            key_mode,
            last_seen_unix,
            pinned_from,
        )
        .await,
    )
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

/// The device this connection actually announced for `peer` - a
/// `pq_hybrid` peer's live `DeviceIdAnnounce` (`SessionState::
/// peer_device_ids`), or a serverless peer's own resolution
/// (`PeerLinkManager::direct_device_id_of`). `None` for either a peer
/// whose device hasn't been learned yet, or one with no `pq_hybrid`
/// identity and no direct link at all.
fn live_peer_device_id(session: &SessionState, peer: UserId) -> Option<String> {
    session.peer_device_ids.get(&peer).cloned().or_else(|| session.peer_link.direct_device_id_of(peer))
}

/// `UiAction::RequestUserInfo`'s handler (`i` on a channel member, `/info`
/// in an open DM): resolves exactly which device this live connection
/// actually is, gathers that one `(nickname, device_id)` row
/// (`gather_single_contact_row`), and lists only the keys that genuinely
/// exist - never the contacts list's always-three ✅/❌ badges, since this
/// popup has nothing to manage, only to show.
pub async fn handle_request_user_info(session: &SessionState, ui_state: &mut UiState, peer: UserId, nickname: String) {
    let device_id = live_peer_device_id(session, peer);
    let row = gather_single_contact_row(
        &session.id_store,
        &session.otp_cli_cfg,
        own_identity_of(session),
        &nickname,
        device_id.as_deref(),
    )
    .await;
    let mut keys = Vec::new();
    let mut last_seen_unix = None;
    if let Some(row) = row {
        last_seen_unix = row.last_seen_unix;
        if let Some(fp) = row.pqh_fingerprint {
            keys.push(UserInfoKeyRow { kind: ContactKeyKind::Pqh, id: fp });
        }
        if let (Some(name), true) = (row.otp_contact_name, row.otp.is_some()) {
            keys.push(UserInfoKeyRow { kind: ContactKeyKind::Otp, id: name });
        }
        if let (Some(name), true) = (row.otp_mail_contact_name, row.otp_mail.is_some()) {
            keys.push(UserInfoKeyRow { kind: ContactKeyKind::OtpMail, id: name });
        }
    }
    ui_state.set_user_info(peer, device_id, last_seen_unix, keys);
}

/// Forgets `nickname` outright - every one of its devices' identity pins,
/// and, for each, whatever OTP keychain entries it had and local
/// bookkeeping (device-pinning plan §3: "forget this nickname, every
/// device"). Every device's own contact names are recomputed fresh, before
/// any pin is removed, rather than trusted from whatever the modal last
/// rendered - a destructive action should never act on a stale snapshot,
/// and once a device's pin is gone its contact name can no longer be
/// recomputed at all. Best-effort on each keychain removal itself, same
/// convention `otp_cli::remove_contact` already documents: a failure there
/// is logged, not fatal, and never blocks forgetting the pin. Returns
/// whether the identity pin itself was actually there to remove.
pub async fn delete_contact(
    id_store: &mut IdStore,
    otp_store: &mut OtpStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
) -> bool {
    let device_ids: Vec<String> = id_store
        .devices_of(nickname)
        .map(|d| d.device_id.clone())
        .collect();
    for device_id in &device_ids {
        remove_device_keychain_entries(id_store, otp_store, otp_cli_cfg, own_identity, nickname, device_id)
            .await;
    }
    let removed = id_store.remove(nickname);
    id_store.save_or_warn();
    removed
}

/// The keychain half of forgetting one device: removes both purposes'
/// contact names for `(nickname, device_id)`, if either exists. Shared by
/// whole-nickname delete (`delete_contact`, one call per device) and
/// per-device delete (`delete_contact_device`) so both clean up identically.
async fn remove_device_keychain_entries(
    id_store: &IdStore,
    otp_store: &mut OtpStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
    device_id: &str,
) {
    for purpose in [OtpPurpose::Live, OtpPurpose::Mail] {
        if let Some(contact_name) =
            otp_contact_name_for(id_store, nickname, device_id, own_identity, purpose)
        {
            if let Err(e) = otp_cli::remove_contact(otp_cli_cfg, &contact_name).await {
                crate::log_warn!("failed to remove {} keychain entry for {nickname}: {e}", purpose.label());
            }
            if otp_store.forget(&contact_name) {
                let _ = otp_store.save();
            }
        }
    }
}

/// Forgets just one device of `nickname` - its identity pin plus that
/// device's own derived OTP/mail keychain entries, leaving every sibling
/// device's pin and keychain entries exactly as they were (device-pinning
/// plan §3's additive rule applied to deletion too). Returns whether the
/// device's pin was actually there to remove.
pub async fn delete_contact_device(
    id_store: &mut IdStore,
    otp_store: &mut OtpStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
    device_id: &str,
) -> bool {
    remove_device_keychain_entries(id_store, otp_store, otp_cli_cfg, own_identity, nickname, device_id)
        .await;
    let removed = id_store.remove_device(nickname, device_id);
    id_store.save_or_warn();
    removed
}

/// `UiAction::DeleteContact`'s handler.
pub async fn handle_delete(session: &mut SessionState, ui_state: &mut UiState, nickname: String) {
    let own = OwnIdentitySnapshot::of(session);
    let own_identity = own.as_identity();
    // Computed before `delete_contact` removes every one of this
    // nickname's devices - one live contact name per device, since each
    // has its own (device-pinning plan §4).
    let live_contact_names: Vec<String> = session
        .id_store
        .devices_of(&nickname)
        .filter_map(|device| {
            otp_contact_name_for(&session.id_store, &nickname, &device.device_id, own_identity, OtpPurpose::Live)
        })
        .collect();
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
    for contact_name in live_contact_names {
        end_active_otp_session_after_key_removed(session, ui_state, &contact_name, &nickname);
    }
    handle_open(session, ui_state).await;
    refresh_mail_recipient_check_if_open(session, ui_state, &nickname).await;
}

/// A key change from `/contacts` (installing, creating, or deleting any of
/// a contact's three keys) must "take effect immediately" - if `/mail` is
/// open composing *to this same nickname*, its recipient check is stale
/// the instant any of that happens, so it's re-run here rather than
/// leaving the compose view to show whatever it last computed until the
/// user edits the field again. A no-op whenever `/mail` isn't open, or is
/// open for someone else - `otp_mail::handle_check_recipient` itself
/// already ignores a result for the wrong nickname, but there is no reason
/// to shell out to `otp` at all for an unrelated compose.
async fn refresh_mail_recipient_check_if_open(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: &str,
) {
    let composing_to = ui_state
        .otp_mail
        .as_ref()
        .map(|m| m.compose.to.clone())
        .filter(|to| to == nickname);
    if let Some(to) = composing_to {
        // Force a fresh device enumeration rather than trusting
        // `handle_check_recipient`'s per-keystroke memoization
        // (`devices_for == to` would still match here, since the
        // nickname itself hasn't changed) - what actually changed is a
        // device's key availability on disk, exactly what a stale
        // `devices` list would miss.
        if let Some(mail) = ui_state.otp_mail.as_mut() {
            mail.compose.devices_for = None;
        }
        crate::client::otp_mail::handle_check_recipient(session, ui_state, to).await;
    }
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
    device_id: &str,
    purpose: OtpPurpose,
    enc_path: &Path,
    dec_path: &Path,
) -> InstallOtpKeyOutcome {
    let Some(contact_name) = otp_contact_name_for(id_store, nickname, device_id, own_identity, purpose)
    else {
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
            // `add_contact` replaced the keychain entry wholesale (fresh
            // tool sequence numbers and offsets), so every aloo-level
            // counter keyed to whatever pad this name held before resets
            // with it - or a manually reinstalled key would be born
            // desynced at this layer (`OtpStore::reset_for_new_pad`).
            otp_store.reset_for_new_pad(&contact_name, None);
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
    device_id: Option<String>,
    purpose: OtpPurpose,
    enc_path: PathBuf,
    dec_path: PathBuf,
) {
    let own = OwnIdentitySnapshot::of(session);
    let own_identity = own.as_identity();
    // A manual install races two other ways this same contact name can be
    // provisioned: this side's own fresh-pad proposal, still waiting on
    // the peer's answer (`otp_awaiting_consent` - `client::otp::confirm_generate`),
    // and the peer's proposal to *us*, sitting unanswered as this side's
    // open invite popup. `otp --add-contact` itself refuses outright once
    // either side has actually installed something under this name, so
    // this never corrupts a pad - but letting a manual install win a race
    // against a negotiation already past that point turns the negotiated
    // side's own install into a permanent, unexplained failure (or, for
    // the streamed-pad path, an endless retry against a conflict that can
    // never resolve itself). Refused here instead, before it ever reaches
    // that ambiguity, the same way a second `/otp` is refused while one is
    // already in flight (`client::otp::handle_provisioning_command`'s own
    // concurrency guard).
    if let Some(contact_name) =
        otp_contact_name_for(&session.id_store, &nickname, device_id.as_deref().unwrap_or(""), own_identity, purpose)
    {
        if session.otp_awaiting_consent.contains_key(&contact_name) {
            ui_state.set_contacts_install_error(format!(
                "a session with {nickname} is already being proposed - answer it or run /endotp \
                 before installing a key manually"
            ));
            return;
        }
        if ui_state
            .otp_invite_open()
            .is_some_and(|invite| invite.contact_name == contact_name)
        {
            ui_state.set_contacts_install_error(format!(
                "{nickname} already proposed a session for this contact - accept or reject it \
                 before installing a key manually"
            ));
            return;
        }
    }
    let outcome = install_otp_key(
        &session.id_store,
        &mut session.otp_store,
        &session.otp_cli_cfg,
        own_identity,
        &nickname,
        device_id.as_deref().unwrap_or(""),
        purpose,
        &enc_path,
        &dec_path,
    )
    .await;
    match outcome {
        InstallOtpKeyOutcome::Ok => {
            ui_state.push_status_notice(format!("installed {} for {nickname}", purpose.label()), true);
            ui_state.close_contacts_install();
            handle_open(session, ui_state).await;
            refresh_mail_recipient_check_if_open(session, ui_state, &nickname).await;
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

/// Deletes just one purpose's keychain entry for `(nickname, device_id)` -
/// the OTP or OTP-mail key detail popup's own "Delete key", independent of
/// the other purpose and of the identity pin itself (`delete_contact_device`
/// is what removes the pin and both purposes together, reached instead
/// from the PQH key's own "Delete key"). Returns whether there was
/// anything to delete.
pub async fn delete_otp_key(
    id_store: &IdStore,
    otp_store: &mut OtpStore,
    otp_cli_cfg: &OtpCliConfig,
    own_identity: OwnIdentity<'_>,
    nickname: &str,
    device_id: &str,
    purpose: OtpPurpose,
) -> bool {
    let Some(contact_name) =
        otp_contact_name_for(id_store, nickname, device_id, own_identity, purpose)
    else {
        return false;
    };
    let had_entry = otp_cli::has_contact(otp_cli_cfg, &contact_name)
        .await
        .unwrap_or(false);
    if let Err(e) = otp_cli::remove_contact(otp_cli_cfg, &contact_name).await {
        crate::log_warn!("failed to remove {} keychain entry for {nickname}: {e}", purpose.label());
    }
    if otp_store.forget(&contact_name) {
        let _ = otp_store.save();
    }
    had_entry
}

/// If `contact_name` (a nickname/device's *live* OTP contact, computed
/// before whichever deletion just ran removed its keychain entry or its
/// whole identity pin) belongs to a currently-connected peer whose
/// session is marked active, ends it locally - the same local effect an
/// incoming `/endotp` from that peer would have.
///
/// Without this, deleting the key out from under an active session left
/// `is_otp_active` stuck true for the rest of the process: the compose
/// bar kept the 🔑 badge, every send still routed through the OTP path
/// and failed at encrypt time against a keychain entry that no longer
/// existed, `/otp` refused to restart ("already active - use /endotp
/// first"), and `/endotp` itself didn't help - it checks `otp_store`,
/// which the deletion had *also* already cleared, so it took the
/// "no active session" branch and returned without ever touching the
/// flag. Only a reconnect (which re-derives `is_otp_active` from
/// scratch, `session::maybe_resolve_p2p_identity_data`) ever cleared it.
fn end_active_otp_session_after_key_removed(
    session: &SessionState,
    ui_state: &mut UiState,
    contact_name: &str,
    nickname: &str,
) {
    let Some(peer) = ui_state.known_users.iter().find_map(|(id, info)| {
        (crate::client::otp::contact_name_for_peer(session, *id, &info.public_key_der).as_deref()
            == Some(contact_name))
        .then_some(*id)
    }) else {
        return;
    };
    if ui_state.is_otp_active(peer) {
        ui_state.clear_otp_active(peer);
        ui_state.push_status_notice(
            format!("ended the live OTP session with {nickname} - its key was just removed"),
            true,
        );
    }
}

/// `UiAction::DeleteContactKey`'s handler.
pub async fn handle_delete_otp_key(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    device_id: Option<String>,
    purpose: OtpPurpose,
) {
    let own = OwnIdentitySnapshot::of(session);
    let own_identity = own.as_identity();
    let raw_device_id = device_id.as_deref().unwrap_or("");
    // Computed before the delete below, while the pin this name is
    // derived from still exists - mail has no "active" toggle at all
    // (`client::otp`'s module doc), so only a live key's deletion can
    // ever have a session to end.
    let live_contact_name = (purpose == OtpPurpose::Live)
        .then(|| otp_contact_name_for(&session.id_store, &nickname, raw_device_id, own_identity, OtpPurpose::Live))
        .flatten();
    let removed = delete_otp_key(
        &session.id_store,
        &mut session.otp_store,
        &session.otp_cli_cfg,
        own_identity,
        &nickname,
        raw_device_id,
        purpose,
    )
    .await;
    if removed {
        ui_state.push_status_notice(format!("removed {} for {nickname}", purpose.label()), true);
    }
    if let Some(contact_name) = live_contact_name {
        end_active_otp_session_after_key_removed(session, ui_state, &contact_name, &nickname);
    }
    handle_open(session, ui_state).await;
    refresh_mail_recipient_check_if_open(session, ui_state, &nickname).await;
}

/// `UiAction::DeleteContactDevice`'s handler.
pub async fn handle_delete_contact_device(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    device_id: Option<String>,
) {
    let own = OwnIdentitySnapshot::of(session);
    let own_identity = own.as_identity();
    let raw_device_id = device_id.as_deref().unwrap_or("");
    // Computed before `delete_contact_device` removes this device's whole
    // identity pin, which the live contact name is derived from.
    let live_contact_name =
        otp_contact_name_for(&session.id_store, &nickname, raw_device_id, own_identity, OtpPurpose::Live);
    let removed = delete_contact_device(
        &mut session.id_store,
        &mut session.otp_store,
        &session.otp_cli_cfg,
        own_identity,
        &nickname,
        raw_device_id,
    )
    .await;
    if removed {
        ui_state.push_status_notice(format!("removed {nickname}'s device"), true);
    }
    if let Some(contact_name) = live_contact_name {
        end_active_otp_session_after_key_removed(session, ui_state, &contact_name, &nickname);
    }
    handle_open(session, ui_state).await;
    refresh_mail_recipient_check_if_open(session, ui_state, &nickname).await;
}

/// What `pin_identity_card` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinIdentityCardOutcome {
    Ok,
    /// The file didn't load, or its self-signature didn't check out
    /// (`crypto::pq::open_identity_card`) - never pinned either way.
    Invalid(String),
    /// The card is genuine, but vouches for a different nickname than the
    /// contact row it was opened from - refused rather than silently
    /// filing it under the wrong name, or under a second, new row.
    NicknameMismatch { card_nickname: String },
}

/// Loads an identity card and checks it vouches for `nickname` - the
/// validation `pin_identity_card` and `pin_identity_card_for_device` both
/// need before deciding *where* to file the resulting key.
fn load_and_verify_identity_card(nickname: &str, path: &Path) -> Result<Vec<u8>, PinIdentityCardOutcome> {
    let card = crate::crypto::pq::load_identity_card(path)
        .map_err(|e| PinIdentityCardOutcome::Invalid(format!("{}: {e}", path.display())))?;
    let Some((card_nickname, bundle)) = crate::crypto::pq::open_identity_card(&card) else {
        return Err(PinIdentityCardOutcome::Invalid(
            "card signature does not match its own key - refusing to pin".to_string(),
        ));
    };
    if card_nickname != nickname {
        return Err(PinIdentityCardOutcome::NicknameMismatch {
            card_nickname: card_nickname.to_string(),
        });
    }
    crate::proto::encode(bundle).map_err(|e| PinIdentityCardOutcome::Invalid(format!("{e}")))
}

/// PQH's "Create key": imports an identity card (`crypto::pq::IdentityCard`,
/// `aloo --export-identity-card`'s output) and pins it as `Verified` -
/// the one way to attach a real `pq_hybrid` identity to a nickname before
/// ever connecting to them, instead of leaving it to trust-on-first-use.
/// Requires the card's own self-attested nickname to match `nickname`
/// exactly: a card is a binding of *one specific* nickname to a key,
/// never a device (§1 - a card vouches for a key, not a device). This
/// always upgrades the nickname's existing *unbound* entry (creating one
/// if there isn't one yet) rather than ever touching an already-bound
/// device's pin: importing a card says nothing about which of a
/// multi-device nickname's devices it is, so it's filed the same way a
/// manually installed key with no confirmed device is, resolved the same
/// "filled in on first use" way any other unbound entry is (§1).
pub fn pin_identity_card(
    id_store: &mut IdStore,
    nickname: &str,
    path: &Path,
) -> PinIdentityCardOutcome {
    let encoded = match load_and_verify_identity_card(nickname, path) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };
    // key_mode-scoped, and set atomically on the one entry it resolves
    // to (not a blind `get_for_device(nickname, "")` followed by several
    // separately-looked-up writes): a nickname can have both an unbound
    // `Direct` pin and an unbound `pq_hybrid` first sighting at once,
    // both sharing the empty device_id sentinel, and a card must only
    // ever touch the latter.
    id_store.pin_unbound_pq_hybrid_card(nickname, &encoded, path.to_path_buf());
    id_store.save_or_warn();
    PinIdentityCardOutcome::Ok
}

/// PQH's "Create key" from the "Add contact" popup (device-pinning plan
/// §3): unlike `pin_identity_card`, this binds directly to `device_id` -
/// something the user just typed, not something to be learned from a
/// live connection later - rather than the nickname's shared unbound
/// entry. Refuses if `(nickname, device_id)` is already pinned, since Add
/// Contact only ever creates a brand-new entry and never silently
/// overwrites one a live connection, another card, or an earlier Add
/// Contact already produced.
pub fn pin_identity_card_for_device(
    id_store: &mut IdStore,
    nickname: &str,
    device_id: &str,
    path: &Path,
) -> PinIdentityCardOutcome {
    if id_store.get_for_device(nickname, device_id).is_some() {
        return PinIdentityCardOutcome::Invalid(format!(
            "{nickname}'s device {device_id:?} is already pinned - open that row instead"
        ));
    }
    let encoded = match load_and_verify_identity_card(nickname, path) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };
    id_store.pin_new_device_with_key_mode(
        nickname,
        device_id,
        &encoded,
        crate::client::idstore::Trust::Verified,
        Some(KeyMode::PqHybrid),
    );
    id_store.set_pinned_from(nickname, device_id, path.to_path_buf());
    id_store.save_or_warn();
    PinIdentityCardOutcome::Ok
}

/// `UiAction::PinIdentityCard`'s handler.
pub async fn handle_pin_identity_card(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    path: PathBuf,
) {
    match pin_identity_card(&mut session.id_store, &nickname, &path) {
        PinIdentityCardOutcome::Ok => {
            ui_state.push_status_notice(format!("pinned {nickname} from identity card"), true);
            ui_state.close_contacts_pqh_create();
            handle_open(session, ui_state).await;
            refresh_mail_recipient_check_if_open(session, ui_state, &nickname).await;
        }
        PinIdentityCardOutcome::Invalid(e) => {
            ui_state.set_contacts_pqh_create_error(e);
        }
        PinIdentityCardOutcome::NicknameMismatch { card_nickname } => {
            ui_state.set_contacts_pqh_create_error(format!(
                "this card vouches for '{card_nickname}', not '{nickname}' - refusing to pin it under the wrong name"
            ));
        }
    }
}

/// `UiAction::PinIdentityCardForDevice`'s handler - the "Add contact"
/// popup's PQH step. Deliberately never closes the details popup on
/// success, unlike `handle_pin_identity_card`: Add Contact's whole point
/// is letting the user keep going to OTP/OTP MAIL right after, in the
/// same popup, now that this nickname's device actually has a key.
pub async fn handle_pin_identity_card_for_device(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    device_id: String,
    path: PathBuf,
) {
    match pin_identity_card_for_device(&mut session.id_store, &nickname, &device_id, &path) {
        PinIdentityCardOutcome::Ok => {
            ui_state.push_status_notice(
                format!("pinned {nickname}'s device {device_id:?} from identity card"),
                true,
            );
            handle_open(session, ui_state).await;
            refresh_mail_recipient_check_if_open(session, ui_state, &nickname).await;
        }
        PinIdentityCardOutcome::Invalid(e) => {
            ui_state.set_contacts_pqh_create_error(e);
        }
        PinIdentityCardOutcome::NicknameMismatch { card_nickname } => {
            ui_state.set_contacts_pqh_create_error(format!(
                "this card vouches for '{card_nickname}', not '{nickname}' - refusing to pin it under the wrong name"
            ));
        }
    }
}

/// Signs `nickname`'s own already-loaded `pq_hybrid` keybundle into an
/// identity card and writes it to `<dir>/<nickname>.aloo-card` - the pure
/// half of `handle_export_own_identity_card`, taking the destination
/// directory explicitly (rather than reaching for `platform::aloo_dir()`
/// itself) so it's exercisable against a scratch directory in tests. `Ok`
/// carries the path written and this bundle's safety phrase.
pub fn export_own_identity_card_to(
    private: &crate::crypto::pq::PqPrivateBundle,
    public_der: &[u8],
    nickname: &str,
    dir: &Path,
) -> Result<(PathBuf, String), String> {
    let public = crate::proto::decode::<crate::crypto::pq::PqPublicBundle>(public_der)
        .map_err(|_| "this session's own keybundle does not decode".to_string())?;
    let card = crate::crypto::pq::make_identity_card(private, &public, nickname)
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{nickname}.aloo-card"));
    crate::crypto::pq::save_identity_card(&card, &path).map_err(|e| e.to_string())?;
    let fp = crate::crypto::pq::bundle_fingerprint(&public).map_err(|e| e.to_string())?;
    Ok((path, crate::crypto::safety::phrase(&fp)))
}

/// `UiAction::ExportOwnIdentityCard`'s handler - `/contacts`' `x`, the
/// live-session equivalent of `aloo --export-identity-card <prefix>
/// <nickname>`: no separate prefix/nickname arguments needed, since a
/// live session already has both loaded. Writes to
/// `~/.aloo/exports/<nickname>.aloo-card` (the same `~/.aloo/exports`
/// root every other export already writes under, `client::export`) -
/// never the server, never anywhere the CLI form's own working directory
/// would put it, since a live session has no natural "current directory"
/// notion. Purely local; never touches the network.
pub async fn handle_export_own_identity_card(session: &SessionState, ui_state: &mut UiState) {
    let dir = crate::platform::aloo_dir().join("exports");
    match export_own_identity_card_to(
        &session.own_pq_private,
        &session.otp_own_pinned_der,
        &ui_state.own_name,
        &dir,
    ) {
        Ok((path, phrase)) => ui_state.push_status_notice(
            format!(
                "exported identity card (own pqhybrid key) to {} - safety phrase: {phrase}",
                path.display()
            ),
            true,
        ),
        Err(e) => ui_state.push_status_notice(format!("could not export identity card: {e}"), false),
    }
}

/// `UiAction::AddBareContact`'s handler - "Add contact" submitted with no
/// identity card imported (yet). Reserves the placeholder
/// (`IdStore::pin_bare_contact`) and refreshes the list right away, so the
/// contact already shows - with all three key badges red - the moment
/// this returns, whether or not the key-details popup that opens
/// alongside it (`tui::contacts::submit_add_contact`) ever adds a key.
/// `pin_bare_contact` refusing (a race with another action pinning the
/// same slot between this popup opening and Enter) is silent here: the
/// popup's own pre-submit duplicate check is what a user actually sees,
/// and a lost race just leaves the real, already-pinned entry as it was.
pub async fn handle_add_bare_contact(
    session: &mut SessionState,
    ui_state: &mut UiState,
    nickname: String,
    device_id: String,
) {
    session.id_store.pin_bare_contact(&nickname, &device_id);
    session.id_store.save_or_warn();
    handle_open(session, ui_state).await;
}
