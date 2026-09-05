//! Deciding who a peer is, and remembering the answer.
//!
//! `docs/PROTOCOL.md` §12's subject matter: the trust-on-first-use pin, the
//! continuity certificate that lets a known peer prove a *new* key is
//! still theirs, the review a user is shown when neither holds, and the
//! narrower pin a pad-only or serverless peer gets.
//!
//! Distinct from `client::idstore`, which is the store this writes into.
//! Nothing here does I/O beyond that store: an identity decision is made
//! from what is already in hand - the pin, the announced key, the
//! signature over it - so all of it is testable with no socket.
//!
//! The rule the whole module exists to hold: a key that does not match
//! what is pinned is never quietly accepted. It is either proven by a
//! continuity certificate or put to the user.

use super::*;

/// `UiAction::AcceptIdentity`'s actual work, pulled out to its own `pub`
/// function so it is directly unit-testable against a hand-built
/// `SessionState`/`UiState` (`test/identity_accept_effects_test.rs`)
/// rather than only reachable end-to-end through a live two-daemon
/// session, which cannot model two distinct devices for one nickname
/// within a single test process (both ends resolve their own device_id
/// from one ambient `~/.aloo/d_id` path). Returns whether a review was
/// actually resolved (i.e. whether the caller should play the bell
/// chime), exactly as the old inline match arm did.
pub async fn accept_identity_review(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
) -> bool {
    if let Some(review) = ui_state.identity_reviews.get(&peer).cloned() {
        // A static key just needs pinning - `known_users` (and
        // hence what future sends encrypt with) already holds this
        // exact key, set unconditionally by `on_user_joined` when
        // the peer joined (docs/PROTOCOL.md §12.4); nothing else
        // was withheld from it, only the local pin.
        let IdentityCase::StaticMismatch {
            new_public_key_der, ..
        } = review.case;
        // The device this connection was actually reviewed under
        // (docs/PROTOCOL.md §12.7) - known by now in the ordinary
        // case, since the review was only ever revealed once
        // punching resolved (`reveal_pending_identity_review`).
        // Falls back to unbound (`""`) only in the rare case the
        // device was never learned at all (`Lost` before `Active`,
        // yet the user chose to `Accept` anyway from fingerprints
        // alone) - additive, never colliding with another
        // unclaimed unbound entry rather than overwriting it, per
        // §1's "additive, never replacing".
        let device_id = session
            .peer_device_ids
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        // Additive (§2): if this exact device is already known
        // under some other key, this is that device's key
        // changing - overwrite in place. Otherwise it's a new
        // device for this nickname - add it, leaving every other
        // device's entry exactly as it was. Key and key_mode set
        // atomically together (`accept_identity_review`), so the
        // rare unbound (`""`) fallback can never land on an
        // unrelated `Direct` entry sharing that same sentinel.
        // Always `PqHybrid`: `check_identity` only ever opens a
        // `StaticMismatch` review for a key that already decoded
        // as a `pq_hybrid` bundle, never derived from
        // `known_users` (which the peer may no longer be in by
        // the time `Accept` is actually pressed).
        session.id_store.accept_identity_review(
            &review.nickname,
            &device_id,
            &new_public_key_der,
            KeyMode::PqHybrid,
            idstore::Trust::Tofu,
        );
        // Recorded against the freshly (re-)pinned device so the
        // *next* mismatch for it has something other than
        // "unknown" to compare against.
        if let Some(addr) = session.peer_link.active_addr(peer) {
            session
                .id_store
                .set_last_seen(&review.nickname, &device_id, addr);
        }
        session.id_store.save_or_warn();
    }
    ui_state.resolve_identity_accept(peer)
}

/// Checks a newly-learned peer's announced identity against the local
/// pinning store (§12), opening a blocking Accept/Reject review if their
/// nickname was previously pinned to a key this connection hasn't proven
/// itself a continuation of. A `pq_hybrid` identity is file-loaded and so
/// stable by construction, which is what makes a byte comparison against
/// the pin definitive (`StaticMismatch` arm) - §12.2.
///
/// Deliberately does **not** use `IdStore::check_and_pin` on a mismatch:
/// that always re-pins as a side effect, which would trust the new key
/// for next time regardless of what the user decides - a `Reject` must
/// leave the old pin untouched until `AcceptIdentity` explicitly re-pins.
/// `IdStore::get` reads without mutating, so the comparison is by hand.
/// Whether `user`'s newly announced identity carries a continuity
/// certificate (§12.6) signed by the one currently pinned for them - i.e.
/// whether this key change was deliberately made by whoever held the old
/// keys, rather than being an unexplained substitution.
///
/// Proving it needs a signing identity separable from the key being
/// replaced, which is exactly what a keybundle has: either half failing to
/// decode as one leaves the change unexplained, and so a question for the
/// user.
pub(super) fn continuity_proven(pinned_der: &[u8], user: &UserInfo) -> bool {
    let (Ok(pinned), Ok(announced)) = (
        proto::decode::<crypto::pq::PqPublicBundle>(pinned_der),
        proto::decode::<crypto::pq::PqPublicBundle>(&user.public_key_der),
    ) else {
        return false;
    };
    crypto::pq::verify_continuity(&pinned, &announced)
}

/// A malformed `public_key_der` is silently skipped - this is a local
/// safety net, not protocol validation.
///
/// **Provisional only.** `device_id` is not known yet at `UserJoined` time
/// - it only arrives later, once the P2P link reaches `Active` and the
/// peer's `DeviceIdAnnounce` decrypts (§12.7) - so this cannot yet decide
/// *which* of a multi-device nickname's entries this connection actually
/// belongs to. What it *can* decide without waiting is whether to gate
/// messaging immediately (§12.4 point 2's "from the moment the mismatch
/// is detected"): by comparing the announced key against *every* device
/// currently pinned for this nickname rather than just one, which never
/// gates a key genuinely already trusted under some device. This can
/// never leak an ungated message to a peer that later turns out to be a
/// different, unrecognised device presenting a copied key (§1's "additive,
/// never replacing" still applies once the device resolves) - sending is
/// itself gated on the same P2P link reaching `Active`, which is a
/// prerequisite for device_id ever resolving at all, so there is no
/// window between "provisionally trusted" and "device confirmed" in
/// which a send could actually go out.
///
/// The precise, per-device resolution - claiming an unbound entry,
/// silently applying a proven continuity certificate, or escalating a
/// same-key-different-device case this coarse check can't distinguish
/// from an ordinary reconnect - happens once the device is actually
/// known, in `finalize_identity_pin`.
pub(super) fn check_identity(session: &mut SessionState, ui_state: &mut UiState, user: &UserInfo) {
    // `public_key_der` is a bincode-encoded `crypto::pq::PqPublicBundle`;
    // a peer announcing anything else has no identity to pin.
    if proto::decode::<crypto::pq::PqPublicBundle>(&user.public_key_der).is_err() {
        return;
    }
    // Scoped by key kind (§1): only this nickname's other `pq_hybrid`
    // -decodable entries are relevant here, never its `Direct`-framed
    // ones - two independent trust dimensions that must never be compared
    // against each other. Decided from the entry's own bytes rather than
    // its stored `key_mode` field, which may not be stamped yet for a
    // freshly first-sighted entry.
    let pq_devices: Vec<Vec<u8>> = session
        .id_store
        .devices_of(&user.name)
        .filter(|d| crypto::pq::fingerprint_of_encoded(&d.key).is_some())
        .map(|d| d.key.clone())
        .collect();

    if pq_devices.is_empty() {
        // True first sighting: nothing to compare against for this
        // dimension, so this is never suspicious - pin it immediately as
        // an unbound entry (`idstore::IdStore`'s "unbound entries" doc),
        // durably, same as before this plan (not merely held for this
        // session) - just not yet attributed to a specific device.
        // `finalize_identity_pin` claims it once the device is known.
        session.id_store.pin_new_device_with_key_mode(
            &user.name,
            "",
            &user.public_key_der,
            idstore::Trust::Tofu,
            Some(user.key_mode),
        );
        session.id_store.save_or_warn();
        return;
    }
    match idstore::compare_key(pq_devices.iter().map(|k| k.as_slice()), &user.public_key_der) {
        idstore::KeyCheck::New => unreachable!("pq_devices was just checked non-empty above"),
        idstore::KeyCheck::Match => {
            // Matches some device already trusted under this nickname -
            // never gates. `finalize_identity_pin` sorts out exactly
            // which device this connection is once it's known, including
            // the "identical key, different device" case a coarse check
            // like this one cannot distinguish from an ordinary
            // reconnect.
        }
        idstore::KeyCheck::Mismatch { .. } if pq_devices.iter().any(|k| continuity_proven(k, user)) => {
            // Provably a deliberate rotation of some device already
            // trusted under this nickname - `finalize_identity_pin`
            // applies it (and says so on the status line) once the
            // device is known; never an alarm, same reasoning as before
            // this plan.
        }
        idstore::KeyCheck::Mismatch { .. } => {
            // Matches nothing this nickname has ever been trusted under,
            // under any device, and no continuity certificate explains it
            // either - gate messaging immediately. The popup itself
            // still waits for address/device id
            // (`reveal_pending_identity_review`, called from
            // `finalize_identity_pin` once they're known, or from the
            // `Lost` arm if punching gives up first).
            // `previous_public_key_der` here is only the coarse "most
            // recently seen device" approximation for display;
            // `finalize_identity_pin` refines it to the exact device
            // actually being compared against before the popup is ever
            // shown.
            let previous_public_key_der = session
                .id_store
                .get(&user.name)
                .map(|k| k.to_vec())
                .unwrap_or_default();
            ui_state.begin_identity_review(
                user.id,
                user.name.clone(),
                IdentityCase::StaticMismatch {
                    new_public_key_der: user.public_key_der.clone(),
                    previous_public_key_der,
                },
            );
        }
    }
}

/// The device-precise counterpart to `check_identity`'s provisional,
/// device-blind decision - runs once this connection's device_id is
/// actually known (`maybe_resolve_p2p_identity_data`), for every peer
/// whose announced key decodes as `pq_hybrid` (a no-op for anyone else,
/// including a `Direct`-framed serverless peer, whose device handling is
/// entirely separate - §5). Re-derives everything fresh from
/// `ui_state.known_users` and `id_store`'s current state rather than
/// trusting anything `check_identity` staged, since by now the one piece
/// it was missing - which specific device this is - is available.
///
/// Runs unconditionally, not just for peers `check_identity` flagged:
/// even the ordinary case (a device already exactly pinned, reconnecting)
/// needs this to refresh its last-seen values, and a fresh first sighting
/// needs this to claim the unbound entry `check_identity` just staged.
pub(super) fn finalize_identity_pin(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    addr: SocketAddr,
    device_id: &str,
) {
    let Some(user) = ui_state.known_users.get(&peer).cloned() else {
        return;
    };
    if proto::decode::<crypto::pq::PqPublicBundle>(&user.public_key_der).is_err() {
        return;
    }
    let nickname = &user.name;

    if session.id_store.get_for_device(nickname, device_id) == Some(user.public_key_der.as_slice())
    {
        // Ordinary reconnect: this exact device already holds this exact
        // key. Refresh last-seen and stop - nothing else to decide.
        session.id_store.set_last_seen(nickname, device_id, addr);
        session.id_store.save_or_warn();
        return;
    }

    if session.id_store.claim_unbound(
        nickname,
        device_id,
        &user.public_key_der,
        Some(KeyMode::PqHybrid),
    ) {
        // The key matched an unbound entry exactly - `check_identity`'s
        // fresh-first-sighting pin, or a manually installed/card-imported
        // one - now resolved to the device that's actually using it.
        session
            .id_store
            .set_key_mode(nickname, device_id, KeyMode::PqHybrid);
        session.id_store.set_last_seen(nickname, device_id, addr);
        session.id_store.save_or_warn();
        return;
    }

    if let Some(existing) = session.id_store.get_for_device(nickname, device_id) {
        // This exact device is already known, under a different key.
        let existing = existing.to_vec();
        if continuity_proven(&existing, &user) {
            session
                .id_store
                .replace_device_key(nickname, device_id, &user.public_key_der);
            session.id_store.save_or_warn();
            ui_state.push_notice(format!(
                "{nickname} moved to a new identity and proved it - pin updated"
            ));
            return;
        }
        open_or_refine_identity_review(session, ui_state, peer, nickname, &existing, &user, addr, device_id);
        return;
    }

    // No entry at all for `(nickname, device_id)`. Does this nickname have
    // any other `pq_hybrid` device pinned? A continuity certificate can
    // legitimately move an identity to a new device in the same step it
    // retires its old keys, so every other device is checked, not just
    // whichever one happens to be "most recent".
    let others: Vec<idstore::DeviceEntry> = session
        .id_store
        .devices_of(nickname)
        .filter(|d| crypto::pq::fingerprint_of_encoded(&d.key).is_some())
        .cloned()
        .collect();
    for other in &others {
        if continuity_proven(&other.key, &user) {
            session
                .id_store
                .replace_device_key(nickname, &other.device_id, &user.public_key_der);
            session
                .id_store
                .rebind_device(nickname, &other.device_id, device_id);
            session.id_store.save_or_warn();
            ui_state.push_notice(format!(
                "{nickname} moved to a new identity and proved it - pin updated"
            ));
            return;
        }
    }
    if others.is_empty() {
        // Defensive: `check_identity` should already have pinned an
        // unbound entry on true first sighting, so this path is normally
        // unreachable - but never leaves a genuinely new nickname
        // unpinned if it somehow is.
        session
            .id_store
            .pin_new_device(nickname, device_id, &user.public_key_der, idstore::Trust::Tofu);
        session
            .id_store
            .set_key_mode(nickname, device_id, KeyMode::PqHybrid);
        session.id_store.set_last_seen(nickname, device_id, addr);
        session.id_store.save_or_warn();
        return;
    }
    // A genuinely new device presenting an unexplained key - whether it
    // matches one of this nickname's other devices exactly (a copied key
    // file, table row 7) or not, this is additive-but-reviewed: `Accept`
    // adds a new entry for this device without touching any other's
    // (§2), it just needs a human to say so first.
    let most_recent = others
        .iter()
        .max_by_key(|d| (d.last_seen_unix.is_some(), d.last_seen_unix.unwrap_or(0)))
        .expect("others is non-empty here");
    open_or_refine_identity_review(
        session,
        ui_state,
        peer,
        nickname,
        &most_recent.key.clone(),
        &user,
        addr,
        device_id,
    );
}

/// Ensures a review naming `previous_key` as the "was" side is staged for
/// `peer` (overwriting whatever coarse approximation `check_identity`
/// staged, if any - safe, since a review is never revealed before this
/// function runs, so nothing shown to the user is ever discarded) and
/// reveals it immediately, since address/device id are known by
/// construction the moment this is called.
#[allow(clippy::too_many_arguments)]
pub(super) fn open_or_refine_identity_review(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
    nickname: &str,
    previous_key: &[u8],
    user: &UserInfo,
    addr: SocketAddr,
    device_id: &str,
) {
    ui_state.begin_identity_review(
        peer,
        nickname.to_string(),
        IdentityCase::StaticMismatch {
            new_public_key_der: user.public_key_der.clone(),
            previous_public_key_der: previous_key.to_vec(),
        },
    );
    if reveal_pending_identity_review(&session.id_store, ui_state, peer, Some(addr), Some(device_id)) {
        voice_stream::play_bell_chime(session);
    }
}

/// Shortens a full SHA-256 hex fingerprint (`crypto::fingerprint`) to its
/// first 16 hex characters (8 bytes) for compact display in a UI warning -
/// still effectively unique for telling two specific keys apart at a
/// glance, without wrapping a 64-character hex string across the screen.
pub(super) fn short_fingerprint(fp: &str) -> &str {
    fp.get(..16).unwrap_or(fp)
}

/// Finishes a mismatch review `check_identity`/`finalize_identity_pin`
/// started with `begin_identity_review`, once this specific connection's
/// P2P address and device id are known - or, on `Lost`, once punching has
/// given up trying to learn them (docs/PROTOCOL.md §12.7). Called from
/// `handle_p2p_event`'s `LinkStatusChanged` arm for both transitions, so
/// the review is never stuck open forever behind a link that never
/// punches through. A no-op (returns `false`) if `peer` has no pending
/// `AwaitingPeerInfo` review - the common case, since most `UserJoined`
/// sightings never mismatch at all.
///
/// The "last known" half names the *specific* device this review's
/// `previous_public_key_der` came from - found by matching that key
/// against `id_store`'s devices for this nickname - rather than the
/// nickname's overall "most recently seen" default, which could be a
/// different device than the one actually being compared against.
/// `None` (shown as "unknown") if that device was never confirmed
/// reachable itself (e.g. the pin came from an identity-card import) or,
/// on the `Lost` fallback, if the device was never learned at all.
pub(super) fn reveal_pending_identity_review(
    id_store: &idstore::IdStore,
    ui_state: &mut UiState,
    peer: UserId,
    new_addr: Option<SocketAddr>,
    new_device_id: Option<&str>,
) -> bool {
    let Some(review) = ui_state.identity_reviews.get(&peer) else {
        return false;
    };
    if review.status != ui::IdentityStatus::AwaitingPeerInfo {
        return false;
    }
    let IdentityCase::StaticMismatch {
        new_public_key_der,
        previous_public_key_der,
    } = &review.case;
    let nickname = review.nickname.clone();
    let previous_entry = id_store
        .devices_of(&nickname)
        .find(|d| d.key == *previous_public_key_der);
    let message = format!(
        "'{nickname}' connected with a different key than last time (was {}, now {}) - possible impersonation.\nLast known from {} (device {}).\nNow connecting from {} (device {}).\nAccept their new key, or reject it.",
        short_fingerprint(&crypto::fingerprint_der(previous_public_key_der)),
        short_fingerprint(&crypto::fingerprint_der(new_public_key_der)),
        display_addr(previous_entry.and_then(|d| d.last_addr)),
        display_device_id(previous_entry.map(|d| d.device_id.as_str())),
        display_addr(new_addr),
        display_device_id(new_device_id),
    );
    ui_state.reveal_identity_review(peer, message)
}

/// What this client has pinned for a serverless peer's nickname, shaped as
/// the `UserInfo` a server would otherwise have relayed (§7.1.5).
///
/// The pinned bytes are taken as they are, readable keybundle or not:
/// which of the two it is decides how this pair talks, not whether they
/// can (`otp::framing_for`). A pin that decodes gets ordinary sealed
/// sends; one that does not is reachable under an already-installed
/// one-time pad, framed direct (§16.2). `None` only when the nickname is
/// not pinned at all - there is then nothing to identify them by.
/// `device_id`, when known (a `direct_punch_to` line named one -
/// `client::p2p::PeerLinkManager::direct_device_id_of`), narrows which of
/// the nickname's pinned devices the key comes from without ever being
/// able to conjure one up: a device-specific pin that isn't there falls
/// back to the ordinary most-recently-seen default rather than failing,
/// exactly `id_store::IdStore::get`'s documented default. `None` behaves
/// exactly as before this parameter existed.
pub fn direct_peer_identity(
    id_store: &crate::client::idstore::IdStore,
    nickname: &str,
    device_id: Option<&str>,
) -> Option<UserInfo> {
    let key = device_id
        .and_then(|d| id_store.get_for_device(nickname, d))
        .or_else(|| id_store.get(nickname))?;
    Some(UserInfo {
        id: crate::client::p2p::direct_peer_id(nickname, device_id),
        name: nickname.to_string(),
        public_key_der: key.to_vec(),
        key_mode: KeyMode::PqHybrid,
    })
}

/// Registers a serverless peer this client can only reach under a pad:
/// their pin is not a readable keybundle, so no `ChannelPresence` envelope
/// can be sealed to them and the handshake that ordinarily introduces a
/// punched peer (§7.1.5) never completes.
///
/// Holding a provisioned pad for the pair is what stands in for it. That
/// is a deliberate substitution, not a gap: under `Direct` framing the pad
/// *is* the authentication (§16.2), so requiring a signature this pair has
/// no keys for would rule out exactly the case this exists to serve.
/// Registering is also all this does - it opens no session and spends
/// nothing; the first actual send is what touches the pad, and its own
/// acknowledgement gate bounds what an impostor taking the nickname could
/// cost (§16.2's one-message bound).
///
/// A peer whose pin *does* decode is left alone: `send_channel_presence`
/// introduces them properly, and doing both would register them twice.
pub fn register_pad_only_peer(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
) -> Option<UiAction> {
    let nickname = session.peer_link.direct_nickname_of(peer)?;
    let device_id = session.peer_link.direct_device_id_of(peer);
    let info = direct_peer_identity(&session.id_store, &nickname, device_id.as_deref())?;
    if crate::client::otp::framing_for(&session.otp_own_pinned_der, &info.public_key_der)
        != crate::client::otp::OtpFraming::Direct
    {
        return None;
    }
    // No pad, nothing to say to them - registering would offer the user a
    // conversation that could not carry a single message.
    let contact_name =
        crate::client::otp::contact_name_if_active(session, peer, &info.public_key_der)?;
    if ui_state.known_users.contains_key(&peer) {
        return None;
    }
    ui_state.known_users.insert(peer, info);
    // The pad is already provisioned, so there is no handshake left to
    // run: every send to them rides it from the first one
    // (`otp::contact_name_if_active` gates on the pad being provisioned,
    // not on a session having been negotiated). Saying so on their row is
    // what makes that visible - unless this side deliberately ended the
    // session and still owes them the notice: re-marking it active would
    // announce as running the very session the reconnect is about to
    // deliver the end of (`otp::resend_pending_end_notices`) - or the end
    // was already confirmed and the pad stands paused
    // (`OtpStore::is_paused`), which `/otp` alone turns back on.
    if !session
        .otp_store
        .get(&contact_name)
        .is_some_and(|s| s.pending_end_notice)
        && !session.otp_store.is_paused(&contact_name)
    {
        ui_state.mark_otp_active(peer);
    }
    on_daemon_peer_appeared(ui_state, session, peer, &nickname, None)
}

/// Tells a serverless peer which channels we are in, so they can place us
/// in the ones we share (`P2pPayload::ChannelPresence`). Sent when their
/// link opens and again whenever our own membership moves; a peer we have
/// no pinned key for is skipped, since nothing can be sealed to them.
/// Records a serverless peer's bootstrap encryption keys from the bundle
/// pinned for their nickname - the job `ServerMessage::UserJoined` does for
/// a peer a server announced (§13.10's "what to encrypt to until the
/// relationship rotates").
///
/// Without this there is nothing to encrypt *to* them with, and since
/// `encrypt_envelope_for` simply yields nothing when the recipient's encap
/// keys are missing, every send to them - including the `ChannelPresence`
/// that would have registered us with them - fails silently. That deadlocks
/// the exchange in exactly the case it exists for: neither side is on a
/// server, so neither is ever announced to the other, so neither ever gets
/// keys. Seeded from the pin instead, which is the same material a server
/// would have relayed.
///
/// Idempotent: a peer whose keys are already known keeps them, so a later
/// rotation is never undone by re-seeding the bootstrap it superseded.
pub fn seed_direct_peer_keys(session: &mut SessionState, peer: UserId, info: &UserInfo) {
    if session.pq_peer_keys.encap_for(peer).is_some() {
        return;
    }
    let Ok(bundle) = proto::decode::<crypto::pq::PqPublicBundle>(&info.public_key_der) else {
        return;
    };
    let Ok(fingerprint) = crypto::pq::bundle_fingerprint(&bundle) else {
        return;
    };
    session
        .pq_peer_keys
        .bootstrap(peer, bundle.bootstrap_encap().clone(), fingerprint);
}

/// Tries `proof` (received under `requested_nickname`, over the link filed
/// as `from`) against every *other* pinned nickname's key - every one of
/// its pinned devices, not just its "most recently seen" default, since a
/// multi-device nickname (device-pinning plan §1) can hold more than one
/// `pq_hybrid` pin and any of them is a legitimate candidate here - stopping
/// at the first genuine cryptographic success (`docs/PROTOCOL.md` §7.1.5).
/// Both proof kinds are only ever tried against a candidate whose pin
/// decodes as a `pq_hybrid` keybundle:
///
/// - a `ChannelPresence` proof, via the ordinary envelope-open
///   (`decrypt_own_envelope`) - nothing to seal an envelope to otherwise;
/// - an `OtpMessage` proof, via only the *outer* `pq_hybrid` seal
///   (`otp::recover_padded_otp_bytes`'s `PqWrapped` branch) - covering a
///   peer who has a real identity *and* an OTP session layered on top of
///   it. A pad-only (`Direct`-framing) sender is deliberately never
///   scanned for: that would mean running every locally-held one-time pad's
///   own decrypt against a ciphertext from an unverified source, one pad at
///   a time, rather than a single cheap signature check - a materially
///   different (and unwanted) cost merely to identify who is speaking.
///
/// A wrong candidate has no observable side effect either way: both checks
/// are ordinary `pq_hybrid` signature verifications that fail before
/// `session.replay.accept` is ever reached, so trying several candidates in
/// a row is safe, and at most one can ever succeed. The pad itself is only
/// ever touched once, by `otp::finish_opening_otp_envelope`, for the one
/// candidate the outer seal already proved correct.
pub(super) async fn scan_pinned_keys_for_match(
    session: &mut SessionState,
    ui_state: &mut UiState,
    from: UserId,
    requested_nickname: &str,
    proof: &crate::client::tui::ui::UnverifiedDirectProof,
) -> Option<ScanMatch> {
    use crate::client::tui::ui::UnverifiedDirectProof;

    let candidates: Vec<(String, Vec<u8>)> = session
        .id_store
        .nicknames()
        .into_iter()
        .filter(|n| n != requested_nickname)
        .flat_map(|n| {
            session
                .id_store
                .devices_of(&n)
                .map(|d| (n.clone(), d.key.clone()))
                .collect::<Vec<_>>()
        })
        .filter(|(_, key_der)| crypto::pq::fingerprint_of_encoded(key_der).is_some())
        .collect();

    for (nickname, key_der) in candidates {
        let info = UserInfo {
            id: from,
            name: nickname.clone(),
            public_key_der: key_der.clone(),
            key_mode: KeyMode::PqHybrid,
        };
        match proof {
            UnverifiedDirectProof::ChannelPresence { envelope } => {
                if let Some(plaintext) = decrypt_own_envelope(envelope, from, &info, None, session) {
                    return Some(ScanMatch {
                        nickname,
                        key_der,
                        recovered: crate::client::tui::ui::RecoveredProof::ChannelPresence {
                            plaintext,
                        },
                    });
                }
            }
            UnverifiedDirectProof::OtpMessage {
                envelope,
                seq,
                channel,
                ..
            } if matches!(
                envelope.content,
                Content::Text | Content::OtpEndSession | Content::OtpEndSessionAck
            ) =>
            {
                let Some(padded) =
                    crate::client::otp::recover_padded_otp_bytes(session, from, &info, envelope)
                else {
                    continue;
                };
                // Proven correct by the outer seal above - only now derive
                // the contact name and spend real pad bytes, exactly once.
                let Some(contact_name) =
                    crate::client::otp::contact_name_for_peer(session, from, &key_der)
                else {
                    continue;
                };
                if !session.otp_store.is_next_expected(&contact_name, *seq) {
                    continue;
                }
                // This scan is only ever tried against a `PqWrapped`
                // candidate (the fingerprint filter above), whose contact
                // name is already device-qualified (§4) - the pre-decrypt
                // device check this passes through is therefore never
                // meaningfully exercised here; whatever's known for `from`
                // is enough (`None` reads as "no claim", which the check
                // only ever refuses on an actual mismatch, never on
                // absence).
                let claimed_device_id = session
                    .peer_device_ids
                    .get(&from)
                    .cloned()
                    .unwrap_or_default();
                let Some((plaintext, ack_proof)) = crate::client::otp::finish_opening_otp_envelope(
                    session,
                    ui_state,
                    from,
                    requested_nickname,
                    &contact_name,
                    channel.as_deref(),
                    &padded,
                    &claimed_device_id,
                )
                .await
                else {
                    continue;
                };
                if !session.otp_store.record_received(&contact_name, *seq) {
                    continue;
                }
                return Some(ScanMatch {
                    nickname,
                    key_der,
                    recovered: crate::client::tui::ui::RecoveredProof::OtpMessage {
                        plaintext,
                        ack_proof,
                        contact_name,
                    },
                });
            }
            _ => {}
        }
    }
    None
}

/// Checks whether `peer`'s address (`PeerLinkManager::active_addr`) and
/// device id (`SessionState::peer_device_ids`, from `on_device_id_announce`)
/// are *both* now known, and if so runs `finalize_identity_pin` - the
/// device-precise resolution `check_identity` could only stage a coarse
/// approximation of at `UserJoined` time. A no-op otherwise - called from
/// both `LinkStatusChanged`'s `Active` arm and `DeviceIdAnnounce`'s arm,
/// since those two pieces of information arrive independently and can
/// race either way; whichever event completes the pair is the one that
/// actually acts.
pub(super) async fn maybe_resolve_p2p_identity_data(
    session: &mut SessionState,
    ui_state: &mut UiState,
    peer: UserId,
) {
    let Some(addr) = session.peer_link.active_addr(peer) else {
        return;
    };
    let Some(device_id) = session.peer_device_ids.get(&peer).cloned() else {
        return;
    };
    finalize_identity_pin(session, ui_state, peer, addr, &device_id);
    // `contact_name_if_active` (device-qualified naming, §4) can only
    // succeed once the peer's device_id is known - which, for a `pq_hybrid`
    // pair, is exactly what just resolved. Re-derives the same
    // reconnect-time "was this session already provisioned" check
    // `UserJoined`'s handler runs eagerly for a `Direct`-framed peer (whose
    // naming needs no device_id and so never had to wait); without this, a
    // still-live `pq_hybrid` OTP session would show "inactive" from the
    // moment its peer reconnects until the next unrelated event happened
    // to refresh it. Only a session genuinely in use - a paused one stays
    // paused across their reconnect (`otp::contact_name_if_session_live`).
    if let Some(user) = ui_state.known_users.get(&peer).cloned()
        && let Some(contact_name) =
            crate::client::otp::contact_name_if_session_live(session, peer, &user.public_key_der)
    {
        ui_state.mark_otp_active(peer);
        crate::client::otp::refresh_otp_key_status(&session.otp_cli_cfg, ui_state, peer, &contact_name)
            .await;
    }
}
