//! Key rotation and identity pinning (US-010, US-011).

use cucumber::{given, then, when};
use crossterm::event::{KeyCode, KeyModifiers};

use aloo::crypto::{self, public_key_to_der};
use aloo::idstore::{IdCheck, IdStore};
use aloo::proto::{KeyMode, UserId};
use aloo::rekey::{
    QueuedOutbound, RemoteKeys, ResumeVerification, sign_rotation, verify_and_parse_rotation,
    verify_rotation, verify_with_fallback,
};
use aloo::ui::ui::{IdentityCase, MessageBody, UiAction, SPINNER_FRAMES};

use crate::steps::ui_common::{id_for, press_key, user_with_mode};
use crate::support::ui_rows;
use crate::world::{AlooWorld, keypair_for};

// ---------------------------------------------------------------------
// Rotation signing and verification (US-010)
// ---------------------------------------------------------------------

#[given("bob holds a key I currently trust")]
async fn bob_trusted_key(w: &mut AlooWorld) {
    w.derived.insert("bob".into(), keypair_for("bob"));
}

#[when("bob rotates to a fresh key, signed with the one it replaces")]
async fn bob_rotates(w: &mut AlooWorld) {
    let old = w.derived.get("bob").expect("bob has no key");
    let new = keypair_for("carol"); // stands in for the freshly generated key
    let new_der = public_key_to_der(&new.public).unwrap();
    let sig = sign_rotation(&old.private, UserId(1), &new_der).unwrap();
    w.rotation_der = new_der;
    w.rotation_sig = sig;
    w.derived.insert("bob-next".into(), new);
}

#[when("someone forges a rotation with a key of their own")]
async fn forged_rotation(w: &mut AlooWorld) {
    let forger = keypair_for("mallory");
    let new = keypair_for("carol");
    let new_der = public_key_to_der(&new.public).unwrap();
    w.rotation_sig = sign_rotation(&forger.private, UserId(1), &new_der).unwrap();
    w.rotation_der = new_der;
}

#[when("the rotated key bytes are tampered with in flight")]
async fn tamper_rotation(w: &mut AlooWorld) {
    w.rotation_der[0] ^= 0xFF;
}

#[then("the rotation is accepted and the new key becomes usable")]
async fn rotation_accepted(w: &mut AlooWorld) {
    let old = w.derived.get("bob").expect("bob has no key");
    assert!(
        verify_rotation(&old.public, UserId(1), &w.rotation_der, &w.rotation_sig),
        "a rotation signed by the key it replaces must verify"
    );
    let parsed = verify_and_parse_rotation(&old.public, UserId(1), &w.rotation_der, &w.rotation_sig)
        .expect("a valid rotation should parse into a usable key");
    // Usable in the only sense that matters: it can encrypt to the new key.
    let next = w.derived.get("bob-next").expect("no rotated key recorded");
    let blocks = crypto::encrypt_chunked(&parsed, b"hello via rotated key").unwrap();
    let out = crypto::decrypt_chunked(&next.private, &blocks).unwrap();
    assert_eq!(out, b"hello via rotated key");
}

#[then("the rotation is refused and the old key stays trusted")]
async fn rotation_refused(w: &mut AlooWorld) {
    let old = w.derived.get("bob").expect("bob has no key");
    assert!(
        !verify_rotation(&old.public, UserId(1), &w.rotation_der, &w.rotation_sig),
        "a rotation that is not signed by the trusted key must not verify"
    );
    assert!(
        verify_and_parse_rotation(&old.public, UserId(1), &w.rotation_der, &w.rotation_sig).is_none(),
        "and it must yield no key at all, so the previous one stays in place"
    );
}

#[then("that same rotation does not verify when replayed at someone else")]
async fn replay_refused(w: &mut AlooWorld) {
    let old = w.derived.get("bob").expect("bob has no key");
    assert!(
        verify_rotation(&old.public, UserId(1), &w.rotation_der, &w.rotation_sig),
        "sanity: it verifies for the recipient it was signed for"
    );
    assert!(
        !verify_rotation(&old.public, UserId(2), &w.rotation_der, &w.rotation_sig),
        "binding the recipient into the signature is what stops a rotation being replayed"
    );
}

// ---------------------------------------------------------------------
// Queueing while waiting for a fresh key (US-010)
// ---------------------------------------------------------------------

#[given("bob uses rsa_per_msg and I have already used his current key")]
async fn bob_key_used(w: &mut AlooWorld) {
    let mut remote = RemoteKeys::new();
    remote.track(UserId(2));
    assert!(remote.try_use(UserId(2)), "his bootstrap key should be good for exactly one message");
    assert!(!remote.try_use(UserId(2)), "and stale immediately after");
    w.remote_keys = Some(remote);
}

#[when(expr = "I type {string} and then {string} to him")]
async fn queue_two(w: &mut AlooWorld, first: String, second: String) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    remote.enqueue(UserId(2), QueuedOutbound::Direct { plaintext: first });
    remote.enqueue(
        UserId(2),
        QueuedOutbound::Channel { channel: "general".into(), plaintext: second },
    );
}

#[then(expr = "both messages are held, not sent")]
async fn both_held(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_ref().expect("no rotation state");
    assert_eq!(remote.queue_len(UserId(2)), 2, "both should be waiting for his next key");
}

#[when("bob's next key arrives")]
async fn bob_key_arrives(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    w.flushed = remote.on_rotated(UserId(2));
    remote.mark_used(UserId(2));
}

#[then(expr = "they go out together, {string} before {string}")]
async fn flushed_in_order(w: &mut AlooWorld, first: String, second: String) {
    assert_eq!(
        w.flushed,
        vec![
            QueuedOutbound::Direct { plaintext: first },
            QueuedOutbound::Channel { channel: "general".into(), plaintext: second },
        ],
        "the whole queue flushes at once, in the order it was typed"
    );
    let remote = w.remote_keys.as_ref().expect("no rotation state");
    assert_eq!(remote.queue_len(UserId(2)), 0, "the queue must be drained, not merely read");
}

#[then("his key is stale again until the next rotation")]
async fn stale_again(w: &mut AlooWorld) {
    let remote = w.remote_keys.as_mut().expect("no rotation state");
    assert!(!remote.try_use(UserId(2)), "flushing a batch consumes freshness like any other send");
}

// ---------------------------------------------------------------------
// Regeneration spinner (US-010)
// ---------------------------------------------------------------------

/// Whatever immediately follows "Ctrl+H: Help" on the header row, trimmed
/// of the two separating spaces - scoped rather than scanning the whole
/// header for a `SPINNER_FRAMES` character, because `-` is both a spinner
/// frame and the header's own `Conn:-` "no traffic yet" glyph
/// (`aloo::netstats::ConnQuality::Unknown`); a whole-row scan would
/// mistake that `-` for a spinner that isn't actually there.
fn after_help_hint(w: &AlooWorld) -> String {
    let rows = ui_rows(w.ui_ref());
    let header = rows.first().expect("header row").clone();
    let idx = header.find("Ctrl+H: Help").expect("expected the help hint on the header row");
    header[idx + "Ctrl+H: Help".len()..].trim_end().to_string()
}

fn spinner_on_header(w: &AlooWorld) -> Option<char> {
    let after = after_help_hint(w);
    after.trim_start_matches(' ').chars().next().filter(|c| SPINNER_FRAMES.contains(c))
}

#[when("a key regeneration starts")]
async fn regeneration_starts(w: &mut AlooWorld) {
    w.ui_mut().tick_spinner(true);
}

#[when("the regeneration keeps running for another moment")]
async fn regeneration_continues(w: &mut AlooWorld) {
    w.ui_mut().tick_spinner(true);
}

#[when("every regeneration finishes")]
async fn regeneration_finishes(w: &mut AlooWorld) {
    w.ui_mut().tick_spinner(false);
}

#[then("a spinner appears right after the help hint")]
async fn spinner_after_hint(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    let header = rows.first().expect("header row");
    let expected = format!("Ctrl+H: Help  {}", SPINNER_FRAMES[0]);
    assert!(
        header.contains(&expected),
        "expected {expected:?} - two spaces after the hint, starting on the first frame: {header:?}"
    );
}

#[then("the spinner has moved on to its next frame")]
async fn spinner_advanced(w: &mut AlooWorld) {
    let shown = spinner_on_header(w).expect("no spinner frame on the header row");
    assert_eq!(shown, SPINNER_FRAMES[1], "each tick should advance exactly one frame");
}

#[then("no spinner is shown")]
async fn no_spinner(w: &mut AlooWorld) {
    let rows = ui_rows(w.ui_ref());
    let header = rows.first().expect("header row");
    assert!(header.contains("Ctrl+H: Help"), "the help hint itself should still be there: {header:?}");
    let after = after_help_hint(w);
    assert!(after.is_empty(), "no spinner frame should be visible when nothing is regenerating: {after:?}");
}

#[then("a restarted spinner begins from the first frame again")]
async fn spinner_restarts(w: &mut AlooWorld) {
    w.ui_mut().tick_spinner(true);
    let shown = spinner_on_header(w).expect("no spinner frame on the header row");
    assert_eq!(
        shown, SPINNER_FRAMES[0],
        "a fresh run must start the cycle over rather than resuming mid-cycle"
    );
}

// ---------------------------------------------------------------------
// Identity pinning (US-011)
// ---------------------------------------------------------------------

#[given("a local identity store with nothing pinned yet")]
async fn empty_store(w: &mut AlooWorld) {
    let path = w.temp_path("idstore");
    w.id_store = Some(IdStore::load(&path).expect("a missing store file must not be an error"));
}

#[when(expr = "{word} is seen with the key {string}")]
async fn seen_with_key(w: &mut AlooWorld, name: String, key: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    w.id_check = Some(store.check_and_pin(&name, key.as_bytes()));
}

#[then("it is a first sighting")]
async fn first_sighting(w: &mut AlooWorld) {
    assert_eq!(w.id_check, Some(IdCheck::New), "a nickname never seen before is simply pinned");
}

#[then("it matches what was pinned")]
async fn pin_matches(w: &mut AlooWorld) {
    assert_eq!(w.id_check, Some(IdCheck::Match), "the same key as last time is not a warning");
}

#[then(expr = "it is flagged as a mismatch against the previous key {string}")]
async fn pin_mismatch(w: &mut AlooWorld, previous: String) {
    assert_eq!(
        w.id_check,
        Some(IdCheck::Mismatch { previous_public_key_der: previous.into_bytes() }),
        "a different key must be reported, carrying the key it replaced"
    );
}

#[then(expr = "{word} is now pinned to the new key")]
async fn repinned(w: &mut AlooWorld, name: String) {
    let store = w.id_store.as_mut().expect("no identity store");
    assert_eq!(
        store.check_and_pin(&name, b"key-b"),
        IdCheck::Match,
        "a mismatch re-pins regardless - the warning is a one-time signal, not a lasting block"
    );
}

#[given("bob's continuity key is pinned from a previous session")]
async fn continuity_pinned(w: &mut AlooWorld) {
    w.derived.insert("continuity".into(), keypair_for("bob"));
}

#[when("bob reconnects and re-asserts that same key, signed by itself")]
async fn resume_asserted(w: &mut AlooWorld) {
    let continuity = w.derived.get("continuity").expect("no continuity key");
    let self_der = public_key_to_der(&continuity.public).unwrap();
    let sig = sign_rotation(&continuity.private, UserId(5), &self_der).unwrap();
    w.rotation_der = self_der;
    w.rotation_sig = sig;
}

#[when("bob reconnects and presents a key nobody can vouch for")]
async fn resume_unverifiable(w: &mut AlooWorld) {
    let forger = keypair_for("mallory");
    let new = keypair_for("carol");
    let new_der = public_key_to_der(&new.public).unwrap();
    w.rotation_sig = sign_rotation(&forger.private, UserId(5), &new_der).unwrap();
    w.rotation_der = new_der;
}

#[then("he is recognised as the same person, with no warning")]
async fn recognised_resumed(w: &mut AlooWorld) {
    let continuity = w.derived.get("continuity").expect("no continuity key");
    // No live in-session key exists: a reconnecting peer has a brand-new
    // UserId, which is exactly why the fallback anchor has to carry it.
    let result =
        verify_with_fallback(None, Some(&continuity.public), UserId(5), &w.rotation_der, &w.rotation_sig);
    assert!(
        matches!(result, ResumeVerification::Resumed(_)),
        "a self-asserted continuity key must verify as a resume, got {result:?}"
    );
    w.verification = Some(result);
}

#[then("nothing vouches for him and the reconnect is not trusted")]
async fn resume_failed(w: &mut AlooWorld) {
    let continuity = w.derived.get("continuity").expect("no continuity key");
    let result =
        verify_with_fallback(None, Some(&continuity.public), UserId(5), &w.rotation_der, &w.rotation_sig);
    assert_eq!(
        result,
        ResumeVerification::Failed,
        "a signature that verifies against neither anchor must not install a key"
    );
}

#[then("an ordinary in-session rotation is still preferred over the pinned key")]
async fn live_preferred(w: &mut AlooWorld) {
    let live = keypair_for("alice");
    let continuity = w.derived.get("continuity").expect("no continuity key");
    let new = keypair_for("carol");
    let new_der = public_key_to_der(&new.public).unwrap();
    let sig = sign_rotation(&live.private, UserId(1), &new_der).unwrap();

    let result = verify_with_fallback(Some(&live.public), Some(&continuity.public), UserId(1), &new_der, &sig);
    match result {
        ResumeVerification::Live(k) => {
            assert_eq!(
                public_key_to_der(&k).unwrap(),
                new_der,
                "the live anchor should return the newly rotated key"
            );
        }
        other => panic!("expected the live anchor to win, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Identity review popup: manual Accept/Reject (US-011, US-017)
// ---------------------------------------------------------------------

/// Simulates `session::check_identity` detecting a static (`rsa`/`password`)
/// key mismatch for an already-present channel member and opening a review
/// for it - the same `IdentityCase::StaticMismatch` the real check builds,
/// just with placeholder key bytes since these scenarios only care about
/// the UI consequences, not the byte comparison itself (covered separately
/// by the `IdStore` scenarios above).
#[when(expr = "{word}'s identity mismatches")]
async fn identity_mismatches(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let message = format!(
        "'{name}' connected with a different key than last time (was aaaaaaaaaaaaaaaa, now bbbbbbbbbbbbbbbb) - possible impersonation. Accept their new key, or reject it."
    );
    let case = IdentityCase::StaticMismatch { new_public_key_der: b"new-key".to_vec(), previous_public_key_der: b"old-key".to_vec() };
    w.ui_mut().push_identity_review(id, name, message, case);
}

/// A channel message from a peer whose review is still unresolved - held
/// rather than shown (docs/PROTOCOL.md §12 "hold and reveal").
#[when(expr = "{word} sends the channel message {string} while unresolved")]
async fn sends_while_unresolved(w: &mut AlooWorld, name: String, body: String) {
    let id = UserId(id_for(&name));
    w.ui_mut().on_channel_message("general", id, name, MessageBody::Text(body));
}

#[then(expr = "the message {string} is not shown yet")]
async fn message_not_shown(w: &mut AlooWorld, body: String) {
    let log = &w.ui_ref().channels[0].log;
    assert!(
        !log.iter().any(|e| e.body == MessageBody::Text(body.clone())),
        "a held message must not be in the visible log yet"
    );
}

#[then(expr = "the message {string} now appears in the channel")]
async fn message_now_shown(w: &mut AlooWorld, body: String) {
    let log = &w.ui_ref().channels[0].log;
    assert!(
        log.iter().any(|e| e.body == MessageBody::Text(body.clone())),
        "the held message must be revealed once its sender is accepted: {log:?}"
    );
}

/// Confirms Accept in the review popup - `Left`/`Right`/`Tab` toggle focus
/// off the default, safer `Reject`, then `Enter` confirms. The popup itself
/// only returns the `UiAction`; applying its actual trust effect
/// (`resolve_identity_accept`) is normally `session::handle_ui_action`'s job
/// - simulated directly here the same way other identity-pinning scenarios
/// above bypass the network layer entirely.
#[when("I accept the review")]
async fn accept_review(w: &mut AlooWorld) {
    press_key(w, KeyCode::Tab, KeyModifiers::NONE);
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    match w.last_action {
        Some(UiAction::AcceptIdentity(peer)) => w.ui_mut().resolve_identity_accept(peer),
        ref other => panic!("expected AcceptIdentity, got {other:?}"),
    }
}

/// Confirms Reject - `Enter` alone, since `Reject` is the default focus.
#[when("I reject the review")]
async fn reject_review(w: &mut AlooWorld) {
    press_key(w, KeyCode::Enter, KeyModifiers::NONE);
    match w.last_action {
        Some(UiAction::RejectIdentity(peer)) => w.ui_mut().resolve_identity_reject(peer),
        ref other => panic!("expected RejectIdentity, got {other:?}"),
    }
}

#[then(expr = "a review popup names {word} with Accept and Reject buttons")]
async fn review_names(w: &mut AlooWorld, name: String) {
    assert_eq!(
        w.ui_ref().identity_review_open().map(|r| r.nickname.as_str()),
        Some(name.as_str()),
        "expected the popup to be showing {name}'s review"
    );
    let rows = ui_rows(w.ui_ref());
    assert!(rows.iter().any(|r| r.contains(&format!("Identity review: {name}"))), "expected a titled popup: {rows:?}");
    assert!(rows.iter().any(|r| r.contains("Accept")), "expected an Accept button: {rows:?}");
    assert!(rows.iter().any(|r| r.contains("Reject")), "expected a Reject button: {rows:?}");
}

#[then("no review popup is shown")]
async fn no_review_popup(w: &mut AlooWorld) {
    assert!(w.ui_ref().identity_review_open().is_none(), "no review should be open");
}

#[then(expr = "{word} is no longer flagged")]
async fn no_longer_flagged(w: &mut AlooWorld, name: String) {
    assert!(!w.ui_ref().is_trust_gated(UserId(id_for(&name))), "{name} should be trusted again after being accepted");
}

#[then(expr = "{word} is still flagged as unverified")]
async fn still_flagged(w: &mut AlooWorld, name: String) {
    assert!(w.ui_ref().is_trust_gated(UserId(id_for(&name))), "{name} should still be untrusted after a reject");
}

// "no private room is open" is already defined in `channels.rs` - reused
// as-is here (selecting an unverified peer must not open their room,
// exactly the same assertion as switching tabs closing one).

#[then(expr = "the outgoing channel message excludes {word} but includes {word}")]
async fn send_excludes(w: &mut AlooWorld, excluded: String, included: String) {
    match w.last_action.as_ref().expect("no action was produced") {
        UiAction::SendChannelText { recipients, .. } => {
            let ids: Vec<UserId> = recipients.iter().map(|(id, _, _)| *id).collect();
            assert!(!ids.contains(&UserId(id_for(&excluded))), "{excluded} is unverified and must be excluded");
            assert!(ids.contains(&UserId(id_for(&included))), "{included} should still receive the message");
        }
        other => panic!("expected SendChannelText, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// rsa_per_msg gated-on-sight reconnect (US-017, docs/PROTOCOL.md §12.6.3)
// ---------------------------------------------------------------------

/// Narrative-only scene-setter: establishes that the nickname used below is
/// a *returning* one with real history, not a first-ever sighting - the
/// `id_store` pin itself isn't modeled at this level, the same shortcut
/// `identity_mismatches` above already takes for the `rsa`/`password` case.
#[given(expr = "{word}'s nickname is already linked to a key from a previous session")]
async fn nickname_already_linked(_w: &mut AlooWorld, _name: String) {}

/// Simulates the `rsa_per_msg` join-time gate `session::check_identity` now
/// applies (`docs/PROTOCOL.md` §12.6.3): a nickname that already has a
/// continuity key pinned is gated the instant it's seen again, before any
/// resume or rotation attempt at all - closing the gap where a peer (an
/// impersonator, or one who simply lost `own_next_keys`) that never even
/// tries to prove continuity would otherwise sail through untouched. Joins
/// the channel exactly as the real `UserJoined` handling does, then opens
/// the review the same way `check_identity`'s new `PerMessage` branch does.
#[when(expr = "{word} rejoins using rsa_per_msg without proving continuity")]
async fn rejoins_unverified(w: &mut AlooWorld, name: String) {
    let id = UserId(id_for(&name));
    let info = user_with_mode(id_for(&name), &name, KeyMode::PerMessage);
    w.ui_mut().on_user_joined("general", info.clone());
    let message = format!(
        "'{name}' is using rsa_per_msg under a nickname previously linked to a different session's key, and hasn't proven continuity with it - possible impersonation. Accept their new key, or reject it."
    );
    let case = IdentityCase::ResumeFailed { new_public_key_der: info.public_key_der };
    w.ui_mut().push_identity_review(id, name, message, case);
}
