//! Sealed-send steps for the one pq_hybrid layout (US-027).
//!
//! These drive `crypto::pq`'s seal/open pair directly rather than a live
//! session, because what the scenarios are about - who a send names as its
//! recipient, which room it belongs to, and whether it has arrived before -
//! is decided entirely by the binding inside the send. The session-level
//! wiring that consults these is covered by `session`'s own tests.

use aloo::client::pq_rekey::{PQ_KEY_RETENTION, PqOwnKeys};
use aloo::client::replay::ReplayGuard;
use aloo::crypto::pq::{
    bundle_fingerprint, open_chunk, open_send, open_setup, seal_chunk, seal_send, seal_setup,
    sign_rotation, verify_rotation,
};
use aloo::proto::UserId;
use cucumber::{given, then, when};

use crate::world::{AlooWorld, pq_bundle_for};

/// Seals to a peer's bootstrap keys - these scenarios are about what a send
/// is bound to, not about rotation, which `pq_hybrid_forward_secrecy` and
/// `pq_rekey_test.rs` cover.
fn seal_to(from: &str, to: &str, channel: Option<String>, send_id: u64, data: &[u8]) -> Vec<u8> {
    let (_, from_private) = pq_bundle_for(from);
    let (to_public, _) = pq_bundle_for(to);
    seal_send(
        &from_private,
        to_public.bootstrap_encap(),
        bundle_fingerprint(&to_public).expect("fingerprint"),
        channel,
        send_id,
        data,
    )
    .expect("sealing should succeed")
}

/// Opens as `who` would: their own bootstrap decryption key and their own
/// fingerprint, which the binding has to name.
fn open_as(
    who: &str,
    sender: &str,
    blob: &[u8],
) -> Option<(aloo::crypto::pq::SendBinding, Vec<u8>)> {
    let (their_public, their_private) = pq_bundle_for(who);
    let (sender_public, _) = pq_bundle_for(sender);
    let fp = bundle_fingerprint(&their_public).expect("fingerprint");
    open_send(
        &[their_private.bootstrap_decap().clone()],
        &fp,
        &sender_public,
        blob,
    )
}

/// The one peer every scenario here receives from.
const SENDER: UserId = UserId(1);

// ---------------------------------------------------------------------
// Given
// ---------------------------------------------------------------------

#[given(expr = "{word} and {word} each have a pq_hybrid identity")]
async fn two_pq_identities(w: &mut AlooWorld, a: String, b: String) {
    let (pub_a, _) = pq_bundle_for(&a);
    let (pub_b, _) = pq_bundle_for(&b);
    assert_ne!(
        bundle_fingerprint(&pub_a).unwrap(),
        bundle_fingerprint(&pub_b).unwrap(),
        "the two identities must genuinely differ or the scenario proves nothing"
    );
    w.replay = ReplayGuard::new();
    w.refused = false;
    w.opened = None;
}

#[given(expr = "{word} also has a pq_hybrid identity")]
async fn another_pq_identity(_w: &mut AlooWorld, who: String) {
    let _ = pq_bundle_for(&who);
}

// ---------------------------------------------------------------------
// When
// ---------------------------------------------------------------------

#[when(expr = "{word} seals {string} for {word}")]
async fn seal_for(w: &mut AlooWorld, from: String, message: String, to: String) {
    w.sealed = seal_to(&from, &to, None, 1, message.as_bytes());
    w.plaintext = message.into_bytes();
}

#[when(expr = "{word} seals {string} for {word} privately")]
async fn seal_privately(w: &mut AlooWorld, from: String, message: String, to: String) {
    seal_for(w, from, message, to).await;
}

#[when(expr = "{word} is handed that very same sealed message")]
async fn handed_to_outsider(w: &mut AlooWorld, who: String) {
    w.opened = open_as(&who, "alice", &w.sealed).map(|(_, pt)| pt);
    w.refused = w.opened.is_none();
}

#[when(expr = "that sealed message is presented as if it belonged to the channel {string}")]
async fn presented_as_channel(w: &mut AlooWorld, channel: String) {
    // The receiving side compares the binding against the channel the
    // payload actually arrived on - exactly what `decrypt_own_envelope`
    // does with `P2pPayload::Envelope`'s own `channel` field.
    w.refused = match open_as("bob", "alice", &w.sealed) {
        Some((binding, _)) => binding.channel.as_deref() != Some(channel.as_str()),
        None => true,
    };
    w.opened = None;
}

#[when(expr = "{word} accepts it")]
async fn accepts_it(w: &mut AlooWorld, who: String) {
    let (binding, plaintext) = open_as(&who, "alice", &w.sealed)
        .expect("the intended recipient should be able to open it");
    assert!(
        w.replay.accept(SENDER, binding.send_id),
        "the first arrival of a send is never a replay"
    );
    w.opened = Some(plaintext);
    w.refused = false;
}

#[when("the very same sealed message arrives again")]
async fn arrives_again(w: &mut AlooWorld) {
    // The bytes still decrypt - they are genuinely alice's - so what has to
    // refuse them is the replay guard, not the crypto.
    let reopened = open_as("bob", "alice", &w.sealed);
    w.refused = match reopened {
        Some((binding, _)) => !w.replay.accept(SENDER, binding.send_id),
        None => true,
    };
}

/// The straggler a durable send queue produces: sealed with the `send_id`
/// it had when it was written, and delivered only once the peer is back -
/// by which time the sender has sealed newer ones.
#[when(expr = "{word} seals {string} for {word} with send id {int}")]
async fn seal_with_send_id(w: &mut AlooWorld, from: String, message: String, to: String, send_id: u64) {
    w.sealed = seal_to(&from, &to, None, send_id, message.as_bytes());
    w.plaintext = message.into_bytes();
    w.held_send_id = send_id;
}

#[when(expr = "it waits undelivered while {int} newer sends reach {word}")]
async fn newer_sends_arrive_first(w: &mut AlooWorld, newer: u64, _who: String) {
    for step in 1..=newer {
        assert!(
            w.replay.accept(SENDER, w.held_send_id + step),
            "each newer send is itself a first arrival"
        );
    }
}

#[when("it is finally delivered")]
async fn finally_delivered(w: &mut AlooWorld) {
    let reopened = open_as("bob", "alice", &w.sealed);
    w.refused = match reopened {
        Some((binding, plaintext)) => {
            let accepted = w.replay.accept(SENDER, binding.send_id);
            w.opened = accepted.then_some(plaintext);
            !accepted
        }
        None => true,
    };
}

#[then(expr = "{word} accepts it")]
async fn accepts_it_then(w: &mut AlooWorld, _who: String) {
    assert!(
        !w.refused,
        "arriving out of order is not a replay - it had never been seen"
    );
}

#[when(expr = "{word} seals a stream of {int} chunks for {word}")]
async fn seal_stream(w: &mut AlooWorld, from: String, count: u32, to: String) {
    let (_, from_private) = pq_bundle_for(&from);
    let (to_public, _) = pq_bundle_for(&to);
    let send_id = 9u64;
    let (setup, k_data) = seal_setup(
        &from_private,
        to_public.bootstrap_encap(),
        bundle_fingerprint(&to_public).expect("fingerprint"),
        None,
        send_id,
    )
    .expect("sealing a setup");
    w.sealed_chunks = (0..count)
        .map(|seq| seal_chunk(&k_data, send_id, seq, format!("chunk {seq}").as_bytes()))
        .collect();
    w.sealed_setup = Some(setup);
}

// ---------------------------------------------------------------------
// Then
// ---------------------------------------------------------------------

#[then(expr = "{word} reads back exactly what was sealed")]
async fn reads_back(w: &mut AlooWorld, who: String) {
    // Opens with whatever keys this recipient actually holds: their
    // rotating set if the scenario established one, their bootstrap key
    // otherwise.
    let plaintext = match w.pq_own_keys.as_ref() {
        Some(own) => {
            let (their_public, _) = pq_bundle_for(&who);
            let (alice_public, _) = pq_bundle_for("alice");
            let fp = bundle_fingerprint(&their_public).expect("fingerprint");
            open_send(&own.candidates_for(SENDER), &fp, &alice_public, &w.sealed).map(|(_, pt)| pt)
        }
        None => open_as(&who, "alice", &w.sealed).map(|(_, pt)| pt),
    }
    .expect("the intended recipient must be able to open it");
    assert_eq!(
        plaintext, w.plaintext,
        "what came out must be exactly what went in"
    );
}

#[then(expr = "{word} refuses it")]
async fn refuses_it(w: &mut AlooWorld, _who: String) {
    assert!(
        w.refused,
        "this must be refused; instead it opened to {:?}",
        w.opened.as_ref().map(|p| String::from_utf8_lossy(p))
    );
}

#[then(expr = "{word} reads back every chunk in that stream")]
async fn reads_back_stream(w: &mut AlooWorld, who: String) {
    let (their_public, their_private) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let their_fp = bundle_fingerprint(&their_public).unwrap();
    let setup = w.sealed_setup.as_ref().expect("no stream in this scenario");
    let k_data = open_setup(
        &[their_private.bootstrap_decap().clone()],
        &their_fp,
        &alice_public,
        setup,
    )
    .expect("the stream setup must verify for its recipient");

    for (seq, ciphertext) in w.sealed_chunks.iter().enumerate() {
        let seq = seq as u32;
        let plaintext = open_chunk(&k_data, setup.binding.send_id, seq, ciphertext)
            .expect("every chunk must open under the key its setup authorised");
        assert_eq!(plaintext, format!("chunk {seq}").into_bytes());
    }
}

#[then("the stream's setup is what proved the sender, before any chunk was accepted")]
async fn setup_proved_the_sender(w: &mut AlooWorld) {
    let (bob_public, bob_private) = pq_bundle_for("bob");
    let (carol_public, _) = pq_bundle_for("carol");
    let bob_fp = bundle_fingerprint(&bob_public).unwrap();
    let setup = w.sealed_setup.as_ref().expect("no stream in this scenario");

    // Verified against the wrong sender, the setup yields no key at all -
    // so there is nothing to decrypt any chunk with.
    assert!(
        open_setup(
            &[bob_private.bootstrap_decap().clone()],
            &bob_fp,
            &carol_public,
            setup
        )
        .is_none(),
        "a stream setup must not verify against an identity that did not send it"
    );
}

#[then("no two chunks of that stream are byte-identical")]
async fn chunks_differ(w: &mut AlooWorld) {
    let chunks = &w.sealed_chunks;
    assert!(chunks.len() > 1, "need at least two chunks to compare");
    for i in 0..chunks.len() {
        for j in (i + 1)..chunks.len() {
            assert_ne!(
                chunks[i], chunks[j],
                "chunks {i} and {j} repeat a nonce, which would leak the plaintext"
            );
        }
    }
}

// ---------------------------------------------------------------------
// Forward secrecy (US-028)
// ---------------------------------------------------------------------

/// Rotation state for the scenario's two sides, built lazily so the
/// non-rotation scenarios above pay nothing for it.
fn own_keys_for(who: &str) -> PqOwnKeys {
    let (_, private) = pq_bundle_for(who);
    PqOwnKeys::new(private.bootstrap_decap().clone())
}

#[given(expr = "{word} has rotated his encryption keys")]
async fn has_rotated(w: &mut AlooWorld, who: String) {
    let mut own = own_keys_for(&who);
    let rotation = own.rotate_for(SENDER);
    w.pq_rotated_encap = Some(rotation.encap);
    w.pq_own_keys = Some(own);
}

#[when(expr = "{word} seals {string} for {word} using his current key")]
async fn seal_to_current_key(w: &mut AlooWorld, from: String, message: String, to: String) {
    let (_, from_private) = pq_bundle_for(&from);
    let (to_public, _) = pq_bundle_for(&to);
    let encap = w
        .pq_rotated_encap
        .clone()
        .expect("no rotation in this scenario");
    w.sealed = seal_send(
        &from_private,
        &encap,
        bundle_fingerprint(&to_public).expect("fingerprint"),
        None,
        1,
        message.as_bytes(),
    )
    .expect("sealing should succeed");
    w.plaintext = message.into_bytes();
}

#[when(expr = "{word} rotates past that key enough times for it to be forgotten")]
async fn rotates_past(w: &mut AlooWorld, who: String) {
    let own = w.pq_own_keys.get_or_insert_with(|| own_keys_for(&who));
    for _ in 0..=PQ_KEY_RETENTION {
        own.rotate_for(SENDER);
    }
}

#[when(expr = "{word} offers {word} a fresh encryption key signed by her identity")]
async fn offers_rotation(w: &mut AlooWorld, from: String, to: String) {
    let (_, from_private) = pq_bundle_for(&from);
    let (to_public, _) = pq_bundle_for(&to);
    let to_fp = bundle_fingerprint(&to_public).expect("fingerprint");
    let mut own = own_keys_for(&from);
    let rotation = own.rotate_for(SENDER);
    let (encoded, signature) =
        sign_rotation(&from_private, SENDER, &to_fp, &rotation).expect("signing a rotation");
    w.pq_rotation = Some((encoded, signature));
    w.pq_rotated_encap = Some(rotation.encap);
}

#[when(expr = "{word} seals {int} messages for {word} under the same key")]
async fn seal_burst(w: &mut AlooWorld, from: String, count: u64, to: String) {
    let (_, from_private) = pq_bundle_for(&from);
    let (to_public, _) = pq_bundle_for(&to);
    let to_fp = bundle_fingerprint(&to_public).expect("fingerprint");
    let mut own = own_keys_for(&to);
    let rotation = own.rotate_for(SENDER);

    w.sealed_burst = (0..count)
        .map(|i| {
            seal_send(
                &from_private,
                &rotation.encap,
                to_fp,
                None,
                i + 1,
                format!("burst {i}").as_bytes(),
            )
            .expect("seal")
        })
        .collect();
    w.pq_own_keys = Some(own);
}

#[when(expr = "{word} rotates once")]
async fn rotates_once(w: &mut AlooWorld, who: String) {
    let own = w.pq_own_keys.get_or_insert_with(|| own_keys_for(&who));
    own.rotate_for(SENDER);
}

#[then(expr = "{word}'s own keybundle file cannot open that message any more")]
async fn keybundle_cannot_open(w: &mut AlooWorld, who: String) {
    let (their_public, their_private) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&their_public).expect("fingerprint");

    let own = w
        .pq_own_keys
        .as_ref()
        .expect("no rotation in this scenario");
    assert!(
        open_send(&own.candidates_for(SENDER), &fp, &alice_public, &w.sealed).is_none(),
        "a key rotated past the retention window must not open its message"
    );
    assert!(
        open_send(
            &[their_private.bootstrap_decap().clone()],
            &fp,
            &alice_public,
            &w.sealed
        )
        .is_none(),
        "and the keybundle on disk must not open it either - that is the whole point"
    );
}

#[then(expr = "{word} trusts it and encrypts to the new key")]
async fn trusts_rotation(w: &mut AlooWorld, who: String) {
    let (their_public, _) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&their_public).expect("fingerprint");
    let (encoded, signature) = w.pq_rotation.clone().expect("no rotation in this scenario");

    let rotation = verify_rotation(&alice_public, SENDER, &fp, &encoded, &signature)
        .expect("a rotation signed by the pinned identity must verify");
    assert_eq!(
        Some(&rotation.encap),
        w.pq_rotated_encap.as_ref(),
        "the keys installed must be the ones that were offered"
    );
}

#[then("a rotation signed by somebody else is refused")]
async fn other_signature_refused(w: &mut AlooWorld) {
    let (bob_public, _) = pq_bundle_for("bob");
    let (mallory_public, _) = pq_bundle_for("mallory");
    let fp = bundle_fingerprint(&bob_public).expect("fingerprint");
    let (encoded, signature) = w.pq_rotation.clone().expect("no rotation in this scenario");

    assert!(
        verify_rotation(&mallory_public, SENDER, &fp, &encoded, &signature).is_none(),
        "only the identity that signed a rotation can vouch for it"
    );
}

#[then(expr = "{word} cannot use that same rotation as if it were meant for her")]
async fn rotation_not_reusable(w: &mut AlooWorld, who: String) {
    let (their_public, _) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let their_fp = bundle_fingerprint(&their_public).expect("fingerprint");
    let (encoded, signature) = w.pq_rotation.clone().expect("no rotation in this scenario");

    assert!(
        verify_rotation(&alice_public, SENDER, &their_fp, &encoded, &signature).is_none(),
        "a rotation names its recipient, so another peer cannot claim it"
    );
}

#[then(expr = "{word} can still open all {int}")]
async fn can_still_open_all(w: &mut AlooWorld, who: String, count: usize) {
    let (their_public, _) = pq_bundle_for(&who);
    let (alice_public, _) = pq_bundle_for("alice");
    let fp = bundle_fingerprint(&their_public).expect("fingerprint");
    let own = w
        .pq_own_keys
        .as_ref()
        .expect("no rotation in this scenario");
    let candidates = own.candidates_for(SENDER);

    assert_eq!(
        w.sealed_burst.len(),
        count,
        "wrong number of messages sealed"
    );
    for (i, blob) in w.sealed_burst.iter().enumerate() {
        let (_, plaintext) = open_send(&candidates, &fp, &alice_public, blob)
            .expect("a retained key must still open a message from the burst");
        assert_eq!(plaintext, format!("burst {i}").into_bytes());
    }
}
