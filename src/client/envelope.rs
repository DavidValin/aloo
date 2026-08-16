//! Building outgoing `proto::Envelope`s from a recipient's public key and
//! a plaintext - pure `crypto` + `proto` glue with no session state, used
//! by the per-recipient send paths (`channel`, `direct_message`). The
//! decrypt counterparts stay in `session`, since they read
//! `SessionState`'s own key material.

use crate::crypto;
use crate::proto::{Content, Envelope, KeyMode};

/// Encrypts `plaintext` for one recipient, dispatching by *their*
/// `KeyMode`: RSA-OAEP (`encrypt_for_one`, needs nothing of ours) or the
/// PQ-hybrid scheme (`encrypt_hybrid_envelope_for`, needs *our own* signing
/// identity, passed as `own_pq_private` - `None` yields `None` for a
/// `PqHybrid` recipient). Callers are responsible for excluding recipients
/// this session can't address (`keymode_policy::can_address`).
///
/// `channel`/`send_id` are what the PQ-hybrid path binds its signature to
/// (`crypto::pq::SendBinding`) - the RSA path ignores them, having no
/// sender-side signature to bind anything to in the first place.
pub(crate) fn encrypt_envelope_for(
    own_pq_private: Option<&crypto::pq::PqPrivateBundle>,
    recipient_encap: Option<&crypto::pq::PqEncapKeys>,
    key_mode: KeyMode,
    pubkey_der: &[u8],
    channel: Option<String>,
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    match key_mode {
        KeyMode::PqHybrid => encrypt_hybrid_envelope_for(
            own_pq_private?,
            recipient_encap?,
            pubkey_der,
            channel,
            send_id,
            plaintext,
            content,
        ),
        _ => encrypt_for_one(pubkey_der, plaintext, content),
    }
}

pub(crate) fn encrypt_for_one(
    pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    let pk = crypto::public_key_from_der(pubkey_der).ok()?;
    let blocks = crypto::encrypt_chunked(&pk, plaintext).ok()?;
    Some(Envelope { content, blocks })
}

/// `PqHybrid` counterpart of `encrypt_for_one` - `sender_signing` is *our
/// own* signing identity (a PQ-hybrid send is signed, unlike an RSA one),
/// `recipient_pubkey_der` a bincode-encoded `crypto::pq::PqPublicBundle`.
/// The whole sealed send rides as `Envelope`'s single `blocks` element, so
/// `Envelope`'s own shape needs no change.
///
/// This is a one-chunk send in the sense of `crypto::pq::seal_send`: the
/// identical construction a voice stream uses, with a stream of length one.
/// `recipient_encap` is their *current* rotating encryption key
/// (`pq_rekey::PqPeerKeys`), which is not the one in `recipient_pubkey_der`
/// once the relationship has rotated - the bundle is only ever the
/// bootstrap. `recipient_pubkey_der` is still needed for their identity
/// fingerprint, which the binding names.
pub(crate) fn encrypt_hybrid_envelope_for(
    sender_signing: &crypto::pq::PqPrivateBundle,
    recipient_encap: &crypto::pq::PqEncapKeys,
    recipient_pubkey_der: &[u8],
    channel: Option<String>,
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    let recipient_fp = crypto::pq::fingerprint_of_encoded(recipient_pubkey_der)?;
    let block = crypto::pq::seal_send(
        sender_signing,
        recipient_encap,
        recipient_fp,
        channel,
        send_id,
        plaintext,
    )
    .ok()?;
    Some(Envelope {
        content,
        blocks: vec![block],
    })
}
