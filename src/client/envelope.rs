//! Building outgoing `proto::Envelope`s from a recipient's public key and
//! a plaintext - pure `crypto` + `proto` glue with no session state, used
//! by the per-recipient send paths (`channel`, `direct_message`). The
//! decrypt counterparts stay in `session`, since they read
//! `SessionState`'s own key material.

use crate::crypto;
use crate::proto::{self, Content, Envelope, KeyMode};

/// Encrypts `plaintext` for one recipient, dispatching by *their*
/// `KeyMode`: RSA-OAEP (`encrypt_for_one`, needs nothing of ours) or the
/// PQ-hybrid scheme (`encrypt_hybrid_envelope_for`, needs *our own* signing
/// identity, passed as `own_pq_private` - `None` yields `None` for a
/// `PqHybrid` recipient). Callers are responsible for excluding recipients
/// this session can't address (`keymode_policy::can_address`).
pub(crate) fn encrypt_envelope_for(
    own_pq_private: Option<&crypto::pq::PqPrivateBundle>,
    key_mode: KeyMode,
    pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    match key_mode {
        KeyMode::PqHybrid => {
            encrypt_hybrid_envelope_for(own_pq_private?, pubkey_der, plaintext, content)
        }
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
/// own* signing identity (required for step 1 of `docs/PROTOCOL.md` §13),
/// `recipient_pubkey_der` a bincode-encoded `crypto::pq::PqPublicBundle`.
/// The whole hybrid blob rides as `Envelope`'s single `blocks` element, so
/// `Envelope`'s own shape needs no change.
pub(crate) fn encrypt_hybrid_envelope_for(
    sender_signing: &crypto::pq::PqPrivateBundle,
    recipient_pubkey_der: &[u8],
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    let recipient_public: crypto::pq::PqPublicBundle = proto::decode(recipient_pubkey_der).ok()?;
    let hybrid =
        crypto::pq::encrypt_hybrid_for_one(sender_signing, &recipient_public, plaintext).ok()?;
    let block = proto::encode(&hybrid).ok()?;
    Some(Envelope {
        content,
        blocks: vec![block],
    })
}
