//! Building outgoing `proto::Envelope`s from a recipient's public key and
//! a plaintext - pure `crypto` + `proto` glue with no session state, split
//! out of `session` so the per-recipient send paths (`channel`,
//! `direct_message`) don't have to reach into the event-loop module for
//! it. Only the client ever *builds* envelopes (the server never sees
//! plaintext); the decrypt counterparts stay in `session`, since they read
//! `SessionState`'s own key material.

use crate::crypto;
use crate::proto::{self, Content, Envelope};

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
/// own* signing identity (`session.own_pq_private`, required for step 1 of
/// `docs/PROTOCOL.md` §13), `recipient_pubkey_der` is the recipient's
/// bincode-encoded `crypto::pq::PqPublicBundle`. The whole hybrid blob is
/// boxed as `Envelope`'s single `blocks` element, same trick already used
/// for file transfer's `FileOfferPayload` convention - `Envelope`'s own
/// shape needs no change.
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
