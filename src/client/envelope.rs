//! Building outgoing `proto::Envelope`s from a recipient's public key and
//! a plaintext - pure `crypto` + `proto` glue with no session state, used
//! by the per-recipient send paths (`channel`, `direct_message`). The
//! decrypt counterparts stay in `session`, since they read
//! `SessionState`'s own key material.

use crate::crypto;
use crate::proto::{Content, Envelope};

/// Encrypts `plaintext` for one recipient under the PQ-hybrid scheme -
/// the only peer-to-peer scheme this app has (`docs/PROTOCOL.md` §13).
/// Needs *our own* signing identity (`own_pq_private`) and *their*
/// current rotating encryption key (`recipient_encap`); a peer whose key
/// we don't hold yet yields `None`, and the caller treats that like any
/// other unreachable recipient.
///
/// `channel`/`send_id` are what the signature is bound to
/// (`crypto::pq::SendBinding`), so one member's copy of a channel message
/// cannot be re-wrapped and passed off to another.
pub(crate) fn encrypt_envelope_for(
    own_pq_private: &crypto::pq::PqPrivateBundle,
    recipient_encap: Option<&crypto::pq::PqEncapKeys>,
    pubkey_der: &[u8],
    channel: Option<String>,
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    encrypt_hybrid_envelope_for(
        own_pq_private,
        recipient_encap?,
        pubkey_der,
        channel,
        send_id,
        plaintext,
        content,
    )
}

/// The sealing itself - `sender_signing` is *our own* signing identity,
/// `recipient_pubkey_der` a bincode-encoded `crypto::pq::PqPublicBundle`.
/// The whole sealed send rides as `Envelope`'s single `blocks` element, so
/// `Envelope`'s own shape needs no change.
///
/// This is a one-chunk send in the sense of `crypto::pq::seal_send`: the
/// identical construction a voice stream uses, with a stream of length
/// one. `recipient_encap` is their *current* rotating encryption key
/// (`pq_rekey::PqPeerKeys`), which is not the one in
/// `recipient_pubkey_der` once the relationship has rotated - the bundle
/// is only ever the bootstrap. `recipient_pubkey_der` is still needed for
/// their identity fingerprint, which the binding names.
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

/// `encrypt_envelope_for` for the OTP layer, whose seal is the outermost
/// layer and so must not name its recipient on the wire
/// (`crypto::pq::seal_send_blinded`). Routing is not a parameter: that
/// layer carries its own under the pad (`client::otp`'s `OtpInner`).
pub(crate) fn encrypt_blinded_envelope_for(
    own_pq_private: &crypto::pq::PqPrivateBundle,
    recipient_encap: Option<&crypto::pq::PqEncapKeys>,
    recipient_pubkey_der: &[u8],
    send_id: u64,
    plaintext: &[u8],
    content: Content,
) -> Option<Envelope> {
    let recipient_fp = crypto::pq::fingerprint_of_encoded(recipient_pubkey_der)?;
    let block = crypto::pq::seal_send_blinded(
        own_pq_private,
        recipient_encap?,
        recipient_fp,
        send_id,
        plaintext,
    )
    .ok()?;
    Some(Envelope {
        content,
        blocks: vec![block],
    })
}
