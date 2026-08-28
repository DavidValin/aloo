//! Post-quantum hybrid encryption for `KeyMode::PqHybrid`: ML-DSA-87 +
//! RSA-4096 to sign, ML-KEM-1024 + X25519 to share a key, AES-256-GCM to
//! encrypt. See `docs/PROTOCOL.md` §13 for the wire-level design; this
//! module is the primitive layer `session.rs`/`channel.rs`/
//! `direct_message.rs`/`voice_stream.rs` build on.
//!
//! Unlike the RSA `my_key` methods (§8: no shared/session key anywhere),
//! this one needs a shared symmetric key per send, so every send is a
//! **setup plus chunks** - one shape for text, voice, files alike (§13.3):
//!
//! 1. Generate a fresh `k_data` and a `SendBinding` naming who the send is
//!    for, which room it belongs to, and which send it is.
//! 2. Wrap `k_data` for that recipient: ML-KEM-1024-encapsulate to their
//!    KEM key, X25519-exchange a throwaway keypair with their X25519 key,
//!    and combine both through HKDF-SHA256 into a one-time `K_wrap`; ship
//!    `k_data XOR K_wrap`. Recovering it needs *both* halves - a break of
//!    ML-KEM-1024 alone, or X25519 alone, isn't enough.
//! 3. Sign the binding and `k_data` with **both** ML-DSA-87 and RSA-PSS -
//!    receivers verify both, so neither primitive alone can forge a send.
//! 4. Encrypt each chunk under `k_data` with a deterministic
//!    `(send_id, seq)` nonce.
//!
//! The keys in steps 2 rotate per peer relationship and are destroyed as
//! they are superseded (`client::pq_rekey`, §13.10) - the signing keys of
//! step 3 are the durable identity and do not.

use std::path::{Path, PathBuf};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key as AesKey, KeyInit as AesKeyInit, Nonce as AesNonce};
use hkdf::Hkdf;
use ml_dsa::signature::{Keypair as MlDsaKeypair, Signer, Verifier};
use ml_dsa::{
    Generate as MlDsaGenerate, KeyExport as MlDsaKeyExport, MlDsa87, Signature as MlDsaSignature,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
// `ml_kem`'s `KeyExport`/`KeyInit` are the identical `crypto_common` traits
// already imported above via `ml_dsa` - only the ones with no `ml_dsa`
// equivalent (`Kem`, `Encapsulate`, `Decapsulate`, `TryKeyInit`) need
// importing again here.
use ml_kem::{Decapsulate, Encapsulate, Kem as MlKemKem, MlKem1024, TryKeyInit as MlKemTryKeyInit};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::{CryptoError, Result};
use crate::proto::UserId;

/// RSA modulus size for a PQ-hybrid identity's signing key - the only RSA
/// key it has, the encryption side being ML-KEM + X25519 (§13.2). Same size
/// as `RSA_PER_MSG_KEY_BITS`, reused rather than re-chosen, since 4096 bits
/// is already this app's established "long-lived, extra margin" size.
pub const PQ_RSA_BITS: usize = super::RSA_PER_MSG_KEY_BITS;

/// HKDF `info` string binding the key-wrap combiner to this exact
/// construction - changing it would silently break interop with a peer
/// still using the old binding, which is the point of domain separation.
const KEY_WRAP_INFO: &[u8] = b"aloo/pq-hybrid/v2/key-wrap";

/// Domain-separation prefix for what a `SendSetup`'s two signatures actually
/// commit to. Keeps a send commitment from ever being mistaken for a
/// signature this app produces anywhere else (a key rotation, say) even if
/// the remaining bytes somehow lined up.
const SEND_DOMAIN: &[u8] = b"aloo/pq-hybrid/v2/send";

/// One PQ-hybrid identity's public half: everything a peer needs to encrypt
/// to, or verify a signature from, this identity. Carried opaquely inside
/// `proto::UserInfo`/`Identify`'s existing `public_key_der: Vec<u8>` field
/// (bincode-encoded) when `key_mode == KeyMode::PqHybrid` - no wire schema
/// change to those structs.
#[derive(Serialize, Deserialize, Clone)]
pub struct PqPublicBundle {
    mldsa_verifying: Vec<u8>,
    rsa_sign_public_der: Vec<u8>,
    /// The **bootstrap** encryption keys - what a peer encrypts to before
    /// this relationship has rotated even once. Superseded per peer as soon
    /// as it has (§13.10); never used again for that peer afterwards.
    bootstrap_encap: PqEncapKeys,
    /// Present when this identity deliberately replaced an earlier one: the
    /// retired identity's signature over this one, so contacts move their
    /// pin across without being asked (§12.6). Absent for an identity that
    /// replaced nothing.
    #[serde(default)]
    continuity: Option<ContinuitySig>,
}

/// One PQ-hybrid identity's private half - loaded from the file the connect
/// popup's `my_key` `file_priv` field points at (see `aloo --keygen-pq-hybrid`).
/// `Clone` so an incoming voice stream's decrypt worker thread (which needs
/// `'static` state - see `voice_stream::spawn_stream_decrypt_worker`) can
/// carry its own copy rather than needing this borrowed across a thread
/// boundary.
#[derive(Serialize, Deserialize, Clone)]
pub struct PqPrivateBundle {
    mldsa_signing: Vec<u8>,
    rsa_sign_private_der: Vec<u8>,
    /// The private half of `PqPublicBundle::bootstrap_encap`. This is the
    /// only encryption key that ever touches disk - every key that
    /// supersedes it is generated in memory and destroyed there, which is
    /// what stops this file opening past traffic (§13.10).
    bootstrap_decap: PqDecapKeys,
}

/// The public half of one PQ-hybrid **encryption** keypair: what a peer
/// encapsulates to. Rotates per peer relationship (§13.10), unlike the
/// signing keys, which are the durable identity.
///
/// Two primitives, so a break of either alone is not enough: ML-KEM-1024
/// for the post-quantum half, X25519 for the classical hedge. That pairing
/// is the same shape as the IETF's X-Wing construction, at a higher ML-KEM
/// parameter set.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PqEncapKeys {
    pub mlkem_encaps: Vec<u8>,
    pub x25519_pub: [u8; 32],
}

/// The private half of a `PqEncapKeys`.
#[derive(Serialize, Deserialize, Clone)]
pub struct PqDecapKeys {
    mlkem_decaps: Vec<u8>,
    x25519_priv: [u8; 32],
}

/// Generates one fresh encryption keypair. Fast - ML-KEM-1024 and X25519
/// keygen are microseconds apiece, unlike a 4096-bit RSA keygen (hundreds
/// of milliseconds), which is precisely what makes rotating inline on the
/// event-loop task practical here, with no background worker needed.
pub fn generate_encryption_keys() -> (PqEncapKeys, PqDecapKeys) {
    let (mlkem_decaps, mlkem_encaps) = MlKem1024::generate_keypair();
    let x_secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let x_public = x25519_dalek::PublicKey::from(&x_secret);
    (
        PqEncapKeys {
            mlkem_encaps: mlkem_encaps.to_bytes().as_slice().to_vec(),
            x25519_pub: x_public.to_bytes(),
        },
        PqDecapKeys {
            mlkem_decaps: mlkem_decaps.to_bytes().as_slice().to_vec(),
            x25519_priv: x_secret.to_bytes(),
        },
    )
}

impl PqPublicBundle {
    /// The encryption keys to use for a peer that has not rotated yet.
    pub fn bootstrap_encap(&self) -> &PqEncapKeys {
        &self.bootstrap_encap
    }

    /// The certificate from the identity this one replaced, if any.
    pub fn continuity(&self) -> Option<&ContinuitySig> {
        self.continuity.as_ref()
    }

    /// Attaches a continuity certificate, producing the bundle that will be
    /// written to disk and announced. Consumes and returns so a caller
    /// cannot forget to use the result.
    pub fn with_continuity(mut self, cert: ContinuitySig) -> Self {
        self.continuity = Some(cert);
        self
    }
}

impl PqPrivateBundle {
    /// The decryption keys matching `PqPublicBundle::bootstrap_encap`.
    pub fn bootstrap_decap(&self) -> &PqDecapKeys {
        &self.bootstrap_decap
    }
}

/// What a send's signatures commit to, beyond the content itself: **who**
/// it is for, **which room** it belongs to, and **which send** it is.
///
/// This is what stops a legitimate recipient from re-wrapping a sender's
/// content for somebody else and passing it off as a message addressed to
/// them: the signature covers `recipient_fp`, so a re-wrap no longer
/// verifies for anyone but the original recipient. `channel` keeps a
/// private message from being replayed into a channel (or the reverse), and
/// `send_id` - the sender's own per-connection counter, already used to tell
/// one stream from another - doubles as the anti-replay sequence a receiver
/// requires to strictly increase per sender.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SendBinding {
    /// `bundle_fingerprint` of the recipient's public bundle. The identity,
    /// not the connection: stable across reconnects, unlike a `UserId`.
    pub recipient_fp: [u8; 32],
    /// `Some(name)` for a channel send, `None` for a direct message.
    pub channel: Option<String>,
    /// The sender's per-connection send counter. Also the basis of every
    /// chunk nonce in this send (`chunk_nonce`).
    pub send_id: u64,
}

/// The per-recipient key material and authentication for one send - the
/// single shape every kind of `pq_hybrid` content is introduced by, whether
/// it carries one chunk (a text message, a file offer) or thousands (a voice
/// stream, a file transfer).
///
/// A stream sends this once, ahead of its chunks; a text message carries it
/// inline alongside its only chunk (`HybridSend`). Either way it is the one
/// place a signature is verified and a `k_data` recovered - never per chunk.
#[derive(Serialize, Deserialize, Clone)]
pub struct SendSetup {
    pub binding: SendBinding,
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_key: [u8; 32],
    /// The sender's throwaway X25519 public key for this send - the
    /// classical half of the wrap. Ephemeral per send, so it contributes
    /// forward secrecy of its own on top of the recipient's rotation.
    pub eph_x25519_pub: [u8; 32],
    pub mldsa_sig: Vec<u8>,
    pub rsa_sig: Vec<u8>,
}

/// A complete one-chunk send: the setup plus its only chunk. Carried as the
/// single element of `Envelope.blocks` for `PqHybrid` text and file offers.
/// Streams don't use this - they send the `SendSetup` on its own and the
/// chunks after it.
#[derive(Serialize, Deserialize)]
pub struct HybridSend {
    pub setup: SendSetup,
    pub ciphertext: Vec<u8>,
}

/// Stable identifier for one PQ-hybrid identity: SHA-256 over the encoded
/// public bundle. Used as `SendBinding::recipient_fp`, and by callers that
/// need to recognise an identity across connections.
/// Covers the identity itself - the signing keys and the bootstrap
/// encryption keys - and deliberately **not** the continuity certificate.
///
/// A certificate is metadata about how this identity came to replace an
/// earlier one, not part of who it is. Excluding it is what lets the
/// certificate sign its own bundle's fingerprint without chasing its tail,
/// and means attaching one never changes the safety phrase a user reads
/// out or the fingerprint their contacts pin.
pub fn bundle_fingerprint(bundle: &PqPublicBundle) -> Result<[u8; 32]> {
    use sha2::Digest;
    let identity = bincode_encode(&(
        &bundle.mldsa_verifying,
        &bundle.rsa_sign_public_der,
        &bundle.bootstrap_encap,
    ))?;
    let digest = Sha256::digest(&identity);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// `bundle_fingerprint` for a bundle still in its announced form - what
/// `Identify`/`UserInfo` carry in `public_key_der` for this `KeyMode`.
/// `None` if those bytes are not a bundle at all.
pub fn fingerprint_of_encoded(encoded: &[u8]) -> Option<[u8; 32]> {
    let bundle: PqPublicBundle = bincode_decode(encoded).ok()?;
    bundle_fingerprint(&bundle).ok()
}

/// The exact bytes both signatures are computed over: a domain tag, the
/// binding, and the data key the binding authorises. Encoding the binding
/// with bincode (length-prefixed strings, fixed field order) is what keeps
/// two different bindings from ever producing the same commitment bytes.
/// Part of the wire contract - the exact bytes both signatures cover,
/// pinned by test vectors (`docs/SECURITY.md`).
pub fn send_commitment(binding: &SendBinding, k_data: &[u8; 32]) -> Result<Vec<u8>> {
    let encoded = bincode_encode(binding)?;
    let mut v = Vec::with_capacity(SEND_DOMAIN.len() + encoded.len() + 32);
    v.extend_from_slice(SEND_DOMAIN);
    v.extend_from_slice(&encoded);
    v.extend_from_slice(k_data);
    Ok(v)
}

/// Opens one send: generates a fresh `k_data`, wraps it for `recipient_public`
/// and signs `(binding, k_data)` with both of the sender's signing keys.
/// Returns the setup to put on the wire and the `k_data` to seal chunks with.
///
/// Called once per recipient per send - a channel message with five members
/// produces five setups, each bound to its own recipient.
pub fn seal_setup(
    sender_signing: &PqPrivateBundle,
    recipient_encap: &PqEncapKeys,
    recipient_fp: [u8; 32],
    channel: Option<String>,
    send_id: u64,
) -> Result<(SendSetup, [u8; 32])> {
    let k_data = fresh_data_key();
    let binding = SendBinding {
        recipient_fp,
        channel,
        send_id,
    };
    let (kem_ciphertext, wrapped_key, eph_x25519_pub) = wrap_key_for(recipient_encap, &k_data)?;
    let commitment = send_commitment(&binding, &k_data)?;

    let mldsa_sig = {
        let sk = decode_mldsa_signing(sender_signing)?;
        sk.sign(&commitment).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&sender_signing.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, &commitment)?;

    Ok((
        SendSetup {
            binding,
            kem_ciphertext,
            wrapped_key,
            eph_x25519_pub,
            mldsa_sig,
            rsa_sig,
        },
        k_data,
    ))
}

/// Recovers and authenticates a send's `k_data`. `None` - fail closed - if
/// the wrap doesn't unwrap, if either signature fails against `sender_public`,
/// or if the setup was not sealed **for this recipient** (`my_fp`).
///
/// That last check is the one that makes a re-wrapped message from a
/// legitimate recipient useless to anyone else: the signature covers the
/// fingerprint of whoever it was really for, so presenting it to a third
/// party fails here rather than decrypting into a message they were never
/// sent. Callers still enforce the parts only they know: that `channel`
/// matches the payload it arrived on, and that `send_id` has not been seen
/// before from this sender.
/// `my_decaps` is every decryption key still worth trying for this peer -
/// the current one first, then recently superseded ones, then the bootstrap
/// (`client::pq_rekey::PqOwnKeys::candidates_for`). A send encrypted just
/// before a rotation must still open, which is what the retained keys are
/// for; anything older than the retention window is gone for good, and that
/// is the forward secrecy (§13.10).
pub fn open_setup(
    my_decaps: &[PqDecapKeys],
    my_fp: &[u8; 32],
    sender_public: &PqPublicBundle,
    setup: &SendSetup,
) -> Option<[u8; 32]> {
    if &setup.binding.recipient_fp != my_fp {
        return None;
    }
    let k_data = my_decaps.iter().find_map(|decap| {
        unwrap_key(
            decap,
            &setup.kem_ciphertext,
            &setup.wrapped_key,
            &setup.eph_x25519_pub,
        )
        .filter(|candidate| {
            // Unwrapping never fails loudly - a wrong key just yields
            // wrong bytes - so the signature is what actually decides
            // whether this key was the right one.
            send_commitment(&setup.binding, candidate)
                .ok()
                .is_some_and(|c| verify_both(sender_public, &c, setup))
        })
    })?;
    let commitment = send_commitment(&setup.binding, &k_data).ok()?;

    if !verify_both(sender_public, &commitment, setup) {
        return None;
    }
    Some(k_data)
}

/// Verifies **both** of a setup's signatures over `commitment`. A break of
/// ML-DSA-87 alone, or RSA-4096 alone, must not be enough to forge a send.
fn verify_both(sender_public: &PqPublicBundle, commitment: &[u8], setup: &SendSetup) -> bool {
    let Ok(vk) = decode_mldsa_verifying(sender_public) else {
        return false;
    };
    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(setup.mldsa_sig.as_slice()) else {
        return false;
    };
    if vk.verify(commitment, &sig).is_err() {
        return false;
    }
    let Ok(rsa_pk) = super::public_key_from_der(&sender_public.rsa_sign_public_der) else {
        return false;
    };
    super::verify(&rsa_pk, commitment, &setup.rsa_sig)
}

/// Domain tag for a rotation signature, kept distinct from a send
/// commitment's so neither could ever be mistaken for the other.
const ROTATION_DOMAIN: &[u8] = b"aloo/pq-hybrid/v2/rotate";

/// Domain tag for a continuity certificate - the old identity vouching for
/// the new one.
const CONTINUITY_DOMAIN: &[u8] = b"aloo/pq-hybrid/v2/continuity";

/// Domain tag for an identity card - an identity vouching for its own
/// pairing with a nickname.
const CARD_DOMAIN: &[u8] = b"aloo/pq-hybrid/v2/card";

/// A retiring identity's signature over the one replacing it.
///
/// Without this, a user who regenerates their keybundle is indistinguishable
/// from a stranger who took their nickname: both just look like "different
/// bytes than last time", and both get the same alarm. With it, a planned
/// change proves itself and re-pins silently, so the alarm is left to mean
/// what it says.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ContinuitySig {
    /// Fingerprint of the identity being retired - what a contact should
    /// already have pinned.
    pub previous_fp: [u8; 32],
    pub mldsa_sig: Vec<u8>,
    pub rsa_sig: Vec<u8>,
}

fn continuity_commitment(previous_fp: &[u8; 32], new_fp: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CONTINUITY_DOMAIN.len() + 64);
    v.extend_from_slice(CONTINUITY_DOMAIN);
    v.extend_from_slice(previous_fp);
    v.extend_from_slice(new_fp);
    v
}

/// Signs `new_public` with the identity being retired, so contacts who
/// pinned the old one can move to the new one without being asked.
///
/// Note what is *not* possible: forging this needs the old private keys.
/// Someone who merely knows a nickname and the old public fingerprint can
/// produce nothing that verifies.
pub fn sign_continuity(
    previous_private: &PqPrivateBundle,
    previous_public: &PqPublicBundle,
    new_public: &PqPublicBundle,
) -> Result<ContinuitySig> {
    let previous_fp = bundle_fingerprint(previous_public)?;
    let new_fp = bundle_fingerprint(new_public)?;
    let commitment = continuity_commitment(&previous_fp, &new_fp);

    let mldsa_sig = {
        let sk = decode_mldsa_signing(previous_private)?;
        sk.sign(&commitment).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&previous_private.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, &commitment)?;

    Ok(ContinuitySig {
        previous_fp,
        mldsa_sig,
        rsa_sig,
    })
}

/// Checks that `new_public` really was vouched for by the identity pinned
/// as `pinned_public`. `false` - and so, an ordinary unexplained key
/// change - if there is no certificate, if it names a different predecessor,
/// or if either signature fails.
pub fn verify_continuity(pinned_public: &PqPublicBundle, new_public: &PqPublicBundle) -> bool {
    let Some(cert) = new_public.continuity.as_ref() else {
        return false;
    };
    let (Ok(pinned_fp), Ok(new_fp)) = (
        bundle_fingerprint(pinned_public),
        bundle_fingerprint(new_public),
    ) else {
        return false;
    };
    if cert.previous_fp != pinned_fp {
        return false;
    }
    let commitment = continuity_commitment(&cert.previous_fp, &new_fp);

    let Ok(vk) = decode_mldsa_verifying(pinned_public) else {
        return false;
    };
    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(cert.mldsa_sig.as_slice()) else {
        return false;
    };
    if vk.verify(&commitment, &sig).is_err() {
        return false;
    }
    let Ok(rsa_pk) = super::public_key_from_der(&pinned_public.rsa_sign_public_der) else {
        return false;
    };
    super::verify(&rsa_pk, &commitment, &cert.rsa_sig)
}

/// An identity vouching for its own pairing with a nickname, shareable by
/// any means at all - email, a message on another app, a USB stick.
///
/// Importing one pins that nickname as verified *before* first contact,
/// which is the one thing pinning alone can never do: a first sighting has
/// nothing to compare against, so it is believed by default. This replaces
/// that leap of faith with something checkable.
#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityCard {
    pub nickname: String,
    pub bundle: PqPublicBundle,
    mldsa_sig: Vec<u8>,
    rsa_sig: Vec<u8>,
}

fn card_commitment(nickname: &str, fp: &[u8; 32]) -> Vec<u8> {
    let name = nickname.as_bytes();
    let mut v = Vec::with_capacity(CARD_DOMAIN.len() + 8 + name.len() + 32);
    v.extend_from_slice(CARD_DOMAIN);
    // Length-prefixed so a nickname can't be shifted into the fingerprint.
    v.extend_from_slice(&(name.len() as u64).to_be_bytes());
    v.extend_from_slice(name);
    v.extend_from_slice(fp);
    v
}

/// Builds a card for this identity under `nickname`.
pub fn make_identity_card(
    private: &PqPrivateBundle,
    public: &PqPublicBundle,
    nickname: &str,
) -> Result<IdentityCard> {
    let fp = bundle_fingerprint(public)?;
    let commitment = card_commitment(nickname, &fp);

    let mldsa_sig = {
        let sk = decode_mldsa_signing(private)?;
        sk.sign(&commitment).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&private.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, &commitment)?;

    Ok(IdentityCard {
        nickname: nickname.to_string(),
        bundle: public.clone(),
        mldsa_sig,
        rsa_sig,
    })
}

/// Checks a card is internally consistent - the bundle inside really did
/// sign this nickname. `None` if not, so a card altered anywhere between
/// its author and here is refused rather than pinned.
///
/// A card is self-signed, which is exactly as much as it claims: it proves
/// whoever holds these keys asked to be known by this name. What makes it
/// worth trusting is the channel it arrived on, not the signature alone.
pub fn open_identity_card(card: &IdentityCard) -> Option<(&str, &PqPublicBundle)> {
    let fp = bundle_fingerprint(&card.bundle).ok()?;
    let commitment = card_commitment(&card.nickname, &fp);

    let vk = decode_mldsa_verifying(&card.bundle).ok()?;
    let sig = MlDsaSignature::<MlDsa87>::try_from(card.mldsa_sig.as_slice()).ok()?;
    vk.verify(&commitment, &sig).ok()?;

    let rsa_pk = super::public_key_from_der(&card.bundle.rsa_sign_public_der).ok()?;
    if !super::verify(&rsa_pk, &commitment, &card.rsa_sig) {
        return None;
    }
    Some((&card.nickname, &card.bundle))
}

pub fn save_identity_card(card: &IdentityCard, path: &Path) -> Result<()> {
    std::fs::write(path, bincode_encode(card)?)?;
    Ok(())
}

pub fn load_identity_card(path: &Path) -> Result<IdentityCard> {
    bincode_decode(&std::fs::read(path)?)
}

/// One offer of fresh encryption keys to one peer (§13.10). Travels
/// opaquely inside `RotateKey`/`KeyRotated`'s existing `new_public_key_der`
/// field - the same trick `PqPublicBundle` already uses on `Identify`, so
/// no new message type is needed.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PqRotation {
    pub encap: PqEncapKeys,
    /// Counts up per peer relationship, so a receiver can refuse an older
    /// rotation that arrives late or is re-injected.
    pub generation: u64,
}

/// What a rotation's two signatures commit to: the domain, who it is for
/// (both the live connection and the durable identity), and the keys being
/// offered. Binding the recipient is what stops one peer replaying a
/// rotation as though it had been addressed to them.
fn rotation_commitment(to: UserId, recipient_fp: &[u8; 32], rotation: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ROTATION_DOMAIN.len() + 8 + 32 + rotation.len());
    v.extend_from_slice(ROTATION_DOMAIN);
    v.extend_from_slice(&to.0.to_be_bytes());
    v.extend_from_slice(recipient_fp);
    v.extend_from_slice(rotation);
    v
}

/// Signs a rotation with the sender's **durable identity** - not with the
/// key being replaced. The verifying key is the pinned identity and never
/// changes, so every rotation is independently verifiable and a reconnect
/// needs nothing special: no chain of prior keys to re-anchor.
pub fn sign_rotation(
    signing: &PqPrivateBundle,
    to: UserId,
    recipient_fp: &[u8; 32],
    rotation: &PqRotation,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let encoded = bincode_encode(rotation)?;
    let commitment = rotation_commitment(to, recipient_fp, &encoded);

    let mldsa_sig = {
        let sk = decode_mldsa_signing(signing)?;
        sk.sign(&commitment).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&signing.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, &commitment)?;
    Ok((encoded, bincode_encode(&(mldsa_sig, rsa_sig))?))
}

/// Domain tag for an OTP mail's payload signature (docs/PROTOCOL.md
/// §17.2), separate from every other signing context so a mail signature
/// can never double as a rotation/continuity/card one or vice versa.
const MAIL_DOMAIN: &[u8] = b"aloo/otp-mail/v1";

fn mail_commitment(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAIL_DOMAIN.len() + payload.len());
    v.extend_from_slice(MAIL_DOMAIN);
    v.extend_from_slice(payload);
    v
}

/// Signs an OTP mail's encoded payload with the sender's durable identity
/// (ML-DSA-87 plus RSA-4096, the same dual-signature every other identity
/// statement here carries). A one-time pad is perfectly confidential but
/// *malleable* - it authenticates nothing - so without this the server (or
/// anyone rewriting the stored blob) could flip payload bits undetected;
/// with it, the receiver verifies the decrypted payload against the
/// sender's **pinned** bundle before believing a byte of it.
pub fn sign_mail(signing: &PqPrivateBundle, payload: &[u8]) -> Result<Vec<u8>> {
    let commitment = mail_commitment(payload);
    let mldsa_sig = {
        let sk = decode_mldsa_signing(signing)?;
        sk.sign(&commitment).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&signing.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, &commitment)?;
    bincode_encode(&(mldsa_sig, rsa_sig))
}

/// Verifies a mail payload signature against the sender's pinned identity.
/// `false` - fail closed - on any malformed or non-matching input.
pub fn verify_mail(sender_public: &PqPublicBundle, payload: &[u8], signature: &[u8]) -> bool {
    let Ok((mldsa_sig, rsa_sig)) = bincode_decode::<(Vec<u8>, Vec<u8>)>(signature) else {
        return false;
    };
    let commitment = mail_commitment(payload);
    let Ok(vk) = decode_mldsa_verifying(sender_public) else {
        return false;
    };
    let Ok(sig) = MlDsaSignature::<MlDsa87>::try_from(mldsa_sig.as_slice()) else {
        return false;
    };
    if vk.verify(&commitment, &sig).is_err() {
        return false;
    }
    let Ok(rsa_pk) = super::public_key_from_der(&sender_public.rsa_sign_public_der) else {
        return false;
    };
    super::verify(&rsa_pk, &commitment, &rsa_sig)
}

/// Verifies a rotation against the sender's pinned identity and returns it.
/// `None` - fail closed - on a bad signature, a rotation addressed to
/// somebody else, or malformed bytes.
pub fn verify_rotation(
    sender_public: &PqPublicBundle,
    to: UserId,
    recipient_fp: &[u8; 32],
    rotation_bytes: &[u8],
    signature: &[u8],
) -> Option<PqRotation> {
    let (mldsa_sig, rsa_sig): (Vec<u8>, Vec<u8>) = bincode_decode(signature).ok()?;
    let commitment = rotation_commitment(to, recipient_fp, rotation_bytes);

    let vk = decode_mldsa_verifying(sender_public).ok()?;
    let sig = MlDsaSignature::<MlDsa87>::try_from(mldsa_sig.as_slice()).ok()?;
    vk.verify(&commitment, &sig).ok()?;

    let rsa_pk = super::public_key_from_der(&sender_public.rsa_sign_public_der).ok()?;
    if !super::verify(&rsa_pk, &commitment, &rsa_sig) {
        return None;
    }
    bincode_decode(rotation_bytes).ok()
}

fn bincode_encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    crate::proto::encode(v).map_err(|e| CryptoError::Encrypt(e.to_string()))
}

fn bincode_decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    crate::proto::decode(bytes).map_err(|e| CryptoError::Decrypt(e.to_string()))
}

/// Generates a fresh PQ-hybrid identity: an ML-DSA-87 keypair, two
/// independent RSA-4096 keypairs (signing, encryption), and an ML-KEM-1024
/// keypair. Slow (real RSA-4096 keygen x2 plus ML-DSA-87/ML-KEM-1024) - only
/// called from `aloo --keygen-pq-hybrid` and `cargo slow`-tagged tests.
pub fn generate_bundle() -> Result<(PqPublicBundle, PqPrivateBundle)> {
    generate_bundle_with_bits(PQ_RSA_BITS)
}

/// `generate_bundle` with the RSA modulus size spelled out, mirroring
/// `KeyPair::generate_with_bits` and existing for the same reason: the
/// acceptance layer needs real, working identities, but RSA-4096 keygen
/// twice per identity is enough to stop people running it at all. The PQ
/// halves are always the real ML-DSA-87/ML-KEM-1024 parameter sets - only
/// the classical hedge shrinks, and only for tests that never assert on it.
pub fn generate_bundle_with_bits(bits: usize) -> Result<(PqPublicBundle, PqPrivateBundle)> {
    let mldsa_signing = MlDsaSigningKey::<MlDsa87>::generate();
    let mldsa_verifying = mldsa_signing.verifying_key();

    let rsa_sign = super::KeyPair::generate_with_bits(bits)?;
    let (bootstrap_encap, bootstrap_decap) = generate_encryption_keys();

    let public = PqPublicBundle {
        mldsa_verifying: mldsa_verifying.to_bytes().as_slice().to_vec(),
        rsa_sign_public_der: super::public_key_to_der(&rsa_sign.public)?,
        bootstrap_encap,
        continuity: None,
    };
    let private = PqPrivateBundle {
        mldsa_signing: mldsa_signing.to_bytes().as_slice().to_vec(),
        rsa_sign_private_der: super::private_key_to_der(&rsa_sign.private)?,
        bootstrap_decap,
    };
    Ok((public, private))
}

pub fn save_public_bundle(bundle: &PqPublicBundle, path: &Path) -> Result<()> {
    std::fs::write(path, bincode_encode(bundle)?)?;
    Ok(())
}

/// The two files a keybundle prefix names **for the CLI key commands**:
/// `<prefix>` holds the private bundle and `<prefix>.pub` the public one.
///
/// Previously re-spelled at each of `--keygen-pq-hybrid`,
/// `--rekey-pq-hybrid` and `--export-identity-card` - four places that had
/// to agree for a keybundle written by one to be loadable by another.
///
/// **This is not the only prefix convention in the tree**, which is why it
/// is scoped to those commands rather than offered as the general rule:
/// `client::daemon::resolve_my_key` and
/// `client::connect::fresh_pq_hybrid_paths_in` both read the private half
/// as `<prefix>.priv`, not as the bare `<prefix>` this returns. The two
/// disagree today; unifying them would change which files an existing
/// install reads, so it is left alone here and noted instead.
pub fn bundle_paths(prefix: &str) -> (PathBuf, PathBuf) {
    (
        PathBuf::from(prefix),
        PathBuf::from(format!("{prefix}.pub")),
    )
}

pub fn load_public_bundle(path: &Path) -> Result<PqPublicBundle> {
    bincode_decode(&std::fs::read(path)?)
}

/// Same as `save_public_bundle`, but restricts the file to owner-only
/// (`0o600`) on unix - this is the one place aloo itself writes a private
/// key to disk (every other `my_key` type's key file is produced externally,
/// e.g. via `openssl`).
pub fn save_private_bundle(bundle: &PqPrivateBundle, path: &Path) -> Result<()> {
    std::fs::write(path, bincode_encode(bundle)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_private_bundle(path: &Path) -> Result<PqPrivateBundle> {
    bincode_decode(&std::fs::read(path)?)
}

/// Ensures a usable keybundle exists at `pub_path`/`priv_path`, generating
/// one if either is missing (no-op if both exist) - so connecting never
/// hard-fails just because the configured files don't exist yet.
/// Deliberately regenerates *both* together rather than salvaging a lone
/// surviving half: a public bundle that doesn't pair with the private one
/// would silently produce an identity that can't decrypt its own incoming
/// messages - far worse than regenerating.
pub fn ensure_bundle_at(pub_path: &Path, priv_path: &Path) -> Result<()> {
    if pub_path.exists() && priv_path.exists() {
        return Ok(());
    }
    let (public, private) = generate_bundle()?;
    if let Some(parent) = priv_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = pub_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    save_private_bundle(&private, priv_path)?;
    save_public_bundle(&public, pub_path)?;
    Ok(())
}

fn decode_mldsa_signing(b: &PqPrivateBundle) -> Result<MlDsaSigningKey<MlDsa87>> {
    MlDsaSigningKey::<MlDsa87>::new_from_slice(&b.mldsa_signing)
        .map_err(|e| CryptoError::Key(e.to_string()))
}

fn decode_mldsa_verifying(b: &PqPublicBundle) -> Result<MlDsaVerifyingKey<MlDsa87>> {
    MlDsaVerifyingKey::<MlDsa87>::new_from_slice(&b.mldsa_verifying)
        .map_err(|e| CryptoError::Key(e.to_string()))
}

fn decode_mlkem_decaps(k: &PqDecapKeys) -> Result<ml_kem::DecapsulationKey<MlKem1024>> {
    ml_kem::DecapsulationKey::<MlKem1024>::new_from_slice(&k.mlkem_decaps)
        .map_err(|e| CryptoError::Key(e.to_string()))
}

fn decode_mlkem_encaps(k: &PqEncapKeys) -> Result<ml_kem::EncapsulationKey<MlKem1024>> {
    ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(&k.mlkem_encaps)
        .map_err(|e| CryptoError::Key(e.to_string()))
}

// (both calls above go through `MlKemTryKeyInit::new_from_slice`, imported above)

/// HKDF-SHA256 combiner: neither `kem_shared` alone nor `rsa_secret` alone
/// determines the result.
/// Part of the wire contract - pinned by test vectors
/// (`docs/SECURITY.md`). The second argument is the classical shared
/// secret: an X25519 exchange since §13.10, an RSA-wrapped secret before it.
pub fn hkdf_combine(kem_shared: &[u8], rsa_secret: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(kem_shared.len() + rsa_secret.len());
    ikm.extend_from_slice(kem_shared);
    ikm.extend_from_slice(rsa_secret);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(KEY_WRAP_INFO, &mut out)
        .expect("32-byte okm is well within HKDF-SHA256's 255*32-byte limit");
    out
}

/// The recipient-specific half (step 3): wrap `k_data` for one recipient's
/// public bundle via ML-KEM-1024 + RSA-4096, combined through the HKDF
/// combiner above.
pub fn wrap_key_for(
    recipient_encap: &PqEncapKeys,
    k_data: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    let ek = decode_mlkem_encaps(recipient_encap)?;
    let (kem_ciphertext, kem_shared) = ek.encapsulate();

    // A throwaway X25519 keypair per send: the shared secret exists only
    // for this wrap and neither side keeps the secret half.
    let eph_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_x25519_pub = x25519_dalek::PublicKey::from(&eph_secret).to_bytes();
    let x_shared = eph_secret.diffie_hellman(&x25519_dalek::PublicKey::from(
        recipient_encap.x25519_pub,
    ));

    let k_wrap = hkdf_combine(kem_shared.as_slice(), x_shared.as_bytes());
    let mut wrapped_key = [0u8; 32];
    for i in 0..32 {
        wrapped_key[i] = k_data[i] ^ k_wrap[i];
    }

    Ok((
        kem_ciphertext.as_slice().to_vec(),
        wrapped_key,
        eph_x25519_pub,
    ))
}

/// Seals a whole one-chunk send (a text message, a file offer) for one
/// recipient: `seal_setup` followed by that setup's only chunk, encoded as
/// the single `Envelope.blocks` element the wire carries.
///
/// A text message is not a special case of anything here - it is simply a
/// send whose stream happens to be one chunk long, sealed by the same code
/// a four-minute voice recording uses.
pub fn seal_send(
    sender_signing: &PqPrivateBundle,
    recipient_encap: &PqEncapKeys,
    recipient_fp: [u8; 32],
    channel: Option<String>,
    send_id: u64,
    data: &[u8],
) -> Result<Vec<u8>> {
    let (setup, k_data) = seal_setup(
        sender_signing,
        recipient_encap,
        recipient_fp,
        channel,
        send_id,
    )?;
    let ciphertext = seal_chunk(&k_data, send_id, 0, data);
    bincode_encode(&HybridSend { setup, ciphertext })
}

/// `seal_send` for a send whose recipient must not be *named* on the wire.
///
/// The binding is signed with the real `recipient_fp` and transmitted with
/// it zeroed. Nothing is weakened: the recipient substitutes their own
/// fingerprint back before verifying, so a send bound to somebody else
/// still fails - not on the explicit comparison `open_setup` makes, but on
/// the two signatures, which is the check that was doing the work all
/// along. What changes is only that an observer can no longer read who a
/// sealed blob is for.
///
/// Used by the OTP layer, where the seal is now the *outermost* layer
/// (`client::otp`'s `build_otp_envelope`) and so has nothing above it left
/// to hide its own header. `channel` is not a parameter because that layer
/// carries its routing under the pad instead (`client::otp`'s `OtpInner`);
/// the binding this signs always names no channel.
///
/// `send_id` stays in the clear - it nonces the chunk, so the recipient
/// needs it before anything can be opened, and it says no more than the
/// per-contact sequence number the same frame states outright.
pub fn seal_send_blinded(
    sender_signing: &PqPrivateBundle,
    recipient_encap: &PqEncapKeys,
    recipient_fp: [u8; 32],
    send_id: u64,
    data: &[u8],
) -> Result<Vec<u8>> {
    let (mut setup, k_data) =
        seal_setup(sender_signing, recipient_encap, recipient_fp, None, send_id)?;
    let ciphertext = seal_chunk(&k_data, send_id, 0, data);
    setup.binding.recipient_fp = [0u8; 32];
    bincode_encode(&HybridSend { setup, ciphertext })
}

/// `seal_send_blinded`'s counterpart. Refuses anything that is not in the
/// blinded shape rather than guessing, so a send that *does* name a
/// recipient cannot be replayed into this path to have the name filled in
/// for it.
///
/// Returns the `send_id` alongside the plaintext - the one part of the
/// binding the caller still has to judge for itself (that it is newer than
/// anything already accepted from this sender).
pub fn open_send_blinded(
    my_decaps: &[PqDecapKeys],
    my_fp: &[u8; 32],
    sender_public: &PqPublicBundle,
    blob: &[u8],
) -> Option<(u64, Vec<u8>)> {
    let mut send: HybridSend = bincode_decode(blob).ok()?;
    if send.setup.binding.recipient_fp != [0u8; 32] || send.setup.binding.channel.is_some() {
        return None;
    }
    // The guess the signatures are about to test.
    send.setup.binding.recipient_fp = *my_fp;
    let k_data = open_setup(my_decaps, my_fp, sender_public, &send.setup)?;
    let plaintext = open_chunk(&k_data, send.setup.binding.send_id, 0, &send.ciphertext)?;
    Some((send.setup.binding.send_id, plaintext))
}

/// Opens a whole one-chunk send, returning what it was bound to alongside
/// the plaintext so the caller can check the parts only it knows (that
/// `channel` matches where this arrived, and that `send_id` is newer than
/// anything already accepted from this sender).
pub fn open_send(
    my_decaps: &[PqDecapKeys],
    my_fp: &[u8; 32],
    sender_public: &PqPublicBundle,
    blob: &[u8],
) -> Option<(SendBinding, Vec<u8>)> {
    let send: HybridSend = bincode_decode(blob).ok()?;
    let k_data = open_setup(my_decaps, my_fp, sender_public, &send.setup)?;
    let plaintext = open_chunk(&k_data, send.setup.binding.send_id, 0, &send.ciphertext)?;
    Some((send.setup.binding, plaintext))
}

/// Recovers `K_data` from a recipient-specific key-wrap using this client's
/// own private bundle - shared by text/file decrypt (`decrypt_hybrid`) and
/// voice stream setup (`voice_stream.rs`, which caches the result for the
/// life of one stream instead of calling this per chunk).
pub fn unwrap_key(
    my_decap: &PqDecapKeys,
    kem_ciphertext: &[u8],
    wrapped_key: &[u8; 32],
    eph_x25519_pub: &[u8; 32],
) -> Option<[u8; 32]> {
    let dk = decode_mlkem_decaps(my_decap).ok()?;
    let kem_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(kem_ciphertext).ok()?;
    let kem_shared = dk.decapsulate(&kem_ct);

    let my_secret = x25519_dalek::StaticSecret::from(my_decap.x25519_priv);
    let x_shared = my_secret.diffie_hellman(&x25519_dalek::PublicKey::from(*eph_x25519_pub));

    let k_wrap = hkdf_combine(kem_shared.as_slice(), x_shared.as_bytes());
    let mut k_data = [0u8; 32];
    for i in 0..32 {
        k_data[i] = wrapped_key[i] ^ k_wrap[i];
    }
    Some(k_data)
}

/// Deterministic per-chunk nonce: unique for the life of one send's
/// `k_data` (which is fresh per send) because `(send_id, seq)` never repeats
/// within one sender's send - so no chunk needs fresh OS randomness, only
/// the counter already on the wire.
/// Part of the wire contract: an independent implementation must derive
/// the identical nonce, so this is public and pinned by test vectors
/// (`docs/SECURITY.md`).
pub fn chunk_nonce(send_id: u64, seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&send_id.to_be_bytes());
    n[8..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Seals one chunk of a send under its already-established `k_data` - cheap,
/// no asymmetric crypto. Used for every kind of content: a text message's
/// only chunk, one 15ms slice of voice, one 512-byte slice of a file.
pub fn seal_chunk(k_data: &[u8; 32], send_id: u64, seq: u32, data: &[u8]) -> Vec<u8> {
    let nonce = chunk_nonce(send_id, seq);
    let cipher = Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(*k_data));
    cipher
        .encrypt(&AesNonce::from(nonce), data)
        .expect("aes-gcm encrypt of one chunk cannot fail")
}

/// Opens one chunk. `None` on a bad AEAD tag - a wrong key, a corrupted
/// chunk, or a `(send_id, seq)` that doesn't match what it was sealed under.
pub fn open_chunk(
    k_data: &[u8; 32],
    send_id: u64,
    seq: u32,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let nonce = chunk_nonce(send_id, seq);
    let cipher = Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(*k_data));
    cipher.decrypt(&AesNonce::from(nonce), ciphertext).ok()
}

/// A fresh, random per-send data key. Every send gets its own, which is what
/// makes the deterministic `(send_id, seq)` chunk nonce safe.
pub fn fresh_data_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&super::random_bytes(32));
    k
}
