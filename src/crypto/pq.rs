//! ML-DSA-87+RSA4096 (sign) / ML-KEM-1024+RSA4096 (key-wrap) / AES-256-GCM
//! (bulk) hybrid encryption for `KeyMode::PqHybrid`. See `docs/PROTOCOL.md`
//! §13 for the full wire-level design; this module is the primitive layer
//! `session.rs`/`channel.rs`/`direct_message.rs`/`voice_stream.rs` build on.
//!
//! Unlike every RSA `my_key` method (§8: "no shared/session key anywhere"),
//! this one *needs* a shared symmetric key per message - that is the whole
//! point of steps 2-3 below - so it is deliberately sign-then-encrypt-then-
//! wrap rather than bent to fit the RSA-OAEP-per-recipient model:
//!
//! 1. Sign `data` with both ML-DSA-87 and RSA-4096 (a separate signing-only
//!    RSA-4096 keypair, never the encryption one below) - a receiver must
//!    verify **both** before trusting `data` at all.
//! 2. AES-256-GCM-encrypt the signed bundle **once** with a fresh random
//!    32-byte `K_data`, regardless of recipient count.
//! 3. For each recipient: ML-KEM-1024-encapsulate to their KEM public key
//!    (`kem_shared`), and separately RSA-OAEP-encrypt a fresh random secret
//!    (`rsa_secret`) to their *encryption* RSA-4096 key (distinct from the
//!    signing one above). Combine `HKDF-SHA256(kem_shared ++ rsa_secret)`
//!    into a one-time wrapping key `K_wrap`, and ship `K_data XOR K_wrap`.
//!    Recovering `K_data` needs *both* `kem_shared` and `rsa_secret` - a
//!    break of ML-KEM-1024 alone, or of RSA-4096 alone, isn't enough.

use std::path::Path;

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

/// RSA modulus size for both RSA-4096 halves of a PQ-hybrid identity (the
/// signing pair and, separately, the encryption pair). Same size as
/// `RSA_PER_MSG_KEY_BITS` - reused rather than re-chosen, since 4096 bits is
/// already this app's established "long-lived, extra security margin" size.
pub const PQ_RSA_BITS: usize = super::RSA_PER_MSG_KEY_BITS;

/// HKDF `info` string binding the key-wrap combiner to this exact
/// construction - changing it would silently break interop with a peer
/// still using the old binding, which is the point of domain separation.
const KEY_WRAP_INFO: &[u8] = b"aloo/pq-hybrid/v1/key-wrap";

/// One PQ-hybrid identity's public half: everything a peer needs to encrypt
/// to, or verify a signature from, this identity. Carried opaquely inside
/// `proto::UserInfo`/`Identify`'s existing `public_key_der: Vec<u8>` field
/// (bincode-encoded) when `key_mode == KeyMode::PqHybrid` - no wire schema
/// change to those structs.
#[derive(Serialize, Deserialize, Clone)]
pub struct PqPublicBundle {
    mldsa_verifying: Vec<u8>,
    rsa_sign_public_der: Vec<u8>,
    mlkem_encaps: Vec<u8>,
    rsa_enc_public_der: Vec<u8>,
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
    mlkem_decaps: Vec<u8>,
    rsa_enc_private_der: Vec<u8>,
}

/// The recipient-specific wire blob carried as the single element of
/// `Envelope.blocks` (`vec![bincode::encode(this)]`) for a `PqHybrid` text
/// or file message. `nonce`/`ciphertext` are identical across every
/// recipient of one send (see module doc); only `kem_ciphertext`/
/// `wrapped_key`/`wrapped_key_rsa` differ per recipient.
#[derive(Serialize, Deserialize)]
pub struct HybridEnvelope {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_key: [u8; 32],
    pub wrapped_key_rsa: Vec<u8>,
}

/// The recipient-specific key-wrap material for one voice stream, computed
/// once at record-start (mirrors the RSA path's "recipients' public keys
/// parsed once at record-start", `docs/PROTOCOL.md` §7.3) and repeated
/// verbatim in every chunk sent to that recipient - see `voice_stream.rs`.
/// Unlike `HybridEnvelope`, this also carries a signature: a voice stream
/// has no single upfront "data" to sign the way a text/file `Envelope`
/// does (§13's step 1 needs *something* to bind the signature to), so the
/// signed payload here is `stream_id ++ k_data` instead - proving both
/// "this stream's key really came from this sender" and "for this specific
/// `stream_id`", so a captured key-setup can't be replayed against a
/// different stream.
#[derive(Serialize, Deserialize, Clone)]
pub struct HybridStreamKeySetup {
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_key: [u8; 32],
    pub wrapped_key_rsa: Vec<u8>,
    pub mldsa_sig: Vec<u8>,
    pub rsa_sig: Vec<u8>,
}

fn stream_commitment(stream_id: u64, k_data: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + 32);
    v.extend_from_slice(&stream_id.to_be_bytes());
    v.extend_from_slice(k_data);
    v
}

/// Wraps a fresh per-stream `k_data` for one recipient (like `wrap_key_for`)
/// and signs the `(stream_id, k_data)` binding with both of the sender's
/// signing keys - called once per recipient at record-start, never per
/// chunk (`docs/PROTOCOL.md` §11.6's "no rotation happens mid-stream"
/// precedent, applied here to "no re-signing mid-stream" instead).
pub fn wrap_key_for_stream(
    sender_signing: &PqPrivateBundle,
    recipient_public: &PqPublicBundle,
    stream_id: u64,
    k_data: &[u8; 32],
) -> Result<HybridStreamKeySetup> {
    let (kem_ciphertext, wrapped_key, wrapped_key_rsa) = wrap_key_for(recipient_public, k_data)?;
    let commitment = stream_commitment(stream_id, k_data);

    let mldsa_sig = {
        let sk = decode_mldsa_signing(sender_signing)?;
        sk.sign(&commitment).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&sender_signing.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, &commitment)?;

    Ok(HybridStreamKeySetup {
        kem_ciphertext,
        wrapped_key,
        wrapped_key_rsa,
        mldsa_sig,
        rsa_sig,
    })
}

/// Recovers and authenticates `k_data` from one chunk's `HybridStreamKeySetup`
/// - `None` if either signature fails to verify against `sender_public`, or
/// the wrap material itself doesn't unwrap. A caller only needs to call this
/// once per `(from, stream_id)` (on the first chunk/key-setup seen for it)
/// and cache the result, exactly like the RSA path's "resolved once, not per
/// chunk" `candidate_privates_for` snapshot.
pub fn unwrap_key_for_stream(
    my_private: &PqPrivateBundle,
    sender_public: &PqPublicBundle,
    stream_id: u64,
    setup: &HybridStreamKeySetup,
) -> Option<[u8; 32]> {
    let k_data = unwrap_key(
        my_private,
        &setup.kem_ciphertext,
        &setup.wrapped_key,
        &setup.wrapped_key_rsa,
    )?;
    let commitment = stream_commitment(stream_id, &k_data);

    let vk = decode_mldsa_verifying(sender_public).ok()?;
    let sig = MlDsaSignature::<MlDsa87>::try_from(setup.mldsa_sig.as_slice()).ok()?;
    vk.verify(&commitment, &sig).ok()?;

    let rsa_pk = super::public_key_from_der(&sender_public.rsa_sign_public_der).ok()?;
    if !super::verify(&rsa_pk, &commitment, &setup.rsa_sig) {
        return None;
    }

    Some(k_data)
}

#[derive(Serialize, Deserialize)]
struct SignedBody {
    data: Vec<u8>,
    mldsa_sig: Vec<u8>,
    rsa_sig: Vec<u8>,
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
    let mldsa_signing = MlDsaSigningKey::<MlDsa87>::generate();
    let mldsa_verifying = mldsa_signing.verifying_key();

    let rsa_sign = super::KeyPair::generate_with_bits(PQ_RSA_BITS)?;
    let rsa_enc = super::KeyPair::generate_with_bits(PQ_RSA_BITS)?;

    let (mlkem_decaps, mlkem_encaps) = MlKem1024::generate_keypair();

    let public = PqPublicBundle {
        mldsa_verifying: mldsa_verifying.to_bytes().as_slice().to_vec(),
        rsa_sign_public_der: super::public_key_to_der(&rsa_sign.public)?,
        mlkem_encaps: mlkem_encaps.to_bytes().as_slice().to_vec(),
        rsa_enc_public_der: super::public_key_to_der(&rsa_enc.public)?,
    };
    let private = PqPrivateBundle {
        mldsa_signing: mldsa_signing.to_bytes().as_slice().to_vec(),
        rsa_sign_private_der: super::private_key_to_der(&rsa_sign.private)?,
        mlkem_decaps: mlkem_decaps.to_bytes().as_slice().to_vec(),
        rsa_enc_private_der: super::private_key_to_der(&rsa_enc.private)?,
    };
    Ok((public, private))
}

pub fn save_public_bundle(bundle: &PqPublicBundle, path: &Path) -> Result<()> {
    std::fs::write(path, bincode_encode(bundle)?)?;
    Ok(())
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
/// one first if either is missing - a no-op if both already exist. Used by
/// `connect.rs::resolve_my_keypair`'s `PqHybrid` arm so connecting never
/// hard-fails just because the configured files don't exist yet (whether
/// that's a fresh, not-yet-generated location the connect popup assigned,
/// or a path the user typed by hand).
///
/// Deliberately treats "either file missing" as "neither is usable" and
/// (re)generates *both* together, rather than trying to salvage a lone
/// surviving half - loading a public bundle that doesn't actually pair with
/// the private one (e.g. after one file was manually deleted and the other
/// wasn't) would silently produce an identity that can't decrypt its own
/// incoming messages, a far worse outcome than just regenerating.
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

fn decode_mlkem_decaps(b: &PqPrivateBundle) -> Result<ml_kem::DecapsulationKey<MlKem1024>> {
    ml_kem::DecapsulationKey::<MlKem1024>::new_from_slice(&b.mlkem_decaps)
        .map_err(|e| CryptoError::Key(e.to_string()))
}

fn decode_mlkem_encaps(b: &PqPublicBundle) -> Result<ml_kem::EncapsulationKey<MlKem1024>> {
    ml_kem::EncapsulationKey::<MlKem1024>::new_from_slice(&b.mlkem_encaps)
        .map_err(|e| CryptoError::Key(e.to_string()))
}

// (both calls above go through `MlKemTryKeyInit::new_from_slice`, imported above)

/// HKDF-SHA256 combiner: neither `kem_shared` alone nor `rsa_secret` alone
/// determines the result.
fn hkdf_combine(kem_shared: &[u8], rsa_secret: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(kem_shared.len() + rsa_secret.len());
    ikm.extend_from_slice(kem_shared);
    ikm.extend_from_slice(rsa_secret);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(KEY_WRAP_INFO, &mut out)
        .expect("32-byte okm is well within HKDF-SHA256's 255*32-byte limit");
    out
}

fn sign_body(sender_signing: &PqPrivateBundle, data: &[u8]) -> Result<Vec<u8>> {
    let mldsa_sig = {
        let sk = decode_mldsa_signing(sender_signing)?;
        sk.sign(data).encode().as_slice().to_vec()
    };
    let rsa_sk = super::private_key_from_der(&sender_signing.rsa_sign_private_der)?;
    let rsa_sig = super::sign(&rsa_sk, data)?;

    let body = SignedBody {
        data: data.to_vec(),
        mldsa_sig,
        rsa_sig,
    };
    bincode_encode(&body)
}

/// Verifies **both** signatures against `sender_public` and returns the
/// original `data` only if both check out - a break in ML-DSA-87 alone, or
/// RSA-4096 alone, must not be enough to forge a message.
fn verify_body(sender_public: &PqPublicBundle, plaintext: &[u8]) -> Option<Vec<u8>> {
    let body: SignedBody = bincode_decode(plaintext).ok()?;

    let vk = decode_mldsa_verifying(sender_public).ok()?;
    let sig = MlDsaSignature::<MlDsa87>::try_from(body.mldsa_sig.as_slice()).ok()?;
    vk.verify(&body.data, &sig).ok()?;

    let rsa_pk = super::public_key_from_der(&sender_public.rsa_sign_public_der).ok()?;
    if !super::verify(&rsa_pk, &body.data, &body.rsa_sig) {
        return None;
    }

    Some(body.data)
}

/// The recipient-independent half of a hybrid send (step 1-2 of the module
/// doc): sign `data`, then AES-256-GCM-encrypt it once under a freshly
/// random `K_data`. Called once per outgoing `Envelope` or once per voice
/// stream - never per recipient, never per chunk.
pub fn encrypt_hybrid_body(
    sender_signing: &PqPrivateBundle,
    data: &[u8],
) -> Result<([u8; 32], [u8; 12], Vec<u8>)> {
    let signed = sign_body(sender_signing, data)?;

    let mut k_data = [0u8; 32];
    k_data.copy_from_slice(&super::random_bytes(32));
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&super::random_bytes(12));

    let cipher = Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(k_data));
    let ciphertext = cipher
        .encrypt(&AesNonce::from(nonce), signed.as_slice())
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    Ok((k_data, nonce, ciphertext))
}

/// The recipient-specific half (step 3): wrap `k_data` for one recipient's
/// public bundle via ML-KEM-1024 + RSA-4096, combined through the HKDF
/// combiner above.
pub fn wrap_key_for(
    recipient_public: &PqPublicBundle,
    k_data: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
    let ek = decode_mlkem_encaps(recipient_public)?;
    let (kem_ciphertext, kem_shared) = ek.encapsulate();

    let rsa_pk = super::public_key_from_der(&recipient_public.rsa_enc_public_der)?;
    let rsa_secret = super::random_bytes(32);
    let wrapped_key_rsa_blocks = super::encrypt_chunked(&rsa_pk, &rsa_secret)?;
    let wrapped_key_rsa = bincode_encode(&wrapped_key_rsa_blocks)?;

    let k_wrap = hkdf_combine(kem_shared.as_slice(), &rsa_secret);
    let mut wrapped_key = [0u8; 32];
    for i in 0..32 {
        wrapped_key[i] = k_data[i] ^ k_wrap[i];
    }

    Ok((
        kem_ciphertext.as_slice().to_vec(),
        wrapped_key,
        wrapped_key_rsa,
    ))
}

/// Convenience for the single-recipient (DM) case: body + wrap in one call.
pub fn encrypt_hybrid_for_one(
    sender_signing: &PqPrivateBundle,
    recipient_public: &PqPublicBundle,
    data: &[u8],
) -> Result<HybridEnvelope> {
    let (k_data, nonce, ciphertext) = encrypt_hybrid_body(sender_signing, data)?;
    let (kem_ciphertext, wrapped_key, wrapped_key_rsa) = wrap_key_for(recipient_public, &k_data)?;
    Ok(HybridEnvelope {
        nonce,
        ciphertext,
        kem_ciphertext,
        wrapped_key,
        wrapped_key_rsa,
    })
}

/// Recovers `K_data` from a recipient-specific key-wrap using this client's
/// own private bundle - shared by text/file decrypt (`decrypt_hybrid`) and
/// voice stream setup (`voice_stream.rs`, which caches the result for the
/// life of one stream instead of calling this per chunk).
pub fn unwrap_key(
    my_private: &PqPrivateBundle,
    kem_ciphertext: &[u8],
    wrapped_key: &[u8; 32],
    wrapped_key_rsa: &[u8],
) -> Option<[u8; 32]> {
    let dk = decode_mlkem_decaps(my_private).ok()?;
    let kem_ct = ml_kem::Ciphertext::<MlKem1024>::try_from(kem_ciphertext).ok()?;
    let kem_shared = dk.decapsulate(&kem_ct);

    let wrapped_rsa_blocks: Vec<Vec<u8>> = bincode_decode(wrapped_key_rsa).ok()?;
    let rsa_sk = super::private_key_from_der(&my_private.rsa_enc_private_der).ok()?;
    let rsa_secret = super::decrypt_chunked(&rsa_sk, &wrapped_rsa_blocks).ok()?;

    let k_wrap = hkdf_combine(kem_shared.as_slice(), &rsa_secret);
    let mut k_data = [0u8; 32];
    for i in 0..32 {
        k_data[i] = wrapped_key[i] ^ k_wrap[i];
    }
    Some(k_data)
}

/// Full decrypt+verify pipeline for a text/file `Envelope.blocks[0]` blob.
/// `None` on any failure (bad AEAD tag, bad signature, malformed bytes) -
/// mirrors `decrypt_envelope_for`'s existing RSA failure path, never panics.
pub fn decrypt_hybrid(
    my_private: &PqPrivateBundle,
    sender_public: &PqPublicBundle,
    blob: &[u8],
) -> Option<Vec<u8>> {
    let env: HybridEnvelope = bincode_decode(blob).ok()?;
    let k_data = unwrap_key(
        my_private,
        &env.kem_ciphertext,
        &env.wrapped_key,
        &env.wrapped_key_rsa,
    )?;

    let cipher = Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(k_data));
    let plaintext = cipher
        .decrypt(&AesNonce::from(env.nonce), env.ciphertext.as_slice())
        .ok()?;

    verify_body(sender_public, &plaintext)
}

/// Deterministic per-chunk nonce for a voice stream: unique for the life of
/// `k_data` (which is fresh per stream) since `(stream_id, seq)` never
/// repeats within one sender's stream - safe without needing fresh OS
/// randomness on every 100ms chunk.
fn chunk_nonce(stream_id: u64, seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&stream_id.to_be_bytes());
    n[8..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Encrypts one voice chunk's raw PCM under a stream's already-established
/// `k_data` (see `HybridStreamKeySetup`) - cheap, no asymmetric crypto.
pub fn encrypt_hybrid_chunk(k_data: &[u8; 32], stream_id: u64, seq: u32, pcm: &[u8]) -> Vec<u8> {
    let nonce = chunk_nonce(stream_id, seq);
    let cipher = Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(*k_data));
    cipher
        .encrypt(&AesNonce::from(nonce), pcm)
        .expect("aes-gcm encrypt of one voice chunk cannot fail")
}

/// Decrypts one voice chunk. `None` on a bad AEAD tag (wrong key, corrupted
/// chunk, or a `(stream_id, seq)` nonce mismatch).
pub fn decrypt_hybrid_chunk(
    k_data: &[u8; 32],
    stream_id: u64,
    seq: u32,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let nonce = chunk_nonce(stream_id, seq);
    let cipher = Aes256Gcm::new(&AesKey::<Aes256Gcm>::from(*k_data));
    cipher.decrypt(&AesNonce::from(nonce), ciphertext).ok()
}

/// A fresh, random per-stream data key - the voice-streaming counterpart of
/// the `K_data` `encrypt_hybrid_body` generates for text/file, but with no
/// "body" to sign-then-encrypt alongside it (a stream has no single upfront
/// plaintext; `wrap_key_for_stream`'s per-recipient signature over
/// `(stream_id, k_data)` is what authenticates it instead).
pub fn fresh_data_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&super::random_bytes(32));
    k
}

/// The wire blob for one `PqHybrid` voice chunk (`Envelope.blocks`-style
/// single-element `Vec<Vec<u8>>` on `StreamChannelChunk`/`StreamDirectChunk`)
/// - `key_setup` is the same `HybridStreamKeySetup` for every chunk of one
/// stream to one recipient (repeated verbatim, see `HybridStreamKeySetup`'s
/// doc for the accepted bandwidth tradeoff this implies), `ciphertext` is
/// this specific chunk's AES-256-GCM output.
#[derive(Serialize, Deserialize)]
pub struct HybridVoiceChunk {
    pub key_setup: HybridStreamKeySetup,
    pub ciphertext: Vec<u8>,
}

/// Builds one chunk's wire blob: encrypts `pcm` under `k_data` (cheap, no
/// asymmetric crypto) and pairs it with the cached `key_setup` from
/// record-start.
pub fn encrypt_hybrid_voice_chunk(
    key_setup: &HybridStreamKeySetup,
    k_data: &[u8; 32],
    stream_id: u64,
    seq: u32,
    pcm: &[u8],
) -> Vec<u8> {
    let ciphertext = encrypt_hybrid_chunk(k_data, stream_id, seq, pcm);
    let chunk = HybridVoiceChunk {
        key_setup: key_setup.clone(),
        ciphertext,
    };
    bincode_encode(&chunk)
        .expect("HybridVoiceChunk is plain data - bincode-encoding it cannot fail")
}
