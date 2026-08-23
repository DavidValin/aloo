use std::fs;
use std::path::Path;

/// ML-DSA-87+RSA4096 / ML-KEM-1024+RSA4096 / AES-256-GCM hybrid `my_key`
/// method (`KeyMode::PqHybrid`) - this app's one peer-to-peer scheme. Kept
/// as its own module since it shares no key material with the RSA-only
/// code below, which now serves only the server auth challenge and its own
/// classical hedge - see its module doc for the full design, and
/// `docs/PROTOCOL.md` §13.
pub mod otp;
pub mod pq;
pub mod safety;

use rand_core::{OsRng, RngCore};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// RSA modulus size used for every keypair this app generates, except
/// `pq_hybrid`'s RSA-4096 hedge (see `RSA_PER_MSG_KEY_BITS`).
pub const RSA_KEY_BITS: usize = 2048;

/// RSA modulus size for `pq_hybrid`'s classical RSA hedge
/// (`crypto::pq::PQ_RSA_BITS`) - larger than `RSA_KEY_BITS` for a stronger
/// margin on the identity that backs every signature and rotation for the
/// life of the keybundle.
pub const RSA_PER_MSG_KEY_BITS: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key error: {0}")]
    Key(String),
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// An RSA keypair. Used to prove identity to the server (`server_key`'s
/// `rsa` type, §5.3) and as the classical hedge inside a `pq_hybrid`
/// keybundle (`crypto::pq`); peer-to-peer content is never encrypted to
/// one directly.
pub struct KeyPair {
    pub private: RsaPrivateKey,
    pub public: RsaPublicKey,
}

impl KeyPair {
    /// Generates a fresh keypair from OS randomness, at `RSA_KEY_BITS`.
    pub fn generate() -> Result<Self> {
        Self::generate_with_bits(RSA_KEY_BITS)
    }

    /// Generates a fresh keypair from OS randomness at a specific modulus
    /// size - used for `pq_hybrid`'s `RSA_PER_MSG_KEY_BITS` hedge.
    pub fn generate_with_bits(bits: usize) -> Result<Self> {
        let mut rng = OsRng;
        let private =
            RsaPrivateKey::new(&mut rng, bits).map_err(|e| CryptoError::Key(e.to_string()))?;
        let public = private.to_public_key();
        Ok(Self { private, public })
    }

    /// Loads a keypair from a PEM-encoded private key file (`file_priv`)
    /// and a PEM-encoded public key file (`file_pub`), as selected in the
    /// connect popup's `my_key` fields.
    pub fn load_from_files(priv_path: &Path, pub_path: &Path) -> Result<Self> {
        let private = load_private_key(priv_path)?;
        let public = load_public_key(pub_path)?;
        Ok(Self { private, public })
    }

    /// Persists this keypair as two PEM files, for first-run key generation.
    pub fn save_to_files(&self, priv_path: &Path, pub_path: &Path) -> Result<()> {
        save_private_key(&self.private, priv_path)?;
        save_public_key(&self.public, pub_path)?;
        Ok(())
    }
}

pub fn load_private_key(path: &Path) -> Result<RsaPrivateKey> {
    let pem = fs::read_to_string(path)?;
    RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| CryptoError::Key(e.to_string()))
}

pub fn load_public_key(path: &Path) -> Result<RsaPublicKey> {
    let pem = fs::read_to_string(path)?;
    RsaPublicKey::from_public_key_pem(&pem).map_err(|e| CryptoError::Key(e.to_string()))
}

pub fn save_private_key(key: &RsaPrivateKey, path: &Path) -> Result<()> {
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| CryptoError::Key(e.to_string()))?;
    fs::write(path, pem.as_bytes())?;
    Ok(())
}

pub fn save_public_key(key: &RsaPublicKey, path: &Path) -> Result<()> {
    let pem = key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| CryptoError::Key(e.to_string()))?;
    fs::write(path, pem)?;
    Ok(())
}

/// Serializes a public key to DER bytes, for embedding in protocol
/// messages (e.g. announcing your public key when joining a channel).
pub fn public_key_to_der(key: &RsaPublicKey) -> Result<Vec<u8>> {
    let doc = key
        .to_public_key_der()
        .map_err(|e| CryptoError::Key(e.to_string()))?;
    Ok(doc.as_bytes().to_vec())
}

pub fn public_key_from_der(bytes: &[u8]) -> Result<RsaPublicKey> {
    RsaPublicKey::from_public_key_der(bytes).map_err(|e| CryptoError::Key(e.to_string()))
}

/// Serializes a private key to PKCS8 DER bytes - used by `crypto::pq` to
/// embed its RSA-4096 signing key inside a `PqPrivateBundle`, the same way
/// `public_key_to_der` already does for public keys embedded in wire
/// messages.
pub fn private_key_to_der(key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let doc = key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::Key(e.to_string()))?;
    Ok(doc.as_bytes().to_vec())
}

pub fn private_key_from_der(bytes: &[u8]) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_der(bytes).map_err(|e| CryptoError::Key(e.to_string()))
}

/// A short, stable identifier for a public key, used to recognize the same
/// peer across reconnects without comparing full DER blobs.
pub fn fingerprint(key: &RsaPublicKey) -> Result<String> {
    let der = public_key_to_der(key)?;
    Ok(fingerprint_der(&der))
}

/// Same as `fingerprint`, but hashes raw DER bytes directly - infallible,
/// since the bytes never need to be a valid key. Used for display on key
/// material that might not parse (e.g. a hand-edited pinned store entry)
/// where `fingerprint`'s `Result` would force a caller to decide what to
/// show on `Err`.
pub fn fingerprint_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    hex_encode(&digest)
}

/// How many hex characters of a fingerprint are enough to tell two
/// specific keys apart at a glance - 16, i.e. the first 8 bytes. Short
/// enough not to wrap across a popup, still far beyond what anyone could
/// collide against a key already pinned.
pub const SHORT_FINGERPRINT_HEX: usize = 16;

/// `fingerprint_der`, cut to `SHORT_FINGERPRINT_HEX`. The form every
/// user-facing surface shows a key in (`session`'s identity-mismatch
/// warning, the message details popup) - a full SHA-256 is for comparing
/// bytes, not for reading.
pub fn short_fingerprint_der(der: &[u8]) -> String {
    let mut fp = fingerprint_der(der);
    fp.truncate(SHORT_FINGERPRINT_HEX);
    fp
}

/// The maximum plaintext length, in bytes, that fits in a single OAEP/SHA-256
/// RSA block for the given key. Longer payloads must be split into several
/// blocks, each encrypted independently.
pub fn max_chunk_len(key: &RsaPublicKey) -> usize {
    let modulus_bytes = key.size();
    let hash_len = Sha256::output_size();
    modulus_bytes.saturating_sub(2 * hash_len + 2)
}

/// Encrypts `data` for `key`, splitting it into as many OAEP blocks as
/// needed. Every block is encrypted separately for this one recipient; to
/// address multiple recipients this must be called once per recipient's
/// public key (see `SPEC.md`: no shared/hybrid session key is used).
pub fn encrypt_chunked(key: &RsaPublicKey, data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let chunk_size = max_chunk_len(key);
    if chunk_size == 0 {
        return Err(CryptoError::Encrypt(
            "key too small for OAEP/SHA-256".into(),
        ));
    }
    let mut rng = OsRng;
    let mut blocks = Vec::new();
    if data.is_empty() {
        let ct = key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), &[])
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        blocks.push(ct);
        return Ok(blocks);
    }
    for chunk in data.chunks(chunk_size) {
        let ct = key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), chunk)
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
        blocks.push(ct);
    }
    Ok(blocks)
}

/// Decrypts and concatenates blocks produced by `encrypt_chunked`.
pub fn decrypt_chunked(key: &RsaPrivateKey, blocks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for block in blocks {
        let pt = key
            .decrypt(Oaep::new::<Sha256>(), block)
            .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
        out.extend_from_slice(&pt);
    }
    Ok(out)
}

/// Signs `data` with `key` using RSA-PSS + SHA-256, with a random salt.
///
/// Used by the server to sign its control-channel offer (`control::make_offer`,
/// §5.3 server auth), and by `crypto::pq` for the classical half of a
/// `pq_hybrid` send commitment (`crypto::pq::seal_setup`) and its other
/// signed constructions. PSS rather than PKCS#1 v1.5 because it is the
/// modern scheme with a security proof behind it; v1.5 is kept alive
/// elsewhere in the world only for compatibility this app has no reason to
/// want (`docs/PROTOCOL.md`: no backwards compatibility).
///
/// Randomised, so signing the same bytes twice gives different signatures -
/// nothing here ever compares two signatures for equality, only verifies
/// them.
pub fn sign(key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    let digest = Sha256::digest(data);
    key.sign_with_rng(&mut OsRng, Pss::new::<Sha256>(), &digest)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))
}

/// Verifies a signature produced by `sign`. Returns `false` (never an
/// `Err`) on any mismatch - callers only ever care whether the new key is
/// trustworthy, not why verification failed.
pub fn verify(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    let digest = Sha256::digest(data);
    key.verify(Pss::new::<Sha256>(), &digest, signature).is_ok()
}

/// Generates `len` cryptographically random bytes, used for auth challenge
/// nonces.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Constant-time byte comparison, used to check a `server_key` password
/// against the server's configured password without leaking timing
/// information about where they first differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Lowercase-hex encoding, shared by fingerprints and the flat-file store
/// `idstore`, which persists key material one hex-encoded line per entry.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decodes a lowercase-hex string back to bytes; `None` on any malformed
/// input (odd length, non-hex character) rather than panicking, so a
/// corrupted line in a hand-edited store is simply dropped by its loader
/// instead of taking down the whole store.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push((hi as u8) << 4 | lo as u8);
    }
    Some(out)
}
