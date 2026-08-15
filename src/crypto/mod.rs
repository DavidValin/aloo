use std::fs;
use std::path::Path;

/// ML-DSA-87+RSA4096 / ML-KEM-1024+RSA4096 / AES-256-GCM hybrid `my_key` method
/// (`KeyMode::PqHybrid`). Kept as its own module since it shares no key
/// material or primitives with the RSA-only code below - see its module doc
/// for the full design, and `docs/PROTOCOL.md` §13.
pub mod pq;

use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

/// RSA modulus size used for every keypair this app generates, except
/// `rsa_per_msg` (see `RSA_PER_MSG_KEY_BITS`).
pub const RSA_KEY_BITS: usize = 2048;

/// RSA modulus size for `rsa_per_msg` (`KeyMode::PerMessage`) keypairs -
/// both the bootstrap keypair announced in `Identify` and every key
/// `rekey::OwnKeys::rotate_for_peer` generates afterward. Larger than
/// `RSA_KEY_BITS` since these keys are short-lived by design (PROTOCOL.md
/// §11) and the whole point of the mode is a stronger security margin per
/// key; the tradeoff is slower keygen on every rotation (already the
/// documented reason live voice is exempted from per-chunk rotation, see
/// §11.6 - that cost only gets more pronounced at 4096 bits).
pub const RSA_PER_MSG_KEY_BITS: usize = 4096;

/// Rounds used to stretch a `my_key` password into the seed for a
/// deterministic keypair (`KeyPair::from_password`) - the only thing this
/// app runs PBKDF2 over. A `server_key` password is *not* hashed: it is
/// sent as-is in `proto::AuthResponse::Password` and compared byte-for-byte
/// (in constant time) against the server's configured password by
/// `server::AuthConfig::verify`.
const PBKDF2_ROUNDS: u32 = 100_000;

/// Fixed domain-separation salt for deterministic key derivation from a
/// password. It is intentionally not random: the whole point of
/// `KeyPair::from_password` is that the same password always reproduces
/// the same keypair, so the user can "log in" from any machine without
/// carrying a key file around.
const PASSWORD_KEY_SALT: &[u8] = b"aloo-app/my-key-derivation/v1";

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

/// An RSA keypair used both to prove identity to the server (`server_key`)
/// and to receive/decrypt messages from other users (`my_key`).
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
    /// size - used for `rsa_per_msg`'s `RSA_PER_MSG_KEY_BITS`.
    pub fn generate_with_bits(bits: usize) -> Result<Self> {
        let mut rng = OsRng;
        let private =
            RsaPrivateKey::new(&mut rng, bits).map_err(|e| CryptoError::Key(e.to_string()))?;
        let public = private.to_public_key();
        Ok(Self { private, public })
    }

    /// Deterministically derives a keypair from a password: the same
    /// password always yields the same keypair, different passwords yield
    /// different (for all practical purposes, unrelated) keypairs.
    pub fn from_password(password: &str) -> Result<Self> {
        let mut seed = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            PASSWORD_KEY_SALT,
            PBKDF2_ROUNDS,
            &mut seed,
        );
        let mut rng = ChaCha20Rng::from_seed(seed);
        let private = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
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

/// Serializes a private key to PKCS8 DER bytes - used by `own_next_keys` to
/// persist a per-peer `rsa_per_msg` continuity private key as a single
/// hex-encoded line (a PEM's multiple lines/headers don't fit that
/// one-line-per-entry file format), the same way `public_key_to_der`
/// already does for public keys embedded in wire messages.
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

/// Same as `fingerprint`, but hashes raw DER bytes directly rather than a
/// parsed `RsaPublicKey` - infallible, since it never needs the bytes to
/// actually be a valid key. Used for display purposes on key material that
/// might not parse (e.g. `idstore::IdStore` showing a fingerprint for
/// whatever bytes were pinned, even from a hand-edited or corrupted store
/// entry) where `fingerprint`'s `Result` would otherwise force a caller to
/// decide what to show on `Err`.
pub fn fingerprint_der(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    hex_encode(&digest)
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

/// Signs `data` with `key` using RSA PKCS#1 v1.5 + SHA-256 - deterministic
/// (no RNG involved), used to authenticate a freshly-rotated `rsa_per_msg`
/// public key (`rekey::rotate_for_peer`) with the private key it replaces.
pub fn sign(key: &RsaPrivateKey, data: &[u8]) -> Result<Vec<u8>> {
    let digest = Sha256::digest(data);
    key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))
}

/// Verifies a signature produced by `sign`. Returns `false` (never an
/// `Err`) on any mismatch - callers only ever care whether the new key is
/// trustworthy, not why verification failed.
pub fn verify(key: &RsaPublicKey, data: &[u8], signature: &[u8]) -> bool {
    let digest = Sha256::digest(data);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
        .is_ok()
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
