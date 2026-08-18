//! Pure protocol glue for the one-time-pad layer that wraps a `pq_hybrid`
//! send (`client::otp`, `client::otp_cli`, `client::otp_store`). No I/O and
//! no subprocess spawning here - see `client::otp_cli` for the actual `otp`
//! CLI invocations this module's types are carried by.
//!
//! aloo never reimplements one-time-pad cryptography or keychain formats:
//! every byte of pad material is generated, stored, consumed and destroyed
//! exclusively by the real `otp` command (github.com/DavidValin/otp-toolkit). This
//! module only shapes the setup messages two peers exchange - over their
//! already-established `pq_hybrid` channel - to hand `otp --add-contact`
//! its key files on each side.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::hex_encode;

/// How much of each 32-byte fingerprint goes into the contact name. Full
/// fingerprints (64 hex chars each) combine with the `otp` CLI's own
/// `_a`/`_b` role suffixes and `_keys/encryption_for_<other>.key` naming to
/// exceed the real binary's internal path-length limit ("key file path too
/// long", verified directly against the installed binary) - 12 bytes (24
/// hex chars) per half keeps every derived path comfortably under it while
/// remaining collision-resistant enough for a local keychain label (the
/// actual cryptographic binding is the full 32-byte fingerprint inside
/// `crypto::pq::SendBinding`, never this name).
const CONTACT_NAME_FP_BYTES: usize = 12;

/// The `/otp` size-input popup's allowed range, in MB *per key* - a fresh
/// pad is always two independent keys this size (`OtpKeySetupPayload`'s
/// doc), so the actual randomness generated and eventually transferred is
/// double whatever's chosen here. The floor keeps a pad large enough to be
/// worth generating and provisioning at all; the ceiling is a sanity bound
/// against a typo, not a cryptographic limit - `otp --new-key-pair` reads
/// that many megabytes of true randomness synchronously before anything
/// else can happen, and the chunked transfer (`OtpKeySetupChunk`) scales
/// linearly with it.
pub const OTP_SIZE_MB_MIN: u32 = 1;
pub const OTP_SIZE_MB_MAX: u32 = 900_000;

/// Whether `size_mb` falls within `OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX` -
/// shared by the size-input popup's own validation and
/// `client::otp::confirm_generate`'s defensive re-check before it ever
/// spends a real subprocess call on the value.
pub fn otp_size_mb_in_range(size_mb: u32) -> bool {
    (OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX).contains(&size_mb)
}

/// Deterministic, order-independent `otp` keychain contact name for a pair
/// of `pq_hybrid` identities: a truncated prefix of their fingerprints,
/// sorted, hex-joined with a separator the `otp` CLI's naming rules allow
/// (no `.`/`..`, no path separators, none of `: * ? " < > | =`, no control
/// characters - a plain `-` between two lowercase-hex halves satisfies all
/// of that). Computed independently and identically by both sides from
/// their own and their peer's fingerprint, so provisioning needs no
/// separate name-negotiation step.
pub fn contact_name_for(own_fp: &[u8; 32], peer_fp: &[u8; 32]) -> String {
    let (a, b) = if own_fp <= peer_fp {
        (own_fp, peer_fp)
    } else {
        (peer_fp, own_fp)
    };
    format!(
        "{}-{}",
        hex_encode(&a[..CONTACT_NAME_FP_BYTES]),
        hex_encode(&b[..CONTACT_NAME_FP_BYTES])
    )
}

/// One peer's half of a freshly generated one-time-pad keypair, sent to the
/// other side over an ordinary `pq_hybrid`-encrypted envelope
/// (`Content::OtpKeySetup`) so it can run `otp --add-contact` locally. The
/// byte contents are the actual pad material - the one-time secret itself,
/// with no computational-hardness fallback if leaked - so this is zeroized
/// on drop the moment it goes out of scope (after being sent, or after
/// being consumed into the receiving side's own `otp --add-contact` call).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtpKeySetupPayload {
    #[zeroize(skip)]
    pub contact_name: String,
    #[zeroize(skip)]
    pub keypair_size_mb: u32,
    /// The role-inverted half generated for the *peer*: bytes that must be
    /// byte-identical to what the peer's own `otp --new-key-pair` run would
    /// have produced as their `decryption_from_<us>.key`. See
    /// `client::otp::initiate_provisioning`'s doc for the exact generation
    /// sequence this respects.
    pub peer_encryption_key: Vec<u8>,
    pub peer_decryption_key: Vec<u8>,
}

/// One fragment of an `OtpKeySetupPayload` in transit
/// (`Content::OtpKeySetup`, `client::otp::confirm_generate`'s send loop /
/// `client::otp::on_key_setup`'s reassembly). A whole pad - the default is
/// 1MB *per key*, 2MB total - cannot be sent as a single `pq_hybrid`
/// envelope: it rides one UDP datagram with no fragmentation/reassembly of
/// its own below this layer, and a payload that large simply cannot fit
/// (the OS refuses the send outright once past ~65KB, well under even one
/// key's raw size). Splitting into many small, ordinary `pq_hybrid` sends -
/// exactly like a stream of chunks - is what lets a whole pad be delivered
/// reliably at all. `offset`/`total_len` describe one key's position (both
/// `enc_chunk` and `dec_chunk` always share the same offset/length, since
/// the two keys are generated the same size).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtpKeySetupChunk {
    #[zeroize(skip)]
    pub contact_name: String,
    #[zeroize(skip)]
    pub keypair_size_mb: u32,
    #[zeroize(skip)]
    pub total_len: u32,
    #[zeroize(skip)]
    pub offset: u32,
    pub enc_chunk: Vec<u8>,
    pub dec_chunk: Vec<u8>,
}

/// Accumulates `OtpKeySetupChunk`s from one sender into the full pad
/// they're reassembling to - the receiving-side counterpart of the sending
/// loop that produces `OtpKeySetupChunk`s in the first place (see its
/// doc). Holds raw pad bytes while incomplete, so - like every other place
/// this app holds pad material in memory - it's zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OtpKeySetupReassembly {
    #[zeroize(skip)]
    contact_name: String,
    #[zeroize(skip)]
    total_len: u32,
    enc: Vec<u8>,
    dec: Vec<u8>,
}

impl OtpKeySetupReassembly {
    pub fn new(chunk: &OtpKeySetupChunk) -> Self {
        Self {
            contact_name: chunk.contact_name.clone(),
            total_len: chunk.total_len,
            enc: Vec::with_capacity(chunk.total_len as usize),
            dec: Vec::with_capacity(chunk.total_len as usize),
        }
    }

    /// Appends one chunk if it actually continues this accumulation - same
    /// `contact_name`/`total_len` as the chunks accepted so far, and
    /// picking up exactly where the last one left off. Returns `false`
    /// (appending nothing) for a chunk that belongs to a different,
    /// unrelated setup attempt from the same sender - the caller is then
    /// expected to start a fresh `OtpKeySetupReassembly` from that chunk
    /// rather than ever reassembling mismatched bytes into one payload.
    pub fn accept(&mut self, chunk: &OtpKeySetupChunk) -> bool {
        if self.contact_name != chunk.contact_name
            || self.total_len != chunk.total_len
            || chunk.offset as usize != self.enc.len()
        {
            return false;
        }
        self.enc.extend_from_slice(&chunk.enc_chunk);
        self.dec.extend_from_slice(&chunk.dec_chunk);
        true
    }

    pub fn is_complete(&self) -> bool {
        self.enc.len() as u32 >= self.total_len && self.dec.len() as u32 >= self.total_len
    }

    /// Takes the accumulated bytes out, leaving this reassembly empty (and
    /// so trivially zeroized when it's dropped right after).
    pub fn take_keys(&mut self) -> (Vec<u8>, Vec<u8>) {
        (std::mem::take(&mut self.enc), std::mem::take(&mut self.dec))
    }
}

/// Proposes starting an OTP session using a keychain contact that (the
/// sender believes) already exists on both sides - the "already have a
/// key" branch of the `/otp` command, carrying no key material at all.
/// Like `OtpKeySetupPayload`, this still requires the receiving side to
/// explicitly accept before anything is considered active - see
/// `client::otp`'s module doc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpSessionRequestPayload {
    pub contact_name: String,
}

/// Reply to either `OtpKeySetupPayload` or `OtpSessionRequestPayload`,
/// reporting the receiving user's explicit accept/reject decision and (on
/// accept) the outcome of applying it (`otp --add-contact`, or a
/// same-contact sanity check for a session request). Carries no key
/// material, so it isn't zeroized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpKeySetupAckPayload {
    pub contact_name: String,
    pub accepted: bool,
    pub reason: Option<String>,
}
