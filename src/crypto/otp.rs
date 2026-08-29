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
/// worth generating and provisioning at all; the ceiling matches the real
/// `otp` binary's own documented streaming limit - "supports keys up to
/// 1TB through streaming architecture" (README.md "Keychain Features") -
/// rather than being an arbitrary, much smaller sanity bound: generation
/// (`otp_cli::new_key_pair`) streams the randomness in fixed-size chunks
/// instead of buffering it whole, and the chunked P2P transfer
/// (`OtpKeySetupChunk`, paced by `client::p2p_reliable::SEND_WINDOW`
/// rather than handed to the link all at once) scales to it the same way.
pub const OTP_SIZE_MB_MIN: u32 = 1;
/// 1 TiB, in MB per key - `1024 * 1024`.
pub const OTP_SIZE_MB_MAX: u32 = 1_048_576;

/// Whether `size_mb` falls within `OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX` -
/// shared by the size-input popup's own validation and
/// `client::otp::confirm_generate`'s defensive re-check before it ever
/// spends a real subprocess call on the value.
pub fn otp_size_mb_in_range(size_mb: u32) -> bool {
    (OTP_SIZE_MB_MIN..=OTP_SIZE_MB_MAX).contains(&size_mb)
}

/// How many random bytes ride inside every OTP message purely so its
/// acknowledgement can be bound to it. 16 bytes is far past any feasible
/// guess, and the cost is fixed per message rather than proportional to it.
pub const ACK_NONCE_BYTES: usize = 16;

/// The proof a receiver returns to show it genuinely decrypted a specific
/// message: `sha256` of that message's nonce.
///
/// Sent in the clear, and safe to be: an attacker holding only the
/// ciphertext cannot learn the nonce without the pad, so cannot produce
/// this. The *nonce itself* is never echoed - that would hand an observer
/// 16 bytes of known plaintext against known ciphertext, which is 16 bytes
/// of recovered pad.
///
/// Costing the receiver nothing is the point. An acknowledgement that
/// spent pad would itself be a message needing acknowledgement, and the
/// chain would never terminate; and a receiver who had to spend key to let
/// the sender continue would force strict turn-taking on every
/// conversation.
pub type AckProof = [u8; 32];

/// The proof for `nonce` - computed by the receiver from what it
/// decrypted, and by the sender from what it generated, with no other way
/// to arrive at it.
pub fn ack_proof_for(nonce: &[u8]) -> AckProof {
    use sha2::{Digest, Sha256};
    Sha256::digest(nonce).into()
}

/// A SHA-256 digest of one key half, used to prove both sides ended up
/// holding byte-identical pad material before either installs it.
///
/// A one-time pad has no integrity check of its own - that is the whole
/// point of the cipher, and it is why a mismatched pair is so dangerous:
/// two keys that differ by a single byte produce plausible-looking
/// ciphertext that decodes to silent garbage, with no error anywhere to
/// say so. Comparing digests before installing is what turns that into a
/// refusal instead. It is not a secrecy measure (the digest reveals
/// nothing usable about a pad this size) but an agreement one.
pub type KeyDigest = [u8; 32];

/// Digests a key file without ever holding it in memory - pads reach 1TB
/// (`OTP_SIZE_MB_MAX`), so this streams a fixed-size buffer rather than
/// reading the file.
pub fn digest_key_file(path: &std::path::Path) -> std::io::Result<KeyDigest> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let read = std::io::Read::read(&mut file, &mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hasher.finalize().into())
}

/// The proof for a pad spend whose plaintext is a whole file rather than
/// a blob aloo composed - a file transfer's content phase, or a voice
/// message's PCM.
///
/// Those two carry the user's bytes verbatim, so there is nowhere to bury
/// a nonce without corrupting what lands on the receiver's disk. The
/// plaintext's own digest stands in, and it proves exactly the same thing:
/// only a party that actually decrypted this message can name it. The
/// ciphertext alone yields nothing without the pad.
///
/// Unlike `ack_proof_for` it isn't fresh per send - the same file sent
/// twice proves the same value. That costs nothing here, because a proof
/// is only ever checked against the *one* sequence number currently
/// pending for the contact (`OtpStore::record_acked`), so a replayed proof
/// has no second gate left to open.
pub fn ack_proof_for_file(path: &std::path::Path) -> std::io::Result<AckProof> {
    digest_key_file(path)
}

/// One value naming the *pair* of halves a pad is - `sha256` of the two
/// half digests, in order.
///
/// What it is for: telling a re-delivery of the pad already installed
/// apart from a genuinely new one offered for the same contact. Those two
/// look identical at the `provisioned` flag, and treating the second as
/// the first is how the two sides end up holding *different* pads under
/// one name - the silent-garbage case the whole two-phase commit exists to
/// prevent.
pub fn pad_pair_digest(enc: &KeyDigest, dec: &KeyDigest) -> KeyDigest {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(enc);
    hasher.update(dec);
    hasher.finalize().into()
}

/// The `otp` keychain contact name for a pair with no `pq_hybrid`
/// identities, derived from the two **pinned public keys** rather than
/// from nicknames.
///
/// Deriving it from the keys is what makes the pad safe to spend. A
/// nickname proves nothing - it is trust-on-first-use and freed the moment
/// its holder disconnects (`docs/PROTOCOL.md` §5.4/§11.2), so anyone may
/// take a familiar one. Had the name been the nickname, an impersonator
/// could have caused this side to encrypt to *the real contact's pad*:
/// unreadable to them, but irreversibly spent, leaving the genuine
/// correspondent's offsets desynchronised and the pad useless. Keyed off
/// the pinned key instead, an impersonator simply derives a different
/// contact name, finds no pad under it, and gets nothing spent on them.
///
/// Same sorted, order-independent construction `contact_name_for` uses, so
/// both sides compute the identical name from their own and their peer's
/// key with nothing negotiated. Used under `Direct` framing
/// (`client::otp::OtpFraming`), where one side's announced key does not
/// decode as a keybundle and so has no fingerprint to name a contact by.
///
/// Not device-qualified, unlike `contact_name_for` - and deliberately so.
/// A pad has no safe multi-device story either way; the two framings just
/// enforce it in different places. A `PqWrapped` pair puts the device in
/// the *name* (§4), because its device data arrives over the separate
/// `DeviceIdAnnounce`. A `Direct` pair has no such channel - a
/// `PunchDatagram` carries no device id, and adding one would be a wire
/// format change - so it binds the device on the *contact* instead
/// (`OtpContactState::bound_peer_device_id`, §5): the first message that
/// genuinely decrypts fixes which device this pad belongs to, and any
/// later one claiming a different device is refused before `otp --decrypt`
/// runs. Naming by keys alone is therefore safe here, and keeps the name
/// derivable from what both sides already hold with nothing configured.
pub fn contact_name_for_keys(own_public_der: &[u8], peer_public_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let own: [u8; 32] = Sha256::digest(own_public_der).into();
    let peer: [u8; 32] = Sha256::digest(peer_public_der).into();
    sorted_truncated_join(own, peer)
}

/// `contact_name_for_keys`'s counterpart for OTP mail - see
/// `contact_name_for_mail`'s doc for why the two must never share a name.
pub fn contact_name_for_keys_mail(own_public_der: &[u8], peer_public_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let own: [u8; 32] = Sha256::digest(own_public_der).into();
    let peer: [u8; 32] = Sha256::digest(peer_public_der).into();
    format!("mail-{}", sorted_truncated_join(own, peer))
}

/// Which independent OTP key a provisioning handshake or a piece of UI text
/// is about - a live `/otp` session (used for messages while both people
/// are online) or a mail-only key (`/new-otp-mail-key`, spent by OTP mail
/// alone). The two are never the same pad; this only ever labels which one,
/// it never changes any cryptography.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpPurpose {
    Live,
    Mail,
}

impl OtpPurpose {
    /// What to call it in a popup title or status line.
    pub fn label(self) -> &'static str {
        match self {
            OtpPurpose::Live => "OTP session",
            OtpPurpose::Mail => "OTP mail key",
        }
    }

    /// Recovers which purpose a contact name belongs to from the name
    /// itself - every mail name is `contact_name_for_mail`'s `mail-`
    /// prefixed form, every live name is not, so this never has to be
    /// guessed or threaded through code that already carries the name.
    pub fn of_contact_name(name: &str) -> Self {
        if name.starts_with("mail-") {
            OtpPurpose::Mail
        } else {
            OtpPurpose::Live
        }
    }
}

/// One side's `(identity fingerprint, device_id)` pair, folded into a
/// single 32-byte value so `contact_name_for`'s sort/truncate/join stays
/// exactly the shape and length it was before device_id joined the
/// equation - `CONTACT_NAME_FP_BYTES`' own doc explains why that length
/// bound is load-bearing (the real `otp` binary's path-length limit), and
/// two independently truncated halves (fingerprint *and* device_id) would
/// have doubled it. Order-independent per side (nothing here depends on
/// which of the two peers is "own"), so both machines still compute this
/// identically with nothing negotiated.
fn device_pair_id(fp: &[u8; 32], device_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(fp);
    hasher.update(device_id.as_bytes());
    hasher.finalize().into()
}

/// Sorts two 32-byte values and hex-joins truncated prefixes of each with
/// a separator the `otp` CLI's naming rules allow (no `.`/`..`, no path
/// separators, none of `: * ? " < > | =`, no control characters - a plain
/// `-` between two lowercase-hex halves satisfies all of that). The one
/// piece `contact_name_for` (device-qualified, `pq_hybrid`) and
/// `contact_name_for_keys` (unqualified, `Direct`/pad-only - the
/// device-pinning plan §5's "pad naming stays unqualified") share: both
/// need an order-independent name computed identically by both sides with
/// nothing negotiated, they just start from different 32-byte inputs.
fn sorted_truncated_join(a: [u8; 32], b: [u8; 32]) -> String {
    let (a, b) = if a <= b { (a, b) } else { (b, a) };
    format!(
        "{}-{}",
        hex_encode(&a[..CONTACT_NAME_FP_BYTES]),
        hex_encode(&b[..CONTACT_NAME_FP_BYTES])
    )
}

/// Deterministic, order-independent `otp` keychain contact name for one
/// *device* of a `pq_hybrid` identity talking to one device of another.
/// Computed independently and identically by both sides from their own
/// and their peer's `(fingerprint, device_id)`, so provisioning needs no
/// separate name-negotiation step - both device_ids are already known
/// (via `DeviceIdAnnounce`) before any `/otp` handshake can start.
///
/// Device-qualified so that two of *either* side's devices never share a
/// pad: a pad is provisioned by one specific machine talking to one
/// specific machine, and this is what gives each such pairing its own
/// independent keychain slot rather than colliding on whichever device
/// happened to provision first (docs/PROTOCOL.md §16, the device-pinning
/// plan §4).
pub fn contact_name_for(own_fp: &[u8; 32], own_device_id: &str, peer_fp: &[u8; 32], peer_device_id: &str) -> String {
    sorted_truncated_join(
        device_pair_id(own_fp, own_device_id),
        device_pair_id(peer_fp, peer_device_id),
    )
}

/// OTP *mail*'s own keychain contact name for the same device pair -
/// deliberately distinct from `contact_name_for`'s (a live name is always
/// lowercase hex plus `-`, so this `mail-` prefix can never collide with
/// one) so a mail key is never the same pad a live `/otp` session would
/// spend. Wraps `contact_name_for` rather than reimplementing the
/// sort/truncate, so it inherits the same order-independence with no
/// separate proof needed.
pub fn contact_name_for_mail(own_fp: &[u8; 32], own_device_id: &str, peer_fp: &[u8; 32], peer_device_id: &str) -> String {
    format!("mail-{}", contact_name_for(own_fp, own_device_id, peer_fp, peer_device_id))
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
    /// `Some(mb per key)` when this asks to generate and share a *fresh*
    /// pad, `None` when it asks to resume one both sides already hold.
    ///
    /// The size is here rather than in the pad's own arrival because it is
    /// the only thing the deciding side actually has to weigh, and by the
    /// time a pad arrives the cost it represents - minutes of transfer and
    /// several gigabytes of disk on both machines - has already been paid.
    /// Asking then is asking too late to matter.
    pub pad_size_mb: Option<u32>,
}

/// Carried by both `Content::OtpEndSession` (either participant's `/endotp`
/// unilaterally ending the session) and `Content::OtpEndSessionAck` (its
/// reply) - one shape for both, since the ack has nothing to report beyond
/// "received" (ending is never refused the way a proposal can be). Carries
/// no key material, so it isn't zeroized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpEndSessionPayload {
    pub contact_name: String,
}

// ---------------------------------------------------------------------
// OTP mail (docs/PROTOCOL.md section 17)
// ---------------------------------------------------------------------

/// Hard cap on one OTP mail's *plaintext* payload (the bincode-encoded
/// `OtpMailPayload`, attachments included). Well under `proto::MAX_FRAME_LEN`
/// so the ciphertext - the same length plus the `otp` CLI's small framing -
/// always fits one control-channel frame with room to spare, and small
/// enough that buffering a whole mail in memory on either end stays
/// reasonable. The *effective* limit is almost always the contact's
/// remaining pad, which the compose view enforces live - this constant only
/// backstops it.
pub const OTP_MAIL_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Slack allowed on top of `OTP_MAIL_MAX_BYTES` for the ciphertext the
/// server sees: the `otp` CLI's output is the plaintext's length plus a
/// small fixed framing overhead, never a blowup, so one spare MB is
/// generous. The server can't see the plaintext to measure it directly -
/// this is the bound it enforces instead.
pub const OTP_MAIL_MAX_CIPHERTEXT_BYTES: usize = OTP_MAIL_MAX_BYTES + 1024 * 1024;

/// A mail id is exactly this many lowercase hex characters (16 random
/// bytes) - see `new_mail_id`/`mail_id_is_valid`.
pub const OTP_MAIL_ID_LEN: usize = 32;

/// A fresh, sender-generated mail id: 16 random bytes, hex-encoded.
/// Generated by the sender (not assigned by the server) so a retried
/// `OtpMailSend` after a lost acknowledgement carries the *same* id and the
/// server can deduplicate instead of storing the mail twice.
pub fn new_mail_id() -> String {
    hex_encode(&crate::crypto::random_bytes(OTP_MAIL_ID_LEN / 2))
}

/// Whether `id` is exactly `OTP_MAIL_ID_LEN` lowercase hex characters.
/// The server uses a mail id as an on-disk filename, so this is validated
/// strictly on both sides before any path is ever built from one - a
/// well-formed id cannot name a path separator, `.`/`..`, or anything else
/// with filesystem meaning.
pub fn mail_id_is_valid(id: &str) -> bool {
    id.len() == OTP_MAIL_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// One voice recording attached to an OTP mail: the complete, decoded
/// PCM16 bytes (`voice::pcm_to_bytes`' output, same shape a finished
/// `MessageBody::Voice` already holds in memory), ready to replay through
/// the existing mixer once the mail is read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtpMailVoice {
    #[zeroize(skip)]
    pub duration_ms: u32,
    pub pcm: Vec<u8>,
}

/// One file attached to an OTP mail - unlike a live P2P transfer (streamed,
/// never buffered whole), a mail attachment is carried inside the mail's
/// single encrypted blob, so its bytes are read whole at send time. The
/// contact's remaining pad (plus `OTP_MAIL_MAX_BYTES`) bounds how large
/// that can ever get.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtpMailFile {
    #[zeroize(skip)]
    pub filename: String,
    pub bytes: Vec<u8>,
}

/// One complete OTP mail, as encrypted end to end: this whole struct,
/// bincode-encoded, is what passes through `otp --encrypt` and travels to
/// the server as an opaque blob (docs/PROTOCOL.md section 17). The server
/// stores and routes it by the *wire* metadata alongside it
/// (`ClientMessage::OtpMailSend`), never by anything in here - `from`/`to`
/// are repeated inside precisely so the receiver can check, after
/// decrypting, that the sealed addressing matches what the server claimed.
/// Zeroized on drop: between decrypt and re-pad this is the only plaintext
/// copy of a mail's content in existence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtpMailPayload {
    #[zeroize(skip)]
    pub from: String,
    #[zeroize(skip)]
    pub to: String,
    /// Unix seconds, UTC - set at the moment the sender confirmed the send.
    #[zeroize(skip)]
    pub sent_at_utc: u64,
    pub subtext: String,
    pub content: String,
    pub voices: Vec<OtpMailVoice>,
    pub attachments: Vec<OtpMailFile>,
}

/// What actually passes through `otp --encrypt` for a mail: the encoded
/// `OtpMailPayload` plus the sender's identity signature over it
/// (`crypto::pq::sign_mail`). A one-time pad is perfectly confidential but
/// authenticates nothing - it's malleable - so the payload carries its own
/// signature, verified by the receiver against the **pinned** bundle for
/// the claimed sender before any field is believed. Zeroized on drop:
/// `payload` is the mail's plaintext.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OtpMailSealed {
    pub payload: Vec<u8>,
    #[zeroize(skip)]
    pub signature: Vec<u8>,
}

/// XORs `data` against an equally-long `pad` - the actual one-time-pad
/// primitive, used only for the *local re-pad* of an already-received mail
/// (never for anything on the wire, which is always the real `otp` CLI's
/// job): a received mail is decrypted through `otp --decrypt` exactly once
/// (consuming keychain pad, exactly like any other OTP receive), then
/// immediately re-encrypted under a locally-generated random pad and stored
/// as that (ciphertext, pad) file pair. Reading the mail later XORs the two
/// in memory; removing it deletes both. `None` on a length mismatch - a
/// truncated pad must never silently "decrypt" a prefix.
pub fn xor_pad(data: &[u8], pad: &[u8]) -> Option<Vec<u8>> {
    if data.len() != pad.len() {
        return None;
    }
    Some(data.iter().zip(pad.iter()).map(|(d, p)| d ^ p).collect())
}

/// Splits `plaintext` into a locally-stored (ciphertext, pad) pair: a fresh
/// random pad the same length, and the XOR of the two. Either half alone is
/// information-theoretically useless - exactly the property the received-
/// mail store needs so that mail content is never at rest in the clear, and
/// deleting either file genuinely destroys the mail.
pub fn repad(plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pad = crate::crypto::random_bytes(plaintext.len());
    let ciphertext = xor_pad(plaintext, &pad).expect("pad was generated at the same length");
    (ciphertext, pad)
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
