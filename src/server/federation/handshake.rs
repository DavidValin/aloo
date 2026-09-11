//! The federation link's mutual authentication and key exchange -
//! `crate::server::federation`'s replacement for TLS, built entirely on
//! `crypto::pq`'s existing PQ-hybrid primitives (the same ones a client's
//! `my_key` uses), reused rather than reinvented:
//!
//! - **Confidentiality**: a fresh ML-KEM-1024+X25519 encryption keypair per
//!   connection from each side (`crypto::pq::generate_encryption_keys`),
//!   each side wrapping a random secret for the other's key
//!   (`crypto::pq::wrap_key_for`/`unwrap_key` - the identical construction
//!   a message send uses), combined via HKDF into one shared secret neither
//!   side alone controls.
//! - **Authentication**: each side's durable identity (`PqPrivateBundle`,
//!   generated once at `server_federation_identity` and never rotated)
//!   signs the *entire* handshake transcript - both `Hello`s and the key
//!   material inside them - with `crypto::pq::sign_with_identity`
//!   (ML-DSA-87 + RSA-4096, exactly as every other identity statement in
//!   this app is signed). The verifier checks that signature against the
//!   `PqPublicBundle` pinned in this server's own settings for the peer id
//!   the connection claims to be
//!   (`crate::settings::FederationPeerConfig::public_key_path`) - a
//!   connection claiming an id this server has no pinned key for is
//!   refused outright, and one that cannot produce a valid signature under
//!   the key pinned for the id it claims is refused just the same. Unlike
//!   the mTLS design this replaces, `self_id` is therefore never just an
//!   unverified label: a peer cannot claim to be a different configured
//!   peer without that peer's private key.
//!
//! Because both sides run identical code and the transcript is built from
//! a canonical (lexicographic) ordering of the two ids, the handshake is
//! fully symmetric - the same function authenticates an inbound accept and
//! an outbound dial.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::control::{ControlReader, ControlWriter};
use crate::crypto::pq::{
    PqEncapKeys, PqPrivateBundle, PqPublicBundle, fresh_data_key, generate_encryption_keys,
    hkdf_combine, sign_with_identity, unwrap_key, verify_with_identity, wrap_key_for,
};

use super::proto::FederationMessage;

/// Domain tag for the handshake transcript signature - distinct from every
/// other signing context in `crypto::pq` (a send, a rotation, an OTP mail),
/// so a signature produced here can never be replayed as one of those or
/// vice versa.
const HANDSHAKE_DOMAIN: &[u8] = b"aloo/federation/v1/handshake";

/// HKDF labels the two directional keys are derived under, keyed by
/// canonical (lexicographically lo/hi) position rather than "client"/
/// "server" - this handshake has no such distinction. Distinct from
/// `crate::control`'s own labels so a federation link's keys can never be
/// confused with a client control channel's.
const KEY_LO_TO_HI: &[u8] = b"aloo/federation/v1/lo-to-hi";
const KEY_HI_TO_LO: &[u8] = b"aloo/federation/v1/hi-to-lo";

/// The largest frame either handshake message may claim, before the other
/// side has proved who it is. Both are small and fixed-shape - a `Hello`
/// is an ML-KEM-1024 encapsulation key plus an X25519 key and a nonce, a
/// `KeyExchange` is a KEM ciphertext plus an ML-DSA-87 and an RSA-4096
/// signature - a few kilobytes together, so 64 KiB is already generous.
///
/// Without this the cap is `proto::MAX_FRAME_LEN`, 64 MiB, which
/// `ControlReader::recv` allocates purely on the strength of a 4-byte
/// length prefix from a peer that has not authenticated yet: anyone able
/// to reach the federation port could hold 64 MiB per connection just by
/// naming a big frame and then going quiet. The full allowance is restored
/// the moment the peer is verified - a real `MailForward` can be large.
const HANDSHAKE_MAX_FRAME_LEN: u32 = 64 * 1024;

/// How long the whole handshake may take before the connection is dropped.
/// Nothing else bounds it: a peer that connects and simply never speaks
/// would otherwise hold a task, a socket and an ephemeral keypair for as
/// long as it cared to. The client-facing listener has always bounded its
/// reads this way (`server::client_loop`'s `heartbeat_timeout`); this is
/// the federation port's equivalent, and it only covers the handshake -
/// an established link is long-lived by design.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// What this server checks a federation connection against: its own
/// durable signing identity, and the pinned public identity of every peer
/// it is willing to link to at all. A `Hello` claiming any other `self_id`
/// is refused before a single signature is even checked.
pub struct FederationTrust<'a> {
    pub self_id: &'a str,
    pub own_identity: &'a PqPrivateBundle,
    /// `(peer_id, pinned public bundle)` - looked up by the `self_id` a
    /// connecting peer claims.
    pub peers: &'a [(String, PqPublicBundle)],
}

impl FederationTrust<'_> {
    fn pinned_key_for(&self, peer_id: &str) -> Option<&PqPublicBundle> {
        self.peers.iter().find(|(id, _)| id == peer_id).map(|(_, key)| key)
    }
}

/// What a completed handshake learned about the peer - everything its
/// `Hello` announced, now that the signature covering it has been checked
/// and so all of it can actually be believed.
#[derive(Debug)]
pub struct PeerAnnouncement {
    pub peer_id: String,
    pub advertise_addr: String,
    /// Where an ordinary client should connect for that server, if its
    /// operator configured one (`server_federation_client_addr`).
    pub client_addr: Option<String>,
}

/// Why a handshake did not produce an authenticated, encrypted link.
#[derive(Debug)]
pub enum HandshakeError {
    /// The peer closed before completing the handshake.
    Closed,
    /// The connection claims to be this server's own id - a misconfigured
    /// `server_federation_id`/`server_federation_peer` somewhere, or one
    /// server's dial racing its own accept loop over loopback.
    ClaimsSelf(String),
    /// `self_id` names no peer this server has a pinned public key for.
    UnknownPeer(String),
    /// The peer's `KeyExchange` signature does not verify against the key
    /// pinned for the id it claims - a spoofed `self_id`, a stale/rotated
    /// key, or active tampering.
    AuthenticationFailed(String),
    /// The first message on the link was not `Hello`, or the second was
    /// not `KeyExchange` - a peer speaking something other than this
    /// handshake.
    UnexpectedMessage,
    /// The peer did not finish the handshake within `HANDSHAKE_TIMEOUT` -
    /// a stalled or deliberately slow connection, holding resources it
    /// has not authenticated itself for.
    TimedOut,
    Io(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "connection closed before the handshake completed"),
            Self::ClaimsSelf(id) => write!(f, "peer claims this server's own federation id ('{id}')"),
            Self::UnknownPeer(id) => {
                write!(f, "'{id}' is not a configured federation peer - refusing")
            }
            Self::AuthenticationFailed(id) => {
                write!(f, "signature from '{id}' does not verify against its pinned public key")
            }
            Self::UnexpectedMessage => write!(f, "peer did not speak the federation handshake"),
            Self::TimedOut => write!(f, "peer did not finish the handshake in time"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<crate::proto::ProtoError> for HandshakeError {
    fn from(e: crate::proto::ProtoError) -> Self {
        Self::Io(std::io::Error::other(e))
    }
}

/// The transcript both sides sign and verify: a canonical (lexicographically
/// ordered by id) encoding of both `Hello`s' key material, so it comes out
/// byte-identical regardless of which side is the dialer and which is the
/// acceptor. Binding both ephemeral keys and nonces is what stops a man in
/// the middle from splicing a genuine signature onto a substituted key
/// exchange, and what makes a captured signature from an earlier session
/// unusable in a new one (fresh keys and nonces every connection).
fn transcript(mine: &Announced<'_>, theirs: &Announced<'_>) -> Vec<u8> {
    let (a, b) = if mine.id < theirs.id { (mine, theirs) } else { (theirs, mine) };
    crate::proto::encode(&(a, b)).expect("encoding a handshake transcript cannot fail")
}

/// Everything one side's `Hello` announces, and therefore everything the
/// transcript signature covers.
///
/// The addresses are in here deliberately, not just the key material. A
/// man in the middle cannot *read* this link - it has neither side's
/// ephemeral private key - but it can relay the handshake verbatim, and
/// anything a signature does not cover it could rewrite along the way.
/// `client_addr` is the one field that gets repeated back to a human as
/// an instruction ("connect to <host:port> instead", §18.4), so leaving
/// it unsigned would hand a network attacker a phishing redirect for
/// free.
#[derive(serde::Serialize)]
struct Announced<'a> {
    id: &'a str,
    advertise_addr: &'a str,
    client_addr: Option<&'a str>,
    encap: &'a PqEncapKeys,
    nonce: &'a [u8; 32],
}

/// Runs the mutual handshake over an unsealed `ControlReader`/`ControlWriter`
/// pair, enabling encryption on both once it succeeds. Identical whichever
/// side calls it - the dialer and the acceptor run exactly the same steps.
/// `advertise_addr` is this server's own, sent to the peer verbatim - it
/// carries no trust weight (nothing is dialed from it inside this
/// function), it is purely informational for the peer's own directory of
/// how to reach this server. Returns the verified peer id and the
/// `advertise_addr` it announced.
pub async fn handshake<R, W>(
    rd: &mut ControlReader<R>,
    wr: &mut ControlWriter<W>,
    trust: &FederationTrust<'_>,
    advertise_addr: &str,
    client_addr: Option<&str>,
) -> Result<PeerAnnouncement, HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Everything an unauthenticated peer can make this server spend is
    // bounded here, and only here: how much it may allocate per frame, and
    // how long it may take. Both are lifted once it has proved who it is.
    rd.set_max_frame_len(HANDSHAKE_MAX_FRAME_LEN);
    let outcome = match tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        authenticate(rd, wr, trust, advertise_addr, client_addr),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => Err(HandshakeError::TimedOut),
    };
    rd.set_max_frame_len(crate::proto::MAX_FRAME_LEN);
    outcome
}

/// `handshake`'s body, minus the resource bounds it wraps this in.
async fn authenticate<R, W>(
    rd: &mut ControlReader<R>,
    wr: &mut ControlWriter<W>,
    trust: &FederationTrust<'_>,
    advertise_addr: &str,
    client_addr: Option<&str>,
) -> Result<PeerAnnouncement, HandshakeError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (my_encap, my_decap) = generate_encryption_keys();
    let my_nonce: [u8; 32] = {
        let bytes = crate::crypto::random_bytes(32);
        bytes.try_into().expect("random_bytes(32) is exactly 32 bytes")
    };

    wr.send(&FederationMessage::Hello {
        self_id: trust.self_id.to_string(),
        advertise_addr: advertise_addr.to_string(),
        client_addr: client_addr.map(str::to_string),
        ephemeral_encap: my_encap.clone(),
        nonce: my_nonce,
    })
    .await?;

    let Some(FederationMessage::Hello {
        self_id: peer_id,
        advertise_addr: peer_advertise_addr,
        client_addr: peer_client_addr,
        ephemeral_encap: peer_encap,
        nonce: peer_nonce,
    }) = rd.recv::<FederationMessage>().await?
    else {
        return Err(HandshakeError::Closed);
    };

    if peer_id == trust.self_id {
        return Err(HandshakeError::ClaimsSelf(peer_id));
    }
    let Some(peer_public) = trust.pinned_key_for(&peer_id) else {
        return Err(HandshakeError::UnknownPeer(peer_id));
    };

    let commitment = transcript(
        &Announced {
            id: trust.self_id,
            advertise_addr,
            client_addr,
            encap: &my_encap,
            nonce: &my_nonce,
        },
        &Announced {
            id: &peer_id,
            advertise_addr: &peer_advertise_addr,
            client_addr: peer_client_addr.as_deref(),
            encap: &peer_encap,
            nonce: &peer_nonce,
        },
    );
    let sig = sign_with_identity(trust.own_identity, HANDSHAKE_DOMAIN, &commitment)
        .map_err(|e| HandshakeError::Io(std::io::Error::other(e.to_string())))?;

    let my_secret = fresh_data_key();
    let (kem_ciphertext, wrapped_key, eph_x25519_pub) = wrap_key_for(&peer_encap, &my_secret)
        .map_err(|e| HandshakeError::Io(std::io::Error::other(e.to_string())))?;

    wr.send(&FederationMessage::KeyExchange { kem_ciphertext, wrapped_key, eph_x25519_pub, sig })
        .await?;

    let Some(FederationMessage::KeyExchange { kem_ciphertext, wrapped_key, eph_x25519_pub, sig }) =
        rd.recv::<FederationMessage>().await?
    else {
        return Err(HandshakeError::Closed);
    };

    if !verify_with_identity(peer_public, HANDSHAKE_DOMAIN, &commitment, &sig) {
        return Err(HandshakeError::AuthenticationFailed(peer_id));
    }

    let their_secret = unwrap_key(&my_decap, &kem_ciphertext, &wrapped_key, &eph_x25519_pub)
        .ok_or_else(|| HandshakeError::AuthenticationFailed(peer_id.clone()))?;

    // Canonical order again, so both sides combine the two contributions
    // identically regardless of who is "self" here.
    let (first, second) = if trust.self_id < peer_id.as_str() {
        (&my_secret, &their_secret)
    } else {
        (&their_secret, &my_secret)
    };
    let shared = hkdf_combine(first, second);
    let (lo_to_hi, hi_to_lo) = {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, &shared);
        let mut lo_to_hi = [0u8; 32];
        let mut hi_to_lo = [0u8; 32];
        hk.expand(KEY_LO_TO_HI, &mut lo_to_hi)
            .expect("32 bytes is well within HKDF-SHA256's limit");
        hk.expand(KEY_HI_TO_LO, &mut hi_to_lo)
            .expect("32 bytes is well within HKDF-SHA256's limit");
        (lo_to_hi, hi_to_lo)
    };
    let (send_key, recv_key) = if trust.self_id < peer_id.as_str() {
        (lo_to_hi, hi_to_lo)
    } else {
        (hi_to_lo, lo_to_hi)
    };

    wr.enable(send_key);
    rd.enable(recv_key);

    Ok(PeerAnnouncement { peer_id, advertise_addr: peer_advertise_addr, client_addr: peer_client_addr })
}
