//! Wire format for the direct client<->client UDP link, and the stateless
//! client<->server UDP rendezvous protocol used to discover a client's own
//! public address. Arranging a link at all (`ClientMessage::RequestPeerLink`/
//! `ServerMessage::PeerCandidates`, `proto.rs`) still goes over the existing
//! TCP connection - only the payloads listed here ever travel over the
//! punched UDP path itself. See `docs/PROTOCOL.md`'s "Direct peer-to-peer
//! transport" section and `crate::client::p2p`.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::proto::Envelope;

/// Target ceiling for one whole UDP datagram on the direct link (a
/// `PunchDatagram`, fully bincode-encoded), chosen to avoid IP
/// fragmentation: VPNs/tunnels/PPPoE routinely carry less than Ethernet's
/// 1500-byte MTU, and many NATs/firewalls drop a fragmented datagram the
/// moment one fragment goes missing. 1200 is the same conservative budget
/// QUIC uses. `file_transfer::FILE_CHUNK_BYTES` and
/// `voice::CHUNK_INTERVAL` are sized so an RSA-family recipient's
/// encrypted chunk stays under this. `pq_hybrid` is the one exception:
/// its per-chunk `HybridStreamKeySetup` (§13.3) is several kilobytes on
/// its own, so no chunk-size choice can fit it - a pre-existing property
/// of the hybrid wire format (see `docs/TESTING.md`'s coverage-gaps entry).
pub const SAFE_DATAGRAM_BYTES: usize = 1200;

/// Client <-> server UDP rendezvous socket only: a stateless STUN-Binding
/// analog. The server never authenticates or stores anything for this - it
/// just echoes back the address a datagram actually arrived from, which is
/// exactly the sender's own server-reflexive (public) address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RendezvousMessage {
    BindingRequest { token: u64 },
    BindingResponse { token: u64, observed: SocketAddr },
}

/// Client <-> client, once each side knows the other's candidate addresses
/// (exchanged via `ClientMessage::RequestPeerLink`/`ServerMessage::PeerCandidates`).
/// Every variant here is scoped to one specific peer purely by which
/// address it arrived from - none of these repeat a `to`/`from` `UserId`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PunchDatagram {
    /// Sent to every candidate address while punching. `link_nonce` is the
    /// sender's own token for its current attempt - the receiver just
    /// echoes it back in `Pong`, it never validates it against anything.
    Ping {
        link_nonce: u64,
    },
    /// Echoes the `link_nonce` from whichever `Ping` this answers. A side
    /// only trusts a `Pong` whose nonce matches its own current attempt.
    Pong {
        link_nonce: u64,
    },
    /// Keeps a NAT/firewall mapping open on an otherwise-idle active link.
    Keepalive {
        link_nonce: u64,
    },
    Ack {
        seq: u32,
    },
    /// A reliably-delivered frame (text/file content) - `payload` is a
    /// bincode encoding of `P2pPayload`. See `crate::client::p2p_reliable`.
    Reliable {
        seq: u32,
        payload: Vec<u8>,
    },
    /// An unreliable, unordered frame (voice PCM chunk) - no ack, no
    /// retransmit; safe because voice chunk decryption derives its AEAD
    /// nonce from `(stream_id, seq)` rather than arrival order.
    Unreliable {
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
}

/// What a `Reliable` frame's `payload` decodes to - the direct-transport
/// content messages. The sending peer's UDP source address already
/// identifies who sent it and which link it belongs to, so none of these
/// carry a `to`/`from`.
/// `channel: Some(name)` addresses a channel send (kept purely for the
/// receiver's own UI bucketing - there is no server-side membership check
/// to lean on anymore); `None` is a DM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2pPayload {
    Envelope {
        channel: Option<String>,
        envelope: Envelope,
    },
    FileOffer {
        channel: Option<String>,
        stream_id: u64,
        envelope: Envelope,
    },
    StreamStart {
        channel: Option<String>,
        stream_id: u64,
    },
    /// The `pq_hybrid` key setup for one stream, sent reliably once per
    /// recipient right after `StreamStart` - a bincode-encoded
    /// `crypto::pq::SendSetup`.
    ///
    /// Carried on its own rather than inside every chunk: the setup is
    /// several kilobytes (an ML-KEM ciphertext, an RSA ciphertext and two
    /// signatures, one of them ML-DSA-87), so repeating it per chunk both
    /// wasted bandwidth and pushed every chunk past `SAFE_DATAGRAM_BYTES`
    /// into guaranteed IP fragmentation. Sent once, chunks stay small.
    ///
    /// Only `pq_hybrid` recipients ever receive this; an RSA-family
    /// recipient's chunks need no setup at all.
    StreamKeySetup {
        stream_id: u64,
        setup: Vec<u8>,
    },
    StreamEnd {
        stream_id: u64,
        duration_ms: u32,
    },
    FileAccept {
        stream_id: u64,
    },
    FileReject {
        stream_id: u64,
    },
    FileChunk {
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
    FileEnd {
        stream_id: u64,
    },
}
