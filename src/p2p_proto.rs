//! Wire format for the direct client<->client UDP link, and the stateless
//! client<->server UDP rendezvous protocol used to discover a client's own
//! public address. Arranging a link at all (`ClientMessage::RequestPeerLink`/
//! `ServerMessage::PeerCandidates`, `proto.rs`) still goes over the existing
//! TCP connection - only the payloads listed here ever travel over the
//! punched UDP path itself. See `docs/PROTOCOL.md`'s "Direct peer-to-peer
//! transport" section and `crate::p2p`.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::proto::Envelope;

/// Target ceiling for one whole UDP datagram sent over the direct link
/// (a `PunchDatagram`, fully bincode-encoded) - chosen to avoid IP
/// fragmentation across the great majority of real-world paths: the
/// common Ethernet MTU is 1500 bytes, but VPNs/tunnels/PPPoE routinely
/// carry a smaller effective MTU, and a fragmented UDP datagram is
/// dropped outright by plenty of NATs/firewalls the moment any one
/// fragment goes missing - worse than just sending a smaller datagram in
/// the first place. 1200 is the same conservative "stays under basically
/// every real path's MTU" budget QUIC and other UDP-based protocols use.
///
/// `file_transfer::FILE_CHUNK_BYTES` and `voice::CHUNK_INTERVAL` are both
/// sized (see their own doc comments) so that a single RSA-family
/// (`Rsa`/`Password`/`None`/`PerMessage`) recipient's encrypted chunk,
/// once wrapped in `PunchDatagram::Reliable`/`Unreliable`, stays
/// comfortably under this. `pq_hybrid` is the one exception: its
/// per-chunk `HybridStreamKeySetup` (`docs/PROTOCOL.md` §13.3) is several
/// kilobytes on its own, repeated on *every* chunk regardless of how
/// small the plaintext is - no chunk-size choice can bring a `pq_hybrid`
/// voice/file chunk under this budget. That's a pre-existing property of
/// the hybrid wire format, not something introduced or fixable here; see
/// `docs/TESTING.md`'s known-coverage-gaps entry for it.
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
    Ping { link_nonce: u64 },
    /// Echoes the `link_nonce` from whichever `Ping` this answers. A side
    /// only trusts a `Pong` whose nonce matches its own current attempt.
    Pong { link_nonce: u64 },
    /// Keeps a NAT/firewall mapping open on an otherwise-idle active link.
    Keepalive { link_nonce: u64 },
    Ack { seq: u32 },
    /// A reliably-delivered frame (text/file content) - `payload` is a
    /// bincode encoding of `P2pPayload`. See `crate::p2p_reliable`.
    Reliable { seq: u32, payload: Vec<u8> },
    /// An unreliable, unordered frame (voice PCM chunk) - no ack, no
    /// retransmit; safe because voice chunk decryption derives its AEAD
    /// nonce from `(stream_id, seq)` rather than arrival order.
    Unreliable { stream_id: u64, seq: u32, blocks: Vec<Vec<u8>> },
}

/// What a `Reliable` frame's `payload` decodes to - the direct-transport
/// stand-ins for the content `ClientMessage` variants that used to be
/// relayed by the server (`SendChannel`/`SendDirect`/`FileOffer`/...). The
/// sending peer's UDP source address already identifies who sent it and
/// which link it belongs to, so none of these carry a `to`/`from` either.
/// `channel: Some(name)` addresses a channel send (kept purely for the
/// receiver's own UI bucketing - there is no server-side membership check
/// to lean on anymore); `None` is a DM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2pPayload {
    Envelope { channel: Option<String>, envelope: Envelope },
    FileOffer { channel: Option<String>, stream_id: u64, envelope: Envelope },
    StreamStart { channel: Option<String>, stream_id: u64 },
    StreamEnd { stream_id: u64, duration_ms: u32 },
    FileAccept { stream_id: u64 },
    FileReject { stream_id: u64 },
    FileChunk { stream_id: u64, seq: u32, blocks: Vec<Vec<u8>> },
    FileEnd { stream_id: u64 },
}
