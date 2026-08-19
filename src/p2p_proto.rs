//! Wire format for the direct client<->client UDP link, and the stateless
//! client<->server UDP rendezvous protocol used to discover a client's own
//! public address. Arranging a link at all (`ClientMessage::RequestPeerLink`/
//! `ServerMessage::PeerCandidates`, `proto.rs`) still goes over the existing
//! TCP connection - only the payloads listed here ever travel over the
//! punched UDP path itself. See `docs/PROTOCOL.md`'s "Direct peer-to-peer
//! transport" section and `crate::client::p2p`.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

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

/// Whether `observed` from a STUN-style `BindingResponse` is safe to treat
/// as this client's public, peer-punchable address. Docker's default UDP
/// port publishing often makes the server see the docker-bridge address
/// (e.g. `172.17.0.1`) instead of the client's real public endpoint -
/// advertising that poisons hole punch across separate networks.
pub fn is_usable_reflexive_observed(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
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
    /// An OTP-wrapped send: `envelope`'s single `blocks` element is a
    /// `pq_hybrid` blob that has additionally been piped through `otp -c
    /// <contact> --encrypt` (`client::otp::wrap_outgoing`) - the receiver
    /// must run `otp -c <contact> --decrypt` first to recover the ordinary
    /// `pq_hybrid` blob before it can be opened. `seq` is this contact's
    /// wire-level OTP sequence number, named by the `OtpDeliveryAck` the
    /// receiver sends back once decode succeeds. Only ever sent to a peer
    /// whose OTP provisioning has completed - see
    /// `client::otp::contact_name_if_active`.
    OtpEnvelope {
        channel: Option<String>,
        seq: u64,
        envelope: Envelope,
    },
    /// `OtpEnvelope`'s file-offer counterpart, mirroring `FileOffer` -
    /// `envelope`'s single `blocks` element is, exactly like `OtpEnvelope`'s,
    /// a `pq_hybrid` blob additionally piped through `otp -c <contact>
    /// --encrypt`: the offer (filename + size) is a genuine pad spend in
    /// its own right (docs/PROTOCOL.md 16.2). `seq` names *this* pad slot
    /// alone; the file's actual content, once accepted, reserves and acks
    /// an independent second slot named by `OtpFileContentSeq`.
    OtpFileOffer {
        channel: Option<String>,
        stream_id: u64,
        seq: u64,
        envelope: Envelope,
    },
    /// Sent back once an `OtpEnvelope`/`OtpFileOffer` has been unwrapped
    /// *and* successfully delivered locally - the genuine network
    /// acknowledgement that lets the sender honestly pass `-y` to `otp`'s
    /// own delivery-confirmation gate for its next send to this contact.
    OtpDeliveryAck {
        seq: u64,
    },
    /// Names an accepted file transfer's *content*-phase OTP pad slot,
    /// sent once, reliably, right after the sender reserves it (once the
    /// content is genuinely OTP-encrypted) and before the first
    /// `FileChunk` - independent of `OtpFileOffer`'s own `seq`, which only
    /// ever named the offer itself (docs/PROTOCOL.md 16.2). The receiver
    /// names this `seq` in the `OtpDeliveryAck` it sends once the whole
    /// file has arrived and been decrypted.
    OtpFileContentSeq {
        stream_id: u64,
        seq: u64,
    },
    /// `OtpFileOffer`'s voice counterpart - carries a `Content::VoiceOffer`
    /// envelope whose plaintext is a bincode-encoded
    /// `client::otp::VoiceOfferPayload`. Auto-accepted on arrival (no
    /// `FileAccept`/`FileReject` round trip): the actual PCM content
    /// streams as ordinary `FileChunk`/`FileEnd` blocks immediately after,
    /// exactly like an accepted file transfer, and OTP-decrypts the same
    /// way (`client::otp::finish_incoming_file`-shaped handling).
    OtpVoiceOffer {
        stream_id: u64,
        seq: u64,
        envelope: Envelope,
    },
    /// This side's `client::device_id`, encrypted the same way any other
    /// per-recipient content is (`Content::DeviceIdAnnounce`'s plaintext is
    /// just the id's raw UTF-8 bytes) - sent automatically the moment a
    /// direct link reaches `Active`, purely so an impersonation review
    /// (docs/PROTOCOL.md §12.7) has a device id to show. `channel: None`
    /// always - this is never addressed to a channel.
    DeviceIdAnnounce {
        envelope: Envelope,
    },

    /// Proposes a live, continuous, multi-user voice call (`docs/PROTOCOL.md`
    /// "Live voice calls") - distinct from a push-to-talk voice message.
    /// `call_id` is a fresh random token (like `link_nonce`) naming the call
    /// for the rest of its life, and doubles as the `stream_id` every
    /// participant's audio to every other participant is keyed under (safe
    /// to share across peers: audio chunks and `StreamKeySetup` are already
    /// scoped by `(from, stream_id)`, never `stream_id` alone). Sent by the
    /// caller to every current member of `channel`, or to the one DM peer
    /// when `channel: None`. Cleartext (no `Envelope`) - unlike a file
    /// offer's filename, a call's existence has nothing worth hiding from
    /// the peer it's already addressed to, and a channel name is already
    /// visible wire metadata elsewhere (`Envelope::channel`).
    CallInvite {
        call_id: u64,
        channel: Option<String>,
    },
    /// Joins call `call_id`: sent both by a freshly-accepting client (to
    /// every other member of the call's channel/DM) and, symmetrically, by
    /// an already-joined participant echoing straight back to whoever it
    /// just learned about this way (the "welcome" reply) - what converges
    /// every participant's roster without any of them acting as a
    /// coordinator the others depend on. Receiving this for a call/`from`
    /// pair already in the local roster is a harmless no-op.
    CallAccept {
        call_id: u64,
    },
    /// Declines an invite - sent only back to whoever it came from (never
    /// broadcast), mirrors `FileReject`. Purely informational: the sender
    /// was never added as a participant, so there is nothing to tear down.
    CallReject {
        call_id: u64,
    },
    /// Leaves call `call_id` - sent to every other participant the leaver
    /// currently knows about, so each tears down that one pairwise audio
    /// stream. The call itself has no other "end" - it simply has however
    /// many participants remain once everyone who has sent this is gone.
    CallEnd {
        call_id: u64,
    },
}
