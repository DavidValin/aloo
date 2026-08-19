//! Direct client<->client transport: server-assisted UDP hole punching, plus
//! the reliable (text/file, `crate::client::p2p_reliable`) and unreliable (voice)
//! delivery built on top of the resulting punched link. See
//! `docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section.
//!
//! The server is never in the data path: it only ever relays the initial
//! candidate exchange (`ClientMessage::RequestPeerLink`/
//! `ServerMessage::PeerCandidates`) and answers a stateless STUN-Binding
//! analog (`p2p_proto::RendezvousMessage`) that lets a client learn its own
//! server-reflexive address. Everything in this module runs entirely
//! client-side. There is deliberately no relay fallback: content only ever
//! travels over a punched link, never through the server, encrypted or
//! otherwise.
//!
//! Establishing that link is a *continuously maintained* state, not a
//! one-shot attempt: as long as a peer is still known (still sharing a
//! channel or an open DM), a link that never opened or that later went
//! quiet is re-signalled and re-punched on an exponential backoff, forever.
//! Content queued against a link that isn't up yet is held, not dropped,
//! and flushed the moment the link comes back - it only surfaces as a
//! visible failure once it has been undeliverable for `PENDING_MAX_AGE`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

use crate::p2p_proto::{P2pPayload, PunchDatagram, RendezvousMessage};
use crate::client::p2p_reliable::{ArqReceiver, ArqSender};
use crate::proto::{self, ClientMessage, UserId};

/// How long a link may sit waiting for the peer's relayed candidates
/// before the attempt is abandoned and retried. Generous because it covers
/// a full client->server->client round trip on the TCP control connection,
/// plus the peer's own tick granularity.
pub const SIGNAL_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `Ping`/`Pong` probing may run against a known candidate list
/// before the attempt is abandoned and retried.
pub const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Comfortably under the ~30s UDP NAT mapping timeout common on consumer
/// routers - driven off the same tick as retransmit scanning, not its own
/// timer.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// How long an `Active` link may go without receiving *anything* from the
/// peer - including their `Keepalive`s, which is what makes this a
/// liveness check rather than a traffic check - before it's treated as
/// lost and re-punched. Three missed keepalives.
pub const LINK_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// First retry delay after a failed establishment attempt; doubles per
/// consecutive failure up to `RETRY_MAX`. A link is never abandoned - the
/// peer being online at all means a direct path may become possible at any
/// moment (their NAT rebinding, a VPN dropping, a firewall rule changing).
pub const RETRY_BASE: Duration = Duration::from_secs(1);
pub const RETRY_MAX: Duration = Duration::from_secs(30);
/// How often to re-probe the server's UDP rendezvous socket. Doubles as
/// the NAT keepalive for the mapping our own reflexive candidate names:
/// without it, a client that connects and sits idle advertises an address
/// its NAT dropped minutes ago.
pub const REFLEXIVE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// How long content may sit queued against a link that isn't up before it
/// is given up on and reported to the user. Deliberately much longer than
/// a punch attempt: a link that fails once and recovers on retry should
/// deliver, not report a failure.
pub const PENDING_MAX_AGE: Duration = Duration::from_secs(60);
/// Ceiling on queued-but-undelivered payloads per link, so a long-dead
/// peer can't grow this without bound.
pub const PENDING_MAX: usize = 64;
/// Ceiling on how many candidate addresses one link will probe. Relayed
/// candidates are bounded by the peer's own interface count, but
/// peer-reflexive ones (`adopt_candidate`) come straight off the wire, so
/// this bounds what a hostile or badly-behaved peer can make us hold.
const CANDIDATES_MAX: usize = 16;
/// How long to wait for one `BindingRequest` to be answered at session
/// start, and how many times to ask before giving up and gathering host
/// candidates only.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_millis(600);
const RENDEZVOUS_ATTEMPTS: u32 = 3;

/// What the UI shows for one peer's direct link (`docs/SPEC.md`'s
/// "Connected UI" - the sidebar colours a name by this). Deliberately
/// coarse: the distinction that matters to a user is "can my messages
/// reach this person right now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    /// Being established (or re-established) right now - anything sent is
    /// queued and flushed once it opens.
    Connecting,
    /// Punched and confirmed live in both directions.
    Active,
    /// Was never established, or has gone quiet; a retry is scheduled.
    Lost,
}

/// Events fed to `session.rs`'s select loop as direct-link traffic
/// arrives, the direct-transport counterpart of the content
/// `ServerMessage` variants this replaces. `from`/`peer` is always known
/// from which link the datagram arrived on, never carried on the wire
/// itself.
pub enum P2pEvent {
    /// `channel: Some(name)` is a channel message, `None` a DM - mirrors
    /// `p2p_proto::P2pPayload::Envelope`.
    Message {
        channel: Option<String>,
        from: UserId,
        envelope: crate::proto::Envelope,
    },
    StreamStart {
        channel: Option<String>,
        from: UserId,
        stream_id: u64,
    },
    /// A `pq_hybrid` stream's key setup, arriving reliably once, ahead of
    /// (or racing) its chunks - see `p2p_proto::P2pPayload::StreamKeySetup`.
    StreamKeySetup {
        from: UserId,
        stream_id: u64,
        setup: Vec<u8>,
    },
    StreamChunk {
        from: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
    /// `duration_ms` isn't carried through - like the server-relayed
    /// version before it, the receiver finalizes with whatever plaintext
    /// was actually accumulated rather than trusting the sender's claimed
    /// duration (see `voice_stream::end_incoming_stream`).
    StreamEnd {
        from: UserId,
        stream_id: u64,
    },
    FileOffer {
        channel: Option<String>,
        from: UserId,
        stream_id: u64,
        envelope: crate::proto::Envelope,
    },
    /// The accepter/rejecter is always exactly whoever we offered the file
    /// to (there is only ever one, per `stream_id`), so unlike `Message`/
    /// `FileOffer` this doesn't need a `from` to disambiguate anything.
    FileAccepted {
        stream_id: u64,
    },
    FileRejected {
        stream_id: u64,
    },
    FileChunk {
        from: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
    FileEnd {
        from: UserId,
        stream_id: u64,
    },
    /// The manager wants these candidates relayed to `peer` - the caller
    /// turns this into a `ClientMessage::RequestPeerLink` over the TCP
    /// control connection. Emitted by `tick_at` (a scheduled retry, or a
    /// changed reflexive address), which has no control sink of its own;
    /// `ensure_link`, which does, signals directly instead.
    Signal {
        peer: UserId,
        candidates: Vec<SocketAddr>,
        link_nonce: u64,
    },
    /// This peer's link changed state - drives the sidebar's colour. Only
    /// emitted on an actual transition, never repeated per tick.
    LinkStatusChanged {
        peer: UserId,
        status: LinkStatus,
    },
    /// Content queued against `peer` has been undeliverable for
    /// `PENDING_MAX_AGE` and has now been dropped. Retrying continues in
    /// the background regardless - this reports the lost content, not the
    /// end of the link.
    LinkFailed {
        peer: UserId,
        reason: String,
    },
    /// OTP-wrapped counterpart of `Message` - mirrors
    /// `p2p_proto::P2pPayload::OtpEnvelope`. `envelope`'s `blocks[0]` is
    /// still OTP-wrapped at this point; `client::otp::unwrap_incoming` runs
    /// before this can be handed to `session::decrypt_envelope_for`.
    OtpMessage {
        channel: Option<String>,
        from: UserId,
        seq: u64,
        envelope: crate::proto::Envelope,
    },
    /// OTP-wrapped counterpart of `FileOffer`.
    OtpFileOffer {
        channel: Option<String>,
        from: UserId,
        stream_id: u64,
        seq: u64,
        envelope: crate::proto::Envelope,
    },
    /// A peer has confirmed successful local decode of the OTP message we
    /// sent as sequence `seq` - the genuine network acknowledgement
    /// `client::otp`'s send-path gating waits for before honestly passing
    /// `-y` to `otp`'s next `--encrypt` for that contact.
    OtpDeliveryAck {
        from: UserId,
        seq: u64,
    },
    /// Mirrors `p2p_proto::P2pPayload::OtpFileContentSeq` - names an
    /// accepted file transfer's content-phase pad slot, independent of the
    /// offer's own `seq`.
    OtpFileContentSeq {
        from: UserId,
        stream_id: u64,
        seq: u64,
    },
    /// OTP-wrapped counterpart of a voice offer - mirrors `OtpFileOffer`,
    /// DM-only (unlike `FileOffer`, never carries a `channel`).
    OtpVoiceOffer {
        from: UserId,
        stream_id: u64,
        seq: u64,
        envelope: crate::proto::Envelope,
    },
    /// A peer's `client::device_id`, still sealed - mirrors
    /// `p2p_proto::P2pPayload::DeviceIdAnnounce`. `session.rs` decrypts it
    /// with `decrypt_own_envelope` (its `Content::DeviceIdAnnounce` tag,
    /// not `Text`, is what routes it here instead of the ordinary message
    /// path) and feeds the plaintext into the impersonation-review flow
    /// (docs/PROTOCOL.md §12.7) rather than any visible log.
    DeviceIdAnnounce {
        from: UserId,
        envelope: crate::proto::Envelope,
    },

    /// Mirrors `p2p_proto::P2pPayload::CallInvite` - see
    /// `crate::client::voice_call` for how a call's roster/audio are handled
    /// from here.
    CallInvite {
        channel: Option<String>,
        from: UserId,
        call_id: u64,
    },
    CallAccept {
        from: UserId,
        call_id: u64,
    },
    CallReject {
        from: UserId,
        call_id: u64,
    },
    CallEnd {
        from: UserId,
        call_id: u64,
    },
}

/// Outgoing traffic originating on a background thread (the voice
/// recorder, the file sender) - handed to `session.rs`'s
/// `record_out_tx`/`record_out_rx` channel, then dispatched into
/// `PeerLinkManager` from the single-threaded select loop. Voice chunks
/// are unreliable; file chunks/end are reliable (a transfer has no
/// acceptable-loss tradeoff the way live audio does). `VoiceEnd`'s
/// `recipients` covers channel fan-out and a DM's single recipient
/// uniformly.
pub enum P2pOutbound {
    ChannelVoiceChunk {
        stream_id: u64,
        seq: u32,
        per_recipient: Vec<(UserId, Vec<Vec<u8>>)>,
    },
    /// A live call's outgoing audio chunk, fanned out to every current
    /// participant - mechanically identical to `ChannelVoiceChunk`
    /// (`stream_id` is the call's own `call_id`), kept as its own variant
    /// because it comes from `voice_call::spawn_call_audio_worker`'s
    /// unbounded, dynamically-addressed capture rather than a bounded
    /// push-to-talk recording, and dispatching it must never touch
    /// anything push-to-talk-specific (`SessionState::own_stream_targets`,
    /// the `MAX_RECORDING_SAMPLES` cap, ...).
    CallVoiceChunk {
        call_id: u64,
        seq: u32,
        per_recipient: Vec<(UserId, Vec<Vec<u8>>)>,
    },
    DirectVoiceChunk {
        to: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
    VoiceEnd {
        stream_id: u64,
        duration_ms: u32,
        recipients: Vec<UserId>,
    },
    FileChunk {
        to: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    },
    FileEnd {
        to: UserId,
        stream_id: u64,
    },
}

/// One decoded datagram off the session's UDP socket. The two protocols
/// share a socket and are told apart purely by source address (the server's
/// rendezvous socket versus anyone else) rather than by trying each
/// decoder: `proto::decode` ignores trailing bytes, so a `BindingResponse`
/// would otherwise decode "successfully" as a `Pong`.
pub enum InboundDatagram {
    Punch(PunchDatagram),
    Rendezvous(RendezvousMessage),
}

/// What a caller gets back from `ensure_link`: whether it's safe to send
/// right now. Voice (never queued, PROTOCOL.md §11.2-style partial
/// delivery) checks this directly and excludes a `Pending` recipient from
/// the stream; text/file offers instead go through
/// `PeerLinkManager::send_reliable_or_queue`, which queues on `Pending`
/// and flushes automatically once the link goes `Active`. There is no
/// terminal "failed" answer: a link to a peer who is still online is
/// always either up or being retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkReadiness {
    Active,
    Pending,
}

enum PeerLinkState {
    /// We've asked the server to relay our candidates to this peer and are
    /// waiting for their reply (their own `RequestPeerLink`, relayed back
    /// as `ServerMessage::PeerCandidates`).
    Requested { started: Instant },
    /// We know at least one candidate address for the peer and are
    /// exchanging `Ping`/`Pong` with all of them, looking for one that
    /// works in both directions.
    Punching { started: Instant },
    Active {
        addr: SocketAddr,
        last_sent: Instant,
        /// Any datagram at all attributed to this peer, keepalives
        /// included - the input to `LINK_IDLE_TIMEOUT`'s liveness check.
        last_received: Instant,
    },
    /// No usable path right now. Not terminal: `retry_at` schedules the
    /// next automatic attempt, and anything queued against the link stays
    /// queued meanwhile.
    Lost {
        reason: String,
        retry_at: Instant,
    },
}

struct PeerLink {
    /// This link's shared identifier, echoed in every `Ping`/`Pong`/
    /// `Keepalive` on it. Both sides converge on the same value (the
    /// initiator's, or the numerically smaller one if both initiated at
    /// once - see `on_peer_candidates`), which is what lets a datagram
    /// arriving from an address nobody advertised still be attributed to
    /// the right link. 64 random bits exchanged only over the
    /// authenticated TCP control connection, so an off-path attacker
    /// can't guess one; this is the same role ICE's ufrag/pwd plays.
    link_nonce: u64,
    state: PeerLinkState,
    /// Every address we might reach this peer at: the ones the server
    /// relayed, plus any peer-reflexive one learned from an incoming
    /// probe (`adopt_candidate`).
    candidates: Vec<SocketAddr>,
    /// Reliable sends waiting for the link to open, oldest first, each
    /// stamped with when it was queued so `PENDING_MAX_AGE` can expire it.
    /// Survives a failed attempt on purpose - a message typed while the
    /// link is flapping should arrive when it recovers, not vanish. Voice
    /// never populates this (see `LinkReadiness`'s doc).
    pending: VecDeque<(Instant, P2pPayload)>,
    /// Consecutive failed establishment attempts, driving `retry_delay`.
    /// Reset the moment the link goes `Active`.
    attempts: u32,
    /// The last status handed to the UI, so `sync_status` only emits on a
    /// real transition.
    reported: LinkStatus,
    arq_tx: ArqSender,
    arq_rx: ArqReceiver,
}

impl PeerLink {
    fn new(link_nonce: u64, state: PeerLinkState) -> Self {
        Self {
            link_nonce,
            state,
            candidates: Vec::new(),
            pending: VecDeque::new(),
            attempts: 0,
            reported: LinkStatus::Connecting,
            arq_tx: ArqSender::new(),
            arq_rx: ArqReceiver::new(),
        }
    }

    fn status(&self) -> LinkStatus {
        match self.state {
            PeerLinkState::Active { .. } => LinkStatus::Active,
            PeerLinkState::Lost { .. } => LinkStatus::Lost,
            PeerLinkState::Requested { .. } | PeerLinkState::Punching { .. } => {
                LinkStatus::Connecting
            }
        }
    }

    fn establishing(&self) -> bool {
        matches!(
            self.state,
            PeerLinkState::Requested { .. } | PeerLinkState::Punching { .. }
        )
    }
}

/// Owns the one UDP socket a session multiplexes every peer link over, and
/// every peer link's state. Lives on `SessionState`, driven entirely from
/// `session::run_connected_session`'s single-threaded select loop - the
/// concurrent piece is just the receive loop task (`spawn_receive_loop`)
/// forwarding raw datagrams in over a channel, exactly like the existing
/// TCP-reader task pattern.
pub struct PeerLinkManager {
    socket: Arc<UdpSocket>,
    /// The server's UDP rendezvous socket: the only address this manager
    /// ever talks to that isn't a peer, and the discriminator that tells
    /// rendezvous replies from punch traffic.
    server_udp_addr: SocketAddr,
    /// This machine's own interface addresses, fixed for the session.
    host_candidates: Vec<SocketAddr>,
    /// Whether the one UDP socket is bound to an IPv6 address. The socket's
    /// family is fixed for the session (`session.rs` picks it from the
    /// server's own address), and a datagram can only ever be sent to an
    /// address of that same family - so this is what keeps candidates of
    /// the other family, ours and the peer's alike, out of a list that is
    /// capped at `CANDIDATES_MAX`.
    local_is_ipv6: bool,
    /// Our server-reflexive (public) address, re-learned every
    /// `REFLEXIVE_REFRESH_INTERVAL` so it can't go stale behind a NAT that
    /// dropped the mapping while we sat idle.
    reflexive: Option<SocketAddr>,
    reflexive_token: u64,
    last_reflexive_probe: Instant,
    links: HashMap<UserId, PeerLink>,
    /// Every address currently attributed to a given peer, so an inbound
    /// data frame (identified only by its source address) reaches the
    /// right link.
    addr_index: HashMap<SocketAddr, UserId>,
    events_tx: UnboundedSender<P2pEvent>,
}

impl PeerLinkManager {
    /// Binds the session's one UDP socket, learns this client's own
    /// candidate addresses (host interfaces plus, best-effort, a
    /// server-reflexive one via `server_udp_addr`), and returns the manager
    /// plus the socket handle the caller must hand to `spawn_receive_loop`.
    /// A failure to learn the reflexive candidate (UDP blocked outbound, a
    /// server whose UDP port isn't reachable, ...) is not fatal - punching
    /// proceeds with host candidates alone, which is still enough on a
    /// shared LAN, and `tick_at` keeps retrying the probe for the rest of
    /// the session in case it starts working.
    pub async fn bind(
        bind_addr: SocketAddr,
        server_udp_addr: SocketAddr,
        events_tx: UnboundedSender<P2pEvent>,
    ) -> std::io::Result<(Self, Arc<UdpSocket>)> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        let local_is_ipv6 = local_addr.is_ipv6();
        let reflexive = learn_reflexive_candidate(&socket, server_udp_addr).await;

        Ok((
            Self {
                socket: socket.clone(),
                server_udp_addr,
                host_candidates: host_candidates(local_addr.port(), local_is_ipv6),
                local_is_ipv6,
                reflexive,
                reflexive_token: 0,
                last_reflexive_probe: Instant::now(),
                links: HashMap::new(),
                addr_index: HashMap::new(),
                events_tx,
            },
            socket,
        ))
    }

    /// Every address this client can currently be reached at, in the order
    /// they're advertised to a peer.
    ///
    /// The server-reflexive address goes **first**, ahead of the host
    /// candidates. It is the only entry that can work between two peers on
    /// different networks, while the host ones are an unbounded list of
    /// whatever `if_addrs` reports - loopback, the LAN address, and one
    /// gateway per Docker bridge, VPN or container network. Since a
    /// receiver stops storing at `CANDIDATES_MAX`, advertising the useful
    /// one last meant a developer machine with enough virtual interfaces
    /// could push the only routable address off the end of its own peer's
    /// list, leaving nothing to punch to but private addresses.
    fn local_candidates(&self) -> Vec<SocketAddr> {
        let mut out = Vec::with_capacity(self.host_candidates.len() + 1);
        if let Some(reflexive) = self.reflexive {
            out.push(reflexive);
        }
        for addr in &self.host_candidates {
            if !out.contains(addr) {
                out.push(*addr);
            }
        }
        out
    }

    /// Ensures a link toward `peer` exists and is being worked on, and
    /// reports whether it's safe to send on it right now. A `Lost` link is
    /// restarted immediately rather than waiting out its backoff - the
    /// backoff exists to rate-limit unattended retries, not to make
    /// someone's next message wait.
    pub async fn ensure_link(
        &mut self,
        wr: &mut impl crate::control::ControlSink,
        peer: UserId,
    ) -> LinkReadiness {
        let readiness = match self.links.get(&peer).map(|l| &l.state) {
            Some(PeerLinkState::Active { .. }) => return LinkReadiness::Active,
            Some(PeerLinkState::Requested { .. } | PeerLinkState::Punching { .. }) => {
                LinkReadiness::Pending
            }
            // No link yet, or one waiting out a retry backoff.
            _ => {
                let (candidates, link_nonce) = self.restart_attempt(peer, Instant::now());
                let _ = wr
                    .send_control(&ClientMessage::RequestPeerLink {
                        peer,
                        candidates,
                        link_nonce,
                    })
                    .await;
                LinkReadiness::Pending
            }
        };
        self.sync_statuses();
        readiness
    }

    /// Starts (or restarts) an establishment attempt toward `peer`,
    /// returning what the caller must get relayed to them. Previously
    /// learned candidates are kept - they may still work, and they give
    /// punching something to probe before the peer's reply arrives - but
    /// anything queued against the link is kept untouched.
    fn start_attempt(&mut self, peer: UserId, now: Instant) -> (Vec<SocketAddr>, u64) {
        let link_nonce = random_token();
        let candidates = self.local_candidates();
        match self.links.get_mut(&peer) {
            Some(link) => {
                link.link_nonce = link_nonce;
                link.state = PeerLinkState::Requested { started: now };
            }
            None => {
                self.links.insert(
                    peer,
                    PeerLink::new(link_nonce, PeerLinkState::Requested { started: now }),
                );
            }
        }
        (candidates, link_nonce)
    }

    /// Starts the reliable layer over for a link that is being punched
    /// again. The ARQ sequence space belongs to one punched link - both
    /// sides restart it together, since both enter a new attempt before
    /// either can transmit on it again - so anything still unacknowledged
    /// goes back to the front of the pending queue to be re-sent under the
    /// new link rather than being lost with the old one. Returns how many
    /// payloads had to be dropped to stay under `PENDING_MAX`.
    fn reset_transport(link: &mut PeerLink, now: Instant) -> usize {
        let unacked = link.arq_tx.reset();
        link.arq_rx.reset();
        for bytes in unacked.into_iter().rev() {
            if let Ok(payload) = proto::decode::<P2pPayload>(&bytes) {
                link.pending.push_front((now, payload));
            }
        }
        let mut dropped = 0;
        while link.pending.len() > PENDING_MAX {
            link.pending.pop_front();
            dropped += 1;
        }
        dropped
    }

    /// `start_attempt`, for a link that may have been carrying traffic:
    /// resets the reliable layer first (see `reset_transport`) and reports
    /// anything that had to be dropped.
    fn restart_attempt(&mut self, peer: UserId, now: Instant) -> (Vec<SocketAddr>, u64) {
        if let Some(link) = self.links.get_mut(&peer) {
            let dropped = Self::reset_transport(link, now);
            if dropped > 0 {
                let _ = self.events_tx.send(P2pEvent::LinkFailed {
                    peer,
                    reason: format!("{dropped} queued messages dropped, too much unsent content"),
                });
            }
        }
        self.start_attempt(peer, now)
    }

    /// Handles an incoming `ServerMessage::PeerCandidates`: if we already
    /// asked `from` for a link, this is their reply and punching starts
    /// now; otherwise it's an implicit invite - we reply in kind (our own
    /// `RequestPeerLink`, echoing `link_nonce`) and start punching too. A
    /// `Lost` link is treated like no link at all, so a peer's retry
    /// re-arms us immediately instead of waiting out our own backoff.
    ///
    /// Both sides pre-warm links on `UserJoined`, so both initiating at
    /// once is the normal case, not the exception - and then each side
    /// starts out holding a different nonce. While both are still
    /// establishing they converge by taking the numerically smaller of the
    /// two, which is what keeps the nonce usable as a shared link
    /// identifier for attributing datagrams from addresses nobody
    /// advertised. Against an already-`Active` link the rule is different:
    /// the same nonce is a stray or duplicate relay and changes nothing,
    /// but a *different* one means the peer has given up on this link and
    /// started a fresh attempt, so we follow them into it rather than
    /// sitting on a link only one side still believes in.
    pub async fn on_peer_candidates(
        &mut self,
        wr: &mut impl crate::control::ControlSink,
        from: UserId,
        candidates: Vec<SocketAddr>,
        link_nonce: u64,
    ) {
        let now = Instant::now();
        let (needs_reply, agreed, restarting) = match self.links.get(&from) {
            Some(link) if link.establishing() => (false, link.link_nonce.min(link_nonce), false),
            Some(link) if matches!(link.state, PeerLinkState::Active { .. }) => {
                if link.link_nonce == link_nonce {
                    return;
                }
                (true, link_nonce, true)
            }
            // `Lost`, or no link at all.
            Some(_) => (true, link_nonce, true),
            None => (true, link_nonce, false),
        };
        if restarting
            && let Some(link) = self.links.get_mut(&from)
        {
            let dropped = Self::reset_transport(link, now);
            if dropped > 0 {
                let _ = self.events_tx.send(P2pEvent::LinkFailed {
                    peer: from,
                    reason: format!("{dropped} queued messages dropped, too much unsent content"),
                });
            }
        }
        if needs_reply {
            let _ = wr
                .send_control(&ClientMessage::RequestPeerLink {
                    peer: from,
                    candidates: self.local_candidates(),
                    link_nonce: agreed,
                })
                .await;
        }
        let local_is_ipv6 = self.local_is_ipv6;
        let link = self
            .links
            .entry(from)
            .or_insert_with(|| PeerLink::new(agreed, PeerLinkState::Punching { started: now }));
        link.link_nonce = agreed;
        link.state = PeerLinkState::Punching { started: now };
        for addr in candidates {
            if link.candidates.len() >= CANDIDATES_MAX {
                break;
            }
            // Nothing can ever be sent to an address of the family this
            // session's socket isn't bound to, so storing one would only
            // spend a `CANDIDATES_MAX` slot that a reachable address needs.
            if addr.is_ipv6() != local_is_ipv6 {
                continue;
            }
            if !link.candidates.contains(&addr) {
                link.candidates.push(addr);
                self.addr_index.insert(addr, from);
            }
        }
        self.send_pings(from);
        self.sync_statuses();
    }

    fn send_pings(&self, peer: UserId) {
        let Some(link) = self.links.get(&peer) else {
            return;
        };
        if !link.establishing() {
            return;
        }
        let dgram = encode_dgram(&PunchDatagram::Ping {
            link_nonce: link.link_nonce,
        });
        for addr in &link.candidates {
            send_dgram(&self.socket, &dgram, *addr);
        }
    }

    /// Sends `payload` to `peer` now if the link is `Active`, or queues it
    /// to be sent automatically once it becomes `Active`. Callers must have
    /// already called `ensure_link` for `peer` (this never starts a new
    /// link itself) - a `payload` for a peer with no link state at all is
    /// simply dropped, since there is nothing to flush it later.
    pub fn send_reliable_or_queue(&mut self, peer: UserId, payload: P2pPayload) {
        let socket = self.socket.clone();
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        if matches!(link.state, PeerLinkState::Active { .. }) {
            Self::transmit_reliable(&socket, link, &payload);
            return;
        }
        // Queued rather than dropped even on a `Lost` link: it is being
        // retried, and `PENDING_MAX_AGE` - not the state right now - is
        // what decides this was undeliverable.
        if link.pending.len() >= PENDING_MAX {
            link.pending.pop_front();
            let _ = self.events_tx.send(P2pEvent::LinkFailed {
                peer,
                reason: "too much unsent content queued for this peer".to_string(),
            });
        }
        link.pending.push_back((Instant::now(), payload));
    }

    /// Sends `blocks` unreliably (no ack, no retransmit) - only ever called
    /// once a caller has already confirmed `LinkReadiness::Active` via
    /// `ensure_link` (voice is never queued, see `LinkReadiness`'s doc), so
    /// a link that isn't `Active` here simply drops the chunk.
    pub fn send_unreliable_voice(
        &mut self,
        peer: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    ) {
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        let PeerLinkState::Active { addr, last_sent, .. } = &mut link.state else {
            return;
        };
        let dgram = encode_dgram(&PunchDatagram::Unreliable {
            stream_id,
            seq,
            blocks,
        });
        send_dgram(&self.socket, &dgram, *addr);
        *last_sent = Instant::now();
    }

    fn transmit_reliable(socket: &UdpSocket, link: &mut PeerLink, payload: &P2pPayload) {
        let PeerLinkState::Active { addr, last_sent, .. } = &mut link.state else {
            return;
        };
        let bytes = proto::encode(payload).unwrap_or_default();
        let seq = link.arq_tx.send(bytes.clone());
        let dgram = encode_dgram(&PunchDatagram::Reliable {
            seq,
            payload: bytes,
        });
        send_dgram(socket, &dgram, *addr);
        *last_sent = Instant::now();
    }

    /// Feeds one datagram straight off `spawn_receive_loop` to whichever
    /// of the two protocols it belongs to.
    pub fn on_inbound(&mut self, addr: SocketAddr, dgram: InboundDatagram) {
        match dgram {
            InboundDatagram::Punch(dgram) => self.on_datagram(addr, dgram),
            InboundDatagram::Rendezvous(msg) => self.on_rendezvous(addr, msg),
        }
    }

    /// `on_datagram_at`, at the current time.
    pub fn on_datagram(&mut self, addr: SocketAddr, dgram: PunchDatagram) {
        self.on_datagram_at(addr, dgram, Instant::now());
    }

    /// Feeds one received punch datagram, already demuxed to `addr` by the
    /// caller's receive loop, into the relevant link.
    ///
    /// Attribution is by source address where one is known, and otherwise
    /// by `link_nonce` against a link currently being established - which
    /// is what makes a NAT that maps a different external port per
    /// destination (symmetric NAT, carrier-grade NAT) punchable at all:
    /// the peer's probe arrives from an address neither side could have
    /// advertised, and `adopt_candidate` learns it. Nonce attribution is
    /// deliberately limited to links being established: letting an
    /// unauthenticated datagram move an already-`Active` link's address
    /// would be a hijack primitive, whereas a peer that genuinely remaps
    /// mid-session is caught by `LINK_IDLE_TIMEOUT` and re-punched from
    /// scratch. Data frames (`Ack`/`Reliable`/`Unreliable`) are never
    /// attributed by nonce - they carry none - so they require a mapping
    /// established by the handshake first.
    /// `now` is injected (rather than read here) so a test can exercise
    /// `LINK_IDLE_TIMEOUT`'s liveness window without sleeping through it,
    /// the same seam `tick`/`tick_at` already provides.
    pub fn on_datagram_at(&mut self, addr: SocketAddr, dgram: PunchDatagram, now: Instant) {
        match dgram {
            PunchDatagram::Ping { link_nonce } => {
                let Some(peer) = self.attribute(addr, link_nonce) else {
                    // An unsolicited probe from a stranger, or a stale
                    // candidate from a link that has moved on: answering
                    // would confirm this socket is live to anyone who
                    // scans it, and would serve no link of ours.
                    return;
                };
                self.adopt_candidate(peer, addr);
                self.note_received(peer, now);
                send_dgram(
                    &self.socket,
                    &encode_dgram(&PunchDatagram::Pong { link_nonce }),
                    addr,
                );
                // Probe straight back at the address they actually reached
                // us from, rather than waiting for the next tick: this is
                // the path most likely to work, and the peer needs our
                // traffic to open their side of the mapping too.
                self.send_pings(peer);
            }
            PunchDatagram::Pong { link_nonce } => {
                let Some(peer) = self.attribute(addr, link_nonce) else {
                    return;
                };
                self.on_pong(peer, addr, link_nonce, now);
            }
            PunchDatagram::Keepalive { link_nonce } => {
                // Purely a liveness beat: it opens nothing and moves
                // nothing, it just proves the peer is still there for
                // `LINK_IDLE_TIMEOUT`'s benefit.
                if let Some(peer) = self.attribute(addr, link_nonce) {
                    self.note_received(peer, now);
                }
            }
            PunchDatagram::Ack { seq } => {
                let Some(&peer) = self.addr_index.get(&addr) else {
                    return;
                };
                self.note_received(peer, now);
                if let Some(link) = self.links.get_mut(&peer) {
                    link.arq_tx.on_ack(seq);
                }
            }
            PunchDatagram::Reliable { seq, payload } => {
                let Some(&peer) = self.addr_index.get(&addr) else {
                    return;
                };
                self.note_received(peer, now);
                self.on_reliable(peer, addr, seq, payload);
            }
            PunchDatagram::Unreliable {
                stream_id,
                seq,
                blocks,
            } => {
                let Some(&peer) = self.addr_index.get(&addr) else {
                    return;
                };
                self.note_received(peer, now);
                let _ = self.events_tx.send(P2pEvent::StreamChunk {
                    from: peer,
                    stream_id,
                    seq,
                    blocks,
                });
            }
        }
        self.sync_statuses();
    }

    /// Handles one rendezvous reply from the server's UDP socket: our own
    /// public address, as observed from outside. A change means the NAT
    /// mapping we've been advertising is gone, so every link that isn't
    /// already up is re-signalled with the new list. Links that *are* up
    /// are deliberately left alone - on a symmetric NAT the server-facing
    /// mapping is independent of the peer-facing ones, so a change here
    /// says nothing about whether a working peer path still works, and
    /// `LINK_IDLE_TIMEOUT` catches it if it doesn't.
    pub fn on_rendezvous(&mut self, addr: SocketAddr, msg: RendezvousMessage) {
        if addr != self.server_udp_addr {
            return;
        }
        let RendezvousMessage::BindingResponse { token, observed } = msg else {
            return;
        };
        if token != self.reflexive_token || self.reflexive == Some(observed) {
            return;
        }
        self.reflexive = Some(observed);
        let candidates = self.local_candidates();
        let stale: Vec<UserId> = self
            .links
            .iter()
            .filter(|(_, l)| !matches!(l.state, PeerLinkState::Active { .. }))
            .map(|(&id, _)| id)
            .collect();
        for peer in stale {
            let link_nonce = random_token();
            if let Some(link) = self.links.get_mut(&peer) {
                link.link_nonce = link_nonce;
                link.state = PeerLinkState::Requested {
                    started: Instant::now(),
                };
            }
            let _ = self.events_tx.send(P2pEvent::Signal {
                peer,
                candidates: candidates.clone(),
                link_nonce,
            });
        }
        self.sync_statuses();
    }

    /// Which peer a datagram from `addr` carrying `link_nonce` belongs to:
    /// an address we already know, or failing that a link currently being
    /// established under that nonce (see `on_datagram`'s doc).
    fn attribute(&self, addr: SocketAddr, link_nonce: u64) -> Option<UserId> {
        if let Some(&peer) = self.addr_index.get(&addr) {
            return Some(peer);
        }
        self.links.iter().find_map(|(&id, link)| {
            (link.link_nonce == link_nonce && link.establishing()).then_some(id)
        })
    }

    /// Records `addr` as somewhere this peer can be reached - a
    /// peer-reflexive candidate, in ICE's terms. A no-op for an address
    /// already known, or once the link is holding `CANDIDATES_MAX`.
    fn adopt_candidate(&mut self, peer: UserId, addr: SocketAddr) {
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        if link.candidates.contains(&addr) || link.candidates.len() >= CANDIDATES_MAX {
            return;
        }
        link.candidates.push(addr);
        self.addr_index.insert(addr, peer);
    }

    fn note_received(&mut self, peer: UserId, now: Instant) {
        if let Some(link) = self.links.get_mut(&peer)
            && let PeerLinkState::Active { last_received, .. } = &mut link.state
        {
            *last_received = now;
        }
    }

    fn on_pong(&mut self, peer: UserId, addr: SocketAddr, link_nonce: u64, now: Instant) {
        let socket = self.socket.clone();
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        if link.link_nonce != link_nonce || matches!(link.state, PeerLinkState::Active { .. }) {
            return;
        }
        link.state = PeerLinkState::Active {
            addr,
            last_sent: now,
            last_received: now,
        };
        link.attempts = 0;
        // Lock the address the answer actually came from, which under NAT
        // is often not any address that was advertised.
        if !link.candidates.contains(&addr) {
            link.candidates.push(addr);
        }
        self.addr_index.insert(addr, peer);
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        let pending = std::mem::take(&mut link.pending);
        for (_, payload) in pending {
            Self::transmit_reliable(&socket, link, &payload);
        }
    }

    fn on_reliable(&mut self, peer: UserId, addr: SocketAddr, seq: u32, payload: Vec<u8>) {
        send_dgram(
            &self.socket,
            &encode_dgram(&PunchDatagram::Ack { seq }),
            addr,
        );
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        for delivered in link.arq_rx.receive(seq, payload) {
            let Ok(p2p_payload) = proto::decode::<P2pPayload>(&delivered) else {
                continue;
            };
            self.emit_payload(peer, p2p_payload);
        }
    }

    fn emit_payload(&self, from: UserId, payload: P2pPayload) {
        let event = match payload {
            P2pPayload::Envelope { channel, envelope } => P2pEvent::Message {
                channel,
                from,
                envelope,
            },
            P2pPayload::FileOffer {
                channel,
                stream_id,
                envelope,
            } => P2pEvent::FileOffer {
                channel,
                from,
                stream_id,
                envelope,
            },
            P2pPayload::StreamStart { channel, stream_id } => P2pEvent::StreamStart {
                channel,
                from,
                stream_id,
            },
            P2pPayload::StreamKeySetup { stream_id, setup } => P2pEvent::StreamKeySetup {
                from,
                stream_id,
                setup,
            },
            P2pPayload::StreamEnd { stream_id, .. } => P2pEvent::StreamEnd { from, stream_id },
            P2pPayload::FileAccept { stream_id } => P2pEvent::FileAccepted { stream_id },
            P2pPayload::FileReject { stream_id } => P2pEvent::FileRejected { stream_id },
            P2pPayload::FileChunk {
                stream_id,
                seq,
                blocks,
            } => P2pEvent::FileChunk {
                from,
                stream_id,
                seq,
                blocks,
            },
            P2pPayload::FileEnd { stream_id } => P2pEvent::FileEnd { from, stream_id },
            P2pPayload::OtpEnvelope {
                channel,
                seq,
                envelope,
            } => P2pEvent::OtpMessage {
                channel,
                from,
                seq,
                envelope,
            },
            P2pPayload::OtpFileOffer {
                channel,
                stream_id,
                seq,
                envelope,
            } => P2pEvent::OtpFileOffer {
                channel,
                from,
                stream_id,
                seq,
                envelope,
            },
            P2pPayload::OtpDeliveryAck { seq } => P2pEvent::OtpDeliveryAck { from, seq },
            P2pPayload::OtpFileContentSeq { stream_id, seq } => {
                P2pEvent::OtpFileContentSeq { from, stream_id, seq }
            }
            P2pPayload::OtpVoiceOffer {
                stream_id,
                seq,
                envelope,
            } => P2pEvent::OtpVoiceOffer {
                from,
                stream_id,
                seq,
                envelope,
            },
            P2pPayload::DeviceIdAnnounce { envelope } => {
                P2pEvent::DeviceIdAnnounce { from, envelope }
            }
            P2pPayload::CallInvite { call_id, channel } => P2pEvent::CallInvite {
                channel,
                from,
                call_id,
            },
            P2pPayload::CallAccept { call_id } => P2pEvent::CallAccept { from, call_id },
            P2pPayload::CallReject { call_id } => P2pEvent::CallReject { from, call_id },
            P2pPayload::CallEnd { call_id } => P2pEvent::CallEnd { from, call_id },
        };
        let _ = self.events_tx.send(event);
    }

    /// Driven off `session.rs`'s existing ~150ms ticker: refreshes our own
    /// reflexive candidate, resends `Ping` for every link still punching,
    /// retransmits unacked reliable frames, sends keepalives on idle
    /// `Active` links, notices links that have gone quiet, and re-signals
    /// links whose retry backoff has elapsed.
    pub fn tick(&mut self) {
        self.tick_at(Instant::now());
    }

    /// `tick`, taking the current time explicitly - a test seam so a punch
    /// timeout or a retry backoff (seconds to a minute) can be exercised
    /// with an injected future `Instant` instead of a real sleep.
    pub fn tick_at(&mut self, now: Instant) {
        self.refresh_reflexive(now);

        let mut lost: Vec<(UserId, String)> = Vec::new();
        for (&peer, link) in self.links.iter_mut() {
            match &mut link.state {
                PeerLinkState::Requested { started } => {
                    if now.duration_since(*started) >= SIGNAL_TIMEOUT {
                        lost.push((peer, "the peer never answered the candidate exchange".into()));
                    }
                }
                PeerLinkState::Punching { started } => {
                    if now.duration_since(*started) >= PUNCH_TIMEOUT {
                        lost.push((peer, "could not establish a direct connection".into()));
                    }
                }
                PeerLinkState::Active {
                    addr,
                    last_sent,
                    last_received,
                } => {
                    let addr = *addr;
                    if now.duration_since(*last_received) >= LINK_IDLE_TIMEOUT {
                        lost.push((peer, "the direct connection went quiet".into()));
                        continue;
                    }
                    match link.arq_tx.due_for_retransmit(now) {
                        Ok(due) => {
                            for (seq, payload) in due {
                                send_dgram(
                                    &self.socket,
                                    &encode_dgram(&PunchDatagram::Reliable { seq, payload }),
                                    addr,
                                );
                                *last_sent = now;
                            }
                        }
                        Err(()) => lost.push((peer, "peer stopped responding".into())),
                    }
                    if link.arq_rx.failed() {
                        lost.push((peer, "too many out-of-order messages".into()));
                    }
                    if now.duration_since(*last_sent) >= KEEPALIVE_INTERVAL {
                        send_dgram(
                            &self.socket,
                            &encode_dgram(&PunchDatagram::Keepalive {
                                link_nonce: link.link_nonce,
                            }),
                            addr,
                        );
                        *last_sent = now;
                    }
                }
                PeerLinkState::Lost { .. } => {}
            }
        }
        for (peer, reason) in lost {
            self.mark_lost(peer, reason, now);
        }

        self.expire_pending(now);
        self.retry_due(now);

        // Re-send pings for every link still being established, every tick
        // - cheap, small packets, and simpler than tracking a separate
        // per-link retry timer at ~150ms tick granularity. `Requested` is
        // included, not just `Punching`: a retry keeps the candidates the
        // previous attempt learned, and probing those straight away can
        // reopen the link without waiting for the signalling round trip to
        // come back.
        let punching: Vec<UserId> = self
            .links
            .iter()
            .filter(|(_, l)| l.establishing())
            .map(|(&id, _)| id)
            .collect();
        for peer in punching {
            self.send_pings(peer);
        }
        self.sync_statuses();
    }

    /// Asks the server's rendezvous socket for our public address again.
    /// The reply arrives asynchronously through `on_rendezvous`; this is
    /// also what keeps the NAT mapping behind that address from expiring
    /// while nothing else is going on.
    fn refresh_reflexive(&mut self, now: Instant) {
        if now.duration_since(self.last_reflexive_probe) < REFLEXIVE_REFRESH_INTERVAL {
            return;
        }
        self.last_reflexive_probe = now;
        self.reflexive_token = random_token();
        let request = encode_dgram_rendezvous(&RendezvousMessage::BindingRequest {
            token: self.reflexive_token,
        });
        send_dgram(&self.socket, &request, self.server_udp_addr);
    }

    /// Moves a link out of service and schedules its next attempt. Never
    /// terminal and never destructive: queued content stays queued, and
    /// the candidates learned so far stay as a starting point for the
    /// retry.
    fn mark_lost(&mut self, peer: UserId, reason: String, now: Instant) {
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        if matches!(link.state, PeerLinkState::Lost { .. }) {
            return;
        }
        let delay = retry_delay(link.attempts);
        link.attempts = link.attempts.saturating_add(1);
        link.state = PeerLinkState::Lost {
            reason,
            retry_at: now + delay,
        };
    }

    /// Drops content that has been undeliverable for `PENDING_MAX_AGE` and
    /// tells the user once per link that it happened. Independent of link
    /// state on purpose: what matters is how long the *content* has been
    /// stuck, not which phase the link is in this instant.
    fn expire_pending(&mut self, now: Instant) {
        let mut expired: Vec<(UserId, usize)> = Vec::new();
        for (&peer, link) in self.links.iter_mut() {
            let mut count = 0;
            while let Some((queued_at, _)) = link.pending.front() {
                if now.duration_since(*queued_at) < PENDING_MAX_AGE {
                    break;
                }
                link.pending.pop_front();
                count += 1;
            }
            if count > 0 {
                expired.push((peer, count));
            }
        }
        for (peer, count) in expired {
            let reason = match self.links.get(&peer).map(|l| &l.state) {
                Some(PeerLinkState::Lost { reason, .. }) => reason.clone(),
                _ => "no direct connection".to_string(),
            };
            let _ = self.events_tx.send(P2pEvent::LinkFailed {
                peer,
                reason: format!(
                    "{reason} - {count} message{} not delivered",
                    if count == 1 { "" } else { "s" }
                ),
            });
        }
    }

    /// Re-signals every `Lost` link whose backoff has elapsed. This is
    /// what makes establishment continuous: as long as `forget` hasn't
    /// removed the peer, a link keeps trying for as long as they're around.
    fn retry_due(&mut self, now: Instant) {
        let due: Vec<UserId> = self
            .links
            .iter()
            .filter(|(_, l)| match &l.state {
                PeerLinkState::Lost { retry_at, .. } => now >= *retry_at,
                _ => false,
            })
            .map(|(&id, _)| id)
            .collect();
        for peer in due {
            let (candidates, link_nonce) = self.restart_attempt(peer, now);
            let _ = self.events_tx.send(P2pEvent::Signal {
                peer,
                candidates,
                link_nonce,
            });
        }
    }

    /// Emits one `LinkStatusChanged` per link whose status actually moved
    /// since the last time the UI was told.
    fn sync_statuses(&mut self) {
        for (&peer, link) in self.links.iter_mut() {
            let status = link.status();
            if status != link.reported {
                link.reported = status;
                let _ = self
                    .events_tx
                    .send(P2pEvent::LinkStatusChanged { peer, status });
            }
        }
    }

    /// Routes one background-thread-originated `P2pOutbound` message to
    /// the right link(s). Voice chunks/end assume their link is already
    /// `Active` (voice is never queued - see `LinkReadiness`) and are
    /// simply dropped otherwise; file chunks/end use the same reliable
    /// path text does.
    pub fn dispatch_outbound(&mut self, msg: P2pOutbound) {
        match msg {
            P2pOutbound::ChannelVoiceChunk {
                stream_id,
                seq,
                per_recipient,
            } => {
                for (id, blocks) in per_recipient {
                    self.send_unreliable_voice(id, stream_id, seq, blocks);
                }
            }
            P2pOutbound::CallVoiceChunk {
                call_id,
                seq,
                per_recipient,
            } => {
                for (id, blocks) in per_recipient {
                    self.send_unreliable_voice(id, call_id, seq, blocks);
                }
            }
            P2pOutbound::DirectVoiceChunk {
                to,
                stream_id,
                seq,
                blocks,
            } => {
                self.send_unreliable_voice(to, stream_id, seq, blocks);
            }
            P2pOutbound::VoiceEnd {
                stream_id,
                duration_ms,
                recipients,
            } => {
                for id in recipients {
                    self.send_reliable_or_queue(
                        id,
                        P2pPayload::StreamEnd {
                            stream_id,
                            duration_ms,
                        },
                    );
                }
            }
            P2pOutbound::FileChunk {
                to,
                stream_id,
                seq,
                blocks,
            } => {
                self.send_reliable_or_queue(
                    to,
                    P2pPayload::FileChunk {
                        stream_id,
                        seq,
                        blocks,
                    },
                );
            }
            P2pOutbound::FileEnd { to, stream_id } => {
                self.send_reliable_or_queue(to, P2pPayload::FileEnd { stream_id });
            }
        }
    }

    /// Whether the link to `peer` is currently `Active` - a test/diagnostic
    /// helper (see `test/p2p_test.rs`'s loopback handshake test); ordinary
    /// send paths go through `ensure_link`'s `LinkReadiness` instead.
    pub fn is_active(&self, peer: UserId) -> bool {
        matches!(
            self.links.get(&peer).map(|l| &l.state),
            Some(PeerLinkState::Active { .. })
        )
    }

    /// This link's current user-visible status, or `None` if no link to
    /// `peer` has ever been started.
    pub fn status(&self, peer: UserId) -> Option<LinkStatus> {
        self.links.get(&peer).map(|l| l.status())
    }

    /// How many addresses this link currently knows to probe - relayed
    /// candidates plus any peer-reflexive ones adopted off the wire.
    pub fn candidate_count(&self, peer: UserId) -> usize {
        self.links.get(&peer).map_or(0, |l| l.candidates.len())
    }

    /// How much content is queued waiting for this link to open.
    pub fn pending_count(&self, peer: UserId) -> usize {
        self.links.get(&peer).map_or(0, |l| l.pending.len())
    }

    /// The token the most recent `BindingRequest` went out with - what a
    /// matching `BindingResponse` has to echo.
    pub fn reflexive_token(&self) -> u64 {
        self.reflexive_token
    }

    /// Everything we currently advertise to peers: this machine's own
    /// interface addresses plus, if it has been learned, our public one.
    pub fn local_candidate_list(&self) -> Vec<SocketAddr> {
        self.local_candidates()
    }

    /// The address an `Active` link is actually using - the one the peer's
    /// `Pong` came from, which under NAT is frequently not any address
    /// either side advertised. A diagnostic (and test) helper.
    pub fn active_addr(&self, peer: UserId) -> Option<SocketAddr> {
        match self.links.get(&peer).map(|l| &l.state) {
            Some(PeerLinkState::Active { addr, .. }) => Some(*addr),
            _ => None,
        }
    }

    /// Drops a peer's link entirely (stops its keepalives and its retries,
    /// frees its ARQ state) - called when `UserLeft`/`UserOffline` removes
    /// the last shared channel/DM relationship with them. The one way a
    /// link stops being retried.
    pub fn forget(&mut self, peer: UserId) {
        self.links.remove(&peer);
        self.addr_index.retain(|_, &mut p| p != peer);
    }
}

/// The delay before the `attempts`-th consecutive retry: doubling from
/// `RETRY_BASE`, capped at `RETRY_MAX`.
fn retry_delay(attempts: u32) -> Duration {
    let shifted = RETRY_BASE
        .checked_mul(1u32.checked_shl(attempts.min(16)).unwrap_or(u32::MAX))
        .unwrap_or(RETRY_MAX);
    shifted.min(RETRY_MAX)
}

/// One datagram out of the session's UDP socket, with the failures that
/// actually mean something surfaced rather than dropped on the floor.
///
/// Every send here used to be a bare `let _ = try_send_to(..)`. That is
/// right for the two failures punching produces by design - a momentarily
/// full send buffer, and the ICMP port-unreachable that comes back from
/// probing a candidate address nobody is listening on - but it also
/// silently swallowed the ones that mean a datagram can *never* leave:
/// a payload past the maximum datagram size, or an address of the family
/// this socket isn't bound to. Neither is recoverable and neither showed
/// up anywhere, in a subsystem whose whole failure mode is "nothing
/// arrives and nothing says why".
///
/// Reported at most once per error kind per session (`WARNED`), so a
/// permanently broken path can't scribble over the TUI on every tick.
fn send_dgram(socket: &UdpSocket, bytes: &[u8], to: SocketAddr) {
    let Err(e) = socket.try_send_to(bytes, to) else {
        return;
    };
    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::ConnectionRefused) {
        return;
    }
    static WARNED: OnceLock<Mutex<HashSet<ErrorKind>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    // A poisoned lock here would mean another thread panicked mid-warning;
    // that is not a reason to lose this one, so recover and carry on.
    let mut warned = warned.lock().unwrap_or_else(|e| e.into_inner());
    if warned.insert(e.kind()) {
        eprintln!(
            "aloo: direct-link UDP send to {to} failed ({e}) - {} byte datagram, \
             suppressing further reports of this kind",
            bytes.len()
        );
    }
}

fn encode_dgram(dgram: &PunchDatagram) -> Vec<u8> {
    proto::encode(dgram).unwrap_or_default()
}

/// A fresh random token for a punch attempt or rendezvous request - reuses
/// `crypto::random_bytes` (backed by `OsRng`) rather than adding a `rand`
/// dependency just for one `u64` per link.
fn random_token() -> u64 {
    let bytes = crate::crypto::random_bytes(8);
    u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))
}

/// This machine's own (interface address, `local_port`) pairs as host
/// candidates - works as-is for same-LAN peers, and loopback is
/// deliberately not filtered out since it's exactly what makes two
/// same-machine sessions (tests, or two local clients) punch trivially.
///
/// Only addresses matching the socket's own family are kept (`want_ipv6`).
/// The session's socket is bound to one family for its whole life, and a
/// `send_to` across families fails outright at the syscall - so an address
/// of the other family is not a worse candidate, it is an impossible one,
/// and advertising it only spends a slot of the peer's `CANDIDATES_MAX`.
fn host_candidates(local_port: u16, want_ipv6: bool) -> Vec<SocketAddr> {
    if_addrs::get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .map(|iface| iface.ip())
                .filter(|ip| ip.is_ipv6() == want_ipv6)
                .map(|ip| SocketAddr::new(ip, local_port))
                .collect()
        })
        .unwrap_or_default()
}

/// Best-effort STUN-Binding-style discovery of this client's own
/// server-reflexive (public) address at session start: asks the server's
/// UDP rendezvous socket up to `RENDEZVOUS_ATTEMPTS` times, waiting
/// `RENDEZVOUS_TIMEOUT` for each `BindingResponse`. `None` if none of them
/// is answered (no outbound UDP allowed, a server whose UDP port isn't
/// published, ...) - callers proceed with host candidates alone, and
/// `PeerLinkManager::refresh_reflexive` keeps asking for the rest of the
/// session in case the answer changes.
async fn learn_reflexive_candidate(
    socket: &UdpSocket,
    server_udp_addr: SocketAddr,
) -> Option<SocketAddr> {
    for _ in 0..RENDEZVOUS_ATTEMPTS {
        let token: u64 = random_token();
        let request = encode_dgram_rendezvous(&RendezvousMessage::BindingRequest { token });
        let _ = socket.send_to(&request, server_udp_addr).await;

        let mut buf = [0u8; 512];
        let deadline = tokio::time::Instant::now() + RENDEZVOUS_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Ok(Ok((n, from))) = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
            else {
                break;
            };
            if from != server_udp_addr {
                continue;
            }
            let Ok(RendezvousMessage::BindingResponse {
                token: got_token,
                observed,
            }) = proto::decode(&buf[..n])
            else {
                continue;
            };
            if got_token == token {
                return Some(observed);
            }
        }
    }
    None
}

fn encode_dgram_rendezvous(msg: &RendezvousMessage) -> Vec<u8> {
    proto::encode(msg).unwrap_or_default()
}

/// Spawned once per session (mirrors `session.rs`'s TCP-reader task):
/// forwards every subsequent datagram on `socket` to `PeerLinkManager` via
/// `raw_tx`, for the main select loop to process with `on_datagram`/
/// `on_rendezvous`. Kept as a thin decode-and-forward task rather than
/// driving `PeerLinkManager` itself, so all link-state mutation stays on
/// the single-threaded session loop. Which decoder to use is decided by
/// source address (see `InboundDatagram`).
pub fn spawn_receive_loop(
    socket: Arc<UdpSocket>,
    server_udp_addr: SocketAddr,
    raw_tx: UnboundedSender<(SocketAddr, InboundDatagram)>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, addr) = match socket.recv_from(&mut buf).await {
                Ok(ok) => ok,
                // A single failed `recv_from` is never fatal: punching
                // pings candidates nobody may be listening on, which can
                // surface here as a transient error (e.g. ICMP
                // port-unreachable). Exiting would drop `raw_tx` and end
                // the *entire client session* over one peer's bad moment,
                // so log and keep listening - same "degrade, never take
                // the session down" principle as every optional subsystem.
                Err(e) => {
                    eprintln!(
                        "aloo: direct-link UDP receive error (ignoring, still listening): {e}"
                    );
                    // Safety net against a permanently-broken socket
                    // erroring instantly forever, which would busy-spin
                    // this task at 100% of a core; transient errors don't
                    // notice 50ms.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let decoded = if addr == server_udp_addr {
                proto::decode::<RendezvousMessage>(&buf[..n])
                    .ok()
                    .map(InboundDatagram::Rendezvous)
            } else {
                proto::decode::<PunchDatagram>(&buf[..n])
                    .ok()
                    .map(InboundDatagram::Punch)
            };
            let Some(decoded) = decoded else { continue };
            if raw_tx.send((addr, decoded)).is_err() {
                // The receiving end (`session.rs`'s `p2p_raw_rx`) is gone,
                // meaning the whole session has already ended - nothing
                // left for this loop to deliver to.
                break;
            }
        }
    });
}
