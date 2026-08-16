//! Direct client<->client transport: server-assisted UDP hole punching, plus
//! the reliable (text/file, `crate::client::p2p_reliable`) and unreliable (voice)
//! delivery built on top of the resulting punched link. See
//! `docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section.
//!
//! The server is never in the data path: it only ever relays the initial
//! candidate exchange (`ClientMessage::RequestPeerLink`/
//! `ServerMessage::PeerCandidates`) and helps a client learn its own
//! server-reflexive address (`p2p_proto::RendezvousMessage`, a stateless
//! STUN-Binding analog). Everything in this module runs entirely
//! client-side. There is deliberately no relay fallback: if a direct path
//! can't be punched open, sends against that peer fail visibly
//! (`P2pEvent::LinkFailed`) rather than silently degrading to a relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWrite;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;

use crate::p2p_proto::{P2pPayload, PunchDatagram, RendezvousMessage};
use crate::client::p2p_reliable::{ArqReceiver, ArqSender};
use crate::proto::{self, ClientMessage, UserId};

/// Total time a link is allowed to spend either waiting for the peer's
/// candidates or actively punching before it's declared unreachable. There
/// is no relay fallback, so this is also, in effect, the worst-case delay
/// before a first send to a brand-new peer either succeeds or fails.
pub const PUNCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Comfortably under the ~30s UDP NAT mapping timeout common on consumer
/// routers - driven off the same tick as retransmit scanning, not its own
/// timer.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// How long a `Failed` link stays failed before a fresh send is allowed to
/// retry the whole handshake - stops a dead peer from re-triggering a punch
/// attempt on every keystroke.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);
/// How long to wait for the server's UDP rendezvous socket to answer a
/// server-reflexive `BindingRequest` at session start, before giving up and
/// gathering host candidates only.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_millis(800);

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
    /// A link to `peer` failed to establish (punch timed out) or died
    /// (retransmit budget exhausted) while something was pending against
    /// it - there is no relay fallback, so this is a terminal failure the
    /// UI must surface, not something to retry silently.
    LinkFailed {
        peer: UserId,
        reason: String,
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

/// What a caller gets back from `ensure_link`: whether it's safe to send
/// right now, or why not. Voice (never queued, PROTOCOL.md §11.6-style
/// partial delivery) checks this directly and excludes a `Pending`/`Failed`
/// recipient from the stream; text/file offers instead go through
/// `PeerLinkManager::send_reliable_or_queue`, which queues on `Pending` and
/// flushes automatically once the link goes `Active`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkReadiness {
    Active,
    Pending,
    Failed(String),
}

enum PeerLinkState {
    /// We've asked the server to relay our candidates to this peer and are
    /// waiting for their reply (their own `RequestPeerLink`, relayed back
    /// as `ServerMessage::PeerCandidates`).
    Requested {
        started: Instant,
    },
    /// We know the peer's candidates and are exchanging `Ping`/`Pong` with
    /// all of them, looking for one that works in both directions.
    Punching {
        started: Instant,
        candidates: Vec<SocketAddr>,
    },
    Active {
        addr: SocketAddr,
        last_sent: Instant,
    },
    Failed {
        since: Instant,
        reason: String,
    },
}

struct PeerLink {
    /// This side's own token for its current attempt - included in every
    /// `Ping` we send, and the only thing an incoming `Pong` is checked
    /// against (each side validates only its own outbound probes; see
    /// `p2p_proto::PunchDatagram`'s doc).
    my_nonce: u64,
    state: PeerLinkState,
    /// Reliable sends queued while not yet `Active` - flushed in order the
    /// moment the link becomes `Active`. Voice never populates this (see
    /// `LinkReadiness`'s doc).
    pending: Vec<P2pPayload>,
    arq_tx: ArqSender,
    arq_rx: ArqReceiver,
}

impl PeerLink {
    fn new(my_nonce: u64, state: PeerLinkState) -> Self {
        Self {
            my_nonce,
            state,
            pending: Vec::new(),
            arq_tx: ArqSender::new(),
            arq_rx: ArqReceiver::new(),
        }
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
    local_candidates: Vec<SocketAddr>,
    links: HashMap<UserId, PeerLink>,
    /// Every candidate address we've been told belongs to a given peer,
    /// so an inbound datagram (identified only by its source address) can
    /// be attributed to the right link.
    addr_index: HashMap<SocketAddr, UserId>,
    events_tx: UnboundedSender<P2pEvent>,
}

impl PeerLinkManager {
    /// Binds the session's one UDP socket, learns this client's own
    /// candidate addresses (host interfaces plus, best-effort, a
    /// server-reflexive one via `server_udp_addr`), and returns the manager
    /// plus the socket handle the caller must hand to `spawn_receive_loop`.
    /// A failure to learn the reflexive candidate (old server, UDP blocked
    /// outbound, ...) is not fatal - punching just proceeds with host
    /// candidates alone, which is still enough on a shared LAN and fails
    /// visibly (no silent relay fallback) otherwise.
    pub async fn bind(
        bind_addr: SocketAddr,
        server_udp_addr: SocketAddr,
        events_tx: UnboundedSender<P2pEvent>,
    ) -> std::io::Result<(Self, Arc<UdpSocket>)> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_port = socket.local_addr()?.port();
        let mut candidates = host_candidates(local_port);

        if let Some(reflexive) = learn_reflexive_candidate(&socket, server_udp_addr).await
            && !candidates.contains(&reflexive)
        {
            candidates.push(reflexive);
        }

        Ok((
            Self {
                socket: socket.clone(),
                local_candidates: candidates,
                links: HashMap::new(),
                addr_index: HashMap::new(),
                events_tx,
            },
            socket,
        ))
    }

    /// Ensures a link toward `peer` exists (starting one, via `wr`, if this
    /// is the first time `peer` is addressed - or restarting one whose
    /// previous attempt has finished its `FAILURE_COOLDOWN`), and reports
    /// whether it's safe to send on it right now.
    pub async fn ensure_link(
        &mut self,
        wr: &mut (impl AsyncWrite + Unpin),
        peer: UserId,
    ) -> LinkReadiness {
        if let Some(link) = self.links.get(&peer) {
            match &link.state {
                PeerLinkState::Active { .. } => return LinkReadiness::Active,
                PeerLinkState::Failed { since, reason } => {
                    if since.elapsed() < FAILURE_COOLDOWN {
                        return LinkReadiness::Failed(reason.clone());
                    }
                    // Cooldown elapsed: fall through and start a fresh attempt.
                }
                _ => return LinkReadiness::Pending,
            }
        }
        let my_nonce = random_token();
        let _ = proto::write_message(
            wr,
            &ClientMessage::RequestPeerLink {
                peer,
                candidates: self.local_candidates.clone(),
                link_nonce: my_nonce,
            },
        )
        .await;
        self.links.insert(
            peer,
            PeerLink::new(
                my_nonce,
                PeerLinkState::Requested {
                    started: Instant::now(),
                },
            ),
        );
        LinkReadiness::Pending
    }

    /// Handles an incoming `ServerMessage::PeerCandidates`: if we already
    /// asked `from` for a link, this is their reply and punching starts
    /// now; otherwise it's an implicit invite - we reply in kind (our own
    /// `RequestPeerLink`, echoing `link_nonce`) and start punching too. A
    /// stray/duplicate candidate list for an already-`Active` link changes
    /// nothing (no need to redo a working link).
    pub async fn on_peer_candidates(
        &mut self,
        wr: &mut (impl AsyncWrite + Unpin),
        from: UserId,
        candidates: Vec<SocketAddr>,
        link_nonce: u64,
    ) {
        if matches!(
            self.links.get(&from).map(|l| &l.state),
            Some(PeerLinkState::Active { .. })
        ) {
            return;
        }
        if !self.links.contains_key(&from) {
            let _ = proto::write_message(
                wr,
                &ClientMessage::RequestPeerLink {
                    peer: from,
                    candidates: self.local_candidates.clone(),
                    link_nonce,
                },
            )
            .await;
            self.links.insert(
                from,
                PeerLink::new(
                    link_nonce,
                    PeerLinkState::Requested {
                        started: Instant::now(),
                    },
                ),
            );
        }
        for addr in &candidates {
            self.addr_index.insert(*addr, from);
        }
        if let Some(link) = self.links.get_mut(&from) {
            link.state = PeerLinkState::Punching {
                started: Instant::now(),
                candidates: candidates.clone(),
            };
        }
        self.send_pings(from);
    }

    fn send_pings(&self, peer: UserId) {
        let Some(link) = self.links.get(&peer) else {
            return;
        };
        let PeerLinkState::Punching { candidates, .. } = &link.state else {
            return;
        };
        let dgram = encode_dgram(&PunchDatagram::Ping {
            link_nonce: link.my_nonce,
        });
        for addr in candidates {
            let _ = self.socket.try_send_to(&dgram, *addr);
        }
    }

    /// Sends `payload` to `peer` now if the link is `Active`, or queues it
    /// to be sent automatically once it becomes `Active`. Callers must have
    /// already called `ensure_link` for `peer` (this never starts a new
    /// link itself) - a `payload` for a peer with no link state at all is
    /// simply dropped, since there is nothing to flush it later.
    pub fn send_reliable_or_queue(&mut self, peer: UserId, payload: P2pPayload) {
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        if matches!(link.state, PeerLinkState::Active { .. }) {
            Self::transmit_reliable(&self.socket, link, &payload);
        } else {
            link.pending.push(payload);
        }
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
        let PeerLinkState::Active { addr, last_sent } = &mut link.state else {
            return;
        };
        let dgram = encode_dgram(&PunchDatagram::Unreliable {
            stream_id,
            seq,
            blocks,
        });
        let _ = self.socket.try_send_to(&dgram, *addr);
        *last_sent = Instant::now();
    }

    fn transmit_reliable(socket: &UdpSocket, link: &mut PeerLink, payload: &P2pPayload) {
        let PeerLinkState::Active { addr, last_sent } = &mut link.state else {
            return;
        };
        let bytes = proto::encode(payload).unwrap_or_default();
        let seq = link.arq_tx.send(bytes.clone());
        let dgram = encode_dgram(&PunchDatagram::Reliable {
            seq,
            payload: bytes,
        });
        let _ = socket.try_send_to(&dgram, *addr);
        *last_sent = Instant::now();
    }

    /// Feeds one received UDP datagram, already demuxed to `addr` by the
    /// caller's receive loop, into the relevant link. A datagram from an
    /// address not associated with any peer (an unsolicited probe, a stale
    /// candidate from a link that's since moved on, ...) is silently
    /// ignored.
    pub fn on_datagram(&mut self, addr: SocketAddr, dgram: PunchDatagram) {
        let Some(&peer) = self.addr_index.get(&addr) else {
            return;
        };
        match dgram {
            PunchDatagram::Ping { link_nonce } => {
                let _ = self
                    .socket
                    .try_send_to(&encode_dgram(&PunchDatagram::Pong { link_nonce }), addr);
            }
            PunchDatagram::Pong { link_nonce } => self.on_pong(peer, addr, link_nonce),
            PunchDatagram::Keepalive { .. } => {}
            PunchDatagram::Ack { seq } => {
                if let Some(link) = self.links.get_mut(&peer) {
                    link.arq_tx.on_ack(seq);
                }
            }
            PunchDatagram::Reliable { seq, payload } => self.on_reliable(peer, addr, seq, payload),
            PunchDatagram::Unreliable {
                stream_id,
                seq,
                blocks,
            } => {
                let _ = self.events_tx.send(P2pEvent::StreamChunk {
                    from: peer,
                    stream_id,
                    seq,
                    blocks,
                });
            }
        }
    }

    fn on_pong(&mut self, peer: UserId, addr: SocketAddr, link_nonce: u64) {
        let Some(link) = self.links.get_mut(&peer) else {
            return;
        };
        if link.my_nonce != link_nonce || matches!(link.state, PeerLinkState::Active { .. }) {
            return;
        }
        link.state = PeerLinkState::Active {
            addr,
            last_sent: Instant::now(),
        };
        let pending = std::mem::take(&mut link.pending);
        for payload in pending {
            Self::transmit_reliable(&self.socket, link, &payload);
        }
    }

    fn on_reliable(&mut self, peer: UserId, addr: SocketAddr, seq: u32, payload: Vec<u8>) {
        let _ = self
            .socket
            .try_send_to(&encode_dgram(&PunchDatagram::Ack { seq }), addr);
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
        };
        let _ = self.events_tx.send(event);
    }

    /// Driven off `session.rs`'s existing ~150ms ticker: resends `Ping` for
    /// every still-`Punching` link, retransmits unacked reliable frames,
    /// sends keepalives on idle `Active` links, and fails links that have
    /// either punched or retransmitted past their budget - emitting
    /// `P2pEvent::LinkFailed` for each, per the no-relay-fallback rule.
    pub fn tick(&mut self) {
        self.tick_at(Instant::now());
    }

    /// `tick`, taking the current time explicitly - a test seam so a punch
    /// timeout (`PUNCH_TIMEOUT`, several seconds) can be exercised with an
    /// injected future `Instant` instead of a real sleep.
    pub fn tick_at(&mut self, now: Instant) {
        let mut failed: Vec<(UserId, String)> = Vec::new();

        for (&peer, link) in self.links.iter_mut() {
            match &mut link.state {
                PeerLinkState::Requested { started } | PeerLinkState::Punching { started, .. } => {
                    if now.duration_since(*started) >= PUNCH_TIMEOUT {
                        failed.push((peer, "could not establish a direct connection".to_string()));
                    }
                }
                PeerLinkState::Active { addr, last_sent } => {
                    let addr = *addr;
                    match link.arq_tx.due_for_retransmit(now) {
                        Ok(due) => {
                            for (seq, payload) in due {
                                let _ = self.socket.try_send_to(
                                    &encode_dgram(&PunchDatagram::Reliable { seq, payload }),
                                    addr,
                                );
                                *last_sent = now;
                            }
                        }
                        Err(()) => failed.push((peer, "peer stopped responding".to_string())),
                    }
                    if link.arq_rx.failed() {
                        failed.push((peer, "too many out-of-order messages".to_string()));
                    }
                    if now.duration_since(*last_sent) >= KEEPALIVE_INTERVAL {
                        let _ = self.socket.try_send_to(
                            &encode_dgram(&PunchDatagram::Keepalive {
                                link_nonce: link.my_nonce,
                            }),
                            addr,
                        );
                        *last_sent = now;
                    }
                }
                PeerLinkState::Failed { .. } => {}
            }
        }
        for (peer, reason) in failed {
            // Only worth telling the user about if something was genuinely
            // stuck waiting on this link (a queued reliable send). A
            // pre-warmed link failing (punching starts on `UserJoined`,
            // long before anyone talks) is unremarkable for channel-mates
            // nobody addresses - a banner for each would be noise. Voice's
            // own `recording_failed` still fires independently when
            // someone actually records to an unreachable peer.
            let had_pending = self
                .links
                .get(&peer)
                .is_some_and(|link| !link.pending.is_empty());
            if let Some(link) = self.links.get_mut(&peer) {
                link.pending.clear();
                link.state = PeerLinkState::Failed {
                    since: now,
                    reason: reason.clone(),
                };
            }
            if had_pending {
                let _ = self.events_tx.send(P2pEvent::LinkFailed { peer, reason });
            }
        }
        // Re-send pings for every link still punching, every tick - cheap,
        // small packets, and simpler than tracking a separate per-link
        // retry timer at ~150ms tick granularity.
        let punching: Vec<UserId> = self
            .links
            .iter()
            .filter(|(_, l)| matches!(l.state, PeerLinkState::Punching { .. }))
            .map(|(&id, _)| id)
            .collect();
        for peer in punching {
            self.send_pings(peer);
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

    /// Drops a peer's link entirely (stops its keepalives, frees its ARQ
    /// state) - called when `UserLeft`/`UserOffline` removes the last
    /// shared channel/DM relationship with them.
    pub fn forget(&mut self, peer: UserId) {
        self.links.remove(&peer);
        self.addr_index.retain(|_, &mut p| p != peer);
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
fn host_candidates(local_port: u16) -> Vec<SocketAddr> {
    if_addrs::get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .map(|iface| SocketAddr::new(iface.ip(), local_port))
                .collect()
        })
        .unwrap_or_default()
}

/// Best-effort STUN-Binding-style discovery of this client's own
/// server-reflexive (public) address: sends a `BindingRequest` to the
/// server's UDP rendezvous socket and waits up to `RENDEZVOUS_TIMEOUT` for
/// its `BindingResponse`. `None` on any failure (old server with no UDP
/// rendezvous socket, no outbound UDP allowed, no reply in time, ...) -
/// callers proceed with host candidates alone in that case.
async fn learn_reflexive_candidate(
    socket: &UdpSocket,
    server_udp_addr: SocketAddr,
) -> Option<SocketAddr> {
    let token: u64 = random_token();
    let request = encode_dgram_rendezvous(&RendezvousMessage::BindingRequest { token });
    let _ = socket.send_to(&request, server_udp_addr).await;

    let mut buf = [0u8; 512];
    let deadline = tokio::time::Instant::now() + RENDEZVOUS_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let Ok(Ok((n, from))) = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await
        else {
            return None;
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

fn encode_dgram_rendezvous(msg: &RendezvousMessage) -> Vec<u8> {
    proto::encode(msg).unwrap_or_default()
}

/// Spawned once per session (mirrors `session.rs`'s TCP-reader task):
/// forwards every subsequent datagram on `socket` to `PeerLinkManager` via
/// `raw_tx`, for the main select loop to process with `on_datagram`. Kept
/// as a thin decode-and-forward task rather than driving `PeerLinkManager`
/// itself, so all link-state mutation stays on the single-threaded session
/// loop.
pub fn spawn_receive_loop(
    socket: Arc<UdpSocket>,
    raw_tx: UnboundedSender<(SocketAddr, PunchDatagram)>,
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
            let Ok(dgram) = proto::decode::<PunchDatagram>(&buf[..n]) else {
                continue;
            };
            if raw_tx.send((addr, dgram)).is_err() {
                // The receiving end (`session.rs`'s `p2p_raw_rx`) is gone,
                // meaning the whole session has already ended - nothing
                // left for this loop to deliver to.
                break;
            }
        }
    });
}
