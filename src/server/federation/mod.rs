//! Server federation: linking two or more `aloo` servers into one shared
//! nickname/channel namespace (docs/PROTOCOL.md's federation section).
//!
//! A federation link is server-to-server, mutually authenticated by
//! durable PQ-hybrid identity (`handshake` - no TLS, no certificates;
//! entirely separate from `server_ssl`'s one-way client-facing TLS), and
//! carries only identity/routing metadata (`proto::FederationMessage`) -
//! never message content, matching the doctrine `crate::server` states for
//! the client-facing protocol too.
//!
//! `FederationConfig` is the state every connection handler and
//! federation link reads/writes: `directory` (`directory::FederationDirectory`,
//! who owns which nickname/channel), `peer_senders` (the live outbound
//! channel to each currently-linked peer, keyed by that peer's own
//! `self_id` - what `broadcast`/`send_to_peer` write to), and
//! `join_proxy_waiters` (correlates an outgoing `JoinProxyRequest` with
//! its eventual `JoinProxyResponse`, which arrives asynchronously on
//! whatever task is reading that peer's link).
//!
//! `FederationContext` adds what only the federation *link* side needs on
//! top of that: read/write access to this server's own `Registry` and
//! `mail::MailStore`, and its `Senders` map - the same three things
//! `crate::server::mod`'s client-facing connection handler already has,
//! needed here so a federation message can join a local client to a
//! mirrored channel, deliver forwarded mail to one, or relay a receipt to
//! one, exactly as if it had arrived over that client's own connection.
//!
//! Cross-server private-channel join proxying (this module) lets a client
//! become a real member of a channel owned by a different federated
//! server, with that server enforcing its password/ban/allowlist exactly
//! as it would locally. What it does *not* do is let that client actually
//! exchange messages with a member connected to a *different* server: two
//! members of the same federated channel can only punch a direct
//! peer-to-peer link (`crate::client::p2p`) if they share one server's
//! `Registry`, since `RequestPeerLink`/`PeerCandidates` are routed purely
//! by local `UserId` today. Two local clients of the *same* server who
//! both join a channel homed elsewhere work exactly like an ordinary
//! local channel - they get real presence and can link to each other -
//! but a member on a different server is invisible to them and vice
//! versa, until the peer-link relay itself is federated too (not yet
//! implemented - see docs/PROTOCOL.md §18.5).

pub mod directory;
pub mod handshake;
pub mod proto;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::control::{ControlReader, ControlWriter};
use crate::crypto::pq::{PqPrivateBundle, PqPublicBundle};
use crate::server::{Registry, Senders, mail};
use crate::settings::FederationPeerConfig;
use directory::{FederationDirectory, Ownership};
use handshake::{FederationTrust, HandshakeError};
use proto::{FederationMessage, JoinProxyOutcome};

/// The live outbound channel to each currently-linked peer, keyed by that
/// peer's own `server_federation_id`. A link that has none yet (still
/// dialing, or dropped) simply has no entry - `broadcast`/`send_to_peer`
/// skip it, the same "best effort, not a guaranteed delivery" contract
/// `Senders` already has for client connections.
type PeerSenders = Arc<Mutex<HashMap<String, LiveLink>>>;

/// One currently-live link to a peer.
struct LiveLink {
    /// Distinguishes this link from any other to the same peer, so the
    /// task that registered it can tell "my entry is still here" from
    /// "something displaced me and this entry is somebody else's" when it
    /// comes to tear down. Without that check a displaced task's teardown
    /// would remove the entry belonging to the link that replaced it.
    link_id: u64,
    sender: mpsc::UnboundedSender<FederationMessage>,
    /// Whether this is the *canonical* direction for this pair - see
    /// `connection_is_canonical`. A non-canonical link is kept only while
    /// no canonical one exists, and is displaced the moment one does.
    canonical: bool,
    /// Fires when this link has been displaced, so the task holding its
    /// socket stops promptly instead of reading a connection nothing will
    /// use again. Both ends displace the same connection (the rule is
    /// computed from data both of them have), so both drop their halves
    /// and the socket closes properly. `notify_one` rather than
    /// `notify_waiters` because it latches: displacement can happen before
    /// the link's own task reaches the point of waiting, and a missed
    /// wakeup would leave the socket held until it died of its own accord.
    /// Correctness does not rest on it arriving, though - `link_id` is
    /// what keeps a late teardown from touching the wrong entry.
    displaced: Arc<tokio::sync::Notify>,
}

/// Whether a connection between `self_id` and `peer_id` is the one the
/// pair should keep, given which side dialed it: the canonical direction
/// is "whichever server's id sorts first did the dialing".
///
/// Both servers dial each other, so two connections can exist at once -
/// most likely at startup, when neither has a live link yet to skip the
/// attempt for. Resolving that by "first one to register wins" is not
/// enough, because each end races independently: it is entirely possible
/// for each side to keep the connection *it* dialed and discard the one it
/// accepted, leaving two half-alive links and no working one. This rule is
/// computed from `(self_id, peer_id, who dialed)` - which both ends of a
/// given connection agree on - so both ends always reach the same verdict
/// about the same socket.
///
/// The alternative considered and rejected was to let only the lower-id
/// server dial at all. That resolves the race just as well but quietly
/// breaks any deployment where the *higher*-id server is the only publicly
/// reachable one (the other behind NAT), which an operator can then only
/// fix by renaming a server - and ids are written into the persisted
/// nickname directory, so renaming is not free.
fn connection_is_canonical(self_id: &str, peer_id: &str, i_dialed: bool) -> bool {
    let dialer_sorts_first = if i_dialed { self_id < peer_id } else { peer_id < self_id };
    dialer_sorts_first
}

/// How long a dropped link waits before redialing, and the starting point
/// `dial_peer` backs off from while a peer stays unreachable. Short,
/// because a link that has just ended is usually a peer restarting and
/// should be picked straight back up.
pub const REDIAL_INTERVAL: Duration = Duration::from_secs(10);

/// The ceiling `dial_peer` backs off to for a peer that stays unreachable.
/// A peer that is down for a weekend should not be dialed - or logged
/// about - 8,000 times a day, but it should still come back on its own
/// within a few minutes of returning, with no operator action.
pub const MAX_REDIAL_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// How often an otherwise-idle link sends a `Ping`, and how long a link
/// may hear *nothing at all* before it is assumed dead.
///
/// Without this, a link that stops carrying traffic in a way TCP never
/// reports - the peer's host vanishing, a NAT or firewall quietly dropping
/// its state, a router rebooted mid-session - is indistinguishable from a
/// link that simply has nothing to say. The reader parks forever, the
/// sender looks live, and every message routed through it is dropped in
/// silence. The client-facing protocol has had exactly this for the same
/// reason since §4.1; the federation link had nothing.
///
/// The timeout is comfortably more than twice the interval, so a single
/// lost ping (or a slow moment) never tears down a healthy link.
pub const FEDERATION_PING_INTERVAL: Duration = Duration::from_secs(30);
pub const FEDERATION_IDLE_TIMEOUT: Duration = Duration::from_secs(100);

/// How long a client waits for a federation peer to answer a
/// `JoinProxyRequest` before giving up - a peer link that is down, or a
/// home server that never replies, must not hang a `JoinChannel` forever.
const JOIN_PROXY_TIMEOUT: Duration = Duration::from_secs(8);

/// Everything a federated server needs besides the sockets themselves.
/// Built once by `main.rs::run_server` from `~/.aloo/settings` and shared
/// (via `Arc`) by the federation listener, every peer-dialing task, and
/// every ordinary client connection that needs to check or announce
/// nickname/channel ownership, or proxy a join.
pub struct FederationConfig {
    /// This server's own label in the federation - how its directory
    /// entries and gossip messages name it as an owner.
    pub self_id: String,
    pub listen_addr: SocketAddr,
    /// What peers should dial to reach this server - `<host>:<port>`, a
    /// `String` rather than a `SocketAddr` since it is purely informational
    /// (put in `Hello`, never itself connected to) and a hostname is a
    /// perfectly ordinary thing to advertise even though `listen_addr`
    /// itself must be a real bind address.
    pub advertise_addr: String,
    /// `server_federation_client_addr` - where an ordinary *client*
    /// should connect for this server, announced to peers in the
    /// handshake so each one can name it to a user who logged in on the
    /// wrong server (§18.4). Every other address here is the
    /// server-to-server port, which no client ever speaks to.
    pub client_addr: Option<String>,
    /// What each peer announced as *its* own client-facing address, learned
    /// at handshake time and kept only while known - the login redirect
    /// falls back to naming the peer's federation id when a peer's
    /// operator never configured one.
    peer_client_addrs: Arc<Mutex<HashMap<String, String>>>,
    /// This server's own durable federation identity - what it signs every
    /// peer-link handshake transcript with (`handshake::handshake`).
    /// Generated once at `server_federation_identity` and never rotated;
    /// its public half is what an operator hands to peers out of band.
    pub identity: PqPrivateBundle,
    pub peers: Vec<FederationPeerConfig>,
    /// The pinned public identity of every configured peer, loaded once at
    /// startup from `FederationPeerConfig::public_key_path` - what
    /// `handshake::handshake` checks a connection's signature against. A
    /// peer whose key cannot be loaded is a startup error (an operator who
    /// configured a peer meant to link to it), the same "refuse to start
    /// rather than silently skip" stance `server_ssl`'s certificate takes.
    peer_keys: Vec<(String, PqPublicBundle)>,
    pub directory: Arc<Mutex<FederationDirectory>>,
    peer_senders: PeerSenders,
    /// Every `JoinProxyRequest` this server is still waiting on an answer
    /// for, keyed by the id it went out under, and carrying **which peer
    /// it went to**: `apply_incoming` resolves (and removes) one only when
    /// the matching `JoinProxyResponse` arrives on that same peer's link.
    /// The request id alone is not enough to key on - it is this server's
    /// own counter from 1, so it is entirely predictable, and without the
    /// peer check any *other* linked peer could answer a request that was
    /// never addressed to it and have its verdict believed. A forged
    /// `Joined` would mirror a channel it does not own into this server
    /// locally, admitting a client the real owner never checked a
    /// password, ban or allowlist for.
    join_proxy_waiters: Arc<Mutex<HashMap<u64, (String, oneshot::Sender<JoinProxyOutcome>)>>>,
    next_request_id: AtomicU64,
    /// Hands each link a `LiveLink::link_id` - see there for why a link
    /// needs to be able to recognise its own registration.
    next_link_id: AtomicU64,
    /// How often an idle link pings, and how long it may hear nothing
    /// before being torn down - `FEDERATION_PING_INTERVAL`/
    /// `FEDERATION_IDLE_TIMEOUT` in production. Adjustable only so a test
    /// can watch a link stay up across several ping cycles without
    /// spending a real minute and a half doing it.
    ping_interval: Duration,
    idle_timeout: Duration,
}

impl FederationConfig {
    /// Loads every configured peer's pinned public key eagerly (failing
    /// fast, like `server_ssl`'s certificate load, if one cannot be read)
    /// and builds the config. `identity` is this server's own durable
    /// signing key, generated/loaded by the caller
    /// (`crypto::pq::ensure_bundle_at`/`load_private_bundle` against
    /// `server_federation_identity`).
    pub fn new(
        self_id: String,
        listen_addr: SocketAddr,
        advertise_addr: String,
        client_addr: Option<String>,
        identity: PqPrivateBundle,
        peers: Vec<FederationPeerConfig>,
        directory: FederationDirectory,
    ) -> Result<Self, String> {
        let peer_keys = peers
            .iter()
            .map(|p| {
                let path = crate::platform::expand_tilde(&p.public_key_path);
                let key = crate::crypto::pq::load_public_bundle(&path).map_err(|e| {
                    format!(
                        "cannot read public key for federation peer '{}' at {}: {e}",
                        p.peer_id,
                        path.display()
                    )
                })?;
                Ok((p.peer_id.clone(), key))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self {
            self_id,
            listen_addr,
            advertise_addr,
            client_addr,
            peer_client_addrs: Arc::new(Mutex::new(HashMap::new())),
            identity,
            peers,
            peer_keys,
            directory: Arc::new(Mutex::new(directory)),
            peer_senders: Arc::new(Mutex::new(HashMap::new())),
            join_proxy_waiters: Arc::new(Mutex::new(HashMap::new())),
            next_request_id: AtomicU64::new(1),
            next_link_id: AtomicU64::new(1),
            ping_interval: FEDERATION_PING_INTERVAL,
            idle_timeout: FEDERATION_IDLE_TIMEOUT,
        })
    }

    /// Shortens this server's liveness timings, for a test that needs to
    /// observe several ping cycles without waiting out the real ones.
    /// `idle_timeout` must stay comfortably more than twice
    /// `ping_interval`, or a single slow moment tears down a healthy link.
    pub fn with_liveness(mut self, ping_interval: Duration, idle_timeout: Duration) -> Self {
        self.ping_interval = ping_interval;
        self.idle_timeout = idle_timeout;
        self
    }

    /// Where an ordinary *client* should be told to connect for peer
    /// `peer_id` - what a wrong-server login redirect names (§18.4).
    ///
    /// Deliberately **not** derived from `server_federation_peer`'s
    /// host/port: that is the server-to-server port, which no client ever
    /// speaks to, so naming it sent users somewhere nothing would answer.
    /// The only address that can be right is the one that peer announces
    /// for itself (`server_federation_client_addr`, carried in the signed
    /// part of its `Hello`). `None` when that peer never configured one,
    /// or has not linked yet - the caller then names the server rather
    /// than an address it would be guessing at.
    pub async fn peer_client_addr(&self, peer_id: &str) -> Option<String> {
        self.peer_client_addrs.lock().await.get(peer_id).cloned()
    }

    fn trust(&self) -> FederationTrust<'_> {
        FederationTrust {
            self_id: &self.self_id,
            own_identity: &self.identity,
            peers: &self.peer_keys,
        }
    }

    /// Sends `msg` to peer `peer_id` specifically, `false` if there is no
    /// live link to it right now.
    pub async fn send_to_peer(&self, peer_id: &str, msg: FederationMessage) -> bool {
        let senders = self.peer_senders.lock().await;
        senders.get(peer_id).is_some_and(|link| link.sender.send(msg).is_ok())
    }

    /// Whether a link to `peer_id` is already up - `dial_peer` checks this
    /// before every redial attempt so two servers configured to dial each
    /// other don't keep opening (and immediately closing) a redundant
    /// second connection every `REDIAL_INTERVAL` for as long as the first
    /// one - established from either direction - stays healthy.
    async fn has_live_link(&self, peer_id: &str) -> bool {
        self.peer_senders.lock().await.contains_key(peer_id)
    }

    fn fresh_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends a `JoinProxyRequest` for `channel` to whichever peer the
    /// directory says owns it, and awaits that peer's `JoinProxyResponse`
    /// (matched by request id in `apply_incoming`) up to
    /// `JOIN_PROXY_TIMEOUT`. `Err` covers every way this can fail to
    /// produce a real answer: the channel isn't known to be owned by any
    /// peer at all, there is no live link to that peer right now, or the
    /// peer never answered in time.
    pub async fn request_join_proxy(
        &self,
        channel: &str,
        joiner_nickname: &str,
        password: Option<&str>,
        joiner_public_key_der: Vec<u8>,
        joiner_key_mode: crate::proto::KeyMode,
    ) -> Result<JoinProxyOutcome, String> {
        let owner = match self.directory.lock().await.owner_of_channel(channel) {
            Some(info) if info.owner != self.self_id => info.owner.clone(),
            _ => return Err("this channel is not known to belong to a federated peer".to_string()),
        };
        let request_id = self.fresh_request_id();
        let (tx, rx) = oneshot::channel();
        self.join_proxy_waiters.lock().await.insert(request_id, (owner.clone(), tx));
        let sent = self
            .send_to_peer(
                &owner,
                FederationMessage::JoinProxyRequest {
                    request_id,
                    channel: channel.to_string(),
                    joiner_nickname: joiner_nickname.to_string(),
                    password: password.map(str::to_string),
                    joiner_public_key_der,
                    joiner_key_mode,
                },
            )
            .await;
        if !sent {
            self.join_proxy_waiters.lock().await.remove(&request_id);
            return Err(format!(
                "federated server '{owner}' is not currently reachable - try again later"
            ));
        }
        log_federation_event(&owner, event::PROXIED_JOIN_CHANNEL_TO_SERVER);
        match tokio::time::timeout(JOIN_PROXY_TIMEOUT, rx).await {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(_)) | Err(_) => {
                self.join_proxy_waiters.lock().await.remove(&request_id);
                Err(format!("federated server '{owner}' did not answer in time"))
            }
        }
    }

    /// Best-effort: tells the channel's owning peer that `nickname` left
    /// (or disconnected from) `channel` - nothing waits on this, so a peer
    /// that is briefly unreachable simply never learns of a departure it
    /// will anyway never act on again (there is no `UserId` tied to it).
    pub async fn notify_leave_if_remote(&self, channel: &str, nickname: &str) {
        let owner = match self.directory.lock().await.owner_of_channel(channel) {
            Some(info) if info.owner != self.self_id => Some(info.owner.clone()),
            _ => None,
        };
        if let Some(owner) = owner {
            self.send_to_peer(
                &owner,
                FederationMessage::LeaveProxyNotice {
                    channel: channel.to_string(),
                    nickname: nickname.to_string(),
                },
            )
            .await;
        }
    }

    /// Forwards `mail` to the federated peer that owns `mail.to`, if any -
    /// a no-op when `to` is unowned, owned by this server, or owned by a
    /// peer with no live link right now (the mail is already durably
    /// stored locally either way; `sync_mail_with_peer` retries this
    /// automatically the next time that peer's link comes up).
    pub async fn forward_mail_if_remote(&self, mail: &mail::StoredMail) {
        let owner = match self.directory.lock().await.owner_of_nickname(&mail.to) {
            Some(Ownership::Owned(owner)) if *owner != self.self_id => Some(owner.clone()),
            _ => None,
        };
        if let Some(owner) = owner {
            self.send_to_peer(&owner, FederationMessage::MailForward { mail: mail.clone() }).await;
            log_federation_event(&owner, event::OTP_MAIL_FORWARDED);
        }
    }

    /// Relays a delivery receipt to the federated peer that owns
    /// `receipt.from`, if any - the mirror of `forward_mail_if_remote` for
    /// the acknowledgement flowing the other way.
    pub async fn relay_receipt_if_remote(&self, receipt: &mail::DeliveredReceipt) {
        let owner = match self.directory.lock().await.owner_of_nickname(&receipt.from) {
            Some(Ownership::Owned(owner)) if *owner != self.self_id => Some(owner.clone()),
            _ => None,
        };
        if let Some(owner) = owner {
            self.send_to_peer(
                &owner,
                FederationMessage::MailDeliveredReceipt {
                    mail_id: receipt.mail_id.clone(),
                    from: receipt.from.clone(),
                    to: receipt.to.clone(),
                },
            )
            .await;
        }
    }
}

/// Sends `msg` to every currently-linked peer - best effort, same as the
/// client-facing `dispatch`/`Senders`: a peer with no live link right now
/// simply misses it (it will catch up on its next `DirectorySnapshot`,
/// for a directory-affecting message). Logs `event` once per peer it
/// actually reached.
pub async fn broadcast(config: &FederationConfig, msg: FederationMessage, event: &'static str) {
    let senders = config.peer_senders.lock().await;
    for (peer_id, link) in senders.iter() {
        if link.sender.send(msg.clone()).is_ok() {
            log_federation_event(peer_id, event);
        }
    }
}

/// Records that channel `name` (owned by this server) was just removed -
/// `/delete-channel`, a superadmin's removal (single or via account
/// removal), or the inactivity sweep, all funnel through here - and
/// gossips it to every linked peer.
pub async fn announce_channel_removed(config: &FederationConfig, name: &str) {
    config.directory.lock().await.remove_channel(name, &config.self_id);
    broadcast(
        config,
        FederationMessage::ChannelRemoved { name: name.to_string(), owner: config.self_id.clone() },
        event::CHANNEL_DELETED,
    )
    .await;
}

/// Records that nickname `nickname` (registered on this server) was just
/// removed - a superadmin's `/remove-account` - and gossips it to every
/// linked peer, so the name stops being permanently blocked for
/// re-registration federation-wide.
pub async fn announce_nickname_removed(config: &FederationConfig, nickname: &str) {
    let _ = config.directory.lock().await.remove_nickname(nickname, &config.self_id);
    broadcast(
        config,
        FederationMessage::NicknameRemoved { nickname: nickname.to_string(), owner: config.self_id.clone() },
        event::NICK_DELETED,
    )
    .await;
}

/// The fixed vocabulary of federation activity this server prints to its
/// own console (`log_federation_event`) - deliberately just an event name
/// and which peer it concerns, never a nickname, channel name, or any
/// message payload, so watching a server's logs can never itself become a
/// side channel for the things federation is otherwise careful not to
/// leak (docs/SECURITY.md's federation trust note).
pub mod event {
    pub const LINK_UP: &str = "LINK_UP";
    pub const LINK_DOWN: &str = "LINK_DOWN";
    pub const NICKS_GOSSIP: &str = "NICKS_GOSSIP";
    pub const NICK_DELETED: &str = "NICK_DELETED";
    pub const CHANNEL_GOSSIP: &str = "CHANNEL_GOSSIP";
    pub const CHANNEL_DELETED: &str = "CHANNEL_DELETED";
    pub const CHANNEL_MEMBER_JOINED: &str = "CHANNEL_MEMBER_JOINED";
    pub const CHANNEL_MEMBER_LEFT: &str = "CHANNEL_MEMBER_LEFT";
    pub const PROXIED_JOIN_CHANNEL_TO_SERVER: &str = "PROXIED_JOIN_CHANNEL_TO_SERVER";
    pub const PROXIED_JOIN_CHANNEL_FROM_SERVER: &str = "PROXIED_JOIN_CHANNEL_FROM_SERVER";
    pub const OTP_MAIL_FORWARDED: &str = "OTP_MAIL_FORWARDED";
    pub const OTP_MAIL_RECEIVED: &str = "OTP_MAIL_RECEIVED";
    pub const OTP_MAIL_DELIVERED: &str = "OTP_MAIL_DELIVERED";
}

/// One console line for an operationally-interesting federation event -
/// see the `event` module doc for what belongs here and why it never
/// carries more than an event name and a peer label. `peer_id` is the
/// federation label the peer's own settings gave it
/// (`server_federation_id`) - the same one every directory entry and
/// other federation log line already names a peer by, not a resolved DNS
/// name. Routed through `log_info!`, never a bare `println!`/`eprintln!`
/// (see `crate::log`'s own doc for why).
fn log_federation_event(peer_id: &str, event: &str) {
    crate::log_info!("Federated server {peer_id} - {event}");
}

/// Everything a federation *link* needs beyond `FederationConfig` itself:
/// access to this server's own client-facing state, so a message arriving
/// over the link can act on it exactly as a client connection would -
/// join a local client to a mirrored channel, deliver forwarded mail to
/// one, or dispatch a relayed receipt to one.
#[derive(Clone)]
pub struct FederationContext {
    pub config: Arc<FederationConfig>,
    pub registry: Arc<Mutex<Registry>>,
    pub senders: Senders,
    pub mail_store: Arc<mail::MailStore>,
}

/// Binds `config.listen_addr` and accepts federation peer connections
/// forever, alongside dialing every configured peer - what `serve_tcp`
/// spawns once when `ServerOptions.federation` is set. A single peer being
/// unreachable, or one connection failing its handshake, is not fatal and
/// only stalls that one link.
pub async fn run(ctx: FederationContext) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(ctx.config.listen_addr).await?;
    serve(listener, ctx).await
}

/// `run`, minus binding the listener itself - what a test binds to an
/// ephemeral port (`:0`) and discovers the real address from, the same
/// split `crate::server::serve`/`serve_with_rendezvous` already give the
/// client-facing listener for exactly that reason.
pub async fn serve(listener: tokio::net::TcpListener, ctx: FederationContext) -> std::io::Result<()> {
    for peer in ctx.config.peers.clone() {
        tokio::spawn(dial_peer(ctx.clone(), peer));
    }
    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_peer_link(tcp, ctx, false).await {
                crate::log_warn!("federation link from {peer_addr} ended: {e}");
            }
        });
    }
}

/// Redials `peer` forever, `REDIAL_INTERVAL` apart, until `run_peer_link`
/// holds a connection open - the same "degrade, never take the task down"
/// shape `udp_rendezvous_loop` uses, applied to a link instead of a
/// socket. Skips the dial entirely on a tick where a link to `peer` is
/// already live - established from either direction - so two servers
/// configured to dial each other don't spend forever opening a redundant
/// second connection every tick just to have it rejected.
///
/// Only ever dials when this server's own id sorts *before* `peer.peer_id`
/// - never the reverse. Two servers each configured to dial the other
/// would otherwise sometimes both succeed at once (most likely at startup,
/// when neither has a live link yet to skip the attempt for): each such
/// connection then wins the `senders`-map race independently on its own
/// two ends, so it is entirely possible for *both* physical connections to
/// end up "confirmed" on the end that dialed it while "superseded" on the
/// end that accepted it - two half-alive links instead of one real one.
/// Comparing ids the same way the handshake's own transcript does
/// sidesteps this rather than trying to detect and repair it after the
/// fact: with only one side ever initiating, at most one connection
/// between any pair can exist at a time, so the dedup this file already
/// has only ever has to break a tie against a genuinely stale link (one
/// whose peer has not yet noticed its socket died), never a fresh race.
async fn dial_peer(ctx: FederationContext, peer: FederationPeerConfig) {
    let mut wait = REDIAL_INTERVAL;
    loop {
        if ctx.config.has_live_link(&peer.peer_id).await {
            // Linked - nothing to do, and nothing to back off from.
            wait = REDIAL_INTERVAL;
        } else {
            match dial_once(&ctx, &peer).await {
                // A link that came up and later ended is not a failure to
                // reach the peer: start the next attempt at the short
                // interval rather than wherever the backoff had climbed to.
                Ok(()) => wait = REDIAL_INTERVAL,
                Err(e) => {
                    // Only the first failure of a run is worth a line. A
                    // peer that is simply down otherwise fills the log with
                    // thousands of identical warnings a day, which is how a
                    // log stops being read at all.
                    if wait == REDIAL_INTERVAL {
                        crate::log_warn!(
                            "could not reach federation peer '{}' at {}:{}: {e} (retrying, \
                             quietly, until it answers)",
                            peer.peer_id,
                            peer.host,
                            peer.port
                        );
                    }
                    wait = next_redial_wait(wait);
                }
            }
        }
        // Jitter, so a set of servers restarted together (one host
        // rebooting, a compose stack coming up) does not settle into
        // dialing each other in lockstep forever.
        tokio::time::sleep(with_jitter(wait)).await;
    }
}

/// The next delay to wait after a failed dial: doubling, up to a ceiling.
pub fn next_redial_wait(current: Duration) -> Duration {
    (current * 2).min(MAX_REDIAL_INTERVAL)
}

/// Spreads a redial delay by up to a quarter either way.
pub fn with_jitter(base: Duration) -> Duration {
    let span = base.as_millis() as u64 / 2;
    if span == 0 {
        return base;
    }
    let offset = u64::from_be_bytes(
        crate::crypto::random_bytes(8).try_into().expect("random_bytes(8) is 8 bytes"),
    ) % span;
    base.saturating_sub(Duration::from_millis(span / 2)) + Duration::from_millis(offset)
}

async fn dial_once(ctx: &FederationContext, peer: &FederationPeerConfig) -> std::io::Result<()> {
    let tcp = TcpStream::connect((peer.host.as_str(), peer.port)).await?;
    run_peer_link(tcp, ctx.clone(), true).await
}

/// One federation link's lifetime, either direction: runs the PQ-hybrid
/// mutual handshake (`handshake::handshake` - authenticates the peer and
/// switches the link to encrypted), deduplicates against an already-live
/// link to the same peer, exchanges directory snapshots, reconciles any
/// mail owed to/from that peer, then relays gossip and proxy traffic until
/// the link drops.
async fn run_peer_link(tcp: TcpStream, ctx: FederationContext, i_dialed: bool) -> std::io::Result<()> {
    let (rd, wr) = tokio::io::split(tcp);
    let mut rd = ControlReader::new(rd);
    let mut wr = ControlWriter::new(wr);

    let peer_id = match handshake::handshake(
        &mut rd,
        &mut wr,
        &ctx.config.trust(),
        &ctx.config.advertise_addr,
        ctx.config.client_addr.as_deref(),
    )
    .await
    {
        Ok(announcement) => {
            // Only now that the signature covering it has been checked is
            // any of what the peer announced worth believing.
            if let Some(client_addr) = announcement.client_addr {
                ctx.config
                    .peer_client_addrs
                    .lock()
                    .await
                    .insert(announcement.peer_id.clone(), client_addr);
            }
            announcement.peer_id
        }
        Err(HandshakeError::ClaimsSelf(peer_id)) => {
            // Never a link worth keeping: `peer_senders` is keyed by id,
            // and inserting under this server's own id would make
            // `send_to_peer` for a genuine peer of that same name
            // (impossible, ids are meant to be unique) or this server's
            // own broadcasts ambiguous.
            crate::log_warn!(
                "federation link claims to be this server's own id ('{peer_id}') - refusing; \
                 check server_federation_id and server_federation_peer for a misconfiguration"
            );
            return Ok(());
        }
        Err(HandshakeError::Closed) => {
            // The peer hung up mid-handshake. On a connection *we* dialed
            // that is worth saying out loud: much the likeliest cause is
            // asymmetric configuration - we list them, they do not list
            // us, so their side refuses us as an unknown peer and closes.
            // Silence here left an operator with a federation that simply
            // never linked and nothing at all in either log to say why.
            if i_dialed {
                crate::log_warn!(
                    "federation peer closed the connection during the handshake - check that it                      lists this server in its own server_federation_peer lines, with this                      server's public key"
                );
            }
            return Ok(());
        }
        Err(e) => {
            crate::log_warn!("federation handshake failed: {e}");
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<FederationMessage>();
    // Kept by this task so it can send its own keepalives without going
    // back through the senders map (whose entry may already belong to a
    // link that displaced this one).
    let ping_tx = tx.clone();
    let link_id = ctx.config.next_link_id.fetch_add(1, Ordering::Relaxed);
    let canonical = connection_is_canonical(&ctx.config.self_id, &peer_id, i_dialed);
    let displaced = Arc::new(tokio::sync::Notify::new());
    {
        // One logical link per peer pair. Both sides dial, so two
        // connections can exist at once; which one survives has to be a
        // decision both ends of a given socket reach identically, or they
        // each keep a different one and neither works. That decision is
        // `connection_is_canonical`, applied here:
        //
        // - nothing registered yet: keep this one, canonical or not. A
        //   single connection is better than none, which is what makes a
        //   peer reachable in only one direction (NAT, a firewall) work.
        // - something registered, and this one is canonical while that one
        //   is not: displace it. The other end of *that* socket reaches the
        //   same verdict about it, so both sides let it go.
        // - anything else: this connection is the redundant one, so drop it.
        let mut senders = ctx.config.peer_senders.lock().await;
        match senders.get(&peer_id) {
            Some(existing) if existing.canonical || !canonical => return Ok(()),
            Some(existing) => existing.displaced.notify_one(),
            None => {}
        }
        senders.insert(
            peer_id.clone(),
            LiveLink { link_id, sender: tx, canonical, displaced: displaced.clone() },
        );
    }
    log_federation_event(&peer_id, event::LINK_UP);

    let (nicknames, channels) = ctx.config.directory.lock().await.snapshot();
    let owned_channels: Vec<String> = channels
        .iter()
        .filter(|info| info.owner == ctx.config.self_id)
        .map(|info| info.name.clone())
        .collect();
    let _ = wr.send(&FederationMessage::DirectorySnapshot { nicknames, channels }).await;
    // Presence gossip is live-only, so a peer linking up now has missed
    // every join that happened before it - and, if this is a relink, has
    // deliberately forgotten what it knew. Only the home server can say
    // who is in one of its channels, so send that here, once, per channel
    // it owns that anyone is actually in.
    for channel in owned_channels {
        let members = ctx.registry.lock().await.federated_membership_of(&channel, &ctx.config.self_id);
        if !members.is_empty() {
            let _ = wr.send(&FederationMessage::ChannelMembership { channel, members }).await;
        }
    }
    sync_mail_with_peer(&ctx, &peer_id).await;

    let mut writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if wr.send(&msg).await.is_err() {
                break;
            }
        }
    });

    let mut displaced_by_another_link = false;
    let mut last_heard = std::time::Instant::now();
    let mut ping = tokio::time::interval(ctx.config.ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // the first tick is immediate; skip it
    loop {
        tokio::select! {
            // Any message at all - a `Ping` included - proves the link is
            // alive, which is what `last_heard` records.
            incoming = rd.recv::<FederationMessage>() => match incoming {
                Ok(Some(msg)) => {
                    last_heard = std::time::Instant::now();
                    apply_incoming(&ctx, &peer_id, msg).await;
                }
                Ok(None) => break,
                Err(e) => {
                    crate::log_warn!("federation link to '{peer_id}' failed: {e}");
                    break;
                }
            },
            _ = ping.tick() => {
                // Silence is measured from the last thing *received*, not
                // from the last time round this loop. Wrapping the read in
                // a timeout instead looks equivalent and is not: `select!`
                // drops and rebuilds the branches it did not take, so this
                // timer's own ticks would restart the read timeout every
                // interval and it could never elapse - the link would be
                // declared healthy precisely because *we* were still
                // talking, which is the one thing that proves nothing.
                if last_heard.elapsed() > ctx.config.idle_timeout {
                    crate::log_warn!(
                        "federation link to '{peer_id}' went silent - dropping it so it redials"
                    );
                    break;
                }
                // Best effort, exactly like every other send here: if the
                // peer is gone, the check above is what notices.
                let _ = ping_tx.send(FederationMessage::Ping);
            }
            // The writer gave up - its half of the socket refused a send,
            // so this link is dead in the send direction and therefore
            // dead. Without watching for it, only the *reader* ever tears
            // a link down, and a half-open socket (the peer's host gone,
            // a NAT dropping its state, a router reboot) never gives the
            // reader anything: writes fail, reads block forever, and the
            // now-useless `tx` stays in `peer_senders` - so `has_live_link`
            // keeps telling `dial_peer` not to redial while every message
            // routed through it is silently dropped. No `LINK_DOWN`, no
            // reconnect, no diagnostic, until the process restarts.
            //
            // Cancelling the in-flight `rd.recv()` here is safe precisely
            // because we leave immediately: `ControlReader::recv` is not
            // cancel-safe (a partially read frame is lost), but nothing
            // reads this stream again - it is dropped on the way out.
            _ = &mut writer_task => {
                crate::log_warn!(
                    "federation link to '{peer_id}' could not be written to - dropping it so it redials"
                );
                break;
            }
            // A better connection to the same peer took this one's place
            // (see the registration above). Stop reading a socket nothing
            // will use again, rather than parking on it forever.
            _ = displaced.notified() => {
                displaced_by_another_link = true;
                break;
            }
        }
    }

    // Only tear down an entry this task still owns. A displaced link's
    // entry already belongs to the connection that replaced it, and
    // removing that would take down the working link and strand the pair
    // until the next redial - the notification above is best effort, so
    // this check, not that one, is what actually makes it safe.
    let still_ours = {
        let mut senders = ctx.config.peer_senders.lock().await;
        if senders.get(&peer_id).is_some_and(|link| link.link_id == link_id) {
            senders.remove(&peer_id);
            true
        } else {
            false
        }
    };
    if !still_ours || displaced_by_another_link {
        writer_task.abort();
        return Ok(());
    }
    // Presence learned from this peer dies with the link - see
    // `ChannelsRegistry::forget_members_of_server` for why holding onto it
    // would be worse than forgetting it.
    let departed = ctx.registry.lock().await.forget_federated_members_of(&peer_id);
    crate::server::dispatch(&ctx.senders, departed).await;
    log_federation_event(&peer_id, event::LINK_DOWN);
    writer_task.abort();
    Ok(())
}

/// Sweeps this server's own mail store for anything owed to or from
/// `peer_id`, now that its link is up: pending mail addressed to a
/// nickname `peer_id` owns (never delivered because that peer was
/// unreachable, or simply never linked before) gets forwarded again, and
/// delivery receipts for a sender `peer_id` owns get relayed again -
/// `MailForward`/`MailDeliveredReceipt` are idempotent on the receiving
/// end, so re-sending one already handled is harmless.
async fn sync_mail_with_peer(ctx: &FederationContext, peer_id: &str) {
    for mail in ctx.mail_store.pending_all() {
        let owner_matches = matches!(
            ctx.config.directory.lock().await.owner_of_nickname(&mail.to),
            Some(Ownership::Owned(owner)) if owner == peer_id
        );
        if owner_matches {
            ctx.config.send_to_peer(peer_id, FederationMessage::MailForward { mail }).await;
            log_federation_event(peer_id, event::OTP_MAIL_FORWARDED);
        }
    }
    for receipt in ctx.mail_store.receipts_all() {
        let owner_matches = matches!(
            ctx.config.directory.lock().await.owner_of_nickname(&receipt.from),
            Some(Ownership::Owned(owner)) if owner == peer_id
        );
        if owner_matches {
            ctx.config
                .send_to_peer(
                    peer_id,
                    FederationMessage::MailDeliveredReceipt {
                        mail_id: receipt.mail_id,
                        from: receipt.from,
                        to: receipt.to,
                    },
                )
                .await;
        }
    }
}

/// A synthetic but stable "source address" for a federation peer's own
/// join-proxy attempts, fed to the same (source, channel) brute-force
/// tracking `ChannelsRegistry::password_check` already uses for a local
/// joiner's real IP - derived from the peer's own id so two different
/// peers' wrong guesses against the same channel are tracked, and on
/// abuse banned, separately, never lumped under one shared address that
/// would let one peer's guessing lock out every other peer's genuine
/// attempts.
fn synthetic_source_ip(peer_id: &str) -> std::net::IpAddr {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    peer_id.hash(&mut hasher);
    let h = hasher.finish().to_be_bytes();
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(h[0], h[1], h[2], h[3]))
}

/// "Fully shared channel list" (docs/PROTOCOL.md §18.2): mirrors `channel`
/// into this server's own local channel registry the moment it is learned
/// about, whether from live `ChannelRegistered` gossip or a peer link's
/// initial `DirectorySnapshot`, and tells this server's own connected
/// clients right away (`ServerMessage::ChannelCreated`) rather than
/// leaving it invisible until someone here happens to join it by name. A
/// no-op for a private channel (stays discoverable only by knowing its
/// name, exactly like a local one), for a channel this server owns itself
/// (it already has full local knowledge - this can happen when a peer's
/// snapshot reflects back something it originally learned from us), or
/// for one already known here (whether as this server's own, a mirror
/// from an earlier join, or a previous call to this same function).
async fn ensure_public_channel_and_announce(ctx: &FederationContext, channel: &proto::FederatedChannelInfo) {
    if channel.kind != crate::proto::ChannelKind::Public || channel.owner == ctx.config.self_id {
        return;
    }
    let newly_known = ctx.registry.lock().await.ensure_public_channel_known(&channel.name, channel.kind);
    if newly_known {
        let outgoing = ctx
            .registry
            .lock()
            .await
            .all_client_ids()
            .into_iter()
            .map(|to| {
                crate::server::Outgoing::new(
                    to,
                    crate::proto::ServerMessage::ChannelCreated {
                        channel: crate::proto::ChannelInfo { name: channel.name.clone(), kind: channel.kind },
                    },
                )
            })
            .collect();
        crate::server::dispatch(&ctx.senders, outgoing).await;
    }
}

/// Applies one message received over an established federation link from
/// `peer_id` - directory gossip, a join/leave proxy, or a mail relay.
async fn apply_incoming(ctx: &FederationContext, peer_id: &str, msg: FederationMessage) {
    match msg {
        FederationMessage::Ping => {
            // Liveness only - it did its whole job by arriving and
            // resetting the idle timeout in `run_peer_link`.
        }
        FederationMessage::Hello { .. } | FederationMessage::KeyExchange { .. } => {
            // Only ever the handshake's own two messages, fully consumed
            // by `handshake::handshake` before the message loop that calls
            // this even starts; a repeat of either is nothing to act on.
        }
        FederationMessage::DirectorySnapshot { nicknames, channels } => {
            {
                // One save for the whole snapshot, not one per entry -
                // see `merge_remote_nicknames` for what the difference
                // costs while this lock is held.
                let mut dir = ctx.config.directory.lock().await;
                let _ = dir.merge_remote_nicknames(nicknames);
                for channel in &channels {
                    dir.merge_remote_channel(channel.clone());
                }
            }
            for channel in channels {
                ensure_public_channel_and_announce(ctx, &channel).await;
            }
        }
        FederationMessage::NicknameRegistered { nickname, owner } => {
            let _ = ctx.config.directory.lock().await.merge_remote_nickname(nickname, owner);
            log_federation_event(peer_id, event::NICKS_GOSSIP);
        }
        FederationMessage::ChannelRegistered { channel } => {
            ctx.config.directory.lock().await.merge_remote_channel(channel.clone());
            log_federation_event(peer_id, event::CHANNEL_GOSSIP);
            ensure_public_channel_and_announce(ctx, &channel).await;
        }
        FederationMessage::ChannelRemoved { name, owner } => {
            // If this server mirrors *that exact* channel (its directory
            // agreed `owner` was the clean, unconflicted owner right
            // before this removal), the mirror is now for a channel that
            // no longer exists anywhere - force-delete it locally too,
            // notifying any local members who had joined it via proxy.
            // A channel this server owns *itself* is never touched here:
            // during an unresolved conflict `owner_of_channel` already
            // returns `None` rather than naming either side, so the
            // comparison below only ever matches a genuine mirror.
            let was_mirroring = {
                let dir = ctx.config.directory.lock().await;
                dir.owner_of_channel(&name).is_some_and(|info| info.owner == owner)
            };
            ctx.config.directory.lock().await.remove_channel(&name, &owner);
            log_federation_event(peer_id, event::CHANNEL_DELETED);
            if was_mirroring {
                let outgoing = ctx
                    .registry
                    .lock()
                    .await
                    .remove_channel(&name, "the federated server that owns it removed it");
                crate::server::dispatch(&ctx.senders, outgoing).await;
            }
        }
        FederationMessage::NicknameRemoved { nickname, owner } => {
            let _ = ctx.config.directory.lock().await.remove_nickname(&nickname, &owner);
            log_federation_event(peer_id, event::NICK_DELETED);
        }
        FederationMessage::JoinProxyRequest {
            request_id,
            channel,
            joiner_nickname,
            password,
            joiner_public_key_der,
            joiner_key_mode,
        } => {
            let identity = proto::RemoteIdentity {
                server: peer_id.to_string(),
                nickname: joiner_nickname,
                public_key_der: joiner_public_key_der,
                key_mode: joiner_key_mode,
            };
            let (outcome, member_outgoing) = {
                let mut reg = ctx.registry.lock().await;
                match reg.join_channel_remote(&channel, &identity, password.as_deref(), synthetic_source_ip(peer_id)) {
                    Some(Ok((kind, admin, outgoing))) => (JoinProxyOutcome::Joined { kind, admin }, outgoing),
                    Some(Err(rejection)) => (JoinProxyOutcome::Rejected(rejection), Vec::new()),
                    None => (JoinProxyOutcome::UnknownChannel, Vec::new()),
                }
            };
            log_federation_event(peer_id, event::PROXIED_JOIN_CHANNEL_FROM_SERVER);
            let granted = matches!(outcome, JoinProxyOutcome::Joined { .. });
            ctx.config
                .send_to_peer(peer_id, FederationMessage::JoinProxyResponse { request_id, outcome })
                .await;
            if granted {
                crate::server::dispatch(&ctx.senders, member_outgoing).await;
                broadcast(
                    &ctx.config,
                    FederationMessage::ChannelMemberJoined { channel, member: identity },
                    event::CHANNEL_MEMBER_JOINED,
                )
                .await;
            }
        }
        FederationMessage::JoinProxyResponse { request_id, outcome } => {
            // Only the peer the request actually went to may answer it -
            // see `join_proxy_waiters`' own doc for what believing anyone
            // else would let a hostile peer mirror into this server. A
            // mismatch leaves the waiter in place so the real peer's
            // answer (or the timeout) still decides.
            let mut waiters = ctx.config.join_proxy_waiters.lock().await;
            let answered_by_the_right_peer =
                waiters.get(&request_id).is_some_and(|(owner, _)| owner == peer_id);
            if answered_by_the_right_peer {
                if let Some((_, tx)) = waiters.remove(&request_id) {
                    let _ = tx.send(outcome);
                }
            } else {
                crate::log_warn!(
                    "federation peer '{peer_id}' answered a join proxy request it was never sent - ignoring"
                );
            }
        }
        FederationMessage::LeaveProxyNotice { channel, nickname } => {
            let outgoing =
                ctx.registry.lock().await.leave_channel_remote(&channel, peer_id, &nickname);
            crate::server::dispatch(&ctx.senders, outgoing).await;
            broadcast(
                &ctx.config,
                FederationMessage::ChannelMemberLeft { channel, server: peer_id.to_string(), nickname },
                event::CHANNEL_MEMBER_LEFT,
            )
            .await;
        }
        FederationMessage::ChannelMemberJoined { channel, member } => {
            // The home server broadcasts this to every linked peer,
            // including whichever one the member actually connects
            // through - naming *this* server. That case is not a remote
            // member at all: it is this server's own local client, whose
            // `mirror_remote_join`/`join`-driven `UserJoined`s already
            // went out through the ordinary local path the moment the
            // join itself completed. Treating it as remote too would
            // double-record it in `remote_members` and, worse, tell that
            // very client a `UserJoined` about themselves.
            if member.server != ctx.config.self_id {
                let outgoing = ctx.registry.lock().await.mirror_channel_member_joined(&channel, &member);
                if !outgoing.is_empty() {
                    log_federation_event(peer_id, event::CHANNEL_MEMBER_JOINED);
                    crate::server::dispatch(&ctx.senders, outgoing).await;
                }
            }
        }
        FederationMessage::ChannelMembership { channel, members } => {
            // Authoritative, and only from the server that actually owns
            // the channel - a peer cannot rewrite the membership of a
            // channel that is not its to describe.
            let owned_by_sender = matches!(
                ctx.config.directory.lock().await.owner_of_channel(&channel),
                Some(info) if info.owner == peer_id
            );
            if owned_by_sender {
                let outgoing = ctx
                    .registry
                    .lock()
                    .await
                    .replace_mirrored_members(&channel, &ctx.config.self_id, members);
                if !outgoing.is_empty() {
                    log_federation_event(peer_id, event::CHANNEL_MEMBER_JOINED);
                    crate::server::dispatch(&ctx.senders, outgoing).await;
                }
            }
        }
        FederationMessage::ChannelMemberLeft { channel, server, nickname } => {
            // Mirror of the guard above: a departure naming *this* server
            // is this server's own local client leaving, already handled
            // by the ordinary local `leave`/disconnect path.
            if server != ctx.config.self_id {
                let outgoing = ctx.registry.lock().await.mirror_channel_member_left(&channel, &server, &nickname);
                if !outgoing.is_empty() {
                    log_federation_event(peer_id, event::CHANNEL_MEMBER_LEFT);
                    crate::server::dispatch(&ctx.senders, outgoing).await;
                }
            }
        }
        FederationMessage::MailForward { mail } => {
            // The ack is only ever sent once `store` genuinely succeeded -
            // never unconditionally. `store`'s own validation should
            // never fail for a mail the originating server already
            // accepted from its own client, but a transient failure (disk
            // full, a permissions problem) is exactly the case
            // `MailForwardAck` exists to guard against: an ack sent
            // anyway would tell the originating server it is safe to
            // forget its only copy of mail that was, in fact, never
            // stored here at all. Silence just means the originating
            // server's copy survives and `sync_mail_with_peer` retries it
            // on the next reconnect.
            let mail_id = mail.mail_id.clone();
            // Already delivered here, and the forwarding server simply
            // never heard the ack (it was lost, or the link dropped before
            // it arrived - `sync_mail_with_peer` re-forwards everything
            // still pending on reconnect). Storing it again would
            // resurrect a `pending/` entry for mail the recipient has had
            // for days and push the ciphertext at them a second time. The
            // ack is what it is actually waiting for, so send that and
            // nothing else.
            if ctx.mail_store.is_delivered(&mail_id) {
                ctx.config.send_to_peer(peer_id, FederationMessage::MailForwardAck { mail_id }).await;
                return;
            }
            if ctx.mail_store.store(&mail).is_ok() {
                let outgoing = {
                    let reg = ctx.registry.lock().await;
                    mail::deliver_locally_if_connected(&reg, &mail)
                };
                crate::server::dispatch(&ctx.senders, outgoing).await;
                log_federation_event(peer_id, event::OTP_MAIL_RECEIVED);
                ctx.config.send_to_peer(peer_id, FederationMessage::MailForwardAck { mail_id }).await;
            }
        }
        FederationMessage::MailForwardAck { mail_id } => {
            ctx.mail_store.forget_after_relay(&mail_id);
        }
        FederationMessage::MailReceiptAck { mail_id } => {
            ctx.mail_store.forget_relayed_receipt(&mail_id);
        }
        FederationMessage::MailDeliveredReceipt { mail_id, from, to } => {
            let receipt = mail::DeliveredReceipt { mail_id: mail_id.clone(), from: from.clone(), to };
            if ctx.mail_store.record_relayed_receipt(&receipt).is_ok() {
                // Recorded durably, so the relaying server may forget the
                // copy it has been re-sending on every reconnect.
                ctx.config
                    .send_to_peer(peer_id, FederationMessage::MailReceiptAck { mail_id: mail_id.clone() })
                    .await;
                log_federation_event(peer_id, event::OTP_MAIL_DELIVERED);
                if let Some(sender_id) = ctx.registry.lock().await.id_by_name(&from) {
                    crate::server::dispatch(
                        &ctx.senders,
                        vec![crate::server::Outgoing::new(
                            sender_id,
                            crate::proto::ServerMessage::OtpMailDelivered { mail_id },
                        )],
                    )
                    .await;
                }
            }
        }
    }
}
