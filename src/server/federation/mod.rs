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
type PeerSenders = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<FederationMessage>>>>;

/// How long a dropped or failed peer link waits before redialing. Fixed
/// rather than backing off - a small, operator-curated peer set redialing
/// every 10s is cheap, and a fixed interval is simpler to reason about
/// than exponential backoff for what is expected to be a handful of
/// long-lived links.
const REDIAL_INTERVAL: Duration = Duration::from_secs(10);

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
    /// for, keyed by the id it went out under - `apply_incoming` resolves
    /// (and removes) one the moment the matching `JoinProxyResponse`
    /// arrives, on whatever link that happens to be.
    join_proxy_waiters: Arc<Mutex<HashMap<u64, oneshot::Sender<JoinProxyOutcome>>>>,
    next_request_id: AtomicU64,
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
            identity,
            peers,
            peer_keys,
            directory: Arc::new(Mutex::new(directory)),
            peer_senders: Arc::new(Mutex::new(HashMap::new())),
            join_proxy_waiters: Arc::new(Mutex::new(HashMap::new())),
            next_request_id: AtomicU64::new(1),
        })
    }

    /// `<host>:<port>` for the configured peer named `peer_id`, or `None`
    /// if this server has no such peer configured (it learned of the name
    /// only through gossip from a third server, or the name is stale).
    pub fn peer_advertise_addr(&self, peer_id: &str) -> Option<String> {
        self.peers
            .iter()
            .find(|p| p.peer_id == peer_id)
            .map(|p| format!("{}:{}", p.host, p.port))
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
        senders.get(peer_id).is_some_and(|tx| tx.send(msg).is_ok())
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
    ) -> Result<JoinProxyOutcome, String> {
        let owner = match self.directory.lock().await.owner_of_channel(channel) {
            Some(info) if info.owner != self.self_id => info.owner.clone(),
            _ => return Err("this channel is not known to belong to a federated peer".to_string()),
        };
        let request_id = self.fresh_request_id();
        let (tx, rx) = oneshot::channel();
        self.join_proxy_waiters.lock().await.insert(request_id, tx);
        let sent = self
            .send_to_peer(
                &owner,
                FederationMessage::JoinProxyRequest {
                    request_id,
                    channel: channel.to_string(),
                    joiner_nickname: joiner_nickname.to_string(),
                    password: password.map(str::to_string),
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
    for (peer_id, tx) in senders.iter() {
        if tx.send(msg.clone()).is_ok() {
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
            if let Err(e) = run_peer_link(tcp, ctx).await {
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
    if ctx.config.self_id >= peer.peer_id {
        return;
    }
    loop {
        if !ctx.config.has_live_link(&peer.peer_id).await {
            if let Err(e) = dial_once(&ctx, &peer).await {
                crate::log_warn!(
                    "could not reach federation peer '{}' at {}:{}: {e}",
                    peer.peer_id,
                    peer.host,
                    peer.port
                );
            }
        }
        tokio::time::sleep(REDIAL_INTERVAL).await;
    }
}

async fn dial_once(ctx: &FederationContext, peer: &FederationPeerConfig) -> std::io::Result<()> {
    let tcp = TcpStream::connect((peer.host.as_str(), peer.port)).await?;
    run_peer_link(tcp, ctx.clone()).await
}

/// One federation link's lifetime, either direction: runs the PQ-hybrid
/// mutual handshake (`handshake::handshake` - authenticates the peer and
/// switches the link to encrypted), deduplicates against an already-live
/// link to the same peer, exchanges directory snapshots, reconciles any
/// mail owed to/from that peer, then relays gossip and proxy traffic until
/// the link drops.
async fn run_peer_link(tcp: TcpStream, ctx: FederationContext) -> std::io::Result<()> {
    let (rd, wr) = tokio::io::split(tcp);
    let mut rd = ControlReader::new(rd);
    let mut wr = ControlWriter::new(wr);

    let peer_id = match handshake::handshake(&mut rd, &mut wr, &ctx.config.trust(), &ctx.config.advertise_addr)
        .await
    {
        Ok((peer_id, _advertise_addr)) => peer_id,
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
        Err(HandshakeError::Closed) => return Ok(()),
        Err(e) => {
            crate::log_warn!("federation handshake failed: {e}");
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<FederationMessage>();
    {
        let mut senders = ctx.config.peer_senders.lock().await;
        // One logical link per peer pair: if both sides dialed each other
        // at once, or a stale link hasn't noticed its socket died yet, the
        // later `Hello` for the same id simply doesn't get a link.
        if senders.contains_key(&peer_id) {
            return Ok(());
        }
        senders.insert(peer_id.clone(), tx);
    }
    log_federation_event(&peer_id, event::LINK_UP);

    let (nicknames, channels) = ctx.config.directory.lock().await.snapshot();
    let _ = wr.send(&FederationMessage::DirectorySnapshot { nicknames, channels }).await;
    sync_mail_with_peer(&ctx, &peer_id).await;

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if wr.send(&msg).await.is_err() {
                break;
            }
        }
    });

    loop {
        match rd.recv::<FederationMessage>().await {
            Ok(Some(msg)) => apply_incoming(&ctx, &peer_id, msg).await,
            Ok(None) => break,
            Err(e) => {
                crate::log_warn!("federation link to '{peer_id}' failed: {e}");
                break;
            }
        }
    }

    ctx.config.peer_senders.lock().await.remove(&peer_id);
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

/// Applies one message received over an established federation link from
/// `peer_id` - directory gossip, a join/leave proxy, or a mail relay.
async fn apply_incoming(ctx: &FederationContext, peer_id: &str, msg: FederationMessage) {
    match msg {
        FederationMessage::Hello { .. } | FederationMessage::KeyExchange { .. } => {
            // Only ever the handshake's own two messages, fully consumed
            // by `handshake::handshake` before the message loop that calls
            // this even starts; a repeat of either is nothing to act on.
        }
        FederationMessage::DirectorySnapshot { nicknames, channels } => {
            let mut dir = ctx.config.directory.lock().await;
            for (nickname, owner) in nicknames {
                let _ = dir.merge_remote_nickname(nickname, owner);
            }
            for channel in channels {
                dir.merge_remote_channel(channel);
            }
        }
        FederationMessage::NicknameRegistered { nickname, owner } => {
            let _ = ctx.config.directory.lock().await.merge_remote_nickname(nickname, owner);
            log_federation_event(peer_id, event::NICKS_GOSSIP);
        }
        FederationMessage::ChannelRegistered { channel } => {
            ctx.config.directory.lock().await.merge_remote_channel(channel);
            log_federation_event(peer_id, event::CHANNEL_GOSSIP);
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
        } => {
            let outcome = {
                let mut reg = ctx.registry.lock().await;
                match reg.join_channel_remote(
                    &channel,
                    peer_id,
                    &joiner_nickname,
                    password.as_deref(),
                    synthetic_source_ip(peer_id),
                ) {
                    Some(Ok((kind, admin))) => JoinProxyOutcome::Joined { kind, admin },
                    Some(Err(rejection)) => JoinProxyOutcome::Rejected(rejection),
                    None => JoinProxyOutcome::UnknownChannel,
                }
            };
            log_federation_event(peer_id, event::PROXIED_JOIN_CHANNEL_FROM_SERVER);
            ctx.config
                .send_to_peer(peer_id, FederationMessage::JoinProxyResponse { request_id, outcome })
                .await;
        }
        FederationMessage::JoinProxyResponse { request_id, outcome } => {
            if let Some(tx) = ctx.config.join_proxy_waiters.lock().await.remove(&request_id) {
                let _ = tx.send(outcome);
            }
        }
        FederationMessage::LeaveProxyNotice { channel, nickname } => {
            ctx.registry.lock().await.leave_channel_remote(&channel, peer_id, &nickname);
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
        FederationMessage::MailDeliveredReceipt { mail_id, from, to } => {
            let receipt = mail::DeliveredReceipt { mail_id: mail_id.clone(), from: from.clone(), to };
            if ctx.mail_store.record_relayed_receipt(&receipt).is_ok() {
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
