//! The server: purely a medium of connection setup, never of content. It
//! authenticates clients, tracks channel membership/presence (and, per
//! the channel-ownership/moderation feature, admin/ban/join-lock state -
//! see `channels_registry`), relays `pq_hybrid` key-rotation notices, and
//! relays the candidate exchange that lets two clients punch a direct UDP
//! link to each other (`crate::client::p2p`) - but every actual message,
//! voice stream, and file transfer travels over that direct link, never
//! through here. See `docs/PROTOCOL.md`'s "Direct peer-to-peer transport"
//! section.
//!
//! `Registry` holds the pure connection/identity bookkeeping and is unit
//! tested directly, with no sockets involved; `channels_registry::
//! ChannelsRegistry` (a field of it) holds the equivalent for channels.
//! `serve`/`run` wire that logic to real TCP connections (optionally
//! under TLS, `ssl`), plus a stateless UDP rendezvous socket
//! (`udp_rendezvous_loop`) that helps a client learn its own public
//! address for hole punching - the one place this module touches UDP at
//! all, and it never sees anything from the punched links themselves.
//!
//! Who may log in is the `users_registry`'s business (accounts on disk,
//! each with a nickname and a password); activation codes are emailed
//! and typed back into the client's own activation popup.

pub mod channels_registry;
pub mod mail;
pub mod ssl;
pub mod users_registry;

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::TlsAcceptor;

use crate::client::ip_ban::{BanOutcome, IpBanList, LOGIN_FAILURE_STRIKES, REGISTRATION_ABUSE_STRIKES};
use crate::p2p_proto::RendezvousMessage;
use crate::proto::{self, ChannelKind, ClientMessage, KeyMode, ServerMessage, UserId, UserInfo};
use users_registry::{AuthCheck, SmtpConfig, UsersRegistry};

pub use channels_registry::{
    CHANNEL_MAX_PASSWORD_ATTEMPTS, CHANNEL_PASSWORD_BAN_DURATION, DEFAULT_CHANNEL_NAME,
};

/// Everything `serve` needs besides a socket: who may log in, whether
/// anyone may register, and how. Built from `~/.aloo/settings` by
/// `main.rs::run_server`; tests build one around a scratch registry.
#[derive(Clone)]
pub struct ServerOptions {
    /// The accounts every `Auth` is checked against (docs/PROTOCOL.md §5).
    pub users: UsersRegistry,
    /// `server_allow_registration` - whether `Register` is answered with
    /// anything but a refusal.
    pub allow_registration: bool,
    /// Where activation emails go out through. Registration with no relay
    /// is refused with a reason rather than creating an account whose
    /// code nobody will ever receive.
    pub smtp: Option<SmtpConfig>,
    /// The OTP mail store's directory (`mail::default_mail_dir` in
    /// production; a scratch dir in tests).
    pub mail_dir: PathBuf,
    /// §4.1's liveness timeout - `proto::HEARTBEAT_TIMEOUT` in
    /// production, milliseconds in the tests that prove it fires.
    pub heartbeat_timeout: Duration,
    /// `server_ssl=on`: every accepted socket is TLS-wrapped with this
    /// before the protocol starts.
    pub tls: Option<TlsAcceptor>,
    /// `server_allow_create_public_channels` - whether a `JoinChannel`
    /// for a not-yet-existing name may create it as `ChannelKind::Public`.
    /// Joining an *existing* public channel, and creating a private one,
    /// are unaffected either way.
    pub allow_create_public_channels: bool,
    /// `server_channel_deletion_unactivity_period` - how long a channel
    /// (other than `DEFAULT_CHANNEL_NAME`) may sit empty with nobody
    /// rejoining it before the background sweep destroys it. `None`
    /// (the default) means the sweep never runs at all, so channels
    /// persist while empty indefinitely.
    pub channel_deletion_unactivity_period: Option<Duration>,
    /// `server_superadmin` - nicknames allowed to activate/deactivate any
    /// account, remove an account (and every channel it administers), or
    /// remove any public channel. Checked fresh on every admin message;
    /// never trusted from anything the client asserts about itself.
    pub superadmins: BTreeSet<String>,
    /// 7 wrong passwords for one address within 24h refuses that address's
    /// logins for the next 24h (`client::ip_ban::LOGIN_FAILURE_STRIKES`).
    /// Shared and mutable across every concurrently-handled connection,
    /// unlike the rest of `ServerOptions` - a `tokio::sync::Mutex` around
    /// the same `IpBanList` type `PeerLinkManager` uses for direct-punch
    /// bans, persisted the same way.
    pub login_bans: Arc<Mutex<IpBanList>>,
    /// More than 3 registrations from one address within 2 days refuses
    /// that address's registrations for the next 7 days
    /// (`client::ip_ban::REGISTRATION_ABUSE_STRIKES`).
    pub registration_bans: Arc<Mutex<IpBanList>>,
}

impl ServerOptions {
    /// Production defaults around `users`: no registration, the real mail
    /// directory, the real heartbeat timeout, no TLS, public channel
    /// creation allowed, no inactivity sweep, no superadmins.
    pub fn new(users: UsersRegistry) -> Self {
        Self {
            users,
            allow_registration: false,
            smtp: None,
            mail_dir: mail::default_mail_dir(),
            heartbeat_timeout: proto::HEARTBEAT_TIMEOUT,
            tls: None,
            allow_create_public_channels: true,
            channel_deletion_unactivity_period: None,
            superadmins: BTreeSet::new(),
            login_bans: Arc::new(Mutex::new(load_ip_bans(
                crate::client::ip_ban::login_ban_default_path(),
            ))),
            registration_bans: Arc::new(Mutex::new(load_ip_bans(
                crate::client::ip_ban::registration_ban_default_path(),
            ))),
        }
    }

    pub fn with_mail_dir(mut self, dir: PathBuf) -> Self {
        self.mail_dir = dir;
        self
    }

    pub fn with_heartbeat_timeout(mut self, timeout: Duration) -> Self {
        self.heartbeat_timeout = timeout;
        self
    }

    pub fn with_tls(mut self, acceptor: TlsAcceptor) -> Self {
        self.tls = Some(acceptor);
        self
    }

    pub fn with_registration(mut self, smtp: Option<SmtpConfig>) -> Self {
        self.allow_registration = true;
        self.smtp = smtp;
        self
    }

    pub fn with_create_public_channels_policy(mut self, allowed: bool) -> Self {
        self.allow_create_public_channels = allowed;
        self
    }

    pub fn with_channel_deletion_unactivity_period(mut self, period: Duration) -> Self {
        self.channel_deletion_unactivity_period = Some(period);
        self
    }

    pub fn with_superadmins(mut self, names: BTreeSet<String>) -> Self {
        self.superadmins = names;
        self
    }

    /// Points the login-failure ban list at `path` instead of the
    /// production default - what test scaffolding uses to keep scratch
    /// runs out of the real `~/.aloo` (`load_ip_bans` still loads it, so a
    /// test that pre-seeds the file, or reopens `ServerOptions` mid-test,
    /// sees a consistent list).
    pub fn with_login_bans_path(mut self, path: PathBuf) -> Self {
        self.login_bans = Arc::new(Mutex::new(load_ip_bans(path)));
        self
    }

    /// `with_login_bans_path`'s counterpart for the registration-abuse
    /// list.
    pub fn with_registration_bans_path(mut self, path: PathBuf) -> Self {
        self.registration_bans = Arc::new(Mutex::new(load_ip_bans(path)));
        self
    }
}

/// Loads an `IpBanList` from `path`, falling back to an empty one bound to
/// the same path on any error other than "not there yet" (already what
/// `load` itself treats as empty) - a corrupt or unreadable ban file
/// should never stop the server from starting. Mirrors
/// `client::p2p::PeerLinkManager`'s own load-or-empty fallback for its
/// direct-punch `IpBanList`.
fn load_ip_bans(path: PathBuf) -> IpBanList {
    IpBanList::load(&path).unwrap_or_else(|e| {
        crate::log_warn!("could not load ban list at {}: {e}", path.display());
        IpBanList::new_empty(path)
    })
}

/// One outbound message produced by a `Registry` mutation, to be delivered
/// to a specific connected client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub to: UserId,
    pub message: ServerMessage,
}

impl Outgoing {
    /// One message for one client - the only way an `Outgoing` is built,
    /// here and in `channels_registry`/`mail`, so the pair always reads
    /// in the order it means: to whom, then what.
    pub fn new(to: UserId, message: ServerMessage) -> Self {
        Self { to, message }
    }

    /// The one shape a refused request is answered in: a
    /// `ServerMessage::Error` carrying the reason back to whoever asked.
    /// The wording is always the registry's - `Registry` and
    /// `ChannelsRegistry` return an `Err(String)` that says why - so this
    /// only ever forwards it, never invents one.
    pub fn error(to: UserId, message: impl Into<String>) -> Self {
        Self::new(
            to,
            ServerMessage::Error {
                message: message.into(),
            },
        )
    }

    /// `error` as the single-message list a `client_loop` arm returns.
    pub fn refuse(to: UserId, message: impl Into<String>) -> Vec<Self> {
        vec![Self::error(to, message)]
    }
}

struct ClientRecord {
    name: String,
    public_key_der: Vec<u8>,
    key_mode: KeyMode,
}

/// Pure connection/channel bookkeeping, with no I/O of its own. Every
/// mutation returns the list of messages that need to go out as a result,
/// leaving delivery to the async layer.
pub struct Registry {
    clients: HashMap<UserId, ClientRecord>,
    next_id: u64,
    channels: channels_registry::ChannelsRegistry,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Starts with one default public channel so a freshly started server
    /// always has something for the first-connected client to auto-join.
    /// No inactivity sweep configured - use `with_channel_deletion_period`
    /// for that.
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            next_id: 1,
            channels: channels_registry::ChannelsRegistry::new(None),
        }
    }

    /// `new`, with the inactivity sweep's period configured from the
    /// start - what `serve_tcp` actually builds from `ServerOptions`.
    pub fn with_channel_deletion_period(period: Option<Duration>) -> Self {
        Self {
            clients: HashMap::new(),
            next_id: 1,
            channels: channels_registry::ChannelsRegistry::new(period),
        }
    }

    pub fn register(&mut self, name: String, public_key_der: Vec<u8>, key_mode: KeyMode) -> UserId {
        let id = UserId(self.next_id);
        self.next_id += 1;
        self.clients.insert(
            id,
            ClientRecord {
                name,
                public_key_der,
                key_mode,
            },
        );
        id
    }

    pub fn name_taken(&self, name: &str) -> bool {
        self.clients.values().any(|c| c.name == name)
    }

    /// Registers `name`/`public_key_der` unless `name` is already in use by
    /// another connected client. The check and the insert happen under the
    /// same `&mut self` call, so callers that hold the registry's lock for
    /// the duration get an atomic check-then-register with no race window
    /// for two simultaneous connections to grab the same nickname.
    pub fn try_register(
        &mut self,
        name: String,
        public_key_der: Vec<u8>,
        key_mode: KeyMode,
    ) -> Result<UserId, String> {
        if self.name_taken(&name) {
            return Err(format!("nickname '{name}' is already taken"));
        }
        Ok(self.register(name, public_key_der, key_mode))
    }

    pub fn user_info(&self, id: UserId) -> Option<UserInfo> {
        self.clients.get(&id).map(|c| UserInfo {
            id,
            name: c.name.clone(),
            public_key_der: c.public_key_der.clone(),
            key_mode: c.key_mode,
        })
    }

    /// The connected client currently holding `name`, if any - what lets an
    /// `OtpMailSend`/`OtpMailAck` reach a recipient/sender who happens to
    /// be online right now instead of waiting for their next
    /// `OtpMailFetch`. Nicknames are unique among connected clients
    /// (`try_register`), so at most one match exists.
    pub fn id_by_name(&self, name: &str) -> Option<UserId> {
        self.clients
            .iter()
            .find(|(_, c)| c.name == name)
            .map(|(id, _)| *id)
    }

    /// Public channels only: private channels are only reachable by
    /// knowing their name (Ctrl+J), never advertised in the tab list.
    pub fn channel_list(&self) -> Vec<proto::ChannelInfo> {
        self.channels.list()
    }

    /// Joins `id` to `name`, creating the channel (as `kind`) if needed;
    /// idempotent for a channel you're already in. Always allows creating
    /// a new public channel - see `join_channel_with_policy` for the
    /// policy-gated version the server's own dispatch loop actually uses.
    /// `name` is validated server-side regardless of the client's UI - the
    /// server never trusts the client. `password` sets a new private
    /// channel's password or is compared (constant-time) against the
    /// existing one (§6.5); `source_ip` scopes the brute-force ban (§6.6).
    pub fn join_channel(
        &mut self,
        id: UserId,
        name: &str,
        kind: ChannelKind,
        password: Option<&str>,
        source_ip: IpAddr,
    ) -> Result<Vec<Outgoing>, String> {
        self.join_channel_with_policy(id, name, kind, password, source_ip, true)
    }

    /// `join_channel`, additionally refusing to *create* a new public
    /// channel when `allow_create_public_channels` is `false`
    /// (`server_allow_create_public_channels`) - joining an existing
    /// public channel, or creating/joining a private one, is unaffected.
    pub fn join_channel_with_policy(
        &mut self,
        id: UserId,
        name: &str,
        kind: ChannelKind,
        password: Option<&str>,
        source_ip: IpAddr,
        allow_create_public_channels: bool,
    ) -> Result<Vec<Outgoing>, String> {
        let user = self
            .user_info(id)
            .ok_or_else(|| "unknown user".to_string())?;
        // Only `Registry` knows every connected client - needed solely to
        // broadcast a genuinely new public channel's creation to everyone
        // but its creator.
        let all_ids: Vec<UserId> = self.clients.keys().copied().collect();
        let clients = &self.clients;
        self.channels.join(
            id,
            &user,
            name,
            kind,
            password,
            source_ip,
            allow_create_public_channels,
            &all_ids,
            |uid| {
                clients.get(&uid).map(|c| UserInfo {
                    id: uid,
                    name: c.name.clone(),
                    public_key_der: c.public_key_der.clone(),
                    key_mode: c.key_mode,
                })
            },
        )
    }

    /// Removes `id` from `name`, notifying remaining members. Empty
    /// private channels are dropped entirely; empty public channels stay
    /// listed.
    pub fn leave_channel(&mut self, id: UserId, name: &str) -> Vec<Outgoing> {
        self.channels.leave(id, name)
    }

    /// Removes `id` from every channel and forgets it entirely (on
    /// disconnect). Peers who shared *any* channel with `id` get exactly
    /// one `UserOffline` each (a full disconnect, not a one-channel
    /// `UserLeft` - see `ServerMessage::UserOffline`), no matter how many
    /// channels they shared.
    pub fn unregister(&mut self, id: UserId) -> Vec<Outgoing> {
        let outgoing = self.channels.remove_from_all(id);
        self.clients.remove(&id);
        outgoing
    }

    /// `/delete-channel`: `caller` must currently administer `name`, and
    /// `name` must be a public channel.
    pub fn delete_channel(&mut self, caller: UserId, name: &str) -> Result<Vec<Outgoing>, String> {
        let caller_name = self
            .user_info(caller)
            .ok_or_else(|| "unknown user".to_string())?
            .name;
        self.channels.delete_channel(&caller_name, name)
    }

    /// `/ban <nickname>`: `caller` must currently administer `channel`.
    pub fn ban_from_channel(
        &mut self,
        caller: UserId,
        channel: &str,
        target_nickname: &str,
    ) -> Result<Vec<Outgoing>, String> {
        let caller_name = self
            .user_info(caller)
            .ok_or_else(|| "unknown user".to_string())?
            .name;
        let target_id = self.id_by_name(target_nickname);
        self.channels.ban(&caller_name, channel, target_nickname, target_id)
    }

    /// `/unban <nickname>`: `caller` must currently administer `channel`.
    pub fn unban_from_channel(
        &mut self,
        caller: UserId,
        channel: &str,
        target_nickname: &str,
    ) -> Result<Vec<Outgoing>, String> {
        let caller_name = self
            .user_info(caller)
            .ok_or_else(|| "unknown user".to_string())?
            .name;
        self.channels.unban(&caller_name, channel, target_nickname)
    }

    /// `/lock-joins`: `caller` must currently administer `channel`.
    /// `allowed: None` is the "All users" option - clears the lock.
    pub fn set_channel_join_lock(
        &mut self,
        caller: UserId,
        channel: &str,
        allowed: Option<Vec<String>>,
    ) -> Result<Vec<Outgoing>, String> {
        let caller_name = self
            .user_info(caller)
            .ok_or_else(|| "unknown user".to_string())?
            .name;
        self.channels.set_join_lock(&caller_name, channel, allowed)
    }

    /// `/assign-admin <nickname>`: `caller` must currently administer
    /// `channel`, and `target_nickname` must currently be a member of it.
    pub fn assign_channel_admin(
        &mut self,
        caller: UserId,
        channel: &str,
        target_nickname: &str,
    ) -> Result<Vec<Outgoing>, String> {
        let caller_name = self
            .user_info(caller)
            .ok_or_else(|| "unknown user".to_string())?
            .name;
        let target_is_member = self
            .id_by_name(target_nickname)
            .is_some_and(|tid| self.channels.is_member(channel, tid));
        self.channels
            .assign_admin(&caller_name, channel, target_nickname, target_is_member)
    }

    /// A superadmin's `/remove-account` cascade: every channel `nickname`
    /// administers is removed outright (never reassigned), its current
    /// members notified with `reason`.
    pub fn remove_channels_administered_by(&mut self, nickname: &str, reason: &str) -> Vec<Outgoing> {
        let names = self.channels.channels_administered_by(nickname);
        names
            .into_iter()
            .flat_map(|name| self.channels.force_delete_channel(&name, reason.to_string()))
            .collect()
    }

    /// A superadmin's `/remove-channel`: removes any channel outright
    /// (never `DEFAULT_CHANNEL_NAME`, even for a superadmin), notifying
    /// its current members with `reason`. Public-only in practice: a
    /// private channel is never advertised to anyone outside its
    /// membership (AC-022, TB-154), so a superadmin has no name to act on
    /// for one it isn't already in - nothing further needs to check this
    /// here.
    pub fn remove_channel(&mut self, name: &str, reason: &str) -> Vec<Outgoing> {
        self.channels.force_delete_channel(name, reason.to_string())
    }

    /// The background inactivity sweep's one entry point - see
    /// `channels_registry::ChannelsRegistry::sweep_inactive`.
    pub fn sweep_inactive_channels(&mut self) {
        self.channels.sweep_inactive();
    }

    /// Relays a `pq_hybrid` key rotation (PROTOCOL.md §7.5/§13.10) point to
    /// point. The server never inspects `signature` - that's the receiving
    /// client's job - and never updates its stored `public_key_der` for
    /// `from`, which stays as whatever `Identify` sent (it only ever
    /// serves as the *bootstrap* key for peers who haven't exchanged a
    /// message with `from` yet).
    pub fn route_key_rotation(
        &self,
        from: UserId,
        to: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Outgoing, String> {
        // The server verifies nothing about the payload itself, and has no
        // notion of which senders rotate: every client runs the one mode
        // that does (§13.10).
        if !self.clients.contains_key(&from) {
            return Err(crate::proto::UNKNOWN_SENDER.to_string());
        }
        if !self.clients.contains_key(&to) {
            return Err(crate::proto::UNKNOWN_RECIPIENT.to_string());
        }
        Ok(Outgoing::new(
            to,
            ServerMessage::KeyRotated {
                from,
                new_public_key_der,
                signature,
            },
        ))
    }

    /// Relays a direct-link candidate proposal (or reply) to `to` -
    /// existence-check-only, exactly like `route_key_rotation`'s recipient
    /// check. The server neither validates nor stores `candidates`/
    /// `link_nonce`; see `crate::client::p2p` for what happens with them next.
    pub fn route_peer_link_request(
        &self,
        from: UserId,
        to: UserId,
        candidates: Vec<SocketAddr>,
        link_nonce: u64,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err(crate::proto::UNKNOWN_RECIPIENT.to_string());
        }
        Ok(Outgoing::new(
            to,
            ServerMessage::PeerCandidates {
                from,
                candidates,
                link_nonce,
            },
        ))
    }
}

// ---------------------------------------------------------------------
// Async wiring
// ---------------------------------------------------------------------

type Senders = Arc<Mutex<HashMap<UserId, mpsc::UnboundedSender<ServerMessage>>>>;

/// Binds `addr` (both TCP and, for the UDP rendezvous socket, the same
/// numeric port - independent port namespaces, so this needs no separate
/// flag) and serves forever.
pub async fn run(addr: SocketAddr, options: ServerOptions) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let udp = UdpSocket::bind(addr).await?;
    serve_with_rendezvous(listener, udp, options).await
}

/// Accepts connections on an already-bound listener and serves forever,
/// with no UDP rendezvous socket - only used by tests that don't exercise
/// direct-link candidate discovery and want one less socket to bind. Split
/// out from `run` so tests can bind to an ephemeral port (`:0`) and
/// discover the real address via `TcpListener::local_addr`.
pub async fn serve(listener: TcpListener, options: ServerOptions) -> std::io::Result<()> {
    serve_tcp(listener, options).await
}

/// `serve`, plus a UDP rendezvous socket bound alongside it (see
/// `udp_rendezvous_loop`) - what `run` actually uses, and what
/// direct-link/hole-punch tests bind explicitly.
pub async fn serve_with_rendezvous(
    listener: TcpListener,
    udp: UdpSocket,
    options: ServerOptions,
) -> std::io::Result<()> {
    tokio::spawn(udp_rendezvous_loop(udp));
    serve_tcp(listener, options).await
}

/// How often the inactivity sweep checks every channel - plenty for the
/// month-scale periods `server_channel_deletion_unactivity_period`
/// documents, and a named constant so this doesn't need rewording if that
/// ever changes.
const CHANNEL_SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Periodically sweeps channels that have been empty and unjoined for too
/// long (`channels_registry::ChannelsRegistry::sweep_inactive`). Modeled
/// on `udp_rendezvous_loop`'s "degrade, never take the whole task down"
/// shape, though there is nothing here that can actually fail.
async fn channel_sweep_loop(registry: Arc<Mutex<Registry>>) {
    let mut ticker = tokio::time::interval(CHANNEL_SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        registry.lock().await.sweep_inactive_channels();
    }
}

async fn serve_tcp(listener: TcpListener, options: ServerOptions) -> std::io::Result<()> {
    let registry = Arc::new(Mutex::new(Registry::with_channel_deletion_period(
        options.channel_deletion_unactivity_period,
    )));
    if options.channel_deletion_unactivity_period.is_some() {
        tokio::spawn(channel_sweep_loop(registry.clone()));
    }
    let senders: Senders = Arc::new(Mutex::new(HashMap::new()));
    // Shared without a lock of its own: every method works on one file at a
    // time and the racy interleavings (two connections storing/acking the
    // same id) each resolve to a harmless no-op for the loser.
    let mail_store = Arc::new(mail::MailStore::open(options.mail_dir.clone())?);
    let options = Arc::new(options);

    loop {
        let (socket, peer) = listener.accept().await?;
        let registry = registry.clone();
        let senders = senders.clone();
        let options = options.clone();
        let mail_store = mail_store.clone();
        tokio::spawn(async move {
            // The TLS handshake happens here, inside the connection's own
            // task, so a client that stalls mid-handshake holds up nobody
            // but itself.
            let socket = match ssl::accept(options.tls.as_ref(), socket).await {
                Ok(socket) => socket,
                Err(e) => {
                    crate::log_warn!("connection {peer} failed TLS: {e}");
                    return;
                }
            };
            if let Err(e) =
                handle_connection(socket, peer, registry, senders, options, mail_store).await
            {
                crate::log_warn!("connection {peer} ended: {e}");
            }
        });
    }
}

/// Stateless STUN-Binding-style rendezvous: echoes back the address a
/// `BindingRequest` datagram arrived from - the sender's server-reflexive
/// (public) address, the one thing a client can't learn about itself. No
/// authentication, no `Registry` access, no state between datagrams: same
/// threat model as a public STUN server. See
/// `crate::client::p2p::learn_reflexive_candidate`.
///
/// A failed `recv_from` is logged and ignored rather than ending the loop,
/// the same "degrade, never take the socket down" handling the client's own
/// receive loop uses (`client::p2p::spawn_receive_loop`). This socket sends
/// to whoever asked, so an ordinary client disappearing can surface an error
/// on a *later* recv (on Windows, `WSAECONNRESET` after the ICMP
/// port-unreachable for a previous reply; `WSAEMSGSIZE` for a datagram
/// larger than `buf`), and breaking on those killed reflexive-address
/// discovery for the whole remaining uptime of the server - leaving every
/// client from then on with host candidates only, able to punch on a LAN
/// and nowhere else.
async fn udp_rendezvous_loop(socket: UdpSocket) {
    let mut buf = [0u8; 512];
    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(ok) => ok,
            Err(e) => {
                crate::log_warn!("UDP rendezvous receive error (ignoring, still listening): {e}");
                // Safety net against a permanently-broken socket erroring
                // instantly forever, which would busy-spin this task at
                // 100% of a core; transient errors don't notice 50ms.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(RendezvousMessage::BindingRequest { token }) = proto::decode(&buf[..n]) else {
            continue;
        };
        let Ok(response) = proto::encode(&RendezvousMessage::BindingResponse {
            token,
            observed: from,
        }) else {
            continue;
        };
        let _ = socket.send_to(&response, from).await;
    }
}

async fn handle_connection(
    socket: ssl::BoxedStream,
    peer_addr: SocketAddr,
    registry: Arc<Mutex<Registry>>,
    senders: Senders,
    options: Arc<ServerOptions>,
    mail_store: Arc<mail::MailStore>,
) -> proto::Result<()> {
    let peer_ip = peer_addr.ip();
    let (rd, wr) = tokio::io::split(socket);
    let mut rd = crate::control::ControlReader::new(rd);
    let mut wr = crate::control::ControlWriter::new(wr);

    // Ephemeral per connection, so recording a session and later stealing
    // the server's TLS key still does not decrypt it.
    let (encap, decap) = crate::crypto::pq::generate_encryption_keys();
    let control = crate::control::make_offer(encap);

    wr.send(&ServerMessage::Hello {
        registration_open: options.allow_registration,
        control,
    })
    .await?;

    // Everything from here on is sealed. A client that sends anything but
    // `SecureChannel` first cannot be talked to at all - there is no
    // plaintext fallback, since one would be a downgrade attack.
    let Some(ClientMessage::SecureChannel(accept)) = rd.recv().await? else {
        return Ok(());
    };
    let Some(keys) = crate::control::open_accept(&decap, &accept) else {
        return Ok(());
    };
    wr.enable(keys.send);
    rd.enable(keys.recv);

    let (nickname, password) = match rd.recv().await? {
        Some(ClientMessage::Auth { nickname, password }) => (nickname, password),
        Some(ClientMessage::Register {
            nickname,
            password,
            email,
        }) => {
            let (ok, reason) =
                match register_account(&options, &nickname, &password, &email, peer_ip).await {
                    Ok(()) => (true, None),
                    Err(reason) => (false, Some(reason)),
                };
            let _ = wr.send(&ServerMessage::RegisterResult { ok, reason }).await;
            return Ok(());
        }
        _ => {
            refuse_auth(&mut wr, "expected auth message").await;
            return Ok(());
        }
    };
    // 7 wrong passwords from one address within 24h refuse that address's
    // logins outright for the next 24h - checked before the slow
    // credential derivation below, not just before answering, so a banned
    // address can't use login attempts to burn server CPU either.
    if options
        .login_bans
        .lock()
        .await
        .is_banned_at(peer_ip, users_registry::now_utc())
    {
        refuse_auth(
            &mut wr,
            "too many failed login attempts from this address - try again later",
        )
        .await;
        return Ok(());
    }
    // The derivation is deliberately slow (§5.1) and the check reads the
    // registry's files - neither belongs on the async executor.
    let check = {
        let users = options.users.clone();
        let (nickname, password) = (nickname.clone(), password.clone());
        tokio::task::spawn_blocking(move || {
            users.check_credentials(&nickname, &password, users_registry::now_utc())
        })
        .await
        .unwrap_or(AuthCheck::Rejected)
    };
    match check {
        AuthCheck::Ok => {}
        AuthCheck::Rejected => {
            options
                .login_bans
                .lock()
                .await
                .record_strike(peer_ip, users_registry::now_utc(), &LOGIN_FAILURE_STRIKES);
            refuse_auth(&mut wr, "authentication failed").await;
            return Ok(());
        }
        AuthCheck::Deactivated { reason } => {
            let _ = wr
                .send(&ServerMessage::AuthResult {
                    ok: false,
                    activation_pending: false,
                    deactivated: Some(reason),
                    reason: None,
                })
                .await;
            return Ok(());
        }
        AuthCheck::ActivationPending { expired } => {
            // An expired pending activation gets exactly one more chance:
            // a fresh code, resent to the same email already on file, the
            // same way registering again with the same data already
            // works (`register_account`) - so a login attempt never has
            // to become a whole separate re-registration round trip. Only
            // an outright refusal (no SMTP configured, no email on file -
            // `register_manual` - or the relay itself failing) still ends
            // the connection here; everything else falls through into the
            // same "wait for Activate" flow an unexpired pending
            // activation already uses.
            if expired && !reissue_and_resend_activation(&options, &nickname).await {
                refuse_auth(
                    &mut wr,
                    "this account's activation code has expired - register again",
                )
                .await;
                return Ok(());
            }
            wr.send(&ServerMessage::AuthResult {
                ok: false,
                activation_pending: true,
                deactivated: None,
                reason: None,
            })
            .await?;
            let Some(ClientMessage::Activate { code }) = rd.recv().await? else {
                refuse_auth(&mut wr, "expected activation code").await;
                return Ok(());
            };
            let outcome = options
                .users
                .activate(&nickname, &code, users_registry::now_utc());
            let reason = match outcome {
                users_registry::ActivationOutcome::Activated => None,
                users_registry::ActivationOutcome::WrongCode
                | users_registry::ActivationOutcome::NothingPending => {
                    Some("wrong activation code".to_string())
                }
                users_registry::ActivationOutcome::Expired => {
                    Some("this account's activation code has expired - register again".to_string())
                }
                users_registry::ActivationOutcome::TooManyWrongCodesAccountRemoved => {
                    Some(users_registry::ACCOUNT_REMOVED_ACTIVATION_REASON.to_string())
                }
            };
            if let Some(reason) = reason {
                refuse_auth(&mut wr, reason).await;
                return Ok(());
            }
        }
    }
    wr.send(&ServerMessage::AuthResult {
        ok: true,
        activation_pending: false,
        deactivated: None,
        reason: None,
    })
    .await?;

    let Some(ClientMessage::Identify {
        public_key_der,
        key_mode,
    }) = rd.recv().await?
    else {
        let _ = wr
            .send(&ServerMessage::Error {
                message: "expected identify message".into(),
            })
            .await;
        return Ok(());
    };

    let id = {
        let mut reg = registry.lock().await;
        match reg.try_register(nickname, public_key_der, key_mode) {
            Ok(id) => id,
            Err(reason) => {
                drop(reg);
                let _ = wr
                    .send(&ServerMessage::IdentifyResult {
                        ok: false,
                        you: None,
                        reason: Some(reason),
                    })
                    .await;
                return Ok(());
            }
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    senders.lock().await.insert(id, tx.clone());

    let _ = tx.send(ServerMessage::IdentifyResult {
        ok: true,
        you: Some(id),
        reason: None,
    });
    let channels = registry.lock().await.channel_list();
    let _ = tx.send(ServerMessage::ChannelList {
        channels,
        superadmins: options.superadmins.iter().cloned().collect(),
    });

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if wr.send(&msg).await.is_err() {
                break;
            }
        }
    });

    let result = client_loop(id, &mut rd, &registry, &senders, peer_ip, &options, &mail_store).await;

    {
        let mut reg = registry.lock().await;
        let outgoing = reg.unregister(id);
        drop(reg);
        dispatch(&senders, outgoing).await;
    }
    senders.lock().await.remove(&id);
    writer_task.abort();
    result
}

/// `id`'s own nickname, checked against `options.superadmins` - the
/// authorization gate every `Admin*` message goes through before it
/// touches anything. Lives beside `register_account` rather than inside
/// `Registry`/`ChannelsRegistry`, on purpose: neither of those needs to
/// know `ServerOptions` exists, exactly as `register_account` already
/// keeps registration policy outside `Registry` today.
fn require_superadmin(options: &ServerOptions, reg: &Registry, id: UserId) -> Result<String, String> {
    let name = reg
        .user_info(id)
        .ok_or_else(|| "unknown user".to_string())?
        .name;
    if options.superadmins.contains(&name) {
        Ok(name)
    } else {
        Err("only a superadmin may do that".to_string())
    }
}

/// A registry mutation's outgoing messages, or - if it refused - the one
/// `Error` reply carrying its reason back to `id`. Every `client_loop`
/// arm that calls a fallible `Registry` method answers this way, which is
/// what keeps those arms one line each and keeps a refusal from being
/// dropped on the floor.
fn or_refuse(id: UserId, result: Result<Vec<Outgoing>, String>) -> Vec<Outgoing> {
    result.unwrap_or_else(|reason| Outgoing::refuse(id, reason))
}

/// Every way `handle_connection` turns a login down before the session
/// starts: one `AuthResult` naming the reason, with the other three
/// fields at the "plain refusal" values that distinguish it from the
/// deactivated and activation-pending answers beside it.
///
/// Best-effort on purpose - the caller returns immediately afterwards, so
/// a write that fails changes nothing about what happens next.
async fn refuse_auth<W: tokio::io::AsyncWrite + Unpin>(
    wr: &mut crate::control::ControlWriter<W>,
    reason: impl Into<String>,
) {
    let _ = wr
        .send(&ServerMessage::AuthResult {
            ok: false,
            activation_pending: false,
            deactivated: None,
            reason: Some(reason.into()),
        })
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn client_loop<R: AsyncRead + Unpin>(
    id: UserId,
    rd: &mut crate::control::ControlReader<R>,
    registry: &Arc<Mutex<Registry>>,
    senders: &Senders,
    source_ip: IpAddr,
    options: &Arc<ServerOptions>,
    mail_store: &mail::MailStore,
) -> proto::Result<()> {
    loop {
        // Any message at all - `Heartbeat` or otherwise - proves the
        // connection is alive and resets this. Nothing arriving within
        // `heartbeat_timeout` (docs/PROTOCOL.md §4.1) is treated exactly
        // like the client closing the connection: this simply returns,
        // and the same unregister/cleanup path in `handle_connection` runs
        // either way.
        let Ok(recv) =
            tokio::time::timeout(options.heartbeat_timeout, rd.recv::<ClientMessage>()).await
        else {
            return Ok(());
        };
        let Some(msg) = recv? else {
            return Ok(());
        };
        let outgoing = {
            let mut reg = registry.lock().await;
            match msg {
                ClientMessage::JoinChannel {
                    name,
                    kind,
                    password,
                } => {
                    let name_for_err = name.clone();
                    reg.join_channel_with_policy(
                        id,
                        &name,
                        kind,
                        password.as_deref(),
                        source_ip,
                        options.allow_create_public_channels,
                    )
                    .unwrap_or_else(|reason| {
                        vec![Outgoing::new(
                            id,
                            ServerMessage::ChannelJoinFailed {
                                name: name_for_err,
                                reason,
                            },
                        )]
                    })
                }
                ClientMessage::LeaveChannel { name } => reg.leave_channel(id, &name),
                ClientMessage::DeleteChannel { name } => {
                    or_refuse(id, reg.delete_channel(id, &name))
                }
                ClientMessage::BanFromChannel { channel, nickname } => {
                    or_refuse(id, reg.ban_from_channel(id, &channel, &nickname))
                }
                ClientMessage::UnbanFromChannel { channel, nickname } => {
                    or_refuse(id, reg.unban_from_channel(id, &channel, &nickname))
                }
                ClientMessage::SetChannelJoinLock { channel, allowed } => {
                    or_refuse(id, reg.set_channel_join_lock(id, &channel, allowed))
                }
                ClientMessage::AssignChannelAdmin { channel, nickname } => {
                    or_refuse(id, reg.assign_channel_admin(id, &channel, &nickname))
                }
                ClientMessage::ChangePassword { old_password, new_password } => {
                    match reg.clients.get(&id).map(|c| c.name.clone()) {
                        None => vec![Outgoing::new(
                            id,
                            ServerMessage::ChangePasswordResult {
                                ok: false,
                                reason: Some("not connected".to_string()),
                            },
                        )],
                        Some(nickname) => {
                            // Deliberately synchronous PBKDF2, unlike
                            // `Auth`'s own check: this connection already
                            // holds `reg`'s lock for every other arm here,
                            // and needs nothing further from it beyond the
                            // caller's own nickname just resolved above, so
                            // a `spawn_blocking` hop would only add latency
                            // without releasing anything else could use in
                            // the meantime - the same one-request-at-a-time
                            // cost every other arm here already accepts,
                            // just a slower one.
                            let now = users_registry::now_utc();
                            let message = match options.users.check_credentials(&nickname, &old_password, now) {
                                AuthCheck::Ok => match options.users.change_password(&nickname, &new_password) {
                                    Ok(()) => ServerMessage::ChangePasswordResult { ok: true, reason: None },
                                    Err(e) => ServerMessage::ChangePasswordResult {
                                        ok: false,
                                        reason: Some(e.to_string()),
                                    },
                                },
                                _ => ServerMessage::ChangePasswordResult {
                                    ok: false,
                                    reason: Some("wrong current password".to_string()),
                                },
                            };
                            vec![Outgoing::new(id, message)]
                        }
                    }
                }
                ClientMessage::AdminDeactivate { nickname, reason } => {
                    match require_superadmin(options, &reg, id) {
                        Err(e) => Outgoing::refuse(id, e),
                        Ok(_) => {
                            let _ = options.users.deactivate(&nickname, &reason);
                            let mut out = Vec::new();
                            if let Some(target_id) = reg.id_by_name(&nickname) {
                                out.push(Outgoing::new(
                                    target_id,
                                    ServerMessage::AccountDeactivated { reason },
                                ));
                            }
                            out
                        }
                    }
                }
                ClientMessage::AdminActivate { nickname } => {
                    match require_superadmin(options, &reg, id) {
                        Err(e) => Outgoing::refuse(id, e),
                        Ok(_) => {
                            let _ = options.users.admin_force_activate(&nickname);
                            Vec::new()
                        }
                    }
                }
                ClientMessage::AdminRemoveAccount { nickname } => {
                    match require_superadmin(options, &reg, id) {
                        Err(e) => Outgoing::refuse(id, e),
                        Ok(_) => {
                            let _ = options.users.remove(&nickname);
                            let mut out = reg.remove_channels_administered_by(
                                &nickname,
                                "the channel has been removed by the admin",
                            );
                            if let Some(target_id) = reg.id_by_name(&nickname) {
                                out.push(Outgoing::error(
                                    target_id,
                                    "this account has been removed from the server",
                                ));
                            }
                            out
                        }
                    }
                }
                ClientMessage::AdminRemoveChannel { name } => {
                    match require_superadmin(options, &reg, id) {
                        Err(e) => Outgoing::refuse(id, e),
                        Ok(_) => reg.remove_channel(&name, "removed by a superadmin"),
                    }
                }
                ClientMessage::RequestUsersList => match require_superadmin(options, &reg, id) {
                    Err(e) => Outgoing::refuse(id, e),
                    Ok(_) => {
                        let users = options
                            .users
                            .nicknames()
                            .into_iter()
                            .map(|nickname| {
                                let admin_of = reg.channels.channels_administered_by(&nickname);
                                proto::UserAdminInfo { nickname, admin_of }
                            })
                            .collect();
                        vec![Outgoing::new(id, ServerMessage::UsersList { users })]
                    }
                },
                ClientMessage::RotateKey {
                    to,
                    new_public_key_der,
                    signature,
                } => match reg.route_key_rotation(id, to, new_public_key_der, signature) {
                    Ok(o) => vec![o],
                    Err(reason) => Outgoing::refuse(id, reason),
                },
                ClientMessage::RequestPeerLink {
                    peer,
                    candidates,
                    link_nonce,
                } => match reg.route_peer_link_request(id, peer, candidates, link_nonce) {
                    Ok(o) => vec![o],
                    Err(reason) => Outgoing::refuse(id, reason),
                },
                // Purely a liveness signal - already did its job just by
                // arriving and resetting the timeout above.
                ClientMessage::Heartbeat => Vec::new(),
                ClientMessage::OtpMailSend {
                    mail_id,
                    to,
                    contact_name,
                    seq,
                    sent_at_utc,
                    ciphertext,
                } => mail::on_mail_send(
                    &reg, mail_store, id, mail_id, to, contact_name, seq, sent_at_utc, ciphertext,
                ),
                ClientMessage::OtpMailFetch => mail::on_mail_fetch(&reg, mail_store, id),
                ClientMessage::OtpMailAck { mail_id } => {
                    mail::on_mail_ack(&reg, mail_store, id, mail_id)
                }
                ClientMessage::OtpMailDeliveredAck { mail_id } => {
                    mail::on_mail_delivered_ack(&reg, mail_store, id, mail_id)
                }
                ClientMessage::SecureChannel(_)
                | ClientMessage::Auth { .. }
                | ClientMessage::Activate { .. }
                | ClientMessage::Register { .. }
                | ClientMessage::Identify { .. } => {
                    Outgoing::refuse(id, "unexpected message after handshake")
                }
            }
        };
        dispatch(senders, outgoing).await;
    }
}

/// `Register` (§5.3) end to end: the abuse gate, the policy checks, the
/// registry write, and the activation email - with the registration
/// rolled back if the email cannot be handed to the relay, so a name is
/// never left taken by an account whose code nobody received. `Err`
/// carries the reason the client is shown.
async fn register_account(
    options: &ServerOptions,
    nickname: &str,
    password: &str,
    email: &str,
    peer_ip: IpAddr,
) -> Result<(), String> {
    if !options.allow_registration {
        return Err("this server does not take registrations".into());
    }
    // More than 3 registration attempts from one address within 2 days -
    // i.e. this, the 4th - refuses this one and every other for the next
    // 7 days. Counted on every attempt (not just ones that go on to
    // succeed), same as `login_bans` counts every wrong password: the
    // thing being rate-limited is load on this endpoint, not successful
    // account creation specifically.
    if options
        .registration_bans
        .lock()
        .await
        .record_strike(
            peer_ip,
            users_registry::now_utc(),
            &REGISTRATION_ABUSE_STRIKES,
        )
        == BanOutcome::Banned
    {
        return Err(
            "too many registrations from this address recently - try again later".into(),
        );
    }
    let Some(smtp) = &options.smtp else {
        return Err("this server has no email delivery configured for registrations".into());
    };
    let registration = {
        let users = options.users.clone();
        let (nickname, password, email) = (
            nickname.to_string(),
            password.to_string(),
            email.to_string(),
        );
        tokio::task::spawn_blocking(move || {
            users.register(&nickname, &password, &email, users_registry::now_utc())
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?
    };
    if let Err(e) =
        users_registry::send_activation_email(smtp, email, nickname, &registration.code).await
    {
        crate::log_warn!("activation email for {nickname} could not be sent: {e}");
        let _ = options.users.remove(nickname);
        return Err("the activation email could not be sent - try again later".into());
    }
    Ok(())
}

/// A login attempt against an account whose activation code has expired
/// (§5.1): reissues a fresh code (`UsersRegistry::reissue_activation`) and
/// re-sends the activation email with the data already on file, exactly
/// as `register_account` does when the same account is registered again
/// while expired - so `handle_connection`'s `ActivationPending { expired:
/// true }` arm never has to end in an outright refusal when there's
/// somewhere to actually send a fresh code. `false` (nothing changed, the
/// caller falls back to refusing) when there's no SMTP relay configured,
/// no email on file for this account (`register_manual` has none), no
/// expired pending activation to reissue against after all, or the relay
/// itself fails to accept the email.
async fn reissue_and_resend_activation(options: &ServerOptions, nickname: &str) -> bool {
    let Some(smtp) = &options.smtp else {
        return false;
    };
    let Some(email) = options.users.email_of(nickname) else {
        return false;
    };
    let registration = {
        let users = options.users.clone();
        let owned_nickname = nickname.to_string();
        let result = tokio::task::spawn_blocking(move || {
            users.reissue_activation(&owned_nickname, users_registry::now_utc())
        })
        .await;
        match result {
            Ok(Ok(Some(registration))) => registration,
            Ok(Ok(None)) => return false,
            Ok(Err(e)) => {
                crate::log_warn!("reissuing activation for {nickname}: {e}");
                return false;
            }
            Err(e) => {
                crate::log_warn!("reissuing activation for {nickname}: {e}");
                return false;
            }
        }
    };
    if let Err(e) =
        users_registry::send_activation_email(smtp, &email, nickname, &registration.code).await
    {
        crate::log_warn!("resent activation email for {nickname} could not be sent: {e}");
        return false;
    }
    true
}

async fn dispatch(senders: &Senders, outgoing: Vec<Outgoing>) {
    let map = senders.lock().await;
    for o in outgoing {
        if let Some(tx) = map.get(&o.to) {
            let _ = tx.send(o.message);
        }
    }
}
