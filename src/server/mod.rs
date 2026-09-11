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
pub mod federation;
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
    /// `server_federation_enabled=on` - this server's link into a
    /// federation of peer servers (`federation`). `None` (the default)
    /// means every federation-aware check in this module is a no-op, so
    /// an unconfigured server behaves exactly as it did before federation
    /// existed.
    pub federation: Option<Arc<federation::FederationConfig>>,
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
            federation: None,
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

    pub fn with_federation(mut self, config: federation::FederationConfig) -> Self {
        self.federation = Some(Arc::new(config));
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
    /// Federation only: a stable, made-up `UserId` for each federated
    /// member this server has ever displayed (in a `UserJoined`/`UserLeft`
    /// for a channel it mirrors) - minted lazily the first time a given
    /// (server, nickname) is seen, from `next_remote_id` counting *down*
    /// from `FEDERATED_ID_CEILING` rather than `next_id`'s own count up
    /// from 1, so the two id spaces can never collide regardless of how
    /// long either server runs. Never forgotten (no cleanup on a
    /// departure): the reservation is cheap to keep and means the same
    /// federated person keeps the same id across every channel and every
    /// rejoin, for the life of this server's process.
    remote_ids: HashMap<(String, String), UserId>,
    next_remote_id: u64,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// The highest `UserId` a federated member may ever be given, and the one
/// `mint_remote_user_id` starts counting *down* from.
///
/// Deliberately **not** `u64::MAX`, for two independent reasons, both in
/// the client:
///
/// - `client::p2p::direct_peer_id` mints its own synthetic ids for
///   serverless direct-punch peers as `hash | 0x8000_0000_0000_0000`, and
///   `is_direct_peer_id` asks nothing more than whether that top bit is
///   set. An id with the top bit set is therefore read by every client as
///   "a peer no server has ever heard of", which makes
///   `p2p::PeerLink::ensure_link` short-circuit to `Pending` forever: the
///   member would sit permanently yellow in the sidebar and anything sent
///   to them would queue silently, with no error and no timeout.
/// - `client::voice_call` uses `UserId(u64::MAX)` itself as its "own id
///   not known yet" sentinel, which the very first federated member a
///   server ever displayed would otherwise be handed exactly.
///
/// Staying below the top bit keeps both of those distinctions intact while
/// preserving the only property the counting-down trick needs: a real
/// local id (counting up from 1) would have to be handed out ~9.2
/// quintillion times to reach it.
const FEDERATED_ID_CEILING: u64 = 0x7FFF_FFFF_FFFF_FFFF;

/// The free-function form of `Registry::remote_user_id`/`remote_user_info`,
/// taking `remote_ids`/`next_remote_id` directly rather than `&mut
/// Registry` - what a wrapper method that also needs to borrow
/// `self.channels` mutably at the same time (`self.channels.join(...)`,
/// say) calls instead, since Rust can see these as disjoint field borrows
/// but not through a `self.method()` call on the whole `Registry`.
fn mint_remote_user_id(
    remote_ids: &mut HashMap<(String, String), UserId>,
    next_remote_id: &mut u64,
    server: &str,
    nickname: &str,
) -> UserId {
    let key = (server.to_string(), nickname.to_string());
    if let Some(id) = remote_ids.get(&key) {
        return *id;
    }
    let id = UserId(*next_remote_id);
    *next_remote_id -= 1;
    remote_ids.insert(key, id);
    id
}

fn mint_remote_user_info(
    remote_ids: &mut HashMap<(String, String), UserId>,
    next_remote_id: &mut u64,
    identity: &federation::proto::RemoteIdentity,
) -> UserInfo {
    UserInfo {
        id: mint_remote_user_id(remote_ids, next_remote_id, &identity.server, &identity.nickname),
        name: identity.nickname.clone(),
        public_key_der: identity.public_key_der.clone(),
        key_mode: identity.key_mode,
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
            remote_ids: HashMap::new(),
            next_remote_id: FEDERATED_ID_CEILING,
        }
    }

    /// `new`, with the inactivity sweep's period configured from the
    /// start - what `serve_tcp` actually builds from `ServerOptions`.
    pub fn with_channel_deletion_period(period: Option<Duration>) -> Self {
        Self {
            clients: HashMap::new(),
            next_id: 1,
            channels: channels_registry::ChannelsRegistry::new(period),
            remote_ids: HashMap::new(),
            next_remote_id: FEDERATED_ID_CEILING,
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

    /// Whether `name` already exists, public or private.
    pub fn channel_exists(&self, name: &str) -> bool {
        self.channels.contains(name)
    }

    /// Every channel `id` currently belongs to.
    pub fn channel_membership_of(&self, id: UserId) -> Vec<String> {
        self.channels.member_of(id)
    }

    /// Whether `id` already belongs to `channel`.
    pub fn is_channel_member(&self, channel: &str, id: UserId) -> bool {
        self.channels.is_member(channel, id)
    }

    /// Validates and (on success) records a federation peer's join-proxy
    /// request - see `channels_registry::ChannelsRegistry::join_remote`.
    /// Only ever called on the server that actually owns `name`. The
    /// `Vec<Outgoing>` in a successful result is for this server's own
    /// *local* members of `name`, who need to be told `identity` just
    /// joined - the caller (`crate::server::federation`) dispatches them
    /// and gossips `ChannelMemberJoined` to every other linked peer.
    pub fn join_channel_remote(
        &mut self,
        name: &str,
        identity: &federation::proto::RemoteIdentity,
        password: Option<&str>,
        source_ip: IpAddr,
    ) -> Option<Result<(ChannelKind, Option<String>, Vec<Outgoing>), proto::ChannelJoinRejection>> {
        let clients = &self.clients;
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels.join_remote(
            name,
            identity,
            password,
            source_ip,
            |uid| {
                clients.get(&uid).map(|c| UserInfo {
                    id: uid,
                    name: c.name.clone(),
                    public_key_der: c.public_key_der.clone(),
                    key_mode: c.key_mode,
                })
            },
            |identity| mint_remote_user_info(remote_ids, next_remote_id, identity),
        )
    }

    /// Applies a federation peer's `LeaveProxyNotice` - see
    /// `channels_registry::ChannelsRegistry::leave_remote`. The result is
    /// for this server's own local members of `name` (the caller gossips
    /// `ChannelMemberLeft` on to every other linked peer).
    pub fn leave_channel_remote(&mut self, name: &str, remote_server: &str, nickname: &str) -> Vec<Outgoing> {
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels.leave_remote(name, remote_server, nickname, |server, nickname| {
            mint_remote_user_id(remote_ids, next_remote_id, server, nickname)
        })
    }

    /// Applies third-party `ChannelMemberJoined` gossip locally - see
    /// `channels_registry::ChannelsRegistry::mirror_member_joined`.
    pub fn mirror_channel_member_joined(
        &mut self,
        channel: &str,
        identity: &federation::proto::RemoteIdentity,
    ) -> Vec<Outgoing> {
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels
            .mirror_member_joined(channel, identity, |identity| mint_remote_user_info(remote_ids, next_remote_id, identity))
    }

    /// Applies third-party `ChannelMemberLeft` gossip locally - see
    /// `channels_registry::ChannelsRegistry::mirror_member_left`.
    pub fn mirror_channel_member_left(&mut self, channel: &str, server: &str, nickname: &str) -> Vec<Outgoing> {
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels.mirror_member_left(channel, server, nickname, |server, nickname| {
            mint_remote_user_id(remote_ids, next_remote_id, server, nickname)
        })
    }

    /// The displayable identity a federated member is shown under here,
    /// minting their synthetic id if this is the first sight of them -
    /// what a signal relayed to one of this server's clients names as its
    /// sender, so it matches the id that member's `UserJoined` used.
    pub fn remote_user_info(
        &mut self,
        identity: &federation::proto::RemoteIdentity,
    ) -> UserInfo {
        mint_remote_user_info(&mut self.remote_ids, &mut self.next_remote_id, identity)
    }

    /// Which federated member a synthetic `UserId` stands for, if it is
    /// one at all - the reverse of `mint_remote_user_id`.
    ///
    /// A client asks for a link, or offers a key rotation, by naming a
    /// `UserId`, and for a federated member that is an id this server made
    /// up locally and no other server has ever heard of. Going back the
    /// other way is what lets the request be addressed to a person on a
    /// named server instead (`FederationMessage::PeerSignal`).
    pub fn federated_member_of(&self, id: UserId) -> Option<(String, String)> {
        self.remote_ids
            .iter()
            .find(|(_, minted)| **minted == id)
            .map(|(key, _)| key.clone())
    }

    /// Whether `id` and the federated member `(server, nickname)` share a
    /// channel - see `ChannelsRegistry::share_a_channel` for why anything
    /// relayed between two clients is gated on it.
    pub fn shares_a_channel_with_federated(
        &self,
        id: UserId,
        server: &str,
        nickname: &str,
    ) -> bool {
        self.channels.share_a_channel(id, server, nickname)
    }

    /// Everyone currently in `channel`, federation-wide - see
    /// `channels_registry::ChannelsRegistry::federated_membership_of`.
    pub fn federated_membership_of(
        &self,
        channel: &str,
        self_id: &str,
    ) -> Vec<federation::proto::RemoteIdentity> {
        let clients = &self.clients;
        self.channels.federated_membership_of(channel, self_id, |uid| {
            clients.get(&uid).map(|c| UserInfo {
                id: uid,
                name: c.name.clone(),
                public_key_der: c.public_key_der.clone(),
                key_mode: c.key_mode,
            })
        })
    }

    /// Applies a home server's authoritative membership list - see
    /// `channels_registry::ChannelsRegistry::replace_mirrored_members`.
    pub fn replace_mirrored_members(
        &mut self,
        channel: &str,
        self_id: &str,
        members: Vec<federation::proto::RemoteIdentity>,
    ) -> Vec<Outgoing> {
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels.replace_mirrored_members(channel, self_id, members, |identity| {
            mint_remote_user_info(remote_ids, next_remote_id, identity)
        })
    }

    /// Forgets every federated member connected through `server` - see
    /// `channels_registry::ChannelsRegistry::forget_members_of_server`.
    pub fn forget_federated_members_of(&mut self, server: &str) -> Vec<Outgoing> {
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels.forget_members_of_server(server, |server, nickname| {
            mint_remote_user_id(remote_ids, next_remote_id, server, nickname)
        })
    }

    /// "Fully shared channel list" - see
    /// `channels_registry::ChannelsRegistry::ensure_public_mirror`.
    pub fn ensure_public_channel_known(&mut self, name: &str, kind: ChannelKind) -> bool {
        self.channels.ensure_public_mirror(name, kind)
    }

    /// Every currently-connected client's `UserId` - used to broadcast
    /// something to everyone, such as a federated public channel's
    /// `ChannelCreated` the moment this server first learns of it.
    pub fn all_client_ids(&self) -> Vec<UserId> {
        self.clients.keys().copied().collect()
    }

    /// Mirrors a federation join-proxy's grant locally - see
    /// `channels_registry::ChannelsRegistry::mirror_remote_join`.
    pub fn mirror_remote_join(
        &mut self,
        id: UserId,
        name: &str,
        kind: ChannelKind,
        admin: Option<String>,
    ) -> Result<Vec<Outgoing>, String> {
        let joiner = self.user_info(id).ok_or_else(|| "unknown user".to_string())?;
        let clients = &self.clients;
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        Ok(self.channels.mirror_remote_join(
            id,
            &joiner,
            name,
            kind,
            admin,
            |uid| {
                clients.get(&uid).map(|c| UserInfo {
                    id: uid,
                    name: c.name.clone(),
                    public_key_der: c.public_key_der.clone(),
                    key_mode: c.key_mode,
                })
            },
            |identity| mint_remote_user_info(remote_ids, next_remote_id, identity),
        ))
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
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
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
            |identity| mint_remote_user_info(remote_ids, next_remote_id, identity),
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
    /// The `(server, nickname)` pairs alongside the outgoing messages are
    /// the *federated* members the ban removed - the caller gossips a
    /// `ChannelMemberLeft` for each so the rest of the federation stops
    /// listing them (`server::federation_announce_ban`).
    pub fn ban_from_channel(
        &mut self,
        caller: UserId,
        channel: &str,
        target_nickname: &str,
    ) -> Result<(Vec<Outgoing>, Vec<(String, String)>), String> {
        let caller_name = self
            .user_info(caller)
            .ok_or_else(|| "unknown user".to_string())?
            .name;
        let target_id = self.id_by_name(target_nickname);
        let remote_ids = &mut self.remote_ids;
        let next_remote_id = &mut self.next_remote_id;
        self.channels.ban(&caller_name, channel, target_nickname, target_id, |server, nickname| {
            mint_remote_user_id(remote_ids, next_remote_id, server, nickname)
        })
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
    pub fn sweep_inactive_channels(&mut self) -> Vec<String> {
        self.channels.sweep_inactive()
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

pub(crate) type Senders = Arc<Mutex<HashMap<UserId, mpsc::UnboundedSender<ServerMessage>>>>;

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
/// long (`channels_registry::ChannelsRegistry::sweep_inactive`), gossiping
/// each one's departure when federation is on. Modeled on
/// `udp_rendezvous_loop`'s "degrade, never take the whole task down"
/// shape, though there is nothing here that can actually fail.
async fn channel_sweep_loop(registry: Arc<Mutex<Registry>>, federation: Option<Arc<federation::FederationConfig>>) {
    let mut ticker = tokio::time::interval(CHANNEL_SWEEP_INTERVAL);
    loop {
        ticker.tick().await;
        let removed = registry.lock().await.sweep_inactive_channels();
        if let Some(federation) = &federation {
            for name in &removed {
                federation::announce_channel_removed(federation, name).await;
            }
        }
    }
}

async fn serve_tcp(listener: TcpListener, options: ServerOptions) -> std::io::Result<()> {
    let registry = Arc::new(Mutex::new(Registry::with_channel_deletion_period(
        options.channel_deletion_unactivity_period,
    )));
    if options.channel_deletion_unactivity_period.is_some() {
        tokio::spawn(channel_sweep_loop(registry.clone(), options.federation.clone()));
    }
    let senders: Senders = Arc::new(Mutex::new(HashMap::new()));
    // Shared without a lock of its own: every method works on one file at a
    // time and the racy interleavings (two connections storing/acking the
    // same id) each resolve to a harmless no-op for the loser.
    let mail_store = Arc::new(mail::MailStore::open(options.mail_dir.clone())?);
    if let Some(config) = options.federation.clone() {
        let ctx = federation::FederationContext {
            config,
            registry: registry.clone(),
            senders: senders.clone(),
            mail_store: mail_store.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = federation::run(ctx).await {
                crate::log_warn!("federation listener stopped: {e}");
            }
        });
    }
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
    // A nickname with no local account can never pass the credential
    // check below regardless of password - if federation already knows
    // it belongs elsewhere (or is in conflict), answer that directly
    // rather than paying for the derivation just to say "rejected" for a
    // reason federation can already name more precisely.
    let check = if let Some(check) = federation_login_precheck(&options, &nickname).await {
        check
    } else {
        // The derivation is deliberately slow (§5.1) and the check reads
        // the registry's files - neither belongs on the async executor.
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
        AuthCheck::RegisteredElsewhere { server_addr } => {
            refuse_auth(
                &mut wr,
                format!(
                    "this nickname is registered on a different federated server - connect to \
                     {server_addr} instead"
                ),
            )
            .await;
            return Ok(());
        }
        AuthCheck::Conflicted => {
            refuse_auth(
                &mut wr,
                "this nickname exists on multiple federated servers - contact an administrator",
            )
            .await;
            return Ok(());
        }
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
                    federation_announce_nickname_removed(&options, &nickname).await;
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

    // Every federation-owned-elsewhere channel this connection was still
    // in is told about the departure before `unregister` forgets its
    // membership entirely - a disconnect gets exactly the same notice an
    // explicit `LeaveChannel` does (see that arm in `client_loop`).
    if let Some(federation) = &options.federation {
        let (nickname, channels) = {
            let reg = registry.lock().await;
            (reg.user_info(id).map(|u| u.name), reg.channel_membership_of(id))
        };
        if let Some(nickname) = nickname {
            for channel in channels {
                federation.notify_leave_if_remote(&channel, &nickname).await;
                federation_announce_channel_member_left(&options, &channel, &nickname).await;
            }
        }
    }

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

/// Whether `nickname` belongs to a different federated server, or is
/// claimed by more than one - checked before the slow local credential
/// derivation runs (see the call site in `handle_connection`). `None`
/// when there is nothing to redirect: federation is off, the nickname has
/// a local account (an ordinary login, or a login while its registration
/// is still only locally recorded and hasn't gossiped out yet), or it is
/// unknown anywhere in the federation - an ordinary `AuthCheck::Rejected`
/// still applies for that last case, exactly as before federation
/// existed.
async fn federation_login_precheck(options: &ServerOptions, nickname: &str) -> Option<AuthCheck> {
    let federation = options.federation.as_ref()?;
    if options.users.is_registered(nickname) {
        return None;
    }
    let owner = match federation.directory.lock().await.owner_of_nickname(nickname)? {
        federation::directory::Ownership::Owned(owner) if *owner == federation.self_id => return None,
        federation::directory::Ownership::Owned(owner) => owner.clone(),
        federation::directory::Ownership::Conflicted(_) => return Some(AuthCheck::Conflicted),
    };
    // The address that peer announces for its *clients*, never the
    // federation address this server dials it on - see
    // `FederationConfig::peer_client_addr`. Falling back to the server's
    // federation id rather than guessing at an address keeps the answer
    // honest: "your account is on serverB" is useful; "connect to
    // serverb.example.com:7880" is a port nothing would answer on.
    Some(AuthCheck::RegisteredElsewhere {
        server_addr: federation.peer_client_addr(&owner).await.unwrap_or(owner),
    })
}

/// If `name` is a channel the federation directory says a *different*
/// server owns, proxies the join to it (`FederationConfig::request_join_proxy`)
/// and returns the answer to give `id` either way: a real local mirror
/// join on success (`Registry::mirror_remote_join`), or the same
/// `ChannelJoinRejected`/`ChannelJoinFailed` shape a local `join` would
/// have produced on refusal. Already-mirrored membership short-circuits
/// straight to a fresh `Joined` with no round trip at all - proxying is
/// only ever needed the *first* time this connection joins a given
/// remote-homed channel. `None` when there is nothing to proxy
/// (federation is off, or `name` is unowned or owned by this server) -
/// `client_loop` falls through to an ordinary local `join` in that case.
async fn federation_proxy_join(
    options: &ServerOptions,
    registry: &Arc<Mutex<Registry>>,
    id: UserId,
    name: &str,
    password: Option<&str>,
) -> Option<Vec<Outgoing>> {
    let federation = options.federation.as_ref()?;
    let owner = {
        let dir = federation.directory.lock().await;
        match dir.owner_of_channel(name) {
            Some(info) if info.owner != federation.self_id => info.owner.clone(),
            Some(_) => return None, // owned by this server - ordinary local join
            None if dir.channel_is_conflicted(name) => {
                return Some(vec![Outgoing::new(
                    id,
                    ServerMessage::ChannelJoinFailed {
                        name: name.to_string(),
                        reason: "this channel exists on multiple federated servers and needs \
                                 administrator resolution"
                            .to_string(),
                    },
                )]);
            }
            None => return None, // genuinely unknown - fall through to local create/join
        }
    };
    // Already mirrored locally (this connection proxied this exact
    // channel before): a no-op, exactly like `join`'s own
    // already-a-member case - no round trip, no answer sent.
    let already_mirrored = {
        let reg = registry.lock().await;
        reg.is_channel_member(name, id)
    };
    if already_mirrored {
        return Some(Vec::new());
    }
    let joiner_info = {
        let reg = registry.lock().await;
        reg.user_info(id)?
    };
    let outcome = federation
        .request_join_proxy(
            name,
            &joiner_info.name,
            password,
            joiner_info.public_key_der.clone(),
            joiner_info.key_mode,
        )
        .await;
    Some(match outcome {
        Ok(federation::proto::JoinProxyOutcome::Joined { kind, admin }) => {
            let mut reg = registry.lock().await;
            reg.mirror_remote_join(id, name, kind, admin)
                .unwrap_or_else(|reason| Outgoing::refuse(id, reason))
        }
        Ok(federation::proto::JoinProxyOutcome::Rejected(rejection)) => vec![Outgoing::new(
            id,
            ServerMessage::ChannelJoinRejected {
                name: name.to_string(),
                kind: rejection,
            },
        )],
        Ok(federation::proto::JoinProxyOutcome::UnknownChannel) => vec![Outgoing::new(
            id,
            ServerMessage::ChannelJoinFailed {
                name: name.to_string(),
                reason: format!("federated server '{owner}' no longer has this channel"),
            },
        )],
        Err(reason) => vec![Outgoing::new(id, ServerMessage::ChannelJoinFailed { name: name.to_string(), reason })],
    })
}

/// `ClientMessage::JoinChannel`'s full handling, run with the registry
/// unlocked except for the brief, bounded moments `federation_proxy_join`
/// and the local `join_channel_with_policy` call themselves need it -
/// pulled out of `client_loop`'s "lock once for the whole match" pattern
/// for exactly that reason (see the call site).
async fn handle_join_channel(
    id: UserId,
    registry: &Arc<Mutex<Registry>>,
    options: &Arc<ServerOptions>,
    source_ip: IpAddr,
    name: String,
    kind: ChannelKind,
    password: Option<String>,
) -> Vec<Outgoing> {
    if let Some(outgoing) = federation_proxy_join(options, registry, id, &name, password.as_deref()).await {
        return outgoing;
    }
    let name_for_err = name.clone();
    let (existed_before, result, joiner_info) = {
        let mut reg = registry.lock().await;
        let existed_before = reg.channel_exists(&name);
        let result = reg.join_channel_with_policy(
            id,
            &name,
            kind,
            password.as_deref(),
            source_ip,
            options.allow_create_public_channels,
        );
        let joiner_info = reg.user_info(id);
        (existed_before, result, joiner_info)
    };
    if !existed_before && result.is_ok() {
        federation_announce_channel(options, &name, kind).await;
    }
    if result.is_ok()
        && let Some(joiner_info) = joiner_info
    {
        federation_announce_channel_member(options, &name, joiner_info).await;
    }
    result.unwrap_or_else(|reason| {
        vec![Outgoing::new(
            id,
            ServerMessage::ChannelJoinFailed {
                name: name_for_err,
                reason,
            },
        )]
    })
}

/// Records a freshly (locally) created channel in the federation
/// directory and gossips it to every linked peer - called only once,
/// right after a `JoinChannel` is confirmed to have created `name`
/// (see the call site in `client_loop`), never for a join of an
/// already-existing channel.
async fn federation_announce_channel(options: &ServerOptions, name: &str, kind: ChannelKind) {
    let Some(federation) = &options.federation else {
        return;
    };
    let info = federation::proto::FederatedChannelInfo {
        name: name.to_string(),
        kind,
        owner: federation.self_id.clone(),
    };
    federation.directory.lock().await.record_local_channel(info.clone());
    federation::broadcast(
        federation,
        federation::proto::FederationMessage::ChannelRegistered { channel: info },
        federation::event::CHANNEL_GOSSIP,
    )
    .await;
}

/// Gossips `member`'s (local) join to `name` to every linked peer, so a
/// server that mirrors this channel - whether as its own home too (never
/// possible, ownership is exclusive) or because one of its own clients
/// joined it via proxy - learns of the new member. A no-op unless the
/// federation directory says *this* server owns `name`: only the home
/// server ever has full membership visibility, so it is the only one
/// that ever sends this (a channel this server merely mirrors gossips
/// nothing on a local join to it - there is no such thing, a local join
/// to a peer-owned channel is always proxied, never local). Called after
/// every successful `JoinChannel`, new channel or not - a rejoin to an
/// already-owned channel is a harmless repeat on the receiving end
/// (`ChannelsRegistry::mirror_member_joined` is idempotent).
async fn federation_announce_channel_member(options: &ServerOptions, name: &str, member: UserInfo) {
    let Some(federation) = &options.federation else {
        return;
    };
    let owned_by_self = matches!(
        federation.directory.lock().await.owner_of_channel(name),
        Some(info) if info.owner == federation.self_id
    );
    if !owned_by_self {
        return;
    }
    let identity = federation::proto::RemoteIdentity {
        server: federation.self_id.clone(),
        nickname: member.name,
        public_key_der: member.public_key_der,
        key_mode: member.key_mode,
    };
    federation::broadcast(
        federation,
        federation::proto::FederationMessage::ChannelMemberJoined { channel: name.to_string(), member: identity },
        federation::event::CHANNEL_MEMBER_JOINED,
    )
    .await;
}

/// Relays one client's signal to a client on another federated server,
/// when `to` is a federated member rather than one of this server's own
/// connections (docs/PROTOCOL.md §18.5).
///
/// `None` means this was an ordinary local `UserId` after all, and the
/// caller should route it locally exactly as before - so nothing about a
/// single-server deployment, or about two clients on the same server,
/// changes. `Some` is the answer to give the client, which is *nothing*:
/// there is no acknowledgement to send, the same as a local route, and
/// the client's own retry covers a signal that goes astray.
async fn federation_peer_signal(
    options: &ServerOptions,
    reg: &mut Registry,
    from: UserId,
    to: UserId,
    payload: federation::proto::PeerSignalPayload,
) -> Option<Vec<Outgoing>> {
    let federation = options.federation.as_ref()?;
    let (to_server, to_nickname) = reg.federated_member_of(to)?;
    // The gate, applied here as well as on delivery: two clients may only
    // be introduced to each other if they already share a channel, which
    // is the same condition two clients on one server meet before
    // exchanging addresses.
    if !reg.shares_a_channel_with_federated(from, &to_server, &to_nickname) {
        return Some(Outgoing::refuse(from, crate::proto::UNKNOWN_RECIPIENT));
    }
    let sender = reg.user_info(from)?;
    federation
        .send_peer_signal(
            &to_server,
            &to_nickname,
            federation::proto::RemoteIdentity {
                server: federation.self_id.clone(),
                nickname: sender.name,
                public_key_der: sender.public_key_der,
                key_mode: sender.key_mode,
            },
            payload,
        )
        .await;
    Some(Vec::new())
}

/// Tells every linked peer that a `/ban` just removed a *federated*
/// member from one of this server's channels, so they stop listing
/// someone the channel's own admin has thrown out. Reuses
/// `ChannelMemberLeft` rather than inventing a ban-specific message:
/// every other server only mirrors presence, and the ban itself is
/// enforced where it lives - here, on the home server, at the next
/// `JoinProxyRequest`.
async fn federation_announce_ban(
    options: &ServerOptions,
    channel: &str,
    member_server: &str,
    nickname: &str,
) {
    let Some(federation) = &options.federation else {
        return;
    };
    federation::broadcast(
        federation,
        federation::proto::FederationMessage::ChannelMemberLeft {
            channel: channel.to_string(),
            server: member_server.to_string(),
            nickname: nickname.to_string(),
        },
        federation::event::CHANNEL_MEMBER_LEFT,
    )
    .await;
}

/// The departure mirror of `federation_announce_channel_member` - see its
/// doc for why this is a no-op unless `name` is owned by this server.
async fn federation_announce_channel_member_left(options: &ServerOptions, name: &str, nickname: &str) {
    let Some(federation) = &options.federation else {
        return;
    };
    let owned_by_self = matches!(
        federation.directory.lock().await.owner_of_channel(name),
        Some(info) if info.owner == federation.self_id
    );
    if !owned_by_self {
        return;
    }
    federation::broadcast(
        federation,
        federation::proto::FederationMessage::ChannelMemberLeft {
            channel: name.to_string(),
            server: federation.self_id.clone(),
            nickname: nickname.to_string(),
        },
        federation::event::CHANNEL_MEMBER_LEFT,
    )
    .await;
}

/// Records a locally-removed channel's departure in the federation
/// directory and gossips it to every linked peer - the deletion mirror of
/// `federation_announce_channel`. Called for `/delete-channel`, a
/// superadmin's `/remove-channel` (single or via account removal), and
/// the inactivity sweep alike, so a deleted channel's name eventually
/// stops being permanently blocked federation-wide instead of staying
/// "owned by a server that no longer has it" forever.
async fn federation_announce_channel_removed(options: &ServerOptions, name: &str) {
    let Some(federation) = &options.federation else {
        return;
    };
    federation::announce_channel_removed(federation, name).await;
}

/// The nickname mirror of `federation_announce_channel_removed` - called
/// for a superadmin's `/remove-account`.
async fn federation_announce_nickname_removed(options: &ServerOptions, nickname: &str) {
    let Some(federation) = &options.federation else {
        return;
    };
    federation::announce_nickname_removed(federation, nickname).await;
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
        // `JoinChannel` is handled outside the "lock the registry for the
        // whole match" pattern every other arm below uses: proxying it to
        // a federation peer (`federation_proxy_join`) can wait seconds on
        // a real network round trip, and holding the registry locked that
        // long would stall every other client on this server - including
        // this server's own federation link, which needs that same lock
        // to answer *other* servers' requests.
        if let ClientMessage::JoinChannel { name, kind, password } = msg {
            let outgoing = handle_join_channel(
                id,
                registry,
                options,
                source_ip,
                name,
                kind,
                password,
            )
            .await;
            dispatch(senders, outgoing).await;
            continue;
        }
        let outgoing = {
            let mut reg = registry.lock().await;
            match msg {
                ClientMessage::LeaveChannel { name } => {
                    let nickname = reg.user_info(id).map(|u| u.name);
                    let outgoing = reg.leave_channel(id, &name);
                    if let Some(federation) = &options.federation
                        && let Some(nickname) = &nickname
                    {
                        federation.notify_leave_if_remote(&name, nickname).await;
                        federation_announce_channel_member_left(options, &name, nickname).await;
                    }
                    outgoing
                }
                ClientMessage::DeleteChannel { name } => {
                    let result = reg.delete_channel(id, &name);
                    if result.is_ok() {
                        federation_announce_channel_removed(options, &name).await;
                    }
                    or_refuse(id, result)
                }
                ClientMessage::BanFromChannel { channel, nickname } => {
                    match reg.ban_from_channel(id, &channel, &nickname) {
                        Ok((outgoing, banned_federated)) => {
                            for (server, nickname) in banned_federated {
                                federation_announce_ban(options, &channel, &server, &nickname).await;
                            }
                            outgoing
                        }
                        Err(reason) => Outgoing::refuse(id, reason),
                    }
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
                            let administered = reg.channels.channels_administered_by(&nickname);
                            let mut out = reg.remove_channels_administered_by(
                                &nickname,
                                "the channel has been removed by the admin",
                            );
                            for name in &administered {
                                federation_announce_channel_removed(options, name).await;
                            }
                            federation_announce_nickname_removed(options, &nickname).await;
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
                        Ok(_) => {
                            let out = reg.remove_channel(&name, "removed by a superadmin");
                            federation_announce_channel_removed(options, &name).await;
                            out
                        }
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
                } => {
                    if let Some(payload) = federation_peer_signal(
                        options,
                        &mut reg,
                        id,
                        to,
                        federation::proto::PeerSignalPayload::KeyRotation {
                            new_public_key_der: new_public_key_der.clone(),
                            signature: signature.clone(),
                        },
                    )
                    .await
                    {
                        payload
                    } else {
                        match reg.route_key_rotation(id, to, new_public_key_der, signature) {
                            Ok(o) => vec![o],
                            Err(reason) => Outgoing::refuse(id, reason),
                        }
                    }
                }
                ClientMessage::RequestPeerLink {
                    peer,
                    candidates,
                    link_nonce,
                } => {
                    if let Some(relayed) = federation_peer_signal(
                        options,
                        &mut reg,
                        id,
                        peer,
                        federation::proto::PeerSignalPayload::Candidates {
                            candidates: candidates.clone(),
                            link_nonce,
                        },
                    )
                    .await
                    {
                        relayed
                    } else {
                        match reg.route_peer_link_request(id, peer, candidates, link_nonce) {
                            Ok(o) => vec![o],
                            Err(reason) => Outgoing::refuse(id, reason),
                        }
                    }
                }
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
                } => {
                    let (outgoing, mail_for_relay) = mail::on_mail_send_with_relay_info(
                        &reg, mail_store, id, mail_id, to.clone(), contact_name, seq, sent_at_utc, ciphertext,
                    );
                    if let Some(federation) = &options.federation
                        && let Some(mail) = mail_for_relay
                    {
                        federation.forward_mail_if_remote(&mail).await;
                    }
                    outgoing
                }
                ClientMessage::OtpMailFetch => mail::on_mail_fetch(&reg, mail_store, id),
                ClientMessage::OtpMailAck { mail_id } => {
                    let (outgoing, receipt) = mail::on_mail_ack_with_relay_info(&reg, mail_store, id, mail_id);
                    if let Some(federation) = &options.federation
                        && let Some(receipt) = receipt
                    {
                        federation.relay_receipt_if_remote(&receipt).await;
                    }
                    outgoing
                }
                ClientMessage::OtpMailDeliveredAck { mail_id } => {
                    mail::on_mail_delivered_ack(&reg, mail_store, id, mail_id)
                }
                ClientMessage::JoinChannel { .. } => {
                    unreachable!("handled above, before this match, and always `continue`s")
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
    // Federation-wide uniqueness, checked before writing anything locally:
    // a nickname already owned by a peer (or in conflict) is refused the
    // same way an already-taken local nickname is, naming which server
    // owns it so the client knows where to register instead.
    if let Some(federation) = &options.federation {
        federation
            .directory
            .lock()
            .await
            .is_registrable_here(nickname, &federation.self_id)?;
    }
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
    // Recorded and gossiped only once the account is actually going to
    // stick (past the email-delivery rollback above). Removed later -
    // an exhausted activation code (`handle_connection`'s
    // `TooManyWrongCodesAccountRemoved` arm) or a superadmin's
    // `/remove-account` (`AdminRemoveAccount`) - is gossiped too, via
    // `federation_announce_nickname_removed`, so a removed nickname does
    // not stay permanently blocked federation-wide.
    if let Some(federation) = &options.federation {
        let _ = federation
            .directory
            .lock()
            .await
            .record_local_nickname(nickname.to_string(), &federation.self_id);
        federation::broadcast(
            federation,
            federation::proto::FederationMessage::NicknameRegistered {
                nickname: nickname.to_string(),
                owner: federation.self_id.clone(),
            },
            federation::event::NICKS_GOSSIP,
        )
        .await;
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

pub(crate) async fn dispatch(senders: &Senders, outgoing: Vec<Outgoing>) {
    let map = senders.lock().await;
    for o in outgoing {
        if let Some(tx) = map.get(&o.to) {
            let _ = tx.send(o.message);
        }
    }
}
