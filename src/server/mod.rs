//! The server: purely a medium of connection setup, never of content. It
//! authenticates clients, tracks channel membership/presence, relays
//! `pq_hybrid` key-rotation notices, and relays the candidate exchange
//! that lets two clients punch a direct UDP link to each other
//! (`crate::client::p2p`) - but every actual message, voice stream, and file
//! transfer travels over that direct link, never through here. See
//! `docs/PROTOCOL.md`'s "Direct peer-to-peer transport" section.
//!
//! `Registry` holds the pure membership/routing logic and is unit tested
//! directly, with no sockets involved. `serve`/`run` wire that logic to
//! real TCP connections (optionally under TLS, `ssl`), plus a stateless
//! UDP rendezvous socket (`udp_rendezvous_loop`) that helps a client learn
//! its own public address for hole punching - the one place this module
//! touches UDP at all, and it never sees anything from the punched links
//! themselves.
//!
//! Who may log in is the `users_registry`'s business (accounts on disk,
//! each with a nickname and a password); `activation` is the small web
//! endpoint that turns an emailed code into an activated account.

pub mod activation;
pub mod mail;
pub mod ssl;
pub mod users_registry;

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncRead;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::TlsAcceptor;

use crate::crypto;
use crate::p2p_proto::RendezvousMessage;
use crate::proto::{
    self, ChannelInfo, ChannelJoinRejection, ChannelKind, ClientMessage, KeyMode, ServerMessage,
    UserId, UserInfo,
};
use crate::validation;
use users_registry::{AuthCheck, SmtpConfig, UsersRegistry};

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
    /// `server_activation_url`, for the link in the activation email.
    pub activation_url: Option<String>,
    /// The OTP mail store's directory (`mail::default_mail_dir` in
    /// production; a scratch dir in tests).
    pub mail_dir: PathBuf,
    /// §4.1's liveness timeout - `proto::HEARTBEAT_TIMEOUT` in
    /// production, milliseconds in the tests that prove it fires.
    pub heartbeat_timeout: Duration,
    /// `server_ssl=on`: every accepted socket is TLS-wrapped with this
    /// before the protocol starts.
    pub tls: Option<TlsAcceptor>,
}

impl ServerOptions {
    /// Production defaults around `users`: no registration, the real mail
    /// directory, the real heartbeat timeout, no TLS.
    pub fn new(users: UsersRegistry) -> Self {
        Self {
            users,
            allow_registration: false,
            smtp: None,
            activation_url: None,
            mail_dir: mail::default_mail_dir(),
            heartbeat_timeout: proto::HEARTBEAT_TIMEOUT,
            tls: None,
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

    pub fn with_registration(mut self, smtp: Option<SmtpConfig>, url: Option<String>) -> Self {
        self.allow_registration = true;
        self.smtp = smtp;
        self.activation_url = url;
        self
    }
}

/// One outbound message produced by a `Registry` mutation, to be delivered
/// to a specific connected client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub to: UserId,
    pub message: ServerMessage,
}

struct ClientRecord {
    name: String,
    public_key_der: Vec<u8>,
    key_mode: KeyMode,
}

struct ChannelRecord {
    kind: ChannelKind,
    members: BTreeSet<UserId>,
    /// Set only for a private channel created with a non-empty password;
    /// `None` for a public channel (a password sent alongside
    /// `ChannelKind::Public` is silently ignored) or a private one created
    /// without one. Fixed at creation like `kind` - there is no message to
    /// change a channel's password afterward.
    password: Option<String>,
}

/// Brute-force tracking for one (source IP, channel name) pair's wrong
/// private-channel-password attempts (US-025).
struct PasswordAttemptRecord {
    /// Consecutive wrong attempts since the last reset (a successful join
    /// to this channel from this IP, or this record not existing yet).
    wrong_attempts: u32,
    /// Set once `wrong_attempts` exceeds `CHANNEL_MAX_PASSWORD_ATTEMPTS`;
    /// checked via `.elapsed() < CHANNEL_PASSWORD_BAN_DURATION`, mirroring
    /// `crate::client::p2p`'s `Instant`/`Duration` cooldown style (its
    /// `FAILURE_COOLDOWN` pattern) - the first use of that style
    /// server-side.
    banned_at: Option<Instant>,
}

/// More than this many wrong-password attempts against one (source IP,
/// channel name) pair trips `CHANNEL_PASSWORD_BAN_DURATION`.
/// The one channel `Registry::new()` always seeds and `remove_member` never
/// deletes, even when empty - every other channel (public or private) is
/// unregistered the instant its last member leaves.
pub const DEFAULT_CHANNEL_NAME: &str = "the-hall";

pub const CHANNEL_MAX_PASSWORD_ATTEMPTS: u32 = 7;
/// How long a brute-force ban (`CHANNEL_MAX_PASSWORD_ATTEMPTS`) lasts.
pub const CHANNEL_PASSWORD_BAN_DURATION: Duration = Duration::from_secs(2 * 60 * 60);

/// Pure connection/channel bookkeeping, with no I/O of its own. Every
/// mutation returns the list of messages that need to go out as a result,
/// leaving delivery to the async layer.
pub struct Registry {
    clients: HashMap<UserId, ClientRecord>,
    channels: HashMap<String, ChannelRecord>,
    next_id: u64,
    /// Brute-force protection for private-channel passwords (US-025):
    /// keyed by (source IP, channel name) rather than `UserId`, because a
    /// `UserId` is never reused (TB-020) - a reconnect always gets a fresh
    /// one, so a per-`UserId` ban would be trivially bypassed by
    /// reconnecting. In-memory only; lost on server restart.
    channel_password_attempts: HashMap<(IpAddr, String), PasswordAttemptRecord>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// Starts with one default public channel so a freshly started server
    /// always has something for the first-connected client to auto-join.
    pub fn new() -> Self {
        let mut channels = HashMap::new();
        channels.insert(
            DEFAULT_CHANNEL_NAME.to_string(),
            ChannelRecord {
                kind: ChannelKind::Public,
                members: BTreeSet::new(),
                password: None,
            },
        );
        Self {
            clients: HashMap::new(),
            channels,
            next_id: 1,
            channel_password_attempts: HashMap::new(),
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
    pub fn channel_list(&self) -> Vec<ChannelInfo> {
        let mut v: Vec<ChannelInfo> = self
            .channels
            .iter()
            .filter(|(_, rec)| rec.kind == ChannelKind::Public)
            .map(|(name, rec)| ChannelInfo {
                name: name.clone(),
                kind: rec.kind,
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Joins `id` to `name`, creating the channel (as `kind`) if needed;
    /// idempotent for a channel you're already in. On success returns the
    /// membership snapshot for the joiner, `UserJoined` for every existing
    /// member, and a `Joined` confirmation. `name` is validated
    /// server-side regardless of the client's UI - the server never trusts
    /// the client. `password` sets a new private channel's password or is
    /// compared (constant-time) against the existing one (§6.5);
    /// `source_ip` scopes the brute-force ban (§6.6) - either way replies
    /// go to `id` only, never leaking password state to anyone else.
    pub fn join_channel(
        &mut self,
        id: UserId,
        name: &str,
        kind: ChannelKind,
        password: Option<&str>,
        source_ip: IpAddr,
    ) -> Result<Vec<Outgoing>, String> {
        let user = self
            .user_info(id)
            .ok_or_else(|| "unknown user".to_string())?;

        if !validation::channel_name_is_valid(name) {
            return Err(format!(
                "channel name must be 1-{} characters of letters, digits, and '-'",
                validation::CHANNEL_NAME_MAX_LEN
            ));
        }
        if !self.channels.contains_key(name)
            && let Some(pw) = password
            && !validation::channel_password_is_valid(pw)
        {
            return Err(format!(
                "channel password must be at most {} characters of letters, digits, and the allowed symbols",
                validation::CHANNEL_PASSWORD_MAX_LEN
            ));
        }

        let existed_before = self.channels.contains_key(name);

        let (existing_members, channel_kind, channel_password, already_member) = {
            let rec = self
                .channels
                .entry(name.to_string())
                .or_insert_with(|| ChannelRecord {
                    kind,
                    members: BTreeSet::new(),
                    password: match kind {
                        ChannelKind::Private => {
                            password.filter(|p| !p.is_empty()).map(str::to_owned)
                        }
                        ChannelKind::Public => None,
                    },
                });
            let existing: Vec<UserId> = rec.members.iter().copied().collect();
            let already = rec.members.contains(&id);
            (existing, rec.kind, rec.password.clone(), already)
        };

        if !already_member && let Some(expected) = &channel_password {
            let attempt_key = (source_ip, name.to_string());
            let banned = self
                .channel_password_attempts
                .get(&attempt_key)
                .and_then(|rec| rec.banned_at)
                .is_some_and(|t| t.elapsed() < CHANNEL_PASSWORD_BAN_DURATION);
            if banned {
                return Ok(vec![Outgoing {
                    to: id,
                    message: ServerMessage::ChannelJoinRejected {
                        name: name.to_string(),
                        kind: ChannelJoinRejection::Banned,
                    },
                }]);
            }
            match password {
                None => {
                    return Ok(vec![Outgoing {
                        to: id,
                        message: ServerMessage::ChannelJoinRejected {
                            name: name.to_string(),
                            kind: ChannelJoinRejection::PasswordRequired,
                        },
                    }]);
                }
                Some(given) if !crypto::constant_time_eq(expected.as_bytes(), given.as_bytes()) => {
                    let rec = self
                        .channel_password_attempts
                        .entry(attempt_key)
                        .or_insert_with(|| PasswordAttemptRecord {
                            wrong_attempts: 0,
                            banned_at: None,
                        });
                    rec.wrong_attempts += 1;
                    let rejection = if rec.wrong_attempts > CHANNEL_MAX_PASSWORD_ATTEMPTS {
                        rec.banned_at = Some(Instant::now());
                        ChannelJoinRejection::Banned
                    } else {
                        ChannelJoinRejection::WrongPassword
                    };
                    return Ok(vec![Outgoing {
                        to: id,
                        message: ServerMessage::ChannelJoinRejected {
                            name: name.to_string(),
                            kind: rejection,
                        },
                    }]);
                }
                Some(_) => {
                    self.channel_password_attempts.remove(&attempt_key);
                }
            }
        }

        if already_member {
            return Ok(Vec::new());
        }
        self.channels
            .get_mut(name)
            .expect("just looked up above")
            .members
            .insert(id);

        let mut outgoing = Vec::new();
        for member_id in existing_members {
            if let Some(info) = self.user_info(member_id) {
                outgoing.push(Outgoing {
                    to: id,
                    message: ServerMessage::UserJoined {
                        channel: name.to_string(),
                        user: info,
                    },
                });
            }
            outgoing.push(Outgoing {
                to: member_id,
                message: ServerMessage::UserJoined {
                    channel: name.to_string(),
                    user: user.clone(),
                },
            });
        }
        outgoing.push(Outgoing {
            to: id,
            message: ServerMessage::Joined {
                channel: ChannelInfo {
                    name: name.to_string(),
                    kind: channel_kind,
                },
            },
        });

        // A brand-new *public* channel is announced to every other client -
        // the one-time ChannelList snapshot at connect otherwise never
        // updates, so this is the only way anyone learns it exists
        // (§6.1/§6.3). A private channel stays unadvertised; the joiner
        // already has `Joined` above.
        if !existed_before && channel_kind == ChannelKind::Public {
            for &other_id in self.clients.keys() {
                if other_id != id {
                    outgoing.push(Outgoing {
                        to: other_id,
                        message: ServerMessage::ChannelCreated {
                            channel: ChannelInfo {
                                name: name.to_string(),
                                kind: channel_kind,
                            },
                        },
                    });
                }
            }
        }

        Ok(outgoing)
    }

    /// Removes `id` from `name`'s membership, deleting the channel if that
    /// empties it - unless `name` is `DEFAULT_CHANNEL_NAME`, which
    /// survives emptying. Returns the remaining members (who should be
    /// notified); empty if `name` doesn't exist or `id` wasn't a member.
    /// Shared by `leave_channel` (`UserLeft`) and `unregister`
    /// (`UserOffline`), which differ only in the wrapping message.
    fn remove_member(&mut self, id: UserId, name: &str) -> Vec<UserId> {
        let (remaining, should_delete) = {
            let Some(rec) = self.channels.get_mut(name) else {
                return Vec::new();
            };
            if !rec.members.remove(&id) {
                return Vec::new();
            }
            let remaining: Vec<UserId> = rec.members.iter().copied().collect();
            let should_delete = rec.members.is_empty() && name != DEFAULT_CHANNEL_NAME;
            (remaining, should_delete)
        };
        if should_delete {
            self.channels.remove(name);
        }
        remaining
    }

    /// Removes `id` from `name`, notifying remaining members. Empty
    /// private channels are dropped entirely; empty public channels stay
    /// listed.
    pub fn leave_channel(&mut self, id: UserId, name: &str) -> Vec<Outgoing> {
        self.remove_member(id, name)
            .into_iter()
            .map(|member_id| Outgoing {
                to: member_id,
                message: ServerMessage::UserLeft {
                    channel: name.to_string(),
                    user_id: id,
                },
            })
            .collect()
    }

    /// Removes `id` from every channel and forgets it entirely (on
    /// disconnect). Peers who shared *any* channel with `id` get exactly
    /// one `UserOffline` each (a full disconnect, not a one-channel
    /// `UserLeft` - see `ServerMessage::UserOffline`), no matter how many
    /// channels they shared.
    pub fn unregister(&mut self, id: UserId) -> Vec<Outgoing> {
        let channel_names: Vec<String> = self
            .channels
            .iter()
            .filter(|(_, rec)| rec.members.contains(&id))
            .map(|(name, _)| name.clone())
            .collect();
        let mut recipients: BTreeSet<UserId> = BTreeSet::new();
        for name in &channel_names {
            recipients.extend(self.remove_member(id, name));
        }
        self.clients.remove(&id);
        recipients
            .into_iter()
            .map(|to| Outgoing {
                to,
                message: ServerMessage::UserOffline { user_id: id },
            })
            .collect()
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
            return Err("unknown sender".to_string());
        }
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing {
            to,
            message: ServerMessage::KeyRotated {
                from,
                new_public_key_der,
                signature,
            },
        })
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
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing {
            to,
            message: ServerMessage::PeerCandidates {
                from,
                candidates,
                link_nonce,
            },
        })
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

async fn serve_tcp(listener: TcpListener, options: ServerOptions) -> std::io::Result<()> {
    let registry = Arc::new(Mutex::new(Registry::new()));
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
            let (ok, reason) = match register_account(&options, &nickname, &password, &email).await
            {
                Ok(()) => (true, None),
                Err(reason) => (false, Some(reason)),
            };
            let _ = wr.send(&ServerMessage::RegisterResult { ok, reason }).await;
            return Ok(());
        }
        _ => {
            let _ = wr
                .send(&ServerMessage::AuthResult {
                    ok: false,
                    activation_pending: false,
                    reason: Some("expected auth message".into()),
                })
                .await;
            return Ok(());
        }
    };
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
            let _ = wr
                .send(&ServerMessage::AuthResult {
                    ok: false,
                    activation_pending: false,
                    reason: Some("authentication failed".into()),
                })
                .await;
            return Ok(());
        }
        AuthCheck::ActivationPending { expired: true } => {
            let _ = wr
                .send(&ServerMessage::AuthResult {
                    ok: false,
                    activation_pending: false,
                    reason: Some(
                        "this account's activation code has expired - register again".into(),
                    ),
                })
                .await;
            return Ok(());
        }
        AuthCheck::ActivationPending { expired: false } => {
            wr.send(&ServerMessage::AuthResult {
                ok: false,
                activation_pending: true,
                reason: None,
            })
            .await?;
            let Some(ClientMessage::Activate { code }) = rd.recv().await? else {
                let _ = wr
                    .send(&ServerMessage::AuthResult {
                        ok: false,
                        activation_pending: false,
                        reason: Some("expected activation code".into()),
                    })
                    .await;
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
            };
            if let Some(reason) = reason {
                let _ = wr
                    .send(&ServerMessage::AuthResult {
                        ok: false,
                        activation_pending: false,
                        reason: Some(reason),
                    })
                    .await;
                return Ok(());
            }
        }
    }
    wr.send(&ServerMessage::AuthResult {
        ok: true,
        activation_pending: false,
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
    let channel_list = registry.lock().await.channel_list();
    let _ = tx.send(ServerMessage::ChannelList(channel_list));

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if wr.send(&msg).await.is_err() {
                break;
            }
        }
    });

    let result = client_loop(
        id,
        &mut rd,
        &registry,
        &senders,
        peer_ip,
        options.heartbeat_timeout,
        &mail_store,
    )
    .await;

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

#[allow(clippy::too_many_arguments)]
async fn client_loop<R: AsyncRead + Unpin>(
    id: UserId,
    rd: &mut crate::control::ControlReader<R>,
    registry: &Arc<Mutex<Registry>>,
    senders: &Senders,
    source_ip: IpAddr,
    heartbeat_timeout: Duration,
    mail_store: &mail::MailStore,
) -> proto::Result<()> {
    loop {
        // Any message at all - `Heartbeat` or otherwise - proves the
        // connection is alive and resets this. Nothing arriving within
        // `heartbeat_timeout` (docs/PROTOCOL.md §4.1) is treated exactly
        // like the client closing the connection: this simply returns,
        // and the same unregister/cleanup path in `handle_connection` runs
        // either way.
        let Ok(recv) = tokio::time::timeout(heartbeat_timeout, rd.recv::<ClientMessage>()).await
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
                    reg.join_channel(id, &name, kind, password.as_deref(), source_ip)
                        .unwrap_or_else(|reason| {
                            vec![Outgoing {
                                to: id,
                                message: ServerMessage::ChannelJoinFailed {
                                    name: name_for_err,
                                    reason,
                                },
                            }]
                        })
                }
                ClientMessage::LeaveChannel { name } => reg.leave_channel(id, &name),
                ClientMessage::RotateKey {
                    to,
                    new_public_key_der,
                    signature,
                } => match reg.route_key_rotation(id, to, new_public_key_der, signature) {
                    Ok(o) => vec![o],
                    Err(reason) => {
                        vec![Outgoing {
                            to: id,
                            message: ServerMessage::Error { message: reason },
                        }]
                    }
                },
                ClientMessage::RequestPeerLink {
                    peer,
                    candidates,
                    link_nonce,
                } => match reg.route_peer_link_request(id, peer, candidates, link_nonce) {
                    Ok(o) => vec![o],
                    Err(reason) => {
                        vec![Outgoing {
                            to: id,
                            message: ServerMessage::Error { message: reason },
                        }]
                    }
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
                | ClientMessage::Identify { .. } => vec![Outgoing {
                    to: id,
                    message: ServerMessage::Error {
                        message: "unexpected message after handshake".into(),
                    },
                }],
            }
        };
        dispatch(senders, outgoing).await;
    }
}

/// `Register` (§5.3) end to end: the policy checks, the registry write,
/// and the activation email - with the registration rolled back if the
/// email cannot be handed to the relay, so a name is never left taken by
/// an account whose code nobody received. `Err` carries the reason the
/// client is shown.
async fn register_account(
    options: &ServerOptions,
    nickname: &str,
    password: &str,
    email: &str,
) -> Result<(), String> {
    if !options.allow_registration {
        return Err("this server does not take registrations".into());
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
    if let Err(e) = users_registry::send_activation_email(
        smtp,
        email,
        nickname,
        &registration.code,
        options.activation_url.as_deref(),
    )
    .await
    {
        crate::log_warn!("activation email for {nickname} could not be sent: {e}");
        let _ = options.users.remove(nickname);
        return Err("the activation email could not be sent - try again later".into());
    }
    Ok(())
}

async fn dispatch(senders: &Senders, outgoing: Vec<Outgoing>) {
    let map = senders.lock().await;
    for o in outgoing {
        if let Some(tx) = map.get(&o.to) {
            let _ = tx.send(o.message);
        }
    }
}
