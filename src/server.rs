//! The server: purely a medium of connections. It relays already-encrypted
//! envelopes between clients and tracks channel membership; it never sees
//! plaintext and never persists anything past the current process's memory.
//!
//! `Registry` holds the pure membership/routing logic and is unit tested
//! directly, with no sockets involved. `serve`/`run` wire that logic to
//! real TCP connections.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use rsa::RsaPrivateKey;
use tokio::io::AsyncRead;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::crypto;
use crate::proto::{
    self, AuthKind, AuthResponse, ChannelInfo, ChannelKind, ClientMessage, Envelope, KeyMode,
    ServerMessage, UserId, UserInfo,
};

/// How the server was started: `--enc rsa <keyfile>`, `--password <pass>`,
/// or neither (open access).
pub enum AuthConfig {
    None,
    Password(String),
    Rsa(Box<RsaPrivateKey>),
}

impl AuthConfig {
    pub fn kind(&self) -> AuthKind {
        match self {
            AuthConfig::None => AuthKind::None,
            AuthConfig::Password(_) => AuthKind::Password,
            AuthConfig::Rsa(_) => AuthKind::Rsa,
        }
    }

    /// A fresh nonce to send as part of `ServerMessage::Hello` when this
    /// config requires RSA auth; `None` otherwise.
    pub fn make_challenge(&self) -> Option<Vec<u8>> {
        match self {
            AuthConfig::Rsa(_) => Some(crypto::random_bytes(32)),
            _ => None,
        }
    }

    /// Checks a client's `AuthResponse` against this config. For RSA, the
    /// client is expected to have encrypted `challenge` with the server's
    /// public key (which it holds as its `server_key` file); decrypting it
    /// back to the original nonce proves that.
    pub fn verify(&self, challenge: Option<&[u8]>, response: &AuthResponse) -> bool {
        match (self, response) {
            (AuthConfig::None, AuthResponse::None) => true,
            (AuthConfig::Password(expected), AuthResponse::Password(given)) => {
                crypto::constant_time_eq(expected.as_bytes(), given.as_bytes())
            }
            (AuthConfig::Rsa(key), AuthResponse::Rsa { blocks }) => {
                match (challenge, crypto::decrypt_chunked(key, blocks)) {
                    (Some(nonce), Ok(plain)) => crypto::constant_time_eq(nonce, &plain),
                    _ => false,
                }
            }
            _ => false,
        }
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
}

/// Pure connection/channel bookkeeping, with no I/O of its own. Every
/// mutation returns the list of messages that need to go out as a result,
/// leaving delivery to the async layer.
pub struct Registry {
    clients: HashMap<UserId, ClientRecord>,
    channels: HashMap<String, ChannelRecord>,
    next_id: u64,
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
            "general".to_string(),
            ChannelRecord { kind: ChannelKind::Public, members: BTreeSet::new() },
        );
        Self { clients: HashMap::new(), channels, next_id: 1 }
    }

    pub fn register(&mut self, name: String, public_key_der: Vec<u8>, key_mode: KeyMode) -> UserId {
        let id = UserId(self.next_id);
        self.next_id += 1;
        self.clients.insert(id, ClientRecord { name, public_key_der, key_mode });
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

    /// Public channels only: private channels are only reachable by
    /// knowing their name (Ctrl+J), never advertised in the tab list.
    pub fn channel_list(&self) -> Vec<ChannelInfo> {
        let mut v: Vec<ChannelInfo> = self
            .channels
            .iter()
            .filter(|(_, rec)| rec.kind == ChannelKind::Public)
            .map(|(name, rec)| ChannelInfo { name: name.clone(), kind: rec.kind })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Joins `id` to `name`, creating the channel (as `kind`) if it doesn't
    /// exist yet. Idempotent: re-joining a channel you're already in is a
    /// no-op. On success, returns `UserJoined` for every existing member
    /// sent to the joiner, `UserJoined` for the joiner sent to every
    /// existing member, and a `Joined` confirmation sent to the joiner.
    pub fn join_channel(
        &mut self,
        id: UserId,
        name: &str,
        kind: ChannelKind,
    ) -> Result<Vec<Outgoing>, String> {
        let user = self.user_info(id).ok_or_else(|| "unknown user".to_string())?;

        let (existing_members, channel_kind, already_member) = {
            let rec = self
                .channels
                .entry(name.to_string())
                .or_insert_with(|| ChannelRecord { kind, members: BTreeSet::new() });
            let existing: Vec<UserId> = rec.members.iter().copied().collect();
            let already = rec.members.contains(&id);
            if !already {
                rec.members.insert(id);
            }
            (existing, rec.kind, already)
        };

        if already_member {
            return Ok(Vec::new());
        }

        let mut outgoing = Vec::new();
        for member_id in existing_members {
            if let Some(info) = self.user_info(member_id) {
                outgoing.push(Outgoing {
                    to: id,
                    message: ServerMessage::UserJoined { channel: name.to_string(), user: info },
                });
            }
            outgoing.push(Outgoing {
                to: member_id,
                message: ServerMessage::UserJoined { channel: name.to_string(), user: user.clone() },
            });
        }
        outgoing.push(Outgoing {
            to: id,
            message: ServerMessage::Joined {
                channel: ChannelInfo { name: name.to_string(), kind: channel_kind },
            },
        });
        Ok(outgoing)
    }

    /// Removes `id` from `name`'s membership set, if present, deleting the
    /// channel outright if that empties a **private** one. Returns the
    /// members who remained (i.e. who should be notified), or an empty
    /// `Vec` if `name` doesn't exist or `id` wasn't a member. Shared by
    /// `leave_channel` (`UserLeft`) and `unregister` (`UserOffline`), which
    /// differ only in which message they wrap this in.
    fn remove_member(&mut self, id: UserId, name: &str) -> Vec<UserId> {
        let (remaining, should_delete) = {
            let Some(rec) = self.channels.get_mut(name) else {
                return Vec::new();
            };
            if !rec.members.remove(&id) {
                return Vec::new();
            }
            let remaining: Vec<UserId> = rec.members.iter().copied().collect();
            let should_delete = rec.members.is_empty() && rec.kind == ChannelKind::Private;
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
                message: ServerMessage::UserLeft { channel: name.to_string(), user_id: id },
            })
            .collect()
    }

    /// Removes `id` from every channel it was in and forgets it entirely
    /// (on disconnect). Notifies every peer who shared *any* of those
    /// channels with `id` via `UserOffline` rather than `UserLeft` - a
    /// full disconnect, not a one-channel departure (SPEC.md's "offline"
    /// behavior; see `ServerMessage::UserOffline`). Each affected peer
    /// gets exactly one `UserOffline`, no matter how many channels it
    /// shared with `id`.
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
            .map(|to| Outgoing { to, message: ServerMessage::UserOffline { user_id: id } })
            .collect()
    }

    /// Relays each recipient's own pre-encrypted envelope to them.
    /// Envelopes addressed to a `UserId` that isn't (or is no longer) a
    /// member of the channel are silently dropped.
    pub fn route_channel_message(
        &self,
        from: UserId,
        channel: &str,
        per_recipient: Vec<(UserId, Envelope)>,
    ) -> Result<Vec<Outgoing>, String> {
        let rec = self.channels.get(channel).ok_or_else(|| format!("no such channel: {channel}"))?;
        if !rec.members.contains(&from) {
            return Err("sender is not a member of this channel".to_string());
        }
        let from_name = self
            .clients
            .get(&from)
            .map(|c| c.name.clone())
            .ok_or_else(|| "unknown sender".to_string())?;

        let mut outgoing = Vec::new();
        for (to, envelope) in per_recipient {
            if !rec.members.contains(&to) {
                continue;
            }
            outgoing.push(Outgoing {
                to,
                message: ServerMessage::ChannelMessage {
                    channel: channel.to_string(),
                    from,
                    from_name: from_name.clone(),
                    envelope,
                },
            });
        }
        Ok(outgoing)
    }

    pub fn route_direct_message(
        &self,
        from: UserId,
        to: UserId,
        envelope: Envelope,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        let from_name = self
            .clients
            .get(&from)
            .map(|c| c.name.clone())
            .ok_or_else(|| "unknown sender".to_string())?;
        Ok(Outgoing { to, message: ServerMessage::DirectMessage { from, from_name, envelope } })
    }

    /// Relays a `rsa_per_msg` key rotation (PROTOCOL.md §7.5/§11) point to
    /// point, exactly like `route_direct_message`. The server never
    /// inspects `signature` - that's the receiving client's job (§11.4) -
    /// and never updates its own stored `public_key_der` for `from`, which
    /// stays as whatever `Identify` sent for the life of the connection
    /// (it only ever serves as the *bootstrap* key for peers who haven't
    /// exchanged a message with `from` yet).
    pub fn route_key_rotation(
        &self,
        from: UserId,
        to: UserId,
        new_public_key_der: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Outgoing, String> {
        let sender = self.clients.get(&from).ok_or_else(|| "unknown sender".to_string())?;
        if sender.key_mode != KeyMode::PerMessage {
            return Err("sender is not in rsa_per_msg mode".to_string());
        }
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::KeyRotated { from, new_public_key_der, signature } })
    }

    // -------------------------------------------------------------
    // Live-streamed voice: Start/End have no per-recipient payload, so
    // (unlike Chunk) they're broadcast the same way `join_channel`
    // broadcasts `UserJoined` - derived from current membership, not a
    // client-supplied list - excluding the sender, who doesn't need their
    // own notice.
    // -------------------------------------------------------------

    pub fn route_channel_stream_start(
        &self,
        from: UserId,
        channel: &str,
        stream_id: u64,
    ) -> Result<Vec<Outgoing>, String> {
        let rec = self.channels.get(channel).ok_or_else(|| format!("no such channel: {channel}"))?;
        if !rec.members.contains(&from) {
            return Err("sender is not a member of this channel".to_string());
        }
        let from_name =
            self.clients.get(&from).map(|c| c.name.clone()).ok_or_else(|| "unknown sender".to_string())?;
        Ok(rec
            .members
            .iter()
            .filter(|&&m| m != from)
            .map(|&to| Outgoing {
                to,
                message: ServerMessage::ChannelStreamStart {
                    channel: channel.to_string(),
                    from,
                    from_name: from_name.clone(),
                    stream_id,
                },
            })
            .collect())
    }

    pub fn route_channel_stream_chunk(
        &self,
        from: UserId,
        channel: &str,
        stream_id: u64,
        seq: u32,
        per_recipient: Vec<(UserId, Vec<Vec<u8>>)>,
    ) -> Result<Vec<Outgoing>, String> {
        let rec = self.channels.get(channel).ok_or_else(|| format!("no such channel: {channel}"))?;
        if !rec.members.contains(&from) {
            return Err("sender is not a member of this channel".to_string());
        }
        let mut outgoing = Vec::new();
        for (to, blocks) in per_recipient {
            if !rec.members.contains(&to) {
                continue;
            }
            outgoing.push(Outgoing {
                to,
                message: ServerMessage::ChannelStreamChunk {
                    channel: channel.to_string(),
                    from,
                    stream_id,
                    seq,
                    blocks,
                },
            });
        }
        Ok(outgoing)
    }

    pub fn route_channel_stream_end(
        &self,
        from: UserId,
        channel: &str,
        stream_id: u64,
        duration_ms: u32,
    ) -> Result<Vec<Outgoing>, String> {
        let rec = self.channels.get(channel).ok_or_else(|| format!("no such channel: {channel}"))?;
        if !rec.members.contains(&from) {
            return Err("sender is not a member of this channel".to_string());
        }
        Ok(rec
            .members
            .iter()
            .filter(|&&m| m != from)
            .map(|&to| Outgoing {
                to,
                message: ServerMessage::ChannelStreamEnd {
                    channel: channel.to_string(),
                    from,
                    stream_id,
                    duration_ms,
                },
            })
            .collect())
    }

    pub fn route_direct_stream_start(
        &self,
        from: UserId,
        to: UserId,
        stream_id: u64,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        let from_name =
            self.clients.get(&from).map(|c| c.name.clone()).ok_or_else(|| "unknown sender".to_string())?;
        Ok(Outgoing { to, message: ServerMessage::DirectStreamStart { from, from_name, stream_id } })
    }

    pub fn route_direct_stream_chunk(
        &self,
        from: UserId,
        to: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::DirectStreamChunk { from, stream_id, seq, blocks } })
    }

    pub fn route_direct_stream_end(
        &self,
        from: UserId,
        to: UserId,
        stream_id: u64,
        duration_ms: u32,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::DirectStreamEnd { from, stream_id, duration_ms } })
    }

    // -------------------------------------------------------------
    // File transfer: always point-to-point (`docs/PROTOCOL.md`'s file
    // transfer section) - a channel send is just N independent offers, one
    // per recipient, so every one of these is an existence-check-only relay
    // exactly like `route_direct_message`/`route_direct_stream_*` above, no
    // channel-membership validation involved.
    // -------------------------------------------------------------

    pub fn route_file_offer(
        &self,
        from: UserId,
        to: UserId,
        stream_id: u64,
        channel: Option<String>,
        envelope: Envelope,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        let from_name = self.clients.get(&from).map(|c| c.name.clone()).ok_or_else(|| "unknown sender".to_string())?;
        Ok(Outgoing { to, message: ServerMessage::FileOffer { from, from_name, stream_id, channel, envelope } })
    }

    pub fn route_file_accept(&self, from: UserId, to: UserId, stream_id: u64) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::FileAccepted { from, stream_id } })
    }

    pub fn route_file_reject(&self, from: UserId, to: UserId, stream_id: u64) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::FileRejected { from, stream_id } })
    }

    pub fn route_file_chunk(
        &self,
        from: UserId,
        to: UserId,
        stream_id: u64,
        seq: u32,
        blocks: Vec<Vec<u8>>,
    ) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::FileChunk { from, stream_id, seq, blocks } })
    }

    pub fn route_file_end(&self, from: UserId, to: UserId, stream_id: u64) -> Result<Outgoing, String> {
        if !self.clients.contains_key(&to) {
            return Err("unknown recipient".to_string());
        }
        Ok(Outgoing { to, message: ServerMessage::FileEnd { from, stream_id } })
    }
}

// ---------------------------------------------------------------------
// Async wiring
// ---------------------------------------------------------------------

type Senders = Arc<Mutex<HashMap<UserId, mpsc::UnboundedSender<ServerMessage>>>>;

/// Binds `addr` and serves forever.
pub async fn run(addr: SocketAddr, auth: AuthConfig) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve(listener, auth).await
}

/// Accepts connections on an already-bound listener and serves forever.
/// Split out from `run` so tests can bind to an ephemeral port (`:0`) and
/// discover the real address via `TcpListener::local_addr`.
pub async fn serve(listener: TcpListener, auth: AuthConfig) -> std::io::Result<()> {
    let registry = Arc::new(Mutex::new(Registry::new()));
    let senders: Senders = Arc::new(Mutex::new(HashMap::new()));
    let auth = Arc::new(auth);

    loop {
        let (socket, peer) = listener.accept().await?;
        let registry = registry.clone();
        let senders = senders.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, registry, senders, auth).await {
                eprintln!("aloo: connection {peer} ended: {e}");
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    registry: Arc<Mutex<Registry>>,
    senders: Senders,
    auth: Arc<AuthConfig>,
) -> proto::Result<()> {
    let (mut rd, mut wr) = tokio::io::split(socket);

    let challenge = auth.make_challenge();
    proto::write_message(&mut wr, &ServerMessage::Hello { auth: auth.kind(), challenge: challenge.clone() })
        .await?;

    let Some(ClientMessage::Auth(response)) = proto::read_message(&mut rd).await? else {
        let _ = proto::write_message(
            &mut wr,
            &ServerMessage::AuthResult { ok: false, reason: Some("expected auth message".into()) },
        )
        .await;
        return Ok(());
    };
    if !auth.verify(challenge.as_deref(), &response) {
        let _ = proto::write_message(
            &mut wr,
            &ServerMessage::AuthResult { ok: false, reason: Some("authentication failed".into()) },
        )
        .await;
        return Ok(());
    }
    proto::write_message(&mut wr, &ServerMessage::AuthResult { ok: true, reason: None }).await?;

    let Some(ClientMessage::Identify { display_name, public_key_der, key_mode }) =
        proto::read_message(&mut rd).await?
    else {
        let _ = proto::write_message(
            &mut wr,
            &ServerMessage::Error { message: "expected identify message".into() },
        )
        .await;
        return Ok(());
    };

    let id = {
        let mut reg = registry.lock().await;
        match reg.try_register(display_name, public_key_der, key_mode) {
            Ok(id) => id,
            Err(reason) => {
                drop(reg);
                let _ = proto::write_message(
                    &mut wr,
                    &ServerMessage::IdentifyResult { ok: false, you: None, reason: Some(reason) },
                )
                .await;
                return Ok(());
            }
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMessage>();
    senders.lock().await.insert(id, tx.clone());

    let _ = tx.send(ServerMessage::IdentifyResult { ok: true, you: Some(id), reason: None });
    let channel_list = registry.lock().await.channel_list();
    let _ = tx.send(ServerMessage::ChannelList(channel_list));

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if proto::write_message(&mut wr, &msg).await.is_err() {
                break;
            }
        }
    });

    let result = client_loop(id, &mut rd, &registry, &senders).await;

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

async fn client_loop<R: AsyncRead + Unpin>(
    id: UserId,
    rd: &mut R,
    registry: &Arc<Mutex<Registry>>,
    senders: &Senders,
) -> proto::Result<()> {
    loop {
        let Some(msg) = proto::read_message::<_, ClientMessage>(rd).await? else {
            return Ok(());
        };
        let outgoing = {
            let mut reg = registry.lock().await;
            match msg {
                ClientMessage::JoinChannel { name, kind } => {
                    let name_for_err = name.clone();
                    reg.join_channel(id, &name, kind).unwrap_or_else(|reason| {
                        vec![Outgoing {
                            to: id,
                            message: ServerMessage::ChannelJoinFailed { name: name_for_err, reason },
                        }]
                    })
                }
                ClientMessage::LeaveChannel { name } => reg.leave_channel(id, &name),
                ClientMessage::SendChannel { channel, per_recipient } => {
                    reg.route_channel_message(id, &channel, per_recipient).unwrap_or_else(|reason| {
                        vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                    })
                }
                ClientMessage::SendDirect { to, envelope } => {
                    match reg.route_direct_message(id, to, envelope) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::StreamChannelStart { channel, stream_id } => {
                    reg.route_channel_stream_start(id, &channel, stream_id).unwrap_or_else(|reason| {
                        vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                    })
                }
                ClientMessage::StreamChannelChunk { channel, stream_id, seq, per_recipient } => reg
                    .route_channel_stream_chunk(id, &channel, stream_id, seq, per_recipient)
                    .unwrap_or_else(|reason| {
                        vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                    }),
                ClientMessage::StreamChannelEnd { channel, stream_id, duration_ms } => reg
                    .route_channel_stream_end(id, &channel, stream_id, duration_ms)
                    .unwrap_or_else(|reason| {
                        vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                    }),
                ClientMessage::StreamDirectStart { to, stream_id } => {
                    match reg.route_direct_stream_start(id, to, stream_id) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::StreamDirectChunk { to, stream_id, seq, blocks } => {
                    match reg.route_direct_stream_chunk(id, to, stream_id, seq, blocks) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::StreamDirectEnd { to, stream_id, duration_ms } => {
                    match reg.route_direct_stream_end(id, to, stream_id, duration_ms) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::RotateKey { to, new_public_key_der, signature } => {
                    match reg.route_key_rotation(id, to, new_public_key_der, signature) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::FileOffer { to, stream_id, channel, envelope } => {
                    match reg.route_file_offer(id, to, stream_id, channel, envelope) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::FileAccept { to, stream_id } => match reg.route_file_accept(id, to, stream_id) {
                    Ok(o) => vec![o],
                    Err(reason) => vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }],
                },
                ClientMessage::FileReject { to, stream_id } => match reg.route_file_reject(id, to, stream_id) {
                    Ok(o) => vec![o],
                    Err(reason) => vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }],
                },
                ClientMessage::FileChunk { to, stream_id, seq, blocks } => {
                    match reg.route_file_chunk(id, to, stream_id, seq, blocks) {
                        Ok(o) => vec![o],
                        Err(reason) => {
                            vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }]
                        }
                    }
                }
                ClientMessage::FileEnd { to, stream_id } => match reg.route_file_end(id, to, stream_id) {
                    Ok(o) => vec![o],
                    Err(reason) => vec![Outgoing { to: id, message: ServerMessage::Error { message: reason } }],
                },
                ClientMessage::Auth(_) | ClientMessage::Identify { .. } => vec![Outgoing {
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

async fn dispatch(senders: &Senders, outgoing: Vec<Outgoing>) {
    let map = senders.lock().await;
    for o in outgoing {
        if let Some(tx) = map.get(&o.to) {
            let _ = tx.send(o.message);
        }
    }
}

