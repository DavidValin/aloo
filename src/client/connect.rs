//! Client-side connection bootstrap: drives the connect popup, then the
//! auth + identify handshake, before handing off to `crate::client::session`'s
//! ongoing connected-session loop.

use std::fs;
use std::io;
use std::io::Stdout;
use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::net::TcpStream;

use crate::BoxError;
use crate::crypto;
use crate::client::idstore;
use crate::validation::is_storable;
use crate::proto::{self, AuthKind, AuthResponse, ClientMessage, KeyMode, ServerMessage};
use crate::client::session;
use crate::client::tui::ui_connect_popup::{self, ConnectPopupState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerKeySelection {
    None,
    Password(String),
    Rsa(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MyKeySelection {
    None,
    Password(String),
    /// `pq_hybrid` (`docs/PROTOCOL.md` §13): both files are keybundles
    /// produced by `aloo --keygen-pq-hybrid`, not PEM.
    PqHybrid {
        file_pub: PathBuf,
        file_priv: PathBuf,
    },
}

/// What the user asked to connect with, as collected by the connect popup
/// (`tui::ui_connect_popup`) and consumed by the handshake here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub nickname: String,
    pub server_key: ServerKeySelection,
    pub my_key: MyKeySelection,
    /// Where the local identity-pinning store lives (see
    /// `aloo::idstore`, `docs/PROTOCOL.md` §12) - the file that remembers
    /// each nickname's full public key from the last time it was seen (for
    /// `password`/`pq_hybrid`), so a reconnecting peer whose key suddenly
    /// changed can be flagged instead of silently trusted. Prefilled from
    /// `idstore::default_path` but freely editable.
    pub id_store_path: PathBuf,
}

/// This client's own resolved key material, whichever `my_key` type
/// produced it. Replaces a bare `RsaPrivateKey` return once `PqHybrid`
/// needed to carry a whole `crypto::pq::PqPrivateBundle` instead - every
/// other `my_key` type still resolves to a plain RSA keypair exactly as
/// before. `pub` so `resolve_my_keypair`'s return type is externally
/// nameable (see its own doc comment).
pub enum ResolvedIdentity {
    Rsa(crypto::KeyPair),
    Pq {
        private: crypto::pq::PqPrivateBundle,
        /// Bincode-encoded `crypto::pq::PqPublicBundle`, precomputed here
        /// (once, from `file_pub`) since `Identify`'s `public_key_der` needs
        /// it and `PqPrivateBundle` alone can't derive it back out.
        public_der: Vec<u8>,
    },
}

/// A distinct error type so `run_client_inner` can tell "the server
/// rejected this nickname" apart from other, fatal handshake failures via
/// `downcast_ref` and loop back to the popup instead of exiting.
#[derive(Debug)]
struct NicknameTakenError(String);

impl std::fmt::Display for NicknameTakenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for NicknameTakenError {}

pub async fn run_client_inner(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    port: u16,
    keyboard_release_reporting: bool,
    hotkey_rx: Option<tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>>,
) -> Result<(), BoxError> {
    let mut popup = ConnectPopupState::new();
    popup.port = port.to_string();
    popup.nickname = local_display_name();

    let mut cache = load_connect_cache();
    prefill_connect_defaults(&mut popup, &cache, &crate::platform::aloo_dir());

    loop {
        let Some(request) = ui_connect_popup::run(terminal, &mut popup)? else {
            return Ok(()); // user cancelled
        };

        // Remembered regardless of whether the connection attempt below
        // actually succeeds ("the last values used in the popup", not "the
        // last successful connection") - a wrong password or an
        // unreachable host doesn't mean the pq_hybrid identity chosen was
        // wrong.
        if let MyKeySelection::PqHybrid {
            file_pub,
            file_priv,
        } = &request.my_key
        {
            cache.record(
                &request.host,
                request.port,
                &file_pub.display().to_string(),
                &file_priv.display().to_string(),
            );
            if let Err(e) = cache.save() {
                eprintln!("aloo: failed to save connect cache: {e}");
            }
        }

        match connect_and_handshake(&request).await {
            Ok((rd, wr, you, identity, key_mode, server_addr)) => {
                let id_store = load_id_store(&request.id_store_path);
                return session::run_connected_session(
                    terminal,
                    rd,
                    wr,
                    request.nickname,
                    you,
                    identity,
                    key_mode,
                    keyboard_release_reporting,
                    id_store,
                    hotkey_rx,
                    server_addr,
                )
                .await;
            }
            Err(e) => {
                let Some(taken) = e.downcast_ref::<NicknameTakenError>() else {
                    return Err(e);
                };
                // Loop back to the popup instead of exiting: everything the
                // user already filled in (host, keys, ...) stays put, only
                // the nickname needs to change.
                popup.error = Some(taken.0.clone());
                popup.focus = ui_connect_popup::Field::Nickname;
            }
        }
    }
}

/// Connects, then runs the auth + identify handshake. On success returns
/// the split stream halves, the `UserId` the server assigned us, our
/// private key (needed to decrypt incoming messages), and the `KeyMode`
/// this session runs under. A taken nickname comes back as
/// `NicknameTakenError` so the caller can retry instead of treating it as
/// fatal.
async fn connect_and_handshake(
    request: &ConnectRequest,
) -> Result<
    (
        crate::control::ControlReader<tokio::io::ReadHalf<TcpStream>>,
        crate::control::ControlWriter<tokio::io::WriteHalf<TcpStream>>,
        proto::UserId,
        ResolvedIdentity,
        KeyMode,
        std::net::SocketAddr,
    ),
    BoxError,
> {
    let (identity, key_mode) = resolve_my_keypair(&request.my_key)?;

    // Prefer IPv4 when the hostname resolves to both families. Docker's IPv6
    // UDP port publishing often poisons STUN (observed address becomes
    // 172.17.0.1) while IPv4 returns the client's real public endpoint.
    let server_addr = resolve_server_prefer_ipv4(&request.host, request.port).await?;
    let stream = TcpStream::connect(server_addr).await?;
    // The server's UDP rendezvous socket binds the same numeric port on the
    // same address (`server::run`) - captured here, before the stream
    // splits, since `peer_addr` needs the whole `TcpStream` and this is the
    // resolved address (DNS already settled), not just whatever hostname
    // the user typed.
    let server_addr = stream.peer_addr()?;
    let (rd, wr) = tokio::io::split(stream);
    let mut rd = crate::control::ControlReader::new(rd);
    let mut wr = crate::control::ControlWriter::new(wr);

    let Some(ServerMessage::Hello {
        auth,
        challenge,
        control,
    }) = rd.recv().await?
    else {
        return Err("server closed the connection during handshake".into());
    };

    // A client that holds the server's public key requires the offer to be
    // signed by it. An unsigned or wrongly-signed offer from a server we
    // *can* authenticate is exactly what a man in the middle would send,
    // so it is refused rather than silently accepted unauthenticated.
    let server_public = match &request.server_key {
        ServerKeySelection::Rsa(path) => Some(crypto::load_public_key(path)?),
        _ => None,
    };
    if !crate::control::verify_offer(&control, server_public.as_ref()) {
        return Err("the server could not prove it is the one this key belongs to".into());
    }
    let (accept, keys) = crate::control::accept_offer(&control)?;
    wr.send(&ClientMessage::SecureChannel(accept)).await?;
    wr.enable(keys.send);
    rd.enable(keys.recv);

    let response = build_auth_response(auth, challenge, &request.server_key)?;
    wr.send(&ClientMessage::Auth(response)).await?;

    let Some(ServerMessage::AuthResult { ok, reason }) = rd.recv().await? else {
        return Err("server closed the connection during authentication".into());
    };
    if !ok {
        return Err(format!("authentication failed: {}", reason.unwrap_or_default()).into());
    }

    let public_key_der = match &identity {
        ResolvedIdentity::Rsa(kp) => crypto::public_key_to_der(&kp.public)?,
        ResolvedIdentity::Pq { public_der, .. } => public_der.clone(),
    };
    wr.send(&ClientMessage::Identify {
        display_name: request.nickname.clone(),
        public_key_der,
        key_mode,
    })
    .await?;

    let Some(ServerMessage::IdentifyResult { ok, you, reason }) = rd.recv().await? else {
        return Err("server closed the connection during identify".into());
    };
    if !ok {
        return Err(Box::new(NicknameTakenError(
            reason.unwrap_or_else(|| "nickname rejected".to_string()),
        )));
    }
    let you = you.ok_or("server accepted identify but returned no user id")?;

    Ok((rd, wr, you, identity, key_mode, server_addr))
}

/// Resolves `host:port`, preferring IPv4 when both A and AAAA records exist.
async fn resolve_server_prefer_ipv4(host: &str, port: u16) -> Result<std::net::SocketAddr, BoxError> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await?
        .collect();
    prefer_ipv4(&addrs).ok_or_else(|| format!("no addresses for {host}:{port}").into())
}

/// Picks which resolved address to connect to: the first IPv4 one, or the
/// first of any family when the host has no A record at all. `None` only for
/// an empty list, which is a resolution failure rather than a choice.
///
/// Preferring IPv4 is not a general-purpose policy - it is specifically
/// about the UDP rendezvous that rides the same host and port. A server
/// reached over IPv6 through Docker's default port publishing sees clients
/// through the bridge, so its STUN answer reports the bridge's own address
/// as the client's public one; the IPv4 path on the same server commonly
/// reports the client's real endpoint. Since an unusable observation costs
/// cross-network punching entirely (`p2p_proto::is_usable_reflexive_observed`
/// can only refuse it, not repair it), the family that tends to yield a true
/// observation is worth preferring at connect time.
///
/// Order within a family is left exactly as the resolver returned it, which
/// is what lets DNS-level ordering (round-robin, sorted by RFC 6724 policy)
/// still mean something.
///
/// `pub` purely so `test/connect_test.rs` can exercise the choice without a
/// live resolver, the same way `resolve_my_keypair` is exposed below - the
/// selection was split out of `resolve_server_prefer_ipv4` for exactly that
/// reason, since the DNS lookup around it cannot be made deterministic in a
/// test. Behaviour is unchanged from the single sort-and-take-first it
/// replaced (a stable sort by `is_ipv6` puts the first IPv4 record first,
/// and leaves the first address of any family first when there is none).
pub fn prefer_ipv4(addrs: &[std::net::SocketAddr]) -> Option<std::net::SocketAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
}

/// `PqHybrid` is never generated in-process here - always loaded from the
/// keybundle files `aloo --keygen-pq-hybrid` produces (§13). `pub` purely
/// so `test/connect_test.rs` can exercise the `PqHybrid` auto-generate arm
/// directly without a live socket.
pub fn resolve_my_keypair(sel: &MyKeySelection) -> Result<(ResolvedIdentity, KeyMode), BoxError> {
    match sel {
        MyKeySelection::None => Ok((
            ResolvedIdentity::Rsa(crypto::KeyPair::generate()?),
            KeyMode::None,
        )),
        MyKeySelection::Password(pw) => Ok((
            ResolvedIdentity::Rsa(crypto::KeyPair::from_password(pw)?),
            KeyMode::Password,
        )),
        MyKeySelection::PqHybrid {
            file_pub,
            file_priv,
        } => {
            // Transparently generates a fresh keybundle at these exact
            // paths if either is missing - covers both a freshly-assigned,
            // not-yet-generated location (`fresh_pq_hybrid_paths_in`) and a
            // path the user typed by hand that simply doesn't exist yet.
            crypto::pq::ensure_bundle_at(file_pub, file_priv)?;
            let private = crypto::pq::load_private_bundle(file_priv)?;
            let public = crypto::pq::load_public_bundle(file_pub)?;
            let public_der = proto::encode(&public)?;
            Ok((
                ResolvedIdentity::Pq {
                    private,
                    public_der,
                },
                KeyMode::PqHybrid,
            ))
        }
    }
}

fn build_auth_response(
    auth_kind: AuthKind,
    challenge: Option<Vec<u8>>,
    server_key: &ServerKeySelection,
) -> Result<AuthResponse, BoxError> {
    match (auth_kind, server_key) {
        (AuthKind::None, _) => Ok(AuthResponse::None),
        (AuthKind::Password, ServerKeySelection::Password(pw)) => {
            Ok(AuthResponse::Password(pw.clone()))
        }
        (AuthKind::Rsa, ServerKeySelection::Rsa(path)) => {
            let server_pub = crypto::load_public_key(path)?;
            let nonce = challenge.ok_or("server requires rsa auth but sent no challenge")?;
            let blocks = crypto::encrypt_chunked(&server_pub, &nonce)?;
            Ok(AuthResponse::Rsa { blocks })
        }
        (kind, _) => Err(format!(
            "server requires {kind:?} auth but no matching server_key was provided"
        )
        .into()),
    }
}

fn local_display_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anon".to_string())
}

/// Loads the identity-pinning store from the connect popup's `id_store`
/// field (§12). Any load failure other than "doesn't exist yet" falls back
/// to an empty in-memory store: refusing to connect over a local
/// bookkeeping-file problem would be worse than running without pinning
/// checks.
fn load_id_store(path: &std::path::Path) -> idstore::IdStore {
    match idstore::IdStore::load(path) {
        Ok(store) => store,
        Err(e) => {
            eprintln!(
                "aloo: failed to load id_store at {}: {e} (continuing this session without identity pinning)",
                path.display()
            );
            idstore::IdStore::new_empty(path.to_path_buf())
        }
    }
}

// ---------------------------------------------------------------------
// Connect-popup field cache (`~/.aloo/.cache`)
//
// Remembers, per (host, port), the `pq_hybrid` keybundle files last used
// there, so relaunch/reconnect prefills the popup instead of starting
// from a fresh identity. Paired with `crypto::pq::ensure_bundle_at`,
// which generates the key material on first actual connect - between the
// two, `pq_hybrid` (the default `my_key` type) never requires running
// `aloo --keygen-pq-hybrid` by hand.
// ---------------------------------------------------------------------

/// Resolves the connect-cache file's path: `~/.aloo/.cache`, same
/// cross-platform `~` resolution as `idstore` (`platform::aloo_dir`).
pub fn cache_path() -> PathBuf {
    crate::platform::aloo_dir().join(".cache")
}

/// One remembered connect-popup state for a specific `(host, port)`.
#[derive(Clone, PartialEq, Eq, Debug)]
struct CachedConnection {
    host: String,
    port: u16,
    pq_file_pub: String,
    pq_file_priv: String,
}

/// The last connect-popup values used, per (host, port); the most recently
/// used entry prefills a freshly-opened popup (`prefill_connect_defaults`),
/// so each server keeps its own remembered `pq_hybrid` identity rather
/// than one global default. Backed by a flat
/// `host<TAB>port<TAB>file_pub<TAB>file_priv`-per-line file, most-recently
/// used last - same forgiving tab-delimited conventions as
/// `IdStore`/`OwnNextKeys` (a corrupted cache must never block connecting).
pub struct ConnectCache {
    path: PathBuf,
    entries: Vec<CachedConnection>,
}

impl ConnectCache {
    /// Starts an empty, in-memory-only cache bound to `path` - used as a
    /// fallback when `load` fails for a reason other than the file simply
    /// not existing yet, mirroring `idstore::IdStore::new_empty`.
    pub fn new_empty(path: PathBuf) -> Self {
        Self {
            path,
            entries: Vec::new(),
        }
    }

    /// Loads `path` if it exists; a missing file isn't an error (first run
    /// - "if .cache file does not exist, use the current defaults") and
    /// just starts empty. A line that doesn't parse as exactly
    /// `host<TAB>port<TAB>file_pub<TAB>file_priv`, or whose port isn't a
    /// valid `u16`, is skipped rather than failing the whole load.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut entries = Vec::new();
        match fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if let [host, port, file_pub, file_priv] = parts[..]
                        && let Ok(port) = port.parse::<u16>()
                    {
                        entries.push(CachedConnection {
                            host: host.to_string(),
                            port,
                            pq_file_pub: file_pub.to_string(),
                            pq_file_priv: file_priv.to_string(),
                        });
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// The most recently used entry, if any: `(host, port, file_pub, file_priv)`.
    pub fn most_recent(&self) -> Option<(&str, u16, &str, &str)> {
        self.entries.last().map(|e| {
            (
                e.host.as_str(),
                e.port,
                e.pq_file_pub.as_str(),
                e.pq_file_priv.as_str(),
            )
        })
    }

    /// Records `(host, port) -> (file_pub, file_priv)` as the most
    /// recently used entry, replacing any existing entry for the pair so
    /// it moves to the end (callers persist via `save`). A field
    /// containing a tab or newline is silently skipped - same injection
    /// reasoning as `IdStore::check_and_pin`.
    pub fn record(&mut self, host: &str, port: u16, file_pub: &str, file_priv: &str) {
        if !is_storable(host) || !is_storable(file_pub) || !is_storable(file_priv) {
            return;
        }
        self.entries.retain(|e| !(e.host == host && e.port == port));
        self.entries.push(CachedConnection {
            host: host.to_string(),
            port,
            pq_file_pub: file_pub.to_string(),
            pq_file_priv: file_priv.to_string(),
        });
    }

    /// Persists all entries to `path`, creating parent directories if
    /// needed - same conventions as `idstore::IdStore::save`.
    pub fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut out = String::new();
        for e in &self.entries {
            out.push_str(&e.host);
            out.push('\t');
            out.push_str(&e.port.to_string());
            out.push('\t');
            out.push_str(&e.pq_file_pub);
            out.push('\t');
            out.push_str(&e.pq_file_priv);
            out.push('\n');
        }
        fs::write(&self.path, out)
    }
}

/// Loads the connect cache from its default path (`~/.aloo/.cache`),
/// falling back to an empty in-memory-only cache on any load failure other
/// than "doesn't exist yet" - same fallback policy, and reasoning, as
/// `load_id_store`: a broken local cache must never block connecting.
fn load_connect_cache() -> ConnectCache {
    let path = cache_path();
    match ConnectCache::load(&path) {
        Ok(cache) => cache,
        Err(e) => {
            eprintln!(
                "aloo: failed to load connect cache at {}: {e} (continuing without it)",
                path.display()
            );
            ConnectCache::new_empty(path)
        }
    }
}

/// A 4-character lowercase-alphanumeric prefix for a freshly-assigned
/// `pq_hybrid` keybundle location - 36^4 (~1.68M) combinations, plenty for
/// a directory that will realistically hold at most a handful of these
/// files at once.
pub fn random_prefix() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    crypto::random_bytes(4)
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Picks a `(file_pub, file_priv)` pair under `dir` that doesn't collide
/// with anything already there (up to 20 tries, then returns the last
/// attempt regardless). Does **not** create the files -
/// `crypto::pq::ensure_bundle_at` does, on first actual connect - so a
/// location can be assigned, shown and cached before any key material
/// exists on disk.
pub fn fresh_pq_hybrid_paths_in(dir: &Path) -> (PathBuf, PathBuf) {
    for _ in 0..20 {
        let prefix = random_prefix();
        let file_pub = dir.join(format!("{prefix}.pub"));
        let file_priv = dir.join(format!("{prefix}.priv"));
        if !file_pub.exists() && !file_priv.exists() {
            return (file_pub, file_priv);
        }
    }
    let prefix = random_prefix();
    (
        dir.join(format!("{prefix}.pub")),
        dir.join(format!("{prefix}.priv")),
    )
}

/// Prefills `popup`'s host/port/`pq_hybrid` file fields once, before it's
/// shown (never reactively afterward). With a cached most-recent entry,
/// restores its host/port/keybundle paths and sets the key type to
/// `PqHybrid` (restored file paths only make sense with it); on first run,
/// assigns a fresh not-yet-generated `pq_hybrid` location under `dir` so
/// the default `my_key` type is immediately connectable.
pub fn prefill_connect_defaults(popup: &mut ConnectPopupState, cache: &ConnectCache, dir: &Path) {
    if let Some((host, port, file_pub, file_priv)) = cache.most_recent() {
        popup.host = host.to_string();
        popup.port = port.to_string();
        popup.my_key.key_type = ui_connect_popup::MyKeyType::PqHybrid;
        popup.my_key.file_pub = file_pub.to_string();
        popup.my_key.file_priv = file_priv.to_string();
    } else {
        let (file_pub, file_priv) = fresh_pq_hybrid_paths_in(dir);
        popup.my_key.file_pub = file_pub.display().to_string();
        popup.my_key.file_priv = file_priv.display().to_string();
    }
}
