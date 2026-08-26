//! Client-side connection bootstrap: drives the connect popup, then the
//! auth + identify handshake, before handing off to `crate::client::session`'s
//! ongoing connected-session loop.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tokio::net::TcpStream;

use crate::BoxError;
use crate::client::idstore;
use crate::client::reconnect;
use crate::client::session;
use crate::client::tui::ui_connect_popup::{self, ConnectPopupState};
use crate::crypto;
use crate::proto::{self, ClientMessage, KeyMode, ServerMessage};
use crate::server::ssl::{self, BoxedStream};
use crate::validation::is_storable;

/// Where this client's own identity comes from. `pq_hybrid`
/// (`docs/PROTOCOL.md` §13) is the only peer-to-peer scheme this app has,
/// so there is nothing to choose between: both files are keybundles
/// produced by `aloo --keygen-pq-hybrid` (or auto-generated on first
/// connect, §13.9), not PEM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyKeySelection {
    pub file_pub: PathBuf,
    pub file_priv: PathBuf,
}

/// What the user asked to connect with, as collected by the connect popup
/// (`tui::ui_connect_popup`) and consumed by the handshake here.
///
/// The identity-pinning store (`aloo::idstore`, `docs/PROTOCOL.md` §12) is
/// not a field: it always lives at `idstore::default_path()` under
/// `ALOO_HOME`, like every other local store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    /// Dial over TLS (`docs/PROTOCOL.md` §1.4); `host` is then also the
    /// name the server's certificate is checked against.
    pub ssl: bool,
    /// Extra trusted roots for `ssl` (`connect_ssl_ca` in settings) - a
    /// self-signed or privately issued server certificate lives here.
    pub ssl_ca: Option<PathBuf>,
    pub nickname: String,
    /// The nickname's password on this server (§5.1).
    pub password: String,
    pub my_key: MyKeySelection,
    /// An activation code to answer `AuthResult { activation_pending }`
    /// with (§5.2) - set by the activation popup on the connect that
    /// follows it, `None` on every other connect.
    pub activation_code: Option<String>,
}

/// What the connect popup's Register button collects (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub ssl_ca: Option<PathBuf>,
    pub nickname: String,
    pub password: String,
    pub email: String,
}

/// This client's own resolved key material, loaded from the keybundle
/// pair `MyKeySelection` names. `pub` so `resolve_my_keypair`'s return
/// type is externally nameable (see its own doc comment).
pub struct ResolvedIdentity {
    pub private: crypto::pq::PqPrivateBundle,
    /// Bincode-encoded `crypto::pq::PqPublicBundle`, precomputed here
    /// (once, from `file_pub`) since `Identify`'s `public_key_der` needs
    /// it and `PqPrivateBundle` alone can't derive it back out.
    pub public_der: Vec<u8>,
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

/// The credentials were right but the account is not activated yet
/// (`AuthResult { activation_pending: true }`, §5.2) - or the code this
/// connect carried was refused. Either way the caller's next move is the
/// activation popup, not an error screen; the string is what it shows.
#[derive(Debug)]
pub struct ActivationRequiredError(pub String);

impl std::fmt::Display for ActivationRequiredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ActivationRequiredError {}

pub async fn run_client_inner(
    surface: &mut crate::client::tui::surface::Surface,
    port: u16,
    keyboard_release_reporting: bool,
    hotkey_rx: Option<
        tokio::sync::mpsc::UnboundedReceiver<crate::client::global_ptt::GlobalPttEvent>,
    >,
    no_server: bool,
) -> Result<(), BoxError> {
    let mut popup = ConnectPopupState::new();
    popup.port = port.to_string();
    popup.nickname = local_display_name();

    let settings_path = crate::settings::default_path();
    let settings = crate::settings::Settings::load_or_create(&settings_path).unwrap_or_else(|e| {
        crate::log_warn!("could not read/create ~/.aloo/settings ({e}); using defaults");
        crate::settings::Settings::default()
    });
    let mut cache = load_connect_cache();
    prefill_connect_defaults(&mut popup, &settings, &cache, &crate::platform::aloo_dir());
    let ssl_ca = settings
        .connect_ssl_ca
        .as_deref()
        .map(crate::platform::expand_tilde);

    if no_server {
        // Nothing to show the connect popup for: with no server there is
        // nobody to authenticate against, so the one thing left to decide
        // is whether there is anybody to reach at all.
        if !settings.has_direct_punch_configured() {
            println!(
                "aloo: --no-server with no direct_punch_to configured in ~/.aloo/settings - \
                 nothing to reach, exiting."
            );
            return Ok(());
        }
        let my_key = MyKeySelection {
            file_pub: PathBuf::from(&popup.my_key.file_pub),
            file_priv: PathBuf::from(&popup.my_key.file_priv),
        };
        let identity = resolve_my_keypair(&my_key)?;
        let you = crate::client::p2p::direct_peer_id(&popup.nickname, None);
        let id_store = load_id_store(&idstore::default_path());
        // Same reasoning as the connected path below: the popup is done
        // with the terminal (there never was one here), so the stdin
        // reader is safe to start now.
        let input_rx = crate::client::tui::terminal::spawn_session_input();
        crate::log_warn!(
            "aloo started as {} with no server - reachable only by the direct_punch_to \
             peers in ~/.aloo/settings",
            popup.nickname
        );
        return session::run_connected_session(
            surface,
            None,
            crate::control::NullSink,
            popup.nickname,
            you,
            identity,
            keyboard_release_reporting,
            id_store,
            hotkey_rx,
            None,
            input_rx,
            None,
            crate::client::export::DIRECT_LABEL.to_string(),
        )
        .await;
    }

    loop {
        // Set only when this iteration's `request` came from a Register
        // that just succeeded - picks the activation popup's wording
        // below (`ActivationPopupState::new_after_registration` instead
        // of `::new`) without threading a parameter through every other
        // path that reaches that popup.
        let mut just_registered = false;
        let mut request = match ui_connect_popup::run(surface, &mut popup)? {
            ui_connect_popup::Submission::Connect(request) => request,
            ui_connect_popup::Submission::Register(mut register) => {
                register.ssl_ca = ssl_ca.clone();
                match register_account(&register).await {
                    Ok(()) => match popup.build_request() {
                        // Registering and connecting share every field but
                        // the keybundle, and Register wouldn't have been
                        // reachable if `my_key` weren't already valid -
                        // so this reuses the just-submitted form to go
                        // straight into activation (§5.2/§5.3) instead of
                        // making the user press Connect a second time.
                        Ok(request) => {
                            just_registered = true;
                            request
                        }
                        Err(e) => {
                            popup.notice = Some(format!(
                                "registered - check {} for the activation code, then Connect \
                                 ({e})",
                                register.email
                            ));
                            popup.focus = ui_connect_popup::Field::Connect;
                            continue;
                        }
                    },
                    Err(e) => {
                        popup.error = Some(format!("registration failed: {e}"));
                        continue;
                    }
                }
            }
            ui_connect_popup::Submission::Cancel => return Ok(()), // user cancelled
        };
        request.ssl_ca = ssl_ca.clone();

        // Remembered regardless of whether the connection attempt below
        // actually succeeds ("the last values used in the popup", not "the
        // last successful connection") - a wrong password or an
        // unreachable host doesn't mean the pq_hybrid identity chosen was
        // wrong, or that the nickname typed was.
        if let Err(e) = crate::settings::Settings::remember_connection(
            &settings_path,
            &request.host,
            request.port,
            &request.nickname,
            request.ssl,
        ) {
            crate::log_warn!("could not remember this connection in ~/.aloo/settings ({e})");
        }
        cache.record(
            &request.host,
            request.port,
            &request.my_key.file_pub.display().to_string(),
            &request.my_key.file_priv.display().to_string(),
        );
        if let Err(e) = cache.save() {
            crate::log_warn!("failed to save connect cache: {e}");
        }

        // An account still waiting for its activation code (§5.2) is asked
        // for it right here, and the connect retried with the answer -
        // as many times as it takes, until the code is right or the user
        // gives up on it with Esc.
        let mut activation = if just_registered {
            ui_connect_popup::ActivationPopupState::new_after_registration(&request.nickname)
        } else {
            ui_connect_popup::ActivationPopupState::new(&request.nickname)
        };
        let outcome = loop {
            match connect_with_reconnect(&request).await {
                Err(e) if e.is::<ActivationRequiredError>() => {
                    activation.error = request.activation_code.as_ref().map(|_| e.to_string());
                    let Some(code) = ui_connect_popup::run_activation(surface, &mut activation)?
                    else {
                        break None;
                    };
                    request.activation_code = Some(code);
                }
                other => break Some(other),
            }
        };
        let Some(outcome) = outcome else {
            popup.error = Some("activation cancelled - the account stays unactivated".into());
            continue;
        };

        match outcome {
            Ok((server_events, sink, you, identity, server_addr)) => {
                let id_store = load_id_store(&idstore::default_path());
                // The stdin reader is started only now, once the popup is
                // done with the terminal - the popup drives its own
                // blocking `event::read()`, and two readers on one tty
                // would race for every keystroke.
                let input_rx = crate::client::tui::terminal::spawn_session_input();
                let server_label = crate::client::export::server_label(&request.host, request.port);
                return session::run_connected_session(
                    surface,
                    Some(server_events),
                    sink,
                    request.nickname,
                    you,
                    identity,
                    keyboard_release_reporting,
                    id_store,
                    hotkey_rx,
                    Some(server_addr),
                    input_rx,
                    // A foreground client has no plan: it opens the
                    // popup, joins the-hall, and goes where the user
                    // takes it.
                    None,
                    server_label,
                )
                .await;
            }
            Err(e) => {
                if let Some(taken) = e.downcast_ref::<NicknameTakenError>() {
                    // Loop back to the popup instead of exiting: everything
                    // the user already filled in (host, keys, ...) stays
                    // put, only the nickname needs to change.
                    popup.error = Some(taken.0.clone());
                    popup.focus = ui_connect_popup::Field::Nickname;
                } else if let Some(refused) = e.downcast_ref::<AuthRefusedError>() {
                    // Same for a wrong password: the form, not an exit.
                    popup.error = Some(refused.0.clone());
                    popup.focus = ui_connect_popup::Field::Password;
                } else if let Some(deactivated) = e.downcast_ref::<AccountDeactivatedError>() {
                    popup.error = Some(deactivated.0.clone());
                    popup.focus = ui_connect_popup::Field::Password;
                } else if let Some(mismatch) = e.downcast_ref::<SslMismatchError>() {
                    // Not a field-level problem - nothing in the form can
                    // fix this, only the settings file can - so no focus
                    // change, just the reason shown.
                    popup.error = Some(mismatch.0.clone());
                } else {
                    return Err(e);
                }
            }
        }
    }
}

/// `Register` over a fresh connection (§5.3): dial, seal the channel, ask,
/// read the answer, hang up. The server closes the connection after its
/// reply either way, so there is nothing to keep.
pub async fn register_account(request: &RegisterRequest) -> Result<(), BoxError> {
    let (mut rd, mut wr, registration_open, _) =
        open_control_channel(&request.host, request.port, request.ssl, request.ssl_ca.as_deref())
            .await?;
    if !registration_open {
        return Err("this server does not take registrations".into());
    }
    wr.send(&ClientMessage::Register {
        nickname: request.nickname.clone(),
        password: request.password.clone(),
        email: request.email.clone(),
    })
    .await?;
    let Some(ServerMessage::RegisterResult { ok, reason }) = rd.recv().await? else {
        return Err("server closed the connection during registration".into());
    };
    if ok {
        Ok(())
    } else {
        Err(reason.unwrap_or_else(|| "registration refused".into()).into())
    }
}

/// The initial connect attempt failed for a reason `diagnose_ssl_mismatch`
/// traced to `connect_using_ssl` being set wrong for this server, not a
/// wrong host, password, or anything else. Downcast for specifically in
/// the connect popup's loop, so this one - and only this one - loops back
/// into the form with the reason shown, the same way a wrong password
/// already does, rather than ending the client the way an unclassified
/// connect failure still does.
#[derive(Debug)]
pub struct SslMismatchError(pub String);

impl std::fmt::Display for SslMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SslMismatchError {}

/// After `request`'s own connect attempt has already failed, tries once
/// more at the same host/port with the *opposite* `ssl` - never to
/// actually connect that way (the result is always discarded), only to
/// tell a genuine transport-mode mismatch apart from every other kind of
/// failure. Bounded to `SSL_DIAGNOSIS_TIMEOUT` so a server that is simply
/// down doesn't turn one failed connect into two slow ones.
const SSL_DIAGNOSIS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

async fn diagnose_ssl_mismatch(request: &ConnectRequest) -> Option<String> {
    let opposite_ssl = !request.ssl;
    let probed = tokio::time::timeout(
        SSL_DIAGNOSIS_TIMEOUT,
        open_control_channel(&request.host, request.port, opposite_ssl, request.ssl_ca.as_deref()),
    )
    .await;
    if !matches!(probed, Ok(Ok(_))) {
        return None;
    }
    Some(if opposite_ssl {
        "this server appears to require SSL - turn connect_using_ssl=on in ~/.aloo/settings"
            .to_string()
    } else {
        "this server appears to reject SSL - turn connect_using_ssl=off in ~/.aloo/settings"
            .to_string()
    })
}

/// How long the very first connect attempt (`connect_with_reconnect`'s own
/// `connect_and_handshake`, never a later automatic reconnect) is given
/// before it's treated as failed. Generous next to `SSL_DIAGNOSIS_TIMEOUT`
/// because this one also has to cover DNS, TCP, and the whole login
/// handshake - not just reaching `Hello`.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// `e` (a real error, or already a synthetic "timed out" one) becomes a
/// `SslMismatchError` when `diagnose_ssl_mismatch` finds the opposite mode
/// works, unless `e` already proves the transport mode was fine (a wrong
/// password, a taken nickname, a deactivated account, or a pending
/// activation code) - probing an unrelated failure would only add latency.
async fn with_ssl_diagnosis(request: &ConnectRequest, e: BoxError) -> BoxError {
    let already_explained = e.downcast_ref::<NicknameTakenError>().is_some()
        || e.downcast_ref::<AuthRefusedError>().is_some()
        || e.downcast_ref::<AccountDeactivatedError>().is_some()
        || e.downcast_ref::<ActivationRequiredError>().is_some();
    if already_explained {
        return e;
    }
    match diagnose_ssl_mismatch(request).await {
        Some(diagnosis) => Box::new(SslMismatchError(format!("{e} - {diagnosis}"))),
        None => e,
    }
}

/// Connects, then hands the connection straight to the reconnect
/// supervisor (`crate::client::reconnect`) - what every session that has a
/// server starts from.
///
/// The session never sees the socket itself: it gets the supervisor's
/// event stream in place of the read half, and a sink whose write half the
/// supervisor replaces on every reconnect (`docs/PROTOCOL.md` §4.2). The
/// first connection is still made here, and still fails here - a server
/// that cannot be reached *at all* is a wrong host or a wrong password far
/// more often than a server that is briefly down, and saying so beats
/// retrying forever against a typo.
pub async fn connect_with_reconnect(
    request: &ConnectRequest,
) -> Result<
    (
        tokio::sync::mpsc::UnboundedReceiver<reconnect::ServerEvent>,
        reconnect::ServerSink,
        proto::UserId,
        ResolvedIdentity,
        std::net::SocketAddr,
    ),
    BoxError,
> {
    // Bounded rather than left to hang: a client that skips TLS against a
    // `connect_using_ssl`-required server (or the other way around) is not
    // a slow connection, it is a mutual stall neither rustls nor this
    // app's own framing ever resolves on its own - the server sits inside
    // its TLS accept waiting for a ClientHello that is never coming, the
    // client sits waiting for a `Hello` that is never coming either,
    // forever, with nothing to time either side out. `CONNECT_TIMEOUT` is
    // generous enough for a real, working, merely slow connection; a
    // timeout is itself already a strong signal worth feeding into the
    // same diagnosis, not just a bare "connect timed out".
    let attempt = tokio::time::timeout(CONNECT_TIMEOUT, connect_and_handshake(request)).await;
    let (rd, wr, you, identity, server_addr) = match attempt {
        Ok(Ok(ok)) => ok,
        Ok(Err(e)) => return Err(with_ssl_diagnosis(request, e).await),
        Err(_elapsed) => {
            let timeout_err: BoxError = format!(
                "connect to {}:{} timed out after {}s",
                request.host,
                request.port,
                CONNECT_TIMEOUT.as_secs()
            )
            .into();
            return Err(with_ssl_diagnosis(request, timeout_err).await);
        }
    };
    let public_key_der = identity.public_der.clone();
    let (sink, lost_rx) = reconnect::ServerSink::new(wr);
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    reconnect::spawn_supervisor(
        rd,
        reconnect::ReconnectPlan {
            request: request.clone(),
            public_key_der,
            backoff: reconnect::Backoff::default(),
        },
        sink.clone(),
        lost_rx,
        events_tx,
    );
    Ok((events_rx, sink, you, identity, server_addr))
}

/// The server refused the nickname/password pair (§5.1) - shown on the
/// connect form rather than ending the client, since a typo in a password
/// is the likeliest cause by far.
#[derive(Debug)]
pub struct AuthRefusedError(pub String);

impl std::fmt::Display for AuthRefusedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AuthRefusedError {}

/// The credentials were right, but a superadmin has deactivated this
/// account. Shown on the connect form exactly like `AuthRefusedError` -
/// no session exists yet at this point, so there's nothing for the
/// full-screen takeover modal (shown to an *already-connected* session
/// that gets deactivated live) to interrupt; an inline reason is both
/// simpler and consistent with every other login failure here.
#[derive(Debug)]
pub struct AccountDeactivatedError(pub String);

impl std::fmt::Display for AccountDeactivatedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AccountDeactivatedError {}

/// Connects, then runs the auth + identify handshake. On success returns
/// the split stream halves, the `UserId` the server assigned us, and our
/// own keybundle (needed to decrypt incoming messages). A taken nickname
/// comes back as `NicknameTakenError` so the caller can retry instead of
/// treating it as fatal.
pub(crate) async fn connect_and_handshake(
    request: &ConnectRequest,
) -> Result<
    (
        crate::control::ControlReader<tokio::io::ReadHalf<BoxedStream>>,
        crate::control::ControlWriter<tokio::io::WriteHalf<BoxedStream>>,
        proto::UserId,
        ResolvedIdentity,
        std::net::SocketAddr,
    ),
    BoxError,
> {
    let identity = resolve_my_keypair(&request.my_key)?;
    let public_key_der = identity.public_der.clone();
    let (rd, wr, you, server_addr) = handshake_as(request, public_key_der).await?;
    Ok((rd, wr, you, identity, server_addr))
}

/// The handshake itself, for an identity that has already been resolved.
///
/// Split out from `connect_and_handshake` for reconnects
/// (`crate::client::reconnect`), which must come back as the *same*
/// identity: re-resolving would re-read (or, on a first run, re-generate)
/// the keybundle files behind this client's back. Everything a reconnect
/// can safely redo - the TCP (and TLS) connect, the sealed control
/// channel, auth, and identify - is here; everything it must not redo is
/// in the caller.
pub async fn handshake_as(
    request: &ConnectRequest,
    public_key_der: Vec<u8>,
) -> Result<
    (
        crate::control::ControlReader<tokio::io::ReadHalf<BoxedStream>>,
        crate::control::ControlWriter<tokio::io::WriteHalf<BoxedStream>>,
        proto::UserId,
        std::net::SocketAddr,
    ),
    BoxError,
> {
    let (mut rd, mut wr, _registration_open, server_addr) =
        open_control_channel(&request.host, request.port, request.ssl, request.ssl_ca.as_deref())
            .await?;

    wr.send(&ClientMessage::Auth {
        nickname: request.nickname.clone(),
        password: request.password.clone(),
    })
    .await?;
    let Some(ServerMessage::AuthResult {
        ok,
        activation_pending,
        deactivated,
        reason,
    }) = rd.recv().await?
    else {
        return Err("server closed the connection during authentication".into());
    };
    if !ok && activation_pending {
        // Right credentials, unactivated account (§5.2): answer with the
        // code this connect carries, or tell the caller to go and get one.
        let Some(code) = &request.activation_code else {
            return Err(Box::new(ActivationRequiredError(
                "this account is waiting for its activation code".into(),
            )));
        };
        wr.send(&ClientMessage::Activate { code: code.clone() })
            .await?;
        let Some(ServerMessage::AuthResult { ok, reason, .. }) = rd.recv().await? else {
            return Err("server closed the connection during activation".into());
        };
        if !ok {
            return Err(Box::new(ActivationRequiredError(
                reason.unwrap_or_else(|| "activation refused".into()),
            )));
        }
    } else if !ok && let Some(reason) = deactivated {
        return Err(Box::new(AccountDeactivatedError(format!(
            "this account has been deactivated: {reason}"
        ))));
    } else if !ok {
        return Err(Box::new(AuthRefusedError(format!(
            "authentication failed: {}",
            reason.unwrap_or_default()
        ))));
    }

    wr.send(&ClientMessage::Identify {
        public_key_der,
        key_mode: KeyMode::PqHybrid,
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

    Ok((rd, wr, you, server_addr))
}

/// Dials the server and brings the sealed control channel up (§1.3): TCP,
/// TLS when asked (§1.4), `Hello`, `SecureChannel`. Returns the two
/// sealed halves, what `Hello` said about registrations, and the
/// server's resolved address - shared by a login and a registration,
/// which differ only in what they say next.
async fn open_control_channel(
    host: &str,
    port: u16,
    use_ssl: bool,
    ssl_ca: Option<&Path>,
) -> Result<
    (
        crate::control::ControlReader<tokio::io::ReadHalf<BoxedStream>>,
        crate::control::ControlWriter<tokio::io::WriteHalf<BoxedStream>>,
        bool,
        std::net::SocketAddr,
    ),
    BoxError,
> {
    // Prefer IPv4 when the hostname resolves to both families. Docker's IPv6
    // UDP port publishing often poisons STUN (observed address becomes
    // 172.17.0.1) while IPv4 returns the client's real public endpoint.
    let server_addr = resolve_server_prefer_ipv4(host, port).await?;
    let stream = TcpStream::connect(server_addr).await?;
    // The server's UDP rendezvous socket binds the same numeric port on the
    // same address (`server::run`) - captured here, before the stream is
    // wrapped and split, since `peer_addr` needs the whole `TcpStream` and
    // this is the resolved address (DNS already settled), not just
    // whatever hostname the user typed.
    let server_addr = stream.peer_addr()?;
    let connector = if use_ssl {
        Some(ssl::client_connector(ssl_ca)?)
    } else {
        None
    };
    let stream = ssl::connect(connector.as_ref(), host, stream).await?;
    let (rd, wr) = tokio::io::split(stream);
    let mut rd = crate::control::ControlReader::new(rd);
    let mut wr = crate::control::ControlWriter::new(wr);

    let Some(ServerMessage::Hello {
        registration_open,
        control,
    }) = rd.recv().await?
    else {
        return Err("server closed the connection during handshake".into());
    };
    let (accept, keys) = crate::control::accept_offer(&control)?;
    wr.send(&ClientMessage::SecureChannel(accept)).await?;
    wr.enable(keys.send);
    rd.enable(keys.recv);
    Ok((rd, wr, registration_open, server_addr))
}

/// Resolves `host:port`, preferring IPv4 when both A and AAAA records exist.
async fn resolve_server_prefer_ipv4(
    host: &str,
    port: u16,
) -> Result<std::net::SocketAddr, BoxError> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
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
/// A function of its own, and `pub`, purely so `test/connect_test.rs` can
/// exercise the choice without a live resolver - the same way
/// `resolve_my_keypair` is exposed below, and for the same reason: the DNS
/// lookup `resolve_server_prefer_ipv4` wraps around it cannot be made
/// deterministic in a test.
pub fn prefer_ipv4(addrs: &[std::net::SocketAddr]) -> Option<std::net::SocketAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
}

/// Keys are never derived in-process here - always loaded from the
/// keybundle files `aloo --keygen-pq-hybrid` produces (§13), generating
/// them first if they aren't there yet. `pub` purely so
/// `test/connect_test.rs` can exercise the auto-generate arm directly
/// without a live socket.
pub fn resolve_my_keypair(sel: &MyKeySelection) -> Result<ResolvedIdentity, BoxError> {
    // Transparently generates a fresh keybundle at these exact paths if
    // either is missing - covers both a freshly-assigned,
    // not-yet-generated location (`fresh_pq_hybrid_paths_in`) and a path
    // the user typed by hand that simply doesn't exist yet.
    crypto::pq::ensure_bundle_at(&sel.file_pub, &sel.file_priv)?;
    let private = crypto::pq::load_private_bundle(&sel.file_priv)?;
    let public = crypto::pq::load_public_bundle(&sel.file_pub)?;
    let public_der = proto::encode(&public)?;
    Ok(ResolvedIdentity {
        private,
        public_der,
    })
}

fn local_display_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anon".to_string())
}

/// Loads the identity-pinning store (§12) from its one location under
/// `ALOO_HOME`. Any load failure other than "doesn't exist yet" falls back
/// to an empty in-memory store: refusing to connect over a local
/// bookkeeping-file problem would be worse than running without pinning
/// checks.
fn load_id_store(path: &std::path::Path) -> idstore::IdStore {
    match idstore::IdStore::load(path) {
        Ok(store) => store,
        Err(e) => {
            crate::log_warn!(
                "failed to load id_store at {}: {e} (continuing this session without identity pinning)",
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
            crate::log_warn!(
                "failed to load connect cache at {}: {e} (continuing without it)",
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

/// Prefills `popup`'s host/port/nickname/`pq_hybrid` file fields once,
/// before it's shown (never reactively afterward).
///
/// Two stores feed it, each answering what it alone knows:
///
/// - **`~/.aloo/settings`** - the host, port and **nickname** last
///   submitted (`Settings::remember_connection`). The nickname only lives
///   here: `.cache` is keyed by `(host, port)`, so it has no slot for the
///   one field that is about the person rather than the server. Absent on
///   a machine that has never connected, which is when `$USER` (already
///   in `popup.nickname`) stands in.
/// - **`~/.aloo/.cache`** - the `pq_hybrid` keybundle paths last used for
///   *that* server, which is why it is per-`(host, port)` rather than
///   global. Restoring them also sets the key type to `PqHybrid`, since
///   restored file paths only make sense with it. On first run a fresh,
///   not-yet-generated location under `dir` is assigned instead, so the
///   default `my_key` type is immediately connectable.
pub fn prefill_connect_defaults(
    popup: &mut ConnectPopupState,
    settings: &crate::settings::Settings,
    cache: &ConnectCache,
    dir: &Path,
) {
    if let Some(host) = &settings.connect_host {
        popup.host = host.clone();
    }
    if let Some(port) = settings.connect_port {
        popup.port = port.to_string();
    }
    if let Some(nickname) = &settings.connect_nickname {
        popup.nickname = nickname.clone();
    }
    popup.ssl = settings.connect_using_ssl;
    popup.registration_available = settings.server_allow_registration;
    if let Some((host, port, file_pub, file_priv)) = cache.most_recent() {
        // Only where settings had nothing to say - a hand-edited
        // `connect_host` is a deliberate answer to the same question, and
        // the cache is the older, less specific of the two records.
        if settings.connect_host.is_none() {
            popup.host = host.to_string();
        }
        if settings.connect_port.is_none() {
            popup.port = port.to_string();
        }
        popup.my_key.file_pub = file_pub.to_string();
        popup.my_key.file_priv = file_priv.to_string();
    } else {
        let (file_pub, file_priv) = fresh_pq_hybrid_paths_in(dir);
        popup.my_key.file_pub = file_pub.display().to_string();
        popup.my_key.file_priv = file_priv.display().to_string();
    }
}
