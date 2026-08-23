//! Optional TLS for the server's connections (docs/PROTOCOL.md §1.4).
//!
//! With `server_ssl=on` in `~/.aloo/settings`, the control connection and
//! the account-activation web endpoint (`crate::server::activation`) are
//! both served under the certificate pair named by `server_ssl_fullchain`
//! / `server_ssl_privkey` - a Let's Encrypt pair, typically, whose `~`
//! paths are resolved through `crate::platform::expand_tilde`.
//!
//! What this adds is *server authentication*. The control channel
//! (`crate::control`) already encrypts everything after `Hello`, but its
//! offer is ephemeral and nothing vouches for it - over plain TCP a man in
//! the middle can substitute their own. A certificate a client can check
//! against a root it trusts is what closes that. The channel's own sealing
//! stays exactly as it is on top of TLS, since it is what pins the
//! post-quantum key transport the rest of the protocol relies on; TLS here
//! is the identity, not the confidentiality.
//!
//! The client end lives here too (`client_connector`, `connect`) rather
//! than under `client/`, so the two halves of one configuration sit
//! together: the roots a client trusts are the public ones it ships with
//! plus, optionally, a PEM file of extra roots (`connect_ssl_ca`) for a
//! server whose certificate is self-signed or privately issued.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Anything a connection can run over: a plain `TcpStream`, or a TLS
/// stream around one. Both ends of the protocol are written against this
/// rather than against `TcpStream`, so turning TLS on changes nothing
/// past the accept/connect.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// One connection, TLS or not, behind one type.
pub type BoxedStream = Box<dyn Stream>;

/// The certificate pair `server_ssl=on` serves with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslFiles {
    pub fullchain: PathBuf,
    pub privkey: PathBuf,
}

impl SslFiles {
    /// `Some` when `server_ssl` is on, with both paths `~`-expanded.
    pub fn from_settings(settings: &crate::settings::Settings) -> Option<Self> {
        settings.server_ssl.then(|| Self {
            fullchain: crate::platform::expand_tilde(&settings.server_ssl_fullchain),
            privkey: crate::platform::expand_tilde(&settings.server_ssl_privkey),
        })
    }
}

/// Reads the pair and builds the acceptor every server socket shares.
/// A missing or unreadable file is an error, never a silent fallback to
/// plaintext: an operator who turned `server_ssl` on meant it.
pub fn load_acceptor(files: &SslFiles) -> Result<TlsAcceptor, String> {
    let chain = std::fs::read(&files.fullchain)
        .map_err(|e| format!("cannot read {}: {e}", files.fullchain.display()))?;
    let key = std::fs::read(&files.privkey)
        .map_err(|e| format!("cannot read {}: {e}", files.privkey.display()))?;
    acceptor_from_pem(&chain, &key)
}

/// `load_acceptor` on in-memory PEM - the half that needs no filesystem,
/// which is also what the TLS tests drive with a generated certificate.
pub fn acceptor_from_pem(fullchain_pem: &[u8], privkey_pem: &[u8]) -> Result<TlsAcceptor, String> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &fullchain_pem[..])
            .collect::<Result<_, _>>()
            .map_err(|e| format!("fullchain is not valid PEM: {e}"))?;
    if certs.is_empty() {
        return Err("fullchain holds no certificate".into());
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &privkey_pem[..])
        .map_err(|e| format!("privkey is not valid PEM: {e}"))?
        .ok_or("privkey holds no private key")?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("certificate and key do not go together: {e}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The connector a client dials a `server_ssl=on` server with: the public
/// roots this binary ships with (`webpki-roots`), plus every certificate
/// in `extra_ca` when given.
pub fn client_connector(extra_ca: Option<&Path>) -> Result<TlsConnector, String> {
    let extra = match extra_ca {
        Some(path) => Some(
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
        ),
        None => None,
    };
    connector_from_roots(extra.as_deref())
}

/// `client_connector` on an in-memory extra-roots PEM.
pub fn connector_from_roots(extra_ca_pem: Option<&[u8]>) -> Result<TlsConnector, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_ca_pem {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &pem[..])
            .collect::<Result<_, _>>()
            .map_err(|e| format!("extra CA file is not valid PEM: {e}"))?;
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err("extra CA file holds no usable certificate".into());
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// The name the server's certificate must be for: a DNS name or an IP
/// literal, whichever the user typed as the host.
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string())
        .map_err(|_| format!("{host:?} is not a name a certificate can be issued for"))
}

/// Server side: wraps a freshly accepted socket in TLS when `acceptor`
/// is set, and boxes it either way.
pub async fn accept(
    acceptor: Option<&TlsAcceptor>,
    tcp: tokio::net::TcpStream,
) -> io::Result<BoxedStream> {
    match acceptor {
        Some(acceptor) => Ok(Box::new(acceptor.accept(tcp).await?)),
        None => Ok(Box::new(tcp)),
    }
}

/// Client side: the mirror of `accept`. `host` is what the certificate is
/// checked against. Takes any `Stream` rather than a `TcpStream` so an
/// SMTP `STARTTLS` upgrade (`users_registry::send_activation_email`) can
/// go through the same door.
pub async fn connect<S: Stream + 'static>(
    connector: Option<&TlsConnector>,
    host: &str,
    stream: S,
) -> io::Result<BoxedStream> {
    match connector {
        Some(connector) => {
            let name = server_name(host).map_err(io::Error::other)?;
            Ok(Box::new(connector.connect(name, stream).await?))
        }
        None => Ok(Box::new(stream)),
    }
}
