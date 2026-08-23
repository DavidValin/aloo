//! Tests for `src/server/ssl.rs`: certificate loading and a real TLS
//! handshake over loopback (docs/PROTOCOL.md §1.4).

use aloo::server::ssl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A self-signed certificate for `localhost`, generated fresh (rcgen's
/// default key is EC, not RSA, so this costs microseconds - nothing like
/// the RSA-4096 keygen `cargo slow` exists for).
fn localhost_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

/// @requirement TB-242
#[test]
fn acceptor_from_pem_rejects_garbage_fullchain_or_privkey() {
    let (_, key) = localhost_cert();
    assert!(ssl::acceptor_from_pem(b"not a certificate", &key).is_err());
    let (chain, _) = localhost_cert();
    assert!(ssl::acceptor_from_pem(&chain, b"not a key").is_err());
    assert!(ssl::acceptor_from_pem(b"", b"").is_err());
}

/// @requirement TB-242
#[test]
fn acceptor_from_pem_accepts_a_matching_certificate_and_key() {
    let (chain, key) = localhost_cert();
    assert!(ssl::acceptor_from_pem(&chain, &key).is_ok());
}

/// `load_acceptor` is `acceptor_from_pem` plus reading the two files named
/// by `server_ssl_fullchain`/`server_ssl_privkey` - a missing file is an
/// error naming the path, never a silent fallback to plaintext.
/// @requirement AC-262
#[test]
fn load_acceptor_reports_which_file_is_missing() {
    let dir = std::env::temp_dir().join(format!(
        "aloo-ssl-test-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let files = ssl::SslFiles {
        fullchain: dir.join("fullchain.pem"),
        privkey: dir.join("privkey.pem"),
    };
    let Err(err) = ssl::load_acceptor(&files) else {
        panic!("a missing certificate pair must not load");
    };
    assert!(err.contains("fullchain.pem"), "{err}");

    let (chain, _) = localhost_cert();
    std::fs::write(&files.fullchain, &chain).unwrap();
    let Err(err) = ssl::load_acceptor(&files) else {
        panic!("a missing key must not load");
    };
    assert!(err.contains("privkey.pem"), "{err}");
}

/// `server_ssl` off means `SslFiles::from_settings` is `None` regardless
/// of what the path fields say - the switch, not the paths, decides.
/// @requirement AC-262
#[test]
fn ssl_files_from_settings_is_none_unless_server_ssl_is_on() {
    let mut settings = aloo::settings::Settings::default();
    assert!(ssl::SslFiles::from_settings(&settings).is_none());
    settings.server_ssl = true;
    settings.server_ssl_fullchain = "~/certs/fullchain.pem".into();
    settings.server_ssl_privkey = "~/certs/privkey.pem".into();
    let files = ssl::SslFiles::from_settings(&settings).unwrap();
    assert!(!files.fullchain.starts_with("~"), "the ~ is expanded: {files:?}");
}

/// `connector_from_roots` needs a real, parsable certificate to add - a
/// file that isn't PEM at all is refused rather than silently trusting
/// only the public roots.
/// @requirement AC-263
#[test]
fn connector_from_roots_rejects_an_unparsable_extra_ca_file() {
    assert!(ssl::connector_from_roots(None).is_ok(), "no extra roots is the plain case");
    assert!(ssl::connector_from_roots(Some(b"not a certificate")).is_err());
    let (chain, _) = localhost_cert();
    assert!(ssl::connector_from_roots(Some(&chain)).is_ok());
}

/// A hostname a certificate could be issued for parses; a value that
/// cannot even be a `ServerName` (empty) is refused up front rather than
/// failing deep inside the handshake with a confusing error.
/// @requirement AC-263
#[test]
fn server_name_accepts_a_hostname_and_an_ip_and_refuses_the_empty_string() {
    assert!(ssl::server_name("chat.example.com").is_ok());
    assert!(ssl::server_name("127.0.0.1").is_ok());
    assert!(ssl::server_name("").is_err());
}

/// The end-to-end proof: a real TLS handshake over loopback, client and
/// server both going through `ssl::accept`/`ssl::connect`, with the
/// generated certificate's own root trusted as the client's only one -
/// what makes this a positive test rather than one that merely exercises
/// error paths.
/// @requirement AC-262, AC-128
#[tokio::test]
async fn a_real_tls_handshake_carries_bytes_both_ways() {
    let (chain, key) = localhost_cert();
    let acceptor = ssl::acceptor_from_pem(&chain, &key).unwrap();
    let connector = ssl::connector_from_roots(Some(&chain)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = ssl::accept(Some(&acceptor), tcp).await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        stream.write_all(b"world").await.unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut stream = ssl::connect(Some(&connector), "localhost", tcp).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");

    server.await.unwrap();
}

/// A client that does not trust the server's (self-signed) certificate
/// refuses the handshake outright - proving `ssl::connect` actually
/// verifies rather than accepting anything with a matching name.
/// @requirement AC-262
#[tokio::test]
async fn a_client_with_the_wrong_trust_root_refuses_the_handshake() {
    let (chain, key) = localhost_cert();
    let acceptor = ssl::acceptor_from_pem(&chain, &key).unwrap();
    // A connector with no extra roots at all - only the public webpki
    // roots, none of which vouch for a self-signed certificate.
    let connector = ssl::connector_from_roots(None).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // The server side may or may not complete depending on how far
        // the client got before aborting; either outcome is fine here.
        let _ = ssl::accept(Some(&acceptor), tcp).await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let result = ssl::connect(Some(&connector), "localhost", tcp).await;
    assert!(result.is_err(), "an untrusted certificate must not be accepted");
    let _ = server.await;
}
