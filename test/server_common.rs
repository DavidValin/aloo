//! Shared scaffolding for every test that runs the real server over a
//! loopback socket (`server_test.rs`, `p2p_test.rs`, `reconnect_test.rs`,
//! `ssl_test.rs`, ...) - included via `#[path = "server_common.rs"] mod
//! server_common;`, the same way `ui_common.rs` is. Not a test target.
//!
//! The server only lets registered nicknames in (docs/PROTOCOL.md §5), so
//! a test server comes with its own scratch users registry under a temp
//! directory, and every nickname a test connects as is registered there
//! first with `password_for(nickname)`. Nothing touches the real
//! `~/.aloo`.

#![allow(dead_code)]

use std::path::PathBuf;

use aloo::control::ControlEndpoint;
use aloo::proto::{ClientMessage, KeyMode, ServerMessage, UserId};
use aloo::server::users_registry::UsersRegistry;
use aloo::server::{ServerOptions, serve, serve_with_rendezvous};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

/// A fresh, unique temp directory for one test's server-side state.
pub fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "aloo-server-test-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The password every test user is registered with: one per nickname, so
/// a test that wants the *wrong* one can use another nickname's.
pub fn password_for(nickname: &str) -> String {
    format!("pw-{nickname}")
}

/// Fast enough that a test suite doing dozens of logins doesn't pay a
/// `dev`-build PBKDF2 tax (`users_registry::USER_KEY_ITERATIONS`'s doc) -
/// still real PBKDF2-HMAC-SHA256, just far fewer rounds of it.
pub const TEST_KEY_ITERATIONS: u32 = 100;

/// A registry at `dir` using `TEST_KEY_ITERATIONS` - what a test opens a
/// *second* handle to a running `TestServer`'s registry with (to register
/// or edit passwords out of band), so both handles derive the same way.
pub fn test_users_registry(dir: impl Into<PathBuf>) -> UsersRegistry {
    UsersRegistry::open_with_iterations(dir, TEST_KEY_ITERATIONS).unwrap()
}

/// Production-shaped options around a scratch registry and a scratch OTP
/// mail directory: no TLS, no registration, the real heartbeat timeout,
/// `TEST_KEY_ITERATIONS` rather than the real (slow-in-`dev`) round count.
pub fn test_options(tag: &str) -> ServerOptions {
    let root = scratch_dir(tag);
    ServerOptions::new(test_users_registry(root.join("users")))
        .with_mail_dir(root.join("server_otp_mail"))
}

/// Registers `nickname` with `password_for(nickname)` if it is not there
/// yet - what lets a test simply name the people it wants connected.
pub fn ensure_user(options: &ServerOptions, nickname: &str) {
    if !options.users.is_registered(nickname) {
        options
            .users
            .register_manual(nickname, &password_for(nickname))
            .unwrap();
    }
}

/// A running server and the registry it reads, so a test can register
/// people and then connect them.
pub struct TestServer {
    pub addr: std::net::SocketAddr,
    pub options: ServerOptions,
}

impl TestServer {
    /// Serves `options` on an ephemeral loopback port, TCP only.
    pub async fn spawn(options: ServerOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = options.clone();
        tokio::spawn(async move {
            let _ = serve(listener, served).await;
        });
        Self { addr, options }
    }

    /// `spawn`, with the UDP rendezvous socket bound alongside - what the
    /// direct-link tests need.
    pub async fn spawn_with_rendezvous(options: ServerOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
        let served = options.clone();
        tokio::spawn(async move {
            let _ = serve_with_rendezvous(listener, udp, served).await;
        });
        Self { addr, options }
    }

    pub fn ensure_user(&self, nickname: &str) {
        ensure_user(&self.options, nickname);
    }

    /// A plain TCP endpoint to this server.
    pub async fn connect(&self) -> ControlEndpoint<tokio::net::TcpStream> {
        ControlEndpoint::new(tokio::net::TcpStream::connect(self.addr).await.unwrap())
    }

    /// Registers `nickname` and runs the whole handshake for it on
    /// `stream`, asserting the documented ordering as it goes.
    pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut ControlEndpoint<S>,
        nickname: &str,
    ) -> UserId {
        self.ensure_user(nickname);
        handshake_with_mode(stream, nickname, &password_for(nickname), KeyMode::PqHybrid).await
    }

    /// `handshake` with an explicit `KeyMode` - the only one there is, but
    /// the tests that pin the mode's wire travel say so explicitly.
    pub async fn handshake_with_mode<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut ControlEndpoint<S>,
        nickname: &str,
        key_mode: KeyMode,
    ) -> UserId {
        self.ensure_user(nickname);
        handshake_with_mode(stream, nickname, &password_for(nickname), key_mode).await
    }
}

/// Brings the sealed channel up and sends `Auth`, returning the server's
/// `AuthResult` - for tests about the answer itself.
pub async fn login<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut ControlEndpoint<S>,
    nickname: &str,
    password: &str,
) -> ServerMessage {
    stream
        .client_handshake()
        .await
        .unwrap()
        .expect("server closed during handshake");
    stream
        .send(&ClientMessage::Auth {
            nickname: nickname.into(),
            password: password.into(),
        })
        .await
        .unwrap();
    stream.recv().await.unwrap().expect("an AuthResult")
}

/// The full documented handshake (docs/PROTOCOL.md §4): `Hello`,
/// `SecureChannel`, `Auth`, `AuthResult { ok: true }`, `Identify`,
/// `IdentifyResult`, then `ChannelList` back to back.
pub async fn handshake_with_mode<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut ControlEndpoint<S>,
    nickname: &str,
    password: &str,
    key_mode: KeyMode,
) -> UserId {
    let result = login(stream, nickname, password).await;
    assert!(
        matches!(result, ServerMessage::AuthResult { ok: true, .. }),
        "auth should succeed for {nickname}, got {result:?}"
    );

    stream
        .send(&ClientMessage::Identify {
            public_key_der: vec![],
            key_mode,
        })
        .await
        .unwrap();

    let identify: ServerMessage = stream.recv().await.unwrap().unwrap();
    let ServerMessage::IdentifyResult {
        ok: true,
        you: Some(you),
        ..
    } = identify
    else {
        panic!("expected a successful IdentifyResult, got {identify:?}");
    };
    let list: ServerMessage = stream.recv().await.unwrap().unwrap();
    assert!(
        matches!(list, ServerMessage::ChannelList { .. }),
        "ChannelList must follow IdentifyResult immediately, got {list:?}"
    );
    you
}
