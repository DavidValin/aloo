//! `client::connect::run_with_processing_screen` against the real
//! `connect_with_reconnect`/`register_account` it wraps, over a real
//! loopback socket - the only way to prove the thing it exists for: that
//! neither call actually starves the animation, keygen included. Pure
//! logic (the redraw/sleep race itself, and the spawn_blocking-vs-not
//! distinction it depends on) is covered directly in `connect_test.rs`;
//! this file is the live-socket half `docs/TESTING.md`'s exception list
//! keeps out of that one.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use aloo::client::connect::{
    ConnectRequest, MyKeySelection, RegisterRequest, connect_with_reconnect, register_account,
    run_with_processing_screen,
};
use aloo::client::tui::surface::Surface;

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aloo-connect-processing-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Binds a real listener that accepts connections and then says nothing
/// at all - `handshake_as` sits genuinely `.await`-ing `Hello`
/// past that point, which is exactly the kind of wait
/// `run_with_processing_screen` is supposed to animate straight through.
async fn silent_listener() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if let Ok((_stream, _)) = listener.accept().await {
                std::future::pending::<()>().await;
            }
        }
    });
    addr
}

/// Runs `fut` through `run_with_processing_screen` (a `Detached` surface -
/// no terminal needed) for `budget_ms`, racing an independent ticker
/// alongside it. The ticker's own count is the animation's stand-in:
/// healthy and roughly proportional to `budget_ms` means the executor was
/// never starved by `fut`; near zero means something inside it blocked
/// without yielding.
async fn ticks_during<T>(fut: impl std::future::Future<Output = T>, budget_ms: u64) -> u32 {
    let counter = Arc::new(AtomicU32::new(0));
    let c = counter.clone();
    let ticker = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            c.fetch_add(1, Ordering::Relaxed);
        }
    });
    let mut surface = Surface::Detached;
    let run = run_with_processing_screen(&mut surface, fut, "connecting...");
    let _ = tokio::time::timeout(std::time::Duration::from_millis(budget_ms), run).await;
    ticker.abort();
    counter.load(Ordering::Relaxed)
}

/// The exact scenario `resolve_my_keypair`'s `spawn_blocking` fix targets
/// (`resolve_identity`'s own doc): no keybundle on disk yet, so real
/// ML-DSA-87/ML-KEM-1024/RSA-4096 keygen runs mid-connect - several
/// seconds of pure synchronous CPU work. Proves the ticker keeps
/// advancing while that keygen is genuinely still running, not merely
/// once it's finished.
/// @requirement AC-373
#[tokio::test]
async fn connect_with_reconnect_does_not_freeze_the_animation_through_real_keygen() {
    let addr = silent_listener().await;
    let dir = temp_dir("nokeys");
    let my_key = MyKeySelection { file_pub: dir.join("k.pub"), file_priv: dir.join("k") };
    assert!(!my_key.file_pub.exists(), "the whole point is that no keybundle exists yet");
    let request = ConnectRequest {
        host: addr.ip().to_string(),
        port: addr.port(),
        nickname: "diag".to_string(),
        password: "pw".to_string(),
        ssl: false,
        ssl_ca: None,
        my_key,
        activation_code: None,
    };
    let ticks = ticks_during(connect_with_reconnect(&request), 1500).await;
    assert!(
        ticks > 20,
        "expected the animation ticker to keep advancing through real keygen \
         (spawn_blocking should keep it off the connecting task), got {ticks} ticks in 1.5s"
    );
}

/// `register_account` itself needs no keys at all (Register only ever
/// sends nickname/password/email) - this isolates whether its own network
/// code (DNS/TCP, TLS off) behaves like ordinary, non-blocking async I/O.
/// @requirement AC-371
#[tokio::test]
async fn register_account_does_not_freeze_the_animation() {
    let addr = silent_listener().await;
    let request = RegisterRequest {
        host: addr.ip().to_string(),
        port: addr.port(),
        ssl: false,
        ssl_ca: None,
        nickname: "diag".to_string(),
        password: "pw".to_string(),
        email: "diag@example.com".to_string(),
    };
    let ticks = ticks_during(register_account(&request), 800).await;
    assert!(
        ticks > 20,
        "expected the animation ticker to keep advancing during register_account, got {ticks} ticks in 0.8s"
    );
}
