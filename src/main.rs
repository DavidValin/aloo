//! CLI entry point: acts as the client (terminal UI) by default, or as the
//! server when run with `--server`.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use aloo::client::connect;
use aloo::client::global_ptt;
use aloo::client::tui::terminal;
use aloo::crypto;
use aloo::server::{self, AuthConfig};
use aloo::settings;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(
    name = "aloo",
    about = "Terminal chat with encrypted text/voice channels"
)]
struct Cli {
    /// Run as the server instead of the client.
    #[arg(long)]
    server: bool,

    /// Port to bind (server) / default-fill in the connect popup (client).
    /// Defaults to 7878 - server mode falls back to whatever
    /// `~/.aloo/settings` last recorded if this flag is omitted.
    #[arg(long)]
    port: Option<u16>,

    /// Server-only: address to bind to. Defaults to 0.0.0.0 - falls back to
    /// whatever `~/.aloo/settings` last recorded if this flag is omitted.
    #[arg(long)]
    bind: Option<String>,

    /// Server-only auth: `--enc rsa <keyfile>` requires clients to prove
    /// they hold the matching public key.
    #[arg(long, num_args = 2, value_names = ["TYPE", "FILE"])]
    enc: Option<Vec<String>>,

    /// Server-only auth: a single shared password every client must send.
    #[arg(long)]
    password: Option<String>,

    /// Generate a fresh PQ-hybrid (`my_key` type `pq_hybrid`) keybundle and
    /// exit - writes `<PREFIX>` (private) and `<PREFIX>.pub` (public),
    /// mirroring `openssl genpkey ... -out my_key` / `my_key.pub` for `rsa`
    /// keys (see README "Generating PQ-hybrid keys"). There is no
    /// `openssl`-equivalent for ML-DSA-87/ML-KEM-1024, hence this flag.
    #[arg(long, value_name = "PREFIX")]
    keygen_pq_hybrid: Option<String>,
}

/// Not `#[tokio::main]`: on macOS, delivering the global push-to-talk
/// shortcut (`crate::client::global_ptt`) needs the process's *real* OS main
/// thread free to pump a `CFRunLoop` - something `#[tokio::main]` would
/// immediately claim for its own `block_on`. Every other path
/// (`--server`, `--keygen-pq-hybrid`, and the client on Windows/Linux)
/// builds its own runtime and behaves exactly as it did before; see
/// `run_client_entry`/`run_client_macos` for the one case that differs.
fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    if let Some(prefix) = &cli.keygen_pq_hybrid {
        return run_keygen_pq_hybrid(prefix);
    }
    if cli.server {
        return build_runtime()?.block_on(run_server(cli));
    }
    run_client_entry(cli)
}

/// A full multi-thread runtime with all drivers enabled - the same flavor
/// `#[tokio::main]` builds by default (this crate's `tokio` dependency
/// already has the `full` feature on), just constructed explicitly so
/// `main` can choose *which* thread runs it.
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

/// Loads `~/.aloo/settings` (creating it with defaults on first run - see
/// `settings::Settings::load_or_create`); a read/parse failure other than
/// "missing" falls back to in-memory defaults rather than refusing to
/// start the app over an optional preferences file.
fn load_settings() -> settings::Settings {
    match settings::Settings::load_or_create(&settings::default_path()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("aloo: could not read/create ~/.aloo/settings ({e}); using defaults");
            settings::Settings::default()
        }
    }
}

/// Client entry point, platform-dispatching only where it has to
/// (`run_client_macos` - see its doc comment). Everywhere else this is
/// exactly what `#[tokio::main]` used to do: build a runtime, block on
/// `run_client`.
fn run_client_entry(cli: Cli) -> Result<(), BoxError> {
    let settings = load_settings();
    let hotkey = global_ptt::hotkey_to_register(&settings);

    #[cfg(target_os = "macos")]
    return run_client_macos(cli, hotkey);

    #[cfg(not(target_os = "macos"))]
    {
        let hotkey_rx = hotkey.and_then(global_ptt::spawn);
        build_runtime()?.block_on(run_client(cli, hotkey_rx))
    }
}

/// macOS-only: Carbon's `RegisterEventHotKey` (what `global_ptt` uses
/// under the hood) only delivers events via the process's real main
/// thread's `CFRunLoop` - see `global_ptt`'s module docs. So on this OS
/// alone, the roles are swapped from every other platform: the actual
/// `main()` thread stays free to register the hotkey and pump that run
/// loop, while the entire client (`run_client`, under its own `tokio`
/// runtime) moves to a spawned thread instead. `run_client` itself is
/// identical either way - it has no idea which thread produced its
/// `hotkey_rx`.
#[cfg(target_os = "macos")]
fn run_client_macos(cli: Cli, hotkey: Option<global_hotkey::hotkey::HotKey>) -> Result<(), BoxError> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (manager, hotkey_rx) = match hotkey.and_then(global_ptt::register_on_current_thread) {
        Some((manager, rx)) => (Some(manager), Some(rx)),
        None => (None, None),
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_for_client = shutdown.clone();
    let handle = std::thread::spawn(move || -> Result<(), BoxError> {
        // The closure boundary guarantees `shutdown` is set on every exit
        // path (including `build_runtime()` itself failing), so the main
        // thread's pump loop below can never be left waiting forever.
        let result = (|| -> Result<(), BoxError> {
            let rt = build_runtime()?;
            rt.block_on(run_client(cli, hotkey_rx))
        })();
        shutdown_for_client.store(true, Ordering::Relaxed);
        result
    });

    // Harmless to keep pumping even if `manager` is `None` (disabled, or
    // registration failed above) - there's simply nothing registered for
    // it to deliver, and this is still what waits for the client thread.
    global_ptt::pump_main_thread(&shutdown);

    let result = match handle.join() {
        Ok(result) => result,
        Err(_) => Err("aloo: client thread panicked".into()),
    };
    // Keeps the hotkey registered for the whole run above - `manager`'s
    // `Drop` unregisters it, so it must outlive the pump loop.
    drop(manager);
    result
}

// ---------------------------------------------------------------------
// PQ-hybrid keygen
// ---------------------------------------------------------------------

fn run_keygen_pq_hybrid(prefix: &str) -> Result<(), BoxError> {
    println!("aloo: generating a PQ-hybrid keybundle (ML-DSA-87 + ML-KEM-1024 + 2x RSA-4096)...");
    println!("this involves real 4096-bit RSA keygen twice and can take a while.");
    let (public, private) = crypto::pq::generate_bundle()?;

    let priv_path = PathBuf::from(prefix);
    let pub_path = PathBuf::from(format!("{prefix}.pub"));
    crypto::pq::save_private_bundle(&private, &priv_path)?;
    crypto::pq::save_public_bundle(&public, &pub_path)?;

    println!(
        "wrote {} (private, keep this secret) and {} (public)",
        priv_path.display(),
        pub_path.display()
    );
    println!(
        "in the connect popup, set my_key type to pq_hybrid and point file_priv/file_pub at these two files."
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------

/// Resolves bind/port/auth CLI-flag-first, falling back to whatever
/// `~/.aloo/settings` last recorded for any flag not given this run, then
/// re-saves the merged result before starting - so a flag actually passed
/// this run becomes what the next flag-less run (e.g. a supervisor
/// restarting the server after a crash) inherits.
async fn run_server(cli: Cli) -> Result<(), BoxError> {
    let mut settings = load_settings();
    let bind = cli
        .bind
        .clone()
        .unwrap_or_else(|| settings.server_bind.clone());
    let port = cli.port.unwrap_or(settings.server_port);

    let auth = match (&cli.enc, &cli.password) {
        (Some(v), None) if v[0] == "rsa" => {
            let keyfile = PathBuf::from(&v[1]);
            let key = crypto::load_private_key(&keyfile)?;
            settings.server_auth = settings::ServerAuth::Rsa(keyfile);
            AuthConfig::Rsa(Box::new(key))
        }
        (Some(v), None) => return Err(format!("unsupported --enc type: {}", v[0]).into()),
        (None, Some(pw)) => {
            settings.server_auth = settings::ServerAuth::Password(pw.clone());
            AuthConfig::Password(pw.clone())
        }
        (None, None) => match settings.server_auth.clone() {
            settings::ServerAuth::None => AuthConfig::None,
            settings::ServerAuth::Password(pw) => AuthConfig::Password(pw),
            settings::ServerAuth::Rsa(keyfile) => {
                AuthConfig::Rsa(Box::new(crypto::load_private_key(&keyfile)?))
            }
        },
        (Some(_), Some(_)) => return Err("--enc and --password are mutually exclusive".into()),
    };

    settings.server_bind = bind.clone();
    settings.server_port = port;
    if let Err(e) = settings.save(&settings::default_path()) {
        eprintln!("aloo: could not persist server settings to ~/.aloo/settings ({e})");
    }

    let addr: SocketAddr = format!("{bind}:{port}").parse()?;
    println!("aloo: server listening on {addr}");
    server::run(addr, auth).await?;
    Ok(())
}

// ---------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------

async fn run_client(
    cli: Cli,
    hotkey_rx: Option<tokio::sync::mpsc::UnboundedReceiver<global_ptt::GlobalPttEvent>>,
) -> Result<(), BoxError> {
    let (mut term, keyboard_release_reporting) = terminal::setup()?;
    let port = cli.port.unwrap_or(settings::DEFAULT_PORT);
    let result =
        connect::run_client_inner(&mut term, port, keyboard_release_reporting, hotkey_rx).await;
    terminal::restore(&mut term)?;
    result
}
