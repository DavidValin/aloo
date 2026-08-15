//! CLI entry point: acts as the client (terminal UI) by default, or as the
//! server when run with `--server`.

use std::io::Stdout;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::event::{KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags};
use global_hotkey::hotkey::HotKey;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use aloo::connect;
use aloo::crypto;
use aloo::global_ptt;
use aloo::server::{self, AuthConfig};
use aloo::settings;

type BoxError = Box<dyn std::error::Error>;

#[derive(Parser, Debug)]
#[command(name = "aloo", about = "Terminal chat with encrypted text/voice channels")]
struct Cli {
    /// Run as the server instead of the client.
    #[arg(long)]
    server: bool,

    /// Port to bind (server) / default-fill in the connect popup (client).
    #[arg(long, default_value_t = 7878)]
    port: u16,

    /// Server-only: address to bind to.
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

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
/// shortcut (`crate::global_ptt`) needs the process's *real* OS main
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
    tokio::runtime::Builder::new_multi_thread().enable_all().build()
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

/// The hotkey to register for global push-to-talk, or `None` if it
/// shouldn't be registered at all this run - either the user turned it off
/// (`global_ptt_enabled = false`) or (Linux only) this session is running
/// under Wayland, which `global_hotkey` has no backend for at all
/// (`global_ptt::is_wayland`). Printed once at startup in the Wayland
/// case per the user's own choice: warn, don't retry, don't crash - Space
/// still works normally while the app is focused either way.
fn hotkey_to_register(settings: &settings::Settings) -> Option<HotKey> {
    if !settings.global_ptt_enabled {
        return None;
    }
    if global_ptt::is_wayland() {
        eprintln!(
            "aloo: global push-to-talk ({}) needs X11 and isn't available under Wayland - Space still works while aloo is focused",
            settings.global_ptt_shortcut
        );
        return None;
    }
    Some(global_ptt::resolve_hotkey(&settings.global_ptt_shortcut))
}

/// Client entry point, platform-dispatching only where it has to
/// (`run_client_macos` - see its doc comment). Everywhere else this is
/// exactly what `#[tokio::main]` used to do: build a runtime, block on
/// `run_client`.
fn run_client_entry(cli: Cli) -> Result<(), BoxError> {
    let settings = load_settings();
    let hotkey = hotkey_to_register(&settings);

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
fn run_client_macos(cli: Cli, hotkey: Option<HotKey>) -> Result<(), BoxError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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

    println!("wrote {} (private, keep this secret) and {} (public)", priv_path.display(), pub_path.display());
    println!(
        "in the connect popup, set my_key type to pq_hybrid and point file_priv/file_pub at these two files."
    );
    Ok(())
}

// ---------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------

async fn run_server(cli: Cli) -> Result<(), BoxError> {
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;
    let auth = match (&cli.enc, &cli.password) {
        (Some(v), None) if v[0] == "rsa" => {
            let key = crypto::load_private_key(&PathBuf::from(&v[1]))?;
            AuthConfig::Rsa(Box::new(key))
        }
        (Some(v), None) => return Err(format!("unsupported --enc type: {}", v[0]).into()),
        (None, Some(pw)) => AuthConfig::Password(pw.clone()),
        (None, None) => AuthConfig::None,
        (Some(_), Some(_)) => return Err("--enc and --password are mutually exclusive".into()),
    };
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
    let (mut terminal, keyboard_release_reporting) = setup_terminal()?;
    let result = connect::run_client_inner(&mut terminal, cli.port, keyboard_release_reporting, hotkey_rx).await;
    restore_terminal(&mut terminal)?;
    result
}

/// Besides the terminal itself, returns whether this terminal actually
/// reports real key releases (Kitty keyboard protocol), queried directly
/// rather than just assumed from the `Push`/`PopKeyboardEnhancementFlags`
/// calls succeeding - a terminal can accept those escape sequences without
/// honoring them, and `UiState::tick_recording_timeout` needs a trustworthy
/// answer to know whether it's ever allowed to auto-stop a recording on
/// its own instead of waiting for a genuine release.
fn setup_terminal() -> Result<(Terminal<CrosstermBackend<Stdout>>, bool), BoxError> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)?;
    let keyboard_release_reporting = crossterm::terminal::supports_keyboard_enhancement().unwrap_or(false);
    if keyboard_release_reporting {
        crossterm::execute!(
            stdout,
            PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::REPORT_EVENT_TYPES)
        )?;
    }
    let backend = CrosstermBackend::new(stdout);
    Ok((Terminal::new(backend)?, keyboard_release_reporting))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<(), BoxError> {
    let _ = crossterm::execute!(terminal.backend_mut(), PopKeyboardEnhancementFlags);
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    disable_raw_mode()?;
    terminal.show_cursor()?;
    Ok(())
}
