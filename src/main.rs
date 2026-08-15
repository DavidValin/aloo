//! CLI entry point: acts as the client (terminal UI) by default, or as the
//! server when run with `--server`.

use std::io::Stdout;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::event::{KeyboardEnhancementFlags, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use aloo::connect;
use aloo::crypto;
use aloo::server::{self, AuthConfig};

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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    if let Some(prefix) = &cli.keygen_pq_hybrid {
        return run_keygen_pq_hybrid(prefix);
    }
    if cli.server {
        run_server(cli).await
    } else {
        run_client(cli).await
    }
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

async fn run_client(cli: Cli) -> Result<(), BoxError> {
    let (mut terminal, keyboard_release_reporting) = setup_terminal()?;
    let result = connect::run_client_inner(&mut terminal, cli.port, keyboard_release_reporting).await;
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
