//! CLI entry point: acts as the client (terminal UI) by default, or as the
//! server when run with `--server`.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use clap::builder::styling::{AnsiColor, Styles};

use aloo::client::connect;
use aloo::client::daemon;
use aloo::client::global_ptt;
use aloo::client::tui::terminal;
use aloo::crypto;
use aloo::server::{self, ServerOptions};
use aloo::settings;
use aloo::validation;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Where `global_ptt` delivers presses of the global push-to-talk
/// shortcut - `None` wherever the shortcut isn't running (turned off,
/// Wayland, or registration lost the combo to someone else).
type HotkeyReceiver = tokio::sync::mpsc::UnboundedReceiver<global_ptt::GlobalPttEvent>;

/// Clap's own defaults, with flag/parameter names (`--port`, and the
/// `<PORT>` placeholder that goes with it) in yellow rather than plain bold.
const HELP_STYLES: Styles = Styles::styled()
    .literal(AnsiColor::Yellow.on_default().bold())
    .placeholder(AnsiColor::Yellow.on_default());

#[derive(Parser, Debug)]
#[command(
    name = "aloo",
    about = concat!(
        "aloo v",
        env!("CARGO_PKG_VERSION"),
        " - Terminal chat with encrypted text/voice channels."
    ),
    styles = HELP_STYLES
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

    /// Server-only: address to bind to, IPv4 or IPv6 (e.g. 0.0.0.0, ::, or
    /// one interface's own address). Defaults to 0.0.0.0, which serves IPv4
    /// only - use :: to serve both families where the OS allows it. Falls
    /// back to whatever `~/.aloo/settings` last recorded if this flag is
    /// omitted. Both the TCP control port and the UDP rendezvous port that
    /// direct peer-to-peer punching needs are bound here, so a family left
    /// out here is a family that cannot punch.
    #[arg(long)]
    bind: Option<String>,

    /// Server-side registry: create an account that can log in right
    /// away - no email, no activation. Edits ~/.aloo/users directly, so
    /// run it on the server's machine; a running server sees it on the
    /// next login.
    #[arg(long, value_names = ["NICKNAME", "PASSWORD"], num_args = 2)]
    register_user: Option<Vec<String>>,

    /// Server-side registry: set a registered nickname's password. Takes
    /// effect on that nickname's next login; sends no email.
    #[arg(long, value_names = ["NICKNAME", "PASSWORD"], num_args = 2)]
    change_password: Option<Vec<String>>,

    /// Generate a fresh PQ-hybrid (`my_key` type `pq_hybrid`) keybundle and
    /// exit - writes `<PREFIX>` (private) and `<PREFIX>.pub` (public),
    /// mirroring `openssl genpkey ... -out my_key` / `my_key.pub` for `rsa`
    /// keys (see README "Generating PQ-hybrid keys"). There is no
    /// `openssl`-equivalent for ML-DSA-87/ML-KEM-1024, hence this flag.
    #[arg(long, value_name = "PREFIX")]
    keygen_pq_hybrid: Option<String>,

    /// Retire an existing PQ-hybrid keybundle for a fresh one, carrying a
    /// continuity certificate signed by the old keys - so contacts who
    /// already pinned you move their pin across silently instead of being
    /// asked whether you might be an impostor. Takes the old prefix and the
    /// new one. Keep the old files until your contacts have reconnected.
    #[arg(long, value_names = ["OLD_PREFIX", "NEW_PREFIX"], num_args = 2)]
    rekey_pq_hybrid: Option<Vec<String>>,

    /// Run in the background, connected, so the global push-to-talk
    /// shortcut works without aloo being open. Joins only the channels
    /// given with `--channels` (never `the-hall` unless you name it) and
    /// puts the focus where `--initial-focus` says, so a held shortcut goes
    /// straight there. Type `aloo` in any terminal to take the session
    /// over, `/daemon` to hand it back.
    #[arg(long)]
    daemon: bool,

    /// Daemon-only: stay in the foreground instead of re-launching
    /// detached. What a service manager wants (systemd `Type=simple`),
    /// since it does its own supervising.
    #[arg(long)]
    foreground: bool,

    /// Print whether a daemon is running, and exit.
    #[arg(long)]
    daemon_status: bool,

    /// Ask a running daemon to shut down, and exit.
    #[arg(long)]
    daemon_stop: bool,

    /// Run with no server at all: reachable only by the direct_punch_to
    /// peers in ~/.aloo/settings. Anything needing a server is refused,
    /// by name, when asked for.
    #[arg(long)]
    no_server: bool,

    /// Start a fresh session even if a daemon is running, instead of
    /// attaching to it.
    #[arg(long)]
    no_attach: bool,

    /// Daemon/client: the server to connect to. Defaults to whatever was
    /// last connected to (`~/.aloo/.cache`).
    #[arg(long)]
    host: Option<String>,

    /// Daemon-only: the nickname to connect as. Defaults to $USER.
    #[arg(long)]
    nick: Option<String>,

    /// Daemon-only: the password the nickname logs in with. Remembered in
    /// ~/.aloo/settings (daemon_server_password) for the next bare
    /// `aloo --daemon`.
    #[arg(long)]
    server_pwd: Option<String>,

    /// Daemon-only: connect over TLS, for a server running with
    /// server_ssl=on. Remembered as daemon_ssl.
    #[arg(long)]
    ssl: bool,

    /// Daemon-only: the `pq_hybrid` keybundle prefix to connect with -
    /// `<PREFIX>` and `<PREFIX>.pub`. Generated on first use if missing.
    #[arg(long, value_name = "PREFIX")]
    my_key: Option<String>,

    /// Daemon-only: the channels to join, comma separated, each
    /// optionally with its password after a colon -
    /// `--channels=team,ops:hunter2`. A colon is legal in neither a
    /// channel name nor a password, which is what keeps it unambiguous;
    /// a password containing a comma can only be set in
    /// `~/.aloo/settings`, where each channel has a line of its own.
    #[arg(long, value_name = "NAME[:PASSWORD],...")]
    channels: Vec<String>,

    /// Daemon-only: where a held push-to-talk shortcut sends its voice, the
    /// first time it opens. `channel:<name>` for a channel, or a bare
    /// nickname for a DM, which opens as soon as that person appears. Only
    /// places it once, at startup - not a standing instruction that keeps
    /// steering focus afterward.
    #[arg(long, value_name = "TARGET")]
    initial_focus: Option<String>,

    /// Daemon-only: with a nickname `--initial-focus`, make sure an OTP
    /// session is running with them. One that is already active - they
    /// survive disconnects and restarts, only `/endotp` ends one - is simply
    /// continued, with no invitation sent and no popup on their side; only
    /// a peer with no live session is invited, once.
    #[arg(long)]
    otp: bool,

    /// Write an identity card for a PQ-hybrid keybundle: a small signed
    /// file pairing your nickname with your identity, shareable by any
    /// means. Whoever imports it has you pinned and verified before you
    /// ever speak. Takes the keybundle prefix and the nickname.
    #[arg(long, value_names = ["PREFIX", "NICKNAME"], num_args = 2)]
    export_identity_card: Option<Vec<String>>,
}

/// Not `#[tokio::main]`: on macOS, delivering the global push-to-talk
/// shortcut (`crate::client::global_ptt`) needs the process's *real* OS main
/// thread free to pump a `CFRunLoop` - something `#[tokio::main]` would
/// immediately claim for its own `block_on`. Every other path
/// (`--server`, `--keygen-pq-hybrid`, and the client or daemon on
/// Windows/Linux) simply builds its own runtime here; see
/// `with_global_ptt` for the one case that differs.
fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    if let Some(prefix) = &cli.keygen_pq_hybrid {
        return run_keygen_pq_hybrid(prefix);
    }
    if let Some(args) = &cli.rekey_pq_hybrid {
        return run_rekey_pq_hybrid(&args[0], &args[1]);
    }
    if let Some(args) = &cli.export_identity_card {
        return run_export_identity_card(&args[0], &args[1]);
    }
    if let Some(args) = &cli.register_user {
        return run_register_user(&args[0], &args[1]);
    }
    if let Some(args) = &cli.change_password {
        return run_change_password(&args[0], &args[1]);
    }
    if cli.server {
        return build_runtime()?.block_on(run_server(cli));
    }
    if cli.daemon_status || cli.daemon_stop {
        return build_runtime()?.block_on(run_daemon_control(&cli));
    }
    if cli.daemon {
        return run_daemon_entry(cli);
    }
    run_client_entry(cli)
}

// ---------------------------------------------------------------------
// Daemon mode
// ---------------------------------------------------------------------

/// `--daemon-status` / `--daemon-stop`: one message to a running daemon.
async fn run_daemon_control(cli: &Cli) -> Result<(), BoxError> {
    use aloo::client::daemon_ipc::AttachMessage;
    let socket = aloo::client::daemon_ipc::socket_path();
    let message = if cli.daemon_stop {
        AttachMessage::Shutdown
    } else {
        AttachMessage::Status
    };
    match daemon::send_control(&socket, message).await {
        Ok(()) => Ok(()),
        Err(e) if cli.daemon_status => {
            // "No daemon" is the answer to a status question, not a
            // failure of it.
            println!("aloo: {e}");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// `--daemon`: background this process unless told to stay, then run.
///
/// The re-exec happens *before* any runtime, thread or audio device is
/// touched, so the child starts clean - see `daemon::spawn_detached` for
/// why that matters more than it might look.
fn run_daemon_entry(cli: Cli) -> Result<(), BoxError> {
    if !cli.foreground && !daemon::is_daemon_child() {
        let log = aloo::client::daemon_ipc::log_path();
        let pid = daemon::spawn_detached(&log)?;
        println!("aloo: daemon started (pid {pid}), logging to {}", log.display());
        println!("aloo: type 'aloo' in any terminal to attach, /daemon to hand it back");
        return Ok(());
    }

    let config = match resolve_daemon_config(&cli) {
        Ok(config) => config,
        Err(e) => {
            daemon::report_startup_failure(&e);
            return Err(e.into());
        }
    };

    // The hotkey has to be registered from the process's real main thread
    // on macOS, exactly as it does for a foreground client - so the daemon
    // reuses the same split rather than inventing a second one.
    let hotkey = global_ptt::hotkey_to_register(&load_settings());
    with_global_ptt(hotkey, move |hotkey_rx| {
        match build_runtime()?.block_on(daemon::run(config, hotkey_rx)) {
            Ok(()) => Ok(()),
            Err(e) => {
                daemon::report_startup_failure(&e);
                Err(e)
            }
        }
    })
}

fn resolve_daemon_config(cli: &Cli) -> Result<aloo::client::daemon::DaemonConfig, String> {
    if let Some(nick) = &cli.nick
        && !validation::nickname_is_registrable(nick)
    {
        return Err(format!(
            "not a valid nickname: {nick:?} - use 1-{} letters, digits, '-' or '_'",
            validation::NICKNAME_MAX_LEN
        ));
    }
    let settings = load_settings();
    let cache = aloo::client::connect::ConnectCache::load(&aloo::client::connect::cache_path())
        .unwrap_or_else(|_| {
            aloo::client::connect::ConnectCache::new_empty(aloo::client::connect::cache_path())
        });
    let flags = aloo::client::daemon::DaemonFlags {
        host: cli.host.clone(),
        port: cli.port,
        nickname: cli.nick.clone(),
        server_pwd: cli.server_pwd.clone(),
        ssl: cli.ssl,
        my_key_prefix: cli.my_key.clone(),
        channels: cli.channels.clone(),
        initial_focus: cli.initial_focus.clone(),
        no_server: cli.no_server,
        otp: cli.otp,
    };
    aloo::client::daemon::DaemonConfig::resolve(&flags, &settings, &cache)
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
            aloo::log_warn!("could not read/create ~/.aloo/settings ({e}); using defaults");
            settings::Settings::default()
        }
    }
}

/// Client entry point. Off macOS `with_global_ptt` adds nothing, so this
/// is exactly what `#[tokio::main]` used to do: build a runtime, block on
/// `run_client`.
fn run_client_entry(cli: Cli) -> Result<(), BoxError> {
    // A running daemon owns this machine's session. Taking it over is what
    // a bare `aloo` means once one exists - connecting a *second* client
    // under the same nickname would be refused by the server anyway
    // (nicknames are unique among connected clients, §5.4), so the choice
    // is between resuming and a confusing error. `--no-attach` is the way
    // to genuinely want a second, separate session.
    if !cli.no_attach {
        let socket = aloo::client::daemon_ipc::socket_path();
        let runtime = build_runtime()?;
        if runtime.block_on(aloo::client::daemon_ipc::is_daemon_running(&socket)) {
            return runtime.block_on(daemon::run_attach_client(&socket));
        }
    }

    let hotkey = global_ptt::hotkey_to_register(&load_settings());
    with_global_ptt(hotkey, move |hotkey_rx| {
        build_runtime()?.block_on(run_client(cli, hotkey_rx))
    })
}

/// Registers the global push-to-talk shortcut, then runs `body` with the
/// channel it delivers on - the one piece of the client and the daemon
/// that has to know which OS it's on.
///
/// Everywhere but macOS there is nothing to arrange: `global_ptt::spawn`
/// owns the hotkey on a thread of its own, so `body` simply runs here.
#[cfg(not(target_os = "macos"))]
fn with_global_ptt<F>(
    hotkey: Option<global_hotkey::hotkey::HotKey>,
    body: F,
) -> Result<(), BoxError>
where
    F: FnOnce(Option<HotkeyReceiver>) -> Result<(), BoxError> + Send + 'static,
{
    body(hotkey.and_then(global_ptt::spawn))
}

/// macOS-only: Carbon's `RegisterEventHotKey` (what `global_ptt` uses)
/// only delivers events via the real main thread's `CFRunLoop`, so on
/// this OS alone the roles are swapped: `main()` stays behind to register
/// the hotkey and pump that run loop while all of `body` - client or
/// daemon, runtime included - runs on a spawned thread. What `body` does
/// is identical either way.
#[cfg(target_os = "macos")]
fn with_global_ptt<F>(
    hotkey: Option<global_hotkey::hotkey::HotKey>,
    body: F,
) -> Result<(), BoxError>
where
    F: FnOnce(Option<HotkeyReceiver>) -> Result<(), BoxError> + Send + 'static,
{
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let (manager, hotkey_rx) = match hotkey.and_then(global_ptt::register_on_current_thread) {
        Some((manager, rx)) => (Some(manager), Some(rx)),
        None => (None, None),
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_for_body = shutdown.clone();
    let handle = std::thread::spawn(move || -> Result<(), BoxError> {
        // `shutdown` is set on every exit path of `body` (including the
        // runtime it builds failing to start), so the main thread's pump
        // loop below can never be left waiting forever.
        let result = body(hotkey_rx);
        shutdown_for_body.store(true, Ordering::Relaxed);
        result
    });

    // Harmless to keep pumping even if `manager` is `None` (disabled, or
    // registration failed above) - there's simply nothing registered for
    // it to deliver, and this is still what waits for the spawned thread.
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

/// Generates a replacement keybundle that can prove it succeeded the old
/// one. The certificate is signed by the keys being retired, so only
/// someone who actually holds them can produce it - which is exactly what
/// distinguishes a planned key change from someone taking your nickname.
fn run_rekey_pq_hybrid(old_prefix: &str, new_prefix: &str) -> Result<(), BoxError> {
    let old_priv = PathBuf::from(old_prefix);
    let old_pub = PathBuf::from(format!("{old_prefix}.pub"));
    let old_private = crypto::pq::load_private_bundle(&old_priv)?;
    let old_public = crypto::pq::load_public_bundle(&old_pub)?;

    println!("aloo: generating a replacement PQ-hybrid keybundle...");
    println!("this involves real 4096-bit RSA keygen and can take a while.");
    let (new_public, new_private) = crypto::pq::generate_bundle()?;

    let cert = crypto::pq::sign_continuity(&old_private, &old_public, &new_public)?;
    let new_public = new_public.with_continuity(cert);

    let new_priv_path = PathBuf::from(new_prefix);
    let new_pub_path = PathBuf::from(format!("{new_prefix}.pub"));
    crypto::pq::save_private_bundle(&new_private, &new_priv_path)?;
    crypto::pq::save_public_bundle(&new_public, &new_pub_path)?;

    println!(
        "wrote {} (private, keep this secret) and {} (public)",
        new_priv_path.display(),
        new_pub_path.display()
    );
    println!(
        "the new identity carries a certificate signed by the old one, so contacts who already"
    );
    println!(
        "pinned you will move across without being asked. Point the connect popup at the new files."
    );
    Ok(())
}

/// Writes a shareable identity card. Self-signed, which is all it claims:
/// it proves whoever holds these keys asked to be known by this name. What
/// makes it worth anything is the channel you send it over.
fn run_export_identity_card(prefix: &str, nickname: &str) -> Result<(), BoxError> {
    let private = crypto::pq::load_private_bundle(&PathBuf::from(prefix))?;
    let public = crypto::pq::load_public_bundle(&PathBuf::from(format!("{prefix}.pub")))?;

    let card = crypto::pq::make_identity_card(&private, &public, nickname)?;
    let path = PathBuf::from(format!("{nickname}.aloo-card"));
    crypto::pq::save_identity_card(&card, &path)?;

    let fp = crypto::pq::bundle_fingerprint(&public)?;
    println!("wrote {}", path.display());
    println!("safety phrase: {}", crypto::safety::phrase(&fp));
    println!(
        "send this file however you like. Whoever imports it has you pinned and verified"
    );
    println!("before you have ever spoken.");
    Ok(())
}

// ---------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------

/// Resolves bind/port CLI-flag-first, falling back to whatever
/// `~/.aloo/settings` last recorded for any flag not given this run, then
/// re-saves the merged result before starting - so a flag actually passed
/// this run becomes what the next flag-less run (e.g. a supervisor
/// restarting the server after a crash) inherits. Everything else the
/// server runs with - TLS, registration, SMTP, the activation endpoint -
/// is settings-only (docs/SPEC.md "Server startup").
async fn run_server(cli: Cli) -> Result<(), BoxError> {
    let mut settings = load_settings();
    let bind = cli
        .bind
        .clone()
        .unwrap_or_else(|| settings.server_bind.clone());
    let port = cli.port.unwrap_or(settings.server_port);

    settings.server_bind = bind.clone();
    settings.server_port = port;
    if let Err(e) = settings.save(&settings::default_path()) {
        aloo::log_warn!("could not persist server settings to ~/.aloo/settings ({e})");
    }

    let users = server::users_registry::UsersRegistry::open(server::users_registry::default_dir())?;
    let mut options = ServerOptions::new(users.clone());

    // Refusing to start beats serving plaintext behind an operator's back:
    // `server_ssl=on` with no certificate is a misconfiguration, not a
    // preference.
    if let Some(files) = server::ssl::SslFiles::from_settings(&settings) {
        let acceptor = server::ssl::load_acceptor(&files)
            .map_err(|e| format!("server_ssl is on but the certificate cannot be used: {e}"))?;
        options = options.with_tls(acceptor);
        println!("aloo: ssl on ({})", files.fullchain.display());
    }

    if settings.server_allow_registration {
        let smtp = server::users_registry::SmtpConfig::from_settings(&settings);
        if smtp.is_none() {
            aloo::log_warn!(
                "server_allow_registration is on but server_smtp_host/server_smtp_port are not set - registrations will be refused"
            );
        }
        options = options.with_registration(smtp, settings.server_activation_url.clone());

        let activation_addr =
            validation::parse_bind_addr(&bind, settings.server_activation_port)?;
        let listener = tokio::net::TcpListener::bind(activation_addr).await?;
        let tls = options.tls.clone();
        let registry = std::sync::Arc::new(users);
        tokio::spawn(async move {
            if let Err(e) = server::activation::run(listener, tls, registry).await {
                aloo::log_warn!("activation endpoint stopped: {e}");
            }
        });
        println!(
            "aloo: registration open, activation endpoint on {}{activation_addr}",
            if settings.server_ssl { "https://" } else { "http://" }
        );
        if !settings.server_ssl {
            aloo::log_warn!(
                "the activation endpoint is plain http - set server_ssl=on to serve it over https"
            );
        }
    }

    let addr: SocketAddr = validation::parse_bind_addr(&bind, port)?;
    println!("aloo: server listening on {addr}");
    server::run(addr, options).await?;
    Ok(())
}

/// `--register-user <nickname> <password>`: straight into the registry
/// the server reads from, active immediately.
fn run_register_user(nickname: &str, password: &str) -> Result<(), BoxError> {
    let users = server::users_registry::UsersRegistry::open(server::users_registry::default_dir())?;
    // `main`'s default error printer shows a returned error's `Debug`, not
    // its `Display` - for `RegisterError` that would print the bare enum
    // variant name (`AlreadyRegistered`) instead of the readable message
    // its own `Display` impl gives, so the message is carried through as
    // a `String` instead, whose own `Debug` is just its quoted content.
    users
        .register_manual(nickname, password)
        .map_err(|e| e.to_string())?;
    println!(
        "aloo: registered {nickname} in {} (active, no email)",
        users.dir().display()
    );
    Ok(())
}

/// `--change-password <nickname> <password>`: rewrites the stored key.
/// Effective on the next login, since every login re-reads it.
fn run_change_password(nickname: &str, password: &str) -> Result<(), BoxError> {
    let users = server::users_registry::UsersRegistry::open(server::users_registry::default_dir())?;
    users
        .change_password(nickname, password)
        .map_err(|e| e.to_string())?;
    println!("aloo: password changed for {nickname}");
    Ok(())
}

// ---------------------------------------------------------------------
// Client mode
// ---------------------------------------------------------------------

async fn run_client(
    cli: Cli,
    hotkey_rx: Option<tokio::sync::mpsc::UnboundedReceiver<global_ptt::GlobalPttEvent>>,
) -> Result<(), BoxError> {
    let (mut surface, keyboard_release_reporting) = terminal::setup_surface()?;
    let port = cli.port.unwrap_or(settings::DEFAULT_PORT);
    let result = connect::run_client_inner(
        &mut surface,
        port,
        keyboard_release_reporting,
        hotkey_rx,
        cli.no_server,
    )
    .await;
    terminal::restore_surface(&mut surface)?;
    result
}
