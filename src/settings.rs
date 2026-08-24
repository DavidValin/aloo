//! A small local preferences store: a flat `key=value` file at
//! `~/.aloo/settings`, same plain-text convention as the other stores
//! rather than a config-format crate for a handful of fields.
//!
//! Holds the global push-to-talk preferences (`crate::client::global_ptt`).
//! Unlike `IdStore` this file is written proactively - `load_or_create`
//! writes the defaults on first run so a user can find and edit the file
//! before ever changing anything.
//!
//! Also holds the serverless direct-punch configuration (`direct_punch`,
//! `direct_punch_port`, and one `direct_punch_to` line per peer) that
//! `crate::client::p2p`'s scheduler runs off, and the optional No-IP
//! dynamic DNS updater alongside it (`noip_when_no_server_and_direct_punch_is_active`,
//! `noip_hostname`, `noip_username`, `noip_password`, `crate::client::noip`)
//! - see `docs/PROTOCOL.md` §7.1.5.
//!
//! Also holds the server's configuration: its last-used `--bind`/`--port`
//! (written every time `--server` starts, so a crashed server relaunched
//! with no flags comes back on the same address), the optional TLS
//! certificate pair (`server_ssl*`, `crate::server::ssl`), whether
//! registrations are taken and the SMTP account the activation emails go
//! out through (`server_allow_registration`, `server_smtp_*`,
//! `crate::server::users_registry`), and where the activation endpoint
//! listens (`server_activation_*`, `crate::server::activation`). The SMTP
//! password and a daemon's login password are persisted as plaintext like
//! every other field - anyone who can read `~/.aloo/settings` already
//! controls this user's account on this machine.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The default global push-to-talk shortcut, in the same syntax
/// `global_hotkey::hotkey::HotKey` parses directly (see
/// `crate::client::global_ptt::resolve_hotkey`).
pub const DEFAULT_GLOBAL_PTT_SHORTCUT: &str = "ctrl+alt+p";

/// The default server bind address and port (`docs/SPEC.md` "Server
/// startup"), also used by the client to prefill the connect popup's port.
pub const DEFAULT_BIND: &str = "0.0.0.0";
pub const DEFAULT_PORT: u16 = 7878;

/// Resolves the settings file path: `~/.aloo/settings`, same home
/// resolution as every other store in this app (`crate::platform`).
pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("settings")
}

/// Where the server's TLS certificate pair is looked for when `server_ssl`
/// is on and the file names it (`docs/SPEC.md` "Server startup"). Written
/// with a literal `~` so the file reads the same on every machine;
/// `crate::platform::expand_tilde` resolves it at load time.
pub const DEFAULT_SERVER_SSL_FULLCHAIN: &str = "~/.aloo/certs/fullchain.pem";
pub const DEFAULT_SERVER_SSL_PRIVKEY: &str = "~/.aloo/certs/privkey.pem";

/// The TCP port the account-activation web endpoint listens on when
/// `server_allow_registration` is on (`crate::server::activation`) - on
/// the same `server_bind` address as the server itself. Its own port
/// because the server's port speaks the framed control protocol and
/// answers with `Hello` before reading a byte, so a browser could never
/// be told apart from a client there.
pub const DEFAULT_SERVER_ACTIVATION_PORT: u16 = 7880;

/// `on`/`true`/`yes`/`1` - the spelling every `on`/`off` setting in this
/// file accepts, so no spelling is a silent no-op.
fn parse_switch(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "on" | "true" | "yes" | "1"
    )
}

fn switch(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// Default size (in megabytes) of a freshly generated OTP keypair
/// (`client::otp::initiate_provisioning`'s `otp --new-key-pair` call).
pub const DEFAULT_OTP_KEYPAIR_SIZE_MB: u32 = 1;
/// Warn once a contact's remaining OTP key drops under this percentage of
/// its original size (`client::otp_cli::status`'s `enc_key_remaining`).
pub const DEFAULT_OTP_LOW_KEY_WARN_PCT: u8 = 10;
/// Poll `otp --status --porcelain` for the low-key warning once every this
/// many OTP send/receive operations, rather than on every single one.
pub const DEFAULT_OTP_STATUS_POLL_INTERVAL: u32 = 20;

/// The UDP port the direct-punch listener binds when `direct_punch=on`.
///
/// Server-coordinated punching (`docs/PROTOCOL.md` §7.1) can use an
/// ephemeral port because the server relays whatever port the socket
/// happened to get. Serverless punching (§7.1.5) has nobody to relay it,
/// so the only thing a peer can address is a port both sides agreed on
/// beforehand - by convention this one, overridable per machine with
/// `direct_punch_port` for anyone who has to NAT-forward a different one.
pub const DEFAULT_DIRECT_PUNCH_PORT: u16 = 7879;

/// How often a `direct_punch_to` target is attempted, in minutes past the
/// hour. Only the values `docs/SPEC.md` "Direct punch settings" lists are
/// representable - the slot grid restarts at every o'clock, and both peers
/// must land on the same grid or their probes never overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PunchFrequency(u32);

/// Every accepted `<frequency>`, in minutes.
pub const PUNCH_FREQUENCIES: [u32; 13] = [1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60];

impl PunchFrequency {
    /// Parses `every_1m`/`every_5m`/.../`every_55m`/`every_1h`. The
    /// `every_` prefix makes a `direct_punch_to` line read unambiguously
    /// at a glance - it is not just a bare number-and-letter that could be
    /// mistaken for a port or something else. `min`/`hour` are accepted
    /// wherever `m`/`h` are (`every_1min` reads more naturally in a
    /// hand-edited file, and the two cannot be confused - there is no unit
    /// here that starts with `m` and isn't minutes).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim().to_ascii_lowercase();
        let err = || {
            format!(
                "not a valid frequency: {s:?} - use one of every_1m, every_5m, every_10m, \
                 every_15m, every_20m, every_25m, every_30m, every_35m, every_40m, every_45m, \
                 every_50m, every_55m, every_1h"
            )
        };
        let Some(rest) = s.strip_prefix("every_") else {
            return Err(err());
        };
        let minutes = if let Some(n) = rest.strip_suffix("min").or_else(|| rest.strip_suffix('m')) {
            n.parse::<u32>().ok()
        } else if let Some(n) = rest.strip_suffix("hour").or_else(|| rest.strip_suffix('h')) {
            n.parse::<u32>().ok().and_then(|h| h.checked_mul(60))
        } else {
            None
        };
        match minutes {
            Some(m) if PUNCH_FREQUENCIES.contains(&m) => Ok(Self(m)),
            _ => Err(err()),
        }
    }

    pub fn minutes(self) -> u32 {
        self.0
    }

    /// How many seconds one slot grid step covers.
    pub fn seconds(self) -> u64 {
        self.0 as u64 * 60
    }

    /// Which slot of the current hour `second_of_hour` falls in. The grid
    /// restarts at every o'clock, which is what makes an interval that does
    /// not divide 60 (`every_55m`) well defined: its slots are :00 and :55, and
    /// the next one after :55 is the *next* hour's :00, not :50 past it.
    pub fn slot_of_hour(self, second_of_hour: u64) -> u64 {
        second_of_hour / self.seconds()
    }
}

impl std::fmt::Display for PunchFrequency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 60 {
            write!(f, "every_1h")
        } else {
            write!(f, "every_{}m", self.0)
        }
    }
}

/// One `direct_punch_to=<nickname>,<host>[:<port>],<frequency>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPunchTarget {
    /// The peer's nickname - the only name a serverless link has, since
    /// there is no server to assign or relay a `UserId` for it.
    pub nickname: String,
    /// A literal IPv4/IPv6 address or a hostname, resolved fresh at every
    /// slot rather than once at startup (a home connection's address moves).
    pub host: String,
    pub port: u16,
    pub frequency: PunchFrequency,
}

impl DirectPunchTarget {
    /// Parses one settings value. The host may carry an explicit port
    /// (`bobpublic.com:9000`, `[2001:db8::1]:9000`); a bare IPv6 literal
    /// needs no brackets precisely because it cannot then also carry one.
    pub fn parse(value: &str) -> Result<Self, String> {
        let parts: Vec<&str> = value.split(',').map(str::trim).collect();
        let [nickname, host, frequency] = parts.as_slice() else {
            return Err(format!(
                "expected <nickname>,<host>,<frequency>, got {value:?}"
            ));
        };
        if nickname.is_empty() || !crate::validation::is_storable(nickname) {
            return Err(format!("not a valid nickname: {nickname:?}"));
        }
        let (host, port) = split_host_port(host)?;
        Ok(Self {
            nickname: (*nickname).to_string(),
            host,
            port,
            frequency: PunchFrequency::parse(frequency)?,
        })
    }

    /// `<nickname>,<host>[:<port>],<frequency>` - the exact spelling
    /// `parse` accepts, so a load/save round trip is lossless.
    pub fn to_setting_value(&self) -> String {
        let host = if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{},{host}:{},{}", self.nickname, self.port, self.frequency)
    }
}

/// Splits `host`, `host:port`, `[v6]` or `[v6]:port` into its two pieces,
/// defaulting the port to `DEFAULT_DIRECT_PUNCH_PORT`, and rejects a host
/// that is neither an IP literal nor a syntactically valid hostname.
fn split_host_port(value: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        // Bracketed IPv6, the one form that can carry a port without the
        // port's colon being ambiguous with the address's own.
        let Some((inside, after)) = rest.split_once(']') else {
            return Err(format!("unterminated '[' in host: {value:?}"));
        };
        let port = match after {
            "" => DEFAULT_DIRECT_PUNCH_PORT,
            p => parse_port(p.strip_prefix(':').unwrap_or(p))?,
        };
        (inside.to_string(), port)
    } else if value.parse::<std::net::Ipv6Addr>().is_ok() {
        (value.to_string(), DEFAULT_DIRECT_PUNCH_PORT)
    } else if let Some((h, p)) = value.rsplit_once(':') {
        (h.to_string(), parse_port(p)?)
    } else {
        (value.to_string(), DEFAULT_DIRECT_PUNCH_PORT)
    };
    if !host_is_valid(&host) {
        return Err(format!(
            "not a valid IPv4 address, IPv6 address or hostname: {host:?}"
        ));
    }
    Ok((host, port))
}

fn parse_port(s: &str) -> Result<u16, String> {
    match s.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(format!("not a valid port: {s:?}")),
    }
}

/// Whether `host` is an IP literal or a hostname worth trying to resolve.
/// Deliberately syntactic only - whether the name resolves is the
/// resolver's answer at punch time, not a settings-file question.
fn host_is_valid(host: &str) -> bool {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub global_ptt_enabled: bool,
    pub global_ptt_shortcut: String,
    pub server_bind: String,
    pub server_port: u16,
    /// Serve the control connection (and the activation endpoint) over
    /// TLS using the certificate pair below (`crate::server::ssl`). Off
    /// unless the file says `on`: turning it on with no certificate in
    /// place refuses to start rather than silently serving plaintext.
    pub server_ssl: bool,
    /// PEM paths, `~`-relative as written (`DEFAULT_SERVER_SSL_FULLCHAIN`/
    /// `DEFAULT_SERVER_SSL_PRIVKEY`); resolved when the server loads them.
    pub server_ssl_fullchain: String,
    pub server_ssl_privkey: String,
    /// Whether `Register` is accepted at all (`docs/PROTOCOL.md` §5.3).
    /// Off by default: with it off, the only way into the registry is
    /// `aloo --register-user` on the server's own machine.
    pub server_allow_registration: bool,
    /// The SMTP account activation emails go out through
    /// (`crate::server::users_registry::send_activation_email`). All four
    /// are needed for a registration to be deliverable; a server with
    /// registration on and no SMTP host refuses registrations with a
    /// reason rather than creating accounts nobody can activate. Port 465
    /// is spoken as implicit TLS, any other port as STARTTLS when the
    /// server offers it.
    pub server_smtp_host: Option<String>,
    pub server_smtp_port: Option<u16>,
    pub server_smtp_username: Option<String>,
    pub server_smtp_password: Option<String>,
    /// Where the activation web endpoint listens
    /// (`DEFAULT_SERVER_ACTIVATION_PORT`), and the public base URL of it
    /// that the activation email links to - e.g.
    /// `https://chat.example.com:7880`. With no URL the email carries the
    /// code alone, to be typed into the client's activation popup.
    pub server_activation_port: u16,
    pub server_activation_url: Option<String>,
    /// Overrides the `otp` binary aloo spawns for the OTP encryption layer
    /// (`client::otp_cli::OtpCliConfig::resolve`) - `None` resolves against
    /// `PATH` (or `ALOO_OTP_BIN`, which always wins over this). aloo never
    /// fetches, downloads, or builds this binary itself.
    pub otp_binary_path: Option<String>,
    pub otp_keypair_size_mb: u32,
    pub otp_low_key_warn_pct: u8,
    pub otp_status_poll_interval: u32,
    /// Nicknames whose incoming voice messages must not play themselves
    /// on arrival (`/mute-voice`, docs/SPEC.md Functionality #15). Written
    /// as one `muted_voice=<nickname>` line per entry rather than a single
    /// comma-separated value: a nickname rejects only whitespace
    /// (`ui_connect_popup::NICKNAME_MAX_LEN` and its input filter), so a
    /// comma is a legal character in one and a joined list would be
    /// ambiguous. A `BTreeSet` so the file is written in a stable order
    /// and doesn't churn between saves.
    ///
    /// Keyed by *nickname*, not `UserId`: that is what survives a
    /// reconnect (a `UserId` never does, §3), and it lets someone be muted
    /// before they have ever connected. It also means this is a comfort
    /// preference, not a security control - nicknames are unique only
    /// among currently-connected clients, never reserved (which is the
    /// whole reason `client::idstore` exists), so a mute can in principle
    /// land on a different person who later takes that name.
    pub muted_voice: BTreeSet<String>,

    // -----------------------------------------------------------------
    // Daemon mode (`aloo --daemon`, docs/SPEC.md "Running in background mode")
    //
    // All optional, and all `None`/empty by default: an absent key means
    // "the flag, the connect cache or the compiled default decides", which
    // is what `client::daemon::DaemonConfig::resolve` implements. A
    // present one is what a bare `aloo --daemon` - the form a systemd unit
    // runs at boot - comes back as.
    // -----------------------------------------------------------------
    pub daemon_host: Option<String>,
    pub daemon_port: Option<u16>,
    pub daemon_nickname: Option<String>,
    /// The password `daemon_nickname` logs in with - the one credential a
    /// daemon needs, and it connects with nobody there to type it.
    pub daemon_server_password: Option<String>,
    /// Connect to the daemon's server over TLS (`connect_ssl`'s daemon
    /// counterpart).
    pub daemon_ssl: bool,
    pub daemon_my_key_pub: Option<String>,
    pub daemon_my_key_priv: Option<String>,
    /// One `daemon_channel=<name>[,<password>]` line per entry, in the
    /// order they should be joined - the same accumulating-key shape (and
    /// the same reason for it) as `muted_voice`, and the same
    /// `name,password` syntax `--channel` takes.
    pub daemon_channels: Vec<String>,
    /// `channel:<name>` or a bare nickname - parsed by
    /// `client::daemon::DaemonFocus::parse`, which owns that grammar. Only
    /// ever *places* the daemon's starting tab once, at launch - not a
    /// standing instruction (`client::daemon::DaemonPlan::should_place_focus`).
    pub daemon_initial_focus: Option<String>,
    pub daemon_otp: bool,
    /// The daemon last ran with no server at all (`--no-server`). Persisted
    /// like every other daemon field so a bare `aloo --daemon` at the next
    /// boot reproduces it - without this a serverless daemon comes back
    /// looking for a host it never had, and refuses to start.
    pub daemon_no_server: bool,
    /// Whether the serverless direct-punch scheduler runs at all
    /// (`docs/PROTOCOL.md` §7.1.5). Off unless the file says `on`, since it
    /// binds a fixed, well-known UDP port and sends unsolicited probes to
    /// hosts named here - neither of which anyone should get by default.
    pub direct_punch: bool,
    /// The local UDP port that scheduler listens on. Only meaningful with
    /// `direct_punch` on; see `DEFAULT_DIRECT_PUNCH_PORT` for why it has to
    /// be fixed at all.
    pub direct_punch_port: u16,
    /// Every `direct_punch_to` line, in file order. One accumulating key
    /// per peer rather than a single comma-joined value - the same shape
    /// `muted_voice` above uses, and here the value has its own commas in
    /// it, so a joined list could not be split back apart at all. Order is
    /// the file's, not sorted: unlike `muted_voice` these are read as a
    /// list of jobs to start, and a file's own order is what a reader
    /// expects them listed in.
    pub direct_punch_to: Vec<DirectPunchTarget>,
    /// Channels this client considers itself in when there is no server to
    /// join one through (`--no-server`, docs/PROTOCOL.md §7.1.5). A channel
    /// is only a name both sides declare - `ChannelPresence` reconciles the
    /// two lists - so with no membership to track this is the whole of it.
    /// One accumulating key per channel, like `muted_voice` and
    /// `direct_punch_to` above.
    pub direct_punch_channels: Vec<String>,
    /// Runs `client::noip::run` in the background whenever there is no
    /// server to hear from - `--no-server`, or the server connection has
    /// been lost - and `direct_punch` names at least one target, so a
    /// peer's `direct_punch_to` line naming this machine's No-IP hostname
    /// keeps resolving to wherever it currently is. Off by default:
    /// turning it on sends this machine's No-IP password out periodically.
    pub noip_when_no_server_and_direct_punch_is_active: bool,
    /// The No-IP hostname to keep updated
    /// (`https://dynupdate.no-ip.com/nic/update?hostname=<noip_hostname>`),
    /// and the account credentials that request authenticates with. Empty
    /// by default like the two SSL paths above; unlike the SMTP settings
    /// these are never all-or-nothing bundled into an `Option` because a
    /// half-filled set is exactly as harmless as an unset one - the
    /// updater simply never fires (`client::noip::NoipConfig::from_settings`).
    pub noip_hostname: String,
    pub noip_username: String,
    pub noip_password: String,
    // -----------------------------------------------------------------
    // The last connection made from the connect popup
    // (`client::connect::run_client_inner`, docs/SPEC.md "Not connected UI")
    //
    // Written every time the popup is submitted, whether or not the
    // connection then succeeds - these are "the values last used", not
    // "the last connection that worked", the same rule the `.cache` file
    // already follows for the keybundle paths beside them.
    //
    // The nickname has nowhere else to live: `.cache` is keyed by
    // `(host, port)` and holds key files only, so it has no slot for the
    // one field that is about the person rather than the server. Host and
    // port sit here beside it rather than being read back out of `.cache`
    // so that one file answers "what did this machine last connect as",
    // which is also what a bare `aloo --daemon` needs
    // (`client::daemon::DaemonConfig::resolve`).
    // -----------------------------------------------------------------
    pub connect_host: Option<String>,
    pub connect_port: Option<u16>,
    pub connect_nickname: Option<String>,
    /// Whether the last connection was made over TLS - the popup's `ssl`
    /// toggle, remembered like the host beside it. The password typed
    /// there is deliberately *not* remembered: it is the one field whose
    /// loss costs nothing to retype and whose leak costs an account.
    pub connect_ssl: bool,
    /// A PEM file of extra root certificates the client trusts on top of
    /// the public roots it ships with - for a server whose certificate
    /// is self-signed or issued by a private CA. Hand-edited only; there
    /// is no popup field for it.
    pub connect_ssl_ca: Option<String>,
    /// `direct_punch_to` lines that would not parse, kept verbatim with the
    /// reason. A malformed line is skipped like any other unparseable
    /// setting, but skipping it *silently* would leave a typo'd nickname or
    /// frequency looking exactly like a peer who simply never answers - so
    /// the caller that starts the scheduler reports these once. Never
    /// written back by `save`.
    pub direct_punch_invalid: Vec<(String, String)>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            global_ptt_enabled: true,
            global_ptt_shortcut: DEFAULT_GLOBAL_PTT_SHORTCUT.to_string(),
            server_bind: DEFAULT_BIND.to_string(),
            server_port: DEFAULT_PORT,
            server_ssl: false,
            server_ssl_fullchain: DEFAULT_SERVER_SSL_FULLCHAIN.to_string(),
            server_ssl_privkey: DEFAULT_SERVER_SSL_PRIVKEY.to_string(),
            server_allow_registration: false,
            server_smtp_host: None,
            server_smtp_port: None,
            server_smtp_username: None,
            server_smtp_password: None,
            server_activation_port: DEFAULT_SERVER_ACTIVATION_PORT,
            server_activation_url: None,
            otp_binary_path: None,
            otp_keypair_size_mb: DEFAULT_OTP_KEYPAIR_SIZE_MB,
            otp_low_key_warn_pct: DEFAULT_OTP_LOW_KEY_WARN_PCT,
            otp_status_poll_interval: DEFAULT_OTP_STATUS_POLL_INTERVAL,
            muted_voice: BTreeSet::new(),
            daemon_host: None,
            daemon_port: None,
            daemon_nickname: None,
            daemon_server_password: None,
            daemon_ssl: false,
            daemon_my_key_pub: None,
            daemon_my_key_priv: None,
            daemon_channels: Vec::new(),
            daemon_initial_focus: None,
            daemon_otp: false,
            daemon_no_server: false,
            direct_punch: false,
            direct_punch_port: DEFAULT_DIRECT_PUNCH_PORT,
            direct_punch_to: Vec::new(),
            direct_punch_channels: Vec::new(),
            noip_when_no_server_and_direct_punch_is_active: false,
            noip_hostname: String::new(),
            noip_username: String::new(),
            noip_password: String::new(),
            connect_host: None,
            connect_port: None,
            connect_nickname: None,
            connect_ssl: false,
            connect_ssl_ca: None,
            direct_punch_invalid: Vec::new(),
        }
    }
}

impl Settings {
    /// Whether this settings file actually names anyone to direct-punch -
    /// the master switch on *and* at least one target, together
    /// (`docs/PROTOCOL.md` §7.1.5). A `--no-server` client start uses this
    /// to decide whether there is anyone to run for at all.
    pub fn has_direct_punch_configured(&self) -> bool {
        self.direct_punch && !self.direct_punch_to.is_empty()
    }

    /// Loads `path`, writing (and returning) the defaults if it doesn't
    /// exist yet, so the file is always present and editable afterward.
    /// Unrecognized or unparseable lines are skipped rather than failing
    /// the load - same tolerance as `IdStore::load`.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(Self::parse(&contents)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let settings = Self::default();
                settings.save(path)?;
                Ok(settings)
            }
            Err(e) => Err(e),
        }
    }

    fn parse(contents: &str) -> Self {
        let mut settings = Self::default();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "global_ptt_enabled" => {
                    if let Ok(b) = value.parse::<bool>() {
                        settings.global_ptt_enabled = b;
                    }
                }
                "global_ptt_shortcut" if !value.is_empty() => {
                    settings.global_ptt_shortcut = value.to_string();
                }
                "server_bind" if !value.is_empty() => {
                    settings.server_bind = value.to_string();
                }
                "server_port" => {
                    if let Ok(p) = value.parse::<u16>() {
                        settings.server_port = p;
                    }
                }
                "server_ssl" => settings.server_ssl = parse_switch(value),
                "server_ssl_fullchain" if !value.is_empty() => {
                    settings.server_ssl_fullchain = value.to_string();
                }
                "server_ssl_privkey" if !value.is_empty() => {
                    settings.server_ssl_privkey = value.to_string();
                }
                "server_allow_registration" => {
                    settings.server_allow_registration = parse_switch(value);
                }
                "server_smtp_host" if !value.is_empty() => {
                    settings.server_smtp_host = Some(value.to_string());
                }
                "server_smtp_port" => {
                    if let Ok(p) = value.parse::<u16>()
                        && p != 0
                    {
                        settings.server_smtp_port = Some(p);
                    }
                }
                "server_smtp_username" if !value.is_empty() => {
                    settings.server_smtp_username = Some(value.to_string());
                }
                "server_smtp_password" if !value.is_empty() => {
                    settings.server_smtp_password = Some(value.to_string());
                }
                "server_activation_port" => {
                    if let Ok(p) = value.parse::<u16>()
                        && p != 0
                    {
                        settings.server_activation_port = p;
                    }
                }
                "server_activation_url" if !value.is_empty() => {
                    settings.server_activation_url = Some(value.trim_end_matches('/').to_string());
                }
                "otp_binary_path" if !value.is_empty() => {
                    settings.otp_binary_path = Some(value.to_string());
                }
                "otp_keypair_size_mb" => {
                    if let Ok(v) = value.parse::<u32>() {
                        settings.otp_keypair_size_mb = v;
                    }
                }
                "otp_low_key_warn_pct" => {
                    if let Ok(v) = value.parse::<u8>() {
                        settings.otp_low_key_warn_pct = v;
                    }
                }
                "otp_status_poll_interval" => {
                    if let Ok(v) = value.parse::<u32>() {
                        settings.otp_status_poll_interval = v;
                    }
                }
                // The one *accumulating* key in this file - every other
                // one is last-wins. Deliberately not `.trim()`-sensitive
                // beyond the whole-value trim above: a nickname can't
                // contain whitespace anyway.
                "muted_voice" if !value.is_empty() && crate::validation::is_storable(value) => {
                    settings.muted_voice.insert(value.to_string());
                }
                "daemon_host" if !value.is_empty() => {
                    settings.daemon_host = Some(value.to_string())
                }
                "daemon_port" => {
                    if let Ok(p) = value.parse::<u16>() {
                        settings.daemon_port = Some(p);
                    }
                }
                "daemon_nickname" if !value.is_empty() => {
                    settings.daemon_nickname = Some(value.to_string())
                }
                "daemon_server_password" if !value.is_empty() => {
                    settings.daemon_server_password = Some(value.to_string())
                }
                "daemon_ssl" => settings.daemon_ssl = parse_switch(value),
                "daemon_my_key_pub" if !value.is_empty() => {
                    settings.daemon_my_key_pub = Some(value.to_string())
                }
                "daemon_my_key_priv" if !value.is_empty() => {
                    settings.daemon_my_key_priv = Some(value.to_string())
                }
                // The second accumulating key, same shape as
                // `muted_voice` and for the same reason: a channel
                // password may contain a comma, so a joined list could
                // not be split back apart.
                "daemon_channel" if !value.is_empty() && crate::validation::is_storable(value) => {
                    settings.daemon_channels.push(value.to_string());
                }
                "daemon_initial_focus" if !value.is_empty() => {
                    settings.daemon_initial_focus = Some(value.to_string())
                }
                "daemon_otp" => {
                    if let Ok(b) = value.parse::<bool>() {
                        settings.daemon_otp = b;
                    }
                }
                // `on`/`off` rather than `true`/`false`, matching how the
                // setting is spelled in every example and in the README -
                // both are accepted so neither spelling is a silent no-op.
                "daemon_no_server" => settings.daemon_no_server = parse_switch(value),
                "direct_punch" => settings.direct_punch = parse_switch(value),
                "direct_punch_port" => {
                    if let Ok(p) = value.parse::<u16>()
                        && p != 0
                    {
                        settings.direct_punch_port = p;
                    }
                }
                "direct_punch_channel"
                    if !value.is_empty()
                        && crate::validation::channel_name_is_valid(value)
                        && !settings.direct_punch_channels.iter().any(|c| c == value) =>
                {
                    settings.direct_punch_channels.push(value.to_string());
                }
                "connect_host" if !value.is_empty() => {
                    settings.connect_host = Some(value.to_string())
                }
                "connect_port" => {
                    if let Ok(p) = value.parse::<u16>() {
                        settings.connect_port = Some(p);
                    }
                }
                "connect_nickname" if !value.is_empty() => {
                    settings.connect_nickname = Some(value.to_string())
                }
                "connect_ssl" => settings.connect_ssl = parse_switch(value),
                "connect_ssl_ca" if !value.is_empty() => {
                    settings.connect_ssl_ca = Some(value.to_string())
                }
                "direct_punch_to" => match DirectPunchTarget::parse(value) {
                    Ok(target) => settings.direct_punch_to.push(target),
                    Err(reason) => settings
                        .direct_punch_invalid
                        .push((value.to_string(), reason)),
                },
                "noip_when_no_server_and_direct_punch_is_active" => {
                    settings.noip_when_no_server_and_direct_punch_is_active = parse_switch(value)
                }
                "noip_hostname" if !value.is_empty() => {
                    settings.noip_hostname = value.to_string()
                }
                "noip_username" if !value.is_empty() => {
                    settings.noip_username = value.to_string()
                }
                "noip_password" if !value.is_empty() => {
                    settings.noip_password = value.to_string()
                }
                _ => {}
            }
        }
        settings
    }

    /// Persists these settings to `path`, creating parent directories if
    /// needed (e.g. `~/.aloo/` on first run).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut contents = format!(
            "global_ptt_enabled={}\nglobal_ptt_shortcut={}\nserver_bind={}\nserver_port={}\n",
            self.global_ptt_enabled, self.global_ptt_shortcut, self.server_bind, self.server_port
        );
        // Every server key is written even when unset (`server_smtp_host=`),
        // so an operator setting the server up finds each one already
        // named in the file rather than having to know it exists.
        contents.push_str(&format!(
            "server_ssl={}\nserver_ssl_fullchain={}\nserver_ssl_privkey={}\n",
            switch(self.server_ssl),
            self.server_ssl_fullchain,
            self.server_ssl_privkey
        ));
        contents.push_str(&format!(
            "server_allow_registration={}\n",
            switch(self.server_allow_registration)
        ));
        contents.push_str(&format!(
            "server_smtp_host={}\nserver_smtp_port={}\nserver_smtp_username={}\nserver_smtp_password={}\n",
            self.server_smtp_host.as_deref().unwrap_or(""),
            self.server_smtp_port.map(|p| p.to_string()).unwrap_or_default(),
            self.server_smtp_username.as_deref().unwrap_or(""),
            self.server_smtp_password.as_deref().unwrap_or(""),
        ));
        contents.push_str(&format!(
            "server_activation_port={}\nserver_activation_url={}\n",
            self.server_activation_port,
            self.server_activation_url.as_deref().unwrap_or("")
        ));
        if let Some(bin) = &self.otp_binary_path {
            contents.push_str(&format!("otp_binary_path={bin}\n"));
        }
        contents.push_str(&format!(
            "otp_keypair_size_mb={}\notp_low_key_warn_pct={}\notp_status_poll_interval={}\n",
            self.otp_keypair_size_mb, self.otp_low_key_warn_pct, self.otp_status_poll_interval
        ));
        // One line per entry, in `BTreeSet` order - see `muted_voice`'s
        // doc for why this isn't one comma-separated value. A name that
        // can't round-trip through a line-oriented file is dropped rather
        // than written, same rule `IdStore::check_and_pin` applies.
        for name in &self.muted_voice {
            if crate::validation::is_storable(name) {
                contents.push_str(&format!("muted_voice={name}\n"));
            }
        }
        // Daemon keys. Only written when set, so a machine that has never
        // run a daemon keeps a settings file with nothing daemon-shaped
        // in it rather than a block of empty values.
        let mut optional = |key: &str, value: &Option<String>| {
            if let Some(value) = value
                && crate::validation::is_storable(value)
            {
                contents.push_str(&format!("{key}={value}\n"));
            }
        };
        optional("daemon_host", &self.daemon_host);
        optional("daemon_nickname", &self.daemon_nickname);
        optional("daemon_server_password", &self.daemon_server_password);
        optional("daemon_my_key_pub", &self.daemon_my_key_pub);
        optional("daemon_my_key_priv", &self.daemon_my_key_priv);
        optional("daemon_initial_focus", &self.daemon_initial_focus);
        if let Some(port) = self.daemon_port {
            contents.push_str(&format!("daemon_port={port}\n"));
        }
        for channel in &self.daemon_channels {
            if crate::validation::is_storable(channel) {
                contents.push_str(&format!("daemon_channel={channel}\n"));
            }
        }
        if self.daemon_otp {
            contents.push_str("daemon_otp=true\n");
        }
        if self.daemon_ssl {
            contents.push_str("daemon_ssl=on\n");
        }
        if self.daemon_no_server {
            contents.push_str("daemon_no_server=true\n");
        }
        contents.push_str(&format!(
            "direct_punch={}\ndirect_punch_port={}\n",
            if self.direct_punch { "on" } else { "off" },
            self.direct_punch_port
        ));
        for target in &self.direct_punch_to {
            contents.push_str(&format!("direct_punch_to={}\n", target.to_setting_value()));
        }
        for channel in &self.direct_punch_channels {
            contents.push_str(&format!("direct_punch_channel={channel}\n"));
        }
        contents.push_str(&format!(
            "noip_when_no_server_and_direct_punch_is_active={}\nnoip_hostname={}\nnoip_username={}\nnoip_password={}\n",
            switch(self.noip_when_no_server_and_direct_punch_is_active),
            self.noip_hostname,
            self.noip_username,
            self.noip_password,
        ));
        // Written by hand rather than through `optional` above: that
        // closure holds a mutable borrow of `contents` for as long as it
        // is alive, and everything between it and here writes directly.
        for (key, value) in [
            ("connect_host", &self.connect_host),
            ("connect_nickname", &self.connect_nickname),
        ] {
            if let Some(value) = value
                && crate::validation::is_storable(value)
            {
                contents.push_str(&format!("{key}={value}\n"));
            }
        }
        if let Some(port) = self.connect_port {
            contents.push_str(&format!("connect_port={port}\n"));
        }
        contents.push_str(&format!("connect_ssl={}\n", switch(self.connect_ssl)));
        if let Some(ca) = &self.connect_ssl_ca
            && crate::validation::is_storable(ca)
        {
            contents.push_str(&format!("connect_ssl_ca={ca}\n"));
        }
        fs::write(path, contents)
    }

    /// Records the keybundle a daemon connects with, so a later bare
    /// `aloo --daemon` comes back as the same identity (see
    /// `client::daemon::resolve_my_key`).
    pub fn set_daemon_my_key(&mut self, selection: &crate::client::connect::MyKeySelection) {
        self.daemon_my_key_pub = Some(selection.file_pub.display().to_string());
        self.daemon_my_key_priv = Some(selection.file_priv.display().to_string());
    }

    /// The general form of `update_muted_voice`: applies `edit` to what is
    /// on disk right now and writes that back, rather than serializing
    /// whatever this process happens to hold.
    ///
    /// Same reasoning, and the same importance. A daemon persists its
    /// resolved configuration at every start, `/mute-voice` writes this
    /// file mid-session, and a connect writes it again - several writers
    /// on one file, where a whole-struct save from any of them would
    /// silently revert the others.
    pub fn update(path: &Path, edit: impl FnOnce(&mut Self)) -> io::Result<()> {
        let mut settings = Self::load_or_create(path)?;
        edit(&mut settings);
        settings.save(path)
    }

    /// Records what the connect popup was just submitted with, so the
    /// next start proposes it again and a bare `aloo --daemon` can reuse
    /// it (`client::daemon::DaemonConfig::resolve`).
    ///
    /// A merging write (`update`), and for the same reason: a daemon may
    /// be running and writing its own keys to this file while a second
    /// `aloo` is being connected in a terminal.
    pub fn remember_connection(
        path: &Path,
        host: &str,
        port: u16,
        nickname: &str,
        ssl: bool,
    ) -> io::Result<()> {
        Self::update(path, |s| {
            s.connect_ssl = ssl;
            // An empty host is what a `--no-server` start stands in for
            // (`client::daemon::DaemonConfig::resolve`), not an address -
            // recording it would leave the next start resolving a host
            // that is not one.
            if !host.is_empty() {
                s.connect_host = Some(host.to_string());
            }
            s.connect_port = Some(port);
            if !nickname.is_empty() {
                s.connect_nickname = Some(nickname.to_string());
            }
        })
    }

    /// Applies `edit` to the *on-disk* muted-voice set and writes the file
    /// back, rather than serializing this process's whole in-memory
    /// `Settings`.
    ///
    /// This distinction is the whole point. `save` writes every field it
    /// holds, and this file has several writers going at once: a daemon
    /// records its configuration at every start, a connect records what it
    /// was submitted with, `/mute-voice` writes mid-session, and
    /// `aloo --server` records its own bind/port/auth. A bare `save` from
    /// any of them would silently revert whatever the others had just
    /// recorded. Reading immediately before writing keeps each writer to
    /// its own keys.
    ///
    /// Not atomic against a genuinely simultaneous writer (no lock file -
    /// that would be a heavier mechanism than a preferences file
    /// warrants), but it closes the window from "the whole session" to
    /// "the microseconds between this read and this write".
    pub fn update_muted_voice(
        path: &Path,
        edit: impl FnOnce(&mut BTreeSet<String>),
    ) -> io::Result<BTreeSet<String>> {
        let mut settings = Self::load_or_create(path)?;
        edit(&mut settings.muted_voice);
        settings.save(path)?;
        Ok(settings.muted_voice)
    }
}
