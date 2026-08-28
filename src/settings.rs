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
//! `crate::server::users_registry`). The SMTP
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

/// `on`/`true`/`yes`/`1` - the spelling every `on`/`off` setting in this
/// file accepts, so no spelling is a silent no-op.
/// Whether the microphone is attenuated while other people's audio is
/// coming out of the speakers (`client::voice::EchoDucker`).
///
/// Three states rather than two because the right answer depends on
/// something the app can observe better than the user can state it: whether
/// the microphone can actually hear the speakers. `Auto` lets
/// `client::voice::EchoProbe` decide that from the audio, and re-decide it
/// when someone plugs headphones in mid-call. `On`/`Off` are for the rooms
/// it gets wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EchoDucking {
    #[default]
    Auto,
    On,
    Off,
}

impl EchoDucking {
    /// Anything unrecognised reads as `Auto` rather than as off - an
    /// unreadable value should land on the default, and the default here is
    /// the one that decides for itself.
    fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "on" | "true" | "yes" | "1" => Self::On,
            "off" | "false" | "no" | "0" => Self::Off,
            _ => Self::Auto,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

impl std::fmt::Display for EchoDucking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

/// A `server_channel_deletion_unactivity_period` value: how long an empty,
/// unjoined channel survives before the inactivity sweep destroys it
/// (`docs/PROTOCOL.md` §6.8). A month is fixed at
/// `CHANNEL_DELETION_MONTH_DAYS` days - no calendar-month arithmetic, so
/// the setting's meaning never depends on which month it happens to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelDeletionPeriod(std::time::Duration);

/// What a `server_channel_deletion_unactivity_period=Nmonths` line counts
/// one month as.
pub const CHANNEL_DELETION_MONTH_DAYS: u64 = 30;

impl ChannelDeletionPeriod {
    /// Parses `Nday`/`Ndays`, `Nweek`/`Nweeks`, or `Nmonth`/`Nmonths` -
    /// styled like `PunchFrequency::parse`: trimmed and lowercased first,
    /// every accepted spelling named in the error.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim().to_ascii_lowercase();
        let err = || format!("not a valid period: {s:?} - use one of Ndays, Nweeks, Nmonths");
        let days_per_unit = if s.ends_with("day") || s.ends_with("days") {
            1
        } else if s.ends_with("week") || s.ends_with("weeks") {
            7
        } else if s.ends_with("month") || s.ends_with("months") {
            CHANNEL_DELETION_MONTH_DAYS
        } else {
            return Err(err());
        };
        let digits = s.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        let count: u64 = digits.parse().map_err(|_| err())?;
        if count == 0 {
            return Err(err());
        }
        Ok(Self(std::time::Duration::from_secs(
            count * days_per_unit * 24 * 60 * 60,
        )))
    }

    pub fn as_duration(self) -> std::time::Duration {
        self.0
    }
}

impl std::fmt::Display for ChannelDeletionPeriod {
    /// Canonicalizes to days - a saved `1month` reads back as `30days`,
    /// numerically identical rather than wording-identical, the same
    /// normalization `PunchFrequency` already applies to its own spellings.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}days", self.0.as_secs() / (24 * 60 * 60))
    }
}

/// One `direct_punch_to=<nickname>[+<device_id>],<host>[:<port>],<frequency>`
/// line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPunchTarget {
    /// The peer's nickname - the only name a serverless link has, since
    /// there is no server to assign or relay a `UserId` for it.
    pub nickname: String,
    /// Which of that nickname's devices this line addresses
    /// (device-pinning plan §5a) - `None` addresses whichever device
    /// `IdStore`'s ordinary most-recently-seen default resolves to, exactly
    /// as every line did before this field existed. `Some` lets a second
    /// line for the same nickname reach a *different* device: each becomes
    /// its own `UserId` (`direct_peer_id`), its own link, and (since a raw
    /// pairing key already differs per device) its own pad.
    pub device_id: Option<String>,
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
    ///
    /// The nickname component may carry a `+<device_id>` suffix, split at
    /// the *first* `+` in the field. `+` is therefore reserved once this
    /// syntax exists: a nickname that itself contains one (`is_storable`
    /// alone does not forbid it) is not refused, but everything from that
    /// first `+` onward is read as a device id rather than part of the
    /// name - the same trade-off the tab/newline field delimiters already
    /// make for `is_storable` itself.
    pub fn parse(value: &str) -> Result<Self, String> {
        let parts: Vec<&str> = value.split(',').map(str::trim).collect();
        let [nick_field, host, frequency] = parts.as_slice() else {
            return Err(format!(
                "expected <nickname>,<host>,<frequency>, got {value:?}"
            ));
        };
        let (nickname, device_id) = match nick_field.split_once('+') {
            Some((nickname, device_id)) => {
                if device_id.is_empty() || !crate::validation::is_storable(device_id) {
                    return Err(format!("not a valid device id: {device_id:?}"));
                }
                (nickname, Some(device_id.to_string()))
            }
            None => (*nick_field, None),
        };
        if !crate::validation::nickname_is_registrable(nickname) {
            return Err(format!("not a valid nickname: {nickname:?}"));
        }
        let (host, port) = split_host_port(host)?;
        Ok(Self {
            nickname: nickname.to_string(),
            device_id,
            host,
            port,
            frequency: PunchFrequency::parse(frequency)?,
        })
    }

    /// `<nickname>[+<device_id>],<host>[:<port>],<frequency>` - the exact
    /// spelling `parse` accepts, so a load/save round trip is lossless.
    pub fn to_setting_value(&self) -> String {
        let host = if self.host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.device_id {
            Some(device_id) => format!(
                "{}+{device_id},{host}:{},{}",
                self.nickname, self.port, self.frequency
            ),
            None => format!("{},{host}:{},{}", self.nickname, self.port, self.frequency),
        }
    }

    /// The key that identifies this line's target uniquely among every
    /// other configured line - nickname alone when unsuffixed (byte-
    /// identical to how every line worked before device suffixes existed),
    /// nickname+device_id when suffixed, so two lines for the same nickname
    /// but different devices never collide.
    pub fn target_key(&self) -> String {
        match &self.device_id {
            Some(device_id) => format!("{}+{device_id}", self.nickname),
            None => self.nickname.clone(),
        }
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
    /// Attenuate the microphone while the other side's audio is coming out
    /// of the speakers, so it is not captured and sent straight back to
    /// them as an echo (`client::voice::EchoDucker`).
    ///
    /// `auto` (the default) works it out from the audio rather than being
    /// told - see `EchoDucking` and `client::voice::EchoProbe`. `on`/`off`
    /// force it either way. A capture device that cancels echo itself
    /// overrides all three (`client::voice::Recorder::echo_cancelled`).
    ///
    /// Applies to live calls and to push-to-talk voice messages alike; both
    /// capture through the same microphone while the same speakers play.
    pub voice_echo_ducking: EchoDucking,
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
    /// server offers it. The email carries the code alone, to be typed
    /// into the client's activation popup.
    pub server_smtp_host: Option<String>,
    pub server_smtp_port: Option<u16>,
    pub server_smtp_username: Option<String>,
    pub server_smtp_password: Option<String>,
    /// Whether a `JoinChannel` for a not-yet-existing name may create it
    /// as public (`docs/PROTOCOL.md` §6.7's `ChannelsRegistry::join`).
    /// Joining an *existing* public channel, and creating/joining a
    /// private one, are unaffected either way. On by default - this is a
    /// server that wants public channel creation curated, not the norm.
    pub server_allow_create_public_channels: bool,
    /// How long a channel (other than `the-hall`) may sit both empty and
    /// unjoined before the background sweep destroys it (§6.8) - `None`
    /// (the default, and what an absent key means) turns the sweep off
    /// entirely, so channels persist while empty indefinitely.
    pub server_channel_deletion_unactivity_period: Option<ChannelDeletionPeriod>,
    /// Nicknames that may activate/deactivate any account, remove one (and
    /// every channel it administers), or remove any public channel (§5.5).
    /// One `server_superadmin=<nickname>` line per admin, the same
    /// one-line-per-entry convention `muted_voice`/`daemon_channel` already
    /// use - never the single bracketed-list form, since a nickname can't
    /// contain a comma but a joined list still reads worse than repeating
    /// the key.
    pub server_superadmin: BTreeSet<String>,
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
    /// Append every channel/DM message (and its voice `.wav`, if any) to
    /// `~/.aloo/exports/<server>/{channels,dms}/*.log` as it arrives or is
    /// sent (`client::export`). Off by default - this writes an
    /// ever-growing plaintext transcript to disk, which nobody should get
    /// without asking for it. Independent of the manual `Ctrl+E` export
    /// popup, which works either way.
    pub autosave_messages: bool,
    /// Lazily pull older history for a channel/DM back in from its
    /// `autosave_messages` `.log` file (`client::export::LogHistoryCursor`)
    /// as the user scrolls up - a screen's worth on first opening it, and
    /// another screen's worth each time they scroll to the top of what's
    /// loaded. Off by default, and independent of `autosave_messages`
    /// itself: this only ever *reads* a `.log` file that may have been
    /// written in an earlier session (or not exist at all, in which case
    /// this is a no-op either way).
    pub resume_from_log: bool,

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
    /// Whether to connect over TLS - shared by both a normal (interactive)
    /// connect and a daemon start, and the only place this is decided:
    /// there is no popup field for it (the connect form silently reads
    /// this at open time and carries it into the request, per
    /// `docs/PROTOCOL.md` §1.4) and no CLI flag either. Edit this file by
    /// hand to change it. A connect that fails because this doesn't match
    /// what the server actually wants gets a specific diagnosis rather
    /// than a bare connection error (`connect::connect_with_reconnect`).
    pub connect_using_ssl: bool,
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
            voice_echo_ducking: EchoDucking::default(),
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
            server_allow_create_public_channels: true,
            server_channel_deletion_unactivity_period: None,
            server_superadmin: BTreeSet::new(),
            otp_binary_path: None,
            otp_keypair_size_mb: DEFAULT_OTP_KEYPAIR_SIZE_MB,
            otp_low_key_warn_pct: DEFAULT_OTP_LOW_KEY_WARN_PCT,
            otp_status_poll_interval: DEFAULT_OTP_STATUS_POLL_INTERVAL,
            muted_voice: BTreeSet::new(),
            autosave_messages: false,
            resume_from_log: false,
            daemon_host: None,
            daemon_port: None,
            daemon_nickname: None,
            daemon_server_password: None,
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
            connect_using_ssl: false,
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
                crate::platform::ensure_parent_dir(path)?;
                fs::write(path, settings.scaffold_contents())?;
                Ok(settings)
            }
            Err(e) => Err(e),
        }
    }

    /// The full, two-section, every-key-named dump `load_or_create` writes
    /// on a machine's very first run - this lists every client option,
    /// then every server option, each under its own `#`-comment header,
    /// so a user opening the file for the first time finds every knob
    /// already there to read and edit rather than having to know it
    /// exists. Never called again after the first run: every later write
    /// goes through `save`, which patches this file's own lines in place
    /// (`patch_into`) rather than regenerating them, so this shape - and
    /// whatever a user has since hand-edited into it - survives. `parse`
    /// (comment- and order-agnostic) reads this or `dense_contents`'
    /// shape identically either way.
    fn scaffold_contents(&self) -> String {
        let mut c = String::new();
        c.push_str("# client options\n# -----------------------------------------\n");
        c.push_str(&format!("global_ptt_enabled={}\n", self.global_ptt_enabled));
        c.push_str(&format!("global_ptt_shortcut={}\n", self.global_ptt_shortcut));
        // The only tri-state switch in the file, and `auto` on its own gives
        // no hint that the other two exist - so the scaffold names them.
        c.push_str("# voice_echo_ducking: auto (decide from the audio), on, off\n");
        c.push_str(&format!("voice_echo_ducking={}\n", self.voice_echo_ducking));
        c.push_str(&format!("autosave_messages={}\n", switch(self.autosave_messages)));
        c.push_str(&format!("resume_from_log={}\n", switch(self.resume_from_log)));
        c.push_str(&format!("daemon_host={}\n", self.daemon_host.as_deref().unwrap_or("")));
        c.push_str(&format!(
            "daemon_port={}\n",
            self.daemon_port.map(|p| p.to_string()).unwrap_or_default()
        ));
        c.push_str(&format!(
            "daemon_nickname={}\n",
            self.daemon_nickname.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "daemon_server_password={}\n",
            self.daemon_server_password.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "daemon_my_key_pub={}\n",
            self.daemon_my_key_pub.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "daemon_my_key_priv={}\n",
            self.daemon_my_key_priv.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "daemon_initial_focus={}\n",
            self.daemon_initial_focus.as_deref().unwrap_or("")
        ));
        c.push_str("# daemon_channel=otherchannel\n");
        c.push_str(&format!("daemon_otp={}\n", self.daemon_otp));
        c.push_str(&format!("daemon_no_server={}\n", switch(self.daemon_no_server)));
        c.push_str(&format!("direct_punch={}\n", switch(self.direct_punch)));
        c.push_str(&format!("direct_punch_port={}\n", self.direct_punch_port));
        c.push_str("# direct_punch_to=alice,alicehost.com:7879,every_1m\n");
        c.push_str("# direct_punch_channel=the-hall\n");
        c.push_str(&format!(
            "noip_when_no_server_and_direct_punch_is_active={}\n",
            switch(self.noip_when_no_server_and_direct_punch_is_active)
        ));
        c.push_str(&format!("noip_hostname={}\n", self.noip_hostname));
        c.push_str(&format!("noip_username={}\n", self.noip_username));
        c.push_str(&format!("noip_password={}\n", self.noip_password));
        c.push_str(&format!("connect_host={}\n", self.connect_host.as_deref().unwrap_or("")));
        c.push_str(&format!(
            "connect_nickname={}\n",
            self.connect_nickname.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "connect_port={}\n",
            self.connect_port.map(|p| p.to_string()).unwrap_or_default()
        ));
        c.push_str(&format!("connect_using_ssl={}\n", switch(self.connect_using_ssl)));
        c.push_str(&format!(
            "connect_ssl_ca={}\n",
            self.connect_ssl_ca.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "otp_binary_path={}\n",
            self.otp_binary_path.as_deref().unwrap_or("")
        ));
        c.push_str(&format!("otp_keypair_size_mb={}\n", self.otp_keypair_size_mb));
        c.push_str(&format!("otp_low_key_warn_pct={}\n", self.otp_low_key_warn_pct));
        c.push_str(&format!(
            "otp_status_poll_interval={}\n",
            self.otp_status_poll_interval
        ));
        // Accumulating keys (one line per entry, `muted_voice`'s own doc
        // explains why) have nothing real to pre-populate on a fresh file -
        // a commented-out example shows the syntax without taking effect.
        c.push_str("# muted_voice=somenickname\n");

        c.push_str("\n# server options\n# -----------------------------------------\n");
        c.push_str(&format!("server_bind={}\n", self.server_bind));
        c.push_str(&format!("server_port={}\n", self.server_port));
        c.push_str(&format!("server_ssl={}\n", switch(self.server_ssl)));
        c.push_str(&format!("server_ssl_fullchain={}\n", self.server_ssl_fullchain));
        c.push_str(&format!("server_ssl_privkey={}\n", self.server_ssl_privkey));
        c.push_str(&format!(
            "server_allow_registration={}\n",
            switch(self.server_allow_registration)
        ));
        c.push_str(&format!(
            "server_smtp_host={}\n",
            self.server_smtp_host.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "server_smtp_port={}\n",
            self.server_smtp_port.map(|p| p.to_string()).unwrap_or_default()
        ));
        c.push_str(&format!(
            "server_smtp_username={}\n",
            self.server_smtp_username.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "server_smtp_password={}\n",
            self.server_smtp_password.as_deref().unwrap_or("")
        ));
        c.push_str(&format!(
            "server_allow_create_public_channels={}\n",
            switch(self.server_allow_create_public_channels)
        ));
        c.push_str(&format!(
            "server_channel_deletion_unactivity_period={}\n",
            self.server_channel_deletion_unactivity_period
                .map(|p| p.to_string())
                .unwrap_or_default()
        ));
        c.push_str("# server_superadmin=somenickname\n");
        c
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
                "voice_echo_ducking" => {
                    settings.voice_echo_ducking = EchoDucking::parse(value);
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
                "server_allow_create_public_channels" => {
                    settings.server_allow_create_public_channels = parse_switch(value);
                }
                "server_channel_deletion_unactivity_period" if !value.is_empty() => {
                    if let Ok(period) = ChannelDeletionPeriod::parse(value) {
                        settings.server_channel_deletion_unactivity_period = Some(period);
                    }
                }
                // Accumulating, same convention as `muted_voice` - one line
                // per superadmin, never a bracketed list, and validated the
                // same way `daemon_nickname` already is: a hand-edited
                // value that couldn't be a real nickname can't name anyone.
                "server_superadmin" if crate::validation::nickname_is_registrable(value) => {
                    settings.server_superadmin.insert(value.to_string());
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
                "autosave_messages" => settings.autosave_messages = parse_switch(value),
                "resume_from_log" => settings.resume_from_log = parse_switch(value),
                "daemon_host" if !value.is_empty() => {
                    settings.daemon_host = Some(value.to_string())
                }
                "daemon_port" => {
                    if let Ok(p) = value.parse::<u16>() {
                        settings.daemon_port = Some(p);
                    }
                }
                "daemon_nickname" if crate::validation::nickname_is_registrable(value) => {
                    settings.daemon_nickname = Some(value.to_string())
                }
                "daemon_server_password" if !value.is_empty() => {
                    settings.daemon_server_password = Some(value.to_string())
                }
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
                "connect_nickname" if crate::validation::nickname_is_registrable(value) => {
                    settings.connect_nickname = Some(value.to_string())
                }
                "connect_using_ssl" => settings.connect_using_ssl = parse_switch(value),
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
    ///
    /// Patches `path`'s own existing lines (`patch_into`) rather than
    /// re-dumping every field in a fixed order, so `load_or_create`'s
    /// one-time, commented, sectioned `scaffold_contents` survives every
    /// later write - a connect, `/mute-voice`, a daemon start, `--server`
    /// recording its bind/port - instead of being flattened into
    /// `dense_contents`'s dense form on the very first one. That dense
    /// form still exists, as the fallback for the one case patching can't
    /// help: nothing to patch because `path` doesn't exist yet (deleted
    /// out from under a running process, or `save` called without going
    /// through `load_or_create` first).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        crate::platform::ensure_parent_dir(path)?;
        let contents = match fs::read_to_string(path) {
            Ok(existing) => self.patch_into(&existing),
            Err(_) => self.dense_contents(),
        };
        fs::write(path, contents)
    }

    /// Every "singular", last-wins key this file manages: its current
    /// value (the blank/off spelling `scaffold_contents` already gives an
    /// unset optional field - never absent, since an *existing* line for
    /// one must stay even while it's unset, only not be freshly added),
    /// and whether a save should add a brand-new line for it when the
    /// file has none yet. That second half is `false` for exactly the
    /// optional fields `dense_contents`'s old `optional` helper used to
    /// skip entirely while unset (daemon/connect/otp_binary_path) - a
    /// machine that has never run a daemon still keeps nothing
    /// daemon-shaped in a freshly-`dense_contents`-written file, and
    /// `patch_into` doesn't invent one either, but if a line already
    /// exists (typically from `scaffold_contents`, which pre-writes every
    /// key blank) it is kept and simply written blank, never deleted.
    fn scalar_fields(&self) -> Vec<(&'static str, String, bool)> {
        let opt_str = |v: &Option<String>| -> (String, bool) {
            match v.clone().filter(|v| crate::validation::is_storable(v)) {
                Some(v) => (v, true),
                None => (String::new(), false),
            }
        };
        let opt_num = |v: Option<u16>| -> (String, bool) {
            match v {
                Some(p) => (p.to_string(), true),
                None => (String::new(), false),
            }
        };
        let (otp_binary_path, has_otp_binary_path) = opt_str(&self.otp_binary_path);
        let (daemon_host, has_daemon_host) = opt_str(&self.daemon_host);
        let (daemon_nickname, has_daemon_nickname) = opt_str(&self.daemon_nickname);
        let (daemon_server_password, has_daemon_server_password) =
            opt_str(&self.daemon_server_password);
        let (daemon_my_key_pub, has_daemon_my_key_pub) = opt_str(&self.daemon_my_key_pub);
        let (daemon_my_key_priv, has_daemon_my_key_priv) = opt_str(&self.daemon_my_key_priv);
        let (daemon_initial_focus, has_daemon_initial_focus) = opt_str(&self.daemon_initial_focus);
        let (daemon_port, has_daemon_port) = opt_num(self.daemon_port);
        let (connect_host, has_connect_host) = opt_str(&self.connect_host);
        let (connect_nickname, has_connect_nickname) = opt_str(&self.connect_nickname);
        let (connect_port, has_connect_port) = opt_num(self.connect_port);
        let (connect_ssl_ca, has_connect_ssl_ca) = opt_str(&self.connect_ssl_ca);
        vec![
            ("global_ptt_enabled", self.global_ptt_enabled.to_string(), true),
            ("global_ptt_shortcut", self.global_ptt_shortcut.clone(), true),
            (
                "voice_echo_ducking",
                self.voice_echo_ducking.to_string(),
                true,
            ),
            ("server_bind", self.server_bind.clone(), true),
            ("server_port", self.server_port.to_string(), true),
            ("server_ssl", switch(self.server_ssl).to_string(), true),
            ("server_ssl_fullchain", self.server_ssl_fullchain.clone(), true),
            ("server_ssl_privkey", self.server_ssl_privkey.clone(), true),
            (
                "server_allow_registration",
                switch(self.server_allow_registration).to_string(),
                true,
            ),
            // Every server key is written even when unset, so an operator
            // setting the server up finds each one already named in the
            // file rather than having to know it exists.
            ("server_smtp_host", self.server_smtp_host.clone().unwrap_or_default(), true),
            (
                "server_smtp_port",
                self.server_smtp_port.map(|p| p.to_string()).unwrap_or_default(),
                true,
            ),
            (
                "server_smtp_username",
                self.server_smtp_username.clone().unwrap_or_default(),
                true,
            ),
            (
                "server_smtp_password",
                self.server_smtp_password.clone().unwrap_or_default(),
                true,
            ),
            (
                "server_allow_create_public_channels",
                switch(self.server_allow_create_public_channels).to_string(),
                true,
            ),
            (
                "server_channel_deletion_unactivity_period",
                self.server_channel_deletion_unactivity_period
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                true,
            ),
            ("otp_keypair_size_mb", self.otp_keypair_size_mb.to_string(), true),
            ("otp_low_key_warn_pct", self.otp_low_key_warn_pct.to_string(), true),
            ("otp_status_poll_interval", self.otp_status_poll_interval.to_string(), true),
            ("autosave_messages", switch(self.autosave_messages).to_string(), true),
            ("resume_from_log", switch(self.resume_from_log).to_string(), true),
            ("direct_punch", switch(self.direct_punch).to_string(), true),
            ("direct_punch_port", self.direct_punch_port.to_string(), true),
            (
                "noip_when_no_server_and_direct_punch_is_active",
                switch(self.noip_when_no_server_and_direct_punch_is_active).to_string(),
                true,
            ),
            ("noip_hostname", self.noip_hostname.clone(), true),
            ("noip_username", self.noip_username.clone(), true),
            ("noip_password", self.noip_password.clone(), true),
            ("connect_using_ssl", switch(self.connect_using_ssl).to_string(), true),
            // Optional - only ever added to the file once actually set.
            ("otp_binary_path", otp_binary_path, has_otp_binary_path),
            ("daemon_host", daemon_host, has_daemon_host),
            ("daemon_nickname", daemon_nickname, has_daemon_nickname),
            ("daemon_server_password", daemon_server_password, has_daemon_server_password),
            ("daemon_my_key_pub", daemon_my_key_pub, has_daemon_my_key_pub),
            ("daemon_my_key_priv", daemon_my_key_priv, has_daemon_my_key_priv),
            ("daemon_initial_focus", daemon_initial_focus, has_daemon_initial_focus),
            ("daemon_port", daemon_port, has_daemon_port),
            ("daemon_otp", self.daemon_otp.to_string(), self.daemon_otp),
            ("daemon_no_server", switch(self.daemon_no_server).to_string(), self.daemon_no_server),
            ("connect_host", connect_host, has_connect_host),
            ("connect_nickname", connect_nickname, has_connect_nickname),
            ("connect_port", connect_port, has_connect_port),
            ("connect_ssl_ca", connect_ssl_ca, has_connect_ssl_ca),
        ]
    }

    /// Every accumulating (one-line-per-entry) key this file manages, and
    /// the full list of lines it should have right now, in the order
    /// they should appear - `BTreeSet` order for `server_superadmin` and
    /// `muted_voice`, file/insertion order for the rest, matching
    /// `dense_contents`/`parse` exactly. An entry that can't round-trip
    /// through a line-oriented file is dropped rather than written, same
    /// rule `IdStore::check_and_pin` applies.
    fn accumulating_fields(&self) -> Vec<(&'static str, Vec<String>)> {
        vec![
            (
                "server_superadmin",
                self.server_superadmin
                    .iter()
                    .filter(|n| crate::validation::nickname_is_registrable(n))
                    .cloned()
                    .collect(),
            ),
            (
                "muted_voice",
                self.muted_voice
                    .iter()
                    .filter(|n| crate::validation::is_storable(n))
                    .cloned()
                    .collect(),
            ),
            (
                "daemon_channel",
                self.daemon_channels
                    .iter()
                    .filter(|c| crate::validation::is_storable(c))
                    .cloned()
                    .collect(),
            ),
            (
                "direct_punch_to",
                self.direct_punch_to.iter().map(DirectPunchTarget::to_setting_value).collect(),
            ),
            ("direct_punch_channel", self.direct_punch_channels.clone()),
        ]
    }

    /// The full, fixed-order, no-comments dump every `save` used to
    /// write unconditionally - kept as `save`'s fallback for when there
    /// is no existing file for `patch_into` to work from.
    fn dense_contents(&self) -> String {
        let mut contents = String::new();
        for (key, value, add_when_missing) in self.scalar_fields() {
            if add_when_missing {
                contents.push_str(&format!("{key}={value}\n"));
            }
        }
        for (key, values) in self.accumulating_fields() {
            for value in values {
                contents.push_str(&format!("{key}={value}\n"));
            }
        }
        contents
    }

    /// Rewrites `existing`'s own lines in place - preserving every
    /// comment, blank line, section header and the file's own key order
    /// - replacing only the value half of a line whose key this struct
    /// manages (blank/off if that field is now unset - an existing line
    /// is never deleted just because the value it holds went back to
    /// nothing, see `scalar_fields`), and appending a line (grouped at
    /// the end, since there is no section header to slot it under) for a
    /// managed key that has no line yet *and* currently has a real value
    /// to write. A key this build doesn't recognize at all - an older or
    /// newer field, or a typo - is left exactly as found, the same
    /// tolerance `parse` already gives it.
    ///
    /// An accumulating key reuses its existing lines positionally: the
    /// Nth existing line becomes the Nth desired value, existing lines
    /// beyond the desired count are dropped, and desired values beyond
    /// what already had a line are inserted right after the last one
    /// that did (or appended at the end, same as a scalar, if the key
    /// had no lines at all).
    fn patch_into(&self, existing: &str) -> String {
        let scalars = self.scalar_fields();
        let accumulating = self.accumulating_fields();

        // How many times each accumulating key already appears, decided
        // up front so the main pass below can recognize "this is the
        // last occurrence" without a lookahead.
        let mut total_occurrences: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for line in existing.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, _)) = trimmed.split_once('=') {
                let key = key.trim();
                if accumulating.iter().any(|(k, _)| *k == key) {
                    *total_occurrences.entry(key).or_insert(0) += 1;
                }
            }
        }

        let mut seen_scalar: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut acc_seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let mut out: Vec<String> = Vec::new();

        for line in existing.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                out.push(line.to_string());
                continue;
            }
            let Some((raw_key, _)) = trimmed.split_once('=') else {
                out.push(line.to_string());
                continue;
            };
            let key = raw_key.trim();

            if let Some((_, value, _)) = scalars.iter().find(|(k, _, _)| *k == key) {
                seen_scalar.insert(key);
                out.push(format!("{key}={value}"));
                continue;
            }

            if let Some((_, desired)) = accumulating.iter().find(|(k, _)| *k == key) {
                let this_idx = *acc_seen.get(key).unwrap_or(&0);
                acc_seen.insert(key, this_idx + 1);
                if this_idx < desired.len() {
                    out.push(format!("{key}={}", desired[this_idx]));
                }
                // else: more existing lines than desired values - drop it.
                let is_last = this_idx + 1 == *total_occurrences.get(key).unwrap_or(&0);
                if is_last && desired.len() > this_idx + 1 {
                    for extra in &desired[this_idx + 1..] {
                        out.push(format!("{key}={extra}"));
                    }
                }
                continue;
            }

            // Not a key this build manages - left exactly as found.
            out.push(line.to_string());
        }

        for (key, value, add_when_missing) in &scalars {
            if !seen_scalar.contains(key) && *add_when_missing {
                out.push(format!("{key}={value}"));
            }
        }
        for (key, desired) in &accumulating {
            if !total_occurrences.contains_key(key) {
                for v in desired {
                    out.push(format!("{key}={v}"));
                }
            }
        }

        let mut result = out.join("\n");
        result.push('\n');
        result
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
            s.connect_using_ssl = ssl;
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
