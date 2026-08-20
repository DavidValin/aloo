//! A small local preferences store: a flat `key=value` file at
//! `~/.aloo/settings`, same plain-text convention as the other stores
//! rather than a config-format crate for a handful of fields.
//!
//! Holds the global push-to-talk preferences (`crate::client::global_ptt`).
//! Unlike `IdStore` this file is written proactively - `load_or_create`
//! writes the defaults on first run so a user can find and edit the file
//! before ever changing anything.
//!
//! Also holds the server's last-used `--bind`/`--port`/auth configuration,
//! written every time `--server` starts, so a crashed server relaunched
//! with no flags comes back on the same address with the same auth. A
//! `password` auth is persisted as plaintext like every other field -
//! anyone who can read `~/.aloo/settings` already controls this user's
//! account on this machine.

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

/// How the server that last ran on this machine was authenticating
/// clients - mirrors `server::AuthConfig`'s three variants, but holds a
/// `Rsa` keyfile *path* rather than a loaded `RsaPrivateKey`, since this is
/// what actually round-trips through a text file (`main.rs::run_server`
/// reloads the key from this path each time it falls back to it).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ServerAuth {
    #[default]
    None,
    Password(String),
    Rsa(PathBuf),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub global_ptt_enabled: bool,
    pub global_ptt_shortcut: String,
    pub server_bind: String,
    pub server_port: u16,
    pub server_auth: ServerAuth,
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
    pub daemon_server_auth_type: Option<String>,
    pub daemon_server_password: Option<String>,
    pub daemon_server_rsa_keyfile: Option<String>,
    pub daemon_my_key_pub: Option<String>,
    pub daemon_my_key_priv: Option<String>,
    /// One `daemon_channel=<name>[,<password>]` line per entry, in the
    /// order they should be joined - the same accumulating-key shape (and
    /// the same reason for it) as `muted_voice`, and the same
    /// `name,password` syntax `--channel` takes.
    pub daemon_channels: Vec<String>,
    /// `channel:<name>` or a bare nickname - parsed by
    /// `client::daemon::DaemonFocus::parse`, which owns that grammar.
    pub daemon_focus: Option<String>,
    pub daemon_otp: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            global_ptt_enabled: true,
            global_ptt_shortcut: DEFAULT_GLOBAL_PTT_SHORTCUT.to_string(),
            server_bind: DEFAULT_BIND.to_string(),
            server_port: DEFAULT_PORT,
            server_auth: ServerAuth::None,
            otp_binary_path: None,
            otp_keypair_size_mb: DEFAULT_OTP_KEYPAIR_SIZE_MB,
            otp_low_key_warn_pct: DEFAULT_OTP_LOW_KEY_WARN_PCT,
            otp_status_poll_interval: DEFAULT_OTP_STATUS_POLL_INTERVAL,
            muted_voice: BTreeSet::new(),
            daemon_host: None,
            daemon_port: None,
            daemon_nickname: None,
            daemon_server_auth_type: None,
            daemon_server_password: None,
            daemon_server_rsa_keyfile: None,
            daemon_my_key_pub: None,
            daemon_my_key_priv: None,
            daemon_channels: Vec::new(),
            daemon_focus: None,
            daemon_otp: false,
        }
    }
}

impl Settings {
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
        // `server_auth`'s three lines can appear in any order (or be
        // partly missing on a hand-edited file), so its pieces are
        // gathered here and only assembled into one `ServerAuth` once the
        // whole file has been read.
        let mut auth_type: Option<&str> = None;
        let mut auth_password: Option<String> = None;
        let mut auth_rsa_keyfile: Option<String> = None;
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
                "server_auth_type" => auth_type = Some(value),
                "server_auth_password" => auth_password = Some(value.to_string()),
                "server_auth_rsa_keyfile" if !value.is_empty() => {
                    auth_rsa_keyfile = Some(value.to_string())
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
                "daemon_server_auth_type" if !value.is_empty() => {
                    settings.daemon_server_auth_type = Some(value.to_string())
                }
                "daemon_server_password" => {
                    settings.daemon_server_password = Some(value.to_string())
                }
                "daemon_server_rsa_keyfile" if !value.is_empty() => {
                    settings.daemon_server_rsa_keyfile = Some(value.to_string())
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
                "daemon_focus" if !value.is_empty() => {
                    settings.daemon_focus = Some(value.to_string())
                }
                "daemon_otp" => {
                    if let Ok(b) = value.parse::<bool>() {
                        settings.daemon_otp = b;
                    }
                }
                _ => {}
            }
        }
        settings.server_auth = match auth_type {
            Some("password") => auth_password.map(ServerAuth::Password).unwrap_or_default(),
            Some("rsa") => auth_rsa_keyfile
                .map(|f| ServerAuth::Rsa(PathBuf::from(f)))
                .unwrap_or_default(),
            _ => ServerAuth::None,
        };
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
        match &self.server_auth {
            ServerAuth::None => contents.push_str("server_auth_type=none\n"),
            ServerAuth::Password(pw) => {
                contents.push_str("server_auth_type=password\n");
                contents.push_str(&format!("server_auth_password={pw}\n"));
            }
            ServerAuth::Rsa(keyfile) => {
                contents.push_str("server_auth_type=rsa\n");
                contents.push_str(&format!("server_auth_rsa_keyfile={}\n", keyfile.display()));
            }
        }
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
        optional("daemon_server_auth_type", &self.daemon_server_auth_type);
        optional("daemon_server_password", &self.daemon_server_password);
        optional("daemon_server_rsa_keyfile", &self.daemon_server_rsa_keyfile);
        optional("daemon_my_key_pub", &self.daemon_my_key_pub);
        optional("daemon_my_key_priv", &self.daemon_my_key_priv);
        optional("daemon_focus", &self.daemon_focus);
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
        fs::write(path, contents)
    }

    /// The `server_key` a daemon should connect with, assembled from the
    /// three `daemon_server_*` keys - which, like `server_auth`'s own
    /// three, may appear in any order or be partly missing on a
    /// hand-edited file.
    pub fn daemon_server_key(&self) -> crate::client::connect::ServerKeySelection {
        use crate::client::connect::ServerKeySelection;
        match self.daemon_server_auth_type.as_deref() {
            Some("password") => self
                .daemon_server_password
                .clone()
                .map(ServerKeySelection::Password)
                .unwrap_or(ServerKeySelection::None),
            Some("rsa") => self
                .daemon_server_rsa_keyfile
                .clone()
                .map(|f| ServerKeySelection::Rsa(PathBuf::from(f)))
                .unwrap_or(ServerKeySelection::None),
            _ => ServerKeySelection::None,
        }
    }

    /// Records `selection` as the three `daemon_server_*` keys, clearing
    /// whichever of them no longer applies - so switching a daemon from
    /// password to rsa auth doesn't leave the old password behind in the
    /// file for the next resolve to pick up.
    pub fn set_daemon_server_key(&mut self, selection: &crate::client::connect::ServerKeySelection) {
        use crate::client::connect::ServerKeySelection;
        self.daemon_server_password = None;
        self.daemon_server_rsa_keyfile = None;
        match selection {
            ServerKeySelection::None => self.daemon_server_auth_type = Some("none".to_string()),
            ServerKeySelection::Password(pw) => {
                self.daemon_server_auth_type = Some("password".to_string());
                self.daemon_server_password = Some(pw.clone());
            }
            ServerKeySelection::Rsa(file) => {
                self.daemon_server_auth_type = Some("rsa".to_string());
                self.daemon_server_rsa_keyfile = Some(file.display().to_string());
            }
        }
    }

    /// Records the keybundle a daemon connects with. Only `pq_hybrid` has
    /// files to record - a daemon never uses any other `my_key` type (see
    /// `client::daemon::resolve_my_key`), so the other variants clear the
    /// keys rather than inventing a representation for them.
    pub fn set_daemon_my_key(&mut self, selection: &crate::client::connect::MyKeySelection) {
        use crate::client::connect::MyKeySelection;
        match selection {
            MyKeySelection::PqHybrid {
                file_pub,
                file_priv,
            } => {
                self.daemon_my_key_pub = Some(file_pub.display().to_string());
                self.daemon_my_key_priv = Some(file_priv.display().to_string());
            }
            _ => {
                self.daemon_my_key_pub = None;
                self.daemon_my_key_priv = None;
            }
        }
    }

    /// The daemon-key counterpart of `update_muted_voice`: applies `edit`
    /// to what is on disk right now and writes it back.
    ///
    /// Same reasoning, and the same importance. A daemon persists its
    /// resolved configuration at every start, and `/mute-voice` writes
    /// this file mid-session - two writers on one file, where a
    /// whole-struct save from either would silently revert the other.
    pub fn update_daemon(path: &Path, edit: impl FnOnce(&mut Self)) -> io::Result<()> {
        let mut settings = Self::load_or_create(path)?;
        edit(&mut settings);
        settings.save(path)
    }

    /// Applies `edit` to the *on-disk* muted-voice set and writes the file
    /// back, rather than serializing this process's whole in-memory
    /// `Settings`.
    ///
    /// This distinction is the whole point. `save` writes every field it
    /// holds, which was safe while `~/.aloo/settings` was a cold file -
    /// written from exactly one place (`main.rs`'s `--server` startup),
    /// once, at launch. `/mute-voice` makes it a file mutated *during* a
    /// session, and daemon mode means an `aloo` process is running
    /// continuously, so a bare `save` here would let a mute silently
    /// revert whatever `server_bind`/`server_port`/auth a concurrently
    /// started `aloo --server` had just recorded - and vice versa. Reading
    /// immediately before writing keeps each writer to its own keys.
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
