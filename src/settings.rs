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
        fs::write(path, contents)
    }
}
