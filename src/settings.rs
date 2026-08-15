//! A small local preferences store, backed by a flat `key=value` file at
//! `~/.aloo/settings` (`crate::platform::aloo_dir()`), following the same
//! plain-text-under-`~/.aloo` convention as `idstore`/`own_next_keys`
//! rather than pulling in a config-format crate for a handful of fields.
//!
//! Holds the global push-to-talk preferences (see `crate::global_ptt`):
//! whether it's enabled, and which shortcut to register. Unlike `IdStore`,
//! this file is written proactively - on first run there is no session
//! data to defer writing until, and the whole point is that a user can
//! find and edit the file even before ever changing anything, so
//! `load_or_create` creates it with the defaults immediately rather than
//! only in memory.
//!
//! Also holds the server's last-used `--bind`/`--port`/auth configuration
//! (`server_bind`, `server_port`, `server_auth`) - written every time
//! `--server` starts, so a server that crashes and gets relaunched with no
//! flags comes back up on the same address with the same auth instead of
//! resetting to the CLI defaults (see `main.rs::run_server`). Following
//! this file's existing plain-text convention, a `password` auth is
//! persisted as plaintext, same as every other field here - anyone who can
//! read `~/.aloo/settings` already controls this user's account on this
//! machine.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The default global push-to-talk shortcut, in the same syntax
/// `global_hotkey::hotkey::HotKey` parses directly (see
/// `crate::global_ptt::resolve_hotkey`).
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub global_ptt_enabled: bool,
    pub global_ptt_shortcut: String,
    pub server_bind: String,
    pub server_port: u16,
    pub server_auth: ServerAuth,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            global_ptt_enabled: true,
            global_ptt_shortcut: DEFAULT_GLOBAL_PTT_SHORTCUT.to_string(),
            server_bind: DEFAULT_BIND.to_string(),
            server_port: DEFAULT_PORT,
            server_auth: ServerAuth::None,
        }
    }
}

impl Settings {
    /// Loads `path` if it exists; if it doesn't (first run), writes the
    /// defaults to it immediately and returns them, so the file is always
    /// present - and editable - after this returns successfully. Lines
    /// that aren't a recognized `key=value` pair, or whose value doesn't
    /// parse, are skipped rather than failing the whole load, same
    /// tolerance as `IdStore::load` for a hand-edited or partially
    /// corrupted file.
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
            let Some((key, value)) = line.split_once('=') else { continue };
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
                "server_auth_rsa_keyfile" if !value.is_empty() => auth_rsa_keyfile = Some(value.to_string()),
                _ => {}
            }
        }
        settings.server_auth = match auth_type {
            Some("password") => auth_password.map(ServerAuth::Password).unwrap_or_default(),
            Some("rsa") => auth_rsa_keyfile.map(|f| ServerAuth::Rsa(PathBuf::from(f))).unwrap_or_default(),
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
        fs::write(path, contents)
    }
}
