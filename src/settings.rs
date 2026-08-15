//! A small local preferences store, backed by a flat `key=value` file at
//! `~/.aloo/settings` (`crate::platform::aloo_dir()`), following the same
//! plain-text-under-`~/.aloo` convention as `idstore`/`own_next_keys`
//! rather than pulling in a config-format crate for two fields.
//!
//! Currently holds only the global push-to-talk preferences (see
//! `crate::global_ptt`): whether it's enabled, and which shortcut to
//! register. Unlike `IdStore`, this file is written proactively - on first
//! run there is no session data to defer writing until, and the whole
//! point is that a user can find and edit the file even before ever
//! changing anything, so `load_or_create` creates it with the defaults
//! immediately rather than only in memory.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The default global push-to-talk shortcut, in the same syntax
/// `global_hotkey::hotkey::HotKey` parses directly (see
/// `crate::global_ptt::resolve_hotkey`).
pub const DEFAULT_GLOBAL_PTT_SHORTCUT: &str = "ctrl+alt+p";

/// Resolves the settings file path: `~/.aloo/settings`, same home
/// resolution as every other store in this app (`crate::platform`).
pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("settings")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub global_ptt_enabled: bool,
    pub global_ptt_shortcut: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self { global_ptt_enabled: true, global_ptt_shortcut: DEFAULT_GLOBAL_PTT_SHORTCUT.to_string() }
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
        let contents = format!(
            "global_ptt_enabled={}\nglobal_ptt_shortcut={}\n",
            self.global_ptt_enabled, self.global_ptt_shortcut
        );
        fs::write(path, contents)
    }
}
