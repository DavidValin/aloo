//! A directory-listing model with browser-style back/forward history -
//! the filesystem half of the in-TUI file browser. Shared by the connect
//! popup's key-file picker and `/file`'s send flow
//! (`tui::ui_connect_popup`, `tui::file_send`); rendering lives with those
//! popups (`tui::ui_connect_popup::render_file_browser`), this module only
//! reads directories and tracks navigation.

use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
}

/// A directory listing with browser-style back/forward history (distinct
/// from the `..` entry, which just moves up one level like any other
/// navigation and is itself recorded on the back stack).
pub struct FileBrowserState {
    pub current_dir: PathBuf,
    pub entries: Vec<DirEntryInfo>,
    pub selected: usize,
    history_back: Vec<PathBuf>,
    history_forward: Vec<PathBuf>,
}

impl FileBrowserState {
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        let entries = read_entries(&dir)?;
        Ok(Self {
            current_dir: dir,
            entries,
            selected: 0,
            history_back: Vec::new(),
            history_forward: Vec::new(),
        })
    }

    fn reload(&mut self) -> io::Result<()> {
        self.entries = read_entries(&self.current_dir)?;
        self.selected = 0;
        Ok(())
    }

    pub fn selected_entry(&self) -> Option<&DirEntryInfo> {
        self.entries.get(self.selected)
    }

    pub fn selected_path(&self) -> Option<PathBuf> {
        let entry = self.selected_entry()?;
        if entry.name == ".." {
            Some(
                self.current_dir
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| self.current_dir.clone()),
            )
        } else {
            Some(self.current_dir.join(&entry.name))
        }
    }

    pub fn select_next(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + self.entries.len() - 1) % self.entries.len();
        }
    }

    /// Enters the currently selected directory, pushing the old location
    /// onto the back-history stack and discarding any forward-history
    /// (a fresh navigation invalidates a stale "forward").
    pub fn navigate_into_selected(&mut self) -> io::Result<()> {
        let Some(target) = self.selected_path() else {
            return Ok(());
        };
        self.history_back.push(self.current_dir.clone());
        self.history_forward.clear();
        self.current_dir = target;
        self.reload()
    }

    pub fn go_back(&mut self) -> io::Result<bool> {
        let Some(prev) = self.history_back.pop() else {
            return Ok(false);
        };
        self.history_forward.push(self.current_dir.clone());
        self.current_dir = prev;
        self.reload()?;
        Ok(true)
    }

    pub fn go_forward(&mut self) -> io::Result<bool> {
        let Some(next) = self.history_forward.pop() else {
            return Ok(false);
        };
        self.history_back.push(self.current_dir.clone());
        self.current_dir = next;
        self.reload()?;
        Ok(true)
    }
}

fn read_entries(dir: &std::path::Path) -> io::Result<Vec<DirEntryInfo>> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.file_type()?.is_dir();
        if is_dir {
            dirs.push(DirEntryInfo { name, is_dir: true });
        } else {
            files.push(DirEntryInfo {
                name,
                is_dir: false,
            });
        }
    }
    dirs.sort_by(|a, b| a.name.cmp(&b.name));
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let mut entries = Vec::with_capacity(dirs.len() + files.len() + 1);
    if dir.parent().is_some() {
        entries.push(DirEntryInfo {
            name: "..".to_string(),
            is_dir: true,
        });
    }
    entries.extend(dirs);
    entries.extend(files);
    Ok(entries)
}
