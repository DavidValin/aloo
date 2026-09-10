//! Every shared-folder transfer this client has taken part in, in either
//! direction, kept on disk so the history survives a restart
//! (`docs/PROTOCOL.md` §7.8).
//!
//! One record per *request*: a download this side asked someone for, or
//! an upload someone asked of this side. Both ends therefore keep their
//! own account of the same exchange, which is what lets each of them
//! cancel it and each of them see what has passed between them without
//! either depending on the other being online.
//!
//! Deliberately not the message log: a shared transfer is not something
//! one person said to another, and putting it there would mix a fetch
//! into the conversation. `Ctrl+D` renders this whole log
//! (`client::tui::transfers_popup`); the per-peer Downloads tab renders
//! the downloads in it from one peer.
//!
//! The on-disk shape is this app's usual tab-separated flat file, with
//! every column after the first few independently optional, so a file
//! written by an older build still loads.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::validation::is_storable;

/// Most records kept on disk. A transfer is a line, so this is a
/// generous history in a small file; the oldest finished ones are
/// dropped past it rather than letting the file grow without limit.
pub const MAX_RECORDS: usize = 500;

/// Which way a transfer went, from this client's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Someone else's folder, coming here.
    Download,
    /// This side's shared folder, going to them.
    Upload,
}

impl TransferDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "down",
            Self::Upload => "up",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "down" => Some(Self::Download),
            "up" => Some(Self::Upload),
            _ => None,
        }
    }

    /// The arrow the popup marks the row with.
    pub fn marker(self) -> &'static str {
        match self {
            Self::Download => "\u{2193}",
            Self::Upload => "\u{2191}",
        }
    }
}

/// Where a transfer stands. Only `Asking` and `Running` are live; the
/// rest are how it ended, and are what a restart loads back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    /// Asked for, nothing back yet - there is no total to count against.
    Asking,
    Running,
    Completed,
    /// Stopped from this side, or from the other one.
    Cancelled,
    Failed(String),
}

impl TransferStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Asking | Self::Running)
    }

    pub fn label(&self) -> String {
        match self {
            Self::Asking => "asking...".to_string(),
            Self::Running => "transferring".to_string(),
            Self::Completed => "done".to_string(),
            Self::Cancelled => "cancelled".to_string(),
            Self::Failed(why) => format!("failed: {why}"),
        }
    }

    fn as_field(&self) -> String {
        match self {
            Self::Asking => "asking".to_string(),
            Self::Running => "running".to_string(),
            Self::Completed => "done".to_string(),
            Self::Cancelled => "cancelled".to_string(),
            // The reason travels with it, minus anything that would
            // break the line.
            Self::Failed(why) => format!("failed:{}", sanitize(why)),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "asking" => Some(Self::Asking),
            "running" => Some(Self::Running),
            "done" => Some(Self::Completed),
            "cancelled" => Some(Self::Cancelled),
            _ => s.strip_prefix("failed:").map(|why| Self::Failed(why.to_string())),
        }
    }

    /// How a live record loads after a restart: whatever was running when
    /// the process ended did not finish, and nothing is resuming it on
    /// its own, so it is history rather than a transfer still in flight.
    fn settled_for_load(self) -> Self {
        match self {
            Self::Asking | Self::Running => Self::Failed("interrupted by a restart".to_string()),
            other => other,
        }
    }
}

/// Strips the two characters a tab-separated line cannot carry.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| *c != '\t' && *c != '\n').collect()
}

/// One transfer, as both the popup and the file see it.
#[derive(Debug, Clone, PartialEq)]
pub struct TransferRecord {
    /// The request this is. Taken from the shared-folder request id,
    /// which is the *requester's* own counter - so it identifies a
    /// record only together with the peer and the direction, since every
    /// requester's first ask is number one.
    pub request_id: u64,
    pub direction: TransferDirection,
    /// Who the other side is, by nickname - the identity that survives a
    /// reconnect, since a `UserId` does not (§3).
    pub peer_name: String,
    pub share: String,
    /// What was asked for inside the share, empty for the whole share.
    pub rel_path: String,
    pub status: TransferStatus,
    pub files_total: Option<u32>,
    pub bytes_total: Option<u64>,
    pub files_done: u32,
    pub bytes_done: u64,
    /// Files that were already on disk at full size and never moved - a
    /// resumed download's skipped ones.
    pub files_skipped: u32,
    /// When it started, Unix seconds, so the list can be ordered by
    /// recency across restarts.
    pub started_unix: u64,
}

impl TransferRecord {
    /// `Photos/holiday`, or just `Photos` for a whole share.
    pub fn label(&self) -> String {
        if self.rel_path.is_empty() {
            self.share.clone()
        } else {
            format!("{}/{}", self.share, self.rel_path)
        }
    }

    /// How far along, `None` while there is nothing to count against.
    pub fn fraction(&self) -> Option<f64> {
        match (self.bytes_total, self.files_total) {
            (Some(total), _) if total > 0 => Some(self.bytes_done as f64 / total as f64),
            (_, Some(files)) if files > 0 => Some(self.files_done as f64 / files as f64),
            _ => None,
        }
    }

    /// Whether this row can be taken off the list. A live one has to be
    /// cancelled first, so nothing is forgotten while it is still moving.
    pub fn is_clearable(&self) -> bool {
        !self.status.is_active()
    }

    fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.request_id,
            self.direction.as_str(),
            sanitize(&self.peer_name),
            sanitize(&self.share),
            sanitize(&self.rel_path),
            self.status.as_field(),
            self.files_total.map(|v| v.to_string()).unwrap_or_default(),
            self.bytes_total.map(|v| v.to_string()).unwrap_or_default(),
            self.files_done,
            self.bytes_done,
            self.files_skipped,
            self.started_unix,
        )
    }

    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split('\t');
        let request_id = fields.next()?.parse().ok()?;
        let direction = TransferDirection::parse(fields.next()?)?;
        let peer_name = fields.next()?.to_string();
        if !is_storable(&peer_name) {
            return None;
        }
        let share = fields.next()?.to_string();
        let rel_path = fields.next().unwrap_or_default().to_string();
        let status = fields
            .next()
            .and_then(TransferStatus::parse)
            .unwrap_or(TransferStatus::Completed);
        let files_total = fields.next().and_then(|s| s.parse().ok());
        let bytes_total = fields.next().and_then(|s| s.parse().ok());
        let files_done = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let bytes_done = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let files_skipped = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let started_unix = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        Some(Self {
            request_id,
            direction,
            peer_name,
            share,
            rel_path,
            status,
            files_total,
            bytes_total,
            files_done,
            bytes_done,
            files_skipped,
            started_unix,
        })
    }
}

/// The log itself: every transfer, newest activity last, saved beside
/// this client's other stores.
#[derive(Debug, Default)]
pub struct TransferLog {
    path: PathBuf,
    records: Vec<TransferRecord>,
}

impl TransferLog {
    /// `<client home>/transfers` - beside `id_store` and the outbox
    /// rather than at a fixed path, so two clients sharing one
    /// `ALOO_HOME` keep their own histories (`outbox::dir_beside`'s own
    /// reasoning).
    pub fn path_beside(client_home: &Path) -> PathBuf {
        client_home
            .parent()
            .map(|dir| dir.join("transfers"))
            .unwrap_or_else(|| PathBuf::from("transfers"))
    }

    /// Reads what is there, tolerating anything that will not parse -
    /// the same forgiveness every other flat file here gives. A record
    /// that was still running when the process ended loads as
    /// interrupted: nothing is resuming it on its own.
    pub fn load(path: PathBuf) -> Self {
        let records = fs::read_to_string(&path)
            .map(|text| {
                text.lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(TransferRecord::parse)
                    .map(|mut r| {
                        r.status = r.status.settled_for_load();
                        r
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self { path, records }
    }

    pub fn new_empty(path: PathBuf) -> Self {
        Self {
            path,
            records: Vec::new(),
        }
    }

    pub fn save(&self) -> io::Result<()> {
        crate::platform::ensure_parent_dir(&self.path)?;
        let mut out = String::new();
        for record in &self.records {
            out.push_str(&record.to_line());
            out.push('\n');
        }
        fs::write(&self.path, out)
    }

    /// Saves, warning rather than failing - a history that could not be
    /// written is not worth ending a session over.
    pub fn save_or_warn(&self) {
        if let Err(e) = self.save() {
            crate::log_warn!("could not write the transfer history: {e}");
        }
    }

    pub fn records(&self) -> &[TransferRecord] {
        &self.records
    }

    /// Every record, most recent first, with everything still live above
    /// everything finished - what the popup and the Downloads tab list.
    pub fn rows(&self) -> Vec<&TransferRecord> {
        let mut rows: Vec<&TransferRecord> = self.records.iter().collect();
        rows.sort_by(|a, b| {
            b.status
                .is_active()
                .cmp(&a.status.is_active())
                .then(b.started_unix.cmp(&a.started_unix))
        });
        rows
    }

    /// One record, named the only way that is unique: direction, who it
    /// is with, and their request id. Two people's first download from
    /// this client are both request 1, so the peer is part of the name.
    pub fn get(
        &self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
    ) -> Option<&TransferRecord> {
        self.records.iter().find(|r| {
            r.direction == direction && r.peer_name == peer_name && r.request_id == request_id
        })
    }

    pub fn get_mut(
        &mut self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
    ) -> Option<&mut TransferRecord> {
        self.records.iter_mut().find(|r| {
            r.direction == direction && r.peer_name == peer_name && r.request_id == request_id
        })
    }

    /// The one download under `request_id`, whoever it is from - a
    /// download's id is *this* side's own counter, so it is unique on its
    /// own and the paths that only know the id can still find it.
    pub fn download_mut(&mut self, request_id: u64) -> Option<&mut TransferRecord> {
        self.records
            .iter_mut()
            .find(|r| r.direction == TransferDirection::Download && r.request_id == request_id)
    }

    pub fn download(&self, request_id: u64) -> Option<&TransferRecord> {
        self.records
            .iter()
            .find(|r| r.direction == TransferDirection::Download && r.request_id == request_id)
    }

    /// Opens a record, replacing any earlier one naming the same
    /// transfer - a restarted session's counter can reach an id it has
    /// used before.
    pub fn start(&mut self, record: TransferRecord) {
        self.records.retain(|r| {
            !(r.direction == record.direction
                && r.peer_name == record.peer_name
                && r.request_id == record.request_id)
        });
        self.records.push(record);
        self.trim();
    }

    /// Drops the oldest finished records once the file would grow past
    /// `MAX_RECORDS`. Live ones are never dropped.
    fn trim(&mut self) {
        while self.records.len() > MAX_RECORDS {
            let Some(oldest) = self
                .records
                .iter()
                .enumerate()
                .filter(|(_, r)| !r.status.is_active())
                .min_by_key(|(_, r)| r.started_unix)
                .map(|(i, _)| i)
            else {
                return;
            };
            self.records.remove(oldest);
        }
    }

    /// Removes one finished record. A live one is refused, which is what
    /// the popup's "cancel it first" rule rests on.
    pub fn clear(
        &mut self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
    ) -> bool {
        let clearable = self
            .get(direction, peer_name, request_id)
            .is_some_and(TransferRecord::is_clearable);
        if clearable {
            self.records.retain(|r| {
                !(r.direction == direction
                    && r.peer_name == peer_name
                    && r.request_id == request_id)
            });
        }
        clearable
    }

    /// Removes every finished record, leaving whatever is still moving.
    pub fn clear_finished(&mut self) -> usize {
        let before = self.records.len();
        self.records.retain(|r| r.status.is_active());
        before - self.records.len()
    }

    pub fn active(&self) -> usize {
        self.records.iter().filter(|r| r.status.is_active()).count()
    }

    pub fn active_in(&self, direction: TransferDirection) -> usize {
        self.records
            .iter()
            .filter(|r| r.direction == direction && r.status.is_active())
            .count()
    }
}

/// Now, in Unix seconds - what a record is stamped with.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
