//! The requester's own record of what it has pulled, or is pulling, from
//! other people's shared folders (`docs/PROTOCOL.md` §7.8) - one item per
//! download asked for, whether that was a single file or a whole folder.
//!
//! Kept here rather than in the message log on purpose: a shared download
//! is something this side went and fetched, not something the other
//! person sent, so it belongs on a list of its own that can be paused,
//! resumed and cleared. Only a `/file` send still writes a row into the
//! conversation.
//!
//! Rendering lives in `super::shared_browser`, whose second tab this is;
//! what the session does with the actions is `session::shared`.

use std::time::{Duration, Instant};

use crate::proto::UserId;

use super::ui::UiState;

/// How long a byte counts towards the speed shown in the header - long
/// enough to ride out the gaps between chunks, short enough that the
/// figure follows a link that has just slowed down
/// (`UiState::fileshare_download_speed_bps`).
pub const SPEED_WINDOW: Duration = Duration::from_secs(3);

pub use crate::client::transfer_log::{
    TransferDirection, TransferRecord, TransferStatus as SharedDownloadStatus,
};

/// A download, as this module has always called it - one direction of a
/// `TransferRecord`, which is now the one shape both the per-peer
/// Downloads tab and the global `Ctrl+D` popup are drawn from
/// (`client::transfer_log`).
pub type SharedDownload = TransferRecord;

/// One byte-arrival sample, for the speed shown in the header.
#[derive(Debug, Clone, Copy)]
struct SpeedSample {
    at: Instant,
    bytes: u64,
}

/// A rolling window of bytes moved, behind each of the header's two
/// speed figures - one per direction (`UiState::tick_transfer_speeds`).
#[derive(Debug, Default)]
pub struct DownloadSpeed {
    samples: Vec<SpeedSample>,
}

impl DownloadSpeed {
    /// Records `bytes` newly written, and forgets anything older than
    /// `SPEED_WINDOW`.
    pub fn record(&mut self, bytes: u64, now: Instant) {
        self.samples.retain(|s| now.duration_since(s.at) < SPEED_WINDOW);
        if bytes > 0 {
            self.samples.push(SpeedSample { at: now, bytes });
        }
    }

    /// Bytes per second over the window, or `None` once nothing has
    /// arrived in it - which is what takes the indicator off the header
    /// rather than freezing it at the last figure.
    pub fn bytes_per_second(&mut self, now: Instant) -> Option<f64> {
        self.samples.retain(|s| now.duration_since(s.at) < SPEED_WINDOW);
        let total: u64 = self.samples.iter().map(|s| s.bytes).sum();
        if total == 0 {
            return None;
        }
        Some(total as f64 / SPEED_WINDOW.as_secs_f64())
    }
}

impl UiState {
    /// Opens a record for a transfer just started, in either direction -
    /// a download this side asked for, or an upload someone asked of it.
    pub fn start_transfer(
        &mut self,
        direction: TransferDirection,
        request_id: u64,
        peer_name: String,
        share: String,
        rel_path: String,
    ) {
        self.transfers.start(TransferRecord {
            request_id,
            direction,
            peer_name,
            share,
            rel_path,
            status: SharedDownloadStatus::Asking,
            files_total: None,
            bytes_total: None,
            files_done: 0,
            bytes_done: 0,
            files_skipped: 0,
            started_unix: crate::client::transfer_log::now_unix(),
        });
    }

    /// The download half of `start_transfer`, which is what the browser
    /// and its Downloads tab deal in.
    pub fn start_shared_download(
        &mut self,
        request_id: u64,
        peer: UserId,
        peer_name: String,
        share: String,
        rel_path: String,
    ) {
        let _ = peer;
        self.start_transfer(
            TransferDirection::Download,
            request_id,
            peer_name,
            share,
            rel_path,
        );
    }

    fn download_mut(&mut self, request_id: u64) -> Option<&mut SharedDownload> {
        self.transfers.download_mut(request_id)
    }

    pub fn shared_download(&self, request_id: u64) -> Option<&SharedDownload> {
        self.transfers.download(request_id)
    }

    /// What the peer's plan says a transfer covers, either direction.
    pub fn set_transfer_plan(
        &mut self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
        files: u32,
        bytes: u64,
    ) {
        if let Some(item) = self.transfers.get_mut(direction, peer_name, request_id) {
            item.files_total = Some(files);
            item.bytes_total = Some(bytes);
            if item.status == SharedDownloadStatus::Asking {
                item.status = SharedDownloadStatus::Running;
            }
        }
    }

    pub fn set_shared_download_plan(&mut self, request_id: u64, files: u32, bytes: u64) {
        if let Some(item) = self.transfers.download_mut(request_id) {
            item.files_total = Some(files);
            item.bytes_total = Some(bytes);
            if item.status == SharedDownloadStatus::Asking {
                item.status = SharedDownloadStatus::Running;
            }
        }
    }

    /// Bytes written for a file still arriving. `delta` is what is new,
    /// so the record and the header's speed window both gain only that.
    pub fn on_shared_download_progress(&mut self, request_id: u64, delta: u64, now: Instant) {
        if let Some(item) = self.download_mut(request_id)
            && item.status.is_active()
        {
            item.bytes_done = item.bytes_done.saturating_add(delta);
            item.status = SharedDownloadStatus::Running;
        }
        self.download_speed.record(delta, now);
    }

    /// One file of an upload has gone out - the sender's own progress,
    /// counted in bytes so its bar reads like the receiver's.
    ///
    /// `skipped` is one the requester refused because it already had it,
    /// which is what a resume is mostly made of: it still counts as one
    /// of the request's files and still fills the bar, but saying so is
    /// what stops the sender's row claiming to have sent bytes it never
    /// put on the wire.
    pub fn on_upload_file_done(
        &mut self,
        peer_name: &str,
        request_id: u64,
        size: u64,
        skipped: bool,
    ) {
        if let Some(item) = self
            .transfers
            .get_mut(TransferDirection::Upload, peer_name, request_id)
            // A file finishing after the transfer was cancelled must not
            // keep the counts moving - it was already in flight when the
            // other end gave up, and the row is history now.
            .filter(|item| item.status.is_active())
        {
            item.files_done += 1;
            item.bytes_done = item.bytes_done.saturating_add(size);
            if skipped {
                item.files_skipped += 1;
            }
            if item.status == SharedDownloadStatus::Asking {
                item.status = SharedDownloadStatus::Running;
            }
        }
    }

    /// One file of `request_id` is finished - `skipped` for one that was
    /// already on disk at full size and never transferred.
    pub fn on_shared_download_file_done(&mut self, request_id: u64, size: u64, skipped: bool) {
        if let Some(item) = self.download_mut(request_id) {
            item.files_done += 1;
            if skipped {
                item.files_skipped += 1;
                item.bytes_done = item.bytes_done.saturating_add(size);
            }
        }
    }

    /// A transfer is over, in either direction.
    pub fn finish_transfer(
        &mut self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
        error: Option<String>,
    ) {
        if let Some(item) = self.transfers.get_mut(direction, peer_name, request_id) {
            if !item.status.is_active() {
                return;
            }
            item.status = match error {
                Some(why) => SharedDownloadStatus::Failed(why),
                None => {
                    // A bar that stops short because a file was skipped
                    // or an estimate was off reads as a failure; one that
                    // genuinely finished shows full.
                    if let Some(total) = item.bytes_total {
                        item.bytes_done = item.bytes_done.max(total);
                    }
                    SharedDownloadStatus::Completed
                }
            };
        }
    }

    /// Puts a stopped download back to waiting on its owner, in place -
    /// what resuming does, since it is the same transfer asked for
    /// again rather than a new one. The counts start over because every
    /// file is offered again; the ones already on disk are refused as
    /// they arrive and counted as skipped (`already_have`).
    pub fn restart_shared_download(&mut self, request_id: u64) {
        if let Some(item) = self.transfers.download_mut(request_id) {
            item.status = SharedDownloadStatus::Asking;
            item.files_total = None;
            item.bytes_total = None;
            item.files_done = 0;
            item.bytes_done = 0;
            item.files_skipped = 0;
            item.started_unix = crate::client::transfer_log::now_unix();
        }
    }

    pub fn finish_shared_download(&mut self, request_id: u64, error: Option<String>) {
        let Some(item) = self.transfers.download_mut(request_id) else {
            return;
        };
        if !item.status.is_active() {
            return;
        }
        item.status = match error {
            Some(why) => SharedDownloadStatus::Failed(why),
            None => {
                if let Some(total) = item.bytes_total {
                    item.bytes_done = item.bytes_done.max(total);
                }
                SharedDownloadStatus::Completed
            }
        };
    }

    /// Marks a transfer stopped from this side. Returns whether there
    /// was a live one to stop, which is what decides whether the peer is
    /// told at all.
    pub fn cancel_transfer(
        &mut self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
    ) -> bool {
        match self.transfers.get_mut(direction, peer_name, request_id) {
            Some(item) if item.status.is_active() => {
                item.status = SharedDownloadStatus::Cancelled;
                true
            }
            _ => false,
        }
    }

    pub fn cancel_shared_download(&mut self, request_id: u64) -> bool {
        match self.transfers.download_mut(request_id) {
            Some(item) if item.status.is_active() => {
                item.status = SharedDownloadStatus::Cancelled;
                true
            }
            _ => false,
        }
    }

    /// Drops one finished record. A live one is never removed - it has
    /// to be cancelled first, so nothing is forgotten while it is still
    /// moving.
    pub fn clear_transfer(
        &mut self,
        direction: TransferDirection,
        peer_name: &str,
        request_id: u64,
    ) -> bool {
        self.transfers.clear(direction, peer_name, request_id)
    }

    pub fn clear_shared_download(&mut self, request_id: u64) -> bool {
        let Some(peer_name) = self
            .transfers
            .download(request_id)
            .map(|r| r.peer_name.clone())
        else {
            return false;
        };
        self.transfers
            .clear(TransferDirection::Download, &peer_name, request_id)
    }

    /// Drops every finished record, leaving whatever is still moving.
    pub fn clear_finished_shared_downloads(&mut self) -> usize {
        self.transfers.clear_finished()
    }


    /// Every download, whoever it is from - what the tab shows when it
    /// has no one peer in view.
    pub fn shared_download_rows(&self) -> Vec<&SharedDownload> {
        self.transfers
            .rows()
            .into_iter()
            .filter(|r| r.direction == TransferDirection::Download)
            .collect()
    }

    pub fn active_shared_downloads(&self) -> usize {
        self.transfers.active_in(TransferDirection::Download)
    }

    /// What the header shows while shared downloads are running - `None`
    /// when none are, or when nothing has arrived recently enough to put
    /// a number on.
    pub fn fileshare_download_speed_bps(&mut self, now: Instant) -> Option<f64> {
        if self.active_shared_downloads() == 0 {
            return None;
        }
        self.download_speed.bytes_per_second(now)
    }

    /// The same figure for what is going *out* of this client's shared
    /// folders. Both sides of a pair can show both at once: a peer can be
    /// serving one folder while pulling another.
    pub fn fileshare_upload_speed_bps(&mut self, now: Instant) -> Option<f64> {
        if self.transfers.active_in(TransferDirection::Upload) == 0 {
            return None;
        }
        self.upload_speed.bytes_per_second(now)
    }

    /// Bytes of a shared *upload* that have gone out - `delta` is what is
    /// new since the last report for that file.
    pub fn on_shared_upload_progress(&mut self, delta: u64, now: Instant) {
        self.upload_speed.record(delta, now);
    }
}

/// Bytes per second as the header spells it - kilobits, since that is
/// what a link's speed is quoted in and what `file_sharing_link_speed_kbps`
/// is set in.
pub fn kbps_of(bytes_per_second: f64) -> u64 {
    (bytes_per_second * 8.0 / 1000.0).round() as u64
}

impl UiState {
    /// Recomputes both of the header's speed figures, on the session's
    /// own ticker rather than at render time.
    pub fn tick_transfer_speeds(&mut self, now: Instant) {
        self.fileshare_download_kbps = self.fileshare_download_speed_bps(now).map(kbps_of);
        self.fileshare_upload_kbps = self.fileshare_upload_speed_bps(now).map(kbps_of);
    }
}
