//! Shared folders over the direct link (`docs/PROTOCOL.md` §7.8): the
//! sealed payloads both sides exchange, the owner-side filesystem work
//! (listing a folder, walking one for download, and confining every
//! peer-supplied path to the share it names), the upload pacer shared
//! sends are held under, and the requester's download layout.
//!
//! Nothing here touches the session or the network - `client::session::
//! shared` owns the wire exchange, and reuses the ordinary file-transfer
//! machinery (`client::file_transfer`, `client::direct_message::
//! handle_send_file`) for the bytes themselves: a shared file is an
//! ordinary `FileOffer` (or, under a live pad session, `OtpFileOffer`)
//! preceded by a `SharedFileTag` naming the request it answers, which is
//! what lets the requester accept it without a popup.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::settings::SharedFolder;

/// Longest folder listing one `SharedListResponse` carries; a folder with
/// more entries is cut here and says so (`SharedListResponse::truncated`).
/// A response is a single sealed envelope on a reliable frame, so it has
/// to stay bounded regardless of what a peer chooses to share.
pub const MAX_SHARED_ENTRIES_PER_RESPONSE: usize = 500;

/// Longest `rel_path` (in characters) a request may name - anything over
/// it is refused as `SharedError::NotFound` before the filesystem is
/// asked, so an unbounded string from a peer never becomes an unbounded
/// path lookup.
pub const MAX_SHARE_REL_PATH_CHARS: usize = 1024;

/// Most files one folder download will ever queue. A folder past this is
/// sent up to the cap and finished with `SharedDownloadDone { error:
/// Some(TooLarge) }` rather than walked without limit.
pub const MAX_SHARED_FILES_PER_DOWNLOAD: usize = 10_000;

/// How far ahead of its steady rate the pacer lets a burst run: one
/// window of `file_transfer::FILE_CHUNK_BYTES`-sized chunks, so a send
/// that has been idle starts promptly rather than one chunk per tick.
pub const PACER_BURST_BYTES: u64 = 64 * crate::client::file_transfer::FILE_CHUNK_BYTES as u64;

// ---------------------------------------------------------------------
// Sealed payloads (§7.8) - each is the plaintext of an `Envelope` whose
// `Content` tag names it, carried on the matching `P2pPayload` variant.
// ---------------------------------------------------------------------

/// One folder a peer may see, as `Content::SharedFolders` lists them -
/// only the name (`SharedFolder::name`), never the owner's real path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFolderSummary {
    pub name: String,
}

/// `Content::SharedListRequest`: "what is in `share`/`rel_path`?".
/// `rel_path` is `/`-separated on the wire whatever OS either side runs,
/// and empty for the share's root. `request_id` is the requester's own
/// token, echoed on the response so it can be matched to the browser
/// view that asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedListRequest {
    pub request_id: u64,
    pub share: String,
    pub rel_path: String,
}

/// One row of a listing: the four things the browser shows
/// (`<name> <created> <updated> <size>`) plus whether it can be entered.
/// Times are Unix seconds, `None` where the filesystem has none (many
/// Linux filesystems record no creation time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub created_unix: Option<u64>,
    pub modified_unix: Option<u64>,
}

/// Why a listing or download could not be served. Deliberately coarse:
/// `NotAllowed` covers both "you may not see this share" and "that path
/// escapes it", so the answer never confirms what exists outside what
/// the requester was shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharedError {
    /// Stopped from the other side - the owner withdrew an upload, or
    /// the requester gave up. Distinct from a failure: nothing went
    /// wrong, someone decided.
    Cancelled,
    /// The share named is not one this requester was announced - it does
    /// not exist, or it exists and is not theirs. Deliberately one answer
    /// for both: telling them apart would let any linked peer probe for
    /// the names of folders they were never shown.
    NoSuchShare,
    /// The path named escapes the share it claims to be inside.
    NotAllowed,
    /// The share itself cannot be read on the owner's machine - the
    /// folder they named does not exist, or is not readable. Their
    /// configuration is at fault, not the request, so it is worth
    /// telling both sides apart from an item simply being gone.
    ShareUnavailable,
    NotFound,
    Io,
    TooLarge,
}

impl SharedError {
    pub fn describe(self) -> &'static str {
        match self {
            SharedError::Cancelled => "stopped by the other side",
            SharedError::NoSuchShare => "that folder is not shared with you",
            SharedError::NotAllowed => "you are not allowed to see that",
            SharedError::ShareUnavailable => {
                "the folder they shared is not readable on their machine"
            }
            SharedError::NotFound => "not found",
            SharedError::Io => "the owner could not read it",
            SharedError::TooLarge => "the folder has more files than one download may carry",
        }
    }
}

/// `Content::SharedListResponse`: the answer to `SharedListRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedListResponse {
    pub request_id: u64,
    pub entries: Vec<SharedEntry>,
    pub truncated: bool,
    pub error: Option<SharedError>,
}

/// `Content::SharedDownloadRequest`: "send me `share`/`rel_path`" - a
/// single file, or a whole folder (every file under it, recursively).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedDownloadRequest {
    pub request_id: u64,
    pub share: String,
    pub rel_path: String,
}

/// `Content::SharedFileTag`: sent by the owner immediately before the
/// `FileOffer`/`OtpFileOffer` that carries the file itself, on the same
/// reliable, ordered link, so it always lands first. Names the request
/// the offer answers and where under it the file belongs; the requester
/// accepts an offer whose `stream_id` it has a tag for without asking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFileTag {
    pub request_id: u64,
    pub stream_id: u64,
    pub rel_path: String,
}

/// `Content::SharedDownloadPlan`: what the request turned out to cover,
/// sent once the owner has walked it and before the first file goes out.
/// The requester's progress bar counts against this rather than against
/// files as they appear, so it is honest from the first byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedDownloadPlan {
    pub request_id: u64,
    pub files: u32,
    pub bytes: u64,
}

/// `Content::SharedDownloadCancel`: the requester has given up. The
/// owner drops whatever is still queued for `request_id` and stops; a
/// file already in flight is left to finish or fail on its own, since
/// the transport has no way to unsend it and the requester discards it
/// either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedDownloadCancel {
    pub request_id: u64,
}

/// `Content::SharedDownloadDone`: the owner has offered every file the
/// request covered (`files` of them), or could not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedDownloadDone {
    pub request_id: u64,
    pub files: u32,
    pub error: Option<SharedError>,
}

// ---------------------------------------------------------------------
// Owner side: which shares a peer may see, and what is in them
// ---------------------------------------------------------------------

/// The share names `nickname` may see, in settings order - what an
/// announce to them lists, and what every request from them is checked
/// against afresh.
pub fn visible_share_names(shares: &[SharedFolder], nickname: &str) -> Vec<String> {
    shares
        .iter()
        .filter(|s| s.access.allows(nickname))
        .map(SharedFolder::name)
        .collect()
}

/// The share `nickname` may see under `name`, or `NoSuchShare` - the one
/// answer for both "there is no such folder" and "there is, and it is not
/// yours", so that a request can never be used to find out which
/// (`SharedError::NoSuchShare`).
pub fn find_visible_share<'a>(
    shares: &'a [SharedFolder],
    nickname: &str,
    name: &str,
) -> Result<&'a SharedFolder, SharedError> {
    shares
        .iter()
        .find(|s| s.name() == name && s.access.allows(nickname))
        .ok_or(SharedError::NoSuchShare)
}

/// Every canonicalized root that `nickname` may **not** see - what makes
/// overlapping shares resolve to the most restrictive of them.
///
/// Shares can nest: `/work` shared with everyone and `/work/payroll`
/// shared with one person is a perfectly ordinary pair of lines to
/// write, and the narrower one is obviously meant to be the stricter
/// statement. Without this, browsing the wider share would walk straight
/// into the narrower one and hand over exactly the folder its own line
/// was drawn around. Every listing, walk and path resolution is filtered
/// against these, so the answer is the same whichever way the folder is
/// reached.
///
/// Canonicalized, because that is the only form in which two spellings
/// of one directory compare equal - and a root that cannot be resolved
/// is simply skipped: it cannot contain anything to hide.
pub fn forbidden_roots(shares: &[SharedFolder], nickname: &str) -> Vec<PathBuf> {
    shares
        .iter()
        .filter(|s| !s.access.allows(nickname))
        .filter_map(|s| s.root().canonicalize().ok())
        .collect()
}

/// Whether `path` (already canonicalized) is inside a share this
/// requester may not see - the test every entry has to pass, however it
/// was reached.
pub fn is_forbidden(path: &Path, forbidden: &[PathBuf]) -> bool {
    forbidden.iter().any(|root| path.starts_with(root))
}

/// Confines a peer-supplied `rel_path` to `root`: the path is split at
/// `/`, every component must be a plain name, and the result must still
/// lie under `root` once both are canonicalized - which is what catches a
/// symlink inside the share pointing out of it. Refused paths answer
/// `NotAllowed`; a path that does not exist answers `NotFound`.
///
/// `/` is the separator on the wire whatever either side runs, so a
/// component can never contain one. What *else* is refused is this
/// machine's own rule rather than a fixed list, because the owner is the
/// only side that knows what its filesystem means: `\` and `:` are a
/// separator and a drive/stream marker on Windows and are refused there,
/// while on Linux and macOS both are ordinary characters in a filename
/// and a file named with one is served like any other - it would
/// otherwise appear in a listing and then be silently missing from the
/// download. A NUL byte is refused everywhere, being legal in no path at
/// all. Confinement itself never rests on this: the canonicalized
/// containment check below is what actually enforces it.
pub fn resolve_shared_path(
    root: &Path,
    rel_path: &str,
    forbidden: &[PathBuf],
) -> Result<PathBuf, SharedError> {
    if rel_path.chars().count() > MAX_SHARE_REL_PATH_CHARS {
        return Err(SharedError::NotFound);
    }
    let mut candidate = root.to_path_buf();
    for component in rel_path.split('/') {
        if component.is_empty() {
            continue;
        }
        let refused_here: &[char] = if cfg!(windows) {
            &['\\', '\0', ':']
        } else {
            &['\0']
        };
        if component == "."
            || component == ".."
            || component.chars().any(|c| refused_here.contains(&c))
        {
            return Err(SharedError::NotAllowed);
        }
        candidate.push(component);
    }
    // The share's own root failing is the owner's configuration being
    // wrong, not this request - said apart so each side is told something
    // it can act on (`share_root_problem`).
    let root_real = root.canonicalize().map_err(|_| SharedError::ShareUnavailable)?;
    let real = candidate.canonicalize().map_err(|_| SharedError::NotFound)?;
    if !real.starts_with(&root_real) {
        return Err(SharedError::NotAllowed);
    }
    if is_forbidden(&real, forbidden) {
        // Inside a narrower share this requester may not see: the most
        // restrictive of two overlapping shares is what applies, and it
        // applies here rather than only in the listing, so reaching for
        // the path directly is refused exactly as browsing to it is.
        return Err(SharedError::NoSuchShare);
    }
    Ok(real)
}

fn unix_seconds(time: std::io::Result<std::time::SystemTime>) -> Option<u64> {
    time.ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// One directory's listing, folders first then files, each group by
/// name, capped at `MAX_SHARED_ENTRIES_PER_RESPONSE` (the flag says
/// whether the cap cut anything). Entries whose metadata cannot be read
/// are skipped rather than failing the whole listing.
pub fn list_directory(
    root: &Path,
    rel_path: &str,
    forbidden: &[PathBuf],
) -> Result<(Vec<SharedEntry>, bool), SharedError> {
    let dir = resolve_shared_path(root, rel_path, forbidden)?;
    let read = std::fs::read_dir(&dir).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => SharedError::NotFound,
        _ => SharedError::Io,
    })?;
    // What every entry has to resolve inside. Taken once here rather
    // than per entry, and from the share's own root rather than from
    // `dir`, so a listing deep inside the share is held to the same
    // boundary as one at the top of it.
    let root_real = root.canonicalize().map_err(|_| SharedError::ShareUnavailable)?;
    let mut entries: Vec<SharedEntry> = read
        .flatten()
        .filter_map(|entry| {
            // An entry is listed only if it is genuinely *in* the share:
            // a symlink pointing out of it, or a nested share this
            // requester may not see, is left out entirely rather than
            // shown and then refused. Listing and downloading have to
            // agree - anything visible here must be fetchable, and
            // anything unfetchable must not be visible, or the listing
            // itself becomes a way to learn what is outside.
            let real = entry.path().canonicalize().ok()?;
            if !real.starts_with(&root_real) || is_forbidden(&real, forbidden) {
                return None;
            }
            let meta = entry.metadata().ok()?;
            Some(SharedEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                size: if meta.is_dir() { 0 } else { meta.len() },
                created_unix: unix_seconds(meta.created()),
                modified_unix: unix_seconds(meta.modified()),
            })
        })
        .collect();
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    let truncated = entries.len() > MAX_SHARED_ENTRIES_PER_RESPONSE;
    entries.truncate(MAX_SHARED_ENTRIES_PER_RESPONSE);
    Ok((entries, truncated))
}

/// One file a download request resolved to: where it sits under the
/// share (`/`-separated, what the requester files it under), the real
/// path to read, and its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadFile {
    pub rel_path: String,
    pub path: PathBuf,
    pub size: u64,
}

/// Every file `rel_path` covers: the one file it names, or every file
/// under the folder it names, walked depth-first in name order. Symlinks
/// are followed only while they stay inside the share
/// (`resolve_shared_path` is applied per entry). Stops at
/// `MAX_SHARED_FILES_PER_DOWNLOAD` with `TooLarge`, keeping what was
/// collected so far so the caller can still send those.
///
/// A directory holding more entries than one listing may carry is walked
/// only as far as that cap reaches, and says so with `TooLarge` rather
/// than reporting a complete download of an incomplete folder. The
/// directory stack is bounded by the same file cap, so a tree of empty
/// directories cannot walk without limit either.
pub fn collect_download(
    root: &Path,
    rel_path: &str,
    forbidden: &[PathBuf],
) -> (Vec<DownloadFile>, Option<SharedError>) {
    let start = match resolve_shared_path(root, rel_path, forbidden) {
        Ok(path) => path,
        Err(e) => return (Vec::new(), Some(e)),
    };
    let base = rel_path.trim_matches('/').to_string();
    let mut out = Vec::new();
    let Ok(meta) = std::fs::metadata(&start) else {
        return (out, Some(SharedError::Io));
    };
    if !meta.is_dir() {
        out.push(DownloadFile {
            rel_path: base,
            path: start,
            size: meta.len(),
        });
        return (out, None);
    }
    let mut pending = vec![base];
    let mut cut_short = false;
    while let Some(dir_rel) = pending.pop() {
        if pending.len() > MAX_SHARED_FILES_PER_DOWNLOAD {
            return (out, Some(SharedError::TooLarge));
        }
        let Ok((entries, truncated)) = list_directory(root, &dir_rel, forbidden) else {
            continue;
        };
        // The listing cap cut this directory, so files under it are being
        // left behind - reported at the end rather than passed off as a
        // complete download.
        cut_short |= truncated;
        // Folders are pushed in reverse so the stack pops them in name
        // order, and files land before the folders they sit beside.
        let (dirs, files): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| e.is_dir);
        for file in files {
            if out.len() >= MAX_SHARED_FILES_PER_DOWNLOAD {
                return (out, Some(SharedError::TooLarge));
            }
            let rel = join_rel(&dir_rel, &file.name);
            let Ok(path) = resolve_shared_path(root, &rel, forbidden) else {
                continue;
            };
            out.push(DownloadFile {
                rel_path: rel,
                path,
                size: file.size,
            });
        }
        for dir in dirs.into_iter().rev() {
            pending.push(join_rel(&dir_rel, &dir.name));
        }
    }
    (out, cut_short.then_some(SharedError::TooLarge))
}

/// `a/b` from `a` and `b`, with an empty prefix yielding just `b`.
pub fn join_rel(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// The parent of a `/`-separated `rel_path`, or empty at the top.
pub fn parent_rel(rel_path: &str) -> String {
    match rel_path.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => String::new(),
    }
}

/// Why a configured share cannot be served, in words the owner can act
/// on - `None` when the folder is there and readable. Checked when a
/// share is configured and again at session start, because the
/// requester's own answer ("the folder they shared is not readable on
/// their machine") can only ever reach the wrong person.
///
/// A relative path is called out on its own: it resolves against
/// whatever directory the process happens to have been started in, so it
/// may work once and never again, which is far more confusing than a
/// path that is simply wrong.
///
/// What a share path may be is the same on all three platforms: an
/// absolute path in that platform's own spelling (`/srv/Public`,
/// `C:\Users\me\Public`, `\\server\share\Public`) or one starting
/// `~/`, which is expanded from `HOME` or, on Windows, `USERPROFILE`
/// (`platform::expand_tilde`). A shell's own variable syntax - `$HOME`
/// or `%USERPROFILE%` - is *not* expanded by aloo in either spelling,
/// and is named here rather than left to fail as a missing folder.
pub fn share_root_problem(folder: &SharedFolder) -> Option<String> {
    let written = folder.path.trim();
    let windows_variable = written.starts_with('%') && written[1..].contains('%');
    if written.starts_with('$') || written.contains("${") || windows_variable {
        return Some(format!(
            "{written:?} looks like a shell variable, which aloo does not expand - write the path out, or start it with ~/"
        ));
    }
    let root = folder.root();
    if root.is_relative() {
        return Some(format!(
            "{written:?} is a relative path, so it depends on where aloo was started - use an absolute path, or one starting with ~/"
        ));
    }
    match std::fs::metadata(&root) {
        Ok(meta) if meta.is_dir() => None,
        Ok(_) => Some(format!("{} is a file, not a folder", root.display())),
        Err(e) => Some(format!("{} cannot be read ({e})", root.display())),
    }
}

// ---------------------------------------------------------------------
// Requester side: where a downloaded file lands
// ---------------------------------------------------------------------

/// `<aloo home>/downloads/fileshare/<owner nickname>` - where everything
/// pulled from someone's shared folders lands, kept apart from
/// `file_transfer::default_download_dir()` so a browsed download and a
/// file someone sent with `/file` never land in the same heap.
pub fn fileshare_download_dir(owner_nickname: &str) -> PathBuf {
    crate::client::file_transfer::default_download_dir()
        .join("fileshare")
        .join(crate::client::file_transfer::safe_filename(owner_nickname))
}

/// `<fileshare dir>/<share>/<rel_path>` - the folder layout as the owner
/// has it, so downloading a folder called `test` gives a folder called
/// `test` with its own subfolders under it, rather than a flattened pile
/// of files. The share's own name is the top of it, which is what makes
/// two shares holding a `notes.txt` land in two different places.
///
/// Every component goes through `file_transfer::safe_filename`, so
/// nothing a peer sent - a `..`, an absolute path, a Windows-illegal
/// name - can name a path outside the directory this builds from.
pub fn download_dest(downloads: &Path, owner_nickname: &str, share: &str, rel_path: &str) -> PathBuf {
    use crate::client::file_transfer::safe_filename;
    let mut dest = downloads.join(safe_filename(owner_nickname)).join(safe_filename(share));
    for component in rel_path.split('/').filter(|c| !c.is_empty()) {
        dest.push(safe_filename(component));
    }
    dest
}

/// Where a shared file is written *while it is arriving* - the final
/// path with `PARTIAL_SUFFIX` appended, in the same directory so the
/// move into place at the end is a rename rather than a copy across
/// filesystems.
///
/// A transfer that is cancelled, fails, or dies with the process
/// therefore never leaves something that looks like the file it was
/// going to be: what is on disk is either the whole file under its own
/// name, or a `.part` nobody will mistake for it.
pub fn partial_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(PARTIAL_SUFFIX);
    dest.with_file_name(name)
}

/// Appended to a shared download's destination while it is in flight
/// (`partial_path`).
pub const PARTIAL_SUFFIX: &str = ".part";

// ---------------------------------------------------------------------
// The upload pacer
// ---------------------------------------------------------------------

/// The bytes-per-second cap `file_sharing_link_speed_kbps` and
/// `file_sharing_max_pct` work out to; `0` for an undeclared speed, which
/// `SharePacer` reads as "no cap".
pub fn rate_from_settings(link_speed_kbps: u32, max_pct: u8) -> u64 {
    (link_speed_kbps as u64) * 1000 / 8 * (max_pct.clamp(1, 100) as u64) / 100
}

/// A token bucket every shared-folder send worker debits per chunk
/// (`file_transfer::spawn_send_file_worker`), so however many shared
/// transfers run at once their total stays at the configured rate. The
/// rate is an atomic so a settings change applies to workers already
/// running; the balance and its clock sit behind a mutex only the
/// workers touch.
pub struct SharePacer {
    rate: AtomicU64,
    state: Mutex<PacerState>,
}

/// The bucket's balance: bytes that may be sent immediately (up to
/// `PACER_BURST_BYTES`), negative once a chunk has been sent on credit,
/// and the instant it was last brought up to date.
#[derive(Debug, Clone, Copy)]
pub struct PacerState {
    pub balance: i64,
    pub last: Instant,
}

impl SharePacer {
    pub fn new(bytes_per_sec: u64) -> Self {
        Self {
            rate: AtomicU64::new(bytes_per_sec),
            state: Mutex::new(PacerState {
                balance: PACER_BURST_BYTES as i64,
                last: Instant::now(),
            }),
        }
    }

    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    /// Applies a new cap on the spot; `0` lifts it.
    pub fn set_rate(&self, bytes_per_sec: u64) {
        self.rate.store(bytes_per_sec, Ordering::Relaxed);
    }

    /// Debits `bytes` and returns how long the caller must wait before
    /// sending them - the pure step `acquire` sleeps on, taking the clock
    /// as an argument so it can be pinned without waiting.
    pub fn debit(state: &mut PacerState, rate: u64, bytes: u64, now: Instant) -> Duration {
        if rate == 0 {
            state.last = now;
            state.balance = PACER_BURST_BYTES as i64;
            return Duration::ZERO;
        }
        let elapsed = now.saturating_duration_since(state.last);
        state.last = now;
        let earned = (elapsed.as_secs_f64() * rate as f64) as i64;
        state.balance = (state.balance + earned).min(PACER_BURST_BYTES as i64);
        state.balance -= bytes as i64;
        if state.balance >= 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((-state.balance) as f64 / rate as f64)
        }
    }

    /// Blocks the calling worker thread until `bytes` may go out.
    pub fn acquire(&self, bytes: u64) {
        let wait = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            Self::debit(&mut state, self.rate(), bytes, Instant::now())
        };
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
    }
}

// ---------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------

/// `1.5 GB`, `12.0 MB`, `3.2 KB`, `512 B` - what the browser's size
/// column shows. Decimal units, one decimal past the first step.
pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1000.0;
    let b = bytes as f64;
    if b >= KB * KB * KB {
        format!("{:.1} GB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}
