//! A permanent, on-disk, per-source-IP ban list for the direct-punch
//! unknown-peer flow (`client::session::on_unauthenticated_direct_proof`) -
//! the first cross-restart-persistent limiter in this codebase, unlike
//! `server::activation::AttemptLimiter` and `server::Registry`'s
//! `channel_password_attempts`, both explicitly in-memory only and lost on
//! restart. Embedded on `PeerLinkManager` rather than `SessionState`: the
//! read-side gate (`is_banned`, consulted by `on_direct_ping`) and the
//! write-side (`record_failed_check`) both only ever run from the single
//! task that owns `&mut session.peer_link`, so an ordinary owned field is
//! enough - no `Arc<Mutex<_>>` needed.
//!
//! On-disk format at `~/.aloo/banned_ips.log`: a header line reading
//! `<n> banned` (display-only - recomputed from the entries below on every
//! save, and never trusted on load, so a hand-edited removal of an entry
//! takes effect immediately even though the header may briefly disagree
//! until the next ban), then one `<date>\t<ip>\t<reason>` line per ban,
//! sorted by ip. Mirrors `client::idstore`'s tab-delimited, tolerant-parse
//! convention: a line that doesn't split into exactly those three fields, or
//! whose ip doesn't parse, is skipped rather than failing the whole load.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// How far back a strike still counts.
const ROLLING_WINDOW_SECS: u64 = 10 * 60 * 60;
/// How many genuine failed checks from one IP bans it.
const STRIKES_TO_BAN: usize = 3;
/// The qualifying strikes must span at least this many distinct wall-clock
/// minutes - three crammed into the same minute do not ban.
const MIN_DISTINCT_MINUTES: usize = 2;

pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("banned_ips.log")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BanRecord {
    date: String,
    reason: String,
}

/// Whether recording one more failed check just banned the IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanOutcome {
    NotYet,
    Banned,
}

pub struct IpBanList {
    path: PathBuf,
    banned: HashMap<IpAddr, BanRecord>,
    /// In-memory only, deliberately not persisted: unix-second timestamps of
    /// genuine failed checks per IP, pruned to `ROLLING_WINDOW_SECS` on
    /// every call. Only the ban itself needs to survive a restart - a
    /// restart shortly before the third strike simply resets the count, the
    /// same trade-off `server::activation::AttemptLimiter` already makes
    /// for everything short of an actual ban.
    recent_failures: HashMap<IpAddr, Vec<u64>>,
}

impl IpBanList {
    /// Starts an empty, in-memory-only list bound to `path` - used as a
    /// fallback when `load` fails for a reason other than the file simply
    /// not existing yet, so a permissions error doesn't refuse to start
    /// direct punching entirely.
    pub fn new_empty(path: PathBuf) -> Self {
        Self {
            path,
            banned: HashMap::new(),
            recent_failures: HashMap::new(),
        }
    }

    /// Loads `path`; a missing file isn't an error (first run) and just
    /// starts empty.
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut banned = HashMap::new();
        match fs::read_to_string(path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let mut fields = line.splitn(3, '\t');
                    let Some(date) = fields.next() else {
                        continue;
                    };
                    let Some(ip) = fields.next() else {
                        continue;
                    };
                    let Some(reason) = fields.next() else {
                        continue;
                    };
                    if let Ok(ip) = ip.parse::<IpAddr>() {
                        banned.insert(
                            ip,
                            BanRecord {
                                date: date.to_string(),
                                reason: reason.to_string(),
                            },
                        );
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(Self {
            path: path.to_path_buf(),
            banned,
            recent_failures: HashMap::new(),
        })
    }

    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.banned.contains_key(&ip)
    }

    /// How many bans are currently on file - what the header line reports.
    pub fn ban_count(&self) -> usize {
        self.banned.len()
    }

    /// Records one genuine failed check (the user agreed to check local
    /// keys, the scan ran, nothing matched) for `ip` at `now_unix`. Bans it
    /// once at least `STRIKES_TO_BAN` such failures land within the last
    /// `ROLLING_WINDOW_SECS`, spanning at least `MIN_DISTINCT_MINUTES`
    /// different wall-clock minutes - three crammed into the same minute do
    /// not ban. An already-banned ip is left alone; in practice this should
    /// never be reached for one, since `on_direct_ping` refuses it before a
    /// check can run again, but this is defense in depth.
    pub fn record_failed_check(&mut self, ip: IpAddr, now_unix: u64) -> BanOutcome {
        if self.is_banned(ip) {
            return BanOutcome::Banned;
        }
        let history = self.recent_failures.entry(ip).or_default();
        history.retain(|&t| now_unix.saturating_sub(t) < ROLLING_WINDOW_SECS);
        history.push(now_unix);
        if history.len() < STRIKES_TO_BAN {
            return BanOutcome::NotYet;
        }
        let distinct_minutes: HashSet<u64> = history.iter().map(|t| t / 60).collect();
        if distinct_minutes.len() < MIN_DISTINCT_MINUTES {
            return BanOutcome::NotYet;
        }
        self.recent_failures.remove(&ip);
        if let Err(e) = self.ban(ip, "repeated unproven direct-punch checks", now_unix) {
            crate::log_warn!("failed to persist a ban for {ip}: {e}");
        }
        // Enforced for the rest of this run regardless of whether the write
        // above succeeded - `ban` already updated `self.banned` before
        // attempting to save it.
        BanOutcome::Banned
    }

    fn ban(&mut self, ip: IpAddr, reason: &str, now_unix: u64) -> io::Result<()> {
        self.banned.insert(
            ip,
            BanRecord {
                date: format_unix(now_unix),
                reason: reason.to_string(),
            },
        );
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut ips: Vec<&IpAddr> = self.banned.keys().collect();
        ips.sort();
        let mut out = format!("{} banned\n", self.banned.len());
        for ip in ips {
            let record = &self.banned[ip];
            out.push_str(&record.date);
            out.push('\t');
            out.push_str(&ip.to_string());
            out.push('\t');
            out.push_str(&record.reason);
            out.push('\n');
        }
        fs::write(&self.path, out)
    }
}

fn format_unix(now_unix: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp(now_unix as i64)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| now_unix.to_string())
}
