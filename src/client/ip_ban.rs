//! An on-disk, per-source-IP ban list, a generic rolling-window strike
//! counter (`record_strike`/`StrikeConfig`) reused by three unrelated
//! gates that all want the same shape - "N qualifying events from one
//! address within a window bans it" - but differ in threshold, window,
//! reason and (for the newer two) how long the ban lasts:
//! - the direct-punch unknown-peer flow
//!   (`client::session::on_unauthenticated_direct_proof`, via
//!   `record_failed_check`/`is_banned` - the original, permanent-ban use,
//!   still the first cross-restart-persistent limiter in this codebase);
//! - `server::mod`'s login-failure gate (7 wrong passwords bans the
//!   address 24h);
//! - `server::mod`'s registration-abuse gate (more than 3 registrations in
//!   2 days bans the address 7 days).
//!
//! Unlike `server::Registry`'s `channel_password_attempts`
//! (`channels_registry.rs`), explicitly in-memory only and lost on
//! restart, every ban here survives one. Direct-punch's own instance is
//! embedded on `PeerLinkManager` rather than `SessionState`: the read-side
//! gate (`is_banned`, consulted by `on_direct_ping`) and the write-side
//! (`record_failed_check`) both only ever run from the single task that
//! owns `&mut session.peer_link`, so an ordinary owned field is enough -
//! no `Arc<Mutex<_>>` needed there. The server's two instances *are*
//! shared across concurrently-handled connections, so it wraps each in a
//! `tokio::sync::Mutex` instead (`ServerOptions::login_bans`/
//! `registration_bans`).
//!
//! On-disk format at `~/.aloo/banned_ips.log` (direct-punch) and the
//! server's own `login_banned_ips.log`/`registration_banned_ips.log`: a
//! header line reading `<n> banned` (display-only - recomputed from the
//! entries below on every save, and never trusted on load, so a
//! hand-edited removal of an entry takes effect immediately even though
//! the header may briefly disagree until the next ban), then one
//! `<date>\t<ip>\t<reason>\t<expires_at>` line per ban, sorted by ip
//! (`expires_at` is a Unix-seconds timestamp, empty for a permanent ban -
//! direct-punch's own bans always are). Mirrors `client::idstore`'s
//! tab-delimited, tolerant-parse convention: a line that doesn't split
//! into at least the first three of those fields, or whose ip doesn't
//! parse, is skipped rather than failing the whole load; a missing or
//! unparseable fourth field is simply read back as "permanent" (also how
//! every ban record written before `expires_at` existed still loads
//! correctly).
//!
//! `is_banned`/`record_failed_check` (direct-punch's own pair) never
//! consult a clock and never expire anything, exactly as before this
//! generalization. `is_banned_at`/`record_strike` are the general,
//! expiry-aware pair the two newer gates use instead.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How far back a strike still counts.
const ROLLING_WINDOW_SECS: u64 = 10 * 60 * 60;
/// How many genuine failed checks from one IP bans it.
const STRIKES_TO_BAN: usize = 3;
/// The qualifying strikes must span at least this many distinct wall-clock
/// minutes - three crammed into the same minute do not ban.
const MIN_DISTINCT_MINUTES: usize = 2;

/// The direct-punch gate's own tuning, expressed as a `StrikeConfig` so
/// `record_failed_check` can share `record_strike`'s implementation - a
/// permanent ban (`ban_duration: None`), exactly as before this type
/// existed.
const DIRECT_PUNCH_STRIKES: StrikeConfig = StrikeConfig {
    strikes_to_ban: STRIKES_TO_BAN,
    window_secs: ROLLING_WINDOW_SECS,
    min_distinct_minutes: MIN_DISTINCT_MINUTES,
    ban_duration: None,
    reason: "repeated unproven direct-punch checks",
};

/// 7 wrong passwords for one address bans it for 24h
/// (`server::mod::LOGIN_FAILURE_LIMIT`). No minute-spread requirement -
/// unlike direct-punch's anti-crash-loop concern, a credential-stuffing
/// script sending all 7 within the same minute should ban just as surely
/// as one spread out.
pub const LOGIN_FAILURE_STRIKES: StrikeConfig = StrikeConfig {
    strikes_to_ban: 7,
    window_secs: 24 * 60 * 60,
    min_distinct_minutes: 1,
    ban_duration: Some(Duration::from_secs(24 * 60 * 60)),
    reason: "7 failed login attempts",
};

/// More than 3 registrations from one address within 2 days - i.e. the
/// 4th - bans it for 7 days.
pub const REGISTRATION_ABUSE_STRIKES: StrikeConfig = StrikeConfig {
    strikes_to_ban: 4,
    window_secs: 2 * 24 * 60 * 60,
    min_distinct_minutes: 1,
    ban_duration: Some(Duration::from_secs(7 * 24 * 60 * 60)),
    reason: "more than 3 registrations within 2 days",
};

pub fn default_path() -> PathBuf {
    crate::platform::aloo_dir().join("banned_ips.log")
}

/// `ServerOptions`'s login-failure ban list, production default.
pub fn login_ban_default_path() -> PathBuf {
    crate::platform::aloo_dir().join("login_banned_ips.log")
}

/// `ServerOptions`'s registration-abuse ban list, production default.
pub fn registration_ban_default_path() -> PathBuf {
    crate::platform::aloo_dir().join("registration_banned_ips.log")
}

/// One rolling-window strike-counting rule: how many qualifying events
/// within `window_secs` (spanning at least `min_distinct_minutes` distinct
/// wall-clock minutes) bans an address, for how long, and why.
#[derive(Debug, Clone, Copy)]
pub struct StrikeConfig {
    pub strikes_to_ban: usize,
    pub window_secs: u64,
    pub min_distinct_minutes: usize,
    /// `None` bans permanently (the direct-punch gate's own rule);
    /// `Some(d)` lifts the ban `d` after the strike that caused it.
    pub ban_duration: Option<Duration>,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BanRecord {
    date: String,
    reason: String,
    /// Unix-seconds deadline; `None` means permanent.
    expires_at: Option<u64>,
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
        if let Some(contents) = crate::platform::read_to_string_optional(path)? {
            for line in contents.lines() {
                let mut fields = line.splitn(4, '\t');
                let Some(date) = fields.next() else {
                    continue;
                };
                let Some(ip) = fields.next() else {
                    continue;
                };
                let Some(reason) = fields.next() else {
                    continue;
                };
                // Absent (older/hand-edited files) or unparseable reads
                // back as permanent rather than failing the line.
                let expires_at = fields.next().and_then(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        s.parse::<u64>().ok()
                    }
                });
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    banned.insert(
                        ip,
                        BanRecord {
                            date: date.to_string(),
                            reason: reason.to_string(),
                            expires_at,
                        },
                    );
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            banned,
            recent_failures: HashMap::new(),
        })
    }

    /// Direct-punch's own read-side gate: permanent, so expiry never
    /// enters into it.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.banned.contains_key(&ip)
    }

    /// The general, expiry-aware read-side gate: banned if there's a
    /// record and either it has no expiry or `now_unix` hasn't reached it
    /// yet. An expired record is left on disk (it still shows in
    /// `ban_count`/the log) rather than pruned - the next successful ban
    /// write recomputes the header anyway, and nothing else reads staleness
    /// out of it.
    pub fn is_banned_at(&self, ip: IpAddr, now_unix: u64) -> bool {
        self.banned
            .get(&ip)
            .is_some_and(|record| record.expires_at.is_none_or(|exp| now_unix < exp))
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
        self.record_strike(ip, now_unix, &DIRECT_PUNCH_STRIKES)
    }

    /// The general write-side counter every gate's own strike-recording
    /// method (`record_failed_check` above, and `server::mod`'s login-
    /// and registration-abuse gates) funnels through. Already-banned is
    /// checked with `is_banned_at` (not the permanent-only `is_banned`),
    /// so a temporary ban from a previous call with a *different* config
    /// against the same list is still honored - not that any caller today
    /// mixes configs against one instance, but nothing here assumes it
    /// won't.
    pub fn record_strike(&mut self, ip: IpAddr, now_unix: u64, config: &StrikeConfig) -> BanOutcome {
        if self.is_banned_at(ip, now_unix) {
            return BanOutcome::Banned;
        }
        let history = self.recent_failures.entry(ip).or_default();
        history.retain(|&t| now_unix.saturating_sub(t) < config.window_secs);
        history.push(now_unix);
        if history.len() < config.strikes_to_ban {
            return BanOutcome::NotYet;
        }
        let distinct_minutes: HashSet<u64> = history.iter().map(|t| t / 60).collect();
        if distinct_minutes.len() < config.min_distinct_minutes {
            return BanOutcome::NotYet;
        }
        self.recent_failures.remove(&ip);
        if let Err(e) = self.ban(ip, config.reason, now_unix, config.ban_duration) {
            crate::log_warn!("failed to persist a ban for {ip}: {e}");
        }
        // Enforced for the rest of this run regardless of whether the write
        // above succeeded - `ban` already updated `self.banned` before
        // attempting to save it.
        BanOutcome::Banned
    }

    fn ban(
        &mut self,
        ip: IpAddr,
        reason: &str,
        now_unix: u64,
        ban_duration: Option<Duration>,
    ) -> io::Result<()> {
        self.banned.insert(
            ip,
            BanRecord {
                date: format_unix(now_unix),
                reason: reason.to_string(),
                expires_at: ban_duration.map(|d| now_unix + d.as_secs()),
            },
        );
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        crate::platform::ensure_parent_dir(&self.path)?;
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
            out.push('\t');
            if let Some(exp) = record.expires_at {
                out.push_str(&exp.to_string());
            }
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
