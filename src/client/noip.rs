//! Dynamic DNS updates for `direct_punch` peers reachable only by hostname
//! (`docs/PROTOCOL.md` §7.1.5's "No-IP updates"): a small background job
//! that keeps a No-IP hostname pointed at this machine's current public
//! address while there is no server to otherwise announce it, so a peer's
//! `direct_punch_to` line naming that hostname keeps resolving to the
//! right place.
//!
//! `run` is what `client::session` starts and stops (`sync_noip_job`) as
//! the server comes and goes; everything else here is the pure scheduling
//! and request/response logic that makes it testable without a live
//! socket to `dynupdate.no-ip.com`.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::server::users_registry::base64;

pub const NOIP_HOST: &str = "dynupdate.no-ip.com";
const NOIP_PORT: u16 = 443;

/// The wall-clock second every update fires on. Chosen so it always lands
/// shortly before a direct-punch slot boundary, which always falls on
/// `:00` of some minute (`docs/PROTOCOL.md` §7.1.5's slot grid) - the
/// No-IP update is meant to land first, then the punch attempts that
/// follow have the freshest address to try.
pub const NOIP_SECOND_OF_MINUTE: u64 = 50;

/// The two gaps `run` alternates between. Neither 330 seconds (5.5
/// minutes) nor any other single whole-second period can both divide
/// evenly *and* always land back on `NOIP_SECOND_OF_MINUTE`, since 330 is
/// not a multiple of 60; alternating a 5-minute gap with a 6-minute one
/// keeps every single fire exactly on `:50` while still averaging exactly
/// 5.5 minutes over every pair of them.
pub const NOIP_GAP_SHORT: Duration = Duration::from_secs(5 * 60);
pub const NOIP_GAP_LONG: Duration = Duration::from_secs(6 * 60);

/// The whole exchange, request to response, must fit in this.
const NOIP_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything one update needs. `from_settings` is the only real
/// constructor - the job is off unless all three are filled in, since a
/// half-configured request would just fail forever rather than doing
/// anything useful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoipConfig {
    pub hostname: String,
    pub username: String,
    pub password: String,
}

impl NoipConfig {
    /// `None` unless `noip_hostname`/`noip_username`/`noip_password` are
    /// all non-empty - whether or not `noip_when_no_server_and_direct_punch_is_active`
    /// itself is on is the caller's to check, since that also depends on
    /// `direct_punch` naming a target, which is not this type's concern.
    pub fn from_settings(settings: &crate::settings::Settings) -> Option<Self> {
        if settings.noip_hostname.is_empty()
            || settings.noip_username.is_empty()
            || settings.noip_password.is_empty()
        {
            return None;
        }
        Some(Self {
            hostname: settings.noip_hostname.clone(),
            username: settings.noip_username.clone(),
            password: settings.noip_password.clone(),
        })
    }
}

/// Seconds from `second_of_minute` (`0..60`) to the next
/// `NOIP_SECOND_OF_MINUTE` mark strictly in the future - sitting exactly
/// on the mark still waits a full minute for the *next* one, so `run`
/// never fires twice in place.
pub fn seconds_until_next_noip_mark(second_of_minute: u64) -> u64 {
    if second_of_minute < NOIP_SECOND_OF_MINUTE {
        NOIP_SECOND_OF_MINUTE - second_of_minute
    } else {
        60 - second_of_minute + NOIP_SECOND_OF_MINUTE
    }
}

/// The raw HTTP/1.1 request `update_once` sends - No-IP's Dynamic DNS
/// Update API, HTTP Basic-authenticated
/// (<https://dynupdate.no-ip.com/nic/update?hostname=...>).
pub fn build_request(config: &NoipConfig) -> String {
    let auth = base64(format!("{}:{}", config.username, config.password).as_bytes());
    format!(
        "GET /nic/update?hostname={} HTTP/1.1\r\n\
         Host: {NOIP_HOST}\r\n\
         Authorization: Basic {auth}\r\n\
         User-Agent: aloo-noip-updater/1\r\n\
         Connection: close\r\n\
         \r\n",
        config.hostname
    )
}

/// The body of a `200` response, trimmed - `good <ip>`/`nochg <ip>` on
/// success, or one of No-IP's documented failure codes (`badauth`,
/// `911`, ...) on a refusal that is still a normal HTTP exchange. Any
/// other status is an error: No-IP reports its own outcome in the body,
/// not the status line, so a non-`200` here means something failed before
/// No-IP's own logic even ran (a proxy, a redirect, a malformed request).
pub fn parse_response(raw: &str) -> Result<String, String> {
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");
    let status_line = head.lines().next().unwrap_or("(empty response)");
    if !status_line.split_whitespace().nth(1).is_some_and(|code| code == "200") {
        return Err(format!("No-IP returned {status_line:?}"));
    }
    Ok(body.trim().to_string())
}

/// One update. The response body is returned as-is on any normal `200`
/// exchange, success code or documented failure code alike - the caller
/// (`run`) is what decides whether it is worth a warning.
pub async fn update_once(config: &NoipConfig) -> Result<String, String> {
    let tcp = tokio::net::TcpStream::connect((NOIP_HOST, NOIP_PORT))
        .await
        .map_err(|e| format!("could not reach {NOIP_HOST}:{NOIP_PORT}: {e}"))?;
    let connector = crate::server::ssl::client_connector(None)?;
    let mut stream = crate::server::ssl::connect(Some(&connector), NOIP_HOST, tcp)
        .await
        .map_err(|e| format!("TLS to {NOIP_HOST}: {e}"))?;
    stream
        .write_all(build_request(config).as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| format!("reading No-IP's response: {e}"))?;
    parse_response(&String::from_utf8_lossy(&response))
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Runs until aborted (`session.rs`'s `sync_noip_job`, which tears this
/// down the moment a server becomes reachable again). Waits for the next
/// `NOIP_SECOND_OF_MINUTE` mark, fires once there, then alternates
/// `NOIP_GAP_SHORT`/`NOIP_GAP_LONG` forever after - see their doc for why
/// that is what keeps every fire on the mark while still averaging 5.5
/// minutes.
pub async fn run(config: NoipConfig) {
    tokio::time::sleep(Duration::from_secs(seconds_until_next_noip_mark(
        unix_now_secs() % 60,
    )))
    .await;
    let mut long_gap = false;
    loop {
        match tokio::time::timeout(NOIP_TIMEOUT, update_once(&config)).await {
            Ok(Ok(body)) if body.starts_with("good") || body.starts_with("nochg") => {}
            Ok(Ok(body)) => {
                crate::log_warn!("No-IP update for {} did not succeed: {body}", config.hostname)
            }
            Ok(Err(e)) => crate::log_warn!("No-IP update for {} failed: {e}", config.hostname),
            Err(_) => crate::log_warn!(
                "No-IP update for {} timed out after {}s",
                config.hostname,
                NOIP_TIMEOUT.as_secs()
            ),
        }
        tokio::time::sleep(if long_gap { NOIP_GAP_LONG } else { NOIP_GAP_SHORT }).await;
        long_gap = !long_gap;
    }
}
