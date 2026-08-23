//! The account-activation web endpoint (docs/PROTOCOL.md §5.3): where the
//! link in an activation email lands.
//!
//! Runs only while `server_allow_registration=on`, on
//! `server_bind:server_activation_port`, over TLS when `server_ssl` is on
//! (the same certificate pair as the server itself) and plain HTTP
//! otherwise. It answers exactly one question - `GET /activate?nickname=
//! <n>&code=<c>` - by calling `UsersRegistry::activate`, the very same
//! call the client's activation popup reaches through
//! `ClientMessage::Activate`; the two paths cannot disagree about what
//! activation means because there is only one.
//!
//! The HTTP is hand-rolled and minimal on purpose: one request line, the
//! headers skipped, one HTML reply, connection closed. Nothing here is
//! a web framework's job.
//!
//! **Brute force.** Twelve digits is a lot to guess, but the endpoint is
//! public and unauthenticated, so it counts attempts per source address:
//! more than `MAX_ATTEMPTS_PER_HOUR` within `ATTEMPT_WINDOW` bans the
//! address for `BAN_DURATION`. The ban is this endpoint's alone - the same
//! address can still connect a client, whose own activation path costs a
//! full reconnect per wrong code.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use super::users_registry::{ActivationOutcome, UsersRegistry};

/// Attempts an address may make within `ATTEMPT_WINDOW` before the next
/// one bans it.
pub const MAX_ATTEMPTS_PER_HOUR: u32 = 10;
pub const ATTEMPT_WINDOW: Duration = Duration::from_secs(60 * 60);
/// How long a banned address is refused.
pub const BAN_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// A request head larger than this is refused unread - an activation
/// link is a few hundred bytes.
const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// How long a connection gets to deliver its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct AttemptRecord {
    window_start: Instant,
    attempts: u32,
    banned_at: Option<Instant>,
}

/// Per-address attempt counting. Pure and clock-injected, so the
/// hour-and-day rules are testable in a blink.
#[derive(Default)]
pub struct AttemptLimiter {
    records: HashMap<IpAddr, AttemptRecord>,
}

/// What the limiter says about one more attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    /// Refused - either already banned, or banned by this very attempt.
    Banned,
}

impl AttemptLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        self.records
            .get(&ip)
            .and_then(|r| r.banned_at)
            .is_some_and(|at| now.duration_since(at) < BAN_DURATION)
    }

    /// Counts one attempt from `ip`. The window restarts once
    /// `ATTEMPT_WINDOW` has passed since it opened; the
    /// `MAX_ATTEMPTS_PER_HOUR + 1`th attempt inside one window trips the
    /// ban. A lapsed ban is forgotten on the next attempt.
    pub fn note_attempt(&mut self, ip: IpAddr, now: Instant) -> Admission {
        if self.is_banned(ip, now) {
            return Admission::Banned;
        }
        let record = self.records.entry(ip).or_insert(AttemptRecord {
            window_start: now,
            attempts: 0,
            banned_at: None,
        });
        record.banned_at = None;
        if now.duration_since(record.window_start) >= ATTEMPT_WINDOW {
            record.window_start = now;
            record.attempts = 0;
        }
        record.attempts += 1;
        if record.attempts > MAX_ATTEMPTS_PER_HOUR {
            record.banned_at = Some(now);
            return Admission::Banned;
        }
        Admission::Allowed
    }
}

/// The one part of an HTTP request this endpoint reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    /// Query parameters in order, percent-decoded.
    pub query: Vec<(String, String)>,
}

impl HttpRequest {
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Parses the request line out of a request head. Everything after the
/// first line (the headers) is ignored.
pub fn parse_request(head: &str) -> Option<HttpRequest> {
    let line = head.lines().next()?;
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect();
    Some(HttpRequest {
        method,
        path: path.to_string(),
        query,
    })
}

/// `%XX` and `+` decoding for a query component. Invalid escapes are kept
/// literally; the values end up validated against a strict alphabet
/// anyway.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One reply: a status and an HTML body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

impl HttpResponse {
    fn page(status: u16, title: &str, text: &str) -> Self {
        Self {
            status,
            body: format!(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>aloo - {title}</title>\
                 <style>body{{font-family:sans-serif;max-width:40em;margin:4em auto;padding:0 1em}}\
                 input{{font-size:1em}}</style></head><body><h1>{title}</h1><p>{text}</p></body></html>\n"
            ),
        }
    }

    /// The bytes on the wire, status line to body.
    pub fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            429 => "Too Many Requests",
            _ => "Error",
        };
        format!(
            "HTTP/1.1 {} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
             Connection: close\r\nCache-Control: no-store\r\n\r\n{}",
            self.status,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }
}

/// The whole endpoint's behaviour for one request, with the clocks
/// injected (`now_utc` for the code's validity, `now` for the limiter).
///
/// A request counts as an attempt only when it actually carries a code
/// to check: the bare form, a wrong path, and a wrong method cost
/// nothing, so a banned address is one that kept submitting codes.
pub fn handle(
    registry: &UsersRegistry,
    limiter: &mut AttemptLimiter,
    ip: IpAddr,
    request: &HttpRequest,
    now_utc: u64,
    now: Instant,
) -> HttpResponse {
    if request.path != "/activate" {
        return HttpResponse::page(404, "Not found", "There is nothing here.");
    }
    if request.method != "GET" && request.method != "HEAD" {
        return HttpResponse::page(405, "Not allowed", "Activation links are opened, not posted.");
    }
    let nickname = request.param("nickname").unwrap_or("").trim();
    let code = request.param("code").unwrap_or("").trim();
    if nickname.is_empty() || code.is_empty() {
        return HttpResponse::page(
            200,
            "Activate your account",
            "<form method=\"get\" action=\"/activate\">\
             <label>Nickname <input name=\"nickname\" maxlength=\"10\"></label><br><br>\
             <label>Activation code <input name=\"code\" maxlength=\"12\" inputmode=\"numeric\"></label><br><br>\
             <button type=\"submit\">Activate</button></form>",
        );
    }
    if limiter.note_attempt(ip, now) == Admission::Banned {
        return HttpResponse::page(
            429,
            "Too many attempts",
            "This address has made too many activation attempts and is blocked for a day.",
        );
    }
    match registry.activate(nickname, code, now_utc) {
        ActivationOutcome::Activated => HttpResponse::page(
            200,
            "Account activated",
            &format!(
                "<b>{}</b> is now active. Open aloo and connect with your nickname and password.",
                html_escape(nickname)
            ),
        ),
        ActivationOutcome::Expired => HttpResponse::page(
            400,
            "Code expired",
            "This activation code is more than an hour old. Register again from aloo to get a new one.",
        ),
        ActivationOutcome::WrongCode | ActivationOutcome::NothingPending => HttpResponse::page(
            400,
            "Not activated",
            "That nickname and code do not match a pending activation.",
        ),
    }
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// Serves the endpoint forever on `listener`, TLS-wrapped when `tls` is
/// given. One task per connection; the limiter is shared across them.
pub async fn run(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    registry: Arc<UsersRegistry>,
) -> std::io::Result<()> {
    let limiter = Arc::new(Mutex::new(AttemptLimiter::new()));
    loop {
        let (socket, peer) = listener.accept().await?;
        let tls = tls.clone();
        let registry = registry.clone();
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let served = tokio::time::timeout(
                REQUEST_TIMEOUT,
                serve_one(socket, peer.ip(), tls, registry, limiter),
            )
            .await;
            if let Ok(Err(e)) = served {
                crate::log_warn!("activation request from {peer} failed: {e}");
            }
        });
    }
}

async fn serve_one(
    socket: tokio::net::TcpStream,
    ip: IpAddr,
    tls: Option<TlsAcceptor>,
    registry: Arc<UsersRegistry>,
    limiter: Arc<Mutex<AttemptLimiter>>,
) -> std::io::Result<()> {
    let mut stream = super::ssl::accept(tls.as_ref(), socket).await?;
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if head.len() > MAX_REQUEST_BYTES {
            let reply = HttpResponse::page(400, "Bad request", "Request too large.");
            stream.write_all(&reply.to_bytes()).await?;
            return Ok(());
        }
    }
    let text = String::from_utf8_lossy(&head);
    let reply = match parse_request(&text) {
        Some(request) => {
            let mut limiter = limiter.lock().await;
            handle(
                &registry,
                &mut limiter,
                ip,
                &request,
                super::users_registry::now_utc(),
                Instant::now(),
            )
        }
        None => HttpResponse::page(400, "Bad request", "That is not an HTTP request."),
    };
    stream.write_all(&reply.to_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}
