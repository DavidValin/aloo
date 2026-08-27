//! Keeping the control connection up for as long as the session lives.
//!
//! Everything that carries content is peer-to-peer (§7.1, §10), so losing
//! the server never stops a conversation - but it does stop *presence*:
//! the nickname is freed after `proto::HEARTBEAT_TIMEOUT` (§4.1), peers
//! are told `UserOffline`, and anyone connecting afterwards is never told
//! this client exists at all. A session that stays up on its direct links
//! while quietly absent from every roster is the worst of both: messages
//! arrive, but nobody can see who sent them.
//!
//! This module closes that gap. A supervisor task owns the read half and
//! the reconnect loop; the session keeps a `ServerSink` whose underlying
//! writer the supervisor swaps out from under it as new connections are
//! established. Neither the session's select loop nor any call site that
//! writes to the control channel knows a reconnect happened - they see a
//! stream of `ServerEvent`s, one of which says the `UserId` changed.
//!
//! Retrying is unconditional and never gives up: the reason the server is
//! away (down, restarting, unreachable, or a laptop's network off) is
//! never distinguishable from the client's side, and all of them end the
//! same way - the server comes back. `--no-server` sessions have no
//! supervisor at all: there is nothing to reconnect *to*, which is a
//! different state and says so (see `ServerLinkState::NoServer`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::control::{ControlReader, ControlSink, ControlWriter};
use crate::proto::{self, ClientMessage, ServerMessage, UserId};

/// How long to wait before the second attempt (the first is immediate -
/// most losses are a socket dropping under a still-working network, and
/// waiting out a backoff for those would be five seconds of nothing for
/// no reason).
pub const RECONNECT_FIRST_DELAY: Duration = Duration::from_secs(5);

/// The ceiling the doubling backoff never passes. A server that has been
/// away for a while is worth asking about twice a minute, not once an
/// hour: the session is otherwise fully alive and the user is waiting.
pub const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(30);

/// How many attempts may fail before the header stops saying "reconnecting"
/// and starts saying the server is down. Below this a reconnect reads as a
/// hiccup, which is what most of them are; at it, something is actually
/// wrong and the user should be told plainly rather than watched a
/// hopeful-sounding counter forever.
pub const SERVER_DOWN_AFTER_ATTEMPTS: u32 = 3;

/// The doubling schedule a supervisor retries on.
///
/// A type rather than two constants read directly so tests can drive a
/// whole sequence of failures in milliseconds instead of minutes - the
/// same reason `server::serve_with_heartbeat_timeout` exists beside
/// `serve`. Production always uses `Backoff::default()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub first: Duration,
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            first: RECONNECT_FIRST_DELAY,
            max: RECONNECT_MAX_DELAY,
        }
    }
}

impl Backoff {
    /// How long to wait before attempt number `failed_attempts + 1`.
    ///
    /// `0` failures means the connection has only just dropped, and the
    /// first attempt is immediate. After that it doubles from `first` up
    /// to `max`.
    pub fn delay_after(self, failed_attempts: u32) -> Duration {
        if failed_attempts == 0 {
            return Duration::ZERO;
        }
        // Shift-count is clamped rather than left to wrap: a session that
        // has been retrying for days would otherwise overflow back to a
        // tight loop.
        let doublings = (failed_attempts - 1).min(16);
        self.first.saturating_mul(1u32 << doublings).min(self.max)
    }
}

/// `Backoff::default().delay_after` - the schedule every real session uses.
pub fn delay_after(failed_attempts: u32) -> Duration {
    Backoff::default().delay_after(failed_attempts)
}

/// Whole seconds still to wait, rounded *up*, so a countdown reads
/// `5, 4, 3, 2, 1` and never sits on a `0` that hasn't happened yet.
pub fn seconds_left(now: Instant, until: Instant) -> u64 {
    let left = until.saturating_duration_since(now);
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

/// What the header says about the control connection - the first element
/// of the header row (`docs/SPEC.md` "Connected UI").
///
/// Deliberately finer-grained than `session::ServerState`: that type
/// answers "can this action happen right now", which has three answers,
/// while this one answers "what is going on", which the user is owed in
/// more detail than yes/no.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerLinkState {
    /// The control connection is up.
    #[default]
    Connected,
    /// An attempt is in flight right now.
    Reconnecting,
    /// Waiting out the backoff before the next attempt, with few enough
    /// failures behind it to still read as a hiccup.
    RetryingIn { seconds_left: u64 },
    /// `SERVER_DOWN_AFTER_ATTEMPTS` attempts or more have failed.
    Down { seconds_left: u64 },
    /// Started with `--no-server` (§7.1.5): there is nothing to connect
    /// to, so nothing is wrong and nothing is being retried.
    NoServer,
}

impl ServerLinkState {
    /// The state to show while waiting `seconds_left` more seconds, having
    /// already had `failed_attempts` attempts fail.
    pub fn waiting(failed_attempts: u32, seconds_left: u64) -> Self {
        if failed_attempts >= SERVER_DOWN_AFTER_ATTEMPTS {
            Self::Down { seconds_left }
        } else {
            Self::RetryingIn { seconds_left }
        }
    }

    /// The one glyph every state renders with - a plain record-circle
    /// rather than a multicolour emoji, so the colour actually shown is
    /// whichever one the header applies (`client::tui::channel::
    /// server_link_color`) and not a fixed one baked into the character
    /// itself.
    pub const ICON: &'static str = "\u{23FA}";

    /// Exactly what the header renders, icon included (`docs/SPEC.md`
    /// "Connected UI"). `punching` is only ever read in the `NoServer`
    /// state - with a server, a direct link being punched is the ordinary
    /// case and the sidebar already colours the peer it belongs to; with
    /// none it is the only thing this client is doing to reach anybody,
    /// and worth saying out loud.
    pub fn label(self, punching: bool) -> String {
        let icon = Self::ICON;
        match self {
            Self::Connected => format!("{icon} Connected to server!"),
            Self::Reconnecting => format!("{icon} Reconnecting..."),
            Self::RetryingIn { seconds_left } => {
                format!("{icon} Reconnecting in {seconds_left}s...")
            }
            Self::Down { seconds_left } => {
                format!("{icon} Server down (reconnecting in {seconds_left} sec...)")
            }
            Self::NoServer if punching => format!("{icon} No server mode (punching)"),
            Self::NoServer => format!("{icon} No server mode"),
        }
    }
}

/// What the supervisor reports to the session's select loop: the server's
/// own messages, plus the connection's own comings and goings.
///
/// One stream rather than a message channel plus a state channel, so the
/// session can never process a message from a connection it has already
/// been told was replaced, or learn about a new `UserId` out of order with
/// the `UserJoined`s that follow it.
#[derive(Debug)]
pub enum ServerEvent {
    /// An ordinary message from the server.
    Message(Box<ServerMessage>),
    /// The control connection has gone. Direct links are unaffected.
    Lost,
    /// Dialling the server right now.
    Attempting,
    /// Waiting out the backoff. `until` is a deadline rather than a
    /// duration so the countdown in the header can be recomputed on every
    /// redraw instead of ticking one message per second up this channel.
    Waiting {
        until: Instant,
        failed_attempts: u32,
        /// Why the last attempt failed, for the one status notice shown
        /// when a reconnect first turns out not to be instant.
        reason: String,
    },
    /// Connected again. `you` is a *new* `UserId` - the server never
    /// reuses one (TB-020), so as far as every peer is concerned this
    /// client just arrived.
    Reconnected { you: UserId },
}

/// The control channel a session writes to, whose socket can be replaced
/// underneath it.
///
/// Cloneable and shared: the session holds one, the supervisor holds
/// another and installs each new connection's writer into it.
///
/// A send with no connection currently installed is **discarded**, exactly
/// as `control::NullSink` discards one under `--no-server`, and for the
/// same reason: while the server is away `session::ServerState` is
/// `Unreachable`, every action needing a server is refused at the point it
/// is asked for, and `session::send_if_server` skips the rest. Anything
/// still arriving here is a backstop, not the mechanism.
///
/// A send that *fails* is how a broken socket is usually noticed first:
/// with nothing arriving from the server there is nothing for the read
/// half to fail on, but the heartbeat (§4.1) keeps writing every
/// `HEARTBEAT_INTERVAL`. The failure drops the writer and wakes the
/// supervisor instead of being returned to the caller - every call site
/// propagates with `?`, and ending the session is the one thing this
/// module exists to prevent.
#[derive(Clone)]
pub struct ServerSink {
    inner: Arc<Mutex<Option<ControlWriter<WriteHalf<crate::server::ssl::BoxedStream>>>>>,
    lost_tx: UnboundedSender<()>,
}

impl ServerSink {
    /// A sink over a live connection, plus the receiver the supervisor
    /// waits on to hear that a write failed.
    pub fn new(writer: ControlWriter<WriteHalf<crate::server::ssl::BoxedStream>>) -> (Self, UnboundedReceiver<()>) {
        let (lost_tx, lost_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                inner: Arc::new(Mutex::new(Some(writer))),
                lost_tx,
            },
            lost_rx,
        )
    }

    /// Puts a freshly established connection's writer in place of whatever
    /// was there.
    pub async fn install(&self, writer: ControlWriter<WriteHalf<crate::server::ssl::BoxedStream>>) {
        *self.inner.lock().await = Some(writer);
    }

    /// Drops the current writer: sends are discarded until one is
    /// installed again.
    pub async fn clear(&self) {
        *self.inner.lock().await = None;
    }

    /// Whether a connection is installed right now. Only the supervisor's
    /// own bookkeeping needs this - the session asks
    /// `session::ServerState`, which is the answer that has been through
    /// the select loop and so cannot disagree with what is on screen.
    pub async fn is_connected(&self) -> bool {
        self.inner.lock().await.is_some()
    }
}

impl ControlSink for ServerSink {
    async fn send_control(&mut self, msg: &ClientMessage) -> proto::Result<()> {
        let mut guard = self.inner.lock().await;
        let Some(writer) = guard.as_mut() else {
            return Ok(());
        };
        if writer.send_control(msg).await.is_err() {
            *guard = None;
            // The supervisor may already be reconnecting (a read failure
            // beat this write to it), in which case this is redundant and
            // harmless; if the receiver is gone the session is ending
            // anyway.
            let _ = self.lost_tx.send(());
        }
        Ok(())
    }
}

/// Everything a reconnect needs to redo the handshake as the same person.
///
/// The identity is carried as its already-encoded public bundle rather
/// than re-resolved from `request.my_key`: resolving again would re-read
/// the keybundle files mid-session (and generate them if they had since
/// gone missing), risking handing the server a public key whose private
/// half this session does not hold - every message anyone encrypted to it
/// would then arrive undecryptable.
#[derive(Debug, Clone)]
pub struct ReconnectPlan {
    pub request: crate::client::connect::ConnectRequest,
    pub public_key_der: Vec<u8>,
    /// `Backoff::default()` everywhere but in tests.
    pub backoff: Backoff,
}

/// Owns the read half and the reconnect loop for the life of the session.
///
/// Runs until the session drops the event receiver, at which point every
/// send fails and the task falls out on its own.
pub fn spawn_supervisor(
    reader: ControlReader<ReadHalf<crate::server::ssl::BoxedStream>>,
    plan: ReconnectPlan,
    sink: ServerSink,
    mut lost_rx: UnboundedReceiver<()>,
    events_tx: UnboundedSender<ServerEvent>,
) {
    tokio::spawn(async move {
        let mut reader = reader;
        loop {
            // Read until this connection ends - either because the socket
            // did, or because a write on it failed.
            loop {
                tokio::select! {
                    incoming = reader.recv::<ServerMessage>() => {
                        match incoming {
                            Ok(Some(msg)) => {
                                if events_tx.send(ServerEvent::Message(Box::new(msg))).is_err() {
                                    return;
                                }
                            }
                            _ => break,
                        }
                    }
                    _ = lost_rx.recv() => break,
                }
            }

            sink.clear().await;
            // Anything the failed writer queued before it broke is gone,
            // and a `()` left in this channel would otherwise cut the next
            // connection short the moment it is established.
            while lost_rx.try_recv().is_ok() {}
            if events_tx.send(ServerEvent::Lost).is_err() {
                return;
            }

            let Some(fresh) = reconnect_loop(&plan, &sink, &events_tx).await else {
                return;
            };
            reader = fresh;
        }
    });
}

/// Dials until it gets in. `None` only when the session has gone away.
///
/// Every failure is retryable, including a rejected nickname: when this
/// client's own previous connection is what still holds the name, the
/// server frees it once `HEARTBEAT_TIMEOUT` expires (§5.4), and the very
/// next attempt succeeds. Giving up there would turn "your network blinked"
/// into "you are locked out of your own nickname".
async fn reconnect_loop(
    plan: &ReconnectPlan,
    sink: &ServerSink,
    events_tx: &UnboundedSender<ServerEvent>,
) -> Option<ControlReader<ReadHalf<crate::server::ssl::BoxedStream>>> {
    let mut failed_attempts: u32 = 0;
    loop {
        // `delay_after(0)` is zero, so the first attempt happens the
        // moment the connection is noticed gone.
        events_tx.send(ServerEvent::Attempting).ok()?;
        match crate::client::connect::handshake_as_bounded_and_diagnosed(
            &plan.request,
            plan.public_key_der.clone(),
        )
        .await
        {
            Ok((reader, writer, you, _server_addr)) => {
                sink.install(writer).await;
                events_tx.send(ServerEvent::Reconnected { you }).ok()?;
                return Some(reader);
            }
            Err(e) => {
                failed_attempts = failed_attempts.saturating_add(1);
                let delay = plan.backoff.delay_after(failed_attempts);
                events_tx
                    .send(ServerEvent::Waiting {
                        until: Instant::now() + delay,
                        failed_attempts,
                        reason: e.to_string(),
                    })
                    .ok()?;
                tokio::time::sleep(delay).await;
            }
        }
    }
}
