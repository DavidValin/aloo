//! Where a diagnostic goes when a terminal UI may be in the way.
//!
//! Every warning this crate emits goes through `log_warn!` rather than a
//! bare `eprintln!`. The reason generalises the one `client::voice`'s
//! `on_stream_error` callback documents for itself: a background task can
//! decide it has something to say at *any* moment, including while ratatui
//! holds the terminal in raw mode on the alternate screen. Bytes written
//! straight to stderr then land wherever the cursor happens to be, tearing
//! a hole through the frame - a warning about an unusable STUN reply
//! (`client::p2p::warn_unusable_reflexive`) printed across the header and
//! the selectors is the shape that takes.
//!
//! One process-wide switch decides which of two things happens instead:
//!
//! - **`Console`** (the default) - one line on stderr. What `--server`,
//!   `--daemon`/`--foreground` and every one-shot CLI subcommand want:
//!   nothing owns the terminal there, so a warning is simply a warning.
//! - **`Silenced`** - nothing is printed. Entered by
//!   `client::tui::terminal::setup` for exactly as long as the TUI owns the
//!   screen, so no frame is ever written through.
//!
//! Silenced lines are not thrown away: the last `RING_CAPACITY` of them are
//! kept, and `client::tui::terminal::restore` replays them to stderr once
//! the terminal has been handed back. A warning worth emitting is still
//! worth reading - it just has to wait for a screen that is not being
//! painted several times a second.

use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// How many silenced lines are kept for the replay on the way out. A
/// session that spends hours warning about the same thing should not grow
/// this without bound, and the oldest lines are the least interesting once
/// there are more than a screenful - so the ring keeps the newest.
pub const RING_CAPACITY: usize = 64;

/// The prefix every line this crate emits carries, so a warning is
/// recognisable as aloo's own among whatever else shares the terminal.
pub const PREFIX: &str = "aloo:";

/// `false` (the default) means write to stderr. An atomic rather than a
/// field on some context object: the call sites are spread across worker
/// threads, audio callbacks and tokio tasks that have no shared owner to
/// hang it off, and the answer is a property of the *process* (does
/// something own the screen right now), not of any one of them.
static SILENCED: AtomicBool = AtomicBool::new(false);

fn ring() -> &'static Mutex<Vec<String>> {
    static RING: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(Vec::new()))
}

/// Stops writing to stderr and starts collecting instead. Called by
/// `client::tui::terminal::setup`, the one place that takes the terminal
/// over.
pub fn silence() {
    SILENCED.store(true, Ordering::Relaxed);
}

/// The inverse, called by `client::tui::terminal::restore`. Does not
/// replay anything by itself - see `drain`, which the same restore path
/// calls immediately afterwards.
pub fn unsilence() {
    SILENCED.store(false, Ordering::Relaxed);
}

pub fn is_silenced() -> bool {
    SILENCED.load(Ordering::Relaxed)
}

/// Takes everything collected while silenced, emptying the ring.
pub fn take_collected() -> Vec<String> {
    let mut ring = ring().lock().unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *ring)
}

/// Writes whatever was collected while the TUI held the screen to stderr,
/// now that it does not. A no-op when nothing was collected, so an
/// ordinary quiet session ends with a clean terminal rather than a header
/// over an empty list.
pub fn drain() {
    let collected = take_collected();
    if collected.is_empty() {
        return;
    }
    eprintln!("{PREFIX} {} message(s) logged during the session:", collected.len());
    for line in collected {
        eprintln!("{line}");
    }
}

/// The one sink every `log_warn!` reaches. Public because the macro
/// expands to a call to it from other modules, not because anything should
/// call it directly - use the macro, which keeps the `aloo:` prefix and
/// the formatting in one place.
pub fn warn(args: std::fmt::Arguments<'_>) {
    let line = format!("{PREFIX} {args}");
    if !is_silenced() {
        eprintln!("{line}");
        return;
    }
    let mut ring = ring().lock().unwrap_or_else(|e| e.into_inner());
    if ring.len() == RING_CAPACITY {
        ring.remove(0);
    }
    ring.push(line);
}

/// One diagnostic line, `aloo:`-prefixed and routed by the current sink.
/// Takes `format!` arguments, and is deliberately the *only* way this
/// crate reports something the user may want to know about but cannot act
/// on in the moment - see the module doc for why a bare `eprintln!` is not
/// an option anywhere a TUI can be running.
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::log::warn(format_args!($($arg)*))
    };
}
