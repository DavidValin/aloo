//! Tracks how quickly protocol messages are moving over this session's
//! socket, in either direction, as the channel view's `Conn:<quality>`
//! header indicator (`crate::client::tui::channel::render_channel_view`, see
//! `docs/SPEC.md` "Connected UI"). There's no ping/pong or RTT measurement
//! in the wire protocol (`docs/PROTOCOL.md`), so this measures the
//! interval between consecutive protocol messages actually observed - sent
//! or received, text or voice-stream chunks alike - rather than a true
//! round trip time: a live conversation with frequent back-and-forth
//! traffic reads as `Good`, and a connection that has gone quiet (whether
//! from network trouble or simply nobody typing) reads as `Bad`, the same
//! way it would look to someone watching the log scroll.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How many of the most recent inter-message intervals feed the running
/// average - "the average of the last 1-3 messages" per `docs/SPEC.md`.
pub const CONN_STATS_MAX_SAMPLES: usize = 3;

/// An average interval at or below this is `Good`.
pub const CONN_GOOD_MAX_INTERVAL: Duration = Duration::from_millis(500);

/// An average interval at or above this is `Bad`; anything in between the
/// two thresholds is `Normal`.
pub const CONN_BAD_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// The header's `Conn:<quality>` classification - see the module doc for
/// what "quality" means here, and the `CONN_*` constants for thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnQuality {
    /// No message has been observed yet this session - nothing to
    /// average. Rendered as a plain `-`.
    #[default]
    Unknown,
    Bad,
    Normal,
    Good,
}

impl ConnQuality {
    /// The exact header glyph for this quality (`docs/SPEC.md` "Connected
    /// UI"): `-` for `Unknown`, otherwise the variant's own name.
    pub fn label(self) -> &'static str {
        match self {
            ConnQuality::Unknown => "-",
            ConnQuality::Bad => "BAD",
            ConnQuality::Normal => "NORMAL",
            ConnQuality::Good => "GOOD",
        }
    }
}

/// A rolling record of the gaps between consecutive protocol messages seen
/// on this session's socket, in either direction (`record_event`).
pub struct ConnStats {
    last_event: Option<Instant>,
    intervals: VecDeque<Duration>,
}

impl ConnStats {
    pub fn new() -> Self {
        Self {
            last_event: None,
            intervals: VecDeque::with_capacity(CONN_STATS_MAX_SAMPLES),
        }
    }

    /// Records one message (sent or received) observed at `now`. The very
    /// first call has nothing to compare against and only seeds
    /// `last_event`; every call after that pushes the gap since the
    /// previous one, evicting the oldest once more than
    /// `CONN_STATS_MAX_SAMPLES` are held. A `now` that is not after the
    /// last recorded event - should not happen with a monotonic clock, but
    /// `Instant` subtraction panics if it ever went backwards - is treated
    /// as a no-op for the interval itself, while still moving `last_event`
    /// forward so a single out-of-order timestamp can't wedge every future
    /// call.
    pub fn record_event(&mut self, now: Instant) {
        if let Some(prev) = self.last_event
            && now >= prev
        {
            if self.intervals.len() == CONN_STATS_MAX_SAMPLES {
                self.intervals.pop_front();
            }
            self.intervals.push_back(now - prev);
        }
        self.last_event = Some(now);
    }

    /// The average of the currently-held intervals, or `None` if fewer
    /// than two messages have ever been observed.
    pub fn average_interval(&self) -> Option<Duration> {
        if self.intervals.is_empty() {
            return None;
        }
        let total: Duration = self.intervals.iter().sum();
        Some(total / self.intervals.len() as u32)
    }

    /// Classifies the current average interval - see the module doc and
    /// the `CONN_*` constants for the thresholds.
    pub fn quality(&self) -> ConnQuality {
        match self.average_interval() {
            None => ConnQuality::Unknown,
            Some(d) if d <= CONN_GOOD_MAX_INTERVAL => ConnQuality::Good,
            Some(d) if d < CONN_BAD_MIN_INTERVAL => ConnQuality::Normal,
            Some(_) => ConnQuality::Bad,
        }
    }
}

impl Default for ConnStats {
    fn default() -> Self {
        Self::new()
    }
}
