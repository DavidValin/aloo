use std::time::{Duration, Instant};

use aloo::netstats::{
    CONN_BAD_MIN_INTERVAL, CONN_GOOD_MAX_INTERVAL, CONN_STATS_MAX_SAMPLES, ConnQuality, ConnStats,
};

/// @requirement TB-121
#[test]
fn quality_is_unknown_with_no_events() {
    let stats = ConnStats::new();
    assert_eq!(stats.average_interval(), None);
    assert_eq!(stats.quality(), ConnQuality::Unknown);
    assert_eq!(stats.quality().label(), "-");
}

/// @requirement TB-120
#[test]
fn average_interval_is_still_none_after_a_single_event() {
    let mut stats = ConnStats::new();
    stats.record_event(Instant::now());
    assert_eq!(
        stats.average_interval(),
        None,
        "one timestamp alone has no gap to measure"
    );
}

/// @requirement TB-120
#[test]
fn average_interval_averages_up_to_three_most_recent_gaps() {
    let mut stats = ConnStats::new();
    let t0 = Instant::now();
    stats.record_event(t0);
    stats.record_event(t0 + Duration::from_millis(100));
    stats.record_event(t0 + Duration::from_millis(300)); // gap 200ms
    // gaps so far: 100ms, 200ms -> average 150ms
    assert_eq!(stats.average_interval(), Some(Duration::from_millis(150)));
}

/// @requirement TB-120
#[test]
fn older_gaps_are_evicted_once_more_than_max_samples_are_recorded() {
    let mut stats = ConnStats::new();
    let t0 = Instant::now();
    // Four events -> three gaps of 300ms each. Capacity is
    // CONN_STATS_MAX_SAMPLES (3), so nothing is evicted yet here - this
    // pins the capacity itself before the next step proves eviction.
    assert_eq!(
        CONN_STATS_MAX_SAMPLES, 3,
        "the rest of this test assumes a capacity of 3"
    );
    stats.record_event(t0);
    stats.record_event(t0 + Duration::from_millis(300));
    stats.record_event(t0 + Duration::from_millis(600));
    stats.record_event(t0 + Duration::from_millis(900));
    assert_eq!(
        stats.average_interval(),
        Some(Duration::from_millis(300)),
        "(300+300+300)/3"
    );

    // A fifth event pushes a fourth gap (90ms) and must evict the oldest
    // 300ms gap, not just grow unbounded.
    stats.record_event(t0 + Duration::from_millis(990));
    assert_eq!(
        stats.average_interval(),
        Some(Duration::from_millis(230)),
        "(300+300+90)/3, oldest 300ms gap evicted"
    );
}

/// @requirement TB-121
#[test]
fn quality_is_good_at_or_below_the_good_threshold() {
    let mut stats = ConnStats::new();
    let t0 = Instant::now();
    stats.record_event(t0);
    stats.record_event(t0 + CONN_GOOD_MAX_INTERVAL);
    assert_eq!(stats.quality(), ConnQuality::Good);
    assert_eq!(stats.quality().label(), "GOOD");
}

/// @requirement TB-121
#[test]
fn quality_is_normal_between_the_two_thresholds() {
    let mut stats = ConnStats::new();
    let t0 = Instant::now();
    stats.record_event(t0);
    stats.record_event(t0 + CONN_GOOD_MAX_INTERVAL + Duration::from_millis(1));
    assert_eq!(stats.quality(), ConnQuality::Normal);
    assert_eq!(stats.quality().label(), "NORMAL");
}

/// @requirement TB-121
#[test]
fn quality_is_bad_at_or_above_the_bad_threshold() {
    let mut stats = ConnStats::new();
    let t0 = Instant::now();
    stats.record_event(t0);
    stats.record_event(t0 + CONN_BAD_MIN_INTERVAL);
    assert_eq!(stats.quality(), ConnQuality::Bad);
    assert_eq!(stats.quality().label(), "BAD");
}

/// @requirement TB-120
#[test]
fn an_out_of_order_timestamp_does_not_panic_or_record_a_negative_interval() {
    let mut stats = ConnStats::new();
    let t0 = Instant::now();
    stats.record_event(t0 + Duration::from_secs(1));
    // A timestamp earlier than the last-recorded one - should never
    // happen with a monotonic clock, but must not panic (Instant
    // subtraction panics if it would go negative) or corrupt the stats.
    stats.record_event(t0);
    assert_eq!(
        stats.average_interval(),
        None,
        "the out-of-order pair contributes no interval"
    );
}
