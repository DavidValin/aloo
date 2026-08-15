use std::thread::sleep;

use aloo::sysstats::{CPU_HEALTHY_MAX_PCT, CpuMonitor};

/// @requirement TB-119
#[test]
fn refresh_reports_a_percentage_in_range() {
    let mut monitor = CpuMonitor::new();
    // sysinfo needs consecutive samples spaced apart to compute real
    // usage; the very first refresh always reads 0.0, which is itself
    // in range, but sleeping past sysinfo's own minimum interval and
    // refreshing again is what actually exercises the real OS sampling
    // path rather than just the harmless startup default.
    monitor.refresh();
    sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL + std::time::Duration::from_millis(50));
    let pct = monitor.refresh();
    assert!(
        (0.0..=100.0).contains(&pct),
        "CPU usage {pct} out of the documented 0..=100 range"
    );
}

/// @requirement TB-119
#[test]
fn cpu_healthy_max_pct_is_a_realistic_percentage() {
    assert!((0.0..=100.0).contains(&CPU_HEALTHY_MAX_PCT));
}
