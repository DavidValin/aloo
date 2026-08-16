//! System CPU sampling for the channel view's `CPU:<pct>%` header
//! indicator (`docs/SPEC.md` "Connected UI") - wraps `sysinfo::System` so
//! `crate::client::tui` never needs to know how CPU usage is actually measured on
//! the underlying OS. `sysinfo` covers Linux, macOS and Windows itself, so
//! there's no per-platform branching here.

use sysinfo::System;

/// Below this percentage the header renders `CPU:<pct>%` in green; at or
/// above it, red - see `crate::client::tui::channel::cpu_color`.
pub const CPU_HEALTHY_MAX_PCT: f32 = 25.0;

/// Samples system-wide CPU usage on demand.
pub struct CpuMonitor {
    sys: System,
}

impl CpuMonitor {
    pub fn new() -> Self {
        Self { sys: System::new() }
    }

    /// Re-samples system-wide CPU usage, clamped to `0.0..=100.0` against
    /// whatever the OS hands back. `sysinfo` needs calls spaced at least
    /// `MINIMUM_CPU_UPDATE_INTERVAL` apart for a real number - the first
    /// call always reads `0.0`, a harmless initial value (renders green,
    /// not misleadingly red) until the first real sample lands.
    pub fn refresh(&mut self) -> f32 {
        self.sys.refresh_cpu_usage();
        self.sys.global_cpu_usage().clamp(0.0, 100.0)
    }
}

impl Default for CpuMonitor {
    fn default() -> Self {
        Self::new()
    }
}
