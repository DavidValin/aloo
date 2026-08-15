//! System CPU sampling for the channel view's `CPU:<pct>%` header
//! indicator (`docs/SPEC.md` "Connected UI") - wraps `sysinfo::System` so
//! `crate::ui` never needs to know how CPU usage is actually measured on
//! the underlying OS. `sysinfo` covers Linux, macOS and Windows itself, so
//! there's no per-platform branching here.

use sysinfo::System;

/// Below this percentage the header renders `CPU:<pct>%` in green; at or
/// above it, red - see `crate::ui::channel::cpu_color`.
pub const CPU_HEALTHY_MAX_PCT: f32 = 25.0;

/// Samples system-wide CPU usage on demand.
pub struct CpuMonitor {
    sys: System,
}

impl CpuMonitor {
    pub fn new() -> Self {
        Self { sys: System::new() }
    }

    /// Re-samples CPU usage and returns the new system-wide percentage,
    /// clamped to `0.0..=100.0` as a defensive bound against whatever the
    /// underlying OS API might hand back. `sysinfo` needs consecutive
    /// calls spaced at least `sysinfo::MINIMUM_CPU_UPDATE_INTERVAL` apart
    /// to report a real number - the very first call after construction
    /// always reads `0.0`, which happens to double as a harmless initial
    /// value for `UiState::cpu_usage_pct` (renders green, not misleadingly
    /// red) until the first real sample lands.
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
