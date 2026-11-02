//! Injectable time and randomness used by maintenance scheduling.
//!
//! Wall-clock values are persisted.  Monotonic values are used only for
//! in-process quiet windows and timeouts, and sampled jitter is persisted
//! before a timer starts.

use cgka_traits::Timestamp;
pub use cgka_traits::maintenance::{MaintenanceRandom, MonotonicClock, WallClock};
use rand::RngCore;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> Timestamp {
        Timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        )
    }

    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Debug)]
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[derive(Debug, Default)]
pub struct OsMaintenanceRandom;

impl MaintenanceRandom for OsMaintenanceRandom {
    fn next_u64(&self) -> u64 {
        rand::rngs::OsRng.next_u64()
    }
}
