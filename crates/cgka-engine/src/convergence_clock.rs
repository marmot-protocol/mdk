//! Dual-clock time source for convergence scheduling.
//!
//! Convergence uses process-local monotonic milliseconds for live scheduling
//! and persisted wall-clock milliseconds only to reconstruct deadlines after a
//! restart. Keeping both values behind one injectable source lets tests advance
//! time without sleeping while keeping unrelated protocol/event timestamps on
//! their existing clocks.

use std::sync::{Arc, Mutex};
use web_time::{Instant, SystemTime, UNIX_EPOCH};

/// One paired convergence-clock observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConvergenceTime {
    pub monotonic_ms: u64,
    pub wall_ms: u64,
}

/// Injectable source of monotonic and wall-clock milliseconds for convergence.
pub trait ConvergenceClock: Send + Sync {
    fn now(&self) -> ConvergenceTime;
}

/// Production convergence clock.
#[derive(Debug)]
pub struct SystemConvergenceClock {
    started_at: Instant,
}

impl Default for SystemConvergenceClock {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl ConvergenceClock for SystemConvergenceClock {
    fn now(&self) -> ConvergenceTime {
        ConvergenceTime {
            monotonic_ms: self
                .started_at
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            wall_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        }
    }
}

/// Manually controlled convergence clock for deterministic tests and harnesses.
#[derive(Clone, Debug)]
pub struct ManualConvergenceClock {
    state: Arc<Mutex<ConvergenceTime>>,
}

impl ManualConvergenceClock {
    pub fn new(monotonic_ms: u64, wall_ms: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(ConvergenceTime {
                monotonic_ms,
                wall_ms,
            })),
        }
    }

    /// Advance both clock domains by the same elapsed duration.
    pub fn advance_ms(&self, delta_ms: u64) {
        let mut now = self.lock();
        now.monotonic_ms = now.monotonic_ms.saturating_add(delta_ms);
        now.wall_ms = now.wall_ms.saturating_add(delta_ms);
    }

    /// Advance only process-local monotonic time.
    pub fn advance_monotonic_ms(&self, delta_ms: u64) {
        let mut now = self.lock();
        now.monotonic_ms = now.monotonic_ms.saturating_add(delta_ms);
    }

    /// Set wall time directly, including backwards-clock test cases.
    pub fn set_wall_ms(&self, wall_ms: u64) {
        self.lock().wall_ms = wall_ms;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConvergenceTime> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ConvergenceClock for ManualConvergenceClock {
    fn now(&self) -> ConvergenceTime {
        *self.lock()
    }
}
