//! Injectable time and randomness used by maintenance scheduling.
//!
//! Wall-clock values are persisted.  Monotonic values are used only for
//! in-process quiet windows and timeouts, and sampled jitter is persisted
//! before a timer starts.  The system implementations are the engine's, so a
//! session and its engine read time the same way.

pub use cgka_engine::{OsMaintenanceRandom, SystemMonotonicClock, SystemWallClock};
pub use cgka_traits::maintenance::{MaintenanceRandom, MonotonicClock, WallClock};
