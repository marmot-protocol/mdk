//! Injectable time and randomness used by maintenance scheduling.
//!
//! Wall-clock values are persisted.  Monotonic values are used only for
//! in-process quiet windows and timeouts, and sampled jitter is persisted
//! before a timer starts. The session and engine use the same system defaults.

pub use cgka_engine::SystemMonotonicClock;
pub use cgka_traits::{EntropySource, MonotonicClock, OsEntropy, SystemWallClock, WallClock};
