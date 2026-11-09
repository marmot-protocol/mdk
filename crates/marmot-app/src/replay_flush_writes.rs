//! Test-only attribution of the writer transactions the recovery runner's
//! replay flush takes on idle maintenance ticks (mdk#3238). Since #3104 the
//! flush runs at every seam, and an account with an inactive adapter repeats
//! the full replay synchronization, and its writes, on every tick.
//!
//! The idle-tick test excludes exactly these sources, so any other idle
//! writer still fails it. Remove this module and its markers once mdk#3238
//! is fixed.
//!
//! Each marker covers one synchronous storage call and never spans an
//! `.await`, so the per-thread count cannot pick up another task's write.
//! The idle test runs on the current-thread runtime, where the worker, the
//! runner and the test share one thread.

use std::cell::Cell;

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    static WRITES: Cell<u64> = const { Cell::new(0) };
}

/// Marks a replay-flush write source while it is alive.
pub(crate) struct ReplayFlushWrite(());

impl ReplayFlushWrite {
    /// Enters a replay-flush write source on this thread.
    pub(crate) fn enter() -> Self {
        DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self(())
    }
}

impl Drop for ReplayFlushWrite {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

/// Counts a writer transaction begun on this thread, if a replay-flush source
/// is entered.
pub(crate) fn note_write_begin() {
    if DEPTH.with(Cell::get) > 0 {
        WRITES.with(|writes| writes.set(writes.get() + 1));
    }
}

/// Writer transactions begun on this thread by replay-flush sources.
pub(crate) fn writes() -> u64 {
    WRITES.with(Cell::get)
}
