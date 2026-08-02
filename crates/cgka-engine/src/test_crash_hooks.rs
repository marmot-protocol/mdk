//! Debug-only pause points for subprocess crash-durability tests.
//!
//! The feature is inert unless a child process explicitly selects one fixed
//! point through `MDK_CGKA_TEST_CRASH_POINT`. No identifiers or state values
//! are emitted.

const CRASH_POINT_ENV: &str = "MDK_CGKA_TEST_CRASH_POINT";
const CRASH_OCCURRENCE_ENV: &str = "MDK_CGKA_TEST_CRASH_OCCURRENCE";
const READY_PREFIX: &str = "MDK_CGKA_TEST_CRASH_READY:";

#[cfg(all(feature = "test-crash-hooks", debug_assertions))]
static MATCHING_OCCURRENCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[inline]
pub(crate) fn pause_if_requested(point: &'static str) {
    #[cfg(all(feature = "test-crash-hooks", debug_assertions))]
    {
        use std::io::Write as _;

        if std::env::var(CRASH_POINT_ENV).as_deref() != Ok(point) {
            return;
        }
        let selected_occurrence = std::env::var(CRASH_OCCURRENCE_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        let occurrence =
            MATCHING_OCCURRENCES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if occurrence != selected_occurrence {
            return;
        }
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        writeln!(stdout, "{READY_PREFIX}{point}").expect("write crash-hook ready marker");
        stdout.flush().expect("flush crash-hook ready marker");
        drop(stdout);
        loop {
            std::thread::park();
        }
    }

    #[cfg(not(all(feature = "test-crash-hooks", debug_assertions)))]
    {
        let _ = (point, CRASH_POINT_ENV, CRASH_OCCURRENCE_ENV, READY_PREFIX);
    }
}
