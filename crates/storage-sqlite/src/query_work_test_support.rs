//! Test-only SQLite work measurement, including reused statements and trigger subprograms.
use crate::SqliteAccountStorage;
use rusqlite::{
    StatementStatus,
    trace::{TraceEvent, TraceEventCodes},
};
use std::{cell::RefCell, collections::HashMap, sync::Mutex, time::Instant};

pub(crate) static QUERY_MEASUREMENT: Mutex<()> = Mutex::new(());
thread_local! {
    static COUNTERS: RefCell<(i64, HashMap<String, i32>)> = RefCell::new((0, HashMap::new()));
}
fn trace(event: TraceEvent<'_>) {
    COUNTERS.with_borrow_mut(|(total, starts)| match event {
        TraceEvent::Stmt(statement, _) => {
            // Trigger subprograms emit additional Stmt events for the outer statement.
            // Do not reset its baseline until Profile completes that execution.
            starts
                .entry(statement.sql().into_owned())
                .or_insert_with(|| statement.get_status(StatementStatus::VmStep));
        }
        TraceEvent::Profile(statement, _) => {
            let before = starts.remove(statement.sql().as_ref()).unwrap_or(0);
            *total += i64::from(statement.get_status(StatementStatus::VmStep) - before);
        }
        _ => {}
    });
}
pub(crate) fn measure<T>(store: &SqliteAccountStorage, action: impl FnOnce() -> T) -> (T, i64) {
    struct ClearTrace<'a>(&'a SqliteAccountStorage);
    impl Drop for ClearTrace<'_> {
        fn drop(&mut self) {
            self.0
                .lock()
                .unwrap()
                .trace_v2(TraceEventCodes::empty(), None);
        }
    }
    COUNTERS.with_borrow_mut(|state| {
        state.0 = 0;
        state.1.clear();
    });
    {
        let conn = store.lock().unwrap();
        conn.flush_prepared_statement_cache();
        conn.trace_v2(
            TraceEventCodes::SQLITE_TRACE_STMT | TraceEventCodes::SQLITE_TRACE_PROFILE,
            Some(trace),
        );
    }
    let guard = ClearTrace(store);
    let result = action();
    drop(guard);
    (result, COUNTERS.with_borrow(|state| state.0))
}
pub(crate) fn measured<T>(
    store: &SqliteAccountStorage,
    label: &str,
    max_steps: i64,
    action: impl FnOnce() -> T,
) -> T {
    let started = Instant::now();
    let (result, steps) = measure(store, action);
    assert!(
        steps < max_steps,
        "{label}: {steps} >= {max_steps}, elapsed={:?}",
        started.elapsed()
    );
    result
}
#[test]
fn cached_statement_measurement_counts_executions_once() {
    use crate::connection::CachedSql;
    let store = SqliteAccountStorage::in_memory().unwrap();
    let run = |count| {
        measure(&store, || {
            let conn = store.lock().unwrap();
            for _ in 0..count {
                assert_eq!(
                    conn.query_row_cached("SELECT 1", [], |r| r.get::<_, i64>(0))
                        .unwrap(),
                    1
                );
            }
        })
        .1
    };
    assert_eq!(run(10), run(1) * 10);
}
