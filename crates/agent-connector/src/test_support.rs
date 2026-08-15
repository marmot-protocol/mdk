//! Test-only output support for the ignored reconciliation benchmark
//! (`bench_idle_reconciliation_scaling`, mdk#1380). Kept in a file named
//! exactly `test_support.rs` so the workspace direct-output audit
//! (`tracing_audit.rs`) treats the explicit benchmark report as artifact
//! output, matching the storage-upgrade benchmark convention.

pub(crate) fn emit_benchmark_line(line: String) {
    println!("{line}");
}
