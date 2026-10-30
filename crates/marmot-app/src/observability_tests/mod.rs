//! Tests of the code moving to `marmot-observability` (#2627) that need the rest of `marmot-app`:
//! a real `MarmotApp` or runtime, `AppError`, the SQLCipher probe counters, or the process proxy
//! policy. One module per file they came from; the tests that need only the moving code stay
//! with it. They reach the moving code the way the rest of the crate does, through `observer`,
//! `wiring` and public items, and through `observability_test_support` and the
//! `test-support`-gated hooks for what only tests read.

mod app_telemetry;
mod collector_host_safety;
mod product_analytics;
