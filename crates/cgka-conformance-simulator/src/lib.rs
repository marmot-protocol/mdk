//! # cgka-conformance-simulator
//!
//! In-process multi-client simulator + shared test fixtures for the CGKA
//! engine.
//!
//! ## Layout
//!
//! - [`bus`] - in-memory [`bus::TransportBus`] with seeded scheduler,
//!   partition support, broadcast / addressed delivery for welcomes.
//! - [`client`] - [`client::HarnessClient`] wrapping `Engine<MemoryStorage>`
//!   plus the real Nostr transport peeler over the in-memory bus.
//! - [`canonicalization`] - executable model of the CGKA canonicalization
//!   contract above the branch selector, re-exported from `cgka-engine`.
//! - [`convergence`] - candidate-state graph scoring rules, re-exported
//!   from `cgka-engine`.
//! - [`openmls_projection`] - bytes-first OpenMLS projection and snapshot
//!   replay probes, re-exported from `cgka-engine`.
//!
//! See [`tests/`](../../tests/) in this crate for canonical scenarios.

pub mod bus;
pub mod client;
pub mod family;
pub mod oracle;
pub mod policy_cases;
pub mod proptest_support;
pub mod report;
pub mod scenario;
pub mod vector;

pub use bus::{ClientId, DeliveryPolicy, TransportBus};
pub use cgka_engine::{canonicalization, convergence, openmls_projection};
pub use client::{ClientBuilder, HarnessClient};
pub use family::{
    GeneratedScenarioCase, generate_convergence_chaos_family,
    generate_convergence_e2e_delivery_family, generate_send_leave_family,
    run_generated_case_report,
};
pub use oracle::{
    BehaviorEvidenceSummary, CoverageMatrixEntry, OracleBehavior, OracleCoverageWarning,
    ScenarioOracleReport, ScenarioStimulus, behavior_evidence, build_scenario_oracle_report,
    coverage_matrix_entry, expected_behaviors, property_test_coverage_entries, scenario_stimuli,
    trace_behaviors,
};
pub use report::{
    ReportArgs, ReportCommand, ReportFailureSummary, ReportInput, ReportRunSummary,
    ScenarioReportSummary, parse_report_command, report_usage, run_report,
};
pub use scenario::{
    AppInvalidationReportObservation, EpochChangeReportObservation, GeneratedScenarioMetadata,
    InvariantFailure, ScenarioReport, ScenarioReportMetadata, ScenarioRunError, ScenarioSpec,
    ScenarioStep, ScenarioStepLogEntry, ScenarioStepStatus, VectorFixtureMetadata,
    run_scenario_report, run_scenario_report_with_outcomes, run_scenario_spec,
    run_vector_fixture_report,
};
pub use vector::{
    AppInvalidationObservation, ClientEventCounts, ClientObservation, EpochChangeObservation,
    ExpectationFailure, ForkRecoveryObservation, PendingResolutionObservation,
    RecoveryOrderingKeyObservation, ScenarioTrace, TraceExpectation, VectorFixture, VectorMismatch,
    compare_trace_expectations, observe_client,
};
