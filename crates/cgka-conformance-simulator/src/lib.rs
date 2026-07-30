//! # cgka-conformance-simulator
//!
//! In-process multi-client simulator + shared test fixtures for the CGKA
//! engine.
//!
//! ## Layout
//!
//! - [`bus`] - in-memory [`bus::TransportBus`] with seeded scheduler,
//!   partition support, broadcast / addressed delivery for welcomes.
//! - [`client`] - [`client::HarnessClient`] wrapping `Engine<SqliteAccountStorage>`
//!   plus the real Nostr transport peeler over the in-memory bus.
//! - active bidirectional decryptability probes that exercise the complete
//!   application-message path and retain per-edge ledger evidence.
//! - [`canonicalization`] - executable model of the CGKA canonicalization
//!   contract above the branch selector, re-exported from `cgka-engine`.
//! - [`convergence`] - candidate-state graph scoring rules, re-exported
//!   from `cgka-engine`.
//! - [`openmls_projection`] - bytes-first OpenMLS projection and snapshot
//!   replay probes, re-exported from `cgka-engine`.
//!
//! See [`tests/`](../../tests/) in this crate for canonical scenarios.

mod audit_capture;
pub mod bus;
pub mod client;
mod decryptability;
pub mod family;
pub mod oracle;
mod pending_work;
pub mod policy_cases;
pub mod proptest_support;
pub mod report;
pub mod scenario;
mod scenario_input_ledger;
pub mod subject;
pub mod vector;

pub use bus::{ClientId, DeliveryPolicy, TransportBus};
pub use cgka_engine::conformance_snapshot::{
    ConformanceAppComponent, ConformanceCanonicalStateSnapshot, ConformanceDisbandedGroupSnapshot,
    ConformanceGroupSnapshot, ConformanceLeafCapabilities, ConformanceLeafSnapshot,
    ConformancePendingWorkSnapshot, ConformanceRequiredCapabilities,
};
pub use cgka_engine::{canonicalization, convergence, openmls_projection};
pub use client::{ClientBuilder, HarnessClient, HarnessStorageMode};
pub use decryptability::{
    BidirectionalDecryptabilityObservation, DecryptabilityProbeSendStatus,
    DirectionalDecryptabilityProbe,
};
pub use family::{
    GeneratedScenarioCase, generate_convergence_chaos_family,
    generate_convergence_e2e_delivery_family, generate_send_leave_family,
    run_generated_case_report, run_generated_case_report_with_storage_mode,
};
pub use oracle::{
    BehaviorEvidenceSummary, CoverageMatrixEntry, OracleBehavior, OracleCoverageWarning,
    ScenarioOracleReport, ScenarioStimulus, behavior_evidence, build_scenario_oracle_report,
    coverage_matrix_entry, expected_behaviors, property_test_coverage_entries, scenario_stimuli,
    trace_behaviors,
};
pub use pending_work::PendingWorkObservation;
pub use report::{
    ReportArgs, ReportCommand, ReportFailureSummary, ReportInput, ReportRunSummary,
    ScenarioReportSummary, parse_report_command, report_usage, run_report,
};
pub use scenario::{
    AppInvalidationReportObservation, EpochChangeReportObservation, GeneratedScenarioMetadata,
    InvariantFailure, ScenarioReport, ScenarioReportMetadata, ScenarioRunError, ScenarioSpec,
    ScenarioStep, ScenarioStepLogEntry, ScenarioStepStatus, VectorFixtureMetadata,
    run_scenario_report, run_scenario_report_with_outcomes,
    run_scenario_report_with_outcomes_and_storage_mode, run_scenario_report_with_storage_mode,
    run_scenario_report_with_subject, run_scenario_spec, run_scenario_spec_with_subject,
    run_vector_fixture_report, run_vector_fixture_report_with_storage_mode,
    validate_scenario_for_subject,
};
pub use scenario_input_ledger::{
    ScenarioInputDisposition, ScenarioInputKind, ScenarioInputLedgerEntry,
};
pub use subject::{
    ConvergenceFaultSubject, ConvergenceSubject, EngineHarnessSubject, SubjectCapability,
    SubjectCreateGroup, SubjectDescriptor, SubjectError, SubjectInviteMembers,
    SubjectSendApplication, SubjectUpdateAdminPolicy, SubjectUpdateGroupData, required_capability,
};
pub use vector::{
    AppInvalidationObservation, ApplicationProfileContract, ClientEventCounts, ClientObservation,
    ConvergenceDecisionObservation, EpochChangeObservation, ExpectationFailure,
    ForkRecoveryObservation, PendingResolutionObservation, RecoveryOrderingKeyObservation,
    ScenarioAdminPolicyObservation, ScenarioErrorObservation, ScenarioTrace, TraceExpectation,
    VectorFixture, VectorMismatch, compare_trace_expectations, observe_client,
    observe_client_exact,
};
