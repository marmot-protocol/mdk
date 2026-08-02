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
mod failure_capsule;
pub mod family;
pub mod oracle;
mod pending_work;
pub mod policy_cases;
pub mod proptest_support;
mod quiescence;
mod reference_subject;
pub mod report;
mod retained_relay;
pub mod scenario;
mod scenario_assertions;
mod scenario_authoring;
mod scenario_faults;
mod scenario_input_ledger;
mod scenario_ir;
pub mod subject;
mod topology;
pub mod vector;

pub use bus::{ClientId, DeliveryPolicy, TransportBus};
pub use cgka_engine::conformance_snapshot::{
    ConformanceAppComponent, ConformanceCanonicalStateSnapshot, ConformanceConstantSnapshot,
    ConformanceDisbandedGroupSnapshot, ConformanceGroupSnapshot, ConformanceLeafCapabilities,
    ConformanceLeafSnapshot, ConformancePendingWorkSnapshot, ConformanceRequiredCapabilities,
    ConformanceStructuralProgressSnapshot, conformance_constant_snapshot,
};
pub use cgka_engine::{canonicalization, convergence, openmls_projection};
pub use client::{ClientBuilder, HarnessClient, HarnessStorageMode};
pub use decryptability::{
    BidirectionalDecryptabilityObservation, DecryptabilityProbeSendStatus,
    DirectionalDecryptabilityProbe,
};
pub use failure_capsule::{
    CapsulePolicySnapshotV1, CapturedTransportArtifactV1, CapturedTransportWindowV1,
    EngineByteReplayObservationV1, EngineByteReplayV1, ExpandedScenarioActionV1,
    FAILURE_CAPSULE_SCHEMA_VERSION, FAILURE_FINGERPRINT_VERSION, FailureCapsuleError,
    FailureCapsuleSensitivity, FailureCapsuleV1, FailureFingerprintV1, FailureIdentityV1,
    MAX_CAPTURED_REPLAY_CHECKPOINT_BYTES, MAX_CAPTURED_TRANSPORT_JSON_BYTES,
    MAX_CAPTURED_TRANSPORT_OBJECTS, ResourceObservationV1, ScenarioFailureCaptureV1,
    TerminalOutcomeClassification, build_fingerprint, digest_json, fingerprint_report_failure,
    promote_failure_capsule_to_vector, read_failure_capsule, replay_engine_bytes,
    write_failure_capsule,
};
pub use family::{
    GeneratedScenarioCase, generate_convergence_chaos_family,
    generate_convergence_e2e_delivery_family, generate_send_leave_family,
    run_generated_case_report, run_generated_case_report_with_capture,
    run_generated_case_report_with_storage_mode,
};
pub use oracle::{
    BehaviorEvidenceSummary, CoverageMatrixEntry, OracleBehavior, OracleCoverageWarning,
    ScenarioOracleReport, ScenarioStimulus, behavior_evidence, build_scenario_oracle_report,
    coverage_matrix_entry, expected_behaviors, property_test_coverage_entries, scenario_stimuli,
    trace_behaviors,
};
pub use pending_work::{
    ClientStructuralProgress, PendingWorkObservation, SubjectProgressSnapshot,
    SubjectTerminalBlocker,
};
pub use quiescence::{
    QuiescenceObservation, QuiescenceOutboundPolicy, QuiescencePolicy, QuiescenceStatus,
    QuiescenceTransportPolicy, QuiescenceWatchdog, drive_subject_to_quiescence,
};
pub use reference_subject::ReferenceModelSubject;
pub use report::{
    ReportArgs, ReportCommand, ReportFailureSummary, ReportInput, ReportRunSummary,
    ScenarioReportSummary, parse_report_command, report_usage, run_report,
};
pub use retained_relay::{
    RelayHistoryCompletenessClaimV2, RelaySyncObservationV2, RetainedRelaySubject,
    ScenarioRelayOrderV2, ScenarioRelaySyncModeV2,
};
pub use scenario::{
    AppInvalidationReportObservation, EpochChangeReportObservation, GeneratedScenarioMetadata,
    InvariantFailure, ScenarioOutboundSelection, ScenarioReport, ScenarioReportMetadata,
    ScenarioRunError, ScenarioSpec, ScenarioStep, ScenarioStepLogEntry, ScenarioStepStatus,
    VectorFixtureMetadata, run_scenario_report, run_scenario_report_with_outcomes,
    run_scenario_report_with_outcomes_and_capture,
    run_scenario_report_with_outcomes_and_storage_mode, run_scenario_report_with_storage_mode,
    run_scenario_report_with_subject, run_scenario_spec, run_scenario_spec_with_subject,
    run_vector_fixture_report, run_vector_fixture_report_with_capture,
    run_vector_fixture_report_with_storage_mode, validate_scenario_for_subject,
};
pub use scenario_assertions::{
    ScenarioAssertionObservationV2, ScenarioAssertionV2, ScenarioComparison,
    ScenarioPredicateObservationV2, ScenarioPredicateV2, ScenarioResourceMetric, resource_value,
};
pub use scenario_authoring::{
    MAX_EXPANDED_SCENARIO_ACTIONS, SCENARIO_AUTHORING_VERSION, ScenarioAuthoringSpec, ScenarioFlow,
    ScenarioParallelLane, compile_authoring_scenario, compile_authoring_yaml,
};
pub use scenario_faults::{
    ScenarioMessageSelectorV2, ScenarioStorageFaultKind, ScenarioStorageFaultV2,
    ScenarioTransportClass,
};
pub use scenario_input_ledger::{
    ScenarioInputDisposition, ScenarioInputKind, ScenarioInputLedgerEntry,
};
pub use scenario_ir::{
    CompiledScenarioActionV2, CompiledScenarioV2, SCENARIO_IR_VERSION, ScenarioActionScheduleV2,
    compile_scenario, preflight_compiled_scenario, stable_action_id,
};
pub use subject::{
    ConvergenceFaultSubject, ConvergenceSubject, EngineHarnessSubject, SubjectCapability,
    SubjectCreateGroup, SubjectDescriptor, SubjectError, SubjectFailureCategory,
    SubjectInviteMembers, SubjectOutboundArtifact, SubjectOutboundKind, SubjectOutboundOutcome,
    SubjectRemoveMembers, SubjectSelfUpdate, SubjectSendApplication, SubjectUpdateAdminPolicy,
    SubjectUpdateGroupData, engine_harness_feature_registry, required_capabilities,
};
pub use topology::{
    ScenarioAccountV2, ScenarioDeviceV2, ScenarioGroupV2, ScenarioProcessV2, ScenarioRelayV2,
    ScenarioTopologyV2,
};
pub use vector::{
    AppInvalidationObservation, ApplicationProfileContract, ClientEventCounts, ClientObservation,
    ConvergenceDecisionObservation, EpochChangeObservation, ExpectationFailure,
    ForkRecoveryObservation, PendingResolutionObservation, RecoveryOrderingKeyObservation,
    ScenarioAdminPolicyObservation, ScenarioErrorObservation, ScenarioTrace, TraceExpectation,
    VectorFixture, VectorMismatch, compare_trace_expectations, observe_client,
    observe_client_exact,
};
