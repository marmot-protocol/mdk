//! # cgka-conformance
//!
//! In-process multi-client simulator + shared test fixtures for the CGKA
//! engine.
//!
//! ## Layout
//!
//! - [`bus`] - in-memory [`bus::TransportBus`] with seeded scheduler,
//!   partition support, broadcast / addressed delivery for welcomes.
//! - [`client`] - [`client::HarnessClient`] wrapping `Engine<MemoryStorage>`
//!   plus a [`peeler::MockPeeler`] (skips actual crypto - tests assert on
//!   inner payloads directly).
//! - [`canonicalization`] - executable model of the CGKA canonicalization
//!   contract above the branch selector, re-exported from `cgka-engine`.
//! - [`convergence`] - candidate-state graph scoring rules, re-exported
//!   from `cgka-engine`.
//! - [`openmls_projection`] - bytes-first OpenMLS projection and snapshot
//!   replay probes, re-exported from `cgka-engine`.
//! - [`peeler`] - pass-through [`peeler::MockPeeler`].
//!
//! See [`tests/`](../../tests/) in this crate for canonical scenarios.

pub mod bus;
pub mod client;
pub mod family;
pub mod peeler;
pub mod policy_cases;
pub mod proptest_support;
pub mod report;
pub mod scenario;
pub mod vector;

pub use bus::{ClientId, DeliveryPolicy, TransportBus};
pub use cgka_engine::{canonicalization, convergence, openmls_projection};
pub use client::{ClientBuilder, HarnessClient};
pub use family::{GeneratedScenarioCase, generate_send_leave_family, run_generated_case_report};
pub use peeler::MockPeeler;
pub use report::{ReportArgs, ReportCommand, parse_report_command, report_usage, run_report};
pub use scenario::{
    GeneratedScenarioMetadata, InvariantFailure, ScenarioReport, ScenarioReportMetadata,
    ScenarioRunError, ScenarioSpec, ScenarioStep, ScenarioStepLogEntry, ScenarioStepStatus,
    run_scenario_report, run_scenario_spec,
};
pub use vector::{
    ClientObservation, ForkRecoveryObservation, RecoveryOrderingKeyObservation, ScenarioTrace,
    VectorFixture, observe_client,
};
