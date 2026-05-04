//! # test-harness
//!
//! In-process multi-client simulator + shared test fixtures for the CGKA
//! engine.
//!
//! ## Layout
//!
//! - [`bus`] — in-memory [`bus::TransportBus`] with seeded scheduler,
//!   partition support, broadcast / addressed delivery for welcomes.
//! - [`client`] — [`client::HarnessClient`] wrapping `Engine<MemoryStorage>`
//!   plus a [`peeler::MockPeeler`] (skips actual crypto — tests assert on
//!   inner payloads directly).
//! - [`peeler`] — pass-through [`peeler::MockPeeler`].
//!
//! See [`tests/`](../../tests/) in this crate for canonical scenarios.

pub mod bus;
pub mod client;
pub mod peeler;
pub mod proptest_support;
pub mod scenario;
pub mod vector;

pub use bus::{ClientId, DeliveryPolicy, TransportBus};
pub use client::{ClientBuilder, HarnessClient};
pub use peeler::MockPeeler;
pub use scenario::{ScenarioRunError, ScenarioSpec, ScenarioStep, run_scenario_spec};
pub use vector::{
    ClientObservation, ForkRecoveryObservation, RecoveryOrderingKeyObservation, ScenarioTrace,
    VectorFixture, observe_client,
};
