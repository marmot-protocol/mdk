//! # incident-replay
//!
//! Adapter that turns a Goggles `agent-state.json` forensic export into
//! conformance vectors for the CGKA simulator. This crate is the skeleton
//! (Phase 2): it **parses** an export and **classifies** it, gating everything
//! downstream behind that verdict.
//!
//! - [`export`] — a lenient, self-owned model of the export (decoupled from the
//!   engine's forensic types; it tracks the stable `marmot-forensics-audit/v2`
//!   wire shape Goggles emits, not the Rust enum).
//! - [`classify`] — the [`classify::classify`] gate: `Healthy | ForkRecovery |
//!   ConvergenceSelected | Quarantine`.
//!
//! Extraction, fault synthesis, and run-and-compare against the simulator are
//! later phases and deliberately absent here.

pub mod classify;
pub mod export;

pub use classify::{QuarantineReason, Verdict, classify};
pub use export::{AgentStateExport, ParseError, parse};
