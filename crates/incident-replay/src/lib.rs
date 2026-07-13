//! # incident-replay
//!
//! Adapter that turns a Goggles `agent-state.json` forensic export into a
//! conformance vector for the CGKA simulator. The pipeline is: **parse** the
//! export, **classify** it, and — for a fork-recovery or convergence incident —
//! **recover** the decision, **synthesize** a scenario, and **accept** it only if
//! the simulator reproduces the recorded outcome (fail-closed).
//!
//! - [`export`] — a lenient, self-owned model of the export (decoupled from the
//!   engine's forensic types; it tracks the stable `marmot-forensics-audit/v2`
//!   wire shape Goggles emits, not the Rust enum).
//! - [`ndjson`] — [`ndjson::parse_stream`], the second parser: the Goggles
//!   streaming NDJSON export (`goggles-group-export/v1`) into the same
//!   [`export::AgentStateExport`], enforcing the stream's fail-closed
//!   completeness contract (terminal `eof`, matching section counts).
//! - [`classify`] — the [`classify::classify`] gate: `Healthy | ForkRecovery |
//!   ConvergenceSelected | Quarantine`. Everything downstream is gated behind it.
//! - [`fork`] — [`fork::recover_fork`] extracts a [`fork::RecoveredFork`] from a
//!   fork-recovery export, or quarantines when it cannot be replayed.
//! - [`convergence`] — [`convergence::recover_convergence`] extracts a
//!   [`convergence::RecoveredConvergence`] from a convergence-selected export
//!   (committer- or witness-decided), or quarantines a shape it cannot reproduce.
//! - [`synth`] — [`synth::synthesize`] / [`synth::synthesize_convergence`] build
//!   the vector for a recovered fork / convergence decision.
//! - [`accept`] — [`accept::accept`] / [`accept::accept_convergence`] run the
//!   synthesized scenario against the simulator and return the vector only if the
//!   recorded outcome reproduces.

pub mod accept;
pub mod classify;
pub mod convergence;
pub mod export;
pub mod fork;
pub mod ndjson;
pub mod synth;

pub use accept::{AcceptError, accept, accept_convergence};
pub use classify::{BehindEngine, BehindMode, QuarantineReason, Verdict, classify};
pub use convergence::{
    ConvergenceDecisionKind, ConvergenceRecoveryError, RecoveredConvergence, recover_convergence,
};
pub use export::{AgentStateExport, ParseError, parse};
pub use fork::{ForkCommitKind, ForkRecoveryError, RecoveredFork, recover_fork};
pub use ndjson::{StreamParseError, is_stream, parse_stream};
pub use synth::{synthesize, synthesize_convergence};
