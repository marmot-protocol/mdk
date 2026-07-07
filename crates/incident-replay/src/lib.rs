//! # incident-replay
//!
//! Adapter that turns a Goggles `agent-state.json` forensic export into a
//! conformance vector for the CGKA simulator. The pipeline is: **parse** the
//! export, **classify** it, and — for a fork-recovery incident — **recover** the
//! fork, **synthesize** a scenario, and **accept** it only if the simulator
//! reproduces the recorded outcome (fail-closed).
//!
//! - [`export`] — a lenient, self-owned model of the export (decoupled from the
//!   engine's forensic types; it tracks the stable `marmot-forensics-audit/v2`
//!   wire shape Goggles emits, not the Rust enum).
//! - [`classify`] — the [`classify::classify`] gate: `Healthy | ForkRecovery |
//!   ConvergenceSelected | Quarantine`. Everything downstream is gated behind it.
//! - [`fork`] — [`fork::recover_fork`] extracts a [`fork::RecoveredFork`] (source
//!   epoch, commit kind, designated winner) from a fork-recovery export, or
//!   quarantines when it cannot be replayed.
//! - [`synth`] — [`synth::synthesize`] builds the concurrent-fork vector for a
//!   recovered fork.
//! - [`accept`] — [`accept::accept`] runs the synthesized scenario against the
//!   simulator and returns the vector only if the recorded winner reproduces.
//!
//! Convergence-selected incidents route to a later phase and are not synthesized
//! here.

pub mod accept;
pub mod classify;
pub mod export;
pub mod fork;
pub mod synth;

pub use accept::{AcceptError, accept};
pub use classify::{QuarantineReason, Verdict, classify};
pub use export::{AgentStateExport, ParseError, parse};
pub use fork::{ForkCommitKind, ForkRecoveryError, RecoveredFork, recover_fork};
pub use synth::synthesize;
