//! In-memory forensic capture for the harness.
//!
//! The engine discards forensic audit events under its default
//! [`marmot_forensics::NoopRecorder`], so decisions it makes but never surfaces
//! as a [`cgka_traits::engine::GroupEvent`] — notably `convergence_decision` —
//! are invisible to a scenario. [`CapturingRecorder`] retains those decisions in
//! memory so the harness can assert on them.
//!
//! It captures **only** `convergence_decision` events: that is the sole consumer
//! today, and a general recorder would accumulate every audit event a
//! chaos-family run emits for no benefit. Widen the filter when a second
//! consumer appears.

use std::sync::{Arc, Mutex, PoisonError};

use marmot_forensics::{AuditEventKind, AuditRecord, ForensicRecorder};

/// Shared, append-only buffer of captured `convergence_decision` events.
///
/// Cloning shares the same buffer, so a client and every engine it builds —
/// including the fresh engine a [`crate::HarnessClient::restart`] constructs —
/// record into one place, and captures survive a restart.
pub(crate) type AuditCapture = Arc<Mutex<Vec<AuditEventKind>>>;

/// A [`ForensicRecorder`] that retains `convergence_decision` events in a shared
/// in-memory buffer and drops everything else.
#[derive(Clone)]
pub(crate) struct CapturingRecorder {
    decisions: AuditCapture,
}

impl CapturingRecorder {
    pub(crate) fn new(decisions: AuditCapture) -> Self {
        Self { decisions }
    }
}

impl ForensicRecorder for CapturingRecorder {
    fn record(&self, record: AuditRecord) {
        if !matches!(record.kind, AuditEventKind::ConvergenceDecision { .. }) {
            return;
        }
        // The recorder sits on the engine's audit hot path and must never panic
        // there. A poisoned lock means a prior panic already doomed the
        // scenario; recover the buffer rather than masking that panic with a
        // second one here.
        self.decisions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record.kind);
    }
}

/// Remove and return the captured `convergence_decision` events, oldest-first.
pub(crate) fn drain_convergence_decisions(capture: &AuditCapture) -> Vec<AuditEventKind> {
    std::mem::take(&mut *capture.lock().unwrap_or_else(PoisonError::into_inner))
}

/// Discard all captured events, resetting the observation window. Used by the
/// `ClearEvents` scenario step so a vector can isolate a decision that happens
/// after setup, the way a hand-written test drains between phases.
pub(crate) fn clear(capture: &AuditCapture) {
    capture
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
}
