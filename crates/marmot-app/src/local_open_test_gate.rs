//! Deterministic per-app gates for local account opens in unit tests.
//!
//! A gate is one-shot: the first blocking open for its account label signals
//! that its result is ready, then waits until the test releases it. Production
//! builds never compile or link this module.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct LocalOpenGates {
    gates: Arc<Mutex<HashMap<String, LocalOpenGate>>>,
}

struct LocalOpenGate {
    reached: std::sync::mpsc::Sender<()>,
    proceed: std::sync::mpsc::Receiver<()>,
}

impl LocalOpenGates {
    pub(crate) fn install(
        &self,
        label: String,
        reached: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
    ) {
        self.gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(label, LocalOpenGate { reached, proceed });
    }

    pub(crate) fn wait(&self, label: &str) {
        let gate = self
            .gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(label);
        let Some(gate) = gate else {
            return;
        };
        let _ = gate.reached.send(());
        let _ = gate.proceed.recv();
    }
}
