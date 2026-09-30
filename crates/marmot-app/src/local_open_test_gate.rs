//! Deterministic per-app gates for local account opens in unit tests.
//!
//! A gate is one-shot: the first blocking open for its account label to reach
//! the gate's startup stage signals, then waits there until the test releases
//! it. Production builds never compile or link this module.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::runtime::account_worker::AccountStartupStage;

#[derive(Clone, Default)]
pub(crate) struct LocalOpenGates {
    gates: Arc<Mutex<HashMap<(String, AccountStartupStage), LocalOpenGate>>>,
}

struct LocalOpenGate {
    reached: std::sync::mpsc::Sender<()>,
    proceed: std::sync::mpsc::Receiver<()>,
}

impl LocalOpenGates {
    pub(crate) fn install(
        &self,
        label: String,
        stage: AccountStartupStage,
        reached: std::sync::mpsc::Sender<()>,
        proceed: std::sync::mpsc::Receiver<()>,
    ) {
        self.gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert((label, stage), LocalOpenGate { reached, proceed });
    }

    pub(crate) fn wait(&self, label: &str, stage: AccountStartupStage) {
        let gate = self
            .gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(label.to_owned(), stage));
        let Some(gate) = gate else {
            return;
        };
        let _ = gate.reached.send(());
        let _ = gate.proceed.recv();
    }
}
