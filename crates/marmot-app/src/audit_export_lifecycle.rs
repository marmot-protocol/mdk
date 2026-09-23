//! Process-local admission for explicit audit export attempts.
//!
//! Local prepare/finish holds `storage_lifecycle` and the account's local-work
//! gate. The in-flight reservation is just an identity: HTTP owns no guard.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct AuditExportLifecycle(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    next_id: u64,
    global_blocks: usize,
    accounts: HashMap<String, AccountState>,
    #[cfg(test)]
    delete_queued_signal: Option<tokio::sync::oneshot::Sender<()>>,
}

#[derive(Default)]
struct AccountState {
    active: Option<Active>,
    blocks: usize,
    local_work: Arc<Mutex<()>>,
}

struct Active {
    id: u64,
    valid: bool,
    destination: String,
}

pub(crate) struct AuditExportAttempt {
    lifecycle: AuditExportLifecycle,
    account: String,
    id: u64,
    destination: String,
}

pub(crate) struct AuditExportMutation {
    lifecycle: AuditExportLifecycle,
    account: Option<String>,
}

impl AuditExportLifecycle {
    #[cfg(test)]
    pub(crate) fn signal_next_delete_queued_for_test(
        &self,
        signal: tokio::sync::oneshot::Sender<()>,
    ) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .delete_queued_signal = Some(signal);
    }

    #[cfg(test)]
    pub(crate) fn notify_delete_queued_for_test(&self) {
        if let Some(signal) = self
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .delete_queued_signal
            .take()
        {
            let _ = signal.send(());
        }
    }

    pub(crate) fn reserve(&self, account: &str, destination: &str) -> Option<AuditExportAttempt> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.global_blocks > 0 {
            return None;
        }
        if let Some(entry) = state.accounts.get_mut(account) {
            if let Some(active) = &mut entry.active {
                if active.destination != destination {
                    // A profile change is an explicit cancellation of its old
                    // HTTP result. The durable cursor still belongs to its
                    // original destination and cannot be silently retargeted.
                    active.valid = false;
                }
                return None;
            }
            if entry.blocks > 0 {
                return None;
            }
        }
        state.next_id = state.next_id.checked_add(1)?;
        let id = state.next_id;
        state.accounts.entry(account.to_owned()).or_default().active = Some(Active {
            id,
            valid: true,
            destination: destination.to_owned(),
        });
        Some(AuditExportAttempt {
            lifecycle: self.clone(),
            account: account.to_owned(),
            id,
            destination: destination.to_owned(),
        })
    }

    pub(crate) fn admit<T>(
        &self,
        attempt: &AuditExportAttempt,
        work: impl FnOnce() -> T,
    ) -> Option<T> {
        let local_work = {
            let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let account = state.accounts.get(&attempt.account)?;
            if !state.allows(attempt) {
                return None;
            }
            account.local_work.clone()
        };
        let _local_work = local_work.lock().unwrap_or_else(|p| p.into_inner());
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if !state.allows(attempt) {
            return None;
        }
        drop(state);
        // Hold only this account's local-work gate across file and database
        // I/O. Global state is never locked while the closure runs.
        Some(work())
    }

    pub(crate) fn mutate_all(&self) -> AuditExportMutation {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.global_blocks += 1;
        let local_work = state
            .accounts
            .values_mut()
            .map(|account| {
                if let Some(active) = &mut account.active {
                    active.valid = false;
                }
                account.local_work.clone()
            })
            .collect::<Vec<_>>();
        drop(state);
        // No admitted prepare/finish can still be mutating a cursor when the
        // caller proceeds to change global recording consent.
        for gate in local_work {
            drop(gate.lock().unwrap_or_else(|p| p.into_inner()));
        }
        AuditExportMutation {
            lifecycle: self.clone(),
            account: None,
        }
    }

    pub(crate) fn mutate_account(&self, account: &str) -> AuditExportMutation {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let entry = state.accounts.entry(account.to_owned()).or_default();
        entry.blocks += 1;
        if let Some(active) = &mut entry.active {
            active.valid = false;
        }
        let local_work = entry.local_work.clone();
        drop(state);
        // The blocker is already visible to new admissions. Drain only this
        // account's admitted local work before destructive mutation begins.
        drop(local_work.lock().unwrap_or_else(|p| p.into_inner()));
        AuditExportMutation {
            lifecycle: self.clone(),
            account: Some(account.to_owned()),
        }
    }
}

impl State {
    fn allows(&self, attempt: &AuditExportAttempt) -> bool {
        self.global_blocks == 0
            && self.accounts.get(&attempt.account).is_some_and(|account| {
                account.blocks == 0
                    && account.active.as_ref().is_some_and(|active| {
                        active.id == attempt.id
                            && active.valid
                            && active.destination == attempt.destination
                    })
            })
    }
}

impl AuditExportAttempt {
    pub(crate) fn destination(&self) -> &str {
        &self.destination
    }
}

impl Drop for AuditExportAttempt {
    fn drop(&mut self) {
        let mut state = self.lifecycle.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state.accounts.get_mut(&self.account) {
            if entry
                .active
                .as_ref()
                .is_some_and(|active| active.id == self.id)
            {
                entry.active = None;
            }
            if entry.active.is_none() && entry.blocks == 0 {
                state.accounts.remove(&self.account);
            }
        }
    }
}

impl Drop for AuditExportMutation {
    fn drop(&mut self) {
        let mut state = self.lifecycle.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(account) = &self.account {
            if let Some(entry) = state.accounts.get_mut(account) {
                entry.blocks -= 1;
                if entry.active.is_none() && entry.blocks == 0 {
                    state.accounts.remove(account);
                }
            }
        } else {
            state.global_blocks -= 1;
        }
    }
}
