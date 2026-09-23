//! Process-local admission for explicit audit export attempts.
//!
//! Only local prepare/finish work holds `storage_lifecycle` and this mutex.
//! The in-flight reservation is just an identity: HTTP owns no local guard.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct AuditExportLifecycle(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    next_id: u64,
    global_blocks: usize,
    accounts: HashMap<String, AccountState>,
}

#[derive(Default)]
struct AccountState {
    active: Option<Active>,
    blocks: usize,
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
        let state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let active = state.accounts.get(&attempt.account)?.active.as_ref()?;
        if state.global_blocks > 0
            || active.id != attempt.id
            || !active.valid
            || active.destination != attempt.destination
        {
            return None;
        }
        // Serialize local work with consent and deletion mutations. This is
        // never called around a network request.
        Some(work())
    }

    pub(crate) fn invalidate_all(&self) {
        self.invalidate_all_with(|| ());
    }

    pub(crate) fn invalidate_all_with<T>(&self, action: impl FnOnce() -> T) -> T {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        for account in state.accounts.values_mut() {
            if let Some(active) = &mut account.active {
                active.valid = false;
            }
        }
        action()
    }

    pub(crate) fn mutate_all(&self) -> AuditExportMutation {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        state.global_blocks += 1;
        for account in state.accounts.values_mut() {
            if let Some(active) = &mut account.active {
                active.valid = false;
            }
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
        AuditExportMutation {
            lifecycle: self.clone(),
            account: Some(account.to_owned()),
        }
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
