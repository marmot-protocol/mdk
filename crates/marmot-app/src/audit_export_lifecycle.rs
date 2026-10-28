//! Process-local admission for explicit audit export attempts.
//!
//! Local prepare/finish holds `storage_lifecycle` and the account's local-work
//! gate. The in-flight reservation is just an identity: HTTP owns no guard.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct AuditExportLifecycle(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    next_id: u64,
    global_blocks: usize,
    directory_blocks: HashMap<PathBuf, usize>,
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
    directory: PathBuf,
    source: Option<(u64, u64)>,
}

pub(crate) struct AuditExportAttempt {
    lifecycle: AuditExportLifecycle,
    account: String,
    id: u64,
    destination: String,
}

pub(crate) struct AuditDirectoryMutation {
    lifecycle: AuditExportLifecycle,
    directory: PathBuf,
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

    pub(crate) fn reserve(
        &self,
        account: &str,
        destination: &str,
        directory: &Path,
    ) -> Option<AuditExportAttempt> {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if state.global_blocks > 0
            || state.directory_blocks.get(directory).copied().unwrap_or(0) > 0
        {
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
            directory: directory.to_owned(),
            source: None,
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

    /// Called inside admitted preparation, while its local-work gate is held.
    pub(crate) fn prepared_source(&self, attempt: &AuditExportAttempt, source: (u64, u64)) {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(active) = state
            .accounts
            .get_mut(&attempt.account)
            .and_then(|entry| entry.active.as_mut())
            && active.id == attempt.id
        {
            active.source = Some(source);
        }
    }

    /// Serialize cursor retirement with every prepare/finish for this directory,
    /// while invalidating only the attempt that actually owns the expiring inode.
    /// Unrelated HTTP completions wait for the gate and remain valid.
    pub(crate) fn mutate_source<T>(
        &self,
        directory: &Path,
        source: (u64, u64),
        mutation: impl FnOnce() -> T,
    ) -> T {
        let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
        *state
            .directory_blocks
            .entry(directory.to_owned())
            .or_default() += 1;
        let mut local_work: Vec<_> = state
            .accounts
            .iter()
            .filter_map(|(account, entry)| {
                entry
                    .active
                    .as_ref()
                    .filter(|active| active.directory == directory)
                    .map(|_| (account.clone(), entry.local_work.clone()))
            })
            .collect();
        local_work.sort_by(|left, right| left.0.cmp(&right.0));
        drop(state);
        let block = AuditDirectoryMutation {
            lifecycle: self.clone(),
            directory: directory.to_owned(),
        };
        let gates: Vec<_> = local_work
            .iter()
            .map(|(_, gate)| gate.lock().unwrap_or_else(|p| p.into_inner()))
            .collect();
        {
            let mut state = self.0.lock().unwrap_or_else(|p| p.into_inner());
            for entry in state.accounts.values_mut() {
                if let Some(active) = &mut entry.active
                    && active.directory == directory
                    && active.source == Some(source)
                {
                    active.valid = false;
                }
            }
        }
        let result = mutation();
        drop(gates);
        drop(block);
        result
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
                            && (active.source.is_some()
                                || self
                                    .directory_blocks
                                    .get(&active.directory)
                                    .copied()
                                    .unwrap_or(0)
                                    == 0)
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

impl Drop for AuditDirectoryMutation {
    fn drop(&mut self) {
        let mut state = self.lifecycle.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(blocks) = state.directory_blocks.get_mut(&self.directory) {
            *blocks -= 1;
            if *blocks == 0 {
                state.directory_blocks.remove(&self.directory);
            }
        }
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    #[test]
    fn source_mutation_blocks_new_reservations_without_blocking_other_directories() {
        let lifecycle = AuditExportLifecycle::default();
        let dir = Path::new("account-a");
        let other = Path::new("account-b");
        lifecycle.mutate_source(dir, (1, 1), || {
            assert!(lifecycle.reserve("a", "receiver", dir).is_none());
            assert!(lifecycle.reserve("b", "receiver", other).is_some());
        });
        assert!(lifecycle.reserve("a", "receiver", dir).is_some());
    }

    #[test]
    fn source_mutation_waits_for_local_work_but_preserves_an_unrelated_completion() {
        let lifecycle = AuditExportLifecycle::default();
        let dir = PathBuf::from("account-a");
        let attempt = Arc::new(lifecycle.reserve("a", "receiver", &dir).unwrap());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let preparing = {
            let lifecycle = lifecycle.clone();
            let attempt = attempt.clone();
            std::thread::spawn(move || {
                lifecycle.admit(&attempt, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    lifecycle.prepared_source(&attempt, (7, 9));
                })
            })
        };
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let mutating = {
            let lifecycle = lifecycle.clone();
            std::thread::spawn(move || {
                lifecycle.mutate_source(&dir, (7, 10), || finished_tx.send(()).unwrap())
            })
        };
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(30))
                .is_err()
        );
        release_tx.send(()).unwrap();
        preparing.join().unwrap();
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        mutating.join().unwrap();
        assert!(lifecycle.admit(&attempt, || ()).is_some());
    }
}
