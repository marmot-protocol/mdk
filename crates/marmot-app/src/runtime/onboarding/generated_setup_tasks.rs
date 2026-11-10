//! Generated setup's background tasks and the teardown fence over them.
//!
//! Each account has at most one task, bound to that account. A teardown
//! (removal or sign-out) fences the account before it touches it: the fence
//! cancels the attempt in flight and holds the task at its gate, and no
//! attempt starts while any fence is held. When the last fence drops, the task
//! checks again: a removed or signed-out account ends it, and an account a
//! cancelled or failed teardown left behind keeps being published
//! (whitenoise-ios#1302). A task scheduled while a fence is held starts at
//! its gate, so the same check covers it.
use super::*;

/// Where a task stands relative to its attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Between attempts: waiting at the gate, backing off or checking.
    Waiting,
    /// Running an attempt, which a fence cancels.
    Attempting,
    /// The task's future is gone, finished or aborted.
    Ended,
}

struct Registry {
    accepting: bool,
    /// Each account's task, kept until a later lookup sees it has ended.
    running: HashMap<String, Task>,
    /// Accounts a teardown is removing or signing out, with how many
    /// teardowns hold each.
    fenced: HashMap<String, usize>,
}

struct Task {
    handle: JoinHandle<()>,
    phase: watch::Receiver<Phase>,
}

impl Task {
    fn has_ended(&self) -> bool {
        *self.phase.borrow() == Phase::Ended
    }
}

impl Registry {
    fn prune_ended(&mut self) {
        self.running.retain(|_, task| !task.has_ended());
    }
}

/// The registry of generated setup tasks, shared by `SetupState`'s clones.
#[derive(Clone)]
pub(super) struct GeneratedSetupTasks {
    registry: Arc<StdMutex<Registry>>,
    /// Bumped whenever a fence is taken or released, so tasks re-read it.
    fences: Arc<watch::Sender<()>>,
}

/// Held by a teardown from before it touches the account until it returns:
/// no attempt for the account runs while any such fence is held.
pub(in crate::runtime) struct GeneratedSetupFence {
    tasks: GeneratedSetupTasks,
    account_id: String,
}

impl Drop for GeneratedSetupFence {
    fn drop(&mut self) {
        {
            let mut registry = self.tasks.lock();
            if let Some(holders) = registry.fenced.get_mut(&self.account_id) {
                *holders -= 1;
                if *holders == 0 {
                    registry.fenced.remove(&self.account_id);
                }
            }
        }
        self.tasks.fences.send_replace(());
    }
}

/// A task's handle on its own account's gate. It is owned by the task's
/// future and dropped with it, finished or aborted, which marks the task
/// ended. Dropping takes no lock: a runtime shutting down may drop the future
/// inline in `tokio::spawn`, under the registry lock.
pub(super) struct GeneratedSetupGate {
    tasks: GeneratedSetupTasks,
    account_id: String,
    phase: watch::Sender<Phase>,
}

impl Drop for GeneratedSetupGate {
    fn drop(&mut self) {
        self.phase.send_replace(Phase::Ended);
    }
}

impl GeneratedSetupGate {
    /// Wait until no teardown fences the account.
    pub(super) async fn wait_unfenced(&self) {
        let mut fences = self.tasks.fences.subscribe();
        while self.tasks.is_fenced(&self.account_id) {
            if fences.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }

    /// End the task if `gone` says its account no longer needs it. The
    /// check and the end are one step under the registry lock, so a task
    /// scheduled again right after (a sign-in following a sign-out) is never
    /// refused for a task that is about to end.
    pub(super) fn end_if(&self, gone: impl FnOnce() -> bool) -> bool {
        let _registry = self.tasks.lock();
        let gone = gone();
        if gone {
            self.phase.send_replace(Phase::Ended);
        }
        gone
    }

    /// Run one attempt unless a teardown fences the account. An attempt can
    /// start only while the account is unfenced, checked under the registry
    /// lock a fence takes, and a fence taken while it runs cancels it.
    /// Returns `None` when a fence kept or cancelled the attempt.
    pub(super) async fn attempt<F: Future>(&self, attempt: F) -> Option<F::Output> {
        let mut fences = self.tasks.fences.subscribe();
        {
            let registry = self.tasks.lock();
            if registry.fenced.contains_key(&self.account_id) {
                return None;
            }
            self.phase.send_replace(Phase::Attempting);
        }
        let fenced = async {
            loop {
                if fences.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
                if self.tasks.is_fenced(&self.account_id) {
                    return;
                }
            }
        };
        let outcome = tokio::select! {
            outcome = attempt => Some(outcome),
            () = fenced => None,
        };
        // The attempt's future is dropped by now, finished or cancelled.
        self.phase.send_replace(Phase::Waiting);
        outcome
    }
}

impl GeneratedSetupTasks {
    pub(super) fn new() -> Self {
        Self {
            registry: Arc::new(StdMutex::new(Registry {
                accepting: true,
                running: HashMap::new(),
                fenced: HashMap::new(),
            })),
            fences: Arc::new(watch::channel(()).0),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_fenced(&self, account_id: &str) -> bool {
        self.lock().fenced.contains_key(account_id)
    }

    /// Fence `account_id` for a teardown. Once this returns no attempt for
    /// the account is in flight, and none starts until every fence is
    /// dropped.
    ///
    /// Cancel-safe: the fence exists from the first poll, so a cancelled
    /// teardown releases it, and the task then carries on. Concurrent
    /// teardowns all wait for the same attempt to stop.
    pub(super) async fn fence(&self, account_id: &str) -> GeneratedSetupFence {
        let (fence, task) = {
            let mut registry = self.lock();
            *registry.fenced.entry(account_id.to_owned()).or_default() += 1;
            registry.prune_ended();
            let fence = GeneratedSetupFence {
                tasks: self.clone(),
                account_id: account_id.to_owned(),
            };
            let task = registry
                .running
                .get(account_id)
                .map(|task| (task.handle.id(), task.phase.clone()));
            (fence, task)
        };
        self.fences.send_replace(());
        // A teardown reached from inside the task's own attempt must not
        // wait for that attempt to stop.
        if let Some((id, mut phase)) = task
            && tokio::task::try_id() != Some(id)
        {
            let _ = phase.wait_for(|phase| *phase != Phase::Attempting).await;
        }
        fence
    }

    /// Start `account_id`'s task from `task`, unless one is running or setup
    /// has shut down. The task gets the account's gate and must run every
    /// attempt through it; under a fence it waits there, so a teardown that
    /// is cancelled or fails still leaves the account published.
    pub(super) fn spawn<T, F>(&self, account_id: &str, task: T) -> bool
    where
        T: FnOnce(GeneratedSetupGate) -> F,
        F: Future<Output = ()> + Send + 'static,
    {
        let mut registry = self.lock();
        registry.prune_ended();
        if !registry.accepting || registry.running.contains_key(account_id) {
            return false;
        }
        let (sender, phase) = watch::channel(Phase::Waiting);
        let task = task(GeneratedSetupGate {
            tasks: self.clone(),
            account_id: account_id.to_owned(),
            phase: sender,
        });
        let handle = tokio::spawn(task);
        registry
            .running
            .insert(account_id.to_owned(), Task { handle, phase });
        true
    }

    /// Shutdown: stop accepting tasks, then abort and join every one.
    pub(super) async fn shutdown(&self) {
        let running = {
            let mut registry = self.lock();
            registry.accepting = false;
            std::mem::take(&mut registry.running)
        };
        for task in running.into_values() {
            task.handle.abort();
            let _ = task.handle.await;
        }
    }

    /// Whether a teardown holds `account_id`'s fence.
    #[cfg(test)]
    pub(super) fn fenced_for_test(&self, account_id: &str) -> bool {
        self.is_fenced(account_id)
    }

    /// Wait for every task to end on its own.
    #[cfg(test)]
    pub(super) async fn join_for_test(&self) {
        let running = std::mem::take(&mut self.lock().running);
        for task in running.into_values() {
            let _ = task.handle.await;
        }
    }
}
