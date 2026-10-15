//! Terminal close for runtime-owned handles that do not live in the storage
//! caches.
//!
//! A handle registers a closer, keyed so a replacement or an account removal
//! can close it individually. `MarmotApp::close_storage` runs every closer
//! inside its terminal-close critical section. Closers are plain closures, so
//! the crates that own the handles (`media-store` today; the engine's own
//! connection for mdk#2323) need no shared trait or new dependency.

use std::collections::HashMap;
use std::sync::Mutex;

type Closer = Box<dyn FnOnce() + Send>;

#[derive(Default)]
pub(crate) struct CloseRegistry {
    closers: Mutex<HashMap<String, Closer>>,
}

impl CloseRegistry {
    fn closers(&self) -> std::sync::MutexGuard<'_, HashMap<String, Closer>> {
        self.closers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Registers `closer` under `key`. A handle already registered under the
    /// key is closed first: a replaced handle must not outlive its successor.
    pub(crate) fn register(&self, key: impl Into<String>, closer: impl FnOnce() + Send + 'static) {
        let previous = self.closers().insert(key.into(), Box::new(closer));
        if let Some(previous) = previous {
            previous();
        }
    }

    /// Closes and forgets one handle, for example on account removal.
    pub(crate) fn close(&self, key: &str) {
        let closer = self.closers().remove(key);
        if let Some(closer) = closer {
            closer();
        }
    }

    /// Closes every registered handle. Closers run outside the lock.
    pub(crate) fn close_all(&self) -> usize {
        let closers = self
            .closers()
            .drain()
            .map(|(_, closer)| closer)
            .collect::<Vec<_>>();
        let count = closers.len();
        for closer in closers {
            closer();
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn closers_run_once_on_replacement_removal_or_close_all() {
        let registry = CloseRegistry::default();
        let closed = Arc::new(AtomicUsize::new(0));
        let counter = |closed: &Arc<AtomicUsize>| {
            let closed = closed.clone();
            move || {
                closed.fetch_add(1, Ordering::SeqCst);
            }
        };
        registry.register("a", counter(&closed));
        registry.register("a", counter(&closed)); // replaces: closes the first
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        registry.register("b", counter(&closed));
        registry.close("b");
        assert_eq!(closed.load(Ordering::SeqCst), 2);
        registry.close("b");
        assert_eq!(registry.close_all(), 1);
        assert_eq!(closed.load(Ordering::SeqCst), 3);
        assert_eq!(registry.close_all(), 0);
    }
}
