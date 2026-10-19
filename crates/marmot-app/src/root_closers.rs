//! The one list [`MarmotApp::close_storage`][crate::MarmotApp::close_storage]
//! closes: a closer for every resource that can hold a file lock inside the
//! Marmot root.
//!
//! The app's handle caches are not that list. Each account engine opens its
//! own connection to `session.sqlite`, which no cache holds, and a cache only
//! reaches what it happens to store (mdk#2323). Anything that opens a
//! lock-holding resource in the root registers it here instead.

use std::sync::{Arc, Mutex, RwLockReadGuard};

use crate::AppError;

/// Closes one registered resource.
///
/// Implementations must not keep the resource alive. An owner that drops its
/// last handle must still release the resource's locks then, not when the app
/// closes storage.
pub(crate) trait RootCloser: Send {
    /// Close the resource if any handle to it is still alive. Terminal and
    /// idempotent. Returns only once the resource is gone, including when its
    /// last handle is being dropped on another thread.
    fn close(&self) -> Result<(), AppError>;

    /// Start closing without waiting: refuse new work, which also stops a
    /// long operation that polls for it (a database compaction), so nothing
    /// blocked behind it holds up the rest of the teardown. [`Self::close`]
    /// still follows.
    fn begin_close(&self) {}

    /// Whether the resource is gone, closed or dropped with its last handle,
    /// so there is nothing left to close.
    fn is_released(&self) -> bool;
}

impl RootCloser for storage_sqlite::DatabaseCloser {
    fn close(&self) -> Result<(), AppError> {
        Ok(storage_sqlite::DatabaseCloser::close(self)?)
    }

    fn begin_close(&self) {
        storage_sqlite::DatabaseCloser::begin_close(self);
    }

    fn is_released(&self) -> bool {
        storage_sqlite::DatabaseCloser::is_released(self)
    }
}

/// Shared by every clone of one [`MarmotApp`][crate::MarmotApp].
#[derive(Clone, Default)]
pub(crate) struct RootClosers {
    closers: Arc<Mutex<Vec<Box<dyn RootCloser>>>>,
}

impl RootClosers {
    /// Register a resource opened while `admission` was held.
    ///
    /// `admission` is the read side of the app's storage lifecycle (see
    /// `MarmotApp::begin_storage_open`). Holding it from the open through this
    /// call is what makes the close complete: `close_storage` takes the write
    /// side, so an open has either registered by the time the close drains this
    /// list, or it has not yet passed the closed check and will refuse.
    pub(crate) fn register(
        &self,
        _admission: &RwLockReadGuard<'_, ()>,
        closer: impl RootCloser + 'static,
    ) {
        let mut closers = self
            .closers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Owners such as account workers come and go; forget their resources
        // once every handle is gone so the list stays bounded.
        closers.retain(|closer| !closer.is_released());
        closers.push(Box::new(closer));
    }

    /// [`RootCloser::begin_close`] on every registered resource, without
    /// waiting on any of them.
    pub(crate) fn begin_close_all(&self) {
        for closer in self
            .closers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
        {
            closer.begin_close();
        }
    }

    /// Close every registered resource that is still alive and empty the
    /// list. Every resource is attempted even if an earlier one fails. Returns
    /// how many were closed and the first error.
    pub(crate) fn close_all(&self) -> (usize, Option<AppError>) {
        let closers = std::mem::take(
            &mut *self
                .closers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut closed = 0;
        let mut first_error = None;
        for closer in closers {
            if closer.is_released() {
                continue;
            }
            closed += 1;
            if let Err(error) = closer.close() {
                first_error.get_or_insert(error);
            }
        }
        (closed, first_error)
    }
}
