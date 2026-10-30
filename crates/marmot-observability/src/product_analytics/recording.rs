//! What `marmot-app` records into the collector besides observations (#2627): the storage-failure
//! kind its errors convert into, and the backlog source an account worker samples. Hosts never see
//! them; `marmot-app` reaches them through [`crate::observer`].

use std::sync::atomic::{AtomicU64, Ordering};

use super::{DiagnosticsPermit, ProductAnalytics, ProductFamily};

/// A storage failure the collector counts, by the class of the error behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageFailureKind {
    Busy,
    Corruption,
    Capacity,
}
impl StorageFailureKind {
    /// The counted kind of a sync error class; other classes are not storage failures.
    pub const fn from_sync_class(class: crate::SyncErrorClass) -> Option<Self> {
        match class {
            crate::SyncErrorClass::StorageBusy => Some(Self::Busy),
            crate::SyncErrorClass::StorageCorruption => Some(Self::Corruption),
            crate::SyncErrorClass::StorageCapacity => Some(Self::Capacity),
            _ => None,
        }
    }
    /// The storage operation it is counted under.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Corruption => "corruption",
            Self::Capacity => "capacity",
        }
    }
}

pub struct ProductBacklogSource {
    id: u64,
    collector: ProductAnalytics,
}
impl ProductBacklogSource {
    pub fn sample(
        &self,
        permit: &DiagnosticsPermit,
        family: ProductFamily,
        operation: &str,
        count: u64,
    ) {
        self.collector
            .backlog(permit, self.id, family, operation, count);
    }
}
impl Drop for ProductBacklogSource {
    fn drop(&mut self) {
        let mut state = self.collector.lock();
        for values in state.backlog.values_mut() {
            values.remove(&self.id);
        }
        state.backlog.retain(|_, values| !values.is_empty());
    }
}
impl ProductAnalytics {
    pub(crate) fn backlog_source(&self) -> ProductBacklogSource {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        ProductBacklogSource {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            collector: self.clone(),
        }
    }
}
