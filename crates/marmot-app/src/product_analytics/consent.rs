//! The consent change guard and the receipt revisions `marmot-app` persists (#2627). Hosts never
//! see them; `marmot-app` reaches them through [`crate::wiring`].

use super::{ProductAnalytics, USAGE_DIAGNOSTICS_POLICY};

/// The revisions a usage-diagnostics receipt is granted under: the consent policy, the product
/// event registry and the export scope.
pub struct ReceiptRevisions {
    pub policy: String,
    pub registry: String,
    pub scope: String,
}

/// What a new receipt records: this collector's revisions, and when it was made.
pub struct ReceiptStamp {
    pub revisions: ReceiptRevisions,
    pub updated_at_ms: i64,
}

/// The consent lock, held across a consent change. Failing closed, reopening after a durable
/// write and stamping a new receipt are steps of a change, so only this guard offers them.
pub struct ConsentChange<'a> {
    collector: &'a ProductAnalytics,
    _consent: std::sync::MutexGuard<'a, ()>,
}

impl ConsentChange<'_> {
    /// Refuse permits until a durable write and its receipt reload succeed.
    pub fn fail_closed(&self) {
        self.collector.lock().persistence_failed = true;
    }
    /// The durable write and its receipt reload succeeded.
    pub fn persisted(&self) {
        self.collector.lock().persistence_failed = false;
    }
    /// This collector's revisions and the wall clock, read under one state lock.
    pub fn receipt_stamp(&self) -> ReceiptStamp {
        let s = self.collector.lock();
        ReceiptStamp {
            revisions: ReceiptRevisions {
                policy: USAGE_DIAGNOSTICS_POLICY.into(),
                registry: s.registry_revision.clone(),
                scope: s.scope.clone(),
            },
            updated_at_ms: self
                .collector
                .clock
                .wall_seconds()
                .saturating_mul(1000)
                .min(i64::MAX as u64) as i64,
        }
    }
}

impl ProductAnalytics {
    /// Take the consent lock for a consent change: restoring the saved receipt, or saving a new
    /// one. Hold it across the whole change. The state lock is taken inside it, as `configure`
    /// takes it: consent, then state.
    pub(crate) fn consent_change(&self) -> ConsentChange<'_> {
        ConsentChange {
            collector: self,
            _consent: self.consent_lock.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}
