//! What `marmot-app` records into the collector besides observations (#2627): the storage-failure
//! kind its errors convert into, the backlog source an account worker samples, and the onboarding
//! pause interactive setup reports. Hosts never see them; `marmot-app` reaches them through the
//! crate root.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    DiagnosticsPermit, ONBOARDING_PAUSE_CONTEXTS, ONBOARDING_PAUSE_ISSUES,
    ONBOARDING_PAUSE_STATUSES, ProductAnalytics, ProductFamily, product_count_bucket,
};

/// One interactive onboarding step that stopped in a blocking status (mdk#3440). Every field is a
/// catalogue label, never an endpoint, identity or free text; a label outside the catalogue drops
/// the observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnboardingPause {
    /// The step, one of the `mdk_onboarding_summary` operations.
    pub step: &'static str,
    /// The blocking status.
    pub status: &'static str,
    /// The step's primary issue: its first step-level finding, else `source_issue`.
    pub issue: &'static str,
    /// The most common issue among the step's failing sources, `none` without one.
    pub source_issue: &'static str,
    /// The relay operation behind the primary finding.
    pub context: &'static str,
    /// Distinct sources with a failing finding; bucketed before it leaves the device.
    pub failing_sources: u64,
}

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
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Corruption => "corruption",
            Self::Capacity => "capacity",
        }
    }
}

/// Test hook for `marmot-app`'s outcome table (#2627): [`StorageFailureKind::as_str`].
#[cfg(any(test, feature = "test-support"))]
impl StorageFailureKind {
    pub const fn as_str_for_test(self) -> &'static str {
        self.as_str()
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

impl ProductAnalytics {
    /// Count one onboarding pause as a transition of `mdk_onboarding_summary`.
    pub(crate) fn onboarding_pause(&self, permit: &DiagnosticsPermit, pause: OnboardingPause) {
        let Some((_, outcome)) = ONBOARDING_PAUSE_STATUSES
            .iter()
            .find(|(status, _)| *status == pause.status)
        else {
            return;
        };
        if !ProductFamily::Onboarding.operations().contains(&pause.step)
            || !ONBOARDING_PAUSE_ISSUES.contains(&pause.issue)
            || !ONBOARDING_PAUSE_ISSUES.contains(&pause.source_issue)
            || !ONBOARDING_PAUSE_CONTEXTS.contains(&pause.context)
        {
            return;
        }
        let mut s = self.lock();
        if !permit.valid() || !Self::enabled(&s) {
            return;
        }
        self.advance(&mut s);
        self.accumulate(
            &mut s,
            ProductFamily::Onboarding.as_str(),
            BTreeMap::from([
                ("operation".into(), pause.step.into()),
                ("outcome".into(), (*outcome).into()),
                ("unit".into(), "transition".into()),
                ("status".into(), pause.status.into()),
                ("issue".into(), pause.issue.into()),
                ("source_issue".into(), pause.source_issue.into()),
                ("context".into(), pause.context.into()),
                (
                    "failing_sources".into(),
                    product_count_bucket(pause.failing_sources).into(),
                ),
            ]),
        );
    }
}
