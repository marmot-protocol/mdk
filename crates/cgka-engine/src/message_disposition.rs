//! One classification table for why a raw inbound message was not applied
//! (mdk#339 / #707): both processing seams and the deferred-peel
//! lifecycle name their dispositions from this enum instead of scattering
//! ad-hoc reason strings, so forensic audit rows (`MessageStateChanged.reason`
//! / `Rejection.reason`) stay a closed, greppable vocabulary.

/// Why a raw inbound message was skipped, deferred, or terminally failed
/// before it could be applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageDisposition {
    /// The message's MLS epoch precedes this device's membership
    /// (`Group::join_epoch`). Permanently undecryptable by design — terminal,
    /// never retried.
    PreMembershipEvent,
    /// The device was a member at the application message's source epoch, but
    /// that epoch is now outside the retained app-payload decryption window.
    /// Terminal under the active convergence policy.
    AppPayloadRetentionExpired,
    /// The transport bytes failed to peel against the current epoch context
    /// and every retained snapshot. Retained as `PeelDeferred`; retried only
    /// when the (epoch, snapshot-set) peel context actually changes.
    RetryPending,
    /// A retained `PeelDeferred` row exhausted its changed-context retry
    /// budget without peeling. The row is released as a local resource
    /// refusal; the same transport id remains eligible on later redelivery.
    RetryBudgetRefused,
    /// A retained `PeelDeferred` row exhausted its durable local residence
    /// budget. Like retry-budget refusal, this is not a validity claim and
    /// exact-id redelivery remains eligible.
    ResidenceBudgetRefused,
    /// The per-group cap on retained `PeelDeferred` rows is reached; the
    /// message was dropped without being persisted so a flood of
    /// undecryptable input cannot grow the durable store unboundedly.
    DeferredCapacityRefused,
    /// The group is under hydration quarantine; input is retained for
    /// post-repair replay (see `LocalIngestState::Quarantined`).
    Quarantined,
}

impl MessageDisposition {
    /// Stable snake_case tag recorded in forensic audit rows.
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::PreMembershipEvent => "pre_membership_event",
            Self::AppPayloadRetentionExpired => "app_payload_retention_expired",
            // Historical audit string, kept for dashboard continuity.
            Self::RetryPending => "peel_failed_no_snapshot",
            Self::RetryBudgetRefused => "resource_refused_retry_budget",
            Self::ResidenceBudgetRefused => "resource_refused_residence_budget",
            Self::DeferredCapacityRefused => "resource_refused_deferred_capacity",
            Self::Quarantined => "quarantined_group_input_deferred",
        }
    }
}
