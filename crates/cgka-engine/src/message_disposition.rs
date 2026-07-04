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
    /// The device was (or may have been) a member at the message's epoch, but
    /// no retained snapshot or past-epoch secret can decrypt it anymore.
    /// Terminal for this device; content-level redelivery is the recovery
    /// path.
    ValidHistorySnapshotMissing,
    /// The transport bytes failed to peel against the current epoch context
    /// and every retained snapshot. Retained as `PeelDeferred`; retried only
    /// when the (epoch, snapshot-set) peel context actually changes.
    RetryPending,
    /// A retained `PeelDeferred` row exhausted its retry budget without ever
    /// peeling. Terminal: indistinguishable from garbage; a legitimate
    /// message re-delivered under a fresh transport id starts over.
    PermanentlyUndecryptable,
    /// The per-group cap on retained `PeelDeferred` rows is reached; the
    /// message was dropped without being persisted so a flood of
    /// undecryptable input cannot grow the durable store unboundedly.
    DeferredCapExceeded,
    /// The group is under hydration quarantine; input is retained for
    /// post-repair replay (see `StaleReason::Quarantined`).
    Quarantined,
}

impl MessageDisposition {
    /// Stable snake_case tag recorded in forensic audit rows.
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::PreMembershipEvent => "pre_membership_event",
            Self::ValidHistorySnapshotMissing => "valid_history_snapshot_missing",
            // Historical audit string, kept for dashboard continuity.
            Self::RetryPending => "peel_failed_no_snapshot",
            Self::PermanentlyUndecryptable => "permanently_undecryptable",
            Self::DeferredCapExceeded => "peel_deferred_cap_exceeded",
            Self::Quarantined => "quarantined_group_input_deferred",
        }
    }
}
