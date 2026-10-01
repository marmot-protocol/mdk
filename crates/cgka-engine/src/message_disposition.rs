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
    /// Two readings, one meaning: the message belongs to the group's history
    /// from before this local copy was installed. As a verdict, an application
    /// message that opened but whose source epoch lies below
    /// `Group::local_copy_install_epoch`, refused by OpenMLS as too distant in
    /// the past; terminal like `AppPayloadRetentionExpired`. As a release
    /// reason, a `PeelDeferred` row whose envelope predates the Welcome
    /// (`Group::local_copy_welcome_created_at`) and left on its own residence
    /// or retry budget; that release raises no resource-refusal, because such
    /// traffic is expected after a join and is not evidence of a stall. Time
    /// never decides a terminal state here.
    PredatesLocalCopy,
    /// The transport bytes failed to peel against the current epoch context
    /// and every retained snapshot. Retained as `PeelDeferred`; retried only
    /// when the full peel context changes: live epoch, retained snapshot set,
    /// or stored commit graph.
    RetryPending,
    /// A retained `PeelDeferred` row exhausted its live-context retry
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
            Self::PredatesLocalCopy => "predates_local_copy",
            // Historical audit string, kept for dashboard continuity.
            Self::RetryPending => "peel_failed_no_snapshot",
            Self::RetryBudgetRefused => "resource_refused_retry_budget",
            Self::ResidenceBudgetRefused => "resource_refused_residence_budget",
            Self::DeferredCapacityRefused => "resource_refused_deferred_capacity",
            Self::Quarantined => "quarantined_group_input_deferred",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MessageDisposition;
    use cgka_traits::message::MessageState;
    use marmot_forensics::v5::{self, BuildProfile, Platform, Producer};
    use marmot_forensics::{AuditEventKind, AuditRecord, ForensicRecorder, JsonlRecorder};

    const ALL: [MessageDisposition; 8] = [
        MessageDisposition::PreMembershipEvent,
        MessageDisposition::AppPayloadRetentionExpired,
        MessageDisposition::PredatesLocalCopy,
        MessageDisposition::RetryPending,
        MessageDisposition::RetryBudgetRefused,
        MessageDisposition::ResidenceBudgetRefused,
        MessageDisposition::DeferredCapacityRefused,
        MessageDisposition::Quarantined,
    ];

    /// A new variant fails to compile here until it is added to `ALL`, so the
    /// v5 parity test below cannot silently skip it.
    #[allow(dead_code)]
    fn all_is_exhaustive(disposition: MessageDisposition) {
        match disposition {
            MessageDisposition::PreMembershipEvent
            | MessageDisposition::AppPayloadRetentionExpired
            | MessageDisposition::PredatesLocalCopy
            | MessageDisposition::RetryPending
            | MessageDisposition::RetryBudgetRefused
            | MessageDisposition::ResidenceBudgetRefused
            | MessageDisposition::DeferredCapacityRefused
            | MessageDisposition::Quarantined => {}
        }
    }

    /// Every tag is a closed category the v5 audit boundary keeps verbatim,
    /// on both fields that carry it, instead of redacting it to
    /// `unclassified` (mdk#2120).
    #[test]
    fn every_disposition_tag_survives_v5_recording() {
        let dir = tempfile::tempdir().unwrap();
        let engine_id = "11".repeat(16);
        let path = marmot_forensics::default_v5_jsonl_path(dir.path(), &engine_id);
        let recorder = JsonlRecorder::open_v5_with_account_ref(
            &path,
            engine_id,
            None,
            Producer {
                mdk_revision: None,
                build_profile: BuildProfile::Debug,
                platform: Platform::Other,
                host_build: None,
            },
        )
        .unwrap();
        let msg_id = "ab".repeat(32);
        for disposition in ALL {
            recorder.record(AuditRecord::new(
                None,
                crate::audit_helpers::message_state_changed_event(
                    msg_id.clone(),
                    MessageState::PeelDeferred,
                    disposition.tag(),
                ),
            ));
            recorder.record(AuditRecord::new(
                None,
                AuditEventKind::Rejection {
                    msg_id: msg_id.clone(),
                    reason: disposition.tag().to_owned(),
                },
            ));
        }

        let body = std::fs::read_to_string(&path).unwrap();
        let mut state_reasons = Vec::new();
        let mut rejection_reasons = Vec::new();
        for line in body.lines() {
            v5::Record::from_json(line.as_bytes()).unwrap();
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            let event = &row["event"];
            let reason = event["reason"].as_str().map(str::to_owned);
            match event["type"].as_str() {
                Some("message_state_changed") => state_reasons.extend(reason),
                Some("rejection") => rejection_reasons.extend(reason),
                _ => {}
            }
        }
        let expected: Vec<String> = ALL.iter().map(|d| d.tag().to_owned()).collect();
        assert_eq!(state_reasons, expected);
        assert_eq!(rejection_reasons, expected);
    }
}
