//! Simulator-owned accounting for every convergence-relevant scenario input.
//!
//! The engine deliberately works in transport/content ids, while scenarios use
//! stable action ids. This ledger joins those layers without exposing ids in
//! reports: the harness registers commit, proposal, and application inputs at
//! send time, records public `IngestOutcome`s and `GroupEvent`s, then refreshes
//! the final durable disposition through the feature-gated conformance view.

use cgka_traits::engine::AppMessageInvalidationReason;
use cgka_traits::ingest::{IngestOutcome, InputRejectionCategory, StaleReason};
use cgka_traits::message::MessageState;
use cgka_traits::types::MessageId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioInputKind {
    Commit,
    Proposal,
    #[default]
    Application,
}

impl ScenarioInputKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Proposal => "proposal",
            Self::Application => "application",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioInputDisposition {
    #[default]
    Pending,
    Accepted,
    Delivered,
    Deduplicated,
    Expired,
    Invalidated,
    Rejected,
    Stale,
    Ignored,
    ResourceRefused,
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScenarioInputMetadata {
    pub scenario_id: String,
    pub kind: ScenarioInputKind,
    pub sender: String,
    pub logical_id: Option<String>,
    pub payload: Option<String>,
    pub aliases: Vec<MessageId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioInputLedgerEntry {
    /// Stable synthetic action id, never a transport or randomized MLS id.
    pub scenario_id: String,
    pub kind: ScenarioInputKind,
    /// Stable scenario label when known, otherwise the sender identity hex.
    pub sender: String,
    /// Deterministic inner application-event id used only to correlate delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_id: Option<String>,
    /// Harness-decoded logical application payload. Commits and proposals omit it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub payload: String,
    /// Current semantic disposition at the observation boundary.
    pub disposition: ScenarioInputDisposition,
    pub send_attempts: usize,
    pub send_accepted: usize,
    pub send_queued: usize,
    pub published: usize,
    pub ingest_attempts: usize,
    pub ingest_accepted: usize,
    pub transport_deferred: usize,
    pub resource_refused: usize,
    pub ignored: usize,
    pub local_state: usize,
    pub rejected: usize,
    pub ingest_errors: usize,
    pub delivered: usize,
    pub deduplicated: usize,
    pub expired: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invalidated: Vec<String>,
    /// True while accepted or retained work lacks a terminal/current outcome.
    pub pending: bool,
}

#[derive(Default)]
pub(crate) struct ScenarioInputTracker {
    entries: BTreeMap<String, ScenarioInputLedgerEntry>,
    metadata: BTreeMap<String, ScenarioInputMetadata>,
    scenario_by_logical_id: BTreeMap<String, String>,
}

impl ScenarioInputTracker {
    pub(crate) fn record_send_attempt(&mut self, metadata: &ScenarioInputMetadata) {
        self.remember_metadata(metadata);
        let entry = self.entry(metadata);
        entry.send_attempts += 1;
        entry.disposition = ScenarioInputDisposition::Pending;
        entry.pending = true;
    }

    pub(crate) fn record_send_accepted(&mut self, metadata: &ScenarioInputMetadata, queued: bool) {
        self.remember_metadata(metadata);
        let entry = self.entry(metadata);
        entry.send_accepted += 1;
        if queued {
            entry.send_queued += 1;
        }
        entry.disposition = ScenarioInputDisposition::Pending;
        entry.pending = true;
    }

    pub(crate) fn record_published(&mut self, metadata: &ScenarioInputMetadata) {
        self.remember_metadata(metadata);
        let entry = self.entry(metadata);
        entry.published += 1;
        if metadata.kind == ScenarioInputKind::Application {
            entry.disposition = ScenarioInputDisposition::Accepted;
            entry.pending = false;
        }
    }

    pub(crate) fn record_confirmed(&mut self, scenario_id: &str) {
        if let Some(entry) = self.entries.get_mut(scenario_id) {
            entry.disposition = ScenarioInputDisposition::Accepted;
            entry.pending = false;
        }
    }

    pub(crate) fn record_rolled_back(&mut self, scenario_id: &str) {
        if let Some(entry) = self.entries.get_mut(scenario_id) {
            entry.disposition = ScenarioInputDisposition::RolledBack;
            push_unique(&mut entry.invalidated, "publish_rolled_back");
            entry.pending = false;
        }
    }

    pub(crate) fn record_ingest(
        &mut self,
        metadata: &ScenarioInputMetadata,
        outcome: Result<&IngestOutcome, ()>,
    ) {
        self.remember_metadata(metadata);
        let entry = self.entry(metadata);
        entry.ingest_attempts += 1;
        match outcome {
            Ok(IngestOutcome::Processed) => {
                entry.ingest_accepted += 1;
                entry.disposition = ScenarioInputDisposition::Accepted;
                entry.pending = false;
            }
            Ok(IngestOutcome::Buffered { .. }) => {
                entry.ingest_accepted += 1;
                entry.disposition = ScenarioInputDisposition::Pending;
                entry.pending = true;
            }
            Ok(IngestOutcome::TransportDeferred { .. }) => {
                entry.transport_deferred += 1;
                entry.disposition = ScenarioInputDisposition::Pending;
                entry.pending = true;
            }
            Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            }) => {
                entry.deduplicated += 1;
                if entry.pending {
                    entry.disposition = ScenarioInputDisposition::Deduplicated;
                }
            }
            Ok(IngestOutcome::Stale {
                reason: StaleReason::BeyondAppRetention,
            }) => {
                entry.expired = 1;
                entry.disposition = ScenarioInputDisposition::Expired;
                entry.pending = false;
            }
            Ok(IngestOutcome::Stale { reason }) => {
                push_unique(&mut entry.invalidated, stale_reason(reason));
                entry.disposition = ScenarioInputDisposition::Stale;
                entry.pending = false;
            }
            Ok(IngestOutcome::Ignored { .. }) => {
                entry.ignored += 1;
                entry.disposition = ScenarioInputDisposition::Ignored;
                entry.pending = false;
            }
            Ok(IngestOutcome::LocalState { .. }) => {
                entry.local_state += 1;
                entry.disposition = ScenarioInputDisposition::Ignored;
                entry.pending = false;
            }
            Ok(IngestOutcome::ResourceRefused { .. }) => {
                entry.resource_refused += 1;
                entry.disposition = ScenarioInputDisposition::ResourceRefused;
                entry.pending = false;
            }
            Ok(IngestOutcome::Rejected { category }) => {
                entry.rejected += 1;
                push_unique_owned(&mut entry.invalidated, format!("{category:?}"));
                entry.disposition = ScenarioInputDisposition::Rejected;
                entry.pending = false;
            }
            Err(()) => {
                entry.ingest_errors += 1;
            }
        }
    }

    pub(crate) fn record_delivered_logical(&mut self, logical_id: &str) {
        let Some(scenario_id) = self.scenario_by_logical_id.get(logical_id).cloned() else {
            return;
        };
        let Some(entry) = self.entries.get_mut(&scenario_id) else {
            return;
        };
        entry.delivered += 1;
        entry.disposition = ScenarioInputDisposition::Delivered;
        entry.pending = false;
    }

    pub(crate) fn record_app_invalidated(
        &mut self,
        metadata: &ScenarioInputMetadata,
        reason: AppMessageInvalidationReason,
    ) {
        self.remember_metadata(metadata);
        let entry = self.entry(metadata);
        let reason = invalidation_reason(reason).to_owned();
        if reason == "beyond_app_retention" {
            entry.expired = 1;
            entry.disposition = ScenarioInputDisposition::Expired;
        } else {
            entry.disposition = ScenarioInputDisposition::Invalidated;
        }
        push_unique_owned(&mut entry.invalidated, reason);
        entry.pending = false;
    }

    pub(crate) fn record_commit_invalidated(
        &mut self,
        metadata: &ScenarioInputMetadata,
        reason: &'static str,
    ) {
        self.remember_metadata(metadata);
        let entry = self.entry(metadata);
        push_unique(&mut entry.invalidated, reason);
        entry.disposition = ScenarioInputDisposition::Invalidated;
        entry.pending = false;
    }

    pub(crate) fn state_queries(&self) -> Vec<(String, ScenarioInputKind, Vec<MessageId>)> {
        self.metadata
            .values()
            .map(|metadata| {
                (
                    metadata.scenario_id.clone(),
                    metadata.kind,
                    metadata.aliases.clone(),
                )
            })
            .collect()
    }

    pub(crate) fn record_storage_state(
        &mut self,
        scenario_id: &str,
        kind: ScenarioInputKind,
        state: MessageState,
    ) {
        let Some(entry) = self.entries.get_mut(scenario_id) else {
            return;
        };
        match state {
            MessageState::Processed => {
                if !is_terminal(&entry.disposition)
                    && (kind != ScenarioInputKind::Application
                        || entry.disposition != ScenarioInputDisposition::Delivered)
                {
                    entry.disposition = ScenarioInputDisposition::Accepted;
                }
                entry.pending = false;
            }
            MessageState::Created | MessageState::Retryable | MessageState::PeelDeferred => {
                if !is_terminal(&entry.disposition) {
                    entry.disposition = ScenarioInputDisposition::Pending;
                    entry.pending = true;
                }
            }
            MessageState::Sent => {
                if kind == ScenarioInputKind::Application {
                    entry.disposition = ScenarioInputDisposition::Accepted;
                    entry.pending = false;
                }
            }
            MessageState::Failed => {
                if !is_terminal(&entry.disposition) {
                    entry.disposition = ScenarioInputDisposition::Rejected;
                    entry.pending = false;
                }
            }
            MessageState::EpochInvalidated => {
                if !matches!(
                    entry.disposition,
                    ScenarioInputDisposition::Expired | ScenarioInputDisposition::RolledBack
                ) {
                    entry.disposition = ScenarioInputDisposition::Invalidated;
                }
                entry.pending = false;
            }
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<ScenarioInputLedgerEntry> {
        self.entries.values().cloned().collect()
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.entries.values().filter(|entry| entry.pending).count()
    }

    pub(crate) fn metadata_for_logical(&self, logical_id: &str) -> Option<ScenarioInputMetadata> {
        self.scenario_by_logical_id
            .get(logical_id)
            .and_then(|scenario_id| self.metadata.get(scenario_id))
            .cloned()
    }

    fn remember_metadata(&mut self, metadata: &ScenarioInputMetadata) {
        if let Some(logical_id) = &metadata.logical_id {
            self.scenario_by_logical_id
                .insert(logical_id.clone(), metadata.scenario_id.clone());
        }
        self.metadata
            .entry(metadata.scenario_id.clone())
            .and_modify(|existing| {
                for alias in &metadata.aliases {
                    if !existing.aliases.contains(alias) {
                        existing.aliases.push(alias.clone());
                    }
                }
            })
            .or_insert_with(|| metadata.clone());
    }

    fn entry(&mut self, metadata: &ScenarioInputMetadata) -> &mut ScenarioInputLedgerEntry {
        self.entries
            .entry(metadata.scenario_id.clone())
            .or_insert_with(|| ScenarioInputLedgerEntry {
                scenario_id: metadata.scenario_id.clone(),
                kind: metadata.kind,
                sender: metadata.sender.clone(),
                logical_id: metadata.logical_id.clone(),
                payload: metadata.payload.clone().unwrap_or_default(),
                disposition: ScenarioInputDisposition::Pending,
                ..Default::default()
            })
    }
}

fn is_terminal(disposition: &ScenarioInputDisposition) -> bool {
    matches!(
        disposition,
        ScenarioInputDisposition::Delivered
            | ScenarioInputDisposition::Expired
            | ScenarioInputDisposition::Invalidated
            | ScenarioInputDisposition::Rejected
            | ScenarioInputDisposition::Stale
            | ScenarioInputDisposition::Ignored
            | ScenarioInputDisposition::ResourceRefused
            | ScenarioInputDisposition::RolledBack
    )
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn push_unique_owned(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn invalidation_reason(reason: AppMessageInvalidationReason) -> &'static str {
    match reason {
        AppMessageInvalidationReason::LosingBranch => "losing_branch",
        AppMessageInvalidationReason::BeyondAnchor => "beyond_anchor",
        AppMessageInvalidationReason::BeyondAppRetention => "beyond_app_retention",
        AppMessageInvalidationReason::UndecryptableInCanonicalState => {
            "undecryptable_in_canonical_state"
        }
    }
}

fn stale_reason(reason: &StaleReason) -> &'static str {
    #[allow(deprecated)]
    match reason {
        StaleReason::AlreadySeen => "already_seen",
        StaleReason::AlreadyAtEpoch { .. } => "already_at_epoch",
        StaleReason::NotForThisClient => "not_for_this_client",
        StaleReason::UnknownGroup => "unknown_group",
        StaleReason::OwnEcho => "own_echo",
        StaleReason::PreMembership => "pre_membership",
        StaleReason::BeyondAnchor => "beyond_anchor",
        StaleReason::BeyondRollbackHorizon => "beyond_rollback_horizon",
        StaleReason::BeyondAppRetention => "beyond_app_retention",
        StaleReason::LosingBranch => "losing_branch",
        StaleReason::InvalidAgainstCanonicalState => "invalid_against_canonical_state",
        StaleReason::SelfEvicted => "self_evicted",
        StaleReason::Quarantined => "quarantined",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::types::{EpochId, GroupId};

    fn metadata(kind: ScenarioInputKind) -> ScenarioInputMetadata {
        ScenarioInputMetadata {
            scenario_id: format!("step-4:{}", kind.label()),
            kind,
            sender: "alice".into(),
            logical_id: (kind == ScenarioInputKind::Application).then(|| "event-id".into()),
            payload: (kind == ScenarioInputKind::Application).then(|| "hello".into()),
            aliases: vec![MessageId::new(vec![1])],
        }
    }

    #[test]
    fn duplicate_attempt_does_not_hide_the_single_delivery() {
        let mut tracker = ScenarioInputTracker::default();
        let metadata = metadata(ScenarioInputKind::Application);
        tracker.record_ingest(&metadata, Ok(&IngestOutcome::Processed));
        tracker.record_delivered_logical("event-id");
        tracker.record_ingest(
            &metadata,
            Ok(&IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate,
            }),
        );

        let entry = &tracker.snapshot()[0];
        assert_eq!(entry.ingest_attempts, 2);
        assert_eq!(entry.ingest_accepted, 1);
        assert_eq!(entry.delivered, 1);
        assert_eq!(entry.deduplicated, 1);
        assert_eq!(entry.disposition, ScenarioInputDisposition::Delivered);
        assert!(!entry.pending);
    }

    #[test]
    fn buffered_commit_and_proposal_are_pending_until_storage_accepts_them() {
        let mut tracker = ScenarioInputTracker::default();
        for kind in [ScenarioInputKind::Commit, ScenarioInputKind::Proposal] {
            let metadata = metadata(kind);
            tracker.record_ingest(
                &metadata,
                Ok(&IngestOutcome::Buffered {
                    group_id: GroupId::new(vec![1]),
                    epoch: EpochId(1),
                }),
            );
            assert_eq!(
                tracker
                    .snapshot()
                    .into_iter()
                    .find(|entry| entry.scenario_id == metadata.scenario_id)
                    .unwrap()
                    .disposition,
                ScenarioInputDisposition::Pending
            );
            tracker.record_storage_state(&metadata.scenario_id, kind, MessageState::Processed);
            assert_eq!(
                tracker
                    .snapshot()
                    .into_iter()
                    .find(|entry| entry.scenario_id == metadata.scenario_id)
                    .unwrap()
                    .disposition,
                ScenarioInputDisposition::Accepted
            );
        }
    }

    #[test]
    fn transport_deferred_is_pending_but_not_accepted() {
        let mut tracker = ScenarioInputTracker::default();
        let metadata = metadata(ScenarioInputKind::Application);
        tracker.record_ingest(
            &metadata,
            Ok(&IngestOutcome::TransportDeferred {
                group_id: GroupId::new(vec![1]),
            }),
        );

        let entry = &tracker.snapshot()[0];
        assert_eq!(entry.ingest_accepted, 0);
        assert_eq!(entry.transport_deferred, 1);
        assert_eq!(entry.disposition, ScenarioInputDisposition::Pending);
        assert!(entry.pending);
    }

    #[test]
    fn processed_storage_does_not_overwrite_terminal_semantic_disposition() {
        let terminal_dispositions = [
            ScenarioInputDisposition::Delivered,
            ScenarioInputDisposition::Expired,
            ScenarioInputDisposition::Invalidated,
            ScenarioInputDisposition::Rejected,
            ScenarioInputDisposition::Stale,
            ScenarioInputDisposition::Ignored,
            ScenarioInputDisposition::ResourceRefused,
            ScenarioInputDisposition::RolledBack,
        ];
        for disposition in terminal_dispositions {
            let mut tracker = ScenarioInputTracker::default();
            let metadata = metadata(ScenarioInputKind::Application);
            tracker.record_send_attempt(&metadata);
            let entry = tracker.entries.get_mut(&metadata.scenario_id).unwrap();
            entry.disposition = disposition.clone();
            entry.pending = false;

            tracker.record_storage_state(
                &metadata.scenario_id,
                ScenarioInputKind::Application,
                MessageState::Processed,
            );

            let entry = &tracker.snapshot()[0];
            assert_eq!(entry.disposition, disposition);
            assert!(!entry.pending);
        }
    }
}
