use std::collections::{BTreeMap, HashMap};

use cgka_traits::GroupId;

use crate::{
    AppClient, AppError, RetentionSweepGroupOutcome, RetentionSweepReport, RetentionSweepStatus,
    SecureDeleteExpiredResult,
};

const RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS: u64 = 5_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetentionSweepGroupInput {
    group_id_hex: String,
    retention_seconds: Option<u64>,
}

/// What the sweep does with one group after storage answers
/// [`storage_sqlite::RetentionExpiryScan`]. Inspection order mirrors the old
/// page classifier: a boundary row still inside clock-skew tolerance defers
/// everything, an expired row the unread projection still counts defers the
/// prune, and only a provably expired group prunes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpiredGroupDecision {
    DeferClockSkew,
    DeferUnread,
    NoExpiredMessages,
    Prune,
}

fn decide_expired_group_action(scan: &storage_sqlite::RetentionExpiryScan) -> ExpiredGroupDecision {
    if scan.skew_boundary_rows {
        ExpiredGroupDecision::DeferClockSkew
    } else if scan.expired_unread {
        ExpiredGroupDecision::DeferUnread
    } else if scan.expired_rows {
        ExpiredGroupDecision::Prune
    } else {
        ExpiredGroupDecision::NoExpiredMessages
    }
}

impl AppClient {
    pub fn sweep_expired_retention(&self, now_ms: u64) -> Result<RetentionSweepReport, AppError> {
        let retention_by_group = self
            .state
            .groups
            .iter()
            .map(|group| {
                (
                    group.group_id_hex.clone(),
                    group.message_retention.disappearing_message_secs,
                )
            })
            .collect::<HashMap<_, _>>();
        let inputs = self
            .app
            .chat_list(&self.state.label, true)?
            .into_iter()
            .map(|row| RetentionSweepGroupInput {
                retention_seconds: retention_by_group.get(&row.group_id_hex).copied(),
                group_id_hex: row.group_id_hex,
            })
            .collect();
        let groups = run_retention_group_sweeps(inputs, |input| {
            self.sweep_expired_retention_for_group(input, now_ms)
        });
        for group in &groups {
            let outcome = match group.status {
                RetentionSweepStatus::NoExpiredMessages => "no_work_due",
                RetentionSweepStatus::Pruned => "performed",
                RetentionSweepStatus::Failed => "failure",
                RetentionSweepStatus::DeferredClockSkew | RetentionSweepStatus::DeferredUnread => {
                    "deferred"
                }
            };
            self.app.product_analytics.observe(
                crate::ProductFamily::Maintenance,
                "retention",
                outcome,
                crate::ProductUnit::Attempt,
                None,
            );
        }
        trace_retention_sweep_summary(&groups);
        Ok(RetentionSweepReport { groups })
    }

    fn sweep_expired_retention_for_group(
        &self,
        input: &RetentionSweepGroupInput,
        now_ms: u64,
    ) -> Result<RetentionSweepGroupOutcome, AppError> {
        let raw_now_seconds = now_ms / 1_000;
        let skew_now_seconds =
            now_ms.saturating_sub(RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS) / 1_000;

        // Storage answers with the projection's own read-cursor comparison
        // over the rows the prune deletes: those whose pinned source-epoch
        // expiry has passed, whatever the group's policy is today.
        let scan = self.app.retention_expiry_scan(
            &self.state.label,
            &input.group_id_hex,
            raw_now_seconds,
            skew_now_seconds,
        )?;
        match decide_expired_group_action(&scan) {
            ExpiredGroupDecision::NoExpiredMessages => Ok(empty_group_outcome(
                &input.group_id_hex,
                RetentionSweepStatus::NoExpiredMessages,
            )),
            ExpiredGroupDecision::DeferClockSkew => Ok(empty_group_outcome(
                &input.group_id_hex,
                RetentionSweepStatus::DeferredClockSkew,
            )),
            ExpiredGroupDecision::DeferUnread => Ok(empty_group_outcome(
                &input.group_id_hex,
                RetentionSweepStatus::DeferredUnread,
            )),
            ExpiredGroupDecision::Prune => {
                let group_id_bytes = hex::decode(&input.group_id_hex)?;
                if group_id_bytes.is_empty() {
                    return Err(AppError::UnknownGroup(input.group_id_hex.clone()));
                }
                let pruned = self.secure_delete_expired_plaintext_for_group_at(
                    &GroupId::new(group_id_bytes),
                    raw_now_seconds,
                )?;
                Ok(pruned_group_outcome(&input.group_id_hex, pruned))
            }
        }
    }
}

fn run_retention_group_sweeps(
    mut inputs: Vec<RetentionSweepGroupInput>,
    mut sweep_group: impl FnMut(
        &RetentionSweepGroupInput,
    ) -> Result<RetentionSweepGroupOutcome, AppError>,
) -> Vec<RetentionSweepGroupOutcome> {
    inputs.sort_by(|left, right| left.group_id_hex.cmp(&right.group_id_hex));
    inputs.dedup_by(|left, right| left.group_id_hex == right.group_id_hex);
    let mut outcomes = Vec::new();
    for input in inputs {
        let Some(retention_seconds) = input.retention_seconds else {
            let error = AppError::UnknownGroup(input.group_id_hex.clone());
            outcomes.push(failed_group_outcome(
                &input.group_id_hex,
                error.privacy_safe_kind(),
            ));
            continue;
        };
        if retention_seconds == 0 {
            continue;
        }
        outcomes.push(match sweep_group(&input) {
            Ok(outcome) => outcome,
            Err(error) => failed_group_outcome(&input.group_id_hex, error.privacy_safe_kind()),
        });
    }
    outcomes
}

fn empty_group_outcome(
    group_id_hex: &str,
    status: RetentionSweepStatus,
) -> RetentionSweepGroupOutcome {
    RetentionSweepGroupOutcome {
        group_id_hex: group_id_hex.to_owned(),
        status,
        pruned_messages: 0,
        secrets_deleted: 0,
        media_ciphertext_sha256: Vec::new(),
        failure_kind: None,
    }
}

fn pruned_group_outcome(
    group_id_hex: &str,
    pruned: SecureDeleteExpiredResult,
) -> RetentionSweepGroupOutcome {
    RetentionSweepGroupOutcome {
        group_id_hex: group_id_hex.to_owned(),
        status: RetentionSweepStatus::Pruned,
        pruned_messages: pruned.pruned_messages,
        secrets_deleted: pruned.secrets_deleted,
        media_ciphertext_sha256: pruned.media_ciphertext_sha256,
        failure_kind: None,
    }
}

fn failed_group_outcome(group_id_hex: &str, failure_kind: &str) -> RetentionSweepGroupOutcome {
    RetentionSweepGroupOutcome {
        group_id_hex: group_id_hex.to_owned(),
        status: RetentionSweepStatus::Failed,
        pruned_messages: 0,
        secrets_deleted: 0,
        media_ciphertext_sha256: Vec::new(),
        failure_kind: Some(failure_kind.to_owned()),
    }
}

fn trace_retention_sweep_summary(groups: &[RetentionSweepGroupOutcome]) {
    let count = |status| groups.iter().filter(|group| group.status == status).count() as u64;
    let failure_kinds = groups
        .iter()
        .filter_map(|group| group.failure_kind.as_deref())
        .fold(BTreeMap::<&str, u64>::new(), |mut counts, kind| {
            *counts.entry(kind).or_default() += 1;
            counts
        });
    tracing::debug!(
        target: "marmot_app::retention",
        method = "sweep_expired_retention",
        groups = groups.len() as u64,
        no_expired_messages = count(RetentionSweepStatus::NoExpiredMessages),
        pruned_groups = count(RetentionSweepStatus::Pruned),
        pruned_messages = groups
            .iter()
            .map(|group| group.pruned_messages)
            .sum::<u64>(),
        deferred_clock_skew = count(RetentionSweepStatus::DeferredClockSkew),
        deferred_unread = count(RetentionSweepStatus::DeferredUnread),
        failures = count(RetentionSweepStatus::Failed),
        failure_kinds = ?failure_kinds,
        "retention sweep completed",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(
        skew_boundary_rows: bool,
        expired_unread: bool,
        expired_rows: bool,
    ) -> storage_sqlite::RetentionExpiryScan {
        storage_sqlite::RetentionExpiryScan {
            skew_boundary_rows,
            expired_unread,
            expired_rows,
        }
    }

    #[test]
    fn skew_tolerance_pins_android_background_policy() {
        assert_eq!(RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS, 5_000);
    }

    #[test]
    fn decision_defers_skew_before_unread_before_pruning() {
        assert_eq!(
            decide_expired_group_action(&scan(true, true, true)),
            ExpiredGroupDecision::DeferClockSkew
        );
        assert_eq!(
            decide_expired_group_action(&scan(false, true, true)),
            ExpiredGroupDecision::DeferUnread
        );
        assert_eq!(
            decide_expired_group_action(&scan(false, false, true)),
            ExpiredGroupDecision::Prune
        );
        assert_eq!(
            decide_expired_group_action(&scan(false, false, false)),
            ExpiredGroupDecision::NoExpiredMessages
        );
    }

    #[test]
    fn group_sweep_omits_disabled_groups_sorts_and_isolates_failures() {
        let input = |group_id_hex: &str, retention_seconds| RetentionSweepGroupInput {
            group_id_hex: group_id_hex.to_owned(),
            retention_seconds,
        };
        let inputs = vec![
            input("cc", Some(60)),
            input("aa", Some(0)),
            input("bb", Some(60)),
            input("dd", Some(60)),
        ];
        let outcomes = run_retention_group_sweeps(inputs, |input| {
            if input.group_id_hex == "bb" {
                return Err(AppError::TransportClosed);
            }
            if input.group_id_hex == "cc" {
                return Ok(empty_group_outcome(
                    &input.group_id_hex,
                    RetentionSweepStatus::DeferredUnread,
                ));
            }
            Ok(pruned_group_outcome(
                &input.group_id_hex,
                SecureDeleteExpiredResult {
                    pruned_messages: 2,
                    secrets_deleted: 1,
                    media_ciphertext_sha256: vec!["dd".repeat(32)],
                    erasure_pending: false,
                },
            ))
        });

        assert_eq!(
            outcomes
                .iter()
                .map(|outcome| outcome.group_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["bb", "cc", "dd"]
        );
        assert_eq!(outcomes[0].status, RetentionSweepStatus::Failed);
        assert_eq!(
            outcomes[0].failure_kind.as_deref(),
            Some("transport_closed")
        );
        assert_eq!(outcomes[1].status, RetentionSweepStatus::DeferredUnread);
        assert_eq!(outcomes[2].status, RetentionSweepStatus::Pruned);
        assert_eq!(outcomes[2].pruned_messages, 2);
        assert_eq!(outcomes[2].secrets_deleted, 1);
        assert_eq!(outcomes[2].media_ciphertext_sha256, vec!["dd".repeat(32)]);
    }
}
