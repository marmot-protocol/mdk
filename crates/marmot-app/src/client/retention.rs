use std::collections::BTreeMap;

use cgka_traits::GroupId;

use crate::{
    AppClient, AppError, RetentionSweepGroupOutcome, RetentionSweepReport, RetentionSweepStatus,
    SecureDeleteExpiredResult,
};

const RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS: u64 = 5_000;

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
        let raw_now_seconds = now_ms / 1_000;
        let group_ids = self
            .app
            .groups_with_expiring_app_events(&self.state.label, raw_now_seconds)?;
        let groups = run_retention_group_sweeps(group_ids, |group_id_hex| {
            self.sweep_expired_retention_for_group(group_id_hex, now_ms)
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
        let groups = groups
            .into_iter()
            .filter(|outcome| self.host_may_see_group_hex(&outcome.group_id_hex))
            .collect();
        Ok(RetentionSweepReport { groups })
    }

    fn sweep_expired_retention_for_group(
        &self,
        group_id_hex: &str,
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
            group_id_hex,
            raw_now_seconds,
            skew_now_seconds,
        )?;
        match decide_expired_group_action(&scan) {
            ExpiredGroupDecision::NoExpiredMessages => Ok(empty_group_outcome(
                group_id_hex,
                RetentionSweepStatus::NoExpiredMessages,
            )),
            ExpiredGroupDecision::DeferClockSkew => Ok(empty_group_outcome(
                group_id_hex,
                RetentionSweepStatus::DeferredClockSkew,
            )),
            ExpiredGroupDecision::DeferUnread => Ok(empty_group_outcome(
                group_id_hex,
                RetentionSweepStatus::DeferredUnread,
            )),
            ExpiredGroupDecision::Prune => {
                let group_id_bytes = hex::decode(group_id_hex)?;
                if group_id_bytes.is_empty() {
                    return Err(AppError::UnknownGroup(group_id_hex.to_owned()));
                }
                let pruned = self.secure_delete_expired_plaintext_for_group_at(
                    &GroupId::new(group_id_bytes),
                    raw_now_seconds,
                )?;
                Ok(pruned_group_outcome(group_id_hex, pruned))
            }
        }
    }
}

fn run_retention_group_sweeps(
    mut group_ids: Vec<String>,
    mut sweep_group: impl FnMut(&str) -> Result<RetentionSweepGroupOutcome, AppError>,
) -> Vec<RetentionSweepGroupOutcome> {
    group_ids.sort();
    group_ids.dedup();
    let mut outcomes = Vec::with_capacity(group_ids.len());
    for group_id_hex in group_ids {
        outcomes.push(match sweep_group(&group_id_hex) {
            Ok(outcome) => outcome,
            Err(error) => failed_group_outcome(&group_id_hex, error.privacy_safe_kind()),
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
    fn group_sweep_sorts_deduplicates_and_isolates_failures() {
        let inputs = vec![
            "cc".to_owned(),
            "aa".to_owned(),
            "bb".to_owned(),
            "bb".to_owned(),
            "dd".to_owned(),
        ];
        let outcomes = run_retention_group_sweeps(inputs, |group_id_hex| {
            if group_id_hex == "bb" {
                return Err(AppError::TransportClosed);
            }
            if group_id_hex == "cc" {
                return Ok(empty_group_outcome(
                    group_id_hex,
                    RetentionSweepStatus::DeferredUnread,
                ));
            }
            Ok(pruned_group_outcome(
                group_id_hex,
                SecureDeleteExpiredResult {
                    pruned_messages: 2,
                    secrets_deleted: 1,
                    media_ciphertext_sha256: vec![group_id_hex.repeat(32)],
                    erasure_pending: false,
                },
            ))
        });

        assert_eq!(
            outcomes
                .iter()
                .map(|outcome| outcome.group_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["aa", "bb", "cc", "dd"]
        );
        assert_eq!(outcomes[0].status, RetentionSweepStatus::Pruned);
        assert_eq!(outcomes[1].status, RetentionSweepStatus::Failed);
        assert_eq!(
            outcomes[1].failure_kind.as_deref(),
            Some("transport_closed")
        );
        assert_eq!(outcomes[2].status, RetentionSweepStatus::DeferredUnread);
        assert_eq!(outcomes[3].status, RetentionSweepStatus::Pruned);
        assert_eq!(outcomes[3].pruned_messages, 2);
        assert_eq!(outcomes[3].secrets_deleted, 1);
        assert_eq!(outcomes[3].media_ciphertext_sha256, vec!["dd".repeat(32)]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sweep_prunes_expiring_rows_in_non_chat_list_groups() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        marmot_account::AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = crate::MarmotApp::with_relay(dir.path(), "wss://retention.example")
            .with_test_relay_client(Arc::new(crate::tests::ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group_id = client
            .create_group("hidden retention", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members");
        let group_id_hex = hex::encode(group_id.as_slice());
        client
            .update_message_retention(&group_id, 24 * 60 * 60)
            .await
            .unwrap();
        let sent_id = client
            .send(&group_id, b"expiring in hidden group")
            .await
            .unwrap()
            .message_ids
            .into_iter()
            .next()
            .expect("send accepted");
        let expires_at = app
            .timeline_messages_with_query(
                "alice",
                crate::TimelineMessageQuery {
                    group_id_hex: Some(group_id_hex.clone()),
                    ..crate::TimelineMessageQuery::default()
                },
            )
            .unwrap()
            .messages
            .into_iter()
            .find(|message| message.message_id_hex == sent_id)
            .and_then(|message| message.retention_expires_at)
            .expect("expiring message pins retention_expires_at");

        // Remove the group from chat_list_rows and in-memory state so it is a
        // non-chat-list/hidden group that still holds expiring app_events rows.
        client
            .state
            .groups
            .retain(|group| group.group_id_hex != group_id_hex);
        let path = app.account_storage_path("alice");
        let keys = app.account_home().load_signing_keys("alice").unwrap();
        let key = app
            .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
            .unwrap();
        storage_sqlite::expect_uncounted_writes_for_test(&path);
        let conn = rusqlite::Connection::open(path).unwrap();
        storage_sqlite::open_hardened_sqlcipher(
            &conn,
            &key,
            storage_sqlite::SqlCipherHardening::cipher_only(),
        )
        .unwrap();
        conn.execute(
            "DELETE FROM chat_list_rows WHERE group_id_hex = ?1",
            rusqlite::params![group_id_hex],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM account_groups WHERE group_id_hex = ?1",
            rusqlite::params![group_id_hex],
        )
        .unwrap();
        drop(conn);
        assert!(
            !app.chat_list("alice", true)
                .unwrap()
                .iter()
                .any(|row| row.group_id_hex == group_id_hex)
        );

        let report = client
            .sweep_expired_retention((expires_at + 6) * 1_000)
            .unwrap();
        let outcome = report
            .groups
            .iter()
            .find(|outcome| outcome.group_id_hex == group_id_hex)
            .expect("hidden/non-chat-list group with expiring rows must be swept");
        assert_eq!(outcome.status, RetentionSweepStatus::Pruned);
        assert!(outcome.pruned_messages >= 1);
        assert!(
            !app.timeline_messages_with_query(
                "alice",
                crate::TimelineMessageQuery {
                    group_id_hex: Some(group_id_hex),
                    ..crate::TimelineMessageQuery::default()
                },
            )
            .unwrap()
            .messages
            .iter()
            .any(|message| message.message_id_hex == sent_id),
            "expired row in hidden/non-chat-list group must be pruned"
        );
    }
}
