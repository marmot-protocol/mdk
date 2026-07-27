use std::collections::{BTreeMap, HashMap};

use cgka_traits::GroupId;

use crate::{
    AppClient, AppError, RetentionSweepGroupOutcome, RetentionSweepReport, RetentionSweepStatus,
    SecureDeleteExpiredResult, TimelineMessageQuery, TimelinePagination,
};

const RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS: u64 = 5_000;
const RETENTION_SWEEP_TIMELINE_PAGE_LIMIT: usize = 200;
const RETENTION_SWEEP_MAX_PAGES: usize = 20;
const RETENTION_SWEEP_SEED_MESSAGE_ID: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetentionSweepGroupInput {
    group_id_hex: String,
    retention_seconds: Option<u64>,
    last_read_timeline_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetentionTimelineScanRow {
    message_id_hex: String,
    timeline_at: u64,
    direction: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetentionTimelineScanPage {
    rows: Vec<RetentionTimelineScanRow>,
    has_more_before: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetentionPageDecision {
    DeferredClockSkew,
    DeferredUnread,
    SafelyExpired,
    KeepScanning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RetentionScanAction {
    Continue {
        before: u64,
        before_message_id: String,
    },
    Complete(RetentionSweepStatus),
    Prune,
}

#[derive(Clone, Debug)]
struct RetentionScanState {
    raw_cutoff_seconds: u64,
    skew_cutoff_seconds: u64,
    last_read_timeline_at: Option<u64>,
    pages_scanned: usize,
    saw_safely_expired: bool,
    before: u64,
    before_message_id: String,
}

impl RetentionScanState {
    fn new(
        raw_cutoff_seconds: u64,
        skew_cutoff_seconds: u64,
        last_read_timeline_at: Option<u64>,
    ) -> Self {
        Self {
            raw_cutoff_seconds,
            skew_cutoff_seconds,
            last_read_timeline_at,
            pages_scanned: 0,
            saw_safely_expired: false,
            before: raw_cutoff_seconds,
            before_message_id: RETENTION_SWEEP_SEED_MESSAGE_ID.to_owned(),
        }
    }

    fn observe_page(&mut self, page: &RetentionTimelineScanPage) -> RetentionScanAction {
        self.pages_scanned = self.pages_scanned.saturating_add(1);
        match classify_retention_page(
            &page.rows,
            self.raw_cutoff_seconds,
            self.skew_cutoff_seconds,
            self.last_read_timeline_at,
        ) {
            RetentionPageDecision::DeferredClockSkew => {
                return RetentionScanAction::Complete(RetentionSweepStatus::DeferredClockSkew);
            }
            RetentionPageDecision::DeferredUnread => {
                return RetentionScanAction::Complete(RetentionSweepStatus::DeferredUnread);
            }
            RetentionPageDecision::SafelyExpired => self.saw_safely_expired = true,
            RetentionPageDecision::KeepScanning => {}
        }

        if page.rows.len() > RETENTION_SWEEP_TIMELINE_PAGE_LIMIT
            || (page.has_more_before && page.rows.len() != RETENTION_SWEEP_TIMELINE_PAGE_LIMIT)
        {
            return RetentionScanAction::Complete(RetentionSweepStatus::DeferredScanExhausted);
        }
        if page.rows.is_empty() {
            return RetentionScanAction::Complete(if self.pages_scanned == 1 {
                RetentionSweepStatus::NoExpiredMessages
            } else {
                RetentionSweepStatus::DeferredScanExhausted
            });
        }
        if !page.has_more_before {
            return self.completed_scan_action();
        }

        let oldest = page
            .rows
            .iter()
            .min_by(|left, right| {
                (left.timeline_at, left.message_id_hex.as_str())
                    .cmp(&(right.timeline_at, right.message_id_hex.as_str()))
            })
            .expect("non-empty retention page has an oldest row");
        if self
            .last_read_timeline_at
            .is_some_and(|last_read| oldest.timeline_at <= last_read)
        {
            return self.completed_scan_action();
        }
        if self.pages_scanned >= RETENTION_SWEEP_MAX_PAGES
            || (oldest.timeline_at, oldest.message_id_hex.as_str())
                >= (self.before, self.before_message_id.as_str())
        {
            return RetentionScanAction::Complete(RetentionSweepStatus::DeferredScanExhausted);
        }

        self.before = oldest.timeline_at;
        self.before_message_id.clone_from(&oldest.message_id_hex);
        RetentionScanAction::Continue {
            before: self.before,
            before_message_id: self.before_message_id.clone(),
        }
    }

    fn completed_scan_action(&self) -> RetentionScanAction {
        if self.saw_safely_expired {
            RetentionScanAction::Prune
        } else {
            RetentionScanAction::Complete(RetentionSweepStatus::NoExpiredMessages)
        }
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
                last_read_timeline_at: row.last_read_timeline_at,
            })
            .collect();
        let groups = run_retention_group_sweeps(inputs, |input, retention_seconds| {
            self.sweep_expired_retention_for_group(input, retention_seconds, now_ms)
        });
        trace_retention_sweep_summary(&groups);
        Ok(RetentionSweepReport { groups })
    }

    fn sweep_expired_retention_for_group(
        &self,
        input: &RetentionSweepGroupInput,
        retention_seconds: u64,
        now_ms: u64,
    ) -> Result<RetentionSweepGroupOutcome, AppError> {
        let raw_now_seconds = now_ms / 1_000;
        let raw_cutoff_seconds = raw_now_seconds.saturating_sub(retention_seconds);
        if raw_cutoff_seconds == 0 {
            return Ok(empty_group_outcome(
                &input.group_id_hex,
                RetentionSweepStatus::NoExpiredMessages,
            ));
        }
        let skew_now_seconds =
            now_ms.saturating_sub(RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS) / 1_000;
        let skew_cutoff_seconds = skew_now_seconds.saturating_sub(retention_seconds);
        let mut scan = RetentionScanState::new(
            raw_cutoff_seconds,
            skew_cutoff_seconds,
            input.last_read_timeline_at,
        );

        loop {
            let page = self.app.timeline_messages_with_query(
                &self.state.label,
                TimelineMessageQuery {
                    group_id_hex: Some(input.group_id_hex.clone()),
                    search: None,
                    pagination: TimelinePagination {
                        before: Some(scan.before),
                        before_message_id: Some(scan.before_message_id.clone()),
                        before_inclusive: false,
                        after: None,
                        after_message_id: None,
                        limit: Some(RETENTION_SWEEP_TIMELINE_PAGE_LIMIT),
                    },
                },
            )?;
            let scan_page = RetentionTimelineScanPage {
                rows: page
                    .messages
                    .into_iter()
                    .map(|message| RetentionTimelineScanRow {
                        message_id_hex: message.message_id_hex,
                        timeline_at: message.timeline_at,
                        direction: message.direction,
                    })
                    .collect(),
                has_more_before: page.has_more_before,
            };
            match scan.observe_page(&scan_page) {
                RetentionScanAction::Continue {
                    before,
                    before_message_id,
                } => {
                    debug_assert_eq!(scan.before, before);
                    debug_assert_eq!(scan.before_message_id, before_message_id);
                }
                RetentionScanAction::Complete(status) => {
                    return Ok(empty_group_outcome(&input.group_id_hex, status));
                }
                RetentionScanAction::Prune => {
                    let group_id_bytes = hex::decode(&input.group_id_hex)?;
                    if group_id_bytes.is_empty() {
                        return Err(AppError::UnknownGroup(input.group_id_hex.clone()));
                    }
                    let pruned = self.secure_delete_expired_plaintext_for_group_at(
                        &GroupId::new(group_id_bytes),
                        raw_now_seconds,
                    )?;
                    return Ok(pruned_group_outcome(&input.group_id_hex, pruned));
                }
            }
        }
    }
}

fn run_retention_group_sweeps(
    mut inputs: Vec<RetentionSweepGroupInput>,
    mut sweep_group: impl FnMut(
        &RetentionSweepGroupInput,
        u64,
    ) -> Result<RetentionSweepGroupOutcome, AppError>,
) -> Vec<RetentionSweepGroupOutcome> {
    inputs.sort_by(|left, right| left.group_id_hex.cmp(&right.group_id_hex));
    inputs.dedup_by(|left, right| left.group_id_hex == right.group_id_hex);
    let mut outcomes = Vec::new();
    for input in inputs {
        let Some(retention_seconds) = input.retention_seconds else {
            outcomes.push(failed_group_outcome(&input.group_id_hex, "unknown_group"));
            continue;
        };
        if retention_seconds == 0 {
            continue;
        }
        outcomes.push(match sweep_group(&input, retention_seconds) {
            Ok(outcome) => outcome,
            Err(error) => failed_group_outcome(&input.group_id_hex, error.privacy_safe_kind()),
        });
    }
    outcomes
}

fn classify_retention_page(
    rows: &[RetentionTimelineScanRow],
    raw_cutoff_seconds: u64,
    skew_cutoff_seconds: u64,
    last_read_timeline_at: Option<u64>,
) -> RetentionPageDecision {
    if rows.iter().any(|row| {
        raw_cutoff_seconds > skew_cutoff_seconds
            && row.timeline_at >= skew_cutoff_seconds
            && row.timeline_at < raw_cutoff_seconds
    }) {
        return RetentionPageDecision::DeferredClockSkew;
    }
    if rows.iter().any(|row| {
        row.timeline_at < raw_cutoff_seconds
            && row.direction == "received"
            && last_read_timeline_at.is_none_or(|last_read| row.timeline_at > last_read)
    }) {
        return RetentionPageDecision::DeferredUnread;
    }
    if rows
        .iter()
        .any(|row| skew_cutoff_seconds > 0 && row.timeline_at < skew_cutoff_seconds)
    {
        return RetentionPageDecision::SafelyExpired;
    }
    RetentionPageDecision::KeepScanning
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
        deferred_scan_exhausted = count(RetentionSweepStatus::DeferredScanExhausted),
        failures = count(RetentionSweepStatus::Failed),
        failure_kinds = ?failure_kinds,
        "retention sweep completed",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(timeline_at: u64, suffix: u8, direction: &str) -> RetentionTimelineScanRow {
        RetentionTimelineScanRow {
            message_id_hex: format!("{suffix:064x}"),
            timeline_at,
            direction: direction.to_owned(),
        }
    }

    fn page(
        rows: Vec<RetentionTimelineScanRow>,
        has_more_before: bool,
    ) -> RetentionTimelineScanPage {
        RetentionTimelineScanPage {
            rows,
            has_more_before,
        }
    }

    #[test]
    fn constants_pin_android_background_policy() {
        assert_eq!(RETENTION_SWEEP_CLOCK_SKEW_TOLERANCE_MS, 5_000);
        assert_eq!(RETENTION_SWEEP_TIMELINE_PAGE_LIMIT, 200);
        assert_eq!(RETENTION_SWEEP_MAX_PAGES, 20);
        assert_eq!(RETENTION_SWEEP_SEED_MESSAGE_ID, "0".repeat(64));
    }

    #[test]
    fn skew_deferral_wins_over_safely_expired_rows() {
        assert_eq!(
            classify_retention_page(&[row(930, 1, "sent"), row(939, 2, "sent")], 940, 935, None,),
            RetentionPageDecision::DeferredClockSkew
        );
        assert_eq!(
            classify_retention_page(&[row(935, 1, "sent")], 940, 935, None),
            RetentionPageDecision::DeferredClockSkew
        );
        assert_eq!(
            classify_retention_page(&[row(934, 1, "sent")], 940, 935, None),
            RetentionPageDecision::SafelyExpired
        );
    }

    #[test]
    fn unread_received_rows_defer_until_the_watermark_reaches_them() {
        let rows = [row(930, 1, "received")];
        assert_eq!(
            classify_retention_page(&rows, 940, 935, None),
            RetentionPageDecision::DeferredUnread
        );
        assert_eq!(
            classify_retention_page(&rows, 940, 935, Some(929)),
            RetentionPageDecision::DeferredUnread
        );
        assert_eq!(
            classify_retention_page(&rows, 940, 935, Some(930)),
            RetentionPageDecision::SafelyExpired
        );
    }

    #[test]
    fn empty_first_page_reports_no_expired_messages() {
        let mut scan = RetentionScanState::new(940, 935, None);
        assert_eq!(
            scan.observe_page(&page(Vec::new(), false)),
            RetentionScanAction::Complete(RetentionSweepStatus::NoExpiredMessages)
        );
    }

    #[test]
    fn safely_expired_rows_prune_after_the_scan_is_proven_complete() {
        let mut scan = RetentionScanState::new(940, 935, Some(934));
        assert_eq!(
            scan.observe_page(&page(vec![row(934, 1, "received")], false)),
            RetentionScanAction::Prune
        );
    }

    #[test]
    fn exact_page_cap_defers_without_pruning() {
        let mut scan = RetentionScanState::new(1_000, 995, None);
        for page_index in 0..RETENTION_SWEEP_MAX_PAGES {
            let timeline_at = 900 - page_index as u64;
            let rows = (0..RETENTION_SWEEP_TIMELINE_PAGE_LIMIT)
                .map(|offset| row(timeline_at, offset as u8, "sent"))
                .collect();
            let action = scan.observe_page(&page(rows, true));
            if page_index + 1 == RETENTION_SWEEP_MAX_PAGES {
                assert_eq!(
                    action,
                    RetentionScanAction::Complete(RetentionSweepStatus::DeferredScanExhausted)
                );
            } else {
                assert!(matches!(action, RetentionScanAction::Continue { .. }));
            }
        }
    }

    #[test]
    fn non_advancing_cursor_defers_without_pruning() {
        let mut scan = RetentionScanState::new(940, 935, None);
        scan.before = 930;
        scan.before_message_id = format!("{:064x}", 1);
        assert_eq!(
            scan.observe_page(&page(vec![row(930, 1, "sent")], true)),
            RetentionScanAction::Complete(RetentionSweepStatus::DeferredScanExhausted)
        );
    }

    #[test]
    fn inconsistent_has_more_page_defers_without_pruning() {
        let mut scan = RetentionScanState::new(940, 935, None);
        assert_eq!(
            scan.observe_page(&page(vec![row(930, 1, "sent")], true)),
            RetentionScanAction::Complete(RetentionSweepStatus::DeferredScanExhausted)
        );
    }

    #[test]
    fn full_pages_advance_the_cursor() {
        let mut scan = RetentionScanState::new(940, 935, None);
        let rows = (0..RETENTION_SWEEP_TIMELINE_PAGE_LIMIT)
            .map(|offset| row(934 - offset as u64, offset as u8, "sent"))
            .collect();
        assert_eq!(
            scan.observe_page(&page(rows, true)),
            RetentionScanAction::Continue {
                before: 735,
                before_message_id: format!("{:064x}", 199),
            }
        );
    }

    #[test]
    fn group_sweep_omits_disabled_groups_sorts_and_isolates_failures() {
        let inputs = vec![
            RetentionSweepGroupInput {
                group_id_hex: "cc".to_owned(),
                retention_seconds: Some(60),
                last_read_timeline_at: None,
            },
            RetentionSweepGroupInput {
                group_id_hex: "aa".to_owned(),
                retention_seconds: Some(0),
                last_read_timeline_at: None,
            },
            RetentionSweepGroupInput {
                group_id_hex: "bb".to_owned(),
                retention_seconds: Some(60),
                last_read_timeline_at: None,
            },
            RetentionSweepGroupInput {
                group_id_hex: "dd".to_owned(),
                retention_seconds: Some(60),
                last_read_timeline_at: None,
            },
        ];
        let outcomes = run_retention_group_sweeps(inputs, |input, _| {
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
