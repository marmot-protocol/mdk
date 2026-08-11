//! Stable aggregate measurements for adversarial campaign reports.

use crate::{ScenarioInputDisposition, ScenarioReport, ScenarioStepStatus};
use cgka_engine::engine_metrics::{EngineMetricsSnapshot, HistogramSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignMeasurementsV1 {
    pub schema_version: String,
    pub total_wall_us: u64,
    pub convergence_latency_us: Option<u64>,
    pub blocked_send_duration_us: u64,
    pub pass_count: usize,
    pub reorg_count: Option<usize>,
    pub reorg_rewind_depth: Option<CampaignHistogramV1>,
    pub reorg_lateness_ms: Option<CampaignHistogramV1>,
    pub unresolved_outcomes: usize,
    pub max_observed_queue_depth: usize,
    pub input_dispositions: BTreeMap<String, usize>,
    pub logical_deliveries: usize,
    pub logical_expirations: usize,
    pub logical_invalidations: usize,
    pub replay_probe_count: Option<u64>,
    pub database_bytes: Option<u64>,
    pub first_failing_action: Option<usize>,
    pub limiting_resource: Option<String>,
    pub steps: Vec<CampaignStepMeasurementV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable_process_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignStepMeasurementV1 {
    pub step_index: usize,
    pub step_type: String,
    pub wall_us: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignHistogramV1 {
    pub buckets: Vec<CampaignHistogramBucketV1>,
    pub overflow_count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignHistogramBucketV1 {
    pub upper_bound: u64,
    pub count: u64,
}

impl From<&HistogramSnapshot> for CampaignHistogramV1 {
    fn from(snapshot: &HistogramSnapshot) -> Self {
        Self {
            buckets: snapshot
                .buckets
                .iter()
                .map(|bucket| CampaignHistogramBucketV1 {
                    upper_bound: bucket.upper_bound,
                    count: bucket.count,
                })
                .collect(),
            overflow_count: snapshot.overflow_count,
        }
    }
}

impl CampaignMeasurementsV1 {
    pub(crate) fn from_report(
        report: &ScenarioReport,
        total_wall_us: u64,
        database_bytes: Option<u64>,
        sampled_max_queue_depth: usize,
        replay_probe_count: Option<u64>,
        engine_metrics: Option<&EngineMetricsSnapshot>,
    ) -> Self {
        let mut latest_by_client = BTreeMap::new();
        if let Some(trace) = &report.observed_trace {
            for observation in &trace.observations {
                latest_by_client.insert(observation.client.as_str(), observation);
            }
        }

        let mut input_dispositions = BTreeMap::new();
        let mut logical_deliveries = 0;
        let mut logical_expirations = 0;
        let mut logical_invalidations = 0;
        let mut blocked_send_duration_us = 0_u64;
        let mut unresolved_outcomes = 0;
        let mut max_observed_queue_depth = 0;
        let mut pass_count = 0_usize;
        for observation in latest_by_client.values() {
            for entry in &observation.scenario_input_ledger {
                *input_dispositions
                    .entry(disposition_label(&entry.disposition).to_owned())
                    .or_default() += 1;
                logical_deliveries += entry.delivered;
                logical_expirations += entry.expired;
                logical_invalidations += entry.invalidated.len();
                unresolved_outcomes += usize::from(entry.pending);
                blocked_send_duration_us =
                    blocked_send_duration_us.saturating_add(entry.blocked_send_duration_us);
            }
            if let Some(pending) = &observation.pending_work {
                max_observed_queue_depth = max_observed_queue_depth.max(
                    pending
                        .bus_queued_messages
                        .saturating_add(pending.bus_delayed_messages)
                        .saturating_add(pending.bus_mailbox_messages),
                );
            }
            pass_count = pass_count.saturating_add(observation.convergence_decisions.len());
        }

        let convergence_latency_us = report
            .quiescence_observations
            .iter()
            .rev()
            .find(|observation| observation.status.is_quiescent())
            .and_then(|observation| {
                report
                    .step_log
                    .iter()
                    .find(|step| step.step_index == observation.step_index)
                    .map(|step| step.wall_us)
            });

        let first_failing_action = report.step_log.iter().find_map(|step| {
            matches!(step.status, ScenarioStepStatus::Failed { .. }).then_some(step.step_index)
        });
        let limiting_resource = report
            .expectation_failures
            .iter()
            .find(|failure| failure.kind == "pending_work_remaining")
            .map(|failure| failure.message.clone())
            .or_else(|| {
                report.step_log.iter().find_map(|step| match &step.status {
                    ScenarioStepStatus::Failed {
                        kind,
                        category: crate::SubjectFailureCategory::Resource,
                        message,
                    } => Some(format!("{kind}: {message}")),
                    _ => None,
                })
            });

        Self {
            schema_version: "1".into(),
            total_wall_us,
            convergence_latency_us,
            blocked_send_duration_us,
            pass_count,
            reorg_count: engine_metrics
                .and_then(|metrics| usize::try_from(metrics.post_settle_reorgs).ok()),
            reorg_rewind_depth: engine_metrics
                .map(|metrics| CampaignHistogramV1::from(&metrics.reorg_rewind_depth)),
            reorg_lateness_ms: engine_metrics
                .map(|metrics| CampaignHistogramV1::from(&metrics.reorg_lateness_ms)),
            unresolved_outcomes,
            max_observed_queue_depth: max_observed_queue_depth.max(sampled_max_queue_depth),
            input_dispositions,
            logical_deliveries,
            logical_expirations,
            logical_invalidations,
            replay_probe_count,
            database_bytes,
            first_failing_action,
            limiting_resource,
            steps: report
                .step_log
                .iter()
                .map(|step| CampaignStepMeasurementV1 {
                    step_index: step.step_index,
                    step_type: step.step_type.clone(),
                    wall_us: step.wall_us,
                })
                .collect(),
            unavailable_process_fields: [
                "cpu_time_us".to_owned(),
                "peak_rss_bytes".to_owned(),
                "filesystem_block_write_lower_bound_bytes".to_owned(),
            ]
            .into_iter()
            .chain(
                database_bytes
                    .is_none()
                    .then(|| "database_bytes".to_owned()),
            )
            .chain(
                convergence_latency_us
                    .is_none()
                    .then(|| "convergence_latency_us".to_owned()),
            )
            .collect(),
        }
    }
}

fn disposition_label(disposition: &ScenarioInputDisposition) -> &'static str {
    match disposition {
        ScenarioInputDisposition::Pending => "pending",
        ScenarioInputDisposition::Deferred => "deferred",
        ScenarioInputDisposition::Accepted => "accepted",
        ScenarioInputDisposition::Delivered => "delivered",
        ScenarioInputDisposition::Deduplicated => "deduplicated",
        ScenarioInputDisposition::Expired => "expired",
        ScenarioInputDisposition::Invalidated => "invalidated",
        ScenarioInputDisposition::Rejected => "rejected",
        ScenarioInputDisposition::Stale => "stale",
        ScenarioInputDisposition::Ignored => "ignored",
        ScenarioInputDisposition::ResourceRefused => "resource_refused",
        ScenarioInputDisposition::RolledBack => "rolled_back",
    }
}
