//! Persisted per-account v5 audit delivery status: the last success, the last
//! typed failure, the pause after a receiver block, and the last measured
//! backlog. It lives beside the delivery cursor in its own small file, so the
//! cursor format can change independently and an over-limit cursor can still
//! be reported. Each tracker attempt records its outcome under its own audit
//! export admission, before releasing its reservation, so writes follow the
//! order of attempts.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use marmot_forensics::local_delivery::{
    DeliveryBacklog, LocalDeliveryFailure, classify_local_failure,
};
use marmot_observability::{AuditOtlpSender, system_time_ms};
use serde::{Deserialize, Serialize};

use crate::{
    AppError, AuditDeliveryBacklog, AuditDeliveryFailure, AuditDeliveryFailureKind,
    AuditDeliveryStatus, MarmotApp,
};

pub(crate) const AUDIT_DELIVERY_STATE_DIR: &str = "audit-otlp-delivery-v5";
const STATUS_FILE: &str = "delivery-status.json";
const STATUS_VERSION: u8 = 1;
const MAX_STATUS_BYTES: u64 = 64 * 1024;
/// A routine outcome (a delivered batch, an unchanged backlog) rewrites the
/// file at most this often while delivery is healthy.
const ROUTINE_WRITE_INTERVAL_MS: u64 = 10_000;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct StoredStatus {
    version: u8,
    destination: String,
    last_success_at_ms: Option<u64>,
    last_failure: Option<AuditDeliveryFailure>,
    consecutive_failures: u64,
    rejected_batches: u64,
    /// Fingerprint of the sender configuration the pause applies to.
    paused_for: Option<String>,
    backlog: Option<AuditDeliveryBacklog>,
    /// When the file was last written.
    #[serde(default)]
    updated_at_ms: u64,
}

/// The sender identity a tracker attempt records status for.
#[derive(Clone)]
pub(crate) struct AuditDeliveryStatusTarget {
    destination: String,
    fingerprint: String,
}

impl AuditDeliveryStatusTarget {
    pub(crate) fn new(sender: &AuditOtlpSender) -> Self {
        Self {
            destination: marmot_observability::wiring::audit_destination(sender).to_owned(),
            fingerprint: marmot_observability::wiring::audit_sender_fingerprint(sender),
        }
    }
}

/// What one delivery attempt observed.
#[derive(Debug, Default)]
pub(crate) struct AuditDeliveryObservation {
    delivered: bool,
    caught_up: bool,
    rejected: Option<u16>,
    failure: Option<(AuditDeliveryFailureKind, Option<u16>)>,
    stalled_on_rejection: bool,
    backlog: Option<DeliveryBacklog>,
}

impl AuditDeliveryObservation {
    pub(crate) fn delivered(&mut self) {
        self.delivered = true;
    }

    /// Nothing is left to deliver.
    pub(crate) fn caught_up(&mut self) {
        self.caught_up = true;
    }

    pub(crate) fn rejected(&mut self, http_status: u16) {
        self.rejected = Some(http_status);
    }

    pub(crate) fn failed(&mut self, kind: AuditDeliveryFailureKind, http_status: Option<u16>) {
        self.failure = Some((kind, http_status));
    }

    /// Delivery found only journals a receiver verdict blocked. It reports
    /// the receiver's rejection, not a local fault.
    pub(crate) fn stalled_on_rejection(&mut self) {
        self.stalled_on_rejection = true;
    }

    pub(crate) fn observed(&mut self, backlog: DeliveryBacklog) {
        self.backlog = Some(backlog);
    }

    /// The failure to log, including a rejection delivery continues past.
    pub(crate) fn logged_failure(&self) -> Option<(AuditDeliveryFailureKind, Option<u16>)> {
        self.failure
            .or(if self.rejected.is_some() || self.stalled_on_rejection {
                Some((AuditDeliveryFailureKind::ReceiverRejected, self.rejected))
            } else {
                None
            })
    }

    fn notable(&self) -> bool {
        self.caught_up
            || self.rejected.is_some()
            || self.failure.is_some()
            || self.stalled_on_rejection
    }
}

pub(crate) fn audit_delivery_state_dir(app: &MarmotApp, account_label: &str) -> PathBuf {
    app.account_dir(account_label)
        .join(AUDIT_DELIVERY_STATE_DIR)
}

/// Classify an attempt error into a host-actionable failure kind.
pub(crate) fn classify_attempt_error(error: &AppError) -> AuditDeliveryFailureKind {
    match error {
        AppError::Io(error) => match classify_local_failure(error) {
            LocalDeliveryFailure::StateOverLimit => AuditDeliveryFailureKind::StateOverLimit,
            LocalDeliveryFailure::TooManyOpenFiles => AuditDeliveryFailureKind::TooManyOpenFiles,
            LocalDeliveryFailure::Io => AuditDeliveryFailureKind::LocalIo,
        },
        _ => AuditDeliveryFailureKind::Internal,
    }
}

/// Whether automatic delivery is paused for this account and sender.
pub(crate) fn audit_delivery_paused(
    app: &MarmotApp,
    account_label: &str,
    sender: &AuditOtlpSender,
) -> bool {
    let stored = load(
        &audit_delivery_state_dir(app, account_label),
        Some(marmot_observability::wiring::audit_destination(sender)),
    );
    is_paused(&stored, Some(sender))
}

/// Fold one attempt's observation into the persisted status. The caller
/// holds the attempt's audit export admission. Status is advisory: a failed
/// write is logged and never fails the attempt it describes.
pub(crate) fn record_observation(
    target: Option<&AuditDeliveryStatusTarget>,
    state_dir: &Path,
    observation: &AuditDeliveryObservation,
) {
    let Some(target) = target else {
        return;
    };
    if let Err(error) = record(target, state_dir, observation, now_ms()) {
        tracing::warn!(
            target: "marmot_app::audit_log",
            method = "record_observation",
            error_kind = error.privacy_safe_kind(),
            "failed to persist v5 audit delivery status"
        );
    }
}

fn record(
    target: &AuditDeliveryStatusTarget,
    state_dir: &Path,
    observation: &AuditDeliveryObservation,
    now_ms: u64,
) -> Result<(), AppError> {
    let mut stored = load(state_dir, Some(&target.destination));
    let routine = !observation.notable()
        && stored.updated_at_ms != 0
        && stored.consecutive_failures == 0
        && stored.paused_for.is_none()
        && now_ms.saturating_sub(stored.updated_at_ms) < ROUTINE_WRITE_INTERVAL_MS;
    if routine {
        return Ok(());
    }
    apply(&mut stored, observation, now_ms, &target.fingerprint);
    store(state_dir, &stored)
}

pub(crate) fn audit_delivery_status_for_app(
    app: &MarmotApp,
    sender: Option<&AuditOtlpSender>,
) -> Result<Vec<AuditDeliveryStatus>, AppError> {
    let destination = sender.map(marmot_observability::wiring::audit_destination);
    Ok(app
        .account_home()
        .accounts()?
        .into_iter()
        .map(|account| {
            let stored = load(&audit_delivery_state_dir(app, &account.label), destination);
            AuditDeliveryStatus {
                account_ref: account.label,
                destination_configured: sender.is_some(),
                paused: is_paused(&stored, sender),
                last_success_at_ms: stored.last_success_at_ms,
                last_failure: stored.last_failure,
                consecutive_failures: stored.consecutive_failures,
                rejected_batches: stored.rejected_batches,
                backlog: stored.backlog,
            }
        })
        .collect())
}

fn is_paused(stored: &StoredStatus, sender: Option<&AuditOtlpSender>) -> bool {
    sender.is_some_and(|sender| {
        stored.paused_for.as_deref()
            == Some(marmot_observability::wiring::audit_sender_fingerprint(sender).as_str())
    })
}

/// Only an attempt that delivered (or found nothing left) lifts a pause; a
/// receiver block sets it. Other failures leave it as it was.
fn apply(
    stored: &mut StoredStatus,
    observation: &AuditDeliveryObservation,
    now_ms: u64,
    fingerprint: &str,
) {
    stored.updated_at_ms = now_ms;
    if let Some(backlog) = observation.backlog {
        stored.backlog = Some(AuditDeliveryBacklog {
            undelivered_bytes: backlog.undelivered_bytes,
            undelivered_segments: backlog.undelivered_segments,
            gaps: backlog.gaps,
            oldest_undelivered_at_ms: backlog.oldest_undelivered_wall_time_ms,
            observed_at_ms: now_ms,
        });
    }
    if let Some(http_status) = observation.rejected {
        stored.rejected_batches = stored.rejected_batches.saturating_add(1);
        stored.last_failure = Some(AuditDeliveryFailure {
            kind: AuditDeliveryFailureKind::ReceiverRejected,
            http_status: Some(http_status),
            at_ms: now_ms,
        });
    }
    // A journal still blocked by an earlier rejection keeps reporting that
    // rejection, with its HTTP status, rather than a local fault.
    if observation.stalled_on_rejection
        && stored
            .last_failure
            .as_ref()
            .is_none_or(|failure| failure.kind != AuditDeliveryFailureKind::ReceiverRejected)
    {
        stored.last_failure = Some(AuditDeliveryFailure {
            kind: AuditDeliveryFailureKind::ReceiverRejected,
            http_status: None,
            at_ms: now_ms,
        });
    }
    let progressed = observation.delivered || observation.caught_up;
    if progressed {
        stored.last_success_at_ms = Some(now_ms);
    }
    if let Some((kind, http_status)) = observation.failure {
        stored.last_failure = Some(AuditDeliveryFailure {
            kind,
            http_status,
            at_ms: now_ms,
        });
        stored.consecutive_failures = stored.consecutive_failures.saturating_add(1);
        if kind == AuditDeliveryFailureKind::ReceiverBlocked {
            stored.paused_for = Some(fingerprint.to_owned());
        }
    } else if observation.rejected.is_some() || observation.stalled_on_rejection {
        stored.consecutive_failures = stored.consecutive_failures.saturating_add(1);
    } else if progressed {
        stored.consecutive_failures = 0;
        stored.paused_for = None;
    }
}

/// A missing, unreadable, or malformed file, or one for another destination,
/// reads as a fresh status.
fn load(state_dir: &Path, destination: Option<&str>) -> StoredStatus {
    let read = || -> Option<StoredStatus> {
        let mut bytes = Vec::new();
        std::fs::File::open(state_dir.join(STATUS_FILE))
            .ok()?
            .take(MAX_STATUS_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_STATUS_BYTES {
            return None;
        }
        serde_json::from_slice::<StoredStatus>(&bytes)
            .ok()
            .filter(|stored| stored.version == STATUS_VERSION)
            .filter(|stored| {
                destination.is_none_or(|destination| stored.destination == destination)
            })
    };
    read().unwrap_or_else(|| StoredStatus {
        version: STATUS_VERSION,
        destination: destination.unwrap_or_default().to_owned(),
        ..StoredStatus::default()
    })
}

/// Staged owner-only and renamed into place, so a crash keeps the previous status.
fn store(state_dir: &Path, stored: &StoredStatus) -> Result<(), AppError> {
    #[cfg(unix)]
    fs_private::prepare_directory_path(
        state_dir,
        0o700,
        fs_private::ExistingDirectoryMode::Enforce,
    )?;
    #[cfg(not(unix))]
    fs_private::create_dir_all_private(state_dir)?;
    let path = state_dir.join(STATUS_FILE);
    let staged = state_dir.join(format!("{STATUS_FILE}.tmp"));
    fs_private::write_private(&staged, &serde_json::to_vec(stored)?)?;
    // `rename` replaces the target on Windows too (`MoveFileExW`).
    if let Err(error) = std::fs::rename(&staged, &path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error.into());
    }
    #[cfg(unix)]
    std::fs::File::open(state_dir)?.sync_all()?;
    Ok(())
}

fn now_ms() -> u64 {
    system_time_ms(SystemTime::now()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(edit: impl FnOnce(&mut AuditDeliveryObservation)) -> AuditDeliveryObservation {
        let mut observation = AuditDeliveryObservation::default();
        edit(&mut observation);
        observation
    }

    fn target() -> AuditDeliveryStatusTarget {
        AuditDeliveryStatusTarget::new(
            &AuditOtlpSender::new("audit", "https://collector.example/v1/logs", "token").unwrap(),
        )
    }

    #[test]
    fn only_success_lifts_a_pause_and_a_rejection_stall_keeps_its_status() {
        let dir = tempfile::tempdir().unwrap();
        let target = target();
        let record_at = |at: u64, observation: AuditDeliveryObservation| {
            record(&target, dir.path(), &observation, at).unwrap();
            load(dir.path(), Some("audit"))
        };
        record_at(1, observation(|o| o.rejected(400)));
        let stored = record_at(
            2,
            observation(AuditDeliveryObservation::stalled_on_rejection),
        );
        assert!(stored.paused_for.is_none());
        let failure = stored.last_failure.unwrap();
        assert_eq!(failure.kind, AuditDeliveryFailureKind::ReceiverRejected);
        assert_eq!(failure.http_status, Some(400));
        assert_eq!(stored.consecutive_failures, 2);
        assert_eq!(stored.rejected_batches, 1);

        record_at(
            3,
            observation(|o| o.failed(AuditDeliveryFailureKind::ReceiverBlocked, Some(401))),
        );
        for (at, observation) in [
            (
                4,
                observation(AuditDeliveryObservation::stalled_on_rejection),
            ),
            (
                5,
                observation(|o| o.failed(AuditDeliveryFailureKind::LocalIo, None)),
            ),
            (
                6,
                observation(|o| o.failed(AuditDeliveryFailureKind::ReceiverRetryable, Some(503))),
            ),
        ] {
            assert!(
                record_at(at, observation).paused_for.is_some(),
                "an attempt at {at} that delivered nothing must not lift the pause"
            );
        }
        let stored = record_at(7, observation(AuditDeliveryObservation::delivered));
        assert!(stored.paused_for.is_none());
        assert_eq!(stored.consecutive_failures, 0);
        assert_eq!(stored.last_success_at_ms, Some(7));
    }

    #[test]
    fn routine_outcomes_rewrite_the_status_at_most_once_per_interval_while_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let target = target();
        let backlog = |bytes| DeliveryBacklog {
            undelivered_bytes: bytes,
            ..DeliveryBacklog::default()
        };
        let delivered = |bytes| {
            observation(|o| {
                o.delivered();
                o.observed(backlog(bytes));
            })
        };
        record(&target, dir.path(), &delivered(300), 1_000).unwrap();
        record(&target, dir.path(), &delivered(200), 2_000).unwrap();
        let stored = load(dir.path(), Some("audit"));
        assert_eq!(stored.backlog.unwrap().undelivered_bytes, 300);
        record(
            &target,
            dir.path(),
            &delivered(100),
            1_000 + ROUTINE_WRITE_INTERVAL_MS,
        )
        .unwrap();
        assert_eq!(
            load(dir.path(), Some("audit"))
                .backlog
                .unwrap()
                .undelivered_bytes,
            100
        );
        // Catching up is always written, so the backlog never reads stale
        // once delivery has drained it.
        record(
            &target,
            dir.path(),
            &observation(|o| {
                o.caught_up();
                o.observed(backlog(0));
            }),
            1_001 + ROUTINE_WRITE_INTERVAL_MS,
        )
        .unwrap();
        assert_eq!(
            load(dir.path(), Some("audit"))
                .backlog
                .unwrap()
                .undelivered_bytes,
            0
        );
    }
}
