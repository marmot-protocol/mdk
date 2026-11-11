//! Persisted per-account v5 audit delivery status: the last success, the last
//! typed failure, the pause after a receiver block, and the last measured
//! backlog. It lives beside the delivery cursor in its own small file, so the
//! cursor format can change independently and an over-limit cursor can still
//! be reported.

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
}

/// What one tracker pass observed for one account.
#[derive(Debug, Default)]
pub(crate) struct AuditDeliveryPass {
    progressed: bool,
    rejected: Option<u16>,
    rejected_batches: u64,
    failure: Option<(AuditDeliveryFailureKind, Option<u16>)>,
    backlog: Option<DeliveryBacklog>,
}

impl AuditDeliveryPass {
    /// A batch was accepted or nothing was left to deliver.
    pub(crate) fn progressed(&mut self) {
        self.progressed = true;
    }

    pub(crate) fn rejected(&mut self, http_status: u16) {
        self.rejected = Some(http_status);
        self.rejected_batches += 1;
    }

    pub(crate) fn failed(&mut self, kind: AuditDeliveryFailureKind, http_status: Option<u16>) {
        self.failure = Some((kind, http_status));
    }

    pub(crate) fn observed(&mut self, backlog: Option<DeliveryBacklog>) {
        if backlog.is_some() {
            self.backlog = backlog;
        }
    }

    /// The failure to log, including a rejection the pass continued past.
    pub(crate) fn logged_failure(&self) -> Option<(AuditDeliveryFailureKind, Option<u16>)> {
        self.failure.or(self
            .rejected
            .map(|status| (AuditDeliveryFailureKind::ReceiverRejected, Some(status))))
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.progressed
            && self.rejected.is_none()
            && self.failure.is_none()
            && self.backlog.is_none()
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

/// Fold one pass into the persisted status. The caller holds the account's
/// audit export admission, so this never races cursor work or deletion.
pub(crate) fn record_pass(
    state_dir: &Path,
    sender: &AuditOtlpSender,
    pass: &AuditDeliveryPass,
) -> Result<(), AppError> {
    if pass.is_empty() {
        return Ok(());
    }
    let destination = marmot_observability::wiring::audit_destination(sender);
    let mut stored = load(state_dir, Some(destination));
    apply(
        &mut stored,
        pass,
        now_ms(),
        marmot_observability::wiring::audit_sender_fingerprint(sender),
    );
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

fn apply(stored: &mut StoredStatus, pass: &AuditDeliveryPass, now_ms: u64, fingerprint: String) {
    if let Some(backlog) = pass.backlog {
        stored.backlog = Some(AuditDeliveryBacklog {
            undelivered_bytes: backlog.undelivered_bytes,
            undelivered_segments: backlog.undelivered_segments,
            gaps: backlog.gaps,
            oldest_undelivered_at_ms: backlog.oldest_undelivered_wall_time_ms,
            observed_at_ms: now_ms,
        });
    }
    if let Some(http_status) = pass.rejected {
        stored.rejected_batches = stored
            .rejected_batches
            .saturating_add(pass.rejected_batches);
        stored.last_failure = Some(AuditDeliveryFailure {
            kind: AuditDeliveryFailureKind::ReceiverRejected,
            http_status: Some(http_status),
            at_ms: now_ms,
        });
    }
    if pass.progressed {
        stored.last_success_at_ms = Some(now_ms);
    }
    if let Some((kind, http_status)) = pass.failure {
        stored.last_failure = Some(AuditDeliveryFailure {
            kind,
            http_status,
            at_ms: now_ms,
        });
        stored.consecutive_failures = stored.consecutive_failures.saturating_add(1);
        stored.paused_for =
            (kind == AuditDeliveryFailureKind::ReceiverBlocked).then_some(fingerprint);
    } else if pass.progressed {
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
    if let Err(error) = std::fs::rename(&staged, &path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error.into());
    }
    Ok(())
}

fn now_ms() -> u64 {
    system_time_ms(SystemTime::now()).unwrap_or(0)
}
