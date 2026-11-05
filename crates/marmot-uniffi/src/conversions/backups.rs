//! Backup setup and ephemeral manual-restore host records.

use marmot_app::{
    BackgroundBackupOutcome, BackupHistoryAvailability, BackupRestorePhase, BackupRestoreStatus,
    BackupSettings, RecoveryWords,
};

/// Shown once. Hosts must clear their own managed copies after confirmation
/// or cancellation; generated strings are not a secure-buffer API.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct RecoveryWordsFfi {
    pub words: Vec<String>,
    /// The two 1-based positions to confirm, in ascending order.
    pub confirm_positions: Vec<u32>,
}

impl std::fmt::Debug for RecoveryWordsFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryWordsFfi")
            .field("confirm_positions", &self.confirm_positions)
            .finish_non_exhaustive()
    }
}
impl From<RecoveryWords> for RecoveryWordsFfi {
    fn from(value: RecoveryWords) -> Self {
        Self {
            words: value.words,
            confirm_positions: value.confirm_positions,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupSettingsFfi {
    pub enabled: bool,
    pub this_device_writes: bool,
}
impl From<BackupSettings> for BackupSettingsFfi {
    fn from(value: BackupSettings) -> Self {
        Self {
            enabled: value.enabled,
            this_device_writes: value.this_device_writes,
        }
    }
}

/// Completion of one existing or newly admitted due pass, not a publication receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackgroundBackupOutcomeFfi {
    NotStarted,
    FinishedAttempt,
}
impl From<BackgroundBackupOutcome> for BackgroundBackupOutcomeFfi {
    fn from(value: BackgroundBackupOutcome) -> Self {
        match value {
            BackgroundBackupOutcome::NotStarted => Self::NotStarted,
            BackgroundBackupOutcome::FinishedAttempt => Self::FinishedAttempt,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BackupRestorePhaseFfi {
    Idle,
    Discovering,
    Restoring,
    Complete,
    Partial,
    Unavailable,
    Cancelled,
}
impl From<BackupRestorePhase> for BackupRestorePhaseFfi {
    fn from(value: BackupRestorePhase) -> Self {
        match value {
            BackupRestorePhase::Idle => Self::Idle,
            BackupRestorePhase::Discovering => Self::Discovering,
            BackupRestorePhase::Restoring => Self::Restoring,
            BackupRestorePhase::Complete => Self::Complete,
            BackupRestorePhase::Partial => Self::Partial,
            BackupRestorePhase::Unavailable => Self::Unavailable,
            BackupRestorePhase::Cancelled => Self::Cancelled,
        }
    }
}

/// Aggregate facts, never words, keys, content or a restore receipt.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupRestoreStatusFfi {
    pub operation: Option<String>,
    pub phase: BackupRestorePhaseFfi,
    pub imported_bundles: u64,
    pub imported_events: u64,
    pub failed_archives: u64,
    pub failed_bundles: u64,
    pub skipped_bundles: u64,
    pub revision: u64,
}
impl From<BackupRestoreStatus> for BackupRestoreStatusFfi {
    fn from(value: BackupRestoreStatus) -> Self {
        Self {
            operation: value.operation.map(|id| id.to_hex()),
            phase: value.phase.into(),
            imported_bundles: value.imported_bundles,
            imported_events: value.imported_events,
            failed_archives: value.failed_archives,
            failed_bundles: value.failed_bundles,
            skipped_bundles: value.skipped_bundles,
            revision: value.revision,
        }
    }
}

/// Private availability metadata for a current chat, not proof that any
/// blob remains downloadable or that account history is complete.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BackupHistoryAvailabilityFfi {
    pub recovery_public_key_hex: String,
    pub newest_written_at: u64,
    pub backups: u32,
}
impl From<BackupHistoryAvailability> for BackupHistoryAvailabilityFfi {
    fn from(value: BackupHistoryAvailability) -> Self {
        Self {
            recovery_public_key_hex: hex::encode(value.recovery_public_key),
            newest_written_at: value.newest_written_at,
            backups: value.backups,
        }
    }
}
