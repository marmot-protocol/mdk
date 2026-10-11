//! Fixed native startup diagnostics; no identifier, path or error-string fields.
/// Fixed stage labels for opt-in native startup capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NativeStartupStageFfi {
    AttachmentTaskQueued,
    AccountResolution,
    AccountStorageCache,
    StorageAdmission,
    DatabaseOpenLock,
    SigningKeys,
    ExternalDatabaseSecret,
    KeyDerivation,
    SaltRead,
    RecoveryProbe,
    RecoveryRekey,
    EncryptedStoreOpen,
    CipherConfiguration,
    CipherKeyApplication,
    OperationalPragmas,
    MigrationInspection,
    MigrationApply,
    AttachmentLocalRead,
    AttachmentFutureWait,
    ProductAnalyticsAdmission,
}
impl From<marmot_app::NativeStartupStage> for NativeStartupStageFfi {
    /// Map the closed native stage set exhaustively, without deriving labels from operation inputs.
    fn from(value: marmot_app::NativeStartupStage) -> Self {
        match value {
            marmot_app::NativeStartupStage::AttachmentTaskQueued => Self::AttachmentTaskQueued,
            marmot_app::NativeStartupStage::AccountResolution => Self::AccountResolution,
            marmot_app::NativeStartupStage::AccountStorageCache => Self::AccountStorageCache,
            marmot_app::NativeStartupStage::StorageAdmission => Self::StorageAdmission,
            marmot_app::NativeStartupStage::DatabaseOpenLock => Self::DatabaseOpenLock,
            marmot_app::NativeStartupStage::SigningKeys => Self::SigningKeys,
            marmot_app::NativeStartupStage::ExternalDatabaseSecret => Self::ExternalDatabaseSecret,
            marmot_app::NativeStartupStage::KeyDerivation => Self::KeyDerivation,
            marmot_app::NativeStartupStage::SaltRead => Self::SaltRead,
            marmot_app::NativeStartupStage::RecoveryProbe => Self::RecoveryProbe,
            marmot_app::NativeStartupStage::RecoveryRekey => Self::RecoveryRekey,
            marmot_app::NativeStartupStage::EncryptedStoreOpen => Self::EncryptedStoreOpen,
            marmot_app::NativeStartupStage::CipherConfiguration => Self::CipherConfiguration,
            marmot_app::NativeStartupStage::CipherKeyApplication => Self::CipherKeyApplication,
            marmot_app::NativeStartupStage::OperationalPragmas => Self::OperationalPragmas,
            marmot_app::NativeStartupStage::MigrationInspection => Self::MigrationInspection,
            marmot_app::NativeStartupStage::MigrationApply => Self::MigrationApply,
            marmot_app::NativeStartupStage::AttachmentLocalRead => Self::AttachmentLocalRead,
            marmot_app::NativeStartupStage::AttachmentFutureWait => Self::AttachmentFutureWait,
            marmot_app::NativeStartupStage::ProductAnalyticsAdmission => {
                Self::ProductAnalyticsAdmission
            }
        }
    }
}
/// Fixed outcome labels for opt-in native startup capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum NativeStartupOutcomeFfi {
    Active,
    Success,
    Failure,
    Abandoned,
}
impl From<marmot_app::NativeStartupOutcome> for NativeStartupOutcomeFfi {
    /// Preserve cancellation versus explicit success/failure across the binding boundary.
    fn from(value: marmot_app::NativeStartupOutcome) -> Self {
        match value {
            marmot_app::NativeStartupOutcome::Active => Self::Active,
            marmot_app::NativeStartupOutcome::Success => Self::Success,
            marmot_app::NativeStartupOutcome::Failure => Self::Failure,
            marmot_app::NativeStartupOutcome::Abandoned => Self::Abandoned,
        }
    }
}
/// Bounded anonymous progress for one operation, including its current migration number.
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeStartupObservationFfi {
    pub token: u64,
    pub stage: NativeStartupStageFfi,
    pub elapsed_ms: u64,
    pub stage_elapsed_ms: u64,
    pub migration_version: Option<u32>,
    pub migrations_completed: u32,
    pub outcome: NativeStartupOutcomeFfi,
}
impl From<marmot_app::NativeStartupObservation> for NativeStartupObservationFfi {
    /// Transfer anonymous timings and numeric schema progress without consulting an account store.
    fn from(v: marmot_app::NativeStartupObservation) -> Self {
        Self {
            token: v.token,
            stage: v.stage.into(),
            elapsed_ms: v.elapsed_ms,
            stage_elapsed_ms: v.stage_elapsed_ms,
            migration_version: v.migration_version,
            migrations_completed: v.migrations_completed,
            outcome: v.outcome.into(),
        }
    }
}
/// At most 16 active observations and 96 historical entries, independent of database locks.
#[derive(Clone, Debug, uniffi::Record)]
pub struct NativeStartupSnapshotFfi {
    pub enabled: bool,
    pub active: Vec<NativeStartupObservationFfi>,
    pub events: Vec<NativeStartupObservationFfi>,
    pub dropped_events: u64,
    pub dropped_scopes: u64,
}
impl From<marmot_app::NativeStartupSnapshot> for NativeStartupSnapshotFfi {
    /// Move the already-bounded arrays and omission counters into an owned host snapshot.
    fn from(v: marmot_app::NativeStartupSnapshot) -> Self {
        Self {
            enabled: v.enabled,
            active: v.active.into_iter().map(Into::into).collect(),
            events: v.events.into_iter().map(Into::into).collect(),
            dropped_events: v.dropped_events,
            dropped_scopes: v.dropped_scopes,
        }
    }
}
