//! Optional fixed-schema progress for encrypted account opening; callbacks never receive private data.
/// Fixed phases of an encrypted store open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOpenPhase {
    CipherConfiguration,
    CipherKeyApplication,
    OperationalPragmas,
    MigrationInspection,
}
/// Numeric schema progress is available before and after each migration transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOpenProgress {
    Phase(StorageOpenPhase),
    MigrationStarted(u32),
    MigrationFinished { version: u32, success: bool },
}
/// Observation failures must never become storage failures or bypass migration rollback.
pub(crate) fn observe(
    observer: Option<&dyn Fn(StorageOpenProgress)>,
    progress: StorageOpenProgress,
) {
    if let Some(observer) = observer {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| observer(progress)));
    }
}
