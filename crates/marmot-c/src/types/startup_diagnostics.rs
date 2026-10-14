//! C mirrors for fixed native startup observations; arrays own their records.
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::conversions::*;
c_enum! {MarmotNativeStartupStage from NativeStartupStageFfi {AttachmentTaskQueued,AccountResolution,AccountStorageCache,StorageAdmission,DatabaseOpenLock,SigningKeys,ExternalDatabaseSecret,KeyDerivation,SaltRead,RecoveryProbe,RecoveryRekey,EncryptedStoreOpen,CipherConfiguration,CipherKeyApplication,OperationalPragmas,MigrationInspection,MigrationApply,AttachmentLocalRead,AttachmentFutureWait,ProductAnalyticsAdmission,}}
c_enum! {MarmotNativeStartupOutcome from NativeStartupOutcomeFfi {Active,Success,Failure,Abandoned,}}
c_mirror! {MarmotNativeStartupObservation from NativeStartupObservationFfi {
 copy token:u64,copy stage:MarmotNativeStartupStage,copy elapsed_ms:u64,copy stage_elapsed_ms:u64,
 opt_copy has_migration_version/migration_version:u32,copy migrations_completed:u32,copy outcome:MarmotNativeStartupOutcome,
}}
c_mirror! {MarmotNativeStartupSnapshot from NativeStartupSnapshotFfi, free marmot_native_startup_snapshot_free {
 copy enabled:bool,vec active/active_len:MarmotNativeStartupObservation,vec events/events_len:MarmotNativeStartupObservation,
 copy dropped_events:u64,copy dropped_scopes:u64,
}}
