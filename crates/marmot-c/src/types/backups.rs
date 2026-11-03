//! C-owned backup setup, status and availability records.
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::conversions::{
    BackupHistoryAvailabilityFfi, BackupRestorePhaseFfi, BackupRestoreStatusFfi, BackupSettingsFfi,
    RecoveryWordsFfi,
};

c_mirror! {
    /// Shown-once recovery words. Clear host copies and promptly free this
    /// record; ordinary managed/FFI strings are not secure buffers.
    MarmotRecoveryWords from RecoveryWordsFfi,
    free marmot_recovery_words_free {
        str_vec words/words_len,
        vec confirm_positions/confirm_positions_len: u32,
    }
}
c_mirror! {
    /// Current account backup settings, not a publication receipt.
    MarmotBackupSettings from BackupSettingsFfi,
    free marmot_backup_settings_free {
        copy enabled: bool,
        copy this_device_writes: bool,
    }
}
c_enum! {
    /// Aggregate operation phase. Complete does not prove global recovery or
    /// that a pointer existed; render committed-prefix counts independently.
    MarmotBackupRestorePhase from BackupRestorePhaseFfi {
        Idle, Discovering, Restoring, Complete, Partial, Unavailable, Cancelled
    }
}
c_mirror! {
    /// Aggregate operation facts. No words, key, content or membership proof.
    MarmotBackupRestoreStatus from BackupRestoreStatusFfi,
    free marmot_backup_restore_status_free {
        opt_str operation,
        copy phase: MarmotBackupRestorePhase,
        copy imported_bundles: u64,
        copy imported_events: u64,
        copy failed_archives: u64,
        copy failed_bundles: u64,
        copy skipped_bundles: u64,
        copy revision: u64,
    }
}
c_mirror! {
    /// Private words-again hint for an actual current chat, not download proof.
    MarmotBackupHistoryAvailability from BackupHistoryAvailabilityFfi,
    list(MarmotBackupHistoryAvailabilityList, marmot_backup_history_availability_list_free) {
        str recovery_public_key_hex,
        copy newest_written_at: u64,
        copy backups: u32,
    }
}

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed};
    #[test]
    fn backup_outputs_deep_free_words_status_and_private_availability() {
        let _lock = audit::test_lock();
        let before = audit::live_allocations();
        let words = boxed(MarmotRecoveryWords::from(RecoveryWordsFfi {
            words: std::iter::repeat_n("abandon".to_owned(), 11)
                .chain(["about".into()])
                .collect(),
            confirm_positions: vec![1, 12],
        }));
        let status = boxed(MarmotBackupRestoreStatus::from(BackupRestoreStatusFfi {
            operation: Some("ab".repeat(16)),
            phase: BackupRestorePhaseFfi::Partial,
            imported_bundles: 1,
            imported_events: 7,
            failed_archives: 2,
            failed_bundles: 3,
            skipped_bundles: 4,
            revision: 9,
        }));
        let hints = boxed(MarmotBackupHistoryAvailabilityList::from(vec![
            BackupHistoryAvailabilityFfi {
                recovery_public_key_hex: "cd".repeat(32),
                newest_written_at: 17,
                backups: 2,
            },
        ]));
        use crate::types::history_import::MarmotHistoryImportProvenance;
        use marmot_uniffi::conversions::{BackupHistorySourceFfi, HistoryImportProvenanceFfi};
        let device = boxed(MarmotHistoryImportProvenance::from(
            HistoryImportProvenanceFfi::Device {
                device_slot_id_hex: "11".repeat(32),
            },
        ));
        let backup = boxed(MarmotHistoryImportProvenance::from(
            HistoryImportProvenanceFfi::Backup {
                source: BackupHistorySourceFfi {
                    recovery_public_key_hex: "22".repeat(32),
                    backup_id_hex: "33".repeat(16),
                    head_sha256_hex: "44".repeat(32),
                    written_at: 27,
                },
            },
        ));
        unsafe {
            assert!(
                matches!(&*device, MarmotHistoryImportProvenance::Device { device_slot_id_hex }
                if std::ffi::CStr::from_ptr(*device_slot_id_hex).to_str().unwrap() == "11".repeat(32))
            );
            assert!(
                matches!(&*backup, MarmotHistoryImportProvenance::Backup { source }
                if source.written_at == 27 && std::ffi::CStr::from_ptr(source.backup_id_hex).to_str().unwrap() == "33".repeat(16))
            );
            // Same free_boxed/CFree boundary used by the parent's opt_rec.
            crate::memory::free_boxed(device);
            crate::memory::free_boxed(backup);
            assert_eq!((*words).words_len, 12);
            assert_eq!(*(*words).confirm_positions.add(1), 12);
            assert_eq!(
                std::ffi::CStr::from_ptr(*(*words).words).to_str().unwrap(),
                "abandon"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr((*status).operation)
                    .to_str()
                    .unwrap(),
                "ab".repeat(16)
            );
            assert!(matches!((*status).phase, MarmotBackupRestorePhase::Partial));
            assert_eq!(
                (
                    (*status).imported_events,
                    (*status).failed_archives,
                    (*status).revision
                ),
                (7, 2, 9)
            );
            assert_eq!((*hints).len, 1);
            assert_eq!(
                std::ffi::CStr::from_ptr((*(*hints).items).recovery_public_key_hex)
                    .to_str()
                    .unwrap(),
                "cd".repeat(32)
            );
            marmot_recovery_words_free(words);
            marmot_backup_restore_status_free(status);
            marmot_backup_history_availability_list_free(hints);
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
