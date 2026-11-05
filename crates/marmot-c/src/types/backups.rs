//! C-owned backup setup, status and availability records.
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::conversions::{
    BackgroundBackupOutcomeFfi, BackupHistoryAvailabilityFfi, BackupRestorePhaseFfi,
    BackupRestoreStatusFfi, BackupSettingsFfi, RecoveryWordsFfi,
};

c_mirror! {
    /// Shown-once recovery words. Clear host copies and promptly free this
    /// record. Its returned word buffers are erased before release; host
    /// copies and earlier managed/FFI copies are not erased by this free.
    MarmotRecoveryWords from RecoveryWordsFfi,
    free marmot_recovery_words_free {
        secret_str_vec words/words_len,
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
    /// One due background pass's admission/completion, not publication success.
    MarmotBackgroundBackupOutcome from BackgroundBackupOutcomeFfi {
        NotStarted, FinishedAttempt
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

    // Observes selected live allocations immediately before their real
    // deallocator. This belongs only to this alloc-audit unit-test binary.
    // The hook never allocates or panics and stops watching a pointer before
    // delegating, so a later reuse of the address cannot inspect freed memory.
    mod root_erasure_observer {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        const CAPACITY: usize = 12;
        struct Slot {
            pointer: AtomicUsize,
            length: AtomicUsize,
            seen: AtomicBool,
            zeroed: AtomicBool,
        }
        impl Slot {
            const fn new() -> Self {
                Self {
                    pointer: AtomicUsize::new(0),
                    length: AtomicUsize::new(0),
                    seen: AtomicBool::new(false),
                    zeroed: AtomicBool::new(false),
                }
            }
        }
        static ENABLED: AtomicBool = AtomicBool::new(false);
        static SLOTS: [Slot; CAPACITY] = [const { Slot::new() }; CAPACITY];

        struct ObservingAllocator;
        // SAFETY: allocation requests and deallocations are delegated to
        // System unchanged. Observation only reads within a selected still
        // live allocation's supplied Layout, before System deallocates it.
        unsafe impl GlobalAlloc for ObservingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                unsafe { System.alloc(layout) }
            }
            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                if ENABLED.load(Ordering::Acquire) {
                    for slot in &SLOTS {
                        if slot
                            .pointer
                            .compare_exchange(
                                pointer as usize,
                                0,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            let length = slot.length.load(Ordering::Acquire);
                            let zeroed = length <= layout.size()
                                && unsafe { std::slice::from_raw_parts(pointer, length) }
                                    .iter()
                                    .all(|byte| *byte == 0);
                            slot.zeroed.store(zeroed, Ordering::Release);
                            slot.seen.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
                unsafe { System.dealloc(pointer, layout) };
            }
        }
        #[global_allocator]
        static ALLOCATOR: ObservingAllocator = ObservingAllocator;

        pub(super) struct Observation {
            count: usize,
        }
        pub(super) struct Outcome {
            pub watched: usize,
            pub deallocated: usize,
            pub all_zero: bool,
        }
        impl Observation {
            pub(super) fn finish(self) -> Outcome {
                ENABLED.store(false, Ordering::Release);
                Outcome {
                    watched: self.count,
                    deallocated: SLOTS[..self.count]
                        .iter()
                        .filter(|slot| slot.seen.load(Ordering::Acquire))
                        .count(),
                    all_zero: SLOTS[..self.count]
                        .iter()
                        .all(|slot| slot.zeroed.load(Ordering::Acquire)),
                }
            }
        }
        impl Drop for Observation {
            fn drop(&mut self) {
                ENABLED.store(false, Ordering::Release);
            }
        }
        // The caller holds audit::test_lock and owns every buffer throughout
        // registration. The first detached word is NULL and intentionally
        // excluded: the existing direct helper assertions cover that word.
        pub(super) unsafe fn watch(words: &super::MarmotRecoveryWords) -> Observation {
            assert!(!ENABLED.load(Ordering::Acquire));
            for slot in &SLOTS {
                slot.pointer.store(0, Ordering::Relaxed);
                slot.length.store(0, Ordering::Relaxed);
                slot.seen.store(false, Ordering::Relaxed);
                slot.zeroed.store(false, Ordering::Relaxed);
            }
            let mut count = 0;
            for &word in unsafe { std::slice::from_raw_parts(words.words, words.words_len) } {
                if word.is_null() {
                    continue;
                }
                assert!(count < CAPACITY);
                let length = unsafe { std::ffi::CStr::from_ptr(word) }
                    .to_bytes_with_nul()
                    .len();
                SLOTS[count].length.store(length, Ordering::Relaxed);
                SLOTS[count].pointer.store(word as usize, Ordering::Release);
                count += 1;
            }
            ENABLED.store(true, Ordering::Release);
            Observation { count }
        }
    }
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
        assert_eq!(audit::live_allocations(), before + 15);
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
            // Inspect the actual erase owner's LIVE allocation, not freed
            // memory. Root dispatch/deallocation is covered below and by the
            // secret_str_vec field; this is not an allocator-time observer.
            let first_word = std::mem::replace(&mut *(*words).words, std::ptr::null_mut());
            let erased = crate::memory::take_erased_c_string(first_word)
                .expect("the first returned word owns an allocation");
            assert_eq!(erased.as_ptr(), first_word.cast::<u8>().cast_const());
            assert_eq!(erased.len(), b"abandon\0".len());
            assert_eq!(erased.as_slice(), &[0; 8]);
            drop(erased);
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
            let observation = root_erasure_observer::watch(&*words);
            marmot_recovery_words_free(words);
            let outcome = observation.finish();
            assert_eq!(
                outcome.watched, 11,
                "the root still owns the remaining words"
            );
            assert_eq!(
                outcome.deallocated, outcome.watched,
                "the root releases every watched allocation"
            );
            assert!(
                outcome.all_zero,
                "each word is erased before its real deallocator runs"
            );
            marmot_recovery_words_free(std::ptr::null_mut());
            marmot_backup_restore_status_free(status);
            marmot_backup_history_availability_list_free(hints);
        }
        assert_eq!(audit::live_allocations(), before);
    }
}
