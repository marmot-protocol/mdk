use super::*;

const PAGE: u64 = 4096;

fn space(file_mib: u64, free_mib: u64) -> DatabaseSpace {
    DatabaseSpace {
        page_size: PAGE,
        page_count: file_mib * MIB / PAGE,
        free_pages: free_mib * MIB / PAGE,
        incremental: false,
    }
}

#[test]
fn compaction_waits_for_enough_free_pages() {
    use CompactionGate::*;
    let plenty = u64::MAX / 2;
    assert_eq!(compaction_gate(&space(60, 0), 0, plenty), NotWorthwhile);
    assert_eq!(
        compaction_gate(&space(60, 14), 0, plenty),
        NotWorthwhile,
        "under 25%"
    );
    assert_eq!(compaction_gate(&space(60, 15), 0, plenty), Due, "25%");
    let mut done = space(60, 30);
    done.incremental = true;
    assert_eq!(
        compaction_gate(&done, 0, plenty),
        NotWorthwhile,
        "only once"
    );
}

#[test]
fn compaction_needs_room_for_two_copies_and_a_small_live_database() {
    use CompactionGate::*;
    // 60 MiB live: the reserve plus two copies must be free.
    let db = space(100, 40);
    assert_eq!(compaction_gate(&db, 10 * MIB, 130 * MIB), Due);
    assert_eq!(compaction_gate(&db, 10 * MIB, 130 * MIB - 1), DiskTooTight);
    // At the cap compaction runs; one page over, it waits.
    assert_eq!(compaction_gate(&space(128, 64), 0, u64::MAX / 2), Due);
    let over = DatabaseSpace {
        free_pages: 64 * MIB / PAGE - 1,
        ..space(128, 64)
    };
    assert_eq!(compaction_gate(&over, 0, u64::MAX / 2), LiveTooLarge);
    // A heavy-attachment account before its bodies moved: far over the cap.
    let large = space(4_600, 4_000);
    assert_eq!(large.live_bytes(), 600 * MIB);
    assert_eq!(compaction_gate(&large, 0, u64::MAX / 2), LiveTooLarge);
}

#[test]
fn the_logged_live_size_is_a_coarse_bucket() {
    assert_eq!(live_mib_bucket(&space(100, 100)), 1);
    assert_eq!(live_mib_bucket(&space(100, 35)), 128);
    assert_eq!(live_mib_bucket(&space(4_600, 4_000)), 1024);
}
