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
    let plenty = u64::MAX / 2;
    assert!(!compaction_due(&space(100, 0), 0, plenty));
    assert!(!compaction_due(&space(100, 24), 0, plenty), "under 25%");
    assert!(
        compaction_due(&space(100, 25), 0, plenty),
        "25% of the file"
    );
    let mut done = space(100, 50);
    done.incremental = true;
    assert!(!compaction_due(&done, 0, plenty), "only once");
}

#[test]
fn compaction_needs_room_for_two_copies_and_a_small_live_database() {
    // 60 MiB live: the reserve plus two copies must be free.
    let db = space(100, 40);
    assert!(compaction_due(&db, 10 * MIB, 130 * MIB));
    assert!(!compaction_due(&db, 10 * MIB, 130 * MIB - 1));
    // The copy is built in memory: a live database over the cap waits.
    let large = space(4_600, 4_000);
    assert_eq!(large.live_bytes(), 600 * MIB);
    assert!(!compaction_due(&large, 0, u64::MAX / 2));
}
