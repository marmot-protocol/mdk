//! mdk#2241: publishing a received attachment must not multiply its size in
//! memory, through either the in-memory path or the file sink's chunked
//! import. This binary holds a single test, measuring the two paths one after
//! the other, so the process-wide SQLite and Rust allocation high-water marks
//! measure only the publication under test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use storage_sqlite::SqliteAppStorage;

use sha2::{Digest, Sha256};
use storage_sqlite::{
    AttachmentAcquisition, AttachmentAssetRef, AttachmentDemand, AttachmentHistoryEntry,
    AttachmentPublishResult, SqlCipherKey, SqliteAccountStorage, StoredAccountGroup,
    StoredAccountState, StoredAppEvent,
};

/// Counts live Rust heap bytes and their peak since the last reset.
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const GROUP: &str = "abababababababababababababababab";
const MIB: usize = 1024 * 1024;

fn group() -> StoredAccountGroup {
    StoredAccountGroup {
        group_id_hex: GROUP.into(),
        endpoint: String::new(),
        profile_name: String::new(),
        profile_description: String::new(),
        image_hash_hex: String::new(),
        image_key_hex: String::new(),
        image_nonce_hex: String::new(),
        image_upload_key_hex: String::new(),
        image_media_type: None,
        admin_keys_hex: String::new(),
        archived: false,
        pending_confirmation: false,
        member_count: None,
        direct_member_ids_hex: None,
        presentation_member_ids_hex: None,
        welcomer_account_id_hex: None,
        via_welcome_message_id_hex: None,
        nostr_routing_last_epoch: 0,
        prior_nostr_routes: vec![],
        self_membership: Default::default(),
        components: vec![],
    }
}

fn sqlite_highwater(reset: bool) -> u64 {
    // SAFETY: plain statistics reads on the process-wide SQLite allocator.
    unsafe { rusqlite::ffi::sqlite3_memory_highwater(i32::from(reset)) as u64 }
}

/// Record a received message (`message` and `source` are repeated hex bytes)
/// carrying one attachment slot for `plaintext`, and claim its acquisition.
fn claimed_job(
    store: &SqliteAppStorage,
    (message, source): (&str, &str),
    plaintext: &[u8],
) -> (AttachmentAssetRef, AttachmentAcquisition) {
    let digest: [u8; 32] = Sha256::digest(plaintext).into();
    let tag = vec![
        "imeta".to_string(),
        "m application/octet-stream".to_string(),
        format!("x {}", hex::encode(digest)),
    ];
    store
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: message.repeat(32),
            source_message_id_hex: Some(source.repeat(32)),
            source_epoch: Some(3),
            direction: "received".into(),
            sender: "33".repeat(32),
            plaintext: String::new(),
            kind: 9,
            tags: vec![tag.clone()],
            recorded_at: 10,
            received_at: 10,
            origin_commit_id: None,
            moderation_grant: false,
        })
        .unwrap();
    let selected = AttachmentHistoryEntry {
        message_id_hex: message.repeat(32),
        attachment_index: 0,
        source_message_id_hex: source.repeat(32),
        source_epoch: Some(3),
        sender: "33".repeat(32),
        timeline_at: 10,
        received_at: 10,
        slot: serde_json::to_value(&tag).unwrap(),
        emoji_tags: Vec::new(),
    };
    let AttachmentDemand::Requested(asset) = store
        .request_attachment_acquisition(GROUP, &selected, digest, 11)
        .unwrap()
    else {
        panic!("attachment demand");
    };
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    (asset, job)
}

/// Start a measurement window, returning the SQLite and Rust baselines.
fn start_window() -> (u64, usize) {
    // SAFETY: a plain statistics read on the process-wide SQLite allocator.
    let sqlite_before = unsafe { rusqlite::ffi::sqlite3_memory_used() } as u64;
    assert!(
        sqlite_before > 0,
        "SQLite memory statistics must be enabled for this measurement"
    );
    sqlite_highwater(true);
    let rust_before = LIVE.load(Ordering::SeqCst);
    PEAK.store(rust_before, Ordering::SeqCst);
    (sqlite_before, rust_before)
}

/// The SQLite and Rust peaks above the window's baselines.
fn end_window((sqlite_before, rust_before): (u64, usize)) -> (u64, usize) {
    (
        sqlite_highwater(false).saturating_sub(sqlite_before),
        PEAK.load(Ordering::SeqCst).saturating_sub(rust_before),
    )
}

/// Both publication paths stay within a fixed budget for a 48 MiB body.
#[test]
fn publishing_a_large_body_adds_a_bounded_amount_of_memory() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("attachment-memory-test-key").unwrap();
    let store =
        SqliteAccountStorage::open_encrypted(dir.path().join("account.sqlite"), &key).unwrap();
    let app = store.app_storage();
    app.save_account_projection_state(
        &StoredAccountState {
            label: "alice".into(),
            groups: vec![group()],
            ..Default::default()
        },
        100,
        300,
    )
    .unwrap();
    // A cheap non-repeating pattern; SQLCipher encrypts pages either way.
    let plaintext: Vec<u8> = (0..48 * MIB)
        .map(|i| (i as u32).wrapping_mul(2654435761).to_le_bytes()[1])
        .collect();
    let (asset, job) = claimed_job(&app, ("11", "22"), &plaintext);

    let window = start_window();
    assert_eq!(
        app.complete_attachment_acquisition(&job, &plaintext, 12, 1 << 40)
            .unwrap(),
        AttachmentPublishResult::Published
    );
    let (sqlite_peak, rust_peak) = end_window(window);
    eprintln!(
        "MDK_BENCH attachment_publication path=memory plaintext_bytes={} sqlite_peak_bytes={sqlite_peak} rust_peak_bytes={rust_peak}",
        plaintext.len()
    );
    // The caller's buffer is the only whole-body copy: SQLite takes it one
    // staging chunk per row through a page cache, and the publication path
    // itself allocates no body-sized Rust buffer.
    let budget = (8 * MIB) as u64;
    assert!(
        sqlite_peak < budget,
        "SQLite held {sqlite_peak} bytes for a {} byte body",
        plaintext.len()
    );
    assert!(
        rust_peak < (2 * MIB),
        "publication allocated {rust_peak} bytes of Rust heap"
    );
    for offset in [0usize, 17 * MIB + 3, plaintext.len() - MIB] {
        let window = app
            .read_retained_attachment(&asset, 12, offset as u64, MIB)
            .unwrap()
            .unwrap();
        assert_eq!(&*window, &plaintext[offset..offset + MIB]);
    }
    assert_eq!(
        app.retained_attachment_byte_count().unwrap(),
        plaintext.len() as u64
    );

    // The file sink publishes a decrypted file through bounded chunk imports.
    let mut file_body = plaintext;
    file_body[0] ^= 0xff;
    let (file_asset, file_job) = claimed_job(&app, ("44", "55"), &file_body);
    let window = start_window();
    assert_eq!(
        app.complete_attachment_acquisition_from_reader(
            &file_job,
            &mut std::io::Cursor::new(&file_body),
            file_body.len() as u64,
            12,
            1 << 40,
            &|| false,
        )
        .unwrap(),
        AttachmentPublishResult::Published
    );
    let (sqlite_peak, rust_peak) = end_window(window);
    eprintln!(
        "MDK_BENCH attachment_publication path=file plaintext_bytes={} sqlite_peak_bytes={sqlite_peak} rust_peak_bytes={rust_peak}",
        file_body.len()
    );
    assert!(
        sqlite_peak < budget,
        "SQLite held {sqlite_peak} bytes importing a {} byte body",
        file_body.len()
    );
    assert!(
        rust_peak < (4 * MIB),
        "the chunked import allocated {rust_peak} bytes of Rust heap"
    );
    let window = app
        .read_retained_attachment(&file_asset, 12, (40 * MIB) as u64, MIB)
        .unwrap()
        .unwrap();
    assert_eq!(&*window, &file_body[40 * MIB..41 * MIB]);
}
