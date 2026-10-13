//! mdk#2241: restoring a ciphertext checkpoint reserves its buffer fallibly.
//! This binary installs an allocator that can refuse large requests, so a
//! failed reservation surfaces as a storage error the runtime retries instead
//! of aborting the process. It holds a single test so the refusal switch never
//! affects another test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use cgka_traits::StorageError;
use sha2::{Digest, Sha256};
use storage_sqlite::{
    AttachmentDemand, AttachmentHistoryEntry, AttachmentPartialIdentity, SqlCipherKey,
    SqliteAccountStorage, StoredAccountGroup, StoredAccountState, StoredAppEvent,
};

/// Refuses every allocation of at least `REFUSE_FROM` bytes.
struct Refusing;
static REFUSE_FROM: AtomicUsize = AtomicUsize::new(usize::MAX);

unsafe impl GlobalAlloc for Refusing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= REFUSE_FROM.load(Ordering::SeqCst) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Refusing = Refusing;

const GROUP: &str = "abababababababababababababababab";
const MIB: usize = 1024 * 1024;

/// A group row the attachment source can join against.
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

/// A refused checkpoint buffer is a retryable storage error that keeps the
/// prefix, and the same prefix restores once memory is available again.
#[test]
fn a_refused_checkpoint_buffer_is_a_storage_error_not_an_abort() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("attachment-reservation-test-key").unwrap();
    let store =
        SqliteAccountStorage::open_encrypted(dir.path().join("account.sqlite"), &key).unwrap();
    store
        .save_account_projection_state(
            &StoredAccountState {
                label: "alice".into(),
                groups: vec![group()],
                ..Default::default()
            },
            100,
            300,
        )
        .unwrap();
    let digest: [u8; 32] = Sha256::digest(b"body").into();
    let tag = vec![
        "imeta".to_string(),
        "m application/octet-stream".to_string(),
        format!("x {}", hex::encode(digest)),
    ];
    store
        .record_app_event(&StoredAppEvent {
            group_id_hex: GROUP.into(),
            message_id_hex: "11".repeat(32),
            source_message_id_hex: Some("22".repeat(32)),
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
        message_id_hex: "11".repeat(32),
        attachment_index: 0,
        source_message_id_hex: "22".repeat(32),
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
    let identity = AttachmentPartialIdentity {
        ciphertext_digest: [1; 32],
        locator_digest: [2; 32],
        etag: "\"v1\"".into(),
        total: 8 * MIB as u64,
    };
    let chunk = vec![0x5a; MIB];
    assert!(
        store
            .checkpoint_attachment_partial(&job, &identity, 0, &chunk, 12, 1 << 40)
            .unwrap()
    );
    // The restore sizes its buffer for the whole 8 MiB representation; refuse
    // that, while the 1 MiB chunk reads it performs still succeed.
    REFUSE_FROM.store(4 * MIB, Ordering::SeqCst);
    let refused =
        store.load_attachment_partial(&job, 13, 64 * MIB as u64, Some((&[1; 32], &[2; 32])));
    REFUSE_FROM.store(usize::MAX, Ordering::SeqCst);
    assert!(
        matches!(refused, Err(StorageError::Backend(_))),
        "a refused reservation is a retryable storage error"
    );
    let restored = store
        .load_attachment_partial(&job, 13, 64 * MIB as u64, Some((&[1; 32], &[2; 32])))
        .unwrap()
        .expect("the refused restore kept the prefix");
    assert_eq!(restored.bytes, chunk);
    assert!(restored.bytes.capacity() >= 8 * MIB);
}
