//! `StorageProvider::mls_write_generation` must move on every write the
//! engine's cached `MlsGroup`s could be stale against, including commits made
//! through another connection to the same database.

use cgka_traits::group::{Group, ProtocolProfile};
use cgka_traits::storage::{GroupStorage, StorageProvider};
use cgka_traits::types::{EpochId, GroupId};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

fn sample_group() -> Group {
    Group {
        id: GroupId::new(vec![7u8; 16]),
        name: "generation".into(),
        description: String::new(),
        epoch: EpochId(1),
        members: vec![],
        required_capabilities: Default::default(),
        protocol_profile: ProtocolProfile::Current,
        removed: false,
        unrecoverable: false,
        disbanded: None,
        join_epoch: EpochId(0),
    }
}

#[test]
fn a_commit_from_another_connection_moves_the_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let key = SqlCipherKey::new("generation-test-key").unwrap();
    let engine_side = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let other_side = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();

    let before = engine_side.mls_write_generation().unwrap();
    assert_eq!(
        engine_side.mls_write_generation().unwrap(),
        before,
        "an idle database reports a stable generation"
    );

    other_side.put_group(&sample_group()).unwrap();
    assert_ne!(
        engine_side.mls_write_generation().unwrap(),
        before,
        "a commit on another connection must invalidate cached groups"
    );
}

#[test]
fn a_closed_store_reports_no_generation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    assert!(store.mls_write_generation().is_some());
    store.close().unwrap();
    assert!(
        store.mls_write_generation().is_none(),
        "closed storage must disable cache reuse"
    );
}
