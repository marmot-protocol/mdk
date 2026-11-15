//! OpenMLS state lost between two processes, for tests of what the next
//! process does with a group it cannot hydrate.

use cgka_traits::{GroupId, StorageProvider as _};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

/// Delete `group_id`'s OpenMLS state from the closed account database at
/// `path`, keeping its Marmot record and stored fanouts. The next open seeds
/// the group, and hydrating it quarantines the group
/// (`OpenMlsGroupMissing`).
pub(crate) fn lose_openmls_group_state(
    path: &std::path::Path,
    key: &SqlCipherKey,
    group_id: &GroupId,
) {
    let storage = SqliteAccountStorage::open_encrypted(path, key).unwrap();
    let mut group = openmls::group::MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .unwrap()
    .expect("the group has OpenMLS state to lose");
    group.delete(storage.mls_storage()).unwrap();
}
