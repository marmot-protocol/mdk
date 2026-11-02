//! Loaded [`MlsGroup`]s kept across engine calls.
//!
//! `MlsGroup::load` is 13 storage reads plus a ratchet-tree decode that grows
//! with the member count, and the send, receive, and group-read paths each
//! paid it on every call. An entry is reused only while the storage backend's
//! OpenMLS write generation is unchanged since the entry was stored, so a
//! write through a freshly loaded group, a snapshot restore, or a rolled-back
//! transaction invalidates it without any call-site bookkeeping.
//!
//! Protocol: `take` removes the entry for the duration of an operation and
//! records the generation it saw. `return_unmodified` stores the object back
//! only if that generation is still current, so it is safe on any exit that
//! did not write through the object. `return` stores it back after an
//! operation that wrote through the object, and only if no other connection
//! committed meanwhile. An error path after a write drops the object.
//!
//! The generation is one counter per storage connection plus SQLite's
//! `data_version`, which moves on commits from other connections and
//! processes. What it cannot see is a second writer on the same connection
//! touching this group's state during an operation; the engine is the only
//! writer of group state on its connection and is single-threaded per
//! account, so that case does not arise.
//!
//! ponytail: one counter for the whole connection, so a write for one group
//! evicts every other group's entry; per-group counters if an account works
//! many groups at once.

use std::collections::HashMap;
use std::sync::Mutex;

use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use openmls::group::MlsGroup;

use crate::engine::Engine;

/// ponytail: whole-map clear at the cap; an LRU only matters once an account
/// actively works more groups than this at once.
const MAX_CACHED_MLS_GROUPS: usize = 32;

/// The half of a generation that comes from other connections and processes;
/// see `StorageProvider::mls_write_generation`.
fn foreign_half(generation: u64) -> u64 {
    generation >> 32
}

struct CachedMlsGroup {
    generation: u64,
    group: MlsGroup,
}

#[derive(Default)]
pub(crate) struct MlsGroupCache {
    entries: Mutex<HashMap<GroupId, CachedMlsGroup>>,
    /// Generation observed when each in-flight group was taken.
    taken: Mutex<HashMap<GroupId, u64>>,
}

impl MlsGroupCache {
    pub(crate) fn forget_group(&self, group_id: &GroupId) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group_id);
        self.taken
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group_id);
    }

    fn store(&self, group_id: &GroupId, generation: u64, group: MlsGroup) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.len() >= MAX_CACHED_MLS_GROUPS && !entries.contains_key(group_id) {
            entries.clear();
        }
        entries.insert(group_id.clone(), CachedMlsGroup { generation, group });
    }

    fn taken_at(&self, group_id: &GroupId) -> Option<u64> {
        self.taken
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(group_id)
    }
}

impl<S: StorageProvider> Engine<S> {
    /// The group's `MlsGroup`: the cached object when nothing has written to
    /// the OpenMLS store since it was stored, otherwise a fresh load. `None`
    /// for an unknown group.
    pub(crate) fn take_mls_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroup>, EngineError> {
        // Sampled before the load so a write that lands during the load still
        // invalidates the object on return.
        let generation = self.storage.mls_write_generation();
        if let Some(generation) = generation {
            self.mls_group_cache
                .taken
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(group_id.clone(), generation);
            let cached = self
                .mls_group_cache
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(group_id);
            if let Some(cached) = cached
                && cached.generation == generation
            {
                return Ok(Some(cached.group));
            }
        }
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))
    }

    /// Store `group` after an operation that wrote through it and succeeded.
    /// Dropped instead when another connection committed since the take, so
    /// an object derived from the earlier state is never tagged as current.
    pub(crate) fn return_mls_group(&self, group_id: &GroupId, group: MlsGroup) {
        let taken = self.mls_group_cache.taken_at(group_id);
        let Some(now) = self.storage.mls_write_generation() else {
            return;
        };
        if taken.is_none_or(|taken| foreign_half(taken) != foreign_half(now)) {
            return;
        }
        self.mls_group_cache.store(group_id, now, group);
    }

    /// Store `group` after an operation that did not write through it. Kept
    /// only if nothing at all wrote to the OpenMLS store since the take, which
    /// makes this safe on every early exit regardless of what else ran.
    pub(crate) fn return_unmodified_mls_group(&self, group_id: &GroupId, group: MlsGroup) {
        let taken = self.mls_group_cache.taken_at(group_id);
        let Some(now) = self.storage.mls_write_generation() else {
            return;
        };
        if taken != Some(now) {
            return;
        }
        self.mls_group_cache.store(group_id, now, group);
    }

    /// Run a read-only `f` against the group's `MlsGroup` and keep the object
    /// cached afterwards. `f` must not write through the group.
    pub(crate) fn with_mls_group<R>(
        &self,
        group_id: &GroupId,
        f: impl FnOnce(&MlsGroup) -> Result<R, EngineError>,
    ) -> Result<R, EngineError> {
        let group = self
            .take_mls_group(group_id)?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let result = f(&group);
        self.return_unmodified_mls_group(group_id, group);
        result
    }
}

#[cfg(test)]
mod tests {
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
    use cgka_traits::error::EngineError;
    use cgka_traits::storage::StorageProvider;
    use cgka_traits::types::EpochId;
    use openmls::prelude::{LeafNodeParameters, MlsGroup};
    use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;
    use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

    use crate::distributed_convergence::tests::test_engine_with_storage;
    use crate::provider::EngineOpenMlsProvider;

    #[tokio::test]
    async fn group_context_tracks_storage_after_rollback_and_foreign_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.sqlite");
        let key = SqlCipherKey::raw([0x43; 32]);
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let mut engine = test_engine_with_storage(storage.clone());

        for return_kind in ["cached", "modified", "unmodified"] {
            let (group_id, created) = engine
                .create_group(CreateGroupRequest {
                    name: "cache".into(),
                    description: String::new(),
                    members: vec![],
                    required_features: vec![],
                    app_components: vec![],
                    initial_admins: vec![],
                })
                .await
                .unwrap();
            let SendResult::GroupCreated { pending, .. } = created else {
                panic!("expected a legacy creation");
            };
            engine.confirm_published(pending).await.unwrap();
            assert_eq!(engine.group_context(&group_id).unwrap().epoch(), EpochId(0));
            assert_eq!(engine.group_context(&group_id).unwrap().epoch(), EpochId(0));

            let mls_id = openmls::group::GroupId::from_slice(group_id.as_slice());
            if return_kind == "cached" {
                // A genuine MLS advance is returned while the outer transaction is
                // still open. Its rollback must invalidate that advanced object.
                let aborted = storage.with_transaction(|_| {
                    let provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
                        &engine.crypto,
                        storage.mls_storage(),
                    );
                    let mut group = engine.take_mls_group(&group_id)?.unwrap();
                    group
                        .self_update(
                            &provider,
                            &engine.identity.signer,
                            LeafNodeParameters::default(),
                        )
                        .unwrap();
                    group.merge_pending_commit(&provider).unwrap();
                    engine.return_mls_group(&group_id, group);
                    assert_eq!(engine.group_context(&group_id)?.epoch(), EpochId(1));
                    Err::<(), EngineError>(EngineError::Other("rollback cache fixture".into()))
                });
                assert!(matches!(aborted, Err(EngineError::Other(reason))
                    if reason == "rollback cache fixture"));
                assert_eq!(
                    MlsGroup::load(storage.mls_storage(), &mls_id)
                        .unwrap()
                        .unwrap()
                        .epoch()
                        .as_u64(),
                    0
                );
                assert_eq!(engine.group_context(&group_id).unwrap().epoch(), EpochId(0));
            }

            let mut taken = match return_kind {
                "cached" => None,
                _ => Some(engine.take_mls_group(&group_id).unwrap().unwrap()),
            };
            if return_kind == "modified" {
                let group = taken.as_mut().unwrap();
                let configuration = group.configuration().clone();
                group
                    .set_configuration(storage.mls_storage(), &configuration)
                    .unwrap();
            }
            // This is a separate SQLCipher connection, not a clone sharing the
            // writer's generation counter. Its committed write changes data_version.
            OpenMlsStorageProvider::delete_group_state(foreign.mls_storage(), &mls_id).unwrap();
            assert!(
                MlsGroup::load(foreign.mls_storage(), &mls_id)
                    .unwrap()
                    .is_none()
            );
            if let Some(group) = taken {
                match return_kind {
                    "modified" => engine.return_mls_group(&group_id, group),
                    "unmodified" => engine.return_unmodified_mls_group(&group_id, group),
                    _ => unreachable!(),
                }
            }
            assert!(
                matches!(engine.group_context(&group_id), Err(EngineError::UnknownGroup(id)) if id == group_id),
                "{return_kind}: a public context must never expose stale MLS state"
            );
        }
    }
}
