//! Compact live-engine facts for conversation capture. This is advisory
//! presentation data; mutation entry points still validate current authority.
use std::collections::HashMap;
use std::sync::Mutex;

use cgka_traits::app_components::GROUP_LIFECYCLE_COMPONENT_ID;
use cgka_traits::storage::StorageProvider;
use cgka_traits::{EngineError, EpochId, GroupId, GroupLifecycleState};
use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;

use crate::Engine;

/// Canonical membership/capability scalars. No roster, administrator list,
/// unsupported-member identities, profile strings or MLS secrets escape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupAuthorityFacts {
    pub epoch: EpochId,
    pub member_count: usize,
    pub is_member: bool,
    pub is_admin: bool,
    pub admin_count: usize,
    pub removed: bool,
    pub unrecoverable: bool,
    pub disbanded: bool,
    pub disbanding_enabled: bool,
    pub has_disbanding_blockers: bool,
}

/// One live engine borrow and one backend read boundary. Never combine a
/// startup/recovery copy of this with newer account rows: capture both under
/// the same worker operation and outer `StorageProvider::with_read_snapshot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupAuthoritySnapshot {
    pub facts: GroupAuthorityFacts,
    pub lifecycle: GroupLifecycleState,
    pub disbanding: bool,
}

#[derive(Default)]
pub(crate) struct GroupAuthorityCache {
    entries: Mutex<HashMap<GroupId, ([u8; 32], GroupAuthorityFacts)>>,
    #[cfg(test)]
    misses: std::sync::atomic::AtomicU64,
}

impl GroupAuthorityCache {
    pub(crate) fn forget_group(&self, group: &GroupId) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(group);
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Capture compact authority from the live, validated engine. Scalar facts
    /// are reused only with a backend token covering their exact group/MLS
    /// sources. Lifecycle and durable disband gates are read on every call.
    /// Unknown or unhydrated engine state never becomes a fabricated Stable.
    /// No network, readiness work or read acknowledgement is performed.
    pub fn group_authority(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupAuthoritySnapshot, EngineError> {
        self.ensure_group_live(group_id)?;
        self.storage.with_read_snapshot(|storage| {
            let revision = storage.group_authority_revision(group_id)?;
            let cached = revision.and_then(|revision| {
                self.group_authority_cache
                    .entries
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(group_id)
                    .filter(|(stored, _)| *stored == revision)
                    .map(|(_, facts)| *facts)
            });
            let facts = match cached {
                Some(facts) => facts,
                None => {
                    #[cfg(test)]
                    self.group_authority_cache
                        .misses
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let facts = self.capture_group_authority_facts(group_id)?;
                    if let Some(revision) = revision {
                        let mut entries = self
                            .group_authority_cache
                            .entries
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        if entries.len() >= 32 && !entries.contains_key(group_id) {
                            entries.clear();
                        }
                        entries.insert(group_id.clone(), (revision, facts));
                    }
                    facts
                }
            };
            let lifecycle = if facts.disbanded {
                GroupLifecycleState::Disbanded
            } else {
                self.epoch_manager
                    .state(group_id)
                    .map(GroupLifecycleState::from)
                    .ok_or_else(|| EngineError::GroupNotHydrated(group_id.clone()))?
            };
            Ok(GroupAuthoritySnapshot {
                facts,
                lifecycle,
                disbanding: self.disbanding_in_progress(group_id)?,
            })
        })
    }

    fn capture_group_authority_facts(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupAuthorityFacts, EngineError> {
        let group = self.storage.get_group(group_id)?;
        let mut facts = GroupAuthorityFacts {
            epoch: group.epoch,
            member_count: group.members.len(),
            is_member: !group.is_terminal()
                && group
                    .members
                    .iter()
                    .any(|m| &m.id == self.identity.self_id()),
            is_admin: false,
            admin_count: 0,
            removed: group.removed,
            unrecoverable: group.unrecoverable,
            disbanded: group.disbanded.is_some(),
            disbanding_enabled: !group.is_terminal()
                && group
                    .required_capabilities
                    .app_components
                    .contains(GROUP_LIFECYCLE_COMPONENT_ID),
            has_disbanding_blockers: false,
        };
        if group.is_terminal() {
            return Ok(facts);
        }
        // Deliberately load within this read boundary, rather than consulting
        // the ratchet cache's connection/data_version token (a different
        // consistency domain). This only happens when authority inputs change.
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let mut admins = crate::app_components::admins_of_group(&mls_group)?;
        admins.sort();
        admins.dedup();
        facts.admin_count = admins.len();
        facts.is_admin = facts.is_member
            && admins
                .iter()
                .any(|key| key.as_slice() == self.identity.self_id().as_slice());
        facts.has_disbanding_blockers = !facts.disbanding_enabled
            && !crate::app_components::lifecycle_support_blockers(&mls_group)?.is_empty();
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_convergence::tests::test_engine;
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
    use cgka_traits::storage::GroupStorage;
    use std::sync::atomic::Ordering;

    async fn fixture() -> (Engine<storage_sqlite::SqliteAccountStorage>, GroupId) {
        let mut engine = test_engine();
        let (group, created) = engine
            .create_group(CreateGroupRequest {
                name: "authority".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        if let SendResult::GroupCreated { pending, .. } = created {
            assert_eq!(
                engine.group_authority(&group).unwrap().lifecycle,
                GroupLifecycleState::PendingPublish
            );
            engine.confirm_published(pending).await.unwrap();
        }
        (engine, group)
    }

    #[tokio::test]
    async fn group_authority_reuses_facts_across_message_ratchets_and_other_groups() {
        let (mut engine, group) = fixture().await;
        let first = engine.group_authority(&group).unwrap();
        assert!(first.facts.is_member);
        assert!(first.facts.is_admin);
        assert_eq!(first.facts.admin_count, 1);
        assert_eq!(first.facts.member_count, 1);
        assert_eq!(first.lifecycle, GroupLifecycleState::Stable);
        assert_eq!(
            first.facts.has_disbanding_blockers,
            !engine
                .disbanding_support_blockers(&group)
                .unwrap()
                .is_empty()
        );
        let misses = engine.group_authority_cache.misses.load(Ordering::Relaxed);
        let payload = MarmotAppEvent::new(
            hex::encode(engine.self_id().as_slice()),
            1_700_000_000,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "hello",
        )
        .encode()
        .unwrap();
        engine
            .send(SendIntent::AppMessage {
                group_id: group.clone(),
                payload,
                expected_epoch: None,
            })
            .await
            .unwrap();
        engine
            .create_group(CreateGroupRequest {
                name: "unrelated".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        assert_eq!(engine.group_authority(&group).unwrap(), first);
        assert_eq!(
            engine.group_authority_cache.misses.load(Ordering::Relaxed),
            misses
        );
    }

    #[tokio::test]
    async fn group_authority_never_reuses_aborted_or_replaced_facts() {
        let (engine, group) = fixture().await;
        let initial = engine.group_authority(&group).unwrap();
        let mut record = engine.storage.get_group(&group).unwrap();
        engine
            .storage
            .with_transaction(|store| {
                record.unrecoverable = true;
                store.put_group(&record)?;
                assert!(engine.group_authority(&group)?.facts.unrecoverable);
                Err::<(), EngineError>(EngineError::Other("rollback".into()))
            })
            .unwrap_err();
        assert_eq!(engine.group_authority(&group).unwrap(), initial);
        record.unrecoverable = false;
        record.removed = true;
        engine.storage.put_group(&record).unwrap();
        let removed = engine.group_authority(&group).unwrap();
        assert!(removed.facts.removed);
        assert!(!removed.facts.is_member);
        assert!(!removed.facts.is_admin);
        record.removed = false;
        engine.storage.put_group(&record).unwrap();
        assert_eq!(engine.group_authority(&group).unwrap(), initial);
    }

    #[tokio::test]
    async fn group_authority_missing_or_unhydrated_epoch_never_defaults_to_stable() {
        let (mut engine, group) = fixture().await;
        engine.group_authority(&group).unwrap();
        engine.epoch_manager.clear_group_state(&group);
        assert!(matches!(
            engine.group_authority(&group),
            Err(EngineError::GroupNotHydrated(_))
        ));
        engine.unhydrated_groups.insert(group.clone());
        assert!(matches!(
            engine.group_authority(&group),
            Err(EngineError::GroupNotHydrated(_))
        ));
        engine.storage.close().unwrap();
        engine.unhydrated_groups.remove(&group);
        assert!(engine.group_authority(&group).is_err());
    }
    #[tokio::test]
    async fn group_authority_reads_lifecycle_again_without_reloading_scalar_facts() {
        let (mut engine, group) = fixture().await;
        engine.group_authority(&group).unwrap();
        let misses = engine.group_authority_cache.misses.load(Ordering::Relaxed);
        engine.epoch_manager.mark_unrecoverable(&group);
        assert_eq!(
            engine.group_authority(&group).unwrap().lifecycle,
            GroupLifecycleState::Unrecoverable
        );
        assert_eq!(
            engine.group_authority_cache.misses.load(Ordering::Relaxed),
            misses
        );
    }
}
