use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::group::Member;
use cgka_traits::storage::{CapabilityStorage, GroupStorage, StorageResult};
use cgka_traits::types::{GroupId, MemberId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

#[derive(Serialize, Deserialize)]
struct CapabilityRequirementRow {
    requires: Capability,
    level: RequirementLevel,
    description: String,
}

impl From<&CapabilityRequirement> for CapabilityRequirementRow {
    fn from(value: &CapabilityRequirement) -> Self {
        Self {
            requires: value.requires,
            level: value.level.clone(),
            description: value.description.to_string(),
        }
    }
}

impl From<CapabilityRequirementRow> for CapabilityRequirement {
    fn from(value: CapabilityRequirementRow) -> Self {
        Self {
            requires: value.requires,
            level: value.level,
            description: intern_capability_description(value.description),
        }
    }
}

fn intern_capability_description(description: String) -> &'static str {
    static INTERNER: OnceLock<Mutex<HashMap<String, &'static str>>> = OnceLock::new();

    let interner = INTERNER.get_or_init(|| Mutex::new(HashMap::new()));
    let mut interner = interner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(interned) = interner.get(description.as_str()) {
        return interned;
    }

    // `CapabilityRequirement` exposes `&'static str` descriptions for
    // registry constants. SQLite has to reconstruct persisted strings, so
    // intern each distinct value once instead of leaking one allocation per
    // read.
    let interned: &'static str = Box::leak(description.clone().into_boxed_str());
    interner.insert(description, interned);
    interned
}

// Keep historical account-only rows readable. New writes retain leaf signing
// keys inside the existing blob, so snapshots and rollback remain atomic.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum StoredMemberCapabilities {
    Leaves {
        #[serde(deserialize_with = "deserialize_capability_version")]
        version: u16,
        leaves: BTreeMap<String, GroupCapabilities>,
    },
    Legacy(#[serde(deserialize_with = "deserialize_legacy_capabilities")] GroupCapabilities),
}

/// Capability blobs are derived knowledge, never authoritative MLS state.
/// Keep strict format decoding, but let callers treat an invalid cache row as
/// unknown until an authenticated leaf/KeyPackage write replaces it. SQL and
/// other storage failures are still propagated by the callers.
pub(crate) fn decode_cached_member_capabilities(record: &[u8]) -> Option<StoredMemberCapabilities> {
    match deserialize(record) {
        Ok(capabilities) => Some(capabilities),
        Err(_) => {
            tracing::warn!(
                target: "marmot.storage_sqlite.capabilities",
                method = "decode_cached_member_capabilities",
                invalid_rows = 1,
                "ignoring undecodable member capability cache row"
            );
            None
        }
    }
}

fn deserialize_legacy_capabilities<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<GroupCapabilities, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.get("version").is_some() || value.get("leaves").is_some() {
        return Err(serde::de::Error::custom(
            "versioned capabilities cannot fall back to legacy",
        ));
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

fn deserialize_capability_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<u16, D::Error> {
    let version = u16::deserialize(deserializer)?;
    if version != 2 {
        return Err(serde::de::Error::custom(
            "unsupported member capability version",
        ));
    }
    Ok(version)
}

/// Bind historical account-only knowledge only when the old roster proves a
/// single leaf. Ambiguous rows become unknown, never the last writer's claim.
/// Also used before roster changes after restoring historical snapshots.
pub(crate) fn promote_legacy_capabilities(
    connection: &rusqlite::Connection,
    group: &cgka_traits::group::Group,
) -> StorageResult<()> {
    let mut accounts = std::collections::BTreeSet::new();
    for member in &group.members {
        if !accounts.insert(member.id.as_slice().to_vec()) {
            continue;
        }
        let record: Option<Vec<u8>> = connection.query_row(
            "SELECT capabilities FROM cgka_member_capabilities WHERE group_id = ?1 AND member_id = ?2",
            params![group.id.as_slice(), member.id.as_slice()], |row| row.get(0),
        ).optional().storage()?;
        let Some(record) = record else {
            continue;
        };
        let Some(StoredMemberCapabilities::Legacy(caps)) =
            decode_cached_member_capabilities(&record)
        else {
            continue;
        };
        let leaves = legacy_leaf_capabilities(group, &member.id, caps);
        connection.execute(
            "UPDATE cgka_member_capabilities SET capabilities = ?3 WHERE group_id = ?1 AND member_id = ?2",
            params![group.id.as_slice(), member.id.as_slice(), serialize(&StoredMemberCapabilities::Leaves { version: 2, leaves })?],
        ).storage()?;
    }
    Ok(())
}

fn legacy_leaf_capabilities(
    group: &cgka_traits::group::Group,
    member_id: &MemberId,
    caps: GroupCapabilities,
) -> BTreeMap<String, GroupCapabilities> {
    let mut leaves = group
        .members
        .iter()
        .filter(|member| &member.id == member_id);
    match (leaves.next(), leaves.next()) {
        (Some(leaf), None) => BTreeMap::from([(hex::encode(&leaf.credential), caps)]),
        _ => BTreeMap::new(),
    }
}

impl CapabilityStorage for SqliteAccountStorage {
    fn register_feature(&self, feature: Feature, req: CapabilityRequirement) -> StorageResult<()> {
        let row = CapabilityRequirementRow::from(&req);
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_features (feature, requirement)
                 VALUES (?1, ?2)",
                params![feature.0, serialize(&row)?],
            )
            .storage()?;
        Ok(())
    }

    fn feature_requirement(
        &self,
        feature: &Feature,
    ) -> StorageResult<Option<CapabilityRequirement>> {
        let record: Option<Vec<u8>> = self
            .lock()?
            .query_row_cached(
                "SELECT requirement FROM cgka_features WHERE feature = ?1",
                params![feature.0],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        record
            .map(|record| deserialize::<CapabilityRequirementRow>(&record).map(Into::into))
            .transpose()
    }

    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> StorageResult<()> {
        let connection = self.lock()?;
        let previous: Option<Vec<u8>> = connection.query_row_cached(
            "SELECT capabilities FROM cgka_member_capabilities WHERE group_id = ?1 AND member_id = ?2",
            params![group_id.as_slice(), member.id.as_slice()], |row| row.get(0),
        ).optional().storage()?;
        let mut leaves = match previous
            .as_deref()
            .and_then(decode_cached_member_capabilities)
        {
            Some(StoredMemberCapabilities::Leaves { leaves, .. }) => leaves,
            Some(StoredMemberCapabilities::Legacy(caps)) => {
                let group: Option<Vec<u8>> = connection
                    .query_row_cached(
                        "SELECT record FROM cgka_groups WHERE id = ?1",
                        params![group_id.as_slice()],
                        |row| row.get(0),
                    )
                    .optional()
                    .storage()?;
                match group
                    .map(|record| deserialize::<cgka_traits::group::Group>(&record))
                    .transpose()?
                {
                    Some(group) => legacy_leaf_capabilities(&group, &member.id, caps),
                    None => BTreeMap::new(),
                }
            }
            None => BTreeMap::new(),
        };
        leaves.insert(hex::encode(&member.credential), capabilities);
        connection
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_member_capabilities
                    (group_id, member_id, capabilities)
                 VALUES (?1, ?2, ?3)",
                params![
                    group_id.as_slice(),
                    member.id.as_slice(),
                    serialize(&StoredMemberCapabilities::Leaves { version: 2, leaves })?
                ],
            )
            .storage()?;
        Ok(())
    }

    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> StorageResult<Option<GroupCapabilities>> {
        let record: Option<Vec<u8>> = self
            .lock()?
            .query_row_cached(
                "SELECT capabilities FROM cgka_member_capabilities
                 WHERE group_id = ?1 AND member_id = ?2",
                params![group_id.as_slice(), member_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        let Some(record) = record else {
            return Ok(None);
        };
        let Some(capabilities) = decode_cached_member_capabilities(&record) else {
            return Ok(None);
        };
        match capabilities {
            StoredMemberCapabilities::Legacy(caps) => {
                // Historical account-only data cannot prove that every sibling
                // supports the last writer's capabilities. Keep that unknown
                // until leaf-aware writes populate the cache.
                let group = self.get_group(group_id)?;
                let multiple_leaves = group
                    .members
                    .iter()
                    .filter(|member| &member.id == member_id)
                    .take(2)
                    .count()
                    == 2;
                Ok(Some(if multiple_leaves {
                    GroupCapabilities::default()
                } else {
                    caps
                }))
            }
            StoredMemberCapabilities::Leaves { leaves, .. } => {
                let group = self.get_group(group_id)?;
                let mut aggregate: Option<GroupCapabilities> = None;
                for member in group
                    .members
                    .iter()
                    .filter(|member| &member.id == member_id)
                {
                    let caps = leaves
                        .get(&hex::encode(&member.credential))
                        .cloned()
                        .unwrap_or_default();
                    match &mut aggregate {
                        None => aggregate = Some(caps),
                        Some(common) => {
                            common.proposals.retain(|id| caps.proposals.contains(id));
                            common.extensions.retain(|id| caps.extensions.contains(id));
                            common
                                .app_components
                                .ids
                                .retain(|id| caps.app_components.contains(*id));
                        }
                    }
                }
                if aggregate.is_none() {
                    // Preserve the storage API for callers caching an account
                    // before its roster projection has been written.
                    for caps in leaves.values() {
                        match &mut aggregate {
                            None => aggregate = Some(caps.clone()),
                            Some(common) => {
                                common.proposals.retain(|id| caps.proposals.contains(id));
                                common.extensions.retain(|id| caps.extensions.contains(id));
                                common
                                    .app_components
                                    .ids
                                    .retain(|id| caps.app_components.contains(*id));
                            }
                        }
                    }
                }
                Ok(aggregate)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use crate::storage::test_support::{gid, member_id, sample_group};
    use cgka_traits::storage::GroupStorage;

    #[test]
    fn undecodable_capability_cache_is_unknown_and_repairable() {
        use cgka_traits::EpochId;
        use cgka_traits::storage::{GroupStateCheckpointRef, MessageStorage};
        for record in [
            b"broken JSON".as_slice(),
            br#"{"leaves":{}}"#.as_slice(),
            br#"{"version":3,"leaves":{}}"#.as_slice(),
        ] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            let bad = sample_group(gid(1), 0, 1);
            let good = sample_group(gid(2), 0, 1);
            let mut caps = GroupCapabilities::default();
            caps.insert(Capability::Proposal(10));
            for group in [&bad, &good] {
                store.put_group(group).unwrap();
                store
                    .save_member_capabilities(&group.id, &group.members[0], caps.clone())
                    .unwrap();
            }
            store
                .lock()
                .unwrap()
                .execute(
                    "UPDATE cgka_member_capabilities SET capabilities = ?2 WHERE group_id = ?1",
                    params![bad.id.as_slice(), record],
                )
                .unwrap();
            assert_eq!(
                store
                    .member_capabilities(&bad.id, &bad.members[0].id)
                    .unwrap(),
                None
            );
            assert_eq!(
                store
                    .member_capabilities(&good.id, &good.members[0].id)
                    .unwrap(),
                Some(caps.clone())
            );
            // Capturing state must not turn a disposable cache failure into a
            // failed engine operation, including before the repair write.
            store.create_group_snapshot(&bad.id, "unknown").unwrap();
            store
                .create_group_state_checkpoint(
                    &bad.id,
                    &GroupStateCheckpointRef {
                        id: "unknown".into(),
                        resulting_epoch: EpochId(0),
                    },
                )
                .unwrap();
            // Migration and subsequent roster changes also see the bad row.
            store
                .lock()
                .unwrap()
                .execute("DELETE FROM cgka_schema_migrations WHERE version > 107", [])
                .unwrap();
            crate::migrations::run_all(&mut store.lock().unwrap()).unwrap();
            store.put_group(&bad).unwrap();
            store
                .save_member_capabilities(&bad.id, &bad.members[0], caps.clone())
                .unwrap();
            assert_eq!(
                store
                    .member_capabilities(&bad.id, &bad.members[0].id)
                    .unwrap(),
                Some(caps)
            );
            store
                .rollback_group_to_snapshot(&bad.id, "unknown")
                .unwrap();
            assert_eq!(
                store
                    .member_capabilities(&bad.id, &bad.members[0].id)
                    .unwrap(),
                None
            );
        }
    }

    #[test]
    fn feature_registry_and_member_capabilities_roundtrip() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        let feature = Feature("self-remove");
        let requirement = CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        };
        store
            .register_feature(feature.clone(), requirement.clone())
            .unwrap();
        assert_eq!(
            store.feature_requirement(&feature).unwrap(),
            Some(requirement)
        );

        let member = Member {
            id: member_id(1),
            credential: vec![],
        };
        let mut caps = GroupCapabilities::default();
        caps.insert(Capability::Proposal(10));
        store
            .save_member_capabilities(&gid(1), &member, caps.clone())
            .unwrap();
        assert_eq!(
            store.member_capabilities(&gid(1), &member.id).unwrap(),
            Some(caps)
        );
        assert_eq!(
            store.member_capabilities(&gid(2), &member.id).unwrap(),
            None
        );
    }

    #[test]
    fn feature_requirement_reuses_description_allocation_across_reads() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let feature = Feature("agent-text-stream");
        store
            .register_feature(
                feature.clone(),
                CapabilityRequirement {
                    requires: Capability::AppComponent(0x8006),
                    level: RequirementLevel::Optional,
                    description: "agent text stream over QUIC",
                },
            )
            .unwrap();

        let first = store.feature_requirement(&feature).unwrap().unwrap();
        let second = store.feature_requirement(&feature).unwrap().unwrap();

        assert_eq!(first.description, second.description);
        assert_eq!(
            first.description.as_ptr(),
            second.description.as_ptr(),
            "SQLite capability reads must not leak a fresh description allocation per read"
        );
    }
    #[test]
    fn invite_all_fresh_devices_capabilities_intersect_leaves_and_survive_rollback() {
        use cgka_traits::storage::MessageStorage;
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut group = sample_group(gid(1), 0, 1);
        let first = group.members[0].clone();
        let second = Member {
            id: first.id.clone(),
            credential: vec![9; 8],
        };
        group.members.push(second.clone());
        store.put_group(&group).unwrap();
        let mut common = GroupCapabilities::default();
        common.insert(Capability::Proposal(10));
        let mut extra = common.clone();
        extra.insert(Capability::Extension(42));
        // Last writer supports more; account capabilities must still reflect
        // the less capable sibling, independent of insertion order.
        store
            .save_member_capabilities(&group.id, &first, common.clone())
            .unwrap();
        store
            .save_member_capabilities(&group.id, &second, extra.clone())
            .unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(common.clone())
        );
        store
            .create_group_snapshot(&group.id, "device-capabilities")
            .unwrap();
        store
            .save_member_capabilities(&group.id, &first, extra.clone())
            .unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(extra.clone())
        );
        store
            .rollback_group_to_snapshot(&group.id, "device-capabilities")
            .unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(common)
        );
        group.members.remove(0);
        store.put_group(&group).unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &second.id).unwrap(),
            Some(extra)
        );
        store
            .release_group_snapshot(&group.id, "device-capabilities")
            .unwrap();
    }
    #[test]
    fn capability_upgrade_preserves_single_leaf_before_sibling_addition() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut group = sample_group(gid(1), 0, 1);
        let first = group.members[0].clone();
        let mut caps = GroupCapabilities::default();
        caps.insert(Capability::Extension(42));
        store.put_group(&group).unwrap();
        store.lock().unwrap().execute(
            "INSERT INTO cgka_member_capabilities (group_id, member_id, capabilities) VALUES (?1, ?2, ?3)",
            params![group.id.as_slice(), first.id.as_slice(), serialize(&caps).unwrap()],
        ).unwrap();
        // Simulate the upgrade from the last account-only writer.
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM cgka_schema_migrations WHERE version > 107", [])
            .unwrap();
        crate::migrations::run_all(&mut store.lock().unwrap()).unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(caps.clone())
        );
        let sibling = Member {
            id: first.id.clone(),
            credential: vec![9; 8],
        };
        group.members.push(sibling.clone());
        store.put_group(&group).unwrap();
        store
            .save_member_capabilities(&group.id, &sibling, caps.clone())
            .unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(caps)
        );
    }

    #[test]
    fn capability_upgrade_preserves_unknown_for_ambiguous_legacy_leaves() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut group = sample_group(gid(1), 0, 1);
        let first = group.members[0].clone();
        group.members.push(Member {
            id: first.id.clone(),
            credential: vec![9; 8],
        });
        store.put_group(&group).unwrap();
        let mut caps = GroupCapabilities::default();
        caps.insert(Capability::Extension(42));
        store.lock().unwrap().execute(
            "INSERT INTO cgka_member_capabilities (group_id, member_id, capabilities) VALUES (?1, ?2, ?3)",
            params![group.id.as_slice(), first.id.as_slice(), serialize(&caps).unwrap()],
        ).unwrap();
        store
            .lock()
            .unwrap()
            .execute("DELETE FROM cgka_schema_migrations WHERE version > 107", [])
            .unwrap();
        crate::migrations::run_all(&mut store.lock().unwrap()).unwrap();
        store
            .save_member_capabilities(&group.id, &group.members[1], caps)
            .unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(GroupCapabilities::default())
        );
    }
    #[test]
    fn capability_leaf_blob_versions_are_explicit_and_fail_closed() {
        let row = StoredMemberCapabilities::Leaves {
            version: 2,
            leaves: BTreeMap::new(),
        };
        let mut json: serde_json::Value =
            serde_json::from_slice(&serialize(&row).unwrap()).unwrap();
        assert_eq!(json["version"], 2);
        assert!(deserialize::<StoredMemberCapabilities>(&serialize(&json).unwrap()).is_ok());
        json["version"] = 3.into();
        // Even future envelopes that add an account aggregate must fail closed.
        json["proposals"] = serde_json::json!([]);
        json["extensions"] = serde_json::json!([]);
        assert!(deserialize::<StoredMemberCapabilities>(&serialize(&json).unwrap()).is_err());
        assert!(matches!(
            deserialize::<StoredMemberCapabilities>(
                &serialize(&GroupCapabilities::default()).unwrap()
            )
            .unwrap(),
            StoredMemberCapabilities::Legacy(_)
        ));
    }

    #[test]
    fn capability_historical_restore_preserves_leaf_before_sibling_addition() {
        use cgka_traits::storage::MessageStorage;
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mut group = sample_group(gid(1), 0, 1);
        let first = group.members[0].clone();
        let mut caps = GroupCapabilities::default();
        caps.insert(Capability::Extension(42));
        store.put_group(&group).unwrap();
        store.lock().unwrap().execute(
            "INSERT INTO cgka_member_capabilities (group_id, member_id, capabilities) VALUES (?1, ?2, ?3)",
            params![group.id.as_slice(), first.id.as_slice(), serialize(&caps).unwrap()],
        ).unwrap();
        store.create_group_snapshot(&group.id, "legacy").unwrap();
        store
            .save_member_capabilities(&group.id, &first, GroupCapabilities::default())
            .unwrap();
        store
            .rollback_group_to_snapshot(&group.id, "legacy")
            .unwrap();
        let sibling = Member {
            id: first.id.clone(),
            credential: vec![9; 8],
        };
        group.members.push(sibling.clone());
        // Cache writes may precede the expanded roster projection.
        store
            .save_member_capabilities(&group.id, &sibling, caps.clone())
            .unwrap();
        store.put_group(&group).unwrap();
        assert_eq!(
            store.member_capabilities(&group.id, &first.id).unwrap(),
            Some(caps)
        );
    }
}
