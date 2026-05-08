use crate::{SqliteResultExt, SqliteStorage, deserialize, serialize};
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::group::Member;
use cgka_traits::storage::{CapabilityStorage, StorageResult};
use cgka_traits::types::{GroupId, MemberId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

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
            description: Box::leak(value.description.into_boxed_str()),
        }
    }
}

impl CapabilityStorage for SqliteStorage {
    fn register_feature(&self, feature: Feature, req: CapabilityRequirement) -> StorageResult<()> {
        let row = CapabilityRequirementRow::from(&req);
        self.lock()?
            .execute(
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
            .query_row(
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
        self.lock()?
            .execute(
                "INSERT OR REPLACE INTO cgka_member_capabilities
                    (group_id, member_id, capabilities)
                 VALUES (?1, ?2, ?3)",
                params![
                    group_id.as_slice(),
                    member.id.as_slice(),
                    serialize(&capabilities)?
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
            .query_row(
                "SELECT capabilities FROM cgka_member_capabilities
                 WHERE group_id = ?1 AND member_id = ?2",
                params![group_id.as_slice(), member_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        record.map(|record| deserialize(&record)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteStorage;
    use crate::storage::test_support::{gid, member_id};

    #[test]
    fn feature_registry_and_member_capabilities_roundtrip() {
        let store = SqliteStorage::in_memory().unwrap();
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
}
