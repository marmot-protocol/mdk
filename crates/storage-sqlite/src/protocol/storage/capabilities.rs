use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::storage::{CapabilityStorage, StorageResult};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    #[test]
    fn feature_registry_roundtrip() {
        let store = SqliteAccountStorage::in_memory().unwrap();
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
}
