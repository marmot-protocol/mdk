//! Per-account activation provenance, independent of sender authorization.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::ConnectorError;

#[derive(Clone)]
pub(crate) struct AgentCreatedGroupsStore {
    pub(crate) dir: PathBuf,
    lock: Arc<Mutex<()>>,
}

#[derive(Default, Serialize, Deserialize)]
struct AgentCreatedGroupsRecord {
    account_id_hex: String,
    group_ids_hex: BTreeSet<String>,
}

impl AgentCreatedGroupsStore {
    pub(crate) fn new(home: &Path) -> Self {
        Self {
            dir: home.join("dev").join("agent-created-groups"),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn contains(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<bool, ConnectorError> {
        let account_id_hex = crate::validation::normalize_hex(account_id_hex)?;
        let group_id_hex = crate::validation::normalize_hex(group_id_hex)?;
        let _guard = crate::lock_recover(&self.lock);
        Ok(self
            .read_record(&account_id_hex)?
            .group_ids_hex
            .contains(&group_id_hex))
    }

    pub(crate) fn add(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<(), ConnectorError> {
        let account_id_hex = crate::validation::normalize_hex(account_id_hex)?;
        let group_id_hex = crate::validation::normalize_hex(group_id_hex)?;
        let _guard = crate::lock_recover(&self.lock);
        let mut record = self.read_record(&account_id_hex)?;
        record.group_ids_hex.insert(group_id_hex);
        self.write_record(&record)
    }

    pub(crate) fn remove(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
    ) -> Result<(), ConnectorError> {
        let account_id_hex = crate::validation::normalize_hex(account_id_hex)?;
        let group_id_hex = crate::validation::normalize_hex(group_id_hex)?;
        let _guard = crate::lock_recover(&self.lock);
        let mut record = self.read_record(&account_id_hex)?;
        if record.group_ids_hex.remove(&group_id_hex) {
            self.write_record(&record)?;
        }
        Ok(())
    }

    fn write_record(&self, record: &AgentCreatedGroupsRecord) -> Result<(), ConnectorError> {
        let account_id_hex = &record.account_id_hex;
        let bytes = serde_json::to_vec_pretty(record)?;
        fs_private::create_dir_all_private(&self.dir)?;
        let path = self.dir.join(format!("{account_id_hex}.json"));
        let temp_path = self.dir.join(format!(".{account_id_hex}.json.tmp"));
        let result = (|| {
            fs_private::write_private(&temp_path, &bytes)?;
            std::fs::rename(&temp_path, &path)?;
            std::fs::File::open(&self.dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        Ok(result?)
    }

    fn read_record(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentCreatedGroupsRecord, ConnectorError> {
        let path = self.dir.join(format!("{account_id_hex}.json"));
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<AgentCreatedGroupsRecord>(&bytes) {
                Ok(record) if record.account_id_hex == account_id_hex => return Ok(record),
                _ => {
                    tracing::warn!(
                        target: "agent_connector",
                        method = "agent_created_groups_read_record",
                        error_code = "invalid_agent_created_groups_record",
                        "ignoring invalid activation provenance record"
                    );
                }
            },
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        // Missing, corrupt, or relocated records must never enable activation.
        Ok(AgentCreatedGroupsRecord {
            account_id_hex: account_id_hex.to_owned(),
            ..Default::default()
        })
    }
}
