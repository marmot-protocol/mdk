//! Per-account welcomer allowlist store with atomic, permission-hardened persistence.

use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use std::fs::{File, OpenOptions};

use serde::{Deserialize, Serialize};

use crate::ALLOWLIST_DIR;
use crate::error::ConnectorError;

#[derive(Clone)]
pub(crate) struct AllowlistStore {
    pub(crate) dir: PathBuf,
    lock: Arc<Mutex<()>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct AllowlistRecord {
    pub(crate) account_id_hex: String,
    pub(crate) welcomer_account_ids_hex: Vec<String>,
}

impl AllowlistStore {
    pub(crate) fn new(home: &Path) -> Self {
        Self {
            dir: home.join("dev").join(ALLOWLIST_DIR),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) fn list(&self, account_id_hex: &str) -> Result<Vec<String>, ConnectorError> {
        let _guard = self.lock.lock().expect("allowlist lock poisoned");
        Ok(self.read_record(account_id_hex)?.welcomer_account_ids_hex)
    }

    pub(crate) fn add(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let _guard = self.lock.lock().expect("allowlist lock poisoned");
        let mut record = self.read_record(account_id_hex)?;
        record
            .welcomer_account_ids_hex
            .push(welcomer_account_id_hex.to_owned());
        normalize_allowlist(&mut record.welcomer_account_ids_hex);
        self.write_record(&record)?;
        Ok(record.welcomer_account_ids_hex)
    }

    pub(crate) fn remove(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let _guard = self.lock.lock().expect("allowlist lock poisoned");
        let mut record = self.read_record(account_id_hex)?;
        record
            .welcomer_account_ids_hex
            .retain(|existing| existing != welcomer_account_id_hex);
        normalize_allowlist(&mut record.welcomer_account_ids_hex);
        self.write_record(&record)?;
        Ok(record.welcomer_account_ids_hex)
    }

    pub(crate) fn contains(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<bool, ConnectorError> {
        Ok(self
            .list(account_id_hex)?
            .iter()
            .any(|existing| existing == welcomer_account_id_hex))
    }

    pub(crate) fn read_record(
        &self,
        account_id_hex: &str,
    ) -> Result<AllowlistRecord, ConnectorError> {
        let path = self.record_path(account_id_hex);
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<AllowlistRecord>(&bytes) {
                Ok(record) if record.account_id_hex == account_id_hex => Ok(record),
                Ok(_mismatched) => {
                    tracing::warn!(
                        target: "agent_connector",
                        method = "allowlist_read_record",
                        error_code = "mismatched_allowlist_record",
                        "ignoring allowlist record whose account id does not match its path"
                    );
                    // The on-disk `account_id_hex` disagrees with the path it was read
                    // from (tampered or relocated file). Treat it like a missing record:
                    // never return it as this account's allowlist, so a forged id field
                    // cannot redirect add/remove writes to a different account's file.
                    Ok(Self::empty_record(account_id_hex))
                }
                Err(_err) => {
                    tracing::warn!(
                        target: "agent_connector",
                        method = "allowlist_read_record",
                        error_code = "corrupt_allowlist_record",
                        "ignoring corrupt allowlist record"
                    );
                    // The corrupt bytes are unrecoverable; fail closed as deny-all so the
                    // next successful allowlist update resets the record instead of
                    // wedging invite policy and control operations on a JSON error.
                    Ok(Self::empty_record(account_id_hex))
                }
            },
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(Self::empty_record(account_id_hex)),
            Err(err) => Err(err.into()),
        }
    }

    pub(crate) fn write_record(&self, record: &AllowlistRecord) -> Result<(), ConnectorError> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let path = self.record_path(&record.account_id_hex);
        let temp_path = self.temp_record_path(&record.account_id_hex);
        let bytes = serde_json::to_vec_pretty(record)?;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        if let Err(err) = std::fs::rename(&temp_path, &path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(err.into());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Self::sync_parent_dir(&self.dir)?;
        Ok(())
    }

    pub(crate) fn record_path(&self, account_id_hex: &str) -> PathBuf {
        self.dir.join(format!("{account_id_hex}.json"))
    }

    pub(crate) fn temp_record_path(&self, account_id_hex: &str) -> PathBuf {
        self.dir.join(format!(".{account_id_hex}.json.tmp"))
    }

    fn empty_record(account_id_hex: &str) -> AllowlistRecord {
        AllowlistRecord {
            account_id_hex: account_id_hex.to_owned(),
            welcomer_account_ids_hex: Vec::new(),
        }
    }

    fn sync_parent_dir(dir: &Path) -> Result<(), ConnectorError> {
        File::open(dir)?.sync_all()?;
        Ok(())
    }
}

pub(crate) fn normalize_allowlist(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
