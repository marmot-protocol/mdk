//! Durable per-account inbound delivery marks (mdk#3551).
//!
//! A mark is the `insert_order` of the last stored row a `SubscribeInbound` scope has been
//! handed, or passed over because it is not for the agent. Rows stored after it, for example
//! while no subscriber was attached during a gateway restart, are delivered to the next
//! subscriber of that scope. A scope is every group of the account, or one group when the
//! subscription names it.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::error::ConnectorError;

#[derive(Clone)]
pub(crate) struct InboundMarks {
    dir: PathBuf,
    lock: Arc<Mutex<()>>,
}

#[derive(Default, Serialize, Deserialize)]
struct InboundMarksRecord {
    account_id_hex: String,
    /// The mark of subscriptions that cover every group of the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    all_groups: Option<i64>,
    /// The marks of subscriptions scoped to one group, by group id hex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    groups: BTreeMap<String, i64>,
}

impl InboundMarksRecord {
    fn mark(&mut self, group_id_hex: Option<&str>) -> Option<&mut i64> {
        match group_id_hex {
            None => self.all_groups.as_mut(),
            Some(group_id_hex) => self.groups.get_mut(group_id_hex),
        }
    }
}

impl InboundMarks {
    pub(crate) fn new(home: &Path) -> Self {
        Self {
            dir: home.join("dev").join("inbound-delivered"),
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// The scope's mark, or `None` when it has never had a subscriber.
    pub(crate) fn get(
        &self,
        account_id_hex: &str,
        group_id_hex: Option<&str>,
    ) -> Result<Option<i64>, ConnectorError> {
        let _guard = crate::lock_recover(&self.lock);
        Ok(self
            .read_record(account_id_hex)?
            .mark(group_id_hex)
            .copied())
    }

    /// Moves the scope's mark forward to `insert_order`, creating it when absent. A mark never
    /// moves back, so concurrent subscribers of one scope cannot rewind each other.
    pub(crate) fn advance(
        &self,
        account_id_hex: &str,
        group_id_hex: Option<&str>,
        insert_order: i64,
    ) -> Result<(), ConnectorError> {
        let _guard = crate::lock_recover(&self.lock);
        let mut record = self.read_record(account_id_hex)?;
        match record.mark(group_id_hex) {
            Some(mark) if *mark >= insert_order => return Ok(()),
            Some(mark) => *mark = insert_order,
            None => match group_id_hex {
                None => record.all_groups = Some(insert_order),
                Some(group_id_hex) => {
                    record.groups.insert(group_id_hex.to_owned(), insert_order);
                }
            },
        }
        self.write_record(&record)
    }

    fn write_record(&self, record: &InboundMarksRecord) -> Result<(), ConnectorError> {
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

    fn read_record(&self, account_id_hex: &str) -> Result<InboundMarksRecord, ConnectorError> {
        let path = self.dir.join(format!("{account_id_hex}.json"));
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<InboundMarksRecord>(&bytes) {
                Ok(record) if record.account_id_hex == account_id_hex => return Ok(record),
                _ => {
                    tracing::warn!(
                        target: "agent_connector",
                        method = "inbound_marks_read_record",
                        error_code = "invalid_inbound_marks_record",
                        "ignoring invalid inbound delivery marks record"
                    );
                }
            },
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        // A missing or unreadable record starts every scope afresh at the newest stored row:
        // history is never replayed as new messages.
        Ok(InboundMarksRecord {
            account_id_hex: account_id_hex.to_owned(),
            ..Default::default()
        })
    }
}
