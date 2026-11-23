//! Durable per-account inbound delivery marks (mdk#3551).
//!
//! A mark is the `insert_order` of the last stored row a `SubscribeInbound` scope has been
//! handed, or passed over because it is not for the agent. Rows stored after it, for example
//! while no subscriber was attached during a gateway restart, are delivered to the next
//! subscriber of that scope. A scope is every group of the account, or one group when the
//! subscription names it. Without a usable mark, the rows received from a point in time on are
//! undelivered instead: from when the subscription began for a scope that never had one, and
//! from when an unreadable record was last written, so its loss does not skip the backlog.
//!
//! The marks live in the account directory, beside the database whose positions they name, so
//! wiping the account removes them with it and a re-imported identity starts afresh.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use marmot_account::AccountHome;
use serde::{Deserialize, Serialize};

use crate::error::ConnectorError;

const INBOUND_MARKS_FILE: &str = "agent-inbound-marks.json";

/// Where a scope's undelivered rows start.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InboundMark {
    /// The rows stored after this `insert_order`.
    After(i64),
    /// The rows received at or after this time, in unix seconds; `None` for the time the
    /// subscription began.
    ReceivedSince(Option<u64>),
}

#[derive(Clone)]
pub(crate) struct InboundMarks {
    account_home: AccountHome,
    lock: Arc<Mutex<()>>,
}

#[derive(Default, Serialize, Deserialize)]
struct InboundMarksRecord {
    /// The mark of subscriptions that cover every group of the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    all_groups: Option<i64>,
    /// The marks of subscriptions scoped to one group, by group id hex.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    groups: BTreeMap<String, i64>,
    /// When this record replaced an unreadable one, when that one was last written: a scope with
    /// no mark here may have had one there, so its rows are undelivered from that time on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lost_since: Option<u64>,
}

impl InboundMarksRecord {
    fn mark(&self, group_id_hex: Option<&str>) -> Option<i64> {
        match group_id_hex {
            None => self.all_groups,
            Some(group_id_hex) => self.groups.get(group_id_hex).copied(),
        }
    }
}

impl InboundMarks {
    pub(crate) fn new(account_home: AccountHome) -> Self {
        Self {
            account_home,
            lock: Arc::new(Mutex::new(())),
        }
    }

    /// Where the scope's undelivered rows start. A read error is returned and changes nothing,
    /// so the next read can still find the mark.
    pub(crate) fn get(
        &self,
        account_label: &str,
        group_id_hex: Option<&str>,
    ) -> Result<InboundMark, ConnectorError> {
        let _guard = crate::lock_recover(&self.lock);
        let Some(bytes) = self.read(account_label)? else {
            return Ok(InboundMark::ReceivedSince(None));
        };
        let Ok(record) = serde_json::from_slice::<InboundMarksRecord>(&bytes) else {
            tracing::warn!(
                target: "agent_connector",
                method = "inbound_marks_get",
                error_code = "invalid_inbound_marks_record",
                "inbound delivery marks record is unreadable; delivering what arrived since it was written"
            );
            return Ok(InboundMark::ReceivedSince(self.written_at(account_label)));
        };
        Ok(match record.mark(group_id_hex) {
            Some(mark) => InboundMark::After(mark),
            None => InboundMark::ReceivedSince(record.lost_since),
        })
    }

    /// Moves the scope's mark forward to `insert_order`, creating it when absent. A mark never
    /// moves back, so concurrent subscribers of one scope cannot rewind each other.
    pub(crate) fn advance(
        &self,
        account_label: &str,
        group_id_hex: Option<&str>,
        insert_order: i64,
    ) -> Result<(), ConnectorError> {
        let _guard = crate::lock_recover(&self.lock);
        let mut record = match self.read(account_label)? {
            None => InboundMarksRecord::default(),
            Some(bytes) => serde_json::from_slice::<InboundMarksRecord>(&bytes).unwrap_or_else(
                // Replace an unreadable record, keeping when it was last written for its other
                // scopes, as `get` does for this one.
                |_| InboundMarksRecord {
                    lost_since: self.written_at(account_label),
                    ..InboundMarksRecord::default()
                },
            ),
        };
        if record
            .mark(group_id_hex)
            .is_some_and(|mark| mark >= insert_order)
        {
            return Ok(());
        }
        match group_id_hex {
            None => record.all_groups = Some(insert_order),
            Some(group_id_hex) => {
                record.groups.insert(group_id_hex.to_owned(), insert_order);
            }
        }
        // Never create the account directory: a mark written after the account was wiped
        // fails rather than leaving a stray directory behind.
        let dir = self.account_home.account_dir(account_label);
        let path = self.path(account_label);
        let temp_path = dir.join(format!(".{INBOUND_MARKS_FILE}.tmp"));
        let bytes = serde_json::to_vec_pretty(&record)?;
        let result = (|| {
            fs_private::write_private(&temp_path, &bytes)?;
            std::fs::rename(&temp_path, &path)?;
            std::fs::File::open(&dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        Ok(result?)
    }

    fn path(&self, account_label: &str) -> std::path::PathBuf {
        self.account_home
            .account_dir(account_label)
            .join(INBOUND_MARKS_FILE)
    }

    /// When the record was last written, in unix seconds.
    fn written_at(&self, account_label: &str) -> Option<u64> {
        let modified = std::fs::metadata(self.path(account_label))
            .and_then(|metadata| metadata.modified())
            .ok()?;
        Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs())
    }

    fn read(&self, account_label: &str) -> Result<Option<Vec<u8>>, ConnectorError> {
        match std::fs::read(self.path(account_label)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}
