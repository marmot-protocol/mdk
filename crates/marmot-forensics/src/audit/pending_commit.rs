//! Closed vocabulary for the pending-commit row (`pending_commit_changed`,
//! mdk#3460). The kind exists only in audit v5; a v4 recorder drops it (see
//! `AuditEventKind::is_v5_only`).
//!
//! The row records what the publish rows of one of this account's pending
//! group commits cannot show: that the commit went stuck, that a read-back or
//! the account's own echo confirmed it rather than a relay's `OK`, or that it
//! was given up as not delivered.
use serde::{Deserialize, Serialize};

/// How one of this account's pending group commits changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCommitChange {
    /// Past the read-back bound, some relay may hold the commit and none has
    /// acknowledged it: the state the account's host reads as stuck.
    /// Recorded once per commit, when it is first read back.
    Stuck,
    /// It confirmed with no relay's `OK` among its acknowledgements, and a
    /// relay returning it to a read among them.
    ReadBackConfirmed,
    /// It confirmed with only the account's own group subscription receiving
    /// it from its relays among its acknowledgements.
    EchoConfirmed,
    /// The commit reached no relay, and it was rolled back as not delivered.
    GivenUp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEventKind, AuditRecord, ForensicRecorder, JsonlRecorder};
    use crate::v5;

    /// The change enum is a schema-visible catalog: a variant added on one
    /// side only fails here, where the sample-kind catalog tests, which write
    /// one change, would not notice.
    #[test]
    fn v5_schema_tracks_the_pending_commit_change_catalog() {
        use PendingCommitChange as C;
        let changes = [C::Stuck, C::ReadBackConfirmed, C::EchoConfirmed, C::GivenUp];
        // Exhaustiveness guard: a new variant fails to compile here.
        for change in changes {
            match change {
                C::Stuck | C::ReadBackConfirmed | C::EchoConfirmed | C::GivenUp => {}
            }
        }
        let names = changes
            .iter()
            .map(|change| {
                serde_json::to_value(change)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<std::collections::BTreeSet<_>>();
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let defined = schema["$defs"]["Operational_pendingCommitChange"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names, defined);
    }

    /// A pending commit is always a group's: the writer refuses a row that
    /// names none, and so do the schema and the Rust validator a receiver
    /// ports.
    #[test]
    fn a_pending_commit_row_names_its_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::audit::default_v5_jsonl_path(dir.path(), &"11".repeat(16));
        let producer = v5::Producer {
            mdk_revision: None,
            build_profile: v5::BuildProfile::Debug,
            platform: v5::Platform::Other,
            host_build: None,
        };
        let recorder =
            JsonlRecorder::open_v5_with_account_ref(&path, "11".repeat(16), None, producer)
                .unwrap();
        let kind = AuditEventKind::PendingCommitChanged {
            change: PendingCommitChange::GivenUp,
            msg_id: "5c".repeat(32),
            pending_secs: 600,
        };
        recorder.record(AuditRecord::new(None, kind.clone()));
        recorder.record(AuditRecord::new(Some("ab".repeat(16)), kind));
        let written = std::fs::read_to_string(&path).unwrap();
        let rows = written
            .lines()
            .filter(|line| line.contains("pending_commit_changed"))
            .collect::<Vec<_>>();
        let [row] = rows.as_slice() else {
            panic!("only the group's row is written: {rows:?}")
        };
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(row).unwrap();
        assert!(validator.is_valid(&value));
        value["group_ref"] = serde_json::Value::Null;
        assert!(!validator.is_valid(&value));
        assert!(v5::Record::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
