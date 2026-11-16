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
}
