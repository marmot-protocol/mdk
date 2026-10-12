//! Closed vocabularies for the relay subscription refusal row
//! (`subscription_refused`). The kind exists only in audit v5; a v4 recorder
//! drops it (see `AuditEventKind::is_v5_only`).
//!
//! Each enum mirrors a name the Nostr transport adapter already uses
//! (`SubscriptionRouteKind`, `TransportEndpointRejectionCategory`,
//! `SubscriptionRefusalDisposition`), so a reader can grep from a row value
//! to its producer.
use serde::{Deserialize, Serialize};

/// Largest number of distinct refusals one row carries. Matches the adapter's
/// per-account bound; refusals it shed are counted in the row's `dropped`.
pub const SUBSCRIPTION_REFUSAL_AUDIT_MAX_ENTRIES: usize = 32;

/// Which of the account's live subscriptions the relay refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionRefusalRoute {
    /// The account inbox, which carries gift-wrapped Welcomes.
    Inbox,
    /// A group route, current or retained.
    Group,
    /// A post-join or recovery maintenance subscription.
    Maintenance,
}

/// The machine-readable prefix of the relay's `CLOSED` reason. The reason
/// text itself is never recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionRefusalCategory {
    Duplicate,
    Pow,
    Blocked,
    RateLimited,
    Invalid,
    Error,
    Unsupported,
    AuthRequired,
    Restricted,
    /// No prefix, or one NIP-01 and NIP-42 do not define.
    Unclassified,
}

/// What the relay client did with the refused REQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionRefusalOutcome {
    /// Kept, to send again after authenticating or reconnecting.
    Pending,
    /// Dropped. Reconnecting does not restore it.
    Dropped,
}

/// Repeated refusals of one route kind on one relay, on
/// [`crate::AuditEventKind::SubscriptionRefused`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionRefusalEntry {
    pub route_kind: SubscriptionRefusalRoute,
    /// The refusing relay. v5 records it as a hashed endpoint reference.
    pub relay_url: String,
    pub refusal_category: SubscriptionRefusalCategory,
    pub disposition: SubscriptionRefusalOutcome,
    /// How many times the relay sent this refusal since the last row. At
    /// least one.
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEventKind, AuditRecord, ForensicRecorder, JsonlRecorder};
    use crate::v5;

    fn entry(count: u64) -> SubscriptionRefusalEntry {
        SubscriptionRefusalEntry {
            route_kind: SubscriptionRefusalRoute::Inbox,
            relay_url: "wss://relay.example".into(),
            refusal_category: SubscriptionRefusalCategory::AuthRequired,
            disposition: SubscriptionRefusalOutcome::Dropped,
            count,
        }
    }

    fn refused(refusals: Vec<SubscriptionRefusalEntry>, dropped: u64) -> AuditEventKind {
        AuditEventKind::SubscriptionRefused { refusals, dropped }
    }

    #[test]
    fn strict_writer_refuses_inconsistent_subscription_refusal_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::audit::default_v5_jsonl_path(dir.path(), &"11".repeat(16));
        let recorder = JsonlRecorder::open_v5_with_account_ref(
            &path,
            "11".repeat(16),
            None,
            v5::Producer {
                mdk_revision: None,
                build_profile: v5::BuildProfile::Debug,
                platform: v5::Platform::Other,
                host_build: None,
            },
        )
        .unwrap();
        recorder.record(AuditRecord::new(None, refused(vec![entry(1)], 0)));
        // No refusal, a refusal that never happened, shed refusals while the
        // row still had room, and more entries than the bound: none written.
        recorder.record(AuditRecord::new(None, refused(Vec::new(), 0)));
        recorder.record(AuditRecord::new(None, refused(vec![entry(0)], 0)));
        recorder.record(AuditRecord::new(None, refused(vec![entry(1)], 3)));
        recorder.record(AuditRecord::new(
            None,
            refused(
                vec![entry(1); SUBSCRIPTION_REFUSAL_AUDIT_MAX_ENTRIES + 1],
                0,
            ),
        ));
        // A full row may carry what the bound shed.
        recorder.record(AuditRecord::new(
            None,
            refused(vec![entry(1); SUBSCRIPTION_REFUSAL_AUDIT_MAX_ENTRIES], 3),
        ));
        let written = std::fs::read_to_string(&path).unwrap();
        let rows = written
            .lines()
            .filter(|line| line.contains("subscription_refused"))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 2, "only the consistent rows are written");
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for row in rows {
            assert!(!row.contains("wss://"), "the relay is a hashed reference");
            let value: serde_json::Value = serde_json::from_str(row).unwrap();
            assert!(validator.is_valid(&value));
            assert!(v5::Record::from_json(row.as_bytes()).is_ok());
            assert!(value["event"]["refusals"][0]["endpoint_ref"].is_string());
        }
        assert!(recorder.health_snapshot().serialization_failures >= 4);
    }

    #[test]
    fn v5_schema_tracks_the_subscription_refusal_enum_catalogs() {
        fn names<T: Serialize>(values: &[T]) -> Vec<String> {
            values
                .iter()
                .map(|value| {
                    serde_json::to_value(value)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        }
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let defs = &schema["$defs"];
        let schema_names = |def: &str| -> Vec<String> {
            defs[def]["enum"]
                .as_array()
                .unwrap_or_else(|| panic!("{def} is an enum"))
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect()
        };
        use SubscriptionRefusalCategory as C;
        assert_eq!(
            schema_names("Operational_subscriptionRefusalRoute"),
            names(&[
                SubscriptionRefusalRoute::Inbox,
                SubscriptionRefusalRoute::Group,
                SubscriptionRefusalRoute::Maintenance,
            ])
        );
        assert_eq!(
            schema_names("Operational_subscriptionRefusalCategory"),
            names(&[
                C::Duplicate,
                C::Pow,
                C::Blocked,
                C::RateLimited,
                C::Invalid,
                C::Error,
                C::Unsupported,
                C::AuthRequired,
                C::Restricted,
                C::Unclassified,
            ])
        );
        assert_eq!(
            schema_names("Operational_subscriptionRefusalOutcome"),
            names(&[
                SubscriptionRefusalOutcome::Pending,
                SubscriptionRefusalOutcome::Dropped,
            ])
        );
    }
}
