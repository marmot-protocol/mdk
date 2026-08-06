use crate::codec::SensitiveBytes;
use cgka_traits::capabilities::GroupCapabilities;
#[cfg(feature = "test-conformance-replay")]
use cgka_traits::convergence_pass::DurableConvergencePass;
use cgka_traits::group::Group;
use cgka_traits::message::MessageRecord;
use cgka_traits::storage::QueuedOutboundIntent;
use cgka_traits::types::MemberId;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub(super) group: Group,
    pub(super) messages: Vec<OrderedMessage>,
    pub(super) queued_outbound: Vec<OrderedQueuedOutbound>,
    pub(super) member_caps: Vec<MemberCapabilitiesSnapshot>,
    pub(super) convergence_policy: Option<Vec<u8>>,
    pub(super) validated_tree_marker: Option<Vec<u8>>,
    pub(super) openmls_values: Vec<OpenMlsValueSnapshot>,
}

/// Branch-addressed canonical state.  Unlike `Snapshot`, this deliberately
/// excludes the mutable message ledger, outbound queue, convergence policy,
/// and pass scheduler so selecting a historical branch cannot rewind current
/// operational work.
#[derive(Serialize, Deserialize)]
pub(super) struct GroupStateCheckpoint {
    pub(super) group: Group,
    pub(super) member_caps: Vec<MemberCapabilitiesSnapshot>,
    pub(super) validated_tree_marker: Option<Vec<u8>>,
    pub(super) openmls_values: Vec<OpenMlsValueSnapshot>,
}

/// Test-only envelope for byte-exact convergence replay.
///
/// Ordinary epoch rollback deliberately excludes the durable convergence pass:
/// a rollback must not silently rewind the pass scheduler. A replay checkpoint
/// has different semantics and must reconstruct the scheduler state as well as
/// the group/OpenMLS state that it governs.
#[cfg(feature = "test-conformance-replay")]
pub(super) const REPLAY_SNAPSHOT_VERSION: u32 = 1;

#[cfg(feature = "test-conformance-replay")]
#[derive(Serialize, Deserialize)]
pub(super) struct ReplaySnapshot {
    pub(super) version: u32,
    pub(super) group: Snapshot,
    pub(super) convergence_pass: Option<DurableConvergencePass>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OrderedMessage {
    pub(super) insert_order: i64,
    pub(super) record: MessageRecord,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OrderedQueuedOutbound {
    pub(super) insert_order: i64,
    pub(super) record: QueuedOutboundIntent,
}

#[derive(Serialize, Deserialize)]
pub(super) struct MemberCapabilitiesSnapshot {
    pub(super) member_id: MemberId,
    pub(super) capabilities: GroupCapabilities,
}

#[derive(Serialize, Deserialize)]
pub(super) struct OpenMlsValueSnapshot {
    pub(super) label: Vec<u8>,
    pub(super) storage_key: Vec<u8>,
    pub(super) group_key: Vec<u8>,
    pub(super) value: SensitiveBytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::SensitiveBytes;

    #[test]
    fn openmls_snapshot_values_have_sensitive_ownership() {
        let row = OpenMlsValueSnapshot {
            label: b"EpochSecrets".to_vec(),
            storage_key: b"storage-key".to_vec(),
            group_key: b"group-key".to_vec(),
            value: SensitiveBytes::new(b"secret-json".to_vec()),
        };

        fn assert_sensitive(_: &SensitiveBytes) {}
        assert_sensitive(&row.value);
        assert_eq!(row.value.as_slice(), b"secret-json");
    }
}
