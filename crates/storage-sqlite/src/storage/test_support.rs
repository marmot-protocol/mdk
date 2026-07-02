use cgka_traits::capabilities::GroupCapabilities;
use cgka_traits::engine::SendIntent;
use cgka_traits::group::{Group, Member};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::QueuedOutboundIntent;
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use openmls_traits::storage::{CURRENT_VERSION, Entity, traits as openmls_storage_traits};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TestGroupState(pub(crate) Vec<u8>);

impl Entity<CURRENT_VERSION> for TestGroupState {}
impl openmls_storage_traits::GroupState<CURRENT_VERSION> for TestGroupState {}

pub(crate) fn gid(n: u8) -> GroupId {
    GroupId::new(vec![n; 4])
}

pub(crate) fn mid(n: u8) -> MessageId {
    MessageId::new(vec![n; 4])
}

pub(crate) fn member_id(n: u8) -> MemberId {
    MemberId::new(vec![n; 4])
}

pub(crate) fn sample_group(id: GroupId, epoch: u64, members: usize) -> Group {
    Group {
        id,
        name: "sample".into(),
        description: "desc".into(),
        epoch: EpochId(epoch),
        members: (0..members as u8)
            .map(|i| Member {
                id: member_id(i),
                credential: vec![i; 8],
            })
            .collect(),
        required_capabilities: GroupCapabilities::default(),
    }
}

pub(crate) fn sample_message(id: MessageId, group_id: GroupId, epoch: u64) -> MessageRecord {
    MessageRecord {
        id,
        group_id,
        epoch: EpochId(epoch),
        state: MessageState::Created,
        payload: vec![0xAA, 0xBB, 0xCC],
    }
}

pub(crate) fn sample_queued_intent(id: MessageId, group_id: GroupId) -> QueuedOutboundIntent {
    QueuedOutboundIntent {
        id,
        group_id: group_id.clone(),
        intent: SendIntent::AppMessage {
            group_id,
            payload: b"queued".to_vec(),
        },
        created_at_ms: 42,
    }
}
