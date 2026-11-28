//! A two-member current-profile group its founder disbands, for tests of what
//! the other member's copy holds before and after the disband settles.

// Shared by every engine test binary; only some disband.
#![allow(dead_code)]

use cgka_engine::{Engine, ManualConvergenceClock};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::types::GroupId;
use storage_sqlite::SqliteAccountStorage;

/// `founder` creates a group with `member`, who joins it.
pub async fn found_and_join(
    founder: &mut Engine<SqliteAccountStorage>,
    member: &mut Engine<SqliteAccountStorage>,
) -> GroupId {
    let (group_id, created) = founder
        .create_group(CreateGroupRequest {
            name: "disbanded".into(),
            description: String::new(),
            members: vec![member.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group");
    };
    let mut welcomes = super::raw_inbox::seal_and_bind(founder, &welcomes);
    super::raw_inbox::join_raw(member, welcomes.remove(0))
        .await
        .unwrap();
    member.drain_events();
    group_id
}

/// `founder`'s disband of `group_id`, published and routed to the group for
/// another member to buffer. A disband is prepared by convergence, so
/// `clock` is `founder`'s convergence clock.
pub async fn published_disband(
    founder: &mut Engine<SqliteAccountStorage>,
    clock: &ManualConvergenceClock,
    group_id: &GroupId,
) -> TransportMessage {
    founder
        .send(SendIntent::Disband {
            group_id: group_id.clone(),
        })
        .await
        .unwrap();
    for _ in 0..8 {
        let sends = founder.advance_convergence(group_id).await.unwrap();
        if let [SendResult::GroupEvolution { msg, pending, .. }] = sends.as_slice() {
            let mut disband = msg.clone();
            founder.confirm_published(*pending).await.unwrap();
            disband.envelope = TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            };
            return disband;
        }
        assert!(sends.is_empty());
        clock.advance_ms(1_000);
    }
    panic!("the disband was never prepared");
}
