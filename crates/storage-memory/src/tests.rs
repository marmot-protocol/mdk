//! Round-trip, snapshot/rollback, and concurrency tests for `MemoryStorage`.
//!
//! Storage is the substrate for engine tests, so these cases cover each
//! storage family directly.

use super::*;
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::engine::SendIntent;

fn gid(n: u8) -> GroupId {
    GroupId::new(vec![n; 4])
}

fn mid(n: u8) -> MessageId {
    MessageId::new(vec![n; 4])
}

fn member_id(n: u8) -> MemberId {
    MemberId::new(vec![n; 4])
}

fn sample_group(id: GroupId, epoch: u64, members: usize) -> Group {
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

fn sample_message(id: MessageId, group_id: GroupId, epoch: u64) -> MessageRecord {
    MessageRecord {
        id,
        group_id,
        epoch: EpochId(epoch),
        state: MessageState::Created,
        payload: vec![0xAA, 0xBB, 0xCC],
    }
}

fn sample_queued_intent(id: MessageId, group_id: GroupId) -> QueuedOutboundIntent {
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

// ── GroupStorage ────────────────────────────────────────────────────────────

#[test]
fn group_roundtrip_preserves_every_field() {
    let store = MemoryStorage::new();
    let g = sample_group(gid(1), 7, 3);
    store.put_group(&g).unwrap();
    assert_eq!(store.get_group(&g.id).unwrap(), g);
}

#[test]
fn group_missing_returns_not_found() {
    let store = MemoryStorage::new();
    assert!(matches!(
        store.get_group(&gid(9)),
        Err(StorageError::NotFound)
    ));
}

#[test]
fn group_delete_cascades_messages_and_caps() {
    let store = MemoryStorage::new();
    let g = sample_group(gid(1), 0, 1);
    store.put_group(&g).unwrap();
    store
        .put_message(&sample_message(mid(1), g.id.clone(), 0))
        .unwrap();
    store
        .save_member_capabilities(&g.id, &g.members[0], GroupCapabilities::default())
        .unwrap();
    store
        .put_queued_outbound_intent(&sample_queued_intent(mid(2), g.id.clone()))
        .unwrap();
    store.delete_group(&g.id).unwrap();
    assert!(store.list_messages(&g.id, EpochId(0)).unwrap().is_empty());
    assert!(
        store
            .list_queued_outbound_intents(&g.id)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .member_capabilities(&g.id, &g.members[0].id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn list_groups_returns_all_ids() {
    let store = MemoryStorage::new();
    store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
    store.put_group(&sample_group(gid(2), 0, 0)).unwrap();
    let mut ids = store.list_groups().unwrap();
    ids.sort_by_key(|g| g.as_slice().to_vec());
    assert_eq!(ids, vec![gid(1), gid(2)]);
}

// ── MessageStorage ──────────────────────────────────────────────────────────

#[test]
fn message_state_transitions() {
    let store = MemoryStorage::new();
    let m = sample_message(mid(1), gid(1), 0);
    store.put_message(&m).unwrap();
    assert_eq!(
        store.get_message(&m.id).unwrap().state,
        MessageState::Created
    );

    store
        .update_message_state(&m.id, MessageState::Retryable)
        .unwrap();
    assert_eq!(
        store.get_message(&m.id).unwrap().state,
        MessageState::Retryable
    );

    store
        .update_message_state(&m.id, MessageState::PeelDeferred)
        .unwrap();
    assert_eq!(
        store.get_message(&m.id).unwrap().state,
        MessageState::PeelDeferred
    );

    store
        .update_message_state(&m.id, MessageState::Processed)
        .unwrap();
    assert_eq!(
        store.get_message(&m.id).unwrap().state,
        MessageState::Processed
    );

    store
        .update_message_state(&m.id, MessageState::Sent)
        .unwrap();
    assert_eq!(store.get_message(&m.id).unwrap().state, MessageState::Sent);
}

#[test]
fn list_messages_filters_by_group_and_epoch() {
    let store = MemoryStorage::new();
    store
        .put_message(&sample_message(mid(1), gid(1), 0))
        .unwrap();
    store
        .put_message(&sample_message(mid(2), gid(1), 5))
        .unwrap();
    store
        .put_message(&sample_message(mid(3), gid(2), 9))
        .unwrap();
    let filtered = store.list_messages(&gid(1), EpochId(3)).unwrap();
    let ids: Vec<_> = filtered.into_iter().map(|m| m.id).collect();
    assert_eq!(ids, vec![mid(2)]);
}

#[test]
fn list_messages_preserves_insert_order_for_replay() {
    let store = MemoryStorage::new();
    store
        .put_message(&sample_message(mid(3), gid(1), 0))
        .unwrap();
    store
        .put_message(&sample_message(mid(1), gid(1), 0))
        .unwrap();
    store
        .put_message(&sample_message(mid(2), gid(1), 0))
        .unwrap();

    let ids: Vec<_> = store
        .list_messages(&gid(1), EpochId(0))
        .unwrap()
        .into_iter()
        .map(|m| m.id)
        .collect();
    assert_eq!(ids, vec![mid(3), mid(1), mid(2)]);
}

// ── OutboundIntentStorage ──────────────────────────────────────────────────

#[test]
fn queued_outbound_intents_are_group_scoped_and_ordered() {
    let store = MemoryStorage::new();
    store
        .put_queued_outbound_intent(&sample_queued_intent(mid(3), gid(1)))
        .unwrap();
    store
        .put_queued_outbound_intent(&sample_queued_intent(mid(1), gid(1)))
        .unwrap();
    store
        .put_queued_outbound_intent(&sample_queued_intent(mid(2), gid(2)))
        .unwrap();

    let ids: Vec<_> = store
        .list_queued_outbound_intents(&gid(1))
        .unwrap()
        .into_iter()
        .map(|queued| queued.id)
        .collect();
    assert_eq!(ids, vec![mid(3), mid(1)]);

    store.delete_queued_outbound_intent(&mid(3)).unwrap();
    let ids: Vec<_> = store
        .list_queued_outbound_intents(&gid(1))
        .unwrap()
        .into_iter()
        .map(|queued| queued.id)
        .collect();
    assert_eq!(ids, vec![mid(1)]);
}

// ── Snapshot / rollback ─────────────────────────────────────────────────────

#[test]
fn snapshot_rollback_restores_group_and_messages() {
    let store = MemoryStorage::new();
    let g0 = sample_group(gid(1), 0, 1);
    store.put_group(&g0).unwrap();
    store
        .put_message(&sample_message(mid(1), g0.id.clone(), 0))
        .unwrap();
    store.create_group_snapshot(&g0.id, "pre-commit").unwrap();

    // Mutate after snapshot.
    let g1 = sample_group(gid(1), 1, 2);
    store.put_group(&g1).unwrap();
    store
        .put_message(&sample_message(mid(2), g0.id.clone(), 1))
        .unwrap();
    store
        .update_message_state(&mid(1), MessageState::Processed)
        .unwrap();

    store
        .rollback_group_to_snapshot(&g0.id, "pre-commit")
        .unwrap();

    assert_eq!(store.get_group(&g0.id).unwrap(), g0);
    let msgs = store.list_messages(&g0.id, EpochId(0)).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].id, mid(1));
    assert_eq!(msgs[0].state, MessageState::Created);
}

#[test]
fn snapshot_rollback_restores_queued_outbound_intents() {
    let store = MemoryStorage::new();
    let g0 = sample_group(gid(1), 0, 1);
    store.put_group(&g0).unwrap();
    store
        .put_queued_outbound_intent(&sample_queued_intent(mid(1), g0.id.clone()))
        .unwrap();
    store.create_group_snapshot(&g0.id, "pre-send").unwrap();

    store.delete_queued_outbound_intent(&mid(1)).unwrap();
    store
        .put_queued_outbound_intent(&sample_queued_intent(mid(2), g0.id.clone()))
        .unwrap();

    store
        .rollback_group_to_snapshot(&g0.id, "pre-send")
        .unwrap();

    let queued = store.list_queued_outbound_intents(&g0.id).unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].id, mid(1));
}

#[test]
fn snapshot_rollback_restores_openmls_memory_values() {
    let store = MemoryStorage::new();
    let g0 = sample_group(gid(1), 0, 1);
    store.put_group(&g0).unwrap();
    store
        .mls_storage()
        .values
        .write()
        .unwrap()
        .insert(b"group-state".to_vec(), b"epoch-0".to_vec());
    store.create_group_snapshot(&g0.id, "pre-commit").unwrap();

    {
        let mut values = store.mls_storage().values.write().unwrap();
        values.insert(b"group-state".to_vec(), b"epoch-1".to_vec());
        values.insert(b"new-secret".to_vec(), b"post-commit".to_vec());
    }

    store
        .rollback_group_to_snapshot(&g0.id, "pre-commit")
        .unwrap();

    let values = store.mls_storage().values.read().unwrap();
    assert_eq!(values.get(b"group-state".as_slice()).unwrap(), b"epoch-0");
    assert!(!values.contains_key(b"new-secret".as_slice()));
}

#[test]
fn rollback_of_missing_snapshot_errors_typed() {
    let store = MemoryStorage::new();
    store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
    assert!(matches!(
        store.rollback_group_to_snapshot(&gid(1), "nope"),
        Err(StorageError::SnapshotMissing(_))
    ));
}

#[test]
fn list_group_snapshots_is_group_scoped_and_sorted() {
    let store = MemoryStorage::new();
    let g1 = sample_group(gid(1), 0, 0);
    let g2 = sample_group(gid(2), 0, 0);
    store.put_group(&g1).unwrap();
    store.put_group(&g2).unwrap();

    store.create_group_snapshot(&g1.id, "z-after").unwrap();
    store.create_group_snapshot(&g2.id, "other-group").unwrap();
    store.create_group_snapshot(&g1.id, "a-before").unwrap();

    assert_eq!(
        store.list_group_snapshots(&g1.id).unwrap(),
        vec!["a-before".to_string(), "z-after".to_string()]
    );
}

#[test]
fn convergence_policy_is_group_scoped_and_snapshot_restored() {
    let store = MemoryStorage::new();
    let g1 = sample_group(gid(1), 0, 0);
    let g2 = sample_group(gid(2), 0, 0);
    store.put_group(&g1).unwrap();
    store.put_group(&g2).unwrap();

    store.put_convergence_policy(&g1.id, b"policy-v1").unwrap();
    store
        .put_convergence_policy(&g2.id, b"other-policy")
        .unwrap();
    store.create_group_snapshot(&g1.id, "policy").unwrap();
    store.put_convergence_policy(&g1.id, b"policy-v2").unwrap();

    store.rollback_group_to_snapshot(&g1.id, "policy").unwrap();

    assert_eq!(
        store.convergence_policy(&g1.id).unwrap(),
        Some(b"policy-v1".to_vec())
    );
    assert_eq!(
        store.convergence_policy(&g2.id).unwrap(),
        Some(b"other-policy".to_vec())
    );
}

// ── AccountDeviceSignerStorage ─────────────────────────────────────────────

#[test]
fn account_device_signer_binding_roundtrip_is_account_scoped() {
    let store = MemoryStorage::new();
    let alice = AccountDeviceSignerBinding {
        marmot_identity: member_id(1),
        mls_signature_public_key: vec![1, 2, 3],
    };
    let bob = AccountDeviceSignerBinding {
        marmot_identity: member_id(2),
        mls_signature_public_key: vec![4, 5, 6],
    };

    store.put_account_device_signer(&alice).unwrap();
    store.put_account_device_signer(&bob).unwrap();

    assert_eq!(
        store.account_device_signer(&member_id(1)).unwrap(),
        Some(alice)
    );
    assert_eq!(
        store.account_device_signer(&member_id(2)).unwrap(),
        Some(bob)
    );
    assert_eq!(store.account_device_signer(&member_id(9)).unwrap(), None);
}

#[test]
fn release_drops_the_snapshot_only() {
    let store = MemoryStorage::new();
    let g = sample_group(gid(1), 0, 0);
    store.put_group(&g).unwrap();
    store.create_group_snapshot(&g.id, "pre-commit").unwrap();
    store.release_group_snapshot(&g.id, "pre-commit").unwrap();
    assert!(matches!(
        store.rollback_group_to_snapshot(&g.id, "pre-commit"),
        Err(StorageError::SnapshotMissing(_))
    ));
    // Group itself is untouched by release.
    assert_eq!(store.get_group(&g.id).unwrap(), g);
}

// ── WelcomeStorage ──────────────────────────────────────────────────────────

#[test]
fn welcome_take_is_one_shot() {
    let store = MemoryStorage::new();
    let w = PendingWelcome {
        message_id: mid(1),
        group_id: gid(1),
        welcome_bytes: vec![1, 2, 3],
    };
    store.put_welcome(&w).unwrap();
    assert_eq!(store.take_welcome(&mid(1)).unwrap(), w);
    assert!(matches!(
        store.take_welcome(&mid(1)),
        Err(StorageError::NotFound)
    ));
}

// ── CapabilityStorage ───────────────────────────────────────────────────────

#[test]
fn feature_registry_roundtrip() {
    let store = MemoryStorage::new();
    let feat = Feature("self-remove");
    let req = CapabilityRequirement {
        requires: Capability::Proposal(10),
        level: RequirementLevel::Required,
        description: "MIP-03",
    };
    store.register_feature(feat.clone(), req.clone()).unwrap();
    assert_eq!(store.feature_requirement(&feat).unwrap(), Some(req));
}

#[test]
fn member_capabilities_per_group_scoped() {
    let store = MemoryStorage::new();
    let mem = Member {
        id: member_id(1),
        credential: vec![],
    };
    let mut caps = GroupCapabilities::default();
    caps.insert(Capability::Proposal(10));

    store
        .save_member_capabilities(&gid(1), &mem, caps.clone())
        .unwrap();

    assert_eq!(
        store.member_capabilities(&gid(1), &mem.id).unwrap(),
        Some(caps)
    );
    // Same member id in a different group is a different entry.
    assert_eq!(store.member_capabilities(&gid(2), &mem.id).unwrap(), None);
}

#[test]
fn member_capabilities_survive_group_delete_in_other_group() {
    let store = MemoryStorage::new();
    let g1 = sample_group(gid(1), 0, 1);
    let g2 = sample_group(gid(2), 0, 1);
    store.put_group(&g1).unwrap();
    store.put_group(&g2).unwrap();
    let caps = GroupCapabilities::default();
    store
        .save_member_capabilities(&g1.id, &g1.members[0], caps.clone())
        .unwrap();
    store
        .save_member_capabilities(&g2.id, &g2.members[0], caps.clone())
        .unwrap();
    store.delete_group(&g1.id).unwrap();
    assert!(
        store
            .member_capabilities(&g1.id, &g1.members[0].id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .member_capabilities(&g2.id, &g2.members[0].id)
            .unwrap()
            .is_some()
    );
}

// ── Concurrency ─────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_put_and_read_under_tokio() {
    let store = MemoryStorage::new();
    let mut handles = Vec::new();
    for i in 0..32u8 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .put_message(&sample_message(mid(i), gid(1), i as u64))
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let all = store.list_messages(&gid(1), EpochId(0)).unwrap();
    assert_eq!(all.len(), 32);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_snapshot_rollback_is_consistent() {
    let store = MemoryStorage::new();
    store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
    store.create_group_snapshot(&gid(1), "s").unwrap();

    // Concurrent puts while snapshot exists.
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            store
                .put_message(&sample_message(mid(i), gid(1), 0))
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    // Rollback should erase every message added after the snapshot.
    store.rollback_group_to_snapshot(&gid(1), "s").unwrap();
    assert!(store.list_messages(&gid(1), EpochId(0)).unwrap().is_empty());
}

// ── Backend accessor ────────────────────────────────────────────────────────

#[test]
fn reports_in_memory_backend() {
    assert_eq!(MemoryStorage::new().backend(), Backend::InMemory);
}
