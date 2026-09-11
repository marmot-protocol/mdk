use super::*;
use cgka_traits::group::Group;
use cgka_traits::storage::{GroupStorage, MessageStorage};
use cgka_traits::transport::{Timestamp, TransportSource};
use storage_sqlite::SqliteAccountStorage;

fn graph_fixture(history: u64) -> (SqliteAccountStorage, GroupId, Vec<MessageId>) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let group_id = GroupId::new(vec![1; 16]);
    storage
        .put_group(&Group {
            id: group_id.clone(),
            name: String::new(),
            description: String::new(),
            epoch: EpochId(10),
            members: Vec::new(),
            required_capabilities: Default::default(),
            protocol_profile: ProtocolProfile::Legacy,
            removed: false,
            unrecoverable: false,
            disbanded: None,
            join_epoch: EpochId(0),
        })
        .unwrap();
    let mut admitted = Vec::new();
    storage
        .with_transaction(|storage| {
            for index in 0..history + 20 {
                let id = MessageId::new(index.to_be_bytes().to_vec());
                let retained = index >= history;
                let payload = StoredMessagePayload::raw_transport(TransportMessage {
                    id: id.clone(),
                    payload: vec![42; 4096],
                    timestamp: Timestamp(0),
                    causal_deps: Vec::new(),
                    source: TransportSource("benchmark".into()),
                    envelope: TransportEnvelope::GroupMessage {
                        transport_group_id: vec![0; 32],
                    },
                })
                .encode()
                .unwrap();
                storage.put_message(&MessageRecord {
                    id: id.clone(),
                    group_id: group_id.clone(),
                    epoch: EpochId(if retained { 10 } else { 0 }),
                    state: MessageState::Processed,
                    payload,
                    deferred_peel: None,
                })?;
                if retained {
                    admitted.push(id);
                }
            }
            Ok::<_, StorageError>(())
        })
        .unwrap();
    (storage, group_id, admitted)
}

#[test]
fn graph_seed_read_boundaries() {
    let (storage, group_id, admitted) = graph_fixture(1);
    let mut old = storage
        .get_message(&MessageId::new(0u64.to_be_bytes().to_vec()))
        .unwrap();
    old.payload = vec![0xff];

    // Irrelevant payloads must never be decoded, even when malformed.
    for state in [MessageState::Processed, MessageState::EpochInvalidated] {
        old.state = state;
        storage.put_message(&old).unwrap();
        assert!(seed_stored_openmls_graph_inputs(&storage, &group_id, 10, None).is_ok());
    }
    for state in OPENMLS_GRAPH_INPUT_STATES {
        old.state = state;
        old.epoch = EpochId(if state == MessageState::Processed {
            10
        } else {
            0
        });
        storage.put_message(&old).unwrap();
        // Retained processed witnesses and unresolved history stay readable
        // inputs; malformed bytes in either must still propagate an error.
        assert!(seed_stored_openmls_graph_inputs(&storage, &group_id, 10, None).is_err());
        assert!(seed_stored_openmls_graph_inputs(&storage, &group_id, 10, Some(&admitted)).is_ok());
    }
    assert!(seed_stored_openmls_graph_inputs(&storage, &group_id, 10, Some(&[])).is_ok());
    assert!(
        seed_stored_openmls_graph_inputs(
            &storage,
            &group_id,
            10,
            Some(std::slice::from_ref(&old.id))
        )
        .is_err()
    );
    let mut other_group = storage.get_group(&group_id).unwrap();
    other_group.id = GroupId::new(vec![2; 16]);
    storage.put_group(&other_group).unwrap();
    old.group_id = other_group.id;
    storage.put_message(&old).unwrap();
    assert!(
        seed_stored_openmls_graph_inputs(
            &storage,
            &group_id,
            10,
            Some(std::slice::from_ref(&old.id))
        )
        .is_ok()
    );
    storage.delete_message(&admitted[0]).unwrap();
    assert!(matches!(
        seed_stored_openmls_graph_inputs(&storage, &group_id, 10, Some(&admitted)),
        Err(OpenMlsProjectionError::Storage(_))
    ));
}

#[test]
#[ignore = "manual graph-seeding benchmark"]
fn graph_seed_benchmark() {
    use std::hint::black_box;
    use std::time::Instant;

    let (storage, group_id, ids) = graph_fixture(20_000);
    for (label, members) in [("candidate", None), ("frozen", Some(ids.as_slice()))] {
        let mut samples = Vec::new();
        for _ in 0..9 {
            let start = Instant::now();
            black_box(seed_stored_openmls_graph_inputs(&storage, &group_id, 10, members).unwrap());
            samples.push(start.elapsed());
        }
        samples.sort();
        eprintln!(
            "{label}: median {:?}; 20000 historical + 20 retained, 4096-byte raw payloads, in-memory SQLite",
            samples[4]
        );
    }
}
