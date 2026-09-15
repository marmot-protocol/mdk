//! Opt-in measurements of negative application-discovery scans on SQLCipher.
use super::*;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest};
use cgka_traits::storage::{GroupStorage, MessageStorage};

thread_local! {
    pub(super) static SCANNED_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[tokio::test]
#[ignore = "measurement: synthetic retained commit prefixes, encrypted file storage"]
async fn measure_negative_application_discovery_prefix() {
    for rows in [0_u64, 100, 1_000, 10_000] {
        let directory = tempfile::tempdir().unwrap();
        let storage = storage_sqlite::SqliteAccountStorage::open_encrypted(
            directory.path().join("account.sqlite"),
            &storage_sqlite::SqlCipherKey::new("synthetic scan measurement").unwrap(),
        )
        .unwrap();
        let mut engine =
            crate::distributed_convergence::tests::test_engine_with_storage(storage.clone());
        let (group, created) = engine
            .create_group(CreateGroupRequest {
                name: "scan measurement".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        if let SendResult::GroupCreated { pending, .. } = created {
            engine.confirm_published(pending).await.unwrap();
        }
        let payload = MarmotAppEvent::new(
            hex::encode(engine.self_id().as_slice()),
            1_700_000_000,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "late",
        )
        .encode()
        .unwrap();
        let SendResult::ApplicationMessage { mut msg, .. } = engine
            .send(SendIntent::AppMessage {
                expected_epoch: None,
                group_id: group.clone(),
                payload,
            })
            .await
            .unwrap()
        else {
            panic!("application");
        };
        msg.id = MessageId::new(vec![0xff; 32]);
        let late = MessageRecord {
            id: msg.id.clone(),
            group_id: group.clone(),
            epoch: engine.epoch(&group).unwrap(),
            state: MessageState::Created,
            payload: StoredMessagePayload::openmls_wire(msg).encode().unwrap(),
            deferred_peel: None,
        };
        let SendResult::GroupEvolution {
            msg: commit,
            pending,
            ..
        } = engine
            .send(SendIntent::SelfUpdate {
                group_id: group.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("commit");
        };
        engine.confirm_published(pending).await.unwrap();
        let encoded = StoredMessagePayload::openmls_wire(commit).encode().unwrap();
        // Synthetic copies isolate read/decode cost, not valid distinct commit
        // generation or end-to-end convergence. Tip metadata is moved only to
        // exercise the pre-decryption BelowAnchor disposition of a late arrival.
        let mut record = storage.get_group(&group).unwrap();
        record.epoch = EpochId(1_000);
        storage.put_group(&record).unwrap();
        storage
            .with_transaction(|store| {
                for index in 0..rows {
                    store.put_message(&MessageRecord {
                        id: MessageId::new(index.to_be_bytes().to_vec()),
                        group_id: group.clone(),
                        epoch: EpochId(0),
                        state: MessageState::ConvergenceDeferred,
                        payload: encoded.clone(),
                        deferred_peel: None,
                    })?;
                }
                Ok::<_, StorageError>(())
            })
            .unwrap();
        SCANNED_ROWS.with(|count| count.set(0));
        let start = std::time::Instant::now();
        for _ in 0..10 {
            assert!(!engine.has_pending_canonical_applications(&group).unwrap());
        }
        let negative_us = start.elapsed().as_micros() / 10;
        let decoded_per_query = SCANNED_ROWS.with(|count| count.get()) / 10;
        assert_eq!(decoded_per_query, rows as usize);
        storage.put_message(&late).unwrap();
        SCANNED_ROWS.with(|count| count.set(0));
        let start = std::time::Instant::now();
        engine
            .drain_canonical_applications(
                &group,
                &mut DeferredPeelExecution::Background {
                    deadline: Some(Instant::now()),
                    rows_remaining: 0,
                },
            )
            .unwrap();
        let late_drain_us = start.elapsed().as_micros();
        let late_drain_rows = SCANNED_ROWS.with(|count| count.get());
        assert_eq!(
            storage.get_message(&late.id).unwrap().state,
            MessageState::EpochInvalidated
        );
        assert!(engine.drain_events().iter().any(|event| matches!(event,
            GroupEvent::AppMessageInvalidated { message_id, reason: cgka_traits::engine::AppMessageInvalidationReason::BeyondAnchor, .. }
            if message_id == &late.id)));
        println!(
            "scan_measurement {}",
            serde_json::json!({
                "prefix_rows": rows, "stored_payload_bytes": encoded.len(),
                "decoded_rows_per_negative_query": decoded_per_query,
                "mean_negative_query_us": negative_us, "late_drain_us": late_drain_us,
                "late_drain_decoded_rows": late_drain_rows,
            })
        );
    }
}
