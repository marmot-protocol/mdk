//! Direct application receive remains recoverable when its pending output write fails (mdk#2872).

use super::*;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::message::StoredMessagePayload;
use rusqlite::{Connection, OptionalExtension, types::Value};
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

fn recording_client(
    id: &[u8],
    storage: SqliteAccountStorage,
    path: &std::path::Path,
) -> cgka_engine::Engine<SqliteAccountStorage> {
    let recorder = marmot_forensics::JsonlRecorder::open_v5_with_account_ref(
        path,
        "11".repeat(16),
        Some("22".repeat(16)),
        marmot_forensics::v5::Producer {
            mdk_revision: None,
            build_profile: marmot_forensics::v5::BuildProfile::Debug,
            platform: marmot_forensics::v5::Platform::Other,
            host_build: None,
        },
    )
    .unwrap();
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .unwrap()
}

fn audit_events(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .map(|row| row["event"].clone())
        .collect()
}

fn audit_transitions(path: &std::path::Path, id: &MessageId) -> Vec<serde_json::Value> {
    let reference = marmot_forensics::v5::EngineMessageRef::from_message_id(id.as_slice()).unwrap();
    audit_events(path)
        .into_iter()
        .filter(|event| {
            event["type"] == "message_state_changed" && event["message_ref"] == reference.as_str()
        })
        .collect()
}

fn message_rows(connection: &Connection, group: &GroupId) -> Vec<Vec<Value>> {
    connection
        .prepare(
            "SELECT id, group_id, epoch, state, storage_format, record, payload, deferred_peel
             FROM cgka_messages WHERE group_id = ?1 ORDER BY id",
        )
        .unwrap()
        .query_map([group.as_slice()], |row| {
            (0..8).map(|index| row.get(index)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn assert_received_transitions(path: &std::path::Path, id: &MessageId) {
    let transitions = audit_transitions(path, id);
    assert_eq!(
        transitions.len(),
        2,
        "one committed receive: {transitions:?}"
    );
    assert!(transitions[0].get("previous_state").is_none());
    assert_eq!(transitions[0]["new_state"], "created");
    assert_eq!(transitions[0]["reason"], "persist");
    assert_eq!(transitions[1]["previous_state"], "created");
    assert_eq!(transitions[1]["new_state"], "processed");
    assert_eq!(transitions[1]["reason"], "state_update");
}

async fn application(
    sender: &mut cgka_engine::Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    content: &str,
) -> (TransportMessage, Vec<u8>) {
    let payload = MarmotAppEvent::new(
        hex::encode(sender.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .unwrap();
    let result = sender
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: payload.clone(),
            expected_epoch: Some(sender.epoch_pin(group_id).unwrap()),
        })
        .await
        .unwrap();
    let SendResult::ApplicationMessage { msg, .. } = result else {
        panic!("expected a same-epoch application, got {result:?}");
    };
    (
        TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
        payload,
    )
}

fn open_observer(path: &std::path::Path, key: &SqlCipherKey) -> Connection {
    let connection = Connection::open(path).unwrap();
    open_hardened_sqlcipher(&connection, key, SqlCipherHardening::live_cache()).unwrap();
    connection
}

fn mls_rows(connection: &Connection, group_id: &GroupId) -> Vec<Vec<Value>> {
    let group_key =
        serde_json::to_vec(&openmls::group::GroupId::from_slice(group_id.as_slice())).unwrap();
    connection
        .prepare(
            "SELECT provider_version, label, storage_key, group_key, value
             FROM openmls_values WHERE group_key = ?1 ORDER BY storage_key",
        )
        .unwrap()
        .query_map([group_key], |row| {
            (0..5).map(|index| row.get(index)).collect()
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn observe(
    phase: &str,
    engine: &cgka_engine::Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    connection: &Connection,
    group_id: &GroupId,
    message: &TransportMessage,
    before_mls: &[Vec<Value>],
) {
    let id = MessageId::new(Sha256::digest(&message.payload).to_vec());
    // Read the complete stored row on a distinct SQL connection, including
    // the legacy slot and the authoritative scalar/payload columns.
    let row: Option<Vec<Value>> = connection
        .query_row(
            "SELECT id, group_id, epoch, state, storage_format, record, payload, deferred_peel
             FROM cgka_messages WHERE id = ?1",
            [id.as_slice()],
            |row| (0..8).map(|index| row.get(index)).collect(),
        )
        .optional()
        .unwrap();
    let record = match storage.get_message(&id) {
        Ok(record) => {
            let wire = StoredMessagePayload::decode(&record.payload).unwrap();
            assert_eq!(
                wire.as_openmls_wire(),
                Some(&TransportMessage {
                    id: id.clone(),
                    ..message.clone()
                }),
                "{phase}: retained content must be the original complete wire message"
            );
            let row = row.as_ref().expect("second connection sees retained row");
            assert_eq!(row[0], Value::Blob(record.id.as_slice().to_vec()));
            assert_eq!(row[1], Value::Blob(record.group_id.as_slice().to_vec()));
            assert_eq!(row[2], Value::Integer(record.epoch.0 as i64));
            assert_eq!(row[4], Value::Integer(2));
            assert_eq!(row[5], Value::Null);
            assert_eq!(row[6], Value::Blob(record.payload.clone()));
            assert_eq!(row[7], Value::Null);
            Some(record)
        }
        Err(StorageError::NotFound) => {
            assert!(row.is_none(), "{phase}: no independently committed row");
            None
        }
        Err(error) => panic!("{phase}: row lookup failed: {error:?}"),
    };
    let alias: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM cgka_processed_transport_ids WHERE id = ?1)",
            [message.id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        alias,
        storage.has_processed_transport_id(&message.id).unwrap()
    );
    let pending = storage.list_pending_application_events().unwrap();
    let independent_pending: Vec<GroupEvent> = connection
        .prepare(
            "SELECT record FROM pending_application_events
             ORDER BY message_insert_order, message_id",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|record| serde_json::from_slice(&record.unwrap()).unwrap())
        .collect();
    assert_eq!(independent_pending, pending);
    eprintln!(
        "{phase}: content_state={:?}, wrapper_alias={alias}, pending_outputs={}, durable_mls_changed={}, engine_state={:?}, durable_epoch={:?}",
        record.as_ref().map(|record| record.state),
        pending.len(),
        mls_rows(connection, group_id) != before_mls,
        engine.epoch_state(group_id),
        storage.get_group(group_id).unwrap().epoch,
    );
}

fn collect_and_ack(
    engine: &mut cgka_engine::Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    events: &mut Vec<GroupEvent>,
) {
    let drained = engine.drain_events();
    let delivered: Vec<_> = drained
        .iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived { message_id, .. } => Some(message_id.clone()),
            _ => None,
        })
        .collect();
    storage
        .delete_pending_application_events(&delivered)
        .unwrap();
    events.extend(drained);
}

#[tokio::test]
async fn direct_application_recovers_after_pending_output_write_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receive-output.sqlite");
    let key = SqlCipherKey::raw([0x51; 32]);
    let mut alice = build_selfremove_client(b"alice-receive-output");
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let audit_path = dir.path().join("receive-audit.jsonl");
    let mut bob = recording_client(b"bob-receive-output", storage.clone(), &audit_path);
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "receive output atomicity".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated {
        pending,
        mut welcomes,
    } = result
    else {
        panic!("expected GroupCreated, got {result:?}");
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome = welcomes.remove(0);
    let welcome_id = welcome.id.clone();
    bob.join_welcome(welcome).await.unwrap();
    bob.drain_events();
    storage
        .delete_pending_application_events(&[welcome_id])
        .unwrap();
    let observer = open_observer(&path, &key);

    // A real peer application proves the fixture and the pending-output path
    // work before the single targeted write is refused.
    let (healthy, healthy_payload) = application(&mut alice, &group_id, "healthy control").await;
    let healthy_id = MessageId::new(Sha256::digest(&healthy.payload).to_vec());
    assert!(matches!(
        bob.ingest(healthy).await.unwrap(),
        IngestOutcome::Processed
    ));
    let mut control_events = Vec::new();
    collect_and_ack(&mut bob, &storage, &mut control_events);
    assert_eq!(
        control_events
            .iter()
            .filter(|event| matches!(event,
                GroupEvent::MessageReceived { sender, payload, .. }
                    if sender == &alice.self_id() && payload == &healthy_payload
            ))
            .count(),
        1,
        "healthy control delivers exactly once"
    );
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
    assert_received_transitions(&audit_path, &healthy_id);

    let (original, payload) = application(&mut alice, &group_id, "recover this original").await;
    let content_id = MessageId::new(Sha256::digest(&original.payload).to_vec());
    let before_mls = mls_rows(&observer, &group_id);
    assert!(
        !before_mls.is_empty(),
        "observe real persisted MLS group state"
    );
    observer
        .execute_batch(&format!(
            "CREATE TRIGGER fail_one_application_output BEFORE INSERT ON pending_application_events
         WHEN NEW.message_id = X'{}'
         BEGIN SELECT RAISE(ABORT, 'injected direct application output write failure'); END",
            hex::encode(content_id.as_slice())
        ))
        .unwrap();
    let failed = bob.ingest(original.clone()).await;
    assert!(
        matches!(&failed,
            Err(EngineError::Storage(StorageError::Backend(detail)))
                if detail.contains("injected direct application output write failure")
        ),
        "must reach the intended pending-output write: {failed:?}"
    );
    observe(
        "after failed write",
        &bob,
        &storage,
        &observer,
        &group_id,
        &original,
        &before_mls,
    );
    let content_after_failure = storage.get_message(&content_id);
    let alias_after_failure = storage.has_processed_transport_id(&original.id).unwrap();
    let output_after_failure = storage.list_pending_application_events().unwrap();
    let mls_after_failure = mls_rows(&observer, &group_id);
    assert!(
        audit_transitions(&audit_path, &content_id).is_empty(),
        "rolled-back receive must emit no committed message-state transition"
    );
    assert!(
        audit_events(&audit_path)
            .iter()
            .any(|event| { event["type"] == "ingest_error" && event["error_kind"] == "storage" })
    );
    let mut events = Vec::new();
    collect_and_ack(&mut bob, &storage, &mut events);
    observer
        .execute_batch("DROP TRIGGER fail_one_application_output")
        .unwrap();

    let retry = bob.ingest(original.clone()).await.unwrap();
    eprintln!("same-engine wrapper retry: {retry:?}");
    bob.advance_convergence(&group_id).await.unwrap();
    collect_and_ack(&mut bob, &storage, &mut events);
    observe(
        "after retry and public advance",
        &bob,
        &storage,
        &observer,
        &group_id,
        &original,
        &before_mls,
    );
    assert_received_transitions(&audit_path, &content_id);

    // Release every connection and reopen the actual encrypted database, so
    // an in-memory cache cannot supply the apparent recovery.
    drop(bob);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut bob = recording_client(b"bob-receive-output", storage.clone(), &audit_path);
    bob.hydrate_all_stored_groups().unwrap();
    collect_and_ack(&mut bob, &storage, &mut events);
    let retry = bob.ingest(original.clone()).await.unwrap();
    eprintln!("reopened wrapper retry: {retry:?}");
    bob.advance_convergence(&group_id).await.unwrap();
    collect_and_ack(&mut bob, &storage, &mut events);
    let observer = open_observer(&path, &key);
    observe(
        "after physical reopen and public advance",
        &bob,
        &storage,
        &observer,
        &group_id,
        &original,
        &before_mls,
    );

    let (following, following_payload) =
        application(&mut alice, &group_id, "following message").await;
    assert!(matches!(
        bob.ingest(following).await.unwrap(),
        IngestOutcome::Processed
    ));
    collect_and_ack(&mut bob, &storage, &mut events);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event,
                GroupEvent::MessageReceived { sender, payload, .. }
                    if sender == &alice.self_id() && payload == &following_payload
            ))
            .count(),
        1,
        "following generation remains usable"
    );
    let delivered = events
        .iter()
        .filter(|event| {
            matches!(event,
                GroupEvent::MessageReceived { message_id, sender, payload: actual, .. }
                    if message_id == &content_id && sender == &alice.self_id() && actual == &payload
            )
        })
        .count();
    let invalidated = events
        .iter()
        .filter(|event| {
            matches!(event,
                GroupEvent::AppMessageInvalidated { message_id, .. } if message_id == &content_id
            )
        })
        .count();
    eprintln!(
        "original outcome: delivered={delivered}, invalidated={invalidated}, following_delivered=1"
    );
    assert_eq!(
        delivered, 1,
        "original valid application must remain recoverable after retry and reopen; invalidated={invalidated}"
    );
    assert_eq!(
        invalidated, 0,
        "storage failure cannot invalidate a valid application"
    );
    assert_received_transitions(&audit_path, &content_id);
    assert!(matches!(content_after_failure, Err(StorageError::NotFound)));
    assert!(
        !alias_after_failure,
        "failed receive leaves no processed wrapper alias"
    );
    assert!(output_after_failure.is_empty());
    assert!(
        mls_after_failure == before_mls,
        "failed receive rolls back the complete persisted MLS state"
    );
    assert_eq!(
        storage.get_message(&content_id).unwrap().state,
        MessageState::Processed
    );
    assert!(
        storage
            .list_pending_application_events()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sent_message_audit_waits_for_both_durable_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sent-audit.sqlite");
    let audit_path = dir.path().join("sent-audit.jsonl");
    let key = SqlCipherKey::raw([0x52; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = recording_client(b"alice-sent-audit", storage.clone(), &audit_path);
    let (group, result) = alice
        .create_group(CreateGroupRequest {
            name: "sent audit atomicity".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = result else {
        panic!("expected a legacy founding commit");
    };
    alice.confirm_published(pending).await.unwrap();
    let observer = open_observer(&path, &key);

    let (control, _) = application(&mut alice, &group, "healthy sent control").await;
    let control_content = MessageId::new(Sha256::digest(&control.payload).to_vec());
    assert_ne!(control.id, control_content, "exercise two distinct rows");
    for id in [&control.id, &control_content] {
        let rows = audit_transitions(&audit_path, id);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["new_state"], "sent");
        assert_eq!(storage.get_message(id).unwrap().state, MessageState::Sent);
    }
    let before = message_rows(&observer, &group);
    let states_before = audit_events(&audit_path)
        .iter()
        .filter(|event| event["type"] == "message_state_changed")
        .count();
    observer
        .execute_batch(&format!(
            "CREATE TRIGGER fail_second_sent_row BEFORE INSERT ON cgka_messages
             WHEN NEW.group_id = X'{group_hex}' AND
                  (SELECT COUNT(*) FROM cgka_messages WHERE group_id = NEW.group_id) = {second}
             BEGIN SELECT RAISE(ABORT, 'injected second sent row failure'); END",
            group_hex = hex::encode(group.as_slice()),
            second = before.len() + 1,
        ))
        .unwrap();
    let payload = MarmotAppEvent::new(
        hex::encode(alice.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "retry this sent event",
    )
    .encode()
    .unwrap();
    let failed = alice
        .send(SendIntent::AppMessage {
            group_id: group.clone(),
            payload,
            expected_epoch: Some(alice.epoch_pin(&group).unwrap()),
        })
        .await;
    assert!(
        matches!(&failed, Err(EngineError::Storage(StorageError::Backend(detail)))
            if detail.contains("injected second sent row failure")),
        "must reach the distinct content-marker write: {failed:?}"
    );
    assert_eq!(message_rows(&observer, &group), before);
    let after = audit_events(&audit_path);
    let states_after = after
        .iter()
        .filter(|event| event["type"] == "message_state_changed")
        .count();
    assert_eq!(
        states_after, states_before,
        "neither rolled-back sent row may claim a committed transition"
    );
    assert!(
        after
            .iter()
            .any(|event| { event["type"] == "send_error" && event["error_kind"] == "storage" })
    );
    observer
        .execute_batch("DROP TRIGGER fail_second_sent_row")
        .unwrap();
    let (retry, _) = application(&mut alice, &group, "retry this sent event").await;
    let retry_content = MessageId::new(Sha256::digest(&retry.payload).to_vec());
    assert_ne!(retry.id, retry_content);
    for id in [&retry.id, &retry_content] {
        let rows = audit_transitions(&audit_path, id);
        assert_eq!(rows.len(), 1, "one committed sent row: {rows:?}");
        assert!(rows[0].get("previous_state").is_none());
        assert_eq!(rows[0]["new_state"], "sent");
        assert_eq!(rows[0]["reason"], "persist");
        assert_eq!(storage.get_message(id).unwrap().state, MessageState::Sent);
    }
    let committed = message_rows(&observer, &group);
    assert_eq!(committed.len(), before.len() + 2);
    drop(alice);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let observer = open_observer(&path, &key);
    assert_eq!(message_rows(&observer, &group), committed);
    let mut alice = recording_client(b"alice-sent-audit", storage.clone(), &audit_path);
    alice.hydrate_all_stored_groups().unwrap();
    let (following, _) = application(&mut alice, &group, "following sent control").await;
    assert_eq!(
        storage.get_message(&following.id).unwrap().state,
        MessageState::Sent
    );
    assert_eq!(audit_transitions(&audit_path, &following.id).len(), 1);
}

#[tokio::test]
async fn welcome_state_audit_waits_for_the_callers_outermost_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("nested-audit.jsonl");
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
    let mut alice = recording_client(b"alice-outer-audit", storage.clone(), &audit_path);
    let mut bob = build_selfremove_client(b"bob-outer-audit");
    let (group, result) = alice
        .create_group(CreateGroupRequest {
            name: "outer audit unit".into(),
            description: String::new(),
            members: vec![bob.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = result else {
        panic!("expected a legacy founding Welcome");
    };
    alice.confirm_published(pending).await.unwrap();
    let id = &welcomes[0].id;
    let before = audit_transitions(&audit_path, id);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0]["new_state"], "sent");

    // The public engine call succeeds in an inner transaction, but that does
    // not grant permission to announce the outer transaction's pending write.
    let failed: Result<(), EngineError> = storage.with_transaction(|outer| {
        outer.with_transaction(|_| {
            alice.mark_sent_welcome_delivered(id)?;
            assert_eq!(
                audit_transitions(&audit_path, id),
                before,
                "a successful nested unit is not an outer commit"
            );
            Ok::<_, EngineError>(())
        })?;
        Err(StorageError::Backend("abandon outer audit unit".into()).into())
    });
    assert!(
        matches!(&failed, Err(EngineError::Storage(StorageError::Backend(detail)))
        if detail == "abandon outer audit unit")
    );
    assert_eq!(storage.get_message(id).unwrap().state, MessageState::Sent);
    assert_eq!(audit_transitions(&audit_path, id), before);

    storage
        .with_transaction(|outer| -> Result<(), EngineError> {
            let failed: Result<(), EngineError> =
                outer.with_group_savepoint(&group, "unused", |_| {
                    alice.mark_sent_welcome_delivered(id)?;
                    Err(StorageError::Backend("abandon savepoint audit unit".into()).into())
                });
            assert!(
                matches!(&failed, Err(EngineError::Storage(StorageError::Backend(detail)))
                if detail == "abandon savepoint audit unit")
            );
            assert_eq!(storage.get_message(id)?.state, MessageState::Sent);
            assert_eq!(audit_transitions(&audit_path, id), before);
            outer.with_transaction(|_| alice.mark_sent_welcome_delivered(id))?;
            assert_eq!(
                audit_transitions(&audit_path, id),
                before,
                "even the surviving nested write still waits for outer COMMIT"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(
        storage.get_message(id).unwrap().state,
        MessageState::Processed
    );
    let after = audit_transitions(&audit_path, id);
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(after[1]["previous_state"], "sent");
    assert_eq!(after[1]["new_state"], "processed");
    assert_eq!(after[1]["reason"], "state_update");
}
