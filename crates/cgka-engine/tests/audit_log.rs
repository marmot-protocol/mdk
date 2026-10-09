//! Forensic audit log — recorder wiring + JSONL round-trip integration tests.
//!
//! Verifies that:
//!   1. An engine built with a `JsonlRecorder` emits ordered, parseable
//!      `AuditEvent` records to disk.
//!   2. The minimum set of event kinds for a single inbound ingest fire
//!      (`IngestEntry` + `IngestOutcome`).
//!   3. Default engine construction (no recorder) is a no-op — the audit
//!      paths cost nothing when forensics is off.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_traits::CgkaEngine;
use cgka_traits::engine::{CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use marmot_forensics::{
    AuditEvent, AuditEventContext, AuditEventKind, AuditHumanActionContext, AuditTransportContext,
    AuditTransportWire, JsonlRecorder,
};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

fn valid_identity(seed: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

struct StubPeeler;

#[async_trait]
impl TransportPeeler for StubPeeler {
    async fn peel_group_message(
        &self,
        _msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn peel_welcome(&self, _msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_group_message(
        &self,
        _payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }

    async fn wrap_welcome(
        &self,
        _payload: &EncryptedPayload,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Backend("test peeler".into()))
    }
}

fn synthetic_welcome_for(recipient: MemberId, msg_id_byte: u8) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(vec![msg_id_byte; 16]),
        payload: vec![1, 2, 3, 4],
        timestamp: Timestamp(0),
        causal_deps: Vec::new(),
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::Welcome { recipient },
    }
}

#[tokio::test]
async fn audit_log_records_ingest_entry_and_outcome_via_jsonl() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let recorder = JsonlRecorder::open(&path, "test-engine-abc".to_string()).unwrap();

    let identity = valid_identity(b"self");
    let mut engine = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
        .identity(identity)
        .account_identity_proof_signer(proof_signer(b"self"))
        .peeler(Box::new(StubPeeler))
        .recorder(Box::new(recorder))
        .build()
        .expect("build engine with recorder");

    // Welcome addressed to someone else → engine takes the `NotForThisClient`
    // path without invoking the peeler. Two audit events expected:
    //   - IngestEntry (msg shape captured)
    //   - IngestOutcome (Stale / NotForThisClient)
    let foreign = MemberId::new(vec![0x33; 32]);
    let msg = synthetic_welcome_for(foreign, 0xaa);
    let outcome = engine.ingest(msg).await.expect("ingest");
    assert!(
        matches!(
            outcome,
            IngestOutcome::Ignored {
                category: cgka_traits::ingest::InputRejectionCategory::WrongRecipient
            }
        ),
        "expected NotForThisClient stale, got {outcome:?}"
    );

    // Drop the engine so the JsonlRecorder flushes on Drop.
    drop(engine);

    let contents = std::fs::read_to_string(&path).expect("read audit log");
    let events: Vec<AuditEvent> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse audit event"))
        .collect();

    assert!(
        !events.is_empty(),
        "audit log should contain at least one event"
    );

    // Schema + engine identity stable across every record.
    for (i, event) in events.iter().enumerate() {
        assert_eq!(
            event.schema_version,
            marmot_forensics::AUDIT_LOG_SCHEMA_VERSION,
            "event {i} schema mismatch"
        );
        assert_eq!(event.engine_id, "test-engine-abc", "event {i} engine_id");
    }

    // Monotonic seq from 0.
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.seq, i as u64, "event {i} seq mismatch");
    }

    // The first two events should be IngestEntry + IngestOutcome for the
    // welcome we sent in.
    let entry = events
        .iter()
        .find(|e| matches!(e.kind, AuditEventKind::IngestEntry { .. }))
        .expect("IngestEntry not recorded");
    match &entry.kind {
        AuditEventKind::IngestEntry {
            msg_id,
            envelope_kind,
            payload_len,
            ..
        } => {
            assert_eq!(envelope_kind, "welcome");
            assert_eq!(*payload_len, 4);
            assert_eq!(msg_id.len(), 32, "msg_id should be 16-byte hex (32 chars)");
        }
        _ => unreachable!(),
    }

    let outcome_event = events
        .iter()
        .find(|e| matches!(e.kind, AuditEventKind::IngestOutcome { .. }))
        .expect("IngestOutcome not recorded");
    match &outcome_event.kind {
        AuditEventKind::IngestOutcome {
            outcome_kind,
            stale_reason,
            ..
        } => {
            assert_eq!(outcome_kind, "ignored");
            assert_eq!(stale_reason.as_deref(), Some("wrong_recipient"));
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn epoch_confirmed_inherits_operation_human_action() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let recorder = JsonlRecorder::open(&path, "test-engine-epoch".to_string()).unwrap();

    let identity = valid_identity(b"self");
    let mut engine = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
        .identity(identity)
        .account_identity_proof_signer(proof_signer(b"self"))
        .peeler(Box::new(StubPeeler))
        .recorder(Box::new(recorder))
        .build()
        .expect("build engine with recorder");

    // `epoch_confirmed` is emitted on the later confirm call, after the engine's
    // ambient context clears, so it must inherit the staging operation's action.
    let audit_context = AuditEventContext {
        human_action: Some(AuditHumanActionContext {
            action: "create_group".into(),
            origin: "local_user".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let (_group_id, send_result) = engine
        .create_group_with_audit_context(
            CreateGroupRequest {
                name: "g".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            },
            Some(audit_context),
        )
        .await
        .expect("create group");
    let SendResult::GroupCreated { pending, .. } = send_result else {
        panic!("expected GroupCreated send result");
    };
    engine.confirm_published(pending).await.expect("confirm");
    drop(engine);

    let events: Vec<AuditEvent> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    let epoch_confirmed = events
        .iter()
        .find(|event| matches!(event.kind, AuditEventKind::EpochConfirmed { .. }))
        .expect("epoch_confirmed should be recorded");
    let human_action = epoch_confirmed
        .context
        .as_ref()
        .and_then(|ctx| ctx.human_action.as_ref())
        .expect("epoch_confirmed should inherit the operation's human_action");
    assert_eq!(human_action.action, "create_group");
    assert_eq!(human_action.origin, "local_user");

    let state_rows = events
        .iter()
        .filter(|event| matches!(event.kind, AuditEventKind::EpochStateChanged { .. }))
        .collect::<Vec<_>>();
    assert!(
        state_rows.iter().any(|event| {
            matches!(
                &event.kind,
                AuditEventKind::EpochStateChanged {
                    new_state,
                    reason,
                    ..
                } if new_state == "pending_publish" && reason == "begin_pending"
            )
        }),
        "begin_pending state transition should be recorded"
    );
    let confirmed_state = state_rows
        .iter()
        .find(|event| {
            matches!(
                &event.kind,
                AuditEventKind::EpochStateChanged {
                    new_state,
                    reason,
                    ..
                } if new_state == "stable" && reason == "publish_confirmed"
            )
        })
        .expect("publish_confirmed state transition should be recorded");
    let state_human_action = confirmed_state
        .context
        .as_ref()
        .and_then(|ctx| ctx.human_action.as_ref())
        .expect("epoch_state_changed should inherit the operation's human_action");
    assert_eq!(state_human_action.action, "create_group");
    assert_eq!(state_human_action.origin, "local_user");
}

#[tokio::test]
async fn engine_without_recorder_is_silent_and_does_not_crash() {
    // No recorder configured -> NoopRecorder. Engine should function normally
    // and emit zero side effects.
    let identity = valid_identity(b"self");
    let mut engine = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
        .identity(identity)
        .account_identity_proof_signer(proof_signer(b"self"))
        .peeler(Box::new(StubPeeler))
        .build()
        .expect("build engine without recorder");

    let foreign = MemberId::new(vec![0x33; 32]);
    let msg = synthetic_welcome_for(foreign, 0xbb);
    let outcome = engine.ingest(msg).await.expect("ingest");
    assert!(matches!(
        outcome,
        IngestOutcome::Ignored {
            category: cgka_traits::ingest::InputRejectionCategory::WrongRecipient
        }
    ));
}

#[tokio::test]
async fn audit_log_records_transport_received_before_ingest_entry() {
    // Requirement #8: when the transport layer supplies a wire envelope, the
    // engine records a `transport_received` row carrying it before `ingest_entry`
    // for the same message.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let recorder = JsonlRecorder::open(&path, "test-engine-wire".to_string()).unwrap();

    let identity = valid_identity(b"self");
    let mut engine = EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .legacy_compatibility_profile()
        .identity(identity)
        .account_identity_proof_signer(proof_signer(b"self"))
        .peeler(Box::new(StubPeeler))
        .recorder(Box::new(recorder))
        .build()
        .expect("build engine with recorder");

    let foreign = MemberId::new(vec![0x44; 32]);
    let msg = synthetic_welcome_for(foreign, 0xbb);
    let wire = AuditTransportWire {
        transport: Some("nostr".into()),
        delivery_plane: Some("account_inbox".into()),
        wire_id: Some("a".repeat(64)),
        wire_kind: Some("1059".into()),
        wire_pubkey_hex: Some("b".repeat(64)),
        relay_url: Some("wss://relay.example".into()),
        subscription_id: Some("sub-xyz".into()),
        nostr_event_id: Some("a".repeat(64)),
        nostr_kind: Some(1059),
        nostr_pubkey_hex: Some("b".repeat(64)),
        gift_wrap_event_id: Some("a".repeat(64)),
        ..Default::default()
    };
    let transport_context = AuditTransportContext {
        transport_source: "nostr".into(),
        delivery_plane: Some("account_inbox".into()),
        relay_url: Some("wss://relay.example".into()),
        subscription_id: Some("sub-xyz".into()),
        wire: Some(wire),
    };
    engine
        .ingest_with_audit_context(msg, Some(transport_context))
        .await
        .expect("ingest");
    drop(engine);

    let events: Vec<AuditEvent> = std::fs::read_to_string(&path)
        .expect("read audit log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse audit event"))
        .collect();

    let received_idx = events
        .iter()
        .position(|e| matches!(e.kind, AuditEventKind::TransportReceived { .. }))
        .expect("transport_received not recorded");
    let entry_idx = events
        .iter()
        .position(|e| matches!(e.kind, AuditEventKind::IngestEntry { .. }))
        .expect("ingest_entry not recorded");
    assert!(
        received_idx < entry_idx,
        "transport_received must precede ingest_entry"
    );

    match &events[received_idx].kind {
        AuditEventKind::TransportReceived {
            msg_id,
            transport,
            payload_len,
            payload_digest,
        } => {
            assert!(msg_id.is_some());
            assert_eq!(transport.wire_kind.as_deref(), Some("1059"));
            assert_eq!(transport.nostr_kind, Some(1059));
            assert_eq!(
                transport.nostr_event_id.as_deref(),
                Some("a".repeat(64).as_str())
            );
            assert_eq!(
                transport.gift_wrap_event_id.as_deref(),
                Some("a".repeat(64).as_str())
            );
            assert_eq!(*payload_len, 4);
            assert_eq!(payload_digest.len(), 64, "payload_digest is a SHA-256 hex");
        }
        _ => unreachable!(),
    }
}

/// Queued logical sends retain their audit identity when a fresh engine prepares
/// their wire artifacts, without representing queue IDs as published messages.
#[tokio::test]
async fn queued_application_audit_correlates_preparation_after_restart() {
    use cgka_traits::{MarmotAppEvent, SendIntent};
    use marmot_forensics::v5::{BuildProfile, Platform, Producer, Record};
    use storage_sqlite::SqlCipherKey;
    use support::epoch_sealed_peeler::EpochSealedPeeler;

    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("account.sqlite");
    let audit_path = dir.path().join("audit.jsonl");
    let key = SqlCipherKey::new("audit-correlation-fixture-key").unwrap();
    let identity = valid_identity(b"queued-audit");
    let build = || {
        let recorder = JsonlRecorder::open_v5_with_account_ref(
            &audit_path,
            "11".repeat(16),
            Some("22".repeat(16)),
            Producer {
                mdk_revision: None,
                build_profile: BuildProfile::Debug,
                platform: Platform::Other,
                host_build: None,
            },
        )
        .unwrap();
        EngineBuilder::new(SqliteAccountStorage::open_encrypted(&db_path, &key).unwrap())
            .legacy_compatibility_profile()
            .identity(identity.clone())
            .account_identity_proof_signer(proof_signer(b"queued-audit"))
            .peeler(Box::new(EpochSealedPeeler))
            .recorder(Box::new(recorder))
            .build()
            .unwrap()
    };
    let mut engine = build();
    let (group_id, created) = engine
        .create_group(CreateGroupRequest {
            name: "audit fixture".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("expected legacy group creation");
    };
    engine.confirm_published(pending).await.unwrap();
    let first = MarmotAppEvent::new(hex::encode(&identity), 1, 9, vec![], "private-first");
    let second = MarmotAppEvent::new(hex::encode(&identity), 2, 9, vec![], "private-second");
    for event in [&first, &second] {
        assert!(matches!(
            engine
                .queue_app_message(group_id.clone(), event.encode().unwrap())
                .await
                .unwrap(),
            SendResult::Queued { .. }
        ));
    }
    drop(engine);
    let mut engine = build();
    engine.hydrate_all_stored_groups().unwrap();
    let prepared = engine
        .converge_and_drain_queued_outbound_intents(&group_id, u64::MAX / 2)
        .await
        .unwrap();
    assert_eq!(prepared.len(), 2, "both retained sends must prepare");
    let wire_ids: Vec<_> = prepared
        .iter()
        .map(|result| match result {
            SendResult::ApplicationMessage { msg, .. } => hex::encode(msg.id.as_slice()),
            _ => panic!("expected application message"),
        })
        .collect();
    // A separate direct send in the fresh engine cannot alias the earlier
    // process's first send, even though its operation counter starts over.
    let third = MarmotAppEvent::new(hex::encode(&identity), 3, 9, vec![], "private-third");
    engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: third.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap();
    assert!(matches!(
        engine
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: b"malformed-private-fixture".to_vec(),
                expected_epoch: None,
            })
            .await,
        Err(cgka_traits::EngineError::InvalidAppMessagePayload(_))
    ));
    drop(engine);

    let contents = std::fs::read_to_string(&audit_path).unwrap();
    for sensitive in [
        first.id.as_str(),
        second.id.as_str(),
        third.id.as_str(),
        "private-first",
        "private-second",
        "private-third",
        "malformed-private-fixture",
        &hex::encode(&identity),
        &hex::encode(group_id.as_slice()),
    ] {
        assert!(
            !contents.contains(sensitive),
            "audit must redact fixture identities/content"
        );
    }
    let rows: Vec<serde_json::Value> = contents
        .lines()
        .map(|line| {
            Record::from_json(line.as_bytes()).expect("strict v5 record");
            serde_json::from_str(line).unwrap()
        })
        .collect();
    let outcomes: Vec<_> = rows
        .iter()
        .filter(|row| row["event"]["type"] == "send_outcome")
        .collect();
    let queued: Vec<_> = outcomes
        .iter()
        .filter(|row| row["event"]["result_kind"] == "queued")
        .collect();
    let application: Vec<_> = outcomes
        .iter()
        .filter(|row| row["event"]["result_kind"] == "application_message")
        .collect();
    assert_eq!(queued.len(), 2);
    assert_eq!(
        application.len(),
        3,
        "queued regeneration must emit a preparation outcome"
    );
    let operation = |row: &serde_json::Value| {
        row["event"]["record_context"]["operation_ref"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_ne!(operation(queued[0]), operation(queued[1]));
    let entries: Vec<_> = rows
        .iter()
        .filter(|row| row["event"]["type"] == "send_entry")
        .collect();
    assert_eq!(operation(entries[0]), operation(queued[0]));
    assert_eq!(operation(entries[1]), operation(queued[1]));
    for index in 0..2 {
        assert_eq!(operation(queued[index]), operation(application[index]));
        assert!(
            queued[index]["event"]["outbound_messages"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        assert_eq!(
            application[index]["event"]["outbound_messages"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let expected_ref = marmot_forensics::v5::EngineMessageRef::from_message_id(
            &hex::decode(&wire_ids[index]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            application[index]["event"]["outbound_messages"][0]["message_ref"],
            expected_ref.as_str()
        );
        assert!(
            !contents.contains(&wire_ids[index]),
            "wire IDs must remain opaque"
        );
    }
    assert_ne!(operation(queued[0]), operation(application[2]));
    assert_ne!(operation(queued[1]), operation(application[2]));
}
