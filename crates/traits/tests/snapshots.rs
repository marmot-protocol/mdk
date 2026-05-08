//! Snapshot tests for the cross-boundary value-type surface.
//!
//! Locks in the JSON shape of every type that crosses a seam (transport,
//! peeler, engine API). Wire-level and log-level shape changes break these
//! tests loudly, which is what we want — a deliberate decision rather than
//! silent drift.
//!
//! Run with `cargo insta test` (or `cargo test`); accept changes with
//! `cargo insta review`.

use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, GroupCapabilities, RequirementLevel,
    TransportKind,
};
use cgka_traits::engine::{
    AppMessageInvalidationReason, CommitOrderingKey, CreateGroupRequest, GroupEvent, KeyPackage,
    SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::group::{Group, Member};
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};

fn gid() -> GroupId {
    GroupId::new(vec![0xAA; 4])
}
fn mid() -> MessageId {
    MessageId::new(vec![0xBB; 4])
}
fn mem_id() -> MemberId {
    MemberId::new(b"alice".to_vec())
}

#[test]
fn snapshot_transport_message_group() {
    let msg = TransportMessage {
        id: mid(),
        payload: vec![1, 2, 3],
        timestamp: Timestamp(1717171717),
        causal_deps: vec![mid()],
        source: TransportSource("nostr".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: vec![0xCC; 4],
        },
    };
    insta::assert_json_snapshot!(msg);
}

#[test]
fn snapshot_transport_message_welcome() {
    let msg = TransportMessage {
        id: mid(),
        payload: vec![0xDE, 0xAD],
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("nostr".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: mem_id(),
        },
    };
    insta::assert_json_snapshot!(msg);
}

#[test]
fn snapshot_encrypted_payload() {
    insta::assert_json_snapshot!(EncryptedPayload {
        ciphertext: vec![0xCA; 8],
        aad: vec![0xFE; 4],
    });
}

#[test]
fn snapshot_ingest_outcomes() {
    insta::assert_json_snapshot!("processed", IngestOutcome::Processed);
    insta::assert_json_snapshot!(
        "buffered",
        IngestOutcome::Buffered {
            group_id: gid(),
            epoch: EpochId(1),
        }
    );
    insta::assert_json_snapshot!(
        "stale_already_seen",
        IngestOutcome::Stale {
            reason: StaleReason::AlreadySeen
        }
    );
    insta::assert_json_snapshot!(
        "stale_already_at_epoch",
        IngestOutcome::Stale {
            reason: StaleReason::AlreadyAtEpoch {
                current: EpochId(2),
                msg_epoch: EpochId(1),
            }
        }
    );
    insta::assert_json_snapshot!(
        "stale_not_for_this_client",
        IngestOutcome::Stale {
            reason: StaleReason::NotForThisClient
        }
    );
    insta::assert_json_snapshot!(
        "stale_unknown_group",
        IngestOutcome::Stale {
            reason: StaleReason::UnknownGroup
        }
    );
    insta::assert_json_snapshot!(
        "stale_own_echo",
        IngestOutcome::Stale {
            reason: StaleReason::OwnEcho
        }
    );
    insta::assert_json_snapshot!(
        "stale_peel_failed",
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
    );
}

#[test]
fn snapshot_peeled_message() {
    let p = PeeledMessage {
        id: mid(),
        group_id: Some(gid()),
        sender: Some(mem_id()),
        content: PeeledContent::MlsMessage {
            bytes: vec![0xAB; 4],
        },
        origin: TransportMessage {
            id: mid(),
            payload: vec![],
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        },
    };
    insta::assert_json_snapshot!(p);
}

#[test]
fn snapshot_send_intents() {
    insta::assert_json_snapshot!(
        "intent_app_message",
        SendIntent::AppMessage {
            group_id: gid(),
            payload: b"hello".to_vec(),
        }
    );
    insta::assert_json_snapshot!(
        "intent_invite",
        SendIntent::Invite {
            group_id: gid(),
            key_packages: vec![KeyPackage(vec![0xEF; 4])],
        }
    );
    insta::assert_json_snapshot!("intent_leave", SendIntent::Leave { group_id: gid() });
    insta::assert_json_snapshot!(
        "intent_update_group_data",
        SendIntent::UpdateGroupData {
            group_id: gid(),
            name: Some("new-name".into()),
            description: None,
        }
    );
}

#[test]
fn snapshot_send_results() {
    let app = SendResult::ApplicationMessage {
        msg: TransportMessage {
            id: mid(),
            payload: vec![],
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("t".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        },
    };
    insta::assert_json_snapshot!("result_application_message", app);
    insta::assert_json_snapshot!(
        "result_proposal",
        SendResult::Proposal {
            msg: TransportMessage {
                id: mid(),
                payload: vec![],
                timestamp: Timestamp(0),
                causal_deps: vec![],
                source: TransportSource("t".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![],
                },
            },
        }
    );
    insta::assert_json_snapshot!(
        "result_group_created",
        SendResult::GroupCreated {
            welcomes: vec![],
            pending: PendingStateRef::new(7),
        }
    );
}

#[test]
fn snapshot_group_events() {
    insta::assert_json_snapshot!(
        "event_group_created",
        GroupEvent::GroupCreated { group_id: gid() }
    );
    insta::assert_json_snapshot!(
        "event_message_received",
        GroupEvent::MessageReceived {
            group_id: gid(),
            sender: mem_id(),
            payload: b"hi".to_vec(),
        }
    );
    insta::assert_json_snapshot!(
        "event_app_message_invalidated",
        GroupEvent::AppMessageInvalidated {
            group_id: gid(),
            message_id: mid(),
            epoch: EpochId(2),
            reason: AppMessageInvalidationReason::LosingBranch,
            decrypted_payload_ref: Some("sha256:payload".into()),
        }
    );
    insta::assert_json_snapshot!(
        "event_epoch_changed",
        GroupEvent::EpochChanged {
            group_id: gid(),
            from: EpochId(1),
            to: EpochId(2),
        }
    );
    insta::assert_json_snapshot!(
        "event_fork_recovered",
        GroupEvent::ForkRecovered {
            group_id: gid(),
            source_epoch: EpochId(1),
            recovered_epoch: EpochId(2),
            winner: CommitOrderingKey {
                source_epoch: EpochId(1),
                commit_digest: [0xAA; 32],
            },
            invalidated: CommitOrderingKey {
                source_epoch: EpochId(1),
                commit_digest: [0xBB; 32],
            },
        }
    );
}

#[test]
fn snapshot_capabilities_types() {
    let mut caps = GroupCapabilities::default();
    caps.insert(Capability::Proposal(10));
    caps.insert(Capability::Extension(0xF2EB));
    insta::assert_json_snapshot!("group_capabilities", caps);

    insta::assert_json_snapshot!(
        "feature_required",
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        }
    );
    insta::assert_json_snapshot!(
        "feature_optional",
        CapabilityRequirement {
            requires: Capability::Proposal(0xFF01),
            level: RequirementLevel::Optional,
            description: "reactions",
        }
    );
    insta::assert_json_snapshot!(
        "feature_transport_required",
        CapabilityRequirement {
            requires: Capability::Extension(0xF2EB),
            level: RequirementLevel::TransportRequired {
                transport: TransportKind::Nostr
            },
            description: "nostr metadata",
        }
    );

    insta::assert_json_snapshot!("status_available", FeatureStatus::Available);
    insta::assert_json_snapshot!("status_upgradeable", FeatureStatus::Upgradeable);
    let mut missing = GroupCapabilities::default();
    missing.insert(Capability::Proposal(10));
    insta::assert_json_snapshot!("status_unavailable", FeatureStatus::Unavailable { missing });
}

#[test]
fn snapshot_group_and_member() {
    insta::assert_json_snapshot!(
        "member",
        Member {
            id: mem_id(),
            credential: vec![1, 2, 3],
        }
    );
    insta::assert_json_snapshot!(
        "group",
        Group {
            id: gid(),
            name: "ops".into(),
            description: "for ops talk".into(),
            epoch: EpochId(3),
            members: vec![Member {
                id: mem_id(),
                credential: vec![],
            }],
            required_capabilities: GroupCapabilities::default(),
        }
    );
}

#[test]
fn snapshot_create_group_request() {
    insta::assert_json_snapshot!(
        "create_group_request",
        format!(
            "{:?}",
            CreateGroupRequest {
                name: "demo".into(),
                description: "".into(),
                members: vec![KeyPackage(vec![0xEF; 4])],
                required_features: vec![Feature("self-remove")],
                initial_admins: vec![],
            }
        )
    );
}
