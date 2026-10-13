//! Convergence policy v2 end to end over real OpenMLS state (spec
//! protocol-core/convergence.md, "Active policy"; mdk#2259).
//!
//! The scenario is the shape of incident mdk#2254. From a shared epoch:
//! - branch A: one ordinary self-update, then three pre-fork members post on it;
//! - branch B: an admin Add plus a second commit (one deeper), then the admin
//!   and the newly added member post on its tip.
//!
//! Policy v1 rewinds A for B (depth first, quorum from any sender). Policy v2,
//! selected because the group requires `marmot.group.convergence-policy.v2`,
//! keeps A: the invitee was not a member of the shared state, so B never meets
//! quorum, and A is witness-protected. The deciding device is an observer that
//! receives every input at once, so this checks the policy-epoch facts the
//! replay captures, not only the pure selector.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, ActivatableAppComponent, AppComponentId,
    CONVERGENCE_POLICY_V2_COMPONENT_ID, ComponentActivationMode, decode_components_list,
    default_group_components,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

struct MockPeeler;

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                created_at: None,
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: MessageId::new(Sha256::digest(&payload.ciphertext).to_vec()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let mut id_material = payload.ciphertext.clone();
        id_material.extend_from_slice(recipient.as_slice());
        Ok(TransportMessage {
            id: MessageId::new(Sha256::digest(&id_material).to_vec()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

type Client = Engine<SqliteAccountStorage>;

fn client(id: &[u8], v2: bool) -> Client {
    let mut supported: Vec<AppComponentId> = default_group_components().into_iter().collect();
    let mut activatable = Vec::new();
    if v2 {
        supported.push(CONVERGENCE_POLICY_V2_COMPONENT_ID);
        activatable.push(ActivatableAppComponent {
            component_id: CONVERGENCE_POLICY_V2_COMPONENT_ID,
            initial_state: Vec::new(),
            mode: ComponentActivationMode::Automatic,
        });
    }
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .activatable_app_components(activatable)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

fn content_hex(msg: &TransportMessage) -> String {
    hex::encode(Sha256::digest(&msg.payload))
}

fn welcome_for(welcomes: &[TransportMessage], name: &[u8]) -> TransportMessage {
    let recipient = MemberId::new(pad32(name));
    welcomes
        .iter()
        .find(|message| {
            matches!(
                &message.envelope,
                TransportEnvelope::Welcome { recipient: actual } if *actual == recipient
            )
        })
        .expect("welcome exists")
        .clone()
}

/// Send `intent`, confirm it, and return the routed commit and any welcomes.
async fn commit(
    engine: &mut Client,
    group_id: &GroupId,
    intent: SendIntent,
) -> (TransportMessage, Vec<TransportMessage>) {
    match engine.send(intent).await.unwrap() {
        SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } => {
            engine.confirm_published(pending).await.unwrap();
            (route(msg, group_id), welcomes)
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
}

async fn post(engine: &mut Client, group_id: &GroupId, text: &str) -> TransportMessage {
    let payload = MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        text.to_string(),
    )
    .encode()
    .unwrap();
    match engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg, .. } => route(msg, group_id),
        other => panic!("expected app message, got {other:?}"),
    }
}

/// Apply `messages` on `engine` through one settled convergence pass.
fn apply(engine: &mut Client, group_id: &GroupId, messages: &[TransportMessage]) {
    for message in messages {
        engine
            .buffer_openmls_convergence_message_at(group_id, message.clone(), 1_000)
            .unwrap();
    }
    engine
        .converge_stored_openmls_messages_at(group_id, 1_000_000)
        .unwrap();
}

struct Outcome {
    /// Observer epoch after convergence, relative to the shared fork epoch.
    observer_advance: u64,
    accepted_commits: Vec<String>,
    branch_a: String,
    branch_b: Vec<String>,
    decisive_rule: Option<&'static str>,
}

async fn incident_shape(v2: bool) -> Outcome {
    let mut alice = client(b"alice", v2);
    let mut bob = client(b"bob", v2);
    let mut carol = client(b"carol", v2);
    let mut dave = client(b"dave", v2);
    let mut frank = client(b"frank", v2);
    let mut eve = client(b"eve", v2);

    let members = vec![
        bob.fresh_key_package().await.unwrap(),
        carol.fresh_key_package().await.unwrap(),
        dave.fresh_key_package().await.unwrap(),
        frank.fresh_key_package().await.unwrap(),
    ];
    let (gid, created) = alice
        .create_group(CreateGroupRequest {
            name: "incident shape".into(),
            description: String::new(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let welcomes = match created {
        SendResult::FoundingGroupCreated { welcomes } => welcomes,
        other => panic!("expected FoundingGroupCreated, got {other:?}"),
    };
    for (engine, name) in [
        (&mut bob, b"bob".as_slice()),
        (&mut carol, b"carol"),
        (&mut dave, b"dave"),
        (&mut frank, b"frank"),
    ] {
        engine
            .join_welcome(welcome_for(&welcomes, name))
            .await
            .unwrap();
    }
    let required: Vec<AppComponentId> = decode_components_list(
        &alice
            .app_component(&gid, APP_COMPONENTS_COMPONENT_ID)
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .into_iter()
    .collect();
    assert_eq!(
        required.contains(&CONVERGENCE_POLICY_V2_COMPONENT_ID),
        v2,
        "every founding member supports v2 exactly when the build does"
    );

    let fork_epoch = alice.epoch(&gid).unwrap().0;

    // Branch A: an ordinary self-update that three pre-fork members use.
    let (a1, _) = commit(
        &mut alice,
        &gid,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
    )
    .await;
    apply(&mut carol, &gid, std::slice::from_ref(&a1));
    apply(&mut dave, &gid, std::slice::from_ref(&a1));
    let a_witnesses = vec![
        post(&mut alice, &gid, "on A from alice").await,
        post(&mut carol, &gid, "on A from carol").await,
        post(&mut dave, &gid, "on A from dave").await,
    ];

    // Branch B: an admin Add, the admin's next commit, and two posters at the
    // tip, one of them the invitee.
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let (b1, b1_welcomes) = commit(
        &mut bob,
        &gid,
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        },
    )
    .await;
    eve.join_welcome(welcome_for(&b1_welcomes, b"eve"))
        .await
        .unwrap();
    let (b2, _) = commit(
        &mut bob,
        &gid,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
    )
    .await;
    apply(&mut eve, &gid, std::slice::from_ref(&b2));
    assert_eq!(eve.epoch(&gid).unwrap(), EpochId(fork_epoch + 2));
    let b_witnesses = vec![
        post(&mut bob, &gid, "on B from bob").await,
        post(&mut eve, &gid, "on B from eve").await,
    ];

    // Frank saw nothing until now and receives everything in one batch.
    let mut inputs = vec![a1.clone(), b1.clone(), b2.clone()];
    inputs.extend(a_witnesses);
    inputs.extend(b_witnesses);
    for message in &inputs {
        frank
            .buffer_openmls_convergence_message_at(&gid, message.clone(), 1_000)
            .unwrap();
    }
    let result = frank
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    let decisive_rule = result.selection_trace.as_ref().and_then(|trace| {
        trace
            .rule_trace
            .iter()
            .find(|rule| rule.decisive)
            .map(|rule| rule.rule_name)
    });
    Outcome {
        observer_advance: frank.epoch(&gid).unwrap().0 - fork_epoch,
        accepted_commits: result.accepted_commits,
        branch_a: content_hex(&a1),
        branch_b: vec![content_hex(&b1), content_hex(&b2)],
        decisive_rule,
    }
}

#[tokio::test]
async fn policy_v1_rewinds_the_witnessed_branch_for_a_deeper_stale_one() {
    let outcome = incident_shape(false).await;
    assert_eq!(outcome.observer_advance, 2);
    assert_eq!(outcome.accepted_commits, outcome.branch_b);
    assert_eq!(outcome.decisive_rule, Some("effective_commit_depth"));
}

#[tokio::test]
async fn policy_v2_keeps_the_branch_more_pre_fork_members_used() {
    let outcome = incident_shape(true).await;
    assert_eq!(outcome.observer_advance, 1);
    assert_eq!(outcome.accepted_commits, vec![outcome.branch_a]);
    assert_eq!(outcome.decisive_rule, Some("protected_senders"));
}

#[tokio::test]
async fn the_v2_component_cannot_be_unrequired_rewritten_or_given_state() {
    use cgka_traits::app_components::{AppComponentData, encode_components_list};

    let mut alice = client(b"alice-v2-guards", true);
    let (gid, _) = alice
        .create_group(CreateGroupRequest {
            name: "v2 guards".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let required = decode_components_list(
        &alice
            .app_component(&gid, APP_COMPONENTS_COMPONENT_ID)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(required.contains(&CONVERGENCE_POLICY_V2_COMPONENT_ID));
    assert_eq!(
        alice
            .app_component(&gid, CONVERGENCE_POLICY_V2_COMPONENT_ID)
            .unwrap(),
        Some(Vec::new()),
        "required with empty state from creation"
    );

    let mut downgraded = required.clone();
    downgraded.remove(&CONVERGENCE_POLICY_V2_COMPONENT_ID);
    let attempts = [
        (
            "cannot be un-required",
            vec![AppComponentData {
                component_id: APP_COMPONENTS_COMPONENT_ID,
                data: encode_components_list(&downgraded),
            }],
        ),
        (
            "state must be empty",
            vec![AppComponentData {
                component_id: CONVERGENCE_POLICY_V2_COMPONENT_ID,
                data: vec![1],
            }],
        ),
        (
            "cannot be updated once present",
            vec![AppComponentData {
                component_id: CONVERGENCE_POLICY_V2_COMPONENT_ID,
                data: Vec::new(),
            }],
        ),
    ];
    for (reason, updates) in attempts {
        let refused = alice
            .send(SendIntent::UpdateAppComponents {
                group_id: gid.clone(),
                updates,
            })
            .await;
        let error = refused.expect_err(reason).to_string();
        assert!(error.contains(reason), "expected `{reason}`, got `{error}`");
    }
    assert!(
        decode_components_list(
            &alice
                .app_component(&gid, APP_COMPONENTS_COMPONENT_ID)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
        .contains(&CONVERGENCE_POLICY_V2_COMPONENT_ID)
    );
}
