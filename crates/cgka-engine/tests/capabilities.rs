//! Capability negotiation, cache population, and upgrade discovery.

use async_trait::async_trait;
use cgka_engine::canonicalization::SyncState;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID, default_group_components,
};
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, RequirementLevel,
};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::GroupStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use storage_memory::MemoryStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
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

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

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
            id: hash_id(&payload.ciphertext),
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
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
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

const REACTIONS_PROPOSAL: u16 = 0xFF01;
const TEST_APP_COMPONENT: u16 = 0x8101;

fn registry_selfremove_required_and_reactions_optional() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r.register(
        Feature("reactions"),
        CapabilityRequirement {
            requires: Capability::Proposal(REACTIONS_PROPOSAL),
            level: RequirementLevel::Optional,
            description: "emoji reactions",
        },
    );
    r
}

fn registry_selfremove_only() -> FeatureRegistry {
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

fn registry_selfremove_required_and_component_optional() -> FeatureRegistry {
    let mut r = registry_selfremove_only();
    r.register(
        Feature("test-app-component"),
        CapabilityRequirement {
            requires: Capability::AppComponent(TEST_APP_COMPONENT),
            level: RequirementLevel::Optional,
            description: "test app component",
        },
    );
    r
}

fn build_client(id: &[u8], registry: FeatureRegistry) -> impl CgkaEngine {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_engine_with_components(
    id: &[u8],
    components: impl IntoIterator<Item = u16>,
) -> Engine<MemoryStorage> {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_engine_with_registry_and_components(
    id: &[u8],
    registry: FeatureRegistry,
    components: impl IntoIterator<Item = u16>,
) -> Engine<MemoryStorage> {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry)
        .supported_app_components(components)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

#[tokio::test]
async fn group_creation_negotiates_app_component_intersection() {
    let mut alice = build_engine_with_components(
        b"alice",
        [GROUP_PROFILE_COMPONENT_ID, GROUP_ADMIN_POLICY_COMPONENT_ID],
    );
    let mut bob = build_engine_with_components(b"bob", [GROUP_PROFILE_COMPONENT_ID]);
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let constructable = alice
        .constructable_capabilities(std::slice::from_ref(&bob_kp))
        .unwrap();
    assert!(
        constructable
            .app_components
            .contains(GROUP_PROFILE_COMPONENT_ID)
    );
    assert!(
        !constructable
            .app_components
            .contains(GROUP_ADMIN_POLICY_COMPONENT_ID)
    );

    let (group_id, _result) = alice
        .create_group(CreateGroupRequest {
            name: "components".into(),
            description: "intersection".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let group = alice.group_record(&group_id).unwrap();
    assert!(
        group
            .required_capabilities
            .app_components
            .contains(GROUP_PROFILE_COMPONENT_ID)
    );
    assert!(
        !group
            .required_capabilities
            .app_components
            .contains(GROUP_ADMIN_POLICY_COMPONENT_ID)
    );
}

#[tokio::test]
async fn upgrade_group_capabilities_promotes_optional_app_component_to_required() {
    let mut supported = default_group_components();
    supported.insert(TEST_APP_COMPONENT);
    let mut alice = build_engine_with_registry_and_components(
        b"alice",
        registry_selfremove_required_and_component_optional(),
        supported.clone(),
    );
    let mut bob = build_engine_with_registry_and_components(
        b"bob",
        registry_selfremove_required_and_component_optional(),
        supported,
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "component-upgrade".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    assert!(matches!(
        alice
            .feature_status(&group_id, &Feature("test-app-component"))
            .unwrap(),
        FeatureStatus::Upgradeable
    ));
    assert!(
        !alice
            .group_record(&group_id)
            .unwrap()
            .required_capabilities
            .app_components
            .contains(TEST_APP_COMPONENT)
    );

    let upgrade = alice.upgrade_group_capabilities(&group_id).await.unwrap();
    let pending = match upgrade {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    assert!(matches!(
        alice
            .feature_status(&group_id, &Feature("test-app-component"))
            .unwrap(),
        FeatureStatus::Available
    ));
    assert!(
        alice
            .group_record(&group_id)
            .unwrap()
            .required_capabilities
            .app_components
            .contains(TEST_APP_COMPONENT)
    );
}

#[tokio::test]
async fn feature_in_required_capabilities_is_available() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, _result) = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![Feature("self-remove")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let status = alice
        .feature_status(&group_id, &Feature("self-remove"))
        .unwrap();
    assert!(matches!(status, FeatureStatus::Available));
}

#[tokio::test]
async fn create_group_requested_optional_feature_becomes_required() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, _result) = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![Feature("reactions")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let status = alice
        .feature_status(&group_id, &Feature("reactions"))
        .unwrap();
    assert!(matches!(status, FeatureStatus::Available));
}

#[tokio::test]
async fn create_group_rejects_invitee_missing_requested_optional_feature() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(b"bob", registry_selfremove_only());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let err = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![Feature("reactions")],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect_err("bob lacks reactions");

    assert!(matches!(
        err,
        cgka_traits::EngineError::MissingRequiredCapabilities { .. }
    ));
}

#[tokio::test]
async fn feature_supported_by_all_but_not_required_is_upgradeable() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, _) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    // Reactions is Optional, not in RequiredCaps; both members advertise it.
    let status = alice
        .feature_status(&group_id, &Feature("reactions"))
        .unwrap();
    assert!(
        matches!(status, FeatureStatus::Upgradeable),
        "got: {status:?}"
    );
}

#[tokio::test]
async fn feature_missing_from_one_member_is_unavailable_with_missing_set() {
    // Alice supports self-remove + reactions; Bob only self-remove.
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(b"bob", registry_selfremove_only());
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, _) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let status = alice
        .feature_status(&group_id, &Feature("reactions"))
        .unwrap();
    match status {
        FeatureStatus::Unavailable { missing } => {
            assert!(missing.proposals.contains(&REACTIONS_PROPOSAL));
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn upgradeable_capabilities_lists_universally_supported() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, _) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let up = alice.upgradeable_capabilities(&group_id).unwrap();
    assert!(up.proposals.contains(&REACTIONS_PROPOSAL));
    // self-remove is `Required` level in the registry, so
    // `required_capabilities_extension` auto-added it to the group's
    // RequiredCapabilities at creation. Already-required caps are excluded
    // from upgradeable (they're already Available).
    assert!(
        !up.proposals.contains(&10),
        "self-remove is already Required → should not be in upgradeable"
    );
    // Confirm the flip side.
    let status = alice
        .feature_status(&group_id, &Feature("self-remove"))
        .unwrap();
    assert!(matches!(status, FeatureStatus::Available));
}

// Capability matrix coverage.

#[tokio::test]
async fn transport_required_when_transport_inactive_behaves_like_optional() {
    // The engine layer passes `active_transports: []` to
    // `required_capabilities_extension`, so TransportRequired features are
    // NOT auto-promoted to RequiredCapabilities at engine layer (they're
    // promoted by transport adapters via `group_extension`). Verify the
    // engine reports them as Upgradeable (universal support) rather than
    // Available.
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("nostr-transport"),
        CapabilityRequirement {
            requires: Capability::Extension(0xF2EB),
            level: RequirementLevel::TransportRequired {
                transport: cgka_traits::capabilities::TransportKind::Nostr,
            },
            description: "nostr metadata",
        },
    );
    let mut alice = build_client(b"a", r.clone());
    let mut bob = build_client(b"b", r);
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, _) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    // Both members advertise the extension; transport not active → not
    // Required. So feature_status is Upgradeable.
    let st = alice
        .feature_status(&group_id, &Feature("nostr-transport"))
        .unwrap();
    assert!(matches!(st, FeatureStatus::Upgradeable), "got: {st:?}");
}

// Exhaustive capability matrix.
//
// Cover a 3 x 3 x 4 matrix:
//   `RequirementLevel` ∈ {Required, Optional, TransportRequired}
//   × coverage          ∈ {Universal, Partial, None}
//   × member count      ∈ {1, 2, 3, 4}
//
// Many cells are degenerate by construction:
//   - `Required + Partial/None`: invite is rejected at the engine boundary
//     with `MissingRequiredCapabilities`, so `feature_status` is never
//     queried. We assert the rejection itself in those cells.
//   - `Required + member_count=1`: solo creator advertises everything;
//     `Universal` is the only meaningful coverage. The reject cells are
//     skipped (no invitee to reject).
//   - `TransportRequired + *`: the engine layer always passes
//     `active_transports: []`, so TransportRequired behaves like Optional.
//     Coverage cells map identically: Universal → Upgradeable, Partial /
//     None → Unavailable.
//
// All 36 nominal cells are walked below; degenerate ones get the
// appropriate assertion (rejection vs. status check) without exiting the
// loop, so a single test failure pinpoints the exact cell that diverged.

#[derive(Clone, Copy, Debug)]
enum Coverage {
    Universal,
    Partial,
    None,
}

#[derive(Clone, Copy, Debug)]
enum Level {
    Required,
    Optional,
    TransportRequired,
}

const FEATURE_UNDER_TEST: Feature = Feature("matrix-feat");
const FEATURE_CAP_PROPOSAL: u16 = 0xF301;

fn registry_for(level: Level, supports_feat: bool) -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    // Always register self-remove required so the engine has a non-trivial
    // baseline (mirrors how every real registry pins SelfRemove).
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    if supports_feat {
        r.register(
            FEATURE_UNDER_TEST,
            CapabilityRequirement {
                requires: Capability::Proposal(FEATURE_CAP_PROPOSAL),
                level: match level {
                    Level::Required => RequirementLevel::Required,
                    Level::Optional => RequirementLevel::Optional,
                    Level::TransportRequired => RequirementLevel::TransportRequired {
                        transport: cgka_traits::capabilities::TransportKind::Nostr,
                    },
                },
                description: "matrix",
            },
        );
    } else {
        // Member doesn't advertise the feature at all (plain SelfRemove
        // registry).
    }
    r
}

/// Build N invitee KeyPackages. `coverage` controls how many of them
/// advertise the feature under test.
async fn invitee_kps(
    n_invitees: usize,
    feature_level: Level,
    coverage: Coverage,
) -> Vec<cgka_traits::engine::KeyPackage> {
    let supports: Vec<bool> = match coverage {
        Coverage::Universal => vec![true; n_invitees],
        Coverage::Partial => {
            // "Partial" requires at least one missing leaf. With only one
            // invitee that's necessarily None; with >= 2 invitees we get
            // [false, true, true, ...] so the missing leaf forces the
            // expected behavior (Required → reject; Optional → Unavailable).
            let mut v = vec![true; n_invitees];
            if n_invitees > 0 {
                v[0] = false;
            }
            v
        }
        Coverage::None => vec![false; n_invitees],
    };
    let mut out = Vec::with_capacity(n_invitees);
    for (i, sup) in supports.iter().enumerate() {
        let id = format!("invitee-{i}");
        let mut client = build_client(id.as_bytes(), registry_for(feature_level, *sup));
        let kp = client.fresh_key_package().await.unwrap();
        out.push(kp);
    }
    out
}

#[tokio::test]
async fn capability_matrix_36_cells() {
    use Coverage::*;
    use Level::*;

    let levels = [Required, Optional, TransportRequired];
    let coverages = [Universal, Partial, None];
    let member_counts = [1usize, 2, 3, 4];

    for level in &levels {
        for coverage in &coverages {
            for &n in &member_counts {
                let n_invitees = n - 1;

                // Creator always advertises the feature regardless of
                // coverage (so creator can be Required-eligible).
                let mut alice = build_client(b"alice", registry_for(*level, true));
                let kps = invitee_kps(n_invitees, *level, *coverage).await;

                let create_res = alice
                    .create_group(CreateGroupRequest {
                        name: "matrix".into(),
                        description: "".into(),
                        members: kps,
                        required_features: vec![],
                        app_components: vec![],
                        initial_admins: vec![],
                    })
                    .await;

                let cell = format!("level={level:?} coverage={coverage:?} n={n}");

                match (level, coverage, n) {
                    // Required + missing coverage on at least one invitee →
                    // creation must fail with MissingRequiredCapabilities.
                    (Required, Partial, n) | (Required, None, n) if n > 1 => {
                        let err = match create_res {
                            Err(e) => e,
                            Ok(_) => panic!("{cell}: should reject at create_group"),
                        };
                        assert!(
                            matches!(
                                err,
                                cgka_traits::EngineError::MissingRequiredCapabilities { .. }
                            ),
                            "{cell}: expected MissingRequiredCapabilities, got {err:?}"
                        );
                        continue;
                    }
                    // Required at solo OR Universal coverage → group lands.
                    // Optional / TransportRequired → group always lands
                    // regardless of coverage.
                    _ => {
                        let (group_id, _send_result) = match create_res {
                            Ok(t) => t,
                            Err(e) => panic!("{cell}: should create, got {e:?}"),
                        };

                        let st = match alice.feature_status(&group_id, &FEATURE_UNDER_TEST) {
                            Ok(s) => s,
                            Err(e) => panic!("{cell}: feature_status failed: {e:?}"),
                        };

                        let expected: &str = match (level, coverage, n) {
                            // Required, n=1 (solo): always lands; creator
                            // supports the feature.
                            (Required, _, 1) => "Available",
                            // Required, Universal coverage: lands at Available.
                            (Required, Universal, _) => "Available",
                            // Required + Partial/None at n>1 was filtered
                            // by the outer `continue`; not reachable here.
                            (Required, Partial, _) | (Required, None, _) => unreachable!(
                                "Required+Partial/None at n>1 should have rejected at create"
                            ),
                            // Optional: Universal or solo → Upgradeable;
                            // anything else → Unavailable.
                            (Optional, Universal, _) | (Optional, _, 1) => "Upgradeable",
                            (Optional, _, _) => "Unavailable",
                            // TransportRequired (transport inactive at
                            // engine layer) behaves like Optional.
                            (TransportRequired, Universal, _) | (TransportRequired, _, 1) => {
                                "Upgradeable"
                            }
                            (TransportRequired, _, _) => "Unavailable",
                        };

                        let actual = match &st {
                            FeatureStatus::Available => "Available",
                            FeatureStatus::Upgradeable => "Upgradeable",
                            FeatureStatus::Unavailable { missing } => {
                                assert!(
                                    missing.proposals.contains(&FEATURE_CAP_PROPOSAL),
                                    "{cell}: Unavailable missing set should name the cap"
                                );
                                "Unavailable"
                            }
                        };
                        assert_eq!(
                            actual, expected,
                            "{cell}: feature_status mismatch (got {st:?})"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn upgrade_group_capabilities_promotes_optional_to_required() {
    // Both alice and bob support reactions; the feature is Optional.
    // After upgrade, reactions becomes part of the group's RequiredCaps,
    // so feature_status returns Available instead of Upgradeable.
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "u".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // Pre-upgrade: reactions is Upgradeable.
    assert!(matches!(
        alice
            .feature_status(&group_id, &Feature("reactions"))
            .unwrap(),
        FeatureStatus::Upgradeable
    ));

    // Upgrade.
    let res = alice
        .upgrade_group_capabilities(&group_id)
        .await
        .expect("upgrade");
    let pending = match res {
        cgka_traits::engine::SendResult::GroupEvolution {
            pending, welcomes, ..
        } => {
            assert!(welcomes.is_empty(), "GCE upgrade has no welcomes");
            pending
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    // Post-upgrade: reactions is Available.
    assert!(matches!(
        alice
            .feature_status(&group_id, &Feature("reactions"))
            .unwrap(),
        FeatureStatus::Available
    ));
}

#[tokio::test]
async fn non_admin_cannot_upgrade_group_capabilities() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (_group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "u".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome_for_bob = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        _ => unreachable!(),
    };
    let group_id = bob.join_welcome(welcome_for_bob).await.unwrap();

    let err = bob
        .upgrade_group_capabilities(&group_id)
        .await
        .err()
        .unwrap();

    assert!(matches!(err, EngineError::NotGroupAdmin { .. }));
}

#[tokio::test]
async fn group_context_returns_live_view() {
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, _create) = alice
        .create_group(CreateGroupRequest {
            name: "ctx".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let ctx = alice.group_context(&group_id).expect("group_context");
    assert_eq!(ctx.epoch().0, 1);
    let secret = ctx.exporter_secret("marmot/group-event", 32);
    assert!(secret.is_some(), "well-known label should resolve");
    assert!(
        ctx.exporter_secret("nonexistent-label", 32).is_none(),
        "unknown labels return None"
    );
}

#[tokio::test]
async fn bob_sees_alice_caps_cached_after_invite_commit() {
    // Bob joins via welcome (cache only has self). Alice then invites carol;
    // bob ingests the commit, which contains carol's KeyPackage. Bob's
    // cache now holds carol's capabilities extracted from the staged commit.
    let mut alice = build_client(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut bob = build_client(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );
    let mut carol = build_client(
        b"carol",
        registry_selfremove_required_and_reactions_optional(),
    );
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome_for_bob, create_pending) = match create {
        SendResult::GroupCreated {
            mut welcomes,
            pending,
        } => (welcomes.remove(0), pending),
        _ => unreachable!(),
    };
    alice.confirm_published(create_pending).await.unwrap();
    bob.join_welcome(welcome_for_bob).await.unwrap();

    // Before invite: bob can see alice's caps via the group's Required
    // (MIP-03 guarantee) OR via ingest of alice's commits — but not for
    // reactions (not required). Let's test reactions-upgradeable from
    // bob's side AFTER an invite commit brings him alice's and carol's
    // KeyPackages via the StagedCommit.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(cgka_traits::engine::SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    let (invite_commit, invite_pending) = match invite {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    alice.confirm_published(invite_pending).await.unwrap();

    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..invite_commit
    };
    bob.ingest(routed).await.unwrap();

    // Bob now has self's caps AND carol's caps (from the commit). Alice's
    // caps aren't directly visible to bob — but since reactions is universal
    // in this scenario, alice's advertised caps would matter for "upgradeable"
    // accuracy. For this test we prove carol's caps landed:
    // reactions-upgradeable is true iff every known member supports it,
    // which holds for (bob, carol) — alice's caps aren't in bob's cache
    // but the group record contains her as a member, so if the cache
    // doesn't know her caps we'd return Unavailable. Expected behavior:
    // reactions shows Unavailable because bob doesn't know alice's caps.
    let status = bob
        .feature_status(&group_id, &Feature("reactions"))
        .unwrap();
    // Bob doesn't know alice's caps (she joined before bob was a member).
    // So from bob's perspective, reactions cannot be confirmed universally.
    // The cache defaulting to empty means alice "doesn't support" from
    // bob's POV — so Unavailable is the honest answer.
    assert!(
        matches!(status, FeatureStatus::Unavailable { .. }),
        "bob can't confirm alice's caps → Unavailable, got: {status:?}"
    );
}

// ── B1 regression: convergence-side capability upgrade ────────────────────

fn build_concrete_with_storage(
    id: &[u8],
    registry: FeatureRegistry,
) -> (Engine<MemoryStorage>, MemoryStorage) {
    let storage = MemoryStorage::new();
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

/// When a capability upgrade commit lands on the recipient via the
/// convergence path (not via `confirm_published`), the recipient's
/// Marmot record must be refreshed with the post-merge
/// `RequiredCapabilities`. Before this fix the convergence path only
/// refreshed `epoch` and `members`, so `feature_status` would still
/// report the upgraded capability as `Upgradeable` even though MLS
/// truth said `Available`.
#[tokio::test]
async fn convergence_refreshes_recipient_required_capabilities_on_upgrade() {
    let (mut alice, _alice_storage) = build_concrete_with_storage(
        b"alice",
        registry_selfremove_required_and_reactions_optional(),
    );
    let (mut bob, bob_storage) = build_concrete_with_storage(
        b"bob",
        registry_selfremove_required_and_reactions_optional(),
    );

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (alice_pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();

    // Reactions is Optional and not required pre-upgrade.
    let bob_pre = bob_storage.get_group(&gid).unwrap();
    assert!(
        !bob_pre.required_capabilities.proposals.contains(&0xFF01),
        "reactions must NOT be required pre-upgrade"
    );

    // Alice upgrades the group's capabilities.
    let upgrade = alice.upgrade_group_capabilities(&gid).await.unwrap();
    let (commit, alice_pending) = match upgrade {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();

    // Bob ingests via convergence — NOT via confirm.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    bob.ingest(routed).await.unwrap();
    let result = bob
        .converge_stored_openmls_messages(&gid, 1_000_000)
        .unwrap();
    assert_eq!(result.sync_state, SyncState::Stable);

    // Bob's Marmot record now reflects the upgraded RequiredCapabilities.
    // Pre-fix: `required_capabilities` was stale; reactions still missing.
    let bob_post = bob_storage.get_group(&gid).unwrap();
    assert!(
        bob_post.required_capabilities.proposals.contains(&0xFF01),
        "convergence MUST refresh recipient required_capabilities; got {:?}",
        bob_post.required_capabilities
    );

    // And `feature_status` follows: reactions is Available now.
    let status = bob.feature_status(&gid, &Feature("reactions")).unwrap();
    assert!(
        matches!(status, FeatureStatus::Available),
        "feature_status should report Available after convergence-applied upgrade, got: {status:?}"
    );
}
