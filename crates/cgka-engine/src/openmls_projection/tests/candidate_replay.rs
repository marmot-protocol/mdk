//! Forked-graph fixtures, replay restoration and resumable-search parity checks.
//! Includes the ignored paired reconstruction measurement; crash-kill coverage
//! lives in `tests/crash_recovery_sqlite.rs`.

use super::{
    CANDIDATE_REPLAY_BUDGET_FLOOR, CANDIDATE_REPLAY_BUDGET_SLACK, CandidateBranchPeel,
    ReplayProfilePolicy, candidate_branch_peel, own_commit_checkpoint_id,
};
use crate::account_identity_proof::{AccountIdentityProofRequest, AccountIdentityProofSigner};
use crate::convergence::V1_MAX_REWIND_COMMITS;
use crate::message_processor::MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS;
use crate::provider::EngineOpenMlsProvider;
use crate::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use async_trait::async_trait;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, GroupStorage, MessageStorage, StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
use openmls::group::MlsGroup;
use openmls::prelude::{MlsMessageIn, ProcessedMessageContent};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

// --- Test devices --------------------------------------------------------

/// Deterministic BIP-340 key for a seed label. Marmot credential identities
/// MUST be a valid 32-byte x-only secp256k1 public key, so identities are
/// derived rather than invented.
fn signing_key(seed: &[u8]) -> SigningKey {
    for counter in 0u64.. {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(key) = SigningKey::from_bytes(&material) {
            return key;
        }
    }
    unreachable!("a signing key is found within u64 counters")
}

fn member_id(seed: &[u8]) -> MemberId {
    MemberId::new(signing_key(seed).verifying_key().to_bytes().to_vec())
}

struct SeedProofSigner(SigningKey);

impl AccountIdentityProofSigner for SeedProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        Ok(self
            .0
            .sign_prehash(&request.proof_event_id()?)
            .map_err(|e| e.to_string())?
            .to_bytes())
    }
}

/// Transport is not under test here: every message is carried verbatim.
struct PassthroughPeeler;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl TransportPeeler for PassthroughPeeler {
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
        Ok(transport_message(
            &payload.ciphertext,
            TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        ))
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let mut message = transport_message(
            &payload.ciphertext,
            TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        );
        // Current-profile founding sends a distinct envelope per invitee,
        // even when the underlying MLS Welcome bytes are shared.
        let mut digest = Sha256::new();
        digest.update(&payload.ciphertext);
        digest.update(recipient.as_slice());
        message.id = MessageId::new(digest.finalize().to_vec());
        Ok(message)
    }
}

fn transport_message(payload: &[u8], envelope: TransportEnvelope) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(Sha256::digest(payload).to_vec()),
        payload: payload.to_vec(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("candidate-branch-peel-test".into()),
        envelope,
    }
}

fn build_client(seed: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(member_id(seed).as_slice().to_vec())
        .account_identity_proof_signer(Arc::new(SeedProofSigner(signing_key(seed))))
        .peeler(Box::new(PassthroughPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

async fn group_with(
    creator: &mut Engine<SqliteAccountStorage>,
    joiners: &mut [&mut Engine<SqliteAccountStorage>],
) -> GroupId {
    let mut key_packages = Vec::new();
    for joiner in joiners.iter_mut() {
        key_packages.push(joiner.fresh_key_package().await.unwrap());
    }
    let (group_id, created) = creator
        .create_group(CreateGroupRequest {
            name: "candidate branch peel".into(),
            description: String::new(),
            members: key_packages,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![creator.self_id()],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("expected GroupCreated");
    };
    creator.confirm_published(pending).await.unwrap();
    for (joiner, welcome) in joiners.iter_mut().zip(welcomes) {
        joiner.join_welcome(welcome).await.unwrap();
    }
    group_id
}

#[tokio::test]
async fn graph_seed_keeps_stale_commits() {
    let (mut alice, storage) = build_client(b"graph-seed");
    let (mut bob, _) = build_client(b"graph-seed-peer");
    let group_id = group_with(&mut alice, &mut [&mut bob]).await;
    let epoch = storage.get_group(&group_id).unwrap().epoch.0;
    let commit = rival_commit(&storage, &alice.self_id(), &group_id);
    admit_rival(&storage, &group_id, &commit, epoch);

    let retained =
        super::seed_stored_openmls_graph_inputs(&storage, &group_id, epoch, None).unwrap();
    assert!(
        retained
            .commit_messages
            .iter()
            .any(|row| row.message.id == commit.id)
    );
    let stale =
        super::seed_stored_openmls_graph_inputs(&storage, &group_id, epoch + 1, None).unwrap();
    assert!(stale.commit_messages.is_empty());
    assert!(stale.stale_commit_drops.iter().any(|row| {
        row.message_id == hex::encode(commit.id.as_slice())
            && row.reason == super::DroppedMessageReason::BeyondAnchor
    }));
    // Seeding classifies; only canonical apply may persist the verdict.
    assert_eq!(
        storage.get_message(&commit.id).unwrap().state,
        MessageState::ConvergenceDeferred
    );
}

// --- Graph fixtures ------------------------------------------------------

/// Grind one more valid commit out of a device's live state without
/// advancing it: the pending commit is cleared, so the next call forks from
/// the same epoch again. This is how a wide same-epoch fork is built.
fn rival_commit(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
) -> TransportMessage {
    rival_commit_inner(storage, sender, group_id, false)
}

fn rival_commit_inner(
    storage: &SqliteAccountStorage,
    sender: &MemberId,
    group_id: &GroupId,
    advance: bool,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
        .expect("load rival MLS group")
        .expect("rival has group state");
    let binding = storage
        .account_device_signer(sender)
        .expect("load signer binding")
        .expect("signer binding exists");
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists");

    let bundle = mls_group
        .commit_builder()
        .load_psks(provider.storage())
        .expect("load PSKs")
        .build(provider.rand(), provider.crypto(), &signer, |_| true)
        .expect("build rival self-update commit")
        .stage_commit(&provider)
        .expect("stage rival self-update commit");
    let (commit, _welcome, _group_info) = bundle.into_contents();
    let bytes = commit
        .tls_serialize_detached()
        .expect("serialize rival self-update commit");
    if advance {
        mls_group.merge_pending_commit(&provider).unwrap();
        let mut group = storage.get_group(group_id).unwrap();
        group.epoch = EpochId(mls_group.epoch().as_u64());
        storage.put_group(&group).unwrap();
    } else {
        mls_group
            .clear_pending_commit(provider.storage())
            .expect("clear the rival's pending commit");
    }

    transport_message(
        &bytes,
        TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    )
}

/// Apply a commit to a device's stored state, putting it on that branch.
/// Grinding successors out of a device ([`rival_commit`]) needs it standing
/// where those successors fork from.
fn adopt_branch(storage: &SqliteAccountStorage, group_id: &GroupId, commit: &TransportMessage) {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, storage.mls_storage());
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mut mls_group = MlsGroup::load(provider.storage(), &mls_group_id)
        .expect("load adopting MLS group")
        .expect("adopter has group state");
    let message = MlsMessageIn::tls_deserialize_exact(commit.payload.as_slice())
        .expect("adopted commit deserializes")
        .try_into_protocol_message()
        .expect("adopted commit is a protocol message");
    let processed = mls_group
        .process_message(&provider, message)
        .expect("adopted commit processes");
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("expected a staged commit");
    };
    mls_group
        .merge_staged_commit(&provider, *staged)
        .expect("merge the adopted commit");

    let mut group = storage.get_group(group_id).unwrap();
    group.epoch = EpochId(mls_group.epoch().as_u64());
    storage.put_group(&group).unwrap();
}

/// Admit a rival commit into the observer's graph in the state ingest
/// leaves behind for a peeled commit that convergence has not adjudicated.
fn admit_rival(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    commit: &TransportMessage,
    source_epoch: u64,
) {
    storage
        .put_message(&MessageRecord {
            id: commit.id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(source_epoch),
            state: MessageState::ConvergenceDeferred,
            payload: StoredMessagePayload::openmls_wire(commit.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();
}

/// Survey the observer's graph exactly as the deferred-peel sweep does,
/// under the rewind allowance the caller wants to give enumeration.
fn peel(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    max_rewind_commits: u64,
) -> CandidateBranchPeel {
    let epoch = storage.get_group(group_id).unwrap().epoch.0;
    candidate_branch_peel(
        storage,
        group_id,
        epoch.saturating_sub(max_rewind_commits),
        max_rewind_commits,
        ReplayProfilePolicy::default(),
        MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS,
    )
    .expect("a branch survey over healthy storage")
}

thread_local! {
    static PANIC_AFTER_REPLAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn panic_after_replay_if_requested() {
    assert!(
        !PANIC_AFTER_REPLAY.replace(false),
        "injected replay panic after MLS writes"
    );
}

fn replay_state(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
) -> (Vec<u8>, String, Vec<String>) {
    let mls = MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .unwrap()
    .unwrap();
    (
        serde_json::to_vec(&storage.get_group(group_id).unwrap()).unwrap(),
        super::own_commit_post_merge_epoch_authenticator(&mls),
        storage.list_group_snapshots(group_id).unwrap(),
    )
}

async fn encrypted_replay_fixture(
    size: usize,
) -> (
    tempfile::TempDir,
    SqliteAccountStorage,
    GroupId,
    Vec<TransportMessage>,
) {
    encrypted_replay_graph_fixture(size, 3, 1).await
}

async fn encrypted_replay_graph_fixture(
    size: usize,
    width: usize,
    depth: usize,
) -> (
    tempfile::TempDir,
    SqliteAccountStorage,
    GroupId,
    Vec<TransportMessage>,
) {
    encrypted_replay_graph_fixture_with_apps(size, width, depth, false).await
}

async fn encrypted_replay_graph_fixture_with_apps(
    size: usize,
    width: usize,
    depth: usize,
    with_apps: bool,
) -> (
    tempfile::TempDir,
    SqliteAccountStorage,
    GroupId,
    Vec<TransportMessage>,
) {
    let root = tempfile::tempdir().unwrap();
    let storage = SqliteAccountStorage::open_encrypted(
        root.path().join("observer.sqlite3"),
        &storage_sqlite::SqlCipherKey::new("replay transaction fixture").unwrap(),
    )
    .unwrap();
    let build = |seed: &[u8], store: SqliteAccountStorage| {
        EngineBuilder::new(store)
            .identity(member_id(seed).as_slice().to_vec())
            .account_identity_proof_signer(Arc::new(SeedProofSigner(signing_key(seed))))
            .peeler(Box::new(PassthroughPeeler))
            .build()
            .unwrap()
    };
    let alice_store = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build(b"transaction-alice", alice_store.clone());
    let mut joiners = vec![build(b"transaction-observer", storage.clone())];
    for i in 2..size {
        joiners.push(build(
            format!("transaction-member-{i}").as_bytes(),
            SqliteAccountStorage::in_memory().unwrap(),
        ));
    }
    let mut packages = Vec::new();
    for joiner in &mut joiners {
        packages.push(joiner.fresh_key_package().await.unwrap());
    }
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "replay transaction".into(),
            description: String::new(),
            members: packages,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group");
    };
    for (joiner, welcome) in joiners.iter_mut().zip(welcomes) {
        joiner.join_welcome(welcome).await.unwrap();
    }
    let mut messages = Vec::new();
    for _ in 0..width {
        let guard = crate::snapshot_guard::SnapshotRollbackGuard::create_group_state(
            &alice_store,
            group_id.clone(),
            crate::snapshot_guard::RewindSite::CandidateBranchSweep,
            "measurement-branch",
        )
        .unwrap();
        for _ in 0..depth {
            messages.push(rival_commit_inner(
                &alice_store,
                &alice.self_id(),
                &group_id,
                true,
            ));
        }
        if with_apps {
            let crypto = RustCrypto::default();
            let provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
                &crypto,
                alice_store.mls_storage(),
            );
            let mut mls = MlsGroup::load(
                provider.storage(),
                &openmls::group::GroupId::from_slice(group_id.as_slice()),
            )
            .unwrap()
            .unwrap();
            let binding = alice_store
                .account_device_signer(&alice.self_id())
                .unwrap()
                .unwrap();
            let signer = SignatureKeyPair::read(
                alice_store.mls_storage(),
                &binding.mls_signature_public_key,
                DEFAULT_CIPHERSUITE.signature_algorithm(),
            )
            .unwrap();
            let payload = cgka_traits::app_event::MarmotAppEvent::new(
                hex::encode(alice.self_id().as_slice()),
                1_700_000_000,
                cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
                vec![],
                "branch witness",
            )
            .encode()
            .unwrap();
            let message = mls
                .create_message(&provider, &signer, &payload)
                .unwrap()
                .tls_serialize_detached()
                .unwrap();
            messages.push(transport_message(
                &message,
                TransportEnvelope::GroupMessage {
                    transport_group_id: group_id.as_slice().to_vec(),
                },
            ));
        }
        guard.commit().unwrap();
    }
    (root, storage, group_id, messages)
}

#[tokio::test]
async fn resumable_search_matches_original_bfs_without_repeating_probes() {
    let (_root, storage, group_id, messages) = encrypted_replay_graph_fixture(10, 4, 3).await;
    for message in &messages {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
    }
    let before = replay_state(&storage, &group_id);
    let inputs = super::seed_stored_openmls_graph_inputs(&storage, &group_id, 0, None).unwrap();
    let mut reference_budget = super::ReplayBudget::for_pass(messages.len(), 64);
    let reference = super::build_stored_openmls_candidate_paths_reference(
        &storage,
        &group_id,
        inputs.commit_messages.clone(),
        &inputs.pending_messages,
        inputs.replay_start_epoch,
        &inputs.own_commits,
        ReplayProfilePolicy::default(),
        &mut reference_budget,
    )
    .unwrap();
    for limit in [1, 3, 7, 32] {
        let mut search = super::resumable::CandidateSearch::new(
            inputs.commit_messages.clone(),
            &inputs.pending_messages,
            inputs.replay_start_epoch,
        )
        .unwrap();
        let mut budget = super::ReplayBudget::for_pass(messages.len(), 64);
        loop {
            let consumed = budget.consumed;
            let done = search
                .advance(
                    &storage,
                    &group_id,
                    &inputs.own_commits,
                    ReplayProfilePolicy::default(),
                    &mut budget,
                    &mut super::ReplaySlice::new(
                        std::time::Instant::now() + std::time::Duration::from_secs(30),
                        limit,
                    ),
                )
                .unwrap();
            assert!(budget.consumed - consumed <= limit as u64);
            assert!(replay_state(&storage, &group_id) == before);
            if done {
                break;
            }
            assert!(
                budget.consumed > consumed,
                "a slice must retain forward progress"
            );
        }
        assert!(search.finish() == reference, "slicing changed BFS results");
        assert_eq!(
            budget.consumed, reference_budget.consumed,
            "slicing repeated replay work"
        );
    }
}

fn reconstruction_state(epoch: u64) -> super::CanonicalizationState {
    super::CanonicalizationState {
        current_tip_epoch: epoch,
        retained_anchor_epoch: 0,
        last_convergence_relevant_input_ms: 0,
        seen_message_ids: Default::default(),
    }
}

#[tokio::test]
async fn resumable_selection_and_peeling_restore_historical_state_and_match_complete_results() {
    use cgka_traits::storage::OutboundIntentStorage;
    let (_root, storage, group_id, messages) =
        encrypted_replay_graph_fixture_with_apps(10, 4, 3, true).await;
    // Our own confirmed update forces checkpoint-based reconstruction as
    // well as a retained-anchor rewind on every slice.
    let mut observer = EngineBuilder::new(storage.clone())
        .identity(member_id(b"transaction-observer").as_slice().to_vec())
        .account_identity_proof_signer(Arc::new(SeedProofSigner(signing_key(
            b"transaction-observer",
        ))))
        .peeler(Box::new(PassthroughPeeler))
        .build()
        .unwrap();
    observer.hydrate_all_stored_groups().unwrap();
    let SendResult::GroupEvolution { pending, .. } = observer
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("own update")
    };
    observer.confirm_published(pending).await.unwrap();
    for message in &messages {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
    }
    storage
        .put_queued_outbound_intent(&cgka_traits::storage::QueuedOutboundIntent {
            id: MessageId::new(b"slice-retained-intent".to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                expected_epoch: None,
                group_id: group_id.clone(),
                payload: b"retained".to_vec(),
            },
            created_at_ms: 1,
            reissue_attempts: 0,
        })
        .unwrap();
    let queued = storage.list_queued_outbound_intents(&group_id).unwrap();
    let before = replay_state(&storage, &group_id);
    let ledger = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let expected = super::canonicalize_stored_openmls_messages_with_profile_policy(
        &storage,
        &group_id,
        reconstruction_state(2),
        vec![],
        super::CanonicalizationPolicy::default(),
        100_000,
        Default::default(),
    )
    .unwrap();
    assert!(
        !expected.accepted_app_messages.is_empty(),
        "exercise application materialization and scoring"
    );
    for limit in [1, 5, 32, usize::MAX] {
        super::resumable::REPLAY_FINGERPRINT_READS.with(|reads| reads.set(0));
        let mut slot = None;
        let mut slices = 0;
        loop {
            let output = super::canonicalize_stored_slice(
                &storage,
                &group_id,
                reconstruction_state(2),
                vec![],
                super::CanonicalizationPolicy::default(),
                100_000,
                Default::default(),
                1,
                &mut slot,
                &mut super::ReplaySlice::new(
                    std::time::Instant::now() + std::time::Duration::from_secs(30),
                    limit,
                ),
            )
            .unwrap();
            assert!(storage.list_queued_outbound_intents(&group_id).unwrap() == queued);
            slices += 1;
            assert!(slices < 100, "continuation restarted instead of advancing");
            assert!(
                replay_state(&storage, &group_id) == before,
                "slice exposed historical state"
            );
            assert!(storage.list_messages(&group_id, EpochId(0)).unwrap() == ledger);
            if let Some(output) = output {
                assert!(output == expected, "selection parity");
                assert!(slot.is_none());
                break;
            }
        }
        let reads = super::resumable::REPLAY_FINGERPRINT_READS.with(|reads| reads.get());
        if limit == usize::MAX {
            assert_eq!(slices, 1);
            assert_eq!(
                reads, 0,
                "completed work does not need a continuation fingerprint"
            );
        } else {
            assert!(slices > 1);
            assert!(
                reads > 0,
                "retained progress must validate its source state"
            );
        }
    }
    let expected_peel = peel(&storage, &group_id, 64);
    let mut slot = None;
    let mut slices = 0;
    let actual = loop {
        let output = super::candidate_peel_slice(
            &storage,
            &group_id,
            0,
            64,
            ReplayProfilePolicy::default(),
            8,
            &mut slot,
            &mut super::ReplaySlice::new(
                std::time::Instant::now() + std::time::Duration::from_secs(30),
                1,
            ),
        )
        .unwrap();
        slices += 1;
        assert!(slices < 100);
        assert!(replay_state(&storage, &group_id) == before);
        if let Some(output) = output {
            break output;
        }
    };
    assert!(actual.contested && expected_peel.contested);
    assert_eq!(actual.replay_probe_count, expected_peel.replay_probe_count);
    assert_eq!(actual.contexts.len(), expected_peel.contexts.len());
    for (a, b) in actual.contexts.iter().zip(&expected_peel.contexts) {
        assert!(a.branch_id == b.branch_id && a.tip_epoch == b.tip_epoch && a.context == b.context);
    }
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn resumable_public_background_advance_retains_progress_until_complete() {
    use cgka_traits::storage::{OutboundIntentStorage, QueuedOutboundIntent};
    let (_root, storage, group_id, messages) = encrypted_replay_graph_fixture(6, 4, 3).await;
    let writer = SqliteAccountStorage::open_encrypted(
        _root.path().join("observer.sqlite3"),
        &storage_sqlite::SqlCipherKey::new("replay transaction fixture").unwrap(),
    )
    .unwrap();
    let clock = crate::ManualConvergenceClock::new(1_000_000, 1_800_000_000_000);
    let mut engine = EngineBuilder::new(storage.clone())
        .identity(member_id(b"transaction-observer").as_slice().to_vec())
        .account_identity_proof_signer(Arc::new(SeedProofSigner(signing_key(
            b"transaction-observer",
        ))))
        .peeler(Box::new(PassthroughPeeler))
        .convergence_clock(Arc::new(clock.clone()))
        .build()
        .unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    engine.set_replay_slice_probe_limit_for_tests(1);
    for message in &messages {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
        let mut row = storage.get_message(&message.id).unwrap();
        row.state = MessageState::Created;
        storage.put_message(&row).unwrap();
    }
    engine.advance_convergence_inputs(&group_id).await.unwrap();
    clock.advance_ms(100_000);
    let mut progress = Vec::new();
    for iteration in 0..128 {
        // A second app connection changes non-replay work between every
        // quantum, as the full app's projection checkpoint does. SQLite's
        // database-wide data_version changes; the actual replay state does not.
        let generation = storage.mls_write_generation();
        writer
            .put_queued_outbound_intent(&QueuedOutboundIntent {
                id: MessageId::new(b"foreign-connection-work".to_vec()),
                group_id: group_id.clone(),
                intent: SendIntent::AppMessage {
                    expected_epoch: None,
                    group_id: group_id.clone(),
                    payload: vec![0],
                },
                created_at_ms: iteration,
                reissue_attempts: 0,
            })
            .unwrap();
        assert_ne!(generation, storage.mls_write_generation());
        let settled = engine.advance_convergence_inputs(&group_id).await.unwrap();
        if let Some(work) = engine.canonical_replays.get(&group_id) {
            progress.push(work.completed_probes());
        }
        if settled {
            assert_eq!(
                storage.get_group(&group_id).unwrap().epoch,
                EpochId(4),
                "settled without applying graph; progress={progress:?}"
            );
            assert!(progress.len() > 1, "progress={progress:?}");
            assert!(
                progress.windows(2).all(|w| w[1] > w[0]),
                "background advance restarted probes: {progress:?}"
            );
            assert_eq!(storage.get_group(&group_id).unwrap().epoch, EpochId(4));
            return;
        }
    }
    panic!("background advance never completed: {progress:?}");
}

#[tokio::test]
async fn resumable_frozen_membership_ignores_later_arrivals_and_new_pass_discards_progress() {
    let (_root, storage, group_id, messages) = encrypted_replay_graph_fixture(6, 3, 2).await;
    for message in &messages[..4] {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
    }
    let admitted = messages[..4]
        .iter()
        .map(|m| m.id.clone())
        .collect::<Vec<_>>();
    let options = super::StoredCanonicalizationOptions {
        admitted_message_ids: Some(&admitted),
        ..Default::default()
    };
    let expected = super::canonicalize_stored_openmls_messages_with_profile_policy(
        &storage,
        &group_id,
        reconstruction_state(1),
        vec![],
        super::CanonicalizationPolicy::default(),
        100_000,
        options.clone(),
    )
    .unwrap();
    let advance = |slot: &mut Option<super::CanonicalReplay>, generation| {
        super::canonicalize_stored_slice(
            &storage,
            &group_id,
            reconstruction_state(1),
            vec![],
            super::CanonicalizationPolicy::default(),
            100_000,
            options.clone(),
            generation,
            slot,
            &mut super::ReplaySlice::new(std::time::Instant::now(), 1),
        )
    };
    let mut slot = None;
    assert!(advance(&mut slot, 1).unwrap().is_none());
    assert_eq!(slot.as_ref().unwrap().completed_probes(), 1);
    for message in &messages[4..] {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
    }
    let ledger_before = storage.list_messages(&group_id, EpochId(0)).unwrap();
    assert!(advance(&mut slot, 1).unwrap().is_none());
    assert_eq!(
        slot.as_ref().unwrap().completed_probes(),
        2,
        "later arrivals must not restart the frozen search"
    );
    assert!(advance(&mut slot, 2).unwrap().is_none());
    assert_eq!(
        slot.as_ref().unwrap().completed_probes(),
        1,
        "new pass must not inherit the old pass's progress"
    );
    let actual = (0..32)
        .find_map(|_| advance(&mut slot, 2).unwrap())
        .expect("frozen search completes");
    assert!(
        actual == expected,
        "later arrivals altered frozen branch selection"
    );
    assert!(storage.list_messages(&group_id, EpochId(0)).unwrap() == ledger_before);
}

#[tokio::test]
async fn resumable_invalidation_restart_panic_and_cumulative_budget_preserve_state() {
    let (_root, storage, group_id, messages) = encrypted_replay_graph_fixture(6, 3, 2).await;
    storage
        .create_group_state_snapshot(&group_id, &super::retained_anchor_snapshot_name(1))
        .unwrap();
    adopt_branch(&storage, &group_id, &messages[0]);
    for message in &messages[..4] {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
    }
    let state = reconstruction_state(2);
    let before = replay_state(&storage, &group_id);
    let mut slot = None;
    let advance = |slot: &mut Option<super::CanonicalReplay>, options| {
        super::canonicalize_stored_slice(
            &storage,
            &group_id,
            state.clone(),
            vec![],
            super::CanonicalizationPolicy::default(),
            100_000,
            options,
            1,
            slot,
            &mut super::ReplaySlice::new(std::time::Instant::now(), 32),
        )
    };
    assert!(advance(&mut slot, Default::default()).unwrap().is_none());
    // A new relevant branch must invalidate partial work even if the live
    // epoch and MLS mutation generation did not change.
    for message in &messages[4..] {
        admit_rival(
            &storage,
            &group_id,
            message,
            super::project_mls_message(&message.payload)
                .unwrap()
                .source_epoch
                .unwrap(),
        );
    }
    assert!(advance(&mut slot, Default::default()).unwrap().is_none());
    assert!(replay_state(&storage, &group_id) == before);
    // Restore writes change the backend generation even when the restored
    // bytes equal the live state. Reuse must be conservative here too.
    storage
        .create_group_state_snapshot(&group_id, "same-state")
        .unwrap();
    storage
        .rollback_group_state_to_snapshot(&group_id, "same-state")
        .unwrap();
    storage
        .release_group_snapshot(&group_id, "same-state")
        .unwrap();
    assert!(advance(&mut slot, Default::default()).unwrap().is_none());
    PANIC_AFTER_REPLAY.set(true);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| advance(
            &mut slot,
            Default::default()
        )))
        .is_err()
    );
    assert!(slot.is_none(), "unwound scratch work must be discarded");
    assert!(replay_state(&storage, &group_id) == before);
    assert!(advance(&mut slot, Default::default()).unwrap().is_none());
    drop(slot.take()); // cancellation/restart loses only scratch progress
    let actual = (0..64)
        .find_map(|_| {
            let result = advance(&mut slot, Default::default()).unwrap();
            assert!(replay_state(&storage, &group_id) == before);
            result
        })
        .expect("eventually completes after restart");
    let expected = super::canonicalize_stored_openmls_messages_with_profile_policy(
        &storage,
        &group_id,
        state.clone(),
        vec![],
        super::CanonicalizationPolicy::default(),
        100_000,
        Default::default(),
    )
    .unwrap();
    assert!(actual == expected);
    let options = super::StoredCanonicalizationOptions {
        replay_probe_budget_override: Some(2),
        ..Default::default()
    };
    assert!(advance(&mut slot, options.clone()).unwrap().is_none());
    assert!(advance(&mut slot, options.clone()).unwrap().is_none());
    assert!(matches!(
        advance(&mut slot, options),
        Err(super::OpenMlsProjectionError::ReplayBudgetExceeded)
    ));
    assert!(slot.is_none());
    assert!(replay_state(&storage, &group_id) == before);
    assert!(advance(&mut slot, Default::default()).unwrap().is_none());
    storage
        .release_group_snapshot(&group_id, &super::retained_anchor_snapshot_name(1))
        .unwrap();
    let unavailable = advance(&mut slot, Default::default())
        .unwrap()
        .expect("missing anchor has a complete verdict");
    assert!(
        unavailable
            .errors
            .contains(&super::CanonicalizationError::MissingRetainedAnchor)
    );
    assert!(unavailable.selected_branch_id.is_none());
}

#[tokio::test]
#[ignore = "isolated encrypted candidate reconstruction measurement; --nocapture"]
async fn candidate_reconstruction_measurement() {
    for size in [10, 20, 50] {
        for (width, depth) in [(10, 1), (1, 8), (8, 4)] {
            let (_root, storage, group_id, messages) =
                encrypted_replay_graph_fixture(size, width, depth).await;
            for message in &messages {
                let epoch = super::project_mls_message(&message.payload)
                    .unwrap()
                    .source_epoch
                    .unwrap();
                admit_rival(&storage, &group_id, message, epoch);
            }
            let before = replay_state(&storage, &group_id);
            let inputs =
                super::seed_stored_openmls_graph_inputs(&storage, &group_id, 0, None).unwrap();
            let mut budget = super::ReplayBudget::for_pass(messages.len(), 64);
            let start = std::time::Instant::now();
            let result = super::build_stored_openmls_candidate_paths(
                &storage,
                &group_id,
                inputs.commit_messages.clone(),
                &inputs.pending_messages,
                inputs.replay_start_epoch,
                &inputs.own_commits,
                ReplayProfilePolicy::default(),
                &mut budget,
            )
            .unwrap();
            let elapsed = start.elapsed().as_micros();
            assert_eq!(result.candidate_paths.len(), width);
            assert!(
                result
                    .materialized
                    .iter()
                    .all(|c| c.tip_epoch == 1 + depth as u64)
            );
            assert!(replay_state(&storage, &group_id) == before);
            let mut durations = budget
                .probe_measurements
                .iter()
                .map(|(_, us)| *us)
                .collect::<Vec<_>>();
            durations.sort();
            let mut search = super::resumable::CandidateSearch::new(
                inputs.commit_messages,
                &inputs.pending_messages,
                inputs.replay_start_epoch,
            )
            .unwrap();
            let mut sliced_budget = super::ReplayBudget::for_pass(messages.len(), 64);
            let sliced_start = std::time::Instant::now();
            let mut slice_times = Vec::new();
            loop {
                let start = std::time::Instant::now();
                let complete = search
                    .advance(
                        &storage,
                        &group_id,
                        &inputs.own_commits,
                        ReplayProfilePolicy::default(),
                        &mut sliced_budget,
                        &mut super::ReplaySlice::new(
                            start + std::time::Duration::from_millis(500),
                            32,
                        ),
                    )
                    .unwrap();
                slice_times.push(start.elapsed().as_micros());
                assert!(replay_state(&storage, &group_id) == before);
                if complete {
                    break;
                }
            }
            let sliced_total = sliced_start.elapsed().as_micros();
            assert!(search.finish() == result);
            assert_eq!(sliced_budget.consumed, budget.consumed);
            eprintln!(
                "sliced measurement: members={size} width={width} depth={depth} elapsed_us={sliced_total} slices={} max_slice_us={} probes={}",
                slice_times.len(),
                slice_times.iter().max().unwrap(),
                sliced_budget.consumed
            );
            eprintln!(
                "candidate measurement: members={size} width={width} depth={depth} elapsed_us={elapsed} probes={} replay_message_inputs={} median_probe_us={} max_probe_us={}",
                budget.consumed,
                budget
                    .probe_measurements
                    .iter()
                    .map(|(n, _)| n)
                    .sum::<usize>(),
                durations[durations.len() / 2],
                durations.last().unwrap()
            );
        }
    }
}

#[tokio::test]
async fn replay_transaction_preserves_results_and_restores_after_error_and_panic() {
    use cgka_traits::storage::{OutboundIntentStorage, QueuedOutboundIntent};
    let (_root, storage, group_id, rivals) = encrypted_replay_fixture(4).await;
    admit_rival(&storage, &group_id, &rivals[0], 1);
    let queued = QueuedOutboundIntent {
        id: MessageId::new(b"retained-replay-work".to_vec()),
        group_id: group_id.clone(),
        intent: SendIntent::AppMessage {
            expected_epoch: None,
            group_id: group_id.clone(),
            payload: b"retained".to_vec(),
        },
        created_at_ms: 1,
        reissue_attempts: 0,
    };
    storage.put_queued_outbound_intent(&queued).unwrap();
    let before = replay_state(&storage, &group_id);
    let ledger = storage.list_messages(&group_id, EpochId(0)).unwrap();
    let own = super::PrevalidatedOwnCommits::default();
    let check = || {
        assert!(
            replay_state(&storage, &group_id) == before,
            "live MLS/group/snapshots changed"
        );
        assert!(
            storage.list_messages(&group_id, EpochId(0)).unwrap() == ledger,
            "input ledger changed"
        );
        assert!(
            storage.list_queued_outbound_intents(&group_id).unwrap() == vec![queued.clone()],
            "queued work changed"
        );
    };
    for rival in &rivals {
        let messages = std::slice::from_ref(rival);
        let previous = super::replay_openmls_messages_probe(
            &storage,
            &group_id,
            messages,
            &own,
            ReplayProfilePolicy::default(),
        )
        .unwrap();
        let changed = super::replay_openmls_messages_prevalidated_output(
            &storage,
            &group_id,
            messages,
            &own,
            ReplayProfilePolicy::default(),
        )
        .unwrap();
        assert!(
            previous == changed,
            "transaction changed replay observations"
        );
        assert_eq!(changed.final_epoch, 2);
        check();
    }
    // A valid commit mutates MLS storage before the invalid suffix errors.
    let mut invalid = rivals[0].clone();
    invalid.payload = vec![0xff];
    let messages = [rivals[0].clone(), invalid];
    assert!(
        super::replay_openmls_messages_prevalidated_output(
            &storage,
            &group_id,
            &messages,
            &own,
            ReplayProfilePolicy::default()
        )
        .is_err()
    );
    check();
    // A nested caller may catch a probe error and continue its own transaction.
    storage
        .with_transaction(|_| -> Result<(), super::OpenMlsProjectionError> {
            assert!(
                super::replay_openmls_messages_prevalidated_output(
                    &storage,
                    &group_id,
                    &messages,
                    &own,
                    ReplayProfilePolicy::default()
                )
                .is_err()
            );
            check();
            Ok(())
        })
        .unwrap();
    let check_caught_panic = || {
        PANIC_AFTER_REPLAY.set(true);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::replay_openmls_messages_prevalidated_output(
                &storage,
                &group_id,
                &rivals[..1],
                &own,
                ReplayProfilePolicy::default(),
            )
        }));
        assert!(panic.is_err());
        check();
    };
    check_caught_panic();
    // Nested transactions have no savepoint: the snapshot guard must also
    // restore a panic caught by a caller that then commits its outer work.
    storage
        .with_transaction(|_| -> Result<(), super::OpenMlsProjectionError> {
            check_caught_panic();
            Ok(())
        })
        .unwrap();
    check();
    // A fresh successful call proves transaction ownership was released.
    super::replay_openmls_messages_prevalidated_output(
        &storage,
        &group_id,
        &rivals[..1],
        &own,
        ReplayProfilePolicy::default(),
    )
    .unwrap();
    check();
}

#[tokio::test]
#[ignore = "paired encrypted WAL/FULL replay measurement; --nocapture"]
async fn replay_transaction_measurement() {
    let (_root, storage, group_id, rivals) = encrypted_replay_fixture(20).await;
    let before = replay_state(&storage, &group_id);
    let own = super::PrevalidatedOwnCommits::default();
    let mut elapsed = [Vec::new(), Vec::new()];
    for round in 0..8 {
        for batched in if round % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let start = std::time::Instant::now();
            for rival in &rivals {
                let output = if batched {
                    super::replay_openmls_messages_prevalidated_output(
                        &storage,
                        &group_id,
                        std::slice::from_ref(rival),
                        &own,
                        ReplayProfilePolicy::default(),
                    )
                } else {
                    super::replay_openmls_messages_probe(
                        &storage,
                        &group_id,
                        std::slice::from_ref(rival),
                        &own,
                        ReplayProfilePolicy::default(),
                    )
                }
                .unwrap();
                assert_eq!(output.final_epoch, 2);
            }
            elapsed[usize::from(batched)].push(start.elapsed().as_micros());
            assert!(replay_state(&storage, &group_id) == before);
        }
    }
    eprintln!(
        "replay measurement: members=20 probes_per_sample=3 unbatched_us={:?} batched_us={:?}",
        elapsed[0], elapsed[1]
    );
}

// --- The halts -----------------------------------------------------------

#[tokio::test]
async fn a_lost_own_commit_checkpoint_halts_enumeration_and_keeps_the_fork() {
    let (mut alice, alice_storage) = build_client(b"peel-halt-alice");
    let (mut bob, bob_storage) = build_client(b"peel-halt-bob");
    let group_id = group_with(&mut alice, &mut [&mut bob]).await;

    // Alice commits at epoch 1 and advances; Bob forks from the same epoch.
    let own_commit = match alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));
    let rival = rival_commit(&bob_storage, &member_id(b"peel-halt-bob"), &group_id);
    admit_rival(&alice_storage, &group_id, &rival, 1);

    // Control: with the checkpoint in place both branches materialize, so
    // the halt below is what empties the contexts — not a graph that never
    // had two branches to enumerate.
    let enumerated = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
    assert!(enumerated.contested);
    assert!(
        enumerated.contexts.len() > 1,
        "a two-way epoch-1 fork offers a context per branch"
    );

    // MLS cannot replay this device's own path-bearing commit from the
    // public wire echo, so losing its post-merge checkpoint costs
    // enumeration the branch it is standing on.
    let checkpoint = own_commit_checkpoint_id(&alice_storage, &own_commit.id).unwrap();
    alice_storage
        .release_group_state_checkpoint(&group_id, &checkpoint)
        .unwrap();

    let halted = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
    assert!(
        halted.contexts.is_empty(),
        "a missing own-commit checkpoint must halt enumeration"
    );
    assert!(
        halted.contested,
        "the fork is in the stored graph, not in what enumeration managed to read"
    );
}

/// A same-epoch fork wide enough that probing it costs more replays than
/// the enumeration budget allows.
///
/// Every rival at the fork epoch becomes a frontier path, and every commit
/// at the next epoch is probed against every one of those paths: the budget
/// is linear in the commit count, the probes are its product.
const WIDTH: usize = 10;
const DEPTH: usize = 13;

/// `WIDTH * (1 + DEPTH)` probes against the smallest budget a legal rewind
/// allowance can produce. Held at compile time so that raising either
/// budget constant lands here, with the arithmetic in view, rather than as
/// a mystifying empty-context assertion.
const _: () = assert!(
    (WIDTH * (1 + DEPTH)) as u64
        > CANDIDATE_REPLAY_BUDGET_SLACK * (WIDTH + DEPTH) as u64 + CANDIDATE_REPLAY_BUDGET_FLOOR
);

#[tokio::test]
async fn an_exhausted_replay_budget_halts_enumeration_and_keeps_the_fork() {
    let (mut alice, alice_storage) = build_client(b"peel-budget-alice");
    let (mut bob, bob_storage) = build_client(b"peel-budget-bob");
    let (mut carol, carol_storage) = build_client(b"peel-budget-carol");
    let group_id = group_with(&mut alice, &mut [&mut bob, &mut carol]).await;

    // Bob forks the epoch WIDTH ways. Alice never leaves epoch 1, so every
    // rival is a branch she has to enumerate.
    let bob_id = member_id(b"peel-budget-bob");
    let mut fork = Vec::new();
    for _ in 0..WIDTH {
        let commit = rival_commit(&bob_storage, &bob_id, &group_id);
        admit_rival(&alice_storage, &group_id, &commit, 1);
        fork.push(commit);
    }

    // Carol adopts one branch and commits on it DEPTH times. Those commits
    // are valid only on that branch, but enumeration cannot know that
    // without probing each of them against every branch.
    adopt_branch(&carol_storage, &group_id, &fork[0]);
    assert_eq!(
        carol_storage.get_group(&group_id).unwrap().epoch,
        EpochId(2)
    );
    let carol_id = member_id(b"peel-budget-carol");
    for _ in 0..DEPTH {
        let commit = rival_commit(&carol_storage, &carol_id, &group_id);
        admit_rival(&alice_storage, &group_id, &commit, 2);
    }

    // Control: the same graph under the production rewind allowance has
    // budget to spare, so it enumerates instead of halting.
    let enumerated = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
    assert!(enumerated.contested);
    assert!(
        enumerated.contexts.len() > 1,
        "a {WIDTH}-way fork offers a context per branch"
    );

    let halted = peel(&alice_storage, &group_id, 0);
    assert!(
        halted.contexts.is_empty(),
        "an exhausted replay budget must halt enumeration"
    );
    assert!(
        halted.contested,
        "the fork is in the stored graph, not in what enumeration managed to read"
    );
}

// --- The cap -------------------------------------------------------------

/// The epoch every device in these fixtures is standing on when the fork
/// happens, so a one-commit branch tips at `FORK_EPOCH + 1` and the
/// two-commit branch at `FORK_EPOCH + 2`.
const FORK_EPOCH: u64 = 1;

/// Wide enough that the surviving branches outnumber the cap: one rival per
/// width, minus the one Carol extends, plus her deeper branch.
const WIDE_FORK_WIDTH: usize = MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS + 2;

/// A fork wider than the cap, with one branch carried a commit deeper, as
/// stored by two devices that never left the fork epoch.
///
/// Bob forks [`WIDE_FORK_WIDTH`] ways and Carol adopts one rival and commits
/// on it, so each observer holds `WIDE_FORK_WIDTH - 1` one-commit branches
/// plus one two-commit branch. Both observers are given the same evidence,
/// which is what lets a peer comparison mean anything.
async fn wide_fork_with_one_deep_branch() -> (GroupId, SqliteAccountStorage, SqliteAccountStorage) {
    let (mut alice, alice_storage) = build_client(b"peel-rank-alice");
    let (mut bob, bob_storage) = build_client(b"peel-rank-bob");
    let (mut carol, carol_storage) = build_client(b"peel-rank-carol");
    let (mut dave, dave_storage) = build_client(b"peel-rank-dave");
    let group_id = group_with(&mut alice, &mut [&mut bob, &mut carol, &mut dave]).await;

    let bob_id = member_id(b"peel-rank-bob");
    let mut fork = Vec::new();
    for _ in 0..WIDE_FORK_WIDTH {
        let commit = rival_commit(&bob_storage, &bob_id, &group_id);
        for observer in [&alice_storage, &dave_storage] {
            admit_rival(observer, &group_id, &commit, FORK_EPOCH);
        }
        fork.push(commit);
    }

    adopt_branch(&carol_storage, &group_id, &fork[0]);
    let deeper = rival_commit(&carol_storage, &member_id(b"peel-rank-carol"), &group_id);
    for observer in [&alice_storage, &dave_storage] {
        admit_rival(observer, &group_id, &deeper, FORK_EPOCH + 1);
    }

    (group_id, alice_storage, dave_storage)
}

fn branch_ids(survey: &CandidateBranchPeel) -> Vec<String> {
    survey
        .contexts
        .iter()
        .map(|context| context.branch_id.clone())
        .collect()
}

#[tokio::test]
async fn a_fork_wider_than_the_cap_keeps_the_same_branches_on_every_peer() {
    let (group_id, alice_storage, dave_storage) = wide_fork_with_one_deep_branch().await;

    let alice = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);
    let dave = peel(&dave_storage, &group_id, V1_MAX_REWIND_COMMITS);

    assert!(alice.contested && dave.contested);
    assert_eq!(
        alice.contexts.len(),
        MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS,
        "a graph offering more branches than the cap must fill it exactly"
    );
    assert_eq!(
        branch_ids(&alice),
        branch_ids(&dave),
        "the capped subset is content-derived, so peers holding the same \
         evidence must keep the same branches in the same order"
    );
}

#[tokio::test]
async fn a_deeper_branch_outranks_shallow_rivals_for_the_capped_contexts() {
    let (group_id, alice_storage, _dave_storage) = wide_fork_with_one_deep_branch().await;

    let survey = peel(&alice_storage, &group_id, V1_MAX_REWIND_COMMITS);

    assert_eq!(
        survey.contexts.iter().map(|c| c.tip_epoch).max(),
        Some(FORK_EPOCH + 2),
        "a branch carried two commits deep holds traffic the one-commit \
         rivals cannot unseal, so filling the cap with rivals must not \
         evict it"
    );
}

#[tokio::test]
async fn uncontested_peel_skips_replay_state_fingerprint() {
    let (_directory, storage, group_id, _) = encrypted_replay_graph_fixture(4, 1, 1).await;
    super::resumable::REPLAY_FINGERPRINT_READS.with(|reads| reads.set(0));
    let result = super::candidate_peel_slice(
        &storage,
        &group_id,
        0,
        64,
        ReplayProfilePolicy::default(),
        8,
        &mut None,
        &mut super::ReplaySlice::unlimited(),
    )
    .unwrap()
    .unwrap();
    assert!(!result.contested);
    assert_eq!(
        super::resumable::REPLAY_FINGERPRINT_READS.with(|reads| reads.get()),
        0
    );
}
