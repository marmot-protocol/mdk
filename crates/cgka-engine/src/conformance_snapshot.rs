//! Synthetic conformance-only projection of canonical group state.
//!
//! This module is available only with the `test-conformance-snapshot` feature.
//! It deliberately returns a domain-separated commitment to MLS exporter state,
//! never the exporter secret itself. Production telemetry and application
//! surfaces must not enable or consume this interface.

use std::collections::BTreeMap;

use cgka_traits::app_components::GroupLifecycleV1;
use cgka_traits::convergence_pass::{ConvergencePassPhase, DurableConvergencePass};
use cgka_traits::engine_state::{EpochState, GroupLifecycleState};
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls::prelude::ProtocolVersion;
use openmls::treesync::Node;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider as OpenMlsStorageProvider};
use openmls_traits::types::VerifiableCiphersuite;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_codec::Serialize as _;

/// Machine-readable snapshot of the convergence constants owned by the engine
/// adapter. Keys are the stable ledger identifiers from the reliability plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceConstantSnapshot {
    pub schema_version: String,
    pub values: BTreeMap<String, u64>,
}

/// Capture the exact engine-owned values needed to reproduce and interpret a
/// conformance failure. App-runtime scheduler constants belong to later
/// adapters and are deliberately not invented here.
pub fn conformance_constant_snapshot() -> ConformanceConstantSnapshot {
    let mut values = BTreeMap::new();
    values.insert(
        "P1.max_rewind_commits".into(),
        crate::convergence::V1_MAX_REWIND_COMMITS,
    );
    values.insert(
        "P2.app_message_past_epoch_limit".into(),
        crate::canonicalization::V1_APP_MESSAGE_PAST_EPOCH_LIMIT,
    );
    values.insert(
        "P3.max_past_epochs".into(),
        crate::wire_format::DEFAULT_MAX_PAST_EPOCHS as u64,
    );
    values.insert(
        "P4.settlement_quiescence_ms".into(),
        crate::canonicalization::V1_SETTLEMENT_QUIESCENCE_MS,
    );
    values.insert(
        "P5.max_convergence_pass_ms".into(),
        crate::canonicalization::V1_MAX_CONVERGENCE_PASS_MS,
    );
    values.insert(
        "P6.witness_quorum_senders_per_epoch".into(),
        crate::convergence::V1_WITNESS_QUORUM_SENDERS_PER_EPOCH as u64,
    );
    values.insert(
        "P7.witness_quorum_epochs".into(),
        crate::convergence::V1_WITNESS_QUORUM_EPOCHS as u64,
    );
    values.insert(
        "P8.max_witness_override_depth".into(),
        crate::convergence::V1_MAX_WITNESS_OVERRIDE_DEPTH,
    );
    values.insert(
        "P9.sender_ratchet_out_of_order_tolerance".into(),
        crate::wire_format::DEFAULT_OUT_OF_ORDER_TOLERANCE as u64,
    );
    values.insert(
        "P10.sender_ratchet_maximum_forward_distance".into(),
        crate::wire_format::DEFAULT_MAXIMUM_FORWARD_DISTANCE as u64,
    );
    values.insert(
        "E1.max_convergence_reprocessing_passes".into(),
        crate::message_processor::MAX_CONVERGENCE_REPROCESSING_PASSES as u64,
    );
    values.insert(
        "E2.max_deferred_peel_attempts".into(),
        crate::message_processor::MAX_DEFERRED_PEEL_ATTEMPTS as u64,
    );
    values.insert(
        "E3.max_peel_deferred_rows_per_group".into(),
        crate::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP as u64,
    );
    values.insert(
        "E4.max_deferred_rows_per_sweep".into(),
        crate::message_processor::MAX_DEFERRED_ROWS_PER_SWEEP as u64,
    );
    values.insert(
        "E5.candidate_replay_budget_slack".into(),
        crate::openmls_projection::CANDIDATE_REPLAY_BUDGET_SLACK,
    );
    values.insert(
        "E6.candidate_replay_budget_floor".into(),
        crate::openmls_projection::CANDIDATE_REPLAY_BUDGET_FLOOR,
    );
    values.insert(
        "E7.self_remove_auto_commit_jitter_min_ms".into(),
        crate::message_processor::SELF_REMOVE_AUTO_COMMIT_JITTER_MIN_MS,
    );
    values.insert(
        "E7.self_remove_auto_commit_jitter_max_ms".into(),
        crate::message_processor::SELF_REMOVE_AUTO_COMMIT_JITTER_MIN_MS
            + crate::message_processor::SELF_REMOVE_AUTO_COMMIT_JITTER_SPAN_MS,
    );
    values.insert(
        "E8.max_deferred_peel_residence_ms".into(),
        crate::message_processor::MAX_DEFERRED_PEEL_RESIDENCE_MS,
    );
    values.insert(
        "E9.max_queued_outbound_intents_per_group".into(),
        crate::message_processor::MAX_QUEUED_OUTBOUND_INTENTS_PER_GROUP as u64,
    );
    values.insert(
        "E10.max_candidate_branch_peel_contexts".into(),
        crate::message_processor::MAX_CANDIDATE_BRANCH_PEEL_CONTEXTS as u64,
    );
    values.insert(
        "E11.foreground_deferred_peel_budget_ms".into(),
        crate::message_processor::FOREGROUND_DEFERRED_PEEL_BUDGET_MS,
    );
    values.insert(
        "E12.max_foreground_deferred_rows".into(),
        crate::message_processor::MAX_FOREGROUND_DEFERRED_ROWS as u64,
    );
    ConformanceConstantSnapshot {
        schema_version: "1".into(),
        values,
    }
}

/// MLS-Exporter label adopted by Marmot's conformance-state contract.
pub const CONFORMANCE_EXPORTER_LABEL: &str = "marmot";
/// MLS-Exporter context adopted by Marmot's conformance-state contract.
pub const CONFORMANCE_EXPORTER_CONTEXT: &[u8] = b"convergence-conformance-v1";
/// Domain separator applied before committing to the exporter secret.
pub const CONFORMANCE_COMMITMENT_DOMAIN: &[u8] = b"marmot-convergence-conformance-v1";
const CONFORMANCE_EXPORTER_LENGTH: usize = 32;

const _: [(); 33] = [(); CONFORMANCE_COMMITMENT_DOMAIN.len()];

/// Exact, implementation-neutral capability projection for one leaf.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceLeafCapabilities {
    pub versions: Vec<u16>,
    pub ciphersuites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
    pub app_components: Vec<u16>,
}

/// One nonblank MLS leaf, retained in leaf-index order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceLeafSnapshot {
    pub leaf_index: u32,
    pub account_identity_hex: String,
    pub signature_public_key_hex: String,
    pub capabilities: ConformanceLeafCapabilities,
}

/// Group-required capabilities from MLS and Marmot app-component state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRequiredCapabilities {
    pub extensions: Vec<u16>,
    pub proposals: Vec<u16>,
    pub credentials: Vec<u16>,
    pub app_components: Vec<u16>,
}

/// One exact `app_data_dictionary` entry in ascending component-id order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceAppComponent {
    pub component_id: u16,
    pub data_hex: String,
}

/// Canonical live-group state needed by the engine simulator's exact oracle.
///
/// Hashes and public protocol values are safe to serialize into synthetic test
/// artifacts. The raw exporter secret is never stored in this value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceGroupSnapshot {
    pub group_id_hex: String,
    pub epoch: u64,
    pub group_context_sha256: String,
    /// The GroupContext hash is also the branch identity used by this local
    /// black-box oracle. It names selected protocol state, not a transport row.
    pub selected_branch_id: String,
    pub exporter_commitment_sha256: String,
    pub leaves: Vec<ConformanceLeafSnapshot>,
    pub sorted_member_identities_hex: Vec<String>,
    pub required_capabilities: ConformanceRequiredCapabilities,
    pub app_components: Vec<ConformanceAppComponent>,
    pub protocol_lifecycle: Option<GroupLifecycleV1>,
    pub convergence_status: GroupLifecycleState,
    pub protocol_profile: ProtocolProfile,
    pub group_name: String,
    pub group_description: String,
    pub admin_identities_hex: Vec<String>,
}

/// Canonical terminal evidence retained after live MLS state is deleted.
///
/// Only cross-client protocol facts belong here. Device-local facts such as
/// whether this exact leaf authored the selected commit are deliberately
/// excluded so equivalent account devices compare equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceDisbandedGroupSnapshot {
    pub group_id_hex: String,
    pub epoch: u64,
    pub actor_identity_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_commit_id_hex: Option<String>,
    pub commit_digest_hex: String,
    pub former_member_identities_hex: Vec<String>,
    pub protocol_lifecycle: GroupLifecycleV1,
    pub convergence_status: GroupLifecycleState,
}

/// Exact canonical state for either a live MLS group or its terminal
/// authenticated disband tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "snapshot", rename_all = "snake_case")]
pub enum ConformanceCanonicalStateSnapshot {
    Live(Box<ConformanceGroupSnapshot>),
    Disbanded(ConformanceDisbandedGroupSnapshot),
}

/// Aggregate work that must be resolved before a simulator may call one
/// account-device quiescent.
///
/// This is diagnostic state, not protocol input. Counts are intentionally
/// payload- and identity-free so failure artifacts explain the blocking
/// subsystem without exposing message contents or group identifiers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformancePendingWorkSnapshot {
    pub non_stable_epoch_state: usize,
    pub recovering_buffered_messages: usize,
    pub active_convergence_passes: usize,
    pub active_convergence_pass_members: usize,
    pub unresolved_convergence_inputs: usize,
    pub queued_outbound_intents: usize,
    pub stored_created_messages: usize,
    pub stored_retryable_messages: usize,
    pub stored_transport_deferred_messages: usize,
    pub pending_engine_events: usize,
    pub pending_auto_publish: usize,
    pub pending_auto_proposals: usize,
    pub valid_proposal_schedule_signals: usize,
    pub pending_state_changes: usize,
    pub pending_leave_requests: usize,
    pub scheduled_self_remove_auto_commits: usize,
    pub scheduled_convergence_groups: usize,
    pub regenerated_standalone_publishes: usize,
    pub regenerated_pending_publishes: usize,
}

impl ConformancePendingWorkSnapshot {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Sanitized scheduling state used by black-box convergence simulators.
///
/// This is a read-only conformance surface. It exposes only aggregate work,
/// lifecycle phase, durable generation/epoch counters, and virtual-clock
/// deadlines. Message, member, account, and group identifiers are excluded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceStructuralProgressSnapshot {
    pub current_epoch: u64,
    pub current_monotonic_ms: u64,
    pub lifecycle: GroupLifecycleState,
    pub pending_work: ConformancePendingWorkSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_phase: Option<ConvergencePassPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_next_wake_monotonic_ms: Option<u64>,
    pub runnable_work: usize,
    #[serde(default)]
    pub terminal_unrecoverable: bool,
}

pub(crate) fn capture_group_snapshot<S: StorageProvider>(
    storage: &S,
    crypto: &RustCrypto,
    group_id: &GroupId,
    epoch_state: &EpochState,
) -> Result<ConformanceGroupSnapshot, EngineError> {
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    let mls_group = MlsGroup::load(storage.mls_storage(), &mls_group_id)
        .map_err(|error| EngineError::Backend(format!("load conformance group: {error:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
    let group_context: openmls::group::GroupContext = <S::Mls as OpenMlsStorageProvider<
        CURRENT_VERSION,
    >>::group_context(
        storage.mls_storage(), &mls_group_id
    )
    .map_err(|error| EngineError::Backend(format!("load conformance group context: {error:?}")))?
    .ok_or_else(|| {
        EngineError::Backend("conformance group context is missing from storage".into())
    })?;

    let group_context_bytes = group_context
        .tls_serialize_detached()
        .map_err(|error| EngineError::Serialize(format!("serialize group context: {error}")))?;
    let group_context_sha256 = hex::encode(Sha256::digest(group_context_bytes));

    let exporter_secret = mls_group
        .export_secret(
            crypto,
            CONFORMANCE_EXPORTER_LABEL,
            CONFORMANCE_EXPORTER_CONTEXT,
            CONFORMANCE_EXPORTER_LENGTH,
        )
        .map_err(|error| EngineError::Backend(format!("derive conformance exporter: {error:?}")))?;
    let mut commitment = Sha256::new();
    commitment.update(CONFORMANCE_COMMITMENT_DOMAIN);
    commitment.update([0]);
    commitment.update(&exporter_secret);
    let exporter_commitment_sha256 = hex::encode(commitment.finalize());
    drop(exporter_secret);

    let nodes = crate::app_components::ratchet_tree_nodes(mls_group.export_ratchet_tree())?;
    let mut leaves = Vec::new();
    for (node_index, node) in nodes.into_iter().enumerate() {
        let Some(Node::LeafNode(leaf)) = node else {
            continue;
        };
        let leaf_index = u32::try_from(node_index / 2)
            .map_err(|_| EngineError::Backend("conformance leaf index overflow".into()))?;
        let account_identity = crate::identity::validated_member_id_of_leaf(&leaf)?;
        let capabilities = leaf.capabilities();
        let mut app_components = crate::app_components::app_components_of_leaf(&leaf)?
            .ids
            .into_iter()
            .collect::<Vec<_>>();
        app_components.sort_unstable();
        leaves.push(ConformanceLeafSnapshot {
            leaf_index,
            account_identity_hex: hex::encode(account_identity.as_slice()),
            signature_public_key_hex: hex::encode(leaf.signature_key().as_slice()),
            capabilities: ConformanceLeafCapabilities {
                versions: capabilities
                    .versions()
                    .iter()
                    .map(protocol_version_u16)
                    .collect::<Result<_, _>>()?,
                ciphersuites: capabilities
                    .ciphersuites()
                    .iter()
                    .map(VerifiableCiphersuite::value)
                    .collect(),
                extensions: capabilities
                    .extensions()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .collect(),
                proposals: capabilities
                    .proposals()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .collect(),
                credentials: capabilities
                    .credentials()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .collect(),
                app_components,
            },
        });
    }

    let mut sorted_member_identities_hex = leaves
        .iter()
        .map(|leaf| leaf.account_identity_hex.clone())
        .collect::<Vec<_>>();
    sorted_member_identities_hex.sort();

    let required = group_context.required_capabilities();
    let mut required_app_components =
        crate::app_components::required_app_components_of_group(&mls_group)?
            .ids
            .into_iter()
            .collect::<Vec<_>>();
    required_app_components.sort_unstable();
    let required_capabilities = ConformanceRequiredCapabilities {
        extensions: required
            .map(|required| {
                required
                    .extension_types()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .collect()
            })
            .unwrap_or_default(),
        proposals: required
            .map(|required| {
                required
                    .proposal_types()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .collect()
            })
            .unwrap_or_default(),
        credentials: required
            .map(|required| {
                required
                    .credential_types()
                    .iter()
                    .copied()
                    .map(u16::from)
                    .collect()
            })
            .unwrap_or_default(),
        app_components: required_app_components,
    };

    let app_components = group_context
        .extensions()
        .app_data_dictionary()
        .map(|dictionary| {
            dictionary
                .dictionary()
                .entries()
                .map(|entry| ConformanceAppComponent {
                    component_id: entry.id(),
                    data_hex: hex::encode(entry.data()),
                })
                .collect()
        })
        .unwrap_or_default();

    let group = storage.get_group(group_id)?;
    let mut admin_identities_hex = crate::app_components::admins_of_group(&mls_group)?
        .into_iter()
        .map(hex::encode)
        .collect::<Vec<_>>();
    admin_identities_hex.sort();
    admin_identities_hex.dedup();

    Ok(ConformanceGroupSnapshot {
        group_id_hex: hex::encode(group_id.as_slice()),
        epoch: group_context.epoch().as_u64(),
        selected_branch_id: group_context_sha256.clone(),
        group_context_sha256,
        exporter_commitment_sha256,
        leaves,
        sorted_member_identities_hex,
        required_capabilities,
        app_components,
        protocol_lifecycle: crate::app_components::lifecycle_of_group(&mls_group)?,
        convergence_status: GroupLifecycleState::from(epoch_state),
        protocol_profile: group.protocol_profile,
        group_name: group.name,
        group_description: group.description,
        admin_identities_hex,
    })
}

pub(crate) fn capture_disbanded_group_snapshot(
    group_id: &GroupId,
    tombstone: &cgka_traits::DisbandTombstone,
) -> ConformanceDisbandedGroupSnapshot {
    let mut former_member_identities_hex = tombstone
        .former_members
        .iter()
        .map(|member| hex::encode(member.id.as_slice()))
        .collect::<Vec<_>>();
    former_member_identities_hex.sort();
    former_member_identities_hex.dedup();

    ConformanceDisbandedGroupSnapshot {
        group_id_hex: hex::encode(group_id.as_slice()),
        epoch: tombstone.epoch.0,
        actor_identity_hex: hex::encode(tombstone.actor.as_slice()),
        origin_commit_id_hex: tombstone
            .origin_commit_id
            .as_ref()
            .map(|message_id| hex::encode(message_id.as_slice())),
        commit_digest_hex: hex::encode(tombstone.commit_digest),
        former_member_identities_hex,
        protocol_lifecycle: GroupLifecycleV1::Disbanded,
        convergence_status: GroupLifecycleState::Disbanded,
    }
}

pub(crate) fn capture_pending_work_snapshot<S: StorageProvider>(
    engine: &crate::Engine<S>,
    group_id: &GroupId,
) -> Result<ConformancePendingWorkSnapshot, EngineError> {
    engine.ensure_group_live(group_id)?;
    let epoch_state = engine
        .epoch_manager
        .state(group_id)
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
    let lifecycle = GroupLifecycleState::from(epoch_state);
    let pass = engine.storage.convergence_pass(group_id)?;
    let messages = engine.storage.list_messages(group_id, EpochId(0))?;
    capture_pending_work_snapshot_from(
        engine,
        group_id,
        epoch_state,
        lifecycle,
        pass.as_ref(),
        &messages,
    )
}

fn capture_pending_work_snapshot_from<S: StorageProvider>(
    engine: &crate::Engine<S>,
    group_id: &GroupId,
    epoch_state: &EpochState,
    lifecycle: GroupLifecycleState,
    pass: Option<&DurableConvergencePass>,
    messages: &[MessageRecord],
) -> Result<ConformancePendingWorkSnapshot, EngineError> {
    let disbanded = engine.storage.disband_tombstone(group_id)?.is_some();
    let recovering_buffered_messages = match epoch_state {
        EpochState::Recovering(recovering) => recovering.buffered().len(),
        _ => 0,
    };

    let active_pass = pass.filter(|pass| pass.is_active());
    let mut stored_created_messages = 0;
    let mut stored_retryable_messages = 0;
    let mut stored_transport_deferred_messages = 0;
    for message in messages {
        match message.state {
            MessageState::Created => stored_created_messages += 1,
            MessageState::Retryable => stored_retryable_messages += 1,
            MessageState::PeelDeferred => stored_transport_deferred_messages += 1,
            MessageState::Sent
            | MessageState::Processed
            | MessageState::Failed
            | MessageState::ConvergenceDeferred
            | MessageState::EpochInvalidated => {}
        }
    }

    Ok(ConformancePendingWorkSnapshot {
        non_stable_epoch_state: usize::from(!matches!(
            lifecycle,
            GroupLifecycleState::Stable | GroupLifecycleState::Disbanded
        )),
        recovering_buffered_messages,
        active_convergence_passes: usize::from(active_pass.is_some()),
        active_convergence_pass_members: active_pass.map_or(0, |pass| pass.members.len()),
        unresolved_convergence_inputs: usize::from(if disbanded {
            false
        } else {
            engine.has_pending_convergence_inputs(group_id)?
        }),
        queued_outbound_intents: engine.storage.list_queued_outbound_intents(group_id)?.len(),
        stored_created_messages,
        stored_retryable_messages,
        stored_transport_deferred_messages,
        pending_engine_events: engine
            .events_buf
            .iter()
            .filter(|event| event_group_id(event) == group_id)
            .count(),
        pending_auto_publish: engine
            .auto_publish_buf
            .iter()
            .filter(|auto| {
                engine
                    .epoch_manager
                    .group_for_pending(auto.pending)
                    .as_ref()
                    == Some(group_id)
            })
            .count(),
        pending_auto_proposals: pending_auto_proposals_for_group(engine, group_id)?,
        valid_proposal_schedule_signals: usize::from(
            engine.valid_proposal_groups.contains(group_id),
        ),
        pending_state_changes: engine
            .pending_state_changes
            .keys()
            .filter(|pending| {
                engine.epoch_manager.group_for_pending(**pending).as_ref() == Some(group_id)
            })
            .count(),
        pending_leave_requests: usize::from(engine.leave_requests.contains_key(group_id)),
        scheduled_self_remove_auto_commits: engine
            .scheduled_self_remove_auto_commits
            .values()
            .filter(|scheduled| scheduled.group_id == *group_id)
            .count(),
        scheduled_convergence_groups: usize::from(
            engine.pending_convergence_groups.contains(group_id),
        ),
        regenerated_standalone_publishes: engine
            .queued_intent_by_message
            .values()
            .filter(|(queued_group_id, _)| queued_group_id == group_id)
            .count(),
        regenerated_pending_publishes: engine
            .queued_intent_by_pending
            .values()
            .filter(|(queued_group_id, _)| queued_group_id == group_id)
            .count(),
    })
}

pub(crate) fn capture_structural_progress_snapshot<S: StorageProvider>(
    engine: &crate::Engine<S>,
    group_id: &GroupId,
) -> Result<ConformanceStructuralProgressSnapshot, EngineError> {
    engine.ensure_group_live(group_id)?;
    let epoch_state = engine
        .epoch_manager
        .state(group_id)
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
    let lifecycle = GroupLifecycleState::from(epoch_state);
    let current_epoch = engine.epoch_manager.epoch(group_id).unwrap_or_default().0;
    let now = engine.convergence_now();
    let mut pass = engine.storage.convergence_pass(group_id)?;
    if let Some(active) = pass.as_mut().filter(|pass| pass.is_active()) {
        let policy = engine
            .convergence_policy_for_group(group_id)
            .map_err(|error| {
                EngineError::Backend(format!("load convergence policy for snapshot: {error}"))
            })?;
        crate::distributed_convergence::normalize_convergence_pass_for_runtime(
            active,
            &policy,
            now,
            engine.convergence_clock_instance_id,
        );
    }
    let messages = engine.storage.list_messages(group_id, EpochId(0))?;
    let pending_work = capture_pending_work_snapshot_from(
        engine,
        group_id,
        epoch_state,
        lifecycle,
        pass.as_ref(),
        &messages,
    )?;

    let mut runnable_work = 0usize;
    let mut next_wake = None;
    if let Some(active) = pass.as_ref().filter(|pass| pass.is_active()) {
        match active.phase {
            ConvergencePassPhase::Collecting => {
                let cutoff = active.cutoff_monotonic_ms();
                if cutoff <= now.monotonic_ms {
                    runnable_work = runnable_work.saturating_add(1);
                } else {
                    next_wake = Some(cutoff);
                }
            }
            ConvergencePassPhase::Frozen | ConvergencePassPhase::Resolving => {
                runnable_work = runnable_work.saturating_add(1);
            }
            ConvergencePassPhase::Completed => {}
        }
    }

    let mut deferred_normalizations = 0usize;
    for record in messages
        .iter()
        .filter(|record| record.state == MessageState::PeelDeferred)
    {
        let (deferred, changed) = crate::message_processor::normalized_deferred_peel_lifecycle(
            record.deferred_peel.as_ref(),
            now,
            engine.convergence_clock_instance_id,
            engine.deferred_peel_residence_ms,
        );
        deferred_normalizations = deferred_normalizations.saturating_add(usize::from(changed));
        let deadline = deferred.residence_deadline_monotonic_ms;
        if deadline <= now.monotonic_ms {
            runnable_work = runnable_work.saturating_add(1);
        } else {
            next_wake = Some(next_wake.map_or(deadline, |current: u64| current.min(deadline)));
        }
    }
    if deferred_normalizations > crate::message_processor::MAX_DEFERRED_ROWS_PER_SWEEP {
        // Runtime maintenance persists lifecycle migrations in bounded slices
        // and immediately schedules another slice while normalization remains.
        runnable_work = runnable_work.saturating_add(1);
        next_wake =
            Some(next_wake.map_or(now.monotonic_ms, |current| current.min(now.monotonic_ms)));
    }

    for scheduled in engine
        .scheduled_self_remove_auto_commits
        .values()
        .filter(|scheduled| scheduled.group_id == *group_id)
    {
        if scheduled.due_at_ms <= now.monotonic_ms {
            runnable_work = runnable_work.saturating_add(1);
        } else {
            next_wake = Some(next_wake.map_or(scheduled.due_at_ms, |current: u64| {
                current.min(scheduled.due_at_ms)
            }));
        }
    }

    let future_scheduled_work = pass
        .as_ref()
        .is_some_and(|pass| pass.phase == ConvergencePassPhase::Collecting)
        || engine
            .scheduled_self_remove_auto_commits
            .values()
            .any(|scheduled| scheduled.group_id == *group_id);
    if engine.pending_convergence_groups.contains(group_id) && !future_scheduled_work {
        runnable_work = runnable_work.saturating_add(1);
    }
    // The schedule above is an edge a host consumes once; a durable intent is
    // level state that outlives an unproductive drain. It stays runnable until
    // the drain regenerates it and hands it to the app, which then owes the
    // confirm or the retry. `Stable` is the drain's own precondition, and a
    // pass inside its window reports the cutoff as the next wake instead.
    let unreleased_outbound_intents = pending_work
        .queued_outbound_intents
        .saturating_sub(pending_work.regenerated_standalone_publishes)
        .saturating_sub(pending_work.regenerated_pending_publishes);
    if unreleased_outbound_intents > 0
        && lifecycle == GroupLifecycleState::Stable
        && !future_scheduled_work
    {
        runnable_work = runnable_work.saturating_add(1);
    }
    if pass.is_none() && pending_work.unresolved_convergence_inputs > 0 {
        runnable_work = runnable_work.saturating_add(1);
    }
    runnable_work = runnable_work
        .saturating_add(pending_work.recovering_buffered_messages)
        .saturating_add(pending_work.pending_engine_events)
        .saturating_add(pending_work.pending_auto_publish)
        .saturating_add(pending_work.pending_auto_proposals)
        .saturating_add(pending_work.valid_proposal_schedule_signals);

    Ok(ConformanceStructuralProgressSnapshot {
        current_epoch,
        current_monotonic_ms: now.monotonic_ms,
        lifecycle,
        pending_work,
        pass_generation: pass.as_ref().map(|pass| pass.generation),
        pass_phase: pass.as_ref().map(|pass| pass.phase),
        earliest_next_wake_monotonic_ms: next_wake,
        runnable_work,
        terminal_unrecoverable: lifecycle == GroupLifecycleState::Unrecoverable,
    })
}

fn pending_auto_proposals_for_group<S: StorageProvider>(
    engine: &crate::Engine<S>,
    group_id: &GroupId,
) -> Result<usize, EngineError> {
    let mut count = 0;
    for proposal in &engine.auto_proposal_buf {
        match engine.storage.get_message(&proposal.id) {
            Ok(record) if record.group_id == *group_id => count += 1,
            Ok(_) => {}
            Err(StorageError::NotFound) => {
                return Err(EngineError::Backend(
                    "conformance auto-proposal buffer references a missing durable row".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(count)
}

fn event_group_id(event: &cgka_traits::engine::GroupEvent) -> &GroupId {
    use cgka_traits::engine::GroupEvent;

    match event {
        GroupEvent::GroupCreated { group_id }
        | GroupEvent::GroupJoined { group_id, .. }
        | GroupEvent::TransportObjectResourceRefused { group_id, .. }
        | GroupEvent::MessageReceived { group_id, .. }
        | GroupEvent::AppMessageInvalidated { group_id, .. }
        | GroupEvent::GroupStateChanged { group_id, .. }
        | GroupEvent::GroupHydrationQuarantined { group_id, .. }
        | GroupEvent::EpochChanged { group_id, .. }
        | GroupEvent::CommitRolledBack { group_id, .. }
        | GroupEvent::GroupStateInvalidated { group_id, .. }
        | GroupEvent::GroupUnrecoverable { group_id }
        | GroupEvent::PendingCommitRecovered { group_id, .. }
        | GroupEvent::GroupHydrationRecovered { group_id, .. } => group_id,
    }
}

fn protocol_version_u16(version: &ProtocolVersion) -> Result<u16, EngineError> {
    let bytes = version
        .tls_serialize_detached()
        .map_err(|error| EngineError::Serialize(format!("serialize protocol version: {error}")))?;
    let bytes: [u8; 2] = bytes.try_into().map_err(|_| {
        EngineError::Serialize("protocol version did not serialize to two bytes".into())
    })?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::{DisbandTombstone, Member, MemberId, MessageId};

    #[test]
    fn commitment_domain_is_the_adopted_33_byte_value() {
        assert_eq!(CONFORMANCE_COMMITMENT_DOMAIN.len(), 33);
        assert_eq!(
            CONFORMANCE_COMMITMENT_DOMAIN,
            b"marmot-convergence-conformance-v1"
        );
    }

    #[test]
    fn constant_snapshot_pins_every_engine_owned_reliability_constant() {
        let snapshot = conformance_constant_snapshot();
        assert_eq!(snapshot.schema_version, "1");
        assert_eq!(snapshot.values.len(), 23);
        for key in [
            "P1.max_rewind_commits",
            "P2.app_message_past_epoch_limit",
            "P3.max_past_epochs",
            "P4.settlement_quiescence_ms",
            "P5.max_convergence_pass_ms",
            "P6.witness_quorum_senders_per_epoch",
            "P7.witness_quorum_epochs",
            "P8.max_witness_override_depth",
            "P9.sender_ratchet_out_of_order_tolerance",
            "P10.sender_ratchet_maximum_forward_distance",
            "E1.max_convergence_reprocessing_passes",
            "E2.max_deferred_peel_attempts",
            "E3.max_peel_deferred_rows_per_group",
            "E4.max_deferred_rows_per_sweep",
            "E5.candidate_replay_budget_slack",
            "E6.candidate_replay_budget_floor",
            "E7.self_remove_auto_commit_jitter_min_ms",
            "E7.self_remove_auto_commit_jitter_max_ms",
            "E8.max_deferred_peel_residence_ms",
            "E9.max_queued_outbound_intents_per_group",
            "E10.max_candidate_branch_peel_contexts",
            "E11.foreground_deferred_peel_budget_ms",
            "E12.max_foreground_deferred_rows",
        ] {
            assert!(snapshot.values.contains_key(key), "missing {key}");
        }
    }

    #[test]
    fn disband_projection_excludes_device_local_authorship_and_canonicalizes_roster() {
        let group_id = GroupId::new(vec![0x10, 0x20]);
        let alice = Member {
            id: MemberId::new(vec![0xa1]),
            credential: vec![0x01],
        };
        let bob = Member {
            id: MemberId::new(vec![0xb2]),
            credential: vec![0x02],
        };
        let base = DisbandTombstone {
            epoch: EpochId(7),
            actor: alice.id.clone(),
            origin_commit_id: Some(MessageId::new(vec![0xc3])),
            commit_digest: [0xd4; 32],
            local_was_committer_leaf: true,
            former_members: vec![bob.clone(), alice.clone(), bob],
            announced: false,
        };
        let sibling_device = DisbandTombstone {
            local_was_committer_leaf: false,
            former_members: vec![alice, base.former_members[0].clone()],
            ..base.clone()
        };

        assert_eq!(
            capture_disbanded_group_snapshot(&group_id, &base),
            capture_disbanded_group_snapshot(&group_id, &sibling_device),
            "device-local authorship and roster order/duplicates must not split canonical state"
        );
    }
}
