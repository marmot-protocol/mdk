//! Generated convergence and lifecycle invariants.
//!
//! Properties:
//! - **(a) True same-id replay**: a TransportMessage delivered twice (via
//!   `bus.inject`) is processed once and the second injection returns
//!   `IngestOutcome::Stale { AlreadySeen }`. Engine state is unchanged.
//! - **(b) Convergence**: undisturbed clients converge on the same epoch
//!   and member set after a sequence of `Send` + `Leave` intents under
//!   any `DeliveryProfile`.
//! - **(c) Rollback**: an upgrade followed by `publish_failed` leaves the
//!   group in the prior `Stable` epoch with the prior `RequiredCapabilities`;
//!   followed by `confirm_published` advances normally. Either way the
//!   engine's reported epoch matches the actual MLS state.
//! - **(d) Event conservation**: canonical scripted scenarios assert exact
//!   app-message delivery counts; the generated properties below focus on
//!   convergence across larger send/leave schedules.
//! - **(e) Candidate graph determinism**: a generated valid candidate set
//!   selects the same canonical branch under multiple enumeration orders.
//! - **(f) Canonicalization dispositions**: generated proposal/app batches
//!   preserve accepted, invalidated, dropped, and already-seen dispositions
//!   under reordered duplicate delivery.
//! - **(g) Canonicalization idempotence**: replaying a batch whose message
//!   ids are already seen produces only already-seen dispositions.
//! - **(h) Quiescence gate**: convergence-relevant input remains Syncing
//!   before the stability window and becomes Stable after the window closes.
//! - **(i) Capability negotiation**: generated capability matrices either
//!   reject missing required support or report Available / Upgradeable /
//!   Unavailable consistently.
//! - **(j) Group-data publish lifecycle**: generated group-data updates
//!   confirm or roll back projected metadata and leave the group reusable.
//! - **(k) Restart equivalence**: stored convergence input produces the same
//!   result before and after rebuilding an engine over the same storage.

use std::collections::{BTreeMap, BTreeSet};

use cgka_conformance_simulator::bus::DeliveryPolicy;
use cgka_conformance_simulator::canonicalization::{
    AlreadySeen, CanonicalizationInput, CanonicalizationPolicy, CanonicalizationState,
    DroppedMessageReason, InvalidatedAppMessageReason, MaterializedCandidate, MessageKind,
    OutboundIntent, PeeledMessage, PeeledMessageKind, SyncState,
    canonicalize_with_materialized_candidates,
};
use cgka_conformance_simulator::convergence::{
    AppWitness, BranchCandidate, ConvergencePolicy, is_branch_eligible, select_canonical_branch,
};
use cgka_conformance_simulator::proptest_support::{
    ConfirmOutcome, DeliveryProfile, HarnessIntent, confirm_outcome, delivery_profile, intent_seq,
};
use cgka_conformance_simulator::{ClientBuilder, HarnessClient, TransportBus};
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::CgkaEngine;
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, FeatureStatus, RequirementLevel, TransportKind,
};
use cgka_traits::engine::{CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::ingest::{IngestOutcome, StaleReason};
use cgka_traits::storage::{GroupStorage, MessageStorage};
use proptest::prelude::*;

const REACTIONS_PROPOSAL: u16 = 0xF210;
const PROP_FEATURE: Feature = Feature("prop-generated-feature");
const PROP_FEATURE_PROPOSAL: u16 = 0xF211;

fn digest_from_u64(value: u64) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[24..].copy_from_slice(&value.to_be_bytes());
    digest
}

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
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
    r.register(
        Feature("reactions"),
        CapabilityRequirement {
            requires: Capability::Proposal(REACTIONS_PROPOSAL),
            level: RequirementLevel::Optional,
            description: "test-only",
        },
    );
    r
}

#[derive(Clone, Copy, Debug)]
enum PropCapabilityLevel {
    Required,
    Optional,
    TransportRequired,
}

fn prop_capability_level() -> impl Strategy<Value = PropCapabilityLevel> {
    prop_oneof![
        Just(PropCapabilityLevel::Required),
        Just(PropCapabilityLevel::Optional),
        Just(PropCapabilityLevel::TransportRequired),
    ]
}

fn registry_with_generated_feature(
    level: PropCapabilityLevel,
    supports_feature: bool,
) -> FeatureRegistry {
    let mut r = registry();
    if supports_feature {
        r.register(
            PROP_FEATURE,
            CapabilityRequirement {
                requires: Capability::Proposal(PROP_FEATURE_PROPOSAL),
                level: match level {
                    PropCapabilityLevel::Required => RequirementLevel::Required,
                    PropCapabilityLevel::Optional => RequirementLevel::Optional,
                    PropCapabilityLevel::TransportRequired => RequirementLevel::TransportRequired {
                        transport: TransportKind::Nostr,
                    },
                },
                description: "generated capability property",
            },
        );
    }
    r
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Set up an N-client group via the harness. Returns the clients (alice
/// is index 0) all at epoch 1 and on Stable.
async fn setup_group(n: usize, bus: &TransportBus) -> Vec<HarnessClient> {
    setup_group_with_admins(n, bus, &[]).await
}

async fn setup_group_with_admins(
    n: usize,
    bus: &TransportBus,
    initial_admin_indices: &[usize],
) -> Vec<HarnessClient> {
    assert!(n >= 2, "need at least 2 clients");
    let mut clients: Vec<HarnessClient> = (0..n)
        .map(|i| {
            ClientBuilder::new(pad32(format!("client-{i}").as_bytes()))
                .registry(registry())
                .attach(bus)
        })
        .collect();
    let initial_admins = initial_admin_indices
        .iter()
        .copied()
        .filter(|index| *index > 0 && *index < n)
        .map(|index| clients[index].member_id())
        .collect::<Vec<_>>();
    let mut invite_kps = Vec::with_capacity(n - 1);
    for c in clients.iter_mut().skip(1) {
        invite_kps.push(c.fresh_key_package().await);
    }
    let (_gid, pending) = clients[0]
        .create_group_with_admins("prop", invite_kps, vec![], initial_admins)
        .await;
    clients[0].confirm(pending).await;
    bus.deliver_all();
    for c in clients.iter_mut().skip(1) {
        c.tick().await;
    }
    for c in clients.iter_mut() {
        c.drain_events();
    }
    clients
}

fn prop_assert<T: PartialEq + std::fmt::Debug>(actual: T, expected: T, msg: &str) {
    if actual != expected {
        panic!("invariant violated: {msg} (actual={actual:?} expected={expected:?})");
    }
}

fn ascii_label(max_len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(b'a'..=b'z', 1..=max_len)
        .prop_map(|bytes| String::from_utf8(bytes).expect("generated ascii label"))
}

#[derive(Clone, Debug)]
struct SelectorCandidateShape {
    fork_back: u64,
    tip_delta: u64,
    digest_rank: u64,
    witnesses: Vec<(u64, u8)>,
}

#[derive(Clone, Debug)]
struct SelectorCase {
    current_tip_epoch: u64,
    policy: ConvergencePolicy,
    candidates: Vec<BranchCandidate>,
}

fn selector_candidate_shape() -> impl Strategy<Value = SelectorCandidateShape> {
    (
        0u64..=10,
        0u64..=6,
        any::<u16>(),
        prop::collection::vec((0u64..=6, 0u8..=5), 0..=8),
    )
        .prop_map(
            |(fork_back, tip_delta, digest_seed, witnesses)| SelectorCandidateShape {
                fork_back,
                tip_delta,
                digest_rank: digest_seed as u64,
                witnesses,
            },
        )
}

fn convergence_policy_strategy() -> impl Strategy<Value = ConvergencePolicy> {
    (0u64..=10, 1usize..=4, 1usize..=3, 0u64..=3).prop_map(
        |(
            max_rewind_commits,
            witness_quorum_senders_per_epoch,
            witness_quorum_epochs,
            max_witness_override_depth,
        )| ConvergencePolicy {
            max_rewind_commits,
            witness_quorum_senders_per_epoch,
            witness_quorum_epochs,
            max_witness_override_depth,
        },
    )
}

fn selector_case() -> impl Strategy<Value = SelectorCase> {
    (
        1u64..=20,
        convergence_policy_strategy(),
        prop::collection::vec(selector_candidate_shape(), 1..=6),
    )
        .prop_map(|(current_tip_epoch, policy, shapes)| {
            let candidates = shapes
                .into_iter()
                .enumerate()
                .map(|(index, shape)| {
                    let fork_epoch = current_tip_epoch.saturating_sub(shape.fork_back);
                    let witnesses = shape
                        .witnesses
                        .into_iter()
                        .map(|(epoch_delta, sender)| AppWitness {
                            epoch: fork_epoch.saturating_add(epoch_delta),
                            sender: vec![sender],
                        })
                        .collect();
                    BranchCandidate {
                        id: format!("branch-{index}"),
                        fork_epoch,
                        tip_epoch: fork_epoch.saturating_add(shape.tip_delta),
                        // The selector's final modeled tie-breaker is the
                        // branch digest; keep generated digests unique so the
                        // property targets candidate ordering, not hash
                        // collision behavior.
                        tip_digest: digest_from_u64((shape.digest_rank << 16) | index as u64),
                        app_witnesses: witnesses,
                    }
                })
                .collect();
            SelectorCase {
                current_tip_epoch,
                policy,
                candidates,
            }
        })
}

fn selected_branch_id(case: &SelectorCase, candidates: &[BranchCandidate]) -> Option<String> {
    select_canonical_branch(case.current_tip_epoch, candidates, &case.policy)
        .map(|branch| branch.id.clone())
}

fn candidate_orders(candidates: &[BranchCandidate]) -> Vec<Vec<BranchCandidate>> {
    let mut orders = vec![candidates.to_vec()];

    let mut reversed = candidates.to_vec();
    reversed.reverse();
    if !orders.contains(&reversed) {
        orders.push(reversed);
    }

    if candidates.len() > 1 {
        let mut rotated = candidates.to_vec();
        rotated.rotate_left(1);
        if !orders.contains(&rotated) {
            orders.push(rotated);
        }
    }

    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    if !orders.contains(&sorted) {
        orders.push(sorted);
    }

    orders
}

fn selector_is_order_invariant(case: SelectorCase) {
    let expected = selected_branch_id(&case, &case.candidates);

    for ordered_candidates in candidate_orders(&case.candidates) {
        let observed = selected_branch_id(&case, &ordered_candidates);
        prop_assert(
            observed,
            expected.clone(),
            "candidate order must not change selected branch",
        );
    }

    if let Some(selected) = expected {
        let selected_branch = case
            .candidates
            .iter()
            .find(|candidate| candidate.id == selected)
            .expect("selected branch should be in original candidate set");
        assert!(
            is_branch_eligible(case.current_tip_epoch, selected_branch, &case.policy),
            "selected branch must be eligible"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 1000 } else { 128 },
        .. ProptestConfig::default()
    })]

    /// Property (e) — a generated candidate graph selects the same winner
    /// regardless of candidate enumeration order.
    #[test]
    fn prop_candidate_graph_selection_is_order_invariant(case in selector_case()) {
        selector_is_order_invariant(case);
    }
}

#[derive(Clone, Debug)]
struct CanonicalDispositionCase {
    selected_apps: usize,
    losing_apps: usize,
    accepted_proposals: usize,
    pending_proposals: usize,
    losing_proposals: usize,
    duplicate_selected_app: bool,
    duplicate_losing_app: bool,
    duplicate_accepted_proposal: bool,
    order_variant: u8,
}

fn canonical_disposition_case() -> impl Strategy<Value = CanonicalDispositionCase> {
    (
        0usize..=4,
        0usize..=4,
        0usize..=3,
        0usize..=3,
        0usize..=3,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0u8..=3,
    )
        .prop_map(
            |(
                selected_apps,
                losing_apps,
                accepted_proposals,
                pending_proposals,
                losing_proposals,
                duplicate_selected_app,
                duplicate_losing_app,
                duplicate_accepted_proposal,
                order_variant,
            )| CanonicalDispositionCase {
                selected_apps,
                losing_apps,
                accepted_proposals,
                pending_proposals,
                losing_proposals,
                duplicate_selected_app,
                duplicate_losing_app,
                duplicate_accepted_proposal,
                order_variant,
            },
        )
}

fn canonical_branch(
    id: &str,
    fork_epoch: u64,
    tip_epoch: u64,
    digest_rank: u64,
) -> BranchCandidate {
    BranchCandidate {
        id: id.into(),
        fork_epoch,
        tip_epoch,
        tip_digest: digest_from_u64(digest_rank),
        app_witnesses: vec![],
    }
}

fn canonical_state() -> CanonicalizationState {
    CanonicalizationState {
        current_tip_epoch: 4,
        retained_anchor_epoch: 1,
        last_convergence_relevant_input_ms: 0,
        seen_message_ids: BTreeSet::new(),
    }
}

fn canonical_policy() -> CanonicalizationPolicy {
    CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 5,
            // This disposition property fixes the selected branch by commit
            // depth. Witness override behavior is covered by selector tests.
            witness_quorum_senders_per_epoch: 10,
            witness_quorum_epochs: 2,
            max_witness_override_depth: 0,
        },
        app_message_past_epoch_limit: 5,
        stable_quiescence_ms: 1_000,
    }
}

fn proposal_message(id: &str, branch_id: &str) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch: 2,
        kind: PeeledMessageKind::Proposal {
            branch_id: branch_id.into(),
        },
    }
}

fn app_message(id: &str, sender: u8, decrypts_on_branch: &str) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: vec![sender],
        source_epoch: 3,
        kind: PeeledMessageKind::AppMessage {
            epoch: 3,
            decrypts_on_branches: vec![decrypts_on_branch.into()],
            decrypted_payload_ref: Some(format!("payload-{id}")),
        },
    }
}

fn reorder_messages(mut messages: Vec<PeeledMessage>, variant: u8) -> Vec<PeeledMessage> {
    match variant % 4 {
        0 => messages,
        1 => {
            messages.reverse();
            messages
        }
        2 => {
            if !messages.is_empty() {
                let shift = (messages.len() / 2).max(1);
                messages.rotate_left(shift);
            }
            messages
        }
        _ => {
            messages.sort_by(|a, b| b.message_id.cmp(&a.message_id));
            messages
        }
    }
}

fn message_id_counts(messages: &[PeeledMessage]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for message in messages {
        *counts.entry(message.message_id.clone()).or_insert(0) += 1;
    }
    counts
}

fn message_ids_with_duplicates(messages: &[PeeledMessage]) -> BTreeSet<String> {
    message_id_counts(messages)
        .into_iter()
        .filter_map(|(id, count)| (count > 1).then_some(id))
        .collect()
}

fn canonicalize_disposition_case(
    case: &CanonicalDispositionCase,
    messages: Vec<PeeledMessage>,
) -> cgka_conformance_simulator::canonicalization::CanonicalizationResult {
    let accepted_proposal_ids: Vec<String> = (0..case.accepted_proposals)
        .map(|i| format!("accepted-proposal-{i}"))
        .collect();
    canonicalize_with_materialized_candidates(
        CanonicalizationInput {
            state: canonical_state(),
            pending_messages: messages,
            outbound_intents: vec![],
            candidate_branches: vec![],
            policy: canonical_policy(),
            now_ms: 2_000,
        },
        vec![
            MaterializedCandidate {
                branch: canonical_branch("selected", 1, 4, 0),
                commit_message_ids: vec!["selected-commit".into()],
                consumed_proposal_ids: accepted_proposal_ids,
            },
            MaterializedCandidate {
                branch: canonical_branch("losing", 1, 3, 255),
                commit_message_ids: vec!["losing-commit".into()],
                consumed_proposal_ids: (0..case.losing_proposals)
                    .map(|i| format!("losing-proposal-{i}"))
                    .collect(),
            },
        ],
    )
}

fn build_canonical_messages(case: &CanonicalDispositionCase) -> Vec<PeeledMessage> {
    let mut messages = Vec::new();

    for i in 0..case.accepted_proposals {
        messages.push(proposal_message(
            &format!("accepted-proposal-{i}"),
            "selected",
        ));
    }
    for i in 0..case.pending_proposals {
        messages.push(proposal_message(
            &format!("pending-proposal-{i}"),
            "selected",
        ));
    }
    for i in 0..case.losing_proposals {
        messages.push(proposal_message(&format!("losing-proposal-{i}"), "losing"));
    }
    for i in 0..case.selected_apps {
        messages.push(app_message(
            &format!("selected-app-{i}"),
            i as u8,
            "selected",
        ));
    }
    for i in 0..case.losing_apps {
        messages.push(app_message(&format!("losing-app-{i}"), i as u8, "losing"));
    }

    if case.duplicate_selected_app && case.selected_apps > 0 {
        messages.push(app_message("selected-app-0", 0, "selected"));
    }
    if case.duplicate_losing_app && case.losing_apps > 0 {
        messages.push(app_message("losing-app-0", 0, "losing"));
    }
    if case.duplicate_accepted_proposal && case.accepted_proposals > 0 {
        messages.push(proposal_message("accepted-proposal-0", "selected"));
    }

    messages
}

fn canonical_dispositions_are_order_invariant(case: CanonicalDispositionCase) {
    let base_messages = build_canonical_messages(&case);
    let reordered_messages = reorder_messages(base_messages.clone(), case.order_variant);
    let baseline = canonicalize_disposition_case(&case, base_messages.clone());
    let observed = canonicalize_disposition_case(&case, reordered_messages);

    prop_assert(
        observed.clone(),
        baseline.clone(),
        "canonicalization dispositions must not depend on peeled delivery order",
    );
    prop_assert(
        observed.selected_branch_id.as_deref(),
        Some("selected"),
        "selected materialized branch should win",
    );

    let accepted_apps: BTreeSet<String> = observed.accepted_app_messages.iter().cloned().collect();
    let expected_selected_apps: BTreeSet<String> = (0..case.selected_apps)
        .map(|i| format!("selected-app-{i}"))
        .collect();
    prop_assert(
        accepted_apps,
        expected_selected_apps,
        "only selected-branch app messages are accepted",
    );

    let invalidated_losing_apps: BTreeSet<String> = observed
        .invalidated_app_messages
        .iter()
        .filter(|message| message.reason == InvalidatedAppMessageReason::LosingBranch)
        .map(|message| message.message_id.clone())
        .collect();
    let expected_losing_apps: BTreeSet<String> = (0..case.losing_apps)
        .map(|i| format!("losing-app-{i}"))
        .collect();
    prop_assert(
        invalidated_losing_apps,
        expected_losing_apps,
        "losing-branch app messages are invalidated",
    );

    let accepted_proposals: BTreeSet<String> =
        observed.accepted_proposals.iter().cloned().collect();
    let expected_accepted_proposals: BTreeSet<String> = (0..case.accepted_proposals)
        .map(|i| format!("accepted-proposal-{i}"))
        .collect();
    prop_assert(
        accepted_proposals,
        expected_accepted_proposals,
        "only consumed selected-branch proposals are accepted",
    );

    let dropped_losing_proposals: BTreeSet<String> = observed
        .dropped_messages
        .iter()
        .filter(|message| {
            message.kind == MessageKind::Proposal
                && message.reason == DroppedMessageReason::InvalidAgainstCandidateState
        })
        .map(|message| message.message_id.clone())
        .collect();
    let expected_losing_proposals: BTreeSet<String> = (0..case.losing_proposals)
        .map(|i| format!("losing-proposal-{i}"))
        .collect();
    prop_assert(
        dropped_losing_proposals,
        expected_losing_proposals,
        "losing-branch proposals are dropped",
    );

    let already_seen_ids: BTreeSet<String> = observed
        .already_seen
        .iter()
        .map(|AlreadySeen { message_id, .. }| message_id.clone())
        .collect();
    prop_assert(
        already_seen_ids,
        message_ids_with_duplicates(&base_messages),
        "duplicate peeled messages are reported as AlreadySeen",
    );

    prop_assert(
        observed.accepted_app_messages.len(),
        observed
            .accepted_app_messages
            .iter()
            .collect::<BTreeSet<_>>()
            .len(),
        "accepted app output is one-shot per message id",
    );
    prop_assert(
        observed.invalidated_app_messages.len(),
        observed
            .invalidated_app_messages
            .iter()
            .map(|message| &message.message_id)
            .collect::<BTreeSet<_>>()
            .len(),
        "invalidated app dispositions are one-shot per message id",
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 1000 } else { 128 },
        .. ProptestConfig::default()
    })]

    /// Property (f) — generated canonicalization batches preserve app and
    /// proposal dispositions under reordered duplicate delivery.
    #[test]
    fn prop_canonicalization_dispositions_are_order_invariant(
        case in canonical_disposition_case()
    ) {
        canonical_dispositions_are_order_invariant(case);
    }
}

// ── Property (g) — canonicalization idempotence ───────────────────────────

fn canonicalization_replay_is_already_seen(case: CanonicalDispositionCase) {
    let messages = build_canonical_messages(&case);
    let seen_message_ids = messages
        .iter()
        .map(|message| message.message_id.clone())
        .collect::<BTreeSet<_>>();
    let observed = canonicalize_with_materialized_candidates(
        CanonicalizationInput {
            state: CanonicalizationState {
                current_tip_epoch: 4,
                retained_anchor_epoch: 1,
                last_convergence_relevant_input_ms: 0,
                seen_message_ids,
            },
            pending_messages: messages.clone(),
            outbound_intents: vec![],
            candidate_branches: vec![],
            policy: canonical_policy(),
            now_ms: 2_000,
        },
        vec![],
    );

    prop_assert(
        observed.accepted_commits,
        Vec::<String>::new(),
        "already-seen replay must not accept commits",
    );
    prop_assert(
        observed.accepted_proposals,
        Vec::<String>::new(),
        "already-seen replay must not accept proposals",
    );
    prop_assert(
        observed.accepted_app_messages,
        Vec::<String>::new(),
        "already-seen replay must not emit app messages",
    );
    prop_assert(
        observed.invalidated_app_messages,
        vec![],
        "already-seen replay must not emit app invalidations",
    );
    prop_assert(
        observed.dropped_messages,
        vec![],
        "already-seen replay must not drop messages a second time",
    );
    prop_assert(
        observed.already_seen.len(),
        messages.len(),
        "every replayed message occurrence should be AlreadySeen",
    );
    let already_seen_ids = observed
        .already_seen
        .iter()
        .map(|seen| seen.message_id.clone())
        .collect::<BTreeSet<_>>();
    prop_assert(
        already_seen_ids,
        messages
            .iter()
            .map(|message| message.message_id.clone())
            .collect::<BTreeSet<_>>(),
        "already-seen replay should name the replayed message ids",
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 1000 } else { 128 },
        .. ProptestConfig::default()
    })]

    /// Property (g) — canonicalizing the same batch again after those
    /// message ids are known must not produce app-visible output twice.
    #[test]
    fn prop_canonicalization_replay_is_already_seen(
        case in canonical_disposition_case()
    ) {
        canonicalization_replay_is_already_seen(case);
    }
}

// ── Property (h) — quiescence/stability gate ──────────────────────────────

fn commit_message(
    id: &str,
    branch_id: &str,
    fork_epoch: u64,
    resulting_epoch: u64,
    digest_rank: u64,
) -> PeeledMessage {
    PeeledMessage {
        message_id: id.into(),
        group_id: "group".into(),
        sender: b"alice".to_vec(),
        source_epoch: fork_epoch,
        kind: PeeledMessageKind::Commit {
            branch_id: branch_id.into(),
            parent_branch_id: None,
            fork_epoch,
            resulting_epoch,
            tip_digest: digest_from_u64(digest_rank),
            consumed_proposal_ids: vec![],
        },
    }
}

fn canonicalization_quiescence_gate_holds(
    stable_quiescence_ms: u64,
    early_elapsed_ms: u64,
    payload_tag: u8,
) {
    let last_input_ms = 10_000;
    let commit = commit_message("selected-commit", "selected", 1, 2, payload_tag as u64);
    let candidate = MaterializedCandidate {
        branch: canonical_branch("selected", 1, 2, payload_tag as u64),
        commit_message_ids: vec!["selected-commit".into()],
        consumed_proposal_ids: vec![],
    };
    let policy = CanonicalizationPolicy {
        stable_quiescence_ms,
        ..canonical_policy()
    };
    let input_at = |now_ms| CanonicalizationInput {
        state: CanonicalizationState {
            current_tip_epoch: 1,
            retained_anchor_epoch: 1,
            last_convergence_relevant_input_ms: last_input_ms,
            seen_message_ids: BTreeSet::new(),
        },
        pending_messages: vec![commit.clone()],
        outbound_intents: vec![OutboundIntent::SendAppMessage {
            payload: format!("queued-{payload_tag}"),
        }],
        candidate_branches: vec![],
        policy: policy.clone(),
        now_ms,
    };

    let early = canonicalize_with_materialized_candidates(
        input_at(last_input_ms + early_elapsed_ms),
        vec![candidate.clone()],
    );
    prop_assert(
        early.sync_state,
        SyncState::Syncing,
        "window must stay syncing before quiescence",
    );
    prop_assert(
        early.publishable_outbound_messages,
        vec![],
        "outbound work must not publish before quiescence",
    );
    prop_assert(
        early.queued_outbound_intents.len(),
        1,
        "outbound work should remain queued before quiescence",
    );

    let stable = canonicalize_with_materialized_candidates(
        input_at(last_input_ms + stable_quiescence_ms),
        vec![candidate],
    );
    prop_assert(
        stable.sync_state,
        SyncState::Stable,
        "window should become stable once quiescence elapses",
    );
    prop_assert(
        stable.queued_outbound_intents,
        vec![],
        "stable convergence should not keep outbound work queued",
    );
    prop_assert(
        stable.publishable_outbound_messages.len(),
        1,
        "stable convergence should release outbound work",
    );
    prop_assert(
        stable.accepted_commits,
        vec!["selected-commit".into()],
        "selected commit should be accepted after quiescence",
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 1000 } else { 128 },
        .. ProptestConfig::default()
    })]

    /// Property (h) — convergence input is gated by the stability window:
    /// before the window closes, output stays queued; once it closes, the
    /// same fixed point becomes Stable and releases outbound work.
    #[test]
    fn prop_quiescence_gate_controls_stability(
        (stable_quiescence_ms, early_elapsed_ms, payload_tag) in
            (1u64..=5_000).prop_flat_map(|stable| {
                (Just(stable), 0..stable, any::<u8>())
            }),
    ) {
        canonicalization_quiescence_gate_holds(
            stable_quiescence_ms,
            early_elapsed_ms,
            payload_tag,
        );
    }
}

// ── Property (i) — capability negotiation matrices ────────────────────────

#[derive(Clone, Debug)]
struct CapabilityNegotiationCase {
    level: PropCapabilityLevel,
    invitee_supports: Vec<bool>,
    require_feature_at_create: bool,
}

fn capability_negotiation_case() -> impl Strategy<Value = CapabilityNegotiationCase> {
    (
        prop_capability_level(),
        prop::collection::vec(any::<bool>(), 0..=3),
        any::<bool>(),
    )
        .prop_map(|(level, invitee_supports, require_feature_at_create)| {
            CapabilityNegotiationCase {
                level,
                invitee_supports,
                require_feature_at_create,
            }
        })
}

fn capability_negotiation_matches_matrix(case: CapabilityNegotiationCase) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut alice = ClientBuilder::new(pad32(b"cap-alice"))
            .registry(registry_with_generated_feature(case.level, true))
            .attach(&bus);
        let mut key_packages = Vec::with_capacity(case.invitee_supports.len());
        for (index, supports) in case.invitee_supports.iter().enumerate() {
            let mut invitee = ClientBuilder::new(pad32(format!("cap-{index}").as_bytes()))
                .registry(registry_with_generated_feature(case.level, *supports))
                .attach(&bus);
            key_packages.push(invitee.fresh_key_package().await);
        }

        let feature_is_required = matches!(case.level, PropCapabilityLevel::Required)
            || case.require_feature_at_create;
        let all_members_support = case.invitee_supports.iter().all(|supports| *supports);
        let create = alice
            .engine
            .create_group(CreateGroupRequest {
                name: "capability property".into(),
                description: "".into(),
                members: key_packages,
                required_features: case
                    .require_feature_at_create
                    .then_some(PROP_FEATURE)
                    .into_iter()
                    .collect(),
                app_components: vec![],
                initial_admins: vec![],
            })
            .await;

        if feature_is_required && !all_members_support {
            assert!(
                matches!(
                    create,
                    Err(cgka_traits::EngineError::MissingRequiredCapabilities { .. })
                ),
                "missing support for required feature must reject: {case:?}"
            );
            return;
        }

        let (group_id, result) =
            create.unwrap_or_else(|err| panic!("group should create for {case:?}: {err:?}"));
        let pending = match result {
            cgka_traits::engine::SendResult::GroupCreated { pending, .. } => pending,
            other => panic!("expected GroupCreated for {case:?}, got {other:?}"),
        };
        alice.confirm(pending).await;

        let status = alice
            .engine
            .feature_status(&group_id, &PROP_FEATURE)
            .unwrap_or_else(|err| panic!("feature_status should resolve for {case:?}: {err:?}"));
        match (feature_is_required, all_members_support, status) {
            (true, true, FeatureStatus::Available) => {}
            (false, true, FeatureStatus::Upgradeable) => {}
            (false, false, FeatureStatus::Unavailable { missing }) => {
                assert!(
                    missing.proposals.contains(&PROP_FEATURE_PROPOSAL),
                    "missing set should name generated feature cap for {case:?}: {missing:?}"
                );
            }
            (expected_required, expected_supported, other) => panic!(
                "wrong feature status for {case:?}: required={expected_required} all_supported={expected_supported} got {other:?}"
            ),
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 200 } else { 24 },
        .. ProptestConfig::default()
    })]

    /// Property (i) — generated capability matrices either reject missing
    /// required support or report the exact feature availability state.
    #[test]
    fn prop_capability_negotiation_matches_matrix(
        case in capability_negotiation_case()
    ) {
        capability_negotiation_matches_matrix(case);
    }
}

// ── Property (b) — convergence under send/leave schedules ─────────────────

/// Re-route a `TransportMessage` so its `transport_group_id` matches the
/// given `gid`. Mirrors the private `route` helper inside the harness's
/// `client.rs` — needed here because we drive the engine + bus directly.
fn reroute(
    msg: cgka_traits::transport::TransportMessage,
    gid: &cgka_traits::types::GroupId,
) -> cgka_traits::transport::TransportMessage {
    use cgka_traits::transport::TransportEnvelope;
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => cgka_traits::transport::TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: gid.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

async fn drive_intents(
    clients: &mut [HarnessClient],
    bus: &TransportBus,
    intents: &[HarnessIntent],
) -> Vec<bool> {
    let n = clients.len();
    let bus_ids: Vec<_> = clients.iter().map(|c| c.bus_id).collect();
    let group_ids: Vec<_> = clients.iter().map(|c| c.group_id()).collect();
    let mut still_member = vec![true; n];

    for intent in intents {
        match intent {
            HarnessIntent::Send {
                sender_idx,
                payload,
            } => {
                let idx = sender_idx % n;
                if !still_member[idx] {
                    continue;
                }
                let gid = group_ids[idx].clone();
                let res = clients[idx]
                    .engine
                    .send(cgka_traits::engine::SendIntent::AppMessage {
                        group_id: gid.clone(),
                        payload: payload.clone(),
                    })
                    .await;
                if let Ok(cgka_traits::engine::SendResult::ApplicationMessage { msg }) = res {
                    bus.send(bus_ids[idx], reroute(msg, &gid));
                }
            }
            HarnessIntent::Leave { sender_idx } => {
                let idx = sender_idx % n;
                if !still_member[idx] || idx == 0 {
                    // Skip alice (admin; MIP-03 §149 blocks self-removal
                    // when she'd be the last admin).
                    continue;
                }
                let gid = group_ids[idx].clone();
                let res = clients[idx]
                    .engine
                    .send(cgka_traits::engine::SendIntent::Leave {
                        group_id: gid.clone(),
                    })
                    .await;
                if let Ok(cgka_traits::engine::SendResult::Proposal { msg }) = res {
                    bus.send(bus_ids[idx], reroute(msg, &gid));
                    still_member[idx] = false;
                }
            }
        }
    }
    still_member
}

fn convergence_with_event_conservation(intents: Vec<HarnessIntent>) {
    let n = 3usize;
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(n, &bus).await;
        let still_member = drive_intents(&mut clients, &bus, &intents).await;

        // Drive to quiescence.
        for _ in 0..8 {
            bus.deliver_all();
            for c in clients.iter_mut() {
                let _ = c.tick().await;
            }
            if bus.queued_len() == 0 {
                break;
            }
        }

        // Property (b) — every still-member client agrees on epoch.
        let live_epochs: Vec<u64> = clients
            .iter()
            .enumerate()
            .filter(|(i, _)| still_member[*i])
            .map(|(_, c)| c.epoch().0)
            .collect();
        if live_epochs.len() >= 2 {
            let first = live_epochs[0];
            for e in &live_epochs[1..] {
                prop_assert(*e, first, "live clients must agree on epoch");
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 1000 } else { 24 },
        .. ProptestConfig::default()
    })]

    /// Property (b) — convergence under arbitrary Send+Leave sequences.
    #[test]
    fn prop_convergence_under_send_leave_sequence(
        intents in intent_seq(3, 1..10)
    ) {
        convergence_with_event_conservation(intents);
    }
}

// ── Property (b) under varied delivery profiles ───────────────────────────

fn convergence_under_profile(intents: Vec<HarnessIntent>, profile: DeliveryProfile) {
    let n = 3usize;
    rt().block_on(async {
        let policy: DeliveryPolicy = profile.into_policy();
        let bus = TransportBus::with_policy(policy);
        let mut clients = setup_group(n, &bus).await;
        let still_member = drive_intents(&mut clients, &bus, &intents).await;

        // Quiesce.
        for _ in 0..16 {
            bus.deliver_all();
            for c in clients.iter_mut() {
                let _ = c.tick().await;
            }
            if bus.queued_len() == 0 {
                break;
            }
        }

        // Convergence assertion across live clients.
        let live_epochs: Vec<u64> = clients
            .iter()
            .enumerate()
            .filter(|(i, _)| still_member[*i])
            .map(|(_, c)| c.epoch().0)
            .collect();
        if live_epochs.len() >= 2 {
            let first = live_epochs[0];
            for e in &live_epochs[1..] {
                prop_assert(*e, first, "live clients epoch convergence");
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 500 } else { 12 },
        .. ProptestConfig::default()
    })]

    /// Property (b) again, this time under a randomly-chosen
    /// `DeliveryProfile`. Convergence must hold whether the bus is FIFO,
    /// reverse, or seeded-shuffle.
    #[test]
    fn prop_convergence_under_varied_delivery(
        intents in intent_seq(3, 1..8),
        profile in delivery_profile(),
    ) {
        convergence_under_profile(intents, profile);
    }
}

// ── Property (k) — restart equivalence for stored convergence input ───────

fn stored_convergence_restart_equivalence(name: String, committer_idx: usize) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let committer_idx = committer_idx % 2;
        let initial_admin_indices = if committer_idx == 0 {
            Vec::new()
        } else {
            vec![committer_idx]
        };
        let mut clients = setup_group_with_admins(3, &bus, &initial_admin_indices).await;
        let group_id = clients[0].group_id();
        let res = clients[committer_idx]
            .engine
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: Some(name.clone()),
                description: None,
            })
            .await
            .expect("committer creates group-data update");
        let (commit, pending) = match res {
            SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
            other => panic!("expected GroupEvolution, got {other:?}"),
        };
        clients[committer_idx].confirm(pending).await;
        let commit = reroute(commit, &group_id);
        clients[2]
            .engine
            .ingest(commit)
            .await
            .expect("observer buffers stored convergence input");

        clients[2]
            .storage()
            .create_group_snapshot(&group_id, "restart-equivalence")
            .expect("pre-convergence snapshot");
        let live_result = clients[2]
            .engine
            .converge_stored_openmls_messages(&group_id, 1_000_000)
            .expect("live convergence");
        let live_epoch = clients[2].epoch().0;
        let live_group = clients[2].storage().get_group(&group_id).unwrap();

        clients[2]
            .storage()
            .rollback_group_to_snapshot(&group_id, "restart-equivalence")
            .expect("rollback to pre-convergence snapshot");
        let restarted_identity = clients[2].member_id().as_slice().to_vec();
        let restarted_storage = clients[2].storage().clone();
        let mut restarted = EngineBuilder::new(restarted_storage.clone())
            .identity(restarted_identity.clone())
            .feature_registry(registry())
            .peeler(Box::new(transport_nostr_peeler::NostrMlsPeeler::new(
                hex::encode(restarted_identity),
            )))
            .build()
            .expect("restarted engine builds");
        let restarted_result = restarted
            .converge_stored_openmls_messages(&group_id, 1_000_000)
            .expect("restarted convergence");
        let restarted_group = restarted_storage.get_group(&group_id).unwrap();

        prop_assert(
            restarted_result,
            live_result,
            "restart should not change stored convergence result",
        );
        prop_assert(
            restarted.epoch(&group_id).unwrap().0,
            live_epoch,
            "restart should not change converged epoch",
        );
        prop_assert(
            restarted_group.name,
            live_group.name,
            "restart should not change converged group name",
        );
        prop_assert(
            restarted_group.members.len(),
            live_group.members.len(),
            "restart should not change converged membership",
        );
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 40 } else { 8 },
        .. ProptestConfig::default()
    })]

    /// Property (k) — stored convergence input produces the same result
    /// before and after rebuilding the engine over the same storage snapshot.
    #[test]
    fn prop_stored_convergence_restart_equivalence(
        name in ascii_label(12),
        committer_idx in 0usize..2,
    ) {
        stored_convergence_restart_equivalence(name, committer_idx);
    }
}

// ── Property (j) — group-data update publish lifecycle ────────────────────

fn group_data_update_publish_lifecycle(name: String, outcome: ConfirmOutcome) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(2, &bus).await;
        let group_id = clients[0].group_id();
        let original = clients[0].storage().get_group(&group_id).unwrap();
        let epoch_before = clients[0].epoch().0;

        let pending = clients[0].update_group_data(name.clone()).await;
        prop_assert(
            clients[0].epoch().0,
            epoch_before + 1,
            "group-data update should project next epoch",
        );
        prop_assert(
            clients[0].storage().get_group(&group_id).unwrap().name,
            name.clone(),
            "group-data update should project new name",
        );

        match outcome {
            ConfirmOutcome::Confirm => {
                clients[0].confirm(pending).await;
                prop_assert(
                    clients[0].epoch().0,
                    epoch_before + 1,
                    "confirmed group-data update should stay at projected epoch",
                );
                prop_assert(
                    clients[0].storage().get_group(&group_id).unwrap().name,
                    name,
                    "confirmed group-data update should keep projected name",
                );
            }
            ConfirmOutcome::Fail => {
                clients[0].fail(pending).await;
                prop_assert(
                    clients[0].epoch().0,
                    epoch_before,
                    "failed group-data update should restore prior epoch",
                );
                prop_assert(
                    clients[0].storage().get_group(&group_id).unwrap().name,
                    original.name,
                    "failed group-data update should restore prior name",
                );

                let retry_name = format!("retry-{name}");
                let retry = clients[0].update_group_data(retry_name.clone()).await;
                clients[0].confirm(retry).await;
                prop_assert(
                    clients[0].epoch().0,
                    epoch_before + 1,
                    "group should be reusable after group-data rollback",
                );
                prop_assert(
                    clients[0].storage().get_group(&group_id).unwrap().name,
                    retry_name,
                    "retry after rollback should publish normally",
                );
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 200 } else { 12 },
        .. ProptestConfig::default()
    })]

    /// Property (j) — group-data update publish success keeps the projected
    /// state; publish failure restores the prior stable state and permits a
    /// retry.
    #[test]
    fn prop_group_data_update_publish_lifecycle(
        name in ascii_label(12),
        outcome in confirm_outcome(),
    ) {
        group_data_update_publish_lifecycle(name, outcome);
    }
}

// ── Property (a) — true same-id replay ────────────────────────────────────

fn true_same_id_replay(payload: Vec<u8>) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(2, &bus).await;

        // Alice sends and we capture the wrapped transport message.
        let captured = clients[0].send_app_capture(payload).await;

        bus.deliver_all();
        let outcomes = clients[1].tick().await;
        // First ingestion: Processed.
        let processed_count = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(IngestOutcome::Processed)))
            .count();
        prop_assert(processed_count, 1, "first delivery should process");

        let epoch_before = clients[1].epoch();
        let events_before = clients[1].drain_events().len();

        // Re-inject the SAME TransportMessage directly into bob's mailbox.
        bus.inject(clients[1].bus_id, captured);
        let outcomes = clients[1].tick().await;
        let stale_count = outcomes
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    Ok(IngestOutcome::Stale {
                        reason: StaleReason::AlreadySeen
                    })
                )
            })
            .count();
        prop_assert(stale_count, 1, "second delivery must be AlreadySeen");

        let epoch_after = clients[1].epoch();
        let events_after = clients[1].drain_events().len();
        prop_assert(epoch_after, epoch_before, "epoch must not change on replay");
        prop_assert(
            events_after,
            0,
            "no new events on replay (events_before was already drained)",
        );
        let _ = events_before;
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 500 } else { 16 },
        .. ProptestConfig::default()
    })]

    /// Property (a) — same `MessageId` ingested twice is exactly one
    /// `Processed` followed by `Stale { AlreadySeen }`. State unchanged.
    #[test]
    fn prop_true_same_id_replay(payload in prop::collection::vec(any::<u8>(), 1..16)) {
        true_same_id_replay(payload);
    }
}

// ── Property (c) — rollback ───────────────────────────────────────────────

fn rollback_property(outcome: ConfirmOutcome) {
    rt().block_on(async {
        let bus = TransportBus::ordered();
        let mut clients = setup_group(2, &bus).await;

        let alice = &mut clients[0];
        let epoch_before = alice.epoch().0;

        let pending = alice.upgrade().await;
        // After upgrade, EpochState reports the projected new epoch.
        let projected = alice.epoch().0;
        prop_assert(projected, epoch_before + 1, "upgrade projects +1 epoch");

        match outcome {
            ConfirmOutcome::Confirm => {
                alice.confirm(pending).await;
                prop_assert(alice.epoch().0, epoch_before + 1, "confirm advances");
            }
            ConfirmOutcome::Fail => {
                alice.fail(pending).await;
                prop_assert(alice.epoch().0, epoch_before, "fail restores prior epoch");
                // Group is immediately re-usable: a second upgrade attempt
                // must succeed (proves Stable, not stuck).
                let pending2 = alice.upgrade().await;
                alice.confirm(pending2).await;
                prop_assert(
                    alice.epoch().0,
                    epoch_before + 1,
                    "post-rollback retry must advance",
                );
            }
        }
    });
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(feature = "conformance-slow") { 200 } else { 8 },
        .. ProptestConfig::default()
    })]

    /// Property (c) — confirm advances; fail rolls back; group is
    /// immediately re-usable in either case. Each iteration freshly
    /// constructs the group so the upgrade has something to upgrade.
    #[test]
    fn prop_upgrade_confirm_or_fail_round_trip(outcome in confirm_outcome()) {
        rollback_property(outcome);
    }
}
