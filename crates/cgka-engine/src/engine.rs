//! [`Engine<S>`] is the OpenMLS-backed [`CgkaEngine`] implementation.
//!
//! Generic over `S: cgka_traits::StorageProvider`. Holds OpenMLS RustCrypto
//! for the crypto + rand half of OpenMLS's provider surface, materializing an
//! `EngineOpenMlsProvider` on demand per MLS call.
//!
//! This file owns construction, trait dispatch, event drains, and small
//! read-only helpers. Group creation, ingest/send, publish lifecycle,
//! convergence, and capability logic live in focused sibling modules.

use crate::bounded_id_set::{BoundedIdSet, DEDUP_CACHE_CAPACITY};
use crate::feature_registry::FeatureRegistry;
use crate::identity::Identity;
use async_trait::async_trait;
use cgka_traits::app_components::{AppComponentId, AppComponentSet, default_group_components};
use cgka_traits::capabilities::{Feature, FeatureStatus, GroupCapabilities};
use cgka_traits::engine::{
    AutoPublish, CgkaEngine, CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason,
    GroupStateChange, KeyPackage, SendIntent, SendResult,
};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContext;
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{LeaveRequest, StorageError, StorageProvider};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::MessageId;
use cgka_traits::types::{EpochId, GroupId, MemberId};
use marmot_forensics::{
    AuditEngineContext, AuditEventContext, AuditEventKind, AuditGroupContext, AuditRecord,
    ForensicRecorder, NoopRecorder,
};
use openmls::prelude::{
    MlsMessageBodyIn, MlsMessageIn, ProcessedMessageContent, Proposal, ProtocolMessage,
};
use openmls_rust_crypto::RustCrypto;
pub use openmls_traits::types::Ciphersuite;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tls_codec::Deserialize as _;

/// Default ciphersuite. MLS-1.0 mandatory-to-implement; TLS-ish naming.
pub const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn hydration_quarantine_reason_tag(reason: GroupHydrationQuarantineReason) -> &'static str {
    match reason {
        GroupHydrationQuarantineReason::OpenMlsLoadFailed => "openmls_load_failed",
        GroupHydrationQuarantineReason::OpenMlsGroupMissing => "openmls_group_missing",
        GroupHydrationQuarantineReason::MemberValidationFailed => "member_validation_failed",
        GroupHydrationQuarantineReason::GroupRecordLoadFailed => "group_record_load_failed",
        GroupHydrationQuarantineReason::PendingCommitRecoveryFailed => {
            "pending_commit_recovery_failed"
        }
    }
}

fn hydration_quarantine_group_digest(group_id: &GroupId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot-hydration-quarantine-group/v1");
    hasher.update(group_id.as_slice());
    hex::encode(hasher.finalize())
}

/// OpenMLS-backed CGKA engine. Construct via [`EngineBuilder`].
/// A group-state change effected by a locally staged commit, buffered until
/// publish confirmation merges that commit. `actor` attributes the change: for
/// our own invite/remove/profile commits it is the local member; for an
/// auto-committed peer SelfRemove it is the leaving member, not us.
#[derive(Clone)]
pub(crate) struct PendingGroupStateChange {
    pub(crate) actor: Option<MemberId>,
    pub(crate) change: GroupStateChange,
}

#[derive(Clone, Debug)]
pub(crate) struct ScheduledSelfRemoveAutoCommit {
    pub(crate) group_id: GroupId,
    pub(crate) proposal_id: MessageId,
    pub(crate) source_epoch: EpochId,
    pub(crate) due_at_ms: u64,
}

pub struct Engine<S: StorageProvider> {
    pub(crate) storage: S,
    pub(crate) crypto: RustCrypto,
    pub(crate) identity: Identity,
    pub(crate) registry: FeatureRegistry,
    pub(crate) supported_app_components: AppComponentSet,
    pub(crate) peeler: Box<dyn TransportPeeler>,
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) max_past_epochs: usize,

    /// Per-group state-machine owner. Every transition, pending-ref
    /// allocation, and fork-detection marker flows through this struct.
    pub(crate) epoch_manager: crate::epoch_manager::EpochManager,

    /// Snapshot + ordering metadata for same-epoch competing commits.
    pub(crate) fork_recovery: crate::fork_recovery::ForkRecoveryManager,

    pub(crate) events_buf: VecDeque<GroupEvent>,
    pub(crate) auto_publish_buf: VecDeque<AutoPublish>,
    /// Standalone proposal messages produced by engine-maintained lifecycle
    /// work. Unlike `auto_publish_buf`, these do not have a pending commit ref.
    pub(crate) auto_proposal_buf: VecDeque<TransportMessage>,
    /// Group-state changes effected by a locally staged commit, with the actor
    /// to attribute each to. Buffered here because publish-before-apply defers
    /// the OpenMLS merge: the `GroupEvent::GroupStateChanged` events are emitted
    /// in `do_confirm_published`, once the pending commit is actually merged,
    /// and dropped in `do_publish_failed`.
    pub(crate) pending_state_changes: HashMap<PendingStateRef, Vec<PendingGroupStateChange>>,

    /// MessageIds the engine has ingested. Backs `StaleReason::AlreadySeen`.
    ///
    /// Bounded hot-process cache in front of the authoritative durable
    /// `MessageRecord` store (checked first in `do_ingest`), so an id that ages
    /// out of the cap is still classified by storage.
    pub(crate) seen_message_ids: BoundedIdSet<MessageId>,

    /// MessageIds this engine has produced via `send` or `create_group` /
    /// `invite`. Backs `StaleReason::OwnEcho` when a message we produced
    /// bounces back via ingest before we filter it client-side.
    ///
    /// Bounded hot-process cache; see `seen_message_ids` above.
    pub(crate) sent_message_ids: BoundedIdSet<MessageId>,

    /// Durable leave requests keyed by group. This is the source of truth for
    /// a user's request to leave across epoch changes and restarts.
    pub(crate) leave_requests: HashMap<GroupId, LeaveRequest>,

    /// Fast runtime gate for groups where the local member must not produce
    /// further outbound group traffic while a leave request is outstanding.
    pub(crate) leaving_groups: HashSet<GroupId>,

    /// Delayed SelfRemove auto-commit attempts keyed by the standalone
    /// proposal's content-derived message id. These are re-checked against live
    /// storage before staging so unrelated commits can invalidate them without
    /// producing a commit storm.
    pub(crate) scheduled_self_remove_auto_commits:
        HashMap<MessageId, ScheduledSelfRemoveAutoCommit>,

    /// Groups the application should feed through its convergence timer even
    /// when the triggering input was processed (for example, a delayed
    /// SelfRemove auto-commit schedule) rather than returned as
    /// `IngestOutcome::Buffered`.
    pub(crate) pending_convergence_groups: HashSet<GroupId>,

    pub(crate) convergence_policy: crate::canonicalization::CanonicalizationPolicy,
    pub(crate) last_convergence_relevant_input_ms: HashMap<GroupId, u64>,
    pub(crate) convergence_clock_started_at: Instant,

    /// Diagnostic post-settle reorg telemetry. Recorded at the convergence
    /// apply site and exposed via [`Engine::engine_metrics`]. Never an input to
    /// convergence or branch selection.
    pub(crate) engine_metrics: crate::engine_metrics::EngineMetrics,

    /// Forensic audit-log recorder. Defaults to [`NoopRecorder`] when the
    /// session is built without one. Engine call sites emit typed events
    /// at every state-relevant decision point so a later analyzer can
    /// reconstruct what each device saw and decided.
    pub(crate) recorder: Box<dyn ForensicRecorder>,
    pub(crate) audit_operation_counter: u64,
    /// Audit context for the in-flight local operation. The
    /// `*_with_audit_context` entry points set this around their `do_*` call so
    /// the secondary rows those emit (e.g. `message_state_changed`,
    /// `group_context`) inherit the operation's `human_action` instead of
    /// landing context-free. `None` outside a human-initiated operation.
    pub(crate) current_audit_context: Option<AuditEventContext>,

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (darkmatter#151 / #417). Keyed by group
    /// id with the coarse recovery reason, this is the engine-side source of
    /// truth the application reads to surface a per-group recovery flow
    /// (darkmatter#426) distinct from healthy or archived groups. Entries are
    /// added by [`Self::quarantine_stored_group_on_hydrate`] and removed by a
    /// successful [`Self::retry_hydrate_quarantined_group`].
    pub(crate) quarantined_groups: HashMap<GroupId, GroupHydrationQuarantineReason>,

    /// Authoritative `transport_group_id -> GroupId` resolver for inbound
    /// routing (#740). A Nostr-routed group's `transport_group_id`
    /// (`nostr_group_id`) differs from its MLS group id, so the direct
    /// `get_group` lookup in `group_id_for_transport_group_id` misses on the
    /// normal production path; this index answers that in O(1) instead of the
    /// former O(groups) scan that deserialized EVERY joined `MlsGroup` — a scan
    /// that ran BEFORE payload authentication, so an unauthenticated peer could
    /// flood unknown `transport_group_id`s to force attacker-paced CPU + storage
    /// I/O. Populated for every group at hydration
    /// ([`Self::hydrate_one_stored_group`]) and establishment (`do_create_group`
    /// / `do_join_welcome`); a `transport_group_id` is immutable for a group's
    /// maintenance is needed for a static route. A `transport_group_id` CAN
    /// change via a Nostr routing-component update commit (rotation); every
    /// commit-apply site therefore calls [`Self::reindex_transport_group_id`],
    /// which additively inserts the new id while leaving the prior id in place
    /// for the rotation overlap window (this map is intentionally many-to-one).
    /// The engine has no group-deletion path today (`StorageProvider::delete_group`
    /// is never called from engine code; a left group's record is retained), so an
    /// entry cannot outlive its group — and even a hypothetical stale entry is
    /// self-correcting, since the resolved `GroupId` is loaded by the caller and a
    /// missing group is dropped as unknown. If engine-side group deletion is ever
    /// added, that site MUST remove the corresponding index entries.
    pub(crate) transport_group_id_index: HashMap<Vec<u8>, GroupId>,

    /// #636: cached hex-encoded snapshot of `seen_message_ids` for the
    /// convergence `CanonicalizationState`, tagged with the seen-set generation
    /// it was built from. A convergence drain runs the pass up to 16× and
    /// previously re-hex-encoded the whole (up to 100k-entry) set every pass;
    /// this rebuilds only when the set actually changed. `None` until first use.
    pub(crate) seen_message_ids_hex_cache: Option<(u64, std::collections::BTreeSet<String>)>,
}

// ── Builder ─────────────────────────────────────────────────────────────────

/// Construction-time wiring for [`Engine`].
pub struct EngineBuilder<S: StorageProvider> {
    storage: S,
    identity_bytes: Option<Vec<u8>>,
    account_identity_proof_signer:
        Option<Arc<dyn crate::account_identity_proof::AccountIdentityProofSigner>>,
    registry: FeatureRegistry,
    supported_app_components: AppComponentSet,
    peeler: Option<Box<dyn TransportPeeler>>,
    ciphersuite: Ciphersuite,
    max_past_epochs: usize,
    recorder: Option<Box<dyn ForensicRecorder>>,
}

impl<S: StorageProvider> EngineBuilder<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            identity_bytes: None,
            account_identity_proof_signer: None,
            registry: FeatureRegistry::new(),
            supported_app_components: AppComponentSet::new(default_group_components()),
            peeler: None,
            ciphersuite: DEFAULT_CIPHERSUITE,
            max_past_epochs: crate::wire_format::DEFAULT_MAX_PAST_EPOCHS,
            recorder: None,
        }
    }

    pub fn identity(mut self, bytes: Vec<u8>) -> Self {
        self.identity_bytes = Some(bytes);
        self
    }

    pub fn account_identity_proof_signer(
        mut self,
        signer: Arc<dyn crate::account_identity_proof::AccountIdentityProofSigner>,
    ) -> Self {
        self.account_identity_proof_signer = Some(signer);
        self
    }

    pub fn feature_registry(mut self, registry: FeatureRegistry) -> Self {
        self.registry = registry;
        self
    }

    pub fn supported_app_components(
        mut self,
        components: impl IntoIterator<Item = AppComponentId>,
    ) -> Self {
        self.supported_app_components = AppComponentSet::new(components);
        self
    }

    pub fn peeler(mut self, peeler: Box<dyn TransportPeeler>) -> Self {
        self.peeler = Some(peeler);
        self
    }

    pub fn ciphersuite(mut self, cs: Ciphersuite) -> Self {
        self.ciphersuite = cs;
        self
    }

    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.max_past_epochs = max_past_epochs;
        self
    }

    /// Install a forensic audit-log recorder. Without this call the engine
    /// uses [`NoopRecorder`] and emits no audit events.
    pub fn recorder(mut self, recorder: Box<dyn ForensicRecorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    pub fn build(self) -> Result<Engine<S>, EngineError> {
        // spec/foundation/mls-protocol.md:11-15 — Marmot has a single
        // mandatory-to-implement ciphersuite. Reject any other ciphersuite at
        // construction so no group can ever be created off-spec.
        if self.ciphersuite != DEFAULT_CIPHERSUITE {
            return Err(EngineError::UnsupportedCiphersuite {
                got: u16::from(self.ciphersuite),
                required: u16::from(DEFAULT_CIPHERSUITE),
            });
        }
        let identity_bytes = self
            .identity_bytes
            .ok_or_else(|| EngineError::Other("identity bytes are required".into()))?;
        let peeler = self
            .peeler
            .ok_or_else(|| EngineError::Other("TransportPeeler is required".into()))?;
        let proof_signer = self.account_identity_proof_signer.ok_or_else(|| {
            EngineError::Other("account identity proof signer is required".into())
        })?;
        let crypto = RustCrypto::default();
        let identity = Identity::load_or_generate(
            self.ciphersuite,
            identity_bytes,
            &self.storage,
            proof_signer.as_ref(),
        )
        .map_err(EngineError::Other)?;

        Ok(Engine {
            storage: self.storage,
            crypto,
            identity,
            registry: self.registry,
            supported_app_components: self.supported_app_components,
            peeler,
            ciphersuite: self.ciphersuite,
            max_past_epochs: self.max_past_epochs,
            epoch_manager: crate::epoch_manager::EpochManager::new(),
            fork_recovery: crate::fork_recovery::ForkRecoveryManager::default(),
            events_buf: VecDeque::new(),
            auto_publish_buf: VecDeque::new(),
            auto_proposal_buf: VecDeque::new(),
            pending_state_changes: HashMap::new(),
            seen_message_ids: BoundedIdSet::with_capacity(DEDUP_CACHE_CAPACITY),
            sent_message_ids: BoundedIdSet::with_capacity(DEDUP_CACHE_CAPACITY),
            leave_requests: HashMap::new(),
            leaving_groups: HashSet::new(),
            scheduled_self_remove_auto_commits: HashMap::new(),
            pending_convergence_groups: HashSet::new(),
            convergence_policy: crate::canonicalization::CanonicalizationPolicy::default(),
            last_convergence_relevant_input_ms: HashMap::new(),
            convergence_clock_started_at: Instant::now(),
            engine_metrics: crate::engine_metrics::EngineMetrics::default(),
            recorder: self.recorder.unwrap_or_else(|| Box::new(NoopRecorder)),
            audit_operation_counter: 0,
            current_audit_context: None,
            quarantined_groups: HashMap::new(),
            transport_group_id_index: HashMap::new(),
            seen_message_ids_hex_cache: None,
        })
    }
}

impl<S: StorageProvider> Engine<S> {
    pub async fn ingest_with_audit_context(
        &mut self,
        msg: TransportMessage,
        transport_context: Option<marmot_forensics::AuditTransportContext>,
    ) -> Result<IngestOutcome, EngineError> {
        let operation_id = self.next_audit_operation_id();
        let msg_id_hex = hex::encode(msg.id.as_slice());
        let mut context = AuditEventContext {
            operation_id: Some(operation_id.clone()),
            human_action: None,
            transport: transport_context,
            engine: None,
            group: None,
            convergence: None,
            source: None,
        };
        // Record the transport wire evidence before ingest when the transport
        // layer supplied it, so an analyzer sees what arrived on the wire ahead
        // of the engine's ingest_entry/outcome for the same message.
        if let Some(wire) = context
            .transport
            .as_ref()
            .and_then(|transport| transport.wire.clone())
        {
            self.audit_with_context(
                None,
                Some(context.clone()),
                crate::audit_helpers::transport_received_event(&msg, wire),
            );
        }
        self.audit_with_context(
            None,
            Some(context.clone()),
            crate::audit_helpers::ingest_entry_event(&msg),
        );
        let result = self.do_ingest(msg).await;
        match &result {
            Ok(outcome) => {
                let group_ref = crate::audit_helpers::ingest_outcome_group_ref(outcome);
                self.recorder.record(AuditRecord {
                    group_ref,
                    context: Some(context),
                    kind: crate::audit_helpers::ingest_outcome_event(msg_id_hex, outcome),
                });
            }
            Err(err) => {
                context.engine = Some(self.audit_engine_context_snapshot());
                self.audit_with_context(
                    None,
                    Some(context),
                    AuditEventKind::IngestError {
                        msg_id: msg_id_hex,
                        error_kind: crate::audit_helpers::engine_error_kind(err).to_string(),
                        detail: crate::audit_helpers::engine_error_detail(err),
                    },
                );
            }
        }
        result
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: Option<AuditEventContext>,
    ) -> Result<SendResult, EngineError> {
        let operation_id = self.next_audit_operation_id();
        let intent_kind = crate::audit_helpers::send_intent_kind_str(&intent).to_string();
        let group_ref = crate::audit_helpers::send_intent_group_ref(&intent);
        let recipient_group_id = crate::audit_helpers::send_intent_group_id(&intent);
        let mut context = context.unwrap_or_default();
        context.operation_id = Some(operation_id);
        self.recorder.record(AuditRecord {
            group_ref: group_ref.clone(),
            context: Some(context.clone()),
            kind: AuditEventKind::SendEntry {
                intent_kind: intent_kind.clone(),
            },
        });
        self.current_audit_context = Some(context.clone());
        let result = self.do_send(intent).await;
        self.current_audit_context = None;
        match &result {
            Ok(send_result) => {
                self.recorder.record(AuditRecord {
                    group_ref: group_ref.clone(),
                    context: Some(context.clone()),
                    kind: crate::audit_helpers::send_outcome_event(intent_kind, send_result),
                });
                for (msg_id, expectation) in
                    self.recipient_expectation_records(&recipient_group_id, send_result)
                {
                    self.recorder.record(AuditRecord {
                        group_ref: group_ref.clone(),
                        context: Some(context.clone()),
                        kind: AuditEventKind::RecipientExpectation {
                            msg_id,
                            expectation,
                        },
                    });
                }
            }
            Err(err) => {
                self.recorder.record(AuditRecord {
                    group_ref,
                    context: Some(context),
                    kind: AuditEventKind::SendError {
                        intent_kind,
                        error_kind: crate::audit_helpers::engine_error_kind(err).to_string(),
                        detail: crate::audit_helpers::engine_error_detail(err),
                    },
                });
            }
        }
        result
    }

    pub async fn create_group_with_audit_context(
        &mut self,
        req: CreateGroupRequest,
        context: Option<AuditEventContext>,
    ) -> Result<(GroupId, SendResult), EngineError> {
        let operation_id = self.next_audit_operation_id();
        let mut context = context.unwrap_or_default();
        context.operation_id = Some(operation_id);
        context.engine = Some(self.audit_engine_context_snapshot());
        self.audit_with_context(
            None,
            Some(context.clone()),
            AuditEventKind::CreateGroupEntry {
                member_count: req.members.len() as u64,
                required_feature_count: req.required_features.len() as u64,
                app_component_count: req.app_components.len() as u64,
                initial_admin_count: req.initial_admins.len() as u64,
            },
        );
        self.current_audit_context = Some(context.clone());
        let result = self.do_create_group(req).await;
        match &result {
            Ok((group_id, send_result)) => {
                let mut outcome_context = context.clone();
                outcome_context.group = self.audit_group_context_snapshot(group_id);
                self.audit_group_with_context(
                    group_id,
                    outcome_context.clone(),
                    crate::audit_helpers::create_group_outcome_event(send_result),
                );
                for (msg_id, expectation) in
                    self.recipient_expectation_records(group_id, send_result)
                {
                    self.audit_group_with_context(
                        group_id,
                        outcome_context.clone(),
                        AuditEventKind::RecipientExpectation {
                            msg_id,
                            expectation,
                        },
                    );
                }
                self.audit_group_context(group_id, "create_group");
            }
            Err(err) => {
                self.audit_with_context(
                    None,
                    Some(context),
                    AuditEventKind::CreateGroupError {
                        error_kind: crate::audit_helpers::engine_error_kind(err).to_string(),
                        detail: crate::audit_helpers::engine_error_detail(err),
                    },
                );
            }
        }
        self.current_audit_context = None;
        result
    }

    /// Compute per-message recipient expectations for a completed send/create,
    /// derived from authenticated membership: the main message (commit, app
    /// message, or proposal) targets all OTHER current group members; each
    /// welcome targets only its added member. Full member pubkeys are included
    /// only in [`AuditDataMode::FullData`]; member refs (salted hashes) and
    /// counts are always safe.
    fn recipient_expectation_records(
        &self,
        group_id: &GroupId,
        result: &SendResult,
    ) -> Vec<(
        marmot_forensics::MessageRefHex,
        marmot_forensics::RecipientExpectation,
    )> {
        use cgka_traits::transport::TransportEnvelope;
        use marmot_forensics::{MessageArtifactKind, RecipientExpectation, RecipientScope};

        let full_data = self.recorder.data_mode() == marmot_forensics::AuditDataMode::FullData;
        let membership_epoch = self
            .audit_group_context_snapshot(group_id)
            .and_then(|ctx| ctx.epoch);
        let mut rows = Vec::new();

        let main = match result {
            SendResult::ApplicationMessage { msg } => {
                Some((msg, MessageArtifactKind::ApplicationMessage))
            }
            SendResult::Proposal { msg } => Some((msg, MessageArtifactKind::Proposal)),
            SendResult::GroupEvolution { msg, .. } => Some((msg, MessageArtifactKind::Commit)),
            SendResult::GroupCreated { .. } | SendResult::Queued { .. } => None,
        };
        if let Some((msg, artifact_kind)) = main {
            let self_id = self.identity.self_id();
            let members = self.do_members(group_id).unwrap_or_default();
            let others: Vec<_> = members.iter().filter(|m| &m.id != self_id).collect();
            let expected_pubkeys_hex = if full_data {
                others
                    .iter()
                    .filter(|m| m.credential.len() == 32)
                    .map(|m| hex::encode(&m.credential))
                    .collect()
            } else {
                Vec::new()
            };
            rows.push((
                hex::encode(msg.id.as_slice()),
                RecipientExpectation {
                    artifact_kind,
                    recipient_scope: RecipientScope::AllOtherCurrentGroupMembers,
                    membership_epoch,
                    basis_commit_id: None,
                    expected_member_refs: others
                        .iter()
                        .map(|m| crate::audit_helpers::member_ref_hex(&m.id))
                        .collect(),
                    expected_pubkeys_hex,
                    expected_count: Some(others.len() as u64),
                },
            ));
        }

        let welcomes = match result {
            SendResult::GroupEvolution { welcomes, .. }
            | SendResult::GroupCreated { welcomes, .. } => welcomes.as_slice(),
            _ => [].as_slice(),
        };
        for welcome in welcomes {
            let recipient = match &welcome.envelope {
                TransportEnvelope::Welcome { recipient } => Some(recipient.clone()),
                TransportEnvelope::GroupMessage { .. } => None,
            };
            let (expected_member_refs, expected_pubkeys_hex, expected_count) = match &recipient {
                Some(recipient) => {
                    let pubkeys = if full_data && recipient.as_slice().len() == 32 {
                        vec![hex::encode(recipient.as_slice())]
                    } else {
                        Vec::new()
                    };
                    (
                        vec![crate::audit_helpers::member_ref_hex(recipient)],
                        pubkeys,
                        Some(1),
                    )
                }
                None => (Vec::new(), Vec::new(), None),
            };
            rows.push((
                hex::encode(welcome.id.as_slice()),
                RecipientExpectation {
                    artifact_kind: MessageArtifactKind::Welcome,
                    recipient_scope: RecipientScope::AddedMemberOnly,
                    membership_epoch,
                    basis_commit_id: None,
                    expected_member_refs,
                    expected_pubkeys_hex,
                    expected_count,
                },
            ));
        }
        rows
    }

    /// Restore stable epoch state for groups already present in storage.
    ///
    /// This is used by production session startup after opening durable
    /// storage. The application is expected to resolve publish success/failure
    /// (`confirm_published` / `publish_failed`) before shutdown, but a *crash*
    /// between transport publish and that resolution violates the
    /// precondition: OpenMLS durably persists the staged commit
    /// (`MlsGroupState::PendingCommit`) and `MlsGroup::load` restores it, while
    /// the in-memory `PendingStateRef` that `confirm_published` /
    /// `publish_failed` require is gone (the `EpochManager` starts empty on
    /// every open). Left untouched, the group is stranded: every subsequent
    /// commit-creating operation fails with a pending-commit error forever.
    ///
    /// So at hydrate time we detect a surviving pending commit and clear it,
    /// treating an unresolved pending publish as publish-failed (the same
    /// rewind `do_publish_failed` performs). The MLS group returns to its
    /// pre-stage epoch, we re-derive the Marmot record from that cleared
    /// state, and we surface a typed `PendingCommitRecovered` event so the
    /// application can run a recovery / resync path — if relays accepted the
    /// commit before the crash, this device is now behind and must catch up.
    ///
    /// **Member-removing commits are deliberately left untouched.** A surviving
    /// pending commit is NOT a reliable crash signal on its own: a deferred
    /// SelfRemove-only commit (the MIP-03 leave path) legitimately persists a
    /// staged commit across process boundaries — a remaining member stages the
    /// commit, projects the departing member out of the Marmot record
    /// *forward*, and a later run publishes + confirms it. Rolling that
    /// back re-derives the record from the pre-stage MLS state and so re-adds a
    /// member who already left, forking convergence (the remaining members
    /// advance past the leave while this device silently rewinds it). Clearing
    /// an additive (invite) commit is safe — it only drops an invitee who never
    /// actually joined — but clearing a Remove/SelfRemove is not. We therefore
    /// scope crash-recovery to staged commits that remove no members, matching
    /// the prior (pre-recovery) behaviour for removal-bearing commits.
    /// Additively refresh a group's `transport_group_id_index` entry from live
    /// MLS state after a commit that may have changed the Nostr routing
    /// component (#740 rotation). Inserts the group's CURRENT `transport_group_id`;
    /// any prior id is left in place so inbound messages still addressed to the
    /// pre-rotation route during the overlap window keep resolving (the map is
    /// many-to-one, matching the spec's "publish to the prior routing address"
    /// overlap model). Called at the commit-apply sites (`do_confirm_published`
    /// for local rotation, remote-commit ingest, and convergence apply); these
    /// only fire on commit application, not per app message, so the extra
    /// `MlsGroup::load` is cost-appropriate. Best-effort: a load / routing-read
    /// failure just forfeits the fast path for this group (inbound would fall to
    /// the unknown-group disposition), never fails the merge.
    pub(crate) fn reindex_transport_group_id(&mut self, group_id: &GroupId) {
        let mls_group = {
            let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                &self.crypto,
                self.storage.mls_storage(),
            );
            let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
            match openmls::group::MlsGroup::load(
                <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
                &mls_gid,
            ) {
                Ok(Some(group)) => group,
                _ => return,
            }
        };
        if let Ok(transport_group_id) =
            crate::app_components::transport_group_id_of_group(&mls_group)
        {
            self.transport_group_id_index
                .insert(transport_group_id, group_id.clone());
        }
    }

    pub fn hydrate_stable_groups_from_storage(&mut self) -> Result<(), EngineError> {
        for group_id in self.storage.list_groups()? {
            if let Err(reason) = self.hydrate_one_stored_group(&group_id) {
                self.quarantine_stored_group_on_hydrate(&group_id, reason);
            }
        }
        Ok(())
    }

    fn hydrate_one_stored_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<EpochId, GroupHydrationQuarantineReason> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|_| GroupHydrationQuarantineReason::OpenMlsLoadFailed)?
        .ok_or(GroupHydrationQuarantineReason::OpenMlsGroupMissing)?;

        // Member-credential + account-identity-proof validation runs one
        // BIP-340 schnorr verification per leaf. All of this state was already
        // validated at join/invite/commit ingress and read back from this
        // device's own encrypted storage, so re-verifying every leaf of every
        // group on every session open is pure repeated work (darkmatter#152:
        // ~50 groups x ~50 members ≈ 2500 schnorr verifications per open, and
        // marmot-app opens a fresh session per client() call).
        //
        // Gate the full walk behind a cheap, content-bound marker (a hash over
        // the exported ratchet-tree bytes). If the stored marker matches the
        // current tree, this exact tree already passed validation in a prior
        // run and is byte-identical now, so the schnorr re-verification is
        // skipped. Any membership/leaf/proof change (or a marker-version bump)
        // yields a different marker and forces full re-validation, so
        // correctness never depends on the marker — only performance. A marker
        // computation/IO failure simply falls back to full validation.
        let current_marker =
            crate::group_lifecycle::compute_validated_tree_marker(&mls_group, self.ciphersuite)
                .ok();
        let already_validated = match (
            &current_marker,
            self.storage.validated_tree_marker(group_id),
        ) {
            (Some(current), Ok(Some(stored))) => stored == *current,
            _ => false,
        };
        if !already_validated {
            crate::group_lifecycle::validate_member_credentials_and_account_proofs(
                &mls_group,
                self.ciphersuite,
            )
            .map_err(|_| GroupHydrationQuarantineReason::MemberValidationFailed)?;
            // Validation passed for this tree state; persist the marker so the
            // next open of an unchanged group skips the per-leaf schnorr work.
            // A write failure is non-fatal: it only forfeits the optimization
            // (the next open re-validates), so it must not quarantine a healthy
            // group.
            if let Some(marker) = &current_marker {
                let _ = self.storage.put_validated_tree_marker(group_id, marker);
            }
        }

        let mut group = self
            .storage
            .get_group(group_id)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?;

        // A staged commit that survived process restart *may* mean the
        // application crashed mid-publish. Clear it (treat as
        // publish-failed) so the group is not permanently wedged, then
        // re-derive the Marmot record from the post-clear MLS state.
        //
        // BUT a surviving pending commit is also the normal cross-process
        // state of a deferred SelfRemove auto-commit, whose Marmot record
        // is already projected forward past the leave. Rolling back a
        // commit that removes a member would re-add the departed member and
        // fork convergence, so we only recover commits that add no
        // member-removal (no `Remove`, no `SelfRemove`). Removal-bearing
        // staged commits are left exactly as they were before this recovery
        // path existed.
        let staged_removes_member = mls_group.pending_commit().is_some_and(|staged| {
            staged.queued_proposals().any(|queued| {
                matches!(
                    queued.proposal(),
                    openmls::prelude::Proposal::Remove(_) | openmls::prelude::Proposal::SelfRemove
                )
            })
        });
        if mls_group.pending_commit().is_some() && !staged_removes_member {
            // Clear the staged commit transactionally (preserves the #421
            // crash-safety fix): the MLS storage mutation must be atomic so a
            // crash mid-clear cannot leave torn group state.
            self.storage
                .with_transaction(|storage| {
                    let tx_provider = crate::provider::EngineOpenMlsProvider::<S>::new(
                        &self.crypto,
                        storage.mls_storage(),
                    );
                    mls_group
                        .clear_pending_commit(
                            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&tx_provider),
                        )
                        .map_err(|e| EngineError::Backend(format!("clear_pending: {e:?}")))
                })
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            let recovered_epoch = EpochId(mls_group.epoch().as_u64());
            group.epoch = recovered_epoch;
            group.members = crate::group_lifecycle::marmot_members(&mls_group);
            group.required_capabilities =
                crate::capability_manager::required_capabilities_from_group(&mls_group);
            crate::group_lifecycle::mirror_app_components_into_record(&mls_group, &mut group);
            self.storage
                .put_group(&group)
                .map_err(|_| GroupHydrationQuarantineReason::PendingCommitRecoveryFailed)?;
            self.audit_group(
                group_id,
                AuditEventKind::PendingCommitRecoveredOnOpen {
                    recovered_epoch: recovered_epoch.0,
                },
            );
            self.events_buf
                .push_back(GroupEvent::PendingCommitRecovered {
                    group_id: group_id.clone(),
                    recovered_epoch,
                });
        }

        if let Some(request) = self
            .leave_request_to_restore_on_hydrate(group_id, &mut mls_group, &group, &provider)
            .map_err(|_| GroupHydrationQuarantineReason::GroupRecordLoadFailed)?
        {
            self.leave_requests.insert(group_id.clone(), request);
            self.leaving_groups.insert(group_id.clone());
        } else {
            self.leave_requests.remove(group_id);
            self.leaving_groups.remove(group_id);
        }

        // #740: record this group's transport routing id so inbound resolution
        // is an O(1) index hit rather than a pre-auth O(groups) MlsGroup-load
        // scan. `mls_group` is owned here (not borrowing `self`), and the
        // `provider` borrow is already released, so this direct field insert is
        // disjoint from the storage/crypto borrows above.
        if let Ok(transport_group_id) =
            crate::app_components::transport_group_id_of_group(&mls_group)
        {
            self.transport_group_id_index
                .insert(transport_group_id, group_id.clone());
        }

        self.epoch_manager.set_stable(group_id.clone(), group.epoch);
        self.audit_group(
            group_id,
            crate::audit_helpers::epoch_state_changed_event(
                None,
                "stable",
                group.epoch,
                "hydrate_stable_group",
                None,
                None,
            ),
        );
        self.audit_group_context(group_id, "hydrate_stable_group");
        Ok(group.epoch)
    }

    fn leave_request_to_restore_on_hydrate(
        &self,
        group_id: &GroupId,
        mls_group: &mut openmls::group::MlsGroup,
        group: &Group,
        provider: &crate::provider::EngineOpenMlsProvider<'_, S>,
    ) -> Result<Option<LeaveRequest>, StorageError> {
        let self_is_still_member = group
            .members
            .iter()
            .any(|member| &member.id == self.identity.self_id());
        if !self_is_still_member {
            self.storage.clear_leave_request(group_id)?;
            return Ok(None);
        }

        if let Some(mut request) = self.storage.leave_request(group_id)? {
            if request.last_proposed_epoch.is_none()
                && self.sent_self_remove_leaving_gate_should_restore(
                    group_id, mls_group, group, provider,
                )?
            {
                request.last_proposed_epoch = Some(group.epoch);
                self.storage.put_leave_request(&request)?;
            }
            return Ok(Some(request));
        }

        if self
            .sent_self_remove_leaving_gate_should_restore(group_id, mls_group, group, provider)?
        {
            let request = LeaveRequest {
                group_id: group_id.clone(),
                requested_at_ms: self.convergence_now_ms(),
                last_proposed_epoch: Some(group.epoch),
            };
            self.storage.put_leave_request(&request)?;
            return Ok(Some(request));
        }

        Ok(None)
    }

    pub(crate) fn load_leave_request_state(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Option<LeaveRequest>, StorageError> {
        if let Some(request) = self.leave_requests.get(group_id) {
            return Ok(Some(request.clone()));
        }
        let Some(request) = self.storage.leave_request(group_id)? else {
            return Ok(None);
        };
        self.leave_requests
            .insert(group_id.clone(), request.clone());
        self.leaving_groups.insert(group_id.clone());
        Ok(Some(request))
    }

    pub(crate) fn has_leave_send_gate(&mut self, group_id: &GroupId) -> Result<bool, StorageError> {
        Ok(self.load_leave_request_state(group_id)?.is_some()
            || self.leaving_groups.contains(group_id))
    }

    pub(crate) fn clear_leave_request_state(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), StorageError> {
        self.storage.clear_leave_request(group_id)?;
        self.leave_requests.remove(group_id);
        self.leaving_groups.remove(group_id);
        Ok(())
    }

    /// Clear ONLY the live OpenMLS group state for `group_id`, leaving every
    /// retained artifact in place.
    ///
    /// Called when the local member is removed from a group (the inbound
    /// removal-commit apply paths). It deletes the OpenMLS-owned rows for the
    /// group — ratchet tree, group context, epoch/message secrets, resumption
    /// PSKs, own-leaf index/nodes, group state/config, the proposal queue, and
    /// the current-epoch encryption key pairs — via `MlsGroup::delete`. That is
    /// enough to stop a later re-add Welcome from failing with
    /// `GroupAlreadyExists` when OpenMLS stages the fresh join, and to keep
    /// OpenMLS from stacking the re-join on stale epoch keypairs / message
    /// secrets / own-leaf index (darkmatter#557).
    ///
    /// Crucially it does NOT delete the Marmot `cgka_groups` record, the retained
    /// anchor snapshots, the stored commit/message history, or the convergence
    /// policy. Keeping those preserves both the removed member's tombstoned
    /// read-only view (member list + history remain queryable) and the
    /// retained-anchor reorg material the canonicalization contract requires:
    /// a competing valid branch arriving within `max_rewind_commits` can still
    /// roll back a losing removal branch by restoring a retained snapshot
    /// (`docs/marmot-architecture/cgka-engine-canonicalization-contract.md`).
    ///
    /// Idempotent and tolerant of partially-missing state: a group whose live
    /// OpenMLS state is already gone (or never materialized) is a no-op. The
    /// in-memory epoch/leave/convergence bookkeeping is intentionally left
    /// untouched here; the durable record still describes the (now non-member)
    /// group, and the bookkeeping is reset when the group is re-joined.
    ///
    /// No identifiers are logged (observability.md privacy rule).
    pub(crate) fn clear_live_openmls_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let storage = <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
            &provider,
        );
        let loaded = openmls::group::MlsGroup::load(storage, &mls_gid)
            .map_err(|e| EngineError::Backend(format!("load live group: {e:?}")))?;
        if let Some(mut mls_group) = loaded {
            mls_group
                .delete(storage)
                .map_err(|e| EngineError::Backend(format!("delete live group: {e:?}")))?;
        }
        Ok(())
    }

    fn sent_self_remove_leaving_gate_should_restore(
        &self,
        group_id: &GroupId,
        mls_group: &mut openmls::group::MlsGroup,
        group: &Group,
        provider: &crate::provider::EngineOpenMlsProvider<'_, S>,
    ) -> Result<bool, cgka_traits::storage::StorageError> {
        if !group
            .members
            .iter()
            .any(|member| &member.id == self.identity.self_id())
        {
            return Ok(false);
        }

        for record in self.storage.list_messages(group_id, EpochId(0))? {
            if record.state != MessageState::Sent {
                continue;
            }
            let Ok(stored_payload) = StoredMessagePayload::decode(&record.payload) else {
                continue;
            };
            let Some(message) = stored_payload.as_openmls_wire() else {
                continue;
            };
            let Ok(projection) = crate::openmls_projection::project_mls_message(&message.payload)
            else {
                continue;
            };
            if projection.kind != crate::openmls_projection::OpenMlsContentKind::Proposal {
                continue;
            }

            let Ok(msg_in) = MlsMessageIn::tls_deserialize_exact(message.payload.as_slice()) else {
                continue;
            };
            let protocol: ProtocolMessage = match msg_in.extract() {
                MlsMessageBodyIn::PrivateMessage(private) => private.into(),
                MlsMessageBodyIn::PublicMessage(public) => public.into(),
                _ => continue,
            };
            let mut hasher = Sha256::new();
            hasher.update(b"cgka-engine-hydrate-selfremove-probe/v1");
            hasher.update(group_id.as_slice());
            hasher.update(record.id.as_slice());
            let digest = hasher.finalize();
            let probe_snapshot = format!("hydrate-selfremove-probe-{}", hex::encode(&digest[..8]));
            let guard = crate::snapshot_guard::SnapshotRollbackGuard::create(
                &self.storage,
                group_id.clone(),
                probe_snapshot,
            )?;
            let processed = mls_group.process_message(provider, protocol);
            guard.commit()?;
            let Ok(processed) = processed else {
                continue;
            };
            if let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content()
                && matches!(queued.proposal(), Proposal::SelfRemove)
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn quarantine_stored_group_on_hydrate(
        &mut self,
        group_id: &GroupId,
        reason: GroupHydrationQuarantineReason,
    ) {
        let reason_tag = hydration_quarantine_reason_tag(reason);
        let group_digest = hydration_quarantine_group_digest(group_id);
        tracing::warn!(
            target: "cgka_engine::hydrate",
            method = "quarantine_stored_group_on_hydrate",
            reason = reason_tag,
            "quarantined stored group during session-open hydration"
        );
        self.audit(AuditEventKind::GroupHydrationQuarantined {
            group_digest,
            reason: reason_tag.to_string(),
        });
        self.quarantined_groups.insert(group_id.clone(), reason);
        self.events_buf
            .push_back(GroupEvent::GroupHydrationQuarantined {
                group_id: group_id.clone(),
                reason,
            });
    }

    /// Stored groups that failed session-open hydration and were skipped so the
    /// rest of the account could open (darkmatter#151 / #417), paired with the
    /// coarse [`GroupHydrationQuarantineReason`] that classifies why.
    ///
    /// This is the engine-side source of truth for the application's per-group
    /// recovery flow (darkmatter#426): a quarantined group is not in the live
    /// roster (`epoch`/`members` return `UnknownGroup`) and otherwise vanishes
    /// from the account with no explanation. The app reads this list to surface
    /// those groups distinctly from healthy/archived ones and to offer
    /// [`Self::retry_hydrate_quarantined_group`].
    ///
    /// Order is unspecified. The returned reason is a copy; the engine retains
    /// its own entry until a retry succeeds.
    pub fn quarantined_groups(&self) -> Vec<(GroupId, GroupHydrationQuarantineReason)> {
        self.quarantined_groups
            .iter()
            .map(|(group_id, reason)| (group_id.clone(), *reason))
            .collect()
    }

    /// Re-attempt hydration of a single quarantined group.
    ///
    /// This is the non-destructive, user-initiated recovery path for a
    /// transiently-bad group — e.g. a partial DB restore that has since been
    /// completed, or storage that was unreadable at session open but is now
    /// available. It re-runs the exact same per-group hydration the session
    /// performs at open ([`Self::hydrate_one_stored_group`]), which only reads
    /// stored state and, at most, clears a stranded non-removal pending commit
    /// (the same crash-recovery already performed at open). It never edits the
    /// encrypted DB, never re-joins, and never discards a group's local
    /// history.
    ///
    /// Returns:
    /// - `Ok(true)` — the group hydrated successfully; it is removed from the
    ///   quarantine list, dropped from [`Self::quarantined_groups`], and is now
    ///   a live group (`epoch`/`members` resolve). A `GroupHydrationRecovered`
    ///   event is queued for the application to refresh its projection.
    /// - `Ok(false)` — the group is still unhealthy. It stays quarantined; the
    ///   stored reason is refreshed to the latest classification so the UI can
    ///   show whether the failure mode changed.
    ///
    /// **Errors.** `UnknownGroup` if the id is not currently quarantined (the
    /// app should only call this for ids returned by
    /// [`Self::quarantined_groups`]).
    ///
    /// Whether and when to retry — automatically on reconnect, on a timer, or
    /// only on explicit user action — is a product decision left to the
    /// application; the engine only exposes the mechanism.
    pub fn retry_hydrate_quarantined_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, EngineError> {
        if !self.quarantined_groups.contains_key(group_id) {
            return Err(EngineError::UnknownGroup(group_id.clone()));
        }
        match self.hydrate_one_stored_group(group_id) {
            Ok(recovered_epoch) => {
                self.quarantined_groups.remove(group_id);
                let reason_tag = "recovered";
                let group_digest = hydration_quarantine_group_digest(group_id);
                tracing::info!(
                    target: "cgka_engine::hydrate",
                    method = "retry_hydrate_quarantined_group",
                    outcome = reason_tag,
                    "recovered a quarantined stored group on retry"
                );
                self.audit(AuditEventKind::GroupHydrationRecovered { group_digest });
                // `recovered_epoch` is the epoch hydration just established and
                // wrote through to storage + epoch_manager (set_stable). Use it
                // directly rather than a second storage.get_group() that could
                // fail and silently emit epoch 0 (darkmatter#441 finding 3).
                self.events_buf
                    .push_back(GroupEvent::GroupHydrationRecovered {
                        group_id: group_id.clone(),
                        recovered_epoch,
                    });
                Ok(true)
            }
            Err(reason) => {
                // Still unhealthy. Keep it quarantined, but refresh the stored
                // reason so the UI reflects the current failure mode. Do not
                // re-emit a quarantine event — the group was never live.
                let reason_tag = hydration_quarantine_reason_tag(reason);
                tracing::warn!(
                    target: "cgka_engine::hydrate",
                    method = "retry_hydrate_quarantined_group",
                    reason = reason_tag,
                    "retry did not recover the quarantined stored group"
                );
                self.quarantined_groups.insert(group_id.clone(), reason);
                Ok(false)
            }
        }
    }

    pub(crate) fn convergence_now_ms(&self) -> u64 {
        self.convergence_clock_started_at
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    /// Aggregate, privacy-safe snapshot of engine diagnostic telemetry.
    ///
    /// Currently the post-settle reorg counters and histograms used for
    /// quiescence tuning (`docs/marmot-architecture/relay-delivery-telemetry.md`
    /// §"Validation: post-settle reorg rate"). Carries only counts and
    /// millisecond/commit buckets — no group ids, epochs, or branch ids. Like
    /// `drain_events`, it is read-only and never feeds convergence.
    pub fn engine_metrics(&self) -> crate::engine_metrics::EngineMetricsSnapshot {
        tracing::trace!(
            target: "cgka_engine::engine_metrics",
            method = "engine_metrics",
            "snapshotting engine metrics"
        );
        self.engine_metrics.snapshot()
    }

    /// Emit an audit-log event with no group attribution.
    pub(crate) fn audit(&self, kind: AuditEventKind) {
        self.audit_with_context(None, None, kind);
    }

    /// Emit an audit-log event attributed to a specific group.
    pub(crate) fn audit_group(&self, group_id: &GroupId, kind: AuditEventKind) {
        self.audit_with_context(Some(group_id), None, kind);
    }

    pub(crate) fn audit_group_with_context(
        &self,
        group_id: &GroupId,
        context: AuditEventContext,
        kind: AuditEventKind,
    ) {
        self.audit_with_context(Some(group_id), Some(context), kind);
    }

    pub(crate) fn audit_with_context(
        &self,
        group_id: Option<&GroupId>,
        context: Option<AuditEventContext>,
        kind: AuditEventKind,
    ) {
        // Fall back to the in-flight operation's context so secondary rows
        // emitted via the context-less `audit`/`audit_group` helpers still
        // carry the operation's `human_action`. An explicit context always wins.
        let context = context.or_else(|| self.current_audit_context.clone());
        let mut record = AuditRecord::new(
            group_id.map(|group_id| hex::encode(group_id.as_slice())),
            kind,
        );
        record.context = context;
        self.recorder.record(record);
    }

    pub fn audit_external(
        &self,
        group_id: Option<&GroupId>,
        context: Option<AuditEventContext>,
        kind: AuditEventKind,
    ) {
        self.audit_with_context(group_id, context, kind);
    }

    pub fn audit_recorder_health(&self) {
        let health = self.recorder.health_snapshot();
        self.audit(AuditEventKind::RecorderHealth {
            serialization_failures: health.serialization_failures,
            write_failures: health.write_failures,
            flush_failures: health.flush_failures,
        });
    }

    /// Filesystem path the installed forensic recorder appends to, if it is
    /// file-backed. `None` for the default [`NoopRecorder`].
    pub fn audit_recorder_path(&self) -> Option<std::path::PathBuf> {
        self.recorder.audit_log_path()
    }

    /// Rotate the installed forensic recorder: discard its current file and
    /// begin a fresh one, then keep recording. No-op for non-file recorders.
    pub fn rotate_audit_recorder(&self) -> std::io::Result<()> {
        self.recorder.rotate()
    }

    /// Switch the installed forensic recorder's [`AuditDataMode`] in place. On a
    /// real change a file-backed recorder rotates so the file carries a single,
    /// unambiguous mode and writes an `audit_data_mode_changed` boundary row.
    /// No-op for the [`NoopRecorder`] or when the mode is unchanged.
    pub fn set_audit_recorder_data_mode(
        &self,
        mode: marmot_forensics::AuditDataMode,
        reason: &str,
    ) -> std::io::Result<()> {
        self.recorder.set_data_mode(mode, reason)
    }

    /// Replace the installed forensic recorder on a live engine. Dropping the
    /// prior recorder flushes and closes any file it held. Used to start or
    /// stop audit logging in place when the audit switch is toggled, without
    /// rebuilding the engine. Pass [`NoopRecorder`] to stop recording.
    pub fn set_recorder(&mut self, recorder: Box<dyn ForensicRecorder>) {
        self.recorder = recorder;
    }

    pub(crate) fn next_audit_operation_id(&mut self) -> String {
        let id = self.audit_operation_counter;
        self.audit_operation_counter = self.audit_operation_counter.wrapping_add(1);
        format!("op-{id}")
    }

    pub fn audit_engine_context(&self) {
        self.audit(AuditEventKind::EngineContext {
            context: self.audit_engine_context_snapshot(),
        });
    }

    pub(crate) fn audit_engine_context_snapshot(&self) -> AuditEngineContext {
        AuditEngineContext {
            ciphersuite: Some(u16::from(self.ciphersuite)),
            max_past_epochs: Some(self.max_past_epochs as u64),
            convergence_max_rewind_commits: Some(
                self.convergence_policy.convergence.max_rewind_commits,
            ),
            supported_app_component_count: Some(self.supported_app_components.ids.len() as u64),
            feature_count: Some(self.registry.iter().count() as u64),
        }
    }

    pub(crate) fn audit_group_context_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Option<AuditGroupContext> {
        let group = self.storage.get_group(group_id).ok()?;
        Some(AuditGroupContext {
            epoch: Some(group.epoch.0),
            member_count: Some(group.members.len() as u64),
            required_app_component_count: Some(
                group.required_capabilities.app_components.ids.len() as u64,
            ),
            admin_count: self
                .admin_pubkeys(group_id)
                .ok()
                .map(|admins| admins.len() as u64),
            convergence_max_rewind_commits: Some(
                self.convergence_policy.convergence.max_rewind_commits,
            ),
        })
    }

    pub(crate) fn audit_group_context(&self, group_id: &GroupId, reason: &str) {
        if let Some(context) = self.audit_group_context_snapshot(group_id) {
            self.audit_group(
                group_id,
                AuditEventKind::GroupContext {
                    reason: reason.to_string(),
                    context,
                },
            );
        }
    }

    /// Emit a `SnapshotCreated` audit event. Call this immediately after
    /// `self.fork_recovery.create_snapshot(&self.storage, ...)` succeeds.
    /// Kept separate from the `create_snapshot` call so callers preserve
    /// disjoint-field borrow patterns when a `provider` is alive.
    pub(crate) fn audit_snapshot_created(
        &self,
        group_id: &GroupId,
        snapshot_name: &str,
        source_epoch: EpochId,
        reason: &str,
    ) {
        self.audit_group(
            group_id,
            AuditEventKind::SnapshotCreated {
                snapshot_name: snapshot_name.to_string(),
                source_epoch: source_epoch.0,
                reason: reason.to_string(),
                state_digest: None,
            },
        );
    }

    /// Return the Marmot group metadata mirrored from signed MLS group state.
    ///
    /// App surfaces use this for projections such as group profile components
    /// without reaching into OpenMLS internals.
    pub fn group_record(&self, group_id: &GroupId) -> Result<Group, EngineError> {
        Ok(self.storage.get_group(group_id)?)
    }

    /// Return the current Marmot admin policy keys mirrored from signed MLS
    /// group state.
    pub fn admin_pubkeys(&self, group_id: &GroupId) -> Result<Vec<[u8; 32]>, EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        let mut admins = crate::app_components::admins_of_group(&mls_group)?;
        admins.sort();
        admins.dedup();
        Ok(admins)
    }

    pub fn safe_export_secret_with_epoch(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<(EpochId, cgka_traits::SecretBytes), EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        let required_components =
            crate::app_components::required_app_components_of_group(&mls_group)?;
        if !required_components.contains(component_id) {
            return Err(EngineError::Other(format!(
                "group does not require app component {component_id:#06x}"
            )));
        }

        let crypto =
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(&provider);
        let storage =
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider);
        if let Some(epoch) = mls_group
            .pending_commit()
            .map(|staged| EpochId(staged.group_context().epoch().as_u64()))
        {
            let secret = mls_group
                .safe_export_secret_from_pending(crypto, storage, component_id)
                .map_err(|e| EngineError::Backend(format!("staged safe_export_secret: {e:?}")))?;
            Ok((epoch, cgka_traits::SecretBytes::new(secret)))
        } else {
            let secret = mls_group
                .safe_export_secret(crypto, storage, component_id)
                .map_err(|e| EngineError::Backend(format!("safe_export_secret: {e:?}")))?;
            Ok((
                EpochId(mls_group.epoch().as_u64()),
                cgka_traits::SecretBytes::new(secret),
            ))
        }
    }

    pub fn current_safe_export_epoch(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<EpochId, EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;

        let required_components =
            crate::app_components::required_app_components_of_group(&mls_group)?;
        if !required_components.contains(component_id) {
            return Err(EngineError::Other(format!(
                "group does not require app component {component_id:#06x}"
            )));
        }

        if let Some(staged) = mls_group.pending_commit() {
            Ok(EpochId(staged.group_context().epoch().as_u64()))
        } else {
            Ok(EpochId(mls_group.epoch().as_u64()))
        }
    }
}

// ── CgkaEngine impl ─────────────────────────────────────────────────────────
//
// Trait methods stay thin: validate the trait boundary, then delegate to
// the module that owns the behavior.

#[async_trait]
impl<S: StorageProvider + 'static> CgkaEngine for Engine<S> {
    async fn ingest(&mut self, msg: TransportMessage) -> Result<IngestOutcome, EngineError> {
        self.ingest_with_audit_context(msg, None).await
    }

    fn drain_events(&mut self) -> Vec<GroupEvent> {
        self.events_buf.drain(..).collect()
    }

    fn drain_auto_publish(&mut self) -> Vec<AutoPublish> {
        self.auto_publish_buf.drain(..).collect()
    }

    fn drain_auto_proposals(&mut self) -> Vec<TransportMessage> {
        self.auto_proposal_buf.drain(..).collect()
    }

    fn drain_pending_convergence_groups(&mut self) -> Vec<GroupId> {
        self.pending_convergence_groups.drain().collect()
    }

    async fn send(&mut self, intent: SendIntent) -> Result<SendResult, EngineError> {
        self.send_with_audit_context(intent, None).await
    }

    async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> Result<Vec<SendResult>, EngineError> {
        let now_ms = self.convergence_now_ms();
        self.converge_and_drain_queued_outbound_intents(group_id, now_ms)
            .await
    }

    async fn confirm_published(
        &mut self,
        pending: PendingStateRef,
    ) -> Result<GroupEvent, EngineError> {
        self.do_confirm_published(pending).await
    }

    async fn publish_failed(&mut self, pending: PendingStateRef) -> Result<(), EngineError> {
        self.do_publish_failed(pending).await
    }

    async fn create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> Result<(GroupId, SendResult), EngineError> {
        self.create_group_with_audit_context(req, None).await
    }

    async fn join_welcome(
        &mut self,
        welcome_msg: TransportMessage,
    ) -> Result<GroupId, EngineError> {
        self.do_join_welcome(welcome_msg).await
    }

    fn feature_status(
        &self,
        group_id: &GroupId,
        feature: &Feature,
    ) -> Result<FeatureStatus, EngineError> {
        self.do_feature_status(group_id, feature)
    }

    fn constructable_capabilities(
        &self,
        key_packages: &[KeyPackage],
    ) -> Result<GroupCapabilities, EngineError> {
        self.do_constructable_capabilities(key_packages)
    }

    fn upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities, EngineError> {
        self.do_upgradeable_capabilities(group_id)
    }

    async fn upgrade_group_capabilities(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendResult, EngineError> {
        self.do_upgrade_group_capabilities(group_id).await
    }

    fn group_context(&self, group_id: &GroupId) -> Result<Box<dyn GroupContext + '_>, EngineError> {
        use crate::provider::EngineOpenMlsProvider;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        // When the group is in `PendingPublish`, the MLS group is at the
        // pre-stage epoch but the staged commit carries the projected
        // future state. Project so callers see the same epoch the rest of
        // the engine reports via `epoch()` / `EpochState`.
        let crypto =
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(&provider);
        let (epoch, group_secret, media_secret, stream_secret) = if let Some(staged) =
            mls_group.pending_commit()
        {
            let group_secret = staged
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| EngineError::Backend(format!("staged export_secret: {e:?}")))?;
            let media_secret = staged
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::ENCRYPTED_MEDIA_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("staged encrypted media export_secret: {e:?}"))
                })?;
            let stream_secret = staged
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::AGENT_TEXT_STREAM_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("staged agent text stream export_secret: {e:?}"))
                })?;
            (
                staged.group_context().epoch().as_u64(),
                group_secret,
                media_secret,
                stream_secret,
            )
        } else {
            let group_secret = mls_group
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
            let media_secret = mls_group
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::ENCRYPTED_MEDIA_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("encrypted media export_secret: {e:?}"))
                })?;
            let stream_secret = mls_group
                .export_secret(
                    crypto,
                    crate::group_lifecycle::EXPORTER_LABEL,
                    crate::group_lifecycle::AGENT_TEXT_STREAM_EXPORTER_CONTEXT,
                    32,
                )
                .map_err(|e| {
                    EngineError::Backend(format!("agent text stream export_secret: {e:?}"))
                })?;
            (
                mls_group.epoch().as_u64(),
                group_secret,
                media_secret,
                stream_secret,
            )
        };
        let mut map = std::collections::HashMap::new();
        map.insert(
            crate::group_lifecycle::EXPORTER_SNAPSHOT_KEY.to_string(),
            cgka_traits::SecretBytes::new(group_secret),
        );
        map.insert(
            crate::group_lifecycle::ENCRYPTED_MEDIA_EXPORTER_SNAPSHOT_KEY.to_string(),
            cgka_traits::SecretBytes::new(media_secret),
        );
        map.insert(
            crate::group_lifecycle::AGENT_TEXT_STREAM_EXPORTER_SNAPSHOT_KEY.to_string(),
            cgka_traits::SecretBytes::new(stream_secret),
        );
        Ok(Box::new(crate::group_context_view::GroupContextView::new(
            EpochId(epoch),
            map,
            Some(crate::app_components::transport_group_id_of_group(
                &mls_group,
            )?),
        )))
    }

    fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<cgka_traits::SecretBytes, EngineError> {
        self.safe_export_secret_with_epoch(group_id, component_id)
            .map(|(_, secret)| secret)
    }

    fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<Option<Vec<u8>>, EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = openmls::group::MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        Ok(crate::app_components::app_component_data_of_group(
            &mls_group,
            component_id,
        ))
    }

    fn own_leaf_index(&self, group_id: &GroupId) -> Result<u32, EngineError> {
        self.do_own_leaf_index(group_id)
    }

    fn members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError> {
        self.do_members(group_id)
    }

    fn epoch(&self, group_id: &GroupId) -> Result<EpochId, EngineError> {
        self.epoch_manager
            .epoch(group_id)
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))
    }

    fn self_id(&self) -> MemberId {
        self.identity.self_id().clone()
    }

    async fn fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        self.do_fresh_key_package()
    }

    async fn delete_key_package(&mut self, key_package: &KeyPackage) -> Result<(), EngineError> {
        self.do_delete_key_package(key_package)
    }
}
