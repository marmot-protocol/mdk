//! Group lifecycle — `create_group`, `join_welcome`, etc.
//!
//! `do_create_group` uses publish-before-apply: it stages an add-members
//! commit, wraps welcomes from the staged group, enters `PendingPublish`,
//! and returns. `Engine::do_confirm_published` merges the MLS commit and
//! updates Marmot records after the application reports transport success.
//! `publish_failed` clears the staged commit and rewinds to `Stable`.
//!
//! For SOLO create (no invitees) there is no pending commit — the engine
//! still issues a `PendingStateRef` so the API shape is uniform, but
//! confirm/fail are state-machine-only no-ops MLS-side.

use crate::capabilities::{
    capabilities_of_key_package, extension_from_group_capabilities, leaf_capabilities,
    required_capabilities_extension_for_features,
};
use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use crate::wire_format::{PURE_PLAINTEXT_WIRE_FORMAT_POLICY, join_config};
use cgka_traits::TransportEndpoint;
use cgka_traits::app_components::{
    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, AppComponentSet, default_group_components,
};
use cgka_traits::capabilities::{GroupCapabilities, TransportKind};
use cgka_traits::engine::{CreateGroupRequest, KeyPackage, SendResult, WelcomeMetadata};
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member, ProtocolProfile};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::AuditEventKind;
use openmls::group::{MlsGroup, MlsGroupCreateConfig};
use openmls::prelude::{
    BasicCredential, CreationFromExternalError, Extension, Extensions, MlsMessageBodyIn,
    MlsMessageIn, WelcomeError,
};
use openmls::treesync::Node;
use openmls_traits::types::Ciphersuite;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

pub(crate) fn welcome_content_dedup_id(
    peeled: &cgka_traits::ingest::PeeledMessage,
) -> Result<cgka_traits::types::MessageId, EngineError> {
    match &peeled.content {
        cgka_traits::ingest::PeeledContent::Welcome { bytes } => {
            Ok(crate::message_processor::content_dedup_id(bytes))
        }
        _ => Err(EngineError::Peeler(
            cgka_traits::error::PeelerError::Malformed("peeled content was not a Welcome".into()),
        )),
    }
}

pub(crate) fn terminal_welcome_error(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::Peeler(cgka_traits::error::PeelerError::DecryptFailed)
            | EngineError::Peeler(cgka_traits::error::PeelerError::Malformed(_))
            | EngineError::Serialize(_)
            | EngineError::InvalidWelcome
            | EngineError::InvalidCredentialIdentity(_)
            | EngineError::InvalidAccountIdentityProof(_)
            | EngineError::MissingRequiredCapabilities { .. }
            | EngineError::NotGroupAdmin { .. }
            | EngineError::WelcomeAlreadyProcessed
    )
}

fn classify_openmls_welcome_error<StorageError: std::fmt::Debug>(
    error: WelcomeError<StorageError>,
) -> EngineError {
    match error {
        WelcomeError::StorageError(_)
        | WelcomeError::PublicGroupError(CreationFromExternalError::WriteToStorageError(_)) => {
            // OpenMLS storage errors are backend-specific and cannot be converted
            // into the Marmot storage error type generically. Keep them retryable
            // without leaking backend details into a user-visible error string.
            EngineError::Backend("OpenMLS Welcome storage failure".into())
        }
        _ => EngineError::InvalidWelcome,
    }
}

/// MLS exporter input for the Nostr kind-445 group-event encryption key:
/// `MLS-Exporter("marmot", "group-event", 32)`.
pub(crate) const EXPORTER_LABEL: &str = "marmot";
pub(crate) const EXPORTER_CONTEXT: &[u8] = b"group-event";
pub(crate) const ENCRYPTED_MEDIA_EXPORTER_CONTEXT: &[u8] = b"encrypted-media";
pub(crate) const AGENT_TEXT_STREAM_EXPORTER_CONTEXT: &[u8] = b"agent-text-stream-quic";

/// Key used in [`cgka_traits::group_context::GroupContextSnapshot`] so peelers
/// can request the registered group-event exporter without separately carrying
/// the MLS label/context pair.
pub(crate) const EXPORTER_SNAPSHOT_KEY: &str = "marmot/group-event";
pub(crate) const ENCRYPTED_MEDIA_EXPORTER_SNAPSHOT_KEY: &str =
    cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY;
pub(crate) const AGENT_TEXT_STREAM_EXPORTER_SNAPSHOT_KEY: &str =
    cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_EXPORTER_CACHE_KEY;

impl<S: StorageProvider> Engine<S> {
    /// Implementation of `CgkaEngine::create_group`.
    pub(crate) async fn do_create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> Result<(GroupId, SendResult), EngineError> {
        // 1. Validate invitees against required capabilities.
        let active_transports: [TransportKind; 0] = []; // engine-layer: no transports
        let (mut required_caps, _) = required_capabilities_extension_for_features(
            &self.registry,
            &active_transports,
            &req.required_features,
            self.new_protocol_profile,
        )?;
        let mut desired_components = AppComponentSet::from(default_group_components());
        for component_id in required_caps.app_components.ids.clone() {
            desired_components.insert(component_id);
        }
        for component in &req.app_components {
            required_caps.app_components.insert(component.component_id);
            desired_components.insert(component.component_id);
        }
        let mut self_supported_components = self.supported_app_components.clone();
        if self.new_protocol_profile == ProtocolProfile::Current {
            self_supported_components.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID);
        }
        let self_missing = required_caps
            .app_components
            .missing_from(&self_supported_components);
        if !self_missing.is_empty() {
            let had = GroupCapabilities {
                app_components: self_supported_components.clone(),
                ..GroupCapabilities::default()
            };
            return Err(EngineError::MissingRequiredCapabilities {
                required: Box::new(required_caps.clone()),
                had: Box::new(had),
            });
        }

        // Per-member role capabilities the agent-text-stream-QUIC component's
        // `required_member_roles` mask demands (#177,
        // agent-text-stream-quic-v1.md). These are enforced against every
        // invitee KeyPackage but are NOT folded into the group's
        // RequiredCapabilities — they are a component-driven per-member
        // advertisement requirement, not an MLS-level group requirement.
        let required_role_caps =
            crate::capability_manager::required_role_capabilities_from_request_components(
                &req.app_components,
            );

        let mut parsed_kps = Vec::with_capacity(req.members.len());
        let mut negotiated_components = desired_components.intersection(&self_supported_components);
        // Engine-owned components (profile + admin policy) are NON-NEGOTIABLE
        // (mdk#746).
        let mut mandatory_components = AppComponentSet::from(default_group_components());
        if self.new_protocol_profile == ProtocolProfile::Current {
            mandatory_components.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID);
        }
        for kp in &req.members {
            let parsed = self.parse_key_package(kp)?;
            if kp.protocol_profile != self.new_protocol_profile {
                return Err(EngineError::InvalidAccountIdentityProof(format!(
                    "cannot create a {:?} group from a {:?} KeyPackage",
                    self.new_protocol_profile, kp.protocol_profile
                )));
            }
            let had = capabilities_of_key_package(&parsed);
            let missing = required_caps.missing_from(&had);
            if !missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(required_caps.clone()),
                    had: Box::new(had),
                });
            }
            let role_missing = required_role_caps.missing_from(&had);
            if !role_missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(required_role_caps.clone()),
                    had: Box::new(had),
                });
            }
            // The per-invitee intersection below would otherwise let an invitee
            // whose leaf omits the profile/admin-policy component negotiate it
            // out. A group created without admin-policy bytes has an empty admin
            // set and frozen membership — every admin-gated operation (and every
            // later join) fails closed forever. Reject such an invitee up front,
            // exactly like a missing required capability; legitimate clients
            // always advertise these (mdk#746).
            let mandatory_missing = mandatory_components.missing_from(&had.app_components);
            if !mandatory_missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(GroupCapabilities {
                        app_components: mandatory_components.clone(),
                        ..GroupCapabilities::default()
                    }),
                    had: Box::new(had),
                });
            }
            negotiated_components = negotiated_components.intersection(&had.app_components);
            parsed_kps.push(parsed);
        }
        required_caps.app_components = negotiated_components;
        // Invariant check (mdk#746): the engine-owned components survived
        // negotiation. The per-invitee guard above is the real runtime gate (it
        // rejects any invitee lacking them in every build); this assertion just
        // documents the post-condition and, because `cargo test` builds with
        // debug assertions on, trips CI if a future negotiation refactor
        // reintroduces the drop despite the guard.
        debug_assert!(
            mandatory_components
                .missing_from(&required_caps.app_components)
                .is_empty(),
            "engine-owned components must not be negotiated out of a created group"
        );
        let required_caps_ext = extension_from_group_capabilities(&required_caps);

        // 2. Build the group config with leaf capabilities, MLS
        //    RequiredCapabilities, and Marmot app-component state.
        let leaf_caps =
            leaf_capabilities(&self.registry, self.ciphersuite, self.new_protocol_profile);
        debug_assert_eq!(
            self.identity.protocol_profile(),
            self.new_protocol_profile,
            "identity proof material must match the new-state profile"
        );
        let leaf_extensions = self
            .identity
            .leaf_extensions(&self.supported_app_components)?;

        // Validate the creator (implicit admin) on the SAME x-only secp256k1
        // basis as the co-admins below (mdk#737 review), so no admin-set entry
        // is accepted on length alone regardless of how the engine identity was
        // constructed.
        crate::identity::validate_credential_identity(self.identity.self_id().as_slice())?;
        let creator_pubkey =
            crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let mut admin_set: Vec<[u8; 32]> = vec![creator_pubkey];
        for extra in &req.initial_admins {
            // Validate each co-admin as a real x-only secp256k1 account key, not
            // just a 32-byte blob (mdk#737); `admin_pubkey_from_member_id` only
            // length-checks.
            crate::identity::validate_credential_identity(extra.as_slice())?;
            let pk = crate::app_components::admin_pubkey_from_member_id(extra)?;
            if !admin_set.contains(&pk) {
                admin_set.push(pk);
            }
        }
        let admin_set_for_coupling = admin_set.clone();

        let app_data_ext = crate::app_components::app_data_dictionary_extension_for_group(
            &required_caps.app_components,
            &crate::app_components::InitialComponentState {
                name: req.name.clone(),
                description: req.description.clone(),
                admins: admin_set,
                app_components: req.app_components.clone(),
            },
        )?;

        let gc_exts = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(required_caps_ext),
            app_data_ext,
        ])
        .map_err(|e| EngineError::Backend(format!("extensions: {e:?}")))?;

        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .capabilities(leaf_caps)
            .with_leaf_node_extensions(leaf_extensions)
            .map_err(|e| EngineError::Backend(format!("leaf extensions: {e:?}")))?
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(self.max_past_epochs)
            .with_group_context_extensions(gc_exts)
            .use_ratchet_tree_extension(true)
            .build();

        // `MlsGroup::new` persists the OpenMLS group as a sequence of value
        // writes. Keep that logical store in one backend transaction so a
        // crash or write fault cannot leave a partial, undiscoverable group.
        let mut mls_group = self.storage.with_transaction(|storage| {
            let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
            let group = MlsGroup::new(
                &provider,
                &self.identity.signer,
                &group_config,
                self.identity.credential_with_key.clone(),
            )
            .map_err(|e| EngineError::Backend(format!("group new: {e:?}")))?;
            crate::app_components::validate_current_profile_group_invariants(&group)?;
            Ok::<MlsGroup, EngineError>(group)
        })?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let group_id = GroupId::new(mls_group.group_id().as_slice().to_vec());

        // Admin-leaf coupling at creation (mdk#737): every admin key MUST
        // correspond to a member of the initial group (creator + invitees).
        // `req.initial_admins` is independent of `req.members`, so without this
        // a group could be created with a phantom/pre-provisioned admin that
        // becomes active the instant a matching leaf appears — with no
        // `AdminAdded` commit other members observe, bypassing the audit trail
        // every commit seam enforces. Runs the SAME coupling validator those
        // seams use, resolved against the PROJECTED initial member accounts (no
        // post-merge MlsGroup exists yet). Placed before `add_members` so an
        // invalid admin set produces no membership/commit side effects.
        let mut projected_member_accounts = std::collections::BTreeSet::new();
        projected_member_accounts.insert(creator_pubkey);
        for parsed in &parsed_kps {
            let member_id = member_id_of_key_package(parsed)?;
            projected_member_accounts.insert(crate::app_components::admin_pubkey_from_member_id(
                &member_id,
            )?);
        }
        crate::app_components::reject_admins_without_member_accounts(
            &admin_set_for_coupling,
            &projected_member_accounts,
            &group_id,
        )?;

        // 3. Add members to produce a staged commit + welcome (skipped for
        //    solo creation). Publish-before-apply keeps the staged commit
        //    attached to `mls_group`; merge happens in `do_confirm_published`.
        //    Welcome bytes are independently serializable from the OpenMLS
        //    return value; they do not require a merged group.
        let mut pending_commit_guard = None;
        let welcome_bytes: Option<Vec<u8>> = if parsed_kps.is_empty() {
            None
        } else {
            let (_commit_out, welcome_out, _group_info) = mls_group
                .add_members(&provider, &self.identity.signer, &parsed_kps)
                .map_err(|e| EngineError::Backend(format!("add_members: {e:?}")))?;
            pending_commit_guard = Some(PendingCommitCleanupGuard::arm(
                &self.storage,
                &provider,
                group_id.clone(),
            ));
            let own_leaf_index = mls_group.own_leaf_index();
            let staged = mls_group.pending_commit().ok_or_else(|| {
                EngineError::Backend("founding add produced no pending commit".into())
            })?;
            crate::app_components::validate_current_profile_invariants_for_staged_commit(
                &mls_group,
                staged,
                own_leaf_index,
            )?;
            crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
                staged,
                &mls_group,
                self.identity.self_id(),
                self.ciphersuite,
            )?;
            let bytes = welcome_out
                .tls_serialize_detached()
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
            Some(bytes)
        };

        // 4. Persist Marmot-side group record with the PROJECTED
        //    post-merge member set before recording outbound welcomes.
        //    SQLite enforces message/group foreign keys, so the group row
        //    must exist before `record_sent_message` writes welcome records.
        //
        //    The MLS group is still at epoch 0 pre-merge, but the `members`
        //    field surfaced via the `CgkaEngine::members` API and walked by
        //    `feature_status` needs to reflect "who the user thinks is in the
        //    group" — which includes invitees they just added. On
        //    `publish_failed` we re-derive from the (still-unmerged) MLS
        //    state, which naturally rolls the projection back.
        let projected_members = projected_members_with_pending(&mls_group, &parsed_kps)?;
        let group_record = Group {
            id: group_id.clone(),
            name: req.name.clone(),
            description: req.description.clone(),
            epoch: EpochId(mls_group.epoch().as_u64()),
            members: projected_members,
            required_capabilities: required_caps,
            protocol_profile: self.new_protocol_profile,
            removed: false,
            join_epoch: EpochId(mls_group.epoch().as_u64()),
        };
        self.storage.put_group(&group_record)?;
        // #740: index this group's transport routing id for O(1) inbound
        // resolution (see `Engine::transport_group_id_index`). Best-effort: a
        // routing-read failure only forfeits the fast path (inbound would fall
        // through to the unknown-group disposition), never fails creation.
        if let Ok(transport_group_id) =
            crate::app_components::transport_group_id_of_group(&mls_group)
        {
            self.transport_group_id_index
                .insert(transport_group_id, group_id.clone());
        }

        // 5. Wrap welcomes via the peeler.
        //
        // Note: we intentionally do NOT emit the commit. The creator is the
        // only party who'd care about the "commit that creates the group at
        // epoch 1," and once they confirm publish they'll merge it locally.
        // Every other member lands in the group via `welcomes`, which carry
        // the post-commit state directly. Dropping the commit avoids a
        // welcome-before-commit `AlreadyAtEpoch` bounce.
        //
        // The context snapshot is built off the still-staged group; for
        // welcomes, only the recipient pubkey matters at wrap time, so the
        // pre-merge group context is sufficient.
        let ctx = build_group_context_snapshot(&mls_group, &provider)?;
        let welcome_relays = welcome_relays_for_group(&mls_group)?;

        let mut welcomes = Vec::with_capacity(parsed_kps.len());
        if let Some(welcome_bytes) = &welcome_bytes {
            for (source_kp, parsed_kp) in req.members.iter().zip(parsed_kps.iter()) {
                let recipient = member_id_of_key_package(parsed_kp)?;
                let payload = EncryptedPayload {
                    ciphertext: welcome_bytes.clone(),
                    aad: vec![],
                };
                let wrapped = if let Some(metadata) =
                    welcome_metadata_for_key_package(source_kp, welcome_relays.as_deref())?
                {
                    self.peeler
                        .wrap_welcome_with_metadata(&payload, &recipient, &metadata)
                        .await
                } else {
                    self.peeler.wrap_welcome(&payload, &recipient).await
                }
                .map_err(EngineError::Peeler)?;
                self.record_sent_message(&wrapped, &group_id, EpochId(0))?;
                welcomes.push(wrapped);
            }
        }

        crate::capability_manager::cache_from_key_packages(&self.storage, &group_id, &parsed_kps)?;
        crate::capability_manager::cache_self_capabilities(
            &self.storage,
            &group_id,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;

        // 7. Enter PendingPublish — the caller must confirm_published once
        //    the transport hands off every welcome. The visible epoch
        //    becomes the projected post-merge epoch. For multi-member
        //    create that's epoch 1 (the staged commit's target); for solo
        //    create it stays 0 (no commit was staged). Tagged
        //    `PendingKind::CreateGroup` so confirm emits `GroupCreated`.
        let projected_epoch = if welcome_bytes.is_some() {
            // Multi-member: the pending commit advances to epoch 1.
            EpochId(1)
        } else {
            EpochId(0)
        };
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged =
            cgka_traits::engine_state::StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            EpochId(0),
            projected_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::CreateGroup,
            self.current_audit_context.clone(),
        )?;
        self.audit_group(
            &group_id,
            crate::audit_helpers::epoch_state_changed_event(
                Some("stable"),
                "pending_publish",
                projected_epoch,
                "begin_pending",
                Some(pending_ref),
                Some(crate::audit_helpers::pending_kind_str(
                    crate::epoch_manager::PendingKind::CreateGroup,
                )),
            ),
        );

        if let Some(guard) = pending_commit_guard {
            guard.disarm();
        }

        let _ = ctx;

        Ok((
            group_id,
            SendResult::GroupCreated {
                welcomes,
                pending: pending_ref,
            },
        ))
    }

    /// Real implementation of `CgkaEngine::join_welcome`.
    ///
    /// Flow:
    /// 1. Dedupe against prior ingest of this welcome
    /// 2. Verify the welcome envelope targets this client
    /// 3. Peel via `TransportPeeler::peel_welcome`
    /// 4. Deserialize the inner MLS Welcome
    /// 5. Stage the welcome into an `MlsGroup` (ratchet tree is embedded)
    /// 6. Persist the Marmot `Group` record
    /// 7. Initialize `EpochState::Stable` at the post-welcome epoch
    /// 8. Persist durable duplicate detection state
    /// 9. Emit `GroupEvent::GroupJoined`
    pub(crate) async fn do_join_welcome(
        &mut self,
        welcome_msg: TransportMessage,
    ) -> Result<GroupId, EngineError> {
        // 1. Dedupe. The ingest-path welcome handler already guards with
        // `seen_message_ids`; direct `CgkaEngine::join_welcome` callers
        // skipped that. Without this check, a re-call would re-stage a
        // Welcome on top of an existing group, which is unsafe.
        if self.seen_message_ids.contains(&welcome_msg.id) {
            return Err(EngineError::WelcomeAlreadyProcessed);
        }
        if let Ok(record) = self.storage.get_message(&welcome_msg.id)
            && matches!(
                record.state,
                cgka_traits::message::MessageState::Processed
                    | cgka_traits::message::MessageState::Failed
                    | cgka_traits::message::MessageState::EpochInvalidated
            )
        {
            return Err(EngineError::WelcomeAlreadyProcessed);
        }

        // 2. Envelope check.
        match &welcome_msg.envelope {
            TransportEnvelope::Welcome { recipient } => {
                if recipient != self.identity.self_id() {
                    return Err(EngineError::Peeler(
                        cgka_traits::error::PeelerError::Malformed(
                            "welcome not addressed to this client".into(),
                        ),
                    ));
                }
            }
            _ => {
                return Err(EngineError::Peeler(
                    cgka_traits::error::PeelerError::Malformed("expected Welcome envelope".into()),
                ));
            }
        }
        let welcome_id = welcome_msg.id.clone();

        // 3. Peel.
        let peeled = self
            .peeler
            .peel_welcome(&welcome_msg)
            .await
            .map_err(EngineError::Peeler)?;
        let content_id = welcome_content_dedup_id(&peeled)?;
        if self.storage.has_ingress_dedup_marker(&content_id)? {
            self.storage.put_ingress_dedup_marker(&welcome_id)?;
            return Err(EngineError::WelcomeAlreadyProcessed);
        }

        let result = self
            .do_join_peeled_welcome(welcome_msg, peeled, content_id.clone())
            .await;
        match &result {
            Ok(_) => {}
            Err(error) if terminal_welcome_error(error) => {
                self.storage.with_transaction(|storage| {
                    storage.put_ingress_dedup_marker(&welcome_id)?;
                    storage.put_ingress_dedup_marker(&content_id)?;
                    Ok::<_, EngineError>(())
                })?;
            }
            Err(_) => {}
        }
        result
    }

    pub(crate) async fn do_join_peeled_welcome(
        &mut self,
        welcome_msg: TransportMessage,
        peeled: cgka_traits::ingest::PeeledMessage,
        content_id: MessageId,
    ) -> Result<GroupId, EngineError> {
        let welcome_id = welcome_msg.id.clone();
        let welcome_bytes = match peeled.content {
            cgka_traits::ingest::PeeledContent::Welcome { bytes } => bytes,
            _ => {
                return Err(EngineError::Peeler(
                    cgka_traits::error::PeelerError::Malformed(
                        "peeled content was not a Welcome".into(),
                    ),
                ));
            }
        };

        // 4. Deserialize.
        let msg_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes.as_slice())
            .map_err(|e| EngineError::Serialize(format!("welcome deserialize: {e:?}")))?;
        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => {
                return Err(EngineError::Serialize(
                    "MLS message did not carry a Welcome".into(),
                ));
            }
        };

        // 5. Stage + land.
        //
        // Use the two-step OpenMLS welcome API so we can read the target group
        // id and clear stale local OpenMLS state BEFORE the join is staged.
        // `ProcessedWelcome::new_from_welcome` decrypts the GroupInfo and
        // consumes the KeyPackage init key material. It therefore belongs in
        // the same transaction as every later join write: a rejected or
        // backend-failed attempt must restore the KeyPackage so the identical
        // Welcome remains retryable.
        // If leftover live OpenMLS state survives for this group id (a re-add
        // after a prior removal, or state that outlived a missed removal commit
        // / restart) AND we are not currently an active member, clear ONLY that
        // live OpenMLS group first: otherwise `into_staged_welcome` fails with
        // `GroupAlreadyExists`, and even if it didn't the re-join would stack on
        // stale epoch keypairs / message-secrets / own-leaf index
        // (mdk#557).
        //
        // The clear is scoped to the live OpenMLS rows only: it does NOT delete
        // the Marmot record, retained-anchor snapshots, stored message history,
        // or convergence policy. Removal itself leaves all of that intact (the
        // removed member keeps a tombstoned read-only view and the engine keeps
        // the retained material a late winning branch needs to roll back a
        // losing removal branch within `max_rewind_commits`); the stale live
        // group is cleared lazily here, only at the moment a re-add arrives, and
        // only for the group being re-joined. We never clear a group we are
        // still an active member of.
        let join_config = join_config(self.max_past_epochs);
        // Building a group from a staged Welcome performs the same multi-row
        // OpenMLS store as group creation. Keep KeyPackage consumption, stale
        // live-state clearing, that store, every Marmot post-check, the
        // discoverable group record, capability cache, and both durable
        // Welcome dispositions in one transaction.
        let (group_id, mls_group, welcome_sender_id) =
            self.storage.with_transaction(|storage| {
                let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, storage.mls_storage());
                let processed = openmls::group::ProcessedWelcome::new_from_welcome(
                    &provider,
                    &join_config,
                    welcome,
                )
                .map_err(classify_openmls_welcome_error)?;
                let group_id = GroupId::new(
                    processed
                        .unverified_group_info()
                        .group_id()
                        .as_slice()
                        .to_vec(),
                );

                let local_state_is_stale = match storage.get_group(&group_id) {
                    Ok(group) => !group
                        .members
                        .iter()
                        .any(|member| &member.id == self.identity.self_id()),
                    Err(cgka_traits::storage::StorageError::NotFound) => false,
                    Err(error) => return Err(EngineError::Storage(error)),
                };
                if local_state_is_stale {
                    self.clear_live_openmls_group_on_storage(storage, &group_id)?;
                }

                let staged = processed
                    .into_staged_welcome(&provider, None)
                    .map_err(classify_openmls_welcome_error)?;
                let welcome_sender = staged
                    .welcome_sender()
                    .map_err(|_| EngineError::InvalidWelcome)?;
                let welcome_sender_id =
                    crate::identity::validated_member_id_of_leaf(welcome_sender)?;
                let mls_group = staged
                    .into_group(&provider)
                    .map_err(classify_openmls_welcome_error)?;

                debug_assert_eq!(
                    group_id,
                    GroupId::new(mls_group.group_id().as_slice().to_vec())
                );

                // 5b. Reject the Welcome if any member leaf carries an invalid
                // Marmot credential identity (foundation/identity.md,
                // joining.md:65).
                let protocol_profile =
                    validate_member_credentials_and_account_proofs(&mls_group, self.ciphersuite)?;
                crate::app_components::validate_current_profile_group_invariants(&mls_group)
                    .map_err(|_| EngineError::InvalidWelcome)?;

                // 5c. Reject active required capabilities this client cannot
                // apply, including required agent-stream roles.
                let mut group_required =
                    crate::capability_manager::required_capabilities_from_group(&mls_group);
                crate::message_processor::merge_capabilities(
                    &mut group_required,
                    &crate::capability_manager::required_role_capabilities_from_group(&mls_group),
                );
                let had = crate::capabilities::self_supported_capabilities(
                    &self.registry,
                    self.ciphersuite,
                    &self.supported_app_components,
                );
                let missing = group_required.missing_from(&had);
                if !missing.is_empty() {
                    return Err(EngineError::MissingRequiredCapabilities {
                        required: Box::new(group_required),
                        had: Box::new(had),
                    });
                }

                // 5d. The authenticated Welcome sender must be an admin.
                crate::app_components::require_admin(&mls_group, &group_id, &welcome_sender_id)?;

                // 5e. Every advertised admin must have a current member leaf.
                crate::app_components::reject_admins_without_member_leaf(
                    &mls_group,
                    &group_id,
                    &crate::app_components::admins_of_group(&mls_group)?,
                )
                .map_err(|error| match error {
                    storage @ EngineError::Storage(_) => storage,
                    _ => EngineError::InvalidWelcome,
                })?;

                // 6. Make the committed OpenMLS group discoverable through the
                // Marmot record and cache this device's capabilities.
                let mut group_record = Group {
                    id: group_id.clone(),
                    name: String::new(),
                    description: String::new(),
                    epoch: EpochId(mls_group.epoch().as_u64()),
                    members: marmot_members(&mls_group),
                    required_capabilities:
                        crate::capability_manager::required_capabilities_from_group(&mls_group),
                    protocol_profile,
                    removed: false,
                    join_epoch: EpochId(mls_group.epoch().as_u64()),
                };
                mirror_app_components_into_record(&mls_group, &mut group_record);
                storage.put_group(&group_record)?;
                crate::capability_manager::cache_self_capabilities(
                    storage,
                    &group_id,
                    &mls_group,
                    self.identity.self_id(),
                    self.ciphersuite,
                )?;

                // Direct join callers need the same durable dedup disposition as
                // the transport-ingest path.
                let payload = StoredMessagePayload::raw_transport(welcome_msg)
                    .encode()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
                storage.put_message(&MessageRecord {
                    id: welcome_id.clone(),
                    group_id: group_id.clone(),
                    epoch: EpochId(mls_group.epoch().as_u64()),
                    state: MessageState::Processed,
                    payload,
                })?;
                storage.put_ingress_dedup_marker(&welcome_id)?;
                storage.put_ingress_dedup_marker(&content_id)?;

                Ok::<_, EngineError>((group_id, mls_group, welcome_sender_id))
            })?;

        // #740: index this joined group's transport routing id for O(1) inbound
        // resolution (see `Engine::transport_group_id_index`).
        if let Ok(transport_group_id) =
            crate::app_components::transport_group_id_of_group(&mls_group)
        {
            self.transport_group_id_index
                .insert(transport_group_id, group_id.clone());
        }

        // 7. State machine: Stable at the post-welcome epoch.
        let joined_epoch = EpochId(mls_group.epoch().as_u64());
        self.epoch_manager
            .set_stable(group_id.clone(), joined_epoch);
        self.audit_group(
            &group_id,
            crate::audit_helpers::epoch_state_changed_event(
                None,
                "stable",
                joined_epoch,
                "join_welcome",
                None,
                None,
            ),
        );
        self.audit_group_context(&group_id, "join_welcome");

        // 9. Emit event + register for in-process dedup.
        self.events_buf
            .push_back(cgka_traits::engine::GroupEvent::GroupJoined {
                group_id: group_id.clone(),
                via_welcome: welcome_id.clone(),
                welcomer: Some(welcome_sender_id.clone()),
            });
        if let Some(new_seconds) =
            crate::app_components::message_retention_seconds_of_group(&mls_group)?
        {
            self.events_buf
                .push_back(cgka_traits::engine::GroupEvent::GroupStateChanged {
                    group_id: group_id.clone(),
                    epoch: EpochId(mls_group.epoch().as_u64()),
                    actor: Some(welcome_sender_id),
                    change: cgka_traits::engine::GroupStateChange::MessageRetentionChanged {
                        old_seconds: 0,
                        new_seconds,
                    },
                    origin_commit_id: None,
                });
        }
        self.seen_message_ids.insert(welcome_id);

        // An authenticated welcome re-validated every leaf and wrote fresh
        // group state — strictly stronger evidence of health than
        // `retry_hydrate_quarantined_group` re-reading stored state. Clear a
        // hydration quarantine for this id so the map cannot go stale against
        // the now-live group (and so an unrepairable group can always be
        // recovered by re-invite). The buffered-message replay below picks up
        // any input retained while quarantined.
        if self.quarantined_groups.remove(&group_id).is_some() {
            let recovered_epoch = EpochId(mls_group.epoch().as_u64());
            tracing::info!(
                target: "cgka_engine::hydrate",
                method = "do_join_welcome",
                outcome = "recovered_via_rejoin",
                "authenticated re-join welcome cleared a hydration quarantine"
            );
            self.audit(AuditEventKind::GroupHydrationRecovered {
                group_digest: crate::engine::hydration_quarantine_group_digest(&group_id),
            });
            self.events_buf
                .push_back(cgka_traits::engine::GroupEvent::GroupHydrationRecovered {
                    group_id: group_id.clone(),
                    recovered_epoch,
                });
        }

        self.replay_buffered_messages(&group_id).await?;
        Ok(group_id)
    }

    pub(crate) fn do_members(&self, group_id: &GroupId) -> Result<Vec<Member>, EngineError> {
        // Source of truth: the Marmot record's `members` list. The send
        // paths write the projected post-merge member set there; confirm
        // and publish_failed re-derive from MLS state. Reading from
        // Marmot keeps `members()` consistent with the engine's reported
        // `EpochState` even during `PendingPublish`.
        let group = self.storage.get_group(group_id)?;
        Ok(group.members)
    }

    pub(crate) fn do_own_leaf_index(&self, group_id: &GroupId) -> Result<u32, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        Ok(mls_group.own_leaf_index().u32())
    }

    /// `constructable_capabilities` implementation.
    pub(crate) fn do_constructable_capabilities(
        &self,
        key_packages: &[cgka_traits::engine::KeyPackage],
    ) -> Result<GroupCapabilities, EngineError> {
        if key_packages.is_empty() {
            return Ok(leaf_capabilities_as_marmot(
                &self.registry,
                self.ciphersuite,
                &self.supported_app_components,
                self.new_protocol_profile,
            ));
        }
        let mut it = key_packages.iter();
        let first_input = it.next().unwrap();
        let first_profile = first_input.protocol_profile;
        let first = self.parse_key_package(first_input)?;
        let mut acc = capabilities_of_key_package(&first);
        for kp in it {
            let parsed = self.parse_key_package(kp)?;
            if kp.protocol_profile != first_profile {
                return Err(EngineError::InvalidAccountIdentityProof(
                    "cannot compute constructable capabilities across mixed-profile KeyPackages"
                        .into(),
                ));
            }
            let other = capabilities_of_key_package(&parsed);
            acc = GroupCapabilities {
                proposals: acc
                    .proposals
                    .intersection(&other.proposals)
                    .copied()
                    .collect(),
                extensions: acc
                    .extensions
                    .intersection(&other.extensions)
                    .copied()
                    .collect(),
                app_components: acc.app_components.intersection(&other.app_components),
            };
        }
        Ok(acc)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn member_id_of_key_package(kp: &openmls::prelude::KeyPackage) -> Result<MemberId, EngineError> {
    crate::identity::validated_member_id_of_leaf(kp.leaf_node())
}

pub(crate) fn welcome_relays_for_group(
    group: &MlsGroup,
) -> Result<Option<Vec<TransportEndpoint>>, EngineError> {
    Ok(
        crate::app_components::nostr_routing_of_group(group)?.map(|routing| {
            routing
                .relays
                .into_iter()
                .map(TransportEndpoint)
                .collect::<Vec<_>>()
        }),
    )
}

pub(crate) fn welcome_metadata_for_key_package(
    key_package: &KeyPackage,
    relays: Option<&[TransportEndpoint]>,
) -> Result<Option<WelcomeMetadata>, EngineError> {
    let Some(relays) = relays else {
        return Ok(None);
    };
    let Some(source) = &key_package.source else {
        return Ok(None);
    };
    Ok(Some(WelcomeMetadata {
        key_package_event_id: source.event_id.clone(),
        relays: relays.to_vec(),
    }))
}

/// Build the projected post-merge member list: existing MLS members + each
/// invitee whose KeyPackage is being added by the staged commit. Used by
/// the send paths so `members()` and `feature_status` reflect the user's
/// intended state during `PendingPublish`. On rollback, the engine simply
/// calls `marmot_members(&mls_group)` against the still-unmerged group to
/// discard the projection.
pub(crate) fn projected_members_with_pending(
    group: &MlsGroup,
    invitees: &[openmls::prelude::KeyPackage],
) -> Result<Vec<Member>, EngineError> {
    let mut out = marmot_members(group);
    for kp in invitees {
        let id = crate::identity::validated_member_id_of_leaf(kp.leaf_node())?;
        if !out.iter().any(|m| m.id == id) {
            out.push(Member {
                id,
                credential: kp.leaf_node().signature_key().as_slice().to_vec(),
            });
        }
    }
    Ok(out)
}

/// Validate the Marmot credential identity of every member leaf in `group`.
///
/// Used at join ingress (`do_join_welcome`) so a Welcome whose resulting group
/// contains any member with an invalid x-only secp256k1 credential identity is
/// rejected before the group is persisted. Returns the offending member's
/// error on the first invalid credential.
pub(crate) fn validate_member_credentials(group: &MlsGroup) -> Result<(), EngineError> {
    for member in group.members() {
        crate::identity::validated_member_id(&member.credential)?;
    }
    Ok(())
}

/// Validate every Marmot member identity and the account-key proof attached to
/// each LeafNode in the exported MLS ratchet tree.
///
/// This is the cold-path full validation: it runs one BIP-340 schnorr
/// verification per leaf. Session open ([`Engine::hydrate_one_stored_group`])
/// gates it behind [`compute_validated_tree_marker`] so an unchanged group's
/// already-validated tree is not re-verified on every open.
pub(crate) fn validate_member_credentials_and_account_proofs(
    group: &MlsGroup,
    ciphersuite: Ciphersuite,
) -> Result<ProtocolProfile, EngineError> {
    validate_member_credentials(group)?;
    let protocol_profile = crate::account_identity_proof::protocol_profile_of_group(group)?;
    let nodes = crate::app_components::ratchet_tree_nodes(group.export_ratchet_tree())?;
    for node in nodes {
        if let Some(Node::LeafNode(leaf)) = node {
            let leaf_profile = crate::account_identity_proof::validate_leaf_account_identity_proof(
                &leaf,
                ciphersuite,
            )?;
            if leaf_profile != protocol_profile {
                return Err(EngineError::InvalidAccountIdentityProof(format!(
                    "group contains a {leaf_profile:?} leaf in a {protocol_profile:?} profile"
                )));
            }
        }
    }
    Ok(protocol_profile)
}

/// Bumped whenever the member-credential / account-identity-proof validation
/// logic changes. A bump makes every previously stored marker mismatch, so a
/// group's tree is fully re-validated under the new rules on the next open.
const VALIDATED_TREE_MARKER_VERSION: u8 = 2;

/// Derive a cheap, content-bound marker certifying a specific ratchet-tree
/// state passed [`validate_member_credentials_and_account_proofs`].
///
/// The marker is `SHA-256(version || ciphersuite || TLS(exported ratchet
/// tree))`. It is bound to the exact bytes the validator reads, so any change
/// to membership, a leaf node, or an account-identity-proof extension yields a
/// different marker. This is deliberately *not* the OpenMLS `tree_hash` or
/// `epoch_authenticator`: the former is `pub(crate)` and the latter is a
/// derived secret that is not bound to the stored leaf bytes the proof
/// validation actually inspects, so neither would detect tampering of the
/// stored tree the way a hash over the exported bytes does.
///
/// Computing the marker is O(tree size) serialization + one hash — no schnorr
/// verification — so doing it per group on every open is far cheaper than the
/// per-leaf BIP-340 verification it lets unchanged groups skip.
pub(crate) fn compute_validated_tree_marker(
    group: &MlsGroup,
    ciphersuite: Ciphersuite,
) -> Result<Vec<u8>, EngineError> {
    let tree = group.export_ratchet_tree();
    let tree_bytes = tree
        .tls_serialize_detached()
        .map_err(|e| EngineError::Backend(format!("serialize ratchet tree: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update([VALIDATED_TREE_MARKER_VERSION]);
    hasher.update(u16::from(ciphersuite).to_be_bytes());
    hasher.update(&tree_bytes);
    Ok(hasher.finalize().to_vec())
}

pub(crate) fn marmot_members(group: &MlsGroup) -> Vec<Member> {
    group
        .members()
        .filter_map(|m| {
            let basic = BasicCredential::try_from(m.credential).ok()?;
            let id = basic.identity().to_vec();
            Some(Member {
                id: MemberId::new(id),
                credential: m.signature_key.to_vec(),
            })
        })
        .collect()
}

fn leaf_capabilities_as_marmot(
    registry: &crate::feature_registry::FeatureRegistry,
    _cs: openmls_traits::types::Ciphersuite,
    supported_app_components: &cgka_traits::app_components::AppComponentSet,
    protocol_profile: ProtocolProfile,
) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for (_f, req) in registry.iter() {
        out.insert(req.requires);
    }
    out.app_components = supported_app_components.clone();
    match protocol_profile {
        ProtocolProfile::Legacy => out.insert(cgka_traits::capabilities::Capability::Extension(
            crate::account_identity_proof::ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE,
        )),
        ProtocolProfile::Current => out
            .app_components
            .insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID),
    }
    out
}

pub(crate) fn build_group_context_snapshot<S: StorageProvider>(
    mls_group: &MlsGroup,
    provider: &EngineOpenMlsProvider<'_, S>,
) -> Result<cgka_traits::group_context::GroupContextSnapshot, EngineError> {
    let secret = mls_group
        .export_secret(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(provider),
            EXPORTER_LABEL,
            EXPORTER_CONTEXT,
            32,
        )
        .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
    let mut map = std::collections::HashMap::new();
    map.insert(EXPORTER_SNAPSHOT_KEY.to_string(), secret);
    Ok(cgka_traits::group_context::GroupContextSnapshot::new(
        EpochId(mls_group.epoch().as_u64()),
        map,
        Some(crate::app_components::transport_group_id_of_group(
            mls_group,
        )?),
    ))
}

/// Mirror signed app-component state into the local app-facing group record.
/// Missing profile state leaves the record's existing values unchanged.
pub(crate) fn mirror_app_components_into_record(
    mls_group: &MlsGroup,
    record: &mut cgka_traits::group::Group,
) {
    if let Ok(Some((name, description))) = crate::app_components::group_profile_of_group(mls_group)
    {
        record.name = name;
        record.description = description;
    }
    if let Ok(components) = crate::app_components::required_app_components_of_group(mls_group) {
        record.required_capabilities.app_components = components;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openmls_welcome_storage_errors_remain_retryable() {
        let direct = classify_openmls_welcome_error(WelcomeError::StorageError("busy"));
        assert!(matches!(direct, EngineError::Backend(_)));
        assert!(!terminal_welcome_error(&direct));

        let nested = classify_openmls_welcome_error(WelcomeError::PublicGroupError(
            CreationFromExternalError::WriteToStorageError("busy"),
        ));
        assert!(matches!(nested, EngineError::Backend(_)));
        assert!(!terminal_welcome_error(&nested));
    }

    #[test]
    fn invalid_openmls_welcome_errors_remain_terminal() {
        let invalid = classify_openmls_welcome_error(WelcomeError::<&str>::UnableToDecrypt);
        assert!(matches!(invalid, EngineError::InvalidWelcome));
        assert!(terminal_welcome_error(&invalid));
    }
}
