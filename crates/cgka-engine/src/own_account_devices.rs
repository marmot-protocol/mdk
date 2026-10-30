//! Same-account Adds and Removes for `SendIntent::AddOwnAccountDevices` and
//! `SendIntent::RemoveOwnAccountDevices` (account-devices-v1.md,
//! "Same-account operations"; mdk#2628 item 2.1e).
//!
//! In a group that requires `marmot.group.account-devices.v1`, a device adds
//! KeyPackages of its own account, or removes other leaves of its account,
//! without admin authority. The Commit carries every proposal by value and
//! nothing else. Its builder never reads the proposal store, so proposals
//! pending in the group stay pending: OpenMLS's own Add and Remove would
//! commit them by reference, which no same-account Commit may do.
//!
//! The checks before staging only name the reason for a refusal. The decision
//! is [`crate::commit_class`]'s, on the parent state replay reads: a Commit it
//! does not call same-account is refused before anything is recorded or
//! published, whoever commits it. An admin gets the same answer, and so does
//! every committer in a group that does not require the component.
//!
//! Each added device gets its Welcome the way an Invite's devices do: one
//! delivery per KeyPackage, naming it ([`Engine::wrap_staged_welcomes`]).
//! Like a self-update, neither intent keeps an `OwnCommitIntent`: when branch
//! selection supersedes one, nothing re-issues it (mdk#1734).
//!
//! Source-bound rejoin shares the by-value member-edit builder below. Its
//! source checks and durable publish lifecycle remain in maintenance/send;
//! the same staged classifier authorizes the resulting atomic Remove+Add.

use crate::commit_class::CommitClass;
use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::{KeyPackage, SendResult};
use cgka_traits::engine_state::{EpochState, InvalidTransition, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::EncryptedPayload;
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls::prelude::{LeafNodeIndex, MlsMessageOut};
use openmls_traits::OpenMlsProvider as _;
use std::collections::HashSet;
use tls_codec::Serialize as _;

const ADD: &str = "AddOwnAccountDevices";
const REMOVE: &str = "RemoveOwnAccountDevices";

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_add_own_account_devices(
        &mut self,
        group_id: GroupId,
        key_packages: Vec<KeyPackage>,
    ) -> Result<SendResult, EngineError> {
        if key_packages.is_empty() {
            return Err(EngineError::Other(
                "adding own account devices requires at least one KeyPackage".into(),
            ));
        }
        self.do_send_own_account_devices(group_id, key_packages, Vec::new(), ADD)
            .await
    }

    pub(crate) async fn do_send_remove_own_account_devices(
        &mut self,
        group_id: GroupId,
        leaf_signature_keys: Vec<Vec<u8>>,
    ) -> Result<SendResult, EngineError> {
        let mut seen = HashSet::new();
        let leaf_signature_keys: Vec<_> = leaf_signature_keys
            .into_iter()
            .filter(|key| seen.insert(key.clone()))
            .collect();
        if leaf_signature_keys.is_empty() {
            return Err(EngineError::Other(
                "removing own account devices requires at least one device".into(),
            ));
        }
        self.do_send_own_account_devices(group_id, Vec::new(), leaf_signature_keys, REMOVE)
            .await
    }

    async fn do_send_own_account_devices(
        &mut self,
        group_id: GroupId,
        key_packages: Vec<KeyPackage>,
        leaf_signature_keys: Vec<Vec<u8>>,
        intent: &'static str,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut mls_group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(InvalidTransition {
                from: state.name(),
                to: intent,
                reason: "same-account commit requires Stable",
            }));
        }
        // account-devices-v1.md, "Sender rules": same-account operations need
        // a canonical state that requires the component. A legacy group never
        // does.
        if crate::commit_class::classify_member_edit(
            &mls_group,
            self.identity.self_id(),
            self.identity.self_id(),
        )? != CommitClass::SameAccount
        {
            return Err(EngineError::InvalidTransition(InvalidTransition {
                from: "AccountDevicesNotRequired",
                to: intent,
                reason: "the group does not require marmot.group.account-devices.v1",
            }));
        }
        let account = crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let existing = self.storage.get_group(&group_id)?;
        let parsed_kps =
            self.own_account_key_packages(&mls_group, &existing, &key_packages, &account)?;
        let removed_leaves = own_account_leaves(&mls_group, &leaf_signature_keys, &account)?;

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let (commit_out, welcome_out) =
            self.stage_member_edits(&mut mls_group, &provider, &parsed_kps, &removed_leaves)?;
        let staged_commit = mls_group.pending_commit().ok_or_else(|| {
            EngineError::Backend("own account devices produced no pending commit".into())
        })?;
        let class = crate::commit_class::authorize_own_staged_commit(
            &mls_group,
            &group_id,
            self.identity.self_id(),
            staged_commit,
        )?;
        if class != CommitClass::SameAccount {
            return Err(EngineError::InvalidTransition(InvalidTransition {
                from: "NotSameAccount",
                to: intent,
                reason: "the commit is not a same-account commit",
            }));
        }
        crate::app_components::validate_admin_leaf_coupling_for_staged_commit(
            &mls_group,
            &group_id,
            staged_commit,
        )?;
        crate::app_components::validate_app_component_integrity_for_staged_commit(
            &mls_group,
            &group_id,
            staged_commit,
        )?;
        crate::account_identity_proof::validate_staged_commit_account_identity_proofs(
            staged_commit,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            &mls_group,
            staged_commit,
            mls_group.own_leaf_index(),
        )?;
        crate::capability_manager::check_key_package_profiles(
            &self.storage,
            &group_id,
            &parsed_kps,
        )?;

        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let welcome_bytes = match welcome_out {
            Some(welcome) if !parsed_kps.is_empty() => Some(
                welcome
                    .tls_serialize_detached()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?,
            ),
            None if parsed_kps.is_empty() => None,
            _ => {
                return Err(EngineError::Backend(
                    "own account devices Welcome does not match its Adds".into(),
                ));
            }
        };
        let commit_msg = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: vec![],
                },
                &pre_commit_ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let commit_msg =
            crate::message_processor::route_wrapped_group_message(commit_msg, &pre_commit_ctx);
        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;
        let welcomes = match welcome_bytes {
            Some(welcome_bytes) => {
                self.wrap_staged_welcomes(
                    &mls_group,
                    &group_id,
                    &commit_msg.id,
                    pre_commit_epoch,
                    &welcome_bytes,
                    &key_packages,
                    &[],
                    &parsed_kps,
                    None,
                )
                .await?
            }
            None => Vec::new(),
        };

        // `members()` shows the requested leaves while the publish is
        // pending; `confirm_published` and `publish_failed` re-derive the
        // record from MLS state. Every added leaf shares an account with a
        // current one, so the projection goes by leaf, never by account.
        let mut group_record = existing;
        group_record.members = crate::group_lifecycle::marmot_members(&mls_group);
        group_record
            .members
            .retain(|member| !leaf_signature_keys.contains(&member.credential));
        for kp in &parsed_kps {
            group_record.members.push(cgka_traits::group::Member {
                id: crate::identity::validated_member_id_of_leaf(kp.leaf_node())?,
                credential: kp.leaf_node().signature_key().as_slice().to_vec(),
            });
        }
        self.storage.put_group(&group_record)?;

        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
        let pending_ref = self.epoch_manager.next_pending_ref();
        self.invalidate_deferred_peel_candidate_cache(&group_id);
        self.epoch_manager.begin_pending(
            group_id.clone(),
            pre_commit_epoch,
            new_epoch,
            StagedCommitHandle::from_bytes(group_id.as_slice().to_vec()),
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        self.audit_group(
            &group_id,
            crate::audit_helpers::epoch_state_changed_event(
                Some("stable"),
                "pending_publish",
                new_epoch,
                "begin_pending",
                Some(pending_ref),
                Some(crate::audit_helpers::pending_kind_str(
                    crate::epoch_manager::PendingKind::GroupEvolution,
                )),
            ),
        );
        self.track_pending_origin_commit(pending_ref, commit_msg.id.clone());
        pending_commit_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: commit_msg,
            welcomes,
            pending: pending_ref,
        })
    }

    /// Stage only the requested by-value Adds/Removes, leaving the proposal
    /// store untouched. Callers authorize the complete staged Commit before
    /// exposing it; this primitive grants no membership authority itself.
    pub(crate) fn stage_member_edits(
        &self,
        group: &mut MlsGroup,
        provider: &EngineOpenMlsProvider<'_, S>,
        adds: &[openmls::prelude::KeyPackage],
        removals: &[LeafNodeIndex],
    ) -> Result<(MlsMessageOut, Option<MlsMessageOut>), EngineError> {
        let leaf_node_parameters = self.own_commit_leaf_parameters(group, &[])?;
        let (commit, welcome, _group_info) = group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds(adds.iter().cloned())
            .propose_removals(removals.iter().copied())
            .leaf_node_parameters(leaf_node_parameters)
            .load_psks(provider.storage())
            .map_err(|e| EngineError::Backend(format!("member edits load_psks: {e:?}")))?
            .build(
                provider.rand(),
                provider.crypto(),
                &self.identity.signer,
                |_| true,
            )
            .map_err(|e| EngineError::Backend(format!("member edits build: {e:?}")))?
            .stage_commit(provider)
            .map_err(|e| EngineError::Backend(format!("member edits stage: {e:?}")))?
            .into_messages();
        Ok((commit, welcome))
    }

    /// Parse `key_packages` for a same-account Add: each belongs to
    /// `account` and advertises everything the group requires, as an Invite's
    /// KeyPackages must (key-packages.md, "Capability advertising").
    fn own_account_key_packages(
        &self,
        mls_group: &MlsGroup,
        existing: &cgka_traits::group::Group,
        key_packages: &[KeyPackage],
        account: &[u8; 32],
    ) -> Result<Vec<openmls::prelude::KeyPackage>, EngineError> {
        let mut required = existing.required_capabilities.clone();
        crate::capability_manager::merge_capabilities(
            &mut required,
            &crate::capability_manager::required_role_capabilities_from_group(mls_group),
        );
        let mut parsed_kps = Vec::with_capacity(key_packages.len());
        for kp in key_packages {
            let parsed = self.parse_key_package(kp)?;
            if kp.protocol_profile != existing.protocol_profile {
                return Err(EngineError::InvalidAccountIdentityProof(format!(
                    "cannot add a {:?} KeyPackage into a {:?} group",
                    kp.protocol_profile, existing.protocol_profile
                )));
            }
            if crate::app_components::credential_account_pubkey(
                parsed.leaf_node().credential().clone(),
            )
            .as_ref()
                != Some(account)
            {
                return Err(EngineError::Other(
                    "a KeyPackage to add belongs to another account".into(),
                ));
            }
            let had = crate::capabilities::capabilities_of_key_package(&parsed);
            if !required.missing_from(&had).is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(required),
                    had: Box::new(had),
                });
            }
            parsed_kps.push(parsed);
        }
        Ok(parsed_kps)
    }
}

/// The leaves a same-account Remove targets: each signature key names a
/// current leaf of `account` other than this device's own.
pub(crate) fn own_account_leaves(
    mls_group: &MlsGroup,
    leaf_signature_keys: &[Vec<u8>],
    account: &[u8; 32],
) -> Result<Vec<LeafNodeIndex>, EngineError> {
    let own_leaf = mls_group.own_leaf_index();
    leaf_signature_keys
        .iter()
        .map(|key| {
            let member = mls_group
                .members()
                .find(|member| &member.signature_key == key)
                .ok_or_else(|| {
                    EngineError::Other("no current leaf has a device's signature key".into())
                })?;
            if member.index == own_leaf {
                return Err(EngineError::Other(
                    "use SendIntent::Leave to remove this device".into(),
                ));
            }
            if crate::app_components::credential_account_pubkey(member.credential).as_ref()
                != Some(account)
            {
                return Err(EngineError::Other(
                    "a leaf to remove belongs to another account".into(),
                ));
            }
            Ok(member.index)
        })
        .collect()
}
