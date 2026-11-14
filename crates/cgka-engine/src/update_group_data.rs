//! `SendIntent::UpdateGroupData` — issues an `AppDataUpdate` commit for
//! `marmot.group.profile.v1`.

use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{
    APP_OWNED_APP_COMPONENT_ID_START, AccountEntryV1, AppComponentData, AppComponentId,
    DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterOperationV1, DeviceRosterUpdateV1,
    DeviceSlotId, GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
    RejectedSlotReasonV1, decode_device_roster_update_v1, encode_device_roster_update_v1,
};
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateProposal, Proposal};
use openmls::prelude::{KeyPackage as MlsKeyPackage, LeafNodeIndex, MlsMessageOut};
use std::collections::BTreeSet;
use tls_codec::{Serialize as _, Size as _, VLByteSlice};

// Local authoring limits for opaque application state carried by later Welcomes.
const APP_STATE_MAX_ENTRIES: usize = 32;
const APP_STATE_MAX_ENCODED_LEN: usize = 8192;

#[derive(Clone, Copy)]
enum AppDataCommitPurpose {
    Ordinary,
    /// Proposals pending in the store stay there; `context` prefixes errors.
    Isolated {
        context: &'static str,
    },
    MoveStatus(DeviceSlotId),
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_update_group_data(
        &mut self,
        group_id: GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendResult, EngineError> {
        if name.is_none() && description.is_none() {
            return Err(EngineError::Other(
                "UpdateGroupData with no fields to change".into(),
            ));
        }

        // A partial update must carry the other field forward from canonical
        // MLS state. The local Group record is only a projection and can lag a
        // component removal; using it here can resurrect removed profile data.
        let mls_group = self.load_mls_group(&group_id)?;
        let current_profile =
            crate::app_components::group_profile_of_group(&mls_group)?.unwrap_or_default();
        let projected_name = name.unwrap_or(current_profile.0);
        let projected_description = description.unwrap_or(current_profile.1);
        let profile_bytes =
            crate::app_components::encode_group_profile(&projected_name, &projected_description)?;

        self.do_send_update_app_components(
            group_id,
            vec![AppComponentData {
                component_id: GROUP_PROFILE_COMPONENT_ID,
                data: profile_bytes,
            }],
        )
        .await
    }

    pub(crate) async fn do_send_update_app_components(
        &mut self,
        group_id: GroupId,
        updates: Vec<AppComponentData>,
    ) -> Result<SendResult, EngineError> {
        self.do_send_app_data_updates(group_id, updates, Vec::new())
            .await
    }

    /// [`Self::do_send_update_app_components`] for a Commit that carries only
    /// `updates`: proposals pending in the store stay there. A leave's
    /// automatic step-down uses it (mdk#3014).
    pub(crate) async fn do_send_isolated_app_component_updates(
        &mut self,
        group_id: GroupId,
        updates: Vec<AppComponentData>,
    ) -> Result<SendResult, EngineError> {
        self.do_send_app_data_updates_with_purpose(
            group_id,
            updates,
            Vec::new(),
            AppDataCommitPurpose::Isolated {
                context: "leave_step_down",
            },
        )
        .await
    }

    /// Stage a [`cgka_traits::engine::SendIntent::RecordRemovedSlot`]: one
    /// roster `SetRejectedSlot` with reason `removed` and a tag signature
    /// key, in a group that requires the roster, for a slot the roster lists
    /// neither as a device nor as a rejected slot (mdk#2761). It goes out as a component update; its
    /// intent kind is what keeps it out of the queue and out of re-issue.
    /// Like an unlink, it is refused with
    /// [`EngineError::LinkDeviceUnsettled`] while a Commit is in flight.
    pub(crate) async fn do_send_record_removed_slot(
        &mut self,
        group_id: GroupId,
        roster_update: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        if self
            .epoch_manager
            .state(&group_id)
            .is_some_and(|state| !matches!(state, EpochState::Stable { .. }))
        {
            return Err(EngineError::LinkDeviceUnsettled { group_id });
        }
        let update = decode_device_roster_update_v1(&roster_update).map_err(|error| {
            EngineError::Serialize(format!("invalid device roster update: {error}"))
        })?;
        let [DeviceRosterOperationV1::SetRejectedSlot(slot, record)] = update.operations() else {
            return Err(EngineError::Other(
                "invalid removed-slot record: it must set exactly one rejected slot".into(),
            ));
        };
        if record.reason != RejectedSlotReasonV1::Removed || record.tag_signature_key.is_none() {
            return Err(EngineError::Other(
                "invalid removed-slot record: it has reason removed and keeps a tag signature key"
                    .into(),
            ));
        }
        let held = self.with_mls_group(&group_id, |mls_group| {
            if !crate::app_components::group_requires_device_roster(mls_group)? {
                return Err(EngineError::InvalidTransition(
                    cgka_traits::engine_state::InvalidTransition {
                        from: "DeviceRosterNotRequired",
                        to: "record_removed_slot",
                        reason: "the group does not require marmot.account.device-roster.v1",
                    },
                ));
            }
            Ok(
                crate::app_components::device_roster_of_group(mls_group).is_some_and(|roster| {
                    roster.devices.contains_key(slot) || roster.rejected_slots.contains_key(slot)
                }),
            )
        })?;
        if held {
            return Err(EngineError::Other(
                "invalid removed-slot record: the roster already holds the slot".into(),
            ));
        }
        self.do_send_update_app_components(
            group_id,
            vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: roster_update,
            }],
        )
        .await
    }

    pub(crate) async fn do_send_import_device_group_rejections(
        &mut self,
        group_id: GroupId,
        roster_update: Vec<u8>,
    ) -> Result<SendResult, EngineError> {
        let proposed =
            decode_device_roster_update_v1(&roster_update).map_err(EngineError::Serialize)?;
        let now = self.wall_clock.now().0;
        let operations = self.with_mls_group(&group_id, |group| {
            if !crate::app_components::group_requires_device_roster(group)? {
                return Err(EngineError::Other(
                    "carried rejection requires a device roster".into(),
                ));
            }
            let roster = crate::app_components::device_roster_of_group(group)
                .ok_or_else(|| EngineError::Other("destination roster is unavailable".into()))?;
            let mut operations = Vec::new();
            for operation in proposed.operations() {
                let DeviceRosterOperationV1::SetRejectedSlot(slot, record) = operation else {
                    return Err(EngineError::Other(
                        "carried rejection contains another operation".into(),
                    ));
                };
                if !roster.devices.contains_key(slot)
                    && !roster.rejected_slots.contains_key(slot)
                    && !(record.reason == RejectedSlotReasonV1::Removed
                        && now.saturating_sub(record.rejected_at) >= 30 * 24 * 60 * 60)
                {
                    operations.push(operation.clone());
                }
            }
            Ok(operations)
        })?;
        if operations.is_empty() {
            return Ok(SendResult::NoChange { group_id });
        }
        let update = DeviceRosterUpdateV1::new(operations)
            .and_then(|update| encode_device_roster_update_v1(&update))
            .map_err(EngineError::Serialize)?;
        self.do_send_app_data_updates_with_purpose(
            group_id,
            vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
            Vec::new(),
            AppDataCommitPurpose::Isolated {
                context: "carried_rejections",
            },
        )
        .await
    }

    pub(crate) async fn do_send_mark_device_group_moved(
        &mut self,
        group_id: GroupId,
        slot: DeviceSlotId,
        expected: DeviceEntryV1,
    ) -> Result<SendResult, EngineError> {
        let valid = crate::device_tag::own_device_slot(&self.storage)? == Some(slot)
            && self.with_mls_group(&group_id, |group| {
                let Some(roster) = crate::app_components::device_roster_of_group(group) else {
                    return Ok(false);
                };
                Ok(crate::app_components::group_requires_device_roster(group)?
                    && roster.devices.get(&slot) == Some(&expected)
                    && expected.tag_signature_key.as_deref() == Some(self.identity.signer.public())
                    && group.own_leaf_node().is_some_and(|leaf| {
                        leaf.signature_key().as_slice() == self.identity.signer.public()
                    }))
            })?;
        if !valid {
            return Err(EngineError::DeviceEntryChanged { group_id });
        }
        let mut moved = expected;
        moved.status = cgka_traits::app_components::DeviceStatusV1::Moved;
        let update =
            DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(slot, moved)])
                .and_then(|update| encode_device_roster_update_v1(&update))
                .map_err(EngineError::Serialize)?;
        self.do_send_app_data_updates_with_purpose(
            group_id,
            vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
            Vec::new(),
            AppDataCommitPurpose::MoveStatus(slot),
        )
        .await
    }

    /// Stage a [`cgka_traits::engine::SendIntent::ReplaceDeviceEntry`]: one
    /// roster `SetDevice` of `slot`, only while the roster still holds
    /// `expected` there. A direct send, a drained queued copy and a re-issue
    /// after a lost fork are all prepared here, so an entry computed from an
    /// older read never replaces a newer one.
    pub(crate) async fn do_send_replace_device_entry(
        &mut self,
        group_id: GroupId,
        slot: DeviceSlotId,
        expected: DeviceEntryV1,
        entry: DeviceEntryV1,
    ) -> Result<SendResult, EngineError> {
        let current = self.with_mls_group(&group_id, |mls_group| {
            Ok(crate::app_components::device_entry_of_group(
                mls_group, &slot,
            ))
        })?;
        if current.as_ref() != Some(&expected) {
            return Err(EngineError::DeviceEntryChanged { group_id });
        }
        let update =
            DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(slot, entry)])
                .and_then(|update| encode_device_roster_update_v1(&update))
                .map_err(EngineError::Serialize)?;
        self.do_send_update_app_components(
            group_id,
            vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        )
        .await
    }

    /// Stage a [`cgka_traits::engine::SendIntent::ReplaceAccountEntry`]: one
    /// roster `SetAccount`, only while the roster still holds `expected` as
    /// its account entry, compared wherever the Commit is prepared, as for
    /// [`Self::do_send_replace_device_entry`].
    pub(crate) async fn do_send_replace_account_entry(
        &mut self,
        group_id: GroupId,
        expected: AccountEntryV1,
        entry: AccountEntryV1,
    ) -> Result<SendResult, EngineError> {
        let current = self.with_mls_group(&group_id, |mls_group| {
            Ok(crate::app_components::account_entry_of_group(mls_group))
        })?;
        if current.as_ref() != Some(&expected) {
            return Err(EngineError::AccountEntryChanged { group_id });
        }
        let update = DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetAccount(entry)])
            .and_then(|update| encode_device_roster_update_v1(&update))
            .map_err(EngineError::Serialize)?;
        self.do_send_update_app_components(
            group_id,
            vec![AppComponentData {
                component_id: DEVICE_ROSTER_COMPONENT_ID,
                data: update,
            }],
        )
        .await
    }

    /// Stage one admin Commit that sets each of `updates` and removes each of
    /// `removals`. [`Self::do_send_update_app_components`] sends updates only;
    /// account-devices activation also removes an entry its component never
    /// defined ([`crate::account_devices_activation`]).
    pub(crate) async fn do_send_app_data_updates(
        &mut self,
        group_id: GroupId,
        updates: Vec<AppComponentData>,
        removals: Vec<AppComponentId>,
    ) -> Result<SendResult, EngineError> {
        self.do_send_app_data_updates_with_purpose(
            group_id,
            updates,
            removals,
            AppDataCommitPurpose::Ordinary,
        )
        .await
    }

    async fn do_send_app_data_updates_with_purpose(
        &mut self,
        group_id: GroupId,
        updates: Vec<AppComponentData>,
        removals: Vec<AppComponentId>,
        purpose: AppDataCommitPurpose,
    ) -> Result<SendResult, EngineError> {
        self.epoch_manager.ensure_pending_space()?;
        if updates.is_empty() {
            return Err(EngineError::Other(
                "UpdateAppComponents requires at least one component update".into(),
            ));
        }

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "UpdateAppComponents",
                    reason: "update_app_components requires Stable",
                },
            ));
        }

        let mut seen = BTreeSet::new();
        for component_id in &removals {
            if !seen.insert(*component_id) {
                return Err(EngineError::Other(
                    "UpdateAppComponents contains duplicate component ids".into(),
                ));
            }
        }
        for update in &updates {
            if !seen.insert(update.component_id) {
                return Err(EngineError::Other(
                    "UpdateAppComponents contains duplicate component ids".into(),
                ));
            }
            // MIP-03 §150, ordered ahead of the component validator: that
            // validator refuses the same payload as a malformed encoding, which
            // would hide the policy refusal behind a wire fault.
            if update.component_id == GROUP_ADMIN_POLICY_COMPONENT_ID
                && crate::app_components::admin_policy_is_empty(&update.data)
            {
                return Err(EngineError::AdminDepletion {
                    group_id: group_id.clone(),
                });
            }
            crate::app_components::refuse_local_group_context_entry(update.component_id)?;
            crate::app_components::validate_app_component_update(update)?;
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut mls_group = self.load_mls_group(&group_id)?;
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        if updates
            .iter()
            .any(|update| update.component_id >= APP_OWNED_APP_COMPONENT_ID_START)
        {
            let dictionary = mls_group
                .extensions()
                .app_data_dictionary()
                .map(|ext| ext.dictionary());
            let mut count = 0;
            let mut encoded_len = 0;
            if let Some(dictionary) = dictionary {
                for entry in dictionary
                    .entries()
                    .filter(|entry| entry.id() >= APP_OWNED_APP_COMPONENT_ID_START)
                {
                    count += 1;
                    encoded_len += entry.tls_serialized_len();
                }
            }
            // Count replacements once, including each id and TLS payload length.
            for update in updates
                .iter()
                .filter(|update| update.component_id >= APP_OWNED_APP_COMPONENT_ID_START)
            {
                if let Some(previous) = dictionary.and_then(|dict| dict.get(&update.component_id)) {
                    encoded_len -= update.component_id.tls_serialized_len()
                        + VLByteSlice(previous).tls_serialized_len();
                } else {
                    count += 1;
                }
                encoded_len += update.component_id.tls_serialized_len()
                    + VLByteSlice(&update.data).tls_serialized_len();
            }
            if count > APP_STATE_MAX_ENTRIES || encoded_len > APP_STATE_MAX_ENCODED_LEN {
                return Err(EngineError::Other(format!(
                    "application state exceeds {APP_STATE_MAX_ENTRIES} entries or {APP_STATE_MAX_ENCODED_LEN} encoded bytes"
                )));
            }
        }

        for update in &updates {
            if update.component_id == GROUP_ADMIN_POLICY_COMPONENT_ID {
                let admins = crate::app_components::decode_admin_policy(&update.data)?;
                crate::app_components::reject_admins_without_member_leaf(
                    &mls_group, &group_id, &admins,
                )?;
            }
        }

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        // Stage the AppDataUpdate commit. Don't merge — confirm path does that.
        let proposals = updates
            .iter()
            .map(|update| {
                Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                    update.component_id,
                    update.data.clone(),
                )))
            })
            .chain(removals.iter().map(|component_id| {
                Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::remove(*component_id)))
            }))
            .collect::<Vec<_>>();
        let commit_out = match purpose {
            AppDataCommitPurpose::Ordinary => self.stage_commit_with_app_data_updates(
                &mut mls_group,
                &provider,
                Vec::new(),
                Vec::new(),
                proposals,
                "app_data_update",
            )?,
            AppDataCommitPurpose::Isolated { context } => self.stage_app_data_commit(
                &mut mls_group,
                &provider,
                Vec::new(),
                Vec::new(),
                proposals,
                false,
                None,
                context,
            )?,
            AppDataCommitPurpose::MoveStatus(slot) => {
                // Only this status operation tags from the authenticated old
                // roster. Ordinary old queued work may have replaced its tag
                // after the global name changed; it must not strand cleanup.
                let roster =
                    crate::app_components::device_roster_of_group(&mls_group).ok_or_else(|| {
                        EngineError::DeviceEntryChanged {
                            group_id: group_id.clone(),
                        }
                    })?;
                let own = crate::device_tag::OwnDeviceTag::find(
                    roster,
                    Some(slot),
                    self.identity.signer.public(),
                )
                .ok_or_else(|| EngineError::DeviceEntryChanged {
                    group_id: group_id.clone(),
                })?;
                let leaf =
                    mls_group
                        .own_leaf_node()
                        .ok_or_else(|| EngineError::DeviceEntryChanged {
                            group_id: group_id.clone(),
                        })?;
                let parameters = if own.reads_as_own(leaf) {
                    openmls::prelude::LeafNodeParameters::default()
                } else {
                    let tag = own.seal(&self.crypto, &self.identity.signer)?;
                    // Keep the current support list and every unrelated leaf
                    // field; this is not an ordinary capability refresh.
                    let advertised = crate::app_components::app_components_of_leaf(leaf)?;
                    let extensions = crate::leaf_advertisement::own_leaf_refresh_extensions(
                        leaf,
                        &advertised,
                        Some(tag),
                    )?
                    .ok_or_else(|| EngineError::DeviceEntryChanged {
                        group_id: group_id.clone(),
                    })?;
                    openmls::prelude::LeafNodeParameters::builder()
                        .with_extensions(extensions)
                        .build()
                };
                self.stage_app_data_commit(
                    &mut mls_group,
                    &provider,
                    Vec::new(),
                    Vec::new(),
                    proposals,
                    false,
                    Some(parameters),
                    "move_status",
                )?
            }
        }
        .0;
        let staged_commit = mls_group.pending_commit().ok_or_else(|| {
            EngineError::Backend("app data update produced no pending commit".into())
        })?;
        crate::commit_class::authorize_own_staged_commit(
            &mls_group,
            &group_id,
            self.identity.self_id(),
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
        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let wrapped = self
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
        let wrapped = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: pre_commit_ctx
                    .transport_group_id()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| group_id.as_slice().to_vec()),
            },
            ..wrapped
        };
        // Derive the app projection before writing any outbound rows. The
        // synchronous staging unit commits both before installing pending state.
        let mut group = self.live_group_record(&group_id)?;
        for update in &updates {
            if update.component_id == GROUP_PROFILE_COMPONENT_ID {
                let (name, description) =
                    crate::app_components::decode_group_profile(&update.data)?;
                group.name = name;
                group.description = description;
            }
        }
        self.record_sent_openmls_message_with_group(
            &wrapped,
            commit_bytes.as_slice(),
            &group,
            pre_commit_epoch,
        )?;
        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
        let pending_ref = self.epoch_manager.next_pending_ref()?;
        let staged = StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.invalidate_deferred_peel_candidate_cache(&group_id);
        self.epoch_manager.begin_pending(
            group_id.clone(),
            pre_commit_epoch,
            new_epoch,
            staged,
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
        self.track_pending_origin_commit(pending_ref, wrapped.id.clone());
        pending_commit_guard.disarm();

        Ok(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: vec![],
            pending: pending_ref,
        })
    }

    /// Stage (don't merge) a commit that carries `AppDataUpdate` proposals,
    /// optionally alongside member removals or adds, through the OpenMLS commit
    /// builder. Every `Update` and `Remove` proposal is mirrored into the
    /// resulting `app_data_dictionary` via the builder's dictionary updater,
    /// matching what recipients compute in
    /// [`crate::openmls_projection::process_commit_with_app_data_updates`].
    /// Shared by the `UpdateAppComponents` path, the coupled admin-policy
    /// removal path in `do_send_remove_members`, and invite-with-admin Adds.
    /// `context` prefixes error messages so failures stay attributable to the
    /// calling intent. Returns the commit and, when Adds were staged, the
    /// Welcome. The commit also takes every proposal pending in the store.
    pub(crate) fn stage_commit_with_app_data_updates(
        &self,
        mls_group: &mut MlsGroup,
        provider: &EngineOpenMlsProvider<'_, S>,
        removals: Vec<LeafNodeIndex>,
        adds: Vec<MlsKeyPackage>,
        proposals: Vec<Proposal>,
        context: &str,
    ) -> Result<(MlsMessageOut, Option<MlsMessageOut>), EngineError> {
        // A first own destination key must describe exactly its post-roster:
        // another member's pending proposals cannot change that first tag.
        let consume_pending = self.first_own_roster_tag(mls_group, &proposals).is_none();
        self.stage_app_data_commit(
            mls_group,
            provider,
            removals,
            adds,
            proposals,
            consume_pending,
            None,
            context,
        )
    }

    /// [`Self::stage_commit_with_app_data_updates`] for a commit that carries
    /// only the given proposals, by value: proposals pending in the store
    /// stay there. The link Commit and its undo use it, so linking or
    /// unlinking one device never executes another member's queued Add,
    /// Remove or roster update.
    pub(crate) fn stage_exact_commit_with_app_data_updates(
        &self,
        mls_group: &mut MlsGroup,
        provider: &EngineOpenMlsProvider<'_, S>,
        removals: Vec<LeafNodeIndex>,
        adds: Vec<MlsKeyPackage>,
        proposals: Vec<Proposal>,
        context: &str,
    ) -> Result<(MlsMessageOut, Option<MlsMessageOut>), EngineError> {
        self.stage_app_data_commit(
            mls_group, provider, removals, adds, proposals, false, None, context,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn stage_app_data_commit(
        &self,
        mls_group: &mut MlsGroup,
        provider: &EngineOpenMlsProvider<'_, S>,
        removals: Vec<LeafNodeIndex>,
        adds: Vec<MlsKeyPackage>,
        proposals: Vec<Proposal>,
        consume_pending: bool,
        preserve_leaf: Option<openmls::prelude::LeafNodeParameters>,
        context: &str,
    ) -> Result<(MlsMessageOut, Option<MlsMessageOut>), EngineError> {
        // Validate the proposal set as one operation. In particular, removal
        // legality is based on the resulting requirement list so one Commit
        // may atomically unrequire and remove an optional component.
        crate::app_components::validate_app_data_update_batch(
            mls_group,
            proposals.iter().filter_map(|proposal| match proposal {
                Proposal::AppDataUpdate(update) => Some(update.as_ref()),
                _ => None,
            }),
        )?;
        let roster_required = crate::app_components::group_requires_device_roster(mls_group)?;
        // The roster `proposals` leave decides whether a Commit that sets this
        // device's own tag key tags its UpdatePath leaf; one another member's
        // pending proposal changes as well is not foreseen here.
        let leaf_node_parameters = match preserve_leaf {
            Some(parameters) => parameters,
            None => self.own_commit_leaf_parameters(mls_group, &proposals)?,
        };
        let mut builder = mls_group
            .commit_builder()
            .consume_proposal_store(consume_pending)
            .propose_removals(removals)
            .propose_adds(adds)
            .add_proposals(proposals)
            .leaf_node_parameters(leaf_node_parameters)
            .load_psks(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    provider,
                ),
            )
            .map_err(|e| EngineError::Backend(format!("{context} load_psks: {e:?}")))?;
        let mut app_data = builder.app_data_dictionary_updater();
        crate::app_components::apply_app_data_updates(
            roster_required,
            &mut app_data,
            builder.app_data_update_proposals(),
        )?;
        builder.with_app_data_dictionary_updates(app_data.changes());
        let commit_bundle = builder
            .build(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::rand(provider),
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(provider),
                &self.identity.signer,
                |_| true,
            )
            .map_err(|e| EngineError::Backend(format!("{context} build: {e:?}")))?
            .stage_commit(provider)
            .map_err(|e| EngineError::Backend(format!("{context} stage: {e:?}")))?;
        let (commit_out, welcome_opt, _gi) = commit_bundle.into_messages();
        Ok((commit_out, welcome_opt))
    }
}
