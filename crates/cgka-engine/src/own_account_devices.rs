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
//! A same-account Add adds siblings, each with a private KeyPackage it handed
//! this device (device-group.md, "Sibling Welcomes"). Each added sibling gets
//! a sibling Welcome, staged with the Commit as an Invite's Welcome is and
//! owed once it confirms, but never a transport message: the host sends it as
//! a kind-461 message in the device group. A published KeyPackage of this
//! account never adds a sibling (mdk#2628 D14).
//! Like a self-update, neither intent keeps an `OwnCommitIntent`: when branch
//! selection supersedes one, nothing re-issues it (mdk#1734).

use crate::commit_class::CommitClass;
use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::private_key_packages::SiblingWelcome;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{DeviceSlotId, valid_sibling_welcome_relays};
use cgka_traits::engine::{KeyPackage, SendIntent, SendResult, SiblingKeyPackage};
use cgka_traits::engine_state::{EpochState, InvalidTransition, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::message::{MessageState, StoredMessagePayload};
use cgka_traits::storage::{StorageError, StorageProvider};
use cgka_traits::transport::{EncryptedPayload, Timestamp};
use cgka_traits::types::{EpochId, GroupId, MessageId};
use openmls::group::MlsGroup;
use openmls::prelude::LeafNodeIndex;
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tls_codec::Serialize as _;

const ADD: &str = "AddOwnAccountDevices";
const REMOVE: &str = "RemoveOwnAccountDevices";

/// What every sibling Welcome of one Add carries besides its own fields,
/// settled before anything is staged.
struct SiblingWelcomePlan {
    from: DeviceSlotId,
    relays: Vec<String>,
}

/// A sibling Welcome built for one added KeyPackage, not yet recorded.
pub(crate) struct BuiltSiblingWelcome {
    pub(crate) id: MessageId,
    pub(crate) content: Vec<u8>,
    pub(crate) key_package_ref: Vec<u8>,
    pub(crate) deliver_until: Timestamp,
}

/// A sibling Welcome this device owes: its Commit confirmed, no kind-461
/// message carrying it was published yet, and its KeyPackage's lifetime has
/// not ended ([`Engine::owed_sibling_welcomes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedSiblingWelcome {
    /// The Welcome's row id, which each transition names.
    pub id: MessageId,
    /// The chat the Welcome joins.
    pub group_id: GroupId,
    /// The encoded sibling Welcome: a 461's content once base64-encoded.
    pub content: Vec<u8>,
    /// The app event id of the 461 sent to carry it, while that send is not
    /// resolved.
    pub carrier: Option<Vec<u8>>,
}

/// The row id of the sibling Welcome for the KeyPackage `key_package_ref`
/// that the Commit `commit_id` adds. A KeyPackage added again after its
/// Commit rolled back gets a row per attempt.
fn sibling_welcome_row_id(commit_id: &MessageId, key_package_ref: &[u8]) -> MessageId {
    let mut hasher = Sha256::new();
    hasher.update(b"marmot sibling welcome row v1");
    hasher.update((commit_id.as_slice().len() as u64).to_be_bytes());
    hasher.update(commit_id.as_slice());
    hasher.update(key_package_ref);
    MessageId::new(hasher.finalize().to_vec())
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_add_own_account_devices(
        &mut self,
        group_id: GroupId,
        siblings: Vec<SiblingKeyPackage>,
    ) -> Result<SendResult, EngineError> {
        if siblings.is_empty() {
            return Err(EngineError::Other(
                "adding own account devices requires at least one KeyPackage".into(),
            ));
        }
        self.do_send_own_account_devices(group_id, siblings, Vec::new(), ADD)
            .await
    }

    /// Refuse now a same-account Add whose siblings a direct send would
    /// refuse now. Run before it is queued, so the sender is answered at
    /// once with nothing written; the drain checks a queued one again when
    /// it prepares it, and refuses it there as `QueuedIntentRefused`.
    pub(crate) fn check_queued_sibling_add(&self, intent: &SendIntent) -> Result<(), EngineError> {
        let SendIntent::AddOwnAccountDevices { group_id, siblings } = intent else {
            return Ok(());
        };
        if siblings.is_empty() {
            return Err(EngineError::Other(
                "adding own account devices requires at least one KeyPackage".into(),
            ));
        }
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_group = MlsGroup::load(
            provider.storage(),
            &openmls::group::GroupId::from_slice(group_id.as_slice()),
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        self.sibling_welcome_plan(&mls_group, siblings).map(|_| ())
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
        siblings: Vec<SiblingKeyPackage>,
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
        if !crate::app_components::group_requires_account_devices(&mls_group)? {
            return Err(EngineError::InvalidTransition(InvalidTransition {
                from: "AccountDevicesNotRequired",
                to: intent,
                reason: "the group does not require marmot.group.account-devices.v1",
            }));
        }
        let account = crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let existing = self.storage.get_group(&group_id)?;
        let key_packages: Vec<KeyPackage> = siblings
            .iter()
            .map(|sibling| sibling.key_package.clone())
            .collect();
        let parsed_kps =
            self.own_account_key_packages(&mls_group, &existing, &key_packages, &account)?;
        let removed_leaves = own_account_leaves(&mls_group, &leaf_signature_keys, &account)?;

        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let pending_commit_guard =
            PendingCommitCleanupGuard::arm(&self.storage, &provider, group_id.clone());
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;
        let leaf_node_parameters = self.own_commit_leaf_parameters(&mls_group, &[])?;
        let (commit_out, welcome_out, _group_info) = mls_group
            .commit_builder()
            .consume_proposal_store(false)
            .propose_adds(parsed_kps.iter().cloned())
            .propose_removals(removed_leaves.iter().copied())
            .leaf_node_parameters(leaf_node_parameters)
            .load_psks(provider.storage())
            .map_err(|e| EngineError::Backend(format!("own account devices load_psks: {e:?}")))?
            .build(
                provider.rand(),
                provider.crypto(),
                &self.identity.signer,
                |_| true,
            )
            .map_err(|e| EngineError::Backend(format!("own account devices build: {e:?}")))?
            .stage_commit(&provider)
            .map_err(|e| EngineError::Backend(format!("own account devices stage: {e:?}")))?
            .into_messages();
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
        let sibling_plan = if siblings.is_empty() {
            None
        } else {
            Some(self.sibling_welcome_plan(&mls_group, &siblings)?)
        };

        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        let welcome_bytes = match (welcome_out, &sibling_plan) {
            (Some(welcome), Some(plan)) => Some((
                welcome
                    .tls_serialize_detached()
                    .map_err(|e| EngineError::Serialize(format!("{e:?}")))?,
                plan,
            )),
            (None, None) => None,
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
        let sibling_welcomes = match welcome_bytes {
            Some((welcome, plan)) => {
                build_sibling_welcomes(plan, &siblings, &parsed_kps, &welcome, &commit_msg.id)?
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

        self.record_sent_openmls_message(
            &commit_msg,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;
        for sibling_welcome in sibling_welcomes {
            self.record_staged_sibling_welcome(
                sibling_welcome,
                &commit_msg.id,
                &group_id,
                pre_commit_epoch,
            )?;
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
            welcomes: Vec::new(),
            pending: pending_ref,
        })
    }

    /// Check the siblings a same-account Add names, as device-group.md
    /// ("Sibling Welcomes") needs them, and settle what their sibling
    /// Welcomes carry. This device must be tagged in the device group it
    /// trusts. Each KeyPackage names no publication (D14) and passes the check
    /// a hand-off from its named slot passes: this account's, single-use,
    /// unexpired, its device tag reading as that slot in that roster, another
    /// roster device, one KeyPackage each. The chat names one to 16 relays for
    /// the new member to fetch from.
    fn sibling_welcome_plan(
        &self,
        mls_group: &MlsGroup,
        siblings: &[SiblingKeyPackage],
    ) -> Result<SiblingWelcomePlan, EngineError> {
        let refused = |reason: &str| EngineError::Other(format!("adding a sibling: {reason}"));
        let own = self
            .own_device_tag(&self.storage)?
            .ok_or_else(|| refused("this device is not tagged in a trusted device group"))?;
        let mut slots = HashSet::new();
        for sibling in siblings {
            if sibling.key_package.source.is_some() {
                return Err(refused("a published KeyPackage never adds a sibling"));
            }
            if sibling.slot == own.slot() {
                return Err(refused("the named slot is this device's"));
            }
            if !slots.insert(sibling.slot) {
                return Err(refused("two KeyPackages name the same sibling"));
            }
            crate::private_key_packages::validate_received_private_key_package(
                &sibling.key_package,
                self.identity.self_id(),
                own.roster(),
                &sibling.slot,
                self.wall_clock.now().0,
            )
            .map_err(|error| refused(&error.to_string()))?;
        }
        let relays: Vec<String> = crate::group_lifecycle::welcome_relays_for_group(mls_group)?
            .unwrap_or_default()
            .into_iter()
            .map(|relay| relay.0)
            .collect();
        if !valid_sibling_welcome_relays(&relays) {
            return Err(refused(
                "the chat must name one to 16 relays, none repeated once parsed",
            ));
        }
        Ok(SiblingWelcomePlan {
            from: own.slot(),
            relays,
        })
    }

    /// Every sibling Welcome this device owes at `now`, in its live groups
    /// (device-group.md, "Sending a sibling Welcome"). The host sends each as
    /// a kind-461 message in the device group. One with a `carrier` already
    /// has a 461 on its way, and gets another only once that one failed. A
    /// disbanded chat owes none: its sibling would join a group every other
    /// member has left.
    pub fn owed_sibling_welcomes(
        &self,
        now: Timestamp,
    ) -> Result<Vec<OwedSiblingWelcome>, EngineError> {
        let mut owed = Vec::new();
        for group_id in self.storage.list_groups()? {
            if self.ensure_group_live(&group_id).is_err()
                || self
                    .stored_group_record(&group_id)?
                    .is_none_or(|group| group.disbanded.is_some())
            {
                continue;
            }
            for record in self.storage.list_messages_in_states(
                &group_id,
                &[MessageState::Sent],
                EpochId(0),
            )? {
                let Ok(StoredMessagePayload::OutboundSiblingWelcome {
                    welcome,
                    deliver_until,
                    carrier,
                    ..
                }) = StoredMessagePayload::decode(&record.payload)
                else {
                    continue;
                };
                if now < deliver_until {
                    owed.push(OwedSiblingWelcome {
                        id: record.id,
                        group_id: group_id.clone(),
                        content: welcome,
                        carrier,
                    });
                }
            }
        }
        Ok(owed)
    }

    /// Record `carrier`, the app event id of the 461 about to carry the owed
    /// sibling Welcome `id`, before that 461 is sent. `false`, recording
    /// nothing, when the Welcome is not owed or already has a carrier.
    pub fn carry_sibling_welcome(
        &self,
        id: &MessageId,
        carrier: &[u8],
    ) -> Result<bool, EngineError> {
        self.update_owed_sibling_welcome(id, |current, _| {
            if current.is_some() {
                return false;
            }
            *current = Some(carrier.to_vec());
            true
        })
    }

    /// Mark the sibling Welcome `id` delivered once the 461 `carrier` was
    /// published, so no 461 carries it again: when to resend one is not
    /// specified yet. `false` when `carrier` does not carry it, or it is no
    /// longer owed.
    pub fn sibling_welcome_delivered(
        &self,
        id: &MessageId,
        carrier: &[u8],
    ) -> Result<bool, EngineError> {
        self.update_owed_sibling_welcome(id, |current, state| {
            let carried = current.as_deref() == Some(carrier);
            if carried {
                *state = MessageState::Processed;
            }
            carried
        })
    }

    /// Clear `carrier` from the sibling Welcome `id` once that 461 failed and
    /// reached no one, so the Welcome is owed again. `false` when `carrier`
    /// does not carry it, or it is no longer owed.
    pub fn sibling_welcome_send_failed(
        &self,
        id: &MessageId,
        carrier: &[u8],
    ) -> Result<bool, EngineError> {
        self.update_owed_sibling_welcome(id, |current, _| {
            let carried = current.as_deref() == Some(carrier);
            if carried {
                *current = None;
            }
            carried
        })
    }

    /// Apply `update` to the carrier and state of the owed sibling Welcome
    /// `id`, writing them back when it returns `true`. Like withdrawal, it
    /// reads only the Welcome's own row.
    fn update_owed_sibling_welcome(
        &self,
        id: &MessageId,
        update: impl FnOnce(&mut Option<Vec<u8>>, &mut MessageState) -> bool,
    ) -> Result<bool, EngineError> {
        let mut record = match self.storage.get_message(id) {
            Ok(record) => record,
            Err(StorageError::NotFound) => return Ok(false),
            Err(error) => return Err(EngineError::Storage(error)),
        };
        if record.state != MessageState::Sent {
            return Ok(false);
        }
        let Ok(StoredMessagePayload::OutboundSiblingWelcome {
            welcome,
            key_package_ref,
            deliver_until,
            mut carrier,
        }) = StoredMessagePayload::decode(&record.payload)
        else {
            return Ok(false);
        };
        if !update(&mut carrier, &mut record.state) {
            return Ok(false);
        }
        record.payload = StoredMessagePayload::outbound_sibling_welcome(
            welcome,
            key_package_ref,
            deliver_until,
            carrier,
        )
        .encode()
        .map_err(|error| EngineError::Serialize(format!("{error:?}")))?;
        self.storage.put_message(&record)?;
        Ok(true)
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

/// One sibling Welcome per added KeyPackage, each naming its own KeyPackage
/// and carrying the staged Commit's Welcome (device-group.md, "Sending a
/// sibling Welcome"). It is deliverable until the KeyPackage's lifetime ends,
/// after which the sibling no longer holds its key.
fn build_sibling_welcomes(
    plan: &SiblingWelcomePlan,
    siblings: &[SiblingKeyPackage],
    parsed_kps: &[openmls::prelude::KeyPackage],
    welcome: &[u8],
    commit_id: &MessageId,
) -> Result<Vec<BuiltSiblingWelcome>, EngineError> {
    siblings
        .iter()
        .zip(parsed_kps)
        .map(|(sibling, parsed)| {
            let key_package_ref = crate::key_package::key_package_ref(parsed)?
                .as_slice()
                .to_vec();
            let content = SiblingWelcome {
                from: plan.from,
                to: sibling.slot,
                key_package_ref: key_package_ref.clone(),
                welcome: welcome.to_vec(),
                relays: plan.relays.clone(),
            }
            .encode()?;
            Ok(BuiltSiblingWelcome {
                id: sibling_welcome_row_id(commit_id, &key_package_ref),
                content,
                key_package_ref,
                deliver_until: Timestamp(parsed.life_time().not_after()),
            })
        })
        .collect()
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
