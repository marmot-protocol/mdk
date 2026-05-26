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
use crate::provider::EngineOpenMlsProvider;
use crate::wire_format::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use crate::wire_format::join_config;
use cgka_traits::TransportEndpoint;
use cgka_traits::app_components::{AppComponentSet, default_group_components};
use cgka_traits::capabilities::{GroupCapabilities, TransportKind};
use cgka_traits::engine::{CreateGroupRequest, KeyPackage, SendResult, WelcomeMetadata};
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId};
use openmls::group::{MlsGroup, MlsGroupCreateConfig, StagedWelcome};
use openmls::prelude::{BasicCredential, Extension, Extensions, MlsMessageBodyIn, MlsMessageIn};
use openmls::treesync::Node;
use openmls_traits::types::Ciphersuite;
use tls_codec::{Deserialize as _, Serialize as _};

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
pub(crate) const ENCRYPTED_MEDIA_EXPORTER_SNAPSHOT_KEY: &str = "marmot/encrypted-media";
pub(crate) const AGENT_TEXT_STREAM_EXPORTER_SNAPSHOT_KEY: &str =
    cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_EXPORTER_LABEL;

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
        )?;
        let mut desired_components = AppComponentSet::from(default_group_components());
        for component_id in required_caps.app_components.ids.clone() {
            desired_components.insert(component_id);
        }
        for component in &req.app_components {
            required_caps.app_components.insert(component.component_id);
            desired_components.insert(component.component_id);
        }
        let self_missing = required_caps
            .app_components
            .missing_from(&self.supported_app_components);
        if !self_missing.is_empty() {
            let had = GroupCapabilities {
                app_components: self.supported_app_components.clone(),
                ..GroupCapabilities::default()
            };
            return Err(EngineError::MissingRequiredCapabilities {
                required: Box::new(required_caps.clone()),
                had: Box::new(had),
            });
        }

        let mut parsed_kps = Vec::with_capacity(req.members.len());
        let mut negotiated_components =
            desired_components.intersection(&self.supported_app_components);
        for kp in &req.members {
            let parsed = self.parse_key_package(kp)?;
            let had = capabilities_of_key_package(&parsed);
            let missing = required_caps.missing_from(&had);
            if !missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: Box::new(required_caps.clone()),
                    had: Box::new(had),
                });
            }
            negotiated_components = negotiated_components.intersection(&had.app_components);
            parsed_kps.push(parsed);
        }
        required_caps.app_components = negotiated_components;
        let required_caps_ext = extension_from_group_capabilities(&required_caps);

        // 2. Build the group config with leaf capabilities, MLS
        //    RequiredCapabilities, and Marmot app-component state.
        let leaf_caps = leaf_capabilities(&self.registry, self.ciphersuite);
        let leaf_extensions = Extensions::from_vec(vec![
            crate::app_components::leaf_app_components_extension(&self.supported_app_components)?,
            self.identity.account_identity_proof_extension.clone(),
        ])
        .map_err(|e| EngineError::Backend(format!("leaf extensions: {e:?}")))?;

        let creator_pubkey =
            crate::app_components::admin_pubkey_from_member_id(self.identity.self_id())?;
        let mut admin_set: Vec<[u8; 32]> = vec![creator_pubkey];
        for extra in &req.initial_admins {
            let pk = crate::app_components::admin_pubkey_from_member_id(extra)?;
            if !admin_set.contains(&pk) {
                admin_set.push(pk);
            }
        }

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

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mut mls_group = MlsGroup::new(
            &provider,
            &self.identity.signer,
            &group_config,
            self.identity.credential_with_key.clone(),
        )
        .map_err(|e| EngineError::Backend(format!("group new: {e:?}")))?;

        // 3. Add members to produce a staged commit + welcome (skipped for
        //    solo creation). Publish-before-apply keeps the staged commit
        //    attached to `mls_group`; merge happens in `do_confirm_published`.
        //    Welcome bytes are independently serializable from the OpenMLS
        //    return value; they do not require a merged group.
        let welcome_bytes: Option<Vec<u8>> = if parsed_kps.is_empty() {
            None
        } else {
            let (_commit_out, welcome_out, _group_info) = mls_group
                .add_members(&provider, &self.identity.signer, &parsed_kps)
                .map_err(|e| EngineError::Backend(format!("add_members: {e:?}")))?;
            let bytes = welcome_out
                .tls_serialize_detached()
                .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
            Some(bytes)
        };

        let group_id = GroupId::new(mls_group.group_id().as_slice().to_vec());

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
        };
        self.storage.put_group(&group_record)?;

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

        crate::capability_manager::cache_from_key_packages(
            &self.storage,
            &group_id,
            &parsed_kps,
            self.ciphersuite,
        )?;
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
        )?;

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
            return Err(EngineError::Other("welcome already processed".to_string()));
        }
        if let Ok(record) = self.storage.get_message(&welcome_msg.id)
            && matches!(
                record.state,
                cgka_traits::message::MessageState::Processed
                    | cgka_traits::message::MessageState::Failed
                    | cgka_traits::message::MessageState::EpochInvalidated
            )
        {
            return Err(EngineError::Other("welcome already processed".to_string()));
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
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let join_config = join_config(self.max_past_epochs);
        let staged = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|e| EngineError::Backend(format!("stage welcome: {e:?}")))?;
        let mls_group = staged
            .into_group(&provider)
            .map_err(|e| EngineError::Backend(format!("into_group: {e:?}")))?;

        let group_id = GroupId::new(mls_group.group_id().as_slice().to_vec());

        // 5b. Reject the Welcome if any member leaf carries an invalid Marmot
        // credential identity (foundation/identity.md, joining.md:65). The
        // Welcome embeds the full ratchet tree, so every current member's
        // credential is checked here at join ingress.
        validate_member_credentials_and_account_proofs(&mls_group, self.ciphersuite)?;

        // 5c. Reject the Welcome if the resulting group has active required
        // capabilities (MLS extensions, proposal types, or Marmot app
        // components) this client cannot apply. The create/invite paths run the
        // symmetric `missing_from` check; joining.md:65 and convergence.md:19
        // require it here too. `had` is this client's CURRENT runtime support
        // (feature registry + supported app components), so a group requiring
        // more than this client can process is rejected even if a stale or
        // over-broad KeyPackage was consumed.
        let group_required =
            crate::capability_manager::required_capabilities_from_group(&mls_group);
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

        // 6. Persist Marmot group record from signed group-context data.
        let mut group_record = Group {
            id: group_id.clone(),
            name: String::new(),
            description: String::new(),
            epoch: EpochId(mls_group.epoch().as_u64()),
            members: marmot_members(&mls_group),
            required_capabilities: crate::capability_manager::required_capabilities_from_group(
                &mls_group,
            ),
        };
        mirror_app_components_into_record(&mls_group, &mut group_record);
        self.storage.put_group(&group_record)?;

        // Cache self's capabilities. Other members' capabilities arrive as
        // we ingest commits that touched their leaves; join-via-welcome
        // alone does not give us KeyPackage-level access to other members.
        crate::capability_manager::cache_self_capabilities(
            &self.storage,
            &group_id,
            &mls_group,
            self.identity.self_id(),
            self.ciphersuite,
        )?;

        // 7. State machine: Stable at the post-welcome epoch.
        self.epoch_manager
            .set_stable(group_id.clone(), EpochId(mls_group.epoch().as_u64()));

        // 8. Persist durable dedup state for direct `join_welcome`
        // callers. The ingest path records the welcome after this
        // method returns, but callers using the trait method directly
        // need restart-safe duplicate detection too.
        let payload = StoredMessagePayload::raw_transport(welcome_msg)
            .encode()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        self.storage.put_message(&MessageRecord {
            id: welcome_id.clone(),
            group_id: group_id.clone(),
            epoch: EpochId(mls_group.epoch().as_u64()),
            state: MessageState::Processed,
            payload,
        })?;

        // 9. Emit event + register for in-process dedup.
        self.events_buf
            .push_back(cgka_traits::engine::GroupEvent::GroupJoined {
                group_id: group_id.clone(),
                via_welcome: welcome_id.clone(),
            });
        self.seen_message_ids.insert(welcome_id);

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
            ));
        }
        let mut it = key_packages.iter();
        let first = self.parse_key_package(it.next().unwrap())?;
        let mut acc = capabilities_of_key_package(&first);
        for kp in it {
            let parsed = self.parse_key_package(kp)?;
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
pub(crate) fn validate_member_credentials_and_account_proofs(
    group: &MlsGroup,
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    validate_member_credentials(group)?;
    let tree = group.export_ratchet_tree();
    let value = serde_json::to_value(tree)
        .map_err(|e| EngineError::Backend(format!("export ratchet tree: {e}")))?;
    let nodes: Vec<Option<Node>> = serde_json::from_value(value)
        .map_err(|e| EngineError::Backend(format!("decode exported ratchet tree: {e}")))?;
    for node in nodes {
        if let Some(Node::LeafNode(leaf)) = node {
            crate::account_identity_proof::validate_leaf_account_identity_proof(
                &leaf,
                ciphersuite,
            )?;
        }
    }
    Ok(())
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
) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for (_f, req) in registry.iter() {
        out.insert(req.requires);
    }
    out.app_components = supported_app_components.clone();
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
