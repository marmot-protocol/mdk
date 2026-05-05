//! Group lifecycle — `create_group`, `join_welcome`, etc.
//!
//! **Publish-before-apply (Task 4.13, landed).** `do_create_group` stages
//! its add-members commit but does NOT call `merge_pending_commit`. The
//! engine wraps welcomes off the still-staged group, transitions to
//! `PendingPublish`, and returns. The actual MLS merge + Marmot record
//! update + capability cache happen in `Engine::do_confirm_published`
//! (in `publish.rs`) once the application reports the welcomes were
//! published. On `publish_failed`, `MlsGroup::clear_pending_commit`
//! discards the staged commit and the engine rewinds to `Stable` at the
//! prior epoch.
//!
//! For SOLO create (no invitees) there is no pending commit — the engine
//! still issues a `PendingStateRef` so the API shape is uniform, but
//! confirm/fail are state-machine-only no-ops MLS-side.

use crate::capabilities::{
    capabilities_of_key_package, leaf_capabilities, required_capabilities_extension_for_features,
};
use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use crate::wire_format::PURE_PLAINTEXT_WIRE_FORMAT_POLICY;
use crate::wire_format::default_join_config;
use cgka_traits::capabilities::{GroupCapabilities, TransportKind};
use cgka_traits::engine::{CreateGroupRequest, SendResult};
use cgka_traits::error::EngineError;
use cgka_traits::group::{Group, Member};
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId, MemberId};
use openmls::group::{MlsGroup, MlsGroupCreateConfig, StagedWelcome};
use openmls::prelude::{BasicCredential, Extension, Extensions, MlsMessageBodyIn, MlsMessageIn};
use tls_codec::{Deserialize as _, Serialize as _};

/// Exporter-secret label the engine reserves for its own internal use (group
/// context snapshots passed to peelers use this).
pub(crate) const EXPORTER_LABEL: &str = "marmot/engine/v1";

impl<S: StorageProvider> Engine<S> {
    /// Real implementation of `CgkaEngine::create_group`. Called by the
    /// stubbed method in `engine.rs` once this lands.
    pub(crate) async fn do_create_group(
        &mut self,
        req: CreateGroupRequest,
    ) -> Result<(GroupId, SendResult), EngineError> {
        // 1. Validate invitees against required capabilities.
        let active_transports: [TransportKind; 0] = []; // engine-layer: no transports
        let (required_caps, required_caps_ext) = required_capabilities_extension_for_features(
            &self.registry,
            &active_transports,
            &req.required_features,
        )?;

        let mut parsed_kps = Vec::with_capacity(req.members.len());
        for kp in &req.members {
            let parsed = self.parse_key_package(kp)?;
            let had = capabilities_of_key_package(&parsed);
            let missing = required_caps.missing_from(&had);
            if !missing.is_empty() {
                return Err(EngineError::MissingRequiredCapabilities {
                    required: required_caps.clone(),
                    had,
                });
            }
            parsed_kps.push(parsed);
        }

        // 2. Build the group config with leaf capabilities + required
        //    capabilities extension + MIP-01 marmot_group_data.
        let leaf_caps = leaf_capabilities(&self.registry, self.ciphersuite);

        // Construct the MIP-01 marmot_group_data extension.
        //
        // Admin set: creator is always included. Additional initial
        // admins from `req.initial_admins` are merged in (deduped).
        // Allows tests + Whitenoise-level bootstrap to create groups with
        // multiple admins from the start, which is the only path (in
        // 0.1.0) for an admin to subsequently self-remove without
        // tripping §149.
        //
        // Other marmot_group_data fields (relays, image, etc.) are
        // placeholders the transport adapter can refine on the way out.
        let creator_pubkey =
            crate::group_data::admin_pubkey_from_member_id(self.identity.self_id())?;
        let mut admin_set: Vec<[u8; 32]> = vec![creator_pubkey];
        for extra in &req.initial_admins {
            let pk = crate::group_data::admin_pubkey_from_member_id(extra)?;
            if !admin_set.contains(&pk) {
                admin_set.push(pk);
            }
        }

        let mut nostr_group_id = [0u8; 32];
        // Deterministic-from-self-id placeholder: real Nostr deployments
        // generate this with secure randomness in the transport adapter.
        // For 0.1.0's engine-only world, copy creator's id so wire bytes are
        // valid + reproducible per-creator. (Will be re-randomized once a
        // transport adapter wires `group_extension`.)
        nostr_group_id.copy_from_slice(&creator_pubkey);
        let mut group_data = crate::group_data::NostrGroupData::fresh(
            &req.name,
            &req.description,
            nostr_group_id,
            creator_pubkey,
        );
        group_data.set_admins(&admin_set);
        let group_data_ext = group_data.to_extension()?;

        let gc_exts = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(required_caps_ext),
            group_data_ext,
        ])
        .map_err(|e| EngineError::Backend(format!("extensions: {e:?}")))?;

        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(self.ciphersuite)
            .capabilities(leaf_caps)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
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

        // 3. Add members → commit + welcome (skipped for solo creation).
        //    Under publish-before-apply (Task 4.13), the staged commit
        //    stays attached to `mls_group`; merge happens in
        //    `do_confirm_published`. The welcome bytes are independently
        //    serializable from the OpenMLS return value — they don't
        //    require a merged group.
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

        // 5. Wrap welcomes via the peeler.
        //
        // Note: we intentionally do NOT emit the commit. The creator is the
        // only party who'd care about the "commit that creates the group at
        // epoch 1," and once they confirm publish they'll merge it locally.
        // Every other member lands in the group via `welcomes`, which carry
        // the post-commit state directly. Dropping the commit eliminates the
        // welcome-before-commit `AlreadyAtEpoch` bounce that the spike
        // cataloged at `docs/learnings.md:66-70` — no commit, no bounce.
        //
        // The context snapshot is built off the still-staged group; for
        // welcomes, only the recipient pubkey matters at wrap time, so the
        // pre-merge group context is sufficient.
        let ctx = build_group_context_snapshot(&mls_group, &provider)?;

        let mut welcomes = Vec::with_capacity(parsed_kps.len());
        if let Some(welcome_bytes) = &welcome_bytes {
            for kp in &parsed_kps {
                let recipient = member_id_of_key_package(kp)?;
                let payload = EncryptedPayload {
                    ciphertext: welcome_bytes.clone(),
                    aad: vec![],
                };
                let wrapped = self
                    .peeler
                    .wrap_welcome(&payload, &recipient)
                    .await
                    .map_err(EngineError::Peeler)?;
                self.record_sent_message(&wrapped, &group_id, EpochId(0))?;
                welcomes.push(wrapped);
            }
        }

        // 6. Persist Marmot-side group record with the PROJECTED
        //    post-merge member set. The MLS group is still at epoch 0
        //    pre-merge, but the `members` field surfaced via the
        //    `CgkaEngine::members` API and walked by `feature_status`
        //    needs to reflect "who the user thinks is in the group" —
        //    which includes invitees they just added. On `publish_failed`
        //    we re-derive from the (still-unmerged) MLS state, which
        //    naturally rolls the projection back.
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

        crate::capability_manager::cache_from_key_packages(&self.storage, &group_id, &parsed_kps)?;
        crate::capability_manager::cache_self_capabilities(
            &self.storage,
            &group_id,
            &mls_group,
            self.identity.self_id(),
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
    /// 1. Verify the welcome envelope targets this client
    /// 2. Peel via `TransportPeeler::peel_welcome`
    /// 3. Deserialize the inner MLS Welcome
    /// 4. Stage the welcome into an `MlsGroup` (ratchet tree is embedded)
    /// 5. Persist the Marmot `Group` record
    /// 6. Initialize `EpochState::Stable` at the post-welcome epoch
    /// 7. Emit `GroupEvent::GroupJoined`
    pub(crate) async fn do_join_welcome(
        &mut self,
        welcome_msg: TransportMessage,
    ) -> Result<GroupId, EngineError> {
        // 1. Envelope check.
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

        // 2. Peel.
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

        // 3. Deserialize.
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

        // 4. Stage + land.
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let join_config = default_join_config();
        let staged = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|e| EngineError::Backend(format!("stage welcome: {e:?}")))?;
        let mls_group = staged
            .into_group(&provider)
            .map_err(|e| EngineError::Backend(format!("into_group: {e:?}")))?;

        let group_id = GroupId::new(mls_group.group_id().as_slice().to_vec());

        // 5. Persist Marmot group record from signed group-context data.
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
        mirror_group_data_into_record(&mls_group, &mut group_record);
        self.storage.put_group(&group_record)?;

        // Task 4.7: cache self's capabilities. Other members' capabilities
        // arrive as we ingest subsequent commits that touched their leaves —
        // join-via-welcome alone doesn't give us KeyPackage-level access to
        // other members.
        crate::capability_manager::cache_self_capabilities(
            &self.storage,
            &group_id,
            &mls_group,
            self.identity.self_id(),
        )?;

        // 6. State machine: Stable at the post-welcome epoch.
        self.epoch_manager
            .set_stable(group_id.clone(), EpochId(mls_group.epoch().as_u64()));

        // 7. Emit event.
        self.events_buf
            .push_back(cgka_traits::engine::GroupEvent::GroupJoined {
                group_id: group_id.clone(),
                via_welcome: welcome_id,
            });

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
            };
        }
        Ok(acc)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn member_id_of_key_package(kp: &openmls::prelude::KeyPackage) -> Result<MemberId, EngineError> {
    let basic: BasicCredential = BasicCredential::try_from(kp.leaf_node().credential().clone())
        .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
    Ok(MemberId::new(basic.identity().to_vec()))
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
        let bc = BasicCredential::try_from(kp.leaf_node().credential().clone())
            .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
        let id = MemberId::new(bc.identity().to_vec());
        if !out.iter().any(|m| m.id == id) {
            out.push(Member {
                id,
                credential: kp.leaf_node().signature_key().as_slice().to_vec(),
            });
        }
    }
    Ok(out)
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
) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for (_f, req) in registry.iter() {
        out.insert(req.requires);
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
            &[],
            32,
        )
        .map_err(|e| EngineError::Backend(format!("export_secret: {e:?}")))?;
    let mut map = std::collections::HashMap::new();
    map.insert(EXPORTER_LABEL.to_string(), secret);
    Ok(cgka_traits::group_context::GroupContextSnapshot::new(
        EpochId(mls_group.epoch().as_u64()),
        map,
        None,
    ))
}

/// Mirror signed `marmot_group_data` into the local app-facing group record.
/// Missing legacy data leaves the record's existing values unchanged.
pub(crate) fn mirror_group_data_into_record(
    mls_group: &MlsGroup,
    record: &mut cgka_traits::group::Group,
) {
    if let Ok(Some(data)) = crate::group_data::read_from_group(mls_group) {
        record.name = String::from_utf8_lossy(data.name.as_slice()).into_owned();
        record.description = String::from_utf8_lossy(data.description.as_slice()).into_owned();
    }
}
