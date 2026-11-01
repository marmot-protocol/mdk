//! Marmot app-component state carried in OpenMLS `app_data_dictionary`.

use cgka_traits::agent_text_stream::AgentTextStreamQuicPolicyV1;
use cgka_traits::app_components::AGENT_TEXT_STREAM_QUIC_COMPONENT_ID;
use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, APP_COMPONENTS_COMPONENT_ID,
    AccountEntryV1, AppComponentData, AppComponentId, AppComponentSet, DEVICE_ROSTER_COMPONENT_ID,
    DEVICE_TAG_COMPONENT_ID, DeviceEntryV1, DeviceRosterV1, DeviceSlotId,
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID, GROUP_LIFECYCLE_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID, GroupLifecycleV1,
    GroupProfileV1, MAX_LEAVES_PER_ACCOUNT, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1,
    PROTOCOL_OWNED_APP_COMPONENT_IDS, SAFE_AAD_COMPONENT_ID, apply_device_roster_update_v1,
    decode_components_list, decode_device_roster_v1, decode_encrypted_media_policy_v1,
    decode_encrypted_media_policy_v2, decode_group_avatar_url_v1, decode_group_blossom_image_v1,
    decode_group_lifecycle_v1, decode_group_profile_v1, decode_nostr_routing_v1,
    decode_quic_varint, encode_component_vectors, encode_components_list,
    encode_group_lifecycle_v1, encode_group_profile_v1,
};
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::ingest::ProposalRejectionCategory;
use cgka_traits::types::{GroupId, MemberId};
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension, Extensions};
use openmls::group::{
    AppDataDictionaryUpdater, GroupContext, MlsGroup, ProcessMessageError, StageCommitError,
    StagedCommit, ValidationError,
};
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    BasicCredential, ContentType, ExtensionType, LeafNode, LeafNodeIndex, ProposalOrRefType,
    ProposalType, ProposalValidationError, QueuedProposal, Sender,
};
use openmls::treesync::Node;
use std::collections::{BTreeMap, BTreeSet};

/// Registry-level contract enforced for every current-profile group state.
///
/// These values are public so portable conformance vectors can cross-check
/// their implementation-neutral hexadecimal contract against the exact set the
/// engine validator consumes.
pub const CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_EXTENSIONS: [u16; 1] = [0x0006];
pub const CURRENT_PROFILE_REQUIRED_PROPOSALS: [u16; 1] = [0x0008];
pub const CURRENT_PROFILE_REQUIRED_APP_COMPONENTS: [AppComponentId; 2] = [
    GROUP_ADMIN_POLICY_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
];
pub const CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_STATE_COMPONENTS: [AppComponentId; 1] =
    [GROUP_ADMIN_POLICY_COMPONENT_ID];
pub const CURRENT_PROFILE_LEAF_ONLY_APP_COMPONENTS: [AppComponentId; 1] =
    [ACCOUNT_IDENTITY_PROOF_COMPONENT_ID];

/// Protocol components with no data at any location
/// (app-components/README.md, "Placement"). A group that requires one carries
/// no GroupContext state for it; the component's own rules say what an entry
/// under its id means.
const NO_DATA_APP_COMPONENTS: [AppComponentId; 1] = [ACCOUNT_DEVICES_COMPONENT_ID];

/// Protocol components whose data lives only in LeafNodes and that no group
/// may require (device-tag-v1.md, "Registry"). Unlike the account proof, a
/// GroupContext entry under one of these ids is unknown data, not an error.
/// Requiring one fails as an unsupported requirement, which is also how a
/// client that does not know the id rejects it, so both kinds of client agree.
const NEVER_REQUIRED_APP_COMPONENTS: [AppComponentId; 1] = [DEVICE_TAG_COMPONENT_ID];

/// Protocol-owned component ids this engine implements and may advertise in
/// its KeyPackages and leaves. A protocol id outside this list is refused by
/// [`validate_supported_app_components`]: advertising a component tells other
/// clients this one enforces its rules, and a group may then require it.
const ADVERTISABLE_PROTOCOL_APP_COMPONENTS: [AppComponentId; 13] = [
    APP_COMPONENTS_COMPONENT_ID,
    GROUP_PROFILE_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
    GROUP_ADMIN_POLICY_COMPONENT_ID,
    NOSTR_ROUTING_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID,
    AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
    GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
    GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    GROUP_LIFECYCLE_COMPONENT_ID,
    ACCOUNT_DEVICES_COMPONENT_ID,
];

/// Whether this build may advertise `marmot.account.device-roster.v1`. Its
/// wire format is unreleased until its spec lands (mdk#2628 3.1), so only
/// test-policy builds, which production never enables, implement it. A build
/// that cannot advertise it can never create or join a device group, and
/// treats roster bytes in other groups as unknown data.
const DEVICE_ROSTER_ADVERTISABLE: bool = cfg!(feature = "test-policy-overrides");

/// Refuse to advertise a protocol-owned component this engine does not
/// implement. Application-owned ids (at or above
/// `APP_OWNED_APP_COMPONENT_ID_START`) and ids the protocol has not assigned
/// stay the host's business.
pub(crate) fn validate_supported_app_components(
    supported: &AppComponentSet,
) -> Result<(), EngineError> {
    for component_id in &supported.ids {
        let advertisable = ADVERTISABLE_PROTOCOL_APP_COMPONENTS.contains(component_id)
            || (*component_id == DEVICE_ROSTER_COMPONENT_ID && DEVICE_ROSTER_ADVERTISABLE);
        if PROTOCOL_OWNED_APP_COMPONENT_IDS.contains(component_id) && !advertisable {
            return Err(EngineError::Other(format!(
                "engine cannot advertise protocol app component {component_id:#06x}: \
                 it does not implement it"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InitialComponentState {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) admins: Vec<[u8; 32]>,
    pub(crate) app_components: Vec<AppComponentData>,
    pub(crate) optional_app_components: Vec<AppComponentData>,
}

/// The `app_data_dictionary` of a new own LeafNode. A leaf that carries
/// `device_tag` also advertises `0x800f` (device-tag-v1.md, "Producing
/// tags"); the host never lists it among its supported components.
pub(crate) fn leaf_app_components_extension(
    supported: &AppComponentSet,
    account_identity_proof: Option<&[u8]>,
    device_tag: Option<Vec<u8>>,
) -> Result<Extension, EngineError> {
    let mut dict = AppDataDictionary::new();
    let mut advertised = supported.ids.clone();
    advertised.insert(APP_COMPONENTS_COMPONENT_ID);
    if account_identity_proof.is_some() {
        advertised.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID);
    }
    if device_tag.is_some() {
        advertised.insert(DEVICE_TAG_COMPONENT_ID);
    }
    dict.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&advertised),
    );
    dict.insert(
        SAFE_AAD_COMPONENT_ID,
        encode_components_list(&BTreeSet::new()),
    );
    if let Some(proof) = account_identity_proof {
        dict.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, proof.to_vec());
    }
    if let Some(tag) = device_tag {
        dict.insert(DEVICE_TAG_COMPONENT_ID, tag);
    }
    Ok(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dict),
    ))
}

pub(crate) fn app_components_of_leaf(leaf: &LeafNode) -> Result<AppComponentSet, EngineError> {
    app_components_of_leaf_extensions(leaf.extensions())
}

/// The app component ids a LeafNode with `extensions` advertises.
pub(crate) fn app_components_of_leaf_extensions(
    extensions: &Extensions<LeafNode>,
) -> Result<AppComponentSet, EngineError> {
    let Some(ext) = extensions.app_data_dictionary() else {
        return Ok(AppComponentSet::default());
    };
    let Some(bytes) = ext.dictionary().get(&APP_COMPONENTS_COMPONENT_ID) else {
        return Ok(AppComponentSet::default());
    };
    let ids = decode_components_list(bytes)
        .map_err(|e| EngineError::Serialize(format!("leaf app_components decode failed: {e}")))?;
    Ok(AppComponentSet::from(ids))
}

pub(crate) fn app_data_dictionary_extension_for_group(
    required: &AppComponentSet,
    initial: &InitialComponentState,
) -> Result<Extension, EngineError> {
    let mut dict = AppDataDictionary::new();
    dict.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&required.ids),
    );
    if required.contains(GROUP_PROFILE_COMPONENT_ID) {
        dict.insert(
            GROUP_PROFILE_COMPONENT_ID,
            encode_group_profile(&initial.name, &initial.description)?,
        );
    }
    if required.contains(GROUP_BLOSSOM_IMAGE_COMPONENT_ID) {
        // The spec's "absent image" encoding is five empty var-bytes fields
        // (group-blossom-image-v1.md), not zero bytes. `encode_component_vectors(&[])`
        // yields an empty Vec, which `validate_group_image` rejects (its first
        // `decode_var_bytes` fails on an empty cursor). Write the canonical
        // five-empty-fields absent state so the created GroupContext validates.
        dict.insert(
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
            encode_component_vectors(&[&[], &[], &[], &[], &[]]),
        );
    }
    if required.contains(GROUP_ADMIN_POLICY_COMPONENT_ID) {
        dict.insert(
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            encode_admin_policy(&initial.admins)?,
        );
    }
    if required.contains(GROUP_LIFECYCLE_COMPONENT_ID) {
        dict.insert(
            GROUP_LIFECYCLE_COMPONENT_ID,
            encode_group_lifecycle_v1(GroupLifecycleV1::Active),
        );
    }
    let mut seen_initial = BTreeSet::new();
    for component in &initial.app_components {
        if !seen_initial.insert(component.component_id) {
            return Err(EngineError::Other(
                "group creation request contains duplicate app components".into(),
            ));
        }
        validate_initial_app_component(component)?;
        if required.contains(component.component_id) {
            dict.insert(component.component_id, component.data.clone());
        }
    }
    for component in &initial.optional_app_components {
        if !seen_initial.insert(component.component_id) {
            return Err(EngineError::Other(
                "group creation request contains duplicate app components".into(),
            ));
        }
        // A roster entry in a group that does not require it would carry a
        // device-group marker's data without its rules.
        if component.component_id == DEVICE_ROSTER_COMPONENT_ID {
            return Err(EngineError::Other(
                "group creation request cannot carry an optional device roster".into(),
            ));
        }
        validate_initial_app_component(component)?;
        dict.insert(component.component_id, component.data.clone());
    }
    Ok(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dict),
    ))
}

pub(crate) fn required_app_components_of_group(
    mls_group: &MlsGroup,
) -> Result<AppComponentSet, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, APP_COMPONENTS_COMPONENT_ID) else {
        return Ok(AppComponentSet::default());
    };
    let ids = decode_components_list(bytes)
        .map_err(|e| EngineError::Serialize(format!("group app_components decode failed: {e}")))?;
    Ok(AppComponentSet::from(ids))
}

pub(crate) fn group_profile_of_group(
    mls_group: &MlsGroup,
) -> Result<Option<(String, String)>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_PROFILE_COMPONENT_ID) else {
        return Ok(None);
    };
    decode_group_profile(bytes).map(Some)
}

pub(crate) fn decode_group_profile(bytes: &[u8]) -> Result<(String, String), EngineError> {
    let profile = decode_group_profile_v1(bytes)
        .map_err(|e| EngineError::Serialize(format!("profile component decode failed: {e}")))?;
    Ok((profile.name, profile.description))
}

pub(crate) fn admins_of_group(mls_group: &MlsGroup) -> Result<Vec<[u8; 32]>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_ADMIN_POLICY_COMPONENT_ID) else {
        return Ok(Vec::new());
    };
    decode_admin_policy(bytes)
}

pub(crate) fn lifecycle_of_group(
    mls_group: &MlsGroup,
) -> Result<Option<GroupLifecycleV1>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_LIFECYCLE_COMPONENT_ID) else {
        return Ok(None);
    };
    decode_group_lifecycle_v1(bytes).map(Some).map_err(|error| {
        EngineError::Serialize(format!("invalid group lifecycle component: {error}"))
    })
}

pub(crate) fn app_component_data_of_group(
    mls_group: &MlsGroup,
    component_id: AppComponentId,
) -> Option<Vec<u8>> {
    app_component_bytes(mls_group, component_id).map(ToOwned::to_owned)
}

/// The device roster `mls_group` holds. `None` when it holds none or it
/// cannot be read.
pub(crate) fn device_roster_of_group(mls_group: &MlsGroup) -> Option<DeviceRosterV1> {
    app_component_bytes(mls_group, DEVICE_ROSTER_COMPONENT_ID)
        .and_then(|bytes| decode_device_roster_v1(bytes).ok())
}

/// The entry of `slot` in the device roster `mls_group` holds. `None` when
/// the roster lists no device there or cannot be read.
pub(crate) fn device_entry_of_group(
    mls_group: &MlsGroup,
    slot: &DeviceSlotId,
) -> Option<DeviceEntryV1> {
    device_roster_of_group(mls_group).and_then(|mut roster| roster.devices.remove(slot))
}

/// The account entry the device roster `mls_group` holds. `None` when the
/// roster cannot be read.
pub(crate) fn account_entry_of_group(mls_group: &MlsGroup) -> Option<AccountEntryV1> {
    device_roster_of_group(mls_group).map(|roster| roster.account)
}

pub(crate) fn message_retention_seconds_of_group(
    mls_group: &MlsGroup,
) -> Result<Option<u64>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_MESSAGE_RETENTION_COMPONENT_ID) else {
        return Ok(None);
    };
    let seconds = decode_message_retention(bytes)?;
    if seconds == 0 {
        Ok(None)
    } else {
        Ok(Some(seconds))
    }
}

pub(crate) fn nostr_routing_of_group(
    mls_group: &MlsGroup,
) -> Result<Option<NostrRoutingV1>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, NOSTR_ROUTING_COMPONENT_ID) else {
        return Ok(None);
    };
    decode_nostr_routing_v1(bytes)
        .map(Some)
        .map_err(|e| EngineError::Serialize(format!("Nostr routing component decode failed: {e}")))
}

pub(crate) fn transport_group_id_of_group(mls_group: &MlsGroup) -> Result<Vec<u8>, EngineError> {
    if let Some(routing) = nostr_routing_of_group(mls_group)? {
        return Ok(routing.nostr_group_id.to_vec());
    }
    Ok(mls_group.group_id().as_slice().to_vec())
}

pub(crate) fn require_admin(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    member_id: &MemberId,
) -> Result<(), EngineError> {
    let member_pubkey = admin_pubkey_from_member_id(member_id)?;
    let admins = admins_of_group(mls_group)?;
    if admins.iter().any(|admin| admin == &member_pubkey) {
        return Ok(());
    }
    Err(EngineError::NotGroupAdmin {
        group_id: group_id.clone(),
    })
}

/// Require an active admin committer for an admin-required Commit. `class` is
/// the Commit's [`crate::commit_class::CommitClass`] in `mls_group`, its
/// candidate parent state.
pub(crate) fn require_admin_for_staged_commit(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    sender: Option<&MemberId>,
    staged: &StagedCommit,
    class: crate::commit_class::CommitClass,
) -> Result<(), EngineError> {
    reject_admin_self_remove_proposals(mls_group, group_id, staged)?;
    if !class.requires_admin() {
        return Ok(());
    }
    let Some(sender) = sender else {
        return Err(EngineError::NotGroupAdmin {
            group_id: group_id.clone(),
        });
    };
    require_admin(mls_group, group_id, sender)
}

/// Receiving-flow step 8 (`protocol-core/joining.md`): the Welcome's `author`
/// may add in the `joined` state. An active admin may, and so may a device of
/// the `joiner`'s own account once that state requires
/// `marmot.group.account-devices.v1` ("Welcome acceptance"). Any other author
/// is [`EngineError::NotGroupAdmin`], an authorization failure.
pub(crate) fn require_welcome_author_authority(
    joined: &MlsGroup,
    group_id: &GroupId,
    author: &MemberId,
    joiner: &MemberId,
) -> Result<(), EngineError> {
    if author == joiner && group_requires_account_devices(joined)? {
        return Ok(());
    }
    require_admin(joined, group_id, author)
}

pub(crate) const fn proposal_rejection_category_tag(
    category: ProposalRejectionCategory,
) -> &'static str {
    match category {
        ProposalRejectionCategory::AuthorizationFailed => "authorization_failed",
        ProposalRejectionCategory::UnsupportedProposal => "unsupported_proposal",
        ProposalRejectionCategory::InvalidEncoding => "invalid_encoding",
        ProposalRejectionCategory::InvalidSignature => "invalid_signature",
        ProposalRejectionCategory::InvalidSelfRemove => "invalid_self_remove",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StandaloneProposalRejection {
    pub(crate) category: ProposalRejectionCategory,
}

impl StandaloneProposalRejection {
    const fn authorization(_reason: &'static str) -> Self {
        Self {
            category: ProposalRejectionCategory::AuthorizationFailed,
        }
    }

    const fn invalid_self_remove(_reason: &'static str) -> Self {
        Self {
            category: ProposalRejectionCategory::InvalidSelfRemove,
        }
    }

    const fn unsupported(_reason: &'static str) -> Self {
        Self {
            category: ProposalRejectionCategory::UnsupportedProposal,
        }
    }

    const fn invalid(_reason: &'static str) -> Self {
        Self {
            category: ProposalRejectionCategory::InvalidEncoding,
        }
    }
}

/// Membership-tag and sender-leaf authentication depend on the source-epoch
/// group state. A same-epoch proposal can therefore fail against the live
/// branch but authenticate against a retained parent branch.
pub(crate) fn is_parent_dependent_process_message_error<StorageError>(
    error: &ProcessMessageError<StorageError>,
    content_type: ContentType,
) -> bool {
    matches!(
        (content_type, error),
        (
            ContentType::Proposal,
            ProcessMessageError::ValidationError(
                ValidationError::UnknownMember | ValidationError::InvalidMembershipTag
            )
        )
    )
}

/// Map only proposal-specific MLS processing failures into the stable,
/// privacy-safe rejection taxonomy. Unrelated commit and local-state failures
/// remain retryable and therefore return `None`.
pub(crate) fn classify_process_message_rejection<StorageError>(
    error: &ProcessMessageError<StorageError>,
    content_type: ContentType,
) -> Option<ProposalRejectionCategory> {
    if is_parent_dependent_process_message_error(error, content_type) {
        return None;
    }
    match (content_type, error) {
        (ContentType::Proposal, ProcessMessageError::UnsupportedProposalType) => {
            Some(ProposalRejectionCategory::UnsupportedProposal)
        }
        (ContentType::Proposal, ProcessMessageError::IncompatibleWireFormat) => {
            Some(ProposalRejectionCategory::InvalidEncoding)
        }
        (ContentType::Proposal, ProcessMessageError::ValidationError(validation)) => {
            match validation {
                ValidationError::WrongEpoch => None,
                ValidationError::MissingMembershipTag
                | ValidationError::InvalidSignature
                | ValidationError::UnauthorizedExternalSender
                | ValidationError::NoExternalSendersExtension
                | ValidationError::InvalidLeafNodeSignature
                | ValidationError::InvalidSenderType => {
                    Some(ProposalRejectionCategory::InvalidSignature)
                }
                _ => Some(ProposalRejectionCategory::InvalidEncoding),
            }
        }
        (
            ContentType::Commit,
            ProcessMessageError::ValidationError(ValidationError::WrongWireFormat),
        ) => Some(ProposalRejectionCategory::InvalidEncoding),
        (
            ContentType::Commit,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                validation,
            )),
        ) => Some(match validation {
            ProposalValidationError::InsufficientCapabilities
            | ProposalValidationError::UnsupportedProposalType => {
                ProposalRejectionCategory::UnsupportedProposal
            }
            ProposalValidationError::UnknownMember
            | ProposalValidationError::UpdateFromNonMember => {
                ProposalRejectionCategory::InvalidSignature
            }
            _ => ProposalRejectionCategory::InvalidEncoding,
        }),
        (
            ContentType::Commit,
            ProcessMessageError::InvalidCommit(
                StageCommitError::AppDataUpdateValidationError(_)
                | StageCommitError::ApplyAppDataUpdateError(_)
                | StageCommitError::GroupContextExtensionsProposalValidationError(_)
                | StageCommitError::LeafNodeValidation(_),
            ),
        ) => Some(ProposalRejectionCategory::InvalidEncoding),
        _ => None,
    }
}

/// Authorize one authenticated proposal against its source-epoch group state.
///
/// This is shared by direct ingest, convergence replay, delayed SelfRemove
/// replay, and staged-Commit validation. OpenMLS has already authenticated the
/// sender and parsed the proposal before this function runs; this layer owns
/// Marmot roles, component semantics, profile rules, and capability checks.
pub(crate) fn authorize_standalone_proposal(
    mls_group: &MlsGroup,
    proposal: &QueuedProposal,
) -> Result<(), StandaloneProposalRejection> {
    authorize_proposal(mls_group, proposal, None)
}

/// `commit` is `None` when admitting a proposal on its own, and the class of
/// the Commit when re-authorizing the proposals that Commit carries. A
/// Commit's AppDataUpdate batch and its resulting state are validated as a
/// whole elsewhere, so the checks that need only the proposal and its source
/// state run here for standalone proposals alone.
fn authorize_proposal(
    mls_group: &MlsGroup,
    proposal: &QueuedProposal,
    commit: Option<crate::commit_class::CommitClass>,
) -> Result<(), StandaloneProposalRejection> {
    let standalone = commit.is_none();
    let Sender::Member(sender_index) = proposal.sender() else {
        return Err(StandaloneProposalRejection::authorization(
            "proposal_sender_not_member",
        ));
    };
    let Some(sender_member) = mls_group.member_at(*sender_index) else {
        return Err(StandaloneProposalRejection::authorization(
            "proposal_sender_not_current_member",
        ));
    };
    let sender_id = crate::identity::validated_member_id(&sender_member.credential)
        .map_err(|_| StandaloneProposalRejection::invalid("proposal_sender_identity_invalid"))?;
    let profile = crate::account_identity_proof::protocol_profile_of_group(mls_group)
        .map_err(|_| StandaloneProposalRejection::invalid("proposal_group_profile_invalid"))?;
    let admins = admins_of_group(mls_group)
        .map_err(|_| StandaloneProposalRejection::invalid("proposal_admin_policy_invalid"))?;
    let sender_pubkey = admin_pubkey_from_member_id(&sender_id)
        .map_err(|_| StandaloneProposalRejection::invalid("proposal_sender_identity_invalid"))?;
    let sender_is_admin = admins.iter().any(|admin| admin == &sender_pubkey);

    match proposal.proposal() {
        Proposal::SelfRemove => {
            if sender_is_admin {
                return Err(StandaloneProposalRejection::invalid_self_remove(
                    "self_remove_sender_is_active_admin",
                ));
            }
        }
        Proposal::AppDataUpdate(update) => {
            if !sender_is_admin {
                return Err(StandaloneProposalRejection::authorization(
                    "app_data_update_sender_not_admin",
                ));
            }
            if update.component_id() == GROUP_LIFECYCLE_COMPONENT_ID
                && proposal.proposal_or_ref_type() == ProposalOrRefType::Reference
            {
                return Err(StandaloneProposalRejection::invalid(
                    "group_lifecycle_update_must_be_inline",
                ));
            }
            if standalone {
                validate_standalone_app_data_update(update).map_err(|_| {
                    StandaloneProposalRejection::invalid("app_data_update_payload_invalid")
                })?;
                // The required list this update proposes, when it sets one.
                let proposed_required = match update.operation() {
                    AppDataUpdateOperation::Update(data)
                        if update.component_id() == APP_COMPONENTS_COMPONENT_ID =>
                    {
                        Some(AppComponentSet::from(
                            decode_components_list(data.as_slice()).map_err(|_| {
                                StandaloneProposalRejection::invalid(
                                    "app_data_update_payload_invalid",
                                )
                            })?,
                        ))
                    }
                    _ => None,
                };
                // device-tag-v1.md, "Registry": no group requires a
                // never-required LeafNode component, and neither does a
                // proposal.
                if proposed_required.as_ref().is_some_and(|ids| {
                    NEVER_REQUIRED_APP_COMPONENTS
                        .iter()
                        .any(|component_id| ids.contains(*component_id))
                }) {
                    return Err(StandaloneProposalRejection::invalid(
                        "app_components_require_never_required_component",
                    ));
                }
                // account-devices-v1.md, "Data": no AppDataUpdate targets the
                // component once its source state requires it. "Removal": no
                // proposal drops it from the required list either.
                let unrequires = proposed_required
                    .as_ref()
                    .is_some_and(|ids| !ids.contains(ACCOUNT_DEVICES_COMPONENT_ID));
                if (update.component_id() == ACCOUNT_DEVICES_COMPONENT_ID || unrequires)
                    && group_requires_account_devices(mls_group).map_err(|_| {
                        StandaloneProposalRejection::invalid("proposal_group_state_invalid")
                    })?
                {
                    return Err(StandaloneProposalRejection::invalid(if unrequires {
                        "app_components_unrequire_account_devices"
                    } else {
                        "account_devices_app_data_update"
                    }));
                }
                // device-roster: a group requires the roster from creation or
                // never, and a roster update applies to the source state.
                let roster_required = group_requires_device_roster(mls_group).map_err(|_| {
                    StandaloneProposalRejection::invalid("proposal_group_state_invalid")
                })?;
                if proposed_required
                    .as_ref()
                    .is_some_and(|ids| ids.contains(DEVICE_ROSTER_COMPONENT_ID) != roster_required)
                {
                    return Err(StandaloneProposalRejection::invalid(
                        "app_components_change_device_roster_requirement",
                    ));
                }
                if update.component_id() == DEVICE_ROSTER_COMPONENT_ID {
                    // device-roster-v1.md, "Removal": a device group keeps
                    // its roster, so no Commit can carry this removal.
                    if roster_required
                        && matches!(update.operation(), AppDataUpdateOperation::Remove)
                    {
                        return Err(StandaloneProposalRejection::invalid("device_roster_remove"));
                    }
                    resolved_app_data_update(
                        roster_required,
                        app_component_bytes(mls_group, DEVICE_ROSTER_COMPONENT_ID),
                        update,
                    )
                    .map_err(|_| {
                        StandaloneProposalRejection::invalid("device_roster_update_invalid")
                    })?;
                }
            }
        }
        Proposal::GroupContextExtensions(update) => {
            if !sender_is_admin {
                return Err(StandaloneProposalRejection::authorization(
                    "group_context_extensions_sender_not_admin",
                ));
            }
            let proposed_required =
                validate_group_context_extension_proposal(mls_group, profile, update.extensions())?;
            if standalone
                && profile == ProtocolProfile::Current
                && proposed_required.contains(DEVICE_ROSTER_COMPONENT_ID)
                    != group_requires_device_roster(mls_group).map_err(|_| {
                        StandaloneProposalRejection::invalid("proposal_group_state_invalid")
                    })?
            {
                return Err(StandaloneProposalRejection::invalid(
                    "group_context_extensions_change_device_roster_requirement",
                ));
            }
            // account-devices-v1.md, "Removal": a group that requires the
            // component keeps requiring it.
            if standalone
                && !proposed_required.contains(ACCOUNT_DEVICES_COMPONENT_ID)
                && group_requires_account_devices(mls_group).map_err(|_| {
                    StandaloneProposalRejection::invalid("proposal_group_state_invalid")
                })?
            {
                return Err(StandaloneProposalRejection::invalid(
                    "group_context_extensions_unrequire_account_devices",
                ));
            }
        }
        Proposal::Add(_) | Proposal::Remove(_) => {
            // account-devices-v1.md, "Authorization": in a same-account
            // Commit every proposal is the committer's own by-value Add or
            // Remove of its account's leaves, which needs no admin. Such
            // operations have no standalone authority.
            if !sender_is_admin && commit != Some(crate::commit_class::CommitClass::SameAccount) {
                return Err(StandaloneProposalRejection::authorization(
                    "membership_proposal_sender_not_admin",
                ));
            }
            validate_membership_proposal(mls_group, proposal)?;
        }
        Proposal::Update(_) => {
            // The current profile's only non-admin standalone proposal is
            // SelfRemove. Deployed legacy groups retain the ordinary MLS
            // member self-update proposal flow.
            if profile == ProtocolProfile::Current && !sender_is_admin {
                return Err(StandaloneProposalRejection::authorization(
                    "update_proposal_sender_not_admin",
                ));
            }
            validate_membership_proposal(mls_group, proposal)?;
        }
        Proposal::PreSharedKey(_)
        | Proposal::ReInit(_)
        | Proposal::ExternalInit(_)
        | Proposal::AppEphemeral(_)
        | Proposal::Custom(_) => {
            return Err(StandaloneProposalRejection::unsupported(
                "standalone_proposal_type_unsupported",
            ));
        }
    }

    Ok(())
}

/// Re-run proposal-sender authorization for every proposal carried by a
/// staged Commit of class `class`. By-reference proposals keep their original
/// authenticated sender; by-value proposals are attributed to the committer by
/// MLS.
pub(crate) fn authorize_staged_commit_proposals(
    mls_group: &MlsGroup,
    staged: &StagedCommit,
    class: crate::commit_class::CommitClass,
) -> Result<(), StandaloneProposalRejection> {
    for proposal in staged.queued_proposals() {
        authorize_proposal(mls_group, proposal, Some(class))?;
    }
    validate_app_data_update_batch(
        mls_group,
        staged.queued_proposals().filter_map(|proposal| {
            if let Proposal::AppDataUpdate(update) = proposal.proposal() {
                Some(update.as_ref())
            } else {
                None
            }
        }),
    )
    .map_err(|_| StandaloneProposalRejection::invalid("app_data_update_payload_invalid"))?;
    Ok(())
}

fn validate_membership_proposal(
    mls_group: &MlsGroup,
    proposal: &QueuedProposal,
) -> Result<(), StandaloneProposalRejection> {
    if let Proposal::Remove(remove) = proposal.proposal()
        && mls_group.member_at(remove.removed()).is_none()
    {
        return Err(StandaloneProposalRejection::invalid(
            "remove_target_not_current_member",
        ));
    }
    crate::account_identity_proof::validate_standalone_proposal_account_identity_proof(
        proposal,
        mls_group,
        mls_group.ciphersuite(),
    )
    .map_err(|_| StandaloneProposalRejection::invalid("proposal_account_proof_invalid"))
}

/// Validate a GroupContextExtensions proposal's state against the current
/// leaves and return the component ids it requires (none on the legacy
/// profile, which has no required-component list to check).
fn validate_group_context_extension_proposal(
    mls_group: &MlsGroup,
    profile: ProtocolProfile,
    extensions: &Extensions<GroupContext>,
) -> Result<AppComponentSet, StandaloneProposalRejection> {
    let required_components = if profile == ProtocolProfile::Current {
        validate_current_profile_group_context(extensions, "proposed group state").map_err(
            |_| {
                StandaloneProposalRejection::invalid(
                    "group_context_extensions_current_profile_invalid",
                )
            },
        )?
    } else {
        AppComponentSet::default()
    };
    let leaves = ratchet_tree_leaves(mls_group.export_ratchet_tree()).map_err(|_| {
        StandaloneProposalRejection::invalid("group_context_extensions_tree_invalid")
    })?;
    validate_resulting_leaf_capabilities(leaves.iter(), extensions, &required_components).map_err(
        |_| {
            StandaloneProposalRejection::unsupported(
                "group_context_extensions_not_supported_by_all_members",
            )
        },
    )?;
    // A roster the proposed state requires must be valid now, as every other
    // known component's bytes must; unknown data elsewhere stays opaque.
    validate_device_roster_state(extensions, &required_components, leaves.iter()).map_err(
        |_| StandaloneProposalRejection::invalid("group_context_extensions_device_roster_invalid"),
    )?;
    Ok(required_components)
}

pub(crate) fn credential_account_pubkey(cred: openmls::prelude::Credential) -> Option<[u8; 32]> {
    let basic = BasicCredential::try_from(cred).ok()?;
    <[u8; 32]>::try_from(basic.identity()).ok()
}

/// Enforce the admin-policy resulting-epoch invariant
/// (spec/app-components/admin-policy-v1.md): in the resulting epoch every admin
/// key MUST correspond to an account with at least one member leaf. A commit
/// that removes an account's last member leaf without dropping that account from
/// `admins` (or otherwise leaves an admin with no leaf) is invalid.
///
/// Validated PRE-merge from the staged commit's resulting GroupContext and its
/// membership changes: a post-merge rejection would be too late even though the
/// storage provider now wraps `merge_staged_commit` in a backend transaction.
pub(crate) fn validate_admin_leaf_coupling_for_staged_commit(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    staged: &StagedCommit,
) -> Result<(), EngineError> {
    // Resulting admins come from the staged (provisional) app_data_dictionary, so
    // an admin-policy update in this same commit is already reflected. When the
    // staged GroupContext carries no admin-policy bytes, the resulting epoch's
    // admin set is the prior epoch's set carried forward
    // (admin-policy-v1.md "Validation"), so evaluate against the current
    // group's admin set instead of skipping the check.
    let staged_admin_bytes = staged
        .group_context()
        .extensions()
        .app_data_dictionary()
        .and_then(|dict| dict.dictionary().get(&GROUP_ADMIN_POLICY_COMPONENT_ID));
    let resulting_admins = match staged_admin_bytes {
        Some(admin_bytes) => decode_admin_policy(admin_bytes)?,
        None => admins_of_group(mls_group)?,
    };
    // An empty carried-forward set means the current epoch has no admin-policy
    // state at all (component bytes cannot encode an empty list), so there is
    // no admin key to orphan and the check is vacuously satisfied. This is not
    // a bypass for admin-less groups: every commit shape that can remove
    // ANOTHER member's leaf requires an authenticated admin sender
    // (`require_admin_for_staged_commit`, enforced before this check on the
    // send, ingest, and convergence-replay paths), which fail-closes when the
    // admin set is empty; the leaf-removing shapes a non-admin may commit are
    // SelfRemove-only and same-account (`crate::commit_class`), which remove
    // only the committer's own account's leaves, so neither can de-leaf
    // another member.
    if resulting_admins.is_empty() {
        return Ok(());
    }

    // Leaves this commit removes: by-reference Remove proposals plus SelfRemove.
    let mut removed_leaves: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for remove in staged.remove_proposals() {
        removed_leaves.insert(remove.remove_proposal().removed().u32());
    }
    for queued in staged.queued_proposals() {
        if matches!(queued.proposal(), Proposal::SelfRemove)
            && let Sender::Member(leaf) = queued.sender()
        {
            removed_leaves.insert(leaf.u32());
        }
    }

    // Resulting member accounts: an account remains a member if ANY of its leaves
    // survives (multi-device), so collect surviving current leaves plus added
    // leaves by account.
    let mut accounts: BTreeSet<[u8; 32]> = BTreeSet::new();
    for member in mls_group.members() {
        if removed_leaves.contains(&member.index.u32()) {
            continue;
        }
        if let Some(pk) = credential_account_pubkey(member.credential) {
            accounts.insert(pk);
        }
    }
    for add in staged.add_proposals() {
        if let Some(pk) = credential_account_pubkey(
            add.add_proposal()
                .key_package()
                .leaf_node()
                .credential()
                .clone(),
        ) {
            accounts.insert(pk);
        }
    }

    if let Some(orphaned) = resulting_admins
        .iter()
        .find(|admin| !accounts.contains(*admin))
    {
        return Err(EngineError::UnknownMember {
            group_id: group_id.clone(),
            member: MemberId::new(orphaned.to_vec()),
        });
    }
    Ok(())
}

/// Reject (pre-merge) a commit whose resulting GroupContext strips or rewrites
/// Marmot component state outside the validated `AppDataUpdate` channel.
///
/// OpenMLS's draft-08 guard only validates the resulting dictionary against a
/// commit's `AppDataUpdate` proposals and returns early when there are none,
/// and the engine's component validators ([`validate_app_component_update`] /
/// [`validate_app_component_remove`]) likewise only run for `AppDataUpdate`
/// operations — so a `GroupContextExtensions`-only commit could otherwise
/// replace the extensions with a set that drops the `app_data_dictionary`
/// (making the group admin-less and freezing every admin-gated operation), or
/// keep every entry present while rewriting its bytes (swapping the admin set,
/// or corrupting profile/routing/retention state with bytes that never passed
/// the component validators).
///
/// Enforced rules, in order:
/// 1. the `app_data_dictionary` extension itself may never be dropped;
/// 2. the engine-owned `app_components` entry and the state entry of every
///    component in the resulting epoch's required set may never be dropped;
///    one Commit may atomically unrequire and remove an optional component;
/// 3. every dictionary entry that changes relative to the current epoch —
///    added, rewritten, or removed — must match one of this commit's own
///    `AppDataUpdate` operations, whose payloads passed the component
///    validators before the commit was staged.
pub(crate) fn validate_app_component_integrity_for_staged_commit(
    mls_group: &MlsGroup,
    _group_id: &GroupId,
    staged: &StagedCommit,
) -> Result<(), EngineError> {
    let current = mls_group.extensions().app_data_dictionary();
    let resulting = staged.group_context().extensions().app_data_dictionary();
    if current.is_some() && resulting.is_none() {
        return Err(EngineError::Other(
            "commit is invalid: resulting GroupContext drops the app_data_dictionary".into(),
        ));
    }
    let current = current.map(|ext| ext.dictionary());
    let resulting = resulting.map(|ext| ext.dictionary());

    // Protect the RESULTING required set. This deliberately permits one
    // authorized Commit to atomically unrequire and remove an optional
    // component, while still rejecting a required entry that disappears.
    let is_current = crate::account_identity_proof::protocol_profile_of_group(mls_group)?
        == ProtocolProfile::Current;
    let mut protected = if resulting
        .and_then(|dictionary| dictionary.get(&APP_COMPONENTS_COMPONENT_ID))
        .is_some()
    {
        required_app_components_of_extensions(
            staged.group_context().extensions(),
            "resulting GroupContext",
        )?
        .ids
    } else if is_current {
        return Err(EngineError::Other(
            "commit is invalid: resulting GroupContext drops current-profile app_components".into(),
        ));
    } else {
        BTreeSet::new()
    };
    if is_current
        || current.is_some_and(|dictionary| dictionary.contains(&APP_COMPONENTS_COMPONENT_ID))
    {
        protected.insert(APP_COMPONENTS_COMPONENT_ID);
    }
    for component_id in &protected {
        // The account proof is required by the GroupContext but its data is
        // LeafNode-only, and on the current profile a no-data component has
        // none at all. Neither has GroupContext state to keep. Legacy groups
        // keep every other required entry, as they always have.
        if *component_id == ACCOUNT_IDENTITY_PROOF_COMPONENT_ID
            || (is_current && NO_DATA_APP_COMPONENTS.contains(component_id))
        {
            continue;
        }
        let still_present = resulting.is_some_and(|dict| dict.contains(component_id));
        if !still_present {
            return Err(EngineError::Other(format!(
                "commit is invalid: resulting GroupContext drops required app component \
                 {component_id:#06x}"
            )));
        }
    }

    // This commit's AppDataUpdate operations by component id: the exact set of
    // resulting values a changed entry is allowed to take, resolved against
    // the parent as every path resolves them. `None` is a Remove.
    let roster_required = group_requires_device_roster(mls_group)?;
    let mut update_ops: BTreeMap<AppComponentId, Vec<Option<Vec<u8>>>> = BTreeMap::new();
    for queued in staged.queued_proposals() {
        if let Proposal::AppDataUpdate(update) = queued.proposal() {
            let parent_bytes = current.and_then(|dict| dict.get(&update.component_id()));
            let op = resolved_app_data_update(roster_required, parent_bytes, update)?;
            update_ops
                .entry(update.component_id())
                .or_default()
                .push(op);
        }
    }
    let component_ids: BTreeSet<AppComponentId> = current
        .into_iter()
        .chain(resulting)
        .flat_map(|dict| dict.entries().map(|entry| entry.id()))
        .collect();
    for component_id in component_ids {
        let before = current.and_then(|dict| dict.get(&component_id));
        let after = resulting.and_then(|dict| dict.get(&component_id));
        if before == after {
            continue;
        }
        let update_backed = update_ops
            .get(&component_id)
            .is_some_and(|ops| ops.iter().any(|op| op.as_deref() == after));
        if !update_backed {
            return Err(EngineError::Other(format!(
                "commit is invalid: resulting GroupContext changes app component \
                 {component_id:#06x} outside an AppDataUpdate proposal"
            )));
        }
    }
    Ok(())
}

/// Validate the complete current application profile carried by an already
/// materialized MLS group.
///
/// Legacy groups deliberately skip these current-profile requirements. Their
/// deployed proof/component rules remain selected by their explicit profile.
pub(crate) fn validate_current_profile_group_invariants(
    group: &MlsGroup,
) -> Result<(), EngineError> {
    let profile = crate::account_identity_proof::protocol_profile_of_group(group)?;
    if profile == ProtocolProfile::Legacy {
        return Ok(());
    }
    let required_components =
        validate_current_profile_group_context(group.extensions(), "group state")?;
    let leaves = ratchet_tree_leaves(group.export_ratchet_tree())?;
    validate_resulting_leaf_capabilities(leaves.iter(), group.extensions(), &required_components)?;
    validate_account_devices_state(group.extensions(), &required_components, &leaves)?;
    validate_device_roster_state(group.extensions(), &required_components, &leaves)
}

/// Receiving-flow step 7 (`protocol-core/joining.md`) for the state a Welcome
/// joins: [`validate_current_profile_group_invariants`], and the GroupInfo
/// rule of `marmot.group.account-devices.v1` ("Data"): when the joined state
/// requires the component, the GroupInfo carries no entry under its id.
/// `group_info_app_data` is the GroupInfo's `app_data_dictionary`, which the
/// caller reads before OpenMLS stages the Welcome and drops the GroupInfo.
pub(crate) fn validate_joined_group_invariants(
    joined: &MlsGroup,
    group_info_app_data: Option<&AppDataDictionaryExtension>,
) -> Result<(), EngineError> {
    validate_current_profile_group_invariants(joined)?;
    if carries_account_devices_data(group_info_app_data) && group_requires_account_devices(joined)?
    {
        return Err(EngineError::Other(
            "invalid account-devices state: the GroupInfo carries account-devices data".into(),
        ));
    }
    Ok(())
}

/// Validate current-profile invariants against the complete state a staged
/// Commit would produce, before the Commit can mutate canonical group state.
pub(crate) fn validate_current_profile_invariants_for_staged_commit(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer_index: LeafNodeIndex,
) -> Result<(), EngineError> {
    let profile = crate::account_identity_proof::protocol_profile_of_group(group)?;
    if profile == ProtocolProfile::Legacy {
        return Ok(());
    }
    let extensions = staged.group_context().extensions();
    let required_components =
        validate_current_profile_group_context(extensions, "resulting group state")?;
    let leaves = conceptual_resulting_leaves(group, staged, committer_index)?;
    validate_resulting_leaf_capabilities(leaves.iter(), extensions, &required_components)?;
    validate_account_devices_transition(group, staged, &required_components)?;
    validate_account_devices_state(extensions, &required_components, &leaves)?;
    validate_device_roster_transition(group, &required_components)?;
    validate_device_roster_state(extensions, &required_components, &leaves)?;
    validate_group_lifecycle_transition(group, staged, committer_index)
}

/// Whether `group` requires `marmot.group.account-devices.v1`. A group on
/// the legacy profile never does: its rules predate the component, so the id
/// in a legacy required list changes nothing, as for clients that predate it.
pub(crate) fn group_requires_account_devices(group: &MlsGroup) -> Result<bool, EngineError> {
    if crate::account_identity_proof::protocol_profile_of_group(group)? == ProtocolProfile::Legacy {
        return Ok(false);
    }
    Ok(required_app_components_of_group(group)?.contains(ACCOUNT_DEVICES_COMPONENT_ID))
}

/// Whether an `app_data_dictionary`, at any location, carries an entry under
/// `marmot.group.account-devices.v1`, which defines none.
pub(crate) fn carries_account_devices_data(
    dictionary: Option<&AppDataDictionaryExtension>,
) -> bool {
    dictionary.is_some_and(|ext| ext.dictionary().contains(&ACCOUNT_DEVICES_COMPONENT_ID))
}

/// Whether `group` requires `marmot.account.device-roster.v1`, which marks
/// it as a device group. A group on the legacy profile never does, as for
/// account-devices.
pub(crate) fn group_requires_device_roster(group: &MlsGroup) -> Result<bool, EngineError> {
    if crate::account_identity_proof::protocol_profile_of_group(group)? == ProtocolProfile::Legacy {
        return Ok(false);
    }
    Ok(required_app_components_of_group(group)?.contains(DEVICE_ROSTER_COMPONENT_ID))
}

/// The resulting GroupContext bytes of one AppDataUpdate operation, given the
/// parent's bytes for its component. `None` removes the entry.
///
/// Every other v1 component's update replaces its state whole. While the
/// parent requires the device roster, a roster update is a diff applied to the
/// parent's roster instead. Before a group requires the roster, its bytes are
/// unknown data and replace whole like any other's. Every send, inbound and
/// replay path resolves updates here, so all of them compute the same state.
pub(crate) fn resolved_app_data_update(
    roster_required: bool,
    parent_bytes: Option<&[u8]>,
    update: &AppDataUpdateProposal,
) -> Result<Option<Vec<u8>>, EngineError> {
    let AppDataUpdateOperation::Update(data) = update.operation() else {
        return Ok(None);
    };
    if roster_required && update.component_id() == DEVICE_ROSTER_COMPONENT_ID {
        let prior = parent_bytes.ok_or_else(|| {
            EngineError::Other(
                "invalid device roster state: the required roster has no GroupContext state".into(),
            )
        })?;
        return apply_device_roster_update_v1(prior, data.as_slice())
            .map(Some)
            .map_err(|error| {
                EngineError::Serialize(format!("invalid device roster update: {error}"))
            });
    }
    Ok(Some(data.as_slice().to_vec()))
}

/// Mirror `updates` into `updater` as resulting GroupContext bytes, each
/// resolved by [`resolved_app_data_update`] against the parent bytes the
/// updater holds. `roster_required` is whether the parent requires the
/// device roster ([`group_requires_device_roster`]).
pub(crate) fn apply_app_data_updates<'a>(
    roster_required: bool,
    updater: &mut AppDataDictionaryUpdater<'_>,
    updates: impl IntoIterator<Item = &'a AppDataUpdateProposal>,
) -> Result<(), EngineError> {
    for update in updates {
        let component_id = update.component_id();
        match resolved_app_data_update(roster_required, updater.old_value(component_id), update)? {
            Some(data) => updater.set(ComponentData::from_parts(component_id, data.into())),
            None => updater.remove(&component_id),
        }
    }
    Ok(())
}

/// The state rules of `marmot.account.device-roster.v1`, for a state whose
/// required list is `required`. They apply only while that list contains the
/// component; before that, roster bytes are unknown data.
///
/// - The roster decodes canonically and keeps its own invariants (at most
///   [`MAX_LEAVES_PER_ACCOUNT`] devices, no slot both a device and rejected).
///   That its entry is present is the generic required-state check.
/// - Every leaf is the same account: a device group holds only the devices of
///   one account.
fn validate_device_roster_state<'a>(
    extensions: &Extensions<GroupContext>,
    required: &AppComponentSet,
    leaves: impl IntoIterator<Item = &'a LeafNode>,
) -> Result<(), EngineError> {
    if !required.contains(DEVICE_ROSTER_COMPONENT_ID) {
        return Ok(());
    }
    let bytes = extensions
        .app_data_dictionary()
        .and_then(|dictionary| dictionary.dictionary().get(&DEVICE_ROSTER_COMPONENT_ID))
        .ok_or_else(|| {
            EngineError::Other(
                "invalid device roster state: the required roster has no GroupContext state".into(),
            )
        })?;
    decode_device_roster_v1(bytes)
        .map_err(|error| EngineError::Serialize(format!("invalid device roster state: {error}")))?;
    let mut account: Option<Vec<u8>> = None;
    for leaf in leaves {
        let identity = BasicCredential::try_from(leaf.credential().clone())
            .map_err(|_| {
                EngineError::Other(
                    "invalid device roster state: a leaf has no basic credential".into(),
                )
            })?
            .identity()
            .to_vec();
        match &account {
            None => account = Some(identity),
            Some(account) if *account != identity => {
                return Err(EngineError::Other(
                    "invalid device roster state: a device group holds another account's leaf"
                        .into(),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// The Commit rule of `marmot.account.device-roster.v1`: a group requires the
/// roster from its creation or never. A Commit may neither start nor stop
/// requiring it, whoever commits it.
fn validate_device_roster_transition(
    parent: &MlsGroup,
    resulting_required: &AppComponentSet,
) -> Result<(), EngineError> {
    if group_requires_device_roster(parent)?
        != resulting_required.contains(DEVICE_ROSTER_COMPONENT_ID)
    {
        return Err(EngineError::Other(
            "commit is invalid: a group requires the device roster from creation or never".into(),
        ));
    }
    Ok(())
}

/// The state rules of `marmot.group.account-devices.v1`, for a state whose
/// required list is `required`. They apply only while that list contains the
/// component; before that, an entry under its id is unknown data.
///
/// - "Data": no entry under the id in the GroupContext or in any leaf.
/// - "Leaf limit": at most [`MAX_LEAVES_PER_ACCOUNT`] leaves per credential
///   identity.
///
/// The support invariant is the generic required-component check
/// ([`validate_resulting_leaf_capabilities`]), which the caller runs first.
fn validate_account_devices_state<'a>(
    extensions: &Extensions<GroupContext>,
    required: &AppComponentSet,
    leaves: impl IntoIterator<Item = &'a LeafNode>,
) -> Result<(), EngineError> {
    if !required.contains(ACCOUNT_DEVICES_COMPONENT_ID) {
        return Ok(());
    }
    if carries_account_devices_data(extensions.app_data_dictionary()) {
        return Err(EngineError::Other(
            "invalid account-devices state: GroupContext carries account-devices data".into(),
        ));
    }
    let mut leaves_per_account: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for leaf in leaves {
        if carries_account_devices_data(leaf.extensions().app_data_dictionary()) {
            return Err(EngineError::Other(
                "invalid account-devices state: a leaf carries account-devices data".into(),
            ));
        }
        let identity = BasicCredential::try_from(leaf.credential().clone())
            .map_err(|_| {
                EngineError::Other(
                    "invalid account-devices state: a leaf has no basic credential".into(),
                )
            })?
            .identity()
            .to_vec();
        let count = leaves_per_account.entry(identity).or_default();
        *count += 1;
        if *count > MAX_LEAVES_PER_ACCOUNT {
            return Err(EngineError::Other(format!(
                "invalid account-devices state: an account holds more than \
                 {MAX_LEAVES_PER_ACCOUNT} leaves"
            )));
        }
    }
    Ok(())
}

/// The Commit rules of `marmot.group.account-devices.v1`, which read the
/// candidate parent or what the Commit adds:
///
/// - "Removal": a Commit whose parent requires the component keeps requiring
///   it.
/// - "Data": such a Commit carries no AppDataUpdate for the component, and a
///   Commit whose resulting state requires it adds no KeyPackage with a
///   KeyPackage-level entry under its id. An entry in the KeyPackage's leaf is
///   a leaf entry, which [`validate_account_devices_state`] covers.
fn validate_account_devices_transition(
    parent: &MlsGroup,
    staged: &StagedCommit,
    resulting_required: &AppComponentSet,
) -> Result<(), EngineError> {
    if group_requires_account_devices(parent)? {
        if !resulting_required.contains(ACCOUNT_DEVICES_COMPONENT_ID) {
            return Err(EngineError::Other(
                "commit is invalid: account-devices cannot be un-required".into(),
            ));
        }
        if staged.queued_proposals().any(|queued| {
            matches!(
                queued.proposal(),
                Proposal::AppDataUpdate(update)
                    if update.component_id() == ACCOUNT_DEVICES_COMPONENT_ID
            )
        }) {
            return Err(EngineError::Other(
                "commit is invalid: AppDataUpdate targets account-devices".into(),
            ));
        }
    }
    if resulting_required.contains(ACCOUNT_DEVICES_COMPONENT_ID)
        && staged.add_proposals().any(|add| {
            carries_account_devices_data(
                add.add_proposal()
                    .key_package()
                    .extensions()
                    .app_data_dictionary(),
            )
        })
    {
        return Err(EngineError::Other(
            "commit is invalid: an added KeyPackage carries account-devices data".into(),
        ));
    }
    Ok(())
}

fn lifecycle_from_extensions(
    extensions: &Extensions<GroupContext>,
) -> Result<Option<GroupLifecycleV1>, EngineError> {
    let Some(bytes) = extensions
        .app_data_dictionary()
        .and_then(|dictionary| dictionary.dictionary().get(&GROUP_LIFECYCLE_COMPONENT_ID))
    else {
        return Ok(None);
    };
    decode_group_lifecycle_v1(bytes).map(Some).map_err(|error| {
        EngineError::Serialize(format!("invalid group lifecycle component: {error}"))
    })
}

pub(crate) fn staged_commit_disbands(
    group: &MlsGroup,
    staged: &StagedCommit,
) -> Result<bool, EngineError> {
    Ok(
        lifecycle_from_extensions(group.extensions())? == Some(GroupLifecycleV1::Active)
            && lifecycle_from_extensions(staged.group_context().extensions())?
                == Some(GroupLifecycleV1::Disbanded),
    )
}

/// Enforce lifecycle-v1 transition and terminal Commit shape at the shared
/// staged-Commit chokepoint used by local sends, direct ingest, convergence
/// replay, and fork recovery.
pub(crate) fn validate_group_lifecycle_transition(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer_index: LeafNodeIndex,
) -> Result<(), EngineError> {
    let before = lifecycle_from_extensions(group.extensions())?;
    let after = lifecycle_from_extensions(staged.group_context().extensions())?;
    let before_required =
        required_app_components_of_group(group)?.contains(GROUP_LIFECYCLE_COMPONENT_ID);
    let after_required = required_app_components_of_extensions(
        staged.group_context().extensions(),
        "resulting group state",
    )?
    .contains(GROUP_LIFECYCLE_COMPONENT_ID);

    if before == Some(GroupLifecycleV1::Disbanded) {
        return Err(EngineError::Other(
            "commit is invalid: Disbanded has no outgoing transition".into(),
        ));
    }

    let enabling = !before_required && after_required;
    if before_required && !after_required {
        return Err(EngineError::Other(
            "commit is invalid: lifecycle-v1 cannot be un-required".into(),
        ));
    }
    if enabling {
        if after != Some(GroupLifecycleV1::Active) {
            return Err(EngineError::Other(
                "commit is invalid: lifecycle enablement must install Active".into(),
            ));
        }
        for queued in staged.queued_proposals() {
            if queued.proposal_or_ref_type() != ProposalOrRefType::Proposal {
                return Err(EngineError::Other(
                    "commit is invalid: lifecycle enablement proposals must be inline".into(),
                ));
            }
            match queued.proposal() {
                Proposal::AppDataUpdate(update)
                    if matches!(
                        update.component_id(),
                        APP_COMPONENTS_COMPONENT_ID | GROUP_LIFECYCLE_COMPONENT_ID
                    ) => {}
                _ => {
                    return Err(EngineError::Other(
                        "commit is invalid: lifecycle enablement contains unrelated proposals"
                            .into(),
                    ));
                }
            }
        }
        return Ok(());
    }

    if before != Some(GroupLifecycleV1::Active) || after != Some(GroupLifecycleV1::Disbanded) {
        if before != after {
            return Err(EngineError::Other(
                "commit is invalid: unsupported group lifecycle transition".into(),
            ));
        }
        if staged.queued_proposals().any(|queued| {
            matches!(
                queued.proposal(),
                Proposal::AppDataUpdate(update)
                    if update.component_id() == GROUP_LIFECYCLE_COMPONENT_ID
            )
        }) {
            return Err(EngineError::Other(
                "commit is invalid: redundant lifecycle update".into(),
            ));
        }
        return Ok(());
    }

    if !before_required || !after_required {
        return Err(EngineError::Other(
            "commit is invalid: disband requires lifecycle-v1 in the parent and result".into(),
        ));
    }

    let committer = group
        .member_at(committer_index)
        .ok_or_else(|| EngineError::Other("commit is invalid: committer leaf is absent".into()))?;
    let committer_id = crate::identity::validated_member_id(&committer.credential)?;
    let committer_admin = admin_pubkey_from_member_id(&committer_id)?;
    let mut lifecycle_updates = 0usize;
    let mut admin_updates = 0usize;
    let mut removed = BTreeSet::new();

    for queued in staged.queued_proposals() {
        if queued.proposal_or_ref_type() != ProposalOrRefType::Proposal {
            return Err(EngineError::Other(
                "commit is invalid: every disband proposal must be inline".into(),
            ));
        }
        match queued.proposal() {
            Proposal::Remove(remove) => {
                removed.insert(remove.removed().u32());
            }
            Proposal::AppDataUpdate(update)
                if update.component_id() == GROUP_LIFECYCLE_COMPONENT_ID =>
            {
                let AppDataUpdateOperation::Update(data) = update.operation() else {
                    return Err(EngineError::Other(
                        "commit is invalid: lifecycle component cannot be removed".into(),
                    ));
                };
                if decode_group_lifecycle_v1(data.as_slice()).map_err(|error| {
                    EngineError::Serialize(format!("invalid group lifecycle component: {error}"))
                })? != GroupLifecycleV1::Disbanded
                {
                    return Err(EngineError::Other(
                        "commit is invalid: terminal lifecycle update is not Disbanded".into(),
                    ));
                }
                lifecycle_updates += 1;
            }
            Proposal::AppDataUpdate(update)
                if update.component_id() == GROUP_ADMIN_POLICY_COMPONENT_ID =>
            {
                let AppDataUpdateOperation::Update(data) = update.operation() else {
                    return Err(EngineError::Other(
                        "commit is invalid: disband must replace the admin policy".into(),
                    ));
                };
                if decode_admin_policy(data.as_slice())? != vec![committer_admin] {
                    return Err(EngineError::Other(
                        "commit is invalid: disband admin policy must contain only the committer"
                            .into(),
                    ));
                }
                admin_updates += 1;
            }
            _ => {
                return Err(EngineError::Other(
                    "commit is invalid: disband contains a forbidden proposal".into(),
                ));
            }
        }
    }
    if lifecycle_updates != 1 || admin_updates != 1 {
        return Err(EngineError::Other(
            "commit is invalid: disband needs exactly one lifecycle and one admin-policy update"
                .into(),
        ));
    }

    let expected: BTreeSet<u32> = group
        .members()
        .filter_map(|member| (member.index != committer_index).then_some(member.index.u32()))
        .collect();
    if removed != expected {
        return Err(EngineError::Other(
            "commit is invalid: disband must remove every source-state leaf except the committer"
                .into(),
        ));
    }
    Ok(())
}

fn validate_current_profile_group_context(
    extensions: &Extensions<GroupContext>,
    context: &str,
) -> Result<AppComponentSet, EngineError> {
    let required = extensions.required_capabilities().ok_or_else(|| {
        EngineError::Other(format!(
            "invalid current-profile {context}: missing required_capabilities"
        ))
    })?;
    if !CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_EXTENSIONS
        .iter()
        .all(|extension_type| {
            required
                .extension_types()
                .contains(&ExtensionType::from(*extension_type))
        })
    {
        return Err(EngineError::Other(format!(
            "invalid current-profile {context}: app_data_dictionary is not a required extension"
        )));
    }
    if !CURRENT_PROFILE_REQUIRED_PROPOSALS
        .iter()
        .all(|proposal_type| {
            required
                .proposal_types()
                .contains(&ProposalType::from(*proposal_type))
        })
    {
        return Err(EngineError::Other(format!(
            "invalid current-profile {context}: app_data_update is not a required proposal"
        )));
    }

    let dictionary = extensions.app_data_dictionary().ok_or_else(|| {
        EngineError::Other(format!(
            "invalid current-profile {context}: missing app_data_dictionary"
        ))
    })?;
    let required_components = required_app_components_of_extensions(extensions, context)?;
    if required_components.contains(GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID)
        || dictionary
            .dictionary()
            .contains(&GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID)
    {
        return Err(EngineError::Other(format!(
            "invalid current-profile {context}: frozen encrypted-media V1 component \
             {GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID:#06x} is not permitted"
        )));
    }
    for mandatory in CURRENT_PROFILE_REQUIRED_APP_COMPONENTS {
        if !required_components.contains(mandatory) {
            return Err(EngineError::Other(format!(
                "invalid current-profile {context}: missing mandatory component requirement \
                 {mandatory:#06x}"
            )));
        }
    }
    for component_id in CURRENT_PROFILE_LEAF_ONLY_APP_COMPONENTS {
        if dictionary.dictionary().contains(&component_id) {
            return Err(EngineError::Other(format!(
                "invalid current-profile {context}: leaf-only account proof appears in GroupContext"
            )));
        }
    }
    for component_id in CURRENT_PROFILE_REQUIRED_GROUP_CONTEXT_STATE_COMPONENTS {
        if !dictionary.dictionary().contains(&component_id) {
            return Err(EngineError::Other(format!(
                "invalid current-profile {context}: required component {component_id:#06x} \
                 has no GroupContext state"
            )));
        }
    }

    for entry in dictionary.dictionary().entries() {
        validate_app_component_bytes(entry.id(), entry.data())?;
    }
    for component_id in &required_components.ids {
        if CURRENT_PROFILE_LEAF_ONLY_APP_COMPONENTS.contains(component_id)
            || NO_DATA_APP_COMPONENTS.contains(component_id)
        {
            continue;
        }
        if !is_known_group_component(*component_id) {
            return Err(EngineError::Other(format!(
                "invalid current-profile {context}: unsupported required component \
                 {component_id:#06x}"
            )));
        }
        if !dictionary.dictionary().contains(component_id) {
            return Err(EngineError::Other(format!(
                "invalid current-profile {context}: required component {component_id:#06x} \
                 has no GroupContext state"
            )));
        }
    }
    Ok(required_components)
}

fn required_app_components_of_extensions(
    extensions: &Extensions<GroupContext>,
    context: &str,
) -> Result<AppComponentSet, EngineError> {
    let dictionary = extensions.app_data_dictionary().ok_or_else(|| {
        EngineError::Other(format!("invalid {context}: missing app_data_dictionary"))
    })?;
    let bytes = dictionary
        .dictionary()
        .get(&APP_COMPONENTS_COMPONENT_ID)
        .ok_or_else(|| {
            EngineError::Other(format!(
                "invalid {context}: missing app_components requirement list"
            ))
        })?;
    let ids = decode_components_list(bytes).map_err(|error| {
        EngineError::Serialize(format!("invalid {context} app_components: {error}"))
    })?;
    Ok(AppComponentSet::from(ids))
}

fn is_known_group_component(component_id: AppComponentId) -> bool {
    // Protocol-owned minus the ids that carry no GroupContext state at all:
    // the leaf-only account proof, the no-data components and the
    // never-required LeafNode components. Reading the canonical list keeps a
    // newly assigned component id format-validated without editing this
    // function.
    PROTOCOL_OWNED_APP_COMPONENT_IDS.contains(&component_id)
        && !CURRENT_PROFILE_LEAF_ONLY_APP_COMPONENTS.contains(&component_id)
        && !NO_DATA_APP_COMPONENTS.contains(&component_id)
        && !NEVER_REQUIRED_APP_COMPONENTS.contains(&component_id)
}

pub(crate) fn ratchet_tree_nodes(
    tree: openmls::treesync::RatchetTree,
) -> Result<Vec<Option<Node>>, EngineError> {
    // RatchetTree intentionally keeps its node vector private. Its stable
    // serde representation exposes the same public Node enum that MDK already
    // uses for cold-path proof and capability validation.
    let value = serde_json::to_value(tree)
        .map_err(|error| EngineError::Backend(format!("export ratchet tree: {error}")))?;
    serde_json::from_value(value)
        .map_err(|error| EngineError::Backend(format!("decode ratchet tree: {error}")))
}

pub(crate) fn ratchet_tree_leaves(
    tree: openmls::treesync::RatchetTree,
) -> Result<Vec<LeafNode>, EngineError> {
    Ok(ratchet_tree_nodes(tree)?
        .into_iter()
        .filter_map(|node| match node {
            Some(Node::LeafNode(leaf)) => Some(*leaf),
            _ => None,
        })
        .collect())
}

/// Deduplicated account identifiers for current leaves that have not yet
/// advertised lifecycle-v1 support.
pub(crate) fn lifecycle_support_blockers(group: &MlsGroup) -> Result<Vec<MemberId>, EngineError> {
    app_component_support_blockers(group, GROUP_LIFECYCLE_COMPONENT_ID)
}

/// Deduplicated account identifiers for current leaves that do not advertise
/// `component_id`. An empty result means the group is eligible to require it.
/// The tree walk is leaf-precise, so one device's support never stands in for
/// a sibling's.
pub(crate) fn app_component_support_blockers(
    group: &MlsGroup,
    component_id: AppComponentId,
) -> Result<Vec<MemberId>, EngineError> {
    let mut seen = std::collections::HashSet::new();
    let mut blockers = Vec::new();
    for leaf in ratchet_tree_leaves(group.export_ratchet_tree())? {
        if !app_components_of_leaf(&leaf)?.contains(component_id) {
            let member = crate::identity::validated_member_id_of_leaf(&leaf)?;
            if seen.insert(member.clone()) {
                blockers.push(member);
            }
        }
    }
    Ok(blockers)
}

fn indexed_ratchet_tree_leaves(
    tree: openmls::treesync::RatchetTree,
) -> Result<BTreeMap<u32, LeafNode>, EngineError> {
    let mut leaves = BTreeMap::new();
    for (node_index, node) in ratchet_tree_nodes(tree)?.into_iter().enumerate() {
        if let Some(Node::LeafNode(leaf)) = node {
            let leaf_index = u32::try_from(node_index / 2)
                .map_err(|_| EngineError::Backend("ratchet tree index overflow".into()))?;
            leaves.insert(leaf_index, *leaf);
        }
    }
    Ok(leaves)
}

fn conceptual_resulting_leaves(
    group: &MlsGroup,
    staged: &StagedCommit,
    committer_index: LeafNodeIndex,
) -> Result<Vec<LeafNode>, EngineError> {
    let mut leaves = indexed_ratchet_tree_leaves(group.export_ratchet_tree())?;
    for remove in staged.remove_proposals() {
        leaves.remove(&remove.remove_proposal().removed().u32());
    }
    for queued in staged.queued_proposals() {
        if matches!(queued.proposal(), Proposal::SelfRemove)
            && let Sender::Member(index) = queued.sender()
        {
            leaves.remove(&index.u32());
        }
    }
    for update in staged.update_proposals() {
        let Sender::Member(index) = update.sender() else {
            return Err(EngineError::Other(
                "invalid resulting group state: Update has no member sender".into(),
            ));
        };
        leaves.insert(index.u32(), update.update_proposal().leaf_node().clone());
    }
    if let Some(path_leaf) = staged.update_path_leaf_node() {
        leaves.insert(committer_index.u32(), path_leaf.clone());
    }
    let mut result = leaves.into_values().collect::<Vec<_>>();
    result.extend(
        staged
            .add_proposals()
            .map(|add| add.add_proposal().key_package().leaf_node().clone()),
    );
    Ok(result)
}

fn validate_resulting_leaf_capabilities<'a>(
    leaves: impl Iterator<Item = &'a LeafNode>,
    extensions: &Extensions<GroupContext>,
    required_components: &AppComponentSet,
) -> Result<(), EngineError> {
    let required = extensions.required_capabilities().ok_or_else(|| {
        EngineError::Other(
            "invalid current-profile group state: missing required_capabilities".into(),
        )
    })?;
    for leaf in leaves {
        let capabilities = leaf.capabilities();
        let supports_required = required.extension_types().iter().all(|required| {
            crate::capabilities::DEFAULT_MLS_EXTENSION_TYPES.contains(&u16::from(*required))
                || capabilities.extensions().contains(required)
        }) && required.proposal_types().iter().all(|required| {
            crate::capabilities::DEFAULT_MLS_PROPOSAL_TYPES.contains(&u16::from(*required))
                || capabilities.proposals().contains(required)
        }) && required
            .credential_types()
            .iter()
            .all(|required| capabilities.credentials().contains(required));
        if !supports_required {
            return Err(EngineError::Other(
                "invalid current-profile resulting state: member lacks a required MLS capability"
                    .into(),
            ));
        }
        let advertised = app_components_of_leaf(leaf)?;
        if !required_components.missing_from(&advertised).is_empty() {
            return Err(EngineError::Other(
                "invalid current-profile resulting state: member lacks a required app component"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Reject an admin set that lists an admin with no member leaf in the CURRENT
/// epoch (admin-policy-v1.md). Used on the outbound `UpdateAppComponents` path,
/// where the commit changes only component bytes and not membership, so the
/// resulting member set equals the current one.
pub(crate) fn reject_admins_without_member_leaf(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    admins: &[[u8; 32]],
) -> Result<(), EngineError> {
    reject_admins_without_member_accounts(admins, &member_account_pubkeys(mls_group), group_id)
}

/// Member account pubkeys currently in the group's ratchet tree.
pub(crate) fn member_account_pubkeys(mls_group: &MlsGroup) -> BTreeSet<[u8; 32]> {
    let mut accounts: BTreeSet<[u8; 32]> = BTreeSet::new();
    for member in mls_group.members() {
        if let Some(pk) = credential_account_pubkey(member.credential) {
            accounts.insert(pk);
        }
    }
    accounts
}

/// Core admin-leaf-coupling check (admin-policy-v1.md "Validation") over an
/// explicit set of member account pubkeys: every admin key MUST correspond to a
/// member account. This is the single validator shared by every seam that
/// establishes or mutates a group's admin set — outbound component updates and
/// commit apply resolve the set from the live `MlsGroup`
/// ([`reject_admins_without_member_leaf`]); group creation resolves it from the
/// projected creator+invitee set (no `MlsGroup` exists yet); welcome-join
/// resolves it from the joined group. Keeping them on one function is why a
/// phantom/pre-provisioned admin can no longer slip in at a seam that "forgot"
/// the check (mdk#737).
///
/// Note the callers build `member_accounts` on two different bases, and that is
/// intentional. Creation uses `member_id_of_key_package` /
/// `validated_member_id_of_leaf` (secp256k1-validated) because it is the
/// authoring path and controls exactly which invitees it admits. The
/// `MlsGroup`-backed callers use [`member_account_pubkeys`] /
/// `credential_account_pubkey` (32-byte length only) because every leaf already
/// present in the tree passed credential validation at its own ingress seam
/// (welcome-join step 5b `validate_member_credentials_and_account_proofs`, and
/// add/commit ingest), so the tree cannot carry an unvalidated member leaf here.
/// The admin set (`decode_admin_policy`) is likewise length-only, so both sides
/// of the coupling comparison share a basis.
///
/// The refusal is [`EngineError::UnknownMember`], naming the orphaned admin key:
/// the account it names has no leaf in this group, which is exactly what that
/// variant says, and it is already wired through the FFI
/// (`MemberNotInGroup`), the CLI, the audit classifier and the conformance
/// simulator. It used to be [`EngineError::Other`] — the unclassified bucket —
/// which reported a policy refusal as a generic fault and threw away which key
/// was at fault. [`validate_admin_leaf_coupling_for_staged_commit`] answers the
/// same way, so the rule reads identically whether it fires on the authoring
/// side or on ingest.
pub(crate) fn reject_admins_without_member_accounts(
    admins: &[[u8; 32]],
    member_accounts: &BTreeSet<[u8; 32]>,
    group_id: &GroupId,
) -> Result<(), EngineError> {
    if admins.is_empty() {
        return Ok(());
    }
    if let Some(orphaned) = admins
        .iter()
        .find(|admin| !member_accounts.contains(*admin))
    {
        return Err(EngineError::UnknownMember {
            group_id: group_id.clone(),
            member: MemberId::new(orphaned.to_vec()),
        });
    }
    Ok(())
}

fn reject_admin_self_remove_proposals(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    staged: &StagedCommit,
) -> Result<(), EngineError> {
    let admins = admins_of_group(mls_group)?;
    if admins.is_empty() {
        return Ok(());
    }
    for queued in staged.queued_proposals() {
        if !matches!(queued.proposal(), Proposal::SelfRemove) {
            continue;
        }
        // Resolve the sender's account pubkey on the SAME (length-based) basis
        // the admin set is decoded on (`decode_admin_policy` /
        // `credential_account_pubkey`), NOT the secp256k1-validating
        // `identity::member_id_of_sender` (mdk#728 review). The admin set is not
        // curve-validated, so a leaf whose 32-byte identity equals a listed
        // admin key but fails secp256k1 validation would resolve to `None` under
        // the validating chokepoint and SKIP this guard — letting that admin
        // self-remove in violation of MIP-03. Matching the admin-set basis keeps
        // both sides of the comparison comparable. Fail CLOSED: a `SelfRemove`
        // whose sender cannot be resolved to a member account is rejected, never
        // waved through (mirrors the Sm7 auto-committer / fork-recovery posture).
        let sender_pubkey = match queued.sender() {
            Sender::Member(leaf_idx) => mls_group
                .member_at(*leaf_idx)
                .and_then(|member| credential_account_pubkey(member.credential)),
            _ => None,
        };
        let Some(sender_pubkey) = sender_pubkey else {
            return Err(EngineError::AdminCannotSelfRemove {
                group_id: group_id.clone(),
            });
        };
        if admins.iter().any(|admin| admin == &sender_pubkey) {
            return Err(EngineError::AdminCannotSelfRemove {
                group_id: group_id.clone(),
            });
        }
    }
    Ok(())
}

pub(crate) fn admin_pubkey_from_member_id(id: &MemberId) -> Result<[u8; 32], EngineError> {
    let bytes = id.as_slice();
    if bytes.len() != 32 {
        return Err(EngineError::Backend(format!(
            "Marmot admin policy requires 32-byte member identities; got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn encode_group_profile(name: &str, description: &str) -> Result<Vec<u8>, EngineError> {
    encode_group_profile_v1(&GroupProfileV1 {
        name: name.to_owned(),
        description: description.to_owned(),
    })
    .map_err(EngineError::Other)
}

/// Encode an admin set as admin-policy-v1 component bytes.
///
/// The empty-set guard below is an encoder invariant, not a live policy
/// refusal: no call site can reach it. Creation seeds the set with the creator
/// (`group_lifecycle::do_create_group`), invite only encodes inside the
/// non-empty-grants branch, disband passes the committer, and remove is guarded
/// by an explicit [`EngineError::AdminDepletion`] check before it gets here
/// (`message_processor::send`). MIP-03 §150 depletion arriving through an
/// author-supplied payload is likewise refused upstream as `AdminDepletion` by
/// [`admin_policy_is_empty`] (#1523). So this stays [`EngineError::Other`]:
/// reaching it would be an engine bug, and dressing it as a policy verdict
/// would claim a refusal no caller can actually provoke.
pub(crate) fn encode_admin_policy(admins: &[[u8; 32]]) -> Result<Vec<u8>, EngineError> {
    let mut admins = admins.to_vec();
    admins.sort();
    admins.dedup();
    if admins.is_empty() {
        return Err(EngineError::Other(
            "admin policy must contain at least one admin".into(),
        ));
    }
    let mut admin_bytes = Vec::with_capacity(admins.len() * 32);
    for admin in &admins {
        admin_bytes.extend_from_slice(admin);
    }
    let mut out = Vec::new();
    cgka_traits::app_components::encode_quic_varint(admin_bytes.len() as u64, &mut out);
    out.extend_from_slice(&admin_bytes);
    Ok(out)
}

/// Whether an admin-policy payload names no admin at all.
///
/// Bytes this cannot parse are not empty, they are malformed, and that verdict
/// belongs to [`decode_admin_policy`] — so an unparseable payload answers
/// `false` here and is refused there.
pub(crate) fn admin_policy_is_empty(bytes: &[u8]) -> bool {
    decode_quic_varint(bytes).is_ok_and(|(len, prefix_len)| len == 0 && prefix_len == bytes.len())
}

pub(crate) fn decode_admin_policy(bytes: &[u8]) -> Result<Vec<[u8; 32]>, EngineError> {
    let (len, prefix_len) = decode_quic_varint(bytes)
        .map_err(|e| EngineError::Serialize(format!("admin policy length decode failed: {e}")))?;
    let len = usize::try_from(len)
        .map_err(|_| EngineError::Serialize("admin policy length is too large".into()))?;
    let end = prefix_len
        .checked_add(len)
        .ok_or_else(|| EngineError::Serialize("admin policy length overflow".into()))?;
    if end != bytes.len() {
        return Err(EngineError::Serialize(
            "admin policy has trailing bytes".into(),
        ));
    }
    if len == 0 || len % 32 != 0 {
        return Err(EngineError::Serialize(
            "admin policy must contain one or more 32-byte keys".into(),
        ));
    }
    let mut admins = Vec::with_capacity(len / 32);
    for chunk in bytes[prefix_len..end].chunks_exact(32) {
        let mut admin = [0u8; 32];
        admin.copy_from_slice(chunk);
        admins.push(admin);
    }
    let mut sorted = admins.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != admins {
        return Err(EngineError::Serialize(
            "admin policy keys must be sorted and unique".into(),
        ));
    }
    Ok(admins)
}

fn app_component_bytes(mls_group: &MlsGroup, component_id: AppComponentId) -> Option<&[u8]> {
    mls_group
        .extensions()
        .app_data_dictionary()?
        .dictionary()
        .get(&component_id)
}

/// Refuse a GroupContext entry this client must never create: a
/// never-required LeafNode component's data belongs in leaves only
/// (device-tag-v1.md, "Registry"). An entry another client created stays
/// unknown data, so only local writes are refused.
pub(crate) fn refuse_local_group_context_entry(
    component_id: AppComponentId,
) -> Result<(), EngineError> {
    if NEVER_REQUIRED_APP_COMPONENTS.contains(&component_id) {
        return Err(EngineError::Other(format!(
            "app component {component_id:#06x} lives only in LeafNodes and cannot be set in \
             GroupContext"
        )));
    }
    Ok(())
}

fn validate_initial_app_component(component: &AppComponentData) -> Result<(), EngineError> {
    refuse_local_group_context_entry(component.component_id)?;
    // A no-data component has no entry for a client to create
    // (app-components/README.md, "Placement"); the engine decides whether a
    // group requires it.
    if NO_DATA_APP_COMPONENTS.contains(&component.component_id) {
        return Err(EngineError::NoDataAppComponent {
            component_id: component.component_id,
        });
    }
    match component.component_id {
        APP_COMPONENTS_COMPONENT_ID
        | SAFE_AAD_COMPONENT_ID
        | ACCOUNT_IDENTITY_PROOF_COMPONENT_ID
        | GROUP_PROFILE_COMPONENT_ID
        | GROUP_ADMIN_POLICY_COMPONENT_ID => Err(EngineError::Other(
            "group creation request cannot override engine-owned app components".into(),
        )),
        NOSTR_ROUTING_COMPONENT_ID => decode_nostr_routing_v1(&component.data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid Nostr routing component: {e}"))),
        GROUP_BLOSSOM_IMAGE_COMPONENT_ID => validate_group_image(&component.data),
        GROUP_AVATAR_URL_COMPONENT_ID => validate_group_avatar_url(&component.data),
        GROUP_MESSAGE_RETENTION_COMPONENT_ID => validate_message_retention(&component.data),
        AGENT_TEXT_STREAM_QUIC_COMPONENT_ID => validate_agent_text_stream_policy(&component.data),
        GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID => {
            validate_encrypted_media_policy_v1(&component.data)
        }
        GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID => {
            validate_encrypted_media_policy_v2(&component.data)
        }
        DEVICE_ROSTER_COMPONENT_ID => decode_device_roster_v1(&component.data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid device roster state: {e}"))),
        _ => Ok(()),
    }
}

/// Validate every known component in a complete GroupContext dictionary.
/// Unknown optional components remain opaque and are intentionally accepted.
pub(crate) fn validate_app_component_dictionary(mls_group: &MlsGroup) -> Result<(), EngineError> {
    let Some(dictionary) = mls_group.extensions().app_data_dictionary() else {
        return Ok(());
    };
    for entry in dictionary.dictionary().entries() {
        validate_app_component_bytes(entry.id(), entry.data())?;
    }
    Ok(())
}

pub(crate) fn validate_app_component_update(
    component: &AppComponentData,
) -> Result<(), EngineError> {
    validate_app_component_bytes(component.component_id, &component.data)
}

fn validate_app_component_bytes(
    component_id: AppComponentId,
    data: &[u8],
) -> Result<(), EngineError> {
    match component_id {
        APP_COMPONENTS_COMPONENT_ID => decode_components_list(data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid app_components component: {e}"))),
        SAFE_AAD_COMPONENT_ID => Err(EngineError::Other(
            "safe_aad group-component state is not supported yet".into(),
        )),
        ACCOUNT_IDENTITY_PROOF_COMPONENT_ID => Err(EngineError::Other(
            "account identity proof is LeafNode-only and cannot be updated in GroupContext".into(),
        )),
        GROUP_PROFILE_COMPONENT_ID => decode_group_profile(data).map(|_| ()),
        GROUP_ADMIN_POLICY_COMPONENT_ID => decode_admin_policy(data).map(|_| ()),
        NOSTR_ROUTING_COMPONENT_ID => decode_nostr_routing_v1(data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid Nostr routing component: {e}"))),
        GROUP_BLOSSOM_IMAGE_COMPONENT_ID => validate_group_image(data),
        GROUP_AVATAR_URL_COMPONENT_ID => validate_group_avatar_url(data),
        GROUP_MESSAGE_RETENTION_COMPONENT_ID => validate_message_retention(data),
        AGENT_TEXT_STREAM_QUIC_COMPONENT_ID => validate_agent_text_stream_policy(data),
        GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID => validate_encrypted_media_policy_v1(data),
        GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID => validate_encrypted_media_policy_v2(data),
        GROUP_LIFECYCLE_COMPONENT_ID => {
            decode_group_lifecycle_v1(data)
                .map(|_| ())
                .map_err(|error| {
                    EngineError::Serialize(format!("invalid group lifecycle component: {error}"))
                })
        }
        _ => Ok(()),
    }
}

/// Validate all AppDataUpdate operations in one Commit as a batch.
///
/// Removal legality is evaluated against the resulting `app_components`
/// requirement list, not the parent epoch's list. That permits the spec's
/// atomic "unrequire and remove" operation while still failing closed if the
/// resulting epoch requires a component whose GroupContext data is removed.
pub(crate) fn validate_app_data_update_batch<'a>(
    mls_group: &MlsGroup,
    updates: impl IntoIterator<Item = &'a AppDataUpdateProposal>,
) -> Result<(), EngineError> {
    let updates = updates.into_iter().collect::<Vec<_>>();
    validate_app_data_update_batch_against(
        required_app_components_of_group(mls_group)?,
        crate::account_identity_proof::protocol_profile_of_group(mls_group)?,
        updates.iter().copied(),
    )?;
    // A roster diff is valid only against the parent it applies to.
    let roster_required = group_requires_device_roster(mls_group)?;
    for update in updates {
        if update.component_id() == DEVICE_ROSTER_COMPONENT_ID {
            resolved_app_data_update(
                roster_required,
                app_component_bytes(mls_group, DEVICE_ROSTER_COMPONENT_ID),
                update,
            )?;
        }
    }
    Ok(())
}

/// Validate the parts of an AppDataUpdate operation that are decidable before
/// a Commit supplies the complete proposal batch.
///
/// A standalone removal can be valid only together with another proposal that
/// un-requires the component in the same Commit. Therefore proposal admission
/// checks the operation's intrinsic encoding/removability here and defers the
/// resulting required-component rule to [`validate_app_data_update_batch`].
fn validate_standalone_app_data_update(update: &AppDataUpdateProposal) -> Result<(), EngineError> {
    match update.operation() {
        AppDataUpdateOperation::Update(data) => validate_app_component_update(&AppComponentData {
            component_id: update.component_id(),
            data: data.as_slice().to_vec(),
        }),
        AppDataUpdateOperation::Remove => validate_app_component_remove_against(
            &AppComponentSet::default(),
            update.component_id(),
        ),
    }
}

fn validate_app_data_update_batch_against<'a>(
    mut resulting_required: AppComponentSet,
    profile: ProtocolProfile,
    updates: impl IntoIterator<Item = &'a AppDataUpdateProposal>,
) -> Result<(), EngineError> {
    let updates = updates.into_iter().collect::<Vec<_>>();
    let mut seen = BTreeSet::new();

    for update in &updates {
        if !seen.insert(update.component_id()) {
            return Err(EngineError::Other(format!(
                "commit contains multiple AppDataUpdate operations for component {:#06x}",
                update.component_id()
            )));
        }
        if update.component_id() == APP_COMPONENTS_COMPONENT_ID {
            match update.operation() {
                AppDataUpdateOperation::Update(data) => {
                    resulting_required = AppComponentSet::from(
                        decode_components_list(data.as_slice()).map_err(|error| {
                            EngineError::Serialize(format!(
                                "invalid app_components component: {error}"
                            ))
                        })?,
                    );
                }
                AppDataUpdateOperation::Remove => {
                    return Err(EngineError::Other(
                        "app_components component cannot be removed".into(),
                    ));
                }
            }
        }
    }

    // On the current profile a required no-data component has no state to
    // keep, so the Commit that activates account-devices may remove an entry
    // left under its id (account-devices-v1.md, "Data"). Legacy groups keep
    // the rule for every required id.
    if profile == ProtocolProfile::Current {
        for component_id in NO_DATA_APP_COMPONENTS {
            resulting_required.ids.remove(&component_id);
        }
    }
    for update in updates {
        match update.operation() {
            AppDataUpdateOperation::Update(data) => {
                validate_app_component_update(&AppComponentData {
                    component_id: update.component_id(),
                    data: data.as_slice().to_vec(),
                })?;
            }
            AppDataUpdateOperation::Remove => {
                validate_app_component_remove_against(&resulting_required, update.component_id())?;
            }
        }
    }
    Ok(())
}

fn validate_app_component_remove_against(
    resulting_required: &AppComponentSet,
    component_id: AppComponentId,
) -> Result<(), EngineError> {
    if component_id == APP_COMPONENTS_COMPONENT_ID {
        return Err(EngineError::Other(
            "app_components component cannot be removed".into(),
        ));
    }
    if component_id == SAFE_AAD_COMPONENT_ID {
        return Err(EngineError::Other(
            "safe_aad group-component state is not supported yet".into(),
        ));
    }
    if component_id == GROUP_LIFECYCLE_COMPONENT_ID {
        return Err(EngineError::Other(
            "group lifecycle component cannot be removed".into(),
        ));
    }
    if resulting_required.contains(component_id) {
        return Err(EngineError::Other(
            "required Marmot app components cannot be removed".into(),
        ));
    }
    Ok(())
}

fn validate_group_avatar_url(bytes: &[u8]) -> Result<(), EngineError> {
    decode_group_avatar_url_v1(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid group avatar URL component: {e}")))
}

fn validate_group_image(bytes: &[u8]) -> Result<(), EngineError> {
    decode_group_blossom_image_v1(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid group image component: {e}")))
}

/// Whether avatar/image component bytes encode a *present* avatar. An empty
/// avatar-url or an all-empty blossom-image is the canonical "absent" encoding
/// (see `encode_group_avatar_url_v1`) and is equivalent to the component being
/// missing entirely. Unparseable bytes are treated as present (conservative:
/// surface a change rather than silently drop one).
pub(crate) fn avatar_component_present(component_id: AppComponentId, bytes: &[u8]) -> bool {
    match component_id {
        GROUP_AVATAR_URL_COMPONENT_ID => {
            decode_group_avatar_url_v1(bytes).map_or(true, |avatar| !avatar.url.is_empty())
        }
        GROUP_BLOSSOM_IMAGE_COMPONENT_ID => group_image_present(bytes),
        _ => true,
    }
}

fn group_image_present(bytes: &[u8]) -> bool {
    decode_group_blossom_image_v1(bytes).map_or(true, |image| image.is_present())
}

pub(crate) fn decode_message_retention(bytes: &[u8]) -> Result<u64, EngineError> {
    if bytes.len() != 8 {
        return Err(EngineError::Serialize(format!(
            "message-retention component must be 8 bytes, got {}",
            bytes.len()
        )));
    }
    let mut encoded = [0u8; 8];
    encoded.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(encoded))
}

fn validate_message_retention(bytes: &[u8]) -> Result<(), EngineError> {
    decode_message_retention(bytes)?;
    Ok(())
}

fn validate_agent_text_stream_policy(bytes: &[u8]) -> Result<(), EngineError> {
    AgentTextStreamQuicPolicyV1::decode_component_state(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid agent text stream component: {e}")))
}

fn validate_encrypted_media_policy_v1(bytes: &[u8]) -> Result<(), EngineError> {
    decode_encrypted_media_policy_v1(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid encrypted media V1 component: {e}")))
}

fn validate_encrypted_media_policy_v2(bytes: &[u8]) -> Result<(), EngineError> {
    decode_encrypted_media_policy_v2(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid encrypted media V2 component: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::app_components::default_group_components;
    use openmls::extensions::RequiredCapabilitiesExtension;

    fn current_profile_extensions(
        required_components: impl IntoIterator<Item = AppComponentId>,
        include_admin_state: bool,
        include_leaf_only_proof_state: bool,
        required_extensions: &[ExtensionType],
        required_proposals: &[ProposalType],
    ) -> Extensions<GroupContext> {
        let required_components = required_components.into_iter().collect();
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(
            APP_COMPONENTS_COMPONENT_ID,
            encode_components_list(&required_components),
        );
        if include_admin_state {
            dictionary.insert(
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                encode_admin_policy(&[[1; 32]]).unwrap(),
            );
        }
        if include_leaf_only_proof_state {
            dictionary.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, vec![0; 104]);
        }
        Extensions::from_vec(vec![
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                required_extensions,
                required_proposals,
                &[],
            )),
            Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
        ])
        .unwrap()
    }

    /// Build the group-creation `app_data_dictionary` for `required` with no
    /// initial component bytes, then assert that every entry the engine writes
    /// passes the engine's own `validate_app_component_update`. Regression for
    /// mdk#174: the engine wrote zero bytes for a required blossom-image
    /// at creation, which its own `validate_group_image` rejects.
    fn assert_creation_state_self_validates(required: AppComponentSet) {
        let initial = InitialComponentState {
            name: "name".to_string(),
            description: "desc".to_string(),
            admins: vec![[7u8; 32]],
            app_components: Vec::new(),
            optional_app_components: Vec::new(),
        };
        let ext = app_data_dictionary_extension_for_group(&required, &initial)
            .expect("creation dictionary should build");
        let Extension::AppDataDictionary(ext) = ext else {
            panic!("expected an AppDataDictionary extension");
        };
        for entry in ext.dictionary().entries() {
            // `app_components` itself is the negotiated id list, validated via
            // the update path's APP_COMPONENTS_COMPONENT_ID arm — include it.
            let component = AppComponentData {
                component_id: entry.id(),
                data: entry.data().to_vec(),
            };
            let component_id = component.component_id;
            validate_app_component_update(&component).unwrap_or_else(|e| {
                panic!(
                    "engine wrote component {component_id:#06x} at creation that its own \
                     validator rejects: {e:?}"
                )
            });
        }
    }

    #[test]
    fn the_device_roster_is_advertisable_only_in_test_policy_builds() {
        // Its wire format is unreleased until its spec lands (mdk#2628 3.1).
        let supported = AppComponentSet::new([DEVICE_ROSTER_COMPONENT_ID]);
        assert_eq!(
            validate_supported_app_components(&supported).is_ok(),
            cfg!(feature = "test-policy-overrides")
        );
    }

    #[test]
    fn group_creation_blossom_image_state_self_validates() {
        let mut ids = BTreeSet::new();
        ids.insert(GROUP_BLOSSOM_IMAGE_COMPONENT_ID);
        assert_creation_state_self_validates(AppComponentSet::from(ids));
    }

    #[test]
    fn group_creation_full_required_set_self_validates() {
        let ids: BTreeSet<AppComponentId> = [
            GROUP_PROFILE_COMPONENT_ID,
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
            GROUP_ADMIN_POLICY_COMPONENT_ID,
        ]
        .into_iter()
        .collect();
        assert_creation_state_self_validates(AppComponentSet::from(ids));
    }

    #[test]
    fn leaf_dictionary_advertises_app_components_and_understands_safe_aad() {
        let mut supported = AppComponentSet::from(default_group_components());
        supported.insert(NOSTR_ROUTING_COMPONENT_ID);

        let ext = leaf_app_components_extension(&supported, None, None).unwrap();
        let Extension::AppDataDictionary(ext) = ext else {
            panic!("expected an AppDataDictionary extension");
        };
        let dictionary = ext.dictionary();

        let advertised = decode_components_list(
            dictionary
                .get(&APP_COMPONENTS_COMPONENT_ID)
                .expect("leaf has app_components entry"),
        )
        .unwrap();
        assert!(advertised.contains(&APP_COMPONENTS_COMPONENT_ID));
        assert!(advertised.contains(&GROUP_PROFILE_COMPONENT_ID));
        assert!(advertised.contains(&GROUP_ADMIN_POLICY_COMPONENT_ID));
        assert!(advertised.contains(&NOSTR_ROUTING_COMPONENT_ID));

        let safe_aad = decode_components_list(
            dictionary
                .get(&SAFE_AAD_COMPONENT_ID)
                .expect("leaf has safe_aad support entry"),
        )
        .unwrap();
        assert!(
            safe_aad.is_empty(),
            "MDK understands safe_aad but does not yet use SafeAAD components"
        );
    }

    #[test]
    fn group_creation_dictionary_does_not_enable_safe_aad_framing() {
        let required = AppComponentSet::from(default_group_components());
        let initial = InitialComponentState {
            name: "name".to_string(),
            description: "desc".to_string(),
            admins: vec![[7u8; 32]],
            app_components: Vec::new(),
            optional_app_components: Vec::new(),
        };

        let ext = app_data_dictionary_extension_for_group(&required, &initial)
            .expect("creation dictionary should build");
        let Extension::AppDataDictionary(ext) = ext else {
            panic!("expected an AppDataDictionary extension");
        };

        assert!(
            ext.dictionary().get(&SAFE_AAD_COMPONENT_ID).is_none(),
            "a GroupContext safe_aad entry would require SafeAAD-framed authenticated_data"
        );
    }

    #[test]
    fn safe_aad_group_state_is_rejected_until_aad_framing_exists() {
        let component = AppComponentData {
            component_id: SAFE_AAD_COMPONENT_ID,
            data: encode_components_list(&BTreeSet::new()),
        };

        assert!(validate_initial_app_component(&component).is_err());
        assert!(validate_app_component_update(&component).is_err());
    }

    #[test]
    fn withdrawn_join_authorization_id_validates_like_an_unassigned_id() {
        // The registry withdrew 0x800a (marmot#427). Every validator that once
        // refused it now answers exactly as for an id the registry never
        // assigned: opaque optional data passes, and requiring it fails closed.
        const WITHDRAWN_JOIN_AUTHORIZATION_ID: AppComponentId = 0x800a;
        const UNASSIGNED_PROTOCOL_ID: AppComponentId = 0xefff;
        for component_id in [WITHDRAWN_JOIN_AUTHORIZATION_ID, UNASSIGNED_PROTOCOL_ID] {
            let component = AppComponentData {
                component_id,
                data: vec![0; 104],
            };
            validate_initial_app_component(&component).expect("opaque initial data");
            validate_app_component_update(&component).expect("opaque update");
            validate_standalone_app_data_update(&AppDataUpdateProposal::update(
                component_id,
                component.data.clone(),
            ))
            .expect("opaque standalone update");

            let mandatory = [
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
            ];
            let with_data = |required: &[AppComponentId]| {
                let extensions = current_profile_extensions(
                    required.iter().copied(),
                    true,
                    false,
                    &[ExtensionType::AppDataDictionary],
                    &[ProposalType::AppDataUpdate],
                );
                let mut dictionary = extensions
                    .app_data_dictionary()
                    .unwrap()
                    .dictionary()
                    .clone();
                dictionary.insert(component_id, component.data.clone());
                Extensions::from_vec(vec![
                    Extension::RequiredCapabilities(
                        extensions.required_capabilities().unwrap().clone(),
                    ),
                    Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
                ])
                .unwrap()
            };
            validate_current_profile_group_context(&with_data(&mandatory), "optional")
                .expect("unknown optional state is preserved");
            let error = validate_current_profile_group_context(
                &with_data(&[mandatory[0], mandatory[1], component_id]),
                "required",
            )
            .expect_err("unknown required component fails closed");
            assert!(
                error.to_string().contains(&format!(
                    "unsupported required component {component_id:#06x}"
                )),
                "{error}"
            );
        }
    }

    #[test]
    fn device_tag_is_never_required_and_unknown_data_in_group_context() {
        // device-tag-v1.md, "Registry": an entry another client put in the
        // GroupContext is unknown data, a group that requires the id is
        // invalid, and this client never creates such an entry.
        let component = AppComponentData {
            component_id: DEVICE_TAG_COMPONENT_ID,
            data: vec![0x77; 128],
        };
        validate_app_component_update(&component).expect("received entry is unknown data");
        validate_standalone_app_data_update(&AppDataUpdateProposal::update(
            DEVICE_TAG_COMPONENT_ID,
            component.data.clone(),
        ))
        .expect("received standalone update is unknown data");

        let mandatory = [
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
        ];
        let with_entry = |required: &[AppComponentId]| {
            let extensions = current_profile_extensions(
                required.iter().copied(),
                true,
                false,
                &[ExtensionType::AppDataDictionary],
                &[ProposalType::AppDataUpdate],
            );
            let mut dictionary = extensions
                .app_data_dictionary()
                .unwrap()
                .dictionary()
                .clone();
            dictionary.insert(DEVICE_TAG_COMPONENT_ID, component.data.clone());
            Extensions::from_vec(vec![
                Extension::RequiredCapabilities(
                    extensions.required_capabilities().unwrap().clone(),
                ),
                Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
            ])
            .unwrap()
        };
        validate_current_profile_group_context(&with_entry(&mandatory), "optional")
            .expect("an unrequired GroupContext entry is unknown data");
        let error = validate_current_profile_group_context(
            &with_entry(&[mandatory[0], mandatory[1], DEVICE_TAG_COMPONENT_ID]),
            "required",
        )
        .expect_err("no group may require the device tag");
        assert!(
            error
                .to_string()
                .contains("unsupported required component 0x800f"),
            "{error}"
        );

        assert!(validate_initial_app_component(&component).is_err());
        assert!(refuse_local_group_context_entry(DEVICE_TAG_COMPONENT_ID).is_err());
        refuse_local_group_context_entry(DEVICE_ROSTER_COMPONENT_ID)
            .expect("only never-required LeafNode ids are refused");
    }

    #[test]
    fn blossom_image_requires_canonical_media_type() {
        let component = |media_type: &[u8]| {
            encode_component_vectors(&[&[1u8; 32], &[2u8; 32], &[3u8; 12], &[4u8; 32], media_type])
        };

        for canonical in [b"image/png".as_slice(), b"image/jpeg".as_slice()] {
            validate_group_image(&component(canonical)).expect("canonical media type");
        }
        for non_canonical in [
            b"Image/PNG".as_slice(),
            b"image/png; charset=utf-8".as_slice(),
            b"image/jpg".as_slice(),
            b" image/png ".as_slice(),
            b"image/png/extra".as_slice(),
            b"image/(png)".as_slice(),
        ] {
            assert!(
                validate_group_image(&component(non_canonical)).is_err(),
                "non-canonical media type {:?} must be rejected",
                String::from_utf8_lossy(non_canonical)
            );
        }
    }

    #[test]
    fn absent_blossom_image_is_five_empty_fields() {
        // The canonical absent encoding is five zero-length var-bytes fields:
        // 5 bytes of 0x00, not an empty Vec.
        let absent = encode_component_vectors(&[&[], &[], &[], &[], &[]]);
        assert_eq!(absent, vec![0u8; 5]);
        // It must round-trip through the image validator as "absent".
        validate_group_image(&absent).expect("five-empty-fields is the absent state");
        // The previous (buggy) zero-byte encoding must NOT validate.
        assert!(validate_group_image(&[]).is_err());
    }

    #[test]
    fn message_retention_state_is_big_endian_seconds() {
        assert_eq!(decode_message_retention(&42u64.to_be_bytes()).unwrap(), 42);
        assert_eq!(decode_message_retention(&0u64.to_be_bytes()).unwrap(), 0);
        assert!(decode_message_retention(&[0u8; 7]).is_err());
    }

    #[test]
    fn admin_policy_validation_error_names_the_orphaned_admin_without_displaying_ids() {
        let secret_group_id = GroupId::new(vec![0xA5; 32]);
        let error = reject_admins_without_member_accounts(
            &[[0x11; 32]],
            &BTreeSet::new(),
            &secret_group_id,
        )
        .unwrap_err();

        // The typed refusal carries both ids for callers that need them...
        match &error {
            EngineError::UnknownMember { group_id, member } => {
                assert_eq!(group_id, &secret_group_id);
                assert_eq!(member.as_slice(), [0x11; 32]);
            }
            other => panic!("expected UnknownMember, got {other:?}"),
        }
        // ...while the display string, which the audit log records verbatim,
        // stays free of them.
        assert!(!error.to_string().contains(&hex::encode([0xA5; 32])));
        assert!(!error.to_string().contains(&hex::encode([0x11; 32])));
    }

    #[test]
    fn app_data_update_batch_rejects_duplicate_component_operations() {
        let updates = [
            AppDataUpdateProposal::update(GROUP_PROFILE_COMPONENT_ID, vec![0, 0]),
            AppDataUpdateProposal::remove(GROUP_PROFILE_COMPONENT_ID),
        ];

        let error = validate_app_data_update_batch_against(
            AppComponentSet::default(),
            ProtocolProfile::Current,
            updates.iter(),
        )
        .expect_err("one operation per component id");

        assert!(error.to_string().contains("multiple AppDataUpdate"));
    }

    #[test]
    fn app_data_update_batch_allows_atomic_unrequire_and_remove() {
        let initial = AppComponentSet::new([
            GROUP_PROFILE_COMPONENT_ID,
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        ]);
        let resulting = [GROUP_PROFILE_COMPONENT_ID, GROUP_ADMIN_POLICY_COMPONENT_ID]
            .into_iter()
            .collect();
        let updates = [
            AppDataUpdateProposal::update(
                APP_COMPONENTS_COMPONENT_ID,
                encode_components_list(&resulting),
            ),
            AppDataUpdateProposal::remove(GROUP_BLOSSOM_IMAGE_COMPONENT_ID),
        ];

        validate_app_data_update_batch_against(initial, ProtocolProfile::Current, updates.iter())
            .expect("the component is optional in the resulting epoch");
    }

    #[test]
    fn standalone_app_data_remove_defers_batch_dependent_requirement_check() {
        let optional_remove = AppDataUpdateProposal::remove(GROUP_BLOSSOM_IMAGE_COMPONENT_ID);
        validate_standalone_app_data_update(&optional_remove)
            .expect("a later commit may atomically unrequire and remove the component");

        let intrinsic_remove = AppDataUpdateProposal::remove(APP_COMPONENTS_COMPONENT_ID);
        validate_standalone_app_data_update(&intrinsic_remove)
            .expect_err("app_components can never be removed");
    }

    #[test]
    fn app_data_update_batch_rejects_removing_resulting_required_component() {
        let initial = AppComponentSet::new([
            GROUP_PROFILE_COMPONENT_ID,
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        ]);
        let updates = [AppDataUpdateProposal::remove(
            GROUP_BLOSSOM_IMAGE_COMPONENT_ID,
        )];

        let error = validate_app_data_update_batch_against(
            initial,
            ProtocolProfile::Current,
            updates.iter(),
        )
        .expect_err("required state must remain present");

        assert!(error.to_string().contains("required Marmot app components"));
    }

    #[test]
    fn required_account_devices_entry_is_removable_only_on_the_current_profile() {
        let required = AppComponentSet::new([
            GROUP_PROFILE_COMPONENT_ID,
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            ACCOUNT_DEVICES_COMPONENT_ID,
        ]);
        let updates = [AppDataUpdateProposal::remove(ACCOUNT_DEVICES_COMPONENT_ID)];

        validate_app_data_update_batch_against(
            required.clone(),
            ProtocolProfile::Current,
            updates.iter(),
        )
        .expect("a no-data component has no state to keep");
        // On a legacy group 0x800d is an opaque id, whose required data stays.
        validate_app_data_update_batch_against(required, ProtocolProfile::Legacy, updates.iter())
            .expect_err("legacy validity is unchanged");
    }

    #[test]
    fn current_profile_group_context_requires_the_complete_mandatory_set() {
        struct Case {
            label: &'static str,
            components: Vec<AppComponentId>,
            admin_state: bool,
            proof_state: bool,
            extensions: Vec<ExtensionType>,
            proposals: Vec<ProposalType>,
            expected_error: &'static str,
        }
        let mandatory = vec![
            GROUP_ADMIN_POLICY_COMPONENT_ID,
            ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
        ];
        let cases = [
            Case {
                label: "missing admin requirement",
                components: vec![ACCOUNT_IDENTITY_PROOF_COMPONENT_ID],
                admin_state: true,
                proof_state: false,
                extensions: vec![ExtensionType::AppDataDictionary],
                proposals: vec![ProposalType::AppDataUpdate],
                expected_error: "0x8003",
            },
            Case {
                label: "missing proof requirement",
                components: vec![GROUP_ADMIN_POLICY_COMPONENT_ID],
                admin_state: true,
                proof_state: false,
                extensions: vec![ExtensionType::AppDataDictionary],
                proposals: vec![ProposalType::AppDataUpdate],
                expected_error: "0x8009",
            },
            Case {
                label: "missing admin state",
                components: mandatory.clone(),
                admin_state: false,
                proof_state: false,
                extensions: vec![ExtensionType::AppDataDictionary],
                proposals: vec![ProposalType::AppDataUpdate],
                expected_error: "has no GroupContext state",
            },
            Case {
                label: "proof incorrectly in GroupContext",
                components: mandatory.clone(),
                admin_state: true,
                proof_state: true,
                extensions: vec![ExtensionType::AppDataDictionary],
                proposals: vec![ProposalType::AppDataUpdate],
                expected_error: "leaf-only account proof",
            },
            Case {
                label: "unknown required component",
                components: vec![
                    GROUP_ADMIN_POLICY_COMPONENT_ID,
                    ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
                    0xF301,
                ],
                admin_state: true,
                proof_state: false,
                extensions: vec![ExtensionType::AppDataDictionary],
                proposals: vec![ProposalType::AppDataUpdate],
                expected_error: "unsupported required component 0xf301",
            },
            Case {
                label: "missing dictionary capability",
                components: mandatory.clone(),
                admin_state: true,
                proof_state: false,
                extensions: vec![],
                proposals: vec![ProposalType::AppDataUpdate],
                expected_error: "not a required extension",
            },
            Case {
                label: "missing update capability",
                components: mandatory,
                admin_state: true,
                proof_state: false,
                extensions: vec![ExtensionType::AppDataDictionary],
                proposals: vec![],
                expected_error: "not a required proposal",
            },
        ];

        for case in cases {
            let extensions = current_profile_extensions(
                case.components,
                case.admin_state,
                case.proof_state,
                &case.extensions,
                &case.proposals,
            );
            let error = validate_current_profile_group_context(&extensions, case.label)
                .expect_err(case.label);
            assert!(
                error.to_string().contains(case.expected_error),
                "{}: {error}",
                case.label
            );
        }
    }

    #[test]
    fn current_profile_group_context_preserves_unknown_optional_state() {
        let mut extensions = current_profile_extensions(
            [
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
            ],
            true,
            false,
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
        );
        let mut dictionary = extensions
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .clone();
        dictionary.insert(0xF301, vec![0xde, 0xad, 0xbe, 0xef]);
        extensions = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(extensions.required_capabilities().unwrap().clone()),
            Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary)),
        ])
        .unwrap();

        validate_current_profile_group_context(&extensions, "test")
            .expect("unknown optional component state is opaque");
    }

    #[test]
    fn current_profile_rejects_frozen_encrypted_media_v1() {
        let extensions = current_profile_extensions(
            [
                GROUP_ADMIN_POLICY_COMPONENT_ID,
                ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
                GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
            ],
            true,
            false,
            &[ExtensionType::AppDataDictionary],
            &[ProposalType::AppDataUpdate],
        );
        let error = validate_current_profile_group_context(&extensions, "test").unwrap_err();
        assert!(
            error.to_string().contains("encrypted-media V1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn encrypted_media_component_ids_do_not_reinterpret_each_others_bytes() {
        let v1 = cgka_traits::app_components::EncryptedMediaPolicyV1::blossom_default(
            ["https://blossom.primal.net".to_owned()],
            false,
        )
        .unwrap();
        let v1 = cgka_traits::app_components::encode_encrypted_media_policy_v1(&v1).unwrap();
        let v2 = cgka_traits::app_components::EncryptedMediaPolicyV2::blossom_default([
            "https://blossom.primal.net".to_owned(),
        ])
        .unwrap();
        let v2 = cgka_traits::app_components::encode_encrypted_media_policy_v2(&v2).unwrap();

        validate_initial_app_component(&AppComponentData {
            component_id: GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
            data: v1.clone(),
        })
        .unwrap();
        validate_initial_app_component(&AppComponentData {
            component_id: GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
            data: v2.clone(),
        })
        .unwrap();
        assert!(
            validate_initial_app_component(&AppComponentData {
                component_id: GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID,
                data: v2,
            })
            .is_err()
        );
        assert!(
            validate_initial_app_component(&AppComponentData {
                component_id: GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
                data: v1,
            })
            .is_err()
        );
    }
}
