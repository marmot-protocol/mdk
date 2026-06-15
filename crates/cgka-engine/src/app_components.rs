//! Marmot app-component state carried in OpenMLS `app_data_dictionary`.

use cgka_traits::agent_text_stream::AgentTextStreamQuicPolicyV1;
use cgka_traits::app_components::AGENT_TEXT_STREAM_QUIC_COMPONENT_ID;
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, AppComponentId, AppComponentSet,
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID, NOSTR_ROUTING_COMPONENT_ID,
    NostrRoutingV1, decode_components_list, decode_encrypted_media_policy_v1,
    decode_group_avatar_url_v1, decode_nostr_routing_v1, decode_quic_varint,
    encode_component_vectors, encode_components_list,
};
use cgka_traits::engine::CommitOrderingPriority;
use cgka_traits::error::EngineError;
use cgka_traits::types::{GroupId, MemberId};
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension};
use openmls::group::{MlsGroup, StagedCommit};
use openmls::messages::proposals::Proposal;
use openmls::prelude::{BasicCredential, LeafNode, Sender};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InitialComponentState {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) admins: Vec<[u8; 32]>,
    pub(crate) app_components: Vec<AppComponentData>,
}

pub(crate) fn leaf_app_components_extension(
    supported: &AppComponentSet,
) -> Result<Extension, EngineError> {
    let mut dict = AppDataDictionary::new();
    dict.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&supported.ids),
    );
    Ok(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dict),
    ))
}

pub(crate) fn app_components_of_leaf(leaf: &LeafNode) -> Result<AppComponentSet, EngineError> {
    let Some(ext) = leaf.extensions().app_data_dictionary() else {
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
    let mut cursor = bytes;
    let name = decode_var_bytes(&mut cursor, 256, "profile name")?;
    let description = decode_var_bytes(&mut cursor, 4096, "profile description")?;
    if !cursor.is_empty() {
        return Err(EngineError::Serialize(
            "profile component has trailing bytes".into(),
        ));
    }
    let name = String::from_utf8(name)
        .map_err(|e| EngineError::Serialize(format!("profile name is not UTF-8: {e}")))?;
    let description = String::from_utf8(description)
        .map_err(|e| EngineError::Serialize(format!("profile description is not UTF-8: {e}")))?;
    Ok((name, description))
}

pub(crate) fn admins_of_group(mls_group: &MlsGroup) -> Result<Vec<[u8; 32]>, EngineError> {
    let Some(bytes) = app_component_bytes(mls_group, GROUP_ADMIN_POLICY_COMPONENT_ID) else {
        return Ok(Vec::new());
    };
    decode_admin_policy(bytes)
}

pub(crate) fn app_component_data_of_group(
    mls_group: &MlsGroup,
    component_id: AppComponentId,
) -> Option<Vec<u8>> {
    app_component_bytes(mls_group, component_id).map(ToOwned::to_owned)
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

pub(crate) fn require_admin_for_staged_commit(
    mls_group: &MlsGroup,
    group_id: &GroupId,
    sender: Option<&MemberId>,
    staged: &StagedCommit,
) -> Result<(), EngineError> {
    reject_admin_self_remove_proposals(mls_group, group_id, staged)?;
    if !staged_commit_requires_admin(staged) {
        return Ok(());
    }
    let Some(sender) = sender else {
        return Err(EngineError::NotGroupAdmin {
            group_id: group_id.clone(),
        });
    };
    require_admin(mls_group, group_id, sender)
}

fn credential_account_pubkey(cred: openmls::prelude::Credential) -> Option<[u8; 32]> {
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
    // an admin-policy update in this same commit is already reflected.
    let Some(dict) = staged.group_context().extensions().app_data_dictionary() else {
        return Ok(());
    };
    let Some(admin_bytes) = dict.dictionary().get(&GROUP_ADMIN_POLICY_COMPONENT_ID) else {
        return Ok(());
    };
    let resulting_admins = decode_admin_policy(admin_bytes)?;
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

    if resulting_admins
        .iter()
        .any(|admin| !accounts.contains(admin))
    {
        return Err(EngineError::Other(format!(
            "admin-policy update is invalid: an admin key has no member leaf in the resulting epoch (group {group_id:?})"
        )));
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
    if admins.is_empty() {
        return Ok(());
    }
    let mut accounts: BTreeSet<[u8; 32]> = BTreeSet::new();
    for member in mls_group.members() {
        if let Some(pk) = credential_account_pubkey(member.credential) {
            accounts.insert(pk);
        }
    }
    if admins.iter().any(|admin| !accounts.contains(admin)) {
        return Err(EngineError::Other(format!(
            "admin-policy update is invalid: an admin key has no member leaf (group {group_id:?})"
        )));
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
        let Some(sender) = member_id_of_sender(queued.sender(), mls_group) else {
            continue;
        };
        let sender_pubkey = admin_pubkey_from_member_id(&sender)?;
        if admins.iter().any(|admin| admin == &sender_pubkey) {
            return Err(EngineError::AdminCannotSelfRemove {
                group_id: group_id.clone(),
            });
        }
    }
    Ok(())
}

fn member_id_of_sender(sender: &Sender, group: &MlsGroup) -> Option<MemberId> {
    match sender {
        Sender::Member(leaf_idx) => {
            let member = group.member_at(*leaf_idx)?;
            let basic = BasicCredential::try_from(member.credential).ok()?;
            Some(MemberId::new(basic.identity().to_vec()))
        }
        _ => None,
    }
}

/// Does this staged commit require the sender to be a group admin?
///
/// `spec/protocol-core/group-messaging.md:46-53` defines an *allowlist* of the
/// only two commit shapes a non-admin may produce:
///
/// - **(a) self-update**: a Commit that updates only the sender's own LeafNode,
///   i.e. an inline update path with no by-reference proposals; and
/// - **(b) SelfRemove-only**: a Commit whose by-reference proposals are all
///   `SelfRemove` (at least one), and nothing else.
///
/// The two shapes must not be combined with each other or with any other
/// proposal type. Every other commit shape — including `PreSharedKey`,
/// `ReInit`, `ExternalInit`, `GroupContextExtensions`, `AppDataUpdate`,
/// `AppEphemeral`, `Custom`, by-reference `Add`/`Remove`/`Update`, illegal
/// combinations, and the empty/no-op commit — requires admin.
///
/// This is the inverse of the allowlist: it returns `true` (admin required)
/// unless the commit is exactly one of the two allowed non-admin shapes.
///
/// `pub` so engine integration tests can classify real OpenMLS staged commits
/// directly; there is no production caller outside this crate.
pub fn staged_commit_requires_admin(staged: &StagedCommit) -> bool {
    !is_allowed_non_admin_commit(staged)
}

/// Authorization-aware branch ordering class for same-epoch fork recovery.
pub(crate) fn commit_ordering_priority_for_staged(staged: &StagedCommit) -> CommitOrderingPriority {
    if staged_commit_requires_admin(staged) {
        CommitOrderingPriority::Privileged
    } else {
        CommitOrderingPriority::Ordinary
    }
}

/// Returns `true` iff `staged` is exactly one of the two commit shapes a
/// non-admin member is permitted to commit. Fail-closed: any unrecognized or
/// combined shape returns `false`.
///
/// Both allowed shapes carry the committer's own update-path leaf node — MLS
/// requires a fresh path on a Remove/SelfRemove commit, and a self-update *is*
/// a path. So the update path is never a disqualifier; classification is driven
/// entirely by the set of by-reference proposals.
fn is_allowed_non_admin_commit(staged: &StagedCommit) -> bool {
    let mut proposal_count = 0usize;
    let mut self_remove_count = 0usize;
    for queued in staged.queued_proposals() {
        proposal_count += 1;
        match queued.proposal() {
            Proposal::SelfRemove => self_remove_count += 1,
            // Any non-SelfRemove by-reference proposal (Add, Remove, Update,
            // PreSharedKey, ReInit, ExternalInit, GroupContextExtensions,
            // AppDataUpdate, AppEphemeral, Custom) disqualifies both allowed
            // shapes.
            _ => return false,
        }
    }

    // Shape (a): self-update only — the committer's update path with no
    // by-reference proposals (updates only the sender's own LeafNode).
    let is_self_update_only = proposal_count == 0 && staged.update_path_leaf_node().is_some();

    // Shape (b): SelfRemove-only — at least one SelfRemove proposal and every
    // by-reference proposal is a SelfRemove. The committer's update path is
    // expected and allowed; it re-keys the committer's own leaf for PCS.
    let is_self_remove_only = self_remove_count > 0 && self_remove_count == proposal_count;

    // The two shapes are mutually exclusive by proposal count; `^` also rejects
    // the empty/no-op commit (neither shape).
    is_self_update_only ^ is_self_remove_only
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
    if name.len() > 256 {
        return Err(EngineError::Other(
            "group profile name must be at most 256 UTF-8 bytes".into(),
        ));
    }
    if description.len() > 4096 {
        return Err(EngineError::Other(
            "group profile description must be at most 4096 UTF-8 bytes".into(),
        ));
    }
    Ok(encode_component_vectors(&[
        name.as_bytes(),
        description.as_bytes(),
    ]))
}

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

fn validate_initial_app_component(component: &AppComponentData) -> Result<(), EngineError> {
    match component.component_id {
        APP_COMPONENTS_COMPONENT_ID
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
        GROUP_ENCRYPTED_MEDIA_COMPONENT_ID => validate_encrypted_media_policy(&component.data),
        _ => Ok(()),
    }
}

pub(crate) fn validate_app_component_update(
    component: &AppComponentData,
) -> Result<(), EngineError> {
    match component.component_id {
        APP_COMPONENTS_COMPONENT_ID => decode_components_list(&component.data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid app_components component: {e}"))),
        GROUP_PROFILE_COMPONENT_ID => decode_group_profile(&component.data).map(|_| ()),
        GROUP_ADMIN_POLICY_COMPONENT_ID => decode_admin_policy(&component.data).map(|_| ()),
        NOSTR_ROUTING_COMPONENT_ID => decode_nostr_routing_v1(&component.data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid Nostr routing component: {e}"))),
        GROUP_BLOSSOM_IMAGE_COMPONENT_ID => validate_group_image(&component.data),
        GROUP_AVATAR_URL_COMPONENT_ID => validate_group_avatar_url(&component.data),
        GROUP_MESSAGE_RETENTION_COMPONENT_ID => validate_message_retention(&component.data),
        AGENT_TEXT_STREAM_QUIC_COMPONENT_ID => validate_agent_text_stream_policy(&component.data),
        GROUP_ENCRYPTED_MEDIA_COMPONENT_ID => validate_encrypted_media_policy(&component.data),
        _ => Ok(()),
    }
}

pub(crate) fn validate_app_component_remove(
    mls_group: &MlsGroup,
    component_id: AppComponentId,
) -> Result<(), EngineError> {
    if component_id == APP_COMPONENTS_COMPONENT_ID {
        return Err(EngineError::Other(
            "app_components component cannot be removed".into(),
        ));
    }
    if required_app_components_of_group(mls_group)?.contains(component_id) {
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
    let mut cursor = bytes;
    let image_hash = decode_var_bytes(&mut cursor, 32, "group image hash")?;
    let image_key = decode_var_bytes(&mut cursor, 32, "group image key")?;
    let image_nonce = decode_var_bytes(&mut cursor, 12, "group image nonce")?;
    let image_upload_key = decode_var_bytes(&mut cursor, 32, "group image upload key")?;
    let media_type = decode_var_bytes(&mut cursor, 128, "group image media type")?;
    if !cursor.is_empty() {
        return Err(EngineError::Serialize(
            "group image component has trailing bytes".into(),
        ));
    }
    let present = !image_hash.is_empty()
        || !image_key.is_empty()
        || !image_nonce.is_empty()
        || !image_upload_key.is_empty()
        || !media_type.is_empty();
    if !present {
        return Ok(());
    }
    if image_hash.len() != 32
        || image_key.len() != 32
        || image_nonce.len() != 12
        || image_upload_key.len() != 32
        || media_type.is_empty()
    {
        return Err(EngineError::Serialize(
            "group image component has invalid partial state".into(),
        ));
    }
    std::str::from_utf8(&media_type)
        .map_err(|e| EngineError::Serialize(format!("group image media type is not UTF-8: {e}")))?;
    Ok(())
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
    let mut cursor = bytes;
    let mut next = |max, label| decode_var_bytes(&mut cursor, max, label).ok();
    let (Some(hash), Some(key), Some(nonce), Some(upload_key), Some(media_type)) = (
        next(32, "group image hash"),
        next(32, "group image key"),
        next(12, "group image nonce"),
        next(32, "group image upload key"),
        next(128, "group image media type"),
    ) else {
        return true;
    };
    !hash.is_empty()
        || !key.is_empty()
        || !nonce.is_empty()
        || !upload_key.is_empty()
        || !media_type.is_empty()
}

fn validate_message_retention(bytes: &[u8]) -> Result<(), EngineError> {
    if bytes.len() != 8 {
        return Err(EngineError::Serialize(format!(
            "message-retention component must be 8 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn validate_agent_text_stream_policy(bytes: &[u8]) -> Result<(), EngineError> {
    AgentTextStreamQuicPolicyV1::decode_component_state(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid agent text stream component: {e}")))
}

fn validate_encrypted_media_policy(bytes: &[u8]) -> Result<(), EngineError> {
    decode_encrypted_media_policy_v1(bytes)
        .map(|_| ())
        .map_err(|e| EngineError::Serialize(format!("invalid encrypted media component: {e}")))
}

fn decode_var_bytes(
    cursor: &mut &[u8],
    max_len: usize,
    label: &str,
) -> Result<Vec<u8>, EngineError> {
    let (len, prefix_len) = decode_quic_varint(cursor)
        .map_err(|e| EngineError::Serialize(format!("{label} length decode failed: {e}")))?;
    let len = usize::try_from(len)
        .map_err(|_| EngineError::Serialize(format!("{label} length is too large")))?;
    if len > max_len {
        return Err(EngineError::Serialize(format!(
            "{label} exceeds maximum length"
        )));
    }
    let end = prefix_len
        .checked_add(len)
        .ok_or_else(|| EngineError::Serialize(format!("{label} length overflow")))?;
    if cursor.len() < end {
        return Err(EngineError::Serialize(format!("{label} is truncated")));
    }
    let bytes = cursor[prefix_len..end].to_vec();
    *cursor = &cursor[end..];
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the group-creation `app_data_dictionary` for `required` with no
    /// initial component bytes, then assert that every entry the engine writes
    /// passes the engine's own `validate_app_component_update`. Regression for
    /// darkmatter#174: the engine wrote zero bytes for a required blossom-image
    /// at creation, which its own `validate_group_image` rejects.
    fn assert_creation_state_self_validates(required: AppComponentSet) {
        let initial = InitialComponentState {
            name: "name".to_string(),
            description: "desc".to_string(),
            admins: vec![[7u8; 32]],
            app_components: Vec::new(),
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
}
