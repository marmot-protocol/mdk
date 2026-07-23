//! Marmot app-component state carried in OpenMLS `app_data_dictionary`.

use cgka_traits::agent_text_stream::AgentTextStreamQuicPolicyV1;
use cgka_traits::app_components::AGENT_TEXT_STREAM_QUIC_COMPONENT_ID;
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, AppComponentId, AppComponentSet,
    GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_AVATAR_URL_COMPONENT_ID,
    GROUP_BLOSSOM_IMAGE_COMPONENT_ID, GROUP_ENCRYPTED_MEDIA_COMPONENT_ID,
    GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID, GroupProfileV1,
    NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, SAFE_AAD_COMPONENT_ID, decode_components_list,
    decode_encrypted_media_policy_v1, decode_group_avatar_url_v1, decode_group_blossom_image_v1,
    decode_group_profile_v1, decode_nostr_routing_v1, decode_quic_varint, encode_component_vectors,
    encode_components_list, encode_group_profile_v1,
};
use cgka_traits::engine::CommitOrderingPriority;
use cgka_traits::error::EngineError;
use cgka_traits::types::{GroupId, MemberId};
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension, Extension};
use openmls::group::{MlsGroup, StagedCommit};
use openmls::messages::proposals::{AppDataUpdateOperation, Proposal};
use openmls::prelude::{BasicCredential, LeafNode, Sender};
use std::collections::{BTreeMap, BTreeSet};

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
    let mut advertised = supported.ids.clone();
    advertised.insert(APP_COMPONENTS_COMPONENT_ID);
    dict.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&advertised),
    );
    dict.insert(
        SAFE_AAD_COMPONENT_ID,
        encode_components_list(&BTreeSet::new()),
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

pub(crate) fn app_component_data_of_group(
    mls_group: &MlsGroup,
    component_id: AppComponentId,
) -> Option<Vec<u8>> {
    app_component_bytes(mls_group, component_id).map(ToOwned::to_owned)
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
    _group_id: &GroupId,
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
    // admin set is empty; the only leaf-removing shape a non-admin may commit
    // is SelfRemove-only, which cannot de-leaf a member of an empty admin set.
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
        return Err(EngineError::Other(
            "admin-policy update is invalid: an admin key has no member leaf in the resulting epoch"
                .into(),
        ));
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
///    component in the current epoch's required set may never be dropped
///    (mirrors [`validate_app_component_remove`]: a component becomes
///    droppable only after a prior commit removes it from the required list);
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

    let mut protected = required_app_components_of_group(mls_group)?.ids;
    protected.insert(APP_COMPONENTS_COMPONENT_ID);
    for component_id in &protected {
        let currently_present = current.is_some_and(|dict| dict.contains(component_id));
        let still_present = resulting.is_some_and(|dict| dict.contains(component_id));
        if currently_present && !still_present {
            return Err(EngineError::Other(format!(
                "commit is invalid: resulting GroupContext drops required app component \
                 {component_id:#06x}"
            )));
        }
    }

    // This commit's AppDataUpdate operations by component id: the exact set of
    // resulting values a changed entry is allowed to take. `None` is a Remove.
    let mut update_ops: BTreeMap<AppComponentId, Vec<Option<&[u8]>>> = BTreeMap::new();
    for queued in staged.queued_proposals() {
        if let Proposal::AppDataUpdate(update) = queued.proposal() {
            let op = match update.operation() {
                AppDataUpdateOperation::Update(data) => Some(data.as_slice()),
                AppDataUpdateOperation::Remove => None,
            };
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
            .is_some_and(|ops| ops.contains(&after));
        if !update_backed {
            return Err(EngineError::Other(format!(
                "commit is invalid: resulting GroupContext changes app component \
                 {component_id:#06x} outside an AppDataUpdate proposal"
            )));
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
pub(crate) fn reject_admins_without_member_accounts(
    admins: &[[u8; 32]],
    member_accounts: &BTreeSet<[u8; 32]>,
    _group_id: &GroupId,
) -> Result<(), EngineError> {
    if admins.is_empty() {
        return Ok(());
    }
    if admins.iter().any(|admin| !member_accounts.contains(admin)) {
        return Err(EngineError::Other("admin key has no member leaf".into()));
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
    encode_group_profile_v1(&GroupProfileV1 {
        name: name.to_owned(),
        description: description.to_owned(),
    })
    .map_err(EngineError::Other)
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
        | SAFE_AAD_COMPONENT_ID
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
        GROUP_PROFILE_COMPONENT_ID => decode_group_profile(data).map(|_| ()),
        GROUP_ADMIN_POLICY_COMPONENT_ID => decode_admin_policy(data).map(|_| ()),
        NOSTR_ROUTING_COMPONENT_ID => decode_nostr_routing_v1(data)
            .map(|_| ())
            .map_err(|e| EngineError::Serialize(format!("invalid Nostr routing component: {e}"))),
        GROUP_BLOSSOM_IMAGE_COMPONENT_ID => validate_group_image(data),
        GROUP_AVATAR_URL_COMPONENT_ID => validate_group_avatar_url(data),
        GROUP_MESSAGE_RETENTION_COMPONENT_ID => validate_message_retention(data),
        AGENT_TEXT_STREAM_QUIC_COMPONENT_ID => validate_agent_text_stream_policy(data),
        GROUP_ENCRYPTED_MEDIA_COMPONENT_ID => validate_encrypted_media_policy(data),
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
    if component_id == SAFE_AAD_COMPONENT_ID {
        return Err(EngineError::Other(
            "safe_aad group-component state is not supported yet".into(),
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
    use cgka_traits::app_components::default_group_components;

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
    fn leaf_dictionary_advertises_app_components_and_understands_safe_aad() {
        let mut supported = AppComponentSet::from(default_group_components());
        supported.insert(NOSTR_ROUTING_COMPONENT_ID);

        let ext = leaf_app_components_extension(&supported).unwrap();
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
    fn admin_policy_validation_error_does_not_display_group_id() {
        let secret_group_id = GroupId::new(vec![0xA5; 32]);
        let error = reject_admins_without_member_accounts(
            &[[0x11; 32]],
            &BTreeSet::new(),
            &secret_group_id,
        )
        .unwrap_err();

        assert!(!error.to_string().contains(&hex::encode([0xA5; 32])));
    }
}
