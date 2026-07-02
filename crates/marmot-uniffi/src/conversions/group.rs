//! Group record, member, management-state, and group-mutation FFI conversions.

use std::collections::{HashMap, HashSet};

use marmot_app::{
    AppBlobEndpoint, AppGroupAdminPolicyComponent, AppGroupEncryptedMediaComponent,
    AppGroupHydrationQuarantineReason, AppGroupMemberRecord, AppGroupMlsState,
    AppGroupNostrRoutingComponent, AppGroupProfileComponent, AppGroupRecord, AppQuarantinedGroup,
    GroupInviteDeclineResult, account_id_hex_from_ref, npub_for_account_id,
};

use super::account::SendSummaryFfi;
use super::common::SelfMembershipFfi;
use crate::errors::MarmotKitError;

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupRecordFfi {
    pub group_id_hex: String,
    pub endpoint: String,
    pub name: String,
    pub description: String,
    pub admins: Vec<String>,
    pub relays: Vec<String>,
    pub nostr_group_id_hex: String,
    /// URL-based group avatar (`marmot.group.avatar-url.v1`), `None` when absent.
    /// When set it takes precedence over a Blossom image avatar.
    pub avatar_url: Option<String>,
    pub avatar_dim: Option<String>,
    pub avatar_thumbhash: Option<String>,
    pub encrypted_media: AppGroupEncryptedMediaComponentFfi,
    /// Per-group disappearing-message retention in seconds
    /// (`marmot.group.message-retention.v1`). `0` means messages never expire.
    pub disappearing_message_secs: u64,
    pub archived: bool,
    pub pending_confirmation: bool,
    /// Whether the local account is still a member of this group, and if not,
    /// whether it left voluntarily or was removed.
    pub self_membership: SelfMembershipFfi,
    pub welcomer_account_id_hex: Option<String>,
    pub via_welcome_message_id_hex: Option<String>,
}

impl From<AppGroupRecord> for AppGroupRecordFfi {
    fn from(value: AppGroupRecord) -> Self {
        let AppGroupProfileComponent {
            name, description, ..
        } = value.profile;
        let AppGroupAdminPolicyComponent { admins, .. } = value.admin_policy;
        let AppGroupNostrRoutingComponent {
            nostr_group_id_hex,
            relays,
            ..
        } = value.nostr_routing;
        let avatar = value.avatar_url;
        let disappearing_message_secs = value.message_retention.disappearing_message_secs;
        Self {
            group_id_hex: value.group_id_hex,
            endpoint: value.endpoint,
            name,
            description,
            admins,
            relays,
            nostr_group_id_hex,
            avatar_url: avatar.present.then_some(avatar.url),
            avatar_dim: avatar.dim,
            avatar_thumbhash: avatar.thumbhash,
            encrypted_media: value.encrypted_media.into(),
            disappearing_message_secs,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            self_membership: value.self_membership.into(),
            welcomer_account_id_hex: value.welcomer_account_id_hex,
            via_welcome_message_id_hex: value.via_welcome_message_id_hex,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppBlobEndpointFfi {
    pub locator_kind: String,
    pub base_url: String,
}

impl From<AppBlobEndpoint> for AppBlobEndpointFfi {
    fn from(value: AppBlobEndpoint) -> Self {
        Self {
            locator_kind: value.locator_kind,
            base_url: value.base_url,
        }
    }
}

impl From<AppBlobEndpointFfi> for AppBlobEndpoint {
    fn from(value: AppBlobEndpointFfi) -> Self {
        Self {
            locator_kind: value.locator_kind,
            base_url: value.base_url,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupEncryptedMediaComponentFfi {
    pub component_id: u32,
    pub component: String,
    pub required: bool,
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<AppBlobEndpointFfi>,
}

impl From<AppGroupEncryptedMediaComponent> for AppGroupEncryptedMediaComponentFfi {
    fn from(value: AppGroupEncryptedMediaComponent) -> Self {
        Self {
            component_id: u32::from(value.component_id),
            component: value.component,
            required: value.required,
            media_format: value.media_format,
            allowed_locator_kinds: value.allowed_locator_kinds,
            default_blob_endpoints: value
                .default_blob_endpoints
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupMemberRecordFfi {
    pub member_id_hex: String,
    pub account: Option<String>,
    pub local: bool,
}

impl From<AppGroupMemberRecord> for AppGroupMemberRecordFfi {
    fn from(value: AppGroupMemberRecord) -> Self {
        Self {
            member_id_hex: value.member_id_hex,
            account: value.account,
            local: value.local,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MemberRefFfi {
    pub member_ref: String,
    pub account_id_hex: String,
    pub npub: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMemberDetailsFfi {
    pub member_id_hex: String,
    pub account: Option<String>,
    pub local: bool,
    pub is_admin: bool,
    pub is_self: bool,
    pub npub: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupDetailsFfi {
    pub group: AppGroupRecordFfi,
    pub members: Vec<GroupMemberDetailsFfi>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMemberActionStateFfi {
    pub member_id_hex: String,
    pub is_self: bool,
    pub is_admin: bool,
    pub can_remove: bool,
    pub can_promote: bool,
    pub can_demote: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupManagementStateFfi {
    pub my_account_id_hex: String,
    pub is_self_admin: bool,
    pub is_last_admin: bool,
    pub can_invite: bool,
    pub can_leave: bool,
    pub requires_self_demote_before_leave: bool,
    pub member_actions: Vec<GroupMemberActionStateFfi>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupMutationResultFfi {
    pub summary: SendSummaryFfi,
    pub details: GroupDetailsFfi,
    pub management_state: GroupManagementStateFfi,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupInviteDeclineResultFfi {
    pub group: AppGroupRecordFfi,
    pub summary: SendSummaryFfi,
}

impl From<GroupInviteDeclineResult> for GroupInviteDeclineResultFfi {
    fn from(value: GroupInviteDeclineResult) -> Self {
        Self {
            group: value.group.into(),
            summary: value.summary.into(),
        }
    }
}

pub(crate) fn normalize_member_ref_ffi(member_ref: &str) -> Result<MemberRefFfi, MarmotKitError> {
    let canonical = canonical_member_ref_input(member_ref);
    let account_id_hex =
        account_id_hex_from_ref(&canonical).map_err(|err| MarmotKitError::InvalidIdentity {
            details: err.to_string(),
        })?;
    let npub =
        npub_for_account_id(&account_id_hex).map_err(|err| MarmotKitError::InvalidIdentity {
            details: err.to_string(),
        })?;
    Ok(MemberRefFfi {
        member_ref: account_id_hex.clone(),
        account_id_hex,
        npub,
    })
}

fn canonical_member_ref_input(member_ref: &str) -> String {
    let trimmed = member_ref.trim();
    let without_nostr = trimmed.strip_prefix("nostr:").unwrap_or(trimmed);
    let without_profile = without_nostr
        .strip_prefix("darkmatter://profile/")
        .unwrap_or(without_nostr);
    without_profile
        .split(['?', '#'])
        .next()
        .unwrap_or(without_profile)
        .trim_matches('/')
        .trim()
        .to_string()
}

pub(crate) fn group_details_ffi(
    group: AppGroupRecordFfi,
    members: Vec<AppGroupMemberRecordFfi>,
    my_account_id_hex: &str,
    display_names: HashMap<String, String>,
) -> Result<GroupDetailsFfi, MarmotKitError> {
    let admin_ids = group.admins.iter().cloned().collect::<HashSet<_>>();
    let members = members
        .into_iter()
        .map(|member| {
            let npub = npub_for_account_id(&member.member_id_hex).map_err(|err| {
                MarmotKitError::InvalidIdentity {
                    details: err.to_string(),
                }
            })?;
            Ok(GroupMemberDetailsFfi {
                is_admin: admin_ids.contains(&member.member_id_hex),
                is_self: member.member_id_hex == my_account_id_hex,
                display_name: display_names.get(&member.member_id_hex).cloned(),
                npub,
                member_id_hex: member.member_id_hex,
                account: member.account,
                local: member.local,
            })
        })
        .collect::<Result<Vec<_>, MarmotKitError>>()?;
    Ok(GroupDetailsFfi { group, members })
}

pub(crate) fn group_management_state_ffi(
    my_account_id_hex: &str,
    details: &GroupDetailsFfi,
) -> GroupManagementStateFfi {
    let admin_count = details
        .members
        .iter()
        .filter(|member| member.is_admin)
        .count();
    let self_member = details
        .members
        .iter()
        .find(|member| member.member_id_hex == my_account_id_hex);
    let is_self_admin = self_member.is_some_and(|member| member.is_admin);
    let is_last_admin = is_self_admin && admin_count == 1;
    let can_invite = is_self_admin;
    let can_leave = self_member.is_some() && !is_self_admin;
    let requires_self_demote_before_leave = self_member.is_some() && is_self_admin;
    let member_actions = details
        .members
        .iter()
        .map(|member| {
            let would_remove_last_admin = member.is_admin && admin_count == 1;
            GroupMemberActionStateFfi {
                member_id_hex: member.member_id_hex.clone(),
                is_self: member.is_self,
                is_admin: member.is_admin,
                can_remove: is_self_admin && !member.is_self && !would_remove_last_admin,
                can_promote: is_self_admin && !member.is_admin,
                can_demote: is_self_admin
                    && member.is_admin
                    && !member.is_self
                    && !would_remove_last_admin,
            }
        })
        .collect();
    GroupManagementStateFfi {
        my_account_id_hex: my_account_id_hex.to_string(),
        is_self_admin,
        is_last_admin,
        can_invite,
        can_leave,
        requires_self_demote_before_leave,
        member_actions,
    }
}

/// MLS-level group state for the conversation's developer/debug view: the
/// current epoch, live member count, and the app components the group requires.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupMlsStateFfi {
    pub group_id_hex: String,
    pub epoch: u64,
    pub member_count: u32,
    pub required_app_components: Vec<u16>,
}

impl From<AppGroupMlsState> for AppGroupMlsStateFfi {
    fn from(value: AppGroupMlsState) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            epoch: value.epoch,
            member_count: value.member_count as u32,
            required_app_components: value.required_app_components,
        }
    }
}

/// Coarse, privacy-safe reason a stored group failed session-open hydration and
/// was quarantined (darkmatter#151 / #417). Carries no group/member ids,
/// payloads, or key material — only a category the client can map to per-reason
/// recovery guidance.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum AppGroupHydrationQuarantineReasonFfi {
    /// OpenMLS returned an error while loading the stored group state.
    OpenMlsLoadFailed,
    /// Marmot metadata referenced a group whose OpenMLS state was missing.
    OpenMlsGroupMissing,
    /// Member credentials, account-identity proofs, or ratchet-tree export
    /// validation failed for the loaded MLS group.
    MemberValidationFailed,
    /// The Marmot group record could not be loaded or refreshed.
    GroupRecordLoadFailed,
    /// Hydrate found a stranded pending commit, but recovery itself failed.
    PendingCommitRecoveryFailed,
}

impl From<AppGroupHydrationQuarantineReason> for AppGroupHydrationQuarantineReasonFfi {
    fn from(value: AppGroupHydrationQuarantineReason) -> Self {
        match value {
            AppGroupHydrationQuarantineReason::OpenMlsLoadFailed => Self::OpenMlsLoadFailed,
            AppGroupHydrationQuarantineReason::OpenMlsGroupMissing => Self::OpenMlsGroupMissing,
            AppGroupHydrationQuarantineReason::MemberValidationFailed => {
                Self::MemberValidationFailed
            }
            AppGroupHydrationQuarantineReason::GroupRecordLoadFailed => Self::GroupRecordLoadFailed,
            AppGroupHydrationQuarantineReason::PendingCommitRecoveryFailed => {
                Self::PendingCommitRecoveryFailed
            }
        }
    }
}

/// A stored group that failed session-open hydration and was skipped so the
/// rest of the account could open (darkmatter#151 / #417). Surfaced so the app
/// can present a per-group recovery flow (darkmatter#426) distinct from healthy
/// and archived groups, and offer a non-destructive re-hydration retry.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AppQuarantinedGroupFfi {
    pub group_id_hex: String,
    pub reason: AppGroupHydrationQuarantineReasonFfi,
}

impl From<AppQuarantinedGroup> for AppQuarantinedGroupFfi {
    fn from(value: AppQuarantinedGroup) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            reason: value.reason.into(),
        }
    }
}
