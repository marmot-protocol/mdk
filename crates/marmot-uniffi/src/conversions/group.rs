//! Group record, member, management-state, and group-mutation FFI conversions.

use std::collections::{HashMap, HashSet};

use marmot_app::{
    AppBlobEndpoint, AppDisbandFailureReason, AppDisbandRequest, AppGroupAdminPolicyComponent,
    AppGroupEncryptedMediaComponent, AppGroupHydrationQuarantineReason, AppGroupLifecycleState,
    AppGroupMemberRecord, AppGroupMlsState, AppGroupNostrRoutingComponent,
    AppGroupProfileComponent, AppGroupRecord, AppProtocolProfile, AppQuarantinedGroup,
    GroupInviteDeclineResult, account_id_hex_from_ref, npub_for_account_id,
};

use super::account::SendSummaryFfi;
use super::common::SelfMembershipFfi;
use super::media::EncryptedMediaVersionFfi;
use crate::errors::MarmotKitError;

#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupRecordFfi {
    pub group_id_hex: String,
    pub protocol_profile: AppProtocolProfileFfi,
    pub endpoint: String,
    /// Whether `marmot.group.profile.v1` is present. A present profile may still
    /// carry empty `name` and `description` fields.
    pub profile_present: bool,
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
    /// Content hash of the encrypted Blossom avatar
    /// (`marmot.group.blossom.image.v1`), `None` when absent. Doubles as a
    /// cache key; fetch + decrypt via `Marmot::download_group_blossom_image`.
    pub image_hash_hex: Option<String>,
    pub encrypted_media: AppGroupEncryptedMediaComponentFfi,
    /// Per-group disappearing-message retention in seconds
    /// (`marmot.group.message-retention.v1`). `0` means messages never expire.
    pub disappearing_message_secs: u64,
    pub archived: bool,
    pub pending_confirmation: bool,
    /// Whether this local group copy is frozen pending verified repair.
    pub unrecoverable: bool,
    /// Whether the local account is still a member of this group, and if not,
    /// whether it left voluntarily or was removed.
    pub self_membership: SelfMembershipFfi,
    /// The local account asked to leave this group and the request has not
    /// resolved yet. Orthogonal to `self_membership`, which records the locally
    /// classified departure rather than whether the request resolved — see
    /// `ChatListRowFfi::leave_request_pending` for the full state table.
    ///
    /// Always equal to `leave_requested_at_ms != null`.
    pub leave_request_pending: bool,
    /// When the local account asked to leave, in milliseconds since the Unix
    /// epoch; `null` when no leave is pending.
    pub leave_requested_at_ms: Option<u64>,
    /// Hide/disable the message composer while this is true. It includes both
    /// this account's durable request and another admin's authenticated
    /// terminal candidate awaiting convergence.
    pub disbanding: bool,
    /// This account's durable request outcome, if any. Another admin's pending
    /// candidate can make `disbanding` true while this remains `null`.
    pub disband_request: Option<DisbandRequestFfi>,
    /// Hide the composer permanently for this group id when terminal.
    pub disbanded: bool,
    pub welcomer_account_id_hex: Option<String>,
    pub via_welcome_message_id_hex: Option<String>,
}

fn profile_ffi_fields(profile: AppGroupProfileComponent) -> (bool, String, String) {
    (profile.present, profile.name, profile.description)
}

impl From<AppGroupRecord> for AppGroupRecordFfi {
    fn from(value: AppGroupRecord) -> Self {
        let (profile_present, name, description) = profile_ffi_fields(value.profile);
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
            protocol_profile: value.protocol_profile.into(),
            endpoint: value.endpoint,
            profile_present,
            name,
            description,
            admins,
            relays,
            nostr_group_id_hex,
            avatar_url: avatar.present.then_some(avatar.url),
            avatar_dim: avatar.dim,
            avatar_thumbhash: avatar.thumbhash,
            image_hash_hex: (value.image.present && !value.image.image_hash_hex.is_empty())
                .then(|| value.image.image_hash_hex.clone()),
            encrypted_media: value.encrypted_media.into(),
            disappearing_message_secs,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            unrecoverable: value.unrecoverable,
            self_membership: value.self_membership.into(),
            leave_request_pending: value.leave_requested_at_ms.is_some(),
            leave_requested_at_ms: value.leave_requested_at_ms,
            disbanding: value.disbanding,
            disband_request: value.disband_request.map(Into::into),
            disbanded: value.disbanded,
            welcomer_account_id_hex: value.welcomer_account_id_hex,
            via_welcome_message_id_hex: value.via_welcome_message_id_hex,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum AppProtocolProfileFfi {
    Legacy,
    Current,
}

impl From<AppProtocolProfile> for AppProtocolProfileFfi {
    fn from(value: AppProtocolProfile) -> Self {
        match value {
            AppProtocolProfile::Legacy => Self::Legacy,
            AppProtocolProfile::Current => Self::Current,
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
    pub version: Option<EncryptedMediaVersionFfi>,
    pub media_format: String,
    pub allowed_locator_kinds: Vec<String>,
    pub default_blob_endpoints: Vec<AppBlobEndpointFfi>,
}

impl From<AppGroupEncryptedMediaComponent> for AppGroupEncryptedMediaComponentFfi {
    fn from(value: AppGroupEncryptedMediaComponent) -> Self {
        let version = if !value.required {
            None
        } else {
            match value.component_id {
                cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_V1_COMPONENT_ID => {
                    Some(EncryptedMediaVersionFfi::V1)
                }
                cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID => {
                    Some(EncryptedMediaVersionFfi::V2)
                }
                _ => None,
            }
        };
        Self {
            component_id: u32::from(value.component_id),
            component: value.component,
            required: value.required,
            version,
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
    pub mls_state: AppGroupMlsStateFfi,
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
    /// Whether a Leave action would do anything: the local account is a member,
    /// is not an admin, and has no leave already in flight.
    ///
    /// When this is `false`, the reason is one of
    /// `requires_self_demote_before_leave` (demote first) or
    /// `leave_request_pending` (already leaving), or `disbanding` / terminal
    /// `lifecycle_state` (ordinary group actions are unavailable) — or the
    /// account is not a member at all. Check those before reporting an error.
    pub can_leave: bool,
    /// Whether an admin must self-demote before leaving. Disbanding and a
    /// terminal lifecycle take precedence and keep this false.
    pub requires_self_demote_before_leave: bool,
    /// A leave is already in flight for this group; `Marmot::leave_group` would
    /// return `MarmotKitError::LeaveAlreadyRequested`. Render progress rather
    /// than a Leave affordance.
    pub leave_request_pending: bool,
    /// When the local account asked to leave, in milliseconds since the Unix
    /// epoch; `null` when no leave is pending.
    pub leave_requested_at_ms: Option<u64>,
    pub lifecycle_state: GroupLifecycleStateFfi,
    pub disbanding_enabled: bool,
    /// Whether terminal convergence currently blocks all ordinary outbound
    /// group work. Hosts should hide the message composer while true.
    pub disbanding: bool,
    pub can_enable_disbanding: bool,
    pub can_disband: bool,
    pub disbanding_blockers: Vec<String>,
    pub disband_request: Option<DisbandRequestFfi>,
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
        .strip_prefix("marmot://profile/")
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
    mls_state: AppGroupMlsStateFfi,
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
    Ok(GroupDetailsFfi {
        group,
        members,
        mls_state,
    })
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
    let lifecycle_terminal = matches!(
        details.mls_state.lifecycle_state,
        GroupLifecycleStateFfi::Disbanded
    );
    let ordinary_actions_enabled = !details.mls_state.disbanding && !lifecycle_terminal;
    let can_invite = is_self_admin && ordinary_actions_enabled;
    // A leave already in flight suppresses `can_leave` so hosts do not offer a
    // second Leave that the engine would reject: the durable request is not
    // epoch-bound, but the SelfRemove proposal backing it is, and re-requesting
    // inside the same epoch returns `EngineError::LeaveAlreadyRequested`, which
    // reaches the host as `MarmotKitError::LeaveAlreadyRequested`. Suppressing
    // the affordance keeps that error off the happy path; it does not prevent it,
    // since this state is not read atomically with the leave it guards.
    let leave_request_pending = details.group.leave_request_pending;
    let can_leave = self_member.is_some()
        && !is_self_admin
        && !leave_request_pending
        && ordinary_actions_enabled;
    let requires_self_demote_before_leave =
        self_member.is_some() && is_self_admin && ordinary_actions_enabled;
    let member_actions = details
        .members
        .iter()
        .map(|member| {
            let would_remove_last_admin = member.is_admin && admin_count == 1;
            GroupMemberActionStateFfi {
                member_id_hex: member.member_id_hex.clone(),
                is_self: member.is_self,
                is_admin: member.is_admin,
                can_remove: is_self_admin
                    && ordinary_actions_enabled
                    && !member.is_self
                    && !would_remove_last_admin,
                can_promote: is_self_admin && ordinary_actions_enabled && !member.is_admin,
                can_demote: is_self_admin
                    && ordinary_actions_enabled
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
        leave_request_pending,
        leave_requested_at_ms: details.group.leave_requested_at_ms,
        lifecycle_state: details.mls_state.lifecycle_state,
        disbanding_enabled: details.mls_state.disbanding_enabled,
        disbanding: details.mls_state.disbanding,
        can_enable_disbanding: is_self_admin
            && ordinary_actions_enabled
            && matches!(
                details.mls_state.lifecycle_state,
                GroupLifecycleStateFfi::Stable
            )
            && !details.mls_state.disbanding_enabled
            && details.mls_state.disbanding_blockers.is_empty(),
        can_disband: is_self_admin
            && ordinary_actions_enabled
            && matches!(
                details.mls_state.lifecycle_state,
                GroupLifecycleStateFfi::Stable
            )
            && details.mls_state.disbanding_enabled,
        disbanding_blockers: details.mls_state.disbanding_blockers.clone(),
        disband_request: details.mls_state.disband_request.clone(),
        member_actions,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum GroupLifecycleStateFfi {
    Stable,
    PendingPublish,
    Merging,
    Recovering,
    Unrecoverable,
    Disbanded,
}

impl From<AppGroupLifecycleState> for GroupLifecycleStateFfi {
    fn from(value: AppGroupLifecycleState) -> Self {
        match value {
            AppGroupLifecycleState::Stable => Self::Stable,
            AppGroupLifecycleState::PendingPublish => Self::PendingPublish,
            AppGroupLifecycleState::Merging => Self::Merging,
            AppGroupLifecycleState::Recovering => Self::Recovering,
            AppGroupLifecycleState::Unrecoverable => Self::Unrecoverable,
            AppGroupLifecycleState::Disbanded => Self::Disbanded,
        }
    }
}

impl From<cgka_traits::GroupLifecycleState> for GroupLifecycleStateFfi {
    fn from(value: cgka_traits::GroupLifecycleState) -> Self {
        AppGroupLifecycleState::from(value).into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DisbandFailureReasonFfi {
    NoLongerAdmin,
    NoLongerMember,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DisbandRequestFfi {
    Pending {
        requested_at_ms: u64,
    },
    Failed {
        requested_at_ms: u64,
        reason: DisbandFailureReasonFfi,
    },
}

impl From<AppDisbandRequest> for DisbandRequestFfi {
    fn from(value: AppDisbandRequest) -> Self {
        match value {
            AppDisbandRequest::Pending { requested_at_ms } => Self::Pending { requested_at_ms },
            AppDisbandRequest::Failed {
                requested_at_ms,
                reason,
            } => Self::Failed {
                requested_at_ms,
                reason: match reason {
                    AppDisbandFailureReason::NoLongerAdmin => {
                        DisbandFailureReasonFfi::NoLongerAdmin
                    }
                    AppDisbandFailureReason::NoLongerMember => {
                        DisbandFailureReasonFfi::NoLongerMember
                    }
                },
            },
        }
    }
}

/// MLS-level group state for the conversation's developer/debug view: the
/// current epoch, live member count, and the app components the group requires.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AppGroupMlsStateFfi {
    pub group_id_hex: String,
    pub protocol_profile: AppProtocolProfileFfi,
    pub lifecycle_state: GroupLifecycleStateFfi,
    pub epoch: u64,
    pub member_count: u32,
    pub unrecoverable: bool,
    pub required_app_components: Vec<u16>,
    pub disbanding_enabled: bool,
    /// True while application messages and all other ordinary outbound group
    /// work are gated pending terminal convergence.
    pub disbanding: bool,
    pub disbanding_blockers: Vec<String>,
    pub disband_request: Option<DisbandRequestFfi>,
}

impl From<AppGroupMlsState> for AppGroupMlsStateFfi {
    fn from(value: AppGroupMlsState) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            protocol_profile: value.protocol_profile.into(),
            lifecycle_state: value.lifecycle_state.into(),
            epoch: value.epoch,
            member_count: super::saturating_u32(value.member_count),
            unrecoverable: value.unrecoverable,
            required_app_components: value.required_app_components,
            disbanding_enabled: value.disbanding_enabled,
            disbanding: value.disbanding,
            disbanding_blockers: value.disbanding_blockers,
            disband_request: value.disband_request.map(Into::into),
        }
    }
}

/// Coarse, privacy-safe reason a stored group failed session-open hydration and
/// was quarantined (mdk#151 / #417). Carries no group/member ids,
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
/// rest of the account could open (mdk#151 / #417). Surfaced so the app
/// can present a per-group recovery flow (mdk#426) distinct from healthy
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

#[cfg(test)]
mod profile_presence_tests {
    use super::*;

    fn profile(present: bool) -> AppGroupProfileComponent {
        AppGroupProfileComponent {
            component_id: 0x8001,
            component: "marmot.group.profile.v1".to_owned(),
            present,
            name: String::new(),
            description: String::new(),
            data_hex: if present {
                "0000".to_owned()
            } else {
                String::new()
            },
        }
    }

    #[test]
    fn ffi_profile_fields_distinguish_absent_from_present_empty() {
        assert_eq!(
            profile_ffi_fields(profile(false)),
            (false, String::new(), String::new())
        );
        assert_eq!(
            profile_ffi_fields(profile(true)),
            (true, String::new(), String::new())
        );
    }
}
