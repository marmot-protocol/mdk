//! C mirrors of the group conversions.

use marmot_uniffi::conversions::{
    AccountDevicesActivationFfi, AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi,
    AppGroupHydrationQuarantineReasonFfi, AppGroupMemberIdsFfi, AppGroupMemberRecordFfi,
    AppGroupMlsStateFfi, AppGroupRecordFfi, AppProtocolProfileFfi, AppQuarantinedGroupFfi,
    CreatedGroupFfi, DisbandFailureReasonFfi, DisbandRequestFfi, EncryptedMediaVersionFfi,
    GroupAppComponentFfi, GroupCommitDeliveryFfi, GroupCommitRefusalCauseFfi,
    GroupCommitRefusedRelayFfi, GroupConversationSnapshotFfi, GroupDetailsFfi,
    GroupInviteDeclineResultFfi, GroupLifecycleStateFfi, GroupManagementStateFfi,
    GroupMemberActionStateFfi, GroupMemberDetailsFfi, GroupMutationResultFfi,
    GroupRecoveryStatusFfi, GroupRejoinInvitationFfi, GroupRosterFfi, MemberRefFfi,
    SelfMembershipFfi,
};
// Group-creation option/image records live on the command module rather
// than `conversions`, because they are inputs, not projections.
use marmot_uniffi::{
    CreateGroupOptionsFfi, DirectConversationOptionsFfi, InitialGroupImageFfi,
    MemberKeyPackagePrewarmSummaryFfi, PreparedGroupImageUploadFfi,
    PreparedGroupImageUploadStateFfi,
};

use super::account::MarmotSendSummary;
use marmot_uniffi::conversions::{
    DetailedGroupCreationResultFfi, GroupCreationResultFfi, GroupInviteResultFfi,
    InviteMembersResultFfi, MemberResolutionOutcomeFfi, MemberResolutionStatusFfi,
};

c_enum! {
    MarmotMemberResolutionStatus from MemberResolutionStatusFfi {
        Selected, MissingKeyPackage, ObsoleteKeyPackage, InvalidKeyPackage,
        IncompatibleKeyPackage, MissingInboxRoute, Incomplete,
    }
}

c_mirror! {
    MarmotMemberResolutionOutcome from MemberResolutionOutcomeFfi {
        str account_id_hex,
        copy status: MarmotMemberResolutionStatus,
        copy selected_device_count: u32,
    }
}
c_mirror! {
    MarmotGroupCreationResult from GroupCreationResultFfi,
    free marmot_group_creation_free {
        opt_str group_id_hex,
        vec member_outcomes/member_outcomes_len: MarmotMemberResolutionOutcome,
    }
}
c_mirror! {
    MarmotDetailedGroupCreationResult from DetailedGroupCreationResultFfi,
    free marmot_detailed_creation_free {
        opt_rec created: MarmotCreatedGroup,
        vec member_outcomes/member_outcomes_len: MarmotMemberResolutionOutcome,
    }
}
c_mirror! {
    MarmotInviteMembersResult from InviteMembersResultFfi,
    free marmot_invite_members_free {
        opt_rec summary: MarmotSendSummary,
        vec member_outcomes/member_outcomes_len: MarmotMemberResolutionOutcome,
    }
}
c_mirror! {
    MarmotGroupInviteResult from GroupInviteResultFfi,
    free marmot_group_invite_free {
        rec invite: MarmotInviteMembersResult,
        rec details: MarmotGroupDetails,
        rec management_state: MarmotGroupManagementState,
    }
}
use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, optional_str, required_str};

c_enum! {
    /// Coarse serialized event size, not an inferred relay limit. Only read
    /// when the corresponding has_size_class flag is true.
    MarmotEventSizeClass from marmot_uniffi::EventSizeClassFfi {
        Under64Kib,
        From64To128Kib,
        From128To256Kib,
        From256To512Kib,
        From512KibTo1Mib,
        From1To2Mib,
        From2To4Mib,
        Over4Mib,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MarmotEventSizeClass {
    fn default() -> Self {
        Self::Under64Kib
    }
}

c_mirror! {
    /// A retained Welcome repair handle after a canonical create or confirmed Add.
    /// Unknown includes legacy rows and later coarse retry outcomes; it does
    /// not clear the debt. A class explains the observed refusal, not delivery:
    /// earlier legacy exposure can be unknown. Requires the matching library and header.
    MarmotPendingWelcomeDelivery from marmot_uniffi::PendingWelcomeDeliveryFfi,
    list(MarmotPendingWelcomeDeliveryList, marmot_pending_welcome_delivery_list_free) {
        str group_id_hex,
        str message_id_hex,
        str recipient_hex,
        copy recorded_at: u64,
        opt_copy has_size_class/size_class: MarmotEventSizeClass,
    }
}

c_enum! {
    /// Why an invite has not reached a relay (mdk#1706). `TooLarge` and
    /// `KeyPackageRetired` are not produced yet. `InboxLookupFailed`: no
    /// usable inbox relay is known for the recipient and MDK's latest lookup
    /// of their inbox relay list failed; MDK looks it up again at its next
    /// retry.
    MarmotInviteDeliveryProblem from marmot_uniffi::conversions::InviteDeliveryProblemFfi {
        NoInboxRelays,
        RefusedByRelays,
        RelaysUnreachable,
        Mixed,
        TooLarge,
        KeyPackageRetired,
        InboxLookupFailed,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MarmotInviteDeliveryProblem {
    fn default() -> Self {
        Self::NoInboxRelays
    }
}

c_enum! {
    /// Why an invite is no longer owed.
    MarmotInviteCancelReason from marmot_uniffi::conversions::InviteCancelReasonFfi {
        SupersededByGroupChange,
        Withdrawn,
    }
}

c_enum! {
    /// Which `MarmotInviteDeliveryState` this is. `RelayAccepted` means a relay
    /// stored the Welcome, not that the recipient received it or joined.
    /// `Undeliverable`: no relay acknowledged it by its deadline; it is not resent.
    MarmotInviteDeliveryStateKind {
        Waiting,
        Sending,
        RelayAccepted,
        Undeliverable,
        Cancelled,
    }
}

/// Where an invite's delivery stands. `problem` is read only when
/// `has_problem` is true: `Sending`'s latest problem, or `Undeliverable`'s
/// cause, which is always set. `cancel_reason` is read only for `Cancelled`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MarmotInviteDeliveryState {
    pub kind: MarmotInviteDeliveryStateKind,
    pub has_problem: bool,
    pub problem: MarmotInviteDeliveryProblem,
    pub cancel_reason: MarmotInviteCancelReason,
}

impl From<marmot_uniffi::conversions::InviteDeliveryStateFfi> for MarmotInviteDeliveryState {
    fn from(value: marmot_uniffi::conversions::InviteDeliveryStateFfi) -> Self {
        use marmot_uniffi::conversions::InviteDeliveryStateFfi as State;
        let (kind, problem, cancel_reason) = match value {
            State::Waiting => (MarmotInviteDeliveryStateKind::Waiting, None, None),
            State::Sending { last_problem } => {
                (MarmotInviteDeliveryStateKind::Sending, last_problem, None)
            }
            State::RelayAccepted => (MarmotInviteDeliveryStateKind::RelayAccepted, None, None),
            State::Undeliverable { cause } => (
                MarmotInviteDeliveryStateKind::Undeliverable,
                Some(cause),
                None,
            ),
            State::Cancelled { reason } => {
                (MarmotInviteDeliveryStateKind::Cancelled, None, Some(reason))
            }
        };
        Self {
            kind,
            has_problem: problem.is_some(),
            problem: problem.map(Into::into).unwrap_or_default(),
            cancel_reason: cancel_reason
                .map(Into::into)
                .unwrap_or(MarmotInviteCancelReason::Withdrawn),
        }
    }
}

c_mirror! {
    /// How an invite's inbox relays answered, as counts, never names: of the
    /// relays not `accepted`, by the latest attempt, `refused` answered and
    /// said no for any reason (including rate-limited and auth-required),
    /// `unreachable` gave no answer, `untried` were not tried.
    MarmotInviteRelayCounts from marmot_uniffi::conversions::InviteRelayCountsFfi {
        copy total: u32,
        copy accepted: u32,
        copy refused: u32,
        copy unreachable: u32,
        copy untried: u32,
    }
}

c_mirror! {
    /// One invited device's Welcome. Times are Unix seconds.
    MarmotInviteDeviceDelivery from marmot_uniffi::conversions::InviteDeviceDeliveryFfi {
        str delivery_id_hex,
        copy state: MarmotInviteDeliveryState,
        copy created_at: u64,
        opt_copy has_deliver_until/deliver_until: u64,
        copy attempt_count: u32,
        opt_copy has_last_attempt_at/last_attempt_at: u64,
        opt_copy has_accepted_at/accepted_at: u64,
        rec relays: MarmotInviteRelayCounts,
    }
}

c_mirror! {
    /// Whether an invite reached the invited account's inbox relays (mdk#1706),
    /// one per group and invited account: `RelayAccepted` once a relay stored
    /// any device's Welcome, read with the device counts. `invite_id_hex` is
    /// NULL for a group's founding members. Requires the matching library and
    /// header.
    MarmotInviteDelivery from marmot_uniffi::conversions::InviteDeliveryFfi,
    list(MarmotInviteDeliveryList, marmot_invite_delivery_list_free) {
        str group_id_hex,
        str recipient_hex,
        opt_str invite_id_hex,
        copy state: MarmotInviteDeliveryState,
        copy device_count: u32,
        copy accepted_device_count: u32,
        vec devices/devices_len: MarmotInviteDeviceDelivery,
    }
}

c_mirror! {
    /// A group change of yours that was not applied (mdk#2332): its call
    /// answered `CompletionUnknown` (or `AcceptedPending`, queued) and MDK then
    /// gave its commit up. Nothing reached members and nothing sends it again.
    /// `queued_intent_id_hex` is NULL for a direct change. `reason` is
    /// `not_delivered`, `event_too_large` or `refused`; `at` is in Unix
    /// seconds. Requires the matching library and header.
    MarmotGroupChangeNotDelivered from marmot_uniffi::conversions::GroupChangeNotDeliveredFfi,
    list(MarmotGroupChangeNotDeliveredList, marmot_group_change_not_delivered_list_free) {
        str group_id_hex,
        str commit_id_hex,
        opt_str queued_intent_id_hex,
        str intent_kind,
        str reason,
        copy at: u64,
    }
}

c_mirror! {
    /// Opaque application-owned group state. Empty data is distinct from absence.
    MarmotGroupAppComponent from GroupAppComponentFfi, free marmot_group_app_component_free {
        copy component_id: u16,
        bytes data/data_len,
    }
}

c_enum! {
    /// Why a group relay refused a change for good (mdk#2333).
    MarmotGroupCommitRefusalCause from GroupCommitRefusalCauseFfi {
        /// Too large for the relay: its own size answer, its known limit, or
        /// the 64 KiB commit floor at a relay whose limit is unknown.
        TooLarge,
        /// Any other final answer from the relay.
        Rejected,
    }
}

c_mirror! {
    /// A group relay that refused a change of yours for good. `size_class` is
    /// read only when `has_size_class` is true: for `TooLarge`, when known.
    MarmotGroupCommitRefusedRelay from GroupCommitRefusedRelayFfi {
        str relay_url,
        copy cause: MarmotGroupCommitRefusalCause,
        opt_copy has_size_class/size_class: MarmotEventSizeClass,
    }
}

c_mirror! {
    /// A change of yours that some group relays have not accepted yet, or
    /// that a group relay refused. Members who read only those relays may not
    /// have it. The change named is the oldest one a relay refused, until the
    /// refusal is acknowledged, or else the oldest one still owed. `since` is
    /// when the first relay accepted it, in Unix seconds. `refused_relays`
    /// lists the relays that refused it, until acknowledged.
    MarmotGroupCommitDelivery from GroupCommitDeliveryFfi,
    free marmot_group_commit_delivery_free {
        str group_id_hex,
        str_vec owed_relay_urls/owed_relay_urls_len,
        copy relay_count: u32,
        copy since: u64,
        vec refused_relays/refused_relays_len: MarmotGroupCommitRefusedRelay,
    }
}

c_enum! {
    /// Where a pending commit stands (mdk#2332).
    MarmotGroupPendingCommitState from marmot_uniffi::conversions::GroupPendingCommitStateFfi {
        /// MDK is still sending it: for its first ten minutes, and for as
        /// long as no relay may hold it while MDK waits to reach one.
        Sending,
        /// Ten minutes past its first attempt, some relay may hold it and none
        /// has acknowledged it. MDK keeps sending it and never gives it up,
        /// since members may have seen it.
        Stuck,
    }
}

c_mirror! {
    /// The group's own commit that has not confirmed yet (mdk#2332). While it
    /// is pending, group changes return `MARMOT_STATUS_GROUP_COMMIT_PENDING`.
    /// `queued_intent_id_hex` is NULL unless it carries a queued change of
    /// yours; `intent_kind` is NULL for a commit MDK made on its own.
    /// `first_attempt_at` (Unix seconds) is read only when
    /// `has_first_attempt_at` is true. `unconfirmed_relay_urls` may hold it
    /// without having acknowledged it; `owed_relay_urls` never received it;
    /// `refused_relays` gave a final latest answer, and can also be
    /// unconfirmed from an earlier attempt.
    MarmotGroupPendingCommit from marmot_uniffi::conversions::GroupPendingCommitFfi,
    free marmot_group_pending_commit_free {
        str group_id_hex,
        str commit_id_hex,
        opt_str queued_intent_id_hex,
        opt_str intent_kind,
        opt_copy has_first_attempt_at/first_attempt_at: u64,
        copy state: MarmotGroupPendingCommitState,
        str_vec unconfirmed_relay_urls/unconfirmed_relay_urls_len,
        str_vec owed_relay_urls/owed_relay_urls_len,
        vec refused_relays/refused_relays_len: MarmotGroupCommitRefusedRelay,
        copy relay_count: u32,
    }
}

c_enum! {
    /// Whether the account can turn on account-devices in a group now. Every
    /// answer is about the whole group, never which members or devices.
    MarmotAccountDevicesActivation from AccountDevicesActivationFfi {
        Eligible,
        NotAdmin,
        AlreadyEnabled,
        LegacyGroup,
        MembersNeedUpdate,
        DevicesNeedReplacement,
        DeviceLimitExceeded,
    }
}

c_enum! {
    /// Marmot protocol profile the group runs.
    MarmotAppProtocolProfile from AppProtocolProfileFfi {
        Legacy,
        Current,
    }
}

c_enum! {
    /// Encrypted-media component version.
    MarmotEncryptedMediaVersion from EncryptedMediaVersionFfi {
        V1,
        V2,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MarmotEncryptedMediaVersion {
    fn default() -> Self {
        Self::V1
    }
}

c_enum! {
    /// Whether the local account is still a member of this group, and if
    /// not, whether it left voluntarily or was removed. `DeviceRemoved`: this
    /// device's leaf was removed while the account keeps another device in
    /// the group, which is not a removal from the group.
    MarmotSelfMembership from SelfMembershipFfi {
        Member,
        Left,
        Removed,
        DeviceRemoved,
    }
}

c_enum! {
    /// Canonical group lifecycle state.
    MarmotGroupLifecycleState from GroupLifecycleStateFfi {
        Stable,
        PendingPublish,
        Merging,
        Recovering,
        Unrecoverable,
        Disbanded,
    }
}

c_enum! {
    /// Why a durable disband request failed.
    MarmotDisbandFailureReason from DisbandFailureReasonFfi {
        NoLongerAdmin,
        NoLongerMember,
    }
}

/// The local account's durable disband request outcome.
#[repr(C)]
pub enum MarmotDisbandRequest {
    Pending {
        requested_at_ms: u64,
    },
    Failed {
        requested_at_ms: u64,
        reason: MarmotDisbandFailureReason,
    },
}

impl From<DisbandRequestFfi> for MarmotDisbandRequest {
    fn from(value: DisbandRequestFfi) -> Self {
        match value {
            DisbandRequestFfi::Pending { requested_at_ms } => Self::Pending { requested_at_ms },
            DisbandRequestFfi::Failed {
                requested_at_ms,
                reason,
            } => Self::Failed {
                requested_at_ms,
                reason: reason.into(),
            },
        }
    }
}

impl CFree for MarmotDisbandRequest {
    unsafe fn free_in_place(&mut self) {}
}

/// Free a disband request returned by `marmot_disband_group`. NULL is a
/// no-op. (Embedded copies inside a chat row are released by the row.)
///
/// # Safety
/// `request` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_disband_request_free(request: *mut MarmotDisbandRequest) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(request) });
}

c_mirror! {
    /// One default blob endpoint of the encrypted-media component. Also a
    /// borrowed input to `marmot_replace_encrypted_media_blob_endpoints`.
    MarmotAppBlobEndpoint from AppBlobEndpointFfi {
        str locator_kind,
        str base_url,
    }
}

impl MarmotAppBlobEndpoint {
    /// # Safety
    /// Both fields must be valid NUL-terminated strings.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AppBlobEndpointFfi, MarmotStatus> {
        Ok(AppBlobEndpointFfi {
            locator_kind: unsafe { required_str(self.locator_kind) }?,
            base_url: unsafe { required_str(self.base_url) }?,
        })
    }
}

c_mirror! {
    /// The group's `marmot.group.encrypted-media.v1` component state.
    MarmotAppGroupEncryptedMediaComponent from AppGroupEncryptedMediaComponentFfi {
        copy component_id: u32,
        str component,
        copy required: bool,
        opt_copy has_version/version: MarmotEncryptedMediaVersion,
        str media_format,
        str_vec allowed_locator_kinds/allowed_locator_kinds_len,
        vec default_blob_endpoints/default_blob_endpoints_len: MarmotAppBlobEndpoint,
    }
}

c_mirror! {
    /// One group's app-level projection record.
    MarmotAppGroupRecord from AppGroupRecordFfi,
    free marmot_app_group_record_free,
    list(MarmotAppGroupRecordList, marmot_app_group_record_list_free) {
        str group_id_hex,
        copy protocol_profile: MarmotAppProtocolProfile,
        str endpoint,
        /// Whether `marmot.group.profile.v1` is present. A present profile
        /// may still carry empty `name` and `description` fields.
        copy profile_present: bool,
        str name,
        str description,
        str_vec admins/admins_len,
        str_vec relays/relays_len,
        str nostr_group_id_hex,
        /// URL-based group avatar, NULL when absent. Takes precedence over
        /// a Blossom image avatar.
        opt_str avatar_url,
        opt_str avatar_dim,
        opt_str avatar_thumbhash,
        /// Content hash of the encrypted Blossom avatar, NULL when absent.
        /// Fetch + decrypt via `marmot_download_group_blossom_image`.
        opt_str image_hash_hex,
        rec encrypted_media: MarmotAppGroupEncryptedMediaComponent,
        /// Per-group disappearing-message retention in seconds. `0` means
        /// messages never expire.
        copy disappearing_message_secs: u64,
        copy archived: bool,
        copy pending_confirmation: bool,
        /// Whether this local group copy is frozen pending verified repair.
        copy unrecoverable: bool,
        copy self_membership: MarmotSelfMembership,
        /// The local account asked to leave and the request has not
        /// resolved yet. Always equal to `has_leave_requested_at_ms`.
        copy leave_request_pending: bool,
        opt_copy has_leave_requested_at_ms/leave_requested_at_ms: u64,
        /// Hide/disable the message composer while true.
        copy disbanding: bool,
        /// This account's durable disband request outcome, if any.
        opt_rec disband_request: MarmotDisbandRequest,
        /// Hide the composer permanently for this group id when terminal.
        copy disbanded: bool,
        opt_str welcomer_account_id_hex,
        opt_str via_welcome_message_id_hex,
        /// The pending leave is blocked: this account is the last active
        /// admin. Keep rendering it as leaving and offer
        /// `marmot_cancel_leave`. Only true while `leave_request_pending`.
        copy leave_blocked: bool,
    }
}

c_mirror! {
    /// One member account of the group roster. An account with several
    /// devices in the group is one row.
    MarmotAppGroupMemberRecord from AppGroupMemberRecordFfi,
    list(MarmotAppGroupMemberRecordList, marmot_app_group_member_record_list_free) {
        str member_id_hex,
        /// Local account label when this member is one of ours. Nullable.
        opt_str account,
        copy local: bool,
        /// How many of this account's devices are in the group.
        copy device_count: u32,
    }
}

c_mirror! {
    /// A normalized member reference (hex / npub / nostr: / marmot:// input).
    MarmotMemberRef from MemberRefFfi,
    free marmot_member_ref_free {
        str member_ref,
        str account_id_hex,
        str npub,
    }
}

c_mirror! {
    /// Enriched member row for group detail screens. An account with
    /// several devices in the group is one row.
    MarmotGroupMemberDetails from GroupMemberDetailsFfi {
        str member_id_hex,
        opt_str account,
        copy local: bool,
        copy is_admin: bool,
        copy is_self: bool,
        str npub,
        opt_str display_name,
        /// How many of this account's devices are in the group.
        copy device_count: u32,
    }
}

c_mirror! {
    /// Current MLS state (epoch, member count, required components) for
    /// the conversation developer/debug view.
    MarmotAppGroupMlsState from AppGroupMlsStateFfi,
    free marmot_app_group_mls_state_free {
        str group_id_hex,
        copy protocol_profile: MarmotAppProtocolProfile,
        copy lifecycle_state: MarmotGroupLifecycleState,
        copy epoch: u64,
        copy member_count: u32,
        copy unrecoverable: bool,
        prim_vec required_app_components/required_app_components_len: u16,
        copy disbanding_enabled: bool,
        /// True while ordinary outbound group work is gated pending
        /// terminal convergence.
        copy disbanding: bool,
        str_vec disbanding_blockers/disbanding_blockers_len,
        opt_rec disband_request: MarmotDisbandRequest,
        /// Convergence stopped retrying a batch that kept failing; new
        /// input or `marmot_retry_group_convergence` resumes it.
        copy convergence_parked: bool,
    }
}

c_mirror! {
    /// Group plus enriched member rows for detail screens.
    MarmotGroupDetails from GroupDetailsFfi,
    free marmot_group_details_free {
        rec group: MarmotAppGroupRecord,
        vec members/members_len: MarmotGroupMemberDetails,
        rec mls_state: MarmotAppGroupMlsState,
    }
}

c_mirror! {
    /// Per-member management action availability.
    MarmotGroupMemberActionState from GroupMemberActionStateFfi {
        str member_id_hex,
        copy is_self: bool,
        copy is_admin: bool,
        copy can_remove: bool,
        copy can_promote: bool,
        copy can_demote: bool,
    }
}

c_mirror! {
    /// Caller permissions plus per-member action availability.
    MarmotGroupManagementState from GroupManagementStateFfi,
    free marmot_group_management_state_free {
        str my_account_id_hex,
        copy is_self_admin: bool,
        copy is_last_admin: bool,
        copy can_invite: bool,
        /// Whether a Leave action would do anything right now.
        copy can_leave: bool,
        /// Whether an admin must self-demote before Leave or Decline; false with device groups on (the default).
        copy requires_self_demote_before_leave: bool,
        /// A leave is already in flight; render progress, not a Leave
        /// affordance.
        copy leave_request_pending: bool,
        opt_copy has_leave_requested_at_ms/leave_requested_at_ms: u64,
        copy lifecycle_state: MarmotGroupLifecycleState,
        copy disbanding_enabled: bool,
        /// Hosts should hide the message composer while true.
        copy disbanding: bool,
        copy can_enable_disbanding: bool,
        copy can_disband: bool,
        str_vec disbanding_blockers/disbanding_blockers_len,
        opt_rec disband_request: MarmotDisbandRequest,
        vec member_actions/member_actions_len: MarmotGroupMemberActionState,
        /// The pending leave is blocked: this account is the last active
        /// admin, so the leave cannot finish.
        copy leave_blocked: bool,
        /// Offer Cancel on the blocked leave (`marmot_cancel_leave`).
        copy can_cancel_leave: bool,
    }
}

c_mirror! {
    /// A group mutation's publish summary plus refreshed details and
    /// management state, in one round trip.
    MarmotGroupMutationResult from GroupMutationResultFfi,
    free marmot_group_mutation_result_free {
        rec summary: MarmotSendSummary,
        rec details: MarmotGroupDetails,
        rec management_state: MarmotGroupManagementState,
    }
}

c_mirror! {
    /// The updated group record plus the decline publish summary.
    MarmotGroupInviteDeclineResult from GroupInviteDeclineResultFfi,
    free marmot_group_invite_decline_result_free {
        rec group: MarmotAppGroupRecord,
        rec summary: MarmotSendSummary,
    }
}

c_enum! {
    /// Why a stored group was quarantined instead of hydrated.
    MarmotAppGroupHydrationQuarantineReason from AppGroupHydrationQuarantineReasonFfi {
        /// OpenMLS returned an error while loading the stored group state.
        OpenMlsLoadFailed,
        /// Marmot metadata referenced a group whose OpenMLS state was
        /// missing.
        OpenMlsGroupMissing,
        /// Member credential / identity-proof / ratchet-tree validation
        /// failed for the loaded MLS group.
        MemberValidationFailed,
        /// The Marmot group record could not be loaded or refreshed.
        GroupRecordLoadFailed,
        /// Hydrate found a stranded pending commit, but recovery failed.
        PendingCommitRecoveryFailed,
        /// A read of past group state could not restore the live group, in
        /// session or at account open. A retry or re-join cannot clear it,
        /// and the next account open restores the live state.
        RewindRestoreFailed,
    }
}

c_mirror! {
    /// One group skipped at session open pending recovery.
    MarmotAppQuarantinedGroup from AppQuarantinedGroupFfi,
    list(MarmotAppQuarantinedGroupList, marmot_app_quarantined_group_list_free) {
        str group_id_hex,
        copy reason: MarmotAppGroupHydrationQuarantineReason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;
    use marmot_uniffi::conversions::SendAcceptDispositionFfi;

    /// Each invite delivery state maps to its own kind, with its problem or
    /// reason, and an invite delivery list and its change event free deeply.
    #[test]
    fn invite_delivery_states_keep_their_kind_and_free_deeply() {
        use marmot_uniffi::conversions::{
            InviteCancelReasonFfi as Reason, InviteDeliveryFfi,
            InviteDeliveryProblemFfi as Problem, InviteDeliveryStateFfi as State,
            InviteDeviceDeliveryFfi, InviteRelayCountsFfi,
        };
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        for (state, kind, problem, reason) in [
            (
                State::Waiting,
                MarmotInviteDeliveryStateKind::Waiting,
                None,
                None,
            ),
            (
                State::Sending { last_problem: None },
                MarmotInviteDeliveryStateKind::Sending,
                None,
                None,
            ),
            (
                State::Sending {
                    last_problem: Some(Problem::Mixed),
                },
                MarmotInviteDeliveryStateKind::Sending,
                Some(MarmotInviteDeliveryProblem::Mixed),
                None,
            ),
            (
                State::RelayAccepted,
                MarmotInviteDeliveryStateKind::RelayAccepted,
                None,
                None,
            ),
            (
                State::Undeliverable {
                    cause: Problem::RefusedByRelays,
                },
                MarmotInviteDeliveryStateKind::Undeliverable,
                Some(MarmotInviteDeliveryProblem::RefusedByRelays),
                None,
            ),
            (
                State::Cancelled {
                    reason: Reason::SupersededByGroupChange,
                },
                MarmotInviteDeliveryStateKind::Cancelled,
                None,
                Some(MarmotInviteCancelReason::SupersededByGroupChange),
            ),
        ] {
            let mirrored = MarmotInviteDeliveryState::from(state);
            assert_eq!(mirrored.kind, kind, "{state:?}");
            assert_eq!(mirrored.has_problem, problem.is_some(), "{state:?}");
            if let Some(problem) = problem {
                assert_eq!(mirrored.problem, problem, "{state:?}");
            }
            if let Some(reason) = reason {
                assert_eq!(mirrored.cancel_reason, reason, "{state:?}");
            }
        }

        let delivery = InviteDeliveryFfi {
            group_id_hex: "12".repeat(16),
            recipient_hex: "56".repeat(32),
            invite_id_hex: Some("9a".repeat(32)),
            state: State::RelayAccepted,
            device_count: 2,
            accepted_device_count: 1,
            devices: vec![InviteDeviceDeliveryFfi {
                delivery_id_hex: "34".repeat(32),
                state: State::RelayAccepted,
                created_at: 5,
                deliver_until: None,
                attempt_count: 2,
                last_attempt_at: Some(6),
                accepted_at: Some(6),
                relays: InviteRelayCountsFfi {
                    total: 3,
                    accepted: 1,
                    refused: 1,
                    unreachable: 1,
                    untried: 0,
                },
            }],
        };
        let list: MarmotInviteDeliveryList = vec![delivery.clone()].into();
        unsafe {
            assert_eq!(list.len, 1);
            let item = &*list.items;
            assert_eq!(
                std::ffi::CStr::from_ptr(item.invite_id_hex)
                    .to_str()
                    .unwrap(),
                "9a".repeat(32)
            );
            assert_eq!((item.accepted_device_count, item.device_count), (1, 2));
            assert_eq!(item.devices_len, 1);
            let device = &*item.devices;
            assert!(!device.has_deliver_until);
            assert!(device.has_accepted_at);
            assert_eq!(device.accepted_at, 6);
            assert_eq!(device.relays.refused, 1);
            marmot_invite_delivery_list_free(boxed(list));
        }
        let event = boxed(crate::types::event::MarmotEvent::from(
            marmot_uniffi::conversions::MarmotEventFfi::InviteDeliveryChanged {
                account_id_hex: "78".repeat(32),
                account_label: "alice".into(),
                delivery,
            },
        ));
        unsafe {
            let crate::types::event::MarmotEvent::InviteDeliveryChanged { delivery, .. } = &*event
            else {
                panic!("an invite delivery change");
            };
            assert_eq!(
                delivery.state.kind,
                MarmotInviteDeliveryStateKind::RelayAccepted
            );
            crate::types::event::marmot_event_free(event);
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }

    #[test]
    fn pending_welcome_outputs_preserve_diagnosis_and_free_deeply() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        for size_class in [
            None,
            Some(marmot_uniffi::EventSizeClassFfi::From128To256Kib),
        ] {
            let list: MarmotPendingWelcomeDeliveryList =
                vec![marmot_uniffi::PendingWelcomeDeliveryFfi {
                    group_id_hex: "12".repeat(16),
                    message_id_hex: "34".repeat(32),
                    recipient_hex: "56".repeat(32),
                    recorded_at: 7,
                    size_class,
                }]
                .into();
            unsafe {
                assert_eq!(list.len, 1);
                let item = &*list.items;
                assert_eq!(
                    std::ffi::CStr::from_ptr(item.group_id_hex)
                        .to_str()
                        .unwrap(),
                    "12".repeat(16)
                );
                assert_eq!(
                    std::ffi::CStr::from_ptr(item.message_id_hex)
                        .to_str()
                        .unwrap(),
                    "34".repeat(32)
                );
                assert_eq!(
                    std::ffi::CStr::from_ptr(item.recipient_hex)
                        .to_str()
                        .unwrap(),
                    "56".repeat(32)
                );
                assert_eq!(item.recorded_at, 7);
                assert_eq!(item.has_size_class, size_class.is_some());
                if size_class.is_some() {
                    assert_eq!(item.size_class, MarmotEventSizeClass::From128To256Kib);
                }
                marmot_pending_welcome_delivery_list_free(boxed(list));
            }
            let event = boxed(crate::types::event::MarmotEvent::from(
                marmot_uniffi::conversions::MarmotEventFfi::WelcomeDeliveryPending {
                    account_id_hex: "78".repeat(32),
                    account_label: "alice".into(),
                    group_id_hex: "12".repeat(16),
                    message_id_hex: "34".repeat(32),
                    recipient_hex: "56".repeat(32),
                    size_class,
                },
            ));
            unsafe {
                let crate::types::event::MarmotEvent::WelcomeDeliveryPending {
                    has_size_class,
                    size_class: class,
                    ..
                } = &*event
                else {
                    panic!("Welcome pending event");
                };
                assert_eq!(*has_size_class, size_class.is_some());
                if size_class.is_some() {
                    assert_eq!(*class, MarmotEventSizeClass::From128To256Kib);
                }
                crate::types::event::marmot_event_free(event);
            }
            #[cfg(feature = "alloc-audit")]
            assert_eq!(crate::memory::audit::live_allocations(), before);
        }
        unsafe {
            marmot_pending_welcome_delivery_list_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn commit_delivery_maps_each_refusal_cause_and_frees_deeply() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let delivery: MarmotGroupCommitDelivery = GroupCommitDeliveryFfi {
            group_id_hex: "12".repeat(16),
            owed_relay_urls: vec!["wss://owed.example".into()],
            relay_count: 4,
            since: 7,
            refused_relays: vec![
                GroupCommitRefusedRelayFfi {
                    relay_url: "wss://small.example".into(),
                    cause: GroupCommitRefusalCauseFfi::TooLarge,
                    size_class: Some(marmot_uniffi::EventSizeClassFfi::From64To128Kib),
                },
                GroupCommitRefusedRelayFfi {
                    relay_url: "wss://ambiguous.example".into(),
                    cause: GroupCommitRefusalCauseFfi::TooLarge,
                    size_class: None,
                },
                GroupCommitRefusedRelayFfi {
                    relay_url: "wss://blocked.example".into(),
                    cause: GroupCommitRefusalCauseFfi::Rejected,
                    size_class: None,
                },
            ],
        }
        .into();
        let expected = [
            (
                "wss://small.example",
                MarmotGroupCommitRefusalCause::TooLarge,
                Some(MarmotEventSizeClass::From64To128Kib),
            ),
            (
                "wss://ambiguous.example",
                MarmotGroupCommitRefusalCause::TooLarge,
                None,
            ),
            (
                "wss://blocked.example",
                MarmotGroupCommitRefusalCause::Rejected,
                None,
            ),
        ];
        unsafe {
            assert_eq!(
                std::ffi::CStr::from_ptr(delivery.group_id_hex)
                    .to_str()
                    .unwrap(),
                "12".repeat(16)
            );
            assert_eq!(delivery.owed_relay_urls_len, 1);
            assert_eq!(
                std::ffi::CStr::from_ptr(*delivery.owed_relay_urls)
                    .to_str()
                    .unwrap(),
                "wss://owed.example"
            );
            assert_eq!((delivery.relay_count, delivery.since), (4, 7));
            assert_eq!(delivery.refused_relays_len, expected.len());
            let refused =
                std::slice::from_raw_parts(delivery.refused_relays, delivery.refused_relays_len);
            for (relay, (url, cause, size_class)) in refused.iter().zip(expected) {
                assert_eq!(
                    std::ffi::CStr::from_ptr(relay.relay_url).to_str().unwrap(),
                    url
                );
                assert_eq!(relay.cause, cause);
                assert_eq!(relay.has_size_class, size_class.is_some());
                if let Some(size_class) = size_class {
                    assert_eq!(relay.size_class, size_class);
                }
            }
            marmot_group_commit_delivery_free(boxed(delivery));
            marmot_group_commit_delivery_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }

    #[test]
    fn pending_commit_maps_its_state_and_optional_fields_and_frees_deeply() {
        use marmot_uniffi::conversions::{GroupPendingCommitFfi, GroupPendingCommitStateFfi};
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let commit = |queued: Option<&str>, first_attempt_at| GroupPendingCommitFfi {
            group_id_hex: "12".repeat(16),
            commit_id_hex: "34".repeat(32),
            queued_intent_id_hex: queued.map(str::to_owned),
            intent_kind: queued.map(|_| "update_group_data".to_owned()),
            first_attempt_at,
            state: if first_attempt_at.is_some() {
                GroupPendingCommitStateFfi::Stuck
            } else {
                GroupPendingCommitStateFfi::Sending
            },
            unconfirmed_relay_urls: vec!["wss://held.example".into()],
            owed_relay_urls: vec!["wss://owed.example".into()],
            refused_relays: vec![GroupCommitRefusedRelayFfi {
                relay_url: "wss://held.example".into(),
                cause: GroupCommitRefusalCauseFfi::Rejected,
                size_class: None,
            }],
            relay_count: 3,
        };
        let stuck: MarmotGroupPendingCommit = commit(Some("56"), Some(9)).into();
        let sending: MarmotGroupPendingCommit = commit(None, None).into();
        let text = |ptr: *const std::ffi::c_char| unsafe {
            std::ffi::CStr::from_ptr(ptr).to_str().unwrap().to_owned()
        };
        unsafe {
            assert_eq!(text(stuck.group_id_hex), "12".repeat(16));
            assert_eq!(text(stuck.commit_id_hex), "34".repeat(32));
            assert_eq!(text(stuck.queued_intent_id_hex), "56");
            assert_eq!(text(stuck.intent_kind), "update_group_data");
            assert!(stuck.has_first_attempt_at);
            assert_eq!(stuck.first_attempt_at, 9);
            assert_eq!(stuck.state, MarmotGroupPendingCommitState::Stuck);
            assert_eq!(stuck.unconfirmed_relay_urls_len, 1);
            assert_eq!(text(*stuck.unconfirmed_relay_urls), "wss://held.example");
            assert_eq!(stuck.owed_relay_urls_len, 1);
            assert_eq!(text(*stuck.owed_relay_urls), "wss://owed.example");
            assert_eq!(stuck.refused_relays_len, 1);
            assert_eq!(
                text((*stuck.refused_relays).relay_url),
                "wss://held.example"
            );
            assert_eq!(
                (*stuck.refused_relays).cause,
                MarmotGroupCommitRefusalCause::Rejected
            );
            assert_eq!(stuck.relay_count, 3);
            assert!(sending.queued_intent_id_hex.is_null());
            assert!(sending.intent_kind.is_null());
            assert!(!sending.has_first_attempt_at);
            assert_eq!(sending.state, MarmotGroupPendingCommitState::Sending);
            marmot_group_pending_commit_free(boxed(stuck));
            marmot_group_pending_commit_free(boxed(sending));
            marmot_group_pending_commit_free(std::ptr::null_mut());
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }

    #[test]
    fn app_component_deep_free() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        for data in [vec![1, 0, 255], vec![]] {
            let mirror: MarmotGroupAppComponent = GroupAppComponentFfi {
                component_id: 0xf301,
                data: data.clone(),
            }
            .into();
            assert_eq!(mirror.component_id, 0xf301);
            assert_eq!(mirror.data_len, data.len());
            if !data.is_empty() {
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(mirror.data, mirror.data_len) },
                    data
                );
            }
            unsafe { marmot_group_app_component_free(boxed(mirror)) };
        }
        unsafe { marmot_group_app_component_free(std::ptr::null_mut()) };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn recovery_status_deep_free_preserves_all_fields() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let mirror: MarmotGroupRecoveryStatus = GroupRecoveryStatusFfi {
            group_id_hex: "01".repeat(16),
            automatic_recovery_failed: true,
            pending_reinvites: 2,
            failed_reinvites: 1,
            rejoin_invitations: vec![GroupRejoinInvitationFfi {
                welcome_id_hex: "02".repeat(32),
                welcomer_account_id_hex: "03".repeat(32),
                epoch: 4,
                local_state_token: "04".repeat(32),
            }],
            history_may_be_incomplete: true,
            history_notice_ids: vec!["05".repeat(24)],
        }
        .into();
        assert!(mirror.automatic_recovery_failed);
        assert_eq!((mirror.pending_reinvites, mirror.failed_reinvites), (2, 1));
        assert_eq!(mirror.rejoin_invitations_len, 1);
        assert_eq!(unsafe { (*mirror.rejoin_invitations).epoch }, 4);
        assert!(mirror.history_may_be_incomplete);
        assert_eq!(mirror.history_notice_ids_len, 1);
        unsafe {
            marmot_group_recovery_status_free(boxed(mirror));
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[cfg(feature = "alloc-audit")]
    #[test]
    fn partial_member_result_free() {
        let _guard = crate::memory::audit::test_lock();
        let start = crate::memory::audit::live_allocations();
        let result: MarmotGroupCreationResult = GroupCreationResultFfi {
            group_id_hex: Some("0102".into()),
            member_outcomes: vec![
                MemberResolutionOutcomeFfi {
                    account_id_hex: "aa".into(),
                    status: MemberResolutionStatusFfi::Selected,
                    selected_device_count: 2,
                },
                MemberResolutionOutcomeFfi {
                    account_id_hex: "bb".into(),
                    status: MemberResolutionStatusFfi::MissingKeyPackage,
                    selected_device_count: 0,
                },
            ],
        }
        .into();
        unsafe {
            marmot_group_creation_free(boxed(result));
            marmot_invite_members_free(boxed(
                InviteMembersResultFfi {
                    summary: None,
                    member_outcomes: vec![MemberResolutionOutcomeFfi {
                        account_id_hex: "cc".into(),
                        status: MemberResolutionStatusFfi::Incomplete,
                        selected_device_count: 0,
                    }],
                }
                .into(),
            ));
            marmot_detailed_creation_free(boxed(
                DetailedGroupCreationResultFfi {
                    created: None,
                    member_outcomes: vec![],
                }
                .into(),
            ));
        }
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    fn record() -> AppGroupRecordFfi {
        AppGroupRecordFfi {
            group_id_hex: "01".repeat(16),
            protocol_profile: AppProtocolProfileFfi::Current,
            endpoint: "marmot:group:01".into(),
            profile_present: true,
            name: "Test".into(),
            description: String::new(),
            admins: vec!["aa".repeat(32)],
            relays: vec![],
            nostr_group_id_hex: "02".repeat(32),
            avatar_url: None,
            avatar_dim: None,
            avatar_thumbhash: None,
            image_hash_hex: None,
            encrypted_media: AppGroupEncryptedMediaComponentFfi {
                component_id: 0x8008,
                component: "marmot.group.encrypted-media.v1".into(),
                required: true,
                version: Some(EncryptedMediaVersionFfi::V1),
                media_format: "encrypted-media-v1".into(),
                allowed_locator_kinds: vec!["blossom-v1".into()],
                default_blob_endpoints: vec![AppBlobEndpointFfi {
                    locator_kind: "blossom-v1".into(),
                    base_url: "https://blossom.example".into(),
                }],
            },
            disappearing_message_secs: 0,
            archived: false,
            pending_confirmation: false,
            unrecoverable: false,
            self_membership: SelfMembershipFfi::Member,
            leave_request_pending: true,
            leave_requested_at_ms: Some(1_700_000_000_123),
            disbanding: false,
            disband_request: Some(DisbandRequestFfi::Failed {
                requested_at_ms: 5,
                reason: DisbandFailureReasonFfi::NoLongerAdmin,
            }),
            disbanded: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
            leave_blocked: true,
        }
    }

    // Deep roundtrip through the most nested plain-record mirror
    // (record → component → endpoints, opt_rec tagged union, opt_copy).
    #[test]
    fn group_record_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAppGroupRecord = record().into();
        assert!(mirror.has_leave_requested_at_ms);
        assert_eq!(mirror.leave_requested_at_ms, 1_700_000_000_123);
        assert!(mirror.leave_blocked);
        assert!(mirror.encrypted_media.has_version);
        assert_eq!(
            mirror.encrypted_media.version,
            MarmotEncryptedMediaVersion::V1
        );
        assert_eq!(mirror.encrypted_media.default_blob_endpoints_len, 1);
        assert!(!mirror.disband_request.is_null());
        assert!(matches!(
            unsafe { &*mirror.disband_request },
            MarmotDisbandRequest::Failed {
                requested_at_ms: 5,
                reason: MarmotDisbandFailureReason::NoLongerAdmin,
            }
        ));
        let root = boxed(mirror);
        unsafe { marmot_app_group_record_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn mutation_result_roundtrip_covers_send_summary() {
        let _guard = crate::memory::audit::test_lock();
        let mirror: MarmotGroupInviteDeclineResult = GroupInviteDeclineResultFfi {
            group: record(),
            summary: marmot_uniffi::conversions::SendSummaryFfi {
                published: 1,
                message_ids: vec!["ab".repeat(32)],
                accept_disposition: SendAcceptDispositionFfi::Published,
                maintenance_disposition:
                    marmot_uniffi::conversions::SendMaintenanceDispositionFfi::Ready,
            },
        }
        .into();
        assert_eq!(mirror.summary.published, 1);
        assert_eq!(mirror.summary.message_ids_len, 1);
        let root = boxed(mirror);
        unsafe { marmot_group_invite_decline_result_free(root) };
    }
}

c_mirror! {
    /// KeyPackage prewarm counters for a prospective member set.
    MarmotMemberKeyPackagePrewarmSummary from MemberKeyPackagePrewarmSummaryFfi,
    free marmot_member_key_package_prewarm_summary_free {
        copy requested_members: u64,
        copy unique_members: u64,
        copy reused_members: u64,
        copy network_resolved_members: u64,
    }
}

c_mirror! {
    /// Created-group payload owned by MarmotDetailedGroupCreationResult.
    /// Its fields are released by the parent's deep-free.
    MarmotCreatedGroup from CreatedGroupFfi {
        str group_id_hex,
        rec chat_list_row: super::chat_list::MarmotChatListRow,
    }
}

c_mirror! {
    /// Member and admin ids for one group in a batch page.
    MarmotAppGroupMemberIds from AppGroupMemberIdsFfi,
    free marmot_app_group_member_ids_free,
    list(MarmotAppGroupMemberIdsList, marmot_app_group_member_ids_list_free) {
        str group_id_hex,
        str_vec member_ids_hex/member_ids_hex_len,
        str_vec admin_ids_hex/admin_ids_hex_len,
    }
}

c_mirror! {
    /// Group details and management state in one read. Free with
    /// `marmot_group_conversation_snapshot_free`.
    MarmotGroupConversationSnapshot from GroupConversationSnapshotFfi,
    free marmot_group_conversation_snapshot_free {
        rec details: MarmotGroupDetails,
        rec management_state: MarmotGroupManagementState,
    }
}

c_mirror! {
    /// The group's member roster at one MLS epoch. Free with
    /// `marmot_group_roster_free`.
    MarmotGroupRoster from GroupRosterFfi,
    free marmot_group_roster_free {
        str group_id_hex,
        vec members/members_len: MarmotGroupMemberDetails,
        copy epoch: u64,
        /// Monotonic change token for MLS roster state plus caller
        /// membership. Non-roster commits may bump it; directory-only
        /// display-name changes do not.
        copy roster_revision: u64,
        copy self_membership: MarmotSelfMembership,
        copy member_count: u32,
        copy lifecycle_state: MarmotGroupLifecycleState,
    }
}

c_enum! {
    /// Where a prepared group image sits in the upload lifecycle.
    MarmotPreparedGroupImageUploadState from PreparedGroupImageUploadStateFfi {
        Staged,
        Uploading,
        Uploaded,
        Failed,
        /// Already attached to a group; it cannot be reused.
        Consumed,
    }
}

c_mirror! {
    /// A group image staged ahead of group creation, so the upload can
    /// finish before the caller commits. Free with
    /// `marmot_prepared_group_image_upload_free`.
    MarmotPreparedGroupImageUpload from PreparedGroupImageUploadFfi,
    free marmot_prepared_group_image_upload_free,
    list(MarmotPreparedGroupImageUploadList, marmot_prepared_group_image_upload_list_free) {
        str upload_id,
        copy state: MarmotPreparedGroupImageUploadState,
        copy attempt_count: u32,
        opt_str last_error_kind,
        /// Set once the image is consumed by a group.
        opt_str group_id_hex,
    }
}

/// An image to attach while creating a group. Borrowed input only: the
/// plaintext bytes are copied, never retained or freed.
#[repr(C)]
pub struct MarmotInitialGroupImage {
    pub plaintext: *const u8,
    pub plaintext_len: usize,
    pub media_type: *const ::std::ffi::c_char,
    /// Nullable.
    pub source_url: *const ::std::ffi::c_char,
    /// Nullable.
    pub dim: *const ::std::ffi::c_char,
    /// Nullable.
    pub thumbhash: *const ::std::ffi::c_char,
}

impl MarmotInitialGroupImage {
    /// # Safety
    /// Strings must be valid; `plaintext` must point to `plaintext_len`
    /// bytes (or be NULL with length 0).
    pub(crate) unsafe fn to_ffi(&self) -> Result<InitialGroupImageFfi, MarmotStatus> {
        if self.plaintext.is_null() && self.plaintext_len != 0 {
            crate::status::set_last_error("plaintext was NULL with nonzero length");
            return Err(MarmotStatus::NullPointer);
        }
        let plaintext = if self.plaintext.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.plaintext, self.plaintext_len) }.to_vec()
        };

        Ok(InitialGroupImageFfi {
            plaintext,
            media_type: unsafe { required_str(self.media_type) }?,
            source_url: unsafe { optional_str(self.source_url) }?,
            dim: unsafe { optional_str(self.dim) }?,
            thumbhash: unsafe { optional_str(self.thumbhash) }?,
        })
    }
}

/// Everything optional about a new group. Borrowed input only.
#[repr(C)]
pub struct MarmotCreateGroupOptions {
    /// Nullable.
    pub description: *const ::std::ffi::c_char,
    /// Nullable; NULL creates the group without an image.
    pub initial_image: *const MarmotInitialGroupImage,
    /// Disappearing-message retention; 0 disables it.
    pub disappearing_message_secs: u64,
}

impl MarmotCreateGroupOptions {
    /// # Safety
    /// Non-NULL strings must be valid; `initial_image` NULL or a valid
    /// struct.
    pub(crate) unsafe fn to_ffi(&self) -> Result<CreateGroupOptionsFfi, MarmotStatus> {
        let initial_image = if self.initial_image.is_null() {
            None
        } else {
            Some(unsafe { (*self.initial_image).to_ffi() }?)
        };

        Ok(CreateGroupOptionsFfi {
            description: unsafe { optional_str(self.description) }?,
            initial_image,
            disappearing_message_secs: self.disappearing_message_secs,
            initial_admins: Vec::new(),
        })
    }
}

/// Founding options for a new direct conversation. Borrowed input only;
/// they never change a reused or retried conversation.
#[repr(C)]
pub struct MarmotDirectConversationOptions {
    /// Disappearing-message retention; 0 disables it.
    pub disappearing_message_secs: u64,
}

impl MarmotDirectConversationOptions {
    pub(crate) fn to_ffi(&self) -> DirectConversationOptionsFfi {
        DirectConversationOptionsFfi {
            disappearing_message_secs: self.disappearing_message_secs,
        }
    }
}

c_mirror! {
    /// Embedded replacement offer; show the authenticated inviter before confirmation.
    MarmotGroupRejoinInvitation from GroupRejoinInvitationFfi {
        str welcome_id_hex,
        str welcomer_account_id_hex,
        copy epoch: u64,
        str local_state_token,
    }
}

c_mirror! {
    /// Durable advisory membership health and explicit rejoin offers.
    /// `history_may_be_incomplete` is set while recovery is parked on this
    /// group's own history; `history_notice_ids` are those occurrences' ids
    /// for `marmot_dismiss_history_notice`.
    MarmotGroupRecoveryStatus from GroupRecoveryStatusFfi,
    free marmot_group_recovery_status_free {
        str group_id_hex,
        copy automatic_recovery_failed: bool,
        copy pending_reinvites: u32,
        copy failed_reinvites: u32,
        vec rejoin_invitations/rejoin_invitations_len: MarmotGroupRejoinInvitation,
        copy history_may_be_incomplete: bool,
        str_vec history_notice_ids/history_notice_ids_len,
    }
}
