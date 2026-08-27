//! C mirrors of the group conversions.

use marmot_uniffi::conversions::{
    AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi, AppGroupHydrationQuarantineReasonFfi,
    AppGroupMemberRecordFfi, AppGroupMlsStateFfi, AppGroupRecordFfi, AppProtocolProfileFfi,
    AppQuarantinedGroupFfi, DisbandFailureReasonFfi, DisbandRequestFfi, EncryptedMediaVersionFfi,
    GroupDetailsFfi, GroupInviteDeclineResultFfi, GroupLifecycleStateFfi, GroupManagementStateFfi,
    GroupMemberActionStateFfi, GroupMemberDetailsFfi, GroupMutationResultFfi, MemberRefFfi,
    SelfMembershipFfi,
};

use super::account::MarmotSendSummary;
use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, required_str};

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
    /// not, whether it left voluntarily or was removed.
    MarmotSelfMembership from SelfMembershipFfi {
        Member,
        Left,
        Removed,
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
    }
}

c_mirror! {
    /// One member row of the group roster.
    MarmotAppGroupMemberRecord from AppGroupMemberRecordFfi,
    list(MarmotAppGroupMemberRecordList, marmot_app_group_member_record_list_free) {
        str member_id_hex,
        /// Local account label when this member is one of ours. Nullable.
        opt_str account,
        copy local: bool,
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
    /// Enriched member row for group detail screens.
    MarmotGroupMemberDetails from GroupMemberDetailsFfi {
        str member_id_hex,
        opt_str account,
        copy local: bool,
        copy is_admin: bool,
        copy is_self: bool,
        str npub,
        opt_str display_name,
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
        /// Whether an admin must self-demote before leaving.
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
