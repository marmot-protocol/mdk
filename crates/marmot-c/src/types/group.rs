//! C mirrors of the group conversions (`marmot-uniffi/src/conversions/group.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    AppBlobEndpointFfi, AppGroupEncryptedMediaComponentFfi, AppGroupHydrationQuarantineReasonFfi,
    AppGroupMemberRecordFfi, AppGroupMlsStateFfi, AppGroupRecordFfi, AppQuarantinedGroupFfi,
    GroupDetailsFfi, GroupInviteDeclineResultFfi, GroupManagementStateFfi,
    GroupMemberActionStateFfi, GroupMemberDetailsFfi, GroupMutationResultFfi, MemberRefFfi,
};

use crate::MarmotStatus;
use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, owned_c_string, owned_opt_c_string, owned_vec,
    required_str,
};
use crate::types::account::MarmotSendSummary;
use crate::types::common::MarmotSelfMembership;

/// One default blob endpoint for encrypted media uploads. Used both as an
/// owned output (nested in the encrypted-media component) and as a borrowed
/// input element of `marmot_replace_encrypted_media_blob_endpoints`
/// (caller-owned; this library never frees input structs).
#[repr(C)]
pub struct MarmotAppBlobEndpoint {
    pub locator_kind: *mut c_char,
    pub base_url: *mut c_char,
}

impl From<AppBlobEndpointFfi> for MarmotAppBlobEndpoint {
    fn from(value: AppBlobEndpointFfi) -> Self {
        Self {
            locator_kind: owned_c_string(value.locator_kind),
            base_url: owned_c_string(value.base_url),
        }
    }
}

impl MarmotAppBlobEndpoint {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// Both fields must be valid NUL-terminated strings.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AppBlobEndpointFfi, MarmotStatus> {
        Ok(AppBlobEndpointFfi {
            locator_kind: unsafe { required_str(self.locator_kind.cast_const()) }?,
            base_url: unsafe { required_str(self.base_url.cast_const()) }?,
        })
    }
}

impl CFree for MarmotAppBlobEndpoint {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.locator_kind);
            free_c_string(self.base_url);
        }
    }
}

/// The group's `marmot.group.encrypted-media.v1` component: whether encrypted
/// media is required, the media format, and which blob locators/endpoints the
/// group allows.
#[repr(C)]
pub struct MarmotAppGroupEncryptedMediaComponent {
    pub component_id: u32,
    pub component: *mut c_char,
    pub required: bool,
    pub media_format: *mut c_char,
    pub allowed_locator_kinds: *mut *mut c_char,
    pub allowed_locator_kinds_len: usize,
    pub default_blob_endpoints: *mut MarmotAppBlobEndpoint,
    pub default_blob_endpoints_len: usize,
}

impl From<AppGroupEncryptedMediaComponentFfi> for MarmotAppGroupEncryptedMediaComponent {
    fn from(value: AppGroupEncryptedMediaComponentFfi) -> Self {
        let (allowed_locator_kinds, allowed_locator_kinds_len) = owned_vec(
            value
                .allowed_locator_kinds
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        let (default_blob_endpoints, default_blob_endpoints_len) = owned_vec(
            value
                .default_blob_endpoints
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        Self {
            component_id: value.component_id,
            component: owned_c_string(value.component),
            required: value.required,
            media_format: owned_c_string(value.media_format),
            allowed_locator_kinds,
            allowed_locator_kinds_len,
            default_blob_endpoints,
            default_blob_endpoints_len,
        }
    }
}

impl CFree for MarmotAppGroupEncryptedMediaComponent {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.component);
            free_c_string(self.media_format);
            free_vec(self.allowed_locator_kinds, self.allowed_locator_kinds_len);
            free_vec(self.default_blob_endpoints, self.default_blob_endpoints_len);
        }
    }
}

/// One group as projected for the chat list and group-detail screens.
#[repr(C)]
pub struct MarmotAppGroupRecord {
    pub group_id_hex: *mut c_char,
    pub endpoint: *mut c_char,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub admins: *mut *mut c_char,
    pub admins_len: usize,
    pub relays: *mut *mut c_char,
    pub relays_len: usize,
    pub nostr_group_id_hex: *mut c_char,
    /// URL-based group avatar (`marmot.group.avatar-url.v1`), NULL when
    /// absent. When set it takes precedence over a Blossom image avatar.
    pub avatar_url: *mut c_char,
    pub avatar_dim: *mut c_char,
    pub avatar_thumbhash: *mut c_char,
    /// Blossom-hosted group image content hash (hex), NULL when absent;
    /// fetch + decrypt via the group image download command. An `avatar_url`
    /// when present takes precedence.
    pub image_hash_hex: *mut c_char,
    pub encrypted_media: MarmotAppGroupEncryptedMediaComponent,
    /// Per-group disappearing-message retention in seconds
    /// (`marmot.group.message-retention.v1`). `0` means messages never expire.
    pub disappearing_message_secs: u64,
    pub archived: bool,
    pub pending_confirmation: bool,
    /// Whether the local account is still a member of this group, and if not,
    /// whether it left voluntarily or was removed.
    pub self_membership: MarmotSelfMembership,
    pub welcomer_account_id_hex: *mut c_char,
    pub via_welcome_message_id_hex: *mut c_char,
}

impl From<AppGroupRecordFfi> for MarmotAppGroupRecord {
    fn from(value: AppGroupRecordFfi) -> Self {
        let (admins, admins_len) = owned_vec(
            value
                .admins
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        let (relays, relays_len) = owned_vec(
            value
                .relays
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            group_id_hex: owned_c_string(value.group_id_hex),
            endpoint: owned_c_string(value.endpoint),
            name: owned_c_string(value.name),
            description: owned_c_string(value.description),
            admins,
            admins_len,
            relays,
            relays_len,
            nostr_group_id_hex: owned_c_string(value.nostr_group_id_hex),
            avatar_url: owned_opt_c_string(value.avatar_url),
            avatar_dim: owned_opt_c_string(value.avatar_dim),
            avatar_thumbhash: owned_opt_c_string(value.avatar_thumbhash),
            image_hash_hex: owned_opt_c_string(value.image_hash_hex),
            encrypted_media: value.encrypted_media.into(),
            disappearing_message_secs: value.disappearing_message_secs,
            archived: value.archived,
            pending_confirmation: value.pending_confirmation,
            self_membership: value.self_membership.into(),
            welcomer_account_id_hex: owned_opt_c_string(value.welcomer_account_id_hex),
            via_welcome_message_id_hex: owned_opt_c_string(value.via_welcome_message_id_hex),
        }
    }
}

impl CFree for MarmotAppGroupRecord {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_c_string(self.endpoint);
            free_c_string(self.name);
            free_c_string(self.description);
            free_vec(self.admins, self.admins_len);
            free_vec(self.relays, self.relays_len);
            free_c_string(self.nostr_group_id_hex);
            free_c_string(self.avatar_url);
            free_c_string(self.avatar_dim);
            free_c_string(self.avatar_thumbhash);
            free_c_string(self.image_hash_hex);
            self.encrypted_media.free_in_place();
            free_c_string(self.welcomer_account_id_hex);
            free_c_string(self.via_welcome_message_id_hex);
        }
    }
}

/// Free a group record root (`marmot_accept_group_invite`,
/// `marmot_set_group_archived`, subscription snapshots). NULL is a no-op.
///
/// # Safety
/// `record` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_group_record_free(record: *mut MarmotAppGroupRecord) {
    unsafe { free_boxed(record) };
}

/// Owned list of group records (chats subscription snapshots).
#[repr(C)]
pub struct MarmotAppGroupRecordList {
    pub items: *mut MarmotAppGroupRecord,
    pub len: usize,
}

impl From<Vec<AppGroupRecordFfi>> for MarmotAppGroupRecordList {
    fn from(value: Vec<AppGroupRecordFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAppGroupRecordList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a group record list root. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_group_record_list_free(list: *mut MarmotAppGroupRecordList) {
    unsafe { free_boxed(list) };
}

/// One row of the group membership roster.
#[repr(C)]
pub struct MarmotAppGroupMemberRecord {
    pub member_id_hex: *mut c_char,
    /// Local account label when the member maps to a signed-in account.
    /// Nullable.
    pub account: *mut c_char,
    pub local: bool,
}

impl From<AppGroupMemberRecordFfi> for MarmotAppGroupMemberRecord {
    fn from(value: AppGroupMemberRecordFfi) -> Self {
        Self {
            member_id_hex: owned_c_string(value.member_id_hex),
            account: owned_opt_c_string(value.account),
            local: value.local,
        }
    }
}

impl CFree for MarmotAppGroupMemberRecord {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.member_id_hex);
            free_c_string(self.account);
        }
    }
}

/// Owned list of membership roster rows (`marmot_group_members`).
#[repr(C)]
pub struct MarmotAppGroupMemberRecordList {
    pub items: *mut MarmotAppGroupMemberRecord,
    pub len: usize,
}

impl From<Vec<AppGroupMemberRecordFfi>> for MarmotAppGroupMemberRecordList {
    fn from(value: Vec<AppGroupMemberRecordFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAppGroupMemberRecordList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_group_members`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_group_member_record_list_free(
    list: *mut MarmotAppGroupMemberRecordList,
) {
    unsafe { free_boxed(list) };
}

/// A normalized member reference (`marmot_normalize_member_ref`): the
/// canonical hex account id plus its `npub` encoding.
#[repr(C)]
pub struct MarmotMemberRef {
    pub member_ref: *mut c_char,
    pub account_id_hex: *mut c_char,
    pub npub: *mut c_char,
}

impl From<MemberRefFfi> for MarmotMemberRef {
    fn from(value: MemberRefFfi) -> Self {
        Self {
            member_ref: owned_c_string(value.member_ref),
            account_id_hex: owned_c_string(value.account_id_hex),
            npub: owned_c_string(value.npub),
        }
    }
}

impl CFree for MarmotMemberRef {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.member_ref);
            free_c_string(self.account_id_hex);
            free_c_string(self.npub);
        }
    }
}

/// Free a member reference root. NULL is a no-op.
///
/// # Safety
/// `member_ref` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_member_ref_free(member_ref: *mut MarmotMemberRef) {
    unsafe { free_boxed(member_ref) };
}

/// One enriched member row for the group-detail screen: roster data plus
/// admin/self flags, `npub`, and a cached display name when known.
#[repr(C)]
pub struct MarmotGroupMemberDetails {
    pub member_id_hex: *mut c_char,
    /// Local account label when the member maps to a signed-in account.
    /// Nullable.
    pub account: *mut c_char,
    pub local: bool,
    pub is_admin: bool,
    pub is_self: bool,
    pub npub: *mut c_char,
    /// Cached profile display name when known. Nullable.
    pub display_name: *mut c_char,
}

impl From<GroupMemberDetailsFfi> for MarmotGroupMemberDetails {
    fn from(value: GroupMemberDetailsFfi) -> Self {
        Self {
            member_id_hex: owned_c_string(value.member_id_hex),
            account: owned_opt_c_string(value.account),
            local: value.local,
            is_admin: value.is_admin,
            is_self: value.is_self,
            npub: owned_c_string(value.npub),
            display_name: owned_opt_c_string(value.display_name),
        }
    }
}

impl CFree for MarmotGroupMemberDetails {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.member_id_hex);
            free_c_string(self.account);
            free_c_string(self.npub);
            free_c_string(self.display_name);
        }
    }
}

/// Group plus enriched member rows for detail screens
/// (`marmot_group_details`).
#[repr(C)]
pub struct MarmotGroupDetails {
    pub group: MarmotAppGroupRecord,
    pub members: *mut MarmotGroupMemberDetails,
    pub members_len: usize,
}

impl From<GroupDetailsFfi> for MarmotGroupDetails {
    fn from(value: GroupDetailsFfi) -> Self {
        let (members, members_len) = owned_vec(value.members.into_iter().map(Into::into).collect());
        Self {
            group: value.group.into(),
            members,
            members_len,
        }
    }
}

impl CFree for MarmotGroupDetails {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            self.group.free_in_place();
            free_vec(self.members, self.members_len);
        }
    }
}

/// Free a group details root. NULL is a no-op.
///
/// # Safety
/// `details` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_details_free(details: *mut MarmotGroupDetails) {
    unsafe { free_boxed(details) };
}

/// Per-member action availability for the group-management UI.
#[repr(C)]
pub struct MarmotGroupMemberActionState {
    pub member_id_hex: *mut c_char,
    pub is_self: bool,
    pub is_admin: bool,
    pub can_remove: bool,
    pub can_promote: bool,
    pub can_demote: bool,
}

impl From<GroupMemberActionStateFfi> for MarmotGroupMemberActionState {
    fn from(value: GroupMemberActionStateFfi) -> Self {
        Self {
            member_id_hex: owned_c_string(value.member_id_hex),
            is_self: value.is_self,
            is_admin: value.is_admin,
            can_remove: value.can_remove,
            can_promote: value.can_promote,
            can_demote: value.can_demote,
        }
    }
}

impl CFree for MarmotGroupMemberActionState {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(self.member_id_hex) };
    }
}

/// Current caller permissions plus per-member action availability
/// (`marmot_group_management_state`).
#[repr(C)]
pub struct MarmotGroupManagementState {
    pub my_account_id_hex: *mut c_char,
    pub is_self_admin: bool,
    pub is_last_admin: bool,
    pub can_invite: bool,
    pub can_leave: bool,
    pub requires_self_demote_before_leave: bool,
    pub member_actions: *mut MarmotGroupMemberActionState,
    pub member_actions_len: usize,
}

impl From<GroupManagementStateFfi> for MarmotGroupManagementState {
    fn from(value: GroupManagementStateFfi) -> Self {
        let (member_actions, member_actions_len) =
            owned_vec(value.member_actions.into_iter().map(Into::into).collect());
        Self {
            my_account_id_hex: owned_c_string(value.my_account_id_hex),
            is_self_admin: value.is_self_admin,
            is_last_admin: value.is_last_admin,
            can_invite: value.can_invite,
            can_leave: value.can_leave,
            requires_self_demote_before_leave: value.requires_self_demote_before_leave,
            member_actions,
            member_actions_len,
        }
    }
}

impl CFree for MarmotGroupManagementState {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.my_account_id_hex);
            free_vec(self.member_actions, self.member_actions_len);
        }
    }
}

/// Free a group management state root. NULL is a no-op.
///
/// # Safety
/// `state` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_management_state_free(
    state: *mut MarmotGroupManagementState,
) {
    unsafe { free_boxed(state) };
}

/// Combined result of a `*_detailed` group mutation: the publish summary
/// plus the refreshed group details and management state.
#[repr(C)]
pub struct MarmotGroupMutationResult {
    pub summary: MarmotSendSummary,
    pub details: MarmotGroupDetails,
    pub management_state: MarmotGroupManagementState,
}

impl From<GroupMutationResultFfi> for MarmotGroupMutationResult {
    fn from(value: GroupMutationResultFfi) -> Self {
        Self {
            summary: value.summary.into(),
            details: value.details.into(),
            management_state: value.management_state.into(),
        }
    }
}

impl CFree for MarmotGroupMutationResult {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            self.summary.free_in_place();
            self.details.free_in_place();
            self.management_state.free_in_place();
        }
    }
}

/// Free a group mutation result root. NULL is a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_mutation_result_free(result: *mut MarmotGroupMutationResult) {
    unsafe { free_boxed(result) };
}

/// Result of declining a group invite: the updated group record plus the
/// publish summary of the decline.
#[repr(C)]
pub struct MarmotGroupInviteDeclineResult {
    pub group: MarmotAppGroupRecord,
    pub summary: MarmotSendSummary,
}

impl From<GroupInviteDeclineResultFfi> for MarmotGroupInviteDeclineResult {
    fn from(value: GroupInviteDeclineResultFfi) -> Self {
        Self {
            group: value.group.into(),
            summary: value.summary.into(),
        }
    }
}

impl CFree for MarmotGroupInviteDeclineResult {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            self.group.free_in_place();
            self.summary.free_in_place();
        }
    }
}

/// Free a group invite decline result root. NULL is a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_invite_decline_result_free(
    result: *mut MarmotGroupInviteDeclineResult,
) {
    unsafe { free_boxed(result) };
}

/// MLS-level group state for the conversation's developer/debug view: the
/// current epoch, live member count, and the app components the group
/// requires.
#[repr(C)]
pub struct MarmotAppGroupMlsState {
    pub group_id_hex: *mut c_char,
    pub epoch: u64,
    pub member_count: u32,
    pub required_app_components: *mut u16,
    pub required_app_components_len: usize,
}

impl From<AppGroupMlsStateFfi> for MarmotAppGroupMlsState {
    fn from(value: AppGroupMlsStateFfi) -> Self {
        let (required_app_components, required_app_components_len) =
            owned_vec(value.required_app_components);
        Self {
            group_id_hex: owned_c_string(value.group_id_hex),
            epoch: value.epoch,
            member_count: value.member_count,
            required_app_components,
            required_app_components_len,
        }
    }
}

impl CFree for MarmotAppGroupMlsState {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_vec(
                self.required_app_components,
                self.required_app_components_len,
            );
        }
    }
}

/// Free a group MLS state root. NULL is a no-op.
///
/// # Safety
/// `state` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_group_mls_state_free(state: *mut MarmotAppGroupMlsState) {
    unsafe { free_boxed(state) };
}

/// Coarse, privacy-safe reason a stored group failed session-open hydration
/// and was quarantined. Carries no group/member ids, payloads, or key
/// material — only a category the client can map to per-reason recovery
/// guidance.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotAppGroupHydrationQuarantineReason {
    /// The MLS stack returned an error while loading the stored group state.
    OpenMlsLoadFailed,
    /// Marmot metadata referenced a group whose MLS state was missing.
    OpenMlsGroupMissing,
    /// Member credentials, account-identity proofs, or ratchet-tree export
    /// validation failed for the loaded MLS group.
    MemberValidationFailed,
    /// The Marmot group record could not be loaded or refreshed.
    GroupRecordLoadFailed,
    /// Hydrate found a stranded pending commit, but recovery itself failed.
    PendingCommitRecoveryFailed,
}

impl From<AppGroupHydrationQuarantineReasonFfi> for MarmotAppGroupHydrationQuarantineReason {
    fn from(value: AppGroupHydrationQuarantineReasonFfi) -> Self {
        match value {
            AppGroupHydrationQuarantineReasonFfi::OpenMlsLoadFailed => Self::OpenMlsLoadFailed,
            AppGroupHydrationQuarantineReasonFfi::OpenMlsGroupMissing => Self::OpenMlsGroupMissing,
            AppGroupHydrationQuarantineReasonFfi::MemberValidationFailed => {
                Self::MemberValidationFailed
            }
            AppGroupHydrationQuarantineReasonFfi::GroupRecordLoadFailed => {
                Self::GroupRecordLoadFailed
            }
            AppGroupHydrationQuarantineReasonFfi::PendingCommitRecoveryFailed => {
                Self::PendingCommitRecoveryFailed
            }
        }
    }
}

impl CFree for MarmotAppGroupHydrationQuarantineReason {
    unsafe fn free_in_place(&mut self) {}
}

/// A stored group that failed session-open hydration and was skipped so the
/// rest of the account could open. Surfaced so the app can present a
/// per-group recovery flow distinct from healthy and archived groups, and
/// offer a non-destructive re-hydration retry.
#[repr(C)]
pub struct MarmotAppQuarantinedGroup {
    pub group_id_hex: *mut c_char,
    pub reason: MarmotAppGroupHydrationQuarantineReason,
}

impl From<AppQuarantinedGroupFfi> for MarmotAppQuarantinedGroup {
    fn from(value: AppQuarantinedGroupFfi) -> Self {
        Self {
            group_id_hex: owned_c_string(value.group_id_hex),
            reason: value.reason.into(),
        }
    }
}

impl CFree for MarmotAppQuarantinedGroup {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(self.group_id_hex) };
    }
}

/// Owned list of quarantined groups (`marmot_quarantined_groups`).
#[repr(C)]
pub struct MarmotAppQuarantinedGroupList {
    pub items: *mut MarmotAppQuarantinedGroup,
    pub len: usize,
}

impl From<Vec<AppQuarantinedGroupFfi>> for MarmotAppQuarantinedGroupList {
    fn from(value: Vec<AppQuarantinedGroupFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAppQuarantinedGroupList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_quarantined_groups`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_app_quarantined_group_list_free(
    list: *mut MarmotAppQuarantinedGroupList,
) {
    unsafe { free_boxed(list) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;
    use marmot_uniffi::conversions::{SelfMembershipFfi, SendSummaryFfi};

    fn sample_encrypted_media() -> AppGroupEncryptedMediaComponentFfi {
        AppGroupEncryptedMediaComponentFfi {
            component_id: 2,
            component: "marmot.group.encrypted-media.v1".into(),
            required: true,
            media_format: "mip04-v2".into(),
            allowed_locator_kinds: vec!["blossom".into(), "https".into()],
            default_blob_endpoints: vec![AppBlobEndpointFfi {
                locator_kind: "blossom".into(),
                base_url: "https://blossom.example".into(),
            }],
        }
    }

    fn sample_group_record() -> AppGroupRecordFfi {
        AppGroupRecordFfi {
            group_id_hex: "aabbccdd".into(),
            endpoint: "nostr".into(),
            name: "burrow".into(),
            description: "alpine chat".into(),
            admins: vec!["aa11".into()],
            relays: vec![
                "wss://relay.example/one".into(),
                "wss://relay.example/two".into(),
            ],
            nostr_group_id_hex: "ee".repeat(32),
            avatar_url: Some("https://img.example/a.png".into()),
            avatar_dim: Some("64x64".into()),
            avatar_thumbhash: Some("abcd".into()),
            image_hash_hex: Some("beef".into()),
            encrypted_media: sample_encrypted_media(),
            disappearing_message_secs: 3600,
            archived: false,
            pending_confirmation: true,
            self_membership: SelfMembershipFfi::Member,
            welcomer_account_id_hex: Some("cc22".into()),
            via_welcome_message_id_hex: Some("dd33".into()),
        }
    }

    fn sample_member_details() -> GroupMemberDetailsFfi {
        GroupMemberDetailsFfi {
            member_id_hex: "aa11".into(),
            account: Some("primary".into()),
            local: true,
            is_admin: true,
            is_self: true,
            npub: "npub1example".into(),
            display_name: Some("Marmy".into()),
        }
    }

    fn sample_details() -> GroupDetailsFfi {
        GroupDetailsFfi {
            group: sample_group_record(),
            members: vec![sample_member_details()],
        }
    }

    fn sample_management_state() -> GroupManagementStateFfi {
        GroupManagementStateFfi {
            my_account_id_hex: "aa11".into(),
            is_self_admin: true,
            is_last_admin: false,
            can_invite: true,
            can_leave: false,
            requires_self_demote_before_leave: true,
            member_actions: vec![GroupMemberActionStateFfi {
                member_id_hex: "bb22".into(),
                is_self: false,
                is_admin: false,
                can_remove: true,
                can_promote: true,
                can_demote: false,
            }],
        }
    }

    fn sample_send_summary() -> SendSummaryFfi {
        SendSummaryFfi {
            published: 1,
            message_ids: vec!["ff".repeat(32)],
        }
    }

    #[test]
    fn group_record_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAppGroupRecord = sample_group_record().into();
        assert_eq!(mirror.admins_len, 1);
        assert_eq!(mirror.relays_len, 2);
        assert!(!mirror.avatar_url.is_null());
        assert_eq!(mirror.disappearing_message_secs, 3600);
        assert_eq!(mirror.self_membership, MarmotSelfMembership::Member);
        assert_eq!(mirror.encrypted_media.allowed_locator_kinds_len, 2);
        assert_eq!(mirror.encrypted_media.default_blob_endpoints_len, 1);
        assert!(!mirror.welcomer_account_id_hex.is_null());
        let name = unsafe { std::ffi::CStr::from_ptr(mirror.name) }
            .to_str()
            .expect("valid UTF-8");
        assert_eq!(name, "burrow");
        let root = boxed(mirror);
        unsafe { marmot_app_group_record_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn blob_endpoint_input_roundtrips_borrowed_fields() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mut owned: MarmotAppBlobEndpoint = AppBlobEndpointFfi {
            locator_kind: "blossom".into(),
            base_url: "https://blossom.example".into(),
        }
        .into();
        let ffi = unsafe { owned.to_ffi() }.expect("valid strings");
        assert_eq!(ffi.locator_kind, "blossom");
        assert_eq!(ffi.base_url, "https://blossom.example");
        unsafe { owned.free_in_place() };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_member_record_list_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotAppGroupMemberRecordList = vec![AppGroupMemberRecordFfi {
            member_id_hex: "aa11".into(),
            account: Some("primary".into()),
            local: true,
        }]
        .into();
        assert_eq!(list.len, 1);
        assert!(!list.items.is_null());
        let first = unsafe { &*list.items };
        assert!(first.local);
        assert!(!first.account.is_null());
        let root = boxed(list);
        unsafe { marmot_app_group_member_record_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn member_ref_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotMemberRef = MemberRefFfi {
            member_ref: "aa11".into(),
            account_id_hex: "aa11".into(),
            npub: "npub1example".into(),
        }
        .into();
        let npub = unsafe { std::ffi::CStr::from_ptr(mirror.npub) }
            .to_str()
            .expect("valid UTF-8");
        assert_eq!(npub, "npub1example");
        let root = boxed(mirror);
        unsafe { marmot_member_ref_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_details_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotGroupDetails = sample_details().into();
        assert_eq!(mirror.members_len, 1);
        let member = unsafe { &*mirror.members };
        assert!(member.is_admin);
        assert!(!member.display_name.is_null());
        assert!(!mirror.group.group_id_hex.is_null());
        let root = boxed(mirror);
        unsafe { marmot_group_details_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_management_state_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotGroupManagementState = sample_management_state().into();
        assert!(mirror.is_self_admin);
        assert!(mirror.requires_self_demote_before_leave);
        assert_eq!(mirror.member_actions_len, 1);
        let action = unsafe { &*mirror.member_actions };
        assert!(action.can_remove);
        assert!(!action.can_demote);
        let root = boxed(mirror);
        unsafe { marmot_group_management_state_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_mutation_result_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotGroupMutationResult = GroupMutationResultFfi {
            summary: sample_send_summary(),
            details: sample_details(),
            management_state: sample_management_state(),
        }
        .into();
        assert_eq!(mirror.summary.published, 1);
        assert_eq!(mirror.summary.message_ids_len, 1);
        assert_eq!(mirror.details.members_len, 1);
        assert_eq!(mirror.management_state.member_actions_len, 1);
        let root = boxed(mirror);
        unsafe { marmot_group_mutation_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_invite_decline_result_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotGroupInviteDeclineResult = GroupInviteDeclineResultFfi {
            group: sample_group_record(),
            summary: sample_send_summary(),
        }
        .into();
        assert!(!mirror.group.group_id_hex.is_null());
        assert_eq!(mirror.summary.published, 1);
        let root = boxed(mirror);
        unsafe { marmot_group_invite_decline_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_mls_state_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAppGroupMlsState = AppGroupMlsStateFfi {
            group_id_hex: "aabb".into(),
            epoch: 42,
            member_count: 3,
            required_app_components: vec![1, 2, 3],
        }
        .into();
        assert_eq!(mirror.epoch, 42);
        assert_eq!(mirror.member_count, 3);
        assert_eq!(mirror.required_app_components_len, 3);
        assert_eq!(unsafe { *mirror.required_app_components.add(2) }, 3);
        let root = boxed(mirror);
        unsafe { marmot_app_group_mls_state_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn quarantined_group_list_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotAppQuarantinedGroupList = vec![
            AppQuarantinedGroupFfi {
                group_id_hex: "aa".into(),
                reason: AppGroupHydrationQuarantineReasonFfi::OpenMlsLoadFailed,
            },
            AppQuarantinedGroupFfi {
                group_id_hex: "bb".into(),
                reason: AppGroupHydrationQuarantineReasonFfi::PendingCommitRecoveryFailed,
            },
        ]
        .into();
        assert_eq!(list.len, 2);
        let first = unsafe { &*list.items };
        assert_eq!(
            first.reason,
            MarmotAppGroupHydrationQuarantineReason::OpenMlsLoadFailed
        );
        let second = unsafe { &*list.items.add(1) };
        assert_eq!(
            second.reason,
            MarmotAppGroupHydrationQuarantineReason::PendingCommitRecoveryFailed
        );
        let root = boxed(list);
        unsafe { marmot_app_quarantined_group_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn quarantine_reason_maps_all_variants() {
        let _guard = crate::memory::audit::test_lock();
        for (ffi, mirror) in [
            (
                AppGroupHydrationQuarantineReasonFfi::OpenMlsLoadFailed,
                MarmotAppGroupHydrationQuarantineReason::OpenMlsLoadFailed,
            ),
            (
                AppGroupHydrationQuarantineReasonFfi::OpenMlsGroupMissing,
                MarmotAppGroupHydrationQuarantineReason::OpenMlsGroupMissing,
            ),
            (
                AppGroupHydrationQuarantineReasonFfi::MemberValidationFailed,
                MarmotAppGroupHydrationQuarantineReason::MemberValidationFailed,
            ),
            (
                AppGroupHydrationQuarantineReasonFfi::GroupRecordLoadFailed,
                MarmotAppGroupHydrationQuarantineReason::GroupRecordLoadFailed,
            ),
            (
                AppGroupHydrationQuarantineReasonFfi::PendingCommitRecoveryFailed,
                MarmotAppGroupHydrationQuarantineReason::PendingCommitRecoveryFailed,
            ),
        ] {
            assert_eq!(MarmotAppGroupHydrationQuarantineReason::from(ffi), mirror);
        }
    }

    #[test]
    fn empty_vecs_and_nones_convert_to_null() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();

        let mut record = sample_group_record();
        record.admins = Vec::new();
        record.relays = Vec::new();
        record.avatar_url = None;
        record.avatar_dim = None;
        record.avatar_thumbhash = None;
        record.welcomer_account_id_hex = None;
        record.via_welcome_message_id_hex = None;
        record.encrypted_media.allowed_locator_kinds = Vec::new();
        record.encrypted_media.default_blob_endpoints = Vec::new();
        let mirror: MarmotAppGroupRecord = record.into();
        assert!(mirror.admins.is_null());
        assert_eq!(mirror.admins_len, 0);
        assert!(mirror.relays.is_null());
        assert!(mirror.avatar_url.is_null());
        assert!(mirror.avatar_dim.is_null());
        assert!(mirror.avatar_thumbhash.is_null());
        assert!(mirror.welcomer_account_id_hex.is_null());
        assert!(mirror.via_welcome_message_id_hex.is_null());
        assert!(mirror.encrypted_media.allowed_locator_kinds.is_null());
        assert!(mirror.encrypted_media.default_blob_endpoints.is_null());
        let root = boxed(mirror);
        unsafe { marmot_app_group_record_free(root) };

        let list: MarmotAppGroupRecordList = Vec::<AppGroupRecordFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_app_group_record_list_free(root) };

        let list: MarmotAppQuarantinedGroupList = Vec::<AppQuarantinedGroupFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_app_quarantined_group_list_free(root) };
    }
}
