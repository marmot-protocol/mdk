//! C mirrors of the account conversions (`marmot-uniffi/src/conversions/account.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    AccountKeyPackageFfi, AccountSummaryFfi, AccountUnreadFfi, GroupLeaveFailureFfi,
    LocalCleanupReportFfi, RelayFailureFfi, SendSummaryFfi, SignOutOutcomeFfi,
    UserProfileMetadataFfi, WipeOutcomeFfi,
};

use crate::MarmotStatus;
use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, optional_str, owned_c_string, owned_opt_c_string,
    owned_vec,
};

/// One signed-in (or signed-out but known) account.
#[repr(C)]
pub struct MarmotAccountSummary {
    pub label: *mut c_char,
    pub account_id_hex: *mut c_char,
    pub local_signing: bool,
    pub signed_out: bool,
    pub running: bool,
}

impl From<AccountSummaryFfi> for MarmotAccountSummary {
    fn from(value: AccountSummaryFfi) -> Self {
        Self {
            label: owned_c_string(value.label),
            account_id_hex: owned_c_string(value.account_id_hex),
            local_signing: value.local_signing,
            signed_out: value.signed_out,
            running: value.running,
        }
    }
}

impl CFree for MarmotAccountSummary {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.label);
            free_c_string(self.account_id_hex);
        }
    }
}

/// Owned list of account summaries (`marmot_list_accounts`).
#[repr(C)]
pub struct MarmotAccountSummaryList {
    pub items: *mut MarmotAccountSummary,
    pub len: usize,
}

impl From<Vec<AccountSummaryFfi>> for MarmotAccountSummaryList {
    fn from(value: Vec<AccountSummaryFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAccountSummaryList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_list_accounts`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_summary_list_free(list: *mut MarmotAccountSummaryList) {
    crate::memory::free_guard(|| unsafe { free_boxed(list) });
}

/// Free a single account summary root. NULL is a no-op.
///
/// # Safety
/// `summary` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_summary_free(summary: *mut MarmotAccountSummary) {
    crate::memory::free_guard(|| unsafe { free_boxed(summary) });
}

/// Per-account unread aggregate for the account-switcher badge.
#[repr(C)]
pub struct MarmotAccountUnread {
    pub account_id_hex: *mut c_char,
    /// Total unread messages across all unarchived conversations.
    pub unread_count: u64,
    /// Number of unarchived conversations with at least one unread message.
    pub unread_conversations: u64,
    /// Whether the account has any unread message at all.
    pub has_unread: bool,
}

impl From<AccountUnreadFfi> for MarmotAccountUnread {
    fn from(value: AccountUnreadFfi) -> Self {
        Self {
            account_id_hex: owned_c_string(value.account_id_hex),
            unread_count: value.unread_count,
            unread_conversations: value.unread_conversations,
            has_unread: value.has_unread,
        }
    }
}

impl CFree for MarmotAccountUnread {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(self.account_id_hex) };
    }
}

/// Owned list of unread aggregates (`marmot_account_unread_summary`).
#[repr(C)]
pub struct MarmotAccountUnreadList {
    pub items: *mut MarmotAccountUnread,
    pub len: usize,
}

impl From<Vec<AccountUnreadFfi>> for MarmotAccountUnreadList {
    fn from(value: Vec<AccountUnreadFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAccountUnreadList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_account_unread_summary`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_unread_list_free(list: *mut MarmotAccountUnreadList) {
    crate::memory::free_guard(|| unsafe { free_boxed(list) });
}

/// Publish outcome for send-shaped operations.
#[repr(C)]
pub struct MarmotSendSummary {
    pub published: u32,
    pub message_ids: *mut *mut c_char,
    pub message_ids_len: usize,
}

impl From<SendSummaryFfi> for MarmotSendSummary {
    fn from(value: SendSummaryFfi) -> Self {
        let (message_ids, message_ids_len) = owned_vec(
            value
                .message_ids
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            published: value.published,
            message_ids,
            message_ids_len,
        }
    }
}

impl CFree for MarmotSendSummary {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.message_ids, self.message_ids_len) };
    }
}

/// Free a send summary root. NULL is a no-op.
///
/// # Safety
/// `summary` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_send_summary_free(summary: *mut MarmotSendSummary) {
    crate::memory::free_guard(|| unsafe { free_boxed(summary) });
}

/// One published (or locally known) MLS KeyPackage.
#[repr(C)]
pub struct MarmotAccountKeyPackage {
    /// Account label, when known. Nullable.
    pub account_ref: *mut c_char,
    pub account_id_hex: *mut c_char,
    pub key_package_id: *mut c_char,
    pub key_package_ref_hex: *mut c_char,
    pub event_id_hex: *mut c_char,
    pub published_at: u64,
    pub key_package_bytes: u64,
    pub source_relays: *mut *mut c_char,
    pub source_relays_len: usize,
    pub local: bool,
    pub relay: bool,
}

impl From<AccountKeyPackageFfi> for MarmotAccountKeyPackage {
    fn from(value: AccountKeyPackageFfi) -> Self {
        let (source_relays, source_relays_len) = owned_vec(
            value
                .source_relays
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            account_ref: owned_opt_c_string(value.account_ref),
            account_id_hex: owned_c_string(value.account_id_hex),
            key_package_id: owned_c_string(value.key_package_id),
            key_package_ref_hex: owned_c_string(value.key_package_ref_hex),
            event_id_hex: owned_c_string(value.event_id_hex),
            published_at: value.published_at,
            key_package_bytes: value.key_package_bytes,
            source_relays,
            source_relays_len,
            local: value.local,
            relay: value.relay,
        }
    }
}

impl CFree for MarmotAccountKeyPackage {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_ref);
            free_c_string(self.account_id_hex);
            free_c_string(self.key_package_id);
            free_c_string(self.key_package_ref_hex);
            free_c_string(self.event_id_hex);
            free_vec(self.source_relays, self.source_relays_len);
        }
    }
}

/// Owned list of key packages (`marmot_account_key_packages`).
#[repr(C)]
pub struct MarmotAccountKeyPackageList {
    pub items: *mut MarmotAccountKeyPackage,
    pub len: usize,
}

impl From<Vec<AccountKeyPackageFfi>> for MarmotAccountKeyPackageList {
    fn from(value: Vec<AccountKeyPackageFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAccountKeyPackageList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_account_key_packages`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_key_package_list_free(
    list: *mut MarmotAccountKeyPackageList,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(list) });
}

/// Nostr user profile metadata. All fields nullable. Used both as a
/// return value (owned; free the root) and as a borrowed input to
/// `marmot_publish_user_profile` (caller-owned; this library never frees
/// input structs).
#[repr(C)]
pub struct MarmotUserProfileMetadata {
    pub name: *mut c_char,
    pub display_name: *mut c_char,
    pub about: *mut c_char,
    pub picture: *mut c_char,
    pub nip05: *mut c_char,
    pub lud16: *mut c_char,
}

impl From<UserProfileMetadataFfi> for MarmotUserProfileMetadata {
    fn from(value: UserProfileMetadataFfi) -> Self {
        Self {
            name: owned_opt_c_string(value.name),
            display_name: owned_opt_c_string(value.display_name),
            about: owned_opt_c_string(value.about),
            picture: owned_opt_c_string(value.picture),
            nip05: owned_opt_c_string(value.nip05),
            lud16: owned_opt_c_string(value.lud16),
        }
    }
}

impl MarmotUserProfileMetadata {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<UserProfileMetadataFfi, MarmotStatus> {
        Ok(UserProfileMetadataFfi {
            name: unsafe { optional_str(self.name) }?,
            display_name: unsafe { optional_str(self.display_name) }?,
            about: unsafe { optional_str(self.about) }?,
            picture: unsafe { optional_str(self.picture) }?,
            nip05: unsafe { optional_str(self.nip05) }?,
            lud16: unsafe { optional_str(self.lud16) }?,
        })
    }
}

impl CFree for MarmotUserProfileMetadata {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.name);
            free_c_string(self.display_name);
            free_c_string(self.about);
            free_c_string(self.picture);
            free_c_string(self.nip05);
            free_c_string(self.lud16);
        }
    }
}

/// Free a profile returned by this library. Never call on structs you
/// allocated yourself as inputs. NULL is a no-op.
///
/// # Safety
/// `profile` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_user_profile_metadata_free(
    profile: *mut MarmotUserProfileMetadata,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(profile) });
}

/// Per-group leave failure inside a wipe outcome. Best-effort: the wipe
/// does not abort on these.
#[repr(C)]
pub struct MarmotGroupLeaveFailure {
    pub group_id_hex: *mut c_char,
    pub reason: *mut c_char,
}

impl From<GroupLeaveFailureFfi> for MarmotGroupLeaveFailure {
    fn from(value: GroupLeaveFailureFfi) -> Self {
        Self {
            group_id_hex: owned_c_string(value.group_id_hex),
            reason: owned_c_string(value.reason),
        }
    }
}

impl CFree for MarmotGroupLeaveFailure {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.group_id_hex);
            free_c_string(self.reason);
        }
    }
}

/// Per-relay KeyPackage deletion (or discovery) failure.
#[repr(C)]
pub struct MarmotRelayFailure {
    pub event_id_hex: *mut c_char,
    pub reason: *mut c_char,
}

impl From<RelayFailureFfi> for MarmotRelayFailure {
    fn from(value: RelayFailureFfi) -> Self {
        Self {
            event_id_hex: owned_c_string(value.event_id_hex),
            reason: owned_c_string(value.reason),
        }
    }
}

impl CFree for MarmotRelayFailure {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.event_id_hex);
            free_c_string(self.reason);
        }
    }
}

/// Local cleanup result inside a sign-out/wipe outcome.
#[repr(C)]
pub struct MarmotLocalCleanupReport {
    pub completed: bool,
    /// Failure classification when not completed. Nullable.
    pub reason: *mut c_char,
}

impl From<LocalCleanupReportFfi> for MarmotLocalCleanupReport {
    fn from(value: LocalCleanupReportFfi) -> Self {
        Self {
            completed: value.completed,
            reason: owned_opt_c_string(value.reason),
        }
    }
}

impl CFree for MarmotLocalCleanupReport {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(self.reason) };
    }
}

/// Structured result of the destructive sign-out-and-wipe.
#[repr(C)]
pub struct MarmotWipeOutcome {
    /// Active MLS groups this account successfully left.
    pub groups_left: u32,
    pub group_leave_failures: *mut MarmotGroupLeaveFailure,
    pub group_leave_failures_len: usize,
    /// Relay-published KeyPackage events successfully deleted.
    pub key_packages_deleted: u32,
    pub key_package_failures: *mut MarmotRelayFailure,
    pub key_package_failures_len: usize,
    pub local_cleanup: MarmotLocalCleanupReport,
}

impl From<WipeOutcomeFfi> for MarmotWipeOutcome {
    fn from(value: WipeOutcomeFfi) -> Self {
        let (group_leave_failures, group_leave_failures_len) = owned_vec(
            value
                .group_leave_failures
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        let (key_package_failures, key_package_failures_len) = owned_vec(
            value
                .key_package_failures
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        Self {
            groups_left: value.groups_left,
            group_leave_failures,
            group_leave_failures_len,
            key_packages_deleted: value.key_packages_deleted,
            key_package_failures,
            key_package_failures_len,
            local_cleanup: value.local_cleanup.into(),
        }
    }
}

impl CFree for MarmotWipeOutcome {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.group_leave_failures, self.group_leave_failures_len);
            free_vec(self.key_package_failures, self.key_package_failures_len);
            self.local_cleanup.free_in_place();
        }
    }
}

/// Free a wipe outcome root. NULL is a no-op.
///
/// # Safety
/// `outcome` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_wipe_outcome_free(outcome: *mut MarmotWipeOutcome) {
    crate::memory::free_guard(|| unsafe { free_boxed(outcome) });
}

/// Structured result of the non-destructive sign-out.
#[repr(C)]
pub struct MarmotSignOutOutcome {
    /// Relay-published KeyPackage events successfully deleted. `0` when
    /// KeyPackage deletion was not requested.
    pub key_packages_deleted: u32,
    pub key_package_failures: *mut MarmotRelayFailure,
    pub key_package_failures_len: usize,
    pub local_cleanup: MarmotLocalCleanupReport,
}

impl From<SignOutOutcomeFfi> for MarmotSignOutOutcome {
    fn from(value: SignOutOutcomeFfi) -> Self {
        let (key_package_failures, key_package_failures_len) = owned_vec(
            value
                .key_package_failures
                .into_iter()
                .map(Into::into)
                .collect(),
        );
        Self {
            key_packages_deleted: value.key_packages_deleted,
            key_package_failures,
            key_package_failures_len,
            local_cleanup: value.local_cleanup.into(),
        }
    }
}

impl CFree for MarmotSignOutOutcome {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.key_package_failures, self.key_package_failures_len);
            self.local_cleanup.free_in_place();
        }
    }
}

/// Free a sign-out outcome root. NULL is a no-op.
///
/// # Safety
/// `outcome` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_sign_out_outcome_free(outcome: *mut MarmotSignOutOutcome) {
    crate::memory::free_guard(|| unsafe { free_boxed(outcome) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    fn sample_wipe_outcome() -> WipeOutcomeFfi {
        WipeOutcomeFfi {
            groups_left: 2,
            group_leave_failures: vec![GroupLeaveFailureFfi {
                group_id_hex: "aabb".into(),
                reason: "relay unreachable".into(),
            }],
            key_packages_deleted: 3,
            key_package_failures: vec![
                RelayFailureFfi {
                    event_id_hex: "cc".into(),
                    reason: "timeout".into(),
                },
                RelayFailureFfi {
                    event_id_hex: "dd".into(),
                    reason: "rejected".into(),
                },
            ],
            local_cleanup: LocalCleanupReportFfi {
                completed: false,
                reason: Some("media cache busy".into()),
            },
        }
    }

    #[test]
    fn wipe_outcome_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotWipeOutcome = sample_wipe_outcome().into();
        assert_eq!(mirror.groups_left, 2);
        assert_eq!(mirror.group_leave_failures_len, 1);
        assert_eq!(mirror.key_package_failures_len, 2);
        assert!(!mirror.local_cleanup.completed);
        assert!(!mirror.local_cleanup.reason.is_null());
        let root = boxed(mirror);
        unsafe { marmot_wipe_outcome_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn profile_input_roundtrips_borrowed_fields() {
        let _guard = crate::memory::audit::test_lock();
        let owned: MarmotUserProfileMetadata = UserProfileMetadataFfi {
            name: Some("marmy".into()),
            display_name: None,
            about: Some("burrow enthusiast".into()),
            picture: None,
            nip05: None,
            lud16: None,
        }
        .into();
        let ffi = unsafe { owned.to_ffi() }.expect("valid strings");
        assert_eq!(ffi.name.as_deref(), Some("marmy"));
        assert_eq!(ffi.display_name, None);
        assert_eq!(ffi.about.as_deref(), Some("burrow enthusiast"));
        let root = boxed(owned);
        unsafe { marmot_user_profile_metadata_free(root) };
    }

    #[test]
    fn empty_lists_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let list: MarmotAccountSummaryList = Vec::<AccountSummaryFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_account_summary_list_free(root) };
    }
}
