//! C mirrors of the account conversions.

use marmot_uniffi::conversions::{
    AccountKeyPackageFfi, AccountSetupReadinessFfi, AccountSummaryFfi, AccountUnreadFfi,
    GroupLeaveFailureFfi, IdentityCreationResultFfi, LocalCleanupReportFfi, RelayFailureFfi,
    SendAcceptDispositionFfi, SendMaintenanceDispositionFfi, SendSummaryFfi, SignOutOutcomeFfi,
    UserProfileMetadataFfi, WipeOutcomeFfi,
};

use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::optional_str;

c_mirror! {
    /// One signed-in (or signed-out but known) account.
    MarmotAccountSummary from AccountSummaryFfi,
    free marmot_account_summary_free,
    list(MarmotAccountSummaryList, marmot_account_summary_list_free) {
        str label,
        str account_id_hex,
        copy local_signing: bool,
        copy external_signing: bool,
        copy signed_out: bool,
        copy running: bool,
    }
}

c_mirror! {
    /// Per-account unread aggregate for the account-switcher badge.
    MarmotAccountUnread from AccountUnreadFfi,
    list(MarmotAccountUnreadList, marmot_account_unread_list_free) {
        str account_id_hex,
        /// Total unread messages across all unarchived conversations.
        copy unread_count: u64,
        /// Number of unarchived conversations that require badge attention.
        copy unread_conversations: u64,
        /// Conversations with badge attention solely from a manual-unread
        /// reminder or pending invitation (no unread messages).
        copy attention_only_conversations: u64,
        /// Whether the account has any badge-worthy conversation.
        copy has_unread: bool,
    }
}

c_enum! {
    /// Post-send maintenance posture.
    MarmotSendMaintenanceDisposition from SendMaintenanceDispositionFfi {
        Ready,
        PostJoinRotationPendingRetryable,
    }
}

c_enum! {
    /// Whether the send published immediately or was accepted pending.
    MarmotSendAcceptDisposition from SendAcceptDispositionFfi {
        Published,
        AcceptedPending,
    }
}

c_mirror! {
    /// Publish outcome for send-shaped operations.
    MarmotSendSummary from SendSummaryFfi,
    free marmot_send_summary_free {
        copy published: u32,
        str_vec message_ids/message_ids_len,
        copy accept_disposition: MarmotSendAcceptDisposition,
        copy maintenance_disposition: MarmotSendMaintenanceDisposition,
    }
}

c_mirror! {
    /// One published (or locally known) MLS KeyPackage.
    MarmotAccountKeyPackage from AccountKeyPackageFfi,
    list(MarmotAccountKeyPackageList, marmot_account_key_package_list_free) {
        /// Account label, when known. Nullable.
        opt_str account_ref,
        str account_id_hex,
        str key_package_id,
        str key_package_ref_hex,
        str event_id_hex,
        copy published_at: u64,
        copy key_package_bytes: u64,
        str_vec source_relays/source_relays_len,
        copy local: bool,
        copy relay: bool,
    }
}

c_mirror! {
    /// Nostr user profile metadata. All fields nullable. Used both as a
    /// return value (owned; free the root) and as a borrowed input to
    /// `marmot_publish_user_profile` (caller-owned; never freed by the
    /// library).
    MarmotUserProfileMetadata from UserProfileMetadataFfi,
    free marmot_user_profile_metadata_free {
        opt_str name,
        opt_str display_name,
        opt_str about,
        opt_str picture,
        opt_str banner,
        opt_str nip05,
        opt_str lud16,
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
            banner: unsafe { optional_str(self.banner) }?,
            nip05: unsafe { optional_str(self.nip05) }?,
            lud16: unsafe { optional_str(self.lud16) }?,
        })
    }
}

c_enum! {
    /// How far an account's setup has progressed.
    MarmotAccountSetupReadiness from AccountSetupReadinessFfi {
        Initializing,
        LocalReady,
        Publishing,
        NetworkReady,
        /// Setup stopped partway; recover with
        /// `marmot_login_recovering_incomplete_setup` or discard it with
        /// `marmot_reset_incomplete_account_setup`.
        RecoveryRequired,
    }
}

c_mirror! {
    /// A freshly created identity plus its published profile and setup
    /// progress. Free with `marmot_identity_creation_result_free`.
    MarmotIdentityCreationResult from IdentityCreationResultFfi,
    free marmot_identity_creation_result_free {
        rec account: MarmotAccountSummary,
        rec profile: MarmotUserProfileMetadata,
        copy readiness: MarmotAccountSetupReadiness,
    }
}

c_mirror! {
    /// Per-group leave failure inside a wipe outcome. Best-effort: the
    /// wipe does not abort on these.
    MarmotGroupLeaveFailure from GroupLeaveFailureFfi {
        str group_id_hex,
        str reason,
    }
}

c_mirror! {
    /// Per-relay KeyPackage deletion (or discovery) failure.
    MarmotRelayFailure from RelayFailureFfi {
        str event_id_hex,
        str reason,
    }
}

c_mirror! {
    /// Local cleanup result inside a sign-out/wipe outcome.
    MarmotLocalCleanupReport from LocalCleanupReportFfi {
        copy completed: bool,
        /// Failure classification when not completed. Nullable.
        opt_str reason,
    }
}

c_mirror! {
    /// Structured result of the destructive sign-out-and-wipe.
    MarmotWipeOutcome from WipeOutcomeFfi,
    free marmot_wipe_outcome_free {
        /// Active MLS groups this account successfully left.
        copy groups_left: u32,
        vec group_leave_failures/group_leave_failures_len: MarmotGroupLeaveFailure,
        /// Relay-published KeyPackage events successfully deleted.
        copy key_packages_deleted: u32,
        vec key_package_failures/key_package_failures_len: MarmotRelayFailure,
        rec local_cleanup: MarmotLocalCleanupReport,
    }
}

c_mirror! {
    /// Structured result of the non-destructive sign-out.
    MarmotSignOutOutcome from SignOutOutcomeFfi,
    free marmot_sign_out_outcome_free {
        /// Relay-published KeyPackage events successfully deleted. `0`
        /// when KeyPackage deletion was not requested.
        copy key_packages_deleted: u32,
        vec key_package_failures/key_package_failures_len: MarmotRelayFailure,
        rec local_cleanup: MarmotLocalCleanupReport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    // One deep-roundtrip test per macro shape (nested record, vec,
    // opt_str, list) — the macros generate every other type the same way.
    #[test]
    fn wipe_outcome_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotWipeOutcome = WipeOutcomeFfi {
            groups_left: 2,
            group_leave_failures: vec![GroupLeaveFailureFfi {
                group_id_hex: "aabb".into(),
                reason: "relay unreachable".into(),
            }],
            key_packages_deleted: 3,
            key_package_failures: vec![RelayFailureFfi {
                event_id_hex: "cc".into(),
                reason: "timeout".into(),
            }],
            local_cleanup: LocalCleanupReportFfi {
                completed: false,
                reason: Some("media cache busy".into()),
            },
        }
        .into();
        assert_eq!(mirror.groups_left, 2);
        assert_eq!(mirror.group_leave_failures_len, 1);
        assert_eq!(mirror.key_package_failures_len, 1);
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
            banner: None,
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
