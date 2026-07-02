//! Account summary, send summary, key-package, and user-profile FFI conversions.

use marmot_app::{
    AccountKeyPackageRecord, AccountUnread, GroupLeaveFailure, LocalCleanupReport, RelayFailure,
    SendSummary, SignOutOutcome, UserProfileMetadata, WipeOutcome,
};

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountSummaryFfi {
    pub label: String,
    pub account_id_hex: String,
    pub local_signing: bool,
    pub signed_out: bool,
    pub running: bool,
}

/// Per-account unread aggregate for the account-switcher badge
/// (darkmatter#461). Computed from each account's materialized chat-list
/// projection without loading a full session/timeline, so accounts that are
/// not the active/running one are reported too.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountUnreadFfi {
    pub account_id_hex: String,
    /// Total unread messages across all unarchived conversations.
    pub unread_count: u64,
    /// Number of unarchived conversations with at least one unread message.
    pub unread_conversations: u64,
    /// Whether the account has any unread message at all.
    pub has_unread: bool,
}

impl From<AccountUnread> for AccountUnreadFfi {
    fn from(value: AccountUnread) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            unread_count: value.unread_count,
            unread_conversations: value.unread_conversations,
            has_unread: value.has_unread,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct SendSummaryFfi {
    pub published: u32,
    pub message_ids: Vec<String>,
}

impl From<SendSummary> for SendSummaryFfi {
    fn from(value: SendSummary) -> Self {
        Self {
            published: value.published as u32,
            message_ids: value.message_ids,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountKeyPackageFfi {
    pub account_ref: Option<String>,
    pub account_id_hex: String,
    pub key_package_id: String,
    pub key_package_ref_hex: String,
    pub event_id_hex: String,
    pub published_at: u64,
    pub key_package_bytes: u64,
    pub source_relays: Vec<String>,
    pub local: bool,
    pub relay: bool,
}

impl From<AccountKeyPackageRecord> for AccountKeyPackageFfi {
    fn from(value: AccountKeyPackageRecord) -> Self {
        Self {
            account_ref: value.account_label,
            account_id_hex: value.account_id_hex,
            key_package_id: value.key_package_id,
            key_package_ref_hex: value.key_package_ref_hex,
            event_id_hex: value.key_package_event_id,
            published_at: value.published_at,
            key_package_bytes: value.key_package_bytes as u64,
            source_relays: value.source_relays,
            local: value.local,
            relay: value.relay,
        }
    }
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct UserProfileMetadataFfi {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub nip05: Option<String>,
    pub lud16: Option<String>,
}

impl From<UserProfileMetadata> for UserProfileMetadataFfi {
    fn from(value: UserProfileMetadata) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            about: value.about,
            picture: value.picture,
            nip05: value.nip05,
            lud16: value.lud16,
        }
    }
}

impl From<UserProfileMetadataFfi> for UserProfileMetadata {
    fn from(value: UserProfileMetadataFfi) -> Self {
        Self {
            name: value.name,
            display_name: value.display_name,
            about: value.about,
            picture: value.picture,
            nip05: value.nip05,
            lud16: value.lud16,
            created_at: 0,
            source_relays: vec![],
        }
    }
}

/// Structured result of `signOutAndWipe`. Every stage of the destructive
/// sign-out is reported independently so the app can render progress and a
/// partial-failure sheet.
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct WipeOutcomeFfi {
    /// Active MLS groups this account successfully left.
    pub groups_left: u32,
    /// Per-group leave failures. Best-effort: the wipe does not abort on these.
    pub group_leave_failures: Vec<GroupLeaveFailureFfi>,
    /// Relay-published KeyPackage events successfully deleted.
    pub key_packages_deleted: u32,
    /// Per-relay KeyPackage deletion (or discovery) failures.
    pub key_package_failures: Vec<RelayFailureFfi>,
    /// Local cleanup (MLS DB, media cache, SQL row, secret-store nsec) result.
    pub local_cleanup: LocalCleanupReportFfi,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupLeaveFailureFfi {
    pub group_id_hex: String,
    pub reason: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayFailureFfi {
    pub event_id_hex: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct LocalCleanupReportFfi {
    pub completed: bool,
    pub reason: Option<String>,
}

/// Structured result of the non-destructive `signOut`. The account's local
/// state is kept on device; only the relay-published KeyPackages are cleaned
/// up (when requested), so the app can render the same per-relay
/// partial-failure sheet as a wipe and show a "will retry on next sign-in" hint.
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct SignOutOutcomeFfi {
    /// Relay-published KeyPackage events successfully deleted. `0` when
    /// `deleteKeyPackages` was `false`.
    pub key_packages_deleted: u32,
    /// Per-relay KeyPackage deletion (or discovery) failures. Best-effort.
    pub key_package_failures: Vec<RelayFailureFfi>,
    /// Local teardown (worker shutdown, subscription deactivation, in-memory
    /// cache eviction) result. Never removes on-disk state.
    pub local_cleanup: LocalCleanupReportFfi,
}

impl From<WipeOutcome> for WipeOutcomeFfi {
    fn from(value: WipeOutcome) -> Self {
        Self {
            groups_left: value.groups_left,
            group_leave_failures: value
                .group_leave_failures
                .into_iter()
                .map(Into::into)
                .collect(),
            key_packages_deleted: value.key_packages_deleted,
            key_package_failures: value
                .key_package_failures
                .into_iter()
                .map(Into::into)
                .collect(),
            local_cleanup: value.local_cleanup.into(),
        }
    }
}

impl From<GroupLeaveFailure> for GroupLeaveFailureFfi {
    fn from(value: GroupLeaveFailure) -> Self {
        Self {
            group_id_hex: value.group_id_hex,
            reason: value.reason,
        }
    }
}

impl From<RelayFailure> for RelayFailureFfi {
    fn from(value: RelayFailure) -> Self {
        Self {
            event_id_hex: value.event_id_hex,
            reason: value.reason,
        }
    }
}

impl From<LocalCleanupReport> for LocalCleanupReportFfi {
    fn from(value: LocalCleanupReport) -> Self {
        Self {
            completed: value.completed,
            reason: value.reason,
        }
    }
}

impl From<SignOutOutcome> for SignOutOutcomeFfi {
    fn from(value: SignOutOutcome) -> Self {
        Self {
            key_packages_deleted: value.key_packages_deleted,
            key_package_failures: value
                .key_package_failures
                .into_iter()
                .map(Into::into)
                .collect(),
            local_cleanup: value.local_cleanup.into(),
        }
    }
}
