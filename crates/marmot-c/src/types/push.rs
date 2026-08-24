//! C mirrors of the native-push registration conversions.

use marmot_uniffi::conversions::{
    GroupPushDebugInfoFfi, GroupPushTokenDebugEntryFfi, LocalPushRegistrationDebugFfi,
    PushPlatformFfi, PushRegistrationFfi, PushRegistrationShareOutcomeFfi,
    PushRegistrationShareStatusFfi, PushRegistrationSyncResultFfi,
};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Native push platform.
    MarmotPushPlatform from PushPlatformFfi {
        Apns,
        Fcm,
    }
}

impl From<MarmotPushPlatform> for PushPlatformFfi {
    fn from(value: MarmotPushPlatform) -> Self {
        match value {
            MarmotPushPlatform::Apns => Self::Apns,
            MarmotPushPlatform::Fcm => Self::Fcm,
        }
    }
}

c_mirror! {
    /// The account's current push registration.
    MarmotPushRegistration from PushRegistrationFfi,
    free marmot_push_registration_free {
        str account_ref,
        str account_id_hex,
        copy platform: MarmotPushPlatform,
        str token_fingerprint,
        str server_pubkey_hex,
        opt_str relay_hint,
        copy created_at_ms: i64,
        copy updated_at_ms: i64,
        opt_copy has_last_shared_at_ms/last_shared_at_ms: i64,
    }
}

c_enum! {
    /// Whether the registration reached every group.
    MarmotPushRegistrationShareStatus from PushRegistrationShareStatusFfi {
        Complete,
        Pending,
    }
}

c_mirror! {
    /// Per-group share fan-out counters.
    MarmotPushRegistrationShareOutcome from PushRegistrationShareOutcomeFfi,
    free marmot_push_registration_share_outcome_free {
        copy status: MarmotPushRegistrationShareStatus,
        copy attempted_groups: u32,
        copy succeeded_groups: u32,
        copy failed_groups: u32,
        copy pending_groups: u32,
    }
}

c_mirror! {
    /// Result of upserting a push registration.
    MarmotPushRegistrationSyncResult from PushRegistrationSyncResultFfi,
    free marmot_push_registration_sync_result_free {
        rec registration: MarmotPushRegistration,
        rec share: MarmotPushRegistrationShareOutcome,
    }
}

c_mirror! {
    /// Local registration state for the push debug view.
    MarmotLocalPushRegistrationDebug from LocalPushRegistrationDebugFfi {
        copy registered: bool,
        copy shareable: bool,
        copy local_notifications_enabled: bool,
        copy native_push_enabled: bool,
        opt_copy has_local_leaf_index/local_leaf_index: u32,
        copy local_token_cached: bool,
    }
}

c_mirror! {
    /// One member's shared push token in the debug view.
    MarmotGroupPushTokenDebugEntry from GroupPushTokenDebugEntryFfi {
        str member_id_hex,
        copy leaf_index: u32,
        copy platform: MarmotPushPlatform,
        str token_fingerprint,
        str server_pubkey_hex,
        copy has_relay_hint: bool,
        copy active_leaf: bool,
        copy member_matches_active_leaf: bool,
        copy is_local_member: bool,
        copy updated_at_ms: i64,
    }
}

c_mirror! {
    /// Per-group push token debug info.
    MarmotGroupPushDebugInfo from GroupPushDebugInfoFfi,
    free marmot_group_push_debug_info_free {
        copy total_token_count: u32,
        copy active_token_count: u32,
        copy stale_token_count: u32,
        copy missing_relay_hint_count: u32,
        opt_copy has_last_token_list_updated_at_ms/last_token_list_updated_at_ms: i64,
        rec local_registration: MarmotLocalPushRegistrationDebug,
        vec tokens/tokens_len: MarmotGroupPushTokenDebugEntry,
    }
}
