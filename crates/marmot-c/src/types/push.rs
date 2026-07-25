//! C mirrors of the push conversions (`marmot-uniffi/src/conversions/push.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    GroupPushDebugInfoFfi, GroupPushTokenDebugEntryFfi, LocalPushRegistrationDebugFfi,
    PushPlatformFfi, PushRegistrationFfi,
};

use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, owned_c_string, owned_opt_c_string, owned_vec,
};

/// Native push platform a device token belongs to. Used both as a return
/// field and as a borrowed input to `marmot_upsert_push_registration`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotPushPlatform {
    /// Apple Push Notification service.
    Apns,
    /// Firebase Cloud Messaging.
    Fcm,
}

impl From<PushPlatformFfi> for MarmotPushPlatform {
    fn from(value: PushPlatformFfi) -> Self {
        match value {
            PushPlatformFfi::Apns => Self::Apns,
            PushPlatformFfi::Fcm => Self::Fcm,
        }
    }
}

impl MarmotPushPlatform {
    /// Read a caller-supplied platform value into the Ffi enum. Infallible;
    /// borrows nothing.
    pub(crate) fn to_ffi(self) -> PushPlatformFfi {
        match self {
            Self::Apns => PushPlatformFfi::Apns,
            Self::Fcm => PushPlatformFfi::Fcm,
        }
    }
}

impl CFree for MarmotPushPlatform {
    unsafe fn free_in_place(&mut self) {}
}

/// One account's local native-push registration
/// (`marmot_push_registration`, `marmot_upsert_push_registration`).
#[repr(C)]
pub struct MarmotPushRegistration {
    /// Account label the registration belongs to.
    pub account_ref: *mut c_char,
    pub account_id_hex: *mut c_char,
    pub platform: MarmotPushPlatform,
    /// Privacy-safe fingerprint of the raw device token; the raw token is
    /// never returned.
    pub token_fingerprint: *mut c_char,
    /// Push-server pubkey the token was encrypted to.
    pub server_pubkey_hex: *mut c_char,
    /// Optional preferred relay for push delivery. Nullable.
    pub relay_hint: *mut c_char,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    /// When the token was last shared into a group token list. `has_*`
    /// false means never shared.
    pub has_last_shared_at_ms: bool,
    pub last_shared_at_ms: i64,
}

impl From<PushRegistrationFfi> for MarmotPushRegistration {
    fn from(value: PushRegistrationFfi) -> Self {
        Self {
            account_ref: owned_c_string(value.account_ref),
            account_id_hex: owned_c_string(value.account_id_hex),
            platform: value.platform.into(),
            token_fingerprint: owned_c_string(value.token_fingerprint),
            server_pubkey_hex: owned_c_string(value.server_pubkey_hex),
            relay_hint: owned_opt_c_string(value.relay_hint),
            created_at_ms: value.created_at_ms,
            updated_at_ms: value.updated_at_ms,
            has_last_shared_at_ms: value.last_shared_at_ms.is_some(),
            last_shared_at_ms: value.last_shared_at_ms.unwrap_or_default(),
        }
    }
}

impl CFree for MarmotPushRegistration {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_ref);
            free_c_string(self.account_id_hex);
            free_c_string(self.token_fingerprint);
            free_c_string(self.server_pubkey_hex);
            free_c_string(self.relay_hint);
        }
    }
}

/// Free a push registration root. NULL is a no-op.
///
/// # Safety
/// `registration` must be NULL or an unfreed pointer returned by this
/// library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_push_registration_free(registration: *mut MarmotPushRegistration) {
    crate::memory::free_guard(|| unsafe { free_boxed(registration) });
}

/// Local-member registration state inside a group push-debug snapshot.
#[repr(C)]
pub struct MarmotLocalPushRegistrationDebug {
    /// Whether the account has a local push registration at all.
    pub registered: bool,
    /// Whether the registration is complete enough to share into groups.
    pub shareable: bool,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
    /// The local member's leaf index in the group, when known. `has_*`
    /// false means unknown.
    pub has_local_leaf_index: bool,
    pub local_leaf_index: u32,
    /// Whether a token for the local member is cached in the group's
    /// token list.
    pub local_token_cached: bool,
}

impl From<LocalPushRegistrationDebugFfi> for MarmotLocalPushRegistrationDebug {
    fn from(value: LocalPushRegistrationDebugFfi) -> Self {
        Self {
            registered: value.registered,
            shareable: value.shareable,
            local_notifications_enabled: value.local_notifications_enabled,
            native_push_enabled: value.native_push_enabled,
            has_local_leaf_index: value.local_leaf_index.is_some(),
            local_leaf_index: value.local_leaf_index.unwrap_or_default(),
            local_token_cached: value.local_token_cached,
        }
    }
}

impl CFree for MarmotLocalPushRegistrationDebug {
    unsafe fn free_in_place(&mut self) {}
}

/// One member's token entry inside a group push-debug snapshot.
#[repr(C)]
pub struct MarmotGroupPushTokenDebugEntry {
    pub member_id_hex: *mut c_char,
    pub leaf_index: u32,
    pub platform: MarmotPushPlatform,
    /// Privacy-safe fingerprint of the member's device token.
    pub token_fingerprint: *mut c_char,
    pub server_pubkey_hex: *mut c_char,
    pub has_relay_hint: bool,
    /// Whether the leaf index is an active leaf in the current group state.
    pub active_leaf: bool,
    /// Whether the token's member id matches the member at that leaf.
    pub member_matches_active_leaf: bool,
    pub is_local_member: bool,
    pub updated_at_ms: i64,
}

impl From<GroupPushTokenDebugEntryFfi> for MarmotGroupPushTokenDebugEntry {
    fn from(value: GroupPushTokenDebugEntryFfi) -> Self {
        Self {
            member_id_hex: owned_c_string(value.member_id_hex),
            leaf_index: value.leaf_index,
            platform: value.platform.into(),
            token_fingerprint: owned_c_string(value.token_fingerprint),
            server_pubkey_hex: owned_c_string(value.server_pubkey_hex),
            has_relay_hint: value.has_relay_hint,
            active_leaf: value.active_leaf,
            member_matches_active_leaf: value.member_matches_active_leaf,
            is_local_member: value.is_local_member,
            updated_at_ms: value.updated_at_ms,
        }
    }
}

impl CFree for MarmotGroupPushTokenDebugEntry {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.member_id_hex);
            free_c_string(self.token_fingerprint);
            free_c_string(self.server_pubkey_hex);
        }
    }
}

/// Aggregated push-token diagnostics for one group
/// (`marmot_group_push_debug_info`).
#[repr(C)]
pub struct MarmotGroupPushDebugInfo {
    pub total_token_count: u32,
    /// Tokens whose leaf is active and matches the member.
    pub active_token_count: u32,
    /// Tokens pointing at removed or mismatched leaves.
    pub stale_token_count: u32,
    pub missing_relay_hint_count: u32,
    /// When the group token list was last updated. `has_*` false means
    /// no token list has been seen.
    pub has_last_token_list_updated_at_ms: bool,
    pub last_token_list_updated_at_ms: i64,
    pub local_registration: MarmotLocalPushRegistrationDebug,
    pub tokens: *mut MarmotGroupPushTokenDebugEntry,
    pub tokens_len: usize,
}

impl From<GroupPushDebugInfoFfi> for MarmotGroupPushDebugInfo {
    fn from(value: GroupPushDebugInfoFfi) -> Self {
        let (tokens, tokens_len) = owned_vec(value.tokens.into_iter().map(Into::into).collect());
        Self {
            total_token_count: value.total_token_count,
            active_token_count: value.active_token_count,
            stale_token_count: value.stale_token_count,
            missing_relay_hint_count: value.missing_relay_hint_count,
            has_last_token_list_updated_at_ms: value.last_token_list_updated_at_ms.is_some(),
            last_token_list_updated_at_ms: value.last_token_list_updated_at_ms.unwrap_or_default(),
            local_registration: value.local_registration.into(),
            tokens,
            tokens_len,
        }
    }
}

impl CFree for MarmotGroupPushDebugInfo {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.tokens, self.tokens_len);
            self.local_registration.free_in_place();
        }
    }
}

/// Free a group push-debug info root. NULL is a no-op.
///
/// # Safety
/// `info` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_push_debug_info_free(info: *mut MarmotGroupPushDebugInfo) {
    crate::memory::free_guard(|| unsafe { free_boxed(info) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    fn sample_registration() -> PushRegistrationFfi {
        PushRegistrationFfi {
            account_ref: "primary".into(),
            account_id_hex: "aa11".into(),
            platform: PushPlatformFfi::Apns,
            token_fingerprint: "fp01".into(),
            server_pubkey_hex: "bb22".into(),
            relay_hint: Some("wss://relay.example".into()),
            created_at_ms: 1_000,
            updated_at_ms: 2_000,
            last_shared_at_ms: Some(3_000),
        }
    }

    fn sample_debug_info() -> GroupPushDebugInfoFfi {
        GroupPushDebugInfoFfi {
            total_token_count: 2,
            active_token_count: 1,
            stale_token_count: 1,
            missing_relay_hint_count: 1,
            last_token_list_updated_at_ms: Some(4_000),
            local_registration: LocalPushRegistrationDebugFfi {
                registered: true,
                shareable: true,
                local_notifications_enabled: false,
                native_push_enabled: true,
                local_leaf_index: Some(3),
                local_token_cached: true,
            },
            tokens: vec![
                GroupPushTokenDebugEntryFfi {
                    member_id_hex: "cc33".into(),
                    leaf_index: 3,
                    platform: PushPlatformFfi::Apns,
                    token_fingerprint: "fp02".into(),
                    server_pubkey_hex: "dd44".into(),
                    has_relay_hint: true,
                    active_leaf: true,
                    member_matches_active_leaf: true,
                    is_local_member: true,
                    updated_at_ms: 4_000,
                },
                GroupPushTokenDebugEntryFfi {
                    member_id_hex: "ee55".into(),
                    leaf_index: 7,
                    platform: PushPlatformFfi::Fcm,
                    token_fingerprint: "fp03".into(),
                    server_pubkey_hex: "ff66".into(),
                    has_relay_hint: false,
                    active_leaf: false,
                    member_matches_active_leaf: false,
                    is_local_member: false,
                    updated_at_ms: 3_500,
                },
            ],
        }
    }

    #[test]
    fn push_registration_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotPushRegistration = sample_registration().into();
        assert_eq!(mirror.platform, MarmotPushPlatform::Apns);
        assert!(!mirror.account_ref.is_null());
        assert!(!mirror.relay_hint.is_null());
        assert!(mirror.has_last_shared_at_ms);
        assert_eq!(mirror.last_shared_at_ms, 3_000);
        let root = boxed(mirror);
        unsafe { marmot_push_registration_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn group_push_debug_info_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotGroupPushDebugInfo = sample_debug_info().into();
        assert_eq!(mirror.total_token_count, 2);
        assert!(mirror.has_last_token_list_updated_at_ms);
        assert_eq!(mirror.last_token_list_updated_at_ms, 4_000);
        assert!(mirror.local_registration.has_local_leaf_index);
        assert_eq!(mirror.local_registration.local_leaf_index, 3);
        assert_eq!(mirror.tokens_len, 2);
        let tokens = unsafe { std::slice::from_raw_parts(mirror.tokens, mirror.tokens_len) };
        assert_eq!(tokens[0].platform, MarmotPushPlatform::Apns);
        assert_eq!(tokens[1].platform, MarmotPushPlatform::Fcm);
        assert!(!tokens[1].has_relay_hint);
        let root = boxed(mirror);
        unsafe { marmot_group_push_debug_info_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn none_and_empty_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let mirror: MarmotPushRegistration = PushRegistrationFfi {
            relay_hint: None,
            last_shared_at_ms: None,
            ..sample_registration()
        }
        .into();
        assert!(mirror.relay_hint.is_null());
        assert!(!mirror.has_last_shared_at_ms);
        assert_eq!(mirror.last_shared_at_ms, 0);
        let root = boxed(mirror);
        unsafe { marmot_push_registration_free(root) };

        let mirror: MarmotGroupPushDebugInfo = GroupPushDebugInfoFfi {
            last_token_list_updated_at_ms: None,
            local_registration: LocalPushRegistrationDebugFfi {
                registered: false,
                shareable: false,
                local_notifications_enabled: false,
                native_push_enabled: false,
                local_leaf_index: None,
                local_token_cached: false,
            },
            tokens: Vec::new(),
            ..sample_debug_info()
        }
        .into();
        assert!(!mirror.has_last_token_list_updated_at_ms);
        assert!(!mirror.local_registration.has_local_leaf_index);
        assert_eq!(mirror.local_registration.local_leaf_index, 0);
        assert!(mirror.tokens.is_null());
        assert_eq!(mirror.tokens_len, 0);
        let root = boxed(mirror);
        unsafe { marmot_group_push_debug_info_free(root) };
    }

    #[test]
    fn platform_input_roundtrips() {
        let _guard = crate::memory::audit::test_lock();
        assert!(matches!(
            MarmotPushPlatform::Apns.to_ffi(),
            PushPlatformFfi::Apns
        ));
        assert!(matches!(
            MarmotPushPlatform::Fcm.to_ffi(),
            PushPlatformFfi::Fcm
        ));
    }
}
