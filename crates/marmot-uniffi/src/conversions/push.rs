//! Push-platform, push-registration, and group-push debug FFI conversions.

use marmot_app::{
    GroupPushDebugInfo, GroupPushTokenDebugEntry, LocalPushRegistrationDebug, PushPlatform,
    PushRegistration,
};

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PushPlatformFfi {
    Apns,
    Fcm,
}

impl From<PushPlatform> for PushPlatformFfi {
    fn from(value: PushPlatform) -> Self {
        match value {
            PushPlatform::Apns => Self::Apns,
            PushPlatform::Fcm => Self::Fcm,
        }
    }
}

impl From<PushPlatformFfi> for PushPlatform {
    fn from(value: PushPlatformFfi) -> Self {
        match value {
            PushPlatformFfi::Apns => Self::Apns,
            PushPlatformFfi::Fcm => Self::Fcm,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PushRegistrationFfi {
    pub account_ref: String,
    pub account_id_hex: String,
    pub platform: PushPlatformFfi,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub relay_hint: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_shared_at_ms: Option<i64>,
}

impl From<PushRegistration> for PushRegistrationFfi {
    fn from(value: PushRegistration) -> Self {
        Self {
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            platform: value.platform.into(),
            token_fingerprint: value.token_fingerprint,
            server_pubkey_hex: value.server_pubkey_hex,
            relay_hint: value.relay_hint,
            created_at_ms: value.created_at_ms,
            updated_at_ms: value.updated_at_ms,
            last_shared_at_ms: value.last_shared_at_ms,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct LocalPushRegistrationDebugFfi {
    pub registered: bool,
    pub shareable: bool,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
    pub local_leaf_index: Option<u32>,
    pub local_token_cached: bool,
}

impl From<LocalPushRegistrationDebug> for LocalPushRegistrationDebugFfi {
    fn from(value: LocalPushRegistrationDebug) -> Self {
        Self {
            registered: value.registered,
            shareable: value.shareable,
            local_notifications_enabled: value.local_notifications_enabled,
            native_push_enabled: value.native_push_enabled,
            local_leaf_index: value.local_leaf_index,
            local_token_cached: value.local_token_cached,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupPushTokenDebugEntryFfi {
    pub member_id_hex: String,
    pub leaf_index: u32,
    pub platform: PushPlatformFfi,
    pub token_fingerprint: String,
    pub server_pubkey_hex: String,
    pub has_relay_hint: bool,
    pub active_leaf: bool,
    pub member_matches_active_leaf: bool,
    pub is_local_member: bool,
    pub updated_at_ms: i64,
}

impl From<GroupPushTokenDebugEntry> for GroupPushTokenDebugEntryFfi {
    fn from(value: GroupPushTokenDebugEntry) -> Self {
        Self {
            member_id_hex: value.member_id_hex,
            leaf_index: value.leaf_index,
            platform: value.platform.into(),
            token_fingerprint: value.token_fingerprint,
            server_pubkey_hex: value.server_pubkey_hex,
            has_relay_hint: value.has_relay_hint,
            active_leaf: value.active_leaf,
            member_matches_active_leaf: value.member_matches_active_leaf,
            is_local_member: value.is_local_member,
            updated_at_ms: value.updated_at_ms,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct GroupPushDebugInfoFfi {
    pub total_token_count: u32,
    pub active_token_count: u32,
    pub stale_token_count: u32,
    pub missing_relay_hint_count: u32,
    pub last_token_list_updated_at_ms: Option<i64>,
    pub local_registration: LocalPushRegistrationDebugFfi,
    pub tokens: Vec<GroupPushTokenDebugEntryFfi>,
}

impl From<GroupPushDebugInfo> for GroupPushDebugInfoFfi {
    fn from(value: GroupPushDebugInfo) -> Self {
        Self {
            total_token_count: value.total_token_count,
            active_token_count: value.active_token_count,
            stale_token_count: value.stale_token_count,
            missing_relay_hint_count: value.missing_relay_hint_count,
            last_token_list_updated_at_ms: value.last_token_list_updated_at_ms,
            local_registration: value.local_registration.into(),
            tokens: value.tokens.into_iter().map(Into::into).collect(),
        }
    }
}
