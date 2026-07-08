//! C mirrors of the notification conversions
//! (`marmot-uniffi/src/conversions/notification.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    BackgroundNotificationCollectionFfi, NotificationCollectionStatusFfi, NotificationSettingsFfi,
    NotificationTriggerFfi, NotificationUpdateFfi, NotificationUserFfi, NotificationWakeSourceFfi,
};

use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, owned_c_string, owned_opt_c_string, owned_vec,
};

/// Platform mechanism that woke the process for background notification
/// collection. Borrowed input to `marmot_collect_notifications_after_wake`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotNotificationWakeSource {
    /// iOS APNs Notification Service Extension wake.
    ApnsNse,
    /// Android FCM data-message wake.
    FcmDataMessage,
    /// Android foreground-service driven collection.
    AndroidForegroundService,
    /// Explicit user- or app-initiated catch-up.
    ManualCatchUp,
}

impl From<NotificationWakeSourceFfi> for MarmotNotificationWakeSource {
    fn from(value: NotificationWakeSourceFfi) -> Self {
        match value {
            NotificationWakeSourceFfi::ApnsNse => Self::ApnsNse,
            NotificationWakeSourceFfi::FcmDataMessage => Self::FcmDataMessage,
            NotificationWakeSourceFfi::AndroidForegroundService => Self::AndroidForegroundService,
            NotificationWakeSourceFfi::ManualCatchUp => Self::ManualCatchUp,
        }
    }
}

impl MarmotNotificationWakeSource {
    /// Read a caller-provided wake source into the Ffi enum. Infallible.
    pub(crate) fn to_ffi(self) -> NotificationWakeSourceFfi {
        match self {
            Self::ApnsNse => NotificationWakeSourceFfi::ApnsNse,
            Self::FcmDataMessage => NotificationWakeSourceFfi::FcmDataMessage,
            Self::AndroidForegroundService => NotificationWakeSourceFfi::AndroidForegroundService,
            Self::ManualCatchUp => NotificationWakeSourceFfi::ManualCatchUp,
        }
    }
}

impl CFree for MarmotNotificationWakeSource {
    unsafe fn free_in_place(&mut self) {}
}

/// Overall outcome of a background notification collection pass.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotNotificationCollectionStatus {
    /// New notifications were collected.
    NewData,
    /// The pass completed but nothing new arrived.
    NoData,
    /// The pass failed; see the collection's `error` field.
    Failed,
}

impl From<NotificationCollectionStatusFfi> for MarmotNotificationCollectionStatus {
    fn from(value: NotificationCollectionStatusFfi) -> Self {
        match value {
            NotificationCollectionStatusFfi::NewData => Self::NewData,
            NotificationCollectionStatusFfi::NoData => Self::NoData,
            NotificationCollectionStatusFfi::Failed => Self::Failed,
        }
    }
}

impl CFree for MarmotNotificationCollectionStatus {
    unsafe fn free_in_place(&mut self) {}
}

/// What kind of event a notification update describes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotNotificationTrigger {
    /// A new message arrived in a group or DM.
    NewMessage,
    /// The account was invited to a group.
    GroupInvite,
}

impl From<NotificationTriggerFfi> for MarmotNotificationTrigger {
    fn from(value: NotificationTriggerFfi) -> Self {
        match value {
            NotificationTriggerFfi::NewMessage => Self::NewMessage,
            NotificationTriggerFfi::GroupInvite => Self::GroupInvite,
        }
    }
}

impl CFree for MarmotNotificationTrigger {
    unsafe fn free_in_place(&mut self) {}
}

/// Per-account notification preferences.
#[repr(C)]
pub struct MarmotNotificationSettings {
    pub account_ref: *mut c_char,
    pub account_id_hex: *mut c_char,
    /// Whether locally rendered notifications are enabled.
    pub local_notifications_enabled: bool,
    /// Whether native push (APNs/FCM) delivery is enabled.
    pub native_push_enabled: bool,
}

impl From<NotificationSettingsFfi> for MarmotNotificationSettings {
    fn from(value: NotificationSettingsFfi) -> Self {
        Self {
            account_ref: owned_c_string(value.account_ref),
            account_id_hex: owned_c_string(value.account_id_hex),
            local_notifications_enabled: value.local_notifications_enabled,
            native_push_enabled: value.native_push_enabled,
        }
    }
}

impl CFree for MarmotNotificationSettings {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_ref);
            free_c_string(self.account_id_hex);
        }
    }
}

/// Free a notification settings root. NULL is a no-op.
///
/// # Safety
/// `settings` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notification_settings_free(
    settings: *mut MarmotNotificationSettings,
) {
    unsafe { free_boxed(settings) };
}

/// A user referenced by a notification (sender or receiver).
#[repr(C)]
pub struct MarmotNotificationUser {
    pub account_id_hex: *mut c_char,
    /// Display name, when known. Nullable.
    pub display_name: *mut c_char,
    /// Profile picture URL, when known. Nullable.
    pub picture_url: *mut c_char,
}

impl From<NotificationUserFfi> for MarmotNotificationUser {
    fn from(value: NotificationUserFfi) -> Self {
        Self {
            account_id_hex: owned_c_string(value.account_id_hex),
            display_name: owned_opt_c_string(value.display_name),
            picture_url: owned_opt_c_string(value.picture_url),
        }
    }
}

impl CFree for MarmotNotificationUser {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_id_hex);
            free_c_string(self.display_name);
            free_c_string(self.picture_url);
        }
    }
}

/// One notification-worthy event, delivered via the notification
/// subscription stream and inside background collections.
#[repr(C)]
pub struct MarmotNotificationUpdate {
    /// Stable dedup key for this notification.
    pub notification_key: *mut c_char,
    /// Stable key identifying the conversation for grouping/threading.
    pub conversation_key: *mut c_char,
    pub trigger: MarmotNotificationTrigger,
    pub account_ref: *mut c_char,
    pub account_id_hex: *mut c_char,
    /// Opaque MLS group id, hex-encoded (variable length; not a 32-byte
    /// Nostr route id).
    pub group_id_hex: *mut c_char,
    /// Group display name, when known. Nullable.
    pub group_name: *mut c_char,
    pub is_dm: bool,
    /// Whether the receiving account was mentioned.
    pub is_mention: bool,
    /// Message id, hex-encoded, when known. Nullable.
    pub message_id_hex: *mut c_char,
    pub sender: MarmotNotificationUser,
    pub receiver: MarmotNotificationUser,
    /// Short displayable preview of the message text. Nullable.
    pub preview_text: *mut c_char,
    /// Reaction emoji when this update is a reaction. Nullable.
    pub reaction_emoji: *mut c_char,
    /// Preview of the message that was reacted to. Nullable.
    pub reacted_to_preview: *mut c_char,
    /// Event timestamp in milliseconds since the Unix epoch.
    pub timestamp_ms: i64,
    /// Whether the event originated from the receiving account itself.
    pub is_from_self: bool,
}

impl From<NotificationUpdateFfi> for MarmotNotificationUpdate {
    fn from(value: NotificationUpdateFfi) -> Self {
        Self {
            notification_key: owned_c_string(value.notification_key),
            conversation_key: owned_c_string(value.conversation_key),
            trigger: value.trigger.into(),
            account_ref: owned_c_string(value.account_ref),
            account_id_hex: owned_c_string(value.account_id_hex),
            group_id_hex: owned_c_string(value.group_id_hex),
            group_name: owned_opt_c_string(value.group_name),
            is_dm: value.is_dm,
            is_mention: value.is_mention,
            message_id_hex: owned_opt_c_string(value.message_id_hex),
            sender: value.sender.into(),
            receiver: value.receiver.into(),
            preview_text: owned_opt_c_string(value.preview_text),
            reaction_emoji: owned_opt_c_string(value.reaction_emoji),
            reacted_to_preview: owned_opt_c_string(value.reacted_to_preview),
            timestamp_ms: value.timestamp_ms,
            is_from_self: value.is_from_self,
        }
    }
}

impl CFree for MarmotNotificationUpdate {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.notification_key);
            free_c_string(self.conversation_key);
            free_c_string(self.account_ref);
            free_c_string(self.account_id_hex);
            free_c_string(self.group_id_hex);
            free_c_string(self.group_name);
            free_c_string(self.message_id_hex);
            self.sender.free_in_place();
            self.receiver.free_in_place();
            free_c_string(self.preview_text);
            free_c_string(self.reaction_emoji);
            free_c_string(self.reacted_to_preview);
        }
    }
}

/// Free a notification update root (delivered by the notification
/// subscription). NULL is a no-op.
///
/// # Safety
/// `update` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notification_update_free(update: *mut MarmotNotificationUpdate) {
    unsafe { free_boxed(update) };
}

/// Result of a background collection pass
/// (`marmot_collect_notifications_after_wake`).
#[repr(C)]
pub struct MarmotBackgroundNotificationCollection {
    pub status: MarmotNotificationCollectionStatus,
    pub notifications: *mut MarmotNotificationUpdate,
    pub notifications_len: usize,
    /// Failure detail when `status` is `Failed`. Nullable.
    pub error: *mut c_char,
}

impl From<BackgroundNotificationCollectionFfi> for MarmotBackgroundNotificationCollection {
    fn from(value: BackgroundNotificationCollectionFfi) -> Self {
        let (notifications, notifications_len) =
            owned_vec(value.notifications.into_iter().map(Into::into).collect());
        Self {
            status: value.status.into(),
            notifications,
            notifications_len,
            error: owned_opt_c_string(value.error),
        }
    }
}

impl CFree for MarmotBackgroundNotificationCollection {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.notifications, self.notifications_len);
            free_c_string(self.error);
        }
    }
}

/// Free a background collection root. NULL is a no-op.
///
/// # Safety
/// `collection` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_background_notification_collection_free(
    collection: *mut MarmotBackgroundNotificationCollection,
) {
    unsafe { free_boxed(collection) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    fn sample_update() -> NotificationUpdateFfi {
        NotificationUpdateFfi {
            notification_key: "notif-1".into(),
            conversation_key: "conv-1".into(),
            trigger: NotificationTriggerFfi::NewMessage,
            account_ref: "primary".into(),
            account_id_hex: "aa11".into(),
            group_id_hex: "bb22".into(),
            group_name: Some("Burrow".into()),
            is_dm: false,
            is_mention: true,
            message_id_hex: Some("cc33".into()),
            sender: NotificationUserFfi {
                account_id_hex: "dd44".into(),
                display_name: Some("Marmy".into()),
                picture_url: Some("https://example.invalid/m.png".into()),
            },
            receiver: NotificationUserFfi {
                account_id_hex: "ee55".into(),
                display_name: Some("Whistler".into()),
                picture_url: Some("https://example.invalid/w.png".into()),
            },
            preview_text: Some("hello burrow".into()),
            reaction_emoji: Some("🎉".into()),
            reacted_to_preview: Some("earlier message".into()),
            timestamp_ms: 1_700_000_000_123,
            is_from_self: false,
        }
    }

    #[test]
    fn notification_settings_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotNotificationSettings = NotificationSettingsFfi {
            account_ref: "primary".into(),
            account_id_hex: "aa11".into(),
            local_notifications_enabled: true,
            native_push_enabled: false,
        }
        .into();
        assert!(!mirror.account_ref.is_null());
        assert!(!mirror.account_id_hex.is_null());
        assert!(mirror.local_notifications_enabled);
        assert!(!mirror.native_push_enabled);
        let root = boxed(mirror);
        unsafe { marmot_notification_settings_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn notification_update_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotNotificationUpdate = sample_update().into();
        assert_eq!(mirror.trigger, MarmotNotificationTrigger::NewMessage);
        assert!(!mirror.notification_key.is_null());
        assert!(!mirror.group_name.is_null());
        assert!(!mirror.message_id_hex.is_null());
        assert!(!mirror.sender.display_name.is_null());
        assert!(!mirror.receiver.picture_url.is_null());
        assert!(!mirror.reaction_emoji.is_null());
        assert_eq!(mirror.timestamp_ms, 1_700_000_000_123);
        assert!(mirror.is_mention);
        let root = boxed(mirror);
        unsafe { marmot_notification_update_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn background_collection_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotBackgroundNotificationCollection = BackgroundNotificationCollectionFfi {
            status: NotificationCollectionStatusFfi::NewData,
            notifications: vec![sample_update(), sample_update()],
            error: Some("partial relay timeout".into()),
        }
        .into();
        assert_eq!(mirror.status, MarmotNotificationCollectionStatus::NewData);
        assert_eq!(mirror.notifications_len, 2);
        assert!(!mirror.notifications.is_null());
        assert!(!mirror.error.is_null());
        let root = boxed(mirror);
        unsafe { marmot_background_notification_collection_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_vec_and_none_convert_to_null() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        let mirror: MarmotBackgroundNotificationCollection = BackgroundNotificationCollectionFfi {
            status: NotificationCollectionStatusFfi::NoData,
            notifications: Vec::new(),
            error: None,
        }
        .into();
        assert_eq!(mirror.status, MarmotNotificationCollectionStatus::NoData);
        assert!(mirror.notifications.is_null());
        assert_eq!(mirror.notifications_len, 0);
        assert!(mirror.error.is_null());
        let root = boxed(mirror);
        unsafe { marmot_background_notification_collection_free(root) };
    }

    #[test]
    fn wake_source_to_ffi_covers_all_variants() {
        let _guard = crate::memory::audit::test_lock();
        let sources = [
            MarmotNotificationWakeSource::ApnsNse,
            MarmotNotificationWakeSource::FcmDataMessage,
            MarmotNotificationWakeSource::AndroidForegroundService,
            MarmotNotificationWakeSource::ManualCatchUp,
        ];
        for source in sources {
            let back: MarmotNotificationWakeSource = source.to_ffi().into();
            assert_eq!(back, source);
        }
    }
}
