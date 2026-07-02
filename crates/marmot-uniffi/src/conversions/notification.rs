//! Notification settings, triggers, users, and update FFI conversions.

use marmot_app::{
    NotificationCollectionStatus, NotificationSettings, NotificationTrigger, NotificationUpdate,
    NotificationUser, NotificationWakeSource,
};

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NotificationWakeSourceFfi {
    ApnsNse,
    FcmDataMessage,
    AndroidForegroundService,
    ManualCatchUp,
}

impl From<NotificationWakeSourceFfi> for NotificationWakeSource {
    fn from(value: NotificationWakeSourceFfi) -> Self {
        match value {
            NotificationWakeSourceFfi::ApnsNse => Self::ApnsNse,
            NotificationWakeSourceFfi::FcmDataMessage => Self::FcmDataMessage,
            NotificationWakeSourceFfi::AndroidForegroundService => Self::AndroidForegroundService,
            NotificationWakeSourceFfi::ManualCatchUp => Self::ManualCatchUp,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NotificationCollectionStatusFfi {
    NewData,
    NoData,
    Failed,
}

impl From<NotificationCollectionStatus> for NotificationCollectionStatusFfi {
    fn from(value: NotificationCollectionStatus) -> Self {
        match value {
            NotificationCollectionStatus::NewData => Self::NewData,
            NotificationCollectionStatus::NoData => Self::NoData,
            NotificationCollectionStatus::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum NotificationTriggerFfi {
    NewMessage,
    GroupInvite,
}

impl From<NotificationTrigger> for NotificationTriggerFfi {
    fn from(value: NotificationTrigger) -> Self {
        match value {
            NotificationTrigger::NewMessage => Self::NewMessage,
            NotificationTrigger::GroupInvite => Self::GroupInvite,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NotificationSettingsFfi {
    pub account_ref: String,
    pub account_id_hex: String,
    pub local_notifications_enabled: bool,
    pub native_push_enabled: bool,
}

impl From<NotificationSettings> for NotificationSettingsFfi {
    fn from(value: NotificationSettings) -> Self {
        Self {
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            local_notifications_enabled: value.local_notifications_enabled,
            native_push_enabled: value.native_push_enabled,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NotificationUserFfi {
    pub account_id_hex: String,
    pub display_name: Option<String>,
    pub picture_url: Option<String>,
}

impl From<NotificationUser> for NotificationUserFfi {
    fn from(value: NotificationUser) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            display_name: value.display_name,
            picture_url: value.picture_url,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct NotificationUpdateFfi {
    pub notification_key: String,
    pub conversation_key: String,
    pub trigger: NotificationTriggerFfi,
    pub account_ref: String,
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub group_name: Option<String>,
    pub is_dm: bool,
    pub is_mention: bool,
    pub message_id_hex: Option<String>,
    pub sender: NotificationUserFfi,
    pub receiver: NotificationUserFfi,
    pub preview_text: Option<String>,
    pub reaction_emoji: Option<String>,
    pub reacted_to_preview: Option<String>,
    pub timestamp_ms: i64,
    pub is_from_self: bool,
}

impl From<NotificationUpdate> for NotificationUpdateFfi {
    fn from(value: NotificationUpdate) -> Self {
        Self {
            notification_key: value.notification_key,
            conversation_key: value.conversation_key,
            trigger: value.trigger.into(),
            account_ref: value.account_ref,
            account_id_hex: value.account_id_hex,
            group_id_hex: value.group_id_hex,
            group_name: value.group_name,
            is_dm: value.is_dm,
            is_mention: value.is_mention,
            message_id_hex: value.message_id_hex,
            sender: value.sender.into(),
            receiver: value.receiver.into(),
            preview_text: value.preview_text,
            reaction_emoji: value.reaction_emoji,
            reacted_to_preview: value.reacted_to_preview,
            timestamp_ms: value.timestamp_ms,
            is_from_self: value.is_from_self,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct BackgroundNotificationCollectionFfi {
    pub status: NotificationCollectionStatusFfi,
    pub notifications: Vec<NotificationUpdateFfi>,
    pub error: Option<String>,
}

impl From<marmot_app::BackgroundNotificationCollection> for BackgroundNotificationCollectionFfi {
    fn from(value: marmot_app::BackgroundNotificationCollection) -> Self {
        Self {
            status: value.status.into(),
            notifications: value.notifications.into_iter().map(Into::into).collect(),
            error: value.error,
        }
    }
}
