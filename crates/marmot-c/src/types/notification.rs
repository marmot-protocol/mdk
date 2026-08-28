//! C mirrors of the notification pipeline conversions.

use marmot_uniffi::conversions::{
    BackgroundNotificationCollectionFfi, CursorPersistenceFfi, NotificationCollectionStatusFfi,
    NotificationSettingsFfi, NotificationTrafficClassFfi, NotificationTriggerFfi,
    NotificationUpdateFfi, NotificationUserFfi, NotificationWakeSourceFfi,
};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Whether a pass may ratchet the durable transport `since` floor.
    /// Caller-supplied to `marmot_client_new_with_cursor_persistence`.
    MarmotCursorPersistence from CursorPersistenceFfi {
        /// Advance the durable floor as events arrive (foreground apps).
        Advance,
        /// Ingest without moving the floor: a sub-second drain on cold
        /// sockets must not skip events it never received.
        Frozen,
    }
}

impl From<MarmotCursorPersistence> for CursorPersistenceFfi {
    fn from(value: MarmotCursorPersistence) -> Self {
        match value {
            MarmotCursorPersistence::Advance => Self::Advance,
            MarmotCursorPersistence::Frozen => Self::Frozen,
        }
    }
}

c_enum! {
    /// What woke the background collection.
    MarmotNotificationWakeSource from NotificationWakeSourceFfi {
        ApnsNse,
        FcmDataMessage,
        AndroidForegroundService,
        ManualCatchUp,
    }
}

impl From<MarmotNotificationWakeSource> for NotificationWakeSourceFfi {
    fn from(value: MarmotNotificationWakeSource) -> Self {
        match value {
            MarmotNotificationWakeSource::ApnsNse => Self::ApnsNse,
            MarmotNotificationWakeSource::FcmDataMessage => Self::FcmDataMessage,
            MarmotNotificationWakeSource::AndroidForegroundService => {
                Self::AndroidForegroundService
            }
            MarmotNotificationWakeSource::ManualCatchUp => Self::ManualCatchUp,
        }
    }
}

c_enum! {
    /// Outcome class of a background collection.
    MarmotNotificationCollectionStatus from NotificationCollectionStatusFfi {
        NewData,
        NoData,
        Failed,
    }
}

c_enum! {
    /// What kind of activity produced the notification.
    MarmotNotificationTrigger from NotificationTriggerFfi {
        NewMessage,
        GroupInvite,
        RemovedFromGroup,
        MadeAdmin,
        RemovedAsAdmin,
    }
}

c_enum! {
    /// Traffic class for host-side filtering.
    MarmotNotificationTrafficClass from NotificationTrafficClassFfi {
        Standard,
        AgentActivity,
    }
}

c_mirror! {
    /// Per-account notification switches.
    MarmotNotificationSettings from NotificationSettingsFfi,
    free marmot_notification_settings_free {
        str account_ref,
        str account_id_hex,
        copy local_notifications_enabled: bool,
        copy native_push_enabled: bool,
    }
}

c_mirror! {
    /// Sender/receiver identity attached to a notification.
    MarmotNotificationUser from NotificationUserFfi {
        str account_id_hex,
        opt_str display_name,
        opt_str picture_url,
    }
}

c_mirror! {
    /// One local-notification update.
    MarmotNotificationUpdate from NotificationUpdateFfi,
    free marmot_notification_update_free {
        str notification_key,
        str conversation_key,
        copy trigger: MarmotNotificationTrigger,
        copy traffic_class: MarmotNotificationTrafficClass,
        str account_ref,
        str account_id_hex,
        str group_id_hex,
        opt_str group_name,
        copy is_dm: bool,
        copy is_mention: bool,
        opt_str message_id_hex,
        rec sender: MarmotNotificationUser,
        rec receiver: MarmotNotificationUser,
        opt_str preview_text,
        opt_str reaction_emoji,
        opt_str reacted_to_preview,
        copy timestamp_ms: i64,
        copy is_from_self: bool,
    }
}

c_mirror! {
    /// Result of a wake-driven background collection pass.
    MarmotBackgroundNotificationCollection from BackgroundNotificationCollectionFfi,
    free marmot_background_notification_collection_free {
        copy status: MarmotNotificationCollectionStatus,
        vec notifications/notifications_len: MarmotNotificationUpdate,
        opt_str error,
    }
}
