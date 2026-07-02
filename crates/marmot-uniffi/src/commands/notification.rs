//! Notification settings, catch-up, and background-collection commands.

use crate::Marmot;
use crate::conversions::{
    BackgroundNotificationCollectionFfi, NotificationSettingsFfi, NotificationWakeSourceFfi,
};
use crate::errors::MarmotKitError;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    // -----------------------------------------------------------------------
    // Notifications
    // -----------------------------------------------------------------------

    pub fn notification_settings(
        &self,
        account_ref: String,
    ) -> Result<NotificationSettingsFfi, MarmotKitError> {
        Ok(self.runtime.notification_settings(&account_ref)?.into())
    }

    pub fn set_local_notifications_enabled(
        &self,
        account_ref: String,
        enabled: bool,
    ) -> Result<NotificationSettingsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .set_local_notifications_enabled(&account_ref, enabled)?
            .into())
    }

    pub async fn set_native_push_enabled(
        &self,
        account_ref: String,
        enabled: bool,
    ) -> Result<NotificationSettingsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .set_native_push_enabled(&account_ref, enabled)
            .await?
            .into())
    }

    pub async fn catch_up_accounts(&self) -> Result<(), MarmotKitError> {
        self.runtime.catch_up_accounts().await?;
        Ok(())
    }

    pub async fn collect_notifications_after_wake(
        &self,
        max_wait_ms: u32,
        source: NotificationWakeSourceFfi,
    ) -> Result<BackgroundNotificationCollectionFfi, MarmotKitError> {
        Ok(self
            .runtime
            .collect_notifications_after_wake(max_wait_ms, source.into())
            .await
            .into())
    }
}
