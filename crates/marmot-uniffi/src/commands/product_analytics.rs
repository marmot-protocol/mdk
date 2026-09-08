//! One consent control for both independent exporters.
use crate::{Marmot, MarmotKitError, conversions::*};
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    pub fn usage_diagnostics_settings(
        &self,
    ) -> Result<UsageDiagnosticsSettingsFfi, MarmotKitError> {
        Ok(self.runtime.usage_diagnostics_settings()?.into())
    }
    pub fn set_usage_diagnostics_consent(
        &self,
        enabled: bool,
    ) -> Result<UsageDiagnosticsSettingsFfi, MarmotKitError> {
        Ok(self.runtime.set_usage_diagnostics_consent(enabled)?.into())
    }
    pub fn usage_diagnostics_status(&self) -> Result<UsageDiagnosticsStatusFfi, MarmotKitError> {
        Ok(self.runtime.usage_diagnostics_status().into())
    }
    pub fn set_product_analytics_runtime_config(
        &self,
        config: ProductAnalyticsRuntimeConfigFfi,
    ) -> Result<(), MarmotKitError> {
        if config
            .registry
            .iter()
            .flat_map(|event| &event.properties)
            .any(|property| {
                property.kind != ProductPropertyKindFfi::Enum && !property.choices.is_empty()
            })
        {
            return Err(MarmotKitError::InvalidProductAnalyticsConfiguration);
        }
        Ok(self
            .runtime
            .set_product_analytics_runtime_config(config.into())?)
    }
    pub fn record_product_event(
        &self,
        event: ProductEventFfi,
    ) -> Result<ProductRecordResultFfi, MarmotKitError> {
        Ok(self.runtime.record_product_event(event.try_into()?)?.into())
    }
    pub async fn set_product_analytics_activity(
        &self,
        activity: ProductAnalyticsActivityFfi,
    ) -> Result<(), MarmotKitError> {
        self.runtime
            .set_product_analytics_activity(activity.into())
            .await;
        Ok(())
    }
    pub async fn flush_product_analytics(&self) -> Result<(), MarmotKitError> {
        self.runtime.flush_product_analytics().await;
        Ok(())
    }
}
