//! One consent control for both independent exporters.
use crate::{Marmot, MarmotKitError, conversions::*};
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_rejects_choices_for_non_enum_properties() {
        let root = tempfile::tempdir().unwrap();
        let kit = Marmot::open(
            root.path().to_string_lossy().into_owned(),
            vec![],
            marmot_app::MarmotAppConfig::default(),
            Some(std::sync::Arc::new(
                marmot_account::LocalFileSecretStore::new(root.path()),
            )),
        )
        .unwrap();
        let config = |kind, choices| ProductAnalyticsRuntimeConfigFfi {
            events_endpoint: None,
            app_key: None,
            metadata: ProductAnalyticsMetadataFfi {
                app_version: "1.0".into(),
                os_family: "linux".into(),
                os_major_version: "1".into(),
                device_class: "desktop".into(),
                host_surface: "native".into(),
                environment: "development".into(),
                is_debug: true,
            },
            registry: vec![ProductEventSchemaFfi {
                name: "app_conversion_check".into(),
                mode: ProductEventModeFfi::Aggregate,
                properties: vec![ProductPropertySchemaFfi {
                    name: "outcome".into(),
                    kind,
                    choices,
                }],
            }],
            allow_loopback: false,
            operator: "fixture".into(),
        };
        for kind in [
            ProductPropertyKindFfi::Boolean,
            ProductPropertyKindFfi::CountBucket,
            ProductPropertyKindFfi::DurationBucket,
        ] {
            assert!(matches!(
                kit.set_product_analytics_runtime_config(config(
                    kind.clone(),
                    vec!["success".into()]
                )),
                Err(MarmotKitError::InvalidProductAnalyticsConfiguration)
            ));
            kit.set_product_analytics_runtime_config(config(kind, vec![]))
                .expect("the same non-enum property without choices is valid");
        }
        kit.set_product_analytics_runtime_config(config(
            ProductPropertyKindFfi::Enum,
            vec!["success".into(), "failure".into()],
        ))
        .expect("enum choices must reach the native configuration");
    }
}
