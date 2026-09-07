//! C records for combined consent and finite product observations.
use crate::macros::{c_enum, c_mirror};
use crate::{
    MarmotStatus,
    memory::{c_bool, optional_str, required_str, str_array},
};
use marmot_uniffi::conversions::*;
c_enum! {MarmotUsageDiagnosticsDecision from UsageDiagnosticsDecisionFfi {AcceptanceRequired,Declined,Granted}}
c_enum! {MarmotProductEventMode from ProductEventModeFfi {Journey,Aggregate}}
c_enum! {MarmotProductAnalyticsActivity from ProductAnalyticsActivityFfi {Foreground,Background,AccountChanged,ForegroundNotification,ForegroundDeepLink}}
c_enum! {MarmotProductRecordResult from ProductRecordResultFfi {Recorded,IgnoredDisabled,IgnoredUnconfigured,IgnoredDuplicate,DroppedCapacity}}
c_enum! {MarmotDiagnosticsExporterStatus from DiagnosticsExporterStatusFfi {Disabled,ConsentRequired,Unconfigured,UnsupportedBuild,Ready,ConfigurationRejected}}
c_enum! {MarmotProductPropertyKind from ProductPropertyKindFfi {Enum,Boolean,CountBucket,DurationBucket}}
c_mirror! {MarmotProductPropertySchema from ProductPropertySchemaFfi{
str name,
enum_val kind: MarmotProductPropertyKind,
str_vec choices/choices_len,
}}
impl MarmotProductPropertySchema {
    /// # Safety
    /// Borrowed pointers must reference valid strings and arrays for this call.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ProductPropertySchemaFfi, MarmotStatus> {
        if self.choices_len > 16 {
            return Err(MarmotStatus::InvalidArgument);
        }
        Ok(ProductPropertySchemaFfi {
            name: unsafe { required_str(self.name) }?,
            kind: MarmotProductPropertyKind::from_c(self.kind)?.into(),
            choices: unsafe { str_array(self.choices.cast(), self.choices_len) }?,
        })
    }
}
c_mirror! {MarmotProductEventProperty from ProductEventPropertyFfi{
str name,
str value,
}}
impl MarmotProductEventProperty {
    /// # Safety
    /// Borrowed pointers must reference valid strings and arrays for this call.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ProductEventPropertyFfi, MarmotStatus> {
        Ok(ProductEventPropertyFfi {
            name: unsafe { required_str(self.name) }?,
            value: unsafe { required_str(self.value) }?,
        })
    }
}
c_mirror! {MarmotProductEvent from ProductEventFfi{
str name,
vec properties/properties_len: MarmotProductEventProperty,
}}
impl MarmotProductEvent {
    /// # Safety
    /// Borrowed pointers must reference valid strings and arrays for this call.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ProductEventFfi, MarmotStatus> {
        Ok(ProductEventFfi {
            name: unsafe { required_str(self.name) }?,
            properties: unsafe {
                read_records(self.properties, self.properties_len, |v| v.to_ffi())
            }?,
        })
    }
}
c_mirror! {MarmotUsageDiagnosticsSettings from UsageDiagnosticsSettingsFfi, free marmot_usage_diagnostics_settings_free{
enum_val decision: MarmotUsageDiagnosticsDecision,
str policy_revision,
str registry_revision,
copy updated_at_ms: i64,
copy previously_enabled: u8,
}}
c_mirror! {MarmotUsageDiagnosticsStatus from UsageDiagnosticsStatusFfi, free marmot_usage_diagnostics_status_free{
enum_val consent: MarmotUsageDiagnosticsDecision,
enum_val telemetry: MarmotDiagnosticsExporterStatus,
enum_val product_analytics: MarmotDiagnosticsExporterStatus,
copy queued_events: u64,
copy dropped_events: u64,
copy accepted_batches: u64,
copy failed_batches: u64,
}}
c_mirror! {MarmotProductAnalyticsMetadata from ProductAnalyticsMetadataFfi{
str app_version,
str os_family,
str os_major_version,
str device_class,
str host_surface,
str environment,
copy is_debug: u8,
}}
impl MarmotProductAnalyticsMetadata {
    /// # Safety
    /// Borrowed pointers must reference valid strings and arrays for this call.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ProductAnalyticsMetadataFfi, MarmotStatus> {
        Ok(ProductAnalyticsMetadataFfi {
            app_version: unsafe { required_str(self.app_version) }?,
            os_family: unsafe { required_str(self.os_family) }?,
            os_major_version: unsafe { required_str(self.os_major_version) }?,
            device_class: unsafe { required_str(self.device_class) }?,
            host_surface: unsafe { required_str(self.host_surface) }?,
            environment: unsafe { required_str(self.environment) }?,
            is_debug: c_bool(self.is_debug),
        })
    }
}
c_mirror! {MarmotProductEventSchema from ProductEventSchemaFfi{
str name,
enum_val mode: MarmotProductEventMode,
vec properties/properties_len: MarmotProductPropertySchema,
}}
impl MarmotProductEventSchema {
    /// # Safety
    /// Borrowed pointers must reference valid strings and arrays for this call.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ProductEventSchemaFfi, MarmotStatus> {
        Ok(ProductEventSchemaFfi {
            name: unsafe { required_str(self.name) }?,
            mode: MarmotProductEventMode::from_c(self.mode)?.into(),
            properties: unsafe {
                read_records(self.properties, self.properties_len, |v| v.to_ffi())
            }?,
        })
    }
}
c_mirror! {MarmotProductAnalyticsRuntimeConfig from ProductAnalyticsRuntimeConfigFfi{
opt_str events_endpoint,
opt_str app_key,
rec metadata: MarmotProductAnalyticsMetadata,
vec registry/registry_len: MarmotProductEventSchema,
copy allow_loopback: u8,
str operator,
}}
impl MarmotProductAnalyticsRuntimeConfig {
    /// # Safety
    /// Borrowed pointers must reference valid strings and arrays for this call.
    pub(crate) unsafe fn to_ffi(&self) -> Result<ProductAnalyticsRuntimeConfigFfi, MarmotStatus> {
        Ok(ProductAnalyticsRuntimeConfigFfi {
            events_endpoint: unsafe { optional_str(self.events_endpoint) }?,
            app_key: unsafe { optional_str(self.app_key) }?,
            metadata: unsafe { self.metadata.to_ffi() }?,
            registry: unsafe { read_records(self.registry, self.registry_len, |v| v.to_ffi()) }?,
            allow_loopback: c_bool(self.allow_loopback),
            operator: unsafe { required_str(self.operator) }?,
        })
    }
}
unsafe fn read_records<T, U>(
    ptr: *const T,
    len: usize,
    f: impl Fn(&T) -> Result<U, MarmotStatus>,
) -> Result<Vec<U>, MarmotStatus> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() || len > 32 {
        return Err(MarmotStatus::InvalidArgument);
    }
    unsafe { std::slice::from_raw_parts(ptr, len) }
        .iter()
        .map(f)
        .collect()
}
impl From<MarmotProductAnalyticsActivity> for ProductAnalyticsActivityFfi {
    fn from(v: MarmotProductAnalyticsActivity) -> Self {
        match v {
            MarmotProductAnalyticsActivity::Foreground => Self::Foreground,
            MarmotProductAnalyticsActivity::Background => Self::Background,
            MarmotProductAnalyticsActivity::AccountChanged => Self::AccountChanged,
            MarmotProductAnalyticsActivity::ForegroundNotification => Self::ForegroundNotification,
            MarmotProductAnalyticsActivity::ForegroundDeepLink => Self::ForegroundDeepLink,
        }
    }
}
impl From<MarmotProductEventMode> for ProductEventModeFfi {
    fn from(v: MarmotProductEventMode) -> Self {
        match v {
            MarmotProductEventMode::Journey => Self::Journey,
            MarmotProductEventMode::Aggregate => Self::Aggregate,
        }
    }
}
impl From<MarmotProductPropertyKind> for ProductPropertyKindFfi {
    fn from(v: MarmotProductPropertyKind) -> Self {
        match v {
            MarmotProductPropertyKind::Enum => Self::Enum,
            MarmotProductPropertyKind::Boolean => Self::Boolean,
            MarmotProductPropertyKind::CountBucket => Self::CountBucket,
            MarmotProductPropertyKind::DurationBucket => Self::DurationBucket,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::CFree;

    #[test]
    fn product_records_preserve_every_config_field_and_free_nested_allocations() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let mut record =
            MarmotProductAnalyticsRuntimeConfig::from(ProductAnalyticsRuntimeConfigFfi {
                events_endpoint: Some("https://analytics.example/prefix/api/v0/events".into()),
                app_key: Some("A-SH-test".into()),
                operator: "test_operator".into(),
                allow_loopback: true,
                metadata: ProductAnalyticsMetadataFfi {
                    app_version: "1.2.3".into(),
                    os_family: "ios".into(),
                    os_major_version: "26".into(),
                    device_class: "phone".into(),
                    host_surface: "native".into(),
                    environment: "staging".into(),
                    is_debug: true,
                },
                registry: vec![ProductEventSchemaFfi {
                    name: "app_action".into(),
                    mode: ProductEventModeFfi::Aggregate,
                    properties: vec![ProductPropertySchemaFfi {
                        name: "action".into(),
                        kind: ProductPropertyKindFfi::Enum,
                        choices: vec!["open".into(), "close".into()],
                    }],
                }],
            });
        let ffi = unsafe { record.to_ffi() }.unwrap();
        assert_eq!(
            ffi.events_endpoint.as_deref(),
            Some("https://analytics.example/prefix/api/v0/events")
        );
        assert_eq!(ffi.app_key.as_deref(), Some("A-SH-test"));
        assert_eq!(ffi.operator, "test_operator");
        assert!(ffi.allow_loopback);
        assert_eq!(ffi.metadata.app_version, "1.2.3");
        assert_eq!(ffi.metadata.os_family, "ios");
        assert_eq!(ffi.metadata.os_major_version, "26");
        assert_eq!(ffi.metadata.device_class, "phone");
        assert_eq!(ffi.metadata.host_surface, "native");
        assert_eq!(ffi.metadata.environment, "staging");
        assert!(ffi.metadata.is_debug);
        assert_eq!(ffi.registry[0].name, "app_action");
        assert_eq!(ffi.registry[0].mode, ProductEventModeFfi::Aggregate);
        assert_eq!(ffi.registry[0].properties[0].name, "action");
        assert_eq!(
            ffi.registry[0].properties[0].kind,
            ProductPropertyKindFfi::Enum
        );
        assert_eq!(ffi.registry[0].properties[0].choices, ["open", "close"]);
        assert!(!format!("{ffi:?}").contains("A-SH-test"));
        unsafe { record.free_in_place() };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn consent_status_fields_and_null_array_rejection() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let settings = MarmotUsageDiagnosticsSettings::from(UsageDiagnosticsSettingsFfi {
            decision: UsageDiagnosticsDecisionFfi::Granted,
            policy_revision: "policy".into(),
            registry_revision: "registry".into(),
            updated_at_ms: 123,
            previously_enabled: true,
        });
        assert_eq!(
            settings.decision,
            MarmotUsageDiagnosticsDecision::Granted as u32
        );
        assert_eq!(
            unsafe { required_str(settings.policy_revision) }.unwrap(),
            "policy"
        );
        assert_eq!(
            unsafe { required_str(settings.registry_revision) }.unwrap(),
            "registry"
        );
        assert_eq!(settings.updated_at_ms, 123);
        assert_eq!(settings.previously_enabled, 1);
        unsafe { marmot_usage_diagnostics_settings_free(crate::memory::boxed(settings)) };
        let status = MarmotUsageDiagnosticsStatus::from(UsageDiagnosticsStatusFfi {
            consent: UsageDiagnosticsDecisionFfi::Granted,
            telemetry: DiagnosticsExporterStatusFfi::Ready,
            product_analytics: DiagnosticsExporterStatusFfi::Unconfigured,
            queued_events: 12,
            dropped_events: 23,
            accepted_batches: 34,
            failed_batches: 45,
        });
        assert_eq!(
            status.consent,
            MarmotUsageDiagnosticsDecision::Granted as u32
        );
        assert_eq!(
            status.telemetry,
            MarmotDiagnosticsExporterStatus::Ready as u32
        );
        assert_eq!(
            status.product_analytics,
            MarmotDiagnosticsExporterStatus::Unconfigured as u32
        );
        assert_eq!(
            (
                status.queued_events,
                status.dropped_events,
                status.accepted_batches,
                status.failed_batches
            ),
            (12, 23, 34, 45)
        );
        unsafe { marmot_usage_diagnostics_status_free(crate::memory::boxed(status)) };
        let invalid = unsafe { read_records::<u8, u8>(std::ptr::null(), 1, |v| Ok(*v)) };
        assert_eq!(invalid, Err(MarmotStatus::InvalidArgument));
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
