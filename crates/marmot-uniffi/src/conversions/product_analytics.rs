//! Usage and diagnostics records. Only reviewed finite observations cross this boundary.
use marmot_app as app;
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum UsageDiagnosticsDecisionFfi {
    AcceptanceRequired,
    Declined,
    Granted,
}
impl From<UsageDiagnosticsDecisionFfi> for app::UsageDiagnosticsDecision {
    fn from(v: UsageDiagnosticsDecisionFfi) -> Self {
        match v {
            UsageDiagnosticsDecisionFfi::AcceptanceRequired => Self::AcceptanceRequired,
            UsageDiagnosticsDecisionFfi::Declined => Self::Declined,
            UsageDiagnosticsDecisionFfi::Granted => Self::Granted,
        }
    }
}
impl From<app::UsageDiagnosticsDecision> for UsageDiagnosticsDecisionFfi {
    fn from(v: app::UsageDiagnosticsDecision) -> Self {
        match v {
            app::UsageDiagnosticsDecision::AcceptanceRequired => Self::AcceptanceRequired,
            app::UsageDiagnosticsDecision::Declined => Self::Declined,
            app::UsageDiagnosticsDecision::Granted => Self::Granted,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProductEventModeFfi {
    Journey,
    Aggregate,
}
impl From<ProductEventModeFfi> for app::ProductEventMode {
    fn from(v: ProductEventModeFfi) -> Self {
        match v {
            ProductEventModeFfi::Journey => Self::Journey,
            ProductEventModeFfi::Aggregate => Self::Aggregate,
        }
    }
}
impl From<app::ProductEventMode> for ProductEventModeFfi {
    fn from(v: app::ProductEventMode) -> Self {
        match v {
            app::ProductEventMode::Journey => Self::Journey,
            app::ProductEventMode::Aggregate => Self::Aggregate,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProductAnalyticsActivityFfi {
    Foreground,
    Background,
    AccountChanged,
    ForegroundNotification,
    ForegroundDeepLink,
}
impl From<ProductAnalyticsActivityFfi> for app::ProductAnalyticsActivity {
    fn from(v: ProductAnalyticsActivityFfi) -> Self {
        match v {
            ProductAnalyticsActivityFfi::Foreground => Self::Foreground,
            ProductAnalyticsActivityFfi::Background => Self::Background,
            ProductAnalyticsActivityFfi::AccountChanged => Self::AccountChanged,
            ProductAnalyticsActivityFfi::ForegroundNotification => Self::ForegroundNotification,
            ProductAnalyticsActivityFfi::ForegroundDeepLink => Self::ForegroundDeepLink,
        }
    }
}
impl From<app::ProductAnalyticsActivity> for ProductAnalyticsActivityFfi {
    fn from(v: app::ProductAnalyticsActivity) -> Self {
        match v {
            app::ProductAnalyticsActivity::Foreground => Self::Foreground,
            app::ProductAnalyticsActivity::Background => Self::Background,
            app::ProductAnalyticsActivity::AccountChanged => Self::AccountChanged,
            app::ProductAnalyticsActivity::ForegroundNotification => Self::ForegroundNotification,
            app::ProductAnalyticsActivity::ForegroundDeepLink => Self::ForegroundDeepLink,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProductRecordResultFfi {
    Recorded,
    IgnoredDisabled,
    IgnoredUnconfigured,
    IgnoredDuplicate,
    DroppedCapacity,
}
impl From<ProductRecordResultFfi> for app::ProductRecordResult {
    fn from(v: ProductRecordResultFfi) -> Self {
        match v {
            ProductRecordResultFfi::Recorded => Self::Recorded,
            ProductRecordResultFfi::IgnoredDisabled => Self::IgnoredDisabled,
            ProductRecordResultFfi::IgnoredUnconfigured => Self::IgnoredUnconfigured,
            ProductRecordResultFfi::IgnoredDuplicate => Self::IgnoredDuplicate,
            ProductRecordResultFfi::DroppedCapacity => Self::DroppedCapacity,
        }
    }
}
impl From<app::ProductRecordResult> for ProductRecordResultFfi {
    fn from(v: app::ProductRecordResult) -> Self {
        match v {
            app::ProductRecordResult::Recorded => Self::Recorded,
            app::ProductRecordResult::IgnoredDisabled => Self::IgnoredDisabled,
            app::ProductRecordResult::IgnoredUnconfigured => Self::IgnoredUnconfigured,
            app::ProductRecordResult::IgnoredDuplicate => Self::IgnoredDuplicate,
            app::ProductRecordResult::DroppedCapacity => Self::DroppedCapacity,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DiagnosticsExporterStatusFfi {
    Disabled,
    ConsentRequired,
    Unconfigured,
    UnsupportedBuild,
    Ready,
    ConfigurationRejected,
}
impl From<DiagnosticsExporterStatusFfi> for app::DiagnosticsExporterStatus {
    fn from(v: DiagnosticsExporterStatusFfi) -> Self {
        match v {
            DiagnosticsExporterStatusFfi::Disabled => Self::Disabled,
            DiagnosticsExporterStatusFfi::ConsentRequired => Self::ConsentRequired,
            DiagnosticsExporterStatusFfi::Unconfigured => Self::Unconfigured,
            DiagnosticsExporterStatusFfi::UnsupportedBuild => Self::UnsupportedBuild,
            DiagnosticsExporterStatusFfi::Ready => Self::Ready,
            DiagnosticsExporterStatusFfi::ConfigurationRejected => Self::ConfigurationRejected,
        }
    }
}
impl From<app::DiagnosticsExporterStatus> for DiagnosticsExporterStatusFfi {
    fn from(v: app::DiagnosticsExporterStatus) -> Self {
        match v {
            app::DiagnosticsExporterStatus::Disabled => Self::Disabled,
            app::DiagnosticsExporterStatus::ConsentRequired => Self::ConsentRequired,
            app::DiagnosticsExporterStatus::Unconfigured => Self::Unconfigured,
            app::DiagnosticsExporterStatus::UnsupportedBuild => Self::UnsupportedBuild,
            app::DiagnosticsExporterStatus::Ready => Self::Ready,
            app::DiagnosticsExporterStatus::ConfigurationRejected => Self::ConfigurationRejected,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ProductPropertyKindFfi {
    Enum,
    Boolean,
    CountBucket,
    DurationBucket,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProductPropertySchemaFfi {
    pub name: String,
    pub kind: ProductPropertyKindFfi,
    pub choices: Vec<String>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProductEventPropertyFfi {
    pub name: String,
    pub value: String,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProductEventFfi {
    pub name: String,
    pub properties: Vec<ProductEventPropertyFfi>,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct UsageDiagnosticsSettingsFfi {
    pub decision: UsageDiagnosticsDecisionFfi,
    pub policy_revision: String,
    pub registry_revision: String,
    pub updated_at_ms: i64,
    pub previously_enabled: bool,
}
impl From<UsageDiagnosticsSettingsFfi> for app::UsageDiagnosticsSettings {
    fn from(v: UsageDiagnosticsSettingsFfi) -> Self {
        Self {
            decision: v.decision.into(),
            policy_revision: v.policy_revision,
            registry_revision: v.registry_revision,
            updated_at_ms: v.updated_at_ms,
            previously_enabled: v.previously_enabled,
        }
    }
}
impl From<app::UsageDiagnosticsSettings> for UsageDiagnosticsSettingsFfi {
    fn from(v: app::UsageDiagnosticsSettings) -> Self {
        Self {
            decision: v.decision.into(),
            policy_revision: v.policy_revision,
            registry_revision: v.registry_revision,
            updated_at_ms: v.updated_at_ms,
            previously_enabled: v.previously_enabled,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct UsageDiagnosticsStatusFfi {
    pub consent: UsageDiagnosticsDecisionFfi,
    pub telemetry: DiagnosticsExporterStatusFfi,
    pub product_analytics: DiagnosticsExporterStatusFfi,
    pub queued_events: u64,
    pub dropped_events: u64,
    pub accepted_batches: u64,
    pub failed_batches: u64,
}
impl From<UsageDiagnosticsStatusFfi> for app::UsageDiagnosticsStatus {
    fn from(v: UsageDiagnosticsStatusFfi) -> Self {
        Self {
            consent: v.consent.into(),
            telemetry: v.telemetry.into(),
            product_analytics: v.product_analytics.into(),
            queued_events: v.queued_events,
            dropped_events: v.dropped_events,
            accepted_batches: v.accepted_batches,
            failed_batches: v.failed_batches,
        }
    }
}
impl From<app::UsageDiagnosticsStatus> for UsageDiagnosticsStatusFfi {
    fn from(v: app::UsageDiagnosticsStatus) -> Self {
        Self {
            consent: v.consent.into(),
            telemetry: v.telemetry.into(),
            product_analytics: v.product_analytics.into(),
            queued_events: v.queued_events,
            dropped_events: v.dropped_events,
            accepted_batches: v.accepted_batches,
            failed_batches: v.failed_batches,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProductAnalyticsMetadataFfi {
    pub app_version: String,
    pub os_family: String,
    pub os_major_version: String,
    pub device_class: String,
    pub host_surface: String,
    pub environment: String,
    pub is_debug: bool,
}
impl From<ProductAnalyticsMetadataFfi> for app::ProductAnalyticsMetadata {
    fn from(v: ProductAnalyticsMetadataFfi) -> Self {
        Self {
            app_version: v.app_version,
            os_family: v.os_family,
            os_major_version: v.os_major_version,
            device_class: v.device_class,
            host_surface: v.host_surface,
            environment: v.environment,
            is_debug: v.is_debug,
        }
    }
}
impl From<app::ProductAnalyticsMetadata> for ProductAnalyticsMetadataFfi {
    fn from(v: app::ProductAnalyticsMetadata) -> Self {
        Self {
            app_version: v.app_version,
            os_family: v.os_family,
            os_major_version: v.os_major_version,
            device_class: v.device_class,
            host_surface: v.host_surface,
            environment: v.environment,
            is_debug: v.is_debug,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProductEventSchemaFfi {
    pub name: String,
    pub mode: ProductEventModeFfi,
    pub properties: Vec<ProductPropertySchemaFfi>,
}
impl From<ProductEventSchemaFfi> for app::ProductEventSchema {
    fn from(v: ProductEventSchemaFfi) -> Self {
        Self {
            name: v.name,
            mode: v.mode.into(),
            properties: v.properties.into_iter().map(Into::into).collect(),
        }
    }
}
#[derive(Clone, uniffi::Record)]
pub struct ProductAnalyticsRuntimeConfigFfi {
    pub events_endpoint: Option<String>,
    pub app_key: Option<String>,
    pub metadata: ProductAnalyticsMetadataFfi,
    pub registry: Vec<ProductEventSchemaFfi>,
    pub allow_loopback: bool,
    pub operator: String,
}
impl From<ProductAnalyticsRuntimeConfigFfi> for app::ProductAnalyticsRuntimeConfig {
    fn from(v: ProductAnalyticsRuntimeConfigFfi) -> Self {
        Self {
            events_endpoint: v.events_endpoint,
            app_key: v.app_key,
            metadata: v.metadata.into(),
            registry: v.registry.into_iter().map(Into::into).collect(),
            allow_loopback: v.allow_loopback,
            operator: v.operator,
        }
    }
}
impl std::fmt::Debug for ProductAnalyticsRuntimeConfigFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductAnalyticsRuntimeConfigFfi")
            .finish_non_exhaustive()
    }
}
impl From<ProductPropertySchemaFfi> for app::ProductPropertySchema {
    fn from(v: ProductPropertySchemaFfi) -> Self {
        Self {
            name: v.name,
            rule: match v.kind {
                ProductPropertyKindFfi::Enum => app::ProductPropertyRule::Enum(v.choices),
                ProductPropertyKindFfi::Boolean => app::ProductPropertyRule::Boolean,
                ProductPropertyKindFfi::CountBucket => app::ProductPropertyRule::CountBucket,
                ProductPropertyKindFfi::DurationBucket => app::ProductPropertyRule::DurationBucket,
            },
        }
    }
}
impl TryFrom<ProductEventFfi> for app::ProductEvent {
    type Error = crate::MarmotKitError;
    fn try_from(v: ProductEventFfi) -> Result<Self, Self::Error> {
        let len = v.properties.len();
        let properties: std::collections::BTreeMap<_, _> = v
            .properties
            .into_iter()
            .map(|p| (p.name, p.value))
            .collect();
        if properties.len() != len {
            return Err(app::AppError::from(app::ProductAnalyticsError::InvalidEvent).into());
        }
        Ok(Self {
            name: v.name,
            properties,
        })
    }
}
