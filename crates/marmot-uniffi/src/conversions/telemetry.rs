//! Host-app performance telemetry value types.

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HostPerformanceOperationFfi {
    SplashReady,
    ForegroundLocalReady,
}

impl From<HostPerformanceOperationFfi> for marmot_app::HostPerformanceOperation {
    fn from(value: HostPerformanceOperationFfi) -> Self {
        match value {
            HostPerformanceOperationFfi::SplashReady => Self::SplashReady,
            HostPerformanceOperationFfi::ForegroundLocalReady => Self::ForegroundLocalReady,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HostPerformanceOutcomeFfi {
    Success,
    Failure,
}

impl From<HostPerformanceOutcomeFfi> for marmot_app::HostPerformanceOutcome {
    fn from(value: HostPerformanceOutcomeFfi) -> Self {
        match value {
            HostPerformanceOutcomeFfi::Success => Self::Success,
            HostPerformanceOutcomeFfi::Failure => Self::Failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_performance_enums_preserve_every_variant() {
        assert!(matches!(
            marmot_app::HostPerformanceOperation::from(
                HostPerformanceOperationFfi::ForegroundLocalReady
            ),
            marmot_app::HostPerformanceOperation::ForegroundLocalReady
        ));
        assert!(matches!(
            marmot_app::HostPerformanceOutcome::from(HostPerformanceOutcomeFfi::Failure),
            marmot_app::HostPerformanceOutcome::Failure
        ));
    }
}
