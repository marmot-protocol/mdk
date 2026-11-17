use marmot_app::{
    FollowAvailability, FollowAvailabilityPage, FollowAvailabilityRefreshPhase,
    FollowAvailabilityRefreshStatus, FollowAvailabilitySource, FollowAvailabilityState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FollowAvailabilityStateFfi {
    Ready,
    Unknown,
    NotFound,
}

impl From<FollowAvailabilityState> for FollowAvailabilityStateFfi {
    fn from(value: FollowAvailabilityState) -> Self {
        match value {
            FollowAvailabilityState::Ready => Self::Ready,
            FollowAvailabilityState::Unknown => Self::Unknown,
            FollowAvailabilityState::NotFound => Self::NotFound,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FollowAvailabilitySourceFfi {
    None,
    Network,
}

impl From<FollowAvailabilitySource> for FollowAvailabilitySourceFfi {
    fn from(value: FollowAvailabilitySource) -> Self {
        match value {
            FollowAvailabilitySource::None => Self::None,
            FollowAvailabilitySource::Network => Self::Network,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FollowAvailabilityFfi {
    pub account_id_hex: String,
    pub state: FollowAvailabilityStateFfi,
    pub checked_at: Option<u64>,
    pub fresh_until: Option<u64>,
    pub key_package_event_id: Option<String>,
    pub source: FollowAvailabilitySourceFfi,
}

impl From<FollowAvailability> for FollowAvailabilityFfi {
    fn from(value: FollowAvailability) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            state: value.state.into(),
            checked_at: value.checked_at,
            fresh_until: value.fresh_until,
            key_package_event_id: value.key_package_event_id,
            source: value.source.into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct FollowAvailabilityPageFfi {
    pub rows: Vec<FollowAvailabilityFfi>,
    pub next_cursor: Option<String>,
}

impl From<FollowAvailabilityPage> for FollowAvailabilityPageFfi {
    fn from(value: FollowAvailabilityPage) -> Self {
        Self {
            rows: value.rows.into_iter().map(Into::into).collect(),
            next_cursor: value.next_cursor,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum FollowAvailabilityRefreshPhaseFfi {
    Idle,
    Running,
    Complete,
    Partial,
    Cancelled,
    Throttled,
    Failed,
}

impl From<FollowAvailabilityRefreshPhase> for FollowAvailabilityRefreshPhaseFfi {
    fn from(value: FollowAvailabilityRefreshPhase) -> Self {
        match value {
            FollowAvailabilityRefreshPhase::Idle => Self::Idle,
            FollowAvailabilityRefreshPhase::Running => Self::Running,
            FollowAvailabilityRefreshPhase::Complete => Self::Complete,
            FollowAvailabilityRefreshPhase::Partial => Self::Partial,
            FollowAvailabilityRefreshPhase::Cancelled => Self::Cancelled,
            FollowAvailabilityRefreshPhase::Throttled => Self::Throttled,
            FollowAvailabilityRefreshPhase::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct FollowAvailabilityRefreshStatusFfi {
    pub operation_id: Option<u64>,
    pub phase: FollowAvailabilityRefreshPhaseFfi,
    pub total: u32,
    pub completed: u32,
    pub ready: u32,
    pub unknown: u32,
    pub not_found: u32,
    pub failed: u32,
    pub truncated: bool,
}

impl From<FollowAvailabilityRefreshStatus> for FollowAvailabilityRefreshStatusFfi {
    fn from(value: FollowAvailabilityRefreshStatus) -> Self {
        Self {
            operation_id: value.operation_id,
            phase: value.phase.into(),
            total: value.total,
            completed: value.completed,
            ready: value.ready,
            unknown: value.unknown,
            not_found: value.not_found,
            failed: value.failed,
            truncated: value.truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_conversion() {
        let row = FollowAvailabilityFfi::from(FollowAvailability {
            account_id_hex: "42".repeat(32),
            state: FollowAvailabilityState::NotFound,
            checked_at: Some(100),
            fresh_until: Some(1_000),
            key_package_event_id: None,
            source: FollowAvailabilitySource::Network,
        });
        assert!(matches!(row.state, FollowAvailabilityStateFfi::NotFound));
        assert!(matches!(row.source, FollowAvailabilitySourceFfi::Network));
        assert_eq!(row.checked_at, Some(100));
        assert_eq!(row.fresh_until, Some(1_000));
        assert_eq!(row.key_package_event_id, None);

        let status = FollowAvailabilityRefreshStatusFfi::from(FollowAvailabilityRefreshStatus {
            operation_id: Some(7),
            phase: FollowAvailabilityRefreshPhase::Partial,
            total: 10,
            completed: 8,
            ready: 4,
            unknown: 2,
            not_found: 2,
            failed: 2,
            truncated: true,
        });
        assert_eq!(status.operation_id, Some(7));
        assert!(matches!(
            status.phase,
            FollowAvailabilityRefreshPhaseFfi::Partial
        ));
        assert_eq!(
            (
                status.total,
                status.completed,
                status.ready,
                status.unknown,
                status.not_found,
                status.failed,
                status.truncated,
            ),
            (10, 8, 4, 2, 2, 2, true)
        );
    }
}
