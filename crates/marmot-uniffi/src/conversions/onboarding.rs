//! Typed onboarding contract for Swift and Kotlin.
use super::UserProfileMetadataFfi;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingStepFfi {
    Profile,
    Follows,
    Relays,
    InboxRelays,
    SingleDevice,
    KeyPackage,
}
impl From<marmot_app::OnboardingStep> for OnboardingStepFfi {
    fn from(value: marmot_app::OnboardingStep) -> Self {
        match value {
            marmot_app::OnboardingStep::Profile => Self::Profile,
            marmot_app::OnboardingStep::Follows => Self::Follows,
            marmot_app::OnboardingStep::Relays => Self::Relays,
            marmot_app::OnboardingStep::InboxRelays => Self::InboxRelays,
            marmot_app::OnboardingStep::KeyPackage => Self::KeyPackage,
            marmot_app::OnboardingStep::SingleDevice => Self::SingleDevice,
        }
    }
}
impl From<OnboardingStepFfi> for marmot_app::OnboardingStep {
    fn from(value: OnboardingStepFfi) -> Self {
        match value {
            OnboardingStepFfi::Profile => Self::Profile,
            OnboardingStepFfi::Follows => Self::Follows,
            OnboardingStepFfi::Relays => Self::Relays,
            OnboardingStepFfi::InboxRelays => Self::InboxRelays,
            OnboardingStepFfi::KeyPackage => Self::KeyPackage,
            OnboardingStepFfi::SingleDevice => Self::SingleDevice,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingStatusFfi {
    Pending,
    Checking,
    Passed,
    NeedsInput,
    RetryableFailure,
    WaitingForSigner,
    Skipped,
}
impl From<marmot_app::OnboardingStatus> for OnboardingStatusFfi {
    fn from(value: marmot_app::OnboardingStatus) -> Self {
        match value {
            marmot_app::OnboardingStatus::Pending => Self::Pending,
            marmot_app::OnboardingStatus::Checking => Self::Checking,
            marmot_app::OnboardingStatus::Passed => Self::Passed,
            marmot_app::OnboardingStatus::NeedsInput => Self::NeedsInput,
            marmot_app::OnboardingStatus::RetryableFailure => Self::RetryableFailure,
            marmot_app::OnboardingStatus::WaitingForSigner => Self::WaitingForSigner,
            marmot_app::OnboardingStatus::Skipped => Self::Skipped,
        }
    }
}
impl From<OnboardingStatusFfi> for marmot_app::OnboardingStatus {
    fn from(value: OnboardingStatusFfi) -> Self {
        match value {
            OnboardingStatusFfi::Pending => Self::Pending,
            OnboardingStatusFfi::Checking => Self::Checking,
            OnboardingStatusFfi::Passed => Self::Passed,
            OnboardingStatusFfi::NeedsInput => Self::NeedsInput,
            OnboardingStatusFfi::RetryableFailure => Self::RetryableFailure,
            OnboardingStatusFfi::WaitingForSigner => Self::WaitingForSigner,
            OnboardingStatusFfi::Skipped => Self::Skipped,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingIssueFfi {
    Missing,
    Malformed,
    FutureDated,
    InvalidRelay,
    RetiredRelay,
    UnsafeRelay,
    Unreachable,
    TimedOut,
    AuthenticationRequired,
    PaymentRequired,
    AccessRestricted,
    NoUsableRoute,
    PublicationFailed,
    SignerUnavailable,
    SignerRejected,
    RecordChanged,
    Interrupted,
    TooManyRelays,
    MultiDeviceUnsupported,
    OtherInstallationPossible,
    DiscoveryIncomplete,
}
impl From<marmot_app::OnboardingIssue> for OnboardingIssueFfi {
    fn from(value: marmot_app::OnboardingIssue) -> Self {
        match value {
            marmot_app::OnboardingIssue::Missing => Self::Missing,
            marmot_app::OnboardingIssue::Malformed => Self::Malformed,
            marmot_app::OnboardingIssue::FutureDated => Self::FutureDated,
            marmot_app::OnboardingIssue::InvalidRelay => Self::InvalidRelay,
            marmot_app::OnboardingIssue::RetiredRelay => Self::RetiredRelay,
            marmot_app::OnboardingIssue::UnsafeRelay => Self::UnsafeRelay,
            marmot_app::OnboardingIssue::Unreachable => Self::Unreachable,
            marmot_app::OnboardingIssue::TimedOut => Self::TimedOut,
            marmot_app::OnboardingIssue::AuthenticationRequired => Self::AuthenticationRequired,
            marmot_app::OnboardingIssue::PaymentRequired => Self::PaymentRequired,
            marmot_app::OnboardingIssue::AccessRestricted => Self::AccessRestricted,
            marmot_app::OnboardingIssue::NoUsableRoute => Self::NoUsableRoute,
            marmot_app::OnboardingIssue::PublicationFailed => Self::PublicationFailed,
            marmot_app::OnboardingIssue::SignerUnavailable => Self::SignerUnavailable,
            marmot_app::OnboardingIssue::SignerRejected => Self::SignerRejected,
            marmot_app::OnboardingIssue::RecordChanged => Self::RecordChanged,
            marmot_app::OnboardingIssue::Interrupted => Self::Interrupted,
            marmot_app::OnboardingIssue::TooManyRelays => Self::TooManyRelays,
            marmot_app::OnboardingIssue::MultiDeviceUnsupported => Self::MultiDeviceUnsupported,
            marmot_app::OnboardingIssue::OtherInstallationPossible => {
                Self::OtherInstallationPossible
            }
            marmot_app::OnboardingIssue::DiscoveryIncomplete => Self::DiscoveryIncomplete,
        }
    }
}
impl From<OnboardingIssueFfi> for marmot_app::OnboardingIssue {
    fn from(value: OnboardingIssueFfi) -> Self {
        match value {
            OnboardingIssueFfi::Missing => Self::Missing,
            OnboardingIssueFfi::Malformed => Self::Malformed,
            OnboardingIssueFfi::FutureDated => Self::FutureDated,
            OnboardingIssueFfi::InvalidRelay => Self::InvalidRelay,
            OnboardingIssueFfi::RetiredRelay => Self::RetiredRelay,
            OnboardingIssueFfi::UnsafeRelay => Self::UnsafeRelay,
            OnboardingIssueFfi::Unreachable => Self::Unreachable,
            OnboardingIssueFfi::TimedOut => Self::TimedOut,
            OnboardingIssueFfi::AuthenticationRequired => Self::AuthenticationRequired,
            OnboardingIssueFfi::PaymentRequired => Self::PaymentRequired,
            OnboardingIssueFfi::AccessRestricted => Self::AccessRestricted,
            OnboardingIssueFfi::NoUsableRoute => Self::NoUsableRoute,
            OnboardingIssueFfi::PublicationFailed => Self::PublicationFailed,
            OnboardingIssueFfi::SignerUnavailable => Self::SignerUnavailable,
            OnboardingIssueFfi::SignerRejected => Self::SignerRejected,
            OnboardingIssueFfi::RecordChanged => Self::RecordChanged,
            OnboardingIssueFfi::Interrupted => Self::Interrupted,
            OnboardingIssueFfi::TooManyRelays => Self::TooManyRelays,
            OnboardingIssueFfi::MultiDeviceUnsupported => Self::MultiDeviceUnsupported,
            OnboardingIssueFfi::OtherInstallationPossible => Self::OtherInstallationPossible,
            OnboardingIssueFfi::DiscoveryIncomplete => Self::DiscoveryIncomplete,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingActionFfi {
    Retry,
    ContinueWithout,
    UseRecommendedRelays,
    EditRelays,
    EditProfile,
    EditFollows,
    ApproveRepair,
    CancelRepair,
    ReconnectSigner,
    EditDiscoveryRelays,
    ContinueAnyway,
    CancelOnboarding,
}
impl From<marmot_app::OnboardingAction> for OnboardingActionFfi {
    fn from(value: marmot_app::OnboardingAction) -> Self {
        match value {
            marmot_app::OnboardingAction::Retry => Self::Retry,
            marmot_app::OnboardingAction::ContinueWithout => Self::ContinueWithout,
            marmot_app::OnboardingAction::UseRecommendedRelays => Self::UseRecommendedRelays,
            marmot_app::OnboardingAction::EditRelays => Self::EditRelays,
            marmot_app::OnboardingAction::EditProfile => Self::EditProfile,
            marmot_app::OnboardingAction::EditFollows => Self::EditFollows,
            marmot_app::OnboardingAction::ApproveRepair => Self::ApproveRepair,
            marmot_app::OnboardingAction::CancelRepair => Self::CancelRepair,
            marmot_app::OnboardingAction::EditDiscoveryRelays => Self::EditDiscoveryRelays,
            marmot_app::OnboardingAction::ReconnectSigner => Self::ReconnectSigner,
            marmot_app::OnboardingAction::ContinueAnyway => Self::ContinueAnyway,
            marmot_app::OnboardingAction::CancelOnboarding => Self::CancelOnboarding,
        }
    }
}
impl From<OnboardingActionFfi> for marmot_app::OnboardingAction {
    fn from(value: OnboardingActionFfi) -> Self {
        match value {
            OnboardingActionFfi::Retry => Self::Retry,
            OnboardingActionFfi::ContinueWithout => Self::ContinueWithout,
            OnboardingActionFfi::UseRecommendedRelays => Self::UseRecommendedRelays,
            OnboardingActionFfi::EditRelays => Self::EditRelays,
            OnboardingActionFfi::EditProfile => Self::EditProfile,
            OnboardingActionFfi::EditFollows => Self::EditFollows,
            OnboardingActionFfi::ApproveRepair => Self::ApproveRepair,
            OnboardingActionFfi::CancelRepair => Self::CancelRepair,
            OnboardingActionFfi::EditDiscoveryRelays => Self::EditDiscoveryRelays,
            OnboardingActionFfi::ReconnectSigner => Self::ReconnectSigner,
            OnboardingActionFfi::ContinueAnyway => Self::ContinueAnyway,
            OnboardingActionFfi::CancelOnboarding => Self::CancelOnboarding,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingFindingFfi {
    pub issue: OnboardingIssueFfi,
    pub endpoint: Option<String>,
}
impl From<marmot_app::OnboardingFinding> for OnboardingFindingFfi {
    fn from(value: marmot_app::OnboardingFinding) -> Self {
        Self {
            issue: value.issue.into(),
            endpoint: value.endpoint,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingStepStateFfi {
    pub step: OnboardingStepFfi,
    pub status: OnboardingStatusFfi,
    pub findings: Vec<OnboardingFindingFfi>,
    pub actions: Vec<OnboardingActionFfi>,
    pub checked_at: Option<u64>,
}
impl From<marmot_app::OnboardingStepState> for OnboardingStepStateFfi {
    fn from(value: marmot_app::OnboardingStepState) -> Self {
        Self {
            step: value.step.into(),
            status: value.status.into(),
            findings: value.findings.into_iter().map(Into::into).collect(),
            actions: value.actions.into_iter().map(Into::into).collect(),
            checked_at: value.checked_at,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingRelayTagRoleFfi {
    Other,
    Unmarked,
    Read,
    Write,
    Inbox,
}
impl From<marmot_app::OnboardingRelayTagRole> for OnboardingRelayTagRoleFfi {
    fn from(value: marmot_app::OnboardingRelayTagRole) -> Self {
        match value {
            marmot_app::OnboardingRelayTagRole::Other => Self::Other,
            marmot_app::OnboardingRelayTagRole::Unmarked => Self::Unmarked,
            marmot_app::OnboardingRelayTagRole::Read => Self::Read,
            marmot_app::OnboardingRelayTagRole::Write => Self::Write,
            marmot_app::OnboardingRelayTagRole::Inbox => Self::Inbox,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingRelayTagDispositionFfi {
    Retained,
    Removed,
    Added,
}
impl From<marmot_app::OnboardingRelayTagDisposition> for OnboardingRelayTagDispositionFfi {
    fn from(value: marmot_app::OnboardingRelayTagDisposition) -> Self {
        match value {
            marmot_app::OnboardingRelayTagDisposition::Retained => Self::Retained,
            marmot_app::OnboardingRelayTagDisposition::Removed => Self::Removed,
            marmot_app::OnboardingRelayTagDisposition::Added => Self::Added,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingRelayCapabilityFfi {
    None,
    Read,
    Write,
    ReadAndWrite,
    Inbox,
}
impl From<marmot_app::OnboardingRelayCapability> for OnboardingRelayCapabilityFfi {
    fn from(value: marmot_app::OnboardingRelayCapability) -> Self {
        match value {
            marmot_app::OnboardingRelayCapability::None => Self::None,
            marmot_app::OnboardingRelayCapability::Read => Self::Read,
            marmot_app::OnboardingRelayCapability::Write => Self::Write,
            marmot_app::OnboardingRelayCapability::ReadAndWrite => Self::ReadAndWrite,
            marmot_app::OnboardingRelayCapability::Inbox => Self::Inbox,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingRelayRepairModeFfi {
    ManualReview,
    RemovalOnly,
    Additive,
    RemovalAndAdditive,
}
impl From<marmot_app::OnboardingRelayRepairMode> for OnboardingRelayRepairModeFfi {
    fn from(value: marmot_app::OnboardingRelayRepairMode) -> Self {
        match value {
            marmot_app::OnboardingRelayRepairMode::ManualReview => Self::ManualReview,
            marmot_app::OnboardingRelayRepairMode::RemovalOnly => Self::RemovalOnly,
            marmot_app::OnboardingRelayRepairMode::Additive => Self::Additive,
            marmot_app::OnboardingRelayRepairMode::RemovalAndAdditive => Self::RemovalAndAdditive,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingRelayTagFfi {
    pub fields: Vec<String>,
    pub endpoint: Option<String>,
    pub role: OnboardingRelayTagRoleFfi,
}
impl From<marmot_app::OnboardingRelayTag> for OnboardingRelayTagFfi {
    fn from(value: marmot_app::OnboardingRelayTag) -> Self {
        Self {
            fields: value.fields,
            endpoint: value.endpoint,
            role: value.role.into(),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingRelayTagChangeFfi {
    pub disposition: OnboardingRelayTagDispositionFfi,
    pub before_index: Option<u64>,
    pub after_index: Option<u64>,
    pub fields: Vec<String>,
    pub endpoint: Option<String>,
    pub role: OnboardingRelayTagRoleFfi,
    pub restores: OnboardingRelayCapabilityFfi,
}
impl From<marmot_app::OnboardingRelayTagChange> for OnboardingRelayTagChangeFfi {
    fn from(value: marmot_app::OnboardingRelayTagChange) -> Self {
        Self {
            disposition: value.disposition.into(),
            before_index: value.before_index,
            after_index: value.after_index,
            fields: value.fields,
            endpoint: value.endpoint,
            role: value.role.into(),
            restores: value.restores.into(),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingRelayRepairFfi {
    pub mode: OnboardingRelayRepairModeFfi,
    pub original_event_id: Option<String>,
    pub original_content: String,
    pub proposed_content: String,
    pub before_tags: Vec<OnboardingRelayTagFfi>,
    pub after_tags: Vec<OnboardingRelayTagFfi>,
    pub changes: Vec<OnboardingRelayTagChangeFfi>,
}
impl From<marmot_app::OnboardingRelayRepair> for OnboardingRelayRepairFfi {
    fn from(value: marmot_app::OnboardingRelayRepair) -> Self {
        Self {
            mode: value.mode.into(),
            original_event_id: value.original_event_id,
            original_content: value.original_content,
            proposed_content: value.proposed_content,
            before_tags: value.before_tags.into_iter().map(Into::into).collect(),
            after_tags: value.after_tags.into_iter().map(Into::into).collect(),
            changes: value.changes.into_iter().map(Into::into).collect(),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingRepairProposalFfi {
    pub step: OnboardingStepFfi,
    pub revision: u64,
    pub previous_event_id: Option<String>,
    pub read_relays: Vec<String>,
    pub write_relays: Vec<String>,
    pub profile: Option<UserProfileMetadataFfi>,
    pub follows: Option<Vec<String>>,
    pub relay_repair: Option<OnboardingRelayRepairFfi>,
}
impl From<marmot_app::OnboardingRepairProposal> for OnboardingRepairProposalFfi {
    fn from(value: marmot_app::OnboardingRepairProposal) -> Self {
        Self {
            step: value.step.into(),
            revision: value.revision,
            previous_event_id: value.previous_event_id,
            read_relays: value.read_relays,
            write_relays: value.write_relays,
            profile: value.profile.map(Into::into),
            follows: value.follows,
            relay_repair: value.relay_repair.map(Into::into),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingSnapshotFfi {
    pub account_id_hex: String,
    pub recovery_epoch: Option<String>,
    pub revision: u64,
    pub ready: bool,
    pub steps: Vec<OnboardingStepStateFfi>,
    pub proposal: Option<OnboardingRepairProposalFfi>,
    pub single_device_notice: Option<OnboardingSingleDeviceNoticeFfi>,
    pub cancellation_pending: bool,
}
impl From<marmot_app::OnboardingSnapshot> for OnboardingSnapshotFfi {
    fn from(value: marmot_app::OnboardingSnapshot) -> Self {
        Self {
            account_id_hex: value.account_id_hex,
            recovery_epoch: value.recovery_epoch,
            revision: value.revision,
            ready: value.ready,
            steps: value.steps.into_iter().map(Into::into).collect(),
            single_device_notice: value.single_device_notice.map(Into::into),
            cancellation_pending: value.cancellation_pending,
            proposal: value.proposal.map(Into::into),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingOptionsFfi {
    pub default_relays: Vec<String>,
    pub discovery_relays: Vec<String>,
}
impl From<marmot_app::OnboardingOptions> for OnboardingOptionsFfi {
    fn from(value: marmot_app::OnboardingOptions) -> Self {
        Self {
            default_relays: value.default_relays,
            discovery_relays: value.discovery_relays,
        }
    }
}
impl From<OnboardingOptionsFfi> for marmot_app::OnboardingOptions {
    fn from(value: OnboardingOptionsFfi) -> Self {
        Self {
            default_relays: value.default_relays,
            discovery_relays: value.discovery_relays,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum OnboardingDeviceDiscoveryFfi {
    NoneFound,
    OtherInstallationPossible,
    Unknown,
}
impl From<marmot_app::OnboardingDeviceDiscovery> for OnboardingDeviceDiscoveryFfi {
    fn from(value: marmot_app::OnboardingDeviceDiscovery) -> Self {
        match value {
            marmot_app::OnboardingDeviceDiscovery::NoneFound => Self::NoneFound,
            marmot_app::OnboardingDeviceDiscovery::OtherInstallationPossible => {
                Self::OtherInstallationPossible
            }
            marmot_app::OnboardingDeviceDiscovery::Unknown => Self::Unknown,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingDevicePackageFfi {
    pub slot_id: String,
    pub key_package_ref_hex: Option<String>,
    pub event_id_hex: String,
    pub published_at: u64,
    pub expires_at: Option<u64>,
    pub usable: bool,
}
impl From<marmot_app::OnboardingDevicePackage> for OnboardingDevicePackageFfi {
    fn from(value: marmot_app::OnboardingDevicePackage) -> Self {
        Self {
            slot_id: value.slot_id,
            key_package_ref_hex: value.key_package_ref_hex,
            event_id_hex: value.event_id_hex,
            published_at: value.published_at,
            expires_at: value.expires_at,
            usable: value.usable,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingSingleDeviceNoticeFfi {
    pub discovery: OnboardingDeviceDiscoveryFfi,
    pub other_packages: Vec<OnboardingDevicePackageFfi>,
    pub discovery_complete: bool,
    pub acknowledged_at: Option<u64>,
}
impl From<marmot_app::OnboardingSingleDeviceNotice> for OnboardingSingleDeviceNoticeFfi {
    fn from(value: marmot_app::OnboardingSingleDeviceNotice) -> Self {
        Self {
            discovery: value.discovery.into(),
            other_packages: value.other_packages.into_iter().map(Into::into).collect(),
            discovery_complete: value.discovery_complete,
            acknowledged_at: value.acknowledged_at,
        }
    }
}

#[cfg(test)]
mod relay_repair_tests {
    use super::*;

    #[test]
    fn typed_relay_repair_projects_exact_source_diff_and_manual_mode() {
        let before = marmot_app::OnboardingRelayTag {
            fields: vec!["r".into(), "wss://retired.example".into(), "read".into()],
            endpoint: Some("wss://retired.example".into()),
            role: marmot_app::OnboardingRelayTagRole::Read,
        };
        let after = marmot_app::OnboardingRelayTag {
            fields: vec!["r".into(), "wss://safe.example".into(), "read".into()],
            endpoint: Some("wss://safe.example".into()),
            role: marmot_app::OnboardingRelayTagRole::Read,
        };
        let input = marmot_app::OnboardingRelayRepair {
            mode: marmot_app::OnboardingRelayRepairMode::RemovalAndAdditive,
            original_event_id: Some("source-id".into()),
            original_content: "opaque".into(),
            proposed_content: "opaque".into(),
            before_tags: vec![before.clone()],
            after_tags: vec![after.clone()],
            changes: vec![marmot_app::OnboardingRelayTagChange {
                disposition: marmot_app::OnboardingRelayTagDisposition::Added,
                before_index: None,
                after_index: Some(0),
                fields: after.fields.clone(),
                endpoint: after.endpoint.clone(),
                role: after.role,
                restores: marmot_app::OnboardingRelayCapability::Read,
            }],
        };
        let projected: OnboardingRelayRepairFfi = input.into();
        assert_eq!(
            projected.mode,
            OnboardingRelayRepairModeFfi::RemovalAndAdditive
        );
        assert_eq!(projected.original_event_id.as_deref(), Some("source-id"));
        assert_eq!(projected.original_content, "opaque");
        assert_eq!(projected.proposed_content, "opaque");
        assert_eq!(projected.before_tags[0].fields, before.fields);
        assert_eq!(
            projected.before_tags[0].role,
            OnboardingRelayTagRoleFfi::Read
        );
        assert_eq!(projected.after_tags[0].fields, after.fields);
        assert_eq!(
            projected.changes[0].disposition,
            OnboardingRelayTagDispositionFfi::Added
        );
        assert_eq!(projected.changes[0].after_index, Some(0));
        assert_eq!(
            projected.changes[0].restores,
            OnboardingRelayCapabilityFfi::Read
        );
        assert_eq!(
            OnboardingRelayRepairModeFfi::from(marmot_app::OnboardingRelayRepairMode::ManualReview),
            OnboardingRelayRepairModeFfi::ManualReview
        );
    }
}
