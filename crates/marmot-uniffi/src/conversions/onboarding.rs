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
#[derive(Clone, Debug, uniffi::Record)]
pub struct OnboardingRepairProposalFfi {
    pub step: OnboardingStepFfi,
    pub revision: u64,
    pub previous_event_id: Option<String>,
    pub read_relays: Vec<String>,
    pub write_relays: Vec<String>,
    pub profile: Option<UserProfileMetadataFfi>,
    pub follows: Option<Vec<String>>,
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
