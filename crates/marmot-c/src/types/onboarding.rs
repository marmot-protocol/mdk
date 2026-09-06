//! C mirrors of the durable onboarding contract.
use super::account::MarmotUserProfileMetadata;
use super::common::MarmotStringList;
use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::conversions::*;
c_enum! { MarmotOnboardingStep from OnboardingStepFfi {  Profile, Follows, Relays, InboxRelays, SingleDevice, KeyPackage  } }
impl MarmotOnboardingStep {
    pub(crate) fn to_ffi(self) -> OnboardingStepFfi {
        match self {
            Self::Profile => OnboardingStepFfi::Profile,
            Self::Follows => OnboardingStepFfi::Follows,
            Self::Relays => OnboardingStepFfi::Relays,
            Self::InboxRelays => OnboardingStepFfi::InboxRelays,
            Self::SingleDevice => OnboardingStepFfi::SingleDevice,
            Self::KeyPackage => OnboardingStepFfi::KeyPackage,
        }
    }
}
c_enum! { MarmotOnboardingStatus from OnboardingStatusFfi {  Pending, Checking, Passed, NeedsInput, RetryableFailure, WaitingForSigner, Skipped  } }
c_enum! { MarmotOnboardingIssue from OnboardingIssueFfi {  Missing, Malformed, FutureDated, InvalidRelay, RetiredRelay, UnsafeRelay, Unreachable, TimedOut, AuthenticationRequired, PaymentRequired, AccessRestricted, NoUsableRoute, PublicationFailed, SignerUnavailable, SignerRejected, RecordChanged, Interrupted, TooManyRelays, MultiDeviceUnsupported, OtherInstallationPossible, DiscoveryIncomplete  } }
c_enum! { MarmotOnboardingAction from OnboardingActionFfi {  Retry, ContinueWithout, UseRecommendedRelays, EditRelays, EditProfile, EditFollows, ApproveRepair, CancelRepair, ReconnectSigner, EditDiscoveryRelays, ContinueAnyway, CancelOnboarding  } }
c_mirror! { MarmotOnboardingFinding from OnboardingFindingFfi { copy issue: MarmotOnboardingIssue, opt_str endpoint, } }
c_mirror! { MarmotOnboardingStepState from OnboardingStepStateFfi { copy step: MarmotOnboardingStep, copy status: MarmotOnboardingStatus, vec findings/findings_len: MarmotOnboardingFinding, vec actions/actions_len: MarmotOnboardingAction, opt_copy has_checked_at/checked_at: u64, } }
c_mirror! { MarmotOnboardingRepairProposal from OnboardingRepairProposalFfi { copy step: MarmotOnboardingStep, copy revision: u64, opt_str previous_event_id, str_vec read_relays/read_relays_len, str_vec write_relays/write_relays_len, opt_rec profile: MarmotUserProfileMetadata, opt_rec follows: MarmotStringList, } }
c_mirror! { MarmotOnboardingSnapshot from OnboardingSnapshotFfi, free marmot_onboarding_snapshot_free { str account_id_hex, copy revision: u64, copy ready: bool, vec steps/steps_len: MarmotOnboardingStepState, opt_rec proposal: MarmotOnboardingRepairProposal, opt_rec single_device_notice: MarmotOnboardingSingleDeviceNotice, copy cancellation_pending: bool, } }

c_enum! { MarmotOnboardingDeviceDiscovery from OnboardingDeviceDiscoveryFfi { NoneFound, OtherInstallationPossible, Unknown } }
c_mirror! { MarmotOnboardingDevicePackage from OnboardingDevicePackageFfi { str slot_id, opt_str key_package_ref_hex, str event_id_hex, copy published_at: u64, opt_copy has_expires_at/expires_at: u64, copy usable: bool, } }
c_mirror! { MarmotOnboardingSingleDeviceNotice from OnboardingSingleDeviceNoticeFfi { copy discovery: MarmotOnboardingDeviceDiscovery, vec other_packages/other_packages_len: MarmotOnboardingDevicePackage, copy discovery_complete: bool, opt_copy has_acknowledged_at/acknowledged_at: u64, } }

#[cfg(all(test, feature = "alloc-audit"))]
mod tests {
    use super::*;
    use crate::memory::{audit, boxed, free_boxed};
    #[test]
    fn onboarding_snapshot_deep_free_releases_nested_proposal_and_actions() {
        let _guard = audit::test_lock();
        let before = audit::live_allocations();
        let ffi = OnboardingSnapshotFfi {
            account_id_hex: "account".into(),
            revision: 4,
            ready: false,
            cancellation_pending: false,
            steps: vec![OnboardingStepStateFfi {
                step: OnboardingStepFfi::Follows,
                status: OnboardingStatusFfi::NeedsInput,
                findings: vec![OnboardingFindingFfi {
                    issue: OnboardingIssueFfi::Malformed,
                    endpoint: Some("wss://example.com".into()),
                }],
                actions: vec![OnboardingActionFfi::ApproveRepair],
                checked_at: Some(42),
            }],
            single_device_notice: Some(OnboardingSingleDeviceNoticeFfi {
                discovery: OnboardingDeviceDiscoveryFfi::OtherInstallationPossible,
                other_packages: vec![OnboardingDevicePackageFfi {
                    slot_id: "slot".into(),
                    key_package_ref_hex: Some("ref".into()),
                    event_id_hex: "event".into(),
                    published_at: 40,
                    expires_at: Some(90),
                    usable: true,
                }],
                discovery_complete: false,
                acknowledged_at: Some(42),
            }),
            proposal: Some(OnboardingRepairProposalFfi {
                step: OnboardingStepFfi::Follows,
                revision: 4,
                previous_event_id: Some("previous".into()),
                read_relays: vec!["wss://example.com".into()],
                write_relays: vec![],
                profile: Some(UserProfileMetadataFfi {
                    name: Some("name".into()),
                    display_name: None,
                    about: None,
                    picture: None,
                    banner: None,
                    nip05: None,
                    lud16: None,
                }),
                follows: Some(vec!["follow".into()]),
            }),
        };
        let value = boxed(MarmotOnboardingSnapshot::from(ffi));
        assert!(audit::live_allocations() > before);
        unsafe {
            free_boxed(value);
        }
        assert_eq!(audit::live_allocations(), before);
    }
    #[test]
    fn onboarding_step_input_rejects_invalid_discriminants() {
        assert!(MarmotOnboardingStep::from_c(u32::MAX).is_err());
        assert_eq!(
            MarmotOnboardingStep::from_c(5).unwrap().to_ffi(),
            OnboardingStepFfi::KeyPackage
        );
    }
}
