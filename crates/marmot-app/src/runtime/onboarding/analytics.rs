//! Usage-diagnostics observation of interactive onboarding (mdk#3440): which step an attempt
//! stopped at and why, as catalogue labels only.
//!
//! A pause is a persisted step in a blocking status. Each distinct (step, status, primary issue)
//! is counted at most once per attempt: the checkpoint keeps the keys it reported, so retries,
//! re-runs and restarts that land on the same pause add nothing. Endpoints never leave this
//! module; only how many distinct sources failed does, and the collector buckets it.
use super::*;
use marmot_observability::OnboardingPause;

/// One reported pause, kept in the checkpoint for the rest of its attempt.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct OnboardingPauseKey {
    step: OnboardingStep,
    status: OnboardingStatus,
    issue: Option<OnboardingIssue>,
}

/// The pause a persisted step shows, if it stopped in a blocking status.
pub(super) fn onboarding_pause(
    state: &OnboardingStepState,
) -> Option<(OnboardingPauseKey, OnboardingPause)> {
    let status = match state.status {
        OnboardingStatus::NeedsInput => "needs_input",
        OnboardingStatus::RetryableFailure => "retryable_failure",
        // Without a finding this is the signer request in flight, not a pause.
        OnboardingStatus::WaitingForSigner if !state.findings.is_empty() => "waiting_for_signer",
        OnboardingStatus::WaitingForSigner
        | OnboardingStatus::Pending
        | OnboardingStatus::Checking
        | OnboardingStatus::Passed
        | OnboardingStatus::Skipped => return None,
    };
    let failing = |finding: &&OnboardingFinding| {
        finding.outcome != OnboardingCheckOutcome::Success
            && finding.issue != OnboardingIssue::InspectionCompleted
    };
    let sources: Vec<_> = state
        .findings
        .iter()
        .filter(failing)
        .filter(|finding| finding.endpoint.is_some())
        .collect();
    // Sources answer concurrently, so their findings arrive in any order. Every
    // choice ranks by catalogue order instead, keeping a pause's key stable
    // across retries: the most common source issue, catalogue order breaking a
    // tie; then the step-level finding earliest in catalogue order, which puts
    // advisory discovery findings last; else a finding with the source issue.
    let source_issue = sources
        .iter()
        .map(|finding| finding.issue)
        .max_by_key(|issue| {
            let count = sources.iter().filter(|f| f.issue == *issue).count();
            (count, std::cmp::Reverse(*issue as u8))
        });
    let rank = |finding: &&OnboardingFinding| (finding.issue as u8, finding.context as u8);
    let primary = state
        .findings
        .iter()
        .filter(failing)
        .filter(|finding| finding.endpoint.is_none())
        .min_by_key(rank)
        .or_else(|| {
            sources
                .iter()
                .copied()
                .filter(|finding| Some(finding.issue) == source_issue)
                .min_by_key(rank)
        });
    let failing_sources = sources
        .iter()
        .filter_map(|finding| finding.endpoint.as_deref())
        .collect::<HashSet<_>>()
        .len();
    Some((
        OnboardingPauseKey {
            step: state.step,
            status: state.status,
            issue: primary.map(|finding| finding.issue),
        },
        OnboardingPause {
            step: step_label(state.step),
            status,
            issue: primary.map_or("none", |finding| issue_label(finding.issue)),
            source_issue: source_issue.map_or("none", issue_label),
            context: context_label(
                primary.map_or_else(Default::default, |finding| finding.context),
            ),
            failing_sources: failing_sources as u64,
        },
    ))
}

fn step_label(step: OnboardingStep) -> &'static str {
    match step {
        OnboardingStep::Profile => "profile",
        OnboardingStep::Follows => "follows",
        OnboardingStep::Relays => "relays",
        OnboardingStep::InboxRelays => "inbox_relays",
        OnboardingStep::SingleDevice => "single_device",
        OnboardingStep::KeyPackage => "key_package",
    }
}

fn issue_label(issue: OnboardingIssue) -> &'static str {
    match issue {
        OnboardingIssue::Missing => "missing",
        OnboardingIssue::Malformed => "malformed",
        OnboardingIssue::FutureDated => "future_dated",
        OnboardingIssue::InvalidRelay => "invalid_relay",
        OnboardingIssue::RetiredRelay => "retired_relay",
        OnboardingIssue::UnsafeRelay => "unsafe_relay",
        OnboardingIssue::Unreachable => "unreachable",
        OnboardingIssue::TimedOut => "timed_out",
        OnboardingIssue::RateLimited => "rate_limited",
        OnboardingIssue::AuthenticationRequired => "authentication_required",
        OnboardingIssue::PaymentRequired => "payment_required",
        OnboardingIssue::AccessRestricted => "access_restricted",
        OnboardingIssue::NoUsableRoute => "no_usable_route",
        OnboardingIssue::PublicationFailed => "publication_failed",
        OnboardingIssue::SignerUnavailable => "signer_unavailable",
        OnboardingIssue::SignerRejected => "signer_rejected",
        OnboardingIssue::RecordChanged => "record_changed",
        OnboardingIssue::Interrupted => "interrupted",
        OnboardingIssue::TooManyRelays => "too_many_relays",
        OnboardingIssue::MultiDeviceUnsupported => "multi_device_unsupported",
        OnboardingIssue::OtherInstallationPossible => "other_installation_possible",
        OnboardingIssue::DiscoveryIncomplete => "discovery_incomplete",
        // A completed check, never a pause's issue; the collector rejects it.
        OnboardingIssue::InspectionCompleted => "inspection_completed",
    }
}

fn context_label(context: OnboardingFindingContext) -> &'static str {
    match context {
        OnboardingFindingContext::Unknown => "unknown",
        OnboardingFindingContext::RecordDiscovery => "record_discovery",
        OnboardingFindingContext::PublishedDeclaration => "published_declaration",
        OnboardingFindingContext::DeclaredRoute => "declared_route",
        OnboardingFindingContext::RepairApproval => "repair_approval",
        OnboardingFindingContext::RepairPublication => "repair_publication",
    }
}

impl OnboardingCheckpoint {
    /// The pauses its attempt has not reported, recorded as reported: those this snapshot shows,
    /// and those `previous` (this attempt's last save) showed, since a save that retries, skips
    /// or rechecks a step clears the pause it was stopped at. The caller records them once the
    /// checkpoint is saved, or forgets them if the save fails. A cancelling save still counts the
    /// step it was stopped at.
    pub(super) fn take_unreported_pauses(
        &mut self,
        previous: Option<&OnboardingCheckpoint>,
    ) -> Vec<OnboardingPause> {
        let previous = previous.filter(|previous| previous.attempt() == self.attempt());
        for key in previous
            .iter()
            .flat_map(|previous| &previous.reported_pauses)
        {
            if !self.reported_pauses.contains(key) {
                self.reported_pauses.push(*key);
            }
        }
        let mut pauses = Vec::new();
        let shown = previous
            .iter()
            .flat_map(|previous| &previous.snapshot.steps)
            .chain(&self.snapshot.steps);
        for (key, pause) in shown.filter_map(onboarding_pause) {
            if !self.reported_pauses.contains(&key) {
                self.reported_pauses.push(key);
                pauses.push(pause);
            }
        }
        pauses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(status: OnboardingStatus, findings: Vec<OnboardingFinding>) -> OnboardingStepState {
        OnboardingStepState {
            step: OnboardingStep::Relays,
            status,
            findings,
            actions: Vec::new(),
            checked_at: None,
        }
    }
    fn at(
        issue: OnboardingIssue,
        endpoint: &str,
        context: OnboardingFindingContext,
    ) -> OnboardingFinding {
        OnboardingFinding {
            endpoint: Some(endpoint.into()),
            ..finding(issue).in_context(context, OnboardingCheckPurpose::DirectoryQuery)
        }
    }

    #[test]
    fn a_pause_reports_the_step_verdict_and_counts_its_failing_sources() {
        use OnboardingFindingContext::{DeclaredRoute, PublishedDeclaration, RecordDiscovery};
        use OnboardingIssue::*;
        let (key, pause) = onboarding_pause(&state(
            OnboardingStatus::RetryableFailure,
            vec![
                at(InvalidRelay, "wss://a.example", PublishedDeclaration),
                at(Unreachable, "wss://b.example", DeclaredRoute),
                at(TimedOut, "wss://c.example", DeclaredRoute),
                at(TimedOut, "wss://b.example", RecordDiscovery),
                at(InspectionCompleted, "wss://d.example", DeclaredRoute),
                finding(NoUsableRoute)
                    .in_context(DeclaredRoute, OnboardingCheckPurpose::DirectoryQuery),
                finding(DiscoveryIncomplete)
                    .in_context(RecordDiscovery, OnboardingCheckPurpose::RecordLookup),
            ],
        ))
        .unwrap();
        assert_eq!(key.issue, Some(NoUsableRoute));
        assert_eq!(
            pause,
            OnboardingPause {
                step: "relays",
                status: "retryable_failure",
                issue: "no_usable_route",
                source_issue: "timed_out",
                context: "declared_route",
                failing_sources: 3,
            }
        );
    }

    #[test]
    fn without_a_step_verdict_the_most_common_source_issue_is_primary() {
        use OnboardingIssue::*;
        let (_, pause) = onboarding_pause(&state(
            OnboardingStatus::RetryableFailure,
            vec![
                at(
                    Unreachable,
                    "wss://a.example",
                    OnboardingFindingContext::RecordDiscovery,
                ),
                at(
                    TimedOut,
                    "wss://b.example",
                    OnboardingFindingContext::DeclaredRoute,
                ),
            ],
        ))
        .unwrap();
        assert_eq!(
            (pause.issue, pause.source_issue, pause.context),
            ("unreachable", "unreachable", "record_discovery")
        );
    }

    #[test]
    fn the_order_sources_answer_in_does_not_change_the_pause() {
        use OnboardingFindingContext::{DeclaredRoute, RecordDiscovery};
        use OnboardingIssue::*;
        let findings = vec![
            at(AuthenticationRequired, "wss://a.example", DeclaredRoute),
            at(Unreachable, "wss://b.example", RecordDiscovery),
            at(Unreachable, "wss://c.example", DeclaredRoute),
            at(AuthenticationRequired, "wss://d.example", RecordDiscovery),
            finding(DiscoveryIncomplete)
                .in_context(RecordDiscovery, OnboardingCheckPurpose::RecordLookup),
            finding(TooManyRelays),
        ];
        let forward =
            onboarding_pause(&state(OnboardingStatus::RetryableFailure, findings.clone()));
        let mut reversed = findings;
        reversed.reverse();
        assert_eq!(
            onboarding_pause(&state(OnboardingStatus::RetryableFailure, reversed)),
            forward
        );
        let (_, pause) = forward.unwrap();
        assert_eq!(
            (pause.issue, pause.source_issue, pause.context),
            ("too_many_relays", "unreachable", "unknown")
        );
        let (_, sources_only) = onboarding_pause(&state(
            OnboardingStatus::RetryableFailure,
            vec![
                at(AuthenticationRequired, "wss://a.example", DeclaredRoute),
                at(Unreachable, "wss://b.example", DeclaredRoute),
                at(Unreachable, "wss://c.example", RecordDiscovery),
            ],
        ))
        .unwrap();
        assert_eq!(
            (sources_only.issue, sources_only.context),
            ("unreachable", "record_discovery")
        );
    }

    #[test]
    fn only_blocking_steps_with_a_reason_to_wait_are_pauses() {
        for status in [
            OnboardingStatus::Pending,
            OnboardingStatus::Checking,
            OnboardingStatus::Passed,
            OnboardingStatus::Skipped,
            // The signer request in flight.
            OnboardingStatus::WaitingForSigner,
        ] {
            assert_eq!(onboarding_pause(&state(status, Vec::new())), None);
        }
        let (_, pause) = onboarding_pause(&state(
            OnboardingStatus::WaitingForSigner,
            vec![finding(OnboardingIssue::SignerUnavailable)],
        ))
        .unwrap();
        assert_eq!(
            (
                pause.status,
                pause.issue,
                pause.context,
                pause.failing_sources
            ),
            ("waiting_for_signer", "signer_unavailable", "unknown", 0)
        );
    }
}
