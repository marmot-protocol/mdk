//! Welcomes whose recipient has no inbox route (mdk#2261).
//!
//! A publish that finds no route stores no retry record, so maintenance would
//! prepare the Welcome again, and record another failure, on every pass. The
//! runtime instead paces each such recipient: maintenance leaves its owed
//! Welcomes alone until its next retry, 10 minutes after the first failure,
//! doubling, at most 6 hours. Each retry asks the routing policy again, so a
//! route the host has installed since is used. Explicit publishes (a host's
//! owed Welcomes, the startup pass, a redelivery) are not held. The pacing is
//! in memory, so a new runtime starts with none: a restart allows one fresh
//! attempt.

use super::*;
use crate::routing::{MissingInboxRouteCause, TransportRoutingError};

/// The wait after a recipient's first publish that found no route.
const FIRST_ROUTE_RETRY_SECS: u64 = 10 * 60;
/// The longest wait between two route retries.
const MAX_ROUTE_RETRY_SECS: u64 = 6 * 60 * 60;

/// Each recipient whose last Welcome publish found no route, with when
/// maintenance next retries it.
#[derive(Debug, Default)]
pub(super) struct WelcomeRouteRetries(HashMap<MemberId, RouteRetry>);

#[derive(Debug)]
struct RouteRetry {
    failures: u32,
    retry_at: Timestamp,
}

impl WelcomeRouteRetries {
    /// A publish to `recipient` found no route at `now`. Only a failure once
    /// the retry is due moves it, so the recipient's other Welcomes failing
    /// in the same pass, or an explicit publish in between, do not.
    fn failed(&mut self, recipient: &MemberId, now: Timestamp) {
        let retry = self.0.entry(recipient.clone()).or_insert(RouteRetry {
            failures: 0,
            retry_at: now,
        });
        if retry.retry_at > now {
            return;
        }
        retry.failures = retry.failures.saturating_add(1);
        retry.retry_at = Timestamp(now.0.saturating_add(route_retry_delay_secs(retry.failures)));
    }

    /// A publish to `recipient` found a route.
    fn routed(&mut self, recipient: &MemberId) {
        self.0.remove(recipient);
    }

    /// Whether maintenance leaves `recipient`'s owed Welcomes alone at `now`.
    fn holds(&self, recipient: &MemberId, now: Timestamp) -> bool {
        self.0
            .get(recipient)
            .is_some_and(|retry| retry.retry_at > now)
    }

    /// Forget every recipient no owed Welcome is addressed to.
    fn retain(&mut self, owed: &HashSet<MemberId>) {
        self.0.retain(|recipient, _| owed.contains(recipient));
    }
}

/// The wait after a recipient's `failures`th publish in a row that found no
/// route: 10 minutes, doubling, at most 6 hours.
fn route_retry_delay_secs(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    FIRST_ROUTE_RETRY_SECS
        .saturating_mul(1 << doublings)
        .min(MAX_ROUTE_RETRY_SECS)
}

/// The v5 `welcome_publish_not_started` reason for a routing failure: a
/// recipient whose list is known and gives nothing to send to has no
/// eligible route; one whose list is unknown could not be resolved.
pub(super) fn route_not_started_reason(
    error: &TransportRoutingError,
) -> audit_v5::NotStartedReason {
    match error {
        TransportRoutingError::MissingInboxRoute(
            MissingInboxRouteCause::EmptyList | MissingInboxRouteCause::NoneUsable,
        ) => audit_v5::NotStartedReason::NoEligibleRoute,
        TransportRoutingError::MissingInboxRoute(MissingInboxRouteCause::NoList)
        | TransportRoutingError::MissingGroupRoute => {
            audit_v5::NotStartedReason::RouteResolutionFailed
        }
    }
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Note what routing `message` found, for a Welcome: a route ends its
    /// recipient's pacing, and a failure paces it.
    pub(super) fn note_welcome_route(
        &self,
        message: &TransportMessage,
        routed: Result<(), &TransportRoutingError>,
    ) {
        let Some(recipient) = welcome_recipient(message) else {
            return;
        };
        let mut retries = self
            .welcome_route_retries
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match routed {
            Ok(()) => retries.routed(&recipient),
            Err(_) => retries.failed(&recipient, self.wall_clock.now()),
        }
    }

    /// Whether maintenance leaves `message`, an owed Welcome, alone this pass
    /// because its recipient's route retry is not due yet.
    pub(super) fn welcome_route_retry_holds(&self, message: &TransportMessage) -> bool {
        welcome_recipient(message).is_some_and(|recipient| {
            self.welcome_route_retries
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .holds(&recipient, self.wall_clock.now())
        })
    }

    /// Forget the pacing of every recipient no owed Welcome is addressed to.
    pub(super) fn retain_welcome_route_retries(&mut self, owed: &HashSet<MemberId>) {
        self.welcome_route_retries
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .retain(owed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_retries_wait_ten_minutes_then_double_to_six_hours() {
        let delays = (1..=8).map(route_retry_delay_secs).collect::<Vec<_>>();
        assert_eq!(
            delays,
            [600, 1_200, 2_400, 4_800, 9_600, 19_200, 21_600, 21_600]
        );
        assert_eq!(route_retry_delay_secs(u32::MAX), MAX_ROUTE_RETRY_SECS);
    }

    #[test]
    fn a_recipient_is_paced_once_per_round() {
        let recipient = MemberId::new(vec![1; 32]);
        let mut retries = WelcomeRouteRetries::default();
        retries.failed(&recipient, Timestamp(1_000));
        // Its other Welcome failing in the same pass leaves the round alone.
        retries.failed(&recipient, Timestamp(1_000));
        assert!(retries.holds(&recipient, Timestamp(1_599)));
        assert!(!retries.holds(&recipient, Timestamp(1_600)));
        retries.failed(&recipient, Timestamp(1_600));
        assert!(retries.holds(&recipient, Timestamp(2_799)));
        assert!(!retries.holds(&recipient, Timestamp(2_800)));
        retries.routed(&recipient);
        assert!(!retries.holds(&recipient, Timestamp(1_600)));
    }

    #[test]
    fn route_causes_map_to_the_existing_not_started_reasons() {
        use MissingInboxRouteCause::*;
        let reason =
            |cause| route_not_started_reason(&TransportRoutingError::MissingInboxRoute(cause));
        assert_eq!(
            [NoList, EmptyList, NoneUsable].map(reason),
            [
                audit_v5::NotStartedReason::RouteResolutionFailed,
                audit_v5::NotStartedReason::NoEligibleRoute,
                audit_v5::NotStartedReason::NoEligibleRoute,
            ]
        );
        assert_eq!(
            route_not_started_reason(&TransportRoutingError::MissingGroupRoute),
            audit_v5::NotStartedReason::RouteResolutionFailed
        );
    }
}
