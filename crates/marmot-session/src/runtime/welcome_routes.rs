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
//!
//! Each paced attempt that finds no route also owes the host one lookup of
//! the recipient's inbox list ([`AccountDeviceRuntime::take_due_welcome_route_lookups`]).
//! The host runs it, installs what it found in its routing policy, and, when
//! that gives a route, releases the recipient's retry
//! ([`AccountDeviceRuntime::release_welcome_route_retry`]), so the next pass
//! sends the Welcome. A lookup that finds nothing usable leaves the pacing as
//! it was. Route discovery stays with the host: the runtime only says whom to
//! look up.

use super::*;
use crate::routing::{MissingInboxRouteCause, TransportRoutingError};
use crate::session::OutboundWelcomeStatus;

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
    /// The host owes a lookup of the recipient's inbox list, for the paced
    /// attempt that last failed.
    lookup_due: bool,
}

impl WelcomeRouteRetries {
    /// A publish to `recipient` found no route at `now`. Only a failure once
    /// the retry is due moves it, so the recipient's other Welcomes failing
    /// in the same pass, or an explicit publish in between, do not.
    fn failed(&mut self, recipient: &MemberId, now: Timestamp) {
        let retry = self.0.entry(recipient.clone()).or_insert(RouteRetry {
            failures: 0,
            retry_at: now,
            lookup_due: false,
        });
        if retry.retry_at > now {
            return;
        }
        retry.failures = retry.failures.saturating_add(1);
        retry.retry_at = Timestamp(now.0.saturating_add(route_retry_delay_secs(retry.failures)));
        retry.lookup_due = true;
    }

    /// Whether any recipient's lookup is owed.
    fn lookup_owed(&self) -> bool {
        self.0.values().any(|retry| retry.lookup_due)
    }

    /// Take up to `limit` owed lookups of recipients `take` accepts.
    fn take_lookups(
        &mut self,
        limit: usize,
        mut take: impl FnMut(&MemberId) -> bool,
    ) -> Vec<MemberId> {
        let mut taken = Vec::new();
        for (recipient, retry) in &mut self.0 {
            if taken.len() == limit {
                break;
            }
            if retry.lookup_due && take(recipient) {
                retry.lookup_due = false;
                taken.push(recipient.clone());
            }
        }
        taken
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
/// eligible route; one whose list is unknown, or could not be looked up,
/// could not be resolved.
pub(super) fn route_not_started_reason(
    error: &TransportRoutingError,
) -> audit_v5::NotStartedReason {
    match error {
        TransportRoutingError::MissingInboxRoute(
            MissingInboxRouteCause::EmptyList | MissingInboxRouteCause::NoneUsable,
        ) => audit_v5::NotStartedReason::NoEligibleRoute,
        TransportRoutingError::MissingInboxRoute(
            MissingInboxRouteCause::NoList | MissingInboxRouteCause::LookupFailed,
        )
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
        let mut retries = self.lock_welcome_route_retries();
        match routed {
            Ok(()) => retries.routed(&recipient),
            Err(_) => retries.failed(&recipient, self.wall_clock.now()),
        }
    }

    /// Whether maintenance leaves `message`, an owed Welcome, alone this pass
    /// because its recipient's route retry is not due yet.
    pub(super) fn welcome_route_retry_holds(&self, message: &TransportMessage) -> bool {
        welcome_recipient(message).is_some_and(|recipient| {
            self.lock_welcome_route_retries()
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

    /// The recipients whose inbox list the host should look up now: at most
    /// `limit` of those whose last paced Welcome publish found no route, that
    /// `take` accepts (a host skips one it is already looking up), and that
    /// an owed Welcome is still addressed to. Each is taken once per paced
    /// attempt; one `take` refuses stays owed. A Welcome that is withdrawn,
    /// expired, delivered or still staged with its commit is not owed, so
    /// nobody is looked up for it.
    pub fn take_due_welcome_route_lookups(
        &self,
        limit: usize,
        take: impl FnMut(&MemberId) -> bool,
    ) -> AccountResult<Vec<MemberId>> {
        if limit == 0 || !self.lock_welcome_route_retries().lookup_owed() {
            return Ok(Vec::new());
        }
        let now = self.wall_clock.now();
        let mut owed = HashSet::new();
        for id in &self.watched_welcomes {
            if let OutboundWelcomeStatus::Owed { message, .. } =
                self.session.outbound_welcome_status(id, now)?
                && let Some(recipient) = welcome_recipient(&message)
            {
                owed.insert(recipient);
            }
        }
        let mut retries = self.lock_welcome_route_retries();
        retries.retain(&owed);
        Ok(retries.take_lookups(limit, take))
    }

    /// The host installed a route to `recipient` in its routing policy: end
    /// its pacing, so the next maintenance pass sends its owed Welcomes.
    pub fn release_welcome_route_retry(&self, recipient: &MemberId) {
        self.lock_welcome_route_retries().routed(recipient);
    }

    fn lock_welcome_route_retries(&self) -> std::sync::MutexGuard<'_, WelcomeRouteRetries> {
        self.welcome_route_retries
            .lock()
            .unwrap_or_else(|error| error.into_inner())
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
            [NoList, EmptyList, NoneUsable, LookupFailed].map(reason),
            [
                audit_v5::NotStartedReason::RouteResolutionFailed,
                audit_v5::NotStartedReason::NoEligibleRoute,
                audit_v5::NotStartedReason::NoEligibleRoute,
                audit_v5::NotStartedReason::RouteResolutionFailed,
            ]
        );
        assert_eq!(
            route_not_started_reason(&TransportRoutingError::MissingGroupRoute),
            audit_v5::NotStartedReason::RouteResolutionFailed
        );
    }
}
