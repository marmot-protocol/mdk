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
//! the recipient's inbox list ([`AccountDeviceRuntime::plan_welcome_route_lookups`]),
//! which also names the lookups the host should stop because no owed Welcome
//! is addressed to their recipient any more. The host runs each lookup,
//! installs what it found in its routing policy, and reports the outcome
//! ([`AccountDeviceRuntime::finish_welcome_route_lookup`]). A route releases
//! the recipient's retry, so the next pass sends the Welcome. A lookup that
//! finds nothing usable leaves the pacing as it was, and its outcome is the
//! route-less Welcomes' delivery problem at once: `InboxLookupFailed` after a
//! failed lookup, until a later lookup answers. Route discovery stays with the
//! host: the runtime only says whom to look up.

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
    /// The host's last lookup of the recipient's inbox list failed.
    lookup_failed: bool,
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
            lookup_failed: false,
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

    /// Take up to `limit` owed lookups of recipients not in `running`.
    fn take_lookups(&mut self, limit: usize, running: &[MemberId]) -> Vec<MemberId> {
        let mut taken = Vec::new();
        for (recipient, retry) in &mut self.0 {
            if taken.len() == limit {
                break;
            }
            if retry.lookup_due && !running.contains(recipient) {
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

    /// A lookup of `recipient`'s list ended without a route; it `failed`, or
    /// answered. Whether the recipient is still paced.
    fn looked_up(&mut self, recipient: &MemberId, failed: bool) -> bool {
        self.0
            .get_mut(recipient)
            .map(|retry| retry.lookup_failed = failed)
            .is_some()
    }

    /// Whether the last lookup of `recipient`'s list failed.
    fn lookup_failed(&self, recipient: &MemberId) -> bool {
        self.0
            .get(recipient)
            .is_some_and(|retry| retry.lookup_failed)
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
/// eligible route; one whose list is unknown, or whose last lookup failed
/// (`lookup_failed`), could not be resolved.
pub(super) fn route_not_started_reason(
    error: &TransportRoutingError,
    lookup_failed: bool,
) -> audit_v5::NotStartedReason {
    match error {
        TransportRoutingError::MissingInboxRoute(_) if lookup_failed => {
            audit_v5::NotStartedReason::RouteResolutionFailed
        }
        TransportRoutingError::MissingInboxRoute(
            MissingInboxRouteCause::EmptyList | MissingInboxRouteCause::NoneUsable,
        ) => audit_v5::NotStartedReason::NoEligibleRoute,
        TransportRoutingError::MissingInboxRoute(MissingInboxRouteCause::NoList)
        | TransportRoutingError::MissingGroupRoute => {
            audit_v5::NotStartedReason::RouteResolutionFailed
        }
    }
}

/// What a host's lookup of a recipient's inbox list found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WelcomeRouteLookup {
    /// A list that gives a route, now in the routing policy.
    Routed,
    /// An answer that gives no route: no list, an empty one, or none usable.
    NoRoute,
    /// No answer: no relay answered in full or in time.
    Failed,
}

/// The lookups a host should start and stop now
/// ([`AccountDeviceRuntime::plan_welcome_route_lookups`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WelcomeRouteLookupPlan {
    pub start: Vec<MemberId>,
    pub stop: Vec<MemberId>,
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

    /// The lookups of recipients' inbox lists a host should start and stop,
    /// given the ones it is `running`. It starts the lookups owed by a paced
    /// Welcome publish that found no route, each once, for a recipient an
    /// owed Welcome is still addressed to and with no lookup running, up to
    /// `limit` running in all; one left out stays owed. It stops each running
    /// lookup whose recipient no owed Welcome is addressed to any more. A
    /// Welcome that is withdrawn, expired, delivered or still staged with its
    /// commit is not owed, so nobody is looked up for it.
    pub fn plan_welcome_route_lookups(
        &self,
        limit: usize,
        running: &[MemberId],
    ) -> AccountResult<WelcomeRouteLookupPlan> {
        // With nothing running, the owed Welcomes are read only when a lookup
        // may start: not while the host starts none (`limit` 0).
        if running.is_empty() && (limit == 0 || !self.lock_welcome_route_retries().lookup_owed()) {
            return Ok(WelcomeRouteLookupPlan::default());
        }
        let owed = self
            .owed_welcomes()?
            .into_iter()
            .map(|(_, recipient)| recipient)
            .collect::<HashSet<_>>();
        let stop = running
            .iter()
            .filter(|recipient| !owed.contains(*recipient))
            .cloned()
            .collect::<Vec<_>>();
        let free = limit.saturating_sub(running.len() - stop.len());
        let mut retries = self.lock_welcome_route_retries();
        retries.retain(&owed);
        let start = retries.take_lookups(free, running);
        Ok(WelcomeRouteLookupPlan { start, stop })
    }

    /// The host's lookup of `recipient`'s inbox list ended with `outcome`,
    /// which the host has installed in its routing policy. A route ends the
    /// recipient's pacing, so the next maintenance pass sends its owed
    /// Welcomes. Otherwise the pacing stays, and the outcome becomes the
    /// delivery problem of each owed Welcome to the recipient that found no
    /// route: `InboxLookupFailed` after a failed lookup, else `NoInboxRelays`.
    pub fn finish_welcome_route_lookup(&self, recipient: &MemberId, outcome: WelcomeRouteLookup) {
        let failed = match outcome {
            WelcomeRouteLookup::Routed => {
                self.lock_welcome_route_retries().routed(recipient);
                return;
            }
            WelcomeRouteLookup::NoRoute => false,
            WelcomeRouteLookup::Failed => true,
        };
        if !self
            .lock_welcome_route_retries()
            .looked_up(recipient, failed)
        {
            return;
        }
        let owed = match self.owed_welcomes() {
            Ok(owed) => owed,
            Err(_) => {
                tracing::warn!(
                    target: TRACE_TARGET,
                    method = "finish_welcome_route_lookup",
                    "owed Welcomes unreadable; the next attempt records the lookup"
                );
                return;
            }
        };
        for (welcome_id, _) in owed.iter().filter(|(_, owed_to)| owed_to == recipient) {
            self.record_welcome_route_lookup(welcome_id, failed);
        }
    }

    /// Whether the last lookup of `message`'s recipient's inbox list failed.
    pub(super) fn welcome_route_lookup_failed(&self, message: &TransportMessage) -> bool {
        welcome_recipient(message)
            .is_some_and(|recipient| self.lock_welcome_route_retries().lookup_failed(&recipient))
    }

    /// Every owed Welcome this runtime watches, with its recipient.
    fn owed_welcomes(&self) -> AccountResult<Vec<(cgka_traits::MessageId, MemberId)>> {
        let now = self.wall_clock.now();
        let mut owed = Vec::new();
        for id in &self.watched_welcomes {
            if let OutboundWelcomeStatus::Owed { message, .. } =
                self.session.outbound_welcome_status(id, now)?
                && let Some(recipient) = welcome_recipient(&message)
            {
                owed.push((id.clone(), recipient));
            }
        }
        Ok(owed)
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
        let reason = |lookup_failed| {
            move |cause| {
                route_not_started_reason(
                    &TransportRoutingError::MissingInboxRoute(cause),
                    lookup_failed,
                )
            }
        };
        assert_eq!(
            [NoList, EmptyList, NoneUsable].map(reason(false)),
            [
                audit_v5::NotStartedReason::RouteResolutionFailed,
                audit_v5::NotStartedReason::NoEligibleRoute,
                audit_v5::NotStartedReason::NoEligibleRoute,
            ]
        );
        // A failed lookup could not resolve the route, whatever was cached.
        assert_eq!(
            [NoList, EmptyList, NoneUsable].map(reason(true)),
            [audit_v5::NotStartedReason::RouteResolutionFailed; 3]
        );
        assert_eq!(
            route_not_started_reason(&TransportRoutingError::MissingGroupRoute, false),
            audit_v5::NotStartedReason::RouteResolutionFailed
        );
    }
}
