//! Borrowed wire facts and immutable requests for the account recovery owner.
use super::*;
use tokio::sync::OwnedSemaphorePermit;

/// An opaque current-source capability. Identities are never diagnostic output.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReplayCaptureToken {
    pub(super) account_id: MemberId,
    pub(super) generation: u64,
    pub(super) request: Arc<str>,
    pub(super) relay: RelayIndex,
}

/// A recovery owner's frozen request. Accepted IO retains this credit until cleanup.
#[derive(Clone)]
pub struct ReplayCapturePlan {
    /// The existing account owner's frozen attempt serial.
    pub attempt_serial: u64,
    /// Current issued sources authorized by that attempt.
    pub sources: Vec<ReplayCaptureToken>,
    /// The process recovery credit retained through accepted IO cleanup.
    pub credit: Arc<OwnedSemaphorePermit>,
}

/// Request execution, not exhaustive history or durable recovery completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayCaptureOutcome {
    /// Every requested source finished original-window capture and placement.
    Complete,
    /// A requested source did not finish; no history certificate is implied.
    Incomplete,
    /// The owner cancelled the operation.
    Cancelled,
    /// An account, issued source, epoch or attempt no longer matches.
    Stale,
}

/// A live REQ's original query and its currently issued endpoint facts.
#[derive(Clone, Copy)]
pub struct ReplayRequestView<'a> {
    state: &'a AdapterState,
    coverage: &'a AccountReplayCoverage,
    account: &'a MemberId,
    id: &'a str,
    window: &'a ReplayWindow,
}

impl ReplayRequestView<'_> {
    /// Account-private wire identity, not a diagnostic reference.
    pub fn id(&self) -> &str {
        self.id
    }

    /// The original lower query bound; zero means unfloored history.
    pub fn since(&self) -> u64 {
        self.window.since
    }

    /// The original signed-safe upper query bound.
    pub fn until(&self) -> u64 {
        REPLAY_OPEN_UNTIL
    }

    /// Empty for the recipient inbox; otherwise the exact issued `h` tags.
    pub fn group_routes(&self) -> impl Iterator<Item = &[u8; 32]> {
        match &self.window.scope {
            ReplayScope::Inbox => [].as_slice(),
            ReplayScope::Groups(routes) => routes.as_slice(),
        }
        .iter()
    }

    /// Non-refused endpoints issued this request, not directory candidates.
    pub fn endpoints(&self) -> impl Iterator<Item = ReplayEndpointView<'_>> {
        self.coverage
            .subscriptions
            .get(self.id)
            .into_iter()
            .flat_map(|relays| relays.iter())
            .filter(|(_, replay)| **replay != RelayReplay::Refused)
            .map(|(relay, _)| ReplayEndpointView {
                state: self.state,
                coverage: self.coverage,
                account: self.account,
                id: self.id,
                relay: *relay,
            })
    }

    /// One available peer admitted this query's complete range in the current epoch.
    pub fn admitted(&self) -> bool {
        self.endpoints().any(|endpoint| endpoint.admitted())
    }

    /// This request's inbox or MLS-group input has reached durable placement
    /// and ordinary native admission. Unrelated requests' waiting peers do not
    /// revoke a completed range; the account cursor independently retains its
    /// strict all-current-source pending and loss fence.
    pub fn placed(&self) -> bool {
        match &self.window.scope {
            ReplayScope::Inbox => {
                self.coverage.inbox_placements == 0
                    && !self
                        .coverage
                        .outbox
                        .iter()
                        .any(|delivery| delivery.group_id_hint.is_none())
            }
            ReplayScope::Groups(_) => {
                self.coverage
                    .request_groups
                    .get(self.id)
                    .is_some_and(|groups| {
                        !groups.is_empty()
                            && groups.iter().all(|id| {
                                self.coverage.groups.get(id).is_some_and(|group| {
                                    self.coverage.group_ready(group)
                                        && group.events.is_empty()
                                        && group.placements == 0
                                        && !self.coverage.native_group_pending(id)
                                        && !self.coverage.outbox.iter().any(|delivery| {
                                            delivery.group_id_hint.as_ref() == Some(id)
                                        })
                                })
                            })
                    })
            }
        }
    }

    /// Every issued peer terminally refused this live request. Such a source
    /// remains observable debt, but supplies no private-capture capability.
    pub fn terminally_refused(&self) -> bool {
        self.coverage
            .subscriptions
            .get(self.id)
            .is_some_and(|relays| {
                !relays.is_empty()
                    && relays
                        .values()
                        .all(|replay| *replay == RelayReplay::Refused)
            })
    }
}

/// One issued endpoint, borrowed under the admission read guard.
#[derive(Clone, Copy)]
pub struct ReplayEndpointView<'a> {
    state: &'a AdapterState,
    coverage: &'a AccountReplayCoverage,
    account: &'a MemberId,
    id: &'a str,
    relay: RelayIndex,
}

impl ReplayEndpointView<'_> {
    /// The indexed endpoint, borrowed without copying its URL.
    pub fn endpoint(&self) -> &TransportEndpoint {
        self.state
            .relay_index
            .resolve(self.relay)
            .expect("an issued endpoint remains indexed")
    }

    /// This endpoint admitted its complete original range in the current epoch.
    pub fn admitted(&self) -> bool {
        self.coverage
            .endpoint_deadlines
            .get(self.id)
            .and_then(|relays| relays.get(&self.relay))
            .is_some_and(|endpoint| endpoint.boundary_admitted)
    }

    /// Freeze this source, not an arbitrary account/endpoint/window request.
    pub fn capture_token(&self) -> ReplayCaptureToken {
        ReplayCaptureToken {
            account_id: self.account.clone(),
            generation: self.coverage.wire_generation,
            request: Arc::from(self.id),
            relay: self.relay,
        }
    }
}

impl ReplayAdmissionStatus<'_> {
    /// Whether the account has an installed route set. A deactivated account's
    /// absent sources are temporary absence, not terminal replay evidence.
    pub fn active(&self) -> bool {
        self._guard.accounts.contains_key(self.account_id)
    }

    /// Wire membership/epoch changes invalidate an owner's cached permission.
    pub fn generation(&self) -> u64 {
        self._guard
            .account_replay_coverage
            .get(self.account_id)
            .map_or(0, |coverage| coverage.wire_generation)
    }

    /// This iterator and its endpoint views allocate nothing.
    pub fn sources(&self) -> impl Iterator<Item = ReplayRequestView<'_>> {
        let state = &*self._guard;
        state
            .account_replay_coverage
            .get(self.account_id)
            .into_iter()
            .flat_map(move |coverage| {
                coverage
                    .windows
                    .iter()
                    .filter(|(id, _)| {
                        !coverage.maintenance.contains(*id)
                            && coverage.subscriptions.contains_key(*id)
                    })
                    .map(move |(id, window)| ReplayRequestView {
                        state,
                        coverage,
                        account: self.account_id,
                        id,
                        window,
                    })
            })
    }
}
