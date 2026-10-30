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

/// One source generation: one REQ on one relay from its last (re)start. It
/// changes whenever the source restarts, so a count never carries across a
/// disconnect, receiver loss or capture. Opaque; never diagnostic output.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplaySourceGeneration(pub(super) u64);

impl ReplaySourceGeneration {
    /// A generation for a consumer's own tests.
    #[doc(hidden)]
    pub fn from_raw_for_test(raw: u64) -> Self {
        Self(raw)
    }
}

/// The connection a relay client holds open to one relay, by its own state:
/// opaque, compared only for equality. A client names every connection
/// differently, and names none for a relay it is not connected to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayConnection {
    handle: u64,
    attempt: usize,
}

impl RelayConnection {
    /// `handle` names the client's relay object, `attempt` the connection
    /// attempt it is on; together they never repeat for one relay.
    pub fn new(handle: u64, attempt: usize) -> Self {
        Self { handle, attempt }
    }
}

/// What one relay's live REQ returned before its physical EOSE in one source
/// generation. Backward paging of a clamped replay does not change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayLiveCount {
    /// Stored events the relay sent before EOSE.
    pub events: usize,
    /// The oldest `created_at` among them.
    pub oldest: Option<u64>,
    /// A local wall-clock second no later than when the relay ran the query
    /// this EOSE answered: stamped before the adapter issued the REQ, or the
    /// SDK's record of the connection it was re-sent on. Everything the relay
    /// stored before then and the filter matches was sent before this EOSE.
    pub requested_at: u64,
    /// A local wall-clock second from which the REQ has been open on the
    /// relay without a break: `requested_at` when the adapter issued it in
    /// this serial. When the SDK sent it again (on a reconnect, or after a
    /// kept `CLOSED`), the second the adapter recorded this EOSE, since when
    /// the SDK sent it is not reliably known. A provisional tail never starts
    /// earlier.
    pub live_from: u64,
}

impl ReplayLiveCount {
    /// The relay sent a full replay page or more before EOSE, so it may have
    /// clamped the reply. Native paging fetches such a window backwards; its
    /// count never fences.
    pub fn clamped(&self) -> bool {
        self.events >= RELAY_REPLAY_PAGE_LIMIT
    }
}

/// Which live counts an owner's observation could see as facts: read from the
/// [`ReplayAdmissionStatus`] its fences were computed from. A fence plan
/// answers only the counts its ticket covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplayFenceTicket(pub(super) u64);

/// One group's fence on its live frames, by any of the group's routes. Not
/// `Debug`: it carries the route.
#[derive(Clone, Copy)]
pub struct ReplayFence {
    /// A routing id of the group.
    pub route: [u8; 32],
    /// Frames sent before this second may be released; the rest stay held.
    pub release_before: u64,
}

/// The account owner's fences on its groups' live frames (mdk#2660), as of
/// the observation `ticket` came from. A group the plan does not name is not
/// fenced by the owner. Not `Debug`: it carries routes.
#[derive(Clone)]
pub struct ReplayFencePlan {
    pub ticket: ReplayFenceTicket,
    pub fences: Vec<ReplayFence>,
}

/// A generation's count that ended while its boundary was admitted: the relay
/// closed the REQ, or the connection dropped.
#[derive(Clone, Copy)]
pub struct ReplayEndedCount {
    pub generation: ReplaySourceGeneration,
    pub count: ReplayLiveCount,
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
            ReplayScope::Groups(_) => self.coverage.request_groups_placed(self.id),
        }
    }

    /// The routes this request carries whose group's live frames a fence
    /// holds: their input is not placed while it does, even when
    /// [`Self::placed`] holds for the rest of the request.
    pub fn fenced_routes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.coverage
            .request_groups
            .get(self.id)
            .into_iter()
            .flatten()
            .filter_map(|group_id| self.coverage.groups.get(group_id))
            .filter(|group| group.held_from().is_some())
            .filter_map(|group| group.routes.get(self.id))
            .flatten()
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

impl AccountReplayCoverage {
    /// Every MLS group request `id` routes has reached durable placement and
    /// ordinary native admission: nothing for those groups is buffered, queued
    /// natively, pinned or waiting in the outbox, except frames a fence holds.
    /// A fence holds one group, never the request: its held frames are owed
    /// on its own routes ([`ReplayRequestView::fenced_routes`]).
    pub(super) fn request_groups_placed(&self, id: &str) -> bool {
        self.request_groups.get(id).is_some_and(|groups| {
            !groups.is_empty()
                && groups.iter().all(|group_id| {
                    self.groups.get(group_id).is_some_and(|group| {
                        self.group_ready(group)
                            && group.events.values().all(|event| group.holds(event))
                            && group.placements == 0
                            && !self.native_group_pending(group_id)
                            && !self
                                .outbox
                                .iter()
                                .any(|delivery| delivery.group_id_hint.as_ref() == Some(group_id))
                    })
                })
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
        self.state_endpoint()
            .is_some_and(|endpoint| endpoint.boundary_admitted)
    }

    /// The source's current generation on this endpoint.
    pub fn generation(&self) -> ReplaySourceGeneration {
        ReplaySourceGeneration(self.state_endpoint().map_or(0, |endpoint| endpoint.serial))
    }

    /// What the current generation's EOSE counted, once it arrived and until
    /// the adapter sees the REQ close or its connection drop. Not admission:
    /// read [`Self::admitted`]; not liveness: read [`Self::streaming`].
    pub fn live_count(&self) -> Option<ReplayLiveCount> {
        self.state_endpoint()
            .and_then(|endpoint| endpoint.live_count)
    }

    /// The relay client reports, now, this relay connected on the connection
    /// the current generation started on. That is the only evidence its REQ
    /// still streams: a notification that it stopped can arrive late, or not
    /// at all (a shutdown, a removed account context, a reconnect the
    /// adapter has not seen yet). It names a connection, not the REQ: it can
    /// stay true until the adapter processes a `CLOSED` or a boundary already
    /// queued for this relay, a delay recovery accepts.
    pub fn streaming(&self) -> bool {
        self.state_endpoint()
            .and_then(|endpoint| endpoint.connection)
            .is_some_and(|connection| {
                self.state.relay_connection(self.account, self.relay) == Some(connection)
            })
    }

    /// The last generation that ended after its boundary was admitted, until
    /// the next one does.
    pub fn ended_count(&self) -> Option<ReplayEndedCount> {
        self.state_endpoint()
            .and_then(|endpoint| endpoint.ended_count)
    }

    fn state_endpoint(&self) -> Option<&ReplayEndpoint> {
        self.coverage
            .endpoint_deadlines
            .get(self.id)
            .and_then(|relays| relays.get(&self.relay))
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

    /// Which of this account's live counts this status shows as facts: hand
    /// it back with the fences computed from them.
    pub fn fence_ticket(&self) -> ReplayFenceTicket {
        ReplayFenceTicket(
            self._guard
                .account_replay_coverage
                .get(self.account_id)
                .map_or(0, |coverage| coverage.fence_ticket),
        )
    }

    /// The routes of every group whose live frames a fence holds now, a route
    /// once per request that carries it. Allocates nothing.
    pub fn fenced_routes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self._guard
            .account_replay_coverage
            .get(self.account_id)
            .into_iter()
            .flat_map(|coverage| coverage.groups.values())
            .filter(|group| group.held_from().is_some())
            .flat_map(|group| group.routes.values().flatten())
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
