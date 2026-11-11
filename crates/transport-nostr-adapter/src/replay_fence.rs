//! Fences on a group's live frames (mdk#2660 phase 4): the hold that keeps
//! newer live input behind a live REQ's unproven range while the account
//! owner's recovery runner owes it.
//!
//! A live EOSE that counted stored events leaves `[since, oldest seen]`
//! unproven on that relay: the relay's cap may have cut what it stored there.
//! Until something proves that range, the group's live frames past it must
//! not go ahead of the older history the owner still fetches. So, once the
//! owner enables fencing for the account:
//!
//! - **Arming.** Such a count holds every group its REQ routes from the REQ's `since`
//!   on, from its EOSE. A count only becomes a fact the owner can see once its
//!   boundary is admitted, and a boundary is admitted only once its group's
//!   range left the native hold, so without this the frames would be gone
//!   before the owner could fence them. An arming belongs to its own count
//!   (the endpoint's count id moves whenever a count is installed or ends): a
//!   count that ends, or that a newer count replaces, before its boundary is
//!   admitted fences nothing, and its arming is dropped. An admission after
//!   the count ended makes it no fact.
//! - **The owner's answer.** A [`ReplayFencePlan`] answers the armings its
//!   ticket covers, that is the counts its observation saw as facts, and sets
//!   each group's release point. Frames sent before it go out oldest first;
//!   the rest stay held, their claims kept. A group the plan does not name is
//!   not fenced by the owner.
//! - **Owner completion.** A hold follows the owner's durable backlog, not a
//!   network request's deadline. Only an answered count and the owner's
//!   advancing/released point let newer input go. Request timeouts,
//!   replay-buffer bounds and loss accounting remain independent. A fence left
//!   holding nothing (no unanswered count, no owner point) ends at once.
//! - **What already left.** A fence holds only what is still in the replay
//!   buffer. A frame its group already handed off, to native ingress (queued
//!   or borrowed) or to a draining batch without it, goes on as late input,
//!   and the range stays owed.
//! - **Replacement.** A fresh activation replaces the account's replay
//!   coverage. The live frames its fences hold have no other copy, so they
//!   move to the new coverage, held from the same point until the owner's
//!   next plan answers; a plan older than the last one applied still answers
//!   nothing. A history copy a fresh REQ asks for again, on the same route
//!   and relay from no later, is dropped: it comes again. Only a frame whose
//!   group the new REQs no longer route, or that the buffer has no room for,
//!   is lost.
//! - **One group.** A fence holds its own group's frames only. They count
//!   neither in the account's pending admission nor against other groups'
//!   placement, so other groups' live boundaries, tails and ingest go on. A
//!   hand-off that rejoined the buffer keeps its placement pin, which a fence
//!   that holds it there exempts in the same way. Held frames stay in the
//!   replay buffer under its bounds: overflow is loss.

use super::*;

/// A fence on one group until the owner releases it. A request timeout
/// cannot complete the owner's acquisition or durable admission.
pub(super) struct GroupFence {
    /// Counts that armed the hold and that no plan has answered yet.
    armed: Vec<FenceArming>,
    /// The owner's release point, while its plans fence the group.
    owner: Option<u64>,
}

/// One live count that armed a group's fence.
struct FenceArming {
    request: Arc<str>,
    relay: RelayIndex,
    serial: u64,
    /// The endpoint's count id when it armed: once that moves, this count is
    /// no longer the endpoint's, and unless it became a fact it fences
    /// nothing.
    count: u64,
    /// Its REQ's `since`: nothing older lies in the range it left unproven.
    since: u64,
    /// The ticket from which an owner's observation sees this count as a
    /// fact; `None` until its boundary is admitted.
    answerable: Option<u64>,
}

impl GroupFence {
    /// The second from which the fence holds frames, while it holds any.
    pub(super) fn held_from(&self) -> Option<u64> {
        self.armed
            .iter()
            .map(|arming| arming.since)
            .chain(self.owner)
            .min()
    }
}

impl GroupReplay {
    /// The second from which a fence holds this group's frames.
    pub(super) fn held_from(&self) -> Option<u64> {
        self.fence.as_ref().and_then(GroupFence::held_from)
    }

    /// Whether a fence holds `event` back.
    pub(super) fn holds(&self, event: &BufferedReplay) -> bool {
        self.held_from()
            .is_some_and(|from| event.delivery.message.timestamp.0 >= from)
    }

    /// Whether a fence holds the buffered event `id` back.
    pub(super) fn holds_id(&self, id: &[u8; 32]) -> bool {
        self.events.get(id).is_some_and(|event| self.holds(event))
    }

    /// Take every buffered event a fence lets go, with no claim, live copy or
    /// ready history left on it; the held rest keeps all three. Unfenced, that
    /// is every event.
    pub(super) fn release(&mut self) -> Vec<([u8; 32], BufferedReplay)> {
        let Some(from) = self.held_from() else {
            for stream in self.streams.values_mut() {
                stream.claims.clear();
            }
            self.live.clear();
            self.ready_history.clear();
            self.restored.clear();
            return self.events.drain().collect();
        };
        let released = self
            .events
            .iter()
            .filter(|(_, event)| event.delivery.message.timestamp.0 < from)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let released = released
            .into_iter()
            .map(|id| {
                for stream in self.streams.values_mut() {
                    stream.claims.remove(&id);
                }
                self.live.remove(&id);
                self.ready_history.remove(&id);
                (
                    id,
                    self.events.remove(&id).expect("released event is buffered"),
                )
            })
            .collect();
        let events = &self.events;
        self.restored.retain(|id| events.contains_key(id));
        released
    }
}

impl AccountReplayCoverage {
    /// Buffered events fences hold back: they are not pending admission.
    pub(super) fn fence_held_items(&self) -> usize {
        if !self.fencing {
            return 0;
        }
        self.groups
            .values()
            .map(|group| {
                group
                    .events
                    .values()
                    .filter(|event| group.holds(event))
                    .count()
            })
            .sum()
    }

    /// Placement pins a fence exempts in `group`: those of hand-offs that
    /// rejoined its buffer and that it holds there. Such a frame is held, not
    /// placed; a pin on a copy still out is never exempt.
    pub(super) fn held_pins(&self, group_id: &GroupId, group: &GroupReplay) -> usize {
        if group.held_from().is_none() {
            return 0;
        }
        group
            .restored
            .iter()
            .filter(|id| self.held_pin(group_id, group, id))
            .count()
    }

    fn held_pin(&self, group_id: &GroupId, group: &GroupReplay, id: &[u8; 32]) -> bool {
        group.restored.contains(id)
            && group.holds_id(id)
            && self
                .unplaced
                .get(id)
                .is_some_and(|groups| groups.contains(group_id))
    }

    /// Whether a placement pin is pending: one a fence exempts is not.
    pub(super) fn unplaced_pending(&self) -> bool {
        if !self.fencing {
            return !self.unplaced.is_empty();
        }
        self.unplaced.iter().any(|(id, groups)| {
            groups.is_empty()
                || groups.iter().any(|group_id| {
                    !self
                        .groups
                        .get(group_id)
                        .is_some_and(|group| self.held_pin(group_id, group, id))
                })
        })
    }

    fn next_fence_ticket(&mut self) -> u64 {
        let ticket = self
            .changes
            .clock
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .checked_add(1)
            .expect("fence ticket exhausted");
        self.fence_ticket = ticket;
        ticket
    }

    /// `relay`'s EOSE for `id` just installed a live count: unless it is
    /// empty, it holds every group the REQ routes until the owner answers it.
    /// One that does not fence retires the endpoint's earlier counts that are
    /// no fact.
    pub(super) fn arm_fence(&mut self, id: &str, relay: RelayIndex) {
        if !self.fencing || self.maintenance.contains(id) {
            return;
        }
        let Some(endpoint) = self
            .endpoint_deadlines
            .get(id)
            .and_then(|relays| relays.get(&relay))
        else {
            return;
        };
        if !endpoint.live_count.is_some_and(|count| count.events > 0) {
            self.retire_fence_armings(id, relay);
            return;
        }
        let serial = endpoint.serial;
        let count = endpoint.count_id;
        let answerable = endpoint.boundary_admitted.then(|| self.next_fence_ticket());
        let since = self.windows.get(id).map_or(0, |window| window.since);
        let request: Arc<str> = Arc::from(id);
        let groups = self
            .request_groups
            .get(id)
            .into_iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        for group_id in groups {
            let Some(group) = self.groups.get_mut(&group_id) else {
                continue;
            };
            let arming = FenceArming {
                request: request.clone(),
                relay,
                serial,
                count,
                since,
                answerable,
            };
            match group.fence.as_mut() {
                Some(fence) => {
                    // A newer count of the same endpoint replaces its last.
                    fence.armed.retain(|armed| {
                        armed.request != arming.request || armed.relay != arming.relay
                    });
                    fence.armed.push(arming);
                }
                None => {
                    group.fence = Some(GroupFence {
                        armed: vec![arming],
                        owner: None,
                    });
                }
            }
        }
        self.wake_replay();
    }

    /// Drop the armings `relay`'s earlier counts for `id` left that never
    /// became facts: a newer count replaced them.
    fn retire_fence_armings(&mut self, id: &str, relay: RelayIndex) {
        let mut released = false;
        for group_id in self.request_groups.get(id).into_iter().flatten() {
            let Some(group) = self.groups.get_mut(group_id) else {
                continue;
            };
            let Some(fence) = group.fence.as_mut() else {
                continue;
            };
            let held = fence.armed.len();
            fence.armed.retain(|arming| {
                arming.answerable.is_some()
                    || arming.relay != relay
                    || arming.request.as_ref() != id
            });
            released |= fence.armed.len() != held;
            end_idle(group);
        }
        if released {
            self.wake_replay();
        }
    }

    /// The oldest buffered frame a fence holds at or after `floor`. A cursor
    /// that passed it would leave it to no restart, so the cursor seal stops
    /// there; a held frame below the floor is already the restart's.
    pub(super) fn fence_held_since(&self, floor: u64) -> Option<u64> {
        if !self.fencing {
            return None;
        }
        self.groups
            .values()
            .flat_map(|group| {
                group
                    .events
                    .values()
                    .filter(|event| group.holds(event))
                    .map(|event| event.delivery.message.timestamp.0)
            })
            .filter(|held| *held >= floor)
            .min()
    }

    /// The boundaries of `admitted` (request, relay, serial, count id) were
    /// just admitted with their counts still current: the counts that armed
    /// fences there become facts an owner's next observation sees. An arming
    /// whose count already ended is not among them.
    pub(super) fn admit_fence_armings(&mut self, admitted: &[(String, RelayIndex, u64, u64)]) {
        if admitted.is_empty() {
            return;
        }
        let ticket = self.next_fence_ticket();
        for (id, relay, serial, count) in admitted {
            for group_id in self.request_groups.get(id.as_str()).into_iter().flatten() {
                let Some(fence) = self
                    .groups
                    .get_mut(group_id)
                    .and_then(|group| group.fence.as_mut())
                else {
                    continue;
                };
                for arming in &mut fence.armed {
                    if arming.answerable.is_none()
                        && arming.relay == *relay
                        && arming.serial == *serial
                        && arming.count == *count
                        && arming.request.as_ref() == id.as_str()
                    {
                        arming.answerable = Some(ticket);
                    }
                }
            }
        }
    }

    /// Drop armings whose count ended, or was replaced, before its boundary
    /// was admitted: such a count is no fact and fences nothing.
    pub(super) fn prune_fence_armings(&mut self) {
        if !self.fencing {
            return;
        }
        let endpoints = &self.endpoint_deadlines;
        let mut released = false;
        for group in self.groups.values_mut() {
            let Some(fence) = group.fence.as_mut() else {
                continue;
            };
            let held = fence.armed.len();
            fence.armed.retain(|arming| {
                arming.answerable.is_some()
                    || endpoints
                        .get(arming.request.as_ref())
                        .and_then(|relays| relays.get(&arming.relay))
                        .is_some_and(|endpoint| {
                            endpoint.serial == arming.serial && endpoint.count_id == arming.count
                        })
            });
            released |= fence.armed.len() != held;
            end_idle(group);
        }
        if released {
            self.wake_replay();
        }
    }

    /// Apply the owner's `plan`: it answers the armings its ticket covers,
    /// and sets the release point of each group it names, beginning a fence
    /// on a group that has none.
    pub(super) fn apply_fence_plan(&mut self, plan: &ReplayFencePlan) {
        self.fencing = true;
        // A plan read before the last one applied answers nothing newer, and
        // its points would undo the newer plan's.
        if plan.ticket.0 < self.fence_plan_ticket {
            return;
        }
        self.fence_plan_ticket = plan.ticket.0;
        let mut named = HashMap::<[u8; 32], u64>::new();
        for fence in &plan.fences {
            named
                .entry(fence.route)
                .and_modify(|at| *at = (*at).min(fence.release_before))
                .or_insert(fence.release_before);
        }
        for group in self.groups.values_mut() {
            let owner = group
                .routes
                .values()
                .flatten()
                .filter_map(|route| named.get(route))
                .copied()
                .min();
            match group.fence.as_mut() {
                Some(fence) => {
                    fence.armed.retain(|arming| {
                        arming
                            .answerable
                            .is_none_or(|ticket| ticket > plan.ticket.0)
                    });
                    fence.owner = owner;
                    end_idle(group);
                }
                None => {
                    if owner.is_some() {
                        group.fence = Some(GroupFence {
                            armed: Vec::new(),
                            owner,
                        });
                    }
                }
            }
        }
        self.wake_replay();
    }
}

/// The live frames a replaced coverage buffered with no other copy, for the
/// coverage that replaces it ([`AccountReplayCoverage::take_carried_live`]).
#[derive(Default)]
pub(super) struct CarriedLive {
    /// Each frame with whether its group's fence held it.
    frames: Vec<(GroupId, TransportDelivery, bool)>,
    /// The second each group's fence held from, for groups with a held frame.
    from: HashMap<GroupId, u64>,
    /// The last owner plan the replaced coverage applied.
    plan_ticket: u64,
    /// The replaced coverage's loss floor, for frames that cannot move.
    floor: Option<u64>,
}

impl AccountReplayCoverage {
    /// Take the live frames this coverage buffers, for the coverage replacing
    /// it: those its fences hold, and those still waiting to be admitted, to
    /// native ingress or past an unended REQ. They have no other copy: native
    /// ingress never had them and nothing durable holds them, so dropping them
    /// would be loss. Frames native ingress owns or that have a durable copy
    /// stay, as replacement already accounts for those; so do history copies
    /// no fence holds, which the fresh REQs replay.
    pub(super) fn take_carried_live(&mut self) -> CarriedLive {
        let mut carried = CarriedLive {
            plan_ticket: self.fence_plan_ticket,
            floor: self.retained_since,
            ..CarriedLive::default()
        };
        let fencing = self.fencing;
        let native_ids = &self.native_ids;
        for (group_id, group) in &mut self.groups {
            let from = group.held_from().filter(|_| fencing);
            let frames = group
                .events
                .iter()
                .filter(|(id, event)| !event.retained && !native_ids.contains_key(*id))
                .map(|(id, event)| (*id, from.is_some() && group.holds(event)))
                .filter(|(id, held)| *held || group.live.contains(id))
                .collect::<Vec<_>>();
            if let Some(from) = from.filter(|_| frames.iter().any(|(_, held)| *held)) {
                carried.from.insert(group_id.clone(), from);
            }
            for (id, held) in frames {
                let event = group.events.remove(&id).expect("carried event is buffered");
                for stream in group.streams.values_mut() {
                    stream.claims.remove(&id);
                }
                group.live.remove(&id);
                group.ready_history.remove(&id);
                self.buffered_items -= 1;
                self.buffered_bytes -= event.delivery.message.payload.len();
                carried
                    .frames
                    .push((group_id.clone(), event.delivery, held));
            }
        }
        carried
    }

    /// Drop the history copies the fresh REQs replay, which replacing this
    /// coverage then does not lose: a copy only streams claim, one of them
    /// on a route and relay that a fresh REQ (`fresh`: route, relay, `since`)
    /// asks again from no later than the copy was sent. Call it after
    /// [`Self::take_carried_live`]; what neither moves nor comes again stays
    /// for the drop to charge as loss.
    pub(super) fn forget_replayed_history(&mut self, fresh: &[([u8; 32], RelayIndex, u64)]) {
        for group in self.groups.values_mut() {
            let replayed = group
                .events
                .iter()
                .filter(|(id, event)| {
                    !event.retained
                        && !self.native_ids.contains_key(*id)
                        && !group.live.contains(*id)
                        && !group.ready_history.contains(*id)
                        && group.streams.iter().any(|(owner, stream)| {
                            stream.claims.contains(*id)
                                && fresh.iter().any(|(route, relay, since)| {
                                    *route == owner.route
                                        && *relay == owner.relay
                                        && *since <= event.delivery.message.timestamp.0
                                })
                        })
                })
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for id in replayed {
                let event = group.events.remove(&id).expect("replayed copy is buffered");
                for stream in group.streams.values_mut() {
                    stream.claims.remove(&id);
                }
                self.buffered_items -= 1;
                self.buffered_bytes -= event.delivery.message.payload.len();
            }
        }
    }

    /// Buffer the live frames a replaced coverage carried
    /// ([`Self::take_carried_live`]) in this one. A frame a fence held is held
    /// here from the point its fence held from, until the owner's next plan
    /// answers; that plan sets the hold as for any fence, and a group it does
    /// not name lets them go. The rest wait for admission as any live frame
    /// does. A frame whose group this coverage does not route, a held one
    /// while it does not fence, or one its buffer has no room for, is lost as
    /// the replaced coverage would have lost it.
    pub(super) fn restore_carried_live(&mut self, carried: CarriedLive) {
        if carried.frames.is_empty() {
            return;
        }
        // A plan older than the last one applied must not undo the holds it
        // set; one read from this coverage is at least as new.
        self.fence_plan_ticket = self.fence_plan_ticket.max(carried.plan_ticket);
        self.fence_ticket = self.fence_ticket.max(carried.plan_ticket);
        let mut lost = false;
        for (group_id, delivery, held) in carried.frames {
            let bytes = delivery.message.payload.len();
            let (items_available, bytes_available) = self.buffer_available();
            let room = (!held || self.fencing) && items_available != 0 && bytes <= bytes_available;
            let Some(group) = self.groups.get_mut(&group_id).filter(|_| room) else {
                lost = true;
                continue;
            };
            let id =
                <[u8; 32]>::try_from(delivery.message.id.as_slice()).expect("buffered event id");
            let since = delivery.message.timestamp.0;
            let claimed = group.live.insert(id);
            match group.events.entry(id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().owners += usize::from(claimed);
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(BufferedReplay {
                        delivery,
                        owners: 1,
                        retained: false,
                    });
                    self.buffered_items += 1;
                    self.buffered_bytes += bytes;
                }
            }
            if held {
                let from = carried.from[&group_id];
                match group.fence.as_mut() {
                    Some(fence) => {
                        fence.owner = Some(fence.owner.map_or(from, |owner| owner.min(from)));
                    }
                    None => {
                        group.fence = Some(GroupFence {
                            armed: Vec::new(),
                            owner: Some(from),
                        });
                    }
                }
            }
            self.retained_since = Some(self.retained_since.map_or(since, |floor| floor.min(since)));
        }
        if lost {
            self.record_loss(carried.floor.unwrap_or(0));
        }
        self.wake_replay();
    }
}

/// End a fence that holds nothing any more: no unanswered count, no owner
/// point.
fn end_idle(group: &mut GroupReplay) {
    if group
        .fence
        .as_ref()
        .is_some_and(|fence| fence.armed.is_empty() && fence.owner.is_none())
    {
        group.fence = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINCE: u64 = 100;

    fn account() -> MemberId {
        MemberId::new(vec![0xA1; 32])
    }

    fn group_id(group: u8) -> GroupId {
        GroupId::new(vec![group; 16])
    }

    fn route(group: u8) -> NostrSubscription {
        NostrSubscription::Group {
            account_id: account(),
            group_id: group_id(group),
            transport_group_id: vec![group; 32],
            endpoints: vec![TransportEndpoint("wss://a.example".to_owned())],
            since: Some(Timestamp(SINCE)),
            attempt: SubscriptionAttempt::INITIAL,
        }
    }

    /// One batch REQ for groups 0 and 1 on relays 1 and 2, with fencing as
    /// given and no native ingress.
    fn fenced_coverage(fencing: bool) -> (AccountReplayCoverage, String, Arc<ReplayLosses>) {
        let batch = pack_group_batches(
            &account(),
            &[route(0), route(1)],
            SubscriptionAttempt::INITIAL,
            0,
        )
        .remove(0);
        let id = batch.subscription_id();
        let losses = Arc::new(ReplayLosses::default());
        let mut coverage = AccountReplayCoverage::new(account(), losses.clone(), Arc::default());
        coverage.fencing = fencing;
        coverage.add_subscription(
            id.clone(),
            &batch,
            HashMap::from([
                (RelayIndex(1), RelayReplay::Awaiting),
                (RelayIndex(2), RelayReplay::Awaiting),
            ]),
            &HashMap::new(),
        );
        (coverage, id, losses)
    }

    fn delivery(group: u8, at: u64, seed: u8, id: &str, payload: usize) -> TransportDelivery {
        let mut event = [seed; 32];
        event[0] = group;
        TransportDelivery {
            account_id: account(),
            group_id_hint: Some(group_id(group)),
            message: TransportMessage {
                id: MessageId::new(event.to_vec()),
                payload: vec![seed; payload],
                timestamp: Timestamp(at),
                causal_deps: Vec::new(),
                source: TransportSource(NOSTR_SOURCE.into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: vec![group; 32],
                },
            },
            received_at: Timestamp(1_000),
            source: TransportDeliverySource {
                transport: TransportSource(NOSTR_SOURCE.into()),
                plane: TransportDeliveryPlane::Group,
                endpoint: Some(TransportEndpoint("wss://a.example".into())),
                subscription_id: Some(id.to_owned()),
                wire: None,
            },
        }
    }

    /// Relay 1 replays `stored` (group, created_at) before its EOSE; relay 2
    /// replays nothing.
    fn replay(
        coverage: &mut AccountReplayCoverage,
        id: &str,
        stored: &[(u8, u64)],
        tx: &mpsc::Sender<TransportDelivery>,
    ) {
        for (seed, &(group, at)) in stored.iter().enumerate() {
            coverage.record_stored_event(id, RelayIndex(1), at);
            coverage
                .stage_delivery(
                    delivery(group, at, seed as u8 + 1, id, 1),
                    Some(RelayIndex(1)),
                    ReplayInput::History,
                    tx,
                )
                .unwrap();
        }
        coverage.record_eose(id, RelayIndex(1));
        coverage.record_eose(id, RelayIndex(2));
    }

    /// What the next drain releases, as (group, created_at), oldest first.
    fn released(coverage: &mut AccountReplayCoverage) -> Vec<(u8, u64)> {
        let mut released = coverage
            .take_ready_deliveries()
            .into_iter()
            .map(|delivery| {
                (
                    delivery.group_id_hint.unwrap().as_slice()[0],
                    delivery.message.timestamp.0,
                )
            })
            .collect::<Vec<_>>();
        released.sort_unstable_by_key(|(group, at)| (*at, *group));
        released
    }

    fn sent(rx: &mut mpsc::Receiver<TransportDelivery>) -> Vec<(u8, u64)> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .map(|delivery| {
                (
                    delivery.group_id_hint.unwrap().as_slice()[0],
                    delivery.message.timestamp.0,
                )
            })
            .collect()
    }

    fn plan(coverage: &AccountReplayCoverage, fences: &[(u8, u64)]) -> ReplayFencePlan {
        ReplayFencePlan {
            ticket: ReplayFenceTicket(coverage.fence_ticket),
            fences: fences
                .iter()
                .map(|&(group, release_before)| ReplayFence {
                    route: [group; 32],
                    release_before,
                })
                .collect(),
        }
    }

    fn held_from(coverage: &AccountReplayCoverage, group: u8) -> Option<u64> {
        coverage.groups[&group_id(group)].held_from()
    }

    /// An EOSE with no stored event before it leaves nothing unproven that a
    /// fence would hold: the range is owed, and the group's frames flow.
    #[tokio::test]
    async fn an_empty_count_holds_nothing() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, mut rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[], &tx);
        assert_eq!(held_from(&coverage, 0), None);
        assert_eq!(held_from(&coverage, 1), None);
        coverage
            .stage_delivery(
                delivery(0, 500, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        assert_eq!(sent(&mut rx), vec![(0, 500)]);
    }

    /// Unless the owner enables fencing, a counted reply holds nothing: the
    /// group is released as soon as its peers settle, as before.
    #[tokio::test]
    async fn nothing_fences_before_the_owner_enables_it() {
        let (mut coverage, id, _) = fenced_coverage(false);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150)], &tx);
        assert_eq!(held_from(&coverage, 0), None);
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
        assert_eq!(coverage.fence_ticket, 0);
    }

    /// A counted reply leaves `[since, oldest seen]` unproven, so it holds
    /// every group its REQ routes from the REQ's `since`, from its EOSE, and
    /// its boundary is admitted with the frames still held: the owner sees
    /// the count. The owner's plan then releases what is older than its
    /// fence and keeps the rest, and frees the group it does not fence.
    #[tokio::test]
    async fn a_counted_reply_holds_its_groups_until_the_owner_answers() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, mut rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150), (0, 300)], &tx);
        assert_eq!(held_from(&coverage, 0), Some(SINCE));
        assert_eq!(held_from(&coverage, 1), Some(SINCE));
        assert!(released(&mut coverage).is_empty(), "held until answered");
        assert!(
            coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted,
            "held frames do not keep the count from becoming a fact"
        );
        assert_ne!(coverage.fence_ticket, 0);

        coverage.apply_fence_plan(&plan(&coverage, &[(0, 200)]));
        assert_eq!(held_from(&coverage, 0), Some(200));
        assert_eq!(held_from(&coverage, 1), None, "not fenced by the owner");
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
        coverage
            .stage_delivery(
                delivery(0, 400, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        coverage
            .stage_delivery(
                delivery(1, 400, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        assert_eq!(
            sent(&mut rx),
            vec![(1, 400)],
            "the fast path holds a fenced frame"
        );
        assert!(released(&mut coverage).is_empty());

        coverage.apply_fence_plan(&plan(&coverage, &[(0, 350)]));
        assert_eq!(released(&mut coverage), vec![(0, 300)], "partial release");
        coverage.apply_fence_plan(&plan(&coverage, &[]));
        assert_eq!(released(&mut coverage), vec![(0, 400)]);
    }

    /// The live frames `groups` hold behind the owner's fence at 200, and the
    /// replay losses the coverage they sit in charges.
    fn held_live(groups: &[u8]) -> (AccountReplayCoverage, Arc<ReplayLosses>) {
        let (mut coverage, id, losses) = fenced_coverage(true);
        let (tx, mut rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150)], &tx);
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 200), (1, 200)]));
        let placed = coverage.take_ready_deliveries();
        assert_eq!(placed.len(), 1, "the frame before the fence goes out");
        for delivery in &placed {
            coverage.ack_placement(&delivery.message.id);
        }
        for &group in groups {
            coverage
                .stage_delivery(
                    delivery(group, 400, 9, &id, 1),
                    Some(RelayIndex(1)),
                    ReplayInput::Live,
                    &tx,
                )
                .unwrap();
        }
        assert!(sent(&mut rx).is_empty(), "the fence holds them");
        (coverage, losses)
    }

    /// The adapter waits one replay deadline for a live REQ's EOSE and
    /// no longer: a relay that never sends one has failed. The frames only it
    /// sent are dropped and owed from the REQ's floor, the account's admission
    /// stops waiting, and the group's later live frames flow unfenced.
    #[tokio::test(start_paused = true)]
    async fn a_relay_that_never_sends_eose_fails_after_one_deadline() {
        let (mut coverage, id, losses) = fenced_coverage(true);
        let (tx, mut rx) = mpsc::channel(8);
        coverage.record_stored_event(&id, RelayIndex(1), 150);
        coverage
            .stage_delivery(
                delivery(0, 150, 1, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::History,
                &tx,
            )
            .unwrap();
        coverage.record_eose(&id, RelayIndex(2));
        assert!(
            released(&mut coverage).is_empty(),
            "relay 1 may still send older frames"
        );
        assert!(coverage.admission_pending());

        tokio::time::advance(REPLAY_WAIT_LIMIT).await;
        coverage.expire_replay(tokio::time::Instant::now());
        assert!(
            released(&mut coverage).is_empty(),
            "its unproven frame is dropped"
        );
        assert!(!coverage.admission_pending(), "nothing waits on the relay");
        assert_eq!(held_from(&coverage, 0), None, "no fence holds the group");
        assert_eq!(
            losses.pending.lock().unwrap().get(&account()),
            Some(&NostrNotificationLossFloor::Since(SINCE)),
            "the dropped window is owed from the REQ's floor"
        );

        coverage
            .stage_delivery(
                delivery(0, 500, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        assert_eq!(sent(&mut rx), vec![(0, 500)]);
    }

    /// A fresh activation of an account whose coverage holds `held` with the
    /// fresh REQs routing `routed`. Both coverages share one loss record and
    /// one ticket clock, as in the adapter; the new one has seen its EOSE.
    fn replace(held: (AccountReplayCoverage, Arc<ReplayLosses>), routed: &[u8]) -> AdapterState {
        let (coverage, losses) = held;
        let mut state = AdapterState {
            replay_losses: losses,
            source_clock: coverage.changes.clock.clone(),
            ..AdapterState::default()
        };
        state.replay_fencing.insert(account());
        state.account_replay_coverage.insert(account(), coverage);
        let routes = routed.iter().map(|&group| route(group)).collect::<Vec<_>>();
        let batch = pack_group_batches(&account(), &routes, SubscriptionAttempt::INITIAL.next(), 0)
            .remove(0);
        state.record_account_replay_start(&account(), std::slice::from_ref(&batch));
        let relay = state
            .relay_index
            .index_for(&TransportEndpoint("wss://a.example".to_owned()));
        state
            .account_replay_coverage
            .get_mut(&account())
            .unwrap()
            .record_eose(&batch.subscription_id(), relay);
        state
    }

    fn pending_loss(losses: &ReplayLosses) -> Option<NostrNotificationLossFloor> {
        losses.pending.lock().unwrap().get(&account()).copied()
    }

    /// A fresh activation replaces the account's coverage. Live frames a fence
    /// holds have no other copy, so they move to the new coverage, held from
    /// the same point, and nothing is lost. The owner's next plan answers them
    /// there; one older than the last it applied still answers nothing.
    #[tokio::test]
    async fn a_fresh_activation_keeps_what_fences_hold() {
        let mut state = replace(held_live(&[0, 1]), &[0, 1]);
        assert_eq!(pending_loss(&state.replay_losses), None);
        let coverage = state.account_replay_coverage.get_mut(&account()).unwrap();
        assert_eq!(held_from(coverage, 0), Some(200));
        assert_eq!(held_from(coverage, 1), Some(200));
        assert!(released(coverage).is_empty(), "still held");
        let stale = ReplayFencePlan {
            ticket: ReplayFenceTicket(0),
            fences: Vec::new(),
        };
        coverage.apply_fence_plan(&stale);
        assert!(
            released(coverage).is_empty(),
            "an older plan answers nothing"
        );
        coverage.apply_fence_plan(&plan(coverage, &[(1, 200)]));
        assert_eq!(released(coverage), vec![(0, 400)]);
        coverage.apply_fence_plan(&plan(coverage, &[]));
        assert_eq!(released(coverage), vec![(1, 400)]);
    }

    /// A live frame no fence holds but that still waits to be admitted has no
    /// other copy either. The recovery runner's post-join step re-activates
    /// an account while one waits; it moves to the new coverage, unfenced,
    /// and goes out once the fresh REQs are ready, with nothing owed.
    #[tokio::test]
    async fn a_fresh_activation_keeps_live_frames_waiting_for_admission() {
        let (mut coverage, id, losses) = fenced_coverage(true);
        let (tx, mut rx) = mpsc::channel(8);
        coverage
            .stage_delivery(
                delivery(0, 400, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        assert!(sent(&mut rx).is_empty(), "its REQ has no EOSE yet");
        let mut state = replace((coverage, losses), &[0]);
        assert_eq!(pending_loss(&state.replay_losses), None);
        let coverage = state.account_replay_coverage.get_mut(&account()).unwrap();
        assert_eq!(held_from(coverage, 0), None, "no fence holds it");
        assert_eq!(released(coverage), vec![(0, 400)]);
    }

    /// A held frame whose group the fresh REQs no longer route has nowhere to
    /// go: it is lost, from the replaced coverage's floor, as before.
    #[tokio::test]
    async fn a_fresh_activation_loses_what_it_no_longer_routes() {
        let state = replace(held_live(&[1]), &[0]);
        assert_eq!(
            pending_loss(&state.replay_losses),
            Some(NostrNotificationLossFloor::Since(SINCE))
        );
    }

    /// A history copy its REQ was still replaying when a fresh activation
    /// replaced the coverage comes again on a fresh REQ that routes its group
    /// on the same relay from no later: replacing loses nothing, and the copy
    /// goes out once the fresh REQ replays it. A copy from a relay the fresh
    /// REQs leave out, or older than their `since`, is lost, from the replaced
    /// coverage's floor, as before.
    #[tokio::test]
    async fn a_fresh_activation_loses_no_history_its_reqs_replay() {
        let lost = Some(NostrNotificationLossFloor::Since(SINCE));
        for (relay, fresh_since, lost) in [
            (RelayIndex(1), SINCE, None),
            (RelayIndex(2), SINCE, lost),
            (RelayIndex(1), 200, lost),
        ] {
            let (mut coverage, id, losses) = fenced_coverage(true);
            let (tx, mut rx) = mpsc::channel(8);
            coverage.record_stored_event(&id, relay, 150);
            coverage
                .stage_delivery(
                    delivery(0, 150, 1, &id, 1),
                    Some(relay),
                    ReplayInput::History,
                    &tx,
                )
                .unwrap();
            assert!(sent(&mut rx).is_empty(), "its REQ has no EOSE yet");
            let mut state = AdapterState {
                replay_losses: losses,
                source_clock: coverage.changes.clock.clone(),
                ..AdapterState::default()
            };
            state.replay_fencing.insert(account());
            state.account_replay_coverage.insert(account(), coverage);
            // The replaced REQ went out with the fresh REQs' relay as relay 1.
            state
                .relay_index
                .index_for(&TransportEndpoint("wss://b.example".to_owned()));
            let a = TransportEndpoint("wss://a.example".to_owned());
            assert_eq!(state.relay_index.index_for(&a), RelayIndex(1));
            let mut fresh_route = route(0);
            if let NostrSubscription::Group { since, .. } = &mut fresh_route {
                *since = Some(Timestamp(fresh_since));
            }
            let batch = pack_group_batches(
                &account(),
                &[fresh_route],
                SubscriptionAttempt::INITIAL.next(),
                0,
            )
            .remove(0);
            state.record_account_replay_start(&account(), std::slice::from_ref(&batch));
            assert_eq!(pending_loss(&state.replay_losses), lost);
            if lost.is_none() {
                let fresh = batch.subscription_id();
                let coverage = state.account_replay_coverage.get_mut(&account()).unwrap();
                coverage.record_stored_event(&fresh, RelayIndex(1), 150);
                coverage
                    .stage_delivery(
                        delivery(0, 150, 1, &fresh, 1),
                        Some(RelayIndex(1)),
                        ReplayInput::History,
                        &tx,
                    )
                    .unwrap();
                coverage.record_eose(&fresh, RelayIndex(1));
                coverage.apply_fence_plan(&plan(coverage, &[]));
                let mut out = released(coverage);
                out.extend(sent(&mut rx));
                assert_eq!(out, vec![(0, 150)], "the fresh REQ replays it");
            }
        }
    }

    /// A plan computed before a count became a fact does not answer it: the
    /// owner's fences are a query of the counts it saw.
    #[tokio::test]
    async fn a_plan_answers_only_the_counts_its_ticket_saw() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        let stale = plan(&coverage, &[]);
        replay(&mut coverage, &id, &[(0, 150)], &tx);
        coverage.apply_fence_plan(&stale);
        assert_eq!(held_from(&coverage, 0), Some(SINCE));
        assert!(released(&mut coverage).is_empty());
        coverage.apply_fence_plan(&plan(&coverage, &[]));
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
    }

    /// A count whose generation ends before its boundary is admitted is no
    /// fact and fences nothing: its arming goes with it.
    #[tokio::test]
    async fn a_count_ended_before_admission_fences_nothing() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        // Relay 2 is still replaying, so relay 1's boundary waits for it.
        coverage.record_stored_event(&id, RelayIndex(2), 140);
        coverage.record_stored_event(&id, RelayIndex(1), 150);
        coverage
            .stage_delivery(
                delivery(0, 150, 1, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::History,
                &tx,
            )
            .unwrap();
        coverage.record_eose(&id, RelayIndex(1));
        assert_eq!(held_from(&coverage, 0), Some(SINCE), "armed at its EOSE");
        assert!(!coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
        coverage.restart_relay(
            RelayIndex(1),
            ReplayRestart::Connection,
            ReplayOrigin::Changed,
            None,
            None,
        );
        coverage.prune_fence_armings();
        assert_eq!(held_from(&coverage, 0), None);
    }

    /// A count the relay closes and the SDK sends again ends unadmitted: the
    /// restored reply's empty recount fences nothing, and nothing of the
    /// closed count still holds.
    #[tokio::test]
    async fn an_empty_recount_after_a_kept_close_holds_nothing() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        // Relay 2 is still replaying, so relay 1's boundary waits for it.
        coverage.record_stored_event(&id, RelayIndex(2), 140);
        coverage.record_stored_event(&id, RelayIndex(1), 150);
        coverage
            .stage_delivery(
                delivery(0, 150, 1, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::History,
                &tx,
            )
            .unwrap();
        coverage.record_eose(&id, RelayIndex(1));
        assert_eq!(held_from(&coverage, 0), Some(SINCE));
        assert!(!coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
        coverage.record_refusal(&id, RelayIndex(1), SubscriptionRefusalDisposition::Pending);
        assert_eq!(held_from(&coverage, 0), None, "the count ended unadmitted");
        coverage.record_eose(&id, RelayIndex(1));
        assert!(
            coverage.endpoint_deadlines[&id][&RelayIndex(1)]
                .live_count
                .is_some_and(|count| count.events == 0),
            "the restored reply counted nothing"
        );
        assert_eq!(held_from(&coverage, 0), None);
        coverage.prune_fence_armings();
        assert_eq!(held_from(&coverage, 0), None);
    }

    /// A newer count that does not fence retires the endpoint's earlier
    /// counts that never became facts, however its earlier count ended.
    #[tokio::test]
    async fn a_newer_empty_count_retires_an_unadmitted_arming() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        coverage.record_stored_event(&id, RelayIndex(2), 140);
        coverage.record_stored_event(&id, RelayIndex(1), 150);
        coverage
            .stage_delivery(
                delivery(0, 150, 1, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::History,
                &tx,
            )
            .unwrap();
        coverage.record_eose(&id, RelayIndex(1));
        assert_eq!(held_from(&coverage, 0), Some(SINCE));
        // The count ends with nothing pruning at once.
        coverage
            .endpoint_deadlines
            .get_mut(&id)
            .unwrap()
            .get_mut(&RelayIndex(1))
            .unwrap()
            .hold_live_count(true);
        assert_eq!(held_from(&coverage, 0), Some(SINCE), "not yet pruned");
        coverage.record_eose(&id, RelayIndex(1));
        assert_eq!(held_from(&coverage, 0), None);
    }

    /// An acknowledgement that admits a boundary after its count ended makes
    /// no arming of that count a fact, so the next prune drops it.
    #[tokio::test]
    async fn an_ended_count_admitted_later_is_no_fact() {
        for immediate_prune in [false, true] {
            let (mut coverage, id, _) = fenced_coverage(true);
            let (tx, _rx) = mpsc::channel(8);
            replay(&mut coverage, &id, &[(0, 150)], &tx);
            coverage.apply_fence_plan(&plan(&coverage, &[]));
            assert_eq!(released(&mut coverage), vec![(0, 150)]);
            coverage.restart_relay(
                RelayIndex(1),
                ReplayRestart::Connection,
                ReplayOrigin::Changed,
                None,
                None,
            );
            coverage.record_stored_event(&id, RelayIndex(1), 160);
            coverage
                .stage_delivery(
                    delivery(0, 160, 2, &id, 1),
                    Some(RelayIndex(1)),
                    ReplayInput::History,
                    &tx,
                )
                .unwrap();
            coverage.record_eose(&id, RelayIndex(1));
            assert_eq!(held_from(&coverage, 0), Some(SINCE));
            assert!(!coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
            if immediate_prune {
                coverage.end_relay_live_counts(RelayIndex(1));
                assert_eq!(held_from(&coverage, 0), None);
            } else {
                // End the count without pruning: ACK must not admit its stale arming.
                coverage
                    .endpoint_deadlines
                    .get_mut(&id)
                    .unwrap()
                    .get_mut(&RelayIndex(1))
                    .unwrap()
                    .end_live_count();
            }
            coverage.ack_placement(&delivery(0, 150, 1, &id, 1).message.id);
            if !immediate_prune {
                assert!(coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
                assert!(
                    coverage.groups[&group_id(0)]
                        .fence
                        .as_ref()
                        .is_some_and(|fence| fence
                            .armed
                            .iter()
                            .all(|arming| arming.answerable.is_none())),
                    "the ended count is no fact"
                );
            }
            coverage.prune_fence_armings();
            assert_eq!(held_from(&coverage, 0), None);
            assert_eq!(released(&mut coverage), vec![(0, 160)]);
        }
    }

    /// A full reply admits the received input behind its fence without
    /// certifying that the relay served the original query completely: the
    /// recovery runner owes the rest.
    #[tokio::test]
    async fn a_full_live_reply_delegates_debt_without_certifying_complete_history() {
        let (mut coverage, id, _) = fenced_coverage(true);
        for at in 0..RELAY_REPLAY_PAGE_LIMIT as u64 {
            coverage.record_stored_event(&id, RelayIndex(1), SINCE + at);
        }
        coverage.record_eose(&id, RelayIndex(1));
        assert!(
            coverage.endpoint_deadlines[&id][&RelayIndex(1)]
                .live_count
                .is_some_and(|count| count.clamped())
        );
        assert_eq!(coverage.snapshot().relay_subscription_attempts_with_eose, 0);
        for group in [0, 1] {
            assert_eq!(held_from(&coverage, group), Some(SINCE));
        }
        assert!(coverage.endpoint_deadlines[&id][&RelayIndex(1)].boundary_admitted);
    }

    /// Delegated history may take arbitrarily many bounded requests. Neither
    /// waiting for the owner nor draining its backlog expires into newer input.
    #[tokio::test(start_paused = true)]
    async fn delegated_backlog_releases_only_as_its_owner_advances() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150), (0, 300)], &tx);

        tokio::time::advance(REPLAY_WAIT_LIMIT * 2).await;
        coverage.expire_replay(tokio::time::Instant::now());
        assert_eq!(held_from(&coverage, 0), Some(SINCE), "await the owner");
        assert!(released(&mut coverage).is_empty());

        coverage.apply_fence_plan(&plan(&coverage, &[(0, 150)]));
        for _ in 0..3 {
            tokio::time::advance(REPLAY_WAIT_LIMIT * 2).await;
            coverage.expire_replay(tokio::time::Instant::now());
            assert!(
                released(&mut coverage).is_empty(),
                "older work is still owed"
            );
        }
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 200)]));
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
        assert_eq!(held_from(&coverage, 0), Some(200));

        tokio::time::advance(REPLAY_WAIT_LIMIT * 2).await;
        coverage.expire_replay(tokio::time::Instant::now());
        assert!(
            released(&mut coverage).is_empty(),
            "the remaining backlog holds"
        );
        coverage.apply_fence_plan(&plan(&coverage, &[]));
        assert_eq!(released(&mut coverage), vec![(0, 300)]);
        assert_eq!(held_from(&coverage, 0), None);
    }

    /// A fence holds its own group, never the account or the request: other
    /// groups' frames flow, the account's admission is not pending, and the
    /// request counts as placed apart from the fenced group's routes.
    #[tokio::test]
    async fn a_fenced_group_leaves_other_groups_alone() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, mut rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150), (1, 160)], &tx);
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 120)]));
        assert_eq!(released(&mut coverage), vec![(1, 160)]);
        coverage.ack_placement(&delivery(1, 160, 2, &id, 1).message.id);
        assert!(!coverage.admission_pending(), "held frames are not pending");
        assert!(coverage.request_groups_placed(&id, true));
        assert!(
            !coverage.request_groups_placed(&id, false),
            "a fetch that waits on the request still waits for its held frames"
        );
        assert_eq!(
            coverage.fence_held_since(0),
            Some(150),
            "the cursor stops there"
        );
        coverage
            .stage_delivery(
                delivery(1, 500, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        assert_eq!(sent(&mut rx), vec![(1, 500)]);
        assert_eq!(held_from(&coverage, 0), Some(120));

        coverage.apply_fence_plan(&plan(&coverage, &[]));
        assert!(coverage.admission_pending(), "released, not yet placed");
        assert!(!coverage.request_groups_placed(&id, true));
        assert_eq!(coverage.fence_held_since(0), None);
    }

    /// A plan read before the last one applied moves no fence: its points
    /// would undo what the newer plan holds.
    #[tokio::test]
    async fn a_stale_plan_moves_no_fence() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150), (0, 300)], &tx);
        let stale = ReplayFencePlan {
            ticket: ReplayFenceTicket(coverage.fence_ticket - 1),
            fences: Vec::new(),
        };
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 200)]));
        coverage.apply_fence_plan(&stale);
        assert_eq!(held_from(&coverage, 0), Some(200));
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
    }

    /// Without native ingress, a hand-off waiting for channel capacity
    /// rejoins the buffer only for an arrival to sort in, never for frames a
    /// fence holds behind it. A fence that moves below it does not call it
    /// back: it already left, so it goes on as late input.
    #[tokio::test]
    async fn a_held_suffix_never_sends_a_hand_off_back() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150), (0, 300)], &tx);
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 200)]));
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
        let outgoing = delivery(0, 150, 1, &id, 1);
        assert!(!coverage.draining_rejoins(&outgoing), "held 300 stays held");
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 120)]));
        assert!(
            !coverage.draining_rejoins(&outgoing),
            "a fence below the hand-off does not recall it"
        );
    }

    /// A hand-off that rejoins the buffer keeps its pin until its next
    /// hand-off, but once a lower plan holds it there it is held, not placed:
    /// the account's admission is not pending, and its request's boundaries
    /// are admitted.
    #[tokio::test]
    async fn a_restored_hand_off_a_fence_covers_is_not_pending() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150), (0, 300)], &tx);
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 200)]));
        let outgoing = delivery(0, 150, 1, &id, 1);
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
        // An arrival below the fence sorts in while 150 waits for capacity.
        coverage.flushing = true;
        coverage
            .stage_delivery(
                delivery(0, 160, 9, &id, 1),
                Some(RelayIndex(1)),
                ReplayInput::Live,
                &tx,
            )
            .unwrap();
        assert!(coverage.draining_rejoins(&outgoing));
        coverage.restore_draining(VecDeque::from([outgoing]));
        coverage.flushing = false;
        assert!(
            !coverage.request_groups_placed(&id, true),
            "pinned and unheld"
        );

        coverage.apply_fence_plan(&plan(&coverage, &[(0, 120)]));
        assert_eq!(coverage.fence_held_items(), 3);
        assert!(!coverage.admission_pending(), "held frames, not placements");
        assert!(coverage.request_groups_placed(&id, true));
        assert!(!coverage.request_groups_placed(&id, false));
        // A new count's boundary is admitted past the held pin.
        coverage.restart_relay(
            RelayIndex(2),
            ReplayRestart::Connection,
            ReplayOrigin::Changed,
            None,
            None,
        );
        coverage.record_eose(&id, RelayIndex(2));
        assert!(coverage.endpoint_deadlines[&id][&RelayIndex(2)].boundary_admitted);
        coverage.apply_fence_plan(&plan(&coverage, &[]));
        assert_eq!(released(&mut coverage), vec![(0, 150), (0, 160), (0, 300)]);
        assert_eq!(coverage.groups[&group_id(0)].placements, 3);
    }

    /// Only a hand-off that rejoined the buffer has its pin exempted: a held
    /// history copy of a frame whose first copy is still out leaves that
    /// copy's pin pending.
    #[tokio::test]
    async fn a_held_copy_leaves_a_pin_still_out_pending() {
        let (mut coverage, id, _) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150)], &tx);
        coverage.apply_fence_plan(&plan(&coverage, &[]));
        assert_eq!(released(&mut coverage), vec![(0, 150)]);
        coverage.restart_relay(
            RelayIndex(2),
            ReplayRestart::Connection,
            ReplayOrigin::Changed,
            None,
            None,
        );
        coverage.record_stored_event(&id, RelayIndex(2), 150);
        coverage
            .stage_delivery(
                delivery(0, 150, 1, &id, 1),
                Some(RelayIndex(2)),
                ReplayInput::History,
                &tx,
            )
            .unwrap();
        coverage.record_eose(&id, RelayIndex(2));
        assert_eq!(held_from(&coverage, 0), Some(SINCE));
        assert_eq!(coverage.fence_held_items(), 1);
        assert!(coverage.admission_pending(), "the first copy is still out");
        assert!(!coverage.request_groups_placed(&id, true));
    }

    /// Held frames stay inside the replay buffer's bounds: what does not fit
    /// is loss, as it is for any frame.
    #[tokio::test]
    async fn held_frames_that_overflow_the_buffer_are_loss() {
        let (mut coverage, id, losses) = fenced_coverage(true);
        let (tx, _rx) = mpsc::channel(8);
        replay(&mut coverage, &id, &[(0, 150)], &tx);
        coverage.apply_fence_plan(&plan(&coverage, &[(0, 120)]));
        let frame = REPLAY_BUFFER_MAX_BYTES / 3 + 1;
        for seed in 10..13 {
            coverage
                .stage_delivery(
                    delivery(0, 200 + u64::from(seed), seed, &id, frame),
                    Some(RelayIndex(1)),
                    ReplayInput::Live,
                    &tx,
                )
                .unwrap();
        }
        assert!(
            losses.pending.lock().unwrap().contains_key(&account()),
            "the frame that did not fit is lost"
        );
        assert_eq!(coverage.groups[&group_id(0)].events.len(), 3);
    }
}
