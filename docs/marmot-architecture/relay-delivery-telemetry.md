# Relay Delivery Telemetry and Quiescence Tuning

**Status:** design draft. This is the target model for measuring Nostr relay delivery behavior so that convergence
quiescence can be tuned from evidence instead of guessed.

This note is the measurement companion to [`distributed-convergence.md`](./distributed-convergence.md). Convergence
defines *how* a client selects a canonical branch from a bag of unordered messages. This note defines *how a client
decides it has waited long enough* before settling, and what it must measure to choose that wait well. Privacy rules for
any emitted signal come from [`overview/observability.md`](./overview/observability.md).

## Problem

A client can never prove it has every message a group has produced. A commit may sit on a relay it does not query, or be
withheld, and in an open asynchronous system there is no way to distinguish "does not exist" from "not delivered to me."
Completeness is unsolvable in the strong sense, and no ordering or consensus mechanism changes that.

The convergence model already accepts this. It does not try to *achieve* completeness; it makes gaps **detectable** (a
commit whose parent is unknown is deferred, not applied) and **bounds the damage** of a missing message (`max_rewind_commits`
plus witness quorum). What remains is the one place where the design still substitutes a heuristic for completeness: the
decision to stop waiting and settle. Today that decision is `settlement_quiescence_ms`, a group-negotiated constant. We
do not have a principled basis for its value.

This note specifies what to measure to set it, and how the measurement maps onto the convergence machine.

### Considered and rejected: Lamport clocks and BFT

We evaluated two structural changes and rejected both. Recording the rationale here so it is not relitigated.

- **Lamport (and vector) clocks.** A Lamport clock is a strictly weaker version of the MLS commit chain we already
  have: the chain links each commit to its parent epoch state cryptographically, so it encodes happens-before with
  authentication, which a self-asserted counter cannot. Clock values are forgeable, so they add nothing in the
  adversarial setting the protocol targets, and `spec/principles.md` already forbids transport-supplied ordering from
  choosing group state for exactly this reason. A scalar Lamport timestamp also does not detect gaps; only a vector
  clock does, and only per sender, which the parent-link already does better. A signed, in-payload **per-sender
  monotonic counter** is the one idea in this family worth keeping, but only as an anti-entropy hint (see
  [Backfill and reconciliation](#backfill-and-reconciliation)), not as state-machine input.
- **BFT consensus.** Classical BFT gives a single agreed order with instant finality, but needs an online quorum and
  multi-round voting over a known validator set. Group-chat members are asynchronously offline, and membership is the
  very thing commits change, so BFT would trade away the offline-tolerance and leaderlessness Marmot is built on. It
  also does not touch the relay-completeness problem: the relays are the asynchronous network the consensus must
  tolerate, not the consensus nodes. The convergence model is already a consensus protocol of the right family for this
  setting — a weighted fork-choice rule (heaviest valid branch by `effective_commit_depth`, attestation weight via
  witness quorum, bounded reorg via `max_rewind_commits`) rather than a quorum-voting one.

## What quiescence actually measures

The naive instinct is to measure relay latency and set quiescence above it. That is the wrong quantity. Quiescence does
not protect against *slow* delivery; it protects against the gap between when the last message arrived and when a
still-in-flight message *would* arrive. The quantity that bounds that gap is the **straggler delay**: for a message that
genuinely exists and is delivered, how much later does its slowest copy show up.

### Separate the two delay sources

Straggler delay has two modes, and only one is coverable by a timer:

- **Delivery jitter:** network and relay flush time for a message that is in flight now. Milliseconds to seconds.
  Bounded, measurable, and what quiescence should cover.
- **Offline republish delay:** a member that was offline reconnects and publishes a commit created earlier. Minutes to
  days. Unbounded. A timer must **not** try to cover this; tuning quiescence against the full straggler distribution
  pins clients in `Syncing` indefinitely (`distributed-convergence.md` warns about the over-high value).

Offline republish is exactly the late-commit case the rollback horizon and witness quorum already handle: such a commit
lands after the client settles and triggers a bounded reorg within `max_rewind_commits`. Therefore quiescence is tuned
against the **delivery-jitter mode only**, and late commits beyond it are a convergence concern, not a timer concern.

### The loss function

Quiescence is not a correctness boundary. Setting it too low costs extra post-settle reorgs and regenerated intents
(annoying, never corrupting — convergence safety holds because both clients converge given the same inputs). Setting it
too high costs liveness: the client stalls in `Syncing`. The objective is therefore to **minimize stall time subject to
keeping the post-settle reorg rate under a target**, where the reorg rate is itself observable. The delivery-jitter
distribution gives one side of that trade; the observed reorg rate gives the other.

### The headline metric: cross-relay arrival spread

Because a group publishes redundantly to multiple relays, the most direct estimator of delivery jitter is already
available without any new protocol: for every message received on more than one relay endpoint, record the delta, in
**local receive time**, between the first copy and each later distinct-endpoint copy. The distribution of those deltas is
the delivery-jitter distribution of the client's own relay set. A high percentile of it (p99-ish) plus margin is the
delivery-jitter quiescence floor.

Local receive time is mandatory here. Nostr `created_at` is identical across copies of the same event and is
publisher-controlled, so it conveys nothing about delivery timing and must never be used as the telemetry clock.

## Two quiescence regimes

"What should quiescence be?" is hard partly because two different situations are conflated. They want different values
and different signals.

- **Initial-sync quiescence.** A reconnecting client is draining stored history from each relay. The natural completion
  signal is not a timer but **EOSE** (end of stored events): once every subscribed relay in the set has sent EOSE for the
  group subscription, the client has each relay's stored set, and a content-level **set reconciliation** pass
  (see below) closes residual gaps. A timer is only the fallback for relays that never send EOSE.
- **Steady-state live quiescence.** A connected client is waiting out the tail of in-flight live messages. Here the
  EOSE signal does not apply and the **cross-relay arrival-spread timer** governs.

Modeling these separately lets each take its appropriate signal instead of forcing one constant to cover both.

## Metric catalogue

All metrics below are local, aggregate, and privacy-safe per [`observability.md`](./overview/observability.md). All
timing is local-receive-time monotonic duration; none uses `created_at`, event ids, relay URLs, or payload-derived
values in any emitted form.

| Metric | Definition | Feeds |
| --- | --- | --- |
| `cross_relay_spread` | Per message seen on ≥2 endpoints: histogram of local-time delta from first copy to each later distinct-endpoint copy. | Steady-state quiescence floor. |
| `corroborated` / `single_source` | Count of messages seen on ≥2 endpoints vs. exactly one within the tracking window. | Relay redundancy health; confidence in the spread estimate. |
| `time_to_first_event` | Per relay (opaque local index): local time from subscription start to first matching event. | Subscription health, slow-relay deprioritization. |
| `time_to_eose` | Per relay: local time from subscription start to EOSE. | Initial-sync gating; relays that never EOSE. |
| `observed_reorg_rate` | Rate of post-settle convergence reorgs attributable to late delivery within the horizon. | The other side of the quiescence loss function. |

`cross_relay_spread` is the foundational one and is self-contained in the transport adapter. The first-event and EOSE
timing land via the raw per-relay event/EOSE stream (phase 2; see [Instrumentation interface](#instrumentation-interface)).
`observed_reorg_rate` is owned by the engine, not the adapter, and is recorded against settle outcomes — specified in
[Validation: post-settle reorg rate](#validation-post-settle-reorg-rate).

## Choosing the static value

`settlement_quiescence_ms` is a single group-negotiated constant. It is **not** computed per client and it does **not**
adapt at runtime. The point of this telemetry is the opposite of auto-tuning: it lets an operator choose the right
constant from real data, once, and set it in group policy. The procedure is offline:

- **Gather.** Collect `cross_relay_spread` (and, for the initial-sync side, the EOSE / first-event timing) across the
  real relay population and real groups, aggregated into the histograms this telemetry already produces.
- **Read the distribution.** Pick a candidate operating point — for example a high percentile of the steady-state spread
  plus margin. The loss function is asymmetric: too low costs extra post-settle reorgs (observable as
  `observed_reorg_rate`), too high costs liveness. Move the candidate until the reorg rate is acceptable.
- **Set the constant.** Encode the chosen value in the negotiated convergence policy. Every member processing an epoch
  uses the same policy bytes; this is not a local preference.

The existing policy already treats `settlement_quiescence_ms` as a floor a client MAY exceed, but only as a deliberate
static configuration choice — never derived from a client's own live measurements. The measurement-to-value step is a
human decision fed by dashboards, not a runtime controller.

## Validation: post-settle reorg rate

`observed_reorg_rate` is the engine-side half of the [loss function](#the-loss-function): it measures how often settling
turned out to be premature, which is the only direct evidence that a chosen `settlement_quiescence_ms` is *too low*. The
spread distribution tells you what value *might* be safe; the reorg rate tells you whether it *was*.

### What a reorg is, in engine terms

The engine reaches `Settled` when quiescence has elapsed and every pending input has a disposition
(`ConvergenceStatus::Settled`, `crates/cgka-engine/src/canonicalization.rs`). It then applies the selected canonical
branch (`set_stable`) and emits `GroupEvent::EpochChanged { from, to }`. A **post-settle reorg** is the case where, after
a group has applied a canonical branch while `Settled`, a later canonicalization pass — triggered by a commit that
arrived *after* that settle, with a `fork_epoch` at or above the retained anchor (i.e. within `max_rewind_commits`) —
selects a *different* canonical branch that diverges at or below the previously-applied tip. This is the engine's
existing fork-recovery path (`GroupEvent::ForkRecovered { source_epoch, recovered_epoch, winner, invalidated }`,
`crates/cgka-engine/src/fork_recovery.rs`); losing-branch app messages are re-dispositioned
`InvalidatedAppMessageReason::LosingBranch`.

A normal forward advance — where the selected branch extends the previously-applied one — is **not** a reorg. The engine
does not distinguish these today; both surface as `EpochChanged`. So the metric requires a small addition: a per-group
record of the last branch applied while `Settled` (its tip, branch id, and the local settle time), against which the
next applied selection is classified.

### What to record

Engine-side, aggregate across groups, local-monotonic timing, never `created_at`:

| Signal | Shape | Why |
| --- | --- | --- |
| `settles` | counter | denominator: settle episodes, summed across groups |
| `post_settle_reorgs` | counter | numerator: settles later superseded by a diverging branch |
| `reorg_rewind_depth` | histogram (commits) | `previous_applied_tip - new_fork_epoch`; how deep the rewind was, vs. `max_rewind_commits` |
| `reorg_lateness_ms` | histogram (ms) | local time from the superseded settle to the reorg — **how much more quiescence would have prevented it** |

`observed_reorg_rate = post_settle_reorgs / settles` is derived. `reorg_lateness_ms` is the most directly actionable
signal of all: its distribution is exactly the extra wait that would have avoided each reorg, so a high percentile of it
is the empirical correction to add on top of the cross-relay-spread floor when
[choosing the static value](#choosing-the-static-value).

### Where it lives

`EngineMetrics` ([`crates/cgka-engine/src/engine_metrics.rs`](../../crates/cgka-engine/src/engine_metrics.rs)) is the
counters struct on `Engine<S>`. It is incremented at the apply/settle site
(`crates/cgka-engine/src/distributed_convergence.rs`, where `set_stable` runs and `EpochChanged` is emitted), keeps a
per-group in-memory last-applied record (tip, branch id, settle time, and a settled-since-apply flag) for reorg
classification, and is read through the `Engine::engine_metrics()` accessor alongside the existing `drain_events()`. The
classifier uses the selected branch's fork epoch (now surfaced on `CanonicalizationResult::selected_fork_epoch`): a
settle whose new branch differs from the prior settled branch and forks *strictly below* the previously-applied tip is a
post-settle reorg; forking *at* the tip is a forward advance and is not counted.

Like all telemetry here it is **diagnostic only and must never feed convergence or branch selection**, and the snapshot
(`EngineMetricsSnapshot`) carries only counts and millisecond/commit buckets — no group ids, epochs, branch ids, or
member ids in any emitted form. Because it is engine-side it is not an adapter metric; it joins the export path through
the relay-plane rollup and ships to Grafana over the same OTLP exporter as the relay metrics.

### Open questions

- **Reorgs during `Resolving`.** Only *post-`Settled`* reorgs reflect premature settling; a re-selection while still
  `Resolving` (before the app was told anything) is normal convergence, not a tuning signal. The classifier gates on
  "the superseded branch was observed in a `Settled` pass," which the per-group record tracks.
- **Denominator choice.** `reorgs / settles` is the natural rate, but `reorgs / canonical-advances` or a per-unit-time
  rate may read better on a dashboard; the raw counters are exported so the operating choice stays open.
- **Restart semantics.** The per-group last-applied record is in-memory; after a restart the first settle re-establishes
  it and is not classified as a reorg. That under-counts slightly across restarts and is acceptable for a tuning signal.

## Backfill and reconciliation

The current fetch path resubscribes with a `since = last_synced - backfill` hint. This is a fine cheap default but has a
structural blind spot that overlaps the convergence-critical case: a commit created offline and published late can carry
a `created_at` earlier than `last_synced`, so a `since` filter excludes it at the relay. That is precisely a valid late
commit inside the rollback horizon — the input branch selection most needs to see.

Two layers address this:

- **Timestamp backfill** stays as the fast path for honestly-recent late delivery on queried relays.
- **Set reconciliation** (Nostr Negentropy, NIP-77) is the correctness backstop: it is content-addressed and
  time-independent, so a backdated-but-present event is reconciled regardless of `created_at`. It cannot recover events
  on relays the client never queries — nothing can — but it converts a silent backdated miss into a detected-and-fetched
  one. It composes cleanly because the engine already treats transport order as advisory; reconciliation just feeds more
  candidate bytes into the same convergence pass.

A signed, in-payload **per-sender monotonic counter** is an optional further hint: a client that holds sender A's #5 and
#7 but not #6 knows to delay settling and re-fetch. It is protocol evidence (inside the MLS payload, signed), so it is
admissible where transport timestamps are not, but it is a liveness aid, never a branch-selection input, and it adds
equivocation surface (a doubled counter is just a fork the engine already detects).

## Instrumentation interface

Telemetry extends the adapter's existing diagnostic surface rather than introducing a parallel one. The pattern to match
is `NostrAdapterMetrics` (aggregate lifecycle counters, explicitly barred from feeding convergence) and
`NostrSdkRelayHealth` (redacted aggregate relay status).

There are **two distinct relay taps**, and conflating them silently breaks the spread metric. `nostr-sdk` 0.44 emits a
`RelayPoolNotification::Event` only the **first time** an event is seen across the pool (deduplicated against its shared
database), but emits a `RelayPoolNotification::Message` for **every** relay copy, carrying that relay's URL. So:

- **Delivery tap** consumes the deduplicated `Event` notification (`handle_relay_event`): each message is routed to the
  engine once. It records lifecycle metrics only and MUST NOT record spread or first-event timing — on this path it
  would only ever see the first relay's copy.
- **Telemetry tap** consumes the raw per-relay `Message`/`RelayMessage::Event` stream (`observe_relay_event`): it records
  `cross_relay_spread` (keyed by the transport-independent `TransportMessage.id`) and per-relay first-event timing,
  seeing every relay copy. Timing uses a local monotonic clock captured at the adapter, never `created_at`. The
  per-message first-sighting table is local-only ephemeral state, pruned on a window; its keys never leave the device or
  appear in logs.
- **EOSE tap** consumes the per-relay `Message`/`RelayMessage::EndOfStoredEvents` stream (`handle_relay_eose`): it
  advances the initial-sync gate (`subscription_synced`) and records EOSE latency.

This split depends on the SDK deduplicating against a real event database (true for the default in-memory store); a
no-op store would make the `Event` path double-deliver. The snapshot accessors return only aggregate histogram buckets
and counts; any future per-relay breakdown uses opaque local indices, never URLs. `observed_reorg_rate` is recorded by
the engine against settle outcomes and is out of scope for the adapter.

## Phasing

1. **Cross-relay arrival spread (foundational).** *Done.* Self-contained in the transport adapter; no protocol change.
   Gives the steady-state quiescence distribution and relay-redundancy health.
   ([`telemetry::RelayDeliveryTelemetry`](../../crates/transport-nostr-adapter/src/telemetry.rs)).
2. **EOSE plumbing and sync timing.** *Done.* Routes EOSE into the adapter, exposing the per-subscription initial-sync
   gate (`subscription_synced`) plus first-event / EOSE latency histograms relative to subscribe time, both in aggregate
   and per relay behind opaque local indices
   ([`telemetry::RelaySyncTelemetry`](../../crates/transport-nostr-adapter/src/telemetry.rs)). *Resolving* those opaque
   indices to relay identity for export is the broad-observability workstream
   ([`relay-observability.md`](./relay-observability.md)).
3. **Engine-side reorg-rate telemetry.** *Done.* Closes the quiescence loss function by measuring post-settle reorgs.
   `EngineMetrics` records `settles`, `post_settle_reorgs`, `reorg_rewind_depth`, and `reorg_lateness_ms` at the
   convergence apply site and exposes them via `Engine::engine_metrics()`
   ([`crates/cgka-engine/src/engine_metrics.rs`](../../crates/cgka-engine/src/engine_metrics.rs)); see
   [Validation: post-settle reorg rate](#validation-post-settle-reorg-rate).
4. **Set the static value from data.** Aggregate (1) and (3) over real relays and groups, read the distributions, and
   choose the negotiated `settlement_quiescence_ms`. An offline operator/analysis step, not a runtime controller.
5. **Set reconciliation (NIP-77).** Fetch-completeness backstop for backdated late commits.

Each phase is independently useful and independently shippable, and (1) de-risks the rest by telling us what our relay
population actually looks like before we commit to (4) or (5).

## Relation to broad relay observability

This note is scoped to *convergence tuning*: every metric here exists to inform a quiescence decision, stays
device-local, and carries no relay identity. A separate, larger workstream wants per-relay **performance** telemetry
(latency, EOSE timing, delivery success, kind acceptance, negentropy sync health) exported to an operator metrics stack
so relays can be ranked good-vs-bad, including a self-hosted strfry fleet that reconciles internally over negentropy.

That workstream is distinct and has its own design doc — [`relay-observability.md`](./relay-observability.md) — because
ranking relays requires relay identity in exported metrics, which the current
[`observability.md`](./overview/observability.md) rule forbids. The agreed direction is:
**relay-identified metrics MAY leave the device to a first-party metrics stack, but only aggregated, opt-in, and behind
k-anonymity thresholds**; that decision will be carried into an `observability.md` amendment when the broad-telemetry
workstream starts. Until then, the per-relay timing in phase 2 keeps relays as opaque device-local indices and exports
nothing. The convergence telemetry here becomes one *consumer* of the shared per-relay collection layer that
broad observability will own (most naturally in the relay plane), not a parallel measurement stack.

## Open questions

- What percentile and margin of `cross_relay_spread` give an acceptable post-settle reorg rate in practice? Phase 1
  produces the data to answer this; the value is empirical, not assumed.
- Should the initial-sync gate require EOSE from *all* subscribed relays, or a quorum of them, when one relay is
  persistently silent? A strict all-relays gate lets one dead relay stall sync.
- Is the per-sender counter worth its equivocation surface, or does NIP-77 reconciliation make it redundant for the
  gap-detection use it targets?
