---
title: "CGKA Engine Quality And Vectors"
created: 2026-05-11
updated: 2026-05-13
tags: [marmot, overview, cgka, conformance, vectors]
status: working-note
---

# CGKA Engine Quality And Vectors

The main goal of this repository is still the CGKA engine.

Nostr account transport notes help us avoid bad boundaries, but the next large
milestone is an engine that can be plugged into whitenoise-rs with confidence.
That means a clean interface, strong chaos coverage, and test vectors that
another implementation can run.

## Integration Target

The engine should be usable from whitenoise-rs through one of two paths:

- a direct interface change in whitenoise-rs;
- a shim that adapts current whitenoise-rs account, relay, and event handling
  to the new engine/session boundary.

The engine boundary should not pull in Nostr relay-plane state. Nostr identity
and transport data may feed the surrounding session and transport layers, but
the engine should keep accepting post-peeling protocol inputs.

## What Must Be True

The engine is in good shape when:

- the public trait boundary is small enough to explain from the spec;
- publish-before-apply is enforced through pending state confirmation;
- fork recovery and branch selection are deterministic;
- app-visible output is emitted only from the selected MLS branch;
- storage transitions are atomic across OpenMLS state and Marmot metadata;
- replay, duplicate, stale-epoch, and future-epoch inputs have named outcomes;
- tracing remains privacy-safe;
- the same behavior is covered by unit tests, scenario tests, generated chaos,
  and portable vectors where possible.

## Test Layers

The current test stack has useful coverage at several levels:

- engine tests for single-boundary behavior;
- session tests for SQLCipher-backed account-device lifecycle;
- Nostr adapter/peeler integration tests over an in-memory relay client;
- conformance simulator scenarios and portable vector fixtures;
- generated scenario families with JSON reports and fixture candidates;
- property tests for selector, canonicalization, capability, lifecycle,
  restart, and generated send/leave histories;
- Tamarin models for distributed convergence.

The remaining gap is a broader byte-level vector story for encodings and
transport shapes.

## Scenario Vectors

Scenario vectors describe behavior at the client/engine level.

They should contain:

- a stable scenario id;
- participant labels;
- ordered input steps;
- delivery faults such as delay, duplicate, reorder, and partition;
- expected application-visible trace;
- expected pending-state confirmations or rollbacks where relevant.

These vectors are good for independent implementations because they avoid
OpenMLS internals.

The existing `crates/cgka-conformance-simulator/vectors/` format is the right
starting point.

## Byte-Level Vectors

Byte-level vectors are still missing.

They should cover byte formats and boundary behavior that an implementation
must reproduce exactly:

- Marmot wire/event encodings;
- app component state and update bytes;
- post-peeling engine input envelopes;
- stored metadata canonicalization where it is part of the contract;
- exporter output contracts where deterministic test inputs are available;
- error cases for malformed component bytes, invalid relay ordering, duplicate
  relays, and unsupported required components.

Whole-scenario byte stability is not the right portability contract for MLS
group histories. Signatures, HPKE ciphertexts, timestamps, and transport wraps
are allowed to differ across implementations. Scenario fixtures should compare
semantic outcomes: epochs, members, pending publish results, delivered payloads,
invalidations, and recovery events.

The first semantic recovery fixture is `group-data-fork-recovery/v1`. It covers
a same-epoch group-data update race and asserts that the recovering client
reaches epoch 2, observes one recovery from epoch 1 to epoch 2, and records
distinct winner and invalidated ordering keys. It does not assert exact commit
digest bytes.

The first convergence-focused generated chaos family is
`convergence-chaos/v1`. It emits ordinary `ScenarioSpec`s with semantic
expectations for invite forks, group-data forks, publish rollback, partitions
and leaves, delayed past-epoch app messages, duplicate/delay/reorder queue
faults, 20+ client message storms, partitioned large-group storms,
multi-committer group-data storms, and mixed message/commit storms. Each run
writes both a report and a `*-fixture.v1.json` candidate so a high-signal
generated case can become a permanent vector after review. Failing generated
cases also run a conservative greedy minimizer and record a smaller reproducer
when removable app/delivery steps can be dropped without changing the failure
kinds.

Exact byte fixtures still matter where bytes are the spec: component encodings,
transport event shapes, post-peel inputs, and malformed encoding cases.

## Chaos Coverage

Chaos coverage should keep expanding around real failure modes:

- duplicate delivery;
- reordered delivery;
- delayed past-epoch messages;
- future-epoch messages that become peelable later;
- partitions and partition healing;
- lost publish acknowledgements;
- publish failures before pending state confirmation;
- concurrent group evolution;
- invite commit and welcome ordering variants;
- restart/reopen between pending work and confirmation;
- multi-device identity lifecycle cases once `IdentityRemove` exists.

Each new chaos case should have a path to one of:

- a fixed scenario vector;
- a generated scenario family;
- a byte-level fixture;
- a Tamarin scenario name.

## Current Artifacts

- Vector manifest:
  [`../../../crates/cgka-conformance-simulator/vectors/manifest.v1.json`](../../../crates/cgka-conformance-simulator/vectors/manifest.v1.json)
- Byte fixture schema:
  [`../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/schema.v1.json`](../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/schema.v1.json)
- First app-component byte fixtures:
  [`../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/`](../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/)
- First pending rollback scenario vector:
  [`../../../crates/cgka-conformance-simulator/vectors/publish-fail.v1.json`](../../../crates/cgka-conformance-simulator/vectors/publish-fail.v1.json)
- Portable scenario fixtures:
  [`../../../crates/cgka-conformance-simulator/vectors/`](../../../crates/cgka-conformance-simulator/vectors/)
- whitenoise-rs shim map and friction list:
  [`whitenoise-integration-map.md`](./whitenoise-integration-map.md)

## Next Useful Work

The next engine-centered pass should focus on:

1. more byte-level fixtures for transport events, post-peel inputs, malformed
   app-component bytes, and exporter contracts where deterministic inputs are
   available;
2. a cross-language fixture runner guide that explains how TypeScript or another
   implementation consumes `ScenarioSpec` and `VectorFixture`;
3. a relay-backed integration tier that sits above the simulator and below a
   production app;
4. domain-aware minimization for generated failures, once the current greedy
   step remover stops being enough;
5. continued expansion of `convergence-chaos/v1` around large groups,
   multi-device identity lifecycle, and message storms with mixed commits.
