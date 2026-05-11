---
title: "CGKA Engine Quality And Vectors"
created: 2026-05-11
updated: 2026-05-11
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

The current test stack already has useful coverage:

- engine tests for single-boundary behavior;
- session tests for SQLCipher-backed account-device lifecycle;
- Nostr adapter/peeler integration tests over an in-memory relay client;
- conformance simulator scenarios;
- generated scenario families;
- Tamarin models for distributed convergence.

The missing piece is a clearer vector story.

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

OpenMLS commit bytes include fresh randomness, so not every engine scenario can
be regenerated into stable byte-level vectors. For those cases, use either:

- captured fixture bytes with expected outcomes; or
- scenario vectors that abstract over the random byte values and assert the
  stable behavior.

Fork-recovery vectors need special care for this reason.

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

## Near-Term Work

The next engine-centered pass should produce:

1. A vector manifest that names every current scenario and whether it is
   portable, Rust-only, generated, or byte-level.
2. A byte-level fixture schema for component/wire-format vectors.
3. At least one app-component byte vector for
   `marmot.transport.nostr.routing.v1` state and update validation.
4. A whitenoise-rs integration note that lists the adapter or shim methods the
   app core would need.
5. A short list of engine API friction points found while mapping that shim.

The Nostr relay-plane work should proceed only far enough to make that
integration map honest.

## Started Artifacts

- Vector manifest:
  [`../../../crates/cgka-conformance-simulator/vectors/manifest.v1.json`](../../../crates/cgka-conformance-simulator/vectors/manifest.v1.json)
- Byte fixture schema:
  [`../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/schema.v1.json`](../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/schema.v1.json)
- First app-component byte fixtures:
  [`../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/`](../../../crates/cgka-conformance-simulator/vectors/byte-fixtures/)
- First pending rollback scenario vector:
  [`../../../crates/cgka-conformance-simulator/vectors/publish-fail.v1.json`](../../../crates/cgka-conformance-simulator/vectors/publish-fail.v1.json)
- whitenoise-rs shim map and friction list:
  [`whitenoise-integration-map.md`](./whitenoise-integration-map.md)
