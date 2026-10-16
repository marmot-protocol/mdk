---
title: "Extraction Brief — Relay Plane into transport-nostr"
created: 2026-10-15
updated: 2026-10-16
tags: [marmot, architecture, review, extraction-brief, transport, nostr]
status: proposed, needs approval before implementation
---

# Extraction Brief — Relay Plane into `transport-nostr`

Step 2 of the [core structure plan](core-structure.md#5-sequencing). It moves the relay plane out of `marmot-app` into
a new `transport-nostr` crate, without changing behaviour. Line counts are production code, measured at baseline
`b76b5338e`, which includes the multi-thread runtime from #2340. `path:line` citations are at `15c4b4aab` (#2361 on
master, after #2341 and #2354), which #2346's branch merged in before it landed. Following the
[review's evidence rules](README.md#evidence-rules),
statements are observed in source unless marked (hypothesis).

## Why this seam first

- **It is the most separable part of `marmot-app`.** `relay_plane/` is about 5.1k production lines. About 10% of it is
  methods on the app's hub objects, and it imports only four things from the rest of the crate (see "Edges to cut
  before moving").
- **It gives transport work a home.** The size handling and coverage surface from [Pass 1 E](e-transport.md#9-recommendations),
  and the per-group transport evidence that [Pass 1 B](b-runtime-concurrency.md#5-options) needs, all belong in the
  transport layer. Today the only place for them is inside `marmot-app`.
- **It removes the app's role as a transport implementation.** After the move, `marmot-app` composes the transport and
  no longer implements it.

## Decision: a new crate on top of the adapter

Create `crates/transport-nostr`, depending on `transport-nostr-adapter` and `transport-nostr-peeler`, rather than
merging into the adapter.

- The relay plane already compiles against the adapter's public API, because it lives in another crate today, so the
  move needs no adapter changes.
- The adapter keeps an SDK-free core, available with its `sdk` feature disabled (the default), which `cgka-session`'s
  test harness uses. Merging the relay plane in would make that core carry the whole relay plane. (`marmot-c` depends on the adapter
  with `sdk` enabled, only for its proxy helper, so it is unaffected either way.)
- It matches the target map in [core-structure §4](core-structure.md#4-proposed-target-structure).

Folding the adapter's `sdk_client.rs` into `transport-nostr` later, so the adapter becomes SDK-free, is a natural
follow-up. It is out of scope here.

## What moves and what stays

| Code | Lines | Moves? |
| --- | ---: | --- |
| `relay_plane/mod.rs` | 3,390 | Moves: the shared plane, router, per-account delivery, overflow and loss fences, notification supervisors, EOSE repair, the per-account adapter and its `TransportAdapter` implementation, health |
| `relay_plane/safety.rs` | 331 | Moves: `RelaySafetyPolicy` (the relay dial chokepoint) and the retired-relay denylist, intact |
| `relay_plane/delivery_spill.rs`, `telemetry.rs` | 291 | Moves |
| `relay_plane/directory.rs`, `directory_wire.rs` | 1,129 | Moves for now: about two thirds is relay I/O, and the plane's health and router depend on it. The directory crate (step 3) later takes the directory bookkeeping and consumes `DirectoryRelayFetcher` as its seam. |
| Per-account publish clients and their cache (`relay_client_for_account_id`, about 11 call sites in `lib.rs`, `directory/`, onboarding, push, blocks) | about 100 | Moves in its own PR (PR 5), together with the eviction rules |
| `network_proxy.rs` | 38 | Stays. The plane calls the adapter's `nostr_builder` directly. |
| `collector_host_safety.rs`, `relay_telemetry_export.rs` | 2,197 | Stay for now, then go to `marmot-observability` (step 6). The exporter's `impl MarmotRelayPlane` block becomes a free constructor. |
| `AppTransportRouting`, `AppKeyPackagePublisher` (`lib.rs`) | about 350 | Stay for this move; each has its own later brief (see Out of scope). `AppTransportRouting` merges with `marmot-account`'s copy into the one routing implementation on `marmot-device-runtime`; `AppKeyPackagePublisher`'s KeyPackage event format goes to `transport-nostr` ([core-structure §4](core-structure.md#4-proposed-target-structure)). |
| Worker-side spill reader and loss import (`client/delivery_spill.rs`, `client/recovery.rs`) | — | Stay: they are app storage and ingest |

## Edges to cut before moving

`relay_plane/` imports only these from the rest of `marmot-app` and `storage-sqlite`:

| Edge | Treatment |
| --- | --- |
| `config::RelayTelemetryExportConfig` (`relay_plane/mod.rs:37`) | Replace it with a one-method export-gate trait that the app's config implements |
| `directory::DirectorySyncPlan` (`relay_plane/mod.rs:40`) | Move the plain-data struct, and `DirectorySyncBatch`, into the relay plane. The directory already depends on the relay plane, so leaving it would create a cycle. Its constructor stays in the app: turn the inherent `impl DirectorySyncPlan` (`directory/sync.rs:145-237`: `from_known_users`, its batching helper and `extend_batches`) into app-side builder functions that return the plane-owned type. It reads app policy (the `DIRECTORY_SYNC_*` constants, one of which holds `user_blocks::MUTE_LIST_KIND`, and `directory_subscription_id`), and an inherent impl cannot stay on a type another crate owns (E0116). |
| `network_proxy::nostr_builder` | Call the adapter's `network_proxy::nostr_builder(network_proxy::socks5_proxy())` directly, as `crates/marmot-app/src/network_proxy.rs:17-18` does today. Passing `Ok(None)` would compile but silently drop SOCKS5 routing and the fail-closed path for a bad proxy configuration. |
| `storage_sqlite::{DeliverySpillDisposition, DeliverySpillLimits}` (`relay_plane/delivery_spill.rs:19`) | Define plane-owned types, and map them in the closure `open_account` builds. No storage crate may depend on the transport crate. |

The relay plane reaches storage only through two closures built in `open_account`: the delivery-loss marker and the
spill store. Those closures remain the interface for the move. Only the spill-store closure changes, to map between
the storage types and the plane-owned types above.

## The surface the crate exports

The move keeps today's surface, so callers change only their import paths. Narrowing it is design work for later
PRs (see the end of this brief).

| Group | Production call sites outside the plane |
| --- | ---: |
| `TransportAdapter` implementation (used by `marmot-account`) | through the trait |
| Delivery intake and receipts | 18 |
| Cursor sealing | 27 |
| Loss and overflow | 48 |
| Coverage and EOSE | 17 |
| Post-join maintenance REQs | 9 |
| Recovery comparison (NIP-77) | 22 |
| Endpoint policy (dial safety) | 41 |
| Directory fetch | 19 |
| Telemetry and health | 11 |
| Signer and account context | 3 |
| Lifecycle (construction, shutdown) | 5 |

The 35 `pub(crate)` adapter methods that the app calls become `#[doc(hidden)] pub` in the move. The test hooks
(10 `_for_test` hooks, including the `new_with_directory_fetcher_for_test` constructor, with 46 calls from
`marmot-app` tests) move behind a `test-support` feature, because
`#[cfg(test)]` doesn't cross crate boundaries.

## PR sequence

Each PR is green on its own and changes no behaviour.

1. **Cut the inbound edges in place.**
   - Move `DirectorySyncPlan` into the plane, and turn its constructor into app-side builder functions. The caller in
     `directory/methods.rs` and the local-account versus discovered-user batching tests in `directory/sync.rs` switch
     to them unchanged.
   - Add the export-gate trait and the plane-owned spill types.
   - Call the adapter's proxy builder directly.
   - Turn `telemetry_exporter` into a free constructor.
   - Put the test hooks behind `cfg(any(test, feature = "test-support"))`.
   - Add the narrow test-support accessors that the eight app-level tests need. Some read private plane fields, for
     example `notification_lag_with_a_legacy_retained_route_stays_bounded` reads
     `app.relay_plane.inner.transport.sdk_relay_client` (`relay_plane/tests.rs:5500-5506`). Rewrite those assertions
     to use the accessors, so PR 2 can move the tests without dropping any.
   - Adapt `relay_label_resolution_is_gated_behind_opt_in` to the new export-gate trait. Today it builds the app's
     `RelayTelemetryRuntimeConfig` from `crate::config` (`relay_plane/tests.rs:33-51`) and the
     `RelayTelemetryExportConfig` values the gate replaces (`:2352-2360`).
   - Proof: `relay_plane/` has no production `crate::` or `storage_sqlite::` imports.
2. **Move the eight tests that build a whole `MarmotApp` or runtime** out of `relay_plane/tests.rs` into the app's
   tests, using the accessors from PR 1. Tests only.
   - Give `relay_telemetry_export.rs`'s `account_publish_counters_round_trip_as_unlabeled_cumulative_sums` its own
     fixture, or move the shared fixture behind `test-support`. Today it imports `AccountPublishFixture` and
     `PublishScript` from `relay_plane::publish_accounting_tests` (`relay_telemetry_export.rs:2466-2475`), a
     `#[cfg(test)] pub(crate)` module (`relay_plane/mod.rs:45-46`) that disappears once the plane is another crate.
3. **Create `crates/transport-nostr` and `git mv` the files.**
   - In `marmot-app`, `mod relay_plane { pub use transport_nostr::*; }` keeps every existing path and re-export, so
     callers do not change.
   - The shim re-exports only `pub` items. Widen to `pub` every `pub(crate)` item the rest of `marmot-app` names
     today: the account adapter's methods, the other plane methods the app calls, and types such as
     `AccountDeliveryReceive` and `RelaySafetyPolicy`.
   - `cfg(test)` is set only on the crate under test, never on its dependencies. Enable `test-support` through
     `marmot-app`'s dev-dependency on `transport-nostr`, so `cargo test -p marmot-app` compiles the hooks and
     accessors its tests call, while a normal build, and so the shipped library, leaves them out.
   - Add the crate's README, AGENTS.md and clippy disallowed-methods list.
   - Update the root README crate map, the root AGENTS.md "Where to go" table, and the adapter and app AGENTS files.
4. **Repoint callers to `transport_nostr::` and delete the shim.** Mechanical.
5. **Move the per-account publish clients onto the plane,** with the cache and eviction rules in the same PR.
6. **Merge the duplicate notification consumer.** The adapter's test-only forwarder either delegates to the plane's
   handler or is removed.

## Proof that behaviour is unchanged

All six must pass on each of PRs 3–6:

1. The moved tests keep their names and pass under `cargo test -p transport-nostr --features test-support`.
2. `cargo test -p marmot-app` passes for the library, `--features test-policy-overrides` (which runs feature-gated
   relay regressions such as `offline_member_post_join_catch_up_sees_the_commit_made_before_its_join`,
   `relay_plane/tests.rs:5533-5535`), `--test relay_runtime`, and
   `--features otlp-export --test relay_telemetry_otlp`. `relay_runtime` is flaky on some local machines, so CI is the
   authority for it.
3. `cargo test -p wn-cli --features test-policy-overrides` passes.
4. `cargo test -p marmot-uniffi --test runtime_threads` passes; it checks #2340's thread placement.
5. `just binding-docs-gate` reports no change to public paths.
6. `cargo tree -p transport-nostr` contains neither `marmot-app` nor `storage-sqlite`.

## Risks

| Risk | Mitigation |
| --- | --- |
| `spawn_router` silently does nothing without a current Tokio runtime (`relay_plane/mod.rs:2132-2134`). Moving it into a public constructor makes that contract public. | After #2340 the UniFFI constructors run inside the binding's runtime. Document the requirement on the constructor now, and take an explicit runtime handle in a later PR. |
| Shutdown does not join the spill writers, the loss-persistence tasks or the directory fetch tasks | Unchanged by the move. #2341 added the close registry, but the relay plane registers nothing in it. Record the unjoined tasks in the crate's AGENTS.md as a follow-up. |
| `open_account` holds the spill and loss closure wiring next to #2341's engine-close changes | #2341 and its follow-up #2357 have landed, so PR 1 edits `open_account` on top of them |
| Cross-account state lives in one `Arc<RelayPlaneTransport>`, held by seven app objects | It moves as a unit. The holders keep their clones. |
| Three sets of per-account SDK clients sit on both sides of the boundary, and their order matters: signer before activation, retirement before reopen | PR 5 moves the publish-client cache and its evictions together. The ordering rules go into the crate's AGENTS.md. |
| The dial-safety chokepoint moves | Keep `RelaySafetyPolicy` intact. Update `dial-safety.md` and the adapter's AGENTS.md. The new crate gets the same clippy disallowed-methods list. |
| Retired-relay denylist location | Move the single literal and its regression tests intact. Keep the `marmot-app` re-export used by bindings and audit. |
| The tracing target `marmot_app::relay_plane` is used by the simulator's filters and by the telemetry docs | Keep the literal target string in the move. Rename it, if wanted, in a separate PR. |

## Out of scope

These build on the moved crate, each as its own design brief:
- a transport-neutral coverage surface beside `TransportAdapter`, with per-route EOSE and paging and stable batches
  (Pass 1 E recommendations 11 and 12, Pass 1 B step 4);
- typed size handling and pre-publish checks (#2334);
- routing derivation: the `NostrRoutingV1` decode the engine does today, which goes to `transport-nostr`;
- merging `AppTransportRouting` with `marmot-account`'s `StaticTransportRouting` into the one routing implementation
  on `marmot-device-runtime`;
- the KeyPackage event format;
- the directory crate (step 3);
- folding the adapter's SDK client into `transport-nostr`.

## Done when

- `relay_plane/` no longer exists in `marmot-app`, and `transport-nostr` builds without `marmot-app` or
  `storage-sqlite`.
- All six proof checks pass, and `just fast-ci` is green.
- The crate map and the AGENTS routing tables name the new crate.

## Open questions

1. Is the name `transport-nostr` confirmed? This is question 4 in [core-structure §6](core-structure.md#6-questions-for-the-product-owner).
2. Keep the tracing target `marmot_app::relay_plane` through the move? The recommendation is yes.
