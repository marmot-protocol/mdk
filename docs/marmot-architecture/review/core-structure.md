---
title: "Review — Core Crate Structure"
created: 2026-10-15
updated: 2026-10-17
tags: [marmot, architecture, review, structure, crates]
status: draft for discussion
---

# Review — Core Crate Structure

This page asks one question of the core crates (`traits`, `cgka-engine`, `cgka-session`, `marmot-account`,
`storage-sqlite`, `marmot-app` and the Nostr transport): is each one shaped for what it is supposed to do? It ranks
the biggest gaps between what each crate is documented to be and what it contains, and it proposes a target crate map
with a sequence for getting there. Baseline `ab1de296f`.

Line counts are production code. They exclude test files and inline `#[cfg(test)]` blocks, so they are lower than
Pass 0's figures. Counts that split mixed files by function are approximate, to about ±15%.

Evidence labels follow the [review's evidence rules](README.md#evidence-rules). Every finding is **observed** (read
in source at the baseline, or measured) unless it is marked **(hypothesis)**. Each finding section in §2 ends with
the citations behind it. §4 and §5 are proposals, not findings.

## Summary

1. **`marmot-app` is a product monolith in a runtime's clothing.** (Observed; §2.1.) Its documented job is "the runtime
   boundary for client applications". Only about 23% of its 107k production lines are runtime orchestration. About 57%
   are product features, and about 20% are infrastructure and observability code (audit logs, telemetry, analytics) that
   belongs lower in the stack or in a crate of its own.
2. **The real per-account core is an undocumented god object.** (Observed; §2.1.) `AppClient` has 58 fields and 449
   methods, 299 of them taking `&mut self`. The docs call it "a lower-level compatibility surface", and they describe a
   `MarmotAccountSession` and `SharedServices` that don't exist. The public runtime mostly forwards calls: 179 of its
   250 public methods are thin delegations, and a feature crosses four hand-written layers.
3. **`storage-sqlite` is the app's whole data model with a protocol store inside it.** (Observed; §2.2.) Protocol
   persistence is 16% of its production code. It exposes 370 public app and transport methods next to 122
   storage-trait methods, about 82% of its public methods are used by `marmot-app`, and its protocol code behaves
   differently depending on app tables.
4. **The lower stack has three identical wrappers and no layer narrows the surface.** (Observed; §2.3 and §2.4.) The
   account runtime makes 34 pass-throughs and hands out the session directly. The session makes 119 more. The engine
   exposes 153 methods, about 38 of which are a storage proxy for account records plus the app's audit sink.
5. **The protocol/app boundary is crossed inside single transactions in both directions.** (Observed; §2.5.) That, not
   the contracts, decides where code lives. Account-runtime state machines sit in `traits` because the engine's
   transactions write them. Drafts are consumed inside the engine's outbound transaction, and the engine's outbox is
   acknowledged inside the app's.
6. **`marmot-account` is two crates in one.** (Observed; §2.6.) Account identity and files are used by the bindings, the
   CLI and the agent connector. The account-device publish runtime is used only by `marmot-app`. The two share no state.
7. **Nostr knowledge sits in the wrong layers in both directions.** (Observed; §2.8.) It is below the transport in the
   engine, `traits`, the account crate and storage, and above it in `marmot-app`'s relay plane.

The proposed direction (§4): about eight focused crates around a slimmer engine and a smaller `marmot-app`. Start with
the seams that are already nearly separate: the media store (in progress, #2314), the relay plane and the directory.

## 1. Each crate's intended role against its contents

| Crate | Documented role | Production lines | What it actually holds |
| --- | --- | ---: | --- |
| `traits` | Shared engine, storage and transport contracts | 10,136 | The contracts (about 5.5k), plus about 2.6k of app-level types: polls, reporting, app-event UI strings, media and avatar components, agent streams, host safety. Also account-runtime state machines: the `OutboundFanout` transitions and maintenance records. |
| `cgka-engine` | The CGKA engine: MLS, convergence, capability rules | 37,203 | Mostly the protocol core: convergence and canonicalization (about 11k, including `openmls_projection.rs`, which is really the replay and apply engine), group lifecycle and send (about 7.2k), message ingest and peel (about 4.8k), publish lifecycle, deferred peel and hydration. A smaller slice does three other jobs: about 30 storage pass-throughs for account records, the app's audit sink and metrics (about 1.7k), and a few product-policy rules (see §2.4). |
| `cgka-session` | One encrypted account-device session | 1,687 | About 700 lines of real work (open, hydrate, effect collation) and 119 pass-throughs. Its API leaks engine types, so callers import the engine anyway. |
| `marmot-account` | Account and session coordinator: publish-before-apply, transport activation | 9,400 | Account identity and files (2.7k), the publish pipeline, a second "legacy" fanout that is the live Welcome path, maintenance, KeyPackage scheduling and a routing implementation the app duplicates |
| `storage-sqlite` | SQLCipher implementation of `StorageProvider` and OpenMLS storage | 43,707 | Protocol 16%, app projections 33%, attachments and avatars 17%, recovery and transport bookkeeping 12%, product state 11%, infrastructure 7%, shared DB 2% |
| `marmot-app` | Multi-account runtime, shared services, relay plane, projections, app events | 107,048 | See §2.1 |
| `transport-nostr-*` | Nostr envelopes and the relay adapter | about 19k (non-test files) | Well scoped, but the relay plane that drives them lives in `marmot-app` |

## 2. The mismatches, in detail

### 2.1 `marmot-app`: a product monolith

| Category | Domains | Share |
| --- | --- | ---: |
| Runtime orchestration, the stated role | Runtime and lifecycle, `AppClient` core, sync, ingest and cursor, relay plane, group command plumbing | about 23% |
| Product features | Directory and search (11.9%), media (9.4%), onboarding (7.8%), messaging and timeline (6.9%), history recovery (6.4%), group management, chat list and presentation windows, notifications, drafts, agent streams, moderation | about 57% |
| Infrastructure and observability | Audit, telemetry and analytics (12.2%, the largest single domain), SQLCipher key derivation, the root lease, dial-safety helpers, `marmot-account` trait implementations, the KeyPackage lifecycle, row-to-DTO mapping | about 20% |

The crate grew from 41k lines on 2026-07-15 to 229k lines, tests included, three months later. That is about 21
lines added for every line removed.

**Four objects, unclear owners.**
- `MarmotApp` (32 fields, 355 methods across 16 files) is a service locator: every other layer holds a clone of it.
- `AppClient` (58 fields, 449 methods) is where nearly every feature lives. The worker owns it.
- `MarmotAppRuntime` (6 fields, 313 methods) is the API the hosts use (`marmot-uniffi` calls 234 of its methods). It
  mostly forwards to `AccountManager` (16 fields, 7 of them onboarding state).
- An `AccountWorkerCommand` enum with 89 variants joins them.

One reaction, for example, goes `MarmotAppRuntime::react_to_message`, then `AccountManager::send_app_event`, then
`AccountWorkerCommand::SendAppEvent`, then `AppClient::send_app_event`, then a 376-line function. The same state is
held in more than one object: `relay_plane` in four, and analytics, the audit tracker configuration and the directory
sync handle in two each.

**Cross-cutting hooks.** About 550 references to audit, performance and analytics hooks sit outside the observability
modules. Forty `_unobserved` functions exist only to pair each public operation with an instrumented wrapper. The
101-variant `AppError` and 47 crate-root re-exports tie every module to the root.

**Seams that already exist in state but not in code.**
- The relay plane depends on almost nothing else in the crate: 10% of its lines are methods on the hub objects.
- The directory makes no account-storage calls and has its own databases, yet it is written as 67 methods on
  `MarmotApp`.

Sync and history recovery are one subsystem split across two files: they share about 10 `AppClient` fields, and sync
references 48 recovery symbols.

**Evidence (observed at `ab1de296f`):**
- Hub objects: `MarmotApp` (`crates/marmot-app/src/lib.rs:484`), `AppClient` (`client/mod.rs:788`),
  `MarmotAppRuntime` and `AccountManager` (`runtime/mod.rs:184`, `:243`).
- The command enum: `runtime/account_worker.rs:339-751`.
- The reaction chain: `runtime/mod.rs:3540`, `runtime/commands.rs:1671`, `account_worker.rs:590` and `:5657`,
  `client/mod.rs:4243` and `:4429`.
- `relay_plane` held four times: `lib.rs:513`, `client/mod.rs:824`, `runtime/mod.rs:377`, `account_worker.rs:333`.
- `AppError`: `error.rs:121`.
- The documented role: [`marmot-app-runtime.md`](../overview/marmot-app-runtime.md) (crate responsibility list) and
  [`app-core-boundary.md`](../overview/app-core-boundary.md) line 49.
- Measured: line counts, domain shares and hook counts by the method in the page header; growth by `git diff --stat`
  from 2026-07-15. The split of the seven mixed hub files is approximate.

### 2.2 `storage-sqlite`: two stores in one type

- **The callers are the app.** One concrete type, `SqliteAccountStorage`, carries 387 public inherent methods (not
  counting six feature-gated ones), 370 of them app or transport, and 122 storage-trait methods. `marmot-app` calls
  about 318 of the public methods (a name-match count). 239 of its 257 re-exports are app DTOs. These counts are at
  `e9ecb12e0`, from the [step 4 brief](brief-storage-boundaries.md).
- **It breaks a stated rule.** The root `AGENTS.md` says to keep transport-specific code out of storage crates. This
  crate holds NIP-77 reconciliation, relay-plane spill, NIP-51 block lists, the NIP-59 moderation outbox, Nostr route
  rows and Blossom upload secrets.
- **The protocol implementation depends on app state.** Message release checks whether an `account_state` row exists.
  The engine's local-forget path wipes about 20 app tables. The outbound path consumes drafts and local submissions,
  and fires an observer registered through `cgka-session`.
- **The schema is jointly owned.** Ten of 112 migrations touch both protocol and app tables (twelve if
  `locally_forgotten_groups` counts as app). Seventeen live triggers, all created by migration 0072, span the sides:
  twelve on the engine's leave and disband tables rewrite `chat_list_rows`, and five on `account_groups` and
  `chat_list_rows` read those engine tables. One more guards `cgka_groups` inserts. About 42 others cross between app
  domains. One of those resets the new media catalog whenever a presentation table's `store_epoch` changes
  (`migrations/0110_media_files.rs:51`). That is what #2314 specifies for a store reset, but it ties the media store's
  lifecycle to a projection table.
- **The engine's cache pays for app writes.** Every app-connection commit changes `PRAGMA data_version`, which
  invalidates the engine's cached MLS groups (`connection.rs:1604-1621`; the cost is unmeasured).

History agrees with the split. Of 164 recent commits to the crate, 69% touched no protocol module and only 15%
touched protocol and app code together.

The couplings a split has to carry, all with file:line in the source inventory:
1. The outbox is acknowledged in the app's transaction.
2. Drafts and local submissions are consumed in the engine's transaction.
3. Message release writes app recovery tables.
4. Group and route deletion clear reconciliation rows.
5. Local forget and local delete span both sides.
6. App tables reference `cgka_groups` and are deleted in cascade with a group.
7. The engine-table triggers above update the chat list.
8. App reads join engine tables.
9. The app writes the engine's authority outbox.
10. App writes invalidate the engine's MLS cache.
11. Both sides share one migration ledger.

Several bridges already half exist: the at-least-once outbox, the released-receipt journal, the secure-delete intents
and the replay fingerprint.

**Evidence (observed at `e9ecb12e0`):**
- `SqliteAccountStorage`: `crates/storage-sqlite/src/connection.rs:1050`.
- The release probe: `storage/messages.rs:319-326`. The forget wipe: `account_projection.rs:1427-1649`.
- Draft and submission consumption: `storage/outbound.rs:20-62`, `:240-263`. The outbox acknowledgement:
  `account_projection.rs:1313-1318`.
- Engine-table triggers: `migrations/0072_chat_list_pages.rs:70-178`, and `reject_forgotten_group_insert` in
  migration 0071. The media reset: `migrations/0110_media_files.rs:51`.
- The cache generation: `connection.rs:1604-1621`. The transport rule: the root `AGENTS.md` invariants.
- Measured: method counts, the migration and trigger classification, and the commit history over non-test files.

### 2.3 The lower stack: three wrappers, no narrowing

A query from the app can cross the account runtime (34 pass-throughs), then the session (119), then the engine.
`session()` and `session_mut()` on the account runtime let the app skip a layer
(`crates/marmot-account/src/runtime.rs:517-523`).

The session's public API exposes `FeatureRegistry`, `CanonicalizationPolicy`, `AccountIdentityProofSigner` and
`GroupAuthoritySnapshot` without re-exporting them. That alone explains most of `marmot-app`'s direct imports of
`cgka_engine`. The session's concrete SQLite type also ends the engine's `S: StorageProvider` genericity, and nothing
above benefits from that genericity.

App concerns tunnel down through the session: the draft-commit observer and the promotion of legacy message rows.

**Evidence (observed):** the session struct and effect collation (`crates/cgka-session/src/lib.rs:193-197`,
`:1482-1578`); the draft observer (`:433-441`); the app's engine imports and session configuration
(`crates/marmot-app/src/lib.rs:15-18`, `:4537-4583`); pass-through counts in
[the engine map](map-engine-contract.md#3-the-api-the-layers-above-use).

### 2.4 The engine: protocol core plus three other jobs

- **A storage proxy for account records.** The account runtime has no store handle of its own, so the engine forwards
  storage calls for it: 21 in `maintenance.rs` and 9 for fanouts and pending references.
- **The app's audit sink.** Eight methods, plus ownership of the recorder's file path and rotation. App audit records
  travel from the app through the runtime and the session into the engine.
- **Product policy.** Several rules belong to product layers, not the protocol:
  - a chat with an `imeta` tag triggers media-secret export (`crates/cgka-engine/src/app_payload.rs:41-48`);
  - an app moderation rule decides which message kinds need source authority;
  - the join transaction creates a post-join maintenance obligation with a 24-hour operational target. Its relay-EOSE
    deadline is set later, when the post-join subscription is installed (`eose_deadline_at` is `None` in this function);
  - the engine decodes `NostrRoutingV1` to derive transport routes.
- **The protocol core is most of the crate, and it is sound.** Convergence and canonicalization are about 11k lines:
  `distributed_convergence.rs`, `canonicalization.rs` and `openmls_projection.rs` are 8,973 lines together at the
  baseline, and `convergence.rs`, `convergence_input.rs`, `convergence_clock.rs` and
  `openmls_projection/{group_activity,resumable}.rs` bring the raw total to 11,003. Group lifecycle and send add about
  7.2k, and message ingest and peel about 4.8k. All of it has matching tests, the simulator and the formal model. The
  three jobs above are a small slice of the 37.2k lines, which makes them cheap to move. The name
  `openmls_projection.rs` hides that it is the replay and apply engine.

**Evidence (observed):**
- The storage proxy: `crates/cgka-engine/src/maintenance.rs` (21 `pub fn`) and `engine.rs:865-990`.
- The audit sink: `engine.rs:2917-2970`.
- Moderation authority: `reporting::requires_source_authority`, called at `message_processor/ingest.rs:1464`.
- The post-join obligation: `group_lifecycle.rs:50-105`. Routing decode: `app_components.rs:235-251`.
- Convergence size: raw lines at `ab1de296f` of `distributed_convergence.rs`, `canonicalization.rs`,
  `openmls_projection.rs`, `convergence.rs`, `convergence_input.rs`, `convergence_clock.rs` and
  `openmls_projection/{group_activity,resumable}.rs`.

### 2.5 The unit of work decides placement

Because the confirm transaction writes the `OutboundFanout` record, its 668-line state machine lives in `traits`, the
shared contract crate. For the same reason, maintenance obligations live there with an EOSE deadline field. Drafts
are consumed inside the engine's outbound transaction, and the engine's outbox is acknowledged inside the app's
checkpoint transaction.

The real architectural rule today is "whatever one transaction must cover lives in the same crate", and the
protocol/app line is drawn around that, not around responsibilities.

**Evidence (observed):** the `OutboundFanout` state machine (`crates/traits/src/transport_adapter.rs:186-853`);
maintenance records with EOSE fields (`crates/traits/src/maintenance.rs:62`, `:130`); the engine's confirm transaction
(`crates/cgka-engine/src/publish.rs:133-288`); draft consumption (`crates/storage-sqlite/src/storage/outbound.rs:50`,
`:253`); the outbox acknowledgement (`account_projection.rs:1313-1318`). The rule stated in the last paragraph is a
reading of these facts (hypothesis).

### 2.6 `marmot-account`: two crates

- **Who uses what.** The bindings, the CLI, the agent connector and the simulator use only `AccountHome`, its error
  and summary types, and the secret stores. Only `marmot-app` uses `AccountDeviceRuntime`. The two halves share no
  state and have different dependencies: `nostr` and the keyring on one side, the session and `traits` on the other.
- **Overlap with the app.**
  - **Routing:** the app's `AppTransportRouting` copies `StaticTransportRouting`.
  - **KeyPackages:** the account owns scheduling and state, while the app owns the Nostr event format and publishes
    outside `TransportAdapter`.
  - **Welcomes:** the "legacy" `DurableTransportFanout` is still the live publication path, next to two app-side
    mechanisms.

**Evidence (observed):**
- Consumers found by searching for `marmot_account::` in `marmot-uniffi`, `cli`, `agent-connector` and the simulator.
- Routing duplication: `AppTransportRouting` (`crates/marmot-app/src/lib.rs:7421-7585`) against
  `StaticTransportRouting` (`crates/marmot-account/src/routing.rs:84-131`).
- KeyPackage publication in the app: `crates/marmot-app/src/lib.rs:7654-7700`.
- The live Welcome path through `DurableTransportFanout`: `crates/marmot-account/src/runtime.rs:4025`, `:4408`.

### 2.7 `traits`: contracts mixed with app types

About 26% of the crate is app-level: polls, reporting, the UI strings in `app_event`, the encrypted-media, avatar and
Blossom components, agent text streams, and host safety. Nostr specifics such as `NostrRoutingV1` and EOSE fields
sit in a crate meant to be transport-neutral. The `CgkaEngine` trait has no generic consumer, so it is a compile-time
witness, not the contract the layers above use.

**Evidence (observed):** UI strings (`crates/traits/src/app_event.rs:112-116`); the compile-time witness
(`crates/traits/src/lib.rs:136`, `crates/cgka-engine/src/lib.rs:96`); `TransportKind::Nostr`
(`crates/traits/src/capabilities.rs:60`); EOSE fields (`crates/traits/src/maintenance.rs:62`, `:130`); the app-level
share measured over the module inventory.

### 2.8 Nostr in the wrong layers

- **Below the transport:**
  - the account identity proof in the engine (mdk#755);
  - `NostrRoutingV1` decoding in the engine;
  - EOSE in `traits` and in the account runtime;
  - Nostr replaceable-event floors in `AccountHome`;
  - NIP-77, NIP-51 and NIP-59 bookkeeping in storage.
- **Above the transport:** the relay plane, and with it the KeyPackage event format, in `marmot-app`.

**Evidence (observed):** the identity proof (`crates/cgka-engine/src/account_identity_proof.rs:13-25`); routing
decode (`crates/cgka-engine/src/app_components.rs:235-251`); replaceable floors
(`crates/marmot-account/src/home.rs:686-712`); `transport_reconciliation.rs`, `delivery_spill.rs`, `user_blocks.rs` and
`moderation_reports.rs` in `crates/storage-sqlite/src/`; and `crates/marmot-app/src/relay_plane/`.

### 2.9 Generic SDK or White Noise's app core

MDK is meant to serve any client building a Marmot app, not only White Noise. Most of the stack is generic, but some
White Noise deployment choices are compiled in:
- the recovery-operated relays are White Noise's (`crates/marmot-app/src/config.rs:18-21`);
- directory search defaults to Open Ranking (`config.rs:13-15`);
- product analytics is written directly against Aptabase (`crates/marmot-app/src/product_analytics/delivery.rs`).

Telemetry and audit delivery already use OTLP, a standard format, and take their endpoints from build-time
configuration (`config.rs:8-12`), so they are generic enough today. Only audit recording has a trait
(`ForensicRecorder` in `marmot-forensics`).

Decision for `marmot-observability`: move the code as it is first. The one seam to get right in that move is the
recording interface `marmot-app` reports through, because that is what any client sees. Exporter traits, such as a
pluggable analytics provider, can come later, if and when another client needs them.

## 3. What stays as it is

- The engine's convergence core, its explicit `EpochState`, and the verification around it (engine tests, conformance
  simulator, Tamarin model).
- The transport trait for publish and receive ([Pass 1 E](e-transport.md#7-the-transport-boundary)).
- One SQLCipher database per account-device identity, and the root lease.
- The bindings' dependence on one runtime API.

## 4. Proposed target structure

```text
Hosts:        marmot-uniffi   marmot-c   cli   agent-connector
                    │  (runtime API + account home only)
Runtime:      marmot-app ── composition root; per-account product core
                    │       (messaging, groups, projections and windows, sync + recovery,
                    │        onboarding coordinator, notifications), split by role per Pass 1 B
App services: directory   media-store + media transfer   app store   marmot-observability
                    │
Account:      marmot-session (session + publish pipeline + maintenance +
                    │         KeyPackage lifecycle + single routing + one Welcome rail)
              marmot-account (identity, files, secrets)          transport-nostr (relay plane + routing,
                    │                                             EOSE/coverage, KeyPackage format)
                    │                                             over transport-nostr-adapter (SDK-free core)
Protocol:     cgka-engine (protocol core; policy injected)   protocol store (StorageProvider + OpenMLS)
                    │
Foundation:   cgka-traits (contracts only)   marmot-components (app component and payload types)
              fs-private   marmot-forensics (schema)
```

| Target crate | Takes from | Main change |
| --- | --- | --- |
| `cgka-traits` | itself | Keeps the engine, storage, transport and capability contracts and the protocol component codec, about 7.5k lines. App types move to `marmot-components`; Nostr routing and EOSE move to `transport-nostr`. |
| `marmot-components` (new) | `traits` | App component and payload types: media, avatar, polls, reporting, agent-stream descriptors. It sits below the engine, because the engine validates components. |
| `cgka-engine` | itself | Protocol core only. Product rules (media-secret export, moderation authority, routing decode, the post-join maintenance target) come in through a small policy interface. The join transaction still writes the post-join obligation, so it stays atomic with the join (§2.5); only its 24-hour target comes from the policy, and `marmot-session` takes the obligation over from there. The account-record storage proxy and audit-recorder ownership move up. `openmls_projection` gets a name that says what it does. |
| Protocol store | `storage-sqlite` | `StorageProvider` and OpenMLS storage. The app tables move out, and the cross-domain writes become explicit hooks or journals. |
| App store | `storage-sqlite` | Projections, product state and the recovery ledger. Transport-specific bookkeeping moves to `transport-nostr` or the directory. |
| `marmot-session` (new) | `cgka-session`, `marmot-account` runtime | One layer that owns the engine and its own account-record store handle: publish pipeline, maintenance, KeyPackage lifecycle, one routing implementation, one Welcome path. It re-exports the config types callers need. |
| `marmot-account` | itself | Identity, files, secret stores: what the bindings, CLI and agent already use. |
| `transport-nostr` (new) | `marmot-app` `relay_plane/` | The relay plane, routing derivation, coverage evidence (EOSE and paging), and the KeyPackage event format, built on `transport-nostr-adapter`, which stays its own crate. This is where Pass 1 E's size handling and coverage surface belong. Folding the adapter's SDK client in later is an option, not part of step 2 ([brief](brief-relay-plane.md#decision-a-new-crate-on-top-of-the-adapter)). |
| `directory` (new) | `marmot-app` `directory/`, relay-plane directory code, previews | Discovery, profiles, KeyPackage lookup and search, with the databases it already owns. |
| `media-store` and media transfer | #2314; `marmot-app` `media/` | The encrypted file store (in progress), plus Blossom transfer, crypto and resume. |
| `marmot-observability` (new) | `marmot-app` `relay_telemetry_export`, `product_analytics`, `audit_otlp_sender`, audit upload, `collector_host_safety` | The code that ships diagnostics off the device: relay telemetry over OTLP, Aptabase product analytics, audit-log upload and OTLP delivery, and the collector dial-safety checks. The recording points stay in `marmot-app` and report through one observer interface, replacing the 40 `_unobserved` pairs over time. Decided 2026-10-15: move it as it is first, and generalize later (§2.9). |
| `marmot-app` | itself | Composition root and per-account product core, organized by role (writer lane, read path, I/O lanes; [Pass 1 B](b-runtime-concurrency.md)). `AppClient` stops being a public type; only `wn sync` uses it today. |

**Dependency rules for the target:**
- Dependencies point downward only.
- App services never depend on `marmot-app`.
- Hosts depend only on `marmot-app` and `marmot-account`. The one existing exception is `marmot-c`, which depends
  on `transport-nostr-adapter` for its process proxy helper.
- No storage crate contains transport code.
- Nothing below `transport-nostr` knows Nostr relay semantics. Nostr identity is the documented exception.

## 5. Sequencing

Each step can ship on its own.

| Step | Change | Why this order | Size |
| --- | --- | --- | --- |
| 1 | `media-store` crate (#2314) | In progress, and the template for the rest | — |
| 2 | Relay plane into `transport-nostr` ([brief](brief-relay-plane.md)) | The most separable seam; gives Pass 1 E's fixes a home | about 5.1k lines move |
| 3 | Directory crate | Already owns its state; makes no account-storage calls | about 11–13k |
| 4 | `storage-sqlite` internal boundaries by table ownership: `protocol/`, `app/` and a `cross/` module, with tests that fail on any detected crossing missing from a shrinking allow-list ([brief](brief-storage-boundaries.md)) | Makes the split reviewable before any crate moves; no behaviour change | Moves, then the `SqliteAppStorage` handle: `marmot-app`'s calls to about 318 app methods (a name-match count) |
| 5 | Lower stack: merge the session into `marmot-session`, split off `marmot-account`, move the engine's storage proxy and audit ownership up, re-export config types | The two fixes that touch this code have landed: #2338 and #2341, which closed #2323 | Touches about 10 `marmot-app` files and `marmot-account` |
| 6 | `marmot-observability` for the exporters, plus an observer interface | Removes the largest `marmot-app` domain | about 7–8k |
| 7 | Inside `marmot-app`: break up `AppClient` along Pass 1 B's roles; make sync and recovery one owned subsystem; take onboarding out of `AccountManager`; remove duplicated state | Depends on the runtime work (multi-thread runtime session) | Large |
| 8 | Split `storage-sqlite` into protocol, app and base crates; move app types into `marmot-components`; inject engine policy | Last, because they need steps 4 and 5 | Large |

Steps 1, 2, 3 and 6 alone would move about a third of `marmot-app`'s production code into focused crates (hypothesis).

## 6. Product-owner decisions

Answered 2026-10-17:
1. **Crate count:** as many as the design needs. Each crate is a black box with a clean interface that does one
   thing; nothing reaches into another crate's internals, except deliberate utility crates.
2. **One database file** for the protocol and app stores stays, unless a strong reason to split appears. The
   couplings in §2.2 therefore stay inside one file; [step 4's brief](brief-storage-boundaries.md) makes them
   explicit.
3. **`AppClient` stops being public**, unless a strong reason appears.
4. **Names:** `transport-nostr`, `marmot-components` and `marmot-observability` are agreed. The per-account runtime
   crate is `marmot-session`, not `marmot-device-runtime`: `marmot-account` keeps identity, files and secrets, which
   the bindings, CLI and agent use, and a plain `marmot-runtime` would sit beside `MarmotAppRuntime`, the Tokio
   runtimes and MarmotKit's runtime.
5. **White Noise's deployment defaults move into configuration that hosts pass in**, and
   `MarmotAppConfig::default()` becomes neutral: the recovery-operated relays, discovery indexer relays, Blossom
   servers, Vertex endpoints, the keychain service name and the moderation label namespace. This needs its own brief,
   because the White Noise apps must then pass their values in.

## Doc drift found in this pass

These architecture docs describe structure the code doesn't have:
- [`app-core-boundary.md`](../overview/app-core-boundary.md) calls `AppClient` a compatibility surface;
- [`marmot-app-runtime.md`](../overview/marmot-app-runtime.md) describes `MarmotAccountSession` and `SharedServices`;
- `storage-sqlite`'s crate docs describe a protocol store;
- `DurableTransportFanout` is labelled legacy but is the live Welcome path.

They should be corrected when the target structure is agreed.
