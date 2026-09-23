---
title: "Current State — Implementations & Spec"
created: 2026-04-19
updated: 2026-09-23
tags: [marmot, overview, current-state, implementations]
status: overview
---

> **2026-05-09 audit pass:** A line-by-line engine review surfaced and closed correctness bugs in recipient
> required-capability refresh, group profile refresh, and the `GroupContext::exporter_secret` over-length contract,
> tightened seven smells (welcome
> dedup at the API surface, atomic `EpochState` transitions, replay error classification, more honest convergence ingest
> outcomes, capability-cache self-id assertion, fail-closed auto-committer admin guard, registry-overwrite warning), and
> added a `SnapshotRollbackGuard` so the snapshot dance is panic-safe. Snapshot names no longer carry plaintext group
> ids. The canonicalization contract now distinguishes `Resolving`, `Settled`, and `Blocked` convergence statuses from
> lifecycle `Stable`. The old auto-commit exception to publish-before-apply is closed: auto-publish work now carries a
> pending ref and confirms or rolls back like
> explicit group evolution.

# Current State — Implementations & Spec

The Nostr relay-client boundary now declares optional owned bounded acquisition
and receiver-scoped notification-loss evidence. The production SDK client
returns explicit unsupported results until #1358 adopts the qualified backend;
the recovery owner and account worker still use their existing execution path.
See [the interface contract](nostr-bounded-acquisition-interface.md).

C6a resolves accepted kind-1009 edits in the durable timeline once, sharing effective text with reply and chat-list
previews. Compact metadata is part of native conversation rows; accepted edit history is a separate paged query.
Migration 76 repairs existing projections. Raw edit events remain available, but edits are no longer transcript rows.
See the [native edit contract](../../../crates/marmot-uniffi/CONVERSATION-WINDOW.md#accepted-edits-c6a).

C7-A adds protected avatar-byte storage and bounded local reads in `storage-sqlite`, with source-generation
fencing and separate narrow LRU bookkeeping. C7-B adds durable download/retry intent, selected-source maintenance,
validated URL/encrypted acquisition and worker-lifetime cancellation. C7-C adds screen-selected opaque targets
and native local access. Released-artifact adoption and device evidence remain C9 work; clients should retain host caches until validated.
See [avatar cache storage](../further-context/avatar-cache-storage.md).

C8-A/B provide indexed per-group attachment-slot discovery in SQLite and typed async
runtime/native pages for #1448. Additions preserve cursors; destructive changes require
replacement. Reads remain local without engine/relay readiness. C8-C1 adds storage-only
durable demand/attempt fencing, protected retained bytes and removal suppression in migration 83.
C8-C2 adds durable source demand (migration 84), bounded background acquisition and protected-byte publication
for accepted conversations. C8-C3 adds protected ciphertext checkpoints and validated HTTP Range resume across interruption.
C8-D1 exposes local retained-asset metadata (up to 64 source slots) and verified byte ranges (up to 1 MiB)
through Rust, UniFFI and C, with no network or engine prerequisite. C8-D2 adds durable cancellation/retry/removal and policy, bounded progress streams, and enables automatic acquisition with the approved limits. Frozen runtimes skip transfers; pending invitations defer attachments. See the [C8 audit and sequence](../further-context/attachment-acquisition.md).

C5 M1 adds a read-only storage conversation opener: bounded canonical history and retained read state in one
snapshot, first-unread/latest selection, and scoped anchor recovery after physical removal. Dirty read projections
return a typed preparation requirement. Live screen composition is C5 M4; native bindings remain M5. See
[bounded conversation opening](../further-context/conversation-opening.md).

C5 M2 adds selected draft metadata, revision-checked mutations and a send handoff that clears the submitted
revision atomically with existing outbox acceptance. Newer edits survive; attachment bytes remain keyed reads.
See [revision-safe conversation drafts](../further-context/conversation-drafts.md).

C5 M3 adds shared Rust conversation capabilities and a bounded identity presentation sidecar, including historical
authors and commit-attributed system references. The combined live window is C5 M4; native screen bindings remain M5.
See [shared conversation presentation](../further-context/conversation-presentation.md).

C5 M4 adds a combined Rust conversation handle: initial/live history, header and identities, read state and draft,
with serialized paging, retained anchors, timed retries and terminal account-store teardown. Its worker capture
combines compact live engine authority with persisted fields on the exact session connection. Initial opens
read the durable account snapshot directly, with permissions disabled until live authority arrives. Busy/startup/
recovery workers cannot hold local history behind relay catch-up; quiet retries upgrade the same window. M5 exposes additive UniFFI/C handles with finite operation deadlines,
cancellation, revisioned draft operations and native parity checks; publication and adoption remain C9.
See the [live conversation implementation plan](../further-context/conversation-live-window-plan.md).

The additive Rust chat-list window API owns bounded live Chats, Unread, Archived and Left windows.
It coordinates the initial subscription/read, serializes paging and stable-anchor recovery, prepares only
required selected presentation, and closes handles on account-store eviction. Invitation acceptance preserves
archive; successful rejoin restores departed conversations. Independent live account attention combines accepted
Unread-list counts with one attention item per active unarchived pending invitation. Archived and departed/departing
groups contribute nothing. It reports unavailable accounts explicitly and refreshes affected accounts without opening lists.
C4 M4 adds UniFFI/C handles, typed window errors and native ownership/parity checks;
release and client adoption remain separate. See the [native handoff](../further-context/chat-projections-native.md),
[bounded live chat-list windows](../further-context/chat-list-windows.md) and
[independent account attention](../further-context/account-attention.md).

Foreground push registration is idempotent when the provider token, platform, server, and relay hint are unchanged:
it preserves the durable revision and completed or pending gossip work instead of broadcasting to every joined
conversation again. Changes to those registration inputs still queue the new revision for all joined groups.
Account workers process scheduled convergence one group per turn, retaining the other groups' deadlines and
alternating queued commands with due recovery passes so neither queue starves the other. Each pass retries group
subscriptions only when a refresh is pending; an unchanged group set needs no account-wide refresh. A running
engine or relay operation still completes before a queued command executes; this is not a wall-clock send latency
guarantee.

Accepted disband requests keep a worker wakeup even without other group work, and hydration restores that wakeup
after restart. The selected inbound convergence replay retains authenticated disband evidence before removing the
former roster. Terminal event projection uses the retained display components and authoritative tombstone instead
of querying deleted MLS state. Failed requests and unrecoverable groups do not acquire an idle retry loop from this scheduling.

`forget_group_local` is a separate account-device operation from leaving, disbanding, and deleting chat history.
It transactionally deletes local app and MLS state with a durable reset cutoff, then removes runtime scheduling and
subscriptions. It needs no peer acknowledgement and works on stalled or pending-disband groups. While awaiting a
new Welcome it cannot resume group work. A fully validated Welcome for the same MLS group id may join with clean
state only when its sender-authenticated inner creation time is strictly newer than the cutoff and its author
matches the MLS inviter. Missing timestamps and equal-second/older invitations are rejected, even when received
later or rewrapped. Normal invitation confirmation policy still applies. The cutoff survives the new join and
restart for Welcome admission. Ordinary post-join messages pass normal MLS validation and the new join-epoch floor,
without a wall-clock drop filter that could mute peers with skewed clocks. Unreadable transport traffic follows the
normal bounded deferred-peel policy; previous chat history and rewind anchors remain erased. Repeated forgetting while awaiting
a Welcome preserves the cutoff; forgetting after a successful join establishes a new one. Clock skew can cause a
legitimate invitation to fall before the boundary; generate another invitation after the sender clock crosses it.
Timestamp filtering is replay policy, not proof against an authorized inviter deliberately redating old content.
Legacy permanent markers migrate to a cutoff at migration time. Ordinary `delete_group_local` still retains
membership and permits fresh messages to recreate the chat. The Rust runtime, UniFFI (`forgetGroupLocal` in Swift), and C expose forgetting; hosts
must close group views/subscriptions and clear host-owned media caches. Existing published or already in-flight
network traffic cannot be recalled. Transport cleanup failures retry without undoing the committed local deletion.

One durable owner now authorizes account-history acquisition from startup, receive, maintenance, convergence and
explicit repair. Coalesced demand keeps independent completion predicates and shared retry eligibility across reopen.
Full-history repair retains one activation across checkpointed work quanta, with a 60-second cooperative overall
budget and safe-boundary cancellation. EOSE alone is not qualified history coverage; the current SDK reports honest
incomplete outcomes. Loss retirement requires qualified admission and an exact live acknowledgment, with cursor
safety and durable debt preserved on failure. Snapshot reads can run during the wait; mutations retain account FIFO
ordering. Network waits remain on the account worker; nonblocking acquisition/scheduling belongs to #1947.
See the [owner integration ledger](../further-context/account-recovery-integration.md) for the acceptance matrix,
same-schema conservative mode, coordinated migration landing and approved unresolved-watermark retention exception.

Superseded invitations now retain their recipients while the app resolves fresh KeyPackages and queues a new
canonical invitation. A recipient already active on the discarded branch receives a durable rejoin offer and must
explicitly confirm replacing that MLS state; local message history remains. `group_recovery_status` exposes offers,
pending/failed inviter recovery, and an `automatic_recovery_failed` warning from distinct paced local observations
with qualified history evidence while the engine remains stalled. EOSE or repeated replay alone cannot mint that evidence. Local self-updates cannot clear a latched warning. Rust runtime, UniFFI, and C expose query, confirm, and decline commands. Hosts must display the
Welcome author and request explicit consent; these commands do not infer consent from ordinary invite acceptance.
See [invitation recovery](../invitation-recovery.md) for persistence, retry, and integration contracts.

The C3 row completion adds bounded selected draft/message/invitation/empty previews and local
row-action availability to presented rows. Draft invalidations refresh both list APIs without
changing activity order or unread state. See [the native contract](../../../crates/marmot-uniffi/CHAT-LIST-ROWS.md);
this is an unreleased follow-up to 0.10.2, with C9 client/device adoption still separate.

The additive presented-chat-list contract exposes complete existing rows plus durable MDK-selected title/avatar
through Rust, UniFFI and C. An attached initial snapshot and ordered replacement updates cover both presentation and
ordinary row changes. Android/iOS adoption remains separate; see the
[native integration contract](../../../crates/marmot-uniffi/README.md#selected-chat-list-presentation).

Deferred transport resource release now preserves app replay eligibility across
lost engine effects and restart. SQLCipher records release evidence atomically
with raw-byte deletion; app recovery retires both inventory and duplicate
receipts before readmission. See [released transport receipts](../storage-format-v2.md#released-transport-receipts).
The production retention and retry limits remain unchanged.

Same-database first opens now serialize SQLCipher key selection, schema migration
and handle publication; salts cannot be overwritten by competing initializers.
Android publishes key material with a per-destination file lock and atomic rename,
preserving API 26 support without hard links; iOS and macOS retain hard-link publication.
Generated identities remain unavailable to background attention and managed workers
until local readiness. Failed pre-readiness setup preserves its files and keys
without preventing healthy accounts from starting; it does not automatically erase
or repair an unreadable database. See [local artifact safety](local-artifact-safety.md#initializing-encrypted-account-databases).

MDK now exposes opt-in durable onboarding for imported identities, with per-step
validation, repair proposals, explicit approval, and Swift/Kotlin/C bindings.
It requires single-device acknowledgment before KeyPackage publication and offers
advisory detection of packages that may belong to another installation.
Account onboarding gates normal worker commands until required checks and
KeyPackage publication complete. Hosts can cancel an interactive attempt at any
step, including approved or ready checkpoints: the account stays signed out, the
attempt is retired, and its exact evidence is retained in the latest cancellation
checkpoint. A later cancellation replaces earlier evidence even if publication
is uncertain. Explicit recovery preserves unreadable/exhausted checkpoints as
opaque evidence and establishes a fresh approval epoch; hosts must adopt the
epoch-aware approval APIs for recovered attempts. Ordinary checkpoints remain
v3; recovered checkpoints use v4 to exclude unsafe older readers. Cancellation of a proposal is
distinct from cancelling a signer future and from ending the attempt. Open Chats
remains host-owned. Host apps still need to adopt the identity-only
entry points and render the screen; see the [binding integration contract](../../../crates/marmot-uniffi/README.md#interactive-account-onboarding).

Where Marmot is today: the merged MIPs define the deployed protocol shape, this workspace is MDK at `0.9.0` (the
unifying bump above the previous `0.8.0` release), Marmot-TS gives us an independent TypeScript implementation, and the
CGKA engine/convergence workspace here is being shaped into spec text.

## The spec

**Merged MIPs:**

- **MIP-00** — Credentials & KeyPackages
- **MIP-01** — Group Construction
- **MIP-02** — Welcomes
- **MIP-03** — Group Messages and SelfRemove
- **Encrypted Media V2** — `marmot.group.encrypted-media.v2`, with frozen V1 support for already-joined legacy groups
- **MIP-05** — Push Notifications

**Implemented engine contracts:**

- **Distributed convergence** — deterministic branch selection for unordered transport input, including the durable
  frozen-pass boundary, in [`../distributed-convergence.md`](../distributed-convergence.md)
- **Bounded offline recovery** — background deferred peeling shares a row/time budget and reuses historical
  contexts within each sweep. The local public app regression recovers all 1,024 backlog messages, exchanges fresh
  traffic and preserves the timeline after restart; see
  [`APP_PATH_COVERAGE.md`](../../../crates/cgka-conformance-simulator/APP_PATH_COVERAGE.md) for scope and evidence.

**In PR / design:**

- **MIP-06** — Multi-Device Support
- **Marmot v2 protocol draft** — protocol principles, publish lifecycle, and MLS app components in
  [marmot-protocol/marmot](https://github.com/marmot-protocol/marmot)
- **CGKA engine canonicalization** — post-peeling commit/proposal/app-message contract in
  [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)

The current spec pressure point is commit ordering. MLS wants one ordered commit log; Nostr and other transports may
deliver unordered, duplicated, delayed input. The engine contract is where that mismatch gets resolved.

MDK now persists a per-group frozen convergence pass around that selector. The pass closes at the earlier of the pinned
one-second selection-relevant quiescence window and five-second absolute cap, resumes safely across restart, resolves
only its digest-bound membership set, and uses independent runtime deadlines so traffic in one group cannot postpone
another group.

Relay reconciliation replay progress is owned by each account's encrypted route state. It survives
subscription rebuilds and empty or failed comparisons, and advances before fetch I/O independently
of admitted event inventory. Retired routes are counted separately from reconciliation failures.
The SDK requires a route-scoped progress store instead of evicting cursors from a shared cache;
see [reconciliation progress ownership](../../../crates/transport-nostr-adapter/README.md#reconciliation-progress-ownership).

## Protocol implementations

### MDK (this repository)

This workspace is the Marmot Development Kit (MDK). Release `0.9.0` unifies every workspace crate under one version
cohort above the previous `0.8.0` MDK layout (`mdk-core`, `mdk-sqlite-storage`, and related crates). The current
crate tree under `crates/` is the production-shaped replacement: OpenMLS-backed engine, SQLCipher storage, Nostr
transports, multi-account app runtime, CLI/daemon/TUI, agent connector stack, UniFFI bindings, and conformance tooling.
The app runtime exposes an explicit prepared founding-image path: image validation/encryption and durable staging,
idempotent Blossom upload, and canonical group creation are separate host-visible operations. The final create uses
uploaded founding metadata and performs no media transfer; the older all-in-one founding-image API keeps its existing
uploaded-before-success semantics while also enforcing the new group-image byte, dimension, pixel, and format limits
before canonical creation.

The workspace maintains a compile-only browser WASM boundary for `cgka-traits`, `cgka-engine`, and
`transport-nostr-peeler` on `wasm32-unknown-unknown`. Required CI keeps those three libraries compiling with
warnings denied, and `just wasm-check` provides the matching local gate. This is a portability boundary, not a
browser-runtime acceptance claim: SQLCipher storage, `marmot-app`, UniFFI/C bindings, the CLI, and daemons remain
outside its scope, and browser execution still requires downstream acceptance coverage.

Hosts can also send app-defined custom events: any non-reserved application event kind with verbatim tags and content,
through `marmot-app`, the MarmotKit bindings, or `wn messages send-event`. Stored events are queryable by kind on
every message surface, and custom kinds materialize as standalone timeline rows under a dedicated `CustomEvent`
update trigger. Kinds MDK owns (chat, reactions, edits, deletes, agent, group system, push token) are rejected on
the custom send path, so apps cannot forge protocol events.

The Claude Code, Codex, OpenCode, and Pi terminal harnesses share typed `inherit`,
`autonomous`, and `unrestricted` execution intent while retaining
backend-specific approval and sandbox semantics. Unrestricted installs require
explicit acknowledgement and an external OS-user, container, or VM boundary;
see [`terminal-harness-execution-profiles.md`](./terminal-harness-execution-profiles.md).

### Marmot-TS (TypeScript)

Marmot-TS is an independent implementation. It is valuable because it catches spec ambiguity that a single reference
implementation would normalize.

## Client reference implementation

### whitenoise-rs + whitenoise

whitenoise-rs is the application core for the Flutter client. It owns account management, relay control, event
processing, chat projection, push notifications, and other app-layer work that should stay above the CGKA engine
boundary.

Known architecture pressure remains in the application layer: large database surface, relay-control migration, and
event-processing complexity. Those are separate from the CGKA engine convergence work.

## Current CGKA engine workspace

This repository now has the main engine candidate:

- `crates/fs-private` — restrictive-by-construction helpers for local files, directories, and Unix sockets.
- `crates/traits` — cross-boundary value types and traits, including the account-aware `TransportAdapter` boundary.
- `crates/cgka-engine` — OpenMLS-backed engine implementation.
- `crates/cgka-session` — production-shaped account-device session wrapper over `Engine<SqliteAccountStorage>`.
- `crates/marmot-account` — account/session orchestration over a session and transport adapter. It activates the transport
  account, uses static transport routing for early harnesses, publishes fresh KeyPackages through an injected boundary,
  and confirms or rolls back pending session work from adapter publish reports.
- `crates/marmot-app` — first multi-account app runtime over account home, per-account projections, shared
  relay/directory cache, relay-list setup, KeyPackage lookup, runtime subscriptions, and app-facing
  group/message/member methods. Detailed group creation returns the exact chat-list row committed with the local
  projection; founding Welcome fanout stays post-response and its app repair index is reconstructed from
  engine-authoritative retained obligations. Its per-account directory cache has an independent numbered migration
  ledger and future-version refusal; installation-wide `shared.sqlite3` now has its own independent
  `shared_schema_migrations` history with transactional adoption of recognized unversioned layouts. See
  [App SQLite Storage Boundaries](../further-context/app-sqlite-storage-boundaries.md).
- `crates/cli` — first real CLI, daemon, and TUI surface over `marmot-app`. It is intentionally product-facing rather
  than a lab harness, and its JSON envelope is shaped for daemon/TUI/testing callers.
- `crates/storage-sqlite` — SQLCipher-backed SQLite storage for Marmot and custom OpenMLS state, with Rust migrations
  for schema/data evolution. Tests and the simulator use its in-memory SQLite mode by default.
- `crates/transport-nostr-adapter` — Nostr transport adapter core for account activation, group subscription sync,
  relay-event routing, and endpoint-level publish reports behind an injectable relay-client boundary. It also has the
  first Marmot kind `30443` KeyPackage event builder/publisher boundary, with MIP-00 metadata supplied explicitly. Its
  optional `sdk` feature provides the first `nostr-sdk` backed relay client.
- `crates/transport-nostr-peeler` — Nostr boundary mapping for kind `445` / `1059` events, kind `445` group envelope
  peeling, and NIP-59 welcome wrap/peel with injected local signer/decrypter.
- `crates/transport-quic-stream` — raw QUIC transport binding for transient agent text stream previews over reliable
  ordered QUIC streams, with transcript hashes tied to durable MLS start/final app-message payloads. Encrypted
  publishers reserve the next sequence and transcript in the per-account SQLCipher database before writing records;
  ambiguous crash state disables that start's live preview rather than risking nonce reuse.
- `crates/transport-quic-broker` — memory-only QUIC pub/sub broker for forwarding live preview records by
  `stream_id + start_event_id` without account state, relay integration, or payload persistence.
- `crates/cgka-conformance-simulator` — multi-client simulator, vectors, generated scenarios, and property tests.
- `crates/marmot-markdown` — CommonMark and Nostr-aware display parser for app message rendering.
- `crates/marmot-forensics` — opt-in v4 JSONL forensic audit schema and recorder traits. Account/device display names
  are excluded; platform, app version and optional system hardware model are retained. Size-rotated segments repeat
  the latest source context with fresh sequence numbers in the same recorder session. App uploads validate v4-only
  snapshots. Exclusive-root app startup removes recognized legacy forensic files and segments, including failed-wipe
  remnants, while preserving v4 files and the separate key-reveal log. See [audit logging](../audit-logging.md).
- `crates/marmot-uniffi` — UniFFI bindings and build scripts for Swift/Kotlin app runtimes.
- `crates/agent-control` — `marmot.agent-control.v2` DTOs and newline-delimited JSON framing for agent integrations.
- `crates/agent-stream-compose` — reusable live-preview stream composition over the QUIC broker publisher.
- `crates/agent-connector` — local `wn-agent` connector daemon bridging agent control, account runtime, and stream
  composition; Hermes and OpenClaw plugins talk to it over a Unix socket. Version 2 stream sessions use random
  per-stream bearer capabilities, reject active stream-id collisions, and replay the original begin receipt for an
  identical request-id retry.
- `integrations/hermes/marmot` and `integrations/openclaw/marmot` — thin control-plane-only agent plugins.
- `formal/tamarin` — formal models for the convergence selector, delivery-order robustness, lifecycle cases, and
  proof/test mapping.
- [marmot-protocol/marmot](https://github.com/marmot-protocol/marmot) — canonical Marmot v2 protocol draft by stable
  surface, including protocol principles and app components (external to this repo).

The current workspace can exercise the peeler-ingest boundary through in-memory clients, reopen encrypted
SQLCipher-backed account-device sessions, preserve MLS signing identity across those reopens, drive a real
`AccountDeviceSession` + `NostrTransportAdapter` + `NostrMlsPeeler` stack over an in-memory relay client, cover publish
ack/fail resolution and delivery/invite-lifecycle chaos cases at that stack boundary, exercise a transport-generic
account runtime for activation, KeyPackage publication, and publish confirmation/rollback, converge stored OpenMLS
messages, emit application-visible group events, model losing-branch invalidations, and test generated delivery
variants.

Generated-account creation now has an explicit durable local-ready entry point. The identity, default profile, setup
journal, stable KeyPackage slot, private KeyPackage material, and exact signed initial publication are persisted before
that entry point returns. Bootstrap/profile/KeyPackage publication then continues as restart-resumable background work;
the compatibility `create_identity` entry point still waits for `NetworkReady`. Hosts using the local-ready entry point
must honor `AccountSetupReadiness`: `LocalReady` is sufficient for local reads and profile rendering, while only
`NetworkReady` means the account may be presented as invite-receivable. `Initializing` means local setup has not yet
reached durable local readiness. `Publishing` includes bounded in-session retry and restart-resumable publication, and
`RecoveryRequired` requires an explicit recovery flow.

## Known gaps

- **Production persistence hardening** — `storage-sqlite` provides encrypted persistence, atomic group snapshots,
  retained-anchor pruning, and privacy-oriented SQLite defaults. `cgka-session` opens one encrypted database per
  account-device identity. App key-management integration, packaging, and longer-term rekey/vacuum/checkpoint policy
  still need production wiring.
- **App-core hardening** — `marmot-app` and `wn` now exercise real account setup, key storage, relay-list repair,
  KeyPackage publication/fetch, directory cache, group membership, group profile projection, message projection, local
  archive state, and sync. Group composition now resolves canonical deduplicated member sets through bounded
  multi-author relay batches, with a non-reserving process-local prewarm path and final mutation-boundary revalidation.
  The next hardening pass should keep app policy in `marmot-app`/`marmot-account` and keep
  `wn` focused on command presentation and stable JSON output. The current boundary is summarized in
  [`app-core-boundary.md`](./app-core-boundary.md).
- **Production transport adapters** — `transport-nostr-adapter` now implements the Nostr adapter core over an injectable
  relay-client boundary, with an optional `nostr-sdk` relay client, exact stale group subscription cleanup,
  adapter-local metrics, privacy-safe tracing, and redacted SDK relay-health summaries. The SDK owns reconnect/backoff,
  retry interval adjustment, jitter, and relay status mechanics. The session crate now has an in-memory relay
  integration harness that drives NIP-59 welcomes, `marmot.transport.nostr.routing.v1`-backed kind `445` group messages,
  invite group evolution, insufficient acks, publish errors, subscription gating, duplicate delivery, reordered delivery,
  invite commit/welcome order variants, and terminal stale-epoch invite commits through the real session, adapter, and
  peeler stack. Production relay auth, relay safety policy, full KeyPackage metadata derivation through the transport
  layer, and account key-management wiring still need integration. The opt-in relay-telemetry export pipeline is built:
local visibility via `wn relay-stats`, an opt-in index→identity resolution boundary, a relay-plane rollup, and an
opt-in OTLP exporter (wire encoding behind the `marmot-app` `otlp-export` feature) — all aggregate, off by default, and
carrying relay identity as the sole label. Wiring its periodic push into a long-running host against the production
first-party endpoint remains ops work; see [`../relay-observability.md`](../relay-observability.md). Each OTLP attempt
now validates every resolved collector address and pins the client, with redirects and proxies disabled. The existing
explicit loopback-test endpoint contract remains local-only; see [Dial Safety](dial-safety.md).
- **Nostr account transport shape** — the likely production shape includes a Nostr user directory, account bootstrap for
  relay-list events, a shared multi-account relay plane, `marmot.transport.nostr.routing.v1` group routing, and explicit
  relay URL safety policy. This is captured as a working note in
  [`nostr-account-transport.md`](./nostr-account-transport.md), but it should not pull focus away from the engine work.
- **Byte-level and scenario vector maturity** — the simulator has a growing portable scenario fixture set, generated
  chaos families, and a runner that writes JSON reports with expectation failures plus generated fixture candidates.
  `convergence-chaos/v1` is the first convergence-focused generated family with built-in semantic expectations, 20+
  client stress cases, mixed message/commit storms, and conservative generated-failure minimization. The byte-level
  vector plan is still thin beyond the first app-component encoding fixtures.
- **whitenoise-rs integration map** — the first integration path is likely a shim over `cgka-session` /
  `marmot-account`, with whitenoise-rs keeping account setup, Nostr directory state, relay-list repair, and shared relay
  plane ownership. The current friction points are tracked in
  [`whitenoise-integration-map.md`](./whitenoise-integration-map.md).
- **Deep same-epoch app-message reordering** — the seeded stack-chaos runner keeps generated app-message reordering
  shallow. A deeper generated reversal exposed OpenMLS `TooDistantInThePast` behavior in the message generation secret
  tree. We need an explicit policy for how much same-epoch app-message reordering the transport/session layer promises
  to tolerate, and how to classify messages outside that window.
- **Portable fork-recovery vectors** — `group-data-fork-recovery/v1` and `concurrent-invite-fork-recovery/v1` are
  semantic fixtures. They check recovery outcomes without requiring exact randomized MLS commit bytes. Exact byte
  fixtures remain for deterministic encodings and transport shapes.
- **Safe Extensions framework support** — still gated on backend library support and migration design.
- **`IdentityRemove` proposal type** — identified as the first likely Marmot-custom proposal, not specified or
  implemented.
- **KeyPackage refresh scheduling** — still a higher-layer production scheduling concern. The engine validates transported
  KeyPackage lifetime validity and range policy; product/session orchestration owns proactive refresh cadence.

## See also

- Target architecture: [`target-architecture.md`](./target-architecture.md)
- Direction: [`direction.md`](./direction.md)
- Engine quality and vectors: [`cgka-engine-quality-and-vectors.md`](./cgka-engine-quality-and-vectors.md)
- Nostr account transport notes: [`nostr-account-transport.md`](./nostr-account-transport.md)
- whitenoise-rs integration map: [`whitenoise-integration-map.md`](./whitenoise-integration-map.md)
- Canonicalization contract:
  [`../cgka-engine-canonicalization-contract.md`](../cgka-engine-canonicalization-contract.md)
- Distributed convergence: [`../distributed-convergence.md`](../distributed-convergence.md)

Usage and diagnostics now has a shared consent receipt and independent OTLP and
stock-Aptabase exporter paths; see [the host contract](../usage-diagnostics.md).
Native consent UI adoption and deployed Aptabase retention verification remain
separate rollout work.


C7-C adds screen avatar metadata, bounded local encoded-byte batches and acquisition/cache invalidation delivery to
resolved chat and conversation subscriptions, with matching UniFFI/C surfaces. C7-B's durable worker remains the
network owner. Client cache migration and flagship-device evidence remain C9 follow-through; this is not a release.
