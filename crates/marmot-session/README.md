# marmot-session

The account-device layer between `marmot-app` and the protocol engine. One `AccountDeviceRuntime` per Marmot
account-device identity opens an `AccountDeviceSession`, the production-shaped wrapper around
`Engine<SqliteAccountStorage>`, and coordinates it with a pluggable `TransportAdapter`. Each lifecycle method returns
app events plus publishable transport work, and the runtime publishes that work, then confirms or rolls back the
session's pending state. App and runtime developers embedding Marmot below `marmot-app` are the main audience.

The crate root is the facade: the runtime, its effects, `SessionConfig`, the errors, and the engine types the session
exposes. The session itself is a private module; the `test-support` feature re-exports it for tests that drive it
directly.

## Opening a session

`SessionConfig::new(database_path, database_key, identity, peeler)` takes the SQLCipher database path and key, the
local identity, and a `TransportPeeler`. `AccountDeviceSession::open` also requires an account identity-proof signer
(`SessionConfig::account_identity_proof_signer`). Optional builder methods set the feature registry, supported
app-component set, protocol profile, storage options, convergence policy, forensic recorder, and maintenance clock/RNG
sources. `SessionConfig::with_storage(storage, opened_in, identity, peeler)` instead runs the session on a connection the host has
already opened, for hosts that must close every connection at a known instant (an iOS app before suspension).

Open fails closed before touching storage if the convergence policy is unacceptable or a legacy protocol profile is
requested without `legacy_compatibility_profile()`. It then opens encrypted storage, builds the engine, retires (for
the current profile) non-current local KeyPackages, and hydrates stored groups. By default hydration is eager: every
group is fully hydrated (or quarantined) before `open` returns. `defer_group_hydration()` runs only the cheap seed
pass; groups are listed but return `GroupNotHydrated` until the host calls `hydrate_next_groups` /
`ensure_group_hydrated` or a send or ingest promotes them on demand. Embedders without a background pipeline should keep
the default.

## What the runtime does

- Opens one local `AccountDeviceSession` from a `SessionConfig` (`AccountDeviceRuntime::open`) and is the host's only
  way to it. The `test-support` feature exposes the session itself, for tests that drive it directly.
- Activates the transport account for that session.
- Publishes fresh KeyPackages through an injected boundary, and drives KeyPackage generator upgrades.
- Turns `SessionEffects.publish` work into `TransportPublishRequest`s, then confirms or rolls back pending session state
  from the adapter's publish reports.
- Reconciles epoch changes and local copy restoration with maintenance quiet windows. Failed bookkeeping stays owned
  for retry without withholding confirmed effects, including when recovery-control ingest resumes publication.
- Keeps a confirmed fanout scheduler-visible while linked Welcomes still await publication bookkeeping. Its retry
  cutoff follows the Welcomes' durable endpoint backoff; work without a stored cutoff uses the ordinary retry delay.
  Welcome backoff does not postpone earlier-ready group work; an incomplete group publication still orders later ones.
- Keeps transport routing policy generic, so the first implementation can be Nostr without baking Nostr into the
  session or engine crates.
- Reserves authenticated Unrecoverable rejoin work through `prepare_group_recovery`; the host resolves only the
  returned members' safe inbox routes, then calls `advance_group_recovery` on the same runtime with held group IDs
  and a caller-owned effects buffer. Apply appended effects even when advancement returns an error. Retry reservations
  and publication continuation are durable. `MarmotAppRuntime` drives this loop automatically; see the
  [rejoin contract](../../docs/marmot-architecture/invitation-recovery.md#automatic-rejoin-of-an-unrecoverable-copy).

## What the session does

- Opens one encrypted SQLite database for one Marmot account-device identity.
- Builds `Engine<SqliteAccountStorage>` with an injected `TransportPeeler`.
- Surfaces `GroupEvent`s and publishable transport work as `SessionEffects`.
- Preserves the publish-before-apply contract: callers confirm or fail pending group operations after transport
  publish, including auto-publish work created while ingesting inbound messages.
- Restored automatic publications retain their own pending reference and linked Welcomes. They cannot supply a
  caller's deferred fanout; their Welcomes leave only after their own Commit acknowledgement.
- Exposes convergence advancement (`advance_convergence`, `advance_convergence_inputs`) so queued outbound work can be
  regenerated from canonical state.
- Exposes durable maintenance, KeyPackage-lifecycle, group-evolution, and transport-fanout records for the account
  layer above it, read and written on the session's own clone of the engine's connection. Group-scoped records ask the
  engine whether the group is live first, so quarantined and unhydrated groups fail as they do on engine accessors.
- Provides compact `group_authority` reads and `with_group_authority_snapshot` for composing host-owned persisted
  reads with current engine facts on this session's store. The callback is synchronous and read-only; unhydrated groups
  return `GroupNotHydrated`. It does not serve a frozen startup snapshot or start relay work. `GroupAuthorityView`
  lends only that read, for code a host hands the session to.
- Provides `canonical_group_membership` for startup reconciliation: authenticated leaf indexes and account
  identities, plus whether this device's own leaf is active. Pending roster projections do not replace those facts.
  Live termination and token cleanup use immutable engine effects captured at apply, rather than this reader.
- Offers `promote_legacy_message_rows` for bounded promotion of legacy stored rows after readiness. Its tests drive it
  here; a host schedules the same promotion on its own clone of the engine's connection.
- Wraps the configured forensic recorder in the account-device's `SharedRecorder`, builds the engine with a clone,
  and writes the open-time `recorder_health` row. `audit_recorder()` hands out the handle; the runtime and the host
  record, rotate and finish the log through their own clones.
- Re-exports the engine types its configuration, signer and group-authority reads expose, the KeyPackage
  metadata and inventory helpers, and the application message size model, so hosts never name `cgka-engine` directly.

The session does **not** do account key derivation, recovery, or key rotation; relay sync, network publish, or
transport adaptation; or UI projection and application databases. Network publish is the runtime's job; the rest lives
in [`marmot-account`](../marmot-account/) and [`marmot-app`](../marmot-app/).

## Routing model

`TransportRoutingPolicy` is the transport-generic boundary. It answers:

- which account inbox endpoints to subscribe to for welcomes;
- which group subscriptions to keep active;
- which endpoints should receive a given outbound transport message;
- which endpoints should receive fresh KeyPackages;
- how many publish acknowledgements are required before pending work is confirmed.

A production Nostr implementation should derive those answers from Nostr state rather than hard-coded configuration:

- account inbox relays are the user's always-on welcome / gift-wrap relays;
- group subscriptions and group-message publish targets come from the group's current
  `marmot.transport.nostr.routing.v1` app component;
- KeyPackage publication targets come from the user's kind `10002` NIP-65 relay list (the same outbox relays the
  account publishes through); there is no dedicated KeyPackage relay list;
- publish acknowledgement thresholds remain app policy over the chosen endpoint set.

`StaticTransportRouting` is only the simple configured implementation used by tests and early harnesses.

`KeyPackagePublisher` is a provisional boundary. The likely production shape moves KeyPackage publication into the
transport adapter family, so the account runtime can ask the active transport to publish a KeyPackage without knowing
whether that means Marmot Nostr kind `30443`, another relay-plane format, or a future non-Nostr transport.

## Own-leaf maintenance

Secondary maintenance write failures do not discard committed session effects. `run_due_maintenance` retries the
owning group's reconciliation and reconstructs missing deadlines for enrolled live copies after restoration or reopen.
Ordinary epoch activity uses the durable rotation baseline; an observed restoration starts a fresh period.

An obligation stays live until its next deadline is durable. After reopen, the canonical leaf hash identifies rotations
that already committed, so completing their bookkeeping does not publish another MLS commit. Repaired deadlines stay
within the 24–36-day policy window and do not reuse failed or completed periodic obligation IDs.

## Refreshing stale leaves

A new build can support an app component that existing groups predate. A group can start requiring a component only
once every member's leaf advertises it (the spec's "Enabling a Component in an Existing Group").

For every live group, enrolled or not, `run_due_maintenance` schedules a leaf refresh when the own leaf advertises fewer
components than the build supports:

- **When.** The self-update runs at a random time within 5 days, so a release does not make every member of a group
  commit at once. The due time is stored on the group's maintenance record, so a restart keeps the sampled delay.
- **How.** The self-update goes through the ordinary obligation pipeline, so every commit hold applies, and it
  re-advertises the supported set. Any own self-update already in flight satisfies the refresh.
- **Cost.** The engine is queried for each group at most every ten minutes unless a due time has arrived. A group whose
  state cannot be read is skipped for that tick without stopping maintenance for the rest of the account.

Maintenance only refreshes leaves. Requiring a component in a group is a separate admin step, and nothing here does
it.

## This device's KeyPackage slot

Each device keeps one KeyPackage in its own slot and replaces it in place
(`foundation/key-packages.md`, "Refreshing a slot"):

- **Lifetime.** A fresh KeyPackage is valid for 30 days plus an hour of clock-skew margin. Receivers still accept the
  84-day validity limit, so KeyPackages from other clients keep working.
- **When it is replaced.** After a Welcome consumes it, when the KeyPackage no longer advertises what this build
  supports, and at least every 7 days while the runtime runs, always before it expires. The weekly refresh is due at a
  random time 6 to 7 days after publication, stored with the lifecycle so a restart keeps it. `run_due_maintenance`
  does the work; account open does not wait for it.
- **Superseded KeyPackages.** An inviter may already hold the old KeyPackage, so its private key stays for 24 hours
  after the replacement's publication is confirmed, or until it expires if that is sooner. A KeyPackage a Welcome
  consumed is kept for 24 hours after it was replaced, without waiting for a confirmed replacement. A retained
  KeyPackage keeps its publication id, so a Welcome must still name it.
- **Artifacts it can no longer send.** A publisher reports a signed KeyPackage it will never send (for example one an
  earlier build signed with a client name over 64 bytes) as `artifact_unusable`. The runtime then replaces it with a
  freshly signed KeyPackage in the same slot instead of retrying it until it expires. Each build does this at most
  once, so a publisher that refuses its own artifacts cannot make it generate a KeyPackage per attempt.
- **Stopping publication.** At sign-out, `withdraw_key_package_slot` asks the slot's relays to delete it, naming only
  this device's slot, so the account's other devices keep theirs. The runtime records the withdrawal before sending it
  and publishes nothing more into the slot. A request no relay accepts is undone and returned as an error. The next
  runtime for the account republishes into the slot with a newer timestamp; a replacement prepared before the
  withdrawal is never published after it.

## KeyPackage generator upgrades

The lifecycle records the KeyPackage generator revision independently of app versions. Records written before revision
tracking default to zero; revision 1 regenerates packages to omit RFC 9420 default capability advertisements.
`MarmotApp` attempts the upgrade on account activation, and `run_due_maintenance` retries durable publication work.
Embedders that use `AccountDeviceRuntime` directly must drive maintenance themselves.

- Fresh private material, its revision, and replacement intent are stored atomically before signing/publication.
- Only a relay acknowledgement promotes the current revision; remaining targets keep their existing fanout retries.
- An old pending replacement is superseded with a strictly newer authoring timestamp in the same stable slot. Its
  private bundle is retained like any superseded KeyPackage, because publication may already have occurred.
- Previous unused current bundles keep their existing expiry/consumption policy.
- Ordinary releases do not bump the generator revision.
- Paused maintenance can finish a prepared current-revision publication, but waits for resume before replacing an
  older pending revision, because that requires generating new private material.

## Queued sends and relay retries

Frozen relay events retain their original bytes, targets and retry order until each outstanding obligation resolves.
Once a group's required acknowledgements and MLS confirmation are complete, a secondary relay's replication retry no
longer blocks new engine-queued application sends. This uses the same publication boundary as foreground sends.
An unmet quorum or pending MLS confirmation still blocks the queued drain, including obligations behind an older
completed-quorum event. Incoming convergence can settle while that publication barrier remains.

Ordinary lower-level convergence calls still await due relay attempts. Owners using
`advance_convergence_with_publication_progress_and_yield` can supply a signal that ends optional secondary waits
after required acknowledgements and MLS confirmation. The signal remains latched for that pass; a later quiet pass
can resume replication. A cancelled attempt keeps its exact bytes and targets, conservative exposure state, and
ordinary retry backoff. An attempt skipped before starting keeps its existing deadline. This does not cancel engine
steps, bypass required publication barriers, or guarantee zero network delay or universal per-relay FIFO delivery.

## What it does not do

- No account homes, signing-key storage or NIP-49 export (see `marmot-account`).
- No UI projection or message database (see `marmot-app`).
- No account-recovery or key-migration UX.
- No derivation of full MIP-00 KeyPackage metadata from fresh engine KeyPackage bytes yet.
- No relay auth, relay-list discovery, relay-list repair, or relay health scoring.

## Tests

```sh
cargo test -p marmot-session
```

- `tests/runtime.rs` plus `tests/runtime/` — the account-device runtime over a real session and a scripted transport:
  transport activation, KeyPackage publication, rotation and retention, Welcome publication and withdrawal, durable
  maintenance, publish confirmation and rollback, frozen fanouts and relay retries, KeyPackage generator upgrades,
  app-component migration, and each device of an account joining only through the Welcome delivery that names its own
  KeyPackage, including, in a group that requires account-devices, a Welcome from another device of the account. An
  upgrade to advertising account-devices replaces the published KeyPackage in its slot and refreshes each existing
  leaf at its own random time.
- `tests/session_lifecycle.rs` — encrypted open/create/confirm/close/reopen, Welcome and app-message ingest,
  auto-publish and SelfRemove re-proposal work, convergence releasing queued outbound work, disband requests, compact authority
  capture, the account records' liveness gate and closed-store failures, KeyPackage cutover on open, and the legacy-row
  promotion facade (using
  [`fixtures/session-promotion-v1.bin`](fixtures/README.md)).
- `tests/nostr_stack.rs` — the production-shaped non-relay stack: SQLCipher storage, the real `NostrMlsPeeler`, and
  `NostrTransportAdapter` over an in-memory relay client. Covers inbox and group subscription routing, NIP-59 Welcome
  and kind `445` group delivery, routing-component-driven `h` tags and publish targets (the transport id is not the MLS
  group id), publish ack/insufficient-ack/error resolution, duplicate and out-of-order delivery, and invite evolution
  with commit and Welcome outputs.
- `tests/nostr_stack_chaos.rs` — seeded no-network delivery-chaos scripts against the same stack, including invite
  lifecycle chaos (wrong-route drops, Welcome replay, shared commit fanout, Welcome/commit ordering). Reports go to
  `target/session-stack-chaos/`.

Test placement rules: [`tests/AGENTS.md`](tests/AGENTS.md).
