# marmot-account

Account-device orchestration for Marmot. This crate sits between `cgka-session` and the app runtime (`marmot-app`): it
owns the local account home, account records, signing-key storage, and the coordination between one
`AccountDeviceSession` and a pluggable `TransportAdapter`. App and runtime developers embedding Marmot below
`marmot-app` are the main audience.

## What this crate does

- Creates and imports local signing identities in an app-owned home, with Nostr public keys as the stable account ids.
  Callers can derive an account id from an nsec before writing any local state, so setup checks can run first.
- Stores public-only account records (no local signing material) for directory-style identity references, and
  external-signer account records.
- Stores signing keys behind an injectable `AccountSecretStore`: a platform keychain/credential-store backend
  (patterned after White Noise) and a local file backend for deterministic tests and development.
- Journals account setup and onboarding so an interrupted setup can resume or be cancelled cleanly.
- Exports a signing key as a NIP-49 `ncryptsec` backup.
- Activates the transport account for one local `AccountDeviceSession`.
- Publishes fresh KeyPackages through an injected boundary, and drives KeyPackage generator upgrades.
- Turns `SessionEffects.publish` work into `TransportPublishRequest`s, then confirms or rolls back pending session state
  from the adapter's publish reports.
- Keeps transport routing policy generic, so the first implementation can be Nostr without baking Nostr into the
  session or engine crates.

## Account home

`AccountHome` is the durable boundary for local account setup. It keeps public summaries separate from secret material.

- `create_nostr_account`, `import_nostr_account`, and `add_public_account` use the Nostr public key as the record label
  for product-facing app surfaces. The older label-taking helpers remain for deterministic lab setup.
- Real app surfaces should use `AccountHome::open_with_keychain` or `open_with_default_keychain`. Tests and local labs
  can use `AccountHome::open`, which uses the local file secret store.
- Relay-list discovery and repair belong above this crate in the Nostr account transport / app-runtime layer. CLI
  account selection belongs in presentation surfaces such as `wn`.

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

## KeyPackage refresh

Running accounts generate a fresh package and event in their installation's persistent random `d` slot every seven
days, or at the existing expiry-based deadline if earlier. Startup catches up overdue maintenance. MLS lifetime and
generator policy remain unchanged. Welcome consumption still triggers replacement on the next maintenance pass
(the managed app worker ticks every 15 seconds).

Superseded unconsumed current and pending bundles remain decryptable until a newer same-slot publication is
acknowledged, then for 24 hours from that ACK’s persisted wall-clock `replaced_at`, capped by MLS expiry. Staging or
unsuccessful publication never starts the grace period. This deliberately short grace covers Welcomes already in flight while gap filling is unavailable; sweeps
run even when network maintenance is paused. Consumed current bundles are deleted atomically on the first replacement
relay ACK, and consumed retained bundles are removed by the sweep.

`observe_key_package_slot_event` accepts authenticated own-author slot observations under the serialized account
owner. Unknown strictly newer events persist a coalesced conflict intent. Maintenance regenerates into the same slot
at most once per hour for conflicts, preserving pending publication retries, ignoring known authored echoes, and
enforcing the existing future-skew limit. Intent clears only when an acknowledged replacement is strictly newer.

## KeyPackage generator upgrades

The lifecycle records the KeyPackage generator revision independently of app versions. Records written before revision
tracking default to zero; revision 1 regenerates packages to omit RFC 9420 default capability advertisements.
`MarmotApp` attempts the upgrade on account activation, and `run_due_maintenance` retries durable publication work.
Embedders that use `AccountDeviceRuntime` directly must drive maintenance themselves.

- Fresh private material, its revision, and replacement intent are stored atomically before signing/publication.
- Only a relay acknowledgement promotes the current revision; remaining targets keep their existing fanout retries.
- An old pending replacement is superseded with a strictly newer authoring timestamp in the same stable slot. Its
  private bundle is retained for 24 hours from supersession (or until MLS expiry), because publication may already have occurred.
- Previous unused current bundles get the same 24-hour grace; consumed bundles are deleted on replacement ACK.
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

- No UI projection or message database (see `marmot-app`).
- No account-recovery or key-migration UX.
- No derivation of full MIP-00 KeyPackage metadata from fresh engine KeyPackage bytes yet.
- No relay auth, relay-list discovery, relay-list repair, or relay health scoring.

## Run the tests

```sh
cargo test -p marmot-account
```

See [`AGENTS.md`](AGENTS.md) for the module map and invariants.
