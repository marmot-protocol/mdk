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
that already committed, so completing their bookkeeping does not publish another MLS commit. Repaired deadlines do not
reuse failed or completed periodic obligation IDs.

## KeyPackage generator upgrades

The lifecycle records the KeyPackage generator revision independently of app versions. Records written before revision
tracking default to zero; revision 1 regenerates packages to omit RFC 9420 default capability advertisements.
`MarmotApp` attempts the upgrade on account activation, and `run_due_maintenance` retries durable publication work.
Embedders that use `AccountDeviceRuntime` directly must drive maintenance themselves.

- Fresh private material, its revision, and replacement intent are stored atomically before signing/publication.
- Only a relay acknowledgement promotes the current revision; remaining targets keep their existing fanout retries.
- An old pending replacement is superseded with a strictly newer authoring timestamp in the same stable slot. Its
  private bundle is retained until expiry, because publication may already have occurred.
- Previous unused current bundles keep their existing expiry/consumption policy.
- Ordinary releases do not bump the generator revision.
- Paused maintenance can finish a prepared current-revision publication, but waits for resume before replacing an
  older pending revision, because that requires generating new private material.

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
