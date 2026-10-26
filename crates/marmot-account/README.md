# marmot-account

Account identity, files and secrets for Marmot: the local account home, account records, signing-key storage and
NIP-49 export. The account-device runtime that drives a session over a transport lives in
[`marmot-session`](../marmot-session/). `marmot-app`, the bindings, the CLI and the agent connector use this crate for
account identity.

## What this crate does

- Creates and imports local signing identities in an app-owned home, with Nostr public keys as the stable account ids.
  Callers can derive an account id from an nsec before writing any local state, so setup checks can run first.
- Stores public-only account records (no local signing material) for directory-style identity references, and
  external-signer account records.
- Stores signing keys behind an injectable `AccountSecretStore`: a platform keychain/credential-store backend
  (patterned after White Noise) and a local file backend for deterministic tests and development.
- Journals account setup and onboarding so an interrupted setup can resume or be cancelled cleanly.
- Exports a signing key as a NIP-49 `ncryptsec` backup.

## Account home

`AccountHome` is the durable boundary for local account setup. It keeps public summaries separate from secret material.

- `create_nostr_account`, `import_nostr_account`, and `add_public_account` use the Nostr public key as the record label
  for product-facing app surfaces. The older label-taking helpers remain for deterministic lab setup.
- Real app surfaces should use `AccountHome::open_with_keychain` with their deployment's keychain service name
  (`MarmotDeployment::keychain_service` in `marmot-app`; this crate compiles in no default). Tests and local labs
  can use `AccountHome::open`, which uses the local file secret store.
- Relay-list discovery and repair belong above this crate in the Nostr account transport / app-runtime layer. CLI
  account selection belongs in presentation surfaces such as `wn`.

## What it does not do

- No MLS state, session, transport or publish work (see `marmot-session`).
- No UI projection or message database (see `marmot-app`).
- No account-recovery or key-migration UX.
- No relay-list discovery or relay-list repair.

## Run the tests

```sh
cargo test -p marmot-account
```

See [`AGENTS.md`](AGENTS.md) for the module map and invariants.
