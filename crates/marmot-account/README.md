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
- Persists NIP-46 communication keys separately from user signing keys and database credentials, with
  crash-discoverable metadata and retryable local removal. Atomic stores return `Nip46SessionWrite`,
  distinguishing new credentials from the existing record retained on setup rollback.
  The protocol and permission approval live in
  `marmot-app`; see [external signer accounts](../../docs/external-signer-accounts.md#nip-46-sessions).
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

For runtime setup, use the setup-specific creation and import methods. They return the account and its captured
`AccountSetupState`. Pass that state to phase changes, completion, and compensation so an old task cannot change a
replacement attempt. The journal records whether setup created the account or promoted a public account before
publishing the account record or its new role.

To cancel an unpublished attempt, call `start_setup_compensation` before stopping its runtime, then call
`finish_setup_compensation` once the runtime has released the account. Retry `CompensationPending` rather than
starting the account. An old journal without recorded ownership can resume setup but cannot authorize compensation.

Explicit legacy reset preserves a native-vault signing key. If a local `secret.json` would enter the wipe payload,
reset returns `AccountSetupConflict` before changing the account or moving its files. The file-backed account and
key stay intact; retrying reset cannot recover this backend. Back up the signing key before wiping the account,
then import the backed-up key. Wipe also removes the account's local data.

Setup succeeds once the journal is removed. If the subsequent directory sync fails, that logical completion does not
guarantee the removal survives power loss. Failed context cleanup leaves the account complete and the private context
pending cleanup. A fresh attempt must clear it before admission.

Public-role restoration keeps a database-credential ownership marker so a later full wipe can retire that credential.
The current records cannot prove a historical credential is absent, so even a role-only restoration can leave a later
wipe with pending credential cleanup.

Opening an `AccountHome` does not remove leftover wipe directories. `MarmotApp` replays local file cleanup after
acquiring the root runtime lease. Lower-level hosts can call `resume_wipe_cleanup` under that exclusive lease;
replay retries completed setup context and detached payload cleanup, retains native cleanup records, and never removes
native credentials. A failed payload cleanup remains pending without blocking unrelated accounts. Invalid root
containers or rename-parent sync failures reject startup; replay refuses container symlinks.

On Windows, the private-file replacement fallback for shared readers is atomic. It does not request write-through
or guarantee durability across power loss.

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
