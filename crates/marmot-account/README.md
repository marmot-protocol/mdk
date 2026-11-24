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
- Secret stores supply a stable, nonsecret `cleanup_namespace` identifying the physical vault and credential namespace.
  Pending wipes retry only through that namespace; switching stores does not discard the original deletion intent.
- Each credential owner has a durable receipt. Shared vaults discover signing keys by account ID and retain
  independent copies, so one home's wipe cannot delete another owner's credential.
- Persists NIP-46 communication keys separately from user signing keys and database credentials, with
  crash-discoverable metadata and retryable local removal. Atomic stores return `Nip46SessionWrite`,
  distinguishing new credentials from the existing record retained on setup rollback.
  Removal retires exact owners without first acquiring raw keys. Once the managed copy is retired, local removal
  completes even if raw legacy cleanup remains pending. Explicit pairing or removal durably closes new legacy
  admission before publishing a new session or discarding its owner reference. Reopening or retrying cannot
  reactivate retained raw keys; pending acquisition keeps its original claim mode.
  Promotion rollback restores the public role before retiring its session credential. A release failure leaves
  exact-owner cleanup pending; another promotion or pairing completes that removal before storing new keys.
  The protocol and permission approval live in
  `marmot-app`; see [external signer accounts](../../docs/external-signer-accounts.md#nip-46-sessions).
- Journals account setup and onboarding so an interrupted setup can resume or be cancelled cleanly.
- Moves the account out of the live catalog before cleanup. If syncing the parent directories fails, MDK defers
  credential release, secret-file scrubbing, and payload deletion until replay. After the sync succeeds, a vault
  failure does not stop local cleanup. A private, nonsecret tombstone retains failed credential deletion for retry
  under exclusive root ownership. Retries release the original receipt, not the current occupant of an account label.
  Ambiguous legacy vault entries remain untouched, with explicit pending cleanup metadata.
  Untracked raw intent survives replacement or deletion of a managed owner and cannot block its cleanup.
  Tombstones without readable deletion intent retain their account and ownership metadata.
- Exports a signing key as a NIP-49 `ncryptsec` backup.

## Account home

`AccountHome` is the durable boundary for local account setup. It keeps public summaries separate from secret material.

- `create_nostr_account`, `import_nostr_account`, and `add_public_account` use the Nostr public key as the record label
  for product-facing app surfaces. The older label-taking helpers remain for deterministic lab setup.
- When beginning runtime setup, use `add_public_account_for_setup` or `add_external_signer_for_setup` instead of
  creating a bare record and journaling afterward. They persist the setup journal before a new record or promotion
  becomes visible, under one mutation lease. The bare methods do not begin setup.
- Real app surfaces should use `AccountHome::open_with_keychain` with their deployment's keychain service name
  (`MarmotDeployment::keychain_service` in `marmot-app`; this crate compiles in no default) and `IosOptions`.
  Other platforms pass `IosOptions::default()`. Tests and local labs can use `AccountHome::open`, which uses the
  local file secret store.
- Opening an account home does not run destructive recovery. After acquiring exclusive cross-process ownership of
  the home, call `resume_wipe_cleanup` to retry pending wipes. `MarmotApp` performs this after acquiring its matching
  root lease. Handle its result before admitting mutations. A lower-level caller must retain exclusive ownership
  for the entire replay.
- Credential lifecycle mutations hold a private root mutation lease, including independently opened homes.
  Contention between independent handles returns an I/O `WouldBlock` before mutation, including replay admission.
  Keep the lock file in place: deleting it would allow two owners to lock different files.
- Relay-list discovery and repair belong above this crate in the Nostr account transport / app-runtime layer. CLI
  account selection belongs in presentation surfaces such as `wn`.

## Secret-store ownership

`AccountSecretStore` implementations persist `SecretCredential` receipts identified by credential kind,
home ID, and owner ID. AccountHome writes the ownership reference before calling the backend and publishes
a signing account only after acquisition succeeds. Owner IDs are random and never reused after retirement.

- `acquire_secret` persists an independent owner copy and returns `Created` or `Existing`. Retrying the same
  owner returns the original material and origin. `MigrateLegacy` explicitly permits copying an old raw credential.
  `SecretNotFound` guarantees no source and no committed or pending receipt for that owner. Uncertain lookup or
  write failures must return another error, so recovery retains the same owner.
- `load_secret` reads that owner's active receipt. It does not substitute a label's newest credential.
  File-vault reads use the pinned directory without a writer lease; native vaults take the provider lease.
- `release_secret` retires that receipt before deleting its material. `Preserve` leaves a durable store-side hold
  even after rollback removes the account record. Adoption persists a new copy before consuming that hold.
- `reconcile_cleanup` retries retired copies without consulting the live account catalog. Retirement metadata
  remains durable; deleting it would permit an old operation to recreate a retired owner.

Native backends store one protected copy per owner. Android uses AES-GCM encrypted files and per-receipt
Android Keystore keys on API 23 or later. SharedPreferences is read only for legacy migration.
On Android, the service lease lives outside the receipt directory. Reads and writes use the directory opened under
that lease. A write syncs its unpublished file, renames it atomically, and syncs the directory before returning.
An invalid final receipt remains an error. A retry reuses its owner's Keystore key. Exact-owner removal deletes the
unpublished file, final receipt, and key.
Before reporting success, the vault checks that the OS-selected no-backup directory still matches the open directory.
Windows managed copies use local-machine persistence and bind to the user SID and MachineGuid, not the computer
name; they do not roam. Durable private record replacement on Windows requires NTFS with POSIX rename support.
macOS checks a persistent marker in the captured keychain as well as its selected domain and path.
The development file store keeps plaintext receipts under `.owned-secrets-v1` with private permissions.
It checks a nonsecret ID in the pinned directory. Moving the vault with that ID keeps its identity; creating another
vault at the old path does not. Back up and restore the original `.credential-store-id-v1` from the vault root along
with `.owned-secrets-v1`. MDK refuses to create a replacement marker over existing managed records.

On Linux and BSD, select the intended Secret Service collection as the default before first use or legacy migration.
MDK binds managed receipts to a nonsecret identity item in that collection. This identity survives keyring updates
and service restarts. First use needs permission to create the item and take a temporary name on the session bus.
Reopening a collection with an existing identity does not need those permissions.

If you change the default collection, restore the original as the default and reopen the account home. Keep the
identity item with its collection when restoring a backup. MDK does not recreate a missing identity over existing
managed records. If a collection or item is locked, unlock it in the OS keyring and retry. Unattended cleanup does
not prompt for an unlock. Legacy lookup still searches all collections, so a managed identity cannot prove that
a raw legacy item is absent.

Managed namespaces identify protected storage separately from raw legacy lookup options. On iOS, the OS resolves
the default managed access group unless `IosOptions.keychain_access_group` selects an authorized group. Apps sharing
a native group also need access to the same lock container, selected when the vault is opened first. Changing the
managed group does not narrow the captured provider's historical raw lookup. That scope can still be unknown.

For iOS app-group roots, pass authorized group identifiers in `IosOptions.app_group_identifiers` to both the home
and any `LocalFileSecretStore`. Foundation validates access to each container; the SDK does not inspect private
entitlement APIs. Default options support app-private roots. C and UniFFI hosts supply the same configuration
through the existing client options record's optional `ios_options` field.

Independent legacy vault entries have no complete ownership history. MDK copies them when needed but does not
automatically delete them. `PendingLegacy` retains cleanup intent when an entry may still exist. Local plaintext
files inside the wiped account (`secret.json` and `.external-sqlcipher-secret`) are separate: MDK attempts to scrub
and unlink them during local cleanup.
A migrated receipt retains its original legacy lookup scope. A different or unknown scope remains pending,
even if the current lookup finds nothing.
A successful local wipe means the account is absent, not that every vault or storage medium has erased its bytes.

> [!WARNING]
> On iOS and Android, ownership binds to the OS container identity and the root's relative path, so an app-container
> relocation preserves existing credentials. Roots must be inside an authorized app or app-group container.
> Elsewhere, ownership binds to the canonical root path. A copy or move to a different logical root is rejected.
> Once credential access establishes an `AccountHome`'s root identity, credential operations and guarded mutations
> reject a path that resolves to a different root. Catalog reads such as `account()` do not check that identity.
> To change logical roots, create a fresh home and reimport the signing identity.
> Copied databases retain their original device-local key; a fresh home does not rebind them.

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
