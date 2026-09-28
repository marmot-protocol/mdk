# Storage-format compatibility fixtures

`storage-v1-v0.9.12.bin` is an encrypted SQLCipher account database written by
the exact `v0.9.12` source tag (`3fc4eb83974eb64ecb298856b0db70cc3055af57`),
before migration 47 existed.

The fixture contains one synthetic current-profile group and one sent
`OutboundWelcome` whose raw transport payload is 16,727 bytes. The old writer
therefore exercises both layers of the legacy JSON number-array encoding. It
contains no production identifiers, keys, messages, or endpoints.

- Test-only SQLCipher key: `mdk storage v1 fixture key`
- SHA-256: `ece0b6e2648937f8fb06dd3c1c1f670fb4d99418bd524d1e33169c197ae71b86`
- Writer: [`write-v0.9.12-fixture.rs.txt`](write-v0.9.12-fixture.rs.txt),
  compiled and run from the exact tag. It uses only
  `SqliteAccountStorage::open_encrypted`, `GroupStorage::put_group`, and
  `MessageStorage::put_message`.

The compatibility test copies this immutable fixture to a private temporary
path before opening it. Never update this file with the current writer; add a
new version-named fixture for a later compatibility boundary.

## `account-v0.10.4.sql`

A complete account database written by the v0.10.4 app runtime, from the exact
`v0.10.4` source tag (`fcc85edd8dbd07c8293c899ee52230f72c54c897`), one release
before migrations 0090-0098. It is rendered as SQL text so review can see that
it holds only synthetic data.

- Writer: [`write-v0.10.4-fixture.rs.txt`](write-v0.10.4-fixture.rs.txt), run
  as an in-crate `marmot-app` test at the tag. Four freshly generated accounts
  talk through a local relay on `ws://127.0.0.1:47104`; this file is account
  `bob`: three groups with messages from three members, one group whose route
  its admin rotated (a retained prior route without a switch time), and a
  persisted transport cursor. The writer exported the database with
  `sqlcipher_export` and `sqlite3 <db> .dump` rendered it. Reloading the SQL
  reproduces the same `sqlite_master` rows and table contents.
- Keys and identities: every key, MLS secret and account identity is synthetic,
  created for this run. No production identifiers or endpoints.
- SHA-256: `50231ecaf048b40122673d7d2de6c41aedd5ae671eb202dd2ad4c1202939c39e`

`migrations/upgrade_v0_10_4_tests.rs` loads it into an encrypted file under a
test-only key and opens it through `SqliteAccountStorage::open_encrypted`. It
checks the migration ledger, schema parity with a fresh database, preserved
rows and cursor, empty recovery and notice state, the one-time retained-route
stamp, and that the v0.10.4 migration set refuses the upgraded file. Never
regenerate this file with a later writer; add a new version-named fixture.
