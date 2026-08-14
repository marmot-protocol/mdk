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
