# Session compatibility fixtures

`session-promotion-v1.bin` is a synthetic SQLCipher account-device database
prepared for the public `AccountDeviceSession` promotion-facade regression.
It contains one confirmed two-member group and one format-1 Welcome row. The
database was created by the normal session API on 2026-08-14, then that one row
was converted to the migration-47 legacy representation before any promotion
ran. It contains only deterministic test identities and test key material.

- Test-only SQLCipher key: `session promotion facade key`
- Deterministic local identity seed: `alice-promotion`
- Group id: `1d3ce58153822ac936ba83eba9cb87db`
- SHA-256: `54b5152274592490e7f22693b08edff9f3ba8ec61a8628044cadc6273efca367`

Storage-level old-writer provenance and exact byte-preservation remain covered
by `storage-sqlite/fixtures/storage-v1-v0.9.12.bin`. This fixture exists only
to keep the session test at its public API boundary.
