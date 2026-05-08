# storage-memory

In-memory implementation of the `cgka_traits::StorageProvider` aggregate. Suitable for tests and ephemeral scenarios. Use `storage-sqlite` for SQLCipher-backed persistence.

## What this crate gives you

`MemoryStorage` implements:

- `GroupStorage`, `MessageStorage`, `WelcomeStorage`, `CapabilityStorage`, `ConvergencePolicyStorage`, and `OutboundIntentStorage`
- `openmls_traits::storage::StorageProvider<CURRENT_VERSION>` (via `openmls_memory_storage`), exposed through the `mls_storage()` accessor

Internals are `Arc<RwLock<...>>` so the same `MemoryStorage` can be cloned and shared across multi-client harness tests. Snapshots also capture the OpenMLS memory map, which makes same-epoch fork recovery testable end-to-end.

## Run the tests

```sh
cargo test -p storage-memory
```

22 tests covering: round-trip every type, snapshot + rollback correctness, convergence policy storage, OpenMLS rollback coverage, concurrent-access soundness under tokio, cascade behavior on group delete.
