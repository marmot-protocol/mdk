# AGENTS.md - crates/storage-sqlite/src/base/migrations

Map for account/session (`cgka_schema_migrations`) Rust migration bodies. Runner and registry: `../migrations.rs`.
Shared-store migrations are separate (`../../shared/migrations.rs`).

## Rules

- File names use padded numeric prefixes: `0001_initial_schema.rs`, `0002_some_change.rs`, and so on.
- Each file exposes `pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()>`.
- Register migrations in `../migrations.rs` (`#[path = "migrations/NNNN_name.rs"] mod migration_NNNN_name;` plus the
  registry entry) in strict version order.
- Prefer Rust migrations when data needs transformation; SQL-only DDL can still live inside `execute_batch`.
- Keep migrations idempotent where SQLite supports it, but rely on `cgka_schema_migrations` for once-only execution.
- A body must roll back completely when the runner's transaction fails: no `COMMIT`, no PRAGMA it relies on inside
  the transaction (declare `suspend_foreign_keys` instead). `tests::every_migration_body_rolls_back_completely` in
  `../migrations.rs` walks every registered body this way, so a migration's own tests need no apply/rollback probe.
- A per-migration test stops at its own version (`run_through(N)`) unless its contract is the head path. Tests that
  ran to head and compared whole rows or trigger sets broke whenever a later migration touched the same table
  (#2691, #2725).
- Non-migration files here are `#[cfg(test)]` modules: `media_open_upgrade_tests.rs` (with its `media_upgrade_prior.rs`
  fixture bodies), `query_work_tests.rs`, `test_support.rs`, and `upgrade_v0_10_4_tests.rs` (loads
  `../../../fixtures/account-v0.10.4.sql`; see `../../../fixtures/README.md`).
