# AGENTS.md - crates/storage-sqlite/src/migrations

Map for account/session (`cgka_schema_migrations`) Rust migration bodies. Runner and registry: `../migrations.rs`.
Shared-store migrations are separate (`../shared/migrations.rs`).

## Rules

- File names use padded numeric prefixes: `0001_initial_schema.rs`, `0002_some_change.rs`, and so on.
- Each file exposes `pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()>`.
- Register migrations in `../migrations.rs` (`#[path = "migrations/NNNN_name.rs"] mod migration_NNNN_name;` plus the
  registry entry) in strict version order.
- Prefer Rust migrations when data needs transformation; SQL-only DDL can still live inside `execute_batch`.
- Keep migrations idempotent where SQLite supports it, but rely on `cgka_schema_migrations` for once-only execution.
- Non-migration files here are `#[cfg(test)]` modules: `query_work_tests.rs`, `test_support.rs`, and
  `upgrade_v0_10_4_tests.rs` (loads `../../fixtures/account-v0.10.4.sql`; see `../../fixtures/README.md`).
