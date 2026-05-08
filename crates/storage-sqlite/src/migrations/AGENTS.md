# AGENTS.md - crates/storage-sqlite/src/migrations

Map for Rust migration bodies.

## Rules

- File names use padded numeric prefixes: `0001_initial_schema.rs`,
  `0002_some_change.rs`, and so on.
- Each file exposes `apply(tx: &Transaction<'_>) -> StorageResult<()>`.
- Register migrations in `src/migrations.rs` in strict version order.
- Prefer Rust migrations when data needs transformation; SQL-only DDL can still
  live inside `execute_batch`.
- Keep migrations idempotent where SQLite supports it, but rely on
  `cgka_schema_migrations` for once-only execution.
