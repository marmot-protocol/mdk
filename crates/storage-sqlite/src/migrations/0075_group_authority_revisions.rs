//! Group-local cache invalidation for compact engine authority reads.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Tokens are random rather than counters: a cache may have observed an
    // uncommitted revision which is later rolled back. A subsequent write must
    // never reuse that revision for different data. Keep deletion tokens too.
    // No source blobs, identities beyond existing keys, or key material copied.
    tx.execute_batch(
        "CREATE TABLE group_authority_revisions (
            source INTEGER NOT NULL,
            source_key BLOB NOT NULL,
            revision BLOB NOT NULL CHECK(length(revision) = 16),
            PRIMARY KEY(source, source_key)
         ) WITHOUT ROWID;
         CREATE TRIGGER group_authority_record_insert AFTER INSERT ON cgka_groups BEGIN
            INSERT INTO group_authority_revisions VALUES(0, NEW.id, randomblob(16))
            ON CONFLICT(source, source_key) DO UPDATE SET revision = excluded.revision;
         END;
         CREATE TRIGGER group_authority_record_update AFTER UPDATE OF id, record ON cgka_groups
         WHEN OLD.id IS NOT NEW.id OR OLD.record IS NOT NEW.record BEGIN
            INSERT INTO group_authority_revisions VALUES(0, OLD.id, randomblob(16))
            ON CONFLICT(source, source_key) DO UPDATE SET revision = excluded.revision;
            INSERT INTO group_authority_revisions VALUES(0, NEW.id, randomblob(16))
            ON CONFLICT(source, source_key) DO UPDATE SET revision = excluded.revision;
         END;
         CREATE TRIGGER group_authority_record_delete AFTER DELETE ON cgka_groups BEGIN
            INSERT INTO group_authority_revisions VALUES(0, OLD.id, randomblob(16))
            ON CONFLICT(source, source_key) DO UPDATE SET revision = excluded.revision;
         END;",
    )
    .storage()?;
    // Exact dependencies of the engine's canonical scalar selector. Ratchet,
    // proposal, transport and application rows do not change these facts.
    let relevant = |row: &str| {
        format!(
            "{row}.group_key IS NOT NULL AND (
         {row}.label = X'54726565' /* Tree */ OR
         {row}.label = X'47726f7570436f6e74657874' /* GroupContext */ OR
         {row}.label = X'47726f75705374617465' /* GroupState */ OR
         {row}.label = X'4f776e4c6561664e6f6465496e646578' /* OwnLeafNodeIndex */)"
        )
    };
    for (name, event, rows) in [
        ("group_authority_mls_insert", "INSERT", &["NEW"][..]),
        ("group_authority_mls_update", "UPDATE", &["OLD", "NEW"][..]),
        ("group_authority_mls_delete", "DELETE", &["OLD"][..]),
    ] {
        let body = rows
            .iter()
            .map(|row| {
                format!(
                    "INSERT INTO group_authority_revisions
             SELECT 1, {row}.group_key, randomblob(16) WHERE {}
             ON CONFLICT(source, source_key) DO UPDATE SET revision = excluded.revision;",
                    relevant(row)
                )
            })
            .collect::<String>();
        let changed = if event == "UPDATE" {
            " AND (OLD.value IS NOT NEW.value OR OLD.group_key IS NOT NEW.group_key
             OR OLD.label IS NOT NEW.label OR OLD.provider_version IS NOT NEW.provider_version
             OR OLD.storage_key IS NOT NEW.storage_key)"
        } else {
            ""
        };
        let selected = rows
            .iter()
            .map(|row| format!("({})", relevant(row)))
            .collect::<Vec<_>>()
            .join(" OR ");
        tx.execute_batch(&format!(
            "CREATE TRIGGER {name} AFTER {event} ON openmls_values
             WHEN ({selected}) {changed} BEGIN {body} END;"
        ))
        .storage()?;
    }
    // Existing groups start at the implicit zero token. No roster/tree decode
    // or history-sized backfill is needed; the first change creates a token.
    Ok(())
}
