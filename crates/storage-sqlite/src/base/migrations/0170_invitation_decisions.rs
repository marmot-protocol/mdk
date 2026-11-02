//! Immutable local-copy admission identities and per-generation invite decisions.
//! No legacy group is seeded from its current epoch.

use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE cgka_invitation_admissions (
            group_id BLOB PRIMARY KEY NOT NULL REFERENCES cgka_groups(id) ON DELETE CASCADE,
            generation BLOB NOT NULL CHECK(length(generation) = 32),
            created_locally INTEGER NOT NULL CHECK(created_locally IN (0, 1)),
            via_welcome BLOB,
            CHECK((created_locally = 1 AND via_welcome IS NULL)
                OR (created_locally = 0 AND via_welcome IS NOT NULL))
        );
        CREATE TABLE invitation_decisions (
            group_id_hex TEXT NOT NULL,
            generation BLOB NOT NULL CHECK(length(generation) = 32),
            version INTEGER NOT NULL CHECK(version BETWEEN 1 AND 9007199254740991),
            declined INTEGER NOT NULL CHECK(declined IN (0, 1)),
            unsent INTEGER NOT NULL CHECK(unsent IN (0, 1)),
            apply_owed INTEGER NOT NULL CHECK(apply_owed IN (0, 1)),
            decline_owed INTEGER NOT NULL CHECK(decline_owed IN (0, 1)),
            PRIMARY KEY(group_id_hex, generation)
        );
        CREATE INDEX invitation_decisions_unsent ON invitation_decisions(group_id_hex, generation)
            WHERE unsent = 1;
        CREATE INDEX invitation_decisions_work ON invitation_decisions(group_id_hex, generation)
            WHERE apply_owed = 1 OR decline_owed = 1;",
    )
    .storage()
}
