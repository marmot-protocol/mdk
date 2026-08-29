use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// Compatibility fence for privacy-critical fields added to the serialized
/// `cgka_key_package_lifecycle.record` value.
///
/// Schema-51 readers deserialize that JSON permissively and would discard the
/// exact deletion, overflow-owner, and multi-consumption journals on their
/// next write. The
/// migration-runner version check rejects an older binary that opens after this
/// migration. These triggers additionally reject a schema-51 writer that was
/// already connected while a newer process applied the migration.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
UPDATE cgka_key_package_lifecycle
SET record = CAST(
    json_set(
        json_insert(
            CAST(record AS TEXT),
            '$.deleted_live_revision_event_ids', json('[]'),
            '$.deletion_overflow_owner_event_id', json('null'),
            '$.retired_publications_pending_deletion', json('[]'),
            '$.consumed_key_package_refs', json('[]')
        ),
        -- Every schema-51 row predates the relay cutover proof, including a
        -- development/backport row that already serialized `false`. Force the
        -- gate closed while preserving any journals it already carries.
        '$.cutover_publication_blocked', json('true')
    ) AS BLOB
)
WHERE singleton = 1;

CREATE TRIGGER cgka_key_package_lifecycle_privacy_journal_insert
BEFORE INSERT ON cgka_key_package_lifecycle
WHEN CASE
    WHEN json_valid(CAST(NEW.record AS TEXT)) = 0 THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$') IS NOT 'object' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.cutover_publication_blocked') IS NOT 'false'
         AND json_type(CAST(NEW.record AS TEXT), '$.cutover_publication_blocked') IS NOT 'true' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.deleted_live_revision_event_ids') IS NOT 'array' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.deletion_overflow_owner_event_id') IS NOT 'null'
         AND json_type(CAST(NEW.record AS TEXT), '$.deletion_overflow_owner_event_id') IS NOT 'array' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.retired_publications_pending_deletion') IS NOT 'array' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.consumed_key_package_refs') IS NOT 'array' THEN 1
    ELSE 0
END
BEGIN
    SELECT RAISE(ABORT, 'key package lifecycle privacy journals are required');
END;

CREATE TRIGGER cgka_key_package_lifecycle_privacy_journal_update
BEFORE UPDATE OF record ON cgka_key_package_lifecycle
WHEN CASE
    WHEN json_valid(CAST(NEW.record AS TEXT)) = 0 THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$') IS NOT 'object' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.cutover_publication_blocked') IS NOT 'false'
         AND json_type(CAST(NEW.record AS TEXT), '$.cutover_publication_blocked') IS NOT 'true' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.deleted_live_revision_event_ids') IS NOT 'array' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.deletion_overflow_owner_event_id') IS NOT 'null'
         AND json_type(CAST(NEW.record AS TEXT), '$.deletion_overflow_owner_event_id') IS NOT 'array' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.retired_publications_pending_deletion') IS NOT 'array' THEN 1
    WHEN json_type(CAST(NEW.record AS TEXT), '$.consumed_key_package_refs') IS NOT 'array' THEN 1
    ELSE 0
END
BEGIN
    SELECT RAISE(ABORT, 'key package lifecycle privacy journals are required');
END;

-- Validate the upgraded row through the same guard. This is deliberately an
-- identity update: valid existing bytes stay byte-for-byte unchanged.
UPDATE cgka_key_package_lifecycle
SET record = record
WHERE singleton = 1;
"#,
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::migrations::{MIGRATIONS, run};
    use cgka_traits::{
        KeyPackageLifecycleState, MessageId, RetiredKeyPackagePublication, Timestamp,
    };
    use rusqlite::{Connection, OptionalExtension, params};

    fn schema_51_lifecycle_record() -> Vec<u8> {
        let mut record = serde_json::to_value(KeyPackageLifecycleState::slot_only("slot".into()))
            .expect("serialize lifecycle fixture");
        let fields = record.as_object_mut().expect("lifecycle is an object");
        fields.remove("cutover_publication_blocked");
        fields.remove("deleted_live_revision_event_ids");
        fields.remove("deletion_overflow_owner_event_id");
        fields.remove("retired_publications_pending_deletion");
        fields.remove("consumed_key_package_refs");
        serde_json::to_vec(&record).expect("serialize schema-51 lifecycle fixture")
    }

    fn privacy_journal_lifecycle_record() -> Vec<u8> {
        let mut lifecycle = KeyPackageLifecycleState::slot_only("slot".into());
        lifecycle.cutover_publication_blocked = true;
        lifecycle
            .deleted_live_revision_event_ids
            .push(MessageId::new(vec![1, 2, 3]));
        lifecycle.deletion_overflow_owner_event_id = Some(MessageId::new(vec![4, 5, 6]));
        lifecycle
            .retired_publications_pending_deletion
            .push(RetiredKeyPackagePublication {
                event_id: MessageId::new(vec![4, 5, 6]),
                authored_created_at: Timestamp(7),
                key_package_ref: Some(vec![8]),
                package_not_after: Some(Timestamp(9)),
                delete_without_successor: true,
                deletion_targets: Vec::new(),
            });
        lifecycle.consumed_key_package_refs.push(vec![10, 11]);
        serde_json::to_vec(&lifecycle).expect("serialize lifecycle privacy journal fixture")
    }

    #[test]
    fn migration_forces_an_existing_false_gate_without_replacing_privacy_journals() {
        let mut connection = Connection::open_in_memory().unwrap();
        run(&mut connection, &MIGRATIONS[..51]).unwrap();
        let mut before: serde_json::Value =
            serde_json::from_slice(&privacy_journal_lifecycle_record()).unwrap();
        before["cutover_publication_blocked"] = serde_json::json!(false);
        let before_bytes = serde_json::to_vec(&before).unwrap();
        connection
            .execute(
                "INSERT INTO cgka_key_package_lifecycle (singleton, record) VALUES (1, ?1)",
                params![before_bytes],
            )
            .unwrap();

        run(&mut connection, MIGRATIONS).unwrap();
        let after: Vec<u8> = connection
            .query_row(
                "SELECT record FROM cgka_key_package_lifecycle WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let after: serde_json::Value = serde_json::from_slice(&after).unwrap();
        assert_eq!(
            after.get("cutover_publication_blocked"),
            Some(&serde_json::json!(true))
        );
        for field in [
            "deleted_live_revision_event_ids",
            "deletion_overflow_owner_event_id",
            "retired_publications_pending_deletion",
            "consumed_key_package_refs",
        ] {
            assert_eq!(
                after.get(field),
                before.get(field),
                "{field} must be preserved"
            );
        }
    }

    #[test]
    fn migration_guards_blob_json_from_already_open_schema_51_writer() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("schema-51-open-writer.sqlite3");
        let mut old_writer = Connection::open(&database).unwrap();
        run(&mut old_writer, &MIGRATIONS[..51]).unwrap();
        old_writer
            .execute(
                "INSERT INTO cgka_key_package_lifecycle (singleton, record) VALUES (1, ?1)",
                params![schema_51_lifecycle_record()],
            )
            .unwrap();

        let mut new_writer = Connection::open(&database).unwrap();
        run(&mut new_writer, MIGRATIONS).unwrap();
        let upgraded: Vec<u8> = new_writer
            .query_row(
                "SELECT record FROM cgka_key_package_lifecycle WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            new_writer
                .query_row(
                    "SELECT typeof(record) FROM cgka_key_package_lifecycle WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "blob",
            "JSON1 backfill must preserve the encrypted table's BLOB representation"
        );
        let upgraded: serde_json::Value = serde_json::from_slice(&upgraded).unwrap();
        for field in [
            "cutover_publication_blocked",
            "deleted_live_revision_event_ids",
            "deletion_overflow_owner_event_id",
            "retired_publications_pending_deletion",
            "consumed_key_package_refs",
        ] {
            let expected = match field {
                "cutover_publication_blocked" => serde_json::json!(true),
                "deletion_overflow_owner_event_id" => serde_json::Value::Null,
                _ => serde_json::json!([]),
            };
            assert_eq!(upgraded.get(field), Some(&expected));
        }

        let privacy_record = privacy_journal_lifecycle_record();
        new_writer
            .execute(
                "UPDATE cgka_key_package_lifecycle SET record = ?1 WHERE singleton = 1",
                params![privacy_record.as_slice()],
            )
            .unwrap();

        let error = old_writer
            .execute(
                "INSERT INTO cgka_key_package_lifecycle (singleton, record) VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET record = excluded.record",
                params![schema_51_lifecycle_record()],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("key package lifecycle privacy journals are required")
        );
        let retained: Vec<u8> = new_writer
            .query_row(
                "SELECT record FROM cgka_key_package_lifecycle WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, privacy_record);

        new_writer
            .execute("DELETE FROM cgka_key_package_lifecycle", [])
            .unwrap();
        assert!(
            old_writer
                .execute(
                    "INSERT INTO cgka_key_package_lifecycle (singleton, record) VALUES (1, ?1)",
                    params![schema_51_lifecycle_record()],
                )
                .is_err(),
            "the insert guard must reject an old-shaped row too"
        );
        let absent: Option<Vec<u8>> = new_writer
            .query_row(
                "SELECT record FROM cgka_key_package_lifecycle WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert!(absent.is_none());
    }
}
