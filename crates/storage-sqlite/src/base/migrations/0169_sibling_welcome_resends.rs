//! Durable local publication/activity observation order and sibling-Welcome
//! resend generations (mdk#2628 D70, D89, D90). Exact Welcome material remains
//! in its engine-owned message row; the app keeps only timing and identities.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE local_observation_clock (
             singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
             last_order INTEGER NOT NULL CHECK(last_order >= 0)
         );
         INSERT INTO local_observation_clock VALUES(1, 0);
         ALTER TABLE cgka_groups ADD COLUMN sibling_resend_after_epoch INTEGER DEFAULT -1;
         UPDATE cgka_groups SET sibling_resend_after_epoch = epoch;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN content_id BLOB;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_observed_order INTEGER;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_epoch INTEGER;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_observed_at_ms INTEGER;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_proof BLOB;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_identity BLOB;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_application_id BLOB;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_has_leaf INTEGER;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_slot_hint BLOB;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN source_resolved INTEGER;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN qualified_slot BLOB;
         ALTER TABLE cgka_processed_transport_ids ADD COLUMN qualified_tag_key BLOB;
         CREATE INDEX idx_processed_transport_content
             ON cgka_processed_transport_ids(group_id, content_id, source_observed_order);
         CREATE INDEX idx_processed_transport_activity
             ON cgka_processed_transport_ids(group_id, qualified_slot, source_observed_order)
             WHERE qualified_slot IS NOT NULL;
         CREATE INDEX idx_processed_transport_source_identity ON cgka_processed_transport_ids(group_id, source_identity, source_observed_order);
         CREATE INDEX idx_processed_transport_pending_source
             ON cgka_processed_transport_ids(group_id, source_has_leaf, source_observed_order)
             WHERE source_resolved = 0;
         CREATE INDEX idx_processed_transport_source_slot ON cgka_processed_transport_ids(group_id, source_slot_hint, source_observed_order) WHERE source_resolved = 0 AND source_has_leaf = 1;
         CREATE INDEX idx_processed_transport_source_application ON cgka_processed_transport_ids(group_id, source_application_id, source_has_leaf, source_observed_order) WHERE source_application_id IS NOT NULL;
         CREATE INDEX idx_processed_transport_unavailable_source ON cgka_processed_transport_ids(group_id, content_id) WHERE source_has_leaf = 0;
         CREATE INDEX idx_processed_transport_qualified_principal ON cgka_processed_transport_ids(group_id, qualified_slot, qualified_tag_key, source_application_id, source_observed_order) WHERE qualified_slot IS NOT NULL;
         CREATE TABLE sibling_welcome_resends (
             welcome_id BLOB PRIMARY KEY,
             chat_id BLOB NOT NULL,
             device_group_id BLOB NOT NULL,
             target_slot BLOB NOT NULL,
             carrier BLOB NOT NULL,
             prepared_carrier BLOB NOT NULL,
             last_carrier_created_at INTEGER NOT NULL,
             publication_order INTEGER,
             published_at_ms INTEGER,
             activity_id BLOB,
             activity_order INTEGER,
             activity_at_ms INTEGER,
             due_at_ms INTEGER
         );
         CREATE INDEX idx_sibling_welcome_resend_carrier ON sibling_welcome_resends(carrier);
         CREATE INDEX idx_sibling_welcome_resend_activity
             ON sibling_welcome_resends(device_group_id, target_slot, publication_order)
             WHERE activity_id IS NULL;
         CREATE INDEX idx_sibling_welcome_resend_due ON sibling_welcome_resends(due_at_ms)
             WHERE due_at_ms IS NOT NULL;",
    )
    .storage()
}
