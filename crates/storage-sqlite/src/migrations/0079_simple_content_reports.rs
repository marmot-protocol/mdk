use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
DROP TRIGGER content_reports_group_deleted;
DROP TABLE content_moderation;
DROP TABLE content_reports;
-- Old eligibility denials are not admin-policy denials under the simplified
-- contract. Re-prove those actions against their authenticated source state.
UPDATE app_events SET authority_state=1,moderation_grant=0
 WHERE kind IN (1985,4891) AND reporting_allowed=0;
DELETE FROM pending_application_authority WHERE EXISTS (
 SELECT 1 FROM app_events e WHERE e.kind=1984 AND e.source_message_id_hex=lower(hex(message_id))
);
-- These reports/labels were already expired and scrubbed by the former workflow.
DELETE FROM app_events WHERE kind IN (1984,1985) AND EXISTS (
 SELECT 1 FROM content_pruned_controls p WHERE p.group_id_hex=app_events.group_id_hex AND p.message_id_hex=app_events.message_id_hex
);
DELETE FROM content_pruned_controls WHERE NOT EXISTS (
 SELECT 1 FROM app_events e WHERE e.group_id_hex=content_pruned_controls.group_id_hex AND e.message_id_hex=content_pruned_controls.message_id_hex
);
ALTER TABLE app_events DROP COLUMN reporting_allowed;
CREATE TABLE content_reports (
 group_id_hex TEXT NOT NULL, report_id_hex TEXT NOT NULL,
 message_id_hex TEXT NOT NULL, message_author TEXT NOT NULL,
 reporter TEXT NOT NULL, reason TEXT NOT NULL, reported_at INTEGER NOT NULL,
 PRIMARY KEY(group_id_hex,report_id_hex),
 FOREIGN KEY(group_id_hex,report_id_hex) REFERENCES app_events(group_id_hex,message_id_hex) ON DELETE CASCADE
);
CREATE INDEX content_reports_target ON content_reports(group_id_hex,message_id_hex,report_id_hex);
CREATE INDEX content_report_labels ON message_modifier_edges(group_id_hex,target_message_id_hex,modifier_message_id_hex) WHERE kind=1985;
CREATE TRIGGER content_reports_group_deleted AFTER DELETE ON account_groups BEGIN
 DELETE FROM content_expired_targets WHERE group_id_hex=OLD.group_id_hex;
 DELETE FROM content_pruned_controls WHERE group_id_hex=OLD.group_id_hex;
 DELETE FROM content_reports WHERE group_id_hex=OLD.group_id_hex;
END;
UPDATE content_report_backfill SET after_order=0,through_order=(SELECT COALESCE(MAX(insert_order),0) FROM app_events);
"#).storage()
}
