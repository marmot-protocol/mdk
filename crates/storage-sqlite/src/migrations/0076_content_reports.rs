use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(r#"
ALTER TABLE app_events ADD COLUMN authority_state INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_events ADD COLUMN authority_context BLOB;
ALTER TABLE app_events ADD COLUMN reporting_allowed INTEGER NOT NULL DEFAULT 1;
UPDATE app_events SET authority_state=1,reporting_allowed=0,moderation_grant=0 WHERE kind IN (1984,1985,4891);
CREATE TABLE pending_application_authority (message_id BLOB PRIMARY KEY, group_id BLOB NOT NULL, record BLOB NOT NULL);
CREATE INDEX pending_application_authority_group ON pending_application_authority(group_id);
CREATE TABLE content_moderation (
    group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL,
    revision_id_hex TEXT NOT NULL, total_reports INTEGER NOT NULL DEFAULT 0,
    pending_reports INTEGER NOT NULL DEFAULT 0, removed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(group_id_hex, message_id_hex)
);
CREATE INDEX content_moderation_pending ON content_moderation(group_id_hex, pending_reports, message_id_hex);
CREATE TABLE content_reports (
    group_id_hex TEXT NOT NULL, report_id_hex TEXT NOT NULL,
    message_id_hex TEXT NOT NULL, revision_id_hex TEXT NOT NULL,
    reporter TEXT NOT NULL, reason TEXT NOT NULL, reported_at INTEGER NOT NULL,
    dismissed_by TEXT, PRIMARY KEY(group_id_hex, report_id_hex)
);
CREATE UNIQUE INDEX content_reports_target ON content_reports(group_id_hex, message_id_hex, revision_id_hex, reporter);
CREATE TABLE content_report_backfill (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1), after_order INTEGER NOT NULL, through_order INTEGER NOT NULL
);
INSERT INTO content_report_backfill SELECT 1, 0, COALESCE(MAX(insert_order),0) FROM app_events;
CREATE TABLE content_expired_targets (group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL, PRIMARY KEY(group_id_hex,message_id_hex));
CREATE TABLE content_pruned_controls (group_id_hex TEXT NOT NULL, message_id_hex TEXT NOT NULL, PRIMARY KEY(group_id_hex,message_id_hex));
CREATE TRIGGER content_reports_group_deleted AFTER DELETE ON account_groups BEGIN
    DELETE FROM content_expired_targets WHERE group_id_hex = OLD.group_id_hex;
    DELETE FROM content_pruned_controls WHERE group_id_hex = OLD.group_id_hex;
    DELETE FROM content_reports WHERE group_id_hex = OLD.group_id_hex;
    DELETE FROM content_moderation WHERE group_id_hex = OLD.group_id_hex;
END;
"#).storage()
}
