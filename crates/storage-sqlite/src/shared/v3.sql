-- Coalesced accepted-profile changes. Old directory rows are read directly at revision zero.
CREATE TABLE directory_presentation_meta (
 id INTEGER PRIMARY KEY CHECK(id=1),
 store_epoch BLOB NOT NULL CHECK(length(store_epoch)=16),
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0)
);
INSERT INTO directory_presentation_meta VALUES(1, randomblob(16), 0);
CREATE TABLE directory_presentation_changes (
 member_id_hex TEXT PRIMARY KEY NOT NULL,
 revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0)
);
CREATE UNIQUE INDEX directory_presentation_by_revision ON directory_presentation_changes(revision);
CREATE TRIGGER directory_presentation_insert AFTER INSERT ON directory_users
WHEN json_extract(CASE WHEN json_valid(NEW.profile_json) THEN NEW.profile_json ELSE '{}' END, '$.display_name', '$.name', '$.picture') IS NOT '[null,null,null]' BEGIN
 UPDATE directory_presentation_meta SET revision=revision+1 WHERE id=1;
 INSERT INTO directory_presentation_changes VALUES(NEW.account_id_hex,(SELECT revision FROM directory_presentation_meta WHERE id=1))
 ON CONFLICT(member_id_hex) DO UPDATE SET revision=excluded.revision;
END;
CREATE TRIGGER directory_presentation_update AFTER UPDATE OF profile_json ON directory_users
WHEN json_extract(CASE WHEN json_valid(OLD.profile_json) THEN OLD.profile_json ELSE '{}' END, '$.display_name', '$.name', '$.picture') IS NOT json_extract(CASE WHEN json_valid(NEW.profile_json) THEN NEW.profile_json ELSE '{}' END, '$.display_name', '$.name', '$.picture') BEGIN
 UPDATE directory_presentation_meta SET revision=revision+1 WHERE id=1;
 INSERT INTO directory_presentation_changes VALUES(NEW.account_id_hex,(SELECT revision FROM directory_presentation_meta WHERE id=1))
 ON CONFLICT(member_id_hex) DO UPDATE SET revision=excluded.revision;
END;
-- Retain a tombstone so offline accounts can clear previously selected data.
CREATE TRIGGER directory_presentation_delete AFTER DELETE ON directory_users
WHEN json_extract(CASE WHEN json_valid(OLD.profile_json) THEN OLD.profile_json ELSE '{}' END, '$.display_name', '$.name', '$.picture') IS NOT '[null,null,null]' BEGIN
 UPDATE directory_presentation_meta SET revision=revision+1 WHERE id=1;
 INSERT INTO directory_presentation_changes VALUES(OLD.account_id_hex,(SELECT revision FROM directory_presentation_meta WHERE id=1))
 ON CONFLICT(member_id_hex) DO UPDATE SET revision=excluded.revision;
END;
