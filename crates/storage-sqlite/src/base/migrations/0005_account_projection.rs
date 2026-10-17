use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE account_state (
    label TEXT PRIMARY KEY NOT NULL,
    updated_at INTEGER NOT NULL,
    last_transport_timestamp INTEGER
);

CREATE TABLE seen_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    seen_at INTEGER NOT NULL
);

CREATE TABLE account_groups (
    group_id_hex TEXT PRIMARY KEY NOT NULL,
    endpoint TEXT NOT NULL,
    profile_name TEXT NOT NULL DEFAULT '',
    profile_description TEXT NOT NULL DEFAULT '',
    image_hash_hex TEXT NOT NULL DEFAULT '',
    image_key_hex TEXT NOT NULL DEFAULT '',
    image_nonce_hex TEXT NOT NULL DEFAULT '',
    image_upload_key_hex TEXT NOT NULL DEFAULT '',
    image_media_type TEXT,
    admin_keys_hex TEXT NOT NULL DEFAULT '',
    archived INTEGER NOT NULL DEFAULT 0,
    pending_confirmation INTEGER NOT NULL DEFAULT 0,
    welcomer_account_id_hex TEXT,
    via_welcome_message_id_hex TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE account_group_app_components (
    group_id_hex TEXT NOT NULL,
    component_id INTEGER NOT NULL,
    component_name TEXT NOT NULL,
    component_data_hex TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, component_id),
    FOREIGN KEY (group_id_hex) REFERENCES account_groups(group_id_hex) ON DELETE CASCADE
);

CREATE TABLE notification_settings (
    account_label TEXT PRIMARY KEY NOT NULL,
    account_id_hex TEXT NOT NULL,
    local_notifications_enabled INTEGER NOT NULL DEFAULT 0,
    native_push_enabled INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE push_registration (
    account_label TEXT PRIMARY KEY NOT NULL,
    account_id_hex TEXT NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    token_bytes BLOB NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    last_shared_at_ms INTEGER
);

CREATE TABLE group_push_tokens (
    group_id_hex TEXT NOT NULL,
    member_id_hex TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    platform INTEGER NOT NULL,
    token_fingerprint TEXT NOT NULL,
    server_pubkey_hex TEXT NOT NULL,
    relay_hint TEXT,
    encrypted_token BLOB NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (group_id_hex, member_id_hex, platform, server_pubkey_hex)
);

CREATE TABLE account_import_markers (
    name TEXT PRIMARY KEY NOT NULL,
    completed_at_unix_seconds INTEGER NOT NULL
);
"#,
    )
    .storage()
}
