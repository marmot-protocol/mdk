use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::app_components::{GROUP_AVATAR_URL_COMPONENT_ID, decode_group_avatar_url_v1};
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, Params, Transaction, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListQuery {
    pub include_archived: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListAvatar {
    pub image_hash_hex: String,
    pub image_key_hex: String,
    pub image_nonce_hex: String,
    pub image_upload_key_hex: String,
    pub media_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListMessagePreview {
    pub message_id_hex: String,
    pub sender: String,
    pub sender_display_name: Option<String>,
    pub plaintext: String,
    pub kind: u64,
    pub timeline_at: u64,
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatListRow {
    pub group_id_hex: String,
    pub archived: bool,
    pub pending_confirmation: bool,
    pub title: String,
    pub group_name: String,
    pub avatar_url: Option<String>,
    pub avatar: Option<ChatListAvatar>,
    pub last_message: Option<ChatListMessagePreview>,
    pub unread_count: u64,
    pub has_unread: bool,
    pub first_unread_message_id_hex: Option<String>,
    pub last_read_message_id_hex: Option<String>,
    pub last_read_timeline_at: Option<u64>,
    pub updated_at: u64,
}

#[derive(Clone, Debug)]
struct AccountGroupRow {
    group_id_hex: String,
    archived: bool,
    pending_confirmation: bool,
    profile_name: String,
    avatar_url: Option<String>,
    avatar: Option<ChatListAvatar>,
}

#[derive(Clone, Debug)]
struct ConversationReadState {
    last_read_message_id_hex: Option<String>,
    last_read_timeline_at: Option<u64>,
    initialized_at: u64,
}

impl SqliteAccountStorage {
    pub fn chat_list_rows(&self, query: ChatListQuery) -> StorageResult<Vec<ChatListRow>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let rows = chat_list_rows_tx(&tx, query)?;
        tx.commit().storage()?;
        Ok(rows)
    }

    pub fn chat_list_row(&self, group_id_hex: &str) -> StorageResult<Option<ChatListRow>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let row = chat_list_row_tx(&tx, group_id_hex)?;
        tx.commit().storage()?;
        Ok(row)
    }

    pub fn ensure_chat_list_rows(&self, local_account_id_hex: &str) -> StorageResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        if !chat_list_projection_complete_tx(&tx)? {
            rebuild_all_chat_list_rows_tx(&tx, local_account_id_hex)?;
        }
        tx.commit().storage()
    }

    pub fn refresh_chat_list_rows(&self, local_account_id_hex: &str) -> StorageResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        rebuild_all_chat_list_rows_tx(&tx, local_account_id_hex)?;
        tx.commit().storage()
    }

    pub fn refresh_chat_list_row(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
    ) -> StorageResult<Option<ChatListRow>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let row = refresh_chat_list_row_tx(&tx, local_account_id_hex, group_id_hex)?;
        tx.commit().storage()?;
        Ok(row)
    }

    pub fn initialize_chat_read_state(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
    ) -> StorageResult<Option<ChatListRow>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let Some(group) = account_group_tx(&tx, group_id_hex)? else {
            tx.commit().storage()?;
            return Ok(None);
        };
        if read_state_tx(&tx, group_id_hex)?.is_none() {
            let latest = latest_kind9_message_tx(&tx, group_id_hex)?;
            let (last_read_message_id_hex, last_read_timeline_at) = latest
                .map(|message| (Some(message.message_id_hex), Some(message.timeline_at)))
                .unwrap_or((None, None));
            let initialized_at = last_read_timeline_at.unwrap_or(0);
            tx.execute(
                "INSERT INTO conversation_read_state (
                    group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                    initialized_at, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    group_id_hex,
                    last_read_message_id_hex,
                    optional_u64_to_i64(last_read_timeline_at)?,
                    u64_to_i64(initialized_at)?,
                    u64_to_i64(unix_now_seconds())?
                ],
            )
            .storage()?;
        }
        rebuild_chat_list_row_for_group_tx(&tx, local_account_id_hex, group)?;
        let row = chat_list_row_tx(&tx, group_id_hex)?;
        tx.commit().storage()?;
        Ok(row)
    }

    pub fn mark_timeline_message_read(
        &self,
        local_account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> StorageResult<Option<ChatListRow>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        if let Some(target) =
            timeline_message_for_read_marker_tx(&tx, group_id_hex, message_id_hex)?
        {
            let should_advance = read_state_tx(&tx, group_id_hex)?
                .and_then(|state| {
                    state
                        .last_read_timeline_at
                        .zip(state.last_read_message_id_hex)
                })
                .is_none_or(|(at, id)| {
                    timeline_tuple_after(target.timeline_at, &target.message_id_hex, at, &id)
                });

            if should_advance {
                tx.execute(
                    "INSERT INTO conversation_read_state (
                        group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                        initialized_at, updated_at
                     )
                     VALUES (?1, ?2, ?3, ?4, ?4)
                     ON CONFLICT(group_id_hex) DO UPDATE SET
                        last_read_message_id_hex = excluded.last_read_message_id_hex,
                        last_read_timeline_at = excluded.last_read_timeline_at,
                        updated_at = excluded.updated_at",
                    params![
                        group_id_hex,
                        &target.message_id_hex,
                        u64_to_i64(target.timeline_at)?,
                        u64_to_i64(unix_now_seconds())?
                    ],
                )
                .storage()?;
            }
        }
        let row = refresh_chat_list_row_tx(&tx, local_account_id_hex, group_id_hex)?;
        tx.commit().storage()?;
        Ok(row)
    }
}

fn rebuild_all_chat_list_rows_tx(
    tx: &Transaction<'_>,
    local_account_id_hex: &str,
) -> StorageResult<()> {
    tx.execute("DELETE FROM chat_list_rows", []).storage()?;
    let groups = account_groups_tx(tx)?;
    for group in groups {
        rebuild_chat_list_row_for_group_tx(tx, local_account_id_hex, group)?;
    }
    Ok(())
}

fn refresh_chat_list_row_tx(
    tx: &Transaction<'_>,
    local_account_id_hex: &str,
    group_id_hex: &str,
) -> StorageResult<Option<ChatListRow>> {
    let Some(group) = account_group_tx(tx, group_id_hex)? else {
        tx.execute(
            "DELETE FROM chat_list_rows WHERE group_id_hex = ?1",
            params![group_id_hex],
        )
        .storage()?;
        return Ok(None);
    };
    rebuild_chat_list_row_for_group_tx(tx, local_account_id_hex, group)?;
    chat_list_row_tx(tx, group_id_hex)
}

fn chat_list_projection_complete_tx(tx: &Transaction<'_>) -> StorageResult<bool> {
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM account_groups AS ag
                LEFT JOIN chat_list_rows AS row
                    ON row.group_id_hex = ag.group_id_hex
                WHERE row.group_id_hex IS NULL
             )",
        [],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM chat_list_rows AS row
                LEFT JOIN account_groups AS ag
                    ON ag.group_id_hex = row.group_id_hex
                WHERE ag.group_id_hex IS NULL
             )",
        [],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM account_groups AS ag
                LEFT JOIN account_group_app_components AS avatar_url
                    ON avatar_url.group_id_hex = ag.group_id_hex
                   AND avatar_url.component_id = ?1
                JOIN chat_list_rows AS row
                    ON row.group_id_hex = ag.group_id_hex
                WHERE row.archived IS NOT ag.archived
                   OR row.pending_confirmation IS NOT ag.pending_confirmation
                   OR row.title IS NOT CASE
                        WHEN trim(ag.profile_name) = '' THEN ag.group_id_hex
                        ELSE ag.profile_name
                      END
                   OR row.group_name IS NOT ag.profile_name
                   OR row.avatar_image_hash_hex IS NOT ag.image_hash_hex
                   OR row.avatar_image_key_hex IS NOT ag.image_key_hex
                   OR row.avatar_image_nonce_hex IS NOT ag.image_nonce_hex
                   OR row.avatar_image_upload_key_hex IS NOT ag.image_upload_key_hex
                   OR row.avatar_media_type IS NOT ag.image_media_type
                   OR (row.avatar_url IS NOT NULL AND avatar_url.component_data_hex IS NULL)
                   OR row.updated_at < COALESCE(avatar_url.updated_at, 0)
                   OR row.updated_at < ag.updated_at
             )",
        params![GROUP_AVATAR_URL_COMPONENT_ID],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM conversation_read_state AS read_state
                JOIN chat_list_rows AS row
                    ON row.group_id_hex = read_state.group_id_hex
                WHERE row.last_read_message_id_hex IS NOT read_state.last_read_message_id_hex
                   OR row.last_read_timeline_at IS NOT read_state.last_read_timeline_at
                   OR row.updated_at < read_state.updated_at
             )",
        [],
    )? {
        return Ok(false);
    }
    if projection_has_rows_tx(
        tx,
        "SELECT EXISTS(
                SELECT 1
                FROM account_groups AS ag
                JOIN chat_list_rows AS row
                    ON row.group_id_hex = ag.group_id_hex
                WHERE row.updated_at < COALESCE((
                        SELECT MAX(mt.received_at)
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                     ), 0)
                   OR row.last_message_id_hex IS NOT (
                        SELECT mt.message_id_hex
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.kind = ?1
                        ORDER BY mt.timeline_at DESC, mt.message_id_hex DESC
                        LIMIT 1
                     )
                   OR row.last_message_sender IS NOT (
                        SELECT mt.sender
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.kind = ?1
                        ORDER BY mt.timeline_at DESC, mt.message_id_hex DESC
                        LIMIT 1
                     )
                   OR row.last_message_preview IS NOT (
                        SELECT mt.plaintext
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.kind = ?1
                        ORDER BY mt.timeline_at DESC, mt.message_id_hex DESC
                        LIMIT 1
                     )
                   OR row.last_message_kind IS NOT (
                        SELECT mt.kind
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.kind = ?1
                        ORDER BY mt.timeline_at DESC, mt.message_id_hex DESC
                        LIMIT 1
                     )
                   OR row.last_message_timeline_at IS NOT (
                        SELECT mt.timeline_at
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.kind = ?1
                        ORDER BY mt.timeline_at DESC, mt.message_id_hex DESC
                        LIMIT 1
                     )
                   OR row.last_message_deleted IS NOT COALESCE((
                        SELECT mt.deleted
                        FROM message_timeline AS mt
                        WHERE mt.group_id_hex = ag.group_id_hex
                          AND mt.kind = ?1
                        ORDER BY mt.timeline_at DESC, mt.message_id_hex DESC
                        LIMIT 1
                     ), 0)
             )",
        params![u64_to_i64(MARMOT_APP_EVENT_KIND_CHAT)?],
    )? {
        return Ok(false);
    }
    Ok(true)
}

fn projection_has_rows_tx<P: Params>(
    tx: &Transaction<'_>,
    sql: &str,
    params: P,
) -> StorageResult<bool> {
    let exists: i64 = tx.query_row(sql, params, |row| row.get(0)).storage()?;
    Ok(exists != 0)
}

fn rebuild_chat_list_row_for_group_tx(
    tx: &Transaction<'_>,
    local_account_id_hex: &str,
    group: AccountGroupRow,
) -> StorageResult<()> {
    let latest = latest_kind9_message_tx(tx, &group.group_id_hex)?;
    let read_state = read_state_tx(tx, &group.group_id_hex)?;
    let unread = unread_summary_tx(
        tx,
        local_account_id_hex,
        &group.group_id_hex,
        read_state.as_ref(),
    )?;
    let now = unix_now_seconds();
    tx.execute(
        "INSERT INTO chat_list_rows (
            group_id_hex, archived, pending_confirmation, title, group_name,
            avatar_url,
            avatar_image_hash_hex, avatar_image_key_hex, avatar_image_nonce_hex,
            avatar_image_upload_key_hex, avatar_media_type,
            last_message_id_hex, last_message_sender, last_message_preview,
            last_message_kind, last_message_timeline_at, last_message_deleted,
            unread_count, first_unread_message_id_hex, last_read_message_id_hex,
            last_read_timeline_at, updated_at
         )
         VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
         )
         ON CONFLICT(group_id_hex) DO UPDATE SET
            archived = excluded.archived,
            pending_confirmation = excluded.pending_confirmation,
            title = excluded.title,
            group_name = excluded.group_name,
            avatar_url = excluded.avatar_url,
            avatar_image_hash_hex = excluded.avatar_image_hash_hex,
            avatar_image_key_hex = excluded.avatar_image_key_hex,
            avatar_image_nonce_hex = excluded.avatar_image_nonce_hex,
            avatar_image_upload_key_hex = excluded.avatar_image_upload_key_hex,
            avatar_media_type = excluded.avatar_media_type,
            last_message_id_hex = excluded.last_message_id_hex,
            last_message_sender = excluded.last_message_sender,
            last_message_preview = excluded.last_message_preview,
            last_message_kind = excluded.last_message_kind,
            last_message_timeline_at = excluded.last_message_timeline_at,
            last_message_deleted = excluded.last_message_deleted,
            unread_count = excluded.unread_count,
            first_unread_message_id_hex = excluded.first_unread_message_id_hex,
            last_read_message_id_hex = excluded.last_read_message_id_hex,
            last_read_timeline_at = excluded.last_read_timeline_at,
            updated_at = excluded.updated_at",
        params![
            &group.group_id_hex,
            bool_i64(group.archived),
            bool_i64(group.pending_confirmation),
            chat_title(&group),
            &group.profile_name,
            group.avatar_url.as_deref(),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_hash_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_key_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_nonce_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .map(|avatar| avatar.image_upload_key_hex.as_str())
                .unwrap_or(""),
            group
                .avatar
                .as_ref()
                .and_then(|avatar| avatar.media_type.as_deref()),
            latest
                .as_ref()
                .map(|message| message.message_id_hex.as_str()),
            latest.as_ref().map(|message| message.sender.as_str()),
            latest.as_ref().map(|message| message.plaintext.as_str()),
            optional_u64_to_i64(latest.as_ref().map(|message| message.kind))?,
            optional_u64_to_i64(latest.as_ref().map(|message| message.timeline_at))?,
            latest
                .as_ref()
                .map(|message| bool_i64(message.deleted))
                .unwrap_or(0),
            u64_to_i64(unread.count)?,
            unread.first_message_id.as_deref(),
            read_state
                .as_ref()
                .and_then(|state| state.last_read_message_id_hex.as_deref()),
            optional_u64_to_i64(
                read_state
                    .as_ref()
                    .and_then(|state| state.last_read_timeline_at)
            )?,
            u64_to_i64(now)?,
        ],
    )
    .storage()?;
    Ok(())
}

#[derive(Clone, Debug)]
struct UnreadSummary {
    count: u64,
    first_message_id: Option<String>,
}

fn unread_summary_tx(
    tx: &Transaction<'_>,
    local_account_id_hex: &str,
    group_id_hex: &str,
    read_state: Option<&ConversationReadState>,
) -> StorageResult<UnreadSummary> {
    let Some(read_state) = read_state else {
        return Ok(UnreadSummary {
            count: 0,
            first_message_id: None,
        });
    };
    let (where_sql, marker_at, marker_id) =
        if let Some(last_read_at) = read_state.last_read_timeline_at {
            (
                "(timeline_at > ?4 OR (timeline_at = ?4 AND message_id_hex > ?5))",
                last_read_at,
                read_state.last_read_message_id_hex.as_deref().unwrap_or(""),
            )
        } else {
            (
                "timeline_at > ?4 AND (?5 = ?5)",
                read_state.initialized_at,
                "",
            )
        };
    let sql = format!(
        "SELECT COUNT(*)
         FROM message_timeline
         WHERE group_id_hex = ?1
           AND kind = ?2
           AND deleted = 0
           AND sender != ?3
           AND {where_sql}"
    );
    let count = tx
        .query_row(
            &sql,
            params![
                group_id_hex,
                u64_to_i64(MARMOT_APP_EVENT_KIND_CHAT)?,
                local_account_id_hex,
                u64_to_i64(marker_at)?,
                marker_id,
            ],
            |row| row.get::<_, i64>(0),
        )
        .storage()
        .and_then(i64_to_u64)?;
    let first_sql = format!(
        "SELECT message_id_hex
         FROM message_timeline
         WHERE group_id_hex = ?1
           AND kind = ?2
           AND deleted = 0
           AND sender != ?3
           AND {where_sql}
         ORDER BY timeline_at ASC, message_id_hex ASC
         LIMIT 1"
    );
    let first_message_id = tx
        .query_row(
            &first_sql,
            params![
                group_id_hex,
                u64_to_i64(MARMOT_APP_EVENT_KIND_CHAT)?,
                local_account_id_hex,
                u64_to_i64(marker_at)?,
                marker_id,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .storage()?;
    Ok(UnreadSummary {
        count,
        first_message_id,
    })
}

fn account_groups_tx(tx: &Transaction<'_>) -> StorageResult<Vec<AccountGroupRow>> {
    let mut stmt = tx
        .prepare(
            "SELECT ag.group_id_hex, ag.archived, ag.pending_confirmation, ag.profile_name,
                    image_hash_hex, image_key_hex, image_nonce_hex,
                    image_upload_key_hex, image_media_type, avatar_url.component_data_hex
             FROM account_groups AS ag
             LEFT JOIN account_group_app_components AS avatar_url
                ON avatar_url.group_id_hex = ag.group_id_hex
               AND avatar_url.component_id = ?1",
        )
        .storage()?;
    stmt.query_map(
        params![GROUP_AVATAR_URL_COMPONENT_ID],
        account_group_from_row,
    )
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

fn account_group_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<Option<AccountGroupRow>> {
    tx.query_row(
        "SELECT ag.group_id_hex, ag.archived, ag.pending_confirmation, ag.profile_name,
                image_hash_hex, image_key_hex, image_nonce_hex,
                image_upload_key_hex, image_media_type, avatar_url.component_data_hex
         FROM account_groups AS ag
         LEFT JOIN account_group_app_components AS avatar_url
            ON avatar_url.group_id_hex = ag.group_id_hex
           AND avatar_url.component_id = ?2
         WHERE ag.group_id_hex = ?1",
        params![group_id_hex, GROUP_AVATAR_URL_COMPONENT_ID],
        account_group_from_row,
    )
    .optional()
    .storage()
}

fn account_group_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountGroupRow> {
    let image_hash_hex: String = row.get(4)?;
    let image_key_hex: String = row.get(5)?;
    let image_nonce_hex: String = row.get(6)?;
    let image_upload_key_hex: String = row.get(7)?;
    let media_type: Option<String> = row.get(8)?;
    let avatar_url_component_hex: Option<String> = row.get(9)?;
    let has_avatar = !image_hash_hex.is_empty()
        || !image_key_hex.is_empty()
        || !image_nonce_hex.is_empty()
        || !image_upload_key_hex.is_empty()
        || media_type.is_some();
    Ok(AccountGroupRow {
        group_id_hex: row.get(0)?,
        archived: row.get::<_, i64>(1)? != 0,
        pending_confirmation: row.get::<_, i64>(2)? != 0,
        profile_name: row.get(3)?,
        avatar_url: decoded_avatar_url(avatar_url_component_hex.as_deref()),
        avatar: has_avatar.then_some(ChatListAvatar {
            image_hash_hex,
            image_key_hex,
            image_nonce_hex,
            image_upload_key_hex,
            media_type,
        }),
    })
}

fn latest_kind9_message_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<Option<ChatListMessagePreview>> {
    tx.query_row(
        "SELECT message_id_hex, sender, plaintext, kind, timeline_at, deleted
         FROM message_timeline
         WHERE group_id_hex = ?1 AND kind = ?2
         ORDER BY timeline_at DESC, message_id_hex DESC
         LIMIT 1",
        params![group_id_hex, u64_to_i64(MARMOT_APP_EVENT_KIND_CHAT)?],
        chat_list_message_from_row,
    )
    .optional()
    .storage()
}

fn timeline_message_for_read_marker_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<Option<ChatListMessagePreview>> {
    tx.query_row(
        "SELECT message_id_hex, sender, plaintext, kind, timeline_at, deleted
         FROM message_timeline
         WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND kind = ?3",
        params![
            group_id_hex,
            message_id_hex,
            u64_to_i64(MARMOT_APP_EVENT_KIND_CHAT)?
        ],
        chat_list_message_from_row,
    )
    .optional()
    .storage()
}

fn chat_list_message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatListMessagePreview> {
    Ok(ChatListMessagePreview {
        message_id_hex: row.get(0)?,
        sender: row.get(1)?,
        sender_display_name: None,
        plaintext: row.get(2)?,
        kind: row.get::<_, i64>(3)?.try_into().unwrap_or_default(),
        timeline_at: row.get::<_, i64>(4)?.try_into().unwrap_or_default(),
        deleted: row.get::<_, i64>(5)? != 0,
    })
}

fn read_state_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<Option<ConversationReadState>> {
    tx.query_row(
        "SELECT last_read_message_id_hex, last_read_timeline_at, initialized_at
         FROM conversation_read_state
         WHERE group_id_hex = ?1",
        params![group_id_hex],
        |row| {
            Ok(ConversationReadState {
                last_read_message_id_hex: row.get(0)?,
                last_read_timeline_at: row
                    .get::<_, Option<i64>>(1)?
                    .and_then(|value| value.try_into().ok()),
                initialized_at: row.get::<_, i64>(2)?.try_into().unwrap_or_default(),
            })
        },
    )
    .optional()
    .storage()
}

fn chat_list_rows_tx(
    tx: &Transaction<'_>,
    query: ChatListQuery,
) -> StorageResult<Vec<ChatListRow>> {
    let sql = if query.include_archived {
        "SELECT group_id_hex, archived, pending_confirmation, title, group_name,
                avatar_url,
                avatar_image_hash_hex, avatar_image_key_hex, avatar_image_nonce_hex,
                avatar_image_upload_key_hex, avatar_media_type,
                last_message_id_hex, last_message_sender, last_message_preview,
                last_message_kind, last_message_timeline_at, last_message_deleted,
                unread_count, first_unread_message_id_hex, last_read_message_id_hex,
                last_read_timeline_at, updated_at
         FROM chat_list_rows
         ORDER BY last_message_timeline_at DESC, group_id_hex"
    } else {
        "SELECT group_id_hex, archived, pending_confirmation, title, group_name,
                avatar_url,
                avatar_image_hash_hex, avatar_image_key_hex, avatar_image_nonce_hex,
                avatar_image_upload_key_hex, avatar_media_type,
                last_message_id_hex, last_message_sender, last_message_preview,
                last_message_kind, last_message_timeline_at, last_message_deleted,
                unread_count, first_unread_message_id_hex, last_read_message_id_hex,
                last_read_timeline_at, updated_at
         FROM chat_list_rows
         WHERE archived = 0
         ORDER BY last_message_timeline_at DESC, group_id_hex"
    };
    let mut stmt = tx.prepare(sql).storage()?;
    stmt.query_map([], chat_list_row_from_row)
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

fn chat_list_row_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<Option<ChatListRow>> {
    tx.query_row(
        "SELECT group_id_hex, archived, pending_confirmation, title, group_name,
                avatar_url,
                avatar_image_hash_hex, avatar_image_key_hex, avatar_image_nonce_hex,
                avatar_image_upload_key_hex, avatar_media_type,
                last_message_id_hex, last_message_sender, last_message_preview,
                last_message_kind, last_message_timeline_at, last_message_deleted,
                unread_count, first_unread_message_id_hex, last_read_message_id_hex,
                last_read_timeline_at, updated_at
         FROM chat_list_rows
         WHERE group_id_hex = ?1",
        params![group_id_hex],
        chat_list_row_from_row,
    )
    .optional()
    .storage()
}

fn chat_list_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChatListRow> {
    let avatar_url: Option<String> = row.get(5)?;
    let image_hash_hex: String = row.get(6)?;
    let image_key_hex: String = row.get(7)?;
    let image_nonce_hex: String = row.get(8)?;
    let image_upload_key_hex: String = row.get(9)?;
    let media_type: Option<String> = row.get(10)?;
    let has_avatar = !image_hash_hex.is_empty()
        || !image_key_hex.is_empty()
        || !image_nonce_hex.is_empty()
        || !image_upload_key_hex.is_empty()
        || media_type.is_some();
    let last_message_id_hex: Option<String> = row.get(11)?;
    let last_message = last_message_id_hex.map(|message_id_hex| ChatListMessagePreview {
        message_id_hex,
        sender: row.get(12).unwrap_or_default(),
        sender_display_name: None,
        plaintext: row.get(13).unwrap_or_default(),
        kind: row
            .get::<_, Option<i64>>(14)
            .unwrap_or_default()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default(),
        timeline_at: row
            .get::<_, Option<i64>>(15)
            .unwrap_or_default()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default(),
        deleted: row.get::<_, i64>(16).unwrap_or_default() != 0,
    });
    let raw_unread_count = row.get::<_, i64>(17)?;
    let unread_count = raw_unread_count
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(17, raw_unread_count))?;
    Ok(ChatListRow {
        group_id_hex: row.get(0)?,
        archived: row.get::<_, i64>(1)? != 0,
        pending_confirmation: row.get::<_, i64>(2)? != 0,
        title: row.get(3)?,
        group_name: row.get(4)?,
        avatar_url,
        avatar: has_avatar.then_some(ChatListAvatar {
            image_hash_hex,
            image_key_hex,
            image_nonce_hex,
            image_upload_key_hex,
            media_type,
        }),
        last_message,
        unread_count,
        has_unread: unread_count > 0,
        first_unread_message_id_hex: row.get(18)?,
        last_read_message_id_hex: row.get(19)?,
        last_read_timeline_at: row
            .get::<_, Option<i64>>(20)?
            .and_then(|value| value.try_into().ok()),
        updated_at: row.get::<_, i64>(21)?.try_into().unwrap_or_default(),
    })
}

fn chat_title(group: &AccountGroupRow) -> &str {
    if group.profile_name.trim().is_empty() {
        &group.group_id_hex
    } else {
        &group.profile_name
    }
}

fn decoded_avatar_url(component_data_hex: Option<&str>) -> Option<String> {
    let bytes = hex::decode(component_data_hex?).ok()?;
    let avatar = decode_group_avatar_url_v1(&bytes).ok()?;
    (!avatar.url.is_empty()).then_some(avatar.url)
}

fn timeline_tuple_after(left_at: u64, left_id: &str, right_at: u64, right_id: &str) -> bool {
    left_at > right_at || (left_at == right_at && left_id > right_id)
}

fn bool_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn optional_u64_to_i64(value: Option<u64>) -> StorageResult<Option<i64>> {
    value.map(u64_to_i64).transpose()
}

fn u64_to_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

fn i64_to_u64(value: i64) -> StorageResult<u64> {
    u64::try_from(value)
        .map_err(|_| StorageError::Serialization(format!("value does not fit in u64: {value}")))
}

fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        StoredAccountGroup, StoredAccountGroupComponent, StoredAccountState, StoredAppEvent,
    };
    use cgka_traits::app_components::{
        GROUP_AVATAR_URL_COMPONENT, GROUP_AVATAR_URL_COMPONENT_ID, GroupAvatarUrlV1,
        encode_group_avatar_url_v1,
    };
    use cgka_traits::app_event::{
        EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_REACTION,
    };

    const LOCAL: &str = "aa";
    const REMOTE: &str = "bb";
    const GROUP: &str = "11";

    fn group() -> StoredAccountGroup {
        StoredAccountGroup {
            group_id_hex: GROUP.to_owned(),
            endpoint: "relay".to_owned(),
            profile_name: "Marmot Lab".to_owned(),
            profile_description: String::new(),
            image_hash_hex: String::new(),
            image_key_hex: String::new(),
            image_nonce_hex: String::new(),
            image_upload_key_hex: String::new(),
            image_media_type: None,
            admin_keys_hex: String::new(),
            archived: false,
            pending_confirmation: false,
            welcomer_account_id_hex: None,
            via_welcome_message_id_hex: None,
            components: Vec::new(),
        }
    }

    fn chat(id: &str, sender: &str, at: u64, plaintext: &str) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: GROUP.to_owned(),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            source_epoch: None,
            direction: if sender == LOCAL { "sent" } else { "received" }.to_owned(),
            sender: sender.to_owned(),
            plaintext: plaintext.to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            recorded_at: at,
            received_at: at,
            origin_commit_id: None,
        }
    }

    fn reaction(id: &str, sender: &str, target: &str, at: u64) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: GROUP.to_owned(),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            source_epoch: None,
            direction: "received".to_owned(),
            sender: sender.to_owned(),
            plaintext: "+".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_REACTION,
            tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
            recorded_at: at,
            received_at: at,
            origin_commit_id: None,
        }
    }

    fn setup_store_with_group(group: StoredAccountGroup) -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .save_account_projection_state(
                &StoredAccountState {
                    label: "alice".to_owned(),
                    groups: vec![group],
                    ..StoredAccountState::default()
                },
                256,
            )
            .unwrap();
        store
    }

    fn setup_store() -> SqliteAccountStorage {
        setup_store_with_group(group())
    }

    fn avatar_url_component(url: &str) -> StoredAccountGroupComponent {
        let bytes = encode_group_avatar_url_v1(&GroupAvatarUrlV1 {
            url: url.to_owned(),
            dim: None,
            thumbhash: None,
        })
        .unwrap();
        StoredAccountGroupComponent {
            component_id: GROUP_AVATAR_URL_COMPONENT_ID,
            component_name: GROUP_AVATAR_URL_COMPONENT.to_owned(),
            component_data_hex: hex::encode(bytes),
        }
    }

    #[test]
    fn initialize_chat_read_state_returns_none_for_unknown_group() {
        let store = setup_store();

        let row = store
            .initialize_chat_read_state(LOCAL, "missing-group")
            .unwrap();

        assert_eq!(row, None);
    }

    #[test]
    fn refresh_chat_list_row_returns_refreshed_single_group_projection() {
        let store = setup_store();
        store
            .record_app_event(&chat("latest", REMOTE, 10, "single row"))
            .unwrap();

        let row = store
            .refresh_chat_list_row(LOCAL, GROUP)
            .unwrap()
            .expect("chat row");

        assert_eq!(row.group_id_hex, GROUP);
        assert_eq!(
            row.last_message
                .as_ref()
                .map(|message| message.message_id_hex.as_str()),
            Some("latest")
        );
        assert_eq!(
            store.refresh_chat_list_row(LOCAL, "missing-group").unwrap(),
            None
        );
    }

    #[test]
    fn refresh_chat_list_row_projects_group_avatar_url() {
        let mut group = group();
        group
            .components
            .push(avatar_url_component("https://cdn.example.com/group.png"));
        let store = setup_store_with_group(group);

        let row = store
            .refresh_chat_list_row(LOCAL, GROUP)
            .unwrap()
            .expect("chat row");

        assert_eq!(
            row.avatar_url.as_deref(),
            Some("https://cdn.example.com/group.png")
        );
    }

    #[test]
    fn chat_list_reads_cached_projection_without_rebuilding() {
        let store = setup_store();
        store
            .record_app_event(&chat("old", REMOTE, 10, "cached"))
            .unwrap();

        assert_eq!(
            store
                .chat_list_rows(crate::ChatListQuery::default())
                .unwrap(),
            Vec::new()
        );

        store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");
        assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

        store
            .record_app_event(&chat("new", REMOTE, 11, "not refreshed yet"))
            .unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");
        assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

        store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");
        assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "new");
    }

    #[test]
    fn ensure_chat_list_rows_backfills_missing_projection_rows() {
        let store = setup_store();
        store
            .record_app_event(&chat("latest", REMOTE, 10, "backfilled"))
            .unwrap();

        store.ensure_chat_list_rows(LOCAL).unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");

        assert_eq!(row.group_id_hex, GROUP);
        assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "latest");
    }

    #[test]
    fn ensure_chat_list_rows_rebuilds_stale_account_group_rows() {
        let store = setup_store();
        store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "UPDATE account_groups
                 SET profile_name = ?1
                 WHERE group_id_hex = ?2",
                params!["Renamed Lab", GROUP],
            )
            .unwrap();
        }

        store.ensure_chat_list_rows(LOCAL).unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");

        assert_eq!(row.title, "Renamed Lab");
        assert_eq!(row.group_name, "Renamed Lab");
    }

    #[test]
    fn ensure_chat_list_rows_rebuilds_stale_message_rows() {
        let store = setup_store();
        store
            .record_app_event(&chat("old", REMOTE, 10, "old preview"))
            .unwrap();
        store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
        store
            .record_app_event(&chat("new", REMOTE, 11, "new preview"))
            .unwrap();

        store.ensure_chat_list_rows(LOCAL).unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");

        let last_message = row.last_message.expect("last message");
        assert_eq!(last_message.message_id_hex, "new");
        assert_eq!(last_message.plaintext, "new preview");
    }

    #[test]
    fn ensure_chat_list_rows_rebuilds_stale_read_state_rows() {
        let store = setup_store();
        store
            .record_app_event(&chat("unread", REMOTE, 10, "needs read state"))
            .unwrap();
        store.refresh_chat_list_row(LOCAL, GROUP).unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute(
                "INSERT INTO conversation_read_state (
                    group_id_hex, last_read_message_id_hex, last_read_timeline_at,
                    initialized_at, updated_at
                 )
                 VALUES (?1, NULL, NULL, 0, 1)",
                params![GROUP],
            )
            .unwrap();
            conn.execute(
                "UPDATE chat_list_rows SET updated_at = 0 WHERE group_id_hex = ?1",
                params![GROUP],
            )
            .unwrap();
        }

        store.ensure_chat_list_rows(LOCAL).unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");

        assert_eq!(row.unread_count, 1);
        assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("unread"));
    }

    #[test]
    fn unread_starts_after_first_open_and_advances_by_visible_kind9() {
        let store = setup_store();
        store
            .record_app_event(&chat("old", REMOTE, 10, "before first open"))
            .unwrap();

        let row = store
            .refresh_chat_list_row(LOCAL, GROUP)
            .unwrap()
            .expect("chat row");
        assert_eq!(row.group_id_hex, GROUP);
        assert_eq!(row.title, "Marmot Lab");
        assert_eq!(row.unread_count, 0);
        assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "old");

        store.initialize_chat_read_state(LOCAL, GROUP).unwrap();
        store
            .record_app_event(&reaction("reaction", REMOTE, "old", 11))
            .unwrap();
        store
            .record_app_event(&chat("new", REMOTE, 12, "after first open"))
            .unwrap();

        let row = store
            .refresh_chat_list_row(LOCAL, GROUP)
            .unwrap()
            .expect("chat row");
        assert_eq!(row.unread_count, 1);
        assert_eq!(row.first_unread_message_id_hex.as_deref(), Some("new"));

        store
            .mark_timeline_message_read(LOCAL, GROUP, "new")
            .unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");
        assert_eq!(row.unread_count, 0);
        assert_eq!(row.last_read_message_id_hex.as_deref(), Some("new"));
    }

    #[test]
    fn own_kind9_send_clears_existing_unread_without_counting_as_unread() {
        let store = setup_store();
        store.initialize_chat_read_state(LOCAL, GROUP).unwrap();
        store
            .record_app_event(&chat("remote", REMOTE, 10, "unread"))
            .unwrap();
        assert_eq!(
            store
                .refresh_chat_list_row(LOCAL, GROUP)
                .unwrap()
                .expect("chat row")
                .unread_count,
            1
        );

        store
            .record_app_event(&chat("own", LOCAL, 11, "my reply"))
            .unwrap();
        store
            .mark_timeline_message_read(LOCAL, GROUP, "own")
            .unwrap();
        let row = store
            .chat_list_rows(crate::ChatListQuery::default())
            .unwrap()
            .pop()
            .expect("chat row");

        assert_eq!(row.unread_count, 0);
        assert_eq!(row.last_read_message_id_hex.as_deref(), Some("own"));
        assert_eq!(row.last_message.as_ref().unwrap().message_id_hex, "own");
    }
}
