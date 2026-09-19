//! Bounded list-only draft metadata and local row action hints. These reads share
//! the row transaction; they never load attachment bytes or change list ordering.
use super::*;
use crate::{ChatListAttachmentKind, ChatListRow, SelfMembership};
use cgka_traits::GroupLifecycleState;

pub const CHAT_LIST_DRAFT_PREVIEW_CHARS: usize = 1024;

/// Message uses the existing `row.last_message`, including its prepared metadata.
/// Invitation/Empty are localization keys, never English display strings.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectedChatPreview {
    Draft(ChatListDraftPreview),
    Message,
    Invitation,
    #[default]
    Empty,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatListDraftPreview {
    /// Trimmed preview only; saving/opening the composer preserves original content.
    pub text: String,
    pub text_truncated: bool,
    pub attachment_count: u64,
    pub attachment_kind: Option<ChatListAttachmentKind>,
}
impl std::fmt::Debug for ChatListDraftPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListDraftPreview")
            .field("text_truncated", &self.text_truncated)
            .field("attachment_count", &self.attachment_count)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SelectedChatPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Draft(_) => "Draft(..)",
            Self::Message => "Message",
            Self::Invitation => "Invitation",
            Self::Empty => "Empty",
        })
    }
}

/// Local display availability, not command authorization. `can_start_leave` opens
/// the existing authoritative leave flow (including admin demotion/disband checks).
/// No engine or roster is loaded to render these hints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatListRowActions {
    pub can_mark_read: bool,
    pub can_mark_unread: bool,
    pub can_pin: bool,
    pub can_unpin: bool,
    pub can_mute: bool,
    pub can_unmute: bool,
    pub can_archive: bool,
    pub can_restore: bool,
    pub can_start_leave: bool,
    pub can_delete_local: bool,
}
impl ChatListRowActions {
    pub fn for_row(row: &ChatListRow) -> Self {
        let departing = row.leave_requested_at_ms.is_some() || row.disbanding;
        let departed = row.self_membership != SelfMembership::Member
            || row.lifecycle_state == GroupLifecycleState::Disbanded;
        let active = !departing && !departed;
        let attention = active && !row.pending_confirmation;
        Self {
            can_mark_read: attention && row.has_unread,
            can_mark_unread: attention && !row.has_unread,
            can_pin: !row.archived && !row.pinned,
            can_unpin: row.pinned,
            can_mute: !row.muted,
            can_unmute: row.muted,
            can_archive: !row.archived,
            can_restore: row.archived,
            can_start_leave: attention && row.lifecycle_state != GroupLifecycleState::Unrecoverable,
            can_delete_local: departed && !departing,
        }
    }
}

pub(crate) fn selected_preview_tx(
    conn: &rusqlite::Connection,
    row: &ChatListRow,
) -> StorageResult<SelectedChatPreview> {
    // Unicode White_Space matches Rust str::trim. SQL bounds the returned text
    // before Rust allocation; even a huge selected draft never crosses this boundary whole.
    const WHITE_SPACE: &str = "\u{0009}\u{000a}\u{000b}\u{000c}\u{000d}\u{0020}\u{0085}\u{00a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}";
    let bytes: Option<Vec<u8>> = conn
        .query_row_cached(
            "SELECT coalesce(substr(CAST(trim(content, ?2) AS BLOB), 1, ?3), x'') FROM message_drafts WHERE group_id_hex=?1",
            params![
                row.group_id_hex,
                WHITE_SPACE,
                ((CHAT_LIST_DRAFT_PREVIEW_CHARS + 1) * 4) as i64
            ],
            |r| r.get(0),
        )
        .optional()
        .storage()?;
    if let Some(bytes) = bytes {
        // BLOB slicing preserves embedded NUL (SQLite text substr stops there).
        // At most one incomplete UTF-8 scalar can end this bounded prefix. We
        // already have more than 1,024 complete scalars when that happens.
        let valid = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(error) if error.error_len().is_none() => {
                std::str::from_utf8(&bytes[..error.valid_up_to()]).expect("validated UTF-8 prefix")
            }
            Err(_) => return Err(StorageError::Serialization("invalid draft UTF-8".into())),
        };
        let mut text = valid.to_owned();
        // Sibling category policy: marmot_app::media::classify_chat_list_attachments.
        // These are local composer attachments, not received imeta with rejection
        // outcomes. Keep the categories aligned while aggregating before allocation.
        // At most four aggregate rows. No attachment plaintext, filename, URL,
        // waveform or thumbhash enters the list snapshot. The PK scopes work to
        // this returned group's draft, independently of other account drafts.
        let mut statement = conn
            .prepare_cached(
                "SELECT CASE WHEN lower(media_type) LIKE 'image/%' THEN 0
                         WHEN lower(media_type) LIKE 'video/%' THEN 1
                         WHEN lower(media_type) LIKE 'audio/%' THEN 2 ELSE 3 END AS kind,
                    count(*) FROM message_draft_attachments WHERE group_id_hex=?1 GROUP BY kind",
            )
            .storage()?;
        let mut attachment_count = 0u64;
        let mut attachment_kind = None;
        let kinds = statement
            .query_map([&row.group_id_hex], |r| {
                Ok((r.get::<_, u32>(0)?, super::nonnegative(r, 1)?))
            })
            .storage()?;
        for item in kinds {
            let (kind, count) = item.storage()?;
            attachment_count = attachment_count.saturating_add(count);
            let kind = match kind {
                0 => ChatListAttachmentKind::Photo,
                1 => ChatListAttachmentKind::Video,
                2 => ChatListAttachmentKind::Audio,
                _ => ChatListAttachmentKind::File,
            };
            attachment_kind = Some(if attachment_kind.is_some() {
                ChatListAttachmentKind::Mixed
            } else {
                kind
            });
        }
        if !text.is_empty() || attachment_count != 0 {
            let text_truncated = text.chars().count() > CHAT_LIST_DRAFT_PREVIEW_CHARS;
            if text_truncated {
                text.truncate(
                    text.char_indices()
                        .nth(CHAT_LIST_DRAFT_PREVIEW_CHARS)
                        .expect("extra char")
                        .0,
                );
            }
            return Ok(SelectedChatPreview::Draft(ChatListDraftPreview {
                text,
                text_truncated,
                attachment_count,
                attachment_kind,
            }));
        }
    }
    Ok(if row.last_message.is_some() {
        SelectedChatPreview::Message
    } else if row.pending_confirmation {
        SelectedChatPreview::Invitation
    } else {
        SelectedChatPreview::Empty
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (SqliteAccountStorage, ChatListRow) {
        let store = SqliteAccountStorage::in_memory().unwrap();
        {
            let conn = store.lock().unwrap();
            conn.execute("INSERT INTO account_groups(group_id_hex, endpoint, profile_name, updated_at) VALUES ('11','fixture','',1)", []).unwrap();
            conn.execute("INSERT INTO chat_list_rows(group_id_hex, activity_sort_at, updated_at) VALUES ('11',7,1)", []).unwrap();
        }
        let row = crate::chat_list::chat_list_row_tx(&store.lock().unwrap(), "11")
            .unwrap()
            .unwrap();
        (store, row)
    }
    fn preview(store: &SqliteAccountStorage, row: &ChatListRow) -> SelectedChatPreview {
        selected_preview_tx(&store.lock().unwrap(), row).unwrap()
    }
    #[test]
    fn chat_list_preview_selection_preserves_empty_reply_only_and_unicode_drafts() {
        let (store, mut row) = fixture();
        assert_eq!(preview(&store, &row), SelectedChatPreview::Empty);
        row.pending_confirmation = true;
        assert_eq!(preview(&store, &row), SelectedChatPreview::Invitation);
        row.last_message = Some(crate::ChatListMessagePreview {
            message_id_hex: "message".into(),
            sender: "sender".into(),
            sender_display_name: None,
            plaintext: "latest".into(),
            media_json: None,
            kind: 9,
            timeline_at: 7,
            deleted: false,
            deletion_source: crate::DeletionSource::Unknown,
            group_system: None,
            attachment_kind: None,
            attachment_count: 0,
            delivery_state: crate::ChatListMessageDeliveryState::NotApplicable,
        });
        assert_eq!(preview(&store, &row), SelectedChatPreview::Message);
        assert!(row.pending_confirmation);
        store.save_message_draft("11", "draft", None, &[]).unwrap();
        assert!(matches!(
            preview(&store, &row),
            SelectedChatPreview::Draft(_)
        ));
        row.last_message = None;

        for text in ["", " \n\t", "\u{2003}\u{00a0}"] {
            store
                .save_message_draft("11", text, Some(&"aa".repeat(32)), &[])
                .unwrap();
            assert_eq!(preview(&store, &row), SelectedChatPreview::Invitation);
            assert_eq!(store.message_draft("11").unwrap().unwrap().content, text);
        }
        store
            .save_message_draft("11", "  hello\n", None, &[])
            .unwrap();
        let SelectedChatPreview::Draft(draft) = preview(&store, &row) else {
            panic!("draft")
        };
        assert_eq!(draft.text, "hello");
        assert!(!draft.text_truncated);
        assert_eq!(draft.attachment_count, 0);
        store.save_message_draft("11", "\0text", None, &[]).unwrap();
        assert!(
            matches!(preview(&store, &row), SelectedChatPreview::Draft(d) if d.text == "\0text")
        );
        store.delete_message_draft("11").unwrap();
        assert_eq!(preview(&store, &row), SelectedChatPreview::Invitation);
        assert_eq!(
            crate::chat_list::chat_list_row_tx(&store.lock().unwrap(), "11")
                .unwrap()
                .unwrap()
                .activity_sort_at,
            7
        );
    }
    #[test]
    fn chat_list_preview_bounds_unicode_text_and_summarizes_without_loading_blobs() {
        let (store, row) = fixture();
        let content = "🦀".repeat(CHAT_LIST_DRAFT_PREVIEW_CHARS + 100);
        store.save_message_draft("11", &content, None, &[]).unwrap();
        // Corrupt optional waveform metadata must not be decoded for a row preview.
        // Large BLOBs remain in SQLCipher; only type/count aggregates are selected.
        store.lock().unwrap().execute("INSERT INTO message_draft_attachments(group_id_hex,position,attachment_id,file_name,media_type,plaintext,waveform_samples_json) VALUES ('11',0,'a','secret','image/png',zeroblob(8000000),'invalid-json'),('11',1,'b','secret','audio/mp4',zeroblob(8000000),'invalid-json')", []).unwrap();
        let SelectedChatPreview::Draft(draft) = preview(&store, &row) else {
            panic!("draft")
        };
        assert_eq!(draft.text.chars().count(), CHAT_LIST_DRAFT_PREVIEW_CHARS);
        assert!(draft.text_truncated);
        assert_eq!(draft.attachment_count, 2);
        assert_eq!(draft.attachment_kind, Some(ChatListAttachmentKind::Mixed));
        assert!(!format!("{draft:?}").contains('🦀'));
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE message_drafts SET content='' WHERE group_id_hex='11'",
                [],
            )
            .unwrap();
        assert!(
            matches!(preview(&store, &row), SelectedChatPreview::Draft(d) if d.text.is_empty() && d.attachment_count == 2)
        );
    }
    #[test]
    fn chat_list_actions_do_not_allow_destructive_work_during_departure() {
        let (_, mut row) = fixture();
        let a = ChatListRowActions::for_row(&row);
        assert!(a.can_mark_unread && a.can_pin && a.can_mute && a.can_archive && a.can_start_leave);
        assert!(!a.can_delete_local);
        row.pending_confirmation = true;
        let a = ChatListRowActions::for_row(&row);
        assert!(!a.can_mark_read && !a.can_mark_unread && !a.can_start_leave);
        row.self_membership = SelfMembership::Left;
        row.leave_requested_at_ms = Some(1);
        let a = ChatListRowActions::for_row(&row);
        assert!(!a.can_start_leave && !a.can_delete_local);
        row.leave_requested_at_ms = None;
        assert!(ChatListRowActions::for_row(&row).can_delete_local);
        row.disbanding = true;
        assert!(!ChatListRowActions::for_row(&row).can_delete_local);
        row.disbanding = false;
        row.self_membership = SelfMembership::Member;
        row.lifecycle_state = GroupLifecycleState::Disbanded;
        let a = ChatListRowActions::for_row(&row);
        assert!(a.can_delete_local && !a.can_start_leave);
        row.archived = true;
        let a = ChatListRowActions::for_row(&row);
        assert!(a.can_restore && !a.can_archive && !a.can_pin && a.can_mute);
        row.muted = true;
        let a = ChatListRowActions::for_row(&row);
        assert!(a.can_unmute && !a.can_mute);
    }
    #[test]
    fn chat_list_draft_query_work_ignores_unrelated_drafts_and_blob_sizes() {
        use crate::query_work_test_support::measure;
        for count in [200, 20_000] {
            let (store, row) = fixture();
            store
                .save_message_draft("11", "selected", None, &[])
                .unwrap();
            let size = if count == 200 { 1024 } else { 8 * 1024 * 1024 };
            store.lock().unwrap().execute("INSERT INTO message_draft_attachments(group_id_hex,position,attachment_id,file_name,media_type,plaintext) VALUES ('11',0,'a','file','image/png',zeroblob(?1))", [size]).unwrap();
            store.lock().unwrap().execute_batch(&format!("INSERT INTO account_groups(group_id_hex,endpoint,updated_at)
                WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < {count})
                SELECT printf('other-%08d',x),'',0 FROM n;
                INSERT INTO message_drafts(group_id_hex,content,created_at_ms,updated_at_ms)
                SELECT group_id_hex,'unrelated',0,0 FROM account_groups WHERE group_id_hex != '11';")).unwrap();
            let (selected, steps) = measure(&store, || preview(&store, &row));
            assert!(
                matches!(selected, SelectedChatPreview::Draft(d) if d.text == "selected" && d.attachment_count == 1)
            );
            assert!(steps < 250, "{count} unrelated drafts: {steps} VM steps");
        }
    }
}
