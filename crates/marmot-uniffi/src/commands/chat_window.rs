//! Additive native entry points for C4's bounded lists and independent summaries.
use crate::conversions::{ChatListViewFfi, ChatListViewQueryFfi};
use crate::subscriptions::{AccountAttentionSubscription, ChatListWindowSubscription};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;
#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Bind to one account/view. None defaults to 50; explicit sizes must be 1–100.
    /// Same as `open_chat_list_query_window` with an unfiltered query.
    pub async fn open_chat_list_window(
        &self,
        account_ref: String,
        view: ChatListViewFfi,
        initial_rows: Option<u32>,
    ) -> Result<Arc<ChatListWindowSubscription>, MarmotKitError> {
        self.open_chat_list_query_window(account_ref, view.into(), initial_rows)
            .await
    }
    /// A live window over every chat `query` matches. The filter runs in SQL
    /// before paging, so chats beyond the window still count. A chat enters or
    /// leaves the window as soon as a fact its filter tests changes. None
    /// defaults to 50 rows; explicit sizes must be 1–100. An invalid query fails
    /// with `InvalidChatListQuery`, a malformed group ID with `InvalidHex`. A
    /// window does not accept a `MessageText` node (`MessageTextInWindow`);
    /// use `chat_list_query_ids`.
    pub async fn open_chat_list_query_window(
        &self,
        account_ref: String,
        query: ChatListViewQueryFfi,
        initial_rows: Option<u32>,
    ) -> Result<Arc<ChatListWindowSubscription>, MarmotKitError> {
        let query = marmot_app::ChatListViewQuery::try_from(query)?;
        Ok(ChatListWindowSubscription::new(
            self.runtime
                .open_chat_list_window(&account_ref, query, initial_rows.map(|n| n as usize))
                .await?,
        ))
    }
    /// Select all: every chat ID in `view`. Same as `chat_list_query_ids` with
    /// an unfiltered query.
    pub async fn chat_list_ids(
        &self,
        account_ref: String,
        view: ChatListViewFfi,
    ) -> Result<Vec<String>, MarmotKitError> {
        self.chat_list_query_ids(account_ref, view.into()).await
    }
    /// Select all: every chat ID `query` matches, in display order, including
    /// chats beyond any open window; the count is the list length. Fails with
    /// `ChatPresentationNotReady`, never a partial list, while base rows, the
    /// presentation a `Text` node reads, or the retained deletions and edits a
    /// `MessageText` node reads are still being prepared; retry later. Unlike
    /// a window, this accepts `MessageText`.
    pub async fn chat_list_query_ids(
        &self,
        account_ref: String,
        query: ChatListViewQueryFfi,
    ) -> Result<Vec<String>, MarmotKitError> {
        let query = marmot_app::ChatListViewQuery::try_from(query)?;
        Ok(self.runtime.chat_list_ids(&account_ref, query).await?)
    }
    /// The subset of `group_ids` still in `view`. Same as
    /// `revalidate_chat_list_query_ids` with an unfiltered query.
    pub async fn revalidate_chat_list_ids(
        &self,
        account_ref: String,
        view: ChatListViewFfi,
        group_ids: Vec<String>,
    ) -> Result<Vec<String>, MarmotKitError> {
        self.revalidate_chat_list_query_ids(account_ref, view.into(), group_ids)
            .await
    }
    /// The subset of `group_ids` still matching `query`, in the caller's order
    /// with duplicates dropped. Only removes; chats that matched since are never
    /// added. Call it right before a bulk action, then run the existing per-chat
    /// commands, which still check their own preconditions.
    pub async fn revalidate_chat_list_query_ids(
        &self,
        account_ref: String,
        query: ChatListViewQueryFfi,
        group_ids: Vec<String>,
    ) -> Result<Vec<String>, MarmotKitError> {
        let query = marmot_app::ChatListViewQuery::try_from(query)?;
        Ok(self
            .runtime
            .revalidate_chat_list_ids(&account_ref, query, group_ids)
            .await?)
    }
    /// Signed-in local/external accounts, independent of any list or active worker.
    pub async fn subscribe_account_attention(
        &self,
    ) -> Result<Arc<AccountAttentionSubscription>, MarmotKitError> {
        Ok(AccountAttentionSubscription::new(
            self.runtime.subscribe_account_attention().await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversions::*;
    use cgka_traits::TransportEndpoint;
    use marmot_app::{AccountSetupRequest, MarmotApp};
    use nostr_relay_builder::MockRelay;
    use std::time::Duration;

    /// A kit with one account holding `groups` local groups. Keep the relay and
    /// directory alive for the test's duration.
    async fn kit_with_groups(groups: &[&str]) -> (MockRelay, tempfile::TempDir, Marmot, String) {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await.to_string();
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relays(dir.path(), vec![url.clone()]);
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let endpoint = TransportEndpoint(url);
        let account = kit
            .runtime
            .create_identity(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
                ..Default::default()
            })
            .await
            .unwrap()
            .account
            .account_id_hex;
        for name in groups {
            kit.create_group(account.clone(), (*name).into(), vec![], None)
                .await
                .unwrap()
                .group_id_hex
                .expect("selected members create a group");
        }
        (relay, dir, kit, account)
    }

    #[tokio::test]
    async fn native_window_commands_run_during_receive_and_attention_is_independent() {
        let (_relay, _dir, kit, account) = kit_with_groups(&["One", "Two", "Three"]).await;
        let attention = kit.subscribe_account_attention().await.unwrap();
        let summary = attention.snapshot().unwrap();
        assert!(attention.snapshot().is_none());
        assert_eq!(summary.accounts.len(), 1);
        assert!(
            matches!(summary.accounts[0].state, AccountAttentionStateFfi::Ready {total} if total.unread_conversations == 0)
        );
        assert!(matches!(
            kit.open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(0))
                .await,
            Err(MarmotKitError::ChatWindowInvalidLimit)
        ));
        assert!(matches!(
            kit.open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(101))
                .await,
            Err(MarmotKitError::ChatWindowInvalidLimit)
        ));
        let window = kit
            .open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(1))
            .await
            .unwrap();
        let initial = window.snapshot().unwrap();
        assert!(window.snapshot().is_none());
        assert_eq!(initial.rows.len(), 1);
        assert!(initial.has_more_after);
        assert!(!initial.has_more_before);
        let mut pending = Box::pin(window.next());
        // This direct Rust receive reaches the inline receiver on its first
        // poll, while the independent command handle stays available.
        assert!(futures::poll!(&mut pending).is_pending());
        let page = tokio::time::timeout(
            Duration::from_secs(5),
            window.page(initial.sequence, ChatListPageDirectionFfi::Forward, 1),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(page.rows.len(), 2);
        let update = pending.await.unwrap().unwrap();
        assert_eq!(update.sequence, page.sequence);
        assert_eq!(
            update.subscription_generation,
            initial.subscription_generation
        );
        assert!(matches!(
            window
                .page(initial.sequence, ChatListPageDirectionFfi::Forward, 1)
                .await,
            Err(MarmotKitError::ChatWindowStale)
        ));
        assert!(matches!(
            window
                .set_visible_anchor(page.sequence, "abcd".into())
                .await,
            Err(MarmotKitError::ChatWindowAnchorOutside)
        ));
        let anchor_id = page.rows[1].row.group_id_hex.clone();
        let anchored = window
            .set_visible_anchor(page.sequence, anchor_id.clone())
            .await
            .unwrap();
        assert!(
            matches!(&anchored.anchor, ChatListAnchorOutcomeFfi::Retained {group_id_hex, index:1} if group_id_hex == &anchor_id)
        );
        let top = window.return_to_top(anchored.sequence).await.unwrap();
        assert!(matches!(top.anchor, ChatListAnchorOutcomeFfi::Top));
        drop(window);
        kit.set_chat_manually_unread(account.clone(), anchor_id.clone(), true)
            .unwrap();
        let summary = tokio::time::timeout(Duration::from_secs(5), attention.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            matches!(summary.accounts[0].state, AccountAttentionStateFfi::Ready {total} if total.unread_conversations == 1 && total.attention_only_conversations == 1 && total.unread_count == 0)
        );
        for (view, expected) in [
            (ChatListViewFfi::Chats, 3),
            (ChatListViewFfi::Unread, 1),
            (ChatListViewFfi::Archived, 0),
            (ChatListViewFfi::Left, 0),
        ] {
            let handle = kit
                .open_chat_list_window(account.clone(), view, None)
                .await
                .unwrap();
            assert_eq!(handle.snapshot().unwrap().rows.len(), expected);
        }
        let window = kit
            .open_chat_list_window(account.clone(), ChatListViewFfi::Chats, None)
            .await
            .unwrap();
        let initial = window.snapshot().unwrap();
        let anchor_id = initial.rows[1].row.group_id_hex.clone();
        window
            .set_visible_anchor(initial.sequence, anchor_id.clone())
            .await
            .unwrap();
        kit.set_group_archived(account.clone(), anchor_id.clone(), true)
            .await
            .unwrap();
        let recovered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let update = window.next().await.unwrap().unwrap();
                if matches!(update.anchor, ChatListAnchorOutcomeFfi::Recovered { .. }) {
                    break update;
                }
            }
        })
        .await
        .unwrap();
        let ChatListAnchorOutcomeFfi::Recovered {
            group_id_hex,
            index,
        } = &recovered.anchor
        else {
            unreachable!()
        };
        assert_ne!(group_id_hex, &anchor_id);
        assert_eq!(
            &recovered.rows[*index as usize].row.group_id_hex,
            group_id_hex
        );
        assert!(
            !recovered
                .rows
                .iter()
                .any(|row| row.row.group_id_hex == anchor_id)
        );
        for row in &recovered.rows {
            kit.set_group_archived(account.clone(), row.row.group_id_hex.clone(), true)
                .await
                .unwrap();
        }
        let last = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let update = window.next().await.unwrap().unwrap();
                if matches!(update.anchor, ChatListAnchorOutcomeFfi::Reset) {
                    break update;
                }
            }
        })
        .await
        .unwrap();
        assert!(last.rows.is_empty());
        kit.runtime.shutdown_and_close().await.unwrap();
        assert!(window.next().await.unwrap().is_none());
        assert!(attention.next().await.unwrap().is_none());
        assert!(matches!(
            window.return_to_top(last.sequence).await,
            Err(MarmotKitError::ChatWindowClosed)
        ));
    }

    /// Select all reads the whole view, not the open window, and revalidation
    /// only removes, keeping the caller's order.
    #[tokio::test]
    async fn select_all_covers_the_view_beyond_the_window_and_revalidation_only_removes() {
        let (_relay, _dir, kit, account) = kit_with_groups(&["One", "Two", "Three"]).await;
        let window = kit
            .open_chat_list_window(account.clone(), ChatListViewFfi::Chats, Some(1))
            .await
            .unwrap();
        assert_eq!(window.snapshot().unwrap().rows.len(), 1);
        let full = kit
            .open_chat_list_window(account.clone(), ChatListViewFfi::Chats, None)
            .await
            .unwrap()
            .snapshot()
            .unwrap();
        let ids = kit
            .chat_list_ids(account.clone(), ChatListViewFfi::Chats)
            .await
            .unwrap();
        assert_eq!(
            ids,
            full.rows
                .iter()
                .map(|row| row.row.group_id_hex.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(ids.len(), 3);

        kit.set_group_archived(account.clone(), ids[1].clone(), true)
            .await
            .unwrap();
        let selected = vec![
            ids[2].to_uppercase(),
            ids[1].clone(),
            ids[0].clone(),
            ids[2].clone(),
        ];
        assert_eq!(
            kit.revalidate_chat_list_ids(account.clone(), ChatListViewFfi::Chats, selected.clone())
                .await
                .unwrap(),
            [ids[2].clone(), ids[0].clone()]
        );
        assert_eq!(
            kit.revalidate_chat_list_ids(account.clone(), ChatListViewFfi::Archived, selected)
                .await
                .unwrap(),
            [ids[1].clone()]
        );
        assert_eq!(
            kit.chat_list_ids(account.clone(), ChatListViewFfi::Archived)
                .await
                .unwrap(),
            [ids[1].clone()]
        );
        assert!(matches!(
            kit.revalidate_chat_list_ids(account, ChatListViewFfi::Chats, vec!["not hex".into()])
                .await,
            Err(MarmotKitError::InvalidHex { .. })
        ));
        kit.runtime.shutdown_and_close().await.unwrap();
    }

    /// The node-list query reaches the same SQL filter for the window, select
    /// all and revalidation, and a malformed node list is a typed refusal.
    #[tokio::test]
    async fn filtered_queries_cross_the_binding_as_node_lists() {
        let (_relay, _dir, kit, account) = kit_with_groups(&["One", "Two", "Three"]).await;
        let all = kit
            .chat_list_ids(account.clone(), ChatListViewFfi::Chats)
            .await
            .unwrap();
        kit.set_chat_manually_unread(account.clone(), all[0].clone(), true)
            .unwrap();
        let query = ChatListViewQueryFfi {
            view: ChatListViewFfi::Chats,
            filter: vec![
                ChatListFilterNodeFfi::Any {
                    children: vec![1, 2],
                },
                ChatListFilterNodeFfi::Condition {
                    condition: ChatListConditionFfi::ManualUnread,
                },
                ChatListFilterNodeFfi::GroupIds {
                    group_ids: vec![all[2].to_uppercase()],
                },
            ],
        };
        let expected = [all[0].clone(), all[2].clone()];
        let window = kit
            .open_chat_list_query_window(account.clone(), query.clone(), None)
            .await
            .unwrap();
        let rows = window.snapshot().unwrap().rows;
        assert_eq!(
            rows.iter()
                .map(|r| r.row.group_id_hex.clone())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            kit.chat_list_query_ids(account.clone(), query.clone())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            kit.revalidate_chat_list_query_ids(account.clone(), query, all.clone())
                .await
                .unwrap(),
            expected
        );
        let shared = ChatListViewQueryFfi {
            view: ChatListViewFfi::Chats,
            filter: vec![
                ChatListFilterNodeFfi::All {
                    children: vec![1, 1],
                },
                ChatListFilterNodeFfi::Condition {
                    condition: ChatListConditionFfi::Pinned,
                },
            ],
        };
        assert!(matches!(
            kit.chat_list_query_ids(account.clone(), shared.clone())
                .await,
            Err(MarmotKitError::InvalidChatListQuery {
                reason: ChatListQueryErrorFfi::SharedChild
            })
        ));
        assert!(matches!(
            kit.open_chat_list_query_window(account.clone(), shared, None)
                .await,
            Err(MarmotKitError::InvalidChatListQuery {
                reason: ChatListQueryErrorFfi::SharedChild
            })
        ));
        // A text node searches titles; its bound is a typed refusal.
        let search = |text: String| ChatListViewQueryFfi {
            view: ChatListViewFfi::Chats,
            filter: vec![ChatListFilterNodeFfi::Text { text }],
        };
        let found = kit
            .chat_list_query_ids(account.clone(), search(" tWO ".into()))
            .await
            .unwrap();
        let window = kit
            .open_chat_list_query_window(account.clone(), search(" tWO ".into()), None)
            .await
            .unwrap();
        let rows = window.snapshot().unwrap().rows;
        assert_eq!(
            rows.iter()
                .map(|r| r.row.group_id_hex.clone())
                .collect::<Vec<_>>(),
            found
        );
        assert!(matches!(
            &rows[..],
            [row] if matches!(&row.presentation.title, PresentationTextFfi::Literal { text } if text == "Two")
        ));
        // A message-text node selects chats by what their messages say, but a
        // window refuses it as a typed error.
        kit.send_text(account.clone(), found[0].clone(), "Pizza on FRIDAY".into())
            .await
            .unwrap();
        let messages = ChatListViewQueryFfi {
            view: ChatListViewFfi::Chats,
            filter: vec![ChatListFilterNodeFfi::MessageText {
                text: " friday ".into(),
            }],
        };
        assert_eq!(
            kit.chat_list_query_ids(account.clone(), messages.clone())
                .await
                .unwrap(),
            found
        );
        assert!(matches!(
            kit.open_chat_list_query_window(account.clone(), messages, None)
                .await,
            Err(MarmotKitError::InvalidChatListQuery {
                reason: ChatListQueryErrorFfi::MessageTextInWindow
            })
        ));
        assert!(matches!(
            kit.chat_list_query_ids(account, search("x".repeat(1025)))
                .await,
            Err(MarmotKitError::InvalidChatListQuery {
                reason: ChatListQueryErrorFfi::TextTooLong
            })
        ));
        kit.runtime.shutdown_and_close().await.unwrap();
    }

    /// A Kotlin caller can cancel a waiting `next()`. The update that arrives
    /// meanwhile must reach the following call rather than the cancelled one.
    #[tokio::test]
    async fn a_cancelled_window_wait_leaves_the_update_for_the_next_call() {
        let (_relay, _dir, kit, account) = kit_with_groups(&["One", "Two"]).await;
        let window = kit
            .open_chat_list_window(account, ChatListViewFfi::Chats, Some(1))
            .await
            .unwrap();
        let initial = window.snapshot().unwrap();
        let mut waiting = Box::pin(window.__ffi_next());
        assert!(futures::poll!(&mut waiting).is_pending());
        let page = window
            .page(initial.sequence, ChatListPageDirectionFfi::Forward, 1)
            .await
            .unwrap();
        // The marker keeper checks the receive annotation. This wait gets
        // no further caller poll before cancellation. A successful page reply
        // follows publishing its update, so the next caller poll must see it.
        drop(waiting);
        let mut following = Box::pin(window.__ffi_next());
        let update = match futures::poll!(&mut following) {
            std::task::Poll::Ready(result) => result.unwrap().unwrap(),
            std::task::Poll::Pending => {
                panic!("acknowledged page is ready on the generated caller poll")
            }
        };
        assert_eq!(update.sequence, page.sequence);
        kit.runtime.shutdown_and_close().await.unwrap();
    }
}
