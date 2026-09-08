//! Account-owned transport receipt access. Views cannot outlive an exclusive
//! client borrow or overlap an engine step on that client.

use std::collections::HashSet;

use storage_sqlite::{
    SqliteAccountStorage, TransportReconciliationInventory, TransportReconciliationRoute,
};

use super::AppClient;
use crate::{AppError, remember_seen_event};

pub(crate) struct SynchronizedTransportReceipts<'a> {
    client: &'a mut AppClient,
    storage: SqliteAccountStorage,
    released: HashSet<String>,
}

/// Production membership reads are available only through the synchronized
/// view. Test accessors inspect pre/post-error cache state without repairing it.
pub(crate) struct SeenEventIndex(HashSet<String>);

impl FromIterator<String> for SeenEventIndex {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
impl SeenEventIndex {
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.0.contains(id)
    }
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    pub(crate) fn insert(&mut self, id: String) -> bool {
        self.0.insert(id)
    }
}

impl AppClient {
    pub(crate) fn remember_seen_event(&mut self, event_id: String) {
        if remember_seen_event(&mut self.seen_events_index.0, &mut self.state, event_id) {
            self.pending_seen_event_count = self
                .pending_seen_event_count
                .saturating_add(1)
                .min(self.state.seen_events.len());
        }
    }

    /// Repair durable release evidence independently of lossy engine effects.
    fn synchronize_released_transport_receipts(
        &mut self,
        storage: &SqliteAccountStorage,
    ) -> Result<HashSet<String>, AppError> {
        let released = storage.consume_released_transport_receipts()?;
        self.released_backfill_reload_pending |= !released.is_empty();
        if !self.released_backfill_reload_pending {
            return Ok(HashSet::new());
        }
        let released = released
            .into_iter()
            .map(|id| hex::encode(id.as_slice()))
            .collect::<HashSet<_>>();
        if !released.is_empty() {
            // No await or fallible operation between acknowledging the durable
            // journal and removing its ids from memory. Never checkpoint stale ids
            // back over the transactional deletion, including unsaved ring entries.
            let unsaved_start = self
                .state
                .seen_events
                .len()
                .saturating_sub(self.pending_seen_event_count);
            self.pending_seen_event_count = self.state.seen_events[unsaved_start..]
                .iter()
                .filter(|id| !released.contains(*id))
                .count();
            self.seen_events_index.0.retain(|id| !released.contains(id));
            self.state.seen_events.retain(|id| !released.contains(id));
            tracing::info!(
                target: "marmot_app::relay_plane",
                method = "synchronize_released_transport_receipts",
                released_count = released.len(),
                "retired released transport receipt claims and restored replay eligibility"
            );
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_released_backfill_reload) {
            return Err(cgka_traits::storage::StorageError::Busy(
                "injected released backfill intent read failure".into(),
            )
            .into());
        }
        self.restore_persisted_epoch_backfill_intents(storage.pending_epoch_backfill_intents()?);
        self.released_backfill_reload_pending = false;
        Ok(released)
    }

    #[cfg(test)]
    pub(crate) fn reconcile_released_transport_receipts(
        &mut self,
    ) -> Result<Vec<String>, AppError> {
        Ok(self.transport_receipts()?.released.into_iter().collect())
    }

    /// Synchronize at the account's exclusive mutation boundary. Storage-only
    /// readers must not consume this client's journal behind its active cache.
    /// A failed reload returns no view, but already-acknowledged IDs have been
    /// invalidated synchronously and reload remains armed for this same client.
    pub(crate) fn transport_receipts(
        &mut self,
    ) -> Result<SynchronizedTransportReceipts<'_>, AppError> {
        let storage = self.app.account_storage(&self.state.label)?;
        let released = self.synchronize_released_transport_receipts(&storage)?;
        Ok(SynchronizedTransportReceipts {
            client: self,
            storage,
            released,
        })
    }
}

impl<'a> SynchronizedTransportReceipts<'a> {
    /// Consume the receipt decision before entering an engine step. The SDK
    /// duplicate check and admission share this borrow without a second query.
    pub(super) fn into_client(self) -> &'a mut AppClient {
        self.client
    }

    pub(crate) fn was_released(&self, event_id: &str) -> bool {
        self.released.contains(event_id)
    }

    pub(crate) fn contains(&self, event_id: &str) -> bool {
        self.client.seen_events_index.0.contains(event_id)
    }

    pub(crate) fn inventory(
        &self,
        route: &TransportReconciliationRoute,
        until: u64,
    ) -> Result<TransportReconciliationInventory, AppError> {
        Ok(self
            .storage
            .transport_reconciliation_inventory(route, until)?)
    }

    pub(crate) fn pending_seen_events(&self) -> Vec<String> {
        let start = self
            .client
            .state
            .seen_events
            .len()
            .saturating_sub(self.client.pending_seen_event_count);
        self.client.state.seen_events[start..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MarmotApp, tests::ScriptedPushRelayClient};
    use cgka_traits::storage::MessageStorage;
    use cgka_traits::{EpochId, MessageId, MessageRecord, MessageState};
    use marmot_account::AccountHome;
    use std::sync::Arc;

    #[tokio::test]
    async fn receipt_access_retires_lost_releases_without_caller_reconciliation() {
        for (boundary, fail_reload) in [
            ("duplicate", false),
            ("inventory", false),
            ("checkpoint", false),
            ("duplicate", true),
            ("inventory", true),
            ("checkpoint", true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let app = MarmotApp::with_relay(dir.path(), "wss://receipts.example")
                .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
            let mut client = app.client("alice").await.unwrap();
            let group = client.create_group("receipt boundary", &[]).await.unwrap();
            let storage = app.account_storage("alice").unwrap();
            let route = TransportReconciliationRoute::Group(
                hex::decode(
                    app.group("alice", &hex::encode(group.as_slice()))
                        .unwrap()
                        .unwrap()
                        .nostr_routing
                        .nostr_group_id_hex,
                )
                .unwrap()
                .try_into()
                .unwrap(),
            );
            let item = storage_sqlite::TransportReconciliationItem {
                event_id: [0xfd; 32],
                created_at: crate::unix_now_seconds(),
            };
            let raw = MessageRecord {
                id: MessageId::new(vec![0xfd; 32]),
                group_id: group,
                epoch: EpochId(0),
                state: MessageState::PeelDeferred,
                payload: Vec::new(),
                deferred_peel: None,
            };
            let id = hex::encode(raw.id.as_slice());
            client.remember_seen_event(id.clone());
            client
                .save_state_with_pending_local_group_deletion_frontier_clears()
                .unwrap();
            client.pending_seen_event_count = client.state.seen_events.len();
            storage.put_message(&raw).unwrap();
            storage.release_message_for_replay(&raw).unwrap();
            // Simulate an intervening stale inventory checkpoint. Consuming the
            // durable journal must revoke it together with the active cache.
            storage
                .record_transport_reconciliation_item(&route, &item)
                .unwrap();
            assert!(
                storage
                    .transport_reconciliation_inventory(&route, item.created_at)
                    .unwrap()
                    .items
                    .contains(&item)
            );
            // No effect observation or explicit reconcile between release and
            // accessing receipts, including an unsaved checkpoint tail.
            if fail_reload {
                client.fail_next_released_backfill_reload = true;
                assert!(matches!(
                    client.transport_receipts(),
                    Err(AppError::Storage(cgka_traits::storage::StorageError::Busy(
                        _
                    )))
                ));
                assert!(!client.seen_events_index.contains(&id));
                assert!(!client.state.seen_events.contains(&id));
                assert!(client.released_backfill_reload_pending);
                assert!(
                    storage
                        .consume_released_transport_receipts()
                        .unwrap()
                        .is_empty()
                );
            }
            // After a reload error this retries on the same client with an
            // already-acknowledged journal; it must still restore backfill.
            let receipts = client.transport_receipts().unwrap();
            match boundary {
                "duplicate" => assert!(!receipts.contains(&id)),
                "inventory" => {
                    assert!(
                        !receipts
                            .inventory(&route, item.created_at)
                            .unwrap()
                            .items
                            .contains(&item)
                    );
                    assert!(!receipts.contains(&id));
                }
                "checkpoint" => assert!(!receipts.pending_seen_events().contains(&id)),
                _ => unreachable!(),
            }
            assert!(!client.state.seen_events.contains(&id));
            assert!(client.has_pending_epoch_backfill());
            assert!(!client.released_backfill_reload_pending);
            client
                .save_state_with_pending_local_group_deletion_frontier_clears()
                .unwrap();
            assert!(!app.load_state("alice").unwrap().seen_events.contains(&id));
        }
    }

    #[tokio::test]
    async fn receipt_access_propagates_closed_storage() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://receipts.example")
            .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        app.account_storage("alice").unwrap().close().unwrap();
        assert!(client.transport_receipts().is_err());
        assert!(
            client
                .save_state_with_pending_local_group_deletion_frontier_clears()
                .is_err()
        );
    }

    #[tokio::test]
    async fn receipt_empty_journal_access_keeps_cache_and_reload_idle() {
        for ring_size in [0, crate::MAX_SEEN_EVENT_IDS] {
            let dir = tempfile::tempdir().unwrap();
            AccountHome::open(dir.path())
                .create_account("alice")
                .unwrap();
            let app = MarmotApp::with_relay(dir.path(), "wss://receipts.example")
                .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
            let mut client = app.client("alice").await.unwrap();
            for id in 0..ring_size {
                client.remember_seen_event(format!("{id:064x}"));
            }
            client.pending_seen_event_count = 0;
            client.fail_next_released_backfill_reload = true;
            let ring_ptr = client.state.seen_events.as_ptr();
            let index_capacity = client.seen_events_index.0.capacity();
            for _ in 0..1024 {
                let receipts = client.transport_receipts().unwrap();
                std::hint::black_box(receipts.contains("absent"));
                assert!(receipts.pending_seen_events().is_empty());
                assert!(!receipts.was_released("absent"));
            }
            assert_eq!(client.state.seen_events.as_ptr(), ring_ptr);
            assert_eq!(client.seen_events_index.0.capacity(), index_capacity);
            assert_eq!(client.seen_events_index.len(), ring_size);
            assert!(client.fail_next_released_backfill_reload);
        }
    }
}
