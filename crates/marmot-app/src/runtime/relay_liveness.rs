use super::{MarmotAppRuntime, wait_for_runtime_shutdown};
use crate::{AppError, RelayLiveness, RelayLivenessStatus};
use cgka_traits::{MemberId, TransportAdapterError, TransportEndpoint};
use std::collections::BTreeMap;
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use transport_nostr::canonical_relay;

/// Latest account-scoped relay snapshots. Slow readers may skip intermediate states.
pub struct RuntimeRelayLivenessSubscription {
    pub snapshot: Vec<RelayLiveness>,
    updates: Mutex<mpsc::Receiver<Result<Vec<RelayLiveness>, AppError>>>,
    producer: tokio::task::JoinHandle<()>,
    stopping: watch::Receiver<bool>,
    closed: watch::Sender<bool>,
}

impl RuntimeRelayLivenessSubscription {
    pub async fn recv(&self) -> Result<Option<Vec<RelayLiveness>>, AppError> {
        let mut stopping = self.stopping.clone();
        let mut closed = self.closed.subscribe();
        if *closed.borrow() {
            return Ok(None);
        }
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => Ok(None),
            _ = closed.changed() => Ok(None),
            update = async { self.updates.lock().await.recv().await } => update.transpose(),
        }
    }

    /// Stop this observer without disconnecting the account's relays.
    pub fn close(&self) {
        self.closed.send_replace(true);
        self.producer.abort();
    }
}

impl Drop for RuntimeRelayLivenessSubscription {
    fn drop(&mut self) {
        self.producer.abort();
    }
}

impl MarmotAppRuntime {
    /// Configured relay URLs with the account's own pool state; performs no dialing.
    pub async fn account_relay_liveness(
        &self,
        account_ref: &str,
    ) -> Result<Vec<RelayLiveness>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let lists = self
            .accounts
            .app
            .account_relay_list_status(&account.label)?;
        let mut rows = BTreeMap::new();
        for url in lists
            .default_relays
            .into_iter()
            .chain(lists.bootstrap_relays)
            .chain(lists.nip65.relays)
            .chain(lists.nip65.read_relays)
            .chain(lists.nip65.write_relays)
            .chain(lists.inbox.relays)
        {
            let url = canonical_relay(&url);
            rows.entry(url.clone()).or_insert(RelayLiveness {
                url,
                status: RelayLivenessStatus::Unknown,
                last_attempt_unix: None,
                last_error: None,
            });
        }
        let account_id = MemberId::new(
            hex::decode(&account.account_id_hex).map_err(|_| AppError::InvalidPublicKey)?,
        );
        if let Some(client) = self
            .shared
            .relay_plane()
            .account_history_relay_client(&account_id)
            .await
        {
            for mut row in client.relay_liveness().await {
                row.url = canonical_relay(&row.url);
                if let Some(current) = rows.get_mut(&row.url) {
                    *current = row;
                }
            }
        }
        Ok(rows.into_values().collect())
    }

    /// Subscribe before reading, so a concurrent transport or list change is retained.
    pub async fn subscribe_relay_liveness(
        &self,
        account_ref: &str,
    ) -> Result<RuntimeRelayLivenessSubscription, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let mut changes = self.shared.relay_plane().relay_liveness_changes();
        let mut directory_changes = self
            .accounts
            .app
            .presentation_signals
            .profile_updates
            .subscribe();
        let stopping = self.shared.lifecycle().subscribe_shutdown();
        let snapshot = self.account_relay_liveness(account_ref).await?;
        let mut current = snapshot.clone();
        let runtime = self.clone();
        let mut producer_stopping = stopping.clone();
        let (tx, rx) = mpsc::channel(1);
        let producer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = wait_for_runtime_shutdown(&mut producer_stopping) => return,
                    _ = tx.closed() => return,
                    changed = async {
                        match &mut changes {
                            Some(changes) => changes.changed().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if changed.is_err() { return; }
                    }
                    changed = directory_changes.recv() => {
                        match changed {
                            Ok(account_id) if account_id != account.account_id_hex => continue,
                            Err(broadcast::error::RecvError::Closed) => return,
                            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        }
                    }
                }
                let update = runtime.account_relay_liveness(&account.label).await;
                if let Ok(rows) = &update {
                    if *rows == current {
                        continue;
                    }
                    current.clone_from(rows);
                }
                let terminal = update.is_err();
                tokio::select! {
                    biased;
                    _ = wait_for_runtime_shutdown(&mut producer_stopping) => return,
                    result = tx.send(update) => {
                        if result.is_err() || terminal { return; }
                    }
                }
            }
        });
        Ok(RuntimeRelayLivenessSubscription {
            snapshot,
            updates: Mutex::new(rx),
            producer,
            stopping,
            closed: watch::channel(false).0,
        })
    }

    /// Reconnect only a configured relay, never an arbitrary caller-supplied target.
    pub async fn reconnect_relay(
        &self,
        account_ref: &str,
        url: &str,
    ) -> Result<RelayLiveness, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let canonical = canonical_relay(url);
        if !self
            .account_relay_liveness(account_ref)
            .await?
            .iter()
            .any(|row| row.url == canonical)
        {
            return Err(TransportAdapterError::Subscription(
                "relay is not configured for this account".into(),
            )
            .into());
        }
        let account_id = MemberId::new(
            hex::decode(&account.account_id_hex).map_err(|_| AppError::InvalidPublicKey)?,
        );
        let mut row = self
            .shared
            .relay_plane()
            .reconnect_relay(&account_id, TransportEndpoint(url.to_owned()))
            .await?;
        row.url = canonical_relay(&row.url);
        Ok(row)
    }
}
