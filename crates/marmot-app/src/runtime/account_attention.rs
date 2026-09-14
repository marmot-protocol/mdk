//! Independent account-switcher attention. Durable chat rows own all counters.
use super::event_routing::{chat_list_event_route, projection_update_from_event};
use super::{AccountManager, MarmotAppRuntime, blocking_app_task, wait_for_runtime_shutdown};
use crate::chat_presentation::signals::PresentationInvalidation;
use crate::{AppError, MarmotAppEvent};
use marmot_account::AccountSummary;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
pub use storage_sqlite::AccountAttentionTotal;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountAttentionUnavailable {
    Preparing,
    ReadFailed,
    Resetting,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountAttentionState {
    Ready(AccountAttentionTotal),
    Unavailable(AccountAttentionUnavailable),
}
/// An unavailable account stays present with no invented zero or stale totals.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountAttentionEntry {
    pub account_id_hex: String,
    pub state: AccountAttentionState,
}
impl std::fmt::Debug for AccountAttentionEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAttentionEntry")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
/// Complete replacement, ordered by stable account identity. Accounts are individually
/// coherent; this is not a cross-database transaction. Local and external signing
/// accounts are included while signed in, whether or not their worker is running.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountAttentionSnapshot {
    pub subscription_generation: String,
    pub sequence: u64,
    pub accounts: Vec<AccountAttentionEntry>,
}
impl std::fmt::Debug for AccountAttentionSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAttentionSnapshot")
            .field("sequence", &self.sequence)
            .field("accounts", &self.accounts.len())
            .finish_non_exhaustive()
    }
}
/// Owns only its aggregate cache and invalidation receivers, never a chat-list window.
/// Drop ends the actor; cancellation of recv does not consume its pending update.
pub struct RuntimeAccountAttentionSubscription {
    pub snapshot: AccountAttentionSnapshot,
    updates: watch::Receiver<Result<AccountAttentionSnapshot, Arc<AppError>>>,
    stopping: watch::Receiver<bool>,
}
impl RuntimeAccountAttentionSubscription {
    /// A catalog read failure is explicit at the stream level. Individual account
    /// failures appear in entries. Both retain a retry obligation without new traffic.
    pub async fn recv(&mut self) -> Result<Option<AccountAttentionSnapshot>, Arc<AppError>> {
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut self.stopping) => Ok(None),
            changed = self.updates.changed() => {
                if changed.is_err() { return Ok(None); }
                self.updates.borrow_and_update().clone().map(Some)
            }
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Account {
    summary: AccountSummary,
    resetting: bool,
}
type Catalog = BTreeMap<String, Account>;
type States = BTreeMap<String, AccountAttentionState>;

fn ensure_open(manager: &AccountManager) -> Result<(), AppError> {
    manager.shared.lifecycle().ensure_running()?;
    if manager.app.storage_closed.load(Ordering::Acquire) {
        return Err(AppError::RuntimeStopping);
    }
    Ok(())
}
async fn catalog(manager: &AccountManager) -> Result<Catalog, AppError> {
    let manager = manager.clone();
    blocking_app_task(move || {
        ensure_open(&manager)?;
        Ok(manager
            .app
            .account_home()
            .accounts_strict()?
            .into_iter()
            .filter(AccountSummary::is_active_signing)
            .map(|summary| {
                (
                    summary.account_id_hex.clone(),
                    Account {
                        resetting: manager.account_is_tearing_down(&summary.account_id_hex),
                        summary,
                    },
                )
            })
            .collect())
    })
    .await
}
struct AccountReads {
    states: States,
    progressed: BTreeSet<String>,
}
async fn read_accounts(
    manager: &AccountManager,
    accounts: Vec<Account>,
) -> Result<AccountReads, AppError> {
    let manager = manager.clone();
    blocking_app_task(move || {
        let mut values = AccountReads {
            states: States::new(),
            progressed: BTreeSet::new(),
        };
        for account in accounts {
            ensure_open(&manager)?;
            let mut progressed = false;
            let mut read = || -> Result<AccountAttentionState, AppError> {
                let app = &manager.app;
                // Use live teardown state, including when it changes after the catalog read.
                if manager.account_is_tearing_down(&account.summary.account_id_hex) {
                    return Ok(AccountAttentionState::Unavailable(
                        AccountAttentionUnavailable::Resetting,
                    ));
                }
                let current = app.account_home().account(&account.summary.label)?;
                if current != account.summary {
                    return Ok(AccountAttentionState::Unavailable(
                        AccountAttentionUnavailable::Resetting,
                    ));
                }
                if !manager.onboarding_worker_allowed(&current.label)? {
                    return Err(AppError::ChatPresentationNotReady);
                }
                app.ensure_account_state(&current.label)?;
                let storage = app.account_storage(&current.label)?;
                // One bounded upgrade/import batch. No selected presentation,
                // full-list warm, timeline DTOs, MLS session or network needed.
                progressed = crate::chat_presentation::maintenance::prepare_base_rows(
                    &storage,
                    &current.account_id_hex,
                )?;
                Ok(AccountAttentionState::Ready(
                    storage.account_attention_total()?,
                ))
            };
            let state = match read() {
                Ok(state) => state,
                Err(
                    AppError::ChatPresentationNotReady
                    | AppError::Storage(cgka_traits::storage::StorageError::NotFound),
                ) => AccountAttentionState::Unavailable(AccountAttentionUnavailable::Preparing),
                Err(AppError::AccountHome(marmot_account::AccountHomeError::UnknownAccount(_))) => {
                    AccountAttentionState::Unavailable(AccountAttentionUnavailable::Resetting)
                }
                Err(_) => {
                    AccountAttentionState::Unavailable(AccountAttentionUnavailable::ReadFailed)
                }
            };
            let state = if manager.account_is_tearing_down(&account.summary.account_id_hex) {
                AccountAttentionState::Unavailable(AccountAttentionUnavailable::Resetting)
            } else {
                state
            };
            if progressed {
                values
                    .progressed
                    .insert(account.summary.account_id_hex.clone());
            }
            values.states.insert(account.summary.account_id_hex, state);
        }
        Ok(values)
    })
    .await
}
fn entries(states: &States) -> Vec<AccountAttentionEntry> {
    states
        .iter()
        .map(|(id, state)| AccountAttentionEntry {
            account_id_hex: id.clone(),
            state: state.clone(),
        })
        .collect()
}
impl MarmotAppRuntime {
    /// Live effective account attention, independent of every chat-list subscription.
    pub async fn subscribe_account_attention(
        &self,
    ) -> Result<RuntimeAccountAttentionSubscription, AppError> {
        ensure_open(&self.accounts)?;
        // Attach all sources before reading catalog or any account database.
        let sources = Sources {
            events: self.events.subscribe(),
            presentation: self.accounts.app.presentation_signals.updates.subscribe(),
            resets: self
                .accounts
                .app
                .presentation_signals
                .account_resets
                .subscribe(),
            catalog: self.accounts.app.presentation_signals.subscribe_catalog(),
        };
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let (accounts, states) = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return Err(AppError::RuntimeStopping),
            initial = async {
                let accounts = catalog(&self.accounts).await?;
                let states = read_accounts(&self.accounts, accounts.values().cloned().collect()).await?.states;
                Ok::<_, AppError>((accounts, states))
            } => initial?,
        };
        let snapshot = AccountAttentionSnapshot {
            subscription_generation: hex::encode(rand::random::<[u8; 16]>()),
            sequence: 0,
            accounts: entries(&states),
        };
        let (updates, receiver) = watch::channel(Ok(snapshot.clone()));
        tokio::spawn(run(
            self.accounts.clone(),
            accounts,
            states,
            snapshot.clone(),
            sources,
            stopping.clone(),
            updates,
        ));
        Ok(RuntimeAccountAttentionSubscription {
            snapshot,
            updates: receiver,
            stopping,
        })
    }
}
#[derive(Default)]
struct Dirty {
    catalog: bool,
    all: bool,
    accounts: BTreeSet<String>,
}
struct Sources {
    events: broadcast::Receiver<MarmotAppEvent>,
    presentation: broadcast::Receiver<PresentationInvalidation>,
    resets: broadcast::Receiver<String>,
    catalog: watch::Receiver<()>,
}
impl Dirty {
    fn account(&mut self, id: &str, known: &Catalog) {
        if known.contains_key(id) {
            self.accounts.insert(id.to_owned());
        } else {
            self.catalog = true;
        }
    }
    fn label(&mut self, label: &str, known: &Catalog) {
        if let Some((id, _)) = known
            .iter()
            .find(|(_, account)| account.summary.label == label)
        {
            self.accounts.insert(id.clone());
        } else {
            self.catalog = true;
        }
    }
    fn event(&mut self, event: MarmotAppEvent, known: &Catalog) {
        if let Some(update) = projection_update_from_event(&event) {
            self.account(&update.account_id_hex, known);
        } else if let Some((id, _)) = chat_list_event_route(&event) {
            self.account(id, known);
        }
    }
    fn has_work(&self) -> bool {
        self.catalog || self.all || !self.accounts.is_empty()
    }
}
impl Sources {
    async fn wait(&mut self, known: &Catalog) -> Dirty {
        loop {
            let mut dirty = Dirty::default();
            tokio::select! {
                event = self.events.recv() => match event {
                    Ok(event) => dirty.event(event, known), Err(_) => { dirty.all = true; dirty.catalog = true; },
                },
                event = self.presentation.recv() => match event {
                    Ok(event) => dirty.label(&event.account_label, known), Err(_) => dirty.all = true,
                },
                event = self.resets.recv() => {
                    dirty.catalog = true;
                    match event { Ok(label) => dirty.label(&label, known), Err(_) => dirty.all = true, }
                },
                _ = self.catalog.changed() => dirty.catalog = true,
            }
            if dirty.has_work() {
                return dirty;
            }
        }
    }
    fn drain(&mut self, dirty: &mut Dirty, known: &Catalog) {
        // Drain only a bounded queued prefix BEFORE reads. Concurrent commits remain queued.
        for _ in 0..self.events.len().min(1024) {
            match self.events.try_recv() {
                Ok(event) => dirty.event(event, known),
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    dirty.all = true;
                    dirty.catalog = true;
                }
                Err(_) => break,
            }
        }
        for _ in 0..self.presentation.len().min(1024) {
            match self.presentation.try_recv() {
                Ok(event) => dirty.label(&event.account_label, known),
                Err(broadcast::error::TryRecvError::Lagged(_)) => dirty.all = true,
                Err(_) => break,
            }
        }
        for _ in 0..self.resets.len().min(1024) {
            dirty.catalog = true;
            match self.resets.try_recv() {
                Ok(label) => dirty.label(&label, known),
                Err(broadcast::error::TryRecvError::Lagged(_)) => dirty.all = true,
                Err(_) => break,
            }
        }
        if self.catalog.has_changed().unwrap_or(true) {
            self.catalog.borrow_and_update();
            dirty.catalog = true;
        }
    }
}
/// Retry policy for this local projection, independent for each unavailable account.
struct Retry {
    at: Instant,
    delay: Duration,
}
impl Retry {
    fn next(previous: Option<&Self>, progress_or_invalidation: bool) -> Self {
        let delay = if progress_or_invalidation {
            Duration::from_secs(1)
        } else {
            previous.map_or(Duration::from_secs(1), |r| {
                (r.delay * 2).min(Duration::from_secs(30))
            })
        };
        Self {
            at: Instant::now() + delay,
            delay,
        }
    }
}
async fn run(
    manager: AccountManager,
    mut known: Catalog,
    mut states: States,
    mut current: AccountAttentionSnapshot,
    mut sources: Sources,
    mut stopping: watch::Receiver<bool>,
    updates: watch::Sender<Result<AccountAttentionSnapshot, Arc<AppError>>>,
) {
    let mut refresh_retry: Option<Retry> = None;
    let mut retries: BTreeMap<_, _> = states
        .iter()
        .filter(|(_, state)| matches!(state, AccountAttentionState::Unavailable(_)))
        .map(|(id, _)| (id.clone(), Retry::next(None, false)))
        .collect();
    loop {
        if ensure_open(&manager).is_err() {
            return;
        }
        // Global read failure must recover the catalog first. Otherwise only due
        // accounts are retried; neither healthy accounts nor the catalog are polled.
        let deadline = refresh_retry
            .as_ref()
            .map(|r| r.at)
            .or_else(|| retries.values().map(|r| r.at).min());
        let mut dirty = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = updates.closed() => return,
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => Dirty::default(),
            dirty = sources.wait(&known) => dirty,
        };
        tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = updates.closed() => return,
            _ = tokio::time::sleep(Duration::from_millis(10)) => {},
        }
        sources.drain(&mut dirty, &known);
        let invalidated_catalog = dirty.catalog;
        let invalidated_all = dirty.all;
        let invalidated_accounts = dirty.accounts.clone();
        if let Some(retry) = &refresh_retry {
            if !dirty.catalog && retry.at > Instant::now() {
                // Full recovery below retains all invalidations received while
                // the catalog is unavailable, without retrying on unrelated traffic.
                continue;
            }
            dirty.catalog = true;
            dirty.all = true;
        } else {
            dirty.accounts.extend(
                retries
                    .iter()
                    .filter(|(_, r)| r.at <= Instant::now())
                    .map(|(id, _)| id.clone()),
            );
        }
        let refresh = async {
            if dirty.catalog {
                let next = catalog(&manager).await?;
                for (id, account) in &next {
                    if known.get(id) != Some(account)
                        || matches!(states.get(id), Some(AccountAttentionState::Unavailable(_)))
                    {
                        dirty.accounts.insert(id.clone());
                    }
                }
                states.retain(|id, _| next.contains_key(id));
                retries.retain(|id, _| next.contains_key(id));
                known = next;
            }
            let accounts = known
                .iter()
                .filter(|(id, _)| dirty.all || dirty.accounts.contains(*id))
                .map(|(_, a)| a.clone())
                .collect();
            let read = read_accounts(&manager, accounts).await?;
            for (id, state) in &read.states {
                if matches!(state, AccountAttentionState::Ready(_)) {
                    retries.remove(id);
                } else {
                    let reset = read.progressed.contains(id)
                        || invalidated_catalog
                        || invalidated_all
                        || invalidated_accounts.contains(id);
                    retries.insert(id.clone(), Retry::next(retries.get(id), reset));
                }
            }
            states.extend(read.states);
            Ok::<_, AppError>(())
        };
        let result = tokio::select! {
            biased;
            _ = wait_for_runtime_shutdown(&mut stopping) => return,
            _ = updates.closed() => return,
            result = refresh => result,
        };
        match result {
            Ok(()) => {
                let accounts = entries(&states);
                if refresh_retry.is_some() || accounts != current.accounts {
                    current.accounts = accounts;
                    current.sequence = current
                        .sequence
                        .checked_add(1)
                        .expect("summary sequence exhausted");
                    let _ = updates.send_replace(Ok(current.clone()));
                }
                refresh_retry = None;
            }
            Err(AppError::RuntimeStopping) => return,
            Err(error) => {
                if refresh_retry.is_none() {
                    let _ = updates.send_replace(Err(Arc::new(error)));
                }
                refresh_retry = Some(Retry::next(refresh_retry.as_ref(), invalidated_catalog));
            }
        }
    }
}
#[cfg(test)]
mod tests;
