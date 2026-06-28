use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use sha2::{Digest, Sha256};

use cgka_traits::TransportEndpoint;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::{
    AppError, KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
    KIND_NOSTR_CONTACT_LIST, KIND_NOSTR_METADATA, MarmotApp, MarmotRelayPlane, blocking_app_task,
};

pub(crate) const DIRECTORY_SYNC_USER_BATCH_SIZE: usize = 200;

pub(crate) const DIRECTORY_SYNC_KINDS: &[u64] = &[
    KIND_NOSTR_METADATA,
    KIND_NOSTR_CONTACT_LIST,
    KIND_NIP65_RELAY_LIST,
    KIND_MARMOT_INBOX_RELAY_LIST,
    KIND_MARMOT_KEY_PACKAGE,
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectorySyncPlan {
    pub(crate) endpoints: Vec<TransportEndpoint>,
    pub(crate) watched_user_count: usize,
    pub(crate) batches: Vec<DirectorySyncBatch>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirectorySyncBatch {
    pub(crate) subscription_id: String,
    pub(crate) authors: Vec<String>,
    pub(crate) kinds: Vec<u64>,
    pub(crate) since: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectorySyncRunSummary {
    pub(crate) watched_user_count: usize,
    pub(crate) active_subscriptions: usize,
    pub(crate) subscriptions_created: usize,
    pub(crate) subscriptions_removed: usize,
}

#[derive(Clone)]
pub(crate) struct DirectorySyncHandle {
    commands: mpsc::Sender<DirectorySyncCommand>,
    abort: AbortHandle,
    rebuild_queued: Arc<AtomicBool>,
}

enum DirectorySyncCommand {
    Rebuild {
        respond: Option<oneshot::Sender<Result<DirectorySyncRunSummary, String>>>,
    },
    Shutdown,
}

impl DirectorySyncPlan {
    pub(crate) fn from_known_users(
        endpoints: Vec<TransportEndpoint>,
        account_ids: Vec<String>,
        since: Option<u64>,
    ) -> Self {
        Self::from_known_users_with_batch_size(
            endpoints,
            account_ids,
            since,
            DIRECTORY_SYNC_USER_BATCH_SIZE,
        )
    }

    fn from_known_users_with_batch_size(
        mut endpoints: Vec<TransportEndpoint>,
        mut account_ids: Vec<String>,
        since: Option<u64>,
        batch_size: usize,
    ) -> Self {
        endpoints.sort();
        endpoints.dedup();
        account_ids.sort();
        account_ids.dedup();

        let batch_size = batch_size.max(1);
        let batches = account_ids
            .chunks(batch_size)
            .enumerate()
            .map(|(index, authors)| {
                let authors = authors.to_vec();
                DirectorySyncBatch {
                    subscription_id: directory_subscription_id(index, &authors),
                    authors,
                    kinds: DIRECTORY_SYNC_KINDS.to_vec(),
                    since,
                }
            })
            .collect::<Vec<_>>();

        Self {
            endpoints,
            watched_user_count: account_ids.len(),
            batches,
        }
    }
}

impl DirectorySyncHandle {
    pub(crate) fn spawn(app: MarmotApp, relay_plane: MarmotRelayPlane) -> Self {
        let (commands, command_rx) = mpsc::channel(32);
        let directory_events = relay_plane.subscribe_directory_events();
        let rebuild_queued = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run_directory_sync_worker(
            app,
            relay_plane,
            command_rx,
            directory_events,
            rebuild_queued.clone(),
        ));
        let abort = task.abort_handle();
        Self {
            commands,
            abort,
            rebuild_queued,
        }
    }

    pub(crate) fn request_rebuild(&self) {
        if self.rebuild_queued.swap(true, Ordering::SeqCst) {
            return;
        }
        match self
            .commands
            .try_send(DirectorySyncCommand::Rebuild { respond: None })
        {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.rebuild_queued.store(false, Ordering::SeqCst);
            }
        }
    }

    pub(crate) async fn request_rebuild_and_wait(
        &self,
    ) -> Result<DirectorySyncRunSummary, AppError> {
        let (respond, response) = oneshot::channel();
        self.commands
            .send(DirectorySyncCommand::Rebuild {
                respond: Some(respond),
            })
            .await
            .map_err(|_| AppError::TransportClosed)?;
        response
            .await
            .map_err(|_| AppError::TransportClosed)?
            .map_err(AppError::RelayDirectory)
    }

    pub(crate) async fn shutdown(&self) {
        let _ = self.commands.send(DirectorySyncCommand::Shutdown).await;
        self.abort.abort();
    }
}

async fn run_directory_sync_worker(
    app: MarmotApp,
    relay_plane: MarmotRelayPlane,
    mut commands: mpsc::Receiver<DirectorySyncCommand>,
    mut directory_events: tokio::sync::broadcast::Receiver<
        crate::relay_plane::DirectoryRelayEventRecord,
    >,
    rebuild_queued: Arc<AtomicBool>,
) {
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(DirectorySyncCommand::Rebuild { respond }) => {
                        rebuild_queued.store(false, Ordering::SeqCst);
                        let result = run_directory_sync_once(app.clone(), relay_plane.clone()).await;
                        if let Some(respond) = respond {
                            let _ = respond.send(result.map_err(|err| err.to_string()));
                        }
                    }
                    Some(DirectorySyncCommand::Shutdown) | None => return,
                }
            }
            event = directory_events.recv() => {
                match event {
                    Ok(record) => {
                        let app = app.clone();
                        let _ = blocking_app_task(move || app.ingest_directory_relay_event(record)).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

async fn run_directory_sync_once(
    app: MarmotApp,
    relay_plane: MarmotRelayPlane,
) -> Result<DirectorySyncRunSummary, AppError> {
    let plan = blocking_app_task(move || app.directory_sync_plan()).await?;
    let watched_user_count = plan.watched_user_count;
    let subscriptions = relay_plane
        .sync_directory_user_subscriptions(plan)
        .await
        .map_err(AppError::RelayDirectory)?;
    Ok(DirectorySyncRunSummary {
        watched_user_count,
        active_subscriptions: subscriptions.active_subscriptions,
        subscriptions_created: subscriptions.subscriptions_created,
        subscriptions_removed: subscriptions.subscriptions_removed,
    })
}

fn directory_subscription_id(index: usize, authors: &[String]) -> String {
    let mut hasher = Sha256::new();
    for author in authors {
        hasher.update((author.len() as u64).to_be_bytes());
        hasher.update(author.as_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    format!("directory_users_{index}_{}", &digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_id(value: u8) -> String {
        format!("{value:064x}")
    }

    async fn wait_for_background_rebuild_flag_to_clear(handle: &DirectorySyncHandle) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while handle
                .rebuild_queued
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker should clear queued rebuild flag after dequeuing the rebuild command");
    }

    #[test]
    fn sync_plan_chunks_known_users_with_privacy_safe_ids() {
        let users = vec![account_id(3), account_id(1), account_id(2), account_id(1)];

        let plan = DirectorySyncPlan::from_known_users_with_batch_size(
            vec![
                TransportEndpoint("wss://relay.example".to_owned()),
                TransportEndpoint("wss://relay.example".to_owned()),
            ],
            users,
            Some(100),
            2,
        );

        assert_eq!(
            plan.endpoints,
            vec![TransportEndpoint("wss://relay.example".to_owned())]
        );
        assert_eq!(plan.watched_user_count, 3);
        assert_eq!(plan.batches.len(), 2);
        assert_eq!(plan.batches[0].authors, vec![account_id(1), account_id(2)]);
        assert_eq!(plan.batches[1].authors, vec![account_id(3)]);
        assert_eq!(plan.batches[0].kinds, DIRECTORY_SYNC_KINDS);
        assert_eq!(plan.batches[0].since, Some(100));
        assert!(!plan.batches[0].subscription_id.contains(&account_id(1)));
        assert_ne!(
            plan.batches[0].subscription_id,
            plan.batches[1].subscription_id
        );
    }

    #[tokio::test]
    async fn background_rebuild_requests_are_coalesced_until_worker_takes_command() {
        let (commands, mut rx) = mpsc::channel(32);
        let task = tokio::spawn(std::future::pending::<()>());
        let handle = DirectorySyncHandle {
            commands,
            abort: task.abort_handle(),
            rebuild_queued: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        handle.request_rebuild();
        handle.request_rebuild();

        assert!(matches!(
            rx.try_recv(),
            Ok(DirectorySyncCommand::Rebuild { respond: None })
        ));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        handle
            .rebuild_queued
            .store(false, std::sync::atomic::Ordering::SeqCst);
        handle.request_rebuild();
        assert!(matches!(
            rx.try_recv(),
            Ok(DirectorySyncCommand::Rebuild { respond: None })
        ));

        task.abort();
    }

    #[tokio::test]
    async fn worker_clears_background_rebuild_flag_when_dequeuing_command() {
        let dir = tempfile::tempdir().unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let relay_plane = MarmotRelayPlane::with_subscription_rebuild_lookback(
            std::time::Duration::from_secs(30),
        );
        let handle = DirectorySyncHandle::spawn(app, relay_plane);

        handle.request_rebuild();
        wait_for_background_rebuild_flag_to_clear(&handle).await;

        handle.request_rebuild();
        wait_for_background_rebuild_flag_to_clear(&handle).await;

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn full_rebuild_channel_coalesces_with_pending_foreground_rebuild() {
        let (commands, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        let (respond, _response) = oneshot::channel();
        commands
            .try_send(DirectorySyncCommand::Rebuild {
                respond: Some(respond),
            })
            .expect("foreground rebuild should fill the one-command channel");
        let handle = DirectorySyncHandle {
            commands,
            abort: task.abort_handle(),
            rebuild_queued: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        handle.request_rebuild();
        assert!(
            handle
                .rebuild_queued
                .load(std::sync::atomic::Ordering::SeqCst),
            "a full command channel should keep the coalescing flag set until an existing rebuild runs"
        );
        handle.request_rebuild();

        assert!(matches!(
            rx.try_recv(),
            Ok(DirectorySyncCommand::Rebuild { respond: Some(_) })
        ));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        task.abort();
    }
}
