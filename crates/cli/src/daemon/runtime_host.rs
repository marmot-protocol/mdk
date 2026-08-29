//! App-runtime hosting glue: reconciliation, event bridge, and hosted command dispatch.

use super::*;
use crate::ImportNsec;

#[derive(Debug)]
pub(crate) struct DaemonState {
    pub(crate) pid: u32,
    pub(crate) started_at: u64,
    pub(crate) last_runtime_activity: Option<DaemonRuntimeActivityReport>,
}

#[derive(Default)]
pub(crate) struct AppRuntimeHost {
    pub(crate) owner: Option<OwnedAppRuntime>,
    pub(crate) bridge: Option<JoinHandle<()>>,
    pub(crate) stream_watch: StreamWatchWorkers,
}

/// The daemon's single owning application graph and the runtime derived from
/// it. Retaining both handles prevents hosted commands from constructing an
/// independently hydrated `MarmotApp` against the daemon-owned root.
#[derive(Clone)]
pub(crate) struct OwnedAppRuntime {
    pub(crate) app: marmot_app::MarmotApp,
    pub(crate) runtime: marmot_app::MarmotAppRuntime,
}

impl AppRuntimeHost {
    pub(crate) async fn abort_all(&mut self) {
        if let Some(owner) = &self.owner {
            owner.runtime.shutdown().await;
        }
        if let Some(handle) = self.bridge.take() {
            handle.abort();
        }
        self.stream_watch.abort_all();
        self.owner = None;
    }
}

#[derive(Default)]
pub(crate) struct DaemonWorkers {
    pub(crate) runtime: AppRuntimeHost,
    pub(crate) stream_compose: StreamComposeWorkers,
}

impl DaemonWorkers {
    pub(crate) async fn abort_all(&mut self) {
        self.runtime.abort_all().await;
        self.stream_compose.abort_all();
    }
}

#[derive(Clone, Debug)]
pub(crate) enum AppRuntimeRefresh {
    None,
    Reconcile,
    RestartSelected(Option<String>),
    CatchUpAll,
}

pub(crate) fn app_runtime_enabled(defaults: &DaemonDefaults) -> bool {
    defaults.relay.is_some()
}

/// Reconcile the app runtime under the workers lock and return the cloned
/// owning app/runtime graph so the caller can perform relay I/O WITHOUT holding
/// the lock. The lock is held only for the host-mutating reconcile (runtime
/// create / bridge spawn / account reconcile), matching the subscription
/// handlers and fixing the head-of-line blocking in #633. Returns `None` when
/// no runtime could be brought up (missing relay / open error).
pub(crate) async fn reconcile_and_clone_runtime(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &SharedDaemonWorkers,
) -> Option<OwnedAppRuntime> {
    let mut guard = workers.lock().await;
    reconcile_app_runtime(defaults, state, events, &mut guard.runtime).await;
    guard.runtime.owner.clone()
}

pub(crate) async fn handle_app_runtime_account_setup_request(
    cli: &Cli,
    import_nsec: &mut Option<crate::ImportNsec>,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &SharedDaemonWorkers,
) -> Option<CliOutput> {
    if !app_runtime_enabled(defaults) {
        return None;
    }
    let mut request = match app_runtime_account_setup_request(cli, import_nsec.as_ref()) {
        Ok(Some(request)) => request,
        Ok(None) => return None,
        Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
    };
    let Some(owner) = reconcile_and_clone_runtime(defaults, state, events, workers).await else {
        return Some(crate::command_output_result(
            cli.json,
            Err(crate::WnError::MissingRelay),
        ));
    };
    request.import_nsec = import_nsec.take().map(ImportNsec::into_inner);
    // create_or_import_account drives relay I/O through the cloned runtime handle (internally
    // synchronized), so it runs off the workers lock.
    let output = owner
        .runtime
        .create_or_import_account(request)
        .await
        .map_err(crate::commands::account::map_account_setup_error)
        .and_then(crate::commands::account::account_setup_command_output);
    Some(crate::command_output_result(cli.json, output))
}

/// Execute-path entry: reconcile under the lock, then dispatch the hosted command off the lock
/// against a cloned runtime handle (#633). This is the common `wn group|message|chats|…` path.
pub(crate) async fn handle_app_runtime_command_request(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &SharedDaemonWorkers,
) -> Option<CliOutput> {
    if !app_runtime_enabled(defaults) || !is_hosted_runtime_command(cli) {
        return None;
    }
    let Some(owner) = reconcile_and_clone_runtime(defaults, state, events, workers).await else {
        return Some(crate::command_output_result(
            cli.json,
            Err(crate::WnError::MissingRelay),
        ));
    };
    dispatch_hosted_runtime_command(cli, defaults, &owner.app, &owner.runtime).await
}

/// Host-based entry used by the stream-compose path (`run_hosted_stream_marker_cli_json`), which
/// already holds the workers lock and owns a `&mut AppRuntimeHost`. Reconciles in place and
/// dispatches against the host's runtime — no re-entrant lock (which would deadlock).
pub(crate) async fn handle_hosted_runtime_command_with_host(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    host: &mut AppRuntimeHost,
) -> Option<CliOutput> {
    if !app_runtime_enabled(defaults) || !is_hosted_runtime_command(cli) {
        return None;
    }
    reconcile_app_runtime(defaults, state, events, host).await;
    let Some(owner) = &host.owner else {
        return Some(crate::command_output_result(
            cli.json,
            Err(crate::WnError::MissingRelay),
        ));
    };
    dispatch_hosted_runtime_command(cli, defaults, &owner.app, &owner.runtime).await
}

/// Dispatch a hosted runtime command against an already-resolved runtime handle. Performs the
/// relay-backed command work and touches no shared daemon state, so callers run it off the
/// workers lock.
pub(crate) async fn dispatch_hosted_runtime_command(
    cli: &Cli,
    defaults: &DaemonDefaults,
    app: &marmot_app::MarmotApp,
    runtime: &marmot_app::MarmotAppRuntime,
) -> Option<CliOutput> {
    let secret_store = match crate::resolve_secret_store(defaults.secret_store) {
        Ok(secret_store) => secret_store,
        Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
    };
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        match crate::open_account_home(&defaults.home, secret_store, &keychain_service) {
            Ok(account_home) => account_home,
            Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
        };
    let output = match cli.command.clone() {
        crate::Command::Group { command } => {
            crate::commands::groups::group_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Chats { command } => {
            crate::commands::chats::chats_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Groups { command } => {
            crate::commands::groups::groups_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Message { command } | crate::Command::Messages { command } => {
            crate::commands::messages::message_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Stream { command } => {
            crate::commands::stream::stream_command_app_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Keys { command } => {
            crate::commands::key_package::key_package_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Follows { command } => {
            crate::commands::follows::follows_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
                cli.relay.clone(),
            )
            .await
        }
        crate::Command::Profile { command } => {
            crate::commands::profile::profile_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
                cli.relay.clone(),
            )
            .await
        }
        crate::Command::Relays { command } => {
            crate::commands::relays::relays_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
                cli.relay.clone(),
            )
            .await
        }
        crate::Command::Users { command } => {
            crate::commands::users::users_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Media { command } => {
            crate::commands::media::media_command_with_runtime(
                &account_home,
                app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Logout { pubkey } => {
            crate::commands::account::logout_command_with_runtime(runtime, pubkey).await
        }
        crate::Command::Sync => {
            let account = match crate::resolve_account(&account_home, cli.account.clone()) {
                Ok(account) => account,
                Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
            };
            if let Err(err) = crate::ensure_local_signing(&account) {
                return Some(crate::command_output_result(cli.json, Err(err)));
            }
            crate::commands::sync::sync_command_with_runtime(app, runtime, account).await
        }
        crate::Command::RelayStats => {
            crate::commands::relay_stats::relay_stats_command_with_runtime(runtime).await
        }
        _ => return None,
    };
    Some(crate::command_output_result(cli.json, output))
}

pub(crate) fn is_hosted_runtime_command(cli: &Cli) -> bool {
    match &cli.command {
        crate::Command::Group { .. } | crate::Command::Groups { .. } => true,
        crate::Command::Chats { command } => !matches!(
            command,
            crate::ChatsCommand::Subscribe | crate::ChatsCommand::SubscribeArchived
        ),
        crate::Command::Message { command } | crate::Command::Messages { command } => {
            !matches!(command, crate::MessageCommand::Subscribe { .. })
        }
        crate::Command::Stream { command } => matches!(
            command,
            crate::StreamCommand::Start { .. }
                | crate::StreamCommand::Finish { .. }
                | crate::StreamCommand::Watch { .. }
                | crate::StreamCommand::Send {
                    start_event_id: Some(_),
                    ..
                }
        ),
        crate::Command::Keys { .. }
        | crate::Command::Logout { .. }
        | crate::Command::Follows { .. }
        | crate::Command::Profile { .. }
        | crate::Command::Relays { .. }
        | crate::Command::RelayStats
        | crate::Command::Sync
        | crate::Command::Users { .. }
        | crate::Command::Media { .. } => true,
        _ => false,
    }
}

pub(crate) fn app_runtime_account_setup_request(
    cli: &Cli,
    import_nsec: Option<&crate::ImportNsec>,
) -> Result<Option<marmot_app::AccountSetupRequest>, crate::WnError> {
    match &cli.command {
        crate::Command::CreateIdentity => {
            if import_nsec.is_some() {
                return Err(crate::WnError::InvalidPublicKey);
            }
            if cli.daemon_default_account_relays.is_empty() {
                return Err(crate::WnError::MissingRelay);
            }
            Ok(Some(marmot_app::AccountSetupRequest {
                identity: None,
                import_nsec: None,
                default_relays: crate::relay_endpoints(cli.daemon_default_account_relays.clone())?,
                bootstrap_relays: crate::relay_endpoints(cli.daemon_discovery_relays.clone())?,
                discovery_relays: crate::relay_endpoints(cli.daemon_discovery_relays.clone())?,
                publish_missing_relay_lists: false,
                publish_initial_key_package: true,
            }))
        }
        crate::Command::Login {
            identity,
            nsec_stdin,
            ..
        } => {
            crate::validate_materialized_secret_identity("login", identity, *nsec_stdin)?;
            if identity.is_none() && import_nsec.is_none() {
                return Err(crate::WnError::MissingLoginIdentity);
            }
            if import_nsec.is_some() && cli.daemon_default_account_relays.is_empty() {
                return Err(crate::WnError::MissingRelay);
            }
            Ok(Some(marmot_app::AccountSetupRequest {
                identity: identity.clone(),
                import_nsec: None,
                default_relays: crate::relay_endpoints(cli.daemon_default_account_relays.clone())?,
                bootstrap_relays: crate::relay_endpoints(cli.daemon_discovery_relays.clone())?,
                discovery_relays: crate::relay_endpoints(cli.daemon_discovery_relays.clone())?,
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
            }))
        }
        crate::Command::Account {
            command:
                crate::AccountCommand::Create {
                    identity,
                    nsec_stdin,
                    default_relays,
                    bootstrap_relays,
                    publish_missing_relay_lists,
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Create {
                    identity,
                    nsec_stdin,
                    default_relays,
                    bootstrap_relays,
                    publish_missing_relay_lists,
                },
        } => {
            crate::validate_materialized_secret_identity("account create", identity, *nsec_stdin)?;
            Ok(Some(marmot_app::AccountSetupRequest {
                identity: identity.clone(),
                import_nsec: None,
                default_relays: crate::relay_endpoints(default_relays.clone())?,
                bootstrap_relays: crate::relay_endpoints(bootstrap_relays.clone())?,
                discovery_relays: crate::relay_endpoints(bootstrap_relays.clone())?,
                publish_missing_relay_lists: *publish_missing_relay_lists,
                publish_initial_key_package: false,
            }))
        }
        _ => Ok(None),
    }
}

pub(crate) fn app_runtime_refresh_after_execute(cli: &Cli) -> AppRuntimeRefresh {
    match &cli.command {
        crate::Command::CreateIdentity | crate::Command::Login { .. } => {
            AppRuntimeRefresh::Reconcile
        }
        crate::Command::Account {
            command: crate::AccountCommand::Create { .. },
        } => AppRuntimeRefresh::Reconcile,
        crate::Command::Group { .. } | crate::Command::Groups { .. } => {
            AppRuntimeRefresh::CatchUpAll
        }
        crate::Command::Message { .. }
        | crate::Command::Messages { .. }
        | crate::Command::Stream { .. } => AppRuntimeRefresh::CatchUpAll,
        crate::Command::Sync => AppRuntimeRefresh::RestartSelected(cli.account.clone()),
        _ => AppRuntimeRefresh::None,
    }
}

pub(crate) async fn refresh_app_runtime(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &SharedDaemonWorkers,
    refresh: AppRuntimeRefresh,
) {
    if !app_runtime_enabled(defaults) {
        return;
    }
    match refresh {
        AppRuntimeRefresh::None => {}
        AppRuntimeRefresh::Reconcile => {
            let _ = reconcile_and_clone_runtime(defaults, state, events, workers).await;
        }
        AppRuntimeRefresh::RestartSelected(selector) => {
            // Bring the runtime up under the lock if it is missing (matching the original
            // "reconcile + return, no restart" for a cold host); otherwise clone the handle and
            // restart off the lock.
            let runtime = {
                let mut guard = workers.lock().await;
                if guard.runtime.owner.is_none() {
                    reconcile_app_runtime(
                        defaults,
                        state.clone(),
                        events.clone(),
                        &mut guard.runtime,
                    )
                    .await;
                    None
                } else {
                    guard
                        .runtime
                        .owner
                        .as_ref()
                        .map(|owner| owner.runtime.clone())
                }
            };
            let Some(runtime) = runtime else {
                return;
            };
            if let Some(account_id) = resolve_app_runtime_account_id(defaults, selector).await {
                if let Err(err) = runtime.restart_account(&account_id).await {
                    record_runtime_activity_error(&state, err.to_string());
                }
            } else {
                // Account not resolvable → reconcile as the original fallback did.
                let mut guard = workers.lock().await;
                reconcile_app_runtime(defaults, state.clone(), events.clone(), &mut guard.runtime)
                    .await;
            }
        }
        AppRuntimeRefresh::CatchUpAll => {
            let runtime =
                reconcile_and_clone_runtime(defaults, state.clone(), events, workers).await;
            if let Some(owner) = runtime
                && let Err(err) = owner.runtime.catch_up_accounts().await
            {
                record_runtime_activity_error(&state, err.to_string());
            }
        }
    }
}

pub(crate) async fn resolve_app_runtime_account_id(
    defaults: &DaemonDefaults,
    selector: Option<String>,
) -> Option<String> {
    let secret_store = crate::resolve_secret_store(defaults.secret_store).ok()?;
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        crate::open_account_home(&defaults.home, secret_store, &keychain_service).ok()?;
    crate::resolve_account(&account_home, selector)
        .ok()
        .map(|account| account.account_id_hex)
}

pub(crate) async fn reconcile_app_runtime(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    host: &mut AppRuntimeHost,
) {
    if !app_runtime_enabled(defaults) {
        return;
    }

    if host.owner.is_none() {
        let owner = match open_app_runtime(defaults) {
            Ok(owner) => owner,
            Err(err) => {
                record_runtime_activity_error(&state, err.to_string());
                return;
            }
        };
        let receiver = owner.runtime.subscribe();
        if let Err(err) = owner.runtime.start().await {
            record_runtime_activity_error(&state, err.to_string());
            return;
        }
        host.bridge = Some(spawn_app_runtime_bridge(
            defaults.clone(),
            state.clone(),
            events.clone(),
            host.stream_watch.clone(),
            owner.app.clone(),
            owner.runtime.clone(),
            owner.runtime.shared_services().agent_streams(),
            receiver,
        ));
        host.owner = Some(owner);
        return;
    }

    if let Some(owner) = &host.owner {
        if let Err(err) = owner.runtime.reconcile_accounts().await {
            record_runtime_activity_error(&state, err.to_string());
        }
        if host
            .bridge
            .as_ref()
            .is_none_or(|handle| handle.is_finished())
        {
            host.bridge = Some(spawn_app_runtime_bridge(
                defaults.clone(),
                state,
                events,
                host.stream_watch.clone(),
                owner.app.clone(),
                owner.runtime.clone(),
                owner.runtime.shared_services().agent_streams(),
                owner.runtime.subscribe(),
            ));
        }
    }
}

pub(crate) fn open_app_runtime(
    defaults: &DaemonDefaults,
) -> Result<OwnedAppRuntime, crate::WnError> {
    let secret_store = crate::resolve_secret_store(defaults.secret_store)?;
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home = crate::open_account_home(&defaults.home, secret_store, &keychain_service)?;
    let app = crate::exclusive_app_for(
        defaults.home.clone(),
        defaults.relay.clone(),
        defaults.discovery_relays.clone(),
        account_home,
    )?;
    let runtime = app.runtime();
    Ok(OwnedAppRuntime { app, runtime })
}

pub(crate) fn spawn_app_runtime_bridge(
    defaults: DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    stream_workers: StreamWatchWorkers,
    app: marmot_app::MarmotApp,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
    mut receiver: broadcast::Receiver<marmot_app::MarmotAppEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    handle_app_runtime_event(
                        &defaults,
                        state.clone(),
                        events.clone(),
                        stream_workers.clone(),
                        app.clone(),
                        runtime.clone(),
                        stream_manager.clone(),
                        event,
                    )
                    .await;
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    record_runtime_activity_error(
                        &state,
                        format!("app runtime event stream lagged: {count} updates dropped"),
                    );
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

pub(crate) async fn handle_app_runtime_event(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    stream_workers: StreamWatchWorkers,
    app: marmot_app::MarmotApp,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
    event: marmot_app::MarmotAppEvent,
) {
    let started_at = unix_now();
    match event {
        marmot_app::MarmotAppEvent::GroupJoined { group_id, .. } => {
            let summary = marmot_app::SyncSummary {
                joined_groups: vec![group_id],
                ..marmot_app::SyncSummary::default()
            };
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::GroupStateUpdated { .. } => {}
        marmot_app::MarmotAppEvent::ProjectionUpdated(_) => {}
        marmot_app::MarmotAppEvent::MessageReceived(message) => {
            // Raw message updates keep kind-1200 starts separate as
            // `AgentStreamStarted`; materialized timeline subscriptions include
            // those starts as timeline rows.
            events.publish_message(message_stream_response(
                runtime_message_json(
                    &message.message,
                    &message.account_id_hex,
                    &message.account_label,
                ),
                "MessageReceived",
            ));
            let summary = marmot_app::SyncSummary {
                messages: vec![message.message],
                ..marmot_app::SyncSummary::default()
            };
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::AgentStreamStarted(message) => {
            events.publish_message(message_stream_response(
                runtime_message_json(
                    &message.message,
                    &message.account_id_hex,
                    &message.account_label,
                ),
                "AgentStreamStarted",
            ));
            let summary = marmot_app::SyncSummary {
                messages: vec![message.message],
                ..marmot_app::SyncSummary::default()
            };
            auto_watch_agent_stream_starts(
                defaults,
                &message.account_id_hex,
                &summary,
                stream_workers,
                app,
                runtime,
                stream_manager,
            )
            .await;
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::GroupEvent(group_event) => {
            let summary = marmot_app::SyncSummary {
                events: vec![group_event.event],
                ..marmot_app::SyncSummary::default()
            };
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::AccountError(error) => {
            record_runtime_activity_error(&state, account_error_activity_message(&error));
        }
        // A confirmed create/invite queued a welcome for re-delivery (mdk#352).
        // The durable record + `redeliver_welcome` handle the repair; this
        // daemon activity path has no runtime-summary shape to record for it.
        marmot_app::MarmotAppEvent::WelcomeDeliveryPending { .. } => {}
        // A group's epoch-gap backfill kept arming without catching up. Like the
        // welcome-repair signal above, this reports a repair need rather than
        // runtime activity, so there is no summary shape to record: it reaches
        // operators through the runtime event stream and the group's forensic
        // `epoch_stall_backfill_escalated` row.
        marmot_app::MarmotAppEvent::EpochStallEscalated { .. } => {}
    }
}

pub(crate) async fn auto_watch_agent_stream_starts(
    defaults: &DaemonDefaults,
    account_id: &str,
    summary: &marmot_app::SyncSummary,
    stream_workers: StreamWatchWorkers,
    app: marmot_app::MarmotApp,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
) {
    let secret_store = match crate::resolve_secret_store(defaults.secret_store) {
        Ok(secret_store) => secret_store,
        Err(_) => return,
    };
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        match crate::open_account_home(&defaults.home, secret_store, &keychain_service) {
            Ok(account_home) => account_home,
            Err(_) => return,
        };
    for message in &summary.messages {
        let Some(start) = marmot_app::StreamStartView::from_event(message.kind, &message.tags)
        else {
            continue;
        };
        if start.route != "quic" {
            continue;
        }
        let group_id = hex::encode(message.group_id.as_slice());
        // Daemon auto-watch is triggered by sender-controlled stream-start
        // candidates, so it must never select no-cert-verification trust or
        // resolve to local/private endpoints. Local trust is only ever chosen
        // via an explicit local user `--insecure-local`, never here.
        let insecure_local = false;
        let stream_id = start.stream_id_hex;
        if stream_manager.watch_exists(Some(account_id), &group_id, Some(stream_id.as_str())) {
            continue;
        }

        let cli = Cli {
            home: Some(defaults.home.clone()),
            socket: None,
            relay: defaults.relay.clone(),
            daemon_discovery_relays: defaults.discovery_relays.clone(),
            daemon_default_account_relays: defaults.default_account_relays.clone(),
            secret_store: defaults.secret_store,
            keychain_service: defaults.keychain_service.clone(),
            account: Some(account_id.to_owned()),
            json: true,
            command: crate::Command::Stream {
                command: crate::StreamCommand::Watch {
                    group: group_id,
                    stream_id: Some(stream_id),
                    server_cert_der_hex: None,
                    insecure_local,
                    background: false,
                },
            },
        };
        if let Ok((report, handle)) = spawn_stream_watch(
            cli,
            account_home.clone(),
            app.clone(),
            runtime.clone(),
            stream_manager.clone(),
        ) {
            stream_workers.replace(report.watch_id, handle);
        }
    }
}

pub(crate) fn empty_runtime_activity_report(started_at: u64) -> DaemonRuntimeActivityReport {
    DaemonRuntimeActivityReport {
        started_at,
        finished_at: started_at,
        accounts: 0,
        events: 0,
        joined_groups: 0,
        messages: 0,
        directory_accounts: 0,
        directory_follows: 0,
        directory_profiles: 0,
        errors: Vec::new(),
    }
}

pub(crate) fn runtime_activity_report_from_summary(
    started_at: u64,
    accounts: usize,
    summary: &marmot_app::SyncSummary,
) -> DaemonRuntimeActivityReport {
    let mut report = empty_runtime_activity_report(started_at);
    report.finished_at = unix_now();
    report.accounts = accounts;
    report.events = summary.events.len();
    report.joined_groups = summary.joined_groups.len();
    report.messages = summary.messages.len();
    report
}

/// Builds the diagnostic string recorded for a runtime account error.
///
/// Privacy: the result is persisted into `DaemonRuntimeActivityReport.errors`
/// and exposed via `wn daemon status --json` / the TUI, so it must never carry
/// the account id or label — only the upstream (already id-free) error message.
pub(crate) fn account_error_activity_message(error: &marmot_app::RuntimeAccountError) -> String {
    format!("app runtime account error: {}", error.message)
}

pub(crate) fn record_runtime_activity_error(state: &Arc<Mutex<DaemonState>>, error: String) {
    let started_at = unix_now();
    let mut report = empty_runtime_activity_report(started_at);
    report.finished_at = unix_now();
    report.errors.push(error);
    record_runtime_activity_report(state, report);
}

pub(crate) fn record_runtime_activity_report(
    state: &Arc<Mutex<DaemonState>>,
    report: DaemonRuntimeActivityReport,
) {
    if let Ok(mut state) = state.lock() {
        state.last_runtime_activity = Some(report);
    }
}

pub(crate) fn apply_defaults(cli: &mut Cli, defaults: &DaemonDefaults) {
    cli.home = Some(defaults.home.clone());
    cli.relay = defaults.relay.clone();
    cli.daemon_discovery_relays = defaults.discovery_relays.clone();
    cli.daemon_default_account_relays = defaults.default_account_relays.clone();
    apply_default_account_relays(cli, defaults);
    cli.secret_store = defaults.secret_store;
    cli.keychain_service = defaults.keychain_service.clone();
    cli.socket = None;
}

pub(crate) fn apply_default_account_relays(cli: &mut Cli, defaults: &DaemonDefaults) {
    let default_relays = defaults.default_account_relays.clone();
    let bootstrap_relays = if defaults.discovery_relays.is_empty() {
        default_relays.clone()
    } else {
        defaults.discovery_relays.clone()
    };
    match &mut cli.command {
        crate::Command::Account {
            command:
                crate::AccountCommand::Create {
                    default_relays: command_default_relays,
                    bootstrap_relays: command_bootstrap_relays,
                    ..
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Create {
                    default_relays: command_default_relays,
                    bootstrap_relays: command_bootstrap_relays,
                    ..
                },
        } => {
            if command_default_relays.is_empty() {
                *command_default_relays = default_relays;
            }
            if command_bootstrap_relays.is_empty() {
                *command_bootstrap_relays = bootstrap_relays;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cli(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv.iter().copied()).expect("argv parses")
    }

    /// This predicate decides whether the daemon answers a command with its
    /// live app runtime or falls through to a runtime-less local run. Getting
    /// it wrong is silent: the command still succeeds, just without whatever
    /// the runtime knows.
    #[test]
    fn user_search_is_answered_with_the_daemons_runtime() {
        // Group co-members are live MLS state only the runtime holds, so a
        // search dispatched without it silently loses them.
        assert!(is_hosted_runtime_command(&cli(&[
            "wn", "users", "search", "alice"
        ])));
    }

    #[test]
    fn user_show_is_answered_with_the_daemons_runtime() {
        assert!(is_hosted_runtime_command(&cli(&[
            "wn",
            "users",
            "show",
            &"aa".repeat(32)
        ])));
    }

    /// Commands that touch no runtime state must keep falling through, so the
    /// daemon does not reconcile accounts to answer a local question.
    #[test]
    fn purely_local_commands_are_not_hosted() {
        assert!(!is_hosted_runtime_command(&cli(&[
            "wn", "settings", "show"
        ])));
        assert!(!is_hosted_runtime_command(&cli(&["wn", "whoami"])));
    }

    #[test]
    fn sync_is_answered_by_the_daemons_account_worker() {
        assert!(is_hosted_runtime_command(&cli(&["wn", "sync"])));
    }

    #[test]
    fn account_create_does_not_force_initial_key_package_publication() {
        let cli = cli(&["wn", "account", "create"]);
        let request = app_runtime_account_setup_request(&cli, None)
            .expect("account create request is valid")
            .expect("account create builds a setup request");

        // Legacy `account create` is the compatibility/repair surface.
        // `create-identity` and `login` publish the initial KeyPackage.
        assert!(!request.publish_initial_key_package);
    }

    /// Streaming subscriptions have their own socket entry points; routing them
    /// through the one-shot hosted path would answer once and hang up.
    #[test]
    fn streaming_subscriptions_are_not_hosted() {
        assert!(!is_hosted_runtime_command(&cli(&[
            "wn",
            "chats",
            "subscribe"
        ])));
    }
}
