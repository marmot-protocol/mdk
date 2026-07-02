//! Streaming subscription handlers (messages, chats, group state).

use super::*;

pub(crate) async fn handle_messages_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    _state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if is_timeline_messages_subscribe(&cli) {
        return handle_timeline_messages_subscription(stream, defaults, runtime, cli).await;
    }
    let (group_id, limit) = match messages_subscribe_args(&cli) {
        Ok(args) => args,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let stream_manager = runtime.shared_services().agent_streams();
    let mut runtime_subscription = match runtime
        .subscribe_messages(
            &account_ref,
            marmot_app::AppMessageQuery {
                group_id_hex: group_id.clone(),
                limit,
            },
        )
        .await
    {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let mut seen_messages =
        BoundedMessageSubscriptionIds::with_limit(MESSAGE_SUBSCRIPTION_DEDUP_LIMIT);
    let mut seen_stream_previews =
        BoundedMessageSubscriptionIds::with_limit(MESSAGE_SUBSCRIPTION_DEDUP_LIMIT);
    let mut event_rx = events.subscribe_messages();
    let mut stream_rx = stream_manager.subscribe();
    if !write_stream_response(
        stream,
        &DaemonStreamResponse::ok(serde_json::json!({
            "trigger": "SubscriptionReady",
            "type": "subscription_ready",
            "group_id": group_id.clone(),
        })),
    )
    .await
    {
        return Ok(());
    }

    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    for message in runtime_subscription.snapshot.drain(..) {
        if !message.message_id_hex.is_empty() {
            seen_messages.insert(message.message_id_hex.clone());
        }
        let display_name = display_names_by_sender
            .entry(message.sender.clone())
            .or_insert_with(|| runtime.display_name_for_account_id(&message.sender))
            .clone();
        let response = message_stream_response(
            app_message_record_json(message, display_name),
            "InitialMessage",
        );
        if !write_stream_response(stream, &response).await {
            return Ok(());
        }
    }

    for response in events.recent_messages() {
        if !write_message_subscription_event(
            stream,
            response,
            group_id.as_deref(),
            &account_ref,
            &mut seen_messages,
            &mut seen_stream_previews,
        )
        .await
        {
            return Ok(());
        }
    }

    for update in stream_manager.recent_updates() {
        let response = agent_stream_update_response(update, false);
        if !write_message_subscription_event(
            stream,
            response,
            group_id.as_deref(),
            &account_ref,
            &mut seen_messages,
            &mut seen_stream_previews,
        )
        .await
        {
            return Ok(());
        }
    }

    if let Some(group_id) = group_id.as_deref() {
        for preview in stream_manager.previews_for_group(Some(&account_ref), group_id) {
            let preview =
                serde_json::to_value(preview).expect("stream preview serialization cannot fail");
            let fingerprint = stream_preview_fingerprint(&preview);
            if !seen_stream_previews.insert(fingerprint) {
                continue;
            }
            let response = stream_preview_response(preview, true);
            if !write_stream_response(stream, &response).await {
                return Ok(());
            }
        }
    }

    loop {
        tokio::select! {
            // Stream-start messages are published before their preview updates; keep that
            // ordering stable when both broadcast channels are ready in the same poll.
            biased;

            update = runtime_subscription.recv() => {
                let Some(update) = update else {
                    return Ok(());
                };
                let response = runtime_message_update_stream_response(update);
                if !write_message_subscription_event(
                    stream,
                    response,
                    group_id.as_deref(),
                    &account_ref,
                    &mut seen_messages,
                    &mut seen_stream_previews,
                )
                .await
                {
                    return Ok(());
                }
            }
            event = event_rx.recv() => {
                match event {
                    Ok(response) => {
                        if !write_message_subscription_event(
                            stream,
                            response,
                            group_id.as_deref(),
                            &account_ref,
                            &mut seen_messages,
                            &mut seen_stream_previews,
                        )
                        .await
                        {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let response = DaemonStreamResponse::err(format!(
                            "message stream lagged: {count} updates dropped"
                        ));
                        if !write_stream_response(stream, &response).await {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
            stream_update = stream_rx.recv() => {
                match stream_update {
                    Ok(update) => {
                        let response = agent_stream_update_response(update, false);
                        if !write_message_subscription_event(
                            stream,
                            response,
                            group_id.as_deref(),
                            &account_ref,
                            &mut seen_messages,
                            &mut seen_stream_previews,
                        )
                        .await
                        {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let response = DaemonStreamResponse::err(format!(
                            "agent stream update stream lagged: {count} updates dropped"
                        ));
                        if !write_stream_response(stream, &response).await {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

pub(crate) async fn handle_timeline_messages_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (group_id, limit) = match timeline_messages_subscribe_args(&cli) {
        Ok(args) => args,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let mut runtime_subscription = match runtime.subscribe_timeline_messages(
        &account_ref,
        marmot_app::TimelineMessageQuery {
            group_id_hex: group_id.clone(),
            search: None,
            pagination: marmot_app::TimelinePagination {
                limit,
                ..marmot_app::TimelinePagination::default()
            },
        },
    ) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    if !write_stream_response(
        stream,
        &DaemonStreamResponse::ok(serde_json::json!({
            "trigger": "TimelineSubscriptionReady",
            "type": "timeline_subscription_ready",
            "group_id": group_id.clone(),
        })),
    )
    .await
    {
        return Ok(());
    }

    let initial = timeline_page_stream_response(
        runtime_subscription.take_snapshot(),
        "InitialTimelinePage",
        &runtime,
        &account_ref,
    );
    if !write_stream_response(stream, &initial).await {
        return Ok(());
    }

    while let Some(update) = runtime_subscription.recv().await {
        let response = match update {
            marmot_app::RuntimeTimelineMessageUpdate::Page { page } => {
                timeline_page_stream_response(page, "TimelineUpdated", &runtime, &account_ref)
            }
            marmot_app::RuntimeTimelineMessageUpdate::Projection(update) => {
                timeline_projection_stream_response(update, &runtime)
            }
        };
        if !write_stream_response(stream, &response).await {
            return Ok(());
        }
    }
    Ok(())
}

pub(crate) fn daemon_account_ref(defaults: &DaemonDefaults, cli: &Cli) -> Result<String, String> {
    let secret_store =
        crate::resolve_secret_store(defaults.secret_store).map_err(|err| err.to_string())?;
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home = crate::open_account_home(&defaults.home, secret_store, &keychain_service)
        .map_err(|err| err.to_string())?;
    let account = crate::resolve_account(&account_home, cli.account.clone())
        .map_err(|err| err.to_string())?;
    if !account.local_signing {
        return Err(format!(
            "account {} is not a local signing account",
            account.account_id_hex
        ));
    }
    Ok(account.account_id_hex)
}

pub(crate) async fn write_message_subscription_event(
    stream: &mut UnixStream,
    response: DaemonStreamResponse,
    group_id: Option<&str>,
    account_id: &str,
    seen_messages: &mut BoundedMessageSubscriptionIds,
    seen_stream_previews: &mut BoundedMessageSubscriptionIds,
) -> bool {
    if !stream_response_matches_subscription(&response, group_id, account_id) {
        return true;
    }
    if mark_stream_response_seen(&response, seen_messages, seen_stream_previews) {
        write_stream_response(stream, &response).await
    } else {
        true
    }
}

pub(crate) async fn handle_chats_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let include_archived = match chats_subscribe_args(&cli) {
        Ok(include_archived) => include_archived,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let mut subscription = match runtime.subscribe_chats(&account_ref, include_archived) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    for chat in subscription.snapshot.drain(..) {
        if !write_stream_response(stream, &chat_stream_response(chat, "InitialChat")).await {
            return Ok(());
        }
    }
    while let Some(chat) = subscription.recv().await {
        if !write_stream_response(stream, &chat_stream_response(chat, "ChatUpdated")).await {
            return Ok(());
        }
    }
    Ok(())
}

pub(crate) async fn handle_group_state_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let group_id = match group_state_subscribe_args(&cli) {
        Ok(group_id) => group_id,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let mut subscription = match runtime.subscribe_group_state(&account_ref, &group_id) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let group_id_value = GroupId::new(hex::decode(&group_id)?);
    let initial_mls = runtime
        .group_mls_state(&account_ref, &group_id_value)
        .await
        .ok()
        .map(crate::commands::groups::group_mls_state_json);
    if !write_stream_response(
        stream,
        &group_state_stream_response(
            subscription.snapshot.clone(),
            "InitialGroupState",
            initial_mls,
        ),
    )
    .await
    {
        return Ok(());
    }
    while let Some(group) = subscription.recv().await {
        let mls = runtime
            .group_mls_state(&account_ref, &group_id_value)
            .await
            .ok()
            .map(crate::commands::groups::group_mls_state_json);
        if !write_stream_response(
            stream,
            &group_state_stream_response(group, "GroupStateUpdated", mls),
        )
        .await
        {
            return Ok(());
        }
    }
    Ok(())
}

pub(crate) fn group_state_subscribe_args(cli: &Cli) -> Result<String, String> {
    match &cli.command {
        crate::Command::Groups {
            command: crate::GroupsCommand::SubscribeState { group_id },
        } => crate::normalize_group_id_hex(group_id).map_err(|err| err.to_string()),
        _ => Err("groups subscribe-state requires dm groups subscribe-state".to_owned()),
    }
}

pub(crate) fn chats_subscribe_args(cli: &Cli) -> Result<bool, String> {
    match &cli.command {
        crate::Command::Chats {
            command: crate::ChatsCommand::Subscribe,
        } => Ok(false),
        crate::Command::Chats {
            command: crate::ChatsCommand::SubscribeArchived,
        } => Ok(true),
        _ => Err("chats subscribe requires dm chats subscribe".to_owned()),
    }
}

pub(crate) fn messages_subscribe_args(
    cli: &Cli,
) -> Result<(Option<String>, Option<usize>), String> {
    let (group, limit) = match &cli.command {
        crate::Command::Message {
            command: crate::MessageCommand::Subscribe { group, limit },
        }
        | crate::Command::Messages {
            command: crate::MessageCommand::Subscribe { group, limit },
        } => (group, *limit),
        _ => return Err("messages subscribe requires dm messages subscribe".to_owned()),
    };
    let group_id = group
        .as_deref()
        .map(crate::normalize_group_id_hex)
        .transpose()
        .map_err(|err| err.to_string())?;
    Ok((group_id, Some(limit.unwrap_or(50).min(200))))
}

pub(crate) fn is_timeline_messages_subscribe(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        crate::Command::Message {
            command: crate::MessageCommand::Timeline {
                command: crate::MessageTimelineCommand::Subscribe { .. },
            },
        } | crate::Command::Messages {
            command: crate::MessageCommand::Timeline {
                command: crate::MessageTimelineCommand::Subscribe { .. },
            },
        }
    )
}

pub(crate) fn timeline_messages_subscribe_args(
    cli: &Cli,
) -> Result<(Option<String>, Option<usize>), String> {
    let (group, limit) = match &cli.command {
        crate::Command::Message {
            command:
                crate::MessageCommand::Timeline {
                    command: crate::MessageTimelineCommand::Subscribe { group, limit },
                },
        }
        | crate::Command::Messages {
            command:
                crate::MessageCommand::Timeline {
                    command: crate::MessageTimelineCommand::Subscribe { group, limit },
                },
        } => (group, *limit),
        _ => {
            return Err(
                "timeline messages subscribe requires dm messages timeline subscribe".to_owned(),
            );
        }
    };
    let group_id = group
        .as_deref()
        .map(crate::normalize_group_id_hex)
        .transpose()
        .map_err(|err| err.to_string())?;
    Ok((group_id, Some(limit.unwrap_or(50).min(200))))
}
