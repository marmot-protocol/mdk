//! `dm` subprocess client, subscription readers, and the runtime/command glue on `TuiApp`.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct DmClient {
    pub(crate) exe: PathBuf,
    pub(crate) home: Option<PathBuf>,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) relay: Option<String>,
    pub(crate) secret_store: Option<SecretStoreKind>,
    pub(crate) keychain_service: Option<String>,
}

impl DmClient {
    pub(crate) fn from_cli(cli: &Cli) -> TuiResult<Self> {
        Ok(Self {
            exe: std::env::current_exe()?,
            home: cli.home.clone(),
            socket: cli.socket.clone(),
            relay: cli.relay.clone(),
            secret_store: cli.secret_store,
            keychain_service: cli.keychain_service.clone(),
        })
    }

    pub(crate) fn run_json<S>(&self, account: Option<&str>, args: &[S]) -> TuiResult<Value>
    where
        S: AsRef<str>,
    {
        let mut command = self.command(account, args);
        let output = command.output()?;
        parse_json_output(output)
    }

    pub(crate) fn run_json_with_stdin<S>(
        &self,
        account: Option<&str>,
        args: &[S],
        stdin: &str,
    ) -> TuiResult<Value>
    where
        S: AsRef<str>,
    {
        let mut child = self
            .command(account, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| TuiError::Cli("dm stdin pipe was not available".to_owned()))?
            .write_all(stdin.as_bytes())?;
        parse_json_output(child.wait_with_output()?)
    }

    pub(crate) fn spawn_json_lines<S>(&self, account: Option<&str>, args: &[S]) -> TuiResult<Child>
    where
        S: AsRef<str>,
    {
        let mut command = self.command(account, args);
        command.stdout(Stdio::piped()).stderr(Stdio::null());
        Ok(command.spawn()?)
    }

    pub(crate) fn command<S>(&self, account: Option<&str>, args: &[S]) -> StdCommand
    where
        S: AsRef<str>,
    {
        let mut command = StdCommand::new(&self.exe);
        command.arg("--json");
        if let Some(home) = &self.home {
            command.arg("--home").arg(home);
        }
        if let Some(socket) = &self.socket {
            command.arg("--socket").arg(socket);
        }
        if let Some(relay) = &self.relay {
            command.arg("--relay").arg(relay);
        }
        if let Some(secret_store) = self.secret_store {
            command.arg("--secret-store").arg(secret_store.as_str());
        }
        if let Some(service) = &self.keychain_service {
            command.arg("--keychain-service").arg(service);
        }
        if let Some(account) = account {
            command.arg("--account").arg(account);
        }
        for arg in args {
            command.arg(arg.as_ref());
        }
        command
    }
}

pub(crate) fn parse_json_output(output: Output) -> TuiResult<Value> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope: Value = serde_json::from_str(stdout.trim()).map_err(|err| {
        let mut message = format!("dm returned invalid JSON: {err}");
        if !stderr.trim().is_empty() {
            message.push_str(&format!("; stderr: {}", stderr.trim()));
        }
        TuiError::Cli(message)
    })?;
    if envelope.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(envelope.get("result").cloned().unwrap_or(Value::Null));
    }
    let message = envelope
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .or_else(|| {
            envelope
                .get("error")
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str)
        })
        .unwrap_or_else(|| stderr.trim());
    Err(TuiError::Cli(message.to_owned()))
}

pub(crate) fn spawn_subscription_reader(
    child: &mut Child,
    label: &'static str,
) -> TuiResult<Receiver<SubscriptionEvent>> {
    let Some(stdout) = child.stdout.take() else {
        return Err(TuiError::Cli(format!(
            "{label} subscription did not expose stdout"
        )));
    };
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) if line.trim().is_empty() => {}
                Ok(line) => match serde_json::from_str::<Value>(&line) {
                    Ok(envelope) => {
                        let event = subscription_event_from_json(envelope);
                        let ended = matches!(event, SubscriptionEvent::Ended);
                        if tx.send(event).is_err() || ended {
                            return;
                        }
                    }
                    Err(err) => {
                        if tx
                            .send(SubscriptionEvent::Error(format!(
                                "invalid {label} subscription JSON: {err}"
                            )))
                            .is_err()
                        {
                            return;
                        }
                    }
                },
                Err(err) => {
                    let _ = tx.send(SubscriptionEvent::Error(err.to_string()));
                    return;
                }
            }
        }
        let _ = tx.send(SubscriptionEvent::Ended);
    });
    Ok(rx)
}

impl TuiApp {
    pub(crate) fn send_message(&mut self, text: String) -> TuiResult<()> {
        let account_id = self.message_account_id()?;
        let group_id = self.message_group_id()?;
        let args = vec!["message", "send", &group_id, &text];
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("sent message", &result);
        if let Some(message_id) = result
            .get("message_ids")
            .and_then(Value::as_array)
            .and_then(|ids| ids.first())
            .and_then(Value::as_str)
        {
            let now = unix_now_seconds();
            upsert_message(
                &mut self.messages,
                MessageRow {
                    message_id: message_id.to_owned(),
                    direction: "sent".to_owned(),
                    from: account_id,
                    from_display_name: None,
                    plaintext: text.clone(),
                    display_text: text,
                    recorded_at: now,
                    received_at: now,
                },
            );
            sort_and_cap_messages(&mut self.messages);
        } else {
            self.refresh_messages()?;
        }
        self.status = status;
        Ok(())
    }

    pub(crate) fn start_stream_composer(
        &mut self,
        stream_id: Option<String>,
        quic_candidates: Vec<String>,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let preview_group_id = group_id.clone();
        let insecure_local =
            crate::commands::stream::first_quic_candidate_is_loopback(&quic_candidates);
        let mut args = vec!["stream".to_owned(), "compose-open".to_owned(), group_id];
        if insecure_local {
            args.push("--insecure-local".to_owned());
        }
        if let Some(stream_id) = stream_id {
            args.push("--stream-id".to_owned());
            args.push(stream_id);
        }
        for candidate in quic_candidates {
            args.push("--quic-candidate".to_owned());
            args.push(candidate);
        }
        let result = self.client.run_json(Some(&account_id), &args)?;
        let stream_id = value_string(&result, "stream_id").unwrap_or_else(|| "unknown".to_owned());
        self.streaming = Some(StreamComposer {
            stream_id: stream_id.clone(),
            group_id: preview_group_id.clone(),
            pending_text: String::new(),
            last_flush: Instant::now(),
        });
        self.input.clear();
        self.refresh_messages()?;
        upsert_live_stream_preview(
            &mut self.live_stream_previews,
            LiveStreamPreview {
                group_id: preview_group_id,
                stream_id: stream_id.clone(),
                author: "me".to_owned(),
                status: "streaming".to_owned(),
                text: String::new(),
                error: None,
                optimistic: true,
            },
            false,
        );
        self.status = format!(
            "now streaming {}; type text and press Enter to finish",
            shorten(&stream_id, 18)
        );
        Ok(())
    }

    pub(crate) fn upsert_active_stream_preview(&mut self, stream_id: &str) {
        let Some(group_id) = self
            .streaming
            .as_ref()
            .map(|streaming| streaming.group_id.clone())
        else {
            return;
        };
        upsert_live_stream_preview(
            &mut self.live_stream_previews,
            LiveStreamPreview {
                group_id,
                stream_id: stream_id.to_owned(),
                author: "me".to_owned(),
                status: "streaming".to_owned(),
                text: self.input.clone(),
                error: None,
                optimistic: true,
            },
            true,
        );
    }

    pub(crate) fn flush_stream_append_if_due(&mut self, now: Instant) -> TuiResult<bool> {
        let Some(streaming) = self.streaming.as_ref() else {
            return Ok(false);
        };
        if streaming.pending_text.is_empty()
            || now.duration_since(streaming.last_flush) < STREAM_APPEND_FLUSH_INTERVAL
        {
            return Ok(false);
        }
        match self.flush_stream_append() {
            Ok(()) => Ok(true),
            Err(err) => {
                if let Some(streaming) = self.streaming.as_mut() {
                    streaming.last_flush = Instant::now();
                }
                Err(err)
            }
        }
    }

    pub(crate) fn flush_stream_append(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let Some((stream_id, text)) = self.streaming.as_mut().and_then(|streaming| {
            if streaming.pending_text.is_empty() {
                None
            } else {
                let text = std::mem::take(&mut streaming.pending_text);
                Some((streaming.stream_id.clone(), text))
            }
        }) else {
            return Ok(());
        };
        let args = vec![
            "stream".to_owned(),
            "compose-append".to_owned(),
            "--stream-id".to_owned(),
            stream_id.clone(),
            text.clone(),
        ];
        let result = match self.client.run_json(Some(&account_id), &args) {
            Ok(result) => result,
            Err(err) => {
                if let Some(streaming) = self.streaming.as_mut()
                    && streaming.stream_id == stream_id
                {
                    streaming.pending_text.insert_str(0, &text);
                }
                return Err(err);
            }
        };
        if let Some(streaming) = self.streaming.as_mut()
            && streaming.stream_id == stream_id
        {
            streaming.last_flush = Instant::now();
        }
        let bytes = result
            .get("text")
            .and_then(Value::as_str)
            .map(str::len)
            .unwrap_or_default();
        self.status = format!("streaming {} bytes on {}", bytes, shorten(&stream_id, 18));
        Ok(())
    }

    pub(crate) fn finish_stream_composer(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let Some(streaming) = self.streaming.take() else {
            return Ok(());
        };
        if self.input.is_empty() {
            self.streaming = Some(streaming);
            self.status = "stream text is empty; type text or Esc cancels".to_owned();
            return Ok(());
        }
        self.streaming = Some(streaming);
        self.flush_stream_append()?;
        let Some(streaming) = self.streaming.take() else {
            return Ok(());
        };
        let args = vec![
            "stream".to_owned(),
            "compose-finish".to_owned(),
            "--stream-id".to_owned(),
            streaming.stream_id.clone(),
        ];
        // Restore the composer if compose-finish fails (daemon gone, broker/QUIC
        // error, relay publish rejection — the failure class from #194). Without
        // this, `self.streaming` stays `None` while `self.input` still holds the
        // draft, so the caught error keeps the TUI alive but the next Enter sends
        // the stream draft through the normal composer path as a regular message.
        let result = match self.client.run_json(Some(&account_id), &args) {
            Ok(result) => result,
            Err(err) => {
                self.streaming = Some(streaming);
                return Err(err);
            }
        };
        self.input.clear();
        remove_live_stream_preview(
            &mut self.live_stream_previews,
            Some(streaming.group_id.as_str()),
            &streaming.stream_id,
        );
        self.refresh_messages()?;
        self.refresh_daemon_status()?;
        let chunk_count = result
            .get("chunk_count")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        self.status = format!(
            "finished stream {} chunks={chunk_count}",
            shorten(&streaming.stream_id, 18)
        );
        Ok(())
    }

    pub(crate) fn cancel_stream_composer(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let Some(streaming) = self.streaming.take() else {
            return Ok(());
        };
        let args = vec![
            "stream".to_owned(),
            "compose-cancel".to_owned(),
            "--stream-id".to_owned(),
            streaming.stream_id.clone(),
        ];
        let _ = self.client.run_json(Some(&account_id), &args);
        self.input.clear();
        remove_live_stream_preview(
            &mut self.live_stream_previews,
            Some(streaming.group_id.as_str()),
            &streaming.stream_id,
        );
        self.status = format!("cancelled stream {}", shorten(&streaming.stream_id, 18));
        Ok(())
    }

    pub(crate) fn update_profile_name(&mut self, name: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let result = self.client.run_json(
            Some(&account_id),
            &[
                "profile",
                "update",
                "--name",
                &name,
                "--display-name",
                &name,
            ],
        )?;
        self.refresh_accounts()?;
        let label = result
            .get("profile")
            .and_then(profile_display_name_from_value)
            .unwrap_or(name);
        self.status = format!("published profile name {label}");
        Ok(())
    }

    pub(crate) fn create_chat(&mut self, name: String, members: Vec<String>) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let all_members = unique_member_refs(members);
        let mut args = vec!["group".to_owned(), "create".to_owned(), name];
        args.extend(all_members.iter().cloned());
        let result = self.client.run_json(Some(&account_id), &args)?;
        let group_id = value_string(&result, "group_id");
        let member_count = all_members.len();
        self.refresh_chats()?;
        if let Some(group_id) = group_id.as_deref() {
            self.select_chat_by_group_id(group_id)?;
        }
        self.status = group_id
            .as_deref()
            .map(|group_id| {
                format!(
                    "created chat {} with {} member(s)",
                    shorten(group_id, 18),
                    member_count
                )
            })
            .unwrap_or_else(|| format!("created chat with {member_count} member(s)"));
        Ok(())
    }

    pub(crate) fn add_selected_chat_members(&mut self, members: Vec<String>) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let members = unique_member_refs(members);
        let mut args = vec!["group".to_owned(), "invite".to_owned(), group_id];
        args.extend(members);
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("added member(s)", &result);
        self.refresh_messages()?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn remove_selected_chat_members(&mut self, members: Vec<String>) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let members = unique_member_refs(members);
        let mut args = vec!["group".to_owned(), "remove".to_owned(), group_id];
        args.extend(members);
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("removed member(s)", &result);
        self.refresh_messages()?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn update_selected_chat(
        &mut self,
        name: Option<String>,
        description: Option<String>,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let mut args = vec!["group".to_owned(), "update".to_owned(), group_id.clone()];
        if let Some(name) = name {
            args.push("--name".to_owned());
            args.push(name);
        }
        if let Some(description) = description {
            args.push("--description".to_owned());
            args.push(description);
        }
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("updated chat", &result);
        self.refresh_chats()?;
        self.select_chat_by_group_id(&group_id)?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn set_selected_chat_archived(&mut self, archived: bool) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let verb = if archived { "archive" } else { "unarchive" };
        self.client
            .run_json(Some(&account_id), &["chats", verb, &group_id])?;
        self.refresh_chats()?;
        self.status = if archived {
            format!("archived chat {}", shorten(&group_id, 18))
        } else {
            format!("unarchived chat {}", shorten(&group_id, 18))
        };
        Ok(())
    }

    pub(crate) fn show_selected_chat_members(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let result = self
            .client
            .run_json(Some(&account_id), &["group", "members", &group_id])?;
        self.status = group_members_status(&result);
        Ok(())
    }

    pub(crate) fn set_archived_chat_visibility(&mut self, include: bool) -> TuiResult<()> {
        self.show_archived_chats = include;
        self.refresh_chats()?;
        self.status = if include {
            "showing archived chats".to_owned()
        } else {
            "hiding archived chats".to_owned()
        };
        Ok(())
    }

    pub(crate) fn create_or_import_account(
        &mut self,
        identity: Option<String>,
        action: &'static str,
    ) -> TuiResult<()> {
        let invocation = account_setup_invocation(identity);
        let result = match invocation.stdin {
            Some(stdin) => self
                .client
                .run_json_with_stdin(None, &invocation.args, &stdin)?,
            None => self.client.run_json(None, &invocation.args)?,
        };
        let selector =
            value_string(&result, "account_id").or_else(|| value_string(&result, "npub"));
        let npub = value_string(&result, "npub").unwrap_or_else(|| "unknown".to_owned());
        let result_display_name = result
            .get("profile")
            .and_then(profile_display_name_from_value)
            .or_else(|| non_empty_value_string(&result, "display_name"));
        let local_signing = result
            .get("local_signing")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        self.refresh_accounts()?;
        if let Some(selector) = selector.as_deref()
            && let Some(index) = selected_account_index(&self.accounts, Some(selector))
        {
            self.selected_account = index;
            // refresh_chats() dispatches on the selected account's local_signing
            // flag: for a local signing account it reloads chats/messages, and for
            // a public-only account it fully clears chats, messages, the
            // messages_account_id/messages_group_id targets, and the prior
            // account's subscriptions. Calling it unconditionally avoids the
            // partial-clear drift where a public-only login left stale send
            // targets pointing at the previous account/chat (issue #196).
            self.refresh_chats()?;
        }

        let signing = if local_signing {
            "local-signing"
        } else {
            "public-only"
        };
        let display_name = self
            .selected_account_row()
            .map(account_display_label)
            .or(result_display_name)
            .unwrap_or(npub);
        self.status = format!("{action} {} {signing}", shorten(&display_name, 18));
        Ok(())
    }

    pub(crate) fn start_stream(
        &mut self,
        stream_id: Option<String>,
        quic_candidates: Vec<String>,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let mut args = vec!["stream".to_owned(), "start".to_owned(), group_id];
        if let Some(stream_id) = stream_id {
            args.push("--stream-id".to_owned());
            args.push(stream_id);
        }
        for candidate in quic_candidates {
            args.push("--quic-candidate".to_owned());
            args.push(candidate);
        }
        let result = self.client.run_json(Some(&account_id), &args)?;
        let stream_id = value_string(&result, "stream_id").unwrap_or_else(|| "unknown".to_owned());
        let status = publish_status(
            &format!("started stream {}", shorten(&stream_id, 18)),
            &result,
        );
        self.refresh_messages()?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn watch_stream(
        &mut self,
        stream_id: Option<String>,
        insecure_local: bool,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let mut args = vec![
            "stream".to_owned(),
            "watch".to_owned(),
            group_id,
            "--background".to_owned(),
        ];
        if let Some(stream_id) = stream_id {
            args.push("--stream-id".to_owned());
            args.push(stream_id);
        }
        if insecure_local {
            args.push("--insecure-local".to_owned());
        }
        let result = self.client.run_json(Some(&account_id), &args)?;
        self.refresh_daemon_status()?;
        let watch_id = value_string(&result, "watch_id").unwrap_or_else(|| "stream".to_owned());
        self.status = format!("watching stream {}", shorten(&watch_id, 24));
        Ok(())
    }

    pub(crate) fn finish_stream(
        &mut self,
        stream_id: String,
        transcript_hash: String,
        chunk_count: u64,
        text: String,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let args = vec![
            "stream".to_owned(),
            "finish".to_owned(),
            group_id,
            "--stream-id".to_owned(),
            stream_id.clone(),
            "--transcript-hash".to_owned(),
            transcript_hash,
            "--chunk-count".to_owned(),
            chunk_count.to_string(),
            text,
        ];
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status(
            &format!("finished stream {}", shorten(&stream_id, 18)),
            &result,
        );
        self.refresh_messages()?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn verify_stream(
        &mut self,
        stream_id: String,
        transcript_hash: String,
        chunk_count: Option<u64>,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let mut args = vec![
            "stream".to_owned(),
            "verify".to_owned(),
            group_id,
            "--stream-id".to_owned(),
            stream_id.clone(),
            "--transcript-hash".to_owned(),
            transcript_hash,
        ];
        if let Some(chunk_count) = chunk_count {
            args.push("--chunk-count".to_owned());
            args.push(chunk_count.to_string());
        }
        let result = self.client.run_json(Some(&account_id), &args)?;
        let verified = result
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        self.status = format!("stream {} verified={verified}", shorten(&stream_id, 18));
        Ok(())
    }

    pub(crate) fn refresh_daemon_status(&mut self) -> TuiResult<()> {
        let result = self.client.run_json(None, &["daemon", "status"])?;
        self.daemon = parse_daemon_view(&result);
        self.ensure_selected_chat_subscription();
        self.ensure_selected_message_subscription();
        self.ensure_selected_group_state_subscription();
        Ok(())
    }

    pub(crate) fn start_daemon(&mut self) -> TuiResult<()> {
        let args = vec!["daemon".to_owned(), "start".to_owned()];
        let result = self.client.run_json(None, &args)?;
        self.daemon = parse_daemon_view(&result);
        self.ensure_selected_chat_subscription();
        self.ensure_selected_message_subscription();
        self.ensure_selected_group_state_subscription();
        self.status = daemon_status_sentence(&self.daemon);
        Ok(())
    }

    pub(crate) fn stop_daemon(&mut self) -> TuiResult<()> {
        let result = self.client.run_json(None, &["daemon", "stop"])?;
        self.daemon = parse_daemon_view(&result);
        self.chat_subscription = None;
        self.message_subscription = None;
        self.group_state_subscription = None;
        self.status = "daemon stopped".to_owned();
        Ok(())
    }

    pub(crate) fn refresh_accounts(&mut self) -> TuiResult<()> {
        let result = self.client.run_json(None, &["account", "list"])?;
        let previous_account_id = self
            .selected_account_row()
            .map(|account| account.account_id.clone())
            .or_else(|| self.initial_account.clone());
        self.accounts = result
            .get("accounts")
            .and_then(Value::as_array)
            .map(|accounts| accounts.iter().filter_map(parse_account).collect())
            .unwrap_or_default();
        self.selected_account =
            selected_account_index(&self.accounts, previous_account_id.as_deref()).unwrap_or(0);
        if self.accounts.is_empty() {
            self.chats.clear();
            self.messages.clear();
            self.messages_account_id = None;
            self.messages_group_id = None;
            self.unread_counts.clear();
            self.chat_subscription = None;
            self.message_subscription = None;
            self.group_state_subscription = None;
            self.group_diagnostics = None;
            self.status = "no identities yet; create one with dm create-identity".to_owned();
            return Ok(());
        }
        self.refresh_chats()
    }

    pub(crate) fn refresh_chats(&mut self) -> TuiResult<()> {
        let Some(account) = self.selected_account_row().cloned() else {
            self.chats.clear();
            self.messages.clear();
            self.messages_account_id = None;
            self.messages_group_id = None;
            self.chat_subscription = None;
            self.message_subscription = None;
            self.group_state_subscription = None;
            self.group_diagnostics = None;
            self.status = "no account selected".to_owned();
            return Ok(());
        };
        if !account.local_signing {
            self.chats.clear();
            self.messages.clear();
            self.messages_account_id = None;
            self.messages_group_id = None;
            self.chat_subscription = None;
            self.message_subscription = None;
            self.group_state_subscription = None;
            self.group_diagnostics = None;
            self.status =
                "selected account is public-only; choose a local signing account".to_owned();
            return Ok(());
        }

        let previous_group_id = self.selected_chat_row().map(|chat| chat.group_id.clone());
        let mut args = vec!["chats".to_owned(), "list".to_owned()];
        if self.show_archived_chats {
            args.push("--include-archived".to_owned());
        }
        let result = self.client.run_json(Some(&account.account_id), &args)?;
        self.chats = result
            .get("chats")
            .and_then(Value::as_array)
            .map(|chats| chats.iter().filter_map(parse_chat).collect())
            .unwrap_or_default();
        retain_unread_counts_for_chats(&mut self.unread_counts, &self.chats);
        self.selected_chat =
            selected_chat_index(&self.chats, previous_group_id.as_deref()).unwrap_or(0);
        if let Err(err) = self.ensure_chat_subscription(&account.account_id) {
            self.status = format!("chat subscription failed: {err}");
        }
        if self.chats.is_empty() {
            self.messages.clear();
            self.messages_account_id = Some(account.account_id.clone());
            self.messages_group_id = None;
            self.group_state_subscription = None;
            if let Err(err) = self.ensure_message_subscription(&account.account_id) {
                self.status = format!("message subscription failed: {err}");
                return Ok(());
            }
            self.status = format!(
                "loaded account {}; no chats",
                shorten(&account_display_label(&account), 18)
            );
            return Ok(());
        }
        self.refresh_messages()
    }

    pub(crate) fn refresh_messages(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let args = vec![
            "message".to_owned(),
            "list".to_owned(),
            "--group".to_owned(),
            group_id.clone(),
            "--limit".to_owned(),
            "50".to_owned(),
        ];
        let result = self.client.run_json(Some(&account_id), &args)?;
        self.messages = result
            .get("messages")
            .and_then(Value::as_array)
            .map(|messages| messages.iter().filter_map(parse_message).collect())
            .unwrap_or_default();
        self.messages_account_id = Some(account_id.clone());
        self.messages_group_id = Some(group_id.clone());
        self.messages_scroll = 0;
        self.unread_counts.remove(&group_id);
        sort_and_cap_messages(&mut self.messages);
        if let Err(err) = self.ensure_message_subscription(&account_id) {
            self.status = format!("message subscription failed: {err}");
            return Ok(());
        }
        let group_state_subscription_error = self
            .ensure_group_state_subscription(&account_id, &group_id)
            .err()
            .map(|err| format!("group state subscription failed: {err}"));
        if self.daemon.running && group_state_subscription_error.is_none() {
            if self
                .group_diagnostics
                .as_ref()
                .is_none_or(|diagnostics| diagnostics.group_id != group_id)
            {
                self.group_diagnostics = Some(GroupDiagnostics::unavailable(
                    &group_id,
                    "loading group state",
                ));
            }
        } else {
            self.refresh_group_diagnostics(&account_id, &group_id);
        }
        self.status = group_state_subscription_error
            .unwrap_or_else(|| format!("loaded {} message(s)", self.messages.len()));
        Ok(())
    }

    pub(crate) fn refresh_group_diagnostics(&mut self, account_id: &str, group_id: &str) {
        self.group_diagnostics = Some(
            match self
                .client
                .run_json(Some(account_id), &["groups", "show", group_id])
            {
                Ok(result) => parse_group_diagnostics(&result).unwrap_or_else(|| {
                    GroupDiagnostics::unavailable(
                        group_id,
                        "groups show did not return group diagnostics",
                    )
                }),
                Err(err) => GroupDiagnostics::unavailable(group_id, err.to_string()),
            },
        );
    }

    pub(crate) fn ensure_chat_subscription(&mut self, account_id: &str) -> TuiResult<()> {
        if !self.daemon.running {
            self.chat_subscription = None;
            return Ok(());
        }
        if self.chat_subscription.as_ref().is_some_and(|subscription| {
            subscription.account_id == account_id
                && subscription.include_archived == self.show_archived_chats
        }) {
            return Ok(());
        }

        self.chat_subscription = None;
        let args = if self.show_archived_chats {
            vec!["chats".to_owned(), "subscribe-archived".to_owned()]
        } else {
            vec!["chats".to_owned(), "subscribe".to_owned()]
        };
        let mut child = self.client.spawn_json_lines(Some(account_id), &args)?;
        let rx = spawn_subscription_reader(&mut child, "chat")?;
        self.chat_subscription = Some(ChatSubscription {
            account_id: account_id.to_owned(),
            include_archived: self.show_archived_chats,
            child,
            rx,
        });
        Ok(())
    }

    pub(crate) fn ensure_message_subscription(&mut self, account_id: &str) -> TuiResult<()> {
        if !self.daemon.running {
            self.message_subscription = None;
            return Ok(());
        }
        if self
            .message_subscription
            .as_ref()
            .is_some_and(|subscription| subscription.account_id == account_id)
        {
            return Ok(());
        }

        self.message_subscription = None;
        let args = message_subscription_args();
        let mut child = self.client.spawn_json_lines(Some(account_id), &args)?;
        let rx = spawn_subscription_reader(&mut child, "message")?;
        self.message_subscription = Some(MessageSubscription {
            account_id: account_id.to_owned(),
            child,
            rx,
        });
        Ok(())
    }

    pub(crate) fn ensure_group_state_subscription(
        &mut self,
        account_id: &str,
        group_id: &str,
    ) -> TuiResult<()> {
        if !self.daemon.running {
            self.group_state_subscription = None;
            return Ok(());
        }
        if self
            .group_state_subscription
            .as_ref()
            .is_some_and(|subscription| {
                subscription.account_id == account_id && subscription.group_id == group_id
            })
        {
            return Ok(());
        }

        self.group_state_subscription = None;
        let args = vec![
            "groups".to_owned(),
            "subscribe-state".to_owned(),
            group_id.to_owned(),
        ];
        let mut child = self.client.spawn_json_lines(Some(account_id), &args)?;
        let rx = spawn_subscription_reader(&mut child, "group state")?;
        self.group_state_subscription = Some(GroupStateSubscription {
            account_id: account_id.to_owned(),
            group_id: group_id.to_owned(),
            child,
            rx,
        });
        Ok(())
    }

    pub(crate) fn ensure_selected_chat_subscription(&mut self) {
        let Some(account) = self.selected_account_row().cloned() else {
            self.chat_subscription = None;
            return;
        };
        if !account.local_signing {
            self.chat_subscription = None;
            return;
        }
        if let Err(err) = self.ensure_chat_subscription(&account.account_id) {
            self.status = format!("chat subscription failed: {err}");
        }
    }

    pub(crate) fn ensure_selected_message_subscription(&mut self) {
        let Some(account) = self.selected_account_row().cloned() else {
            self.message_subscription = None;
            return;
        };
        if !account.local_signing {
            self.message_subscription = None;
            return;
        }
        if let Err(err) = self.ensure_message_subscription(&account.account_id) {
            self.status = format!("message subscription failed: {err}");
        }
    }

    pub(crate) fn ensure_selected_group_state_subscription(&mut self) {
        let Some(account) = self.selected_account_row().cloned() else {
            self.group_state_subscription = None;
            return;
        };
        if !account.local_signing {
            self.group_state_subscription = None;
            return;
        }
        let Some(group_id) = self.selected_chat_row().map(|chat| chat.group_id.clone()) else {
            self.group_state_subscription = None;
            return;
        };
        if let Err(err) = self.ensure_group_state_subscription(&account.account_id, &group_id) {
            self.status = format!("group state subscription failed: {err}");
        }
    }

    pub(crate) fn drain_chat_subscription(&mut self) -> bool {
        let Some(subscription) = self.chat_subscription.as_ref() else {
            return false;
        };
        let mut events = Vec::new();
        loop {
            match subscription.rx.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    events.push(SubscriptionEvent::Ended);
                    break;
                }
            }
        }
        if events.is_empty() {
            return false;
        }
        let previous_group_id = self.selected_chat_row().map(|chat| chat.group_id.clone());
        let mut chats_changed = false;
        for event in events {
            match event {
                SubscriptionEvent::Result(result) => {
                    if let Some(status) = apply_chat_subscription_result(
                        &mut self.chats,
                        &mut self.selected_chat,
                        self.show_archived_chats,
                        &result,
                    ) {
                        chats_changed = true;
                        self.status = status;
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.status = format!("chat subscription failed: {err}");
                }
                SubscriptionEvent::Ended => {
                    self.chat_subscription = None;
                    break;
                }
            }
        }
        if chats_changed {
            let selected_group_id = self.selected_chat_row().map(|chat| chat.group_id.clone());
            if previous_group_id != selected_group_id {
                self.messages.clear();
                self.messages_account_id = None;
                self.messages_group_id = None;
                self.message_subscription = None;
                self.group_state_subscription = None;
            }
            self.ensure_selected_message_subscription();
            self.ensure_selected_group_state_subscription();
        }
        true
    }

    pub(crate) fn drain_group_state_subscription(&mut self) -> bool {
        let Some((group_id, events)) = ({
            let Some(subscription) = self.group_state_subscription.as_ref() else {
                return false;
            };
            let mut events = Vec::new();
            loop {
                match subscription.rx.try_recv() {
                    Ok(event) => events.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        events.push(SubscriptionEvent::Ended);
                        break;
                    }
                }
            }
            if events.is_empty() {
                None
            } else {
                Some((subscription.group_id.clone(), events))
            }
        }) else {
            return false;
        };

        for event in events {
            match event {
                SubscriptionEvent::Result(result) => {
                    if let Some(update) = group_state_subscription_update(&result, &group_id) {
                        if let Some(diagnostics) = update.diagnostics {
                            self.group_diagnostics = Some(diagnostics);
                        } else {
                            self.group_diagnostics = Some(GroupDiagnostics::unavailable(
                                &update.group_id,
                                "group state update did not include diagnostics",
                            ));
                        }
                        if let Some(status) = update.status {
                            self.status = status;
                        }
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.status = format!("group state subscription failed: {err}");
                }
                SubscriptionEvent::Ended => {
                    self.group_state_subscription = None;
                    break;
                }
            }
        }
        true
    }

    pub(crate) fn drain_message_subscription(&mut self) -> bool {
        let Some(subscription) = self.message_subscription.as_ref() else {
            return false;
        };
        let mut events = Vec::new();
        loop {
            match subscription.rx.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    events.push(SubscriptionEvent::Ended);
                    break;
                }
            }
        }
        if events.is_empty() {
            return false;
        }
        for event in events {
            match event {
                SubscriptionEvent::Result(result) => {
                    let loaded_group_id = self.messages_group_id.clone();
                    if let Some(status) = apply_tui_subscription_result(
                        &mut self.messages,
                        &mut self.live_stream_previews,
                        &mut self.unread_counts,
                        loaded_group_id.as_deref(),
                        &result,
                    ) {
                        self.status = status;
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.status = format!("message subscription failed: {err}");
                }
                SubscriptionEvent::Ended => {
                    self.message_subscription = None;
                    break;
                }
            }
        }
        true
    }
}
