//! `wn` subprocess client, subscription readers, and the runtime/command glue on `TuiApp`.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct WnClient {
    pub(crate) exe: PathBuf,
    pub(crate) home: Option<PathBuf>,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) relay: Option<String>,
    /// First-run discovery relays from `wn tui --discovery-relays`, forwarded to
    /// the `daemon start` child (no JSON change; flag passthrough only).
    pub(crate) discovery_relays: Vec<String>,
    /// First-run default account relays from `wn tui --default-account-relays`,
    /// forwarded to the `daemon start` child and used as the account-setup relay.
    pub(crate) default_account_relays: Vec<String>,
    pub(crate) secret_store: Option<SecretStoreKind>,
    pub(crate) keychain_service: Option<String>,
}

impl WnClient {
    pub(crate) fn from_cli(cli: &Cli) -> TuiResult<Self> {
        let (discovery_relays, default_account_relays) = match &cli.command {
            crate::Command::Tui {
                discovery_relays,
                default_account_relays,
            } => (discovery_relays.clone(), default_account_relays.clone()),
            _ => (Vec::new(), Vec::new()),
        };
        Ok(Self {
            exe: std::env::current_exe()?,
            home: cli.home.clone(),
            socket: cli.socket.clone(),
            relay: cli.relay.clone(),
            discovery_relays,
            default_account_relays,
            secret_store: cli.secret_store,
            keychain_service: cli.keychain_service.clone(),
        })
    }

    /// The relay to hand account setup (`create-identity` / `login`) when no
    /// global `--relay` already covers it. `command` appends `--relay` from
    /// `self.relay` to every child, so supplying one here too would pass it
    /// twice; only fill in when `self.relay` is absent, preferring a default
    /// account relay and falling back to a discovery relay.
    pub(crate) fn account_setup_relay(&self) -> Option<String> {
        if self.relay.is_some() {
            return None;
        }
        self.default_account_relays
            .first()
            .or_else(|| self.discovery_relays.first())
            .cloned()
    }

    /// Append the first-run setup relay as a command-local `--relay` when no global
    /// `--relay` already covers the child. `profile update` and `follows add|remove`
    /// require a relay; `--relay` is a global clap flag, so this command-local
    /// position lands in the same slot those handlers read. Mirrors
    /// `account_setup_relay`'s only-when-absent rule, so a global relay is never
    /// passed twice.
    pub(crate) fn with_setup_relay(&self, mut args: Vec<String>) -> Vec<String> {
        if let Some(relay) = self.account_setup_relay() {
            args.push("--relay".to_owned());
            args.push(relay);
        }
        args
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
            .ok_or_else(|| TuiError::Cli("wn stdin pipe was not available".to_owned()))?
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
        let mut message = format!("wn returned invalid JSON: {err}");
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

pub(crate) fn media_upload_send_args(
    group_id: String,
    file_path: String,
    caption: Option<String>,
) -> Vec<String> {
    let mut args = vec![
        "media".to_owned(),
        "upload".to_owned(),
        group_id,
        file_path,
        "--send".to_owned(),
    ];
    if let Some(caption) = caption.filter(|caption| !caption.trim().is_empty()) {
        args.push("--message".to_owned());
        args.push(caption);
    }
    args
}

/// Build the argv for a reply send: `messages send --group <g> --reply-to <id>
/// <text>`. The `--reply-to` flag must precede the trailing text; a `--reply-to`
/// placed after the text is swallowed as literal message text and rejected by
/// the CLI send guard (`reply_to_after_message_text`).
pub(crate) fn reply_send_args(group_id: &str, reply_to: &str, text: &str) -> Vec<String> {
    vec![
        "messages".to_owned(),
        "send".to_owned(),
        "--group".to_owned(),
        group_id.to_owned(),
        "--reply-to".to_owned(),
        reply_to.to_owned(),
        text.to_owned(),
    ]
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

/// A completed effect handed back from the worker to the event loop: the effect
/// that ran (so the fold knows how to interpret it) plus, in order, every call's
/// parsed result — or the first error encountered.
pub(crate) struct EffectDone {
    pub(crate) effect: Effect,
    pub(crate) result: Result<Vec<Value>, String>,
}

/// Runs queued [`Effect`]s on one dedicated worker thread, so a user-initiated
/// `wn` round-trip never blocks the render loop and queued mutations run in FIFO
/// order — a single thread draining a single channel preserves submission order
/// end to end. Results return over a second channel drained on `tick`, mirroring
/// the media pipeline and the subscription readers.
///
/// Supervision is deliberately omitted. If the worker thread ever panicked it
/// would drop `done_tx`; `drain` would then see `Disconnected`, and any in-flight
/// status (`sending...`, `loading chat...`, …) would be stranded with no fold to
/// clear it — there is no restart. That is acceptable because the realistic panic
/// surface here is empty: an effect is just `run_json`, which returns a `Result`
/// (spawn/IO/JSON failures are values, not panics) reduced to a message string,
/// and `parse_json_output` is panic-free (lossy UTF-8 decode, checked JSON parse,
/// no indexing or unwraps). Reaching a panic would take an allocation abort, by
/// which point the whole process is already lost.
///
/// A `wn` child still running when the app quits is left to finish: dropping the
/// app drops `tx`, so the worker exits after its current effect, but that child
/// is not killed. A send completing just after quit is acceptable (the work
/// reached the relay); a read (a load) merely wastes the moment it takes to
/// exit. Neither warrants tracking and reaping children across shutdown.
pub(crate) struct EffectRunner {
    tx: mpsc::Sender<Effect>,
    rx: Receiver<EffectDone>,
}

impl EffectRunner {
    pub(crate) fn spawn(client: WnClient) -> Self {
        let (tx, effect_rx) = mpsc::channel::<Effect>();
        let (done_tx, rx) = mpsc::channel::<EffectDone>();
        thread::spawn(move || {
            // `recv` returns `Err` once the app drops its `tx` (shutdown), so the
            // worker exits cleanly. Effects run strictly one at a time in the
            // order received.
            while let Ok(effect) = effect_rx.recv() {
                let result = run_effect(&client, &effect);
                if done_tx.send(EffectDone { effect, result }).is_err() {
                    return;
                }
            }
        });
        Self { tx, rx }
    }

    /// Queue an effect to run off the event loop. The send only fails if the
    /// worker is gone, which happens only at shutdown; a dropped effect then
    /// simply never folds, which is correct while tearing down.
    pub(crate) fn enqueue(&self, effect: Effect) {
        let _ = self.tx.send(effect);
    }

    /// Drain every effect that finished since the last tick, for folding now.
    pub(crate) fn drain(&self) -> Vec<EffectDone> {
        let mut done = Vec::new();
        // `try_recv` yields `Empty` when caught up and `Disconnected` only if the
        // worker died; either ends the drain. The worker holds `done_tx` for the
        // app's lifetime, so `Disconnected` is a shutdown-only edge.
        while let Ok(item) = self.rx.try_recv() {
            done.push(item);
        }
        done
    }

    #[cfg(test)]
    pub(crate) fn recv_timeout(&self, timeout: Duration) -> Option<EffectDone> {
        self.rx.recv_timeout(timeout).ok()
    }
}

/// Run every call an effect expands to, in order, short-circuiting on the first
/// error (mirroring the `?` chaining the synchronous handlers used). Worker
/// thread only. The error is reduced to a message string at this boundary; the
/// folds only ever surface it on the status line.
fn run_effect(client: &WnClient, effect: &Effect) -> Result<Vec<Value>, String> {
    let mut values = Vec::new();
    for call in effect.calls() {
        match client.run_json(Some(&call.account), &call.args) {
            Ok(value) => values.push(value),
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(values)
}

/// Reduce a single-call effect's outcome to its one result value. A successful
/// effect with no calls yields `Null` (defensive; every effect has at least one
/// call today).
fn single_effect_value(result: Result<Vec<Value>, String>) -> Result<Value, String> {
    result.map(|mut values| values.pop().unwrap_or(Value::Null))
}

impl TuiApp {
    /// Fold a completed effect back into state, exactly as the synchronous
    /// handler folded its `run_json` return. A failure lands on the status line
    /// and never tears down the session (the caught-error invariant).
    pub(crate) fn apply_effect_done(&mut self, done: EffectDone) {
        let EffectDone { effect, result } = done;
        match effect {
            Effect::SendMessage {
                account,
                group,
                text,
            } => {
                self.fold_optimistic_send(account, group, text, None, "sent message", result);
            }
            Effect::SendReply {
                account,
                group,
                reply_to,
                text,
            } => {
                self.fold_optimistic_send(
                    account,
                    group,
                    text,
                    Some(reply_to),
                    "sent reply",
                    result,
                );
            }
            Effect::React { emoji, .. } => {
                self.fold_status_effect(result, format!("reacted {emoji}"));
            }
            Effect::Unreact { .. } => {
                self.fold_status_effect(result, "removed reaction".to_owned());
            }
            Effect::Delete { .. } => {
                self.fold_status_effect(result, "deleted message".to_owned());
            }
            Effect::LoadTimeline { account, group } => {
                self.fold_load_timeline(account, group, result);
            }
            Effect::MarkRead { group, .. } => {
                self.fold_mark_read(group, result);
            }
            Effect::GroupDiagnostics { group, .. } => {
                self.fold_group_diagnostics(group, result);
            }
            Effect::UserSearch { query, .. } => {
                self.fold_user_search(query, result);
            }
            Effect::LoadGroupDetail { account, group } => {
                self.fold_group_detail(account, group, result);
            }
            Effect::LoadInvites { account } => {
                self.fold_invites(account, result);
            }
            Effect::Relist { account, .. } => {
                self.fold_relist(account, result);
            }
        }
    }

    /// Fold an effect whose only visible outcome is a status line: report
    /// `success` on `Ok`, or the caught error otherwise.
    fn fold_status_effect(&mut self, result: Result<Vec<Value>, String>, success: String) {
        self.status = match result {
            Ok(_) => success,
            Err(err) => format!("error: {err}"),
        };
    }

    #[cfg(test)]
    pub(crate) fn apply_effect_done_for_test(&mut self, done: EffectDone) {
        self.apply_effect_done(done);
    }

    /// Wait for `count` queued effects to finish on the worker and fold each,
    /// for end-to-end tests over a fake `wn`. Panics if the worker stalls.
    #[cfg(test)]
    pub(crate) fn settle_effects(&mut self, count: usize) {
        for _ in 0..count {
            let done = self
                .effects
                .recv_timeout(Duration::from_secs(5))
                .expect("effect worker produced a result");
            self.apply_effect_done(done);
        }
    }

    /// Send the composer text off the event loop. The optimistic row folds in
    /// when the send lands (the timeline projection upserts over it by id once it
    /// reaches the materialized view), so nothing blocks the render loop.
    pub(crate) fn send_message(&mut self, text: String) -> TuiResult<()> {
        let effect = self.resolve_send_message(text)?;
        self.effects.enqueue(effect);
        self.status = "sending...".to_owned();
        Ok(())
    }

    /// Resolve (without running) the send effect. Uses the documented plural
    /// `messages send` surface, matching react/unreact/delete/retry.
    pub(crate) fn resolve_send_message(&self, text: String) -> TuiResult<Effect> {
        Ok(Effect::SendMessage {
            account: self.message_account_id()?,
            group: self.message_group_id()?,
            text,
        })
    }

    /// Send the composer text as a reply to the selected message, off the event
    /// loop. The target resolves at submit with the same clear error the other
    /// interactions use when nothing is selected; the optimistic reply row folds
    /// in when the reply lands.
    pub(crate) fn send_reply(&mut self, text: String) -> TuiResult<()> {
        let effect = self.resolve_reply(text)?;
        self.effects.enqueue(effect);
        self.status = "sending reply...".to_owned();
        Ok(())
    }

    pub(crate) fn resolve_reply(&self, text: String) -> TuiResult<Effect> {
        Ok(Effect::SendReply {
            account: self.message_account_id()?,
            group: self.message_group_id()?,
            reply_to: self.selected_timeline_message_id()?,
            text,
        })
    }

    /// Fold a completed send/reply, exactly as the synchronous path did: report
    /// the publish status and, while the pane still shows the target chat, insert
    /// the optimistic row the timeline projection later upserts over by id. A row
    /// for a chat the user has since left is dropped (the send still happened;
    /// its group feed surfaces it on return). With no returned id, reload the
    /// page like the synchronous path did.
    fn fold_optimistic_send(
        &mut self,
        account: String,
        group: String,
        text: String,
        reply_to: Option<String>,
        action: &str,
        result: Result<Vec<Value>, String>,
    ) {
        let result = match single_effect_value(result) {
            Ok(value) => value,
            Err(err) => {
                self.status = format!("error: {err}");
                return;
            }
        };
        let status = publish_status(action, &result);
        if self.messages_group_id.as_deref() == Some(group.as_str()) {
            if let Some(message_id) = result
                .get("message_ids")
                .and_then(Value::as_array)
                .and_then(|ids| ids.first())
                .and_then(Value::as_str)
            {
                let now = unix_now_seconds();
                let row = TimelineRow {
                    message_id: message_id.to_owned(),
                    direction: "sent".to_owned(),
                    from: account,
                    from_display_name: None,
                    plaintext: text.clone(),
                    display_text: text,
                    timeline_at: now,
                    received_at: now,
                    deleted: false,
                    reactions: Vec::new(),
                    reply: reply_to.map(|reply_to_message_id| TimelineReply {
                        reply_to_message_id,
                        preview: None,
                    }),
                    attachments: Vec::new(),
                };
                if let TimelineFoldOutcome::Inserted(index) =
                    apply_timeline_change(&mut self.timeline, TimelineChange::Upsert(Box::new(row)))
                {
                    self.timeline_scroll.on_insert(index, self.timeline.len());
                }
            } else {
                let _ = self.refresh_messages();
            }
        }
        self.status = status;
    }

    /// The message id of the currently selected timeline row. Errors when the
    /// pane is empty (nothing to target), surfaced on the status line.
    pub(crate) fn selected_timeline_message_id(&self) -> TuiResult<String> {
        let index = self
            .timeline_scroll
            .resolved_selection(self.timeline.len())
            .ok_or_else(|| TuiError::Cli("no message selected".to_owned()))?;
        Ok(self.timeline[index].message_id.clone())
    }

    /// React to the selected message (`messages react <group> <id> [emoji]`). The
    /// subprocess runs off the event loop; the timeline projection subscription
    /// folds the reaction in both directions, so the fold only updates status.
    pub(crate) fn react_to_selected_message(&mut self, emoji: String) -> TuiResult<()> {
        let effect = self.resolve_react(emoji)?;
        self.effects.enqueue(effect);
        self.status = "reacting...".to_owned();
        Ok(())
    }

    /// Resolve (without running) the react effect for the selected row.
    pub(crate) fn resolve_react(&self, emoji: String) -> TuiResult<Effect> {
        Ok(Effect::React {
            account: self.message_account_id()?,
            group: self.message_group_id()?,
            message_id: self.selected_timeline_message_id()?,
            emoji,
        })
    }

    /// Remove your own reaction from the selected message
    /// (`messages unreact <group> <id>`), off the event loop (see `react_...`).
    pub(crate) fn unreact_selected_message(&mut self) -> TuiResult<()> {
        let effect = self.resolve_unreact()?;
        self.effects.enqueue(effect);
        self.status = "removing reaction...".to_owned();
        Ok(())
    }

    pub(crate) fn resolve_unreact(&self) -> TuiResult<Effect> {
        Ok(Effect::Unreact {
            account: self.message_account_id()?,
            group: self.message_group_id()?,
            message_id: self.selected_timeline_message_id()?,
        })
    }

    /// Delete the selected message (`messages delete <group> <id>`) off the event
    /// loop. Delete only makes sense for your own messages; the ownership check
    /// runs at resolve time, so a clear status-line error fires before anything
    /// is queued. No list refetch: the projection tombstones the row.
    pub(crate) fn delete_selected_message(&mut self) -> TuiResult<()> {
        let effect = self.resolve_delete()?;
        self.effects.enqueue(effect);
        self.status = "deleting...".to_owned();
        Ok(())
    }

    pub(crate) fn resolve_delete(&self) -> TuiResult<Effect> {
        let account = self.message_account_id()?;
        let group = self.message_group_id()?;
        let index = self
            .timeline_scroll
            .resolved_selection(self.timeline.len())
            .ok_or_else(|| TuiError::Cli("no message selected".to_owned()))?;
        // Gate on the same ownership predicate the renderer uses to color a row
        // as yours, resolved against the loaded message account. A `direction`
        // check alone diverges: an own message arriving on the received path (a
        // second device, a re-sync echo) renders as yours but would be refused.
        if !timeline_row_is_self(&self.timeline[index], self.message_account_row()) {
            return Err(TuiError::Cli(
                "can only delete your own messages".to_owned(),
            ));
        }
        Ok(Effect::Delete {
            account,
            group,
            message_id: self.timeline[index].message_id.clone(),
        })
    }

    /// Retry a failed outbound event (`messages retry <group> <event-id>`). The
    /// event id is an explicit argument, not the selected row: timeline rows carry
    /// no failed-send state to target from (documented in the README).
    pub(crate) fn retry_message(&mut self, event_id: String) -> TuiResult<()> {
        let account_id = self.message_account_id()?;
        let group_id = self.message_group_id()?;
        self.client.run_json(
            Some(&account_id),
            &["messages", "retry", &group_id, &event_id],
        )?;
        self.status = format!("retried {}", shorten(&event_id, 18));
        Ok(())
    }

    pub(crate) fn send_image(
        &mut self,
        file_path: String,
        caption: Option<String>,
    ) -> TuiResult<()> {
        let account_id = self.message_account_id()?;
        let group_id = self.message_group_id()?;
        let args = media_upload_send_args(group_id, file_path, caption);
        let result = self.client.run_json(Some(&account_id), &args)?;
        self.refresh_messages()?;
        let file_name = result
            .get("attachments")
            .and_then(Value::as_array)
            .and_then(|attachments| attachments.first())
            .and_then(|attachment| attachment.get("media"))
            .and_then(|media| media.get("file_name"))
            .and_then(Value::as_str)
            .unwrap_or("media");
        let message_count = result
            .get("sent")
            .and_then(|sent| sent.get("message_ids"))
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default();
        self.status = format!("sent {file_name} ({message_count} message(s))");
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
                text: self.input.value().to_owned(),
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
        let args = self.client.with_setup_relay(vec![
            "profile".to_owned(),
            "update".to_owned(),
            "--name".to_owned(),
            name.clone(),
            "--display-name".to_owned(),
            name.clone(),
        ]);
        let result = self.client.run_json(Some(&account_id), &args)?;
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

    /// Enter the group-detail screen for the selected chat, loading its data
    /// (one-shot; no per-view subscriptions). A fresh selection starts at the top.
    pub(crate) fn open_group_detail(&mut self) -> TuiResult<()> {
        let group_id = self.require_selected_group()?;
        self.group_detail = None;
        self.load_group_detail(&group_id)?;
        self.screen = Screen::GroupDetail;
        // Honest in-flight feedback while the four-call load runs off-loop; the
        // fold clears it on settle.
        self.status = LOADING_GROUP_DETAIL_STATUS.to_owned();
        Ok(())
    }

    /// Load (or reload) the group-detail view off the event loop: members with
    /// admin badges (`groups members` + `groups admins`), relay hints
    /// (`groups relays`), and name/description (`groups show`). The member
    /// selection is preserved and clamped across reloads so a membership change
    /// never jumps the cursor.
    pub(crate) fn load_group_detail(&mut self, group_id: &str) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        self.loading_group_detail = Some(group_id.to_owned());
        self.effects.enqueue(Effect::LoadGroupDetail {
            account: account_id,
            group: group_id.to_owned(),
        });
        Ok(())
    }

    /// Fold a completed group-detail load. Dropped if a newer open superseded it
    /// or the screen was left (`loading_group_detail` is cleared on leave, and
    /// reloads of the same group keep it set so each reload still folds). The
    /// four results arrive in `calls()` order: members, admins, relays, show.
    fn fold_group_detail(
        &mut self,
        account: String,
        group: String,
        result: Result<Vec<Value>, String>,
    ) {
        if self.loading_group_detail.as_deref() != Some(group.as_str())
            || !matches!(self.screen, Screen::GroupDetail)
        {
            return;
        }
        let results = match result {
            Ok(values) => values,
            Err(err) => {
                self.status = format!("error: {err}");
                return;
            }
        };
        let [members_result, admins_result, relays_result, show_result] = results.as_slice() else {
            self.status = "group detail load returned unexpected results".to_owned();
            return;
        };
        let (name, description) = parse_group_profile(show_result).unwrap_or_else(|| {
            (
                self.selected_chat_row()
                    .map(|chat| chat.name.clone())
                    .unwrap_or_default(),
                String::new(),
            )
        });
        let members = parse_group_members(members_result);
        let admins = parse_group_admins(admins_result);
        let relays = parse_group_relays(relays_result);
        let previous = self.group_detail.as_ref().map_or(0, |view| view.selected);
        let mut view = build_group_detail(
            &group,
            &name,
            &description,
            &members,
            &admins,
            &relays,
            &account,
        );
        view.selected = previous.min(view.members.len().saturating_sub(1));
        self.group_detail = Some(view);
        // Clear the in-flight status now the load settled, but only if it is still
        // showing: a reload triggered by a mutation (rename/add/remove/promote)
        // has already set its own confirmation, which must not be clobbered.
        if self.status == LOADING_GROUP_DETAIL_STATUS {
            self.status = "group detail".to_owned();
        }
    }

    fn reload_group_detail_if_active(&mut self, group_id: &str) -> TuiResult<()> {
        if matches!(self.screen, Screen::GroupDetail) {
            self.load_group_detail(group_id)?;
        }
        Ok(())
    }

    pub(crate) fn rename_group(&mut self, group_id: &str, name: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let result = self.client.run_json(
            Some(&account_id),
            &["groups", "rename", group_id, name.as_str()],
        )?;
        let status = publish_status("renamed group", &result);
        self.reload_group_detail_if_active(group_id)?;
        self.refresh_chats()?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn add_group_member(&mut self, group_id: &str, pubkey: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let mut args = vec![
            "groups".to_owned(),
            "add-members".to_owned(),
            group_id.to_owned(),
        ];
        args.extend(unique_member_refs(vec![pubkey]));
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("added member(s)", &result);
        self.reload_group_detail_if_active(group_id)?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn remove_group_member(&mut self, group_id: &str, pubkey: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let mut args = vec![
            "groups".to_owned(),
            "remove-members".to_owned(),
            group_id.to_owned(),
        ];
        args.extend(unique_member_refs(vec![pubkey]));
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("removed member(s)", &result);
        self.reload_group_detail_if_active(group_id)?;
        self.status = status;
        Ok(())
    }

    pub(crate) fn promote_group_member(&mut self, group_id: &str, pubkey: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let result = self.client.run_json(
            Some(&account_id),
            &["groups", "promote", group_id, pubkey.as_str()],
        )?;
        let status = publish_status("promoted admin", &result);
        self.reload_group_detail_if_active(group_id)?;
        self.status = status;
        Ok(())
    }

    /// Leave the group and return to the main view. On success the chat is gone
    /// from the list, so the group-detail state is dropped and the chats are
    /// re-listed before the screen shows again.
    pub(crate) fn leave_group(&mut self, group_id: &str) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let result = self
            .client
            .run_json(Some(&account_id), &["groups", "leave", group_id])?;
        let status = publish_status("left group", &result);
        self.leave_group_detail();
        self.refresh_chats()?;
        self.status = status;
        Ok(())
    }

    /// Log out (permanently remove) an account via `wn logout <pubkey>`, then
    /// reload accounts and chats. `wn logout` is destructive: it removes the
    /// account's local data and signing key from this device. Because the
    /// selected account is usually its own target, it is gone from `account list`
    /// afterward, so this reuses the `/refresh` helper to reload accounts + chats
    /// and drop back to the login menu when the last account is removed — never
    /// leaving the TUI pointed at a removed account or a stale subscription (the
    /// account-switch and empty-account clearing both live in that refresh path).
    pub(crate) fn logout_account(&mut self, account_id: &str, npub: &str) -> TuiResult<()> {
        // The wipe is irreversible; its own failure still propagates (nothing was
        // removed, so `error:` is the honest report). But once it succeeds, the
        // account is gone whatever the follow-up reload does — reporting a reload
        // failure as `error:` would mask a completed wipe and leave the removed
        // account and its stale subscriptions on screen. So report the logout
        // unconditionally and fold a reload failure into the same status, naming
        // `/refresh` as the retry.
        self.client.run_json(None, &["logout", account_id])?;
        let logged_out = format!("logged out {}", shorten(&terminal_safe_text(npub), 18));
        self.status = match self.refresh_or_return_to_login() {
            Ok(()) => logged_out,
            Err(err) => {
                format!("{logged_out}; account list reload failed ({err}) — /refresh to retry")
            }
        };
        Ok(())
    }

    /// Open the pending-invites list picker (`groups invites`) off the event
    /// loop; the picker (or an empty-state info card) opens when the list lands.
    /// A load already in flight is not re-queued.
    pub(crate) fn open_invites(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        if self.loading_invites {
            return Ok(());
        }
        self.loading_invites = true;
        self.status = "loading invites...".to_owned();
        self.effects.enqueue(Effect::LoadInvites {
            account: account_id,
        });
        Ok(())
    }

    /// Fold the pending-invites list into the invites picker (an empty result
    /// shows an info card rather than an empty picker). The picker is not
    /// screen-scoped (it is reachable from both the main view and group detail),
    /// but it is anchored to the enqueuing account: a result whose account no
    /// longer matches the selection is dropped rather than opening a picker of a
    /// switched-away account's invites.
    fn fold_invites(&mut self, account: String, result: Result<Vec<Value>, String>) {
        if !self.loading_invites {
            return;
        }
        self.loading_invites = false;
        if self
            .selected_account_row()
            .map(|selected| selected.account_id.as_str())
            != Some(account.as_str())
        {
            return;
        }
        let result = match single_effect_value(result) {
            Ok(value) => value,
            Err(err) => {
                self.status = format!("error: {err}");
                return;
            }
        };
        let items = parse_invite_items(&result);
        let count = items.len();
        self.popup = Some(if items.is_empty() {
            Popup::info("Invites", "No pending invites.")
        } else {
            Popup::invites(items, 0)
        });
        self.status = format!("{count} pending invite(s)");
    }

    /// After an accept/decline from the invites picker, re-read the pending
    /// invites and refold the refreshed list back into the still-open picker,
    /// clamping the selection so one action does not lose the user's place. An
    /// empty result closes the picker; the accept/decline status already reports
    /// the outcome.
    pub(crate) fn refold_invites_picker(&mut self, prev_selected: usize) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let result = self
            .client
            .run_json(Some(&account_id), &["groups", "invites"])?;
        let items = parse_invite_items(&result);
        self.popup = match items.len() {
            0 => None,
            len => Some(Popup::invites(items, prev_selected.min(len - 1))),
        };
        Ok(())
    }

    /// Accept a pending invite, then refresh the chat list and select the newly
    /// joined chat so it is immediately open. Accepting from the group-detail
    /// screen returns to the main view: that screen shows the previously selected
    /// group, which the refreshed list and selection have now moved past.
    pub(crate) fn accept_invite(&mut self, group_id: &str) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        self.client
            .run_json(Some(&account_id), &["groups", "accept", group_id])?;
        self.refresh_chats()?;
        self.select_chat_by_group_id(group_id)?;
        if self.screen == Screen::GroupDetail {
            self.leave_group_detail();
        }
        self.status = format!("accepted invite {}", shorten(group_id, 18));
        Ok(())
    }

    pub(crate) fn decline_invite(&mut self, group_id: &str) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        self.client
            .run_json(Some(&account_id), &["groups", "decline", group_id])?;
        self.refresh_chats()?;
        self.status = format!("declined invite {}", shorten(group_id, 18));
        Ok(())
    }

    // ---- Phase 5b: user search, profile, and relay health ----

    /// Enter the user-search screen. A query (from `/users <query>`) runs
    /// immediately; an empty open lands on the query field awaiting input.
    pub(crate) fn open_user_search(&mut self, query: Option<String>) {
        let mut view = UserSearchView::default();
        if let Some(query) = query
            .map(|query| query.trim().to_owned())
            .filter(|q| !q.is_empty())
        {
            view.query.set_value(query);
        }
        let run_now = !view.query.is_empty();
        self.user_search = Some(view);
        self.screen = Screen::UserSearch;
        self.status = "user search".to_owned();
        if run_now && let Err(err) = self.run_user_search() {
            self.status = format!("error: {err}");
        }
    }

    /// Run the one-shot `users search <query>` off the event loop; the results
    /// fold into the view when they land. An empty query is a no-op with a hint.
    pub(crate) fn run_user_search(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let query = self
            .user_search
            .as_ref()
            .map(|view| view.query.value().trim().to_owned())
            .unwrap_or_default();
        if query.is_empty() {
            self.status = "type a query, then Enter to search".to_owned();
            return Ok(());
        }
        self.searching_users = Some(query.clone());
        self.status = "searching...".to_owned();
        self.effects.enqueue(Effect::UserSearch {
            account: account_id,
            query,
        });
        Ok(())
    }

    /// Fold a completed user search into the view, dropping a result whose query
    /// no longer matches the pending search (a newer query superseded it) or
    /// whose screen has been left.
    fn fold_user_search(&mut self, query: String, result: Result<Vec<Value>, String>) {
        if self.searching_users.as_deref() != Some(query.as_str()) {
            return;
        }
        self.searching_users = None;
        if self.user_search.is_none() {
            return;
        }
        let result = match single_effect_value(result) {
            Ok(value) => value,
            Err(err) => {
                self.status = format!("error: {err}");
                return;
            }
        };
        let results = parse_user_search_results(&result);
        let count = results.len();
        if let Some(view) = self.user_search.as_mut() {
            view.focus = if results.is_empty() {
                UserSearchFocus::Query
            } else {
                UserSearchFocus::Results
            };
            view.results = results;
            view.selected = 0;
        }
        self.status = format!("found {count} user(s)");
    }

    /// Open the dismiss-on-any-key profile card for the selected search result
    /// (`users show <pubkey>`).
    pub(crate) fn open_search_profile_card(&mut self) -> TuiResult<()> {
        let Some(pubkey) = self
            .user_search
            .as_ref()
            .and_then(UserSearchView::selected_result)
            .map(|result| result.pubkey.clone())
        else {
            return Ok(());
        };
        let result = self.client.run_json(None, &["users", "show", &pubkey])?;
        self.popup = Some(Popup::Card {
            title: "Profile".to_owned(),
            body: profile_card_lines(&result),
        });
        Ok(())
    }

    /// Enter the own-profile screen, loading fields (`profile show`) and follows
    /// (`follows list`) as a one-shot read.
    pub(crate) fn open_profile(&mut self) -> TuiResult<()> {
        self.profile_view = None;
        self.load_profile()?;
        self.screen = Screen::Profile;
        self.status = "profile".to_owned();
        Ok(())
    }

    /// Load (or reload) the profile view, preserving and clamping the cursor so a
    /// field edit or (un)follow never jumps the selection.
    pub(crate) fn load_profile(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let show = self
            .client
            .run_json(Some(&account_id), &["profile", "show"])?;
        let follows = self
            .client
            .run_json(Some(&account_id), &["follows", "list"])?;
        let previous = self.profile_view.as_ref().map_or(0, |view| view.selected);
        let mut view = parse_profile_view(&show, &follows);
        view.selected = previous.min(view.row_count().saturating_sub(1));
        self.profile_view = Some(view);
        Ok(())
    }

    /// Publish a single profile field (`profile update --<field> <value>`). The
    /// CLI fetches the current profile and overlays only this flag, so the other
    /// fields survive. Reloads the profile and account list on success.
    pub(crate) fn update_profile_field(
        &mut self,
        field: ProfileField,
        value: String,
    ) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let args = self.client.with_setup_relay(vec![
            "profile".to_owned(),
            "update".to_owned(),
            field.flag().to_owned(),
            value,
        ]);
        self.client.run_json(Some(&account_id), &args)?;
        self.load_profile()?;
        self.refresh_accounts()?;
        self.status = format!("updated {}", field.label());
        Ok(())
    }

    pub(crate) fn follow_user(&mut self, pubkey: &str) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let args = self.client.with_setup_relay(vec![
            "follows".to_owned(),
            "add".to_owned(),
            pubkey.to_owned(),
        ]);
        self.client.run_json(Some(&account_id), &args)?;
        self.reload_follows()?;
        self.status = format!("followed {}", shorten(pubkey, 18));
        Ok(())
    }

    pub(crate) fn unfollow_user(&mut self, pubkey: &str) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let args = self.client.with_setup_relay(vec![
            "follows".to_owned(),
            "remove".to_owned(),
            pubkey.to_owned(),
        ]);
        self.client.run_json(Some(&account_id), &args)?;
        self.reload_follows()?;
        self.status = format!("unfollowed {}", shorten(pubkey, 18));
        Ok(())
    }

    fn reload_follows(&mut self) -> TuiResult<()> {
        if self.profile_view.is_some() {
            self.load_profile()?;
        }
        Ok(())
    }

    /// Enter the relay-health screen, loading the redacted `relay-stats` snapshot.
    /// `relay-stats` reads the live `wnd` runtime when a socket exists and falls
    /// back to a fresh in-process read otherwise, so it always returns a snapshot.
    pub(crate) fn open_relay_health(&mut self) -> TuiResult<()> {
        let data = self.load_relay_health()?;
        self.relay_health = Some(RelayHealthView { data, scroll: 0 });
        self.screen = Screen::RelayHealth;
        self.status = "relay health".to_owned();
        Ok(())
    }

    /// Re-read `relay-stats`, preserving the scroll offset.
    pub(crate) fn refresh_relay_health(&mut self) -> TuiResult<()> {
        let data = self.load_relay_health()?;
        let scroll = self.relay_health.as_ref().map_or(0, |view| view.scroll);
        self.relay_health = Some(RelayHealthView { data, scroll });
        self.status = "refreshed relay health".to_owned();
        Ok(())
    }

    fn load_relay_health(&mut self) -> TuiResult<RelayHealthData> {
        let result = self.client.run_json(None, &["relay-stats"])?;
        Ok(parse_relay_health(&result, self.daemon.running))
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

    pub(crate) fn set_selected_chat_muted(&mut self, duration: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let result = self
            .client
            .run_json(Some(&account_id), &["chats", "mute", &group_id, &duration])?;
        let muted_until = result.get("muted_until_ms").and_then(Value::as_i64);
        self.status = match muted_until {
            Some(until) => format!("muted chat {} until {}", shorten(&group_id, 18), until),
            None => format!("muted chat {} forever", shorten(&group_id, 18)),
        };
        Ok(())
    }

    pub(crate) fn clear_selected_chat_muted(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        self.client
            .run_json(Some(&account_id), &["chats", "unmute", &group_id])?;
        self.status = format!("unmuted chat {}", shorten(&group_id, 18));
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
        let invocation = account_setup_invocation(identity, self.client.account_setup_relay());
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
        self.ensure_selected_timeline_subscription();
        self.ensure_selected_notification_subscription();
        Ok(())
    }

    pub(crate) fn start_daemon(&mut self) -> TuiResult<()> {
        let args = daemon_start_args(
            &self.client.discovery_relays,
            &self.client.default_account_relays,
        );
        let result = self.client.run_json(None, &args)?;
        self.daemon = parse_daemon_view(&result);
        self.ensure_selected_chat_subscription();
        self.ensure_selected_message_subscription();
        self.ensure_selected_group_state_subscription();
        self.ensure_selected_timeline_subscription();
        self.ensure_selected_notification_subscription();
        self.status = daemon_status_sentence(&self.daemon);
        Ok(())
    }

    pub(crate) fn stop_daemon(&mut self) -> TuiResult<()> {
        let result = self.client.run_json(None, &["daemon", "stop"])?;
        self.daemon = parse_daemon_view(&result);
        self.chat_subscription = None;
        self.message_subscription = None;
        self.group_state_subscription = None;
        self.timeline_subscription = None;
        self.notification_subscription = None;
        self.status = "daemon stopped".to_owned();
        Ok(())
    }

    /// Reload just the account list (`wn account list`), reselecting the
    /// previously active account, and clear all chat/message/subscription state
    /// when no accounts remain. Does not load chats or route the screen; the
    /// startup/login flow decides the screen from the resulting account count.
    pub(crate) fn load_accounts(&mut self) -> TuiResult<()> {
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
            self.clear_timeline_pane();
            self.messages_account_id = None;
            self.messages_group_id = None;
            self.chat_subscription = None;
            self.message_subscription = None;
            self.group_state_subscription = None;
            self.notification_subscription = None;
            self.group_diagnostics = None;
            self.status = "no identities yet; create one from the login screen".to_owned();
        }
        Ok(())
    }

    pub(crate) fn refresh_accounts(&mut self) -> TuiResult<()> {
        self.load_accounts()?;
        if self.accounts.is_empty() {
            return Ok(());
        }
        self.refresh_chats()
    }

    pub(crate) fn refresh_chats(&mut self) -> TuiResult<()> {
        let Some(account) = self.selected_account_row().cloned() else {
            self.chats.clear();
            self.clear_timeline_pane();
            self.messages_account_id = None;
            self.messages_group_id = None;
            self.chat_subscription = None;
            self.message_subscription = None;
            self.group_state_subscription = None;
            self.notification_subscription = None;
            self.group_diagnostics = None;
            self.status = "no account selected".to_owned();
            return Ok(());
        };
        if !account.local_signing {
            self.chats.clear();
            self.clear_timeline_pane();
            self.messages_account_id = None;
            self.messages_group_id = None;
            self.chat_subscription = None;
            self.message_subscription = None;
            self.group_state_subscription = None;
            self.notification_subscription = None;
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
        sort_chats_by_activity(&mut self.chats);
        self.selected_chat =
            selected_chat_index(&self.chats, previous_group_id.as_deref()).unwrap_or(0);
        if let Err(err) = self.ensure_chat_subscription(&account.account_id) {
            self.status = format!("chat subscription failed: {err}");
        }
        if let Err(err) = self.ensure_notification_subscription(&account.account_id) {
            self.status = format!("notification subscription failed: {err}");
        }
        if self.chats.is_empty() {
            self.clear_timeline_pane();
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

    /// Load (or reload) the selected chat's timeline off the event loop. Resolves
    /// the selected account/group synchronously (a clear error if either is
    /// missing) and hands the load to the effect worker; the page, subscriptions,
    /// mark-read, and diagnostics are folded in when the result lands.
    pub(crate) fn refresh_messages(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        self.begin_timeline_load(account_id, group_id);
        Ok(())
    }

    /// Reset the pane to a loading state (only when switching to a different
    /// group, so a same-chat reload never flashes empty), tag the pending target
    /// for the stale guard, and queue the timeline load.
    pub(crate) fn begin_timeline_load(&mut self, account_id: String, group_id: String) {
        // Any explicit or fired load supersedes a pending flick-through preview.
        self.flick_countdown = None;
        if self.messages_group_id.as_deref() != Some(group_id.as_str()) {
            // Drop the prior chat's pane and its per-group subscriptions so their
            // drains cannot pollute the pane while the new chat loads.
            self.clear_timeline_pane();
            self.messages_group_id = None;
            self.group_state_subscription = None;
            self.group_diagnostics = None;
        }
        self.loading_chat = Some(group_id.clone());
        self.status = "loading chat...".to_owned();
        self.effects.enqueue(Effect::LoadTimeline {
            account: account_id,
            group: group_id,
        });
    }

    /// Fold a completed timeline load into the pane, exactly as the synchronous
    /// path did after its `run_json` returned — but dropping a result whose group
    /// no longer matches the pending target (a newer open superseded it).
    fn fold_load_timeline(
        &mut self,
        account: String,
        group: String,
        result: Result<Vec<Value>, String>,
    ) {
        if self.loading_chat.as_deref() != Some(group.as_str()) {
            return;
        }
        let result = match single_effect_value(result) {
            Ok(value) => value,
            Err(err) => {
                self.loading_chat = None;
                self.status = format!("error: {err}");
                return;
            }
        };
        if self.messages_group_id.as_deref() == Some(group.as_str()) {
            // Same-chat reload: the pane and its timeline subscription stayed live
            // (a different-chat open clears them and reloads fresh, so a stale
            // fold there is harmless). A subscription insert may have landed
            // between enqueue and now; merging the page in by id — the same
            // idempotent upsert-by-id fold the subscription and history paging
            // use — keeps those live rows instead of erasing them with a full
            // replace, and preserves the existing scroll/pin (the pane was never
            // reset). A genuinely new page row shifts the scroll exactly as a live
            // insert would; a row already present is an idempotent update.
            for row in parse_timeline_page(&result) {
                if let TimelineFoldOutcome::Inserted(index) =
                    apply_timeline_change(&mut self.timeline, TimelineChange::Upsert(Box::new(row)))
                {
                    self.timeline_scroll.on_insert(index, self.timeline.len());
                }
            }
        } else {
            // Different-chat open: the pane was cleared on enqueue, so replace it
            // with the fresh page and reset the scroll to the pinned default.
            self.timeline = parse_timeline_page(&result);
            self.timeline_scroll = TimelineScroll {
                has_more_before: timeline_page_has_more_before(&result),
                ..TimelineScroll::default()
            };
        }
        self.messages_account_id = Some(account.clone());
        self.messages_group_id = Some(group.clone());
        self.loading_chat = None;
        // Establish all three subscriptions regardless of any one's outcome. The
        // timeline feed drives the pane's live updates and its `ensure_*` also
        // kills a stale prior-group child, so a failed plain feed must not skip
        // it. Each error surfaces on the status line; the user sees the first by
        // precedence (message, then timeline, then group state).
        let message_subscription_error = self
            .ensure_message_subscription(&account)
            .err()
            .map(|err| format!("message subscription failed: {err}"));
        let timeline_subscription_error = self
            .ensure_timeline_subscription(&account, &group)
            .err()
            .map(|err| format!("timeline subscription failed: {err}"));
        let group_state_subscription_error = self
            .ensure_group_state_subscription(&account, &group)
            .err()
            .map(|err| format!("group state subscription failed: {err}"));
        if self.daemon.running && group_state_subscription_error.is_none() {
            if self
                .group_diagnostics
                .as_ref()
                .is_none_or(|diagnostics| diagnostics.group_id != group)
            {
                self.group_diagnostics =
                    Some(GroupDiagnostics::unavailable(&group, "loading group state"));
            }
        } else {
            // No daemon (or its state feed failed): fetch diagnostics off-loop.
            self.effects.enqueue(Effect::GroupDiagnostics {
                account: account.clone(),
                group: group.clone(),
            });
        }
        // Opening a chat clears its badge: mark it read off-loop and fold the
        // returned projection into the row rather than waiting for a push (the
        // chats feed does not emit one after a local mark-read).
        self.effects.enqueue(Effect::MarkRead { account, group });
        self.status = message_subscription_error
            .or(timeline_subscription_error)
            .or(group_state_subscription_error)
            .unwrap_or_else(|| format!("loaded {} message(s)", self.timeline.len()));
    }

    /// Fold a completed mark-read: apply the returned projection to the chat's
    /// row, clearing the badge. The runtime read marker is forward-only, so
    /// re-marking is idempotent. On failure the badge is left honest (never
    /// zeroed locally) and the mark-read is re-armed for the next tick.
    fn fold_mark_read(&mut self, group: String, result: Result<Vec<Value>, String>) {
        match single_effect_value(result) {
            Ok(value) => {
                fold_chat_projection(
                    &mut self.chats,
                    &mut self.selected_chat,
                    &group,
                    parse_chat_projection(&value),
                );
            }
            Err(err) => {
                self.pending_mark_read = true;
                self.set_drain_status(format!("mark-read failed: {err}"));
            }
        }
    }

    /// Fold group diagnostics for the loaded chat (the no-daemon fallback),
    /// dropping the result if the pane has since moved to another group.
    fn fold_group_diagnostics(&mut self, group: String, result: Result<Vec<Value>, String>) {
        if self.messages_group_id.as_deref() != Some(group.as_str()) {
            return;
        }
        self.group_diagnostics = Some(match single_effect_value(result) {
            Ok(value) => parse_group_diagnostics(&value).unwrap_or_else(|| {
                GroupDiagnostics::unavailable(
                    &group,
                    "groups show did not return group diagnostics",
                )
            }),
            Err(err) => GroupDiagnostics::unavailable(&group, err),
        });
    }

    /// Fold a completed background chats re-list (the debounced response to a
    /// notification for a non-selected chat). Refreshes each row's projection
    /// (unread + last-message) and re-orders by activity while preserving the
    /// messages pane, its subscriptions, and the highlighted chat by group id.
    /// Unlike `refresh_chats` this never reloads the timeline or resets
    /// subscriptions, and it is silent on success (ambient) so it never clobbers
    /// the status line.
    fn fold_relist(&mut self, account: String, result: Result<Vec<Value>, String>) {
        // Anchor to the enqueuing account: if the selection changed while the
        // re-list was in flight, its rows belong to a different account — dropping
        // them here keeps the fold from clobbering the now-selected account's chats
        // with a stale account's list.
        if self
            .selected_account_row()
            .map(|account| account.account_id.as_str())
            != Some(account.as_str())
        {
            return;
        }
        let value = match single_effect_value(result) {
            Ok(value) => value,
            Err(err) => {
                // Re-arm like the synchronous path did so a transient failure
                // retries next tick instead of dropping the batch.
                self.pending_chat_relist = true;
                self.set_drain_status(format!("chat re-list failed: {err}"));
                return;
            }
        };
        // Capture the selected chat BEFORE replacing the list, then reselect it by
        // group id after resorting. A naive resort-preserving-selection helper here
        // would read the old index into the freshly parsed (unsorted) list and jump
        // the highlight onto a different chat.
        let previous_group_id = self.selected_chat_row().map(|chat| chat.group_id.clone());
        self.chats = value
            .get("chats")
            .and_then(Value::as_array)
            .map(|chats| chats.iter().filter_map(parse_chat).collect())
            .unwrap_or_default();
        sort_chats_by_activity(&mut self.chats);
        self.selected_chat = selected_chat_index(&self.chats, previous_group_id.as_deref())
            .unwrap_or_else(|| self.selected_chat.min(self.chats.len().saturating_sub(1)));
    }

    /// Fetch and prepend the previous history page. Runs synchronously like every
    /// other TUI action; `loading_older` guards against re-entry and is cleared on
    /// both the success and error paths so a failed page does not wedge paging.
    pub(crate) fn load_older_messages(&mut self) -> TuiResult<()> {
        let Some(cursor) = oldest_timeline_cursor(&self.timeline) else {
            return Ok(());
        };
        let account_id = self.message_account_id()?;
        let group_id = self.message_group_id()?;
        let args = vec![
            "messages".to_owned(),
            "timeline".to_owned(),
            "list".to_owned(),
            "--group".to_owned(),
            group_id,
            "--before".to_owned(),
            cursor.timeline_at.to_string(),
            "--before-message-id".to_owned(),
            cursor.message_id,
            "--limit".to_owned(),
            TUI_TIMELINE_PAGE_SIZE.to_string(),
        ];
        self.timeline_scroll.loading_older = true;
        let result = match self.client.run_json(Some(&account_id), &args) {
            Ok(result) => result,
            Err(err) => {
                self.timeline_scroll.loading_older = false;
                return Err(err);
            }
        };
        // Rows arrive oldest-first. Upsert each by id — the only merge that stays
        // idempotent if the exclusive cursor ever overlaps — and shift the scroll
        // model by the count of genuinely new rows so an overlap neither duplicates
        // a row nor over-shifts the selection.
        let older = parse_timeline_page(&result);
        let mut prepended = 0;
        for row in older {
            if let TimelineFoldOutcome::Inserted(_) =
                apply_timeline_change(&mut self.timeline, TimelineChange::Upsert(Box::new(row)))
            {
                prepended += 1;
            }
        }
        self.timeline_scroll.on_prepend(prepended);
        self.timeline_scroll.has_more_before = timeline_page_has_more_before(&result);
        self.timeline_scroll.loading_older = false;
        self.status = format!("loaded {prepended} older message(s)");
        Ok(())
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

    pub(crate) fn ensure_timeline_subscription(
        &mut self,
        account_id: &str,
        group_id: &str,
    ) -> TuiResult<()> {
        if !self.daemon.running {
            self.timeline_subscription = None;
            return Ok(());
        }
        if self
            .timeline_subscription
            .as_ref()
            .is_some_and(|subscription| {
                subscription.account_id == account_id && subscription.group_id == group_id
            })
        {
            return Ok(());
        }

        self.timeline_subscription = None;
        let args = timeline_subscription_args(group_id);
        let mut child = self.client.spawn_json_lines(Some(account_id), &args)?;
        let rx = spawn_subscription_reader(&mut child, "timeline")?;
        self.timeline_subscription = Some(TimelineSubscription {
            account_id: account_id.to_owned(),
            group_id: group_id.to_owned(),
            child,
            rx,
        });
        Ok(())
    }

    /// Keep the runtime-wide notification subscription alive for `account_id`.
    /// Account-keyed (not per group) like the message feed, and daemon-only: with
    /// no daemon it is dropped. Idempotent — a live child for the same account is
    /// left in place. Same keyed re-spawn / Drop lifecycle as the other feeds.
    pub(crate) fn ensure_notification_subscription(&mut self, account_id: &str) -> TuiResult<()> {
        if !self.daemon.running {
            self.notification_subscription = None;
            return Ok(());
        }
        if self
            .notification_subscription
            .as_ref()
            .is_some_and(|subscription| subscription.account_id == account_id)
        {
            return Ok(());
        }

        self.notification_subscription = None;
        let args = notification_subscription_args();
        let mut child = self.client.spawn_json_lines(Some(account_id), &args)?;
        let rx = spawn_subscription_reader(&mut child, "notification")?;
        self.notification_subscription = Some(NotificationSubscription {
            account_id: account_id.to_owned(),
            child,
            rx,
        });
        Ok(())
    }

    /// Clear the messages pane: drop the loaded timeline rows, reset the scroll
    /// model to its pinned default, and stop the per-group timeline subscription.
    pub(crate) fn clear_timeline_pane(&mut self) {
        self.timeline.clear();
        self.timeline_scroll = TimelineScroll::default();
        self.timeline_subscription = None;
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

    /// Re-establish the timeline subscription for the currently loaded group (the
    /// pane target), used when daemon state changes. Keyed to the loaded group,
    /// not the highlighted chat, so it stays in lockstep with the pane snapshot.
    pub(crate) fn ensure_selected_timeline_subscription(&mut self) {
        let (Some(account_id), Some(group_id)) = (
            self.messages_account_id.clone(),
            self.messages_group_id.clone(),
        ) else {
            self.timeline_subscription = None;
            return;
        };
        if let Err(err) = self.ensure_timeline_subscription(&account_id, &group_id) {
            self.status = format!("timeline subscription failed: {err}");
        }
    }

    /// Re-establish the runtime-wide notification subscription for the selected
    /// local signing account, dropping it for no account or a public-only one.
    /// Mirrors `ensure_selected_message_subscription`; both are account-wide.
    pub(crate) fn ensure_selected_notification_subscription(&mut self) {
        let Some(account) = self.selected_account_row().cloned() else {
            self.notification_subscription = None;
            return;
        };
        if !account.local_signing {
            self.notification_subscription = None;
            return;
        }
        if let Err(err) = self.ensure_notification_subscription(&account.account_id) {
            self.status = format!("notification subscription failed: {err}");
        }
    }

    /// Assign a status produced by a background drain, but only while the main
    /// view is showing. On the login/account-select screen the status line
    /// carries the nsec prompt and picker guidance; a live drain (a picker
    /// reached via `A` keeps its subscriptions running) must apply its state
    /// changes without clobbering that prompt.
    pub(crate) fn set_drain_status(&mut self, status: String) {
        if self.screen == Screen::Main {
            self.status = status;
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
                        self.set_drain_status(status);
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.set_drain_status(format!("chat subscription failed: {err}"));
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
                self.clear_timeline_pane();
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
                            self.set_drain_status(status);
                        }
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.set_drain_status(format!("group state subscription failed: {err}"));
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
                    // The plain feed drives only QUIC stream previews now (unread
                    // is runtime-backed). Skip initial replays, then apply preview
                    // updates; no local counting happens here.
                    if !is_initial_subscription_result(&result)
                        && let Some(status) =
                            apply_subscription_result(&mut self.live_stream_previews, &result)
                    {
                        self.set_drain_status(status);
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.set_drain_status(format!("message subscription failed: {err}"));
                }
                SubscriptionEvent::Ended => {
                    self.message_subscription = None;
                    break;
                }
            }
        }
        true
    }

    pub(crate) fn drain_timeline_subscription(&mut self) -> bool {
        let Some(subscription) = self.timeline_subscription.as_ref() else {
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
        let loaded_group_id = self.messages_group_id.clone();
        for event in events {
            match event {
                SubscriptionEvent::Result(result) => {
                    // The timeline feed is the live source for the loaded chat's
                    // badge and preview: fold its `chat_list_row` into that chat's
                    // row (the chats feed does not push these), then drive the pane.
                    if let Some((group_id, projection)) = timeline_chat_list_row(&result) {
                        // Viewing is reading: if the imported count for the
                        // viewed chat is nonzero, schedule a mark-read so the
                        // badge clears instead of re-accruing as we read.
                        if should_mark_loaded_chat_read(
                            loaded_group_id.as_deref(),
                            &group_id,
                            &projection,
                        ) {
                            self.pending_mark_read = true;
                        }
                        fold_chat_projection(
                            &mut self.chats,
                            &mut self.selected_chat,
                            &group_id,
                            projection,
                        );
                    }
                    apply_timeline_event(
                        &mut self.timeline,
                        &mut self.timeline_scroll,
                        loaded_group_id.as_deref(),
                        parse_timeline_event(&result),
                    );
                }
                SubscriptionEvent::Error(err) => {
                    self.set_drain_status(format!("timeline subscription failed: {err}"));
                }
                SubscriptionEvent::Ended => {
                    self.timeline_subscription = None;
                    break;
                }
            }
        }
        true
    }

    /// Drain the runtime-wide notification feed. Each event folds through the
    /// pure `apply_notification_event` reducer, which deduplicates by
    /// `notification_key`: a NewMessage for a non-loaded chat sets the debounce
    /// flag (tick coalesces to one re-list), a GroupInvite surfaces a status
    /// notice, and everything else is ignored.
    pub(crate) fn drain_notification_subscription(&mut self) -> bool {
        let Some(subscription) = self.notification_subscription.as_ref() else {
            return false;
        };
        // The feed is runtime-wide, so it carries every local account's events;
        // filter by the envelope account against the account this subscription
        // was opened for before acting on any of them.
        let subscription_account_id = subscription.account_id.clone();
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
        let loaded_group_id = self.messages_group_id.clone();
        for event in events {
            match event {
                SubscriptionEvent::Result(result) => {
                    // Drop another account's notification before it can insert a
                    // dedup key, arm a re-list, or surface a notice on this
                    // account's status line.
                    if notification_event_account(&result)
                        .is_some_and(|account| account != subscription_account_id)
                    {
                        continue;
                    }
                    if let NotificationOutcome::Invite(notice) = apply_notification_event(
                        &mut self.seen_notification_keys,
                        &mut self.pending_chat_relist,
                        loaded_group_id.as_deref(),
                        parse_notification_event(&result),
                    ) {
                        self.set_drain_status(notice);
                    }
                }
                SubscriptionEvent::Error(err) => {
                    self.set_drain_status(format!("notification subscription failed: {err}"));
                }
                SubscriptionEvent::Ended => {
                    self.notification_subscription = None;
                    break;
                }
            }
        }
        true
    }
}
