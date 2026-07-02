//! `TuiApp` state plus the event loop, key handling, and selection methods.

use super::*;

pub(crate) struct TuiApp {
    pub(crate) client: DmClient,
    pub(crate) initial_account: Option<String>,
    pub(crate) running: bool,
    pub(crate) focus: Focus,
    pub(crate) accounts: Vec<AccountRow>,
    pub(crate) selected_account: usize,
    pub(crate) chats: Vec<ChatRow>,
    pub(crate) selected_chat: usize,
    pub(crate) messages_account_id: Option<String>,
    pub(crate) messages_group_id: Option<String>,
    pub(crate) unread_counts: HashMap<String, usize>,
    pub(crate) show_archived_chats: bool,
    pub(crate) messages: Vec<MessageRow>,
    pub(crate) messages_scroll: u16,
    pub(crate) messages_viewport: u16,
    pub(crate) live_stream_previews: Vec<LiveStreamPreview>,
    pub(crate) chat_subscription: Option<ChatSubscription>,
    pub(crate) message_subscription: Option<MessageSubscription>,
    pub(crate) group_state_subscription: Option<GroupStateSubscription>,
    pub(crate) daemon: DaemonView,
    pub(crate) group_diagnostics: Option<GroupDiagnostics>,
    pub(crate) input: String,
    pub(crate) streaming: Option<StreamComposer>,
    pub(crate) status: String,
    pub(crate) show_help: bool,
}

impl TuiApp {
    pub(crate) fn new(cli: Cli) -> TuiResult<Self> {
        let client = DmClient::from_cli(&cli)?;
        Ok(Self {
            client,
            initial_account: cli.account.clone(),
            running: true,
            focus: Focus::Composer,
            accounts: Vec::new(),
            selected_account: 0,
            chats: Vec::new(),
            selected_chat: 0,
            messages_account_id: None,
            messages_group_id: None,
            unread_counts: HashMap::new(),
            show_archived_chats: false,
            messages: Vec::new(),
            messages_scroll: 0,
            messages_viewport: 0,
            live_stream_previews: Vec::new(),
            chat_subscription: None,
            message_subscription: None,
            group_state_subscription: None,
            daemon: DaemonView::default(),
            group_diagnostics: None,
            input: String::new(),
            streaming: None,
            status: "loading accounts".to_owned(),
            show_help: false,
        })
    }

    pub(crate) fn run(&mut self) -> TuiResult<()> {
        let mut terminal = ratatui::init();
        let result = (|| -> TuiResult<()> {
            let _ = self.refresh_daemon_status();
            self.refresh_accounts()?;
            let mut dirty = true;
            while self.running {
                dirty |= self.tick();
                if dirty {
                    terminal.draw(|frame| self.render(frame))?;
                    dirty = false;
                }
                if event::poll(UI_EVENT_WAIT)? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            self.handle_key(key)?;
                            dirty = true;
                        }
                        _ => {
                            dirty = true;
                        }
                    }
                }
            }
            Ok(())
        })();
        ratatui::restore();
        result
    }

    pub(crate) fn tick(&mut self) -> bool {
        let now = Instant::now();
        let mut changed = false;
        changed |= self.drain_chat_subscription();
        changed |= self.drain_group_state_subscription();
        changed |= self.drain_message_subscription();
        match self.flush_stream_append_if_due(now) {
            Ok(flushed) => changed |= flushed,
            Err(err) => {
                self.status = format!("stream append failed: {err}");
                changed = true;
            }
        }
        changed
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return Ok(());
        }
        if self.streaming.is_some() {
            // Streaming key handling (finish/cancel/append) performs fallible
            // daemon/relay operations. Mirror the non-streaming Enter path and
            // tick(): catch errors into the status line instead of propagating
            // them out of run() and tearing down the whole TUI session. The
            // composer state is preserved on failures that keep `self.streaming`
            // set, so the user can retry Enter/Esc.
            if let Err(err) = self.handle_streaming_key(key) {
                self.status = format!("error: {err}");
            }
            return Ok(());
        }

        match key.code {
            KeyCode::Char('?') if self.focus != Focus::Composer => {
                self.show_help = !self.show_help;
            }
            KeyCode::Char('q') if self.focus != Focus::Composer && self.input.is_empty() => {
                self.running = false;
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.previous(),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::PageUp => {
                let by = self.messages_page();
                self.scroll_messages_up(by);
            }
            KeyCode::PageDown => {
                let by = self.messages_page();
                self.scroll_messages_down(by);
            }
            KeyCode::Home => {
                self.messages_scroll = u16::MAX;
            }
            KeyCode::End => {
                self.messages_scroll = 0;
            }
            KeyCode::Enter => {
                if let Err(err) = self.activate_focus() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Esc => {
                self.show_help = false;
                self.input.clear();
            }
            KeyCode::Backspace if self.focus == Focus::Composer => {
                self.input.pop();
            }
            KeyCode::Char('/') if self.focus != Focus::Composer => {
                self.show_help = false;
                self.focus = Focus::Composer;
                self.input.push('/');
            }
            KeyCode::Char('j') if self.focus != Focus::Composer => self.move_selection(1),
            KeyCode::Char('k') if self.focus != Focus::Composer => self.move_selection(-1),
            KeyCode::Char(character) if self.focus == Focus::Composer => {
                self.show_help = false;
                self.input.push(character);
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn move_selection(&mut self, delta: isize) {
        match self.focus {
            Focus::Accounts => {
                self.selected_account =
                    move_index(self.selected_account, self.accounts.len(), delta);
            }
            Focus::Chats => {
                self.selected_chat = move_index(self.selected_chat, self.chats.len(), delta);
            }
            Focus::Messages => {
                if delta < 0 {
                    self.scroll_messages_up(1);
                } else if delta > 0 {
                    self.scroll_messages_down(1);
                }
            }
            Focus::Composer => {}
        }
    }

    pub(crate) fn messages_page(&self) -> u16 {
        self.messages_viewport.saturating_sub(1).max(1)
    }

    pub(crate) fn scroll_messages_up(&mut self, by: u16) {
        self.messages_scroll = self.messages_scroll.saturating_add(by);
    }

    pub(crate) fn scroll_messages_down(&mut self, by: u16) {
        self.messages_scroll = self.messages_scroll.saturating_sub(by);
    }

    pub(crate) fn activate_focus(&mut self) -> TuiResult<()> {
        match self.focus {
            Focus::Accounts => self.select_current_account(),
            Focus::Chats => self.refresh_messages(),
            Focus::Messages => Ok(()),
            Focus::Composer => self.submit_input(),
        }
    }

    pub(crate) fn submit_input(&mut self) -> TuiResult<()> {
        let input = self.input.trim().to_owned();
        self.input.clear();
        if input.is_empty() {
            return Ok(());
        }
        if input.starts_with('/') {
            let command = parse_slash_command(&input).map_err(TuiError::Cli)?;
            return self.run_slash_command(command);
        }
        self.send_message(input)
    }

    pub(crate) fn handle_streaming_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        match key.code {
            KeyCode::Enter => self.finish_stream_composer(),
            KeyCode::Esc => self.cancel_stream_composer(),
            KeyCode::Backspace => {
                self.status =
                    "stream editing is append-only in this preview; Esc cancels".to_owned();
                Ok(())
            }
            KeyCode::Char(character) => {
                self.input.push(character);
                let mut stream_id = None;
                if let Some(streaming) = self.streaming.as_mut() {
                    streaming.pending_text.push(character);
                    stream_id = Some(streaming.stream_id.clone());
                    self.status = format!(
                        "queued {} byte(s) on {}",
                        streaming.pending_text.len(),
                        shorten(&streaming.stream_id, 18)
                    );
                }
                if let Some(stream_id) = stream_id {
                    self.upsert_active_stream_preview(&stream_id);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn run_slash_command(&mut self, command: SlashCommand) -> TuiResult<()> {
        match command {
            SlashCommand::Help => {
                self.show_help = true;
                Ok(())
            }
            SlashCommand::Refresh => self.refresh_accounts(),
            SlashCommand::Account(selector) => self.select_account_by_selector(&selector),
            SlashCommand::AccountCreate => self.create_or_import_account(None, "created identity"),
            SlashCommand::AccountAddPublic(account) => {
                self.create_or_import_account(Some(account), "logged in public identity")
            }
            SlashCommand::AccountImportSecret(secret) => {
                self.create_or_import_account(Some(secret), "logged in identity")
            }
            SlashCommand::DaemonStatus => {
                self.refresh_daemon_status()?;
                self.status = daemon_status_sentence(&self.daemon);
                Ok(())
            }
            SlashCommand::DaemonStart => self.start_daemon(),
            SlashCommand::DaemonStop => self.stop_daemon(),
            SlashCommand::ChatNew { name, members } => self.create_chat(name, members),
            SlashCommand::ChatRename(name) => self.update_selected_chat(Some(name), None),
            SlashCommand::ChatDescribe(description) => {
                self.update_selected_chat(None, Some(description))
            }
            SlashCommand::ChatArchive => self.set_selected_chat_archived(true),
            SlashCommand::ChatUnarchive => self.set_selected_chat_archived(false),
            SlashCommand::ChatArchived(include) => self.set_archived_chat_visibility(include),
            SlashCommand::MembersAdd(members) => self.add_selected_chat_members(members),
            SlashCommand::MembersRemove(members) => self.remove_selected_chat_members(members),
            SlashCommand::MembersList => self.show_selected_chat_members(),
            SlashCommand::KeysFetch(account) => {
                let result = self.client.run_json(None, &["keys", "fetch", &account])?;
                let bytes = result
                    .get("key_package_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                self.status = format!("fetched key package bytes={bytes}");
                Ok(())
            }
            SlashCommand::KeysRotate => {
                let account_id = self.require_selected_local_account()?;
                let result = self
                    .client
                    .run_json(Some(&account_id), &["keys", "rotate"])?;
                let bytes = result
                    .get("key_package_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                self.status = format!("rotated key package bytes={bytes}");
                Ok(())
            }
            SlashCommand::ProfileName(name) => self.update_profile_name(name),
            SlashCommand::StreamCompose {
                stream_id,
                quic_candidates,
            } => self.start_stream_composer(stream_id, quic_candidates),
            SlashCommand::StreamStart {
                stream_id,
                quic_candidates,
            } => self.start_stream(stream_id, quic_candidates),
            SlashCommand::StreamWatch {
                stream_id,
                insecure_local,
            } => self.watch_stream(stream_id, insecure_local),
            SlashCommand::StreamStatus => {
                self.refresh_daemon_status()?;
                self.status = stream_watch_status(&self.daemon);
                Ok(())
            }
            SlashCommand::StreamFinish {
                stream_id,
                transcript_hash,
                chunk_count,
                text,
            } => self.finish_stream(stream_id, transcript_hash, chunk_count, text),
            SlashCommand::StreamVerify {
                stream_id,
                transcript_hash,
                chunk_count,
            } => self.verify_stream(stream_id, transcript_hash, chunk_count),
            SlashCommand::Quit => {
                self.running = false;
                Ok(())
            }
        }
    }

    pub(crate) fn select_current_account(&mut self) -> TuiResult<()> {
        if self.accounts.is_empty() {
            return Ok(());
        }
        self.refresh_chats()
    }

    pub(crate) fn select_account_by_selector(&mut self, selector: &str) -> TuiResult<()> {
        let Some(index) = self
            .accounts
            .iter()
            .position(|account| account_matches(account, selector))
        else {
            return Err(TuiError::Cli(format!("account not loaded: {selector}")));
        };
        self.selected_account = index;
        self.status = format!(
            "selected account {}",
            self.selected_account_row()
                .map(|account| shorten(&account_display_label(account), 18))
                .unwrap_or_else(|| shorten(selector, 18))
        );
        self.refresh_chats()
    }

    pub(crate) fn select_chat_by_group_id(&mut self, group_id: &str) -> TuiResult<()> {
        let Some(index) = self.chats.iter().position(|chat| chat.group_id == group_id) else {
            return Ok(());
        };
        self.selected_chat = index;
        self.refresh_messages()
    }

    pub(crate) fn selected_account_row(&self) -> Option<&AccountRow> {
        self.accounts.get(self.selected_account)
    }

    pub(crate) fn message_account_row(&self) -> Option<&AccountRow> {
        self.messages_account_id
            .as_deref()
            .and_then(|account_id| {
                self.accounts
                    .iter()
                    .find(|account| account.account_id == account_id)
            })
            .or_else(|| self.selected_account_row())
    }

    pub(crate) fn selected_chat_row(&self) -> Option<&ChatRow> {
        self.chats.get(self.selected_chat)
    }

    pub(crate) fn message_account_id(&self) -> TuiResult<String> {
        if let Some(account_id) = &self.messages_account_id {
            return Ok(account_id.clone());
        }
        self.require_selected_local_account()
    }

    pub(crate) fn message_group_id(&self) -> TuiResult<String> {
        if let Some(group_id) = &self.messages_group_id {
            return Ok(group_id.clone());
        }
        self.require_selected_group()
    }

    pub(crate) fn require_selected_local_account(&self) -> TuiResult<String> {
        let account = self
            .selected_account_row()
            .ok_or_else(|| TuiError::Cli("no account selected".to_owned()))?;
        if !account.local_signing {
            return Err(TuiError::Cli(
                "selected account is public-only and cannot sign".to_owned(),
            ));
        }
        Ok(account.account_id.clone())
    }

    pub(crate) fn require_selected_group(&self) -> TuiResult<String> {
        self.selected_chat_row()
            .map(|chat| chat.group_id.clone())
            .ok_or_else(|| TuiError::Cli("no chat selected".to_owned()))
    }
}
