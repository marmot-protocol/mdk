//! `TuiApp` state plus the event loop, key handling, and selection methods.

use super::*;

pub(crate) struct TuiApp {
    pub(crate) client: WnClient,
    pub(crate) initial_account: Option<String>,
    pub(crate) running: bool,
    pub(crate) screen: Screen,
    /// True once an account has been activated into the main view, so `Esc` from
    /// the account picker knows whether there is a session to return to.
    pub(crate) entered_main: bool,
    /// Whether the opt-in MLS group diagnostics panel is shown (`/diagnostics`).
    pub(crate) show_diagnostics: bool,
    pub(crate) focus: Focus,
    pub(crate) accounts: Vec<AccountRow>,
    pub(crate) selected_account: usize,
    /// The account-picker highlight, kept separate from `selected_account` so
    /// picker navigation never mutates the live selection. It is seeded from
    /// `selected_account` when the picker opens and committed back only on
    /// `Enter`; `Esc` discards it.
    pub(crate) picker_selection: usize,
    pub(crate) chats: Vec<ChatRow>,
    pub(crate) selected_chat: usize,
    pub(crate) messages_account_id: Option<String>,
    pub(crate) messages_group_id: Option<String>,
    pub(crate) unread_counts: HashMap<String, usize>,
    pub(crate) show_archived_chats: bool,
    pub(crate) timeline: Vec<TimelineRow>,
    pub(crate) timeline_scroll: TimelineScroll,
    pub(crate) live_stream_previews: Vec<LiveStreamPreview>,
    pub(crate) chat_subscription: Option<ChatSubscription>,
    pub(crate) message_subscription: Option<MessageSubscription>,
    pub(crate) timeline_subscription: Option<TimelineSubscription>,
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
        let client = WnClient::from_cli(&cli)?;
        Ok(Self {
            client,
            initial_account: cli.account.clone(),
            running: true,
            screen: Screen::Login(LoginMode::Menu),
            entered_main: false,
            show_diagnostics: false,
            focus: Focus::Chats,
            accounts: Vec::new(),
            selected_account: 0,
            picker_selection: 0,
            chats: Vec::new(),
            selected_chat: 0,
            messages_account_id: None,
            messages_group_id: None,
            unread_counts: HashMap::new(),
            show_archived_chats: false,
            timeline: Vec::new(),
            timeline_scroll: TimelineScroll::default(),
            live_stream_previews: Vec::new(),
            chat_subscription: None,
            message_subscription: None,
            timeline_subscription: None,
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
            self.start()?;
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
        changed |= self.drain_timeline_subscription();
        match self.flush_stream_append_if_due(now) {
            Ok(flushed) => changed |= flushed,
            Err(err) => {
                self.status = format!("stream append failed: {err}");
                changed = true;
            }
        }
        changed
    }

    /// Route the opening screen from the loaded account list: no accounts opens
    /// the login menu, one drops straight into the main view, several open the
    /// account picker.
    pub(crate) fn start(&mut self) -> TuiResult<()> {
        self.load_accounts()?;
        // An explicit `--account`/`WN_ACCOUNT` selector that resolves to a loaded
        // account is honored directly, so it wins over the several-accounts
        // picker instead of routing purely on the account count.
        let initial_index = self
            .initial_account
            .as_deref()
            .and_then(|selector| selected_account_index(&self.accounts, Some(selector)));
        if let Some(index) = initial_index {
            self.selected_account = index;
        }
        match startup_screen(self.accounts.len(), initial_index.is_some()) {
            Screen::Main => self.enter_main(),
            Screen::Login(LoginMode::AccountSelect) => {
                self.open_account_picker();
                Ok(())
            }
            screen => {
                self.screen = screen;
                Ok(())
            }
        }
    }

    /// Open the account picker, seeding its highlight from the currently active
    /// account so navigation starts on the current selection and `Esc` discards
    /// cleanly back to that account without committing a different one.
    pub(crate) fn open_account_picker(&mut self) {
        self.picker_selection = self.selected_account;
        self.screen = Screen::Login(LoginMode::AccountSelect);
    }

    /// Commit to the main view without reloading: used after account setup, which
    /// has already loaded the new account's chats.
    pub(crate) fn show_main(&mut self) {
        self.screen = Screen::Main;
        self.focus = Focus::Chats;
        self.entered_main = true;
    }

    /// Enter the main view for the currently selected account, loading its chats.
    pub(crate) fn enter_main(&mut self) -> TuiResult<()> {
        self.show_main();
        self.refresh_chats()
    }

    /// Reload accounts and chats, dropping back to the login menu if the last
    /// account has disappeared. Backs the `/refresh` slash command.
    pub(crate) fn refresh_or_return_to_login(&mut self) -> TuiResult<()> {
        self.refresh_accounts()?;
        if self.accounts.is_empty() {
            self.entered_main = false;
            self.screen = Screen::Login(LoginMode::Menu);
        }
        Ok(())
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return Ok(());
        }
        // The streaming check sits ahead of the screen dispatch (behind only
        // Ctrl-C) so the invariant is structural: while a stream is open, keys go
        // to the composer and `tick()` keeps flushing regardless of which screen
        // is showing. Otherwise a future Main->Login transition with a live stream
        // would silently bypass the streaming keys.
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
        match self.screen {
            Screen::Login(mode) => return self.handle_login_key(mode, key),
            Screen::Main => {}
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
            KeyCode::Esc => {
                self.show_help = false;
                self.input.clear();
            }
            KeyCode::Char('/') if self.focus != Focus::Composer => {
                self.show_help = false;
                self.focus = Focus::Composer;
                self.input.push('/');
            }
            // Reopen the account picker from the chat list (the accounts pane is
            // gone; `A` is its replacement entry point).
            KeyCode::Char('A') if self.focus == Focus::Chats => {
                self.show_help = false;
                self.open_account_picker();
            }
            // Messages pane: the message-offset scroll model. `k`/Up and PageUp
            // may reach the oldest loaded row and page in older history.
            KeyCode::Up | KeyCode::Char('k') if self.focus == Focus::Messages => {
                self.messages_select_up();
            }
            KeyCode::Down | KeyCode::Char('j') if self.focus == Focus::Messages => {
                self.timeline_scroll.select_down(self.timeline.len());
            }
            KeyCode::PageUp if self.focus == Focus::Messages => self.messages_page_up(),
            KeyCode::PageDown if self.focus == Focus::Messages => {
                self.timeline_scroll.page_down(self.timeline.len());
            }
            KeyCode::End | KeyCode::Char('G') if self.focus == Focus::Messages => {
                self.timeline_scroll.jump_newest(self.timeline.len());
            }
            KeyCode::Home | KeyCode::Char('g') if self.focus == Focus::Messages => {
                self.messages_jump_oldest();
            }
            KeyCode::Char('i') | KeyCode::Enter if self.focus == Focus::Messages => {
                self.focus = Focus::Composer;
            }
            // Chat list navigation.
            KeyCode::Up | KeyCode::Char('k') if self.focus != Focus::Composer => {
                self.move_selection(-1);
            }
            KeyCode::Down | KeyCode::Char('j') if self.focus != Focus::Composer => {
                self.move_selection(1);
            }
            KeyCode::Enter => {
                if let Err(err) = self.activate_focus() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Backspace if self.focus == Focus::Composer => {
                self.input.pop();
            }
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
            Focus::Chats => {
                self.selected_chat = move_index(self.selected_chat, self.chats.len(), delta);
            }
            // The messages pane owns its own selection through `timeline_scroll`;
            // it is driven directly in `handle_key`, not through `move_selection`.
            Focus::Messages | Focus::Composer => {}
        }
    }

    /// Move the account-picker highlight (login/account-select screen only).
    /// This is picker-local state committed to `selected_account` on `Enter`, so
    /// navigation never disturbs the active selection.
    pub(crate) fn move_account_selection(&mut self, delta: isize) {
        self.picker_selection = move_index(self.picker_selection, self.accounts.len(), delta);
    }

    /// Move the message selection one row older, paging in older history when the
    /// move lands on the oldest loaded row.
    pub(crate) fn messages_select_up(&mut self) {
        self.timeline_scroll.select_up(self.timeline.len());
        self.request_older_if_needed();
    }

    /// Page the message selection up by a screenful, paging in older history when
    /// the move lands on the oldest loaded row.
    pub(crate) fn messages_page_up(&mut self) {
        self.timeline_scroll.page_up(self.timeline.len());
        self.request_older_if_needed();
    }

    /// Jump the message selection to the oldest loaded row (the `g` / `Home`
    /// binding), paging in older history since that lands on the oldest row.
    pub(crate) fn messages_jump_oldest(&mut self) {
        self.timeline_scroll.jump_oldest(self.timeline.len());
        self.request_older_if_needed();
    }

    /// Fetch the previous history page when the selection has reached the oldest
    /// loaded row and more history remains. Errors surface on the status line so a
    /// failed page never tears down the session; `loading_older` is cleared on the
    /// error path inside `load_older_messages`.
    pub(crate) fn request_older_if_needed(&mut self) {
        if self
            .timeline_scroll
            .should_request_older(self.timeline.len())
            && let Err(err) = self.load_older_messages()
        {
            self.status = format!("error: {err}");
        }
    }

    pub(crate) fn activate_focus(&mut self) -> TuiResult<()> {
        match self.focus {
            // Opening a chat also moves focus to the messages pane so the reader
            // can immediately scroll the conversation.
            Focus::Chats => {
                self.refresh_messages()?;
                self.focus = Focus::Messages;
                Ok(())
            }
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

    /// Handle a keypress on the login/account-select screen. Fallible account
    /// setup is caught into the status line so a failed create/login never tears
    /// down the session (mirrors the streaming and main-view Enter paths).
    pub(crate) fn handle_login_key(&mut self, mode: LoginMode, key: KeyEvent) -> TuiResult<()> {
        match mode {
            LoginMode::Menu => self.handle_login_menu_key(key),
            LoginMode::AccountSelect => self.handle_account_select_key(key),
            LoginMode::NsecEntry => self.handle_nsec_entry_key(key),
        }
        Ok(())
    }

    fn handle_login_menu_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('c') => self.create_identity_from_login(),
            KeyCode::Char('l') => self.begin_nsec_entry(),
            KeyCode::Char('q') => self.running = false,
            _ => {}
        }
    }

    fn handle_account_select_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_account_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_account_selection(1),
            KeyCode::Enter => {
                // Commit the picker highlight before loading; `Esc` (below) never
                // reaches here, so the live selection only changes on `Enter`.
                self.selected_account = self.picker_selection;
                if let Err(err) = self.enter_main() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Char('c') => self.create_identity_from_login(),
            KeyCode::Char('l') => self.begin_nsec_entry(),
            KeyCode::Char('q') => self.running = false,
            // Only return to the main view when one is already active (opened via
            // `A`); at startup with several accounts there is nothing to return to.
            KeyCode::Esc if self.entered_main => self.show_main(),
            _ => {}
        }
    }

    fn handle_nsec_entry_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => self.submit_nsec_login(),
            KeyCode::Esc => {
                self.input.clear();
                match login_mode_for_accounts(self.accounts.len()) {
                    LoginMode::AccountSelect => self.open_account_picker(),
                    mode => self.screen = Screen::Login(mode),
                }
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(character) => self.input.push(character),
            _ => {}
        }
    }

    /// Create a new local signing identity from the login screen; enter the main
    /// view on success, surface the error on the status line otherwise.
    fn create_identity_from_login(&mut self) {
        match self.create_or_import_account(None, "created identity") {
            Ok(()) => self.show_main(),
            Err(err) => self.status = format!("error: {err}"),
        }
    }

    fn begin_nsec_entry(&mut self) {
        self.screen = Screen::Login(LoginMode::NsecEntry);
        self.input.clear();
        self.status = "enter nsec; Enter submits, Esc cancels".to_owned();
    }

    /// Submit the masked nsec-entry field through the existing stdin-piped login
    /// path. The value is cleared before shelling out (as the composer does), so
    /// a secret never lingers in state after submission.
    fn submit_nsec_login(&mut self) {
        let identity = self.input.trim().to_owned();
        self.input.clear();
        if identity.is_empty() {
            self.status = "nsec is empty; type an nsec or press Esc".to_owned();
            return;
        }
        match self.create_or_import_account(Some(identity), "logged in identity") {
            Ok(()) => self.show_main(),
            Err(err) => self.status = format!("error: {err}"),
        }
    }

    pub(crate) fn run_slash_command(&mut self, command: SlashCommand) -> TuiResult<()> {
        match command {
            SlashCommand::Help => {
                self.show_help = true;
                Ok(())
            }
            SlashCommand::Refresh => self.refresh_or_return_to_login(),
            SlashCommand::Diagnostics => {
                self.show_diagnostics = !self.show_diagnostics;
                self.status = if self.show_diagnostics {
                    "diagnostics panel on".to_owned()
                } else {
                    "diagnostics panel off".to_owned()
                };
                Ok(())
            }
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
            SlashCommand::ChatMute(duration) => self.set_selected_chat_muted(duration),
            SlashCommand::ChatUnmute => self.clear_selected_chat_muted(),
            SlashCommand::ChatArchived(include) => self.set_archived_chat_visibility(include),
            SlashCommand::MembersAdd(members) => self.add_selected_chat_members(members),
            SlashCommand::MembersRemove(members) => self.remove_selected_chat_members(members),
            SlashCommand::MembersList => self.show_selected_chat_members(),
            SlashCommand::Image { file_path, caption } => self.send_image(file_path, caption),
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
