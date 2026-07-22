//! `TuiApp` state plus the event loop, key handling, and selection methods.

use super::*;

/// Disables bracketed paste on drop so an unwind out of `run` cannot leave the
/// user's terminal in bracketed-paste mode. `ratatui::init` installs a panic
/// hook that restores the terminal, but bracketed paste is enabled outside
/// ratatui's knowledge, so its hook does not disable it. The normal exit path
/// still disables explicitly (see `run`) to keep the teardown ordering visible;
/// this guard only covers the panic/unwind path. Best-effort chrome: failures
/// are ignored.
struct BracketedPasteGuard;

impl Drop for BracketedPasteGuard {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stdout(), DisableBracketedPaste);
    }
}

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
    pub(crate) show_archived_chats: bool,
    pub(crate) timeline: Vec<TimelineRow>,
    pub(crate) timeline_scroll: TimelineScroll,
    pub(crate) live_stream_previews: Vec<LiveStreamPreview>,
    pub(crate) chat_subscription: Option<ChatSubscription>,
    pub(crate) message_subscription: Option<MessageSubscription>,
    pub(crate) timeline_subscription: Option<TimelineSubscription>,
    pub(crate) group_state_subscription: Option<GroupStateSubscription>,
    pub(crate) notification_subscription: Option<NotificationSubscription>,
    /// Debounce gate for the notification-driven chats re-list. A NewMessage for
    /// a non-loaded chat sets it; `tick` performs exactly one re-list per tick
    /// when set, then clears it, coalescing every such event since the last tick
    /// into a single `chats list` re-read.
    pub(crate) pending_chat_relist: bool,
    /// Schedule a `chats mark-read` for the loaded chat. The timeline fold arms
    /// it when it imports a nonzero unread count for the viewed chat (viewing is
    /// reading); `tick` issues at most one mark-read per tick, then the folded
    /// zero count leaves it clear. Cleared before the call and re-armed on error
    /// like `pending_chat_relist`, so a failure retries next tick, not forever.
    pub(crate) pending_mark_read: bool,
    /// Notification `notification_key`s already handled, so the runtime feed's
    /// duplicated emissions do not re-trigger a re-list or a repeated invite
    /// notice. FIFO-bounded to the recent event window, not unbounded.
    pub(crate) seen_notification_keys: SeenNotificationKeys,
    pub(crate) daemon: DaemonView,
    pub(crate) group_diagnostics: Option<GroupDiagnostics>,
    pub(crate) input: Input,
    pub(crate) streaming: Option<StreamComposer>,
    pub(crate) status: String,
    /// The one open modal, or none. While set it captures every key (routed at
    /// the top of `handle_key`) and overlays whatever screen is showing.
    pub(crate) popup: Option<Popup>,
    /// Group-detail screen state, loaded on entry and dropped on exit. Present
    /// only while `screen == Screen::GroupDetail`.
    pub(crate) group_detail: Option<GroupDetailView>,
    /// User-search screen state (Phase 5b). Present only while
    /// `screen == Screen::UserSearch`; a one-shot load, no per-view subscription.
    pub(crate) user_search: Option<UserSearchView>,
    /// Own-profile screen state (Phase 5b). Present only while
    /// `screen == Screen::Profile`.
    pub(crate) profile_view: Option<ProfileView>,
    /// Relay-health screen state (Phase 5b). Present only while
    /// `screen == Screen::RelayHealth`.
    pub(crate) relay_health: Option<RelayHealthView>,
    /// Inbound-media state (Phase 6): terminal image capability, per-hash
    /// download/decode status, and the decoded protocols the renderer draws.
    pub(crate) media: MediaState,
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
            show_archived_chats: false,
            timeline: Vec::new(),
            timeline_scroll: TimelineScroll::default(),
            live_stream_previews: Vec::new(),
            chat_subscription: None,
            message_subscription: None,
            timeline_subscription: None,
            group_state_subscription: None,
            notification_subscription: None,
            pending_chat_relist: false,
            pending_mark_read: false,
            seen_notification_keys: SeenNotificationKeys::new(),
            daemon: DaemonView::default(),
            group_diagnostics: None,
            input: Input::default(),
            streaming: None,
            status: "loading accounts".to_owned(),
            popup: None,
            group_detail: None,
            user_search: None,
            profile_view: None,
            relay_health: None,
            media: MediaState::new(),
        })
    }

    pub(crate) fn run(&mut self) -> TuiResult<()> {
        let mut terminal = ratatui::init();
        // Detect the terminal's image capability once, now that raw mode is on and
        // before the event loop starts reading stdin. Detection failure leaves
        // media placeholders in place (no image protocol).
        self.media.detect_capability();
        // Bracketed paste delivers a paste as one `Event::Paste(text)` instead of a
        // burst of key events, so a multi-line paste keeps its newlines instead of
        // firing Enter (send) on every line. Best-effort chrome: ignore failures
        // and always disable before restore.
        let _ = crossterm::execute!(std::io::stdout(), EnableBracketedPaste);
        // Safety net so a panic unwinding out of the loop still disables bracketed
        // paste (ratatui's panic hook restores the terminal but does not know
        // about this mode). The explicit disable below keeps the normal path's
        // ordering; the guard's drop then repeats it harmlessly.
        let _bracketed_paste = BracketedPasteGuard;
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
                        Event::Paste(text) => {
                            self.handle_paste(text);
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
        let _ = crossterm::execute!(std::io::stdout(), DisableBracketedPaste);
        ratatui::restore();
        result
    }

    /// Route pasted text (from bracketed paste) into whatever input is accepting
    /// characters — the streaming composer, the nsec field, or the main composer —
    /// as literal characters with no keybinding interpretation. Newlines are kept
    /// (normalized to `\n`) so multi-line content lands verbatim. Paste elsewhere
    /// is ignored, mirroring where typed characters are accepted.
    pub(crate) fn handle_paste(&mut self, text: String) {
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        // A popup is modal (mirroring `handle_key`): a text-entry popup takes the
        // paste into its own input, and every other popup swallows it so nothing
        // leaks into the composer hidden behind the popup.
        if let Some(popup) = self.popup.as_mut() {
            if let Popup::Text { input, .. } = popup {
                input.insert_str(&text);
            }
            return;
        }
        if self.streaming.is_some() {
            self.input.insert_str(&text);
            let mut stream_id = None;
            if let Some(streaming) = self.streaming.as_mut() {
                streaming.pending_text.push_str(&text);
                stream_id = Some(streaming.stream_id.clone());
                // Mirror the typed-char status so a paste is as visible as typing.
                self.status = format!(
                    "queued {} byte(s) on {}",
                    streaming.pending_text.len(),
                    shorten(&streaming.stream_id, 18)
                );
            }
            if let Some(stream_id) = stream_id {
                self.upsert_active_stream_preview(&stream_id);
            }
            return;
        }
        match self.screen {
            Screen::Login(LoginMode::NsecEntry) => self.input.insert_str(&text),
            Screen::Main if self.focus == Focus::Composer => self.input.insert_str(&text),
            // Paste into the search query only while it has focus, mirroring
            // where typed characters are accepted on that screen.
            Screen::UserSearch => {
                if let Some(view) = self.user_search.as_mut()
                    && view.focus == UserSearchFocus::Query
                {
                    view.query.insert_str(&text);
                }
            }
            _ => {}
        }
    }

    pub(crate) fn tick(&mut self) -> bool {
        let now = Instant::now();
        let mut changed = false;
        changed |= self.drain_chat_subscription();
        changed |= self.drain_group_state_subscription();
        changed |= self.drain_message_subscription();
        changed |= self.drain_timeline_subscription();
        changed |= self.drain_notification_subscription();
        // Fold completed media downloads/decodes in, then start downloads for any
        // newly-visible image the terminal can render. Both are off-loop: the
        // subprocess and decode run on worker threads; this only folds results.
        changed |= self.media.drain();
        changed |= self.ensure_media_downloads();
        // Debounce: notification drains coalesce every NewMessage for a
        // non-loaded chat since the last tick into this one pending flag, so at
        // most one background `chats list` re-read runs per tick. Cleared before
        // the call and re-armed on error so a transient failure retries next
        // tick instead of dropping the batch; the flag is checked once per tick,
        // so a permanently-failing re-list retries at most once per tick (the
        // tick cadence is the hot-loop ceiling by construction).
        if self.pending_chat_relist {
            self.pending_chat_relist = false;
            if let Err(err) = self.relist_chats() {
                self.pending_chat_relist = true;
                self.set_drain_status(format!("chat re-list failed: {err}"));
            }
            changed = true;
        }
        // Viewing is reading: the timeline fold arms this when the viewed chat's
        // unread count grows, and we clear it with one `chats mark-read` here.
        // Same once-per-tick, re-arm-on-error discipline as the re-list above; a
        // success folds the count to zero so the timeline fold stops re-arming.
        if self.pending_mark_read {
            self.pending_mark_read = false;
            if let (Some(account_id), Some(group_id)) = (
                self.messages_account_id.clone(),
                self.messages_group_id.clone(),
            ) && let Err(err) = self.mark_selected_chat_read(&account_id, &group_id)
            {
                self.pending_mark_read = true;
                self.set_drain_status(format!("mark-read failed: {err}"));
            }
            changed = true;
        }
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
        // A popup is modal: it captures every key (behind only Ctrl-C) so the
        // screen behind it — and the streaming and screen dispatch below — see
        // nothing. This is what makes `q` under the help card close the card
        // instead of quitting the app.
        if self.popup.is_some() {
            return self.handle_popup_key(key);
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
            Screen::GroupDetail => return self.handle_group_detail_key(key),
            Screen::UserSearch => return self.handle_user_search_key(key),
            Screen::Profile => return self.handle_profile_key(key),
            Screen::RelayHealth => return self.handle_relay_health_key(key),
            Screen::Main => {}
        }

        match key.code {
            KeyCode::Char('?') if self.focus != Focus::Composer => {
                self.popup = Some(Popup::help());
            }
            KeyCode::Char('q') if self.focus != Focus::Composer && self.input.is_empty() => {
                self.running = false;
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.previous(),
            // Esc is the escape hatch the armed-interaction hint advertises: it
            // clears an armed `/react`/`/reply`/`/delete` prefill (pristine or
            // edited) so a user who armed a reaction by accident can back out. A
            // hand-typed draft is never an armed command, so Esc leaves it intact
            // — Esc must not silently destroy text the user wrote by hand, the
            // same reason r/d/R refuse to clobber a draft.
            KeyCode::Esc if is_armed_interaction(self.input.value()) => {
                self.input.clear();
            }
            KeyCode::Char('/') if self.focus != Focus::Composer => {
                self.focus = Focus::Composer;
                self.input.insert('/');
            }
            // Reopen the account picker from the chat list (the accounts pane is
            // gone; `A` is its replacement entry point).
            KeyCode::Char('A') if self.focus == Focus::Chats => {
                self.open_account_picker();
            }
            // Group detail and invites are entered from the chat list.
            KeyCode::Char('g') if self.focus == Focus::Chats => {
                if let Err(err) = self.open_group_detail() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Char('I') if self.focus == Focus::Chats => {
                if let Err(err) = self.open_invites() {
                    self.status = format!("error: {err}");
                }
            }
            // Full-view screens entered from the chat list (Phase 5b).
            KeyCode::Char('s') if self.focus == Focus::Chats => {
                self.open_user_search(None);
            }
            KeyCode::Char('p') if self.focus == Focus::Chats => {
                if let Err(err) = self.open_profile() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Char('h') if self.focus == Focus::Chats => {
                if let Err(err) = self.open_relay_health() {
                    self.status = format!("error: {err}");
                }
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
            // Message-interaction accelerators (Messages focus, popups are Phase 5).
            // `r` and `d` prefill a slash command in the composer so Enter is the
            // visible action; `u` removes your own reaction immediately (no input).
            KeyCode::Char('r') if self.focus == Focus::Messages => {
                self.prefill_composer("/react ");
            }
            KeyCode::Char('u') if self.focus == Focus::Messages => {
                if let Err(err) = self.unreact_selected_message() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Char('d') if self.focus == Focus::Messages => {
                self.prefill_composer("/delete");
            }
            // `R` prefills `/reply ` (draft-protected, like `r`/`d`) and names the
            // reply target on the status line; the target resolves at submit.
            KeyCode::Char('R') if self.focus == Focus::Messages => {
                self.begin_reply();
            }
            // Open the selected message's downloaded image full-size.
            KeyCode::Char('o') if self.focus == Focus::Messages => {
                self.open_selected_image_viewer();
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
            // Composer cursor editing (Phase 3). Left/Right/Home/End move; Delete
            // removes the char at the cursor; Backspace the one before it.
            KeyCode::Left if self.focus == Focus::Composer => self.input.left(),
            KeyCode::Right if self.focus == Focus::Composer => self.input.right(),
            KeyCode::Home if self.focus == Focus::Composer => self.input.home(),
            KeyCode::End if self.focus == Focus::Composer => self.input.end(),
            KeyCode::Delete if self.focus == Focus::Composer => self.input.delete(),
            KeyCode::Backspace if self.focus == Focus::Composer => {
                self.input.backspace();
            }
            // Ctrl-U is the readline kill-line: an unconditional composer clear
            // whatever the field holds — an armed interaction prefill or a
            // hand-typed draft — so the composer hint can name a key that always
            // clears. It precedes the plain-Char insert so Ctrl-U is never typed
            // as a literal `u`.
            KeyCode::Char('u')
                if self.focus == Focus::Composer
                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.input.clear();
            }
            KeyCode::Char(character) if self.focus == Focus::Composer => {
                self.input.insert(character);
            }
            _ => {}
        }
        Ok(())
    }

    /// Start a background download+decode for every image in the loaded timeline
    /// that the terminal can render and has not been requested yet. Idempotent:
    /// once a hash is tracked it is skipped, so this is safe to call every tick.
    /// The subprocess and decode run off-loop in `spawn_media_download`.
    pub(crate) fn ensure_media_downloads(&mut self) -> bool {
        if !self.media.supported() {
            return false;
        }
        let (Some(account_id), Some(group_id)) = (
            self.messages_account_id.clone(),
            self.messages_group_id.clone(),
        ) else {
            return false;
        };
        let candidates: Vec<String> = self
            .timeline
            .iter()
            .flat_map(|row| row.attachments.iter())
            .filter_map(TimelineAttachment::image_hash)
            .filter(|hash| !self.media.is_tracked(hash))
            .map(str::to_owned)
            .collect();
        // Cap concurrent downloads: `downloads_to_start` returns at most the free
        // in-flight slots (and dedups a hash that appears twice), so a timeline
        // full of images does not spawn a subprocess and thread for each at once.
        // The unstarted remainder is picked up on later ticks as workers finish.
        let mut started = false;
        for hash in self.media.downloads_to_start(&candidates) {
            let output_path = match self.media_cache_path(&hash) {
                Ok(path) => path,
                Err(err) => {
                    self.set_drain_status(format!("media cache: {err}"));
                    continue;
                }
            };
            let args = [
                "media".to_owned(),
                "download".to_owned(),
                group_id.clone(),
                hash.clone(),
                "--output".to_owned(),
                output_path.to_string_lossy().into_owned(),
            ];
            let command = self.client.command(Some(&account_id), &args);
            let tx = self.media.begin_download(hash.clone());
            spawn_media_download(command, output_path, hash, tx);
            started = true;
        }
        started
    }

    /// The per-hash cache path for a decrypted download, under the TUI home when
    /// one is set (else a private temp dir). Passed as `--output` so the CLI does
    /// not write the file's basename into the current directory. The directory is
    /// created restrictive-by-construction; the CLI writes the file privately.
    fn media_cache_path(&self, hash: &str) -> TuiResult<PathBuf> {
        let cache_dir = self
            .client
            .home
            .clone()
            .unwrap_or_else(std::env::temp_dir)
            .join("tui-media-cache");
        fs_private::create_dir_all_private(&cache_dir)?;
        Ok(cache_dir.join(hash))
    }

    /// Open the selected message's downloaded image full-size, or explain on the
    /// status line why it cannot (no capability, not downloaded, or no image).
    fn open_selected_image_viewer(&mut self) {
        let total = self.timeline.len();
        let Some(index) = self.timeline_scroll.resolved_selection(total) else {
            self.status = "no message selected".to_owned();
            return;
        };
        // Clone the row so the timeline borrow ends before the popup/status write.
        let Some(row) = self.timeline.get(index).cloned() else {
            return;
        };
        let ready = row.attachments.iter().find_map(|attachment| {
            let hash = attachment.image_hash()?;
            self.media
                .is_ready(hash)
                .then(|| (attachment.display_name(), hash.to_owned()))
        });
        match ready {
            Some((name, hash)) => {
                self.popup = Some(Popup::Image {
                    title: format!("Image: {name}"),
                    hash,
                });
            }
            None if !self.media.supported() => {
                self.status = "this terminal has no image protocol".to_owned();
            }
            None if row.attachments.iter().any(|a| a.image_hash().is_some()) => {
                self.status = "image not downloaded yet".to_owned();
            }
            None => self.status = "no image on the selected message".to_owned(),
        }
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

    /// Prefill the composer with an accelerator's slash command and focus it, but
    /// only when the composer is empty. A draft is never clobbered: `r`/`d` after
    /// Tab-cycling to Messages would otherwise silently destroy typed text, so an
    /// existing draft is left intact and the status line explains the suppression.
    fn prefill_composer(&mut self, command: &str) {
        if self.input.is_empty() {
            self.input.set_value(command);
            self.focus = Focus::Composer;
        } else {
            self.status = "composer has a draft; clear it before using r/d".to_owned();
        }
    }

    /// `R` accelerator: prefill `/reply ` (draft-protected via `prefill_composer`)
    /// and, when the prefill takes, set a status line naming the reply target so
    /// the pending reply is visible. The target itself resolves at submit; this
    /// status line is informational only.
    fn begin_reply(&mut self) {
        let had_draft = !self.input.is_empty();
        self.prefill_composer("/reply ");
        if !had_draft && let Some(row) = self.selected_timeline_row() {
            self.status = reply_target_status(row);
        }
    }

    /// The currently selected timeline row (newest by default), if any.
    pub(crate) fn selected_timeline_row(&self) -> Option<&TimelineRow> {
        self.timeline_scroll
            .resolved_selection(self.timeline.len())
            .and_then(|index| self.timeline.get(index))
    }

    pub(crate) fn submit_input(&mut self) -> TuiResult<()> {
        let input = self.input.value().trim().to_owned();
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
                self.input.insert(character);
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
                self.input.set_masked(false);
                match login_mode_for_accounts(self.accounts.len()) {
                    LoginMode::AccountSelect => self.open_account_picker(),
                    mode => self.screen = Screen::Login(mode),
                }
            }
            KeyCode::Left => self.input.left(),
            KeyCode::Right => self.input.right(),
            KeyCode::Home => self.input.home(),
            KeyCode::End => self.input.end(),
            KeyCode::Delete => self.input.delete(),
            KeyCode::Backspace => self.input.backspace(),
            // Ctrl-U kill-line, shared with the composer: the nsec field reuses the
            // same `Input`, so the readline convention carries over and clearing
            // key material promptly is safety-positive. Nothing else binds it here.
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.clear();
            }
            KeyCode::Char(character) => self.input.insert(character),
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
        // Reuse the composer input's masked mode so the field renders as `*` per
        // char and key material never reaches the screen.
        self.input.set_masked(true);
        self.status = "enter nsec; Enter submits, Esc cancels".to_owned();
    }

    /// Submit the masked nsec-entry field through the existing stdin-piped login
    /// path. The value is cleared before shelling out (as the composer does), so
    /// a secret never lingers in state after submission.
    fn submit_nsec_login(&mut self) {
        let identity = self.input.value().trim().to_owned();
        self.input.clear();
        if identity.is_empty() {
            self.status = "nsec is empty; type an nsec or press Esc".to_owned();
            return;
        }
        match self.create_or_import_account(Some(identity), "logged in identity") {
            Ok(()) => {
                // Leaving nsec entry: the shared input returns to plain composer mode.
                self.input.set_masked(false);
                self.show_main();
            }
            Err(err) => self.status = format!("error: {err}"),
        }
    }

    pub(crate) fn run_slash_command(&mut self, command: SlashCommand) -> TuiResult<()> {
        match command {
            SlashCommand::Help => {
                self.popup = Some(Popup::help());
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
            SlashCommand::React { emoji } => self.react_to_selected_message(emoji),
            SlashCommand::Unreact => self.unreact_selected_message(),
            SlashCommand::Delete => self.delete_selected_message(),
            SlashCommand::Reply { text } => self.send_reply(text),
            SlashCommand::Retry { event_id } => self.retry_message(event_id),
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
            SlashCommand::UsersSearch { query } => {
                self.open_user_search(query);
                Ok(())
            }
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

    /// Route a key into the open popup. The pure `popup_key` reducer owns the
    /// edit/navigate/submit/cancel decision; the app only closes the popup and
    /// runs the resolved CLI call, catching its error onto the status line so a
    /// failed action never tears down the session.
    pub(crate) fn handle_popup_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        let Some(popup) = self.popup.as_mut() else {
            return Ok(());
        };
        match popup_key(popup, key.code) {
            PopupAction::None => {}
            PopupAction::Dismiss => self.popup = None,
            PopupAction::Submit(submit) => {
                // The invites picker stays open across actions so one
                // accept/decline does not lose the user's place: capture the
                // selection, run the action, then refold the refreshed list back
                // into the picker (which closes it once empty). Every other popup
                // is one-shot and closes on submit.
                let refold = match &self.popup {
                    Some(Popup::Picker {
                        purpose: PickerPurpose::Invites,
                        selected,
                        ..
                    }) => Some(*selected),
                    _ => None,
                };
                self.popup = None;
                if let Err(err) = self.run_popup_submit(submit) {
                    self.status = format!("error: {err}");
                }
                if let Some(selected) = refold
                    && let Err(err) = self.refold_invites_picker(selected)
                {
                    self.status = format!("error: {err}");
                }
            }
        }
        Ok(())
    }

    fn run_popup_submit(&mut self, submit: PopupSubmit) -> TuiResult<()> {
        match submit {
            PopupSubmit::RenameGroup { group_id, name } => self.rename_group(&group_id, name),
            PopupSubmit::AddMember { group_id, pubkey } => self.add_group_member(&group_id, pubkey),
            PopupSubmit::RemoveMember { group_id, pubkey } => {
                self.remove_group_member(&group_id, pubkey)
            }
            PopupSubmit::PromoteMember { group_id, pubkey } => {
                self.promote_group_member(&group_id, pubkey)
            }
            PopupSubmit::LeaveGroup { group_id } => self.leave_group(&group_id),
            PopupSubmit::AcceptInvite { group_id } => self.accept_invite(&group_id),
            PopupSubmit::DeclineInvite { group_id } => self.decline_invite(&group_id),
            PopupSubmit::UpdateProfileField { field, value } => {
                self.update_profile_field(field, value)
            }
            PopupSubmit::FollowUser { pubkey } => self.follow_user(&pubkey),
            PopupSubmit::Unfollow { pubkey } => self.unfollow_user(&pubkey),
            PopupSubmit::NewChat { name, pubkey } => {
                self.create_chat(name, vec![pubkey])?;
                self.reveal_chat_from_search();
                Ok(())
            }
            PopupSubmit::AddUserToChat { group_id, pubkey } => {
                self.add_group_member(&group_id, pubkey)?;
                self.select_chat_by_group_id(&group_id)?;
                self.reveal_chat_from_search();
                Ok(())
            }
        }
    }

    /// After a user-search action opens a new chat or adds someone to the open one,
    /// leave the search screen for the main view so the freshly selected chat is
    /// visible. Mirrors the invite-accept return: the search screen would otherwise
    /// hide the chat the action just targeted. A no-op off the search screen, so the
    /// same submit reached from elsewhere (e.g. group detail) is unaffected.
    fn reveal_chat_from_search(&mut self) {
        if self.screen == Screen::UserSearch {
            self.user_search = None;
            self.screen = Screen::Main;
            self.focus = Focus::Chats;
        }
    }

    /// Group-detail screen keys. `Esc` drops the view and returns to the main
    /// view; member/group actions open a popup that routes back through
    /// `run_popup_submit`.
    pub(crate) fn handle_group_detail_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        match key.code {
            KeyCode::Esc => self.leave_group_detail(),
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(view) = self.group_detail.as_mut() {
                    view.select_up();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(view) = self.group_detail.as_mut() {
                    view.select_down();
                }
            }
            KeyCode::Char('A') => self.open_add_member_popup(),
            KeyCode::Char('R') => self.open_rename_group_popup(),
            KeyCode::Char('x') => self.open_remove_member_popup(),
            KeyCode::Char('P') => self.open_promote_member_popup(),
            KeyCode::Char('L') => self.open_leave_group_popup(),
            KeyCode::Char('I') => {
                if let Err(err) = self.open_invites() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Char('?') => self.popup = Some(Popup::help()),
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn leave_group_detail(&mut self) {
        self.group_detail = None;
        self.screen = Screen::Main;
        self.focus = Focus::Chats;
    }

    fn open_add_member_popup(&mut self) {
        if let Some(view) = &self.group_detail {
            self.popup = Some(Popup::Text {
                purpose: TextPurpose::AddMemberByPubkey {
                    group_id: view.group_id.clone(),
                },
                title: "Add Member".to_owned(),
                input: Input::default(),
            });
        }
    }

    fn open_rename_group_popup(&mut self) {
        if let Some(view) = &self.group_detail {
            let mut input = Input::default();
            input.set_value(view.name.clone());
            self.popup = Some(Popup::Text {
                purpose: TextPurpose::RenameGroup {
                    group_id: view.group_id.clone(),
                },
                title: "Rename Group".to_owned(),
                input,
            });
        }
    }

    fn open_remove_member_popup(&mut self) {
        let Some(view) = &self.group_detail else {
            return;
        };
        let Some(member) = view.selected_member() else {
            return;
        };
        if member.is_self {
            self.status = "cannot remove yourself; press L to leave".to_owned();
            return;
        }
        self.popup = Some(Popup::Confirm {
            purpose: ConfirmPurpose::RemoveMember {
                group_id: view.group_id.clone(),
                pubkey: member.npub.clone(),
            },
            title: "Remove Member".to_owned(),
            body: vec![format!(
                "Remove {}?",
                shorten(&terminal_safe_text(&member.npub), 24)
            )],
        });
    }

    fn open_promote_member_popup(&mut self) {
        let Some(view) = &self.group_detail else {
            return;
        };
        let Some(member) = view.selected_member() else {
            return;
        };
        if member.is_self {
            self.status = "cannot promote yourself".to_owned();
            return;
        }
        if member.is_admin {
            self.status = "member is already an admin".to_owned();
            return;
        }
        self.popup = Some(Popup::Confirm {
            purpose: ConfirmPurpose::PromoteMember {
                group_id: view.group_id.clone(),
                pubkey: member.npub.clone(),
            },
            title: "Promote to Admin".to_owned(),
            body: vec![format!(
                "Promote {} to admin?",
                shorten(&terminal_safe_text(&member.npub), 24)
            )],
        });
    }

    /// The admin-leave guard: an admin cannot leave (info card, sole-admin vs
    /// step-down message); a non-admin gets the normal confirm popup.
    fn open_leave_group_popup(&mut self) {
        let Some(view) = &self.group_detail else {
            return;
        };
        self.popup = Some(
            match leave_group_decision(view.account_is_admin, view.admin_count) {
                LeaveDecision::Blocked(message) => Popup::info(CANNOT_LEAVE_TITLE, message),
                LeaveDecision::Confirm => Popup::Confirm {
                    purpose: ConfirmPurpose::LeaveGroup {
                        group_id: view.group_id.clone(),
                    },
                    title: "Leave Group".to_owned(),
                    body: vec![format!(
                        "Leave {}?",
                        shorten(&terminal_safe_text(&view.name), 24)
                    )],
                },
            },
        );
    }

    /// Drop any Phase 5b full-view state and return to the main view. Shared by
    /// the search/profile/relay-health `Esc` handlers (their data is a one-shot
    /// load with no per-view subscription to tear down).
    pub(crate) fn leave_screen(&mut self) {
        self.user_search = None;
        self.profile_view = None;
        self.relay_health = None;
        self.screen = Screen::Main;
        self.focus = Focus::Chats;
    }

    /// User-search keys. `Esc` leaves the screen from either focus; otherwise the
    /// query field or the result list handles the key per the screen's focus.
    pub(crate) fn handle_user_search_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        if key.code == KeyCode::Esc {
            self.leave_screen();
            return Ok(());
        }
        match self.user_search.as_ref().map(|view| view.focus) {
            Some(UserSearchFocus::Query) => self.handle_user_search_query_key(key),
            Some(UserSearchFocus::Results) => self.handle_user_search_results_key(key),
            None => {}
        }
        Ok(())
    }

    /// Query-focus keys: typing edits the query (so `j`/`k`/`?` are literal text),
    /// `Enter` runs the search, and `Down` steps into the results.
    fn handle_user_search_query_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter => {
                if let Err(err) = self.run_user_search() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Down => {
                if let Some(view) = self.user_search.as_mut()
                    && !view.results.is_empty()
                {
                    view.focus = UserSearchFocus::Results;
                }
            }
            KeyCode::Left => self.with_search_query(Input::left),
            KeyCode::Right => self.with_search_query(Input::right),
            KeyCode::Home => self.with_search_query(Input::home),
            KeyCode::End => self.with_search_query(Input::end),
            KeyCode::Delete => self.with_search_query(Input::delete),
            KeyCode::Backspace => self.with_search_query(Input::backspace),
            KeyCode::Char(character) => {
                if let Some(view) = self.user_search.as_mut() {
                    view.query.insert(character);
                }
            }
            _ => {}
        }
    }

    fn with_search_query(&mut self, edit: impl FnOnce(&mut Input)) {
        if let Some(view) = self.user_search.as_mut() {
            edit(&mut view.query);
        }
    }

    /// Results-focus keys: `j`/`k` navigate (with `k` at the top returning to the
    /// query), `Enter` opens the profile card, `c` starts a chat, `a` adds to the
    /// open chat, and `i`/`/` return to the query.
    fn handle_user_search_results_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(view) = self.user_search.as_mut() {
                    if view.selected == 0 {
                        view.focus = UserSearchFocus::Query;
                    } else {
                        view.select_up();
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(view) = self.user_search.as_mut() {
                    view.select_down();
                }
            }
            KeyCode::Enter => {
                if let Err(err) = self.open_search_profile_card() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Char('c') => self.open_new_chat_with_user_popup(),
            KeyCode::Char('a') => self.open_add_user_to_chat_popup(),
            KeyCode::Char('i') | KeyCode::Char('/') => {
                if let Some(view) = self.user_search.as_mut() {
                    view.focus = UserSearchFocus::Query;
                }
            }
            KeyCode::Char('?') => self.popup = Some(Popup::help()),
            _ => {}
        }
    }

    fn open_new_chat_with_user_popup(&mut self) {
        let Some(result) = self
            .user_search
            .as_ref()
            .and_then(UserSearchView::selected_result)
        else {
            return;
        };
        let pubkey = result.pubkey.clone();
        let mut input = Input::default();
        input.set_value(result.display_label());
        self.popup = Some(Popup::Text {
            purpose: TextPurpose::NewChatWithUser { pubkey },
            title: "New Chat".to_owned(),
            input,
        });
    }

    /// Add the selected found user to the open chat. Guarded: only when a chat is
    /// loaded (the open conversation); otherwise a status-line notice explains.
    fn open_add_user_to_chat_popup(&mut self) {
        let Some(result) = self
            .user_search
            .as_ref()
            .and_then(UserSearchView::selected_result)
        else {
            return;
        };
        let pubkey = result.pubkey.clone();
        let label = result.display_label();
        let Some(group_id) = self.messages_group_id.clone() else {
            self.status = "open a chat first to add a user to it".to_owned();
            return;
        };
        self.popup = Some(Popup::Confirm {
            purpose: ConfirmPurpose::AddUserToChat { group_id, pubkey },
            title: "Add to Chat".to_owned(),
            body: vec![format!(
                "Add {} to the open chat?",
                shorten(&terminal_safe_text(&label), 24)
            )],
        });
    }

    /// Profile-screen keys: `j`/`k` move the field/follow cursor, `Enter` edits
    /// the selected field, `f` follows by pubkey, `x` unfollows the selected row.
    pub(crate) fn handle_profile_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        match key.code {
            KeyCode::Esc => self.leave_screen(),
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(view) = self.profile_view.as_mut() {
                    view.select_up();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(view) = self.profile_view.as_mut() {
                    view.select_down();
                }
            }
            KeyCode::Enter => self.open_profile_edit_popup(),
            KeyCode::Char('f') => {
                self.popup = Some(Popup::Text {
                    purpose: TextPurpose::FollowByPubkey,
                    title: "Follow User".to_owned(),
                    input: Input::default(),
                });
            }
            KeyCode::Char('x') => self.open_unfollow_popup(),
            KeyCode::Char('?') => self.popup = Some(Popup::help()),
            _ => {}
        }
        Ok(())
    }

    /// Open the edit popup for the selected profile field, prefilled with its
    /// current value. A no-op with a status notice when a follow row is selected.
    fn open_profile_edit_popup(&mut self) {
        let Some(view) = &self.profile_view else {
            return;
        };
        let Some(ProfileTarget::Field(field)) = view.selected_target() else {
            self.status = "select a field to edit; f follows, x unfollows".to_owned();
            return;
        };
        let mut input = Input::default();
        if let Some(value) = view.field_value(field) {
            input.set_value(value.to_owned());
        }
        self.popup = Some(Popup::Text {
            purpose: TextPurpose::EditProfileField { field },
            title: format!("Edit {}", field.label()),
            input,
        });
    }

    fn open_unfollow_popup(&mut self) {
        let Some(view) = &self.profile_view else {
            return;
        };
        let Some(ProfileTarget::Follow(index)) = view.selected_target() else {
            self.status = "select a follow to unfollow".to_owned();
            return;
        };
        let Some(npub) = view.follows.get(index).cloned() else {
            return;
        };
        self.popup = Some(Popup::Confirm {
            purpose: ConfirmPurpose::Unfollow {
                pubkey: npub.clone(),
            },
            title: "Unfollow".to_owned(),
            body: vec![format!(
                "Unfollow {}?",
                shorten(&terminal_safe_text(&npub), 24)
            )],
        });
    }

    /// Relay-health keys: `r` refreshes, `j`/`k` and PageUp/PageDown scroll.
    pub(crate) fn handle_relay_health_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        match key.code {
            KeyCode::Esc => self.leave_screen(),
            KeyCode::Char('r') => {
                if let Err(err) = self.refresh_relay_health() {
                    self.status = format!("error: {err}");
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll_relay_health(-1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_relay_health(1),
            KeyCode::PageUp => self.scroll_relay_health(-10),
            KeyCode::PageDown => self.scroll_relay_health(10),
            KeyCode::Char('?') => self.popup = Some(Popup::help()),
            _ => {}
        }
        Ok(())
    }

    fn scroll_relay_health(&mut self, delta: i16) {
        if let Some(view) = self.relay_health.as_mut() {
            // Clamp downward scroll to the last content line so `j`/PageDown past the
            // end parks at the bottom instead of scrolling into empty space, mirroring
            // the timeline's clamped paging.
            let max_scroll = relay_health_lines(&view.data).len().saturating_sub(1) as u16;
            view.scroll = if delta < 0 {
                view.scroll.saturating_sub(delta.unsigned_abs())
            } else {
                view.scroll.saturating_add(delta as u16).min(max_scroll)
            };
        }
    }
}
