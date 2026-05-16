use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use serde_json::Value;

use crate::{Cli, CliOutput, SecretStoreKind};

type TuiResult<T> = Result<T, TuiError>;

const DAEMON_STATUS_INTERVAL: Duration = Duration::from_secs(2);
const LIVE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
enum TuiError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Cli(String),
}

pub(crate) async fn run_tui(cli: Cli) -> CliOutput {
    match TuiApp::new(cli).and_then(|mut app| app.run()) {
        Ok(()) => CliOutput {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
        Err(err) => CliOutput {
            code: 1,
            stdout: String::new(),
            stderr: format!("error: {err}\n"),
        },
    }
}

#[derive(Clone, Debug)]
struct DmClient {
    exe: PathBuf,
    home: Option<PathBuf>,
    socket: Option<PathBuf>,
    relay: Option<String>,
    secret_store: Option<SecretStoreKind>,
    keychain_service: Option<String>,
}

impl DmClient {
    fn from_cli(cli: &Cli) -> TuiResult<Self> {
        Ok(Self {
            exe: std::env::current_exe()?,
            home: cli.home.clone(),
            socket: cli.socket.clone(),
            relay: cli.relay.clone(),
            secret_store: cli.secret_store,
            keychain_service: cli.keychain_service.clone(),
        })
    }

    fn run_json<S>(&self, account: Option<&str>, args: &[S]) -> TuiResult<Value>
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

        let output = command.output()?;
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccountRow {
    account_id: String,
    npub: String,
    local_signing: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChatRow {
    group_id: String,
    name: String,
    archived: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MessageRow {
    direction: String,
    from: String,
    plaintext: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct DaemonView {
    running: bool,
    pid: Option<u64>,
    sync_interval_ms: Option<u64>,
    last_sync: Option<DaemonSyncView>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DaemonSyncView {
    accounts: u64,
    events: u64,
    joined_groups: u64,
    messages: u64,
    errors: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Focus {
    Accounts,
    Chats,
    Composer,
}

impl Focus {
    fn next(self) -> Self {
        match self {
            Self::Accounts => Self::Chats,
            Self::Chats => Self::Composer,
            Self::Composer => Self::Accounts,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Accounts => Self::Composer,
            Self::Chats => Self::Accounts,
            Self::Composer => Self::Chats,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Chats => "chats",
            Self::Composer => "composer",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SlashCommand {
    Help,
    Refresh,
    Sync,
    Account(String),
    AccountCreate,
    AccountAddPublic(String),
    AccountImportSecret(String),
    DaemonStatus,
    DaemonStart { sync_interval_ms: Option<u64> },
    DaemonStop,
    ChatNew { name: String, members: Vec<String> },
    ChatRename(String),
    ChatDescribe(String),
    ChatArchive,
    ChatUnarchive,
    ChatArchived(bool),
    ChatMembers,
    MembersAdd(Vec<String>),
    MembersRemove(String),
    MembersClear,
    MembersList,
    Invite(String),
    Remove(String),
    ImageSend(String),
    KeysPublish,
    KeysFetch(String),
    Quit,
}

struct TuiApp {
    client: DmClient,
    initial_account: Option<String>,
    running: bool,
    focus: Focus,
    accounts: Vec<AccountRow>,
    selected_account: usize,
    chats: Vec<ChatRow>,
    selected_chat: usize,
    show_archived_chats: bool,
    messages: Vec<MessageRow>,
    daemon: DaemonView,
    last_daemon_poll: Instant,
    last_live_refresh: Instant,
    member_draft: Vec<String>,
    input: String,
    status: String,
    show_help: bool,
}

impl TuiApp {
    fn new(cli: Cli) -> TuiResult<Self> {
        let client = DmClient::from_cli(&cli)?;
        let now = Instant::now();
        Ok(Self {
            client,
            initial_account: cli.account.clone(),
            running: true,
            focus: Focus::Composer,
            accounts: Vec::new(),
            selected_account: 0,
            chats: Vec::new(),
            selected_chat: 0,
            show_archived_chats: false,
            messages: Vec::new(),
            daemon: DaemonView::default(),
            last_daemon_poll: now,
            last_live_refresh: now,
            member_draft: Vec::new(),
            input: String::new(),
            status: "loading accounts".to_owned(),
            show_help: false,
        })
    }

    fn run(&mut self) -> TuiResult<()> {
        let mut terminal = ratatui::init();
        let result = (|| -> TuiResult<()> {
            let _ = self.refresh_daemon_status();
            self.refresh_accounts()?;
            while self.running {
                self.tick();
                terminal.draw(|frame| self.render(frame))?;
                if event::poll(Duration::from_millis(200))? {
                    match event::read()? {
                        Event::Key(key) if key.kind == KeyEventKind::Press => {
                            self.handle_key(key)?;
                        }
                        _ => {}
                    }
                }
            }
            Ok(())
        })();
        ratatui::restore();
        result
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_daemon_poll) >= DAEMON_STATUS_INTERVAL {
            if let Err(err) = self.refresh_daemon_status() {
                self.status = format!("daemon status failed: {err}");
            }
            self.last_daemon_poll = now;
        }

        if should_live_refresh(
            &self.daemon,
            &self.input,
            now.duration_since(self.last_live_refresh),
        ) {
            match self.refresh_accounts() {
                Ok(()) => {
                    self.status = live_refresh_status(
                        self.accounts.len(),
                        self.chats.len(),
                        self.messages.len(),
                    );
                }
                Err(err) => {
                    self.status = format!("live refresh failed: {err}");
                }
            }
            self.last_live_refresh = now;
        }
    }

    fn render(&self, frame: &mut Frame) {
        let area = frame.area();
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(5),
            ])
            .split(area);

        self.render_header(frame, root[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(34),
                Constraint::Length(36),
                Constraint::Min(24),
            ])
            .split(root[1]);

        self.render_accounts(frame, body[0]);
        self.render_chats(frame, body[1]);
        self.render_messages(frame, body[2]);
        self.render_composer(frame, root[2]);

        if self.show_help {
            self.render_help(frame, centered_rect(70, 70, area));
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let account = self
            .selected_account_row()
            .map(|account| shorten(&account.npub, 18))
            .unwrap_or_else(|| "no account".to_owned());
        let chat = self
            .selected_chat_row()
            .map(|chat| shorten(&chat.name, 24))
            .unwrap_or_else(|| "no chat".to_owned());
        let daemon = daemon_header_label(&self.daemon);
        let line = Line::from(vec![
            Span::styled(
                "dm",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::raw(format!("focus={}  ", self.focus.title())),
            Span::raw(format!("daemon={daemon}  ")),
            Span::raw(format!("account={account}  chat={chat}")),
        ]);
        frame.render_widget(
            Paragraph::new(line)
                .block(Block::default().borders(Borders::ALL).title("Darkmatter"))
                .alignment(Alignment::Left),
            area,
        );
    }

    fn render_accounts(&self, frame: &mut Frame, area: Rect) {
        let items = if self.accounts.is_empty() {
            vec![ListItem::new("no accounts")]
        } else {
            self.accounts
                .iter()
                .enumerate()
                .map(|(index, account)| {
                    let marker = if index == self.selected_account {
                        ">"
                    } else {
                        " "
                    };
                    let signing = if account.local_signing {
                        "local"
                    } else {
                        "public"
                    };
                    let style = selected_style(index == self.selected_account);
                    ListItem::new(Line::from(vec![
                        Span::raw(format!("{marker} ")),
                        Span::styled(shorten(&account.npub, 22), Style::default().fg(Color::Cyan)),
                        Span::raw(format!(" {signing}")),
                    ]))
                    .style(style)
                })
                .collect()
        };
        frame.render_widget(
            List::new(items).block(panel_block("Accounts", self.focus == Focus::Accounts)),
            area,
        );
    }

    fn render_chats(&self, frame: &mut Frame, area: Rect) {
        let items = if self.chats.is_empty() {
            vec![ListItem::new("no chats")]
        } else {
            self.chats
                .iter()
                .enumerate()
                .map(|(index, chat)| {
                    let marker = if index == self.selected_chat {
                        ">"
                    } else {
                        " "
                    };
                    let archived = if chat.archived { " archived" } else { "" };
                    let style = selected_style(index == self.selected_chat);
                    ListItem::new(Line::from(vec![
                        Span::raw(format!("{marker} ")),
                        Span::styled(shorten(&chat.name, 24), Style::default().fg(Color::Green)),
                        Span::raw(archived),
                    ]))
                    .style(style)
                })
                .collect()
        };
        frame.render_widget(
            List::new(items).block(panel_block("Chats", self.focus == Focus::Chats)),
            area,
        );
    }

    fn render_messages(&self, frame: &mut Frame, area: Rect) {
        let lines = if self.messages.is_empty() {
            vec![Line::from("no messages")]
        } else {
            self.messages
                .iter()
                .rev()
                .flat_map(|message| {
                    let author = if message.direction == "sent" {
                        "me".to_owned()
                    } else {
                        shorten(&message.from, 18)
                    };
                    [
                        Line::from(vec![
                            Span::styled(author, Style::default().fg(Color::Yellow)),
                            Span::raw(": "),
                            Span::raw(message.plaintext.clone()),
                        ]),
                        Line::from(""),
                    ]
                })
                .collect()
        };
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Messages", false))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_composer(&self, frame: &mut Frame, area: Rect) {
        let prompt = if self.input.is_empty() {
            "type a message or /help".to_owned()
        } else {
            composer_display_text(&self.input)
        };
        let lines = vec![
            Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::Cyan)),
                Span::raw(prompt),
            ]),
            Line::from(member_draft_line(&self.member_draft)),
            Line::from(self.status.clone()),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Composer", self.focus == Focus::Composer))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(Span::styled(
                "Darkmatter TUI",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Tab cycles panels. Arrows move. Enter selects or submits. Ctrl-C quits."),
            Line::from(""),
            Line::from("/sync"),
            Line::from("/refresh"),
            Line::from("/account <npub-or-hex>"),
            Line::from("/account create"),
            Line::from("/account add <npub-or-hex>"),
            Line::from("/account import <nsec>"),
            Line::from("/daemon status"),
            Line::from("/daemon start [sync-interval-ms]"),
            Line::from("/daemon stop"),
            Line::from("/chat new <name> [member-npub-or-hex ...]"),
            Line::from("/chat rename <name>"),
            Line::from("/chat describe <description>"),
            Line::from("/chat archive"),
            Line::from("/chat unarchive"),
            Line::from("/chat archived [on|off]"),
            Line::from("/chat members"),
            Line::from("/members add <npub-or-hex> [...]"),
            Line::from("/members remove <npub-or-hex>"),
            Line::from("/members clear"),
            Line::from("/members list"),
            Line::from("/invite <npub-or-hex>"),
            Line::from("/remove <npub-or-hex>"),
            Line::from("/image <path>"),
            Line::from("/keys publish"),
            Line::from("/keys fetch <npub-or-hex>"),
            Line::from("/quit"),
        ];
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Help"))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn handle_key(&mut self, key: KeyEvent) -> TuiResult<()> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return Ok(());
        }

        match key.code {
            KeyCode::Char('?') if self.focus != Focus::Composer || self.input.is_empty() => {
                self.show_help = !self.show_help;
            }
            KeyCode::Char('q') if self.focus != Focus::Composer && self.input.is_empty() => {
                self.running = false;
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.previous(),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
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
                self.focus = Focus::Composer;
                self.input.push('/');
            }
            KeyCode::Char('j') if self.focus != Focus::Composer => self.move_selection(1),
            KeyCode::Char('k') if self.focus != Focus::Composer => self.move_selection(-1),
            KeyCode::Char(character) if self.focus == Focus::Composer => {
                self.input.push(character);
            }
            _ => {}
        }
        Ok(())
    }

    fn move_selection(&mut self, delta: isize) {
        match self.focus {
            Focus::Accounts => {
                self.selected_account =
                    move_index(self.selected_account, self.accounts.len(), delta);
            }
            Focus::Chats => {
                self.selected_chat = move_index(self.selected_chat, self.chats.len(), delta);
            }
            Focus::Composer => {}
        }
    }

    fn activate_focus(&mut self) -> TuiResult<()> {
        match self.focus {
            Focus::Accounts => self.select_current_account(),
            Focus::Chats => self.refresh_messages(),
            Focus::Composer => self.submit_input(),
        }
    }

    fn submit_input(&mut self) -> TuiResult<()> {
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

    fn run_slash_command(&mut self, command: SlashCommand) -> TuiResult<()> {
        match command {
            SlashCommand::Help => {
                self.show_help = true;
                Ok(())
            }
            SlashCommand::Refresh => self.refresh_accounts(),
            SlashCommand::Sync => {
                let account_id = self.require_selected_local_account()?;
                let result = self.client.run_json(Some(&account_id), &["sync"])?;
                let status = sync_status(&result);
                self.refresh_chats()?;
                self.status = status;
                Ok(())
            }
            SlashCommand::Account(selector) => self.select_account_by_selector(&selector),
            SlashCommand::AccountCreate => self.create_or_import_account(None, "created account"),
            SlashCommand::AccountAddPublic(account) => {
                self.create_or_import_account(Some(account), "added public account")
            }
            SlashCommand::AccountImportSecret(secret) => {
                self.create_or_import_account(Some(secret), "imported account")
            }
            SlashCommand::DaemonStatus => {
                self.refresh_daemon_status()?;
                self.status = daemon_status_sentence(&self.daemon);
                Ok(())
            }
            SlashCommand::DaemonStart { sync_interval_ms } => self.start_daemon(sync_interval_ms),
            SlashCommand::DaemonStop => self.stop_daemon(),
            SlashCommand::ChatNew { name, members } => self.create_chat(name, members),
            SlashCommand::ChatRename(name) => self.update_selected_chat(Some(name), None),
            SlashCommand::ChatDescribe(description) => {
                self.update_selected_chat(None, Some(description))
            }
            SlashCommand::ChatArchive => self.set_selected_chat_archived(true),
            SlashCommand::ChatUnarchive => self.set_selected_chat_archived(false),
            SlashCommand::ChatArchived(include) => self.set_archived_chat_visibility(include),
            SlashCommand::ChatMembers => self.show_selected_chat_members(),
            SlashCommand::MembersAdd(members) => {
                add_member_refs(&mut self.member_draft, members);
                self.status = member_draft_status(&self.member_draft);
                Ok(())
            }
            SlashCommand::MembersRemove(member) => {
                let removed = remove_member_ref(&mut self.member_draft, &member);
                self.status = if removed {
                    member_draft_status(&self.member_draft)
                } else {
                    format!("member draft did not include {}", shorten(&member, 18))
                };
                Ok(())
            }
            SlashCommand::MembersClear => {
                self.member_draft.clear();
                self.status = "member draft cleared".to_owned();
                Ok(())
            }
            SlashCommand::MembersList => {
                self.status = member_draft_status(&self.member_draft);
                Ok(())
            }
            SlashCommand::Invite(member) => {
                let account_id = self.require_selected_local_account()?;
                let group_id = self.require_selected_group()?;
                let args = vec![
                    "group".to_owned(),
                    "invite".to_owned(),
                    group_id,
                    "--member".to_owned(),
                    member,
                ];
                let result = self.client.run_json(Some(&account_id), &args)?;
                let status = publish_status("invited member", &result);
                self.refresh_messages()?;
                self.status = status;
                Ok(())
            }
            SlashCommand::Remove(member) => {
                let account_id = self.require_selected_local_account()?;
                let group_id = self.require_selected_group()?;
                let args = vec![
                    "group".to_owned(),
                    "remove".to_owned(),
                    group_id,
                    "--member".to_owned(),
                    member,
                ];
                let result = self.client.run_json(Some(&account_id), &args)?;
                let status = publish_status("removed member", &result);
                self.refresh_messages()?;
                self.status = status;
                Ok(())
            }
            SlashCommand::ImageSend(path) => Err(TuiError::Cli(image_send_error(&path))),
            SlashCommand::KeysPublish => {
                let account_id = self.require_selected_local_account()?;
                let result = self
                    .client
                    .run_json(Some(&account_id), &["keys", "publish"])?;
                let bytes = result
                    .get("key_package_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                self.status = format!("published key package bytes={bytes}");
                Ok(())
            }
            SlashCommand::KeysFetch(account) => {
                let result = self.client.run_json(None, &["keys", "fetch", &account])?;
                let bytes = result
                    .get("key_package_bytes")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                self.status = format!("fetched key package bytes={bytes}");
                Ok(())
            }
            SlashCommand::Quit => {
                self.running = false;
                Ok(())
            }
        }
    }

    fn send_message(&mut self, text: String) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let args = vec!["message", "send", &group_id, &text];
        let result = self.client.run_json(Some(&account_id), &args)?;
        let status = publish_status("sent message", &result);
        self.refresh_messages()?;
        self.status = status;
        Ok(())
    }

    fn create_chat(&mut self, name: String, members: Vec<String>) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let mut all_members = Vec::new();
        add_member_refs(&mut all_members, self.member_draft.clone());
        add_member_refs(&mut all_members, members);
        let mut args = vec!["group".to_owned(), "create".to_owned(), name];
        args.extend(all_members.iter().cloned());
        let result = self.client.run_json(Some(&account_id), &args)?;
        let group_id = value_string(&result, "group_id");
        let member_count = all_members.len();
        self.member_draft.clear();
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

    fn update_selected_chat(
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

    fn set_selected_chat_archived(&mut self, archived: bool) -> TuiResult<()> {
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

    fn show_selected_chat_members(&mut self) -> TuiResult<()> {
        let account_id = self.require_selected_local_account()?;
        let group_id = self.require_selected_group()?;
        let result = self
            .client
            .run_json(Some(&account_id), &["group", "members", &group_id])?;
        self.status = group_members_status(&result);
        Ok(())
    }

    fn set_archived_chat_visibility(&mut self, include: bool) -> TuiResult<()> {
        self.show_archived_chats = include;
        self.refresh_chats()?;
        self.status = if include {
            "showing archived chats".to_owned()
        } else {
            "hiding archived chats".to_owned()
        };
        Ok(())
    }

    fn create_or_import_account(
        &mut self,
        identity: Option<String>,
        action: &'static str,
    ) -> TuiResult<()> {
        let mut args = vec!["account".to_owned(), "create".to_owned()];
        args.extend(identity);
        let result = self.client.run_json(None, &args)?;
        let selector =
            value_string(&result, "account_id").or_else(|| value_string(&result, "npub"));
        let npub = value_string(&result, "npub").unwrap_or_else(|| "unknown".to_owned());
        let local_signing = result
            .get("local_signing")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        self.refresh_accounts()?;
        if let Some(selector) = selector.as_deref()
            && let Some(index) = selected_account_index(&self.accounts, Some(selector))
        {
            self.selected_account = index;
            if local_signing {
                self.refresh_chats()?;
            } else {
                self.chats.clear();
                self.messages.clear();
            }
        }

        let signing = if local_signing {
            "local-signing"
        } else {
            "public-only"
        };
        self.status = format!("{action} {} {signing}", shorten(&npub, 18));
        Ok(())
    }

    fn refresh_daemon_status(&mut self) -> TuiResult<()> {
        let result = self.client.run_json(None, &["daemon", "status"])?;
        self.daemon = parse_daemon_view(&result);
        Ok(())
    }

    fn start_daemon(&mut self, sync_interval_ms: Option<u64>) -> TuiResult<()> {
        let mut args = vec!["daemon".to_owned(), "start".to_owned()];
        if let Some(sync_interval_ms) = sync_interval_ms {
            args.push("--sync-interval-ms".to_owned());
            args.push(sync_interval_ms.to_string());
        }
        let result = self.client.run_json(None, &args)?;
        self.daemon = parse_daemon_view(&result);
        self.status = daemon_status_sentence(&self.daemon);
        Ok(())
    }

    fn stop_daemon(&mut self) -> TuiResult<()> {
        let result = self.client.run_json(None, &["daemon", "stop"])?;
        self.daemon = parse_daemon_view(&result);
        self.status = "daemon stopped".to_owned();
        Ok(())
    }

    fn refresh_accounts(&mut self) -> TuiResult<()> {
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
            self.status = "no accounts yet; create one with dm account create".to_owned();
            return Ok(());
        }
        self.refresh_chats()
    }

    fn refresh_chats(&mut self) -> TuiResult<()> {
        let Some(account) = self.selected_account_row().cloned() else {
            self.chats.clear();
            self.messages.clear();
            self.status = "no account selected".to_owned();
            return Ok(());
        };
        if !account.local_signing {
            self.chats.clear();
            self.messages.clear();
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
        self.selected_chat =
            selected_chat_index(&self.chats, previous_group_id.as_deref()).unwrap_or(0);
        if self.chats.is_empty() {
            self.messages.clear();
            self.status = format!("loaded account {}; no chats", shorten(&account.npub, 18));
            return Ok(());
        }
        self.refresh_messages()
    }

    fn refresh_messages(&mut self) -> TuiResult<()> {
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
        self.status = format!("loaded {} message(s)", self.messages.len());
        Ok(())
    }

    fn select_current_account(&mut self) -> TuiResult<()> {
        if self.accounts.is_empty() {
            return Ok(());
        }
        self.refresh_chats()
    }

    fn select_account_by_selector(&mut self, selector: &str) -> TuiResult<()> {
        let Some(index) = self
            .accounts
            .iter()
            .position(|account| account_matches(account, selector))
        else {
            return Err(TuiError::Cli(format!("account not loaded: {selector}")));
        };
        self.selected_account = index;
        self.status = format!("selected account {}", shorten(selector, 18));
        self.refresh_chats()
    }

    fn select_chat_by_group_id(&mut self, group_id: &str) -> TuiResult<()> {
        let Some(index) = self.chats.iter().position(|chat| chat.group_id == group_id) else {
            return Ok(());
        };
        self.selected_chat = index;
        self.refresh_messages()
    }

    fn selected_account_row(&self) -> Option<&AccountRow> {
        self.accounts.get(self.selected_account)
    }

    fn selected_chat_row(&self) -> Option<&ChatRow> {
        self.chats.get(self.selected_chat)
    }

    fn require_selected_local_account(&self) -> TuiResult<String> {
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

    fn require_selected_group(&self) -> TuiResult<String> {
        self.selected_chat_row()
            .map(|chat| chat.group_id.clone())
            .ok_or_else(|| TuiError::Cli("no chat selected".to_owned()))
    }
}

fn parse_slash_command(input: &str) -> Result<SlashCommand, String> {
    let trimmed = input.trim();
    if !trimmed.starts_with('/') {
        return Err("slash command must start with /".to_owned());
    }
    let mut parts = trimmed[1..].split_whitespace();
    let Some(command) = parts.next() else {
        return Err("empty slash command".to_owned());
    };
    let rest = parts.map(str::to_owned).collect::<Vec<_>>();
    match command {
        "help" | "?" => Ok(SlashCommand::Help),
        "refresh" => Ok(SlashCommand::Refresh),
        "sync" => Ok(SlashCommand::Sync),
        "account" => parse_account_command(rest),
        "daemon" => parse_daemon_command(rest),
        "chat" => parse_chat_command(rest),
        "members" => parse_members_command(rest),
        "invite" => one_arg(command, rest).map(SlashCommand::Invite),
        "remove" => one_arg(command, rest).map(SlashCommand::Remove),
        "image" => one_arg(command, rest).map(SlashCommand::ImageSend),
        "keys" => parse_keys_command(rest),
        "quit" | "q" => Ok(SlashCommand::Quit),
        other => Err(format!("unknown slash command: /{other}")),
    }
}

fn parse_chat_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, name, members @ ..] if command == "new" => Ok(SlashCommand::ChatNew {
            name: name.clone(),
            members: members.to_vec(),
        }),
        [command] if command == "new" => Err("/chat new requires a name".to_owned()),
        [command, name @ ..] if command == "rename" && !name.is_empty() => {
            Ok(SlashCommand::ChatRename(name.join(" ")))
        }
        [command] if command == "rename" => Err("/chat rename requires a name".to_owned()),
        [command, description @ ..] if command == "describe" && !description.is_empty() => {
            Ok(SlashCommand::ChatDescribe(description.join(" ")))
        }
        [command] if command == "describe" => {
            Err("/chat describe requires a description".to_owned())
        }
        [command] if command == "archive" => Ok(SlashCommand::ChatArchive),
        [command] if command == "unarchive" => Ok(SlashCommand::ChatUnarchive),
        [command] if command == "archived" => Ok(SlashCommand::ChatArchived(true)),
        [command, value] if command == "archived" => {
            parse_on_off(value).map(SlashCommand::ChatArchived)
        }
        [command] if command == "members" => Ok(SlashCommand::ChatMembers),
        [] => Err(
            "/chat expects new, rename, describe, archive, unarchive, archived, or members"
                .to_owned(),
        ),
        _ => Err(
            "/chat expects new, rename, describe, archive, unarchive, archived, or members"
                .to_owned(),
        ),
    }
}

fn parse_members_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command, members @ ..] if command == "add" && !members.is_empty() => {
            Ok(SlashCommand::MembersAdd(members.to_vec()))
        }
        [command] if command == "add" => {
            Err("/members add requires at least one member".to_owned())
        }
        [command, member] if command == "remove" => Ok(SlashCommand::MembersRemove(member.clone())),
        [command, ..] if command == "remove" => {
            Err("/members remove expects exactly one member".to_owned())
        }
        [command] if command == "clear" => Ok(SlashCommand::MembersClear),
        [command] if command == "list" => Ok(SlashCommand::MembersList),
        [command, ..] if command == "clear" => {
            Err("/members clear does not accept arguments".to_owned())
        }
        [command, ..] if command == "list" => {
            Err("/members list does not accept arguments".to_owned())
        }
        [] => Err("/members expects add, remove, clear, or list".to_owned()),
        _ => Err("/members expects add, remove, clear, or list".to_owned()),
    }
}

fn parse_daemon_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command] if command == "status" => Ok(SlashCommand::DaemonStatus),
        [command] if command == "start" => Ok(SlashCommand::DaemonStart {
            sync_interval_ms: None,
        }),
        [command, sync_interval_ms] if command == "start" => {
            let sync_interval_ms = sync_interval_ms
                .parse::<u64>()
                .map_err(|_| "/daemon start interval must be milliseconds".to_owned())?;
            Ok(SlashCommand::DaemonStart {
                sync_interval_ms: Some(sync_interval_ms),
            })
        }
        [command] if command == "stop" => Ok(SlashCommand::DaemonStop),
        [] => Err("/daemon expects status, start, or stop".to_owned()),
        [command, ..] if command == "status" => {
            Err("/daemon status does not accept arguments".to_owned())
        }
        [command, ..] if command == "stop" => {
            Err("/daemon stop does not accept arguments".to_owned())
        }
        _ => Err("/daemon expects status, start, or stop".to_owned()),
    }
}

fn parse_account_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command] if command == "create" => Ok(SlashCommand::AccountCreate),
        [command, account] if command == "add" => {
            Ok(SlashCommand::AccountAddPublic(account.clone()))
        }
        [command, secret] if command == "import" => {
            Ok(SlashCommand::AccountImportSecret(secret.clone()))
        }
        [selector] => Ok(SlashCommand::Account(selector.clone())),
        [] => Err("/account expects a selector, create, add, or import".to_owned()),
        [command, ..] if command == "create" => {
            Err("/account create does not accept arguments".to_owned())
        }
        [command, ..] if command == "add" => {
            Err("/account add expects exactly one npub or hex pubkey".to_owned())
        }
        [command, ..] if command == "import" => {
            Err("/account import expects exactly one nsec".to_owned())
        }
        _ => Err("/account expects a selector, create, add, or import".to_owned()),
    }
}

fn parse_keys_command(args: Vec<String>) -> Result<SlashCommand, String> {
    match args.as_slice() {
        [command] if command == "publish" => Ok(SlashCommand::KeysPublish),
        [command, account] if command == "fetch" => Ok(SlashCommand::KeysFetch(account.clone())),
        _ => Err("/keys expects 'publish' or 'fetch <npub-or-hex>'".to_owned()),
    }
}

fn parse_on_off(value: &str) -> Result<bool, String> {
    match value {
        "on" | "true" | "yes" => Ok(true),
        "off" | "false" | "no" => Ok(false),
        _ => Err("expected on or off".to_owned()),
    }
}

fn one_arg(command: &str, args: Vec<String>) -> Result<String, String> {
    match args.as_slice() {
        [arg] => Ok(arg.clone()),
        [] => Err(format!("/{command} requires an argument")),
        _ => Err(format!("/{command} accepts exactly one argument")),
    }
}

fn parse_account(value: &Value) -> Option<AccountRow> {
    Some(AccountRow {
        account_id: value_string(value, "account_id")?,
        npub: value_string(value, "npub")?,
        local_signing: value.get("local_signing").and_then(Value::as_bool)?,
    })
}

fn parse_chat(value: &Value) -> Option<ChatRow> {
    let profile = value.get("profile")?;
    Some(ChatRow {
        group_id: value_string(value, "group_id")?,
        name: value_string(profile, "name").unwrap_or_else(|| "unnamed".to_owned()),
        archived: value
            .get("archived")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_message(value: &Value) -> Option<MessageRow> {
    Some(MessageRow {
        direction: value_string(value, "direction").unwrap_or_else(|| "received".to_owned()),
        from: value_string(value, "from").unwrap_or_else(|| "unknown".to_owned()),
        plaintext: value_string(value, "plaintext")?,
    })
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn selected_account_index(accounts: &[AccountRow], selector: Option<&str>) -> Option<usize> {
    selector.and_then(|selector| {
        accounts
            .iter()
            .position(|account| account_matches(account, selector))
    })
}

fn selected_chat_index(chats: &[ChatRow], group_id: Option<&str>) -> Option<usize> {
    group_id.and_then(|group_id| chats.iter().position(|chat| chat.group_id == group_id))
}

fn account_matches(account: &AccountRow, selector: &str) -> bool {
    account.account_id == selector || account.npub == selector
}

fn move_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let max = len.saturating_sub(1) as isize;
    (current as isize + delta).clamp(0, max) as usize
}

fn sync_status(result: &Value) -> String {
    let events = result
        .get("events")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let joined = result
        .get("joined_groups")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let messages = result
        .get("messages")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    format!("sync: events={events} joined={joined} messages={messages}")
}

fn publish_status(action: &str, result: &Value) -> String {
    let published = result
        .get("published")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    format!("{action}; published={published}")
}

fn parse_daemon_view(value: &Value) -> DaemonView {
    DaemonView {
        running: value
            .get("running")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        pid: value.get("pid").and_then(Value::as_u64),
        sync_interval_ms: value.get("sync_interval_ms").and_then(Value::as_u64),
        last_sync: value.get("last_sync").and_then(parse_daemon_sync_view),
    }
}

fn parse_daemon_sync_view(value: &Value) -> Option<DaemonSyncView> {
    Some(DaemonSyncView {
        accounts: value.get("accounts").and_then(Value::as_u64)?,
        events: value.get("events").and_then(Value::as_u64).unwrap_or(0),
        joined_groups: value
            .get("joined_groups")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        messages: value.get("messages").and_then(Value::as_u64).unwrap_or(0),
        errors: value
            .get("errors")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
    })
}

fn daemon_header_label(daemon: &DaemonView) -> String {
    if !daemon.running {
        return "off".to_owned();
    }
    let mut label = daemon
        .pid
        .map(|pid| format!("on pid={pid}"))
        .unwrap_or_else(|| "on".to_owned());
    if let Some(sync) = &daemon.last_sync {
        label.push_str(&format!(
            " sync={}/{}/{}",
            sync.events, sync.joined_groups, sync.messages
        ));
        if sync.errors > 0 {
            label.push_str(&format!(" errors={}", sync.errors));
        }
    }
    label
}

fn daemon_status_sentence(daemon: &DaemonView) -> String {
    if !daemon.running {
        return "daemon not running".to_owned();
    }
    let interval = daemon
        .sync_interval_ms
        .map(|interval| format!(" interval={}ms", interval))
        .unwrap_or_default();
    let sync = daemon
        .last_sync
        .as_ref()
        .map(|sync| {
            format!(
                " last-sync accounts={} events={} joined={} messages={} errors={}",
                sync.accounts, sync.events, sync.joined_groups, sync.messages, sync.errors
            )
        })
        .unwrap_or_default();
    format!("daemon running{interval}{sync}")
}

fn should_live_refresh(daemon: &DaemonView, input: &str, elapsed: Duration) -> bool {
    daemon.running && input.is_empty() && elapsed >= LIVE_REFRESH_INTERVAL
}

fn live_refresh_status(accounts: usize, chats: usize, messages: usize) -> String {
    format!("live refresh: accounts={accounts} chats={chats} messages={messages}")
}

fn add_member_refs(draft: &mut Vec<String>, members: Vec<String>) {
    for member in members {
        if !member.is_empty() && !draft.iter().any(|existing| existing == &member) {
            draft.push(member);
        }
    }
}

fn remove_member_ref(draft: &mut Vec<String>, member: &str) -> bool {
    let Some(index) = draft.iter().position(|existing| existing == member) else {
        return false;
    };
    draft.remove(index);
    true
}

fn member_draft_line(draft: &[String]) -> String {
    if draft.is_empty() {
        return "members: none".to_owned();
    }
    format!("members: {}", member_ref_summary(draft))
}

fn member_draft_status(draft: &[String]) -> String {
    if draft.is_empty() {
        return "member draft is empty".to_owned();
    }
    format!("member draft: {}", member_ref_summary(draft))
}

fn member_ref_summary(members: &[String]) -> String {
    members
        .iter()
        .map(|member| shorten(member, 14))
        .collect::<Vec<_>>()
        .join(", ")
}

fn group_members_status(result: &Value) -> String {
    let members = result
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .filter_map(|member| {
                    value_string(member, "npub").or_else(|| value_string(member, "member_id"))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if members.is_empty() {
        return "members: none".to_owned();
    }
    format!("members: {}", member_ref_summary(&members))
}

fn image_send_error(path: &str) -> String {
    format!(
        "image messages are not implemented yet; {path} was not sent because encrypted media upload is still draft-only"
    )
}

fn selected_style(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

fn panel_block(title: &'static str, focused: bool) -> Block<'static> {
    let style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_style(style)
        .title(title)
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn shorten(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_owned();
    }
    if max_len <= 3 {
        return value.chars().take(max_len).collect();
    }
    let prefix_len = (max_len - 3) / 2;
    let suffix_len = max_len - 3 - prefix_len;
    let prefix = value.chars().take(prefix_len).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(suffix_len)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

fn composer_display_text(input: &str) -> String {
    const ACCOUNT_IMPORT_PREFIX: &str = "/account import ";
    if let Some(secret) = input.strip_prefix(ACCOUNT_IMPORT_PREFIX)
        && !secret.is_empty()
    {
        return format!("{ACCOUNT_IMPORT_PREFIX}<hidden nsec>");
    }
    input.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_command_parser_understands_core_commands() {
        assert_eq!(parse_slash_command("/help"), Ok(SlashCommand::Help));
        assert_eq!(parse_slash_command("/sync"), Ok(SlashCommand::Sync));
        assert_eq!(
            parse_slash_command("/account npub1abc"),
            Ok(SlashCommand::Account("npub1abc".to_owned()))
        );
        assert!(parse_slash_command("/new general npub1bob").is_err());
    }

    #[test]
    fn slash_command_parser_handles_key_package_commands() {
        assert_eq!(
            parse_slash_command("/keys publish"),
            Ok(SlashCommand::KeysPublish)
        );
        assert_eq!(
            parse_slash_command("/keys fetch npub1bob"),
            Ok(SlashCommand::KeysFetch("npub1bob".to_owned()))
        );
        assert!(parse_slash_command("/keys").is_err());
    }

    #[test]
    fn slash_command_parser_handles_account_onboarding_commands() {
        assert_eq!(
            parse_slash_command("/account create"),
            Ok(SlashCommand::AccountCreate)
        );
        assert_eq!(
            parse_slash_command("/account add npub1bob"),
            Ok(SlashCommand::AccountAddPublic("npub1bob".to_owned()))
        );
        assert_eq!(
            parse_slash_command("/account import nsec1secret"),
            Ok(SlashCommand::AccountImportSecret("nsec1secret".to_owned()))
        );
    }

    #[test]
    fn slash_command_parser_handles_daemon_commands() {
        assert_eq!(
            parse_slash_command("/daemon status"),
            Ok(SlashCommand::DaemonStatus)
        );
        assert_eq!(
            parse_slash_command("/daemon start"),
            Ok(SlashCommand::DaemonStart {
                sync_interval_ms: None,
            })
        );
        assert_eq!(
            parse_slash_command("/daemon start 750"),
            Ok(SlashCommand::DaemonStart {
                sync_interval_ms: Some(750),
            })
        );
        assert_eq!(
            parse_slash_command("/daemon stop"),
            Ok(SlashCommand::DaemonStop)
        );
        assert!(parse_slash_command("/daemon restart").is_err());
    }

    #[test]
    fn slash_command_parser_handles_chat_and_member_management_commands() {
        assert_eq!(
            parse_slash_command("/chat new general npub1bob deadbeef"),
            Ok(SlashCommand::ChatNew {
                name: "general".to_owned(),
                members: vec!["npub1bob".to_owned(), "deadbeef".to_owned()],
            })
        );
        assert_eq!(
            parse_slash_command("/chat rename Project Room"),
            Ok(SlashCommand::ChatRename("Project Room".to_owned()))
        );
        assert_eq!(
            parse_slash_command("/chat describe planning space"),
            Ok(SlashCommand::ChatDescribe("planning space".to_owned()))
        );
        assert_eq!(
            parse_slash_command("/chat archive"),
            Ok(SlashCommand::ChatArchive)
        );
        assert_eq!(
            parse_slash_command("/chat unarchive"),
            Ok(SlashCommand::ChatUnarchive)
        );
        assert_eq!(
            parse_slash_command("/chat archived"),
            Ok(SlashCommand::ChatArchived(true))
        );
        assert_eq!(
            parse_slash_command("/chat archived off"),
            Ok(SlashCommand::ChatArchived(false))
        );
        assert_eq!(
            parse_slash_command("/chat members"),
            Ok(SlashCommand::ChatMembers)
        );
        assert_eq!(
            parse_slash_command("/members add npub1bob npub1carol"),
            Ok(SlashCommand::MembersAdd(vec![
                "npub1bob".to_owned(),
                "npub1carol".to_owned(),
            ]))
        );
        assert_eq!(
            parse_slash_command("/members remove npub1bob"),
            Ok(SlashCommand::MembersRemove("npub1bob".to_owned()))
        );
        assert_eq!(
            parse_slash_command("/members clear"),
            Ok(SlashCommand::MembersClear)
        );
        assert_eq!(
            parse_slash_command("/members list"),
            Ok(SlashCommand::MembersList)
        );
    }

    #[test]
    fn member_draft_adds_uniquely_and_removes_by_pubkey() {
        let mut members = vec!["npub1bob".to_owned()];

        add_member_refs(
            &mut members,
            vec!["npub1bob".to_owned(), "npub1carol".to_owned()],
        );
        assert_eq!(members, vec!["npub1bob", "npub1carol"]);

        assert!(remove_member_ref(&mut members, "npub1bob"));
        assert_eq!(members, vec!["npub1carol"]);
        assert!(!remove_member_ref(&mut members, "npub1missing"));
    }

    #[test]
    fn slash_command_parser_keeps_image_send_explicitly_unsupported() {
        assert_eq!(
            parse_slash_command("/image /tmp/photo.jpg"),
            Ok(SlashCommand::ImageSend("/tmp/photo.jpg".to_owned()))
        );
        assert!(image_send_error("/tmp/photo.jpg").contains("not implemented"));
    }

    #[test]
    fn daemon_status_json_becomes_header_and_status_text() {
        let daemon = parse_daemon_view(&serde_json::json!({
            "running": true,
            "pid": 1234,
            "sync_interval_ms": 750,
            "last_sync": {
                "accounts": 2,
                "events": 3,
                "joined_groups": 1,
                "messages": 4,
                "errors": ["relay unavailable"]
            }
        }));

        assert_eq!(
            daemon_header_label(&daemon),
            "on pid=1234 sync=3/1/4 errors=1"
        );
        assert_eq!(
            daemon_status_sentence(&daemon),
            "daemon running interval=750ms last-sync accounts=2 events=3 joined=1 messages=4 errors=1"
        );
        assert_eq!(
            daemon_status_sentence(&parse_daemon_view(&serde_json::json!({"running": false}))),
            "daemon not running"
        );
    }

    #[test]
    fn live_refresh_waits_for_running_daemon_idle_input_and_interval() {
        let running = DaemonView {
            running: true,
            ..DaemonView::default()
        };
        let stopped = DaemonView::default();

        assert!(should_live_refresh(
            &running,
            "",
            LIVE_REFRESH_INTERVAL + Duration::from_millis(1)
        ));
        assert!(!should_live_refresh(
            &running,
            "/account",
            LIVE_REFRESH_INTERVAL + Duration::from_millis(1)
        ));
        assert!(!should_live_refresh(
            &stopped,
            "",
            LIVE_REFRESH_INTERVAL + Duration::from_millis(1)
        ));
        assert!(!should_live_refresh(
            &running,
            "",
            LIVE_REFRESH_INTERVAL - Duration::from_millis(1)
        ));
    }

    #[test]
    fn composer_redacts_nsec_imports_without_hiding_other_input() {
        assert_eq!(
            composer_display_text("/account import nsec1secret"),
            "/account import <hidden nsec>"
        );
        assert_eq!(
            composer_display_text("/account add npub1bob"),
            "/account add npub1bob"
        );
    }

    #[test]
    fn account_selection_matches_npub_or_hex_pubkey() {
        let account = AccountRow {
            account_id: "abc123".to_owned(),
            npub: "npub1abc".to_owned(),
            local_signing: true,
        };

        assert!(account_matches(&account, "abc123"));
        assert!(account_matches(&account, "npub1abc"));
        assert!(!account_matches(&account, "abc"));
    }

    #[test]
    fn move_index_clamps_at_list_edges() {
        assert_eq!(move_index(0, 3, -1), 0);
        assert_eq!(move_index(0, 3, 1), 1);
        assert_eq!(move_index(2, 3, 1), 2);
        assert_eq!(move_index(0, 0, 1), 0);
    }
}
