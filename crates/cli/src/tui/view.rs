//! TUI rendering: `TuiApp` draw methods and Ratatui line/style helpers.

use super::*;

pub(crate) fn daemon_header_label(daemon: &DaemonView) -> String {
    if !daemon.running {
        return "off".to_owned();
    }
    let mut label = daemon
        .pid
        .map(|pid| format!("on pid={pid}"))
        .unwrap_or_else(|| "on".to_owned());
    if let Some(activity) = &daemon.last_runtime_activity {
        label.push_str(&format!(
            " activity={}/{}/{}",
            activity.events, activity.joined_groups, activity.messages
        ));
        if activity.errors > 0 {
            label.push_str(&format!(" errors={}", activity.errors));
        }
    }
    let active_streams = daemon
        .stream_watches
        .iter()
        .filter(|watch| watch.status == "running")
        .count();
    if active_streams > 0 {
        label.push_str(&format!(" streams={active_streams}"));
    }
    label
}

pub(crate) fn daemon_status_sentence(daemon: &DaemonView) -> String {
    if !daemon.running {
        return "daemon not running".to_owned();
    }
    let activity = daemon
        .last_runtime_activity
        .as_ref()
        .map(|activity| {
            format!(
                " last-activity accounts={} events={} joined={} messages={} errors={}",
                activity.accounts,
                activity.events,
                activity.joined_groups,
                activity.messages,
                activity.errors
            )
        })
        .unwrap_or_default();
    let streams = stream_watch_status(daemon);
    let streams = if streams == "streams: none" {
        String::new()
    } else {
        format!(" {streams}")
    };
    format!("daemon running{activity}{streams}")
}

pub(crate) fn stream_watch_status(daemon: &DaemonView) -> String {
    if daemon.stream_watches.is_empty() {
        return "streams: none".to_owned();
    }
    let running = daemon
        .stream_watches
        .iter()
        .filter(|watch| watch.status == "running")
        .count();
    let completed = daemon
        .stream_watches
        .iter()
        .filter(|watch| watch.status == "completed")
        .count();
    let failed = daemon
        .stream_watches
        .iter()
        .filter(|watch| watch.status == "failed")
        .count();
    let latest = daemon
        .stream_watches
        .last()
        .map(|watch| {
            watch
                .stream_id
                .as_deref()
                .map(|stream_id| shorten(stream_id, 18))
                .unwrap_or_else(|| shorten(&watch.watch_id, 18))
        })
        .unwrap_or_else(|| "none".to_owned());
    format!("streams: running={running} completed={completed} failed={failed} latest={latest}")
}

pub(crate) fn stream_preview_lines(
    daemon: &DaemonView,
    live_previews: &[LiveStreamPreview],
    group_id: Option<&str>,
) -> Vec<Line<'static>> {
    let Some(group_id) = group_id else {
        return Vec::new();
    };
    let mut lines = live_previews
        .iter()
        .filter(|preview| preview.group_id == group_id)
        .filter_map(|preview| {
            stream_preview_line_pair(
                &preview.author,
                &preview.status,
                &preview.text,
                preview.error.as_deref(),
            )
        })
        .flatten()
        .collect::<Vec<_>>();
    lines.extend(
        daemon
            .stream_watches
            .iter()
            .filter(|watch| watch.group_id == group_id)
            .filter(|watch| {
                let Some(stream_id) = watch.stream_id.as_deref() else {
                    return true;
                };
                !live_previews
                    .iter()
                    .any(|preview| preview.group_id == group_id && preview.stream_id == stream_id)
            })
            .filter_map(|watch| {
                stream_preview_line_pair(
                    "stream",
                    &watch.status,
                    watch.text.as_deref().unwrap_or_default(),
                    watch.error.as_deref(),
                )
            })
            .flatten(),
    );
    lines
}

pub(crate) fn stream_preview_line_pair(
    author: &str,
    status: &str,
    text: &str,
    error: Option<&str>,
) -> Option<[Line<'static>; 2]> {
    let body = match status {
        "completed" => return None,
        "failed" => format!(
            "stream failed: {}",
            terminal_safe_text(error.unwrap_or("stream watch failed"))
        ),
        _ => {
            if text.is_empty() {
                return None;
            } else {
                terminal_safe_text(text)
            }
        }
    };
    Some([
        Line::from(""),
        Line::from(vec![
            Span::styled(
                terminal_safe_text(author),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(": "),
            Span::raw(body),
        ]),
    ])
}

pub(crate) fn message_lines(
    messages: &[MessageRow],
    selected_account: Option<&AccountRow>,
) -> Vec<Line<'static>> {
    messages
        .iter()
        .flat_map(|message| {
            let author = terminal_safe_text(&message_author_label(message, selected_account));
            [
                Line::from(vec![
                    Span::styled(author, Style::default().fg(Color::Yellow)),
                    Span::raw(": "),
                    Span::raw(terminal_safe_text(&message.display_text)),
                ]),
                Line::from(""),
            ]
        })
        .collect()
}

pub(crate) fn chat_row_line(chat: &ChatRow, selected: bool, unread_count: usize) -> Line<'static> {
    let marker = if selected { ">" } else { " " };
    let archived = if chat.archived { " archived" } else { "" };
    let mut ambient_style = Style::default();
    let mut label_style = row_label_style(selected, Color::Green);
    if unread_count > 0 {
        ambient_style = ambient_style.add_modifier(Modifier::BOLD);
        label_style = label_style.add_modifier(Modifier::BOLD);
    }
    Line::from(vec![
        Span::styled(format!("{marker} "), ambient_style),
        Span::styled(chat_label(&chat.name, unread_count, 24), label_style),
        Span::styled(archived.to_owned(), ambient_style),
    ])
}

pub(crate) fn chat_label(name: &str, unread_count: usize, max_len: usize) -> String {
    let name = terminal_safe_text(name);
    if unread_count == 0 {
        return shorten(&name, max_len);
    }
    shorten(&format!("{name} ({unread_count})"), max_len)
}

pub(crate) fn status_panel_lines(
    status: &str,
    diagnostics: Option<&GroupDiagnostics>,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(terminal_safe_text(status)),
        Line::from(""),
        Line::from(""),
    ];
    let Some(diagnostics) = diagnostics else {
        lines.push(Line::from("MLS no group selected"));
        return lines;
    };
    if let Some(error) = &diagnostics.error {
        lines.push(Line::from(format!(
            "MLS group={} unavailable: {}",
            shorten(&terminal_safe_text(&diagnostics.group_id), 18),
            terminal_safe_text(error)
        )));
        return lines;
    }
    let epoch = diagnostics
        .epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let member_count = diagnostics
        .member_count
        .map(|member_count| member_count.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    lines.push(Line::from(format!(
        "MLS epoch={epoch} group={} members={member_count}",
        shorten(&terminal_safe_text(&diagnostics.group_id), 18)
    )));
    if diagnostics.components.is_empty() {
        lines.push(Line::from("components: none"));
        return lines;
    }
    lines.push(Line::from("components:"));
    lines.extend(
        diagnostics
            .components
            .iter()
            .map(group_component_diagnostics_line),
    );
    lines
}

pub(crate) fn group_component_diagnostics_line(
    component: &GroupComponentDiagnostics,
) -> Line<'static> {
    let id = component
        .component_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    Line::from(format!(
        "{} id={id} data={}",
        terminal_safe_text(&component.component),
        terminal_safe_text(&component.data_hex)
    ))
}

pub(crate) fn selected_style(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

pub(crate) fn row_label_style(selected: bool, color: Color) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color)
    }
}

pub(crate) fn panel_block(title: &str, focused: bool) -> Block<'_> {
    let style = if focused {
        Style::default().fg(FOCUS_ACCENT)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    Block::default()
        .borders(Borders::ALL)
        .border_style(style)
        .title(title)
}

pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
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

impl TuiApp {
    pub(crate) fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
                Constraint::Length(12),
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
        self.render_status_panel(frame, root[3]);
        self.render_slash_suggestions(frame, root[2]);

        if self.show_help {
            self.render_help(frame, centered_rect(70, 70, area));
        }
    }

    pub(crate) fn render_header(&self, frame: &mut Frame, area: Rect) {
        let account = self
            .selected_account_row()
            .map(|account| shorten(&terminal_safe_text(&account_display_label(account)), 18))
            .unwrap_or_else(|| "no account".to_owned());
        let chat = self
            .selected_chat_row()
            .map(|chat| shorten(&terminal_safe_text(&chat.name), 24))
            .unwrap_or_else(|| "no chat".to_owned());
        let daemon = terminal_safe_text(&daemon_header_label(&self.daemon));
        let line = Line::from(vec![
            Span::styled(
                "dm",
                Style::default()
                    .fg(FOCUS_ACCENT)
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

    pub(crate) fn render_accounts(&self, frame: &mut Frame, area: Rect) {
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
                        Span::styled(
                            shorten(&terminal_safe_text(&account_display_label(account)), 22),
                            row_label_style(index == self.selected_account, ACCOUNT_ACCENT),
                        ),
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

    pub(crate) fn render_chats(&self, frame: &mut Frame, area: Rect) {
        let items = if self.chats.is_empty() {
            vec![ListItem::new("no chats")]
        } else {
            self.chats
                .iter()
                .enumerate()
                .map(|(index, chat)| {
                    let selected = index == self.selected_chat;
                    let unread_count = self
                        .unread_counts
                        .get(&chat.group_id)
                        .copied()
                        .unwrap_or_default();
                    ListItem::new(chat_row_line(chat, selected, unread_count))
                        .style(selected_style(selected))
                })
                .collect()
        };
        frame.render_widget(
            List::new(items).block(panel_block("Chats", self.focus == Focus::Chats)),
            area,
        );
    }

    pub(crate) fn render_messages(&mut self, frame: &mut Frame, area: Rect) {
        let mut lines = if self.messages.is_empty() {
            vec![Line::from("no messages")]
        } else {
            message_lines(&self.messages, self.message_account_row())
        };
        let group_id = self
            .messages_group_id
            .as_deref()
            .or_else(|| self.selected_chat_row().map(|chat| chat.group_id.as_str()));
        for preview in stream_preview_lines(&self.daemon, &self.live_stream_previews, group_id) {
            lines.push(preview);
        }

        let inner_width = area.width.saturating_sub(2);
        let inner_height = area.height.saturating_sub(2);
        self.messages_viewport = inner_height;

        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        let total = u16::try_from(paragraph.line_count(inner_width)).unwrap_or(u16::MAX);
        let (clamped_scroll, scroll_top) =
            messages_scroll_offsets(total, inner_height, self.messages_scroll);
        self.messages_scroll = clamped_scroll;

        let title = if scroll_top == 0 && self.messages_scroll == 0 {
            "Messages".to_owned()
        } else if self.messages_scroll == 0 {
            format!("Messages [{scroll_top} above]")
        } else {
            format!(
                "Messages [{scroll_top} above | {} below]",
                self.messages_scroll
            )
        };

        frame.render_widget(
            paragraph
                .block(panel_block(&title, self.focus == Focus::Messages))
                .scroll((scroll_top, 0)),
            area,
        );
    }

    pub(crate) fn render_composer(&self, frame: &mut Frame, area: Rect) {
        let prompt = if self.streaming.is_some() && self.input.is_empty() {
            "streaming... type text, Enter finishes, Esc cancels".to_owned()
        } else if self.input.is_empty() {
            "type a message or / for commands".to_owned()
        } else {
            composer_display_text(&self.input)
        };
        let lines = vec![Line::from(vec![
            Span::styled("> ", Style::default().fg(FOCUS_ACCENT)),
            Span::raw(terminal_safe_text(&prompt)),
        ])];
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Composer", self.focus == Focus::Composer))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    pub(crate) fn render_slash_suggestions(&self, frame: &mut Frame, composer_area: Rect) {
        if self.focus != Focus::Composer || self.streaming.is_some() || self.show_help {
            return;
        }
        let lines = slash_suggestion_lines(&self.input, SLASH_SUGGESTION_LIMIT);
        if lines.is_empty() || composer_area.width < 12 || composer_area.y == 0 {
            return;
        }

        let height = (lines.len() as u16 + 2).min(composer_area.y);
        let width = composer_area.width.saturating_sub(4).clamp(12, 84);
        let area = Rect {
            x: composer_area.x + (composer_area.width.saturating_sub(width) / 2),
            y: composer_area.y - height,
            width,
            height,
        };
        frame.render_widget(Clear, area);
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Commands"))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    pub(crate) fn render_status_panel(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new(status_panel_lines(
                &self.status,
                self.group_diagnostics.as_ref(),
            ))
            .block(panel_block("Status", false))
            .wrap(Wrap { trim: false }),
            area,
        );
    }

    pub(crate) fn render_help(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(Span::styled(
                "Darkmatter TUI",
                Style::default()
                    .fg(FOCUS_ACCENT)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Tab cycles panels. Arrows move. Enter selects or submits. Ctrl-C quits."),
            Line::from(
                "Messages panel: Up/Down or j/k scroll; PageUp/PageDown, Home/End jump. New messages stick to the bottom.",
            ),
            Line::from(""),
            Line::from("/refresh"),
            Line::from("/account <npub-or-hex>"),
            Line::from("/create-identity"),
            Line::from("/login <nsec-or-npub>"),
            Line::from("/daemon status"),
            Line::from("/daemon start"),
            Line::from("/daemon stop"),
            Line::from("/chat new <name> [member-npub-or-hex ...]"),
            Line::from("/chat rename <name>"),
            Line::from("/chat describe <description>"),
            Line::from("/chat archive"),
            Line::from("/chat unarchive"),
            Line::from("/chat archived [on|off]"),
            Line::from("/members add <npub-or-hex> [...]"),
            Line::from("/members remove <npub-or-hex> [...]"),
            Line::from("/members list"),
            Line::from("/keys fetch <npub-or-hex>"),
            Line::from("/keys rotate"),
            Line::from("/name <display-name>"),
            Line::from("/profile name <display-name>"),
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
}
