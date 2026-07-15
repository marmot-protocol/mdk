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

/// The messages-pane title: plain "Messages" when pinned with everything on
/// screen, otherwise annotated with the row counts above and below the viewport
/// so the reader knows history or newer content is off-screen.
pub(crate) fn timeline_pane_title(total: usize, first: usize, last: usize) -> String {
    let above = first;
    let below = total.saturating_sub(last + 1);
    match (above, below) {
        (0, 0) => "Messages".to_owned(),
        (above, 0) => format!("Messages [{above} older]"),
        (0, below) => format!("Messages [{below} newer]"),
        (above, below) => format!("Messages [{above} older | {below} newer]"),
    }
}

/// Apply the selection highlight to a row's rendered lines: a dark-gray
/// background over every span, bumping a dark-gray foreground to gray so the
/// timestamp/reply/attachment text stays legible on the highlight.
fn highlight_timeline_lines(lines: Vec<Line<'static>>) -> Vec<Line<'static>> {
    lines
        .into_iter()
        .map(|line| {
            let spans = line
                .spans
                .into_iter()
                .map(|span| {
                    let mut style = span.style.bg(Color::DarkGray);
                    if span.style.fg == Some(Color::DarkGray) {
                        style = style.fg(Color::Gray);
                    }
                    Span::styled(span.content, style)
                })
                .collect::<Vec<_>>();
            Line::from(spans)
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
                "wn",
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
                .block(Block::default().borders(Borders::ALL).title("White Noise"))
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
        let focused = self.focus == Focus::Messages;
        if self.timeline.is_empty() {
            frame.render_widget(
                Paragraph::new(vec![Line::from("no messages")])
                    .block(panel_block("Messages", focused)),
                area,
            );
            return;
        }

        let inner_width = area.width.saturating_sub(2);
        let inner_height = area.height.saturating_sub(2);

        // Live stream previews sit in a bottom block that only exists (and only
        // reserves viewport rows) while the view is anchored at the newest row.
        let group_id = self
            .messages_group_id
            .as_deref()
            .or_else(|| self.selected_chat_row().map(|chat| chat.group_id.as_str()));
        let preview_lines =
            stream_preview_lines(&self.daemon, &self.live_stream_previews, group_id);
        let bottom_block = if self.timeline_scroll.is_pinned() {
            u16::try_from(preview_lines.len()).unwrap_or(u16::MAX)
        } else {
            0
        };

        let selected_account = self.message_account_row();
        let heights = timeline_row_heights(&self.timeline, selected_account, inner_width);
        let total = self.timeline.len();
        let selected = self.timeline_scroll.resolved_selection(total);

        // One algorithm decides both the reported visible range and what is drawn,
        // so the follow-scroll feedback and the rendered rows never diverge.
        let (title, mut lines, range) = match timeline_visible_range(
            &heights,
            inner_height,
            self.timeline_scroll.offset,
            bottom_block,
        ) {
            Some((first, last)) => {
                let mut lines = Vec::new();
                for index in first..=last {
                    let mut row_lines = timeline_row_lines(&self.timeline[index], selected_account);
                    if selected == Some(index) {
                        row_lines = highlight_timeline_lines(row_lines);
                    }
                    lines.extend(row_lines);
                    // Blank separator row, counted in each row's rendered height.
                    lines.push(Line::from(""));
                }
                (
                    timeline_pane_title(total, first, last),
                    lines,
                    Some((first, last)),
                )
            }
            None => ("Messages".to_owned(), Vec::new(), None),
        };
        if bottom_block > 0 {
            lines.extend(preview_lines);
        }

        if let Some((first, last)) = range {
            self.timeline_scroll
                .record_visible_range(first, last, total);
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block(&title, focused))
                // Match `timeline_row_height`, which measures with wrapping: without
                // this, long lines truncate at the pane edge and the reserved-vs-drawn
                // height mismatch breaks bottom-anchoring.
                .wrap(Wrap { trim: false }),
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
                "White Noise TUI",
                Style::default()
                    .fg(FOCUS_ACCENT)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Tab cycles panels. Arrows move. Enter selects or submits. Ctrl-C quits."),
            Line::from("Messages: j/k or arrows move; PageUp/PageDown page."),
            Line::from(
                "G/g jump newest/oldest; past oldest loads history; i/Enter focus composer.",
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
