//! TUI rendering: `TuiApp` draw methods and Ratatui line/style helpers.

use super::*;

use ratatui_image::StatefulImage;

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

/// The dark-gray last-message preview line under a chat row (wn-tui style):
/// `<sender>: <text>`, trailing-truncated. `None` when the chat has no last
/// message yet. A deleted last message renders as a tombstone; a group-system
/// row renders its summary instead of raw JSON. All untrusted text passes
/// through `terminal_safe_text`.
pub(crate) fn chat_preview_line(chat: &ChatRow) -> Option<Line<'static>> {
    let preview = chat_preview_text(chat.projection.last_message.as_ref()?);
    Some(Line::from(vec![
        Span::raw("    "),
        Span::styled(preview, Style::default().fg(Color::DarkGray)),
    ]))
}

/// The preview body for a chat's last message, terminal-safe and trailing-
/// truncated to [`TUI_CHAT_PREVIEW_LIMIT`] chars.
fn chat_preview_text(message: &ChatLastMessage) -> String {
    let body = if message.deleted {
        "message deleted".to_owned()
    } else if message.kind == Some(GROUP_SYSTEM_KIND) {
        // Group-system rows carry JSON in `plaintext`; summarize as the pane does.
        chat_preview_group_system(message)
    } else {
        match chat_preview_sender(message) {
            Some(sender) => format!("{sender}: {}", message.plaintext),
            None => message.plaintext.clone(),
        }
    };
    truncate_preview(&terminal_safe_text(&body), TUI_CHAT_PREVIEW_LIMIT)
}

/// The sender label for a preview: the display name, else a shortened id.
fn chat_preview_sender(message: &ChatLastMessage) -> Option<String> {
    message
        .sender_display_name
        .clone()
        .or_else(|| message.sender.as_deref().map(|sender| shorten(sender, 16)))
}

/// Summarize a group-system last message ("alice added bob") by reusing the
/// timeline's summarizer over a minimal value; falls back to the raw plaintext.
fn chat_preview_group_system(message: &ChatLastMessage) -> String {
    let value = serde_json::json!({
        "from_display_name": message.sender_display_name,
        "from": message.sender,
    });
    group_system_summary(&value, &message.plaintext).unwrap_or_else(|| message.plaintext.clone())
}

/// Trailing-truncate `text` to `max` chars, appending an ellipsis when clipped.
/// Prose-friendly, unlike `shorten`'s middle ellipsis for ids.
fn truncate_preview(text: &str, max: usize) -> String {
    let clipped = text.chars().take(max).collect::<String>();
    if text.chars().count() > max {
        format!("{clipped}...")
    } else {
        clipped
    }
}

/// The opt-in MLS group diagnostics panel body (`/diagnostics`). This is the old
/// status panel minus its leading status-message line, which now lives in the
/// one-line status bar. Group id and error text pass through `terminal_safe_text`.
pub(crate) fn diagnostics_panel_lines(
    diagnostics: Option<&GroupDiagnostics>,
) -> Vec<Line<'static>> {
    let Some(diagnostics) = diagnostics else {
        return vec![Line::from("MLS no group selected")];
    };
    if let Some(error) = &diagnostics.error {
        return vec![Line::from(format!(
            "MLS group={} unavailable: {}",
            shorten(&terminal_safe_text(&diagnostics.group_id), 18),
            terminal_safe_text(error)
        ))];
    }
    let epoch = diagnostics
        .epoch
        .map(|epoch| epoch.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let member_count = diagnostics
        .member_count
        .map(|member_count| member_count.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    let mut lines = vec![Line::from(format!(
        "MLS epoch={epoch} group={} members={member_count}",
        shorten(&terminal_safe_text(&diagnostics.group_id), 18)
    ))];
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

/// Render `text` with a black-on-white cursor cell at char index `cursor` when
/// `focused` — a trailing space when the cursor sits at the end. Unfocused
/// renders the text as a single plain span (no cursor). Indexing is by char, so
/// the cell lands on a whole multi-byte character.
pub(crate) fn cursor_spans(text: &str, cursor: usize, focused: bool) -> Vec<Span<'static>> {
    if !focused {
        return vec![Span::raw(text.to_owned())];
    }
    let chars = text.chars().collect::<Vec<_>>();
    let cursor = cursor.min(chars.len());
    let before = chars[..cursor].iter().collect::<String>();
    let (at, after) = match chars.get(cursor) {
        Some(&ch) => (
            ch.to_string(),
            chars[cursor + 1..].iter().collect::<String>(),
        ),
        None => (" ".to_owned(), String::new()),
    };
    vec![
        Span::raw(before),
        Span::styled(at, Style::default().fg(Color::Black).bg(Color::White)),
        Span::raw(after),
    ]
}

/// Render an editable field's `display` string as lines: split on embedded
/// newlines (multi-line paste), make each segment terminal-safe, and draw the
/// cursor cell on the segment that holds char index `cursor` when `focused`. The
/// first line carries the optional `prefix` span (the composer `> ` prompt or the
/// nsec `nsec ` label). Shared by the composer and the login nsec field.
pub(crate) fn input_field_lines(
    display: &str,
    cursor: usize,
    focused: bool,
    prefix: Option<Span<'static>>,
) -> Vec<Line<'static>> {
    // The cursor is a char index into the raw value, but it is rendered against
    // the display string, which can be shorter (nsec redaction, stripped format
    // chars). Clamp it into the display's range so a cursor cell always renders —
    // at the display end when the raw cursor lies beyond it. Pure rendering: the
    // submitted value and redaction are untouched.
    let cursor = cursor.min(display.chars().count());
    let mut base = 0usize;
    let mut placed = false;
    display
        .split('\n')
        .enumerate()
        .map(|(index, segment)| {
            let safe = terminal_safe_text(segment);
            let seg_len = segment.chars().count();
            let on_this = focused && !placed && cursor <= base + seg_len;
            let mut spans = Vec::new();
            if index == 0
                && let Some(prefix) = prefix.clone()
            {
                spans.push(prefix);
            }
            if on_this {
                placed = true;
                spans.extend(cursor_spans(&safe, cursor - base, true));
            } else {
                spans.push(Span::raw(safe));
            }
            base += seg_len + 1;
            Line::from(spans)
        })
        .collect()
}

/// The composer's rendered lines: the `> ` prompt then the display text with the
/// cursor cell when focused. Empty input shows the cursor cell (focused) or a dim
/// placeholder. The value is redacted (`/login <hidden nsec>`) via
/// `composer_display_text` and made terminal-safe before rendering.
pub(crate) fn composer_lines(input: &Input, focused: bool, streaming: bool) -> Vec<Line<'static>> {
    let prompt = Span::styled("> ", Style::default().fg(FOCUS_ACCENT));
    if input.is_empty() {
        if focused && !streaming {
            return input_field_lines("", 0, true, Some(prompt));
        }
        let placeholder = if streaming {
            "streaming... type text, Enter finishes, Esc cancels"
        } else {
            "type a message or / for commands"
        };
        return vec![Line::from(vec![
            prompt,
            Span::styled(placeholder.to_owned(), Style::default().fg(Color::DarkGray)),
        ])];
    }
    let display = composer_display_text(input.value());
    input_field_lines(&display, input.cursor(), focused, Some(prompt))
}

/// The composer's auto-grow height in rows: the wrapped line count of its
/// rendered content plus the top and bottom borders, clamped to 3..=8. Measured
/// with the same wrap the renderer uses (`Paragraph::line_count`) so the reserved
/// height matches what is drawn; the growth steals from the flexible messages
/// row, never the bars.
pub(crate) fn composer_height(
    input: &Input,
    focused: bool,
    streaming: bool,
    inner_width: u16,
) -> u16 {
    let lines = composer_lines(input, focused, streaming);
    let content = if inner_width == 0 {
        lines.len()
    } else {
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .line_count(inner_width)
    };
    u16::try_from(content)
        .unwrap_or(u16::MAX)
        .saturating_add(2)
        .clamp(3, 8)
}

impl TuiApp {
    pub(crate) fn render(&mut self, frame: &mut Frame) {
        match self.screen {
            Screen::Login(mode) => self.render_login(frame, mode),
            Screen::Main => self.render_main(frame),
            Screen::GroupDetail => self.render_group_detail(frame),
            Screen::UserSearch => self.render_user_search(frame),
            Screen::Profile => self.render_profile(frame),
            Screen::RelayHealth => self.render_relay_health(frame),
        }
        // A popup overlays whatever screen is showing. Cloned so the immutable
        // popup render can run inside this `&mut self` method without holding a
        // borrow of `self.popup`. The image viewer needs `&mut self` for its
        // protocol, so it renders through a dedicated method.
        if let Some(popup) = self.popup.clone() {
            if let Popup::Image { title, hash } = &popup {
                self.render_image_popup(frame, title, hash);
            } else {
                self.render_popup(frame, &popup, frame.area());
            }
        }
    }

    /// Render the full-size image viewer popup: a centered card with a cyan
    /// border, the decoded image aspect-fit inside, and a dismiss hint. Falls
    /// back to a text card if the protocol is somehow gone.
    fn render_image_popup(&mut self, frame: &mut Frame, title: &str, hash: &str) {
        let rect = centered_rect(80, 80, frame.area());
        frame.render_widget(Clear, rect);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(terminal_safe_text(title));
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        // Reserve the bottom row for the dismiss hint; the image fills the rest.
        let image_area = Rect {
            height: inner.height.saturating_sub(1),
            ..inner
        };
        let hint_area = Rect {
            y: inner.y + inner.height.saturating_sub(1),
            height: 1,
            ..inner
        };
        if let Some(protocol) = self.media.protocol_mut(hash) {
            frame.render_stateful_widget(StatefulImage::new(), image_area, protocol);
        }
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "[any key] dismiss",
                Style::default().fg(Color::DarkGray),
            ))),
            hint_area,
        );
    }

    fn render_main(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let show_diagnostics = self.show_diagnostics;
        let diagnostics_lines = if show_diagnostics {
            diagnostics_panel_lines(self.group_diagnostics.as_ref())
        } else {
            Vec::new()
        };

        // Vertical stack: the chat/messages row takes all reclaimed space, then
        // the opt-in diagnostics panel, the composer, and the one-line hints and
        // status bars that replaced the old header and status panel. The composer
        // auto-grows with its wrapped content (borders included, clamped 3..=8);
        // because it is a fixed-length row and the chat/messages body is the only
        // `Min` row, that growth steals from the messages row, never the bars.
        let composer_rows = composer_height(
            &self.input,
            self.focus == Focus::Composer,
            self.streaming.is_some(),
            area.width.saturating_sub(2),
        );
        let mut constraints = vec![Constraint::Min(6)];
        if show_diagnostics {
            let height = (diagnostics_lines.len() as u16 + 2).clamp(3, 11);
            constraints.push(Constraint::Length(height));
        }
        constraints.push(Constraint::Length(composer_rows));
        constraints.push(Constraint::Length(1));
        constraints.push(Constraint::Length(1));
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(36), Constraint::Min(24)])
            .split(root[0]);
        self.render_chats(frame, body[0]);
        self.render_messages(frame, body[1]);

        let mut index = 1;
        if show_diagnostics {
            self.render_diagnostics_panel(frame, root[index], diagnostics_lines);
            index += 1;
        }
        let composer_area = root[index];
        index += 1;
        let hints_area = root[index];
        index += 1;
        let status_area = root[index];

        self.render_composer(frame, composer_area);
        self.render_slash_suggestions(frame, composer_area);
        self.render_hints(frame, hints_area);
        self.render_status_bar(frame, status_area);
    }

    fn render_login(&self, frame: &mut Frame, mode: LoginMode) {
        let area = frame.area();
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(area);
        match mode {
            LoginMode::Menu => self.render_login_menu(frame, root[0]),
            LoginMode::AccountSelect => self.render_account_picker(frame, root[0]),
            LoginMode::NsecEntry => self.render_nsec_entry(frame, root[0]),
        }
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_login_menu(&self, frame: &mut Frame, area: Rect) {
        let lines = vec![
            Line::from(Span::styled(
                "White Noise",
                Style::default()
                    .fg(FOCUS_ACCENT)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("No identities yet. Get started:"),
            Line::from(""),
            Line::from("  c   Create a new identity"),
            Line::from("  l   Log in with an nsec"),
            Line::from("  q   Quit"),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Welcome", false))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_account_picker(&self, frame: &mut Frame, area: Rect) {
        let items = if self.accounts.is_empty() {
            vec![ListItem::new("no accounts")]
        } else {
            self.accounts
                .iter()
                .enumerate()
                .map(|(index, account)| {
                    let selected = index == self.picker_selection;
                    let marker = if selected { ">" } else { " " };
                    let signing = if account.local_signing {
                        "local"
                    } else {
                        "public"
                    };
                    ListItem::new(Line::from(vec![
                        Span::raw(format!("{marker} ")),
                        Span::styled(
                            shorten(&terminal_safe_text(&account_display_label(account)), 22),
                            row_label_style(selected, ACCOUNT_ACCENT),
                        ),
                        Span::raw(format!(" {signing}")),
                    ]))
                    .style(selected_style(selected))
                })
                .collect()
        };
        frame.render_widget(
            List::new(items).block(panel_block("Select Account", true)),
            area,
        );
    }

    fn render_nsec_entry(&self, frame: &mut Frame, area: Rect) {
        // The field reuses the composer input's masked mode (`display()` returns
        // `*` per char); it is always the focused input on this screen, so the
        // cursor cell renders. Key material never reaches the buffer.
        let mut lines = vec![
            Line::from("Paste or type your nsec, then press Enter:"),
            Line::from(""),
        ];
        lines.extend(input_field_lines(
            &self.input.display(),
            self.input.cursor(),
            true,
            Some(Span::styled("nsec ", Style::default().fg(FOCUS_ACCENT))),
        ));
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Log in with nsec", true))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_diagnostics_panel(&self, frame: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Diagnostics", false))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn render_hints(&self, frame: &mut Frame, area: Rect) {
        // The user-search screen's hint depends on its internal focus, which the
        // shared `hints_line` signature cannot carry; derive it here instead. On
        // the main view, an armed interaction command in the composer replaces the
        // static keymap with a persistent "what Enter does, Esc clears" hint,
        // recomputed here each frame so it survives later status events.
        let text = match (self.screen, self.user_search.as_ref()) {
            (Screen::UserSearch, Some(view)) => user_search_hint(view.focus).to_owned(),
            (Screen::Main, _) => {
                armed_interaction_hint(self.input.value(), self.selected_timeline_row())
                    .unwrap_or_else(|| {
                        hints_line(self.screen, self.focus, self.entered_main).to_owned()
                    })
            }
            _ => hints_line(self.screen, self.focus, self.entered_main).to_owned(),
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                text,
                Style::default().fg(Color::DarkGray),
            ))),
            area,
        );
    }

    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let account_label = self
            .selected_account_row()
            .map(account_display_label)
            .unwrap_or_else(|| "no account".to_owned());
        let text = status_bar_line(
            &account_label,
            self.daemon.running,
            self.chats.len(),
            total_unread(&self.chats),
            &self.status,
            area.width as usize,
        );
        frame.render_widget(Paragraph::new(Line::from(text)), area);
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
                    // Unread badge and preview both come from the runtime-backed
                    // projection now — no TUI-local counting.
                    let mut lines =
                        vec![chat_row_line(chat, selected, chat.projection.unread_count)];
                    if let Some(preview) = chat_preview_line(chat) {
                        lines.push(preview);
                    }
                    ListItem::new(lines).style(selected_style(selected))
                })
                .collect()
        };
        let list = List::new(items).block(panel_block("Chats", self.focus == Focus::Chats));
        // Drive the list with a ListState synced to the selection so it always
        // scrolls the highlighted chat into view. Rows are 1-2 lines tall;
        // ratatui's List accounts for multi-line item heights when it computes
        // the offset, which a plain `render_widget` (offset fixed at 0) does not.
        let mut state = ListState::default();
        if !self.chats.is_empty() {
            state.select(Some(self.selected_chat.min(self.chats.len() - 1)));
        }
        frame.render_stateful_widget(list, area, &mut state);
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
        let media = self.media.view();
        let heights =
            timeline_row_heights_media(&self.timeline, selected_account, inner_width, media);
        let total = self.timeline.len();
        let selected = self.timeline_scroll.resolved_selection(total);

        // Ready images to draw over their reserved blocks, collected as owned
        // `(hash, rect)` so the immutable `self` borrows (media view, account) end
        // before the `&mut self.media` render pass below.
        let mut image_draws: Vec<(String, Rect)> = Vec::new();

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
                // Rows below the pane's top edge, tracking each row's block start so
                // reserved image blocks can be turned into absolute rects.
                let mut cursor_y: u16 = 0;
                // `index` addresses three parallel collections (the timeline rows,
                // their heights, and the selection), so a range loop reads clearer
                // than zipping them.
                #[allow(clippy::needless_range_loop)]
                for index in first..=last {
                    let mut row_lines =
                        timeline_row_lines_media(&self.timeline[index], selected_account, media);
                    if selected == Some(index) {
                        row_lines = highlight_timeline_lines(row_lines);
                    }
                    lines.extend(row_lines);
                    // Blank separator row, counted in each row's rendered height.
                    lines.push(Line::from(""));

                    for (hash, offset, rows) in timeline_row_image_blocks(
                        &self.timeline[index],
                        selected_account,
                        inner_width,
                        media,
                    ) {
                        let rect = Rect {
                            x: area.x + 1,
                            y: area.y + 1 + cursor_y + offset,
                            width: inner_width,
                            height: rows,
                        };
                        let inner = Rect {
                            x: area.x + 1,
                            y: area.y + 1,
                            width: inner_width,
                            height: inner_height,
                        };
                        let clipped = rect.intersection(inner);
                        if clipped.height > 0 && clipped.width > 0 {
                            image_draws.push((hash, clipped));
                        }
                    }
                    cursor_y = cursor_y.saturating_add(heights[index]);
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

        // Draw each ready image over its reserved block. The blank lines above
        // gave it the space; `StatefulImage` aspect-fits within the rect.
        for (hash, rect) in image_draws {
            if let Some(protocol) = self.media.protocol_mut(&hash) {
                frame.render_stateful_widget(StatefulImage::new(), rect, protocol);
            }
        }
    }

    pub(crate) fn render_composer(&self, frame: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Composer;
        let lines = composer_lines(&self.input, focused, self.streaming.is_some());
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Composer", focused))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    pub(crate) fn render_slash_suggestions(&self, frame: &mut Frame, composer_area: Rect) {
        if self.focus != Focus::Composer || self.streaming.is_some() || self.popup.is_some() {
            return;
        }
        let lines = slash_suggestion_lines(self.input.value(), SLASH_SUGGESTION_LIMIT);
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

    /// Render the one open popup: a centered rect, `Clear` behind, cyan border,
    /// the popup's title, its body (embedded input, confirm/card lines, or picker
    /// rows), a blank spacer, and the bottom `[key] action` hint row.
    pub(crate) fn render_popup(&self, frame: &mut Frame, popup: &Popup, area: Rect) {
        let rect = centered_rect(70, 70, area);
        frame.render_widget(Clear, rect);
        let mut lines: Vec<Line<'static>> = Vec::new();
        match popup {
            Popup::Text { body, input, .. } => {
                lines.extend(body.iter().map(|line| Line::from(terminal_safe_text(line))));
                lines.push(input_cursor_line("> ", input));
            }
            Popup::Confirm { body, .. } | Popup::Card { body, .. } => {
                lines.extend(body.iter().map(|line| Line::from(terminal_safe_text(line))))
            }
            Popup::Picker {
                items, selected, ..
            } => {
                for (index, item) in items.iter().enumerate() {
                    let is_selected = index == *selected;
                    let marker = if is_selected { ">" } else { " " };
                    let line = Line::from(vec![
                        Span::raw(format!("{marker} ")),
                        Span::styled(
                            shorten(&terminal_safe_text(&item.label), 40),
                            row_label_style(is_selected, Color::Green),
                        ),
                    ]);
                    lines.push(line);
                }
            }
            // Rendered by `render_image_popup`, not here; `render` routes it away.
            Popup::Image { .. } => {}
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            popup_hint(popup),
            Style::default().fg(Color::DarkGray),
        )));
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan))
                        .title(terminal_safe_text(popup.title())),
                )
                .wrap(Wrap { trim: false }),
            rect,
        );
    }

    fn render_group_detail(&self, frame: &mut Frame) {
        let area = frame.area();
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(6),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(area);
        frame.render_widget(
            Paragraph::new(group_detail_lines(self.group_detail.as_ref()))
                .block(panel_block("Group Detail", true))
                .wrap(Wrap { trim: false }),
            root[0],
        );
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_user_search(&self, frame: &mut Frame) {
        let root = screen_body_layout(frame.area());
        let lines = self
            .user_search
            .as_ref()
            .map(user_search_lines)
            .unwrap_or_else(|| vec![Line::from("loading user search...")]);
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("User Search", true))
                .wrap(Wrap { trim: false }),
            root[0],
        );
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_profile(&self, frame: &mut Frame) {
        let root = screen_body_layout(frame.area());
        let lines = self
            .profile_view
            .as_ref()
            .map(profile_lines)
            .unwrap_or_else(|| vec![Line::from("loading profile...")]);
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Profile", true))
                .wrap(Wrap { trim: false }),
            root[0],
        );
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_relay_health(&self, frame: &mut Frame) {
        let root = screen_body_layout(frame.area());
        let (lines, scroll) = match self.relay_health.as_ref() {
            Some(view) => (relay_health_lines(&view.data), view.scroll),
            None => (vec![Line::from("loading relay health...")], 0),
        };
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel_block("Relay Health", true))
                .wrap(Wrap { trim: false })
                .scroll((scroll, 0)),
            root[0],
        );
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }
}

/// The shared full-view layout: a flexible body row over a one-line hints bar
/// and a one-line status bar. Used by every Phase 5 screen.
fn screen_body_layout(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area)
}

/// The composer-style input line for a text popup: the prefix, the value split
/// around a black-on-white cursor cell (a trailing space when the cursor is at
/// the end). The value passes through `terminal_safe_text`.
pub(crate) fn input_cursor_line(prefix: &str, input: &Input) -> Line<'static> {
    let value = input.display();
    let chars: Vec<char> = value.chars().collect();
    let cursor = input.cursor().min(chars.len());
    let before: String = chars[..cursor].iter().collect();
    let cursor_style = Style::default().fg(Color::Black).bg(Color::White);
    let mut spans = vec![
        Span::styled(prefix.to_owned(), Style::default().fg(FOCUS_ACCENT)),
        Span::raw(terminal_safe_text(&before)),
    ];
    if cursor < chars.len() {
        let at: String = chars[cursor].to_string();
        let after: String = chars[cursor + 1..].iter().collect();
        spans.push(Span::styled(terminal_safe_text(&at), cursor_style));
        spans.push(Span::raw(terminal_safe_text(&after)));
    } else {
        spans.push(Span::styled(" ".to_owned(), cursor_style));
    }
    Line::from(spans)
}

/// The group-detail screen body: name and description header, the member list
/// with admin/you badges and a selection highlight, then the relay hints. Every
/// name, npub, and relay passes through `terminal_safe_text`.
pub(crate) fn group_detail_lines(view: Option<&GroupDetailView>) -> Vec<Line<'static>> {
    let Some(view) = view else {
        return vec![Line::from("loading group detail...")];
    };
    let mut lines = vec![Line::from(vec![
        Span::styled("Group ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            shorten(&terminal_safe_text(&view.name), 48),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ])];
    if !view.description.is_empty() {
        lines.push(Line::from(Span::styled(
            terminal_safe_text(&view.description),
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!("Members ({})", view.members.len())));
    for (index, member) in view.members.iter().enumerate() {
        let is_selected = index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        let mut spans = vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                shorten(&terminal_safe_text(&member.npub), 28),
                row_label_style(is_selected, Color::Green),
            ),
        ];
        if member.is_admin {
            spans.push(Span::styled(" [admin]", Style::default().fg(Color::Yellow)));
        }
        if member.is_self {
            spans.push(Span::styled(" (you)", Style::default().fg(Color::DarkGray)));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!("Relays ({})", view.relays.len())));
    for relay in &view.relays {
        lines.push(Line::from(format!("  {}", terminal_safe_text(relay))));
    }
    lines
}

/// The user-search screen body: the query field (with the cursor cell in query
/// focus) then the result rows, each showing the display label, a shortened
/// npub, and the `matched_field · match_quality · radius` attribution. Every
/// name and npub passes through `terminal_safe_text`.
pub(crate) fn user_search_lines(view: &UserSearchView) -> Vec<Line<'static>> {
    let query_focused = view.focus == UserSearchFocus::Query;
    let mut lines = input_field_lines(
        &view.query.display(),
        view.query.cursor(),
        query_focused,
        Some(Span::styled("search ", Style::default().fg(FOCUS_ACCENT))),
    );
    lines.push(Line::from(""));
    if view.results.is_empty() {
        lines.push(Line::from(Span::styled(
            "no results — type a query and press Enter",
            Style::default().fg(Color::DarkGray),
        )));
        return lines;
    }
    lines.push(Line::from(format!("Results ({})", view.results.len())));
    let results_focused = view.focus == UserSearchFocus::Results;
    for (index, result) in view.results.iter().enumerate() {
        let is_selected = results_focused && index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        lines.push(Line::from(vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                shorten(&terminal_safe_text(&result.display_label()), 28),
                row_label_style(is_selected, Color::Green),
            ),
            Span::styled(
                format!("  {}", terminal_safe_text(&shorten(&result.npub, 18))),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!(
                "    {} · {} · radius {}",
                terminal_safe_text(&result.matched_field),
                terminal_safe_text(&result.match_quality),
                result.radius
            ),
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines
}

/// The own-profile screen body: the npub header, the six editable fields with a
/// selection highlight (unset fields dimmed), then the follow list. Every value
/// passes through `terminal_safe_text`; picture URLs render as literal text.
pub(crate) fn profile_lines(view: &ProfileView) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("Profile ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                shorten(&terminal_safe_text(&view.npub), 32),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from("Fields"),
    ];
    for (index, field) in ProfileField::ALL.iter().enumerate() {
        let is_selected = index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        let value_span = match view.field_value(*field) {
            Some(value) => Span::raw(terminal_safe_text(value)),
            None => Span::styled("(unset)".to_owned(), Style::default().fg(Color::DarkGray)),
        };
        lines.push(Line::from(vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                format!("{}: ", field.label()),
                row_label_style(is_selected, Color::Green),
            ),
            value_span,
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!("Follows ({})", view.follows.len())));
    for (index, follow) in view.follows.iter().enumerate() {
        let is_selected = ProfileField::ALL.len() + index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        lines.push(Line::from(vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                shorten(&terminal_safe_text(follow), 28),
                row_label_style(is_selected, Color::Green),
            ),
        ]));
    }
    lines
}

/// The relay-health screen body: a daemon-state and health-summary header, then
/// the counters, delivery-spread, sync-timing, and per-relay sections. Every
/// field is a counter, an opaque relay index, or a fixed percentile label — no
/// relay URLs exist in the source and none are rendered (decision 3).
pub(crate) fn relay_health_lines(data: &RelayHealthData) -> Vec<Line<'static>> {
    let daemon = if data.daemon_running {
        "on"
    } else {
        "off (in-process telemetry)"
    };
    vec![
        Line::from(format!(
            "daemon {daemon} · device-local, redacted (opaque relay indices, no URLs)"
        )),
        Line::from(format!(
            "health: sdk_backed={} relays={} connected={} connecting={} disconnected={} attempts={} successes={}",
            data.sdk_backed,
            data.total_relays,
            data.connected,
            data.connecting,
            data.disconnected,
            data.connection_attempts,
            data.connection_successes,
        )),
        Line::from(""),
        Line::from("counters"),
        Line::from(format!(
            "  accounts={} group_subs={} created={} removed={}",
            data.active_accounts,
            data.active_group_subscriptions,
            data.subscriptions_created,
            data.subscriptions_removed,
        )),
        Line::from(format!(
            "  inbound seen={} delivered={} dropped={}",
            data.inbound_seen, data.inbound_delivered, data.inbound_dropped,
        )),
        Line::from(format!(
            "  publish attempts={} successes={} failures={}",
            data.publish_attempts, data.publish_successes, data.publish_failures,
        )),
        Line::from(""),
        Line::from("delivery spread"),
        Line::from(format!(
            "  observed={} corroborated={} single_source={} samples={} p50={} p99={}",
            data.observed,
            data.corroborated,
            data.single_source,
            data.spread_samples,
            data.spread_p50,
            data.spread_p99,
        )),
        Line::from(""),
        Line::from("sync timing"),
        Line::from(format!(
            "  tracked={} synced={} first_event_p50={} eose_p50={}",
            data.tracked_subscriptions,
            data.synced_subscriptions,
            data.first_event_p50,
            data.eose_p50,
        )),
        Line::from(""),
    ]
    .into_iter()
    .chain(relay_health_per_relay_lines(&data.per_relay))
    .collect()
}

fn relay_health_per_relay_lines(rows: &[RelayHealthRow]) -> Vec<Line<'static>> {
    if rows.is_empty() {
        return vec![Line::from("per-relay: none observed yet")];
    }
    let mut lines = vec![Line::from("per-relay (opaque device-local index)")];
    lines.extend(rows.iter().map(|row| {
        Line::from(format!(
            "  relay#{} first_deliverer={} delivered_first={} delivered_later={} first_event_p50={} eose_p50={}",
            row.relay_index,
            row.first_deliverer,
            row.delivered_first,
            row.delivered_later,
            row.first_event_p50,
            row.eose_p50,
        ))
    }));
    lines
}
