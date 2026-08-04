//! TUI rendering: `TuiApp` draw methods and Ratatui line/style helpers.

use super::*;
use marmot_app::OFF_GRAPH_SEARCH_RADIUS;

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

/// The messages-pane title: the loaded chat's name (its `base`, or plain
/// "Messages" when nothing is loaded) when pinned with everything on screen,
/// otherwise annotated with the row counts above and below the viewport so the
/// reader knows history or newer content is off-screen. Naming the loaded chat
/// makes the pane target visible — the flick preview retargets the pane to a
/// chat the highlight may have since moved past, so the title is the WYSIWYG cue
/// for which conversation is shown.
pub(crate) fn timeline_pane_title(base: &str, total: usize, first: usize, last: usize) -> String {
    let above = first;
    let below = total.saturating_sub(last + 1);
    match (above, below) {
        (0, 0) => base.to_owned(),
        (above, 0) => format!("{base} [{above} older]"),
        (0, below) => format!("{base} [{below} newer]"),
        (above, below) => format!("{base} [{above} older | {below} newer]"),
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
    let mut label_style = row_label_style(selected, Color::Cyan);
    if unread_count > 0 {
        ambient_style = ambient_style.add_modifier(Modifier::BOLD);
        label_style = label_style.add_modifier(Modifier::BOLD);
    }
    let (name, badge) = chat_label(&chat.name, unread_count, 24);
    let mut spans = vec![
        Span::styled(format!("{marker} "), ambient_style),
        Span::styled(name, label_style),
    ];
    if let Some(badge) = badge {
        // The yellow bold unread badge. On the selected (black-on-white) row it
        // takes the same fg bump as the name so it stays readable.
        spans.push(Span::styled(
            badge,
            row_label_style(selected, Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(archived.to_owned(), ambient_style));
    Line::from(spans)
}

/// A chat row's name and unread badge, split so the badge can carry its own
/// style: `(name, Some(" (N)"))` when unread, `(name, None)` when read. The
/// name is truncated to leave the whole badge within `max_len`, so the badge
/// survives truncation intact.
pub(crate) fn chat_label(
    name: &str,
    unread_count: usize,
    max_len: usize,
) -> (String, Option<String>) {
    let name = terminal_safe_text(name);
    if unread_count == 0 {
        return (shorten(&name, max_len), None);
    }
    let badge = format!(" ({unread_count})");
    let budget = max_len.saturating_sub(badge.chars().count());
    (shorten(&name, budget), Some(badge))
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

/// A pane body together with the index of the body line a viewport has to keep
/// visible: the *last* line of the selected row, since a row can span several
/// lines. `None` when the body carries no selection at all.
///
/// Bodies are built at full length regardless of the pane's height, so without
/// this anchor a pane silently hides its own selection once the body outgrows
/// the area — the marker and the highlight both live inside the row.
pub(crate) struct PaneBody {
    pub(crate) lines: Vec<Line<'static>>,
    pub(crate) anchor: Option<usize>,
}

impl PaneBody {
    /// Record the line about to be pushed as the selection anchor. Called at the
    /// point a row is emitted, so the anchor cannot drift out of step with the
    /// layout the way a recomputed index would.
    fn anchor_next(&mut self) {
        self.anchor = Some(self.lines.len());
    }

    fn push(&mut self, line: Line<'static>) {
        self.lines.push(line);
    }

    fn extend(&mut self, lines: impl IntoIterator<Item = Line<'static>>) {
        self.lines.extend(lines);
    }
}

/// The vertical scroll offset, in post-wrap rows, that a `height`-row viewport
/// `width` cells wide needs for `anchor` to be its last visible row. Zero
/// whenever the content through the anchor already fits, so a pane that fits
/// never scrolls, and moving the selection back up unwinds the offset.
///
/// The measurement runs through the same word wrapper the renderer uses and
/// `Paragraph::scroll` counts post-wrap rows, so the offset cannot disagree with
/// what actually gets drawn — which is the failure mode a hand-rolled row count
/// would have.
fn selection_scroll_offset(
    lines: &[Line<'static>],
    anchor: Option<usize>,
    width: u16,
    height: u16,
) -> u16 {
    let Some(anchor) = anchor else {
        return 0;
    };
    let Some(through_anchor) = lines.get(..=anchor) else {
        return 0;
    };
    let rows = Paragraph::new(through_anchor.to_vec())
        .wrap(Wrap { trim: false })
        .line_count(width);
    u16::try_from(rows)
        .unwrap_or(u16::MAX)
        .saturating_sub(height)
}

/// A wrapped body paragraph scrolled so its selection anchor stays visible in an
/// `inner`-sized viewport. Selection-bearing bodies go through here rather than
/// building a `Paragraph` directly, because an unscrolled render pins the offset
/// at 0 and draws the selection off the bottom of the viewport.
fn selection_paragraph(body: PaneBody, inner: Rect) -> Paragraph<'static> {
    let offset = selection_scroll_offset(&body.lines, body.anchor, inner.width, inner.height);
    Paragraph::new(body.lines)
        .wrap(Wrap { trim: false })
        .scroll((offset, 0))
}

/// Render a selection-bearing pane body inside `block`, scrolled to its
/// selection. The viewport is the block's inner rect, so the borders are
/// accounted for wherever this is called.
fn render_selection_pane(frame: &mut Frame, area: Rect, block: Block<'_>, body: PaneBody) {
    let inner = block.inner(area);
    frame.render_widget(selection_paragraph(body, inner).block(block), area);
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

/// The popup body content (everything above the pinned hint row): semantic-
/// colored body lines, the embedded input cursor line for a text popup, or the
/// picker rows. Untrusted body text and picker labels pass through
/// `terminal_safe_text`. Confirm bodies render yellow ("are you sure?"); the
/// typed-token logout body renders red (irreversible key destruction); other
/// bodies keep the default foreground. The `Image` variant renders through
/// `render_image_popup`, so it has no body here.
pub(crate) fn popup_body_lines(popup: &Popup) -> PaneBody {
    let mut pane = PaneBody {
        lines: Vec::new(),
        anchor: None,
    };
    match popup {
        Popup::Text {
            purpose,
            body,
            input,
            ..
        } => {
            let style = if matches!(purpose, TextPurpose::ConfirmLogout { .. }) {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            pane.extend(
                body.iter()
                    .map(|line| Line::from(Span::styled(terminal_safe_text(line), style))),
            );
            pane.push(input_cursor_line("> ", input));
        }
        Popup::Confirm { body, .. } => pane.extend(body.iter().map(|line| {
            Line::from(Span::styled(
                terminal_safe_text(line),
                Style::default().fg(Color::Yellow),
            ))
        })),
        Popup::Card { body, .. } => {
            pane.extend(body.iter().map(|line| Line::from(terminal_safe_text(line))))
        }
        Popup::Picker {
            items, selected, ..
        } => {
            for (index, item) in items.iter().enumerate() {
                let is_selected = index == *selected;
                let marker = if is_selected { ">" } else { " " };
                if is_selected {
                    pane.anchor_next();
                }
                pane.push(Line::from(vec![
                    Span::raw(format!("{marker} ")),
                    Span::styled(
                        shorten(&terminal_safe_text(&item.label), 40),
                        row_label_style(is_selected, Color::Cyan),
                    ),
                ]));
            }
        }
        // Rendered by `render_image_popup`, not here.
        Popup::Image { .. } => {}
    }
    pane
}

/// The content-sized, exactly-centered rect for a popup: a per-variant width
/// (text 50, confirm 55, card/info 70, picker 60) and a height snug to the
/// measured (wrapped) body plus a blank gap, the hint row, and the two borders.
/// Both dimensions clamp to the available area. The `Image` viewer is sized
/// separately (`render_image_popup`), so it never reaches here.
pub(crate) fn popup_rect(popup: &Popup, area: Rect) -> Rect {
    let width = popup_width(popup).min(area.width);
    let inner_width = width.saturating_sub(2).max(1);
    let body_rows = Paragraph::new(popup_body_lines(popup).lines)
        .wrap(Wrap { trim: false })
        .line_count(inner_width);
    let body_rows = u16::try_from(body_rows).unwrap_or(u16::MAX);
    // body + blank gap + hint row + top and bottom borders.
    let height = body_rows.saturating_add(4);
    centered_cell_rect(width, height, area)
}

/// The nominal (pre-clamp) popup width in cells, by variant.
fn popup_width(popup: &Popup) -> u16 {
    match popup {
        Popup::Text { .. } => 50,
        Popup::Confirm { .. } => 55,
        Popup::Card { .. } => 70,
        Popup::Picker { .. } => 60,
        // Unused: the image viewer sizes itself; keep the match total.
        Popup::Image { .. } => 70,
    }
}

/// A rect of `width`×`height` cells centered in `area`, each dimension clamped
/// to fit. Cell-based (unlike the percentage `centered_rect` the image viewer
/// uses) so popups size to their content.
pub(crate) fn centered_cell_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w, h)
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
    /// border, the decoded image aspect-fit inside, and a dismiss hint. The popup
    /// draws its own dedicated protocol (`viewer_protocol_mut`) — native on a
    /// pixel-capable terminal, a fresh cell-exact halfblock instance on a
    /// halfblock-only one — so it never re-resizes the shared inline protocol the
    /// timeline draws. Only when that image's retained pixels were evicted (an
    /// image older than the retention window) is there no dedicated instance; the
    /// popup then draws the shared inline protocol as a last resort, since the
    /// evicted pixels survive only there. If neither exists the card stays empty.
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
        if let Some(protocol) = self.media.viewer_protocol_mut(hash) {
            // The popup's own dedicated instance (native or halfblock): drawing
            // it at popup size never disturbs the shared inline protocol.
            frame.render_stateful_widget(media_image_widget(), image_area, protocol);
        } else if let Some(protocol) = self.media.protocol_mut(hash) {
            // Evicted image only: its pixels survive solely inside the inline
            // protocol, so the popup draws that as a last resort.
            frame.render_stateful_widget(media_image_widget(), image_area, protocol);
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
            .constraints([
                Constraint::Length(sidebar_width(area.width)),
                Constraint::Min(24),
            ])
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
        // Center the brand/menu block within the body rather than letting it fill
        // the whole pane — the login screen reads as a focused card, not a
        // full-height panel.
        let body = root[0];
        let content = match mode {
            LoginMode::Menu => centered_cell_rect(44, 9, body),
            LoginMode::AccountSelect => {
                let rows = u16::try_from(self.accounts.len().max(1))
                    .unwrap_or(u16::MAX)
                    .saturating_add(2);
                // Floor the card at 4 rows (two borders + a row) but do not cap it
                // here: `centered_cell_rect` clamps the height down to `body`, so a
                // terminal shorter than the floor stays panic-free (a bare
                // `clamp(4, body.height)` would assert `min > max` when the body is
                // squeezed below 4 rows).
                centered_cell_rect(50, rows.max(4), body)
            }
            LoginMode::NsecEntry => centered_cell_rect(54, 7, body),
        };
        match mode {
            LoginMode::Menu => self.render_login_menu(frame, content),
            LoginMode::AccountSelect => self.render_account_picker(frame, content),
            LoginMode::NsecEntry => self.render_nsec_entry(frame, content),
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
        // Drive the list with a ListState synced to the selection so the
        // highlighted account always scrolls into view, exactly as the chats
        // sidebar does. A plain `render_widget` pins the offset at 0, which
        // hides the marker once the account list outgrows the card.
        let mut state = ListState::default();
        if !self.accounts.is_empty() {
            state.select(Some(self.picker_selection.min(self.accounts.len() - 1)));
        }
        frame.render_stateful_widget(
            List::new(items).block(panel_block("Select Account", true)),
            area,
            &mut state,
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
        let spans = match (self.screen, self.user_search.as_ref()) {
            (Screen::UserSearch, Some(view)) => {
                keymap_hint_spans(&user_search_hint(view.focus, &view.purpose))
            }
            (Screen::Main, _) => {
                match armed_interaction_hint(self.input.value(), self.selected_timeline_row()) {
                    Some(armed) => armed_hint_spans(&armed),
                    None => {
                        keymap_hint_spans(hints_line(self.screen, self.focus, self.entered_main))
                    }
                }
            }
            _ => keymap_hint_spans(hints_line(self.screen, self.focus, self.entered_main)),
        };
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
        let account = self.selected_account_row();
        let line = status_bar_line(
            account.and_then(|account| account.display_name.as_deref()),
            account.map(|account| account.npub.as_str()),
            self.daemon.running,
            self.chats.len(),
            total_unread(&self.chats),
            &self.status,
            area.width as usize,
        );
        // The DarkGray bar fill: the Paragraph base style covers the whole area,
        // and the line's spans set only a foreground so the fill shows through.
        frame.render_widget(
            Paragraph::new(line).style(Style::default().bg(Color::DarkGray).fg(Color::White)),
            area,
        );
    }

    pub(crate) fn render_chats(&self, frame: &mut Frame, area: Rect) {
        if self.chats.is_empty() {
            // Chats load synchronously, so an empty list is genuinely empty (there
            // is no in-flight frame to show a loading spinner for); a dark-gray,
            // centered notice.
            let block = panel_block("Chats", self.focus == Focus::Chats);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            render_centered_notice(frame, inner, "no chats yet", Color::DarkGray);
            return;
        }
        let items: Vec<ListItem> = self
            .chats
            .iter()
            .enumerate()
            .map(|(index, chat)| {
                let selected = index == self.selected_chat;
                // Unread badge and preview both come from the runtime-backed
                // projection now — no TUI-local counting.
                let mut lines = vec![chat_row_line(chat, selected, chat.projection.unread_count)];
                if let Some(preview) = chat_preview_line(chat) {
                    lines.push(preview);
                }
                ListItem::new(lines).style(selected_style(selected))
            })
            .collect();
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

    /// The messages-pane title base: the loaded chat's terminal-safe, shortened
    /// name, or the plain "Messages" when no chat is loaded (or its row is not in
    /// the list). Keyed on the loaded pane target (`messages_group_id`), not the
    /// highlighted selection, so it names the conversation actually on screen.
    fn loaded_chat_title(&self) -> String {
        self.messages_group_id
            .as_deref()
            .and_then(|group_id| self.chats.iter().find(|chat| chat.group_id == group_id))
            .map(|chat| shorten(&terminal_safe_text(&chat.name), MESSAGES_TITLE_NAME_LIMIT))
            .unwrap_or_else(|| "Messages".to_owned())
    }

    pub(crate) fn render_messages(&mut self, frame: &mut Frame, area: Rect) {
        let focused = self.focus == Focus::Messages;
        let base_title = self.loaded_chat_title();
        if self.timeline.is_empty() {
            // Three distinct, color-coded empty states: an in-flight load
            // (yellow), the pick-a-chat prompt when nothing is loaded, and a
            // genuinely empty loaded chat (both dark gray). Keyed off the async
            // load flag and whether a chat is loaded into the pane.
            let (text, color) = empty_messages_notice(
                self.loading_chat.is_some(),
                self.messages_group_id.is_some(),
            );
            let block = panel_block(&base_title, focused);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            render_centered_notice(frame, inner, text, color);
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
        // The row highlight renders when the messages pane holds focus, or while an
        // interaction is armed in the composer: r/d/R move focus to the composer,
        // but the highlighted row is the exact target of the pending action, so it
        // must stay lit while aimed at. A chat previewed with focus on the chat list
        // and nothing armed (flick-through) shows no stray highlight — arming never
        // leaves focus on Chats, so this cannot fight flick-through. Scroll/
        // visibility are unaffected (they key off the offset, not this selection).
        let selected = if focused || is_armed_interaction(self.input.value()) {
            self.timeline_scroll.resolved_selection(total)
        } else {
            None
        };

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
                    timeline_pane_title(&base_title, total, first, last),
                    lines,
                    Some((first, last)),
                )
            }
            None => (base_title.clone(), Vec::new(), None),
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
                frame.render_stateful_widget(media_image_widget(), rect, protocol);
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

    /// Render the one open popup: a content-sized centered rect, `Clear` behind,
    /// a cyan border with a cyan-bold ` Title ` heading, the popup body (embedded
    /// input, semantic-colored confirm/card lines, or picker rows) at the top,
    /// and the centered `[key] action` hint pinned to the bottom row.
    pub(crate) fn render_popup(&self, frame: &mut Frame, popup: &Popup, area: Rect) {
        let rect = popup_rect(popup, area);
        frame.render_widget(Clear, rect);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(format!(" {} ", terminal_safe_text(popup.title())))
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        // Body fills the top; the hint is pinned to the last inner row, centered.
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(inner);
        // The rect is content-sized, so this only scrolls when the body could not
        // fit the screen — a picker with more rows than the terminal is tall.
        frame.render_widget(
            selection_paragraph(popup_body_lines(popup), rows[0]),
            rows[0],
        );
        frame.render_widget(
            Paragraph::new(Line::from(popup_hint_spans(popup_hint(popup)))).centered(),
            rows[1],
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
        match self.group_detail.as_ref() {
            Some(view) => render_selection_pane(
                frame,
                root[0],
                panel_block("Group Detail", true),
                group_detail_lines(Some(view)),
            ),
            None => {
                render_loading_screen(frame, root[0], "Group Detail", "loading group detail...")
            }
        }
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_user_search(&self, frame: &mut Frame) {
        let root = screen_body_layout(frame.area());
        match self.user_search.as_ref() {
            Some(view) => render_selection_pane(
                frame,
                root[0],
                panel_block("User Search", true),
                user_search_lines(view, self.searching_users.is_some()),
            ),
            None => render_loading_screen(frame, root[0], "User Search", "loading user search..."),
        }
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_profile(&self, frame: &mut Frame) {
        let root = screen_body_layout(frame.area());
        match self.profile_view.as_ref() {
            Some(view) => render_selection_pane(
                frame,
                root[0],
                panel_block("Profile", true),
                profile_lines(view),
            ),
            None => render_loading_screen(frame, root[0], "Profile", "loading profile..."),
        }
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }

    fn render_relay_health(&self, frame: &mut Frame) {
        let root = screen_body_layout(frame.area());
        match self.relay_health.as_ref() {
            Some(view) => frame.render_widget(
                Paragraph::new(relay_health_lines(&view.data))
                    .block(panel_block("Relay Health", true))
                    .wrap(Wrap { trim: false })
                    .scroll((view.scroll, 0)),
                root[0],
            ),
            None => {
                render_loading_screen(frame, root[0], "Relay Health", "loading relay health...")
            }
        }
        self.render_hints(frame, root[1]);
        self.render_status_bar(frame, root[2]);
    }
}

/// Render a single-line notice horizontally centered on the vertical middle row
/// of `inner`, in `color`. The shared treatment for every pane's loading/empty
/// state (yellow while a load is in flight, dark gray when genuinely empty). The
/// text is a trusted static notice.
fn render_centered_notice(frame: &mut Frame, inner: Rect, text: &str, color: Color) {
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let row = Rect {
        x: inner.x,
        y: inner.y + inner.height / 2,
        width: inner.width,
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text.to_owned(),
            Style::default().fg(color),
        )))
        .centered(),
        row,
    );
}

/// Render a full-view screen's panel with a centered yellow in-flight notice —
/// the shared treatment for a Phase 5 screen whose one-shot load has not landed
/// yet (its view is still `None`).
fn render_loading_screen(frame: &mut Frame, area: Rect, title: &str, text: &str) {
    let block = panel_block(title, true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    render_centered_notice(frame, inner, text, Color::Yellow);
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
pub(crate) fn group_detail_lines(view: Option<&GroupDetailView>) -> PaneBody {
    let Some(view) = view else {
        return PaneBody {
            lines: vec![Line::from("loading group detail...")],
            anchor: None,
        };
    };
    let mut body = PaneBody {
        lines: vec![Line::from(vec![
            Span::styled("Group ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                shorten(&terminal_safe_text(&view.name), 48),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ])],
        anchor: None,
    };
    if !view.description.is_empty() {
        body.push(Line::from(Span::styled(
            terminal_safe_text(&view.description),
            Style::default().fg(Color::DarkGray),
        )));
    }
    body.push(Line::from(""));
    body.push(Line::from(format!("Members ({})", view.members.len())));
    for (index, member) in view.members.iter().enumerate() {
        let is_selected = index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        let mut spans = vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                shorten(&terminal_safe_text(&member.npub), 28),
                row_label_style(is_selected, Color::Cyan),
            ),
        ];
        if member.is_admin {
            spans.push(Span::styled(" [admin]", Style::default().fg(Color::Yellow)));
        }
        if member.is_self {
            spans.push(Span::styled(" (you)", Style::default().fg(Color::DarkGray)));
        }
        if is_selected {
            body.anchor_next();
        }
        body.push(Line::from(spans));
    }
    body.push(Line::from(""));
    body.push(Line::from(format!("Relays ({})", view.relays.len())));
    for relay in &view.relays {
        body.push(Line::from(format!("  {}", terminal_safe_text(relay))));
    }
    body
}

/// The user-search screen body: the query field (with the cursor cell in query
/// focus) then the result rows, each showing the display label, a shortened
/// npub, and the `matched_field · match_quality · provenance` attribution. Every
/// name and npub passes through `terminal_safe_text`.
pub(crate) fn user_search_lines(view: &UserSearchView, searching: bool) -> PaneBody {
    let query_focused = view.focus == UserSearchFocus::Query;
    let mut body = PaneBody {
        lines: input_field_lines(
            &view.query.display(),
            view.query.cursor(),
            query_focused,
            Some(Span::styled("search ", Style::default().fg(FOCUS_ACCENT))),
        ),
        anchor: None,
    };
    body.push(Line::from(""));
    if view.results.is_empty() {
        // Distinguish an in-flight search (yellow) from a settled empty result
        // (dark gray), keyed off the async search flag.
        let (text, color) = if searching {
            ("searching...", Color::Yellow)
        } else {
            ("no results — type a query and press Enter", Color::DarkGray)
        };
        body.push(Line::from(Span::styled(text, Style::default().fg(color))));
        return body;
    }
    body.push(Line::from(format!("Results ({})", view.results.len())));
    let results_focused = view.focus == UserSearchFocus::Results;
    for (index, result) in view.results.iter().enumerate() {
        let is_selected = results_focused && index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        let mut spans = vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                shorten(&terminal_safe_text(&result.display_label()), 28),
                row_label_style(is_selected, Color::Cyan),
            ),
            Span::styled(
                format!("  {}", terminal_safe_text(&shorten(&result.npub, 18))),
                Style::default().fg(Color::DarkGray),
            ),
        ];
        if result.following {
            // Passive state, styled like the row's other metadata (dark gray),
            // not like attention (yellow) or chrome (cyan).
            spans.push(Span::styled(
                "  [following]",
                Style::default().fg(Color::DarkGray),
            ));
        }
        body.push(Line::from(spans));
        let provenance = if result.radius == OFF_GRAPH_SEARCH_RADIUS {
            "discovery".to_owned()
        } else {
            format!("radius {}", result.radius)
        };
        // Anchor on the attribution line rather than the label above it, so
        // scrolling to the last result brings the whole two-line row into view.
        if is_selected {
            body.anchor_next();
        }
        body.push(Line::from(Span::styled(
            format!(
                "    {} · {} · {provenance}",
                terminal_safe_text(&result.matched_field),
                terminal_safe_text(&result.match_quality),
            ),
            Style::default().fg(Color::DarkGray),
        )));
    }
    body
}

/// The own-profile screen body: the npub header, the six editable fields with a
/// selection highlight (unset fields dimmed), then the follow list. Every value
/// passes through `terminal_safe_text`; picture URLs render as literal text.
/// Fields and follows share one selection index, so both can be the anchor.
pub(crate) fn profile_lines(view: &ProfileView) -> PaneBody {
    let mut body = PaneBody {
        lines: vec![
            Line::from(vec![
                Span::styled("Profile ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    shorten(&terminal_safe_text(&view.npub), 32),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from("Fields"),
        ],
        anchor: None,
    };
    for (index, field) in ProfileField::ALL.iter().enumerate() {
        let is_selected = index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        let value_span = match view.field_value(*field) {
            Some(value) => Span::raw(terminal_safe_text(value)),
            None => Span::styled("(unset)".to_owned(), Style::default().fg(Color::DarkGray)),
        };
        if is_selected {
            body.anchor_next();
        }
        body.push(Line::from(vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                format!("{}: ", field.label()),
                row_label_style(is_selected, Color::Cyan),
            ),
            value_span,
        ]));
    }
    body.push(Line::from(""));
    body.push(Line::from(format!("Follows ({})", view.follows.len())));
    for (index, follow) in view.follows.iter().enumerate() {
        let is_selected = ProfileField::ALL.len() + index == view.selected;
        let marker = if is_selected { ">" } else { " " };
        if is_selected {
            body.anchor_next();
        }
        body.push(Line::from(vec![
            Span::raw(format!("{marker} ")),
            Span::styled(
                shorten(&terminal_safe_text(follow), 28),
                row_label_style(is_selected, Color::Cyan),
            ),
        ]));
    }
    body
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
        Line::from(format!(
            "forwarder: running={} restarts={} lag_incidents={} lagged={} panics={} unexpected_exits={}",
            data.notification_forwarder_running,
            data.notification_forwarder_restarts,
            data.notification_forwarder_lag_incidents,
            data.notification_forwarder_lagged_notifications,
            data.notification_forwarder_panics,
            data.notification_forwarder_unexpected_exits,
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
