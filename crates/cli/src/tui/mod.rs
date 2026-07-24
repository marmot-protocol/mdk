//! Ratatui terminal UI over the `wn --json` surface: entry point and module wiring.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Output, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use serde_json::Value;

use crate::{Cli, CliOutput, SecretStoreKind};

mod app;
mod client;
mod media;
mod model;
mod slash;
mod view;

pub(crate) use app::*;
pub(crate) use client::*;
pub(crate) use media::*;
pub(crate) use model::*;
pub(crate) use slash::*;
pub(crate) use view::*;

type TuiResult<T> = Result<T, TuiError>;
const UI_EVENT_WAIT: Duration = Duration::from_millis(50);
/// Ticks of quiet after the last chat-list selection move before the highlighted
/// chat is previewed (flick-through). At the ~50ms tick cadence this is ~150ms,
/// so racing through the list with j/k coalesces to a single load of the chat
/// the user settles on instead of one load per row. Each move resets the count;
/// the tick loop counts it down (no separate timer).
const FLICK_PREVIEW_DEBOUNCE_TICKS: u32 = 3;
const STREAM_APPEND_FLUSH_INTERVAL: Duration = Duration::from_millis(125);
/// Chrome accent: focused borders, labels, prompts, and selected markers. Cyan
/// in the color-role split — green is reserved strictly for self (own messages)
/// and the daemon-connection dot.
const FOCUS_ACCENT: Color = Color::Cyan;
const ACCOUNT_ACCENT: Color = Color::White;
const DEFAULT_STREAM_CANDIDATE: &str = crate::DEFAULT_PRODUCTION_QUIC_BROKER_CANDIDATE;
const SLASH_SUGGESTION_LIMIT: usize = 8;
const TUI_MESSAGE_SCROLLBACK_LIMIT: usize = 1_000;
/// Materialized-timeline page size for the snapshot load and each history page.
const TUI_TIMELINE_PAGE_SIZE: usize = 100;
/// Blank rows rendered below each timeline message as a separator; counted in a
/// row's rendered height so the visibility walk and the renderer agree.
const TIMELINE_MESSAGE_SEPARATOR_ROWS: u16 = 1;
/// Rows reserved for a decoded inline image at its message's position; the
/// renderer draws the aspect-fit image over this block. Counted in the row's
/// height so the scroll model stays in lockstep.
const MEDIA_IMAGE_ROWS: u16 = 8;
/// The most inbound-media downloads allowed to run at once. Each spawns a
/// subprocess and a worker thread, so an unbounded fan-out (a screen full of
/// images) would spike process/thread pressure. The remainder stay untracked
/// and are slotted on later ticks as running downloads complete.
const MEDIA_MAX_IN_FLIGHT: usize = 3;
/// How many decoded images stay retained in memory for the full-size viewer on
/// pixel-capable terminals. Each retained copy is decode-capped (at most
/// ~11.8 MB RGBA), so four bound the viewer's worst-case footprint at ~47 MB
/// while comfortably covering the freshest arrivals (`MEDIA_MAX_IN_FLIGHT`
/// admits three at a time). Opening an evicted image's viewer falls back to
/// the cell-exact halfblock popup.
const MEDIA_VIEWER_RETAINED_IMAGES: usize = 4;
const TUI_LIVE_STREAM_PREVIEW_LIMIT: usize = 128;
/// Cap on the notification-key dedup set. Dedup only needs to cover the recent
/// event window (the runtime feed emits duplicates close together), so the set
/// ages out the oldest keys past this bound instead of growing per-session.
const TUI_SEEN_NOTIFICATION_KEYS_LIMIT: usize = 512;
const TUI_LIVE_STREAM_TEXT_LIMIT: usize = 64 * 1024;
/// Max chars of the chat-list last-message preview line before trailing-ellipsis
/// truncation. The List widget clips overflow too; this keeps a stored preview
/// tidy and bounded independent of the panel width.
const TUI_CHAT_PREVIEW_LIMIT: usize = 48;

/// Max chars of the loaded chat's name in the messages-pane title before
/// trailing-ellipsis truncation, leaving room for the `[N older | M newer]`
/// overflow annotation alongside it. The panel border clips overflow too; this
/// keeps the title tidy and bounded independent of the pane width.
const MESSAGES_TITLE_NAME_LIMIT: usize = 32;

/// The in-flight status shown while a group-detail load runs off the event loop,
/// matching the `sending...`/`loading chat...`/`searching...` in-flight
/// vocabulary. The fold clears it on settle, and leaving mid-load resets it, both
/// guarded on this exact value so a more relevant status (e.g. a mutation's
/// confirmation) is never clobbered.
const LOADING_GROUP_DETAIL_STATUS: &str = "loading group detail...";

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

#[cfg(test)]
mod tests;
