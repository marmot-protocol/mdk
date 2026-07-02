//! Ratatui terminal UI over the `dm --json` surface: entry point and module wiring.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Output, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use serde_json::Value;

use crate::{Cli, CliOutput, SecretStoreKind};

mod app;
mod client;
mod model;
mod slash;
mod view;

pub(crate) use app::*;
pub(crate) use client::*;
pub(crate) use model::*;
pub(crate) use slash::*;
pub(crate) use view::*;

type TuiResult<T> = Result<T, TuiError>;
const UI_EVENT_WAIT: Duration = Duration::from_millis(50);
const STREAM_APPEND_FLUSH_INTERVAL: Duration = Duration::from_millis(125);
const FOCUS_ACCENT: Color = Color::Green;
const ACCOUNT_ACCENT: Color = Color::White;
const DEFAULT_STREAM_CANDIDATE: &str = crate::DEFAULT_PRODUCTION_QUIC_BROKER_CANDIDATE;
const SLASH_SUGGESTION_LIMIT: usize = 8;
const TUI_MESSAGE_SCROLLBACK_LIMIT: usize = 1_000;
const TUI_LIVE_STREAM_PREVIEW_LIMIT: usize = 128;
const TUI_LIVE_STREAM_TEXT_LIMIT: usize = 64 * 1024;

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
