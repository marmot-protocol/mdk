//! Inbound-media pipeline for the message pane: terminal-capability detection, a
//! per-plaintext-hash download-and-decode worker that runs off the event loop,
//! and the decoded terminal protocols the renderer draws.
//!
//! The status map and its `apply` reducer are pure and reducer-tested with fake
//! `MediaLoad` events; the `Picker`, the decoded `StatefulProtocol`s, and the
//! worker thread are the runtime side. Nothing here blocks the 50ms event loop:
//! the subprocess and the `image` decode both run on a worker thread and deliver
//! their result over an `mpsc` channel drained on `tick`, mirroring the
//! subscription readers.

use super::*;

use std::collections::HashMap;
use std::path::Path;
use std::sync::mpsc::Sender;

use image::DynamicImage;
use ratatui_image::picker::cap_parser::QueryStdioOptions;
use ratatui_image::picker::{Picker, ProtocolType};
use ratatui_image::protocol::StatefulProtocol;

/// A worker-thread result delivered back to the event loop. `Downloaded` is the
/// `downloading -> loading` ladder step (the subprocess finished, the decode is
/// starting); `Decoded`/`Failed` are terminal.
pub(crate) enum MediaLoad {
    Downloaded {
        hash: String,
    },
    Decoded {
        hash: String,
        /// Boxed to keep the `mpsc` message small; a `DynamicImage` is large.
        image: Box<DynamicImage>,
    },
    Failed {
        hash: String,
        error: String,
    },
}

/// Inbound-media runtime state: the detected terminal image `Picker`, the
/// per-hash status map (`MediaStatus`), the decoded protocols the renderer draws,
/// and the worker-result channel.
pub(crate) struct MediaState {
    /// `None` until capability detection runs, and after it if the terminal has
    /// no image protocol. `None` means placeholders forever, no downloads.
    picker: Option<Picker>,
    statuses: HashMap<String, MediaStatus>,
    protocols: HashMap<String, StatefulProtocol>,
    tx: Sender<MediaLoad>,
    rx: Receiver<MediaLoad>,
}

impl Default for MediaState {
    fn default() -> Self {
        Self::new()
    }
}

impl MediaState {
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            picker: None,
            statuses: HashMap::new(),
            protocols: HashMap::new(),
            tx,
            rx,
        }
    }

    /// Detect the terminal's image capability once, querying stdio. Called after
    /// raw-mode init and before the event loop owns stdin. A non-tty query fails
    /// fast; the shorter timeout bounds a tty that never answers. On any query
    /// failure the picker stays `None` (placeholders only). The query is kept only
    /// as the "is this an image-capable terminal" gate: the reported protocol is
    /// discarded and replaced with the cell-exact halfblocks protocol by
    /// `adopt_picker`, so the earlier iTerm2/Kitty misdetection no longer matters.
    pub(crate) fn detect_capability(&mut self) {
        let mut options = QueryStdioOptions::default();
        options.timeout = Duration::from_millis(500);
        if let Ok(picker) = Picker::from_query_stdio_with_options(options) {
            self.adopt_picker(picker);
        }
    }

    /// Whether the terminal has a usable image protocol.
    pub(crate) fn supported(&self) -> bool {
        self.picker.is_some()
    }

    /// A borrowed snapshot for the pure layout functions.
    pub(crate) fn view(&self) -> MediaView<'_> {
        MediaView::new(&self.statuses, self.supported())
    }

    /// Whether this hash already has a status (download requested), so the
    /// download trigger does not re-spawn a worker for it.
    pub(crate) fn is_tracked(&self, hash: &str) -> bool {
        self.statuses.contains_key(hash)
    }

    /// How many downloads are running right now: spawned but not yet decoded or
    /// failed. `Ready`/`Failed` are terminal and do not count against the cap.
    pub(crate) fn in_flight(&self) -> usize {
        self.statuses
            .values()
            .filter(|status| matches!(status, MediaStatus::Downloading | MediaStatus::Decoding))
            .count()
    }

    /// Choose which of `candidates` to start now, preserving their order,
    /// respecting `MEDIA_MAX_IN_FLIGHT` and skipping hashes already tracked
    /// (running, ready, or failed) or already chosen this pass. The unstarted
    /// remainder is left for a later tick, when completing downloads free slots.
    pub(crate) fn downloads_to_start(&self, candidates: &[String]) -> Vec<String> {
        let mut budget = MEDIA_MAX_IN_FLIGHT.saturating_sub(self.in_flight());
        let mut chosen: Vec<String> = Vec::new();
        for hash in candidates {
            if budget == 0 {
                break;
            }
            if self.is_tracked(hash) || chosen.contains(hash) {
                continue;
            }
            chosen.push(hash.clone());
            budget -= 1;
        }
        chosen
    }

    /// Whether this hash has a decoded, drawable protocol.
    pub(crate) fn is_ready(&self, hash: &str) -> bool {
        matches!(self.statuses.get(hash), Some(MediaStatus::Ready))
    }

    /// The decoded protocol for a ready image, for the renderer to draw.
    pub(crate) fn protocol_mut(&mut self, hash: &str) -> Option<&mut StatefulProtocol> {
        self.protocols.get_mut(hash)
    }

    /// Mark a hash downloading and hand out a sender for its worker. Called by the
    /// download trigger before spawning the worker.
    pub(crate) fn begin_download(&mut self, hash: String) -> Sender<MediaLoad> {
        self.statuses.insert(hash, MediaStatus::Downloading);
        self.tx.clone()
    }

    /// Drain every worker result and fold it into the status/protocol maps.
    /// Returns whether anything changed (so `tick` can mark the frame dirty).
    pub(crate) fn drain(&mut self) -> bool {
        let mut changed = false;
        // The sender is held here too, so the channel never disconnects while the
        // app lives; `while let Ok` covers both the empty and (defensively) the
        // disconnected case.
        while let Ok(load) = self.rx.try_recv() {
            self.apply(load);
            changed = true;
        }
        changed
    }

    /// The pure status/protocol reducer. Building the protocol on `Decoded` is the
    /// only non-pure step (it consumes the `Picker`); every transition is folded
    /// by hash so a duplicate or out-of-order event is idempotent.
    fn apply(&mut self, load: MediaLoad) {
        match load {
            MediaLoad::Downloaded { hash } => {
                self.statuses.insert(hash, MediaStatus::Decoding);
            }
            MediaLoad::Decoded { hash, image } => match self.picker.as_ref() {
                Some(picker) => {
                    let protocol = picker.new_resize_protocol(*image);
                    self.protocols.insert(hash.clone(), protocol);
                    self.statuses.insert(hash, MediaStatus::Ready);
                }
                None => {
                    self.statuses
                        .insert(hash, MediaStatus::Failed("no image protocol".to_owned()));
                }
            },
            MediaLoad::Failed { hash, error } => {
                self.statuses.insert(hash, MediaStatus::Failed(error));
            }
        }
    }

    /// Inject a picker for headless tests, so the `Decoded` reducer path and the
    /// renderer run without a real terminal. Routes through the same `adopt_picker`
    /// chokepoint the runtime uses, so a test picker forced to a pixel protocol is
    /// still normalized to cell-exact halfblocks (proving the invariant holds
    /// whatever the terminal reports).
    #[cfg(test)]
    pub(crate) fn with_test_picker(picker: Picker) -> Self {
        let mut state = Self::new();
        state.adopt_picker(picker);
        state
    }

    /// Feed a worker result directly, for reducer tests with fake events.
    #[cfg(test)]
    pub(crate) fn apply_for_test(&mut self, load: MediaLoad) {
        self.apply(load);
    }

    /// Adopt `picker` as the terminal image picker, normalizing it to the
    /// cell-exact halfblocks protocol whatever the terminal reported. This is the
    /// single chokepoint through which any picker enters `MediaState` — both the
    /// runtime capability query and the test hook store their picker here — so no
    /// caller can install an un-normalized (pixel-protocol) picker.
    ///
    /// The protocol chosen here governs *every* image render path: the inline
    /// timeline blocks and the full-screen image viewer popup (`o`) both draw the
    /// one shared `StatefulProtocol` built per hash from this picker. It must be
    /// cell-exact for both:
    ///
    /// - Inline, images occupy a reserved block of cells *inside a scrolling
    ///   message list*. Halfblocks draws ordinary colored cells (`▀` with fg/bg),
    ///   bounded strictly to the reserved rect, so it never spills past the block
    ///   and is erased and redrawn correctly on scroll through ratatui's normal
    ///   cell diff.
    /// - The popup has no full clear on close: ratatui erases it by diffing cells.
    ///   A pixel protocol stores its image terminal-side, out of that diff's reach,
    ///   so it cannot be reliably erased and would linger after the popup is
    ///   dismissed.
    ///
    /// The pixel protocols (iTerm2/Kitty/Sixel) map the cell rect to pixels via the
    /// terminal's detected font size and store the image terminal-side behind
    /// `set_skip` cells. When font-size detection falls back to the arbitrary
    /// `(10, 20)` default (`ratatui-image` first tries a `TIOCGWINSZ` ioctl for the
    /// window pixel size and only reaches `(10, 20)` when both the escape-sequence
    /// cell-size query and that ioctl fail), the pixels overflow the reserved block
    /// and occlude the next message, and the terminal-side image is left as an
    /// artifact a partial redraw cannot erase on scroll. Halfblocks depends on no
    /// font size for containment (the font size only tunes intermediate sampling
    /// detail), so it is robust in every terminal.
    fn adopt_picker(&mut self, mut picker: Picker) {
        picker.set_protocol_type(ProtocolType::Halfblocks);
        self.picker = Some(picker);
    }
}

/// Run a media download and decode on a worker thread, delivering the outcome
/// over `tx`. The subprocess and the `image` decode both run here, never on the
/// event loop. Success is decided by the `wn --json` envelope, not the exit code.
pub(crate) fn spawn_media_download(
    mut command: StdCommand,
    output_path: PathBuf,
    hash: String,
    tx: Sender<MediaLoad>,
) {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    thread::spawn(move || {
        let downloaded = command
            .output()
            .map_err(TuiError::from)
            .and_then(parse_json_output);
        match downloaded {
            Ok(_) => {
                // Advance to the decoding ladder step, then decode off-loop.
                let _ = tx.send(MediaLoad::Downloaded { hash: hash.clone() });
                match decode_image(&output_path) {
                    Ok(image) => {
                        let _ = tx.send(MediaLoad::Decoded {
                            hash,
                            image: Box::new(image),
                        });
                    }
                    Err(error) => {
                        let _ = tx.send(MediaLoad::Failed { hash, error });
                    }
                }
            }
            Err(err) => {
                let _ = tx.send(MediaLoad::Failed {
                    hash,
                    error: shorten(&err.to_string(), 60),
                });
            }
        }
    });
}

/// Decode a downloaded file with `image`, guessing the format from content (the
/// cache file is named by hash and has no extension).
fn decode_image(path: &Path) -> Result<DynamicImage, String> {
    image::ImageReader::open(path)
        .map_err(|err| err.to_string())?
        .with_guessed_format()
        .map_err(|err| err.to_string())?
        .decode()
        .map_err(|err| err.to_string())
}
