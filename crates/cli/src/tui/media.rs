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
use ratatui_image::{FilterType, Resize, StatefulImage};

/// The one resize policy every media `StatefulImage` render passes to
/// `ratatui-image` — the inline timeline block and the image-viewer popup both
/// route through here. `Resize::Fit(None)` would fall back to
/// `FilterType::Nearest`, which downscales by sparse sampling: on a photo shrunk
/// to a terminal-sized target the surviving samples read as pixelated noise.
/// Lanczos3 computes proper windowed averages instead, so the small render stays
/// a legible preview. Cost is bounded: the resize runs once per (image,
/// target-size) pair (`ratatui-image` re-encodes only when the target area
/// changes) and a Lanczos3 pass at terminal-sized targets is tens of
/// milliseconds.
pub(crate) fn media_image_resize() -> Resize {
    Resize::Fit(Some(FilterType::Lanczos3))
}

/// The configured `StatefulImage` widget every media render site draws with —
/// the inline timeline blocks and both viewer-popup paths — so the resize
/// policy above cannot be bypassed by constructing a widget ad hoc.
pub(crate) fn media_image_widget() -> StatefulImage<StatefulProtocol> {
    StatefulImage::new().resize(media_image_resize())
}

/// Decode-time bound on a decoded image's pixel area, sized to the largest
/// plausible terminal display target. A fullscreen retina terminal is roughly
/// 200+ columns by 50+ rows at font cells up to ~(14, 30) physical pixels —
/// about 2800x1650 window pixels — and the image-viewer popup shows at most 80%
/// of that (~2240x1320). The 2100x1400 box covers that for both orientations
/// (`Resize::Fit` never upscales, so a retained copy only needs to match the
/// largest area it can ever be displayed at). Everything larger is downscaled on
/// the worker thread; at RGBA8 a capped image costs at most
/// 2100 x 1400 x 4 bytes = ~11.8 MB, where an unbounded 48 MP camera photo
/// would cost ~190 MB.
const MEDIA_DECODED_MAX_WIDTH: u32 = 2100;
const MEDIA_DECODED_MAX_HEIGHT: u32 = 1400;

/// Downscale `image` to fit inside the decode-time cap box, preserving aspect;
/// images already inside the box pass through untouched (`DynamicImage::resize`
/// would upscale them, costing memory for no fidelity). Runs on the worker
/// thread, never the event loop: a Lanczos3 pass over a large camera photo can
/// take hundreds of milliseconds.
pub(crate) fn cap_decoded_image(image: DynamicImage) -> DynamicImage {
    if image.width() <= MEDIA_DECODED_MAX_WIDTH && image.height() <= MEDIA_DECODED_MAX_HEIGHT {
        return image;
    }
    image.resize(
        MEDIA_DECODED_MAX_WIDTH,
        MEDIA_DECODED_MAX_HEIGHT,
        FilterType::Lanczos3,
    )
}

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
    /// The pixel-protocol picker the startup query reported, kept only when the
    /// terminal actually has one (the query never reaches a pixel protocol
    /// without a real font size). The inline picker above is always forced to
    /// halfblocks; this one exists solely so the full-size viewer popup can
    /// draw the terminal's native image protocol.
    viewer_picker: Option<Picker>,
    /// Decoded pixels retained for the viewer popup, per hash, on every
    /// image-capable terminal — pixel or halfblock-only. They seed the popup's
    /// own dedicated protocol (native on a pixel terminal, a fresh halfblock
    /// instance otherwise), so the popup never draws, and so never re-resizes,
    /// the shared inline protocol. Images are decode-capped, so each entry costs
    /// at most ~11.8 MB, and the map is bounded by eviction.
    viewer_images: HashMap<String, DynamicImage>,
    /// Insertion order of `viewer_images` for oldest-first eviction.
    viewer_order: VecDeque<String>,
    /// The one on-demand viewer protocol, built when the viewer popup opens
    /// and dropped when it closes. Keyed by hash so a stale popup for another
    /// image can never draw it.
    viewer_protocol: Option<(String, StatefulProtocol)>,
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
            viewer_picker: None,
            viewer_images: HashMap::new(),
            viewer_order: VecDeque::new(),
            viewer_protocol: None,
            statuses: HashMap::new(),
            protocols: HashMap::new(),
            tx,
            rx,
        }
    }

    /// Detect the terminal's image capability once, querying stdio. Called after
    /// raw-mode init and before the event loop owns stdin. A non-tty query fails
    /// fast; the shorter timeout bounds a tty that never answers. On any query
    /// failure the picker stays `None` (placeholders only). The inline renderer
    /// uses the query only as the "is this an image-capable terminal" gate — the
    /// reported protocol is normalized to cell-exact halfblocks by
    /// `adopt_picker` — while a reported pixel protocol is remembered separately
    /// for the full-size viewer popup.
    pub(crate) fn detect_capability(&mut self) {
        let mut options = QueryStdioOptions::default();
        options.timeout = Duration::from_millis(500);
        if let Ok(picker) = Picker::from_query_stdio_with_options(options) {
            self.adopt_picker(picker, iterm2_session());
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
                    let image = *image;
                    // Keep a copy for the viewer popup before the inline protocol
                    // consumes the decode. Retained on every image-capable
                    // terminal (not only pixel ones): the popup builds its own
                    // dedicated protocol from this copy, so drawing it at popup
                    // size never disturbs the shared inline protocol's cached
                    // size. Bounded by eviction, so the extra copies stay
                    // memory-safe.
                    let viewer_copy = image.clone();
                    let protocol = picker.new_resize_protocol(image);
                    self.protocols.insert(hash.clone(), protocol);
                    self.statuses.insert(hash.clone(), MediaStatus::Ready);
                    self.retain_viewer_image(hash, viewer_copy);
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

    /// Retain a decode-capped copy of `hash`'s pixels for the viewer popup,
    /// evicting oldest-first past `MEDIA_VIEWER_RETAINED_IMAGES`. Re-decoding a
    /// hash refreshes its pixels in place without double-counting it in the
    /// eviction order (the reducer folds duplicates idempotently).
    fn retain_viewer_image(&mut self, hash: String, image: DynamicImage) {
        if !self.viewer_images.contains_key(&hash) {
            self.viewer_order.push_back(hash.clone());
        }
        self.viewer_images.insert(hash, image);
        while self.viewer_order.len() > MEDIA_VIEWER_RETAINED_IMAGES {
            if let Some(evicted) = self.viewer_order.pop_front() {
                self.viewer_images.remove(&evicted);
            }
        }
    }

    /// Build the popup's own dedicated protocol from the retained pixels for
    /// `hash`, so the popup never draws — and so never re-resizes — the shared
    /// inline `protocols[hash]`. Uses the terminal's native pixel picker when it
    /// has one, otherwise a fresh halfblocks instance built from the inline
    /// picker; either way this is a distinct instance from the inline protocol,
    /// dropped when the popup closes.
    ///
    /// Returns whether one was built. It is `false` only when the pixels were
    /// evicted from the bounded retention (viewing an image older than the
    /// retention window); the popup then draws the shared inline protocol as a
    /// last resort — the evicted image's pixels survive only inside that
    /// protocol, and `ratatui-image` exposes no way to read them back out to
    /// seed a distinct instance. Any previously built viewer protocol is dropped
    /// either way.
    pub(crate) fn build_viewer_protocol(&mut self, hash: &str) -> bool {
        // Prefer the terminal's native pixel picker; fall back to the inline
        // halfblocks picker so a halfblock-only terminal still gets a dedicated
        // (distinct-from-inline) instance rather than reusing the inline one.
        let picker = self.viewer_picker.as_ref().or(self.picker.as_ref());
        self.viewer_protocol = match (picker, self.viewer_images.get(hash)) {
            (Some(picker), Some(image)) => {
                Some((hash.to_owned(), picker.new_resize_protocol(image.clone())))
            }
            _ => None,
        };
        self.viewer_protocol.is_some()
    }

    /// The on-demand viewer protocol for `hash`, if one was built for exactly
    /// that hash and not yet dropped.
    pub(crate) fn viewer_protocol_mut(&mut self, hash: &str) -> Option<&mut StatefulProtocol> {
        self.viewer_protocol
            .as_mut()
            .filter(|(built_for, _)| built_for == hash)
            .map(|(_, protocol)| protocol)
    }

    /// Drop the on-demand viewer protocol (the popup closed). Frees the
    /// protocol's pixel copy and its encoded payload; the retained viewer image
    /// stays so reopening the popup rebuilds it.
    pub(crate) fn drop_viewer_protocol(&mut self) {
        self.viewer_protocol = None;
    }

    /// Inject a picker for headless tests, so the `Decoded` reducer path and the
    /// renderer run without a real terminal. Routes through the same `adopt_picker`
    /// chokepoint the runtime uses, so a test picker forced to a pixel protocol is
    /// still normalized to cell-exact halfblocks for the inline renderer (proving
    /// the invariant holds whatever the terminal reports). The iTerm2-session
    /// hint is pinned off so tests behave the same inside and outside iTerm2;
    /// `with_test_picker_in_iterm2_session` covers the hint itself.
    #[cfg(test)]
    pub(crate) fn with_test_picker(picker: Picker) -> Self {
        let mut state = Self::new();
        state.adopt_picker(picker, false);
        state
    }

    /// As `with_test_picker`, but as if the process were running inside an
    /// iTerm2 session (`ITERM_SESSION_ID` and friends), without touching the
    /// test process's real environment.
    #[cfg(test)]
    pub(crate) fn with_test_picker_in_iterm2_session(picker: Picker) -> Self {
        let mut state = Self::new();
        state.adopt_picker(picker, true);
        state
    }

    /// Feed a worker result directly, for reducer tests with fake events.
    #[cfg(test)]
    pub(crate) fn apply_for_test(&mut self, load: MediaLoad) {
        self.apply(load);
    }

    /// Adopt `picker` as the terminal image picker: remember a reported pixel
    /// protocol for the viewer popup, then normalize the inline picker to the
    /// cell-exact halfblocks protocol whatever the terminal reported. This is the
    /// single chokepoint through which any picker enters `MediaState` — both the
    /// runtime capability query and the test hooks store their picker here — so
    /// no caller can install an un-normalized (pixel-protocol) picker for the
    /// inline renderer.
    ///
    /// Inline, images occupy a reserved block of cells *inside a scrolling
    /// message list*. Halfblocks draws ordinary colored cells (`▀` with fg/bg),
    /// bounded strictly to the reserved rect, so it never spills past the block
    /// and is erased and redrawn correctly on scroll through ratatui's normal
    /// cell diff. The pixel protocols (iTerm2/Kitty/Sixel) instead map the cell
    /// rect to pixels via the terminal's detected font size and store the image
    /// terminal-side behind `set_skip` cells. When font-size detection falls back
    /// to the arbitrary `(10, 20)` default (`ratatui-image` first tries a
    /// `TIOCGWINSZ` ioctl for the window pixel size and only reaches `(10, 20)`
    /// when both the escape-sequence cell-size query and that ioctl fail), the
    /// pixels overflow the reserved block and occlude the next message, and the
    /// terminal-side image is left as an artifact a partial redraw cannot erase
    /// on scroll. Halfblocks depends on no font size for containment (the font
    /// size only tunes intermediate sampling detail), so it is robust in every
    /// terminal.
    ///
    /// A *reported* pixel protocol is still real capability, and the modal viewer
    /// popup is a safe place to use it (its close path forces a full terminal
    /// repaint, which is what a scrolling inline block cannot afford per frame).
    /// So before the halfblocks normalization, a non-halfblocks picker is cloned
    /// into `viewer_picker`. `ratatui-image` only reports a pixel protocol
    /// together with a queried (or `TIOCGWINSZ`-derived) font size — the
    /// `(10, 20)` fallback path always reports halfblocks — so a retained viewer
    /// picker always carries a real font size. Inside an iTerm2 session the
    /// query is answered kitty-style and misdetected as Kitty (the reason the
    /// inline forcing exists at all), so `iterm2_session` overrides the viewer
    /// protocol to iTerm2's own.
    fn adopt_picker(&mut self, mut picker: Picker, iterm2_session: bool) {
        if picker.protocol_type() != ProtocolType::Halfblocks {
            let mut viewer_picker = picker.clone();
            if iterm2_session {
                viewer_picker.set_protocol_type(ProtocolType::Iterm2);
            }
            self.viewer_picker = Some(viewer_picker);
        }
        picker.set_protocol_type(ProtocolType::Halfblocks);
        self.picker = Some(picker);
    }
}

/// Whether this process is running inside an iTerm2 session, per the same
/// environment markers `ratatui-image` itself trusts as iTerm2 hints
/// (`ITERM_SESSION_ID`, `LC_TERMINAL`, `TERM_PROGRAM`). Used only to pick the
/// viewer popup's protocol; inline rendering never depends on it.
fn iterm2_session() -> bool {
    std::env::var("ITERM_SESSION_ID").is_ok_and(|value| !value.is_empty())
        || std::env::var("LC_TERMINAL").is_ok_and(|value| value.contains("iTerm"))
        || std::env::var("TERM_PROGRAM").is_ok_and(|value| value.contains("iTerm"))
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
                let decoded = decode_image(&output_path).map(cap_decoded_image);
                // Whether decode produced an in-memory image or an error, the file
                // has no remaining reader; remove the decrypted plaintext artifact
                // before signalling completion so it never lingers at rest.
                // Best-effort: it may already be gone.
                let _ = std::fs::remove_file(&output_path);
                match decoded {
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
                // A failed download may still have written a partial file (e.g.
                // ENOSPC mid-write); the startup sweep clears it next session.
                let _ = tx.send(MediaLoad::Failed {
                    hash,
                    error: shorten(&err.to_string(), 60),
                });
            }
        }
    });
}

/// Best-effort sweep of the flat media-cache directory: remove every entry it
/// holds, keeping the directory itself. Decrypted-media artifacts are deleted
/// right after decode, so anything still here is litter from a crashed session —
/// decrypted plaintext at rest — swept at startup so it never lingers.
///
/// A missing directory and per-entry errors are ignored (the sweep is advisory).
/// Only the directory's own entries are touched — the layout is flat, so no
/// recursion is needed — and `remove_file` unlinks a symlink rather than
/// following it, so nothing outside the directory is ever removed. The root
/// itself must be a real directory: `read_dir` follows a symlink at the path,
/// and the no-home fallback lives under the shared temp dir where a symlinked
/// `tui-media-cache` could be pre-planted to redirect the unlinks. The check
/// races `read_dir` in principle; the sweep is best-effort startup cleanup,
/// not a security boundary for an already-writable directory.
pub(crate) fn sweep_media_cache_dir(dir: &Path) {
    let is_real_dir = dir
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_dir());
    if !is_real_dir {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let _ = std::fs::remove_file(entry.path());
    }
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
