use std::fmt;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use crate::{HarnessError, Result, RunnerEvent};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

pub(crate) const DEFAULT_MAX_RECORD_BYTES: usize = MIB;
pub(crate) const HARD_MAX_RECORD_BYTES: usize = 4 * MIB;
pub(crate) const DEFAULT_MAX_STDOUT_BYTES: usize = 16 * MIB;
pub(crate) const HARD_MAX_STDOUT_BYTES: usize = 64 * MIB;
pub(crate) const DEFAULT_MAX_TEXT_BYTES: usize = MIB;
pub(crate) const HARD_MAX_TEXT_BYTES: usize = 8 * MIB;
pub(crate) const DEFAULT_MAX_ARTIFACT_BUFFER_BYTES: usize = 512 * KIB;
pub(crate) const HARD_MAX_ARTIFACT_BUFFER_BYTES: usize = 4 * MIB;
pub(crate) const DEFAULT_MAX_BACKEND_EVENTS: usize = 8192;
pub(crate) const HARD_MAX_BACKEND_EVENTS: usize = 65_536;
pub(crate) const DEFAULT_MAX_TEXT_EVENTS: usize = 256;
pub(crate) const HARD_MAX_TEXT_EVENTS: usize = 4096;
pub(crate) const DEFAULT_MAX_REPLY_CHUNKS: usize = 64;
pub(crate) const HARD_MAX_REPLY_CHUNKS: usize = 256;
pub(crate) const DEFAULT_MAX_DURABLE_SENDS: usize = 128;
pub(crate) const HARD_MAX_DURABLE_SENDS: usize = 512;
pub(crate) const HARD_MAX_ARTIFACTS: usize = crate::artifacts::MAX_ARTIFACTS_PER_RESULT;

/// Stable, privacy-safe classification of the first per-invocation output limit breached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutputLimitKind {
    /// One stdout JSONL record exceeded its byte cap before a delimiter arrived.
    StdoutRecord,
    /// Total raw stdout bytes exceeded the invocation cap.
    StdoutBytes,
    /// Framed backend records, including blank, ignored, and malformed ones, exceeded the cap.
    BackendEvents,
    /// Parsed assistant-text bytes exceeded the invocation cap.
    AssistantTextBytes,
    /// Parsed assistant-text events exceeded the invocation cap.
    AssistantTextEvents,
    /// Assistant text retained for an artifact caption exceeded its buffer cap.
    ArtifactBuffer,
    /// Declared artifacts across the invocation exceeded the configured count.
    ArtifactCount,
    /// Staged reply chunks exceeded the invocation cap.
    ReplyChunks,
    /// Attempted durable output requests, including retries, exceeded the cap.
    DurableSends,
}

impl OutputLimitKind {
    /// Stable tracing and error-classification value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StdoutRecord => "stdout_record_limit",
            Self::StdoutBytes => "stdout_bytes_limit",
            Self::BackendEvents => "backend_event_limit",
            Self::AssistantTextBytes => "assistant_text_bytes_limit",
            Self::AssistantTextEvents => "assistant_text_event_limit",
            Self::ArtifactBuffer => "artifact_buffer_limit",
            Self::ArtifactCount => "artifact_count_limit",
            Self::ReplyChunks => "reply_chunk_limit",
            Self::DurableSends => "durable_send_limit",
        }
    }
}

impl fmt::Display for OutputLimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Unvalidated per-invocation output limit values. Convert with [`OutputLimits::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputLimitSettings {
    /// Maximum bytes in one stdout record, excluding its LF delimiter.
    pub max_record_bytes: usize,
    /// Maximum raw stdout bytes, including delimiters and ignored output.
    pub max_stdout_bytes: usize,
    /// Maximum parsed assistant-text bytes.
    pub max_text_bytes: usize,
    /// Maximum assistant-text bytes retained for an artifact caption, including separators.
    pub max_artifact_buffer_bytes: usize,
    /// Maximum framed backend records.
    pub max_backend_events: usize,
    /// Maximum parsed assistant-text events.
    pub max_text_events: usize,
    /// Maximum staged reply chunks.
    pub max_reply_chunks: usize,
    /// Maximum attempted durable output requests.
    pub max_durable_sends: usize,
    /// Maximum declared artifacts.
    pub max_artifacts: usize,
}

impl Default for OutputLimitSettings {
    fn default() -> Self {
        Self {
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_artifact_buffer_bytes: DEFAULT_MAX_ARTIFACT_BUFFER_BYTES,
            max_backend_events: DEFAULT_MAX_BACKEND_EVENTS,
            max_text_events: DEFAULT_MAX_TEXT_EVENTS,
            max_reply_chunks: DEFAULT_MAX_REPLY_CHUNKS,
            max_durable_sends: DEFAULT_MAX_DURABLE_SENDS,
            max_artifacts: HARD_MAX_ARTIFACTS,
        }
    }
}

impl OutputLimitSettings {
    fn bounds(&self) -> [(&'static str, usize, usize); 9] {
        [
            (
                "max_record_bytes",
                self.max_record_bytes,
                HARD_MAX_RECORD_BYTES,
            ),
            (
                "max_stdout_bytes",
                self.max_stdout_bytes,
                HARD_MAX_STDOUT_BYTES,
            ),
            ("max_text_bytes", self.max_text_bytes, HARD_MAX_TEXT_BYTES),
            (
                "max_artifact_buffer_bytes",
                self.max_artifact_buffer_bytes,
                HARD_MAX_ARTIFACT_BUFFER_BYTES,
            ),
            (
                "max_backend_events",
                self.max_backend_events,
                HARD_MAX_BACKEND_EVENTS,
            ),
            (
                "max_text_events",
                self.max_text_events,
                HARD_MAX_TEXT_EVENTS,
            ),
            (
                "max_reply_chunks",
                self.max_reply_chunks,
                HARD_MAX_REPLY_CHUNKS,
            ),
            (
                "max_durable_sends",
                self.max_durable_sends,
                HARD_MAX_DURABLE_SENDS,
            ),
            ("max_artifacts", self.max_artifacts, HARD_MAX_ARTIFACTS),
        ]
    }
}

/// Validated, finite per-invocation limits for untrusted backend output.
///
/// Every limit is at least one and at most its documented hard maximum; there is no
/// unlimited value.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct OutputLimits {
    settings: OutputLimitSettings,
}

impl OutputLimits {
    /// Validates every limit against `1..=hard maximum`.
    pub fn new(settings: OutputLimitSettings) -> Result<Self> {
        for (name, value, maximum) in settings.bounds() {
            if !(1..=maximum).contains(&value) {
                return Err(HarnessError::Config(format!(
                    "output limit {name} must be between 1 and {maximum}"
                )));
            }
        }
        Ok(Self { settings })
    }

    pub fn max_record_bytes(&self) -> usize {
        self.settings.max_record_bytes
    }

    pub fn max_stdout_bytes(&self) -> usize {
        self.settings.max_stdout_bytes
    }

    pub fn max_text_bytes(&self) -> usize {
        self.settings.max_text_bytes
    }

    pub fn max_artifact_buffer_bytes(&self) -> usize {
        self.settings.max_artifact_buffer_bytes
    }

    pub fn max_backend_events(&self) -> usize {
        self.settings.max_backend_events
    }

    pub fn max_text_events(&self) -> usize {
        self.settings.max_text_events
    }

    pub fn max_reply_chunks(&self) -> usize {
        self.settings.max_reply_chunks
    }

    pub fn max_durable_sends(&self) -> usize {
        self.settings.max_durable_sends
    }

    pub fn max_artifacts(&self) -> usize {
        self.settings.max_artifacts
    }
}

impl fmt::Debug for OutputLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.settings, formatter)
    }
}

/// Adds `amount` to a counter only when the result stays within `limit`.
/// Arithmetic overflow is a breach, never a saturating admission.
pub(crate) fn charge(
    counter: &mut usize,
    amount: usize,
    limit: usize,
    kind: OutputLimitKind,
) -> std::result::Result<(), OutputLimitKind> {
    match counter.checked_add(amount) {
        Some(next) if next <= limit => {
            *counter = next;
            Ok(())
        }
        _ => Err(kind),
    }
}

/// Shared per-invocation limits plus a first-breach-wins stop latch.
///
/// The backend runner and the reply collector share one instance. Whichever side
/// detects a breach first latches its class; the other side observes the stop
/// notification out of band, so a full event channel cannot delay it.
#[derive(Clone)]
pub struct TurnOutputControl {
    inner: Arc<TurnOutputInner>,
}

struct TurnOutputInner {
    limits: OutputLimits,
    stop: watch::Sender<Option<OutputLimitKind>>,
}

impl TurnOutputControl {
    pub fn new(limits: OutputLimits) -> Self {
        let (stop, _) = watch::channel(None);
        Self {
            inner: Arc::new(TurnOutputInner { limits, stop }),
        }
    }

    pub fn limits(&self) -> &OutputLimits {
        &self.inner.limits
    }

    /// Latches `kind` unless another class already won, and returns the winning class.
    pub fn latch(&self, kind: OutputLimitKind) -> OutputLimitKind {
        self.inner.stop.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(kind);
                true
            } else {
                false
            }
        });
        self.latched().unwrap_or(kind)
    }

    /// Returns the latched breach class, if any.
    pub fn latched(&self) -> Option<OutputLimitKind> {
        *self.inner.stop.borrow()
    }

    /// Latches `kind` and returns the stable error for the winning class.
    pub fn exceeded(&self, kind: OutputLimitKind) -> HarnessError {
        HarnessError::OutputLimitExceeded {
            kind: self.latch(kind),
        }
    }

    /// Returns the latched error without latching a new class.
    pub fn stop_error(&self) -> Option<HarnessError> {
        self.latched()
            .map(|kind| HarnessError::OutputLimitExceeded { kind })
    }

    /// Resolves once any breach is latched. Cancellation-safe.
    pub async fn stopped(&self) -> OutputLimitKind {
        let mut receiver = self.inner.stop.subscribe();
        let latched = receiver
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|kind| *kind);
        match latched {
            Some(kind) => kind,
            // `self` keeps the sender alive, so the channel never closes here.
            None => std::future::pending().await,
        }
    }

    /// Sends one event unless a breach is latched before or while waiting on
    /// channel backpressure.
    pub async fn send_event(
        &self,
        tx: &mpsc::Sender<RunnerEvent>,
        event: RunnerEvent,
    ) -> std::result::Result<(), HarnessError> {
        if let Some(error) = self.stop_error() {
            return Err(error);
        }
        tokio::select! {
            biased;
            kind = self.stopped() => Err(HarnessError::OutputLimitExceeded { kind }),
            result = tx.send(event) => result.map_err(|_| {
                self.stop_error().unwrap_or(HarnessError::BackendStream)
            }),
        }
    }
}

impl Default for TurnOutputControl {
    fn default() -> Self {
        Self::new(OutputLimits::default())
    }
}

impl fmt::Debug for TurnOutputControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnOutputControl")
            .field("limits", &self.inner.limits)
            .field("latched", &self.latched())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn with(update: impl FnOnce(&mut OutputLimitSettings)) -> OutputLimitSettings {
        let mut settings = OutputLimitSettings::default();
        update(&mut settings);
        settings
    }

    #[test]
    fn defaults_are_valid_finite_and_within_hard_maxima() {
        let limits = OutputLimits::new(OutputLimitSettings::default()).unwrap();
        assert_eq!(limits, OutputLimits::default());
        assert_eq!(limits.max_record_bytes(), 1024 * 1024);
        assert_eq!(limits.max_stdout_bytes(), 16 * 1024 * 1024);
        assert_eq!(limits.max_text_bytes(), 1024 * 1024);
        assert_eq!(limits.max_artifact_buffer_bytes(), 512 * 1024);
        assert_eq!(limits.max_backend_events(), 8192);
        assert_eq!(limits.max_text_events(), 256);
        assert_eq!(limits.max_reply_chunks(), 64);
        assert_eq!(limits.max_durable_sends(), 128);
        assert_eq!(limits.max_artifacts(), 10);
    }

    #[test]
    fn every_limit_accepts_one_and_hard_maximum_and_rejects_zero_and_maximum_plus_one() {
        type Setter = fn(&mut OutputLimitSettings, usize);
        let setters: [(Setter, usize, &str); 9] = [
            (
                |s, v| s.max_record_bytes = v,
                HARD_MAX_RECORD_BYTES,
                "max_record_bytes",
            ),
            (
                |s, v| s.max_stdout_bytes = v,
                HARD_MAX_STDOUT_BYTES,
                "max_stdout_bytes",
            ),
            (
                |s, v| s.max_text_bytes = v,
                HARD_MAX_TEXT_BYTES,
                "max_text_bytes",
            ),
            (
                |s, v| s.max_artifact_buffer_bytes = v,
                HARD_MAX_ARTIFACT_BUFFER_BYTES,
                "max_artifact_buffer_bytes",
            ),
            (
                |s, v| s.max_backend_events = v,
                HARD_MAX_BACKEND_EVENTS,
                "max_backend_events",
            ),
            (
                |s, v| s.max_text_events = v,
                HARD_MAX_TEXT_EVENTS,
                "max_text_events",
            ),
            (
                |s, v| s.max_reply_chunks = v,
                HARD_MAX_REPLY_CHUNKS,
                "max_reply_chunks",
            ),
            (
                |s, v| s.max_durable_sends = v,
                HARD_MAX_DURABLE_SENDS,
                "max_durable_sends",
            ),
            (
                |s, v| s.max_artifacts = v,
                HARD_MAX_ARTIFACTS,
                "max_artifacts",
            ),
        ];
        for (set, maximum, name) in setters {
            for valid in [1, maximum] {
                assert!(OutputLimits::new(with(|s| set(s, valid))).is_ok(), "{name}");
            }
            for invalid in [0, maximum + 1, usize::MAX] {
                let error = OutputLimits::new(with(|s| set(s, invalid))).unwrap_err();
                assert!(error.to_string().contains(name), "{name}");
            }
        }
    }

    #[test]
    fn charge_is_checked_and_never_saturates() {
        let mut counter = 3;
        assert!(charge(&mut counter, 2, 5, OutputLimitKind::StdoutBytes).is_ok());
        assert_eq!(counter, 5);
        assert_eq!(
            charge(&mut counter, 1, 5, OutputLimitKind::StdoutBytes),
            Err(OutputLimitKind::StdoutBytes)
        );
        assert_eq!(counter, 5);
        let mut counter = usize::MAX;
        assert_eq!(
            charge(&mut counter, 1, usize::MAX, OutputLimitKind::BackendEvents),
            Err(OutputLimitKind::BackendEvents)
        );
    }

    #[test]
    fn stable_kind_names_are_exact() {
        let kinds = [
            (OutputLimitKind::StdoutRecord, "stdout_record_limit"),
            (OutputLimitKind::StdoutBytes, "stdout_bytes_limit"),
            (OutputLimitKind::BackendEvents, "backend_event_limit"),
            (
                OutputLimitKind::AssistantTextBytes,
                "assistant_text_bytes_limit",
            ),
            (
                OutputLimitKind::AssistantTextEvents,
                "assistant_text_event_limit",
            ),
            (OutputLimitKind::ArtifactBuffer, "artifact_buffer_limit"),
            (OutputLimitKind::ArtifactCount, "artifact_count_limit"),
            (OutputLimitKind::ReplyChunks, "reply_chunk_limit"),
            (OutputLimitKind::DurableSends, "durable_send_limit"),
        ];
        for (kind, name) in kinds {
            assert_eq!(kind.as_str(), name);
            let error = HarnessError::OutputLimitExceeded { kind };
            assert_eq!(error.privacy_safe_kind(), name);
        }
    }

    #[tokio::test]
    async fn first_latched_breach_wins_and_wakes_waiters() {
        let control = TurnOutputControl::default();
        assert_eq!(control.latched(), None);
        let waiter = {
            let control = control.clone();
            tokio::spawn(async move { control.stopped().await })
        };
        tokio::task::yield_now().await;
        assert_eq!(
            control.latch(OutputLimitKind::ReplyChunks),
            OutputLimitKind::ReplyChunks
        );
        assert_eq!(
            control.latch(OutputLimitKind::StdoutBytes),
            OutputLimitKind::ReplyChunks
        );
        assert!(matches!(
            control.exceeded(OutputLimitKind::DurableSends),
            HarnessError::OutputLimitExceeded {
                kind: OutputLimitKind::ReplyChunks
            }
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .unwrap()
                .unwrap(),
            OutputLimitKind::ReplyChunks
        );
        assert_eq!(control.stopped().await, OutputLimitKind::ReplyChunks);
    }

    #[tokio::test]
    async fn send_event_is_interrupted_by_stop_while_the_channel_is_full() {
        let control = TurnOutputControl::default();
        let (tx, _rx) = mpsc::channel(1);
        control
            .send_event(&tx, RunnerEvent::Text("first".to_owned()))
            .await
            .unwrap();
        let blocked = {
            let control = control.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                control
                    .send_event(&tx, RunnerEvent::Text("second".to_owned()))
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!blocked.is_finished());
        control.latch(OutputLimitKind::AssistantTextBytes);
        let result = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(HarnessError::OutputLimitExceeded {
                kind: OutputLimitKind::AssistantTextBytes
            })
        ));
        assert!(matches!(
            control.send_event(&tx, RunnerEvent::LivenessUnknown).await,
            Err(HarnessError::OutputLimitExceeded { .. })
        ));
    }

    #[test]
    fn debug_reports_limits_and_latch_only() {
        let control = TurnOutputControl::default();
        control.latch(OutputLimitKind::BackendEvents);
        let debug = format!("{control:?}");
        assert!(debug.contains("max_record_bytes"));
        assert!(debug.contains("BackendEvents"));
    }
}
