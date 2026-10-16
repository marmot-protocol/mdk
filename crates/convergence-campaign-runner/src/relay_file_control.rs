use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cgka_conformance_simulator::ScenarioMessageSelectorV2;
use cgka_conformance_simulator::process_orchestrator::{
    ProcessRelayControl, ProcessRelayControlError,
};
use nostr_relay_builder::prelude::{
    Backend, BoxedFuture, DatabaseError, DatabaseEventStatus, Event, EventId, Events, Filter, Kind,
    MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RelayBuilder, SaveEventStatus,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

const PUBLICATION_LOG: &str = "publication-log.v1.jsonl";
const HIDDEN_EVENTS: &str = "hidden-events";
const CONTROL_SECRET: &str = "control-secret";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RelayPublicationClassV1 {
    GroupMessage,
    Welcome,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RelayPublicationV1 {
    event_token: String,
    class: RelayPublicationClassV1,
}

impl RelayPublicationV1 {
    fn from_event(event: &Event, secret: &[u8; 32]) -> Self {
        let class = if event.kind == Kind::MlsGroupMessage {
            RelayPublicationClassV1::GroupMessage
        } else if event.kind == Kind::GiftWrap {
            RelayPublicationClassV1::Welcome
        } else {
            RelayPublicationClassV1::Other
        };
        Self {
            event_token: opaque_event_token(secret, &event.id.to_hex()),
            class,
        }
    }

    fn is_addressable(&self, include_welcomes: bool) -> bool {
        self.class == RelayPublicationClassV1::GroupMessage
            || (include_welcomes && self.class == RelayPublicationClassV1::Welcome)
    }
}

#[derive(Clone, Debug)]
struct FileRecordingRelayDatabase {
    inner: MemoryDatabase,
    control_root: PathBuf,
    secret: [u8; 32],
    publication_write: Arc<Mutex<()>>,
}

impl FileRecordingRelayDatabase {
    fn hidden(&self, event_id: &EventId) -> bool {
        self.control_root
            .join(HIDDEN_EVENTS)
            .join(opaque_event_token(&self.secret, &event_id.to_hex()))
            .is_file()
    }

    fn append_publication(&self, event: &Event) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(&RelayPublicationV1::from_event(event, &self.secret))
            .map_err(io::Error::other)?;
        bytes.push(b'\n');
        let mut file = fs_private::open_private_append(&self.control_root.join(PUBLICATION_LOG))?;
        file.write_all(&bytes)?;
        file.sync_data()
    }
}

impl NostrDatabase for FileRecordingRelayDatabase {
    fn backend(&self) -> Backend {
        self.inner.backend()
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> BoxedFuture<'a, Result<SaveEventStatus, DatabaseError>> {
        Box::pin(async move {
            let status = self.inner.save_event(event).await?;
            if status.is_success() {
                let _guard = self.publication_write.lock().await;
                self.append_publication(event)
                    .map_err(DatabaseError::backend)?;
            }
            Ok(status)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<DatabaseEventStatus, DatabaseError>> {
        Box::pin(async move {
            if self.hidden(event_id) {
                return Ok(DatabaseEventStatus::NotExistent);
            }
            self.inner.check_id(event_id).await
        })
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<Option<Event>, DatabaseError>> {
        Box::pin(async move {
            if self.hidden(event_id) {
                return Ok(None);
            }
            self.inner.event_by_id(event_id).await
        })
    }

    fn count(&self, filter: Filter) -> BoxedFuture<'_, Result<usize, DatabaseError>> {
        Box::pin(async move { Ok(self.query(filter).await?.len()) })
    }

    fn query(&self, filter: Filter) -> BoxedFuture<'_, Result<Events, DatabaseError>> {
        Box::pin(async move {
            // Apply the requested limit only after hidden events are removed;
            // otherwise one hidden newest event would incorrectly reduce the
            // visible result below the relay client's requested page size.
            let mut database_filter = filter.clone();
            database_filter.limit = None;
            let events = self.inner.query(database_filter).await?;
            let mut visible = Events::new(&filter);
            visible.extend(events.into_iter().filter(|event| !self.hidden(&event.id)));
            Ok(visible)
        })
    }

    fn delete(&self, filter: Filter) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.delete(filter)
    }

    fn wipe(&self) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.wipe()
    }
}

pub fn file_control_relay_builder(control_root: &Path) -> io::Result<RelayBuilder> {
    fs_private::create_dir_all_private(control_root)?;
    fs_private::create_dir_all_private(&control_root.join(HIDDEN_EVENTS))?;
    fs_private::ensure_private_file(&control_root.join(PUBLICATION_LOG))?;
    let secret = read_control_secret(control_root)?;
    Ok(
        cgka_conformance_simulator::harness_relay_builder().database(FileRecordingRelayDatabase {
            inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
                events: true,
                max_events: Some(75_000),
            }),
            control_root: control_root.to_path_buf(),
            secret,
            publication_write: Arc::new(Mutex::new(())),
        }),
    )
}

pub struct FileProcessRelayControl {
    control_root: PathBuf,
    secret: [u8; 32],
    action_events: Mutex<BTreeMap<String, Vec<RelayPublicationV1>>>,
}

impl FileProcessRelayControl {
    pub fn new(control_root: impl Into<PathBuf>) -> io::Result<Self> {
        let control_root = control_root.into();
        fs_private::create_dir_all_private(&control_root)?;
        fs_private::create_dir_all_private(&control_root.join(HIDDEN_EVENTS))?;
        fs_private::ensure_private_file(&control_root.join(PUBLICATION_LOG))?;
        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        fs_private::write_private(&control_root.join(CONTROL_SECRET), &secret)?;
        Ok(Self {
            control_root,
            secret,
            action_events: Mutex::new(BTreeMap::new()),
        })
    }

    fn read_publications(&self) -> Result<Vec<RelayPublicationV1>, ProcessRelayControlError> {
        let bytes = std::fs::read(self.control_root.join(PUBLICATION_LOG))
            .map_err(|error| control_error("relay_publication_log_read", error))?;
        let complete_len = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        let mut publications = Vec::new();
        for line in bytes[..complete_len].split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            publications.push(
                serde_json::from_slice(line)
                    .map_err(|error| control_error("relay_publication_log_parse", error))?,
            );
        }
        Ok(publications)
    }

    fn publications_since(
        &self,
        before: usize,
    ) -> Result<Vec<RelayPublicationV1>, ProcessRelayControlError> {
        let mut publications = self.read_publications()?;
        if before > publications.len() {
            return Err(control_error(
                "relay_publication_cursor_invalid",
                "the retained relay publication cursor moved backwards",
            ));
        }
        Ok(publications.split_off(before))
    }
}

#[async_trait::async_trait]
impl ProcessRelayControl for FileProcessRelayControl {
    async fn publication_cursor(&self) -> Result<usize, ProcessRelayControlError> {
        Ok(self.read_publications()?.len())
    }

    async fn action_publication_tokens(
        &self,
        before: usize,
        include_welcomes: bool,
    ) -> Result<Vec<String>, ProcessRelayControlError> {
        Ok(self
            .publications_since(before)?
            .into_iter()
            .filter(|event| event.is_addressable(include_welcomes))
            .map(|event| event.event_token)
            .collect())
    }

    fn publication_token(&self, event_id: &str) -> String {
        opaque_event_token(&self.secret, event_id)
    }

    async fn record_action_publications(
        &self,
        action_id: &str,
        before: usize,
        include_welcomes: bool,
        tokens: &BTreeSet<String>,
    ) -> Result<(), ProcessRelayControlError> {
        let mut seen = BTreeSet::new();
        let events = self
            .publications_since(before)?
            .into_iter()
            .filter(|event| {
                event.is_addressable(include_welcomes)
                    && tokens.contains(&event.event_token)
                    && seen.insert(event.event_token.clone())
            })
            .collect::<Vec<_>>();
        self.action_events
            .lock()
            .await
            .insert(action_id.to_owned(), events);
        Ok(())
    }

    async fn set_action_event_visibility(
        &self,
        selector: &ScenarioMessageSelectorV2,
        visible: bool,
    ) -> Result<(), ProcessRelayControlError> {
        if selector.publication.is_some() || selector.sender.is_some() || selector.class.is_some() {
            return Err(control_error(
                "unsupported_relay_selector",
                "the retained relay gate requires an action_id-only selector",
            ));
        }
        let action_id = selector.action_id.as_deref().ok_or_else(|| {
            control_error(
                "missing_relay_action_id",
                "the retained relay gate requires an action id",
            )
        })?;
        let action_events = self.action_events.lock().await;
        let event_token = action_events
            .get(action_id)
            .and_then(|events| events.get(selector.occurrence))
            .map(|event| event.event_token.as_str())
            .ok_or_else(|| {
                control_error(
                    "relay_event_not_found",
                    "no immediately published group-message or Welcome relay event matched the scenario action",
                )
            })?;
        let hidden_path = self.control_root.join(HIDDEN_EVENTS).join(event_token);
        if visible {
            std::fs::remove_file(&hidden_path).map_err(|error| {
                relay_visibility_error(error, io::ErrorKind::NotFound, "relay_event_not_removed")
            })?;
        } else {
            fs_private::create_new_private(&hidden_path).map_err(|error| {
                relay_visibility_error(
                    error,
                    io::ErrorKind::AlreadyExists,
                    "relay_event_already_removed",
                )
            })?;
        }
        Ok(())
    }
}

fn read_control_secret(control_root: &Path) -> io::Result<[u8; 32]> {
    std::fs::read(control_root.join(CONTROL_SECRET))?
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid relay control secret"))
}

fn opaque_event_token(secret: &[u8; 32], event_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(secret);
    digest.update(event_id.as_bytes());
    hex::encode(digest.finalize())
}

fn control_error(code: &str, error: impl std::fmt::Display) -> ProcessRelayControlError {
    ProcessRelayControlError {
        code: code.into(),
        message: error.to_string(),
    }
}

fn relay_visibility_error(
    error: io::Error,
    semantic_kind: io::ErrorKind,
    semantic_code: &str,
) -> ProcessRelayControlError {
    if error.kind() == semantic_kind {
        control_error(semantic_code, error)
    } else {
        control_error("relay_event_visibility_io", error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication(event_token: &str, class: RelayPublicationClassV1) -> RelayPublicationV1 {
        RelayPublicationV1 {
            event_token: event_token.into(),
            class,
        }
    }

    #[tokio::test]
    async fn file_control_maps_complete_publications_and_reverses_visibility() {
        let root = tempfile::tempdir().unwrap();
        let control = FileProcessRelayControl::new(root.path()).unwrap();
        let group_token = opaque_event_token(&control.secret, "group-event");
        let welcome_token = opaque_event_token(&control.secret, "welcome-event");
        let records = [
            publication(&group_token, RelayPublicationClassV1::GroupMessage),
            publication(&welcome_token, RelayPublicationClassV1::Welcome),
        ];
        let mut bytes = records
            .iter()
            .flat_map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .collect::<Vec<_>>();
        bytes.extend_from_slice(br#"{"event_token":"partial""#);
        fs_private::write_private(&root.path().join(PUBLICATION_LOG), &bytes).unwrap();

        assert_eq!(control.publication_cursor().await.unwrap(), 2);
        let tokens = control.action_publication_tokens(0, true).await.unwrap();
        assert_eq!(
            tokens,
            [
                control.publication_token("group-event"),
                control.publication_token("welcome-event"),
            ]
        );
        control
            .record_action_publications("step-1:invite", 0, true, &tokens.into_iter().collect())
            .await
            .unwrap();

        let selector = ScenarioMessageSelectorV2 {
            action_id: Some("step-1:invite".into()),
            occurrence: 1,
            ..Default::default()
        };
        control
            .set_action_event_visibility(&selector, false)
            .await
            .unwrap();
        let marker = root.path().join(HIDDEN_EVENTS).join(welcome_token);
        assert!(marker.is_file());
        control
            .set_action_event_visibility(&selector, true)
            .await
            .unwrap();
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn file_control_attributes_only_the_action_publications() {
        let root = tempfile::tempdir().unwrap();
        let control = FileProcessRelayControl::new(root.path()).unwrap();
        let records = [
            publication(
                &control.publication_token("unrelated-event"),
                RelayPublicationClassV1::GroupMessage,
            ),
            publication(
                &control.publication_token("welcome-event"),
                RelayPublicationClassV1::Welcome,
            ),
            publication(
                &control.publication_token("action-event"),
                RelayPublicationClassV1::GroupMessage,
            ),
        ];
        let bytes = records
            .iter()
            .flat_map(|record| {
                let mut line = serde_json::to_vec(record).unwrap();
                line.push(b'\n');
                line
            })
            .collect::<Vec<_>>();
        fs_private::write_private(&root.path().join(PUBLICATION_LOG), &bytes).unwrap();

        assert_eq!(
            control.action_publication_tokens(1, false).await.unwrap(),
            [control.publication_token("action-event")]
        );
        assert_eq!(
            control
                .action_publication_tokens(4, false)
                .await
                .unwrap_err()
                .code,
            "relay_publication_cursor_invalid"
        );
        let action_token = control.publication_token("action-event");
        control
            .record_action_publications(
                "step-1:send_app_message",
                0,
                false,
                &BTreeSet::from([action_token.clone()]),
            )
            .await
            .unwrap();
        let action_events = control.action_events.lock().await;
        let recorded = action_events["step-1:send_app_message"]
            .iter()
            .map(|event| event.event_token.as_str())
            .collect::<Vec<_>>();
        assert_eq!(recorded, [action_token.as_str()]);
    }

    #[test]
    fn visibility_errors_distinguish_semantic_state_from_io_failures() {
        let semantic = relay_visibility_error(
            io::Error::new(io::ErrorKind::AlreadyExists, "hidden"),
            io::ErrorKind::AlreadyExists,
            "relay_event_already_removed",
        );
        assert_eq!(semantic.code, "relay_event_already_removed");

        let infrastructure = relay_visibility_error(
            io::Error::new(io::ErrorKind::PermissionDenied, "read only"),
            io::ErrorKind::AlreadyExists,
            "relay_event_already_removed",
        );
        assert_eq!(infrastructure.code, "relay_event_visibility_io");
    }
}
