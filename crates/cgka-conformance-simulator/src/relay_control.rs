//! Simulator-owned retained-relay recording and reversible query visibility.
//!
//! The control is deliberately outside production transport code. Scenario
//! adapters use successful relay admission order to associate immediate MLS
//! publications with stable action ids, then temporarily remove selected
//! events from retained queries without tombstoning the underlying event.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use nostr_relay_builder::prelude::{
    Backend, BoxedFuture, DatabaseError, DatabaseEventStatus, Event, EventId, Events, Filter, Kind,
    MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, RelayBuilder, SaveEventStatus,
};
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant, sleep};

use crate::ScenarioMessageSelectorV2;

pub(crate) const RELAY_ACTION_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct RecordingRelayDatabase {
    inner: MemoryDatabase,
    publication_log: Arc<Mutex<Vec<Event>>>,
    hidden_event_ids: Arc<Mutex<BTreeSet<EventId>>>,
}

impl NostrDatabase for RecordingRelayDatabase {
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
                self.publication_log.lock().await.push(event.clone());
            }
            Ok(status)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<DatabaseEventStatus, DatabaseError>> {
        Box::pin(async move {
            if self.hidden_event_ids.lock().await.contains(event_id) {
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
            if self.hidden_event_ids.lock().await.contains(event_id) {
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
            let hidden_event_ids = self.hidden_event_ids.lock().await;
            let mut visible = Events::new(&filter);
            visible.extend(
                events
                    .into_iter()
                    .filter(|event| !hidden_event_ids.contains(&event.id)),
            );
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

#[derive(Clone, Debug)]
pub(crate) struct SequencedRelayEvent {
    publication_sequence: usize,
    event: Event,
}

pub(crate) type RelayActionEvents = BTreeMap<String, Vec<SequencedRelayEvent>>;

#[derive(Clone, Copy, Debug)]
pub(crate) struct RelayControlError {
    pub code: &'static str,
    pub message: &'static str,
}

pub(crate) struct RelayActionExpectation<'a> {
    pub include_welcomes: bool,
    pub expected_publications: usize,
    pub expected_event_ids: &'a [String],
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct RelayControl {
    publication_log: Arc<Mutex<Vec<Event>>>,
    hidden_event_ids: Arc<Mutex<BTreeSet<EventId>>>,
}

impl RelayControl {
    pub fn new() -> Self {
        Self {
            publication_log: Arc::new(Mutex::new(Vec::new())),
            hidden_event_ids: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    pub fn relay_builder(&self) -> RelayBuilder {
        RelayBuilder::default().database(RecordingRelayDatabase {
            inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
                events: true,
                max_events: Some(75_000),
            }),
            publication_log: Arc::clone(&self.publication_log),
            hidden_event_ids: Arc::clone(&self.hidden_event_ids),
        })
    }

    pub async fn publication_cursor(&self) -> usize {
        self.publication_log.lock().await.len()
    }

    pub async fn record_action_events(
        &self,
        action_events: &mut RelayActionEvents,
        action_id: &str,
        before: usize,
        include_welcomes: bool,
    ) -> Result<usize, RelayControlError> {
        let publication_log = self.publication_log.lock().await;
        if before > publication_log.len() {
            return Err(RelayControlError {
                code: "relay_publication_cursor_invalid",
                message: "the retained relay publication cursor moved backwards",
            });
        }
        let mut events = publication_log[before..]
            .iter()
            .enumerate()
            .filter(|(_, event)| {
                event.kind == Kind::MlsGroupMessage
                    || (include_welcomes && event.kind == Kind::GiftWrap)
            })
            .map(|(offset, event)| SequencedRelayEvent {
                publication_sequence: before + offset,
                event: event.clone(),
            })
            .collect::<Vec<_>>();
        events.sort_by_key(|event| event.publication_sequence);
        let recorded = events.len();
        action_events.insert(action_id.to_owned(), events);
        Ok(recorded)
    }

    pub async fn wait_for_action_events(
        &self,
        action_events: &mut RelayActionEvents,
        action_id: &str,
        before: usize,
        expectation: RelayActionExpectation<'_>,
    ) -> Result<(), RelayControlError> {
        let RelayActionExpectation {
            include_welcomes,
            expected_publications,
            expected_event_ids,
            timeout,
        } = expectation;
        if expected_event_ids.len() > expected_publications {
            return Err(RelayControlError {
                code: "relay_action_publication_identity_count_mismatch",
                message: "the action's expected relay event ids do not match its publication count",
            });
        }
        let expected_event_ids = expected_event_ids.iter().cloned().collect::<BTreeSet<_>>();
        let deadline = Instant::now() + timeout;
        loop {
            let recorded = self
                .record_action_events(action_events, action_id, before, include_welcomes)
                .await?;
            let observed_event_ids = action_events
                .get(action_id)
                .into_iter()
                .flatten()
                .map(|event| event.event.id.to_hex())
                .collect::<BTreeSet<_>>();
            if expected_event_ids.len() == expected_publications
                && observed_event_ids
                    .iter()
                    .any(|event_id| !expected_event_ids.contains(event_id))
            {
                return Err(RelayControlError {
                    code: "relay_action_publication_identity_mismatch",
                    message: "a retained relay event admitted after the action cursor was not published by that action",
                });
            }
            if recorded == expected_publications
                && expected_event_ids.is_subset(&observed_event_ids)
            {
                return Ok(());
            }
            if recorded > expected_publications {
                return Err(RelayControlError {
                    code: "relay_action_publication_count_mismatch",
                    message: "the process action published more retained relay events than expected",
                });
            }
            if Instant::now() >= deadline {
                return Err(RelayControlError {
                    code: "relay_action_publication_timeout",
                    message: "the action's expected retained relay publications were not admitted before the deadline",
                });
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn set_action_event_visibility(
        &self,
        action_events: &RelayActionEvents,
        selector: &ScenarioMessageSelectorV2,
        visible: bool,
    ) -> Result<(), RelayControlError> {
        if selector.publication.is_some() || selector.sender.is_some() || selector.class.is_some() {
            return Err(RelayControlError {
                code: "unsupported_relay_selector",
                message: "the retained relay gate requires an action_id-only selector",
            });
        }
        let action_id = selector.action_id.as_deref().ok_or(RelayControlError {
            code: "missing_relay_action_id",
            message: "the retained relay gate requires an action id",
        })?;
        let event_id = action_events
            .get(action_id)
            .and_then(|events| events.get(selector.occurrence))
            .map(|event| event.event.id)
            .ok_or(RelayControlError {
                code: "relay_event_not_found",
                message: "no immediately published group-message or Welcome relay event matched the scenario action; deferred publications are not action-addressable on this adapter",
            })?;
        let mut hidden_event_ids = self.hidden_event_ids.lock().await;
        if visible {
            if !hidden_event_ids.remove(&event_id) {
                return Err(RelayControlError {
                    code: "relay_event_not_removed",
                    message: "the selected event is not currently hidden from the relay",
                });
            }
        } else if !hidden_event_ids.insert(event_id) {
            return Err(RelayControlError {
                code: "relay_event_already_removed",
                message: "the selected event is already hidden from the relay",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_database_preserves_successful_relay_admission_order() {
        let control = RelayControl::new();
        let database = RecordingRelayDatabase {
            inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
                events: true,
                max_events: None,
            }),
            publication_log: Arc::clone(&control.publication_log),
            hidden_event_ids: Arc::clone(&control.hidden_event_ids),
        };
        let keys = nostr::Keys::generate();
        let first = nostr::EventBuilder::new(Kind::MlsGroupMessage, "first admitted")
            .custom_created_at(nostr::Timestamp::from_secs(200))
            .sign_with_keys(&keys)
            .unwrap();
        let second = nostr::EventBuilder::new(Kind::MlsGroupMessage, "second admitted")
            .custom_created_at(nostr::Timestamp::from_secs(100))
            .sign_with_keys(&keys)
            .unwrap();

        assert!(database.save_event(&first).await.unwrap().is_success());
        assert!(database.save_event(&second).await.unwrap().is_success());
        assert!(!database.save_event(&first).await.unwrap().is_success());

        let recorded = control.publication_log.lock().await;
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].id, first.id);
        assert_eq!(recorded[1].id, second.id);
        drop(recorded);

        control.hidden_event_ids.lock().await.insert(first.id);
        assert_eq!(
            database.check_id(&first.id).await.unwrap(),
            DatabaseEventStatus::NotExistent
        );
        assert!(database.event_by_id(&first.id).await.unwrap().is_none());
        let one_group_event = Filter::new().kind(Kind::MlsGroupMessage).limit(1);
        assert_eq!(database.count(one_group_event.clone()).await.unwrap(), 1);
        assert_eq!(
            database
                .query(one_group_event.clone())
                .await
                .unwrap()
                .first()
                .map(|event| event.id),
            Some(second.id),
            "the query limit must be applied after hidden events are filtered"
        );

        assert!(control.hidden_event_ids.lock().await.remove(&first.id));
        assert_eq!(
            database
                .query(one_group_event)
                .await
                .unwrap()
                .first()
                .map(|event| event.id),
            Some(first.id),
            "restoring visibility must expose the original retained event"
        );
    }

    #[tokio::test]
    async fn delayed_welcome_remains_addressable_as_its_actions_explicit_occurrence() {
        let control = RelayControl::new();
        let database = RecordingRelayDatabase {
            inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
                events: true,
                max_events: None,
            }),
            publication_log: Arc::clone(&control.publication_log),
            hidden_event_ids: Arc::clone(&control.hidden_event_ids),
        };
        let keys = nostr::Keys::generate();
        let group_message = nostr::EventBuilder::new(Kind::MlsGroupMessage, "commit")
            .sign_with_keys(&keys)
            .unwrap();
        let welcome = nostr::EventBuilder::new(Kind::GiftWrap, "welcome")
            .sign_with_keys(&keys)
            .unwrap();
        assert!(
            database
                .save_event(&group_message)
                .await
                .unwrap()
                .is_success()
        );

        let mut action_events = RelayActionEvents::new();
        assert_eq!(
            control
                .record_action_events(&mut action_events, "invite", 0, true)
                .await
                .unwrap(),
            1
        );
        let delayed_database = database.clone();
        let delayed_welcome = welcome.clone();
        let delayed_admission = tokio::spawn(async move {
            sleep(Duration::from_millis(25)).await;
            assert!(
                delayed_database
                    .save_event(&delayed_welcome)
                    .await
                    .unwrap()
                    .is_success()
            );
        });
        control
            .wait_for_action_events(
                &mut action_events,
                "invite",
                0,
                RelayActionExpectation {
                    include_welcomes: true,
                    expected_publications: 2,
                    expected_event_ids: &[],
                    timeout: Duration::from_secs(1),
                },
            )
            .await
            .unwrap();
        delayed_admission.await.unwrap();

        let selector = ScenarioMessageSelectorV2 {
            action_id: Some("invite".into()),
            occurrence: 1,
            ..Default::default()
        };
        control
            .set_action_event_visibility(&action_events, &selector, false)
            .await
            .unwrap();
        assert!(database.event_by_id(&welcome.id).await.unwrap().is_none());
        assert!(
            database
                .event_by_id(&group_message.id)
                .await
                .unwrap()
                .is_some()
        );
        control
            .set_action_event_visibility(&action_events, &selector, true)
            .await
            .unwrap();
        assert!(database.event_by_id(&welcome.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn action_identity_rejects_a_delayed_publication_from_an_earlier_action() {
        let control = RelayControl::new();
        let database = RecordingRelayDatabase {
            inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
                events: true,
                max_events: None,
            }),
            publication_log: Arc::clone(&control.publication_log),
            hidden_event_ids: Arc::clone(&control.hidden_event_ids),
        };
        let keys = nostr::Keys::generate();
        let delayed_prior = nostr::EventBuilder::new(Kind::MlsGroupMessage, "prior action")
            .sign_with_keys(&keys)
            .unwrap();
        let current = nostr::EventBuilder::new(Kind::MlsGroupMessage, "current action")
            .sign_with_keys(&keys)
            .unwrap();
        assert!(
            database
                .save_event(&delayed_prior)
                .await
                .unwrap()
                .is_success()
        );

        let error = control
            .wait_for_action_events(
                &mut RelayActionEvents::new(),
                "current",
                0,
                RelayActionExpectation {
                    include_welcomes: false,
                    expected_publications: 1,
                    expected_event_ids: &[current.id.to_hex()],
                    timeout: Duration::from_secs(1),
                },
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, "relay_action_publication_identity_mismatch");
    }
}
