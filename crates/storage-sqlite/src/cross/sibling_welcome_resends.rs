//! Local publication and authenticated device-group activity share one durable
//! order. These observations live outside protocol snapshots: a rewind cannot
//! make a previously qualified message new in a later delivery generation.
use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{OutboundFanoutStorage, StorageError, StorageProvider, StorageResult};
use cgka_traits::{EpochId, GroupId, MessageId, PublicationObservation};
use rusqlite::{OptionalExtension, params};

pub(crate) fn next_order(conn: &rusqlite::Connection) -> StorageResult<u64> {
    let order: Option<i64> = conn
        .query_row_cached(
            "UPDATE local_observation_clock SET last_order = last_order + 1
             WHERE singleton = 1 AND last_order < 9223372036854775807
             RETURNING last_order",
            [],
            |row| row.get(0),
        )
        .optional()
        .storage()?;
    i64_to_u64(
        order.ok_or_else(|| StorageError::Backend("local observation order unavailable".into()))?,
    )
}

pub(crate) fn delete_group_resends(
    conn: &rusqlite::Connection,
    group_id: &GroupId,
) -> StorageResult<()> {
    conn.execute_cached(
        "DELETE FROM sibling_welcome_resends WHERE chat_id = ?1 OR device_group_id = ?1",
        params![group_id.as_slice()],
    )
    .storage()?;
    Ok(())
}

impl SqliteAccountStorage {
    /// Reserve the actual generated carrier and attach its engine association
    /// on this same connection. The readiness callback is synchronous engine
    /// work, with no external side effect; failure rolls back both owners.
    pub fn reserve_sibling_welcome_carrier<E>(
        &self,
        id: &MessageId,
        device_group: &GroupId,
        target: &[u8; 32],
        carrier: &[u8],
        created_at: u64,
        attach: impl FnOnce() -> Result<bool, E>,
    ) -> Result<bool, E>
    where
        E: From<StorageError>,
    {
        use cgka_traits::MessageStorage as _;
        self.with_transaction(|store| {
            let record = store.get_message(id)?;
            if !store.app_storage().prepare_sibling_welcome_resend(
                id.as_slice(),
                record.group_id.as_slice(),
                device_group.as_slice(),
                target,
                carrier,
                created_at,
            )? {
                return Ok(false);
            }
            if !attach()? {
                return Err(
                    StorageError::Backend("sibling Welcome readiness changed".into()).into(),
                );
            }
            Ok(true)
        })
    }

    /// Persist a receipt transition and its first local acceptance observation
    /// together. An already accepted legacy row never gains invented timing.
    pub fn put_observed_outbound_fanout(
        &self,
        fanout: &mut cgka_traits::OutboundFanout,
        now_ms: u64,
    ) -> StorageResult<()> {
        let mut next = fanout.clone();
        self.with_transaction(|store| {
            if next.first_acceptance_observation().is_none()
                && next.outcome().accepted_targets > 0
                && store
                    .outbound_fanout(next.message_id())?
                    .is_some_and(|prior| prior.outcome().accepted_targets == 0)
            {
                let conn = store.lock()?;
                u64_to_i64(now_ms)?;
                let observation = PublicationObservation {
                    order: next_order(&conn)?,
                    at_ms: now_ms,
                };
                next.observe_first_acceptance(observation)
                    .map_err(|_| StorageError::Backend("invalid publication observation".into()))?;
            }
            store.put_outbound_fanout(&next)
        })?;
        *fanout = next;
        Ok(())
    }
}

const SIBLING_WELCOME_RESEND_WAIT_MS: u64 = 600_000;

impl SqliteAppStorage {
    /// Linearization point for the first durable qualified observation of this
    /// authenticated message. The caller has attributed its sending leaf to a
    /// current trusted-roster device. Replayed content and rewrapped duplicates
    /// reuse the earliest existing qualification outside all MLS snapshots.
    pub fn observe_sibling_welcome_activity(
        &self,
        group_id: &GroupId,
        content_id: &MessageId,
        source_epoch: EpochId,
        slot: &[u8; 32],
        now_ms: u64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let floor = conn
                .query_row_cached(
                    "SELECT sibling_resend_after_epoch FROM cgka_groups WHERE id = ?1",
                    params![group_id.as_slice()],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional()
                .storage()?
                .flatten();
            let Some(floor) = floor else {
                return Ok(());
            };
            if !i64::try_from(source_epoch.0).is_ok_and(|epoch| epoch > floor) {
                return Ok(());
            }
            let existing = conn
                .query_row_cached(
                    "SELECT qualified_order FROM cgka_processed_transport_ids
                 WHERE group_id = ?1 AND content_id = ?2 AND qualified_order IS NOT NULL
                 ORDER BY qualified_order LIMIT 1",
                    params![group_id.as_slice(), content_id.as_slice()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .storage()?;
            if existing.is_some() {
                return Ok(());
            }
            let wrapper = conn
                .query_row_cached(
                    "SELECT id FROM cgka_processed_transport_ids
                 WHERE group_id = ?1 AND content_id = ?2 ORDER BY id LIMIT 1",
                    params![group_id.as_slice(), content_id.as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
                .storage()?;
            let Some(wrapper) = wrapper else {
                return Ok(());
            };
            let at_ms = u64_to_i64(now_ms)?;
            let due = u64_to_i64(
                now_ms
                    .checked_add(SIBLING_WELCOME_RESEND_WAIT_MS)
                    .ok_or_else(|| {
                        StorageError::Backend("sibling Welcome deadline overflow".into())
                    })?,
            )?;
            let order = u64_to_i64(next_order(&conn)?)?;
            conn.execute_cached(
                "UPDATE cgka_processed_transport_ids SET qualified_order = ?2,
                     qualified_at_ms = ?3, qualified_slot = ?4 WHERE id = ?1",
                params![wrapper, order, at_ms, slot],
            )
            .storage()?;
            conn.execute_cached(
                "UPDATE sibling_welcome_resends SET activity_id = ?3,
                     activity_order = ?4, activity_at_ms = ?5, due_at_ms = ?6
                 WHERE device_group_id = ?1 AND target_slot = ?2
                     AND publication_order < ?4 AND activity_id IS NULL",
                params![
                    group_id.as_slice(),
                    slot,
                    content_id.as_slice(),
                    order,
                    at_ms,
                    due
                ],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Persist a successful generation using only the fanout's immutable first
    /// acceptance observation. Recover the first qualifying activity even if
    /// publication projection was delayed behind activity projection/restart.
    pub fn record_sibling_welcome_publication(
        &self,
        welcome_id: &[u8],
        carrier: &[u8],
        observation: PublicationObservation,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "UPDATE sibling_welcome_resends SET publication_order = ?2,
                    published_at_ms = ?3, carrier = ?4, activity_id = NULL, activity_order = NULL,
                    activity_at_ms = NULL, due_at_ms = NULL
                 WHERE welcome_id = ?1 AND (publication_order IS NULL OR publication_order < ?2)",
                params![
                    welcome_id,
                    u64_to_i64(observation.order)?,
                    u64_to_i64(observation.at_ms)?,
                    carrier
                ],
            )
            .storage()?;
            let first: Option<(Vec<u8>, i64, i64)> = conn
                .query_row_cached(
                    "SELECT p.content_id, p.qualified_order, p.qualified_at_ms
                 FROM sibling_welcome_resends AS r
                 JOIN cgka_processed_transport_ids AS p
                   ON p.group_id = r.device_group_id AND p.qualified_slot = r.target_slot
                 WHERE r.welcome_id = ?1 AND r.activity_id IS NULL
                   AND r.publication_order = ?2 AND p.qualified_order > r.publication_order
                 ORDER BY p.qualified_order LIMIT 1",
                    params![welcome_id, u64_to_i64(observation.order)?],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .storage()?;
            if let Some((id, order, at_ms)) = first {
                let due = at_ms
                    .checked_add(u64_to_i64(SIBLING_WELCOME_RESEND_WAIT_MS)?)
                    .ok_or_else(|| {
                        StorageError::Backend("sibling Welcome deadline overflow".into())
                    })?;
                conn.execute_cached(
                    "UPDATE sibling_welcome_resends SET activity_id = ?2,
                        activity_order = ?3, activity_at_ms = ?4, due_at_ms = ?5
                     WHERE welcome_id = ?1 AND publication_order = ?6 AND activity_id IS NULL",
                    params![
                        welcome_id,
                        id,
                        order,
                        at_ms,
                        due,
                        u64_to_i64(observation.order)?
                    ],
                )
                .storage()?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::test_support::{gid, mid, sample_group};
    use cgka_traits::storage::{GroupStorage, MessageStorage};
    use cgka_traits::{
        FanoutTargetStatus, MemberId, OutboundFanout, Timestamp, TransportEndpoint,
        TransportEnvelope, TransportMessage, TransportPublishRequest, TransportPublishTarget,
        TransportSource,
    };

    fn fanout(id: u8) -> OutboundFanout {
        OutboundFanout::stage(
            TransportPublishRequest {
                account_id: MemberId::new(vec![1; 32]),
                message: TransportMessage {
                    id: mid(id),
                    payload: vec![id],
                    timestamp: Timestamp(1),
                    causal_deps: vec![],
                    source: TransportSource("test".into()),
                    envelope: TransportEnvelope::GroupMessage {
                        transport_group_id: vec![7; 32],
                    },
                },
                target: TransportPublishTarget::Group {
                    group_id: gid(1),
                    transport_group_id: vec![7; 32],
                    endpoints: vec![TransportEndpoint("https://one.example".into())],
                },
                required_acks: 1,
            },
            None,
            None,
            5,
        )
        .unwrap()
    }

    pub(super) fn accept(
        store: &SqliteAccountStorage,
        id: u8,
        now_ms: u64,
    ) -> PublicationObservation {
        let mut outgoing = fanout(id);
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_attempt_started_at(0, 5).unwrap();
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_target_accepted(0).unwrap();
        store
            .put_observed_outbound_fanout(&mut outgoing, now_ms)
            .unwrap();
        outgoing.first_acceptance_observation().unwrap()
    }

    #[test]
    fn sibling_resend_observations_freeze_first_activity_across_generations_and_snapshot_replay() {
        // Contract: a qualified content id is immutable across wrapper replay,
        // source-row rewinds, and later successful Welcome generations. This
        // is the cheapest owner of the persisted order/deadline transaction.
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let app = store.app_storage();
        let slot = [3; 32];
        app.prepare_sibling_welcome_resend(
            b"welcome",
            b"chat",
            gid(1).as_slice(),
            &slot,
            b"carrier1",
            1,
        )
        .unwrap();
        store
            .create_group_snapshot(&gid(1), "before-observation")
            .unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(1), &mid(11))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(11), EpochId(0), &slot, 100)
            .unwrap();
        assert_eq!(
            app.sibling_welcome_carrier_reservation(b"welcome").unwrap(),
            Some((b"carrier1".to_vec(), 1))
        );
        let first = accept(&store, 2, 100);
        app.record_sibling_welcome_publication(b"welcome", b"carrier1", first)
            .unwrap();
        assert_eq!(
            app.sibling_welcome_carrier_reservation(b"welcome").unwrap(),
            None,
            "a successful generation cannot be retried as an unexposed reservation"
        );
        assert!(
            !app.prepare_sibling_welcome_resend(
                b"welcome",
                b"chat",
                gid(1).as_slice(),
                &slot,
                b"carrier1",
                1,
            )
            .unwrap(),
            "a published carrier cannot be prepared again in the same second"
        );
        assert!(
            app.due_sibling_welcome_resends(u64::from(1_000_000u32))
                .unwrap()
                .is_empty(),
            "pre-publication activity cannot arm"
        );
        // Same millisecond and a backward wall-clock move retain honest local
        // order; an activity qualified after publication still arms exactly.
        store
            .put_processed_transport_content(&gid(1), &mid(3), &mid(12))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(12), EpochId(0), &slot, 99)
            .unwrap();
        assert!(app.due_sibling_welcome_resends(600_098).unwrap().is_empty());
        assert_eq!(
            app.due_sibling_welcome_resends(600_099).unwrap(),
            vec![(b"welcome".to_vec(), b"carrier1".to_vec())]
        );
        store
            .put_processed_transport_content(&gid(1), &mid(4), &mid(13))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(13), EpochId(0), &slot, 200)
            .unwrap();
        app.record_sibling_welcome_publication(b"welcome", b"carrier1", first)
            .unwrap();
        assert_eq!(
            app.due_sibling_welcome_resends(600_099).unwrap().len(),
            1,
            "later traffic/projection cannot slide first deadline"
        );
        app.prepare_sibling_welcome_resend(
            b"welcome",
            b"chat",
            gid(1).as_slice(),
            &slot,
            b"carrier2",
            2,
        )
        .unwrap();
        assert!(
            app.prepare_sibling_welcome_resend(
                b"welcome",
                b"chat",
                gid(1).as_slice(),
                &slot,
                b"carrier2",
                2,
            )
            .unwrap(),
            "an unexposed exact retry reuses its reservation"
        );
        let second = accept(&store, 5, 300);
        // Activity projects before the successful publication effect. The
        // publication owner must recover it by its immutable durable order.
        store
            .put_processed_transport_content(&gid(1), &mid(6), &mid(14))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(14), EpochId(0), &slot, 301)
            .unwrap();
        app.record_sibling_welcome_publication(b"welcome", b"carrier2", second)
            .unwrap();
        assert!(app.due_sibling_welcome_resends(600_300).unwrap().is_empty());
        assert_eq!(app.due_sibling_welcome_resends(600_301).unwrap().len(), 1);
        assert!(
            !app.prepare_sibling_welcome_resend(
                b"welcome",
                b"chat",
                gid(1).as_slice(),
                &slot,
                b"carrier1",
                1,
            )
            .unwrap(),
            "clock rollback cannot revive an older successful carrier"
        );
        app.prepare_sibling_welcome_resend(
            b"welcome",
            b"chat",
            gid(1).as_slice(),
            &slot,
            b"carrier3",
            3,
        )
        .unwrap();
        let third = accept(&store, 7, 400);
        app.record_sibling_welcome_publication(b"welcome", b"carrier3", third)
            .unwrap();
        store
            .rollback_group_to_snapshot(&gid(1), "before-observation")
            .unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(8), &mid(14))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(14), EpochId(0), &slot, 500)
            .unwrap();
        assert!(
            app.due_sibling_welcome_resends(1_000_000)
                .unwrap()
                .is_empty(),
            "old qualified content cannot arm another generation after rewind/rewrap"
        );
        store
            .put_processed_transport_content(&gid(1), &mid(9), &mid(15))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(15), EpochId(0), &slot, 501)
            .unwrap();
        assert_eq!(app.due_sibling_welcome_resends(600_501).unwrap().len(), 1);
        store.delete_group(&gid(1)).unwrap();
        assert!(
            app.due_sibling_welcome_resends(1_000_000)
                .unwrap()
                .is_empty()
        );
        assert!(!store.has_processed_transport_id(&mid(9)).unwrap());
    }

    #[test]
    fn first_publication_observation_commits_with_receipt_and_legacy_acceptance_stays_unknown() {
        // Contract: failed durable receipt writes cannot consume a publication
        // order or leak an observation; legacy accepted rows stay unknown.
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut outgoing = fanout(1);
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_attempt_started_at(0, 5).unwrap();
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_target_accepted(0).unwrap();
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE ON cgka_outbound_fanout BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;").unwrap();
        let error = store
            .put_observed_outbound_fanout(&mut outgoing, 1_000)
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Backend(ref message) if message.contains("injected receipt failure"))
        );
        assert_eq!(outgoing.first_acceptance_observation(), None);
        assert_eq!(
            store
                .outbound_fanout(&mid(1))
                .unwrap()
                .unwrap()
                .target_status(0),
            Some(FanoutTargetStatus::Attempting)
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_receipt")
            .unwrap();
        store
            .put_observed_outbound_fanout(&mut outgoing, 1_001)
            .unwrap();
        assert_eq!(
            outgoing.first_acceptance_observation(),
            Some(PublicationObservation {
                order: 1,
                at_ms: 1_001
            })
        );
        store
            .put_observed_outbound_fanout(&mut outgoing, 2_000)
            .unwrap();
        assert_eq!(
            outgoing.first_acceptance_observation(),
            Some(PublicationObservation {
                order: 1,
                at_ms: 1_001
            })
        );
        let mut legacy = fanout(2);
        legacy.mark_attempt_started_at(0, 5).unwrap();
        legacy.mark_target_accepted(0).unwrap();
        store.put_outbound_fanout(&legacy).unwrap();
        store
            .put_observed_outbound_fanout(&mut legacy, 3_000)
            .unwrap();
        assert_eq!(legacy.first_acceptance_observation(), None);
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE local_observation_clock SET last_order = 9223372036854775807",
                [],
            )
            .unwrap();
        let mut overflow = fanout(3);
        store.put_outbound_fanout(&overflow).unwrap();
        overflow.mark_attempt_started_at(0, 5).unwrap();
        store.put_outbound_fanout(&overflow).unwrap();
        overflow.mark_target_accepted(0).unwrap();
        assert!(
            matches!(store.put_observed_outbound_fanout(&mut overflow, 4_000),
            Err(StorageError::Backend(ref message)) if message == "local observation order unavailable")
        );
        assert_eq!(overflow.first_acceptance_observation(), None);
        assert_eq!(
            store
                .outbound_fanout(&mid(3))
                .unwrap()
                .unwrap()
                .target_status(0),
            Some(FanoutTargetStatus::Attempting)
        );
    }
}

#[cfg(test)]
mod cutover_tests {
    use super::*;
    use crate::base::test_support::{gid, mid, sample_group};
    use cgka_traits::storage::{GroupStorage, MessageStorage};

    #[test]
    fn sibling_resend_cutover_never_upgrades_pre_floor_content_after_rewrap_or_rewind() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 7, 0)).unwrap();
        // The migration owner separately proves this existing-group floor is
        // captured at upgrade. Here exercise its admission rule through real
        // storage operations, including a legacy wrapper whose binding arrives late.
        store
            .lock()
            .unwrap()
            .execute("UPDATE cgka_groups SET sibling_resend_after_epoch = 7", [])
            .unwrap();
        store.create_group_snapshot(&gid(1), "floor").unwrap();
        let app = store.app_storage();
        app.prepare_sibling_welcome_resend(
            b"welcome",
            b"chat",
            gid(1).as_slice(),
            &[3; 32],
            b"carrier",
            1,
        )
        .unwrap();
        let observation = super::tests::accept(&store, 20, 100);
        app.record_sibling_welcome_publication(b"welcome", b"carrier", observation)
            .unwrap();
        store.put_processed_transport_id(&gid(1), &mid(1)).unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(1), &mid(11))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(11), EpochId(7), &[3; 32], 101)
            .unwrap();
        store.put_group(&sample_group(gid(1), 8, 0)).unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(2), &mid(11))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(11), EpochId(7), &[3; 32], 102)
            .unwrap();
        store.rollback_group_to_snapshot(&gid(1), "floor").unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(3), &mid(11))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(11), EpochId(7), &[3; 32], 103)
            .unwrap();
        assert!(
            app.due_sibling_welcome_resends(1_000_000)
                .unwrap()
                .is_empty()
        );
        store.put_group(&sample_group(gid(1), 8, 0)).unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(4), &mid(12))
            .unwrap();
        app.observe_sibling_welcome_activity(&gid(1), &mid(12), EpochId(8), &[3; 32], 104)
            .unwrap();
        assert_eq!(app.due_sibling_welcome_resends(600_104).unwrap().len(), 1);
    }
}
