//! Carrier reservation and immutable actual accepted-publication time cross
//! the engine and app owners. Heartbeats reuse the existing D35 activity row;
//! no per-message source observation or local ordering clock is maintained.
use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteAppStorage, SqliteResultExt, u64_to_i64};
use cgka_traits::storage::{OutboundFanoutStorage, StorageError, StorageProvider, StorageResult};
use cgka_traits::{GroupId, MessageId, PublicationObservation};
use rusqlite::params;

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
                u64_to_i64(now_ms)?;
                let observation = PublicationObservation { at_ms: now_ms };
                next.observe_first_acceptance(observation)
                    .map_err(|_| StorageError::Backend("invalid publication observation".into()))?;
            }
            store.put_outbound_fanout(&next)
        })?;
        *fanout = next;
        Ok(())
    }
}

impl SqliteAppStorage {
    /// Only the exact prepared carrier may become the latest successfully
    /// published generation. Duplicate projection never retimes it; a late
    /// callback for an older carrier cannot replace its successor or resurrect
    /// retired metadata.
    pub fn record_sibling_welcome_publication(
        &self,
        welcome_id: &[u8],
        carrier: &[u8],
        observation: PublicationObservation,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE sibling_welcome_resends SET published_at_ms = ?3, carrier = ?2
             WHERE welcome_id = ?1 AND prepared_carrier = ?2
               AND (published_at_ms IS NULL OR carrier != ?2)",
                params![welcome_id, carrier, u64_to_i64(observation.at_ms)?],
            )
            .storage()?;
        Ok(())
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

    fn accept(store: &SqliteAccountStorage, id: u8, at_ms: u64) -> PublicationObservation {
        let mut outgoing = fanout(id);
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_attempt_started_at(0, 5).unwrap();
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_target_accepted(0).unwrap();
        store
            .put_observed_outbound_fanout(&mut outgoing, at_ms)
            .unwrap();
        outgoing.first_acceptance_observation().unwrap()
    }

    #[test]
    fn repair_uses_current_incarnation_heartbeat_after_latest_accepted_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("heartbeat-repair.db");
        let key = crate::SqlCipherKey::raw([31; 32]);
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let app = store.app_storage();
        let slot = [3; 32];
        let slot_hex = hex::encode(slot);
        let prepare = |carrier, created| {
            app.prepare_sibling_welcome_resend(
                b"welcome",
                b"chat",
                gid(1).as_slice(),
                &slot,
                carrier,
                created,
            )
            .unwrap()
        };
        assert!(prepare(b"first", 1));
        app.track_device_activity(&[(slot_hex.clone(), 7)], 900)
            .unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "no actual accepted publication"
        );
        app.record_sibling_welcome_publication(b"welcome", b"first", accept(&store, 1, 1000))
            .unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "first sighting never counts as a heartbeat"
        );
        app.note_device_active(&slot_hex, 7, 600, 900).unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "599 seconds is not enough"
        );
        app.note_device_active(&slot_hex, 7, 601, 900).unwrap();
        assert!(
            app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "exactly 600 seconds qualifies"
        );
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 8).unwrap(),
            "a relink cannot inherit its predecessor's heartbeat"
        );
        assert!(!prepare(b"first", 1), "published identity cannot be reused");
        assert!(prepare(b"second", 2));
        assert!(
            app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "unaccepted preparation preserves prior repair debt"
        );
        assert_eq!(
            app.sibling_welcome_carrier_reservation(b"welcome").unwrap(),
            Some((b"second".to_vec(), 2))
        );
        app.record_sibling_welcome_publication(b"welcome", b"second", accept(&store, 2, 2001))
            .unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "latest successful carrier resets the heartbeat threshold"
        );
        app.record_sibling_welcome_publication(
            b"welcome",
            b"first",
            PublicationObservation { at_ms: 0 },
        )
        .unwrap();
        app.record_sibling_welcome_publication(
            b"welcome",
            b"second",
            PublicationObservation { at_ms: 0 },
        )
        .unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "late old and duplicate callbacks cannot retime the generation"
        );
        app.note_device_active(&slot_hex, 7, 602, 900).unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap(),
            "fractional publication time cannot round the wait down"
        );
        app.note_device_active(&slot_hex, 7, 603, 900).unwrap();
        assert!(app.sibling_welcome_resend_is_due(b"welcome", 7).unwrap());
        store.put_processed_transport_id(&gid(1), &mid(9)).unwrap();
        store
            .create_group_snapshot(&gid(1), "before-heartbeat")
            .unwrap();
        app.track_device_activity(&[(slot_hex.clone(), 8)], 900)
            .unwrap();
        store
            .rollback_group_to_snapshot(&gid(1), "before-heartbeat")
            .unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"welcome", 8).unwrap(),
            "snapshot rollback does not fabricate an incarnation heartbeat"
        );
        app.note_device_active(&slot_hex, 8, 603, 900).unwrap();
        store.close().unwrap();
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(
            reopened.has_processed_transport_id(&mid(9)).unwrap(),
            "permanent wrapper admission survives restart"
        );
        let app = reopened.app_storage();
        assert!(app.sibling_welcome_resend_is_due(b"welcome", 8).unwrap());
        assert_eq!(
            app.sibling_welcome_carrier_reservation(b"welcome").unwrap(),
            None
        );
        assert_eq!(
            app.sibling_welcome_resend_batch(None, 32).unwrap(),
            vec![(b"welcome".to_vec(), b"second".to_vec())]
        );
        app.delete_sibling_welcome_resend(b"welcome").unwrap();
        app.record_sibling_welcome_publication(
            b"welcome",
            b"second",
            PublicationObservation { at_ms: 1 },
        )
        .unwrap();
        assert!(
            app.sibling_welcome_resend_batch(None, 32)
                .unwrap()
                .is_empty(),
            "late projection cannot resurrect retired work"
        );
        reopened.close().unwrap();
    }

    #[test]
    fn first_publication_time_commits_with_receipt_and_legacy_acceptance_stays_unknown() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut outgoing = fanout(1);
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_attempt_started_at(0, 5).unwrap();
        store.put_outbound_fanout(&outgoing).unwrap();
        outgoing.mark_target_accepted(0).unwrap();
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE ON cgka_outbound_fanout BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END;").unwrap();
        assert!(
            matches!(store.put_observed_outbound_fanout(&mut outgoing,1000),Err(StorageError::Backend(message)) if message.contains("injected receipt failure"))
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
            .put_observed_outbound_fanout(&mut outgoing, 1001)
            .unwrap();
        store
            .put_observed_outbound_fanout(&mut outgoing, 2000)
            .unwrap();
        assert_eq!(
            outgoing.first_acceptance_observation(),
            Some(PublicationObservation { at_ms: 1001 })
        );
        // The adopted timestamp survives reading an older serialized fanout
        // whose observation also carried the now-retired scalar order.
        let mut legacy_shape = serde_json::to_value(&outgoing).unwrap();
        legacy_shape["first_acceptance_observation"]["order"] = 91.into();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE cgka_outbound_fanout SET record=?2 WHERE message_id=?1",
                params![
                    mid(1).as_slice(),
                    serde_json::to_vec(&legacy_shape).unwrap()
                ],
            )
            .unwrap();
        assert_eq!(
            store
                .outbound_fanout(&mid(1))
                .unwrap()
                .unwrap()
                .first_acceptance_observation(),
            Some(PublicationObservation { at_ms: 1001 })
        );
        let mut legacy = fanout(2);
        legacy.mark_attempt_started_at(0, 5).unwrap();
        legacy.mark_target_accepted(0).unwrap();
        store.put_outbound_fanout(&legacy).unwrap();
        store
            .put_observed_outbound_fanout(&mut legacy, 3000)
            .unwrap();
        assert_eq!(legacy.first_acceptance_observation(), None);
        let app = store.app_storage();
        app.prepare_sibling_welcome_resend(
            b"legacy",
            b"chat",
            gid(1).as_slice(),
            &[3; 32],
            b"carrier",
            1,
        )
        .unwrap();
        app.note_device_active(&hex::encode([3; 32]), 7, 9000, 9000)
            .unwrap();
        assert!(
            !app.sibling_welcome_resend_is_due(b"legacy", 7).unwrap(),
            "unknown legacy publication time never repairs"
        );
    }
}
