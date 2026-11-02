//! Local publication and authenticated device-group activity share one durable
//! order. These observations live outside protocol snapshots: a rewind cannot
//! make a previously qualified message new in a later delivery generation.
use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{OutboundFanoutStorage, StorageError, StorageProvider, StorageResult};
use cgka_traits::{GroupId, MessageId, PublicationObservation};
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

pub(crate) fn decode_source_proof(
    bytes: &[u8],
) -> StorageResult<cgka_traits::storage::AuthenticatedDeviceGroupSource> {
    let (version, source): (u8, cgka_traits::storage::AuthenticatedDeviceGroupSource) =
        crate::deserialize(bytes)?;
    if version != 1 {
        return Err(StorageError::Serialization(
            "unsupported native source proof version".into(),
        ));
    }
    Ok(source)
}

/// Native acceptance and first local source observation are one transaction.
/// Only an existing admitted wrapper/content association can own this fact.
/// The lifetime ledger survives snapshots; later exact-source proof fills an
/// unavailable leaf without changing its first order/time.
pub(crate) fn observe_native_source(
    store: &SqliteAccountStorage,
    group_id: &GroupId,
    content_id: &MessageId,
    source: &cgka_traits::storage::AuthenticatedDeviceGroupSource,
    now_ms: u64,
) -> StorageResult<()> {
    // Every retained observation must support its fixed deadline without
    // SQLite integer promotion or a wrapped timestamp.
    u64_to_i64(
        now_ms
            .checked_add(SIBLING_WELCOME_RESEND_WAIT_MS)
            .ok_or_else(|| StorageError::Backend("sibling Welcome deadline overflow".into()))?,
    )?;
    store.with_transaction(|store| {
        let conn = store.lock()?;
        let current: Option<(Vec<u8>, Option<Vec<u8>>)> = conn.query_row_cached(
            "SELECT id, source_proof FROM cgka_processed_transport_ids WHERE group_id = ?1 AND content_id = ?2
             ORDER BY source_observed_order IS NULL, source_observed_order, id LIMIT 1",
            params![group_id.as_slice(), content_id.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().storage()?;
        let Some((wrapper, prior)) = current else { return Ok(()); };
        if let Some(prior) = prior {
            let old = decode_source_proof(&prior)?;
            if old.leaf.is_none() && source.leaf.is_some() && old.epoch == source.epoch && old.sender == source.sender
                && old.leaf_index == source.leaf_index && old.application_id == source.application_id {
                // Exact ciphertext was reauthenticated under its actual source
                // epoch. Upgrade its provisional identity, never its stamp.
                conn.execute_cached(
                    "UPDATE cgka_processed_transport_ids SET source_identity = ?3 WHERE group_id = ?1 AND source_identity = ?2",
                    params![group_id.as_slice(), old.identity.as_slice(), source.identity.as_slice()],
                ).storage()?;
                conn.execute_cached(
                    "UPDATE cgka_processed_transport_ids SET source_proof = ?2, source_has_leaf = 1, source_slot_hint = ?3 WHERE id = ?1",
                    params![wrapper, crate::serialize(&(1u8, source))?, source.leaf.as_ref().and_then(|leaf| leaf.slot_hint.as_ref().map(|slot| slot.as_slice()))],
                ).storage()?;
                // A later known-key alias was held while this source was
                // unavailable. Only matching authenticated identity coalesces.
                conn.execute_cached(
                    "UPDATE cgka_processed_transport_ids SET source_resolved = 1
                     WHERE group_id = ?1 AND source_identity = ?2 AND source_proof IS NOT NULL
                       AND id != (SELECT id FROM cgka_processed_transport_ids WHERE group_id = ?1 AND source_identity = ?2 AND source_observed_order IS NOT NULL ORDER BY source_observed_order LIMIT 1)",
                    params![group_id.as_slice(), source.identity.as_slice()],
                ).storage()?;
            }
        }
        conn.execute_cached("UPDATE cgka_processed_transport_ids SET source_identity = ?2, source_application_id = ?3 WHERE id = ?1 AND source_identity IS NULL",
            params![wrapper, source.identity.as_slice(), source.application_id.as_ref().map(|id| id.as_slice())]).storage()?;
        let (owner, bytes): (Vec<u8>, Option<Vec<u8>>) = conn.query_row_cached(
            "SELECT id, source_proof FROM cgka_processed_transport_ids
             WHERE group_id = ?1 AND source_identity = ?2
             ORDER BY source_observed_order IS NULL, source_observed_order, id LIMIT 1",
            params![group_id.as_slice(), source.identity.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).storage()?;
        let wrapper = owner;
        if let Some(bytes) = bytes {
            let old = decode_source_proof(&bytes)?;
            if old.epoch != source.epoch || old.sender != source.sender || old.leaf_index != source.leaf_index
                || (old.leaf.is_some() && source.leaf.is_some() && old.leaf != source.leaf) {
                // Another accepted encryption of the same application event
                // cannot replace the earliest source or make it fresh. Its
                // different source cannot fill an older partial proof either.
                return Ok(());
            }
            if old.leaf.is_none() && source.leaf.is_some() {
                conn.execute_cached(
                    "UPDATE cgka_processed_transport_ids SET source_proof = ?2, source_has_leaf = 1, source_slot_hint = ?3 WHERE id = ?1",
                    params![wrapper, crate::serialize(&(1u8, source))?, source.leaf.as_ref().and_then(|leaf| leaf.slot_hint.as_ref().map(|slot| slot.as_slice()))],
                ).storage()?;
            }
            return Ok(());
        }
        conn.execute_cached(
            "UPDATE cgka_processed_transport_ids SET source_proof = ?2, source_has_leaf = ?3,
                 source_observed_order = ?4, source_observed_at_ms = ?5, source_resolved = 0, source_epoch = ?6, source_slot_hint = ?7 WHERE id = ?1",
            params![wrapper, crate::serialize(&(1u8, source))?, source.leaf.is_some(),
                u64_to_i64(next_order(&conn)?)?, u64_to_i64(now_ms)?, u64_to_i64(source.epoch.0)?, source.leaf.as_ref().and_then(|leaf| leaf.slot_hint.as_ref().map(|slot| slot.as_slice()))],
        ).storage()?;
        Ok(())
    })
}

const SIBLING_WELCOME_RESEND_WAIT_MS: u64 = 600_000;

impl SqliteAppStorage {
    /// Attribute a native accepted observation to a current trusted-roster
    /// device. This transaction never allocates a timestamp or order: delayed
    /// proof/projection cannot turn pre-publication content into fresh activity.
    pub fn qualify_sibling_welcome_activity(
        &self,
        group_id: &GroupId,
        content_id: &MessageId,
        slot: &[u8; 32],
        verified_tag_key: &[u8],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let wrapper: Option<Vec<u8>> = conn.query_row_cached(
                "SELECT id FROM cgka_processed_transport_ids WHERE group_id = ?1 AND content_id = ?2
                 AND source_resolved = 0 AND source_has_leaf = 1 ORDER BY source_observed_order LIMIT 1",
                params![group_id.as_slice(), content_id.as_slice()], |row| row.get(0),
            ).optional().storage()?;
            let Some(wrapper) = wrapper else { return Ok(()); };
            conn.execute_cached(
                "UPDATE cgka_processed_transport_ids SET qualified_slot = ?2, qualified_tag_key = ?3, source_resolved = 1 WHERE id = ?1",
                params![wrapper, slot, verified_tag_key],
            ).storage()?;
            // read_entry verified this exact roster key's signature over the
            // source leaf key and slot. Different MLS keys can therefore be
            // aliases of one device principal; another roster key/slot cannot.
            conn.execute_cached(
                "UPDATE cgka_processed_transport_ids SET source_resolved = 2
                 WHERE group_id = ?1 AND qualified_slot = ?2 AND qualified_tag_key = ?3
                   AND source_application_id = (SELECT source_application_id FROM cgka_processed_transport_ids WHERE id = ?4)
                   AND id != (SELECT id FROM cgka_processed_transport_ids WHERE group_id = ?1 AND qualified_slot = ?2 AND qualified_tag_key = ?3
                     AND source_application_id = (SELECT source_application_id FROM cgka_processed_transport_ids WHERE id = ?4)
                     ORDER BY source_observed_order LIMIT 1)",
                params![group_id.as_slice(), slot, verified_tag_key, wrapper],
            ).storage()?;
            // Earliest authenticated source observation wins even if its
            // proof/attribution was delayed. This can tighten, never slide a
            // deadline later. A coalesced alias cannot remain timing evidence.
            conn.execute_cached(
                "UPDATE sibling_welcome_resends AS r SET (activity_id, activity_order, activity_at_ms, due_at_ms) =
                   (SELECT p.content_id, p.source_observed_order, p.source_observed_at_ms, p.source_observed_at_ms + ?3
                    FROM cgka_processed_transport_ids AS p WHERE p.group_id = r.device_group_id AND p.qualified_slot = r.target_slot
                      AND p.source_resolved = 1 AND p.source_epoch > (SELECT sibling_resend_after_epoch FROM cgka_groups WHERE id = p.group_id)
                      AND p.source_observed_order > r.publication_order ORDER BY p.source_observed_order LIMIT 1)
                 WHERE r.device_group_id = ?1 AND r.target_slot = ?2 AND r.publication_order IS NOT NULL AND
                   (r.activity_id IS NULL OR EXISTS(SELECT 1 FROM cgka_processed_transport_ids AS a WHERE a.group_id = ?1 AND a.content_id = r.activity_id AND a.source_resolved = 2)
                    OR EXISTS(SELECT 1 FROM cgka_processed_transport_ids AS p WHERE p.group_id = ?1 AND p.qualified_slot = ?2 AND p.source_resolved = 1 AND p.source_epoch > (SELECT sibling_resend_after_epoch FROM cgka_groups WHERE id = p.group_id)
                      AND p.source_observed_order > r.publication_order AND p.source_observed_order < r.activity_order))",
                params![group_id.as_slice(), slot, u64_to_i64(SIBLING_WELCOME_RESEND_WAIT_MS)?],
            ).storage()?;
            Ok(())
        })
    }

    /// Mark a definitively unattributable accepted source without timing it as
    /// activity. Unavailable source proof is left pending by the caller.
    pub fn ignore_sibling_welcome_activity(
        &self,
        group_id: &GroupId,
        content_id: &MessageId,
    ) -> StorageResult<()> {
        self.lock()?.execute_cached(
            "UPDATE cgka_processed_transport_ids SET source_resolved = 1
             WHERE group_id = ?1 AND content_id = ?2 AND source_resolved = 0 AND source_has_leaf = 1",
            params![group_id.as_slice(), content_id.as_slice()],
        ).storage()?;
        Ok(())
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
                    "SELECT p.content_id, p.source_observed_order, p.source_observed_at_ms
                 FROM sibling_welcome_resends AS r
                 JOIN cgka_processed_transport_ids AS p
                   ON p.group_id = r.device_group_id AND p.qualified_slot = r.target_slot
                 WHERE r.welcome_id = ?1 AND r.activity_id IS NULL
                   AND r.publication_order = ?2 AND p.source_resolved = 1
                   AND p.source_epoch > (SELECT sibling_resend_after_epoch FROM cgka_groups WHERE id = p.group_id)
                   AND p.source_observed_order > r.publication_order
                 ORDER BY p.source_observed_order LIMIT 1",
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
fn observe_source(
    store: &SqliteAccountStorage,
    group: &GroupId,
    id: &MessageId,
    epoch: cgka_traits::EpochId,
    now: u64,
) {
    use cgka_traits::storage::{
        AuthenticatedDeviceGroupLeaf, AuthenticatedDeviceGroupSource, MessageStorage,
    };
    store
        .observe_authenticated_device_group_source(
            group,
            id,
            &AuthenticatedDeviceGroupSource {
                identity: id.clone(),
                application_id: Some(id.clone()),
                epoch,
                sender: cgka_traits::MemberId::new(vec![1; 32]),
                leaf_index: 1,
                leaf: Some(AuthenticatedDeviceGroupLeaf {
                    signature_key: vec![2; 32],
                    device_tag: Some(vec![3]),
                    slot_hint: Some([3; 32]),
                }),
            },
            now,
        )
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::test_support::{gid, mid, sample_group};
    use cgka_traits::EpochId;
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
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("native-observation.db");
        let key = crate::SqlCipherKey::new("synthetic native observation").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
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
        let partial = cgka_traits::storage::AuthenticatedDeviceGroupSource {
            identity: mid(211),
            application_id: Some(mid(11)),
            epoch: EpochId(0),
            sender: MemberId::new(vec![1; 32]),
            leaf_index: 1,
            leaf: None,
        };
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_native_observation BEFORE UPDATE OF source_proof ON cgka_processed_transport_ids BEGIN SELECT RAISE(ABORT, 'injected source failure'); END;").unwrap();
        let error = store
            .with_transaction(|store| {
                store.put_processed_transport_content(&gid(1), &mid(19), &mid(29))?;
                store.observe_authenticated_device_group_source(&gid(1), &mid(29), &partial, 100)
            })
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Backend(ref message) if message.contains("injected source failure"))
        );
        assert!(
            !store.has_processed_transport_id(&mid(19)).unwrap(),
            "native observation failure rolls back its admission marker"
        );
        store
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_native_observation")
            .unwrap();
        store
            .observe_authenticated_device_group_source(&gid(1), &mid(11), &partial, 100)
            .unwrap();
        assert!(
            store
                .pending_authenticated_device_group_sources(&gid(1), true, None, None, 32)
                .unwrap()
                .is_empty()
        );

        assert_eq!(
            app.sibling_welcome_carrier_reservation(b"welcome").unwrap(),
            Some((b"carrier1".to_vec(), 1))
        );
        let first = accept(&store, 2, 100);
        app.record_sibling_welcome_publication(b"welcome", b"carrier1", first)
            .unwrap();
        drop(app);
        store.close().unwrap();
        drop(store);
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let app = store.app_storage();
        // A new encryption at a later source epoch cannot freshen the same
        // earlier event while its original source proof is unavailable.
        store
            .put_processed_transport_content(&gid(1), &mid(21), &mid(31))
            .unwrap();
        let known_alias = cgka_traits::storage::AuthenticatedDeviceGroupSource {
            identity: mid(11),
            application_id: Some(mid(11)),
            epoch: EpochId(1),
            sender: MemberId::new(vec![1; 32]),
            leaf_index: 1,
            leaf: Some(cgka_traits::storage::AuthenticatedDeviceGroupLeaf {
                signature_key: vec![2; 32],
                device_tag: Some(vec![3]),
                slot_hint: Some(slot),
            }),
        };
        store
            .observe_authenticated_device_group_source(&gid(1), &mid(31), &known_alias, 101)
            .unwrap();
        assert!(
            store
                .pending_authenticated_device_group_sources(&gid(1), true, None, None, 32)
                .unwrap()
                .is_empty(),
            "ambiguous alias holds until exact old source proof resolves"
        );
        // A distinct known source with the same app id stays independent once
        // the partial proof establishes that it was the other sender.
        store
            .put_processed_transport_content(&gid(1), &mid(22), &mid(32))
            .unwrap();
        let distinct = cgka_traits::storage::AuthenticatedDeviceGroupSource {
            identity: mid(32),
            leaf_index: 2,
            leaf: Some(cgka_traits::storage::AuthenticatedDeviceGroupLeaf {
                signature_key: vec![9; 32],
                device_tag: Some(vec![4]),
                slot_hint: Some([4; 32]),
            }),
            ..known_alias.clone()
        };
        store
            .observe_authenticated_device_group_source(&gid(1), &mid(32), &distinct, 102)
            .unwrap();
        // Exact-source proof and current-roster attribution arrive after the
        // publication. The native prepublication stamp must remain old.
        observe_source(&store, &gid(1), &mid(11), EpochId(0), 9_999);
        let pending = store
            .pending_authenticated_device_group_sources(&gid(1), true, None, None, 32)
            .unwrap();
        assert!(
            pending.iter().any(|(id, _)| *id == mid(32)),
            "a different authenticated source cannot be coalesced away"
        );
        assert!(
            !pending.iter().any(|(id, _)| *id == mid(31)),
            "same-source alias coalesces to earliest native observation"
        );
        app.ignore_sibling_welcome_activity(&gid(1), &mid(32))
            .unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(23), &mid(33))
            .unwrap();
        let leaf_rekey_alias = cgka_traits::storage::AuthenticatedDeviceGroupSource {
            identity: mid(33),
            leaf: Some(cgka_traits::storage::AuthenticatedDeviceGroupLeaf {
                signature_key: vec![8; 32],
                device_tag: Some(vec![3]),
                slot_hint: Some(slot),
            }),
            ..known_alias.clone()
        };
        store
            .observe_authenticated_device_group_source(&gid(1), &mid(33), &leaf_rekey_alias, 103)
            .unwrap();

        app.qualify_sibling_welcome_activity(&gid(1), &mid(11), &slot, &[3; 32])
            .unwrap();
        app.qualify_sibling_welcome_activity(&gid(1), &mid(33), &slot, &[3; 32])
            .unwrap();
        let alias_state: i64 = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT source_resolved FROM cgka_processed_transport_ids WHERE content_id = ?1",
                params![mid(33).as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            alias_state, 2,
            "different MLS keys verified by the same current device tag key coalesce to the earlier observation"
        );

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
        for n in 40..80 {
            store
                .put_processed_transport_content(&gid(1), &mid(n), &mid(n + 40))
                .unwrap();
            let partial = cgka_traits::storage::AuthenticatedDeviceGroupSource {
                identity: mid(n + 40),
                application_id: Some(mid(n + 40)),
                ..partial.clone()
            };
            store
                .observe_authenticated_device_group_source(&gid(1), &mid(n + 40), &partial, 98)
                .unwrap();
        }
        for n in 140..180 {
            let unready = cgka_traits::storage::AuthenticatedDeviceGroupSource {
                identity: mid(n + 40),
                application_id: Some(mid(n + 40)),
                leaf: Some(cgka_traits::storage::AuthenticatedDeviceGroupLeaf {
                    signature_key: vec![7; 32],
                    device_tag: Some(vec![7]),
                    slot_hint: Some([7; 32]),
                }),
                ..partial.clone()
            };
            store
                .put_processed_transport_content(&gid(1), &mid(n), &mid(n + 40))
                .unwrap();
            store
                .observe_authenticated_device_group_source(&gid(1), &mid(n + 40), &unready, 98)
                .unwrap();
        }
        observe_source(&store, &gid(1), &mid(12), EpochId(0), 99);
        let eligible = store
            .pending_authenticated_device_group_sources(&gid(1), true, Some(&[[7; 32]]), None, 32)
            .unwrap();
        assert_eq!(
            eligible.len(),
            1,
            "current-key-unready prefix cannot consume the healthy proof-present result budget"
        );
        assert_eq!(eligible[0].0, mid(12));

        assert_eq!(
            store
                .pending_authenticated_device_group_sources(&gid(1), false, None, None, 32)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            store
                .pending_authenticated_device_group_sources(
                    &gid(1),
                    true,
                    Some(&[[7; 32]]),
                    None,
                    32
                )
                .unwrap()[0]
                .0,
            mid(12),
            "unavailable older source proof must not starve healthy activity"
        );
        app.qualify_sibling_welcome_activity(&gid(1), &mid(12), &slot, &[3; 32])
            .unwrap();
        assert!(app.due_sibling_welcome_resends(600_098).unwrap().is_empty());
        assert_eq!(
            app.due_sibling_welcome_resends(600_099).unwrap(),
            vec![(b"welcome".to_vec(), b"carrier1".to_vec())]
        );
        store
            .put_processed_transport_content(&gid(1), &mid(4), &mid(13))
            .unwrap();
        observe_source(&store, &gid(1), &mid(13), EpochId(0), 200);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(13), &slot, &[3; 32])
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
        observe_source(&store, &gid(1), &mid(14), EpochId(0), 301);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(14), &slot, &[3; 32])
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
        observe_source(&store, &gid(1), &mid(14), EpochId(0), 500);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(14), &slot, &[3; 32])
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
        observe_source(&store, &gid(1), &mid(15), EpochId(0), 501);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(15), &slot, &[3; 32])
            .unwrap();
        assert_eq!(app.due_sibling_welcome_resends(600_501).unwrap().len(), 1);
        store.delete_group(&gid(1)).unwrap();
        assert!(
            app.due_sibling_welcome_resends(1_000_000)
                .unwrap()
                .is_empty()
        );
        assert!(!store.has_processed_transport_id(&mid(9)).unwrap());
        store.close().unwrap();
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
    use cgka_traits::EpochId;
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
        observe_source(&store, &gid(1), &mid(11), EpochId(7), 101);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(11), &[3; 32], &[3; 32])
            .unwrap();
        store.put_group(&sample_group(gid(1), 8, 0)).unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(2), &mid(11))
            .unwrap();
        observe_source(&store, &gid(1), &mid(11), EpochId(7), 102);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(11), &[3; 32], &[3; 32])
            .unwrap();
        store.rollback_group_to_snapshot(&gid(1), "floor").unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(3), &mid(11))
            .unwrap();
        observe_source(&store, &gid(1), &mid(11), EpochId(7), 103);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(11), &[3; 32], &[3; 32])
            .unwrap();
        assert!(
            app.due_sibling_welcome_resends(1_000_000)
                .unwrap()
                .is_empty()
        );
        store.put_group(&sample_group(gid(1), 8, 0)).unwrap();
        store
            .put_processed_transport_content(&gid(1), &mid(5), &mid(15))
            .unwrap();
        let alias = cgka_traits::storage::AuthenticatedDeviceGroupSource {
            identity: mid(15),
            application_id: Some(mid(11)),
            epoch: EpochId(8),
            sender: cgka_traits::MemberId::new(vec![1; 32]),
            leaf_index: 1,
            leaf: Some(cgka_traits::storage::AuthenticatedDeviceGroupLeaf {
                signature_key: vec![8; 32],
                device_tag: Some(vec![3]),
                slot_hint: Some([3; 32]),
            }),
        };
        store
            .observe_authenticated_device_group_source(&gid(1), &mid(15), &alias, 104)
            .unwrap();
        app.qualify_sibling_welcome_activity(&gid(1), &mid(15), &[3; 32], &[3; 32])
            .unwrap();
        assert!(
            app.due_sibling_welcome_resends(1_000_000)
                .unwrap()
                .is_empty(),
            "later-source-epoch leaf rekey cannot upgrade an already observed pre-floor event under the same device tag principal"
        );
        store
            .put_processed_transport_content(&gid(1), &mid(4), &mid(12))
            .unwrap();
        observe_source(&store, &gid(1), &mid(12), EpochId(8), 104);
        app.qualify_sibling_welcome_activity(&gid(1), &mid(12), &[3; 32], &[3; 32])
            .unwrap();
        assert_eq!(app.due_sibling_welcome_resends(600_104).unwrap().len(), 1);
    }
}
