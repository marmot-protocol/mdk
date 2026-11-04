//! Real compared pairing, native Join, local Made cut and old membership
//! cleanup compose here. Native tag/branch and storage-only rollback contracts
//! remain in their cheaper owners; this owns App scheduling and reopen.
use super::*;
use crate::tests::device_group::history_delivery::{local_blossom, send_text, use_blossom};

#[test]
fn a_move_keeps_old_trust_until_made_and_retries_its_atomic_cut_after_reopen() {
    run_composed_app_runtime_test("device-group-move", || async {
        let (
            relay,
            [
                mut original,
                mut moving,
                mut destination,
                mut destination_sibling,
            ],
        ) = alice_devices::<4>().await;
        // Only this real loopback media fixture needs the existing dev dial opt-in.
        moving.app.config.allow_loopback_blob_endpoints = true;
        original.app.config.allow_loopback_blob_endpoints = true;
        // Construct each real HTTP transport with that existing configuration.
        moving = reopen(moving).await;
        original = reopen(original).await;
        // A real old-chat gap Add (not a founding sibling) owes D76 history.
        let chat = moving
            .client
            .create_group("Keep this chat", &[])
            .await
            .unwrap();
        let blossom = local_blossom();
        use_blossom(
            &mut moving.client,
            &chat,
            cgka_traits::app_components::BLOSSOM_LOCATOR_KIND_V1,
            &blossom.url,
        )
        .await;
        let long = "x".repeat(15_000);
        for index in 0..=crate::history_delivery::MAX_INLINE_BUNDLES {
            send_text(&mut moving.client, &chat, &format!("{index}{long}")).await;
        }
        let received_chat = original
            .client
            .create_group("Receive old history", &[])
            .await
            .unwrap();
        use_blossom(
            &mut original.client,
            &received_chat,
            cgka_traits::app_components::BLOSSOM_LOCATOR_KIND_V1,
            &blossom.url,
        )
        .await;
        let mut historical = Vec::new();
        for index in 0..=crate::history_delivery::MAX_INLINE_BUNDLES {
            historical.push(
                send_text(
                    &mut original.client,
                    &received_chat,
                    &format!("receive{index}{long}"),
                )
                .await,
            );
        }
        let old = link(&relay, &mut original, &mut moving, "Moving").await;
        let target = link(
            &relay,
            &mut destination,
            &mut destination_sibling,
            "Destination sibling",
        )
        .await;
        assert_ne!(old, target);
        use cgka_traits::app_components::{RejectedSlotReasonV1, RejectedSlotV1};
        let collision_slot = hex::decode(destination_sibling.slot_hex())
            .unwrap()
            .try_into()
            .unwrap();
        let imported_slot = [91; 32];
        let destination_rejected_slot = [92; 32];
        let expired_slot = [93; 32];
        let rejected_at = unix_now_seconds().saturating_sub(10);
        let not_me = |at| RejectedSlotV1 {
            reason: RejectedSlotReasonV1::NotMe,
            rejected_at: at,
            tag_signature_key: None,
        };
        let effects = moving
            .client
            .runtime
            .reject_device_slots(
                &old,
                &[],
                vec![
                    (imported_slot, not_me(rejected_at)),
                    (collision_slot, not_me(rejected_at)),
                    (destination_rejected_slot, not_me(rejected_at)),
                ],
                Default::default(),
            )
            .await
            .unwrap();
        moving
            .client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        let effects = moving
            .client
            .runtime
            .record_removed_slot(
                &old,
                &[],
                expired_slot,
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at: unix_now_seconds().saturating_sub(30 * 24 * 60 * 60),
                    tag_signature_key: Some(moving.client.runtime.own_signature_key()),
                },
                Default::default(),
            )
            .await
            .unwrap();
        moving
            .client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        let destination_rejection = not_me(rejected_at.saturating_sub(1));
        let effects = destination
            .client
            .runtime
            .reject_device_slots(
                &target,
                &[],
                vec![(destination_rejected_slot, destination_rejection.clone())],
                Default::default(),
            )
            .await
            .unwrap();
        destination
            .client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        deliver_new(&mut original.client, &relay, &mut original.cursor).await;
        deliver_new(
            &mut destination_sibling.client,
            &relay,
            &mut destination_sibling.cursor,
        )
        .await;
        assert_eq!(
            moving.roster(&old).rejected_slots[&imported_slot],
            not_me(rejected_at)
        );
        assert_eq!(
            destination.roster(&target).rejected_slots[&destination_rejected_slot],
            destination_rejection
        );
        let slot: [u8; 32] = hex::decode(moving.slot_hex()).unwrap().try_into().unwrap();
        let original_slot: [u8; 32] = hex::decode(original.slot_hex())
            .unwrap()
            .try_into()
            .unwrap();
        let old_entry = moving.roster(&old).devices[&slot].clone();
        moving.client.sibling_key_package_upkeep(&[]).await;
        let issued = moving.client.runtime.issued_private_key_packages().unwrap();
        assert!(
            !issued.is_empty(),
            "actual old-namespace issued keys must participate in the Made rollback"
        );
        original.client.sibling_key_package_upkeep(&[]).await;
        deliver_new(&mut original.client, &relay, &mut original.cursor).await;
        deliver_new(&mut moving.client, &relay, &mut moving.cursor).await;
        for _ in 0..3 {
            moving.client.run_due_maintenance().await.unwrap();
            deliver_new(&mut original.client, &relay, &mut original.cursor).await;
            original.client.run_due_maintenance().await.unwrap();
            deliver_new(&mut moving.client, &relay, &mut moving.cursor).await;
        }
        assert!(
            original.client.state_group_record(&chat).is_some(),
            "actual sibling Welcome joined the ordinary chat"
        );
        let old_history = moving
            .client
            .prepare_history_upload()
            .unwrap()
            .expect("the real old-chat Add owes Blossom history");
        blossom
            .refuse_uploads
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let old_history = old_history.run().await;
        blossom
            .refuse_uploads
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // The opposite direction is a real D76 delivery too. Its prepared
        // receiver work must not survive the same source cut as the upload.
        assert!(
            moving.client.state_group_record(&received_chat).is_some(),
            "the authentic reverse-direction Welcome joined before preparing fetch work"
        );
        original.client.drive_history_deliveries().await;
        assert!(
            original
                .app
                .account_storage("alice")
                .unwrap()
                .app_storage()
                .unsent_history_deliveries()
                .unwrap()
                .iter()
                .any(
                    |owed| owed.group_id_hex == hex::encode(received_chat.as_slice())
                        && owed.receiver_slot_hex == hex::encode(slot)
                ),
            "the actual reverse Add owes history before Blossom runs"
        );
        original.client.drive_history_blobs().await;
        deliver_new(&mut moving.client, &relay, &mut moving.cursor).await;
        let old_fetch = moving
            .client
            .prepare_history_fetch()
            .unwrap()
            .expect("a real old-source Blossom delivery");
        assert!(!blossom.blobs.lock().unwrap().is_empty());
        blossom.blobs.lock().unwrap().clear(); // an actual server can forget its blob
        let before_reads = blossom.reads.lock().unwrap().len();
        let old_fetch = old_fetch.run().await;
        assert!(
            blossom.reads.lock().unwrap().len() > before_reads,
            "the real HTTP fetch reached the now-empty server"
        );
        let received_chat_hex = hex::encode(received_chat.as_slice());
        let moving_storage = moving.app.account_storage("alice").unwrap().app_storage();
        assert!(historical.iter().all(|id| {
            moving_storage
                .timeline_message(&received_chat_hex, id)
                .unwrap()
                .is_none()
        }));
        let before_chat_epoch = original.client.runtime.group_record(&chat).unwrap().epoch;
        let old_roster = original.roster(&old);
        assert!(
            original
                .client
                .runtime
                .own_account_leaf_claims(&chat, &old_roster)
                .unwrap()
                .iter()
                .any(|(_, claim)| *claim
                    == cgka_traits::app_components::DeviceTagClaim::Device(slot))
        );
        published_key_package(&mut moving.client, &relay).await;
        choose_link(&relay, &mut destination, &mut moving).await;
        moving.op(DeviceLinkOp::ConfirmMatch).await;
        moving.step(&relay).await;
        destination.step(&relay).await;
        // Use the same actual App ingress as step, without driving pairing:
        // the validated Welcome must record Joined while old trust remains.
        deliver_new(&mut moving.client, &relay, &mut moving.cursor).await;
        let store = moving.app.account_storage("alice").unwrap();
        let joined = store
            .app_storage()
            .device_group_move(&target)
            .unwrap()
            .unwrap();
        assert_eq!(joined.phase, storage_sqlite::DeviceGroupMovePhase::Joined);
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(old.clone())
        );
        assert_eq!(
            moving.trust(&target),
            Some(DeviceGroupTrust::AwaitingWelcome)
        );
        let issued = moving.client.runtime.issued_private_key_packages().unwrap();
        assert!(!issued.is_empty());
        let fault = linked_device_chats::account_database(&moving.app);
        let taken_before: i64 = fault
            .query_row(
                "SELECT count(*) FROM private_key_packages_received WHERE taken_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            taken_before > 0,
            "the ordinary gap Add consumed real private stock"
        );
        fault.execute_batch("CREATE TRIGGER fail_app_move_made BEFORE UPDATE OF phase ON device_group_moves WHEN NEW.phase = 2 BEGIN SELECT RAISE(ABORT, 'app move Made checkpoint failed'); END;").unwrap();
        // Reopening loses the in-memory new-device pairing session, not the
        // joined move. A real new request must still stay unanswered until Made.
        moving = reopen(moving).await;
        published_key_package(&mut destination.client, &relay).await;
        assert_eq!(
            destination.op(DeviceLinkOp::Start).await.new_device,
            Some(NewDeviceLinkState::WaitingForAnswer)
        );
        let waiting = moving.step(&relay).await;
        let requesting = destination.step(&relay).await;
        assert_eq!(
            requesting.new_device,
            Some(NewDeviceLinkState::WaitingForAnswer),
            "the real requester must receive no Answer from the reopened Joined mover"
        );
        assert_eq!(
            waiting
                .prompt_for_slot(&destination.slot_hex())
                .expect("the actual new request reached the reopened mover")
                .state,
            DeviceLinkPromptState::Preparing,
            "a reopened Joined mover must not answer a pairing request"
        );
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(old.clone())
        );
        let error = moving
            .client
            .drive_device_group_moves(unix_now_seconds())
            .await
            .unwrap_err();
        assert!(
            matches!(error.as_engine_error(), Some(cgka_traits::EngineError::Storage(cgka_traits::storage::StorageError::Backend(message))) if message.contains("app move Made checkpoint failed")),
            "{error:?}"
        );
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(old.clone())
        );
        assert_eq!(
            moving.trust(&target),
            Some(DeviceGroupTrust::AwaitingWelcome)
        );
        assert_eq!(
            store
                .app_storage()
                .device_group_move(&target)
                .unwrap()
                .unwrap(),
            joined
        );
        assert_eq!(
            moving.client.runtime.issued_private_key_packages().unwrap(),
            issued,
            "native key retirement rolled back with Made"
        );
        let target_roster = moving.roster(&target);
        assert_eq!(
            target_roster.devices[&slot].tag_signature_key.as_ref(),
            Some(&moving.client.runtime.own_signature_key()),
            "actual first own Commit preceded the failed local checkpoint"
        );
        fault
            .execute_batch("DROP TRIGGER fail_app_move_made")
            .unwrap();
        drop(fault);
        moving = reopen(moving).await;
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(old.clone())
        );
        let made = moving.op(DeviceLinkOp::Read).await;
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(target.clone())
        );
        assert_eq!(
            made.moves.last().unwrap().state,
            crate::DeviceGroupMoveState::Made
        );
        assert!(
            made.moves
                .last()
                .unwrap()
                .old_siblings
                .iter()
                .any(|sibling| sibling.slot_id_hex == hex::encode(original_slot)
                    && sibling.question_suppressed)
        );
        assert!(
            moving
                .client
                .runtime
                .issued_private_key_packages()
                .unwrap()
                .is_empty()
        );
        assert!(!moving.client.device_unlinked);
        let before_old_history = relay.published_event_ids().len();
        assert!(
            moving.client.finish_history_upload(old_history).await,
            "a failed old-source upload is discarded after Made, not deferred into the destination"
        );
        assert_eq!(relay.published_event_ids().len(), before_old_history);
        assert!(
            store
                .app_storage()
                .unsent_history_deliveries()
                .unwrap()
                .is_empty()
        );
        assert!(
            moving.client.finish_history_fetch(old_fetch),
            "a failed old-source fetch is discarded without rearming or importing after Made"
        );
        assert!(
            moving_storage
                .parked_history_delivery_chats()
                .unwrap()
                .is_empty()
        );
        assert!(historical.iter().all(|id| {
            moving_storage
                .timeline_message(&received_chat_hex, id)
                .unwrap()
                .is_none()
        }));
        // Ordinary native old-group work may still finish after Made. A
        // post-status SelfUpdate follows destination tagging, so cleanup must
        // identify the actual leaf by the selected old entry's signature key.
        moving.step(&relay).await;
        assert_eq!(
            moving.roster(&old).devices[&slot].status,
            cgka_traits::app_components::DeviceStatusV1::Moved
        );
        let effects = moving
            .client
            .runtime
            .send(SendIntent::SelfUpdate {
                group_id: old.clone(),
            })
            .await
            .unwrap();
        moving
            .client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        deliver_new(&mut original.client, &relay, &mut original.cursor).await;
        assert!(original.roster(&old).devices.contains_key(&slot));
        assert!(
            !original
                .client
                .runtime
                .own_account_leaf_claims(&old, &original.roster(&old))
                .unwrap()
                .iter()
                .any(|(_, claim)| *claim
                    == cgka_traits::app_components::DeviceTagClaim::Device(slot)),
            "the still-member mover no longer tags against the old roster"
        );
        assert!(
            moving
                .client
                .runtime
                .canonical_group_membership(&old)
                .unwrap()
                .local_leaf_active
        );
        original.client.drive_device_removals().await;
        assert!(!original.roster(&old).devices.contains_key(&slot));
        deliver_new(&mut moving.client, &relay, &mut moving.cursor).await;
        assert!(
            moving.client.runtime.group_record(&old).unwrap().removed,
            "moved cleanup removes the actual MLS leaf, not only its roster entry"
        );
        for _ in 0..8 {
            moving.step(&relay).await;
            original.step(&relay).await;
            original.client.drive_device_removals().await;
            destination.step(&relay).await;
            if store.is_group_forgotten(&old).unwrap()
                && !original.roster(&old).devices.contains_key(&slot)
            {
                break;
            }
        }
        assert!(store.is_group_forgotten(&old).unwrap());
        assert_eq!(
            store
                .app_storage()
                .device_group_move(&target)
                .unwrap()
                .unwrap()
                .phase,
            storage_sqlite::DeviceGroupMovePhase::Finished
        );
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(target.clone())
        );
        assert!(!original.roster(&old).devices.contains_key(&slot));
        assert!(!original.roster(&old).rejected_slots.contains_key(&slot));
        let target_roster = moving.roster(&target);
        assert_eq!(
            target_roster.rejected_slots[&imported_slot],
            not_me(rejected_at),
            "the carried fact keeps its original age"
        );
        assert_eq!(
            target_roster.rejected_slots[&destination_rejected_slot], destination_rejection,
            "the destination's existing rejection wins"
        );
        assert!(!target_roster.rejected_slots.contains_key(&expired_slot));
        assert!(target_roster.devices.contains_key(&collision_slot));
        assert!(!target_roster.rejected_slots.contains_key(&collision_slot));
        let view = moving.op(DeviceLinkOp::Read).await;
        let movement = view.moves.last().unwrap();
        assert_eq!(
            movement.overridden_rejection_slots,
            vec![hex::encode(collision_slot)]
        );
        let move_id = movement.move_id.clone();
        let dismissed = moving
            .op(DeviceLinkOp::DismissMoveSibling {
                move_id,
                slot_id_hex: hex::encode(original_slot),
            })
            .await;
        assert!(
            !dismissed
                .moves
                .last()
                .unwrap()
                .old_siblings
                .iter()
                .find(|sibling| sibling.slot_id_hex == hex::encode(original_slot))
                .unwrap()
                .question_suppressed
        );
        assert!(
            !moving.roster(&target).devices.contains_key(&original_slot),
            "dismissing recognition neither links nor removes a device"
        );
        assert_eq!(
            original.client.runtime.group_record(&chat).unwrap().epoch,
            before_chat_epoch,
            "moved cleanup makes no ordinary-chat Remove"
        );
        assert!(
            moving
                .client
                .runtime
                .canonical_group_membership(&chat)
                .unwrap()
                .local_leaf_active
        );
        assert!(
            original
                .client
                .runtime
                .own_account_leaf_claims(&chat, &old_roster)
                .unwrap()
                .iter()
                .any(|(_, claim)| *claim
                    == cgka_traits::app_components::DeviceTagClaim::Device(slot)),
            "the actual old-tagged leaf stayed, so an unclaimed tag cannot mask cleanup"
        );
        let query = linked_device_chats::account_database(&moving.app);
        let taken_after: i64 = query
            .query_row(
                "SELECT count(*) FROM private_key_packages_received WHERE taken_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            taken_after, taken_before,
            "Made keeps consumed-reference tombstones"
        );
        drop(query);
        let selected = original.client.runtime.group_record(&old).unwrap();
        let cause = selected
            .device_roster_departures
            .iter()
            .find(|cause| cause.slot == slot)
            .expect("selected old Moved cleanup");
        assert_eq!(
            cause.cause,
            cgka_traits::group::DeviceRosterDepartureCause::Moved
        );
        assert_eq!(cause.tag_signature_key, old_entry.tag_signature_key);
        assert_eq!(cause.entry_rename_id, old_entry.rename_id);
        assert_eq!(cause.linked_at, old_entry.linked_at);
        assert!(store.app_storage().device_removals().unwrap().is_empty());
    });
}

/// A real approver deadline undo can arrive with the authentic Welcome.
/// That admitted-but-not-Made destination alone is forgotten; old trust is
/// neither reconstructed nor passed through another trust transition.
#[test]
fn a_failed_move_forgets_only_the_destination_without_restoring_old_trust() {
    run_composed_app_runtime_test("device-group-move-failure", || async {
        let (relay, [mut original, mut moving, mut destination]) = alice_devices::<3>().await;
        let old = link(&relay, &mut original, &mut moving, "Moving").await;
        let store = moving.app.account_storage("alice").unwrap();
        let original_provenance = store
            .app_storage()
            .device_group(&hex::encode(old.as_slice()))
            .unwrap()
            .unwrap();
        published_key_package(&mut moving.client, &relay).await;
        let slot = choose_link(&relay, &mut destination, &mut moving).await;
        moving.op(DeviceLinkOp::ConfirmMatch).await;
        moving.step(&relay).await;
        destination.step(&relay).await;
        let target = destination.client.trusted_device_group().unwrap().unwrap();
        assert_ne!(target, old);
        destination
            .client
            .drive_device_pairing_at(unix_now_seconds() + LINK_DEADLINE_SECS + 1)
            .await;
        destination.step(&relay).await;
        assert_eq!(
            link_record(&destination, &target, &slot).outcome,
            DeviceLinkOutcome::Failed
        );
        deliver_new(&mut moving.client, &relay, &mut moving.cursor).await;
        let joined = store
            .app_storage()
            .device_group_move(&target)
            .unwrap()
            .unwrap();
        assert_eq!(
            joined.phase,
            storage_sqlite::DeviceGroupMovePhase::Joined,
            "actual native join preceded its authenticated removal"
        );
        assert!(moving.client.runtime.group_record(&target).unwrap().removed);
        let fault = linked_device_chats::account_database(&moving.app);
        fault.execute_batch("CREATE TRIGGER fail_move_end AFTER UPDATE OF phase ON device_group_moves WHEN NEW.phase = 3 BEGIN SELECT RAISE(ABORT, 'move end after forget failed'); END;").unwrap();
        let failed = moving
            .client
            .drive_device_group_moves(unix_now_seconds())
            .await;
        assert!(
            matches!(failed, Err(ref error) if error.to_string().contains("move end after forget failed")),
            "{failed:?}"
        );
        assert!(
            store.is_group_forgotten(&target).unwrap(),
            "real native forget committed before the later phase-end fault"
        );
        assert_eq!(
            store
                .app_storage()
                .device_group_move(&target)
                .unwrap()
                .unwrap()
                .phase,
            storage_sqlite::DeviceGroupMovePhase::Joined
        );
        fault.execute_batch("DROP TRIGGER fail_move_end").unwrap();
        drop(fault);
        moving = reopen(moving).await;
        moving
            .client
            .drive_device_group_moves(unix_now_seconds())
            .await
            .unwrap();
        let view = moving.op(DeviceLinkOp::Read).await;
        assert_eq!(
            view.moves.last().unwrap().state,
            crate::DeviceGroupMoveState::Failed
        );
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(old.clone())
        );
        assert_eq!(
            store
                .app_storage()
                .device_group(&hex::encode(old.as_slice()))
                .unwrap(),
            Some(original_provenance.clone())
        );
        assert!(store.is_group_forgotten(&target).unwrap());
        assert!(!store.is_group_forgotten(&old).unwrap());
        assert!(
            moving
                .client
                .runtime
                .canonical_group_membership(&old)
                .unwrap()
                .local_leaf_active
        );
        assert!(!moving.client.device_unlinked);
        moving = reopen(moving).await;
        assert_eq!(
            moving.client.trusted_device_group().unwrap(),
            Some(old.clone())
        );
        assert_eq!(
            store
                .app_storage()
                .device_group(&hex::encode(old.as_slice()))
                .unwrap(),
            Some(original_provenance)
        );
        assert!(store.is_group_forgotten(&target).unwrap());
        assert_eq!(
            moving
                .op(DeviceLinkOp::Read)
                .await
                .moves
                .last()
                .unwrap()
                .state,
            crate::DeviceGroupMoveState::Failed
        );
    });
}
