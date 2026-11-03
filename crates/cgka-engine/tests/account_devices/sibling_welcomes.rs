//! Sending sibling Welcomes (mdk#2628 3.5b, device-group.md "Sending a
//! sibling Welcome").
//!
//! A same-account Add names, for each KeyPackage, the slot of the sibling
//! that handed it over. Its Commit stages one sibling Welcome row per
//! KeyPackage instead of a transport Welcome: the encoded `SiblingWelcome`
//! the host sends as a kind-461 message in the device group. The row is owed
//! once the Commit confirms, fails with a Commit that rolls back, and is owed
//! no more once its KeyPackage expires or its chat is disbanded. The host
//! records each 461's app event id on the row before the send, marks the row
//! delivered by that carrier, and clears a failed carrier so the row is owed
//! again. A direct send's refusal comes before anything is written; so does a
//! queued one's, checked before the queue, and the drain checks it again.

use super::device_roster::{clocked_roster_device, key_package_ref, roster_device, slot};
use super::device_tag::hold_slot;
use super::send_intents::Untouched;
use super::tagged_siblings::*;
use super::*;
use cgka_engine::private_key_packages::SiblingWelcome;
use cgka_traits::app_components::DEVICE_ROSTER_COMPONENT_ID;
use cgka_traits::engine::KeyPackageSource;
use cgka_traits::error::SiblingAddRefusal;
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::storage::{GroupStorage as _, OutboundIntentStorage as _};
use cgka_traits::types::EpochId;
use std::sync::{Arc, Mutex};

/// A sibling's applied voluntary departure is not a missing-device gap.
/// The commit's authenticated SelfRemove, rather than account disappearance,
/// must hold another private Add while the observing device keeps this copy.
#[tokio::test]
async fn an_applied_sibling_self_remove_holds_private_adds() {
    use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sibling-departures.sqlite");
    let key = SqlCipherKey::raw([0x57; 32]);
    let clock = manual_convergence_clock();
    let phone = build_device(
        SqliteAccountStorage::open_encrypted(&path, &key).unwrap(),
        b"bob",
        &[
            ACCOUNT_DEVICES_COMPONENT_ID,
            DEVICE_ROSTER_COMPONENT_ID,
            cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID,
        ],
        Box::<MockPeeler>::default(),
        Some(&clock),
    );
    let (mut phone, mut siblings, device_group) =
        tag_devices(vec![phone, roster_device(b"bob"), roster_device(b"bob")]).await;
    let mut laptop = siblings.remove(0);
    let mut tablet = siblings.remove(0);
    let mut alice = chat_device(b"alice");
    let gid = found_routed_group(&mut alice, &mut [&mut phone, &mut laptop, &mut tablet]).await;

    // Ordinary Remove carries no voluntary-departure fact, even when its
    // committer is another leaf of the same account. Re-adding is permitted.
    let laptop_key = signature_key(&laptop, &gid);
    let remove = send_commit(&mut phone, remove_own_devices(&gid, vec![laptop_key]), &gid).await;
    for receiver in [&mut alice, &mut laptop, &mut tablet] {
        assert_accepted(receiver, &remove, &gid).await;
    }
    let replacement = handed(&mut laptop, slot(2), slot(1));
    assert_eq!(
        phone
            .engine
            .sibling_add_refusal(&gid, &replacement)
            .unwrap(),
        None
    );
    assert_eq!(
        tablet
            .engine
            .sibling_add_refusal(&gid, &handed(&mut laptop, slot(2), slot(3)))
            .unwrap(),
        None
    );
    let add = send_commit(&mut phone, add_own_devices(&gid, vec![replacement]), &gid).await;
    for receiver in [&mut alice, &mut tablet] {
        assert_accepted(receiver, &add, &gid).await;
    }
    let welcome = owed(&phone).remove(0);
    laptop.engine.drain_events();
    assert_joins_from(&mut laptop, &welcome, &gid, &phone).await;
    let replacement = handed(&mut laptop, slot(2), slot(1));
    let tablet_replacement = handed(&mut laptop, slot(2), slot(3));
    // A readable trusted roster can recognize the departing sibling while
    // this observer's own tag key is not ready. This is a valid non-user edit,
    // preserving its entry and user marker, not a corrupt roster fixture.
    let original_entry =
        super::device_roster::roster_of(&phone, &device_group).devices[&slot(1)].clone();
    let mut unready = original_entry.clone();
    unready.tag_signature_key = None;
    let edit = super::device_roster::roster_update(
        &device_group,
        vec![cgka_traits::app_components::DeviceRosterOperationV1::SetDevice(slot(1), unready)],
    );
    let edit = send_commit(&mut phone, edit, &device_group).await;
    for receiver in [&mut laptop, &mut tablet] {
        assert_accepted(receiver, &edit, &device_group).await;
    }
    let roster = super::device_roster::roster_of(&phone, &device_group);
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            load_group(&phone, &gid).own_leaf_node().unwrap(),
            &roster
        ),
        cgka_traits::app_components::DeviceTagClaim::Unclaimed
    );

    let SendResult::Proposal { msg } = laptop
        .engine
        .send(SendIntent::Leave {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("ordinary SelfRemove proposal")
    };
    phone
        .engine
        .ingest(route_to_group(&msg, &gid))
        .await
        .unwrap();
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .is_empty(),
        "a proposal is not applied departure"
    );
    let delay = phone
        .engine
        .scheduled_self_remove_auto_commit_delay_ms(&gid)
        .unwrap()
        .unwrap();
    clock.advance_ms(delay);
    phone.engine.advance_convergence(&gid).await.unwrap();
    let publications = phone.engine.drain_auto_publish();
    assert_eq!(publications.len(), 1);
    let publication = &publications[0];
    let epoch = load_group(&phone, &gid).epoch().as_u64();
    let pending_epoch = phone.engine.epoch(&gid).unwrap();
    let observer = rusqlite::Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    // A source-roster storage/decode failure is not an unclaimed tag.
    // Swallowing it would consume the source leaf without its required fact.
    let dg_key = serde_json::to_vec(&openmls::group::GroupId::from_slice(
        device_group.as_slice(),
    ))
    .unwrap();
    let context: Vec<u8> = observer
        .query_row(
            "SELECT value FROM openmls_values WHERE label = ?1 AND group_key = ?2",
            rusqlite::params![b"GroupContext".as_slice(), &dg_key],
            |row| row.get(0),
        )
        .unwrap();
    observer
        .execute(
            "UPDATE openmls_values SET value = ?1 WHERE label = ?2 AND group_key = ?3",
            rusqlite::params![b"{".as_slice(), b"GroupContext".as_slice(), &dg_key],
        )
        .unwrap();
    let error = phone
        .engine
        .confirm_published(publication.pending)
        .await
        .unwrap_err();
    assert!(
        matches!(error, EngineError::Backend(ref message) if message.starts_with("load device group:")),
        "{error}"
    );
    assert_eq!(load_group(&phone, &gid).epoch().as_u64(), epoch);
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .is_empty()
    );
    observer
        .execute(
            "UPDATE openmls_values SET value = ?1 WHERE label = ?2 AND group_key = ?3",
            rusqlite::params![&context, b"GroupContext".as_slice(), &dg_key],
        )
        .unwrap();
    observer.execute_batch("CREATE TRIGGER reject_sibling_fact BEFORE INSERT ON cgka_groups BEGIN SELECT RAISE(ABORT, 'sibling fact commit held'); END;").unwrap();
    let error = phone
        .engine
        .confirm_published(publication.pending)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("sibling fact commit held"),
        "{error}"
    );
    assert_eq!(load_group(&phone, &gid).epoch().as_u64(), epoch);
    assert_eq!(phone.engine.epoch(&gid).unwrap(), pending_epoch);
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .is_empty()
    );
    observer
        .execute_batch("DROP TRIGGER reject_sibling_fact")
        .unwrap();
    phone
        .engine
        .confirm_published(publication.pending)
        .await
        .unwrap();
    assert_eq!(phone.engine.members(&gid).unwrap().len(), 3);
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .contains(&slot(2)),
        "a recognized sibling departure is independent of observer tag readiness"
    );
    let restore = super::device_roster::roster_update(
        &device_group,
        vec![
            cgka_traits::app_components::DeviceRosterOperationV1::SetDevice(
                slot(1),
                original_entry,
            ),
        ],
    );
    let restore = send_commit(&mut phone, restore, &device_group).await;
    for receiver in [&mut laptop, &mut tablet] {
        assert_accepted(receiver, &restore, &device_group).await;
    }
    assert_eq!(
        phone
            .engine
            .sibling_add_refusal(&gid, &replacement)
            .unwrap(),
        Some(SiblingAddRefusal::SiblingLeft)
    );
    // Selected remote replay, not just the own-confirmation path, records the
    // authenticated proposal sender's slot before consuming its source leaf.
    tablet
        .engine
        .ingest(route_to_group(&msg, &gid))
        .await
        .unwrap();
    assert_accepted(&mut tablet, &route_to_group(&publication.msg, &gid), &gid).await;
    assert_eq!(
        tablet
            .engine
            .sibling_add_refusal(&gid, &tablet_replacement)
            .unwrap(),
        Some(SiblingAddRefusal::SiblingLeft)
    );

    // The hold survives a physical encrypted-store close/reopen and engine
    // hydration. The per-commit checkpoint was written by real confirmation.
    let checkpoint = phone
        .storage
        .list_group_state_checkpoints(&gid)
        .unwrap()
        .into_iter()
        .find(|checkpoint| checkpoint.resulting_epoch == phone.engine.epoch(&gid).unwrap())
        .unwrap();
    let failed_probe: Result<(), cgka_traits::StorageError> =
        phone
            .storage
            .with_group_savepoint(&gid, "departure-checkpoint-read", |storage| {
                storage.restore_group_state_checkpoint(&gid, &checkpoint.id)?;
                assert!(
                    storage
                        .get_group(&gid)?
                        .self_removed_sibling_slots
                        .contains(&slot(2))
                );
                Err(cgka_traits::StorageError::Backend(
                    "rollback checkpoint read".into(),
                ))
            });
    assert!(
        matches!(failed_probe, Err(cgka_traits::StorageError::Backend(message)) if message == "rollback checkpoint read")
    );
    let Device { engine, storage } = phone;
    drop(engine);
    drop(observer);
    storage.close().unwrap();
    drop(storage);
    let mut phone = super::device_roster::roster_device_on(
        SqliteAccountStorage::open_encrypted(&path, &key).unwrap(),
        b"bob",
    );
    // The same real encrypted reopen can find only the device group corrupt.
    // Its optional attribution context must not block an ordinary chat Commit.
    let observer = rusqlite::Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    let reopened_context: Vec<u8> = observer
        .query_row(
            "SELECT value FROM openmls_values WHERE label = ?1 AND group_key = ?2",
            rusqlite::params![b"GroupContext".as_slice(), &dg_key],
            |row| row.get(0),
        )
        .unwrap();
    observer
        .execute(
            "UPDATE openmls_values SET value = ?1 WHERE label = ?2 AND group_key = ?3",
            rusqlite::params![b"{".as_slice(), b"GroupContext".as_slice(), &dg_key],
        )
        .unwrap();
    phone.engine.hydrate_all_stored_groups().unwrap();
    assert!(
        phone
            .engine
            .quarantined_groups()
            .iter()
            .any(|(id, _)| id == &device_group)
    );
    let error = phone
        .engine
        .set_device_tag_group(Some(device_group.clone()))
        .unwrap_err();
    assert!(
        matches!(error, EngineError::UnknownGroup(ref id) if id == &device_group),
        "{error}"
    );
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .contains(&slot(2))
    );
    let before_update = load_group(&phone, &gid).epoch().as_u64();
    let SendResult::GroupEvolution {
        msg: post_quarantine_update,
        pending,
        ..
    } = phone
        .engine
        .send(SendIntent::SelfUpdate {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("ordinary chat SelfUpdate stages");
    };
    phone
        .engine
        .confirm_published(pending)
        .await
        .expect("unavailable sibling attribution must not block the chat's ordinary Commit");
    assert_eq!(load_group(&phone, &gid).epoch().as_u64(), before_update + 1);
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .contains(&slot(2)),
        "unavailable context must preserve previously applied knowledge"
    );
    observer
        .execute(
            "UPDATE openmls_values SET value = ?1 WHERE label = ?2 AND group_key = ?3",
            rusqlite::params![&reopened_context, b"GroupContext".as_slice(), &dg_key],
        )
        .unwrap();
    assert!(
        phone
            .engine
            .retry_hydrate_quarantined_group(&device_group)
            .unwrap()
    );
    drop(observer);
    phone
        .engine
        .set_device_tag_group(Some(device_group))
        .unwrap();
    assert_eq!(
        phone
            .engine
            .sibling_add_refusal(&gid, &replacement)
            .unwrap(),
        Some(SiblingAddRefusal::SiblingLeft)
    );
    // Both actual preparation and advisory admission use the same refusal.
    let error = phone
        .engine
        .send(add_own_devices(&gid, vec![replacement.clone()]))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        EngineError::Other(reason) if reason == "adding a sibling: the sibling left this chat"
    ));

    // A fresh authenticated Welcome starts a new membership, even though
    // this device retains the removed prior copy and its departure knowledge.
    alice
        .engine
        .ingest(route_to_group(&msg, &gid))
        .await
        .unwrap();
    assert_accepted(&mut alice, &route_to_group(&publication.msg, &gid), &gid).await;
    assert_accepted(
        &mut alice,
        &route_to_group(&post_quarantine_update, &gid),
        &gid,
    )
    .await;
    let fresh = phone.engine.fresh_key_package().await.unwrap();
    let remove_account = send_commit(
        &mut alice,
        SendIntent::RemoveMembers {
            group_id: gid.clone(),
            members: vec![phone.engine.self_id()],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut phone, &remove_account, &gid).await;
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .contains(&slot(2))
    );
    let SendResult::GroupEvolution {
        pending,
        mut welcomes,
        ..
    } = alice
        .engine
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![fresh],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    else {
        panic!("fresh invitation");
    };
    alice.engine.confirm_published(pending).await.unwrap();
    phone.engine.join_welcome(welcomes.remove(0)).await.unwrap();
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .is_empty()
    );
    let Device { engine, storage } = phone;
    drop(engine);
    storage.close().unwrap();
}

/// A historical anchor cannot undo current-membership knowledge. Only a
/// target leaf in the final selected tree ends the hold; a losing candidate
/// SelfRemove creates no hold of its own.
#[tokio::test]
async fn a_sibling_departure_hold_survives_rewind_until_a_selected_leaf_returns() {
    let clock = manual_convergence_clock();
    let (mut phone, mut siblings, _) = tag_devices(vec![
        clocked_roster_device(b"bob", &clock),
        roster_device(b"bob"),
        roster_device(b"bob"),
    ])
    .await;
    let mut laptop = siblings.remove(0);
    let mut tablet = siblings.remove(0);
    let mut alice = chat_device(b"alice");
    let gid = found_routed_group(&mut alice, &mut [&mut phone, &mut laptop, &mut tablet]).await;
    let replacement = handed(&mut laptop, slot(2), slot(1));
    let tablet_replacement = handed(&mut laptop, slot(2), slot(3));
    let key = signature_key(&laptop, &gid);
    let ordinary = send_commit(&mut tablet, remove_own_devices(&gid, vec![key]), &gid).await;
    let child = send_commit(
        &mut tablet,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    // A real other account follows the original selected Remove branch.
    // It will later author the longer branch that contains no returning leaf.
    assert_accepted(&mut alice, &ordinary, &gid).await;
    assert_accepted(&mut alice, &child, &gid).await;
    let SendResult::Proposal { msg } = laptop
        .engine
        .send(SendIntent::Leave {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("ordinary SelfRemove");
    };
    phone
        .engine
        .ingest(route_to_group(&msg, &gid))
        .await
        .unwrap();
    let delay = phone
        .engine
        .scheduled_self_remove_auto_commit_delay_ms(&gid)
        .unwrap()
        .unwrap();
    clock.advance_ms(delay);
    phone.engine.advance_convergence(&gid).await.unwrap();
    let publication = phone.engine.drain_auto_publish().remove(0);
    phone
        .engine
        .confirm_published(publication.pending)
        .await
        .unwrap();
    assert_eq!(
        phone
            .engine
            .sibling_add_refusal(&gid, &replacement)
            .unwrap(),
        Some(SiblingAddRefusal::SiblingLeft)
    );
    phone.engine.ingest(ordinary).await.unwrap();
    phone.engine.ingest(child).await.unwrap();
    clock.advance_ms(1_000_000);
    phone
        .engine
        .converge_stored_openmls_messages_at(
            &gid,
            cgka_engine::ConvergenceClock::now(&clock).monotonic_ms,
        )
        .unwrap();
    assert_eq!(
        phone.engine.epoch(&gid).unwrap(),
        tablet.engine.epoch(&gid).unwrap()
    );
    assert_eq!(
        phone
            .engine
            .sibling_add_refusal(&gid, &replacement)
            .unwrap(),
        Some(SiblingAddRefusal::SiblingLeft)
    );
    // Tablet only probes the losing SelfRemove. A candidate must not persist
    // a fact, or its otherwise legitimate Add below would be refused.
    tablet
        .engine
        .ingest(route_to_group(&msg, &gid))
        .await
        .unwrap();
    tablet
        .engine
        .ingest(route_to_group(&publication.msg, &gid))
        .await
        .unwrap();
    tablet
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert!(
        tablet
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .is_empty()
    );
    assert_eq!(
        tablet
            .engine
            .sibling_add_refusal(&gid, &tablet_replacement)
            .unwrap(),
        None
    );
    let before_return_epoch = phone.engine.epoch(&gid).unwrap();
    assert_eq!(before_return_epoch, alice.engine.epoch(&gid).unwrap());
    let without_return = send_commit(
        &mut alice,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    let without_return_child = send_commit(
        &mut alice,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    let added = send_commit(
        &mut tablet,
        add_own_devices(&gid, vec![tablet_replacement]),
        &gid,
    )
    .await;
    phone.engine.ingest(added).await.unwrap();
    clock.advance_ms(1_000_000);
    phone
        .engine
        .converge_stored_openmls_messages_at(
            &gid,
            cgka_engine::ConvergenceClock::now(&clock).monotonic_ms,
        )
        .unwrap();
    assert_eq!(
        phone.engine.epoch(&gid).unwrap(),
        tablet.engine.epoch(&gid).unwrap()
    );
    assert!(
        phone
            .storage
            .get_group(&gid)
            .unwrap()
            .self_removed_sibling_slots
            .is_empty()
    );
    // The selected return above has ended the current-membership hold.
    // A longer real fork starts before it and removes that leaf from the
    // selected tree, but contains no newly applied SelfRemove.
    phone.engine.ingest(without_return).await.unwrap();
    phone.engine.ingest(without_return_child).await.unwrap();
    clock.advance_ms(1_000_000);
    phone
        .engine
        .converge_stored_openmls_messages_at(
            &gid,
            cgka_engine::ConvergenceClock::now(&clock).monotonic_ms,
        )
        .unwrap();
    assert_eq!(
        phone.engine.epoch(&gid).unwrap(),
        alice.engine.epoch(&gid).unwrap(),
        "the longer branch must really be selected"
    );
    assert_eq!(
        load_group(&phone, &gid).epoch_authenticator().as_slice(),
        load_group(&alice, &gid).epoch_authenticator().as_slice(),
        "matching epochs alone do not prove matching selected trees"
    );
    assert_eq!(
        phone
            .engine
            .sibling_add_refusal(&gid, &replacement)
            .unwrap(),
        None,
        "a historical anchor must not revive a hold ended by a selected return"
    );
}

struct AtTime(u64);
impl cgka_traits::maintenance::WallClock for AtTime {
    fn now(&self) -> Timestamp {
        Timestamp(self.0)
    }
    fn now_ms(&self) -> u64 {
        self.0 * 1_000
    }
}
impl cgka_traits::maintenance::MaintenanceRandom for AtTime {
    fn next_u64(&self) -> u64 {
        0
    }
}

fn reopen_at_time(device: Device, account: &[u8], now: u64) -> Device {
    reopen_at_time_recording(device, account, now, None)
}

fn reopen_at_time_recording(
    device: Device,
    account: &[u8],
    now: u64,
    recorder: Option<Box<dyn marmot_forensics::ForensicRecorder>>,
) -> Device {
    let Device { engine, storage } = device;
    drop(engine);
    let clock = Arc::new(AtTime(now));
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    supported.extend([
        ACCOUNT_DEVICES_COMPONENT_ID,
        DEVICE_ROSTER_COMPONENT_ID,
        cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID,
    ]);
    let builder = EngineBuilder::new(storage.clone())
        .identity(pad32(account))
        .account_identity_proof_signer(proof_signer(account))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .peeler(Box::<MockPeeler>::default())
        .maintenance_sources(clock.clone(), clock);
    let builder = if let Some(recorder) = recorder {
        builder.recorder(recorder)
    } else {
        builder
    };
    let mut engine = builder.build().unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    Device { engine, storage }
}

/// A valid private KeyPackage whose MLS key differs from the device's tag
/// key. Another implementation may rotate its MLS signer independently;
/// device-group.md binds private hand-offs by tag, not by one shared signer.
fn with_another_mls_key(
    sibling: &Device,
    template: &SiblingKeyPackage,
    roster: &cgka_traits::app_components::DeviceRosterV1,
) -> SiblingKeyPackage {
    let parsed = parse_key_package(&template.key_package);
    let leaf = parsed.leaf_node();
    let signer = SignatureKeyPair::new(DEFAULT_CIPHERSUITE.signature_algorithm()).unwrap();
    let mut dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    let proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
        .unwrap();
    let created_at = u64::from_be_bytes(proof[32..40].try_into().unwrap());
    dictionary.insert(
        ACCOUNT_IDENTITY_PROOF_COMPONENT_ID,
        account_identity_proof_component(
            &pad32(b"bob"),
            signer.public(),
            DEFAULT_CIPHERSUITE,
            DEFAULT_CIPHERSUITE.signature_algorithm(),
            created_at,
            proof_signer(b"bob").as_ref(),
        )
        .unwrap(),
    );
    dictionary.insert(
        cgka_traits::app_components::DEVICE_TAG_COMPONENT_ID,
        cgka_engine::device_tag::seal_device_tag(
            &RustCrypto::default(),
            &roster.leaf_tag_key,
            &template.slot,
            &device_signer(sibling),
            signer.public(),
        )
        .unwrap(),
    );
    let mut extensions = leaf.extensions().clone();
    extensions
        .add_or_replace(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
    let bundle = MlsKeyPackage::builder()
        .key_package_lifetime(*parsed.life_time())
        .leaf_node_capabilities(leaf.capabilities().clone())
        .leaf_node_extensions(extensions)
        .build(
            DEFAULT_CIPHERSUITE,
            &OpenMlsRustCrypto::default(),
            &signer,
            CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: signer.public().into(),
            },
        )
        .unwrap();
    SiblingKeyPackage {
        slot: template.slot,
        key_package: KeyPackage::new(
            MlsMessageOut::from(bundle.key_package().clone())
                .tls_serialize_detached()
                .unwrap(),
        )
        .with_protocol_profile(ProtocolProfile::Current),
    }
}

/// A selected Add by another sibling defeats an earlier presence read,
/// including when a device uses different MLS signers for its allocations.
/// Re-check the slot before a direct send and at a queued Add's actual drain.
#[tokio::test]
async fn a_sibling_added_while_its_add_waits_is_not_added_again_at_drain() {
    // Exercise authenticated-slot detection with both orientations of distinct MLS signers.
    for existing_uses_distinct_mls_key in [false, true] {
        // Send preflight reads this same clock. Slow setup must not settle
        // the rival before this test has queued the losing Add (mdk#2892).
        let clock = manual_convergence_clock();
        let (mut phone, mut devices, device_group) = tag_devices(vec![
            clocked_roster_device(b"bob", &clock),
            roster_device(b"bob"),
            roster_device(b"bob"),
        ])
        .await;
        let mut laptop = devices.remove(0);
        let mut tablet = devices.remove(0);
        let mut alice = chat_device(b"alice");
        let gid = found_routed_group(&mut alice, &mut [&mut phone, &mut tablet]).await;
        let template = handed(&mut laptop, slot(2), slot(1));
        let roster = super::device_roster::roster_of(&phone, &device_group);
        let candidate = if existing_uses_distinct_mls_key {
            template
        } else {
            with_another_mls_key(&laptop, &template, &roster)
        };
        assert_eq!(
            phone.engine.sibling_add_refusal(&gid, &candidate).unwrap(),
            None
        );
        let first = handed(&mut laptop, slot(2), slot(3));
        let first = if existing_uses_distinct_mls_key {
            with_another_mls_key(&laptop, &first, &roster)
        } else {
            first
        };
        let add = send_commit(&mut tablet, add_own_devices(&gid, vec![first]), &gid).await;
        phone
            .engine
            .buffer_openmls_convergence_message_at(&gid, add, 1_000)
            .unwrap();
        let SendResult::Queued { intent_id, .. } = phone
            .engine
            .send(add_own_devices(&gid, vec![candidate.clone()]))
            .await
            .unwrap()
        else {
            panic!("expected the Add to queue while the competing Add settles")
        };
        clock.advance_ms(999_000);
        phone
            .engine
            .converge_stored_openmls_messages_at(&gid, 1_000_000)
            .unwrap();
        phone.engine.drain_events();
        clock.advance_ms(100);
        let prepared = phone
            .engine
            .converge_and_drain_queued_outbound_intents(&gid, 1_000_100)
            .await
            .unwrap();
        assert_eq!(prepared.len(), 0, "a stale queued Add must stage no Commit");
        assert!(
            phone
                .storage
                .list_queued_outbound_intents(&gid)
                .unwrap()
                .is_empty()
        );
        assert!(phone.engine.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::QueuedIntentRefused { intent_id: refused, .. } if *refused == intent_id
        )));
        assert!(sibling_rows(&phone, &gid).is_empty());
        assert_eq!(
            phone.engine.sibling_add_refusal(&gid, &candidate).unwrap(),
            Some(SiblingAddRefusal::KeyPackage),
            "the selected tree already holds this sibling under another MLS key"
        );
        assert_refused(
            phone
                .engine
                .send(add_own_devices(&gid, vec![candidate]))
                .await,
            "the chat already holds the sibling",
        );
    }
}

/// A chat can predate device-group tagging. Its old untagged leaf still
/// names the linked device by the roster's signature key.
#[tokio::test]
async fn an_untagged_existing_sibling_is_refused_until_its_leaf_is_removed() {
    let mut alice = chat_device(b"alice");
    let mut phone = roster_device(b"bob");
    let mut laptop = roster_device(b"bob");
    let gid = found_routed_group(&mut alice, &mut [&mut phone, &mut laptop]).await;
    let laptop_index = load_group(&laptop, &gid).own_leaf_index();
    let (mut phone, mut siblings, device_group) = tag_devices(vec![phone, laptop]).await;
    let mut laptop = siblings.remove(0);
    let roster = super::device_roster::roster_of(&phone, &device_group);
    let group = load_group(&phone, &gid);
    let leaf = group.public_group().leaf(laptop_index).unwrap();
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(leaf, &roster),
        cgka_traits::app_components::DeviceTagClaim::Unclaimed
    );
    assert_eq!(
        Some(leaf.signature_key().as_slice()),
        roster.devices[&slot(2)].tag_signature_key.as_deref()
    );
    let candidate = handed(&mut laptop, slot(2), slot(1));
    assert_eq!(
        cgka_engine::device_tag::device_tag_claim(
            parse_key_package(&candidate.key_package).leaf_node(),
            &roster,
        ),
        cgka_traits::app_components::DeviceTagClaim::Device(slot(2))
    );
    let before = Untouched::of(&phone, &gid);
    let before_rows = rows(&phone, &gid);
    assert_eq!(
        phone.engine.sibling_add_refusal(&gid, &candidate).unwrap(),
        Some(SiblingAddRefusal::KeyPackage)
    );
    assert_other_error(
        phone
            .engine
            .send(add_own_devices(&gid, vec![candidate.clone()]))
            .await,
        "adding a sibling: the chat already holds the sibling",
    );
    assert_eq!(Untouched::of(&phone, &gid), before);
    assert_eq!(rows(&phone, &gid), before_rows);
    assert!(
        phone
            .storage
            .list_queued_outbound_intents(&gid)
            .unwrap()
            .is_empty()
    );

    let laptop_key = signature_key(&laptop, &gid);
    let remove = send_commit(&mut phone, remove_own_devices(&gid, vec![laptop_key]), &gid).await;
    assert_accepted(&mut alice, &remove, &gid).await;
    assert_accepted(&mut laptop, &remove, &gid).await;
    assert!(laptop.engine.group_record(&gid).unwrap().removed);
    assert_eq!(
        phone.engine.sibling_add_refusal(&gid, &candidate).unwrap(),
        None
    );
    let add = send_commit(&mut phone, add_own_devices(&gid, vec![candidate]), &gid).await;
    assert_accepted(&mut alice, &add, &gid).await;
    let [welcome] = &owed(&phone)[..] else {
        panic!("one owed sibling Welcome")
    };
    assert_joins_from(&mut laptop, welcome, &gid, &phone).await;
}

/// `device`'s sibling Welcome rows in `gid`.
fn sibling_rows(device: &Device, gid: &GroupId) -> Vec<(MessageState, StoredMessagePayload)> {
    device
        .storage
        .list_messages(gid, EpochId(0))
        .unwrap()
        .into_iter()
        .filter_map(|record| {
            let payload = StoredMessagePayload::decode(&record.payload).ok()?;
            matches!(
                payload,
                StoredMessagePayload::StagedSiblingWelcome { .. }
                    | StoredMessagePayload::OutboundSiblingWelcome { .. }
            )
            .then_some((record.state, payload))
        })
        .collect()
}

fn rows(device: &Device, gid: &GroupId) -> Vec<MessageRecord> {
    device.storage.list_messages(gid, EpochId(0)).unwrap()
}

/// bob adds his laptop to the chat. The Commit stages a sibling Welcome
/// instead of a transport Welcome, owed only once the Commit confirms: the
/// encoded `SiblingWelcome` from bob's slot to the laptop's, naming the
/// handed KeyPackage and the chat's relay. Every member accepts the Commit,
/// and the laptop joins through the sibling Welcome, consuming the private
/// KeyPackage.
#[tokio::test]
async fn a_sibling_add_owes_its_sibling_welcome_once_its_commit_confirms() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let laptop = &mut new[0];
    let sibling = handed(laptop, slot(2), slot(1));
    let SendResult::GroupEvolution {
        msg,
        welcomes,
        pending,
    } = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![sibling.clone()]))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    assert!(welcomes.is_empty(), "{welcomes:?}");
    assert!(owed(&m.bob).is_empty());
    let [(MessageState::Sent, StoredMessagePayload::StagedSiblingWelcome { .. })] =
        &sibling_rows(&m.bob, &gid)[..]
    else {
        panic!("one staged sibling Welcome")
    };

    m.bob.engine.confirm_published(pending).await.unwrap();
    let [owed] = &owed(&m.bob)[..] else {
        panic!("one owed sibling Welcome")
    };
    assert_eq!((&owed.group_id, &owed.carrier), (&gid, &None));
    let welcome = SiblingWelcome::decode(&owed.content).unwrap();
    assert_eq!(
        (welcome.from, welcome.to, welcome.relays),
        (slot(1), slot(2), vec![RELAY.to_string()])
    );
    assert_eq!(
        welcome.key_package_ref,
        key_package_ref(&sibling.key_package)
    );

    let add = route_to_group(&msg, &gid);
    for member in [&mut m.alice, &mut m.bob_sibling, &mut m.carol] {
        assert_accepted(member, &add, &gid).await;
    }
    assert_joins_from(laptop, owed, &gid, &m.bob).await;
    assert!(
        laptop
            .engine
            .issued_private_key_packages()
            .unwrap()
            .is_empty()
    );
}

/// The host records a 461's app event id on the row before its send. A
/// second carrier is refused while one is on its way; only the carrier that
/// failed clears, and the row is owed again; only the carrier that went out
/// marks it delivered, and a delivered row is owed no more.
#[tokio::test]
async fn a_sibling_welcome_is_delivered_only_by_its_carrier() {
    let (mut m, mut new) = siblings(2).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let [owed_now] = &owed(&m.bob)[..] else {
        panic!("one owed sibling Welcome")
    };
    let id = &owed_now.id;
    let engine = &m.bob.engine;

    assert!(engine.carried_sibling_welcomes().unwrap().is_empty());
    assert!(engine.carry_sibling_welcome(id, b"first").unwrap());
    assert_eq!(
        engine.carried_sibling_welcomes().unwrap(),
        vec![(id.clone(), b"first".to_vec())]
    );
    assert!(!engine.carry_sibling_welcome(id, b"second").unwrap());
    assert_eq!(owed(&m.bob)[0].carrier.as_deref(), Some(&b"first"[..]));
    assert!(!engine.sibling_welcome_send_failed(id, b"second").unwrap());
    assert!(!engine.sibling_welcome_delivered(id, b"second").unwrap());
    assert!(engine.sibling_welcome_send_failed(id, b"first").unwrap());
    assert_eq!(owed(&m.bob)[0].carrier, None);
    assert!(engine.carried_sibling_welcomes().unwrap().is_empty());

    assert!(engine.carry_sibling_welcome(id, b"second").unwrap());
    assert_eq!(
        engine.carried_sibling_welcomes().unwrap(),
        vec![(id.clone(), b"second".to_vec())]
    );
    assert!(!engine.sibling_welcome_delivered(id, b"first").unwrap());
    assert!(engine.sibling_welcome_delivered(id, b"second").unwrap());
    assert!(owed(&m.bob).is_empty());
    assert!(engine.carried_sibling_welcomes().unwrap().is_empty());
    assert!(!engine.carry_sibling_welcome(id, b"third").unwrap());
    assert!(!engine.sibling_welcome_send_failed(id, b"second").unwrap());
    let [(MessageState::Processed, _)] = &sibling_rows(&m.bob, &gid)[..] else {
        panic!("one delivered sibling Welcome")
    };

    // A second genuine Add has its own obligation, after every original
    // carrier-outcome assertion above. Its withdrawal is read by the
    // carried list before any other caller can retire it.
    let sibling = handed(&mut new[1], slot(3), slot(1));
    let commit = send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let [next] = &owed(&m.bob)[..] else {
        panic!("one new sibling Welcome")
    };
    let next_id = next.id.clone();
    assert_ne!(next_id, *id);
    let StoredMessagePayload::OutboundSiblingWelcome {
        origin: cgka_traits::message::SiblingWelcomeOrigin::ConfirmedCommit(origin),
        ..
    } = StoredMessagePayload::decode(&m.bob.storage.get_message(&next_id).unwrap().payload)
        .unwrap()
    else {
        panic!("the second Add has its own confirmed origin")
    };
    assert_eq!(origin, commit.id);
    assert!(
        m.bob
            .engine
            .carry_sibling_welcome(&next_id, b"withdrawn")
            .unwrap()
    );
    assert_eq!(
        m.bob.engine.carried_sibling_welcomes().unwrap(),
        vec![(next_id.clone(), b"withdrawn".to_vec())]
    );
    m.bob
        .storage
        .update_message_state(&origin, MessageState::EpochInvalidated)
        .unwrap();
    assert_eq!(
        m.bob.storage.get_message(&next_id).unwrap().state,
        MessageState::Sent
    );
    assert!(m.bob.engine.carried_sibling_welcomes().unwrap().is_empty());
    assert_eq!(
        m.bob.storage.get_message(&next_id).unwrap().state,
        MessageState::Failed
    );
    assert_eq!(
        m.bob.storage.get_message(id).unwrap().state,
        MessageState::Processed
    );
}

/// A forensic state row: the message id, the state it left, the state it
/// entered and its epoch.
type StateRow = (String, Option<String>, String, Option<u64>);

/// The forensic rows naming one message's state changes.
#[derive(Clone, Default)]
struct StateRows(Arc<Mutex<Vec<StateRow>>>);

impl StateRows {
    fn of(&self, id: &MessageId) -> Vec<(Option<String>, String, Option<u64>)> {
        let id = hex::encode(id.as_slice());
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(msg_id, ..)| *msg_id == id)
            .map(|(_, previous, new, epoch)| (previous.clone(), new.clone(), *epoch))
            .collect()
    }
}

impl marmot_forensics::ForensicRecorder for StateRows {
    fn record(&self, record: marmot_forensics::AuditRecord) {
        if let marmot_forensics::AuditEventKind::MessageStateChanged {
            msg_id,
            previous_state,
            new_state,
            epoch,
            ..
        } = record.kind
        {
            self.0
                .lock()
                .unwrap()
                .push((msg_id, previous_state, new_state, epoch));
        }
    }
}

/// A delivered sibling Welcome writes the forensic row an invite Welcome's
/// state change writes: from sent to processed, at its epoch. Carrying it
/// and clearing a failed carrier change no state and write none.
#[tokio::test]
async fn a_delivered_sibling_welcome_writes_its_state_row() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let Device { engine, storage } = m.bob;
    drop(engine);
    let state_rows = StateRows::default();
    let mut bob = super::device_roster::recorded_roster_device_on(
        storage,
        b"bob",
        Box::new(state_rows.clone()),
    );
    bob.engine.hydrate_all_stored_groups().unwrap();
    let [owed_now] = &owed(&bob)[..] else {
        panic!("one owed sibling Welcome")
    };
    let id = owed_now.id.clone();
    let epoch = bob.storage.get_message(&id).unwrap().epoch.0;

    assert!(bob.engine.carry_sibling_welcome(&id, b"first").unwrap());
    assert!(
        bob.engine
            .sibling_welcome_send_failed(&id, b"first")
            .unwrap()
    );
    assert!(bob.engine.carry_sibling_welcome(&id, b"second").unwrap());
    assert!(state_rows.of(&id).is_empty());
    assert!(
        bob.engine
            .sibling_welcome_delivered(&id, b"second")
            .unwrap()
    );
    assert_eq!(
        state_rows.of(&id),
        vec![(Some("sent".into()), "processed".into(), Some(epoch))]
    );
}

/// A sibling Welcome is owed until its KeyPackage expires, when the sibling
/// drops the key. From then on nothing sends it; its row stays as it is, as
/// an invite Welcome's does past its deadline.
#[tokio::test]
async fn a_sibling_welcome_is_owed_until_its_key_package_expires() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    let not_after = cgka_engine::key_package::key_package_metadata(&sibling.key_package)
        .unwrap()
        .not_after;
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let owed_at = |now| m.bob.engine.owed_sibling_welcomes(Timestamp(now)).unwrap();
    assert_eq!(owed_at(not_after - 1).len(), 1);
    assert!(owed_at(not_after).is_empty());
    let selected = owed_at(not_after - 1).remove(0);
    m.bob = reopen_at_time(m.bob, b"bob", not_after);
    assert!(
        !m.bob
            .engine
            .carry_sibling_welcome(&selected.id, b"expired-carrier")
            .unwrap(),
        "a Welcome selected before expiry cannot acquire a new carrier at expiry"
    );
    let record = m.bob.storage.get_message(&selected.id).unwrap();
    assert!(matches!(
        cgka_traits::StoredMessagePayload::decode(&record.payload).unwrap(),
        cgka_traits::StoredMessagePayload::OutboundSiblingWelcome { carrier: None, .. }
    ));
}

/// A disbanded chat owes no sibling Welcome: its sibling would join a group
/// every other member has left.
#[tokio::test]
async fn a_disbanded_chat_owes_no_sibling_welcome() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    let add = send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    assert_eq!(owed(&m.bob).len(), 1);
    assert_accepted(&mut m.alice, &add, &gid).await;
    let SendResult::DisbandRequested { .. } = m
        .alice
        .engine
        .send(SendIntent::Disband {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected a disband request")
    };
    let [SendResult::GroupEvolution { msg, pending, .. }] =
        &m.alice.engine.advance_convergence(&gid).await.unwrap()[..]
    else {
        panic!("expected the disband commit")
    };
    m.alice.engine.confirm_published(*pending).await.unwrap();
    let disband = route_to_group(msg, &gid);
    m.bob.engine.ingest(disband).await.unwrap();
    m.bob
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert!(m.bob.storage.get_group(&gid).unwrap().disbanded.is_some());
    assert!(owed(&m.bob).is_empty());
}

/// A sibling Welcome fails with its Commit: when the publish fails, and when
/// a restart rolls back the staged Commit. Neither is ever owed.
#[tokio::test]
async fn a_sibling_welcome_fails_with_its_commit() {
    let (mut m, mut new) = siblings(2).await;
    let gid = m.gid.clone();
    let laptop = handed(&mut new[0], slot(2), slot(1));
    let tablet = handed(&mut new[1], slot(3), slot(1));

    let SendResult::GroupEvolution { pending, .. } = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![laptop]))
        .await
        .unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    m.bob.engine.publish_failed(pending).await.unwrap();
    assert!(owed(&m.bob).is_empty());
    let [(MessageState::Failed, _)] = &sibling_rows(&m.bob, &gid)[..] else {
        panic!("one failed sibling Welcome")
    };

    m.bob
        .engine
        .send(add_own_devices(&gid, vec![tablet]))
        .await
        .unwrap();
    let Device { engine, storage } = m.bob;
    drop(engine);
    let mut bob = super::device_roster::roster_device_on(storage, b"bob");
    bob.engine.hydrate_all_stored_groups().unwrap();
    assert!(load_group(&bob, &gid).pending_commit().is_none());
    assert!(owed(&bob).is_empty());
    let states: Vec<_> = sibling_rows(&bob, &gid)
        .into_iter()
        .map(|(state, _)| state)
        .collect();
    assert_eq!(states, vec![MessageState::Failed; 2]);
}

/// A losing Add can still be selected again. A reopen keeps its Welcome
/// held, without publishing it or permanently retiring it from a lost event.
#[tokio::test]
async fn a_losing_sibling_add_holds_its_welcome_across_restart() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let rival = send_commit(
        &mut m.alice,
        SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("selected branch".into()),
            description: None,
        },
        &gid,
    )
    .await;
    let sibling = handed(&mut new[0], slot(2), slot(1));
    let own = send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let id = owed(&m.bob)[0].id.clone();
    assert!(m.bob.engine.carry_sibling_welcome(&id, b"carrier").unwrap());
    let Device { engine, storage } = m.bob;
    drop(engine);
    m.bob = super::device_roster::roster_device_on(storage, b"bob");
    assert!(
        owed(&m.bob).is_empty(),
        "unhydrated state holds rather than withdraws"
    );
    assert_eq!(
        m.bob.storage.get_message(&id).unwrap().state,
        MessageState::Sent
    );
    m.bob.engine.hydrate_all_stored_groups().unwrap();
    assert_eq!(owed(&m.bob)[0].carrier.as_deref(), Some(&b"carrier"[..]));
    m.bob.engine.ingest(rival).await.unwrap();
    m.bob
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    assert_eq!(
        m.bob.engine.stored_message_state(&own.id).unwrap(),
        Some(MessageState::ConvergenceDeferred)
    );
    let Device { engine, storage } = m.bob;
    drop(engine);
    let mut bob = super::device_roster::roster_device_on(storage, b"bob");
    bob.engine.hydrate_all_stored_groups().unwrap();
    assert!(owed(&bob).is_empty());
    assert_eq!(
        bob.storage.get_message(&id).unwrap().state,
        MessageState::Sent
    );
    assert!(!bob.engine.carry_sibling_welcome(&id, b"new").unwrap());
    assert!(
        bob.engine
            .sibling_welcome_delivered(&id, b"carrier")
            .unwrap()
    );
    assert_eq!(
        bob.storage.get_message(&id).unwrap().state,
        MessageState::Processed
    );
}

/// Missing evidence and an unsettled chat hold new delivery. Proven terminal
/// invalidation retires the row durably, even if the origin later reads live.
#[tokio::test]
async fn sibling_welcome_origin_unknown_and_settling_hold_but_terminal_retires_after_reopen() {
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let id = owed(&m.bob)[0].id.clone();
    let StoredMessagePayload::OutboundSiblingWelcome {
        origin: cgka_traits::message::SiblingWelcomeOrigin::ConfirmedCommit(origin),
        ..
    } = StoredMessagePayload::decode(&m.bob.storage.get_message(&id).unwrap().payload).unwrap()
    else {
        panic!("expected a confirmed Add origin");
    };
    let commit = m.bob.storage.get_message(&origin).unwrap();
    assert!(
        m.bob
            .engine
            .carry_sibling_welcome(&id, b"before-unknown")
            .unwrap()
    );
    m.bob.storage.delete_message(&origin).unwrap();
    assert!(owed(&m.bob).is_empty());
    assert_eq!(
        m.bob.engine.carried_sibling_welcomes().unwrap(),
        vec![(id.clone(), b"before-unknown".to_vec())]
    );
    let Device { engine, storage } = m.bob;
    drop(engine);
    m.bob = super::device_roster::roster_device_on(storage, b"bob");
    m.bob.engine.hydrate_all_stored_groups().unwrap();
    assert!(owed(&m.bob).is_empty());
    assert_eq!(
        m.bob.engine.carried_sibling_welcomes().unwrap(),
        vec![(id.clone(), b"before-unknown".to_vec())]
    );
    assert!(
        m.bob
            .engine
            .sibling_welcome_send_failed(&id, b"before-unknown")
            .unwrap()
    );
    assert!(m.bob.engine.carried_sibling_welcomes().unwrap().is_empty());
    assert_eq!(
        m.bob.storage.get_message(&id).unwrap().state,
        MessageState::Sent
    );
    assert!(!m.bob.engine.carry_sibling_welcome(&id, b"unknown").unwrap());
    m.bob.storage.put_message(&commit).unwrap();
    assert_eq!(owed(&m.bob).len(), 1);
    assert!(
        m.bob
            .engine
            .carry_sibling_welcome(&id, b"before-settling")
            .unwrap()
    );
    let SendResult::GroupEvolution { pending, .. } = m
        .bob
        .engine
        .send(SendIntent::SelfUpdate { group_id: gid })
        .await
        .unwrap()
    else {
        panic!("expected a pending Commit");
    };
    assert!(owed(&m.bob).is_empty());
    assert_eq!(
        m.bob.engine.carried_sibling_welcomes().unwrap(),
        vec![(id.clone(), b"before-settling".to_vec())]
    );
    assert!(
        m.bob
            .engine
            .sibling_welcome_send_failed(&id, b"before-settling")
            .unwrap()
    );
    assert!(m.bob.engine.carried_sibling_welcomes().unwrap().is_empty());
    assert!(
        !m.bob
            .engine
            .carry_sibling_welcome(&id, b"settling")
            .unwrap()
    );
    m.bob.engine.publish_failed(pending).await.unwrap();
    assert_eq!(owed(&m.bob).len(), 1);
    assert!(owed(&m.bob)[0].carrier.is_none());
    m.bob
        .storage
        .update_message_state(&origin, MessageState::EpochInvalidated)
        .unwrap();
    assert!(owed(&m.bob).is_empty());
    assert_eq!(
        m.bob.storage.get_message(&id).unwrap().state,
        MessageState::Failed
    );
    assert!(m.bob.engine.carried_sibling_welcomes().unwrap().is_empty());
    let Device { engine, storage } = m.bob;
    drop(engine);
    let mut bob = super::device_roster::roster_device_on(storage, b"bob");
    bob.engine.hydrate_all_stored_groups().unwrap();
    bob.storage.put_message(&commit).unwrap();
    assert!(owed(&bob).is_empty());
    assert!(bob.engine.carried_sibling_welcomes().unwrap().is_empty());
    assert_eq!(
        bob.storage.get_message(&id).unwrap().state,
        MessageState::Failed
    );
    assert!(!bob.engine.carry_sibling_welcome(&id, b"retired").unwrap());
}

/// Development binaries once discarded an outbound Welcome's origin. Such
/// persisted rows cannot guess that their Add remains selected after upgrade.
#[tokio::test]
async fn an_unproven_development_sibling_welcome_is_not_handed_off_after_reopen() {
    use cgka_traits::message::SiblingWelcomeOrigin;
    let (mut m, mut new) = siblings(1).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    send_commit(&mut m.bob, add_own_devices(&gid, vec![sibling]), &gid).await;
    let id = owed(&m.bob)[0].id.clone();
    let mut record = m.bob.storage.get_message(&id).unwrap();
    let mut legacy = StoredMessagePayload::decode(&record.payload).unwrap();
    let StoredMessagePayload::OutboundSiblingWelcome {
        origin, carrier, ..
    } = &mut legacy
    else {
        panic!("one outbound sibling Welcome");
    };
    assert!(carrier.is_none());
    *origin = SiblingWelcomeOrigin::LegacyUnproven;
    record.payload = legacy.encode().unwrap();
    m.bob.storage.put_message(&record).unwrap();
    let Device { engine, storage } = m.bob;
    drop(engine);
    let mut bob = super::device_roster::roster_device_on(storage, b"bob");
    bob.engine.hydrate_all_stored_groups().unwrap();
    assert!(owed(&bob).is_empty());
    assert_eq!(
        bob.storage.get_message(&id).unwrap().state,
        MessageState::Failed
    );
    assert!(bob.engine.carried_sibling_welcomes().unwrap().is_empty());
    assert!(!bob.engine.carry_sibling_welcome(&id, b"new").unwrap());
}

/// Each sibling Add the sender cannot back with a sibling Welcome is refused
/// before anything is written: the chat's rows, record and epoch stay as they
/// were, and no Commit is left staged, so a valid Add still goes through.
/// The pre-check a host runs before it takes a KeyPackage names each refusal
/// of one sibling, writing nothing either, and passes the valid Add.
#[tokio::test]
async fn a_sibling_add_refused_for_its_welcome_writes_nothing() {
    let (bob, mut new, device_gid) = tagged_devices(b"bob", 2).await;
    let mut m = routed_members(chat_device(b"alice"), bob).await;
    let gid = m.gid.clone();
    let laptop = handed(&mut new[0], slot(2), slot(1));
    let tablet = handed(&mut new[1], slot(3), slot(1));
    let named = |sibling: &SiblingKeyPackage, n: u8| SiblingKeyPackage {
        slot: slot(n),
        ..sibling.clone()
    };
    let published = SiblingKeyPackage {
        key_package: KeyPackage {
            source: Some(KeyPackageSource {
                event_id: hash_id(b"published"),
            }),
            ..laptop.key_package.clone()
        },
        ..laptop.clone()
    };
    let untagged = SiblingKeyPackage {
        slot: slot(2),
        key_package: new_sibling_key_package(&mut m.bob, b"bob").await,
    };
    // The laptop's own last-resort KeyPackage carries its tag and names no
    // publication, but no sibling hands one over.
    let last_resort = SiblingKeyPackage {
        slot: slot(2),
        key_package: new[0]
            .engine
            .fresh_key_package()
            .await
            .unwrap()
            .with_protocol_profile(ProtocolProfile::Current),
    };
    // Its profile is not the chat's.
    let legacy = SiblingKeyPackage {
        key_package: laptop
            .key_package
            .clone()
            .with_protocol_profile(ProtocolProfile::Legacy),
        ..laptop.clone()
    };
    let before = (Untouched::of(&m.bob, &gid), rows(&m.bob, &gid));
    let assert_untouched = |bob: &Device| {
        assert_eq!((Untouched::of(bob, &gid), rows(bob, &gid)), before);
    };
    let pre_check = |bob: &Device, chat: &GroupId, sibling: &SiblingKeyPackage| {
        bob.engine.sibling_add_refusal(chat, sibling).unwrap()
    };
    for (siblings, reason) in [
        (
            vec![published],
            "a published KeyPackage never adds a sibling",
        ),
        (vec![named(&laptop, 1)], "the named slot is this device's"),
        (
            vec![laptop.clone(), named(&tablet, 2)],
            "two KeyPackages name the same sibling",
        ),
        (vec![named(&tablet, 2)], "not tagged as the sender's"),
        (vec![named(&laptop, 9)], "not tagged as the sender's"),
        (vec![untagged], "not tagged as the sender's"),
        (vec![last_resort], "last resort"),
        (
            vec![legacy],
            "says Legacy, but its decoded account proof is Current",
        ),
    ] {
        if let [sibling] = &siblings[..] {
            assert_eq!(
                pre_check(&m.bob, &gid, sibling),
                Some(SiblingAddRefusal::KeyPackage),
                "{reason}"
            );
            assert_untouched(&m.bob);
        }
        assert_refused(
            m.bob.engine.send(add_own_devices(&gid, siblings)).await,
            reason,
        );
        assert_untouched(&m.bob);
    }

    // bob is not tagged: his slot is not in the roster, or he names no
    // device group.
    hold_slot(&m.bob, slot(9));
    assert_eq!(
        pre_check(&m.bob, &gid, &laptop),
        Some(SiblingAddRefusal::NotTagged)
    );
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&gid, vec![laptop.clone()]))
            .await,
        "this device is not tagged in a trusted device group",
    );
    assert_untouched(&m.bob);
    hold_slot(&m.bob, slot(1));
    m.bob.engine.set_device_tag_group(None).unwrap();
    assert_eq!(
        pre_check(&m.bob, &gid, &laptop),
        Some(SiblingAddRefusal::NotTagged)
    );
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&gid, vec![laptop.clone()]))
            .await,
        "this device is not tagged in a trusted device group",
    );
    assert_untouched(&m.bob);
    m.bob.engine.set_device_tag_group(Some(device_gid)).unwrap();

    // A chat that names no relay.
    let mut alice = chat_device(b"alice");
    let bob_kp = m.bob.engine.fresh_key_package().await.unwrap();
    let unrouted = found_group(&mut alice, vec![bob_kp], true, &mut [&mut m.bob]).await;
    let unrouted_before = (Untouched::of(&m.bob, &unrouted), rows(&m.bob, &unrouted));
    for refusal in [
        pre_check(&m.bob, &unrouted, &laptop),
        m.bob.engine.chat_sibling_add_refusal(&unrouted).unwrap(),
    ] {
        assert_eq!(refusal, Some(SiblingAddRefusal::ChatRelays));
    }
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&unrouted, vec![laptop.clone()]))
            .await,
        "the chat must name one to 16 relays, none repeated once parsed",
    );
    assert_eq!(
        (Untouched::of(&m.bob, &unrouted), rows(&m.bob, &unrouted)),
        unrouted_before
    );

    // A chat that names one relay twice, spelled two ways: the sibling's
    // admission parses them as one and would refuse the Welcome.
    let mut alice = chat_device(b"alice");
    let twice = found_group_routed_through(
        &mut alice,
        &mut [&mut m.bob],
        &[RELAY, &format!("{RELAY}/")],
    )
    .await;
    let twice_before = (Untouched::of(&m.bob, &twice), rows(&m.bob, &twice));
    for refusal in [
        pre_check(&m.bob, &twice, &laptop),
        m.bob.engine.chat_sibling_add_refusal(&twice).unwrap(),
    ] {
        assert_eq!(refusal, Some(SiblingAddRefusal::ChatRelays));
    }
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&twice, vec![laptop.clone()]))
            .await,
        "none repeated once parsed",
    );
    assert_eq!(
        (Untouched::of(&m.bob, &twice), rows(&m.bob, &twice)),
        twice_before
    );

    // A chat that does not require 0x800d takes no same-account Add.
    let mut alice = chat_device(b"alice");
    let bob_kp = m.bob.engine.fresh_key_package().await.unwrap();
    let legacy_chat = found_group(&mut alice, vec![bob_kp], false, &mut [&mut m.bob]).await;
    let legacy_before = (
        Untouched::of(&m.bob, &legacy_chat),
        rows(&m.bob, &legacy_chat),
    );
    for refusal in [
        pre_check(&m.bob, &legacy_chat, &laptop),
        m.bob.engine.chat_sibling_add_refusal(&legacy_chat).unwrap(),
    ] {
        assert_eq!(refusal, Some(SiblingAddRefusal::AccountDevicesNotRequired));
    }
    assert_not_required(
        m.bob
            .engine
            .send(add_own_devices(&legacy_chat, vec![laptop.clone()]))
            .await,
    );
    assert_eq!(
        (
            Untouched::of(&m.bob, &legacy_chat),
            rows(&m.bob, &legacy_chat)
        ),
        legacy_before
    );

    // A chat where bob's account holds as many leaves as it may.
    let mut alice = chat_device(b"alice");
    let template = m.bob.engine.fresh_key_package().await.unwrap();
    let full = found_group_routed_with(
        &mut alice,
        &mut [&mut m.bob],
        (1..MAX_LEAVES_PER_ACCOUNT)
            .map(|_| sibling_key_package(&template, b"bob"))
            .collect(),
        &[RELAY],
    )
    .await;
    let full_before = (Untouched::of(&m.bob, &full), rows(&m.bob, &full));
    for refusal in [
        pre_check(&m.bob, &full, &laptop),
        m.bob.engine.chat_sibling_add_refusal(&full).unwrap(),
    ] {
        assert_eq!(refusal, Some(SiblingAddRefusal::AccountLeaves));
    }
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&full, vec![laptop.clone()]))
            .await,
        &limit_error(),
    );
    assert_eq!(
        (Untouched::of(&m.bob, &full), rows(&m.bob, &full)),
        full_before
    );

    assert_eq!(pre_check(&m.bob, &gid, &laptop), None);
    assert_eq!(m.bob.engine.chat_sibling_add_refusal(&gid).unwrap(), None);
    assert_untouched(&m.bob);
    send_commit(
        &mut m.bob,
        add_own_devices(&gid, vec![laptop, tablet]),
        &gid,
    )
    .await;
    assert_eq!(owed(&m.bob).len(), 2);
}

/// A sibling whose KeyPackage does not advertise everything the chat
/// requires, as an older app's would not, cannot be added there. The
/// pre-check names it before a host takes the KeyPackage, though the chat
/// itself takes same-account Adds, and the send refuses it, writing nothing.
#[tokio::test]
async fn a_sibling_add_the_chat_requires_more_for_is_named_by_the_pre_check() {
    let older = device_advertising(
        b"bob",
        &[ACCOUNT_DEVICES_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID],
        Box::<MockPeeler>::default(),
    );
    let (bob, mut new, _) = tag_devices(vec![roster_device(b"bob"), older]).await;
    let mut m = routed_members(chat_device(b"alice"), bob).await;
    let gid = m.gid.clone();
    let sibling = handed(&mut new[0], slot(2), slot(1));
    let before = (Untouched::of(&m.bob, &gid), rows(&m.bob, &gid));

    assert_eq!(m.bob.engine.chat_sibling_add_refusal(&gid).unwrap(), None);
    assert_eq!(
        m.bob.engine.sibling_add_refusal(&gid, &sibling).unwrap(),
        Some(SiblingAddRefusal::KeyPackage)
    );
    let refused = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![sibling]))
        .await;
    assert!(
        matches!(
            refused,
            Err(EngineError::MissingRequiredCapabilities { .. })
        ),
        "{refused:?}"
    );
    assert_eq!((Untouched::of(&m.bob, &gid), rows(&m.bob, &gid)), before);
}

/// A same-account Add sent while the chat's convergence is pending is
/// checked as a direct send would be before it is queued, so one a direct
/// send would refuse is refused at once, with nothing written or queued.
/// One that passes is queued and checked again when the drain prepares it:
/// with bob's tag gone by then, the drain refuses it as `QueuedIntentRefused`
/// and retires it with its KeyPackage, staging no sibling Welcome.
#[tokio::test]
async fn a_queued_sibling_add_is_checked_before_the_queue_and_at_drain() {
    let clock = manual_convergence_clock();
    let bob = clocked_roster_device(b"bob", &clock);
    let (bob, mut new, _) = tag_devices(vec![bob, roster_device(b"bob")]).await;
    let mut m = routed_members(chat_device(b"alice"), bob).await;
    let gid = m.gid.clone();
    let laptop = handed(&mut new[0], slot(2), slot(1));
    let published = SiblingKeyPackage {
        key_package: KeyPackage {
            source: Some(KeyPackageSource {
                event_id: hash_id(b"published"),
            }),
            ..laptop.key_package.clone()
        },
        ..laptop.clone()
    };
    let carol_update = send_commit(
        &mut m.carol,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    m.bob
        .engine
        .buffer_openmls_convergence_message_at(&gid, carol_update, 1_000)
        .unwrap();
    let queued = |bob: &Device| bob.storage.list_queued_outbound_intents(&gid).unwrap();
    let before = (Untouched::of(&m.bob, &gid), rows(&m.bob, &gid));

    assert_other_error(
        m.bob.engine.send(add_own_devices(&gid, vec![])).await,
        "adding own account devices requires at least one KeyPackage",
    );
    assert_eq!((Untouched::of(&m.bob, &gid), rows(&m.bob, &gid)), before);
    assert!(queued(&m.bob).is_empty());
    assert_refused(
        m.bob
            .engine
            .send(add_own_devices(&gid, vec![published]))
            .await,
        "a published KeyPackage never adds a sibling",
    );
    assert_eq!((Untouched::of(&m.bob, &gid), rows(&m.bob, &gid)), before);
    assert!(queued(&m.bob).is_empty());

    let SendResult::Queued { intent_id, .. } = m
        .bob
        .engine
        .send(add_own_devices(&gid, vec![laptop]))
        .await
        .unwrap()
    else {
        panic!("expected the Add to queue")
    };
    assert_eq!(queued(&m.bob).len(), 1);

    m.bob.engine.set_device_tag_group(None).unwrap();
    clock.advance_ms(999_000);
    m.bob
        .engine
        .converge_stored_openmls_messages_at(&gid, 1_000_000)
        .unwrap();
    m.bob.engine.drain_events();
    clock.advance_ms(100);
    let prepared = m
        .bob
        .engine
        .converge_and_drain_queued_outbound_intents(&gid, 1_000_100)
        .await
        .unwrap();
    assert!(prepared.is_empty(), "{prepared:?}");
    let refusals: Vec<_> = m
        .bob
        .engine
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::QueuedIntentRefused {
                intent_id,
                intent_kind,
                ..
            } => Some((intent_id, intent_kind)),
            _ => None,
        })
        .collect();
    assert_eq!(
        refusals,
        vec![(intent_id, "add_own_account_devices".to_string())]
    );
    assert!(queued(&m.bob).is_empty());
    assert!(sibling_rows(&m.bob, &gid).is_empty());
    assert!(owed(&m.bob).is_empty());
}

/// Creation's one canonical founding Add retains a sibling's private
/// Welcome separately from the ordinary invitee's transport Welcome. Both
/// receivers join the same epoch, and the private key is consumed only by
/// its sibling route.
#[tokio::test]
async fn a_founding_add_keeps_sibling_and_transport_welcomes_independent() {
    let (mut creator, mut siblings, _) = tagged_devices(b"alice", 1).await;
    let mut other = chat_device(b"bob");
    let public = other.engine.fresh_key_package().await.unwrap();
    let private = handed(&mut siblings[0], slot(2), slot(1));
    let mut unusable = private.clone();
    unusable.key_package.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![7; 32]),
    });
    let request = founding_request(vec![public]);
    let (gid, result) = creator
        .engine
        .create_group_with_siblings_and_audit_context(
            request,
            Vec::new(),
            vec![unusable, private.clone()],
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = result else {
        panic!("canonical founding create")
    };
    assert_eq!(
        welcomes.len(),
        1,
        "only the other account uses transport delivery"
    );
    assert_eq!(creator.engine.group_record(&gid).unwrap().epoch, EpochId(1));
    assert_eq!(creator.engine.members(&gid).unwrap().len(), 3);
    assert!(load_group(&creator, &gid).pending_commit().is_none());
    let deliveries = owed(&creator);
    assert_eq!(deliveries.len(), 1);
    assert_eq!(
        SiblingWelcome::decode(&deliveries[0].content)
            .unwrap()
            .key_package_ref,
        key_package_ref(&private.key_package)
    );
    assert!(matches!(
        &sibling_rows(&creator, &gid)[..],
        [(
            MessageState::Sent,
            StoredMessagePayload::OutboundSiblingWelcome { .. }
        )]
    ));
    assert_eq!(
        other
            .engine
            .join_welcome(welcomes[0].clone())
            .await
            .unwrap(),
        gid
    );
    assert_joins_from(&mut siblings[0], &deliveries[0], &gid, &creator).await;
    assert!(
        siblings[0]
            .engine
            .issued_private_key_packages()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        other.engine.members(&gid).unwrap(),
        creator.engine.members(&gid).unwrap()
    );
}

/// A published KeyPackage never qualifies for the optional private route.
/// Its omission preserves the ordinary founder and its transport Welcome.
#[tokio::test]
async fn an_inadmissible_founding_sibling_does_not_block_other_accounts() {
    let (mut creator, mut siblings, _) = tagged_devices(b"alice", 1).await;
    let mut other = chat_device(b"bob");
    let public = other.engine.fresh_key_package().await.unwrap();
    let mut private = handed(&mut siblings[0], slot(2), slot(1));
    private.key_package.source = Some(KeyPackageSource {
        event_id: MessageId::new(vec![7; 32]),
    });
    let (gid, result) = creator
        .engine
        .create_group_with_siblings_and_audit_context(
            founding_request(vec![public]),
            Vec::new(),
            vec![private],
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = result else {
        panic!("canonical ordinary creation despite optional sibling refusal")
    };
    assert_eq!(welcomes.len(), 1);
    assert_eq!(creator.engine.members(&gid).unwrap().len(), 2);
    assert_eq!(
        other
            .engine
            .join_welcome(welcomes[0].clone())
            .await
            .unwrap(),
        gid
    );
    assert!(sibling_rows(&creator, &gid).is_empty());
    assert!(owed(&creator).is_empty());
}

fn founding_request(members: Vec<KeyPackage>) -> CreateGroupRequest {
    use cgka_traits::app_components::{
        NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
    };
    CreateGroupRequest {
        name: "founding siblings".into(),
        description: String::new(),
        members,
        required_features: Vec::new(),
        initial_admins: Vec::new(),
        app_components: vec![AppComponentData {
            component_id: NOSTR_ROUTING_COMPONENT_ID,
            data: encode_nostr_routing_v1(
                &NostrRoutingV1::new([0x43; 32], vec![RELAY.to_owned()]).unwrap(),
            )
            .unwrap(),
        }],
    }
}

/// Explicit founding siblings never bypass the ordinary founders' component
/// negotiation: if another account's client lacks account-devices, the chat
/// may still be created as before, but never with these sibling additions.
#[tokio::test]
async fn founding_siblings_cannot_bypass_the_other_founders_capabilities() {
    use cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID;
    let (mut creator, mut siblings, _) = tagged_devices(b"alice", 1).await;
    let mut other = device_advertising(
        b"bob",
        &[NOSTR_ROUTING_COMPONENT_ID],
        Box::<MockPeeler>::default(),
    );
    let public = other.engine.fresh_key_package().await.unwrap();
    let private = handed(&mut siblings[0], slot(2), slot(1));
    let request = founding_request(vec![public]);
    let (gid, _) = creator
        .engine
        .create_group_with_siblings_and_audit_context(request, Vec::new(), vec![private], None)
        .await
        .unwrap();
    assert!(!requires_account_devices(&creator.engine, &gid));
    assert_eq!(creator.engine.members(&gid).unwrap().len(), 2);
    assert!(owed(&creator).is_empty());
}

/// Eligibility can end after a caller selected private stock. The engine's
/// authoritative clock omits that sibling before staging; the ordinary
/// founder still receives and joins its canonical Welcome.
#[tokio::test]
async fn a_founding_sibling_expiring_at_engine_admission_is_omitted() {
    let (creator, mut siblings, device_group) = tagged_devices(b"alice", 1).await;
    let private = handed(&mut siblings[0], slot(2), slot(1));
    let not_after = cgka_engine::key_package::key_package_metadata(&private.key_package)
        .unwrap()
        .not_after;
    let mut creator = reopen_at_time(creator, b"alice", not_after);
    creator
        .engine
        .set_device_tag_group(Some(device_group))
        .unwrap();
    let mut other = chat_device(b"bob");
    let public = other.engine.fresh_key_package().await.unwrap();
    let (gid, result) = creator
        .engine
        .create_group_with_siblings_and_audit_context(
            founding_request(vec![public]),
            Vec::new(),
            vec![private],
            None,
        )
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = result else {
        panic!("ordinary founding creation")
    };
    assert_eq!(welcomes.len(), 1);
    assert_eq!(creator.engine.members(&gid).unwrap().len(), 2);
    assert_eq!(
        other
            .engine
            .join_welcome(welcomes[0].clone())
            .await
            .unwrap(),
        gid
    );
    assert!(sibling_rows(&creator, &gid).is_empty());
}

/// The Add's existing tagged KeyPackage leaf does not prove the lost Welcome
/// arrived. Rearm preserves its exact bytes/ref/expiry and makes no Add; only
/// the matching target's real MLS Update or Commit suppresses later repair.
#[tokio::test]
async fn delivered_sibling_welcome_repair_uses_target_participation_not_the_adds_tag() {
    use cgka_engine::SiblingWelcomeResendOutcome::{Complete, Rearmed};
    for target_uses_update_proposal in [false, true] {
        let (mut phone, mut siblings, device_group) = tagged_devices(b"bob", 2).await;
        let mut laptop = siblings.remove(0);
        let mut tablet = siblings.remove(0);
        let gid = found_routed_group(&mut phone, &mut [&mut tablet]).await;
        let roster = super::device_roster::roster_of(&phone, &device_group);
        let candidate = handed(&mut laptop, slot(2), slot(1));
        let add = send_commit(&mut phone, add_own_devices(&gid, vec![candidate]), &gid).await;
        assert_accepted(&mut tablet, &add, &gid).await;
        let original = owed(&phone).remove(0);
        phone
            .engine
            .carry_sibling_welcome(&original.id, b"first")
            .unwrap();
        phone
            .engine
            .sibling_welcome_delivered(&original.id, b"first")
            .unwrap();
        // Another tagged device participates. Account-wide or any-device
        // Update/Commit evidence would incorrectly suppress this repair.
        let tablet_update = send_commit(
            &mut tablet,
            SendIntent::SelfUpdate {
                group_id: gid.clone(),
            },
            &gid,
        )
        .await;
        assert_accepted(&mut phone, &tablet_update, &gid).await;
        assert!(
            phone
                .engine
                .own_account_leaf_claims(&gid, &roster)
                .unwrap()
                .iter()
                .any(|(_, claim)| *claim
                    == cgka_traits::app_components::DeviceTagClaim::Device(slot(2)))
        );
        #[derive(Clone)]
        struct Records(Arc<Mutex<Vec<marmot_forensics::AuditRecord>>>);
        impl marmot_forensics::ForensicRecorder for Records {
            fn record(&self, record: marmot_forensics::AuditRecord) {
                self.0.lock().unwrap().push(record);
            }
        }
        let records = Records(Arc::default());
        phone = reopen_at_time_recording(phone, b"bob", NOW, Some(Box::new(records.clone())));
        let transitions = || {
            records
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|record| {
                    matches!(
                        record.kind,
                        marmot_forensics::AuditEventKind::MessageStateChanged { .. }
                    )
                })
                .count()
        };
        let epoch = phone.engine.epoch(&gid).unwrap();
        let baseline = transitions();
        let store = phone.storage.clone();
        let aborted: Result<(), EngineError> = store.with_transaction(|outer| {
            outer.with_transaction(|_| {
                assert_eq!(
                    phone.engine.rearm_sibling_welcome(
                        &original.id,
                        b"first",
                        Timestamp(NOW),
                        &roster
                    )?,
                    Rearmed
                );
                assert_eq!(
                    transitions(),
                    baseline,
                    "nested write must not append before owning commit"
                );
                Ok::<_, EngineError>(())
            })?;
            Err(EngineError::Other("abort rearm owner".into()))
        });
        assert!(
            matches!(aborted, Err(EngineError::Other(message)) if message == "abort rearm owner")
        );
        assert_eq!(
            transitions(),
            baseline,
            "rolled-back rearm cannot be audited as committed"
        );
        assert_eq!(
            store.get_message(&original.id).unwrap().state,
            MessageState::Processed
        );
        store.with_transaction(|outer| {
            let aborted: Result<(), EngineError> = outer.with_group_savepoint(&gid, "rearm-audit-inner", |_| {
                phone.engine.rearm_sibling_welcome(&original.id, b"first", Timestamp(NOW), &roster)?;
                Err(EngineError::Other("abort inner rearm".into()))
            });
            assert!(matches!(aborted, Err(EngineError::Other(message)) if message == "abort inner rearm"));
            assert_eq!(store.get_message(&original.id).unwrap().state, MessageState::Processed);
            assert_eq!(phone.engine.rearm_sibling_welcome(&original.id, b"first", Timestamp(NOW), &roster)?, Rearmed);
            assert_eq!(transitions(), baseline);
            Ok::<_, EngineError>(())
        }).unwrap();
        assert_eq!(
            transitions(),
            baseline + 1,
            "exactly the committed Processed-to-Sent rearm must be audited"
        );
        let repaired = owed(&phone).remove(0);
        assert_eq!(repaired.content, original.content);
        assert_eq!(repaired.id, original.id);
        assert_eq!(
            phone.engine.epoch(&gid).unwrap(),
            epoch,
            "repair must not make another Add"
        );
        phone
            .engine
            .carry_sibling_welcome(&original.id, b"second")
            .unwrap();
        phone
            .engine
            .sibling_welcome_delivered(&original.id, b"second")
            .unwrap();
        if target_uses_update_proposal {
            assert_eq!(
                phone
                    .engine
                    .rearm_sibling_welcome(&original.id, b"second", Timestamp(NOW), &roster)
                    .unwrap(),
                Rearmed
            );
            assert_eq!(
                phone.storage.get_message(&original.id).unwrap().state,
                MessageState::Sent
            );
        }
        let welcome = SiblingWelcome::decode(&original.content).unwrap();
        assert_eq!(
            laptop
                .engine
                .join_sibling_welcome(&hash_id(&original.content), &welcome, None)
                .await
                .unwrap(),
            cgka_traits::welcome::SiblingWelcomeJoin::Settled(IngestOutcome::Processed)
        );
        // Catch the joiner up with the other device's participation Commit.
        assert_accepted(&mut laptop, &tablet_update, &gid).await;
        if target_uses_update_proposal {
            let crypto = RustCrypto::default();
            let provider = EngineOpenMlsProvider::<SqliteAccountStorage>::new(
                &crypto,
                laptop.storage.mls_storage(),
            );
            let (proposal, _) = load_group(&laptop, &gid)
                .propose_self_update(
                    &provider,
                    &device_signer(&laptop),
                    LeafNodeParameters::default(),
                )
                .unwrap();
            let proposal = group_transport(proposal, &gid, "target-self-update");
            assert_eq!(
                phone.engine.ingest(proposal.clone()).await.unwrap(),
                IngestOutcome::Processed
            );
            let (_, commit) = craft(
                &tablet,
                &gid,
                Parts {
                    by_reference: vec![proposal],
                    ..Parts::default()
                },
            );
            assert_accepted(&mut phone, &commit, &gid).await;
        } else {
            let update = send_commit(
                &mut laptop,
                SendIntent::SelfUpdate {
                    group_id: gid.clone(),
                },
                &gid,
            )
            .await;
            assert_accepted(&mut phone, &update, &gid).await;
        }
        assert_eq!(
            phone
                .engine
                .rearm_sibling_welcome(&original.id, b"second", Timestamp(NOW), &roster)
                .unwrap(),
            Complete,
            "update_proposal={target_uses_update_proposal}"
        );
        assert!(owed(&phone).is_empty());
    }
}

/// Ended metadata cannot outlive an unarmed/rearmed obligation or permit
/// lower-timestamp registration after the host clock rolls backwards.
#[tokio::test]
async fn sibling_welcome_expiry_is_terminal_before_timing_and_highwater_retire() {
    use cgka_engine::SiblingWelcomeResendOutcome::{Complete, Rearmed};
    let (mut phone, mut siblings, device_group) = tagged_devices(b"expiry-owner", 1).await;
    let mut laptop = siblings.remove(0);
    let gid = found_routed_group(&mut phone, &mut []).await;
    let candidate = handed(&mut laptop, slot(2), slot(1));
    send_commit(&mut phone, add_own_devices(&gid, vec![candidate]), &gid).await;
    let original = owed(&phone).remove(0);
    phone
        .engine
        .carry_sibling_welcome(&original.id, b"first")
        .unwrap();
    phone
        .engine
        .sibling_welcome_delivered(&original.id, b"first")
        .unwrap();
    let roster = super::device_roster::roster_of(&phone, &device_group);
    assert_eq!(
        phone
            .engine
            .rearm_sibling_welcome(&original.id, b"first", Timestamp(NOW), &roster)
            .unwrap(),
        Rearmed
    );
    let record = phone.storage.get_message(&original.id).unwrap();
    let StoredMessagePayload::OutboundSiblingWelcome { deliver_until, .. } =
        StoredMessagePayload::decode(&record.payload).unwrap()
    else {
        panic!("retained welcome");
    };
    let storage = phone.storage.clone();
    assert!(
        storage
            .reserve_sibling_welcome_carrier::<EngineError>(
                &original.id,
                &device_group,
                &slot(2),
                b"prepared",
                NOW,
                || phone
                    .engine
                    .carry_sibling_welcome(&original.id, b"prepared")
            )
            .unwrap()
    );
    assert!(
        !storage
            .app_storage()
            .sibling_welcome_resend_is_due(
                original.id.as_slice(),
                roster.devices[&slot(2)].linked_at
            )
            .unwrap(),
        "not armed: retirement must not rely only on due rows"
    );
    assert!(
        phone
            .engine
            .sibling_welcome_resend_has_ended(&original.id, deliver_until)
            .unwrap()
    );
    assert_eq!(
        phone
            .engine
            .rearm_sibling_welcome(&original.id, b"first", deliver_until, &roster)
            .unwrap(),
        Complete,
        "Sent/carrier mismatch cannot hide expiry"
    );
    storage
        .app_storage()
        .delete_sibling_welcome_resend(original.id.as_slice())
        .unwrap();
    assert_eq!(
        storage.get_message(&original.id).unwrap().state,
        MessageState::Failed
    );
    assert!(
        phone
            .engine
            .owed_sibling_welcomes(Timestamp(NOW))
            .unwrap()
            .is_empty()
    );
    assert!(
        !phone
            .engine
            .sibling_welcome_delivered(&original.id, b"prepared")
            .unwrap(),
        "late outcome cannot resurrect terminal original"
    );
    assert!(
        matches!(storage.reserve_sibling_welcome_carrier::<EngineError>(&original.id, &device_group, &slot(2), b"rollback", NOW-1, || phone.engine.carry_sibling_welcome(&original.id, b"rollback")), Err(EngineError::Storage(cgka_traits::StorageError::Backend(message))) if message == "sibling Welcome readiness changed")
    );
    assert!(
        storage
            .app_storage()
            .sibling_welcome_resend_batch(None, 32)
            .unwrap()
            .is_empty(),
        "failed attach rolls back registration after retired high-water"
    );
}
