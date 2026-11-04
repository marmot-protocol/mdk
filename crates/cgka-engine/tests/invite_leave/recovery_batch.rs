use super::*;
use cgka_traits::engine::GroupHydrationQuarantineReason;
use cgka_traits::group_recovery::{GroupMemberRecovery, group_recovery_grant_bytes};
use cgka_traits::maintenance::GroupEvolutionSemantic;
use cgka_traits::storage::MaintenanceStorage;
use cgka_traits::types::EpochId;
use openmls_traits::signatures::Signer as _;
use storage_sqlite::SqlCipherKey;

fn current_client(seed: &[u8], storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(seed))
        .account_identity_proof_signer(proof_signer(seed))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

async fn grant_for_request(
    admin: &Engine<SqliteAccountStorage>,
    target: &mut Engine<SqliteAccountStorage>,
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    request_id: [u8; 32],
) -> GroupMemberRecovery {
    let member = target.self_id();
    let source = admin
        .group_recovery_source(
            group_id,
            &member,
            &target.own_recovery_key_hash(group_id).unwrap(),
        )
        .unwrap();
    let key_package = target.fresh_key_package().await.unwrap();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300;
    let payload = group_recovery_grant_bytes(
        group_id,
        &admin.self_id(),
        &request_id,
        expires_at,
        &source,
        &key_package,
    )
    .unwrap();
    let (_, signer) = load_group_and_signer(storage, &member, group_id);
    GroupMemberRecovery {
        member,
        source,
        key_package,
        request_id,
        expires_at,
        device_signature: signer.sign(&payload).unwrap(),
    }
}

#[tokio::test]
async fn batch_reopen() {
    for count in [2, 32] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("batch.sqlite");
        let key = SqlCipherKey::new("batch recovery encrypted restart").unwrap();
        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let mut admin = current_client(b"batch-admin", storage.clone());
        let mut recipients = Vec::with_capacity(count);
        let mut packages = Vec::with_capacity(count);
        for index in 0..count {
            let seed = format!("batch-member-{index}").into_bytes();
            let target_storage = SqliteAccountStorage::in_memory_for_test().unwrap();
            let mut target = current_client(&seed, target_storage.clone());
            packages.push(target.fresh_key_package().await.unwrap());
            recipients.push((seed, target, target_storage));
        }
        let (group_id, created) = admin
            .create_group(CreateGroupRequest {
                name: "batch recovery".into(),
                description: String::new(),
                members: packages,
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![recipients[0].1.self_id()],
            })
            .await
            .unwrap();
        let SendResult::FoundingGroupCreated { welcomes } = created else {
            panic!("expected founding group");
        };
        for ((_, target, _), welcome) in recipients.iter_mut().zip(welcomes) {
            assert_eq!(
                welcome.envelope,
                TransportEnvelope::Welcome {
                    recipient: target.self_id()
                }
            );
            target.join_welcome(welcome.clone()).await.unwrap();
            admin.mark_sent_welcome_delivered(&welcome.id).unwrap();
        }
        let admins = admin.admin_pubkeys(&group_id).unwrap();
        let before = storage.get_group(&group_id).unwrap();
        let mut grants = Vec::with_capacity(count);
        for (index, (_, target, target_storage)) in recipients.iter_mut().enumerate() {
            grants.push(
                grant_for_request(&admin, target, target_storage, &group_id, [index as u8; 32])
                    .await,
            );
        }
        if count == 2 {
            for members in [vec![], vec![grants[0].clone(); 33]] {
                assert!(matches!(
                    admin
                        .send(SendIntent::RecoverMembers {
                            group_id: group_id.clone(),
                            members
                        })
                        .await,
                    Err(EngineError::Other(_))
                ));
            }
            let (_, second, second_storage) = &mut recipients[1];
            let duplicate_request = grant_for_request(
                &admin,
                second,
                second_storage,
                &group_id,
                grants[0].request_id,
            )
            .await;
            for members in [
                vec![grants[0].clone(), grants[0].clone()],
                vec![grants[0].clone(), duplicate_request],
            ] {
                assert!(matches!(
                    admin
                        .send(SendIntent::RecoverMembers {
                            group_id: group_id.clone(),
                            members
                        })
                        .await,
                    Err(EngineError::GroupRecoverySourceMismatch { .. })
                ));
            }
            assert_eq!(storage.get_group(&group_id).unwrap(), before);
            assert!(
                storage
                    .list_group_evolutions_for_group(&group_id)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                load_group_and_signer(&storage, &admin.self_id(), &group_id)
                    .0
                    .pending_commit()
                    .is_none()
            );
            assert!(admin.outstanding_sent_welcomes().unwrap().is_empty());
        }
        let SendResult::GroupEvolution {
            msg,
            welcomes,
            pending,
        } = admin
            .send(SendIntent::RecoverMembers {
                group_id: group_id.clone(),
                members: grants,
            })
            .await
            .unwrap()
        else {
            panic!("expected atomic recovery");
        };
        assert_eq!(welcomes.len(), count);
        assert!(admin.outstanding_sent_welcomes().unwrap().is_empty());
        drop(admin);
        drop(storage);

        let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let mut admin = current_client(b"batch-admin", storage.clone());
        admin.hydrate_all_stored_groups().unwrap();
        let restored = admin.drain_auto_publish();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].msg, msg);
        assert_eq!(restored[0].welcomes, welcomes);
        assert_eq!(restored[0].pending, pending);
        assert!(admin.outstanding_sent_welcomes().unwrap().is_empty());
        admin.confirm_published(pending).await.unwrap();
        assert_eq!(admin.admin_pubkeys(&group_id).unwrap(), admins);
        let released = admin.outstanding_sent_welcomes().unwrap();
        assert_eq!(released.len(), count);
        let released_by_id: std::collections::HashMap<_, _> = released
            .iter()
            .map(|(_, message)| (&message.id, message))
            .collect();
        let welcomes_by_recipient: std::collections::HashMap<_, _> = welcomes
            .iter()
            .map(|welcome| {
                let TransportEnvelope::Welcome { recipient } = &welcome.envelope else {
                    panic!("expected addressed Welcome");
                };
                (recipient, welcome)
            })
            .collect();
        assert_eq!(welcomes_by_recipient.len(), count);
        let (canonical, _) = load_group_and_signer(&storage, &admin.self_id(), &group_id);
        for (seed, target, target_storage) in recipients {
            let member = target.self_id();
            drop(target);
            let mut record = target_storage.get_group(&group_id).unwrap();
            record.unrecoverable = true;
            target_storage.put_group(&record).unwrap();
            let mut target = current_client(&seed, target_storage.clone());
            target.hydrate_all_stored_groups().unwrap();
            let welcome = welcomes_by_recipient.get(&member).copied().unwrap();
            assert_eq!(released_by_id.get(&welcome.id).copied(), Some(welcome));
            target.join_welcome(welcome.clone()).await.unwrap();
            assert_eq!(target.members(&group_id).unwrap().len(), count + 1);
            assert_eq!(target.admin_pubkeys(&group_id).unwrap(), admins);
            let (joined, _) = load_group_and_signer(&target_storage, &member, &group_id);
            assert_eq!(
                joined.epoch_authenticator().as_slice(),
                canonical.epoch_authenticator().as_slice()
            );
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum MissingArtifact {
    SourceEpoch,
    OwnLeaf,
    SignedCommit,
    Welcome,
}

#[tokio::test]
async fn recovery_artifact_quarantine() {
    for missing in [
        MissingArtifact::SourceEpoch,
        MissingArtifact::OwnLeaf,
        MissingArtifact::SignedCommit,
        MissingArtifact::Welcome,
    ] {
        let (mut admin, storage, mut target, _, group_id, target_storage) =
            member_recovery_fixture().await;
        let grant =
            grant_for_request(&admin, &mut target, &target_storage, &group_id, [19; 32]).await;
        let SendResult::GroupEvolution { welcomes, .. } = admin
            .send(SendIntent::RecoverMembers {
                group_id: group_id.clone(),
                members: vec![grant],
            })
            .await
            .unwrap()
        else {
            panic!("expected recovery evolution");
        };
        let mut evolution = storage
            .list_group_evolutions_for_group(&group_id)
            .unwrap()
            .into_iter()
            .find(|evolution| {
                matches!(
                    evolution.semantic,
                    GroupEvolutionSemantic::RecoverMembers { .. }
                )
            })
            .unwrap();
        match missing {
            MissingArtifact::SourceEpoch => {
                evolution.source_epoch = EpochId(evolution.source_epoch.0 + 1)
            }
            MissingArtifact::OwnLeaf => evolution.own_leaf_before_hash.as_mut().unwrap()[0] ^= 1,
            MissingArtifact::SignedCommit => evolution.signed_message_id = None,
            MissingArtifact::Welcome => storage.delete_message(&welcomes[0].id).unwrap(),
        }
        storage.put_group_evolution(&evolution).unwrap();
        drop(admin);
        let mut reopened = current_client(b"recovery-admin", storage.clone());
        reopened.hydrate_all_stored_groups().unwrap();
        assert_eq!(
            reopened.quarantined_groups(),
            vec![(
                group_id.clone(),
                GroupHydrationQuarantineReason::PendingCommitRecoveryFailed
            )],
            "{missing:?}"
        );
        assert!(reopened.drain_auto_publish().is_empty(), "{missing:?}");
        assert!(
            reopened.outstanding_sent_welcomes().unwrap().is_empty(),
            "{missing:?}"
        );
        assert!(
            matches!(reopened.epoch(&group_id), Err(EngineError::UnknownGroup(_))),
            "{missing:?}"
        );
        assert_eq!(
            storage.group_evolution(&evolution.id).unwrap(),
            Some(evolution),
            "{missing:?}"
        );
    }
}
