//! A media chat or reaction replayed inside a convergence pass carries its
//! source-epoch encrypted-media secret, captured while replay authenticates
//! it: later commits in the same pass prune that epoch's retained anchor
//! before the application event is drained.

use super::*;
use cgka_traits::app_components::GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_REACTION;

#[tokio::test]
async fn replayed_media_application_carries_source_secret_past_anchor_horizon() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "media source secret".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    let start = carol.epoch(&group_id).unwrap().0;

    // One frozen backlog: the commit to E+1, a media application at E+1,
    // then enough commits to carry the tip past the anchor horizon.
    let mut backlog = vec![self_update(&mut alice, &group_id).await];
    let sender_secret = alice
        .group_context(&group_id)
        .unwrap()
        .exporter_secret(GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY, 32)
        .expect("sender exports the E+1 media secret");
    backlog.push(send_media(&mut alice, &group_id, MARMOT_APP_EVENT_KIND_CHAT).await);
    backlog.push(send_media(&mut alice, &group_id, MARMOT_APP_EVENT_KIND_REACTION).await);
    backlog.push(send_app(&mut alice, &group_id, b"plain text".to_vec()).await);
    for _ in 0..6 {
        backlog.push(self_update(&mut alice, &group_id).await);
    }
    for message in backlog {
        carol
            .buffer_openmls_convergence_message_at(&group_id, message, 1_000)
            .unwrap();
    }

    // A pass admits commits only up to its future horizon, so the backlog
    // takes more than one pass; nothing is drained in between, as in one
    // sync batch. The last pass advances the tip past the source epoch's
    // anchor horizon.
    for now_ms in (1..=4).map(|step| step * 1_000_000) {
        carol
            .converge_stored_openmls_messages_at(&group_id, now_ms)
            .unwrap();
    }
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(start + 7));
    assert!(
        carol
            .retained_encrypted_media_exporter_secret(&group_id, EpochId(start + 1))
            .unwrap()
            .is_none(),
        "the pass prunes the media application's source anchor"
    );
    let mut received = received_messages(&mut carol);
    received.sort_by(|a, b| a.0.cmp(&b.0));
    let [
        (reaction_content, reaction_epoch, Some(reaction_secret)),
        (media_content, media_epoch, Some(media_secret)),
        (plain_content, _, None),
    ] = received.as_slice()
    else {
        panic!("expected secrets on attachment-bearing messages only: {received:?}");
    };
    assert_eq!(reaction_content, b":party:");
    assert_eq!(*reaction_epoch, EpochId(start + 1));
    assert!(
        reaction_secret.as_bytes() == sender_secret.as_slice(),
        "reaction carries its authenticated source key"
    );
    assert_eq!(media_content, b"photo");
    assert_eq!(*media_epoch, EpochId(start + 1));
    assert_eq!(plain_content, b"plain text");
    assert!(
        media_secret.as_bytes() == sender_secret.as_slice(),
        "chat media carries its authenticated source key"
    );
}

/// A media application that arrives after the receiver already left its
/// source epoch, in the same sync as further commits, still carries its key:
/// the receiver sits at E+3, media from E+1 arrives with four more commits,
/// and the pass ends at E+7 with the E+1 anchor pruned.
#[tokio::test]
async fn late_media_application_carries_source_secret_past_anchor_horizon() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage) = build_client(b"carol");
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "late media".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    let start = carol.epoch(&group_id).unwrap().0;

    let mut on_time = vec![self_update(&mut alice, &group_id).await];
    let sender_secret = alice
        .group_context(&group_id)
        .unwrap()
        .exporter_secret(GROUP_ENCRYPTED_MEDIA_EXPORTER_CACHE_KEY, 32)
        .expect("sender exports the E+1 media secret");
    let media = send_media(&mut alice, &group_id, MARMOT_APP_EVENT_KIND_CHAT).await;
    let reaction = send_media(&mut alice, &group_id, MARMOT_APP_EVENT_KIND_REACTION).await;
    let plain = send_app(&mut alice, &group_id, b"plain text".to_vec()).await;
    for _ in 0..2 {
        on_time.push(self_update(&mut alice, &group_id).await);
    }
    let mut late = vec![media, reaction, plain];
    for _ in 0..4 {
        late.push(self_update(&mut alice, &group_id).await);
    }

    for message in on_time {
        carol
            .buffer_openmls_convergence_message_at(&group_id, message, 1_000)
            .unwrap();
    }
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .unwrap();
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(start + 3));
    carol.drain_events();

    for message in late {
        carol
            .buffer_openmls_convergence_message_at(&group_id, message, 2_000_000)
            .unwrap();
    }
    for now_ms in (3..=5).map(|step| step * 1_000_000) {
        carol
            .converge_stored_openmls_messages_at(&group_id, now_ms)
            .unwrap();
    }
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(start + 7));
    assert!(
        carol
            .retained_encrypted_media_exporter_secret(&group_id, EpochId(start + 1))
            .unwrap()
            .is_none(),
        "the pass prunes the late media application's source anchor"
    );

    let mut received = received_messages(&mut carol);
    received.sort_by(|a, b| a.0.cmp(&b.0));
    let [
        (reaction_content, reaction_epoch, Some(reaction_secret)),
        (media_content, media_epoch, Some(media_secret)),
        (plain_content, _, None),
    ] = received.as_slice()
    else {
        panic!("expected secrets on late attachment-bearing messages only: {received:?}");
    };
    assert_eq!(reaction_content, b":party:");
    assert_eq!(*reaction_epoch, EpochId(start + 1));
    assert!(
        reaction_secret.as_bytes() == sender_secret.as_slice(),
        "reaction carries its authenticated source key"
    );
    assert_eq!(media_content, b"photo");
    assert_eq!(*media_epoch, EpochId(start + 1));
    assert_eq!(plain_content, b"plain text");
    assert!(
        media_secret.as_bytes() == sender_secret.as_slice(),
        "chat media carries its authenticated source key"
    );
}

async fn send_media(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    kind: u64,
) -> TransportMessage {
    let mut tags = vec![vec![
        "imeta".into(),
        "url https://blossom.example/attachment".into(),
        "m image/png".into(),
    ]];
    let author = hex::encode(engine.self_id().as_slice());
    let content = if kind == MARMOT_APP_EVENT_KIND_REACTION {
        let target = MarmotAppEvent::new(
            &author,
            1_700_000_000,
            MARMOT_APP_EVENT_KIND_CHAT,
            tags.clone(),
            "photo",
        )
        .id;
        tags.push(vec!["e".into(), target]);
        tags.push(vec![
            "emoji".into(),
            "party".into(),
            "https://blossom.example/attachment".into(),
        ]);
        ":party:"
    } else {
        "photo"
    };
    let payload = MarmotAppEvent::new(author, 1_700_000_000, kind, tags, content)
        .encode()
        .unwrap();
    match engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .unwrap()
    {
        SendResult::ApplicationMessage { msg, .. } => route(msg, group_id),
        other => panic!("expected ApplicationMessage, got {other:?}"),
    }
}

fn received_messages(
    engine: &mut Engine<SqliteAccountStorage>,
) -> Vec<(Vec<u8>, EpochId, Option<cgka_traits::EncryptedMediaSecret>)> {
    engine
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::MessageReceived {
                epoch,
                payload,
                encrypted_media_secret,
                ..
            } => Some((app_content(&payload), epoch, encrypted_media_secret)),
            _ => None,
        })
        .collect()
}

async fn self_update(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
) -> TransportMessage {
    let (commit, pending) = evolution(
        engine
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    engine.confirm_published(pending).await.unwrap();
    route(commit, group_id)
}
