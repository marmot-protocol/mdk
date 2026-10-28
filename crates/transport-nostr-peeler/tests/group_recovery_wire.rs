use std::sync::Arc;

use cgka_traits::{
    AuthenticatedGroupRecovery, EpochId, GroupId, GroupRecoveryBody, GroupRecoveryMessage,
    GroupRecoverySource, KeyPackage, MAX_GROUP_RECOVERY_BODY_BYTES, MemberId, PeelerError,
    TransportEnvelope, TransportMessage, TransportPeeler,
};
use nostr::nips::nip59::GiftWrapBuilder;
use nostr::prelude::{
    EventBuilder, FinalizeEvent, FinalizeUnsignedEvent, Keys, Kind, Tag, UnsignedEvent,
};
use transport_nostr_peeler::{
    GROUP_RECOVERY_PROTOCOL_TAG, GROUP_RECOVERY_PROTOCOL_VERSION, KIND_MDK_GROUP_RECOVERY_RUMOR,
    MAX_GROUP_RECOVERY_EVENT_BYTES, NostrMlsPeeler, NostrTransportEvent, gift_wrap_rumor,
};

fn member(keys: &Keys) -> MemberId {
    MemberId::new(keys.public_key().to_bytes().to_vec())
}

fn request() -> GroupRecoveryMessage {
    GroupRecoveryMessage {
        group_id: GroupId::new(vec![7; 16]),
        request_id: [8; 32],
        expires_at: 2_000_000_000,
        body: GroupRecoveryBody::Request {
            device_key_hash: [9; 32],
        },
    }
}

fn protocol_tag() -> Tag {
    Tag::custom(
        GROUP_RECOVERY_PROTOCOL_TAG,
        [GROUP_RECOVERY_PROTOCOL_VERSION],
    )
}

fn rumor(author: &Keys, receiver: &Keys, content: String, protocol: Vec<Tag>) -> UnsignedEvent {
    EventBuilder::new(Kind::Custom(KIND_MDK_GROUP_RECOVERY_RUMOR), content)
        .tags(
            protocol
                .into_iter()
                .chain([Tag::public_key(receiver.public_key())]),
        )
        .finalize_unsigned(author.public_key())
}

// Construct independently signed outer and inner protocol tags to exercise the
// trust boundary, not just the production wrapper's matching-tag construction.
fn signed_carrier(sender: &Keys, receiver: &Keys, rumor: UnsignedEvent) -> TransportMessage {
    let event = GiftWrapBuilder::new(receiver.public_key(), rumor)
        .extra_tags([protocol_tag()])
        .finalize(sender)
        .unwrap();
    NostrTransportEvent::from_nostr_event(&event)
        .unwrap()
        .to_transport_message()
        .unwrap()
}

#[tokio::test]
async fn recovery_account_roundtrip() {
    let recovering = Keys::generate();
    let coordinator = Keys::generate();
    let recovering_peeler = NostrMlsPeeler::new().with_welcome_signer(recovering.clone());
    let coordinator_peeler = NostrMlsPeeler::new().with_welcome_signer(coordinator.clone());
    let source = GroupRecoverySource {
        epoch: EpochId(12),
        epoch_authenticator_hash: [4; 32],
        leaf_index: 3,
        leaf_hash: [5; 32],
        device_key_hash: [9; 32],
        coordinator_key_hash: [11; 32],
    };
    let mut challenge = request();
    challenge.body = GroupRecoveryBody::Challenge {
        source: source.clone(),
    };
    let mut grant = request();
    grant.body = GroupRecoveryBody::Grant {
        source,
        key_package: KeyPackage::with_source_event_id(
            vec![1, 2, 3],
            cgka_traits::MessageId::new(vec![9; 32]),
        )
        .with_protocol_profile(cgka_traits::group::ProtocolProfile::Current),
        // Wire tests authenticate the NIP-59 account seal; the engine verifies
        // this separate device proof against the persisted MLS public key.
        device_signature: vec![10; 64],
    };
    for (message, from, to, sender, receiver) in [
        (
            request(),
            &recovering_peeler,
            &coordinator_peeler,
            &recovering,
            &coordinator,
        ),
        (
            challenge,
            &coordinator_peeler,
            &recovering_peeler,
            &coordinator,
            &recovering,
        ),
        (
            grant,
            &recovering_peeler,
            &coordinator_peeler,
            &recovering,
            &coordinator,
        ),
    ] {
        let wrapped = from
            .wrap_group_recovery(&message, &member(receiver))
            .await
            .unwrap();
        assert_eq!(
            wrapped.envelope,
            TransportEnvelope::GroupRecovery {
                recipient: member(receiver)
            }
        );
        let event = NostrTransportEvent::from_transport_message(&wrapped).unwrap();
        assert_ne!(
            event.pubkey,
            sender.public_key().to_hex(),
            "outer ephemeral author is not the sender"
        );
        assert_eq!(
            event.single_tag_value(GROUP_RECOVERY_PROTOCOL_TAG).unwrap(),
            "1"
        );
        let peeled = to.peel_group_recovery(&wrapped).await.unwrap();
        if let (
            GroupRecoveryBody::Grant {
                key_package: received,
                ..
            },
            GroupRecoveryBody::Grant {
                key_package: sent, ..
            },
        ) = (&peeled.message.body, &message.body)
        {
            assert_eq!(
                received.source, sent.source,
                "preserve published KeyPackage provenance"
            );
        }
        assert_eq!(
            peeled,
            AuthenticatedGroupRecovery {
                sender: member(sender),
                message
            }
        );
        assert!(
            to.peel_welcome(&wrapped).await.is_err(),
            "recovery must not enter Welcome handling"
        );
    }
}

#[tokio::test]
async fn recovery_rejects_wrong_route() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let foreign = Keys::generate();
    let from = NostrMlsPeeler::new().with_welcome_signer(sender.clone());
    let to = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());
    let wrong = NostrMlsPeeler::new().with_welcome_signer(foreign.clone());
    let wrapped = from
        .wrap_group_recovery(&request(), &member(&receiver))
        .await
        .unwrap();
    assert!(matches!(
        wrong.peel_group_recovery(&wrapped).await,
        Err(PeelerError::WrongRecipient)
    ));
    let mut forged_route = wrapped;
    forged_route.envelope = TransportEnvelope::GroupRecovery {
        recipient: member(&foreign),
    };
    assert!(matches!(
        to.peel_group_recovery(&forged_route).await,
        Err(PeelerError::WrongRecipient)
    ));
    let wrong_inner = rumor(
        &sender,
        &foreign,
        String::from_utf8(request().encode().unwrap()).unwrap(),
        vec![protocol_tag()],
    );
    let wrapped = signed_carrier(&sender, &receiver, wrong_inner);
    assert!(matches!(
        to.peel_group_recovery(&wrapped).await,
        Err(PeelerError::WrongRecipient)
    ));
}

#[tokio::test]
async fn recovery_forged_sender() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let impersonated = Keys::generate();
    let to = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());
    let forged_rumor = rumor(
        &impersonated,
        &receiver,
        String::from_utf8(request().encode().unwrap()).unwrap(),
        vec![protocol_tag()],
    );
    let forged = signed_carrier(&sender, &receiver, forged_rumor);
    assert!(
        to.peel_group_recovery(&forged).await.is_err(),
        "valid seal must not authenticate a different rumor author"
    );
    let wrapped = NostrMlsPeeler::new()
        .with_welcome_signer(sender)
        .wrap_group_recovery(&request(), &member(&receiver))
        .await
        .unwrap();
    let mut event = NostrTransportEvent::from_transport_message(&wrapped).unwrap();
    event.sig = None;
    let unsigned = event.to_transport_message().unwrap();
    assert!(
        to.peel_group_recovery(&unsigned).await.is_err(),
        "routing conversion does not authenticate a carrier"
    );
}

#[tokio::test]
async fn recovery_strict_tags() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let to = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());
    let content = String::from_utf8(request().encode().unwrap()).unwrap();
    for tags in [
        vec![],
        vec![Tag::custom(GROUP_RECOVERY_PROTOCOL_TAG, ["2"])],
        vec![
            protocol_tag(),
            Tag::custom(GROUP_RECOVERY_PROTOCOL_TAG, ["2"]),
        ],
        vec![Tag::custom(GROUP_RECOVERY_PROTOCOL_TAG, ["1", "extra"])],
    ] {
        let inner = rumor(&sender, &receiver, content.clone(), tags);
        let wrapped = signed_carrier(&sender, &receiver, inner);
        assert!(
            to.peel_group_recovery(&wrapped).await.is_err(),
            "signed outer hint cannot replace authenticated inner version"
        );
    }
    let mut wrong_kind = rumor(&sender, &receiver, content.clone(), vec![protocol_tag()]);
    wrong_kind.kind = Kind::TextNote;
    assert!(
        to.peel_group_recovery(&signed_carrier(&sender, &receiver, wrong_kind))
            .await
            .is_err()
    );
    let inner = rumor(&sender, &receiver, content, vec![protocol_tag()]);
    let wrapped = gift_wrap_rumor(Arc::new(sender.clone()), receiver.public_key(), inner)
        .await
        .unwrap();
    let valid = NostrTransportEvent::from_nostr_event(&wrapped).unwrap();
    for tags in [
        vec![vec![GROUP_RECOVERY_PROTOCOL_TAG.into(), "2".into()]],
        vec![vec![GROUP_RECOVERY_PROTOCOL_TAG.into()]],
        vec![vec![
            GROUP_RECOVERY_PROTOCOL_TAG.into(),
            "1".into(),
            "extra".into(),
        ]],
        vec![
            vec![GROUP_RECOVERY_PROTOCOL_TAG.into(), "1".into()],
            vec![GROUP_RECOVERY_PROTOCOL_TAG.into(), "2".into()],
        ],
    ] {
        let mut event = valid.clone();
        event.tags.retain(|tag| {
            tag.first()
                .is_none_or(|name| name != GROUP_RECOVERY_PROTOCOL_TAG)
        });
        event.tags.extend(tags);
        event.id = event.computed_id();
        assert!(
            event.to_transport_message().is_err(),
            "duplicate or malformed protocol tags fail before dispatch"
        );
    }
    let mut duplicate_recipient = valid.clone();
    duplicate_recipient.tags.push(vec!["p".into()]);
    duplicate_recipient.id = duplicate_recipient.computed_id();
    assert!(duplicate_recipient.to_transport_message().is_err());
    let mut tampered = valid.clone();
    tampered.tags.push(vec!["untrusted".into(), "value".into()]);
    tampered.id = tampered.computed_id();
    let tampered = tampered.to_transport_message().unwrap();
    assert!(
        to.peel_group_recovery(&tampered).await.is_err(),
        "recomputed outer id does not repair a broken signature"
    );
    let mut missing = valid;
    missing.tags.retain(|tag| {
        tag.first()
            .is_none_or(|name| name != GROUP_RECOVERY_PROTOCOL_TAG)
    });
    missing.id = missing.computed_id();
    let mut message = missing.to_transport_message().unwrap();
    assert!(matches!(
        message.envelope,
        TransportEnvelope::Welcome { .. }
    ));
    message.envelope = TransportEnvelope::GroupRecovery {
        recipient: member(&receiver),
    };
    assert!(to.peel_group_recovery(&message).await.is_err());
}

#[tokio::test]
async fn recovery_rejects_oversize() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let to = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());
    let mut content = String::from_utf8(request().encode().unwrap()).unwrap();
    content.extend(std::iter::repeat_n(
        ' ',
        MAX_GROUP_RECOVERY_BODY_BYTES + 1 - content.len(),
    ));
    let inner = rumor(&sender, &receiver, content, vec![protocol_tag()]);
    let wrapped = signed_carrier(&sender, &receiver, inner);
    assert!(
        wrapped.payload.len() < MAX_GROUP_RECOVERY_EVENT_BYTES,
        "exercise inner body bound after real authenticated unwrap"
    );
    assert!(to.peel_group_recovery(&wrapped).await.is_err());
    let mut oversize = wrapped;
    oversize.payload = vec![b' '; MAX_GROUP_RECOVERY_EVENT_BYTES + 1];
    assert!(to.peel_group_recovery(&oversize).await.is_err());
}
