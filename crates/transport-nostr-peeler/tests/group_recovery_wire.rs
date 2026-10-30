use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use cgka_traits::{
    AuthenticatedGroupRecovery, EpochId, GroupId, GroupRecoveryBody, GroupRecoveryMessage,
    GroupRecoverySource, KeyPackage, MAX_GROUP_RECOVERY_BODY_BYTES, MemberId, PeelerError,
    TransportEnvelope, TransportMessage, TransportPeeler,
};
use nostr::nips::nip59::GiftWrapBuilder;
use nostr::prelude::{
    Event, EventBuilder, FinalizeEvent, FinalizeUnsignedEvent, Keys, Kind, PublicKey, Tag,
    UnsignedEvent,
};
use transport_nostr_peeler::{
    GROUP_RECOVERY_PROTOCOL_TAG, GROUP_RECOVERY_PROTOCOL_VERSION, KIND_MDK_GROUP_RECOVERY_RUMOR,
    MAX_GROUP_RECOVERY_EVENT_BYTES, NostrMlsPeeler, NostrTransportEvent, gift_wrap_rumor,
};

#[derive(Debug)]
struct OnceSigner {
    keys: Keys,
    consumed: Mutex<HashSet<String>>,
}

impl transport_nostr_peeler::MarmotNostrSigner for OnceSigner {
    fn get_public_key(
        &self,
    ) -> transport_nostr_peeler::SignerFuture<
        '_,
        Result<PublicKey, transport_nostr_peeler::MarmotSignerError>,
    > {
        transport_nostr_peeler::MarmotNostrSigner::get_public_key(&self.keys)
    }

    fn sign_event(
        &self,
        unsigned: UnsignedEvent,
    ) -> transport_nostr_peeler::SignerFuture<
        '_,
        Result<Event, transport_nostr_peeler::MarmotSignerError>,
    > {
        transport_nostr_peeler::MarmotNostrSigner::sign_event(&self.keys, unsigned)
    }

    fn nip04_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> transport_nostr_peeler::SignerFuture<
        'a,
        Result<String, transport_nostr_peeler::MarmotSignerError>,
    > {
        transport_nostr_peeler::MarmotNostrSigner::nip04_encrypt(&self.keys, public_key, content)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> transport_nostr_peeler::SignerFuture<
        'a,
        Result<String, transport_nostr_peeler::MarmotSignerError>,
    > {
        transport_nostr_peeler::MarmotNostrSigner::nip04_decrypt(&self.keys, public_key, payload)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> transport_nostr_peeler::SignerFuture<
        'a,
        Result<String, transport_nostr_peeler::MarmotSignerError>,
    > {
        transport_nostr_peeler::MarmotNostrSigner::nip44_encrypt(&self.keys, public_key, content)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> transport_nostr_peeler::SignerFuture<
        'a,
        Result<String, transport_nostr_peeler::MarmotSignerError>,
    > {
        // An external signer may issue a one-use decryption grant per layer.
        // Trial classification must not spend the grant before actual admission.
        if !self.consumed.lock().unwrap().insert(payload.to_owned()) {
            return Box::pin(async { Err("decryption grant already consumed".into()) });
        }
        transport_nostr_peeler::MarmotNostrSigner::nip44_decrypt(&self.keys, public_key, payload)
    }
}

fn member(keys: &Keys) -> MemberId {
    MemberId::new(keys.public_key().to_bytes().to_vec())
}

async fn peel_recovery(
    peeler: &NostrMlsPeeler,
    message: &TransportMessage,
) -> Result<AuthenticatedGroupRecovery, PeelerError> {
    match peeler.peel_welcome(message).await?.content {
        cgka_traits::PeeledContent::GroupRecovery { recovery } => Ok(*recovery),
        _ => Err(PeelerError::Malformed(
            "expected authenticated recovery".into(),
        )),
    }
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
async fn recovery_outer_is_private() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let from = NostrMlsPeeler::new().with_welcome_signer(sender);
    let recipient = member(&receiver);
    let recovery = from
        .wrap_group_recovery(&request(), &recipient)
        .await
        .unwrap();
    let welcome = from
        .wrap_welcome_with_metadata(
            &cgka_traits::EncryptedPayload {
                ciphertext: b"welcome bytes".to_vec(),
                aad: Vec::new(),
            },
            &recipient,
            &cgka_traits::engine::WelcomeMetadata {
                key_package_event_id: cgka_traits::MessageId::new(vec![4; 32]),
                relays: vec!["wss://relay.example".into()],
            },
        )
        .await
        .unwrap();
    let recovery_event = NostrTransportEvent::from_transport_message(&recovery).unwrap();
    let welcome_event = NostrTransportEvent::from_transport_message(&welcome).unwrap();
    assert_eq!(recovery_event.kind, welcome_event.kind);
    assert_eq!(
        recovery_event.tags, welcome_event.tags,
        "repair control must not have an outer discriminator absent from Welcomes"
    );
    assert_eq!(recovery.envelope, welcome.envelope);
}

#[tokio::test]
async fn recovery_unmarked_dispatch() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let to = NostrMlsPeeler::new().with_welcome_signer(OnceSigner {
        keys: receiver.clone(),
        consumed: Mutex::new(HashSet::new()),
    });
    let inner = rumor(
        &sender,
        &receiver,
        String::from_utf8(request().encode().unwrap()).unwrap(),
        vec![protocol_tag()],
    );
    let wrapped = GiftWrapBuilder::new(receiver.public_key(), inner)
        .finalize(&sender)
        .unwrap();
    let message = NostrTransportEvent::from_nostr_event(&wrapped)
        .unwrap()
        .to_transport_message()
        .unwrap();
    assert_eq!(
        peel_recovery(&to, &message).await.unwrap(),
        AuthenticatedGroupRecovery {
            sender: member(&sender),
            message: request()
        }
    );
    let opened = NostrMlsPeeler::new()
        .with_welcome_signer(receiver)
        .peel_account_gift_wrap(&message)
        .await
        .unwrap();
    assert!(matches!(
        &opened,
        transport_nostr_peeler::AccountGiftWrap::GroupRecovery(_)
    ));
    let (peeled, provenance) = opened.into_welcome().unwrap();
    assert!(provenance.is_none());
    assert!(peeled.sender.is_none());
    assert!(peeled.group_id.is_none());
    assert!(matches!(
        peeled.content,
        cgka_traits::PeeledContent::GroupRecovery { .. }
    ));
}

#[tokio::test]
async fn welcome_stays_ordinary() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let to = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());
    // A protocol-looking tag alone cannot change an authenticated Welcome's kind.
    for markers in [Vec::new(), vec![protocol_tag()]] {
        let inner = EventBuilder::new(Kind::Custom(444), "d2VsY29tZSBieXRlcw==")
            .tags([
                Tag::custom("e", [hex::encode([4; 32])]),
                Tag::custom("relays", ["wss://relay.example"]),
            ])
            .tags(markers)
            .finalize_unsigned(sender.public_key());
        let wrapped = GiftWrapBuilder::new(receiver.public_key(), inner)
            .finalize(&sender)
            .unwrap();
        let message = NostrTransportEvent::from_nostr_event(&wrapped)
            .unwrap()
            .to_transport_message()
            .unwrap();
        let peeled = to.peel_welcome(&message).await.unwrap();
        assert!(matches!(
            peeled.content,
            cgka_traits::PeeledContent::Welcome { .. }
        ));
        assert!(peel_recovery(&to, &message).await.is_err());
    }
}

#[tokio::test]
async fn unmarked_bad_inner_rejected() {
    let sender = Keys::generate();
    let receiver = Keys::generate();
    let to = NostrMlsPeeler::new().with_welcome_signer(receiver.clone());
    let content = String::from_utf8(request().encode().unwrap()).unwrap();
    for markers in [
        Vec::new(),
        vec![Tag::custom(GROUP_RECOVERY_PROTOCOL_TAG, ["2"])],
        vec![protocol_tag(), protocol_tag()],
        vec![Tag::custom(GROUP_RECOVERY_PROTOCOL_TAG, ["1", "extra"])],
    ] {
        let inner = rumor(&sender, &receiver, content.clone(), markers);
        let wrapped = GiftWrapBuilder::new(receiver.public_key(), inner)
            .finalize(&sender)
            .unwrap();
        let message = NostrTransportEvent::from_nostr_event(&wrapped)
            .unwrap()
            .to_transport_message()
            .unwrap();
        assert!(peel_recovery(&to, &message).await.is_err());
        assert!(to.peel_welcome(&message).await.is_err());
    }
    let mut unsupported = rumor(&sender, &receiver, content, vec![protocol_tag()]);
    unsupported.kind = Kind::TextNote;
    let wrapped = GiftWrapBuilder::new(receiver.public_key(), unsupported)
        .finalize(&sender)
        .unwrap();
    let message = NostrTransportEvent::from_nostr_event(&wrapped)
        .unwrap()
        .to_transport_message()
        .unwrap();
    assert!(peel_recovery(&to, &message).await.is_err());
    assert!(to.peel_welcome(&message).await.is_err());
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
            TransportEnvelope::Welcome {
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
            event.tags,
            vec![vec!["p".to_owned(), receiver.public_key().to_hex()]]
        );
        let peeled = peel_recovery(to, &wrapped).await.unwrap();
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
            matches!(
                to.peel_welcome(&wrapped).await.unwrap().content,
                cgka_traits::PeeledContent::GroupRecovery { .. }
            ),
            "authenticated recovery must not enter Welcome handling"
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
    assert!(
        wrong.peel_welcome(&wrapped).await.is_err(),
        "wrong signer cannot authenticate or dispatch inbox control"
    );
    let mut forged_route = wrapped;
    forged_route.envelope = TransportEnvelope::Welcome {
        recipient: member(&foreign),
    };
    assert!(matches!(
        peel_recovery(&to, &forged_route).await,
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
        peel_recovery(&to, &wrapped).await,
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
        peel_recovery(&to, &forged).await.is_err(),
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
        peel_recovery(&to, &unsigned).await.is_err(),
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
            peel_recovery(&to, &wrapped).await.is_err(),
            "signed outer hint cannot replace authenticated inner version"
        );
    }
    let mut wrong_kind = rumor(&sender, &receiver, content.clone(), vec![protocol_tag()]);
    wrong_kind.kind = Kind::TextNote;
    assert!(
        peel_recovery(&to, &signed_carrier(&sender, &receiver, wrong_kind))
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
        let inner = rumor(
            &sender,
            &receiver,
            String::from_utf8(request().encode().unwrap()).unwrap(),
            vec![protocol_tag()],
        );
        let event = GiftWrapBuilder::new(receiver.public_key(), inner)
            .extra_tags(
                tags.iter()
                    .map(|tag| Tag::custom(&tag[0], tag[1..].iter().map(String::as_str))),
            )
            .finalize(&sender)
            .unwrap();
        let message = NostrTransportEvent::from_nostr_event(&event)
            .unwrap()
            .to_transport_message()
            .unwrap();
        assert_eq!(
            peel_recovery(&to, &message).await.unwrap().message,
            request(),
            "outer protocol-looking metadata cannot override the authenticated inner kind and version"
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
        peel_recovery(&to, &tampered).await.is_err(),
        "recomputed outer id does not repair a broken signature"
    );
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
    assert!(peel_recovery(&to, &wrapped).await.is_err());
    let mut oversize = wrapped;
    oversize.payload = vec![b' '; MAX_GROUP_RECOVERY_EVENT_BYTES + 1];
    assert!(peel_recovery(&to, &oversize).await.is_err());
}
