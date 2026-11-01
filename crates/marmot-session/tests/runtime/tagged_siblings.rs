// Tagged siblings: the setup a runtime test needs to add a sibling device to
// a chat (mdk#2628 3.5b-2), as the engine's tests build it on engines. A
// same-account Add goes through only when the adder is tagged in its
// account's device group, each KeyPackage is a private one its sibling handed
// over, and the chat names its relays. The Add publishes no Welcome; the
// adder owes a sibling Welcome, which it carries as a 461 in the device group.
// The device roster is advertisable only in test-policy builds.

/// Builders for two tagged devices of one account, a chat one of them is in,
/// and the 461 that carries a sibling Welcome between them.
#[cfg(feature = "test-policy-overrides")]
mod tagged_siblings {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use cgka_traits::IngestOutcome;
    use cgka_traits::app_components::{
        ACCOUNT_DEVICES_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1,
        DeviceRosterOperationV1, DeviceRosterUpdateV1, DeviceRosterV1, DeviceSlotId,
        NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_device_roster_update_v1,
        encode_device_roster_v1, encode_nostr_routing_v1,
    };
    use cgka_traits::engine::{KeyPackage, SiblingKeyPackage};
    use cgka_traits::storage::DeviceGroupWelcomeExpectation;
    use cgka_traits::welcome::SiblingWelcomeJoin;
    use marmot_session::{
        CanonicalizationPolicy, KIND_SIBLING_WELCOME, OwedSiblingWelcome, SiblingWelcome,
        key_package_metadata,
    };

    /// The device group's Nostr routing id; [`nostr_routing`] routes a chat
    /// through another.
    const DEVICE_GROUP_ROUTE: [u8; 32] = [0xd6; 32];
    const CHAT_ROUTE: [u8; 32] = [0x5a; 32];
    /// The relay [`nostr_routing`] names, which every group here uses.
    const RELAY: &str = "wss://group.example";
    pub(super) const NOW: u64 = 1_000;

    /// A session of `account` in `name.sqlite` advertising `components`
    /// beside the defaults and Nostr routing. It settles convergence without
    /// waiting, so a test applies another device's Commit in one step.
    fn session(
        dir: &tempfile::TempDir,
        name: &str,
        account: &[u8],
        components: &[u16],
    ) -> AccountDeviceSession {
        let mut supported = default_group_components();
        supported.insert(NOSTR_ROUTING_COMPONENT_ID);
        for component in components {
            supported.insert(*component);
        }
        AccountDeviceSession::open(
            SessionConfig::new(
                dir.path().join(format!("{name}.sqlite")),
                SqlCipherKey::new("tagged siblings").unwrap(),
                pad32(account),
                Box::new(nostr_peeler(account)),
            )
            .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner {
                keys: deterministic_nostr_keys(account),
            }))
            .protocol_profile(ProtocolProfile::Current)
            .supported_app_components(supported)
            .convergence_policy(CanonicalizationPolicy {
                settlement_quiescence_ms: 0,
                ..CanonicalizationPolicy::default()
            }),
        )
        .unwrap()
    }

    /// A device of `account` that can join its device group and chats that
    /// require account-devices, with a KeyPackage published under `slot`.
    /// The test publisher would give every device of an account one slot.
    async fn roster_device(
        dir: &tempfile::TempDir,
        name: &str,
        account: &[u8],
        slot: DeviceSlotId,
    ) -> Device {
        let session = session(
            dir,
            name,
            account,
            &[ACCOUNT_DEVICES_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID],
        );
        session
            .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
                hex::encode(slot),
            ))
            .unwrap();
        let mut device = Device::with_session(session, KeyPackage::new(Vec::new()));
        device.publish().await;
        device
    }

    /// The slot `device` publishes its KeyPackages under, which makes the
    /// roster entry there its own.
    pub(super) fn own_slot(device: &Device) -> DeviceSlotId {
        hex::decode(device.lifecycle().stable_slot_id)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn entry(label: &str) -> DeviceEntryV1 {
        DeviceEntryV1 {
            label: label.into(),
            client: "test-client".into(),
            ..DeviceEntryV1::default()
        }
    }

    fn key_package_ref(key_package: &KeyPackage) -> Vec<u8> {
        hex::decode(key_package_metadata(key_package).unwrap().key_package_ref_hex).unwrap()
    }

    /// `device` publishes `group_id` through `route` on [`RELAY`].
    fn route(device: &Device, group_id: &GroupId, route: [u8; 32]) {
        device.routing.update(|routing| {
            routing.with_group_route(
                group_id.clone(),
                route.to_vec(),
                vec![TransportEndpoint(RELAY.into())],
            )
        });
    }

    /// The group messages `device` has published, oldest first.
    fn group_messages(device: &Device) -> Vec<TransportMessage> {
        device
            .adapter
            .publishes()
            .into_iter()
            .map(|publish| publish.message)
            .filter(|message| matches!(message.envelope, TransportEnvelope::GroupMessage { .. }))
            .collect()
    }

    /// Alice's phone and laptop in her device group, whose id it returns.
    /// The phone founds it and links the laptop, as a confirmed device link
    /// does (mdk#2628 D28, D41), and each sets its tag signature key in its
    /// own roster entry, so both tag.
    pub(super) async fn tagged_phone_and_laptop(
        dir: &tempfile::TempDir,
    ) -> (Device, Device, GroupId) {
        let mut phone = roster_device(dir, "alice-phone", b"alice", [1; 32]).await;
        let mut laptop = roster_device(dir, "alice-laptop", b"alice", [2; 32]).await;
        let device_group = GroupId::new(vec![0xd6; 16]);
        let founding = DeviceRosterV1 {
            leaf_tag_key: [0x33; 32],
            devices: [(own_slot(&phone), entry("Phone"))].into_iter().collect(),
            ..DeviceRosterV1::default()
        };
        let laptop_entry = DeviceEntryV1 {
            announced_key_package: Some(key_package_ref(&laptop.key_package)),
            ..entry("Laptop")
        };
        let roster_update = encode_device_roster_update_v1(
            &DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(
                own_slot(&laptop),
                laptop_entry,
            )])
            .unwrap(),
        )
        .unwrap();
        laptop
            .runtime
            .expect_device_group_welcome(&DeviceGroupWelcomeExpectation {
                group_id: device_group.clone(),
                sender_signature_key: phone.runtime.own_signature_key(),
                key_package_ref: key_package_ref(&laptop.key_package),
                expires_at: u64::MAX,
            })
            .unwrap();
        let routing = NostrRoutingV1::new(DEVICE_GROUP_ROUTE, vec![RELAY.into()]).unwrap();
        let created = phone
            .runtime
            .session_mut()
            .create_group_with_chosen_id_and_audit_context(
                CreateGroupRequest {
                    name: String::new(),
                    description: String::new(),
                    members: vec![laptop.key_package.clone()],
                    required_features: Vec::new(),
                    app_components: vec![
                        AppComponentData {
                            component_id: DEVICE_ROSTER_COMPONENT_ID,
                            data: encode_device_roster_v1(&founding).unwrap(),
                        },
                        AppComponentData {
                            component_id: NOSTR_ROUTING_COMPONENT_ID,
                            data: encode_nostr_routing_v1(&routing).unwrap(),
                        },
                    ],
                    initial_admins: Vec::new(),
                },
                device_group.clone(),
                Some(roster_update),
                Timestamp(u64::MAX),
                Default::default(),
            )
            .await
            .unwrap();
        let [PublishWork::FoundingGroupCreated { welcomes }] = &created.effects.publish[..] else {
            panic!("expected founding group creation");
        };
        let [to_laptop] = &rumors_for(welcomes, b"alice", &[&laptop.key_package]).await[..] else {
            unreachable!()
        };
        assert_eq!(laptop.ingest(to_laptop).await.outcome, IngestOutcome::Processed);
        for device in [&mut phone, &mut laptop] {
            route(device, &device_group, DEVICE_GROUP_ROUTE);
            device
                .runtime
                .set_device_tag_group(Some(device_group.clone()))
                .unwrap();
        }
        set_own_key(&mut phone, &mut laptop, &device_group).await;
        set_own_key(&mut laptop, &mut phone, &device_group).await;
        (phone, laptop, device_group)
    }

    /// `device` sets its tag signature key in its own roster entry, and
    /// `sibling` applies the update.
    async fn set_own_key(device: &mut Device, sibling: &mut Device, device_group: &GroupId) {
        let before = group_messages(device).len();
        let effects = device
            .runtime
            .set_device_tag_key_holding(&[])
            .await
            .unwrap();
        assert!(effects.failures.is_empty(), "{:?}", effects.failures);
        let [update] = &group_messages(device)[before..] else {
            panic!("one roster update");
        };
        let epoch = sibling.runtime.session().epoch(device_group).unwrap();
        sibling
            .runtime
            .session_mut()
            .ingest(update.clone())
            .await
            .unwrap();
        sibling
            .runtime
            .advance_convergence(device_group)
            .await
            .unwrap();
        assert_eq!(
            sibling.runtime.session().epoch(device_group).unwrap().0,
            epoch.0 + 1
        );
    }

    /// Bob's chat, with `phone` as a member who is not an admin. Bob
    /// advertises account-devices, so the chat requires it from its founding
    /// (mdk#2628 item 2.3), and the phone joins with a fresh KeyPackage, which
    /// its tag names as its slot.
    pub(super) async fn bobs_chat_with(dir: &tempfile::TempDir, phone: &mut Device) -> GroupId {
        let mut bob = session(dir, "bob", b"bob", &[ACCOUNT_DEVICES_COMPONENT_ID]);
        phone.publish().await;
        let created = bob
            .create_group(CreateGroupRequest {
                name: "same account".into(),
                description: String::new(),
                members: vec![phone.key_package.clone()],
                required_features: Vec::new(),
                app_components: vec![nostr_routing()],
                initial_admins: Vec::new(),
            })
            .await
            .unwrap();
        let [PublishWork::FoundingGroupCreated { welcomes }] = &created.effects.publish[..] else {
            panic!("expected founding group creation");
        };
        let [to_phone] = &rumors_for(welcomes, b"alice", &[&phone.key_package]).await[..] else {
            unreachable!()
        };
        assert_eq!(phone.ingest(to_phone).await.outcome, IngestOutcome::Processed);
        let chat = created.group_id;
        assert!(
            phone
                .runtime
                .group_record(&chat)
                .unwrap()
                .required_capabilities
                .app_components
                .contains(ACCOUNT_DEVICES_COMPONENT_ID)
        );
        let alice = phone.runtime.self_id();
        assert!(
            !phone
                .runtime
                .admin_pubkeys(&chat)
                .unwrap()
                .iter()
                .any(|admin| admin.as_slice() == alice.as_slice())
        );
        route(phone, &chat, CHAT_ROUTE);
        chat
    }

    /// A private KeyPackage `sibling` issues to `to`, as its hand-off gives
    /// it.
    pub(super) fn handed(sibling: &mut Device, to: &Device) -> SiblingKeyPackage {
        let before = sibling.runtime.issued_private_key_packages().unwrap();
        assert_eq!(
            sibling
                .runtime
                .issue_private_key_packages(&own_slot(to), 1, None, NOW)
                .unwrap(),
            1
        );
        let issued = sibling
            .runtime
            .issued_private_key_packages()
            .unwrap()
            .into_iter()
            .find(|record| !before.contains(record))
            .unwrap();
        SiblingKeyPackage {
            slot: own_slot(sibling),
            key_package: KeyPackage::new(issued.key_package)
                .with_protocol_profile(ProtocolProfile::Current),
        }
    }

    /// `adder` carries `owed` as a 461 in `device_group`, pinned to the
    /// group's epoch and branch as the app sends it, and marks it delivered
    /// once the message is published. Returns the message.
    pub(super) async fn carry(
        adder: &mut Device,
        device_group: &GroupId,
        owed: &OwedSiblingWelcome,
    ) -> TransportMessage {
        let event = MarmotAppEvent::new(
            hex::encode(adder.runtime.self_id().as_slice()),
            NOW,
            KIND_SIBLING_WELCOME,
            Vec::new(),
            BASE64.encode(&owed.content),
        );
        let carrier = hex::decode(&event.id).unwrap();
        assert!(
            adder
                .runtime
                .carry_sibling_welcome(&owed.id, &carrier)
                .unwrap()
        );
        let before = group_messages(adder).len();
        let pin = adder.runtime.epoch_pin(device_group).unwrap();
        let effects = adder
            .runtime
            .send(SendIntent::AppMessage {
                group_id: device_group.clone(),
                payload: event.encode().unwrap(),
                expected_epoch: Some(pin),
            })
            .await
            .unwrap();
        assert!(
            effects
                .published_app_messages
                .iter()
                .any(|published| published.app_event_id == event.id)
        );
        assert!(
            adder
                .runtime
                .sibling_welcome_delivered(&owed.id, &carrier)
                .unwrap()
        );
        let [message] = &group_messages(adder)[before..] else {
            panic!("one device-group message");
        };
        message.clone()
    }

    /// `sibling` reads `message` in `device_group` and joins the chat through
    /// the sibling Welcome its 461 carries, as the app admits it. Returns the
    /// join's events.
    pub(super) async fn join_from(
        sibling: &mut Device,
        message: TransportMessage,
        device_group: &GroupId,
    ) -> Vec<GroupEvent> {
        let read = sibling
            .runtime
            .session_mut()
            .ingest(message)
            .await
            .unwrap();
        let received: Vec<_> = read
            .effects
            .events
            .into_iter()
            .filter_map(|event| match event {
                GroupEvent::MessageReceived {
                    group_id,
                    message_id,
                    payload,
                    ..
                } if &group_id == device_group => Some((message_id, payload)),
                _ => None,
            })
            .collect();
        let [(message_id, payload)] = &received[..] else {
            panic!("one device-group message read");
        };
        let event = MarmotAppEvent::decode(payload).unwrap();
        assert_eq!(event.kind, KIND_SIBLING_WELCOME);
        let welcome = SiblingWelcome::decode(&BASE64.decode(&event.content).unwrap()).unwrap();
        assert_eq!(
            sibling
                .runtime
                .join_sibling_welcome(message_id, &welcome, None)
                .await
                .unwrap(),
            SiblingWelcomeJoin::Settled(IngestOutcome::Processed)
        );
        sibling.runtime.session_mut().drain().events
    }
}
