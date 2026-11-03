// Tagged siblings: the setup a runtime test needs to add a sibling device to
// a chat (mdk#2628 3.5b-2), as the engine's tests build it on engines. A
// same-account Add goes through only when the adder is tagged in its
// account's device group, each KeyPackage is a private one its sibling handed
// over, and the chat names its relays. The Add publishes no Welcome; the
// adder owes a sibling Welcome, which it carries as a 461 in the device group.
// This fixture uses policy-test roster advertisement; explicit dev-device-groups
// builds may also advertise the adopted roster.

/// Builders for two tagged devices of one account, a chat one of them is in,
/// and the 461 that carries a sibling Welcome between them.
#[cfg(feature = "test-policy-overrides")]
mod tagged_siblings {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use cgka_traits::IngestOutcome;
    use cgka_traits::app_components::{
        ACCOUNT_DEVICES_COMPONENT_ID, AccountEntryV1, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1,
        DeviceRosterOperationV1, DeviceRosterUpdateV1, DeviceRosterV1, DeviceSlotId,
        NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, RejectedSlotReasonV1, RejectedSlotV1,
        decode_device_roster_v1, encode_device_roster_update_v1, encode_device_roster_v1,
        encode_nostr_routing_v1,
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
        hex::decode(
            key_package_metadata(key_package)
                .unwrap()
                .key_package_ref_hex,
        )
        .unwrap()
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
        assert_eq!(
            laptop.ingest(to_laptop).await.outcome,
            IngestOutcome::Processed
        );
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

    /// The one roster write path requires user-edit provenance before any
    /// publication, preserves the journal's supplied id, and leaves non-user
    /// metadata writes on that same id.
    #[tokio::test]
    async fn roster_user_edits_require_fresh_ids_and_non_user_edits_preserve_them() {
        use cgka_traits::EngineError;
        use cgka_traits::app_components::decode_device_roster_v1;
        use marmot_session::DeviceRosterEdit;

        fn read(device: &Device, group: &GroupId, slot: &DeviceSlotId) -> DeviceEntryV1 {
            let bytes = device
                .runtime
                .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
                .unwrap()
                .unwrap();
            decode_device_roster_v1(&bytes).unwrap().devices[slot].clone()
        }

        let dir = relaxed_storage_dir().unwrap();
        let (mut phone, _laptop, group) = tagged_phone_and_laptop(&dir).await;
        let slot = own_slot(&phone);
        let fresh = [0x71; 16];
        let edit = phone
            .runtime
            .edit_device_roster_entry(&group, &slot, &[], |entry| {
                entry.label = "Kitchen".into();
                entry.rename_id = Some(fresh);
            })
            .await
            .unwrap();
        assert!(matches!(edit, DeviceRosterEdit::Committed(_)));
        let current = read(&phone, &group, &slot);
        assert_eq!(current.label, "Kitchen");
        assert_eq!(current.rename_id, Some(fresh));
        let published = group_messages(&phone).len();

        for invalid in 0..3 {
            let error = phone
                .runtime
                .edit_device_roster_entry(&group, &slot, &[], |entry| match invalid {
                    0 => entry.label = "Stale id".into(),
                    1 => {
                        entry.settings.bring_history = !entry.settings.bring_history;
                        entry.rename_id = None;
                    }
                    _ => entry.rename_id = Some([0x72; 16]),
                })
                .await
                .unwrap_err();
            let expected = if invalid == 2 {
                "non-user device edit must preserve rename id"
            } else {
                "device label or settings edit needs a fresh rename id"
            };
            assert!(
                matches!(error.as_engine_error(), Some(EngineError::Serialize(reason)) if reason == expected)
            );
            assert_eq!(group_messages(&phone).len(), published);
            assert_eq!(read(&phone, &group, &slot), current);
        }

        phone
            .runtime
            .edit_device_roster_entry(&group, &slot, &[], |entry| {
                entry.platform = "desktop".into();
            })
            .await
            .unwrap();
        let metadata = read(&phone, &group, &slot);
        assert_eq!(metadata.platform, "desktop");
        assert_eq!(metadata.rename_id, Some(fresh));
        phone
            .runtime
            .edit_device_roster_entry(&group, &slot, &[], |entry| {
                entry.settings.bring_history = !entry.settings.bring_history;
                entry.rename_id = Some([0x73; 16]);
            })
            .await
            .unwrap();
        let settings = read(&phone, &group, &slot);
        assert_eq!(settings.rename_id, Some([0x73; 16]));
        assert_ne!(
            settings.settings.bring_history,
            metadata.settings.bring_history
        );
    }

    fn roster<A, R, K>(runtime: &AccountDeviceRuntime<A, R, K>, group: &GroupId) -> DeviceRosterV1
    where
        A: TransportAdapter,
        R: TransportRoutingPolicy,
        K: KeyPackagePublisher,
    {
        decode_device_roster_v1(
            &runtime
                .app_component(group, DEVICE_ROSTER_COMPONENT_ID)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    /// Make the actual unlink commit that removes this sibling and records its
    /// previously authenticated tag key, rather than seeding a roster row.
    async fn remove_sibling(
        phone: &mut Device,
        sibling: &Device,
        group: &GroupId,
        rejected_at: u64,
    ) {
        let slot = own_slot(sibling);
        let before = roster(&phone.runtime, group);
        let signature_key = phone
            .runtime
            .own_account_leaf_claims(group, &before)
            .unwrap()
            .into_iter()
            .find_map(|(key, claim)| {
                (claim == cgka_traits::app_components::DeviceTagClaim::Device(slot)).then_some(key)
            })
            .expect("the sibling has a tagged leaf");
        let removed = RejectedSlotV1 {
            reason: RejectedSlotReasonV1::Removed,
            rejected_at,
            tag_signature_key: before.devices[&slot].tag_signature_key.clone(),
        };
        assert!(removed.tag_signature_key.is_some());
        let update = DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::RemoveDevice(slot),
            DeviceRosterOperationV1::SetRejectedSlot(slot, removed.clone()),
        ])
        .unwrap();
        let effects = phone
            .runtime
            .send(SendIntent::UnlinkDevice {
                group_id: group.clone(),
                leaf_signature_key: signature_key,
                roster_update: encode_device_roster_update_v1(&update).unwrap(),
            })
            .await
            .unwrap();
        assert!(effects.failures.is_empty());
        assert!(matches!(
            effects.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
        let mut expected = before;
        expected.devices.remove(&slot);
        expected.rejected_slots.insert(slot, removed);
        assert_eq!(roster(&phone.runtime, group), expected);
    }

    /// Destructive withdrawal reads the trusted merged roster; the publisher
    /// supplies only external receipts, and zero ACK remains a retryable error.
    #[tokio::test]
    async fn removed_slot_withdrawal_checks_the_roster_and_acknowledgement() {
        let dir = relaxed_storage_dir().unwrap();
        let (mut phone, laptop, group) = tagged_phone_and_laptop(&dir).await;
        let own = own_slot(&phone);
        let removed = own_slot(&laptop);
        let not_me = [9; 32];
        phone
            .runtime
            .reject_device_slots(
                &group,
                &[],
                vec![(
                    not_me,
                    RejectedSlotV1 {
                        reason: RejectedSlotReasonV1::NotMe,
                        rejected_at: NOW,
                        tag_signature_key: None,
                    },
                )],
                Default::default(),
            )
            .await
            .unwrap();
        let before = roster(&phone.runtime, &group);
        let published = group_messages(&phone).len();
        for protected in [own, removed, not_me] {
            assert_eq!(
                phone
                    .runtime
                    .withdraw_removed_device_slot(&group, &protected)
                    .await
                    .unwrap(),
                None
            );
        }
        assert_eq!(group_messages(&phone).len(), published);
        assert_eq!(roster(&phone.runtime, &group), before);

        remove_sibling(&mut phone, &laptop, &group, NOW).await;
        let removed_roster = roster(&phone.runtime, &group);
        let routing = phone.routing.clone();
        drop(phone);
        let publisher = WithdrawingKeyPackages::default();
        let wall = Arc::new(TestWallClock::new(NOW));
        let mut runtime = AccountDeviceRuntime::new(
            session(
                &dir,
                "alice-phone",
                b"alice",
                &[ACCOUNT_DEVICES_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID],
            ),
            RecordingAdapter::default(),
            routing.clone(),
            publisher.clone(),
        )
        .with_maintenance_sources(
            wall,
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        assert_eq!(roster(&runtime, &group), removed_roster);
        assert_eq!(
            runtime
                .withdraw_removed_device_slot(&group, &removed)
                .await
                .unwrap(),
            None
        );
        assert!(
            publisher.withdrawals().is_empty(),
            "a reopened host must first name its trusted device group"
        );
        runtime.set_device_tag_group(Some(group.clone())).unwrap();

        routing.update(|routing| routing.key_package_endpoints(Vec::new()));
        let error = runtime
            .withdraw_removed_device_slot(&group, &removed)
            .await
            .unwrap_err();
        assert!(matches!(error, AccountError::KeyPackage(error)
            if error.message == "no KeyPackage publication endpoints are configured"
                && !error.externally_exposed && !error.artifact_unusable));
        assert!(publisher.withdrawals().is_empty());
        let endpoints = vec![
            TransportEndpoint("wss://keys-one.example".into()),
            TransportEndpoint("wss://keys-two.example".into()),
        ];
        routing.update(|routing| routing.key_package_endpoints(endpoints.clone()));
        publisher.refuse.store(true, Ordering::Relaxed);
        let error = runtime
            .withdraw_removed_device_slot(&group, &removed)
            .await
            .unwrap_err();
        assert!(matches!(error, AccountError::KeyPackage(error)
            if error.message == "no KeyPackage relay accepted the slot withdrawal"
                && !error.externally_exposed && !error.artifact_unusable));
        assert_eq!(publisher.withdrawals().len(), 1);
        assert_eq!(roster(&runtime, &group), removed_roster);

        publisher.refuse.store(false, Ordering::Relaxed);
        assert_eq!(
            runtime
                .withdraw_removed_device_slot(&group, &removed)
                .await
                .unwrap(),
            Some(2)
        );
        let expected = KeyPackageSlotWithdrawal {
            account_id: MemberId::new(pad32(b"alice")),
            slot_id: hex::encode(removed),
            created_at: Timestamp(NOW + 5 * 60),
            endpoints,
        };
        assert_eq!(publisher.withdrawals(), vec![expected.clone(), expected]);
        assert_eq!(roster(&runtime, &group), removed_roster);
    }

    /// Runtime-owned outcome/host-hold behavior; engine tests own SetAccount
    /// atomicity and stale expected-entry races.
    #[tokio::test]
    async fn account_roster_edit_waits_for_hold_and_reports_unchanged() {
        use marmot_session::{DeviceRosterEdit, DeviceRosterEditBlocked};

        let dir = relaxed_storage_dir().unwrap();
        let (mut phone, _laptop, group) = tagged_phone_and_laptop(&dir).await;
        let before = roster(&phone.runtime, &group);
        let desired = AccountEntryV1 {
            backup_writer: Some(own_slot(&phone)),
            recovery_public_key: Some(vec![0x71; 32]),
        };
        let published = group_messages(&phone).len();
        let held = phone
            .runtime
            .edit_roster_account_entry(&group, std::slice::from_ref(&group), |entry| {
                *entry = desired.clone()
            })
            .await
            .unwrap();
        assert!(matches!(
            held,
            DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Busy)
        ));
        assert_eq!(group_messages(&phone).len(), published);
        assert_eq!(roster(&phone.runtime, &group), before);

        let committed = phone
            .runtime
            .edit_roster_account_entry(&group, &[], |entry| *entry = desired.clone())
            .await
            .unwrap();
        assert!(matches!(committed, DeviceRosterEdit::Committed(effects)
            if effects.failures.is_empty()
                && matches!(effects.pending.as_slice(), [PendingResolution::Confirmed { .. }])));
        let mut expected = before;
        expected.account = desired.clone();
        assert_eq!(roster(&phone.runtime, &group), expected);
        assert_eq!(group_messages(&phone).len(), published + 1);
        let unchanged = phone
            .runtime
            .edit_roster_account_entry(&group, &[], |entry| *entry = desired.clone())
            .await
            .unwrap();
        assert!(matches!(unchanged, DeviceRosterEdit::Unchanged));
        let unreadable = phone
            .runtime
            .edit_roster_account_entry(&GroupId::new(vec![0xab; 16]), &[], |entry| *entry = desired)
            .await
            .unwrap();
        assert!(matches!(
            unreadable,
            DeviceRosterEdit::Blocked(DeviceRosterEditBlocked::Unreadable)
        ));
        assert_eq!(group_messages(&phone).len(), published + 1);
        assert_eq!(roster(&phone.runtime, &group), expected);
    }

    /// Pin the inclusive clock boundary instead of replaying the app's
    /// separate held/31-day/29-day relay journey.
    #[tokio::test]
    async fn removed_slot_record_expires_at_exactly_thirty_days() {
        const RETENTION: u64 = 30 * 24 * 60 * 60;
        let dir = relaxed_storage_dir().unwrap();
        let (mut phone, laptop, group) = tagged_phone_and_laptop(&dir).await;

        // The shared fixture delivered the founding Welcome to the laptop
        // directly. Complete its real outbound obligation through the runtime
        // before advancing maintenance, which also retries owed Welcomes.
        let owed = phone.runtime.outstanding_welcome_deliveries().unwrap();
        let [(owed_group, welcome)] = owed.as_slice() else {
            panic!("one founding Welcome is owed");
        };
        assert_eq!(owed_group, &group);
        assert!(
            matches!(&welcome.envelope, TransportEnvelope::Welcome { recipient }
            if *recipient == laptop.runtime.self_id())
        );
        let inbox = TransportEndpoint("wss://device-inbox.example".into());
        phone.routing.update(|routing| {
            routing.with_inbox_route(laptop.runtime.self_id(), vec![inbox.clone()])
        });
        let roster_before_delivery = roster(&phone.runtime, &group);
        let publishes_before_delivery = phone.adapter.publishes().len();
        let groups_before_delivery = group_messages(&phone).len();
        let delivered = phone.runtime.redeliver_welcome(&welcome.id).await.unwrap();
        assert!(delivered.failures.is_empty());
        assert!(delivered.welcome_failures.is_empty());
        assert!(delivered.pending.is_empty());
        let [report] = delivered.reports.as_slice() else {
            panic!("one founding Welcome publish report");
        };
        assert_eq!(report.message_id, welcome.id);
        assert!(report.met_required_acks());
        assert_eq!(report.accepted_count(), 1);
        let publishes = phone.adapter.publishes();
        let [request] = &publishes[publishes_before_delivery..] else {
            panic!("one founding Welcome publish request");
        };
        assert_eq!(request.message, *welcome);
        assert_eq!(request.target.endpoints(), &[inbox]);
        assert!(
            phone
                .runtime
                .outstanding_welcome_deliveries()
                .unwrap()
                .is_empty()
        );
        assert_eq!(group_messages(&phone).len(), groups_before_delivery);
        assert_eq!(roster(&phone.runtime, &group), roster_before_delivery);

        let removed = own_slot(&laptop);
        remove_sibling(&mut phone, &laptop, &group, NOW).await;
        let not_me = [9; 32];
        phone
            .runtime
            .reject_device_slots(
                &group,
                &[],
                vec![(
                    not_me,
                    RejectedSlotV1 {
                        reason: RejectedSlotReasonV1::NotMe,
                        rejected_at: NOW,
                        tag_signature_key: None,
                    },
                )],
                Default::default(),
            )
            .await
            .unwrap();
        let before = roster(&phone.runtime, &group);
        let published = group_messages(&phone).len();
        let wall = Arc::new(TestWallClock::new(NOW));
        phone.runtime = phone.runtime.with_maintenance_sources(
            wall.clone(),
            Arc::new(TestMonotonicClock::default()),
            Arc::new(TestRandom::new(0)),
        );
        wall.set(NOW + RETENTION - 1);
        let before_expiry = phone.runtime.run_due_maintenance().await.unwrap();
        assert!(before_expiry.failures.is_empty());
        assert!(before_expiry.welcome_failures.is_empty());
        assert!(before_expiry.pending.is_empty());
        assert_eq!(roster(&phone.runtime, &group), before);
        assert_eq!(group_messages(&phone).len(), published);

        wall.set(NOW + RETENTION);
        let expired = phone.runtime.run_due_maintenance().await.unwrap();
        assert!(expired.failures.is_empty());
        assert!(expired.welcome_failures.is_empty());
        assert!(matches!(
            expired.pending.as_slice(),
            [PendingResolution::Confirmed { .. }]
        ));
        let mut expected = before;
        expected.rejected_slots.remove(&removed);
        assert!(expected.rejected_slots.contains_key(&not_me));
        assert_eq!(roster(&phone.runtime, &group), expected);
        assert_eq!(group_messages(&phone).len(), published + 1);
        phone.runtime.run_due_maintenance().await.unwrap();
        assert_eq!(group_messages(&phone).len(), published + 1);
        assert_eq!(roster(&phone.runtime, &group), expected);
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
        assert_eq!(
            phone.ingest(to_phone).await.outcome,
            IngestOutcome::Processed
        );
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
        wall: &TestWallClock,
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
        adder.adapter.fail_endpoints_as(
            vec![TransportEndpoint(RELAY.into())],
            TransportEndpointFailureKind::PossiblyExposed,
        );
        let first = adder
            .runtime
            .send(SendIntent::AppMessage {
                group_id: device_group.clone(),
                payload: event.encode().unwrap(),
                expected_epoch: Some(pin),
            })
            .await
            .unwrap();
        assert!(
            first
                .unresolved_app_messages
                .iter()
                .any(|m| m.app_event_id == event.id)
        );
        assert!(
            !adder
                .runtime
                .sibling_welcome_send_failed(&owed.id, &carrier)
                .unwrap()
        );
        assert_eq!(
            adder.runtime.owed_sibling_welcomes(Timestamp(NOW)).unwrap()[0]
                .carrier
                .as_deref(),
            Some(carrier.as_slice())
        );
        adder
            .adapter
            .fail_endpoints_as(Vec::new(), TransportEndpointFailureKind::PossiblyExposed);
        wall.set(wall.0.load(Ordering::SeqCst) + 3_600);
        let effects = adder.runtime.resume_outbound_fanouts().await.unwrap();
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
        let [first, retry] = &group_messages(adder)[before..] else {
            panic!("the frozen device-group message is attempted twice");
        };
        assert_eq!(first, retry);
        retry.clone()
    }

    /// `sibling` reads `message` in `device_group` and joins the chat through
    /// the sibling Welcome its 461 carries, as the app admits it. Returns the
    /// join's events.
    pub(super) async fn join_from(
        sibling: &mut Device,
        message: TransportMessage,
        device_group: &GroupId,
    ) -> Vec<GroupEvent> {
        let read = sibling.runtime.session_mut().ingest(message).await.unwrap();
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
