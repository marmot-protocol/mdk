// Two devices of one account. Welcomes are gift-wrapped to the account, so
// each device receives the rumor for every KeyPackage an inviter added, and
// joins only through the one that names its own (`protocol-core/joining.md`,
// "Delivery"). These devices use the real Nostr peeler, so a delivery carries
// its rumor's `e` claim to the engine.

fn nostr_device_session(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    account: &[u8],
) -> AccountDeviceSession {
    nostr_device_session_with_peeler(path, key, account, Box::new(nostr_peeler(account)))
}

fn nostr_peeler(account: &[u8]) -> transport_nostr_peeler::NostrMlsPeeler {
    transport_nostr_peeler::NostrMlsPeeler::new()
        .with_welcome_signer(deterministic_nostr_keys(account))
}

fn nostr_device_session_with_peeler(
    path: impl Into<std::path::PathBuf>,
    key: &SqlCipherKey,
    account: &[u8],
    peeler: Box<dyn TransportPeeler>,
) -> AccountDeviceSession {
    use cgka_traits::app_components::NOSTR_ROUTING_COMPONENT_ID;
    let keys = deterministic_nostr_keys(account);
    let mut components = default_group_components();
    components.insert(NOSTR_ROUTING_COMPONENT_ID);
    AccountDeviceSession::open(
        SessionConfig::new(
            path,
            SqlCipherKey::new(key.as_secret_str()).unwrap(),
            pad32(account),
            peeler,
        )
        .account_identity_proof_signer(Arc::new(NostrAccountIdentityProofSigner { keys }))
        .protocol_profile(ProtocolProfile::Current)
        .supported_app_components(components),
    )
    .unwrap()
}

fn nostr_routing() -> AppComponentData {
    use cgka_traits::app_components::{
        NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, encode_nostr_routing_v1,
    };
    let routing = NostrRoutingV1::new([0x5a; 32], vec!["wss://group.example".into()]).unwrap();
    AppComponentData {
        component_id: NOSTR_ROUTING_COMPONENT_ID,
        data: encode_nostr_routing_v1(&routing).unwrap(),
    }
}

/// One device of an account, with its own database and a published
/// KeyPackage.
struct Device {
    runtime: AccountDeviceRuntime<RecordingAdapter, StaticTransportRouting, RecordingKeyPackages>,
    /// The device's current KeyPackage as an inviter fetches it, carrying the
    /// id of its publication for the inviter to name in the rumor.
    key_package: cgka_traits::engine::KeyPackage,
}

impl Device {
    async fn open(path: std::path::PathBuf, key: &SqlCipherKey, account: &[u8]) -> Self {
        let mut device = Self::with_session(
            nostr_device_session(path, key, account),
            cgka_traits::engine::KeyPackage::new(Vec::new()),
        );
        device.publish().await;
        device
    }

    fn with_session(
        session: AccountDeviceSession,
        key_package: cgka_traits::engine::KeyPackage,
    ) -> Self {
        Self {
            runtime: AccountDeviceRuntime::new(
                session,
                RecordingAdapter::default(),
                StaticTransportRouting::new(vec![])
                    .key_package_endpoints(vec![TransportEndpoint("wss://keys.example".into())]),
                RecordingKeyPackages::default(),
            ),
            key_package,
        }
    }

    /// Close the device and open its database again, as after an app update.
    fn reopen(self, path: std::path::PathBuf, key: &SqlCipherKey, account: &[u8]) -> Self {
        let Self {
            runtime,
            key_package,
        } = self;
        drop(runtime);
        Self::with_session(nostr_device_session(path, key, account), key_package)
    }

    async fn publish(&mut self) {
        let key_package = self.runtime.publish_fresh_key_package().await.unwrap();
        let event_id = self.lifecycle().authored_event_id.unwrap();
        self.key_package = cgka_traits::engine::KeyPackage {
            source: Some(cgka_traits::engine::KeyPackageSource { event_id }),
            ..key_package
        };
    }

    fn lifecycle(&self) -> cgka_traits::KeyPackageLifecycleState {
        self.runtime.key_package_maintenance_status().unwrap().unwrap()
    }

    async fn ingest(&mut self, welcome: &TransportMessage) -> marmot_session::IngestEffects {
        self.runtime
            .session_mut()
            .ingest(welcome.clone())
            .await
            .unwrap()
    }

    /// Ingest `welcomes` in order, keeping each delivery's effects.
    async fn ingest_all(
        &mut self,
        welcomes: &[&TransportMessage],
    ) -> Vec<marmot_session::IngestEffects> {
        let mut results = Vec::new();
        for welcome in welcomes {
            results.push(self.ingest(welcome).await);
        }
        results
    }

    fn rejoin_offers(&self, group_id: &GroupId) -> Vec<MessageId> {
        self.runtime
            .pending_group_rejoins_for(group_id)
            .unwrap()
            .into_iter()
            .map(|offer| offer.message_id)
            .collect()
    }
}

fn ignored(category: cgka_traits::ingest::InputRejectionCategory) -> cgka_traits::IngestOutcome {
    cgka_traits::IngestOutcome::Ignored { category }
}

fn not_addressed() -> cgka_traits::IngestOutcome {
    ignored(cgka_traits::ingest::InputRejectionCategory::NotAddressedToThisDevice)
}

fn duplicate() -> cgka_traits::IngestOutcome {
    ignored(cgka_traits::ingest::InputRejectionCategory::Duplicate)
}

fn outcomes(results: &[marmot_session::IngestEffects]) -> Vec<cgka_traits::IngestOutcome> {
    results
        .iter()
        .map(|effects| effects.outcome.clone())
        .collect()
}

/// The groups joined across `results`, with the delivery each came through.
fn joins(results: &[marmot_session::IngestEffects]) -> Vec<(GroupId, MessageId)> {
    results
        .iter()
        .flat_map(|effects| &effects.effects.events)
        .filter_map(|event| match event {
            GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                ..
            } => Some((group_id.clone(), via_welcome.clone())),
            _ => None,
        })
        .collect()
}

/// Peel `welcome` as a device of `account` would: the KeyPackage publication
/// its rumor names, and the MLS Welcome it carries.
async fn rumor(welcome: &TransportMessage, account: &[u8]) -> (MessageId, Vec<u8>) {
    let (peeled, provenance) = transport_nostr_peeler::NostrMlsPeeler::new()
        .with_welcome_signer(deterministic_nostr_keys(account))
        .peel_welcome_with_provenance(welcome)
        .await
        .unwrap();
    let PeeledContent::Welcome { bytes, .. } = peeled.content else {
        panic!("a Welcome rumor peels to Welcome content");
    };
    (
        MessageId::new(provenance.key_package_event_id.to_vec()),
        bytes,
    )
}

/// A rumor from `inviter` to `account` carrying `welcome_bytes` and naming
/// `key_package_event_id`.
async fn rewrapped(
    inviter: &[u8],
    account: &[u8],
    welcome_bytes: Vec<u8>,
    key_package_event_id: MessageId,
) -> TransportMessage {
    transport_nostr_peeler::NostrMlsPeeler::new()
        .with_welcome_signer(deterministic_nostr_keys(inviter))
        .wrap_welcome_with_metadata(
            &EncryptedPayload {
                ciphertext: welcome_bytes,
                aad: Vec::new(),
            },
            &MemberId::new(pad32(account)),
            &cgka_traits::engine::WelcomeMetadata {
                key_package_event_id,
                relays: vec![TransportEndpoint("wss://group.example".into())],
            },
        )
        .await
        .unwrap()
}

/// The inviter's side of adding devices of `account` in one Commit: one rumor
/// per added KeyPackage, each gift-wrapped to the account and naming that
/// KeyPackage, all carrying the same Welcome. Returns the rumors in the order
/// of `key_packages`.
async fn rumors_for(
    welcomes: &[TransportMessage],
    account: &[u8],
    key_packages: &[&cgka_traits::engine::KeyPackage],
) -> Vec<TransportMessage> {
    assert_eq!(welcomes.len(), key_packages.len(), "one rumor per KeyPackage");
    let account_id = MemberId::new(pad32(account));
    let mut named = Vec::new();
    for welcome in welcomes {
        assert!(matches!(
            &welcome.envelope,
            TransportEnvelope::Welcome { recipient } if recipient == &account_id
        ));
        let (names, welcome_bytes) = rumor(welcome, account).await;
        named.push((names, welcome_bytes, welcome));
    }
    assert!(
        named.windows(2).all(|pair| pair[0].1 == pair[1].1),
        "every rumor carries the one Welcome"
    );
    key_packages
        .iter()
        .map(|key_package| {
            let [(_, _, welcome)] = named
                .iter()
                .filter(|(names, _, _)| names == &publication_id(key_package))
                .collect::<Vec<_>>()[..]
            else {
                panic!("exactly one rumor names each KeyPackage");
            };
            (*welcome).clone()
        })
        .collect()
}

async fn create_group(
    inviter: &mut AccountDeviceSession,
    members: &[&cgka_traits::engine::KeyPackage],
    name: &str,
) -> (GroupId, Vec<TransportMessage>) {
    let created = inviter
        .create_group(CreateGroupRequest {
            name: name.into(),
            description: String::new(),
            members: members.iter().map(|&member| member.clone()).collect(),
            required_features: Vec::new(),
            app_components: vec![nostr_routing()],
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    let welcomes = match &created.effects.publish[..] {
        [PublishWork::FoundingGroupCreated { welcomes }] => welcomes.clone(),
        [PublishWork::GroupCreated { welcomes, pending }] => {
            inviter.confirm_published(*pending).await.unwrap();
            welcomes.clone()
        }
        _ => panic!("expected group creation publish work"),
    };
    (created.group_id, welcomes)
}

async fn evolve(inviter: &mut AccountDeviceSession, intent: SendIntent) -> Vec<TransportMessage> {
    let effects = inviter.send(intent).await.unwrap();
    let [PublishWork::GroupEvolution {
        welcomes, pending, ..
    }] = &effects.publish[..]
    else {
        panic!("expected one group evolution");
    };
    inviter.confirm_published(*pending).await.unwrap();
    welcomes.clone()
}

/// A device's KeyPackage records changed only by the consumption of
/// `consumed`.
#[track_caller]
fn assert_only_consumed(
    before: &cgka_traits::KeyPackageLifecycleState,
    mut after: cgka_traits::KeyPackageLifecycleState,
    consumed: &cgka_traits::engine::KeyPackage,
) {
    assert!(after.last_consumed_at.is_some());
    assert_eq!(
        after.last_consumed_key_package_ref,
        Some(key_package_ref(consumed))
    );
    after.last_consumed_at = before.last_consumed_at;
    after.last_consumed_key_package_ref = before.last_consumed_key_package_ref.clone();
    assert_eq!(&after, before);
}

/// Peels as releases before this check did: the rumor's KeyPackage claim never
/// reached the engine.
struct ClaimlessPeeler(transport_nostr_peeler::NostrMlsPeeler);

#[async_trait]
impl TransportPeeler for ClaimlessPeeler {
    async fn peel_group_recovery(
        &self,
        msg: &TransportMessage,
    ) -> Result<cgka_traits::AuthenticatedGroupRecovery, PeelerError> {
        self.0.peel_group_recovery(msg).await
    }

    async fn wrap_group_recovery(
        &self,
        message: &cgka_traits::GroupRecoveryMessage,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        self.0.wrap_group_recovery(message, recipient).await
    }

    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        self.0.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        let mut peeled = self.0.peel_welcome(msg).await?;
        if let PeeledContent::Welcome {
            key_package_event_id,
            ..
        } = &mut peeled.content
        {
            *key_package_event_id = None;
        }
        Ok(peeled)
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        self.0.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        self.0.wrap_welcome(payload, recipient).await
    }
}

/// Bob, and two devices of Alice's account that have each published a
/// KeyPackage.
struct Account {
    /// Holds every database for the test's lifetime.
    _dir: tempfile::TempDir,
    bob: AccountDeviceSession,
    phone: Device,
    laptop: Device,
}

async fn alice_with_two_devices(label: &str) -> Account {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new(label).unwrap();
    let phone = Device::open(dir.path().join("alice-phone.sqlite"), &key, b"alice").await;
    let laptop = Device::open(dir.path().join("alice-laptop.sqlite"), &key, b"alice").await;
    let bob = nostr_device_session(dir.path().join("bob.sqlite"), &key, b"bob");
    assert_eq!(
        phone.runtime.session().self_id(),
        laptop.runtime.session().self_id()
    );
    assert_ne!(
        publication_id(&phone.key_package),
        publication_id(&laptop.key_package)
    );
    Account {
        _dir: dir,
        bob,
        phone,
        laptop,
    }
}

#[tokio::test]
async fn each_device_joins_only_through_its_own_rumor_in_either_order() {
    let Account {
        _dir,
        mut bob,
        mut phone,
        mut laptop,
        ..
    } = alice_with_two_devices("multi-device welcome order").await;
    let (phone_before, laptop_before) = (phone.lifecycle(), laptop.lifecycle());
    let (group_id, welcomes) = create_group(&mut bob, &[&phone.key_package, &laptop.key_package], "both at once").await;
    let [to_phone, to_laptop] = &rumors_for(&welcomes, b"alice", &[&phone.key_package, &laptop.key_package]).await[..]
    else {
        unreachable!()
    };

    // The phone receives the laptop's rumor first, then both again.
    let results = phone
        .ingest_all(&[to_laptop, to_phone, to_laptop, to_phone])
        .await;
    assert_eq!(
        outcomes(&results),
        vec![
            not_addressed(),
            cgka_traits::IngestOutcome::Processed,
            duplicate(),
            duplicate(),
        ]
    );
    assert_eq!(joins(&results), vec![(group_id.clone(), to_phone.id.clone())]);

    // The laptop receives its own rumor first, then both again.
    let results = laptop
        .ingest_all(&[to_laptop, to_phone, to_phone, to_laptop])
        .await;
    assert_eq!(
        outcomes(&results),
        vec![
            cgka_traits::IngestOutcome::Processed,
            duplicate(),
            duplicate(),
            duplicate(),
        ]
    );
    assert_eq!(joins(&results), vec![(group_id.clone(), to_laptop.id.clone())]);

    // Neither device holds an offer, and each consumed only its own
    // KeyPackage.
    for (device, before) in [(&phone, &phone_before), (&laptop, &laptop_before)] {
        assert!(device.rejoin_offers(&group_id).is_empty());
        assert_only_consumed(before, device.lifecycle(), &device.key_package);
    }
}

#[tokio::test]
async fn a_sibling_added_later_leaves_the_member_device_as_it_was() {
    let Account {
        _dir,
        mut bob,
        mut phone,
        mut laptop,
        ..
    } = alice_with_two_devices("multi-device later sibling").await;
    let (group_id, welcomes) = create_group(&mut bob, &[&phone.key_package], "phone first").await;
    let [to_phone] = &rumors_for(&welcomes, b"alice", &[&phone.key_package]).await[..] else {
        unreachable!()
    };
    assert_eq!(
        phone.ingest(to_phone).await.outcome,
        cgka_traits::IngestOutcome::Processed
    );
    let phone_epoch = phone.runtime.session().epoch(&group_id).unwrap();
    let phone_before = phone.lifecycle();

    // The laptop's Welcome opens with no KeyPackage the phone holds, which
    // the phone used to record as a failed join.
    let welcomes = evolve(
        &mut bob,
        SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![laptop.key_package.clone()],
            initial_admins: Vec::new(),
        },
    )
    .await;
    let [to_laptop] = &rumors_for(&welcomes, b"alice", &[&laptop.key_package]).await[..] else {
        unreachable!()
    };
    let results = phone.ingest_all(&[to_laptop, to_laptop]).await;
    assert_eq!(outcomes(&results), vec![not_addressed(), duplicate()]);
    assert_eq!(
        phone.runtime.session().epoch(&group_id).unwrap(),
        phone_epoch
    );
    assert_eq!(phone.lifecycle(), phone_before);

    let results = laptop.ingest_all(&[to_laptop]).await;
    assert_eq!(joins(&results), vec![(group_id, to_laptop.id.clone())]);
}

#[tokio::test]
async fn a_rumor_naming_an_unknown_key_package_is_ignored_like_a_siblings() {
    let Account {
        _dir,
        mut bob,
        mut phone,
        ..
    } = alice_with_two_devices("multi-device unknown key package").await;
    let before = phone.lifecycle();
    let (group_id, welcomes) = create_group(&mut bob, &[&phone.key_package], "unknown claim").await;
    let [to_phone] = &rumors_for(&welcomes, b"alice", &[&phone.key_package]).await[..] else {
        unreachable!()
    };
    // The phone's own Welcome, named under a KeyPackage nobody published.
    let (_, welcome_bytes) = rumor(to_phone, b"alice").await;
    let unknown = rewrapped(
        b"bob",
        b"alice",
        welcome_bytes,
        MessageId::new(vec![0x99; 32]),
    )
    .await;

    let results = phone.ingest_all(&[&unknown, &unknown]).await;
    assert_eq!(outcomes(&results), vec![not_addressed(), duplicate()]);
    assert_eq!(phone.lifecycle(), before);
    assert!(phone.runtime.session().epoch(&group_id).is_err());

    let results = phone.ingest_all(&[to_phone, &unknown]).await;
    assert_eq!(
        outcomes(&results),
        vec![cgka_traits::IngestOutcome::Processed, duplicate()]
    );
    assert_eq!(joins(&results), vec![(group_id, to_phone.id.clone())]);
    assert_only_consumed(&before, phone.lifecycle(), &phone.key_package);
}

#[tokio::test]
async fn a_siblings_rumor_never_becomes_a_rejoin_offer() {
    let Account {
        _dir,
        mut bob,
        mut phone,
        mut laptop,
        ..
    } = alice_with_two_devices("multi-device rejoin").await;
    let (group_id, welcomes) = create_group(&mut bob, &[&phone.key_package], "rejoin").await;
    let [to_phone] = &rumors_for(&welcomes, b"alice", &[&phone.key_package]).await[..] else {
        unreachable!()
    };
    assert_eq!(
        phone.ingest(to_phone).await.outcome,
        cgka_traits::IngestOutcome::Processed
    );

    // Bob removes Alice while the phone is offline, then adds the phone's next
    // KeyPackage and the laptop in one Commit. The phone still holds the
    // group, and the one Welcome opens with its new KeyPackage too.
    evolve(
        &mut bob,
        SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![phone.runtime.session().self_id()],
        },
    )
    .await;
    phone.publish().await;
    let phone_before = phone.lifecycle();
    let welcomes = evolve(
        &mut bob,
        SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![phone.key_package.clone(), laptop.key_package.clone()],
            initial_admins: Vec::new(),
        },
    )
    .await;
    let [to_phone, to_laptop] = &rumors_for(&welcomes, b"alice", &[&phone.key_package, &laptop.key_package]).await[..]
    else {
        unreachable!()
    };

    let results = phone.ingest_all(&[to_laptop]).await;
    assert_eq!(outcomes(&results), vec![not_addressed()]);
    assert!(phone.rejoin_offers(&group_id).is_empty());
    assert_eq!(phone.lifecycle(), phone_before);

    let results = phone.ingest_all(&[to_phone, to_laptop]).await;
    assert_eq!(
        outcomes(&results)[0],
        cgka_traits::IngestOutcome::LocalState {
            state: cgka_traits::LocalIngestState::RejoinConfirmationRequired,
        }
    );
    assert_eq!(phone.rejoin_offers(&group_id), vec![to_phone.id.clone()]);

    let results = laptop.ingest_all(&[to_phone, to_laptop]).await;
    assert_eq!(outcomes(&results)[0], not_addressed());
    assert_eq!(joins(&results), vec![(group_id, to_laptop.id.clone())]);
}

#[tokio::test]
async fn a_key_package_retained_without_its_publication_id_still_opens_its_welcome() {
    let Account {
        _dir,
        mut bob,
        mut phone,
        ..
    } = alice_with_two_devices("multi-device legacy retained").await;
    let legacy = phone.key_package.clone();
    let (group_id, welcomes) = create_group(&mut bob, &[&phone.key_package], "legacy").await;
    let [to_phone] = &rumors_for(&welcomes, b"alice", &[&phone.key_package]).await[..] else {
        unreachable!()
    };

    // The phone replaces its KeyPackage, and its record of the old one
    // predates publication ids, as records written by earlier releases do.
    phone.publish().await;
    let mut lifecycle = phone.lifecycle();
    let retained = lifecycle
        .retained_private_material
        .iter_mut()
        .find(|material| material.key_package.bytes == legacy.bytes)
        .expect("the replaced KeyPackage keeps its private material");
    assert_eq!(retained.authored_event_id, Some(publication_id(&legacy)));
    retained.authored_event_id = None;
    phone
        .runtime
        .session()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    // The rumor names a publication the phone has no record of, but the
    // Welcome opens with a KeyPackage it holds and cannot attribute to any
    // publication: one of its own from before ids were recorded.
    let results = phone.ingest_all(&[to_phone]).await;
    assert_eq!(joins(&results), vec![(group_id, to_phone.id.clone())]);
}

#[tokio::test]
async fn a_welcome_naming_a_superseded_key_package_still_joins() {
    let Account {
        _dir,
        mut bob,
        mut phone,
        ..
    } = alice_with_two_devices("multi-device superseded").await;
    // Bob fetched the phone's KeyPackage just before the phone replaced it.
    let fetched = phone.key_package.clone();
    phone.publish().await;
    let before = phone.lifecycle();
    let (group_id, welcomes) = create_group(&mut bob, &[&fetched], "superseded").await;
    let [to_phone] = &rumors_for(&welcomes, b"alice", &[&fetched]).await[..] else {
        unreachable!()
    };

    let results = phone.ingest_all(&[to_phone]).await;
    assert_eq!(joins(&results), vec![(group_id, to_phone.id.clone())]);
    let after = phone.lifecycle();
    assert_eq!(after.current_key_package_ref, before.current_key_package_ref);
    assert!(
        after
            .retained_private_material
            .iter()
            .any(|material| material.key_package.bytes == fetched.bytes && material.consumed)
    );
}

/// The phone holds a group Bob has since removed Alice from, and Bob's next
/// Commit adds the phone's new KeyPackage and the laptop. The phone runs a
/// release from before deliveries were checked against its KeyPackages.
/// Returns the phone, the group, and the rumors to the phone and to the
/// laptop.
async fn rejoin_before_the_upgrade(
    dir: &tempfile::TempDir,
    key: &SqlCipherKey,
) -> (
    Device,
    GroupId,
    TransportMessage,
    TransportMessage,
) {
    let path = dir.path().join("alice-phone.sqlite");
    let mut phone = Device::with_session(
        nostr_device_session_with_peeler(
            path,
            key,
            b"alice",
            Box::new(ClaimlessPeeler(nostr_peeler(b"alice"))),
        ),
        cgka_traits::engine::KeyPackage::new(Vec::new()),
    );
    phone.publish().await;
    let laptop = Device::open(dir.path().join("alice-laptop.sqlite"), key, b"alice").await;
    let mut bob = nostr_device_session(dir.path().join("bob.sqlite"), key, b"bob");
    let (group_id, welcomes) = create_group(&mut bob, &[&phone.key_package], "upgrade").await;
    let [to_phone] = &rumors_for(&welcomes, b"alice", &[&phone.key_package]).await[..] else {
        unreachable!()
    };
    assert_eq!(
        phone.ingest(to_phone).await.outcome,
        cgka_traits::IngestOutcome::Processed
    );
    evolve(
        &mut bob,
        SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![phone.runtime.session().self_id()],
        },
    )
    .await;
    phone.publish().await;
    let welcomes = evolve(
        &mut bob,
        SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![phone.key_package.clone(), laptop.key_package.clone()],
            initial_admins: Vec::new(),
        },
    )
    .await;
    let [to_phone, to_laptop] = &rumors_for(
        &welcomes,
        b"alice",
        &[&phone.key_package, &laptop.key_package],
    )
    .await[..]
    else {
        unreachable!()
    };
    (phone, group_id, to_phone.clone(), to_laptop.clone())
}

fn rejoin_required() -> cgka_traits::IngestOutcome {
    cgka_traits::IngestOutcome::LocalState {
        state: cgka_traits::LocalIngestState::RejoinConfirmationRequired,
    }
}

#[tokio::test]
async fn an_offer_stored_before_the_upgrade_under_a_siblings_rumor_still_rejoins() {
    let dir = tempfile::tempdir().unwrap();
    let key = SqlCipherKey::new("multi-device upgrade offer").unwrap();
    let (mut phone, group_id, to_phone, to_laptop) = rejoin_before_the_upgrade(&dir, &key).await;
    // The old release offers the laptop's rumor, which also opens with the
    // phone's KeyPackage, and keeps that first copy when the phone's own
    // rumor arrives.
    let results = phone.ingest_all(&[&to_laptop, &to_phone]).await;
    assert_eq!(
        outcomes(&results),
        vec![rejoin_required(), rejoin_required()]
    );
    assert_eq!(phone.rejoin_offers(&group_id), vec![to_laptop.id.clone()]);

    // After the update the stored offer is still the phone's to confirm: its
    // Welcome opens with the phone's own KeyPackage, and the phone's own
    // rumor is long past the transport cursor.
    let mut phone = phone.reopen(dir.path().join("alice-phone.sqlite"), &key, b"alice");
    assert_eq!(phone.ingest(&to_phone).await.outcome, rejoin_required());
    assert_eq!(phone.rejoin_offers(&group_id), vec![to_laptop.id.clone()]);
    let offer = phone
        .runtime
        .pending_group_rejoins_for(&group_id)
        .unwrap()
        .remove(0);
    let joined = phone
        .runtime
        .confirm_group_rejoin(&offer.message_id, &offer.rejoin.unwrap().local_state_token)
        .await
        .unwrap();
    assert_eq!(joined, group_id);
    assert_eq!(
        phone.lifecycle().last_consumed_key_package_ref,
        Some(key_package_ref(&phone.key_package))
    );
}

/// The publication an inviter names when it adds `key_package`.
fn publication_id(key_package: &cgka_traits::engine::KeyPackage) -> MessageId {
    key_package.source.clone().unwrap().event_id
}
