//! The account's device group (mdk#2628 item 3.1): a hidden group holding
//! only this account's devices, with their roster
//! (`marmot.account.device-roster.v1`) as group state.
//!
//! - A device group is never a chat. It stays out of the chat list and every
//!   projection, while its transport routes stay live so its commits arrive.
//!   A group is one when the engine says it requires the roster, or when
//!   `device_groups` records it.
//! - This device trusts one only if it created it or joined it through the
//!   Welcome a confirmed link named. Requiring the roster never makes a group
//!   trusted, and holding the account key never authenticates a device.
//! - The engine decides which Welcome that is, before it joins (D28, D30).
//!   The new device records the link's expectation (the group, the signature
//!   key of the existing device's leaf, the end of the wait) before it sends
//!   its own confirmation, and the engine joins a device group only through
//!   the Welcome that matches it. The app never judges a joined group's
//!   Welcome after the fact.
//! - The founding Add may hold this account's own device only through the
//!   exact `KeyPackageRef` a confirmed link names (D14, D21).
//! - While this device trusts one, it names each KeyPackage in its own roster
//!   entry before that KeyPackage reaches its slot (3.4). The runtime holds
//!   publication until the roster does; this module tells it which group.
//!
//! - While this device trusts one, it tags its KeyPackages and leaves from
//!   its roster (3.1d). The founder's own entry carries its tag signature key
//!   from the start; a device that joins sets its own on its next maintenance
//!   pass.
//!
//! - The host reads the roster only as [`LinkedDevice`]s, this account's own
//!   devices, from the device group this device trusts. The group's own events
//!   never reach the host; `LinkedDevicesChanged` stands in for them.
//!
//! A confirmed link comes from device pairing. Until pairing reaches the app,
//! only the test-policy hook supplies one.

use cgka_traits::app_components::{
    AppComponentData, DEVICE_ROSTER_COMPONENT_ID, DeviceEntryV1, DeviceRosterV1, DeviceSlotId,
    DeviceStatusV1, NOSTR_ROUTING_COMPONENT_ID, decode_device_roster_v1, encode_device_roster_v1,
    encode_nostr_routing_v1,
};
use cgka_traits::engine::CreateGroupRequest;
use cgka_traits::storage::{
    DeviceGroupWelcomeExpectation, DeviceGroupWelcomeStorage as _, GroupStorage as _,
    MaintenanceStorage as _, StorageError,
};
use cgka_traits::{EpochId, Group, GroupId, KeyPackage, TransportGroupSubscription};
use rand::RngCore as _;
use rand::rngs::OsRng;
use storage_sqlite::{DeviceGroupRecord, DeviceGroupTrust};

use super::{AppClient, UnpublishedWelcomeDelivery, UnpublishedWelcomeKind, group_is_terminal};
use crate::{AppError, unix_now_seconds};

/// A link both devices confirmed, as device pairing produces it.
#[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedDeviceLink {
    /// The new device's published KeyPackage event.
    pub key_package_event_id_hex: String,
    /// That KeyPackage's `KeyPackageRef`, covered by the new device's
    /// confirmation.
    pub key_package_ref_hex: String,
    /// The device group, covered by the existing device's confirmation. On a
    /// first link the existing device chooses it before the group exists.
    pub device_group_id: GroupId,
    /// The MLS signature key of the existing device's leaf in that group,
    /// covered by the same confirmation: the only sender whose Welcome into
    /// it the new device joins (D28).
    pub welcome_sender_key: Vec<u8>,
}

/// How long the new device waits for its Welcome after it records a
/// confirmed link, in seconds: the pairing session's lifetime (D27). The
/// engine joins no Welcome under the link after it.
pub(crate) const WELCOME_WAIT_SECS: u64 = 600;

/// One of this account's devices, as the roster of the device group this
/// device trusts lists it. Every entry is this account's own device: the
/// engine refuses a device group that holds another account's leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedDevice {
    /// The device's KeyPackage slot (the Nostr `d`), 64 lowercase hex
    /// characters. Actions on the device name it by this.
    pub slot_id_hex: String,
    /// Whether this is the calling device.
    pub is_this_device: bool,
    /// The name the user gave the device; empty until set.
    pub label: String,
    /// The device's client name; empty until set.
    pub client: String,
    /// The device's platform; empty until set.
    pub platform: String,
    /// When the device was linked, in Unix seconds, as its linker wrote it.
    pub linked_at: u64,
    /// The slot of the device that linked it; `None` for the founder.
    pub linked_by_slot_id_hex: Option<String>,
    pub status: LinkedDeviceStatus,
    /// Its siblings add it to the chats the account's devices were already
    /// in when it was linked.
    pub add_to_all_chats: bool,
    /// Its siblings bring it chat history when they add it to a chat.
    pub bring_history: bool,
    /// Inactivity never removes it.
    pub keep_while_inactive: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkedDeviceStatus {
    Active,
    /// Its siblings marked it inactive.
    Inactive,
    /// It recorded that it is signing out.
    Leaving,
}

impl AppClient {
    /// Whether `group_id` is a device group.
    pub(crate) fn is_device_group(&self, group_id: &GroupId) -> Result<bool, AppError> {
        if self
            .app
            .account_storage(&self.state.label)?
            .app_storage()
            .device_group(&hex::encode(group_id.as_slice()))?
            .is_some()
        {
            return Ok(true);
        }
        self.holds_device_group(group_id)
    }

    /// Whether the engine holds `group_id` as a group requiring the roster.
    fn holds_device_group(&self, group_id: &GroupId) -> Result<bool, AppError> {
        Ok(self
            .stored_group(group_id)?
            .is_some_and(|group| requires_roster(&group)))
    }

    /// The engine's durable record of `group_id`. Every device-group decision
    /// reads it rather than the live group, which a deferred open has not
    /// hydrated yet and a quarantine hides, so neither changes a verdict.
    fn stored_group(&self, group_id: &GroupId) -> Result<Option<Group>, AppError> {
        match self
            .app
            .account_storage(&self.state.label)?
            .get_group(group_id)
        {
            Ok(group) => Ok(Some(group)),
            Err(StorageError::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether the host may learn of `group_id`: never for a device group,
    /// and never through a check that failed. Every host surface built from
    /// engine or recovery state rather than the projection filters with this:
    /// quarantine, history notices and their changes, epoch-stall
    /// escalations, deferred events, recovery-status and superseded-change
    /// updates, and Welcome redelivery.
    pub(crate) fn host_may_see_group(&self, group_id: &GroupId) -> bool {
        self.is_device_group(group_id)
            .is_ok_and(|is_device_group| !is_device_group)
    }

    /// [`Self::host_may_see_group`] for a hex group id.
    pub(crate) fn host_may_see_group_hex(&self, group_id_hex: &str) -> bool {
        hex::decode(group_id_hex).is_ok_and(|bytes| self.host_may_see_group(&GroupId::new(bytes)))
    }

    /// The device group's current route, or none once the group is terminal
    /// or unreadable. A device group never switches routes, so it keeps no
    /// prior ones. A deferred open has not hydrated the group yet: it has no
    /// route until the post-hydration reconcile installs one, and a routing
    /// rebuild before then must not fail on it.
    fn device_group_subscriptions(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<TransportGroupSubscription>, AppError> {
        if group_is_terminal(&self.runtime, group_id)
            || self.skips_quarantined_group_reads(group_id)
        {
            return Ok(Vec::new());
        }
        let routing = match self.nostr_routing_for_group(group_id) {
            Ok(routing) => routing,
            Err(error)
                if matches!(
                    error.as_engine_error(),
                    Some(cgka_traits::error::EngineError::GroupNotHydrated(_))
                ) =>
            {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        Ok(vec![routing.subscription(group_id)?])
    }

    /// Keep the device group's route live with no projection.
    pub(crate) fn ensure_device_group_route(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let subscriptions = self.device_group_subscriptions(group_id)?;
        Ok(self.routing.replace_group_routes(group_id, subscriptions))
    }

    /// Add every device group's route to a rebuilt routing snapshot.
    pub(crate) fn preserve_device_group_routes(
        &self,
        routing: &crate::AppTransportRouting,
    ) -> Result<(), AppError> {
        for group_id in self.runtime.live_group_ids()? {
            if self.state_group_record(&group_id).is_none() && self.is_device_group(&group_id)? {
                routing
                    .replace_group_routes(&group_id, self.device_group_subscriptions(&group_id)?);
            }
        }
        Ok(())
    }

    /// The existing device's side of a confirmed link: create the device group
    /// under the id the link chose, adding the new device's KeyPackage, the
    /// one with the confirmed `KeyPackageRef` and no other.
    ///
    /// Refused unless this device advertises the roster, has no device group
    /// of its own yet, and finds that KeyPackage published by this account.
    #[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
    pub(crate) async fn create_device_group(
        &mut self,
        link: &ConfirmedDeviceLink,
    ) -> Result<GroupId, AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        // The id names no group this device holds, so a restart can take a
        // held group under a `creating` row for this creation's. Nothing else
        // reaches this client before the row is written.
        if self.stored_group(&link.device_group_id)?.is_some() {
            return Err(AppError::DeviceGroupRefused("device_group_exists"));
        }
        let account = self.app.account_home().account(&self.state.label)?;
        let sibling = self
            .app
            .fetch_validated_account_key_packages(
                &self.state.label,
                Vec::new(),
                "create_device_group",
            )
            .await?
            .into_iter()
            .find(|fetched| {
                fetched.key_package_event_id == link.key_package_event_id_hex
                    && fetched.key_package_ref_hex == link.key_package_ref_hex
            })
            .ok_or(AppError::DeviceGroupRefused("key_package_not_published"))?;
        // The founding exception: this account's own device, through exactly
        // the confirmed KeyPackage. Directory validation already bound the
        // event's author to the credential; check the account and ref again
        // on the bytes the engine adds.
        let metadata = marmot_session::key_package_metadata(&sibling.key_package)
            .map_err(|error| AppError::InvalidKeyPackageEvent(error.to_string()))?;
        if metadata.credential_identity_hex != account.account_id_hex
            || metadata.key_package_ref_hex != link.key_package_ref_hex
        {
            return Err(AppError::DeviceGroupRefused("key_package_not_confirmed"));
        }
        let own_lifecycle = self
            .app
            .account_storage(&self.state.label)?
            .key_package_lifecycle()?
            .ok_or(AppError::DeviceGroupRefused("slot_unavailable"))?;
        let own_slot = device_slot(&own_lifecycle.stable_slot_id)?;
        let sibling_slot = device_slot(&sibling.key_package_id)?;
        if own_slot == sibling_slot {
            return Err(AppError::DeviceGroupRefused("key_package_not_confirmed"));
        }

        let now = unix_now_seconds();
        let mut roster = DeviceRosterV1::default();
        OsRng.fill_bytes(&mut roster.leaf_tag_key);
        // Each founding entry announces the KeyPackage in that device's slot
        // (3.4), so neither device owes a roster commit before it publishes.
        // This device's entry also carries its tag signature key, so the
        // engine tags its founding leaf (3.1d); the new device sets its own
        // once it joins.
        roster.devices.insert(
            own_slot,
            DeviceEntryV1 {
                linked_at: now,
                announced_key_package: own_lifecycle.current_key_package_ref,
                tag_signature_key: Some(self.runtime.own_signature_key()),
                ..DeviceEntryV1::default()
            },
        );
        roster.devices.insert(
            sibling_slot,
            DeviceEntryV1 {
                linked_at: now,
                linked_by: Some(own_slot),
                announced_key_package: Some(hex::decode(&link.key_package_ref_hex)?),
                ..DeviceEntryV1::default()
            },
        );
        let roster = encode_device_roster_v1(&roster)
            .map_err(|_| AppError::DeviceGroupRefused("roster_invalid"))?;
        let routing = encode_nostr_routing_v1(&self.app.new_nostr_routing(None)?)
            .map_err(AppError::InvalidNostrRouting)?;
        let request = CreateGroupRequest {
            name: String::new(),
            description: String::new(),
            members: vec![sibling.key_package],
            required_features: Vec::new(),
            app_components: vec![
                AppComponentData {
                    component_id: NOSTR_ROUTING_COMPONENT_ID,
                    data: routing,
                },
                AppComponentData {
                    component_id: DEVICE_ROSTER_COMPONENT_ID,
                    data: roster,
                },
            ],
            initial_admins: Vec::new(),
        };
        self.refresh_member_inbox_routes(std::iter::once(account.account_id_hex.as_str()))?;

        // Record the chosen id before the engine writes anything, so a crash
        // between the two leaves a row a restart settles.
        let group_id_hex = hex::encode(link.device_group_id.as_slice());
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if !storage.insert_device_group(&DeviceGroupRecord {
            group_id_hex: group_id_hex.clone(),
            trust: DeviceGroupTrust::Creating,
            key_package_ref_hex: Some(link.key_package_ref_hex.clone()),
            recorded_at: now,
        })? {
            return Err(AppError::DeviceGroupRefused("device_group_exists"));
        }
        let audit_context = Self::local_human_action_context(
            "create_device_group",
            vec!["members"],
            vec![NOSTR_ROUTING_COMPONENT_ID, DEVICE_ROSTER_COMPONENT_ID],
            Some(1),
        );
        let prepared = match self
            .runtime
            .prepare_create_group_with_chosen_id_and_audit_context(
                request,
                link.device_group_id.clone(),
                audit_context.clone(),
            )
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                storage.delete_device_group(&group_id_hex, DeviceGroupTrust::Creating)?;
                return Err(error.into());
            }
        };
        let group_id = prepared.group_id;
        // The group is canonical now, so nothing below may turn this into an
        // error. A restart settles the row and reinstalls the route.
        super::recover_post_canonical_result(
            "record_created_device_group",
            storage
                .set_device_group_trust(
                    &group_id_hex,
                    DeviceGroupTrust::Creating,
                    DeviceGroupTrust::Created,
                    None,
                    now,
                )
                .map(drop)
                .map_err(AppError::from),
        );
        let welcome_intents = super::recover_post_canonical_result(
            "prepare_device_group_welcome_delivery_index",
            Self::founding_welcome_delivery_intent_ids(&prepared.effects),
        );
        self.unpublished_welcome_delivery = Some(UnpublishedWelcomeDelivery {
            group_id: group_id.clone(),
            audit_context,
            kind: UnpublishedWelcomeKind::Founding {
                effects: prepared.effects,
                welcome_intents,
            },
        });
        super::recover_post_canonical_result(
            "install_device_group_route",
            self.ensure_device_group_route(&group_id).map(drop),
        );
        super::recover_post_canonical_result("name_device_tag_group", self.sync_device_tag_group());
        self.linked_devices_changed = true;
        Ok(group_id)
    }

    /// The new device's side of a confirmed link, before it sends its own
    /// confirmation: wait [`WELCOME_WAIT_SECS`] for the Welcome into the
    /// device group the link names, from the leaf it names. The engine joins
    /// that group only through that Welcome, and refuses every other Welcome
    /// into its id meanwhile, so a group someone else founded under the id
    /// never joins and never takes it.
    ///
    /// The group must be new to this device. Its waiting row is written
    /// first and removed again if the engine cannot record the expectation.
    /// A crash between the two writes leaves a row with no expectation
    /// behind it, which admits nothing and which the next sweep drops.
    #[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
    pub(crate) fn record_confirmed_device_link(
        &mut self,
        link: &ConfirmedDeviceLink,
    ) -> Result<(), AppError> {
        if !self.app.device_groups_enabled() {
            return Err(AppError::DeviceGroupRefused("roster_unsupported"));
        }
        let now = unix_now_seconds();
        self.end_welcome_waits(now)?;
        if self.stored_group(&link.device_group_id)?.is_some() {
            return Err(AppError::DeviceGroupRefused("device_group_exists"));
        }
        let group_id_hex = hex::encode(link.device_group_id.as_slice());
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if !storage.insert_device_group(&DeviceGroupRecord {
            group_id_hex: group_id_hex.clone(),
            trust: DeviceGroupTrust::AwaitingWelcome,
            key_package_ref_hex: Some(link.key_package_ref_hex.clone()),
            recorded_at: now,
        })? {
            return Err(AppError::DeviceGroupRefused("device_group_exists"));
        }
        let expected = self
            .runtime
            .expect_device_group_welcome(&DeviceGroupWelcomeExpectation {
                group_id: link.device_group_id.clone(),
                sender_signature_key: link.welcome_sender_key.clone(),
                expires_at: now.saturating_add(WELCOME_WAIT_SECS),
            });
        if let Err(error) = expected {
            storage.delete_device_group(&group_id_hex, DeviceGroupTrust::AwaitingWelcome)?;
            return Err(error.into());
        }
        Ok(())
    }

    /// The new device's side of a withdrawn link: stop waiting for the
    /// Welcome into `group_id`. The engine's expectation goes first, so once
    /// this returns no Welcome under the link joins; then the waiting row. On
    /// an error the caller retries, and a row left without its expectation
    /// admits nothing meanwhile.
    ///
    /// Returns whether the link was still waiting. When it was not, the
    /// Welcome already joined and the group settles as linked.
    #[cfg_attr(not(feature = "test-policy-overrides"), allow(dead_code))]
    pub(crate) fn withdraw_confirmed_device_link(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.runtime.withdraw_device_group_welcome(group_id)?;
        if self.stored_group(group_id)?.is_some() {
            return Ok(false);
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        storage.delete_device_group(
            &hex::encode(group_id.as_slice()),
            DeviceGroupTrust::AwaitingWelcome,
        )?;
        Ok(true)
    }

    /// End every wait for a link's Welcome that can no longer join a group:
    /// one that ran out by `now`, whose engine expectation goes first, and one
    /// with no expectation behind it, as a crash inside a record or a
    /// withdrawal leaves. Neither admits a Welcome, and a row left waiting
    /// would refuse a new link until the wait ran out. A group the engine
    /// holds under a waiting row joined in time, since the engine joins none
    /// after the wait or without the expectation, and settles as linked
    /// instead.
    pub(crate) fn end_welcome_waits(&mut self, now: u64) -> Result<(), AppError> {
        let account_storage = self.app.account_storage(&self.state.label)?;
        let storage = account_storage.app_storage();
        for record in storage.device_groups()? {
            if record.trust != DeviceGroupTrust::AwaitingWelcome {
                continue;
            }
            let group_id = GroupId::new(hex::decode(&record.group_id_hex)?);
            if self.stored_group(&group_id)?.is_some() {
                continue;
            }
            if now >= record.recorded_at.saturating_add(WELCOME_WAIT_SECS) {
                self.runtime.withdraw_device_group_welcome(&group_id)?;
            } else if account_storage
                .device_group_welcome_expectation(&group_id)?
                .is_some()
            {
                continue;
            }
            storage.delete_device_group(&record.group_id_hex, DeviceGroupTrust::AwaitingWelcome)?;
        }
        Ok(())
    }

    /// Settle the trust of a device group the engine holds, whether its
    /// Welcome was just processed or a restart finds a join the app never saw.
    /// It is trusted only as the one a confirmed link named; any other stays
    /// untrusted and hidden.
    ///
    /// Returns whether the group is a device group. One that took the id a
    /// link named without requiring the roster is not: the link's waiting row
    /// goes, and the group projects as any other.
    pub(crate) fn settle_held_device_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        let Some(group) = self.stored_group(group_id)? else {
            return Ok(true);
        };
        if !requires_roster(&group) {
            if storage.delete_device_group(&group_id_hex, DeviceGroupTrust::AwaitingWelcome)? {
                tracing::warn!(
                    target: "marmot_app::client::device_group",
                    method = "settle_held_device_group",
                    "a group without the roster took the id a confirmed link named; it is no device group"
                );
            }
            return Ok(storage.device_group(&group_id_hex)?.is_some());
        }
        let now = unix_now_seconds();
        if storage.set_device_group_trust(
            &group_id_hex,
            DeviceGroupTrust::AwaitingWelcome,
            DeviceGroupTrust::Linked,
            None,
            now,
        )? {
            self.linked_devices_changed = true;
            self.sync_device_tag_group()?;
            return Ok(true);
        }
        if storage.device_group(&group_id_hex)?.is_some() {
            return Ok(true);
        }
        storage.insert_device_group(&DeviceGroupRecord {
            group_id_hex,
            trust: DeviceGroupTrust::Untrusted,
            key_package_ref_hex: None,
            recorded_at: now,
        })?;
        tracing::warn!(
            target: "marmot_app::client::device_group",
            method = "settle_held_device_group",
            "holds a device group no confirmed link named; it stays untrusted"
        );
        Ok(true)
    }

    /// Settle creations a restart interrupted, and end waits for a link's
    /// Welcome that ran out. A row becomes `created` only if the engine holds
    /// the group as this device created it: requiring the roster, with a copy
    /// that began at epoch 0, where no Welcome-installed copy begins.
    /// Otherwise the row goes, and a device group the engine holds settles
    /// like any other held one.
    pub(crate) fn reconcile_device_groups(&mut self) -> Result<(), AppError> {
        self.end_welcome_waits(unix_now_seconds())?;
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        for record in storage.device_groups()? {
            if record.trust != DeviceGroupTrust::Creating {
                continue;
            }
            let group_id = GroupId::new(hex::decode(&record.group_id_hex)?);
            let created_here = self.stored_group(&group_id)?.is_some_and(|group| {
                requires_roster(&group) && group.local_copy_install_epoch == EpochId(0)
            });
            if created_here {
                storage.set_device_group_trust(
                    &record.group_id_hex,
                    DeviceGroupTrust::Creating,
                    DeviceGroupTrust::Created,
                    None,
                    record.recorded_at,
                )?;
                self.linked_devices_changed = true;
            } else {
                storage.delete_device_group(&record.group_id_hex, DeviceGroupTrust::Creating)?;
            }
        }
        Ok(())
    }

    /// Test-policy hook: act on `link` as the existing device, as if pairing
    /// had confirmed it, and deliver the founding Welcome. Pairing does not
    /// reach the app yet, so this is the only way to create a device group.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub async fn dev_create_device_group(
        &mut self,
        link: ConfirmedDeviceLink,
    ) -> Result<GroupId, AppError> {
        let group_id = self.create_device_group(&link).await?;
        self.drive_unpublished_welcome_delivery(None).await;
        Ok(group_id)
    }

    /// Test-policy hook: act on `link` as the new device, as if pairing had
    /// confirmed it.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub fn dev_record_confirmed_device_link(
        &mut self,
        link: ConfirmedDeviceLink,
    ) -> Result<(), AppError> {
        self.record_confirmed_device_link(&link)
    }

    /// Test-policy hook: withdraw a link this device recorded as the new
    /// device, as if pairing had cancelled it.
    #[cfg(feature = "test-policy-overrides")]
    #[doc(hidden)]
    pub fn dev_withdraw_confirmed_device_link(
        &mut self,
        group_id: &GroupId,
    ) -> Result<bool, AppError> {
        self.withdraw_confirmed_device_link(group_id)
    }

    /// Tell the runtime which device group this device announces its
    /// KeyPackages in (mdk#2628 3.4): the one [`Self::rostered_device_group`]
    /// picks. Every path that publishes a KeyPackage calls this first, so a
    /// change of trust holds from the next publication. The runtime reads the
    /// roster itself when it publishes, and holds publication back while it
    /// cannot.
    pub(crate) fn sync_key_package_announcement_group(&mut self) -> Result<(), AppError> {
        let group = self.rostered_device_group()?;
        self.runtime.set_key_package_announcement_group(group);
        Ok(())
    }

    /// Tell the runtime which device group this device tags its KeyPackages
    /// and leaves from (mdk#2628 3.1d): the one it announces in. Naming the
    /// group hydrates it, so a deferred open names it only once hydration
    /// has run; before then, and while the group is not live, this device
    /// builds untagged. The group stays named either way.
    pub(crate) fn sync_device_tag_group(&mut self) -> Result<(), AppError> {
        let group = self.rostered_device_group()?;
        let renamed = self.runtime.device_tag_group() != group.as_ref();
        if self.runtime.set_device_tag_group(group).is_err() && renamed {
            tracing::warn!(
                target: "marmot_app::client::device_group",
                method = "sync_device_tag_group",
                "this device's device group is not live; it tags nothing until it is"
            );
        }
        Ok(())
    }

    /// Publish a fresh KeyPackage for an app path that does not wait for
    /// maintenance, announcing it first in this device's device group. If
    /// the announcement, or this device's tag signature key before it, cannot
    /// be set now, the publication is refused with nothing staged, and
    /// maintenance makes them later.
    pub(crate) async fn publish_fresh_key_package_announced(
        &mut self,
    ) -> Result<KeyPackage, AppError> {
        self.sync_key_package_announcement_group()?;
        self.set_device_tag_key().await?;
        self.announce_and_publish_fresh_key_package().await
    }

    async fn announce_and_publish_fresh_key_package(&mut self) -> Result<KeyPackage, AppError> {
        self.announce_key_package(true).await?;
        Ok(self.runtime.publish_fresh_key_package().await?)
    }

    /// [`Self::publish_fresh_key_package_announced`] for a republication of
    /// the current KeyPackage. When the runtime would publish a fresh one
    /// instead, that one is announced.
    pub(crate) async fn republish_key_package_announced(&mut self) -> Result<KeyPackage, AppError> {
        self.sync_key_package_announcement_group()?;
        // Set first: once this device tags, an untagged current KeyPackage is
        // stale, and the republish falls back to a fresh one.
        self.set_device_tag_key().await?;
        if self.runtime.key_package_announcement_group().is_some()
            && self.runtime.key_package_republish_falls_back()?
        {
            return self.announce_and_publish_fresh_key_package().await;
        }
        self.announce_key_package(false).await?;
        Ok(self.runtime.republish_key_package().await?)
    }

    /// Announce the KeyPackage about to go out: a fresh one, staged now if
    /// none is, or the current one. A failed read of this device's device
    /// group refuses the publication, since the runtime treats no group as
    /// nothing to announce. A failed announcement leaves the runtime's gate to
    /// refuse it. The caller has named both groups.
    async fn announce_key_package(&mut self, fresh: bool) -> Result<(), AppError> {
        if self.runtime.key_package_announcement_group().is_none() {
            return Ok(());
        }
        let result = async {
            let held = self.epoch_gap_held_groups()?;
            let effects = if fresh {
                self.runtime
                    .announce_fresh_key_package_holding(&held)
                    .await?
            } else {
                self.runtime.announce_key_package_holding(&held).await?
            };
            self.observe_drained_session_events(&effects)
                .await
                .map(drop)
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(
                target: "marmot_app::client::device_group",
                method = "announce_key_package",
                error_kind = error.privacy_safe_kind(),
                "could not announce this device's key package; maintenance retries"
            );
        }
        Ok(())
    }

    /// Set this device's tag signature key in its roster entry if it is due,
    /// before a KeyPackage publication: the runtime stages none while it is
    /// due (mdk#2628 3.1d). A failed update leaves that gate to refuse the
    /// publication.
    async fn set_device_tag_key(&mut self) -> Result<(), AppError> {
        self.sync_device_tag_group()?;
        if self.runtime.device_tag_group().is_none() {
            return Ok(());
        }
        let result = async {
            let held = self.epoch_gap_held_groups()?;
            let effects = self.runtime.set_device_tag_key_holding(&held).await?;
            self.observe_drained_session_events(&effects)
                .await
                .map(drop)
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(
                target: "marmot_app::client::device_group",
                method = "set_device_tag_key",
                error_kind = error.privacy_safe_kind(),
                "could not set this device's tag signature key; maintenance retries"
            );
        }
        Ok(())
    }

    /// This account's device group, if this device trusts one.
    pub(crate) fn trusted_device_group(&self) -> Result<Option<GroupId>, AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        storage
            .device_groups()?
            .into_iter()
            .find(|record| record.trust.is_trusted())
            .map(|record| Ok(GroupId::new(hex::decode(record.group_id_hex)?)))
            .transpose()
    }

    /// The device group whose roster this device reads: the one it trusts,
    /// while device groups are on and it is stored, not terminal, and
    /// requires the roster. A group that cannot be looked up is
    /// `roster_unavailable`, an error that never names the group.
    fn rostered_device_group(&self) -> Result<Option<GroupId>, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(None);
        }
        let Some(group_id) = self.trusted_device_group()? else {
            return Ok(None);
        };
        if self
            .stored_group(&group_id)
            .map_err(|_| AppError::DeviceGroupRefused("roster_unavailable"))?
            .is_none_or(|group| group.is_terminal() || !requires_roster(&group))
        {
            return Ok(None);
        }
        Ok(Some(group_id))
    }

    /// The device group this device trusts and its roster: the one way to
    /// read the roster. None when device groups are off, when this device
    /// trusts none, or when that group is terminal. A roster that cannot be
    /// read is `roster_unavailable`, an error that never names the group.
    pub(crate) fn trusted_device_roster(
        &mut self,
    ) -> Result<Option<(GroupId, DeviceRosterV1)>, AppError> {
        let Some(group_id) = self.rostered_device_group()? else {
            return Ok(None);
        };
        let unavailable = || AppError::DeviceGroupRefused("roster_unavailable");
        if !self
            .runtime
            .ensure_group_hydrated(&group_id)
            .map_err(|_| unavailable())?
        {
            return Err(unavailable());
        }
        let roster = self
            .runtime
            .app_component(&group_id, DEVICE_ROSTER_COMPONENT_ID)
            .ok()
            .flatten()
            .and_then(|bytes| decode_device_roster_v1(&bytes).ok())
            .ok_or_else(unavailable)?;
        Ok(Some((group_id, roster)))
    }

    /// This account's devices from the trusted device group's roster: this
    /// device first, then by when each was linked, then by slot. Empty when
    /// [`Self::trusted_device_roster`] has no roster.
    pub(crate) fn linked_devices(&mut self) -> Result<Vec<LinkedDevice>, AppError> {
        let Some((_, roster)) = self.trusted_device_roster()? else {
            return Ok(Vec::new());
        };
        // A slot that is not 32 bytes names no roster entry.
        let own_slot = self
            .app
            .account_storage(&self.state.label)?
            .key_package_lifecycle()?
            .and_then(|lifecycle| device_slot(&lifecycle.stable_slot_id).ok());
        let mut devices: Vec<_> = roster
            .devices
            .into_iter()
            .map(|(slot, entry)| linked_device(slot, entry, own_slot.as_ref()))
            .collect();
        // Stable, so equal keys keep the roster's slot order.
        devices.sort_by_key(|device| (!device.is_this_device, device.linked_at));
        Ok(devices)
    }

    /// Whether the linked devices may have changed since the last call. Set
    /// at open and by every hidden device-group event and change of trust.
    pub(crate) fn take_linked_devices_changed(&mut self) -> bool {
        std::mem::take(&mut self.linked_devices_changed) && self.app.device_groups_enabled()
    }

    /// Whether this device's KeyPackage refresh is overdue because its device
    /// group can't take the announcement, so the host warns the user (D31
    /// choice 6). Always false while device groups are off. It names the
    /// device group first, so a change of trust since the last maintenance
    /// pass counts.
    pub(crate) fn key_package_refresh_overdue(&mut self) -> Result<bool, AppError> {
        if !self.app.device_groups_enabled() {
            return Ok(false);
        }
        self.sync_key_package_announcement_group()?;
        Ok(self.runtime.key_package_refresh_overdue()?)
    }

    /// Recompute [`Self::key_package_refresh_overdue`] after a maintenance
    /// pass, and owe hosts a `KeyPackageRefreshOverdueChanged` when it
    /// changed. A failed read keeps the last answer.
    pub(crate) fn note_key_package_refresh_overdue(&mut self) {
        let Ok(overdue) = self.key_package_refresh_overdue() else {
            return;
        };
        if self.key_package_refresh_overdue.replace(overdue) != Some(overdue) {
            self.key_package_refresh_overdue_changed = true;
        }
    }

    /// Whether the overdue-refresh answer may have changed since the last
    /// call. Set at open and when a maintenance pass changes it.
    pub(crate) fn take_key_package_refresh_overdue_changed(&mut self) -> bool {
        std::mem::take(&mut self.key_package_refresh_overdue_changed)
            && self.app.device_groups_enabled()
    }
}

fn linked_device(
    slot: DeviceSlotId,
    entry: DeviceEntryV1,
    own_slot: Option<&DeviceSlotId>,
) -> LinkedDevice {
    LinkedDevice {
        slot_id_hex: hex::encode(slot),
        is_this_device: own_slot == Some(&slot),
        label: entry.label,
        client: entry.client,
        platform: entry.platform,
        linked_at: entry.linked_at,
        linked_by_slot_id_hex: entry.linked_by.map(hex::encode),
        status: match entry.status {
            DeviceStatusV1::Active => LinkedDeviceStatus::Active,
            DeviceStatusV1::Inactive => LinkedDeviceStatus::Inactive,
            DeviceStatusV1::Leaving => LinkedDeviceStatus::Leaving,
        },
        add_to_all_chats: entry.settings.add_to_all_chats,
        bring_history: entry.settings.bring_history,
        keep_while_inactive: entry.settings.keep_while_inactive,
    }
}

fn requires_roster(group: &Group) -> bool {
    group
        .required_capabilities
        .app_components
        .contains(DEVICE_ROSTER_COMPONENT_ID)
}

/// A KeyPackage slot as the roster keys it: 32 bytes, the Nostr `d`.
fn device_slot(slot_hex: &str) -> Result<DeviceSlotId, AppError> {
    hex::decode(slot_hex)
        .ok()
        .and_then(|bytes| DeviceSlotId::try_from(bytes).ok())
        .ok_or(AppError::DeviceGroupRefused("slot_unavailable"))
}
