//! MDK advertises `marmot.group.account-devices.v1` (mdk#2628, item 2.2):
//! fresh KeyPackages and new leaves list it, a group founded only by devices
//! that advertise it requires it (item 2.3), and devices that do not are
//! still invited into groups that do not require it. An admin turns it on in
//! an existing group only when the user asks (item 2.4).

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::*;
use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;

fn advertises_account_devices(key_package: &KeyPackage) -> bool {
    cgka_engine::key_package::key_package_metadata(key_package)
        .unwrap()
        .app_components
        .contains(&ACCOUNT_DEVICES_COMPONENT_ID)
}

fn requires_account_devices(client: &AppClient, group: &GroupId) -> bool {
    client
        .runtime
        .session()
        .group_record(group)
        .unwrap()
        .required_capabilities
        .app_components
        .contains(ACCOUNT_DEVICES_COMPONENT_ID)
}

/// Whether `client`'s own leaf in `group` advertises every component the app
/// supports, account-devices included.
fn own_leaf_advertises_everything(client: &AppClient, group: &GroupId) -> bool {
    client
        .runtime
        .session()
        .own_leaf_missing_app_components(group)
        .unwrap()
        .is_empty()
}

/// A published KeyPackage, the creator's leaf and an invited member's leaf
/// all advertise account-devices. Every founder advertises it, so the new
/// group requires it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_packages_and_leaves_advertise_account_devices() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob_id = home.create_account("bob").unwrap().account_id_hex;
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay.clone());
    assert!(
        app.supported_app_component_ids()
            .contains(&ACCOUNT_DEVICES_COMPONENT_ID)
    );
    remember_test_member_inbox(&app, &bob_id, "wss://relay.example");
    let mut bob = app.client("bob").await.unwrap();
    let bob_key_package = published_key_package(&mut bob, &relay).await;
    assert!(advertises_account_devices(&bob_key_package));
    bob.sync().await.unwrap();

    let mut alice = app.client("alice").await.unwrap();
    let group = alice.create_group("team", &[]).await.unwrap();
    assert!(own_leaf_advertises_everything(&alice, &group));
    assert!(requires_account_devices(&alice, &group));
    alice
        .invite_members(&group, &[bob_id.as_str()])
        .await
        .unwrap();
    let mut cursor = 0;
    deliver_new(&mut bob, &relay, &mut cursor).await;
    bob.sync().await.unwrap();
    bob.accept_group_invite(&group).unwrap();

    for client in [&alice, &bob] {
        assert_eq!(client.members(&group).unwrap().len(), 2);
        assert!(own_leaf_advertises_everything(client, &group));
        assert!(requires_account_devices(client, &group));
    }
}

/// Devices on a build from before account-devices: one founds a group with
/// an upgraded creator, so the group does not require it, and the other is
/// then invited.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_packages_without_account_devices_found_and_join_a_group() {
    let (directory, app, accounts, fetcher) = member_resolution_fixture(2, false).await;
    let before_account_devices = app
        .supported_app_component_ids()
        .into_iter()
        .filter(|id| *id != ACCOUNT_DEVICES_COMPONENT_ID)
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    for account in &accounts {
        let key_package =
            fresh_key_package_with_components(&app, account, false, before_account_devices.clone())
                .await;
        assert!(!advertises_account_devices(&key_package));
        events.push(member_resolution_key_package_event(account, key_package));
    }
    {
        let mut served = fetcher.events.lock().unwrap();
        served.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        served.extend(events);
    }
    let creator = AccountHome::open(directory.path())
        .create_account("creator")
        .unwrap();
    let mut client = app.client(&creator.label).await.unwrap();

    let group = client
        .create_group("team", &[accounts[0].account_id_hex.as_str()])
        .await
        .unwrap();
    assert!(own_leaf_advertises_everything(&client, &group));
    assert!(!requires_account_devices(&client, &group));
    client
        .invite_members(&group, &[accounts[1].account_id_hex.as_str()])
        .await
        .unwrap();
    assert_eq!(client.group_mls_state(&group).unwrap().member_count, 3);
    assert!(!requires_account_devices(&client, &group));
}

/// Turning account-devices on (mdk#2628, item 2.4) is an admin action the
/// user asks for. The host first reads an aggregate answer: a member device
/// without support holds the group back without being named, and the action
/// is refused before anything is published. Once that device is gone the
/// admin turns it on, and from then on it is enabled for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admin_turns_account_devices_on_once_the_group_is_eligible() {
    use cgka_traits::error::{AccountDevicesActivationRefusal, EngineError};

    let (directory, app, accounts, fetcher) = member_resolution_fixture(1, false).await;
    let before_account_devices = app
        .supported_app_component_ids()
        .into_iter()
        .filter(|id| *id != ACCOUNT_DEVICES_COMPONENT_ID)
        .collect::<Vec<_>>();
    let key_package =
        fresh_key_package_with_components(&app, &accounts[0], false, before_account_devices).await;
    {
        let mut served = fetcher.events.lock().unwrap();
        served.retain(|event| event.kind != KIND_MARMOT_KEY_PACKAGE);
        served.push(member_resolution_key_package_event(
            &accounts[0],
            key_package,
        ));
    }
    let creator = AccountHome::open(directory.path())
        .create_account("creator")
        .unwrap();
    let mut client = app.client(&creator.label).await.unwrap();
    let member = accounts[0].account_id_hex.as_str();
    let group = client.create_group("team", &[member]).await.unwrap();
    assert!(!requires_account_devices(&client, &group));

    assert_eq!(
        client.account_devices_activation(&group).unwrap(),
        AppAccountDevicesActivation::MembersNeedUpdate
    );
    let epoch = client.group_mls_state(&group).unwrap().epoch;
    let refused = client.enable_account_devices(&group).await.unwrap_err();
    assert!(
        matches!(
            refused.as_engine_error(),
            Some(EngineError::AccountDevicesActivationRefused {
                reason: AccountDevicesActivationRefusal::UnsupportedLeaves,
                ..
            })
        ),
        "{refused:?}"
    );
    assert_eq!(client.group_mls_state(&group).unwrap().epoch, epoch);
    assert!(!requires_account_devices(&client, &group));

    client.remove_members(&group, &[member]).await.unwrap();
    assert_eq!(
        client.account_devices_activation(&group).unwrap(),
        AppAccountDevicesActivation::Eligible
    );
    client.enable_account_devices(&group).await.unwrap();
    assert!(requires_account_devices(&client, &group));
    assert_eq!(
        client.account_devices_activation(&group).unwrap(),
        AppAccountDevicesActivation::AlreadyEnabled
    );
}
