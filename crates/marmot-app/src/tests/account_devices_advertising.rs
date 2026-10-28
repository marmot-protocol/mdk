//! MDK advertises `marmot.group.account-devices.v1` (mdk#2628, item 2.2):
//! fresh KeyPackages and new leaves list it, a device whose KeyPackage does
//! not is still invited, and no group requires it unless someone asks.

use super::canonical_membership::{app_at, deliver_new, published_key_package};
use super::*;
use cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID;
use cgka_traits::engine::SendIntent;

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
/// all advertise account-devices, and the group does not require it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn key_packages_and_leaves_advertise_account_devices_without_requiring_it() {
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
        assert!(!requires_account_devices(client, &group));
    }
}

/// A device on a build from before account-devices is still invited into a
/// group that does not require it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_package_without_account_devices_is_still_invited() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let carol = home.create_account("carol").unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay);
    remember_test_member_inbox(&app, &carol.account_id_hex, "wss://relay.example");
    let before_account_devices = app
        .supported_app_component_ids()
        .into_iter()
        .filter(|id| *id != ACCOUNT_DEVICES_COMPONENT_ID)
        .collect();
    let mut carol_key_package =
        fresh_key_package_with_components(&app, &carol, false, before_account_devices).await;
    assert!(!advertises_account_devices(&carol_key_package));
    // The Welcome rumor names the KeyPackage's publication.
    carol_key_package.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: MessageId::new(vec![0x5a; 32]),
    });

    let mut alice = app.client("alice").await.unwrap();
    let group = alice.create_group("team", &[]).await.unwrap();
    let effects = alice
        .runtime
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![carol_key_package],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(effects.failures.is_empty(), "{:?}", effects.failures);
    alice
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    assert!(
        alice
            .members(&group)
            .unwrap()
            .iter()
            .any(|member| member.member_id_hex == carol.account_id_hex)
    );
    assert!(!requires_account_devices(&alice, &group));
}
