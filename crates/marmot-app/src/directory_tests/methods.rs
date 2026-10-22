//! Directory record hydration over a real `MarmotApp`'s account home.

use crate::MarmotApp;
use nostr_directory::hydrate_directory_record;

#[test]
fn hydration_uses_one_catalog() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    let home = app.account_home();
    let alice = home.create_account("alice").unwrap();
    // Legacy homes can retain two labels for one identity.
    let mut alias = alice.clone();
    alias.label = "z-alias".into();
    let alias_dir = home.account_dir(&alias.label);
    fs_private::create_dir_all_private(&alias_dir).unwrap();
    fs_private::write_private(
        &alias_dir.join("account.json"),
        &serde_json::to_vec(&alias).unwrap(),
    )
    .unwrap();
    let local_accounts = app.directory().local_accounts_by_id().unwrap();
    let local = &local_accounts[&alice.account_id_hex];
    assert_eq!(
        *local.directory_for_test(),
        app.directory()
            .local_account_for_id_for_test(&alice.account_id_hex)
            .unwrap()
    );
    assert_eq!(local.label, home.accounts().unwrap().last().unwrap().label);
    assert_ne!(local.directory_for_test().label, local.label);
    // Notification's existing single-entry reader keeps the first alias.
    assert_eq!(
        app.display_name_from_directory_entry(&alice.account_id_hex, None)
            .unwrap()
            .as_deref(),
        Some(local.directory_for_test().label.as_str())
    );
    let entry = app
        .directory()
        .empty_directory_record_for_test(&alice.account_id_hex);
    for label in ["alice", "z-alias"] {
        fs_private::write_private(&home.account_dir(label).join("account.json"), b"broken")
            .unwrap();
    }
    for index in 0..1000 {
        let mut row = entry.clone();
        if index != 0 {
            row.account_id_hex = format!("{index:064x}");
        }
        let hydrated = hydrate_directory_record(row, &local_accounts).unwrap();
        if index == 0 {
            assert_eq!(hydrated.local_account.unwrap(), *local.directory_for_test());
        } else {
            assert!(hydrated.local_account.is_none());
        }
    }
    assert!(app.directory().local_accounts_by_id().unwrap().is_empty());
}
