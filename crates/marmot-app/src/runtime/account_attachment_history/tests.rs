use super::*;
use crate::{MarmotApp, MediaAttachmentOutcome};
use marmot_account::AccountHome;
use storage_sqlite::StoredAppEvent;
fn add(s: &storage_sqlite::SqliteAccountStorage, group: &str, id: u64) {
    s.record_app_event(&StoredAppEvent {
        group_id_hex: group.into(),
        message_id_hex: format!("{id:064x}"),
        source_message_id_hex: Some(format!("{:064x}", id + 100)),
        source_epoch: Some(0),
        direction: "received".into(),
        sender: "11".repeat(32),
        plaintext: "private caption".into(),
        kind: 9,
        tags: vec![vec!["imeta".into(), "v future".into()]],
        recorded_at: id,
        received_at: id,
        origin_commit_id: None,
        moderation_grant: false,
    })
    .unwrap();
}
#[tokio::test]
async fn account_pages_are_local_account_isolated_and_keep_typed_rejections() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path()).unwrap();
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let s = app.account_storage("alice").unwrap();
    let runtime = app.runtime();
    for id in 1..=3 {
        add(&s, if id == 2 { "bb" } else { "aa" }, id);
    }
    let AccountAttachmentPageRead::Page(first) = runtime
        .account_attachment_history_page("alice", AccountAttachmentQuery::default(), 1, None)
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert_eq!(first.entries[0].group_id_hex, "aa");
    assert!(matches!(
        first.entries[0].entry.attachment,
        MediaAttachmentOutcome::Rejected {
            attachment_index: 0,
            ..
        }
    ));
    assert!(s.due_attachment_acquisitions(1_000, 64).unwrap().is_empty());
    assert!(matches!(
        runtime
            .account_attachment_history_page(
                "bob",
                AccountAttachmentQuery::default(),
                1,
                first.next_cursor.clone()
            )
            .await
            .unwrap(),
        AccountAttachmentPageRead::CursorMismatch
    ));
    let AccountAttachmentPageRead::Page(empty) = runtime
        .account_attachment_history_page("bob", AccountAttachmentQuery::default(), 1, None)
        .await
        .unwrap()
    else {
        panic!("page")
    };
    assert!(empty.entries.is_empty());
    add(&s, "cc", 4);
    assert!(matches!(
        runtime
            .account_attachment_history_page(
                "alice",
                AccountAttachmentQuery::default(),
                1,
                first.next_cursor
            )
            .await
            .unwrap(),
        AccountAttachmentPageRead::Page(_)
    ));
    runtime.shutdown_and_close().await.unwrap();
    assert!(
        runtime
            .account_attachment_history_version("alice")
            .await
            .is_err()
    );
}
