use super::*;

/// Progress reaches the broadcast immediately; accounting cannot re-emit old
/// projection snapshots and distinguishes a closed subscriber set.
#[test]
fn projection_progress_counts_broadcast_results_without_buffering_snapshots() {
    let (events, mut receiver) = broadcast::channel(4);
    let progress = ProjectionPublicationProgress::new(events, "account", "label");
    let update = AppProjectionUpdate {
        group_id_hex: "group".into(),
        timeline_messages: Vec::new(),
        timeline_changes: Vec::new(),
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    };
    progress.publish(update.clone());
    assert!(
        matches!(receiver.try_recv().unwrap(), MarmotAppEvent::ProjectionUpdated(received) if received.update == update)
    );
    drop(receiver);
    progress.publish(update);
    let publication = progress.take_publication();
    assert_eq!(publication.attempted, 2);
    assert_eq!(publication.accepted, 1);
    assert_eq!(publication.no_subscribers, 1);
    assert_eq!(progress.take_publication().attempted, 0);
}
