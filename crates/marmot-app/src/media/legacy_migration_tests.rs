use super::*;

const RUNNING: AttachmentMigrationState = AttachmentMigrationState::Running { remaining_bytes: 7 };

#[test]
fn the_reported_state_adds_what_batches_saw_to_the_database_view() {
    let mut progress = LegacyMigrationProgress::default();
    assert_eq!(
        progress.state(AttachmentMigrationState::NotNeeded),
        AttachmentMigrationState::NotNeeded
    );
    assert_eq!(progress.state(RUNNING), RUNNING);

    progress.paused = Some(5);
    assert_eq!(
        progress.state(RUNNING),
        AttachmentMigrationState::Paused { needed_bytes: 5 }
    );
    // A pause means nothing once the database holds no legacy bodies.
    assert_eq!(
        progress.state(AttachmentMigrationState::NotNeeded),
        AttachmentMigrationState::NotNeeded
    );

    progress.paused = None;
    progress.moved = true;
    assert_eq!(progress.state(RUNNING), RUNNING);
    assert_eq!(
        progress.state(AttachmentMigrationState::NotNeeded),
        AttachmentMigrationState::Complete
    );
}
