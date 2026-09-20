use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    // Metadata after the large plaintext column otherwise requires walking its
    // overflow pages. Keep selected composer reads on a blob-free covering index.
    tx.execute_batch(
        "CREATE INDEX message_draft_attachment_descriptors ON message_draft_attachments (
            group_id_hex, position, attachment_id, file_name, media_type,
            length(plaintext), dim, thumbhash, duration_seconds, waveform_samples_json
        );",
    )
    .storage()
}
