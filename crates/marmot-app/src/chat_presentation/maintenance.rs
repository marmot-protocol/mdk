//! One bounded local maintenance step. Shared snapshots are released before account writes.
use super::select_chat_presentation;
use crate::{AppError, UserProfileMetadata};
use storage_sqlite::{
    CHAT_PRESENTATION_BATCH_LIMIT, ChatPresentationActivePeer, ChatPresentationCatchUp,
    ChatPresentationInput, ChatPresentationVersion, SqliteAccountStorage, SqliteSharedStorage,
    StoredChatPresentation,
};

fn prepare(
    shared: &SqliteSharedStorage,
    local: &str,
    epoch: &[u8],
    inputs: Vec<ChatPresentationInput>,
) -> Result<Vec<(ChatPresentationInput, StoredChatPresentation)>, AppError> {
    inputs
        .into_iter()
        .map(|input| {
            let peer = select_chat_presentation(&input, local, None).peer_id;
            let (profile, version) = if let Some(peer) = &peer {
                let evidence = shared.directory_presentation(peer)?;
                if evidence.version.store_epoch != epoch {
                    return Err(cgka_traits::storage::StorageError::Serialization(
                        "directory incarnation changed during presentation preparation".into(),
                    )
                    .into());
                }
                let profile = evidence
                    .profile_json
                    .map(|json| {
                        serde_json::from_str::<UserProfileMetadata>(&json).map_err(|_| {
                            cgka_traits::storage::StorageError::Serialization(
                                "invalid cached presentation profile".into(),
                            )
                        })
                    })
                    .transpose()?;
                (profile, evidence.version)
            } else {
                (
                    None,
                    ChatPresentationVersion {
                        store_epoch: epoch.to_vec(),
                        revision: 0,
                    },
                )
            };
            let presentation =
                select_chat_presentation(&input, local, peer.as_deref().zip(profile.as_ref()));
            Ok((
                input,
                StoredChatPresentation {
                    presentation,
                    profile_version: Some(version),
                },
            ))
        })
        .collect()
}

/// Returns whether another bounded step should be scheduled after yielding.
pub(crate) fn maintain(
    account: &SqliteAccountStorage,
    shared: &SqliteSharedStorage,
    local: &str,
) -> Result<bool, AppError> {
    let checkpoint = account.chat_presentation_checkpoint()?;
    let head = shared.directory_presentation_version()?;
    let mut next = checkpoint.state.clone();
    if next.shared_epoch != head.store_epoch {
        next = ChatPresentationCatchUp {
            shared_epoch: head.store_epoch,
            // Reconciliation reads current profiles directly. Only changes after this
            // captured head need replaying, including changes made while it runs.
            revision: head.revision,
            ..Default::default()
        };
        account.commit_chat_presentation_batch(&checkpoint, &next, &[])?;
        return Ok(true);
    }
    if next.reconciling {
        let inputs = account.chat_presentation_inputs_after(next.reconcile_after.as_deref())?;
        next.reconcile_after = inputs
            .last()
            .map(|input| input.group_id_hex.clone())
            .or(next.reconcile_after);
        if inputs.len() < CHAT_PRESENTATION_BATCH_LIMIT {
            next.reconciling = false;
            next.reconcile_after = None;
        }
        let values = prepare(shared, local, &next.shared_epoch, inputs)?;
        account.commit_chat_presentation_batch(&checkpoint, &next, &values)?;
        return Ok(true);
    }
    // New dependencies hydrate directly even when their profile predates the watermark.
    let pending = account.pending_chat_presentation_inputs()?;
    if !pending.is_empty() {
        let values = prepare(shared, local, &next.shared_epoch, pending)?;
        account.commit_chat_presentation_batch(&checkpoint, &next, &values)?;
        return Ok(true);
    }
    if let Some(mut active) = next.active.clone() {
        let current = shared.directory_presentation(&active.member_id_hex)?;
        if current.version.store_epoch != next.shared_epoch {
            return Ok(true);
        }
        if current.version.revision != active.revision {
            // Coalescing moved this identity past other unprocessed revisions. Abandon the old
            // cursor but keep the watermark; advancing it to the newer revision would skip them.
            next.active = None;
            account.commit_chat_presentation_batch(&checkpoint, &next, &[])?;
            return Ok(true);
        }
        let groups = account
            .chat_presentation_dependents(&active.member_id_hex, active.after_group.as_deref())?;
        active.after_group = groups.last().cloned().or(active.after_group);
        if groups.len() < CHAT_PRESENTATION_BATCH_LIMIT {
            next.revision = active.revision;
            next.active = None;
        } else {
            next.active = Some(active);
        }
        let mut inputs = Vec::with_capacity(groups.len());
        for group in groups {
            if let Some(input) = account.chat_presentation_input(&group)? {
                inputs.push(input);
            }
        }
        let values = prepare(shared, local, &next.shared_epoch, inputs)?;
        account.commit_chat_presentation_batch(&checkpoint, &next, &values)?;
        return Ok(true);
    }
    if next.revision == head.revision {
        return Ok(false);
    }
    let changes = shared.directory_presentation_changes(next.revision)?;
    if changes.head.store_epoch != next.shared_epoch {
        return Ok(true);
    }
    for change in &changes.changes {
        if account
            .chat_presentation_dependents(&change.member_id_hex, None)?
            .is_empty()
        {
            next.revision = change.version.revision;
            continue;
        }
        next.active = Some(ChatPresentationActivePeer {
            member_id_hex: change.member_id_hex.clone(),
            revision: change.version.revision,
            after_group: None,
        });
        break;
    }
    if changes.changes.is_empty() {
        next.revision = changes.head.revision;
    }
    account.commit_chat_presentation_batch(&checkpoint, &next, &[])?;
    Ok(true)
}
#[cfg(test)]
mod tests;
