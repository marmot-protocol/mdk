//! One bounded local maintenance step. Shared snapshots are released before account writes.
use super::{presentation_peer, select_chat_presentation};
use crate::{AppError, UserProfileMetadata};
use storage_sqlite::SqliteAppStorage;
use storage_sqlite::{
    CHAT_PRESENTATION_BATCH_LIMIT, ChatPresentationActivePeer, ChatPresentationCatchUp,
    ChatPresentationInput, ChatPresentationVersion, SqliteAccountStorage, SqliteSharedStorage,
    StoredChatPresentation,
};

/// One local preparation batch shared by the account worker and offline first reads.
/// Storage CAS checks make overlapping callers safe; `false` alone does not establish
/// readiness because another caller may have committed the work in the meantime.
pub(crate) fn prepare_batch(
    account: &SqliteAccountStorage,
    shared: &SqliteSharedStorage,
    local: &str,
) -> Result<bool, AppError> {
    let initialized = prepare_base_rows(&account.app_storage(), local)?;
    Ok(maintain(account, shared, local)? || initialized)
}

/// Initialize one bounded batch without preparing unrelated selected values.
pub(crate) fn prepare_base_rows(account: &SqliteAppStorage, local: &str) -> Result<bool, AppError> {
    let classifier = crate::MarmotApp::chat_list_mention_classifier(local);
    let mut initialized = false;
    for group in account.pending_chat_presentation_rows()? {
        initialized |= account.initialize_chat_presentation_row(local, &group, &classifier)?;
    }
    Ok(initialized)
}

fn prepare(
    shared: &SqliteSharedStorage,
    local: &str,
    epoch: &[u8],
    inputs: Vec<ChatPresentationInput>,
) -> Result<Vec<(ChatPresentationInput, StoredChatPresentation)>, AppError> {
    inputs
        .into_iter()
        .map(|mut input| {
            let peer = presentation_peer(&input, local);
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
            input.search_peer_names = super::search_peer_names(&presentation, profile.as_ref());
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
    let account_app = account.app_storage();
    let checkpoint = account_app.chat_presentation_checkpoint()?;
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
        return commit_progress(&account_app, &checkpoint, &next, &[]);
    }
    if next.reconciling {
        let inputs = account_app.chat_presentation_inputs_after(next.reconcile_after.as_deref())?;
        next.reconcile_after = inputs
            .last()
            .map(|input| input.group_id_hex.clone())
            .or(next.reconcile_after);
        if inputs.len() < CHAT_PRESENTATION_BATCH_LIMIT {
            next.reconciling = false;
            next.reconcile_after = None;
        }
        let values = prepare(shared, local, &next.shared_epoch, inputs)?;
        return commit_progress(&account_app, &checkpoint, &next, &values);
    }
    // New dependencies hydrate directly even when their profile predates the watermark.
    let pending = account_app.pending_chat_presentation_inputs()?;
    if !pending.is_empty() {
        let values = prepare(shared, local, &next.shared_epoch, pending)?;
        return commit_progress(&account_app, &checkpoint, &next, &values);
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
            return commit_progress(&account_app, &checkpoint, &next, &[]);
        }
        let groups = account_app
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
            if let Some(input) = account_app.chat_presentation_input(&group)? {
                inputs.push(input);
            }
        }
        let values = prepare(shared, local, &next.shared_epoch, inputs)?;
        return commit_progress(&account_app, &checkpoint, &next, &values);
    }
    if next.revision == head.revision {
        return Ok(false);
    }
    let changes = shared.directory_presentation_changes(next.revision)?;
    if changes.head.store_epoch != next.shared_epoch {
        return Ok(true);
    }
    for change in &changes.changes {
        if account_app
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
    commit_progress(&account_app, &checkpoint, &next, &[])
}

fn commit_progress(
    account: &SqliteAppStorage,
    checkpoint: &storage_sqlite::ChatPresentationCheckpoint,
    next: &ChatPresentationCatchUp,
    values: &[(ChatPresentationInput, StoredChatPresentation)],
) -> Result<bool, AppError> {
    let advanced = account.commit_chat_presentation_batch(checkpoint, next, values)?;
    if !advanced {
        tracing::warn!(target: "marmot_app::runtime", method = "chat_presentation_maintenance",
            "presentation batch made no progress; retrying on the next wakeup or maintenance tick");
    }
    Ok(advanced)
}

/// Prepare only missing selections required by a bounded screen window. This does
/// not advance the account-wide catch-up checkpoint or wait for unrelated rows.
pub(crate) fn prepare_window(
    account: &SqliteAppStorage,
    shared: &SqliteSharedStorage,
    local: &str,
    groups: &[String],
) -> Result<(), AppError> {
    let epoch = shared.directory_presentation_version()?.store_epoch;
    for group in groups {
        let Some(input) = account.chat_presentation_input(group)? else {
            continue;
        };
        for (input, selected) in prepare(shared, local, &epoch, vec![input])? {
            account.store_chat_presentation(&input, &selected)?;
        }
    }
    Ok(())
}

/// Catch-up steps a text read runs before reporting "not ready".
const SEARCH_CATCH_UP_STEPS: usize = 4;

/// Bring the search text a query over `view` matches up to date, in bounded
/// work, so a text read never needs a running account worker: a few steps of
/// the account-wide profile catch-up (`maintain`), then one batch of the rows
/// pending in the view. The storage read reports pending rows as not ready;
/// catch-up still owed after these steps is reported here as
/// `ChatPresentationNotReady`, and the caller's retry continues it.
pub(crate) fn prepare_search_batch(
    app: &crate::MarmotApp,
    label: &str,
    account: &SqliteAccountStorage,
    local: &str,
    view: storage_sqlite::ChatListView,
) -> Result<(), AppError> {
    let shared = app.shared_storage()?;
    let app_storage = account.app_storage();
    let before = app_storage.chat_presentation_version()?;
    let mut owed = false;
    for _ in 0..SEARCH_CATCH_UP_STEPS {
        owed = maintain(account, &shared, local)?;
        if !owed {
            break;
        }
    }
    let pending = app_storage.chat_list_pending_search_text(view, CHAT_PRESENTATION_BATCH_LIMIT)?;
    let prepared = prepare_window(&app_storage, &shared, local, &pending);
    if owed || !pending.is_empty() {
        app.presentation_signals.wake();
    }
    let after = app_storage.chat_presentation_version()?;
    if after != before {
        // Other windows re-read rows this step rewrote.
        let _ = app
            .presentation_signals
            .updates
            .send(super::signals::PresentationInvalidation {
                account_label: label.to_owned(),
                version: after,
            });
    }
    prepared?;
    if owed {
        return Err(AppError::ChatPresentationNotReady);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
