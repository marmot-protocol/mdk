//! Search operands are captured once, outside loaded-row authority. Platform
//! matching remains the existing host predicate over these owned scalar facts.
use super::*;
use crate::chat_selection::presentation::{
    SearchMessage, SearchPresentation, SearchPreviewMessage,
};

pub(super) fn preview(
    input: &storage_sqlite::SelectionSearchPreviewInput,
    scope: &super::super::presentation::SearchScope,
    now: i64,
    replacement: Option<&Option<SearchPreviewMessage>>,
    media_preview_fallbacks: &HashMap<String, String>,
    budget: &CaptureBudget,
) -> Result<SearchPresentation, ContextError> {
    let encoded = input
        .routing_component_hex
        .as_deref()
        .ok_or(ContextError::NotReady(RequiredContext::AccountSource))?;
    let bytes =
        hex::decode(encoded).map_err(|_| ContextError::NotReady(RequiredContext::AccountSource))?;
    let routing = crate::AppGroupNostrRoutingComponent::from_bytes(&bytes)
        .map_err(|_| ContextError::NotReady(RequiredContext::AccountSource))?;
    if input
        .media_json
        .as_ref()
        .map_or(0, String::len)
        .checked_mul(32)
        .is_none_or(|estimate| estimate > budget.remaining_total())
    {
        return Err(ContextError::ResourceExhausted);
    }
    let mut last_message = if let Some(replacement) = replacement {
        replacement
            .as_ref()
            .map(SearchPreviewMessage::try_owned_copy)
            .transpose()
            .map_err(resource)?
    } else if let Some(message_id) = &input.message_id_hex {
        let (attachment_kind, attachment_count) =
            crate::media::classify_chat_list_attachments(input.media_json.as_deref());
        Some(SearchPreviewMessage {
            message_id_hex: super::super::presentation::owned_text(message_id).map_err(resource)?,
            resolved_media_preview_fallback: None,
            plaintext: super::super::presentation::owned_text(&input.plaintext)
                .map_err(resource)?,
            kind: input.kind,
            deleted: input.deleted,
            attachment_kind,
            attachment_count,
            group_system: input.group_system.clone(),
        })
    } else {
        None
    };
    bind_media_preview_fallback(last_message.as_mut(), media_preview_fallbacks)?;
    Ok(SearchPresentation {
        scope: scope.clone(),
        nostr_group_id_hex: routing.nostr_group_id_hex,
        last_message,
        messages: Vec::new(),
        capture_now_ms: now,
    })
}
/// Bind only an exact chosen message, including optimistic replacement. A
/// previous message's cache entry cannot supply the current preview's text.
fn bind_media_preview_fallback(
    preview: Option<&mut SearchPreviewMessage>,
    fallbacks: &HashMap<String, String>,
) -> Result<(), ContextError> {
    if let Some(preview) = preview {
        preview.resolved_media_preview_fallback = fallbacks
            .get(&preview.message_id_hex)
            .map(|text| super::super::presentation::owned_text(text))
            .transpose()
            .map_err(resource)?;
    }
    Ok(())
}
impl CaptureBuilder {
    pub fn capture_search_messages(
        &mut self,
        store: &storage_sqlite::SqliteAppStorage,
        cancelled: &impl Fn() -> bool,
    ) -> Result<(), ContextError> {
        let Some(search) = self.scope.search.as_ref() else {
            return Ok(());
        };
        if self.operands.is_empty() {
            return Ok(());
        }
        self.budget
            .charge(
                0,
                self.candidates
                    .len()
                    .checked_mul(256)
                    .ok_or(ContextError::ResourceExhausted)?,
            )
            .map_err(resource)?;
        // Borrow identities from native candidate ownership, not host rows.
        let mut by_group = HashMap::new();
        by_group
            .try_reserve(self.candidates.len())
            .map_err(|_| ContextError::ResourceExhausted)?;
        for (index, candidate) in self.candidates.iter().enumerate() {
            by_group.insert(candidate.id.as_str(), index);
        }
        let mut operand_indices = HashMap::new();
        operand_indices
            .try_reserve(self.operands.len())
            .map_err(|_| ContextError::ResourceExhausted)?;
        for (index, operand) in self.operands.iter().enumerate() {
            operand_indices.insert(operand.candidate_slot as usize, index);
        }
        let now = self.capture_now_ms;
        let operands = &mut self.operands;
        let budget = &mut self.budget;
        store.visit_selection_messages(
            search.sql_needle.as_deref(),
            budget.remaining_text(),
            cancelled,
            &|group, kind, deleted| {
                !deleted
                    && matches!(kind, 1 | 9 | 1209)
                    && by_group
                        .get(group)
                        .is_some_and(|slot| operand_indices.contains_key(slot))
            },
            &mut |input| {
                if input.deleted || !matches!(input.kind, 1 | 9 | 1209) {
                    return Ok(());
                }
                let Some(index) = by_group
                    .get(input.group_id_hex)
                    .and_then(|slot| operand_indices.get(slot))
                    .copied()
                else {
                    return Ok(());
                };
                let target = operands[index]
                    .search
                    .as_mut()
                    .ok_or(ContextError::NotReady(RequiredContext::Presentation))?;
                // Preflight every unbounded source byte before serde/copy. Raw imeta
                // is transient; only accepted MIME scalar strings are retained.
                let raw = input
                    .message_id_hex
                    .len()
                    .checked_add(input.sender.len())
                    .and_then(|n| n.checked_add(input.plaintext.len()))
                    .and_then(|n| n.checked_add(input.media_json.map_or(0, str::len)))
                    .ok_or(ContextError::ResourceExhausted)?;
                if raw > budget.remaining_text()
                    || input
                        .media_json
                        .map_or(0, str::len)
                        .checked_mul(32)
                        .and_then(|n| n.checked_add(raw))
                        .is_none_or(|estimate| estimate > budget.remaining_total())
                {
                    return Err(ContextError::ResourceExhausted);
                }
                let media = input.media_json.map(|raw| {
                    serde_json::from_str::<serde_json::Value>(raw)
                        .unwrap_or_else(|_| serde_json::Value::String(raw.to_owned()))
                });
                let outcomes = crate::media_attachment_outcomes_from_media_json(
                    media.as_ref(),
                    input.source_epoch,
                    false,
                );
                let mut media_types = Vec::new();
                media_types
                    .try_reserve(outcomes.len())
                    .map_err(|_| ContextError::ResourceExhausted)?;
                for outcome in outcomes {
                    if let crate::MediaAttachmentOutcome::Accepted { reference, .. } = outcome {
                        media_types.push(reference.media_type);
                    }
                }
                let bytes = input
                    .message_id_hex
                    .len()
                    .checked_add(input.sender.len())
                    .and_then(|n| n.checked_add(input.plaintext.len()))
                    .and_then(|n| {
                        media_types
                            .iter()
                            .try_fold(n, |n, m| n.checked_add(m.len()))
                    })
                    .ok_or(ContextError::ResourceExhausted)?;
                budget
                    .charge(
                        bytes,
                        std::mem::size_of::<SearchMessage>()
                            + 128
                            + media_types.len() * std::mem::size_of::<String>(),
                    )
                    .map_err(resource)?;
                target
                    .messages
                    .try_reserve(1)
                    .map_err(|_| ContextError::ResourceExhausted)?;
                target.messages.push(SearchMessage {
                    message_id_hex: super::super::presentation::owned_text(input.message_id_hex)
                        .map_err(resource)?,
                    sender: super::super::presentation::owned_text(input.sender)
                        .map_err(resource)?,
                    plaintext: super::super::presentation::owned_text(input.plaintext)
                        .map_err(resource)?,
                    kind: input.kind,
                    timeline_at: input.timeline_at,
                    deleted: input.deleted,
                    retention_seconds: input.retention_seconds,
                    retention_expires_at: input.retention_expires_at,
                    retention_expired: search_retention_expired(
                        now,
                        input.timeline_at,
                        input.retention_seconds,
                        input.retention_expires_at,
                    ),
                    media_types,
                });
                Ok(())
            },
        )
    }
    /// Same pure local saved-cache resolver as native prepared chat previews;
    /// invoke only after the account SQL snapshot has been released.
    pub fn prepare_search_system_names(
        &mut self,
        app: &crate::MarmotApp,
    ) -> Result<(), CaptureError> {
        let mut ids = HashSet::new();
        for operand in &self.operands {
            if self
                .overlays
                .preview_overrides
                .contains_key(&operand.group_id_hex)
            {
                continue;
            }
            if let Some(event) = operand
                .search
                .as_ref()
                .and_then(|s| s.last_message.as_ref())
                .and_then(|m| m.group_system.as_ref())
            {
                if event.provenance
                    != storage_sqlite::GroupSystemEventProvenance::AuthenticatedGroupState
                {
                    continue;
                }
                for id in [
                    event.actor_account_id_hex.as_deref(),
                    event.subject_account_id_hex.as_deref(),
                ]
                .into_iter()
                .flatten()
                .filter_map(crate::chat_presentation::canonical_identity)
                {
                    if !ids.contains(&id) {
                        // Conservative transient saved-name workspace (the
                        // existing identity selector bounds one name to256B),
                        // including identity/hash buckets and source records.
                        self.budget
                            .charge(0, 1024)
                            .map_err(|_| CaptureError::ResourceExhausted)?;
                        ids.try_reserve(1)
                            .map_err(|_| CaptureError::ResourceExhausted)?;
                        ids.insert(id);
                    }
                }
            }
        }
        let names = app
            .chat_system_display_names(ids)
            .map_err(|_| CaptureError::NotReady)?;
        for operand in &mut self.operands {
            if self
                .overlays
                .preview_overrides
                .contains_key(&operand.group_id_hex)
            {
                continue;
            }
            if let Some(event) = operand
                .search
                .as_mut()
                .and_then(|s| s.last_message.as_mut())
                .and_then(|m| m.group_system.as_mut())
            {
                if event.provenance
                    != storage_sqlite::GroupSystemEventProvenance::AuthenticatedGroupState
                {
                    continue;
                }
                let actor = event
                    .actor_account_id_hex
                    .as_deref()
                    .and_then(crate::chat_presentation::canonical_identity)
                    .and_then(|id| names.get(&id));
                let subject = event
                    .subject_account_id_hex
                    .as_deref()
                    .and_then(crate::chat_presentation::canonical_identity)
                    .and_then(|id| names.get(&id));
                // Charge every retained occurrence, including repeated actors
                // across many rows; unique-name accounting would undercount.
                let bytes = actor
                    .map_or(0, |text| text.len())
                    .checked_add(subject.map_or(0, |text| text.len()))
                    .ok_or(CaptureError::ResourceExhausted)?;
                self.budget
                    .charge(bytes, 0)
                    .map_err(|_| CaptureError::ResourceExhausted)?;
                event.actor_display_name = actor
                    .map(|text| super::super::presentation::owned_text(text))
                    .transpose()
                    .map_err(|_| CaptureError::ResourceExhausted)?;
                event.subject_display_name = subject
                    .map(|text| super::super::presentation::owned_text(text))
                    .transpose()
                    .map_err(|_| CaptureError::ResourceExhausted)?;
            }
        }
        Ok(())
    }
}

// Exact existing search-only local-expiry contract. Search has no read anchor,
// deferral or current group policy; overflow/unrepresentable deadlines retain.
fn search_retention_expired(
    now_ms: i64,
    timeline_at: u64,
    retention: Option<u64>,
    pinned: Option<u64>,
) -> bool {
    let deadline = pinned.filter(|value| *value > 0).or_else(|| {
        retention
            .filter(|value| *value > 0)
            .map(|seconds| timeline_at.saturating_add(seconds))
    });
    deadline.is_some_and(|seconds| {
        seconds <= (i64::MAX / 1000) as u64 && seconds <= (now_ms.max(0) / 1000) as u64
    })
}
#[cfg(test)]
mod tests {
    use super::search_retention_expired as expired;
    use super::*;
    #[test]
    fn media_preview_fallback_is_bound_to_exact_replaced_message_and_required_proof() {
        let mut preview = SearchPreviewMessage {
            message_id_hex: "private-current-message-sentinel".into(),
            resolved_media_preview_fallback: Some("stale-caller-fallback-sentinel".into()),
            plaintext: String::new(),
            kind: 9,
            deleted: false,
            attachment_kind: None,
            attachment_count: 0,
            group_system: None,
        };
        let mut fallbacks = HashMap::from([(
            "private-old-message-sentinel".into(),
            "old-file-sentinel".into(),
        )]);
        bind_media_preview_fallback(Some(&mut preview), &fallbacks).unwrap();
        assert_eq!(preview.resolved_media_preview_fallback, None);
        fallbacks.insert(
            preview.message_id_hex.clone(),
            "current-file-sentinel".into(),
        );
        bind_media_preview_fallback(Some(&mut preview), &fallbacks).unwrap();
        assert_eq!(
            preview.resolved_media_preview_fallback.as_deref(),
            Some("current-file-sentinel")
        );
        let old = preview.try_owned_copy().unwrap();
        preview.message_id_hex = "private-optimistic-message-sentinel".into();
        bind_media_preview_fallback(Some(&mut preview), &fallbacks).unwrap();
        assert_eq!(preview.resolved_media_preview_fallback, None);
        assert_ne!(preview, old);
        assert!(!format!("{preview:?} {old:?}").contains("sentinel"));
        assert!(
            old.text_bytes().unwrap() >= "current-file-sentinel".len() + old.message_id_hex.len()
        );
    }
    #[test]
    fn search_expiry_matches_positive_pinned_fallback_clock_and_overflow_boundaries() {
        assert!(!expired(1999, 0, None, Some(2)));
        assert!(expired(2000, 0, None, Some(2)));
        assert!(expired(2001, 0, None, Some(2)));
        assert!(!expired(-1, 0, Some(1), None));
        assert!(!expired(i64::MAX, 0, None, None));
        assert!(!expired(i64::MAX, 0, Some(0), Some(0)));
        assert!(expired(3000, 1, Some(2), Some(0)));
        assert!(!expired(2999, 1, Some(2), None));
        assert!(!expired(i64::MAX, u64::MAX, Some(1), None));
        assert!(!expired(
            i64::MAX,
            0,
            Some(1),
            Some((i64::MAX / 1000) as u64 + 1)
        ));
        assert!(expired(i64::MAX, 0, None, Some((i64::MAX / 1000) as u64)));
        assert!(!expired(1000, 0, Some(1), Some(2))); // Positive pinned deadline wins.
    }
}
