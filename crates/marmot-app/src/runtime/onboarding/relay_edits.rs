//! Manual endpoint edits retain untouched signed tags rather than reconstructing the declaration.
use super::relay_repair::{manual_review, relay_tag, tag_change};
use super::*;

/// Interpret explicit lists as endpoint-role selections, retaining every untouched
/// occurrence verbatim. Opaque tags are outside the list editor's scope.
pub(super) fn manual_relay_edit(
    step: OnboardingStep,
    event: Option<&NostrTransportEvent>,
    reads: &[String],
    writes: &[String],
) -> OnboardingRelayRepair {
    let before: Vec<_> = event
        .map(|event| {
            event
                .tags
                .iter()
                .cloned()
                .map(|tag| relay_tag(step, tag))
                .collect()
        })
        .unwrap_or_default();
    let read_keys: HashSet<_> = reads.iter().map(|endpoint| relay_key(endpoint)).collect();
    let write_keys: HashSet<_> = writes.iter().map(|endpoint| relay_key(endpoint)).collect();
    let mut after = Vec::new();
    let mut changes = Vec::new();
    for (index, tag) in before.iter().enumerate() {
        let read = tag
            .endpoint
            .as_ref()
            .is_some_and(|value| read_keys.contains(&relay_key(value)));
        let write = tag
            .endpoint
            .as_ref()
            .is_some_and(|value| write_keys.contains(&relay_key(value)));
        let retained = match tag.role {
            OnboardingRelayTagRole::Other => true,
            OnboardingRelayTagRole::Read | OnboardingRelayTagRole::Inbox => read,
            OnboardingRelayTagRole::Write => write,
            OnboardingRelayTagRole::Unmarked => read && write,
        };
        if retained {
            changes.push(tag_change(
                tag,
                OnboardingRelayTagDisposition::Retained,
                Some(index),
                Some(after.len()),
                OnboardingRelayCapability::None,
            ));
            after.push(tag.clone());
        } else {
            changes.push(tag_change(
                tag,
                OnboardingRelayTagDisposition::Removed,
                Some(index),
                None,
                OnboardingRelayCapability::None,
            ));
            // A deliberately narrowed unmarked declaration keeps its original position.
            if tag.role == OnboardingRelayTagRole::Unmarked && (read || write) {
                let mut fields = tag.fields.clone();
                fields.push(if read { "read" } else { "write" }.into());
                append_edit_tag(step, fields, &mut after, &mut changes);
            }
        }
    }
    let mut selected = HashSet::new();
    for endpoint in reads.iter().chain(writes) {
        let key = relay_key(endpoint);
        if !selected.insert(key.clone()) {
            continue;
        }
        let has_read = after.iter().any(|tag| {
            tag.endpoint
                .as_ref()
                .is_some_and(|value| relay_key(value) == key)
                && matches!(
                    tag.role,
                    OnboardingRelayTagRole::Read
                        | OnboardingRelayTagRole::Unmarked
                        | OnboardingRelayTagRole::Inbox
                )
        });
        let has_write = after.iter().any(|tag| {
            tag.endpoint
                .as_ref()
                .is_some_and(|value| relay_key(value) == key)
                && matches!(
                    tag.role,
                    OnboardingRelayTagRole::Write | OnboardingRelayTagRole::Unmarked
                )
        });
        let add_read = read_keys.contains(&key) && !has_read;
        let add_write = write_keys.contains(&key) && !has_write;
        if !add_read && !add_write {
            continue;
        }
        let mut fields = vec![
            if step == OnboardingStep::InboxRelays {
                "relay"
            } else {
                "r"
            }
            .into(),
            endpoint.clone(),
        ];
        if step == OnboardingStep::Relays && add_read != add_write {
            fields.push(if add_read { "read" } else { "write" }.into());
        }
        append_edit_tag(step, fields, &mut after, &mut changes);
    }
    let removed = changes
        .iter()
        .any(|change| change.disposition == OnboardingRelayTagDisposition::Removed);
    let added = changes
        .iter()
        .any(|change| change.disposition == OnboardingRelayTagDisposition::Added);
    let mode = match (removed, added) {
        (true, true) => OnboardingRelayRepairMode::RemovalAndAdditive,
        (true, false) => OnboardingRelayRepairMode::RemovalOnly,
        (false, true) => OnboardingRelayRepairMode::Additive,
        (false, false) => return manual_review(event, before),
    };
    let content = event.map(|event| event.content.clone()).unwrap_or_default();
    OnboardingRelayRepair {
        mode,
        original_event_id: event.map(|event| event.id.clone()),
        original_content: content.clone(),
        proposed_content: content,
        before_tags: before,
        after_tags: after,
        changes,
    }
}

fn append_edit_tag(
    step: OnboardingStep,
    fields: Vec<String>,
    after: &mut Vec<OnboardingRelayTag>,
    changes: &mut Vec<OnboardingRelayTagChange>,
) {
    let tag = relay_tag(step, fields);
    let capability = match tag.role {
        OnboardingRelayTagRole::Read => OnboardingRelayCapability::Read,
        OnboardingRelayTagRole::Write => OnboardingRelayCapability::Write,
        OnboardingRelayTagRole::Unmarked => OnboardingRelayCapability::ReadAndWrite,
        OnboardingRelayTagRole::Inbox => OnboardingRelayCapability::Inbox,
        OnboardingRelayTagRole::Other => OnboardingRelayCapability::None,
    };
    changes.push(tag_change(
        &tag,
        OnboardingRelayTagDisposition::Added,
        None,
        Some(after.len()),
        capability,
    ));
    after.push(tag);
}
