//! Lossless, consent-gated relay repair proposals over exact signed tags.
use super::*;

fn relay_tag_name(step: OnboardingStep) -> &'static str {
    if step == OnboardingStep::Relays {
        "r"
    } else {
        "relay"
    }
}

fn relay_tag(step: OnboardingStep, fields: Vec<String>) -> OnboardingRelayTag {
    let relevant = fields
        .first()
        .is_some_and(|name| name == relay_tag_name(step));
    let endpoint = relevant.then(|| fields.get(1).cloned()).flatten();
    let role = if !relevant
        || endpoint
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        OnboardingRelayTagRole::Other
    } else if step == OnboardingStep::InboxRelays {
        OnboardingRelayTagRole::Inbox
    } else {
        match fields.get(2).map(String::as_str) {
            None => OnboardingRelayTagRole::Unmarked,
            Some("read") => OnboardingRelayTagRole::Read,
            Some("write") => OnboardingRelayTagRole::Write,
            _ => OnboardingRelayTagRole::Other,
        }
    };
    OnboardingRelayTag {
        fields,
        endpoint,
        role,
    }
}

fn tag_change(
    tag: &OnboardingRelayTag,
    disposition: OnboardingRelayTagDisposition,
    before_index: Option<usize>,
    after_index: Option<usize>,
    restores: OnboardingRelayCapability,
) -> OnboardingRelayTagChange {
    OnboardingRelayTagChange {
        disposition,
        before_index: before_index.map(|value| value as u64),
        after_index: after_index.map(|value| value as u64),
        fields: tag.fields.clone(),
        endpoint: tag.endpoint.clone(),
        role: tag.role,
        restores,
    }
}

fn manual_review(
    event: Option<&NostrTransportEvent>,
    before_tags: Vec<OnboardingRelayTag>,
) -> OnboardingRelayRepair {
    let changes = before_tags
        .iter()
        .enumerate()
        .map(|(index, tag)| {
            tag_change(
                tag,
                OnboardingRelayTagDisposition::Retained,
                Some(index),
                Some(index),
                OnboardingRelayCapability::None,
            )
        })
        .collect();
    let content = event.map(|value| value.content.clone()).unwrap_or_default();
    OnboardingRelayRepair {
        mode: OnboardingRelayRepairMode::ManualReview,
        original_event_id: event.map(|value| value.id.clone()),
        original_content: content.clone(),
        proposed_content: content,
        after_tags: before_tags.clone(),
        before_tags,
        changes,
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

impl AccountManager {
    pub(super) fn minimal_relay_repair(
        &self,
        step: OnboardingStep,
        event: Option<&NostrTransportEvent>,
        defaults: &[String],
    ) -> (OnboardingRelayRepair, Vec<String>, Vec<String>) {
        let before = event
            .map(|value| {
                value
                    .tags
                    .iter()
                    .cloned()
                    .map(|fields| relay_tag(step, fields))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let manual = || (manual_review(event, before.clone()), Vec::new(), Vec::new());
        if event.is_some_and(|value| {
            value.kind != step.kind()
                || !validate_onboarding_record(value).is_empty()
                || value.created_at > unix_now_seconds() + FUTURE_CLOCK_SKEW
        }) {
            return manual();
        }

        let classifications = self.app.relay_plane.classify_relay_endpoints(
            before
                .iter()
                .filter_map(|tag| tag.endpoint.clone())
                .collect(),
        );
        let policies: HashMap<String, RelayEndpointPolicy> = classifications
            .into_iter()
            .map(|classified| (classified.endpoint, classified.policy))
            .collect();
        let mut after = Vec::with_capacity(before.len() + 1);
        let mut changes = Vec::with_capacity(before.len() + 1);
        let mut safe_endpoints = HashMap::new();
        let mut has_read = false;
        let mut has_write = false;
        let mut has_inbox = false;
        let mut removed = 0;
        for (index, tag) in before.iter().enumerate() {
            if tag
                .fields
                .first()
                .is_some_and(|name| name == relay_tag_name(step))
            {
                if tag.role == OnboardingRelayTagRole::Other {
                    return manual();
                }
                let Some(endpoint) = tag.endpoint.as_ref() else {
                    return manual();
                };
                match policies.get(endpoint) {
                    Some(RelayEndpointPolicy::Retired) => {
                        changes.push(tag_change(
                            tag,
                            OnboardingRelayTagDisposition::Removed,
                            Some(index),
                            None,
                            OnboardingRelayCapability::None,
                        ));
                        removed += 1;
                        continue;
                    }
                    // A route the direct dialer cannot use may still be useful
                    // to a Tor or LAN client. Do not erase its declaration.
                    Some(RelayEndpointPolicy::Unsafe) => {}
                    Some(RelayEndpointPolicy::Allowed) => {
                        safe_endpoints
                            .entry(relay_key(endpoint))
                            .or_insert_with(|| endpoint.clone());
                        match tag.role {
                            OnboardingRelayTagRole::Unmarked => {
                                has_read = true;
                                has_write = true;
                            }
                            OnboardingRelayTagRole::Read => has_read = true,
                            OnboardingRelayTagRole::Write => has_write = true,
                            OnboardingRelayTagRole::Inbox => has_inbox = true,
                            OnboardingRelayTagRole::Other => unreachable!(),
                        }
                    }
                    _ => return manual(),
                }
            }
            changes.push(tag_change(
                tag,
                OnboardingRelayTagDisposition::Retained,
                Some(index),
                Some(after.len()),
                OnboardingRelayCapability::None,
            ));
            after.push(tag.clone());
        }
        if safe_endpoints.len() > MAX_RELAYS {
            return manual();
        }

        let missing_read = step == OnboardingStep::Relays && !has_read;
        let missing_write = step == OnboardingStep::Relays && !has_write;
        let missing_inbox = step == OnboardingStep::InboxRelays && !has_inbox;
        let mut added = false;
        if missing_read || missing_write || missing_inbox {
            let allowed_defaults = self
                .app
                .relay_plane
                .classify_relay_endpoints(defaults.to_vec())
                .into_iter()
                .filter(|classified| classified.policy == RelayEndpointPolicy::Allowed)
                .map(|classified| classified.endpoint.trim().to_owned())
                .collect::<Vec<_>>();
            let candidate = allowed_defaults
                .iter()
                .find_map(|endpoint| safe_endpoints.get(&relay_key(endpoint)))
                .or_else(|| {
                    (safe_endpoints.len() < MAX_RELAYS)
                        .then(|| allowed_defaults.first())
                        .flatten()
                });
            let Some(endpoint) = candidate else {
                return manual();
            };
            let (fields, restores) = if missing_inbox {
                (
                    vec!["relay".into(), endpoint.clone()],
                    OnboardingRelayCapability::Inbox,
                )
            } else if missing_read && missing_write {
                (
                    vec!["r".into(), endpoint.clone()],
                    OnboardingRelayCapability::ReadAndWrite,
                )
            } else if missing_read {
                (
                    vec!["r".into(), endpoint.clone(), "read".into()],
                    OnboardingRelayCapability::Read,
                )
            } else {
                (
                    vec!["r".into(), endpoint.clone(), "write".into()],
                    OnboardingRelayCapability::Write,
                )
            };
            let tag = relay_tag(step, fields);
            changes.push(tag_change(
                &tag,
                OnboardingRelayTagDisposition::Added,
                None,
                Some(after.len()),
                restores,
            ));
            after.push(tag);
            added = true;
        }
        if removed == 0 && !added {
            return manual();
        }

        let mut read_relays = Vec::new();
        let mut write_relays = Vec::new();
        for tag in &after {
            let Some(endpoint) = tag.endpoint.as_deref() else {
                continue;
            };
            match tag.role {
                OnboardingRelayTagRole::Unmarked => {
                    push_unique(&mut read_relays, endpoint);
                    push_unique(&mut write_relays, endpoint);
                }
                OnboardingRelayTagRole::Read | OnboardingRelayTagRole::Inbox => {
                    push_unique(&mut read_relays, endpoint);
                }
                OnboardingRelayTagRole::Write => push_unique(&mut write_relays, endpoint),
                OnboardingRelayTagRole::Other => {}
            }
        }
        let content = event.map(|value| value.content.clone()).unwrap_or_default();
        (
            OnboardingRelayRepair {
                mode: match (removed > 0, added) {
                    (true, true) => OnboardingRelayRepairMode::RemovalAndAdditive,
                    (true, false) => OnboardingRelayRepairMode::RemovalOnly,
                    (false, true) => OnboardingRelayRepairMode::Additive,
                    (false, false) => unreachable!(),
                },
                original_event_id: event.map(|value| value.id.clone()),
                original_content: content.clone(),
                proposed_content: content,
                before_tags: before,
                after_tags: after,
                changes,
            },
            read_relays,
            write_relays,
        )
    }

    /// Prepare an exact, minimal relay repair without signing or publishing.
    /// When no lossless candidate exists, return a typed manual-review preview
    /// with no approval action; callers may open a prefilled manual editor.
    pub async fn propose_onboarding_relay_repair(
        &self,
        account_ref: &str,
        step: OnboardingStep,
    ) -> Result<OnboardingSnapshot, AppError> {
        let (account_id, attempt) = self.peek_onboarding_attempt(account_ref)?;
        let transaction = self.onboarding_transaction(&account_id);
        let _transaction = transaction.lock().await;
        let mut c = self
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        self.require_captured_attempt(&c, attempt)?;
        if !step.relay()
            || c.approved
            || c.snapshot.steps[step.index()].status != OnboardingStatus::NeedsInput
        {
            return Err(onboarding_error());
        }
        let (repair, read_relays, write_relays) = self.minimal_relay_repair(
            step,
            c.records[step.index()].as_ref(),
            &c.options.default_relays,
        );
        let manual = repair.mode == OnboardingRelayRepairMode::ManualReview;
        c.snapshot.proposal = Some(OnboardingRepairProposal {
            step,
            revision: c
                .snapshot
                .revision
                .checked_add(1)
                .ok_or_else(onboarding_error)?,
            previous_event_id: repair.original_event_id.clone(),
            read_relays,
            write_relays,
            profile: None,
            follows: None,
            relay_repair: Some(repair),
        });
        c.snapshot.steps[step.index()].actions = if manual {
            vec![OnboardingAction::EditRelays, OnboardingAction::CancelRepair]
        } else {
            vec![
                OnboardingAction::ApproveRepair,
                OnboardingAction::CancelRepair,
            ]
        };
        self.save_onboarding(&mut c)?;
        Ok(c.snapshot)
    }
}
