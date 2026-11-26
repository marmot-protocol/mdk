//! Lossless, consent-gated relay repair proposals over exact signed tags.
use super::*;

fn relay_tag_name(step: OnboardingStep) -> &'static str {
    if step == OnboardingStep::Relays {
        "r"
    } else {
        "relay"
    }
}

pub(super) fn relay_tag(step: OnboardingStep, fields: Vec<String>) -> OnboardingRelayTag {
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
            Some(marker) if marker.eq_ignore_ascii_case("read") => OnboardingRelayTagRole::Read,
            Some(marker) if marker.eq_ignore_ascii_case("write") => OnboardingRelayTagRole::Write,
            _ => OnboardingRelayTagRole::Other,
        }
    };
    OnboardingRelayTag {
        fields,
        endpoint,
        role,
    }
}

pub(super) fn tag_change(
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
        removal_reason: OnboardingRelayRemovalReason::None,
    }
}

fn removal(
    tag: &OnboardingRelayTag,
    before_index: usize,
    reason: OnboardingRelayRemovalReason,
) -> OnboardingRelayTagChange {
    OnboardingRelayTagChange {
        removal_reason: reason,
        ..tag_change(
            tag,
            OnboardingRelayTagDisposition::Removed,
            Some(before_index),
            None,
            OnboardingRelayCapability::None,
        )
    }
}

/// The declared routes a step's last check showed cannot serve their role,
/// by normalized endpoint. Only a deliberate policy answer counts: the relay
/// refused the declared-route check with `auth-required` or
/// `payment-required` while the client held the account's local key. A
/// timeout, an unreachable relay or another refusal can be an outage that
/// passes, so it never nominates a route for removal (mdk#3449).
pub(super) fn unusable_routes(
    findings: &[OnboardingFinding],
) -> BTreeMap<String, OnboardingRelayRemovalReason> {
    findings
        .iter()
        .filter(|finding| {
            finding.context == OnboardingFindingContext::DeclaredRoute && finding.local_key_held
        })
        .filter_map(|finding| {
            let reason = match finding.issue {
                OnboardingIssue::AuthenticationRequired => {
                    OnboardingRelayRemovalReason::AuthenticationRequired
                }
                OnboardingIssue::PaymentRequired => OnboardingRelayRemovalReason::PaymentRequired,
                _ => return None,
            };
            Some((relay_key(finding.endpoint.as_deref()?), reason))
        })
        .collect()
}

/// The routes a relay entry declares: (read, write, inbox).
fn declared_roles(role: OnboardingRelayTagRole) -> (bool, bool, bool) {
    match role {
        OnboardingRelayTagRole::Unmarked => (true, true, false),
        OnboardingRelayTagRole::Read => (true, false, false),
        OnboardingRelayTagRole::Write => (false, true, false),
        OnboardingRelayTagRole::Inbox => (false, false, true),
        OnboardingRelayTagRole::Other => (false, false, false),
    }
}

pub(super) fn manual_review(
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

impl AccountSetup<'_> {
    /// `unusable` names declared routes to remove besides retired ones (see
    /// [`unusable_routes`]). With `removal_only`, the preview never adds a
    /// route: an unusable entry that is the list's last policy-allowed route
    /// for one of its roles stays, so a cleanup never empties a role.
    pub(super) fn minimal_relay_repair(
        &self,
        step: OnboardingStep,
        event: Option<&NostrTransportEvent>,
        defaults: &[String],
        unusable: &BTreeMap<String, OnboardingRelayRemovalReason>,
        removal_only: bool,
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

        let classifications = self.app().relay_plane.classify_relay_endpoints(
            before
                .iter()
                .filter_map(|tag| tag.endpoint.clone())
                .collect(),
        );
        let policies: HashMap<String, RelayEndpointPolicy> = classifications
            .into_iter()
            .map(|classified| (classified.endpoint, classified.policy))
            .collect();
        let relevant = |tag: &OnboardingRelayTag| {
            tag.fields
                .first()
                .is_some_and(|name| name == relay_tag_name(step))
        };
        let unusable_reason = |endpoint: &str| {
            (policies.get(endpoint) == Some(&RelayEndpointPolicy::Allowed))
                .then(|| unusable.get(&relay_key(endpoint)).copied())
                .flatten()
        };
        // A removal-only preview keeps, in tag order, the first unusable
        // endpoint (with all its tags) that declares a role no allowed entry
        // left in the list declares, and removes the rest.
        let mut kept = HashSet::new();
        if removal_only {
            let mut covered = (false, false, false);
            let mut unusable_roles: HashMap<String, (bool, bool, bool)> = HashMap::new();
            for tag in before.iter().filter(|tag| relevant(tag)) {
                let Some(endpoint) = tag.endpoint.as_deref() else {
                    continue;
                };
                let (read, write, inbox) = declared_roles(tag.role);
                if unusable_reason(endpoint).is_some() {
                    let roles = unusable_roles.entry(relay_key(endpoint)).or_default();
                    *roles = (roles.0 || read, roles.1 || write, roles.2 || inbox);
                } else if policies.get(endpoint) == Some(&RelayEndpointPolicy::Allowed) {
                    covered = (covered.0 || read, covered.1 || write, covered.2 || inbox);
                }
            }
            for tag in before.iter().filter(|tag| relevant(tag)) {
                let Some(endpoint) = tag.endpoint.as_deref() else {
                    continue;
                };
                let key = relay_key(endpoint);
                let Some(&(read, write, inbox)) = unusable_roles.get(&key) else {
                    continue;
                };
                if (read && !covered.0) || (write && !covered.1) || (inbox && !covered.2) {
                    covered = (covered.0 || read, covered.1 || write, covered.2 || inbox);
                    kept.insert(key);
                }
            }
        }
        let mut after = Vec::with_capacity(before.len() + 1);
        let mut changes = Vec::with_capacity(before.len() + 1);
        let mut safe_endpoints = HashMap::new();
        let mut has_read = false;
        let mut has_write = false;
        let mut has_inbox = false;
        let mut removed = 0;
        for (index, tag) in before.iter().enumerate() {
            if relevant(tag)
                && let Some(endpoint) = tag
                    .endpoint
                    .as_ref()
                    .filter(|_| tag.role != OnboardingRelayTagRole::Other)
            {
                if let Some(reason) = unusable_reason(endpoint)
                    && !kept.contains(&relay_key(endpoint))
                {
                    changes.push(removal(tag, index, reason));
                    removed += 1;
                    continue;
                }
                match policies.get(endpoint) {
                    Some(RelayEndpointPolicy::Retired) => {
                        changes.push(removal(tag, index, OnboardingRelayRemovalReason::Retired));
                        removed += 1;
                        continue;
                    }
                    // A route the direct dialer cannot use (unsafe, invalid,
                    // or unknown-marker) stays verbatim so lossless repair
                    // never forces a destructive reset (mdk#3727).
                    Some(RelayEndpointPolicy::Unsafe)
                    | Some(RelayEndpointPolicy::Invalid)
                    | None => {}
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
        if step == OnboardingStep::InboxRelays && safe_endpoints.len() > MAX_RELAYS {
            return manual();
        }

        let mut added = false;
        // Some clients write NIP-65 `r` tags into kind-10050 inbox lists.
        // When no allowed `relay` tag exists yet, copy the allowed `r`-tag URLs
        // into `relay` tags (still bounded by MAX_RELAYS for inbox activation).
        if step == OnboardingStep::InboxRelays && !has_inbox {
            let r_urls: Vec<String> = before
                .iter()
                .filter(|tag| tag.fields.first().is_some_and(|name| name == "r"))
                .filter_map(|tag| tag.fields.get(1).cloned())
                .filter(|url| !url.trim().is_empty())
                .collect();
            if !r_urls.is_empty() {
                let mut seen = HashSet::new();
                let mut copied = Vec::new();
                for classified in self.app().relay_plane.classify_relay_endpoints(r_urls) {
                    if is_onion_relay(&classified.endpoint)
                        || classified.policy != RelayEndpointPolicy::Allowed
                    {
                        continue;
                    }
                    let endpoint = classified.endpoint.trim().to_owned();
                    let key = relay_key(&endpoint);
                    if !unusable.contains_key(&key) && seen.insert(key) {
                        copied.push(endpoint);
                    }
                }
                if copied.len() > MAX_RELAYS {
                    return manual();
                }
                for endpoint in copied {
                    let tag = relay_tag(step, vec!["relay".into(), endpoint]);
                    changes.push(tag_change(
                        &tag,
                        OnboardingRelayTagDisposition::Added,
                        None,
                        Some(after.len()),
                        OnboardingRelayCapability::Inbox,
                    ));
                    after.push(tag);
                    has_inbox = true;
                    added = true;
                }
            }
        }

        let missing_read = step == OnboardingStep::Relays && !has_read;
        let missing_write = step == OnboardingStep::Relays && !has_write;
        let missing_inbox = step == OnboardingStep::InboxRelays && !has_inbox;
        if missing_read || missing_write || missing_inbox {
            let allowed_defaults = self
                .app()
                .relay_plane
                .classify_relay_endpoints(defaults.to_vec())
                .into_iter()
                .filter(|classified| classified.policy == RelayEndpointPolicy::Allowed)
                .map(|classified| classified.endpoint.trim().to_owned())
                // Never put back a route this preview treats as unusable.
                .filter(|endpoint| !unusable.contains_key(&relay_key(endpoint)))
                .collect::<Vec<_>>();
            let can_add_new = step == OnboardingStep::Relays || safe_endpoints.len() < MAX_RELAYS;
            let candidate = allowed_defaults
                .iter()
                .find_map(|endpoint| safe_endpoints.get(&relay_key(endpoint)))
                .or_else(|| can_add_new.then(|| allowed_defaults.first()).flatten());
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
            if policies.get(endpoint) == Some(&RelayEndpointPolicy::Invalid) {
                continue;
            }
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

    /// The preview `propose_onboarding_relay_repair` would show for `step`,
    /// and the unusable routes it was built from, or `Err` when the step
    /// accepts none. Local work only: no fetch, signature or publication.
    pub(super) fn relay_repair_preview(
        &self,
        c: &OnboardingCheckpoint,
        step: OnboardingStep,
    ) -> Result<RelayRepairPreview, AppError> {
        let state = &c.snapshot.steps[step.index()];
        let unusable = unusable_routes(&state.findings);
        // A step that passed offers only advice: removal of retired or
        // unusable declarations, never an added route.
        let passed = state.status == OnboardingStatus::Passed
            && (!unusable.is_empty()
                || state
                    .findings
                    .iter()
                    .any(|finding| finding.issue == OnboardingIssue::RetiredRelay));
        if !step.relay()
            || c.approved
            || c.snapshot
                .proposal
                .as_ref()
                .is_some_and(|proposal| proposal.step != step)
            || (!c.relay_step_editable(step) && !passed)
        {
            return Err(onboarding_error());
        }
        let (mut repair, mut read_relays, mut write_relays) = self.minimal_relay_repair(
            step,
            c.records[step.index()].as_ref(),
            c.options.defaults_for(step),
            &unusable,
            passed,
        );
        if passed && repair.mode != OnboardingRelayRepairMode::RemovalOnly {
            return Err(onboarding_error());
        }
        // Removing a retired or unusable declaration cannot make a timed-out
        // usable route complete inspection. Do not present that removal as an
        // approvable fix.
        if repair.mode == OnboardingRelayRepairMode::RemovalOnly
            && state
                .findings
                .iter()
                .any(|finding| finding.issue == OnboardingIssue::NoUsableRoute)
        {
            repair = manual_review(c.records[step.index()].as_ref(), repair.before_tags);
            read_relays.clear();
            write_relays.clear();
        }
        Ok(RelayRepairPreview {
            repair,
            read_relays,
            write_relays,
            unusable,
        })
    }

    /// Whether `step` should offer `RemoveUnusableRelays`: its preview is
    /// approvable and removes at least one declared entry.
    pub(super) fn relay_cleanup_available(
        &self,
        c: &OnboardingCheckpoint,
        step: OnboardingStep,
    ) -> bool {
        step.relay()
            && c.snapshot.proposal.is_none()
            && !c.snapshot.cancellation_pending
            && self.relay_repair_preview(c, step).is_ok_and(|preview| {
                preview.repair.mode != OnboardingRelayRepairMode::ManualReview
                    && preview
                        .repair
                        .changes
                        .iter()
                        .any(|change| change.disposition == OnboardingRelayTagDisposition::Removed)
            })
    }

    /// Prepare an exact, minimal relay repair without signing or publishing.
    /// When no lossless candidate exists, return a typed manual-review preview
    /// with no approval action; callers may open a prefilled manual editor.
    pub async fn propose_onboarding_relay_repair(
        &self,
        account_ref: &str,
        step: OnboardingStep,
    ) -> Result<OnboardingSnapshot, AppError> {
        let (account_id, attempt) = self.records().peek_onboarding_attempt(account_ref)?;
        let transaction = self.app().onboarding_transaction(&account_id);
        let _transaction = transaction.lock().await;
        let mut c = self
            .records()
            .onboarding_checkpoint(account_ref)?
            .ok_or_else(onboarding_error)?;
        self.require_captured_attempt(&c, attempt)?;
        let RelayRepairPreview {
            repair,
            read_relays,
            write_relays,
            unusable,
        } = self.relay_repair_preview(&c, step)?;
        let manual = repair.mode == OnboardingRelayRepairMode::ManualReview;
        let inconclusive = check_inconclusive(&c.snapshot.steps[step.index()].findings)
            || (step == OnboardingStep::Relays && self.nip65_exceeds_dial_cap(&c));
        // A typed preview replaces any earlier append-only editor proposal.
        c.append_relays = false;
        c.manual_relay_edit = false;
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
            inconclusive,
            unusable_routes: if manual { BTreeMap::new() } else { unusable },
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

pub(super) struct RelayRepairPreview {
    pub(super) repair: OnboardingRelayRepair,
    pub(super) read_relays: Vec<String>,
    pub(super) write_relays: Vec<String>,
    pub(super) unusable: BTreeMap<String, OnboardingRelayRemovalReason>,
}
