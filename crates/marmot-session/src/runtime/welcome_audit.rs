//! The sender's v5 Welcome audit rows (`welcome_prepared`,
//! `welcome_event_size`, `welcome_publish_started`/`_finished`,
//! `welcome_publish_not_started`, `welcome_withdrawn`) for every retained
//! outbound Welcome a transport wrapped as a Nostr event. Each row is built
//! from the Welcome's own stored row, so a Welcome is described the same way
//! whichever path prepares, sends, retries or retires it, and every row of one
//! Welcome carries the operation id derived from its outer event
//! ([`welcome_audit_operation_id`]).

use super::*;
use crate::session::WelcomeSettlement;

/// The most Welcome ids remembered as already prepared in this process. A
/// prepared row is written once per Welcome; past this many the memory is
/// cleared, and a Welcome prepared again after that may be recorded twice.
const MAX_PREPARED_WELCOMES_REMEMBERED: usize = 4096;

/// The v5 operation id of one outbound Welcome, named by its id: its
/// `welcome_prepared` row and every other row of it share this id, whichever
/// path prepares or sends it.
pub fn welcome_audit_operation_id(welcome_id: &cgka_traits::MessageId) -> audit_v5::LocalId {
    v5_local_id(b"welcome-operation", welcome_id.as_slice(), 0)
}

/// A retained outbound Welcome as its v5 rows name it.
pub(super) struct V5Welcome {
    pub(super) op_id: audit_v5::LocalId,
    pub(super) outer: audit_v5::NostrEventRef,
    pub(super) recipient_ref: audit_v5::MemberRef,
    pub(super) group_ref: audit_v5::GroupRef,
    pub(super) facts: cgka_engine::engine::OutboundWelcomeAuditFacts,
}

/// One publish pass over a Welcome's relays: its started row, recorded with a
/// fresh attempt id only when the transport is called, and what its finished
/// row needs. A pass a hold stops before the transport is called records
/// neither row.
pub(super) struct V5WelcomePass {
    welcome_id: cgka_traits::MessageId,
    group_ref: audit_v5::GroupRef,
    started: audit_v5::WelcomePublishStarted,
    recorded: bool,
}

impl V5WelcomePass {
    /// Record the started row, at the moment the transport is called.
    pub(super) fn start(&mut self, audit: &SharedRecorder) {
        let Ok(attempt_id) = hex::encode(rand::random::<[u8; 16]>()).try_into() else {
            return;
        };
        self.started.attempt_id = attempt_id;
        audit.record_v5_event(
            Some(self.group_ref.clone()),
            audit_v5::Event::WelcomePublishStarted(self.started.clone()),
        );
        self.recorded = true;
    }
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// What the audit reads of the retained Welcome `message`, when audit is
    /// on; `None` for anything else, or a row that cannot be read now. One
    /// read serves every row of a publish pass.
    pub(super) fn welcome_audit_facts(
        &self,
        message: &TransportMessage,
    ) -> Option<cgka_engine::engine::OutboundWelcomeAuditFacts> {
        if !self.audit.is_enabled()
            || !matches!(message.envelope, TransportEnvelope::Welcome { .. })
        {
            return None;
        }
        self.session
            .outbound_welcome_audit_facts(&message.id)
            .ok()
            .flatten()
    }

    /// The Welcome `facts` describe as its v5 rows name it; `None` without a
    /// v5 recorder or for a Welcome another transport wrapped.
    fn v5_welcome_of(
        &self,
        facts: cgka_engine::engine::OutboundWelcomeAuditFacts,
    ) -> Option<V5Welcome> {
        if !self.audit.records_v5() {
            return None;
        }
        let outer = v5_outbound_welcome_ref(&facts.message)?;
        let TransportEnvelope::Welcome { recipient } = &facts.message.envelope else {
            return None;
        };
        let recipient_ref = audit_v5::MemberRef::from_member_identity(recipient.as_slice()).ok()?;
        let group_ref = audit_v5::GroupRef::from_group_id(facts.group_id.as_slice()).ok()?;
        Some(V5Welcome {
            op_id: welcome_audit_operation_id(&facts.message.id),
            outer,
            recipient_ref,
            group_ref,
            facts,
        })
    }

    /// Record `welcome_prepared` and `welcome_event_size` for each Welcome
    /// just retained, exactly as the engine stored it: the commit it waits
    /// on (none for a founding Welcome) and the KeyPackage it answers.
    /// Called where each first reaches the runtime: a create, a host's
    /// accepted commit, and a drained or automatic commit when published.
    /// Each is watched from here, so it is seen to settle. A Welcome is
    /// remembered once its row is read, so a failed read is tried again.
    pub(super) fn note_retained_welcomes(&mut self, welcomes: &[TransportMessage]) {
        self.watch_welcomes(welcomes.iter().map(|welcome| welcome.id.clone()));
        for welcome in welcomes {
            if self.v5_prepared_welcomes.contains(&welcome.id) {
                continue;
            }
            let facts = if self.audit.is_enabled() {
                match self.session.outbound_welcome_audit_facts(&welcome.id) {
                    Ok(facts) => facts,
                    Err(_) => continue,
                }
            } else {
                None
            };
            if self.v5_prepared_welcomes.len() >= MAX_PREPARED_WELCOMES_REMEMBERED {
                self.v5_prepared_welcomes.clear();
            }
            self.v5_prepared_welcomes.insert(welcome.id.clone());
            if let Some(v5) = facts.and_then(|facts| self.v5_welcome_of(facts)) {
                self.record_v5_welcome_prepared(&v5);
                self.record_v5_welcome_size(&v5, welcome);
            }
        }
    }

    /// Note each Welcome a create retained ([`Self::note_retained_welcomes`]).
    pub(super) fn note_founding_welcomes(&mut self, effects: &SessionEffects) {
        for work in &effects.publish {
            if let PublishWork::FoundingGroupCreated { welcomes }
            | PublishWork::GroupCreated { welcomes, .. } = work
            {
                self.note_retained_welcomes(welcomes);
            }
        }
    }

    fn record_v5_welcome_prepared(&self, v5: &V5Welcome) {
        // A constructed row names the KeyPackage it answers.
        let Some(key_package_ref) = v5
            .facts
            .key_package_event_id
            .as_ref()
            .and_then(|id| <[u8; 32]>::try_from(id.as_slice()).ok())
            .map(|id| audit_v5::NostrEventRef::from_validated_event_id(&id))
        else {
            return;
        };
        let (mode, basis) = match &v5.facts.origin_commit_id {
            None => (audit_v5::Mode::Founding, audit_v5::Basis::Founding {}),
            Some(origin) => {
                let Ok(commit_ref) = audit_v5::EngineMessageRef::from_message_id(origin.as_slice())
                else {
                    return;
                };
                (
                    audit_v5::Mode::Invite,
                    audit_v5::Basis::Commit { commit_ref },
                )
            }
        };
        self.audit.record_v5_event(
            Some(v5.group_ref.clone()),
            audit_v5::Event::WelcomePrepared(audit_v5::WelcomePrepared {
                op_id: v5.op_id.clone(),
                recipient_ref: v5.recipient_ref.clone(),
                mode,
                basis,
                key_package_event_ref: Some(key_package_ref),
                outer_event_ref: Some(v5.outer.clone()),
                construction: audit_v5::Construction::Constructed,
                // Retained: canonical for a founding Welcome, staged with its
                // commit for an invite's.
                retention: audit_v5::Retention::Committed,
                failure_stage: None,
                reason: None,
                elapsed_us: None,
            }),
        );
    }

    fn record_v5_welcome_size(&self, v5: &V5Welcome, welcome: &TransportMessage) {
        let Some(size_class) = self.adapter.event_size_class(welcome) else {
            return;
        };
        self.audit.record_v5_event(
            Some(v5.group_ref.clone()),
            audit_v5::Event::WelcomeEventSize(audit_v5::WelcomeEventSize {
                op_id: v5.op_id.clone(),
                outer_event_ref: v5.outer.clone(),
                event_size_class: v5_size_class(size_class),
            }),
        );
    }

    /// Record `welcome_withdrawn` for each Welcome of a commit refused as too
    /// large, once its rollback has retired the Welcome, and stop watching
    /// it: the reason is known here, not to the watcher.
    pub(super) fn record_v5_welcomes_refused(
        &mut self,
        welcome_ids: &[cgka_traits::MessageId],
        oversized: OversizedEvent,
    ) {
        let reason = match oversized.artifact {
            OversizedArtifact::Welcome => audit_v5::WithdrawalReason::WelcomeTooLarge,
            OversizedArtifact::Commit => audit_v5::WithdrawalReason::CommitTooLarge,
            // An invite is refused for its commit or a Welcome only.
            OversizedArtifact::ApplicationMessage | OversizedArtifact::Other => return,
        };
        for welcome_id in welcome_ids {
            let Ok(Some(facts)) = self.session.outbound_welcome_audit_facts(welcome_id) else {
                continue;
            };
            if facts.state != MessageState::Failed {
                continue;
            }
            self.watched_welcomes
                .retain(|watched| watched != welcome_id);
            if let Some(v5) = self.v5_welcome_of(facts) {
                self.record_v5_welcome_withdrawn(
                    &v5,
                    reason,
                    Some(v5_size_class(oversized.size_class)),
                );
            }
        }
    }

    /// Record `welcome_withdrawn` for a watched Welcome that settled without
    /// being delivered.
    pub(super) fn record_v5_welcome_settled(
        &self,
        welcome_id: &cgka_traits::MessageId,
        settlement: WelcomeSettlement,
    ) {
        let reason = match settlement {
            WelcomeSettlement::Withdrawn => audit_v5::WithdrawalReason::Withdrawn,
            WelcomeSettlement::CommitSuperseded => audit_v5::WithdrawalReason::CommitSuperseded,
            WelcomeSettlement::Expired => audit_v5::WithdrawalReason::Expired,
            WelcomeSettlement::Delivered | WelcomeSettlement::Untracked => return,
        };
        if !self.audit.records_v5() {
            return;
        }
        if let Ok(Some(facts)) = self.session.outbound_welcome_audit_facts(welcome_id)
            && let Some(v5) = self.v5_welcome_of(facts)
        {
            self.record_v5_welcome_withdrawn(&v5, reason, None);
        }
    }

    fn record_v5_welcome_withdrawn(
        &self,
        v5: &V5Welcome,
        reason: audit_v5::WithdrawalReason,
        oversized_size_class: Option<audit_v5::EventSizeClass>,
    ) {
        self.audit.record_v5_event(
            Some(v5.group_ref.clone()),
            audit_v5::Event::WelcomeWithdrawn(audit_v5::WelcomeWithdrawn {
                op_id: v5.op_id.clone(),
                outer_event_ref: v5.outer.clone(),
                recipient_ref: v5.recipient_ref.clone(),
                reason,
                oversized_size_class,
            }),
        );
    }

    /// Record `welcome_publish_not_started` for a Welcome whose publish found
    /// no route.
    pub(super) fn record_v5_welcome_not_started(
        &self,
        facts: Option<cgka_engine::engine::OutboundWelcomeAuditFacts>,
        reason: audit_v5::NotStartedReason,
    ) {
        if let Some(v5) = facts.and_then(|facts| self.v5_welcome_of(facts)) {
            self.audit.record_v5_event(
                Some(v5.group_ref.clone()),
                audit_v5::Event::WelcomePublishNotStarted(audit_v5::WelcomePublishNotStarted {
                    op_id: v5.op_id,
                    outer_event_ref: v5.outer,
                    recipient_ref: v5.recipient_ref,
                    reason,
                    elapsed_us: None,
                }),
            );
        }
    }

    /// The v5 rows of one publish pass over `endpoints` of the Welcome
    /// `facts` describe, ready for [`V5WelcomePass::start`].
    pub(super) fn v5_welcome_pass(
        &self,
        facts: Option<cgka_engine::engine::OutboundWelcomeAuditFacts>,
        endpoints: &[TransportEndpoint],
        required_acks: usize,
        accepted_before: usize,
        route_source: audit_v5::RouteSource,
    ) -> Option<V5WelcomePass> {
        let v5 = self.v5_welcome_of(facts?)?;
        let target_count = u32::try_from(endpoints.len()).ok()?;
        let required_acks = u32::try_from(required_acks).ok()?;
        let accepted_before_count = u32::try_from(accepted_before).ok()?;
        let mut targets = endpoints
            .iter()
            .filter_map(v5_endpoint_ref)
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        let targets_complete =
            targets.len() == endpoints.len() && targets.len() <= audit_v5::MAX_ENDPOINTS;
        targets.truncate(audit_v5::MAX_ENDPOINTS);
        Some(V5WelcomePass {
            welcome_id: v5.facts.message.id.clone(),
            group_ref: v5.group_ref,
            started: audit_v5::WelcomePublishStarted {
                op_id: v5.op_id,
                // Replaced by a fresh id when the pass starts.
                attempt_id: "00".repeat(16).try_into().ok()?,
                outer_event_ref: v5.outer,
                recipient_ref: v5.recipient_ref,
                route_source,
                targets,
                target_count: Some(target_count),
                targets_complete,
                required_acks,
                accepted_before_count,
            },
            recorded: false,
        })
    }

    /// Record the finished row of a pass that started. The cumulative
    /// acceptance count comes from the Welcome's stored fanout, so it holds
    /// even when this pass's own endpoint results are incomplete; retention
    /// comes from the Welcome's stored row.
    pub(super) fn record_v5_welcome_publish_finished(
        &self,
        pass: &Option<V5WelcomePass>,
        report: Option<&TransportPublishReport>,
        attempted: &[TransportEndpoint],
        accepted_total: usize,
        required_acks: usize,
    ) {
        let Some(pass) = pass.as_ref().filter(|pass| pass.recorded) else {
            return;
        };
        let Ok(required_acks) = u32::try_from(required_acks) else {
            return;
        };
        let mut results = Vec::new();
        let mut source_count = 0usize;
        if let Some(report) = report {
            source_count = report.accepted.len() + report.failed.len();
            for receipt in &report.accepted {
                if let Some(endpoint_ref) = v5_endpoint_ref(&receipt.endpoint) {
                    results.push(audit_v5::EndpointResult {
                        endpoint_ref,
                        status: audit_v5::EndpointStatus::Acknowledged,
                        failure_kind: None,
                        rejection_category: (receipt.ack_kind
                            == Some(TransportEndpointAckKind::Duplicate))
                        .then_some(audit_v5::RejectionCategory::Duplicate),
                    });
                }
            }
            for failure in &report.failed {
                if let Some(result) = v5_failed_endpoint_result(failure) {
                    results.push(result);
                }
            }
        }
        results.sort_by(|a, b| a.endpoint_ref.cmp(&b.endpoint_ref));
        let unique = results
            .windows(2)
            .all(|pair| pair[0].endpoint_ref < pair[1].endpoint_ref);
        results.dedup_by(|a, b| a.endpoint_ref == b.endpoint_ref);
        let results_complete = report.is_some()
            && unique
            && results.len() == attempted.len()
            && source_count == attempted.len()
            && results.len() <= audit_v5::MAX_ENDPOINTS;
        results.truncate(audit_v5::MAX_ENDPOINTS);
        let accepted_this_attempt_count = results_complete
            .then(|| report.and_then(|report| u32::try_from(report.accepted.len()).ok()))
            .flatten();
        let accepted_total_count = u32::try_from(accepted_total).ok();
        // Met by the stored total whatever this pass's detail; unmet only
        // when every endpoint of the pass answered.
        let policy = match accepted_total_count {
            Some(total) if total >= required_acks => audit_v5::Policy::Met,
            Some(_) if results_complete => audit_v5::Policy::Unmet,
            _ => audit_v5::Policy::Unknown,
        };
        let state = self
            .session
            .outbound_welcome_audit_facts(&pass.welcome_id)
            .ok()
            .flatten()
            .map(|facts| facts.state);
        // A met policy completes an owed Welcome: the runtime marks it
        // delivered right after this row. A withdrawn one stays withdrawn.
        let retained_state = match (state, policy) {
            (Some(MessageState::Processed | MessageState::Sent), audit_v5::Policy::Met) => {
                audit_v5::RetainedState::Completed
            }
            (Some(MessageState::Sent), audit_v5::Policy::Unmet | audit_v5::Policy::Unknown) => {
                audit_v5::RetainedState::Pending
            }
            _ => audit_v5::RetainedState::Unknown,
        };
        self.audit.record_v5_event(
            Some(pass.group_ref.clone()),
            audit_v5::Event::WelcomePublishFinished(audit_v5::WelcomePublishFinished {
                attempt_id: pass.started.attempt_id.clone(),
                outer_event_ref: pass.started.outer_event_ref.clone(),
                results,
                results_complete,
                accepted_this_attempt_count,
                accepted_total_count,
                required_acks,
                policy,
                retained_state,
                elapsed_us: None,
            }),
        );
    }
}

/// The outer event reference of a retained outbound Welcome the Nostr
/// transport wrapped. Its id is the one this account's own peeler gave the
/// wrap it built, the event's NIP-01 hash, which is the id the recipient
/// observes; the session parses no transport event to check it again.
/// `None` for another transport's Welcome.
fn v5_outbound_welcome_ref(message: &TransportMessage) -> Option<audit_v5::NostrEventRef> {
    if message.source.0 != "nostr" {
        return None;
    }
    let id = <[u8; 32]>::try_from(message.id.as_slice()).ok()?;
    Some(audit_v5::NostrEventRef::from_validated_event_id(&id))
}

fn v5_size_class(size_class: cgka_traits::EventSizeClass) -> audit_v5::EventSizeClass {
    match size_class {
        cgka_traits::EventSizeClass::Under64Kib => audit_v5::EventSizeClass::Under64Kib,
        cgka_traits::EventSizeClass::From64To128Kib => audit_v5::EventSizeClass::From64To128Kib,
        cgka_traits::EventSizeClass::From128To256Kib => audit_v5::EventSizeClass::From128To256Kib,
        cgka_traits::EventSizeClass::From256To512Kib => audit_v5::EventSizeClass::From256To512Kib,
        cgka_traits::EventSizeClass::From512KibTo1Mib => audit_v5::EventSizeClass::From512KibTo1Mib,
        cgka_traits::EventSizeClass::From1To2Mib => audit_v5::EventSizeClass::From1To2Mib,
        cgka_traits::EventSizeClass::From2To4Mib => audit_v5::EventSizeClass::From2To4Mib,
        cgka_traits::EventSizeClass::Over4Mib => audit_v5::EventSizeClass::Over4Mib,
    }
}
