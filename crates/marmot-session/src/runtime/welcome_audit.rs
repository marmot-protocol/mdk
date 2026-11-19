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
    /// `welcome_id` as its v5 rows name it, from its stored row in any
    /// state; `None` without a v5 recorder, for any other row, or for a
    /// Welcome another transport wrapped.
    pub(super) fn v5_welcome(&self, welcome_id: &cgka_traits::MessageId) -> Option<V5Welcome> {
        if !self.audit.records_v5() {
            return None;
        }
        let facts = self
            .session
            .outbound_welcome_audit_facts(welcome_id)
            .ok()??;
        let outer = v5_outbound_welcome_ref(&facts.message)?;
        let TransportEnvelope::Welcome { recipient } = &facts.message.envelope else {
            return None;
        };
        let recipient_ref = audit_v5::MemberRef::from_member_identity(recipient.as_slice()).ok()?;
        let group_ref = audit_v5::GroupRef::from_group_id(facts.group_id.as_slice()).ok()?;
        Some(V5Welcome {
            op_id: welcome_audit_operation_id(welcome_id),
            outer,
            recipient_ref,
            group_ref,
            facts,
        })
    }

    /// The group a publish of `message` is audited under: its target's
    /// group, or for a Welcome the group its stored row names, so generic
    /// publish rows of Welcomes are found with their group.
    pub(super) fn audit_group_of(
        &self,
        message: &TransportMessage,
        target_group: Option<GroupId>,
    ) -> Option<GroupId> {
        if target_group.is_some() || !matches!(message.envelope, TransportEnvelope::Welcome { .. })
        {
            return target_group;
        }
        self.session
            .outbound_welcome_audit_facts(&message.id)
            .ok()
            .flatten()
            .map(|facts| facts.group_id)
    }

    /// Record `welcome_prepared` and `welcome_event_size` for each Welcome a
    /// commit just staged, exactly as the engine stored it: the commit it
    /// waits on and the KeyPackage it answers. Called where every such
    /// Welcome first reaches the runtime: a host's commit when accepted, and
    /// a drained or automatic commit when it is published.
    pub(super) fn record_v5_welcomes_prepared(&mut self, welcomes: &[TransportMessage]) {
        if !self.audit.records_v5() {
            return;
        }
        for welcome in welcomes {
            if self.v5_prepared_welcomes.len() >= MAX_PREPARED_WELCOMES_REMEMBERED {
                self.v5_prepared_welcomes.clear();
            }
            if !self.v5_prepared_welcomes.insert(welcome.id.clone()) {
                continue;
            }
            let Some(v5) = self.v5_welcome(&welcome.id) else {
                continue;
            };
            let commit_ref = v5
                .facts
                .origin_commit_id
                .as_ref()
                .and_then(|id| audit_v5::EngineMessageRef::from_message_id(id.as_slice()).ok());
            let key_package_ref = v5
                .facts
                .key_package_event_id
                .as_ref()
                .and_then(|id| <[u8; 32]>::try_from(id.as_slice()).ok())
                .map(|id| audit_v5::NostrEventRef::from_validated_event_id(&id));
            // A constructed invite row names the commit and the KeyPackage.
            if let (Some(commit_ref), Some(key_package_ref)) = (commit_ref, key_package_ref) {
                self.audit.record_v5_event(
                    Some(v5.group_ref.clone()),
                    audit_v5::Event::WelcomePrepared(audit_v5::WelcomePrepared {
                        op_id: v5.op_id.clone(),
                        recipient_ref: v5.recipient_ref.clone(),
                        mode: audit_v5::Mode::Invite,
                        basis: audit_v5::Basis::Commit { commit_ref },
                        key_package_event_ref: Some(key_package_ref),
                        outer_event_ref: Some(v5.outer.clone()),
                        construction: audit_v5::Construction::Constructed,
                        // Retained, staged with its commit.
                        retention: audit_v5::Retention::Committed,
                        failure_stage: None,
                        reason: None,
                        elapsed_us: None,
                    }),
                );
            }
            self.record_v5_welcome_size(&v5, welcome);
        }
    }

    /// Record `welcome_event_size` for each founding Welcome a create just
    /// retained; the app's probe records their `welcome_prepared` rows.
    pub(super) fn record_v5_founding_welcome_sizes(&self, effects: &SessionEffects) {
        for work in &effects.publish {
            let (PublishWork::FoundingGroupCreated { welcomes }
            | PublishWork::GroupCreated { welcomes, .. }) = work
            else {
                continue;
            };
            for welcome in welcomes {
                if let Some(v5) = self.v5_welcome(&welcome.id) {
                    self.record_v5_welcome_size(&v5, welcome);
                }
            }
        }
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

    /// Record `welcome_withdrawn` for each Welcome of an invite refused as
    /// too large, before its commit is rolled back.
    pub(super) fn record_v5_welcomes_refused(
        &self,
        welcomes: &[TransportMessage],
        oversized: OversizedEvent,
    ) {
        let reason = match oversized.artifact {
            OversizedArtifact::Welcome => audit_v5::WithdrawalReason::WelcomeTooLarge,
            OversizedArtifact::Commit => audit_v5::WithdrawalReason::CommitTooLarge,
            // An invite is refused for its commit or a Welcome only.
            OversizedArtifact::ApplicationMessage | OversizedArtifact::Other => return,
        };
        for welcome in welcomes {
            if let Some(v5) = self.v5_welcome(&welcome.id) {
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
        if let Some(v5) = self.v5_welcome(welcome_id) {
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
        welcome_id: &cgka_traits::MessageId,
        reason: audit_v5::NotStartedReason,
    ) {
        if let Some(v5) = self.v5_welcome(welcome_id) {
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

    /// The v5 rows of one publish pass of `message` over `endpoints`, ready
    /// for [`V5WelcomePass::start`]; `None` for anything but a Welcome
    /// [`Self::v5_welcome`] names.
    pub(super) fn v5_welcome_pass(
        &self,
        message: &TransportMessage,
        endpoints: &[TransportEndpoint],
        required_acks: usize,
        accepted_before: usize,
        route_source: audit_v5::RouteSource,
    ) -> Option<V5WelcomePass> {
        if !matches!(message.envelope, TransportEnvelope::Welcome { .. }) {
            return None;
        }
        let v5 = self.v5_welcome(&message.id)?;
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
            welcome_id: message.id.clone(),
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
        let retained_state = match (state, policy) {
            (Some(MessageState::Processed), audit_v5::Policy::Met) => {
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
