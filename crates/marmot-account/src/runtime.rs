//! Account-device runtime: drives session effects through transport publish,
//! confirmation, and rollback, and the effect aggregates it produces.

use std::collections::VecDeque;

use cgka_session::{
    AccountDeviceSession, CreateGroupEffects, IngestEffects, PublishWork, QueuedIntentRef,
    SessionEffects,
};
use cgka_traits::AppComponentId;
use cgka_traits::engine::{CreateGroupRequest, GroupEvent, KeyPackage, SendIntent};
use cgka_traits::engine_state::PendingStateRef;
use cgka_traits::group::{Group, Member};
use cgka_traits::ingest::IngestOutcome;
use cgka_traits::transport::TransportMessage;
use cgka_traits::{
    EpochId, GroupId, Timestamp, TransportAccountActivation, TransportAdapter, TransportDelivery,
    TransportGroupSync, TransportPublishReport, TransportPublishRequest,
};
use marmot_forensics::{AuditEventContext, AuditEventKind, PublishRelayFailure};

use crate::error::{AccountError, AccountResult};
use crate::key_package::{KeyPackagePublication, KeyPackagePublisher, NoopKeyPackagePublisher};
use crate::routing::{
    StaticTransportRouting, TransportRoutingPolicy, publish_target_group_id, publish_target_kind,
    publish_target_relay_urls,
};

const TRACE_TARGET: &str = "marmot_account::runtime";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PublishStatus {
    met_required_acks: bool,
    accepted_by_any_endpoint: bool,
}

pub struct AccountDeviceRuntime<A, R = StaticTransportRouting, K = NoopKeyPackagePublisher> {
    session: AccountDeviceSession,
    adapter: A,
    routing: R,
    key_packages: K,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    pub fn new(session: AccountDeviceSession, adapter: A, routing: R, key_packages: K) -> Self {
        Self {
            session,
            adapter,
            routing,
            key_packages,
        }
    }

    pub fn session(&self) -> &AccountDeviceSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut AccountDeviceSession {
        &mut self.session
    }

    pub fn group_record(&self, group_id: &GroupId) -> AccountResult<Group> {
        Ok(self.session.group_record(group_id)?)
    }

    pub fn admin_pubkeys(&self, group_id: &GroupId) -> AccountResult<Vec<[u8; 32]>> {
        Ok(self.session.admin_pubkeys(group_id)?)
    }

    pub fn app_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<Option<Vec<u8>>> {
        Ok(self.session.app_component(group_id, component_id)?)
    }

    pub fn safe_export_secret(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.safe_export_secret(group_id, component_id)?)
    }

    pub fn exporter_secret(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> AccountResult<cgka_traits::SecretBytes> {
        Ok(self.session.exporter_secret(group_id, label, length)?)
    }

    pub fn exporter_secret_with_epoch(
        &self,
        group_id: &GroupId,
        label: &str,
        length: usize,
    ) -> AccountResult<(EpochId, cgka_traits::SecretBytes)> {
        Ok(self
            .session
            .exporter_secret_with_epoch(group_id, label, length)?)
    }

    pub fn safe_export_secret_with_epoch(
        &mut self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<(EpochId, cgka_traits::SecretBytes)> {
        Ok(self
            .session
            .safe_export_secret_with_epoch(group_id, component_id)?)
    }

    pub fn current_safe_export_epoch(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> AccountResult<EpochId> {
        Ok(self
            .session
            .current_safe_export_epoch(group_id, component_id)?)
    }

    pub async fn activate_transport(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "activate_transport",
            inbox_endpoint_count = self.routing.local_inbox_endpoints().len(),
            group_subscription_count = self.routing.group_subscriptions().len(),
            "activating account transport"
        );
        self.adapter
            .activate_account(TransportAccountActivation {
                account_id: self.session.self_id(),
                inbox_endpoints: self.routing.local_inbox_endpoints(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn sync_transport_groups(&self, since: Option<Timestamp>) -> AccountResult<()> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "sync_transport_groups",
            group_subscription_count = self.routing.group_subscriptions().len(),
            "syncing account group subscriptions"
        );
        self.adapter
            .sync_account_groups(TransportGroupSync {
                account_id: self.session.self_id(),
                group_subscriptions: self.routing.group_subscriptions(),
                since,
            })
            .await?;
        Ok(())
    }

    pub async fn publish_fresh_key_package(&mut self) -> AccountResult<KeyPackage> {
        tracing::debug!(
            target: TRACE_TARGET,
            method = "publish_fresh_key_package",
            endpoint_count = self.routing.key_package_endpoints().len(),
            "publishing fresh key package"
        );
        let key_package = self.session.fresh_key_package().await?;
        self.key_packages
            .publish_key_package(KeyPackagePublication {
                account_id: self.session.self_id(),
                key_package: key_package.clone(),
                endpoints: self.routing.key_package_endpoints(),
            })
            .await?;
        Ok(key_package)
    }

    pub async fn create_group(
        &mut self,
        request: CreateGroupRequest,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self.session.create_group(request).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok((group_id, effects))
    }

    pub async fn create_group_with_audit_context(
        &mut self,
        request: CreateGroupRequest,
        context: AuditEventContext,
    ) -> AccountResult<(GroupId, AccountDeviceEffects)> {
        let CreateGroupEffects { group_id, effects } = self
            .session
            .create_group_with_audit_context(request, context.clone())
            .await?;
        let effects = self
            .publish_session_effects_with_audit_context(effects, Some(context))
            .await?;
        Ok((group_id, effects))
    }

    pub async fn send(&mut self, intent: SendIntent) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.send(intent).await?;
        self.publish_session_effects(effects).await
    }

    pub async fn send_with_audit_context(
        &mut self,
        intent: SendIntent,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self
            .session
            .send_with_audit_context(intent, context.clone())
            .await?;
        self.publish_session_effects_with_audit_context(effects, Some(context))
            .await
    }

    pub async fn advance_convergence(
        &mut self,
        group_id: &GroupId,
    ) -> AccountResult<AccountDeviceEffects> {
        let effects = self.session.advance_convergence(group_id).await?;
        self.publish_session_effects(effects).await
    }

    pub fn members(&self, group_id: &GroupId) -> AccountResult<Vec<Member>> {
        Ok(self.session.members(group_id)?)
    }

    pub fn own_leaf_index(&self, group_id: &GroupId) -> AccountResult<u32> {
        Ok(self.session.own_leaf_index(group_id)?)
    }

    pub async fn ingest_delivery(
        &mut self,
        delivery: TransportDelivery,
    ) -> AccountResult<AccountIngestEffects> {
        if delivery.account_id != self.session.self_id() {
            return Err(AccountError::WrongAccountDelivery);
        }
        let IngestEffects { outcome, effects } = self.session.ingest_delivery(delivery).await?;
        let effects = self.publish_session_effects(effects).await?;
        Ok(AccountIngestEffects { outcome, effects })
    }

    pub async fn publish_session_effects(
        &mut self,
        effects: SessionEffects,
    ) -> AccountResult<AccountDeviceEffects> {
        self.publish_session_effects_with_audit_context(effects, None)
            .await
    }

    async fn publish_session_effects_with_audit_context(
        &mut self,
        effects: SessionEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        let mut queue = VecDeque::new();
        output.absorb_session_effects(effects, &mut queue);

        while let Some(work) = queue.pop_front() {
            match work {
                PublishWork::ApplicationMessage { msg } | PublishWork::Proposal { msg } => {
                    self.publish_one(msg, &mut output, context.clone()).await?;
                }
                PublishWork::GroupCreated { welcomes, pending } => {
                    self.publish_group_created(
                        welcomes,
                        pending,
                        &mut output,
                        &mut queue,
                        context.clone(),
                    )
                    .await?;
                }
                PublishWork::GroupEvolution {
                    msg,
                    welcomes,
                    pending,
                } => {
                    self.publish_group_evolution(
                        msg,
                        welcomes,
                        pending,
                        &mut output,
                        &mut queue,
                        context.clone(),
                    )
                    .await?;
                }
                PublishWork::AutoPublish { msg, pending } => {
                    self.publish_pending(
                        vec![msg],
                        pending,
                        &mut output,
                        &mut queue,
                        context.clone(),
                    )
                    .await?;
                }
            }
        }

        Ok(output)
    }

    async fn publish_pending(
        &mut self,
        messages: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let mut all_published = true;
        for message in messages {
            all_published &= self
                .publish_one(message, output, context.clone())
                .await?
                .met_required_acks;
        }

        if all_published {
            let effects = self.session.confirm_published(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
        } else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_group_created(
        &mut self,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let mut all_published = true;
        let mut any_welcome_exposed = false;
        for welcome in welcomes {
            let status = self.publish_one(welcome, output, context.clone()).await?;
            any_welcome_exposed |= status.accepted_by_any_endpoint;
            if !status.met_required_acks {
                all_published = false;
                if !any_welcome_exposed {
                    break;
                }
            }
        }

        if all_published || any_welcome_exposed {
            let effects = self.session.confirm_published(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);
        } else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_group_evolution(
        &mut self,
        commit: TransportMessage,
        welcomes: Vec<TransportMessage>,
        pending: PendingStateRef,
        output: &mut AccountDeviceEffects,
        queue: &mut VecDeque<PublishWork>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        if self
            .publish_one(commit, output, context.clone())
            .await?
            .met_required_acks
        {
            let effects = self.session.confirm_published(pending).await?;
            output
                .pending
                .push(PendingResolution::Confirmed { pending });
            output.absorb_session_effects(effects, queue);

            for welcome in welcomes {
                self.publish_one(welcome, output, context.clone()).await?;
            }
        } else {
            let effects = self.session.publish_failed(pending).await?;
            output
                .pending
                .push(PendingResolution::RolledBack { pending });
            output.absorb_session_effects(effects, queue);
        }
        Ok(())
    }

    async fn publish_one(
        &self,
        message: TransportMessage,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PublishStatus> {
        let message_id = message.id.clone();
        let msg_id_hex = hex::encode(message_id.as_slice());
        let mut publish_context = context.unwrap_or_default();
        publish_context.operation_id = Some(format!("publish-{msg_id_hex}"));
        let target = match self.routing.publish_target(&message) {
            Ok(target) => target,
            Err(e) => {
                self.session.record_audit_event(
                    None,
                    Some(publish_context),
                    AuditEventKind::PublishFailure {
                        msg_id: msg_id_hex,
                        stage: "routing".into(),
                        target_kind: "unknown".into(),
                        relay_urls: Vec::new(),
                        reason: e.to_string(),
                    },
                );
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(PublishStatus::default());
            }
        };
        let required_acks = self.routing.required_acks(&target);
        let target_kind = publish_target_kind(&target).to_string();
        let relay_urls = publish_target_relay_urls(&target);
        let target_group_id = publish_target_group_id(&target);
        self.session.record_audit_event(
            target_group_id.as_ref(),
            Some(publish_context.clone()),
            AuditEventKind::PublishAttempt {
                msg_id: msg_id_hex.clone(),
                target_kind: target_kind.clone(),
                relay_urls: relay_urls.clone(),
                required_acks: required_acks as u64,
            },
        );
        let report = match self
            .adapter
            .publish(TransportPublishRequest {
                account_id: self.session.self_id(),
                message,
                target,
                required_acks,
            })
            .await
        {
            Ok(report) => report,
            Err(e) => {
                self.session.record_audit_event(
                    target_group_id.as_ref(),
                    Some(publish_context),
                    AuditEventKind::PublishFailure {
                        msg_id: msg_id_hex,
                        stage: "adapter".into(),
                        target_kind,
                        relay_urls,
                        reason: e.to_string(),
                    },
                );
                output.failures.push(PublishFailure {
                    message_id,
                    reason: e.to_string(),
                });
                return Ok(PublishStatus::default());
            }
        };
        let published = report.met_required_acks();
        let accepted_by_any_endpoint = report.accepted_count() > 0;
        self.session.record_audit_event(
            target_group_id.as_ref(),
            Some(publish_context.clone()),
            AuditEventKind::PublishOutcome {
                msg_id: hex::encode(report.message_id.as_slice()),
                target_kind: target_kind.clone(),
                accepted_relay_urls: report
                    .accepted
                    .iter()
                    .map(|receipt| receipt.endpoint.0.clone())
                    .collect(),
                failed_relays: report
                    .failed
                    .iter()
                    .map(|failure| PublishRelayFailure {
                        relay_url: failure.endpoint.0.clone(),
                        reason: failure.reason.clone(),
                    })
                    .collect(),
                required_acks: report.required_acks as u64,
                met_required_acks: published,
            },
        );
        if !published {
            self.session.record_audit_event(
                target_group_id.as_ref(),
                Some(publish_context),
                AuditEventKind::PublishFailure {
                    msg_id: hex::encode(report.message_id.as_slice()),
                    stage: "required_acks".into(),
                    target_kind,
                    relay_urls,
                    reason: "insufficient publish acknowledgements".into(),
                },
            );
            output.failures.push(PublishFailure {
                message_id: report.message_id.clone(),
                reason: "insufficient publish acknowledgements".into(),
            });
        }
        output.reports.push(report);
        Ok(PublishStatus {
            met_required_acks: published,
            accepted_by_any_endpoint,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountDeviceEffects {
    pub events: Vec<GroupEvent>,
    pub queued: Vec<QueuedIntentRef>,
    pub reports: Vec<TransportPublishReport>,
    pub failures: Vec<PublishFailure>,
    pub pending: Vec<PendingResolution>,
}

impl AccountDeviceEffects {
    fn absorb_session_effects(
        &mut self,
        effects: SessionEffects,
        queue: &mut VecDeque<PublishWork>,
    ) {
        self.events.extend(effects.events);
        self.queued.extend(effects.queued);
        queue.extend(effects.publish);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIngestEffects {
    pub outcome: IngestOutcome,
    pub effects: AccountDeviceEffects,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishFailure {
    pub message_id: cgka_traits::MessageId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingResolution {
    Confirmed { pending: PendingStateRef },
    RolledBack { pending: PendingStateRef },
}
