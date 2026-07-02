//! Transport routing policy: the routing trait, its errors, and the static
//! routing harness, plus publish-target inspection helpers.

use std::collections::HashMap;

use cgka_traits::transport::{TransportEnvelope, TransportMessage};
use cgka_traits::{
    GroupId, MemberId, TransportEndpoint, TransportGroupSubscription, TransportPublishTarget,
};

pub trait TransportRoutingPolicy: Send + Sync {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint>;
    fn key_package_endpoints(&self) -> Vec<TransportEndpoint>;
    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription>;
    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError>;
    fn required_acks(&self, target: &TransportPublishTarget) -> usize;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportRoutingError {
    #[error("missing inbox route for recipient")]
    MissingInboxRoute,
    #[error("missing group route for transport group id")]
    MissingGroupRoute,
}

#[derive(Clone, Debug)]
pub struct StaticTransportRouting {
    local_inbox_endpoints: Vec<TransportEndpoint>,
    key_package_endpoints: Vec<TransportEndpoint>,
    inbox_routes: HashMap<MemberId, Vec<TransportEndpoint>>,
    group_routes: Vec<TransportGroupSubscription>,
    required_acks: usize,
}

impl StaticTransportRouting {
    pub fn new(local_inbox_endpoints: Vec<TransportEndpoint>) -> Self {
        Self {
            key_package_endpoints: local_inbox_endpoints.clone(),
            local_inbox_endpoints,
            inbox_routes: HashMap::new(),
            group_routes: Vec::new(),
            required_acks: 1,
        }
    }

    pub fn key_package_endpoints(mut self, endpoints: Vec<TransportEndpoint>) -> Self {
        self.key_package_endpoints = endpoints;
        self
    }

    pub fn required_acks(mut self, required_acks: usize) -> Self {
        self.required_acks = required_acks;
        self
    }

    pub fn with_inbox_route(
        mut self,
        account_id: MemberId,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        self.inbox_routes.insert(account_id, endpoints);
        self
    }

    pub fn with_group_route(
        mut self,
        group_id: GroupId,
        transport_group_id: Vec<u8>,
        endpoints: Vec<TransportEndpoint>,
    ) -> Self {
        self.group_routes.push(TransportGroupSubscription {
            group_id,
            transport_group_id,
            endpoints,
        });
        self
    }
}

impl TransportRoutingPolicy for StaticTransportRouting {
    fn local_inbox_endpoints(&self) -> Vec<TransportEndpoint> {
        self.local_inbox_endpoints.clone()
    }

    fn key_package_endpoints(&self) -> Vec<TransportEndpoint> {
        self.key_package_endpoints.clone()
    }

    fn group_subscriptions(&self) -> Vec<TransportGroupSubscription> {
        self.group_routes.clone()
    }

    fn publish_target(
        &self,
        message: &TransportMessage,
    ) -> Result<TransportPublishTarget, TransportRoutingError> {
        match &message.envelope {
            TransportEnvelope::Welcome { recipient } => {
                let endpoints = self
                    .inbox_routes
                    .get(recipient)
                    .cloned()
                    .ok_or(TransportRoutingError::MissingInboxRoute)?;
                Ok(TransportPublishTarget::Inbox {
                    recipient: recipient.clone(),
                    endpoints,
                })
            }
            TransportEnvelope::GroupMessage { transport_group_id } => {
                let route = self
                    .group_routes
                    .iter()
                    .find(|route| route.transport_group_id == *transport_group_id)
                    .cloned()
                    .ok_or(TransportRoutingError::MissingGroupRoute)?;
                Ok(TransportPublishTarget::Group {
                    group_id: route.group_id,
                    transport_group_id: route.transport_group_id,
                    endpoints: route.endpoints,
                })
            }
        }
    }

    fn required_acks(&self, _target: &TransportPublishTarget) -> usize {
        self.required_acks
    }
}

pub(crate) fn publish_target_kind(target: &TransportPublishTarget) -> &'static str {
    match target {
        TransportPublishTarget::Group { .. } => "group",
        TransportPublishTarget::Inbox { .. } => "inbox",
    }
}

pub(crate) fn publish_target_relay_urls(target: &TransportPublishTarget) -> Vec<String> {
    target
        .endpoints()
        .iter()
        .map(|endpoint| endpoint.0.clone())
        .collect()
}

pub(crate) fn publish_target_group_id(target: &TransportPublishTarget) -> Option<GroupId> {
    match target {
        TransportPublishTarget::Group { group_id, .. } => Some(group_id.clone()),
        TransportPublishTarget::Inbox { .. } => None,
    }
}
