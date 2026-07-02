use cgka_traits::{
    TransportAccountActivation, TransportEndpoint, TransportGroupSync, TransportPublishRequest,
    TransportPublishTarget,
};
use nostr_sdk::prelude::RelayUrl;

const MAX_RELAY_ENDPOINTS_PER_ROUTE: usize = 16;

#[derive(Clone, Debug)]
pub(crate) struct RelaySafetyPolicy {
    max_endpoints_per_route: usize,
}

impl Default for RelaySafetyPolicy {
    fn default() -> Self {
        Self {
            max_endpoints_per_route: MAX_RELAY_ENDPOINTS_PER_ROUTE,
        }
    }
}

impl RelaySafetyPolicy {
    pub(crate) fn sanitize_activation(
        &self,
        mut activation: TransportAccountActivation,
    ) -> Result<TransportAccountActivation, String> {
        activation.inbox_endpoints =
            self.sanitize_endpoints(activation.inbox_endpoints, "account inbox")?;
        for group in &mut activation.group_subscriptions {
            group.endpoints = self.sanitize_endpoints(group.endpoints.clone(), "group route")?;
        }
        Ok(activation)
    }

    pub(crate) fn sanitize_group_sync(
        &self,
        mut sync: TransportGroupSync,
    ) -> Result<TransportGroupSync, String> {
        for group in &mut sync.group_subscriptions {
            group.endpoints = self.sanitize_endpoints(group.endpoints.clone(), "group route")?;
        }
        Ok(sync)
    }

    pub(crate) fn sanitize_publish_request(
        &self,
        mut request: TransportPublishRequest,
    ) -> Result<TransportPublishRequest, String> {
        match &mut request.target {
            TransportPublishTarget::Group { endpoints, .. } => {
                *endpoints = self.sanitize_endpoints(endpoints.clone(), "group publish")?;
            }
            TransportPublishTarget::Inbox { endpoints, .. } => {
                *endpoints = self.sanitize_endpoints(endpoints.clone(), "inbox publish")?;
            }
        }
        Ok(request)
    }

    pub(crate) fn sanitize_endpoints(
        &self,
        endpoints: Vec<TransportEndpoint>,
        context: &str,
    ) -> Result<Vec<TransportEndpoint>, String> {
        let mut sanitized = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let raw = endpoint.as_str().trim();
            if raw.is_empty() {
                return Err(format!("{context}: invalid relay endpoint"));
            }
            let relay_url = RelayUrl::parse(raw)
                .map_err(|err| format!("{context}: invalid relay endpoint: {err}"))?;
            let endpoint = TransportEndpoint(relay_url.to_string());
            if !sanitized.contains(&endpoint) {
                sanitized.push(endpoint);
            }
        }
        if sanitized.len() > self.max_endpoints_per_route {
            return Err(format!(
                "{context}: relay endpoint count {} exceeds limit {}",
                sanitized.len(),
                self.max_endpoints_per_route
            ));
        }
        Ok(sanitized)
    }
}
