use std::sync::Arc;

use cgka_traits::engine::KeyPackage;
use cgka_traits::{MemberId, MessageId, TransportAdapterError, TransportEndpoint};
use nostr::base64::Engine as _;
use nostr::base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use transport_nostr_peeler::NostrTransportEvent;

use crate::{NostrPublishOutcome, NostrRelayClient};

pub const KIND_MARMOT_KEY_PACKAGE: u64 = 30_443;
pub const KIND_MARMOT_KEY_PACKAGE_RELAY_LIST: u64 = 10_051;

const D_TAG: &str = "d";
const IDENTITY_TAG: &str = "i";
const MLS_PROTOCOL_VERSION_TAG: &str = "mls_protocol_version";
const MLS_CIPHERSUITE_TAG: &str = "mls_ciphersuite";
const MLS_EXTENSIONS_TAG: &str = "mls_extensions";
const MLS_PROPOSALS_TAG: &str = "mls_proposals";
const APP_COMPONENTS_TAG: &str = "app_components";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NostrKeyPackagePublication {
    pub account_id: MemberId,
    pub key_package: KeyPackage,
    pub key_package_slot_id: String,
    pub key_package_ref: String,
    pub mls_ciphersuite: String,
    pub mls_extensions: Vec<String>,
    pub mls_proposals: Vec<String>,
    pub app_components: Vec<String>,
    pub publish_endpoints: Vec<TransportEndpoint>,
}

impl NostrKeyPackagePublication {
    pub fn to_event(&self) -> Result<NostrTransportEvent, TransportAdapterError> {
        if self.account_id.as_slice().len() != 32 {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage account id must be a 32-byte Nostr pubkey".into(),
            ));
        }
        if self.key_package_slot_id.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage d tag must not be empty".into(),
            ));
        }
        if self.key_package_ref.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage i tag must not be empty".into(),
            ));
        }
        if self.mls_ciphersuite.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage mls_ciphersuite tag must not be empty".into(),
            ));
        }
        if self.mls_extensions.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage mls_extensions tag must not be empty".into(),
            ));
        }
        if self.mls_proposals.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage mls_proposals tag must not be empty".into(),
            ));
        }
        if self.app_components.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage app_components tag must not be empty".into(),
            ));
        }
        if self.publish_endpoints.is_empty() {
            return Err(TransportAdapterError::Publish(
                "Marmot KeyPackage publish endpoints must not be empty".into(),
            ));
        }

        let identity = hex::encode(self.account_id.as_slice());
        let tags = vec![
            vec![D_TAG.into(), self.key_package_slot_id.clone()],
            vec![MLS_PROTOCOL_VERSION_TAG.into(), "1.0".into()],
            vec![IDENTITY_TAG.into(), self.key_package_ref.clone()],
            vec![MLS_CIPHERSUITE_TAG.into(), self.mls_ciphersuite.clone()],
            values_tag(MLS_EXTENSIONS_TAG, &self.mls_extensions),
            values_tag(MLS_PROPOSALS_TAG, &self.mls_proposals),
            values_tag(APP_COMPONENTS_TAG, &self.app_components),
        ];

        Ok(NostrTransportEvent::new_unsigned(
            identity,
            KIND_MARMOT_KEY_PACKAGE,
            tags,
            BASE64_STANDARD.encode(self.key_package.bytes()),
        ))
    }
}

#[derive(Clone)]
pub struct NostrKeyPackagePublisher {
    relay_client: Arc<dyn NostrRelayClient>,
    required_acks: usize,
}

impl NostrKeyPackagePublisher {
    pub fn new(relay_client: Arc<dyn NostrRelayClient>) -> Self {
        Self {
            relay_client,
            required_acks: 1,
        }
    }

    pub fn required_acks(mut self, required_acks: usize) -> Self {
        self.required_acks = required_acks;
        self
    }

    pub async fn publish_key_package(
        &self,
        publication: &NostrKeyPackagePublication,
    ) -> Result<NostrPublishOutcome, TransportAdapterError> {
        let event = publication.to_event()?;
        let event_id = MessageId::new(hex::decode(&event.id).map_err(|err| {
            TransportAdapterError::Publish(format!("invalid KeyPackage event id: {err}"))
        })?);
        let mut outcome = self
            .relay_client
            .publish_event(&publication.publish_endpoints, &event, self.required_acks)
            .await?;
        outcome.message_id.get_or_insert(event_id);
        Ok(outcome)
    }
}

fn values_tag(name: &str, values: &[String]) -> Vec<String> {
    std::iter::once(name.to_owned())
        .chain(values.iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;
    use crate::NostrSubscription;

    #[derive(Default)]
    struct RecordingRelay {
        published: Mutex<Vec<(Vec<TransportEndpoint>, NostrTransportEvent, usize)>>,
    }

    #[async_trait]
    impl NostrRelayClient for RecordingRelay {
        async fn subscribe(
            &self,
            _subscription: NostrSubscription,
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn unsubscribe(
            &self,
            _subscription: NostrSubscription,
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn unsubscribe_account(
            &self,
            _account_id: &MemberId,
        ) -> Result<(), TransportAdapterError> {
            Ok(())
        }

        async fn publish_event(
            &self,
            endpoints: &[TransportEndpoint],
            event: &NostrTransportEvent,
            required_acks: usize,
        ) -> Result<NostrPublishOutcome, TransportAdapterError> {
            self.published
                .lock()
                .unwrap()
                .push((endpoints.to_vec(), event.clone(), required_acks));
            Ok(NostrPublishOutcome::accepted(endpoints.to_vec()))
        }
    }

    #[test]
    fn marmot_key_package_event_uses_kind_30443_and_marmot_tags() {
        let publication = sample_publication();

        let event = publication.to_event().unwrap();

        assert_eq!(event.kind, KIND_MARMOT_KEY_PACKAGE);
        assert_eq!(event.pubkey, "a1".repeat(32));
        assert_eq!(event.content, "AQIDBA==");
        assert_eq!(tag(&event, "d"), Some("slot-1"));
        assert_eq!(tag(&event, "mls_protocol_version"), Some("1.0"));
        assert_eq!(tag(&event, "i"), Some("bb".repeat(32).as_str()));
        assert_eq!(tag(&event, "mls_ciphersuite"), Some("0x0001"));
        assert_eq!(tag(&event, "encoding"), None);
        assert_eq!(tag(&event, "relays"), None);
        assert_eq!(
            event
                .tags
                .iter()
                .find(|candidate| candidate
                    .first()
                    .is_some_and(|name| name == "app_components"))
                .unwrap(),
            &vec![
                "app_components".to_string(),
                "0x8001".to_string(),
                "0x8003".to_string(),
                "0x8004".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn publisher_sends_marmot_key_package_event_to_configured_endpoints() {
        let relay = Arc::new(RecordingRelay::default());
        let publisher = NostrKeyPackagePublisher::new(relay.clone()).required_acks(2);
        let publication = sample_publication();

        let outcome = publisher.publish_key_package(&publication).await.unwrap();

        assert_eq!(outcome.accepted.len(), 2);
        let published = relay.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, publication.publish_endpoints);
        assert_eq!(published[0].1.kind, KIND_MARMOT_KEY_PACKAGE);
        assert_eq!(published[0].2, 2);
    }

    fn sample_publication() -> NostrKeyPackagePublication {
        NostrKeyPackagePublication {
            account_id: MemberId::new(vec![0xA1; 32]),
            key_package: KeyPackage::new(vec![1, 2, 3, 4]),
            key_package_slot_id: "slot-1".into(),
            key_package_ref: "bb".repeat(32),
            mls_ciphersuite: "0x0001".into(),
            mls_extensions: vec!["0x0006".into(), "0xf2f1".into(), "0x000a".into()],
            mls_proposals: vec!["0x0008".into(), "0x000a".into()],
            app_components: vec!["0x8001".into(), "0x8003".into(), "0x8004".into()],
            publish_endpoints: vec![
                TransportEndpoint("wss://kp-a.example".into()),
                TransportEndpoint("wss://kp-b.example".into()),
            ],
        }
    }

    fn tag<'a>(event: &'a NostrTransportEvent, name: &str) -> Option<&'a str> {
        event
            .tags
            .iter()
            .find(|candidate| candidate.first().is_some_and(|tag_name| tag_name == name))
            .and_then(|candidate| candidate.get(1))
            .map(String::as_str)
    }
}
