//! Foreign handle for a host-driven agent stream publisher.

use std::sync::Arc;

use crate::conversions::{SendSummaryFfi, group_id_from_hex};
use crate::{Marmot, MarmotKitError};

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PublisherRecordFfi {
    Text,
    Status,
    Progress,
}

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PublisherTrustFfi {
    PublicOnly,
    AllowLoopback,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PublisherOptionsFfi {
    pub candidate: String,
    pub server_cert_der: Option<Vec<u8>>,
    pub trust: PublisherTrustFfi,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PublisherInfoFfi {
    pub stream_id_hex: String,
    pub start_message_id_hex: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PublisherAckFfi {
    pub chunk_count: u64,
    /// A preview transport error does not discard the accepted transcript.
    pub live_error: Option<String>,
}

#[derive(uniffi::Object)]
pub struct AgentTextPublisher {
    inner: Arc<marmot_app::AgentPublisher>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Publish a new stream start and return a handle for appending records.
    /// No exporter secret or framing state crosses the foreign boundary.
    pub async fn open_agent_publisher(
        &self,
        account_ref: String,
        group_id_hex: String,
        options: PublisherOptionsFfi,
    ) -> Result<Arc<AgentTextPublisher>, MarmotKitError> {
        use rand::RngCore;
        let group = group_id_from_hex(&group_id_hex)?;
        let mut stream_id = vec![0; 32];
        rand::rngs::OsRng.fill_bytes(&mut stream_id);
        let inner = self
            .runtime
            .open_agent_publisher(
                account_ref,
                group,
                stream_id,
                marmot_app::AgentPublisherOptions {
                    candidate: options.candidate,
                    server_cert_der: options.server_cert_der,
                    insecure_local: matches!(options.trust, PublisherTrustFfi::AllowLoopback),
                },
            )
            .await?;
        Ok(Arc::new(AgentTextPublisher { inner }))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AgentTextPublisher {
    pub fn info(&self) -> PublisherInfoFfi {
        PublisherInfoFfi {
            stream_id_hex: hex::encode(self.inner.stream_id()),
            start_message_id_hex: self.inner.start_id().to_owned(),
        }
    }

    pub async fn append(
        &self,
        kind: PublisherRecordFfi,
        text: String,
    ) -> Result<PublisherAckFfi, MarmotKitError> {
        let kind = match kind {
            PublisherRecordFfi::Text => marmot_app::AgentPublisherRecord::Text,
            PublisherRecordFfi::Status => marmot_app::AgentPublisherRecord::Status,
            PublisherRecordFfi::Progress => marmot_app::AgentPublisherRecord::Progress,
        };
        let ack = self.inner.append(kind, text).await?;
        Ok(PublisherAckFfi {
            chunk_count: ack.chunk_count,
            live_error: ack.error,
        })
    }

    pub async fn finish(&self) -> Result<SendSummaryFfi, MarmotKitError> {
        Ok(self.inner.finish().await?.into())
    }

    pub async fn cancel(&self) {
        self.inner.cancel().await;
    }
}
