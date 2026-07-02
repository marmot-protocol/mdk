//! Live agent text stream anchor/watch commands.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rand::rngs::OsRng;

use crate::Marmot;
use crate::conversions::{AgentStreamStartFfi, group_id_from_hex};
use crate::errors::MarmotKitError;
use crate::subscriptions::AgentStreamSubscription;

fn random_agent_stream_id() -> Vec<u8> {
    let mut stream_id = vec![0; 32];
    OsRng.fill_bytes(&mut stream_id);
    stream_id
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Anchor a live agent text stream start in the encrypted group history.
    /// Host apps pass the broker candidate(s) they will publish to, such as
    /// `quic://quic-broker.ipf.dev:4450`; omit `stream_id_hex` to let Rust
    /// generate a 32-byte stream id.
    pub async fn start_agent_text_stream(
        &self,
        account_ref: String,
        group_id_hex: String,
        stream_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<AgentStreamStartFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let stream_id = match stream_id_hex {
            Some(value) => hex::decode(value).map_err(|err| MarmotKitError::InvalidHex {
                details: err.to_string(),
            })?,
            None => random_agent_stream_id(),
        };
        let stream_id_hex = hex::encode(&stream_id);
        let (_, summary) = self
            .runtime
            .start_agent_text_stream(
                &account_ref,
                &group_id,
                &stream_id,
                unix_now_seconds(),
                quic_candidates,
            )
            .await?;
        Ok(AgentStreamStartFfi::new(stream_id_hex, summary))
    }

    /// Watch a live agent text stream over the brokered QUIC channel. Pass
    /// `stream_id_hex = None` to follow the latest stream in the group (the
    /// common case when reacting to an AgentStreamStarted event). The returned
    /// subscription yields incremental `Chunk`s then a terminal `Finished` /
    /// `Failed`. `server_cert_der` pins a self-signed broker cert (else platform
    /// trust); `insecure_local` is loopback-only for testing.
    ///
    /// `async` only so the underlying runtime call can spawn the QUIC
    /// subscriber task via `tokio::spawn` (which needs an active runtime); the
    /// method itself does not await. Mirrors `subscribe_chats` /
    /// `subscribe_messages`.
    pub async fn watch_agent_text_stream(
        &self,
        account_ref: String,
        group_id_hex: String,
        stream_id_hex: Option<String>,
        server_cert_der: Option<Vec<u8>>,
        insecure_local: bool,
    ) -> Result<Arc<AgentStreamSubscription>, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let watch = self
            .runtime
            .watch_agent_text_stream(
                &account_ref,
                &group_id,
                marmot_app::AgentStreamWatchOptions {
                    stream_id_hex,
                    server_cert_der,
                    insecure_local,
                },
            )
            .await?;
        Ok(AgentStreamSubscription::new(watch))
    }
}
