//! Host-driven publishing, using the same transcript composer as wn-agent.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_stream_compose::{
    StreamComposeAck, StreamComposeCommand, StreamComposeReport, run_stream_compose_session,
};
use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN;
use cgka_traits::{GroupId, MessageId};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::AbortHandle;
use transport_quic_broker::OpenBrokerTextPublisher;

use super::agent_stream_watch::{
    broker_trust_for_candidate, parse_quic_candidate, resolve_broker_addr,
};
use super::{MarmotAppRuntime, wait_for_runtime_shutdown};
use crate::{AgentTextStreamFinishRequest, AppError, SendSummary};

/// Broker routing and trust for a single live preview.
pub struct AgentPublisherOptions {
    pub candidate: String,
    pub server_cert_der: Option<Vec<u8>>,
    pub insecure_local: bool,
}

/// A record included in the stream transcript hash.
pub enum AgentPublisherRecord {
    Text,
    Status,
    Progress,
}

enum PublisherState {
    Active,
    Sealed(AgentTextStreamFinishRequest),
    Finished(SendSummary),
    Cancelled,
}

/// A single stream. Methods serialize appends and finalization; dropping the
/// last handle requests cancellation. Free it before closing its runtime.
pub struct AgentPublisher {
    runtime: MarmotAppRuntime,
    account: String,
    group: GroupId,
    stream_id: Vec<u8>,
    start_id: String,
    commands: mpsc::Sender<StreamComposeCommand>,
    cancel: mpsc::Sender<()>,
    abort: AbortHandle,
    state: Arc<Mutex<PublisherState>>,
}

impl MarmotAppRuntime {
    /// Anchor a new stream, then connect to its validated broker in the
    /// background. Transport loss affects previews, not the final transcript.
    pub async fn open_agent_publisher(
        &self,
        account: String,
        group: GroupId,
        stream_id: Vec<u8>,
        options: AgentPublisherOptions,
    ) -> Result<Arc<AgentPublisher>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let candidate = parse_quic_candidate(&options.candidate)?;
        let address = tokio::time::timeout(
            Duration::from_secs(5),
            resolve_broker_addr(&candidate.authority, options.insecure_local),
        )
        .await
        .map_err(|_| AppError::AgentStreamPublisher("broker resolution timed out".into()))??;
        let trust = broker_trust_for_candidate(
            &candidate.server_name,
            options.server_cert_der,
            options.insecure_local,
        );
        let (_, summary) = self
            .start_agent_text_stream(
                &account,
                &group,
                &stream_id,
                now(),
                vec![options.candidate.clone()],
            )
            .await?;
        let start_id = summary
            .message_ids
            .first()
            .cloned()
            .ok_or(AppError::AgentStreamStartNotConfirmed)?;
        let group_hex = hex::encode(group.as_slice());
        let stream_hex = hex::encode(&stream_id);
        let crypto = self
            .agent_text_stream_crypto_for_start_event(
                Some(&account),
                Some(&group_hex),
                Some(&stream_hex),
                &start_id,
            )
            .await?;
        let open = OpenBrokerTextPublisher {
            broker_addr: address,
            server_name: candidate.server_name,
            trust,
            stream_id: stream_id.clone(),
            start_event_id: MessageId::new(hex::decode(&start_id)?),
            crypto: Some(crypto.crypto),
            max_plaintext_frame_len: crypto.policy_max_plaintext_frame_len,
        };
        let report = StreamComposeReport {
            account: Some(account.clone()),
            group_id: group_hex,
            stream_id: stream_hex,
            start_message_id: start_id.clone(),
            candidate: options.candidate,
            status: "streaming".into(),
            text: String::new(),
            transcript_hash: None,
            chunk_count: 0,
            error: None,
        };
        let (commands, rx) = mpsc::channel(16);
        let (cancel, cancel_rx) = mpsc::channel(1);
        let shutdown_cancel = cancel.clone();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let task = tokio::spawn(async move {
            let compose = run_stream_compose_session(
                open,
                AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize,
                rx,
                cancel_rx,
                report,
            );
            tokio::pin!(compose);
            tokio::select! {
                _ = &mut compose => {},
                _ = wait_for_runtime_shutdown(&mut stopping) => {
                    let _ = shutdown_cancel.try_send(());
                    // Let the composer emit its terminal Abort, with a bound
                    // even if the broker is unresponsive during shutdown.
                    let _ = tokio::time::timeout(Duration::from_secs(3), &mut compose).await;
                }
            }
        });
        Ok(Arc::new(AgentPublisher {
            runtime: self.clone(),
            account,
            group,
            stream_id,
            start_id,
            commands,
            cancel,
            abort: task.abort_handle(),
            state: Arc::new(Mutex::new(PublisherState::Active)),
        }))
    }
}

impl AgentPublisher {
    pub fn stream_id(&self) -> &[u8] {
        &self.stream_id
    }

    pub fn start_id(&self) -> &str {
        &self.start_id
    }

    /// Append a transcript record. The ack never copies the accumulated text.
    pub async fn append(
        &self,
        kind: AgentPublisherRecord,
        text: String,
    ) -> Result<StreamComposeAck, AppError> {
        self.runtime.shared.lifecycle().ensure_running()?;
        let state = self.state.lock().await;
        if !matches!(*state, PublisherState::Active) {
            return Err(AppError::AgentStreamPublisher(
                "stream is not active".into(),
            ));
        }
        let (respond, response) = oneshot::channel();
        let command = match kind {
            AgentPublisherRecord::Text => StreamComposeCommand::Append { text, respond },
            AgentPublisherRecord::Status => StreamComposeCommand::Status {
                status: text,
                respond,
            },
            AgentPublisherRecord::Progress => StreamComposeCommand::Progress { text, respond },
        };
        self.commands.send(command).await.map_err(|_| closed())?;
        response
            .await
            .map_err(|_| closed())?
            .map_err(AppError::AgentStreamPublisher)
    }

    /// Seal the composed transcript and publish its durable final. A failed
    /// send leaves the sealed request intact; successful retries return the
    /// original receipt without publishing another final.
    pub async fn finish(self: &Arc<Self>) -> Result<SendSummary, AppError> {
        self.runtime.shared.lifecycle().ensure_running()?;
        // Reserve finalization before spawning; the task keeps the reservation
        // even if its caller is cancelled.
        let mut state = Arc::clone(&self.state).lock_owned().await;
        let publisher = Arc::clone(self);
        tokio::spawn(async move {
            let this = publisher;
            this.runtime.shared.lifecycle().ensure_running()?;
            match &*state {
                PublisherState::Finished(summary) => return Ok(summary.clone()),
                PublisherState::Cancelled => return Err(closed()),
                PublisherState::Active => {
                    let (respond, response) = oneshot::channel();
                    this.commands
                        .send(StreamComposeCommand::Finish {
                            expected: None,
                            respond,
                        })
                        .await
                        .map_err(|_| closed())?;
                    let report = response
                        .await
                        .map_err(|_| closed())?
                        .map_err(AppError::AgentStreamPublisher)?;
                    let hash = hex::decode(report.transcript_hash.ok_or_else(closed)?)?;
                    let transcript_hash = hash.try_into().map_err(|_| closed())?;
                    *state = PublisherState::Sealed(AgentTextStreamFinishRequest {
                        stream_id: this.stream_id.clone(),
                        start_event_id: this.start_id.clone(),
                        final_text_or_reference: report.text,
                        transcript_hash,
                        chunk_count: report.chunk_count,
                        finished_at: now(),
                    });
                }
                PublisherState::Sealed(_) => {}
            }
            let PublisherState::Sealed(request) = &*state else {
                unreachable!()
            };
            let (_, summary) = this
                .runtime
                .finish_agent_text_stream(&this.account, &this.group, request.clone())
                .await?;
            *state = PublisherState::Finished(summary.clone());
            Ok(summary)
        })
        .await
        .map_err(|_| closed())?
    }

    /// Cancel a preview. Finalization already in progress wins; a completed
    /// durable final cannot be retracted through this handle.
    pub async fn cancel(&self) {
        let mut state = self.state.lock().await;
        if matches!(*state, PublisherState::Active | PublisherState::Sealed(_)) {
            let _ = self.cancel.try_send(());
            *state = PublisherState::Cancelled;
        }
    }
}

impl Drop for AgentPublisher {
    fn drop(&mut self) {
        let _ = self.cancel.try_send(());
        // No async cleanup is required from a foreign destructor. The
        // composer owns a bounded connect/write lifecycle after cancellation.
        if self.runtime.is_stopping() {
            self.abort.abort();
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn closed() -> AppError {
    AppError::AgentStreamPublisher("publisher closed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn finish_reserves_before_spawn() {
        let root = tempfile::tempdir().unwrap();
        let runtime = crate::MarmotApp::with_relays(root.path(), vec![]).runtime();
        let (commands, mut received) = mpsc::channel(1);
        let (cancel, _cancelled) = mpsc::channel(1);
        let task = tokio::spawn(async {});
        let publisher = Arc::new(AgentPublisher {
            runtime,
            account: String::new(),
            group: GroupId::new(vec![]),
            stream_id: vec![],
            start_id: String::new(),
            commands,
            cancel,
            abort: task.abort_handle(),
            state: Arc::new(Mutex::new(PublisherState::Active)),
        });
        let finish = publisher.finish();
        tokio::pin!(finish);
        // Poll finish once without letting its spawned task run.
        tokio::select! {
            biased;
            _ = &mut finish => panic!("finish must await the composer"),
            _ = std::future::ready(()) => {}
        }
        let cancel = publisher.cancel();
        tokio::pin!(cancel);
        tokio::select! {
            biased;
            _ = &mut cancel => panic!("cancel must wait for finalization"),
            _ = std::future::ready(()) => {}
        }
        let StreamComposeCommand::Finish { respond, .. } = received.recv().await.unwrap() else {
            panic!("expected finalization");
        };
        // Stop at the composer boundary: no network or account is needed.
        respond.send(Err("fixture failure".into())).unwrap();
        assert!(
            matches!(finish.await, Err(AppError::AgentStreamPublisher(error))
            if error == "fixture failure")
        );
        cancel.await;
    }
}
