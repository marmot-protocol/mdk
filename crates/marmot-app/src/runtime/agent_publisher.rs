//! Host-driven publishing, using the same transcript composer as wn-agent.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_stream_compose::{
    StreamComposeAck, StreamComposeCommand, StreamComposeReport, StreamFinishExpectation,
    run_stream_compose_session_candidates,
};
use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN;
use cgka_traits::{GroupId, MessageId};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::AbortHandle;
use transport_quic_broker::{BrokerServerTrust, OpenBrokerTextPublisher};

use super::agent_stream_watch::{
    broker_trust_for_candidate, parse_quic_candidate, resolve_broker_addr,
};
use super::{MarmotAppRuntime, wait_for_runtime_shutdown};
use crate::{AgentTextStreamFinishRequest, AppError, SendSummary};

/// Whether an unavailable broker route prevents opening the publisher.
pub enum AgentPublisherRouting {
    Required,
    BestEffort,
}

/// Broker routing, parent linkage, and transcript chunking for a live preview.
pub struct AgentPublisherOptions {
    pub candidates: Vec<String>,
    pub routing: AgentPublisherRouting,
    pub parent_message_id: Option<String>,
    pub chunk_bytes: usize,
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
    Finished(AgentTextStreamFinishRequest, SendSummary),
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
    policy_max_plaintext_frame_len: Option<u32>,
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
        if options.chunk_bytes == 0
            || options.chunk_bytes > AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize
        {
            return Err(AppError::AgentStreamPublisher(
                "invalid stream chunk size".into(),
            ));
        }
        let mut routes = Vec::new();
        for candidate in &options.candidates {
            let resolved = async {
                let parsed = parse_quic_candidate(candidate)?;
                let address = tokio::time::timeout(
                    Duration::from_secs(5),
                    resolve_broker_addr(&parsed.authority, options.insecure_local),
                )
                .await
                .map_err(|_| {
                    AppError::AgentStreamPublisher("broker resolution timed out".into())
                })??;
                let trust = broker_trust_for_candidate(
                    &parsed.server_name,
                    options.server_cert_der.clone(),
                    options.insecure_local,
                );
                Ok::<_, AppError>((candidate.clone(), address, parsed.server_name, trust))
            }
            .await;
            match resolved {
                Ok(route) => routes.push(route),
                Err(error) if matches!(options.routing, AgentPublisherRouting::Required) => {
                    return Err(error);
                }
                Err(_) => continue,
            }
        }
        if matches!(options.routing, AgentPublisherRouting::Required) && routes.is_empty() {
            return Err(AppError::AgentStreamPublisher(
                "no broker candidates".into(),
            ));
        }
        let (_, summary) = self
            .start_agent_text_stream_with_parent(
                &account,
                &group,
                &stream_id,
                now(),
                options.parent_message_id,
                options.candidates,
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
        // The composer never dials `open`: connections come from `candidates`
        // below, and `open` only supplies stream_id, start_event_id, crypto,
        // and max_plaintext_frame_len. The address fields are placeholders.
        let open = OpenBrokerTextPublisher {
            broker_addr: routes
                .first()
                .map(|(_, addr, ..)| *addr)
                .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 9))),
            server_name: routes
                .first()
                .map(|(_, _, name, _)| name.clone())
                .unwrap_or_else(|| "localhost".into()),
            trust: routes
                .first()
                .map(|(_, _, _, trust)| trust.clone())
                .unwrap_or(BrokerServerTrust::Platform),
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
            candidate: routes
                .first()
                .map(|(candidate, ..)| candidate.clone())
                .unwrap_or_default(),
            status: "streaming".into(),
            text: String::new(),
            transcript_hash: None,
            chunk_count: 0,
            error: None,
        };
        // An empty candidate set keeps the transcript alive without dialing.
        let candidates = routes
            .into_iter()
            .map(
                |(_, broker_addr, server_name, trust)| OpenBrokerTextPublisher {
                    broker_addr,
                    server_name,
                    trust,
                    ..open.clone()
                },
            )
            .collect();
        let (commands, rx) = mpsc::channel(16);
        let (cancel, cancel_rx) = mpsc::channel(1);
        let shutdown_cancel = cancel.clone();
        let mut stopping = self.shared.lifecycle().subscribe_shutdown();
        let task = tokio::spawn(async move {
            let compose = run_stream_compose_session_candidates(
                open,
                candidates,
                options.chunk_bytes,
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
            policy_max_plaintext_frame_len: crypto.policy_max_plaintext_frame_len,
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

    /// Group policy cap advertised to control clients.
    pub fn policy_frame_limit(&self) -> Option<u32> {
        self.policy_max_plaintext_frame_len
    }

    /// Whether an idle sweeper may evict this publisher: no other handle
    /// exists and the stream is still active. Sealed and finished publishers
    /// are retained because the sealed transcript is the durable-send retry
    /// handle. The `try_lock` is sound only under the sole-handle check, since
    /// every state-lock holder also owns an `Arc` handle.
    pub fn is_idle_evictable(self: &Arc<Self>) -> bool {
        Arc::strong_count(self) == 1
            && self
                .state
                .try_lock()
                .is_ok_and(|state| matches!(*state, PublisherState::Active))
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
    pub async fn finish(
        self: &Arc<Self>,
        expected: Option<StreamFinishExpectation>,
    ) -> Result<SendSummary, AppError> {
        self.runtime.shared.lifecycle().ensure_running()?;
        // Reserve finalization before spawning; the task keeps the reservation
        // even if its caller is cancelled.
        let mut state = Arc::clone(&self.state).lock_owned().await;
        let publisher = Arc::clone(self);
        tokio::spawn(async move {
            let this = publisher;
            this.runtime.shared.lifecycle().ensure_running()?;
            match &*state {
                PublisherState::Finished(request, summary) => {
                    check_expected(request, expected.as_ref())?;
                    return Ok(summary.clone());
                }
                PublisherState::Cancelled => return Err(closed()),
                PublisherState::Active => {
                    let (respond, response) = oneshot::channel();
                    this.commands
                        .send(StreamComposeCommand::Finish {
                            expected: expected.clone(),
                            respond,
                        })
                        .await
                        .map_err(|_| closed())?;
                    let report = response
                        .await
                        .map_err(|_| closed())?
                        // The composer only rejects a Finish on expectation mismatch.
                        .map_err(|_| AppError::AgentStreamFinishMismatch)?;
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
            check_expected(request, expected.as_ref())?;
            let request = request.clone();
            let (_, summary) = this
                .runtime
                .finish_agent_text_stream(&this.account, &this.group, request.clone())
                .await
                .map_err(|err| AppError::AgentStreamSendFailed(Box::new(err)))?;
            *state = PublisherState::Finished(request, summary.clone());
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

fn check_expected(
    request: &AgentTextStreamFinishRequest,
    expected: Option<&StreamFinishExpectation>,
) -> Result<(), AppError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if request.final_text_or_reference != expected.final_text
        || expected
            .transcript_hash_hex
            .as_ref()
            .is_some_and(|hash| *hash != hex::encode(request.transcript_hash))
        || expected
            .chunk_count
            .is_some_and(|count| count != request.chunk_count)
    {
        return Err(AppError::AgentStreamFinishMismatch);
    }
    Ok(())
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
            policy_max_plaintext_frame_len: None,
            commands,
            cancel,
            abort: task.abort_handle(),
            state: Arc::new(Mutex::new(PublisherState::Active)),
        });
        let finish = publisher.finish(None);
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
        respond.send(Err("mismatch fixture".into())).unwrap();
        assert!(matches!(
            finish.await,
            Err(AppError::AgentStreamFinishMismatch)
        ));
        cancel.await;
    }
    #[tokio::test]
    async fn sealed_finish_retains_retry() {
        let root = tempfile::tempdir().unwrap();
        let runtime = crate::MarmotApp::with_relays(root.path(), vec![]).runtime();
        let (commands, mut received) = mpsc::channel(1);
        let (cancel, mut cancelled) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        let request = AgentTextStreamFinishRequest {
            stream_id: vec![1; 32],
            start_event_id: hex::encode([2; 32]),
            final_text_or_reference: "done".into(),
            transcript_hash: [3; 32],
            chunk_count: 1,
            finished_at: 1,
        };
        let publisher = Arc::new(AgentPublisher {
            runtime,
            account: "missing".into(),
            group: GroupId::new(vec![1; 16]),
            stream_id: request.stream_id.clone(),
            start_id: request.start_event_id.clone(),
            policy_max_plaintext_frame_len: None,
            commands,
            cancel,
            abort: task.abort_handle(),
            state: Arc::new(Mutex::new(PublisherState::Sealed(request))),
        });
        assert!(!publisher.is_idle_evictable());
        let mismatch = StreamFinishExpectation {
            final_text: "different".into(),
            transcript_hash_hex: None,
            chunk_count: None,
        };
        assert!(matches!(
            publisher.finish(Some(mismatch)).await,
            Err(AppError::AgentStreamFinishMismatch)
        ));
        let expected = StreamFinishExpectation {
            final_text: "done".into(),
            transcript_hash_hex: Some(hex::encode([3; 32])),
            chunk_count: Some(1),
        };
        // The absent account fails the durable send. Retrying still uses the
        // sealed request, without consulting the finished composer.
        for _ in 0..2 {
            assert!(matches!(
                publisher.finish(Some(expected.clone())).await,
                Err(AppError::AgentStreamSendFailed(_))
            ));
            assert!(matches!(
                *publisher.state.lock().await,
                PublisherState::Sealed(_)
            ));
            assert!(received.try_recv().is_err());
        }
        // A queued cancel must not force-abort the task before it emits Abort.
        publisher.cancel.try_send(()).unwrap();
        drop(publisher);
        assert!(!task.is_finished());
        assert_eq!(cancelled.recv().await, Some(()));
        task.abort();
    }
}
