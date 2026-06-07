//! Local Marmot agent connector daemon.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_control::{
    AgentControlAccount, AgentControlDebugFinalSend, AgentControlEnvelope, AgentControlError,
    AgentControlEvent, AgentControlRequest, AgentControlResponse, read_envelope, write_frame,
};
use agent_stream_compose::{StreamComposeCommand, StreamComposeReport, run_stream_compose_session};
use cgka_traits::{GroupId, MessageId, engine::GroupEvent};
use marmot_account::{AccountHome, AccountHomeError, AccountSummary};
use marmot_app::{
    AgentTextStreamFinishRequest, AppError, MarmotApp, MarmotAppEvent, MarmotAppRuntime,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use transport_quic_broker::{BrokerServerTrust, OpenBrokerTextPublisher};

const AGENT_SOCKET_DIR_MODE: u32 = 0o700;
const AGENT_SOCKET_MODE: u32 = 0o600;
const ALLOWLIST_DIR: &str = "agent-allowlist";
const STREAM_COMPOSE_CHANNEL_DEPTH: usize = 32;
const STREAM_COMPOSE_CHUNK_BYTES: usize = 1024;

#[derive(Clone, Debug)]
pub struct AgentConnectorConfig {
    pub home: PathBuf,
    pub socket: PathBuf,
    pub relays: Vec<String>,
    pub allow_any: bool,
    pub debug_controls: bool,
}

impl AgentConnectorConfig {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let socket = default_socket_path(&home);
        Self {
            home,
            socket,
            relays: Vec::new(),
            allow_any: false,
            debug_controls: false,
        }
    }
}

#[derive(Clone)]
pub struct AgentConnector {
    account_home: AccountHome,
    allowlists: AllowlistStore,
    allow_any: bool,
    debug_controls: bool,
    debug_events: broadcast::Sender<AgentControlEvent>,
    debug_final_sends: DebugFinalSendStore,
    streams: StreamSessionStore,
    runtime: MarmotAppRuntime,
    relays: Vec<String>,
    connection_errors: Arc<AtomicU64>,
}

impl AgentConnector {
    pub fn open(config: AgentConnectorConfig) -> Result<Self, ConnectorError> {
        let account_home = AccountHome::open(&config.home);
        let relays = config.relays;
        let app = MarmotApp::with_relays_and_account_home(
            &config.home,
            relays.clone(),
            account_home.clone(),
        );
        let runtime = MarmotAppRuntime::new(app);
        let allowlists = AllowlistStore::new(&config.home);
        let (debug_events, _) = broadcast::channel(1024);
        Ok(Self {
            account_home,
            allowlists,
            allow_any: config.allow_any,
            debug_controls: config.debug_controls,
            debug_events,
            debug_final_sends: DebugFinalSendStore::default(),
            streams: StreamSessionStore::default(),
            runtime,
            relays,
            connection_errors: Arc::new(AtomicU64::new(0)),
        })
    }

    pub async fn serve_once(&self, listener: &UnixListener) -> Result<(), ConnectorError> {
        let (stream, _peer_addr) = listener.accept().await?;
        self.handle_connection(stream).await
    }

    pub async fn start(&self) -> Result<(), ConnectorError> {
        self.runtime.start().await?;
        self.spawn_invite_policy_worker();
        self.ensure_agent_accounts_ready().await?;
        Ok(())
    }

    async fn ensure_agent_accounts_ready(&self) -> Result<(), ConnectorError> {
        let accounts = self.account_home.accounts()?;
        for account in accounts.into_iter().filter(|account| account.local_signing) {
            self.ensure_agent_account_relay_lists(&account.label)
                .await?;
            let has_key_package = !self
                .runtime
                .account_key_packages(&account.label, Vec::new())
                .await?
                .is_empty();
            if !has_key_package {
                self.runtime.publish_key_package(&account.label).await?;
            }
        }
        Ok(())
    }

    async fn ensure_agent_account_relay_lists(
        &self,
        account_ref: &str,
    ) -> Result<(), ConnectorError> {
        let missing_nip65 = self.runtime.account_nip65_relays(account_ref)?.is_empty();
        let missing_inbox = self.runtime.account_inbox_relays(account_ref)?.is_empty();
        if self.relays.is_empty() || (!missing_nip65 && !missing_inbox) {
            return Ok(());
        }

        let relays = self.configured_relay_endpoints();
        if missing_nip65 {
            self.runtime
                .set_account_nip65_relays(account_ref, relays.clone(), relays.clone())
                .await?;
        }
        if missing_inbox {
            self.runtime
                .set_account_inbox_relays(account_ref, relays.clone(), relays)
                .await?;
        }
        Ok(())
    }

    fn configured_relay_endpoints(&self) -> Vec<cgka_traits::TransportEndpoint> {
        self.relays.iter().map(|relay| endpoint(relay)).collect()
    }

    pub async fn handle_connection(&self, stream: UnixStream) -> Result<(), ConnectorError> {
        authorize_connector_peer(&stream)?;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let Some(request): Option<AgentControlEnvelope<AgentControlRequest>> =
            read_envelope(&mut reader).await?
        else {
            return Ok(());
        };
        if let AgentControlRequest::SubscribeInbound {
            account_id_hex,
            group_id_hex,
        } = request.payload
        {
            return self
                .stream_inbound_events(request.id, account_id_hex, group_id_hex, &mut write_half)
                .await;
        }
        let response = match self.handle_request(request.payload).await {
            Ok(response) => response,
            Err(err) => self.error_response(&err),
        };
        let response = AgentControlEnvelope::new(request.id, response);
        write_frame(&mut write_half, &response).await?;
        Ok(())
    }

    fn error_response(&self, err: &ConnectorError) -> AgentControlResponse {
        tracing::warn!(
            target: "agent_connector",
            method = "handle_connection",
            error_code = err.privacy_safe_code(),
            "control request failed"
        );
        AgentControlResponse::Error {
            code: err.code().to_owned(),
            message: err.client_message().to_owned(),
        }
    }

    async fn handle_request(
        &self,
        request: AgentControlRequest,
    ) -> Result<AgentControlResponse, ConnectorError> {
        match request {
            AgentControlRequest::AccountList => self.account_list_response(),
            AgentControlRequest::AllowlistList { account_id_hex } => {
                self.allowlist_response(&account_id_hex)
            }
            AgentControlRequest::AllowlistAdd {
                account_id_hex,
                welcomer_account_id_hex,
            } => self.allowlist_add_response(&account_id_hex, &welcomer_account_id_hex),
            AgentControlRequest::AllowlistRemove {
                account_id_hex,
                welcomer_account_id_hex,
            } => self.allowlist_remove_response(&account_id_hex, &welcomer_account_id_hex),
            AgentControlRequest::DebugInjectInbound {
                account_id_hex,
                group_id_hex,
                message_id_hex,
                sender_account_id_hex,
                text,
            } => self.debug_inject_inbound_response(
                &account_id_hex,
                &group_id_hex,
                &message_id_hex,
                &sender_account_id_hex,
                text,
            ),
            AgentControlRequest::DebugRecordedFinals => self.debug_recorded_finals_response(),
            AgentControlRequest::SendFinal {
                account_id_hex,
                group_id_hex,
                text,
                reply_to_message_id_hex,
            } => {
                self.send_final_response(
                    &account_id_hex,
                    &group_id_hex,
                    text,
                    reply_to_message_id_hex,
                )
                .await
            }
            AgentControlRequest::StreamBegin {
                account_id_hex,
                group_id_hex,
                stream_id_hex,
                quic_candidates,
            } => {
                self.stream_begin_response(
                    &account_id_hex,
                    &group_id_hex,
                    stream_id_hex,
                    quic_candidates,
                )
                .await
            }
            AgentControlRequest::StreamAppend {
                stream_id_hex,
                append_text,
            } => {
                self.stream_append_response(&stream_id_hex, append_text)
                    .await
            }
            AgentControlRequest::StreamStatus {
                stream_id_hex,
                status,
            } => self.stream_status_response(&stream_id_hex, status).await,
            AgentControlRequest::StreamFinalize {
                stream_id_hex,
                final_text,
                transcript_hash_hex,
                chunk_count,
            } => {
                self.stream_finalize_response(
                    &stream_id_hex,
                    final_text,
                    &transcript_hash_hex,
                    chunk_count,
                )
                .await
            }
            AgentControlRequest::StreamCancel { stream_id_hex, .. } => {
                self.stream_cancel_response(&stream_id_hex)
            }
            AgentControlRequest::AccountCreate {
                label,
                publish_key_package,
            } => {
                self.create_account_response(label, publish_key_package)
                    .await
            }
            AgentControlRequest::AccountPublishKeyPackage { account_id_hex } => {
                let account = self.local_account_for_account_id(&account_id_hex)?;
                let key_package_bytes = self.runtime.publish_key_package(&account.label).await?;
                Ok(AgentControlResponse::KeyPackagePublished {
                    account_id_hex,
                    key_package_bytes,
                })
            }
            other => Ok(AgentControlResponse::Error {
                code: "unsupported_request".to_owned(),
                message: unsupported_request_message(&other).to_owned(),
            }),
        }
    }

    fn account_list_response(&self) -> Result<AgentControlResponse, ConnectorError> {
        let accounts = self
            .account_home
            .accounts()?
            .into_iter()
            .map(|account| AgentControlAccount {
                account_id_hex: account.account_id_hex,
                label: account.label,
                local_signing: account.local_signing,
            })
            .collect();
        Ok(AgentControlResponse::AccountList { accounts })
    }

    async fn create_account_response(
        &self,
        label: Option<String>,
        publish_key_package: bool,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = match label {
            Some(label) => self.account_home.create_account(&label)?,
            None => self.account_home.create_nostr_account()?,
        };
        if publish_key_package {
            self.runtime.publish_key_package(&account.label).await?;
        }
        Ok(AgentControlResponse::AccountCreated {
            account: AgentControlAccount {
                account_id_hex: account.account_id_hex,
                label: account.label,
                local_signing: account.local_signing,
            },
        })
    }

    fn local_account_for_account_id(
        &self,
        account_id_hex: &str,
    ) -> Result<AccountSummary, ConnectorError> {
        self.account_home
            .accounts()?
            .into_iter()
            .find(|account| account.account_id_hex == account_id_hex)
            .ok_or_else(|| AccountHomeError::UnknownAccount(account_id_hex.to_owned()).into())
    }

    fn allowlist_response(
        &self,
        account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        Ok(AgentControlResponse::Allowlist {
            account_id_hex: account.account_id_hex.clone(),
            welcomer_account_ids_hex: self.allowlists.list(&account.account_id_hex)?,
        })
    }

    fn allowlist_add_response(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let welcomer_account_id_hex =
            AccountHome::account_id_for_public_key(welcomer_account_id_hex)?;
        Ok(AgentControlResponse::Allowlist {
            account_id_hex: account.account_id_hex.clone(),
            welcomer_account_ids_hex: self
                .allowlists
                .add(&account.account_id_hex, &welcomer_account_id_hex)?,
        })
    }

    fn allowlist_remove_response(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let welcomer_account_id_hex =
            AccountHome::account_id_for_public_key(welcomer_account_id_hex)?;
        Ok(AgentControlResponse::Allowlist {
            account_id_hex: account.account_id_hex.clone(),
            welcomer_account_ids_hex: self
                .allowlists
                .remove(&account.account_id_hex, &welcomer_account_id_hex)?,
        })
    }

    async fn send_final_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        text: String,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        if self.debug_controls {
            return self.debug_record_final_send_response(
                account_id_hex,
                group_id_hex,
                text,
                reply_to_message_id_hex,
            );
        }

        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id = GroupId::new(hex::decode(group_id_hex)?);
        let summary = if let Some(target_message_id) = reply_to_message_id_hex {
            self.runtime
                .reply_to_message(&account.label, &group_id, &target_message_id, &text)
                .await?
        } else {
            self.runtime
                .send_message(&account.label, &group_id, text.into_bytes())
                .await?
        };
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: summary.message_ids,
        })
    }

    fn debug_inject_inbound_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
        sender_account_id_hex: &str,
        text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        let event = AgentControlEvent::InboundMessage {
            account_id_hex: normalize_hex(account_id_hex)?,
            group_id_hex: normalize_hex(group_id_hex)?,
            message_id_hex: normalize_hex(message_id_hex)?,
            sender_account_id_hex: normalize_hex(sender_account_id_hex)?,
            text,
        };
        let _ = self.debug_events.send(event);
        Ok(AgentControlResponse::Ack)
    }

    fn debug_recorded_finals_response(&self) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        Ok(AgentControlResponse::DebugRecordedFinals {
            sends: self.debug_final_sends.list(),
        })
    }

    fn debug_record_final_send_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        text: String,
        reply_to_message_id_hex: Option<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        self.ensure_debug_controls()?;
        let record = self.debug_final_sends.record(AgentControlDebugFinalSend {
            account_id_hex: normalize_hex(account_id_hex)?,
            group_id_hex: normalize_hex(group_id_hex)?,
            text,
            reply_to_message_id_hex: reply_to_message_id_hex
                .map(|value| normalize_hex(&value))
                .transpose()?,
            message_ids_hex: Vec::new(),
        });
        Ok(AgentControlResponse::FinalSent {
            message_ids_hex: record.message_ids_hex,
        })
    }

    fn ensure_debug_controls(&self) -> Result<(), ConnectorError> {
        if self.debug_controls {
            Ok(())
        } else {
            Err(ConnectorError::DebugControlsDisabled)
        }
    }

    async fn stream_begin_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        stream_id_hex: Option<String>,
        quic_candidates: Vec<String>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let group_id = GroupId::new(hex::decode(&group_id_hex)?);
        let stream_id = stream_id_hex
            .map(|stream_id_hex| -> Result<Vec<u8>, ConnectorError> {
                Ok(hex::decode(normalize_hex(&stream_id_hex)?)?)
            })
            .transpose()?
            .unwrap_or_else(transport_quic_stream::random_stream_id);
        let stream_id_hex = hex::encode(&stream_id);
        let candidate = first_quic_candidate(&quic_candidates)?;
        let parsed_candidate = parse_quic_candidate(&candidate)?;
        let broker_addr = resolve_quic_candidate_addr(&parsed_candidate).await?;
        let trust = broker_trust_for_addr(broker_addr);
        let (_payload, summary) = self
            .runtime
            .start_agent_text_stream(
                &account.label,
                &group_id,
                &stream_id,
                unix_now_seconds(),
                quic_candidates.clone(),
            )
            .await?;
        let start_message_id_hex =
            summary.message_ids.first().cloned().ok_or_else(|| {
                ConnectorError::Stream("stream start returned no message id".into())
            })?;
        let crypto = self
            .runtime
            .agent_text_stream_crypto_for_start_event(
                Some(&account.label),
                Some(&group_id_hex),
                Some(&stream_id_hex),
                &start_message_id_hex,
            )
            .await?;

        let (tx, rx) = mpsc::channel(STREAM_COMPOSE_CHANNEL_DEPTH);
        let report = StreamComposeReport {
            account: Some(account.account_id_hex.clone()),
            group_id: group_id_hex.clone(),
            stream_id: stream_id_hex.clone(),
            start_message_id: start_message_id_hex.clone(),
            candidate: candidate.clone(),
            status: "streaming".to_owned(),
            text: String::new(),
            transcript_hash: None,
            chunk_count: 0,
            error: None,
        };
        let handle = tokio::spawn(run_stream_compose_session(
            OpenBrokerTextPublisher {
                broker_addr,
                server_name: parsed_candidate.server_name,
                trust,
                stream_id: stream_id.clone(),
                start_event_id: MessageId::new(hex::decode(&start_message_id_hex)?),
                crypto: Some(crypto.crypto),
            },
            STREAM_COMPOSE_CHUNK_BYTES,
            rx,
            report,
        ));
        self.streams.insert(
            stream_id_hex.clone(),
            ActiveStreamSession {
                account_label: account.label,
                group_id,
                stream_id,
                start_message_id_hex: start_message_id_hex.clone(),
                tx,
                abort: handle.abort_handle(),
            },
        );
        Ok(AgentControlResponse::StreamBegun {
            stream_id_hex,
            start_message_id_hex,
            quic_candidates,
        })
    }

    async fn stream_append_response(
        &self,
        stream_id_hex: &str,
        append_text: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.get(stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        session
            .tx
            .send(StreamComposeCommand::Append {
                text: append_text,
                respond,
            })
            .await
            .map_err(|_| ConnectorError::Stream("stream compose session is closed".into()))?;
        response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        Ok(AgentControlResponse::Ack)
    }

    async fn stream_status_response(
        &self,
        stream_id_hex: &str,
        status: String,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.get(stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        session
            .tx
            .send(StreamComposeCommand::Status { status, respond })
            .await
            .map_err(|_| ConnectorError::Stream("stream compose session is closed".into()))?;
        response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        Ok(AgentControlResponse::Ack)
    }

    async fn stream_finalize_response(
        &self,
        stream_id_hex: &str,
        final_text: String,
        transcript_hash_hex: &str,
        chunk_count: u64,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        let session = self.streams.remove(&stream_id_hex)?;
        let (respond, response) = oneshot::channel();
        if session
            .tx
            .send(StreamComposeCommand::Finish { respond })
            .await
            .is_err()
        {
            session.abort.abort();
            return Err(ConnectorError::Stream(
                "stream compose session is closed".into(),
            ));
        }
        let report = response
            .await
            .map_err(|err| ConnectorError::Stream(err.to_string()))?
            .map_err(ConnectorError::Stream)?;
        if report.text != final_text {
            return Err(ConnectorError::Stream(
                "stream final text does not match appended transcript".into(),
            ));
        }
        let transcript_hash = transcript_hash_from_hex(transcript_hash_hex)?;
        let expected_transcript_hash_hex = hex::encode(transcript_hash);
        let actual_transcript_hash_hex = report
            .transcript_hash
            .as_deref()
            .map(normalize_hex)
            .transpose()?;
        if actual_transcript_hash_hex.as_deref() != Some(expected_transcript_hash_hex.as_str()) {
            return Err(ConnectorError::Stream(
                "stream final transcript hash does not match appended transcript".into(),
            ));
        }
        if report.chunk_count != chunk_count {
            return Err(ConnectorError::Stream(
                "stream final chunk count does not match appended transcript".into(),
            ));
        }
        let (_payload, summary) = self
            .runtime
            .finish_agent_text_stream(
                &session.account_label,
                &session.group_id,
                AgentTextStreamFinishRequest {
                    stream_id: session.stream_id,
                    start_event_id: session.start_message_id_hex,
                    final_text_or_reference: final_text,
                    transcript_hash,
                    chunk_count,
                    finished_at: unix_now_seconds(),
                },
            )
            .await?;
        Ok(AgentControlResponse::StreamFinalized {
            stream_id_hex,
            message_ids_hex: summary.message_ids,
        })
    }

    fn stream_cancel_response(
        &self,
        stream_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let session = self.streams.remove(stream_id_hex)?;
        let _ = session.tx.try_send(StreamComposeCommand::Cancel);
        session.abort.abort();
        Ok(AgentControlResponse::Ack)
    }

    async fn stream_inbound_events<W>(
        &self,
        request_id: Option<String>,
        account_id_hex: Option<String>,
        group_id_hex: Option<String>,
        writer: &mut W,
    ) -> Result<(), ConnectorError>
    where
        W: AsyncWrite + Unpin,
    {
        let mut runtime_events = self.runtime.subscribe();
        let mut debug_events = self.debug_events.subscribe();
        if let Err(err) = self.runtime.catch_up_accounts().await {
            let err = ConnectorError::from(err);
            let response = AgentControlEnvelope::new(request_id, self.error_response(&err));
            write_frame(writer, &response).await?;
            return Ok(());
        }
        let response = AgentControlEnvelope::new(request_id.clone(), AgentControlResponse::Ack);
        write_frame(writer, &response).await?;
        loop {
            let event = tokio::select! {
                event = runtime_events.recv() => {
                    let Ok(event) = event else {
                        continue;
                    };
                    control_event_from_runtime_event(
                        event,
                        account_id_hex.as_deref(),
                        group_id_hex.as_deref(),
                    )
                }
                event = debug_events.recv() => {
                    let Ok(event) = event else {
                        continue;
                    };
                    control_event_from_debug_event(
                        event,
                        account_id_hex.as_deref(),
                        group_id_hex.as_deref(),
                    )
                }
            };
            let Some(event) = event else {
                continue;
            };
            let envelope = AgentControlEnvelope::new(request_id.clone(), event);
            write_frame(writer, &envelope).await?;
        }
    }

    fn spawn_invite_policy_worker(&self) {
        let connector = self.clone();
        tokio::spawn(async move {
            connector.run_invite_policy_worker().await;
        });
    }

    async fn run_invite_policy_worker(self) {
        let mut events = self.runtime.subscribe();
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            };
            let MarmotAppEvent::GroupEvent(group_event) = event else {
                continue;
            };
            let GroupEvent::GroupJoined {
                group_id, welcomer, ..
            } = group_event.event
            else {
                continue;
            };
            let _ = self
                .apply_invite_policy(&group_event.account_id_hex, &group_id, welcomer)
                .await;
        }
    }

    async fn apply_invite_policy(
        &self,
        account_id_hex: &str,
        group_id: &GroupId,
        welcomer: Option<cgka_traits::MemberId>,
    ) -> Result<(), ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let allowed = self.allow_any
            || match welcomer {
                Some(welcomer) => {
                    let welcomer_account_id_hex = hex::encode(welcomer.as_slice());
                    self.allowlists
                        .contains(&account.account_id_hex, &welcomer_account_id_hex)?
                }
                None => false,
            };
        if allowed {
            self.runtime
                .accept_group_invite(&account.label, group_id)
                .await?;
        } else {
            self.runtime
                .decline_group_invite(&account.label, group_id)
                .await?;
        }
        Ok(())
    }
}

pub async fn serve_socket(config: AgentConnectorConfig) -> Result<(), ConnectorError> {
    let listener = bind_connector_socket(&config.socket)?;
    let connector = AgentConnector::open(config)?;
    connector.start().await?;
    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(err) = connector.handle_connection(stream).await {
                let connection_error =
                    connector.connection_errors.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    target: "agent_connector",
                    method = "serve_socket",
                    connection_error,
                    error_code = err.privacy_safe_code(),
                    "connection failed"
                );
            }
        });
    }
}

fn control_event_from_runtime_event(
    event: MarmotAppEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    match event {
        MarmotAppEvent::MessageReceived(update) => {
            let group_id_hex = hex::encode(update.message.group_id.as_slice());
            if !inbound_filter_matches(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &group_id_hex,
            ) || update.message.sender == update.account_id_hex
            {
                return None;
            }
            Some(AgentControlEvent::InboundMessage {
                account_id_hex: update.account_id_hex,
                group_id_hex,
                message_id_hex: update.message.message_id_hex,
                sender_account_id_hex: update.message.sender,
                text: update.message.plaintext,
            })
        }
        MarmotAppEvent::GroupEvent(group_event) => match group_event.event {
            GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                welcomer,
            } => {
                let group_id_hex = hex::encode(group_id.as_slice());
                if !inbound_filter_matches(
                    account_filter,
                    &group_event.account_id_hex,
                    group_filter,
                    &group_id_hex,
                ) {
                    return None;
                }
                Some(AgentControlEvent::GroupInvite {
                    account_id_hex: group_event.account_id_hex,
                    group_id_hex,
                    via_welcome_message_id_hex: hex::encode(via_welcome.as_slice()),
                    welcomer_account_id_hex: welcomer.map(|member| hex::encode(member.as_slice())),
                })
            }
            _ => None,
        },
        _ => None,
    }
}

fn control_event_from_debug_event(
    event: AgentControlEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    let (account_id_hex, group_id_hex) = match &event {
        AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::GroupInvite {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::StreamUpdate {
            account_id_hex,
            group_id_hex,
            ..
        } => (account_id_hex, group_id_hex),
    };
    inbound_filter_matches(account_filter, account_id_hex, group_filter, group_id_hex)
        .then_some(event)
}

fn inbound_filter_matches(
    account_filter: Option<&str>,
    account_id_hex: &str,
    group_filter: Option<&str>,
    group_id_hex: &str,
) -> bool {
    account_filter.is_none_or(|filter| filter == account_id_hex)
        && group_filter.is_none_or(|filter| filter == group_id_hex)
}

fn unsupported_request_message(request: &AgentControlRequest) -> &'static str {
    match request {
        AgentControlRequest::SubscribeInbound { .. } => {
            "subscribe_inbound must be sent as the first request on a streaming connection"
        }
        _ => "request is not implemented by this connector slice",
    }
}

#[derive(Clone, Default)]
struct DebugFinalSendStore {
    sends: Arc<Mutex<Vec<AgentControlDebugFinalSend>>>,
}

impl DebugFinalSendStore {
    fn record(&self, mut send: AgentControlDebugFinalSend) -> AgentControlDebugFinalSend {
        let mut sends = self.sends.lock().expect("debug final send lock poisoned");
        let next_id = sends.len() + 1;
        send.message_ids_hex = vec![format!("{next_id:064x}")];
        sends.push(send.clone());
        send
    }

    fn list(&self) -> Vec<AgentControlDebugFinalSend> {
        self.sends
            .lock()
            .expect("debug final send lock poisoned")
            .clone()
    }
}

#[derive(Clone)]
struct AllowlistStore {
    dir: PathBuf,
    lock: Arc<Mutex<()>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AllowlistRecord {
    account_id_hex: String,
    welcomer_account_ids_hex: Vec<String>,
}

impl AllowlistStore {
    fn new(home: &Path) -> Self {
        Self {
            dir: home.join("dev").join(ALLOWLIST_DIR),
            lock: Arc::new(Mutex::new(())),
        }
    }

    fn list(&self, account_id_hex: &str) -> Result<Vec<String>, ConnectorError> {
        let _guard = self.lock.lock().expect("allowlist lock poisoned");
        Ok(self.read_record(account_id_hex)?.welcomer_account_ids_hex)
    }

    fn add(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let _guard = self.lock.lock().expect("allowlist lock poisoned");
        let mut record = self.read_record(account_id_hex)?;
        record
            .welcomer_account_ids_hex
            .push(welcomer_account_id_hex.to_owned());
        normalize_allowlist(&mut record.welcomer_account_ids_hex);
        self.write_record(&record)?;
        Ok(record.welcomer_account_ids_hex)
    }

    fn remove(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<Vec<String>, ConnectorError> {
        let _guard = self.lock.lock().expect("allowlist lock poisoned");
        let mut record = self.read_record(account_id_hex)?;
        record
            .welcomer_account_ids_hex
            .retain(|existing| existing != welcomer_account_id_hex);
        normalize_allowlist(&mut record.welcomer_account_ids_hex);
        self.write_record(&record)?;
        Ok(record.welcomer_account_ids_hex)
    }

    fn contains(
        &self,
        account_id_hex: &str,
        welcomer_account_id_hex: &str,
    ) -> Result<bool, ConnectorError> {
        Ok(self
            .list(account_id_hex)?
            .iter()
            .any(|existing| existing == welcomer_account_id_hex))
    }

    fn read_record(&self, account_id_hex: &str) -> Result<AllowlistRecord, ConnectorError> {
        let path = self.record_path(account_id_hex);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(AllowlistRecord {
                account_id_hex: account_id_hex.to_owned(),
                welcomer_account_ids_hex: Vec::new(),
            }),
            Err(err) => Err(err.into()),
        }
    }

    fn write_record(&self, record: &AllowlistRecord) -> Result<(), ConnectorError> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let path = self.record_path(&record.account_id_hex);
        std::fs::write(&path, serde_json::to_vec_pretty(record)?)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    fn record_path(&self, account_id_hex: &str) -> PathBuf {
        self.dir.join(format!("{account_id_hex}.json"))
    }
}

fn normalize_allowlist(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[derive(Clone, Default)]
struct StreamSessionStore {
    sessions: Arc<Mutex<HashMap<String, ActiveStreamSession>>>,
}

#[derive(Clone)]
struct ActiveStreamSession {
    account_label: String,
    group_id: GroupId,
    stream_id: Vec<u8>,
    start_message_id_hex: String,
    tx: mpsc::Sender<StreamComposeCommand>,
    abort: tokio::task::AbortHandle,
}

impl StreamSessionStore {
    fn insert(&self, stream_id_hex: String, session: ActiveStreamSession) {
        let mut sessions = self.sessions.lock().expect("stream session lock poisoned");
        if let Some(previous) = sessions.insert(stream_id_hex, session) {
            let _ = previous.tx.try_send(StreamComposeCommand::Cancel);
            previous.abort.abort();
        }
    }

    fn get(&self, stream_id_hex: &str) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        self.sessions
            .lock()
            .expect("stream session lock poisoned")
            .get(&stream_id_hex)
            .cloned()
            .ok_or_else(|| {
                ConnectorError::Stream(format!("no active stream session for {stream_id_hex}"))
            })
    }

    fn remove(&self, stream_id_hex: &str) -> Result<ActiveStreamSession, ConnectorError> {
        let stream_id_hex = normalize_hex(stream_id_hex)?;
        self.sessions
            .lock()
            .expect("stream session lock poisoned")
            .remove(&stream_id_hex)
            .ok_or_else(|| {
                ConnectorError::Stream(format!("no active stream session for {stream_id_hex}"))
            })
    }
}

#[derive(Clone, Debug)]
struct ParsedQuicCandidate {
    original: String,
    authority: String,
    server_name: String,
}

fn first_quic_candidate(candidates: &[String]) -> Result<String, ConnectorError> {
    candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .map(|candidate| candidate.trim().to_owned())
        .ok_or_else(|| ConnectorError::Stream("stream begin requires a quic:// candidate".into()))
}

fn parse_quic_candidate(candidate: &str) -> Result<ParsedQuicCandidate, ConnectorError> {
    let trimmed = candidate.trim();
    let Some(rest) = trimmed.strip_prefix("quic://") else {
        return Err(ConnectorError::Stream(format!(
            "invalid QUIC candidate: {trimmed}"
        )));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.is_empty() {
        return Err(ConnectorError::Stream(format!(
            "invalid QUIC candidate: {trimmed}"
        )));
    }
    let server_name = candidate_server_name(authority)?;
    Ok(ParsedQuicCandidate {
        original: trimmed.to_owned(),
        authority: authority.to_owned(),
        server_name,
    })
}

async fn resolve_quic_candidate_addr(
    candidate: &ParsedQuicCandidate,
) -> Result<SocketAddr, ConnectorError> {
    let mut addrs = tokio::net::lookup_host(&candidate.authority)
        .await
        .map_err(|err| {
            ConnectorError::Stream(format!(
                "failed to resolve QUIC candidate {}: {err}",
                candidate.original
            ))
        })?;
    addrs.next().ok_or_else(|| {
        ConnectorError::Stream(format!("invalid QUIC candidate: {}", candidate.original))
    })
}

fn candidate_server_name(authority: &str) -> Result<String, ConnectorError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, _)) = rest.split_once(']') else {
            return Err(ConnectorError::Stream(format!(
                "invalid QUIC candidate authority: {authority}"
            )));
        };
        return Ok(host.to_owned());
    }
    authority
        .rsplit_once(':')
        .map(|(host, _)| host.to_owned())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            ConnectorError::Stream(format!("invalid QUIC candidate authority: {authority}"))
        })
}

fn broker_trust_for_addr(broker_addr: SocketAddr) -> BrokerServerTrust {
    if broker_addr.ip().is_loopback() {
        BrokerServerTrust::InsecureLocal
    } else {
        BrokerServerTrust::Platform
    }
}

fn transcript_hash_from_hex(value: &str) -> Result<[u8; 32], ConnectorError> {
    let bytes = hex::decode(normalize_hex(value)?)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| ConnectorError::Stream(format!("invalid transcript hash length: {actual}")))
}

fn normalize_hex(value: &str) -> Result<String, ConnectorError> {
    Ok(hex::encode(hex::decode(value)?))
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error(transparent)]
    AccountHome(#[from] AccountHomeError),
    #[error(transparent)]
    App(#[from] AppError),
    #[error(transparent)]
    Control(#[from] AgentControlError),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("debug controls are disabled")]
    DebugControlsDisabled,
    #[error("agent stream error: {0}")]
    Stream(String),
}

impl ConnectorError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AccountHome(_) => "account_home_error",
            Self::App(_) => "app_error",
            Self::Control(_) => "control_error",
            Self::Hex(_) => "invalid_hex",
            Self::Json(_) => "json_error",
            Self::Io(_) => "io_error",
            Self::DebugControlsDisabled => "debug_controls_disabled",
            Self::Stream(_) => "stream_error",
        }
    }

    pub fn client_message(&self) -> &'static str {
        match self {
            Self::DebugControlsDisabled => "debug controls are disabled",
            Self::Hex(_) => "invalid hex value",
            Self::Json(_) | Self::Control(_) => "invalid control request",
            Self::Stream(_) => "agent stream request failed",
            Self::Io(_) => "connector I/O failed",
            Self::AccountHome(_) | Self::App(_) => "connector request failed",
        }
    }

    pub fn privacy_safe_code(&self) -> &'static str {
        self.code()
    }
}

pub fn default_socket_path(home: &Path) -> PathBuf {
    home.join("dev").join("dm-agent.sock")
}

pub fn bind_connector_socket(socket: &Path) -> Result<UnixListener, ConnectorError> {
    if let Some(parent) = socket.parent() {
        prepare_socket_dir(parent)?;
    }
    let listener = UnixListener::bind(socket)?;
    harden_socket_permissions(socket)?;
    Ok(listener)
}

fn prepare_socket_dir(parent: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(
        parent,
        std::fs::Permissions::from_mode(AGENT_SOCKET_DIR_MODE),
    )
}

fn harden_socket_permissions(socket: &Path) -> std::io::Result<()> {
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(AGENT_SOCKET_MODE))
}

fn authorize_connector_peer(stream: &UnixStream) -> std::io::Result<()> {
    let peer_uid = stream.peer_cred()?.uid();
    let server_uid = current_effective_uid();
    if peer_uid == server_uid {
        Ok(())
    } else {
        Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "agent connector peer UID does not match server UID",
        ))
    }
}

fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

fn endpoint(url: &str) -> cgka_traits::TransportEndpoint {
    cgka_traits::TransportEndpoint(url.to_owned())
}

#[cfg(test)]
mod tests {
    use agent_control::{
        AgentControlEnvelope, AgentControlEvent, AgentControlRequest, AgentControlResponse,
        read_envelope, write_frame,
    };
    use cgka_traits::MessageId;
    use cgka_traits::agent_text_stream::{
        AGENT_TEXT_STREAM_RECORD_STATUS, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA,
        AgentTextStreamTranscriptV1,
    };
    use marmot_account::AccountHome;
    use marmot_app::{AccountSetupRequest, MarmotApp, MarmotAppRuntime};
    use nostr_relay_builder::MockRelay;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use tokio::io::BufReader;
    use tokio::net::UnixStream;
    use tokio::time::{Duration, sleep, timeout};

    use crate::{AgentConnector, AgentConnectorConfig, bind_connector_socket, serve_socket};

    const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

    #[tokio::test]
    async fn connector_socket_serves_account_list() {
        let dir = tempfile::tempdir().unwrap();
        let account_home = AccountHome::open(dir.path());
        let account = account_home.create_account("agent").unwrap();
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: Vec::new(),
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();
        assert_eq!(
            socket
                .parent()
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            socket.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
        let server = tokio::spawn(async move { connector.serve_once(&listener).await });

        let client = UnixStream::connect(&socket).await.unwrap();
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_read = BufReader::new(client_read);
        let request = AgentControlEnvelope::request(
            Some("req-accounts".to_owned()),
            AgentControlRequest::AccountList,
        );
        write_frame(&mut client_write, &request).await.unwrap();

        let response: AgentControlEnvelope<AgentControlResponse> =
            read_envelope(&mut client_read).await.unwrap().unwrap();
        assert_eq!(response.id.as_deref(), Some("req-accounts"));
        let AgentControlResponse::AccountList { accounts } = response.payload else {
            panic!("expected account list response");
        };
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id_hex, account.account_id_hex);
        assert_eq!(accounts[0].label, "agent");
        assert!(accounts[0].local_signing);

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connector_socket_subscribes_to_inbound_messages() {
        let dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
        let setup_runtime = MarmotAppRuntime::new(app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
        let human = setup_runtime.create_identity(setup).await.unwrap();
        let group_id = setup_runtime
            .create_group(
                &agent.account.account_id_hex,
                "agent inbound",
                std::slice::from_ref(&human.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        setup_runtime.shutdown().await;

        let group_id_hex = hex::encode(group_id.as_slice());
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let server = tokio::spawn(serve_socket(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: false,
            debug_controls: false,
        }));

        let subscriber = connect_with_retry(&socket).await;
        let (subscriber_read, mut subscriber_write) = tokio::io::split(subscriber);
        let mut subscriber_read = BufReader::new(subscriber_read);
        let subscribe = AgentControlEnvelope::request(
            Some("req-subscribe".to_owned()),
            AgentControlRequest::SubscribeInbound {
                account_id_hex: Some(agent.account.account_id_hex.clone()),
                group_id_hex: Some(group_id_hex.clone()),
            },
        );
        write_frame(&mut subscriber_write, &subscribe)
            .await
            .unwrap();
        let ack: AgentControlEnvelope<AgentControlResponse> = timeout(
            CONTROL_RESPONSE_TIMEOUT,
            read_envelope(&mut subscriber_read),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(ack.id.as_deref(), Some("req-subscribe"));
        assert_eq!(ack.payload, AgentControlResponse::Ack);

        let sender = connect_with_retry(&socket).await;
        let (sender_read, mut sender_write) = tokio::io::split(sender);
        let mut sender_read = BufReader::new(sender_read);
        let send = AgentControlEnvelope::request(
            Some("req-human-final".to_owned()),
            AgentControlRequest::SendFinal {
                account_id_hex: human.account.account_id_hex.clone(),
                group_id_hex: group_id_hex.clone(),
                text: "hello agent".to_owned(),
                reply_to_message_id_hex: None,
            },
        );
        write_frame(&mut sender_write, &send).await.unwrap();
        let sent: AgentControlEnvelope<AgentControlResponse> =
            timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(&mut sender_read))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert!(matches!(
            sent.payload,
            AgentControlResponse::FinalSent { .. }
        ));

        let inbound = read_matching_inbound_message(&mut subscriber_read, "hello agent").await;
        assert_eq!(inbound.id.as_deref(), Some("req-subscribe"));
        let AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex: event_group_id_hex,
            sender_account_id_hex,
            text,
            ..
        } = inbound.payload
        else {
            panic!("expected inbound message event");
        };
        assert_eq!(account_id_hex, agent.account.account_id_hex);
        assert_eq!(event_group_id_hex, group_id_hex);
        assert_eq!(sender_account_id_hex, human.account.account_id_hex);
        assert_eq!(text, "hello agent");

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn connector_debug_controls_inject_inbound_and_record_final_sends() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let account_id_hex = "11".repeat(32);
        let group_id_hex = "22".repeat(32);
        let message_id_hex = "33".repeat(32);
        let sender_account_id_hex = "44".repeat(32);
        let server = tokio::spawn(serve_socket(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: Vec::new(),
            allow_any: false,
            debug_controls: true,
        }));

        let subscriber = connect_with_retry(&socket).await;
        let (subscriber_read, mut subscriber_write) = tokio::io::split(subscriber);
        let mut subscriber_read = BufReader::new(subscriber_read);
        let subscribe = AgentControlEnvelope::request(
            Some("req-debug-subscribe".to_owned()),
            AgentControlRequest::SubscribeInbound {
                account_id_hex: Some(account_id_hex.clone()),
                group_id_hex: Some(group_id_hex.clone()),
            },
        );
        write_frame(&mut subscriber_write, &subscribe)
            .await
            .unwrap();
        let ack: AgentControlEnvelope<AgentControlResponse> = timeout(
            CONTROL_RESPONSE_TIMEOUT,
            read_envelope(&mut subscriber_read),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(ack.payload, AgentControlResponse::Ack);

        let injected = send_control_request(
            &socket,
            "req-debug-inject",
            AgentControlRequest::DebugInjectInbound {
                account_id_hex: account_id_hex.clone(),
                group_id_hex: group_id_hex.clone(),
                message_id_hex: message_id_hex.clone(),
                sender_account_id_hex: sender_account_id_hex.clone(),
                text: "ping from connector".to_owned(),
            },
        )
        .await;
        assert_eq!(injected.payload, AgentControlResponse::Ack);

        let inbound =
            read_matching_inbound_message(&mut subscriber_read, "ping from connector").await;
        let AgentControlEvent::InboundMessage {
            account_id_hex: event_account_id_hex,
            group_id_hex: event_group_id_hex,
            message_id_hex: event_message_id_hex,
            sender_account_id_hex: event_sender_account_id_hex,
            text,
        } = inbound.payload
        else {
            panic!("expected debug inbound message event");
        };
        assert_eq!(event_account_id_hex, account_id_hex);
        assert_eq!(event_group_id_hex, group_id_hex);
        assert_eq!(event_message_id_hex, message_id_hex);
        assert_eq!(event_sender_account_id_hex, sender_account_id_hex);
        assert_eq!(text, "ping from connector");

        let sent = send_control_request(
            &socket,
            "req-debug-final",
            AgentControlRequest::SendFinal {
                account_id_hex: account_id_hex.clone(),
                group_id_hex: group_id_hex.clone(),
                text: "marmot-e2e-ok: ping from connector".to_owned(),
                reply_to_message_id_hex: Some(message_id_hex.clone()),
            },
        )
        .await;
        let AgentControlResponse::FinalSent { message_ids_hex } = sent.payload else {
            panic!("expected debug final sent response");
        };
        assert_eq!(message_ids_hex, vec![format!("{:064x}", 1)]);

        let recorded = send_control_request(
            &socket,
            "req-debug-finals",
            AgentControlRequest::DebugRecordedFinals,
        )
        .await;
        let AgentControlResponse::DebugRecordedFinals { sends } = recorded.payload else {
            panic!("expected recorded debug finals");
        };
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].account_id_hex, account_id_hex);
        assert_eq!(sends[0].group_id_hex, group_id_hex);
        assert_eq!(
            sends[0].text,
            "marmot-e2e-ok: ping from connector".to_owned()
        );
        assert_eq!(
            sends[0].reply_to_message_id_hex.as_deref(),
            Some(message_id_hex.as_str())
        );
        assert_eq!(sends[0].message_ids_hex, vec![format!("{:064x}", 1)]);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn connector_debug_controls_are_disabled_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: Vec::new(),
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();

        let response = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-debug-disabled",
            AgentControlRequest::DebugRecordedFinals,
        )
        .await;
        let AgentControlResponse::Error { code, .. } = response.payload else {
            panic!("expected debug controls disabled error");
        };
        assert_eq!(code, "debug_controls_disabled");
    }

    #[tokio::test]
    async fn connector_socket_updates_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let account_home = AccountHome::open(dir.path());
        let agent = account_home.create_account("agent").unwrap();
        let welcomer = account_home.create_account("welcomer").unwrap();
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: Vec::new(),
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();

        let added = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-allow-add",
            AgentControlRequest::AllowlistAdd {
                account_id_hex: agent.account_id_hex.clone(),
                welcomer_account_id_hex: welcomer.account_id_hex.clone(),
            },
        )
        .await;
        assert_allowlist(
            added,
            "req-allow-add",
            &agent.account_id_hex,
            &[welcomer.account_id_hex.as_str()],
        );

        let listed = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-allow-list",
            AgentControlRequest::AllowlistList {
                account_id_hex: agent.account_id_hex.clone(),
            },
        )
        .await;
        assert_allowlist(
            listed,
            "req-allow-list",
            &agent.account_id_hex,
            &[welcomer.account_id_hex.as_str()],
        );

        let removed = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-allow-remove",
            AgentControlRequest::AllowlistRemove {
                account_id_hex: agent.account_id_hex.clone(),
                welcomer_account_id_hex: welcomer.account_id_hex.clone(),
            },
        )
        .await;
        assert_allowlist(removed, "req-allow-remove", &agent.account_id_hex, &[]);
    }

    #[tokio::test]
    async fn connector_policy_accepts_allowed_welcomer() {
        let agent_dir = tempfile::tempdir().unwrap();
        let human_dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let agent_app = MarmotApp::with_relay(agent_dir.path(), relay_url.clone());
        let human_app = MarmotApp::with_relay(human_dir.path(), relay_url.clone());
        let agent_setup_runtime = MarmotAppRuntime::new(agent_app.clone());
        let human_runtime = MarmotAppRuntime::new(human_app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = agent_setup_runtime
            .create_identity(setup.clone())
            .await
            .unwrap();
        let human = human_runtime.create_identity(setup).await.unwrap();
        agent_setup_runtime.shutdown().await;

        let socket = agent_dir.path().join("dev").join("dm-agent.sock");
        let server = tokio::spawn(serve_socket(AgentConnectorConfig {
            home: agent_dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: false,
            debug_controls: false,
        }));
        let added = send_control_request(
            &socket,
            "req-allow-human",
            AgentControlRequest::AllowlistAdd {
                account_id_hex: agent.account.account_id_hex.clone(),
                welcomer_account_id_hex: human.account.account_id_hex.clone(),
            },
        )
        .await;
        assert_allowlist(
            added,
            "req-allow-human",
            &agent.account.account_id_hex,
            &[human.account.account_id_hex.as_str()],
        );

        let group_id = human_runtime
            .create_group(
                &human.account.account_id_hex,
                "allowed invite",
                std::slice::from_ref(&agent.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        let group_id_hex = hex::encode(group_id.as_slice());
        wait_for_group_state(&agent_app, &agent.account.label, &group_id_hex, |group| {
            !group.pending_confirmation && !group.archived
        })
        .await;

        human_runtime.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn connector_policy_declines_unlisted_welcomer() {
        let agent_dir = tempfile::tempdir().unwrap();
        let human_dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let agent_app = MarmotApp::with_relay(agent_dir.path(), relay_url.clone());
        let human_app = MarmotApp::with_relay(human_dir.path(), relay_url.clone());
        let agent_setup_runtime = MarmotAppRuntime::new(agent_app.clone());
        let human_runtime = MarmotAppRuntime::new(human_app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = agent_setup_runtime
            .create_identity(setup.clone())
            .await
            .unwrap();
        let human = human_runtime.create_identity(setup).await.unwrap();
        agent_setup_runtime.shutdown().await;

        let socket = agent_dir.path().join("dev").join("dm-agent.sock");
        let server = tokio::spawn(serve_socket(AgentConnectorConfig {
            home: agent_dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: false,
            debug_controls: false,
        }));
        assert!(matches!(
            send_control_request(&socket, "req-ready", AgentControlRequest::AccountList)
                .await
                .payload,
            AgentControlResponse::AccountList { .. }
        ));

        let group_id = human_runtime
            .create_group(
                &human.account.account_id_hex,
                "unlisted invite",
                std::slice::from_ref(&agent.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        let group_id_hex = hex::encode(group_id.as_slice());
        wait_for_group_state(&agent_app, &agent.account.label, &group_id_hex, |group| {
            !group.pending_confirmation && group.archived
        })
        .await;

        human_runtime.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn connector_policy_allow_any_accepts_unlisted_welcomer() {
        let agent_dir = tempfile::tempdir().unwrap();
        let human_dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let agent_app = MarmotApp::with_relay(agent_dir.path(), relay_url.clone());
        let human_app = MarmotApp::with_relay(human_dir.path(), relay_url.clone());
        let agent_setup_runtime = MarmotAppRuntime::new(agent_app.clone());
        let human_runtime = MarmotAppRuntime::new(human_app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = agent_setup_runtime
            .create_identity(setup.clone())
            .await
            .unwrap();
        let human = human_runtime.create_identity(setup).await.unwrap();
        agent_setup_runtime.shutdown().await;

        let socket = agent_dir.path().join("dev").join("dm-agent.sock");
        let server = tokio::spawn(serve_socket(AgentConnectorConfig {
            home: agent_dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: true,
            debug_controls: false,
        }));
        assert!(matches!(
            send_control_request(&socket, "req-ready", AgentControlRequest::AccountList)
                .await
                .payload,
            AgentControlResponse::AccountList { .. }
        ));

        let group_id = human_runtime
            .create_group(
                &human.account.account_id_hex,
                "allow any invite",
                std::slice::from_ref(&agent.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        let group_id_hex = hex::encode(group_id.as_slice());
        wait_for_group_state(&agent_app, &agent.account.label, &group_id_hex, |group| {
            !group.pending_confirmation && !group.archived
        })
        .await;

        human_runtime.shutdown().await;
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn connector_socket_creates_local_account() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: Vec::new(),
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();
        let server = tokio::spawn(async move { connector.serve_once(&listener).await });

        let client = UnixStream::connect(&socket).await.unwrap();
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_read = BufReader::new(client_read);
        let request = AgentControlEnvelope::request(
            Some("req-create".to_owned()),
            AgentControlRequest::AccountCreate {
                label: Some("agent".to_owned()),
                publish_key_package: false,
            },
        );
        write_frame(&mut client_write, &request).await.unwrap();

        let response: AgentControlEnvelope<AgentControlResponse> =
            read_envelope(&mut client_read).await.unwrap().unwrap();
        assert_eq!(response.id.as_deref(), Some("req-create"));
        let AgentControlResponse::AccountCreated { account } = response.payload else {
            panic!("expected account created response");
        };
        assert_eq!(account.label, "agent");
        assert!(account.local_signing);

        let stored = AccountHome::open(dir.path()).account("agent").unwrap();
        assert_eq!(stored.account_id_hex, account.account_id_hex);

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connector_socket_publishes_key_package() {
        let dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let account_home = AccountHome::open(dir.path());
        let account = account_home.create_account("agent").unwrap();
        let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url.clone()],
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();
        let server = tokio::spawn(async move { connector.serve_once(&listener).await });

        let client = UnixStream::connect(&socket).await.unwrap();
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_read = BufReader::new(client_read);
        let request = AgentControlEnvelope::request(
            Some("req-publish".to_owned()),
            AgentControlRequest::AccountPublishKeyPackage {
                account_id_hex: account.account_id_hex.clone(),
            },
        );
        write_frame(&mut client_write, &request).await.unwrap();

        let response: AgentControlEnvelope<AgentControlResponse> =
            read_envelope(&mut client_read).await.unwrap().unwrap();
        assert_eq!(response.id.as_deref(), Some("req-publish"));
        let AgentControlResponse::KeyPackagePublished {
            account_id_hex,
            key_package_bytes,
        } = response.payload.clone()
        else {
            panic!(
                "expected key package published response, got {:?}",
                response.payload
            );
        };
        assert_eq!(account_id_hex, account.account_id_hex);
        assert!(key_package_bytes > 0);
        let fetched = app
            .fetch_latest_key_package_for_account_id(
                &account.account_id_hex,
                vec![crate::endpoint(&relay_url)],
            )
            .await
            .unwrap();
        assert_eq!(key_package_bytes, fetched.key_package.bytes().len());

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connector_start_publishes_key_package_for_existing_local_account() {
        let dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let account_home = AccountHome::open(dir.path());
        let account = account_home.create_account("agent").unwrap();
        let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: dir.path().join("dev").join("dm-agent.sock"),
            relays: vec![relay_url.clone()],
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();

        connector.start().await.unwrap();

        let fetched = app
            .fetch_latest_key_package_for_account_id(
                &account.account_id_hex,
                vec![crate::endpoint(&relay_url)],
            )
            .await
            .unwrap();
        assert!(!fetched.key_package.bytes().is_empty());

        connector.runtime.shutdown().await;
    }

    #[tokio::test]
    async fn connector_socket_sends_final_message() {
        let dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
        let setup_runtime = MarmotAppRuntime::new(app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
        let human = setup_runtime.create_identity(setup).await.unwrap();
        let group_id = setup_runtime
            .create_group(
                &agent.account.account_id_hex,
                "agent final",
                std::slice::from_ref(&human.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        setup_runtime.shutdown().await;

        let group_id_hex = hex::encode(group_id.as_slice());
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();
        let server = tokio::spawn(async move { connector.serve_once(&listener).await });

        let client = UnixStream::connect(&socket).await.unwrap();
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_read = BufReader::new(client_read);
        let request = AgentControlEnvelope::request(
            Some("req-final".to_owned()),
            AgentControlRequest::SendFinal {
                account_id_hex: agent.account.account_id_hex,
                group_id_hex,
                text: "final answer".to_owned(),
                reply_to_message_id_hex: None,
            },
        );
        write_frame(&mut client_write, &request).await.unwrap();

        let response: AgentControlEnvelope<AgentControlResponse> =
            read_envelope(&mut client_read).await.unwrap().unwrap();
        assert_eq!(response.id.as_deref(), Some("req-final"));
        let AgentControlResponse::FinalSent { message_ids_hex } = response.payload else {
            panic!("expected final sent response");
        };
        assert_eq!(message_ids_hex.len(), 1);
        assert!(!message_ids_hex[0].is_empty());

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connector_socket_composes_and_finalizes_stream() {
        let dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
        let setup_runtime = MarmotAppRuntime::new(app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
        let human = setup_runtime.create_identity(setup).await.unwrap();
        let group_id = setup_runtime
            .create_group(
                &agent.account.account_id_hex,
                "agent stream",
                std::slice::from_ref(&human.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        setup_runtime.shutdown().await;

        let group_id_hex = hex::encode(group_id.as_slice());
        let stream_id_hex = hex::encode([0x77; 32]);
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();

        let begun = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-begin",
            AgentControlRequest::StreamBegin {
                account_id_hex: agent.account.account_id_hex.clone(),
                group_id_hex: group_id_hex.clone(),
                stream_id_hex: Some(stream_id_hex.clone()),
                quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
            },
        )
        .await;
        let AgentControlResponse::StreamBegun {
            stream_id_hex: begun_stream_id_hex,
            start_message_id_hex,
            quic_candidates,
        } = begun.payload
        else {
            panic!("expected stream begun response");
        };
        assert_eq!(begun_stream_id_hex, stream_id_hex);
        assert_eq!(quic_candidates, vec!["quic://127.0.0.1:9"]);

        let appended = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-append",
            AgentControlRequest::StreamAppend {
                stream_id_hex: stream_id_hex.clone(),
                append_text: "hello stream".to_owned(),
            },
        )
        .await;
        assert_eq!(appended.payload, AgentControlResponse::Ack);

        let status = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-status",
            AgentControlRequest::StreamStatus {
                stream_id_hex: stream_id_hex.clone(),
                status: "thinking".to_owned(),
            },
        )
        .await;
        assert_eq!(status.payload, AgentControlResponse::Ack);

        let transcript_hash_hex = expected_stream_transcript_hash(
            &stream_id_hex,
            &start_message_id_hex,
            &[
                (AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, "hello stream"),
                (AGENT_TEXT_STREAM_RECORD_STATUS, "thinking"),
            ],
        );
        let finalized = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-finalize",
            AgentControlRequest::StreamFinalize {
                stream_id_hex: stream_id_hex.clone(),
                final_text: "hello stream".to_owned(),
                transcript_hash_hex,
                chunk_count: 2,
            },
        )
        .await;
        let AgentControlResponse::StreamFinalized {
            stream_id_hex: finalized_stream_id_hex,
            message_ids_hex,
        } = finalized.payload
        else {
            panic!("expected stream finalized response");
        };
        assert_eq!(finalized_stream_id_hex, stream_id_hex);
        assert_eq!(message_ids_hex.len(), 1);
        assert!(!message_ids_hex[0].is_empty());
    }

    #[tokio::test]
    async fn connector_socket_cancels_stream_session() {
        let dir = tempfile::tempdir().unwrap();
        let relay = MockRelay::run().await.unwrap();
        let relay_url = relay.url().await.to_string();
        let app = MarmotApp::with_relay(dir.path(), relay_url.clone());
        let setup_runtime = MarmotAppRuntime::new(app);
        let setup = AccountSetupRequest {
            default_relays: vec![crate::endpoint(&relay_url)],
            bootstrap_relays: vec![crate::endpoint(&relay_url)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        };
        let agent = setup_runtime.create_identity(setup.clone()).await.unwrap();
        let human = setup_runtime.create_identity(setup).await.unwrap();
        let group_id = setup_runtime
            .create_group(
                &agent.account.account_id_hex,
                "agent cancelled stream",
                std::slice::from_ref(&human.account.account_id_hex),
                None,
            )
            .await
            .unwrap();
        setup_runtime.shutdown().await;

        let group_id_hex = hex::encode(group_id.as_slice());
        let stream_id_hex = hex::encode([0x88; 32]);
        let socket = dir.path().join("dev").join("dm-agent.sock");
        let connector = AgentConnector::open(AgentConnectorConfig {
            home: dir.path().to_path_buf(),
            socket: socket.clone(),
            relays: vec![relay_url],
            allow_any: false,
            debug_controls: false,
        })
        .unwrap();
        let listener = bind_connector_socket(&socket).unwrap();

        let begun = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-begin-cancel",
            AgentControlRequest::StreamBegin {
                account_id_hex: agent.account.account_id_hex,
                group_id_hex,
                stream_id_hex: Some(stream_id_hex.clone()),
                quic_candidates: vec!["quic://127.0.0.1:9".to_owned()],
            },
        )
        .await;
        assert!(matches!(
            begun.payload,
            AgentControlResponse::StreamBegun { .. }
        ));

        let status = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-status",
            AgentControlRequest::StreamStatus {
                stream_id_hex: stream_id_hex.clone(),
                status: "thinking".to_owned(),
            },
        )
        .await;
        assert_eq!(status.payload, AgentControlResponse::Ack);

        let cancelled = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-cancel",
            AgentControlRequest::StreamCancel {
                stream_id_hex: stream_id_hex.clone(),
                reason: Some("gateway_replaced_text".to_owned()),
            },
        )
        .await;
        assert_eq!(cancelled.payload, AgentControlResponse::Ack);

        let append_after_cancel = serve_control_request_once(
            &connector,
            &listener,
            &socket,
            "req-stream-append-after-cancel",
            AgentControlRequest::StreamAppend {
                stream_id_hex,
                append_text: "late".to_owned(),
            },
        )
        .await;
        let AgentControlResponse::Error { code, .. } = append_after_cancel.payload else {
            panic!("expected append-after-cancel error");
        };
        assert_eq!(code, "stream_error");
    }

    async fn connect_with_retry(socket: &Path) -> UnixStream {
        for _ in 0..100 {
            match UnixStream::connect(socket).await {
                Ok(stream) => return stream,
                Err(_) => sleep(Duration::from_millis(20)).await,
            }
        }
        UnixStream::connect(socket).await.unwrap()
    }

    async fn send_control_request(
        socket: &Path,
        id: &str,
        request: AgentControlRequest,
    ) -> AgentControlEnvelope<AgentControlResponse> {
        let client = connect_with_retry(socket).await;
        let (client_read, mut client_write) = tokio::io::split(client);
        let mut client_read = BufReader::new(client_read);
        let request = AgentControlEnvelope::request(Some(id.to_owned()), request);
        write_frame(&mut client_write, &request).await.unwrap();
        timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(&mut client_read))
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    async fn serve_control_request_once(
        connector: &AgentConnector,
        listener: &tokio::net::UnixListener,
        socket: &Path,
        id: &str,
        request: AgentControlRequest,
    ) -> AgentControlEnvelope<AgentControlResponse> {
        let (server, response) = tokio::join!(
            connector.serve_once(listener),
            send_control_request(socket, id, request)
        );
        server.unwrap();
        response
    }

    fn assert_allowlist(
        response: AgentControlEnvelope<AgentControlResponse>,
        expected_id: &str,
        expected_account_id_hex: &str,
        expected_welcomer_account_ids_hex: &[&str],
    ) {
        assert_eq!(response.id.as_deref(), Some(expected_id));
        let AgentControlResponse::Allowlist {
            account_id_hex,
            welcomer_account_ids_hex,
        } = response.payload
        else {
            panic!("expected allowlist response");
        };
        assert_eq!(account_id_hex, expected_account_id_hex);
        assert_eq!(
            welcomer_account_ids_hex,
            expected_welcomer_account_ids_hex
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        );
    }

    fn expected_stream_transcript_hash(
        stream_id_hex: &str,
        start_message_id_hex: &str,
        records: &[(u8, &str)],
    ) -> String {
        let stream_id = hex::decode(stream_id_hex).unwrap();
        let start_event_id = MessageId::new(hex::decode(start_message_id_hex).unwrap());
        let mut transcript = AgentTextStreamTranscriptV1::new(stream_id, start_event_id);
        for (seq, (record_type, text)) in (1_u64..).zip(records.iter()) {
            transcript.append(seq, *record_type, text.as_bytes());
        }
        hex::encode(transcript.hash())
    }

    async fn wait_for_group_state<F>(
        app: &MarmotApp,
        account_label: &str,
        group_id_hex: &str,
        mut predicate: F,
    ) where
        F: FnMut(&marmot_app::AppGroupRecord) -> bool,
    {
        timeout(Duration::from_secs(30), async {
            loop {
                if let Some(group) = app.group(account_label, group_id_hex).unwrap()
                    && predicate(&group)
                {
                    return;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn read_matching_inbound_message<R>(
        reader: &mut R,
        expected_text: &str,
    ) -> AgentControlEnvelope<AgentControlEvent>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        for _ in 0..10 {
            let event: AgentControlEnvelope<AgentControlEvent> =
                timeout(CONTROL_RESPONSE_TIMEOUT, read_envelope(reader))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            if matches!(
                &event.payload,
                AgentControlEvent::InboundMessage { text, .. } if text == expected_text
            ) {
                return event;
            }
        }
        panic!("expected inbound message event with text {expected_text:?}");
    }
}
