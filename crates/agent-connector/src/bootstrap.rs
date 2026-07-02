//! Bootstrap a local Marmot agent account through a running `dm-agent` control socket.

use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_control::{
    AgentControlAccount, AgentControlEnvelope, AgentControlError, AgentControlRequest,
    AgentControlResponse, encode_frame, read_envelope,
};
use marmot_app::{nprofile_for_account_id, npub_for_account_id, validate_relay_urls};
use rand::RngCore;
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};

pub const DEFAULT_BOOTSTRAP_LABEL: &str = "hermes-agent";
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.eu.whitenoise.chat",
    "wss://relay.us.whitenoise.chat",
];
pub const DEFAULT_QUIC_CANDIDATE: &str = "quic://quic-broker.ipf.dev:4450";

#[derive(Clone, Debug)]
pub struct BootstrapOptions {
    pub home: PathBuf,
    pub socket: PathBuf,
    pub label: String,
    pub account_id_hex: Option<String>,
    pub auth_token: Option<String>,
    pub relays: Vec<String>,
    pub quic_candidates: Vec<String>,
    pub create_if_missing: bool,
    pub publish_key_package: bool,
    pub wait_for_socket: Duration,
    pub request_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootstrapResult {
    pub account_id_hex: String,
    pub label: String,
    pub local_signing: bool,
    pub created: bool,
    pub key_package_published: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_package_bytes: Option<usize>,
    pub socket: String,
    pub relays: Vec<String>,
    pub quic_candidates: Vec<String>,
    pub npub: String,
    pub nprofile: String,
    pub qr_payload: String,
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("invalid account pubkey hex: {0}")]
    InvalidAccountIdHex(String),
    #[error("invalid account pubkey length: expected 32 bytes, got {0}")]
    InvalidAccountIdLength(usize),
    #[error("auth token file not found: {0}")]
    AuthTokenFileNotFound(PathBuf),
    #[error("{0} is empty")]
    EmptyAuthToken(String),
    #[error("dm-agent socket not found: {0}")]
    SocketNotFound(PathBuf),
    #[error("no local signing agent account found")]
    NoLocalSigningAccount,
    #[error("local signing account not found: {0}")]
    AccountNotFound(String),
    #[error("multiple local signing accounts use label {0:?}; pass --account-id-hex")]
    MultipleAccountsForLabel(String),
    #[error("multiple local signing accounts exist; pass --account-id-hex ({0})")]
    MultipleAccounts(String),
    #[error("expected {expected} response, got {actual}")]
    UnexpectedResponse {
        expected: &'static str,
        actual: String,
    },
    #[error("control response id mismatch")]
    ResponseIdMismatch,
    #[error("key package published for unexpected account: expected {expected}, got {actual}")]
    KeyPackageAccountMismatch { expected: String, actual: String },
    #[error("{code}: {message}")]
    ControlRejected { code: String, message: String },
    #[error(transparent)]
    Control(#[from] AgentControlError),
    #[error(transparent)]
    App(#[from] marmot_app::AppError),
    #[error("bootstrap request timed out")]
    RequestTimedOut,
}

pub async fn run_bootstrap(options: BootstrapOptions) -> Result<BootstrapResult, BootstrapError> {
    validate_relay_urls(&options.relays)?;
    wait_for_socket(&options.socket, options.wait_for_socket).await?;
    let client = ControlClient::new(
        options.socket.clone(),
        options.auth_token.clone(),
        options.request_timeout,
    );

    let account_state = bootstrap_agent_account(
        &client,
        BootstrapAccountOptions {
            label: options.label.clone(),
            account_id_hex: options.account_id_hex.clone(),
            create_if_missing: options.create_if_missing,
            publish_key_package: options.publish_key_package,
        },
    )
    .await?;

    let npub = npub_for_account_id(&account_state.account_id_hex)?;
    let nprofile = nprofile_for_account_id(&account_state.account_id_hex, &options.relays)?;
    let result = BootstrapResult {
        account_id_hex: account_state.account_id_hex.clone(),
        label: account_state.label.clone(),
        local_signing: account_state.local_signing,
        created: account_state.created,
        key_package_published: options.publish_key_package,
        key_package_bytes: account_state.key_package_bytes,
        socket: options.socket.display().to_string(),
        relays: options.relays.clone(),
        quic_candidates: options.quic_candidates.clone(),
        npub,
        nprofile: nprofile.clone(),
        qr_payload: nprofile,
    };

    Ok(result)
}

#[derive(Clone, Debug)]
struct BootstrapAccountOptions {
    label: String,
    account_id_hex: Option<String>,
    create_if_missing: bool,
    publish_key_package: bool,
}

#[derive(Clone, Debug)]
struct BootstrapAccountState {
    account_id_hex: String,
    label: String,
    local_signing: bool,
    created: bool,
    key_package_bytes: Option<usize>,
}

struct ControlClient {
    socket_path: PathBuf,
    auth_token: Option<String>,
    request_timeout: Duration,
}

impl ControlClient {
    fn new(socket_path: PathBuf, auth_token: Option<String>, request_timeout: Duration) -> Self {
        Self {
            socket_path,
            auth_token,
            request_timeout,
        }
    }

    async fn request(
        &self,
        payload: AgentControlRequest,
    ) -> Result<AgentControlEnvelope<AgentControlResponse>, BootstrapError> {
        let request_id = new_request_id();
        let mut envelope = AgentControlEnvelope::request(Some(request_id.clone()), payload);
        if let Some(auth_token) = &self.auth_token {
            envelope = envelope.with_auth_token(auth_token.clone());
        }

        let frame = encode_frame(&envelope)?;
        let connect = UnixStream::connect(&self.socket_path);
        let mut stream = timeout(self.request_timeout, connect)
            .await
            .map_err(|_| BootstrapError::RequestTimedOut)?
            .map_err(AgentControlError::Io)?;

        timeout(self.request_timeout, async {
            stream
                .write_all(&frame)
                .await
                .map_err(AgentControlError::Io)
                .map_err(BootstrapError::Control)?;
            stream
                .flush()
                .await
                .map_err(AgentControlError::Io)
                .map_err(BootstrapError::Control)?;
            let mut reader = BufReader::new(stream);
            let response = read_envelope::<_, AgentControlResponse>(&mut reader)
                .await
                .map_err(BootstrapError::Control)?
                .ok_or(BootstrapError::Control(AgentControlError::EmptyFrame))?;
            if response.id.as_deref() != Some(request_id.as_str()) {
                return Err(BootstrapError::ResponseIdMismatch);
            }
            Ok(response)
        })
        .await
        .map_err(|_| BootstrapError::RequestTimedOut)?
    }
}

async fn bootstrap_agent_account(
    client: &ControlClient,
    options: BootstrapAccountOptions,
) -> Result<BootstrapAccountState, BootstrapError> {
    let list = client.request(AgentControlRequest::AccountList).await?;
    ensure_response_type(&list, "account_list")?;
    let AgentControlResponse::AccountList { accounts } = list.payload else {
        return Err(unexpected_response("account_list", &list.payload));
    };

    let local_signing = local_signing_accounts(accounts);
    let selected = select_account(
        &local_signing,
        options.account_id_hex.as_deref(),
        &options.label,
    )?;

    if let Some(account) = selected {
        let mut key_package_bytes = None;
        if options.publish_key_package {
            let account_id_hex = normalize_account_id_hex(&account.account_id_hex)?;
            let published = client
                .request(AgentControlRequest::AccountPublishKeyPackage {
                    account_id_hex: account_id_hex.clone(),
                })
                .await?;
            ensure_response_type(&published, "key_package_published")?;
            let AgentControlResponse::KeyPackagePublished {
                account_id_hex: echoed_account_id_hex,
                key_package_bytes: bytes,
            } = published.payload
            else {
                return Err(unexpected_response(
                    "key_package_published",
                    &published.payload,
                ));
            };
            let echoed_account_id_hex = normalize_account_id_hex(&echoed_account_id_hex)?;
            if echoed_account_id_hex != account_id_hex {
                return Err(BootstrapError::KeyPackageAccountMismatch {
                    expected: account_id_hex,
                    actual: echoed_account_id_hex,
                });
            }
            key_package_bytes = Some(bytes);
        }

        return Ok(BootstrapAccountState {
            account_id_hex: normalize_account_id_hex(&account.account_id_hex)?,
            label: account.label.clone(),
            local_signing: account.local_signing,
            created: false,
            key_package_bytes,
        });
    }

    if !options.create_if_missing {
        return Err(BootstrapError::NoLocalSigningAccount);
    }

    let created = client
        .request(AgentControlRequest::AccountCreate {
            label: Some(options.label.clone()),
            publish_key_package: options.publish_key_package,
        })
        .await?;
    ensure_response_type(&created, "account_created")?;
    let AgentControlResponse::AccountCreated { account } = created.payload else {
        return Err(unexpected_response("account_created", &created.payload));
    };

    Ok(BootstrapAccountState {
        account_id_hex: normalize_account_id_hex(&account.account_id_hex)?,
        label: account.label,
        local_signing: account.local_signing,
        created: true,
        key_package_bytes: None,
    })
}

fn local_signing_accounts(accounts: Vec<AgentControlAccount>) -> Vec<AgentControlAccount> {
    accounts
        .into_iter()
        .filter(|account| account.local_signing)
        .collect()
}

fn select_account<'a>(
    accounts: &'a [AgentControlAccount],
    account_id_hex: Option<&str>,
    label: &str,
) -> Result<Option<&'a AgentControlAccount>, BootstrapError> {
    if let Some(account_id_hex) = account_id_hex {
        let normalized = normalize_account_id_hex(account_id_hex)?;
        return accounts
            .iter()
            .find(|account| account.account_id_hex == normalized)
            .ok_or_else(|| BootstrapError::AccountNotFound(normalized))
            .map(Some);
    }

    let label_matches = accounts
        .iter()
        .filter(|account| account.label == label)
        .collect::<Vec<_>>();
    if label_matches.len() == 1 {
        return Ok(Some(label_matches[0]));
    }
    if label_matches.len() > 1 {
        return Err(BootstrapError::MultipleAccountsForLabel(label.to_owned()));
    }
    if accounts.len() == 1 {
        return Ok(Some(&accounts[0]));
    }
    if accounts.len() > 1 {
        let summary = accounts
            .iter()
            .map(|account| format!("{}={}", account.label, account.account_id_hex))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(BootstrapError::MultipleAccounts(summary));
    }
    Ok(None)
}

pub fn normalize_account_id_hex(value: &str) -> Result<String, BootstrapError> {
    let normalized = value.trim().to_ascii_lowercase();
    let raw = hex::decode(&normalized)
        .map_err(|_| BootstrapError::InvalidAccountIdHex(value.to_owned()))?;
    if raw.len() != 32 {
        return Err(BootstrapError::InvalidAccountIdLength(raw.len()));
    }
    Ok(normalized)
}

async fn wait_for_socket(socket_path: &Path, wait_for: Duration) -> Result<(), BootstrapError> {
    let deadline = tokio::time::Instant::now() + wait_for;
    while !socket_path.exists() {
        if tokio::time::Instant::now() >= deadline {
            return Err(BootstrapError::SocketNotFound(socket_path.to_path_buf()));
        }
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

fn ensure_response_type(
    envelope: &AgentControlEnvelope<AgentControlResponse>,
    expected: &'static str,
) -> Result<(), BootstrapError> {
    if matches!(envelope.payload, AgentControlResponse::Error { .. }) {
        let AgentControlResponse::Error { code, message } = &envelope.payload else {
            unreachable!()
        };
        return Err(BootstrapError::ControlRejected {
            code: code.clone(),
            message: message.clone(),
        });
    }
    let actual = response_type_name(&envelope.payload);
    if actual != expected {
        return Err(BootstrapError::UnexpectedResponse {
            expected,
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn unexpected_response(expected: &'static str, response: &AgentControlResponse) -> BootstrapError {
    BootstrapError::UnexpectedResponse {
        expected,
        actual: response_type_name(response).to_owned(),
    }
}

fn response_type_name(response: &AgentControlResponse) -> &'static str {
    match response {
        AgentControlResponse::Ack => "ack",
        AgentControlResponse::Error { .. } => "error",
        AgentControlResponse::AccountList { .. } => "account_list",
        AgentControlResponse::AccountCreated { .. } => "account_created",
        AgentControlResponse::KeyPackagePublished { .. } => "key_package_published",
        AgentControlResponse::ProfilePublished { .. } => "profile_published",
        AgentControlResponse::FinalSent { .. } => "final_sent",
        AgentControlResponse::AppEventSent { .. } => "app_event_sent",
        AgentControlResponse::Allowlist { .. } => "allowlist",
        AgentControlResponse::GroupInfo { .. } => "group_info",
        AgentControlResponse::StreamBegun { .. } => "stream_begun",
        AgentControlResponse::StreamFinalized { .. } => "stream_finalized",
        AgentControlResponse::DebugRecordedFinals { .. } => "debug_recorded_finals",
        AgentControlResponse::MediaDownloaded { .. } => "media_downloaded",
    }
}

fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn default_bootstrap_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".marmot-agent"))
        .unwrap_or_else(|| PathBuf::from("/data/marmot-agent"))
}

pub fn resolve_bootstrap_home(home: Option<PathBuf>) -> PathBuf {
    home.or_else(|| std::env::var_os("MARMOT_HOME").map(PathBuf::from))
        .unwrap_or_else(default_bootstrap_home)
}

pub fn resolve_bootstrap_socket(home: &Path, socket: Option<PathBuf>) -> PathBuf {
    socket
        .or_else(|| std::env::var_os("MARMOT_AGENT_SOCKET").map(PathBuf::from))
        .unwrap_or_else(|| crate::default_socket_path(home))
}

pub fn read_bootstrap_auth_token(
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    home: &Path,
) -> Result<Option<String>, BootstrapError> {
    if let Some(token) = auth_token {
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err(BootstrapError::EmptyAuthToken("--auth-token".to_owned()));
        }
        return Ok(Some(token));
    }
    if let Ok(token) = std::env::var("MARMOT_AGENT_AUTH_TOKEN") {
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err(BootstrapError::EmptyAuthToken(
                "MARMOT_AGENT_AUTH_TOKEN".to_owned(),
            ));
        }
        return Ok(Some(token));
    }

    let explicit_env = std::env::var_os("MARMOT_AGENT_AUTH_TOKEN_FILE").map(PathBuf::from);
    let explicit_path = auth_token_file.or(explicit_env);
    let token_path = explicit_path
        .clone()
        .unwrap_or_else(|| home.join("control.token"));
    if !token_path.exists() {
        if explicit_path.is_some() {
            return Err(BootstrapError::AuthTokenFileNotFound(token_path));
        }
        return Ok(None);
    }
    let token = std::fs::read_to_string(&token_path)
        .map_err(|_| BootstrapError::AuthTokenFileNotFound(token_path.clone()))?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(BootstrapError::EmptyAuthToken(
            token_path.display().to_string(),
        ));
    }
    Ok(Some(token))
}

pub fn resolve_bootstrap_relays(cli_relays: Vec<String>) -> Vec<String> {
    if !cli_relays.is_empty() {
        return clean_values(cli_relays);
    }
    if let Ok(value) = std::env::var("MARMOT_RELAYS").or_else(|_| std::env::var("MARMOT_RELAY")) {
        let parsed = csv_values(&value);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_owned())
        .collect()
}

pub fn resolve_bootstrap_quic_candidates(
    cli_candidates: Vec<String>,
    cli_csv: Option<String>,
    no_quic: bool,
) -> Vec<String> {
    if no_quic {
        return Vec::new();
    }
    let mut candidates = cli_candidates;
    if let Some(csv) = cli_csv {
        candidates.extend(csv_values(&csv));
    }
    let cleaned = clean_values(candidates);
    if !cleaned.is_empty() {
        return cleaned;
    }
    if let Ok(value) = std::env::var("MARMOT_QUIC_CANDIDATES") {
        let parsed = csv_values(&value);
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![DEFAULT_QUIC_CANDIDATE.to_owned()]
}

fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn clean_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use agent_control::{
        AgentControlEnvelope, AgentControlRequest, AgentControlResponse, write_frame,
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    use super::*;

    const ACCOUNT_ID: &str = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";

    #[tokio::test]
    async fn bootstrap_creates_agent_account_when_none_exists() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("dm-agent.sock");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server =
            spawn_mock_server(
                socket_path.clone(),
                requests.clone(),
                |request| match request {
                    AgentControlRequest::AccountList => AgentControlResponse::AccountList {
                        accounts: Vec::new(),
                    },
                    AgentControlRequest::AccountCreate {
                        label,
                        publish_key_package,
                    } => {
                        assert_eq!(label.as_deref(), Some(DEFAULT_BOOTSTRAP_LABEL));
                        assert!(publish_key_package);
                        AgentControlResponse::AccountCreated {
                            account: AgentControlAccount {
                                account_id_hex: ACCOUNT_ID.to_owned(),
                                label: DEFAULT_BOOTSTRAP_LABEL.to_owned(),
                                local_signing: true,
                            },
                        }
                    }
                    other => panic!("unexpected request: {other:?}"),
                },
            )
            .await;

        let result = run_bootstrap(test_options(socket_path)).await.unwrap();
        server.abort();

        assert!(result.created);
        assert_eq!(result.account_id_hex, ACCOUNT_ID);
        assert_eq!(
            result.npub,
            "npub14f8usejl26twx0dhuxjh9cas7keav9vr0v8nvtwtrjqx3vycc76qqh9nsy"
        );
        assert!(result.nprofile.starts_with("nprofile1"));
        assert!(!result.qr_payload.contains("quic://"));
        let recorded = requests.lock().await;
        assert_eq!(recorded.len(), 2);
        assert!(matches!(recorded[0], AgentControlRequest::AccountList));
        assert!(matches!(
            recorded[1],
            AgentControlRequest::AccountCreate { .. }
        ));
    }

    #[tokio::test]
    async fn bootstrap_reuses_existing_account_and_repairs_key_package() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("dm-agent.sock");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server =
            spawn_mock_server(
                socket_path.clone(),
                requests.clone(),
                |request| match request {
                    AgentControlRequest::AccountList => AgentControlResponse::AccountList {
                        accounts: vec![AgentControlAccount {
                            account_id_hex: ACCOUNT_ID.to_owned(),
                            label: DEFAULT_BOOTSTRAP_LABEL.to_owned(),
                            local_signing: true,
                        }],
                    },
                    AgentControlRequest::AccountPublishKeyPackage { account_id_hex } => {
                        assert_eq!(account_id_hex, ACCOUNT_ID);
                        AgentControlResponse::KeyPackagePublished {
                            account_id_hex: ACCOUNT_ID.to_owned(),
                            key_package_bytes: 1234,
                        }
                    }
                    other => panic!("unexpected request: {other:?}"),
                },
            )
            .await;

        let result = run_bootstrap(test_options(socket_path)).await.unwrap();
        server.abort();

        assert!(!result.created);
        assert!(result.key_package_published);
        assert_eq!(result.key_package_bytes, Some(1234));
        let recorded = requests.lock().await;
        assert_eq!(recorded.len(), 2);
        assert!(matches!(
            recorded[1],
            AgentControlRequest::AccountPublishKeyPackage { .. }
        ));
    }

    #[tokio::test]
    async fn bootstrap_honors_repeated_and_csv_quic_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("dm-agent.sock");
        let server = spawn_mock_server(
            socket_path.clone(),
            Arc::new(Mutex::new(Vec::new())),
            |request| match request {
                AgentControlRequest::AccountList => AgentControlResponse::AccountList {
                    accounts: vec![AgentControlAccount {
                        account_id_hex: ACCOUNT_ID.to_owned(),
                        label: DEFAULT_BOOTSTRAP_LABEL.to_owned(),
                        local_signing: true,
                    }],
                },
                AgentControlRequest::AccountPublishKeyPackage { .. } => {
                    AgentControlResponse::KeyPackagePublished {
                        account_id_hex: ACCOUNT_ID.to_owned(),
                        key_package_bytes: 12,
                    }
                }
                other => panic!("unexpected request: {other:?}"),
            },
        )
        .await;

        let mut options = test_options(socket_path);
        options.relays = vec!["wss://relay.one".to_owned()];
        options.quic_candidates = vec![
            "quic://one".to_owned(),
            "quic://two".to_owned(),
            "quic://three".to_owned(),
        ];
        let result = run_bootstrap(options).await.unwrap();
        server.abort();

        assert_eq!(result.relays, vec!["wss://relay.one".to_owned()]);
        assert_eq!(
            result.quic_candidates,
            vec![
                "quic://one".to_owned(),
                "quic://two".to_owned(),
                "quic://three".to_owned(),
            ]
        );
        assert!(result.qr_payload.starts_with("nprofile1"));
        assert!(!result.qr_payload.contains("quic://one"));
    }

    #[tokio::test]
    async fn bootstrap_rejects_invalid_relay_before_account_ops() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = test_options(dir.path().join("dm-agent.sock"));
        options.relays = vec!["not-a-relay-url".to_owned()];

        let err = run_bootstrap(options).await.unwrap_err();
        assert!(matches!(
            err,
            BootstrapError::App(marmot_app::AppError::InvalidNostrRouting(_))
        ));
    }

    #[tokio::test]
    async fn bootstrap_rejects_key_package_for_wrong_account() {
        const OTHER_ACCOUNT: &str =
            "bb4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b5";
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("dm-agent.sock");
        let server = spawn_mock_server(
            socket_path.clone(),
            Arc::new(Mutex::new(Vec::new())),
            |request| match request {
                AgentControlRequest::AccountList => AgentControlResponse::AccountList {
                    accounts: vec![AgentControlAccount {
                        account_id_hex: ACCOUNT_ID.to_owned(),
                        label: DEFAULT_BOOTSTRAP_LABEL.to_owned(),
                        local_signing: true,
                    }],
                },
                AgentControlRequest::AccountPublishKeyPackage { .. } => {
                    AgentControlResponse::KeyPackagePublished {
                        account_id_hex: OTHER_ACCOUNT.to_owned(),
                        key_package_bytes: 1234,
                    }
                }
                other => panic!("unexpected request: {other:?}"),
            },
        )
        .await;

        let err = run_bootstrap(test_options(socket_path)).await.unwrap_err();
        server.abort();

        assert!(matches!(
            err,
            BootstrapError::KeyPackageAccountMismatch { .. }
        ));
    }

    fn test_options(socket: PathBuf) -> BootstrapOptions {
        BootstrapOptions {
            home: PathBuf::from("/tmp/marmot-agent"),
            socket,
            label: DEFAULT_BOOTSTRAP_LABEL.to_owned(),
            account_id_hex: None,
            auth_token: None,
            relays: DEFAULT_RELAYS
                .iter()
                .map(|relay| (*relay).to_owned())
                .collect(),
            quic_candidates: vec![DEFAULT_QUIC_CANDIDATE.to_owned()],
            create_if_missing: true,
            publish_key_package: true,
            wait_for_socket: Duration::from_millis(100),
            request_timeout: Duration::from_secs(1),
        }
    }

    async fn spawn_mock_server<F>(
        socket_path: PathBuf,
        requests: Arc<Mutex<Vec<AgentControlRequest>>>,
        handler: F,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(AgentControlRequest) -> AgentControlResponse + Send + Sync + 'static,
    {
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).unwrap();
        }
        let listener = UnixListener::bind(&socket_path).unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            ready_tx.send(()).ok();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = tokio::io::split(stream);
                let mut reader = BufReader::new(reader);
                let mut line = Vec::new();
                if reader.read_until(b'\n', &mut line).await.unwrap() == 0 {
                    continue;
                }
                let envelope: AgentControlEnvelope<AgentControlRequest> =
                    agent_control::decode_envelope(&line).unwrap();
                requests.lock().await.push(envelope.payload.clone());
                let response = AgentControlEnvelope::new(envelope.id, handler(envelope.payload));
                write_frame(&mut writer, &response).await.unwrap();
                writer.shutdown().await.unwrap();
            }
        });
        ready_rx.await.unwrap();
        task
    }
}
