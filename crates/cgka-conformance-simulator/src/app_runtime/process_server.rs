//! Child entry point shared by the local and distributed node executables.
use super::process_backend::{Init, ParticipantServer};
use super::process_io::{MAX_FRAME_BYTES, PROTOCOL, Request, Response, WireError};
use super::process_relay::RelayServer;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub async fn run(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(role, "participant" | "relay") {
        return Err("unknown app scenario process role".into());
    }
    super::process_io::watch_parent()?;
    let mut participant: Option<ParticipantServer> = None;
    let outcome = serve(role, &mut participant).await;
    if let Some(server) = participant {
        server.runtime.shutdown_and_close().await?;
    }
    outcome
}

async fn serve(
    role: &str,
    participant: &mut Option<ParticipantServer>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut relay: Option<RelayServer> = None;
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut writer = tokio::io::stdout();
    loop {
        let mut bytes = Vec::new();
        let count = (&mut reader)
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut bytes)
            .await?;
        if count == 0 {
            break;
        }
        if bytes.len() > MAX_FRAME_BYTES || !bytes.ends_with(b"\n") {
            return Err("invalid app scenario request frame".into());
        }
        let request: Request = serde_json::from_slice(&bytes)?;
        let close = request.method == "close";
        let result = if request.protocol != PROTOCOL {
            Err(WireError::environment("app_process_protocol_mismatch"))
        } else if request.method == "hello" {
            Ok(
                serde_json::json!({"protocol":PROTOCOL,"policy_overrides":cfg!(feature="test-policy-overrides"),"worker_threads":4}),
            )
        } else if role == "participant" {
            if request.method == "initialize" && participant.is_none() {
                let init: Init = serde_json::from_value(request.args)?;
                match ParticipantServer::initialize(init).await {
                    Ok((server, account)) => {
                        *participant = Some(server);
                        Ok(serde_json::json!(account))
                    }
                    Err(error) => Err(error),
                }
            } else if let Some(server) = participant.as_mut() {
                server.handle(&request.method, request.args).await
            } else {
                Err(WireError::environment("app_process_not_initialized"))
            }
        } else {
            if relay.is_none() {
                relay = Some(RelayServer::start().await?);
            }
            relay
                .as_mut()
                .expect("relay initialized")
                .handle(&request.method, request.args)
                .await
        };
        let success = result.is_ok();
        let response = Response {
            protocol: PROTOCOL.into(),
            id: request.id,
            result,
        };
        let bytes = serde_json::to_vec(&response)?;
        if bytes.len() >= MAX_FRAME_BYTES {
            return Err("app scenario response exceeds frame budget".into());
        }
        writer.write_all(&bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        if close && success {
            return Ok(());
        }
    }
    Ok(())
}
