//! Local operator controls, deliberately outside the agent-control protocol.
use crate::ConnectorError;
use marmot_app::{
    MarmotApp, MarmotAppConfig, MarmotAppRuntime, UsageDiagnosticsSettings, UsageDiagnosticsStatus,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum UsageDiagnosticsCommand {
    Show,
    Enable,
    Disable,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UsageDiagnosticsReport {
    pub settings: UsageDiagnosticsSettings,
    pub status: UsageDiagnosticsStatus,
    pub disclosure: String,
}
fn apply(
    runtime: &MarmotAppRuntime,
    command: UsageDiagnosticsCommand,
) -> Result<UsageDiagnosticsReport, ConnectorError> {
    if !matches!(command, UsageDiagnosticsCommand::Show) {
        runtime
            .set_usage_diagnostics_consent(matches!(command, UsageDiagnosticsCommand::Enable))?;
    }
    Ok(UsageDiagnosticsReport {
        settings: runtime.usage_diagnostics_settings()?,
        status: runtime.usage_diagnostics_status(),
        disclosure: marmot_app::USAGE_DIAGNOSTICS_DISCLOSURE.into(),
    })
}
fn path(home: &Path) -> std::path::PathBuf {
    home.join("dev").join("usage-diagnostics.sock")
}
pub(crate) fn bind(home: &Path) -> Result<tokio::net::UnixListener, ConnectorError> {
    crate::bind_connector_socket_with_mode(&path(home), 0o700, 0o600)
}
pub(crate) async fn serve_one(
    mut stream: tokio::net::UnixStream,
    runtime: &MarmotAppRuntime,
) -> Result<(), ConnectorError> {
    // The management socket is owner-only. Tokens used by agent-control never grant consent.
    if stream.peer_cred()?.uid() != unsafe { libc::geteuid() } {
        return Ok(());
    }
    let exchange = async {
        let byte = stream.read_u8().await?;
        let command = match byte {
            0 => UsageDiagnosticsCommand::Show,
            1 => UsageDiagnosticsCommand::Enable,
            2 => UsageDiagnosticsCommand::Disable,
            _ => return Ok::<_, ConnectorError>(()),
        };
        let result = apply(runtime, command).map_err(|_| "usage diagnostics update failed");
        let payload = serde_json::to_vec(&result)?;
        stream.write_all(&payload).await?;
        stream.shutdown().await?;
        Ok(())
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), exchange).await;
    Ok(())
}
pub async fn manage_usage_diagnostics(
    home: &Path,
    command: UsageDiagnosticsCommand,
) -> Result<UsageDiagnosticsReport, ConnectorError> {
    match tokio::net::UnixStream::connect(path(home)).await {
        Ok(mut stream) => {
            let exchange = async {
                stream
                    .write_u8(match command {
                        UsageDiagnosticsCommand::Show => 0,
                        UsageDiagnosticsCommand::Enable => 1,
                        UsageDiagnosticsCommand::Disable => 2,
                    })
                    .await?;
                let mut bytes = Vec::new();
                stream.take(8192).read_to_end(&mut bytes).await?;
                let result: Result<UsageDiagnosticsReport, String> =
                    serde_json::from_slice(&bytes)?;
                result.map_err(|_| std::io::Error::other("usage diagnostics update failed").into())
            };
            tokio::time::timeout(std::time::Duration::from_secs(5), exchange)
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "local usage diagnostics request timed out",
                    )
                })?
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            let config = MarmotAppConfig {
                usage_diagnostics_silent: true,
                ..Default::default()
            };
            let app = MarmotApp::try_with_relays_and_account_home_and_config(
                home,
                Vec::new(),
                marmot_account::AccountHome::open(home),
                config,
            )?;
            let runtime = app.runtime();
            crate::configure_product_analytics(&runtime)?;
            apply(&runtime, command)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn owner_socket_updates_the_active_consent_without_starting_collectors() {
        let home = tempfile::Builder::new()
            .prefix(".mdk-usage-test-")
            .tempdir_in(std::env::var_os("HOME").expect("test home"))
            .unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            home.path(),
            Vec::new(),
            marmot_account::AccountHome::open(home.path()),
            MarmotAppConfig {
                usage_diagnostics_silent: true,
                ..Default::default()
            },
        )
        .unwrap();
        let runtime = app.runtime();
        let listener = bind(home.path()).unwrap();
        for command in [
            UsageDiagnosticsCommand::Enable,
            UsageDiagnosticsCommand::Show,
            UsageDiagnosticsCommand::Disable,
        ] {
            let server = async {
                let (stream, _) = listener.accept().await.unwrap();
                serve_one(stream, &runtime).await.unwrap();
            };
            let client = manage_usage_diagnostics(home.path(), command);
            let (_, report) = tokio::join!(server, client);
            let report = report.unwrap();
            assert_eq!(
                report.settings.decision,
                if matches!(command, UsageDiagnosticsCommand::Disable) {
                    marmot_app::UsageDiagnosticsDecision::Declined
                } else {
                    marmot_app::UsageDiagnosticsDecision::Granted
                }
            );
            assert_eq!(
                report.status.product_analytics,
                marmot_app::DiagnosticsExporterStatus::Disabled
            );
            assert_eq!(
                report.status.telemetry,
                marmot_app::DiagnosticsExporterStatus::Disabled
            );
        }
    }
}
