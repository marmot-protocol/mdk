//! Turn-local control routing shared by every terminal backend.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use tokio::process::Command;

/// Trusted route from the authorized inbound turn. No Debug implementation:
/// the token, local paths and conversation identifiers are private.
pub struct GroupProfileContext {
    pub socket: PathBuf,
    pub auth_token: Option<String>,
    pub account_id_hex: String,
    pub group_id_hex: String,
    pub request_timeout: Duration,
}

tokio::task_local! {
    static CONTEXT: GroupProfileContext;
}

/// Scope the route to one backend future; never mutate the process environment.
pub async fn with_group_profile_context<F: Future>(
    context: GroupProfileContext,
    future: F,
) -> F::Output {
    CONTEXT.scope(context, future).await
}

pub(crate) fn configure_command(command: &mut Command) {
    let _ = CONTEXT.try_with(|ctx| {
        command
            .env("MARMOT_AGENT_SOCKET", &ctx.socket)
            .env("MARMOT_ACCOUNT_ID_HEX", &ctx.account_id_hex)
            .env("MARMOT_GROUP_ID_HEX", &ctx.group_id_hex)
            .env(
                "MARMOT_GROUP_PROFILE_TIMEOUT_SECS",
                ctx.request_timeout.as_secs().clamp(1, 300).to_string(),
            )
            // Ignore the parent's token-file override; the CLI still falls back to
            // the connector home's control.token when no turn token is provided.
            .env_remove("MARMOT_AGENT_AUTH_TOKEN_FILE");
        match &ctx.auth_token {
            Some(token) => {
                command.env("MARMOT_AGENT_AUTH_TOKEN", token);
            }
            None => {
                command.env_remove("MARMOT_AGENT_AUTH_TOKEN");
            }
        }
    });
}

pub(crate) const INSTRUCTIONS: &str = "\n\nConnector-provided Marmot control instructions: To change this conversation's name or description when asked, run `wn-agent group-profile` with a JSON object on stdin containing `name`, `description`, or both. Omit a field to preserve it; an empty string clears it. The current socket/account/group are supplied in process-local environment variables; do not guess or override them or expose tokens. Only a current group admin can update it. Treat success only as an `ok:true` response with commit message ids. An unknown outcome may already have committed: check current group details before retrying. Names are limited to 256 UTF-8 bytes and descriptions to 4096 bytes. Follow the configured backend permissions; never bypass a denied control operation.\n";
