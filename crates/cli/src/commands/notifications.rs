//! `notifications` command namespace handlers.

use crate::{CommandOutput, NotificationsCommand, WnError, unsupported_command};

pub(crate) fn notifications_command(
    command: NotificationsCommand,
) -> Result<CommandOutput, WnError> {
    match command {
        NotificationsCommand::Subscribe => unsupported_command(
            "notifications subscribe",
            "notification derivation and delivery are not exposed by the daemon yet",
        ),
    }
}
