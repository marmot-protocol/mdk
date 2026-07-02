//! `notifications` command namespace handlers.

use crate::{CommandOutput, DmError, NotificationsCommand, unsupported_command};

pub(crate) fn notifications_command(
    command: NotificationsCommand,
) -> Result<CommandOutput, DmError> {
    match command {
        NotificationsCommand::Subscribe => unsupported_command(
            "notifications subscribe",
            "notification derivation and delivery are not exposed by the daemon yet",
        ),
    }
}
