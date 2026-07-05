//! `notifications` command namespace handlers.

use crate::{CommandOutput, NotificationsCommand, WnError};

pub(crate) fn notifications_command(
    command: NotificationsCommand,
) -> Result<CommandOutput, WnError> {
    match command {
        NotificationsCommand::Subscribe => Err(WnError::NotificationsSubscribeRequiresDaemon),
    }
}
