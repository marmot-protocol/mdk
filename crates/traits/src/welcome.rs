//! Pending-welcome persistence.
//!
//! Minimal shape matching the `WelcomeState::{None, Pending, Active}` enum
//! chosen for this refactor. A `Declined` variant is not modeled — today
//! clients auto-accept welcomes. Adding user-driven decline is a later
//! feature and can reuse this storage shape (just add a `declined` flag or
//! a `Rejected` state at that time).

use crate::types::{GroupId, MessageId};
use serde::{Deserialize, Serialize};

/// A welcome the engine has received but not yet processed (e.g. because the
/// client is offline or joining hasn't been confirmed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWelcome {
    pub message_id: MessageId,
    pub group_id: GroupId,
    pub welcome_bytes: Vec<u8>,
}
