//! Whether each invite reached the invited account's inbox relays
//! (mdk#1706): the session's per-Welcome deliveries of each account's newest
//! invite, one per invited device, rolled up into one answer per invited
//! account and group.
//!
//! A relay's acknowledgement is not the recipient's. `RelayAccepted` means a
//! relay stored the Welcome, not that the recipient received it or joined.
//! Relays appear only as counts, never by name.

pub use cgka_traits::maintenance::{
    WelcomeCancelReason, WelcomeDeliveryProblem, WelcomeDeliveryState, WelcomeRelayCounts,
};
use marmot_session::WelcomeDeliveryOutcome;

/// One invited account's invite to one group, as its newest invite left it.
/// Each of the account's invited devices gets its own Welcome; `state` rolls
/// them up: a relay stored one device's Welcome (`RelayAccepted`), else one is
/// still being sent (the first such device's `Sending`), else one waits for
/// its commit (`Waiting`), else all are settled undelivered and it is the
/// first device's state. Read it with the device counts: "1 of 2
/// devices".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteDelivery {
    pub group_id_hex: String,
    /// The invited account.
    pub recipient_hex: String,
    /// The commit that added the account, hex; `None` for a group's founding
    /// members, whom the create added.
    pub invite_id_hex: Option<String>,
    pub state: WelcomeDeliveryState,
    pub device_count: u32,
    /// Devices whose Welcome a relay stored.
    pub accepted_device_count: u32,
    /// One entry per invited device, in the order they were recorded.
    pub devices: Vec<InviteDeviceDelivery>,
}

/// One invited device's Welcome. Times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteDeviceDelivery {
    /// The Welcome's id.
    pub delivery_id_hex: String,
    pub state: WelcomeDeliveryState,
    /// When this device first recorded the Welcome.
    pub created_at: u64,
    /// When MDK stops sending it, if it has a deadline.
    pub deliver_until: Option<u64>,
    /// Publish attempts made, including those that found no inbox relay.
    pub attempt_count: u32,
    pub last_attempt_at: Option<u64>,
    /// When a relay first stored it.
    pub accepted_at: Option<u64>,
    pub relays: WelcomeRelayCounts,
}

/// One [`InviteDelivery`] per invite the session listed: each account's
/// newest invite, its Welcomes in the order they were first recorded.
pub(crate) fn invite_deliveries(invites: Vec<Vec<WelcomeDeliveryOutcome>>) -> Vec<InviteDelivery> {
    invites
        .into_iter()
        .filter(|devices| !devices.is_empty())
        .map(account_invite)
        .collect()
}

fn account_invite(devices: Vec<WelcomeDeliveryOutcome>) -> InviteDelivery {
    let first = &devices[0].record;
    let accepted = devices
        .iter()
        .filter(|device| device.state == WelcomeDeliveryState::RelayAccepted)
        .count();
    InviteDelivery {
        group_id_hex: hex::encode(first.group_id.as_slice()),
        recipient_hex: hex::encode(first.recipient.as_slice()),
        invite_id_hex: first
            .origin_commit_id
            .as_ref()
            .map(|commit| hex::encode(commit.as_slice())),
        state: rolled_up_state(&devices),
        device_count: u32::try_from(devices.len()).unwrap_or(u32::MAX),
        accepted_device_count: u32::try_from(accepted).unwrap_or(u32::MAX),
        devices: devices.into_iter().map(device_delivery).collect(),
    }
}

/// The account's state from its devices' states alone, in their recorded
/// order, so attempt timing never moves it.
fn rolled_up_state(devices: &[WelcomeDeliveryOutcome]) -> WelcomeDeliveryState {
    if devices
        .iter()
        .any(|device| device.state == WelcomeDeliveryState::RelayAccepted)
    {
        return WelcomeDeliveryState::RelayAccepted;
    }
    if let Some(sending) = devices
        .iter()
        .find(|device| matches!(device.state, WelcomeDeliveryState::Sending { .. }))
    {
        return sending.state;
    }
    if devices
        .iter()
        .any(|device| device.state == WelcomeDeliveryState::Waiting)
    {
        return WelcomeDeliveryState::Waiting;
    }
    devices
        .first()
        .map_or(WelcomeDeliveryState::Waiting, |device| device.state)
}

fn device_delivery(delivery: WelcomeDeliveryOutcome) -> InviteDeviceDelivery {
    let record = delivery.record;
    InviteDeviceDelivery {
        delivery_id_hex: hex::encode(record.welcome_id.as_slice()),
        state: delivery.state,
        created_at: record.created_at.0,
        deliver_until: delivery.deliver_until.map(|at| at.0),
        attempt_count: record.attempts,
        last_attempt_at: record.last_attempt_at.map(|at| at.0),
        accepted_at: record.accepted_at.map(|at| at.0),
        relays: record.relays,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::maintenance::WelcomeDeliveryRecord;
    use cgka_traits::transport::Timestamp;
    use cgka_traits::{GroupId, MemberId, MessageId};

    fn device(welcome: u8, state: WelcomeDeliveryState) -> WelcomeDeliveryOutcome {
        WelcomeDeliveryOutcome {
            record: WelcomeDeliveryRecord {
                welcome_id: MessageId::new(vec![welcome; 32]),
                group_id: GroupId::new(vec![1; 16]),
                recipient: MemberId::new(vec![2; 32]),
                origin_commit_id: Some(MessageId::new(vec![20; 32])),
                created_at: Timestamp(100),
                attempts: 1,
                last_attempt_at: Some(Timestamp(100 + u64::from(welcome))),
                accepted_at: None,
                relays: WelcomeRelayCounts::default(),
                last_problem: None,
            },
            state,
            deliver_until: None,
        }
    }

    const UNREACHABLE: WelcomeDeliveryState = WelcomeDeliveryState::Sending {
        last_problem: Some(WelcomeDeliveryProblem::RelaysUnreachable),
    };

    /// An account counts as reached once a relay stored one of its devices'
    /// Welcomes, reported with how many devices that is.
    #[test]
    fn an_account_is_reached_when_one_of_its_devices_is() {
        let invites = invite_deliveries(vec![vec![
            device(1, UNREACHABLE),
            device(2, WelcomeDeliveryState::RelayAccepted),
        ]]);
        assert_eq!(invites.len(), 1);
        let invite = &invites[0];
        assert_eq!(invite.invite_id_hex, Some(hex::encode([20; 32])));
        assert_eq!(invite.state, WelcomeDeliveryState::RelayAccepted);
        assert_eq!((invite.accepted_device_count, invite.device_count), (1, 2));
    }

    /// Devices still being sent to with different problems read as the
    /// first one's, though the other was attempted later: attempt timing
    /// never moves the account's answer.
    #[test]
    fn an_account_still_being_sent_to_reads_as_its_first_sending_device() {
        let refused = WelcomeDeliveryState::Sending {
            last_problem: Some(WelcomeDeliveryProblem::RefusedByRelays),
        };
        let invites = invite_deliveries(vec![vec![device(1, refused), device(2, UNREACHABLE)]]);
        assert_eq!(invites[0].state, refused);
    }
}
