//! The account worker's inbox relay check (relay health; see
//! `client::relay_checks`).
//!
//! One check runs per account at a time, beside the writer: a host check
//! while one runs is refused at once with [`AppError::RelayCheckRunning`],
//! and the worker's own check at its start (the account's own key only) is
//! skipped when one already runs, since every check covers every inbox
//! relay. Its continuation runs on the writer: the client keeps what it
//! established, the worker publishes the check state and announces a changed
//! answer, then answers the host. A check belongs to the client that started
//! it: before the worker replaces its client it cancels it
//! ([`RelayChecks::replace`]), and before the worker returns it cancels it
//! and waits for its task ([`RelayChecks::end`]). A host waiting on a
//! cancelled check gets the error a dropped worker reply gives.

use std::collections::BTreeSet;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::client::relay_checks::RunningInboxCheck;
use crate::relay_health::RunOutcome;
use crate::{AppClient, AppError};

/// A host check's reply.
pub(super) type HostCheckReply = oneshot::Sender<Result<(), AppError>>;

struct Running {
    check: RunningInboxCheck,
    /// The host check it answers; `None` for the worker's own.
    respond: Option<HostCheckReply>,
}

#[derive(Default)]
pub(super) struct RelayChecks {
    running: Option<Running>,
    /// Cancels the current client's check.
    cancel: CancellationToken,
    /// Checks of a replaced client, still finishing. The worker waits for
    /// them when it returns.
    retired: Vec<RunningInboxCheck>,
}

impl RelayChecks {
    /// The host asks for a check of account `label`. Returns the reply to
    /// send now: refused while a check runs, answered when there is nothing
    /// to dial or the check cannot start; `None` once a check started, which
    /// answers when it ends.
    pub(super) fn request(
        &mut self,
        client: &AppClient,
        label: &str,
        respond: HostCheckReply,
    ) -> Option<(HostCheckReply, Result<(), AppError>)> {
        if self.running.is_some() {
            return Some((respond, Err(AppError::RelayCheckRunning)));
        }
        match client.begin_inbox_relay_check(label, false) {
            Ok(Some(start)) => {
                self.running = Some(Running {
                    check: start.spawn(self.cancel.clone()),
                    respond: Some(respond),
                });
                None
            }
            Ok(None) => Some((respond, Ok(()))),
            Err(error) => Some((respond, Err(error))),
        }
    }

    /// The worker's own check, once per client: true once it started, a
    /// check already runs, or it never will (a remote or host signer); false
    /// while the lists hold no inbox relay to dial or cannot be read, to ask
    /// again when they change.
    pub(super) fn start_own(&mut self, client: &AppClient, label: &str) -> bool {
        if self.running.is_some() {
            return true;
        }
        if !client
            .app
            .account_home()
            .account(label)
            .is_ok_and(|account| account.local_signing)
        {
            return true;
        }
        match client.begin_inbox_relay_check(label, true) {
            Ok(Some(start)) => {
                self.running = Some(Running {
                    check: start.spawn(self.cancel.clone()),
                    respond: None,
                });
                true
            }
            Ok(None) | Err(_) => false,
        }
    }

    pub(super) fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// The relays the running check dials.
    pub(super) fn checking(&self) -> BTreeSet<String> {
        self.running
            .as_ref()
            .map(|running| running.check.relays().clone())
            .unwrap_or_default()
    }

    /// The running check's outcome, once its task ends. Pending while none
    /// runs. Cancel-safe.
    pub(super) async fn next(&mut self) -> Option<RunOutcome> {
        match &mut self.running {
            Some(running) => running.check.result().await,
            None => std::future::pending().await,
        }
    }

    /// The continuation, on the writer: the client keeps what the check
    /// established. Returns the host reply to send, if a host asked.
    pub(super) fn settle(
        &mut self,
        client: &mut AppClient,
        outcome: Option<RunOutcome>,
    ) -> Option<(HostCheckReply, Result<(), AppError>)> {
        let running = self.running.take()?;
        let result = match outcome {
            Some(outcome) => {
                client.finish_inbox_relay_check(&outcome);
                Ok(())
            }
            None => Err(AppError::TransportClosed),
        };
        running.respond.map(|respond| (respond, result))
    }

    /// Before the worker replaces its client: cancel its check. Its result
    /// never reaches the next client, and a host waiting on it hears the
    /// worker dropped its reply.
    pub(super) fn replace(&mut self) {
        self.retired.retain(|check| !check.is_finished());
        self.cancel.cancel();
        self.cancel = CancellationToken::new();
        self.retired
            .extend(self.running.take().map(|running| running.check));
    }

    /// When the worker returns: cancel the check and wait for its task.
    pub(super) async fn end(&mut self) {
        self.cancel.cancel();
        let running = self.running.take().map(|running| running.check);
        for check in running.into_iter().chain(self.retired.drain(..)) {
            check.end().await;
        }
    }
}
