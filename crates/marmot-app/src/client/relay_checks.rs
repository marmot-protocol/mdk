//! The account's inbox relay check on the writer (relay health): what a
//! check dials and with which signer, the task that runs it beside the
//! writer, and its result kept on the client.
//!
//! A check task holds the relay plane, the relays and the signer the client
//! already holds, nothing else of the client (mdk#3466 T1). It belongs to the
//! client that started it: the worker cancels it before replacing that
//! client, and cancels and waits for it before it returns
//! (`runtime::account_worker::relay_checks`). Its results stay on the client
//! and go with it. Dropped unended, a check aborts its task.

use std::collections::BTreeSet;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::AppClient;
use crate::AppError;
use crate::relay_health::{CheckSnapshot, RunInputs, RunOutcome, run_inbox_check};

/// A check the writer began: its relays and what its task needs.
pub(crate) struct InboxCheckStart {
    relays: BTreeSet<String>,
    inputs: RunInputs,
}

impl InboxCheckStart {
    /// Run the check beside the writer, until it ends or `cancel` is
    /// cancelled.
    pub(crate) fn spawn(self, cancel: CancellationToken) -> RunningInboxCheck {
        let InboxCheckStart { relays, inputs } = self;
        let task = tokio::spawn({
            let relays = relays.clone();
            async move {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => None,
                    outcome = run_inbox_check(&relays, &inputs) => Some(outcome),
                }
            }
        });
        RunningInboxCheck { relays, task }
    }
}

/// A check running beside the writer. Dropped unended, its task is aborted.
pub(crate) struct RunningInboxCheck {
    relays: BTreeSet<String>,
    task: JoinHandle<Option<RunOutcome>>,
}

impl Drop for RunningInboxCheck {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RunningInboxCheck {
    pub(crate) fn relays(&self) -> &BTreeSet<String> {
        &self.relays
    }

    /// The check's outcome once its task ends; `None` when it was cancelled
    /// or its task failed. Cancel-safe until it returns; poll it no more
    /// after that.
    pub(crate) async fn result(&mut self) -> Option<RunOutcome> {
        (&mut self.task).await.ok().flatten()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Wait for the task to end; cancel its token first to stop it.
    pub(crate) async fn end(mut self) {
        let _ = (&mut self.task).await;
    }
}

impl AppClient {
    /// An inbox check of every allowed inbox relay of account `label`, the
    /// first 16 by URL, answered with the signer this client holds; `None`
    /// when the lists hold none to dial. `own_key_only` starts nothing
    /// unless that signer is the account's own key, so a remote or host
    /// signer is never asked unprompted.
    pub(crate) fn begin_inbox_relay_check(
        &self,
        label: &str,
        own_key_only: bool,
    ) -> Result<Option<InboxCheckStart>, AppError> {
        let local_key = self.app.account_home().account(label)?.local_signing;
        if own_key_only && !local_key {
            return Ok(None);
        }
        let relays = self
            .app
            .account_relay_health(label, &CheckSnapshot::default())?
            .checkable_inbox_relays();
        if relays.is_empty() {
            return Ok(None);
        }
        Ok(Some(InboxCheckStart {
            relays,
            inputs: RunInputs {
                plane: self.relay_plane.clone(),
                account_id_hex: hex::encode(self.adapter.account_id().as_slice()),
                signer: self.transport_signer.clone(),
                local_key,
            },
        }))
    }

    /// Keep what a check established, on the writer.
    pub(crate) fn finish_inbox_relay_check(&mut self, outcome: &RunOutcome) {
        for (relay, record) in outcome {
            if let Some(record) = record {
                self.inbox_relay_checks.insert(relay.clone(), *record);
            }
        }
    }
}
