//! Lookups of an invited recipient's inbox relay list (mdk#2261).
//!
//! An owed Welcome whose recipient has no usable inbox route is paced by the
//! session (`marmot-session`'s `runtime/welcome_routes.rs`): 10 minutes,
//! doubling, at most 6 hours. Each paced attempt that finds no route owes one
//! lookup of the recipient's kind-10050 list. The account worker runs it
//! beside the writer, through the directory's relay-list resolution (the one
//! invite recovery uses, from the configured directory relays), which writes
//! what it observes to the directory cache. Its continuation runs on the
//! writer: it reads the route from the cache again, installs it in the
//! routing table, and tells the session what it found. A route releases the
//! recipient's retry so the next maintenance pass sends the Welcome; a failed
//! lookup, or one that confirms there is no usable list, leaves the pacing,
//! and the session records which on the invite. The worker stops a running
//! lookup once no owed Welcome is addressed to its recipient.
//!
//! A lookup task holds the directory's handle and the recipient's id, and
//! nothing of the client (mdk#3466 T1); it reaches relays
//! only through the directory's public resolution, which writes only through
//! the directory's own store (T2). It belongs to the client that started it:
//! the worker cancels it before replacing that client, and cancels and waits
//! for it before it returns. Cancellation stops waiting at once, as
//! [`LOOKUP_TIMEOUT`] does: runtime shutdown gives the account's work only a
//! short bound, and a lookup has nothing of its own to finish. A cache write
//! the directory already handed to its blocking pool finishes there; the
//! directory opens no cache once storage is closed. Dropped unended, a
//! lookup aborts its task.

use std::time::Duration;

use cgka_traits::MemberId;
use marmot_session::WelcomeRouteLookup;
use nostr_directory::Directory;
use nostr_directory::error::DirectoryError;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::AppClient;
use crate::{AppError, CursorPersistence, MarmotApp};

/// How long one lookup may take, both hops (discovery relays, then the
/// recipient's advertised outboxes) included. One that takes longer failed.
pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A lookup the writer began: the recipient and what the task needs.
pub(crate) struct RouteLookupStart {
    recipient: MemberId,
    directory: Directory<MarmotApp>,
}

impl RouteLookupStart {
    /// Run the lookup beside the writer, until it ends, [`LOOKUP_TIMEOUT`]
    /// passes or `cancel` is cancelled.
    pub(crate) fn spawn(self, cancel: CancellationToken) -> RunningRouteLookup {
        let RouteLookupStart {
            recipient,
            directory,
        } = self;
        let account_id_hex = hex::encode(recipient.as_slice());
        let task = tokio::spawn(async move {
            let resolve = tokio::time::timeout(
                LOOKUP_TIMEOUT,
                // No relays named: the directory reads its configured
                // directory relays, else the operational ones.
                directory
                    .resolve_account_relay_list_status_for_account_id(&account_id_hex, Vec::new()),
            );
            tokio::select! {
                biased;
                () = cancel.cancelled() => None,
                resolved = resolve => Some(looked_up(resolved)),
            }
        });
        RunningRouteLookup { recipient, task }
    }
}

/// Whether a lookup answered: it found the recipient's lists, or found them
/// explicitly empty. No answer in time, a read no relay finished, a fetch
/// error or a cache error is a failed lookup.
fn looked_up(
    resolved: Result<
        Result<nostr_directory::AccountRelayListStatus, DirectoryError>,
        tokio::time::error::Elapsed,
    >,
) -> bool {
    matches!(
        resolved,
        Ok(Ok(_) | Err(DirectoryError::MissingRelayLists(_)))
    )
}

/// A lookup running beside the writer. Dropped unended, its task is aborted.
pub(crate) struct RunningRouteLookup {
    recipient: MemberId,
    task: JoinHandle<Option<bool>>,
}

impl Drop for RunningRouteLookup {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RunningRouteLookup {
    pub(crate) fn recipient(&self) -> &MemberId {
        &self.recipient
    }

    /// Whether the lookup answered, once its task ends; a cancelled lookup,
    /// or one whose task failed, did not. Cancel-safe until it
    /// returns; poll it no more after that.
    pub(crate) async fn result(&mut self) -> bool {
        matches!((&mut self.task).await, Ok(Some(true)))
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Wait for the task to end; cancel its token first to stop it.
    pub(crate) async fn end(mut self) {
        let _ = (&mut self.task).await;
    }
}

/// The lookups a worker should start and stop now.
pub(crate) struct RouteLookupPlan {
    pub(crate) start: Vec<RouteLookupStart>,
    pub(crate) stop: Vec<MemberId>,
}

impl AppClient {
    /// The lookups to start and stop, given the recipients of those
    /// `running`: at most `limit` running in all. Nothing starts while
    /// maintenance is paused or cursors are frozen, as for invite recovery:
    /// the owed lookups wait for a client that runs maintenance. A running
    /// lookup whose recipient no owed Welcome is addressed to any more stops.
    pub(crate) fn plan_welcome_route_lookups(
        &self,
        limit: usize,
        running: &[MemberId],
    ) -> RouteLookupPlan {
        let limit = if self.runtime.maintenance_is_paused()
            || self.app.cursor_persistence() == CursorPersistence::Frozen
        {
            0
        } else {
            limit
        };
        let plan = match self.runtime.plan_welcome_route_lookups(limit, running) {
            Ok(plan) => plan,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "plan_welcome_route_lookups",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "owed inbox lookups unreadable; retried on a later turn"
                );
                return RouteLookupPlan {
                    start: Vec::new(),
                    stop: Vec::new(),
                };
            }
        };
        RouteLookupPlan {
            start: plan
                .start
                .into_iter()
                .map(|recipient| RouteLookupStart {
                    recipient,
                    directory: self.app.directory(),
                })
                .collect(),
            stop: plan.stop,
        }
    }

    /// A lookup of `recipient`'s inbox list ended, answered or not: install
    /// the route the directory cache now gives, or why there is none, and
    /// tell the session what it found. Returns whether it found a route,
    /// which releases the recipient's retry, so the caller runs maintenance.
    pub(crate) fn finish_welcome_route_lookup(
        &self,
        recipient: &MemberId,
        answered: bool,
    ) -> Result<bool, AppError> {
        let route = self
            .app
            .member_inbox_route(&hex::encode(recipient.as_slice()))?;
        let outcome = match (&route, answered) {
            (Ok(_), _) => WelcomeRouteLookup::Routed,
            (Err(_), true) => WelcomeRouteLookup::NoRoute,
            (Err(_), false) => WelcomeRouteLookup::Failed,
        };
        self.routing.replace_inbox_route(recipient.clone(), route);
        self.runtime.finish_welcome_route_lookup(recipient, outcome);
        Ok(outcome == WelcomeRouteLookup::Routed)
    }
}
