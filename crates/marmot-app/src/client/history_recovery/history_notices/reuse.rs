//! The account's recovery answer as A keeps it from one publish to the next
//! (mdk#3273): what it was read at, and whether it still holds. It reads the
//! two recovery queries, the routes in memory, the runner's survey and the
//! facts of each group it names. Each moves a field here, and no time is an
//! input, so the answer has no `valid_until`.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::sync::Arc;

use marmot_session::ChangeStamp;

use super::{Fact, GroupFacts, RecoveryRead};
use crate::client::AppClient;
use crate::{AccountRecoveryStatus, AppError};

/// What the account's recovery answer is read at besides its groups' facts.
/// Read before the answer's own reads, so a change that lands during them
/// ends the reuse at the next publish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryInputs {
    /// The account database's recovery-notice write count: every write to a
    /// recovery obligation or a recovery copy, through any connection this
    /// process has open on it, and every change of the file it cannot
    /// attribute. `None` once the database is closed.
    notice_writes: Option<u64>,
    /// The routing's version: the routes in memory decide which rejoin
    /// notices show and which group a unit catching up names.
    routes: u64,
}

#[cfg_attr(not(test), allow(dead_code))] // A reads them at every publish (mdk#3273 PR 8).
impl AppClient {
    /// The account recovery answer's inputs now ([`RecoveryInputs`]).
    pub(crate) fn recovery_inputs(&self) -> RecoveryInputs {
        RecoveryInputs {
            notice_writes: (!self.engine_storage.is_closed())
                .then(|| self.engine_storage.recovery_notice_write_count()),
            routes: self.routing.version(),
        }
    }
}

/// The account's recovery status with the read it was built from, and what
/// both were read at. Not `Debug`: the read carries groups.
pub(crate) struct RecoveryAnswer {
    /// A builds each group's notices from the same read.
    read: Result<RecoveryRead, Arc<AppError>>,
    status: Result<AccountRecoveryStatus, Arc<AppError>>,
    validity: RecoveryValidity,
}

/// What a [`RecoveryAnswer`] was read at. The runner's survey is the read's
/// own [`super::SurveyMark`].
struct RecoveryValidity {
    inputs: RecoveryInputs,
    /// Each group the status asked a fact of, with the stamp its facts were
    /// read at.
    groups: Vec<(Vec<u8>, ChangeStamp)>,
    /// False when the read failed, or the status used a fact that did not
    /// settle or had no stamp: a group outside the mirror, or live facts.
    reusable: bool,
}

#[cfg_attr(not(test), allow(dead_code))] // A keeps it (mdk#3273 PR 8).
impl RecoveryAnswer {
    /// The answer from `read`, whose inputs were at `inputs` before it, with
    /// the account status built with `facts`.
    pub(crate) fn build(
        inputs: RecoveryInputs,
        read: Result<RecoveryRead, AppError>,
        facts: &dyn GroupFacts,
    ) -> Self {
        let read = read.map_err(Arc::new);
        let recorder = Recorder::new(facts);
        let status = match &read {
            Ok(read) => Ok(read.account_status(&recorder)),
            Err(error) => Err(Arc::clone(error)),
        };
        let (groups, facts_reusable) = recorder.finish();
        Self {
            validity: RecoveryValidity {
                inputs,
                groups,
                reusable: read.is_ok() && facts_reusable,
            },
            read,
            status,
        }
    }

    /// Whether the answer still holds with its inputs now at `inputs` and
    /// each group's change stamp now at `stamp`: no input moved, no survey
    /// changed what is catching up since the read, and no group the status
    /// asked a fact of moved or left the mirror (`stamp` gives `None`).
    pub(crate) fn holds(
        &self,
        inputs: &RecoveryInputs,
        stamp: &dyn Fn(&[u8]) -> Option<ChangeStamp>,
    ) -> bool {
        let validity = &self.validity;
        validity.reusable
            && validity.inputs.notice_writes.is_some()
            && validity.inputs.notice_writes == inputs.notice_writes
            && validity.inputs.routes == inputs.routes
            && self
                .read
                .as_ref()
                .is_ok_and(|read| !read.survey().landed_since())
            && validity
                .groups
                .iter()
                .all(|(group, at)| stamp(group).is_some_and(|now| now.unchanged_since(at)))
    }

    /// The read the status was built from.
    pub(crate) fn read(&self) -> Result<&RecoveryRead, &Arc<AppError>> {
        self.read.as_ref()
    }

    pub(crate) fn status(&self) -> &Result<AccountRecoveryStatus, Arc<AppError>> {
        &self.status
    }

    /// How the status differs from the client's live one now, or `None`.
    /// The notices are compared strictly. What is catching up is compared
    /// strictly unless a survey changed it after the read: the runner writes
    /// its survey off the worker (decision 2). A failure matches a failure
    /// of the same form.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn differs_from_live(&self, client: &AppClient) -> Option<&'static str> {
        match (&self.status, &client.account_recovery_status()) {
            (Ok(ours), Ok(live)) => {
                if ours.notices != live.notices {
                    return Some("history notices");
                }
                let surveyed = self
                    .read
                    .as_ref()
                    .is_ok_and(|read| read.survey().landed_since());
                let catching_up = ours.catching_up_group_ids_hex == live.catching_up_group_ids_hex
                    && ours.inbox_catching_up == live.inbox_catching_up;
                (!surveyed && !catching_up).then_some("catching up")
            }
            (Err(ours), Err(live)) if format!("{ours:?}") == format!("{live:?}") => None,
            _ => Some("success or failure"),
        }
    }
}

/// [`GroupFacts`] that note each group asked of, and whether every fact
/// asked settled.
struct Recorder<'a> {
    facts: &'a dyn GroupFacts,
    asked: RefCell<BTreeSet<Vec<u8>>>,
    settled: Cell<bool>,
}

impl<'a> Recorder<'a> {
    fn new(facts: &'a dyn GroupFacts) -> Self {
        Self {
            facts,
            asked: RefCell::default(),
            settled: Cell::new(true),
        }
    }

    fn note(&self, group_id: &[u8], fact: Fact) -> Fact {
        let mut asked = self.asked.borrow_mut();
        if !asked.contains(group_id) {
            asked.insert(group_id.to_vec());
        }
        self.settled.set(self.settled.get() && fact.settled);
        fact
    }

    /// Each group asked of with its stamp, and whether an answer built with
    /// these facts may be kept: every fact settled and every group had a
    /// stamp.
    fn finish(self) -> (Vec<(Vec<u8>, ChangeStamp)>, bool) {
        let mut reusable = self.settled.get();
        let groups = self
            .asked
            .into_inner()
            .into_iter()
            .filter_map(|group| match self.facts.stamp(&group) {
                Some(stamp) => Some((group, stamp)),
                None => {
                    reusable = false;
                    None
                }
            })
            .collect();
        (groups, reusable)
    }
}

impl GroupFacts for Recorder<'_> {
    fn host_may_see(&self, group_id: &[u8]) -> Fact {
        self.note(group_id, self.facts.host_may_see(group_id))
    }

    fn unrecoverable(&self, group_id: &[u8]) -> Fact {
        self.note(group_id, self.facts.unrecoverable(group_id))
    }

    fn stamp(&self, group_id: &[u8]) -> Option<ChangeStamp> {
        self.facts.stamp(group_id)
    }
}

#[cfg(test)]
mod tests;
