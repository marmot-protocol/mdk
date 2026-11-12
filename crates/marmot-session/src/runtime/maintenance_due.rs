//! When session maintenance next has work (mdk#3265). The account worker
//! sleeps until [`MaintenanceDue::at`] instead of running maintenance on every
//! 15 s tick. `at` holds only stored times. Work owed with no stored time (a
//! send failure, an in-memory retry, a KeyPackage to build, a deadline still
//! to sample) is [`MaintenanceDue::retry_while_owed`], which the worker
//! retries 15 s after its last run while it lasts, as the tick did. Reporting
//! such work as due "now" would read as new work on every re-read and run
//! maintenance back to back.
use super::*;

/// The result of [`AccountDeviceRuntime::maintenance_due`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaintenanceDue {
    /// The earliest stored time at which maintenance has work. Only stored
    /// times: a time at or before now is work that came due then.
    pub at: Option<Timestamp>,
    /// Work with no stored time is owed: it is retried 15 s after the last
    /// run while it lasts.
    pub retry_while_owed: bool,
}

impl MaintenanceDue {
    /// Owed work with no stored time.
    fn owed(&mut self) {
        self.retry_while_owed = true;
    }

    fn at(&mut self, at: Timestamp) {
        self.at = Some(self.at.map_or(at, |earliest| earliest.min(at)));
    }

    fn at_opt(&mut self, at: Option<Timestamp>) {
        if let Some(at) = at {
            self.at(at);
        }
    }
}

/// When a fanout target's backoff ends, from the same rule the retry uses,
/// or `None` once it needs no retry.
fn target_retry_at(target: &TransportFanoutTarget) -> Option<Timestamp> {
    // The delay from time zero is the instant the backoff ends.
    transport_retry_delay_ms(target, 0).map(|ends_ms| Timestamp(ends_ms.div_ceil(1_000)))
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: crate::routing::TransportRoutingPolicy,
    K: crate::key_package::KeyPackagePublisher,
{
    /// When [`Self::run_due_maintenance_holding`] next has work. `held` gives
    /// each group the caller holds from new self-updates and when that hold
    /// ends (mdk#2258): a held group's owed self-update is due then, not
    /// every 15 s. It reads every live group's maintenance state and every
    /// obligation, so the caller runs it once per wake, not per loop turn.
    pub fn maintenance_due(&self, held: &[(GroupId, Timestamp)]) -> AccountResult<MaintenanceDue> {
        let mut due = MaintenanceDue::default();
        let now = self.wall_clock.now();
        self.key_package_due(now, &mut due)?;
        self.transport_fanouts_due(&mut due)?;
        if !self.watched_welcomes.is_empty() || !self.pending_leaf_reconciliations.is_empty() {
            due.owed();
        }
        let (recovery_at, coordinating) = self.group_recovery_due()?;
        due.at_opt(recovery_at.map(Timestamp));
        if coordinating {
            due.owed();
        }
        let obligations = self.session.maintenance_obligations()?;
        let open = |obligation: &&MaintenanceObligation| {
            !matches!(
                obligation.phase,
                MaintenancePhase::Complete | MaintenancePhase::Failed
            )
        };
        if !self.maintenance_paused {
            let elapsed = self.monotonic_clock.elapsed();
            for group_id in self.session.live_group_ids()? {
                let Some(state) = skips_group_this_tick(self.session.group_maintenance(&group_id))?
                else {
                    continue;
                };
                let state = state.as_ref();
                due.at_opt(state.and_then(|state| state.leaf_refresh_due_at));
                // The component check repeats on its own interval.
                match self.component_migration_checked_at.get(&group_id) {
                    Some(checked) => {
                        let wait = COMPONENT_MIGRATION_RECHECK
                            .saturating_sub(elapsed.saturating_sub(*checked));
                        due.at(Timestamp(now.0.saturating_add(wait.as_secs())));
                    }
                    None => due.owed(),
                }
                let Some(state) = state.filter(|state| state.periodic_enrolled) else {
                    continue;
                };
                if obligations
                    .iter()
                    .filter(open)
                    .any(|obligation| obligation.group_id == group_id)
                {
                    continue;
                }
                // A missing deadline is sampled on the next run.
                match state.next_periodic_rotation_at {
                    Some(at) => due.at(at),
                    None => due.owed(),
                }
            }
        }
        for obligation in obligations.iter().filter(open) {
            self.obligation_due(obligation, held, &mut due)?;
        }
        Ok(due)
    }

    fn obligation_due(
        &self,
        obligation: &MaintenanceObligation,
        held: &[(GroupId, Timestamp)],
        due: &mut MaintenanceDue,
    ) -> AccountResult<()> {
        if self
            .pending_leaf_reconciliations
            .contains_key(&obligation.group_id)
        {
            return Ok(());
        }
        let Some(group) = skips_group_this_tick(self.session.group_record(&obligation.group_id))?
        else {
            return Ok(());
        };
        // A terminal group's obligation is failed on the next run.
        if group.is_terminal() {
            due.owed();
            return Ok(());
        }
        match obligation.phase {
            MaintenancePhase::CatchUp => due.at_opt(obligation.eose_deadline_at),
            MaintenancePhase::EoseTimeout | MaintenancePhase::Grace => {
                match obligation.grace_until {
                    Some(at) => due.at(at),
                    None => due.owed(),
                }
            }
            MaintenancePhase::Quiet => match obligation.quiet_since {
                Some(since) => due.at(Timestamp(
                    since
                        .0
                        .saturating_add(self.maintenance_timing.quiet.as_secs()),
                )),
                None => due.owed(),
            },
            MaintenancePhase::Jitter => match obligation.not_before {
                Some(at) => due.at(at),
                None => due.owed(),
            },
            _ => {
                // A held group's self-update waits for its hold to end.
                if let Some((_, until)) =
                    held.iter().find(|(group, _)| *group == obligation.group_id)
                {
                    due.at(*until);
                } else if let Some(until) = self.commit_delivery_hold_until(&obligation.group_id)? {
                    due.at(until);
                } else {
                    due.owed();
                }
            }
        }
        Ok(())
    }

    /// When the commit-delivery hold on `group_id`'s self-update ends, if
    /// one holds it now.
    fn commit_delivery_hold_until(&self, group_id: &GroupId) -> AccountResult<Option<Timestamp>> {
        let now = self.wall_clock.now();
        Ok(self
            .undelivered_commit(group_id)?
            .map(|commit| {
                Timestamp(
                    commit
                        .since
                        .0
                        .saturating_add(COMMIT_DELIVERY_SELF_UPDATE_HOLD_SECS),
                )
            })
            .filter(|until| *until > now))
    }

    fn key_package_due(&self, now: Timestamp, due: &mut MaintenanceDue) -> AccountResult<()> {
        let Some(lifecycle) = self.session.key_package_lifecycle()? else {
            // Paused maintenance prepares no new KeyPackage.
            if !self.key_package_slot_withdrawn && !self.maintenance_paused {
                due.owed();
            }
            return Ok(());
        };
        // Private material expires whether or not maintenance is paused.
        due.at_opt(lifecycle.current_not_after);
        due.at_opt(
            lifecycle
                .pending_replacement
                .as_ref()
                .map(|pending| pending.not_after),
        );
        for material in &lifecycle.retained_private_material {
            due.at(material.delete_at());
        }
        if self.key_package_slot_withdrawn {
            return Ok(());
        }
        // The current publication's unacknowledged relays, at their backoff.
        if self.key_package_has_pending_fanout()? {
            for target in &lifecycle.publication_targets {
                due.at_opt(target_retry_at(target));
            }
        }
        // Paused maintenance finishes publishing what is prepared and
        // prepares nothing new, as the run does.
        match lifecycle.pending_replacement.as_ref() {
            Some(pending)
                if self.pending_replacement_obsolete(&lifecycle, pending)
                    || pending.signed_event.is_none() =>
            {
                if !self.maintenance_paused {
                    due.owed();
                }
            }
            Some(pending) => {
                for target in &pending.targets {
                    due.at_opt(target_retry_at(target));
                }
            }
            None if self.maintenance_paused => {}
            None if lifecycle.last_consumed_key_package_ref
                == lifecycle.current_key_package_ref
                || self.current_key_package_replacement_due(&lifecycle, now) =>
            {
                due.owed();
            }
            None => due.at_opt(self.key_package_maintenance_next_due()?),
        }
        Ok(())
    }

    fn transport_fanouts_due(&self, due: &mut MaintenanceDue) -> AccountResult<()> {
        let mut confirmed = None::<Vec<cgka_traits::MessageId>>;
        for fanout in self.session.transport_fanouts()? {
            due.at_opt(fanout.bounded_until);
            // An unconfirmed evolution's relays wait for its confirmation.
            // The run re-derives a confirmation whose marker write failed,
            // so this does too.
            if let Some(evolution_id) = fanout.evolution_id.as_ref()
                && !fanout.evolution_confirmed
            {
                if confirmed.is_none() {
                    confirmed = Some(
                        self.session
                            .group_evolutions()?
                            .into_iter()
                            .filter(|evolution| evolution.phase == GroupEvolutionPhase::Confirmed)
                            .map(|evolution| evolution.id)
                            .collect(),
                    );
                }
                if !confirmed
                    .as_ref()
                    .is_some_and(|confirmed| confirmed.contains(evolution_id))
                {
                    continue;
                }
            }
            for target in &fanout.targets {
                due.at_opt(target_retry_at(target));
            }
        }
        Ok(())
    }
}
