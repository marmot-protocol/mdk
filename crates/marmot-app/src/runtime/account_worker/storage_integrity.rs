//! Periodic detection after readiness, using only fixed diagnostic categories.
use crate::AppClient;
use cgka_session::SessionError;
use cgka_traits::storage::StorageError;
use std::time::{Duration, Instant};
use storage_sqlite::IntegrityProbe;

const INTERVAL: Duration = Duration::from_secs(120);
const BUDGET: Duration = Duration::from_secs(1);
const INCOMPLETE_ALERT_THRESHOLD: u32 = 3;

pub(super) struct Schedule {
    next: Instant,
    pending: Option<tokio::task::JoinHandle<Result<IntegrityProbe, SessionError>>>,
    pending_counted_incomplete: bool,
    consecutive_incomplete: u32,
}

impl Schedule {
    pub(super) fn new() -> Self {
        Self {
            next: Instant::now(),
            pending: None,
            pending_counted_incomplete: false,
            consecutive_incomplete: 0,
        }
    }

    pub(super) async fn tick(&mut self, client: &AppClient) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.is_finished())
        {
            let pending = self.pending.take().expect("finished probe exists");
            self.observe(pending.await);
        }
        // Never stack checks behind the one connection's mutex. A probe that
        // outlives an entire interval still counts as incomplete so a blocked
        // connection cannot silently suppress health alerts forever.
        if self.pending.is_some() {
            if Instant::now() >= self.next {
                self.record_incomplete();
                self.pending_counted_incomplete = true;
                self.next = Instant::now() + INTERVAL;
            }
            return;
        }
        if Instant::now() < self.next {
            return;
        }
        self.next = Instant::now() + INTERVAL;
        self.pending = Some(
            client
                .runtime
                .session()
                .spawn_storage_integrity_probe(BUDGET),
        );
        self.pending_counted_incomplete = false;
    }

    fn observe(
        &mut self,
        outcome: Result<Result<IntegrityProbe, SessionError>, tokio::task::JoinError>,
    ) {
        match outcome {
            Ok(Ok(IntegrityProbe::Healthy)) => {
                self.consecutive_incomplete = 0;
                tracing::debug!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "healthy",
                "account storage structural integrity check completed"
                );
            }
            Ok(Ok(IntegrityProbe::Corrupt)) => {
                self.consecutive_incomplete = 0;
                tracing::error!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "corrupt",
                "account storage integrity check failed; operator recovery required"
                );
            }
            Ok(Err(SessionError::Storage(StorageError::Closed(_)))) => {}
            Ok(Ok(IntegrityProbe::Incomplete)) | Ok(Err(_)) | Err(_) => {
                if !self.pending_counted_incomplete {
                    self.record_incomplete();
                }
            }
        }
        self.pending_counted_incomplete = false;
    }

    fn record_incomplete(&mut self) {
        self.consecutive_incomplete = self.consecutive_incomplete.saturating_add(1);
        if self.consecutive_incomplete >= INCOMPLETE_ALERT_THRESHOLD {
            tracing::error!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "incomplete",
                consecutive_incomplete = self.consecutive_incomplete,
                "account storage integrity has not completed; operator attention required"
            );
        } else {
            tracing::warn!(
                target: "marmot_app::storage_integrity",
                method = "periodic_probe", status = "incomplete",
                "account storage integrity check incomplete; health is unknown"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_streak_resets_only_after_a_completed_check() {
        let mut schedule = Schedule::new();
        for expected in 1..=INCOMPLETE_ALERT_THRESHOLD {
            schedule.observe(Ok(Ok(IntegrityProbe::Incomplete)));
            assert_eq!(schedule.consecutive_incomplete, expected);
        }
        schedule.observe(Ok(Err(SessionError::Storage(StorageError::Closed(
            "test close".to_owned(),
        )))));
        assert_eq!(schedule.consecutive_incomplete, INCOMPLETE_ALERT_THRESHOLD);
        schedule.observe(Ok(Ok(IntegrityProbe::Healthy)));
        assert_eq!(schedule.consecutive_incomplete, 0);
    }

    #[test]
    fn overdue_then_incomplete_counts_as_one_interval() {
        let mut schedule = Schedule::new();
        schedule.record_incomplete();
        schedule.pending_counted_incomplete = true;
        schedule.observe(Ok(Ok(IntegrityProbe::Incomplete)));
        assert_eq!(schedule.consecutive_incomplete, 1);
        schedule.observe(Ok(Ok(IntegrityProbe::Incomplete)));
        assert_eq!(schedule.consecutive_incomplete, 2);
    }
}
