//! The observed-operation combinator (#2627): begin a product observation, run the work, then
//! finish with the outcome a rule picks from its result. It is what replaces a public method's
//! `_unobserved` twin.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "#2627 PR 8 converts the `_unobserved` operation pairs to this combinator"
    )
)]

use super::{ProductAnalytics, ProductFamily, ProductObservation, ProductUnit};
use cgka_traits::SendAcceptDisposition;

/// One product operation, begun when it is built. Dropping it before its work finishes records
/// `cancelled`. With diagnostics off it holds no observation: its work still runs and nothing is
/// recorded.
#[must_use = "an observed operation runs nothing until it is given its work"]
pub(crate) struct ObservedOperation(Option<ProductObservation>);

impl ProductAnalytics {
    pub(crate) fn observed(
        &self,
        family: ProductFamily,
        operation: &'static str,
        unit: ProductUnit,
    ) -> ObservedOperation {
        ObservedOperation(self.begin(family, operation, unit))
    }
}

impl ObservedOperation {
    /// Run `work`, then finish with the outcome `rule` picks from its result.
    pub(crate) fn run<T>(
        self,
        work: impl FnOnce() -> T,
        rule: impl FnOnce(&T) -> &'static str,
    ) -> T {
        let output = work();
        self.finish(&output, rule);
        output
    }

    /// Await `work`, then finish with the outcome `rule` picks from its result.
    pub(crate) async fn run_async<T>(
        self,
        work: impl Future<Output = T>,
        rule: impl FnOnce(&T) -> &'static str,
    ) -> T {
        let output = work.await;
        self.finish(&output, rule);
        output
    }

    fn finish<T>(self, output: &T, rule: impl FnOnce(&T) -> &'static str) {
        if let Some(observation) = self.0 {
            observation.finish(rule(output));
        }
    }
}

/// `success` or `failure`: the rule most operations use.
pub fn success_or_failure<T, E>(result: &Result<T, E>) -> &'static str {
    if result.is_ok() { "success" } else { "failure" }
}

/// `confirmed` or `failure`: Welcome redelivery.
pub(crate) fn confirmed_or_failure<T, E>(result: &Result<T, E>) -> &'static str {
    if result.is_ok() {
        "confirmed"
    } else {
        "failure"
    }
}

/// A send's outcome: `confirmed`, `pending` or `unknown` by how the engine accepted it, or
/// `rejected`.
pub(crate) fn send_outcome<T, E>(
    result: &Result<T, E>,
    accepted: impl FnOnce(&T) -> SendAcceptDisposition,
) -> &'static str {
    match result.as_ref().map(accepted) {
        Ok(SendAcceptDisposition::Published) => "confirmed",
        Ok(SendAcceptDisposition::AcceptedPending) => "pending",
        Ok(SendAcceptDisposition::CompletionUnknown) => "unknown",
        Err(_) => "rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::configured;
    use super::*;
    use cgka_traits::SendAcceptDisposition::Published;

    /// A configured collector that was never granted consent has diagnostics off: every form
    /// and rule still runs its work and returns its result.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn diagnostics_off_runs_the_work_and_records_nothing() {
        let (collector, _clock) = configured();
        let observed =
            || collector.observed(ProductFamily::Sync, "full_history", ProductUnit::Action);
        let mut ran = 0;

        assert_eq!(
            observed().run(
                || {
                    ran += 1;
                    Ok::<_, ()>(1)
                },
                success_or_failure
            ),
            Ok(1)
        );
        assert_eq!(
            observed().run(
                || {
                    ran += 1;
                    Err::<(), _>(2)
                },
                confirmed_or_failure
            ),
            Err(2)
        );
        assert_eq!(
            observed()
                .run_async(async { Ok::<_, ()>(Published) }, |result| send_outcome(
                    result,
                    |d| *d
                ))
                .await,
            Ok(Published)
        );
        assert_eq!(ran, 2);
        assert_eq!(collector.status().queued_events, 0);
        #[cfg(feature = "product-analytics-export")]
        assert!(collector.test_payloads().is_empty());
    }

    /// Each row runs one observed operation on a freshly granted collector and lists what it
    /// recorded: `(event, operation, outcome)`.
    #[cfg(feature = "product-analytics-export")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn each_rule_picks_its_outcome_and_a_dropped_operation_records_cancelled() {
        use crate::product_analytics::{UsageDiagnosticsDecision, UsageDiagnosticsSettings};
        use cgka_traits::SendAcceptDisposition::{AcceptedPending, CompletionUnknown};

        async fn row<F: Future<Output = ()>>(
            label: &str,
            expected: &[(&str, &str, &str)],
            run: impl FnOnce(ProductAnalytics) -> F,
        ) {
            let (collector, _clock) = configured();
            collector.set_receipt(
                UsageDiagnosticsSettings {
                    decision: UsageDiagnosticsDecision::Granted,
                    ..Default::default()
                },
                "observed-operation-test".into(),
            );
            run(collector.clone()).await;
            // Sealing also adds the window's coverage row, which carries no outcome.
            let recorded: Vec<_> = collector
                .test_payloads()
                .iter()
                .filter_map(|row| {
                    let props = &row["props"];
                    Some((
                        row["eventName"].as_str()?.to_owned(),
                        props["operation"].as_str()?.to_owned(),
                        props["outcome"].as_str()?.to_owned(),
                    ))
                })
                .collect();
            let expected: Vec<_> = expected
                .iter()
                .map(|(event, operation, outcome)| {
                    (
                        event.to_string(),
                        operation.to_string(),
                        outcome.to_string(),
                    )
                })
                .collect();
            assert_eq!(recorded, expected, "{label}");
        }
        const SYNC: &str = "mdk_sync_summary";
        let sync = |c: &ProductAnalytics| {
            c.observed(ProductFamily::Sync, "full_history", ProductUnit::Action)
        };
        let send = |c: &ProductAnalytics| {
            c.observed(ProductFamily::MessageAction, "text", ProductUnit::Action)
        };
        let send_rule = |result: &Result<SendAcceptDisposition, ()>| send_outcome(result, |d| *d);

        row(
            "success",
            &[(SYNC, "full_history", "success")],
            |c| async move {
                assert_eq!(sync(&c).run(|| Ok::<_, ()>(7), success_or_failure), Ok(7));
            },
        )
        .await;
        row(
            "failure",
            &[(SYNC, "full_history", "failure")],
            |c| async move {
                let result = sync(&c).run_async(async { Err::<(), _>("boom") }, success_or_failure);
                assert_eq!(result.await, Err("boom"));
            },
        )
        .await;
        for (accepted, outcome) in [
            (Ok(Published), "confirmed"),
            (Ok(AcceptedPending), "pending"),
            (Ok(CompletionUnknown), "unknown"),
            (Err(()), "rejected"),
        ] {
            row(
                outcome,
                &[("mdk_message_action_summary", "text", outcome)],
                |c| async move {
                    assert_eq!(
                        send(&c).run_async(async { accepted }, send_rule).await,
                        accepted
                    );
                },
            )
            .await;
        }
        for (result, outcome) in [(Ok(()), "confirmed"), (Err(()), "failure")] {
            row(
                outcome,
                &[("mdk_welcome_summary", "retry", outcome)],
                |c| async move {
                    let welcome = c.observed(ProductFamily::Welcome, "retry", ProductUnit::Attempt);
                    assert_eq!(welcome.run(|| result, confirmed_or_failure), result);
                },
            )
            .await;
        }
        // Wake collection's rule: whether the collection reported an error.
        row(
            "custom",
            &[("mdk_notification_summary", "schedule", "failure")],
            |c| async move {
                let collected = c
                    .observed(
                        ProductFamily::Notification,
                        "schedule",
                        ProductUnit::Attempt,
                    )
                    .run(
                        || Some("catch-up failed"),
                        |error: &Option<&str>| {
                            if error.is_none() {
                                "success"
                            } else {
                                "failure"
                            }
                        },
                    );
                assert_eq!(collected, Some("catch-up failed"));
            },
        )
        .await;
        row(
            "dropped before its work",
            &[(SYNC, "full_history", "cancelled")],
            |c| async move {
                drop(sync(&c));
            },
        )
        .await;
        row(
            "dropped while its work waits",
            &[(SYNC, "full_history", "cancelled")],
            |c| async move {
                let pending = std::future::pending::<Result<(), ()>>();
                let waiting = sync(&c).run_async(pending, success_or_failure);
                assert!(
                    tokio::time::timeout(std::time::Duration::ZERO, waiting)
                        .await
                        .is_err()
                );
            },
        )
        .await;
        row("consent revoked while its work runs", &[], |c| async move {
            let revoked = sync(&c).run(
                || {
                    c.revoke_memory();
                    Ok::<_, ()>(())
                },
                success_or_failure,
            );
            assert_eq!(revoked, Ok(()));
        })
        .await;
    }
}
