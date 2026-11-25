//! A Welcome pass asks each of its inbox relays on its own.
//!
//! One request to many relays stops at its acknowledgement goal and drops
//! the answers still to come, so a Welcome reached only the first relay that
//! took it, and a relay that takes gift wraps it cannot serve back could be
//! that one. A pass with more relays than its goal sends one request per relay
//! instead (`relay_sends`). It is done once its answers meet its goal, or all
//! have answered (`until_met`), and its answers are joined into the result
//! one request would have given (`join_relay_answers`).
//!
//! A detached wave settles each pass as before, while the relays still
//! answering go on as the wave's remaining pass ([`RemainingWelcomeSends`]),
//! which the host runs and finishes as a wave of its own. Its finish records
//! the late answers on the Welcome's retry record without counting a new
//! attempt (`finish_remaining_pass`), and in the same write on its delivery
//! record, if it has one, as counts of the whole attempt. The pass has its own
//! `welcome_publish_started`/`_finished` rows. A remaining pass that is
//! cancelled before it finishes records nothing: both records stay as its
//! first pass left them, so those relays are retried after their backoff, as a
//! relay the first pass did not hear from always was, and its started row has
//! no finished row.

use super::*;
use futures::future::BoxFuture;
use std::task::Poll;

/// What one relay request of a pass answered, with the relays it asked.
pub(super) type RelayAnswer = (
    Vec<TransportEndpoint>,
    Result<TransportPublishReport, TransportAdapterError>,
);

/// One relay request of a pass, as the transport runs it.
pub(super) type RelayPublish<'a> =
    BoxFuture<'a, Result<TransportPublishReport, TransportAdapterError>>;

/// The relay requests of a pass still to answer. A pass polls them in turn
/// itself: a `FuturesUnordered` wakes its caller each time it has polled them
/// all, which would read to the wave as an attempt that yields.
pub(super) type RelaySends<'a> = Vec<BoxFuture<'a, RelayAnswer>>;

/// The requests of the pass `request` describes: one per relay when it names
/// more relays than its goal, so each relay's answer counts on its own;
/// otherwise `request` itself, since every relay must answer anyway.
pub(super) fn relay_sends<'a, S>(send: &S, request: &TransportPublishRequest) -> RelaySends<'a>
where
    S: Fn(TransportPublishRequest) -> RelayPublish<'a>,
{
    let endpoints = request.target.endpoints();
    let requests = match asked_one_by_one(endpoints, request.required_acks) {
        None => vec![(endpoints.to_vec(), request.clone())],
        Some(distinct) => distinct
            .iter()
            .map(|endpoint| {
                (
                    vec![endpoint.clone()],
                    TransportPublishRequest {
                        account_id: request.account_id.clone(),
                        message: request.message.clone(),
                        target: publish_target_with_endpoints(
                            &request.target,
                            vec![endpoint.clone()],
                        ),
                        required_acks: 1,
                    },
                )
            })
            .collect(),
    };
    requests
        .into_iter()
        .map(|(asked, request)| {
            let publish = send(request);
            async move { (asked, publish.await) }.boxed()
        })
        .collect()
}

/// The most relays a pass asks one by one. A longer route goes out as one
/// request over all of them, as every route did before passes asked relay by
/// relay, so a transport that limits a route's relays still judges it whole.
/// The count is of the route as given, before the transport drops any relay
/// it will not use; such a pass stops at its goal, as it did before.
const MAX_RELAYS_ASKED_ONE_BY_ONE: usize = 16;

/// The relays a pass asks one by one: each distinct relay of `endpoints`,
/// when there are more of them than the goal and no more than
/// [`MAX_RELAYS_ASKED_ONE_BY_ONE`]. `None` when one request over all of them
/// does. A relay named twice is one relay: asked twice, it would meet a goal
/// of two on its own.
fn asked_one_by_one(
    endpoints: &[TransportEndpoint],
    required_acks: usize,
) -> Option<Vec<TransportEndpoint>> {
    let mut distinct = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        if !distinct.contains(endpoint) {
            distinct.push(endpoint.clone());
        }
    }
    (required_acks.max(1) + 1..=MAX_RELAYS_ASKED_ONE_BY_ONE)
        .contains(&distinct.len())
        .then_some(distinct)
}

/// Run `sends` until their answers meet `required_acks`, or all have
/// answered. Every request is polled once before the pass is done, so each
/// is started under the hold check that started the pass. Returns the
/// answers, and the requests still waiting for theirs.
pub(super) async fn until_met(
    mut sends: RelaySends<'_>,
    required_acks: usize,
) -> (Vec<RelayAnswer>, RelaySends<'_>) {
    let goal = required_acks.max(1);
    let mut answers = Vec::new();
    let mut accepted = 0;
    futures::future::poll_fn(|cx| {
        let mut at = 0;
        while at < sends.len() {
            match sends[at].poll_unpin(cx) {
                Poll::Ready(answer) => {
                    drop(sends.swap_remove(at));
                    if let Ok(report) = &answer.1 {
                        accepted += report.accepted.len();
                    }
                    answers.push(answer);
                }
                Poll::Pending => at += 1,
            }
        }
        if sends.is_empty() || accepted >= goal {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    (answers, sends)
}

/// The result one request over all of `request`'s relays would have given
/// for `answers`: the answer itself when there is one; otherwise a report of
/// every receipt and failure when any relay accepted, or no request failed,
/// and else the failure of every relay. A request that failed naming no relay
/// leaves each relay it asked unknown, and when every request failed so, the
/// first error stands for all.
pub(super) fn join_relay_answers(
    request: &TransportPublishRequest,
    mut answers: Vec<RelayAnswer>,
) -> Result<TransportPublishReport, TransportAdapterError> {
    if answers.len() == 1 {
        return answers.pop().expect("one answer").1;
    }
    let count = answers.len();
    let mut message_id = None;
    let mut accepted = Vec::new();
    let mut failed = Vec::new();
    let mut failed_requests = 0;
    let mut unnamed = Vec::new();
    for (asked, result) in answers {
        match result {
            Ok(report) => {
                message_id.get_or_insert(report.message_id);
                accepted.extend(report.accepted);
                failed.extend(report.failed);
            }
            Err(error) => {
                failed_requests += 1;
                if let Some(id) = error.publish_message_id() {
                    message_id.get_or_insert_with(|| id.clone());
                }
                if error.publish_endpoint_failures().is_empty() {
                    failed.extend(asked.into_iter().map(ambiguous_endpoint_failure));
                    unnamed.push(error);
                } else {
                    failed.extend(error.publish_endpoint_failures().iter().cloned());
                }
            }
        }
    }
    let message_id = message_id.unwrap_or_else(|| request.message.id.clone());
    if !accepted.is_empty() || failed_requests == 0 {
        return Ok(TransportPublishReport {
            message_id,
            accepted,
            failed,
            required_acks: request.required_acks,
        });
    }
    if unnamed.len() == count {
        return Err(unnamed.swap_remove(0));
    }
    let summary = cgka_traits::collapse_publish_failure_summaries(
        failed.iter().map(|failure| failure.reason.as_str()),
    );
    Err(TransportAdapterError::PublishEndpoints(
        cgka_traits::TransportPublishFailure::with_endpoint_failures(summary, failed)
            .with_message_id(message_id),
    ))
}

/// The relays a wave's passes were still waiting on when the wave was done,
/// still asking. A detached wave hands them to its host
/// (`CompletedWelcomePublishTask::take_remaining`); dropping them stops them.
pub(super) struct RemainingWelcomeSends<'a> {
    /// Each request, answering with the index of its pass in the wave. Only
    /// its owner polls it; the lock keeps a task that holds it `Sync`.
    sends: std::sync::Mutex<FuturesUnordered<BoxFuture<'a, (usize, RelayAnswer)>>>,
    passes: Vec<(usize, RemainingPass)>,
    group_id: Option<GroupId>,
    audit: SharedRecorder,
}

/// The relays one pass left still answering.
pub(super) struct RemainingPass {
    welcome_id: cgka_traits::MessageId,
    /// The group of the Welcome, when its wave knows it.
    group_id: Option<GroupId>,
    endpoints: Vec<TransportEndpoint>,
    /// Each relay's stored attempt count before the first pass, for every
    /// relay that pass asked.
    attempts_before: Vec<(TransportEndpoint, u32)>,
    /// Every relay the first pass asked, and what those that answered it
    /// said. The Welcome's delivery counts are those of the whole attempt
    /// (mdk#1706), and when the first pass's record was not saved its
    /// answers are recorded here.
    first_attempted: Vec<TransportEndpoint>,
    first_report: TransportPublishReport,
    /// Whether an error of the first pass may have reached a relay.
    first_exposure: bool,
    v5_welcome: Option<V5WelcomePass>,
    /// The Welcome's acknowledgement policy.
    required_acks: usize,
    answers: Vec<RelayAnswer>,
}

impl<'a> RemainingWelcomeSends<'a> {
    pub(super) fn new(
        sends: FuturesUnordered<BoxFuture<'a, (usize, RelayAnswer)>>,
        group_id: Option<GroupId>,
        audit: SharedRecorder,
    ) -> Self {
        Self {
            sends: std::sync::Mutex::new(sends),
            passes: Vec::new(),
            group_id,
            audit,
        }
    }

    /// Keep the pass `index` of the wave, the Welcome of `group_id` that
    /// `attempt` sent, if relays it asked are not among those that `answers`
    /// answered: their requests are among the sends still running.
    pub(super) fn push(
        &mut self,
        index: usize,
        attempt: &PreparedLegacyPublishAttempt,
        group_id: Option<GroupId>,
        answers: &[RelayAnswer],
    ) {
        let answered = answers
            .iter()
            .flat_map(|(asked, _)| asked.iter())
            .collect::<HashSet<_>>();
        let endpoints = attempt
            .retry_endpoints
            .iter()
            .filter(|endpoint| !answered.contains(endpoint))
            .cloned()
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            return;
        }
        let accepted = attempt.accepted_before
            + answers
                .iter()
                .filter_map(|(_, result)| result.as_ref().ok())
                .map(|report| report.accepted.len())
                .sum::<usize>();
        let v5_welcome = attempt
            .v5_welcome
            .as_ref()
            .and_then(|pass| pass.remaining(&endpoints, accepted));
        let attempts_before = attempt
            .fanout
            .targets
            .iter()
            .filter(|target| attempt.retry_endpoints.contains(&target.endpoint))
            .map(|target| (target.endpoint.clone(), target.attempt_count))
            .collect();
        let first_exposure = answers.iter().any(|(asked, result)| {
            result
                .as_ref()
                .is_err_and(|error| !publish_error_reached_no_relay(error, asked))
        });
        self.passes.push((
            index,
            RemainingPass {
                welcome_id: attempt.message_id.clone(),
                group_id,
                endpoints,
                attempts_before,
                first_attempted: attempt.retry_endpoints.clone(),
                first_report: joined_report(&attempt.message_id, attempt.required_acks, answers),
                first_exposure,
                v5_welcome,
                required_acks: attempt.required_acks,
                answers: Vec::new(),
            },
        ));
    }

    pub(super) fn is_empty(&self) -> bool {
        self.passes.is_empty()
    }

    /// The Welcomes whose relays are still answering.
    pub(super) fn message_ids(&self) -> Vec<cgka_traits::MessageId> {
        self.passes
            .iter()
            .map(|(_, pass)| pass.welcome_id.clone())
            .collect()
    }

    /// Record each pass's started row: its relays now answer to it.
    pub(super) fn start(&mut self) {
        for (_, pass) in &mut self.passes {
            if let Some(v5) = pass.v5_welcome.as_mut() {
                v5.start(&self.audit);
            }
        }
    }

    /// Wait for every relay's answer, each bounded by the transport's own
    /// publish deadline.
    pub(super) async fn run(mut self) -> CompletedWelcomePublish {
        let mut sends = std::mem::take(
            self.sends
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        while let Some((index, answer)) = sends.next().await {
            if let Some((_, pass)) = self.passes.iter_mut().find(|(at, _)| *at == index) {
                pass.answers.push(answer);
            }
        }
        let (metadata, completions) = self
            .passes
            .into_iter()
            .map(|(_, pass)| {
                (
                    WelcomePublishMetadata {
                        recipient: None,
                        welcome_id: pass.welcome_id.clone(),
                        group_id: pass.group_id.clone(),
                        effects: AccountDeviceEffects::default(),
                    },
                    Some(LegacyPublishCompletion::Remaining(Box::new(pass))),
                )
            })
            .unzip();
        CompletedWelcomePublish {
            group_id: self.group_id,
            metadata,
            completions,
            audit: self.audit,
        }
    }
}

/// Every receipt and named failure of `answers`, as one report.
fn joined_report(
    welcome_id: &cgka_traits::MessageId,
    required_acks: usize,
    answers: &[RelayAnswer],
) -> TransportPublishReport {
    let mut report = TransportPublishReport {
        message_id: welcome_id.clone(),
        accepted: Vec::new(),
        failed: Vec::new(),
        required_acks,
    };
    for (_, result) in answers {
        match result {
            Ok(answer) => {
                report.accepted.extend(answer.accepted.iter().cloned());
                report.failed.extend(answer.failed.iter().cloned());
            }
            Err(error) => report
                .failed
                .extend(error.publish_endpoint_failures().iter().cloned()),
        }
    }
    report
}

impl RemainingPass {
    /// Every receipt and named failure of the pass's answers, as its finished
    /// row reads them.
    fn report(&self) -> TransportPublishReport {
        joined_report(&self.welcome_id, self.required_acks, &self.answers)
    }

    /// Record this pass's finished row from its answers, with no stored
    /// outcome: for a pass whose results are dropped unreconciled.
    pub(super) fn record_dropped(&self, audit: &SharedRecorder) {
        if let Some(v5) = &self.v5_welcome {
            v5.record_dropped(
                audit,
                &Ok(self.report()),
                &self.endpoints,
                self.required_acks,
            );
        }
    }
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Record what the relays of a remaining pass answered on the Welcome's
    /// retry record, and on its delivery record in the same write. Its first
    /// pass counted and dated their attempt and left them failed, so each
    /// answer only says how that attempt ended: an acceptance, a refusal, or
    /// a possible exposure. When the first pass's record could not be saved,
    /// this pass records that whole attempt: every relay the first pass
    /// asked is counted and dated, with what it or this pass answered. When
    /// the record cannot be read or saved, the finished row still records the
    /// relays' answers, with no stored total. The first pass met the
    /// Welcome's policy, so this one never reports it undelivered.
    pub(super) fn finish_remaining_pass(
        &self,
        pass: RemainingPass,
    ) -> AccountResult<PublishStatus> {
        let report = pass.report();
        let met = PublishStatus {
            met_required_acks: true,
            accepted_by_any_endpoint: true,
            ..PublishStatus::default()
        };
        let read = self.session.transport_fanout(&pass.welcome_id);
        // A withdrawal since dropped the record, and nothing is owed; or it
        // cannot be read now.
        let Ok(Some(mut fanout)) = read else {
            self.record_v5_welcome_publish_finished(
                &pass.v5_welcome,
                Some(&report),
                &pass.endpoints,
                None,
                pass.required_acks,
            );
            return read.map(|_| met).map_err(Into::into);
        };
        for (asked, result) in &pass.answers {
            if let Err(error) = result
                && !publish_error_reached_no_relay(error, asked)
            {
                fanout.possible_exposure = true;
            }
        }
        let attempts_before = |endpoint: &TransportEndpoint| {
            pass.attempts_before
                .iter()
                .find(|(asked, _)| asked == endpoint)
                .map_or(0, |(_, count)| *count)
        };
        // The first pass's record was not saved when a relay still answering
        // has no attempt counted since.
        let first_pass_unsaved = fanout.targets.iter().any(|target| {
            target.state != TransportFanoutAttemptState::Accepted
                && pass.endpoints.contains(&target.endpoint)
                && target.attempt_count <= attempts_before(&target.endpoint)
        });
        // The whole attempt's answers: the first pass's with these late ones.
        let mut whole_attempt = report.clone();
        whole_attempt
            .accepted
            .extend(pass.first_report.accepted.iter().cloned());
        whole_attempt
            .failed
            .extend(pass.first_report.failed.iter().cloned());
        let recorded = if first_pass_unsaved {
            fanout.possible_exposure |= pass.first_exposure;
            &pass.first_attempted
        } else {
            &pass.endpoints
        };
        let now = self.wall_clock.now();
        for target in &mut fanout.targets {
            if target.state == TransportFanoutAttemptState::Accepted
                || !recorded.contains(&target.endpoint)
            {
                continue;
            }
            let before = attempts_before(&target.endpoint);
            if target.attempt_count <= before {
                target.attempt_count = before.saturating_add(1);
                target.last_attempt_at = Some(now);
                target.state = TransportFanoutAttemptState::AttemptedFailed;
                target.failure_code = Some("publish_failed".into());
            }
            if whole_attempt
                .accepted
                .iter()
                .any(|receipt| receipt.endpoint == target.endpoint)
            {
                target.state = TransportFanoutAttemptState::Accepted;
                target.failure_code = None;
            } else if let Some(failure) = whole_attempt
                .failed
                .iter()
                .find(|failure| failure.endpoint == target.endpoint)
                && !failure.reason.is_empty()
            {
                target.failure_code = Some("transport_rejected".into());
            }
        }
        // The delivery counts are the whole attempt's. Its attempt is counted
        // already, unless the first pass's save, which counts it, failed. The
        // finished row covers only this pass's relays.
        self.put_pass_fanout_counting(
            &fanout,
            &pass.v5_welcome,
            Some(&report),
            &pass.endpoints,
            welcome_outcomes::PassCounts {
                attempted: &pass.first_attempted,
                report: Some(&whole_attempt),
                counts_attempt: first_pass_unsaved,
            },
        )?;
        let accepted_total = accepted_fanout_targets(&fanout);
        self.settle_met_welcome(&fanout.exact_message, accepted_total, fanout.required_acks);
        self.record_v5_welcome_publish_finished(
            &pass.v5_welcome,
            Some(&report),
            &pass.endpoints,
            Some(accepted_total),
            fanout.required_acks,
        );
        Ok(PublishStatus {
            possible_ambiguous_exposure: fanout.possible_exposure,
            ..met
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relays(names: &[&str]) -> Vec<TransportEndpoint> {
        names
            .iter()
            .map(|name| TransportEndpoint(format!("wss://{name}.example")))
            .collect()
    }

    /// A relay an inbox list names twice is asked once: two requests to it
    /// would meet a goal of two with one relay's acknowledgement.
    #[test]
    fn a_relay_named_twice_is_one_relay() {
        assert_eq!(asked_one_by_one(&relays(&["a", "a"]), 2), None);
        assert_eq!(asked_one_by_one(&relays(&["a", "a"]), 1), None);
        assert_eq!(
            asked_one_by_one(&relays(&["a", "b", "a"]), 1),
            Some(relays(&["a", "b"]))
        );
        assert_eq!(asked_one_by_one(&relays(&["a", "b", "a"]), 2), None);
    }

    /// A route over the limit is not split into requests of one relay, each
    /// of which a transport that limits a route's relays would let through.
    #[test]
    fn a_route_over_the_limit_goes_out_as_one_request() {
        let names = (0..=MAX_RELAYS_ASKED_ONE_BY_ONE)
            .map(|at| format!("r{at}"))
            .collect::<Vec<_>>();
        let names = names.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(asked_one_by_one(&relays(&names), 1), None);
        assert_eq!(
            asked_one_by_one(&relays(&names[1..]), 1),
            Some(relays(&names[1..]))
        );
    }
}
