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
//! attempt (`finish_remaining_pass`), and the pass has its own
//! `welcome_publish_started`/`_finished` rows. A remaining pass that is
//! cancelled before it finishes records nothing: the record stays as its
//! first pass left it, so those relays are retried after their backoff, as a
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
    let requests = if endpoints.len() <= request.required_acks.max(1) {
        vec![(endpoints.to_vec(), request.clone())]
    } else {
        endpoints
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
            .collect()
    };
    requests
        .into_iter()
        .map(|(asked, request)| {
            let publish = send(request);
            async move { (asked, publish.await) }.boxed()
        })
        .collect()
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
    /// Each relay's stored attempt count before its first pass.
    attempts_before: Vec<(TransportEndpoint, u32)>,
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
            .filter(|target| endpoints.contains(&target.endpoint))
            .map(|target| (target.endpoint.clone(), target.attempt_count))
            .collect();
        self.passes.push((
            index,
            RemainingPass {
                welcome_id: attempt.message_id.clone(),
                group_id,
                endpoints,
                attempts_before,
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

impl RemainingPass {
    /// Every receipt and named failure of the pass's answers, as its finished
    /// row reads them.
    fn report(&self) -> TransportPublishReport {
        let mut report = TransportPublishReport {
            message_id: self.welcome_id.clone(),
            accepted: Vec::new(),
            failed: Vec::new(),
            required_acks: self.required_acks,
        };
        for (_, result) in &self.answers {
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
    /// retry record. Its first pass counted and dated their attempt and left
    /// them failed, so each answer only says how that attempt ended: an
    /// acceptance, a refusal, or a possible exposure. When the first pass's
    /// record could not be saved, the attempt is counted and dated here. When
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
        let now = self.wall_clock.now();
        for target in &mut fanout.targets {
            if target.state == TransportFanoutAttemptState::Accepted
                || !pass.endpoints.contains(&target.endpoint)
            {
                continue;
            }
            // The first pass's record was not saved: its attempt is not
            // counted yet.
            let before = pass
                .attempts_before
                .iter()
                .find(|(endpoint, _)| *endpoint == target.endpoint)
                .map_or(0, |(_, count)| *count);
            if target.attempt_count <= before {
                target.attempt_count = before.saturating_add(1);
                target.last_attempt_at = Some(now);
                target.state = TransportFanoutAttemptState::AttemptedFailed;
                target.failure_code = Some("publish_failed".into());
            }
            if report
                .accepted
                .iter()
                .any(|receipt| receipt.endpoint == target.endpoint)
            {
                target.state = TransportFanoutAttemptState::Accepted;
                target.failure_code = None;
            } else if let Some(failure) = report
                .failed
                .iter()
                .find(|failure| failure.endpoint == target.endpoint)
                && !failure.reason.is_empty()
            {
                target.failure_code = Some("transport_rejected".into());
            }
        }
        self.put_pass_fanout(&fanout, &pass.v5_welcome, Some(&report), &pass.endpoints)?;
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
