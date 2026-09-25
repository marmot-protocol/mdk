use super::*;

fn require(ok: bool, rule: &'static str) -> Result<(), ContractError> {
    if ok {
        Ok(())
    } else {
        Err(ContractError::rule(rule))
    }
}
fn ordered_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|w| w[0] < w[1])
}

pub(super) fn validate(record: &RecordFields) -> Result<(), ContractError> {
    require(record.seq.get() > 0, "sequence must be positive")?;
    let has_group = record.group_ref.is_some();
    match &record.event {
        Event::WelcomePrepared(e) => {
            require(
                match e.mode {
                    Mode::Founding => matches!(e.basis, Basis::Founding { .. }),
                    Mode::Invite => !matches!(e.basis, Basis::Founding { .. }),
                },
                "preparation mode/basis mismatch",
            )?;
            match e.construction {
                Construction::Failed => {
                    require(
                        e.outer_event_ref.is_none() && e.retention == Retention::NotAttempted,
                        "failed construction cannot retain an artifact",
                    )?;
                    let valid_reason = match e.failure_stage {
                        Some(PreparationStage::Selection) => {
                            matches!(
                                e.reason,
                                Some(
                                    PreparationReason::NoUsableKeyPackage
                                        | PreparationReason::InternalFailed
                                        | PreparationReason::Unclassified
                                )
                            ) && e.key_package_event_ref.is_none()
                        }
                        Some(PreparationStage::Validation) => matches!(
                            e.reason,
                            Some(
                                PreparationReason::KeyPackageInvalid
                                    | PreparationReason::InternalFailed
                                    | PreparationReason::Unclassified
                            )
                        ),
                        Some(PreparationStage::Construction) => matches!(
                            e.reason,
                            Some(
                                PreparationReason::ConstructionFailed
                                    | PreparationReason::StorageFailed
                                    | PreparationReason::InternalFailed
                                    | PreparationReason::Unclassified
                            )
                        ),
                        _ => false,
                    };
                    require(valid_reason, "invalid preparation failure classification")?;
                }
                Construction::Constructed => {
                    require(
                        has_group
                            && e.outer_event_ref.is_some()
                            && e.key_package_event_ref.is_some(),
                        "constructed Nostr Welcome requires group and artifact links",
                    )?;
                    require(
                        e.mode != Mode::Invite || matches!(e.basis, Basis::Commit { .. }),
                        "constructed invite requires actual commit basis",
                    )?;
                    match e.retention {
                        Retention::Committed | Retention::NotAttempted => require(
                            e.failure_stage.is_none() && e.reason.is_none(),
                            "successful preparation cannot carry failure",
                        )?,
                        Retention::Failed | Retention::Unknown => require(
                            e.failure_stage == Some(PreparationStage::Retention)
                                && matches!(
                                    e.reason,
                                    Some(
                                        PreparationReason::RetentionFailed
                                            | PreparationReason::StorageFailed
                                            | PreparationReason::InternalFailed
                                            | PreparationReason::Unclassified
                                    )
                                ),
                            "invalid retention failure classification",
                        )?,
                    }
                }
            }
        }
        Event::WelcomePublishStarted(e) => {
            require(
                e.required_acks > 0,
                "required acknowledgments must be positive",
            )?;
            require(
                e.targets.len() <= MAX_ENDPOINTS && ordered_unique(&e.targets),
                "targets must be bounded, sorted and unique",
            )?;
            require(
                e.target_count.is_none_or(|n| n as usize >= e.targets.len()),
                "target count smaller than captured list",
            )?;
            require(
                !e.targets_complete || e.target_count == Some(e.targets.len() as u32),
                "complete target list needs exact total",
            )?;
            // A zero-target result belongs in not_started; omitted targets must be explicit.
            require(
                e.target_count != Some(0) && (!e.targets_complete || !e.targets.is_empty()),
                "started publication needs a target",
            )?;
        }
        Event::WelcomePublishFinished(e) => {
            require(
                e.required_acks > 0,
                "required acknowledgments must be positive",
            )?;
            require(
                e.results.len() <= MAX_ENDPOINTS
                    && e.results
                        .windows(2)
                        .all(|w| w[0].endpoint_ref < w[1].endpoint_ref),
                "results must be bounded, sorted and endpoint-unique",
            )?;
            for result in &e.results {
                require(
                    match result.status {
                        EndpointStatus::Acknowledged => {
                            result.failure_kind.is_none() && result.rejection_category.is_none()
                        }
                        EndpointStatus::Failed => result.failure_kind.is_some(),
                    },
                    "invalid endpoint result",
                )?;
            }
            let captured_acks = e
                .results
                .iter()
                .filter(|r| r.status == EndpointStatus::Acknowledged)
                .count() as u32;
            require(
                e.accepted_this_attempt_count >= captured_acks
                    && (!e.results_complete || e.accepted_this_attempt_count == captured_acks),
                "current acknowledgment count inconsistent with results",
            )?;
            require(
                e.accepted_total_count >= e.accepted_this_attempt_count,
                "cumulative acknowledgments smaller than current attempt",
            )?;
            require(
                match e.policy {
                    Policy::Met => e.accepted_total_count >= e.required_acks,
                    Policy::Unmet => e.accepted_total_count < e.required_acks,
                    Policy::Unknown => true,
                },
                "policy contradicts acknowledgment counts",
            )?;
            require(
                e.retained_state != RetainedState::Completed || e.policy == Policy::Met,
                "completed obligation requires met policy",
            )?;
        }
        Event::WelcomePublishNotStarted(_) => {}
        Event::WelcomeObserved(e) => {
            require(
                e.acquisition != Acquisition::LocalReplay
                    || (e.endpoint_ref.is_none() && e.fetch_id.is_none()),
                "local replay is not fresh network acquisition",
            )?;
        }
        Event::WelcomeUnwrapped(e) => {
            require(
                match e.result {
                    UnwrapResult::Validated => {
                        e.rumor_event_ref.is_some()
                            && e.key_package_event_ref.is_some()
                            && e.reason.is_none()
                    }
                    UnwrapResult::Rejected | UnwrapResult::Failed => {
                        e.rumor_event_ref.is_none()
                            && e.key_package_event_ref.is_none()
                            && e.reason.is_some()
                    }
                },
                "unwrap result contradicts validated provenance",
            )?;
        }
        Event::WelcomeJoinFinished(e) => {
            if e.result == JoinResult::Joined {
                require(
                    has_group
                        && e.epoch.is_some()
                        && e.engine_commit == EngineCommit::Committed
                        && e.reason.is_none(),
                    "joined requires committed scoped state",
                )?;
            } else {
                require(
                    e.engine_commit != EngineCommit::Committed,
                    "non-join cannot claim join commit",
                )?;
                let classified = match e.result {
                    JoinResult::Duplicate => {
                        e.reason == Some(JoinReason::Duplicate)
                            && e.engine_commit == EngineCommit::NotAttempted
                    }
                    JoinResult::Deferred => {
                        e.reason == Some(JoinReason::RejoinConfirmationRequired)
                    }
                    JoinResult::Rejected => matches!(
                        e.reason,
                        Some(
                            JoinReason::WrongRecipient
                                | JoinReason::InvalidSignature
                                | JoinReason::InvalidEncoding
                                | JoinReason::UnsupportedFeature
                                | JoinReason::AuthorizationFailed
                                | JoinReason::MissingKeyPackage
                                | JoinReason::Unclassified
                        )
                    ),
                    JoinResult::Failed => matches!(
                        e.reason,
                        Some(
                            JoinReason::StorageFailed
                                | JoinReason::InternalFailed
                                | JoinReason::Unclassified
                        )
                    ),
                    JoinResult::Joined => unreachable!(),
                };
                require(classified, "invalid join reason")?;
            }
        }
        Event::AppGroupUpdateFinished(e) => {
            require(has_group, "app update requires group")?;
            if e.checkpoint == Checkpoint::Committed {
                require(
                    e.compute != Compute::Failed && e.reason.is_none(),
                    "app commit contradicts computation failure",
                )?;
                require(
                    e.cause != UpdateCause::InviteConfirmation
                        || e.invite_state == InviteState::Accepted,
                    "confirmation commit requires accepted app state",
                )?;
            } else {
                require(
                    e.invite_state == InviteState::Unknown,
                    "uncommitted app update cannot assert invite state",
                )?;
                require(
                    (e.compute != Compute::Failed
                        && e.checkpoint != Checkpoint::FailedBeforeCommit)
                        || e.reason.is_some(),
                    "app failure requires classified reason",
                )?;
            }
        }
        Event::GroupBaseline(e) => {
            require(has_group, "baseline requires group")?;
            require(
                e.members.len() <= MAX_MEMBERS
                    && e.members
                        .windows(2)
                        .all(|w| w[0].member_ref < w[1].member_ref),
                "members must be bounded, sorted and unique",
            )?;
            require(
                e.member_count.is_none_or(|n| n as usize >= e.members.len()),
                "member count smaller than captured list",
            )?;
            require(
                !e.members_complete || e.member_count == Some(e.members.len() as u32),
                "complete membership requires exact count",
            )?;
            require(
                e.limitations.len() <= 4
                    && e.limitations
                        .iter()
                        .enumerate()
                        .all(|(i, v)| !e.limitations[..i].contains(v)),
                "duplicate baseline limitation",
            )?;
            require(
                e.members.iter().all(|m| m.admin.is_some())
                    || e.limitations.contains(&Limitation::AdminPolicyUnavailable),
                "unknown admin flags need explicit limitation",
            )?;
            require(
                e.epoch.is_some() || e.limitations.contains(&Limitation::StateUnavailable),
                "unknown epoch needs explicit limitation",
            )?;
            require(
                !(e.limitations.contains(&Limitation::MemberLimit)
                    || e.limitations.contains(&Limitation::ByteLimit))
                    || !e.members_complete,
                "truncated baseline cannot claim complete membership",
            )?;
            match e.capture {
                Capture::Complete => require(
                    e.epoch.is_some()
                        && e.members_complete
                        && e.member_count.is_some_and(|n| n > 0)
                        && e.limitations.is_empty()
                        && e.members.iter().all(|m| m.admin.is_some()),
                    "invalid complete baseline",
                )?,
                Capture::Partial => require(
                    !e.limitations.is_empty(),
                    "partial baseline needs limitation",
                )?,
                Capture::Failed => require(
                    e.members.is_empty()
                        && e.epoch.is_none()
                        && e.member_count.is_none()
                        && !e.members_complete
                        && e.limitations.contains(&Limitation::StateUnavailable)
                        && matches!(e.basis, Basis::Unavailable { .. }),
                    "failed baseline cannot invent state",
                )?,
            }
            require(
                e.reason != BaselineReason::Joined || e.cause_outer_event_ref.is_some(),
                "join baseline requires Welcome cause",
            )?;
        }
    }
    Ok(())
}
