//! Classification behaviour, exercised through the public parse + classify API
//! against synthetic, non-sensitive fixtures.

use incident_replay::{
    BehindEngine, BehindMode, HaltedEngine, QuarantineReason, Verdict, classify, halt_advisory,
    liveness_advisory, parse,
};

fn load(name: &str) -> incident_replay::AgentStateExport {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let json =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read fixture {path}: {err}"));
    parse(&json).unwrap_or_else(|err| panic!("parse fixture {name}: {err}"))
}

#[test]
fn healthy_export_classifies_as_healthy() {
    assert_eq!(classify(&load("healthy.json")), Verdict::Healthy);
}

#[test]
fn fork_resolution_without_contested_convergence_is_fork_recovery() {
    assert_eq!(classify(&load("fork-recovery.json")), Verdict::ForkRecovery);
}

#[test]
fn routine_single_branch_convergence_is_healthy() {
    // Real traffic emits many convergence_decisions that select the sole branch
    // with no loser. Those are not incidents.
    assert_eq!(
        classify(&load("healthy-routine-convergence.json")),
        Verdict::Healthy
    );
}

#[test]
fn contested_convergence_dominates_fork_recovery() {
    // A real incident carries both a fork_resolution and a contested
    // convergence_decision; the convergence selection wins the route.
    assert_eq!(
        classify(&load("convergence-selected.json")),
        Verdict::ConvergenceSelected
    );
}

#[test]
fn fork_resolution_with_missing_snapshot_quarantines() {
    // The winning branch's pre-commit snapshot was unavailable, so the fork
    // cannot be replayed — quarantine rather than emit a wrong vector.
    assert_eq!(
        classify(&load("quarantine-missing-snapshot.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::MissingSnapshot
        }
    );
}

#[test]
fn contested_convergence_outranks_a_missing_snapshot_fork() {
    // A reproducible convergence selection routes to Phase 4 even alongside an
    // unrecoverable fork: the missing-snapshot quarantine only applies when the
    // fork-recovery path is the one being taken.
    assert_eq!(
        classify(&load("convergence-with-missing-snapshot-fork.json")),
        Verdict::ConvergenceSelected
    );
}

#[test]
fn partial_audit_coverage_alone_stays_healthy() {
    // The group_context reports 3 members while only 2 engines contributed
    // events. Audit is opt-in, so real groups routinely have more members than
    // exporting engines (a real six-member group exported from only two
    // engines); coverage alone is not an incident, and gating on it would
    // quarantine those groups forever.
    assert_eq!(
        classify(&load("healthy-partial-audit-coverage.json")),
        Verdict::Healthy
    );
}

#[test]
fn an_engine_the_group_advanced_past_quarantines_as_went_dark() {
    // engine-a's audit stream ends at epoch 4 — with one stray event *within*
    // the catch-up grace of the group reaching epoch 6 — so its lag reads as
    // going dark, not as an engine demonstrably running without its commits.
    // This shape is also exactly what a member offline through two quick commits
    // looks like on a single pull; it quarantines fail-closed by design,
    // and cross-pull persistence — not this one verdict — is the operator's
    // discriminator between a genuine split and catch-up still in flight.
    assert_eq!(
        classify(&load("quarantine-went-dark-engine.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence {
                group_epoch: 6,
                engines: vec![BehindEngine {
                    engine_id: "engine-a".into(),
                    epoch: 4,
                    mode: BehindMode::WentDark,
                }],
            }
        }
    );
}

#[test]
fn an_active_engine_two_epochs_behind_quarantines_as_active_while_behind() {
    // engine-b keeps recording events well past the catch-up grace after
    // engine-a evidenced epoch 6, yet never advances beyond 4: commits are not
    // reaching it while its other traffic flows.
    assert_eq!(
        classify(&load("quarantine-epoch-divergence.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence {
                group_epoch: 6,
                engines: vec![BehindEngine {
                    engine_id: "engine-b".into(),
                    epoch: 4,
                    mode: BehindMode::ActiveWhileBehind,
                }],
            }
        }
    );
}

#[test]
fn catch_up_deadline_saturates_for_hostile_wall_timestamps() {
    let json = format!(
        r#"{{ "events": [
            {{ "engine_id": "engine-b", "wall_time_ms": {},
               "kind": {{ "type": "group_state_changed", "epoch": 4 }} }},
            {{ "engine_id": "engine-a", "wall_time_ms": {},
               "kind": {{ "type": "group_state_changed", "epoch": 6 }} }}
        ] }}"#,
        u64::MAX,
        u64::MAX - 1
    );
    let export = parse(&json).expect("hostile timestamps still parse");

    assert_eq!(
        classify(&export),
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence {
                group_epoch: 6,
                engines: vec![BehindEngine {
                    engine_id: "engine-b".into(),
                    epoch: 4,
                    mode: BehindMode::WentDark,
                }],
            }
        }
    );
}

#[test]
fn one_epoch_of_lag_is_routine_propagation_not_divergence() {
    assert_eq!(
        classify(&load("healthy-lagging-engine.json")),
        Verdict::Healthy
    );
}

#[test]
fn a_behind_engine_without_timestamps_leaves_the_gate_unarmed() {
    // engine-b sits two epochs back, but its own events carry no wall clock, so
    // there is no moment to time its lag from. The gate refuses to arm on
    // untimed evidence rather than guess when the engine went quiet — legacy and
    // partially-instrumented exports classify as before.
    assert_eq!(
        classify(&load("healthy-untimed-behind-engine.json")),
        Verdict::Healthy
    );
}

#[test]
fn an_untimed_group_advance_leaves_the_gate_unarmed() {
    // engine-b's lag is plainly visible — its high-water epoch trails the group
    // by two — but the only evidence of the group moving past it carries no wall
    // clock, so there is no moment to order the lag against. It is the missing
    // order evidence, not the lag, that keeps the gate unarmed rather than
    // guessing when the group left the engine behind.
    assert_eq!(
        classify(&load("healthy-untimed-group-advance.json")),
        Verdict::Healthy
    );
}

#[test]
fn a_reproducible_incident_outranks_the_liveness_gate() {
    // A fork resolution is a replayable incident; an engine left behind
    // elsewhere in the export must not preempt it (recovery fail-closes
    // downstream if the data it needs turns out to be missing).
    assert_eq!(
        classify(&load("fork-recovery-with-behind-engine.json")),
        Verdict::ForkRecovery
    );
}

#[test]
fn liveness_advisory_surfaces_behind_an_incident_verdict() {
    // The export routes to ForkRecovery (rule 4 outranks the rule-5 liveness
    // gate), so classify's single verdict hides engine-b, which sits 12 epochs
    // behind while still active — exactly the shape the real e1a04e82 export
    // carried. liveness_advisory exposes that co-occurring incident so the CLI
    // can print it as a secondary advisory alongside the accepted vector.
    let export = load("fork-with-active-behind-engine.json");
    assert_eq!(classify(&export), Verdict::ForkRecovery);
    assert_eq!(
        liveness_advisory(&export),
        Some(QuarantineReason::EpochDivergence {
            group_epoch: 31,
            engines: vec![BehindEngine {
                engine_id: "engine-b".into(),
                epoch: 19,
                mode: BehindMode::ActiveWhileBehind,
            }],
        })
    );
}

#[test]
fn truncated_projection_quarantines_even_when_contested() {
    // A capped derived_projections section means the export is incomplete;
    // reproduction could miss witnesses, so truncation quarantines regardless of
    // any incident signal in the (uncapped) event log.
    assert_eq!(
        classify(&load("quarantine-truncated.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::TruncatedProjections
        }
    );
}

#[test]
fn a_convergence_pass_that_halted_unrecoverably_quarantines() {
    // PR #1110 made a convergence pass able to halt: it emits
    // `convergence_run_state` with `phase: unrecoverable`, and the group stays
    // blocked until a verified repair clears the marker. The engine is stating
    // outright that it stopped, so — unlike the epoch-divergence gate's
    // inferential lag — no timestamps are needed to believe it.
    //
    // This fixture carries the halt reason mdk#1182 retired: a pass whose base
    // epoch disagreed with the tip now discards and reopens instead of halting,
    // so nothing emits `convergence_pass_base_changed` today. Kept deliberately —
    // exports already recorded it, and the gate matches no reason whitelist, so a
    // historical export must still arm. `frozen_pass_integrity_failure` covers
    // the reason a current engine emits (see `quarantine-repeated-halt.json`).
    let export = load("quarantine-convergence-pass-halt.json");
    assert_eq!(
        classify(&export),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["convergence_pass_base_changed".into()],
                }],
            }
        }
    );
}

#[test]
fn a_halt_carrying_only_an_error_kind_reports_the_error_kind() {
    // The `missing_retained_anchor` halt is the one `unrecoverable` phase a
    // current engine emits with `reason: None`, naming itself only through
    // `error_kind`. Reporting the reason alone would name this engine
    // `unspecified` and lose the single field that says what broke, so the gate
    // falls back to `error_kind`.
    assert_eq!(
        classify(&load("quarantine-anchorless-halt.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["missing_retained_anchor".into()],
                }],
            }
        }
    );
}

#[test]
fn a_group_hydrated_into_the_unrecoverable_state_quarantines() {
    // The other halt surface (mdk #1106): the engine's epoch machine re-entered
    // `unrecoverable` on hydrate, so a durable halt survived a process restart.
    // This is the shape the real 26a9f546 export carried — the row Goggles
    // derives its error-severity `epoch_state_transition` projection from — and
    // the classifier previously read nothing but the row's epoch, so a hard
    // client failure surfaced only as the misleading label `went dark`.
    let export = load("quarantine-hydrate-unrecoverable.json");
    assert_eq!(
        classify(&export),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-b".into(),
                    reasons: vec!["hydrate_unrecoverable_group".into()],
                }],
            }
        }
    );
}

#[test]
fn both_halt_surfaces_on_one_engine_report_one_entry_per_reason() {
    // An engine that halts mid-pass and then hydrates back into the halt records
    // both surfaces, repeatedly. The report is per engine, with each distinct
    // reason once: a halt is a state, not a count, so repetition is not severity.
    let export = load("quarantine-repeated-halt.json");
    assert_eq!(
        classify(&export),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec![
                        "frozen_pass_integrity_failure".into(),
                        "hydrate_unrecoverable_group".into(),
                    ],
                }],
            }
        }
    );
}

#[test]
fn a_verified_repair_after_a_halt_clears_the_halt() {
    // The halt is a state, not a permanent record: rule 5 says the group stays
    // blocked "until a verified repair clears the marker", and there is exactly
    // one legal exit from `Unrecoverable` — `repair_to_stable`, driven by an
    // authenticated Welcome, which emits `epoch_state_changed { new_state:
    // "stable", reason: "join_welcome_repair" }` right after the transition. An
    // engine that halted and then completed that repair is repaired, so
    // quarantining it would send the operator after a device that already
    // healed. Only this engine appears, at the post-repair epoch, so rule 6
    // stays unarmed and `Healthy` is the whole verdict.
    let export = load("healthy-halt-cleared-by-repair.json");
    assert_eq!(classify(&export), Verdict::Healthy);
    // The advisory is verdict-independent, so a cleared halt must vanish from it
    // too — otherwise the CLI would still print the halt beneath a healthy line.
    assert_eq!(halt_advisory(&export), None);
}

#[test]
fn a_halt_after_a_verified_repair_still_quarantines() {
    // A repaired group can halt again. Both rows are present here exactly as in
    // the cleared case — only their order differs — so this is the shape a
    // presence-only "halted, but also repaired ⇒ downgrade" rule gets wrong, and
    // it gets it wrong on the dangerous side: a device that is halted *right now*
    // would read as healthy. Ordering the two by their own clock is what
    // distinguishes them.
    assert_eq!(
        classify(&load("quarantine-halt-after-repair.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["hydrate_unrecoverable_group".into()],
                }],
            }
        }
    );
}

#[test]
fn a_verified_repair_in_another_group_does_not_clear_a_halt() {
    // `Unrecoverable` is per-group state, and one engine serves many groups. Here
    // the engine re-joined group b — a real repair, for a group that was never
    // halted — while group a stays blocked. Clearing per engine rather than per
    // (engine, group) would report this device healthy on the strength of a
    // repair that never touched the halted group. Both real exports on hand carry
    // `group_ref` on every event line, so this scoping is live, not latent.
    assert_eq!(
        classify(&load("quarantine-halt-with-repair-in-another-group.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["hydrate_unrecoverable_group".into()],
                }],
            }
        }
    );
}

#[test]
fn an_untimed_repair_does_not_clear_a_halt() {
    // Same group, same engine, both rows present — but neither carries a wall
    // clock, so nothing says which came last, and the two orders have opposite
    // meanings (see `a_halt_after_a_verified_repair_still_quarantines`). The halt
    // stands. Note the asymmetry this preserves: *arming* rule 5 needs no
    // timestamps, because a halt is self-reported and repetition-proof, while
    // *clearing* it is an ordering claim that untimed rows cannot support. Fail
    // closed — a missed repair costs a re-pull, a missed halt costs the incident.
    assert_eq!(
        classify(&load("quarantine-untimed-halt-with-repair.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["hydrate_unrecoverable_group".into()],
                }],
            }
        }
    );
}

#[test]
fn one_untimed_halt_row_among_timed_ones_still_blocks_a_later_repair() {
    // Mixed instrumentation: the same engine and group recorded an untimed halt, a
    // timed halt, and then a repair newer than the *timed* halt. The untimed row
    // may be the newest evidence of all — nothing in the export says otherwise —
    // so the halt is unorderable and stands, exactly as when no halt row carries a
    // clock at all. Reading the newest timed halt as *the* halt position is the
    // fail-open direction: it lets a repair clear a halt whose real position is
    // unknown, turning a live halt into a healthy verdict on partially
    // instrumented input.
    assert_eq!(
        classify(&load("quarantine-partially-timed-halt-with-repair.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["hydrate_unrecoverable_group".into()],
                }],
            }
        }
    );
}

#[test]
fn a_repair_sharing_the_halt_millisecond_does_not_clear_it() {
    // The other boundary of the same comparison: both rows carry a clock, and it
    // is the same one. A millisecond is coarser than the two transitions, so a
    // tie says only that they landed in the same tick — not which came first —
    // and the two orders have opposite meanings. Strictly-after is therefore the
    // rule, and a tie fails closed like any other unorderable pair.
    assert_eq!(
        classify(&load("quarantine-halt-and-repair-at-one-instant.json")),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt {
                engines: vec![HaltedEngine {
                    engine_id: "engine-a".into(),
                    reasons: vec!["hydrate_unrecoverable_group".into()],
                }],
            }
        }
    );
}

#[test]
fn a_convergence_run_at_the_tip_proves_the_engine_is_not_behind() {
    // engine-b's group-state evidence stops at epoch 4, but it went on to run a
    // convergence pass whose canonical tip was 6 — an epoch it can only have
    // started from by having materialized it locally. Reading only the older
    // signal would report a healthy engine as two epochs behind. This is the same
    // reasoning `convergence_decision.current_tip_epoch` already carries, applied
    // to the denser of the two surfaces (a real export logs roughly twice as many
    // run-state rows as decisions). A non-terminal phase must also leave the halt
    // gate unarmed.
    assert_eq!(
        classify(&load("healthy-convergence-run-at-tip.json")),
        Verdict::Healthy
    );
}

#[test]
fn a_discarded_convergence_pass_proves_the_engine_is_not_behind() {
    // mdk#1182 replaced the `base_epoch_mismatch` halt with a repair:
    // `convergence_pass_discarded`. Its `current_tip_epoch` comes from
    // `convergence_tip_epoch()` at every call site, so it is the engine's own
    // materialized tip — the same evidence class as
    // `convergence_run_state.current_tip_epoch`. engine-b's group-state evidence
    // stops at epoch 4 and the discard row is its only later signal, so ignoring
    // the row reports a healthy engine as two epochs behind.
    //
    // `stale_base_epoch` is deliberately *ahead* of the tip here (9 > 6): it is
    // inherited scheduling state that can split from the tip in either direction,
    // never an epoch any engine materialized, so folding it into the group's
    // high-water mark would invent a tip nobody reached and report every engine
    // behind it. Only the tip counts.
    assert_eq!(
        classify(&load("healthy-convergence-pass-discarded-at-tip.json")),
        Verdict::Healthy
    );
}

#[test]
fn halt_advisory_surfaces_behind_an_incident_verdict() {
    // A halt is a client failure, not a branch contest, so it must not preempt a
    // replayable incident — the fork still routes. But it must not be lost to
    // that single verdict either, so `halt_advisory` exposes it the way
    // `liveness_advisory` exposes rule 6.
    let export = load("fork-with-halted-engine.json");
    assert_eq!(classify(&export), Verdict::ForkRecovery);
    assert_eq!(
        halt_advisory(&export),
        Some(QuarantineReason::UnrecoverableHalt {
            engines: vec![HaltedEngine {
                engine_id: "engine-b".into(),
                reasons: vec!["hydrate_unrecoverable_group".into()],
            }],
        })
    );
}

#[test]
fn a_halt_outranks_the_epoch_divergence_it_explains() {
    // engine-b is both halted and two epochs behind — the real 26a9f546 pairing,
    // where the halt is *why* the engine stopped advancing. The diagnosis is the
    // verdict; the inference stays available as the secondary advisory rather than
    // sending the operator to re-pull for a confirmation they already have.
    let export = load("quarantine-halt-and-divergence.json");
    assert!(matches!(
        classify(&export),
        Verdict::Quarantine {
            reason: QuarantineReason::UnrecoverableHalt { .. }
        }
    ));
    assert!(matches!(
        liveness_advisory(&export),
        Some(QuarantineReason::EpochDivergence { .. })
    ));
}
