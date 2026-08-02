//! Human-oriented scenario structure and deterministic lowering rules.
//!
//! Adapters never execute these nodes. Authoring documents first lower to a
//! canonical [`ScenarioSpec`](crate::ScenarioSpec), which is then compiled and
//! preflighted through `scenario_ir` like any other canonical JSON input.

use serde::{Deserialize, Serialize};

use crate::{
    SCENARIO_IR_VERSION, ScenarioRunError, ScenarioSpec, ScenarioStep, SubjectFailureCategory,
};

pub const SCENARIO_AUTHORING_VERSION: &str = "1";
/// Hard compiler resource bound. Execution campaigns may choose lower limits,
/// but authoring expansion never allocates an unbounded action schedule.
pub const MAX_EXPANDED_SCENARIO_ACTIONS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAuthoringSpec {
    pub name: String,
    pub authoring_version: String,
    pub clients: Vec<String>,
    pub steps: Vec<ScenarioFlow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioParallelLane {
    pub name: String,
    pub steps: Vec<ScenarioFlow>,
}

/// Authoring-only control flow. Its serialization is deliberately distinct
/// from the canonical step's nested `type` tag so an author cannot accidentally pass
/// this document directly to an adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "flow", rename_all = "snake_case")]
pub enum ScenarioFlow {
    Action {
        step: ScenarioStep,
    },
    Repeat {
        count: u32,
        steps: Vec<ScenarioFlow>,
    },
    /// Deterministic logical concurrency. Each lane contributes at most one
    /// action per round, in declared lane order. A named barrier blocks a lane
    /// until every lane reaches the same next barrier.
    Parallel {
        lanes: Vec<ScenarioParallelLane>,
    },
    /// Start flattened actions at `floor(i * 1000 / actions_per_second)`
    /// milliseconds from the block start. The first action starts immediately.
    /// Explicit time advances and barriers are rejected inside the block so
    /// the schedule has one unambiguous clock owner.
    Rate {
        actions_per_second: u32,
        steps: Vec<ScenarioFlow>,
    },
    /// Repeat one flattened burst at exact `every_ms` start intervals. A burst
    /// may not contain explicit time advances or barriers. A zero interval is
    /// valid and represents multiple immediate bursts.
    Burst {
        count: u32,
        every_ms: u64,
        steps: Vec<ScenarioFlow>,
    },
    /// Synchronization marker. At top level it is retained as a recorded no-op;
    /// inside `parallel` it is emitted once after every lane reaches it.
    Barrier {
        name: String,
    },
}

#[derive(Clone, Debug)]
enum ExpandedFlow {
    Action(ScenarioStep),
    Barrier(String),
}

pub fn compile_authoring_scenario(
    authored: &ScenarioAuthoringSpec,
) -> Result<ScenarioSpec, ScenarioRunError> {
    if authored.authoring_version != SCENARIO_AUTHORING_VERSION {
        return Err(authoring_error(format!(
            "unsupported authoring version {}",
            authored.authoring_version
        )));
    }
    let expanded = expand_sequence(&authored.steps)?;
    let canonical = ScenarioSpec {
        name: authored.name.clone(),
        spec_version: SCENARIO_IR_VERSION.into(),
        clients: authored.clients.clone(),
        steps: expanded
            .into_iter()
            .map(|flow| match flow {
                ExpandedFlow::Action(step) => step,
                ExpandedFlow::Barrier(name) => ScenarioStep::Barrier { name },
            })
            .collect(),
    };
    crate::compile_scenario(&canonical)?;
    Ok(canonical)
}

/// Parse human YAML and immediately lower it to canonical JSON-shaped IR.
/// The returned value is the only form an executor may consume.
pub fn compile_authoring_yaml(yaml: &str) -> Result<ScenarioSpec, ScenarioRunError> {
    let authored = serde_yaml_ng::from_str::<ScenarioAuthoringSpec>(yaml)
        .map_err(|error| authoring_error(format!("invalid scenario authoring YAML: {error}")))?;
    compile_authoring_scenario(&authored)
}

fn expand_sequence(steps: &[ScenarioFlow]) -> Result<Vec<ExpandedFlow>, ScenarioRunError> {
    let mut expanded = Vec::new();
    for step in steps {
        expanded.extend(expand_flow(step)?);
        ensure_expansion_bound(expanded.len())?;
    }
    Ok(expanded)
}

fn expand_flow(flow: &ScenarioFlow) -> Result<Vec<ExpandedFlow>, ScenarioRunError> {
    match flow {
        ScenarioFlow::Action { step } => {
            if matches!(step, ScenarioStep::Barrier { .. }) {
                return Err(authoring_error(
                    "canonical barrier actions are reserved for the compiler; use flow=barrier",
                ));
            }
            Ok(vec![ExpandedFlow::Action(step.clone())])
        }
        ScenarioFlow::Barrier { name } => {
            validate_barrier_name(name)?;
            Ok(vec![ExpandedFlow::Barrier(name.clone())])
        }
        ScenarioFlow::Repeat { count, steps } => {
            let body = expand_sequence(steps)?;
            let capacity = body
                .len()
                .checked_mul(*count as usize)
                .ok_or_else(|| authoring_error("repeat expansion is too large"))?;
            ensure_expansion_bound(capacity)?;
            let mut expanded = Vec::with_capacity(capacity);
            for _ in 0..*count {
                expanded.extend(body.iter().cloned());
            }
            Ok(expanded)
        }
        ScenarioFlow::Parallel { lanes } => Ok(expand_parallel(lanes)?
            .into_iter()
            .map(|item| match item {
                ExpandedFlow::Barrier(name) => ExpandedFlow::Action(ScenarioStep::Barrier { name }),
                action => action,
            })
            .collect()),
        ScenarioFlow::Rate {
            actions_per_second,
            steps,
        } => expand_rate(*actions_per_second, steps),
        ScenarioFlow::Burst {
            count,
            every_ms,
            steps,
        } => expand_burst(*count, *every_ms, steps),
    }
}

fn expand_parallel(lanes: &[ScenarioParallelLane]) -> Result<Vec<ExpandedFlow>, ScenarioRunError> {
    if lanes.is_empty() {
        return Err(authoring_error("parallel requires at least one lane"));
    }
    let mut names = std::collections::BTreeSet::new();
    let mut expanded_lanes = Vec::with_capacity(lanes.len());
    for lane in lanes {
        if lane.name.trim().is_empty() {
            return Err(authoring_error("parallel lane name must not be empty"));
        }
        if !names.insert(&lane.name) {
            return Err(authoring_error(format!(
                "duplicate parallel lane name {}",
                lane.name
            )));
        }
        expanded_lanes.push(expand_sequence(&lane.steps)?);
    }

    let mut cursors = vec![0_usize; lanes.len()];
    let mut result = Vec::new();
    loop {
        let mut active = false;
        let mut made_progress = false;
        for (lane, cursor) in expanded_lanes.iter().zip(cursors.iter_mut()) {
            let Some(item) = lane.get(*cursor) else {
                continue;
            };
            active = true;
            if matches!(item, ExpandedFlow::Barrier(_)) {
                continue;
            }
            result.push(item.clone());
            ensure_expansion_bound(result.len())?;
            *cursor += 1;
            made_progress = true;
        }
        if !active {
            break;
        }
        if made_progress {
            continue;
        }

        let barriers = expanded_lanes
            .iter()
            .zip(&cursors)
            .map(|(lane, cursor)| match lane.get(*cursor) {
                Some(ExpandedFlow::Barrier(name)) => Ok(name.as_str()),
                Some(ExpandedFlow::Action(_)) => unreachable!("action would have made progress"),
                None => Err(authoring_error(
                    "parallel lane ended before reaching the next barrier",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let barrier = barriers[0];
        if barriers.iter().any(|candidate| *candidate != barrier) {
            return Err(authoring_error(format!(
                "parallel lanes reached different barriers: {}",
                barriers.join(", ")
            )));
        }
        result.push(ExpandedFlow::Barrier(barrier.into()));
        ensure_expansion_bound(result.len())?;
        for cursor in &mut cursors {
            *cursor += 1;
        }
    }
    Ok(result)
}

fn expand_rate(
    actions_per_second: u32,
    steps: &[ScenarioFlow],
) -> Result<Vec<ExpandedFlow>, ScenarioRunError> {
    if actions_per_second == 0 {
        return Err(authoring_error("rate actions_per_second must be non-zero"));
    }
    let body = expand_sequence(steps)?;
    reject_timed_or_barrier_body("rate", &body)?;

    let mut result = Vec::with_capacity(body.len().saturating_mul(2));
    let mut previous_offset = 0_u64;
    for (index, item) in body.into_iter().enumerate() {
        let numerator = (index as u128)
            .checked_mul(1_000)
            .ok_or_else(|| authoring_error("rate schedule overflows"))?;
        let offset = numerator / u128::from(actions_per_second);
        let offset =
            u64::try_from(offset).map_err(|_| authoring_error("rate schedule overflows"))?;
        append_time_delta(&mut result, offset - previous_offset);
        result.push(item);
        ensure_expansion_bound(result.len())?;
        previous_offset = offset;
    }
    Ok(result)
}

fn expand_burst(
    count: u32,
    every_ms: u64,
    steps: &[ScenarioFlow],
) -> Result<Vec<ExpandedFlow>, ScenarioRunError> {
    let body = expand_sequence(steps)?;
    reject_timed_or_barrier_body("burst", &body)?;
    let capacity = body
        .len()
        .checked_mul(count as usize)
        .and_then(|actions| actions.checked_add(count.saturating_sub(1) as usize))
        .ok_or_else(|| authoring_error("burst expansion is too large"))?;
    ensure_expansion_bound(capacity)?;
    let mut result = Vec::with_capacity(capacity);
    for burst_index in 0..count {
        if burst_index > 0 {
            append_time_delta(&mut result, every_ms);
        }
        result.extend(body.iter().cloned());
    }
    Ok(result)
}

fn reject_timed_or_barrier_body(
    block: &str,
    body: &[ExpandedFlow],
) -> Result<(), ScenarioRunError> {
    if body.iter().any(|flow| {
        matches!(
            flow,
            ExpandedFlow::Barrier(_) | ExpandedFlow::Action(ScenarioStep::AdvanceTime { .. })
        )
    }) {
        return Err(authoring_error(format!(
            "{block} body cannot contain barriers or advance_time"
        )));
    }
    Ok(())
}

fn append_time_delta(expanded: &mut Vec<ExpandedFlow>, delta_ms: u64) {
    if delta_ms > 0 {
        expanded.push(ExpandedFlow::Action(ScenarioStep::AdvanceTime { delta_ms }));
    }
}

fn validate_barrier_name(name: &str) -> Result<(), ScenarioRunError> {
    if name.trim().is_empty() {
        Err(authoring_error("barrier name must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_expansion_bound(len: usize) -> Result<(), ScenarioRunError> {
    if len > MAX_EXPANDED_SCENARIO_ACTIONS {
        Err(authoring_error(format!(
            "expanded scenario exceeds {MAX_EXPANDED_SCENARIO_ACTIONS} actions"
        )))
    } else {
        Ok(())
    }
}

fn authoring_error(message: impl Into<String>) -> ScenarioRunError {
    ScenarioRunError {
        step_index: None,
        kind: "scenario_authoring_error".into(),
        category: SubjectFailureCategory::Environment,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(step: ScenarioStep) -> ScenarioFlow {
        ScenarioFlow::Action { step }
    }

    fn send(sender: &str, payload: &str) -> ScenarioFlow {
        action(ScenarioStep::SendAppMessage {
            sender: sender.into(),
            payload: payload.into(),
        })
    }

    #[test]
    fn parallel_is_round_robin_and_barriers_wait_for_every_lane() {
        let expanded = expand_flow(&ScenarioFlow::Parallel {
            lanes: vec![
                ScenarioParallelLane {
                    name: "alice".into(),
                    steps: vec![
                        send("alice", "a1"),
                        send("alice", "a2"),
                        ScenarioFlow::Barrier {
                            name: "sent".into(),
                        },
                        send("alice", "a3"),
                    ],
                },
                ScenarioParallelLane {
                    name: "bob".into(),
                    steps: vec![
                        send("bob", "b1"),
                        ScenarioFlow::Barrier {
                            name: "sent".into(),
                        },
                        send("bob", "b2"),
                    ],
                },
            ],
        })
        .expect("parallel expands");

        let payloads = expanded
            .iter()
            .map(|item| match item {
                ExpandedFlow::Action(ScenarioStep::SendAppMessage { payload, .. }) => {
                    payload.as_str()
                }
                ExpandedFlow::Action(ScenarioStep::Barrier { name }) => name.as_str(),
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        assert_eq!(payloads, ["a1", "b1", "a2", "sent", "a3", "b2"]);
    }

    #[test]
    fn rate_uses_absolute_integer_deadlines_without_drift() {
        let expanded = expand_rate(
            3,
            &[
                send("alice", "0"),
                send("alice", "1"),
                send("alice", "2"),
                send("alice", "3"),
            ],
        )
        .expect("rate expands");
        let deltas = expanded
            .iter()
            .filter_map(|item| match item {
                ExpandedFlow::Action(ScenarioStep::AdvanceTime { delta_ms }) => Some(*delta_ms),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(deltas, [333, 333, 334]);
    }

    #[test]
    fn burst_inserts_exact_start_interval_between_immediate_bodies() {
        let expanded = expand_burst(3, 250, &[send("alice", "one"), send("bob", "two")])
            .expect("burst expands");
        assert_eq!(expanded.len(), 8);
        assert!(matches!(
            expanded[2],
            ExpandedFlow::Action(ScenarioStep::AdvanceTime { delta_ms: 250 })
        ));
        assert!(matches!(
            expanded[5],
            ExpandedFlow::Action(ScenarioStep::AdvanceTime { delta_ms: 250 })
        ));
    }

    #[test]
    fn mismatched_parallel_barrier_is_a_compile_error() {
        let error = expand_flow(&ScenarioFlow::Parallel {
            lanes: vec![
                ScenarioParallelLane {
                    name: "one".into(),
                    steps: vec![ScenarioFlow::Barrier { name: "a".into() }],
                },
                ScenarioParallelLane {
                    name: "two".into(),
                    steps: vec![ScenarioFlow::Barrier { name: "b".into() }],
                },
            ],
        })
        .expect_err("different barriers must fail");
        assert_eq!(error.kind, "scenario_authoring_error");
    }

    #[test]
    fn authored_json_round_trips_and_lowers_to_canonical_json() {
        let authored = ScenarioAuthoringSpec {
            name: "authoring/round-trip".into(),
            authoring_version: SCENARIO_AUTHORING_VERSION.into(),
            clients: vec!["alice".into()],
            steps: vec![ScenarioFlow::Repeat {
                count: 2,
                steps: vec![send("alice", "hello")],
            }],
        };
        let json = serde_json::to_value(&authored).expect("serialize authoring document");
        assert_eq!(json["steps"][0]["flow"], "repeat");
        assert_eq!(json["steps"][0]["steps"][0]["flow"], "action");
        assert_eq!(
            json["steps"][0]["steps"][0]["step"]["type"],
            "send_app_message"
        );
        let decoded: ScenarioAuthoringSpec =
            serde_json::from_value(json).expect("deserialize authoring document");
        let canonical = compile_authoring_scenario(&decoded).expect("lower authoring document");
        assert_eq!(canonical.spec_version, SCENARIO_IR_VERSION);
        assert_eq!(canonical.steps.len(), 2);
        assert!(
            serde_json::to_value(&canonical)
                .expect("serialize canonical document")
                .get("authoring_version")
                .is_none()
        );
    }

    #[test]
    fn expansion_bound_fails_before_allocating_repeated_output() {
        let error = expand_flow(&ScenarioFlow::Repeat {
            count: MAX_EXPANDED_SCENARIO_ACTIONS as u32 + 1,
            steps: vec![send("alice", "hello")],
        })
        .expect_err("oversized expansion must fail");
        assert!(error.message.contains("exceeds"));
    }

    #[test]
    fn yaml_is_authoring_only_and_compiles_to_the_same_canonical_ir() {
        let yaml = r#"
name: authoring/yaml
authoring_version: "1"
clients: [alice]
steps:
  - flow: rate
    actions_per_second: 2
    steps:
      - flow: action
        step:
          type: send_app_message
          sender: alice
          payload: one
      - flow: action
        step:
          type: send_app_message
          sender: alice
          payload: two
"#;
        let canonical = compile_authoring_yaml(yaml).expect("YAML lowers");
        assert_eq!(canonical.spec_version, SCENARIO_IR_VERSION);
        assert!(matches!(
            canonical.steps[1],
            ScenarioStep::AdvanceTime { delta_ms: 500 }
        ));
        assert_eq!(canonical.steps.len(), 3);
    }
}
