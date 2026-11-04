//! Opt-in native OpenCode session transport. The shared runner owns child lifetime and routing.
use marmot_terminal_harness::{
    Attachment, Invocation, Outcome, ParsedEvent, PromptTransport, RunFailure, RunnerEvent,
    SteerOutcome, current_group_id,
    process::{EnvironmentChange, ProcessSpec, run_interactive_jsonl_process},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

#[derive(Default)]
pub(crate) struct Native {
    groups: Mutex<HashMap<String, Arc<Active>>>,
}
struct Active {
    input: mpsc::Sender<Option<String>>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    closed: bool,
    next: u64,
    pending: HashMap<u64, oneshot::Sender<SteerOutcome>>,
    leases: Vec<Box<dyn Send + Sync>>,
}
struct Registration<'a> {
    owner: &'a Native,
    group: Option<String>,
    active: Arc<Active>,
}
impl Drop for Registration<'_> {
    fn drop(&mut self) {
        {
            let mut state = self.active.state.lock().unwrap();
            state.closed = true;
            state.pending.clear();
        }
        if let Some(group) = &self.group {
            let mut groups = self.owner.groups.lock().unwrap();
            if groups
                .get(group)
                .is_some_and(|a| Arc::ptr_eq(a, &self.active))
            {
                groups.remove(group);
            }
        }
    }
}
impl Native {
    pub fn active(&self, group: &str) -> bool {
        self.groups
            .lock()
            .unwrap()
            .get(group)
            .is_some_and(|a| !a.state.lock().unwrap().closed)
    }
    pub async fn steer(
        &self,
        group: &str,
        text: &str,
        files: Vec<String>,
        lease: Option<Box<dyn Send + Sync>>,
    ) -> SteerOutcome {
        let active = self.groups.lock().unwrap().get(group).cloned();
        let Some(active) = active else {
            return SteerOutcome::Unavailable;
        };
        let (request, id, response) = {
            let mut state = active.state.lock().unwrap();
            if state.closed {
                return SteerOutcome::Unavailable;
            }
            state.next += 1;
            let id = state.next;
            let (tx, rx) = oneshot::channel();
            state.pending.insert(id, tx);
            if let Some(lease) = lease {
                state.leases.push(lease);
            }
            (
                json!({"type":"steer","id":id,"prompt":text,"files":files}).to_string(),
                id,
                rx,
            )
        };
        if active.input.send(Some(request)).await.is_err() {
            active.state.lock().unwrap().pending.remove(&id);
            return SteerOutcome::Unavailable;
        }
        tokio::time::timeout(Duration::from_secs(20), response)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(SteerOutcome::Uncertain)
    }
    fn register(
        &self,
        group: Option<String>,
        input: mpsc::Sender<Option<String>>,
    ) -> Registration<'_> {
        let active = Arc::new(Active {
            input,
            state: Mutex::new(State::default()),
        });
        if let Some(group) = &group {
            self.groups
                .lock()
                .unwrap()
                .insert(group.clone(), active.clone());
        }
        Registration {
            owner: self,
            group,
            active,
        }
    }
    pub async fn run(
        &self,
        bin: &str,
        invocation: Invocation,
        attachments: &[Attachment],
        environment: Vec<EnvironmentChange>,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> Result<Outcome, RunFailure> {
        let files =
            super::opencode::prepare_attachments(attachments).map_err(|error| RunFailure {
                error,
                observed_session: None,
            })?;
        let (input, rx) = mpsc::channel(64);
        let registration = self.register(current_group_id(), input);
        let active = registration.active.clone();
        let prompt = json!({"bin":bin,"session":invocation.session_id,"prompt":invocation.prompt,"files":files}).to_string();
        run_interactive_jsonl_process(
            ProcessSpec {
                executable: "/usr/bin/python3".into(),
                args: vec![
                    "-u".into(),
                    "-c".into(),
                    include_str!("native_bridge.py").into(),
                ],
                cwd: invocation.cwd,
                environment,
                prompt: PromptTransport::Stdin(format!("{prompt}\n")),
                trace_method: "opencode_native",
                backend_name: "opencode",
                total_timeout: invocation.timeout,
                idle_timeout: invocation.idle_timeout,
            },
            tx,
            move |line| active.observe(line),
            rx,
        )
        .await
    }
}

impl Active {
    fn observe(&self, line: &str) -> Result<ParsedEvent, ()> {
        let value: Value = serde_json::from_str(line).map_err(|_| ())?;
        match value["type"].as_str() {
            Some("session") => Ok(ParsedEvent::Session(
                value["session"].as_str().ok_or(())?.into(),
            )),
            Some("ack") => {
                if let Some(id) = value["id"].as_u64()
                    && let Some(waiter) = self.state.lock().unwrap().pending.remove(&id)
                {
                    let outcome = if value["inactive"] == true {
                        SteerOutcome::Unavailable
                    } else if value["persisted"] == true {
                        SteerOutcome::Accepted
                    } else {
                        SteerOutcome::Uncertain
                    };
                    let _ = waiter.send(outcome);
                }
                Ok(ParsedEvent::Ignored)
            }
            Some("finishing") => {
                let mut state = self.state.lock().unwrap();
                if !state.closed && state.pending.is_empty() {
                    self.input
                        .try_send(Some(json!({"type":"finish"}).to_string()))
                        .map_err(|_| ())?;
                    state.closed = true;
                    if matches!(
                        self.input.try_send(None),
                        Err(mpsc::error::TrySendError::Full(_))
                    ) {
                        let input = self.input.clone();
                        tokio::spawn(async move {
                            let _ = input.send(None).await;
                        });
                    }
                }
                Ok(ParsedEvent::Ignored)
            }
            Some("text") => Ok(ParsedEvent::Text(value["text"].as_str().ok_or(())?.into())),
            Some("error") => Ok(ParsedEvent::Error {
                session_id: None,
                summary:
                    "OpenCode native session failed; inspect private backend state before retrying"
                        .into(),
            }),
            _ => Ok(ParsedEvent::Ignored),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn native_transport_protocol_regressions() {
        let status = std::process::Command::new("python3")
            .args([
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                "test_native_bridge.py",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .expect("Python 3 is required for native OpenCode transport tests");
        assert!(
            status.success(),
            "native transport protocol regressions failed"
        );
    }

    #[tokio::test]
    async fn steering_is_group_scoped_and_completion_waits_for_ack() {
        let native = Arc::new(Native::default());
        let (a, mut receive_a) = mpsc::channel(8);
        let (b, mut receive_b) = mpsc::channel(8);
        let first = native.register(Some("first".into()), a);
        let _second = native.register(Some("second".into()), b);
        let worker = native.clone();
        let pending =
            tokio::spawn(async move { worker.steer("first", "followup", vec![], None).await });
        let request: Value =
            serde_json::from_str(&receive_a.recv().await.unwrap().unwrap()).unwrap();
        assert!(receive_b.try_recv().is_err());
        first.active.observe(r#"{"type":"finishing"}"#).unwrap();
        assert!(receive_a.try_recv().is_err());
        first
            .active
            .observe(&json!({"type":"ack","id":request["id"],"persisted":true}).to_string())
            .unwrap();
        assert_eq!(pending.await.unwrap(), SteerOutcome::Accepted);
        first.active.observe(r#"{"type":"finishing"}"#).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&receive_a.recv().await.unwrap().unwrap()).unwrap()["type"],
            "finish"
        );
        assert!(matches!(receive_a.recv().await, Some(None)));
        first.active.observe(r#"{"type":"finishing"}"#).unwrap();
        assert!(receive_a.try_recv().is_err());
        assert_eq!(
            native.steer("first", "later", vec![], None).await,
            SteerOutcome::Unavailable
        );
        assert!(native.active("second"));
    }

    #[tokio::test]
    async fn closed_writer_is_definitely_unavailable_and_drops_pending_ack() {
        let native = Native::default();
        let (input, receive) = mpsc::channel(8);
        let registration = native.register(Some("room".into()), input);
        drop(receive);
        assert_eq!(
            native.steer("room", "unsent", vec![], None).await,
            SteerOutcome::Unavailable
        );
        assert!(registration.active.state.lock().unwrap().pending.is_empty());
    }

    #[tokio::test]
    async fn dropped_registration_marks_pending_uncertain_without_removing_successor() {
        let native = Arc::new(Native::default());
        let (input, mut receive) = mpsc::channel(8);
        let original = native.register(Some("room".into()), input);
        let worker = native.clone();
        let pending =
            tokio::spawn(async move { worker.steer("room", "followup", vec![], None).await });
        receive.recv().await.unwrap();
        let (replacement, _receive) = mpsc::channel(8);
        let _successor = native.register(Some("room".into()), replacement);
        drop(original);
        assert_eq!(pending.await.unwrap(), SteerOutcome::Uncertain);
        assert!(native.active("room"));
    }
}
