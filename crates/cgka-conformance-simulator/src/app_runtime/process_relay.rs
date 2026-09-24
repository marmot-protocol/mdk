//! Relay ownership and control use the same retained-relay semantics in either layout.
use super::process_io::{ProcessClient, WireError};
use crate::relay_control::{RelayActionEvents, RelayActionExpectation, RelayControl};
use crate::{ScenarioMessageSelectorV2, SubjectError};
use nostr_relay_builder::LocalRelay;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

pub(crate) struct RelayProcess {
    client: ProcessClient,
    publications: std::sync::Mutex<Option<Vec<nostr::prelude::Event>>>,
    _root: TempDir,
}
#[derive(Clone)]
pub(crate) enum RelayBackend {
    Local(RelayControl),
    Remote(Arc<RelayProcess>),
}
pub(crate) enum ProxyBackend {
    Local(crate::relay_fault_proxy::RelayFaultProxy),
    Remote(Arc<RelayProcess>),
}
impl RelayBackend {
    pub async fn start(
        process: bool,
    ) -> Result<(Self, ProxyBackend, Option<LocalRelay>, String), SubjectError> {
        if process {
            let root = tempfile::Builder::new()
                .prefix("marmot-app-relay-")
                .tempdir()
                .map_err(super::environment_error)?;
            fs_private::create_dir_all_private(root.path()).map_err(super::environment_error)?;
            let client = ProcessClient::spawn("relay", root.path()).map_err(|e| e.subject())?;
            let url: String = client
                .call_async("initialize", json!({}))
                .await
                .map_err(|e| e.subject())?;
            let process = Arc::new(RelayProcess {
                client,
                publications: std::sync::Mutex::new(None),
                _root: root,
            });
            Ok((
                Self::Remote(process.clone()),
                ProxyBackend::Remote(process),
                None,
                url,
            ))
        } else {
            let control = RelayControl::new();
            let relay = LocalRelay::new(control.relay_builder());
            relay.run().await.map_err(super::environment_error)?;
            let url = relay.url().await.to_string();
            let upstream = url
                .strip_prefix("ws://")
                .ok_or_else(|| super::environment_error("local relay must use ws"))?
                .trim_end_matches('/')
                .parse()
                .map_err(super::environment_error)?;
            let proxy = crate::relay_fault_proxy::RelayFaultProxy::start(upstream)
                .await
                .map_err(super::environment_error)?;
            let url = proxy.url();
            Ok((
                Self::Local(control),
                ProxyBackend::Local(proxy),
                Some(relay),
                url,
            ))
        }
    }
    pub async fn shutdown(&self) -> Result<(), SubjectError> {
        if let Self::Remote(p) = self {
            if p.publications.lock().expect("relay cache lock").is_some() {
                return Ok(());
            }
            let publications = self.diagnostic_publications().await;
            let close = p.client.call_async::<()>("close", json!([])).await;
            let exit = p.client.reap();
            *p.publications.lock().expect("relay cache lock") = Some(publications?);
            close.map_err(|e| e.subject())?;
            exit.map_err(|e| e.subject())?;
        }
        Ok(())
    }
    pub fn pid(&self) -> Option<u32> {
        match self {
            Self::Remote(p) => Some(p.client.pid()),
            Self::Local(_) => None,
        }
    }
    pub async fn publication_cursor(&self) -> Result<usize, SubjectError> {
        match self {
            Self::Local(c) => Ok(c.publication_cursor().await),
            Self::Remote(p) => p
                .client
                .call_async("cursor", json!([]))
                .await
                .map_err(|e| e.subject()),
        }
    }
    pub async fn diagnostic_publications(
        &self,
    ) -> Result<Vec<nostr::prelude::Event>, SubjectError> {
        if let Self::Remote(p) = self
            && let Some(events) = p.publications.lock().expect("relay cache lock").as_ref()
        {
            return Ok(events.clone());
        }
        match self {
            Self::Local(c) => c
                .diagnostic_publications()
                .await
                .into_iter()
                .map(|event| {
                    let json = serde_json::to_string(&event).map_err(super::environment_error)?;
                    nostr::prelude::Event::from_json(json).map_err(super::environment_error)
                })
                .collect(),
            Self::Remote(p) => p
                .client
                .call_async("publications", json!([]))
                .await
                .map_err(|e| e.subject()),
        }
    }
    async fn wait(
        &self,
        mode: &str,
        events: &mut RelayActionEvents,
        action: &str,
        before: usize,
        e: RelayActionExpectation<'_>,
    ) -> Result<usize, SubjectError> {
        match self {
            Self::Local(c) => match mode {
                "exact" => {
                    c.wait_for_exact_action_events(events, action, before, e)
                        .await
                        .map_err(super::relay_control_error)?;
                    Ok(0)
                }
                "at_least" => c
                    .wait_for_at_least_action_events(events, action, before, e)
                    .await
                    .map_err(super::relay_control_error),
                _ => {
                    c.wait_for_action_events(events, action, before, e)
                        .await
                        .map_err(super::relay_control_error)?;
                    Ok(0)
                }
            },
            Self::Remote(p) => p
                .client
                .call_async(
                    "wait",
                    json!([
                        mode,
                        action,
                        before,
                        e.include_welcomes,
                        e.expected_publications,
                        e.expected_event_ids,
                        e.timeout.as_millis() as u64
                    ]),
                )
                .await
                .map_err(|e| e.subject()),
        }
    }
    pub async fn wait_for_action_events(
        &self,
        events: &mut RelayActionEvents,
        action: &str,
        before: usize,
        e: RelayActionExpectation<'_>,
    ) -> Result<(), SubjectError> {
        self.wait("count", events, action, before, e)
            .await
            .map(|_| ())
    }
    pub async fn wait_for_exact_action_events(
        &self,
        events: &mut RelayActionEvents,
        action: &str,
        before: usize,
        e: RelayActionExpectation<'_>,
    ) -> Result<(), SubjectError> {
        self.wait("exact", events, action, before, e)
            .await
            .map(|_| ())
    }
    pub async fn wait_for_at_least_action_events(
        &self,
        events: &mut RelayActionEvents,
        action: &str,
        before: usize,
        e: RelayActionExpectation<'_>,
    ) -> Result<usize, SubjectError> {
        self.wait("at_least", events, action, before, e).await
    }
    pub async fn set_action_event_visibility(
        &self,
        events: &RelayActionEvents,
        selector: &ScenarioMessageSelectorV2,
        visible: bool,
    ) -> Result<(), SubjectError> {
        match self {
            Self::Local(c) => c
                .set_action_event_visibility(events, selector, visible)
                .await
                .map_err(super::relay_control_error),
            Self::Remote(p) => p
                .client
                .call_async("visibility", json!([selector, visible]))
                .await
                .map_err(|e| e.subject()),
        }
    }
}
impl ProxyBackend {
    pub async fn interrupt(&self, duration: Duration) -> Result<(u64, u64), SubjectError> {
        match self {
            Self::Local(p) => p
                .interrupt(duration)
                .await
                .map_err(super::environment_error),
            Self::Remote(p) => p
                .client
                .call_async("interrupt", json!([duration.as_millis() as u64]))
                .await
                .map_err(|e| e.subject()),
        }
    }
}
pub(super) struct RelayServer {
    _relay: LocalRelay,
    proxy: crate::relay_fault_proxy::RelayFaultProxy,
    control: RelayControl,
    events: RelayActionEvents,
}
impl RelayServer {
    pub async fn start() -> Result<Self, WireError> {
        let control = RelayControl::new();
        let relay = LocalRelay::new(control.relay_builder());
        relay
            .run()
            .await
            .map_err(|_| WireError::environment("app_relay_start_failed"))?;
        let url = relay.url().await.to_string();
        let upstream = url
            .strip_prefix("ws://")
            .and_then(|s| s.trim_end_matches('/').parse().ok())
            .ok_or_else(|| WireError::environment("app_relay_address_invalid"))?;
        let proxy = crate::relay_fault_proxy::RelayFaultProxy::start(upstream)
            .await
            .map_err(|_| WireError::environment("app_relay_proxy_failed"))?;
        Ok(Self {
            _relay: relay,
            proxy,
            control,
            events: Default::default(),
        })
    }
    pub async fn handle(&mut self, method: &str, args: Value) -> Result<Value, WireError> {
        fn decode<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, WireError> {
            serde_json::from_value(v)
                .map_err(|_| WireError::environment("app_process_invalid_arguments"))
        }
        fn encode<T: serde::Serialize>(v: T) -> Result<Value, WireError> {
            serde_json::to_value(v).map_err(|_| WireError::environment("app_process_result_encode"))
        }
        match method {
            "initialize" => encode(self.proxy.url()),
            "close" => encode(()),
            "cursor" => encode(self.control.publication_cursor().await),
            "publications" => encode(self.control.diagnostic_publications().await),
            "wait" => {
                let (
                    mode,
                    action,
                    before,
                    include_welcomes,
                    expected_publications,
                    ids,
                    timeout_ms,
                ): (String, String, usize, bool, usize, Vec<String>, u64) = decode(args)?;
                if timeout_ms > 60_000 {
                    return Err(WireError::environment("app_relay_timeout_invalid"));
                }
                let e = RelayActionExpectation {
                    include_welcomes,
                    expected_publications,
                    expected_event_ids: &ids,
                    timeout: Duration::from_millis(timeout_ms),
                };
                let count = match mode.as_str() {
                    "exact" => {
                        self.control
                            .wait_for_exact_action_events(&mut self.events, &action, before, e)
                            .await
                            .map_err(super::relay_control_error)?;
                        0
                    }
                    "count" => {
                        self.control
                            .wait_for_action_events(&mut self.events, &action, before, e)
                            .await
                            .map_err(super::relay_control_error)?;
                        0
                    }
                    "at_least" => self
                        .control
                        .wait_for_at_least_action_events(&mut self.events, &action, before, e)
                        .await
                        .map_err(super::relay_control_error)?,
                    _ => return Err(WireError::environment("app_relay_wait_mode_invalid")),
                };
                encode(count)
            }
            "visibility" => {
                let (selector, visible): (ScenarioMessageSelectorV2, bool) = decode(args)?;
                self.control
                    .set_action_event_visibility(&self.events, &selector, visible)
                    .await
                    .map_err(super::relay_control_error)?;
                encode(())
            }
            "interrupt" => {
                let (millis,): (u64,) = decode(args)?;
                if !(1..=30_000).contains(&millis) {
                    return Err(WireError::environment("app_relay_outage_invalid"));
                }
                encode(
                    self.proxy
                        .interrupt(Duration::from_millis(millis))
                        .await
                        .map_err(|_| WireError::environment("app_relay_interrupt_failed"))?,
                )
            }
            _ => Err(WireError::environment("app_process_unknown_method")),
        }
    }
}
