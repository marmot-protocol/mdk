use super::*;
use crate::collector_host_safety;
impl ProductAnalytics {
    #[cfg(test)]
    pub(super) async fn send_pending(&self) {
        if let Some(permit) = self.permit() {
            self.send_pending_with_permit(&permit).await;
        }
    }
    pub(super) async fn send_pending_with_permit(&self, permit: &DiagnosticsPermit) {
        let _lock = tokio::select! {
            biased;
            _ = permit.cancelled() => return,
            lock = self.send_lock.lock() => lock,
        };
        if !permit.valid() {
            return;
        }
        let (config, batch, expires) = {
            let mut s = self.lock();
            if !permit.valid() || !Self::enabled(&s) {
                return;
            }
            self.advance(&mut s);
            let mut batch = Vec::new();
            let mut expires = Duration::MAX;
            for _ in 0..25 {
                if let Some(e) = s.queue.pop_front() {
                    s.queue_bytes -= e.bytes;
                    if self.valid_payload(&s.config, &e.payload) {
                        expires = expires.min(e.created.saturating_add(EVENT_TTL));
                        batch.push(e.payload);
                    } else {
                        s.status.dropped_events = s.status.dropped_events.saturating_add(1);
                    }
                } else {
                    break;
                }
            }
            (s.config.clone(), batch, expires)
        };
        if batch.is_empty() {
            return;
        }
        let mut delivery = DetachedBatch {
            collector: self.clone(),
            permit: permit.clone(),
            count: batch.len() as u64,
            accepted: false,
        };
        let Some(endpoint) = config.events_endpoint else {
            return;
        };
        let Some(key) = config.app_key else {
            return;
        };
        for attempt in 0..=3 {
            if !permit.valid() || self.clock.monotonic() >= expires {
                return;
            }
            let pin = tokio::select! {
                biased;
                _ = permit.cancelled() => return,
                result = collector_host_safety::resolve_with(
                    &endpoint, collector_host_safety::system_resolve,
                ) => result,
            };
            let mut retry_delay = None;
            if let Ok(pin) = pin {
                if !permit.valid() || self.clock.monotonic() >= expires {
                    return;
                }
                let Ok(client) = pin.build_client() else {
                    return;
                };
                let request = client.post(pin.url).header("App-Key", &key).json(&batch);
                if !permit.valid() || self.clock.monotonic() >= expires {
                    return;
                }
                let result = tokio::select! {
                    biased;
                    _ = permit.cancelled() => return,
                    result = request.send() => result,
                };
                if !permit.valid() {
                    return;
                }
                match result {
                    Ok(response) if response.status().is_success() => {
                        let mut s = self.lock();
                        if permit.valid() {
                            s.status.accepted_batches = s.status.accepted_batches.saturating_add(1);
                            delivery.accepted = true;
                        }
                        return;
                    }
                    Ok(response) if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                        let delay = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| retry_after(v, self.clock.wall_seconds()))
                            .unwrap_or(5);
                        // Never retry earlier than requested. Long delays exceed our memory budget.
                        if delay <= 300 {
                            retry_delay = Some(delay.max(1));
                        }
                    }
                    Ok(response)
                        if matches!(response.status().as_u16(), 400 | 401 | 403 | 404 | 422) =>
                    {
                        let mut s = self.lock();
                        if !permit.valid() {
                            return;
                        }
                        s.status.product_analytics =
                            DiagnosticsExporterStatus::ConfigurationRejected;
                        s.status.dropped_events =
                            s.status.dropped_events.saturating_add(s.queue.len() as u64);
                        s.queue.clear();
                        s.queue_bytes = 0;
                    }
                    Err(error) if error.is_connect() => {
                        retry_delay = Some(1u64 << attempt);
                    }
                    // A server/proxy 5xx can follow an accepted upstream write.
                    // Aptabase provides no idempotency receipt, so retrying it can
                    // double-count. Only known nonacceptance is retried above.
                    _ => {}
                }
            } else {
                retry_delay = Some(1u64 << attempt);
            }
            if attempt < 3
                && let Some(delay) = retry_delay
            {
                tokio::select! {
                    biased;
                    _ = permit.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
                }
                continue;
            }
            return;
        }
    }
}

// Covers timeout/cancellation of a detached flush as well as explicit transport failure.
struct DetachedBatch {
    collector: ProductAnalytics,
    permit: DiagnosticsPermit,
    count: u64,
    accepted: bool,
}
impl Drop for DetachedBatch {
    fn drop(&mut self) {
        let mut s = self.collector.lock();
        if !self.accepted && self.permit.valid() {
            s.status.failed_batches = s.status.failed_batches.saturating_add(1);
            s.status.dropped_events = s.status.dropped_events.saturating_add(self.count);
        }
    }
}
fn retry_after(value: &str, now: u64) -> Option<u64> {
    value.parse().ok().or_else(|| {
        chrono::DateTime::parse_from_rfc2822(value)
            .ok()
            .map(|date| (date.timestamp().max(0) as u64).saturating_sub(now))
    })
}
