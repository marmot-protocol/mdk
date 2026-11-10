use std::sync::{Arc, Mutex as StdMutex};

use crate::{MarmotKitError, conversions::RelayLivenessFfi};

/// One account's complete relay snapshots. Closing does not disconnect relays.
#[derive(uniffi::Object)]
pub struct RelayLivenessSubscription {
    snapshot: StdMutex<Option<Vec<RelayLivenessFfi>>>,
    inner: marmot_app::RuntimeRelayLivenessSubscription,
}

impl RelayLivenessSubscription {
    pub(crate) fn new(mut inner: marmot_app::RuntimeRelayLivenessSubscription) -> Arc<Self> {
        let snapshot = std::mem::take(&mut inner.snapshot)
            .into_iter()
            .map(Into::into)
            .collect();
        Arc::new(Self {
            snapshot: StdMutex::new(Some(snapshot)),
            inner,
        })
    }
}

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl RelayLivenessSubscription {
    /// Take the initial snapshot once; subsequent calls return an empty list.
    pub fn snapshot(&self) -> Vec<RelayLivenessFfi> {
        super::take_snapshot(&self.snapshot).unwrap_or_default()
    }

    /// Receive the latest complete snapshot, or None after cancellation or runtime shutdown.
    #[marmot_uniffi_macros::receive]
    pub async fn next(&self) -> Result<Option<Vec<RelayLivenessFfi>>, MarmotKitError> {
        Ok(self
            .inner
            .recv()
            .await?
            .map(|rows| rows.into_iter().map(Into::into).collect()))
    }

    /// End pending and future receives without changing the account's connections.
    pub fn cancel(&self) {
        self.inner.close();
    }
}
