//! Opt-in memory diagnostics remain usable before native startup completes.
use crate::{Marmot, MarmotKitError, conversions::NativeStartupSnapshotFfi};
#[uniffi::export]
impl Marmot {
    /// Enable or revoke bounded process-local capture. No database, upload or consent setting is changed.
    pub fn set_startup_diagnostics_enabled(&self, enabled: bool) -> Result<(), MarmotKitError> {
        self.app.set_startup_diagnostics_enabled(enabled);
        Ok(())
    }
    /// Snapshot fixed native phases and migration progress without account/keystore/storage queries.
    pub fn startup_diagnostics_snapshot(&self) -> Result<NativeStartupSnapshotFfi, MarmotKitError> {
        Ok(self.app.startup_diagnostics_snapshot().into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// Exercise capture before startup with an isolated local test home, without an OS credential service.
    #[test]
    fn startup_capture_is_disabled_until_explicitly_enabled() {
        let root = tempfile::tempdir().unwrap();
        let marmot = Marmot::open(
            root.path().to_string_lossy().into_owned(),
            vec![],
            marmot_app::MarmotAppConfig::white_noise(),
            Some(std::sync::Arc::new(
                marmot_account::LocalFileSecretStore::new(root.path()),
            )),
        )
        .unwrap();
        assert!(!marmot.startup_diagnostics_snapshot().unwrap().enabled);
        marmot.set_startup_diagnostics_enabled(true).unwrap();
        assert!(marmot.startup_diagnostics_snapshot().unwrap().enabled);
        marmot.set_startup_diagnostics_enabled(false).unwrap();
        assert!(
            marmot
                .startup_diagnostics_snapshot()
                .unwrap()
                .events
                .is_empty()
        );
    }
}
