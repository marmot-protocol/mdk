#[cfg(test)]
use std::collections::HashMap;
use std::env;

use marmot_terminal_harness::{ConfigSpec, LoadedConfig, Result, load_config_with};

use crate::codex::CodexBackend;

const SPEC: ConfigSpec = ConfigSpec {
    env_prefix: "WN_CODEX",
    default_home_name: "codex",
    default_bin: "codex",
    display_name: "Codex",
    reply_prefix: "wn-codex",
    bin_env_name: "WN_CODEX_BIN",
    account_env_name: "WN_CODEX_ACCOUNT_ID_HEX",
    legacy_allowed_senders_env: None,
};

#[derive(Clone)]
pub(crate) struct Config {
    shared: LoadedConfig,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        Self::from_lookup(&mut |name| env::var(name).ok())
    }

    #[cfg(test)]
    fn from_pairs(pairs: &[(&str, &str)]) -> Result<Self> {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        Self::from_lookup(&mut |name| map.get(name).map(|value| (*value).to_owned()))
    }

    fn from_lookup(lookup: &mut impl FnMut(&str) -> Option<String>) -> Result<Self> {
        Ok(Self {
            shared: load_config_with(SPEC, lookup)?,
        })
    }

    pub(crate) fn into_harness(self) -> (marmot_terminal_harness::Config, CodexBackend) {
        let backend = CodexBackend::new(self.shared.bin, self.shared.harness.execution_profile);
        (self.shared.harness, backend)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use marmot_terminal_harness::DEFAULT_MAX_REPLY_BYTES;

    use super::*;

    const SENDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn defaults() -> Vec<(&'static str, &'static str)> {
        vec![
            ("HOME", "/home/test"),
            ("WN_CODEX_ALLOWED_SENDERS_HEX", SENDER),
        ]
    }

    #[test]
    fn defaults_are_isolated_and_match_terminal_harness_limits() {
        let config = Config::from_pairs(&defaults()).unwrap();
        assert!(
            config
                .shared
                .harness
                .socket
                .ends_with(".marmot-agents/codex/dev/wn-agent.sock")
        );
        assert_eq!(config.shared.bin, "codex");
        assert_eq!(
            config.shared.harness.max_reply_bytes,
            DEFAULT_MAX_REPLY_BYTES
        );
        assert_eq!(
            config.shared.harness.backend_timeout,
            Duration::from_secs(3600)
        );
        assert_eq!(
            config.shared.harness.backend_idle_timeout,
            Duration::from_secs(120)
        );
    }

    #[test]
    fn rejects_missing_sender_invalid_activation_and_zero_timeouts() {
        assert!(Config::from_pairs(&[("HOME", "/home/test")]).is_err());
        let mut invalid_activation = defaults();
        invalid_activation.push(("WN_CODEX_ACTIVATION", "mention"));
        assert!(Config::from_pairs(&invalid_activation).is_err());
        for name in [
            "WN_CODEX_TIMEOUT_SECS",
            "WN_CODEX_IDLE_TIMEOUT_SECS",
            "WN_CODEX_REQUEST_TIMEOUT_SECS",
        ] {
            let mut pairs = defaults();
            pairs.push((name, "0"));
            assert!(Config::from_pairs(&pairs).is_err(), "accepted zero {name}");
        }
    }

    #[test]
    fn account_error_names_the_actual_source_variable() {
        let mut pairs = defaults();
        pairs.push(("MARMOT_ACCOUNT_ID_HEX", "invalid"));
        let error = Config::from_pairs(&pairs)
            .err()
            .expect("invalid account id");
        assert!(error.to_string().contains("MARMOT_ACCOUNT_ID_HEX"));
    }
}
