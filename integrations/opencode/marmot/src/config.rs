#[cfg(test)]
use std::collections::HashMap;
use std::env;

use marmot_terminal_harness::{ConfigSpec, LoadedConfig, ModelSelection, Result, load_config_with};

use crate::opencode::OpencodeBackend;

const SPEC: ConfigSpec = ConfigSpec {
    env_prefix: "WN_OPENCODE",
    default_home_name: "harnesses",
    default_bin: "opencode",
    display_name: "opencode",
    reply_prefix: "wn-opencode",
    bin_env_name: "WN_OPENCODE_BIN",
    account_env_name: "WN_OPENCODE_ACCOUNT_ID_HEX",
    legacy_allowed_senders_env: Some("WN_OPENCODE_ADMIN_HEX"),
};

#[derive(Clone)]
pub(crate) struct Config(LoadedConfig, ModelSelection);

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
        let models = ModelSelection::from_config(
            lookup("WN_OPENCODE_MODEL"),
            lookup("WN_OPENCODE_MODEL_ALIASES_JSON").as_deref(),
        )?;
        Ok(Self(load_config_with(SPEC, lookup)?, models))
    }

    pub(crate) fn into_harness(self) -> (marmot_terminal_harness::Config, OpencodeBackend) {
        let backend = OpencodeBackend {
            bin: self.0.bin,
            execution_profile: self.0.harness.execution_profile,
            models: self.1,
        };
        (self.0.harness, backend)
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
            ("WN_OPENCODE_ALLOWED_SENDERS_HEX", SENDER),
        ]
    }

    #[test]
    fn config_uses_allowed_senders_and_shared_defaults() {
        let config = Config::from_pairs(&defaults()).unwrap();
        assert!(config.0.harness.allowed_senders.contains(SENDER));
        assert_eq!(config.0.harness.max_reply_bytes, DEFAULT_MAX_REPLY_BYTES);
        assert_eq!(config.0.harness.backend_timeout, Duration::from_secs(3600));
        assert_eq!(
            config.0.harness.backend_idle_timeout,
            Duration::from_secs(120)
        );
        assert!(
            config
                .0
                .harness
                .socket
                .ends_with(".marmot-agents/harnesses/dev/wn-agent.sock")
        );
    }

    #[test]
    fn config_accepts_legacy_admin_alias() {
        let config =
            Config::from_pairs(&[("HOME", "/home/test"), ("WN_OPENCODE_ADMIN_HEX", SENDER)])
                .unwrap();
        assert!(config.0.harness.allowed_senders.contains(SENDER));
    }

    #[test]
    fn config_loads_model_default_and_aliases() {
        let mut pairs = defaults();
        pairs.push(("WN_OPENCODE_MODEL", "venice/deepseek-v4-1-flash"));
        pairs.push((
            "WN_OPENCODE_MODEL_ALIASES_JSON",
            r#"{"deepseek":"venice/deepseek-v4-1-flash"}"#,
        ));
        let (_, backend) = Config::from_pairs(&pairs).unwrap().into_harness();
        assert_eq!(
            backend.models.default_model(),
            Some("venice/deepseek-v4-1-flash")
        );
        assert_eq!(
            backend.models.resolve("deepseek").as_deref(),
            backend.models.default_model()
        );
    }

    #[test]
    fn config_rejects_reply_cap_above_marmot_ceiling() {
        let mut pairs = defaults();
        pairs.push(("WN_OPENCODE_MAX_REPLY_BYTES", "60001"));
        assert!(Config::from_pairs(&pairs).is_err());
    }
}
