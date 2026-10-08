#[cfg(test)]
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use marmot_terminal_harness::{ConfigSpec, HarnessError, LoadedConfig, Result, load_config_with};

use crate::goose::GooseBackend;

const SPEC: ConfigSpec = ConfigSpec {
    env_prefix: "WN_GOOSE",
    default_home_name: "goose",
    default_bin: "goose",
    display_name: "Goose",
    reply_prefix: "wn-goose",
    bin_env_name: "WN_GOOSE_BIN",
    account_env_name: "WN_GOOSE_ACCOUNT_ID_HEX",
    legacy_allowed_senders_env: None,
};

const PATH_ROOT_ENV: &str = "WN_GOOSE_PATH_ROOT";

#[derive(Clone)]
pub(crate) struct Config {
    shared: LoadedConfig,
    goose_path_root: Option<PathBuf>,
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
        let shared = load_config_with(SPEC, lookup)?;
        let goose_path_root = match lookup(PATH_ROOT_ENV) {
            None => None,
            Some(raw) => {
                let path = PathBuf::from(raw);
                // Goose itself rejects a relative GOOSE_PATH_ROOT; fail before spawn instead.
                if !path.is_absolute() {
                    return Err(HarnessError::Config(format!(
                        "{PATH_ROOT_ENV} must be an absolute path"
                    )));
                }
                Some(path)
            }
        };
        Ok(Self {
            shared,
            goose_path_root,
        })
    }

    pub(crate) fn into_harness(self) -> Result<(marmot_terminal_harness::Config, GooseBackend)> {
        let backend = GooseBackend::new(
            self.shared.bin,
            self.shared.harness.execution_profile,
            self.goose_path_root,
        )?;
        Ok((self.shared.harness, backend))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use marmot_terminal_harness::{DEFAULT_MAX_REPLY_BYTES, ExecutionProfile};

    use super::*;

    const SENDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn defaults() -> Vec<(&'static str, &'static str)> {
        vec![
            ("HOME", "/home/test"),
            ("WN_GOOSE_ALLOWED_SENDERS_HEX", SENDER),
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
                .ends_with(".marmot-agents/goose/dev/wn-agent.sock")
        );
        assert_eq!(config.shared.bin, "goose");
        assert_eq!(config.goose_path_root, None);
        assert_eq!(
            config.shared.harness.execution_profile,
            ExecutionProfile::Inherit
        );
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
    fn path_root_must_be_absolute() {
        let mut absolute = defaults();
        absolute.push((PATH_ROOT_ENV, "/home/test/.marmot-agents/goose/goose-root"));
        assert_eq!(
            Config::from_pairs(&absolute).unwrap().goose_path_root,
            Some(PathBuf::from("/home/test/.marmot-agents/goose/goose-root"))
        );

        let mut relative = defaults();
        relative.push((PATH_ROOT_ENV, "goose-root"));
        let error = Config::from_pairs(&relative).err().expect("relative root");
        assert!(error.to_string().contains(PATH_ROOT_ENV));
    }

    #[test]
    fn rejects_missing_sender_invalid_activation_and_zero_timeouts() {
        assert!(Config::from_pairs(&[("HOME", "/home/test")]).is_err());
        let mut invalid_activation = defaults();
        invalid_activation.push(("WN_GOOSE_ACTIVATION", "mention"));
        assert!(Config::from_pairs(&invalid_activation).is_err());
        for name in [
            "WN_GOOSE_TIMEOUT_SECS",
            "WN_GOOSE_IDLE_TIMEOUT_SECS",
            "WN_GOOSE_REQUEST_TIMEOUT_SECS",
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
