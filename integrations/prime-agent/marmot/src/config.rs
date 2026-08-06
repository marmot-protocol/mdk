use std::env;
use std::path::PathBuf;

use marmot_terminal_harness::{ConfigSpec, HarnessError, LoadedConfig, Result, load_config_with};

use crate::prime::PrimeBackend;

const CONFIG_SPEC: ConfigSpec = ConfigSpec {
    env_prefix: "WN_PRIME_AGENT",
    default_home_name: "prime-agent",
    default_bin: "prime-agent",
    display_name: "Prime Agent",
    reply_prefix: "wn-prime-agent",
    bin_env_name: "WN_PRIME_AGENT_BIN",
    account_env_name: "WN_PRIME_AGENT_ACCOUNT_ID_HEX",
    legacy_allowed_senders_env: None,
};

pub(crate) struct Config {
    loaded: LoadedConfig,
    daemon_socket: PathBuf,
}

impl Config {
    pub(crate) fn from_env() -> Result<Self> {
        Self::load_with(&mut |name| env::var(name).ok())
    }

    fn load_with(lookup: &mut impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let loaded = load_config_with(CONFIG_SPEC, lookup)?;
        let daemon_socket = lookup("WN_PRIME_AGENT_DAEMON_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| loaded.home.join("dev").join("prime-agent.sock"));
        if daemon_socket.as_os_str().is_empty() {
            return Err(HarnessError::Config(
                "WN_PRIME_AGENT_DAEMON_SOCKET must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            loaded,
            daemon_socket,
        })
    }

    pub(crate) fn into_harness(self) -> (marmot_terminal_harness::Config, PrimeBackend) {
        let backend = PrimeBackend::new(self.loaded.bin, self.daemon_socket);
        (self.loaded.harness, backend)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const SENDER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn prime_config_defaults_daemon_socket_below_private_home() {
        let map = HashMap::from([
            ("HOME", "/home/test"),
            ("WN_PRIME_AGENT_ALLOWED_SENDERS_HEX", SENDER),
        ]);
        let config =
            Config::load_with(&mut |name| map.get(name).map(|value| (*value).to_owned())).unwrap();
        assert_eq!(
            config.daemon_socket,
            PathBuf::from("/home/test/.marmot-agents/prime-agent/dev/prime-agent.sock")
        );
    }
}
