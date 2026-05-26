use std::time::Duration;

const DEFAULT_DIRECTORY_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarmotAppConfig {
    pub directory_max_future_skew: Duration,
}

impl Default for MarmotAppConfig {
    fn default() -> Self {
        Self {
            directory_max_future_skew: DEFAULT_DIRECTORY_MAX_FUTURE_SKEW,
        }
    }
}

impl MarmotAppConfig {
    pub fn with_directory_max_future_skew(mut self, skew: Duration) -> Self {
        self.directory_max_future_skew = skew;
        self
    }
}
