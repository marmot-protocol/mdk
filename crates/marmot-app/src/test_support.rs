use cgka_traits::GroupId;
use cgka_traits::convergence_pass::DurableConvergencePass;
use cgka_traits::storage::ConvergencePassStorage;

use crate::{AppError, MarmotApp};

impl MarmotApp {
    /// Inspect the durable pass without advancing the engine or its scheduler.
    /// Relay tests use this to witness retained input before exercising a send.
    #[doc(hidden)]
    pub fn convergence_pass_for_test(
        &self,
        label: &str,
        group_id: &GroupId,
    ) -> Result<Option<DurableConvergencePass>, AppError> {
        Ok(self.account_storage(label)?.convergence_pass(group_id)?)
    }
}
