//! Test support for the code moving to `marmot-observability` (#2627): the collector fixtures
//! `marmot-app`'s tests use. Gated `cfg(any(test, feature = "test-support"))` like the hooks on
//! the collector and the collector helper, so the move carries the gate unchanged and
//! `marmot-app`'s dev-dependency turns it on.

pub use crate::product_analytics::fixtures::configured;
#[cfg(feature = "product-analytics-export")]
pub use crate::product_analytics::fixtures::{grant, test_product_collector};
pub use crate::product_analytics::observed::success_or_failure;
