//! Shared presentation building blocks for C5. M4 owns worker capture and live
//! composition; these selectors do not subscribe, acknowledge reads or fetch media.
mod capabilities;
pub use capabilities::*;
mod window;
pub use window::*;
#[cfg(test)]
mod tests;
